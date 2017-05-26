//! A Client Queries Handler is the main entry point of a Resolver.
//!
//! It accepts queries received as messages from the Udp and Tcp listeners,
//! and initiate the chain of futures required to fetch the responses.
//!
//! The chain includes coalescing similar queries, retrying, marking servers as
//! unresponsive after too many timeouts, and bringing them back to life after
//! regular probes have been successfully received.

use cache::Cache;
use client_query::ClientQuery;
use coarsetime::{Duration, Instant};
use config::Config;
use dns::{self, NormalizedQuestion, NormalizedQuestionKey, NormalizedQuestionMinimal};
use futures::Future;
use futures::Stream;
use futures::future;
use futures::sync::mpsc::Receiver;
use futures::sync::oneshot;
use jumphash::JumpHasher;
use parking_lot::RwLock;
use pending_query::{PendingQueries, PendingQuery};
use rand::distributions::{IndependentSample, Range};
use rand;
use resolver::{ResolverCore, LoadBalancingMode};
use std::io;
use std::net;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::Relaxed;
use std::time;
use super::{UPSTREAM_QUERY_MAX_TIMEOUT_MS, UPSTREAM_PROBES_DELAY_MS};
use tokio_core::reactor::Handle;
use tokio_timer::{wheel, Timer};
use upstream_server::UpstreamServer;
use varz::Varz;

pub struct ClientQueriesHandler {
    cache: Cache,
    config: Rc<Config>,
    handle: Handle,
    net_udp_socket: net::UdpSocket,
    net_ext_udp_sockets_rc: Rc<Vec<net::UdpSocket>>,
    pending_queries: PendingQueries,
    upstream_servers_arc: Arc<RwLock<Vec<UpstreamServer>>>,
    upstream_servers_live_arc: Arc<RwLock<Vec<usize>>>,
    waiting_clients_count: Rc<AtomicUsize>,
    jumphasher: JumpHasher,
    timer: Timer,
    varz: Arc<Varz>,
}

impl Clone for ClientQueriesHandler {
    fn clone(&self) -> Self {
        ClientQueriesHandler {
            cache: self.cache.clone(),
            config: self.config.clone(),
            handle: self.handle.clone(),
            net_udp_socket: self.net_udp_socket.try_clone().unwrap(),
            net_ext_udp_sockets_rc: self.net_ext_udp_sockets_rc.clone(),
            pending_queries: self.pending_queries.clone(),
            upstream_servers_arc: self.upstream_servers_arc.clone(),
            upstream_servers_live_arc: self.upstream_servers_live_arc.clone(),
            waiting_clients_count: self.waiting_clients_count.clone(),
            jumphasher: self.jumphasher,
            timer: self.timer.clone(),
            varz: self.varz.clone(),
        }
    }
}

impl ClientQueriesHandler {
    pub fn new(resolver_core: &ResolverCore) -> Self {
        let timer = wheel()
            .max_capacity(resolver_core.config.max_active_queries)
            .build();
        ClientQueriesHandler {
            cache: resolver_core.cache.clone(),
            config: resolver_core.config.clone(),
            handle: resolver_core.handle.clone(),
            net_udp_socket: resolver_core.net_udp_socket.try_clone().unwrap(),
            net_ext_udp_sockets_rc: resolver_core.net_ext_udp_sockets_rc.clone(),
            pending_queries: resolver_core.pending_queries.clone(),
            upstream_servers_arc: resolver_core.upstream_servers_arc.clone(),
            upstream_servers_live_arc: resolver_core.upstream_servers_live_arc.clone(),
            waiting_clients_count: resolver_core.waiting_clients_count.clone(),
            jumphasher: resolver_core.jumphasher,
            timer: timer,
            varz: resolver_core.varz.clone(),
        }
    }

    pub fn fut_process_stream(&self,
                              handle: &Handle,
                              resolver_rx: Receiver<ClientQuery>)
                              -> impl Future<Item = (), Error = io::Error> {
        let handle = handle.clone();
        let mut self_inner = self.clone();
        let fut_client_query = resolver_rx.for_each(move |client_query| {
                                                        let fut = self_inner
                                                            .fut_process_client_query(client_query)
                                                            .map_err(|_| {});
                                                        handle.spawn(fut);
                                                        future::ok(())
                                                    });
        fut_client_query.map_err(|_| io::Error::last_os_error())
    }

    fn cap_pending_queries(&mut self) -> bool {
        if self.waiting_clients_count.load(Relaxed) < self.config.max_waiting_clients {
            return false;
        }
        debug!("Too many waiting clients, dropping the first slot");
        let mut map = self.pending_queries.map_arc.write();
        let key = match map.keys().next() {
            None => return false,
            Some(key) => key.clone(),
        };
        if let Some(pending_query) = map.remove(&key) {
            self.varz.inflight_queries.dec();
            let clients_count = pending_query.client_queries.len();
            let prev_count = self.waiting_clients_count.fetch_sub(clients_count, Relaxed);
            assert!(prev_count >= clients_count);
        }
        true
    }

    fn maybe_add_to_existing_pending_query(&mut self,
                                           normalized_question_key: &NormalizedQuestionKey,
                                           client_query: &ClientQuery)
                                           -> bool {
        let mut pending_queries = self.pending_queries.map_arc.write();
        match pending_queries.get_mut(normalized_question_key) {
            None => false,
            Some(pending_query) => {
                pending_query.client_queries.push(client_query.clone());
                self.waiting_clients_count.fetch_add(1, Relaxed);
                true
            }
        }
    }

    fn maybe_respond_with_stale_entry(&mut self,
                                      client_query: &ClientQuery)
                                      -> Box<Future<Item = (), Error = io::Error>> {
        let normalized_question = &client_query.normalized_question;
        let cache_entry = self.cache.get2(normalized_question);
        if let Some(mut cache_entry) = cache_entry {
            self.varz.client_queries_offline.inc();
            debug!("All upstream servers are down - Responding with stale entry");
            return client_query.response_send(&mut cache_entry.packet, Some(&self.net_udp_socket));
        }
        if let Ok(mut packet) = dns::build_servfail_packet(normalized_question) {
            debug!("Returning SERVFAIL due to upstream timeouts");
            return client_query.response_send(&mut packet, Some(&self.net_udp_socket));
        }
        Box::new(future::ok(()))
    }

    fn maybe_respond_to_all_clients_with_stale_entry
        (&mut self,
         pending_query: &PendingQuery)
         -> Box<Future<Item = (), Error = io::Error>> {
        let mut fut = Vec::with_capacity(pending_query.client_queries.len());
        for client_query in &pending_query.client_queries {
            fut.push(self.maybe_respond_with_stale_entry(client_query));
        }
        Box::new(future::join_all(fut).map(|_| {}))
    }

    fn maybe_send_probe_to_offline_servers(&self,
                                           query_packet: &[u8],
                                           upstream_servers: &mut Vec<UpstreamServer>,
                                           upstream_servers_live: &Vec<usize>,
                                           net_ext_udp_socket: &net::UdpSocket)
                                           -> Result<Option<usize>, io::Error> {
        if upstream_servers_live.len() == upstream_servers.len() {
            return Ok(None);
        }
        let offline_servers: Vec<_> = upstream_servers
            .iter()
            .enumerate()
            .filter_map(|(idx, upstream_server)| if upstream_server.offline {
                            Some(idx)
                        } else {
                            None
                        })
            .collect();
        if offline_servers.is_empty() {
            warn!("Inconsistency between the live servers map and offline status");
            return Ok(None);
        }
        let mut rng = rand::thread_rng();
        let random_offline_server_range = Range::new(0usize, offline_servers.len());
        let random_offline_server_idx = offline_servers[random_offline_server_range
                                                            .ind_sample(&mut rng)];
        let mut random_offline_server = &mut upstream_servers[random_offline_server_idx];
        if let Some(last_probe_ts) = random_offline_server.last_probe_ts {
            if last_probe_ts.elapsed_since_recent() <
               Duration::from_millis(UPSTREAM_PROBES_DELAY_MS) {
                return Ok(None);
            }
        }
        info!("Sending probe to {}", random_offline_server.remote_addr);
        random_offline_server.last_probe_ts = Some(Instant::recent());
        net_ext_udp_socket
            .send_to(query_packet, &random_offline_server.socket_addr)
            .map(|_| Some(random_offline_server_idx))
    }

    fn fut_process_client_query(&mut self,
                                client_query: ClientQuery)
                                -> Box<Future<Item = (), Error = io::Error>> {
        debug!("Incoming client query");
        if self.upstream_servers_live_arc.read().is_empty() {
            return self.maybe_respond_with_stale_entry(&client_query);
        }
        let normalized_question = &client_query.normalized_question;
        let key = normalized_question.key();
        self.cap_pending_queries();
        if self.maybe_add_to_existing_pending_query(&key, &client_query) {
            return Box::new(future::ok(()));
        }
        let mut upstream_servers = self.upstream_servers_arc.write();
        let (query_packet, normalized_question_minimal, upstream_server_idx, net_ext_udp_socket) =
            match normalized_question.new_pending_query(&upstream_servers,
                                                        &self.upstream_servers_live_arc.read(),
                                                        &self.net_ext_udp_sockets_rc,
                                                        &self.jumphasher,
                                                        false,
                                                        self.config.lbmode) {
                Err(_) => return Box::new(future::ok(())),
                Ok(res) => res,
            };
        let probe_idx =
            self.maybe_send_probe_to_offline_servers(&query_packet,
                                                     &mut upstream_servers,
                                                     &self.upstream_servers_live_arc.read(),
                                                     net_ext_udp_socket);
        let mut upstream_server = &mut upstream_servers[upstream_server_idx];
        let (done_tx, done_rx) = oneshot::channel();
        let mut pending_query = PendingQuery::new(normalized_question_minimal,
                                                  upstream_server,
                                                  upstream_server_idx,
                                                  net_ext_udp_socket,
                                                  &client_query,
                                                  done_tx);
        debug_assert_eq!(pending_query.client_queries.len(), 1);
        self.waiting_clients_count.fetch_add(1, Relaxed);
        if let Ok(Some(probe_idx)) = probe_idx {
            pending_query.probed_upstream_server_idx = Some(probe_idx);
        }
        let mut map = self.pending_queries.map_arc.write();
        debug!("Sending {:?} to {:?}",
               pending_query.normalized_question_minimal,
               upstream_server.socket_addr);
        self.varz.inflight_queries.inc();
        upstream_server.prepare_send(&self.config);
        upstream_server.pending_queries_count =
            upstream_server.pending_queries_count.saturating_add(1);
        debug!("queries_count for server {}: {}",
               upstream_server_idx,
               upstream_server.pending_queries_count);
        map.insert(key, pending_query);
        let _ = net_ext_udp_socket.send_to(&query_packet, &upstream_server.socket_addr);
        self.varz.upstream_sent.inc();
        let done_rx = done_rx.map_err(|_| ());
        let timeout =
            self.timer.timeout(done_rx,
                               time::Duration::from_millis(upstream_server.timeout_ms_est()));
        let retry_query = self.clone();
        let upstream_servers_arc = self.upstream_servers_arc.clone();
        let upstream_servers_live_arc = self.upstream_servers_live_arc.clone();
        let config = self.config.clone();
        let normalized_question = normalized_question.clone();
        let handle = self.handle.clone();
        let net_ext_udp_sockets_rc = self.net_ext_udp_sockets_rc.clone();
        let fut = timeout
            .map(|_| {})
            .map_err(|_| io::Error::last_os_error())
            .or_else(move |_| {
                {
                    let mut upstream_servers = upstream_servers_arc.write();
                    {
                        let mut upstream_server = &mut upstream_servers[upstream_server_idx];
                        upstream_server.pending_queries_count =
                            upstream_server.pending_queries_count.saturating_sub(1);
                        upstream_server.record_failure(&config, &handle, &net_ext_udp_sockets_rc);
                    }
                    *upstream_servers_live_arc.write() =
                        UpstreamServer::live_servers(&mut upstream_servers);
                }
                retry_query.fut_retry_query(normalized_question)
            });
        Box::new(fut)
    }

    fn fut_retry_query(&self,
                       normalized_question: NormalizedQuestion)
                       -> Box<Future<Item = (), Error = io::Error>> {
        debug!("timeout");
        let mut map = self.pending_queries.map_arc.write();
        let key = normalized_question.key();
        let mut pending_query = match map.get_mut(&key) {
            None => return Box::new(future::ok(())) as Box<Future<Item = (), Error = io::Error>>,
            Some(pending_query) => pending_query,
        };
        let mut upstream_servers = self.upstream_servers_arc.write();
        let upstream_server_idx = pending_query.upstream_server_idx;
        upstream_servers[upstream_server_idx].pending_queries_count = upstream_servers
            [upstream_server_idx]
            .pending_queries_count
            .saturating_sub(1);
        debug!("Decrementing the number of pending queries for upstream {}: {}",
               upstream_server_idx,
               upstream_servers[upstream_server_idx].pending_queries_count);

        let nq = normalized_question.new_pending_query(&upstream_servers,
                                                       &self.upstream_servers_live_arc.read(),
                                                       &self.net_ext_udp_sockets_rc,
                                                       &self.jumphasher,
                                                       true,
                                                       self.config.lbmode);
        let (query_packet, normalized_question_minimal, upstream_server_idx, net_ext_udp_socket) =
            match nq {
                Ok(x) => x,
                Err(_) => {
                    return Box::new(future::ok(())) as Box<Future<Item = (), Error = io::Error>>
                }
            };
        let upstream_server = &mut upstream_servers[upstream_server_idx];

        debug!("new attempt with upstream server: {:?}",
               upstream_server.socket_addr);
        let (done_tx, done_rx) = oneshot::channel();
        pending_query.normalized_question_minimal = normalized_question_minimal;
        pending_query.local_port = net_ext_udp_socket.local_addr().unwrap().port();
        pending_query.ts = Instant::recent();
        pending_query.upstream_server_idx = upstream_server_idx;
        pending_query.done_tx = done_tx;
        let _ = net_ext_udp_socket.send_to(&query_packet, &upstream_server.socket_addr);
        upstream_server.pending_queries_count =
            upstream_server.pending_queries_count.saturating_add(1);
        debug!("New attempt: upstream server {} queries count: {}",
               upstream_server_idx,
               upstream_server.pending_queries_count);
        let done_rx = done_rx.map_err(|_| ());
        let timeout = self.timer
            .timeout(done_rx,
                     time::Duration::from_millis(UPSTREAM_QUERY_MAX_TIMEOUT_MS));
        let map_arc = self.pending_queries.map_arc.clone();
        let waiting_clients_count = self.waiting_clients_count.clone();
        let upstream_servers_arc = self.upstream_servers_arc.clone();
        let upstream_servers_live_arc = self.upstream_servers_live_arc.clone();
        let config = self.config.clone();
        let handle = self.handle.clone();
        let varz = self.varz.clone();
        let net_ext_udp_sockets_rc = self.net_ext_udp_sockets_rc.clone();
        let mut retry_query = self.clone();
        let fut = timeout
            .map(|_| {})
            .map_err(|_| io::Error::last_os_error())
            .or_else(move |_| {
                debug!("retry failed as well");
                varz.upstream_timeout.inc();
                {
                    let mut upstream_servers = upstream_servers_arc.write();
                    upstream_servers[upstream_server_idx].pending_queries_count =
                        upstream_servers[upstream_server_idx]
                            .pending_queries_count
                            .saturating_sub(1);
                    debug!("Failed new attempt: upstream server {} queries count: {}",
                           upstream_server_idx,
                           upstream_servers[upstream_server_idx].pending_queries_count);
                    upstream_servers[upstream_server_idx]
                        .record_failure(&config, &handle, &net_ext_udp_sockets_rc);
                    *upstream_servers_live_arc.write() =
                        UpstreamServer::live_servers(&mut upstream_servers);
                }
                let mut map = map_arc.write();
                if let Some(pending_query) = map.remove(&key) {
                    varz.inflight_queries.dec();
                    let fut = retry_query
                        .maybe_respond_to_all_clients_with_stale_entry(&pending_query);
                    let _ = pending_query.done_tx.send(());
                    waiting_clients_count.fetch_sub(pending_query.client_queries.len(), Relaxed);
                    return fut;
                }
                Box::new(future::ok(())) as Box<Future<Item = (), Error = io::Error>>
            });
        debug!("retrying...");
        Box::new(fut) as Box<Future<Item = (), Error = io::Error>>
    }
}

/// Local additions to the `NormalizedQuestion` struct, for convenience
impl NormalizedQuestion {
    fn pick_upstream(&self,
                     upstream_servers: &Vec<UpstreamServer>,
                     upstream_servers_live: &Vec<usize>,
                     jumphasher: &JumpHasher,
                     is_retry: bool,
                     lbmode: LoadBalancingMode)
                     -> Result<usize, &'static str> {
        let live_count = upstream_servers_live.len();
        if live_count == 0 {
            debug!("All upstream servers are down");
            return Err("All upstream servers are down");
        }
        match lbmode {
            LoadBalancingMode::Fallback => Ok(upstream_servers_live[0]),
            LoadBalancingMode::Uniform => {
                let mut i = jumphasher.slot(&self.qname, live_count as u32) as usize;
                if is_retry {
                    i = (i + 1) % live_count;
                }
                Ok(upstream_servers_live[i])
            }
            LoadBalancingMode::P2 => {
                let mut busy_map = upstream_servers_live
                    .iter()
                    .map(|&i| (i, upstream_servers[i].pending_queries_count))
                    .collect::<Vec<(usize, u64)>>();
                busy_map.sort_by_key(|x| x.1);
                let i = if busy_map.len() == 1 {
                    0
                } else {
                    ((self.tid as usize) + (is_retry as usize & 1)) & 1
                };
                Ok(busy_map[i].0)
            }
        }
    }

    fn new_pending_query<'t>
        (&self,
         upstream_servers: &Vec<UpstreamServer>,
         upstream_servers_live: &Vec<usize>,
         net_ext_udp_sockets: &'t Vec<net::UdpSocket>,
         jumphasher: &JumpHasher,
         is_retry: bool,
         lbmode: LoadBalancingMode)
         -> Result<(Vec<u8>, NormalizedQuestionMinimal, usize, &'t net::UdpSocket), &'static str> {
        let (query_packet, normalized_question_minimal) =
            dns::build_query_packet(self, false).expect("Unable to build a new query packet");
        let upstream_server_idx = match self.pick_upstream(upstream_servers,
                                                           upstream_servers_live,
                                                           jumphasher,
                                                           is_retry,
                                                           lbmode) {
            Err(e) => return Err(e),
            Ok(upstream_server_idx) => upstream_server_idx,
        };
        let mut rng = rand::thread_rng();
        let random_token_range = Range::new(0usize, net_ext_udp_sockets.len());
        let random_token = random_token_range.ind_sample(&mut rng);
        let net_ext_udp_socket = &net_ext_udp_sockets[random_token];
        Ok((query_packet, normalized_question_minimal, upstream_server_idx, net_ext_udp_socket))
    }
}
