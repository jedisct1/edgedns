//! A Client Queries Handler is the main entry point of a Resolver.
//!
//! It accepts queries received as messages from the Udp and Tcp listeners,
//! and initiate the chain of futures required to fetch the responses.
//!
//! The chain includes coalescing similar queries, retrying, marking servers as
//! unresponsive after too many timeouts, and bringing them back to life after
//! regular probes have been successfully received.

use super::{FAILURE_TTL, UPSTREAM_PROBES_DELAY_MS, UPSTREAM_QUERY_MAX_TIMEOUT_MS};
use cache::Cache;
use cache::CacheKey;
use client_query::{ClientQuery, ResolverResponse};
use coarsetime::{Duration, Instant};
use config::Config;
use dns;
use dns::*;
use errors::*;
use futures::Future;
use futures::Stream;
use futures::future;
use futures::sync::mpsc::Receiver;
use futures::sync::oneshot;
use globals::Globals;
use jumphash::JumpHasher;
use parking_lot::{Mutex, RwLock};
use rand;
use rand::distributions::{IndependentSample, Range};
use resolver::{LoadBalancingMode, ResolverCore};
use std::collections::HashMap;
use std::io;
use std::net;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::Relaxed;
use std::time;
use tokio_core::reactor::Handle;
use tokio_timer::{wheel, Timer};
use upstream_server::{UpstreamServer, UpstreamServerForQuery};
use varz::Varz;

#[derive(Default)]
pub struct WaitingClients {
    pub client_queries: Vec<ClientQuery>,
    pub upstream_tx: Option<oneshot::Sender<Vec<u8>>>,
}

#[derive(Default)]
pub struct PendingQueriesInner {
    pub waiting_clients: HashMap<UpstreamQuestion, Arc<Mutex<WaitingClients>>>,
    pub local_question_to_waiting_client: HashMap<LocalUpstreamQuestion, UpstreamQuestion>,
}

#[derive(Clone, Default)]
pub struct PendingQueries {
    pub inner: Arc<RwLock<PendingQueriesInner>>,
}

pub struct ClientQueriesHandler {
    globals: Globals,
    handle: Handle,
    net_udp_socket: net::UdpSocket,
    net_ext_udp_sockets_rc: Rc<Vec<net::UdpSocket>>,
    jumphasher: JumpHasher,
    timer: Timer,
}

impl Clone for ClientQueriesHandler {
    fn clone(&self) -> Self {
        ClientQueriesHandler {
            globals: self.globals.clone(),
            handle: self.handle.clone(),
            net_udp_socket: self.net_udp_socket.try_clone().unwrap(),
            net_ext_udp_sockets_rc: Rc::clone(&self.net_ext_udp_sockets_rc),
            jumphasher: self.jumphasher,
            timer: self.timer.clone(),
        }
    }
}

impl ClientQueriesHandler {
    pub fn new(resolver_core: &ResolverCore) -> Self {
        let timer = wheel()
            .max_capacity(resolver_core.globals.config.max_active_queries)
            .build();
        ClientQueriesHandler {
            globals: resolver_core.globals.clone(),
            handle: resolver_core.handle.clone(),
            net_udp_socket: resolver_core.net_udp_socket.try_clone().unwrap(),
            net_ext_udp_sockets_rc: Rc::clone(&resolver_core.net_ext_udp_sockets_rc),
            jumphasher: resolver_core.jumphasher,
            timer: timer,
        }
    }

    pub fn fut_process_stream(
        &self,
        handle: &Handle,
        resolver_rx: Receiver<ClientQuery>,
    ) -> impl Future {
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

    fn fut_process_client_query(
        &mut self,
        client_query: ClientQuery,
    ) -> impl Future<Item = (), Error = DNSError> {
        let normalized_question = &client_query.normalized_question;
        let custom_hash = client_query.session_state.inner.read().custom_hash;
        let local_upstream_question = LocalUpstreamQuestion {
            qname_lc: normalized_question.qname_lc.clone(), // XXX - maybe make qname_lc a Rc
            qtype: normalized_question.qtype,
            qclass: normalized_question.qclass,
            dnssec: normalized_question.dnssec,
            custom_hash,
        };
        let mut pending_queries = self.globals.pending_queries.inner.write();
        let upstream_question = pending_queries
            .local_question_to_waiting_client
            .get(&local_upstream_question)
            .cloned();
        if let Some(upstream_question) = upstream_question {
            debug!("Already in-flight");
            let mut waiting_clients = pending_queries
                .waiting_clients
                .get_mut(&upstream_question)
                .expect("No waiting clients, but existing local question");
            waiting_clients.lock().client_queries.push(client_query);
            return future::ok(());
        }

        debug!("Incoming client query");
        let tid: u16 = rand::random();
        let packet = match dns::build_query_packet(&client_query.normalized_question, tid, false) {
            Err(e) => return future::err(e),
            Ok(packet) => packet,
        };

        let remote_addr = {
            let upstream_servers_for_query = &client_query
                .session_state
                .inner
                .read()
                .upstream_servers_for_query;
            if upstream_servers_for_query.is_empty() {
                return future::err(DNSError::NoServers);
            }
            let upstream_server_for_query = &upstream_servers_for_query[0];
            let remote_addr = &upstream_server_for_query.remote_addr;
            remote_addr.clone()
        };
        let net_ext_udp_sockets = &self.net_ext_udp_sockets_rc;
        let mut rng = rand::thread_rng();
        let random_ext_socket_i = Range::new(0, net_ext_udp_sockets.len()).ind_sample(&mut rng);
        let net_ext_udp_socket = &net_ext_udp_sockets[random_ext_socket_i];
        if let Err(e) = net_ext_udp_socket.send_to(&packet, remote_addr) {
            return future::err(DNSError::Io(e));
        }
        debug!("Query sent to upstream");

        let upstream_question = UpstreamQuestion {
            qname_lc: local_upstream_question.qname_lc.clone(),
            qtype: local_upstream_question.qtype,
            qclass: local_upstream_question.qclass,
            local_port: net_ext_udp_socket.local_addr().unwrap().port(),
            tid,
            server_addr: remote_addr,
        };
        let already_present = pending_queries
            .local_question_to_waiting_client
            .insert(local_upstream_question.clone(), upstream_question.clone()) // XXX - Make upstream_question a Rc
            .is_some();
        debug_assert!(!already_present);

        let pending_queries_inner = self.globals.pending_queries.inner.clone();
        let (upstream_tx, upstream_rx): (
            oneshot::Sender<Vec<u8>>,
            oneshot::Receiver<Vec<u8>>,
        ) = oneshot::channel();

        let waiting_clients = Arc::new(Mutex::new(WaitingClients {
            client_queries: vec![client_query],
            upstream_tx: Some(upstream_tx),
        }));
        pending_queries
            .waiting_clients
            .insert(upstream_question, waiting_clients.clone());

        let mut cache_inner = self.globals.cache.clone();
        let (min_ttl, max_ttl, failure_ttl) = (
            self.globals.config.min_ttl,
            self.globals.config.max_ttl,
            FAILURE_TTL,
        );
        let fut = upstream_rx
            .map_err(|_| {})
            .and_then(move |upstream_packet| {
                let response = ResolverResponse {
                    packet: upstream_packet,
                    dnssec: false,
                };
                let mut waiting_clients = waiting_clients.lock();
                for mut client_query in waiting_clients.client_queries.iter_mut() {
                    let _ = client_query
                        .response_tx
                        .take()
                        .unwrap()
                        .send(response.clone());
                }
                waiting_clients.client_queries.clear();

                let mut pending_queries = pending_queries_inner.write();
                let upstream_question = pending_queries
                    .local_question_to_waiting_client
                    .remove(&local_upstream_question)
                    .expect("Local upstream question vanished");
                pending_queries
                    .waiting_clients
                    .remove(&upstream_question)
                    .expect("Waiting clients set vanished");

                if let Ok(ttl) = dns::min_ttl(&response.packet, min_ttl, max_ttl, failure_ttl) {
                    match dns::rcode(&response.packet) {
                        DNS_RCODE_NOERROR | DNS_RCODE_NXDOMAIN => {
                            let cache_key =
                                CacheKey::from_local_upstream_question(local_upstream_question);
                            cache_inner.insert(cache_key, response.packet, ttl);
                        }
                        _ => {}
                    }
                }
                future::ok(())
            });
        self.handle.spawn(fut);
        future::ok(())
    }
}
