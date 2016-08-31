use cache::Cache;
use client_query::*;
use dns::{NormalizedQuestion, NormalizedQuestionKey, NormalizedQuestionMinimal,
          build_query_packet, normalize, tid, set_tid, overwrite_qname, build_tc_packet,
          build_health_check_packet, build_servfail_packet, min_ttl, set_ttl, rcode,
          DNS_HEADER_SIZE, DNS_RCODE_SERVFAIL};
use mio::*;
use mio::deprecated::{EventLoop, EventLoopBuilder, Handler, Sender};
use mio::timer::Timeout;
use nix::fcntl::FcntlArg::F_SETFL;
use nix::fcntl::{fcntl, O_NONBLOCK};
use nix::sys::socket::{bind, setsockopt, sockopt, AddressFamily, SockFlag, SockType, SockLevel,
                       SockAddr, socket, InetAddr};
use rand::distributions::{IndependentSample, Range};
use rand;
use std::collections::HashMap;
use std::hash::{Hash, SipHasher13, Hasher};
use std::io;
use std::net::{UdpSocket, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::{RawFd, FromRawFd};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};
use std::u64;
use super::RPDNSContext;
use varz::Varz;

use super::{DNS_MAX_SIZE, DNS_QUERY_MIN_SIZE, UDP_BUFFER_SIZE, UPSTREAM_TIMEOUT_MS,
            UPSTREAM_MAX_TIMEOUT_MS, MAX_ACTIVE_QUERIES, MAX_CLIENTS_WAITING_FOR_QUERY,
            MAX_WAITING_CLIENTS, HEALTH_CHECK_MS, UPSTREAM_INITIAL_TIMEOUT_MS, MIN_TTL,
            FAILURE_TTL};

#[derive(Clone, Debug)]
pub struct ResolverResponse {
    pub client_tok: Token,
    pub response: Vec<u8>,
    pub dnssec: bool,
}

struct ExtUdpSocketTuple {
    local_port: u16,
    ext_udp_socket: udp::UdpSocket,
}

struct UpstreamServer {
    remote_addr: String,
    socket_addr: SocketAddr,
    failures: u32,
    offline: bool,
}

impl UpstreamServer {
    fn new(remote_addr: &str) -> Result<UpstreamServer, &'static str> {
        let socket_addr = match FromStr::from_str(remote_addr) {
            Err(_) => return Err("Unable to parse an upstream resolver address"),
            Ok(socket_addr) => socket_addr,
        };
        let upstream_server = UpstreamServer {
            remote_addr: remote_addr.to_owned(),
            socket_addr: socket_addr,
            failures: 0,
            offline: false,
        };
        Ok(upstream_server)
    }
}

pub struct Resolver {
    udp_socket: UdpSocket,
    pending_queries: PendingQueries,
    ext_udp_socket_tuples: Vec<ExtUdpSocketTuple>,
    upstream_servers: Vec<UpstreamServer>,
    upstream_servers_live: Vec<usize>,
    waiting_clients_count: usize,
    cache: Cache,
    varz: Arc<Varz>,
    decrement_ttl: bool,
    failover: bool,
    upstream_max_failures: u32,
}

struct PendingQueries {
    map: HashMap<NormalizedQuestionKey, ActiveQuery>,
}

struct ActiveQuery {
    normalized_question_minimal: NormalizedQuestionMinimal,
    socket_addr: SocketAddr,
    local_port: u16,
    client_queries: Vec<ClientQuery>,
    ts: Instant,
    delay: u64,
    upstream_server_idx: usize,
    timeout: Timeout,
}

impl PendingQueries {
    fn new() -> PendingQueries {
        let map = HashMap::new();
        PendingQueries { map: map }
    }
}

pub enum TimeoutToken {
    Key(NormalizedQuestionKey),
    HealthCheck,
}

impl Handler for Resolver {
    type Timeout = TimeoutToken;
    type Message = ClientQuery;

    fn timeout(&mut self, event_loop: &mut EventLoop<Self>, timeout_token: TimeoutToken) {
        match timeout_token {
            TimeoutToken::Key(normalized_question_key) => {
                self.timeout_question(event_loop, normalized_question_key)
            }
            TimeoutToken::HealthCheck => self.timeout_health_check(event_loop),
        }
    }

    fn ready(&mut self, event_loop: &mut EventLoop<Self>, token: Token, events: Ready) {
        if !events.is_readable() {
            debug!("Not readable");
            return;
        }
        loop {
            let mut packet = [0u8; DNS_MAX_SIZE];
            let ext_udp_socket_tuple = &self.ext_udp_socket_tuples[usize::from(token)];
            let ext_udp_socket = &ext_udp_socket_tuple.ext_udp_socket;
            let res = ext_udp_socket.recv_from(&mut packet).expect("UDP socket error");
            let (count, client_addr) = match res {
                None => break,
                Some(tuple) => tuple,
            };
            if count < DNS_HEADER_SIZE {
                info!("Short response without a header, using UDP");
                self.varz.resolver_errors.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            if let Some(idx) = self.upstream_servers
                .iter()
                .position(|upstream_server| upstream_server.socket_addr == client_addr) {
                if !self.upstream_servers_live.iter().any(|&x| x == idx) {
                    self.upstream_servers[idx].failures = 0;
                    self.upstream_servers[idx].offline = false;
                    self.upstream_servers_live.push(idx);
                    self.upstream_servers_live.sort();
                    info!("{} came back online",
                          self.upstream_servers[idx].remote_addr);
                } else if self.upstream_servers[idx].failures > 0 {
                    self.upstream_servers[idx].failures -= 1;
                    debug!("Failures count for server {} decreased to {}",
                           idx,
                           self.upstream_servers[idx].failures);
                }
            }
            if count < DNS_QUERY_MIN_SIZE {
                info!("Short response without a query, using UDP");
                self.varz.resolver_errors.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let mut packet = &mut packet[..count];
            let normalized_question = match normalize(packet, false) {
                Err(e) => {
                    info!("Unexpected question in a response: {}", e);
                    continue;
                }
                Ok(normalized_question) => normalized_question,
            };
            let ttl = match min_ttl(packet) {
                Err(e) => {
                    info!("Unexpected answers in a response ({}): {}",
                          normalized_question,
                          e);
                    self.varz.resolver_errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                Ok(ttl) => {
                    if rcode(packet) == DNS_RCODE_SERVFAIL {
                        let _ = set_ttl(packet, FAILURE_TTL);
                        FAILURE_TTL
                    } else if ttl < MIN_TTL {
                        if self.decrement_ttl {
                            let _ = set_ttl(packet, MIN_TTL);
                        }
                        MIN_TTL
                    } else {
                        ttl
                    }
                }
            };
            let normalized_question_key = normalized_question.key();
            {
                let active_query = match self.pending_queries.map.get(&normalized_question_key) {
                    None => {
                        debug!("No clients waiting for this query");
                        continue;
                    }
                    Some(active_query) => active_query,
                };
                if ext_udp_socket_tuple.local_port != active_query.local_port {
                    debug!("Got a reponse on port {} for a query sent on port {}",
                           ext_udp_socket_tuple.local_port,
                           active_query.local_port);
                    continue;
                }
                if active_query.socket_addr != client_addr {
                    info!("Sent a query to {:?} but got a response from {:?}",
                          active_query.socket_addr,
                          client_addr);
                    continue;
                }
                if active_query.normalized_question_minimal.tid != tid(packet) {
                    debug!("Sent a query with tid {} but got a response for tid {:?}",
                           active_query.normalized_question_minimal.tid,
                           tid(packet));
                    continue;
                }
                let client_queries = &active_query.client_queries;
                for client_query in client_queries {
                    set_tid(packet, client_query.normalized_question.tid);
                    overwrite_qname(packet, &client_query.normalized_question.qname);
                    self.varz.resolver_received.fetch_add(1, Ordering::Relaxed);
                    match client_query.proto {
                        ClientQueryProtocol::UDP => {
                            if client_query.ts.elapsed() <
                               Duration::from_millis(UPSTREAM_TIMEOUT_MS) {
                                if packet.len() >
                                   client_query.normalized_question.payload_size as usize {
                                    let packet = build_tc_packet(&client_query.normalized_question)
                                        .unwrap();
                                    let _ = self.udp_socket
                                        .send_to(&packet, client_query.client_addr.unwrap());
                                } else {
                                    let _ = self.udp_socket
                                        .send_to(&packet, client_query.client_addr.unwrap());
                                };
                            }
                        }
                        ClientQueryProtocol::TCP => {
                            let resolver_response = ResolverResponse {
                                response: packet.to_vec(),
                                client_tok: client_query.client_tok.unwrap(),
                                dnssec: client_query.normalized_question.dnssec,
                            };
                            let tcpclient_tx = client_query.tcpclient_tx.clone().unwrap();
                            let _ = tcpclient_tx.send(resolver_response);
                        }
                    }
                }
                event_loop.clear_timeout(&active_query.timeout);
            }
            if let Some(active_query) = self.pending_queries.map.remove(&normalized_question_key) {
                self.waiting_clients_count -= active_query.client_queries.len();
            }
            self.cache.insert(normalized_question_key, packet.to_owned(), ttl);
            let cache_stats = self.cache.stats();
            self.varz.cache_frequent_len.store(cache_stats.frequent_len, Ordering::Relaxed);
            self.varz.cache_recent_len.store(cache_stats.recent_len, Ordering::Relaxed);
            self.varz.cache_inserted.store(cache_stats.inserted, Ordering::Relaxed);
            self.varz.cache_evicted.store(cache_stats.evicted, Ordering::Relaxed);
        }
    }

    fn notify(&mut self, event_loop: &mut EventLoop<Self>, client_query: ClientQuery) {
        let normalized_question = &client_query.normalized_question;
        let key = normalized_question.key();
        if self.waiting_clients_count > MAX_WAITING_CLIENTS {
            info!("Too many waiting clients, dropping the first slot");
            let key = match self.pending_queries.map.keys().next() {
                None => return,
                Some(key) => key.clone(),
            };
            if let Some(active_query) = self.pending_queries.map.remove(&key) {
                self.waiting_clients_count -= active_query.client_queries.len();
                event_loop.clear_timeout(&active_query.timeout);
            }
            return;
        }
        let mut create_active_query = true;
        if let Some(active_query) = self.pending_queries.map.get_mut(&key) {
            create_active_query = false;
            if active_query.client_queries.len() < MAX_CLIENTS_WAITING_FOR_QUERY {
                active_query.client_queries.push(client_query.clone());
                self.waiting_clients_count += 1;
            } else {
                info!("More than {} clients waiting for a response to the same query",
                      MAX_CLIENTS_WAITING_FOR_QUERY);
            }
            let obsolete = active_query.ts.elapsed() >
                           Duration::from_millis(active_query.delay as u64);
            if obsolete {
                let mut new_server_went_offline = false;
                {
                    let mut previous_upstream_server =
                        &mut self.upstream_servers[active_query.upstream_server_idx];
                    if previous_upstream_server.failures >= self.upstream_max_failures {
                        if !previous_upstream_server.offline {
                            warn!("Putting {:?} offline", previous_upstream_server.socket_addr);
                            previous_upstream_server.offline = true;
                        }
                        new_server_went_offline = true;
                    } else {
                        debug!("Timeout while waiting for a response from resolver {:?} - delay \
                                was {}",
                               previous_upstream_server.socket_addr,
                               active_query.delay);
                        active_query.delay *= 2;
                        previous_upstream_server.failures += 1;
                        debug!("Upstream {:?} failures={}/{}",
                               previous_upstream_server.socket_addr,
                               previous_upstream_server.failures,
                               self.upstream_max_failures);
                    }
                }
                if new_server_went_offline && self.upstream_servers_live.len() > 0 {
                    debug!("Live upstream servers before removal of the dead one: {:?}",
                           self.upstream_servers_live);
                    let mut new_live: Vec<usize> =
                        Vec::with_capacity(self.upstream_servers_live.len() - 1);
                    for (idx, upstream_server) in self.upstream_servers.iter().enumerate() {
                        if !upstream_server.offline {
                            new_live.push(idx);
                        }
                    }
                    self.upstream_servers_live = new_live;
                    debug!("Live upstream servers after removal of the dead one: {:?}",
                           self.upstream_servers_live);
                }
                if active_query.delay > UPSTREAM_MAX_TIMEOUT_MS {
                    debug!("Timeout deadline reached while waiting for a response from resolver");
                    return;
                }
                let (query_packet,
                     normalized_question_minimal,
                     upstream_server_idx,
                     ext_udp_socket_tuple) =
                    match normalized_question.new_active_query(&self.upstream_servers,
                                                               &self.upstream_servers_live,
                                                               &self.ext_udp_socket_tuples,
                                                               true,
                                                               self.failover) {
                        Err(_) => return,
                        Ok(res) => res,
                    };
                let upstream_server = &self.upstream_servers[upstream_server_idx];
                active_query.normalized_question_minimal = normalized_question_minimal;
                active_query.socket_addr = upstream_server.socket_addr;
                active_query.local_port = ext_udp_socket_tuple.local_port;
                ext_udp_socket_tuple.ext_udp_socket
                    .send_to(&query_packet, &upstream_server.socket_addr)
                    .unwrap();
            }
            debug_assert_eq!(create_active_query, false);
        }
        if create_active_query {
            let (query_packet,
                 normalized_question_minimal,
                 upstream_server_idx,
                 ext_udp_socket_tuple) =
                match normalized_question.new_active_query(&self.upstream_servers,
                                                           &self.upstream_servers_live,
                                                           &self.ext_udp_socket_tuples,
                                                           false,
                                                           self.failover) {
                    Err(_) => return,
                    Ok(res) => res,
                };
            let upstream_server = &self.upstream_servers[upstream_server_idx];
            let timeout = match event_loop.timeout(TimeoutToken::Key(key.clone()),
                                                   Duration::from_millis(UPSTREAM_TIMEOUT_MS)) {
                Err(_) => return,
                Ok(timeout) => timeout,
            };
            let active_query = ActiveQuery {
                normalized_question_minimal: normalized_question_minimal,
                socket_addr: upstream_server.socket_addr,
                local_port: ext_udp_socket_tuple.local_port,
                client_queries: vec![client_query.clone()],
                ts: Instant::now(),
                delay: UPSTREAM_INITIAL_TIMEOUT_MS,
                upstream_server_idx: upstream_server_idx,
                timeout: timeout,
            };
            self.pending_queries.map.insert(key, active_query);
            self.waiting_clients_count += 1;
            ext_udp_socket_tuple.ext_udp_socket
                .send_to(&query_packet, &upstream_server.socket_addr)
                .unwrap();
        }
    }
}

impl Resolver {
    fn timeout_question(&mut self,
                        _event_loop: &mut EventLoop<Self>,
                        normalized_question_key: NormalizedQuestionKey) {
        if let Some(active_query) = self.pending_queries.map.remove(&normalized_question_key) {
            let cache_entry = self.cache.get(&normalized_question_key);
            let outdated_packet = if let Some(cache_entry) = cache_entry {
                Some(cache_entry.packet)
            } else {
                None
            };
            let client_queries = &active_query.client_queries;
            for client_query in client_queries {
                let mut packet = if let Some(ref outdated_packet) = outdated_packet {
                    let mut outdated_packet = outdated_packet.clone();
                    overwrite_qname(&mut outdated_packet,
                                    &client_query.normalized_question.qname);
                    outdated_packet
                } else {
                    build_servfail_packet(&client_query.normalized_question).unwrap()
                };
                set_tid(&mut packet, client_query.normalized_question.tid);
                self.varz.resolver_timeout.fetch_add(1, Ordering::Relaxed);
                match client_query.proto {
                    ClientQueryProtocol::UDP => {
                        if client_query.ts.elapsed() < Duration::from_millis(UPSTREAM_TIMEOUT_MS) {
                            if packet.len() >
                               client_query.normalized_question.payload_size as usize {
                                let packet = build_tc_packet(&client_query.normalized_question)
                                    .unwrap();
                                let _ = self.udp_socket
                                    .send_to(&packet, client_query.client_addr.unwrap());
                            } else {
                                let _ = self.udp_socket
                                    .send_to(&packet, client_query.client_addr.unwrap());
                            };
                        }
                    }
                    ClientQueryProtocol::TCP => {
                        let resolver_response = ResolverResponse {
                            response: packet.to_vec(),
                            client_tok: client_query.client_tok.unwrap(),
                            dnssec: client_query.normalized_question.dnssec,
                        };
                        let tcpclient_tx = client_query.tcpclient_tx.clone().unwrap();
                        let _ = tcpclient_tx.send(resolver_response);
                    }
                }
            }
            self.waiting_clients_count -= active_query.client_queries.len();
        }
    }

    fn timeout_health_check(&mut self, event_loop: &mut EventLoop<Self>) {
        if self.upstream_servers_live.is_empty() {
            info!("All resolvers are dead - forcing them back to life");
            for upstream_server in self.upstream_servers.iter_mut() {
                upstream_server.failures = 0;
                upstream_server.offline = false;
            }
            self.upstream_servers_live = (0..self.upstream_servers.len()).collect();
        } else {
            let (packet, _normalized_question) = build_health_check_packet().unwrap();
            let mut rng = rand::thread_rng();
            let random_token_range = Range::new(0usize, self.ext_udp_socket_tuples.len());
            for upstream_server in self.upstream_servers
                .iter()
                .filter(|upstream_server| upstream_server.offline) {
                let random_token = random_token_range.ind_sample(&mut rng);
                let ext_udp_socket_tuple = &self.ext_udp_socket_tuples[random_token];
                match ext_udp_socket_tuple.ext_udp_socket
                    .send_to(&packet, &upstream_server.socket_addr) {
                    Ok(_) => debug!("Health check send to {:?}", upstream_server.socket_addr),
                    Err(e) => warn!("Couldn't send a health check packet: {}", e),
                };
            }
        }
        event_loop.timeout(TimeoutToken::HealthCheck,
                     Duration::from_millis(HEALTH_CHECK_MS))
            .expect("Unable to reschedule the health check");
    }

    pub fn spawn(rpdns_context: &RPDNSContext,
                 upstream_servers_str: Vec<&str>,
                 decrement_ttl: bool,
                 failover: bool,
                 ports: u16,
                 upstream_max_failures: u32)
                 -> io::Result<Sender<ClientQuery>> {
        let udp_socket =
            rpdns_context.udp_socket.try_clone().expect("Unable to clone the UDP listening socket");
        let mut builder = EventLoopBuilder::new();
        builder.timer_capacity(MAX_ACTIVE_QUERIES);
        let mut event_loop = builder.build().expect("Couldn't instantiate an event loop");
        let resolver_tx: Sender<ClientQuery> = event_loop.channel();
        let pending_queries = PendingQueries::new();
        let mut ext_udp_socket_tuples = Vec::new();
        let ports = if ports > 65535 - 1024 {
            65535 - 1024
        } else {
            ports
        };
        for port in 1024..1024 + ports {
            if (port + 1) % 1024 == 0 {
                info!("Binding ports... {}/{}", port, ports)
            }
            if let Ok(ext_udp_socket) = mio_socket_udp_bound(port) {
                event_loop.register(&ext_udp_socket,
                              Token(ext_udp_socket_tuples.len()),
                              Ready::readable(),
                              PollOpt::edge())
                    .unwrap();
                let ext_udp_socket_tuple = ExtUdpSocketTuple {
                    local_port: port,
                    ext_udp_socket: ext_udp_socket,
                };
                ext_udp_socket_tuples.push(ext_udp_socket_tuple);
            }
        }
        if ext_udp_socket_tuples.is_empty() {
            panic!("Couldn't bind any ports");
        }
        let upstream_servers: Vec<UpstreamServer> = upstream_servers_str.iter()
            .map(|s| UpstreamServer::new(s).expect("Invalid upstream server address"))
            .collect();
        let upstream_servers_live: Vec<usize> = (0..upstream_servers.len()).collect();
        event_loop.timeout(TimeoutToken::HealthCheck,
                     Duration::from_millis(HEALTH_CHECK_MS))
            .expect("Unable to set up the health check");
        let mut resolver = Resolver {
            udp_socket: udp_socket,
            pending_queries: pending_queries,
            ext_udp_socket_tuples: ext_udp_socket_tuples,
            upstream_servers: upstream_servers,
            upstream_servers_live: upstream_servers_live,
            waiting_clients_count: 0,
            cache: rpdns_context.cache.clone(),
            varz: rpdns_context.varz.clone(),
            decrement_ttl: decrement_ttl,
            failover: failover,
            upstream_max_failures: upstream_max_failures,
        };
        if decrement_ttl {
            info!("Resolver mode: TTL will be automatically decremented");
        }
        if failover {
            info!("Failover mode: upstream servers will be tried sequentially");
        }
        thread::spawn(move || {
            event_loop.run(&mut resolver).expect("Event loop died");
        });
        Ok(resolver_tx)
    }
}

impl NormalizedQuestion {
    fn pick_upstream(&self,
                     _upstream_servers: &Vec<UpstreamServer>,
                     upstream_servers_live: &Vec<usize>,
                     is_retry: bool,
                     failover: bool)
                     -> Result<usize, &'static str> {
        let live_count = upstream_servers_live.len();
        if live_count == 0 {
            warn!("All upstream servers are down");
            return Err("All upstream servers are down");
        }
        if failover {
            return Ok(upstream_servers_live[0]);
        }
        let mut hs = SipHasher13::new();
        self.qname.hash(&mut hs);
        let h = hs.finish();
        let mut i = (h / (u64::MAX / (live_count as u64))) as usize;
        if i >= live_count {
            i = live_count - 1;
        }
        if is_retry {
            i = (i + 1) % live_count;
        }
        Ok(upstream_servers_live[i])
    }

    fn new_active_query<'t>
        (&self,
         upstream_servers: &Vec<UpstreamServer>,
         upstream_servers_live: &Vec<usize>,
         ext_udp_socket_tuples: &'t Vec<ExtUdpSocketTuple>,
         is_retry: bool,
         failover: bool)
         -> Result<(Vec<u8>, NormalizedQuestionMinimal, usize, &'t ExtUdpSocketTuple), &'static str> {
        let (query_packet, normalized_question_minimal) = build_query_packet(&self, false)
            .expect("Unable to build a new query packet");
        let upstream_server_idx =
            match self.pick_upstream(upstream_servers, upstream_servers_live, is_retry, failover) {
                Err(e) => return Err(e),
                Ok(upstream_server_idx) => upstream_server_idx,
            };
        let mut rng = rand::thread_rng();
        let random_token_range = Range::new(0usize, ext_udp_socket_tuples.len());
        let random_token = random_token_range.ind_sample(&mut rng);
        let ext_udp_socket_tuple = &ext_udp_socket_tuples[random_token];
        Ok((query_packet, normalized_question_minimal, upstream_server_idx, ext_udp_socket_tuple))
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn socket_udp_set_buffer_size(socket_fd: RawFd) {
    let _ = setsockopt(socket_fd, sockopt::SndBufForce, &UDP_BUFFER_SIZE);
    let _ = setsockopt(socket_fd, sockopt::RcvBufForce, &UDP_BUFFER_SIZE);
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn socket_udp_set_buffer_size(socket_fd: RawFd) {
    let _ = setsockopt(socket_fd, sockopt::SndBuf, &UDP_BUFFER_SIZE);
    let _ = setsockopt(socket_fd, sockopt::RcvBuf, &UDP_BUFFER_SIZE);
}

fn socket_udp_v4() -> io::Result<RawFd> {
    let socket_fd = socket(AddressFamily::Inet,
                           SockType::Datagram,
                           SockFlag::empty(),
                           SockLevel::Udp as i32)?;
    Ok(socket_fd)
}

fn socket_udp_v6() -> io::Result<RawFd> {
    let socket_fd = socket(AddressFamily::Inet6,
                           SockType::Datagram,
                           SockFlag::empty(),
                           SockLevel::Udp as i32)?;
    Ok(socket_fd)
}

fn set_nonblock(sock: RawFd) -> io::Result<()> {
    fcntl(sock, F_SETFL(O_NONBLOCK))?;
    Ok(())
}

fn mio_socket_udp_bound(port: u16) -> io::Result<udp::UdpSocket> {
    let actual = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), port));
    let nix_addr = SockAddr::Inet(InetAddr::from_std(&actual));
    let socket_fd = match actual {
        SocketAddr::V4(_) => socket_udp_v4()?,
        SocketAddr::V6(_) => socket_udp_v6()?,
    };
    set_nonblock(socket_fd)?;
    setsockopt(socket_fd, sockopt::ReuseAddr, &true)?;
    setsockopt(socket_fd, sockopt::ReusePort, &true)?;
    socket_udp_set_buffer_size(socket_fd);
    bind(socket_fd, &nix_addr)?;
    let socket: udp::UdpSocket = unsafe { udp::UdpSocket::from_raw_fd(socket_fd) };
    Ok(socket)
}
