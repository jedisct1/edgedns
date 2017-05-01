//! Resolvers accept queries from Udp and Tcp listeners whose responses were
//! not present in the cache.
//!
//! The `ResolverCore` class is also responsible for binding the UDP sockets dedicated
//! to communicating with upstream resolvers.

use cache::Cache;
use client_queries_handler::ClientQueriesHandler;
use client_query::ClientQuery;
use coarsetime::Instant;
use config::Config;
use dns::{NormalizedQuestionKey, NormalizedQuestionMinimal};
use ext_response::ExtResponse;
use futures::Future;
use futures::sync::mpsc::{channel, Receiver, Sender};
use futures::sync::oneshot;
use jumphash::JumpHasher;
use log_dnstap;
use net_helpers::*;
use nix::sys::socket::{bind, setsockopt, sockopt, SockAddr, InetAddr};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::io::Cursor;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::net;
use std::os::unix::io::FromRawFd;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::thread;
use super::{EdgeDNSContext, UPSTREAM_INITIAL_TIMEOUT_MS};
use tokio_core::reactor::{Core, Handle};
use upstream_server::UpstreamServer;
use varz::Varz;

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum LoadBalancingMode {
    Uniform,
    Fallback,
    P2,
}

pub struct PendingQuery {
    pub normalized_question_minimal: NormalizedQuestionMinimal,
    pub local_port: u16,
    pub client_queries: Vec<ClientQuery>,
    pub ts: Instant,
    pub delay: u64,
    pub upstream_server_idx: usize,
    pub probed_upstream_server_idx: Option<usize>,
    pub done_tx: oneshot::Sender<()>,
}

impl PendingQuery {
    pub fn new(normalized_question_minimal: NormalizedQuestionMinimal,
               upstream_server: &UpstreamServer,
               upstream_server_idx: usize,
               net_ext_udp_socket: &net::UdpSocket,
               client_query: &ClientQuery,
               done_tx: oneshot::Sender<()>)
               -> Self {
        PendingQuery {
            normalized_question_minimal: normalized_question_minimal,
            local_port: net_ext_udp_socket.local_addr().unwrap().port(),
            client_queries: vec![client_query.clone()],
            ts: Instant::recent(),
            delay: UPSTREAM_INITIAL_TIMEOUT_MS,
            upstream_server_idx: upstream_server_idx,
            probed_upstream_server_idx: None,
            done_tx: done_tx,
        }
    }
}

#[derive(Clone)]
pub struct PendingQueries {
    pub map_arc: Arc<RwLock<HashMap<NormalizedQuestionKey, PendingQuery>>>,
}

impl PendingQueries {
    pub fn new() -> Self {
        let map_arc = Arc::new(RwLock::new(HashMap::new()));
        PendingQueries { map_arc: map_arc }
    }
}

pub struct ResolverCore {
    pub config: Rc<Config>,
    pub handle: Handle,
    pub dnstap_sender: Option<log_dnstap::Sender>,
    pub net_udp_socket: net::UdpSocket,
    pub net_ext_udp_sockets_rc: Rc<Vec<net::UdpSocket>>,
    pub pending_queries: PendingQueries,
    pub upstream_servers_arc: Arc<RwLock<Vec<UpstreamServer>>>,
    pub upstream_servers_live_arc: Arc<RwLock<Vec<usize>>>,
    pub waiting_clients_count: Rc<AtomicUsize>,
    pub cache: Cache,
    pub varz: Arc<Varz>,
    pub decrement_ttl: bool,
    pub lbmode: LoadBalancingMode,
    pub upstream_max_failures: u32,
    pub jumphasher: JumpHasher,
}

impl ResolverCore {
    pub fn spawn(edgedns_context: &EdgeDNSContext) -> io::Result<Sender<ClientQuery>> {
        let config = &edgedns_context.config;
        let net_udp_socket = edgedns_context
            .udp_socket
            .try_clone()
            .expect("Unable to clone the UDP listening socket");
        let (resolver_tx, resolver_rx): (Sender<ClientQuery>, Receiver<ClientQuery>) =
            channel(edgedns_context.config.max_active_queries);
        let pending_queries = PendingQueries::new();
        let mut net_ext_udp_sockets: Vec<net::UdpSocket> = Vec::new();
        let ports = if config.udp_ports > 65535 - 1024 {
            65535 - 1024
        } else {
            config.udp_ports
        };
        for port in 1024..1024 + ports {
            if (port + 1) % 1024 == 0 {
                info!("Binding ports... {}/{}", port, ports)
            }
            if let Ok(net_ext_udp_socket) = net_socket_udp_bound(port) {
                net_ext_udp_sockets.push(net_ext_udp_socket);
            }
        }
        if net_ext_udp_sockets.is_empty() {
            panic!("Couldn't bind any ports");
        }
        let upstream_servers: Vec<UpstreamServer> = config
            .upstream_servers
            .iter()
            .map(|s| UpstreamServer::new(s).expect("Invalid upstream server address"))
            .collect();
        let upstream_servers_live: Vec<usize> = (0..config.upstream_servers.len()).collect();
        let upstream_servers_live_arc = Arc::new(RwLock::new(upstream_servers_live));
        let upstream_servers_arc = Arc::new(RwLock::new(upstream_servers));
        if config.decrement_ttl {
            info!("Resolver mode: TTL will be automatically decremented");
        }
        let config = edgedns_context.config.clone();
        let dnstap_sender = edgedns_context.dnstap_sender.clone();
        let cache = edgedns_context.cache.clone();
        let varz = edgedns_context.varz.clone();
        let decrement_ttl = config.decrement_ttl;
        let lbmode = config.lbmode;
        let upstream_max_failures = config.upstream_max_failures;
        thread::Builder::new()
            .name("resolver".to_string())
            .spawn(move || {
                let mut event_loop = Core::new().expect("No event loop");
                let handle = event_loop.handle();
                let resolver_core = ResolverCore {
                    config: Rc::new(config),
                    handle: handle.clone(),
                    dnstap_sender: dnstap_sender,
                    net_udp_socket: net_udp_socket,
                    net_ext_udp_sockets_rc: Rc::new(net_ext_udp_sockets),
                    pending_queries: pending_queries,
                    upstream_servers_arc: upstream_servers_arc,
                    upstream_servers_live_arc: upstream_servers_live_arc,
                    waiting_clients_count: Rc::new(AtomicUsize::new(0)),
                    cache: cache,
                    varz: varz,
                    decrement_ttl: decrement_ttl,
                    lbmode: lbmode,
                    upstream_max_failures: upstream_max_failures,
                    jumphasher: JumpHasher::default(),
                };
                info!("Registering UDP ports...");
                for net_ext_udp_socket in &*resolver_core.net_ext_udp_sockets_rc {
                    let ext_response_listener =
                        ExtResponse::new(&resolver_core,
                                         net_ext_udp_socket.local_addr().unwrap().port());
                    let stream =
                        ext_response_listener.fut_process_stream(&handle, net_ext_udp_socket);
                    handle.spawn(stream.map_err(|_| {}).map(|_| {}));
                }
                let client_queries_handler = ClientQueriesHandler::new(&resolver_core);
                let stream = client_queries_handler.fut_process_stream(&handle, resolver_rx);
                event_loop
                    .handle()
                    .spawn(stream.map_err(|_| {}).map(|_| {}));
                info!("UDP ports registered");
                loop {
                    event_loop.turn(None)
                }
            })
            .unwrap();
        Ok(resolver_tx)
    }
}

fn net_socket_udp_bound(port: u16) -> io::Result<net::UdpSocket> {
    let actual = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), port));
    let nix_addr = SockAddr::Inet(InetAddr::from_std(&actual));
    let socket_fd = match actual {
        SocketAddr::V4(_) => try!(socket_udp_v4()),
        SocketAddr::V6(_) => try!(socket_udp_v6()),
    };
    try!(set_nonblock(socket_fd));
    try!(setsockopt(socket_fd, sockopt::ReuseAddr, &true));
    try!(setsockopt(socket_fd, sockopt::ReusePort, &true));
    socket_udp_set_buffer_size(socket_fd);
    try!(bind(socket_fd, &nix_addr));
    let net_socket: net::UdpSocket = unsafe { net::UdpSocket::from_raw_fd(socket_fd) };
    Ok(net_socket)
}
