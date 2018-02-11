//! UDP Listeners accept connections from clients over UDP.
//!
//! A query whose response is cached will be answered immediately by UDP Listeners.
//!
//! Queries for non-cached responses are forwarded to Resolvers over a single-message
//! Future channel.
//!
//! UDP Listeners don't keep any state and don't schedule any futures. Which also
//! means that they don't handle timeouts if Resolvers are unresponsive.
//!
//! Timeouts are currently handled by the Resolvers themselves.

use super::EdgeDNSContext;
use cache::Cache;
use client_queries_handler::PendingQueries;
use client_query::*;
use config::Config;
use dns;
use dnssector::DNSSector;
use errors::*;
use failure;
use futures::Sink;
use futures::future::{self, Future};
use futures::oneshot;
use futures::stream::Stream;
use futures::sync::mpsc::Sender;
use globals::Globals;
use hooks::{Action, Hooks, SessionState, Stage};
use parking_lot::RwLock;
use query_router::*;
use std::io;
use std::net::{self, SocketAddr};
use std::rc::Rc;
use std::sync::{mpsc, Arc};
use std::thread;
use tokio_core::reactor::{Core, Handle};
use udp_stream::*;
use upstream_server::{UpstreamServer, UpstreamServerForQuery};
use varz::Varz;

use super::{DNS_QUERY_MAX_SIZE, DNS_QUERY_MIN_SIZE};

struct UdpAcceptor {
    config: Rc<Config>,
    default_upstream_servers_for_query: Rc<Vec<UpstreamServerForQuery>>,
    net_udp_socket: net::UdpSocket,
    resolver_tx: Sender<ClientQuery>,
    cache: Cache,
    varz: Varz,
    hooks_arc: Arc<RwLock<Hooks>>,
    pending_queries: PendingQueries,
}

pub struct UdpAcceptorCore {
    config: Rc<Config>,
    net_udp_socket: net::UdpSocket,
    resolver_tx: Sender<ClientQuery>,
    cache: Cache,
    varz: Varz,
    hooks_arc: Arc<RwLock<Hooks>>,
    pending_queries: PendingQueries,
    service_ready_tx: Option<mpsc::SyncSender<u8>>,
}

impl UdpAcceptor {
    fn new(udp_acceptor_core: &UdpAcceptorCore) -> Self {
        let config = &udp_acceptor_core.config;
        let default_upstream_servers_for_query = config
            .upstream_servers_str
            .iter()
            .map(
                |s| UpstreamServerForQuery::from_upstream_server(&UpstreamServer::new(s).expect("Invalid upstream server address")),
            )
            .collect();
        UdpAcceptor {
            config: udp_acceptor_core.config.clone(),
            default_upstream_servers_for_query: Rc::new(default_upstream_servers_for_query),
            net_udp_socket: udp_acceptor_core
                .net_udp_socket
                .try_clone()
                .expect("Couldn't clone a UDP socket"),
            resolver_tx: udp_acceptor_core.resolver_tx.clone(),
            cache: udp_acceptor_core.cache.clone(),
            varz: Arc::clone(&udp_acceptor_core.varz),
            hooks_arc: Arc::clone(&udp_acceptor_core.hooks_arc),
            pending_queries: udp_acceptor_core.pending_queries.clone(),
        }
    }

    fn fut_process_query(
        &self,
        packet: Vec<u8>,
        client_addr: SocketAddr,
    ) -> impl Future<Item = (), Error = failure::Error> {
        self.varz.client_queries_udp.inc();
        let count = packet.len();
        if count < DNS_QUERY_MIN_SIZE || count > DNS_QUERY_MAX_SIZE {
            info!("Short query using UDP");
            self.varz.client_queries_errors.inc();
            return Box::new(future::ok(())) as Box<Future<Item = _, Error = _>>;
        }
        let dns_sector = match DNSSector::new(packet) {
            Ok(dns_sector) => dns_sector,
            Err(e) => return Box::new(future::err(e)),
        };
        let parsed_packet = match dns_sector.parse() {
            Ok(parsed_packet) => parsed_packet,
            Err(e) => return Box::new(future::err(e)),
        };
        let globals = Globals {
            config: Arc::new(self.config.as_ref().clone()),
            cache: self.cache.clone(),
            varz: Arc::clone(&self.varz),
            hooks_arc: Arc::clone(&self.hooks_arc),
            resolver_tx: self.resolver_tx.clone(),
            pending_queries: self.pending_queries.clone(),
        };
        let session_state = SessionState::default();
        session_state.inner.write().upstream_servers_for_query =
            self.default_upstream_servers_for_query.as_ref().clone(); // XXX - Remove clone()
        let query_router = QueryRouter::create(
            Rc::new(globals),
            parsed_packet,
            ClientQueryProtocol::UDP,
            session_state,
        );
        let net_udp_socket_inner = self.net_udp_socket.try_clone().unwrap();
        let fut = match query_router {
            PacketOrFuture::Packet(packet) => {
                let _ = self.net_udp_socket.send_to(&packet, client_addr);
                return Box::new(future::ok(()));
            }
            PacketOrFuture::Future(fut) => Box::new(fut.map(move |packet| {
                let _ = net_udp_socket_inner.send_to(&packet, client_addr);
            })),
        };
        fut
    }

    fn fut_process_stream<'a>(
        self,
        handle: &Handle,
    ) -> impl Future<Item = (), Error = failure::Error> + 'a {
        let handle_inner = handle.clone();
        UdpStream::from_net_udp_socket(
            self.net_udp_socket
                .try_clone()
                .expect("Unable to clone UDP socket"),
            handle,
        ).expect("Cannot create a UDP stream")
            .for_each(move |(packet, client_addr)| {
                let fut = self.fut_process_query(packet, client_addr).map_err(|_| {});
                handle_inner.spawn(fut);
                future::ok(())
            })
    }
}

impl UdpAcceptorCore {
    fn run(mut self, mut event_loop: Core, udp_acceptor: UdpAcceptor) -> io::Result<()> {
        let service_ready_tx = self.service_ready_tx.take().unwrap();
        let handle = event_loop.handle();
        let stream = udp_acceptor.fut_process_stream(&handle);
        handle.spawn(stream.map_err(|_| {}).map(|_| {}));
        service_ready_tx
            .send(0)
            .map_err(|_| io::Error::last_os_error())?;
        loop {
            event_loop.turn(None)
        }
    }

    pub fn spawn(
        edgedns_context: &EdgeDNSContext,
        resolver_tx: Sender<ClientQuery>,
        service_ready_tx: mpsc::SyncSender<u8>,
    ) -> io::Result<(thread::JoinHandle<()>)> {
        let net_udp_socket = edgedns_context.udp_socket.try_clone()?;
        let config = edgedns_context.config.clone();
        let cache = edgedns_context.cache.clone();
        let varz = Arc::clone(&edgedns_context.varz);
        let hooks_arc = Arc::clone(&edgedns_context.hooks_arc);
        let pending_queries = edgedns_context.pending_queries.clone();

        let udp_acceptor_th = thread::Builder::new()
            .name("udp_acceptor".to_string())
            .spawn(move || {
                let event_loop = Core::new().unwrap();
                let udp_acceptor_core = UdpAcceptorCore {
                    config: Rc::new(config),
                    net_udp_socket,
                    cache,
                    resolver_tx,
                    service_ready_tx: Some(service_ready_tx),
                    varz,
                    hooks_arc,
                    pending_queries,
                };
                let udp_acceptor = UdpAcceptor::new(&udp_acceptor_core);
                udp_acceptor_core
                    .run(event_loop, udp_acceptor)
                    .expect("Unable to spawn a UDP listener");
            })
            .unwrap();
        info!("UDP listener is ready");
        Ok(udp_acceptor_th)
    }
}
