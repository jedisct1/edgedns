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
use resolver_queries_handler::PendingQueries;
use std::io;
use std::net::{self, SocketAddr};
use std::rc::Rc;
use std::sync::{mpsc, Arc};
use std::thread;
use tokio_core::reactor::{Core, Handle};
use tokio_timer::{wheel, Timer};
use udp_stream::*;
use varz::Varz;

use super::{DNS_QUERY_MAX_SIZE, DNS_QUERY_MIN_SIZE};

struct UdpAcceptor {
    globals: Globals,
    net_udp_socket: Rc<net::UdpSocket>,
    timer: Timer,
}

pub struct UdpAcceptorCore {
    globals: Globals,
    net_udp_socket: Rc<net::UdpSocket>,
    service_ready_tx: Option<mpsc::SyncSender<u8>>,
    timer: Timer,
}

impl UdpAcceptor {
    fn new(udp_acceptor_core: &UdpAcceptorCore) -> Self {
        UdpAcceptor {
            globals: udp_acceptor_core.globals.clone(),
            net_udp_socket: udp_acceptor_core.net_udp_socket.clone(),
            timer: udp_acceptor_core.timer.clone(),
        }
    }

    fn fut_process_query(
        &self,
        packet: Vec<u8>,
        client_addr: SocketAddr,
    ) -> impl Future<Item = (), Error = failure::Error> {
        self.globals.varz.client_queries_udp.inc();
        let count = packet.len();
        if count < DNS_QUERY_MIN_SIZE || count > DNS_QUERY_MAX_SIZE {
            info!("Short query using UDP");
            self.globals.varz.client_queries_errors.inc();
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
        let session_state = SessionState::default();
        session_state.inner.write().upstream_servers_for_query = self.globals
            .default_upstream_servers_for_query
            .as_ref()
            .clone();
        let query_router = QueryRouter::create(
            Rc::new(self.globals.clone()),
            parsed_packet,
            ClientQueryProtocol::UDP,
            session_state,
            self.timer.clone(),
        );
        let net_udp_socket_inner = self.net_udp_socket.clone();
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
        globals: Globals,
        edgedns_context: &EdgeDNSContext,
        resolver_tx: Sender<ClientQuery>,
        service_ready_tx: mpsc::SyncSender<u8>,
    ) -> io::Result<(thread::JoinHandle<()>)> {
        let net_udp_socket = edgedns_context.udp_socket.try_clone()?;
        let timer = wheel()
            .max_capacity(edgedns_context.config.max_active_queries)
            .build();

        let udp_acceptor_th = thread::Builder::new()
            .name("udp_acceptor".to_string())
            .spawn(move || {
                let event_loop = Core::new().unwrap();
                let udp_acceptor_core = UdpAcceptorCore {
                    globals,
                    net_udp_socket: Rc::new(net_udp_socket),
                    service_ready_tx: Some(service_ready_tx),
                    timer,
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
