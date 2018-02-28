//! Resolvers accept queries from Udp and Tcp listeners whose responses were
//! not present in the cache.
//!
//! The `ResolverCore` class is also responsible for binding the UDP sockets dedicated
//! to communicating with upstream resolvers.

use super::EdgeDNSContext;
use cache::Cache;
use client_query::ClientQuery;
use coarsetime::{Duration, Instant};
use config::Config;
use dns::NormalizedQuestionKey;
use ext_udp_listener::ExtUdpListener;
use futures::Future;
use futures::sync::mpsc::{channel, Receiver, Sender};
use futures::sync::oneshot;
use globals::Globals;
use jumphash::JumpHasher;
use log_dnstap;
use net_helpers::*;
use nix::sys::socket::{bind, setsockopt, sockopt, InetAddr, SockAddr};
use parking_lot::RwLock;
use resolver_queries_handler::{PendingQueries, ResolverQueriesHandler};
use std::collections::HashMap;
use std::io;
use std::io::Cursor;
use std::net;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::FromRawFd;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::thread;
use tokio_core::reactor::{Core, Handle};
use upstream_server::{UpstreamServer, UpstreamServerForQuery};

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum LoadBalancingMode {
    Uniform,
    Fallback,
    P2,
}

pub struct ResolverCore {
    pub globals: Globals,
    pub handle: Handle,
    pub dnstap_sender: Option<log_dnstap::Sender>,
    pub net_udp_socket: net::UdpSocket,
    pub net_ext_udp_sockets_rc: Rc<Vec<net::UdpSocket>>,
    pub decrement_ttl: bool,
    pub lbmode: LoadBalancingMode,
    pub jumphasher: JumpHasher,
}

impl ResolverCore {
    pub fn spawn(edgedns_context: &EdgeDNSContext) -> io::Result<Globals> {
        let config = &edgedns_context.config;
        let net_udp_socket = edgedns_context
            .udp_socket
            .try_clone()
            .expect("Unable to clone the UDP listening socket");
        let (resolver_tx, resolver_rx): (Sender<ClientQuery>, Receiver<ClientQuery>) =
            channel(edgedns_context.config.max_active_queries);
        let mut net_ext_udp_sockets: Vec<net::UdpSocket> = Vec::new();
        let ports = if config.udp_ports > 65_535 - 1024 {
            65_535 - 1024
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
        if config.decrement_ttl {
            info!("Resolver mode: TTL will be automatically decremented");
        }
        let default_upstream_servers_for_query = config
            .upstream_servers_str
            .iter()
            .map(
                |s| UpstreamServerForQuery::from_upstream_server(&UpstreamServer::new(s).expect("Invalid upstream server address")),
            )
            .collect();
        let globals = Globals {
            config: Arc::new(edgedns_context.config.clone()),
            cache: edgedns_context.cache.clone(),
            hooks_arc: Arc::clone(&edgedns_context.hooks_arc),
            resolver_tx,
            pending_queries: edgedns_context.pending_queries.clone(),
            varz: edgedns_context.varz.clone(),
            default_upstream_servers_for_query: Arc::new(default_upstream_servers_for_query),
        };
        let dnstap_sender = edgedns_context.dnstap_sender.clone();
        let decrement_ttl = config.decrement_ttl;
        let lbmode = config.lbmode;
        let globals_inner = globals.clone();
        thread::Builder::new()
            .name("resolver".to_string())
            .spawn(move || {
                let mut event_loop = Core::new().expect("No event loop");
                let handle = event_loop.handle();
                let resolver_core = ResolverCore {
                    globals: globals_inner,
                    handle: handle.clone(),
                    dnstap_sender,
                    net_udp_socket,
                    net_ext_udp_sockets_rc: Rc::new(net_ext_udp_sockets),
                    decrement_ttl,
                    lbmode,
                    jumphasher: JumpHasher::default(),
                };
                info!("Registering UDP ports...");
                for net_ext_udp_socket in &*resolver_core.net_ext_udp_sockets_rc {
                    let ext_udp_listener = ExtUdpListener::new(&resolver_core, net_ext_udp_socket);
                    let stream = ext_udp_listener
                        .fut_process_stream(net_ext_udp_socket.try_clone().unwrap());
                    handle.spawn(stream.map_err(|_| {}));
                }
                let resolver_queries_handler = ResolverQueriesHandler::new(&resolver_core);
                let stream = resolver_queries_handler.fut_process_stream(&handle, resolver_rx);
                event_loop
                    .handle()
                    .spawn(stream.map_err(|_| {}).map(|_| {}));
                info!("UDP ports registered");
                loop {
                    event_loop.turn(None)
                }
            })
            .unwrap();
        Ok(globals)
    }
}

fn net_socket_udp_bound(port: u16) -> io::Result<net::UdpSocket> {
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
    let net_socket: net::UdpSocket = unsafe { net::UdpSocket::from_raw_fd(socket_fd) };
    Ok(net_socket)
}
