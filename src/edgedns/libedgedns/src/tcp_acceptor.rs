//! Accept connections from clients over TCP.
//!
//! This is a rewrite of the original mio-based code.

use super::{DNS_QUERY_MAX_SIZE, DNS_QUERY_MIN_SIZE, MAX_TCP_IDLE_MS};
use super::EdgeDNSContext;
use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
use bytes::BufMut;
use cache::{Cache, CacheKey};
use client_query::*;
use config::Config;
use dns::{self, NormalizedQuestion};
use errors::*;
use failure;
use futures::Sink;
use futures::future::{self, Future};
use futures::stream::Stream;
use futures::sync::mpsc::{channel, Sender};
use futures::sync::oneshot;
use hooks::{Hooks, SessionState};
use parking_lot::RwLock;
use std::cell::RefCell;
use std::io::{self, Read, Write};
use std::net::{self, SocketAddr};
use std::rc::Rc;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time;
use tcp_arbitrator::TcpArbitrator;
use tokio_core::net::{TcpListener, TcpStream};
use tokio_core::reactor::{Core, Handle};
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_io::io::{read_exact, write_all, ReadHalf, WriteHalf};
use tokio_timer::{wheel, Timer};
use upstream_server::{UpstreamServer, UpstreamServerForQuery};
use varz::Varz;

struct TcpAcceptor {
    default_upstream_servers_for_query: Rc<Vec<UpstreamServerForQuery>>,
    timer: Timer,
    net_tcp_listener: net::TcpListener,
    resolver_tx: Sender<ClientQuery>,
    cache: Cache,
    varz: Varz,
    hooks_arc: Arc<RwLock<Hooks>>,
    tcp_arbitrator: TcpArbitrator,
}

pub struct TcpAcceptorCore {
    config: Rc<Config>,
    timer: Timer,
    net_tcp_listener: net::TcpListener,
    resolver_tx: Sender<ClientQuery>,
    cache: Cache,
    varz: Varz,
    hooks_arc: Arc<RwLock<Hooks>>,
    service_ready_tx: Option<mpsc::SyncSender<u8>>,
    tcp_arbitrator: TcpArbitrator,
}

struct TcpClientQuery {
    timer: Timer,
    wh: WriteHalf<TcpStream>,
    resolver_tx: Sender<ClientQuery>,
    cache: Cache,
    varz: Varz,
    hooks_arc: Arc<RwLock<Hooks>>,
}

impl TcpClientQuery {
    pub fn new(tcp_acceptor: &TcpAcceptor, wh: WriteHalf<TcpStream>) -> Self {
        TcpClientQuery {
            timer: tcp_acceptor.timer.clone(),
            wh: wh,
            resolver_tx: tcp_acceptor.resolver_tx.clone(),
            cache: tcp_acceptor.cache.clone(),
            varz: Arc::clone(&tcp_acceptor.varz),
            hooks_arc: Arc::clone(&tcp_acceptor.hooks_arc),
        }
    }

    fn fut_process_query(&self, packet: Vec<u8>) -> impl Future<Item = (), Error = failure::Error> {
        Box::new(future::ok(()))
    }
}

impl TcpAcceptor {
    fn new(tcp_acceptor_core: &TcpAcceptorCore) -> Self {
        let config = &tcp_acceptor_core.config;
        let default_upstream_servers_for_query = config
            .upstream_servers_str
            .iter()
            .map(
                |s| UpstreamServerForQuery::from_upstream_server(&UpstreamServer::new(s).expect("Invalid upstream server address")),
            )
            .collect();
        TcpAcceptor {
            cache: tcp_acceptor_core.cache.clone(),
            default_upstream_servers_for_query: Rc::new(default_upstream_servers_for_query),
            hooks_arc: Arc::clone(&tcp_acceptor_core.hooks_arc),
            net_tcp_listener: tcp_acceptor_core
                .net_tcp_listener
                .try_clone()
                .expect("Couldn't clone a TCP socket"),
            resolver_tx: tcp_acceptor_core.resolver_tx.clone(),
            tcp_arbitrator: tcp_acceptor_core.tcp_arbitrator.clone(),
            timer: tcp_acceptor_core.timer.clone(),
            varz: Arc::clone(&tcp_acceptor_core.varz),
        }
    }

    fn fut_process_client(
        &mut self,
        client: TcpStream,
        client_addr: SocketAddr,
    ) -> impl Future<Item = (), Error = failure::Error> {
        let mut tcp_arbitrator = self.tcp_arbitrator.clone();
        let (session_rx, session_idx) = match tcp_arbitrator.new_session(&client_addr) {
            Ok(r) => r,
            Err(_) => {
                return Box::new(future::err(DNSError::TooBusy.into()))
                    as Box<Future<Item = _, Error = _>>
            }
        };
        debug!(
            "Incoming connection using TCP, session index {}",
            session_idx
        );
        let varz = Arc::clone(&self.varz);
        varz.client_queries_tcp.inc();
        let (rh, wh) = client.split();
        let varz = Arc::clone(&self.varz);

        let fut_expected_len = read_exact(rh, vec![0u8; 2])
            .map_err(|e| DNSError::Io(e).into())
            .and_then(move |(rh, len_buf)| {
                let expected_len = BigEndian::read_u16(&len_buf) as usize;
                if expected_len < DNS_QUERY_MIN_SIZE || expected_len > DNS_QUERY_MAX_SIZE {
                    info!("Suspicious query length: {}", expected_len);
                    varz.client_queries_errors.inc();
                    return future::err(DNSError::InvalidPacket.into());
                }
                debug!("Expected length: {}", expected_len);
                future::ok((rh, expected_len))
            });
        let fut_packet_read = fut_expected_len.and_then(move |(rh, expected_len)| {
            read_exact(rh, vec![0u8; expected_len]).map_err(|e| DNSError::Io(e).into())
        });
        let tcp_client_query = TcpClientQuery::new(&self, wh);
        let fut_packet = fut_packet_read
            .and_then(move |(rh, packet)| tcp_client_query.fut_process_query(packet));
        let mut tcp_arbitrator = self.tcp_arbitrator.clone();
        let fut_timeout = self.timer
            .timeout(fut_packet, time::Duration::from_millis(MAX_TCP_IDLE_MS))
            .map(|_| {})
            .map_err(|_: failure::Error| {});

        let fut_with_timeout = fut_timeout.then(move |_| {
            debug!("Closing TCP connection with session index {}", session_idx);
            tcp_arbitrator.delete_session(session_idx);
            future::ok(())
        });
        let fut_session_rx = session_rx.map(|_| {});
        let fut = fut_session_rx
            .select(fut_with_timeout)
            .map(|_| {})
            .map_err(|_| DNSError::Timeout.into());
        Box::new(fut) as Box<Future<Item = _, Error = _>>
    }

    fn fut_process_stream(
        mut self,
        handle: &Handle,
    ) -> impl Future<Item = (), Error = failure::Error> {
        let tcp_listener = TcpListener::from_listener(
            self.net_tcp_listener
                .try_clone()
                .expect("Unable to clone a TCP socket"),
            &self.net_tcp_listener.local_addr().unwrap(),
            handle,
        ).expect("Unable to create a tokio TCP listener");
        let handle = handle.clone();
        tcp_listener
            .incoming()
            .for_each(move |(client, client_addr)| {
                let fut_client = self.fut_process_client(client, client_addr);
                handle.spawn(fut_client.map_err(|_| {}));
                Ok(())
            })
            .map_err(|_| DNSError::Unexpected.into())
    }
}

impl TcpAcceptorCore {
    fn run(mut self, mut event_loop: Core, tcp_acceptor: TcpAcceptor) -> io::Result<()> {
        let service_ready_tx = self.service_ready_tx.take().unwrap();
        let handle = event_loop.handle();
        let stream = tcp_acceptor.fut_process_stream(&handle);
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
        let net_tcp_listener = edgedns_context.tcp_listener.try_clone()?;
        let config = edgedns_context.config.clone();
        let cache = edgedns_context.cache.clone();
        let varz = Arc::clone(&edgedns_context.varz);
        let hooks_arc = Arc::clone(&edgedns_context.hooks_arc);
        let tcp_arbitrator = edgedns_context.tcp_arbitrator.clone();
        let timer = wheel()
            .tick_duration(time::Duration::from_millis(MAX_TCP_IDLE_MS / 2))
            .max_timeout(time::Duration::from_millis(MAX_TCP_IDLE_MS))
            .build();

        let tcp_acceptor_th = thread::Builder::new()
            .name("tcp_acceptor".to_string())
            .spawn(move || {
                let event_loop = Core::new().unwrap();
                let tcp_acceptor_core = TcpAcceptorCore {
                    cache,
                    config: Rc::new(config),
                    hooks_arc,
                    net_tcp_listener,
                    resolver_tx,
                    service_ready_tx: Some(service_ready_tx),
                    tcp_arbitrator,
                    timer,
                    varz,
                };
                let tcp_acceptor = TcpAcceptor::new(&tcp_acceptor_core);
                tcp_acceptor_core
                    .run(event_loop, tcp_acceptor)
                    .expect("Unable to spawn a tcp listener");
            })
            .unwrap();
        info!("TCP listener is ready");
        Ok(tcp_acceptor_th)
    }
}
