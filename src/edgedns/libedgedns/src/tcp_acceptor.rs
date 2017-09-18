//! Accept connections from clients over TCP.
//!
//! This is a rewrite of the original mio-based code.

use super::{DNS_QUERY_MAX_SIZE, DNS_QUERY_MIN_SIZE, MAX_TCP_IDLE_MS};
use super::EdgeDNSContext;
use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
use bytes::BufMut;
use cache::Cache;
use client_query::*;
use dns::{self, NormalizedQuestion};
use futures::Sink;
use futures::future::{self, Future};
use futures::stream::Stream;
use futures::sync::mpsc::{channel, Sender};
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
use varz::Varz;

struct TcpAcceptor {
    timer: Timer,
    handle: Handle,
    net_tcp_listener: net::TcpListener,
    resolver_tx: Sender<ClientQuery>,
    cache: Cache,
    varz: Arc<Varz>,
    hooks_arc: Arc<RwLock<Hooks>>,
    tcp_arbitrator: TcpArbitrator,
}

pub struct TcpAcceptorCore {
    timer: Timer,
    handle: Handle,
    net_tcp_listener: net::TcpListener,
    resolver_tx: Sender<ClientQuery>,
    cache: Cache,
    varz: Arc<Varz>,
    hooks_arc: Arc<RwLock<Hooks>>,
    service_ready_tx: Option<mpsc::SyncSender<u8>>,
    tcp_arbitrator: TcpArbitrator,
}

struct TcpClientQuery {
    timer: Timer,
    wh: WriteHalf<TcpStream>,
    handle: Handle,
    resolver_tx: Sender<ClientQuery>,
    cache: Cache,
    varz: Arc<Varz>,
    hooks_arc: Arc<RwLock<Hooks>>,
}

impl TcpClientQuery {
    pub fn new(tcp_acceptor: &TcpAcceptor, wh: WriteHalf<TcpStream>) -> Self {
        TcpClientQuery {
            timer: tcp_acceptor.timer.clone(),
            wh: wh,
            handle: tcp_acceptor.handle.clone(),
            resolver_tx: tcp_acceptor.resolver_tx.clone(),
            cache: tcp_acceptor.cache.clone(),
            varz: tcp_acceptor.varz.clone(),
            hooks_arc: tcp_acceptor.hooks_arc.clone(),
        }
    }

    fn fut_process_query(
        mut self,
        normalized_question: NormalizedQuestion,
    ) -> Box<Future<Item = (), Error = io::Error>> {
        let (tcpclient_tx, tcpclient_rx) = channel(1);
        let cache_entry = self.cache.get2(&normalized_question);
        let session_state = SessionState::default();
        let client_query = ClientQuery::tcp(
            tcpclient_tx,
            normalized_question,
            self.varz.clone(),
            self.hooks_arc.clone(),
            session_state,
        );
        let wh_cell = RefCell::new(self.wh);
        let fut = tcpclient_rx
            .into_future()
            .map_err(|_| {})
            .map(|(resolver_response, _)| resolver_response)
            .and_then(move |resolver_response| match resolver_response {
                None => {
                    warn!("No resolver response - TX part of the channel closed");
                    future::err(())
                }
                Some(resolver_response) => future::ok(resolver_response),
            })
            .and_then(|resolver_response| {
                let wh = wh_cell.into_inner();
                write_all(wh, resolver_response.packet)
                    .map(|_| {})
                    .map_err(|_| {})
            });
        if let Some(mut cache_entry) = cache_entry {
            if !cache_entry.is_expired() {
                self.varz.client_queries_cached.inc();
                self.handle.spawn(fut.map_err(|_| {}));
                return client_query.response_send(&mut cache_entry.packet, None);
            }
            debug!("expired");
            self.varz.client_queries_expired.inc();
        }
        let fut_send = self.resolver_tx.send(client_query).map_err(|_| {});
        let futs = fut.join(fut_send);
        Box::new(futs.map(|_| {}).map_err(|_| io::Error::last_os_error()))
    }
}

impl TcpAcceptor {
    fn new(tcp_acceptor_core: &TcpAcceptorCore) -> Self {
        TcpAcceptor {
            timer: tcp_acceptor_core.timer.clone(),
            handle: tcp_acceptor_core.handle.clone(),
            net_tcp_listener: tcp_acceptor_core
                .net_tcp_listener
                .try_clone()
                .expect("Couldn't clone a TCP socket"),
            resolver_tx: tcp_acceptor_core.resolver_tx.clone(),
            cache: tcp_acceptor_core.cache.clone(),
            varz: tcp_acceptor_core.varz.clone(),
            hooks_arc: tcp_acceptor_core.hooks_arc.clone(),
            tcp_arbitrator: tcp_acceptor_core.tcp_arbitrator.clone(),
        }
    }

    fn fut_process_client(
        &mut self,
        client: TcpStream,
        client_addr: SocketAddr,
    ) -> Box<Future<Item = (), Error = io::Error>> {
        let (session_rx, session_idx) = match self.tcp_arbitrator.new_session(&client_addr) {
            Ok(r) => r,
            Err(_) => return Box::new(future::err(io::Error::last_os_error())),
        };
        debug!(
            "Incoming connection using TCP, session index {}",
            session_idx
        );
        let varz = self.varz.clone();
        varz.client_queries_tcp.inc();
        let (rh, wh) = client.split();
        let fut_expected_len = read_exact(rh, vec![0u8; 2]).and_then(move |(rh, len_buf)| {
            let expected_len = BigEndian::read_u16(&len_buf) as usize;
            if expected_len < DNS_QUERY_MIN_SIZE || expected_len > DNS_QUERY_MAX_SIZE {
                info!("Suspicious query length: {}", expected_len);
                varz.client_queries_errors.inc();
                return future::err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Suspicious query length",
                ));
            }
            debug!("Expected length: {}", expected_len);
            future::ok((rh, expected_len))
        });
        let fut_packet_read =
            fut_expected_len.and_then(|(rh, expected_len)| read_exact(rh, vec![0u8; expected_len]));
        let varz = self.varz.clone();
        let tcp_client_query = TcpClientQuery::new(self, wh);
        let fut_packet = fut_packet_read.and_then(move |(rh, packet)| {
            let normalized_question = match dns::normalize(&packet, true) {
                Ok(normalized_question) => normalized_question,
                Err(e) => {
                    debug!("Error while parsing the question: {}", e);
                    varz.client_queries_errors.inc();
                    return Box::new(future::err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Suspicious query",
                    ))) as Box<Future<Item = _, Error = _>>;
                }
            };
            tcp_client_query.fut_process_query(normalized_question)
        });
        let fut_timeout = self.timer
            .timeout(fut_packet, time::Duration::from_millis(MAX_TCP_IDLE_MS));
        let mut tcp_arbitrator = self.tcp_arbitrator.clone();
        let fut_with_timeout = fut_timeout.then(move |_| {
            debug!("Closing TCP connection with session index {}", session_idx);
            tcp_arbitrator.delete_session(session_idx);
            future::ok(())
        });
        let fut_session_rx = session_rx.map(|_| {});
        let fut = fut_session_rx
            .select(fut_with_timeout)
            .map(|_| {})
            .map_err(|_| io::Error::last_os_error());
        Box::new(fut) as Box<Future<Item = _, Error = _>>
    }

    fn fut_process_stream<'a>(
        mut self,
        handle: &Handle,
    ) -> impl Future<Item = (), Error = io::Error> + 'a {
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
            .map_err(|_| io::Error::last_os_error())
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
        let cache = edgedns_context.cache.clone();
        let varz = edgedns_context.varz.clone();
        let hooks_arc = edgedns_context.hooks_arc.clone();
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
                    timer,
                    handle: event_loop.handle(),
                    net_tcp_listener,
                    cache,
                    resolver_tx,
                    service_ready_tx: Some(service_ready_tx),
                    varz,
                    hooks_arc,
                    tcp_arbitrator,
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
