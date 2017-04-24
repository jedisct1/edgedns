
use bytes::{BufMut, BytesMut};
use cache::Cache;
use client_query::*;
use client::*;
use coarsetime::Instant;
use config::Config;
use dns;
use mio;
use mio::*;
use std::net;
use rand;
use rand::distributions::{IndependentSample, Range};
use resolver::*;
use siphasher::sip::SipHasher13;
use std::hash::{Hash, Hasher};
use std::io;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time;
use std::usize;
use super::EdgeDNSContext;
use varz::Varz;

use super::{DNS_QUERY_MIN_SIZE, DNS_QUERY_MAX_SIZE, DNS_MAX_TCP_SIZE, MAX_EVENTS_PER_BATCH,
            MAX_TCP_CLIENTS, MAX_TCP_IDLE_MS, MAX_TCP_HASH_DISTANCE};

const NOTIFY_TOK: Token = Token(usize::MAX - 1);
const TIMER_TOK: Token = Token(usize::MAX - 2);
const LISTENER_TOK: Token = Token(usize::MAX - 3);

pub const TCP_QUERY_HEADER_SIZE: usize = 2;

pub struct TcpListener {
    resolver_tx: channel::SyncSender<ClientQuery>,
    service_ready_tx: mpsc::SyncSender<u8>,
    config: Config,
    cache: Cache,
    varz: Arc<Varz>,
}

struct TcpListenerHandler {
    mio_poll: mio::Poll,
    mio_timers: timer::Timer<Token>,
    cache: Cache,
    mio_listener: tcp::TcpListener,
    resolver_tx: channel::SyncSender<ClientQuery>,
    tcpclient_tx: channel::SyncSender<ResolverResponse>,
    clients: Vec<Option<Client>>,
    varz: Arc<Varz>,
}

impl TcpListenerHandler {
    fn timeout(&mut self, client_tok: Token) {
        debug!("timeout! {:?}", client_tok);
        let client_idx = usize::from(client_tok) - 2;
        {
            let client = &mut match self.clients[client_idx].as_mut() {
                                  None => {
                debug!("Timeout from a nonexistent client received");
                return;
            }
                                  Some(client) => client,
                              };
            if client.attic {
                debug!("Timeout from a client in the attic");
                return;
            }
            let _ = client.tcp_stream.shutdown(Shutdown::Both);
        }
        self.reset_connection(client_idx);
    }

    fn notify(&mut self, resolver_response: ResolverResponse) {
        let client_tok = resolver_response.client_tok;
        debug!("notify: client_tok: {:?}", client_tok);
        let client_idx = usize::from(client_tok) - 2;
        let client = &mut match self.clients[client_idx].as_mut() {
                              None => {
            debug!("Client token not found but notification received");
            return;
        }
                              Some(client) => client,
                          };
        if !client.resolving {
            debug!("Received a notification from a client that is not resolving yet");
            return;
        }
        let packet = resolver_response.response;
        let packet_len = packet.len();
        if packet_len < DNS_QUERY_MIN_SIZE || packet_len > DNS_MAX_TCP_SIZE {
            info!("Invalid reponse length to send over TCP");
            let _ = client.tcp_stream.shutdown(Shutdown::Both);
            return;
        }
        let client_normalized_question = match client.normalized_question {
            None => {
                debug!("Missing normalized question");
                let _ = client.tcp_stream.shutdown(Shutdown::Both);
                return;
            }
            Some(ref normalized_question) => normalized_question,
        };
        let normalized_question = match dns::normalize(&packet, false) {
            Err(_) => {
                info!("Invalid response to send over TCP");
                let _ = client.tcp_stream.shutdown(Shutdown::Both);
                return;
            }
            Ok(normalized_question) => normalized_question,
        };
        if client_normalized_question.dnssec != resolver_response.dnssec ||
           client_normalized_question.minimal() != normalized_question.minimal() {
            debug!("Received a response that doesn't match the question (for TCP)");
            return;
        }
        let mut write_buf = BytesMut::with_capacity(TCP_QUERY_HEADER_SIZE + packet_len);
        let binlen = [(packet_len >> 8) as u8, packet_len as u8];
        write_buf.put_slice(&binlen);
        write_buf.put_slice(&packet);
        let _ = client.tcp_stream.write(write_buf.as_ref());
        let _ = client.tcp_stream.shutdown(Shutdown::Read);
    }

    fn ready(&mut self, token: Token, events: Ready) {
        assert_ne!(token, Token(0));
        let token_usize = usize::from(token);
        if events.is_error() {
            debug!("Error event for {:?}", token);
            if token_usize >= 2 {
                let client_idx = token_usize - 2;
                self.reset_connection(client_idx);
            }
            return;
        }
        if events.is_hup() {
            debug!("Hup event for {:?}", token);
            if token_usize >= 2 {
                let client_idx = token_usize - 2;
                self.reset_connection(client_idx);
            }
            return;
        }
        if events.is_readable() {
            debug!("Read event for {:?}", token);
            if token == LISTENER_TOK {
                let _ = self.accept();
                self.mio_poll
                    .reregister(&self.mio_listener,
                                token,
                                Ready::readable() | Ready::hup(),
                                PollOpt::edge() | PollOpt::oneshot())
                    .expect("Cannot reregister an event set for a listener");
            } else {
                let client_tok = token;
                let client_idx = usize::from(client_tok) - 2;
                let _ = self.data_received(client_tok);
                if let Some(ref client) = self.clients[client_idx] {
                    self.mio_poll
                        .reregister(&client.tcp_stream,
                                    client_tok,
                                    client.interest,
                                    PollOpt::edge() | PollOpt::oneshot())
                        .expect("Cannot reregister an event set after a client read");
                }
            }
        }
    }

    fn accept(&mut self) -> io::Result<()> {
        debug!("accept()");
        self.varz.client_queries_tcp.inc();
        let tcp_stream = match self.mio_listener.accept() {
            Ok((tcp_stream, _)) => tcp_stream,
            Err(e) => {
                error!("Accept error: {}", e);
                return Err(e);
            }
        };
        let peer_addr = try!(tcp_stream.peer_addr()).ip();
        let mut hs = SipHasher13::new();
        peer_addr.hash(&mut hs);
        let h = hs.finish();
        let slot = h as usize % self.clients.len();
        debug!("New ideal slot would be {}", slot);
        let mut new_slot = None;
        for i in 0..MAX_TCP_HASH_DISTANCE {
            let probed_slot = (slot + i) % self.clients.len();
            if self.clients[probed_slot].is_none() {
                new_slot = Some(probed_slot);
                break;
            }
        }
        if new_slot.is_none() {
            debug!("TCP hash section is full");
            let mut rng = rand::thread_rng();
            let random_distance = Range::new(0, MAX_TCP_HASH_DISTANCE);
            let random_slot = (slot + random_distance.ind_sample(&mut rng)) % self.clients.len();
            {
                let client = &self.clients[random_slot]
                                  .as_ref()
                                  .expect("Random TCP slot should not have been free");
                let _ = client.tcp_stream.shutdown(Shutdown::Both);
            }
            self.reset_connection(random_slot);
            new_slot = Some(random_slot);
        }
        let mut client = Client::new(tcp_stream);
        client.interest.insert(Ready::readable());
        let client_idx = new_slot.unwrap();
        self.clients[client_idx] = Some(client);
        let client = &mut self.clients[client_idx].as_mut().unwrap();
        let client_tok = Token(client_idx + 2);
        debug!("Allocating new slot: {} (Token={:?})",
               new_slot.unwrap(),
               client_tok);
        self.mio_poll
            .register(&client.tcp_stream,
                      client_tok,
                      client.interest,
                      PollOpt::edge() | PollOpt::oneshot())
            .expect("Unable to register a connection");
        if let Ok(timeout) =
            self.mio_timers
                .set_timeout(time::Duration::from_millis(MAX_TCP_IDLE_MS), client_tok) {
            client.timeout = Some(timeout);
        }
        Ok(())
    }

    fn data_received(&mut self, client_tok: Token) -> io::Result<()> {
        debug!("data received {:?}", client_tok);
        let client_idx = usize::from(client_tok) - 2;
        let mut client = &mut self.clients[client_idx]
                                  .as_mut()
                                  .expect("Data received from an unwired client");
        let mut read_buf = &mut client.read_buf;
        loop {
            let res = client
                .tcp_stream
                .read(unsafe { read_buf.bytes_mut() })
                .map_non_block();
            match res {
                Err(e) => {
                    error!("{:?} Error while reading socket: {:?}", client_tok, e);
                    break;
                }
                Ok(None) => {
                    debug!("Client socket is empty");
                    break;
                }
                Ok(Some(0)) => {
                    debug!("Client socket is closed; nothing to read");
                    break;
                }
                Ok(Some(count)) => {
                    debug!("Client socket got {} bytes", count);
                    unsafe { BufMut::advance_mut(read_buf, count) };
                    let bytes = read_buf.as_ref();
                    let bytes_len = bytes.len();
                    if bytes_len < TCP_QUERY_HEADER_SIZE {
                        assert!(client.expected_len.is_none());
                        continue;
                    }
                    if client.expected_len.is_none() {
                        let expected_len = ((bytes[0] as u16) << 8) | (bytes[1] as u16);
                        if (expected_len as usize) < DNS_QUERY_MIN_SIZE ||
                           (expected_len as usize) > DNS_QUERY_MAX_SIZE {
                            info!("Suspicious query length");
                            self.varz.client_queries_errors.inc();
                            let _ = client.tcp_stream.shutdown(Shutdown::Both);
                            continue;
                        } else {
                            debug!("Expected length: {}", expected_len);
                            client.expected_len = Some(expected_len);
                        }
                    }
                    if let Some(expected_len) = client.expected_len {
                        if bytes_len > TCP_QUERY_HEADER_SIZE + expected_len as usize {
                            info!("Large query");
                            self.varz.client_queries_errors.inc();
                            let _ = client.tcp_stream.shutdown(Shutdown::Both);
                            continue;
                        }
                        if bytes_len < TCP_QUERY_HEADER_SIZE + expected_len as usize {
                            info!("Partial query");
                            continue;
                        }
                        assert_eq!(bytes_len, TCP_QUERY_HEADER_SIZE + expected_len as usize);
                        let packet = &bytes[TCP_QUERY_HEADER_SIZE..];
                        let normalized_question = match dns::normalize(packet, true) {
                            Ok(normalized_question) => normalized_question,
                            Err(e) => {
                                debug!("Error while parsing the question: {}", e);
                                self.varz.client_queries_errors.inc();
                                let _ = client.tcp_stream.shutdown(Shutdown::Both);
                                continue;
                            }
                        };
                        let cache_entry = self.cache.get2(&normalized_question);
                        if let Some(mut cache_entry) = cache_entry {
                            if !cache_entry.is_expired() {
                                self.varz.client_queries_cached.inc();
                                debug!("cached");
                                let packet_len = cache_entry.packet.len();
                                dns::set_tid(&mut cache_entry.packet, normalized_question.tid);
                                dns::overwrite_qname(&mut cache_entry.packet,
                                                     &normalized_question.qname);
                                let mut write_buf = BytesMut::with_capacity(TCP_QUERY_HEADER_SIZE +
                                                                            packet_len);
                                let binlen = [(packet_len >> 8) as u8, packet_len as u8];
                                write_buf.put_slice(&binlen);
                                write_buf.put_slice(&cache_entry.packet);
                                let _ = client.tcp_stream.write(write_buf.as_ref());
                                let _ = client.tcp_stream.shutdown(Shutdown::Read);
                                continue;
                            }
                            debug!("expired");
                            self.varz.client_queries_expired.inc();
                        }

                        let client_query = ClientQuery {
                            proto: ClientQueryProtocol::TCP,
                            client_addr: None,
                            client_tok: Some(client_tok),
                            tcpclient_tx: Some(self.tcpclient_tx.clone()),
                            normalized_question: normalized_question.clone(),
                            ts: Instant::recent(),
                        };
                        client.normalized_question = Some(normalized_question);
                        client.resolving = true;
                        let _ = self.resolver_tx.send(client_query);
                        client.interest.insert(Ready::writable());
                    }
                }
            }
        }
        Ok(())
    }

    fn reset_connection(&mut self, client_idx: usize) {
        debug!("TCP reset; removing client #{:?}", client_idx);
        {
            let mut client = &mut self.clients[client_idx]
                                      .as_mut()
                                      .expect("Reseting nonexistent connection");
            assert_eq!(client.attic, false);
            client.attic = true;
            client.interest = Ready::none();
            if let Some(ref timeout) = client.timeout {
                self.mio_timers.cancel_timeout(timeout);
            }
            client.timeout = None;
        }
        self.clients[client_idx] = None;
    }
}

impl TcpListener {
    fn run(self, tcp_socket: net::TcpListener, addr: String) -> io::Result<()> {
        let mio_poll = mio::Poll::new().expect("Couldn't instantiate an event loop");
        let mio_timers = timer::Builder::default()
            .num_slots(MAX_TCP_CLIENTS / 256)
            .capacity(MAX_TCP_CLIENTS)
            .build();
        mio_poll
            .register(&mio_timers, TIMER_TOK, Ready::readable(), PollOpt::edge())
            .expect("Could not register the timers");
        let actual = addr.parse()
            .expect("Unable to parse the TCP address to bind");
        let mio_listener = tcp::TcpListener::from_listener(tcp_socket, &actual)
            .expect("Unable to use the TCP socket");
        debug!("tcp listener socket={:?}", mio_listener);
        self.service_ready_tx.send(1).unwrap();
        try!(mio_poll.register(&mio_listener,
                               LISTENER_TOK,
                               Ready::readable() | Ready::hup(),
                               PollOpt::edge() | PollOpt::oneshot()));
        let (tcpclient_tx, tcpclient_rx): (channel::SyncSender<ResolverResponse>,
                                           channel::Receiver<ResolverResponse>) =
            channel::sync_channel(self.config.max_active_queries);
        mio_poll
            .register(&tcpclient_rx, NOTIFY_TOK, Ready::all(), PollOpt::edge())
            .expect("Could not register the resolver channel");
        let mut handler = TcpListenerHandler {
            mio_poll: mio_poll,
            mio_timers: mio_timers,
            cache: self.cache,
            mio_listener: mio_listener,
            resolver_tx: self.resolver_tx.clone(),
            tcpclient_tx: tcpclient_tx,
            clients: Vec::with_capacity(MAX_TCP_CLIENTS),
            varz: self.varz,
        };
        for _ in 0..MAX_TCP_CLIENTS {
            handler.clients.push(None)
        }
        info!("TCP listener is ready");
        let mut events = mio::Events::with_capacity(MAX_EVENTS_PER_BATCH);
        loop {
            match handler.mio_poll.poll(&mut events, None) {
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
                _ => {}
            }
            for event in events.iter() {
                match event.token() {
                    NOTIFY_TOK => {
                        while let Ok(client_query) = tcpclient_rx.try_recv() {
                            handler.notify(client_query)
                        }
                    }
                    TIMER_TOK => {
                        while let Some(timeout_token) = handler.mio_timers.poll() {
                            handler.timeout(timeout_token)
                        }
                    }
                    token => handler.ready(token, event.kind()),
                }
            }
        }
    }

    pub fn spawn(edgedns_context: &EdgeDNSContext,
                 resolver_tx: channel::SyncSender<ClientQuery>,
                 service_ready_tx: mpsc::SyncSender<u8>)
                 -> io::Result<(thread::JoinHandle<()>)> {
        let tcp_socket = edgedns_context
            .tcp_socket
            .try_clone()
            .expect("Unable to clone the TCP listening socket");
        let tcp_listener = TcpListener {
            resolver_tx: resolver_tx,
            service_ready_tx: service_ready_tx,
            config: edgedns_context.config.clone(),
            cache: edgedns_context.cache.clone(),
            varz: edgedns_context.varz.clone(),
        };
        let listen_addr = edgedns_context.listen_addr.clone();
        let tcp_listener_th = thread::Builder::new()
            .name("tcp_listener".to_string())
            .spawn(move || {
                       tcp_listener
                           .run(tcp_socket, listen_addr)
                           .expect("Unable to spawn a TCP listener");
                   })
            .unwrap();
        Ok(tcp_listener_th)
    }
}

trait MapNonBlock<T> {
    fn map_non_block(self) -> io::Result<Option<T>>;
}

impl<T> MapNonBlock<T> for io::Result<T> {
    fn map_non_block(self) -> io::Result<Option<T>> {
        use std::io::ErrorKind::WouldBlock;

        match self {
            Ok(value) => Ok(Some(value)),
            Err(err) => {
                if let WouldBlock = err.kind() {
                    Ok(None)
                } else {
                    Err(err)
                }
            }
        }
    }
}
