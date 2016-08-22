
use bytes::{Buf, ByteBuf, MutBuf};
use cache::Cache;
use client::*;
use client_query::*;
use dns;
use mio::*;
use rand::distributions::{IndependentSample, Range};
use rand;
use resolver::*;
use slab;
use std::hash::{Hash, SipHasher13, Hasher};
use std::io;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::thread;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use super::RPDNSContext;
use varz::Varz;

type Slab<T> = slab::Slab<T, Token>;

use super::{DNS_QUERY_MIN_SIZE, DNS_QUERY_MAX_SIZE, DNS_MAX_TCP_SIZE, MAX_TCP_CLIENTS,
            MAX_TCP_IDLE_MS, MAX_TCP_HASH_DISTANCE};

const LISTENER_TOK: Token = Token(1);
pub const TCP_QUERY_HEADER_SIZE: usize = 2;

pub struct TcpListener {
    resolver_tx: Sender<ClientQuery>,
    cache: Cache,
    varz: Arc<Varz>,
}

struct TcpListenerHandler {
    cache: Cache,
    mio_listener: tcp::TcpListener,
    resolver_tx: Sender<ClientQuery>,
    tcpclient_tx: Sender<ResolverResponse>,
    clients: Vec<Option<Client>>,
    varz: Arc<Varz>,
}

impl Handler for TcpListenerHandler {
    type Timeout = Token;
    type Message = ResolverResponse;

    fn timeout(&mut self, event_loop: &mut EventLoop<Self>, client_tok: Token) {
        debug!("timeout! {:?}", client_tok);
        let client_idx = usize::from(client_tok) - 2;
        {
            let ref mut client = match self.clients[client_idx].as_mut() {
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
            client.interest.remove(EventSet::readable());
            event_loop.reregister(&client.tcp_stream,
                            client_tok,
                            client.interest,
                            PollOpt::edge() | PollOpt::oneshot())
                .expect("Cannot reregister an event set after a timeout");
            let _ = client.tcp_stream.shutdown(Shutdown::Both);
        }
        self.reset_connection(event_loop, client_idx);
    }

    fn notify(&mut self, event_loop: &mut EventLoop<Self>, resolver_response: ResolverResponse) {
        let client_tok = resolver_response.client_tok;
        debug!("notify: client_tok: {:?}", client_tok);
        let client_idx = usize::from(client_tok) - 2;
        let ref mut client = match self.clients[client_idx].as_mut() {
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
            info!("Received a response that doesn't match the question (for TCP)");
            info!("dnssec client: {} - dnssec response: {}",
                  client_normalized_question.dnssec,
                  resolver_response.dnssec);
            return;
        }
        let mut write_bufw = ByteBuf::mut_with_capacity(TCP_QUERY_HEADER_SIZE + packet_len);
        let binlen = [(packet_len >> 8) as u8, packet_len as u8];
        write_bufw.write_slice(&binlen);
        write_bufw.write_slice(&packet);
        let write_buf: ByteBuf = write_bufw.flip();
        client.write_buf = Some(write_buf);
        if let Some(mut write_buf) = client.write_buf.as_mut() {
            if let Ok(count) = client.tcp_stream.write(write_buf.bytes()) {
                write_buf.advance(count);
            }
        };
        client.interest.remove(EventSet::readable());
        event_loop.reregister(&client.tcp_stream,
                        client_tok,
                        client.interest,
                        PollOpt::edge() | PollOpt::oneshot())
            .expect("Cannot reregister an event set after a notification");
        let _ = client.tcp_stream.shutdown(Shutdown::Read);
    }

    fn ready(&mut self, event_loop: &mut EventLoop<Self>, token: Token, events: EventSet) {
        assert!(token != Token(0));
        let token_usize = usize::from(token);
        if events.is_error() {
            debug!("Error event for {:?}", token);
            if token_usize >= 2 {
                let client_idx = token_usize - 2;
                self.reset_connection(event_loop, client_idx);
            }
            return;
        }
        if events.is_hup() {
            debug!("Hup event for {:?}", token);
            if token_usize >= 2 {
                let client_idx = token_usize - 2;
                self.reset_connection(event_loop, client_idx);
            }
            return;
        }
        if events.is_readable() {
            debug!("Read event for {:?}", token);
            if token == LISTENER_TOK {
                let _ = self.accept(event_loop);
                event_loop.reregister(&self.mio_listener,
                                token,
                                EventSet::readable() | EventSet::hup(),
                                PollOpt::edge() | PollOpt::oneshot())
                    .expect("Cannot reregister an event set for a listener");
            } else {
                let client_tok = token;
                let client_idx = usize::from(client_tok) - 2;
                let _ = self.data_received(event_loop, client_tok);
                if let Some(ref client) = self.clients[client_idx] {
                    event_loop.reregister(&client.tcp_stream,
                                    client_tok,
                                    client.interest,
                                    PollOpt::edge() | PollOpt::oneshot())
                        .expect("Cannot reregister an event set after a client read");
                }
            }
        }
    }
}

impl TcpListenerHandler {
    fn accept(&mut self, event_loop: &mut EventLoop<TcpListenerHandler>) -> io::Result<()> {
        debug!("accept()");
        self.varz.client_queries_tcp.fetch_add(1, Ordering::Relaxed);
        let tcp_stream = match self.mio_listener.accept() {
            Ok(Some((tcp_stream, _))) => tcp_stream,
            Ok(None) => unreachable!(),
            Err(e) => {
                error!("Accept error: {}", e);
                return Err(e);
            }
        };
        let peer_addr = tcp_stream.peer_addr()?.ip();
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
                let ref client = self.clients[random_slot]
                    .as_ref()
                    .expect("Random TCP slot should not have been free");
                let _ = client.tcp_stream.shutdown(Shutdown::Both);
            }
            self.reset_connection(event_loop, random_slot);
            new_slot = Some(random_slot);
        }
        let mut client = Client::new(tcp_stream);
        client.interest.insert(EventSet::readable());
        let client_idx = new_slot.unwrap();
        self.clients[client_idx] = Some(client);
        let ref mut client = self.clients[client_idx].as_mut().unwrap();
        let client_tok = Token(client_idx + 2);
        debug!("Allocating new slot: {} (Token={:?})",
               new_slot.unwrap(),
               client_tok);
        event_loop.register(&client.tcp_stream,
                      client_tok,
                      client.interest,
                      PollOpt::edge() | PollOpt::oneshot())
            .expect("Unable to register a connection");
        if let Ok(timeout) =
               event_loop.timeout(client_tok, Duration::from_millis(MAX_TCP_IDLE_MS)) {
            client.timeout = Some(timeout);
        }
        Ok(())
    }

    fn data_received(&mut self,
                     _event_loop: &mut EventLoop<TcpListenerHandler>,
                     client_tok: Token)
                     -> io::Result<()> {
        debug!("data received {:?}", client_tok);
        let client_idx = usize::from(client_tok) - 2;
        let mut client =
            &mut self.clients[client_idx].as_mut().expect("Data received from an unwired client");
        let mut read_bufw = &mut client.read_bufw;
        loop {
            let res = client.tcp_stream.read(unsafe { read_bufw.mut_bytes() }).map_non_block();
            match res {
                Err(e) => {
                    error!("{:?} Error while reading socket: {:?}", client_tok, e);
                    client.interest.remove(EventSet::readable());
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
                    unsafe { read_bufw.advance(count) };
                    let bytes = read_bufw.bytes();
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
                            self.varz.client_queries_errors.fetch_add(1, Ordering::Relaxed);
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
                            self.varz.client_queries_errors.fetch_add(1, Ordering::Relaxed);
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
                                self.varz.client_queries_errors.fetch_add(1, Ordering::Relaxed);
                                let _ = client.tcp_stream.shutdown(Shutdown::Both);
                                continue;
                            }
                        };
                        let cache_entry = self.cache.get2(&normalized_question);
                        if let Some(mut cache_entry) = cache_entry {
                            if !cache_entry.is_expired() {
                                self.varz.client_queries_cached.fetch_add(1, Ordering::Relaxed);
                                debug!("cached");
                                let packet_len = cache_entry.packet.len();
                                dns::set_tid(&mut cache_entry.packet, normalized_question.tid);
                                dns::overwrite_qname(&mut cache_entry.packet,
                                                     &normalized_question.qname);
                                let mut write_bufw =
                                    ByteBuf::mut_with_capacity(TCP_QUERY_HEADER_SIZE + packet_len);
                                let binlen = [(packet_len >> 8) as u8, packet_len as u8];
                                write_bufw.write_slice(&binlen);
                                write_bufw.write_slice(&cache_entry.packet);
                                let write_buf: ByteBuf = write_bufw.flip();
                                client.write_buf = Some(write_buf);
                                if let Some(mut write_buf) = client.write_buf.as_mut() {
                                    if let Ok(count) = client.tcp_stream.write(write_buf.bytes()) {
                                        write_buf.advance(count);
                                    }
                                };
                                let _ = client.tcp_stream.shutdown(Shutdown::Read);
                                continue;
                            }
                            debug!("expired");
                            self.varz.client_queries_expired.fetch_add(1, Ordering::Relaxed);
                        }

                        let client_query = ClientQuery {
                            proto: ClientQueryProtocol::TCP,
                            client_addr: None,
                            client_tok: Some(client_tok),
                            tcpclient_tx: Some(self.tcpclient_tx.clone()),
                            normalized_question: normalized_question.clone(),
                            ts: Instant::now(),
                        };
                        client.normalized_question = Some(normalized_question);
                        client.resolving = true;
                        let _ = self.resolver_tx.send(client_query);
                        client.interest.insert(EventSet::writable());
                    }
                }
            }
        }
        Ok(())
    }

    fn reset_connection(&mut self,
                        event_loop: &mut EventLoop<TcpListenerHandler>,
                        client_idx: usize) {
        debug!("TCP reset; removing client #{:?}", client_idx);
        {
            let mut client =
                &mut self.clients[client_idx].as_mut().expect("Reseting nonexistent connection");
            assert_eq!(client.attic, false);
            client.attic = true;
            client.interest = EventSet::none();
            if let Some(ref timeout) = client.timeout {
                event_loop.clear_timeout(&timeout);
            }
            client.timeout = None;
        }
        self.clients[client_idx] = None;
    }
}

impl TcpListener {
    fn run(self, addr: String) -> io::Result<()> {
        let mut builder = EventLoopBuilder::new();
        builder.timer_capacity(MAX_TCP_CLIENTS);
        let mut event_loop = builder.build().expect("Couldn't instantiate an event loop");
        let actual = addr.parse().expect("Unable to parse the TCP address to bind");
        let mio_listener = tcp::TcpListener::bind(&actual).expect("Unable to bind the TCP socket");
        debug!("tcp listener socket={:?}", mio_listener);
        event_loop.register(&mio_listener,
                      LISTENER_TOK,
                      EventSet::readable() | EventSet::hup(),
                      PollOpt::edge() | PollOpt::oneshot())?;
        let tcpclient_tx: Sender<ResolverResponse> = event_loop.channel();
        let mut handler = TcpListenerHandler {
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
        let _ = event_loop.run(&mut handler);
        Ok(())
    }

    pub fn spawn(rpdns_context: &RPDNSContext,
                 resolver_tx: Sender<ClientQuery>)
                 -> io::Result<(thread::JoinHandle<()>)> {
        let tcp_listener = TcpListener {
            resolver_tx: resolver_tx,
            cache: rpdns_context.cache.clone(),
            varz: rpdns_context.varz.clone(),
        };
        let listen_addr = rpdns_context.listen_addr.clone();
        let tcp_listener_th = thread::spawn(move || {
            tcp_listener.run(listen_addr).expect("Unable to spawn a TCP listener");
        });
        Ok((tcp_listener_th))
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
