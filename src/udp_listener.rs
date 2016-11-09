use cache::Cache;
use client_query::*;
use dns;
use mio::*;
use nix::sys::socket::{bind, setsockopt, sockopt, AddressFamily, SockFlag, SockType, SockLevel,
                       SockAddr, socket, InetAddr};
use std::io;
use std::net::{UdpSocket, SocketAddr};
use std::os::unix::io::{RawFd, FromRawFd};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::Instant;
use super::RPDNSContext;
use varz::Varz;

use super::{UDP_BUFFER_SIZE, DNS_MAX_UDP_SIZE, DNS_QUERY_MIN_SIZE, DNS_QUERY_MAX_SIZE};

pub struct UdpListener {
    socket: UdpSocket,
    resolver_tx: channel::SyncSender<ClientQuery>,
    service_ready_tx: mpsc::SyncSender<u8>,
    cache: Cache,
    varz: Arc<Varz>,
}

impl UdpListener {
    fn run(mut self) -> io::Result<()> {
        debug!("udp listener socket={:?}", self.socket);
        self.service_ready_tx.send(0).unwrap();
        let mut packet = [0u8; DNS_MAX_UDP_SIZE];
        loop {
            let (count, client_addr) =
                self.socket.recv_from(&mut packet).expect("UDP socket error");
            self.varz.client_queries_udp.inc();
            if count < DNS_QUERY_MIN_SIZE || count > DNS_QUERY_MAX_SIZE {
                info!("Short query using UDP");
                self.varz.client_queries_errors.inc();
                continue;
            }
            let packet = &packet[..count];
            let normalized_question = match dns::normalize(packet, true) {
                Ok(normalized_question) => normalized_question,
                Err(e) => {
                    debug!("Error while parsing the question: {}", e);
                    self.varz.client_queries_errors.inc();
                    continue;
                }
            };
            let cache_entry = self.cache.get2(&normalized_question);
            if let Some(mut cache_entry) = cache_entry {
                if !cache_entry.is_expired() {
                    self.varz.client_queries_cached.inc();
                    if cache_entry.packet.len() > normalized_question.payload_size as usize {
                        debug!("cached, but has to be truncated");
                        let packet = dns::build_tc_packet(&normalized_question).unwrap();
                        let _ = self.socket.send_to(&packet, &client_addr);
                        continue;
                    }
                    debug!("cached");
                    dns::set_tid(&mut cache_entry.packet, normalized_question.tid);
                    dns::overwrite_qname(&mut cache_entry.packet, &normalized_question.qname);
                    let _ = self.socket.send_to(&cache_entry.packet, &client_addr);
                    continue;
                }
                debug!("expired");
                self.varz.client_queries_expired.inc();
            }
            let client_query = ClientQuery {
                proto: ClientQueryProtocol::UDP,
                client_tok: None,
                client_addr: Some(client_addr),
                tcpclient_tx: None,
                normalized_question: normalized_question,
                ts: Instant::now(),
            };
            let _ = self.resolver_tx.send(client_query);
        }
    }

    pub fn spawn(rpdns_context: &RPDNSContext,
                 resolver_tx: channel::SyncSender<ClientQuery>,
                 service_ready_tx: mpsc::SyncSender<u8>)
                 -> io::Result<(thread::JoinHandle<()>)> {
        let udp_socket =
            rpdns_context.udp_socket.try_clone().expect("Unable to clone the UDP listening socket");
        let udp_listener = UdpListener {
            socket: udp_socket,
            resolver_tx: resolver_tx,
            service_ready_tx: service_ready_tx,
            cache: rpdns_context.cache.clone(),
            varz: rpdns_context.varz.clone(),
        };
        let udp_listener_th = thread::spawn(move || {
            udp_listener.run().expect("Unable to spawn a UDP listener");
        });
        info!("UDP listener is ready");
        Ok((udp_listener_th))
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
    let socket_fd = try!(socket(AddressFamily::Inet,
                                SockType::Datagram,
                                SockFlag::empty(),
                                SockLevel::Udp as i32));
    Ok(socket_fd)
}

fn socket_udp_v6() -> io::Result<RawFd> {
    let socket_fd = try!(socket(AddressFamily::Inet6,
                                SockType::Datagram,
                                SockFlag::empty(),
                                SockLevel::Udp as i32));
    Ok(socket_fd)
}

pub fn socket_udp_bound(addr: &str) -> io::Result<UdpSocket> {
    let actual: SocketAddr = FromStr::from_str(addr).expect("Invalid address");
    let nix_addr = SockAddr::Inet(InetAddr::from_std(&actual));
    let socket_fd = match actual {
        SocketAddr::V4(_) => try!(socket_udp_v4()),
        SocketAddr::V6(_) => try!(socket_udp_v6()),
    };
    let _ = setsockopt(socket_fd, sockopt::ReuseAddr, &true);
    let _ = setsockopt(socket_fd, sockopt::ReusePort, &true);
    socket_udp_set_buffer_size(socket_fd);
    bind(socket_fd, &nix_addr).expect("Unable to bind a UDP socket");
    let socket: UdpSocket = unsafe { UdpSocket::from_raw_fd(socket_fd) };
    Ok(socket)
}
