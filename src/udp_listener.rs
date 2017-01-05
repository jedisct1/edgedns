use cache::Cache;
use client_query::*;
use coarsetime::Instant;
use dns;
use mio::*;
use std::io;
use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use super::EdgeDNSContext;
use varz::Varz;

use super::{DNS_MAX_UDP_SIZE, DNS_QUERY_MIN_SIZE, DNS_QUERY_MAX_SIZE};

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
                ts: Instant::recent(),
            };
            let _ = self.resolver_tx.send(client_query);
        }
    }

    pub fn spawn(edgedns_context: &EdgeDNSContext,
                 resolver_tx: channel::SyncSender<ClientQuery>,
                 service_ready_tx: mpsc::SyncSender<u8>)
                 -> io::Result<(thread::JoinHandle<()>)> {
        let udp_socket = edgedns_context.udp_socket
            .try_clone()
            .expect("Unable to clone the UDP listening socket");
        let udp_listener = UdpListener {
            socket: udp_socket,
            resolver_tx: resolver_tx,
            service_ready_tx: service_ready_tx,
            cache: edgedns_context.cache.clone(),
            varz: edgedns_context.varz.clone(),
        };
        let udp_listener_th = thread::Builder::new()
            .name("udp_listener".to_string())
            .spawn(move || { udp_listener.run().expect("Unable to spawn a UDP listener"); })
            .unwrap();
        info!("UDP listener is ready");
        Ok(udp_listener_th)
    }
}
