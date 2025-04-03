//! A Client Query represents a question sent from the Udp and Tcp listeners
//! to a Resolver. It does *not* represent a question sent to an upstream server.

use super::{DNS_MAX_TCP_SIZE, DNS_MAX_UDP_SIZE, DNS_QUERY_MIN_SIZE};
use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
use coarsetime::Instant;
use dns::{self, NormalizedQuestion};
use futures::sync::mpsc::Sender;
use futures::Sink;
use futures::{future, Future};
use std::io;
use std::net::{self, SocketAddr};
use std::sync::Arc;
use varz::Varz;

#[derive(Clone, Debug)]
pub struct ResolverResponse {
    pub packet: Vec<u8>,
    pub dnssec: bool,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ClientQueryProtocol {
    UDP,
    TCP,
}

#[derive(Clone)]
pub struct ClientQuery {
    pub proto: ClientQueryProtocol,
    pub client_addr: Option<SocketAddr>,
    pub tcpclient_tx: Option<Sender<ResolverResponse>>,
    pub normalized_question: NormalizedQuestion,
    pub ts: Instant,
    pub varz: Arc<Varz>,
}

impl ClientQuery {
    pub fn udp(
        client_addr: SocketAddr,
        normalized_question: NormalizedQuestion,
        varz: Arc<Varz>,
    ) -> Self {
        ClientQuery {
            proto: ClientQueryProtocol::UDP,
            client_addr: Some(client_addr),
            tcpclient_tx: None,
            normalized_question,
            ts: Instant::recent(),
            varz,
        }
    }

    pub fn tcp(
        tcpclient_tx: Sender<ResolverResponse>,
        normalized_question: NormalizedQuestion,
        varz: Arc<Varz>,
    ) -> Self {
        ClientQuery {
            proto: ClientQueryProtocol::TCP,
            client_addr: None,
            tcpclient_tx: Some(tcpclient_tx),
            normalized_question,
            ts: Instant::recent(),
            varz: varz.clone(),
        }
    }

    pub fn response_send(
        &self,
        packet: &mut [u8],
        net_udp_socket: Option<&net::UdpSocket>,
    ) -> Box<dyn Future<Item = (), Error = io::Error>> {
        let normalized_question = &self.normalized_question;
        let packet_len = packet.len();
        let mut refused_packet;
        let packet = if packet_len < DNS_QUERY_MIN_SIZE
            || (self.proto == ClientQueryProtocol::UDP && packet_len > DNS_MAX_UDP_SIZE)
            || (self.proto == ClientQueryProtocol::TCP && packet_len > DNS_MAX_TCP_SIZE)
        {
            refused_packet = dns::build_refused_packet(normalized_question).unwrap();
            refused_packet.as_mut()
        } else {
            packet
        };
        let tc_packet;
        let packet = if self.proto == ClientQueryProtocol::UDP
            && packet.len() > normalized_question.payload_size as usize
        {
            tc_packet = dns::build_tc_packet(normalized_question).unwrap();
            tc_packet.as_ref()
        } else {
            dns::set_tid(packet, normalized_question.tid);
            dns::overwrite_qname(packet, &normalized_question.qname);
            packet
        };
        match self.proto {
            ClientQueryProtocol::UDP => {
                let _ = net_udp_socket
                    .expect("Response sent using UDP but no associated UDP socket")
                    .send_to(packet, self.client_addr.unwrap());
            }
            ClientQueryProtocol::TCP => {
                let packet_len = packet.len();
                let mut tcp_packet = vec![0; 2 + packet_len];
                BigEndian::write_u16(&mut tcp_packet, packet_len as u16);
                tcp_packet[2..].copy_from_slice(packet);
                let resolver_response = ResolverResponse {
                    packet: tcp_packet,
                    dnssec: normalized_question.dnssec,
                };
                return Box::new(
                    self.tcpclient_tx
                        .clone()
                        .expect("Response sent using TCP but no associated TCP client channel")
                        .send(resolver_response)
                        .map(|_| {})
                        .map_err(|_| io::Error::last_os_error()),
                );
            }
        }
        Box::new(future::ok(()))
    }
}
