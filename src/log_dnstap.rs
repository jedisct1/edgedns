use config::Config;
use coarsetime::Clock;
use dnstap::{self, DNSMessage, DNSTapWriter, MessageType, SocketProtocol};
use std::net::SocketAddr;

pub struct LogDNSTap {
    dnstap_writer: DNSTapWriter,
    dnstap_identity: Option<Vec<u8>>,
    dnstap_version: Option<Vec<u8>>,
}

impl LogDNSTap {
    pub fn new(config: &Config) -> LogDNSTap {
        assert!(config.dnstap_enabled);
        let socket_path = config.dnstap_socket_path
            .clone()
            .expect("dnstap requires a UNIX socket path");
        let dnstap_builder = DNSTapWriter::build()
            .backlog(config.dnstap_backlog)
            .unix_socket_path(socket_path.clone());
        let dnstap_writer = dnstap_builder.start();
        info!("dnstap writer started -- UNIX socket path is [{}]",
              socket_path);
        let dnstap_identity = config.dnstap_identity.as_ref().map(|x| x.as_bytes().to_owned());
        let dnstap_version = config.dnstap_version.as_ref().map(|x| x.as_bytes().to_owned());
        LogDNSTap {
            dnstap_writer: dnstap_writer,
            dnstap_identity: dnstap_identity,
            dnstap_version: dnstap_version,
        }
    }

    pub fn sender(&self) -> Sender {
        Sender::new(&self.dnstap_writer,
                    self.dnstap_identity.clone(),
                    self.dnstap_version.clone())
    }
}

#[derive(Clone)]
pub struct Sender {
    template_forwarder_response: DNSMessage,
    dnstap_sender: dnstap::Sender,
}

impl Sender {
    pub fn new(dnstap_writer: &DNSTapWriter,
               dnstap_identity: Option<Vec<u8>>,
               dnstap_version: Option<Vec<u8>>)
               -> Sender {
        Sender {
            template_forwarder_response: DNSMessage::new(dnstap_identity,
                                                         dnstap_version,
                                                         MessageType::FORWARDER_RESPONSE),
            dnstap_sender: dnstap_writer.sender(),
        }
    }

    pub fn send_forwarder_response(&self,
                                   packet: &[u8],
                                   client_addr: SocketAddr,
                                   client_port: u16) {
        let mut dns_message = self.template_forwarder_response.clone();
        dns_message.socket_protocol = Some(SocketProtocol::UDP);
        dns_message.query_port = Some(client_port);
        dns_message.response_address = Some(client_addr.ip());
        dns_message.response_port = Some(client_addr.port());
        dns_message.response_packet = Some(packet.to_owned());
        dns_message.response_time = Some(Clock::recent_since_epoch().into());
        let _ = self.dnstap_sender.send(dns_message);
    }
}
