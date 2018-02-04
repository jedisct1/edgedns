//! A Client Query represents a question sent from the Udp and Tcp listeners
//! to a Resolver. It does *not* represent a question sent to an upstream server.

use super::{DNS_MAX_TCP_SIZE, DNS_MAX_UDP_SIZE, DNS_QUERY_MIN_SIZE};
use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
use coarsetime::Instant;
use dns::{self, NormalizedQuestion};
use dnssector::*;
use errors::*;
use failure;
use futures::{future, Future};
use futures::Sink;
use futures::sync::mpsc::Sender;
use hooks::{Hooks, SessionState, Stage};
use parking_lot::RwLock;
use std::io;
use std::net::{self, SocketAddr};
use std::sync::Arc;
use upstream_server::UpstreamServerForQuery;
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
    pub ts: Instant,
    pub session_state: SessionState,
}

impl ClientQuery {
    pub fn udp2(
        parsed_packet: &ParsedPacket,
        session_state: &mut SessionState,
    ) -> Result<(), failure::Error> {
        return Err(DNSError::Unimplemented.into());
    }

    pub fn tcp(
        tcpclient_tx: Sender<ResolverResponse>,
        normalized_question: NormalizedQuestion,
        session_state: SessionState,
        custom_hash: (u64, u64),
    ) -> Self {
        ClientQuery {
            proto: ClientQueryProtocol::TCP,
            ts: Instant::recent(),
            session_state,
        }
    }
}
