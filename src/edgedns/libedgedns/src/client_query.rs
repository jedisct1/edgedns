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
use futures::sync::oneshot;
use futures::task::{self, Task};
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

pub struct ClientQuery {
    pub response_tx: oneshot::Sender<ResolverResponse>,
    pub normalized_question: NormalizedQuestion,
    pub proto: ClientQueryProtocol,
    pub ts: Instant,
    pub session_state: SessionState,
    pub task: Task,
}

impl ClientQuery {
    pub fn udp(
        response_tx: oneshot::Sender<ResolverResponse>,
        parsed_packet: &mut ParsedPacket,
        session_state: SessionState,
    ) -> Result<ClientQuery, failure::Error> {
        let normalized_question = NormalizedQuestion::from_parsed_packet(parsed_packet)?;
        Ok(ClientQuery {
            normalized_question,
            proto: ClientQueryProtocol::UDP,
            ts: Instant::recent(),
            session_state,
            task: task::current(),
            response_tx,
        })
    }

    pub fn tcp(
        response_tx: oneshot::Sender<ResolverResponse>,
        normalized_question: NormalizedQuestion,
        session_state: SessionState,
        custom_hash: (u64, u64),
    ) -> Self {
        ClientQuery {
            normalized_question,
            proto: ClientQueryProtocol::TCP,
            ts: Instant::recent(),
            session_state,
            task: task::current(),
            response_tx,
        }
    }
}
