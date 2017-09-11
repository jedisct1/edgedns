//! A `PendingQuery` is a query sent to upstream servers, whose response may
//! eventually be dispatched across multiple `ClientQuery` instances waiting for
//! the same response.

use client_query::ClientQuery;
use coarsetime::Instant;
use dns::{NormalizedQuestionKey, NormalizedQuestionMinimal};
use futures::sync::mpsc::{channel, Receiver, Sender};
use futures::sync::oneshot;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net;
use std::sync::Arc;
use upstream_server::UpstreamServer;
use varz::Varz;

pub struct PendingQuery {
    pub normalized_question_minimal: NormalizedQuestionMinimal,
    pub local_port: u16,
    pub client_queries: Vec<ClientQuery>,
    pub ts: Instant,
    pub upstream_server_idx: usize,
    pub probed_upstream_server_idx: Option<usize>,
    pub done_tx: oneshot::Sender<()>,
    pub varz: Arc<Varz>,
}

impl PendingQuery {
    pub fn new(
        normalized_question_minimal: NormalizedQuestionMinimal,
        upstream_server: &UpstreamServer,
        upstream_server_idx: usize,
        net_ext_udp_socket: &net::UdpSocket,
        client_query: &ClientQuery,
        done_tx: oneshot::Sender<()>,
    ) -> Self {
        let varz = client_query.varz.clone();
        PendingQuery {
            normalized_question_minimal: normalized_question_minimal,
            local_port: net_ext_udp_socket.local_addr().unwrap().port(),
            client_queries: vec![client_query.clone()],
            ts: Instant::recent(),
            upstream_server_idx: upstream_server_idx,
            probed_upstream_server_idx: None,
            done_tx: done_tx,
            varz: varz,
        }
    }
}

#[derive(Clone)]
pub struct PendingQueries {
    pub map_arc: Arc<RwLock<HashMap<NormalizedQuestionKey, PendingQuery>>>,
}

impl PendingQueries {
    pub fn new() -> Self {
        let map_arc = Arc::new(RwLock::new(HashMap::new()));
        PendingQueries { map_arc: map_arc }
    }
}
