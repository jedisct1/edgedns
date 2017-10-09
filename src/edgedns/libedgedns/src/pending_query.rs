//! A `PendingQuery` is a query sent to upstream servers, whose response may
//! eventually be dispatched across multiple `ClientQuery` instances waiting for
//! the same response.

use client_query::ClientQuery;
use coarsetime::Instant;
use dns::{NormalizedQuestionKey, NormalizedQuestionMinimal};
use ext_udp_listener::ExtUdpQueryKey;
use futures::sync::mpsc::{channel, Receiver, Sender};
use futures::sync::oneshot;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::{self, SocketAddr};
use std::sync::Arc;
use upstream_server::UpstreamServer;
use varz::Varz;

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct PendingQueryKey {
    pub normalized_question_key: NormalizedQuestionKey,
    pub custom_hash: (u64, u64),
}

pub struct PendingQuery {
    pub normalized_question_minimal: NormalizedQuestionMinimal,
    pub client_queries: Vec<ClientQuery>,
    pub ts: Instant,
    pub upstream_server_idx: usize,
    pub probed_upstream_server_idx: Option<usize>,
    pub done_tx: oneshot::Sender<()>,
    pub varz: Arc<Varz>,
    pub ext_udp_query_key: Option<ExtUdpQueryKey>,
    pub custom_hash: (u64, u64),
}

impl PendingQuery {
    pub fn new(
        normalized_question_minimal: NormalizedQuestionMinimal,
        upstream_server: &UpstreamServer,
        upstream_server_idx: usize,
        client_query: &ClientQuery,
        done_tx: oneshot::Sender<()>,
    ) -> Self {
        let varz = Arc::clone(&client_query.varz);
        PendingQuery {
            normalized_question_minimal,
            client_queries: vec![client_query.clone()],
            ts: Instant::recent(),
            upstream_server_idx,
            probed_upstream_server_idx: None,
            done_tx,
            varz,
            ext_udp_query_key: None,
            custom_hash: (0, 0),
        }
    }
}

#[derive(Clone)]
pub struct PendingQueries {
    pub map_arc: Arc<RwLock<HashMap<PendingQueryKey, PendingQuery>>>,
    pub ext_udp_map_arc: Arc<RwLock<HashMap<ExtUdpQueryKey, PendingQueryKey>>>,
}

impl PendingQueries {
    pub fn new() -> Self {
        let map_arc = Arc::new(RwLock::new(HashMap::new()));
        let ext_udp_map_arc = Arc::new(RwLock::new(HashMap::new()));
        PendingQueries {
            map_arc,
            ext_udp_map_arc,
        }
    }
}
