use cache::Cache;
use client_query::ClientQuery;
use config::Config;
use futures::sync::mpsc::Sender;
use hooks::Hooks;
use parking_lot::RwLock;
use resolver_queries_handler::PendingQueries;
use std::collections::HashMap;
use std::sync::Arc;
use upstream_server::UpstreamServerForQuery;
use varz::Varz;

#[derive(Clone)]
pub struct Globals {
    pub config: Arc<Config>,
    pub cache: Cache,
    pub varz: Varz,
    pub hooks_arc: Arc<RwLock<Hooks>>,
    pub resolver_tx: Sender<ClientQuery>,
    pub pending_queries: PendingQueries,
    pub default_upstream_servers_for_query: Arc<Vec<UpstreamServerForQuery>>,
}
