use cache::Cache;
use config::Config;
use hooks::Hooks;
use parking_lot::RwLock;
use std::sync::Arc;
use varz::Varz;

#[derive(Clone)]
pub struct Globals {
    pub config: Arc<Config>,
    pub cache: Cache,
    pub varz: Varz,
    pub hooks_arc: Arc<RwLock<Hooks>>,
}
