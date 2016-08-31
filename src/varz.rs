use std::sync::atomic::{AtomicUsize, AtomicU64};
use std::time::Instant;

pub struct StartInstant(pub Instant);

#[derive(Default)]
pub struct Varz {
    pub start_instant: StartInstant,
    pub cache_frequent_len: AtomicUsize,
    pub cache_recent_len: AtomicUsize,
    pub cache_inserted: AtomicU64,
    pub cache_evicted: AtomicU64,
    pub client_queries_udp: AtomicUsize,
    pub client_queries_tcp: AtomicUsize,
    pub client_queries_cached: AtomicUsize,
    pub client_queries_expired: AtomicUsize,
    pub client_queries_errors: AtomicUsize,
    pub resolver_errors: AtomicUsize,
    pub resolver_received: AtomicUsize,
    pub resolver_timeout: AtomicUsize,
}

impl Default for StartInstant {
    fn default() -> StartInstant {
        StartInstant(Instant::now())
    }
}
