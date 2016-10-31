use prometheus::{Counter, Gauge};
use std::time::Instant;

pub struct StartInstant(pub Instant);

pub struct Varz {
    pub start_instant: StartInstant,
    pub uptime: Gauge,
    pub cache_frequent_len: Gauge,
    pub cache_recent_len: Gauge,
    pub cache_test_len: Gauge,
    pub cache_inserted: Gauge,
    pub cache_evicted: Gauge,
    pub client_qps: Gauge,
    pub client_queries: Gauge,
    pub client_queries_udp: Counter,
    pub client_queries_tcp: Counter,
    pub client_queries_cached: Counter,
    pub client_queries_expired: Counter,
    pub client_queries_errors: Counter,
    pub upstream_errors: Counter,
    pub upstream_received: Counter,
    pub upstream_timeout: Counter,
}

impl Varz {
    pub fn new() -> Varz {
        Varz {
            start_instant: StartInstant::default(),
            uptime: register_gauge!(opts!("edgedns_uptime",
                                          "Uptime",
                                          labels!{"handler" => "all",}))
                .unwrap(),
            cache_frequent_len: register_gauge!(opts!("edgedns_cache_frequent_len",
                                                      "Number of entries in the cached set of \
                                                       frequent items",
                                                      labels!{"handler" => "all",}))
                .unwrap(),
            cache_recent_len: register_gauge!(opts!("edgedns_cache_recent_len",
                                                    "Number of entries in the cached set of \
                                                     recent items",
                                                    labels!{"handler" => "all",}))
                .unwrap(),
            cache_test_len: register_gauge!(opts!("edgedns_cache_test_len",
                                                  "Number of entries in the cached set of \
                                                   staged items",
                                                  labels!{"handler" => "all",}))
                .unwrap(),
            cache_inserted: register_gauge!(opts!("edgedns_cache_inserted",
                                                  "Number of entries added to the cache",
                                                  labels!{"handler" => "all",}))
                .unwrap(),
            cache_evicted: register_gauge!(opts!("edgedns_cache_evicted",
                                                 "Number of entries evicted from the cache",
                                                 labels!{"handler" => "all",}))
                .unwrap(),
            client_qps: register_gauge!(opts!("edgedns_client_qps",
                                              "Average number of client queries per second",
                                              labels!{"handler" => "all",}))
                .unwrap(),
            client_queries: register_gauge!(opts!("edgedns_client_queries",
                                                  "Number of client queries received",
                                                  labels!{"handler" => "all",}))
                .unwrap(),
            client_queries_udp: register_counter!(opts!("edgedns_client_queries_udp",
                                                        "Number of client queries received \
                                                         using UDP",
                                                        labels!{"handler" => "all",}))
                .unwrap(),
            client_queries_tcp: register_counter!(opts!("edgedns_client_queries_tcp",
                                                        "Number of client queries received \
                                                         using TCP",
                                                        labels!{"handler" => "all",}))
                .unwrap(),
            client_queries_cached: register_counter!(opts!("edgedns_client_queries_cached",
                                                           "Number of client queries sent from \
                                                            the cache",
                                                           labels!{"handler" => "all",}))
                .unwrap(),
            client_queries_expired: register_counter!(opts!("edgedns_client_queries_expired",
                                                            "Number of expired client queries",
                                                            labels!{"handler" => "all",}))
                .unwrap(),
            client_queries_errors: register_counter!(opts!("edgedns_client_queries_errors",
                                                           "Number of bogus client queries",
                                                           labels!{"handler" => "all",}))
                .unwrap(),
            upstream_errors: register_counter!(opts!("edgedns_upstream_errors",
                                                     "Number of bogus upstream servers responses",
                                                     labels!{"handler" => "all",}))
                .unwrap(),
            upstream_received: register_counter!(opts!("edgedns_upstream_received",
                                                       "Number of upstream servers responses",
                                                       labels!{"handler" => "all",}))
                .unwrap(),
            upstream_timeout: register_counter!(opts!("edgedns_upstream_timeout",
                                                      "Number of upstream servers responses \
                                                       having timed out",
                                                      labels!{"handler" => "all",}))
                .unwrap(),
        }
    }
}

impl Default for Varz {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for StartInstant {
    fn default() -> StartInstant {
        StartInstant(Instant::now())
    }
}
