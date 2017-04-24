use config::Config;
use coarsetime::{Duration, Instant};
use clockpro_cache::*;
use dns;
use dns::{NormalizedQuestion, NormalizedQuestionKey, DNS_CLASS_IN, DNS_RCODE_NXDOMAIN};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
pub struct CacheEntry {
    pub expiration: Instant,
    pub packet: Vec<u8>,
}

impl CacheEntry {
    pub fn is_expired(&self) -> bool {
        let now = Instant::recent();
        now > self.expiration
    }
}

#[derive(Clone)]
pub struct Cache {
    config: Config,
    arc_mx: Arc<Mutex<ClockProCache<NormalizedQuestionKey, CacheEntry>>>,
}

pub struct CacheStats {
    pub frequent_len: usize,
    pub recent_len: usize,
    pub test_len: usize,
    pub inserted: u64,
    pub evicted: u64,
}

impl Cache {
    pub fn new(config: Config) -> Cache {
        let arc = ClockProCache::new(config.cache_size).unwrap();
        let arc_mx = Arc::new(Mutex::new(arc));
        Cache {
            config: config,
            arc_mx: arc_mx,
        }
    }

    pub fn stats(&self) -> CacheStats {
        let cache = self.arc_mx.lock().unwrap();
        CacheStats {
            frequent_len: cache.frequent_len(),
            recent_len: cache.recent_len(),
            test_len: cache.test_len(),
            inserted: cache.inserted(),
            evicted: cache.evicted(),
        }
    }

    pub fn insert(&mut self,
                  normalized_question_key: NormalizedQuestionKey,
                  packet: Vec<u8>,
                  ttl: u32)
                  -> bool {
        debug_assert!(packet.len() >= dns::DNS_HEADER_SIZE);
        if packet.len() < dns::DNS_HEADER_SIZE {
            return false;
        }
        let now = Instant::recent();
        let duration = Duration::from_secs(ttl as u64);
        let expiration = now + duration;
        let cache_entry = CacheEntry {
            expiration: expiration,
            packet: packet,
        };
        let mut cache = self.arc_mx.lock().unwrap();
        cache.insert(normalized_question_key, cache_entry)
    }

    pub fn get(&mut self, normalized_question_key: &NormalizedQuestionKey) -> Option<CacheEntry> {
        let mut cache = self.arc_mx.lock().unwrap();
        cache
            .get_mut(normalized_question_key)
            .and_then(|res| Some(res.clone()))
    }

    pub fn get2(&mut self, normalized_question: &NormalizedQuestion) -> Option<CacheEntry> {
        if let Some(special_packet) = self.handle_special_queries(normalized_question) {
            Some(CacheEntry {
                     expiration: Instant::recent() +
                                 Duration::from_secs(self.config.max_ttl as u64),
                     packet: special_packet,
                 })
        } else if normalized_question.qclass != DNS_CLASS_IN {
            Some(CacheEntry {
                     expiration: Instant::recent() +
                                 Duration::from_secs(self.config.max_ttl as u64),
                     packet: dns::build_refused_packet(normalized_question).unwrap(),
                 })
        } else {
            let normalized_question_key = normalized_question.key();
            let cache_entry = self.get(&normalized_question_key);
            if let Some(mut cache_entry) = cache_entry {
                if self.config.decrement_ttl {
                    let now = Instant::recent();
                    if now <= cache_entry.expiration {
                        let remaining_ttl = cache_entry.expiration.duration_since(now).as_secs();
                        let _ = dns::set_ttl(&mut cache_entry.packet, remaining_ttl as u32);
                    }
                }
                return Some(cache_entry);
            }
            if !normalized_question_key.dnssec {
                let qname = normalized_question_key.qname_lc;
                if let Some(qname_shifted) = dns::qname_shift(&qname) {
                    let mut normalized_question_key = normalized_question.key();
                    normalized_question_key.qname_lc = qname_shifted.to_owned();
                    let shifted_cache_entry = self.get(&normalized_question_key);
                    if let Some(shifted_cache_entry) = shifted_cache_entry {
                        debug!("Shifted query cached");
                        let shifted_packet = shifted_cache_entry.packet;
                        if shifted_packet.len() >= dns::DNS_HEADER_SIZE &&
                           dns::rcode(&shifted_packet) == DNS_RCODE_NXDOMAIN {
                            debug!("Shifted query returned NXDOMAIN");
                            return Some(CacheEntry {
                                            expiration: shifted_cache_entry.expiration,
                                            packet: dns::build_nxdomain_packet(normalized_question)
                                                .unwrap(),
                                        });
                        }
                    }
                }
            }
            None
        }
    }

    fn handle_special_queries(&self, normalized_question: &NormalizedQuestion) -> Option<Vec<u8>> {
        if normalized_question.qclass == dns::DNS_CLASS_IN &&
           normalized_question.qtype == dns::DNS_TYPE_ANY {
            debug!("ANY query");
            let packet = dns::build_any_packet(normalized_question, self.config.max_ttl).unwrap();
            return Some(packet);
        }
        if normalized_question.qclass == dns::DNS_CLASS_CH &&
           normalized_question.qtype == dns::DNS_TYPE_TXT {
            debug!("CHAOS TXT");
            let packet = dns::build_version_packet(normalized_question, self.config.max_ttl)
                .unwrap();
            return Some(packet);
        }
        None
    }
}
