//! Shared cache for DNS responses
//!
//! The cache is currently shared across all threads, and maps
//! `NormalizedQuestionKey` keys to DNS responses in wire format.
//!
//! DNS responses are stored as originally received from upstream servers,
//! and need to be modified to fit the original format of client queries
//! before being actually sent to clients.
//!
//! The cache current uses the CLOCK-Pro algorithm, but can be trivially
//! replaced with the `arc-cache` or `cart-cache` crates that expose a
//! similar API (but might be subject to patents).
//!
//! With a typical workload, it is expected that the vast majority of cached
//! responses end up in the `frequent` section of the cache.
//! The `test` and `recent` section act as a security valve when a spike of
//! previously unknown queries is observed.

use clockpro_cache::*;
use coarsetime::{Duration, Instant};
use config::Config;
use dns;
use dns::{LocalUpstreamQuestion, NormalizedQuestion, DNS_CLASS_IN, DNS_RCODE_NXDOMAIN};
use dnssector::ParsedPacket;
use errors::*;
use failure;
use parking_lot::Mutex;
use std::sync::Arc;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CacheKey {
    pub local_upstream_question: LocalUpstreamQuestion,
}

impl CacheKey {
    pub fn from_parsed_packet(
        parsed_packet: &mut ParsedPacket,
        custom_hash: (u64, u64),
        bypass_cache: bool,
    ) -> Result<CacheKey, failure::Error> {
        let dnssec = parsed_packet.dnssec();
        let (qname_lc, qtype, qclass) = parsed_packet
            .question_raw()
            .map(|(qname, qtype, qclass)| (dns::qname_lc(qname), qtype, qclass))
            .ok_or(DNSError::Inconsistent)?;
        let local_upstream_question = LocalUpstreamQuestion {
            qname_lc,
            qtype,
            qclass,
            dnssec,
            custom_hash,
            bypass_cache,
        };
        Ok(CacheKey {
            local_upstream_question,
        })
    }

    pub fn from_normalized_question(
        normalized_question: &NormalizedQuestion,
        custom_hash: (u64, u64),
        bypass_cache: bool,
    ) -> CacheKey {
        let local_upstream_question = LocalUpstreamQuestion {
            qname_lc: normalized_question.qname_lc.clone(),
            qtype: normalized_question.qtype,
            qclass: normalized_question.qclass,
            dnssec: normalized_question.dnssec,
            custom_hash,
            bypass_cache,
        };
        CacheKey {
            local_upstream_question,
        }
    }

    pub fn from_local_upstream_question(
        local_upstream_question: LocalUpstreamQuestion,
    ) -> CacheKey {
        CacheKey {
            local_upstream_question,
        }
    }
}

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
    config: Arc<Config>,
    arc_mx: Arc<Mutex<ClockProCache<CacheKey, CacheEntry>>>,
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
            config: Arc::new(config),
            arc_mx: arc_mx,
        }
    }

    pub fn stats(&self) -> CacheStats {
        let cache = self.arc_mx.lock();
        CacheStats {
            frequent_len: cache.frequent_len(),
            recent_len: cache.recent_len(),
            test_len: cache.test_len(),
            inserted: cache.inserted(),
            evicted: cache.evicted(),
        }
    }

    pub fn insert(&mut self, cache_key: CacheKey, packet: Vec<u8>, ttl: u32) -> bool {
        debug_assert!(packet.len() >= dns::DNS_HEADER_SIZE);
        if packet.len() < dns::DNS_HEADER_SIZE {
            return false;
        }
        let now = Instant::recent();
        let duration = Duration::from_secs(u64::from(ttl));
        let expiration = now + duration;
        let cache_entry = CacheEntry {
            expiration: expiration,
            packet: packet,
        };
        let mut cache = self.arc_mx.lock();
        cache.insert(cache_key, cache_entry)
    }

    pub fn get(&mut self, cache_key: &CacheKey) -> Option<CacheEntry> {
        let mut cache = self.arc_mx.lock();
        cache.get_mut(cache_key).and_then(|res| Some(res.clone()))
    }

    /// get2() does a couple things before checking that a key is present in the cache.
    ///
    /// It rejects queries that are not in the `IN` class, that we probably never
    /// want to cache.
    ///
    /// It then checks if a cached response is present and still valid.
    /// If `x.example.com` is not present, but `example.com` is cached with an `NXDOMAIN`
    /// response code, we assume that `x.example.com` doesn't exist either (RFC 8020).
    ///
    /// We are not checking additional cache entries for now. Both to be minimize
    /// possible incompatibilities with RFC 8020, and for speed.
    /// This might be revisited later.
    pub fn get2(&mut self, cache_key: &CacheKey) -> Option<CacheEntry> {
        let cache_entry = self.get(cache_key);
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
        if !cache_key.local_upstream_question.dnssec {
            let qname_lc = &cache_key.local_upstream_question.qname_lc;
            if let Some(qname_shifted) = dns::qname_shift(qname_lc) {
                let qname_lc_shifted = qname_shifted;
                let local_upstream_question = LocalUpstreamQuestion {
                    qname_lc: qname_lc_shifted.to_owned(),
                    qtype: cache_key.local_upstream_question.qtype,
                    qclass: cache_key.local_upstream_question.qclass,
                    dnssec: cache_key.local_upstream_question.dnssec,
                    custom_hash: cache_key.local_upstream_question.custom_hash,
                    bypass_cache: cache_key.local_upstream_question.bypass_cache,
                };
                let shifted_cache_key = CacheKey {
                    local_upstream_question,
                };
                let shifted_cache_entry = self.get(&shifted_cache_key);
                if let Some(shifted_cache_entry) = shifted_cache_entry {
                    debug!("Shifted query cached");
                    let shifted_packet = shifted_cache_entry.packet;
                    if shifted_packet.len() >= dns::DNS_HEADER_SIZE
                        && dns::rcode(&shifted_packet) == DNS_RCODE_NXDOMAIN
                    {
                        debug!("Shifted query returned NXDOMAIN");
                        let local_upstream_question = &cache_key.local_upstream_question;
                        return Some(CacheEntry {
                            expiration: shifted_cache_entry.expiration,
                            packet: dns::build_nxdomain_packet(
                                &local_upstream_question.qname_lc,
                                local_upstream_question.qtype,
                                local_upstream_question.qclass,
                            ).unwrap(),
                        });
                    }
                }
            }
        }
        None
    }
}
