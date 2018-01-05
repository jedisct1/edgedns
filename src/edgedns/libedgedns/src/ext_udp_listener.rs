//! Handler for responses received from upstream servers using UDP.
//!
//! Questions are decoupled from responses. We don't maintain network-specific
//! states, as a `PendingQuery` structure is enough to validate that a response
//! matches an actual question waiting for an answser, with the correct IP,
//! the correct port and the correct query ID.
//!
//! A valid response is dispatched to the list of Client Queries waiting for it,
//! and is inserted into the cache.
//!
//! Due to the decoupling, we don't have any ways to know if a response without
//! DNSSEC information is a response to a query with the `DO` bit, but the zone is
//! not signed, or a response to a question sent without the `DO` bit. We encode
//! the `DO` bit in the case of the query name in order to lift this ambiguity.

use super::{DNS_QUERY_MIN_SIZE, FAILURE_TTL};
use cache::{Cache, CacheKey};
use client_query::ClientQuery;
use config::Config;
use dns::{min_ttl, normalize, rcode, set_ttl, tid, NormalizedQuestionKey,
          NormalizedQuestionMinimal, DNS_RCODE_SERVFAIL};
use futures::Future;
use futures::Stream;
use futures::future;
use log_dnstap;
use parking_lot::RwLock;
use resolver::ResolverCore;
use std::io;
use std::net::{self, SocketAddr};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::Relaxed;
use tokio_core::reactor::Handle;
use udp_stream::*;
use upstream_server::UpstreamServer;
use varz::Varz;

pub struct ExtUdpListener {
    local_port: u16,
    net_udp_socket: net::UdpSocket,
}

impl ExtUdpListener {
    pub fn new(resolver_core: &ResolverCore, local_port: u16) -> Self {
        ExtUdpListener {
            local_port: local_port,
            net_udp_socket: resolver_core.net_udp_socket.try_clone().unwrap(),
        }
    }
}
