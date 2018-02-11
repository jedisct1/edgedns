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
use dns::{min_ttl, rcode, set_ttl, tid, NormalizedQuestionKey, UpstreamQuestion,
          DNS_RCODE_SERVFAIL};
use errors::*;
use failure;
use futures::Future;
use futures::Stream;
use futures::future;
use globals::Globals;
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
    globals: Globals,
    handle: Handle,
    local_port: u16,
}

impl ExtUdpListener {
    pub fn new(resolver_core: &ResolverCore, net_ext_udp_socket: &net::UdpSocket) -> Self {
        debug!(
            "New ext UDP listener spawned on port {}",
            net_ext_udp_socket.local_addr().unwrap().port()
        );
        ExtUdpListener {
            globals: resolver_core.globals.clone(),
            handle: resolver_core.handle.clone(),
            local_port: net_ext_udp_socket.local_addr().unwrap().port(),
        }
    }

    pub fn fut_process_stream(
        mut self,
        net_ext_udp_socket: net::UdpSocket,
    ) -> impl Future<Item = (), Error = failure::Error> {
        let fut_ext_socket = UdpStream::from_net_udp_socket(net_ext_udp_socket, &self.handle)
            .expect("Cannot create a UDP stream")
            .for_each(move |(packet, client_addr)| {
                self.fut_process_ext_socket(packet, client_addr)
            });
        fut_ext_socket
    }

    fn fut_process_ext_socket(
        &mut self,
        packet: Vec<u8>,
        server_addr: SocketAddr,
    ) -> impl Future<Item = (), Error = failure::Error> {
        info!("Something received on external port {}", self.local_port);
        let pending_queries = self.globals.pending_queries.inner.read();
        let upstream_question =
            match UpstreamQuestion::from_packet(&packet, self.local_port, &server_addr) {
                Err(e) => return future::err(e.into()),
                Ok(upstream_question) => upstream_question,
            };
        let mut waiting_clients = match pending_queries.waiting_clients.get(&upstream_question) {
            None => {
                warn!("Spurious response received");
                return future::err(DNSError::SpuriousResponse.into());
            }
            Some(waiting_clients) => waiting_clients.lock(),
        };
        let _ = waiting_clients.upstream_tx.take().unwrap().send(packet);
        future::ok(())
    }
}
