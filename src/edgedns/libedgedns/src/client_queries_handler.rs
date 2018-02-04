//! A Client Queries Handler is the main entry point of a Resolver.
//!
//! It accepts queries received as messages from the Udp and Tcp listeners,
//! and initiate the chain of futures required to fetch the responses.
//!
//! The chain includes coalescing similar queries, retrying, marking servers as
//! unresponsive after too many timeouts, and bringing them back to life after
//! regular probes have been successfully received.

use super::{UPSTREAM_PROBES_DELAY_MS, UPSTREAM_QUERY_MAX_TIMEOUT_MS};
use cache::Cache;
use client_query::ClientQuery;
use coarsetime::{Duration, Instant};
use config::Config;
use dns::{self, NormalizedQuestion, NormalizedQuestionKey};
use futures::Future;
use futures::Stream;
use futures::future;
use futures::sync::mpsc::Receiver;
use futures::sync::oneshot;
use jumphash::JumpHasher;
use parking_lot::RwLock;
use rand;
use rand::distributions::{IndependentSample, Range};
use resolver::{LoadBalancingMode, ResolverCore};
use std::collections::HashMap;
use std::io;
use std::net;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::Relaxed;
use std::time;
use tokio_core::reactor::Handle;
use tokio_timer::{wheel, Timer};
use upstream_server::{UpstreamServer, UpstreamServerForQuery};
use varz::Varz;

pub struct ClientQueriesHandler {
    cache: Cache,
    config: Rc<Config>,
    handle: Handle,
    net_udp_socket: net::UdpSocket,
    net_ext_udp_sockets_rc: Rc<Vec<net::UdpSocket>>,
    upstream_servers_arc: Arc<RwLock<HashMap<SocketAddr, UpstreamServer>>>,
    waiting_clients_count: Rc<AtomicUsize>,
    jumphasher: JumpHasher,
    timer: Timer,
    varz: Varz,
}

impl Clone for ClientQueriesHandler {
    fn clone(&self) -> Self {
        ClientQueriesHandler {
            cache: self.cache.clone(),
            config: Rc::clone(&self.config),
            handle: self.handle.clone(),
            net_udp_socket: self.net_udp_socket.try_clone().unwrap(),
            net_ext_udp_sockets_rc: Rc::clone(&self.net_ext_udp_sockets_rc),
            upstream_servers_arc: Arc::clone(&self.upstream_servers_arc),
            waiting_clients_count: Rc::clone(&self.waiting_clients_count),
            jumphasher: self.jumphasher,
            timer: self.timer.clone(),
            varz: Arc::clone(&self.varz),
        }
    }
}

impl ClientQueriesHandler {
    pub fn new(resolver_core: &ResolverCore) -> Self {
        let timer = wheel()
            .max_capacity(resolver_core.config.max_active_queries)
            .build();
        ClientQueriesHandler {
            cache: resolver_core.cache.clone(),
            config: Rc::clone(&resolver_core.config),
            handle: resolver_core.handle.clone(),
            net_udp_socket: resolver_core.net_udp_socket.try_clone().unwrap(),
            net_ext_udp_sockets_rc: Rc::clone(&resolver_core.net_ext_udp_sockets_rc),
            upstream_servers_arc: Arc::clone(&resolver_core.upstream_servers_arc),
            waiting_clients_count: Rc::clone(&resolver_core.waiting_clients_count),
            jumphasher: resolver_core.jumphasher,
            timer: timer,
            varz: Arc::clone(&resolver_core.varz),
        }
    }

    pub fn fut_process_stream(
        &self,
        handle: &Handle,
        resolver_rx: Receiver<ClientQuery>,
    ) -> impl Future {
        let handle = handle.clone();
        let mut self_inner = self.clone();
        let fut_client_query = resolver_rx.for_each(move |client_query| {
            let fut = self_inner
                .fut_process_client_query(&client_query)
                .map_err(|_| {});
            handle.spawn(fut);
            future::ok(())
        });
        fut_client_query.map_err(|_| io::Error::last_os_error())
    }

    fn fut_process_client_query(
        &mut self,
        client_query: &ClientQuery,
    ) -> impl Future<Item = (), Error = io::Error> {
        debug!("Incoming client query");
        client_query.task.notify();
        future::ok(())
    }
}
