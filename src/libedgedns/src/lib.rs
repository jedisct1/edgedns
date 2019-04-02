//! Import all the required crates, instanciate the main components and start
//! the service.
#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]
#![cfg_attr(feature = "clippy", allow(identity_op, ptr_arg, collapsible_if, let_and_return))]
#![allow(dead_code, unused_imports, unused_variables)]

extern crate base64;
extern crate byteorder;
extern crate clockpro_cache;
#[macro_use]
extern crate bpf;
extern crate bytes;
extern crate coarsetime;
extern crate dnstap;
extern crate env_logger;
#[macro_use]
extern crate futures;
extern crate jumphash;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate net2;
extern crate nix;
extern crate parking_lot;
extern crate privdrop;
extern crate rand;
extern crate siphasher;
extern crate slab;
extern crate socket_priority;
extern crate tokio_core;
#[macro_use]
extern crate tokio_io;
extern crate tokio_timer;
extern crate toml;

#[cfg(feature = "webservice")]
extern crate hyper;

#[macro_use]
extern crate prometheus;

mod cache;
mod client_query;
mod client_queries_handler;
mod config;
pub mod dns;
mod ext_response;
mod log_dnstap;
mod net_helpers;
mod pending_query;
mod resolver;
use std::io;
mod tcp_acceptor;
mod tcp_arbitrator;
mod udp_acceptor;
mod udp_stream;
mod upstream_probe;
mod upstream_server;
mod varz;

#[cfg(feature = "webservice")]
mod webservice;

use cache::Cache;
pub use config::Config;
use log_dnstap::LogDNSTap;
use net_helpers::*;
use privdrop::PrivDrop;
use resolver::*;
use std::net;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use tcp_acceptor::*;
use tcp_arbitrator::TcpArbitrator;
use udp_acceptor::*;
use varz::*;

#[cfg(feature = "webservice")]
use webservice::*;

const CLOCK_RESOLUTION: u64 = 100;
const DNS_MAX_SIZE: usize = 65535;
const DNS_MAX_TCP_SIZE: usize = 65535;
const DNS_MAX_UDP_SIZE: usize = 4096;
const DNS_QUERY_MAX_SIZE: usize = 283;
const DNS_QUERY_MIN_SIZE: usize = 17;
const DNS_UDP_NOEDNS0_MAX_SIZE: usize = 512;
const HEALTH_CHECK_MS: u64 = 10 * 1000;
const MAX_EVENTS_PER_BATCH: usize = 1024;
const MAX_TCP_CLIENTS: usize = 1_000;
const MAX_TCP_HASH_DISTANCE: usize = 10;
const MAX_TCP_IDLE_MS: u64 = 10 * 1000;
const FAILURE_TTL: u32 = 30;
const TCP_BACKLOG: usize = 1024;
const UDP_BUFFER_SIZE: usize = 16 * 1024 * 1024;
const UPSTREAM_TOTAL_TIMEOUT_MS: u64 = 5 * 1000;
const UPSTREAM_QUERY_MIN_TIMEOUT_MS: u64 = 1 * 1000;
const UPSTREAM_QUERY_MAX_TIMEOUT_MS: u64 = UPSTREAM_TOTAL_TIMEOUT_MS * 3 / 4;
const UPSTREAM_QUERY_MAX_DEVIATION_COEFFICIENT: f64 = 4.0;
const UPSTREAM_PROBES_DELAY_MS: u64 = 1 * 1000;

#[cfg(feature = "webservice")]
const WEBSERVICE_THREADS: usize = 1;

pub struct EdgeDNSContext {
    pub config: Config,
    pub listen_addr: String,
    pub udp_socket: net::UdpSocket,
    pub tcp_listener: net::TcpListener,
    pub cache: Cache,
    pub varz: Arc<Varz>,
    pub tcp_arbitrator: TcpArbitrator,
    pub dnstap_sender: Option<log_dnstap::Sender>,
}

pub struct EdgeDNS;

impl EdgeDNS {
    #[cfg(feature = "webservice")]
    fn webservice_start(
        edgedns_context: &EdgeDNSContext,
        service_ready_tx: mpsc::SyncSender<u8>,
    ) -> io::Result<thread::JoinHandle<()>> {
        WebService::spawn(edgedns_context, service_ready_tx)
    }

    #[cfg(not(feature = "webservice"))]
    fn webservice_start(
        _edgedns_context: &EdgeDNSContext,
        _service_ready_tx: mpsc::SyncSender<u8>,
    ) -> io::Result<thread::JoinHandle<()>> {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Support for metrics was not compiled in",
        ))
    }

    fn privileges_drop(config: &Config) {
        let mut pd = PrivDrop::default();
        if let Some(ref user) = config.user {
            pd = pd.user(user).expect("User not found");
        }
        if let Some(ref group) = config.group {
            pd = pd.group(group).expect("Group not found");
        }
        if let Some(ref chroot_dir) = config.chroot_dir {
            pd = pd.chroot(chroot_dir);
        }
        pd.apply().expect("Unable to drop privileges");
    }

    pub fn new(config: Config) -> EdgeDNS {
        let ct = coarsetime::Updater::new(CLOCK_RESOLUTION)
            .start()
            .expect("Unable to spawn the internal timer");
        let varz = Arc::new(Varz::new());
        let cache = Cache::new(config.clone());
        let udp_socket =
            socket_udp_bound(&config.listen_addr).expect("Unable to create a UDP client socket");
        let tcp_listener =
            socket_tcp_bound(&config.listen_addr).expect("Unable to create a TCP client socket");
        let (log_dnstap, dnstap_sender) = if config.dnstap_enabled {
            let log_dnstap = LogDNSTap::new(&config);
            let dnstap_sender = log_dnstap.sender();
            (Some(log_dnstap), Some(dnstap_sender))
        } else {
            (None, None)
        };
        let tcp_arbitrator = TcpArbitrator::with_capacity(config.max_tcp_clients);
        let edgedns_context = EdgeDNSContext {
            config: config.clone(),
            listen_addr: config.listen_addr.to_owned(),
            udp_socket: udp_socket,
            tcp_listener: tcp_listener,
            cache: cache,
            varz: varz,
            tcp_arbitrator: tcp_arbitrator,
            dnstap_sender: dnstap_sender,
        };
        let resolver_tx =
            ResolverCore::spawn(&edgedns_context).expect("Unable to spawn the resolver");
        let (service_ready_tx, service_ready_rx) = mpsc::sync_channel::<u8>(1);
        let mut tasks: Vec<thread::JoinHandle<()>> = Vec::new();
        for _ in 0..config.udp_acceptor_threads {
            let udp_acceptor = UdpAcceptorCore::spawn(
                &edgedns_context,
                resolver_tx.clone(),
                service_ready_tx.clone(),
            ).expect("Unable to spawn a UDP listener");
            tasks.push(udp_acceptor);
            service_ready_rx.recv().unwrap();
        }
        for _ in 0..config.tcp_acceptor_threads {
            let tcp_listener = TcpAcceptorCore::spawn(
                &edgedns_context,
                resolver_tx.clone(),
                service_ready_tx.clone(),
            ).expect("Unable to spawn a TCP listener");
            tasks.push(tcp_listener);
            service_ready_rx.recv().unwrap();
        }
        if config.webservice_enabled {
            let webservice = Self::webservice_start(&edgedns_context, service_ready_tx.clone());
            tasks.push(webservice.unwrap());
            service_ready_rx.recv().unwrap();
        }
        Self::privileges_drop(&config);
        log_dnstap.map(|mut x| x.start());
        info!("EdgeDNS is ready to process requests");
        for task in tasks {
            let _ = task.join();
        }
        ct.stop().unwrap();
        EdgeDNS
    }
}
