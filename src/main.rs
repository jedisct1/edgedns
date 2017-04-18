#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]

#[macro_use]
extern crate log;
extern crate clockpro_cache;
#[macro_use]
extern crate bpf;
extern crate bytes;
extern crate clap;
extern crate coarsetime;
#[cfg(feature = "nightly")]
extern crate dnstap;
extern crate env_logger;
extern crate framestream;
extern crate jumphash;
extern crate mio;
extern crate nix;
extern crate privdrop;
extern crate rand;
extern crate siphasher;
extern crate slab;
extern crate socket_priority;
extern crate toml;

#[cfg(feature = "webservice")]
extern crate hyper;

#[macro_use]
extern crate prometheus;

mod cache;
mod client_query;
mod client;
mod config;
mod dns;
#[cfg(feature = "nightly")]
mod log_dnstap;
mod net_helpers;
mod resolver;
mod tcp_listener;
mod udp_listener;
mod varz;

#[cfg(feature = "webservice")]
mod webservice;

use cache::Cache;
use clap::{Arg, App};
use config::Config;
use log_dnstap::LogDNSTap;
use net_helpers::*;
use privdrop::PrivDrop;
use resolver::*;
use std::net::{self, UdpSocket};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use tcp_listener::*;
use udp_listener::*;
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
const UPSTREAM_INITIAL_TIMEOUT_MS: u64 = 1 * 1000;
const UPSTREAM_MAX_TIMEOUT_MS: u64 = 3 * 1000;
const UPSTREAM_TIMEOUT_MS: u64 = 5 * 1000;

#[cfg(feature = "webservice")]
const WEBSERVICE_THREADS: usize = 1;

pub struct EdgeDNSContext {
    pub config: Config,
    pub listen_addr: String,
    pub udp_socket: UdpSocket,
    pub tcp_socket: net::TcpListener,
    pub cache: Cache,
    pub varz: Arc<Varz>,
    pub dnstap_sender: Option<log_dnstap::Sender>,
}

struct EdgeDNS;

impl EdgeDNS {
    #[cfg(feature = "webservice")]
    fn webservice_start(
        edgedns_context: &EdgeDNSContext,
        service_ready_tx: mpsc::SyncSender<u8>,
    ) -> thread::JoinHandle<()> {
        WebService::spawn(edgedns_context, service_ready_tx)
            .expect("Unable to spawn the web service")
    }

    #[cfg(not(feature = "webservice"))]
    fn webservice_start(
        _edgedns_context: &EdgeDNSContext,
        _service_ready_tx: mpsc::SyncSender<u8>,
    ) {
        debug!("This build was not compiled with support for webservices");
    }

    fn privileges_drop(config: &Config) {
        let mut pd = PrivDrop::default();
        if let Some(ref user) = config.user {
            pd = pd.user(user);
        }
        if let Some(ref group) = config.group {
            pd = pd.group(group);
        }
        if let Some(ref chroot_dir) = config.chroot_dir {
            pd = pd.chroot(chroot_dir);
        }
        pd.apply().unwrap();
    }

    fn new(config: Config) -> Result<EdgeDNS, std::string::String> {
        let ct = coarsetime::Updater::new(CLOCK_RESOLUTION)
            .start()
            .expect("Unable to spawn the internal timer");
        let varz = Arc::new(Varz::new());
        let cache = Cache::new(config.clone());
        let udp_socket = match socket_udp_bound(&config.listen_addr) {
            Err(err) => {
                return Err(format!("Unable to create a UDP client socket ({}): {}", &config.listen_addr, err));
            },
            Ok(udp_socket) => udp_socket,
        };
        let tcp_socket = match socket_tcp_bound(&config.listen_addr) {
            Err(err) => {
                return Err(format!("Unable to create a TCP client socket ({}): {}", &config.listen_addr, err));
            },
            Ok(tcp_socket) => tcp_socket,
        };
        let (log_dnstap, dnstap_sender) = if config.dnstap_enabled {
            let log_dnstap = LogDNSTap::new(&config);
            let dnstap_sender = log_dnstap.sender();
            (Some(log_dnstap), Some(dnstap_sender))
        } else {
            (None, None)
        };
        let edgedns_context = EdgeDNSContext {
            config: config.clone(),
            listen_addr: config.listen_addr.to_owned(),
            udp_socket: udp_socket,
            tcp_socket: tcp_socket,
            cache: cache,
            varz: varz,
            dnstap_sender: dnstap_sender,
        };
        let resolver_tx = Resolver::spawn(&edgedns_context).expect("Unable to spawn the resolver");
        let (service_ready_tx, service_ready_rx) = mpsc::sync_channel::<u8>(1);
        let mut tasks: Vec<thread::JoinHandle<()>> = Vec::new();
        for _ in 0..config.udp_listener_threads {
            let udp_listener = UdpListener::spawn(&edgedns_context,
                                                  resolver_tx.clone(),
                                                  service_ready_tx.clone())
                    .expect("Unable to spawn a UDP listener");
            tasks.push(udp_listener);
            service_ready_rx.recv().unwrap();
        }
        for _ in 0..config.tcp_listener_threads {
            let tcp_listener = TcpListener::spawn(&edgedns_context,
                                                  resolver_tx.clone(),
                                                  service_ready_tx.clone())
                    .expect("Unable to spawn a TCP listener");
            tasks.push(tcp_listener);
            service_ready_rx.recv().unwrap();
        }
        if config.webservice_enabled {
            let webservice = Self::webservice_start(&edgedns_context, service_ready_tx.clone());
            tasks.push(webservice);
            service_ready_rx.recv().unwrap();
        }
        Self::privileges_drop(&config);
        log_dnstap.map(|mut x| x.start());
        info!("EdgeDNS is ready to process requests");
        for task in tasks {
            let _ = task.join();
        }
        ct.stop().unwrap();
        Ok(EdgeDNS)
    }
}

fn main() {
    env_logger::init().expect("Failed to init logger");

    let matches = App::new("EdgeDNS")
        .version("0.2.1")
        .author("Frank Denis")
        .about("A caching DNS reverse proxy")
        .arg(Arg::with_name("config_file")
                 .short("c")
                 .long("config")
                 .value_name("FILE")
                 .help("Path to the edgedns.toml config file")
                 .takes_value(true)
                 .required(true))
        .get_matches();

    let config_file = match matches.value_of("config_file") {
        None => {
            error!("A path to the configuration file is required");
            return;
        }
        Some(config_file) => config_file,
    };
    let config = match Config::from_path(config_file) {
        Err(err) => {
            error!("The configuration couldn't be loaded -- [{}]: [{}]",
                   config_file,
                   err);
            return;
        }
        Ok(config) => config,
    };
    match EdgeDNS::new(config) {
        Err(errstr) => error!("Failed to start EdgeDNS: {}", errstr),
        Ok(_) => return,
    }
}
