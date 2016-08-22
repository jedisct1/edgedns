#![feature(question_mark)]
#![feature(sip_hash_13)]

#[macro_use] extern crate log;
extern crate arc_cache;
extern crate bytes;
extern crate clap;
extern crate env_logger;
extern crate mio;
extern crate nix;
extern crate rand;
extern crate rustc_serialize;
extern crate slab;

#[cfg(feature = "webservice")]
extern crate civet;
#[cfg(feature = "webservice")]
extern crate conduit_middleware;
#[cfg(feature = "webservice")]
extern crate conduit_router;
#[cfg(feature = "webservice")]
extern crate conduit;

mod cache;
mod client_query;
mod client;
mod dns;
mod resolver;
mod tcp_listener;
mod udp_listener;
mod varz;

#[cfg(feature = "webservice")]
mod webservice;

use cache::Cache;
use clap::{Arg, App};
use resolver::*;
use std::net::UdpSocket;
use std::sync::Arc;
use std::str::FromStr;
use tcp_listener::*;
use udp_listener::*;
use varz::*;

#[cfg(feature = "webservice")]
use webservice::*;

const DNS_MAX_SIZE: usize = 65535;
const DNS_MAX_TCP_SIZE: usize = 65535;
const DNS_MAX_UDP_SIZE: usize = 4096;
const DNS_QUERY_MAX_SIZE: usize = 283;
const DNS_QUERY_MIN_SIZE: usize = 17;
const DNS_UDP_NOEDNS0_MAX_SIZE: usize = 512;
const HEALTH_CHECK_MS: u64 = 10 * 1000;
const MAX_ACTIVE_QUERIES: usize = 100_000;
const MAX_CLIENTS_WAITING_FOR_QUERY: usize = 1_000;
const MAX_TCP_CLIENTS: usize = 1_000;
const MAX_TCP_HASH_DISTANCE: usize = 10;
const MAX_TCP_IDLE_MS: u64 = 10 * 1000;
const MAX_WAITING_CLIENTS: usize = MAX_ACTIVE_QUERIES * 10;
const MIN_TTL: u32 = 60;
const MAX_TTL: u32 = 86400;
const FAILURE_TTL: u32 = 30;
const UDP_BUFFER_SIZE: usize = 16 * 1024 * 1024;
const UPSTREAM_INITIAL_TIMEOUT_MS: u64 = 1 * 1000;
const UPSTREAM_MAX_TIMEOUT_MS: u64 = 8 * 1000;
const UPSTREAM_TIMEOUT_MS: u64 = 10 * 1000;

#[cfg(feature = "webservice")]
const WEBSERVICE_PORT: u16 = 8888;
#[cfg(feature = "webservice")]
const WEBSERVICE_THREADS: u32 = 2;

pub struct RPDNSContext {
    pub udp_socket: UdpSocket,
    pub listen_addr: String,
    pub cache: Cache,
    pub varz: Arc<Varz>
}

struct RPDNS;

impl RPDNS {
    #[cfg(feature = "webservice")]
    fn webservice_start(rpdns_context: &RPDNSContext) {
        let _ = WebService::spawn(&rpdns_context).expect("Unable to spawn the web service");
    }

    #[cfg(not(feature = "webservice"))]
    fn webservice_start(_rpdns_context: &RPDNSContext) { }

    fn new(cache_size: usize, listen_addr: &str, upstream_servers_str: Vec<&str>, decrement_ttl: bool, failover: bool, ports: u16, max_failures: u32) -> RPDNS {
        let varz = Arc::new(Varz::default());
        let cache = Cache::new(cache_size, decrement_ttl);
        let udp_socket = socket_udp_bound(&listen_addr).expect("Unable to create a client socket");
        let rpdns_context = RPDNSContext {
            udp_socket: udp_socket,
            listen_addr: listen_addr.to_owned(),
            cache: cache,
            varz: varz
        };
        let resolver_tx = Resolver::spawn(&rpdns_context, upstream_servers_str, decrement_ttl, failover, ports, max_failures).expect("Unable to spawn the resolver");

        Self::webservice_start(&rpdns_context);
        let udp_listener = UdpListener::spawn(&rpdns_context, resolver_tx.clone()).expect("Unable to spawn a UDP listener");
        let tcp_listener = TcpListener::spawn(&rpdns_context, resolver_tx.clone()).expect("Unable to spawn a TCP listener");
        let _ = udp_listener.join();
        let _ = tcp_listener.join();

        RPDNS
    }
}

fn main() {
    env_logger::init().expect("Failed to init logger");

    let matches = App::new("EdgeDNS").version("0.1").author("Frank Denis").about("A caching DNS reverse proxy").

    arg(Arg::with_name("upstream_servers_str").short("u").long("upstream").value_name("server:port,server:port...").help("Comma-delimited list of upstream servers").use_delimiter(true).default_value("8.8.8.8:53,8.8.4.4:53")).

    arg(Arg::with_name("listen_addr").short("l").long("listen").value_name("address:port").help("Listen address").takes_value(true).default_value("127.0.0.1:53")).

    arg(Arg::with_name("cache_size").short("c").long("cachesize").value_name("count").help("Max number of cached entries").takes_value(true).default_value("250000")).

    arg(Arg::with_name("decrement_ttl").short("r").long("resolver-mode").help("Resolver mode, decrements TTL").takes_value(false)).

    arg(Arg::with_name("failover").short("f").long("failover").help("Failover; try upstream servers sequentially instead of balancing the load").takes_value(false)).

    arg(Arg::with_name("ports_count").short("p").long("ports-count").value_name("count").help("Max number of UDP ports to use for outgoing connections, up to 64511").takes_value(true).default_value("8")).

    arg(Arg::with_name("upstream_max_failures").short("F").long("max-failures").value_name("count").help("Max failures before marking a server as temporarily unresponsive").takes_value(true).default_value("3")).

    get_matches();
    let upstream_servers_str: Vec<&str> = matches.values_of("upstream_servers_str").unwrap().collect();
    let listen_addr = matches.value_of("listen_addr").unwrap();
    let cache_size = FromStr::from_str(matches.value_of("cache_size").unwrap()).expect("Invalid number of cached entries");
    let decrement_ttl = matches.is_present("decrement_ttl");
    let failover = matches.is_present("failover");
    let ports = FromStr::from_str(matches.value_of("ports_count").unwrap()).expect("Invalid number of ports");
    let upstream_max_failures = FromStr::from_str(matches.value_of("upstream_max_failures").unwrap()).expect("Invalid value for the maximum number of failures");

    let _ = RPDNS::new(cache_size, listen_addr, upstream_servers_str, decrement_ttl, failover, ports, upstream_max_failures);
}
