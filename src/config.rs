use std::io::prelude::*;
use std::fs::File;
use std::io::{Error, ErrorKind};
use std::path::Path;
use resolver::LoadBalancingMode;
use toml;

#[derive(Clone, Debug)]
pub struct Config {
    pub decrement_ttl: bool,
    pub upstream_servers: Vec<String>,
    pub lbmode: LoadBalancingMode,
    pub upstream_max_failures: u32,
    pub cache_size: usize,
    pub udp_ports: u16,
    pub listen_addr: String,
    pub webservice_enabled: bool,
    pub webservice_listen_addr: String,
    pub min_ttl: u32,
    pub max_ttl: u32,
    pub user: Option<String>,
    pub group: Option<String>,
    pub chroot_dir: Option<String>,
    pub udp_listener_threads: usize,
    pub tcp_listener_threads: usize,
    pub dnstap_enabled: bool,
    pub dnstap_backlog: usize,
    pub dnstap_socket_path: Option<String>,
    pub dnstap_identity: Option<String>,
    pub dnstap_version: Option<String>,
    pub max_waiting_clients: usize,
    pub max_active_queries: usize,
    pub max_clients_waiting_for_query: usize,
}

impl Config {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Config, Error> {
        let mut fd = try!(File::open(path));
        let mut toml = String::new();
        try!(fd.read_to_string(&mut toml));
        Self::from_string(&toml)
    }

    pub fn from_string(toml: &str) -> Result<Config, Error> {
        let toml_config = match toml.parse() {
            Ok(toml_config) => toml_config,
            Err(_) => {
                return Err(Error::new(ErrorKind::InvalidData,
                                      "Syntax error - config file is not valid TOML"))
            }
        };
        Self::parse(toml_config)
    }

    fn parse(toml_config: toml::Value) -> Result<Config, Error> {
        let config_upstream = toml_config.get("upstream");
        let decrement_ttl_str =
            config_upstream
                .and_then(|x| x.get("type"))
                .map_or("authoritative",
                        |x| x.as_str().expect("upstream.type must be a string"));
        let decrement_ttl = match decrement_ttl_str {
            "authoritative" => false,
            "resolver" => true,
            _ => {
                return Err(Error::new(ErrorKind::InvalidData,
                                      "Invalid value for the type of upstream servers. Must be \
                                       'authoritative or 'resolver'"))
            }
        };

        let upstream_servers = config_upstream
            .and_then(|x| x.get("servers"))
            .expect("upstream.servers is required")
            .as_array()
            .expect("Invalid list of upstream servers")
            .iter()
            .map(|x| {
                     x.as_str()
                         .expect("upstream servers must be strings")
                         .to_owned()
                 })
            .collect();

        let lbmode_str = config_upstream
            .and_then(|x| x.get("strategy"))
            .map_or("uniform",
                    |x| x.as_str().expect("upstream.strategy must be a string"));
        let lbmode = match lbmode_str {
            "uniform" => LoadBalancingMode::Uniform,
            "fallback" => LoadBalancingMode::Fallback,
            "minload" => LoadBalancingMode::P2,
            _ => {
                return Err(Error::new(ErrorKind::InvalidData,
                                      "Invalid value for the load balancing/failover strategy"))
            }
        };

        let upstream_max_failures = config_upstream
            .and_then(|x| x.get("max_failures"))
            .map_or(3, |x| {
                x.as_integer()
                    .expect("upstream.max_failures must be an integer")
            }) as u32;

        let config_cache = toml_config.get("cache");

        let cache_size = config_cache
            .and_then(|x| x.get("max_items"))
            .map_or(250_000, |x| {
                x.as_integer()
                    .expect("cache.max_items must be an integer")
            }) as usize;

        let min_ttl = config_cache
            .and_then(|x| x.get("min_ttl"))
            .map_or(60,
                    |x| x.as_integer().expect("cache.min_ttl must be an integer")) as
                      u32;

        let max_ttl = config_cache
            .and_then(|x| x.get("max_ttl"))
            .map_or(86_400,
                    |x| x.as_integer().expect("cache.max_ttl must be an integer")) as
                      u32;

        let config_network = toml_config.get("network");

        let udp_ports = config_network
            .and_then(|x| x.get("udp_ports"))
            .map_or(8, |x| {
                x.as_integer()
                    .expect("network.udp_ports must be an integer")
            }) as u16;

        let listen_addr = config_network
            .and_then(|x| x.get("listen"))
            .map_or("0.0.0.0:53",
                    |x| x.as_str().expect("network.listen_addr must be a string"))
            .to_owned();

        let config_webservice = toml_config.get("webservice");

        let webservice_enabled = config_webservice
            .and_then(|x| x.get("enabled"))
            .map_or(false, |x| {
                x.as_bool()
                    .expect("webservice.enabled must be a boolean")
            });

        let webservice_listen_addr = config_webservice
            .and_then(|x| x.get("listen"))
            .map_or("0.0.0.0:9090", |x| {
                x.as_str()
                    .expect("webservice.listen_addr must be a string")
            })
            .to_owned();

        let config_global = toml_config.get("global");

        let user = config_global
            .and_then(|x| x.get("user"))
            .map(|x| {
                     x.as_str()
                         .expect("global.user must be a string")
                         .to_owned()
                 });

        let group = config_global
            .and_then(|x| x.get("group"))
            .map(|x| {
                     x.as_str()
                         .expect("global.group must be a string")
                         .to_owned()
                 });

        let chroot_dir = config_global
            .and_then(|x| x.get("chroot_dir"))
            .map(|x| {
                     x.as_str()
                         .expect("global.chroot must be a string")
                         .to_owned()
                 });

        let udp_listener_threads = config_global
            .and_then(|x| x.get("threads_udp"))
            .map_or(1, |x| {
                x.as_integer()
                    .expect("global.threads_udp must be an integer")
            }) as usize;

        let tcp_listener_threads = config_global
            .and_then(|x| x.get("threads_tcp"))
            .map_or(1, |x| {
                x.as_integer()
                    .expect("global.threads_tcp must be an integer")
            }) as usize;

        let max_waiting_clients = config_global
            .and_then(|x| x.get("max_waiting_clients"))
            .map_or(1_000_000, |x| {
                x.as_integer()
                    .expect("global.max_waiting_clients must be an integer")
            }) as usize;

        let max_active_queries = config_global
            .and_then(|x| x.get("max_active_queries"))
            .map_or(100_000, |x| {
                x.as_integer()
                    .expect("global.max_active_queries must be an integer")
            }) as usize;

        let max_clients_waiting_for_query = config_global
            .and_then(|x| x.get("max_clients_waiting_for_query"))
            .map_or(1_000, |x| {
                x.as_integer()
                    .expect("global.max_clients_waiting_for_query must be an integer")
            }) as usize;

        let config_dnstap = toml_config.get("dnstap");

        let dnstap_enabled =
            config_dnstap
                .and_then(|x| x.get("enabled"))
                .map_or(false,
                        |x| x.as_bool().expect("dnstap.enabled must be a boolean"));

        let dnstap_backlog = config_dnstap
            .and_then(|x| x.get("backlog"))
            .map_or(4096, |x| {
                x.as_integer()
                    .expect("dnstap.backlog must be an integer")
            }) as usize;

        let dnstap_socket_path = config_dnstap
            .and_then(|x| x.get("socket_path"))
            .map(|x| {
                     x.as_str()
                         .expect("dnstap.socket_path must be a string")
                         .to_owned()
                 });

        let dnstap_identity = config_dnstap
            .and_then(|x| x.get("identity"))
            .map(|x| {
                     x.as_str()
                         .expect("dnstap.identity must be a string")
                         .to_owned()
                 });

        let dnstap_version = config_dnstap
            .and_then(|x| x.get("version"))
            .map(|x| {
                     x.as_str()
                         .expect("dnstap.version must be a string")
                         .to_owned()
                 });

        Ok(Config {
               decrement_ttl: decrement_ttl,
               upstream_servers: upstream_servers,
               lbmode: lbmode,
               upstream_max_failures: upstream_max_failures,
               cache_size: cache_size,
               udp_ports: udp_ports,
               listen_addr: listen_addr,
               webservice_enabled: webservice_enabled,
               webservice_listen_addr: webservice_listen_addr,
               min_ttl: min_ttl,
               max_ttl: max_ttl,
               user: user,
               group: group,
               chroot_dir: chroot_dir,
               udp_listener_threads: udp_listener_threads,
               tcp_listener_threads: tcp_listener_threads,
               dnstap_enabled: dnstap_enabled,
               dnstap_backlog: dnstap_backlog,
               dnstap_socket_path: dnstap_socket_path,
               dnstap_identity: dnstap_identity,
               dnstap_version: dnstap_version,
               max_waiting_clients: max_waiting_clients,
               max_active_queries: max_active_queries,
               max_clients_waiting_for_query: max_clients_waiting_for_query,
           })
    }
}
