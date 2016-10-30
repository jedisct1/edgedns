use std::io::prelude::*;
use std::fs::File;
use std::io::{Error, ErrorKind};
use std::path::Path;
use toml;

#[derive(Clone, Debug)]
pub struct Config {
    pub decrement_ttl: bool,
    pub upstream_servers: Vec<String>,
    pub failover: bool,
    pub upstream_max_failures: u32,
    pub cache_size: usize,
    pub udp_ports: u16,
    pub listen_addr: String,
    pub webservice_enabled: bool,
    pub webservice_listen_addr: String,
    pub min_ttl: u32,
    pub max_ttl: u32,
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
        let decrement_ttl_str = toml_config.lookup("upstream.type").map_or("authoritative", |x| {
            x.as_str().expect("upstream.type must be a string")
        });
        let decrement_ttl = match decrement_ttl_str {
            "authoritative" => false,
            "resolver" => true,
            _ => {
                return Err(Error::new(ErrorKind::InvalidData,
                                      "Invalid value for the type of upstream servers. Must be \
                                       'authoritative or 'resolver'"))
            }
        };

        let upstream_servers = toml_config.lookup("upstream.servers")
            .expect("upstream.servers is required")
            .as_slice()
            .expect("Invalid list of upstream servers")
            .iter()
            .map(|x| x.as_str().expect("upstream servers must be strings").to_owned())
            .collect();

        let failover_str = toml_config.lookup("upstream.strategy").map_or("uniform", |x| {
            x.as_str().expect("upstream.strategy must be a string")
        });
        let failover = match failover_str {
            "uniform" => false,
            "fallback" => true,
            _ => {
                return Err(Error::new(ErrorKind::InvalidData,
                                      "Invalid value for the load balancing/failover strategy"))
            }
        };

        let upstream_max_failures =
            toml_config.lookup("upstream.max_failures").map_or(3, |x| {
                x.as_integer().expect("upstream.max_failures must be an integer")
            }) as u32;

        let cache_size = toml_config.lookup("cache.max_items").map_or(250_000, |x| {
            x.as_integer().expect("cache.max_items must be an integer")
        }) as usize;

        let min_ttl = toml_config.lookup("cache.min_ttl").map_or(60, |x| {
            x.as_integer().expect("cache.min_ttl must be an integer")
        }) as u32;

        let max_ttl = toml_config.lookup("cache.max_ttl").map_or(86_400, |x| {
            x.as_integer().expect("cache.max_ttl must be an integer")
        }) as u32;

        let udp_ports = toml_config.lookup("network.udp_ports").map_or(8, |x| {
            x.as_integer().expect("network.udp_ports must be an integer")
        }) as u16;

        let listen_addr = toml_config.lookup("network.listen")
            .map_or("0.0.0.0:53",
                    |x| x.as_str().expect("network.listen_addr must be a string"))
            .to_owned();

        let webservice_enabled = toml_config.lookup("webservice.enabled").map_or(false, |x| {
            x.as_bool().expect("webservice.enabled must be a boolean")
        });

        let webservice_listen_addr = toml_config.lookup("webservice.listen")
            .map_or("0.0.0.0:9090",
                    |x| x.as_str().expect("webservice.listen_addr must be a string"))
            .to_owned();

        Ok(Config {
            decrement_ttl: decrement_ttl,
            upstream_servers: upstream_servers,
            failover: failover,
            upstream_max_failures: upstream_max_failures,
            cache_size: cache_size,
            udp_ports: udp_ports,
            listen_addr: listen_addr,
            webservice_enabled: webservice_enabled,
            webservice_listen_addr: webservice_listen_addr,
            min_ttl: min_ttl,
            max_ttl: max_ttl,
        })
    }
}
