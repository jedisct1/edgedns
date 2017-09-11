//! Import all the required crates, instanciate the main components and start
//! the service.
#![feature(conservative_impl_trait)]
#![allow(dead_code, unused_imports, unused_variables)]

extern crate clap;
extern crate env_logger;
extern crate libedgedns;
#[macro_use]
extern crate log;

use clap::{App, Arg};
use libedgedns::{Config, EdgeDNS};

fn main() {
    env_logger::init().expect("Failed to init logger");

    let matches = App::new("EdgeDNS")
        .version("0.2.1")
        .author("Frank Denis")
        .about("A caching DNS reverse proxy")
        .arg(
            Arg::with_name("config_file")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Path to the edgedns.toml config file")
                .takes_value(true)
                .required(true),
        )
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
            error!(
                "The configuration couldn't be loaded -- [{}]: [{}]",
                config_file,
                err
            );
            return;
        }
        Ok(config) => config,
    };
    EdgeDNS::new(config);
}
