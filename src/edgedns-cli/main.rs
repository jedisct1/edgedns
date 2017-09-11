extern crate clap;
extern crate futures;
extern crate prost;
#[macro_use]
extern crate prost_derive;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_uds;

use clap::{App, Arg};
use prost::Message;
use std::str;
use tokio_core::reactor::Core;
use tokio_io::io::write_all;
use tokio_uds::UnixStream;

pub mod cli {
    include!(concat!(env!("OUT_DIR"), "/edgedns.cli.rs"));
}

static DEFAULT_UNIX_SOCKET_PATH: &'static str = "/tmp/edgedns.sock";

struct CLI {
    socket_path: String,
}

impl CLI {
    fn send_to_socket(&self, serialized: Vec<u8>) {
        let mut event_loop = Core::new().expect("No event loop");
        let handle = event_loop.handle();
        let socket = UnixStream::connect(&self.socket_path, &handle).expect(&format!(
            "Unable to connect to a unix socket named {}",
            &self.socket_path
        ));
        let task = write_all(socket, serialized);
        event_loop.run(task).unwrap();
    }

    fn service_load(&self, service_id: &str, library_path: &str) {
        let mut command = cli::Command::default();
        let action_service_load = cli::command::ServiceLoad {
            service_id: service_id.to_string(),
            library_path: library_path.to_string(),
        };
        let action = cli::command::Action::ServiceLoad(action_service_load);
        command.action = Some(action);
        let mut serialized = Vec::with_capacity(command.encoded_len());
        command
            .encode(&mut serialized)
            .expect("Unable to serialize a service-load action");
        self.send_to_socket(serialized);
    }

    fn service_unload(&self, service_id: &str) {
        let mut command = cli::Command::default();
        let action_service_unload = cli::command::ServiceUnload {
            service_id: service_id.to_string(),
        };
        let action = cli::command::Action::ServiceUnload(action_service_unload);
        command.action = Some(action);
        let mut serialized = Vec::with_capacity(command.encoded_len());
        command
            .encode(&mut serialized)
            .expect("Unable to serialize a service-unload action");
        self.send_to_socket(serialized);
    }

    pub fn new() {
        let matches = App::new("EdgeDNS CLI")
            .version("0.0.1")
            .author("Frank Denis")
            .about("Command-line interface for EdgeDNS")
            .arg(
                Arg::with_name("socket-path")
                    .short("s")
                    .long("socket-path")
                    .value_name("socket-path")
                    .default_value(DEFAULT_UNIX_SOCKET_PATH)
                    .help("Sets the path to the UNIX socket")
                    .takes_value(true)
                    .required(true),
            )
            .arg(
                Arg::with_name("service-load")
                    .short("L")
                    .long("service-load")
                    .value_name("service-id")
                    .help("Loads a shared library for the given service identifier")
                    .takes_value(true)
                    .required(false),
            )
            .arg(
                Arg::with_name("service-unload")
                    .short("U")
                    .long("service-unload")
                    .value_name("service-id")
                    .help("Removes the service matching the given identifier")
                    .takes_value(true)
                    .required(false),
            )
            .arg(
                Arg::with_name("library-path")
                    .short("l")
                    .long("library-path")
                    .value_name("path")
                    .help("Provides the path to the .so/.dylib file")
                    .takes_value(true)
                    .required(false),
            )
            .get_matches();
        let socket_path = matches
            .value_of("socket-path")
            .expect("Missing path to the UNIX socket");
        let cli = CLI {
            socket_path: socket_path.to_string(),
        };
        match matches.value_of("service-load") {
            None => {}
            Some(service_id) => {
                let library_path = matches
                    .value_of("library-path")
                    .expect("Library path required to register a service");
                return cli.service_load(service_id, library_path);
            }
        };
        match matches.value_of("service-unload") {
            None => {}
            Some(service_id) => {
                return cli.service_unload(service_id);
            }
        };
        eprintln!(
            "{}\n\nNo commands given. Use --help for more information.",
            matches.usage()
        );
    }
}

fn main() {
    CLI::new();
}
