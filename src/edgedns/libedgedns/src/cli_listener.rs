use futures::{Future, Stream};
use prost::Message;
use std::fs;
use std::io::Cursor;
use std::io::Write;
use std::str;
use tokio_core::reactor::Core;
use tokio_io::io::{read_to_end, write_all};
use tokio_uds::{UnixListener, UnixStream};

pub mod cli {
    include!(concat!(env!("OUT_DIR"), "/edgedns.cli.rs"));
}

pub struct CLIListener {
    socket_path: String,
}

impl CLIListener {}
