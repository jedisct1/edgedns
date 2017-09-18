use futures::{Future, Stream};
use hooks::Hooks;
use parking_lot::RwLock;
use prost::Message;
use std::fs;
use std::io::Cursor;
use std::io::Write;
use std::path::PathBuf;
use std::str;
use std::sync::Arc;
use tokio_core::reactor::Core;
use tokio_io::io::{read_to_end, write_all};
use tokio_uds::{UnixListener, UnixStream};

pub mod cli {
    include!(concat!(env!("OUT_DIR"), "/edgedns.cli.rs"));
}

pub struct CLIListener {
    socket_path: String,
    hooks_arc: Arc<RwLock<Hooks>>,
}

impl CLIListener {
    pub fn new(&self) {
        let mut event_loop = Core::new().expect("No event loop");
        let handle = event_loop.handle();
        let listener = match UnixListener::bind(&self.socket_path, &handle) {
            Ok(m) => m,
            Err(_) => {
                let _ = fs::remove_file(&self.socket_path);
                UnixListener::bind(&self.socket_path, &handle).expect(&format!(
                    "Unable to create a unix socket named [{}]",
                    self.socket_path
                ))
            }
        };
        let task = listener.incoming().for_each(|(socket, _client_addr)| {
            let hooks_arc = self.hooks_arc.clone();
            let buf = Vec::new();
            let reader = read_to_end(socket, buf)
                .map(|(socket, _buf)| {
                    println!("incoming: {:?}", str::from_utf8(&_buf).unwrap());
                    socket
                })
                .and_then(move |mut socket| {
                    socket.write_all(b"test").unwrap();
                    let path = PathBuf::from("/tmp/zok.dylib");
                    hooks_arc.write().load_library(&path).unwrap();
                    Ok(())
                })
                .then(|_| Ok(()));
            handle.spawn(reader);
            Ok(())
        });
        event_loop.run(task).unwrap();
    }
}
