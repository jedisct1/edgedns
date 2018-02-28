use futures::{Future, Stream};
use hooks::Hooks;
use parking_lot::RwLock;
use prost::Message;
use std::fs;
use std::io::{Cursor, Write};
use std::path::PathBuf;
use std::str;
use std::sync::Arc;
use std::thread;
use tokio_core::reactor::{Core, Handle};
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
    pub fn new(socket_path: String, hooks_arc: Arc<RwLock<Hooks>>) -> Self {
        CLIListener {
            socket_path,
            hooks_arc,
        }
    }

    fn client_action(
        action: Option<cli::command::Action>,
        hooks_arc: &Arc<RwLock<Hooks>>,
    ) -> Result<(), &'static str> {
        match action {
            Some(cli::command::Action::ServiceLoad(service_load)) => {
                match hooks_arc.write().load_library_for_service_id(
                    &service_load.library_path,
                    service_load.service_id.as_bytes(),
                ) {
                    Err(e) => Err(e),
                    _ => Ok(()),
                }
            }
            Some(cli::command::Action::ServiceUnload(service_unload)) => match hooks_arc
                .write()
                .unregister_service(service_unload.service_id.as_bytes())
            {
                Err(e) => Err(e),
                _ => Ok(()),
            },
            _ => Err("Unsupported action"),
        }
    }

    fn client_process(&self, socket: UnixStream, handle: &Handle) {
        let hooks_arc = Arc::clone(&self.hooks_arc);
        let buf = Vec::new();
        let reader = read_to_end(socket, buf)
            .map(move |(socket, serialized)| {
                let res = match cli::Command::decode(&mut Cursor::new(serialized)) {
                    Err(_) => Err("Invalid serialized command received from the CLI"),
                    Ok(command) => Self::client_action(command.action, &hooks_arc),
                };
                (res, socket)
            })
            .and_then(move |(_res, mut socket)| {
                let _ = socket.write_all(b"DONE\n");
                Ok(())
            })
            .then(|_| Ok(()));
        handle.spawn(reader)
    }

    pub fn spawn(self) {
        let cli_listener_th = thread::Builder::new()
            .name("cli_listener".to_string())
            .spawn(move || {
                let mut event_loop = Core::new().unwrap();
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
                    self.client_process(socket, &handle);
                    Ok(())
                });
                event_loop.run(task).unwrap();
            });
    }
}
