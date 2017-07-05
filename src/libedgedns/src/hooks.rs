//! Pre/post cache/request hooks

use dnssector::c_abi::{self, FnTable};
use dnssector::{DNSSector, ParsedPacket};
use nix::libc::c_void;
use libloading::{Symbol, Library};

pub enum Stage {
    Deliver,
}

pub struct Hooks {
    dlh: Option<Library>,
}

impl Hooks {
    pub fn new() -> Self {
        let path = "c_hook.dylib";
        let dlh = match Library::new(path) {
            Err(err) => {
                error!(
                    "Cannot load the sample hooks C library [{}] [{}]",
                    path,
                    err
                );
                None
            }
            Ok(dlh) => Some(dlh),
        };
        Hooks { dlh: dlh }
    }

    #[inline]
    pub fn enabled(&self, _stage: Stage) -> bool {
        self.dlh.is_some()
    }

    pub fn apply(&self, packet: Vec<u8>, stage: Stage) -> Option<Vec<u8>> {
        if !self.enabled(stage) {
            return None;
        }
        let dlh = self.dlh.as_ref().unwrap();
        let hook: Symbol<unsafe extern "C" fn(*const FnTable, *mut ParsedPacket) -> ()> =
            unsafe { dlh.get(b"hook").unwrap() };

        let ds = match DNSSector::new(packet) {
            Ok(ds) => ds,
            Err(e) => {
                warn!("{}", e);
                return None;
            }
        };
        let mut parsed_packet = ds.parse().expect("cannot run parser");

        let fn_table = c_abi::fn_table();
        unsafe { hook(&fn_table, &mut parsed_packet) }

        let packet = parsed_packet.into_packet();

        Some(packet)
    }
}
