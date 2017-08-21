//! Pre/post cache/request hooks

use client_query::ClientQuery;
use dnssector::{DNSSector, ParsedPacket};
use dnssector::c_abi::{self, FnTable};
use libloading::{self, Library};
#[cfg(unix)]
use libloading::os::unix::Symbol;
#[cfg(windows)]
use libloading::os::windows::Symbol;
use nix::libc::{c_int, c_void};
use std::mem;
use std::sync::Arc;

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct SessionState;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Action {
    Pass = 1,
    Lookup,
    Drop,
}

impl From<Action> for c_int {
    fn from(v: Action) -> c_int {
        v as c_int
    }
}

impl From<c_int> for Action {
    fn from(id: c_int) -> Action {
        match id {
            x if x == Action::Pass.into() => Action::Pass,
            x if x == Action::Lookup.into() => Action::Lookup,
            _ => Action::Drop,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Stage {
    Recv,
    Deliver,
}

struct ActiveLibrary {
    library: Arc<Library>,
    hook_recv: Symbol<unsafe extern "C" fn(*const FnTable, *mut ParsedPacket) -> c_int>,
    hook_deliver: Symbol<unsafe extern "C" fn(*const FnTable, *mut ParsedPacket) -> c_int>,
}

pub struct Hooks {
    dlh: Option<ActiveLibrary>,
}

impl Hooks {
    pub fn new() -> Self {
        let path = "c_hook.dylib";
        let library = match Library::new(path) {
            Err(err) => {
                error!(
                    "Cannot load the sample hooks C library [{}] [{}]",
                    path,
                    err
                );
                return Hooks { dlh: None };
            }
            Ok(library) => Arc::new(library),
        };
        let library_inner = library.clone();
        let hook_recv_hl: libloading::Symbol<
            unsafe extern "C" fn(*const FnTable, *mut ParsedPacket) -> c_int,
        > = unsafe { library_inner.get("hook_recv".as_bytes()).unwrap() };
        let hook_recv = unsafe { hook_recv_hl.into_raw() };
        let hook_deliver_hl: libloading::Symbol<
            unsafe extern "C" fn(*const FnTable, *mut ParsedPacket) -> c_int,
        > = unsafe { library_inner.get("hook_deliver".as_bytes()).unwrap() };
        let hook_deliver = unsafe { hook_deliver_hl.into_raw() };
        let al = ActiveLibrary {
            library,
            hook_recv,
            hook_deliver,
        };
        Hooks { dlh: Some(al) }
    }

    #[inline]
    pub fn enabled(&self, _stage: Stage) -> bool {
        self.dlh.is_some()
    }

    pub fn apply_clientside(
        &self,
        session_state: SessionState,
        packet: Vec<u8>,
        stage: Stage,
    ) -> Result<(Action, Vec<u8>), &'static str> {
        if !self.enabled(stage) {
            return Ok((Action::Pass, packet));
        }
        let ds = match DNSSector::new(packet) {
            Ok(ds) => ds,
            Err(e) => {
                warn!("Cannot parse packet: {}", e);
                return Err("Cannot parse packet");
            }
        };
        let mut parsed_packet = match ds.parse() {
            Ok(parsed_packet) => parsed_packet,
            Err(e) => {
                warn!("Invalid packet: {}", e);
                return Err("Invalid packet");
            }
        };
        let dlh = self.dlh.as_ref().unwrap();
        let hook = match stage {
            Stage::Recv => &dlh.hook_recv,
            Stage::Deliver => &dlh.hook_deliver,
        };
        let fn_table = c_abi::fn_table();
        let action = unsafe { hook(&fn_table, &mut parsed_packet) }.into();

        let packet = parsed_packet.into_packet();
        Ok((action, packet))
    }

    pub fn apply_serverside(
        &self,
        packet: Vec<u8>,
        stage: Stage,
    ) -> Result<(Action, Vec<u8>), &'static str> {
        if !self.enabled(stage) {
            return Ok((Action::Pass, packet));
        }
        let ds = match DNSSector::new(packet) {
            Ok(ds) => ds,
            Err(e) => {
                warn!("Cannot parse packet: {}", e);
                return Err("Cannot parse packet");
            }
        };
        let mut parsed_packet = match ds.parse() {
            Ok(parsed_packet) => parsed_packet,
            Err(e) => {
                warn!("Invalid packet: {}", e);
                return Err("Invalid packet");
            }
        };
        let dlh = self.dlh.as_ref().unwrap();
        let hook = match stage {
            Stage::Recv => &dlh.hook_recv,
            Stage::Deliver => &dlh.hook_deliver,
        };
        let fn_table = c_abi::fn_table();
        let action = unsafe { hook(&fn_table, &mut parsed_packet) }.into();
        let packet = parsed_packet.into_packet();
        Ok((action, packet))
    }
}
