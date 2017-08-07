//! Pre/post cache/request hooks

use client_query::ClientQuery;
use dnssector::c_abi::{self, FnTable};
use dnssector::{DNSSector, ParsedPacket};
use nix::libc::{c_int, c_void};
use libloading::{Library, Symbol};
use std::mem;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Action {
    Pass = 1,
    Lookup,
    Drop,
}

impl From<Action> for c_int {
    fn from(v: Action) -> c_int {
        unsafe { mem::transmute(v as c_int) }
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

    pub fn apply_clientside(
        &self,
        client_query: &ClientQuery,
        packet: Vec<u8>,
        stage: Stage,
    ) -> Result<(Action, Vec<u8>), &'static str> {
        if !self.enabled(stage) {
            return Ok((Action::Pass, packet));
        }
        let dlh = self.dlh.as_ref().unwrap();
        let symbol = match stage {
            Stage::Recv => "hook_recv",
            Stage::Deliver => "hook_deliver",
        };
        let hook: Symbol<unsafe extern "C" fn(*const FnTable, *mut ParsedPacket) -> c_int> =
            unsafe { dlh.get(symbol.as_bytes()).unwrap() };

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
        let dlh = self.dlh.as_ref().unwrap();
        let hook: Symbol<unsafe extern "C" fn(*const FnTable, *mut ParsedPacket) -> c_int> =
            unsafe { dlh.get(b"hook").unwrap() };

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

        let fn_table = c_abi::fn_table();
        let action = unsafe { hook(&fn_table, &mut parsed_packet) }.into();

        let packet = parsed_packet.into_packet();
        Ok((action, packet))
    }
}
