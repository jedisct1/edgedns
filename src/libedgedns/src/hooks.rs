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
use qp_trie::Trie;
use std::ffi::OsStr;
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

type HookSymbolClientT = unsafe extern "C" fn(*const FnTable, *mut ParsedPacket) -> c_int;

struct ServiceHooks {
    library: Arc<Library>,
    hook_recv: Option<Symbol<HookSymbolClientT>>,
    hook_deliver: Option<Symbol<HookSymbolClientT>>,
}

struct Service {
    service_hooks: Option<ServiceHooks>,
}

pub struct Hooks {
    services: Trie<Vec<u8>, Service>,
}

impl Service {
    fn new(library_path: Option<&str>) -> Result<Service, &'static str> {
        let library_path = match library_path {
            None => {
                return Ok(Service {
                    service_hooks: None,
                })
            }
            Some(library_path) => library_path,
        };
        let library = match Library::new(library_path) {
            Err(e) => {
                error!("Cannot load the dynamic library [{}] [{}]", library_path, e);
                return Err("Unable to load the dynamic library");
            }
            Ok(library) => Arc::new(library),
        };

        let library_inner = library.clone();

        let hook_recv_hl: libloading::Result<libloading::Symbol<HookSymbolClientT>> =
            unsafe { library_inner.get("hook_recv".as_bytes()) };
        let hook_recv = hook_recv_hl.ok().map(|hook| unsafe { hook.into_raw() });

        let hook_deliver_hl: libloading::Result<libloading::Symbol<HookSymbolClientT>> =
            unsafe { library_inner.get("hook_deliver".as_bytes()) };
        let hook_deliver = hook_deliver_hl.ok().map(|hook| unsafe { hook.into_raw() });

        let service_hooks = ServiceHooks {
            library,
            hook_recv,
            hook_deliver,
        };
        Ok(Service {
            service_hooks: Some(service_hooks),
        })
    }
}

impl Hooks {
    pub fn new() -> Self {
        let mut services = Trie::new();
        let master_service =
            Service::new(Some("c_hook.dylib")).expect("Unable to load the master service");
        let master_service_id = vec![0u8; 1];
        services.insert(master_service_id, master_service);
        Hooks { services }
    }

    #[inline]
    pub fn enabled(&self, _stage: Stage) -> bool {
        let master_service_id = vec![0u8; 1];
        let service = self.services.get(&master_service_id);
        service
            .expect("Nonexistent service")
            .service_hooks
            .is_some()
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
        let master_service_id = vec![0u8; 1];
        let service = self.services
            .get(&master_service_id)
            .expect("Nonexistent service");
        let service_hooks = service.service_hooks.as_ref().unwrap();
        let hook = match stage {
            Stage::Recv => service_hooks.hook_recv.as_ref().unwrap(),
            Stage::Deliver => service_hooks.hook_deliver.as_ref().unwrap(),
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
        let master_service_id = vec![0u8; 1];
        let service = self.services
            .get(&master_service_id)
            .expect("Nonexistent service");
        let service_hooks = service.service_hooks.as_ref().unwrap();
        let hook = match stage {
            Stage::Recv => service_hooks.hook_recv.as_ref().unwrap(),
            Stage::Deliver => service_hooks.hook_deliver.as_ref().unwrap(),
        };
        let fn_table = c_abi::fn_table();
        let action = unsafe { hook(&fn_table, &mut parsed_packet) }.into();
        let packet = parsed_packet.into_packet();
        Ok((action, packet))
    }
}
