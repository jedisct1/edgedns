//! Pre/post cache/request hooks

use dnssector::c_abi::{self, FnTable};
use dnssector::DNSSector;
use libloading::{Symbol, Library};

pub struct Hooks;

impl Hooks {
    pub fn new() -> Self {
        Hooks
    }
}
