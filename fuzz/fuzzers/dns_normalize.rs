#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate libedgedns;

use libedgedns::dns;

fuzz_target!(|data: &[u8]| {
                 let _ = dns::normalize(data, false).map(|r| r.key());
                 let _ = dns::normalize(data, true).map(|r| r.key());
             });
