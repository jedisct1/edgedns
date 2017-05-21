//! Upstream Probes are synthetic questions designed to perform health checks
//!
//! They include an authenticated timestamp and an optional zone, for servers
//! that don't send any response to zones they are not authoritative for.

use base64;
use byteorder::{NativeEndian, ReadBytesExt, WriteBytesExt};
use coarsetime::Clock;
use dns;
use rand::distributions::{IndependentSample, Range};
use rand::{self, Rng};
use siphasher::sip::SipHasher13;
use std::hash::{Hash, Hasher};
use std::io::Cursor;
use std::net::{self, SocketAddr};
use std::rc::Rc;
use tokio_core::reactor::Handle;
use upstream_server::UpstreamServer;

const PROBE_PREFIX: &[u8] = b"edgedns-probe-";
const PROBE_SUFFIX: &[u8] = b"";
const PROBE_KEY_LEN: usize = 12;
const PROBE_KEY_B64_LEN: usize = 16;

lazy_static! {
    static ref HASHER: SipHasher13 = {
        let mut rng = rand::thread_rng();   
        SipHasher13::new_with_keys(rng.gen(), rng.gen())          
    };
}

pub struct UpstreamProbe {
    hasher: SipHasher13,
}

impl UpstreamProbe {
    pub fn new(handle: &Handle,
               net_ext_udp_sockets: &Rc<Vec<net::UdpSocket>>,
               upstream_server: &UpstreamServer)
               -> Self {
        let probe = UpstreamProbe { hasher: *HASHER };
        let probe_qname = probe
            .compute_probe_qname(PROBE_SUFFIX, &upstream_server.socket_addr)
            .unwrap();
        let packet = dns::build_probe_packet(&probe_qname).unwrap();
        let mut rng = rand::thread_rng();
        let random_token_range = Range::new(0usize, net_ext_udp_sockets.len());
        let random_token = random_token_range.ind_sample(&mut rng);
        let net_ext_udp_socket = &net_ext_udp_sockets[random_token];
        let _ = net_ext_udp_socket.send_to(&packet, &upstream_server.socket_addr);
        info!("Sent probe to {}", upstream_server.socket_addr.ip());
        probe
    }

    fn compute_probe_qname(&self,
                           probe_suffix: &[u8],
                           socket_addr: &SocketAddr)
                           -> Result<Vec<u8>, &'static str> {
        let mut hasher = self.hasher;
        let mut probe_key = Vec::with_capacity(PROBE_KEY_LEN);
        let now_secs = Clock::recent_since_epoch().as_secs();
        probe_key
            .write_u32::<NativeEndian>(now_secs as u32)
            .unwrap();
        (now_secs as u32).hash(&mut hasher);
        socket_addr.hash(&mut hasher);
        probe_key
            .write_u64::<NativeEndian>(hasher.finish())
            .unwrap();
        let probe_key_b64 = base64::encode_config(&probe_key, base64::URL_SAFE_NO_PAD);
        let probe_key_b64 = probe_key_b64.as_bytes();
        let mut probe_name = Vec::with_capacity(1 + PROBE_PREFIX.len() + probe_key_b64.len() + 1 +
                                                probe_suffix.len() +
                                                1);
        probe_name.push((PROBE_PREFIX.len() + probe_key_b64.len()) as u8);
        probe_name.extend(PROBE_PREFIX);
        probe_name.extend(probe_key_b64);
        if !probe_suffix.is_empty() {
            probe_name.push(probe_suffix.len() as u8);
            probe_name.extend(probe_suffix);
        }
        probe_name.push(0u8);
        Ok(probe_name)
    }

    fn verify_probe_qname(&self,
                          probe_name: &[u8],
                          probe_suffix: &[u8],
                          socket_addr: &SocketAddr)
                          -> Result<(), &'static str> {
        let probe_prefix_len = PROBE_PREFIX.len();
        let probe_suffix_len_with_terminator = if probe_suffix.is_empty() {
            0
        } else {
            probe_suffix.len() + 1
        };
        if probe_name.len() !=
           1 + probe_prefix_len + PROBE_KEY_B64_LEN + 1 + probe_suffix_len_with_terminator {
            return Err("Name length doesn't match the length of a valid probe");
        }
        if probe_name.is_empty() ||
           probe_name[0] as usize != probe_prefix_len + PROBE_KEY_B64_LEN ||
           !probe_name[1..].starts_with(PROBE_PREFIX) {
            return Err("Probe prefix doesn't match");
        }
        let probe_key_b64 = &probe_name[1 + probe_prefix_len..
        (probe_name.len() - probe_suffix_len_with_terminator - 1)];
        let probe_key = match base64::decode_config(probe_key_b64, base64::URL_SAFE_NO_PAD) {
            Ok(probe_key) => probe_key,
            _ => return Err("Unable to decode the key"),
        };
        if probe_key.len() != PROBE_KEY_LEN {
            return Err("Decoded key doesn't have the expected length");
        }
        let mut probe_key_c = Cursor::new(probe_key);
        let ts_secs = probe_key_c.read_u32::<NativeEndian>().unwrap() as u64;
        let now_secs = Clock::recent_since_epoch().as_secs();
        if ts_secs < now_secs || ts_secs - now_secs > 10 {
            return Err("Probe response is too old");
        }
        let expected_h = probe_key_c.read_u64::<NativeEndian>().unwrap();
        let mut hasher = self.hasher;
        (now_secs as u32).hash(&mut hasher);
        socket_addr.hash(&mut hasher);
        if hasher.finish() != expected_h {
            return Err("Wrong hash for the given probe");
        }
        Ok(())
    }
}
