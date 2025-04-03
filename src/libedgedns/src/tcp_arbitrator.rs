//! Arbitrator, mainly used for client TCP sessions
//! Enforces a maximum amount of simultaneous sessions, but refusing new oneshot
//! once the slab is full, or by reusing existing slots.

use super::MAX_TCP_HASH_DISTANCE;
use futures::sync::oneshot;
use parking_lot::Mutex;
use rand::distributions::{IndependentSample, Range};
use rand::{self, Rng};
use siphasher::sip::SipHasher13;
use slab::Slab;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::Arc;

struct Session {
    session_tx: oneshot::Sender<()>,
    h: u64,
}

struct Sessions {
    slab: Slab<Session>,
}

#[derive(Clone)]
pub struct TcpArbitrator {
    sessions_mx: Arc<Mutex<Sessions>>,
    hasher: SipHasher13,
}

impl TcpArbitrator {
    pub fn with_capacity(capacity: usize) -> Self {
        let slab = Slab::with_capacity(capacity);
        let sessions = Sessions { slab };
        let mut rng = rand::thread_rng();
        let hasher = SipHasher13::new_with_keys(rng.gen(), rng.gen());
        TcpArbitrator {
            sessions_mx: Arc::new(Mutex::new(sessions)),
            hasher,
        }
    }

    pub fn new_session(
        &mut self,
        client_addr: &SocketAddr,
    ) -> Result<(oneshot::Receiver<()>, usize), &'static str> {
        let mut hasher = self.hasher;
        client_addr.ip().hash(&mut hasher);
        let h = hasher.finish();
        let (session_tx, session_rx) = oneshot::channel();
        let session = Session { session_tx, h };
        let slab = &mut self.sessions_mx.lock().slab;
        self.recycle_slot_if_full(slab, h);
        if slab.len() == slab.capacity() {
            warn!("Tcp arbitrator slab is full");
            return Err("Tcp arbitrator slab is full");
        }
        let idx = slab.insert(session);
        Ok((session_rx, idx))
    }

    pub fn delete_session(&mut self, idx: usize) {
        self.sessions_mx.lock().slab.remove(idx);
    }

    fn recycle_slot_if_full(&self, slab: &mut Slab<Session>, h: u64) {
        if slab.len() < slab.capacity() {
            return;
        }
        let mut rng = rand::thread_rng();
        let random_distance = Range::new(0, MAX_TCP_HASH_DISTANCE).ind_sample(&mut rng);
        let capacity = slab.capacity();
        let base_slot = (h as usize) % capacity;
        let mut new_slot = None;
        for i in 0..MAX_TCP_HASH_DISTANCE {
            let probed_slot =
                (base_slot + (random_distance + i) % MAX_TCP_HASH_DISTANCE) % capacity;
            match slab.get(probed_slot) {
                None => {
                    new_slot = Some(probed_slot);
                    break;
                }
                Some(session) => {
                    if session.h == h {
                        new_slot = Some(probed_slot);
                        break;
                    }
                }
            }
        }
        let new_slot = new_slot.unwrap_or((base_slot + random_distance) % MAX_TCP_HASH_DISTANCE);
        if slab.contains(new_slot) {
            let prev_session = slab.remove(new_slot);
            info!("Recycling session index {}", new_slot);
            let _ = prev_session.session_tx.send(());
        }
    }
}
