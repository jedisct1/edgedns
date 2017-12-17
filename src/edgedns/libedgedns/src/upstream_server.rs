//! We currently keep very few information about Upstream Servers.
//! Mainly their IP address, and their state, along with the timestamp
//! of the last probe, for servers that we previously marked as unresponsive.
//!
//! The number of in-flight queries for individual servers is also present,
//! so that we can use this information for balancing the load.

use super::{UPSTREAM_QUERY_MAX_DEVIATION_COEFFICIENT, UPSTREAM_QUERY_MAX_TIMEOUT_MS,
            UPSTREAM_QUERY_MIN_TIMEOUT_MS};
use coarsetime::{Duration, Instant};
use config::Config;
use std::net::{self, SocketAddr};
use std::rc::Rc;
use std::sync::Arc;
use tokio_core::reactor::Handle;
use upstream_probe::UpstreamProbe;
use varz::Varz;

const RTT_DECAY: f64 = 0.125;
const RTT_DEV_DECAY: f64 = 0.25;

#[derive(Clone, Copy, Debug)]
pub struct UpstreamServerForQuery {
    pub socket_addr: SocketAddr,
}

impl UpstreamServerForQuery {
    pub fn from_upstream_server(upstream_server: &UpstreamServer) -> UpstreamServerForQuery {
        UpstreamServerForQuery {
            socket_addr: upstream_server.socket_addr,
        }
    }
}

pub struct UpstreamServer {
    pub remote_addr: String,
    pub socket_addr: SocketAddr,
    pub pending_queries_count: u64,
    pub failures: u32,
    pub last_successful_response_instant: Instant,
    pub offline: bool,
    pub last_probe_ts: Option<Instant>,
    pub rtt_est: Option<f64>,
    pub rtt_dev_est: f64,
}

impl UpstreamServer {
    pub fn new(remote_addr: &str) -> Result<UpstreamServer, &'static str> {
        let socket_addr = match remote_addr.parse() {
            Err(_) => return Err("Unable to parse an upstream resolver address"),
            Ok(socket_addr) => socket_addr,
        };
        let upstream_server = UpstreamServer {
            remote_addr: remote_addr.to_owned(),
            socket_addr: socket_addr,
            pending_queries_count: 0,
            failures: 0,
            last_successful_response_instant: Instant::now(),
            offline: false,
            last_probe_ts: None,
            rtt_est: None,
            rtt_dev_est: 0.0,
        };
        Ok(upstream_server)
    }

    fn reset_state(&mut self) {
        self.offline = false;
        self.failures = 0;
        self.pending_queries_count = 0;
        self.last_successful_response_instant = Instant::recent();
    }

    pub fn prepare_send(&mut self, config: &Config) {
        if self.offline
            || self.last_successful_response_instant.elapsed_since_recent()
                < config.upstream_max_failure_duration
        {
            return;
        }
        self.last_successful_response_instant = Instant::now();
    }

    pub fn record_failure(
        &mut self,
        config: &Config,
        handle: &Handle,
        ext_net_udp_sockets_rc: &Rc<Vec<net::UdpSocket>>,
    ) {
        if self.offline {
            return;
        }
        self.failures = self.failures.saturating_add(1);
        if self.last_successful_response_instant.elapsed_since_recent()
            < config.upstream_max_failure_duration
        {
            return;
        }
        self.offline = true;
        warn!(
            "Too many failures from resolver {}, putting offline",
            self.remote_addr
        );
    }

    pub fn record_success_after_failure(&mut self) {
        if !self.offline {
            self.failures = self.failures.saturating_sub(1);
            if self.failures == 0 {
                self.last_successful_response_instant = Instant::recent();
            }
            return;
        }
        self.reset_state();
        warn!("Marking {} as live again", self.socket_addr);
    }

    #[inline]
    fn ewma(cur: Option<f64>, v: f64, decay: f64) -> f64 {
        match cur {
            None => v,
            Some(cur) => (1.0 - decay) * cur + decay * v,
        }
    }

    pub fn record_rtt(&mut self, rtt: Duration, varz: &Arc<Varz>) {
        let rtt = rtt.as_f64();
        let rtt_est = Self::ewma(self.rtt_est, rtt, RTT_DECAY);
        self.rtt_est = Some(rtt_est);
        self.rtt_dev_est = Self::ewma(Some(self.rtt_dev_est), (rtt - rtt_est).abs(), RTT_DEV_DECAY);
        varz.upstream_avg_rtt.set(Self::ewma(
            Some(varz.upstream_avg_rtt.get()),
            rtt_est,
            RTT_DECAY,
        ));
    }

    pub fn timeout_ms_est(&self) -> u64 {
        let timeout = match self.rtt_est {
            None => UPSTREAM_QUERY_MAX_TIMEOUT_MS,
            Some(rtt_est) => {
                let timeout = ((rtt_est
                    + self.rtt_dev_est * UPSTREAM_QUERY_MAX_DEVIATION_COEFFICIENT)
                    * 1000.0) as u64;
                if timeout < UPSTREAM_QUERY_MIN_TIMEOUT_MS {
                    UPSTREAM_QUERY_MIN_TIMEOUT_MS
                } else if timeout > UPSTREAM_QUERY_MAX_TIMEOUT_MS {
                    UPSTREAM_QUERY_MAX_TIMEOUT_MS
                } else {
                    timeout
                }
            }
        };
        debug!(
            "Upstream {} timeout_ms_est={} (rtt_est: {} rtt_dev_est: {})",
            self.remote_addr,
            timeout,
            self.rtt_est.unwrap_or(-1.0),
            self.rtt_dev_est
        );
        timeout
    }

    pub fn live_servers(upstream_servers: &mut Vec<UpstreamServer>) -> Vec<usize> {
        let mut new_live: Vec<usize> = Vec::with_capacity(upstream_servers.len());
        for (idx, upstream_server) in upstream_servers.iter().enumerate() {
            if !upstream_server.offline {
                new_live.push(idx);
            }
        }
        if new_live.is_empty() {
            warn!("No more live servers, trying to resurrect them all");
            for (idx, upstream_server) in upstream_servers.iter_mut().enumerate() {
                upstream_server.offline = false;
                new_live.push(idx);
            }
        }
        info!("Live upstream servers: {:?}", new_live);
        new_live
    }
}
