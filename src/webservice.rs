
use civet::{Config, response, Server};
use conduit_middleware::{Middleware, MiddlewareBuilder};
use conduit_router::RouteBuilder;
use conduit::{Request, Response};
use rustc_serialize::json;
use std::collections::HashMap;
use std::error::Error;
use std::io::{self, Cursor};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc::channel;
use std::thread::spawn;
use varz::{StartInstant, Varz};

use super::RPDNSContext;
use super::{WEBSERVICE_PORT, WEBSERVICE_THREADS};

#[derive(RustcDecodable, RustcEncodable, Debug)]
struct PublicVarz {
    uptime: u64,
    cache_len: usize,
    cache_frequent_len: usize,
    cache_recent_len: usize,
    client_qps: f32,
    client_queries_cached: usize,
    client_queries_cached_ratio: f32,
    client_queries_errors: usize,
    client_queries_expired: usize,
    client_queries_inserted: u64,
    client_queries_evicted: u64,
    client_queries: usize,
    client_queries_tcp: usize,
    client_queries_udp: usize,
    resolver_errors: usize,
    resolver_received: usize,
    resolver_timeout: usize,
}

impl PublicVarz {
    fn new(varz: &Arc<Varz>) -> PublicVarz {
        let StartInstant(start_instant) = varz.start_instant;
        let uptime = start_instant.elapsed().as_secs();
        let cache_frequent_len = varz.cache_frequent_len.load(Ordering::Relaxed);
        let cache_recent_len = varz.cache_recent_len.load(Ordering::Relaxed);
        let client_queries_udp = varz.client_queries_udp.load(Ordering::Relaxed);
        let client_queries_tcp = varz.client_queries_tcp.load(Ordering::Relaxed);
        let client_queries = client_queries_udp + client_queries_tcp;
        let client_queries_cached = varz.client_queries_cached.load(Ordering::Relaxed);
        let client_queries_cached_ratio = if client_queries == 0 {
            0.0
        } else {
            (client_queries_cached as f32 * 100.0) / (client_queries as f32)
        };
        let client_qps = if uptime == 0 {
            0.0
        } else {
            (client_queries as f32) / (uptime as f32)
        };
        PublicVarz {
            uptime: uptime,
            cache_len: cache_frequent_len + cache_recent_len,
            cache_frequent_len: cache_frequent_len,
            cache_recent_len: cache_recent_len,
            client_qps: client_qps,
            client_queries: client_queries,
            client_queries_udp: client_queries_udp,
            client_queries_tcp: client_queries_tcp,
            client_queries_cached: client_queries_cached,
            client_queries_cached_ratio: client_queries_cached_ratio,
            client_queries_inserted: varz.cache_inserted.load(Ordering::Relaxed),
            client_queries_evicted: varz.cache_evicted.load(Ordering::Relaxed),
            client_queries_expired: varz.client_queries_expired.load(Ordering::Relaxed),
            client_queries_errors: varz.client_queries_errors.load(Ordering::Relaxed),
            resolver_errors: varz.resolver_errors.load(Ordering::Relaxed),
            resolver_received: varz.resolver_received.load(Ordering::Relaxed),
            resolver_timeout: varz.resolver_timeout.load(Ordering::Relaxed),
        }
    }
}

pub struct WebService {
    varz: Arc<Varz>,
}

impl Middleware for WebService {
    fn before(&self, req: &mut Request) -> Result<(), Box<Error + Send>> {
        req.mut_extensions().insert(self.varz.clone());
        Ok(())
    }
}

impl WebService {
    fn new(rpdns_context: &RPDNSContext) -> WebService {
        WebService { varz: rpdns_context.varz.clone() }
    }

    fn varz(req: &mut Request) -> io::Result<Response> {
        let varz = req.extensions().find::<Arc<Varz>>().unwrap();
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_owned(),
                       vec!["application/json".to_owned()]);
        headers.insert("Server".to_owned(), vec!["EdgeDNS Webservice".to_owned()]);
        let public_varz = PublicVarz::new(varz);
        let body = json::encode(&public_varz).unwrap().into_bytes();
        Ok(response(200, headers, Cursor::new(body)))
    }

    pub fn spawn(rpdns_context: &RPDNSContext) -> io::Result<()> {
        let mut builder = MiddlewareBuilder::new(Self::varz);
        let web_service = WebService::new(&rpdns_context);
        builder.add(web_service);
        let mut router = RouteBuilder::new();
        router.get("/varz", builder);
        let mut cfg = Config::new();
        cfg.port(WEBSERVICE_PORT).keep_alive(false).threads(WEBSERVICE_THREADS);
        spawn(|| {
            let server = Server::start(cfg, router).expect("Unable to spawn the web service");
            let _ = server;
            info!("Webservice started on port {}", WEBSERVICE_PORT);
            let (_tx, rx) = channel::<()>();
            rx.recv().unwrap();
        });
        Ok(())
    }
}
