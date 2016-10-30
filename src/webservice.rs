use hyper::header::{ContentLength, ContentType};
use hyper::mime::{self, Mime};
use hyper::server::{Server, Request, Response};
use hyper::status::StatusCode;
use hyper::uri::RequestUri::AbsolutePath;
use rustc_serialize::json;
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::thread::spawn;
use varz::{StartInstant, Varz};

use super::RPDNSContext;
use super::{WEBSERVICE_ADDRESS, WEBSERVICE_THREADS};

#[derive(RustcDecodable, RustcEncodable, Debug)]
struct PublicVarz {
    uptime: u64,
    cache_len: usize,
    cache_frequent_len: usize,
    cache_recent_len: usize,
    cache_test_len: usize,
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
        let cache_test_len = varz.cache_test_len.load(Ordering::Relaxed);
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
            cache_test_len: cache_test_len,
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

impl WebService {
    fn new(rpdns_context: &RPDNSContext) -> WebService {
        WebService { varz: rpdns_context.varz.clone() }
    }

    fn handler(&self, req: Request, mut res: Response) {
        match req.uri {
            AbsolutePath(ref path) if path == "/varz" => path,
            _ => {
                *res.status_mut() = StatusCode::NotFound;
                return;
            }
        };
        let public_varz = PublicVarz::new(&self.varz);
        let body = json::encode(&public_varz).unwrap();
        {
            let headers = res.headers_mut();
            headers.set(ContentLength(body.len() as u64));
            headers.set(ContentType(Mime(mime::TopLevel::Application,
                                         mime::SubLevel::Json,
                                         vec![(mime::Attr::Charset, mime::Value::Utf8)])));
        }
        let mut res = res.start().unwrap();
        res.write_all(&body.into_bytes()).unwrap();
        res.end().unwrap();
    }

    pub fn spawn(rpdns_context: &RPDNSContext) -> io::Result<()> {
        let web_service = WebService::new(rpdns_context);
        spawn(move || {
            let mut server = Server::http(WEBSERVICE_ADDRESS)
                .expect("Unable to spawn the webservice");
            server.keep_alive(None);
            info!("Webservice started on {}", WEBSERVICE_ADDRESS);
            server.handle_threads(move |req: Request, res: Response| {
                                    web_service.handler(req, res)
                                },
                                WEBSERVICE_THREADS)
                .expect("Unable to start the webservice");
        });
        Ok(())
    }
}
