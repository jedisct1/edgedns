//! Expose metrics via the Prometheus API

use futures::future::{self, FutureResult};
use hyper;
use hyper::header::{ContentLength, ContentType};
use hyper::mime::Mime;
use hyper::server::{Http, Service, Server, Request, Response};
use hyper::{StatusCode, Uri};
use prometheus::{self, Encoder, TextEncoder};
use std::io;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use varz::{StartInstant, Varz};

use super::EdgeDNSContext;

#[derive(Clone)]
pub struct WebService {
    varz: Arc<Varz>,
}

impl Service for WebService {
    type Request = Request;
    type Response = Response;
    type Error = hyper::Error;
    type Future = FutureResult<Response, hyper::Error>;

    fn call(&self, req: Request) -> Self::Future {
        if req.uri().path() != "/metrics" {
            return future::ok(Response::new().with_status(StatusCode::NotFound));
        }
        let StartInstant(start_instant) = self.varz.start_instant;
        let uptime = start_instant.elapsed().as_secs();
        self.varz.uptime.set(uptime as f64);
        let client_queries = self.varz.client_queries_udp.get() +
            self.varz.client_queries_tcp.get();
        self.varz.client_queries.set(client_queries);
        let metric_families = prometheus::gather();
        let mut buffer = vec![];
        let encoder = TextEncoder::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        future::ok(
            Response::new()
                .with_header(ContentLength(buffer.len() as u64))
                .with_header(ContentType(encoder.format_type().parse::<Mime>().unwrap()))
                .with_body(buffer)
        )
    }
}

impl WebService {
    fn new(edgedns_context: &EdgeDNSContext) -> WebService {
        WebService { varz: edgedns_context.varz.clone() }
    }

    pub fn spawn(edgedns_context: &EdgeDNSContext,
                 service_ready_tx: mpsc::SyncSender<u8>)
                 -> io::Result<thread::JoinHandle<()>> {
        let listen_addr = edgedns_context
            .config
            .webservice_listen_addr
            .parse()
            .expect("Unsupport listen address for the prometheus service");
        let web_service = WebService::new(edgedns_context);
        let webservice_th = thread::Builder::new()
            .name("webservice".to_string())
            .spawn(
                move || {
                    let server = Http::new()
                        .keep_alive(false)
                        .bind(&listen_addr, move || Ok(web_service.clone()))
                        .expect("Unable to spawn the webservice");
                    service_ready_tx.send(2).unwrap();
                    info!("Webservice started on {}", listen_addr);
                    server.run().expect("Unable to start the webservice");
                }
            )
            .unwrap();
        Ok(webservice_th)
    }
}
