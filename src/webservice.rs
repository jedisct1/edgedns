use hyper::header::ContentType;
use hyper::mime::Mime;
use hyper::server::{Server, Request, Response};
use hyper::status::StatusCode;
use hyper::uri::RequestUri::AbsolutePath;
use prometheus::{self, Encoder, TextEncoder};
use varz::{StartInstant, Varz};
use std::io;
use std::sync::Arc;
use std::thread::spawn;

use super::RPDNSContext;
use super::WEBSERVICE_THREADS;

pub struct WebService {
    varz: Arc<Varz>,
}

impl WebService {
    fn new(rpdns_context: &RPDNSContext) -> WebService {
        WebService { varz: rpdns_context.varz.clone() }
    }

    fn handler(&self, req: Request, mut res: Response) {
        match req.uri {
            AbsolutePath(ref path) if path == "/metrics" => path,
            _ => {
                *res.status_mut() = StatusCode::NotFound;
                return;
            }
        };
        let StartInstant(start_instant) = self.varz.start_instant;
        let uptime = start_instant.elapsed().as_secs();
        self.varz.uptime.set(uptime as f64);
        let client_queries = self.varz.client_queries_udp.get() +
                             self.varz.client_queries_tcp.get();
        self.varz.client_queries.set(client_queries);
        if uptime > 0 {
            self.varz.client_qps.set(client_queries / (uptime as f64));
        }
        let metric_families = prometheus::gather();
        let mut buffer = vec![];
        let encoder = TextEncoder::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        res.headers_mut()
            .set(ContentType(encoder.format_type().parse::<Mime>().unwrap()));
        res.send(&buffer).unwrap();
    }

    pub fn spawn(rpdns_context: &RPDNSContext) -> io::Result<()> {
        let listen_addr = rpdns_context.config.webservice_listen_addr.to_owned();
        let web_service = WebService::new(rpdns_context);
        spawn(move || {
            let mut server = Server::http(&*listen_addr).expect("Unable to spawn the webservice");
            server.keep_alive(None);
            info!("Webservice started on {}", listen_addr);
            server.handle_threads(move |req: Request, res: Response| {
                                    web_service.handler(req, res)
                                },
                                WEBSERVICE_THREADS)
                .expect("Unable to start the webservice");
        });
        Ok(())
    }
}
