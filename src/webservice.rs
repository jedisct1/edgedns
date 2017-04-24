use hyper::header::ContentType;
use hyper::mime::Mime;
use hyper::server::{Server, Request, Response};
use hyper::status::StatusCode;
use hyper::uri::RequestUri::AbsolutePath;
use prometheus::{self, Encoder, TextEncoder};
use varz::{StartInstant, Varz};
use std::io;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;

use super::EdgeDNSContext;
use super::WEBSERVICE_THREADS;

pub struct WebService {
    varz: Arc<Varz>,
}

impl WebService {
    fn new(edgedns_context: &EdgeDNSContext) -> WebService {
        WebService { varz: edgedns_context.varz.clone() }
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
        let metric_families = prometheus::gather();
        let mut buffer = vec![];
        let encoder = TextEncoder::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        res.headers_mut()
            .set(ContentType(encoder.format_type().parse::<Mime>().unwrap()));
        res.send(&buffer).unwrap();
    }

    pub fn spawn(edgedns_context: &EdgeDNSContext,
                 service_ready_tx: mpsc::SyncSender<u8>)
                 -> io::Result<thread::JoinHandle<()>> {
        let listen_addr = edgedns_context.config.webservice_listen_addr.to_owned();
        let web_service = WebService::new(edgedns_context);
        let webservice_th = thread::Builder::new()
            .name("webservice".to_string())
            .spawn(move || {
                let mut server =
                    Server::http(&*listen_addr).expect("Unable to spawn the webservice");
                server.keep_alive(None);
                service_ready_tx.send(2).unwrap();
                info!("Webservice started on {}", listen_addr);
                server
                    .handle_threads(move |req: Request, res: Response| {
                                        web_service.handler(req, res)
                                    },
                                    WEBSERVICE_THREADS)
                    .expect("Unable to start the webservice");
            })
            .unwrap();
        Ok(webservice_th)
    }
}
