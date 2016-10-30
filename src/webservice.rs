use hyper::header::ContentType;
use hyper::mime::Mime;
use hyper::server::{Server, Request, Response};
use hyper::status::StatusCode;
use hyper::uri::RequestUri::AbsolutePath;
use prometheus::{self, Encoder, TextEncoder};
use std::io;
use std::thread::spawn;

use super::RPDNSContext;
use super::WEBSERVICE_THREADS;

pub struct WebService;

impl WebService {
    fn new(_rpdns_context: &RPDNSContext) -> WebService {
        WebService {}
    }

    fn handler(&self, req: Request, mut res: Response) {
        match req.uri {
            AbsolutePath(ref path) if path == "/metrics" => path,
            _ => {
                *res.status_mut() = StatusCode::NotFound;
                return;
            }
        };
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
