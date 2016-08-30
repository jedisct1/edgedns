
use dns::NormalizedQuestion;
use mio::*;
use mio::deprecated::Sender;
use resolver::*;
use std::net::SocketAddr;
use std::time::Instant;

#[derive(Copy, Clone, Debug)]
pub enum ClientQueryProtocol {
    UDP,
    TCP,
}

#[derive(Clone, Debug)]
pub struct ClientQuery {
    pub proto: ClientQueryProtocol,
    pub client_addr: Option<SocketAddr>,
    pub tcpclient_tx: Option<Sender<ResolverResponse>>,
    pub client_tok: Option<Token>,
    pub normalized_question: NormalizedQuestion,
    pub ts: Instant,
}
