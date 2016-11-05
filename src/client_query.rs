use dns::NormalizedQuestion;
use mio::*;
use resolver::*;
use std::net::SocketAddr;
use std::time::Instant;

#[derive(Copy, Clone, Debug)]
pub enum ClientQueryProtocol {
    UDP,
    TCP,
}

#[derive(Clone)]
pub struct ClientQuery {
    pub proto: ClientQueryProtocol,
    pub client_addr: Option<SocketAddr>,
    pub tcpclient_tx: Option<channel::SyncSender<ResolverResponse>>,
    pub client_tok: Option<Token>,
    pub normalized_question: NormalizedQuestion,
    pub ts: Instant,
}
