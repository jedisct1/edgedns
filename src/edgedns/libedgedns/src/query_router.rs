use super::{DNS_UDP_NOEDNS0_MAX_SIZE, DNS_MAX_TCP_SIZE, DNS_MAX_UDP_SIZE, DNS_RESPONSE_MIN_SIZE,
            UPSTREAM_TOTAL_TIMEOUT_MS};
use byteorder::{BigEndian, ByteOrder};
use cache::*;
use client_query::*;
use dns;
use dns::*;
use dnssector::*;
use errors::*;
use failure;
use futures::{future, Future};
use futures::Async;
use futures::Sink;
use futures::prelude::*;
use futures::sync::mpsc::Sender;
use futures::sync::oneshot;
use futures::task;
use globals::*;
use hooks;
use hooks::*;
use std::ptr;
use std::rc::Rc;
use std::time;
use tokio_timer::{Timeout, TimeoutError, Timer};
use upstream_server::*;

pub struct Answer {
    packet: Vec<u8>,
    ttl: Option<u32>,
    special: bool,
}

impl From<Vec<u8>> for Answer {
    fn from(packet: Vec<u8>) -> Answer {
        Answer {
            packet,
            ttl: None,
            special: false,
        }
    }
}

impl From<(Vec<u8>, u32)> for Answer {
    fn from(packet_ttl: (Vec<u8>, u32)) -> Answer {
        Answer {
            packet: packet_ttl.0,
            ttl: Some(packet_ttl.1),
            special: false,
        }
    }
}

pub enum PacketOrFuture {
    Packet(Vec<u8>),
    Future(Box<Future<Item = Vec<u8>, Error = failure::Error>>),
}

pub enum AnswerOrFuture {
    Answer(Answer),
    Future(Box<Future<Item = Answer, Error = failure::Error>>),
}

pub struct QueryRouter {
    globals: Rc<Globals>,
    session_state: Option<SessionState>,
    timer: Timer,
}

impl QueryRouter {
    fn rewrite_according_to_original_query(
        &self,
        parsed_packet: &mut ParsedPacket,
        answer: Answer,
        protocol: ClientQueryProtocol,
    ) -> Result<Vec<u8>, failure::Error> {
        let mut packet = answer.packet;
        if packet.len() < DNS_RESPONSE_MIN_SIZE || !dns::qr(&packet) {
            xbail!(DNSError::Unexpected);
        }
        if let Some(ttl) = answer.ttl {
            dns::set_ttl(&mut packet, ttl).map_err(|_| DNSError::InternalError)?
        };

        {
            let original_qname = match parsed_packet.question_raw() {
                Some((original_qname, ..)) => original_qname,
                None => xbail!(DNSError::Unexpected),
            };
            dns::overwrite_qname(&mut packet, original_qname)?;
        }

        let tid = parsed_packet.tid();
        dns::set_tid(&mut packet, tid);

        let packet_len = packet.len();
        if packet.len() < DNS_RESPONSE_MIN_SIZE
            || (protocol == ClientQueryProtocol::UDP && packet_len > DNS_MAX_UDP_SIZE)
            || (protocol == ClientQueryProtocol::TCP && packet_len > DNS_MAX_TCP_SIZE)
        {
            let normalized_question = match NormalizedQuestion::from_parsed_packet(parsed_packet) {
                Ok(normalized_question) => normalized_question,
                Err(_) => xbail!(DNSError::InvalidPacket),
            };
            let (qtype, qclass) = parsed_packet.qtype_qclass().ok_or(DNSError::Unexpected)?;
            let original_qname = match parsed_packet.question_raw() {
                Some((original_qname, ..)) => original_qname,
                None => xbail!(DNSError::Unexpected),
            };
            packet = dns::build_refused_packet(original_qname, qtype, qclass, tid)?;
        }

        match protocol {
            ClientQueryProtocol::UDP
                if packet_len > DNS_UDP_NOEDNS0_MAX_SIZE as usize
                    && (packet_len > DNS_MAX_UDP_SIZE as usize
                        || packet_len > parsed_packet.max_payload()) =>
            {
                let (qtype, qclass) = parsed_packet.qtype_qclass().ok_or(DNSError::Unexpected)?;
                let original_qname = match parsed_packet.question_raw() {
                    Some((original_qname, ..)) => original_qname,
                    None => xbail!(DNSError::Unexpected),
                };
                packet = dns::build_tc_packet(original_qname, qtype, qclass, tid)?;
            }
            ClientQueryProtocol::UDP => debug_assert!(packet_len <= DNS_MAX_UDP_SIZE),

            ClientQueryProtocol::TCP => {
                if packet_len > DNS_MAX_TCP_SIZE {
                    xbail!(DNSError::InternalError)
                }
                packet.reserve(2);
                unsafe {
                    packet.set_len(2 + packet_len);
                    ptr::copy(packet.as_ptr(), packet.as_mut_ptr().offset(2), packet_len);
                }
                BigEndian::write_u16(&mut packet, packet_len as u16);
            }
        }
        Ok(packet)
    }

    pub fn create(
        globals: Rc<Globals>,
        mut parsed_packet: ParsedPacket,
        protocol: ClientQueryProtocol,
        session_state: SessionState,
        timer: Timer,
    ) -> PacketOrFuture {
        let mut query_router = QueryRouter {
            globals,
            session_state: Some(session_state),
            timer,
        };
        match query_router.create_answer(&mut parsed_packet) {
            Ok(AnswerOrFuture::Answer(answer)) => {
                let packet = match query_router.rewrite_according_to_original_query(
                    &mut parsed_packet,
                    answer,
                    protocol,
                ) {
                    Ok(packet) => packet,
                    Err(e) => return PacketOrFuture::Future(Box::new(future::err(e))),
                };
                PacketOrFuture::Packet(packet)
            }
            Ok(AnswerOrFuture::Future(future)) => {
                let fut = future.and_then(move |answer| {
                    let packet = query_router
                        .rewrite_according_to_original_query(&mut parsed_packet, answer, protocol)
                        .expect("Unable to rewrite according to the original query");
                    future::ok(packet)
                });
                PacketOrFuture::Future(Box::new(fut))
            }
            Err(e) => PacketOrFuture::Future(Box::new(future::err(e))),
        }
    }

    fn create_answer(
        &mut self,
        mut parsed_packet: &mut ParsedPacket,
    ) -> Result<AnswerOrFuture, failure::Error> {
        if let Some(answer) =
            SpecialQueries::handle_special_queries(&self.globals, &mut parsed_packet)
        {
            return Ok(AnswerOrFuture::Answer(answer));
        };

        let hooks_arc = self.globals.hooks_arc.read();
        if hooks_arc.enabled(Stage::Recv) {
            let action = hooks_arc
                .apply_clientside(
                    self.session_state.as_mut().unwrap(),
                    parsed_packet,
                    Stage::Recv,
                )
                .map_err(|e| DNSError::HookError(e))?;
            match action {
                hooks::Action::Pass | hooks::Action::Pipe | hooks::Action::Purge => {
                    self.session_state
                        .as_mut()
                        .expect("session_state is None")
                        .inner
                        .write()
                        .bypass_cache = true
                }
                hooks::Action::Drop => return Err(DNSError::Refused.into()),
                hooks::Action::Fail => {
                    let tid = parsed_packet.tid();
                    let (qtype, qclass) = parsed_packet.qtype_qclass().ok_or(DNSError::Unexpected)?;
                    let original_qname = match parsed_packet.question_raw() {
                        Some((original_qname, ..)) => original_qname,
                        None => xbail!(DNSError::Unexpected),
                    };
                    let packet = dns::build_refused_packet(original_qname, qtype, qclass, tid)?;
                    let answer = Answer::from(packet);
                    return Ok(AnswerOrFuture::Answer(answer));
                }
                hooks::Action::Hash => {}
                _ => return Err(DNSError::Unimplemented.into()),
            }
        }
        let (custom_hash, bypass_cache) = {
            let session_state = self.session_state
                .as_ref()
                .expect("session_state is None")
                .inner
                .read();
            (session_state.custom_hash, session_state.bypass_cache)
        };
        if !bypass_cache {
            let cache_key =
                CacheKey::from_parsed_packet(&mut parsed_packet, custom_hash, bypass_cache)?;
            let cache_entry = self.globals.cache.clone().get2(&cache_key);
            match cache_entry {
                None => {}
                Some(cache_entry) => {
                    if !cache_entry.is_expired() {
                        let cached_packet = cache_entry.packet;
                        let answer = Answer::from(cached_packet);
                        return Ok(AnswerOrFuture::Answer(answer));
                    }
                }
            }
        }
        let (response_tx, response_rx) = oneshot::channel();
        let client_query = ClientQuery::udp(
            response_tx,
            &mut parsed_packet,
            self.session_state.take().unwrap(),
        )?;
        let fut_send = self.globals
            .resolver_tx
            .clone()
            .send(client_query)
            .map_err(|_| DNSError::InternalError.into());

        let client_query_fut = response_rx
            .map_err(|e| DNSError::InternalError.into())
            .and_then(move |resolver_response| {
                let answer = Answer::from(resolver_response.packet);
                Ok(answer)
            });

        let client_query_fut = fut_send.and_then(move |_| client_query_fut);
        let fut_timeout = self.timer.timeout(
            client_query_fut,
            time::Duration::from_millis(UPSTREAM_TOTAL_TIMEOUT_MS),
        );

        Ok(AnswerOrFuture::Future(Box::new(fut_timeout)))
    }
}

struct SpecialQueries;

impl SpecialQueries {
    fn handle_special_queries(
        globals: &Globals,
        parsed_packet: &mut ParsedPacket,
    ) -> Option<Answer> {
        let tid = parsed_packet.tid();
        let (qtype, qclass) = parsed_packet.qtype_qclass()?;

        if qclass == dns::DNS_CLASS_IN && qtype == dns::DNS_TYPE_ANY {
            debug!("ANY query");
            let original_qname = match parsed_packet.question_raw() {
                Some((original_qname, ..)) => original_qname,
                None => return None,
            };
            let packet =
                dns::build_any_packet(original_qname, qtype, qclass, tid, globals.config.max_ttl)
                    .unwrap();
            let mut answer = Answer::from(packet);
            answer.special = true;
            return Some(answer);
        }

        if qclass == dns::DNS_CLASS_CH && qtype == dns::DNS_TYPE_TXT {
            debug!("CHAOS TXT");
            let original_qname = match parsed_packet.question_raw() {
                Some((original_qname, ..)) => original_qname,
                None => return None,
            };
            let packet = dns::build_version_packet(
                original_qname,
                qtype,
                qclass,
                tid,
                globals.config.max_ttl,
            ).unwrap();
            let mut answer = Answer::from(packet);
            answer.special = true;
            return Some(answer);
        }

        if qclass != dns::DNS_CLASS_IN {
            debug!("!IN class");
            let original_qname = match parsed_packet.question_raw() {
                Some((original_qname, ..)) => original_qname,
                None => return None,
            };
            let packet = dns::build_refused_packet(original_qname, qtype, qclass, tid).unwrap();
            let mut answer = Answer::from(packet);
            answer.special = true;
            return Some(answer);
        }
        None
    }
}
