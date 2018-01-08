use super::{DNS_UDP_NOEDNS0_MAX_SIZE, DNS_MAX_TCP_SIZE, DNS_MAX_UDP_SIZE, DNS_RESPONSE_MIN_SIZE};
use byteorder::{BigEndian, ByteOrder};
use cache::*;
use client_query::ClientQueryProtocol;
use dns;
use dns::*;
use dnssector::*;
use errors::*;
use failure;
use futures::{future, Future};
use globals::*;
use hooks;
use hooks::*;
use std::ptr;
use std::rc::Rc;

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
    Future(Box<Future<Item = (), Error = failure::Error>>),
}

pub enum AnswerOrFuture {
    Answer(Answer),
    Future(Box<Future<Item = (), Error = failure::Error>>),
}

pub struct QueryRouter {
    globals: Rc<Globals>,
}

impl QueryRouter {
    fn rewrite_according_to_original_query(
        &self,
        parsed_packet: &mut ParsedPacket,
        answer: Answer,
        protocol: ClientQueryProtocol,
    ) -> Result<Vec<u8>, failure::Error> {
        if !answer.special && !parsed_packet.is_response() {
            xbail!(DNSError::Unexpected);
        }
        let mut packet = answer.packet;
        match answer.ttl {
            Some(ttl) => dns::set_ttl(&mut packet, ttl).map_err(|_| DNSError::InternalError)?,
            None => {}
        };

        {
            let original_qname = match parsed_packet.question_raw() {
                Some((original_qname, ..)) => original_qname,
                None => xbail!(DNSError::Unexpected),
            };
            dns::overwrite_qname(&mut packet, original_qname)?;
        }

        let packet_len = packet.len();
        if packet.len() < DNS_RESPONSE_MIN_SIZE
            || (protocol == ClientQueryProtocol::UDP && packet_len > DNS_MAX_UDP_SIZE)
            || (protocol == ClientQueryProtocol::TCP && packet_len > DNS_MAX_TCP_SIZE)
        {
            let normalized_question = match NormalizedQuestion::from_parsed_packet(parsed_packet) {
                Ok(normalized_question) => normalized_question,
                Err(_) => xbail!(DNSError::InvalidPacket),
            };
            packet = dns::build_refused_packet(&normalized_question)?;
        }

        match protocol {
            ClientQueryProtocol::UDP
                if packet_len > DNS_UDP_NOEDNS0_MAX_SIZE as usize
                    && (packet_len > DNS_MAX_UDP_SIZE as usize
                        || packet_len > parsed_packet.max_payload()) =>
            {
                let normalized_question =
                    match NormalizedQuestion::from_parsed_packet(parsed_packet) {
                        Ok(normalized_question) => normalized_question,
                        Err(_) => xbail!(DNSError::InvalidPacket),
                    };
                packet = dns::build_tc_packet(&normalized_question)?;
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
        return Ok(packet);
    }

    pub fn create(
        globals: Rc<Globals>,
        mut parsed_packet: ParsedPacket,
        protocol: ClientQueryProtocol,
    ) -> PacketOrFuture {
        let mut query_router = QueryRouter { globals };
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
            Ok(AnswerOrFuture::Future(future)) => PacketOrFuture::Future(future),
            Err(e) => return PacketOrFuture::Future(Box::new(future::err(e))),
        }
    }

    fn create_answer(
        &mut self,
        mut parsed_packet: &mut ParsedPacket,
    ) -> Result<AnswerOrFuture, failure::Error> {
        match SpecialQueries::handle_special_queries(&self.globals, &mut parsed_packet) {
            Some(answer) => return Ok(AnswerOrFuture::Answer(answer)),
            None => {}
        };
        let mut session_state = SessionState::default();
        let hooks_arc = self.globals.hooks_arc.read();
        if hooks_arc.enabled(Stage::Recv) {
            let action = hooks_arc
                .apply_clientside(&mut session_state, parsed_packet, Stage::Recv)
                .map_err(|e| DNSError::HookError(e))?;
            if action != hooks::Action::Pass {
                return Err(DNSError::Unimplemented.into());
            }
        }

        let cache_key = CacheKey::from_parsed_packet(&mut parsed_packet)?;
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

        let packet = Vec::new();
        let answer = Answer::from(packet);
        Ok(AnswerOrFuture::Answer(answer))
    }
}

struct SpecialQueries;

impl SpecialQueries {
    fn handle_special_queries(
        globals: &Globals,
        parsed_packet: &mut ParsedPacket,
    ) -> Option<Answer> {
        let (qtype, qclass) = parsed_packet.qtype_qclass()?;

        if qclass == dns::DNS_CLASS_IN && qtype == dns::DNS_TYPE_ANY {
            debug!("ANY query");
            let normalized_question = match NormalizedQuestion::from_parsed_packet(parsed_packet) {
                Ok(normalized_question) => normalized_question,
                Err(_) => return None,
            };
            let packet =
                dns::build_any_packet(&normalized_question, globals.config.max_ttl).unwrap();
            let mut answer = Answer::from(packet);
            answer.special = true;
            return Some(answer);
        }

        if qclass == dns::DNS_CLASS_CH && qtype == dns::DNS_TYPE_TXT {
            debug!("CHAOS TXT");
            let normalized_question = match NormalizedQuestion::from_parsed_packet(parsed_packet) {
                Ok(normalized_question) => normalized_question,
                Err(_) => return None,
            };
            let packet =
                dns::build_version_packet(&normalized_question, globals.config.max_ttl).unwrap();
            let mut answer = Answer::from(packet);
            answer.special = true;
            return Some(answer);
        }

        if qclass != dns::DNS_CLASS_IN {
            debug!("!IN class");
            let normalized_question = match NormalizedQuestion::from_parsed_packet(parsed_packet) {
                Ok(normalized_question) => normalized_question,
                Err(_) => return None,
            };
            let packet = dns::build_refused_packet(&normalized_question).unwrap();
            let mut answer = Answer::from(packet);
            answer.special = true;
            return Some(answer);
        }
        None
    }
}
