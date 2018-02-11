use failure::Error;
use failure::Fail;
use failure::ResultExt;
use std::io;

#[derive(Debug, Fail)]
pub enum DNSError {
    #[fail(display = "generic error: {}", _0)]
    GenericError(&'static str),
    #[fail(display = "hook error: {}", _0)]
    HookError(&'static str),
    #[fail(display = "inconsistent data")]
    Inconsistent,
    #[fail(display = "internal error")]
    InternalError,
    #[fail(display = "invalid packet")]
    InvalidPacket,
    #[fail(display = "unexpected data")]
    Unexpected,
    #[fail(display = "unimplemented")]
    Unimplemented,
    #[fail(display = "{}", _0)]
    Io(#[cause] io::Error),
    #[fail(display = "no servers available for this query")]
    NoServers,
    #[fail(display = "response to a nonexistent question")]
    SpuriousResponse,
    #[fail(display = "timeout")]
    Timeout,
}
