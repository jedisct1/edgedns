//! A streaming interface to tokio-io UDP sockets.
//!
//! This provides a consistent interface with TCP sockets.

use futures::{Async, Stream, Poll};
use net::SocketAddr;
use std::io;
use std::net;
use std::rc::Rc;
use super::DNS_MAX_UDP_SIZE;
use tokio_core::net::UdpSocket;
use tokio_core::reactor::Handle;

pub struct UdpStream {
    udp_socket: UdpSocket,
    buf: Rc<Vec<u8>>,
}

impl UdpStream {
    pub fn from_socket(udp_socket: UdpSocket) -> Result<Self, io::Error> {
        let buf = Rc::new(vec![0; DNS_MAX_UDP_SIZE]);
        Ok(UdpStream { udp_socket, buf })
    }

    pub fn from_net_udp_socket(net_udp_socket: net::UdpSocket,
                               handle: &Handle)
                               -> Result<Self, io::Error> {
        let udp_socket = UdpSocket::from_socket(net_udp_socket, handle)?;
        Self::from_socket(udp_socket)
    }
}

impl Stream for UdpStream {
    type Item = (Rc<Vec<u8>>, SocketAddr);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let client_ip = {
            let bufw = Rc::get_mut(&mut self.buf).unwrap();
            let capacity = bufw.capacity();
            unsafe { bufw.set_len(capacity) };
            let (count, client_ip) = try_nb!(self.udp_socket.recv_from(bufw));
            unsafe { bufw.set_len(count) };
            client_ip
        };
        let buf = self.buf.clone();
        Ok(Async::Ready(Some((buf, client_ip))))
    }
}
