extern crate libedgedns;
extern crate nix;
extern crate regex;


#[cfg(test)]
mod test {
    extern crate env_logger;
    use libedgedns::{Config, EdgeDNS};
    use std::thread;
    use std::env;
    use std::process::Command;
    use nix::sys::signal::*;
    use nix::unistd::*;
    use nix::sys::socket::{socketpair, AddressFamily, SockType, SockFlag};
    use regex::Regex;



    #[test]
    fn empty_config_test() {
        let (fdc, fdp) = socketpair(AddressFamily::Unix, SockType::Stream, 0, SockFlag::empty()).expect("socketpair");
        match fork().expect("fork failed") {
            ForkResult::Parent{ child } => {
                let mut s = String::new();
                loop {
                    let mut buf = [0;1];
                    let res = read(fdp, &mut buf);
                    if res.is_err() {
                        break;
                    }
                    let res = res.unwrap();
                    if res > 0 {
                        s.push(buf[0] as char);

                    }
                    if s.contains("UDP listener is ready") && s.contains("TCP listener is ready") {
                        break;
                    }
                }
                let re = Regex::new(r"Created a UDP socket: (\d+)").unwrap();
                for cap in re.captures_iter(&s) {
                    println!("UDP ports: {}", &cap[1]);
                }

                kill(child, SIGKILL).expect("kill failed");
            }
            ForkResult::Child => {
                env::set_var("RUST_LOG", "info");
                dup2(fdc, 2);
                env_logger::init().expect("Failed to init logger");
                let config = Config::from_string(r#"
[upstream]
servers = ["8.8.8.8:53"]
[network]
listen = "127.0.0.1:0"
udp_ports = 1
[global]
threads_udp = 1
threads_tcp = 1
"#);
                assert!(config.is_ok());
                EdgeDNS::new(config.unwrap());
            }
        }

    }
}
