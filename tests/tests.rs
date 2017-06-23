extern crate libedgedns;
extern crate nix;
extern crate regex;


#[cfg(test)]
mod test {
    extern crate env_logger;
    use libedgedns::{Config, EdgeDNS};
    use std::env;
    use std::os::unix::io::RawFd;
    use nix::sys::signal::{kill, SIGKILL};
    use nix::sys::ioctl::libc::pid_t;
    use nix::unistd::*;
    use nix::sys::socket::{socketpair, AddressFamily, SockType, SockFlag};
    use regex::Regex;
    use std::process::{Output, Command, ExitStatus};
    use std::string::String;

    struct EdgeDNSInstance {
        stdout: RawFd,
        pid: pid_t,
        udp_ports: Vec<u16>,
    }
    impl EdgeDNSInstance {
        pub fn done(&self) {
            kill(self.pid, SIGKILL).expect("kill failed")
        }
    }
    fn spawn_edgedns(cfg_str: &str) -> EdgeDNSInstance {
        let mut ret = EdgeDNSInstance {
            pid: 0,
            stdout: 0,
            udp_ports: Vec::new(),
        };
        let (fdc, fdp) = socketpair(AddressFamily::Unix, SockType::Stream, 0, SockFlag::empty())
            .expect("socketpair");
        match fork().expect("fork failed") {
            ForkResult::Parent { child } => {
                ret.pid = child;
                ret.stdout = fdp;
                let mut s = String::new();
                loop {
                    let mut buf = [0; 1];
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
                    ret.udp_ports.push(cap[1].parse::<u16>().unwrap());
                }
            }
            ForkResult::Child => {
                env::set_var("RUST_LOG", "info");
                dup2(fdc, 2).expect("dup2 failed"); /* have env_logger log to the socketpair */
                env_logger::init().expect("Failed to init logger");
                let config = Config::from_string(cfg_str);
                assert!(config.is_ok());
                EdgeDNS::new(config.unwrap());
            }
        }
        ret
    }


    #[test]
    fn empty_config() {
        let cfg = r#"
[upstream]
servers = ["8.8.8.8:53"]
[network]
listen = "127.0.0.1:0"
udp_ports = 1
[global]
threads_udp = 1
threads_tcp = 1
"#;
        let server = spawn_edgedns(&cfg);
        server.done();
    }

    enum Qprotocol {
        UDP,
        TCP,
    }
    struct CmdOutput {
        stdout: String,
        stderr: String,
        status: ExitStatus,
    }
    fn dig(query: &str, proto: Qprotocol, server: &str, port: u16) -> CmdOutput {
        let output = Command::new("dig")
            .arg(query)
            .arg(format!("@{}", server))
            .arg("-p")
            .arg(format!("{}", port))
            .output()
            .unwrap();
        let mut stdout = String::new();
        let mut stderr = String::new();
        match String::from_utf8(output.stdout) {
            Err(_) => (),
            Ok(s) => stdout = s,
        }
        match String::from_utf8(output.stderr) {
            Err(_) => (),
            Ok(s) => stderr = s,
        }
        CmdOutput {
            stdout: stdout,
            stderr: stderr,
            status: output.status,
        }
    }

    #[test]
    fn simple_dig_query() {
        let cfg = r#"
[upstream]
servers = ["8.8.8.8:53"]
[network]
listen = "127.0.0.1:0"
udp_ports = 1
[global]
threads_udp = 1
threads_tcp = 1
"#;
        let server = spawn_edgedns(&cfg);
        let re = Regex::new(r"\n;; ANSWER SECTION:\n127.0.0.1.xip.io.\s+\d+\s+IN\s+A\s+127.0.0.1")
            .unwrap();
        for port in &server.udp_ports {
            assert!(re.is_match(&dig("127.0.0.1.xip.io", Qprotocol::UDP, "127.0.0.1", *port).stdout));
        }
        server.done();
    }
}
