extern crate libedgedns;
extern crate nix;
extern crate regex;
extern crate tempfile;

#[cfg(test)]
mod test {
    extern crate env_logger;
    use libedgedns::{Config, EdgeDNS};

    use nix::sys::signal::{kill, SIGKILL};
    use nix::sys::ioctl::libc::pid_t;
    use nix::unistd::{fork, read, ForkResult, dup2};
    use nix::sys::ioctl::libc::alarm;
    use nix::sys::socket::{socketpair, AddressFamily, SockType, SockFlag};

    use regex::Regex;

    use std::env;
    use std::io::Write;
    use std::process::{exit, Output, Command, ExitStatus};
    use std::os::unix::io::RawFd;
    use std::os::unix::process::CommandExt;
    use std::string::String;
    use std::time::Duration;

    use tempfile::NamedTempFile;

    struct EdgeDNSInstance {
        server: Server,
        udp_ports: Vec<u16>,
        tcp_ports: Vec<u16>,
    }

    struct Server {
        pid: pid_t,
        startup_text: String,
        output: RawFd,
    }
    impl Server {
            pub fn new() -> Server {
                Server{pid: 0, startup_text: String::from(""), output: 0}
            }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            if self.pid != 0 {
                kill(self.pid, SIGKILL).expect("kill failed")
            }
        }
    }

    fn spawn_server<F1, F2>(child_fn: F1, mut is_ready: F2, timeout: Duration) -> Server
        where F1: Fn() -> (),
              F2: FnMut(&str, pid_t) -> bool
    {

        let mut server = Server {
            pid: 0,
            output: 0,
            startup_text: String::new(),
        };
        let (fdc, fdp) = socketpair(AddressFamily::Unix, SockType::Stream, 0, SockFlag::empty())
            .expect("socketpair");
        match fork().expect("fork failed") {
            ForkResult::Parent { child } => {
                server.pid = child;
                server.output = fdp;

                /* FIXME: a non-unsafe way to do this */
                unsafe {
                    alarm(timeout.as_secs() as u32);
                }
                loop {
                    let mut buf = [0; 1];
                    let res = read(fdp, &mut buf);
                    if res.is_err() {
                        break;
                    }
                    let res = res.unwrap();
                    if res > 0 {
                        server.startup_text.push(buf[0] as char);
                    }
                    if is_ready(&server.startup_text, child) {
                        break;
                    }
                }
                unsafe {
                    alarm(0);
                }
            }
            ForkResult::Child => {
                dup2(fdc, 1).expect("dup2 failed");
                dup2(fdc, 2).expect("dup2 failed");
                child_fn();
                println!("The child exited");
                exit(0);
            }
        }
        server
    }

    fn spawn_edgedns(cfg_str: &str) -> EdgeDNSInstance {
        let mut ret = EdgeDNSInstance {
            udp_ports: Vec::new(),
            tcp_ports: Vec::new(),
            server: spawn_server(|| {
                                     env::set_var("RUST_LOG", "info");
                                     env_logger::init().expect("Failed to init logger");
                                     let config = Config::from_string(cfg_str);
                                     assert!(config.is_ok());
                                     EdgeDNS::new(config.unwrap());
                                 },
                                 |out, _| {
                                     out.contains("UDP listener is ready") &&
                                     out.contains("TCP listener is ready")
                                 },
                                 Duration::new(5, 0)),
        };

        for proto in ["TCP", "UDP"].iter() {
            let re = Regex::new(&format!(r"Created a {} socket: (\d+)", proto)).unwrap();
            for cap in re.captures_iter(&ret.server.startup_text) {
                let port = cap[1].parse::<u16>().unwrap();
                if *proto == "UDP" {
                    ret.udp_ports.push(port);
                } else {
                    ret.tcp_ports.push(port);
                }
            }
        }

        ret
    }

    struct CoreDNS {
        server: Server,
        udp_port: u16,
    }

    fn spawn_coredns(domain: &str, zone_str: &str) -> CoreDNS {
        let mut conf_file = NamedTempFile::new().unwrap();
        let mut zone_file = NamedTempFile::new().unwrap();
        zone_file.write_all(zone_str.as_bytes());
        let zfile_path = zone_file.path().to_str().unwrap();
        let conf_str = format!(r#"
{}:0 {{
    file {}
    errors stdout
    log stdout
}}
"#, domain, zfile_path);
        conf_file.write_all(conf_str.as_bytes());
        let cfile_path = conf_file.path().to_str().unwrap();
        let mut ret = CoreDNS {
            udp_port : 0,
            server: Server::new(),
        };
        ret.server = spawn_server(|| {
                let cmd = Command::new("coredns")
                    .args(&["-log", "-dns.port", "0", "-conf", cfile_path])
                    .exec();
                ::std::process::exit(1);
            },
            |out, pid| {
                if !out.contains("CoreDNS-008") {
                    return false;
                }
                let lsof = Command::new("lsof")
                    .arg("-p")
                    .arg(&format!("{}", pid))
                    .output();
                let lsof = String::from_utf8(lsof.unwrap().stdout).unwrap();

                let re = Regex::new(r"0t0\s+UDP \*:(\d+)").unwrap();
                let mut udp_port: u16 = 0;
                for cap in re.captures_iter(&lsof) {
                    udp_port = cap[1].parse::<u16>().unwrap();
                }
                ret.udp_port = udp_port;
                true
            },
            Duration::new(5, 0));
        ret
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
        let server = format!("@{}", server);
        let port = format!("{}", port);
        let mut args = vec![query, &server, "-p", &port];
        match proto {
            Qprotocol::TCP => args.push("+tcp"),
            _ => (),
        }
        let output = Command::new("dig").args(args).output().unwrap();
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

    /* tests */
    #[test]
    fn coredns_test() {
        let coredns = spawn_coredns("example.com", r#"
$ORIGIN example.com.     ; designates the start of this zone file in the namespace
$TTL 1h                  ; default expiration time of all resource records without their own TTL value
example.com.  IN  SOA   ns.example.com. username.example.com. ( 2007120710 1d 2h 4w 1h )
example.com.  IN  NS    ns                    ; ns.example.com is a nameserver for example.com
example.com.  IN  NS    ns.somewhere.example. ; ns.somewhere.example is a backup nameserver for example.com
example.com.  IN  MX    10 mail.example.com.  ; mail.example.com is the mailserver for example.com
@             IN  MX    20 mail2.example.com. ; equivalent to above line, "@" represents zone origin
@             IN  MX    50 mail3              ; equivalent to above line, but using a relative host name
example.com.  IN  A     192.0.2.1             ; IPv4 address for example.com
IN  AAAA  2001:db8:10::1        ; IPv6 address for example.com
ns            IN  A     192.0.2.2             ; IPv4 address for ns.example.com
IN  AAAA  2001:db8:10::2        ; IPv6 address for ns.example.com
www           IN  CNAME example.com.          ; www.example.com is an alias for example.com
wwwtest       IN  CNAME www                   ; wwwtest.example.com is another alias for www.example.com
mail          IN  A     192.0.2.3             ; IPv4 address for mail.example.com
mail2         IN  A     192.0.2.4             ; IPv4 address for mail2.example.com
mail3         IN  A     192.0.2.5             ; IPv4 address for mail3.example.com
"#);
        let cfg = format!(r#"
[upstream]
servers = ["127.0.0.1:{}"]
[network]
listen = "127.0.0.1:0"
udp_ports = 1
[global]
threads_udp = 1
threads_tcp = 1
"#, coredns.udp_port);
        let server = spawn_edgedns(&cfg);
        let re = Regex::new(r"\n;; ANSWER SECTION:\nmail.example.com.\s+\d+\s+IN\s+A\s+192.0.2.3").unwrap();
        for port in &server.udp_ports {
            let output = dig("mail.example.com", Qprotocol::UDP, "127.0.0.1", *port).stdout;
            assert!(re.is_match(&output));
        }
        for port in &server.tcp_ports {
            let output = dig("127.0.0.1.xip.io", Qprotocol::TCP, "127.0.0.1", *port).stdout;
            println!("{}", output);
            assert!(re.is_match(&output));
        }
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
            let output = dig("127.0.0.1.xip.io", Qprotocol::UDP, "127.0.0.1", *port).stdout;
            assert!(re.is_match(&output));
        }
        for port in &server.tcp_ports {
            let output = dig("127.0.0.1.xip.io", Qprotocol::TCP, "127.0.0.1", *port).stdout;
            assert!(re.is_match(&output));
        }
    }
}
