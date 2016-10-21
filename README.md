![EdgeDNS](https://raw.github.com/jedisct1/edgedns/master/edgedns.png)

A high performance DNS cache designed for Content Delivery Networks, with
built-in security mechanisms to protect origins, clients and itself.

# Installation from source

EdgeDNS is designed to work on rust-nightly.

rust-nightly can be installed using [rustup](https://www.rustup.rs/):
```bash
$ curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain nightly
```

Compile and install `edgedns` with:
```bash
$ cargo install --git https://github.com/jedisct1/edgedns
```

And find the `edgedns` binary in `~/.cargo/bin/edgedns`.

# Operation

EdgeDNS has two modes of operation:
- In "virtual DNS" mode, it acts as an **authoritative** server, and sits
between **authoritative** DNS servers and resolvers. It ensures that only
correct queries are sent to upstream servers, balances the load across multiple
upstreams, reduces the load by caching recent and frequent queries, mitigates
DDoS attacks and does its best to respond to critical queries even when upstream
servers are slow or unresponsive.
- In "resolver" mode, EdgeDNS can act as a simple, non-recursive DNS cache,
sitting between a recursive **resolver** and stub resolvers.

"virtual DNS" is the default mode, but this can be changed with the
`--resolver-mode` command-line switch.

By default, the load is distributed using consistent hashing, ensuring that
the upstream servers get a similar share, but queries for a given zone always
favor the same upstream server.

As an alternative, servers can be tried sequentially, using the `--failover`
switch.

A unique feature of EdgeDNS is that it uses a fixed number of UDP sockets.
Sockets designed to receive responses from upstream servers are all open at
once, and are then kept open forever. Matching responses with queries is
entirely done by the application instead of the kernel.

As a result, the server will not start if the maximum number of UDP ports to
use is larger than the maximum number of file descriptors allowed.

Tweaking `/etc/security/limits.conf` or using `ulimit -n` might thus be
required prior to starting the server.

By default, only `8` UDP ports are open. This is acceptable for a local cache
("resolver mode") sending queries to a local resolver on a trusted network.
In all other scenarios, raising this number as much as possible (up to `64511`)
using the `--ports-count` command-line option is highly recommended.

Live statistics are exposed as a JSON object on `http://0.0.0.0:8888/varz`.
Please note that the current schema might eventually be revisited to better
match the [Prometheus](https://prometheus.io/) expectations.
