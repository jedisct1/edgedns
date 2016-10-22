![EdgeDNS](https://raw.github.com/jedisct1/edgedns/master/edgedns.png)

A high performance DNS cache designed for Content Delivery Networks, with
built-in security mechanisms to protect origins, clients and itself.

# Installation from source

EdgeDNS is designed to work on rust-nightly.

rust-nightly can be installed using [rustup](https://www.rustup.rs/):
```sh
curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain nightly
```

Compile and install `edgedns` with:
```sh
cargo install --git https://github.com/jedisct1/edgedns
```

And find the `edgedns` binary in `~/.cargo/bin/edgedns`.

# Quickstart

### As a cache for authoritative servers ("virtual DNS" mode)

```
edgedns --cachesize=250000 --ports-count=64000 \
        --upstream=192.168.1.1:53 --listen=0.0.0.0:53
```

Act as a "secondary DNS server" for the zones served by one or more
"primary DNS servers". The external IP address `edgedns` is listening
to can be configured as a public authoritative server for the zone.

This will reduce the load on the "primary server", mitigate common
attacks, and ensure a continuity of service even if the primary server
has temporary outages.

Binding as many ports as possible (`--ports-count`) is recommended in
this mode of operation. This may require some adjustments to your
system configuration. See below.

### As a local DNS cache

```sh
edgedns --resolver-mode --cachesize=250000 \
        --upstream=8.8.8.8:53,8.8.4.4:53 --listen=127.0.0.1:53
```

And use `127.0.0.1` as a resolver. EdgeDNS will cache responses,
balance the load across the resolvers set, and improve your experience
by making DNS more reliable.

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

This software is still a work in progress. More features are planned,
with a focus on automatic DDoS mitigation.

# Features

### Reliable

EdgeDNS is written in Rust, which by design prevents common security
and reliability issues while remaining extremely fast.

EdgeDNS can thus be used as a protection layer for DNS resolvers and
authoritative servers.

EdgeDNS has been running flawlessly on the public
[dnscrypt.org-fr](https://fr.dnscrypt.org/) server since January 2016.

### DNSSEC support

EdgeDNS is fully compatible with DNSSEC.

### Low memory usage

In virtual DNS mode, responses are cached independently instead of
performing zone transfers, in order to favor caching of hot records.

With a large number of zones, and an uneven distribution of queries
across records, this leads to a very low memory usage compared to
secondary servers keeping entire zones.

### EDNS0 support

EdgeDNS fully supports EDNS0 both to respond to clients, and to
communicate with upstream servers. This minimizes the number of
queries requiring TCP and reduces latency.

### Minimal truncated responses

Responses that don't fit within the maximum payload size supported by
a client get a truncated response, whose content cannot be used by a
resolver or stub resolver.

Instead of forwarding truncated responses sent by authoritative
servers, EdgeDNS directly synthesizes the shortest possible responses.

### Correct support for the dns0x20 extension

In order to improve resistance against forgery, some clients support
the dns0x20 extension, which randomizes casing in DNS names. This
shouldn't lead to distinct cache entries. The cache normalize names,
but respect the form initially sent by clients in its responses.

### Coalescing of identical queries

Multiple clients can be simultaneously waiting for the same cache
entry to be filled.

Similar in-flight queries are coalesced, and the first received
response is dispatched among all waiting clients.

### Latency guarantee

Slow authoritative servers can have a huge impact on clients, even if
this is a temporary situation.

EdgeDNS does its best to guarantee a maximum latency. If a response
that needs to be refreshed doesn't get a response within a given time
frame, EdgeDNS can directly respond with cached records in order to
avoid breaking the latency guarantee.

### Short responses to ANY queries

ANY queries are commonly used to conduct DDoS attacks.

The ANY query type has been deprecated for a while, but not answering
queries with the ANY type breaks legacy software, namely Qmail.

Cloudflare handles ANY queries by synthesizing responses with HINFO
records. EdgeDNS implements this proposal as well. It doesn't violate
the protocol, doesn't break Qmail and mitigate abuses, while not
requiring any interactions with authoritative servers.

### Query validation

Only valid queries should be sent to authoritative servers. This
mitigates common attacks exploiting vulnerabilities in resolvers
and authoritative servers.

### Negative caching

The absence of data is cached. Temporary errors such as `SERVFAIL`
responses are also cached for a short period of time, in order to
avoid hammering upstream servers.

### Automatic failover

Outages of upstream servers are quickly detected, and background
probes are sent to bring them back to the pool as soon as they get
operational again.

### Consistent hashing

In order to improve cache locality, the same questions should preferably
be always sent to the same upstream servers.

Consistent hashing limits the amount of reshuffling after servers are
being flagged as down or back up, and is a strategy the proxy can use
in order to distribute queries amount authoritative servers.

As an alternative, EdgeDNS can send data to a primary upstream
servers, and fall back to a list of backup servers in case of an outage.

### Resilience against temporary outages of authoritive servers

If authoritative servers cannot be reached for a given zone, and a
previous version of the response is available, EdgeDNS serves that
version instead of returning a server failure.

If authoritative responses are received, but with a significant delay,
EdgeDNS responds with a previous version of the response, and updates
its cache as soon as the update is effectively being received.

### Resilience against cache pollution

An attacker could fill the cache with entries of little relevance, or
invalid entries, in order to reduce the cache efficiency, or partly
disrupt the service.

In order to protect against cache pollution, EdgeDNS uses the
CLOCK-Pro algorithm. This algorithm separately tracks recently used
and frequently used entries.

A significant amount of new entries does not have a perceptible
impact on frequently asked DNS questions.

### Response rate limiting

If the global RTT becomes too high, either the infrastructure is
suffering a major incident, or the authoritative servers are under
attack.

In this situation, EdgeDNS tries answering legitimate questions, and
block malicious traffic, which is likely to be coming from spoofed
source IP addresses.

In order to do so, it responds to uncached records with truncated
responses, forcing a retries using TCP.

### TCP slots reuse

The number of simultaneous connections coming from the same client IP
address is capped, and dynamically adjusted according to the total
number of free slots.

After the cap is reached, new connections recycle older connections
from the same client IP. A single client opening many TCP connections
doesn't affect the general service availablity.

