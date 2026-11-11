# Configuration

This file describes the whole language, including what is designed but
not built yet. A directive that is not built is refused by `okena check`
("not supported by this version of okena yet"), never ignored.

## Built today

| Block | Directives |
|---|---|
| `okena` | `workers`, `io_engine`, `busy_poll`, `watchdog`, `drain delay= timeout=`, `metrics [token=]`, `user`, `ticket_keys`, `handshake_budget wait=`, `quic_server_id HEX`, `cache_memory`, `cache_disk PATH size=`, `fleet ADDR...`, `cdn_loop NAME [max=]`, `bird PATH protocol= [pool=]` |
| `vrrp IFACE` | `vrid=`, `priority=`, `address=A/N`, `advert=`, `preempt=`, `track=POOL` (a floating address, VRRP v3) |
| `tcp ADDR...` | `to`, `limits { connections; per_source }`, `timeout { idle }`, `proxy_protocol send v1\|v2`, `tls { cert; key }`, `tls passthrough { sni NAME... to pool P; default reject\|to pool P }` (a `default to pool` alone is enough) |
| `udp ADDR...` | `to`, `responses N`, `limits { connections }` (flows), `timeout { idle }` |
| `http ADDR...` | `host`, `route`, `errors CODES file= [backend]`, `maintenance file= retry= allow= except=`, `limits`, `timeout { idle; header; body_idle; response }`, `trusted_proxies`, `access_log`, `tracing`, `http2 on\|off`, `http3 on\|off\|retry\|v2`, `preferred_address`, `early_data on\|off`, `tls { cert; key; ktls on\|off }` |
| `route PATH... [METHOD...]` | `to`, `redirect`, `respond`, `rewrite path`, `signed_urls key= [key2=]`, `header set\|add\|drop`, `response header set\|add\|drop` |
| `pool NAME` | `server ADDR [weight=N] [max=N] [backup]`, `queue timeout=`, `balance least-request\|peak-ewma\|round-robin\|least-conn\|random\|maglev\|ring-hash\|source-hash [key=] [bound=]\|first`, `sticky cookie= [ttl=] [samesite=]`, `connect timeout=`, `health tcp\|http\|grpc ...`, `slow_start`, `tls { trust FILE; sni NAME; cert FILE; key FILE }` (TLS to the backends), `protocol h1\|h2\|fastcgi` |

Certificate compression (RFC 8879) needs nothing configured: a TLS 1.3 client
that offers it with brotli (Chrome) or zlib (Firefox, Safari, OpenSSL) gets the
chain compressed, brotli first; about a third smaller for a leaf and its
intermediate, compressed once per worker for each chain (and staple), not for
each handshake.

`tls { cert FILE; key FILE }` on an `http` listener makes it HTTPS: TLS
1.3 with a certificate chain (leaf first) and its key: EC P-256 (SEC 1 or
PKCS #8), RSA (PKCS #1 or #8) or Ed25519 (PKCS #8; served to clients that
offer ed25519, which browsers do not: pair it with an EC certificate). With
several certificates each line names its key, `cert FILE key=FILE`; the
client's SNI picks the one whose subjectAltName names the host (exactly,
then `*.parent`), the first being the default. A request whose `Host`
the chosen certificate does not name gets 421 (domain fronting). ALPN
http/1.1, then the records are sealed and opened by okena itself, which
for request and response traffic costs less than the kernel's TLS (1.5%
under plaintext against 20%, docs/BENCHMARK.md). `ktls on` in the block
hands the connection to the kernel (kTLS) instead, when the host has the
`tls` module (`modprobe tls`; without it okena seals the records and says
so once at the start; `OKENA_KTLS=off` forces that). A `tcp` listener's
TLS always runs on kTLS, its bytes going through the kernel; `ktls off`
there is refused. Session tickets are on: a returning client resumes
without the certificate and the signature. The ticket key rotates every
hour and the previous one is still accepted, so a ticket lasts one to two
hours; keys live in memory only (a restart starts afresh). For a fleet,
A client that offers no TLS 1.3 gets TLS 1.2 (RFC 5246), on kTLS when the host
has it, else its records sealed and opened by okena as 1.3's are: ECDHE with
the certificate's key, ECDSA or RSA, and AES-128-GCM or ChaCha20-Poly1305
(the first of those in the client's order); x25519, else secp256r1 (an ECDSA
certificate, being on secp256r1, needs that one offered); rsa_pss_rsae_sha256,
else rsa_pkcs1_sha256, for an RSA key; the extended master secret (RFC 7627)
whenever the client offers it; secure renegotiation said, and no
renegotiation; session tickets (RFC 5077) under the same keys as 1.3's (their
rotation, `ticket_keys` for a fleet), a resumed session being an abbreviated
handshake with no signature, taken only for its certificate, its suite and
the same extended master secret. A name with an ECDSA and an RSA certificate gives the RSA one
to a client whose suites take only it. Nothing in common: a handshake_failure
alert. No CBC suites, no RSA key exchange, no SHA-1 signatures.

A TLS connection okena closes once an answer is done (`Connection: close`,
HTTP/1.0, an error) ends with a close_notify alert, 1.2 or 1.3, records sealed
here or on kTLS: a client can tell the end from a cut, and a TLS 1.2 client
keeps its session for a resumption.

`http2 on` in an `http` listener speaks HTTP/2 to clients that ask for it:
ALPN h2 on a TLS listener (preferred over http/1.1 when the client offers
both), prior knowledge (the connection preface) on a plain one. Each
stream is proxied like an HTTP/1.1 request (routes, pools, retries,
rewrites, logs all apply; backends still get HTTP/1.1): up to 100 streams
a connection, flow control both ways, malformed requests reset, and a
client resetting more than 200 streams a second gets GOAWAY
ENHANCE_YOUR_CALM. Off by default.

`http3 on` adds HTTP/3 on the same port over UDP: QUIC v1 and v2, the
listener's `tls { }` certificate (it is required), one UDP socket a
worker. Requests are proxied like HTTP/2 streams (backends get
HTTP/1.1); HTTP/1.1 and HTTP/2 answers on that listener announce it
(`Alt-Svc: h3=":PORT"; ma=86400`), which a client only sees after a first
request over TCP. To be found before that, publish an HTTPS record (RFC 9460)
in your DNS, okena has no part in it:

```
example.com. 3600 IN HTTPS 1 . alpn="h3,h2"
```

with `port=N` when it is not 443. A worker holding 64 connections whose
address is not validated yet answers new ones with a Retry first (a
token sealed with a key the workers share, good for 10 s); `http3 retry`
does so for every new connection. On a drain each connection gets
GOAWAY, finishes the requests it has, then closes (H3_NO_ERROR). 0-RTT
is not accepted unless `early_data on`: then a resumed client may send
requests in its first flight (RFC 9001 4.6), which can be replayed, so
only GET, HEAD and OPTIONS go on (with `Early-Data: 1` to the backend, RFC
8470) and anything else is refused with REQUEST_REJECTED, for the client to
send again after the handshake. A connection stays in the QUIC version its client chose;
On a route, `priority critical|normal|bulk` says what goes first when a worker
is pressed, by how full a listener's `limits { connections }` are or how late
its loop runs. Level 1, at 80% or 50 ms: idle connections go sooner. Level 2, 85%
or 100 ms: responses say `Connection: close`. Level 3, 90% or 250 ms: `bulk`
routes answer 503 with `Retry-After: 1`. Level 4, 97% or 1 s: so do `normal`
ones, which is the default, and only `critical` goes on. Each worker decides for
itself, once a second; the level rises at once and falls one step at a time, after 3
quiet seconds and 5 points below where it rose. Changes are logged.

On a route, `hedge after=50ms` (or `after=p95`) cuts the tail of a pool: a GET,
HEAD or other idempotent request with no body that has no answer by then is sent
again to another server, and the first answer goes to the client while the other
is cancelled. `after=pNN` is that percentile of the pool's recent answers in each
worker, and hedges nothing until 64 have been seen. An answer of 500 or more
does not win. Hedges spend the pool's retry budget, so a backend in trouble does
not get twice the load: past the budget a request just waits for its server. A
pool of one server has nothing to hedge to. `max=` can only be 1.

On a route, `mirror pool NAME N%` sends a copy of that share of its requests
(all without `N%`) to another pool and throws away what it answers. The client
never waits for it: a shadow slow, down or failing is not noticed. A body is
copied as it is read; if the shadow falls about 64 KiB behind, that copy is
dropped, the backend seeing it cut short. At most 256 copies run at once in a
worker: past that, requests are not copied. Copies are not in the access log or
the metrics. Rewrites and header changes of the route apply to them. Do not
mirror requests a backend cannot take twice to anything that acts on them.

On a route, `split api=95% canary=5% sticky=cookie:NAME` shares the traffic
between pools, in place of `to`: 2 to 8 of them, adding up to 100%. Without
`sticky=` each request is drawn. With `sticky=cookie:NAME` a new client is given
a number from 0 to 99 in that cookie, and the number picks the pool: raising a
canary from 5% to 10% leaves those in it where they are and moves only the next
5%. `sticky=header:NAME` hashes the value. A client can choose its pool with the
cookie: this is for releases, not for security.

On a route, `cors origins=LIST methods=LIST headers=LIST expose=LIST
max_age=TIME credentials` answers browsers. `origins=` is needed: whole origins
(`https://app.example.com,https://b.test:8443`), matched exactly, one of them
may have a `*` for the host's labels (`https://*.example.com`), or `*` alone for
any, which cannot go with `credentials`. Preflights (OPTIONS with Origin and
Access-Control-Request-Method) are answered with 204 by okena: the backend is
not asked and no `limit` is spent, so the route must accept OPTIONS. `methods=`
defaults to GET, HEAD, POST; without `headers=` a preflight is told yes to what
it asks. The headers go on every answer of the route, a 429 and okena's own
errors too, and the backend's `Access-Control-*` are dropped. Without `*` answers
say `Vary: Origin`, so that a cache does not serve one origin another's.

On a route, `limit RATE burst=N key=K instances=N` refuses what goes past a
rate: `100/s`, `3000/m` or `10000/h`, for the whole instance and never per
worker. `burst=`, how many may come at once, is a second of the rate by
default. `key=` gives each value its own limit: `client.ip`, `method`,
`header:NAME`, `query:NAME` or `cookie:NAME`; without it the route has one. A
request without that field counts as one key of its own, so leaving it out is
no way around. `instances=4` takes a quarter of the rate, for a fleet of 4. A
route may have several; each must let the request through. What is refused gets
429 with `Retry-After`, on a connection that stays open, and the backend is not
asked. The table holds about 256k keys and lives across reloads; when it is
full, keys in use stay, idle ones are pushed out, and new keys share the
limit's own bucket.

On a route, `fault abort=STATUS delay=TIME percent=N` takes that share of its
requests (all without `percent`): to see how clients take failure and slowness.
`abort=` answers a status from 400 to 599 and never asks the backend; it closes
the connection, as okena's own errors do. `delay=`, up to 10 minutes, holds the
request first, and without `abort=` it then goes on as usual. Up to 1024
requests a worker are held; past that they are not delayed. A client that goes
while held is only noticed afterwards. A reload takes effect for new requests.

`okena { quic_cc bbr }` sets the congestion control of new QUIC connections (default `cubic`; measured with `bbr`: 3 MB at 30 ms RTT in 1.48 s against 6.07 s at 1% loss, 1.06 s against 0.87 s with none).

`http3 v2` moves a v1 client that offers v2 to it (RFC 9368). `okena { quic_server_id HEX key=HEX rotation=N }`: with `key=` (16 bytes) the IDs are encrypted, QUIC-LB's four-pass cipher (draft-ietf-quic-load-balancers 5.4.2) with `rotation=` (0 to 6) in their first three bits; the other five bits stay in the clear for the kernel's steering, random but for their value modulo the workers, so the worker is visible to anyone and at most 32 workers take QUIC. A malformed value stops the configuration. Adding or removing a key, or the ID itself, takes a restart: steering is built when the sockets open. `okena { quic_server_id HEX }` (1 or 2 bytes) puts this instance's ID in
its QUIC connection IDs, QUIC-LB's plaintext format (a first octet, the
server ID, the worker, at least 4 random bytes), so a load balancer in front
of a fleet can route by connection ID. `preferred_address
ADDR:PORT [ADDR:PORT]` (an IPv4 and an IPv6 address) offers clients
somewhere to move to after the handshake (RFC 9000 9.6): okena listens
there too and the connection follows the client. A client
that offers only ALPN hq-interop (the QUIC
interop runner's HTTP/0.9: `GET /path`, the body back alone) gets it,
proxied as a GET. Off by default.

`protocol h2` in a pool speaks HTTP/2 to its backends: prior knowledge,
or ALPN h2 under the pool's `tls { }`. Requests share a few connections a
server (at most 4, each carrying as many streams as the server allows),
whatever protocol the client spoke; a backend's trailers (gRPC's status)
reach HTTP/2 clients as trailers and HTTP/1.1 clients after the last
chunk. A stream the backend resets, or a connection that goes, is a 502
(or another try, as for any failed request). When okena itself cannot serve a gRPC
request (content-type application/grpc), it answers as gRPC: status 200
with grpc-status (14 UNAVAILABLE for 502 and 503, 4 DEADLINE_EXCEEDED
for 504 and 408, ...) and grpc-message; the access log keeps the HTTP
status.

gRPC-Web, for browsers, needs nothing configured: a request with content-type
`application/grpc-web` or `application/grpc-web+proto` (`+json` alike) to a pool
with `protocol h2` reaches it as gRPC (`application/grpc...`, `te: trailers`),
and its answer comes back as gRPC-Web (`application/grpc-web...`), the backend's
trailers (`grpc-status`, `grpc-message`) as the last message, a trailer frame,
over HTTP/1.1, 2 and 3 alike; an error with no body keeps `grpc-status` in its
head. The text mode (`application/grpc-web-text`, what a browser's grpc-web
library sends by default) is the same in base64: the request's body is decoded on
its way to the backend (padding after each message taken), the answer's encoded
as it comes, the trailer frame in it, padded only at its end. A body that is not
base64 resets the backend's stream (CANCEL) and the client gets UNAVAILABLE, in
its own content-type (okena's gRPC errors to a gRPC-Web client are gRPC-Web). A
gRPC backend's answer with a Content-Length is passed on chunked, so that its
trailers keep a place. A pool of HTTP/1.1
(a backend that speaks gRPC-Web itself) gets the request as it is. A page on
another origin needs the route's `cors` (with `x-grpc-web`, `x-user-agent` and
`grpc-timeout` allowed, and `grpc-status`, `grpc-message` exposed).

`okena { ticket_keys FILE }` takes the keys from a file every instance
reads: one a line, 32 bytes of base64 (`openssl rand -base64 32`), the
first sealing new tickets, an optional second (the previous) still
opening them. okena looks at the file once a second and takes what changed,
with no reload: a fleet rotates by writing a new first line, the old one
second, to every instance (a file written whole and renamed over the old one
is never read half done). A file that cannot be read or does not hold keys
leaves the keys in use, and is said once; okena does not rotate them itself. The header timeout covers
the handshake. Backends get `X-Forwarded-Proto: https`. On a `tcp`
listener `tls` terminates TLS and moves plaintext to the backend; there
it needs kTLS (okena refuses to start without the module), and the
handshake has the default header timeout (10 s). `tls passthrough` on a
`tcp` listener does not decrypt: okena reads the ClientHello's
server_name, picks the pool from the `sni` lines (exact names, `*.parent`
wildcards), else `default` (`reject` when absent), and moves the bytes
untouched, the ClientHello first (after a PROXY header when configured).

Everything else below (the rest of TLS, policies, auth, limits on requests,
caching, files, addons, discovery and most tooling) is the
design the code is heading for.

One file, `okena.conf`, read top to bottom. The smallest useful config is
two lines; everything else has a default chosen for safety and speed, and
`okena explain` prints the effective config with every default filled in.

## Principles

* **Say what, not how.** You declare listeners, routes and pools; okena
  picks the engine (XDP, sockmap, splice, HTTP) that does it cheapest.
* **One layer, one place.** Every setting lives in the block of the
  network layer it acts on (see Layers).
* **One way to write each thing.** No synonyms, no deprecated spellings.
* **Units in the values:** `250ms`, `30s`, `5m`; `16KiB`, `4MiB`; `100/s`,
  `5000/m`; `20%`.
* **Errors point at the line.** `okena check` reports `file:line:col`, what
  was expected, and a suggestion (`unknown directive "timout", did you mean
  "timeout"?`). Unknown keys are errors, never ignored.
* **Reload is safe.** A config that does not validate never replaces the
  running one. `okena check --diff` shows what a reload would change.

## Syntax

```
directive arg arg key=value {
    nested directive
}
```

* One directive per line; `#` starts a comment.
* Strings need quotes only when they contain spaces, `{`, `}` or `;`
  (`#` and `=` are ordinary inside a word, and so is the placeholder
  `{*}`: `redirect 301 /new/{*}`).
* `${env:NAME}` and `${file:/path}` substitute at load time (secrets from
  files, never inline).
* `include "conf.d/*.conf"` splices files in place, in sorted order.
* Options go on the directive's line as `key=value`. When they do not fit,
  the same keys can be written as a block, one per line:
  `connect timeout=1s warm=4` and `connect { timeout 1s; warm 4 }` mean
  the same; `okena fmt` picks the line form when it fits in 80 columns.
* On the command line (`okena tcp :5432 to db1:5432`) and in
  `OKENA_CONFIG`, the text is the same language; a listener with a single
  directive may drop its braces, and a directive may follow a `}` on the
  same line (`okena { workers 4 } tcp :5432 to db1:5432`).
* `policy NAME { ... }` defines a reusable set of route directives; `use
  NAME` applies it. Directives written in the route override the policy, all
  of that name (a route's `limit` replaces the policy's), and with two `use`,
  the first overrides the second. A policy cannot use another.

## Layers

A configuration reads the way a connection travels up the network
stack. A listener's keyword says what okena speaks with clients on that
address; inside it, each block belongs to one layer, in the order data
goes up:

| Layer | OSI | Where it is configured |
|---|---|---|
| address and transport | 3-4 | the listener: `tcp`, `udp`, `http` (HTTP is over TCP), its addresses, `limits`, `timeout`, `proxy_protocol` |
| session and presentation | 5-6 | `tls { }` inside a `tcp` or `http` listener: certificates, versions, ALPN, client certificates, or SNI routing without decrypting |
| application | 7 | inside an `http` listener: `host`, `route`, headers, auth, limits on requests |

Backends mirror it: a `pool` has `server`s (address), `connect` (L4),
`tls` (encryption towards them), `protocol` (h1, h2, grpc) and `health`
checks at the layer they test (`tcp`, `tls`, `http`).

Nothing is configured at a layer it does not act on: a TCP listener has
no routes, an HTTP route has no TCP options, and a certificate is always
in a `tls` block, whatever runs on top of it.

## The smallest configs

L4 TCP balancer (PostgreSQL replicas):

```
tcp :5432 {
    to 10.0.0.11:5432 10.0.0.12:5432
}
```

HTTP reverse proxy:

```
http :80 {
    route /* { to 127.0.0.1:3000 }
}
```

HTTPS: the same, with the TLS layer added:

```
okena { acme /var/lib/okena/acme ca=https://acme-v02.api.letsencrypt.org/directory }
http :80 { route /* { redirect 308 https://example.com/{*} } }   # (and the CA's proof)
http :443 {
    tls { acme example.com }        # a certificate from the CA, renewed by okena
    host example.com {
        route /* { to 127.0.0.1:3000 }
    }
}
```

TLS ends at okena, raw TCP behind (IMAP, a database):

```
tcp :993 {
    tls { cert /etc/okena/mail.pem }
    to 10.0.0.30:143
}
```

TLS passes through untouched, routed by the name the client asks for:

```
tcp :443 {
    tls passthrough {
        sni api.example.com to pool api-tls
        sni *.internal      to pool internal
    }
}
```

On the command line, inside Docker:

```
docker run --network host okena tcp :5432 to db:5432
docker run --network host okena 'http :80 { route /* { to app:3000 } }'
```

## Top level

```
okena {
    workers auto              # min(affinity mask, cgroup CPU quota)
    io_engine auto            # auto | io_uring | epoll
    busy_poll 50us            # poll this long after activity instead of sleeping
    watchdog 2s               # a worker stuck this long is replaced
    drain delay=2s timeout=7s # fits inside docker stop's 10 s
    metrics :9464             # /metrics, /status, /dashboard, /live, /ready
    # metrics :9464 token=/etc/okena/metrics.token   # all but /live and /ready behind it
    admin unix:/run/okena/admin.sock  # `okena reload`, `okena backend`
    user okena                # or okena:okena, 65532:65532: who faces the network
    handshake_budget 100us wait=1s  # TLS hello crypto per loop iteration (0us: off);
                              # past it hellos queue, and those older than wait close
    acme /var/lib/okena/acme ca=https://acme-v02.api.letsencrypt.org/directory email=ops@example.com
                              # automatic HTTPS: `tls { acme NAME... }` (below)
    # planned:
    profile balanced          # balanced | latency | throughput | memory-lean
    reload on-change          # watch the config directory (today: SIGHUP, `okena reload`)
}
```

The metrics address also serves `/status`, the instance now as JSON, and
`/dashboard` (and `/`), a page that reads `/status` once a second and
follows the traffic's way through: each listener, with its protocols
(HTTP/1.1, HTTP/2, HTTP/3 and QUIC's retry, v2 and 0-RTT; TLS, kTLS,
client certificates; PROXY protocol), its certificates (names, key, days
until they expire, in colour as the day nears), its limits and timeouts,
and its rates (connections, requests, 5xx and bytes a second); for HTTP,
latency (p50, p90, p99 over the last ten seconds, from a log-linear
histogram whose buckets are an eighth of their value wide), requests by
protocol, the 401, 403, 404 and 429 it answered, WebSocket upgrades and
cache hits; TLS handshakes by version, resumed and failed or abandoned, and
QUIC's; for UDP, flows, new flows, datagrams and bytes each way, and what a
flow may get back (`responses`), with the instance's dropped datagrams at
the top. Each route,
with its methods, what it passes through (limit, auth, cache, cors,
compress, rewrite, headers, hedge, mirror, split, fault, priority) and
where it goes: a pool, with how many of its servers are up, or okena itself
(a redirect, files). Then each pool, with how it balances (and on what
key), its health check, TLS to its servers, sticky sessions and slow
start, who uses it (the listeners and routes that send to it, mirrors
included), and its servers with their state (`up`, `down` by health,
`drain` by the API), weight, backup, connections against `max=`, and
rates. At the top: version, engine, workers, uptime, reloads, restarts,
a drain, and the totals. The rates come from samples the admin process takes once
a second, so they are the same for everyone who looks and cost the workers
nothing. `okena top [-c FILE]` shows the same as a table, over the admin
socket, a fresh frame a second; `okena top once` prints it one time, for
scripts.

`token=FILE` puts everything on that address but `/live` and `/ready` (the
probes) behind a token, the file's first line, 16 to 255 printable bytes. It
is accepted as `Authorization: Bearer TOKEN`, as Prometheus' `authorization`
sends it, or as the password of Basic authentication, any user name, so a
browser can open the dashboard; without it the answer is 401 asking for
Basic. It is compared in constant time. The token travels as written:
without TLS on that address, keep it on a trusted network or behind a
proxy that adds TLS.

Besides connections, bytes and responses by class, `/metrics` has, by
listener: `okena_http_request_duration_seconds` (a histogram, from the
request head to the end of its answer), `okena_http_requests_by_protocol_total`
(`protocol` http/1.1, h2, h3), `okena_http_responses_by_code_total` (401,
403, 404, 429), `okena_websocket_upgrades_total`, `okena_cache_hits_total`,
`okena_tls_handshakes_total` (`version` 1.2 or 1.3; `result` resumed, or
failed for a handshake that failed or that its client left),
`okena_quic_handshakes_total`, `okena_udp_datagrams_total` (`direction`);
and `okena_udp_dropped_total`, the datagrams lost with no flow to take
them or a socket buffer full. `okena_tls_certificate_not_after_seconds`
is when each certificate served ends (seconds since 1970), labelled with its
first name, `source` (file, acme, acme_pending, local, local_pending) and its
`entry`: `(okena_tls_certificate_not_after_seconds - time()) / 86400 < 14` is
the alert rule.

`user NAME[:GROUP]` (or numbers) makes the processes that face the
network, or read what it sends, run as that user and group with no
capability: workers, health checks, the control process and JWKS, the admin
process and the logger. The supervisor stays as it was started, as nginx's
master does: a reload reads private keys that only root may read and binds
ports below 1024, and the reload's compiler, which reads them, is boxed in
by seccomp and Landlock to reading. So the access logs' directories must be
the user's to write, and what the control process reads (a discovery file,
a token) the user's to read. A name is looked up in /etc/passwd and
/etc/group; with no group, the user's own. Started by anyone but root,
okena may only name itself.

Profiles set groups of defaults: `latency` enables busy polling, NAPI
polling and smaller batches; `throughput` larger batches and `SEND_ZC`
thresholds; `memory-lean` smaller pools and earlier trimming. Any single
setting can still be overridden.

## Listeners

```
tcp     ADDR...   { ... }   # L4 stream proxy; with tls { } it terminates or routes TLS
udp     ADDR...   { ... }   # L4 datagrams (DNS, games, syslog)
http    ADDR...   { ... }   # L7; with tls { } it is HTTPS (and HTTP/2, HTTP/3)
```

`udp` forwards datagrams. A client on a listener is a flow, pinned to the
server it got until it goes quiet for `timeout { idle }` (30 s), then
forgotten; `limits { connections N }` is how many flows it holds (the default
as for `tcp`), and when it is full an idle one makes room or the new
client's datagrams are dropped: flows in use are never pushed out by new
ones. `responses N` ends a flow at its Nth answer, at once (DNS: `responses
1`); `responses 0` expects none (syslog, metrics), and its flows take no
socket of their own. Without it a flow lasts as long as it is used (games,
VoIP, QUIC to a backend that speaks it):

```
udp :53 { to pool dns; responses 1; timeout { idle 5s } }
udp :514 { to pool logs; responses 0 }
udp :27015 { to pool game; timeout { idle 2m } }
```

A flow that expects answers has its own connected socket: answers come only
from its backend, and an ICMP "port unreachable" from it counts as a failed
connect (three take it out for 10 s, as for `tcp`). A flow whose server goes
down, by health checks or passively, moves on its next datagram, within a
second; `okena backend drain` keeps the flows a server has and gives it no
new ones. Bound to every address (`udp :53`), answers leave from the
address the client wrote to. The same port can be `tcp` and `udp` at once,
but not `udp` and an `http3` listener. A reload hands the sockets on with
the datagrams queued in them; an answer an old worker waits for still
reaches its client, within the drain timeout. An upgrade does the same.
Each worker has its own socket, so a client stays on one worker; a reload
that changes the number of workers moves some flows, which start again on
their next datagram (to the same server with `balance source-hash`).

`xdp` (L4 in the kernel, direct server return) is a mode of `tcp` and
`udp` listeners: `tcp 203.0.113.10:80 { mode xdp; to pool web }`.

Transport settings, the same in every listener:

```
limits {
    connections 200000
    per_source 256                  # connections per client address
}
timeout {
    idle 60s
}
proxy_protocol send v2              # tcp: tell the backend who the client is
proxy_protocol accept from=10.0.0.0/8   # believe PROXY v1/v2 from these
```

The TLS layer:

```
tls {
    cert /etc/okena/fullchain.pem key=/etc/okena/key.pem   # or one per host,
    acme example.com www.example.com   # or from a CA (ACME), okena renewing it
    auto                            # or one from the CA for each name of the host blocks
    redirect off                    # (plain http for those names; 308 to https by default)
    local localhost app.test 127.0.0.1 # or from okena's own CA (development)
    ocsp off                        # (OCSP stapling: on by default, below)
    on_demand *.example.com ask=http://127.0.0.1:9000/ok   # certificates as names come
    versions 1.2 1.3
    alpn h2 http/1.1
    client_ca /etc/okena/clients.pem required
}
tls passthrough {                   # tcp only: route on SNI, never decrypt
    sni api.example.com to pool api-tls
    default reject
}
```

**On-demand certificates.** `on_demand [PATTERN...] [ask=URL] [max=N]` in a tls
block gets a certificate from the ACME CA for a name the moment a client asks for
it (its SNI), when no certificate of the listener has it: for platforms whose
customers bring their own domains. A pattern is a name or `*.parent` (any name
under it); `ask=http://...` is asked first, GET URL?domain=NAME (or &domain=), and
only a 200 lets okena ask the CA; at least one of the two is needed, so a
stranger's names cannot make okena use up the CA's limits. `max=` caps how many
(64 at most). The handshake waits (each second looked at again, 15 s at most)
while the acme process gets it, then goes on with it, without a reload; a name
refused (for 10 minutes), not allowed, past `max=`, or not served in time goes
on at once with the listener's own certificate (one okena signs, when the block
has none). The certificates are kept in DIR as the others, named in
DIR/on_demand.list, served again after a restart and renewed the same way.
(Requests whose Host differs from such a name are not answered 421.)

**OCSP stapling.** A certificate whose chain names its issuer and whose leaf names
an OCSP responder (Authority Information Access, http://) is stapled: okena asks
the responder, by a CertID of SHA-1 hashes (as RFC 5019 asks), and a client that
sends status_request gets the answer with the certificate (TLS 1.3: in the
leaf's entry; TLS 1.2: a CertificateStatus message), so it need not ask the CA
itself. An answer is taken only when the issuer signed it, or a
responder the issuer delegated to (its certificate, signed by the issuer, for
OCSPSigning, carried in the answer); when it names the certificate and says it
is good; and while it is current (thisUpdate passed, nextUpdate to come: never
stapled past it). It is asked for again halfway to its nextUpdate; a failure is
tried again after 5 minutes, then twice as long up to an hour, the last good
answer kept until its nextUpdate. A revoked certificate is said in the log, and
nothing is stapled for it; when it is one okena got by ACME, the acme process is
woken and renews it at once. A process of its own, `okena-ocsp`, does the asking;
`ocsp off` in a tls block keeps its certificates out of it.

**Automatic HTTPS.** `acme NAME...` in a tls block is a certificate for those
names from an ACME CA (RFC 8555: Let's Encrypt, ZeroSSL, a step-ca of one's own),
named once in `okena { acme DIR ca=URL [email=ADDRESS] [trust=FILE]
[challenge=http-01|tls-alpn-01|dns-01] }`: `ca=` is the CA's directory URL
(https), `trust=` a PEM file whose first certificate signs the CA's own (else the
system's roots), `email=` the account's contact. Up to 16 such lines, 15 names
each; a wildcard (`*.example.com`) with DNS-01 only.

`fallback=URL` names a second CA, asked at once when an order with the first
fails (down, rate-limited, refusing), before any backoff; `fallback_trust=FILE`
is its anchor. `eab=FILE` and `fallback_eab=FILE` give a CA an external account
binding (RFC 8555 7.3.4), which ZeroSSL, Google's CA and many private CAs ask
for: one line, `KID:HMAC_KEY`, as the CA gave them (the key base64url). A CA
whose directory says `externalAccountRequired` and has none is not asked for an
account, and the log says why.

okena keeps them in DIR (made 0700, the `user`'s): `DIR/account.key`, the
account's key (P-256, made once), and for each certificate `DIR/NAME/cert.pem` (the
chain) and `DIR/NAME/key.pem` (0600), NAME its first name. They are loaded as
`cert` loads files; until there are any, the listener serves a certificate it
signs itself for the names (7 days), so it is up from the start. A process of its
own, `okena-acme`, asks the CA: an order for the names, each proven, a new key
and its CSR, the chain. With HTTP-01 (the default) the CA fetches
`http://NAME/.well-known/acme-challenge/TOKEN`: port 80 must reach an http
listener of this okena, which answers it before any route, whatever the routes
say (a token not being asked for goes on to the routes). With TLS-ALPN-01 (RFC
8737) no port 80 is needed: the CA opens TLS to port 443 asking only for ALPN
`acme-tls/1`, and that handshake alone gets a certificate the acme process made
for the name, carrying the proof; every other client of the name gets the
ordinary one. With DNS-01 nothing of okena need be reachable, and wildcards can be
had: okena puts a TXT record `_acme-challenge.NAME` through the DNS provider's
API, waits for it to spread, and removes it after, whatever the outcome.
`dns=cloudflare dns_token=FILE` (an API token with Zone.DNS edit, alone in the
file), and if wanted `dns_api=URL` (else Cloudflare's), `dns_wait=` (20 s by
default) and `dns_trust=FILE` (the API's anchor, else the system's roots). The
zone is the first of the name and its parents that the token's account holds.
Or any server that takes dynamic updates (BIND, Knot, PowerDNS): `dns=rfc2136
dns_server=HOST:PORT dns_key=FILE [dns_wait=]`, the key file one line as
`nsupdate -y` takes it, `[hmac-sha256:]NAME:SECRET` (base64). The UPDATE goes
over TCP signed with TSIG (HMAC-SHA256, RFC 8945), and the server's answer must
be signed with the same key; the zone is the first of the name and its parents
that the server does not answer NOTAUTH or NOTZONE for. Or Route 53: `dns=route53
dns_key=FILE [dns_api=] [dns_wait=] [dns_trust=]`, the file one line,
`ACCESS_KEY_ID:SECRET[:SESSION_TOKEN]`, a key allowed
`route53:ListHostedZonesByName`, `ChangeResourceRecordSets` and `GetChange`.
Requests are signed with AWS Signature Version 4; the zone is the hosted zone
named as the name or its nearest parent; a name's values (a wildcard's and its
parent's share one) go in one record set, okena waits for Route 53 to say the
change is INSYNC before `dns_wait`, and deletes the record set after. The files are written beside and renamed over, and okena reloads
itself: the new certificate is served, no connection dropped. A certificate is
renewed when two thirds of its life have gone (less a random part, up to a
twentieth of it, so that certificates got together are not renewed together), or when the CA says so: a CA with
ARI (RFC 9773, Let's Encrypt's renewalInfo) is asked, for each certificate,
what window it wants it renewed in, and okena renews at a random time within it
(earlier, say, ahead of a revocation, or later); asked again as its Retry-After
says (an hour to a day), and the new order names the certificate it replaces.
After a failed order the next one goes first to the CA's staging
directory (`staging=URL`; Let's Encrypt's own when `ca=` is Let's Encrypt;
`staging=off` for none), whose certificate is not kept: only when it succeeds
is the CA asked, so a name that keeps failing does not use up the CA's rate
limits. The failure is kept in DIR/NAME/status, so a restart does the same.
A failed order is tried again
after a minute, then twice as long each time up to six hours, the one being served
kept meanwhile (the log says what failed). A restart finds the files and asks
nothing until a renewal is due.

**`tls { auto }`** is a certificate from the CA for each name of the listener's
host blocks, as an `acme NAME` line for each would be (a wildcard's only with
DNS-01). Without `okena { acme ... }`, Let's Encrypt is the CA and
/var/lib/okena/acme the directory (made, parents included). For every name okena
gets from the CA, `auto`'s and `acme` lines' alike, a plain http listener
answers `308 Permanent Redirect` to `https://NAME[:PORT]` and the same target
(the tls block's listener's port, left out when 443), after the ACME challenges;
other names go on to the routes, and `redirect off` in the tls block keeps
plain http for its names.

**A local CA.** `local NAME...` in a tls block is a certificate for development
names (`localhost`, `app.test`, `*.app.test`, `127.0.0.1`, `::1`) signed by a CA
of okena's own, kept in `okena { local_ca DIR }` (by default /var/lib/okena/ca):
`DIR/root.key` (P-256, 0600) and `DIR/root.pem` (10 years), made at the first
start that needs them, DIR 0700 and the `user`'s. Its certificates are signed
in memory at each start or reload: a new key, 7 days, renewed by a reload of
okena's own two thirds of the way. `okena trust` puts `DIR/root.pem` in the
system's trust store and brings its bundle up to date
(/usr/local/share/ca-certificates and update-ca-certificates on Debian, Ubuntu
and Alpine; /etc/pki/ca-trust/source/anchors and update-ca-trust on Fedora and
RHEL; /etc/pki/trust/anchors on openSUSE; trust extract-compat on Arch), making
the CA first when there is none; `okena trust remove` takes it out. Browsers
with a store of their own (Firefox) are not touched: the command says how.
Without a CA (a reload that finds none) the names get a certificate that signs
itself. Keep the CA's key to this machine: whoever has it can sign for any name
the machine trusts.

**A fleet.** `shared=on` says DIR is shared by several okena instances (a volume
they all mount, NFS included), so that one of them orders a certificate and the
others take it. A certificate due, an instance takes `DIR/NAME/lock` (written
beside and linked there: only one link succeeds); the one holding it orders,
then removes it. The others look each second: a certificate on disk that is not
the one they serve is taken (a reload, as for their own), and a lock gone with
none new (the order failed) is taken by one of them. A lock says until when it
holds (10 minutes); one past that is an instance that died ordering, moved aside
and ordered again. With HTTP-01 the CA may reach any instance: the one ordering
writes its challenges to `DIR/NAME/http-01` and waits 2 seconds before telling
the CA; the others answer them too. DNS-01 needs nothing more. TLS-ALPN-01
cannot be shared (the proof is in one instance's handshake), and is refused
with `shared=on`. Each instance keeps its own account (the same key when they
start from one DIR/account.key).

The application layer (http) adds its own limits and timeouts:

```
limits { header_size 32KiB; body_size 10MiB; h2_streams 128 }
timeout { header 10s; body_idle 30s; response 30s }
trusted_proxies 10.0.0.0/8          # believe X-Forwarded-For from these
access_log /var/log/okena/access.log   # or stdout, stderr, off (default), or a URL:
# access_log syslog://10.0.0.5          syslog over UDP (514)
# access_log syslog+tcp://logs:601      over TCP
# access_log syslog+tls://logs:6514 trust=/etc/okena/logs-ca.pem
# access_log otlp://collector:4318      OpenTelemetry logs over OTLP/HTTP
# access_log otlp+https://collector:4318/v1/logs trust=/etc/okena/ca.pem
```

`trusted_proxies` names the peers whose forwarding headers count (load
balancers, CDNs in front of okena). From any other peer,
`X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host` and `Forwarded`
are dropped and okena writes its own. From a trusted peer, the
`X-Forwarded-For` it sent is extended with the peer's address and its
`X-Forwarded-Proto` and `X-Forwarded-Host` are kept. The client (in logs,
and later in limits) is then the rightmost address of that chain that is
not trusted itself; an entry that is not an address stops the walk at the
last trusted hop.

Behind a CDN, `trusted_proxies cloudflare` takes Cloudflare's published ranges, built
into okena (`okena ranges cloudflare` prints them). `allow cloudflare` on a route
lets only those addresses in, so the origin cannot be reached around the CDN (on a
listener without `trusted_proxies`, where the client is the peer). Both also take
`file:PATH`, a range a line, `#` for comments: `contrib/ranges/update.sh PATH`
fetches Cloudflare's current list there, from cron, and `okena reload` takes it.

Access logs are one JSON line per exchange: `time` (UTC, ms), `listener`,
`client`, `peer` (the TCP peer), `method`, `host`, `target`, `status`, `bytes` (sent to the
client), `duration_ms` (from the request head to the end of the
response), `upstream`, `source` (`backend`, or `okena` when okena answered
itself: a redirect, an error, a file, the cache) and `retried`; with
`tracing`, also `trace_id` and `span_id`. The target is kept up to 944 bytes. Workers never write files: they pass lines to a
logger process through a pipe and drop them (counted in
`okena_access_log_dropped_total`) rather than wait when it falls behind.
Lines of different workers may be up to a second out of order. A reload
or `SIGUSR1` makes the logger reopen its files, so logrotate needs only
`kill -USR1`.

The logger also sends lines over the network, and it alone waits on it: a
collector that is slow or gone costs lines, never a request's latency.

* **Syslog** (RFC 5424): each line is one message, `<190>1 TIME HOST okena
  PID access - LINE`: local7.info as nginx sends it, TIME the line's own, PID
  the supervisor's. Over UDP (`syslog://`, RFC 5426) each message is one
  datagram. Over TCP (`syslog+tcp://`) and TLS (`syslog+tls://`, RFC 5425)
  it is framed by octet counting (RFC 6587), on one connection that is kept
  open. A connection the collector closed is noticed before lines are
  written to it, so they go on a new connection and are not lost.
* **OTLP** (`otlp://`, `otlp+https://`): each line becomes one
  OpenTelemetry log record in OTLP/HTTP JSON, POSTed to `/v1/logs` (or the
  URL's path) once a second or every 512 KiB. Its fields are attributes,
  under OpenTelemetry's names where there are some: `http.request.method`,
  `http.response.status_code`, `url.path`, `url.query`, `server.address`,
  `client.address`, `network.peer.address`, `http.response.size`; the
  others are `okena.*`. The record's time is the line's. Severity is INFO,
  WARN for 4xx, ERROR for 5xx, and the body is `METHOD TARGET STATUS`. The
  resource is `service.name=okena` and `host.name`. Records a collector
  did not take are kept and sent with the next batch, up to 1 MiB.

A destination that cannot be reached is logged once. It is tried again
after 1 s, then 2, 4 and so on up to 30 s, and logged again when it is
back. Meanwhile syslog lines are dropped. A name is resolved again at each
connection. TLS servers are verified as backends are, against `trust=FILE`
(its first certificate) or the system's roots (`SSL_CERT_FILE`, else the
usual bundles); `trust=` is refused on a destination without TLS.

### Tracing

```
tracing otlp://collector:4318                 # spans to /v1/traces
tracing otlp+https://collector:4318 sample=5% trust=/etc/okena/ca.pem
```

With `tracing`, each request on the listener is an OpenTelemetry server
span (W3C Trace Context). A client that sends a valid `traceparent` gets
its trace continued, and its span becomes okena's parent. Otherwise okena
starts a new trace. The backend always gets a `traceparent` naming okena's
span, so the trace goes on through it; the client's own `traceparent` is
replaced and its `tracestate` passes untouched.

Sampling is parent-based, as OpenTelemetry's default sampler: a trace the
client marked sampled is kept, one it marked unsampled is not, and a new
one is kept for `sample=` of them (100% unless said, decided on the trace
id's low bits as TraceIdRatio does). A trace not kept still reaches the
backend, marked unsampled.

A kept span is sent at the end of its exchange, through the logger as
access lines are, so a worker never waits on the collector. It is named
by the method, of kind SERVER, from the request head to the end of the
response, and carries the attributes the access log's records have under
OpenTelemetry's names. A 5xx makes its status an error; a 4xx does not.
With tracing, access lines carry `trace_id` and `span_id`, and OTLP log
records their `traceId` and `spanId`, so logs and traces meet. Copies
(`mirror`, `hedge`) carry the same `traceparent` and send no span of their
own. Spans to a collector that is away are kept and retried as OTLP log
records are.

### Error pages

```
errors 502 503 504 file=/srv/errors/down.html     # in an http listener, or a route
errors 404 file=/srv/errors/404.html
route /api/* { errors 5xx backend file=/srv/errors/api.json; to pool api }
```

`errors` answers okena's own errors (a backend that cannot be reached, a
timeout, a request it refuses, no route) with a page of one's own instead
of its short text. A code is a status from 400 to 599 or a class (`4xx`,
`5xx`). A route's pages are looked at before its listener's; an error that
comes before a route is chosen (a request okena cannot read, no route)
takes the listener's. With `backend`, the errors a backend answers are
replaced too: their status stays and their body never reaches the client
(so a stack trace does not leak), and the connection to that backend is not
kept. The file is read with the configuration, a reload reads it again; a
page is at most 16 KiB. Its type comes from its extension: `.json`
application/json, `.txt` text/plain, anything else HTML. In it, `{status}`,
`{reason}` and `{request_id}` become the answer's own; the request id is
also in `X-Request-Id`, so a user can give it and the access log finds it.
The answer is never cached and closes the connection, as okena's errors do.
gRPC requests keep their own errors (grpc-status), not a page.

### Maintenance

```
okena maintenance on                  # every request: 503, Retry-After, the page
okena maintenance on /api/*           # or a route's, named as written
okena maintenance off /api/*          # that route back; `off` alone: everything
okena maintenance                     # how it is: "on" or "off", and the routes
```

and, in an http listener, how it goes there (each key may be left out):

```
maintenance file=/srv/maint.html retry=2m allow=10.0.0.0/8,192.0.2.7 except=/healthz,/status/*
```

In maintenance a request gets 503 with `Retry-After` (`retry`, 30 s unless
said) and the page: `file` (read as an error page is, with its
placeholders), or a short text with the request id. `allow` lets clients
in (as `trusted_proxies` has them: the team that checks the work), and
`except` paths (exact, or a prefix with a trailing `*`: the balancer's
health check) are still served. `/ready` does not change: the instance is
up and the page is its answer. The state lives in the admin API, so a
reload keeps it and a restart or an upgrade starts out of it; `/status`
and the dashboard show it. Sixteen routes may be in maintenance at once.

## HTTP routes

A route matches on host, path, method, headers and query, in that order.
Inside a route, `match` narrows further; its conditions use the same
names as limit keys (`method`, `header:NAME`, `query:NAME`, `cookie:NAME`,
`client.ip`), joined by AND. `NAME=VALUE` is exact, `NAME=VALUE*` a prefix, `NAME`
alone says it is there; `client.ip=` takes a CIDR, and is the client as
`trusted_proxies` has it. The first block that fits, in the order written, is the
one, and a route has 32 at most.

A block is the route with some directives changed: what it has replaces what the
route has under that name, all the rest stays, so an `auth` on the route holds in
every block. `to`, `redirect` and `split` count as one. `limit` adds instead: a
block's goes with the route's, as replacing it could loosen it unawares. A block has
no `match` or `use` inside it.
The most specific match wins (exact host over wildcard, static path over
parameter over `*`); ties are an error at load time, not a surprise in
production.

```
http :443 {
    tls { auto }
    host api.example.com www.example.com {
    route /v1/users/{id} GET PUT {
        use authenticated
        to pool users
    }

    route /v1/* {
        match header:x-canary=yes {
            to pool api-canary
        }
        to pool api
    }

    route /static/* {
        files /srv/static precompressed=br,gz cache=1y
    }

    route /old/* {
        redirect 301 /new/{*}
    }
    }
}
```

Route directives:

```
to pool NAME                     # or: to ADDR... for an inline pool
split api=95% api-canary=5% sticky=cookie:okena_split
mirror pool shadow 10%           # copy of the request, response ignored
redirect 301 /new/{*}             # okena answers; {*} = the path after the route's prefix
redirect 308 https://{host}{*}    # {host} = the request's host name, its port left out
redirect 308 https://{host}{path} # {path} = the whole path (normalized), the query kept
respond 404                       # okena answers with the code alone (4xx, 5xx)
header set   x-env prod            # replaces what the client sent
header add   x-via okena           # keeps it, adds one more
header drop  x-internal-*          # a name, or a prefix with *
response header set strict-transport-security "max-age=63072000"
response header drop server
rewrite path /v1/{*} -> /{*}       # the backend sees /users for /v1/users
priority critical                # critical | normal | bulk (shedding order)
timeout total=5s try=2s          # whole request incl. retries / one attempt
retry 2 on=connect,reset,503 idempotent-only
hedge after=p95 max=1            # tail cutting for idempotent requests
cache 30s stale-while-revalidate=5m vary=accept-encoding max=1MiB
cors origins=https://app.example.com methods=GET,POST credentials

match method=POST header:content-type=application/json {
    limit 20/s key=client.ip       # a block applies only when it matches
}
limit 100/s burst=200 key=client.ip
limit 10000/m key=header:x-api-key instances=4   # share of a fleet-wide limit
```

`cache` keeps answers in memory, in each worker: `okena { cache_memory 64MiB }` is
for each one, and a reload starts empty. Each worker fetches on its own, and the
answers it has are not seen by the others. When many ask at once for what is not
there, one goes to the backend and the rest wait for it.

`okena { cache_disk /var/cache/okena size=200GiB }` adds a second tier, on disk, that
is one for every worker and every okena process on the machine. What one worker
fills, all of them serve. The cache survives reloads, upgrades and restarts, and a
reboot too if okena was stopped cleanly. Memory stays the first tier: a worker
looks there first, then on disk, then asks the backend. An answer it keeps goes to
both tiers. A hit from disk says `Cache-Status: okena; hit; ttl=N; detail=disk`.

The directory must exist and be writable by whoever starts okena. It holds three
files: `okena.dat` holds the answers, `okena.idx` says where each one is, and
`okena.lock` is taken only while a worker starts. The disk is used as two logs, cut
into segments of 64 KiB to 64 MiB (a sixteenth of the size): a small one, a tenth of
the store, where answers come in, and a main one. A process of its own,
`okena-cache`, keeps room free ahead of both, S3-FIFO. An answer asked for again
while it is in the small log moves to the main one. One asked for once goes, and its
key is remembered: if it is asked for again later, it goes straight to the main log.
In the main log, an answer that is still asked for is kept; one that is not goes.
So a crawler that reads everything once does not push out what people keep asking
for. An answer larger than a segment, or with a head over 8 KiB, stays in memory
only. Nothing is overwritten while a client is still being sent it: until then, new
answers are not written to disk. Each record is
checked against its key and its place before it is served, so a damaged file is a
miss, never a wrong answer. A different `size=` makes a new store; processes still
on the old one keep it until they go. When the directory cannot be used, okena says
so and keeps answers in memory only.

Every okena on one store must see the others' processes: one host, or one pid
namespace. A store whose last process did not stop cleanly is kept after a crash,
because the pages were in the kernel's cache, but not after a reboot. Heads are read
and records written in place, through the page cache.

A body of 64 KiB or more, from disk or from `files`, goes from the page cache to the
socket without copies: splice through a pipe with io_uring, sendfile with epoll. This
needs HTTP/1.1 in the clear or with kTLS (`tls { ktls on }`), and an answer that is
not compressed. Anything else is read into okena and sent from there, as before.
`/metrics` counts `okena_zero_copy_bytes_total`, and for the disk
`okena_cache_disk_hits_total`, `okena_cache_disk_writes_total` and
`okena_cache_disk_full_total` (answers not written because the oldest part was still
being sent).

| Option | Meaning |
|---|---|
| the time | how long an answer is good, unless the backend's `s-maxage` or `max-age` says otherwise |
| `stale-while-revalidate=T` | past that, serve it at once for T while it is fetched again; `must-revalidate` takes this away |
| `stale-if-error=T` | past that, still answer with it for T when the backend fails: 500, 502, 503, 504, or okena's own 502/504 for a backend that cannot be reached. The origin's `Cache-Control: stale-if-error=N` (RFC 5861) wins over the route's; `must-revalidate` takes it away |
| `vary=a,b` | up to 4 request fields that are part of the key, with host and target. `Accept-Encoding` counts as the set of codings it takes (br, zstd, gzip; `q=0` takes one away): `gzip, br` and `br;q=1, gzip` are one answer |
| `query=all\|none\|a,b` | the target's query in the key: all of it (the default), none of it, or only the parameters named, in that order, whatever order the request has them in. An absent parameter and an empty one are not the same |
| `host=off` | the host is not in the key: one answer for every name the listener serves |
| `slice=SIZE` | large objects kept in slices of this size (64 KiB to 64 MiB), each fetched with a Range of its own: see below |
| `max=SIZE` | the largest answer kept, 1 MiB by default |
| `shared=on` | the answer is the same for everyone: see below |

Kept: GET answers of 200, 301, 308, 404 and 410 with a length or chunked. HEAD reads
them. Not kept: `Cache-Control` no-store, private or no-cache, `Set-Cookie`, `Vary`
naming a field not in `vary=`, or a body with no length, as a cut would look like
its end. A request with a body goes to the backend; a conditional one reads what is
kept and gets a 200, and on a miss is not kept. A `Range` of bytes (`a-b`, `a-`,
`-n`) on a kept 200 is answered from the cache: a 206 with `Content-Range`, or a 416
past its end. Several ranges, another unit or an `If-Range` get the whole answer, a
200, as a server may always give. A `Range` of what is not kept yet goes to the
backend as it is, and fills nothing. A client's own `Cache-Control`
is not obeyed.

Unless `shared=on`, a request with Cookie or Authorization, or on a route with `auth`,
neither reads nor fills: an answer for one person must not reach another. A hit says
`Age` and `Cache-Status: okena; hit; ttl=N`, negative when stale, and runs behind
what the route has for clients: auth, limits, CORS and `response` rules.

Every answer of a route with `cache` says what the cache did with it, in
`Cache-Status` (RFC 9211):

| `Cache-Status` | When |
|---|---|
| `okena; hit; ttl=N` | from the cache (`; detail=disk` from `cache_disk`) |
| `okena; fwd=miss; stored` | from the backend, and kept |
| `okena; fwd=miss` | from the backend, not kept (`no-store`, a status it does not keep, too large, a range of what is not there yet) |
| `okena; fwd=bypass` | past the cache: a request for one person |
| `okena; fwd=method` | past the cache: a method it does not keep |
| `okena; fwd=stale; fwd-status=503; ttl=-N` | the backend failed, and a stale copy answered (stale-if-error) |

A backend's own `Cache-Status` is passed on, and okena's comes after it, as the RFC
orders them.

`slice=4MiB` is for video and downloads. An object is kept as slices: each one a
cache entry of its own, fetched from the backend with `Range: bytes=` of that slice
and kept whole. A client's answer is put together from them: a whole GET as one
200, a range as a 206 of the slices it covers. Only those slices are fetched, so a
client that seeks to the end of a 4 GB file costs the backend a few slices, not
4 GB. A slice that is not there is fetched while the client waits for it, and the
next one is asked for while the current one goes out. The backend must answer a
Range with a 206 that says where it begins. One that answers with a 200 (for an
object larger than a slice) is not sliced: the request goes to it as it came. A
slice whose `Content-Range` is not the one asked for is never kept, and a client
waiting for it is cut rather than sent the wrong bytes. A purge of the object's URL
takes all its slices.

`signed_urls key=FILE [key2=FILE]` on a route serves only links the origin signed,
until they expire. The key is the first line of its file (16 to 128 bytes), shared
with whoever signs. A link carries in its query `expires=` (Unix seconds), `sig=`
and, if wanted, `prefix=` and `ip=`. `sig` is the HMAC-SHA256 of
`PATH\nEXPIRES\nIP`, in base64url without padding. PATH is the link's path as
it is in the link, or the prefix when there is one. IP is empty when there is none.

```
okena sign /etc/okena/url.key /video/a.mp4 1h               # one file, an hour
okena sign /etc/okena/url.key /live/x/0.ts 6h prefix=/live/x/   # a whole stream
okena sign /etc/okena/url.key /dl/f.zip 10m ip=203.0.113.7  # one client
```

With `prefix=`, one signature serves every path under that prefix: the segments of
an HLS or DASH stream. With `ip=`, only that client may use the link (the address
`trusted_proxies` gives, behind a CDN). `key2=` is taken as well, so a key can be
rotated without breaking the links already out. Anything wrong (no signature,
expired, another path, another client, a parameter twice) is a 403, the same for
each. The check comes before the cache, so a cached answer still wants a valid
link. The cache keeps one answer per object, not one per link: `expires`, `prefix`,
`ip` and `sig` are not part of its key.

A shield tier is a pool of other okenas between the edges and the origin, each
caching. With `balance maglev key=url` every edge sends an object to the same
shield, so the origin is asked for it once, however many edges there are:

```
okena { cdn_loop examplecdn }                  # on every edge and every shield
pool shields {
    balance maglev key=url
    server shield-1.internal:80
    server shield-2.internal:80
}
http :443 { route /* { cache 1h stale-if-error=1h; to pool shields } }
```

Each cache adds its own `Cache-Status`, the one nearest the origin first, so a
client sees what each did. `okena { cdn_loop NAME [max=3] }` (RFC 8586) names
okena in `CDN-Loop` on every request to a backend, after what the request said
there already. A request that comes in naming it `max` times or more (in any case,
with or without parameters) has gone round in circles, for example an origin
pointed back at the edges, and gets a 508 Loop Detected. Other CDNs' names do not
count.

`okena { bird /run/bird/bird.ctl protocol=anycast pool=web }` announces an anycast
address only while this okena can take traffic, through BIRD's control socket. It
sends `enable anycast` and `disable anycast`, for BIRD's protocol that exports the
address over BGP. okena can take traffic as `/ready` says: not draining (`okena
drain`, a stop, the old process of an upgrade) and, with `pool=`, while that pool
has a server up. A node whose backends are all down withdraws itself, and the
routers send its share of clients to the other nodes.

okena tells BIRD as soon as its state changes, and again every 5 seconds, so a BIRD
that restarted learns it. When BIRD does not answer, okena says so once and tries
again every second. On a stop the address is withdrawn during the drain delay: use
`drain delay=` of a few seconds, so the route is gone before the connections are.
The admin process talks to BIRD (as `user`, so the socket must let that user in).
If okena dies outright, BIRD keeps announcing, so pair this with a check in BIRD
itself or a `birdc disable` in the service manager's stop hook.

```
# bird.conf
protocol static anycast { ipv4; route 203.0.113.10/32 blackhole; }
protocol bgp upstream { local as 65001; neighbor 10.0.0.1 as 65000;
                        ipv4 { export where proto = "anycast"; }; }
```

Without BGP, two okenas can share one address with VRRP version 3 (RFC 9568), as
keepalived does beside HAProxy:

```
vrrp eth0 vrid=51 priority=150 address=203.0.113.10/24 advert=1s track=web
# the other one: priority=100
```

The highest priority holds the address on the interface. It says so every `advert=`
(10 ms to 40.95 s, 1 s by default) to 224.0.0.18. When those adverts stop for three
intervals and a bit, the backup with the next priority adds the address and sends a
gratuitous ARP, so the network learns where it is. The real MAC answers for it; no
virtual MAC is used. With `preempt=on` (the default), a node of higher priority that
comes back takes the address again. Health counts as well. An okena that cannot take
traffic (draining, stopping, or `track=POOL` with no server up) gives the address up
with an advert of priority 0, so the other takes it at once, and as a backup it does
not take it. A stop gives the address up first. A reload that leaves `vrrp` as it
was changes nothing, master included.

It runs in a process of its own, `okena-vrrp`, as root (raw and packet sockets; the
address added and removed over netlink), confined by seccomp to what it does, with
the admin process telling it whether okena can take traffic. IPv4 for now. Every
node on the link must use the same `vrid` and `advert`.

A purge takes answers back at once, from every worker's memory and from the disk:

```
okena purge url https://shop.example/p/a?x=1     # this answer
okena purge prefix shop.example/assets/          # all under it
okena purge tag product-42                       # all that the origin tagged so
curl -X POST -H "Authorization: Bearer $TOKEN" 'http://10.0.0.1:9464/purge?tag=product-42'
```

A URL is matched by its host, in any case, and its target as the client asked for
it, query included. An answer's tags are what the origin said in `Cache-Tag`
(commas between them) and `Surrogate-Key` (spaces between them). `okena purge` goes
through the `admin` socket. `POST /purge` is on the metrics listener, and needs its
`token=`: without one, purges over HTTP are refused.

A purge covers an answer whose fetch began before it, even one still in flight when
the purge came. Purges are checked when an answer is about to be served, so a purge
costs nothing at the time it is made, however much is cached. Up to 1024 purges are
remembered; past that, anything fetched before the oldest purge forgotten counts as
purged, so it is fetched again rather than served stale. With `cache_disk` the
purges are kept in the store, so they hold for every okena process on it and
outlive restarts and upgrades.

`okena { fleet 10.0.0.2:9464 10.0.0.3:9464 }` names the metrics listeners of the
other instances. `okena purge` asks each of them too, over HTTP with this instance's
metrics token (the fleet shares one), and prints a line for each: `ok`, the status
it answered with, or `no answer`. This is plain HTTP: keep it on a private network.

`redirects FILE code=301` keeps thousands of old paths in a file, one lookup each:
lines `/old /new` or `/old https://else/ 302`, `#` for comments, each path once. The
path is the normalized one, exact, and the client's query goes along. What is not in
the file goes on through the route; auth and limits of the route come first.

`hold 10s` makes a request wait for a backend, for that long, when none can be connected
to, instead of a 502: for a pool that is restarting. Nothing has reached a backend then,
so a POST can wait too. It tries every 100 ms, ejected servers included, so one that is
back is found at once. It is about connections: a 503 from a backend is its answer.

`allow 10.0.0.0/8 2001:db8::/32` and `deny ...` on a route look at the client as
`trusted_proxies` has it, before anything else on the route: a 403. A deny wins, and with
any `allow` what is not in one is refused. Either takes `file:PATH`, one address or
range a line, `#` for comments: lists of thousands cost one step a bit.

`okena { geoip /etc/okena/GeoLite2-Country.mmdb }` loads a MaxMind country database, up
to 64 MiB, read at start and on a reload. Then `allow country:BR,PT` and `deny country:RU`
go on a route, and `match client.country=BR,PT` in a block; a route that names a country
with no file is refused at load. An address in no network has no country: it is not in
any list, so `deny` lets it by and `allow` does not. It is the client as `trusted_proxies`
has it. A broken file gives no country, and does not stop a worker.

Request bodies reach the backend byte for byte, whatever the protocol: nothing in okena
rewrites them, so signed webhooks need no setting.

`idempotency header=idempotency-key ttl=24h lock=60s` on a route makes a request that
changes something, sent twice with the same key, reach the backend once, whichever
worker takes it. The second gets the first's answer with `Idempotency-Replayed: true`.
GET, HEAD and OPTIONS are left alone, as is a request with no key.

The key counts with the route and whoever `auth` proved, so it is no way to someone
else's answers. While the first runs, others get a 409. A key sent again with another
method, target, length or content type gets a 422; the body itself is not compared. Up
to 4096 keys at once and past `ttl` they go; with no room the answer is a 503 rather
than a request without the guarantee.

Every answer of the backend is kept, 500s too, as it may have done the work, but for
502, 503 and 504, and for no connection at all: then the key is free again. If the
request was sent and no answer came, the key stays locked until `lock`: a retry gets a
409 until then, and after that it runs. So make `lock` longer than the backend may take.
An answer over 48 KiB cannot be replayed: a retry gets a 409, not a second run. Keys
live in memory: they outlive a reload and a worker, not a restart.

`limit 10000/d burst=10000 key=auth.user` is a quota: it comes back little by little
over the day, with no fixed hour when it resets, and starts over with a restart.

A route either forwards (`to`), redirects (`redirect CODE TARGET`, with
301, 302, 303, 307 or 308; TARGET a path or an `http(s)://` URL, where `{host}`
is the name the request was for) or answers (`respond CODE`: 400, 401, 403,
404, 405, 410, 421, 429, 500 to 504, with no body; in a route whose `match`
blocks forward, it is what the others get). A
redirect keeps the request's query unless TARGET has its own, and keeps
the connection open (it closes it when the request had a body, which
okena does not read). `rewrite path FROM/{*} -> TO` changes what the
backend is asked for when the (normalized) path starts with FROM: TO
with `{*}` = the rest, the request's query kept. `rewrite path ~REGEX -> TO`
does it when the regex matches the path, `$1` to `$9` in TO its groups.

**Regular expressions.** `route ~REGEX` matches the (normalized) path by a
regular expression: such routes are tried in the order written, after an exact
path and before any prefix (`/api/*`, `/*`), as nginx's `location ~` are; their
methods hold as for any route. `match path=~REGEX` and `match header:NAME=~REGEX`
(or `query:`, `cookie:`) do it in a match block. The syntax is PCRE's, a subset:
`.`, `[a-z]`, `[^/]`, `\d \w \s` and their capitals, `^ $`, `( )` (9 groups), `(?: )`,
`|`, `* + ? {n} {n,} {n,m}` (and lazy, with a `?` after), `(?i)` first for either
case. It is compiled at load into an automaton run in time linear in the path
(a Pike VM): no regex can make a worker backtrack (no ReDoS); one that does not
read is refused at load, with why. Quote one with braces, spaces or `;` in it
(`route "~^/a{2}$"`), and write `\\` for a `\` inside quotes.
`okena regex PATTERN TEXT...` shows what a pattern makes of each TEXT: the match
and its groups.

Header changes apply to what goes to the backend
(`header`) or back to the client (`response header`), in the order
written. Names are lower-case tokens and never one okena owns itself
(`host`, framing, `connection` and the other hop-by-hop fields,
`x-forwarded-*`, `forwarded`, `x-request-id`); values never contain CR,
LF or NUL, so a header change cannot inject one. A value may use
`${client.ip}` (the client, after `trusted_proxies`), `${request.id}`,
`${time.us}` and `${time.s}` (wall clock, microseconds or seconds since
the epoch): `header set x-request-start "t=${time.us}"`. Any other name
is an error at load.

Every limit, rate or count is for the whole instance (all workers
together), never per worker.

## Authentication

Today, on a route: `auth api_key header=x-api-key keys=FILE`, `auth basic
users=FILE realm=NAME` (both take `identity=NAME` and `forward=on`) and `auth jwt`.

```
auth jwt {
    jwks /etc/okena/jwks.json      # a JWK set, read at load and on a reload
    issuer https://auth.example.com
    audience api
    leeway 30s                     # the default
    claims sub -> x-user-id, scope -> x-user-scope
}
```

Or by URL, kept up to date by a process of its own, `okena-keys`:

```
jwks https://auth.example.com/.well-known/jwks.json trust=/etc/okena/idp-ca.pem refresh=10m stale=24h
```

`trust` is required with `https`: a PEM file whose first certificate is the
anchor. The chain up to it, the validity window and the host name in the URL are
always checked. `http://` is accepted for `localhost` and `127.0.0.x` only.
`refresh` (10 min by default) is how often it is fetched, and `stale` (24 h) how
long the keys hold after the last good fetch; past that they are dropped and
tokens are refused.

A failed fetch, a body that is not a set, or a set with no key usable here changes
nothing, and is retried within 30 s; a change of keys makes every worker forget
the tokens it verified, within a second. A reload keeps the keys of the URLs that stay. At start,
okena waits up to 3 s for the first keys, and until they come tokens get a 401. A
token with a `kid` not here asks for a fetch at once, 10 s apart at most. Sets with
the same URL and `trust` are one set, with the times of the first. Shared secrets
(`oct`) in a set by URL are left out: anyone who can read it could sign.

Limits: TLS 1.3 with AES-128-GCM towards the provider, one anchor, a response of
256 KB, 32 keys in a set, 64 sets. Redirects are not followed.

ES256, RS256, PS256, EdDSA and HS256. A bearer token must have `exp`; `issuer`
and `audience` are checked when given, and a route with no `issuer` takes
whoever holds a key. The algorithm must fit the key: an `oct` key needs its
`alg`, and 32 bytes at least; RSA 2048 bits at least. `alg: none` and a `crit`
header are refused, as is JSON a strict parser would not take: its grammar is
checked whole, UTF-8 included, and a name given twice or with an escape at the
top of the document is refused. A failure is 401 with
`WWW-Authenticate: Bearer`. A token is verified once and kept by each worker until
it expires. The claims named are told to the backend, in fields whose client
values are dropped, 256 bytes in all; a token that does not fit is refused, as is
one with a control byte in such a claim. The first one is also what `limit
key=jwt.sub` counts by.

`auth mtls` asks for what the listener's `client_ca` proved: the handshake comes
before any route, so the authority is the listener's, and a route with `auth mtls`
on a listener with none is refused at load. The backend is told the subject's
commonName, in `x-user-id` or `identity=`, up to 64 bytes; `limit key=auth.user`
counts by it, or by a hash of it past 20 bytes.

```
http :443 {
    tls {
        cert /etc/okena/server.pem
        key /etc/okena/server.key
        client_ca /etc/okena/clients.pem required    # or optional
    }
    route /admin/* { auth mtls identity=x-admin; to pool admin }
}
```

`required`, the default, refuses a connection with no good certificate in the
handshake, whatever the route. With `optional` a client may send none, and a
route with `auth mtls` answers 401. A certificate sent must be good in both cases.
Every certificate in the file is a CA the chain may reach (256 over all
listeners), the one whose subject is what the chain's last certificate names as
its issuer; only CAs signing, each link in date; an extended key usage, if there is one, must allow client
authentication; the commonName must be there, with no control byte.

TLS 1.2 clients are asked too (a CertificateRequest for ECDSA or RSA:
ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256 or rsa_pkcs1_sha256), with the same
checks. Its TLS 1.3 session tickets come after the client's
certificate is checked (the first record under the server's key), and carry who
the client is and which CAs the listener asks: a resumption is that client again,
with no certificate (a full handshake costs a chain and two signatures), and it
is taken only on a listener asking the same CAs; another listener's ticket, or
one with no one in it, is a full handshake there; TLS 1.2 tickets carry the same. A certificate revoked after
its ticket was issued still resumes until the ticket ends (one to two hours). Not on a `tcp` listener, and not with `http3`: it is
refused at load, because QUIC would be a way around it. A client's chain must fit
in 16 KB.

`client_ca FILE crl=FILE` checks revocation: FILE holds certificate revocation
lists (PEM `X509 CRL` blocks, or one list in DER), each signed by one of the
CAs (else refused at load). A chain with a certificate one of them lists,
among those that CA signed (a client, or an intermediate and so all of its
clients), is refused; a list past its nextUpdate refuses every client of its
CA until a fresh one is loaded (a reload), better shut than open. 65536
revoked certificates over all listeners; OCSP for clients is not asked.

`auth forward pool=NAME path=/verify copy=a,b timeout=2s cache=30s` has another
service decide. The request waits, and okena asks: GET on `path`, on that pool, so
its TLS, health checks and balancing apply, with the client's Cookie and
Authorization and `X-Forwarded-Method`, `X-Forwarded-Uri` and `X-Forwarded-Host`.

* A 2xx lets the request go on. The fields named in `copy` go to the backend, in
  place of whatever the client sent under those names; the first is what
  `limit key=auth.user` counts by. A field that does not fit in 256 bytes in all,
  or has a control byte, is a 503.
* A 3xx or 4xx is the client's answer, with its `Location`, `WWW-Authenticate` and
  first `Set-Cookie`, and no body.
* Anything else, no answer within `timeout`, or the pool down is 503: when who
  decides cannot be asked, nobody gets in.

`cache` keeps a 2xx in each worker, by method, host, target, Cookie and
Authorization together; a refusal is not kept, nor is a request with neither of
those two. A session revoked at the service goes on working for up to that long.
Limits and faults on the route run after it. At most 256 requests of a worker wait
at once, and past that they get a 503.

A keys file has lines `name:key`, a users file `name:SALT:SHA256HEX`, the hash
being of SALT and the password together, as in
`printf '%s%s' "$salt" "$password" | sha256sum`. Names are up to 20 bytes, and
lines starting with `#` are skipped. okena reads the file at load and keeps only
hashes; a reload reads it again.

Without a good credential the answer is 401 with `WWW-Authenticate`, and the
backend is not asked. With one, the backend gets who it is in `x-user-id` (or
`identity=`), and whatever the client sent under that name is dropped: it cannot
claim to be someone else. The credential itself is not passed on, unless
`forward=on`. `limit ... key=auth.user` gives each one their own limit.

Basic uses a salted SHA-256 and not bcrypt, which would stop a worker for tens of
milliseconds a try. It suits long random passwords, not ones people choose:
should that file leak, weak ones fall quickly.

```
policy authenticated {
    auth jwt {
        jwks https://auth.example.com/.well-known/jwks.json refresh=10m
        issuer https://auth.example.com
        audience api
        claims sub -> x-user-id, scope -> x-user-scope
    }
    limit 50/s key=jwt.sub
}

policy partners {
    auth api_key header=x-api-key keys=${file:/etc/okena/partner-keys}
}

policy admin {
    auth mtls
    allow 10.0.0.0/8
}

policy sso {
    auth forward pool=sso path=/verify copy=x-user-id,x-user-role cache=30s
}
```

## Pools

```
pool api {
    server 10.0.1.10:8080 weight=2
    server 10.0.1.11:8080
    server 10.0.1.12:8080 backup
    server unix:/run/api.sock
    discover dns api.service.internal port=8080 refresh=ttl

    balance least-request          # the default; or peak-ewma | round-robin | least-conn | random
                                   # | maglev key=K | ring-hash key=K | source-hash
    protocol h2                    # http1 (default) | h2 | h2c | grpc
    tls {                          # TLS to the backends (needs the kernel tls module)
        trust /etc/okena/internal-ca.pem   # the first certificate is the anchor; the chain is
                                           # verified: only a CA signs, and each link in date
        sni api.internal                   # SNI + the name checked against the certificate
        cert /etc/okena/edge.pem           # what okena shows a backend that asks for a
        key /etc/okena/edge.key            # certificate (authenticated origin pulls)
    }

    connect timeout=1s warm=4 max=512 idle=55s rate=200/s
    source 10.0.0.2 10.0.0.3       # more source addresses, more ports
    concurrency adaptive           # or: concurrency 256
    retry_budget 20% min=10/s

    health http GET /healthz every=2s timeout=500ms expect=200..299 host=api.internal
                                   # or: health tcp (connect only); expect defaults
                                   # to 200..399, host to the server as written
                                   # or: health grpc [SERVICE] every=2s host=...
                                   #     (grpc.health.v1.Health/Check over HTTP/2
                                   #     by prior knowledge; passes on SERVING)
    outlier errors=5 eject=30s max_ejected=50%
    slow_start 30s
}
```

`cert` and `key` in a pool's `tls` block are the certificate okena shows a backend
that asks for one, so that an origin can let in its CDN's edges and no one else:
authenticated origin pulls, from okena's side. The key may be EC P-256, RSA or
Ed25519, and the chain goes as the file has it. A backend that asks for a
certificate when the pool has none gets an empty one: one that only asks serves the
request anonymously, one that requires it refuses, and the client gets a 502. Client
certificates are TLS 1.3; a TLS 1.2 backend that asks for one is refused (502).

`maglev` and `ring-hash` send a key to one server: the same one in every worker,
after a reload, and on every okena with the same servers, which is what a cache, a
shard or a session kept in memory wants. The key is `key=source` (the client's
address, the default; for `http` the one trusted proxies give), `header:NAME`,
`cookie:NAME`, `query:NAME` (a parameter), `path` (without the query) or `url` (the host and the whole
target: a cache's key, for shields); `source-hash` is `maglev` on the
client's address, which is all a `tcp` or `udp` listener can hash on. A request
without its key is drawn at random, as is a retry. `maglev` shares out evenly and
looks up in one step; `ring-hash` (160 points per unit of weight) moves the fewest
keys. Taking one of six servers out of the file moved its own keys and, of the
others, 0.1% with maglev and none with ring-hash. A server that is down, drained
or ejected keeps its place: its keys go to others, the same others everywhere,
and no other key moves. They take the weights in the file, not `okena backend
weight`, and an address a name resolves to anew is taken in within a second.

`bound=125%` (101% to 1000%) bounds the load (Mirrokni et al., 2017; HAProxy's
`hash-balance-factor`): a server takes a key while its connections in use are
under that share of the pool's mean, counted in each worker; past it the key
goes to the next server the key itself gives, the same everywhere. A hot key
spills only as far as it must and comes back when the load falls; every other
key stays. Forty requests at once on one key went to three of four servers, at
most fifteen on one, where without a bound they all went to one.

`sticky cookie=NAME [ttl=1h] [samesite=lax|strict|none]` keeps an http client on
the server it got, by a cookie that names it: 16 hex digits of a hash of its
address, the same on every worker and every okena, with no secret to share (as
with nginx's and HAProxy's, one who has it can find the address by trying them).
A cookie that names a server of the pool that is up wins over `balance`, also
while the server is drained, which is what a drain is for: the sessions there
end there, new clients go elsewhere. A server down or ejected, a retry, a cookie
that names nothing: the balance picks and the answer sets the cookie, with
Path=/, HttpOnly, SameSite (Lax unless told), Max-Age for a ttl, and Secure on
a TLS listener or with SameSite=None. okena's own answers (errors, cache hits,
files) set none. A WebSocket upgrade follows the cookie too. A `tcp` or `udp`
listener has no cookies: `source-hash` keeps those clients in place.

`server ADDR max=N` gives a server no more than N connections in use at once,
for the whole instance; each address of a name has its own. A full server is not
chosen, not even when all else is down. With every server full an http request
waits its turn (first in, first out in each worker) for `queue timeout=` (the
pool's connect timeout unless told), then gets a 503; one that leaves a server
lets the first waiting one go at once, and places freed in another worker are
seen within a millisecond. A `tcp` connection does not wait: it is closed.
Workers count in a table they share, each in its own row, and a place is taken
before the count is read (a locked add), so two workers racing for the last
place cannot both have it. A worker that is replaced gives its places back. A
reload's draining connections are not counted by the new workers, so during a
drain a server can have more. `balance first` takes the servers in the file's
order, each up to its max, so that the last ones can be stopped while traffic
is low; idle connections kept for reuse do not count.

## Sites, caching and the edge

`php DIR` runs a PHP site through PHP-FPM, as nginx's and Caddy's usual
configurations do; its pool speaks FastCGI:

```
pool fpm { server unix:/run/php-fpm/www.sock; protocol fastcgi }
http :443 {
    tls { auto }
    host example.com { route /* { php /srv/www; to pool fpm } }
}
```

The script is found beneath DIR (opened as `files` opens, so nothing outside it
is reached): a path with a segment ending in `.php` is that script, and what
follows it `PATH_INFO` (`/blog/index.php/2026/11`); a directory is its index
(`index=`, `index.php` by default), and one asked for without its slash is
redirected to it; any other file that is there is served as `files` serves it,
never handed to PHP (so `/uploads/x.php.jpg` is an image); anything else goes to
DIR's index, the front controller of Laravel, Symfony or WordPress, with the
request's own `REQUEST_URI`. Only names ending in `.php` reach PHP.

PHP gets the CGI params from the request okena would send (its header changes,
X-Forwarded-For, the request id): `SCRIPT_FILENAME`, `SCRIPT_NAME`,
`DOCUMENT_ROOT`, `PATH_INFO`, `REQUEST_METHOD`, `REQUEST_URI`, `QUERY_STRING`,
`CONTENT_TYPE`, `CONTENT_LENGTH`, `REMOTE_ADDR` (the client), `SERVER_NAME`,
`SERVER_PORT`, `HTTPS`, and each field as `HTTP_*` (never `HTTP_PROXY`). Its
answer's CGI head becomes a status line (`Status:`, a `Location:` alone is 302),
its body chunks, its STDERR the log's (`fastcgi: ...`). The connection to FPM is
kept and pooled. A request body needs a length (a chunked one: 411). A pool
with `protocol fastcgi` serves any FastCGI responder: without `php`,
`SCRIPT_NAME` is the path. Health checks for it: `health tcp`.

`files DIR` answers a route from a directory, by the request's whole path:
`route /assets/* { files /srv/site }` serves `/srv/site/assets/...`.

| Option | Meaning |
|---|---|
| `index=NAME` | what a directory answers with, `index.html` by default; a directory with no slash is redirected to one with it |
| `fallback=/PATH` | what answers instead of a 404: `/index.html` for a single-page app |
| `precompressed=br,zst,gz` | a `.br`, `.zst` or `.gz` next to the file, if the client takes it, in that order; the answer then varies on Accept-Encoding, with its own ETag, and has no ranges |
| `cache=T` or `cache=immutable` | `Cache-Control: public, max-age=...` |

`early_hints /a.css /b.js` on a route sends a 103 for GET requests as soon as the
request is on its way to the backend, with `rel=preload` and an `as=` by the
extension. A backend's own 103 goes through too. HTTP/1.0 clients get none.

`headers preset=secure` sets `Strict-Transport-Security`, `X-Content-Type-Options`,
`X-Frame-Options` and `Referrer-Policy` on what goes through a route, over what the
backend said. A route's own `response header` of the same name stands. okena's own
answers (401, 429, 502...) do not carry them.

`compress gzip min=1KiB`, on a listener, a host block or a route (`compress off`
there undoes it), compresses answers on the way out: 200s of text, JSON, JavaScript,
XML or SVG, from `min` up (256 B by default; an answer of unknown length always) to
clients that say they take gzip. Not what is encoded already, `no-transform`, HEAD or
HTTP/1.0. The answer loses its `ETag` and `Accept-Ranges`, and goes chunked. The cache
keeps the original and compresses for each client.

`compress br gzip` adds Brotli: of the two, the first written that the client takes
(`Accept-Encoding`, `q=0` meaning no); `compress br` alone, or `compress gzip br` to
prefer gzip. Each piece of the answer is a Brotli meta-block with Huffman codes made
for it, then brought to a whole byte: what went out decodes at once, so a stream
(server-sent events, a slow page) is not held back. A piece that would not get
smaller goes stored.

They are built for speed: about 100 MiB/s on one core each. gzip is DEFLATE with fixed
codes, for text about 0.7 of what `gzip -1` achieves; Brotli, on the same matcher with
codes of its own, about 0.93 of `brotli -q1` and a quarter smaller than that gzip. A
worker is held for some 150 µs for each 16 KiB, which counts for a site made of large
dynamic pages. A worker has 64 of these going at once, past that answers go as they
are. zstd is refused at load: there is none yet.

Compressing an answer that holds both a secret and something the client chose can
leak the secret to someone who sees its length (BREACH): keep those routes out of it.

GET and HEAD, with `ETag`, `Last-Modified`, `If-None-Match`, `If-Modified-Since`,
`If-Range` and one byte range; several ranges in a request get the whole file. A name
that begins with a dot is not served, but for `.well-known`. Only regular files are
served.

A link may lead anywhere inside the directory, and nowhere outside it. That is the
kernel's doing (`openat2`, `RESOLVE_BENEATH`), and on top of it each worker confines
itself with Landlock to reading those directories: it could not read a private key
even with a bug in okena. Where the kernel has no Landlock okena says so at the
start. Workers with no `files` route cannot open a file at all.

With io_uring a slow disk does not hold up the worker's other connections, but opening
a file is still done in place; with epoll, reading too.

```
http :443 {
    tls { auto }
    canonical example.com              # www -> apex, 301
    headers preset=secure              # HSTS, nosniff, frame and referrer policy; on a
                                       # listener, a host or a route; preset=none undoes it
    compress gzip min=1KiB

    route /assets/* {
        files /srv/site precompressed=br,zst,gz cache=immutable
    }
    route /api/* {
        idempotency header=idempotency-key ttl=24h
        hold 10s                       # wait for a pool that is restarting
        to pool api
    }
    route /webhooks/* {
        allow file:/etc/okena/webhook-sources.list
        to pool api
    }
    route /* {
        files /srv/site fallback=/index.html   # SPA: client-side routes
        early_hints /assets/app.css /assets/app.js
    }
}

http :443 {
    tls { cert /etc/okena/cdn.pem }
    trusted_proxies cloudflare         # its published ranges
    cache disk=/var/cache/okena size=200GiB memory=2GiB {
        key host path query=v,lang
        stale_if_error 1h
        slice 4MiB
    }
    signed_urls key=/etc/okena/url.key
    to pool shield
}

http :443 {
    tls { auto }
    auth oidc issuer=https://accounts.google.com client=${env:OIDC_ID} secret=${env:OIDC_SECRET} allow_domain=example.com
    to grafana:3000
}
```

## Addons and alerts

```
addon waf {
    run /usr/local/bin/coraza-okena
    phases request_headers request_body
    timeout 2ms on_error=allow
}

alerts {
    telegram token=${env:TG_TOKEN} chat=${env:TG_CHAT}
    webhook https://hooks.example.com/okena
    on backend reload certificate
}
```

## Discovery and backends from the outside

```
pool users {
    server users:8080                        # a name: resolved, re-resolved by TTL
    discover file /etc/okena/users.list      # one address per line, watched
    discover srv _users._tcp.service.consul
    discover docker label=okena.pool=users port=8080
    discover kubernetes service=shop/users port=http
    discover consul service=users tag=v2
}
```

`discover file PATH [port=N] [max=64]` takes a pool's servers from a file, one
`ADDRESS[:PORT] [weight=N]` a line (`#` starts a comment; `port=` for lines
without one), so anything that can write a file can place backends:
consul-template, a script, a CI job. It may stand beside `server` lines, or alone.
The control process looks at the file once a second (a stat: nothing more when it
did not change), and workers have what it read within another: a line added is
served within two seconds. An address that stays keeps its slot, its health and
its connections whatever the order of the lines; one taken out has its idle
connections closed; a weight changes in place. Up to `max` servers (1 to 256),
the first lines. A file that cannot be read, or has a line that is not an
address, changes nothing: the servers known go on, and it is said once. One that
turns up empty after having servers is believed once it has stayed empty for
three seconds, as an editor may truncate before it writes; writing a new file and
renaming it over the old one never shows half a file. The supervisor reads it
before the workers start. `okena backend drain POOL PATH` drains all of them.

`discover srv NAME [max=64]` takes them from DNS SRV records (RFC 2782), as
Consul and Kubernetes headless services give them: each record's target is
resolved (A and AAAA, /etc/hosts first) and each address served on the record's
port, with its weight (0 is the least, not none). The lowest priority are the
servers; those of higher ones are backups, used only when none of those is up.
NAME is a full name, not completed with search domains. It is looked up again
when the shortest TTL runs out (1 to 60 s), with EDNS0 so that answers past 512
bytes come whole. A lookup that fails, or gives nothing that resolves, keeps the
servers known so far and is said once: DNS going away never empties a pool.

`discover docker label=KEY[=VALUE] [port=N] [network=NAME]
[socket=/var/run/docker.sock] [max=64]` takes them from the running containers
that have the label, as Docker's Engine API lists them, asked once a second
over its unix socket. A container is served at its address on `network` (or its
first network), on the port of its `okena.port` label, else `port=`, else the one
TCP port it exposes; `okena.weight` gives a weight. One with a health check is
served only while it is healthy, so traffic waits for it to start. One that
cannot be placed (no address, more than one port and no `okena.port`) is left
out (`okena backend list` shows what is served); the others are served. Docker not answering, or answering what
cannot be read, changes nothing; an empty list is believed. In Compose:

```
services:
  okena:
    volumes: ["/var/run/docker.sock:/var/run/docker.sock:ro"]
  api:
    labels: { okena.pool: api, okena.port: "8080" }
```

The socket is root on the host to whoever can write to it. okena only reads it,
but a read-only proxy (Tecnativa's docker-socket-proxy with `CONTAINERS=1`, and
`socket=` pointed at it) gives okena no more than it needs.

`discover kubernetes service=NAMESPACE/NAME [port=NAME|N] [api=HOST:PORT]
[token=PATH] [ca=PATH] [name=HOST] [max=64]` takes them from the Service's
EndpointSlices, asked of the API server once a second over TLS 1.3 that okena
verifies (the chain to `ca`, each certificate in date, the name `name`), with
the service account's token, read again each time as it is rotated, and with
resourceVersion=0 so that the API server answers from its cache. Inside a pod
the defaults are all it needs: the API at KUBERNETES_SERVICE_HOST and _PORT,
the token and ca.crt of the service account, the name kubernetes.default.svc;
EC and RSA certificates both verify. An endpoint is served while it is ready;
when none is, those that still serve while they terminate are, as kube-proxy
does, so that a rollout never leaves the pool empty. Its port is the slice's
port of that name, or the number given, or the slice's only port. An API
server that does not answer, refuses (403: the service account needs `get` and
`list` on `endpointslices` in the namespace) or is not the one it should be
changes nothing, and is said once.

`discover consul service=NAME [dc=DC] [tag=TAG] [token=PATH] [api=HOST:PORT]
[port=N] [max=64]` takes them from Consul's catalog, as the agent's HTTP API
gives a service's instances whose health checks pass
(`/v1/health/service/NAME?passing=1`), asked once a second: Consul's own checks
decide, and an instance that fails them is out within two seconds. Each is
served at its service address, or its node's when it registered none, on the
port it registered (`port=` for one that registered none), with its weight for
passing checks; IPv4 and IPv6 alike, while one whose address is a name is left
out. `dc=` asks another datacenter, `tag=` only the instances with that tag.
`token=` is a file holding the ACL token (it needs `service:read` on the service
and `node:read`), read again each time as it is rotated. The API is the local
agent's, plain HTTP, at 127.0.0.1:8500 unless `api=` says otherwise (an address,
not a name). An agent that does not answer, answers what cannot be read, or
refuses (a 403 is said as the token's) changes nothing, and is said once; an
empty list is believed. `discover srv NAME.service.consul` gives the same from
Consul's DNS, without weights.

## The Kubernetes Gateway API

```
okena {
    gateway kubernetes dir=/var/lib/okena/gateway     # class=okena unless said
}
http :8081 { route /healthz { respond 404 } }          # (what is not the cluster's)
include "/var/lib/okena/gateway/*.conf"
```

`gateway kubernetes dir=DIR [class=NAME] [api=HOST:PORT] [token=PATH] [ca=PATH]
[name=HOST]` makes okena the implementation of the Gateway API for the Gateways
whose `gatewayClassName` is NAME (okena). A process of its own reads the
Gateways and the HTTPRoutes once a second from the API server, over the same
verified TLS and with the same credentials as `discover kubernetes` (inside a
pod the defaults are all it needs), and writes them as okena's configuration in
DIR/gateway.conf. When that changes, okena reloads: what it serves is always a
configuration `okena check` passes, and one that does not pass is refused
whole, the running one kept (and asked for again every 5 s for a minute: a
port okena just stopped listening on is let go only when the workers draining
it are gone). The main file takes it in with `include`. The GatewayClass, when
there is one of that name, must have `controllerName: okena.dev/gateway-controller`;
one of another controller's is not served. The service account needs `list` on
gateways, httproutes, grpcroutes, tlsroutes, tcproutes and referencegrants, `get` on gatewayclasses, services and secrets, `patch`
on gatewayclasses/status, gateways/status and httproutes/status, and what
`discover kubernetes` needs.

What it reads, and becomes:

* A listener (HTTP or HTTPS, its port, maybe its hostname) is an `http :PORT`
  block. An HTTPS listener's certificateRefs, Secrets of its namespace, are
  written to DIR/certs (0600) and are the block's `tls` certificates; a
  certificate renewed is served within two seconds. `allowedRoutes` from
  `Same` (the default) or `All`.
* An HTTPRoute attaches to the listeners its parentRefs name (a sectionName or a
  port narrows it), for the hostnames both allow, each one a `host` block. The
  routes of no hostname, and of a wildcard that covers a host, are under each
  host too, after its own.
* A match's path: Exact is that route; PathPrefix /p is the routes /p and /p/*;
  RegularExpression is `route "~^(?:R)$"` (the whole path, okena's engine:
  linear time; one it cannot read is left out, not the file). Its headers (a
  RegularExpression one too), method and queryParams are a `match` block.
* A GRPCRoute is the same on the path gRPC asks for: a method's service and
  name are /S/M; a service alone, every method of it; a name alone, or a
  RegularExpression, a regular expression. Its backends' pools speak HTTP/2
  (`protocol h2`), and every listener takes HTTP/2 (`http2 on`). In a route the more
  precise come first, as the Gateway API orders them; one that cannot be chosen
  is left out, and a path with nothing for the rest answers 404.
* Filters: RequestHeaderModifier and ResponseHeaderModifier (`header`, `response
  header`; a header okena writes itself, Host among them, is left alone),
  RequestRedirect (`redirect`, to the request's host when it names none),
  URLRewrite's path (`rewrite path`), RequestMirror (`mirror`). Any other filter
  makes the rule answer 500.
* A TLS listener (Passthrough) is a `tcp` block with `tls passthrough`: a TLSRoute's
  hostnames its `sni` lines, one of none its `default`, the rest refused; a TCP
  listener a `tcp` block to its TCPRoute's backend. The first route that names
  a hostname has it, the first backend okena can serve is the one (weights
  are for HTTP).
* backendRefs, Services of the route's own namespace or of one whose
  ReferenceGrant lets the route's kind and namespace refer to it, are pools
  that follow their EndpointSlices, the Service's port found by its name;
  several, by weight (`split`). None to be had, a Service or a port that is not
  there, another namespace's with no grant: 500. A listener's Secret of another
  namespace needs a ReferenceGrant there too (from Gateway, to Secret).

Status is written back, as merge patches of the status subresources and only
when it changed (DIR/status.state remembers what was written): the GatewayClass
Accepted; a Gateway Accepted and Programmed (not when okena refused what was
written for it), each listener with its attachedRoutes, Accepted (or
UnsupportedProtocol, Invalid), ResolvedRefs (or InvalidCertificateRef) and
Programmed; an HTTPRoute, for each parentRef naming one of these Gateways,
Accepted (or NoMatchingParent, NotAllowedByListeners,
NoMatchingListenerHostname) and ResolvedRefs (or BackendNotFound,
RefNotPermitted, InvalidKind), what other controllers wrote in it kept.

Not there yet: regular expressions in query parameters, URLRewrite's hostname,
a backendRef's own filters, UDPRoute, and weights between backends of a
TLSRoute or TCPRoute. A regular expression path is
tried after an exact path and before a prefix, as okena's own are (the Gateway
API leaves its place to the implementation).

Everything a route's author writes reaches the file only as what it is: names
and paths are checked for what they may be made of, values are quoted and
escaped, a value with `${` in it is left out (it could otherwise read okena's
environment or files), and what cannot be told is left out, not guessed. The API
server not answering, refusing or answering what cannot be read changes nothing,
and is said once.

The admin API changes the running state without editing files, given
`admin unix:PATH` in the `okena` block:

```
okena backend list                         # pool, server, weight, active, up|drain|down
okena backend drain api 10.0.1.10:8080     # no new connection; those it has go on
okena backend up api 10.0.1.10:8080        # takes the drain back
okena backend weight api 10.0.1.11:8080 3  # 1..65535, 0 for the weight in the file
okena reload                               # and says how it went; 1 when it did not take
okena drain [wait]                         # the instance out of rotation
okena resume                               # and back
okena maintenance [on|off [ROUTE]]         # 503 and the maintenance page (### Maintenance)
```

`okena drain` takes the whole instance out of a fleet's rotation without cutting
anything: `/ready` answers 503, so the balancer in front stops sending, and
HTTP/1 connections close after the answer they carry, so that their clients
come back through it to another instance. Requests in flight finish, and new
connections are still served for as long as the balancer takes to notice.
`okena drain wait` returns once nothing is left open (60 s at most), the moment
to stop or upgrade it; `okena resume` puts it back. A reload keeps a drain; a
restart or an upgrade starts in rotation. HTTP/2 and HTTP/3 connections are told
to go with a GOAWAY (NO_ERROR, the last stream taken), on the next tick: what
they have in flight finishes, a stream a client opens after it is refused
(REFUSED_STREAM, which a client may send again elsewhere), and each connection
closes once nothing is left on it. A shutdown or a reload does the same once its
workers stop accepting, so idle HTTP/2 connections no longer hold it for its
drain timeout.

Each takes `-c FILE` to find the socket. A server is named as in the file, so a name
means all its addresses. A drained server is not chosen even when every other is down:
with none left a request gets a 502. A reload keeps drains and weights, by pool and
server, and forgets those of a server that left the file; an upgrade or a restart starts
from the file. The socket is the owner's only, by mode and by a look at the caller. It
is opened when okena starts, so adding or moving `admin` takes a restart.

## Alerts

```
alerts {
    webhook https://hooks.example.com/okena       # POST of JSON
    slack https://hooks.slack.com/services/T/B/X  # an incoming webhook
    telegram token=123:ABC chat=-100123            # the Bot API's sendMessage
    on backend reload worker discovery certificate # the default: all of them
    every 10s                                      # a message a window, at most
    name edge-1                                    # the default: the host's name
}
```

What goes wrong, and what comes back, told to people: a backend ejected or
back (passively or by health checks), a worker restarted, a reload refused,
discovery that cannot be done, a certificate near its end (`certificate`: one
from a file or the ACME CA with less than 14 days left, or past it; looked at
each hour, told once a day; ACME's are renewed at two thirds of their life, so
this is one that has failed for weeks). Any process of okena puts such a line in a ring
of shared memory as it logs it, with no lock, and the control process sends
what came over each `every` window: the same line from several workers (each
ejects a backend on its own) once, with how many times, at most 32 lines a
message and the count of the rest. A webhook gets
`{"source":"okena","name":...,"events":[{"kind":...,"text":...,"count":N}],"more":N}`;
Slack and Telegram a text. A send that fails keeps what it had for the next
window and is said once in the log; an alert never makes another. HTTPS is
verified against the system's roots (SSL_CERT_FILE when set, else the usual
bundles), or `trust=FILE`'s first certificate; `http://` is for a private
network. Up to 8 targets; Telegram's `api=URL` points it elsewhere.

## Tooling

```
okena check okena.conf             # validate; non-zero exit on error
okena check --diff                 # what a reload would change
okena fmt -w okena.conf            # canonical formatting
okena explain                      # effective config, defaults included
okena route 'GET https://api.example.com/v1/users/42 x-canary:yes'
okena top                          # live per-route/backend view
okena bench https://localhost/v1/ rate=200k duration=60s
okena health                       # exit 0 when ready (Docker HEALTHCHECK)
okena check --host                 # kernel features, limits, sysctls, container
okena certs                        # the certificates served, their expiry, ACME's state
okena cert selfsigned DIR a.test b.test days=30   # DIR/key.pem, DIR/cert.pem
okena cert csr DIR a.example.com   # DIR/key.pem, DIR/csr.pem, for a CA to sign
okena sign KEYFILE /path 1h        # a signed link (signed_urls)
okena ranges cloudflare            # a provider's ranges, as built in
okena purge url|prefix|tag VALUE   # take cached answers back (and on the fleet)
```

`okena certs` lists what a configuration serves, a line each: the names, the
issuer (`itself` when self-signed), the notAfter (UTC) and the days left, and where
it comes from: a file, ACME (with what the acme process last did and when it
renews or tries again: it keeps that in DIR/NAME/status), one signed here until
the CA's comes, or on demand.

`okena cert` makes ECDSA P-256 keys (SEC1, mode 0600) and either a certificate that
signs itself, for a test or a development name, or a request (CSR) for a CA. The
names go in the subjectAltName, and the first is the CN as well. It is the same
code that answers ACME.

`okena bench URL [key=value...]` is an open-loop load generator (http://,
https:// over TLS 1.3 and kTLS, tcp:// and udp:// for echo). Options: `rate=N`
(requests/s in all, `k` and `M` allowed; without it the run is closed
loop), `conns=64`, `duration=10s`, `warmup=1s`, `workers=1` (processes),
`method=GET`, `header='Name: value'` (repeatable), `body=TEXT`,
`size=64` (tcp), `sni=NAME`, `new=on` (a new connection, and TLS
handshake, for every request), `proto=h1|h2` (HTTP/2: prior knowledge on
http://, ALPN h2 on https://, one stream at a time a connection),
`format=text|kv`. It reports p50 to p99.99
and the maximum three ways: `latency` from the time the schedule asked
for each request (corrected for coordinated omission), `service` from the
actual send, and `sender`, how late the generator itself was. Requests the
schedule asked for that never went out are reported as `behind`.

`okena upgrade -c FILE`, with `okena { upgrade /run/okena/upgrade.sock }` in the
configuration of both, puts a new binary in place with no connection refused or lost. It
compiles its configuration, takes the listening sockets from the running okena, starts
its workers, and only then tells the old one, which finishes what it has, within its
drain timeout, and exits. Until then the old one has lost nothing: if the new one cannot
start it goes on. The socket is the owner's only, by mode and by a look at the caller.
What is reused goes by the address as written; a listener the new configuration no
longer has closes. HTTP/3 connections do not survive it, as QUIC sockets are opened anew.
The new okena is a new process in the foreground of whoever started it; under
systemd the old one tells it `MAINPID=` of the new as it leaves (the unit needs
`NotifyAccess=all` for the new one's `READY=1`).

### systemd

okena speaks systemd's protocols with no library (contrib/systemd has a unit and a
socket unit):

* **Notify** (`Type=notify-reload`): `READY=1` once the workers serve, with
  `MAINPID`; `RELOADING=1` (with `MONOTONIC_USEC`) and then `READY=1` around each
  reload, whether it took or not; `STOPPING=1` when it stops; `WATCHDOG=1` once a
  second while `WatchdogSec=` asks, from the supervisor, so a supervisor that hangs
  is restarted.
* **Socket activation**: the sockets of a `.socket` unit, passed on fds from 3
  (`LISTEN_FDS`, for this process: `LISTEN_PID`), are taken by the listeners with
  the same address and kind: `ListenStream` for `tcp` and `http`, `ListenDatagram`
  for `udp`, and `:443` in okena.conf takes a socket on any address of that port.
  Every worker accepts from systemd's socket (each holds a dup of it, and a reload
  that adds workers dups it again), so the unit wants `ReusePort=no`. A socket no
  listener takes is closed and said; a listener none is there for opens its own.
  QUIC's sockets are okena's. With systemd holding the sockets, a restart refuses
  no connection: the new okena takes them, the old one drains what it has.


`okena route 'GET https://api.example.com/v1/users/42 x-canary:yes' [-c FILE]` answers
"where does this request go", without starting anything: listener, route, the `match`
block that fits, filters, and the pool with its servers, or the redirect or the
directory. It goes through the code that routes real requests. There is no client, so
a `client.ip` condition counts as not met, and it says so. Which server of a pool, or
which side of a split, depends on the moment, and it does not say.

## Docker Compose

```yaml
services:
  okena:
    image: okena
    network_mode: host             # no docker-proxy in the path
    cpuset: "0-3"                  # pinned cores, no CFS throttling
    security_opt:
      - seccomp=docker/okena.seccomp.json  # enables the io_uring engine
    volumes:
      - ./okena.conf:/etc/okena/okena.conf:ro
    environment:
      JWT_AUDIENCE: api
    stop_grace_period: 10s
```

With host networking the sysctls are the host's (`okena check --host`
lists them). Without it, publish ports with the daemon's `userland-proxy`
disabled and set the per-namespace ones on the service:

```yaml
    sysctls:
      net.core.somaxconn: 65535
      net.ipv4.ip_local_port_range: "1024 65535"
      net.ipv4.tcp_tw_reuse: 1
```
 Without the seccomp profile okena still runs,
on the epoll engine, and says so at startup.
