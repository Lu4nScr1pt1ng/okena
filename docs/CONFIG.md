# Configuration

This file describes the whole language, including what is designed but
not built yet. A directive that is not built is refused by `okena check`
("not supported by this version of okena yet"), never ignored.

## Built today

| Block | Directives |
|---|---|
| `okena` | `workers`, `io_engine`, `busy_poll`, `watchdog`, `drain delay= timeout=`, `metrics`, `ticket_keys`, `handshake_budget wait=`, `quic_server_id HEX` |
| `tcp ADDR...` | `to`, `limits { connections; per_source }`, `timeout { idle }`, `proxy_protocol send v1\|v2`, `tls { cert; key }`, `tls passthrough { sni NAME... to pool P; default reject\|to pool P }` |
| `udp ADDR...` | `to`, `responses N`, `limits { connections }` (flows), `timeout { idle }` |
| `http ADDR...` | `host`, `route`, `limits`, `timeout { idle; header; body_idle; response }`, `trusted_proxies`, `access_log`, `http2 on\|off`, `http3 on\|off\|retry\|v2`, `preferred_address`, `early_data on\|off`, `tls { cert; key; ktls on\|off }` |
| `route PATH... [METHOD...]` | `to`, `redirect`, `rewrite path`, `header set\|add\|drop`, `response header set\|add\|drop` |
| `pool NAME` | `server ADDR [weight=N] [max=N] [backup]`, `queue timeout=`, `balance least-request\|peak-ewma\|round-robin\|least-conn\|random\|maglev\|ring-hash\|source-hash [key=]\|first`, `sticky cookie= [ttl=] [samesite=]`, `connect timeout=`, `health tcp\|http\|grpc ...`, `slow_start`, `tls { trust FILE; sni NAME }` (TLS to the backends), `protocol h1\|h2` |

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

`okena { ticket_keys FILE }` takes the keys from a file every instance
reads: one a line, 32 bytes of base64 (`openssl rand -base64 32`), the
first sealing new tickets, an optional second (the previous) still
opening them. Rotating is then a new first line and a reload (SIGHUP) on
each instance; okena does not rotate them itself. The header timeout covers
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
http :443 {
    tls { cert auto }               # ACME for the hosts below
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
    metrics :9464             # /metrics, /live, /ready
    admin unix:/run/okena/admin.sock  # `okena reload`, `okena backend`
    handshake_budget 100us wait=1s  # TLS hello crypto per loop iteration (0us: off);
                              # past it hellos queue, and those older than wait close
    # planned:
    profile balanced          # balanced | latency | throughput | memory-lean
    reload on-change          # watch the config directory (today: SIGHUP, `okena reload`)
    acme email=ops@example.com
}
```

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
    cert auto                       # ACME; or a file, or one per host
    versions 1.2 1.3
    alpn h2 http/1.1
    client_ca /etc/okena/clients.pem required
}
tls passthrough {                   # tcp only: route on SNI, never decrypt
    sni api.example.com to pool api-tls
    default reject
}
```

The application layer (http) adds its own limits and timeouts:

```
limits { header_size 32KiB; body_size 10MiB; h2_streams 128 }
timeout { header 10s; body_idle 30s; response 30s }
trusted_proxies 10.0.0.0/8          # believe X-Forwarded-For from these
access_log /var/log/okena/access.log   # or stdout, stderr, off (default)
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

Access logs are one JSON line per exchange: `time` (UTC, ms), `listener`,
`client`, `peer` (the TCP peer), `method`, `host`, `target`, `status`, `bytes` (sent to the
client), `duration_ms` (from the request head to the end of the
response), `upstream`, `source` (`backend`, or `okena` when okena answered
itself) and `retried`. Workers never write files: they pass lines to a
logger process through a pipe and drop them (counted in
`okena_access_log_dropped_total`) rather than wait when it falls behind.
Lines of different workers may be up to a second out of order. A reload
or `SIGUSR1` makes the logger reopen its files, so logrotate needs only
`kill -USR1`.

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
    tls { cert auto }
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

| Option | Meaning |
|---|---|
| the time | how long an answer is good, unless the backend's `s-maxage` or `max-age` says otherwise |
| `stale-while-revalidate=T` | past that, serve it at once for T while it is fetched again; `must-revalidate` takes this away |
| `vary=a,b` | up to 4 request fields that are part of the key, with host and target |
| `max=SIZE` | the largest answer kept, 1 MiB by default |
| `shared=on` | the answer is the same for everyone: see below |

Kept: GET answers of 200, 301, 308, 404 and 410 with a length or chunked. HEAD reads
them. Not kept: `Cache-Control` no-store, private or no-cache, `Set-Cookie`, `Vary`
naming a field not in `vary=`, or a body with no length, as a cut would look like
its end. A request's `Range`, or a body, goes to the backend; a conditional one reads
what is kept and gets a 200, and on a miss is not kept. A client's own `Cache-Control`
is not obeyed.

Unless `shared=on`, a request with Cookie or Authorization, or on a route with `auth`,
neither reads nor fills: an answer for one person must not reach another. A hit says
`Age` and `Cache-Status: okena; hit; ttl=N`, negative when stale, and runs behind
what the route has for clients: auth, limits, CORS and `response` rules.

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

A route either forwards (`to`) or redirects (`redirect CODE TARGET`, with
301, 302, 303, 307 or 308; TARGET a path or an `http(s)://` URL). A
redirect keeps the request's query unless TARGET has its own, and keeps
the connection open (it closes it when the request had a body, which
okena does not read). `rewrite path FROM/{*} -> TO` changes what the
backend is asked for when the (normalized) path starts with FROM: TO
with `{*}` = the rest, the request's query kept. Header changes apply to what goes to the backend
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
256 KB, 32 keys in a set, 8 sets. Redirects are not followed.

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
The chain must reach the first certificate in the file, with only CAs signing and
each link in date; an extended key usage, if there is one, must allow client
authentication; the commonName must be there, with no control byte.

On such a listener: TLS 1.3 only, no tickets, in either direction: a resumed session
has no certificate to look at. Not on a `tcp` listener, and not with `http3`: it is
refused at load, because QUIC would be a way around it. A client's chain must fit
in 16 KB. Revocation (CRL, OCSP) is not checked.

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

`maglev` and `ring-hash` send a key to one server: the same one in every worker,
after a reload, and on every okena with the same servers, which is what a cache, a
shard or a session kept in memory wants. The key is `key=source` (the client's
address, the default; for `http` the one trusted proxies give), `header:NAME`,
`cookie:NAME` or `path` (without the query); `source-hash` is `maglev` on the
client's address, which is all a `tcp` or `udp` listener can hash on. A request
without its key is drawn at random, as is a retry. `maglev` shares out evenly and
looks up in one step; `ring-hash` (160 points per unit of weight) moves the fewest
keys. Taking one of six servers out of the file moved its own keys and, of the
others, 0.1% with maglev and none with ring-hash. A server that is down, drained
or ejected keeps its place: its keys go to others, the same others everywhere,
and no other key moves. They take the weights in the file, not `okena backend
weight`, and an address a name resolves to anew is taken in within a second.

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

It is built for speed: about 100 MiB/s on one core, and for text about 0.7 of what
`gzip -1` achieves; a worker is held for some 150 µs for each 16 KiB, which counts for
a site made of large dynamic pages. A worker has 64 of these going at once, past
that answers go as they are. zstd is refused at load: there is none yet.

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
    tls { cert auto }
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
    trusted_proxies cloudflare         # provider ranges, refreshed
    cache disk=/var/cache/okena size=200GiB memory=2GiB {
        key host path query=v,lang
        stale_if_error 1h
        slice 4MiB
    }
    signed_urls key=${file:/etc/okena/url.key}
    to pool shield
}

http :443 {
    tls { cert auto }
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
    on backend_down pool_empty cert_expiring overload
}
```

## Discovery and backends from the outside

```
pool users {
    server users:8080                        # a name: resolved, re-resolved by TTL
    discover file /etc/okena/users.list      # one address per line, watched
    discover srv _users._tcp.service.consul
    discover docker label=okena.pool=users port=8080
}
```

The admin API changes the running state without editing files, given
`admin unix:PATH` in the `okena` block:

```
okena backend list                         # pool, server, weight, active, up|drain|down
okena backend drain api 10.0.1.10:8080     # no new connection; those it has go on
okena backend up api 10.0.1.10:8080        # takes the drain back
okena backend weight api 10.0.1.11:8080 3  # 1..65535, 0 for the weight in the file
okena reload                               # and says how it went; 1 when it did not take
```

Each takes `-c FILE` to find the socket. A server is named as in the file, so a name
means all its addresses. A drained server is not chosen even when every other is down:
with none left a request gets a 502. A reload keeps drains and weights, by pool and
server, and forgets those of a server that left the file; an upgrade or a restart starts
from the file. The socket is the owner's only, by mode and by a look at the caller. It
is opened when okena starts, so adding or moving `admin` takes a restart.

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
```

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
The new okena is a new process in the foreground of whoever started it, so a service
manager has to be told: with systemd, a `Type=notify` unit does not follow it yet.

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
