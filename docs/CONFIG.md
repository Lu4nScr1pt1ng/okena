# Configuration

This file describes the whole language, including what is designed but
not built yet. A directive that is not built is refused by `okena check`
("not supported by this version of okena yet"), never ignored.

## Built today

| Block | Directives |
|---|---|
| `okena` | `workers`, `io_engine`, `busy_poll`, `watchdog`, `drain delay= timeout=`, `metrics`, `ticket_keys` |
| `tcp ADDR...` | `to`, `limits { connections; per_source }`, `timeout { idle }`, `proxy_protocol send v1\|v2`, `tls { cert; key }` |
| `http ADDR...` | `host`, `route`, `limits`, `timeout { idle; header; body_idle; response }`, `trusted_proxies`, `access_log`, `tls { cert; key }` |
| `route PATH... [METHOD...]` | `to`, `redirect`, `rewrite path`, `header set\|add\|drop`, `response header set\|add\|drop` |
| `pool NAME` | `server ADDR [weight=N] [backup]`, `balance least-request\|peak-ewma\|round-robin\|least-conn\|random`, `connect timeout=`, `health tcp\|http ...`, `slow_start` |

`tls { cert FILE; key FILE }` on an `http` listener makes it HTTPS: TLS
1.3 with an EC P-256 certificate chain (leaf first) and its key. With
several certificates each line names its key, `cert FILE key=FILE`; the
client's SNI picks the one whose subjectAltName names the host (exactly,
then `*.parent`), the first being the default. A request whose `Host`
the chosen certificate does not name gets 421 (domain fronting). ALPN
http/1.1, then the connection handed to the kernel's TLS (kTLS) when the
host has the `tls` module (`modprobe tls`), or records sealed by okena
itself when it does not (said once at the start; `OKENA_KTLS=off` forces
it). Session tickets are on: a returning client resumes
without the certificate and the signature. The ticket key rotates every
hour and the previous one is still accepted, so a ticket lasts one to two
hours; keys live in memory only (a restart starts afresh). For a fleet,
`okena { ticket_keys FILE }` takes the keys from a file every instance
reads: one a line, 32 bytes of base64 (`openssl rand -base64 32`), the
first sealing new tickets, an optional second (the previous) still
opening them. Rotating is then a new first line and a reload (SIGHUP) on
each instance; okena does not rotate them itself. The header timeout covers
the handshake. Backends get `X-Forwarded-Proto: https`. On a `tcp`
listener `tls` terminates TLS and moves plaintext to the backend; there
it needs kTLS (okena refuses to start without the module), and the
handshake has the default header timeout (10 s).

Everything else below (the rest of TLS, `udp`, policies, auth, limits on requests,
caching, files, addons, discovery, the admin API and most tooling) is the
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
  NAME` applies it. Directives written in the route override the policy.

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
    # planned:
    profile balanced          # balanced | latency | throughput | memory-lean
    reload on-change          # watch the config directory (today: SIGHUP)
    admin unix:/run/okena/admin.sock
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
`client.ip`), joined by AND.
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
cache 30s stale-while-revalidate=5m vary=accept-encoding
cors origins=https://app.example.com methods=GET,POST credentials

match method=POST header:content-type=application/json {
    limit 20/s key=client.ip       # a block applies only when it matches
}
limit 100/s burst=200 key=client.ip
limit 10000/m key=header:x-api-key instances=4   # share of a fleet-wide limit
```

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
    auth mtls ca=/etc/okena/admin-ca.pem
    allow 10.0.0.0/8
}

policy sso {
    auth forward https://auth.internal/verify copy=x-user-id,x-user-role
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
                                   # (planned: maglev key=... | ring-hash key=...)
    protocol h2                    # http1 (default) | h2 | h2c | grpc
    tls sni=api.internal ca=/etc/okena/internal-ca.pem

    connect timeout=1s warm=4 max=512 idle=55s rate=200/s
    source 10.0.0.2 10.0.0.3       # more source addresses, more ports
    concurrency adaptive           # or: concurrency 256
    retry_budget 20% min=10/s

    health http GET /healthz every=2s timeout=500ms expect=200..299 host=api.internal
                                   # or: health tcp (connect only); expect defaults
                                   # to 200..399, host to the server as written
    outlier errors=5 eject=30s max_ejected=50%
    slow_start 30s
}
```

## Sites, caching and the edge

```
http :443 {
    tls { cert auto }
    canonical example.com              # www -> apex, 301
    headers preset=secure              # HSTS, nosniff, frame and referrer policy
    compress gzip zstd min=1KiB

    route /assets/* {
        files /srv/site precompressed=br,zst,gz cache=immutable
    }
    route /api/* {
        idempotency header=idempotency-key ttl=24h
        hold 10s                       # wait for a pool that is restarting
        to pool api
    }
    route /webhooks/* {
        body raw                       # forwarded byte for byte, for signatures
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

The admin API changes the running state without editing files:

```
okena backend drain api 10.0.1.10:8080
okena backend weight api 10.0.1.11:8080 3
okena reload
```

## Tooling

```
okena check okena.conf             # validate; non-zero exit on error
okena check --diff                 # what a reload would change
okena fmt -w okena.conf            # canonical formatting
okena explain                      # effective config, defaults included
okena route 'GET https://api.example.com/v1/users/42 x-canary:yes'
okena top                          # live per-route/backend view
okena bench https://localhost/v1/ --rate 200k --duration 60s
okena health                       # exit 0 when ready (Docker HEALTHCHECK)
okena check --host                 # kernel features, limits, sysctls, container
```

`okena route` answers "where does this request go": listener, matched
route and why, filters in order, pool, chosen backend and the limits that
apply.

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
