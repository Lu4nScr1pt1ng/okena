# Configuration

One file, `okena.conf`, read top to bottom. The smallest useful config is
two lines; everything else has a default chosen for safety and speed, and
`okena explain` prints the effective config with every default filled in.

## Principles

* **Say what, not how.** You declare listeners, routes and pools; okena
  picks the engine (XDP, sockmap, splice, HTTP) that does it cheapest.
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
* Strings need quotes only when they contain spaces or `{}#=`.
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

## The smallest configs

L4 TCP balancer (PostgreSQL replicas):

```
tcp :5432 {
    to 10.0.0.11:5432 10.0.0.12:5432
}
```

HTTPS reverse proxy with an automatic certificate:

```
https example.com {
    to 127.0.0.1:3000
}
```

Inside Docker, with the backend as a compose service:

```
docker run --network host okena https example.com to app:3000
```

`https NAME` implies `:443`, a certificate for `NAME` from ACME, an `:80`
listener that redirects to HTTPS and serves ACME challenges, HTTP/2 and
HTTP/3. Each implied thing can be overridden or turned off.

## Top level

```
okena {
    workers auto              # min(affinity mask, cgroup CPU quota)
    profile balanced          # balanced | latency | throughput | memory-lean
    io_engine auto            # auto | io_uring | epoll
    busy_poll 50us            # poll this long after activity instead of sleeping
    reload on-change          # watch the config directory
    drain delay=2s timeout=7s # fits inside docker stop's 10 s
    admin unix:/run/okena/admin.sock
    metrics :9464
    log access stdout format=json
    acme email=ops@example.com
}
```

Profiles set groups of defaults: `latency` enables busy polling, NAPI
polling and smaller batches; `throughput` larger batches and `SEND_ZC`
thresholds; `memory-lean` smaller pools and earlier trimming. Any single
setting can still be overridden.

## Listeners

```
tcp     ADDR...            { ... }   # L4 TCP proxy
udp     ADDR...            { ... }   # L4 UDP proxy (DNS, games, syslog)
xdp     ADDR...            { ... }   # L4 in the kernel, DSR (needs backend setup)
tls     ADDR...            { ... }   # SNI routing without decryption
http    ADDR...            { ... }   # plaintext HTTP
https   HOST|ADDR...       { ... }   # HTTP over TLS (+ h2, h3)
```

Common listener directives:

```
limits {
    connections 200000
    per_source 256                  # connections per client address
    header_size 32KiB
    body_size 10MiB
    h2_streams 128
}
timeout {
    handshake 5s
    header 10s
    idle 60s
    body_idle 30s
}
proxy_protocol accept from=10.0.0.0/8   # believe PROXY v1/v2 from these
trusted_proxies 10.0.0.0/8              # believe X-Forwarded-For from these
```

## L4

```
tcp :443 {
    to pool web-tls
    proxy_protocol send v2
}

tls :443 {
    sni api.example.com   to pool api-tls
    sni *.internal        to pool internal
    default               reject
}

xdp 203.0.113.10:80 203.0.113.10:443 {
    to pool web
    balance maglev
    encap gue               # ipip | gue; backends answer clients directly
}
```

## HTTP routes

A route matches on host, path, method, headers and query, in that order.
Inside a route, `match` narrows further; its conditions use the same
names as limit keys (`method`, `header:NAME`, `query:NAME`, `cookie:NAME`,
`client.ip`), joined by AND.
The most specific match wins (exact host over wildcard, static path over
parameter over `*`); ties are an error at load time, not a surprise in
production.

```
https api.example.com www.example.com {
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
```

Route directives:

```
to pool NAME                     # or: to ADDR... for an inline pool
split api=95% api-canary=5% sticky=cookie:okena_split
mirror pool shadow 10%           # copy of the request, response ignored
rewrite path /v1/{*} -> /{*}
header set   x-request-start "${time.us}"
header drop  x-internal-*
response header set strict-transport-security "max-age=63072000"
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

    balance least-request          # least-request | peak-ewma | round-robin
                                   # | maglev key=... | ring-hash key=... | least-conn
    protocol h2                    # http1 (default) | h2 | h2c | grpc
    tls sni=api.internal ca=/etc/okena/internal-ca.pem

    connect timeout=1s warm=4 max=512 idle=55s rate=200/s
    source 10.0.0.2 10.0.0.3       # more source addresses, more ports
    concurrency adaptive           # or: concurrency 256
    retry_budget 20% min=10/s

    health http GET /healthz every=2s timeout=500ms expect=200..299
    outlier errors=5 eject=30s max_ejected=50%
    slow_start 30s
}
```

## Sites, caching and the edge

```
https example.com www.example.com {
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

https cdn.example.com {
    trusted_proxies cloudflare         # provider ranges, refreshed
    cache disk=/var/cache/okena size=200GiB memory=2GiB {
        key host path query=v,lang
        stale_if_error 1h
        slice 4MiB
    }
    signed_urls key=${file:/etc/okena/url.key}
    to pool shield
}

https grafana.example.com {
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
      - seccomp=okena.seccomp.json # enables the io_uring engine
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
