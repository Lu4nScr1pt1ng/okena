# Configuring okena

okena reads one file, `/etc/okena/okena.conf` unless you pass `-c FILE`. The
language is small and strict: every directive is checked before anything
runs, an unknown word is an error with a suggestion, and a value always
carries its unit. Everything has a default, so you write only what you want
to change.

This page starts with a working config and builds up from there. The second
half is a reference, ordered by what you are trying to do.

**Contents**

1. [A first configuration](#a-first-configuration)
2. [How a configuration is shaped](#how-a-configuration-is-shaped)
3. [Syntax](#syntax)
4. [Listeners: `http`, `tcp`, `udp`](#listeners)
5. [TLS](#tls)
6. [Hosts and routes](#hosts-and-routes)
7. [What a route can do](#what-a-route-can-do)
8. [Pools and backends](#pools-and-backends)
9. [Protocols: HTTP/2, HTTP/3, gRPC, WebSocket](#protocols)
10. [The `okena` block](#the-okena-block)
11. [Metrics, logs, traces and alerts](#metrics-logs-traces-and-alerts)
12. [The edge: XDP, VRRP, anycast, Kubernetes](#the-edge)
13. [Running okena](#running-okena)
14. [Recipes](#recipes)
15. [Limits at a glance](#limits-at-a-glance)

---

## A first configuration

A reverse proxy for an app on port 3000:

```nginx
http :80 {
    route /* { to 127.0.0.1:3000 }
}
```

Check it, see it with every default filled in, then run it:

```sh
okena check okena.conf        # exit 0 when it is valid
okena explain okena.conf      # the config as okena will run it
okena -c okena.conf
```

`okena explain` shows the main settings as okena will run them, with every
default filled in: the `okena` block, pools, listener limits and timeouts, TLS
versions, and each route's target and retries. It's a view, not a file to
copy: route filters, certificates and the like aren't shown, and inline pools
appear as `pool (inline 0)`, `pool (inline 1)` and so on (routes using them
say `to pool (inline)`).

The same with HTTPS, a certificate from Let's Encrypt renewed by okena, and
HTTP redirected to HTTPS:

```nginx
http :80 { route /* { respond 404 } }   # see below

http :443 {
    tls { auto }
    host example.com www.example.com {
        route /* { to 127.0.0.1:3000 }
    }
}
```

The `:80` listener is needed for two things okena does on its own, before any
route: answering Let's Encrypt's HTTP-01 challenge, and redirecting every name
it has a certificate for to `https://` with a 308. Its route only sees what is
left: requests for other names.

A TCP load balancer in front of two database replicas:

```nginx
tcp :5432 {
    to 10.0.0.11:5432 10.0.0.12:5432
}
```

Each of these already has health tracking, keep-alive pools, retries for
safe requests, timeouts and graceful reloads. The rest of this page is about
changing what they do.

---

## How a configuration is shaped

A connection travels from left to right. HTTP goes through hosts and routes;
`tcp` and `udp` go straight to a pool:

```
            ┌───────────────────── okena ──────────────────────┐
client ───▶ │ http listener ──▶ host ──▶ route ──▶ pool ───────┼──▶ server
client ───▶ │ tcp / udp listener ────────────────▶ pool ───────┼──▶ server
            └──────────────────────────────────────────────────┘
```

| Block | What it is | Example |
|---|---|---|
| `okena { }` | the process: workers, I/O engine, metrics, caches | `okena { workers 4 }` |
| `http ADDR { }` | an L7 listener: HTTP/1.1, HTTP/2, HTTP/3, with or without TLS | `http :443 { ... }` |
| `tcp ADDR { }` | an L4 stream listener, optionally ending or routing TLS | `tcp :5432 { ... }` |
| `udp ADDR { }` | an L4 datagram listener | `udp :53 { ... }` |
| `host NAME { }` | inside `http`: the routes for some host names | `host api.example.com { ... }` |
| `route PATH { }` | inside `http` or `host`: what to do with matching requests | `route /api/* { ... }` |
| `pool NAME { }` | a named set of backends and how to use them | `pool api { server 10.0.0.1:8080 }` |

`host` is optional: routes written straight in the listener serve any name.
Two more blocks stand alone at the top, `policy` (reusable route settings) and
`alerts`, plus the one-line `vrrp` directive.

**A setting lives in the block of the layer it acts on.** Connection limits
and idle timeouts are on the listener. Certificates are always in a `tls { }`
block, whether the listener is `http` or `tcp`. Header rules and auth are on
routes. How to connect to backends is on the pool. A TCP listener has no
routes and a route has no TCP options: most misplaced settings are errors
rather than settings that silently do nothing.

`to` takes either `pool NAME` or addresses. Addresses written inline become
a pool of their own with the default settings:

```nginx
route /app/* { to 127.0.0.1:3000 127.0.0.1:3001 }  # an inline pool
route /api/* { to pool api }                        # a named one
```

---

## Syntax

```nginx
directive argument argument key=value {
    nested directive
}
```

* A directive ends at a newline or at `;`. Blocks open with `{` on the
  directive's line. After a closing `}`, start a new line or write `;` before
  the next directive.
* `#` starts a comment.
* Quote a value when it has spaces, `{`, `}` or `;` in it, or starts with `#`:
  `respond 200 "all good"`, `header set x-color "#fff"`. Inside quotes, `\"`,
  `\\`, `\n` and `\t` work. Single quotes are not quotes.
* Options are `key=value` on the line. Many directives with options
  (for example `connect`, `queue`, `outlier`, `health`, `sticky`, a pool's
  `tls`, a route's `timeout`, `hedge`, `cors`, `limit`, `fault`,
  `idempotency`, `drain`) can also be written as a block, one option per line;
  flags without `=` stay on the line (`cors credentials { ... }`). These two are
  the same:

  ```nginx
  connect timeout=1s warm=4 max=256
  connect {
      timeout 1s
      warm 4
      max 256
  }
  ```

* `include "conf.d/*.conf"` inserts files in sorted order, as if written
  there. It goes at the top level only; the path is relative to the file that
  includes it; `*` and `?` work in the last part of the path, and a pattern that
  matches nothing is fine. Includes can nest up to 8 deep.

### Units

Every number that has a unit says it:

| Kind | Written as |
|---|---|
| time | `250ms`, `30s`, `5m`, `2h`, `1d`; `50us` where microseconds make sense |
| size | `512B`, `16KiB`, `4MiB`, `2GiB`, `1TiB` (binary units, the unit is required) |
| rate | `100/s`, `3000/m`, `10000/h` (`limit` also takes `/d`) |
| share | `20%` |

### The command line and `OKENA_CONFIG`

The same language works without a file. On the command line and in
`OKENA_CONFIG` (not in a file), a listener with a single directive may drop
its braces, and blocks may follow each other on one line:

```sh
okena tcp :5432 to db1:5432 db2:5432
okena 'okena { workers 2 } tcp :5432 to db1:5432'
okena 'http :80 { route /* { to app:3000 } }'
OKENA_CONFIG='http :80 { route /* { to app:3000 } }' okena
docker run --network host okena tcp :5432 to db:5432
```

### When something is wrong

`okena check` reports syntax and schema errors like a compiler: file, line,
column, the line itself, and a suggestion when there is a close match. Some
checks on values (a directory that doesn't exist, an option out of range)
print only the message, naming the directive.

```
okena.conf:3:9: error: unknown directive `timout`
     3 |         timout { idle 30s }
       |         ^^^^^^
       = help: did you mean `timeout`?
```

A reload whose config does not check never replaces the running one.
`okena fmt -w okena.conf` rewrites a file with canonical indentation and
spacing, and leaves comments where they are.

---

## Listeners

A listener is a keyword (`http`, `tcp`, `udp`) followed by up to 16
addresses:

```nginx
http :80 { ... }                    # port 80 on every address, IPv4 and IPv6
http :80 :8080 { ... }              # two ports, one set of routes
tcp 10.0.0.5:5432 { ... }           # one address
tcp 0.0.0.0:6379 [::1]:6379 { ... } # IPv4 everywhere, IPv6 loopback only
```

`:PORT` listens on every address, both families.

### Limits and timeouts

```nginx
limits {
    connections 100000      # open at once, shared out among the workers (default: auto, as many as the file limit allows)
    per_source 256          # per client address (tcp and http only)
}
timeout {
    idle 60s                # http 60s, tcp 1h, udp 30s
}
mss 1400                    # tcp and http: clamp TCP segments (tunnels that drop ICMP)
```

`connections` is divided evenly among the workers (rounded up): each worker
refuses past its share. See [Per worker or per
instance](#per-worker-or-per-instance) for every limit.

### `http`

```nginx
http :443 {
    tls { auto }
    http2 on                         # off by default
    http3 on                         # off by default; needs tls
    trusted_proxies 10.0.0.0/8       # whose X-Forwarded-For to believe
    access_log /var/log/okena/access.log
    limits { body_size 10MiB }
    timeout { header 10s; body_idle 30s; response 30s; idle 60s }

    route /api/* { to pool api }
    route /* { files /srv/site }
}
```

| Timeout | Default | What happens when it runs out |
|---|---|---|
| `header` | 10s | the request head did not arrive in time: 408 (a connection that sent nothing is just closed) |
| `body_idle` | 30s | a body stalled in either direction: 408 for a request body; a client that stops reading is let go |
| `response` | 30s | the backend sent no response head: 504, or another try if the route's `retry` allows |
| `idle` | 60s | a keep-alive connection waited this long for its next request |

`limits { body_size SIZE }` caps request bodies (no cap by default; larger
values are cut to 4 GiB): a `Content-Length` over it is a 413 before anything reaches a
backend, and a chunked body gets the 413 once it grows past it. A request
head is at most 16 KiB (431 past that, 414 when the request line alone is too
long).

**Client addresses.** By default the client is the TCP peer, and any
`X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`, `Forwarded`,
`X-Real-IP`, `True-Client-IP` and `CF-Connecting-IP` the client sent are
dropped. okena writes its own `X-Forwarded-For`, `X-Forwarded-Proto` and
`X-Request-Id`. With `trusted_proxies`, a peer in that list has its
`X-Forwarded-For` kept and extended, and the client becomes the rightmost
address in the chain that is not itself trusted. Logs, limits, `allow`/`deny`
and `client.ip` all use that address.

```nginx
trusted_proxies cloudflare                    # Cloudflare's published ranges, built in
trusted_proxies 10.0.0.0/8 file:/etc/okena/lb-ranges.txt
```

`okena ranges cloudflare` prints the built-in list.
`contrib/ranges/update.sh PATH` fetches the current one into a file, for
cron.

**Headers for every route.** `header`, `response header`, `compress` and
`headers preset=` can stand on the listener or a `host` block and then apply
to every route below. The listener's rules run first, then the host's, then
the route's, so the route has the last word.

**One canonical name.** `canonical example.com` sends `www.example.com` to
`example.com` with a 301, keeping scheme, port and path (`canonical
www.example.com` goes the other way). Other names and requests by IP address
are left alone.

### `tcp`

```nginx
tcp :5432 {
    to pool db
    limits { connections 20000; per_source 100 }
    timeout { idle 1h }
    proxy_protocol send v2           # tell the backend who the client is (v1 or v2)
}
```

Bytes are relayed in both directions with backpressure, half-close and
graceful drain. A `tcp` listener can also end TLS or route it by name without
decrypting it, see [TLS on a `tcp` listener](#tls-on-a-tcp-listener). With
`mode xdp` it runs in the kernel, see [XDP](#xdp-load-balancing-in-the-kernel).

### `udp`

```nginx
udp :53    { to pool dns;  responses 1; timeout { idle 5s } }    # one answer per query
udp :514   { to pool logs; responses 0 }                          # no answers expected
udp :27015 { to pool game; timeout { idle 2m } }                  # a long-lived flow
```

Each client is a *flow*, kept on the server it was given until it goes quiet
for `timeout { idle }` (30 s by default). `limits { connections N }` is the
number of flows; when it is full, an idle flow makes room, and flows in use
are never pushed out.

* `responses N` ends a flow at its Nth answer (DNS: `responses 1`).
  `responses 0` expects none, and such flows don't use a socket each.
* A flow that expects answers has its own connected socket, so only its
  backend can answer it. An ICMP "port unreachable" counts as a failed
  connect.
* When its server goes down, a flow moves on its next datagram.
* A listener bound to every address answers from the address the client
  wrote to.
* A reload hands the sockets over with their queued datagrams.

The same port can be both `tcp` and `udp`, but not `udp` and `http3`.

---

## TLS

TLS is always a `tls { }` block. On an `http` listener it makes HTTPS (and
allows HTTP/2 by ALPN and HTTP/3). On a `tcp` listener it ends TLS and sends
plaintext to the backend, or, with `tls passthrough`, routes by name without
decrypting.

okena has its own TLS 1.3 and 1.2, both directions, with no OpenSSL.

### Certificates from files

```nginx
tls {
    cert /etc/okena/example.pem key=/etc/okena/example.key
    cert /etc/okena/other.pem   key=/etc/okena/other.key
}
```

The PEM holds the chain, leaf first. Keys may be EC P-256, RSA or Ed25519
(Ed25519 only goes to clients that ask for it, which browsers don't, so pair
it with an EC certificate). With several certificates, the client's SNI picks
the one whose subjectAltName names the host, exact first, then `*.parent`.
The first one is the default. When the client sent SNI, a request whose
`Host` the chosen certificate doesn't cover gets 421, which stops domain
fronting.

With a single certificate you can also write the key on its own line:
`cert FILE` and `key FILE`. When a name has both an ECDSA and an RSA
certificate, clients that only take RSA get the RSA one.

### Automatic HTTPS

`tls { auto }` gets a certificate from an ACME CA for every name in the
listener's `host` blocks, and renews it. Without an `okena { acme ... }`
line, the CA is Let's Encrypt and certificates live in `/var/lib/okena/acme`.
Each name is one certificate, and an instance holds 16 ACME certificates at
most. Wildcard names (`*.example.com`) need `challenge=dns-01`; with HTTP-01
they are skipped. Without any `host` block, `auto` has no name to ask for.

```nginx
http :80  { route /* { respond 404 } }        # challenge and redirect; 404 for anything else

http :443 {
    tls { auto }
    host example.com www.example.com { route /* { to pool web } }
    host api.example.com             { route /* { to pool api } }
}
```

To name the certificates yourself, or to use a CA other than Let's Encrypt,
declare the CA in the `okena` block (with no such line, `auto` uses Let's
Encrypt; once you write it, `ca=` is required) and list names with `acme
NAME...` (each line is one certificate, up to 15 names):

```nginx
okena { acme /var/lib/okena/acme ca=https://acme-v02.api.letsencrypt.org/directory }

http :443 {
    tls {
        acme example.com www.example.com
        acme api.example.com
    }
    route /* { to pool web }
}
```

Until the first certificate arrives, the listener serves one it signs itself
for 7 days, so it is up from the start. Every name okena gets a certificate
for is redirected from plain HTTP to HTTPS with a 308. `redirect off` in the
`tls` block turns that off. An `http :80` listener must exist for HTTP-01 and
for the redirect; okena answers the challenge before any route. okena doesn't
check that it exists: without it, HTTP-01 orders fail and nothing is
redirected.

**Choosing the CA and the challenge** is done once, in the `okena` block:

```nginx
okena {
    acme /var/lib/okena/acme ca=https://acme-v02.api.letsencrypt.org/directory email=ops@example.com
}
```

| Option | Meaning |
|---|---|
| `ca=URL` | the CA's directory URL (required on this line, even for Let's Encrypt) |
| `email=ADDR` | the account contact |
| `trust=FILE` | the CA's anchor, for a private CA (otherwise the system's roots) |
| `challenge=` | `http-01` (default), `tls-alpn-01` (port 443 only, no port 80) or `dns-01` (nothing needs to be reachable; required for wildcards) |
| `eab=FILE` | external account binding, `KID:HMAC_KEY` on one line (ZeroSSL, Google, most private CAs) |
| `fallback=URL` `fallback_trust=` `fallback_eab=` | a second CA, used at once when an order with the first fails |
| `staging=URL\|off` | after a failure, the next order is tried on a staging CA first, so a broken name doesn't burn production rate limits: Let's Encrypt's staging when `ca=` is Let's Encrypt, otherwise only the one you name |
| `shared=on` | several instances share the directory (a volume, NFS): one orders, the others pick it up |

DNS-01 talks to your DNS provider:

```nginx
okena { acme /var/lib/okena/acme ca=https://acme-v02.api.letsencrypt.org/directory challenge=dns-01 dns=cloudflare dns_token=/etc/okena/cf.token }
```

| `dns=` | Credentials | Notes |
|---|---|---|
| `cloudflare` | `dns_token=FILE`: an API token with Zone.DNS edit | `dns_api=` for another endpoint |
| `rfc2136` | `dns_server=HOST:PORT dns_key=FILE`, the key as `nsupdate -y` takes it | BIND, Knot, PowerDNS; TSIG HMAC-SHA256 over TCP |
| `route53` | `dns_key=FILE`: `ACCESS_KEY_ID:SECRET[:SESSION_TOKEN]` | needs ListHostedZonesByName, ChangeResourceRecordSets, GetChange |

`dns_wait=` (20 s by default) is how long to wait for the record to spread,
and `dns_trust=FILE` the provider API's CA, when it isn't a public one.

**Renewal.** A certificate is renewed when two thirds of its life has passed,
with some jitter, or inside the window the CA asks for when it supports ARI
(RFC 9773). Failed orders back off from a minute up to six hours, and the old
certificate is served meanwhile. okena reloads itself to pick up a new
certificate (a reload: see [Reloads](#reloads-drains-and-upgrades)).

**On demand.** For platforms where customers bring their own domains,
`on_demand` gets a certificate the first time a client asks for a name:

```nginx
okena { acme /var/lib/okena/acme ca=https://acme-v02.api.letsencrypt.org/directory }

http :443 {
    tls { on_demand *.customers.example.com ask=http://127.0.0.1:9000/allowed max=64 }
    route /* { to pool tenants }
}
```

It needs the CA declared with `okena { acme ... }`, and a pattern, an `ask=`
URL, or both, so that strangers can't make okena spend the CA's limits.
`ask=` (an `http://` URL, usually a local service of yours) receives `GET
URL?domain=NAME`, and only a 200 allows the order. `max=` caps how many names
it will get certificates for (64 at most). The
handshake waits up to 15 s for the certificate; past that it goes on with the
listener's default certificate.

### Certificates for development

`local NAME...` signs certificates with a CA of okena's own, kept in
`/var/lib/okena/ca` (or `okena { local_ca DIR }`):

```nginx
http :443 {
    tls { local localhost app.test *.app.test 127.0.0.1 }
    route /* { to 127.0.0.1:3000 }
}
```

`okena trust` adds that CA to the system trust store (Debian, Ubuntu, Alpine,
Fedora, RHEL, openSUSE, Arch). `okena trust remove` takes it out. Firefox has
its own store and the command tells you how to add it there. For a one-off
certificate: `okena cert selfsigned DIR a.test b.test days=30`, and for a CSR
to send to a CA: `okena cert csr DIR a.example.com`.

### Versions, ALPN and kTLS

```nginx
tls {
    cert /etc/okena/site.pem key=/etc/okena/site.key
    versions 1.3                 # default: 1.2 1.3
    alpn h2 http/1.1             # in order of preference; h2 here turns HTTP/2 on
    ktls on                      # hand records to the kernel (default off on http)
}
```

* `versions 1.3` refuses TLS 1.2 clients. HTTP/3 needs 1.3.
* `alpn h2` offers HTTP/2 and so turns it on; with `http2 off` written, it's
  an error. `alpn h2` alone refuses clients that offer only HTTP/1.1 (one that
  offers no ALPN at all still speaks HTTP/1.1).
* TLS 1.3 suites: AES-128-GCM, ChaCha20-Poly1305 (when the client puts it
  first) and AES-256-GCM. TLS 1.2: ECDHE with ECDSA or RSA, the same AEADs,
  extended master secret. No CBC, no RSA key exchange, no SHA-1, no
  renegotiation.
* Key exchange: X25519MLKEM768 (post-quantum hybrid), X25519 and P-256.
* By default okena seals records itself, which costs about 1.5% against
  plaintext. `ktls on` moves them to the kernel (`modprobe tls`), which
  enables zero-copy file and cache bodies over TLS but costs more per
  request. A `tcp` listener that ends TLS always uses kTLS, so it needs the
`tls` kernel module.
* Certificate compression (RFC 8879, brotli and zlib) needs no
  configuration.
* Session tickets are on. Without a file, okena makes its own key, rotates it
  every hour and still accepts the previous one. For a fleet, share keys with
  `okena { ticket_keys FILE }`: base64 32-byte keys (`openssl rand -base64
  32`), the first line sealing new tickets and the second, if any, still
  opening old ones. With a file okena doesn't rotate: you rewrite it (it is
  read again each second).

### OCSP stapling

Stapling is on for any certificate that names an OCSP responder. okena fetches
and verifies the response, refreshes it halfway to its `nextUpdate`, and never
staples a stale one. A revoked ACME certificate is renewed at once. `ocsp off`
in a `tls` block turns it off.

### Client certificates (mTLS)

```nginx
http :443 {
    tls {
        cert /etc/okena/server.pem key=/etc/okena/server.key
        client_ca /etc/okena/clients.pem required crl=/etc/okena/clients.crl
    }
    route /admin/* { auth mtls identity=x-admin; to pool admin }
}
```

`required` (the default) refuses a handshake without a valid certificate.
`optional` lets it through, and routes with `auth mtls` answer 401. Chains
are verified against the CAs in the file, with dates, key usage and the
`crl=` revocation lists. The certificate's commonName goes to the backend in
`x-user-id` (or `identity=`). Not available on `tcp` listeners or together
with `http3`.

### Encrypted Client Hello

```nginx
okena { ech public.example.com /etc/okena/ech.key }
```

Clients that have okena's ECH config (published in DNS) show only the public
name in the clear; the real name and the rest of the hello travel encrypted.
`okena ech new FILE` makes a key and `okena ech print` prints the value for
the `ech=` parameter of your HTTPS DNS record. List older keys after the
first to keep them working during a rotation.

### TLS on a `tcp` listener

End TLS and pass plaintext (IMAP, a database, anything over TCP):

```nginx
tcp :993 {
    tls { cert /etc/okena/mail.pem key=/etc/okena/mail.key }
    to 10.0.0.30:143
}
```

Or route by the name the client asks for, without decrypting:

```nginx
tcp :443 {
    tls passthrough {
        sni api.example.com *.api.example.com to pool api-tls
        sni internal.example.com to pool internal
        default reject                 # or: default to pool fallback
    }
}
```

The ClientHello is read for its SNI and then forwarded untouched, after a
PROXY header when `proxy_protocol send` is set.

---

## Hosts and routes

### Host blocks

```nginx
http :443 {
    tls { auto }
    host example.com www.example.com {
        route /* { to pool site }
    }
    host *.example.com {               # with tls { auto }: needs challenge=dns-01
        route /* { to pool tenants }
    }
    route /* { respond 404 }           # any other host
}
```

An exact name wins over a wildcard, and a wildcard over the listener's own
routes. Lookup is a hash table probe, so a thousand hosts cost the same as
one.

### Route matching

```nginx
route /healthz { respond 200 "ok" }           # exact
route /api/* { to pool api }                  # prefix
route /api/admin/* GET POST { to pool admin } # a longer prefix, two methods
route ~^/u/(\d+)$ { to pool users }           # a regular expression
route /* { to pool site }                     # everything else
```

For a request, okena looks at:

1. an exact path;
2. regular expressions, in the order written;
3. prefixes, longest first.

A route may list up to 32 paths and methods. When a route matches the path
but not the method, the next shorter prefix is tried. Two routes that could
match the same request the same way are an error at load time.

**Paths are normalized before matching**: `%XX` of unreserved characters
decoded, other escapes upper-cased, `//` folded. Requests that can't be
normalized safely get a 400: `.` and `..` segments, encoded `/` or `\`, raw
`\`, encoded control bytes. The backend gets the path as the client sent it.

**Regular expressions** use a PCRE subset: `.`, classes, `\d \w \s`, anchors,
groups (9 captures), `(?: )`, alternation, `* + ? {n,m}` (lazy too) and `(?i)`.
They compile to an automaton that runs in linear time, so no pattern can make
a worker backtrack. Quote a pattern that has braces, spaces or `;`:
`route "~^/a{2}$"`. To try one out: `okena regex '^/u/(\d+)$' /u/42`.

### `match` blocks

Inside a route, `match` picks a variant by method, header, query, cookie,
client address or country. The first block that fits wins; a route has at
most 32.

```nginx
route /api/* {
    match header:x-canary=yes {
        to pool api-canary
    }
    match method=POST header:content-type=application/json {
        limit 20/s key=client.ip
    }
    limit 200/s key=client.ip
    to pool api
}
```

| Condition | Meaning |
|---|---|
| `NAME=VALUE` | exact value |
| `NAME=VALUE*` | prefix |
| `NAME=~REGEX` | regular expression |
| `NAME` | present |
| `method=GET,HEAD` | one of the methods |
| `client.ip=10.0.0.0/8` | the client (after `trusted_proxies`) in a range |
| `client.country=BR,PT` | with `okena { geoip FILE }` |
| `path=~REGEX` | the normalized path |

NAME is `header:X`, `query:X` or `cookie:X`. Conditions in one block are ANDed.
A block replaces what the route says under the same directive name, so an
`auth` on the route still applies in every block. `to`, `redirect` and `split`
count as one name. `limit` is the exception: a block's limits are *added* to
the route's, so a block can't loosen a limit by accident.

### Policies

A `policy` is a named set of route directives, applied with `use`:

```nginx
policy authenticated {
    auth jwt {
        jwks https://auth.example.com/.well-known/jwks.json trust=/etc/okena/idp-ca.pem
        issuer https://auth.example.com
        audience api
        claims sub -> x-user-id
    }
    limit 50/s key=jwt.sub
}

http :443 {
    tls { auto }
    host api.example.com {
        route /v1/* { use authenticated; to pool api }
        route /admin/* { use authenticated; allow 10.0.0.0/8; to pool admin }
    }
}
```

Directives written in the route override the policy's under the same name.
That includes `limit`: unlike in a `match` block, a route's own `limit`
replaces all of the policy's. With two `use` lines, the first wins. A policy
can't use another.

### Where does this request go?

```sh
okena route 'GET https://api.example.com/v1/users/42 x-canary:yes' -c okena.conf
```

prints the listener, route, `match` block, filters and pool (blank for an
inline pool) that would handle
it, using the same code that routes real traffic.

---

## What a route can do

A route does one of three things with a request: forwards it (`to`,
`split`), answers it itself (`respond`, `redirect`, `files`, `php` with
FastCGI), or refuses it (auth, limits, `allow`/`deny`). Everything else
adjusts how that happens.

### Forward

```nginx
to pool api                                  # a named pool
to 10.0.0.1:8080 10.0.0.2:8080               # an inline pool
split stable=95% canary=5% sticky=cookie:okena_split
mirror pool shadow 10%                       # copy 10% of requests, ignore the answers
```

**`split`** shares traffic between 2 to 8 pools, adding up to 100%. Without
`sticky=` each request is drawn. With `sticky=cookie:NAME` a client gets a
number from 0 to 99 in a cookie and keeps its pool, so raising a canary from
5% to 10% moves only the next 5% of clients. `sticky=header:NAME` hashes a
header. A client can set its own cookie, so use this for releases, not
security.

**`mirror`** sends a copy of a share of requests (all of them without `N%`)
to another pool and discards what it answers. The client never waits for the
shadow. If the shadow falls 64 KiB behind on a body, that copy is cut. At most
256 copies run at once per worker. Don't mirror requests that change things
to a backend that would act on them.

### Answer directly

```nginx
respond 200 "ok"                              # a body (text/plain unless type=)
respond 204
respond 200 "{\"status\":\"up\"}" type=application/json
redirect 301 /new/{*}                         # {*}: the rest of the path after the route's prefix
redirect 308 https://{host}{path}             # {host}: requested name; {path}: the whole path
redirects /etc/okena/old-urls.txt code=301    # thousands of redirects, one lookup;
to pool site                                  # what isn't in the file goes on
```

A redirect keeps the query unless the target has its own. The redirect file
holds `/old /new` or `/old https://elsewhere/ 302` per line; paths not in it
continue through the route.

### Serve files

```nginx
route /assets/* { files /srv/site precompressed=br,zst,gz cache=immutable }
route /*        { files /srv/site fallback=/index.html }     # a single-page app
```

The request's whole path is looked up under the directory:
`/assets/app.js` → `/srv/site/assets/app.js`.

| Option | Meaning |
|---|---|
| `index=NAME` | what a directory answers with (`index.html`); a directory without its slash is redirected |
| `fallback=/PATH` | served instead of a 404 |
| `precompressed=br,zst,gz` | serve `file.br`, `.zst` or `.gz` next to the file when the client accepts it |
| `cache=T` or `cache=immutable` | `Cache-Control: public, max-age=...` |

GET and HEAD, ETag and Last-Modified, conditional requests and single byte
ranges are handled. Dotfiles are not served, except `.well-known`. Symlinks
can't escape the directory (`openat2` with `RESOLVE_BENEATH`), and workers are
confined by Landlock to reading only the directories they serve. Bodies of
64 KiB or more go from the page cache to the socket with sendfile, without a
copy, over plain HTTP/1.1 or kTLS.

### PHP and FastCGI

```nginx
pool fpm { server unix:/run/php-fpm/www.sock; protocol fastcgi }

http :443 {
    tls { auto }
    host example.com {
        route /* { php /srv/www; to pool fpm }
    }
}
```

A path with a segment ending in `.php` runs that script, with the rest as
`PATH_INFO`. A directory runs its `index.php` (`index=` to change it). A file
that exists and isn't PHP is served as a static file and never given to PHP,
so `/uploads/x.php.jpg` stays an image. Anything else goes to the front
controller, which is what Laravel, Symfony and WordPress expect. A request
body needs a length (a chunked one gets 411). Without
`php`, a `protocol fastcgi` pool works with any FastCGI responder.

### Change requests and responses

```nginx
header set   x-env prod                      # replace what the client sent
header add   x-via okena                     # add another
header drop  x-internal-*                    # a name, or a prefix with *
response header set strict-transport-security "max-age=63072000"
response header drop server
rewrite path /v1/{*} -> /{*}                 # the backend sees /users for /v1/users
rewrite path ~^/u/(\d+)$ -> /users/$1        # with a regex and groups
headers preset=secure                        # HSTS, nosniff, frame and referrer policy
compress br gzip min=1KiB                    # on a listener, a host or a route
early_hints /assets/app.css /assets/app.js   # 103 with preload links, for GET
```

* Header values may use `${client.ip}`, `${request.id}`, `${time.us}` and
  `${time.s}`: `header set x-request-start "t=${time.us}"`.
* Names okena owns can't be changed: `host`, framing, hop-by-hop fields,
  `x-forwarded-*`, `forwarded`, `x-request-id`. Values can't contain CR, LF or
  NUL.
* `response header` rules apply to okena's own answers too (redirects,
  `respond`), so an HSTS rule on the listener covers everything.
* A route undoes what it inherits with `compress off` and `headers
  preset=none`.
* `compress` handles 200 answers of text, JSON, JavaScript, XML and SVG from `min` up (256
  bytes by default). It skips content that is already encoded, `no-transform`,
  HEAD and HTTP/1.0, and streams as it goes, so server-sent events aren't
  held back. It runs at about 100 MiB/s per core. Leave routes that mix secrets
  with user input out of it (BREACH).

### Retries, timeouts and the tail

```nginx
retry 2 on=reset,timeout,503
timeout try=2s total=5s
hedge after=p95
hold 10s
priority critical
```

| Directive | Meaning |
|---|---|
| `retry N on=LIST` | up to N more tries (0 to 5) on another server, on `reset`, `timeout`, `5xx`, `500`, `502`, `503`, `504`. Default: `retry 1 on=reset,502,503,504`. Only GET, HEAD, PUT, DELETE and OPTIONS without a body are retried; `retry 0` never sends a request twice |
| `timeout try=T total=T` | `try` replaces the listener's `response` timeout for each try; `total` is how late a retry may still start. Whole seconds, 1s to 1h (`500ms` becomes 1s) |
| `hedge after=50ms` | if an idempotent request without a body has no answer by then, send a copy to another server and take the first good answer. Needs a pool of two or more servers. `after=p95` uses that percentile of the pool's recent answers, once the worker has seen 64 |
| `hold 10s` | when no server accepts connections (a pool restarting), wait up to 10 s instead of a 502. Safe for POSTs: nothing was sent yet |
| `priority critical\|normal\|bulk` | under overload, `bulk` routes are refused first (503), then `normal`, and `critical` goes on |

Retries and hedges spend the pool's `retry_budget`, so an outage can't turn
into a retry storm. A failed connect moves to another server (up to 3
attempts, each on a different server) without needing `retry`, because nothing
was sent.

**Overload.** Each worker checks, every second, how full its fullest
listener is (`limits { connections }`) and how late its own loop is running,
and answers in steps:

| Level | Listener full | Loop late | What changes |
|---|---|---|---|
| 1 | 80% | 50 ms | idle connections are closed sooner |
| 2 | 85% | 100 ms | responses say `Connection: close`, to free slots |
| 3 | 90% | 250 ms | `priority bulk` routes answer 503 with `Retry-After: 1` |
| 4 | 97% | 1 s | so do `normal` routes (the default); only `critical` gets through |

A level rises at once and falls one step at a time, after 3 quiet seconds, so
it doesn't flap around a threshold.

### Access control

```nginx
allow 10.0.0.0/8 2001:db8::/32 file:/etc/okena/partners.txt
deny  203.0.113.0/24
allow cloudflare                       # only Cloudflare may reach this origin
allow country:BR,PT                    # with okena { geoip FILE }
```

`allow` and `deny` look at the client after `trusted_proxies` and answer 403.
A deny wins; with any `allow`, everything not allowed is refused. Lists of
thousands of entries cost one lookup. `okena { geoip /path/GeoLite2-Country.mmdb }`
loads a MaxMind country database for `country:`.

### Authentication

| Method | Directive |
|---|---|
| API keys | `auth api_key header=x-api-key keys=/etc/okena/keys` |
| HTTP Basic | `auth basic users=/etc/okena/users realm=admin` |
| JWT | `auth jwt { jwks ...; issuer ...; audience ... }` |
| Client certificates | `auth mtls` (with the listener's `client_ca`) |
| An external service | `auth forward pool=sso path=/verify copy=x-user-id` |

On success the backend gets the identity in `x-user-id` (or `identity=NAME`;
for JWT, in the headers `claims` names),
and a client-sent header with that name is dropped, so nobody can claim to be
someone else. The credential itself is not forwarded unless `forward=on`. On
failure, `api_key`, `basic`, `jwt` and `mtls` answer 401 with
`WWW-Authenticate` (forward auth: below), and the backend is never asked. `limit key=auth.user` gives each identity its own limit.

**Key and user files.** A keys file has `name:key` lines. A users file has
`name:SALT:SHA256HEX` lines, the hash taken over salt and password:

```sh
salt=$(openssl rand -hex 8); printf '%s:%s:%s\n' alice "$salt" "$(printf '%s%s' "$salt" "$password" | sha256sum | cut -d' ' -f1)"
```

Basic uses salted SHA-256 instead of bcrypt, which would stall a worker for
milliseconds per attempt. Use long random passwords.

**JWT.**

```nginx
auth jwt {
    jwks https://auth.example.com/.well-known/jwks.json trust=/etc/okena/idp-ca.pem refresh=10m stale=24h
    issuer https://auth.example.com
    audience api
    leeway 30s
    claims sub -> x-user-id, scope -> x-user-scope
}
```

ES256, RS256, PS256, EdDSA and HS256 (HS256 keys only from a `jwks` file: a
set fetched by URL never contributes a shared secret). Tokens must have `exp`; `issuer` and
`audience` are checked when given. `alg: none`, a `crit` header and malformed
JSON are refused.

`jwks` takes a file or an HTTPS URL. An HTTPS URL needs `trust=FILE`, the
anchor its certificate must chain to (plain `http://` only for localhost). A
separate process fetches it every `refresh` (10m) and at once when a token
names an unknown `kid`; keys stay valid for `stale` (24h) after the last good
fetch. Verified tokens are cached per worker until they expire or the keys
change. A refetch for an unknown `kid` happens at most every 10 s.

Each claim named in `claims` goes to the backend in its header, and whatever
the client sent under those names is dropped. The first claim listed is the
user's identity, what `key=jwt.sub` and `key=auth.user` count by. Without a
`claims` line there is no identity, and such a limit puts every request in
one shared bucket.

**Forward auth.** The request waits while okena asks the `pool` with `GET
path`, passing Cookie, Authorization and `X-Forwarded-Method/Uri/Host`. A 2xx
lets the request through and copies the `copy=` headers to it. A 3xx or 4xx is
the client's answer. Anything else, or no answer within `timeout=` (2s by
default), is a 503:
when the decision can't be made, nobody gets in. `cache=30s` keeps positive
answers per worker, for requests that carry Cookie or Authorization.

### Rate limits and quotas

```nginx
limit 100/s burst=200 key=client.ip
limit 10000/m key=header:x-api-key
limit 10000/d burst=10000 key=auth.user      # up to 10000 a day, refilled gradually
limit 3000/s key=client.ip instances=4       # a quarter each, for a fleet of 4
```

A refused request gets 429 with `Retry-After` on a connection that stays
open. Without `key=`, all clients share one bucket. `key=` is `client.ip`, `method`, `header:NAME`, `query:NAME`,
`cookie:NAME`, `auth.user` or `jwt.sub`. Requests without that field share
one key, so dropping a header doesn't escape the limit. `burst` defaults to
one second of the rate (at least 1): set it for hourly and daily quotas, or
a `10000/d` limit allows one request every 8.6 seconds. A route may have several limits, and each one must
pass. The table holds about 256k keys and survives reloads.

### CORS

```nginx
cors origins=https://app.example.com,https://*.example.com methods=GET,POST headers=content-type,authorization max_age=10m credentials
```

okena answers preflights itself with 204 (the route must accept OPTIONS) and
adds the headers to every answer of the route, its own errors included.
`expose=` lists response headers the browser may read. The
backend's `Access-Control-*` headers are replaced. `origins=*` can't be used
with `credentials`.

### Idempotency keys

```nginx
idempotency header=idempotency-key ttl=24h lock=60s
```

A POST (or any non-safe request) sent twice with the same key reaches the
backend once. The second gets the first answer with `Idempotency-Replayed:
true`. While the first is running, a repeat gets 409; the same key with a
different method, target, length or type gets 422. The key is scoped by route
and authenticated user. After a 502, 503, 504 or a failed connect the key is
released, so a repeat reaches the backend again (the work may not have been
done). Answers up to 48 KiB can be replayed; for a larger one, repeats get
409 until `ttl`. Keys live in memory and survive reloads, not restarts.

### Signed URLs

```nginx
route /video/* { signed_urls key=/etc/okena/url.key key2=/etc/okena/url.old; to pool media }
```

Only links signed with the shared key are served, until they expire:

```sh
okena sign /etc/okena/url.key /video/a.mp4 1h                        # one file
okena sign /etc/okena/url.key /live/x/0.ts 6h prefix=/live/x/        # a whole HLS stream
okena sign /etc/okena/url.key /dl/f.zip 10m ip=203.0.113.7           # one client
```

The signature is HMAC-SHA256, keyed with the first line of the key file, of
`PATH\nEXPIRES\nIP`, where PATH is `prefix=` when one is given and IP is empty
without `ip=`. It goes base64url in `sig=`, next to `expires=` (and `prefix=`,
`ip=`), so your own backend can sign links too. Anything wrong is a
403. `key2` keeps old links working while you rotate.

### Caching

```nginx
okena { cache_memory 256MiB; cache_disk /var/cache/okena size=200GiB }

http :443 {
    tls { auto }
    route /api/* { to pool api }
    route /* { cache 10m stale-while-revalidate=1m stale-if-error=1h; to pool site }
}
```

`cache TIME` keeps answers for TIME unless the backend's `s-maxage` or
`max-age` says otherwise. Memory is per worker (`cache_memory`, 64 MiB by
default). `cache_disk` adds a shared second tier that all workers and
processes on the machine use, and that survives reloads, upgrades and clean
restarts. In each worker, concurrent misses for the same object make one
backend request; the others wait for it (5 s at most).

| Option | Meaning |
|---|---|
| `stale-while-revalidate=T` | serve a stale answer for up to T while fetching a fresh one |
| `stale-if-error=T` | serve a stale answer for up to T when the backend fails (5xx or unreachable) |
| `vary=accept-encoding,accept-language` | up to 4 request headers in the key |
| `query=all\|none\|a,b` | which query parameters are part of the key (all by default) |
| `host=off` | one entry for every host name the listener serves |
| `max=SIZE` | the largest answer kept (1 MiB) |
| `slice=4MiB` | keep large objects in slices fetched with Range requests (video, downloads) |
| `shared=on` | cache even requests with Cookie or Authorization: the answer is the same for everyone |

What is cached: GET answers of 200, 301, 308, 404 and 410 whose end is known
(a `Content-Length` or chunked).
`no-store`, `private`, `no-cache` and `Set-Cookie` are respected. Requests
with Cookie or Authorization, or on a route with `auth`, bypass the cache
unless `shared=on`. Conditional requests get 304, single ranges get 206.
Every answer says what happened in `Cache-Status` (RFC 9211), for example
`okena; hit; ttl=42` or `okena; fwd=miss; stored`.

**Purging** takes effect at once in every worker, on disk, and on the other
instances listed in `okena { fleet ... }`:

```sh
okena purge url https://shop.example/p/a?x=1
okena purge prefix shop.example/assets/
okena purge tag product-42              # tags from the origin's Cache-Tag or Surrogate-Key
curl -X POST -H "Authorization: Bearer $TOKEN" 'http://10.0.0.1:9464/purge?tag=product-42'
```

**A shield tier.** Put a pool of okenas between edges and the origin and
hash by URL, so each object is fetched from the origin once:

```nginx
okena { cdn_loop examplecdn }              # 508 when a request comes back around
pool shields {
    balance maglev key=url
    server shield-1.internal:80
    server shield-2.internal:80
}
http :443 {
    tls { auto }
    route /* { cache 1h stale-if-error=1h; to pool shields }
}
```

### Error pages and maintenance

```nginx
errors 502 503 504 file=/srv/errors/down.html          # on a listener or a route
route /api/* { errors 5xx backend file=/srv/errors/api.json; to pool api }
maintenance file=/srv/maint.html retry=2m allow=10.0.0.0/8 except=/healthz
```

`errors` (on a listener or a route) replaces okena's own error answers with
your page; with `backend`,
the backend's errors too (the status stays, its body never reaches the
client). `{status}`, `{reason}` and `{request_id}` are filled in. Pages are
read with the config, up to 16 KiB.

The `maintenance` line, on an `http` listener, only describes the page: `retry=` for its
`Retry-After` (30s by default), `allow=` clients that are still served (your
team), `except=` paths that are still served, exact or `prefix*` (the load
balancer's health check). Maintenance itself is switched at runtime, through
the admin socket (`okena { admin ... }`), and survives reloads:

```sh
okena maintenance on              # every request: 503 with Retry-After and the page
okena maintenance on /api/*       # only this route
okena maintenance off
```

### Fault injection

```nginx
fault abort=503 percent=5            # 5% of requests get a 503 from okena
```

One `fault` per route. `abort=` (400 to 599) answers in place of the backend;
`delay=` (up to 10m) holds the request first and then lets it go on, or, with
`abort=` too, answers late: `fault delay=2s percent=10`, `fault delay=1s
abort=504`. It shows how clients cope with errors and slowness.

### Addons

```nginx
addon waf {
    run /usr/local/bin/coraza-okena -rules /etc/crs
    timeout 50ms
    on_error allow                 # or deny (the default): 503
}

route /api/* {
    addon waf
    to pool api
}
```

An addon is a program okena starts and keeps running, called for each
request of the routes that name it: it lets the request go on (with fields
set, added or removed, or its target changed) or answers it itself. It runs
apart, in any language; a crash or a hang costs only its own routes what
their `on_error` says. `concurrency` (default 1024) and `breaker errors=5
open=1s` bound what a slow or failing addon may hold. Everything about them,
the protocol included: [ADDONS.md](ADDONS.md).

---

## Pools and backends

```nginx
pool api {
    server 10.0.1.10:8080 weight=2
    server 10.0.1.11:8080 max=500
    server api-3.internal:8080           # a name: resolved, re-resolved by TTL
    server unix:/run/api.sock
    server 10.0.1.99:8080 backup         # only when no other server is up

    balance least-request
    health http GET /healthz every=2s expect=200..299
    connect timeout=1s warm=4
}
```

### Servers

`server ADDR [weight=N] [max=N] [backup]`. Addresses are IPv4, IPv6
(`[2001:db8::1]:80`), `unix:PATH` or names. A name is resolved from
`/etc/hosts` and DNS (with search domains, A and AAAA), up to 8 addresses
used, re-resolved by TTL (at least once a minute) and immediately when a
connect fails. When DNS fails, the
last known addresses are kept.

`max=N` caps connections in use to that server across the instance. When all
servers are full, HTTP requests wait in line for `queue timeout=` (the
connect timeout by default) and then get a 503. TCP connections are closed.

### Balancing

| `balance` | How a server is picked |
|---|---|
| `least-request` | **default.** Two at random, the one with fewer requests in flight (power of two choices) |
| `peak-ewma` | the lowest moving average of latency × load: slow servers get less |
| `round-robin` | in turn, by weight |
| `least-conn` | the fewest open connections |
| `random` | at random, by weight |
| `maglev key=K` | consistent hashing, even spread, one-step lookup |
| `ring-hash key=K` | consistent hashing that moves the fewest keys when servers change |
| `source-hash` | maglev keyed on the client address; the hash to use on `tcp` and `udp`, where there are no headers |
| `first` | the first server in file order until it is full (`max=`), then the next |

Hash keys: `source` (default), `header:NAME`, `cookie:NAME`, `query:NAME`,
`path`, `url`. The same key goes to the same server in every worker, after
reloads and on every instance with the same servers. With `maglev` and
`ring-hash`, add `bound=125%` to cap
any server at that share of the average load: a hot key spills over to the
next server its hash gives, and comes back when load drops.

### Health

```nginx
health tcp every=2s timeout=1s rise=2 fall=3
health http GET /healthz every=2s expect=200..299 host=api.internal
health grpc my.Service every=2s
```

Defaults: `every=2s timeout=1s rise=2 fall=3`, and servers start as up.
Active checks run once per instance, in a process of their own, not once per
worker. `rise` successes bring a server up, `fall` failures take it down.
`expect` defaults to 200..399. The gRPC check calls
`grpc.health.v1.Health/Check` and passes on `SERVING`.

Passive checks are always on, per worker:

```nginx
outlier errors=5 eject=10s max_ejected=50%        # the defaults
```

A server that gives 5 failing answers in a row (5xx, closing without an
answer, or no answer within the `response` timeout),
or 3 failed connects, is left out for `eject`. For failing answers, never
more than `max_ejected` of the pool is out at once; failed connects eject
regardless, since a server that can't be reached can't serve either. `errors=0` ignores answers (for APIs whose 503s
are deliberate). When every server is down, okena uses them all anyway (panic
mode) rather than refuse everything.

### Connections to backends

```nginx
connect timeout=2s max=512 idle=50s warm=0 rate=200/s
```

| Option | Default | Meaning |
|---|---|---|
| `timeout` | 2s | connect timeout; past it, the next server |
| `max` | 512 | idle keep-alive connections kept per server, per worker (not the same as `server ... max=`, which caps connections in use) |
| `idle` | 50s | how long an idle connection is kept (below common backend keep-alive values, so okena closes first) |
| `warm` | 0 | connections opened ahead of need per server, so the first requests after a quiet spell find one |
| `rate` | none | new connections per second per server, so a cold start can't open thousands at once |

### Protecting backends

```nginx
concurrency adaptive                  # or: concurrency 256
retry_budget 20% min=10/s             # the default
slow_start 30s
sticky cookie=srv ttl=1h samesite=lax
source 10.0.0.2 10.0.0.3
```

* **`concurrency N`** caps requests in flight to the pool; past it, a 503 at
  once instead of piling onto a saturated backend. `concurrency adaptive
  [min=4] [max=1024]` finds the cap from response times (gradient method, as
  Netflix's concurrency-limits and Envoy do).
* **`retry_budget`** caps retries and hedges at that share of requests plus
  `min` per second, in each worker (with 8 workers, `min=10/s` allows up to
  80 a second).
* **`slow_start 30s`** ramps up the share of a server that comes back, over
  that window.
* **`sticky cookie=NAME`** keeps an HTTP client on the server it got, by a
  cookie naming a hash of the server. Clients that already have a
  drained server's cookie keep going to it (until the cookie's `ttl`); new
  clients go elsewhere. WebSocket upgrades follow
  the cookie.
* **`source ADDR...`** spreads outgoing connections over up to 8 local
  addresses, each adding about 28 000 ports per backend, for proxies that run
  out of ephemeral ports.

### Per worker or per instance

Counted across the whole instance: `per_source`, rate limits (`limit`), a
server's `max=`, idempotency keys. Divided among the workers, each refusing
past its share (at least 1 each): a listener's `connections`, a pool's
`concurrency`, `connect rate=`. Per worker: the memory cache, retry budgets,
passive health (`outlier`), JWT and forward-auth caches, idle connections to
backends (`connect max=`).

### Talking to backends: protocol and TLS

```nginx
pool grpc {
    server 10.0.2.10:9000
    protocol h2                         # h1 (default) | h2 | fastcgi
    tls {
        trust /etc/okena/internal-ca.pem
        sni api.internal
        cert /etc/okena/edge.pem        # shown to backends that ask (origin pulls)
        key /etc/okena/edge.key
    }
}
```

`protocol h2` multiplexes requests over a few connections per server (at
most 4 in each worker), with prior knowledge on plaintext or ALPN under `tls`. Clients may
speak any protocol; a backend's trailers reach HTTP/2 clients as trailers and
HTTP/1.1 clients after the last chunk.

A pool's `tls` is for `http` listeners: a `tcp` or `udp` listener can't
re-encrypt to a pool, and `okena check` refuses one that points at a pool
with `tls`.

`tls` verifies the backend's chain up to the first certificate in `trust`
(required) and its name against `sni`. Give it the one root or private CA
the backend's chain ends at: a bundle doesn't work, since only its first
certificate counts. Unlike ACME, alerts and JWKS, pools never use the
system's roots.

### Discovery

Servers can come from outside the file. Any of these can sit next to
`server` lines:

```nginx
pool users {
    discover file /etc/okena/users.list port=8080
    discover srv _users._tcp.service.consul
    discover docker label=okena.pool=users port=8080
    discover kubernetes service=shop/users port=http
    discover consul service=users tag=v2
}
```

| Source | Where servers come from | Checked |
|---|---|---|
| `file PATH` | one `ADDRESS[:PORT] [weight=N]` per line | every second |
| `srv NAME` | DNS SRV records; higher priorities are backups | by TTL (1-60 s) |
| `docker label=K[=V]` | running containers with the label, via the Docker socket; containers with a health check join when healthy | every second |
| `kubernetes service=NS/NAME` | the Service's EndpointSlices, ready endpoints (terminating ones only if none are ready) | every second |
| `consul service=NAME` | Consul's catalog, instances whose checks pass | every second |

`max=N` caps how many servers a source may add. Without it, a source that
more than doubles is picked up by an automatic reload, at most every 10 s. Changes reach the workers within two seconds, and a server that stays keeps
its health and connections. A source that fails or returns garbage changes
nothing: DNS or an API going away never empties a pool.

`share=N` weighs whole sources against each other: `discover kubernetes
service=a/x share=1` and `discover kubernetes service=a/y share=3` send three
times more to y, whatever the number of pods on each side.

Docker options: `port=`, `network=`, `socket=` (a read-only socket proxy is
a good idea), per-container `okena.port` and `okena.weight` labels.
Kubernetes options (all defaulted inside a pod): `port=`, `api=`, `token=`,
`ca=`, `name=`; the service account needs `get` and `list` on
`endpointslices`. Consul options: `dc=`, `tag=`, `token=FILE`, `api=`,
`port=`.

### Changing backends at runtime

With `okena { admin unix:/run/okena/admin.sock }`:

```sh
okena backend list
okena backend drain api 10.0.1.10:8080     # no new requests; the ones in flight finish
okena backend up api 10.0.1.10:8080
okena backend weight api 10.0.1.11:8080 3
```

Drains and weights survive reloads.

---

## Protocols

### HTTP/2

`http2 on` on an `http` listener serves HTTP/2 by ALPN on TLS and by prior
knowledge on plaintext (h2c). Up to 100 streams per connection with flow
control; clients that reset more than 200 streams a second get GOAWAY. Every
route feature works the same; backends get HTTP/1.1 unless their pool says
`protocol h2`.

### HTTP/3 and QUIC

```nginx
http :443 {
    tls { auto }
    http2 on
    http3 on                       # one of: on | retry | v2 | off
    early_data on                  # 0-RTT for GET, HEAD, OPTIONS
    route /* { to pool web }
}
```

`http3 on` adds QUIC v1 and v2 on the same port over UDP and advertises it
with `Alt-Svc`. To be found on the first visit, publish a DNS HTTPS record:
`example.com. 3600 IN HTTPS 1 . alpn="h3,h2"`.

| Setting | Meaning |
|---|---|
| `http3 retry` | validate every new client's address with a Retry (by default only under load: past 64 unvalidated connections per worker) |
| `http3 v2` | move v1 clients that offer v2 to it |
| `early_data on` | accept 0-RTT; only GET, HEAD and OPTIONS proceed, marked `Early-Data: 1` (HTTP/3 only) |
| `preferred_address ADDR:PORT [ADDR:PORT]` | an address clients move to after the handshake (HTTP/3 only) |
| `okena { quic_cc bbr }` | congestion control (CUBIC by default) |
| `okena { quic_server_id HEX key=HEX rotation=N }` | QUIC-LB connection IDs, so a load balancer in front can route by connection ID |


### gRPC and gRPC-Web

```nginx
pool greeter { server 10.0.3.10:50051; protocol h2; health grpc }
http :443 {
    tls { auto }
    http2 on
    route /* { to pool greeter }
}
```

Trailers carry `grpc-status` through. When okena itself can't serve a gRPC
call (no server, timeout), it answers as gRPC: 14 UNAVAILABLE, 4
DEADLINE_EXCEEDED and so on. gRPC-Web (binary and text) from browsers is
translated to gRPC for a `protocol h2` pool with no configuration; add the
route's `cors` for pages on other origins.

### WebSocket and other upgrades

Nothing to configure. An `Upgrade` request answered with 101 turns the
connection into a tunnel with the backend. Over HTTP/2, clients use extended
CONNECT (RFC 8441) and the backend still gets an HTTP/1.1 upgrade.

---

## The `okena` block

Settings for the process as a whole. All are optional.

```nginx
okena {
    workers auto
    profile balanced
    metrics :9464 token=/etc/okena/metrics.token
    admin unix:/run/okena/admin.sock
    user okena
    reload on-change
    last_good on
}
```

| Directive | Default | Meaning |
|---|---|---|
| `workers N\|auto` | auto | one per CPU allowed by the affinity mask and the cgroup quota (at most 1024) |
| `io_engine auto\|io_uring\|epoll` | auto | io_uring when the kernel and seccomp allow it, otherwise epoll (okena logs why) |
| `profile` | balanced | `latency` (busy-poll), `throughput` (never poll), `memory-lean` (fewer idle connections, smaller cache) |
| `pin_workers auto\|on\|off` | auto | `auto` pins a worker past half a core of load and unpins it under a fifth |
| `busy_poll auto\|DURATION` | auto | poll instead of sleeping: `auto` polls only while events arrive within 50 µs of each other, and only on a pinned worker; `200us` always polls that long; `0us` never |
| `watchdog DURATION` | 2s | a worker stuck this long is replaced |
| `drain delay=T timeout=T` | 0s, 8s | on stop, reload and upgrade: wait `delay` (for load balancers to notice), then let connections finish for `timeout`; what is still open after that is closed |
| `reload on-change\|signal` | signal | `on-change` reloads when the file or an included one changes |
| `last_good on\|off` | off | keep the last config that ran as `FILE.good` and start from it if `FILE` is broken |
| `user NAME\|UID[:GROUP]` | | drop to this user for everything that faces the network |
| `metrics ADDR [token=FILE]` | | Prometheus, health probes, status, dashboard |
| `admin unix:PATH` | | the socket `okena reload`, `backend`, `drain`, `top`, `purge` use |
| `upgrade unix:PATH` | | binary upgrades without dropping connections (`okena upgrade`) |
| `handshake_budget T wait=T` | 100us, 1s | TLS crypto per loop turn, so a handshake flood can't starve requests in flight; hellos waiting longer than `wait` are closed |
| `ticket_keys FILE` | | shared TLS session ticket keys for a fleet |
| `cache_memory SIZE` | 64MiB | the response cache in memory, per worker |
| `cache_disk DIR size=SIZE` | | a shared disk tier |
| `geoip FILE` | | a MaxMind country database, for `country:` and `client.country` |
| `acme DIR ca=URL ...` | | the ACME CA, see [TLS](#automatic-https) |
| `local_ca DIR` | /var/lib/okena/ca | the development CA |
| `ech NAME KEYFILE...` | | Encrypted Client Hello |
| `quic_cc cubic\|bbr` | cubic | QUIC congestion control |
| `quic_server_id HEX` | | QUIC-LB server ID |
| `fleet ADDR...` | | other instances' metrics addresses, for `okena purge` (they must share the metrics token) |
| `cdn_loop NAME [max=N]` | | loop detection between caches (RFC 8586) |
| `bird PATH protocol=P [pool=]` | | announce an anycast route through BIRD while healthy |
| `gateway kubernetes dir=DIR` | | act as a Kubernetes Gateway API implementation |
| `xdp IFACE...` `drop` `syn_rate` | | the in-kernel packet path, see [XDP](#xdp-load-balancing-in-the-kernel) |

**Security model.** Each kind of process (workers, health checker, logger,
admin, ACME, cache keeper...) runs under its own seccomp filter: no `execve`,
no `ptrace`, no executable memory, and an io_uring worker is allowed only a
handful of system calls. With `user`, everything that touches the network
drops to that user with no capabilities. The supervisor stays as started so
it can bind low ports and read private keys on reload, and the config
compiler it uses for that is confined to reading by seccomp and Landlock.

---

## Metrics, logs, traces and alerts

### The metrics address

`okena { metrics :9464 }` serves:

| Path | What |
|---|---|
| `/metrics` | Prometheus metrics |
| `/live` | 200 while the process runs |
| `/ready` | 200 while it serves; 503 while starting or draining |
| `/status` | the instance as JSON |
| `/dashboard`, `/` | a live page of listeners, routes, pools and servers |
| `POST /purge` | cache purge (needs `token=`) |

With `token=FILE`, everything except `/live` and `/ready` needs the token, as
`Authorization: Bearer` or as a Basic password, so Prometheus and a browser
both work. Use it on a trusted network or behind TLS.

Notable metrics: requests, bytes and responses by status class per listener;
`okena_http_request_duration_seconds`; `okena_tls_handshakes_total` by
version and result; `okena_cache_hits_total`; `okena_http_retries_total`;
`okena_udp_dropped_total`; and `okena_tls_certificate_not_after_seconds` for
expiry alerts:

```
(okena_tls_certificate_not_after_seconds - time()) / 86400 < 14
```

`okena top` shows the same as a table in the terminal, refreshed every
second.

### Access logs

On an `http` listener:

```nginx
access_log /var/log/okena/access.log         # or stdout, stderr, off (default)
access_log syslog://10.0.0.5                 # UDP 514
access_log syslog+tcp://logs:601
access_log syslog+tls://logs:6514 trust=/etc/okena/logs-ca.pem
access_log otlp://collector:4318             # OpenTelemetry logs over OTLP/HTTP
```

One JSON line per request: `time`, `listener`, `client`, `peer`, `method`,
`host`, `target`, `status`, `bytes`, `duration_ms`, `upstream`, `source`
(`backend` or `okena`), `retried`, and with tracing, `trace_id` and
`span_id`. Workers never write files or wait for the network: they pass lines
to a logger process and drop them (counted in
`okena_access_log_dropped_total`) rather than slow down a request.
`SIGUSR1` or a reload reopens files, which is all logrotate needs.

### Tracing

On an `http` listener:

```nginx
tracing otlp://collector:4318 sample=5%
```

Each request becomes an OpenTelemetry server span (W3C Trace Context). A
valid incoming `traceparent` is continued; otherwise okena starts a trace.
The backend always gets okena's span as parent. Sampling is parent-based, and
`sample=` applies to new traces. For `otlp+https://`, `trust=FILE` names the
collector's CA.

### Alerts

```nginx
alerts {
    webhook https://hooks.example.com/okena
    slack https://hooks.slack.com/services/T/B/X
    telegram token=123:ABC chat=-100123
    on backend reload worker discovery certificate
    every 10s
    name edge-1
}
```

Backends down or unreachable and back (health checks, failed connects;
ejection for failing answers is logged but not alerted), workers restarted, reloads refused, discovery
failing, certificates within 14 days of expiry. Repeats from several workers
are grouped into one message per `every` window. HTTPS targets are verified
against the system roots, or `trust=FILE`; Telegram takes `api=` for a Bot API
other than Telegram's.

---

## The edge

### XDP: load balancing in the kernel

```nginx
okena { xdp eth0 }

pool web {
    server 10.0.0.21:80
    server 10.0.0.22:80
    health tcp every=200ms
}

tcp 203.0.113.10:80 { mode xdp; to pool web }
tcp [2001:db8::10]:443 { mode xdp encap=gue; to pool web }
```

A `mode xdp` listener isn't a socket. Its packets are handled in the NIC
driver before the kernel's network stack, wrapped in an outer header and
sent to a server, which answers the client directly (direct server return).
The flow table keeps a flow on its server, and new flows go through a maglev
table that is the same on every instance, so ECMP between balancers is safe.
IPv4 and IPv6 in any mix, IP-in-IP or GUE (`encap=gue port=6080`, which lets
the servers' NICs spread flows by RSS). Path MTU discovery works through it.
`udp` listeners take `mode xdp` too. It needs `okena { xdp IFACE }` naming the
interfaces (`okena check` says so when it's missing), and CAP_BPF and
CAP_NET_ADMIN; without the capabilities okena serves everything else and says
why.

On the servers: the VIP on `lo`, the tunnel device up (`tunl0`, `sit0`,
`ip6tnl0`, or `ip fou add port 6080 gue`), `rp_filter` off on it, and
`arp_ignore=1`, `arp_announce=2`.

**A packet filter for everything.** The same program can drop traffic for
every listener, whatever its engine:

```nginx
okena {
    xdp eth0
    drop 192.0.2.0/24 2001:db8:bad::/48 file:/etc/okena/drop.txt
    syn_rate 100/s burst=200          # new TCP connections per source (IPv4 address or IPv6 /64)
}
```

Lists of a million prefixes per family; a dropped packet costs about 40 ns.

### A floating address with VRRP

```nginx
vrrp eth0 vrid=51 priority=150 address=203.0.113.10/24 advert=1s track=web
# on the other node: priority=100
```

VRRP v3 (RFC 9568), IPv4 or IPv6. The node with the highest priority holds
the address, and takes it back when it returns (`preempt=off` to leave it
where it is). An okena that can't take traffic (draining, stopping, or its
`track` pool with no server up) gives it up immediately.

### Anycast with BIRD

```nginx
okena { bird /run/bird/bird.ctl protocol=anycast pool=web }
```

okena enables BIRD's `anycast` protocol only while it can serve (and `pool`
has a server up), so an unhealthy node withdraws its route. Pair it with
`drain delay=` of a few seconds.

### Kubernetes Gateway API

```nginx
okena { gateway kubernetes dir=/var/lib/okena/gateway }
include "/var/lib/okena/gateway/*.conf"
```

okena watches Gateways, HTTPRoutes, GRPCRoutes, TLSRoutes, TCPRoutes and
UDPRoutes of its GatewayClass (`controllerName: okena.dev/gateway-controller`),
writes them as okena config, reloads when they change, and reports status
back. Inside a pod nothing else is needed; elsewhere give `api=`, `token=`,
`ca=` and `name=`, as for `discover kubernetes`. `class=` picks another
GatewayClass name. A generated config that doesn't check is refused whole, and the running
one stays.

---

## Running okena

### Commands

| Command | What it does |
|---|---|
| `okena [run] [-c FILE]` | serve (default `/etc/okena/okena.conf`) |
| `okena check [FILE]` | validate; exit 0 when valid |
| `okena check --diff [FILE]` | what a reload with FILE would change in the running instance |
| `okena check --host [FILE]` | host settings that would hold okena back (conntrack, somaxconn, ports, file limits, kTLS, io_uring) |
| `okena explain [FILE]` | the effective config, defaults written out |
| `okena fmt [-w] FILE` | canonical layout |
| `okena route 'METHOD URL [name:value...]'` | which route and pool a request would take |
| `okena regex PATTERN TEXT...` | test a route regex |
| `okena reload` | reload and report the result |
| `okena upgrade -c FILE` | replace the binary without refusing a connection |
| `okena drain [wait]` / `okena resume` | take the instance out of rotation (`/ready` 503) and back |
| `okena backend list\|drain\|up\|weight` | change servers at runtime |
| `okena maintenance [on\|off [ROUTE]]` | maintenance mode |
| `okena top [once]` | live view of listeners, pools and servers |
| `okena purge url\|prefix\|tag VALUE` | purge the cache (and the fleet's) |
| `okena health` | exit 0 when the running instance is ready (for Docker HEALTHCHECK; needs `metrics`) |
| `okena certs` | certificates served, expiry, ACME state |
| `okena cert selfsigned\|csr DIR NAME...` | make a key and a certificate or CSR |
| `okena trust [remove]` | install the development CA |
| `okena sign KEYFILE PATH TTL` | a signed URL |
| `okena ech new FILE` / `okena ech print` | ECH keys and their DNS value |
| `okena ranges cloudflare` | a built-in provider range list |
| `okena bench URL [rate=N] ...` | open-loop load generator with coordinated-omission correction |

Commands that talk to a running instance find its admin socket through the
config, so they take `-c FILE` too.

### Reloads, drains and upgrades

* **Reload** (`SIGHUP`, `okena reload`, or `reload on-change`): the new config
  is compiled in a separate process; if anything is wrong, nothing changes.
  New workers take over the listening sockets, so no new connection is
  refused, and the old workers finish the requests they have. A connection
  still open when the drain timeout runs out (8 s by default, plus a 5 s
  margin) is closed: raise `okena { drain timeout= }` if you carry long
  `tcp` streams, WebSockets or downloads you don't want cut on reload.
* **Drain** (`okena drain`): `/ready` turns 503 so the load balancer in front
  stops sending, HTTP/1 connections close after their current response,
  HTTP/2 and HTTP/3 get GOAWAY. `okena drain wait` returns when nothing is
  left open.
* **Upgrade** (`okena upgrade -c FILE`, with `okena { upgrade unix:PATH }`):
  the new binary takes the sockets from the running one and starts its
  workers; only then does the old one drain, as on a reload, and exit. If the
  new one can't start, the old one carries on. HTTP/3 connections don't
  survive an upgrade: QUIC sockets are opened anew, and clients reconnect.
* An HTTP/1.x request that crashes a worker twice is quarantined for 10
  minutes (503 before parsing), and a stuck worker is replaced by the watchdog.

### systemd

`contrib/systemd` has a service and a socket unit. okena speaks the notify
protocol (`Type=notify-reload`: `READY=1`, `RELOADING=1`, `STOPPING=1`,
`WATCHDOG=1`) and accepts socket activation, without libsystemd. With systemd
holding the sockets, even a restart refuses no new connection.

### Docker

The image is built `FROM scratch`, under 1 MB, runs as non-root (65532), and reads
`/etc/okena/okena.conf`:

```yaml
services:
  okena:
    image: okena
    network_mode: host                     # no docker-proxy in the path
    cpuset: "0-3"
    security_opt:
      - seccomp=docker/okena.seccomp.json  # Docker's default profile plus io_uring
    volumes:
      - ./okena.conf:/etc/okena/okena.conf:ro
    stop_grace_period: 10s
```

The image runs as an unprivileged user, so with host networking it can't bind
ports below 1024 as it is. Either lower the host's limit (`sysctl
net.ipv4.ip_unprivileged_port_start=80`), or start the container as root
(`user: "0:0"`) and let okena drop privileges itself with `okena { user 65532 }`:
only the supervisor keeps root, to bind ports and read keys on reload.

Without the seccomp profile okena runs on epoll and says so. Without host
networking, disable the daemon's userland proxy and raise
`net.core.somaxconn` and `net.ipv4.ip_local_port_range` with `sysctls:`.
`okena check --host` lists what to change.

---

## Recipes

Complete configurations for common jobs. Each one passes `okena check`.

### A website and its API, on one domain

```nginx
okena { metrics 127.0.0.1:9464 }

pool api {
    server 10.0.1.10:8080
    server 10.0.1.11:8080
    health http GET /healthz
}

http :80 { route /* { respond 404 } }

http :443 {
    tls { auto }
    http2 on
    http3 on
    headers preset=secure
    compress br gzip

    host example.com www.example.com {
        route /api/* { to pool api }
        route /assets/* { files /srv/site precompressed=br,gz cache=immutable }
        route /* { files /srv/site fallback=/index.html }
    }
}
```

### An API gateway: JWT, per-user limits, CORS

```nginx
policy signed_in {
    auth jwt {
        jwks https://auth.example.com/.well-known/jwks.json trust=/etc/okena/idp-ca.pem
        issuer https://auth.example.com
        audience api
        claims sub -> x-user-id
    }
    limit 100/s key=jwt.sub
    cors origins=https://app.example.com methods=GET,POST,PUT,DELETE headers=authorization,content-type
}

pool orders { server 10.0.2.10:8080; server 10.0.2.11:8080 }
pool users  { server 10.0.3.10:8080 }

http :443 {
    tls { auto }
    http2 on
    trusted_proxies 10.0.0.0/8
    access_log stdout

    host api.example.com {
        route /v1/orders/* GET POST OPTIONS {
            use signed_in
            idempotency header=idempotency-key ttl=24h
            to pool orders
        }
        route /v1/users/* GET PUT OPTIONS { use signed_in; to pool users }
        route /healthz { respond 200 "ok" }
    }
}
```

### A canary release

```nginx
pool stable { server 10.0.4.10:8080; server 10.0.4.11:8080 }
pool canary { server 10.0.4.20:8080 }

http :443 {
    tls { auto }
    host shop.example.com {
        route /* {
            match header:x-canary=yes {
                to pool canary                      # testers opt in
            }
            split stable=95% canary=5% sticky=cookie:release
        }
    }
}
```

### A PostgreSQL primary with a standby

Everything goes to the primary; the standby gets connections only while the
primary is down.

```nginx
pool pg {
    server 10.0.0.11:5432
    server 10.0.0.12:5432 backup
    health tcp every=1s fall=2
}

tcp :5432 {
    to pool pg
    limits { per_source 200 }
    timeout { idle 1h }
}
```

### A caching edge in front of an origin

```nginx
okena { cache_memory 1GiB; cache_disk /var/cache/okena size=200GiB }

pool origin {
    server origin.example.net:443
    tls { trust /etc/okena/origin-root.pem; sni origin.example.net }   # the root the origin's chain ends at
}

http :443 {
    tls { auto }
    http2 on
    http3 on
    trusted_proxies cloudflare
    host cdn.example.com {
        route /* { cache 1h stale-while-revalidate=5m stale-if-error=1d; to pool origin }
    }
}
```

### Containers that register themselves

```nginx
pool web { discover docker label=okena.pool=web port=8080 }

http :80 {
    route /* { to pool web }
}
```

Start a container with `--label okena.pool=web` and it receives traffic within
two seconds, or once its Docker health check passes if it has one. Stop it and
it leaves the pool just as fast.

---

## Limits at a glance

| What | Limit |
|---|---|
| addresses per listener | 16 |
| paths and methods per route | 32 |
| `match` blocks per route | 32 |
| request head | 16 KiB |
| request body | unlimited by default, `limits { body_size }` up to 4 GiB |
| HTTP/2 streams per connection | 100 |
| `split` pools | 2 to 8 |
| `retry` | 0 to 5 |
| `source` addresses | 8 |
| ACME certificates | 16 per instance (each `acme` line is one, up to 15 names; with `auto`, each name is one) |
| error page | 16 KiB |
| `respond` body | 4 KiB |
| rate limit keys | about 256k, kept across reloads |
| idempotency keys | 4096 |
| cache purge rules | 1024; past that, older rules widen into "everything fetched before" |
| include depth | 8 |
| workers | 1024 |
