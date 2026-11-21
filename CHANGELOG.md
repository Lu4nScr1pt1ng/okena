# Changelog

okena follows [semantic versioning](https://semver.org). Until 1.0 the
configuration language may still change between minor versions; each change
is listed here, with what to write instead.

## 0.3.0 — 2026-11-21

Faster HTTP/2 and HTTP/3 for clients that repeat their requests, HTTP/3
clients that no longer stall, short-lived connections on many cores, gzip
twice as fast, and fixes for request bodies and mirrors. No configuration
from 0.2.0 has to change.

### Install

```sh
curl -fsSL https://raw.githubusercontent.com/Lu4nScr1pt1ng/okena/v0.3.0/scripts/install.sh | sh
docker run -p 8080:8080 ghcr.io/lu4nscr1pt1ng/okena:0.3.0
```

Or download `okena-0.3.0-linux-x86_64.tar.gz` below and check it against its
`.sha256`.

### Faster

- **HTTP/2 and HTTP/3:** each connection keeps what its last request head
  turned into at each step (the header block's fields, the HTTP/1.1 head
  made of them, its parse) and what its last answer head was encoded to; the
  same input again gets the kept result, made by the same checks. Nothing
  is kept from a block that changed a compression table or a head that
  failed its checks. A repeated request costs 44% less of the server on
  HTTP/2 (below h2o's) and 30% less on HTTP/3.
- **HTTP/3:** a client's Initial is acknowledged at once, before the
  handshake's signature (RFC 9000 13.2.1): its first RTT sample no longer
  holds its pacing at our signing time for the whole connection (ngtcp2
  clients stalled ~1 ms at a time when handshakes waited for one worker);
  MAX_STREAMS counts a stream done when its answer is complete, as HTTP/2
  does, so a client never waits for the acknowledgement of answers it has
  (256 stream entries a connection). baseline-h3: 1.29M -> 1.47M req/s on
  8 cores.
- **HTTP/2, HTTP/3:** a request's path 16% shorter in instructions; a
  repeated Huffman string (a client's :path, which encoders never index)
  copied, not decoded; static tables looked up by hash.
- **HTTP/1.1:** the strict parser checks the method, the target and field
  names 32 bytes at a time.
- **epoll:** a listening socket for each worker (SO_REUSEPORT): on 64 cores
  short-lived connections had every worker try one contended accept queue;
  a read of the client that came short is not followed by one that can only
  say EAGAIN; held requests (handler holds, `fault delay=`) answered on time,
  waits to the microsecond with epoll_pwait2 (Linux 5.11+).
- **gzip:** about twice as fast for the same output: the hash is no longer
  cleared for each answer, matches are compared eight bytes at a time, codes
  come from tables and go out in one write, CRC-32 eight bytes a step.

### Fixed

- **epoll:** a request body that came while its backend was connecting was
  never read: the request hung until the client gave up.
- **mirror:** a copy whose shadow was still connecting lost the body that
  came meanwhile.
- **QUIC:** answers batched with a path MTU probe larger than the path were
  lost until the loss timer found them (a 10 ms stall a few times a second);
  timers to the microsecond.

## 0.2.0 — 2026-11-20

Much faster over TLS, HTTP/2 and HTTP/3, handler modules, files kept in
memory, and the fixes the external conformance suites (tlsfuzzer, h2spec,
h3spec, RFC 9111 cache tests) asked for. No configuration from 0.1.0 has to
change.

### Install

```sh
curl -fsSL https://raw.githubusercontent.com/Lu4nScr1pt1ng/okena/v0.2.0/scripts/install.sh | sh
docker run -p 8080:8080 ghcr.io/lu4nscr1pt1ng/okena:0.2.0
```

Or download `okena-0.2.0-linux-x86_64.tar.gz` below and check it against its
`.sha256`.

### New

- **Handler modules:** code assembled into okena itself
  (`make MODULES="a.inc b.inc"`, `route ... { handler NAME }`), as nginx's
  modules are compiled into nginx: request bodies up to 1 MiB over HTTP/1.1,
  HTTP/2 and HTTP/3, answers held on okena's timers, the route's compression,
  head lines and trailers of the handler's own (gRPC's `grpc-status`).
- **`files ... memory=SIZE`:** the files a route serves kept in memory, one
  store shared by every worker (one copy however many CPUs), sent from there
  without a copy, a small file in the same TLS record as its head.
- **`okena { date on|off }`:** the Date field okena writes (on by default, as
  RFC 9110 asks).
- **Cache:** a stale copy with a validator is revalidated (304 freshens it);
  `Vary` on fields `vary=` does not name keeps one variant; Age, Date and
  Expires as RFC 9111 counts them; invalidation; `CDN-Cache-Control`.
- **TLS:** `cert ... missing=skip` (a listener opened only when its files are
  there); `reload on-change` watches certificates and keys too.
- **Memory guard:** near the cgroup's memory limit, new streams are refused
  and idle connections closed before the kernel's OOM killer acts.

### Faster

- **HTTP/1.1:** answers to pipelined requests go out together, one write
  (16 at a time: 6x); a read is handled right after its event, while its
  bytes are in the cache.
- **epoll:** a new connection wakes one worker instead of every idle one (64
  workers: short-lived connections were at a third of their rate); sockets
  written with send, past the files' layer.
- **io_uring:** what a completion delivers is taken at once, not after the
  whole batch (HTTP/2: up to 19% more).
- **HTTP/2:** HPACK's dynamic table on the way out; END_STREAM on the body's
  last DATA frame; a batch's HEADERS first, then its DATA (a client decodes
  them in one run: 6% fewer of its cycles an answer); a small body okena
  answers itself goes without content-length (RFC 9113 8.1.1), kept for a
  HEAD, a larger body and a backend's answer; on epoll a full connection
  buffer is written at once and the stream goes on; handler answers written
  in a per-worker area.
- **HTTP/3:** QPACK's dynamic table on the way out; the answers in the
  datagram that carries the ACK (half the datagrams); frame lengths in as
  few bytes as they take; many answers in a datagram; large datagrams where the path takes them (path MTU probing up
  to 60000 bytes), segmented sends of one size; a send batch's datagrams one
  after another; a stream's send state kept with its connection; bodies from
  the memory store not copied into the send ring.
- **TLS:** RSA signatures by CRT with a fixed window (4x); records sealed in
  a per-worker area and written at once on epoll; AES-GCM sealing in one
  pass (AES and GHASH interleaved) on CPUs without VAES.

### Fixed

- **QUIC:** a worker could crash under load when loss detection followed an
  ACK; CONNECTION_CLOSE sent again to a packet that comes while closing;
  a lost packet of the QPACK decoder stream sent again (after one loss the
  client stopped using its table for the rest of the connection); a
  client's unidirectional stream opened after a higher one is read (its
  QPACK inserts were dropped); transport parameters, frames and TLS messages checked as RFC 9000 and
  9001 ask; HTTP/3 control, QPACK and request stream rules (h3spec 85/85).
- **TLS:** alerts where RFC 8446 asks for them (protocol_version,
  missing_extension, illegal_parameter...), a client's KeyUpdate,
  compress_certificate checked, 0-RTT before a HelloRetryRequest skipped, a
  Finished arriving in pieces, P-256 key shares checked (tlsfuzzer).
- **HTTP:** Date on okena's own heads, strict chunk extensions, 400 for
  request content codings; WebSocket over an https listener; a broken h2c
  preface closed.

### License

okena is now under the **Apache License 2.0** (`Apache-2.0`), from AGPL-3.0-only:
use, modify and embed it anywhere, commercially too, with an explicit patent
grant. 0.1.0 stays as it was published (AGPL-3.0-only).

## 0.1.0 — 2026-11-19

The first release: one static binary of about 1 MB for Linux on x86-64, no
libc and no dependencies, and a container image built `FROM scratch`.

### Install

```sh
curl -fsSL https://raw.githubusercontent.com/Lu4nScr1pt1ng/okena/v0.1.0/scripts/install.sh | sh
docker run -p 8080:8080 ghcr.io/lu4nscr1pt1ng/okena:0.1.0
```

Or download `okena-0.1.0-linux-x86_64.tar.gz` below and check it against its
`.sha256`. Linux 6.1 or later (6.12 LTS for every feature); io_uring is used
when the kernel allows it, epoll otherwise.

### What it does

- **Load balancing (L4 and L7):** TCP and UDP proxying; least-request (the
  default), peak-EWMA, round-robin, least-connections, random, Maglev, ring
  hash and source hash; weights, backups, slow start, bounded loads;
  zone-aware balancing (`okena { zone }`, endpoints' zones from Kubernetes);
  active health checks (TCP, HTTP, gRPC, UDP, with `send=` and `match=`),
  outlier ejection, retry budgets, adaptive concurrency, sticky sessions;
  PROXY protocol v1/v2 in and out; XDP balancing with direct server return.
- **Reverse proxy:** HTTP/1.1, HTTP/2 and HTTP/3 to clients; HTTP/1.1, HTTP/2
  and FastCGI to backends; routing by host, path, regular expression, method,
  header, query, cookie, client address, country, ASN or TLS fingerprint
  (JA4); rewrites, redirects, static files with sendfile (and directory
  listings with `browse=on`), PHP-FPM, WebSocket, gRPC and gRPC-Web,
  gzip/Brotli/zstd compression, caching in memory and on disk.
- **API gateway:** JWT (ES256/384, RS256/384/512, PS256/384/512, EdDSA,
  HS256; JWKS by URL), API keys, Basic (bcrypt files too), mTLS, forward
  auth with login redirects; rate limits and quotas (per client, key, user
  or claim; shared across a fleet; `RateLimit-*` headers); CORS; idempotency
  keys; signed URLs; traffic splitting, mirroring, hedging, fault injection;
  addons in any language (Python, Go, Rust, C SDKs), proxy-wasm plugins,
  Envoy's ext_authz/ext_proc, a Coraza WAF, OIDC login, gRPC-JSON
  transcoding.
- **Forward proxy:** CONNECT tunnels to the destinations a route lists, with
  `Proxy-Authorization`; private and link-local addresses refused unless
  allowed.
- **TLS:** TLS 1.3 and 1.2 of its own, post-quantum key exchange
  (X25519MLKEM768), automatic certificates over ACME (HTTP-01, TLS-ALPN-01,
  DNS-01 with Cloudflare, Route 53 or RFC 2136), OCSP stapling, Encrypted
  Client Hello, SNI routing without decrypting, kTLS, TLS to backends.
- **Kubernetes:** Gateway API (HTTPRoute, GRPCRoute, TLSRoute, TCPRoute,
  UDPRoute) and Ingress, with ingress-nginx's common annotations (canary,
  auth-url, rewrite-target, ssl-redirect, CORS, limits...); a Helm chart.
- **Operations:** reloads and binary upgrades without dropping a connection;
  routes changed at runtime (CLI and HTTP API); service discovery (DNS, SRV,
  files, Docker, Kubernetes, Consul); Prometheus metrics and metrics pushed
  over OTLP; JSON access logs to files, syslog or OTLP; OpenTelemetry tracing
  (W3C Trace Context and B3); a live dashboard; alerts to webhooks, Slack and
  Telegram; systemd notify and socket activation.
- **Safety:** each kind of process under its own seccomp filter (no
  `execve`, no executable memory), privileges dropped, Landlock around files,
  strict HTTP parsing, a watchdog and a quarantine for requests that crash a
  worker.

See [docs/BENCHMARK.md](docs/BENCHMARK.md) for how it compares with HAProxy,
nginx, Envoy, Traefik and Caddy.
