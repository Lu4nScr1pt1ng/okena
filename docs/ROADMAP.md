# Roadmap

Phases 0-3 make the first product: an L4 and HTTP/1.1 balancer with TLS
that runs anywhere, Docker included. Everything after builds on code that
already carries traffic.

Every case in [EDGE_CASES.md](EDGE_CASES.md) that a phase touches is a
test in that phase.

Each phase ends with something usable in production for its scope, and
with its exit criteria met: tests, fuzzing, and a benchmark against the
established proxy for that job, on the same machine, cores pinned,
open-loop load, p50/p99/p99.9 reported. A phase that loses on latency to
the reference is not finished.

References used for comparison: HAProxy 3.x (L4 and HTTP/1), nginx
(HTTP/1, static), Envoy (h2, gRPC, gateway features), Katran (XDP).

## Phase 0 — Foundation

* Repository, pinned fasm2 toolchain, `make`, `make test`, CI.
* Core carried over from fasm2crud and generalised: supervisor, worker
  per CPU, io_uring loop, pools with trimming, seccomp, stats pages.
* Timer wheel (hierarchical, O(1)), TSC/vDSO time, CPUID dispatch,
  kernel feature probing (`okena check --host`).
* Configuration: lexer, parser, validator with suggestions, compiler to
  the sealed plan (in a compiler child); `okena check`, `okena fmt`,
  `okena explain`; last good configuration kept.
* Worker heartbeat watchdog and query-of-death quarantine.
* Provided buffer rings with incremental consumption, recv/send bundles.
* Test harness: unit tests in assembly, Python integration runner,
  `okena bench` (open loop, coordinated-omission corrected).
* Two I/O engines from day one: io_uring and epoll, same code above them,
  both in CI.
* Container awareness: cgroup CPU quota and memory limit, `scratch`
  image, seccomp profile, `okena health`, `okena check --host`.
* Benchmark topologies: netns/veth on one host (CI) and two hosts over a
  real NIC; measure the no-op forwarding floor and set the latency targets
  as floor + X.

Exit: a worker echoes TCP at line rate on both engines; 1M idle
connections fit in the memory budget; config errors point at the right
line; the image runs under Docker's default profile (epoll) and with the
okena profile (io_uring), and the startup line says which.

## Phase 1 — L4

* `tcp` and `udp` listeners, pools, `round-robin`, `least-conn`,
  `source-hash`, `maglev`, `random`.
* Data path: copy through provided buffers, splice through a pipe pool,
  and sockmap via an eBPF program assembled by fasm2 — measured against
  each other, default chosen per message size; half-close handled.
* Names as backends (async resolver, `/etc/resolv.conf`, TTLs), so
  `to db:5432` works in compose.
* Upstream port management (`IP_BIND_ADDRESS_NO_PORT`, source addresses),
  `TCP_USER_TIMEOUT`, connect rate limits.
* Hot-worker detection and steering away from overloaded workers.
* TCP health checks, passive failure detection, backup servers.
* PROXY protocol v1/v2 in and out, trusted sources.
* Reuseport eBPF steering by CPU.
* Overload manager v1 (slots, loop lag), per-source connection limits.
* Graceful drain, reload of pools and listeners.
* `make chaos`: workers killed and stopped, backends killed and
  black-holed, netem loss/delay, port and memory exhaustion.

Exit: beats HAProxy `mode tcp` on added latency and connections/s per
core; reload under load drops nothing; chaos suite passes (backend
killed, black-holed without RST, slow, refusing, port range exhausted).

## Phase 2 — HTTP/1.1 reverse proxy

* Strict parser with chunked support and smuggling rules; serialiser.
* Compiled router (host hash, wildcard trie, path radix, predicates).
* Upstream keep-alive pools with warm connections, LIFO reuse.
* `least-request` (P2C), `peak-ewma`; HTTP health checks; outlier
  ejection; slow start; panic mode.
* Timeouts, retries with budgets, CoDel queueing, adaptive concurrency.
* Header rewrites, `Forwarded`/`X-Forwarded-*`, request IDs, redirects.
* WebSocket upgrade (then L4 splicing for the upgraded stream).
* Strict response parsing (HEAD, 1xx, 204/304, close-delimited), the
  keep-alive reuse race handled.
* Access logs through the logger process; `/metrics`.
* Differential fuzzing of the parser; smuggling test corpus.

Exit: beats HAProxy and nginx on added p99 for h1 keep-alive; survives a
10x spike above capacity with flat latency for admitted traffic and fast
503s for the rest; no smuggling case in the corpus passes.

## Phase 3 — TLS

Progress: `src/crypto/` has SHA-256 (SHA-NI, and a scalar path for
CPUs without it, picked by CPUID), HMAC, HKDF and the TLS 1.3
HKDF-Expand-Label, X25519 (constant time; mulx/adcx/adox, the ladder in
OpenSSL's order; 25.6 us, as fast as OpenSSL 3.5 on the same machine)
and AES-128-GCM (AES-NI and PCLMULQDQ; in place with the tag
after the record, the tag checked in constant time before anything is
decrypted) and P-256 ECDSA (deterministic nonces, RFC 6979; a fixed-base
table of 37 Booth windows with constant-time selection and Jacobian mixed
additions, a P-256-shaped Montgomery multiply and square on ADX, the
nonce's inversion blinded; 15.6 us per signature, as fast as OpenSSL 3.5
on the same machine), all checked by `tests/kat`
against the published vectors and reference implementations (the
signatures byte for byte against the cryptography package).
`tls { cert FILE; key FILE }` loads a PEM chain (leaf first) and its EC
P-256 key (SEC 1 or unencrypted PKCS #8), and `okena check` refuses RSA,
other curves, encrypted keys, broken PEM and a key that does not match the
certificate (`tests/tls`); until the handshake exists okena refuses to
serve such a listener rather than serve it in plaintext. The TLS 1.3
server handshake (`src/tls/handshake.inc`: x25519, AES-128-GCM, ECDSA
P-256, ALPN, middlebox compatibility) and user-space records pass
`tests/tls/handshake.py` through an echo harness, against OpenSSL,
`s_client` and curl: records split and dribbled, a forged Finished, and the
refusals with their alerts. `http` listeners serve HTTPS on both engines
(`src/http/tls.inc`, `tests/tls/https.py`): the handshake before the first
request, the client Finished taken with a peek so a request sent with it
stays in the socket, then kTLS (TCP_ULP, TLS_TX, TLS_RX; linked socket
commands on io_uring). On this machine, 4 workers, a route okena answers
itself: 284k requests/s over keep-alive HTTPS (406k plain), and ~75 us of
worker CPU per new HTTPS connection (wrk was the limit at 16k/s). Without
kTLS (no module, the kernel refusing the keys, or `OKENA_KTLS=off`) the
client side of the exchange goes through user-space records, sealed two
at a time, invisible to proxy.inc: 302k requests/s keep-alive (ahead of
kTLS for small answers), 755 MB/s on a 50 MB download against 933 with
kTLS (one AES block at a time for now). `tcp` listeners terminate TLS
too: the handshake on the same code, then the L4 session over kTLS
(both engines, `tests/tls/https.py`). A client that offers x25519 but
sends another group's share first gets a HelloRetryRequest (s_client and
curl with P-256 first). The ephemeral key comes from a fixed-base table
on the Edwards curve (`x25519_base`: 8.0 us against 26 us for the
ladder), and secrets are wiped 16 bytes a store: `tls_hello` takes 57 us
on a real ClientHello (`tests/tls/server.asm`, mode P). In the proxy, 4
workers, a new HTTPS connection each request, client on other cores:
77 us of user and 61 us of kernel CPU per connection. Session tickets
(stateless, AES-GCM under a key the supervisor makes before the workers
fork, so any worker resumes any ticket, and reloads keep it): issued in
the server's flight (the resumption secret needs only the client
Finished, known then), resumed with psk_dhe_ke (ECDHE still: forward
secrecy), binders checked, no certificate or signature, about 27 us of
worker CPU saved. AES-128-GCM runs eight blocks at a time (eight AES
pipelines side by side; GHASH by H^8..H^1 with one reduction): 4.3 GB/s
on 16 KiB records, from 1.84 (OpenSSL 3.5, VAES: 5.8); a 50 MB download
with user-space records went from 755 MB/s to 1.05 GB/s, level with
kTLS. Ticket keys rotate hourly in the supervisor: three slots on a page
shared with the workers, the new key written into the slot not in use,
then made current; tickets open under the current or the previous key.
Next: a ticket key file shared by a fleet, a VAES/VPCLMULQDQ path, then
phase 4.

* SHA-2, HMAC, HKDF (from fasm2crud), AES-GCM (AES-NI, VAES/VPCLMULQDQ),
  ChaCha20-Poly1305, X25519, ML-KEM-768, P-256 ECDH/ECDSA, Ed25519.
* TLS 1.3 server: X25519MLKEM768, SNI, ALPN, tickets with rotation,
  handshake budget.
* kTLS handoff, so splice and zero-copy work on TLS connections.
* `tls` listener (SNI routing, passthrough).
* TLS to upstreams: TLS 1.3 and 1.2 client, X.509 validation,
  RSA/ECDSA/Ed25519 verification, session resumption.
* TLS 1.2 server (ECDHE + AEAD) for older clients.
* Known-answer, Wycheproof and differential tests; constant-time checks;
  tlsfuzzer.

Exit: handshakes/s per core at or above OpenSSL-based HAProxy for ECDSA
certificates; kTLS steady state within a few percent of plaintext.

## Phase 4 — HTTP/2 and gRPC

* h2 downstream and upstream, HPACK, RFC 9218 priorities, flow control.
* Protocol translation h1 ↔ h2 in both directions; WebSocket over h2.
* Upstream multiplexing; gRPC routing, trailers, gRPC health checks,
  gRPC status mapping.
* Abuse limits (rapid reset, CONTINUATION, HPACK bomb, floods).
* h2spec clean; fuzzing of frames and HPACK.

Exit: beats Envoy on added p99 for gRPC unary and streaming.

## Phase 5 — Gateway

* JWT/JWKS (fetched by the control process), verified-token cache, API
  keys, Basic, mTLS identity, forward-auth with answer cache.
* Rate limits: GCRA per instance through leases, bounded key table with
  eviction under key floods; quotas.
* CORS, path rewrites, splits, mirroring, hedging, priorities.
* HTTP cache with coalescing and stale-while-revalidate.
* Static files and SPAs (fallback, ranges, ETag), precompressed variants,
  on-the-fly gzip/zstd for text, 103 Early Hints.
* Fault injection per route (`fault delay=`, `fault abort=`).
* OIDC login, idempotency keys, GeoIP, redirect maps, security header
  presets, `body raw` for signed webhooks, deploy hold.
* `okena route` dry-run.

Exit: each filter's added latency measured and documented; a route with
auth + limit stays within the latency budget in ARCHITECTURE.md.

## Phase 6 — Operations

* Binary upgrade with socket handoff; admin API and CLI.
* SRV/file discovery, Docker discovery by labels, Kubernetes
  EndpointSlices.
* Shared ticket keys and drain API for fleets.
* ACME (HTTP-01, TLS-ALPN-01, DNS-01 for wildcards) in its own process.
* Alerts (webhook, Telegram, Slack) from the control process.
* OTLP tracing; `okena top`.
* Landlock, privilege drop, systemd socket activation, container image.

Exit: a week-long soak with reloads and upgrades every minute under load
loses no request; `make chaos` passes with every dependency (DNS,
discovery, JWKS, ACME, control process, logger, disk) failed in turn.

## Phase 7 — Edge and CDN

* Disk cache tier: append-only segments, lock-free shared index, S3-FIFO,
  sendfile to the socket.
* Cache keys, `Vary` normalisation, slicing, `stale-if-error`, purge by
  URL/prefix/tag with fleet fan-out, `Cache-Status`.
* Shield tier, signed URLs, CDN provider ranges, authenticated origin
  pulls, health-driven BGP announcement (through BIRD).

Exit: hit path serves from page cache at line rate with zero copies;
origin load stays flat during a purge-and-refill storm.

## Phase 8 — Kernel fast paths

* `xdp` listener: Maglev in eBPF, IPIP/GUE encapsulation, DSR,
  connection tracking table, backend health from user space.
* XDP pre-filter for the other engines: drop lists, per-source SYN rate.
* zcrx zero-copy receive on supported NICs; NIC TLS offload.

Exit: packets/s per core comparable to Katran.

## Phase 9 — HTTP/3 and QUIC

* QUIC v1/v2, QUIC-LB connection IDs with eBPF steering, retry, recovery,
  CUBIC/BBR, pacing, GSO/GRO, ECN; QPACK; HTTP/3.
* QUIC interop runner clean.

## Phase 10 — Breadth

* TLS 1.2, RSA certificates (signing), client-certificate auth at scale.
* Brotli on the fly.
* Consul discovery, Kubernetes Gateway API.
* Certificate compression, Encrypted Client Hello.
* AVX-512 paths where they pay.

## Phase 11 — Addons

* Shared-memory addon protocol, supervision, deadlines, circuit breakers.
* SDKs (C, Rust, Go, Python); a reference WAF addon on Coraza.
* `ext_authz` / `ext_proc` adapter.

Exit: an addon that answers immediately adds under 5 us at p99; a crashing
or hanging addon never affects routes that do not use it.
