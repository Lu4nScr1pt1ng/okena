# Roadmap

Phases 0-3 make the first product: an L4 and HTTP/1.1 balancer with TLS
that runs anywhere, Docker included. Everything after builds on code that
already carries traffic.

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
  the sealed plan; `okena check`, `okena fmt`, `okena explain`.
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
* Static files with precompressed variants.
* `okena route` dry-run.

Exit: each filter's added latency measured and documented; a route with
auth + limit stays within the latency budget in ARCHITECTURE.md.

## Phase 6 — Operations

* Binary upgrade with socket handoff; admin API and CLI.
* SRV/file discovery, Docker discovery by labels, Kubernetes
  EndpointSlices.
* Shared ticket keys and drain API for fleets.
* ACME (HTTP-01, TLS-ALPN-01) in its own process.
* OTLP tracing; `okena top`.
* Landlock, privilege drop, systemd socket activation, container image.

Exit: a week-long soak with reloads and upgrades every minute under load
loses no request.

## Phase 7 — Kernel fast paths

* `xdp` listener: Maglev in eBPF, IPIP/GUE encapsulation, DSR,
  connection tracking table, backend health from user space.
* XDP pre-filter for the other engines: drop lists, per-source SYN rate.
* zcrx zero-copy receive on supported NICs; NIC TLS offload.

Exit: packets/s per core comparable to Katran.

## Phase 8 — HTTP/3 and QUIC

* QUIC v1/v2, QUIC-LB connection IDs with eBPF steering, retry, recovery,
  CUBIC/BBR, pacing, GSO/GRO, ECN; QPACK; HTTP/3.
* QUIC interop runner clean.

## Phase 9 — Breadth

* TLS 1.2, RSA certificates (signing), client-certificate auth at scale.
* Compression (gzip/zstd/brotli) on the fly.
* Consul discovery, Kubernetes Gateway API.
* Certificate compression, Encrypted Client Hello.
* AVX-512 paths where they pay.
