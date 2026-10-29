# Architecture

okena is an L4/L7 load balancer, reverse proxy and API gateway written in
x86-64 assembly (fasm2) for Linux. One static binary, no libc, no runtime.
This document records how it is built and why. What gets built when is in
[ROADMAP.md](ROADMAP.md); how it is configured is in [CONFIG.md](CONFIG.md).

## Goals, in order

1. **Never stall.** No request waits on a lock, a blocking syscall, an
   allocation or another core. A slow backend, a slow client, a reload or a
   traffic spike degrades only the traffic that caused it.
2. **Survive monstrous spikes.** Every resource has a fixed ceiling reserved
   up front; past it, okena sheds load early and cheaply instead of
   queueing. Latency of the traffic it accepts stays flat.
3. **Latency first, then throughput.** p99 and p99.9 are the numbers we
   optimise; median and req/s follow from removing work.
4. **Pay only for what you use.** A plain TCP balancer runs none of the
   HTTP code; a route without auth runs no auth code. Configuration is
   compiled, not interpreted.
5. **Correct and safe by construction.** Strict parsing, explicit limits,
   isolated processes, verified crypto.

## Modes

Every listener picks the cheapest engine that does the job:

| Engine | What it does | Data path | Per-connection cost |
|---|---|---|---|
| `xdp` | L4 balancing in the NIC driver, Maglev hashing, IPIP/GUE encapsulation, direct server return | eBPF in the kernel, no socket at all | none (flow table entry) |
| `tcp` / `udp` | L4 proxy: terminates TCP, picks a backend, moves bytes | sockmap redirect in the kernel when possible, otherwise io_uring splice | two sockets, ~256 B state |
| `tls-passthrough` | L4 routing by SNI/ALPN, no decryption | peek ClientHello, then like `tcp` | as `tcp` |
| `http` | L7 proxy and gateway: HTTP/1.1, HTTP/2, HTTP/3, WebSocket, gRPC | io_uring, kTLS, zero-copy body forwarding | ~256 B idle, buffers only while active |

An application that only needs `tcp` gets a balancer that never parses a
byte of its traffic.

## Process model

```
supervisor (PID 1 in a container, or under systemd)
 ├─ owns all listening sockets (SO_REUSEPORT, one per worker per listener)
 ├─ compiles the configuration into an immutable plan (memfd, sealed)
 ├─ worker 0 ── pinned to CPU 0 ── its own io_uring, memory, upstream connections
 ├─ worker 1 ── pinned to CPU 1
 ├─ ...
 ├─ logger   ── drains access-log rings, writes files/stdout/OTLP
 ├─ resolver ── DNS and service discovery, publishes backend sets
 └─ (optional) acme ── certificate issuance and renewal
```

The design carries over what was measured in fasm2crud: shared-nothing
worker processes, one ring each, supervisor holding the listeners so a
crashed worker loses no queued connection, graceful drain on SIGTERM,
`PR_SET_PDEATHSIG`. A shared accept queue measured 4x worse there and is
not used.

**Connection steering.** A `SO_ATTACH_REUSEPORT_EBPF` program picks the
worker whose CPU received the packet (`SO_INCOMING_CPU`/RX queue), so a
connection's interrupts, softirq, socket and worker share one core and its
cache. With RSS/aRFS configured on the NIC, a flow never crosses cores.
For QUIC the same program routes by connection ID (QUIC-LB format), so
migrated clients land on the worker that owns their connection.

## No locks, anywhere on the request path

This is the rule the rest of the design follows from.

| Shared thing | How it is shared without a lock |
|---|---|
| Configuration | Immutable plan in a sealed memfd. A reload maps a new generation and each worker switches its pointer at the top of its loop (RCU by quiescent state: a worker between iterations holds no reference). Connections keep the generation they started on; a generation is unmapped when its count drops to zero. |
| Backend sets (DNS, discovery, health) | Same mechanism: the resolver publishes a new immutable set, workers swap at loop top. Health state for the set is a per-backend word written by one owner only. |
| Statistics | Per-worker counters and histograms, plain stores, in a per-worker shared page. Readers (`/metrics`, `okena top`) sum across workers. Torn reads are avoided with a sequence counter per block (seqlock where the writer never waits). |
| Access logs | One single-producer/single-consumer ring per worker to the logger. When it is full the line is dropped and counted; the worker never waits for the disk. |
| Global rate limits | Token leases: a shared table of buckets (open addressing, 64-byte aligned, one bucket per cache line). A worker takes a batch of tokens with one `lock xadd` and spends them locally; the atomic is paid once per batch, not per request. Lease size adapts to the key's rate so hot keys stay accurate. |
| Caches (HTTP cache, JWKS, TLS tickets) | Per worker. A response cached on one worker is not looked up on another; cross-worker hit rate is traded for zero contention. Request coalescing works per worker. |
| Supervisor ↔ worker control | Messages over a socketpair read through the worker's own ring. |

The only atomics in the process are lease refills, plan reference counts
and the seqlock counters, none of which a request waits on.

**Nothing blocks the loop.** All I/O goes through io_uring, including file
reads (static files, certificates on reload), timers, signals (signalfd)
and DNS. Work that is slow by nature runs elsewhere: certificate issuance
in the acme process, log formatting and writing in the logger, config
compilation in the supervisor. TLS handshakes run inline but are
budgeted (see below).

## Surviving spikes

A spike has to be absorbed or refused in microseconds, without a cascade.

* **Everything is preallocated as address space.** Connection slots,
  buffers, upstream connections, h2 streams, timers: each pool is reserved
  once at its maximum (`mmap` with `MAP_NORESERVE`, guard pages) and made
  resident on demand. No `malloc`, no growth, no fragmentation, no page
  table work under load beyond first touch. Pools are LIFO so the warmest
  item is reused first, and idle tails go back to the kernel
  (`MADV_DONTNEED`) when the load is gone, as in fasm2crud. Hot pools use
  2 MiB pages (THP `madvise`) to cut TLB misses.
* **Admission before work.** The order of checks follows cost: XDP/eBPF
  drop list and per-source SYN rate (optional) → kernel SYN cookies →
  per-source connection limit at accept → TLS handshake budget → request
  limits → route rate limit → backend concurrency limit. A request that
  will be refused is refused at the cheapest layer that knows it.
* **Overload manager.** Each worker tracks its own pressure: free
  connection slots, free buffers, loop lag (TSC time between iterations),
  handshake debt. Pressure levels switch on measures in steps, all
  reversible with hysteresis:
  1. shorten keep-alive idle timeout, stop accepting h2 streams beyond a
     lower limit;
  2. disable TLS full handshakes for new clients in favour of resumptions,
     send `Connection: close` after responses;
  3. reject new requests on low-priority routes with 503 + `Retry-After`;
  4. stop accepting new connections (the kernel queue and SYN cookies take
     over).
* **Queues are bounded in time, not only size.** Requests waiting for an
  upstream connection or a concurrency slot use CoDel-style management:
  when the queue's minimum sojourn time stays above target (default 5 ms)
  for an interval, waiting requests are failed fast and LIFO admission
  kicks in, so the freshest clients (the ones still waiting) are served.
* **Adaptive concurrency per pool.** A gradient limiter (as in Netflix
  concurrency-limits / Envoy adaptive concurrency) measures the backend's
  minimum RTT and grows or shrinks the in-flight limit so the backend is
  kept just below its saturation knee. A spike becomes fast 503s at the
  edge instead of a collapsed backend.
* **Retry budgets.** Retries are capped as a fraction of live traffic
  (default 20%) plus a small floor, per pool. A spike can never multiply
  itself through retries.
* **Priorities.** Routes carry a priority class (`critical`, `normal`,
  `bulk`). Shedding, queue admission and h2 scheduling respect it, so
  login and checkout survive when the image thumbnailer is shed.
* **Slow peers cost a fixed amount.** Read/write deadlines, header and
  body progress deadlines, total deadlines for borrowed buffers; flow
  control in both directions, so a slow client pushes back on its backend
  stream instead of making okena buffer it.
* **Handshake budget.** Full TLS handshakes cost ~100x a request. Each
  worker spends at most a configured share of each loop iteration on
  asymmetric crypto; the rest wait in a bounded queue with deadlines.
  Resumed sessions skip the queue. A handshake flood degrades new-client
  latency, never existing connections.

## Latency

A proxy's latency is what it adds on top of the backend. The budget we
design for, measured on loopback with pinned cores and open-loop load
(numbers to beat, checked by `okena bench` in CI):

| Path | Added p50 | Added p99 | Added p99.9 |
|---|---|---|---|
| `tcp` mode, first byte through an open connection | < 5 us | < 15 us | < 50 us |
| `http` h1 keep-alive, no filters | < 10 us | < 30 us | < 100 us |
| `http` with TLS (kTLS), auth and rate limit | < 20 us | < 50 us | < 150 us |

These hold up to the knee of the throughput curve; past it the overload
manager sheds instead of letting queues (and the tail) grow. What buys
them:

* **No queues inside okena.** A request is parsed, routed and written to
  the upstream in the same loop iteration its bytes arrived in. There is
  no hand-off between threads, no internal channel, no wake-up of another
  core.
* **Stream, never store-and-forward.** Headers go upstream as soon as they
  are parsed; body bytes follow as they arrive; response bytes go to the
  client as they arrive. Time to first byte is not tied to body size.
  Buffering a whole body happens only when a feature needs it (retrying a
  request with a body, caching), and is bounded.
* **Warm upstream connections.** Keep-alive pools with LIFO reuse,
  pre-connect to a configurable minimum per backend (`warm`), TCP Fast
  Open and TLS resumption towards backends, happy eyeballs for dual-stack.
  A request never pays a connect it could have avoided.
* **Socket settings for latency:** `TCP_NODELAY` everywhere, `TCP_QUICKACK`
  after reads that expect a quick reply, `TCP_NOTSENT_LOWAT` so the kernel
  does not hoard unsent data, `SO_BUSY_POLL`/NAPI polling in the latency
  profile, `IP_TOS`/DSCP passthrough, BBR on client-facing sockets where
  the kernel offers it.
* **Fewer syscalls, not faster ones.** One `io_uring_enter` per iteration
  for everything; completions reaped in budgets so a burst on one
  connection cannot delay the others by more than one budget.
* **Predictable CPU.** Workers pinned, no migration; interrupts for a
  queue on the same core as its worker; `SCHED_FIFO` optional; hot code
  and data laid out by cache line; no page faults on the hot path once
  warm (pools prefaulted up to their warm reserve); no syscalls for time
  (TSC, vDSO).
* **Tail-cutting features:** request hedging (send a second copy after the
  pool's p95 for idempotent routes, cancel the loser), `peak-ewma`
  balancing that steers away from a backend before it times out, outlier
  ejection, and h2 upstream multiplexing so one slow response never blocks
  another (no head-of-line blocking above TCP).
* **Measured, always.** Every log line carries queue, connect, TLS, upstream
  first byte and total time; histograms per route and backend expose the
  tail; `okena bench` reports p50/p99/p99.9/max corrected for coordinated
  omission. A change that moves p99 is visible in the benchmark job.

## I/O: io_uring

Inherited from fasm2crud (`SINGLE_ISSUER`, `DEFER_TASKRUN`, `SUBMIT_ALL`,
`NO_SQARRAY`, registered ring fd, multishot accept into direct
descriptors, one `io_uring_enter` per iteration, budgeted reaping,
adaptive busy polling timed by the TSC), plus what a proxy needs:

* **Provided buffer rings with incremental consumption** for reads, and
  **recv/send bundles** to move several buffers per completion. A proxy
  holds many idle keep-alive connections, so unlike fasm2crud a connection
  does not own an input buffer while idle: it costs its ~256-byte header
  and a buffer is attached only when bytes arrive. One million idle
  connections is ~256 MB, not 16 GB.
* **Zero-copy forwarding.** Bodies and L4 streams are not copied through
  user space when they do not need to be inspected:
  * `sockmap`/`sk_msg` redirect for `tcp` mode (bytes go socket to socket
    inside the kernel);
  * `splice` through a per-worker pipe pool otherwise;
  * `SEND_ZC` for large writes from our buffers (threshold measured, about
    16 KiB; below it a copy is cheaper than the notification);
  * zero-copy receive (`zcrx`) with NIC header/data split, where the NIC
    supports it.
* **kTLS.** The handshake runs in okena; the session keys are then handed
  to the kernel (`TLS_TX`/`TLS_RX`). Records are encrypted in the kernel
  (or on the NIC with TLS offload), so splice, sendfile and zero-copy work
  for TLS traffic too. Ciphers the kernel lacks, and key updates the
  kernel cannot take, fall back to user-space records.
* **NAPI busy polling** registered on the ring (`IORING_REGISTER_NAPI`)
  for the latency profile: the worker polls the NIC queue it is pinned to
  instead of waiting for an interrupt.
* **UDP:** GSO/GRO, `recvmsg` multishot, `SO_TXTIME` pacing for QUIC.
* Kernel features are probed at startup; each one has a fallback, and
  `okena check --host` reports which are active.

Target kernel: 6.12 LTS or newer for the full feature set; 6.1 runs with
fallbacks (no incremental buffers, no bundles, no zcrx).

## Memory layout

* Connection header: 256 bytes, one cache line for the hot fields (state,
  flags, deadlines, ring indices), the rest cold.
* Buffers: 16 KiB (one TLS record plus headroom) from the provided ring;
  large buffers (128 KiB) on loan with total deadlines.
* Upstream connections live in per-worker, per-backend LIFO free lists
  (most recently used first: warm in the backend's cache too). Idle ones
  are closed after `idle_timeout`, so N workers do not keep N times the
  connections a backend needs.
* Strings in the plan (hosts, header names, paths) are interned; routing
  compares indices, not bytes.
* Every worst case is checked at assembly time, as in fasm2crud.

## Request path (http engine)

```
recv bundle ─▶ TLS (kTLS) ─▶ parse (SIMD) ─▶ route (compiled) ─▶ filters ─▶ balance ─▶ upstream
                                                                    │            │
                                         early reject (4xx/429/503) ◀┘            └▶ retry / hedge / mirror
```

* **Parsing** is strict RFC 9110/9112 with AVX2 scanning (AVX-512 when
  present), resumable, linear in input. Unlike fasm2crud a proxy must
  accept `Transfer-Encoding: chunked`, so smuggling is prevented by the
  rules instead: CL and TE together → 400; TE other than a single final
  `chunked` → 400; obs-fold, bare LF, bare CR, NUL, whitespace before `:`
  → 400; requests are re-serialised to the upstream from the parsed form,
  never forwarded as raw header bytes. Differential fuzzing against other
  parsers keeps it honest.
* **Routing** is compiled per listener into a decision structure: exact
  host hash → wildcard host suffix trie → per-host path radix tree (static
  segments, `{params}`, `*` tails) → method bitmask → header/query
  predicates ordered by cost. No regular expressions in the default path;
  `regex` exists, compiled to a DFA at load time, with a size limit.
* **Filters** are a fixed, compiled list per route (auth, limit, rewrite,
  CORS, cache, ...). A route without filters calls none.
* **Headers out** are written once into the upstream buffer: hop-by-hop
  headers dropped, `Forwarded`/`X-Forwarded-*` set from the trusted-proxy
  policy, request ID and `traceparent` added, rewrites applied.
* **Responses** stream back with flow control; small ones are batched with
  pipelined responses into one send.

### HTTP/2

HPACK with table-driven Huffman, RFC 9218 priorities, independent flow
control per stream, upstream multiplexing (one h2 connection to a backend
carries many client requests, which matters for gRPC). Abuse limits are
part of the protocol code, not an add-on: rapid reset (CVE-2023-44487),
CONTINUATION flood, HPACK bombs, SETTINGS/PING/PRIORITY floods, empty
DATA frames, window-zero stalls — each counted per connection with a
cost model that closes the connection when it exceeds its budget.

### HTTP/3 and QUIC

QUIC v1 and v2, connection IDs encoding the worker (QUIC-LB), stateless
retry under load, address validation tokens, CUBIC and BBR, pacing, GSO,
ECN. 0-RTT off by default and, when on, only for routes marked idempotent.

## TLS

* TLS 1.3 first; TLS 1.2 (ECDHE + AEAD only) for clients that need it.
* Key exchange: **X25519MLKEM768** (post-quantum hybrid, default),
  X25519, P-256.
* AEAD: AES-128/256-GCM (AES-NI, VAES + VPCLMULQDQ), ChaCha20-Poly1305
  (AVX2), chosen by client preference and hardware.
* Certificates: ECDSA P-256 and Ed25519 signing first; RSA-PSS signing
  later. Verification of RSA, ECDSA and Ed25519 for upstream TLS and
  client certificates, with an X.509 path validator restricted to what
  WebPKI needs.
* SNI selects the certificate; ALPN picks h2/http/1.1; resumption with
  tickets encrypted under keys rotated every hour and shared across
  workers through the plan (read-only, so no lock).
* ACME (RFC 8555) with HTTP-01 and TLS-ALPN-01, in its own process.
* All secret-dependent code is constant time; crypto is tested against
  known-answer vectors, Wycheproof, and differential runs against a
  reference library, as fasm2crud already does for SHA-256 and Argon2.

## Load balancing

| Algorithm | When |
|---|---|
| `least-request` (power of two choices, weighted) | default for http; no herding, O(1) |
| `peak-ewma` | latency-sensitive pools; picks by in-flight x decayed latency |
| `round-robin` (smooth weighted) | uniform backends, predictable spread |
| `maglev` / `ring-hash` with bounded load | affinity by header, cookie, path or source |
| `source-hash`, `random` | L4 and simple cases |
| `least-conn` | long-lived connections (WebSocket, tcp) |

* Health: active (TCP, HTTP, gRPC health, TLS handshake), passive outlier
  detection (consecutive 5xx/gateway errors, success-rate ejection, with
  a maximum ejected share so a bad check cannot empty a pool), slow start
  for recovered and new backends, panic mode (use all backends when too
  few are healthy).
* Locality: prefer backends in the same zone while they have capacity.
* Active health checks are spread so that each backend is checked once per
  interval by the whole process, not once per worker; results are
  published like any backend set.
* Discovery: static, DNS (A/AAAA/SRV with TTL; okena has its own async
  resolver), files watched through inotify, the admin API; Docker, Consul
  and Kubernetes endpoints later.

## Gateway features

Authentication (JWT with JWKS for HS/RS/PS/ES/EdDSA, API keys hashed in
the plan, Basic, mTLS identity, forward-auth to an external service),
rate limiting (GCRA, local or global through leases, keyed by any request
attribute), quotas, CORS, header and path rewrites, redirects, request and
response size limits, IP allow/deny with an LPM trie, HTTP caching (RFC
9111, per worker, with coalescing and stale-while-revalidate), compression
(precompressed variants, fast gzip/zstd/brotli later), traffic splitting
(weights, header/cookie overrides for canaries), mirroring, request
hedging for tail latency, early hints, static files, and maintenance
pages. Extensions are composed from built-in filters plus forward-auth;
there is no scripting runtime, because a scripting runtime is where
proxies lose their latency.

## Observability

* `/metrics` (Prometheus/OpenMetrics) on the admin listener: per listener,
  route, pool and backend; latency as log-linear histograms (HDR style,
  under 1% error) kept per worker and merged on scrape.
* Access logs (JSON or logfmt, field list configurable), sampled or full,
  through the logger process.
* Tracing: W3C `traceparent` propagation, OTLP/HTTP export of spans with
  head and tail sampling.
* `okena top`: live terminal view reading the shared statistics pages.
* Timings in every log line: queue, connect, TLS, upstream first byte,
  total, so a slow request says where it was slow.

## Operations

* **Reload** (`SIGHUP`, `okena reload`, admin API): compile, validate, diff,
  swap. A config that does not validate is rejected and the running one
  stays. Listeners added or removed are opened/closed by the supervisor.
* **Binary upgrade** (`SIGUSR2`): the supervisor execs the new binary,
  hands it the listening sockets, and the old workers drain. No connection
  is refused during an upgrade.
* **Admin API** on a Unix socket by default (or an authenticated
  listener): status, drain/undrain a backend, change weights, reload,
  dump the effective configuration.
* **Tooling in the binary:** `okena check` (validate, with line:column
  errors and suggestions), `okena fmt`, `okena explain` (effective config
  with defaults), `okena route 'GET https://api.example.com/v1/users'`
  (which listener, route, filters, pool and backend a request would get),
  `okena bench` (open-loop load generator with coordinated-omission
  correction, built on the same engine).
* Containers from `scratch`, systemd unit with socket activation.

## Security

* Seccomp filter per process type, io_uring opcode restrictions
  (`IORING_REGISTER_RESTRICTIONS`), Landlock for the filesystem, privileges
  dropped after binding (or `CAP_NET_BIND_SERVICE` only), no writable and
  executable memory, guard pages around every pool.
* Private keys live only in workers' memory, mapped `MADV_DONTDUMP`, and
  are wiped on generation release.
* Trusted proxy lists decide whether `X-Forwarded-For` and PROXY protocol
  are believed.
* Fuzzing (HTTP/1, HPACK, h2 frames, TLS records, config parser, DNS) and
  conformance suites (h2spec, Autobahn for WebSocket, tlsfuzzer, QUIC
  interop runner) are part of `make test`.

## Platform

Linux x86-64, baseline x86-64-v3 (AVX2, BMI2, AES-NI, PCLMULQDQ). VAES,
VPCLMULQDQ, SHA-NI and AVX-512 paths are chosen at startup through CPUID.
The development machine (Ryzen 7 5700G, Zen 3) has VAES/VPCLMULQDQ at 256
bits and SHA-NI but no AVX-512, so AVX-512 paths are tested on other
hardware or under Intel SDE.

## Source layout

```
src/main.asm
src/sys/      syscall numbers, io_uring, bpf, socket and kTLS definitions
src/core/     supervisor, worker loop, ring, pools, timer wheel, time (TSC/vDSO), stats, overload
src/config/   lexer, parser, validator, compiler to the plan, diff
src/net/      listeners, addresses, PROXY protocol, DNS resolver, discovery
src/l4/       tcp/udp proxy, splice, sockmap control, SNI peek
src/http/     h1, h2, hpack, h3, qpack, router, response writer
src/tls/      records, handshake, x509, ktls, tickets, acme
src/quic/     packets, streams, recovery, congestion control
src/crypto/   sha2, hmac, hkdf, aes-gcm, chacha20-poly1305, x25519, ml-kem, p256, ed25519, rsa
src/lb/       algorithms, health, outlier detection, concurrency limits
src/gw/       auth, rate limits, cors, cache, rewrites, mirror, hedging
src/bpf/      eBPF programs (reuseport steering, sockmap, XDP), assembled by fasm2 macros
src/admin/    admin API, metrics, top
tests/        unit, kat, fuzz, conformance, integration, bench
```

The eBPF programs are written in assembly too: fasm2 macros emit BPF
instructions, and okena loads them with `bpf(2)`. No clang, no libbpf.
