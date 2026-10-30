# Architecture

okena is an L4/L7 load balancer, reverse proxy and API gateway written in
x86-64 assembly (fasm2) for Linux. One static binary, no libc, no runtime.
This document records how it is built and why. What gets built when is in
[ROADMAP.md](ROADMAP.md); how it is configured is in [CONFIG.md](CONFIG.md).

It describes the design okena is heading for. Where the code already does
something differently from the plan, the text says so with **Today:**, so
this file never claims more than what runs. What works now is listed in
the README.

## Goals, in order

1. **Never stall, never fall over.** No request waits on a lock, a blocking syscall, an
   allocation or another core. A slow backend, a slow client, a reload or a
   traffic spike degrades only the traffic that caused it. Every
   component can fail; each failure stays inside its own unit and the
   rest keeps serving with the last state it knew.
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
| `tcp` + `tls passthrough` | L4 routing by SNI/ALPN, no decryption | peek ClientHello, then like `tcp` | as `tcp` |
| `http` | L7 proxy and gateway: HTTP/1.1, HTTP/2, HTTP/3, WebSocket, gRPC | io_uring, kTLS, zero-copy body forwarding | ~256 B idle, buffers only while active |

An application that only needs `tcp` gets a balancer that never parses a
byte of its traffic.

## Process model

```
supervisor (PID 1 in a container, or under systemd)
 ├─ owns all listening sockets (SO_REUSEPORT, one per worker per listener)
 ├─ runs a short-lived compiler child that validates the configuration
 │  before the supervisor compiles it; watches worker heartbeats
 ├─ worker 0 ── pinned to CPU 0 ── its own io_uring, memory, upstream connections
 ├─ worker 1 ── pinned to CPU 1
 ├─ ...
 ├─ logger   ── reads access-log lines from the workers, writes files/stdout
 ├─ control  ── DNS, service discovery, JWKS and other remote keys, active
 │              health checks; publishes immutable sets to the workers
 ├─ admin    ── admin API and /metrics, reads the workers' stats pages
 └─ (optional) acme ── certificate issuance and renewal
```

Nothing that serves a scrape, an admin call or a key fetch runs inside a
worker, so none of it can delay a request.

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

**Hot workers.** Affinity has a failure mode: one busy RX queue, or a few
huge clients, can overload one worker while the others idle. Each worker
publishes a pressure level in a BPF array map (one word, written by its
owner). When a worker is above its threshold, the steering program sends
its new connections to the least loaded worker instead. Long-lived
connections that pile up on one worker (h2, WebSocket) are rebalanced by
asking clients to reconnect: h2 `GOAWAY` after a stream count, WebSocket
never forcibly. When the NIC has fewer queues than workers, or no
steering program can be loaded, the kernel's reuseport hash is used.

**Cores, SMT and NUMA.** Worker count defaults to one per CPU the process
may use (affinity mask and cgroup quota, see Containers). The `latency`
profile uses one worker per physical core and leaves SMT siblings to
interrupts; which is better is measured per machine in phase 0. On
multi-socket machines each worker's pools are first-touched on its own
node, and workers prefer backends' connections created on their node.

## No locks, anywhere on the request path

This is the rule the rest of the design follows from.

| Shared thing | How it is shared without a lock |
|---|---|
| Configuration | An immutable plan, copied into each worker when it is forked. A reload does not change a running worker: it starts a new generation of workers on the new plan, and the old ones stop accepting and finish their connections. Nothing is shared, so nothing needs a lock or a reference count. (A plan in a sealed memfd swapped by quiescent state would let a reload keep the workers; it is not needed so far.) |
| Backend sets (DNS, discovery, health) | Same mechanism: the control process publishes a new immutable set, workers swap at loop top. Active health state is a per-backend word written only by the control process. |
| Passive health (outlier detection) | Each worker counts errors per backend in its own memory and ejects locally: 3 failed connects, or 5 failing answers in a row (5xx, no response head in time), take the backend out of that worker for 10 s, never more than half of a pool. **Today** there is no instance-wide sum yet; the plan is for the control process to sum the workers' counts every 100 ms, so 16 workers that each see 1/16 of the errors still eject quickly. |
| Pool-wide limits (`max` connections, `concurrency`) | Leases, like rate limits: a pool's limit is split into per-worker shares that move to the workers that need them. A pool limit means the whole instance, never per worker. |
| Statistics | Per-worker counters, plain increments in the worker's private memory; once a tick (1 s) the worker copies the block to its page of a shared table. Readers (`/metrics`, later `okena top`) sum across workers. Every counter is an aligned 64-bit word, so no single value is ever torn; the values are at most a second old. Histograms will follow the same path. |
| Access logs | Each worker formats lines into a private 4 KiB buffer and hands it over with one non-blocking `write` to a pipe (at most `PIPE_BUF` bytes, so atomic: lines of different workers never mix), when the buffer is full and once a tick. That is one syscall per ~13 lines. The logger process writes them to files. A full pipe (1 MiB) drops the lines and counts them; the worker never waits for the disk. The pipe outlives the logger and every worker generation, which keeps reloads and logger restarts simple. Per-worker rings the logger polls would save that syscall; they are worth it only if a profile shows it. |
| Rate limits | Every limit is per instance (all workers together); okena never applies a limit per worker, which would multiply it by the worker count. Token leases: a shared table of buckets (open addressing, 64-byte aligned, one bucket per cache line). A worker takes a batch of tokens with one `lock xadd` and spends them locally; the atomic is paid once per batch, not per request. Lease size adapts to the key's rate: hot keys take big batches, keys near their limit take one token at a time and stay exact. The table has a fixed size; when a flood of new keys fills it, the least recently used keys whose buckets are full (they carry no information) are evicted first, and new keys are admitted under a shared per-route bucket so a key flood cannot bypass the limit. |
| JWKS, remote keys | Fetched by the control process and published like a backend set. |
| Caches | Memory tier and verified tokens per worker (no contention). The disk cache is shared: lock-free reads with per-slot versions, inserts by compare-and-swap, append-only segments (see Edge, CDN and caching). |
| TLS ticket keys | In the plan (read-only), rotated hourly by the supervisor; optionally loaded from a file shared by a fleet of instances. |
| Supervisor ↔ worker control | Signals: SIGTERM asks a worker to drain, read through a signalfd on the worker's own ring. Generations make anything richer unnecessary so far. |

The only atomics in the process are lease refills, plan reference counts
and the seqlock counters, none of which a request waits on.

**Nothing blocks the loop.** All I/O goes through io_uring, including file
reads (static files, certificates on reload), timers, signals (signalfd)
and DNS. Work that is slow by nature runs elsewhere: certificate issuance
in the acme process, log writing in the logger (a worker only formats
its lines, with no syscall for the time), config compilation in the
supervisor. TLS handshakes run inline but are
budgeted (see below).

## Resilience and fault tolerance

okena assumes that everything fails: its own code, the machine, the
backends, the network, the services it depends on. The rule is **static
stability**: when something okena depends on fails, the data path keeps
working with what it last knew, and the failure stays inside the smallest
possible unit.

**Failure domains, smallest first**

| Unit | When it fails | Blast radius |
|---|---|---|
| a request | bad input, timeout, backend error | that request (and its connection when framing is lost) |
| a connection | protocol abuse, slow peer, reset | that connection |
| a backend | crash, black hole, slowness | ejected; its requests retried within the budget |
| an addon | crash, hang, slowness | its routes follow `on_error`; it is restarted |
| a worker | crash, hang | its connections; the kernel queues new ones for its replacement |
| the control process | crash | nothing on the data path; workers keep the last published state; it is restarted |
| the logger / disk | crash, disk full | log lines dropped and counted |
| the supervisor | must not fail | see below |
| the host | power, kernel | the fleet: other instances, BGP withdrawal, DNS failover |

**The supervisor is small and never touches untrusted input.** It forks,
reaps, holds sockets and swaps generations; nothing else. Parsing and
compiling the configuration, the riskiest code it runs, happens first in a
short-lived compiler child, inside its own seccomp filter; a bug in the
parser kills the child, never the supervisor, and the running
configuration stays. Only bytes the child accepted are then compiled by
the supervisor itself (the same bytes, read once). Under systemd with socket activation, or a
container restart policy, even a supervisor crash loses no queued
connection: the listening sockets outlive it.

**Hung workers are found and replaced.** Each worker bumps a heartbeat in
its stats page every loop iteration. A worker whose heartbeat has not
moved for `watchdog` (default 2 s) while it has work is killed and
replaced; the stall is logged with its last known state. An infinite
loop or a deadlock-shaped bug costs two seconds of one worker's
connections, not the service.

**Queries of death.** A request that crashes a worker would crash its
replacement too, and the next. Before running risky stages (parsing,
decompression, addon replies), a worker writes a fingerprint of the
request (listener, route, a hash of the request head) into its shared
page. When a worker dies, the supervisor reads the fingerprint; after two
crashes with the same one, workers refuse requests with that fingerprint
(400, logged and alerted) for an hour. One poisoned request cannot take
down the fleet one worker at a time.

**Dependencies fail safe, with last known good state:**

* DNS failing or answering empty: backends keep their last addresses
  (stale) until DNS answers again; an empty answer never empties a pool
  that had backends, unless the operator removes them.
* Discovery source down (Docker, Kubernetes, files): the last set stays.
* JWKS endpoint down: cached keys stay valid for `stale` (default 24 h);
  new key IDs are fetched when they appear, rate limited.
* ACME or the CA down: the current certificate stays; renewal retries
  with backoff long before expiry.
* Health checker unable to run (control process restarting): backends
  keep their last state; passive detection continues in the workers.
* Configuration invalid at startup: with `last_good` on (default for
  reloads, optional at startup) okena starts on the last configuration
  that compiled, saved next to the file, and says so loudly.
* Disk cache I/O errors: the cache is bypassed and the error counted;
  requests go to the origin.

**Backends fail; requests should not.** Covered in detail elsewhere:
outlier ejection, retries with budgets, hedging, deploy hold, panic mode,
`stale-if-error`, circuit breakers and adaptive concurrency, all chosen
so that a failing backend sheds its own load instead of spreading it.

**Every fast path has a slow path.** io_uring → epoll, sockmap → splice
→ copy, kTLS → user-space records, zcrx → normal receive, eBPF steering
→ reuseport hash, huge pages → normal pages. A feature that fails at
startup or at runtime switches to its fallback for that connection or
worker, logs it once, and exposes it as a metric. okena never refuses to
serve because an optimisation is unavailable.

**State that matters survives restarts:** ticket keys (optionally on
disk), the disk cache (its index is rebuilt from the segments in the
background after a restart, serving misses meanwhile), the last good
configuration, the last known backend sets (so a restart during a DNS
outage still has backends). Rate-limit and outlier state are deliberately
not persisted: they rebuild in seconds.

**Health of okena itself:** `/live` answers as long as the supervisor and
one worker run; `/ready` fails while starting, draining, or when no pool
of the default route has a backend. Fleets and orchestrators use them to
take an instance out before it fails.

**Faults are tested, not hoped for.** `make chaos` runs the service under
load while killing workers (SIGKILL and SIGSTOP), the control process,
addons and backends; filling the disk; injecting packet loss, delay and
reordering (netem); black-holing backends with iptables; exhausting ports
and memory (cgroup limits); stepping the clock. A run passes when every
request got either a correct response or a fast, explicit error, never a
hang. Routes can also inject faults on purpose (`fault delay=100ms 5%`,
`fault abort=503 1%`) to test the clients and backends behind okena.

## Surviving spikes

A spike has to be absorbed or refused in microseconds, without a cascade.

* **Everything is preallocated as address space** (see Memory). Connection slots,
  buffers, upstream connections, h2 streams, timers: each pool is reserved
  once at its maximum (`mmap` with `MAP_NORESERVE`, guard pages) and made
  resident on demand. No `malloc`, no growth, no fragmentation, no page
  table work under load beyond first touch. Pools are LIFO so the warmest
  item is reused first, and idle tails go back to the kernel
  (`MADV_DONTNEED`) when the load is gone, as in fasm2crud. Hot pools use
  2 MiB pages (THP `madvise`) to cut TLB misses.
* **Reserved is not resident.** Address space reserved with
  `MAP_NORESERVE` can still run the machine out of memory when it is
  touched. Pool ceilings are derived from the memory actually available
  (cgroup `memory.max`, else `MemAvailable`), the warm reserve is
  prefaulted and locked (`mlock`), and the overload manager reads the
  cgroup's `memory.current` and kernel socket memory every tick. okena
  sheds load before the OOM killer would pick it.
* **Admission before work.** The order of checks follows cost: XDP/eBPF
  drop list and per-source SYN rate (optional) → kernel SYN cookies →
  per-source connection limit at accept → TLS handshake budget → request
  limits → route rate limit → backend concurrency limit. A request that
  will be refused is refused at the cheapest layer that knows it.
* **Overload manager.** Each worker tracks its own pressure: free
  connection slots, free buffers, loop lag (TSC time between iterations),
  handshake debt. Pressure levels switch on measures in steps, all
  reversible with hysteresis:
  1. shorten keep-alive idle timeout, lower the h2 stream limit;
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
  (default 20%) plus a small floor (10/s), per pool, kept by each worker
  (a fraction does not depend on how many workers share it). A spike can
  never multiply itself through retries.
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
  latency, never existing connections. **Today** the budget is TSC time
  per loop iteration (`handshake_budget`, 100 us by default) for server
  hellos (TLS 1.3 and 1.2); a ClientHello with `pre_shared_key` skips the
  queue up to twice the budget, so fake tickets stay bounded; the queue
  holds 1024 per worker and closes what waited longer than `wait` (1 s).
  With 6000 handshakes arriving at once on one worker, an open keep-alive
  connection's p99 went from 1.6 ms to 0.47 ms. Upstream (client)
  handshakes are not budgeted: okena starts them itself, one per pool
  connection.

## Upstream connections

The classic ways a proxy fails under a spike are on the backend side, not
the client side.

* **Ephemeral ports.** One source address can open ~28k (default range)
  connections to one backend address before `connect` fails with
  `EADDRNOTAVAIL`. okena binds upstream sockets with
  `IP_BIND_ADDRESS_NO_PORT` and `IP_LOCAL_PORT_RANGE` (the kernel picks
  the port at connect time, per 4-tuple), can spread connections over
  several source addresses (`source 10.0.0.2 10.0.0.3`), and counts free
  ports per backend as a pressure signal. Keep-alive and h2 multiplexing
  keep the need low in the first place.
* **TIME_WAIT.** okena lets the backend close idle connections when it
  can (its idle timeout is set below the backend's), so TIME_WAIT lands
  on the backend, not on okena's port space.
* **The reuse race.** A backend may close an idle keep-alive connection
  just as okena sends on it. A request that failed on a reused connection
  before receiving any response byte is retried once on a new connection
  if it is idempotent or had no body sent yet; this does not count
  against the retry budget. Pools close idle connections a little before
  the backend would (`idle`, default below the common 60 s / 75 s).
* **Black holes.** A backend that vanishes without RST is found by
  `TCP_USER_TIMEOUT` and keepalive on upstream sockets, connect
  deadlines, and response deadlines, not by waiting for the kernel's
  15-minute retransmission limit.
* **Connection storms on backends.** New connections to a backend are
  rate limited per worker (`connect rate=`) and recovering backends warm
  up through slow start, so a reconnect wave after a restart does not
  knock the backend over again.
* **Protocol translation.** Each side speaks its own protocol: h1, h2 or
  h3 downstream to h1, h2 or h2c upstream, in every combination. okena
  converts framing (chunked ↔ DATA frames, trailers, `Content-Length`),
  drops connection-specific headers, maps gRPC errors, and handles the
  awkward cases explicitly: `HEAD` and 204/304 without bodies, 1xx and
  `Expect: 100-continue`, responses delimited by close, upgrade to
  WebSocket over h1, h2 (RFC 8441) and h3 (RFC 9220). Responses from
  backends are parsed as strictly as requests; a malformed response
  becomes a 502, never forwarded bytes.

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
manager sheds instead of letting queues (and the tail) grow.

The numbers are a starting point, not a promise: a proxy hop costs at
least two extra trips through the kernel's TCP stack, and on loopback
that floor alone is several microseconds. Phase 0 measures the floor (a
no-op forwarder) on the reference machine and the targets are set as
"floor + X". Loopback also hides NIC, interrupt and RSS effects, so every
benchmark runs on two topologies: network namespaces over veth on one
host (repeatable, in CI) and two hosts over a real NIC (the numbers that
count). The load generator, okena and the backend get disjoint cores.

What buys them:

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
  queue on the same core as its worker; hot code and data laid out by
  cache line; no real-time scheduling (a `SCHED_FIFO` worker that busy
  polls starves the softirq and kernel threads on its own core and causes
  the stalls it was meant to avoid); no page faults on the hot path once
  warm (pools prefaulted up to their warm reserve); no syscalls for time
  (TSC, vDSO).
* **Expensive checks run once.** A signature check on a JWT costs tens of
  microseconds (ES256 verification, RSA-2048 a bit less), which alone
  would break the budget above. Verified tokens are cached per worker by
  a hash of the token until their `exp` (bounded size, CLOCK eviction), so
  a client pays the verification once per token, not once per request.
  Forward-auth answers are cached the same way when the auth service
  allows it (`Cache-Control`). API keys are compared by a keyed hash
  lookup, not a scan.
* **First visit is fast too.** TLS 1.3 is one round trip; resumption skips
  the certificate; ECDSA chains are small enough for the server's first
  flight to fit the initial congestion window (`okena check` warns when a
  chain does not). HTTP/3 removes the TCP round trip, `Alt-Svc` and HTTPS
  DNS records advertise it.
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
  connections cost okena ~256 MB instead of 16 GB; the kernel adds a few
  KiB per socket on top, which `limits connections` accounts for.
  Backpressure is kept as in fasm2crud: a connection has at most one
  receive armed (single-shot with buffer selection, or multishot capped to
  one buffer), and none while its peer's output is full, so TCP flow
  control still slows down whoever sends too fast.
* **Zero-copy forwarding.** Bodies and L4 streams are not copied through
  user space when they do not need to be inspected. Three ways exist, and
  phase 1 measures them against each other before one becomes the
  default per case:
  * `sockmap` with an `sk_skb` verdict program (bytes go socket to socket
    inside the kernel). Fastest on paper, but okena must still watch
    for half-close and errors, and kernel versions differ in how well it
    handles backpressure;
  * `splice` through pipes. A pipe is held by a connection while its
    destination is full, so pipes come from a bounded pool, sized down
    with `F_SETPIPE_SZ`, with a copy path when the pool is empty; io_uring
    may run a splice on its worker threads instead of inline, which adds
    latency, so this is measured, not assumed;
  * receive into a provided buffer and send it, with `SEND_ZC` for large
    writes (threshold measured, around 16 KiB; below it a copy is cheaper
    than the completion notification). One copy, simplest, often the
    fastest for small messages.
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

**epoll engine.** io_uring is blocked by the default seccomp profiles of
Docker (since 25.0), containerd and Kubernetes `RuntimeDefault`, by
gVisor, and by some hardened kernels (`kernel.io_uring_disabled`). okena
ships with a second I/O engine on epoll (edge triggered, `EPOLLEXCLUSIVE`
not needed with per-worker sockets) with `recvmmsg`/`sendmmsg` for UDP,
`splice` and kTLS still available. The engine is chosen at startup (or
forced with `io_engine`) and logged; everything above the engine is the
same code. okena also ships the seccomp profile that allows exactly what
the io_uring engine needs, so the fast engine is one flag away
(see Containers).

## Memory

Memory follows the load: small at rest, growing in steps a spike can
use at once, shrinking when the load is gone, never fragmenting, and
never costing a lock or a syscall on the request path.

**Reserve address space, commit on demand.** Every pool reserves its
maximum once, as address space (`MAP_NORESERVE`, guard pages at both
ends). Reserving is free; only touched pages cost memory. A pool grows by
committing the next chunk of its own range, so its items never move,
pointers stay valid, and growth needs no copy, no lock and no
reallocation. The ceiling is derived at startup from the memory really
available (cgroup `memory.max`, else `MemAvailable`) and the configured
limits, so "reserved" can never promise more than the machine has.

**Size classes, not a general allocator.** There is no `malloc`. Each
kind of object has its own pool with a fixed size: connection headers
(256 B), h2 streams, timers, upstream connections, and I/O buffers in a
few classes (4, 16, 64 KiB, plus 128 KiB loans with deadlines). Fixed
sizes mean no fragmentation and O(1) allocation: a pop from a per-worker
LIFO free list, the most recently freed (still in cache, already
faulted in) first. Configuration generations live in arenas that are
released whole when the generation retires.

**Buffers sized by what a connection does.** An idle connection holds no
buffer at all (~256 B in okena). **Today** that holds for `tcp`
sessions (128 B, buffers from the provided ring only while bytes move).
An `http` session has a 512-byte state in a dense array and 64 KiB of
buffer address space (request, output, response), touched only as far as
an exchange uses it; 2 s after its last exchange an idle keep-alive
connection gives all of its buffers back (`MADV_DONTNEED`). Measured:
~1.2 KB per idle connection (state, session, client address record),
against 12.7 KB before. A connection gets a 4 KiB buffer on its
first bytes, which is enough for most requests; it moves to 16 KiB when
it fills one (TLS records, large headers) and to 64 KiB for sustained
streams (downloads, uploads, L4 tunnels), stepping down again when its
rate drops — the same idea as the kernel's TCP buffer auto-tuning, so
memory goes to the connections that move bytes. Socket buffers are
capped per listener (`SO_RCVBUF`/`SO_SNDBUF`) so the kernel cannot hold
more than okena accounts for.

**Grow ahead of demand, shrink behind it.** Each pool keeps a warm
reserve: committed, prefaulted pages ready for an instant spike. The
reserve tracks an exponentially weighted peak of recent use, so after a
burst it stays large for a while (the next burst often follows) and
decays slowly. Growth happens off the request path: on the timer tick,
when free items fall below the reserve, the next chunk is prefaulted
with `MADV_POPULATE_WRITE` (one syscall, no page-fault storm under load);
if a spike outruns that, items are still served from the committed range
and fault in on first touch. Shrinking is the reverse, with hysteresis:
items at the bottom of the LIFO stacks, beyond the reserve and unused for
`trim_idle` (30 s), go back with `MADV_DONTNEED` a bounded number per
tick. A busy pool never trims, so it never pays faults for trimming.

**Huge pages where they pay.** Large, hot, long-lived pools (connection
headers, buffer classes, the cache index) are 2 MiB aligned and use
transparent huge pages (`MADV_HUGEPAGE`) to cut TLB misses; small or
short-lived ones stay on 4 KiB pages so trimming stays fine-grained.
Explicit huge pages (`MAP_HUGETLB`) are used when the host provides them.
**Today** every pool is marked `MADV_NOHUGEPAGE`: with THP on `always`,
the first touch of a sparse pool committed a whole 2 MiB page and a
worker at rest grew from 0.7 MB to 13 MB. Huge pages come back per pool,
for pools dense enough to fill them, once measured.

**Pressure-aware.** The overload manager reads the cgroup's
`memory.current` and pressure stall information (`memory.pressure`, PSI)
every tick. Rising pressure first shrinks warm reserves and trims
harder, then steps down buffer classes for new connections, then sheds
load; okena gives memory back before the kernel has to take it, and
never reaches the OOM killer. The minimum working set (the warm
reserves okena needs to stay responsive) is locked with `mlock`.

**NUMA and cache lines.** Each worker first-touches its own pools, so
they live on its node. Hot fields of every object share one cache line;
objects that different cores write are on different cache lines
(64-byte alignment, no false sharing). Per-worker data is never written
by another worker.

**Accounting.** Every pool reports reserved, committed, in use and warm
bytes in `/metrics` and `okena top`, so memory is explained, not
guessed. Every limit is explicit; when one is reached, okena answers 503
or applies backpressure instead of growing.

Layout details:

* Connection header: 256 bytes; the first cache line holds the hot
  fields (state, flags, deadlines, ring indices), the rest is cold.
* Upstream connections live in per-worker, per-backend LIFO free lists
  (most recently used first: warm in the backend's cache too). Idle ones
  are closed after `idle`, so N workers do not keep N times the
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
* **Paths** are where proxies and backends disagree and auth is bypassed
  (`/admin/../public`, `%2e%2e`, `%2F`, `//`, `;` parameters, overlong
  UTF-8). okena decodes and normalises once for routing, rejects what
  cannot be normalised safely, and forwards either the normalised path or
  the original (`path forward=normalized|original`), so routing and the
  backend see the same resource. Matching is case-sensitive unless a
  route says otherwise.
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
* **Responses** stream back with flow control; a small response's head and
  the body already on hand go out in one send (one TLS record), and small
  ones are batched with pipelined responses into one send.

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

* TLS 1.3 first; TLS 1.2 (ECDHE + AEAD only) for clients that need it,
  and early as a client, because many internal backends still speak only
  TLS 1.2 with RSA certificates.
* Certificate compression (RFC 8879) and Encrypted Client Hello later.
* Key exchange: **X25519MLKEM768** (post-quantum hybrid, default),
  X25519, P-256. **Today** the hybrid is served (preferred when the
  client sends its share); ML-KEM-768 runs on AVX2 (15.5 us an
  encapsulation, under OpenSSL's 25). okena's own client side (upstreams) offers it too,
  first, with x25519 and P-256 shares beside it for backends without it.
* AEAD: AES-128/256-GCM (AES-NI, VAES + VPCLMULQDQ), ChaCha20-Poly1305
  (AVX2), chosen by client preference and hardware. **Today** AES-128-GCM and
  ChaCha20-Poly1305 (TLS 1.3; ChaCha20 when it is the client's first
  suite); AES-256-GCM is not offered.
* Certificates: ECDSA P-256 and Ed25519 signing first; RSA-PSS signing
  later. Verification of RSA, ECDSA and Ed25519 for upstream TLS and
  client certificates, with an X.509 path validator restricted to what
  WebPKI needs.
* SNI selects the certificate; ALPN picks h2/http/1.1; resumption with
  tickets encrypted under keys rotated every hour and shared across
  workers through the plan (read-only, so no lock).
* ACME (RFC 8555) with HTTP-01 and TLS-ALPN-01, in its own process, and
  DNS-01 through provider APIs (Cloudflare, Route 53, RFC 2136) for
  wildcard certificates; staging first on new configs, backoff that
  respects the CA's rate limits, renewal at two thirds of the lifetime
  (certificates are getting shorter), the old certificate kept until the
  new one is live.
* Certificates from files are watched and swapped without a reload; many
  certificates (thousands of domains) are indexed by name, wildcard
  included, and IDNA names are matched in their punycode form.
* All secret-dependent code is constant time; crypto is tested against
  known-answer vectors, Wycheproof, and differential runs against a
  reference library, as fasm2crud already does for SHA-256 and Argon2.

## Load balancing

| Algorithm | When |
|---|---|
| `least-request` (power of two choices, weighted) | default for every pool (requests in flight for http, connections for tcp); no herding, O(1): one random draw, no division, no scan |
| `peak-ewma` | latency-sensitive pools; two random servers, the lower (latency + 1) x (in flight + 1) / weight wins. Latency per server and worker: for http from the request sent to the response head, for tcp the connect time; a slower sample is taken at once (the peak), others blend in and the value decays toward 0 with tau = 10 s, so a slow server is tried again once its latency has decayed to the others'. The TSC is read only for pools that use it |
| `round-robin` (smooth weighted) | uniform backends, predictable spread |
| `maglev` / `ring-hash` with bounded load | affinity by header, cookie, path or source |
| `source-hash`, `random` | L4 and simple cases |
| `least-conn` | long-lived connections (WebSocket, tcp) |

* Health: active (TCP, HTTP, gRPC health, TLS handshake, and protocol
  checks that know roles: PostgreSQL primary or standby through
  `pg_is_in_recovery()`, Redis `role`, MySQL read-only), passive outlier
  detection (consecutive 5xx/gateway errors, success-rate ejection, with
  a maximum ejected share so a bad check cannot empty a pool), slow start
  for recovered and new backends, panic mode (use all backends when too
  few are healthy).
* Locality: prefer backends in the same zone while they have capacity.
* Active health checks are spread so that each backend is checked once per
  interval by the whole process, not once per worker; results are
  published like any backend set.
* Discovery: static, DNS (A/AAAA/SRV with TTL; okena has its own async
  resolver), files watched through inotify, the admin API, Docker labels; Consul
  and Kubernetes endpoints later.

## Gateway features

Built in, in assembly, compiled into the route only where configured:

* **Identity:** JWT with JWKS (HS/RS/PS/ES/EdDSA, leeway for clock skew),
  API keys hashed in the plan, Basic, mTLS identity, forward-auth, and a
  full OIDC login (authorization code + PKCE, encrypted session cookie)
  so internal tools (Grafana, admin panels, a PaaS dashboard) sit behind
  "sign in with Google" plus an e-mail or domain allowlist.
* **Traffic control:** rate limits (GCRA per instance through leases,
  keyed by any request attribute), quotas, concurrency limits, priorities,
  IP allow/deny with an LPM trie, GeoIP (MaxMind `.mmdb` reader:
  `client.country`, `client.asn`) for routing and blocking.
* **Idempotency keys:** for routes marked `idempotency`, a request with an
  `Idempotency-Key` header is answered once; a repeat while the first is
  in flight waits for it, a repeat after it gets the stored response
  (bounded size and time). A double click or a mobile retry on a flaky
  network becomes one write, enforced at the edge, on top of whatever the
  application does.
* **Shaping requests and responses:** header and path rewrites, redirect
  maps loaded from files (thousands of 301s in a hash, not a list of
  rules), trailing-slash and `www` canonicalisation, request and response
  size limits per route, CORS, security header presets (HSTS, nosniff,
  frame options, referrer policy).
* **Compression:** precompressed variants (`.br`, `.zst`, `.gz`) picked by
  `Accept-Encoding`, and on-the-fly gzip and zstd for text responses
  (JSON, HTML) above a size threshold, at a fast level, with a CPU budget
  under the overload manager; brotli on the fly later. On a slow mobile
  network, a 60 KiB JSON going out as 9 KiB is worth more than any
  microsecond saved in the proxy.
* **Fast first paint:** 103 Early Hints with `Link: preload` (configured,
  or learned from the `Link` headers the backend sent last time), so the
  browser fetches CSS and fonts while the backend is still rendering.
* **Release safety:** traffic splitting (weights, header/cookie overrides
  for canaries), mirroring, request hedging, and **deploy hold**: when
  every backend of a pool refuses connections (a container being
  replaced), requests wait up to `hold` (default 0, typically 5-10 s)
  for one to come back instead of failing; names are re-resolved at once
  on connect failure, since a recreated container usually has a new IP.
* **Static sites and SPAs:** static files with `sendfile`/splice
  (zero-copy, kTLS included), `ETag`/`Last-Modified`, ranges, immutable
  caching for hashed assets, SPA fallback (`fallback /index.html` for
  client-side routes, never for missing assets), custom error pages.
* **Webhooks:** routes that carry signed payloads (Stripe, payment and
  e-mail providers) get `body raw`: the body is forwarded byte for byte,
  never re-encoded or decompressed, with source IP allowlists.

## Addons

Everything above is built in because it is on the hot path and must be
in assembly. For everything else there are addons: separate processes,
in any language, that okena calls at defined phases of a request. They
cannot slow down routes that do not use them and cannot crash okena.

```
addon waf {
    run /usr/local/bin/coraza-okena      # okena starts and supervises it
    phases request_headers request_body
    timeout 2ms on_error=allow           # or deny
    concurrency 1024
}

route /api/* {
    use addon waf
    to pool api
}
```

* **Transport:** shared memory, not HTTP or gRPC. Each worker has a pair
  of single-producer/single-consumer rings with each addon (a memfd the
  addon maps), messages in a fixed binary layout, header values passed by
  offset into a shared arena. A worker posts every call of a loop
  iteration and wakes the addon once (one `eventfd` write per batch); the
  addon's answers come back through the worker's io_uring. No lock, no
  copy of the request beyond what the addon asks for.
* **Phases:** `request_headers`, `request_body` (streamed in chunks or
  buffered, bounded), `response_headers`, `response_body`, `log`
  (fire-and-forget, never waited for).
* **Actions an addon can return:** continue, set/remove headers, set
  variables for later filters (`addon.waf.score`), pick a pool, rewrite
  the path, replace the body, or answer directly (status, headers, body).
* **Isolation:** per-call deadline, concurrency limit and circuit breaker
  per addon; an addon that crashes is restarted by the supervisor and its
  pending calls follow `on_error`. Its time shows up as its own column in
  logs and histograms.
* **SDKs:** the protocol is small and fixed-layout, so thin SDKs (C, Rust,
  Go, Python) are a few hundred lines each. An adapter for Envoy's
  `ext_authz` and `ext_proc` gRPC APIs lets existing services plug in.
* **Good addon material:** WAF rule engines (Coraza, OWASP CRS), image
  resizing, bot challenges, OpenAPI request validation, GraphQL depth and
  cost limits, gRPC-JSON transcoding, custom business rules, analytics.

**Alerts** are an addon in the other direction: okena emits events
(backend ejected or back, pool empty, certificate expiring in 14 days,
overload level changed, worker restarted) to a webhook, Telegram or
Slack, deduplicated and rate limited by the control process.

## Edge, CDN and caching

okena is built to be the software of a CDN node: an edge that caches,
terminates TLS close to users and protects the origin. A CDN also needs
network (points of presence, anycast addresses, transit capacity to
absorb terabit attacks); that part is infrastructure, and okena
cooperates with it instead of pretending to replace it.

**Cache.** Two tiers:

* **memory**, per worker, for the hottest small objects (no contention);
* **disk**, shared by the workers of the instance (otherwise disk use
  would be multiplied by the worker count). Objects are written
  append-only into large segment files (log structured, no fragmentation,
  eviction by whole segments); the index is a shared hash table that
  readers walk without locks (a version per slot, readers retry when a
  slot changed under them) and writers update with compare-and-swap.
  Reads go from the page cache to the socket with `sendfile`/splice
  (zero-copy, kTLS too); `O_DIRECT` reads through io_uring for objects
  that should not pollute the page cache.
* Admission with S3-FIFO, so one-hit wonders (crawlers) do not evict the
  working set.

RFC 9111 semantics, plus what a CDN needs: cache keys configurable
(host, path, chosen query parameters, headers, cookies), `Vary`
normalisation (`Accept-Encoding` reduced to the variants served), request
collapsing, `stale-while-revalidate`, **`stale-if-error`** (origin down
or mid-deploy → serve the last good copy), revalidation with
`ETag`/`Last-Modified`, negative caching, range requests and slicing of
large files (video, downloads), `Cache-Status` (RFC 9211), and purge by
URL, prefix or tag (`Cache-Tag`/`Surrogate-Key` from the origin) through
the admin API, fanned out to every node of a fleet.

**Tiers.** An edge's pool can be another okena (`shield`): edges in
several regions fill from one shield, which alone talks to the origin.
**Signed URLs** (HMAC with expiry, path prefix, optional client IP) let
the origin hand out links to protected content that edges validate
without calling it.

**Distribution.** Nodes in several regions are reached through GeoDNS or
anycast (BGP announced by a routing daemon such as BIRD, with okena's
health deciding whether the address is announced: a node that fails its
own checks withdraws itself).

**Behind someone else's CDN** (Cloudflare and the like), the edge cases
are about trust: `trusted_proxies cloudflare` loads the provider's
published ranges (refreshed by the control process), the client address
comes from the provider's header only when the peer is in those ranges,
authenticated origin pulls (mTLS from the CDN) can be required, and the
listener can refuse everyone else, so the origin is not reachable around
the CDN.

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

* **Reload** (`SIGHUP`; later `okena reload` and the admin API): the file
  is read once, a compiler child validates those bytes, the supervisor
  compiles the same bytes, opens new addresses' sockets and keeps the
  sockets of addresses that stay, then starts a new worker generation;
  the old one stops accepting and finishes its sessions. Anything that
  fails before that commit (invalid file, compiler crash, a port another
  program holds) leaves the running configuration as it was. When the
  worker count goes down, no socket of a remaining address is closed
  (it may hold queued connections): the remaining workers serve the
  extra ones.
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
* Containers from `scratch` (see Containers), systemd unit with socket activation.

## Containers

okena must be as good inside Docker or Kubernetes as on bare metal, and
trivial to run there. Containers change several facts the design depends
on, so each one is handled explicitly:

| Container fact | What okena does |
|---|---|
| `--cpus=2` on a 16-core host still shows 16 CPUs in the affinity mask; 16 workers would hit the CFS quota and stall for whole periods (the worst tail latency there is) | `workers auto` = min(affinity mask, ceil(cgroup `cpu.max` quota)); a warning when a quota is set, recommending `--cpuset-cpus` for pinned, unthrottled cores; throttling (`cpu.stat nr_throttled`) is a metric |
| `--memory` limit | pool ceilings come from `memory.max`; the overload manager watches `memory.current` |
| io_uring blocked by the default seccomp profile | epoll engine by default in that case; `okena.seccomp.json` in the image enables io_uring with an allowlist; the startup line says which engine runs and why |
| No `CAP_BPF`/`CAP_NET_ADMIN` | no XDP, sockmap or steering program; reuseport hash and splice instead; each fallback logged once |
| Published ports go through `docker-proxy` (fasm2crud measured 295k req/s through it against 755k direct) | docs and the compose example use host networking or `userland-proxy: false` for performance, and `okena check --host` detects docker-proxy in the path |
| Service names (`api:8080`) resolve through Docker's DNS (127.0.0.11) or cluster DNS | the resolver reads `/etc/resolv.conf` and `search`/`ndots`, honours TTLs, and re-resolves; names are first class in `to` and `server` |
| `docker stop` sends SIGTERM and kills after 10 s | drain: readiness turns false first (`/ready` fails, load balancers and Kubernetes stop sending), wait `drain_delay`, then close idle connections and finish in-flight ones; defaults fit inside 10 s and a warning says so if `drain_timeout` does not |
| Config edited on a bind mount or a ConfigMap (atomic symlink swap) | `reload on-change` watches the directory, not the file, so editor renames and `..data` swaps are seen; a broken edit is rejected and logged |
| No shell, no curl in a `scratch` image | `okena health` subcommand for `HEALTHCHECK`; `okena check`, `okena route` and `okena top` work with `docker exec` |
| Many network sysctls are per network namespace | the compose example sets `net.core.somaxconn`, `net.ipv4.ip_local_port_range`, `net.ipv4.tcp_tw_reuse`; `okena check --host` prints what is missing |

Ways to configure, from quickest to fullest, all the same language:

```
docker run --network host okena tcp :5432 to db1:5432 db2:5432
docker run -e OKENA_CONFIG='https example.com { to app:3000 }' okena
docker run -v ./okena.conf:/etc/okena/okena.conf:ro okena
```

`OKENA_*` environment variables are not a second config system: the
command line and `OKENA_CONFIG` are config text, and `${env:NAME}`
inside a file reads any variable, so secrets come from the orchestrator.

The image is `FROM scratch`: the static binary, the seccomp profile, a
default config that serves a status page, runs as a non-root user with
a read-only root filesystem, and binds ports below 1024 through
`ip_unprivileged_port_start` (Docker sets it to 0) or
`CAP_NET_BIND_SERVICE`. Logs go to stdout as JSON by default.

Docker discovery (`discover docker label=okena.pool=api`, reading the
Docker API on its Unix socket) and Kubernetes (EndpointSlices, later
Gateway API) come in phase 6.

## Host and kernel limits

Many failures under a spike are not okena's code but host limits it
inherits. `okena check --host` inspects them and says what to change:

* `net.core.somaxconn`, `net.ipv4.tcp_max_syn_backlog`, SYN cookies on;
* `nf_conntrack`: a full conntrack table drops new connections for the
  whole host; proxy ports should be exempt (`NOTRACK`) or the table sized;
* ephemeral port range and `tcp_tw_reuse`;
* `RLIMIT_NOFILE` (registered descriptor tables count against it too);
* socket memory (`tcp_mem`, `tcp_rmem`, `tcp_wmem`) against the expected
  connection count;
* NIC queues, RSS, IRQ affinity against the worker layout, THP mode,
  invariant TSC, clock source;
* `initcwnd` on the route towards clients.

## Fleet and high availability

okena is one instance per host; a fleet is several instances behind
anycast/ECMP, a cloud L4 balancer, DNS, or VRRP (keepalived). What a fleet
needs from okena:

* `xdp` mode uses Maglev with the same table on every instance, so a flow
  that moves between instances (ECMP change) usually keeps its backend;
* TLS ticket keys can come from a shared file, so resumption works across
  instances and survives restarts;
* rate limits are per instance; a fleet-wide limit is configured as the
  per-instance share (`limit ... instances=4`), and an exact distributed
  limiter is out of scope until a shared store is worth its latency;
* health and drain state are exposed through the admin API so a fleet
  controller can drain an instance before maintenance.

## Non-goals

* A user-space TCP stack or DPDK: the kernel stack with io_uring, XDP and
  kTLS keeps the operating system's tools (tcpdump, ss, sysctls) and gets
  within reach of bypass stacks for proxy workloads.
* Scripting inside the workers (Lua, WASM): extensions are built-in
  filters plus out-of-process addons, so an extension can never stall a
  worker.
* A WAF rule engine in the core; IP lists, limits and strict parsing cover
  protocol-level abuse, and rule engines plug in as addons.
* Sharing caches between workers.

## Risks

* **Scope.** TLS, HTTP/2, QUIC and all crypto in assembly is years of
  work. The roadmap delivers a production L4 balancer first, then HTTP,
  then TLS, so value arrives early and later phases build on code that
  already carries traffic.
* **Crypto correctness.** Mitigated by known-answer and Wycheproof
  vectors, differential testing against reference libraries,
  constant-time checks, fuzzing, and by supporting few algorithms.
* **Kernel features move.** Each fast path has a fallback and a startup
  probe; CI runs on the oldest supported kernel as well as a recent one.

## Security

* eBPF programs and XDP need `CAP_BPF` and `CAP_NET_ADMIN`; the supervisor
  loads them at startup and drops both before forking workers. Without
  them okena runs on the fallbacks.
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
src/cache/    memory tier, disk segments, lock-free index, purge
src/addon/    shared-memory protocol, addon supervision, alerts
src/admin/    admin API, metrics, top
tests/        unit, kat, fuzz, conformance, integration, bench
```

The eBPF programs are written in assembly too: fasm2 macros emit BPF
instructions, and okena loads them with `bpf(2)`. No clang, no libbpf.
