# Benchmarks

Measurements of okena, and comparisons with the established software for
each job (OpenSSL for crypto, HAProxy and nginx for proxying, Envoy for
gRPC), kept so they can be rerun and compared later. Every entry says
when, on what, and how.
A number without its method is not recorded here.

The exit criteria in [ROADMAP.md](ROADMAP.md) compare against references
on the same machine, with cores pinned and open-loop load. Entries made
with a closed-loop generator (wrk) say so; the two-host topology is not
in place yet.

## The load generator

`okena bench URL rate=N conns=C duration=D` gives every connection a
schedule (one request each C/N seconds, the connections staggered) and
measures each answer from the time its request was due, the way wrk2
does: a stall is charged to every request it held back, not only to the
one that saw it. It prints three histograms:

* `latency`: from the schedule (the number to quote);
* `service`: from the actual send (what a closed-loop tool reports);
* `sender`: how late the generator itself sent a request whose connection
  was idle, so its own error is on the page (on this machine, p99 under
  0.5 us and p99.9 a few us when it has a core of its own).

`behind` counts requests the schedule asked for that never went out: the
server did not keep up, and the percentiles do not include them. A run
with `behind` above zero did not reach its rate and says nothing about
latency at that rate. Without `rate=` the run is closed loop.

## Machine

Unless an entry says otherwise:

| | |
|---|---|
| CPU | AMD Ryzen 7 5700G (Zen 3, 8 cores / 16 threads), VAES and VPCLMULQDQ on ymm, SHA-NI, no AVX-512 |
| Memory | 30 GiB |
| Kernel | Linux 7.2.11 |
| OpenSSL | 3.5.3 (16 Sep 2025) |
| Pinning | `taskset -c 3` for single-core crypto, unless stated |

## Crypto, one core

Microbenchmarks: one operation in a loop, single thread, the time per
operation. okena through `build/kat` mode `B` (op, count, input); OpenSSL
through `openssl speed` on the same core.

```
python3 - <<'EOF'
import os, subprocess, sys
sys.path.insert(0, "tests/kat"); import mlkem_ref as M
run = lambda d: int(subprocess.run(["taskset", "-c", "3", "build/kat"], input=b"B" + d, capture_output=True).stdout)
ek, dk = M.keygen(os.urandom(32), os.urandom(32)); k, c = M.encaps(ek, os.urandom(32)); n = 5000
print("encaps us", run(b"K" + n.to_bytes(4, "little") + ek + os.urandom(32)) / n / 1000)
EOF
taskset -c 3 openssl speed -seconds 2 ML-KEM-768
taskset -c 3 openssl speed -seconds 2 -bytes 16384 -evp chacha20-poly1305
taskset -c 3 openssl speed -seconds 2 ed25519
```

| Operation | okena | OpenSSL 3.5.3 | Date | Notes |
|---|---|---|---|---|
| X25519 (variable base) | 25.6 us | ~25.6 us | 2026-10 | mulx/adcx/adox ladder |
| X25519 (fixed base, key generation) | 8.0 us | | 2026-10 | Edwards-form table |
| ECDSA P-256 sign (RFC 6979) | 15.6 us | ~15.6 us | 2026-10 | fixed-base table, blinded inversion |
| ECDSA P-256 verify | 67 us | 47.8 us | 2026-10-30 | u1 G by the fixed-base table, u2 Q by a width-5 NAF in Jacobian coordinates (259 us with two constant-time ladders) |
| Ed25519 sign | 9.7 us | 30.2 us | 2026-10-30 | fixed-base table (constant time), Barrett mod L |
| Ed25519 verify | 39 us | 79.8 us | 2026-10-30 | variable-base windows (public data) |
| AES-128-GCM, 16 KiB records | 6.9 GB/s | 5.8 GB/s | 2026-10 | VAES + VPCLMULQDQ on ymm (4.3 GB/s on the SSE path) |
| ChaCha20-Poly1305 seal, 16 KiB records | 1.34 GB/s | 3.1 GB/s | 2026-10-30 | two blocks a ymm, scalar Poly1305; OpenSSL runs eight blocks and a vector Poly1305. Only without kTLS (the kernel seals otherwise) |
| Keccak-f[1600] | 368 ns | | 2026-10-30 | scalar; 490 ns before theta was fused into rho/pi |
| Keccak-f[1600], four at once | ~1.25 of one | | 2026-10-30 | AVX2 |
| ML-KEM-768 key generation | 12.9 us | 36 us | 2026-10-30 | AVX2 NTT, four-way Keccak |
| ML-KEM-768 encapsulation | 15.5 us | 25 us | 2026-10-30 | 49.7 us scalar, 36 us after the Keccak work, 22.4 us with the AVX2 NTT |
| ML-KEM-768 decapsulation | 16.6 us | 37 us | 2026-10-30 | |

## TLS handshakes

| Measure | Result | Date | How |
|---|---|---|---|
| `tls_hello` on a real ClientHello (x25519, ECDSA) | 57 us | 2026-10 | `tests/tls/server.asm`, mode P |
| Worker CPU per new HTTPS connection (x25519) | ~75 us (77 user + 61 kernel with the client on other cores) | 2026-10 | 4 workers, a route okena answers, new connection per request |
| Worker CPU saved by a session ticket | ~27 us | 2026-10 | same, resumed |

## gRPC against Envoy, open loop (2026-10-31)

`tests/bench/grpc.sh`: okena (`http2 on`, a pool with `protocol h2`) and
Envoy 1.40.2 (official image, host network, `--concurrency 2`, circuit
breakers raised so it queues rather than refuses) on cores 1-2, plain
HTTP/2 both sides, in front of the same grpc-go backend
(tests/bench/grpc, `GOMAXPROCS=2` on 4-5), loaded by the same Go program
(grpc-go client, raw-bytes codec, 8 connections) with `GOMAXPROCS=8` on
the four other physical cores; 64-byte messages, 10 s after 2 s. Unary:
a call per tick, latency from the schedule. Stream: 8 server-streaming
calls held open, the backend sends on a schedule and stamps each message,
latency until it arrives. Each rate straight to the backend first; "added"
is a proxy's percentile minus that. Other containers stopped.

| Scenario | Path | rate | p50 / p99 / p99.9 / max (us) | added p50 / p99 | errors |
|---|---|---|---|---|---|
| unary, 5000/s | direct | 5000/s | 137 / 194 / 457 / 1487 | | 0 |
| unary, 20000/s | direct | 20001/s | 135 / 741 / 1859 / 3064 | | 0 |
| unary, 40000/s | direct | 40002/s | 173 / 2222 / 3405 / 5796 | | 0 |
| stream, 5000/s | direct | 5000/s | 45 / 62 / 72 / 243 | | 0 |
| stream, 20000/s | direct | 20001/s | 52 / 73 / 168 / 525 | | 0 |
| stream, 80000/s | direct | 80001/s | 33 / 135 / 470 / 5640 | | 0 |
| unary, 5000/s | okena, 2 cores | 5000/s | 172 / 229 / 455 / 2660 | +35 / +35 | 0 |
| unary, 20000/s | okena, 2 cores | 20000/s | 172 / 731 / 1724 / 3492 | +37 / -10 | 0 |
| unary, 40000/s | okena, 2 cores | 40001/s | 178 / 1229 / 2849 / 7294 | +5 / -993 | 0 |
| stream, 5000/s | okena, 2 cores | 5000/s | 64 / 87 / 152 / 2432 | +19 / +25 | 0 |
| stream, 20000/s | okena, 2 cores | 19998/s | 73 / 98 / 250 / 2893 | +21 / +25 | 0 |
| stream, 80000/s | okena, 2 cores | 80007/s | 59 / 108 / 448 / 2428 | +26 / -27 | 0 |
| unary, 5000/s | Envoy 1.40.2, 2 threads | 5000/s | 257 / 368 / 576 / 2134 | +120 / +174 | 0 |
| unary, 20000/s | Envoy 1.40.2, 2 threads | 20001/s | 685 / 2649 / 5852 / 12204 | +550 / +1908 | 0 |
| unary, 40000/s | Envoy 1.40.2, 2 threads | 32800/s | 1140200 / 5377467 / 7330549 / 10611783 | +1140027 / +5375245 | 0 |
| stream, 5000/s | Envoy 1.40.2, 2 threads | 5000/s | 80 / 110 / 139 / 1189 | +35 / +48 | 0 |
| stream, 20000/s | Envoy 1.40.2, 2 threads | 19998/s | 94 / 128 / 238 / 1294 | +42 / +55 | 0 |
| stream, 80000/s | Envoy 1.40.2, 2 threads | 80001/s | 136 / 222 / 491 / 2062 | +103 / +87 | 0 |

Read with care:

* okena adds less at every point: unary 35 us at p50 and p99 at 5k/s
  (Envoy 120 / 174 us), streamed messages 19-26 us at p50 and 25 us at
  p99 (Envoy 35-103 / 48-87 us).
* At 20k unary calls/s Envoy's two threads are near their limit (+550 us
  at p50, +1.9 ms at p99); at 40k/s it passes it (32.8k/s served, queues of
  seconds). okena serves 40k/s with its p50 5 us above the direct path.
* The load program is the limit at the top rates: its own p99 straight to
  the backend reaches 2.2 ms for unary at 40k/s, and an added p99 below
  zero there means the proxy smoothed the client's bursts, not that it
  took time away. The comparison that holds is p50, and p99 at 5k-20k/s.
* Bidirectional streaming does not go through okena yet: a stream's
  request and response run one after the other (the HTTP/1.1 exchange
  under each stream), so a call that needs answers before it ends its
  request stalls. Unary and server streaming are what is measured here;
  client streaming fits the same order but is not measured.
* Before this run okena cut such clients off: gRPC's BDP pings and window
  updates (one each per DATA frame read) counted against the 2000 a
  second cheap-frame budget, on the client side and towards the backend
  (502s). DATA and HEADERS sent now earn two cheap frames each.

## HTTP/2 against HTTP/1.1 through okena (2026-10-31)

One worker on core 1, the backend `l4bench http` on 4-5, `okena bench`
with 4 workers on 6, 7, 14, 15, 32 connections (`proto=h2`: one stream at a
time each, as h2load's default), 3 s after 0.5 s. Backends get HTTP/1.1
either way.

| | closed loop | p50 / p99 / p99.9 at 40k/s |
|---|---|---|
| plain, HTTP/1.1 | 86.8k/s | 31 / 48 / 69 us |
| plain, HTTP/2 | 81.6k/s (-6%) | 32 / 51 / 77 us |
| TLS, HTTP/1.1 | 85.8k/s | 31 / 53 / 72 us |
| TLS, HTTP/2 | 80.0k/s (-7%) | 32 / 58 / 270 us |

Per request, HTTP/2 costs about as much kernel time as HTTP/1.1 (11.0 us
against 10.8) and 0.7 us more in user space (HPACK, frames, the stream's
session and its HTTP/1.1 head). Before frames were sent once per loop
iteration (h2_flush) a response's END_STREAM went in a send of its own:
58.7k/s and 15.6 us of kernel time a request.

## HTTPS against HAProxy, open loop (2026-10-31)

`tests/bench/tls.sh`: okena and HAProxy 3.2 (official image, host network,
`nbthread 2`, OpenSSL 3.5.7) on cores 1-2, the backend `l4bench http` on
4-5, `okena bench` with 8 workers on the four other physical cores (0, 3,
6, 7 and their SMT siblings), ECDSA P-256, X25519MLKEM768 (both servers
take the client's hybrid share), AES-128-GCM, 10 s a run. Latency from the
schedule (corrected for coordinated omission); `behind` counts requests the
schedule asked for that never went out. Other containers stopped.

| Scenario | Server | req/s | behind | p50 / p99 / p99.9 / max (us) | errors |
|---|---|---|---|---|---|
| keep-alive, closed loop | okena, 2 cores | 169122.4 | 0 | 389 / 454 / 622 / 3206 | 0 |
| keep-alive, 50000/s | okena, 2 cores | 50000.0 | 0 | 33 / 49 / 231 / 2863 | 0 |
| keep-alive, 100000/s | okena, 2 cores | 100000.0 | 0 | 36 / 65 / 532 / 735 | 0 |
| new connection each, closed loop | okena, 2 cores | 17055.4 | 0 | 3735 / 7077 / 9699 / 11166 | 0 |
| new connection each, 2000/s | okena, 2 cores | 2000.0 | 0 | 372 / 548 / 1343 / 2883 | 0 |
| new connection each, 5000/s | okena, 2 cores | 5000.0 | 0 | 1490 / 3473 / 4325 / 5865 | 0 |
| new connection each, 10000/s | okena, 2 cores | 10000.0 | 0 | 4390 / 7012 / 7798 / 9282 | 0 |
| keep-alive, closed loop | HAProxy 3.2, 2 threads | 87106.5 | 0 | 729 / 933 / 1196 / 1508 | 0 |
| keep-alive, 50000/s | HAProxy 3.2, 2 threads | 50000.0 | 0 | 210 / 63963 / 72351 / 75388 | 0 |
| keep-alive, 100000/s | HAProxy 3.2, 2 threads | 100000.0 | 0 | 830472 / 1744830 / 1761607 / 1764706 | 0 |
| new connection each, closed loop | HAProxy 3.2, 2 threads | 4551.9 | 0 | 14024 / 15335 / 18350 / 19231 | 0 |
| new connection each, 2000/s | HAProxy 3.2, 2 threads | 2000.0 | 0 | 606 / 1097 / 1671 / 4763 | 0 |
| new connection each, 5000/s | HAProxy 3.2, 2 threads | 5000.0 | 0 | 654311 / 1174405 / 1183079 / 1183079 | 0 |
| new connection each, 10000/s | HAProxy 3.2, 2 threads | 4888.0 | 50865 | 4194303 / 7113539 / 7113539 / 7116019 | 0 |

Read with care:

* Keep-alive: okena's ceiling is 1.9 times HAProxy's (169k/s against 87k/s);
  at 50k/s its p99 is 49 us, HAProxy's 64 ms. At 100k/s HAProxy is past its
  ceiling and its queue grows for the whole run.
* New connections: 17.1k handshakes/s against 4.55k (3.7 times). At 5k/s
  HAProxy is saturated (p50 0.65 s), at 10k/s it falls behind by half.
* Open: okena's latency on new connections rises from ~0.37 ms at 2k/s to
  1.3-1.5 ms at 5k/s while its two workers are ~35% busy and the generator
  ~15% a process. Not the handshake budget (the same with it off), not
  wakeups (the same with busy_poll); the generator's own lag grows with it.
  Not isolated yet.

## HTTPS steady state against plaintext (2026-10-30)

okena with 2 workers on cores 1-2 (`taskset`), the backend `l4bench http`
(answers `ok`) on cores 4-5, `okena bench` with 4 workers on 6, 7, 14 and
15 (SMT siblings are i and i + 8: nothing shares a physical core), 64
keep-alive connections, ECDSA P-256, X25519MLKEM768. Closed loop for the
ceiling, then 10 s open loop at 100k/s (about 60% of it), three runs.

| Records | closed loop | p50 @100k/s | p99 @100k/s | p99.9 @100k/s |
|---|---|---|---|---|
| plaintext HTTP | 163.5k/s | 37-38 us | 91-696 us | 0.75-2.2 ms |
| user space (the default now) | 161.0k/s (-1.5%) | 43-53 us | 158-174 us | 0.58-2.7 ms |
| kTLS (`ktls on`) | 131.5k/s (-19.6%) | 62-70 us | 0.59-1.18 ms | 1.9-6.2 ms |

The workers ran at ~1.96 cores in every mode, 95% of it in the kernel;
kTLS added ~4 us of kernel time per request. A ping-pong of 100-byte
messages between two pinned processes (one TLS record each way) puts it
at ~1.5 us per record and direction: 7.0 us of server CPU per exchange
plain, 8.4 with kTLS on receive, 8.8 on send, 10.1 on both (4 KiB: 7.6,
10.3, 10.4, 12.3). The sender's own lag stayed under 0.65 ms at its
maximum and under a microsecond at p99. The p99.9 swings between runs in
every mode, plaintext included: this is a desktop (a browser open), not
an isolated host.

An idle keep-alive HTTPS connection on user-space records keeps its keys'
page and gives the record buffers back: 2000 of them cost the worker
~1.2 KiB each.

## HTTPS throughput (earlier, closed loop)

4 workers, a route okena answers itself, `wrk` on other cores, keep-alive.

| Measure | Result | Date |
|---|---|---|
| HTTPS keep-alive, kTLS | 284k requests/s | 2026-10 |
| HTTPS keep-alive, user-space records | 302k requests/s | 2026-10 |
| Plain HTTP keep-alive | 406k requests/s | 2026-10 |
| 50 MB download, kTLS | 933 MB/s | 2026-10 |
| 50 MB download, user-space records | 1.05 GB/s (755 MB/s before the eight-block GCM) | 2026-10 |

## Handshake budget

One worker, 6000 TLS handshakes arriving at once (three Python clients,
500-connection bursts), and an open keep-alive HTTPS connection asking
meanwhile: the latency of that connection. okena on core 1, the asking
client on core 2, the flood on cores 3-7. The handshake throughput was the
same in every case, but the Python clients bound it, so the budget's cost
in handshakes per second is not measured here.

| `handshake_budget` | p50 | p99 | Date |
|---|---|---|---|
| off (`0us`) | 31 us | 1.62 ms | 2026-10-30 |
| 200 us | 31 us | 0.84 ms | 2026-10-30 |
| 100 us (default) | 30 us | 0.47 ms | 2026-10-30 |
| 50 us | 31 us | 0.33 ms | 2026-10-30 |

The maximum stayed at 1.5-3 ms in every mode, budget or not; its cause is
not isolated yet.

## Against HAProxy, in front of a real API (2026-10-30)

The backend is [fasm2crud](https://github.com/Lu4nScr1pt1ng/fasm2Crud): an
HTTP/1.1 JSON API in assembly with PostgreSQL 18 behind it (auth tokens,
notes stored as rows). Every scenario runs straight to it too, so what a
proxy adds shows. Rerun with `tests/bench/api.sh` (its header says how to
start the backend).

| | |
|---|---|
| okena | this commit, io_uring, native, `taskset -c 1,2` (2 workers) |
| HAProxy | 3.2.26 (OpenSSL 3.5.7), official image, `--network host`, `--cpuset-cpus 1,2`, `nbthread 2`, `http-reuse always`, TLS 1.3 suite AES-128-GCM |
| backend | fasm2crud native, 2 workers on cores 3-4, `API_RATE=0`; PostgreSQL 18.1 in its compose (unpinned) |
| load | wrk 4.x, 6 threads on cores 5-7 and 13-15, 64 connections, 10 s a scenario; closed loop (no coordinated-omission correction) |
| TLS | ECDSA P-256 certificate on both; "x25519" runs force the client's groups through `OPENSSL_CONF`, the others take its default (X25519MLKEM768); wrk does not resume sessions, so every new connection is a full handshake |

| Scenario | Server | req/s | p50 / p99 (us) | non-2xx |
|---|---|---|---|---|
| GET /healthz, keep-alive | fasm2crud direct | 348847 | 180 / 260 | 0 |
| GET a note (token + PostgreSQL), keep-alive | fasm2crud direct | 51592 | 1050 / 3880 | 0 |
| POST a note (PostgreSQL write), keep-alive | fasm2crud direct | 8528 | 7110 / 10320 | 0 |
| GET /healthz, keep-alive | okena, 2 cores | 162605 | 369 / 448 | 0 |
| GET a note (token + PostgreSQL), keep-alive | okena, 2 cores | 52743 | 1040 / 4390 | 0 |
| POST a note (PostgreSQL write), keep-alive | okena, 2 cores | 8219 | 7050 / 280930 | 0 |
| GET /healthz through TCP (L4) | okena, 2 cores | 172569 | 344 / 411 | 0 |
| HTTPS GET /healthz, keep-alive | okena, 2 cores | 125525 | 462 / 890 | 0 |
| HTTPS GET a note, keep-alive | okena, 2 cores | 52098 | 1040 / 4320 | 0 |
| HTTPS, a new connection per request (x25519, ECDSA) | okena, 2 cores | 15052 | 870 / 2160 | 0 |
| HTTPS, a new connection per request (X25519MLKEM768) | okena, 2 cores | 10107 | 1380 / 2010 | 0 |
| GET /healthz, keep-alive | HAProxy 3.2, 2 threads | 106739 | 544 / 813 | 0 |
| GET a note (token + PostgreSQL), keep-alive | HAProxy 3.2, 2 threads | 50784 | 1020 / 4820 | 0 |
| POST a note (PostgreSQL write), keep-alive | HAProxy 3.2, 2 threads | 8185 | 7050 / 269140 | 0 |
| GET /healthz through TCP (L4) | HAProxy 3.2, 2 threads | 138119 | 431 / 508 | 0 |
| HTTPS GET /healthz, keep-alive | HAProxy 3.2, 2 threads | 83069 | 710 / 1010 | 0 |
| HTTPS GET a note, keep-alive | HAProxy 3.2, 2 threads | 42756 | 990 / 4840 | 0 |
| HTTPS, a new connection per request (x25519, ECDSA) | HAProxy 3.2, 2 threads | 5889 | 5050 / 6200 | 0 |
| HTTPS, a new connection per request (X25519MLKEM768) | HAProxy 3.2, 2 threads | 5025 | 5900 / 6860 | 0 |

Read with care:

* A proxy on 2 cores in front of a backend on 2 cores is the proxy's
  ceiling for `/healthz` (the backend alone does 349k/s): okena forwards
  163k/s at a p99 of 448 us, HAProxy 107k/s at 813 us; through L4, 173k/s
  against 138k/s.
* Where PostgreSQL is the limit (reading a note, ~52k/s), both proxies add
  close to nothing; okena's p99 stays a little under HAProxy's.
* Writing notes is PostgreSQL's limit (8.5k/s). Its p99 swings between
  runs and between servers (a first run had 334 ms for okena and 12 ms for
  HAProxy, this one 281 ms and 269 ms); the same load through okena alone
  at 8 and 64 connections gave p99s of 1.1 ms and 9.5 ms. That tail is the
  database's (checkpoints and autovacuum under a stream of inserts), not
  the proxies'.
* New HTTPS connections: 15.1k/s for okena against 5.9k/s for HAProxy with
  x25519 (2.6 times), 10.1k/s against 5.0k/s with the post-quantum hybrid.
* HTTPS keep-alive: 126k/s against 83k/s (okena hands the keys to kTLS;
  HAProxy 3.2 seals in user space).

Not measured yet: this comparison in open loop (`okena bench`), the
two-host topology, and nginx. The HTTPS rows above were taken with kTLS,
before user-space records became the default for `http` listeners.
