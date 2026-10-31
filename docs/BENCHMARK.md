# Benchmarks

Measurements of okena, and comparisons with the established software for
each job (OpenSSL for crypto, HAProxy and nginx for proxying), kept so they
can be rerun and compared later. Every entry says when, on what, and how.
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
