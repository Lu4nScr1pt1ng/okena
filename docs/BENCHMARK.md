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
| X25519 (variable base) | 25.2 us | 25.5 us | 2026-11-12 | mulx/adcx/adox ladder; 5 multiplications and 4 squares a step at ~45 cycles: the scalar ladder's floor without AVX-512 IFMA (Zen 3 has none) |
| X25519 (fixed base, key generation) | 8.0 us | | 2026-10 | Edwards-form table |
| ECDSA P-256 sign (RFC 6979) | 12.3 us | ~15.6 us | 2026-11-12 | fixed-base table; Z and k inverted blinded, in variable time, trailing zeros at once (tzcnt, a Montgomery step for 2^t); only x made affine. 15.6 us with Fermat's inversion of Z |
| ECDSA P-256 verify, a key in use | 14.2 us | 47.8 us | 2026-11-12 | from a key's 16th use, a fixed-base table of its own (37 x 64 affine multiples, made once, ~1 ms): u1 G + u2 Q in 74 mixed additions, no doubling; entries read at their index and X = r Z^2 checked without an inversion (all public data) |
| ECDSA P-256 verify, a key seen once | 67 us | 47.8 us | 2026-10-30 | u1 G by the fixed-base table, u2 Q by a width-5 NAF in Jacobian coordinates (259 us with two constant-time ladders) |
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

## HTTP/1.1 against Envoy, HAProxy and nginx, all in Docker (2026-11-12)

`tests/bench/http.sh`. Every proxy in a container on the same two cores (1-2,
their SMT siblings idle), host network: okena from this tree's image with its
seccomp profile (io_uring), Envoy 1.40, HAProxy 3.2 and nginx 1.27 from their
official images, each with as many threads as cores and tuned by its own
documentation (upstream keep-alive, Envoy's circuit breakers raised, no
access logs). The backend is nginx answering "ok" from memory on cores 4-5
(320k req/s straight to it); plain HTTP/1.1, keep-alive on both sides.

The most each does, closed loop (wrk, 8 threads, 256 connections, 10 s):

| Proxy (2 cores) | most req/s | per core |
|---|---|---|
| okena | 146471 | 73235 |
| HAProxy 3.2 | 104479 | 52239 |
| nginx 1.27 | 86024 | 43012 |
| Envoy 1.40 | 36713 | 18356 |

Envoy was at 189% CPU with no errors: that is what its HTTP/1 path costs here.

Latency at fixed rates, open loop (okena bench, 64 connections, 4 workers,
from the schedule), each point three times and the median of each
percentile, microseconds:

| Proxy | rate | p50 / p99 / p99.9 / max | behind | errors |
|---|---|---|---|---|
| okena | 10000/s | 44 / 62 / 89 / 565 | 0 | 0 |
| okena | 30000/s | 40 / 64 / 116 / 1172 | 0 | 0 |
| okena | 80000/s | 44 / 69 / 123 / 778 | 0 | 0 |
| HAProxy | 10000/s | 53 / 73 / 100 / 397 | 0 | 0 |
| HAProxy | 30000/s | 51 / 99 / 3047 / 7553 | 0 | 0 |
| HAProxy | 80000/s | 151 / 211812 / 226492 / 228813 | 0 | 0 |
| nginx | 10000/s | 58 / 77 / 116 / 635 | 0 | 0 |
| nginx | 30000/s | 61 / 133 / 573 / 1580 | 0 | 0 |
| nginx | 80000/s | 344 / 2919235 / 2952790 / 2957399 | 45411 | 35 |
| Envoy | 10000/s | 121 / 200 / 327 / 2304 | 0 | 0 |
| Envoy | 30000/s | 696 / 1327 / 3932 / 5036 | 0 | 0 |
| Envoy | 80000/s | (did not keep up: 416034 behind) | | 64 |

* okena does 40% more than HAProxy, 70% more than nginx and four times
  Envoy on the same cores, and has the lowest p50, p99 and p99.9 at every
  rate; it alone holds 80000/s on two cores (p99 69 us, p99.9 123).
* The first run of this table (same day) had okena **losing at p99.9** at
  10000/s and 30000/s: 589 and 1146 us against HAProxy's 104 and 315. The
  cause was not okena's loop (no iteration over 300 us, checked) nor the
  CPU's idle states (holding /dev/cpu_dma_latency at 20 us changed nothing),
  but its workers being pinned one to a core: on a host that runs anything
  else, a pinned worker waits for whatever took its core, milliseconds, where
  the others' threads move. Free, p99.9 fell to 54-59 us; but under load free
  workers sometimes shared a core (at 80000/s p99 466-532 us, pinned 73-89).
  `pin_workers auto` (now the default) is each by turn: a worker past half a
  core pins itself, one under a fifth lets go; throughput is the same either
  way (155k req/s, io_uring, pinned or free).

## HTTPS, TLS 1.3 and 1.2, against Envoy, HAProxy and nginx, all in Docker (2026-11-12)

`TLS=1.3 tests/bench/http.sh` (and `TLS=1.2`): the same setup as above, each
proxy terminating TLS with the same ECDSA P-256 certificate and that version
only (ALPN http/1.1, its own defaults: session tickets on), the backend plain.
Keep-alive throughput from wrk. Full handshakes from `openssl s_time -new`, two
on each of the eight load cores, never a resumption (wrk resumes nearly every
connection: okena's counters showed 10250 of 10266, so its "new connections"
are abbreviated handshakes); their rate is a floor where the clients are the
limit (okena's is: about 14k a second here), so the proxy's CPU (its
container's cgroup) gives what a handshake costs it. Latency from oha (it
speaks TLS 1.2; slower than okena bench, so every number is higher than plain
HTTP's for all), median of three.

| Proxy (2 cores) | TLS | keep-alive req/s | full handshakes/s | handshakes per CPU-second |
|---|---|---|---|---|
| okena | 1.3 | 144845 | 9940 | 8299 |
| Envoy 1.40 | 1.3 | 31932 | 8328 | 5197 |
| HAProxy 3.2 | 1.3 | 79028 | 6302 | 3336 |
| nginx 1.27 | 1.3 | 72893 | 5285 | 2915 |
| okena | 1.2 | 141724 | 13182 | 9646 |
| Envoy 1.40 | 1.2 | 30510 | 10738 | 6630 |
| HAProxy 3.2 | 1.2 | 79140 | 6840 | 3621 |
| nginx 1.27 | 1.2 | 70379 | 6060 | 3365 |

Latency, microseconds, p50 / p99 / p99.9 / max:

| Proxy | TLS | 10000/s | 30000/s | 60000/s |
|---|---|---|---|---|
| okena | 1.3 | 131 / 268 / 548 / 10679 | 254 / 593 / 2786 / 17844 | 474 / 957 / 4231 / 13696 |
| HAProxy | 1.3 | 193 / 398 / 3409 / 22324 | 446 / 902 / 6415 / 20348 | 849 / 40664 / 55724 / 58785 |
| nginx | 1.3 | 202 / 452 / 4546 / 19518 | 486 / 1067 / 8844 / 18730 | 865 / 7334 / 18085 / 22265 |
| Envoy | 1.3 | 441 / 973 / 6369 / 16563 | 2166 / 88412 / 92521 / 94741 | did not keep up |
| okena | 1.2 | 132 / 261 / 453 / 12659 | 253 / 557 / 3698 / 20729 | 466 / 1118 / 6805 / 18912 |
| HAProxy | 1.2 | 189 / 388 / 2548 / 16435 | 427 / 1152 / 11306 / 23450 | 878 / 19350 / 34224 / 37499 |
| nginx | 1.2 | 199 / 443 / 4649 / 19750 | 441 / 1068 / 8616 / 19004 | 943 / 6377 / 16881 / 21856 |
| Envoy | 1.2 | 419 / 900 / 6672 / 22762 | 1590 / 19581 / 20804 / 22473 | did not keep up |

* After ECDSA signatures went from 14.9 to 12.3 us and handshakes stopped
  calling getrandom (a pool, MADV_WIPEONFORK), okena's handshakes per
  CPU-second: 8636 (1.3, was 8299) and 10213 (1.2, was 9646). Most of what is
  left is the kernel's (the TCP connection) and X25519's ladder.
* okena keeps its plaintext throughput with TLS (records sealed and opened
  in user space, ~1.5%); the others lose 20-25%. 80% over HAProxy, twice
  nginx, 4.5 times Envoy, either version.
* A full handshake costs okena 60% less CPU than Envoy (1.3; 45% less in
  1.2) and 2.5 to 3 times less than HAProxy and nginx. In 1.3 the client
  offers X25519MLKEM768 first (OpenSSL 3.5's default): an ML-KEM
  encapsulation each. Of okena's user-space time in a 1.2 handshake about
  half is X25519 (25.2 us variable base, 7.9 us from its table; OpenSSL 25.5)
  and a fifth ECDSA P-256 (14.7 us a signature); the rest of a handshake's
  cost is the kernel's (accept, the TCP connection), the same for all.
* The lowest p50, p99 and p99.9 at every rate and version.
* This run found two things in okena's TLS 1.2: its records went to kTLS
  whenever the host had the module, ignoring `ktls` (1.3 keeps them in user
  space unless `ktls on`): 16% less keep-alive traffic than 1.3, now the same;
  and it took the client's first suite, AES-256 for every OpenSSL client,
  where it now prefers AES-128 unless the client puts ChaCha20 first.

## HTTP/2 against Envoy, HAProxy and nginx, all in Docker (2026-11-12)

`H2=1 tests/bench/http.sh`: the same setup, the clients speaking HTTP/2 in
clear (h2c, prior knowledge: okena `http2 on`, Envoy's codec AUTO, HAProxy
`proto h2`, nginx `http2 on`), HTTP/1.1 with keep-alive to the backend. The
most each does from h2load (nghttp2; 64 connections, 16 streams each, 10 s;
counted only when every answer came over h2c and 99% were 2xx); latency from
okena bench proto=h2 (64 connections, one stream at a time each, open loop),
each point five times and the median of each percentile: on this host one run
of ten seconds can move a p99.9 several times either way.

| Proxy (2 cores) | most req/s | per core |
|---|---|---|
| okena | 182033 | 91016 |
| HAProxy 3.2 | 97503 | 48751 |
| nginx 1.27 | 73328 | 36664 |
| Envoy 1.40 | 39586 | 19793 |

| Proxy | rate | p50 / p99 / p99.9 / max (us) | behind | errors |
|---|---|---|---|---|
| okena | 10000/s | 46 / 65 / 95 / 1016 | 0 | 0 |
| okena | 30000/s | 40 / 66 / 94 / 717 | 0 | 0 |
| okena | 80000/s | 51 / 178 / 1196 / 2762 | 0 | 0 |
| HAProxy | 10000/s | 56 / 73 / 110 / 930 | 0 | 0 |
| HAProxy | 30000/s | 65 / 82 / 159 / 1178 | 0 | 0 |
| HAProxy | 80000/s | 200 / 236978 / 251658 / 257911 | 0 | 0 |
| nginx | 10000/s | 71 / 97 / 141 / 525 | 0 | 0 |
| nginx | 30000/s | 91 / 266 / 1884 / 3370 | 0 | 0 |
| nginx | 80000/s | 671088 / 2248146 / 2309050 / 2309050 | 12686 | 33 |
| Envoy | 10000/s | 163 / 221 / 331 / 1059 | 0 | 0 |
| Envoy | 30000/s | 255852 / 1090519 / 1107296 / 1113241 | 0 | 0 |
| Envoy | 80000/s | (did not keep up: 461850 behind) | | 64 |

* okena does 87% more than HAProxy, 2.5 times nginx and 4.6 times Envoy, and
  more over HTTP/2 than over HTTP/1.1 (many streams, fewer syscalls).
* The lowest p50, p99 and p99.9 at every rate; at 80000/s on two cores only
  okena answers in under a millisecond at p99 (178 us; HAProxy 237 ms).
* A first run with a median of three had okena at 315 us at p99.9 at
  30000/s against HAProxy's 157; a paired rerun, 679 against 1261; with five
  runs, 94 against 159. Its tail moves with the host's noise, not okena's
  pinning (free, auto and pinned compared natively: auto 99-101 us).

## gRPC against Envoy, HAProxy and nginx, all in Docker (2026-11-12)

`tests/bench/grpcmax.sh`: each proxy in a container on the same two cores,
gRPC over h2c both sides (okena `protocol h2`, Envoy's cluster on HTTP/2,
HAProxy `proto h2` both ends, nginx `grpc_pass`), the Go echo backend of
tests/bench/grpc on cores 4-5 and 12-13. Unary calls of 64 bytes. The most
from h2load posting gRPC frames (64 connections, 16 streams); every proxy
checked first to end calls with grpc-status 0 (grpcbench: 4000 calls, no
error for any). Latency from grpcbench (Go, open loop), median of three.

| Path (2 cores) | unary calls/s | per core |
|---|---|---|
| straight to the backend | 222228 | |
| okena | 145688 | 72844 |
| HAProxy 3.2 | 55347 | 27673 |
| Envoy 1.40 | 50898 | 25449 |
| nginx 1.27 | 35118 | 17559 |

| Path | rate | p50 / p99 / p99.9 / max (us) |
|---|---|---|
| direct | 5000/s | 148 / 182 / 461 / 2128 |
| direct | 20000/s | 143 / 644 / 1976 / 3120 |
| direct | 40000/s | 123 / 1210 / 3983 / 11389 |
| okena | 5000/s | 184 / 243 / 467 / 1482 |
| okena | 20000/s | 194 / 1166 / 3239 / 6036 |
| okena | 40000/s | 202 / 3050 / 10684 / 20033 |
| HAProxy | 5000/s | 200 / 269 / 508 / 1507 |
| HAProxy | 20000/s | 232 / 1594 / 3193 / 4756 |
| HAProxy | 40000/s | 8178 / 96825 / 143748 / 152105 |
| Envoy | 5000/s | 268 / 361 / 539 / 2471 |
| Envoy | 20000/s | 982 / 45236 / 72069 / 89040 |
| Envoy | 40000/s | 22541 / 220870 / 289437 / 341809 |
| nginx | 5000/s | 212 / 286 / 553 / 1675 |
| nginx | 20000/s | 8873 / 116461 / 143665 / 177335 |
| nginx | 40000/s | 1889012 / 6308947 / 7758162 / 9545108 |

* okena does 2.6 times HAProxy's gRPC calls, 2.9 times Envoy's (gRPC's own
  proxy) and 4.1 times nginx's, on the same two cores.
* The Go client is most of every latency here (straight to the backend, p50
  148 us and p99.9 2 ms at 20000/s). Within that: okena lowest at p50 and p99
  everywhere, and at p99.9 at 5000 and 40000/s; at 20000/s its p99.9 is
  HAProxy's (3239 against 3193 us, under the client's noise). At 40000/s only
  okena stays near the backend's own tail (p99 3 ms; HAProxy 97 ms, Envoy
  221 ms, nginx seconds).

## L4, TCP and UDP, against HAProxy, nginx and Envoy, all in Docker (2026-11-12)

`tests/bench/l4max.sh`: okena (`tcp` and `udp` listeners), HAProxy 3.2
(`mode tcp`; UDP is not in its open source edition), nginx 1.27 (`stream`)
and Envoy 1.40 (tcp_proxy, udp_proxy), each in a container on the host
network on cores 1-2, in front of the same backends (tests/bench/l4bench.c:
an echo, a sink, a UDP echo on 4-5 and 12-13), loaded by l4bench on the
other cores. ping1: one connection, 64 bytes and their echo, closed loop;
ping256: 256 connections, a message in flight on each; bulk: 8 connections
writing to the sink (bulk256: 256); connect: a new connection per 64-byte
exchange, the client closing with a reset; udp1/udp256: the same as ping
with datagrams. Median of 3 runs.

| Path (2 cores) | test | rate | p50 / p99 / p99.9 / max (µs) | lost |
|---|---|---|---|---|
| direct | ping1 | 65097/s | 15.0 / 21.2 / 29.7 / 203.3 |  |
| direct | ping256 | 465604/s | 560.1 / 1002.1 / 1206.2 / 2286.6 | 0 |
| direct | bulk | 241.23 Gbit/s | |  |
| direct | bulk256 | 109.32 Gbit/s | |  |
| direct | connect | 91227/s | 83.2 / 144.5 / 190.5 / 333.8 | 0 |
| direct | udp1 | 73721/s | 13.4 / 16.8 / 21.1 / 464.5 | 0 |
| direct | udp256 | 574350/s | 433.6 / 485.1 / 501.9 / 729.3 | 0 |
| okena | ping1 | 37097/s | 26.5 / 33.8 / 50.2 / 421.7 |  |
| okena | ping256 | 154448/s | 1700.6 / 1871.6 / 2282.8 / 2672.3 | 0 |
| okena | bulk | 53.36 Gbit/s | |  |
| okena | bulk256 | 51.00 Gbit/s | |  |
| okena | connect | 24299/s | 325.2 / 572.1 / 629.3 / 744.1 | 0 |
| okena | udp1 | 37410/s | 26.4 / 33.3 / 48.0 / 141.3 | 0 |
| okena | udp256 | 186815/s | 1382.7 / 1451.2 / 1978.0 / 2317.8 | 0 |
| haproxy | ping1 | 28131/s | 34.8 / 46.4 / 73.5 / 128.9 |  |
| haproxy | ping256 | 131037/s | 1958.1 / 2486.6 / 2720.7 / 3451.5 | 0 |
| haproxy | bulk | 20.98 Gbit/s | |  |
| haproxy | bulk256 | 20.62 Gbit/s | |  |
| haproxy | connect | 21640/s | 367.8 / 493.1 / 563.3 / 3398.4 | 0 |
| nginx | ping1 | 29768/s | 33.0 / 43.3 / 71.1 / 127.4 |  |
| nginx | ping256 | 140184/s | 1916.2 / 2015.4 / 2598.8 / 3096.9 | 0 |
| nginx | bulk | 22.92 Gbit/s | |  |
| nginx | bulk256 | 21.40 Gbit/s | |  |
| nginx | connect | 14040/s | 443.2 / 4549.1 / 10237.5 / 13051.3 | 0 |
| nginx | udp1 | 33471/s | 29.4 / 36.8 / 54.5 / 126.7 | 0 |
| nginx | udp256 | 145634/s | 1768.5 / 1812.9 / 1966.9 / 2352.9 | 0 |
| envoy | ping1 | 24476/s | 39.9 / 54.0 / 85.5 / 161.1 |  |
| envoy | ping256 | 106803/s | 2374.8 / 3021.9 / 3327.0 / 4018.7 | 0 |
| envoy | bulk | 41.77 Gbit/s | |  |
| envoy | bulk256 | 34.19 Gbit/s | |  |
| envoy | connect | 12473/s | 646.5 / 1142.4 / 1549.0 / 3070.2 | 0 |
| envoy | udp1 | 29976/s | 32.5 / 46.1 / 70.8 / 198.4 | 0 |
| envoy | udp256 | 131256/s | 2062.6 / 2164.9 / 2365.6 / 3072.5 | 0 |

* okena first in every row. One flow (ping1, udp1) by `busy_poll auto`: a
  pinned worker polls while events come within 50 µs of each other.
* Bulk: large buffers for a direction that fills a small one, a small hot
  provided ring, and on io_uring the bulk directions read and write in the
  loop through the buffer given back last: 256 connections no longer fall
  behind 8 (35 -> 51 Gbit/s).
* Connect: an abort passed on as an abort (SO_LINGER 0 on the other side)
  leaves no TIME_WAIT on okena's ports: 14.5k -> 24.3k/s, p99 8.5 -> 0.57 ms.

## XDP L4 balancing against Katran, one core (2026-11-12)

`tests/bench/xdp.sh` (kernel 7.3.0, pktgen loaded): okena's `mode xdp`
(okena.conf, a `udp` VIP, three reals) against Katran's balancer.bpf.c at
04a4733 (built with the container's clang 18, loaded with libbpf 1.3, its
maps filled as its control plane does: the default router's MAC, one VIP,
the ring, an LRU a CPU of 2^20 / CPUs flows), both encapsulating in IPIP
and sending back with XDP_TX. In a privileged container of its own:
pktgen on three CPUs into a veth, the balancer's NAPI a thread on a core
of its own (4), what it sends dropped by XDP on the far end (core 6).
UDP, 60-byte packets; packets a second the balancer sent (XDP_TX on its
veth), the median of 5 seconds; the balancer's core busy all the time.
`base` is XDP_TX and nothing else: what the veth path costs alone (the veth
turns pktgen's skbs into XDP buffers, a copy; a NIC would not). est: 1024
flows over and over (in the flow table); new: source address and port
drawn for each packet (every packet a new flow).

| | est | new |
|---|---|---|
| base (the path alone) | 3.42 M | 3.47 M |
| okena | **2.57 M** | **1.98 M** |
| Katran | 2.20 M | 1.60 M |
| Katran, MAX_CONN_RATE out of reach | 2.31 M | 1.21 M |
| okena, no bound on new flows remembered | | 1.30 M |

* Less the path, a packet of a flow in the table costs okena's program
  about 100 ns, Katran's about 160 ns. The kernel's own count of the time
  in each program (`kernel.bpf_stats_enabled`, now printed by the bench;
  it adds its clock reads to each run): okena 122 ns, Katran 157 ns, est;
  the same 122 ns after IPv6, GUE and ICMP were added to the program.
* Before this entry okena did 1.99 M (est) and 1.10 M (new): the next hop
  (bpf_fib_lookup, the kernel's routes and neighbours) was asked for every
  packet. Now each CPU keeps the kernel's answer for a real for the time
  step it got it in (2^30 ns): Katran's speed without its fixed default
  router MAC, and a route or neighbour change is followed within a second
  (tests/xdp/vip.sh changes a real's MAC under load).
* New flows: past 125000 a time step on one CPU they are routed by the
  ring and not remembered, as Katran does (its MAX_CONN_RATE): the flows
  in the table are not pushed out by a flood. With neither bound, okena
  1.30 M against Katran 1.21-1.27 M (two runs): there the LRU insert is
  most of the cost.

## Large HTTP/1.1 response bodies, all in Docker (2026-11-12)

`tests/bench/httpbig.sh`: the same four proxies (nginx with
`proxy_buffering off`), the backend `l4bench httpbig` (GET /SIZE answered
with SIZE bytes, keep-alive), h2load --h1, 64 connections, closed loop,
median of 3. A Content-Length body of 16 KiB or more that nothing in between
needs to see goes by the L4 relay, counted to the byte
(src/http/counted.inc).

| Path (2 cores) | body | Gbit/s | requests/s |
|---|---|---|---|
| direct | 64KB | 36.0 | 68593 |
| okena | 64KB | 30.1 | 57387 |
| haproxy | 64KB | 19.4 | 36959 |
| nginx | 64KB | 6.2 | 11830 |
| envoy | 64KB | 12.8 | 24335 |
| direct | 1.0MB | 146.5 | 17466 |
| okena | 1.0MB | 49.6 | 5918 |
| haproxy | 1.0MB | 26.4 | 3147 |
| nginx | 1.0MB | 7.7 | 919 |
| envoy | 1.0MB | 33.2 | 3959 |

## Gateway features against Envoy, HAProxy and nginx, all in Docker (2026-11-12)

`tests/bench/gw.sh`: each proxy in a container on cores 1-2, a listener a
scenario so that one feature never touches another's numbers, in front of
the same backend (`l4bench httpbig`: 100-byte answers, cacheable for an
hour); wrk, 256 connections, closed loop, median of 3. none: the plain
proxy. jwt: ES256 bearer tokens checked (signature, exp, iss, aud), 100000
different tokens in turn (users), each used some 15 times in a run; Envoy's
jwt_authn with its cache on (200000), HAProxy's jwt_verify (no cache),
nginx has no JWT outside NGINX Plus. limit: a per-client-address limit
never reached (its cost). cache: every request a hit (okena `cache 1h`,
HAProxy's `cache`, nginx `proxy_cache`, Envoy's cache filter). check: a
bad token got 401.

| Proxy (2 cores) | scenario | requests/s | p99 (wrk) | check |
|---|---|---|---|---|
| okena | none | 108372 | 3.35ms | - |
| okena | jwt | 96719 | 3.80ms | 401 |
| okena | limit | 111477 | 2.92ms | - |
| okena | cache | 293852 | 1.13ms | - |
| envoy | none | 29325 | 10.84ms | - |
| envoy | jwt | 25374 | 12.63ms | 401 |
| envoy | limit | 29245 | 10.91ms | - |
| envoy | cache | 28291 | 11.17ms | - |
| haproxy | none | 86073 | 3.22ms | - |
| haproxy | jwt | 23341 | 12.60ms | 401 |
| haproxy | limit | 83748 | 3.50ms | - |
| haproxy | cache | 182960 | 1.60ms | - |
| nginx | none | 82965 | 3.38ms | - |
| nginx | jwt | (NGINX Plus only) | | |
| nginx | limit | 75952 | 4.42ms | - |
| nginx | cache | 54460 | 5.06ms | - |

* JWT: verified tokens kept in a two-way table of 128 Ki a worker (was 1024
  direct mapped), and a key in use verifies with a table of its own (ECDSA
  67 -> 14.2 us): 36k -> 97k requests/s.
* Cache hit: one send for head and body (163k -> 276k), and the clock from
  the TSC instead of a system call at each lookup.

## Idle keep-alive connections: memory, all in Docker (2026-11-12)

`tests/bench/idlemem.sh`: 100000 clients (in a container of their own) each
make one request, read its answer and stay connected, idle. The proxy's own
memory, `anon` from its container's cgroup (the kernel's socket buffers left
out, the same for all), before the connections and 5 s after the last; the
count is of the connections open on the proxy's side at that moment (a
first version counted what the client had read, connections the proxy had
closed meanwhile included: its figures were too low, okena's 534 B among
them).

| Proxy (2 workers) | idle connections | memory before | after | per connection |
|---|---|---|---|---|
| okena | 100000 | 5 MiB | 75 MiB | 727 B |
| HAProxy 3.2 | 100000 | 71 MiB | 185 MiB | 1189 B |
| nginx 1.27 | 100000 | 840 MiB | 896 MiB | 587 B |
| Envoy 1.40 | 100000 | 18 MiB | 1599 MiB | 16572 B |

* okena 971 -> 727 B: the client's side record 256 -> 64 bytes (the PROXY
  header in a table of its own), no transparent huge pages on per-session
  tables. What is left: the session (128 B), the HTTP state (512 B), the
  side record (64 B). nginx's connection is smaller; its arrays are
  reserved up front for `worker_connections` (1000000 here: 840 MiB before
  the first), so in all okena holds less up to some 1.4 million connections.
* Past 56000 idle connections okena used to close what came: the default
  `limits { connections }` was 65536 and the overload manager acts at 80%
  of it. The default is now what a worker can hold. 262144 idle
  connections through okena held 233 MiB; more was this host's conntrack
  table (262144 entries), not okena.

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
latency until it arrives. Bidi: 8 bidirectional streams held open, a
message on the next one each tick, latency until its echo comes back.
Each rate straight to the backend first; "added" is a proxy's percentile
minus that. Other containers stopped.

| Scenario | Path | rate | p50 / p99 / p99.9 / max (us) | added p50 / p99 | errors |
|---|---|---|---|---|---|
| unary, 5000/s | direct | 5000/s | 137 / 198 / 384 / 1832 | | 0 |
| unary, 20000/s | direct | 20000/s | 136 / 771 / 2175 / 3394 | | 0 |
| unary, 40000/s | direct | 40001/s | 175 / 2289 / 3441 / 6505 | | 0 |
| stream, 5000/s | direct | 5000/s | 45 / 64 / 82 / 227 | | 0 |
| stream, 20000/s | direct | 20000/s | 51 / 73 / 194 / 663 | | 0 |
| stream, 80000/s | direct | 80002/s | 27 / 139 / 329 / 5627 | | 0 |
| bidi, 5000/s | direct | 5000/s | 105 / 127 / 145 / 1789 | | 0 |
| bidi, 20000/s | direct | 20000/s | 104 / 146 / 903 / 2468 | | 0 |
| bidi, 40000/s | direct | 40000/s | 84 / 274 / 1694 / 3092 | | 0 |
| unary, 5000/s | okena, 2 cores | 5000/s | 170 / 246 / 779 / 2984 | +33 / +48 | 0 |
| unary, 20000/s | okena, 2 cores | 20000/s | 174 / 799 / 2219 / 4701 | +38 / +28 | 0 |
| unary, 40000/s | okena, 2 cores | 40001/s | 179 / 1199 / 2509 / 4447 | +4 / -1090 | 0 |
| stream, 5000/s | okena, 2 cores | 5000/s | 67 / 92 / 259 / 1294 | +22 / +28 | 0 |
| stream, 20000/s | okena, 2 cores | 20000/s | 73 / 101 / 302 / 2411 | +22 / +28 | 0 |
| stream, 80000/s | okena, 2 cores | 80000/s | 54 / 104 / 311 / 2230 | +27 / -35 | 0 |
| bidi, 5000/s | okena, 2 cores | 5000/s | 139 / 165 / 318 / 2806 | +34 / +38 | 0 |
| bidi, 20000/s | okena, 2 cores | 20000/s | 139 / 193 / 1335 / 2981 | +35 / +47 | 0 |
| bidi, 40000/s | okena, 2 cores | 40001/s | 118 / 270 / 1817 / 2991 | +34 / -4 | 0 |
| unary, 5000/s | Envoy 1.40.2, 2 threads | 5000/s | 258 / 348 / 492 / 1391 | +121 / +150 | 0 |
| unary, 20000/s | Envoy 1.40.2, 2 threads | 20005/s | 548 / 5659 / 8112 / 12325 | +412 / +4888 | 0 |
| unary, 40000/s | Envoy 1.40.2, 2 threads | 40006/s | 1634 / 122000 / 162877 / 195744 | +1459 / +119711 | 0 |
| stream, 5000/s | Envoy 1.40.2, 2 threads | 5000/s | 75 / 97 / 133 / 1171 | +30 / +33 | 0 |
| stream, 20000/s | Envoy 1.40.2, 2 threads | 20000/s | 94 / 133 / 260 / 1269 | +43 / +60 | 0 |
| stream, 80000/s | Envoy 1.40.2, 2 threads | 79998/s | 142 / 239 / 494 / 2610 | +115 / +100 | 0 |
| bidi, 5000/s | Envoy 1.40.2, 2 threads | 5000/s | 141 / 182 / 245 / 1827 | +36 / +55 | 0 |
| bidi, 20000/s | Envoy 1.40.2, 2 threads | 20000/s | 148 / 210 / 305 / 1429 | +44 / +64 | 0 |
| bidi, 40000/s | Envoy 1.40.2, 2 threads | 40001/s | 158 / 376 / 1765 / 2927 | +74 / +102 | 0 |

Read with care:

* okena adds less at p99 at every point: unary 48 us at 5k/s (Envoy
  150), streamed messages 28 us (Envoy 33-100), bidirectional 38-47 us
  (Envoy 55-102). At p50 it adds less everywhere too, by little for
  bidirectional streams at 5k/s (34 against 36 us).
* okena's p99.9 is the worse one in places (bidirectional at 20k/s:
  1.3 ms against 0.3 ms; unary at 5k/s: 0.8 ms against 0.5 ms): its
  tail is wakeups (`busy_poll` takes it in, see the open-loop HTTPS
  entry) and is not isolated further yet.
* At 20k unary calls/s Envoy's two threads are near their limit (+412 us
  at p50, +4.9 ms at p99); at 40k/s it queues (p99 0.12 s). okena serves
  40k/s with its p50 4 us above the direct path.
* The load program is the limit at the top rates: its own p99 straight to
  the backend reaches 2.3 ms for unary at 40k/s, and an added p99 below
  zero there means the proxy smoothed the client's bursts, not that it
  took time away. The comparison that holds is p50, and p99 at 5k-20k/s.
* Bidirectional streams through okena are new in this run: when both ends
  speak HTTP/2 the response is read as soon as the request head is out
  and the body follows beside it. Getting there under load found the
  cheap-frame budget cutting gRPC peers off (their BDP pings and window
  updates follow every DATA frame: credited now, and no budget towards
  backends), OUT full of okena's own DATA turning a PING into GOAWAY
  (DATA leaves room for control frames now), and an epoll worker that
  slept with deliveries waiting. Bidirectional 4 KB messages at 80k/s
  through one core run clean on both engines.

## HTTP/3 against HAProxy and nginx, all in Docker (2026-11-12)

`tests/bench/h3.sh`: okena (2 workers, `http3 on`, its image and seccomp
profile), HAProxy 3.2 (`nbthread 2`, `bind quic4@`, OpenSSL 3.5.7) and
nginx 1.27 (2 workers, `listen ... quic reuseport`), each in a container
on the host network, all on cores 1-2; the backend `l4bench http` on 4-5;
the load on the four other physical cores, from h2load built with HTTP/3
(nghttp2 1.66, ngtcp2 1.14, nghttp3 1.11 on OpenSSL 3.5:
tests/bench/h3/Dockerfile) and from `okena bench proto=h3`. ECDSA P-256,
X25519 for all three, 10 s a run. h2load is closed loop and its latencies
are per request after the connection (no correction for coordinated
omission); "first byte" includes the handshake. `okena bench` counts from
when the schedule asked for the request. Other containers stopped. One run
of each table.

| HTTP/3, many streams (64 x 10) | server | requests/s | p50 / p99 / p99.9 / max (µs) | failed |
|---|---|---|---|---|
| closed loop | okena, 2 workers | 191906.90 | 3324 / 6169 / 8508 / 43284 | 0 |
| closed loop | HAProxy 3.2, 2 threads | 127340.00 | 4913 / 6270 / 8682 / 75016 | 0 |
| closed loop | nginx 1.27, 2 workers | 94840.00 | 6068 / 19606 / 53718 / 157335 | 0 |

| HTTP/3, a new connection each | server | requests/s | p50 / p99 / p99.9 / max (µs) | failed | first byte, mean / max |
|---|---|---|---|---|---|
| 2000/s | okena, 2 workers | 2016.00 | 6779 / 15561 / 19792 / 20919 | 0 | 17.03ms / 57.07ms |
| 2000/s | HAProxy 3.2, 2 threads | 1315.49 | 21682 / 51317 / 56980 / 69738 | 0 | 60.65ms / 15.00s |
| 2000/s | nginx 1.27, 2 workers | 1117.19 | 73421 / 741532 / 3033018 / 12652843 | 0 | 637.06ms / 15.01s |
| 5000/s | okena, 2 workers | 4987.60 | 15987 / 36988 / 47504 / 50705 | 0 | 48.26ms / 129.41ms |
| 5000/s | HAProxy 3.2, 2 threads | 702.17 | 5156054 / 18132465 / 18755820 / 18961135 | 49810 | 15.33s / 19.71s |
| 5000/s | nginx 1.27, 2 workers | 1114.87 | 72841 / 1505312 / 6248082 / 21255953 | 12092 | 6.24s / 28.29s |
| 10000/s | okena, 2 workers | 9973.97 | 41953 / 115147 / 140529 / 171528 | 0 | 111.30ms / 293.54ms |
| 10000/s | HAProxy 3.2, 2 threads | 656.39 | 3297326 / 14433474 / 15183472 / 15329551 | 135310 | 18.05s / 29.62s |
| 10000/s | nginx 1.27, 2 workers | 770.75 | 444765 / 17037002 / 27112139 / 34425584 | 127208 | 7.23s / 34.46s |

| HTTP/3, keep-alive at 18k/s (60 x 300/s) | server | requests/s | p50 / p99 / p99.9 / max (µs) | failed |
|---|---|---|---|---|
| quiet | okena, 2 workers | 16778.30 | 67 / 131 / 240 / 10100 | 0 |
| under an Initial flood | okena, 2 workers | 16762.52 | 151 / 3562 / 16841 / 27560 | 0 |
| quiet | HAProxy 3.2, 2 threads | 16769.46 | 97 / 209 / 526 / 23792 | 0 |
| under an Initial flood | HAProxy 3.2, 2 threads | 8458.89 | 801 / 97291 / 103927 / 197957 | 0 |
| quiet | nginx 1.27, 2 workers | 16772.82 | 104 / 431 / 1383 / 19053 | 0 |
| under an Initial flood | nginx 1.27, 2 workers | 6150.80 | 120 / 28605 / 271364 / 27685075 | 0 |

| HTTP/3, open loop (60 connections) | server | requests/s | p50 / p99 / p99.9 / max (µs) | errors |
|---|---|---|---|---|
| 5000/s | okena, 2 workers | 5000.0 | 52 / 90 / 115 / 996 | 0 |
| 5000/s | HAProxy 3.2, 2 threads | 5000.0 | 69 / 117 / 196 / 4016 | 0 |
| 5000/s | nginx 1.27, 2 workers | 5000.0 | 61 / 204 / 266 / 355 | 0 |
| 18000/s | okena, 2 workers | 18000.0 | 43 / 66 / 98 / 2086 | 0 |
| 18000/s | HAProxy 3.2, 2 threads | 18000.0 | 70 / 114 / 188 / 1105 | 0 |
| 18000/s | nginx 1.27, 2 workers | 18000.0 | 55 / 99 / 327 / 1703 | 0 |
| 40000/s | okena, 2 workers | 40000.0 | 46 / 73 / 253 / 3159 | 0 |
| 40000/s | HAProxy 3.2, 2 threads | 40000.0 | 121 / 4718 / 8257 / 16569 | 0 |
| 40000/s | nginx 1.27, 2 workers | 40000.0 | 99 / 199229 / 213909 / 215075 | 0 |

* Many streams: okena 51% above HAProxy, twice nginx.
* Handshakes: okena keeps up to about 10k new connections a second on two
  cores with none failing; HAProxy and nginx top out near 0.7-1.3k/s here,
  and fail connections when offered more.
* Keep-alive, quiet: okena first at every percentile with both generators
  now. With h2load it used to be 10 to 40 µs behind at p50, and the two
  generators disagreed. The cause was in the load, not the server: h2load
  starts each connection's 300/s schedule when its handshake ends; okena
  completed the 60 handshakes in one burst, so ever after its requests came
  in bursts of 10-12 within 100 µs (a capture on lo showed it), and each
  waited for the ones before it (a request to a loopback backend costs
  about 10 µs of the kernel's time to send); HAProxy and nginx, slower at
  the handshakes, got theirs spread out. The connections now start 1 ms
  apart (`-r 8 --rate-period=1ms`), and every server gets the same arrivals:
  okena p50 / p99 67 / 131 µs, HAProxy 97 / 209, nginx 104 / 431 (with the
  same arrivals in an A/B of three runs: 71 against nginx's 79 at p50).
  The requests/s column counts the ramp of the connections too.
* Within a turn of the loop a QUIC socket is now read after the other
  completions: the answers from the backends go out before new requests
  come in (backend reply to datagram out, p50 41-46 µs in a burst).
* Under the flood (about 300k Initials a second, real ClientHellos never
  answered, tests/bench/h3flood.py) okena keeps the whole rate; HAProxy
  falls to 8.5k/s and nginx to 6.2k/s, with p99 near 30-100 ms. okena's
  own p99 is 3.6 ms and p99.9 17 ms here, against 0.5 and 2 ms on
  2026-11-05 (okena outside Docker then, HAProxy at 2.1k/s and nginx at
  4.1k/s). Six more runs, three with and three without the change below:
  p99 0.55-2.9 ms, p99.9 1.6-19 ms, alike for both; the flood's tail
  varies run to run, to be looked at. Modulo steering spreads the
  flood over the workers.
* An answer used to cost 3 datagrams out and 4 in: an ACK alone, the answer,
  MAX_STREAMS alone, and the client's ACK of each. Now about 1 and 2. Old
  and new binary alternated: `okena bench` p50 at 18k/s 46 -> 39 µs, h2load
  130-170 -> 103-156 µs (one binary varies that much between runs).
* Congestion control through a relay, 3 MB, medians: at 30 ms RTT and 1%
  loss CUBIC 6.07 s and `quic_cc bbr` 1.48 s, at 100 ms and no loss 2.66 and
  3.16 s. CUBIC's figure is what the loss model predicts (0.55 MB/s), not a
  fault; BBR ignores losses, and is about 20% slower with none, so CUBIC
  stays the default.

### QUIC interop runner (2026-11-05)

quic-interop-runner, okena as the server, testcases only (no goodput).
All 22 cases, on the image of 7bec09e:

| client | passed | not supported by the client | failed |
|---|---|---|---|
| ngtcp2 | 22 | | |
| neqo | 22 | | |
| picoquic | 22 | | |
| aioquic | 21 | E | |
| quic-go | 19 | E, V2 | CM |
| quiche | 16 | C20, U, E, V2 | Z, CM |

Then on the image of 00fae83 (ACKs held, split HEADERS waiting), eight
cases (transfer, zerortt, resumption, connectionmigration, rebind-port,
multiplexing, transferloss, transfercorruption): 8 of 8 for ngtcp2, neqo,
picoquic, aioquic; 7 of 8 for quic-go and quiche, zerortt passing on quiche,
connectionmigration failing on both.

That failure is the pair's, not a fault of the server's: neither sends
anything to the preferred address (quic-go's qlog shows it parsed it,
quiche's sets `disable_active_migration`), and the download completes on the
first path. The runner tells the client only "transfer" for this case, so it
cannot answer "not supported" and the check finds a single path.

On 2026-11-06, after the fixes to HTTP/3 answers, another eight cases: handshake,
transfer, retry, resumption, zerortt, http3, multiplexing, rebind-port. 8 of 8
with each of ngtcp2, quic-go, quiche, neqo, picoquic and aioquic. This set has no
connectionmigration, so it says nothing new about the two failures above. The
full matrix of that day ran out of its time limit and left no result: it is not
counted.

## What a rate limit adds (2026-11-05)

`okena bench`, open loop, HTTP/1.1, 20k requests/s on 64 connections through
okena (2 workers on cores 1-2) to `l4bench http` (cores 4-5), three runs of
5 s each, alternating; no request refused in these, all 100000 answered. In µs:

| route | p50 | p99 | p99.9 |
|---|---|---|---|
| no limit | 32.5-32.8 | 46.6-50.2 | 72-215 |
| `limit 900000/s key=client.ip` | 32.0-32.5 | 45.1-47.6 | 71-131 |
| `limit 900000/s key=header:x-api-key` | 32.3-32.8 | 45.6-48.6 | 78-100 |
| `limit 30000/s burst=100 key=client.ip` | 32.0-32.5 | 46.1-48.6 | 74-1278 |

At p50 and p99 what it adds is below what this measures. The last row, at two
thirds of the limit, shows 672 and 1278 µs at p99.9 in two runs of three: not
enough runs to say whether that is the limit or the machine.

## What CORS adds (2026-11-05)

As for the rate limit above: 20k requests/s on 64 connections, HTTP/1.1, 2
workers, three runs of 5 s each, alternating, in µs. Three origins in the list,
the one matching a `*`.

| route | p50 | p99 | p99.9 |
|---|---|---|---|
| no cors | 32.3 | 47-58 | 95-438 |
| `cors`, a request with an Origin | 32.3-32.8 | 51-64 | 105-2752 |
| `cors`, a preflight, answered by okena | 16.6-17.4 | 28-32 | 211-1573 |

Up to 0.5 µs at p50; p99.9 here moves too much between runs of 5 s to say more.

## What auth, split, mirror and hedge add (2026-11-06)

`okena bench`, open loop, HTTP/1.1, 20k requests/s on 64 connections through
okena (2 workers on cores 1-2) to `l4bench http` (cores 4-5), three runs of 2 s
after 0.5 s, alternating; all 40000 answered in each, no error. Medians of the
three runs, in µs, and the worst p99.9 of them:

| route | p50 | p99 | p99.9 | worst p99.9 |
|---|---|---|---|---|
| no filter | 32.5 | 51.2 | 145 | 1327 |
| `auth api_key` | 32.8 | 48.1 | 114 | 295 |
| `auth api_key` + `limit key=auth.user` | 33.3 | 49.7 | 72 | 108 |
| `auth jwt` HS256 | 33.3 | 49.7 | 234 | 934 |
| `auth jwt` HS256 + `limit key=jwt.sub` | 33.8 | 49.2 | 234 | 1344 |
| `split` 50/50 | 33.3 | 48.1 | 113 | 344 |
| `mirror`, every request | 34.3 | 45.6 | 115 | 148 |
| `hedge after=500ms`, none fired | 33.3 | 47.1 | 221 | 483 |

Up to about 1.3 µs at p50 with auth and a limit, 1.8 µs for a mirror, which is a
second request to a second pool; at p99 nothing above the noise. p99.9 at 2 s a
run says little: the route with no filter reaches 1327 µs, as far as any.
One key and one token throughout, so the JWT rows are nearly all the token
cache's hits: only each worker's first request verifies a signature.

Against the budget in ARCHITECTURE.md, which counts what is added on top of the
backend: the same load straight at `l4bench`, then through okena, three runs of
15 s, in µs. TLS is 1.3 with ECDSA P-256, on connections opened once. In the
last two rows `ss` showed `tcp-ulp-tls` on all 64 connections.

| route | p50 | p99 | p99.9 | p99.99 |
|---|---|---|---|---|
| straight to the backend | 14.6-14.8 | 24.8-25.1 | 40-42 | 51-63 |
| through okena, no filter | 32.3 | 45.1-47.6 | 71-96 | 762-1851 |
| TLS, `auth api_key` + `limit` | 33.3-33.8 | 49.2-54.8 | 70-258 | 639-1966 |
| kTLS, `auth api_key` + `limit` | 38.9 | 50.7-58.4 | 101-369 | 2196-2523 |
| kTLS, `auth jwt` + `limit` | 38.9-39.4 | 51.7-58.9 | 79-819 | 1868-2818 |

Added to the backend, against a budget of 20, 50 and 150 for "TLS (kTLS), auth
and rate limit": TLS in okena adds 19 at p50 and 30 at p99, and kTLS 24 and 34,
over the budget at p50 by 4 µs. p99.9 adds 41 at the median run with TLS, but
218 at the worst, and with kTLS 219 to 779 in four runs of six: not within it.
With no filter, 18 and 22 against a budget of 10 and 30: p50 is over it.

The p99.99 of 2-3 ms, and most of what p99.9 has over p99, is a worker going to sleep
and waking. It comes with okena in the path on both engines, with workers and backends
pinned, and with a cache hit too, so it is not the backend. Timing the loop itself,
turns longer than 800 µs are all in the wait for the kernel: the work after it took 1
or 2 µs. With `busy_poll`, where the worker does not sleep, three runs of 6 s each in µs:

| route | p50 | p99 | p99.9 | p99.99 |
|---|---|---|---|---|
| no filter, sleeps | 33.8-34.3 | 46.6-55.8 | 385-754 | 2392-3015 |
| no filter, `busy_poll 200us` | 28.4-28.9 | 38.4-41.0 | 52-60 | 211-803 |

And with `busy_poll 200us`, 10 s a run, over a backend alone at 14.8, 25 and 41:

| route | p50 | p99 | p99.9 | p99.99 |
|---|---|---|---|---|
| TLS, `auth api_key` + `limit` | 29.2-29.7 | 40.4-45.1 | 57-77 | 166-918 |

That adds 15, 20 and 36 µs: inside the budget of 20, 50 and 150, in all three, with TLS
in user space (kTLS was not measured with it). It costs a core per worker at 100% while
traffic keeps coming, so it is a choice: without it p50 and p99 are still in budget, and
p99.9 is not. Which part of the kernel's wake-up it is was not found: that needs tracing
as root. What is left at p99.99 was not looked into.

## UDP against TCP, through okena (2026-11-07)

`okena bench udp://` and `tcp://`, 20k requests/s on 64 sockets of 64 bytes, 4 s,
to an echo in C (recvmmsg and sendmmsg) and its TCP twin, 2 workers not pinned, on a
laptop with other work; three runs each, in µs. Straight to the UDP echo: p50 8, p99
14-16, p99.9 20-31.

| through okena | p50 | p99 | p99.9 |
|---|---|---|---|
| `udp`, io_uring | 21.2-21.5 | 41.5-43.0 | 860-1671 |
| `tcp`, io_uring | 22.5-23.0 | 47.6-48.1 | 1081-1671 |
| `udp`, epoll | 22.0-23.0 | 38.9-51.2 | 307-1720 |
| `tcp`, epoll | 23.6-27.4 | 43.0-46.6 | 332-1360 |
| `udp`, io_uring, `busy_poll 200us` | 16.4 | 25.1 | 38.4 |
| `tcp`, io_uring, `busy_poll 200us` | 17.4 | 27.6 | 41.0 |

A datagram costs what a TCP message does, a little less: about 14 µs over the echo
alone at p50, the two extra trips through the kernel. Its tail is the same as TCP's,
the worker waking up (above); with busy polling it goes. At 100k/s the p50 stays at 24
and nothing is behind. The flows were made before the clock started; what a new flow
costs (a socket, a connect, an epoll entry) is not in these numbers.

## Phase 8's exit: zero copy, and a purge storm (2026-11-11)

`python3 tests/bench/phase8.py`: okena with 2 workers on cores 2-3, wrk (`-t4 -c32`,
closed loop) on 8-15, one host, over loopback; Linux 7.3. Two runs; the ranges are
both.

**The hit path.** A body of 4 MiB, 5 s after 1 s of warm-up. CPU is okena's own
processes, user and system, per GiB sent; "zero copy" is
`okena_zero_copy_bytes_total` over the bytes wrk read.

| | Gbit/s | CPU s/GiB | of it user | zero copy | p99 |
|---|---|---|---|---|---|
| `files`, io_uring | 81-101 | 0.15-0.21 | 0.001 | 98-99% | 18-22 ms |
| disk cache hit, io_uring | 76-78 | 0.22 | 0.001 | 100% | 22 ms |
| memory cache hit (copied), io_uring | 29 | 0.58 | 0.03 | 0% | 42-44 ms |
| `files`, epoll | 81-101 | 0.15-0.20 | 0.002 | 98-100% | 18-21 ms |
| disk cache hit, epoll | 87-88 | 0.18 | 0.002 | 97-98% | 19-24 ms |
| memory cache hit (copied), epoll | 30 | 0.58 | 0.04 | 0% | 53 ms |

From the page cache, okena's own work is next to nothing: a millisecond of user time
per GiB, the rest is the kernel moving pages. The copy costs three times the CPU and
gives a third of the throughput. At 10 Gbit/s this is a fifth of a core; two cores
fill loopback at 80-100 Gbit/s, eight to ten times a 10 GbE port and three to four
times 25 GbE. The two-host lab is not in place, so line rate on a NIC is inferred
from this, not measured.

Three defects found on the way, fixed before these numbers:

* io_uring spliced through a pipe, and the kernel runs every `IORING_OP_SPLICE` on an
  io-wq thread: 13 Gbit/s at 1.3 CPU s/GiB, six `iou-wrk` threads busy. It now makes a
  descriptor of the client's own (`IORING_OP_FIXED_FD_INSTALL`, Linux 6.8) and uses
  sendfile like epoll, with a poll for room through the ring. Before 6.8, the pipes.
* epoll delivered queued results until the queue was empty, and a body to a client
  that keeps up queues its next piece as each goes: the loop kept from its events and
  its tick for as long as bodies went, ticks 100-250 ms late, and the overload manager
  shed requests (503, `Connection: close`). Each turn now delivers at most 1024, and a
  zero-copy body that has had its share waits for the next turn. Copied, p99 went from
  507 ms to 57; zero copy from 135 ms to 14, and 7.5 to 11.9 GB/s.
* An answer larger than `cache_memory` said `stored` and was dropped half way. Now it
  is not kept, and says so.

**A purge-and-refill storm.** 16 objects of 16 KiB, requested in turn, `cache 1h` with
memory and disk; the origin takes 2 ms an answer. For 5 s, `okena purge prefix` every
50 ms (about 100 purges), against 5 s without.

| clients | | req/s | p99 | origin requests | per purge |
|---|---|---|---|---|---|
| 4 | quiet | 66k-77k | 76-95 µs | 0 | |
| 4 | storm | 49k-62k | 2.2 ms | 2048-2519 | 20-25 |
| 128 | quiet | 84k | 2.1 ms | 0 | |
| 128 | storm | 96k | 4.5 ms | 3226-3228 | 32 |

The origin sees at most one fetch per object and worker after each purge (16 × 2 =
32), however many clients ask. A miss for what is being fetched waits for that fetch.
With 32 times the clients, the origin's load is the same bound; it follows the purges,
not the traffic. The clients barely notice: at 128 connections the rate holds. At 4,
each connection waits behind a refill about once per purge, and p99 is the origin's 2
ms.

## What a cache hit costs (2026-11-06)

The same load, 20k requests/s on 64 connections, HTTP/1.1, 2 workers pinned as a
set to cores 1-2, two runs of 5 s after 1 s, in µs; a body of 2 bytes. A third run
was cut by the time limit of the script and is not counted.

| route | p50 | p99 | p99.9 |
|---|---|---|---|
| to the backend | 33.8 | 51.7-57.3 | 244-827 |
| `cache`, a hit | 25.6 | 38.4-39.4 | 176-236 |

8 µs less at p50 than going to the backend, about 10 µs over the backend answering
by itself (table above). Bodies past one read are not measured here.

## What compressing costs (2026-11-06)

1 MiB of word-like text from `files`, one worker on core 1, one client on keep-alive,
2 s each: 1819 answers/s as they are, 105/s with `compress gzip`, 472 KB each. So about
105 MiB/s through the compressor, some 150 µs of the loop for each piece of 16 KiB. A
text of 300 KB: ratio 2.23 against 3.13 for `gzip -1`.

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
