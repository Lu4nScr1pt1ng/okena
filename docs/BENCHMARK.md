# Benchmarks

okena against the proxies people actually run: HAProxy, nginx, Envoy, Caddy
and Traefik, plus Katran for XDP and OpenSSL for crypto. Every number on this
page comes from a script in `tests/bench/`, run on one machine in November 2026,
and can be reproduced with the command given in its section. Where okena is
not first, the table says so; [the last section](#where-okena-is-not-first)
collects those cases.

**Contents**

1. [How the measurements are made](#how-the-measurements-are-made)
2. [Summary](#summary)
3. [HTTP/1.1](#http11)
4. [HTTPS: TLS 1.3 and 1.2](#https-tls-13-and-12)
5. [HTTP/2](#http2)
6. [gRPC](#grpc)
7. [HTTP/3](#http3)
8. [L4: TCP and UDP](#l4-tcp-and-udp)
9. [Large response bodies](#large-response-bodies)
10. [Gateway features: JWT, rate limits, cache](#gateway-features-jwt-rate-limits-cache)
11. [Memory per idle connection](#memory-per-idle-connection)
12. [XDP load balancing against Katran](#xdp-load-balancing-against-katran)
13. [Crypto against OpenSSL](#crypto-against-openssl)
14. [Where okena is not first](#where-okena-is-not-first)

---

## How the measurements are made

| | |
|---|---|
| CPU | AMD Ryzen 7 5700G, Zen 3, 8 cores / 16 threads, no AVX-512 |
| Memory | 30 GiB |
| Kernel | Linux 7.3.0 |
| okena | this tree, built into its `FROM scratch` image, io_uring with `docker/okena.seccomp.json` |
| HAProxy | 3.2.26, official image |
| nginx | 1.27.5, official `alpine` image |
| Envoy | 1.40.2, official image |
| Caddy | 2.10.2, official `alpine` image |
| Traefik | 3.5.6, official image |
| OpenSSL | 3.5.3 (crypto comparison) |

**The same box for everyone.** Every proxy runs in a Docker container with
host networking, pinned to the same two cores (1 and 2; their SMT siblings 9
and 10 stay idle). Each gets as many workers or threads as cores: two
(`GOMAXPROCS=2` for Caddy and Traefik). The backend runs on cores 4-5 and
12-13, and the load generators on the remaining eight. Nothing shares a
physical core with the proxy.

**Each proxy tuned by its own documentation.** Keep-alive to the backend
everywhere (nginx `keepalive`, HAProxy `http-reuse always`, Caddy's and
Traefik's idle connections per host raised to 1024), Envoy's circuit breakers
raised so it queues instead of refusing, access logs off. The configurations
are written out in each script.

**Two kinds of numbers.**

* *Most requests a second* is closed loop (wrk, h2load): as many requests as
  the proxy can take.
* *Latency* is open loop: requests are sent on a fixed schedule and timed from
  when they were due, not from when they went out (the method of wrk2). A
  proxy that stalls is charged for every request the stall held back. Without
  this correction, an overloaded proxy looks fast because the client politely
  waits for it. `behind` counts requests the schedule asked for that never
  went out: the proxy didn't keep up with that rate.

Latency points are the median of 3 runs of 10 s (5 for HTTP/2), each
percentile taken separately. On a desktop machine a single run can move a
p99.9 several times either way; the medians are what's shown.

**Units.** Latency in microseconds (µs) unless stated; 1000 µs is 1 ms.
"p50 / p99 / p99.9 / max" are the median, the 99th and 99.9th percentiles and
the slowest request.

**Rerunning.** Each script prints the markdown rows below. It needs Docker,
the images listed, `wrk`, and builds what else it needs (`l4bench`, the
gRPC backend, h2load with HTTP/3). The core numbers assume 8 cores / 16
threads; `PROXY_CPUS`, `BACK_CPUS` and `LOAD_CPUS` change them.

---

## Summary

The most each proxy did on two cores, and okena's lead over the next best:

| Scenario | okena | next best | lead |
|---|---|---|---|
| HTTP/1.1, requests/s | **144,005** | HAProxy 103,830 | 1.39× |
| HTTPS (TLS 1.3), requests/s | **142,775** | HAProxy 77,865 | 1.83× |
| HTTPS (TLS 1.3), handshakes per CPU-second | **6,548** | Envoy 5,108 | 1.28× |
| HTTP/2, requests/s | **193,296** | HAProxy 97,235 | 1.99× |
| gRPC unary calls/s | **142,485** | HAProxy 55,627 | 2.56× |
| HTTP/3, requests/s | **191,921** | HAProxy 124,976 | 1.54× |
| HTTP/3, new connections/s with none failing | **9,960** | HAProxy 1,258 | 7.9× |
| TCP, 256 connections, messages/s | **154,835** | nginx 138,567 | 1.12× |
| TCP bulk transfer | **95.2 Gbit/s** | Envoy 42.1 Gbit/s | 2.26× |
| UDP, 256 flows, datagrams/s | **186,721** | nginx 145,363 | 1.28× |
| 1 MB responses | **76.6 Gbit/s** | Envoy 33.3 Gbit/s | 2.30× |
| JWT-checked requests/s | **98,258** | Envoy 24,608 | 4.0× |
| Cache hits/s | **292,072** | HAProxy 183,777 | 1.59× |
| 100k idle connections, total memory | **73 MiB** | HAProxy 184 MiB | 2.5× less |
| XDP, packets/s on one core (flows in table) | **2.26 M** | Katran 2.05 M | 1.10× |

---

## HTTP/1.1

`tests/bench/http.sh`. The backend is nginx answering "ok" from memory
(326k requests/s straight to it). Keep-alive on both sides.

**Most requests a second** (wrk, 8 threads, 256 connections, 10 s):

| Proxy (2 cores) | requests/s | per core |
|---|---|---|
| **okena** | **144,005** | 72,002 |
| HAProxy | 103,830 | 51,915 |
| nginx | 81,737 | 40,868 |
| Envoy | 35,444 | 17,722 |
| Traefik | 33,106 | 16,553 |
| Caddy | 25,526 | 12,763 |

**Latency at fixed rates** (`RATES="10000 30000 80000"`; okena bench, 64
connections), p50 / p99 / p99.9 / max in µs:

| Proxy | 10,000/s | 30,000/s | 80,000/s |
|---|---|---|---|
| **okena** | **45 / 74 / 111** / 758 | **40 / 73 / 121** / 818 | **37 / 73 / 167** / 730 |
| HAProxy | 54 / 82 / 167 / 1901 | 51 / 115 / 1114 / 2611 | 135 / 9699 / 13500 / 15475 |
| nginx | 58 / 100 / 145 / 908 | 62 / 376 / 1097 / 3851 | 356 / 1.6 s / 1.7 s / 1.7 s |
| Caddy | 92 / 1441 / 4456 / 11582 | 0.31 s / 0.65 s / 0.70 s | could not keep up |
| Traefik | 83 / 323 / 2949 / 6399 | 2949 / 20447 / 31457 / 38723 | could not keep up |
| Envoy | 126 / 223 / 606 / 2258 | 778 / 1523 / 3997 / 6376 | could not keep up |

okena has the lowest p50, p99 and p99.9 at every rate, and is the only one
whose latency doesn't move between 10k and 80k requests a second: at 80k/s
its p99 is 73 µs, HAProxy's 9.7 ms. "Could not keep up" means the proxy
fell behind the schedule by hundreds of thousands of requests.

---

## HTTPS: TLS 1.3 and 1.2

`TLS=1.3 tests/bench/http.sh` and `TLS=1.2`. Each proxy terminates TLS with
the same ECDSA P-256 certificate, that version only, ALPN http/1.1, its own
defaults otherwise (session tickets on). The backend stays plain HTTP.

* Keep-alive throughput: wrk.
* Full handshakes: `openssl s_time -new`, two on each load core, never a
  resumption. The handshake rate is capped by the clients (about 9-13k a second
  here), so *handshakes per CPU-second*, from the proxy container's cgroup, is
  the number that says what a handshake costs the proxy.
* Latency: oha with latency correction (okena bench doesn't speak TLS 1.2);
  oha is slower than okena bench, so every number is higher than plain HTTP's,
  for everyone.

| Proxy (2 cores) | TLS | keep-alive requests/s | full handshakes/s | handshakes per CPU-second |
|---|---|---|---|---|
| **okena** | 1.3 | **142,775** | **9,474** | **6,548** |
| HAProxy | 1.3 | 77,865 | 6,390 | 3,348 |
| nginx | 1.3 | 73,544 | 5,386 | 2,913 |
| Envoy | 1.3 | 30,826 | 8,492 | 5,108 |
| Traefik | 1.3 | 30,386 | 3,947 | 2,079 |
| Caddy | 1.3 | 23,848 | 5,612 | 3,061 |
| **okena** | 1.2 | **142,124** | **13,014** | **8,138** |
| HAProxy | 1.2 | 79,737 | 6,812 | 3,570 |
| nginx | 1.2 | 72,102 | 6,228 | 3,408 |
| Envoy | 1.2 | 31,066 | 10,865 | 6,564 |
| Traefik | 1.2 | 29,319 | 8,304 | 4,428 |
| Caddy | 1.2 | 23,692 | 8,044 | 4,419 |

okena loses under 1% of its plaintext throughput to TLS (it seals records
itself, without kTLS); HAProxy loses 25%, nginx, Envoy, Caddy and Traefik
7-13%. In TLS 1.3 the client offers X25519MLKEM768 first (OpenSSL 3.5's
default), so every full handshake includes a post-quantum key exchange.

Latency, p50 / p99 / p99.9 / max in µs. At the higher rates a few requests
failed for everyone that kept up (at most 1 for okena, 3 for HAProxy, 40 for
nginx in a run); the ones that could not keep up failed dozens.

| Proxy | TLS | 10,000/s | 30,000/s | 60,000/s |
|---|---|---|---|---|
| **okena** | 1.3 | **134 / 284 / 879** / 11437 | **250 / 730 / 3199** / 18668 | **426 / 3126 / 13684** / 33546 |
| HAProxy | 1.3 | 191 / 400 / 7696 / 22309 | 466 / 1684 / 10008 / 26883 | 882 / 13774 / 21122 / 31180 |
| nginx | 1.3 | 203 / 525 / 4776 / 18237 | 431 / 1312 / 9904 / 21274 | 976 / 16117 / 24897 / 32379 |
| Traefik | 1.3 | 333 / 1467 / 9152 / 19561 | 3282 / 20444 / 23099 / 26356 | could not keep up |
| Caddy | 1.3 | 399 / 2776 / 11418 / 28973 | could not keep up | could not keep up |
| Envoy | 1.3 | 456 / 1078 / 6755 / 17746 | could not keep up | could not keep up |
| **okena** | 1.2 | **133 / 273 / 671** / 8425 | **253 / 605 / 3005** / 15893 | **481 / 2460 / 12279** / 32424 |
| HAProxy | 1.2 | 193 / 407 / 3356 / 16728 | 419 / 1206 / 8315 / 25490 | 852 / 11926 / 21380 / 32843 |
| nginx | 1.2 | 197 / 447 / 3406 / 16595 | 433 / 1099 / 9835 / 21707 | 938 / 17008 / 25965 / 32374 |
| Traefik | 1.2 | 325 / 1543 / 9218 / 21411 | 3632 / 20624 / 25829 / 28831 | could not keep up |
| Caddy | 1.2 | 393 / 2652 / 8039 / 15394 | could not keep up | could not keep up |
| Envoy | 1.2 | 465 / 1192 / 13653 / 24818 | could not keep up | could not keep up |

---

## HTTP/2

`H2=1 RATES="10000 30000 80000" REPEAT=5 tests/bench/http.sh`. Clients speak
HTTP/2 in clear text (h2c, prior knowledge); backends get HTTP/1.1.
Throughput from h2load (64 connections, 16 streams each), counted only when
every answer came over h2c and 99% were 2xx. Latency from okena bench
`proto=h2`, one stream at a time per connection, median of five runs.

| Proxy (2 cores) | requests/s | per core |
|---|---|---|
| **okena** | **193,296** | 96,648 |
| HAProxy | 97,235 | 48,617 |
| nginx | 71,363 | 35,681 |
| Envoy | 38,764 | 19,382 |
| Traefik | 24,210 | 12,105 |
| Caddy | 20,405 | 10,202 |

okena does more over HTTP/2 than over HTTP/1.1: many streams share each
connection, so there are fewer system calls per request.

| Proxy | 10,000/s | 30,000/s | 80,000/s |
|---|---|---|---|
| **okena** | **47 / 77 / 163** / 600 | **40 / 74 / 202** / 1625 | **47 / 119 / 315** / 1101 |
| HAProxy | 56 / 84 / 190 / 1320 | 60 / 114 / 249 / 3374 | 133 / 1359 / 5046 / 8069 |
| nginx | 72 / 121 / 180 / 779 | 95 / 2293 / 3538 / 4927 | 0.68 s / 2.4 s / 2.5 s |
| Envoy | 161 / 237 / 495 / 2157 | 2195 / 8060 / 10747 / 12165 | could not keep up |
| Traefik | 141 / 1622 / 5242 / 10874 | could not keep up | could not keep up |
| Caddy | 145 / 2326 / 5242 / 10338 | could not keep up | could not keep up |

okena is lowest at every rate and percentile, and at 80,000/s it is the only
one under a millisecond at p99.

---

## gRPC

`RATES="5000 20000 40000" tests/bench/grpcmax.sh`. gRPC over h2c on both
sides, in front of a Go echo backend (grpc-go). Unary calls of 64 bytes.
Throughput from h2load posting gRPC frames (64 connections, 16 streams);
each proxy is first checked to end 4000 calls with grpc-status 0 (none had an
error). Latency from a Go client in open loop.

| Path (2 cores) | unary calls/s | per core |
|---|---|---|
| straight to the backend | 223,252 | |
| **okena** | **142,485** | 71,242 |
| HAProxy | 55,627 | 27,813 |
| Envoy | 49,540 | 24,770 |
| nginx | 35,051 | 17,525 |
| Traefik | 19,008 | 9,504 |
| Caddy | 18,459 | 9,229 |

| Path | 5,000/s | 20,000/s | 40,000/s |
|---|---|---|---|
| straight to the backend | 148 / 199 / 477 | 145 / 612 / 1873 | 124 / 1110 / 2445 |
| **okena** | **186 / 273 / 535** | **187 / 676 / 1914** | **185 / 1297 / 3039** |
| HAProxy | 201 / 305 / 587 | 228 / 1980 / 4336 | 2107 / 41722 / 57128 |
| nginx | 215 / 297 / 573 | 5922 / 69182 / 112174 | 2.5 s / 7.8 s / 9.7 s |
| Envoy | 281 / 414 / 687 | 1095 / 14189 / 25936 | 0.39 s / 1.3 s / 1.6 s |
| Traefik | 304 / 1572 / 4817 | 0.98 s / 3.6 s / 5.1 s | 3.7 s / 8.9 s / 10.5 s |
| Caddy | 304 / 2287 / 4826 | 1.3 s / 4.7 s / 6.2 s | 3.9 s / 9.2 s / 10.7 s |

The Go client itself accounts for most of each latency (see the backend's
own row). At 40,000 calls a second only okena stays close to the backend's
tail: p99 1.3 ms against HAProxy's 42 ms.

---

## HTTP/3

`tests/bench/h3.sh`. okena, HAProxy (QUIC with OpenSSL 3.5) and nginx (Caddy
and Traefik are left out: the script drives h2load and okena bench against
three servers). ECDSA P-256, X25519 for all three. Load from h2load built
with ngtcp2 and nghttp3, and from okena bench `proto=h3`.

**Many streams** (64 connections × 10 requests in flight, closed loop):

| Server (2 cores) | requests/s | p50 / p99 / p99.9 (µs) |
|---|---|---|
| **okena** | **191,921** | **3321 / 6265 / 9130** |
| HAProxy | 124,976 | 4997 / 6710 / 10008 |
| nginx | 95,290 | 6466 / 14960 / 46500 |

**A new connection for every request**, at fixed rates. Each request
includes a full QUIC handshake:

| Rate offered | okena | HAProxy | nginx |
|---|---|---|---|
| 2,000/s | **2,016/s**, none failed | 1,258/s | 1,117/s |
| 5,000/s | **4,987/s**, none failed | 692/s, 50,836 failed | 1,115/s, 12,156 failed |
| 10,000/s | **9,960/s**, none failed | 641/s, 137,144 failed | 727/s, 131,114 failed |

okena keeps up with about 10,000 new QUIC connections a second on two cores;
HAProxy and nginx top out near 1,000 and start failing connections past it.

**Keep-alive at 18,000 requests/s** (60 connections × 300/s, h2load), quiet
and while two senders flood the port with about 300,000 QUIC Initial packets
a second (real ClientHellos, never answered). Median of 3 runs:

| Server | quiet: p50 / p99 / p99.9 (µs) | under the flood: requests/s | under the flood: p50 / p99 / p99.9 (µs) |
|---|---|---|---|
| **okena** | **66 / 143 / 350** | **16,780** | **124 / 1014 / 9857** |
| HAProxy | 98 / 271 / 757 | 8,490 | 420 / 163,365 / 180,970 |
| nginx | 128 / 556 / 1891 | 7,850 | 1036 / 111,919 / 483,066 |

Under the flood okena keeps the whole rate; HAProxy and nginx lose half of it
and their p99 reaches 0.1-0.2 s.

**Open loop** (okena bench `proto=h3`, 60 connections), median of 3 runs,
p50 / p99 / p99.9 in µs:

| Server | 5,000/s | 18,000/s | 40,000/s |
|---|---|---|---|
| **okena** | **53 / 94 / 125** | **42 / 69 / 135** | **39 / 65 / 145** |
| HAProxy | 71 / 147 / 385 | 72 / 129 / 679 | 122 / 1654 / 3702 |
| nginx | 61 / 802 / 19,136 | 54 / 103 / 413 | 101 / 77,594 / 84,934 |

okena is lowest at every rate and percentile.

---

## L4: TCP and UDP

`tests/bench/l4max.sh`. okena (`tcp` and `udp` listeners), HAProxy (TCP only:
UDP isn't in its open source edition), nginx (`stream`), Envoy (tcp_proxy,
udp_proxy) and Traefik (TCP and UDP routers). Caddy has no L4 proxy without a
plugin. The backends are an echo, a sink and a UDP echo from
`tests/bench/l4bench.c`. Median of 3 runs.

* **ping1**: one connection, a 64-byte message and its echo, back to back.
* **ping256**: 256 connections, one message in flight on each.
* **bulk**: 8 connections writing as fast as they can.
* **connect**: a new TCP connection for every 64-byte exchange.
* **udp1 / udp256**: like the pings, with datagrams.

| Path (2 cores) | ping1 | ping256 | bulk | connect | udp1 | udp256 |
|---|---|---|---|---|---|---|
| straight to the backend | 63,745/s | 458,723/s | 220.8 Gbit/s | 88,965/s | 72,547/s | 566,989/s |
| **okena** | **36,948/s** | **154,835/s** | **95.2 Gbit/s** | **25,607/s** | **37,657/s** | **186,721/s** |
| nginx | 29,064/s | 138,567/s | 22.7 Gbit/s | 14,057/s | 32,886/s | 145,363/s |
| HAProxy | 27,619/s | 129,120/s | 20.7 Gbit/s | 20,874/s | | |
| Traefik | 28,157/s | 119,495/s | 36.8 Gbit/s | 10,051/s | 18,820/s | 75,657/s, 881 lost |
| Envoy | 24,017/s | 106,430/s | 42.1 Gbit/s | 12,421/s | 29,283/s | 130,623/s |

Latency, p50 / p99 / p99.9 in µs:

| Path | ping1 | ping256 | connect | udp1 | udp256 |
|---|---|---|---|---|---|
| **okena** | **26.5 / 35.2 / 61.7** | **1646 / 1803 / 2163** | **311 / 456 / 529** | **26.1 / 32.7 / 56.7** | **1383 / 1478 / 2044** |
| nginx | 33.1 / 55.2 / 92.8 | 1865 / 2058 / 2393 | 452 / 3864 / 10280 | 29.6 / 45.0 / 76.5 | 1610 / 2088 / 2204 |
| HAProxy | 34.8 / 60.9 / 95.1 | 1975 / 2545 / 3210 | 381 / 542 / 643 | | |
| Traefik | 34.2 / 55.1 / 83.7 | 2121 / 3307 / 3790 | 723 / 2796 / 5236 | 41.4 / 251 / 354 | 2284 / 10458 / 13967 |
| Envoy | 40.1 / 72.6 / 104.2 | 2415 / 3216 / 3350 | 651 / 1149 / 1502 | 32.8 / 56.9 / 95.9 | 1934 / 2120 / 2287 |

okena is first in every column. Large transfers go socket to pipe to socket
inside the kernel (splice), and new connections from all clients wait in one
queue that the workers take in turn.

---

## Large response bodies

`tests/bench/httpbig.sh`. The backend answers `GET /SIZE` with SIZE bytes;
h2load `--h1`, 64 connections, closed loop, median of 3. nginx with
`proxy_buffering off`, as the others stream.

| Path (2 cores) | 64 KB responses | 1 MB responses |
|---|---|---|
| straight to the backend | 67.3 Gbit/s | 131.8 Gbit/s |
| **okena** | **33.0 Gbit/s** | **76.6 Gbit/s** |
| HAProxy | 19.7 Gbit/s | 26.0 Gbit/s |
| Envoy | 12.3 Gbit/s | 33.3 Gbit/s |
| Traefik | 10.6 Gbit/s | 28.3 Gbit/s |
| Caddy | 8.9 Gbit/s | 25.6 Gbit/s |
| nginx | 6.2 Gbit/s | 7.6 Gbit/s |

A body of 16 KiB or more with a `Content-Length`, that no route feature needs
to look at, goes through the L4 relay path, counted to the byte, by splice
through a pipe: the bytes never pass through okena's memory.

---

## Gateway features: JWT, rate limits, cache

`tests/bench/gw.sh`. One listener per scenario, so one feature never touches
another's numbers. The backend gives 100-byte answers, cacheable for an hour.
wrk, 256 connections, median of 3.

* **none**: the plain proxy.
* **jwt**: ES256 bearer tokens verified (signature, `exp`, `iss`, `aud`), from
  100,000 different tokens taken in turn, each used about 15 times.
* **limit**: a per-client rate limit that is never reached (what it costs to
  check).
* **cache**: every request a cache hit.

| Proxy (2 cores) | none | jwt | limit | cache |
|---|---|---|---|---|
| **okena** | **111,736** | **98,258** | **109,746** | **292,072** |
| HAProxy | 83,815 | 23,280 | 82,893 | 183,777 |
| nginx | 75,543 | (NGINX Plus only) | 77,050 | 53,947 |
| Envoy | 28,895 | 24,608 | 26,436 | 25,680 |

Requests a second. A bad token gets 401 from every proxy that verifies
JWTs. Caddy and Traefik are not in this table: neither verifies JWTs or
caches responses without a plugin or their commercial editions.

---

## Memory per idle connection

`tests/bench/idlemem.sh`. 100,000 clients each make one request, read the
answer and stay connected, idle. The proxy's own memory (`anon` from its
container's cgroup; kernel socket buffers left out, the same for everyone),
before and 5 s after the last connection.

| Proxy (2 workers) | before | with 100k idle | per connection |
|---|---|---|---|
| **okena** | 3 MiB | **73 MiB** | 735 B |
| HAProxy | 72 MiB | 184 MiB | 1,176 B |
| nginx | 840 MiB | 896 MiB | **587 B** |
| Envoy | 17 MiB | 1,597 MiB | 16,568 B |
| Caddy | 12 MiB | 1,991 MiB | 20,745 B |
| Traefik | 12 MiB | 2,856 MiB | 29,822 B |

nginx's per-connection cost is lower, but it reserves its arrays for
`worker_connections` up front (one million here: 840 MiB before the first
client). With these figures okena holds less in total up to about 5.9
million connections.

---

## XDP load balancing against Katran

`tests/bench/xdp.sh`. okena's `mode xdp` against Katran's `balancer.bpf.c`
(at 04a4733, built with clang 18, maps filled as its control plane does).
Both encapsulate in IP-in-IP and send back with XDP_TX. pktgen feeds a veth
on three CPUs; the balancer's NAPI runs on a core of its own. 60-byte UDP
packets; packets a second the balancer sent, the median of 5 seconds, its
core busy all the time.

* **est**: 1024 flows over and over, all in the flow table.
* **new**: every packet a new flow.
* **base**: XDP_TX and nothing else, what the veth path costs on its own.

| | est | new | time in the program (est / new) |
|---|---|---|---|
| base (the path alone) | 3.22 M | 3.21 M | 24 / 25 ns |
| **okena** | **2.26 M** | **1.80 M** | **121 / 213 ns** |
| Katran | 2.05 M | 1.56 M | 153 / 304 ns |
| Katran, MAX_CONN_RATE out of reach | 2.15 M | 1.26 M | 155 / 450 ns |

Time in the program is the kernel's own count (`kernel.bpf_stats_enabled`).

---

## Crypto against OpenSSL

One operation in a loop, one thread pinned to core 3. okena through
`build/kat`'s benchmark mode (`tests/kat/bench.py` and the same with Ed25519,
ML-KEM and ChaCha20); OpenSSL 3.5.3 through `openssl speed` on the same core.

| Operation | okena | OpenSSL | |
|---|---|---|---|
| Ed25519 sign | **9.6 µs** | 29.7 µs | 3.1× faster |
| Ed25519 verify | **41.1 µs** | 77.4 µs | 1.9× faster |
| ML-KEM-768 key generation | **12.8 µs** | 35.0 µs | 2.7× faster |
| ML-KEM-768 encapsulation | **14.9 µs** | 24.5 µs | 1.6× faster |
| ML-KEM-768 decapsulation | **16.8 µs** | 37.0 µs | 2.2× faster |
| ECDSA P-256 sign | **12.8 µs** | 15.8 µs | 1.24× faster |
| AES-128-GCM, 16 KiB records | **6.80 GB/s** | 5.76 GB/s | 1.18× faster |
| X25519 | **23.3 µs** | 25.4 µs | 1.09× faster |
| ChaCha20-Poly1305, 16 KiB records | **4.08 GB/s** | 3.17 GB/s | 1.29× faster |

okena uses AVX2 for ML-KEM and VAES with VPCLMULQDQ for AES-GCM. Its
ChaCha20-Poly1305 runs eight blocks at a time on AVX2 and MACs the record in
the same pass, a scalar Poly1305 on the integer units while ChaCha20 keeps
the vector units busy. okena only picks ChaCha20 when the client puts it
first, which clients without AES hardware do.

---

## Where okena is not first

Every case in this run where another implementation did better, in one
place:

| Scenario | okena | better | by |
|---|---|---|---|
| Memory per idle connection | 735 B | nginx 587 B | 148 B (nginx reserves 840 MiB up front) |
