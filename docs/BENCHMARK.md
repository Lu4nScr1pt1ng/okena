# Benchmarks

okena against the proxies people actually run: HAProxy, nginx, Envoy, Caddy
and Traefik, plus Katran for XDP and OpenSSL for crypto. Every number on this
page comes from a script in `tests/bench/`, run on one machine in November 2026
(the whole page again on 2026-11-17, but memory per idle connection and the
crypto table), and can be reproduced with the command given in its section. Where okena is
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
physical core with the proxy. The host runs firewalld, whose rules and
conntrack every proxy's packets go through alike; without them every number
here would be higher (okena's HTTP/1.1 on loopback: 160k → 232k requests a
second, measured outside the containers).

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
| HTTP/1.1, requests/s | **151,974** | HAProxy 100,434 | 1.51× |
| HTTPS (TLS 1.3), requests/s | **152,437** | HAProxy 82,825 | 1.84× |
| HTTPS (TLS 1.3), handshakes per CPU-second | **6,450** | Envoy 5,263 | 1.23× |
| HTTP/2, requests/s | **241,365** | HAProxy 104,350 | 2.31× |
| gRPC unary calls/s | **155,925** | HAProxy 55,450 | 2.81× |
| HTTP/3, requests/s | **192,004** | HAProxy 132,061 | 1.45× |
| HTTP/3, new connections/s with none failing | **9,980** | HAProxy 1,266 | 7.9× |
| TCP, 256 connections, messages/s | **155,663** | nginx 141,854 | 1.10× |
| TCP bulk transfer | **102.1 Gbit/s** | Envoy 39.1 Gbit/s | 2.61× |
| UDP, 256 flows, datagrams/s | **200,781** | nginx 146,346 | 1.37× |
| 1 MB responses | **78.9 Gbit/s** | Envoy 34.0 Gbit/s | 2.32× |
| JWT-checked requests/s | **103,084** | Envoy 26,319 | 3.9× |
| Cache hits/s | **300,816** | HAProxy 183,485 | 1.64× |
| 100k idle connections, total memory | **73 MiB** | HAProxy 184 MiB | 2.5× less |
| XDP, packets/s on one core (flows in table) | **2.30 M** | Katran 2.13 M | 1.08× |

---

## HTTP/1.1

`tests/bench/http.sh`. The backend is nginx answering "ok" from memory
(333k requests/s straight to it). Keep-alive on both sides.

**Most requests a second** (wrk, 8 threads, 256 connections, 10 s):

| Proxy (2 cores) | requests/s | per core |
|---|---|---|
| **okena** | **151,974** | 75,987 |
| HAProxy | 100,434 | 50,217 |
| nginx | 97,071 | 48,535 |
| Traefik | 36,118 | 18,059 |
| Envoy | 35,352 | 17,676 |
| Caddy | 27,799 | 13,899 |

**Latency at fixed rates** (`RATES="10000 30000 80000"`; okena bench, 64
connections), p50 / p99 / p99.9 / max in µs:

| Proxy | 10,000/s | 30,000/s | 80,000/s |
|---|---|---|---|
| **okena** | **43 / 55** / 82 / 163 | **39 / 49 / 92** / 978 | **34 / 56 / 81** / 525 |
| HAProxy | 50 / 62 / **80** / 174 | 48 / 73 / 94 / 595 | 131 / 17563 / 29360 / 32200 |
| nginx | 56 / 74 / 113 / 211 | 57 / 100 / 303 / 1488 | 0.11 s / 1.9 s / 2.0 s / 2.0 s |
| Traefik | 80 / 223 / 1998 / 4949 | 3473 / 21495 / 29884 / 49561 | could not keep up |
| Caddy | 88 / 401 / 2260 / 5416 | 0.11 s / 0.31 s / 0.36 s | could not keep up |
| Envoy | 114 / 172 / 208 / 1053 | 663 / 1032 / 1277 / 1860 | could not keep up |

okena has the lowest p50 and p99 at every rate and the lowest p99.9 but at
10,000/s, where HAProxy's is 2 µs lower (80 against 82). It is the only one
whose latency doesn't move between 10k and 80k requests a second: at 80k/s
its p99 is 56 µs, HAProxy's 17.6 ms. "Could not keep up" means the proxy
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
| **okena** | 1.3 | **152,437** | **9,547** | **6,450** |
| HAProxy | 1.3 | 82,825 | 6,562 | 3,430 |
| nginx | 1.3 | 73,579 | 5,411 | 2,979 |
| Envoy | 1.3 | 33,380 | 8,566 | 5,263 |
| Traefik | 1.3 | 32,673 | 4,073 | 2,148 |
| Caddy | 1.3 | 24,442 | 5,799 | 3,151 |
| **okena** | 1.2 | **150,052** | **13,429** | **8,090** |
| HAProxy | 1.2 | 84,388 | 7,137 | 3,730 |
| nginx | 1.2 | 79,011 | 6,353 | 3,507 |
| Envoy | 1.2 | 32,876 | 11,342 | 6,804 |
| Traefik | 1.2 | 32,554 | 8,534 | 4,536 |
| Caddy | 1.2 | 24,780 | 8,330 | 4,583 |

okena loses nothing measurable of its plaintext throughput to TLS (it seals
records itself, without kTLS); HAProxy loses 16-18%, nginx 19-24%, Envoy,
Caddy and Traefik 6-12%. In TLS 1.3 the client offers X25519MLKEM768 first (OpenSSL 3.5's
default), so every full handshake includes a post-quantum key exchange.

Latency, p50 / p99 / p99.9 / max in µs. At the higher rates a few requests
failed for everyone that kept up (at most 1 for okena, 12 for HAProxy, 30 for
nginx in a run); the ones that could not keep up failed dozens.

| Proxy | TLS | 10,000/s | 30,000/s | 60,000/s |
|---|---|---|---|---|
| **okena** | 1.3 | **128 / 240 / 481** / 13453 | **232 / 478 / 2548** / 15288 | **410 / 879 / 4200** / 14245 |
| HAProxy | 1.3 | 186 / 371 / 5056 / 23332 | 407 / 757 / 7223 / 22238 | 792 / 3217 / 13167 / 23002 |
| nginx | 1.3 | 195 / 423 / 6800 / 24714 | 426 / 934 / 13207 / 27161 | 940 / 3657 / 17605 / 23164 |
| Traefik | 1.3 | 315 / 1156 / 9466 / 24338 | 3858 / 24193 / 28450 / 32041 | could not keep up |
| Caddy | 1.3 | 370 / 2272 / 10522 / 26623 | could not keep up | could not keep up |
| Envoy | 1.3 | 402 / 814 / 4917 / 14500 | 1239 / 22995 / 30581 / 32320 | could not keep up |
| **okena** | 1.2 | **129 / 245 / 886** / 14044 | **242 / 486 / 2253** / 14161 | **445 / 957 / 4762** / 13896 |
| HAProxy | 1.2 | 188 / 381 / 2563 / 15216 | 428 / 826 / 9790 / 28367 | 813 / 3227 / 15210 / 26056 |
| nginx | 1.2 | 188 / 404 / 3765 / 13671 | 448 / 1037 / 8249 / 18383 | 964 / 6079 / 19922 / 22288 |
| Traefik | 1.2 | 312 / 1224 / 7241 / 23897 | 4366 / 22944 / 26187 / 30139 | could not keep up |
| Caddy | 1.2 | 384 / 2223 / 4363 / 19010 | could not keep up | could not keep up |
| Envoy | 1.2 | 402 / 835 / 1866 / 18783 | 1243 / 9336 / 15345 / 18382 | could not keep up |

---

## HTTP/2

`H2=1 RATES="10000 30000 80000" REPEAT=5 tests/bench/http.sh`. Clients speak
HTTP/2 in clear text (h2c, prior knowledge); backends get HTTP/1.1.
Throughput from h2load (64 connections, 16 streams each), counted only when
every answer came over h2c and 99% were 2xx. Latency from okena bench
`proto=h2`, one stream at a time per connection, median of five runs.

| Proxy (2 cores) | requests/s | per core |
|---|---|---|
| **okena** | **241,365** | 120,682 |
| HAProxy | 104,350 | 52,175 |
| nginx | 73,102 | 36,551 |
| Envoy | 40,448 | 20,224 |
| Traefik | 24,527 | 12,263 |
| Caddy | 20,837 | 10,418 |

okena does more over HTTP/2 than over HTTP/1.1: many streams share each
connection, so there are fewer system calls per request.

| Proxy | 10,000/s | 30,000/s | 80,000/s |
|---|---|---|---|
| **okena** | **45 / 57 / 90** / 233 | **40 / 57 / 86** / 704 | **41 / 64 / 99** / 856 |
| HAProxy | 55 / 68 / 97 / 192 | 63 / 78 / 108 / 426 | 145 / 319 / 9961 / 13618 |
| nginx | 68 / 89 / 130 / 327 | 91 / 1687 / 2047 / 2813 | 0.52 s / 2.6 s / 2.6 s |
| Envoy | 155 / 202 / 262 / 547 | 1114 / 5373 / 7536 / 8899 | could not keep up |
| Traefik | 139 / 2326 / 6815 / 11122 | could not keep up | could not keep up |
| Caddy | 139 / 1605 / 4095 / 7739 | could not keep up | could not keep up |

okena is lowest at every rate and percentile; at 80,000/s its p99.9 is 99 µs,
HAProxy's 10 ms.

---

## gRPC

`RATES="5000 20000 40000" tests/bench/grpcmax.sh`. gRPC over h2c on both
sides, in front of a Go echo backend (grpc-go). Unary calls of 64 bytes.
Throughput from h2load posting gRPC frames (64 connections, 16 streams);
each proxy is first checked to end 4000 calls with grpc-status 0 (none had an
error). Latency from a Go client in open loop. The backend is started anew
for each path: one that has just taken a few million calls is slower for the
next (until 2026-11-17 the script kept it, and whoever came after the direct
run lost about 5%).

| Path (2 cores) | unary calls/s | per core |
|---|---|---|
| straight to the backend | 225,050 | |
| **okena** | **155,925** | 77,962 |
| HAProxy | 55,450 | 27,725 |
| Envoy | 51,396 | 25,698 |
| nginx | 34,959 | 17,479 |
| Traefik | 19,728 | 9,864 |
| Caddy | 19,438 | 9,719 |

| Path | 5,000/s | 20,000/s | 40,000/s |
|---|---|---|---|
| straight to the backend | 147 / 185 / 718 | 143 / 668 / 2137 | 122 / 1024 / 2370 |
| **okena** | **182 / 244** / 461 | **180 / 604 / 1768** | **181 / 1066 / 2600** |
| HAProxy | 196 / 257 / **452** | 220 / 775 / 2250 | 6295 / 76881 / 121529 |
| nginx | 211 / 274 / 459 | 14 ms / 0.35 s / 0.44 s | 1.9 s / 7.8 s / 10.0 s |
| Envoy | 268 / 327 / 466 | 942 / 17568 / 27131 | 0.14 s / 0.39 s / 0.45 s |
| Traefik | 298 / 1121 / 4463 | 0.81 s / 3.3 s / 4.5 s | 3.8 s / 8.9 s / 10.3 s |
| Caddy | 299 / 1709 / 4318 | 1.0 s / 4.1 s / 5.6 s | 3.9 s / 9.1 s / 10.6 s |

The Go client itself accounts for most of each latency (see the backend's
own row). At 40,000 calls a second only okena stays close to the backend's
tail: p99 1.1 ms against HAProxy's 77 ms. At 5,000/s HAProxy's and nginx's
p99.9 are 2-9 µs under okena's.

---

## HTTP/3

`tests/bench/h3.sh`. okena, HAProxy (QUIC with OpenSSL 3.5) and nginx (Caddy
and Traefik are left out: the script drives h2load and okena bench against
three servers). ECDSA P-256, X25519 for all three. Load from h2load built
with ngtcp2 and nghttp3, and from okena bench `proto=h3`.

**Many streams** (64 connections × 10 requests in flight, closed loop):

| Server (2 cores) | requests/s | p50 / p99 / p99.9 (µs) |
|---|---|---|
| **okena** | **192,004** | **2949** / 6844 / 9565 |
| HAProxy | 132,061 | 4756 / **5776 / 7332** |
| nginx | 101,657 | 5204 / 25156 / 63645 |

In closed loop a request waits behind the ones in flight, so these latencies
follow throughput: HAProxy's tail is shorter at two thirds of okena's rate.
Latency at the same rate for all three is the open loop table below.

**A new connection for every request**, at fixed rates. Each request
includes a full QUIC handshake:

| Rate offered | okena | HAProxy | nginx |
|---|---|---|---|
| 2,000/s | **2,016/s**, none failed | 1,266/s | 1,124/s |
| 5,000/s | **4,988/s**, none failed | 697/s, 50,296 failed | 1,131/s, 10,370 failed |
| 10,000/s | **9,980/s**, none failed | 688/s, 139,182 failed | 921/s, 126,122 failed |

okena keeps up with about 10,000 new QUIC connections a second on two cores;
HAProxy and nginx top out near 1,000 and start failing connections past it.

**Keep-alive at 18,000 requests/s** (60 connections × 300/s, h2load), quiet
and while two senders flood the port with about 300,000 QUIC Initial packets
a second (real ClientHellos, never answered). Median of 3 runs:

| Server | quiet: p50 / p99 / p99.9 (µs) | under the flood: requests/s | under the flood: p50 / p99 / p99.9 (µs) |
|---|---|---|---|
| **okena** | **62 / 134 / 801** | **16,778** | **118 / 1157 / 16178** |
| HAProxy | 319 / 705 / 889 | 8,533 | 799 / 97,252 / 104,420 |
| nginx | 112 / 498 / 1032 | 8,269 | 249 / 28,868 / 444,368 |

Under the flood okena keeps the whole rate; HAProxy and nginx lose half of it
and their p99 reaches 0.03-0.1 s.

**Open loop** (okena bench `proto=h3`, 60 connections), median of 3 runs,
p50 / p99 / p99.9 in µs:

| Server | 5,000/s | 18,000/s | 40,000/s |
|---|---|---|---|
| **okena** | **48 / 78 / 105** | **38 / 54 / 90** | **36 / 56 / 96** |
| HAProxy | 67 / 94 / 122 | 61 / 77 / 117 | 108 / 438 / 1359 |
| nginx | 58 / 671 / 7733 | 48 / 69 / 155 | 76 / 19,398 / 33,554 |

okena is lowest at every rate and percentile. okena bench acknowledges as
browsers do (RFC 9000 13.2.1: after two packets or 25 ms, or with the next
request), so a request is two datagrams.

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
| straight to the backend | 66,904/s | 462,777/s | 207.7 Gbit/s | 91,627/s | 73,825/s | 569,997/s |
| **okena** | **37,378/s** | **155,663/s** | **102.1 Gbit/s** | **25,921/s** | **38,213/s** | **200,781/s** |
| nginx | 30,837/s | 141,854/s | 22.9 Gbit/s | 14,156/s | 33,756/s | 146,346/s |
| HAProxy | 29,019/s | 127,262/s | 20.7 Gbit/s | 21,429/s | | |
| Traefik | 29,603/s | 120,262/s | 37.7 Gbit/s | 9,994/s | 19,515/s | 75,594/s, 988 lost |
| Envoy | 25,320/s | 107,884/s | 39.1 Gbit/s | 12,618/s | 30,306/s | 131,190/s |

Latency, p50 / p99 / p99.9 in µs:

| Path | ping1 | ping256 | connect | udp1 | udp256 |
|---|---|---|---|---|---|
| **okena** | **26.4 / 31.2 / 51.5** | **1632 / 1702 / 1785** | **308 / 437 / 494** | **25.9 / 30.6 / 44.5** | **1304 / 1700** / 1930 |
| nginx | 31.9 / 38.9 / 66.4 | 1711 / 1995 / 2053 | 438 / 4556 / 11143 | 29.3 / 34.3 / 55.1 | 1656 / 1899 / **1925** |
| HAProxy | 34.0 / 41.7 / 71.1 | 1998 / 2187 / 2790 | 373 / 495 / 543 | | |
| Traefik | 33.1 / 40.4 / 71.0 | 2110 / 3308 / 3690 | 719 / 3393 / 5360 | 40.4 / 244 / 335 | 2225 / 8948 / 13230 |
| Envoy | 38.8 / 49.4 / 80.3 | 2366 / 3147 / 3261 | 639 / 1132 / 1924 | 32.4 / 41.2 / 68.8 | 1955 / 1994 / 2092 |

okena is first in every column but udp256's p99.9, 5 µs over nginx's. Large
transfers go socket to pipe to socket
inside the kernel (splice), and new connections from all clients wait in one
queue that the workers take in turn.

---

## Large response bodies

`tests/bench/httpbig.sh`. The backend answers `GET /SIZE` with SIZE bytes;
h2load `--h1`, 64 connections, closed loop, median of 3. nginx with
`proxy_buffering off`, as the others stream.

| Path (2 cores) | 64 KB responses | 1 MB responses |
|---|---|---|
| straight to the backend | 66.8 Gbit/s | 127.8 Gbit/s |
| **okena** | **33.8 Gbit/s** | **78.9 Gbit/s** |
| HAProxy | 19.4 Gbit/s | 26.3 Gbit/s |
| Envoy | 12.8 Gbit/s | 34.0 Gbit/s |
| Traefik | 10.6 Gbit/s | 29.1 Gbit/s |
| Caddy | 9.1 Gbit/s | 25.9 Gbit/s |
| nginx | 6.3 Gbit/s | 7.7 Gbit/s |

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
| **okena** | **115,164** | **103,084** | **114,908** | **300,816** |
| HAProxy | 84,714 | 23,498 | 86,274 | 183,485 |
| nginx | 79,616 | (NGINX Plus only) | 72,978 | 54,463 |
| Envoy | 31,270 | 26,319 | 29,861 | 28,933 |

Requests a second. A bad token gets 401 from every proxy that verifies
JWTs. Caddy and Traefik are not in this table: neither verifies JWTs or
caches responses without a plugin or their commercial editions.

---

## Addons: what an addon that answers at once adds

`tests/bench/addon.sh`. Phase 13's exit: okena (2 workers) in front of
l4bench http, two routes to it, one through an addon in C
(`sdk/c/examples/hello.c`, continue with nothing changed), one without.
okena bench in open loop, 32 connections, each route run alternately three
times for 10 s; the median of each percentile. Cores pinned: okena, the
addon, the backend and the load each on their own (Ryzen 7 5700G). The
round trip is okena's own histogram of the calls
(`okena_addon_call_seconds`: from posting the call to taking its answer;
upper bounds of its buckets).

With `poll 2ms` (the addon polls 2 ms after a call before it sleeps, so
under this traffic it never sleeps; not rerun on 2026-11-17):

| Rate | p50 without / with | p99 without / with | p99.9 without / with | the call's round trip p50 / p99 / p99.9 |
|---|---|---|---|---|
| 5,000/s | 43.5 / 46.1 µs | 69.6 / 72.7 µs (**+3.1**) | 94.2 / 98.3 µs | ≤ 1 / **≤ 2** / ≤ 8 µs |
| 20,000/s | 33.3 / 34.8 µs | 57.3 / 58.4 µs (**+1.0**) | 107.5 / 107.5 µs | ≤ 1 / **≤ 2** / ≤ 20 µs |

With the default `poll 50us`, a call that comes after a longer gap finds
the addon asleep and pays its wakeup (the eventfd, then a core out of its
idle state):

| Rate | p50 without / with | p99 without / with | the call's round trip p50 / p99 / p99.9 |
|---|---|---|---|
| 5,000/s | 44.0 / 51.2 µs | 66.6 / 67.6 µs | ≤ 10 / ≤ 20 / ≤ 20 µs |
| 20,000/s | 33.3 / 35.3 µs | 44.5 / 56.8 µs | ≤ 1 / ≤ 12.5 / ≤ 20 µs |

At 50,000/s two workers on two cores are saturated (the route without the
addon already has a p99 of 112-332 µs from run to run) and the difference
says nothing; the round trip's p99 is ≤ 8 µs there, mostly the call waiting
for its worker's loop. A single run's p99 moves by 10-15 µs on this desktop,
which is why the round trip is measured inside okena as well.

---

## Memory per idle connection

`tests/bench/idlemem.sh` (not rerun on 2026-11-17). 100,000 clients each make one request, read the
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
| base (the path alone) | 3.09 M | 3.25 M | 25 / 24 ns |
| **okena** | **2.30 M** | **1.89 M** | **118 / 208 ns** |
| Katran | 2.13 M | 1.68 M | 153 / 275 ns |
| Katran, MAX_CONN_RATE out of reach | 2.15 M | 1.28 M | 151 / 435 ns |

Time in the program is the kernel's own count (`kernel.bpf_stats_enabled`).

---

## Crypto against OpenSSL

One operation in a loop, one thread pinned to core 3. okena through
`build/kat`'s benchmark mode (`tests/kat/bench.py` and the same with Ed25519,
ML-KEM and ChaCha20); OpenSSL 3.5.3 through `openssl speed` on the same core.
From the earlier run: on 2026-11-17 only X25519 (23.8 µs), P-256 signing
(12.4 µs) and AES-128-GCM (6.48 GB/s) were measured again, within a few
percent of these.

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
| HTTP/1.1 at 10,000/s, p99.9 | 82 µs | HAProxy 80 µs | 2 µs |
| gRPC at 5,000/s, p99.9 | 461 µs | HAProxy 452 µs, nginx 459 µs | 9 µs |
| UDP, 256 flows, p99.9 | 1,930 µs | nginx 1,925 µs | 5 µs |
| HTTP/3 in closed loop, p99 / p99.9 | 6,844 / 9,565 µs | HAProxy 5,776 / 7,332 µs | HAProxy at 132k requests/s, okena at 192k |
