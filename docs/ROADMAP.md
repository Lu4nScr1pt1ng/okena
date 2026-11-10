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
(HTTP/1, static), Envoy (h2, gRPC, gateway features), Katran (XDP); phase 11
adds Caddy, Traefik, Pingora, Kong, APISIX, IPVS and dnsdist, and compares
okena as a whole.

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
  `okena bench` (open loop, coordinated-omission corrected). **Done:**
  `okena bench` (src/bench/bench.inc) drives HTTP, HTTPS (kTLS) and TCP
  echo on a per-connection schedule, wrk2's correction, and reports the
  generator's own lag beside it (tests/bench/run.py).
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
  `source-hash`, `maglev`, `random` (and `ring-hash`; the hashing ones done on
  2026-11-07, with `udp`).
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
on 16 KiB records, from 1.84; a 50 MB download
with user-space records went from 755 MB/s to 1.05 GB/s, level with
kTLS. Ticket keys rotate hourly in the supervisor: three slots on a page
shared with the workers, the new key written into the slot not in use,
then made current; tickets open under the current or the previous key.
Where the CPU has VAES and VPCLMULQDQ the eight blocks go two to an
instruction on ymm: 6.9 GB/s on 16 KiB records (OpenSSL 3.5: 5.8). `okena {
ticket_keys FILE }` shares the keys across a fleet (tickets resume on any
instance; the operator rotates with a new first line and a reload). SNI picks
among several certificates of a listener by their subjectAltName names
(exact, then one wildcard label, else the first), and a Host the chosen
certificate does not name gets 421. `tls passthrough` routes tcp
connections on the ClientHello's server_name without decrypting (both
engines, `tests/tls/passthrough.py`). Key exchange is x25519 or secp256r1 (`p256_ecdh`, the P-256 arithmetic
already present for ECDSA; the client's share decides, x25519 preferred,
HelloRetryRequest for a supported group sent without its share), so the
default clients of the ecosystem and tlsfuzzer negotiate (its TLS 1.3
sanity passes). TLS to the upstreams is in: a pool's `tls { trust FILE;
sni NAME }` runs a TLS 1.3 client handshake to the backend (the same
crypto as the server), verifies the server certificate (the chain to the
trust anchor, the validity window and the host name), and hands the keys
to kTLS so the proxy data path stays plaintext; a backend's session
tickets (kTLS control records) are drained with recvmsg. Both engines
(on epoll the kTLS options are set at once and the tickets drained with a
non-blocking recvmsg), and verified connections go back to the pool. Still open
from the list: TLS 1.2 for older clients, a full tlsfuzzer conformance
run (needs an HTTP-responding harness); then phase 4. TLS 1.2 for older
clients is in on the server side: a ClientHello without TLS 1.3 runs an
ECDHE_ECDSA / AES-128-GCM 1.2 handshake (ServerHello, Certificate, a signed
ServerKeyExchange, ServerHelloDone, then ClientKeyExchange and the Finished
exchange) and the keys go to kTLS 1.2; it is kTLS-only (no module, the
connection is refused). TLS 1.2 to upstreams is in too: a pool's tls { }
falls back to a 1.2 ECDHE handshake (ECDHE_ECDSA / ECDHE_RSA, AES-128-GCM)
for a backend that has no 1.3, verifying the ServerKeyExchange signature
and the certificate chain, over kTLS. A tlsfuzzer harness (tests/tls/tlsfuzz.py) drives tlsfuzzer's
TLS stack against a live okena -- TLS 1.3 and 1.2 handshakes with an HTTP
response, and negative probes -- skipped unless tlsfuzzer is installed; a
broad conformance run over its script suite is the remaining QA work.
The handshake budget is in (`okena { handshake_budget 100us wait=1s }`,
src/http/hsbudget.inc): server hellos spend at most that much TSC time per
loop iteration, the rest wait in a bounded FIFO the loop drains first on
the next iterations (never sleeping while it holds any), resumptions skip
it up to twice the budget, and hellos that waited past `wait` are closed
(okena_tls_handshakes_deferred_total, okena_tls_handshakes_shed_total;
tests/tls/budget.py on both engines). With 6000 handshakes at once on one
worker, an open connection's p99 went from 1.6 ms to 0.47 ms.
X25519MLKEM768 is in, preferred over x25519 and secp256r1 when the client
sends its share (Chrome, Firefox, curl and OpenSSL 3.5 by default):
Keccak (SHA-3, SHAKE) and ML-KEM-768 encapsulation in src/crypto, the
client's key checked (FIPS 203's modulus check, illegal_parameter
otherwise), the 64-byte hybrid secret (ML-KEM's, then x25519's) into the
key schedule, resumption on top (psk_dhe_ke). Checked byte for byte against
a FIPS 203 reference in tests/kat and against OpenSSL's decapsulation;
s_client and curl negotiate it. The polynomial arithmetic runs on AVX2
(eight dword coefficients a ymm, a 32-bit Barrett) and the matrix rows and
the noise on a four-way Keccak: key generation 12.9 us, encapsulation
15.5 us, decapsulation 16.6 us, against OpenSSL 3.5's 36, 25 and 37 us on
the same core (docs/BENCHMARK.md). Towards
upstreams too: ML-KEM-768 key generation and decapsulation (implicit
rejection in constant time), the client's ClientHello offering the hybrid
first beside x25519 and P-256, the decapsulation run once however the
server's flight arrives; checked against the reference and, both ways,
against OpenSSL (tests/kat, tests/tls/client.py against an s_server that
takes nothing else). TLS_CHACHA20_POLY1305_SHA256 is in: ChaCha20 on
AVX2 two blocks at a time, Poly1305 on mulx, the RFC 8439 AEAD (tag checked
before decrypting), picked when it is the client's first suite (no AES in
its hardware, OpenSSL's PRIORITIZE_CHACHA) or the only one shared; the
flight, tickets, user-space records and kTLS (its 56-byte crypto_info; a
kernel without it falls back to user-space records for that suite only)
all take it. Ed25519 is in (SHA-512 and RFC 8032 in src/crypto; signing
9.7 us, verification 39 us, OpenSSL 3.5: 30 and 80): servers present
Ed25519 certificates (PKCS #8 keys) to clients that offer ed25519, beside an
EC sibling for the rest, and upstream chains and CertificateVerify verify
with it. Wycheproof runs in make test (tests/wycheproof, vectors fetched once
at a pinned commit into build/wycheproof, skipped without them): 2821
cases over AES-128-GCM, ChaCha20-Poly1305, X25519, ECDSA and ECDH P-256,
Ed25519, RSA PKCS #1 v1.5 and PSS, HMAC and HKDF, and ML-KEM-768
encapsulation, key generation and decapsulation; it found RSA signatures
not below n verifying (refused now). Left for later: Wycheproof's DER
encodings of ECDSA signatures through the TLS and X.509 parsers.
The steady-state exit, measured open loop with `okena bench`
(docs/BENCHMARK.md): kTLS was 20% under plaintext on keep-alive requests,
with a p99 four to eight times plaintext's, all of it kernel time in the
kernel's TLS. `http` listeners now seal records in user space by default
(`ktls on` for the kernel): 161k requests/s against 163.5k plain on two
cores (-1.5%), p50 43-53 us against 38 us at 100k/s. Handshakes, open loop
against HAProxy 3.2 on the same two cores (tests/bench/tls.sh): 17.1k new
HTTPS connections/s against 4.55k (3.7 times), and keep-alive 169k/s
against 87k/s with a p99 of 49 us at 50k/s against HAProxy's 64 ms. Both
exits are met. Open, not blocking: a latency knee near 5k new
connections/s at ~35% CPU, the p99.9 tail of this desktop machine, a broad
tlsfuzzer run, and Wycheproof's DER ECDSA encodings through the parsers.
Found on the way: ECDSA verification ran two constant-time ladders on
public data (259 us; 67 us now, OpenSSL 48), and a server flight split
across reads failed upstream TLS (fixed).

* SHA-2, HMAC, HKDF (from fasm2crud), AES-GCM (AES-NI, VAES/VPCLMULQDQ),
  ChaCha20-Poly1305, X25519, ML-KEM-768, P-256 ECDH/ECDSA, Ed25519.
* TLS 1.3 server: X25519MLKEM768, SNI, ALPN, tickets with rotation,
  handshake budget.
* kTLS handoff, so splice and zero-copy work on TLS connections.
* `tls` listener (SNI routing, passthrough).
* TLS to upstreams: TLS 1.3 and 1.2 client, X.509 validation,
  RSA/ECDSA/Ed25519 verification, session resumption.
* TLS 1.2 server (ECDHE_ECDSA + AES-GCM) for older clients, over kTLS.
* Known-answer, Wycheproof and differential tests; constant-time checks;
  tlsfuzzer.

Exit: handshakes/s per core at or above OpenSSL-based HAProxy for ECDSA
certificates; kTLS steady state within a few percent of plaintext.

## Phase 4 — HTTP/2 and gRPC

Progress: HPACK is in (src/http/hpack.inc: the dynamic table, Huffman both
ways, a stateless encoder, expansion bounded by the caller's buffer;
tests/h2/hpack_suite.py: RFC 7541 appendix C byte for byte and a
differential run against the hpack package). HTTP/2 towards clients is in
(src/http/h2.inc, `http2 on`): ALPN h2 and prior knowledge, the frames and
their errors, flow control both ways, up to 100 streams each proxied as an
HTTP/1.1 exchange of its own (the design below), malformed requests reset,
rapid reset answered with GOAWAY; tests/h2/run.py on both engines, plain
and TLS. Abuse budgets: rapid reset (200 resets a second), a CONTINUATION
flood (64 frames a block, 16 KiB), frames that ask work and carry nothing
(PRIORITY, SETTINGS, PING, WINDOW_UPDATE, empty DATA: 2000 a second),
pings and settings a client does not read the answers to; each ends in
GOAWAY ENHANCE_YOUR_CALM. tests/h2/fuzz.py sends mutated and random frame
sequences (4000 connections an engine clean; `make fuzz` runs more).
A chunked response's trailers reach the client (after the last chunk for
HTTP/1.1, a trailing HEADERS for HTTP/2), so gRPC's status gets through.
HTTP/2 towards backends is in (src/http/h2u.inc, `protocol h2` in a
pool): connections of their own a server (at most 4, streams up to what
the server allows), the h2.inc connection code in client mode, the
requesting session's upstream side served like an HTTP/2 stream's client
side (its HTTP/1.1 head into HEADERS with :authority and te: trailers,
the body unframed into DATA, the response back as HTTP/1.1, chunk-framed
with its trailers when it has no length); RST_STREAM, GOAWAY and a lost
connection fail the requests they hold. tests/h2/upstream.py on both
engines against an HTTP/2 server and okena itself. okena's own errors to a
gRPC request (content-type application/grpc) are gRPC answers:
Trailers-Only, grpc-status from the HTTP status (502/503 UNAVAILABLE,
504/408 DEADLINE_EXCEEDED, ...); a head with content-length: 0 ends its
HTTP/2 stream itself. ALPN h2 over a pool's TLS is tested okena to
okena (tests/h2/upstream.py, when the tls module is loaded); that found
the upstream TLS client stuck on a server that sends its NewSessionTicket
with its Finished, fixed. h2spec (v2.6.0, fetched pinned into build/,
tests/h2/h2spec.py) passes every case on both engines over TLS (ALPN h2 on
TLS 1.2 too, which its client speaks) and all but the invalid preface by
prior knowledge, which a listener shared with HTTP/1.1 reads as HTTP/1.1.
Against Envoy 1.40.2 (tests/bench/grpc.sh, docs/BENCHMARK.md) okena adds
less latency at p99 for unary calls, server-streamed messages and
bidirectional streams at every rate measured (unary at 5k/s: 48 us
against 150; bidirectional at 20k/s: 47 against 64). Bidirectional
streams: when the client side is an HTTP/2 stream and the pool speaks
HTTP/2, the response is read as soon as the request head is out and the
body goes upstream beside it (http_duplex_pump). Those runs found the
cheap-frame budget cutting gRPC peers off (their BDP pings and window
updates follow every DATA frame: DATA and HEADERS sent earn four now, no
budget towards backends), OUT full of DATA turning a PING into GOAWAY
CALM (512 bytes are kept for control frames), queue checks reading a
clobbered length, and an epoll worker sleeping with deliveries queued.
WebSocket over h2 is in (RFC 8441: SETTINGS_ENABLE_CONNECT_PROTOCOL, an
extended CONNECT with :protocol websocket becomes an HTTP/1.1 upgrade
with okena's own Sec-WebSocket-Key, the backend's 101 the stream's 200;
then the backend's bytes go to the stream by the exchange's loop and the
client's DATA to the backend beside it, with sends of its own, until the
backend closes; tests/h2/websocket.py on both engines). Open: okena's
p99.9 at some rates (wakeups); an ordinary request body streamed both
ways when only one end is HTTP/2 (that exchange stays in turn); RFC 9218
priorities. gRPC health checks are in (`health grpc [SERVICE]`:
grpc.health.v1.Health/Check over HTTP/2 by prior knowledge from the
health process, which walks the answer's frames, not its headers: SERVING
passes; another status, Trailers-Only, RST_STREAM or GOAWAY fail, each
logged with its reason; tests/health/run.py). The design: an h2
connection is a session whose streams are sessions of their own, each
running the existing HTTP/1.1 exchange (routing, pools, retries, upstream
TLS, logs, rewrites) with its client side redirected to the connection,
as user-space TLS records redirect it today: h_recv on a stream hands it
the request (from HEADERS, CONTINUATION and DATA), h_send takes its
response and turns it into HEADERS and DATA. Then the connection itself:
the preface, SETTINGS, PING, GOAWAY, RST_STREAM, WINDOW_UPDATE and flow
control both ways, the abuse budgets (rapid reset, CONTINUATION, SETTINGS
and PING floods, empty frames, window-zero stalls); ALPN h2 on TLS
listeners and prior knowledge on plain ones; h2spec and frame fuzzing.
Upstream h2 and gRPC come after.

* h2 downstream and upstream, HPACK, RFC 9218 priorities, flow control.
* Protocol translation h1 ↔ h2 in both directions; WebSocket over h2.
* Upstream multiplexing; gRPC routing, trailers, gRPC health checks,
  gRPC status mapping.
* Abuse limits (rapid reset, CONTINUATION, HPACK bomb, floods).
* h2spec clean; fuzzing of frames and HPACK.

Exit: beats Envoy on added p99 for gRPC unary and streaming. Met
(2026-10-31, docs/BENCHMARK.md): unary, server streaming and
bidirectional streams, every rate measured.

## Phase 5 — HTTP/3 and QUIC

Next after phase 4. QUIC terminates on the same workers: one UDP socket
per worker per listener (SO_REUSEPORT), the connection ID naming the
worker so an eBPF reuseport program steers every packet of a connection
to the worker that holds it; TLS 1.3 from src/tls (the handshake without
records, QUIC's packet protection with the same AES-GCM, ChaCha20 and
header protection); each HTTP/3 request stream a session running the
HTTP/1.1 exchange, as HTTP/2 streams do (src/http/h2.inc), so routing,
pools and everything after them stay one code path.

**Done** (2026-11-05; `http3 on`, off by default). As built, against the plan
below: steering is classic BPF on the reuseport group, not eBPF; 0-RTT goes by
method (GET, HEAD, OPTIONS), not by route; BBR is there but CUBIC stays the
default (`quic_cc bbr`: far better under loss, about 20% slower without). Of
the exit, two measures are accepted as they stand and left open: quiet latency,
ahead open loop but 10 to 40 µs behind at p50 under h2load, unexplained; and
the flood, close to flat (p99 0.5 ms against 0.2) but p99.9 at 2 ms against 0.4.

In: packet protection (RFC
9001, 9369, with the RFC's test vectors), Version Negotiation, the
handshake on a UDP socket per worker (TLS 1.3 in QUIC mode, X25519 and
X25519MLKEM768), the 3x amplification limit, ACK ranges, PTO, CUBIC (RFC 9438)
with packet and time threshold loss detection; request streams as
sessions running the HTTP/1.1 exchange, QPACK with the static and the dynamic table (the client's inserts, our decoder stream),
stream and connection flow control, out-of-order stream data held until
the gap fills, Retry with sealed address tokens (under load or always:
`http3 retry`), GOAWAY on drain, Alt-Svc on HTTP/1.1 and HTTP/2 answers.
Stateless resets with a key the workers share. Key updates (RFC 9001 6)
and NAT rebinding (the client followed to its new address, the path
validated), preferred_address (each path probed both ways, a probe's
answer 3x what came at most), packets steered to the worker their connection ID names
(classic BPF on the reuseport group). Resumption with session tickets,
0-RTT behind `early_data on` (safe methods only), ECN marks and ACK_ECN, compatible version negotiation to v2
(RFC 9368), the loss timer, hq-interop for the interop runner
(tests/interop). tests/h3/run.py drives
it with aioquic and curl (ngtcp2) on both engines, through a relay that
loses a tenth of the datagrams each way. Measured against HAProxy 3.2
and nginx 1.27 (docs/BENCHMARK.md, h2load with HTTP/3 and `okena bench
proto=h3`): ahead on many streams (196k/s against 132k and 95k), on
handshakes (10k/s on two cores, none failing, against about 1.2k) and under
an Initial flood (18k/s kept, p99 0.5 ms; they fall to 2.1k and 4.1k/s). Quiet:
ahead open loop at p50 and p99, 10 to 40 µs behind at p50 under h2load. The
interop runner: 22 of 22 with ngtcp2, neqo, picoquic; only client limits left
on the others. BBR behind `quic_cc bbr`. Open: why the two generators disagree
on quiet latency, the flood's p99.9 (2 ms against 0.4). `okena bench proto=h3`
is in. QUIC-LB IDs in the clear or encrypted
(`quic_server_id`), budgets on rapid reset, probes and ACKs, the header
deadline per stream.

* QUIC v1 (RFC 9000/9001/9002) and v2 (RFC 9369): packets, frames,
  streams and their flow control, ACKs, loss recovery, CUBIC then BBR,
  pacing, PMTU, connection migration; stateless retry and address
  validation tokens under load; 0-RTT off by default, and when on only
  for routes marked idempotent.
* QUIC-LB connection IDs (worker, and instance for a fleet) with eBPF
  steering; GSO/GRO and recvmmsg/sendmmsg batching, ECN.
* QPACK (RFC 9204) with its encoder and decoder streams; HTTP/3 (RFC
  9114) with SETTINGS, GOAWAY, server-initiated cancellation; Alt-Svc
  on HTTP/1.1 and HTTP/2 answers, and HTTPS DNS records documented.
* Abuse limits as in HTTP/2 (stream floods, resets, ACK and crypto
  frame floods, amplification bounded by the 3x rule before validation).
* `okena bench` speaks HTTP/3 too, so the exits are measured open loop.

Exit: the QUIC interop runner clean against the main clients and servers;
handshakes/s per core and added p99 for HTTP/3 at or better than HAProxy
3.x's QUIC (and nginx's) on the same machine; loss and reordering (netem)
do not stall a connection; under a flood of Initial packets retry keeps
the accepted connections' latency flat.
## Phase 6 — Gateway

Done. OIDC login is not built in: `auth forward` hands it to a proxy that does it, such as
oauth2-proxy, as a login flow is a lot of security surface for what that gives. In: `fault abort= delay=`, `cors`, `split`, `mirror`, `hedge`, `policy` and `use`, `cache` in memory with coalescing and stale-while-revalidate, `files` with ranges, validators, precompressed variants and a fallback, `compress gzip`, `early_hints`, `headers preset=`, `okena route`, `redirects`, `hold`, `priority` with an overload manager, `auth api_key`,
`basic`, `mtls` (`client_ca` over TCP), `forward` and `jwt` (a JWK set from a file or a URL), `match` blocks, `limit` (by rate, up to a day), `idempotency`, `allow` and `deny`, GeoIP by country.

* JWT/JWKS (fetched by a process of its own, not the control process: a slow
  provider must not hold up DNS), verified-token cache, API
  keys, Basic, mTLS identity, forward-auth with answer cache.
* Rate limits: GCRA per instance through leases, bounded key table with
  eviction under key floods; quotas.
* CORS, path rewrites, splits, mirroring, hedging, priorities.
* HTTP cache with coalescing and stale-while-revalidate.
* Static files and SPAs (fallback, ranges, ETag), precompressed variants,
  on-the-fly gzip/zstd for text, 103 Early Hints.
* Fault injection per route (`fault delay=`, `fault abort=`).
* Idempotency keys, GeoIP (country), redirect maps, security header
  presets, deploy hold.
* `okena route` dry-run.

Exit: each filter's added latency measured and documented; a route with
auth + limit stays within the latency budget in ARCHITECTURE.md. Met with `busy_poll`
(docs/BENCHMARK.md); without it p99.9 is over, by what a worker's sleep costs.

## Phase 7 — Operations

* Binary upgrade with socket handoff (`okena upgrade`: done); admin API and CLI
  (`okena backend`, `okena reload`: done).
* SRV/file discovery, Docker discovery by labels, Kubernetes EndpointSlices
  (`discover file`, `srv`, `docker`, `kubernetes`: done).
* Shared ticket keys and drain API for fleets (`ticket_keys` followed without a
  reload, `okena drain` and `resume`, GOAWAY on a drain for HTTP/2 and 3: done).
* Alerts (webhook, Telegram, Slack) from the control process (done).
* OTLP tracing; access logs out over OTLP and syslog (RFC 5424, UDP, TCP and
  TLS) besides files, through the logger process (done).
* `okena top`; a read-only dashboard from the admin process (listeners, routes,
  pools and servers with their health, drains and limits), behind the admin
  socket or an address with its own auth (done: `/status`, `/dashboard`,
  `metrics ... token=`; bytes by HTTP listener and passive ejections are not
  counted yet).
* Error pages of one's own (`errors 502 503 504 file=/srv/down.html`, by status
  and by route, also for errors a backend sent: done) and a maintenance mode (done)
  (`okena maintenance on [route]`: a page and a Retry-After, health checks
  and allowed addresses still let in).
* Landlock, privilege drop, systemd socket activation, container image (done:
  Landlock in every process, `user`, socket activation and the notify protocol
  with contrib/systemd units, a `scratch` image as uid 65532 with its seccomp
  profile).

Exit: a week-long soak with reloads and upgrades every minute under load
loses no request; `make chaos` passes with every dependency (DNS,
discovery, JWKS, control process, logger, disk) failed in turn (`make chaos`
passes for all of them, with workers, backends and ports too; `make soak`
runs the soak for as long as asked, and passes on both engines with a
reload every 5 s and an upgrade every 15 s; the week-long run is to be done
on a machine that can spare it).

## Phase 8 — Edge and CDN

* Disk cache tier: append-only segments, lock-free shared index, S3-FIFO,
  sendfile to the socket. (Done: `cache_disk`, with segments, a lock-free
  index shared by all workers and processes, pins, and a store that
  outlives reloads, upgrades and restarts; zero copy from the page cache to
  the socket, splice with io_uring and sendfile with epoll, kTLS too;
  S3-FIFO, kept by a process of its own off the request path.)
* Cache keys, `Vary` normalisation, slicing, `stale-if-error`, purge by
  URL/prefix/tag with fleet fan-out, `Cache-Status`. (Done: keys with
  `query=` and `host=off`, Accept-Encoding normalised, `stale-if-error`
  from the route and the origin, `Cache-Status` on every answer; purge by
  URL, prefix and tag, kept in the store, over the admin socket and HTTP,
  fanned out to `fleet`; ranges answered from the cache, and `slice=` for
  large objects.)
* Shield tier, signed URLs, CDN provider ranges, authenticated origin
  pulls, health-driven BGP announcement (through BIRD). (Done: signed
  URLs, with prefix, client address and key rotation, and `okena sign`;
  Cloudflare's ranges by name in `trusted_proxies` and `allow`, and
  `file:PATH` lists; authenticated origin pulls, a pool's client
  certificate over TLS 1.3; the shield tier, `key=url` and `cdn_loop`;
  health-driven anycast through BIRD's control socket; VRRP v3.)
* A floating address for a pair of instances without BGP: VRRP v3 (RFC 9568),
  with health deciding who holds it and gratuitous ARP / unsolicited NA on a
  change, as keepalived beside HAProxy does it. (Done for IPv4, with
  gratuitous ARP; IPv6 and unsolicited NA to come.)

Exit: hit path serves from page cache at line rate with zero copies;
origin load stays flat during a purge-and-refill storm. (Every item is
built; both measurements are still to be made on the lab.)

## Phase 9 — Breadth

* Automatic HTTPS, as Caddy does it: `tls auto` (or a listener on :443 with host
  names and no certificate) and okena does the rest. ACME (RFC 8555) in a process
  of its own, the only one that talks to a CA and writes keys, out of the
  workers' seccomp and Landlock: HTTP-01 answered by the :80 listener,
  TLS-ALPN-01 by the :443 one (no port 80 needed), DNS-01 through a provider
  (Cloudflare, Route 53, RFC 2136) for wildcards. Let's Encrypt by default,
  ZeroSSL and any ACME CA (an internal step-ca) as fallbacks when one fails or
  rate-limits; External Account Binding. ECDSA P-256 keys, renewal at two
  thirds of the lifetime with jitter, and earlier when ARI (RFC 9773) says so;
  backoff that respects the CA's limits, and the staging CA first when a name
  has failed. Certificates reach the workers as a reload of keys only, with no
  connection dropped; until a name has one it is served a short-lived
  self-signed certificate, never a refused handshake. OCSP stapling, with the
  staple refreshed before it ends and a revoked certificate replaced at once.
  Plain http redirected to https for those names (`redirect off` to keep it).
  On-demand certificates for names not in the file, behind a check (`ask` URL
  or an allow list) so a stranger's name cannot make okena ask for one. Storage
  in a directory (0700, keys 0600) that a fleet can share, with a lock so one
  instance orders and the others take its result; `okena certs` lists them with
  their expiry and what was last tried. A local CA for development names
  (`localhost`, `*.test`), trusted with one command. Metrics and alerts for
  certificates near their end.
  Built so far: `okena { acme DIR ca=URL }` and `tls { acme NAME... }`: the
  okena-acme process (account key, JWS ES256, orders, HTTP-01 answered by any
  http listener's workers or TLS-ALPN-01 by their TLS 1.3 handshake or DNS-01
  through Cloudflare's API, RFC 2136 (TSIG) or Route 53 (SigV4), wildcards
  included, CSR, the chain), a self-signed certificate until then,
  files renamed into DIR, a reload of its own, renewal at two thirds, backoff
  from a minute to six hours; `okena cert` for keys, CSRs and self-signed ones.
  A fallback CA, asked at once when the first fails; external account binding
  (EAB) for either. ARI (RFC 9773): the CA's renewal window followed, the
  order naming the certificate it replaces. OCSP stapling (TLS 1.3 and 1.2),
  for every certificate with a responder, ACME's or not: issuer- or
  delegate-signed answers only, refreshed halfway to nextUpdate; an ACME
  certificate the CA says is revoked renewed at once.
  On-demand certificates (`on_demand` patterns, `ask=`, `max=`): the handshake
  parked until the acme process has one, then served from a shared store.
  `okena certs`. A fleet sharing DIR (`shared=on`): a lock per certificate
  (link(2), stale ones moved aside), HTTP-01 challenges shared through
  DIR/NAME/http-01, the others taking the certificate from disk.
  The local CA: `tls { local NAME... }`, `okena { local_ca DIR }`, made at the
  first start, leaves of 7 days signed at each compile (AKI, IP SANs), renewed
  by a reload of its own; `okena trust [remove]` for the system's store.
  `tls { auto }`: the host blocks' names, Let's Encrypt and /var/lib/okena/acme
  by default; plain http redirected (308) to https for every name from the CA,
  `redirect off` to keep it. Renewal with jitter (up to 1/20 of the life
  earlier); after a failure the staging CA first (`staging=`, Let's Encrypt's
  by default for it), across restarts. `okena_tls_certificate_not_after_seconds`
  on /metrics and `alerts { on certificate }` (under 14 days left, told daily).
  Exit: a fresh install with `tls auto` serves a valid certificate within a
  minute; a CA down, rate-limited or answering wrongly never takes a served
  certificate away; `make chaos` with the CA failed in turn passes.
* TLS 1.2, RSA certificates (signing), client-certificate auth at scale.
* FastCGI to PHP-FPM and others (`php` on a route: index files, the script
  path checked against the root, try-files), as nginx and Caddy do it.
* Regular expressions in routes, `match` and `rewrite`, compiled to an
  automaton that runs in linear time (no backtracking, so no ReDoS), with
  captures for the rewrite.
* gRPC-Web for browsers, and gRPC to JSON transcoding from the service's
  descriptors.
* Brotli on the fly.
* Consul discovery, Kubernetes Gateway API.
* Certificate compression, Encrypted Client Hello.
* AVX-512 paths where they pay.

## Phase 10 — Kernel fast paths

* `xdp` listener: Maglev in eBPF, IPIP/GUE encapsulation, DSR,
  connection tracking table, backend health from user space.
* XDP pre-filter for the other engines: drop lists, per-source SYN rate.
* zcrx zero-copy receive on supported NICs; NIC TLS offload.

Exit: packets/s per core comparable to Katran.

## Phase 11 — Proof at scale: benchmarks, performance, no needless limits

Every phase so far met its own exit against one reference. This one measures
okena as a whole against the best of each field, makes it faster where it
loses, removes every limit that exists only because it was simpler, and shows,
with numbers and not claims, how far it goes: from one core to a fleet that
carries a large CDN's traffic. Nothing is added here that is not measured, and
nothing measured is left worse than before.

**First, the two documents everything rests on.** Before any measurement,
[EDGE_CASES.md](EDGE_CASES.md) and [ARCHITECTURE.md](ARCHITECTURE.md) are
read again against the code as it is and against what the best proxies have
learned since they were written. For the edge cases: is each one handled the
best way and not only a way (the RFC's behaviour, what HAProxy, nginx and
Envoy do, and why okena differs where it does), does every line have a test
that would fail without its handling, and what is missing: the smuggling,
desync, protocol-confusion, resource-exhaustion and timing cases published
since, each protocol okena gained after the list was made (HTTP/2, HTTP/3,
QUIC, `udp`, discovery, the admin API), and the cases only a fleet meets. For
the architecture: does each decision still hold with what was built and
measured (processes, engines, the shared tables, where state lives, how a
worker is confined), is there a better structure now that the whole is
known, and is what the document says what the code does. Both come out of it
corrected and complete, and the rest of the phase measures against them.

**The bench lab.** A reproducible setup, in the repository: two to four hosts
(and one-host netns topologies for CI), cores pinned, IRQs and RSS queues
placed, CPU frequency fixed, SMT noted, kernel and NIC firmware recorded. Open
loop throughout (`okena bench`, wrk2-style corrected latency, and h2load,
k6 or Gatling where a second generator settles a doubt), p50 to p99.99 and
the maximum, and every run kept with its raw histograms, so that a regression
in any later commit is seen by CI against the last release.

**Against whom.** On the same hardware and with each one tuned by its own
documentation, not left at defaults:

* L4 TCP and UDP: HAProxy, nginx stream, Envoy, IPVS, Katran (XDP).
* HTTP/1.1 and HTTP/2, plain and TLS: HAProxy, nginx, Envoy, Caddy, Traefik,
  Pingora; gRPC: Envoy, HAProxy.
* HTTP/3: nginx, Caddy, HAProxy, Envoy where each supports it.
* Gateway features (auth, JWT, rate limits, cache, compression): Envoy, Kong,
  APISIX, nginx; static files: nginx.
* DNS load balancing: dnsdist; game-style UDP: a tuned HAProxy/nginx stream
  setup and a bare C relay as the floor.

**What is measured.** Requests and packets per second per core and per host;
latency at fixed loads from 10% to past saturation, and how it degrades past
it (it must degrade, not collapse); connections per second and TLS handshakes
per second (full and resumed, P-256, Ed25519, X25519MLKEM768); idle connection
cost (memory per connection at 1M and 10M); reload, upgrade and drain under
load (requests lost: none); behaviour under abuse (slowloris, rapid reset,
floods) while measuring the legitimate traffic's latency; tail under noisy
neighbours and CPU quota in containers.

**Performance work.** Profiles (perf, eBPF off-CPU and wake-up tracing, TSC
counters in the hot paths) decide, not guesses. Already known to look at: the
worker wake-up that makes the p99.9 tail (adaptive busy polling instead of
all or nothing, NAPI busy poll, `SO_PREFER_BUSY_POLL`); batching of sends and
receives on every path; zero-copy (`SEND_ZC`, splice, sockmap, kTLS with
`sendfile`) chosen per size by measurement; GSO/GRO for UDP and QUIC; cache
lines shared between cores (none on the hot path, proven by perf c2c);
branch layout and AVX-512 where it pays; the cost of each gateway feature per
request, so that a route pays only for what it uses.

**Memory.** Every structure accounted for and exported (`okena_memory_bytes`
by kind): pools that grow and shrink with the load and give pages back
(`MADV_FREE`) when it falls, never on the request path; bounded everything,
with a clear behaviour when a bound is reached (shed, queue or refuse, never
crash or swap); huge pages for the big tables where they help the TLB;
NUMA-local allocation per worker; a steady state that does not grow over a
week of churn (checked by the soak). Memory must never be the reason a
request waits.

**Limits that need not be.** Each fixed limit in the code is listed (servers,
pools, listeners, routes, flows, header sizes, queue lengths, discovered
servers, ...) and either removed (sized from the configuration, or growing),
or kept with the reason written next to it and a number high enough that no
real deployment meets it. A configuration that grows tenfold must work without
a rebuild.

**A review of everything.** Each subsystem read again with the measurements in
hand: is this the fastest correct way, does it do work it need not, does it
take a lock, a syscall or a copy it could avoid, does its worst case have a
bound. Findings fixed, and the ones not fixed written down with why.

**How far it scales.** The question, answered with measurements and a model:
what it takes to carry millions of requests per second, and a traffic of the
order of Cloudflare's (tens of millions of HTTP requests per second, and DNS
at the same order), and where okena would stop first. Per core, per host
(cores, NIC queues, memory bandwidth), and across a fleet (ECMP or anycast in
front, QUIC-LB connection IDs, shared ticket keys, fleet-wide rate limits,
cache shield): what grows linearly, what does not, and what is changed so that
it does. The same for the extremes of latency: DNS (answers in microseconds,
millions of queries per second per host, behind `udp` or in front of an
authoritative server) and online games (UDP flows whose jitter matters more
than their mean, measured as a distribution per flow, with busy polling and
core isolation).

**What runs the largest edges, replaced.** The aim is not to be fast in a lab
but to be able to take the place of what carries the world's traffic today:
Cloudflare's (Pingora for HTTP, Unimog for L4, its DNS), AWS's (ELB/ALB/NLB,
Hyperplane, CloudFront, Route 53), Google's (Maglev, the GFE), Meta's (Katran,
Proxygen), Fastly's and Akamai's edges. For each, what it does that okena must
do too, as well or better, written down and checked off:

* Many tenants on one fleet: millions of host names and certificates loaded
  and changed without a reload that costs anything (configuration as data,
  pushed by API and applied per tenant), each tenant isolated in its limits,
  its memory and its share of CPU, so that one tenant's surge or attack never
  touches another's latency.
* Global anycast: the same addresses everywhere, BGP announced by health
  (phase 8), consistent hashing that survives a site joining or leaving,
  QUIC and TCP connections that keep their backend when the path moves.
* Attack traffic as a normal load: millions of packets per second of SYN, UDP
  and HTTP floods absorbed at the edge (XDP pre-filter, SYN cookies, per-source
  and per-tenant budgets, challenge responses) while real users keep their
  latency; layer 7 attacks told apart by behaviour, not only by rate.
* Change without fear: upgrades, reloads and configuration pushes to a whole
  fleet in stages, with automatic rollback when error rates or latency move;
  no global outage from one bad push.
* Observability at that size: metrics, logs and traces sampled and aggregated
  so that seeing the traffic never costs what serving it does.
* DNS at the scale of a public resolver and of an authoritative service: rate
  limiting, response rate limiting, DNSSEC passing through untouched, and
  answers in microseconds.

**A real case to prove it on: an online game.** okena is a balancer, not a
matchmaker, and the point is to show that in the busiest kind of game service it
helps everywhere it sits and never stands in the way. A competitive shooter's
platform, end to end:

* The lobby and matchmaking: millions of players at once searching for a
  match or browsing servers, over HTTPS, gRPC and WebSocket. okena in front of
  the matchmakers sends each player to the nearest region (GeoIP, latency to
  each region measured by the health checks, not guessed), keeps a player's
  session on its matchmaker (`sticky`, `maglev`), absorbs the surge when a
  season starts (queues with `max=`, rate limits per player, cache for the
  server list), and shows which servers are up and how loaded through its
  metrics and admin API. Measured: requests per second per host, p99 at the
  peak, and that no matchmaker is overloaded while another is idle.
* The match itself: once placed, a player's UDP traffic goes to one game
  server and stays there for the whole match. With okena in that path (to
  hide the servers' addresses and take attacks, as a game-oriented DDoS
  service does), a flow never moves while its server is up: not on a reload,
  an upgrade, a change in the number of workers, nor on another site taking
  over the address (flows keyed so that any okena sends them to the same
  server). What it adds is measured per flow as a distribution, mean and
  jitter (p99 minus p50) at 64 to 1200 bytes and 20 to 128 packets a second
  per player, with busy polling and isolated cores: the target is tens of
  microseconds added, and jitter no larger than the network's own. A player
  whose server dies is not silently moved to one that knows nothing of the
  match: the flow ends and the game's own reconnect decides.
* Where okena should not be: the case where players connect straight to the
  game server's address is said plainly, with what okena still does around it
  (the lobby, the server list, attack filtering in front of the servers' own
  addresses with `xdp`).

The exit for this case: a simulated platform of millions of players (the
lobby load and the match traffic generated together) runs through okena with
no player moved off a match, no p99 latency target missed, and nothing in
okena that the game's design would have to work around.

Each of these is shown on the lab first and in the model of a fleet next:
how many hosts, of which kind, carry a given share of a global load, and that
the cost per request falls, not rises, as the fleet grows.

Exit: published results, reproducible from the repository, in which okena
equals or beats the best compared on latency (p50, p99, p99.9) in every
category above, and on throughput per core in all but those where a
kernel-only path (IPVS, Katran) is the reference, where it comes within 10%
with `xdp`; memory per idle connection at or under the best; no fixed limit
that a real deployment can reach; a written, measured path to a fleet that
carries tens of millions of requests per second; and, for each of the large
edges named above, the list of what it does with okena's answer to each item,
measured, so that the claim that okena can replace it stands on numbers.

## Phase 12 — Addons

* Shared-memory addon protocol, supervision, deadlines, circuit breakers.
* SDKs (C, Rust, Go, Python); a reference WAF addon on Coraza.
* proxy-wasm plugins (the ABI Envoy, nginx and Traefik run), in a process of
  their own like the other addons.
* `ext_authz` / `ext_proc` adapter.

Exit: an addon that answers immediately adds under 5 us at p99; a crashing
or hanging addon never affects routes that do not use it.
