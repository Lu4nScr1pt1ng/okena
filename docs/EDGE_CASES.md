# Edge cases

What okena does in the situations that break proxies. Each line is a
behaviour to implement and a test to keep. The HTTP/1.x parsing table is
checked line by line against a running okena by `tests/httpproxy/edge.py`
(both engines), the upstream responses table by `tests/httpproxy/upstream.py`, paths and hosts by
`tests/httpproxy/routing.py`, client identity by `tests/httpproxy/identity.py`, failing backends and
misbehaving clients by `tests/httpproxy/failures.py`, odd ClientHellos by `tests/tls/hello.py`, HTTP/2 abuse by `tests/h2/abuse.py` (with h2spec for
conformance), and its parser against a reference by `tests/http/run.py`. "Reject" means a 4xx/5xx with
the connection closed when its framing can no longer be trusted.

## Network and TCP

| Case | Behaviour |
|---|---|
| SYN flood | kernel SYN cookies; optional XDP per-source SYN rate; accept queue sized by `somaxconn` |
| Connection that never sends a byte | `TCP_DEFER_ACCEPT` for HTTP; handshake deadline |
| Slowloris (headers a byte at a time) | header progress and total deadlines; linear-time resumable parsing |
| Slow read (client never reads the response) | write progress deadline; backpressure to the upstream stream, not buffering |
| Half-close (client sends FIN, still reads) | kept open in `tcp` mode until both sides close; in HTTP, the response is still delivered |
| RST in the middle of a response | upstream stream cancelled, upstream connection reused only if its framing is intact |
| Client IP behind NAT (thousands of users, one address) | per-source connection limits configurable, and keyable by other attributes |
| IPv6, dual stack, IPv4-mapped addresses | normalised to one form for limits, logs and ACLs; happy eyeballs to dual-stack backends |
| MTU/PMTU black holes | `TCP_MSS` clamp option; QUIC starts at 1200 bytes and probes 1350 and 1452 (RFC 9000 14.3), a lost probe costing nothing |
| Clients behind proxies that send PROXY protocol | accepted only from `proxy_protocol accept from=`; v1 and v2 with TLVs (TLS info, unique ID) |
| Upstream port exhaustion | `IP_BIND_ADDRESS_NO_PORT`, several source addresses, free ports as a pressure signal |
| Backend black-holed (no RST, no answer) | connect deadline, `TCP_USER_TIMEOUT`, keepalive, response deadline |
| Backend IP changes (container recreated, DNS failover) | re-resolve on TTL and immediately on connect failure |
| Conntrack table full on the host | detected by `okena check --host`; `NOTRACK` guidance |

## TLS

| Case | Behaviour |
|---|---|
| No SNI (old clients, IP access) | `default` certificate per listener, or reject |
| SNI and `Host` disagree (domain fronting) | 421 Misdirected Request unless the certificate covers both and the route allows it |
| HTTP/2 connection coalescing to a host this connection should not serve | 421, so the browser opens a new connection |
| ClientHello split across several TCP segments / records | buffered up to 16 KiB before routing (`tls` mode and termination), a byte per record or per segment included; a larger hello closes the connection |
| Records out of place before the hello (application data, ChangeCipherSpec, an empty record), an SSLv2 hello | `unexpected_message`; a record past 2^14+256 `record_overflow` |
| Large post-quantum ClientHello (ML-KEM shares) | supported; bugs in middleboxes that drop big ClientHellos are the client's, but okena never needs a second round trip for it |
| HelloRetryRequest | supported for groups okena prefers |
| TLS 1.2-only clients and backends | ECDHE + AEAD; RSA key exchange and CBC never; TLS 1.0 and 1.1 `handshake_failure`. An ECDSA certificate needs its curve in the client's groups (RFC 8422 5.1), else the RSA one or `handshake_failure` |
| 0-RTT replay | off by default; when on, only idempotent routes, `Early-Data: 1` forwarded, 425 when a route is not safe |
| Ticket key leak / rotation | hourly rotation, old keys accepted for one lifetime, never written to disk unless shared on purpose |
| Certificate expiring, ACME failing | old certificate kept, alert at 14 days, backoff respecting CA limits |
| Wildcard and multi-domain certificates, thousands of domains | name index with wildcard lookup; IDNA via punycode |
| Client certificate optional on some routes | handshake requests it per listener; routes decide whether it is required; post-handshake auth not used |
| Upstream with a self-signed or private CA | `tls ca=` per pool; never "verify off" silently (`insecure` must be spelled out and is logged at startup) |
| kTLS unsupported for the cipher or key update | user-space record layer for that connection |
| TLS passthrough to backends that need the client address | PROXY protocol v2 out |

## HTTP/1.x parsing (smuggling and desync)

| Case | Behaviour |
|---|---|
| `Content-Length` and `Transfer-Encoding` together | reject 400 |
| Duplicate or comma-joined differing `Content-Length` | reject 400; identical repeated values collapsed |
| `Transfer-Encoding` not ending in a single `chunked`, or with odd casing/whitespace | reject 400 |
| Chunk extensions, huge chunk sizes, chunk size overflow | extensions bounded and dropped; size overflow → 400 |
| Trailers | forwarded only to protocols that carry them, bounded |
| Obsolete line folding, bare CR, bare LF, NUL, control bytes | reject 400 |
| Whitespace between header name and colon | reject 400 |
| Header names with invalid token characters | reject 400 |
| HTTP/1.0 without `Host`, with keep-alive | accepted, routed by the listener's default; forwarded as HTTP/1.1 with `Host` set to the listener's address; `Connection: keep-alive` honoured |
| HTTP/0.9 | 400 as soon as its line ends (no head would ever follow) |
| Absolute-form target (`GET http://host/ HTTP/1.1`) | its authority must be the `Host` (letters in any case), else 400: two hosts named is a request a server behind could read either way; sent on in origin form |
| `CONNECT` | 405 unless a route allows tunnelling (forward proxy is opt-in) |
| `*` target | only with `OPTIONS`; any other method 400 |
| Empty lines before the request line | dropped (RFC 9112 2.2: a client may send a CRLF after a body); a bare LF is still 400 |
| `TRACE` | 405 by default |
| Request line or headers too large | 414 (the line alone fills the buffer) / 431 |
| Too many headers | 431 |
| Huge cookies (many `Cookie` lines) | combined per RFC, size-limited |
| `Expect: 100-continue` | answered by okena: 100 when the request goes on, 413 when its length is past `body_size` |
| Pipelined requests | answered in order; a request with an error closes after earlier responses are sent |
| An error answered with bytes still unread (a body, a head too large) | lingering close: the writing side shut, what comes read and dropped until the client closes or the header timeout passes, so no reset takes the answer with it |
| Request body on GET/DELETE | forwarded as framed; never assumed empty |
| Upgrade on a request with a body | reject |
| `Connection` naming other headers | those headers removed as hop-by-hop |

## Upstream responses

| Case | Behaviour |
|---|---|
| Malformed response (bad framing, invalid headers, bare LF, obs-fold, a status under 100, a version other than 1.0/1.1) | 502, upstream connection closed |
| Status line without a reason (`HTTP/1.1 200`, its space missing too) | accepted: servers send it, and the reason means nothing |
| Field values with bytes above 0x7F (obs-text) | kept as they came |
| A 101 the request did not ask for | 502 |
| Response to `HEAD`, 204, 304 with a body or `Content-Length` | no body forwarded; connection to the backend closed if it sent one anyway |
| Response delimited by connection close | supported; converted to chunked or DATA frames for the client |
| Several 1xx before the final response | forwarded (103 Early Hints included) or dropped per route |
| Response before the request body was fully sent | request body stopped, response forwarded, upstream connection not reused |
| Backend closes a reused keep-alive connection | retry once on a new connection if no response byte arrived and the request is safe to repeat |
| `Content-Length` shorter or longer than the body | 502 if detected before the response started; after, the client's connection is closed before the body's end (a length not met, no last chunk), so it cannot take a truncated body for a whole one |
| Bytes after a response (past its length, a body on 204/304/HEAD), even arriving late | never read as the next response: the pooled connection is looked at before reuse and dropped if anything is waiting on it |
| Upstream sends `Transfer-Encoding` and `Content-Length` | treated as invalid, 502 |
| Huge response headers | limit, 502 |
| Backend sets hop-by-hop headers or `Upgrade` without being asked | stripped |
| `Set-Cookie` with multiple values | never folded with commas |

## Paths, hosts and routing

| Case | Behaviour |
|---|---|
| Dot segments, `%2e%2e`, `%2F`, `//`, `;params`, overlong UTF-8, backslashes | routes match a normalized form, computed once: unreserved escapes decoded (`/%61dmin` is `/admin`), `//` one `/`, a segment's `;params` left out as servlet containers do (`/admin;x/y` is `/admin/y`); refused (400): `.` and `..` segments raw, escaped or behind a parameter (`..;`), escaped `/`, `\` or control bytes, a raw `\`, bad escapes, overlong UTF-8 (`%C0%AE`). The target is forwarded as the client sent it |
| Percent-encoding case (`%2f` vs `%2F`) | normalised to upper case for matching; `%25` stays a `%` (a backend that decodes twice is its own bug) |
| Unicode paths | escaped, matched as escaped (upper-case hex); raw bytes above 0x7F are not allowed in a target; overlong forms refused, other invalid UTF-8 (`%FF`, old Latin-1 links) passed on |
| Trailing slash | `/a` and `/a/` are different unless `slash redirect` or `slash ignore` |
| Query string with repeated keys, empty values, no `=` | kept as sent; matchers define first/any semantics |
| `Host` with port, upper case, trailing dot | normalised for matching (lower case, port stripped, trailing dot removed); a port over 65535, `::`, raw UTF-8 or a list is 400 |
| `Host` missing or several | 400 |
| Unknown host | the listener's routes outside any `host` block, or 404; never another host's routes. `*.example.com` takes any depth below it, not `example.com` itself |
| Two routes that match the same request | load-time error |
| Very large route tables (thousands of hosts/paths) | compiled tries; lookup cost independent of rule count |

## HTTP/2

| Case | Behaviour |
|---|---|
| Rapid reset, CONTINUATION flood, HPACK bomb, SETTINGS/PING/PRIORITY floods, zero window, empty DATA frames | cost model per connection, GOAWAY and close |
| A request head larger than okena takes (16 KiB decoded, 128 fields) | that stream's alone: 431 (and RST_STREAM NO_ERROR when a body was to follow); the block is decoded to its end so the HPACK table stays the client's, and the connection goes on. A compressed block past 16 KiB, or insertions that would copy more than 256 KiB past that point, is GOAWAY ENHANCE_YOUR_CALM |
| Pseudo-headers missing, duplicated, after regular headers, uppercase header names | stream error PROTOCOL_ERROR |
| `Connection`-specific headers in h2 | stream error |
| `TE` other than `trailers` | stream error |
| Content-Length disagreeing with DATA frames | stream error |
| Cookie split into several fields | joined with `; ` towards h1 |
| Stream ID exhaustion, `GOAWAY` from upstream | new connection, in-flight streams below the last ID retried when safe |
| h2c upgrade from h1 | supported only when configured; prior-knowledge h2c on a listener |
| Extended CONNECT (WebSocket over h2) | supported, translated to h1 Upgrade towards backends that need it |

## HTTP/3 and QUIC

| Case | Behaviour |
|---|---|
| Client address migration, NAT rebinding | the kernel steers each packet to the worker its connection ID names (classic BPF on the reuseport group: the ID's first byte), so a moved client still reaches its connection; the client followed to its new address (the newest packet decides), the path validated with PATH_CHALLENGE, 3x limit until it is; a new IP restarts congestion control and the RTT. Active migration (new connection IDs) not offered yet |
| Key update | followed (RFC 9001 6): the next keys tried when the key phase flips, ours updated with them |
| Session resumption over QUIC | a ticket at 1-RTT after the handshake; a ticket of ours resumes |
| 0-RTT | off unless `early_data on`; then a ticket's age within 11 s, only GET/HEAD/OPTIONS in early data (replayable: `Early-Data: 1` to the backend), anything else REQUEST_REJECTED |
| QPACK | a dynamic table of 2048 bytes for the client's inserts, no blocked streams; a reference outside it is QPACK_DECOMPRESSION_FAILED, a bad instruction QPACK_ENCODER_STREAM_ERROR; responses use the static table |
| Rapid reset over HTTP/3 | more than 200 requests a second cancelled by the client (STOP_SENDING, RESET_STREAM): CONNECTION_CLOSE H3_EXCESSIVE_LOAD |
| Slowloris over HTTP/3 (a request head that never ends, the connection kept alive with PINGs) | `timeout { header }` per stream: RESET_STREAM H3_REQUEST_INCOMPLETE; a stalled body: `body_idle`, 408 |
| HEADERS frames split across packets on several streams at once | one gathered at a time, the others' bytes wait with the data held ahead of a gap and go on when it is done; refused (H3_REQUEST_REJECTED) only when that room is full |
| ACK of a packet never sent (optimistic ACK) over QUIC | CONNECTION_CLOSE PROTOCOL_VIOLATION; ranges below the 128 packets remembered cost their parsing only |
| CRYPTO frames after the handshake | their bounds checked, their bytes ignored: nothing kept, nothing sent but the ACK any packet gets |
| PATH_CHALLENGE from another address, to reflect traffic at a third party | answered at 3x its datagram at most, nothing when that cannot carry it, 16 answers a second a connection; the rest dropped |
| ECN | our datagrams ECT(0); the marks received counted per space and reported in ACK_ECN. Marks stop on a connection whose client acknowledges data without counts; a rise in the CE count is a congestion event |
| The client's hello again before the handshake is done | our Initial and Handshake data go again at once, not at the probe timer |
| Amplification | 3x limit before address validation; Retry under load (64 unvalidated connections a worker) or always (`http3 retry`) |
| Version negotiation, QUIC v2 | supported: Version Negotiation for unknown versions; a v1 client whose version_information offers v2 stays in v1 unless `http3 v2` moves it (compatible version negotiation, RFC 9368) |
| 1-RTT packets before the client's Finished | dropped unacknowledged (they come again once the handshake completes) |
| Out-of-order stream data | held (up to 64 pieces a connection) and acknowledged, delivered when the gap fills |
| UDP blocked or throttled by the network | clients fall back to TCP; `Alt-Svc` not sent if h3 failed recently for that listener |
| Stateless reset | supported, tokens derived per instance (shareable across a fleet) |

## WebSocket, streaming, long-lived

| Case | Behaviour |
|---|---|
| WebSocket over h1, h2, h3 | all supported, any combination with the backend |
| Idle WebSocket | own idle timeout (`websocket idle=`), ping not injected unless configured |
| Server-Sent Events, long polling, streamed LLM responses | no buffering, flush per write, no total timeout unless set |
| gRPC streaming, deadlines (`grpc-timeout`) | honoured as the request timeout when shorter; trailers carried |
| Graceful drain with long-lived connections | new connections stop, h2 `GOAWAY`, WebSocket closed with 1001 after `drain_timeout` |
| Large uploads on slow networks | `limits { body_size }` per listener (413 before the backend for a `Content-Length` past it, counted as it goes for chunked), body progress deadline (`body_idle`, 408) instead of a short total deadline |

## Load balancing and backends

| Case | Behaviour |
|---|---|
| All backends down | panic mode for health (try them anyway), `hold` while a pool is restarting; then 503 with `Retry-After: 1` when health says every server is down, 502 when a server refused by itself |
| Flapping backend | health hysteresis (rise/fall counts), slow start |
| One slow backend | `peak-ewma`, outlier ejection, hedging |
| New backend added under load | slow start, connection rate limit |
| Backend with a connection limit (databases) | pool `max` per instance through leases |
| Primary/replica databases | role-aware health checks; separate pools for writes and reads |
| Sticky sessions after a backend leaves | consistent hashing moves only that backend's keys; cookie stickiness falls back to the hash |
| Weight 0 / drain | no new requests, existing connections finish |
| Retry storms | retry budget; no retry on non-idempotent methods unless allowed |
| Backends on the same host as okena | Unix sockets as backends (`server unix:/run/app.sock`) |

## Client identity and headers

| Case | Behaviour |
|---|---|
| Spoofed `X-Forwarded-For` | ignored unless the peer is in `trusted_proxies`; rightmost untrusted address is the client (ports, brackets, IPv4-mapped, several lines; an entry that is not an address stops the walk) |
| Spoofed `X-Real-IP`, `True-Client-IP`, `CF-Connecting-IP` | dropped unless the peer is trusted: a backend that reads them would take the client's word for its address |
| Behind a CDN | provider ranges loaded and refreshed; provider header trusted only from them |
| `Forwarded` vs `X-Forwarded-*` | `X-Forwarded-*` read and written; `Forwarded` passed on from a trusted peer, dropped from others (the client is taken from `X-Forwarded-For`) |
| IPv6 addresses in logs, `${client.ip}`, the PROXY protocol | RFC 5952's form (`2001:db8::1`) |
| Request IDs from clients | kept if valid and trusted, otherwise replaced; always in logs |
| Trace context | W3C `traceparent` propagated or started |
| Header injection through rewrites using client values | values validated (no CR/LF/NUL) before writing |

## Caching

| Case | Behaviour |
|---|---|
| `Set-Cookie` on a cacheable response | not cached unless the route says the cookie is safe to drop |
| `Authorization` on the request | not cached unless `Cache-Control: public` or route says so |
| `Vary: *`, `Vary` on high-cardinality headers | not cached / normalised variants only |
| Cache poisoning through unkeyed headers (`X-Forwarded-Host`, `X-Original-URL`) | such headers stripped before reaching the origin unless keyed |
| Thundering herd on expiry | request collapsing, `stale-while-revalidate` |
| Origin down | `stale-if-error` |
| Range on an uncached large object | slice fetching; first slice served while the rest fills |
| Purge across a fleet | admin API fan-out by URL, prefix or tag |

## Operations

| Case | Behaviour |
|---|---|
| Invalid config on reload | rejected, running config kept, error with line:column |
| Reload during heavy traffic | no dropped connections; old generations freed as connections finish |
| Binary upgrade | listeners handed over, old workers drain |
| Worker crash | only its connections lost; queued connections wait for the replacement |
| Worker hung (infinite loop) | heartbeat watchdog kills and replaces it after 2 s |
| The same request crashes workers repeatedly | fingerprint quarantined after two crashes, 400 for an hour, alert |
| Parser bug in the configuration | compiler child dies, supervisor and running config unaffected |
| Control process crash | workers keep last backend sets, keys and health; restarted |
| DNS returns nothing or fails | last addresses kept (stale), pool never emptied by DNS |
| JWKS endpoint down | cached keys valid for `stale`; new key IDs retried with backoff |
| Invalid configuration at startup | `last_good` starts the last configuration that compiled |
| Disk cache I/O errors | cache bypassed, requests go to origin |
| Supervisor crash | systemd socket activation / restart policy; sockets outlive it |
| Disk full (cache, logs) | cache stops admitting, logs drop and count, traffic unaffected |
| Clock jumps (NTP step, VM migration) | monotonic clock for deadlines; wall clock only for `Date`, logs, certificates and JWT `exp` (with leeway) |
| Running out of file descriptors | limit checked at start against `limits connections`, 503 before `EMFILE` |
| Container limits | cgroup CPU and memory respected, epoll engine where io_uring is blocked |
| Leap seconds, DST | irrelevant to monotonic time; logs in UTC |
