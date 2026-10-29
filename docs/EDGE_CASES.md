# Edge cases

What okena does in the situations that break proxies. Each line is a
behaviour to implement and a test to keep. "Reject" means a 4xx/5xx with
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
| MTU/PMTU black holes | `TCP_MSS` clamp option; QUIC packet size probing |
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
| ClientHello split across several TCP segments / records | buffered up to a limit before routing (`tls` mode and termination) |
| Large post-quantum ClientHello (ML-KEM shares) | supported; bugs in middleboxes that drop big ClientHellos are the client's, but okena never needs a second round trip for it |
| HelloRetryRequest | supported for groups okena prefers |
| TLS 1.2-only clients and backends | ECDHE + AEAD; RSA key exchange and CBC never |
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
| HTTP/1.0 without `Host`, with keep-alive | accepted, `Host` from the listener's default; `Connection: keep-alive` honoured |
| HTTP/0.9 | rejected |
| Absolute-form target (`GET http://host/ HTTP/1.1`) | host taken from the target as RFC 9112 says, must agree with `Host` |
| `CONNECT` | 405 unless a route allows tunnelling (forward proxy is opt-in) |
| `TRACE` | 405 by default |
| Request line or headers too large | 414 / 431 |
| Too many headers | 431 |
| Huge cookies (many `Cookie` lines) | combined per RFC, size-limited |
| `Expect: 100-continue` | forwarded or answered by okena when the body would be rejected anyway (size, auth) |
| Pipelined requests | answered in order; a request with an error closes after earlier responses are sent |
| Request body on GET/DELETE | forwarded as framed; never assumed empty |
| Upgrade on a request with a body | reject |
| `Connection` naming other headers | those headers removed as hop-by-hop |

## Upstream responses

| Case | Behaviour |
|---|---|
| Malformed response (bad framing, invalid headers) | 502, upstream connection closed |
| Response to `HEAD`, 204, 304 with a body or `Content-Length` | no body forwarded; connection to the backend closed if it sent one anyway |
| Response delimited by connection close | supported; converted to chunked or DATA frames for the client |
| Several 1xx before the final response | forwarded (103 Early Hints included) or dropped per route |
| Response before the request body was fully sent | request body stopped, response forwarded, upstream connection not reused |
| Backend closes a reused keep-alive connection | retry once on a new connection if no response byte arrived and the request is safe to repeat |
| `Content-Length` shorter or longer than the body | 502 if detected before the response started; connection reset to the client after, so it cannot cache a truncated body |
| Upstream sends `Transfer-Encoding` and `Content-Length` | treated as invalid, 502 |
| Huge response headers | limit, 502 |
| Backend sets hop-by-hop headers or `Upgrade` without being asked | stripped |
| `Set-Cookie` with multiple values | never folded with commas |

## Paths, hosts and routing

| Case | Behaviour |
|---|---|
| Dot segments, `%2e%2e`, `%2F`, `//`, `;params`, overlong UTF-8, backslashes | normalised once, unsafe forms rejected, `path forward=normalized|original` |
| Percent-encoding case (`%2f` vs `%2F`) | normalised to upper case for matching |
| Unicode paths | matched as UTF-8 bytes after percent-decoding; invalid UTF-8 rejected unless the route allows raw bytes |
| Trailing slash | `/a` and `/a/` are different unless `slash redirect` or `slash ignore` |
| Query string with repeated keys, empty values, no `=` | kept as sent; matchers define first/any semantics |
| `Host` with port, upper case, trailing dot | normalised for matching (lower case, port stripped by listener, trailing dot removed) |
| `Host` missing or several | 400 |
| Unknown host | listener's `default` route, or 421/404, never the first route by accident |
| Two routes that match the same request | load-time error |
| Very large route tables (thousands of hosts/paths) | compiled tries; lookup cost independent of rule count |

## HTTP/2

| Case | Behaviour |
|---|---|
| Rapid reset, CONTINUATION flood, HPACK bomb, SETTINGS/PING/PRIORITY floods, zero window, empty DATA frames | cost model per connection, GOAWAY and close |
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
| Client address migration, NAT rebinding | connection ID routing to the owning worker; path validation |
| Amplification | 3x limit before address validation; Retry under load |
| Version negotiation, QUIC v2 | supported |
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
| Large uploads on slow networks | per-route body size, body progress deadline instead of a short total deadline |

## Load balancing and backends

| Case | Behaviour |
|---|---|
| All backends down | panic mode for health (try them anyway), `hold` while a pool is restarting, then 503 with `Retry-After` |
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
| Spoofed `X-Forwarded-For` | ignored unless the peer is in `trusted_proxies`; rightmost untrusted address is the client |
| Behind a CDN | provider ranges loaded and refreshed; provider header trusted only from them |
| `Forwarded` vs `X-Forwarded-*` | both supported, one canonical set written upstream |
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
| Disk full (cache, logs) | cache stops admitting, logs drop and count, traffic unaffected |
| Clock jumps (NTP step, VM migration) | monotonic clock for deadlines; wall clock only for `Date`, logs, certificates and JWT `exp` (with leeway) |
| Running out of file descriptors | limit checked at start against `limits connections`, 503 before `EMFILE` |
| Container limits | cgroup CPU and memory respected, epoll engine where io_uring is blocked |
| Leap seconds, DST | irrelevant to monotonic time; logs in UTC |
