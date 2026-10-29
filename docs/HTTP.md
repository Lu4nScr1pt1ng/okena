# HTTP engine (design)

How the `http` listeners of phase 2 move a request from a client to a
backend and the response back. The parser (`src/http/parse.inc`) and the
chunked decoder (`src/http/chunk.inc`) exist and are tested; this is the
data path around them. It follows ARCHITECTURE.md; what is specific to
HTTP is here.

## Shape

An HTTP session is one client connection. It carries a sequence of
exchanges (keep-alive, pipelining); each exchange is one request and one
response:

```
client ─▶ head ─▶ route ─▶ upstream (pooled) ─▶ request head + body ─▶ backend
client ◀─ response head + body ◀─────────────────────────────────────── backend
```

* The session reads the request head into a head buffer. With provided
  buffers a head can arrive split across buffers; while incomplete, its
  bytes are gathered into a 16 KiB head buffer from a pool (returned when
  the head is parsed), so the parser always sees one contiguous head. A
  head larger than `limits { header_size }` is 431.
* The head is parsed strictly. Errors answer with the HTTP status the
  parser gives (400, 431, 501, 505) and `Connection: close`.
* Routing picks a route by host and path (see Routing), then a server of
  the route's pool.
* The request head is written anew: method, the target as parsed, the
  fields that are not hop-by-hop, `Host`, then okena's own: `Forwarded`
  / `X-Forwarded-For` / `X-Forwarded-Proto` / `X-Forwarded-Host`
  (honouring `trusted_proxies`), `X-Request-Id`, and the framing it
  chooses (`Content-Length`, or `Transfer-Encoding: chunked` when the
  length is unknown).
* The body streams: bytes are forwarded as they arrive, through the same
  one-buffer-per-direction backpressure as L4. A chunked body is decoded
  and framed again; a `Content-Length` body is counted to the byte, so
  the next request on the connection starts exactly where it must.
* The response head is parsed as strictly as the request; a malformed
  one is a 502 and the upstream connection is closed. It is rewritten
  the same way (hop-by-hop dropped, framing chosen). Bodies follow the
  rules: none for HEAD, 1xx, 204, 304; `Content-Length`; chunked; or
  until the backend closes (then chunked towards an HTTP/1.1 client).
* 1xx responses (100 Continue, 103 Early Hints) are forwarded before the
  final one.
* When the exchange ends cleanly and both sides allow it, the client
  connection waits for its next request and the upstream connection goes
  back to its pool.

## Upgrades (WebSocket and others)

A request with `Connection: upgrade` and `Upgrade` keeps its `Upgrade`
field and is sent with `Connection: upgrade`. When the backend answers
101, the 101 goes to the client with the same two fields; then the bytes
either side sent behind its head (the backend's first frames, the
client's early data) are delivered, and the session becomes a plain L4
tunnel: the same relay as `tcp` listeners, with its backpressure, idle
timeout and half-close. Its upstream connection never returns to a
pool. Any other answer is an ordinary response and the connection keeps
serving requests; a 101 to a request that did not ask for one is a 502.

## Upstream connection pools

Per worker, per server: a LIFO stack of idle connections (the warmest
first), at most `connect max`, closed after `connect idle`. A request
takes one or opens one. A connection is reused only when its previous
response was framed and fully read, and it did not say `close`.

The reuse race (the backend closing an idle connection just as okena
writes on it) is handled: when a reused connection fails before any
response byte, the request is sent again on a new connection if it is
idempotent or had no body; this does not count against the retry budget.
The pool's idle timeout defaults below the common backend values.

## Retries and outliers

A request that is idempotent (GET, HEAD, PUT, DELETE, OPTIONS) and has
no body is sent once more, to another server when the pool has one, when
the backend answers 502, 503 or 504 or closes before any response byte.
Its head is still in the session's output buffer, so nothing is parsed
again. A per-worker budget stops retries from multiplying an outage: at
most a fifth of the requests, plus 10 per second
(`okena_http_retries_total` counts them). A request with a body is never
sent twice.

Outlier ejection works like the connect failures of L4: a server that
gives 5 failing answers in a row (5xx, or no response head in time) is
left out for 10 s by that worker; any other answer resets its count.
When every server is out, they are all used again (panic), as in L4.

## Routing

Routes are compiled per listener:

1. host: exact names in a hash, then wildcards (`*.example.com`) by
   suffix, then the listener's default routes;
2. path: a radix tree of segments; static segments beat `{param}`, which
   beats a `*` tail; the most specific route wins and ties are a
   configuration error;
3. method set, then (later) header and query predicates.

Paths are matched after normalization (percent-decoding of unreserved
characters, dot segments, duplicate slashes); a path that cannot be
normalized safely is a 400. The target forwarded is the original unless
the route asks for the normalized one (`path forward=normalized`).

## Timeouts and errors

Each listener has its own clocks (`timeout { header; response; idle }`).
A clock is a FIFO list per listener, since all its sessions share one
limit: arming and stopping are O(1) and a tick looks only at what
expires. A session waiting on its backend is not idle; the response
clock owns it.

| Phase | Default | On expiry |
|---|---|---|
| request head (`header`), from the first byte or the connection | 10 s | 408, close; a connection that never sent a byte is closed silently |
| request body progress | 30 s between bytes | close |
| connect | pool `connect timeout` | next server, or 502/503 |
| response head (`response`), from the end of the request | 30 s | 504, close |
| response body progress | 60 s between bytes | close both |
| idle keep-alive | 60 s | close |

Errors produced by okena are short, plain bodies with a request id, and
always `Connection: close` when the framing of the connection is in
doubt.

## What comes after

Access logs, `trusted_proxies`, HTTP/2 (phase 4), then the gateway
filters of phase 5 on the same exchange structure.
