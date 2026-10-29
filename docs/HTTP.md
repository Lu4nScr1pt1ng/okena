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

| Phase | Default | On expiry |
|---|---|---|
| request head | 10 s | 408, close |
| request body progress | 30 s between bytes | close |
| connect | pool `connect timeout` | next server, or 502/503 |
| response head | route `timeout try=` (30 s) | 504 |
| response body progress | 60 s between bytes | close both |
| idle keep-alive | 60 s | close |

Errors produced by okena are short, plain bodies with a request id, and
always `Connection: close` when the framing of the connection is in
doubt.

## What comes after

WebSocket and other upgrades (the session becomes an L4 tunnel after the
101), retries with budgets, outlier detection on 5xx, access logs, HTTP/2
(phase 4), then the gateway filters of phase 5 on the same exchange
structure.
