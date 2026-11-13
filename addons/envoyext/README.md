# ext-okena

Envoy's external authorization (`ext_authz`) and external processing
(`ext_proc`) gRPC APIs, for okena: services written for Envoy decide okena's
requests unchanged.

```sh
cd addons/envoyext && go build -o /usr/local/bin/ext-okena .
```

```nginx
addon authz {
    run /usr/local/bin/ext-okena -authz 10.0.0.7:9001
    timeout 200ms
    on_error deny            # Envoy's failure_mode_allow: false; allow is true
}
route /api/* { addon authz; to pool api }
```

**`-authz HOST:PORT`** (`envoy.service.auth.v3.Authorization/Check`). Each
request is a `CheckRequest`: method, path, host, scheme, protocol, query, the
headers (lowercase, with `:method`, `:path`, `:authority` and `:scheme`, as
Envoy sends them), the client's address, and `-context KEY=VALUE` as
`context_extensions`. OK lets the request on with `ok_response`'s headers set
(or added, with `append`), `headers_to_remove` removed and
`query_parameters_to_set` / `_to_remove` applied; a denial is okena's answer
with `denied_response`'s status (403 unless given), headers and body.

**`-proc HOST:PORT`** (`envoy.service.ext_proc.v3.ExternalProcessor/Process`).
Each request opens a stream and sends its `request_headers`; the answer's
header mutation is applied (a `:path` is the request's new target, routed
again; `:authority` its Host) or its `immediate_response` answers the
client.

With both, `ext_authz` is asked first. A service that cannot be reached or
fails (`-timeout`, default 5 s, or the addon's own timeout first) makes okena
apply `on_error` at once, and counts toward the addon's circuit breaker.

| Flag | |
|---|---|
| `-authz HOST:PORT` | an ext_authz service |
| `-proc HOST:PORT` | an ext_proc service |
| `-tls`, `-ca FILE` | speak TLS to them (the system's CAs, or this one) |
| `-timeout D` | a call's time (default 5s) |
| `-context KEY=VALUE` | `context_extensions` for ext_authz (repeatable) |
| `-workers N` | requests asked about at once (default 256) |

**Bodies and responses.** With the addon's `phases request_body`,
`-authz-body` sends the body (`with_request_body`: `raw_body`, `body`) and
`-proc-body` sends ext_proc a `request_body` after the headers. With
`response_headers` or `response_body`, the request's ext_proc stream stays
open and gets `response_headers` (and, with `-proc-body`, a counted
`response_body` up to `body`): their header mutations change the response,
an `immediate_response` replaces it. A stream whose response never comes is
closed after a minute.
