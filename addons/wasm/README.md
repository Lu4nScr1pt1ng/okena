# wasm-okena

[proxy-wasm](https://github.com/proxy-wasm/spec) plugins, the ABI Envoy,
nginx and Traefik run, as an okena addon. The plugins run on
[wazero](https://wazero.io) (pure Go, no cgo) in a process of their own, like
every addon: a plugin that crashes or hangs costs its routes their
`on_error`, nothing else.

```sh
cd addons/wasm && go build -o /usr/local/bin/wasm-okena .
```

```nginx
addon auth {
    run /usr/local/bin/wasm-okena -plugin /etc/okena/auth.wasm -config @/etc/okena/auth.json -cluster authz=10.0.0.5:8080
    timeout 100ms
}
route /api/* { addon auth; to pool api }
```

For each request the plugin's HTTP context gets `proxy_on_request_headers`
with the headers as Envoy gives them: lowercase names, plus `:method`,
`:path`, `:authority` and `:scheme`. What it changes goes back to okena: a
changed `:path` is the request's new target, `:authority` its Host, the other
fields set, added or removed. `proxy_send_local_response` is okena's answer
to the client. A plugin that pauses after `proxy_http_call` gets the answer
(the call is made from this process, to the cluster's address) and continues
or answers then.

| Flag | |
|---|---|
| `-plugin FILE` | the `.wasm` |
| `-config TEXT` | the plugin's configuration (`@FILE` reads a file) |
| `-vm-config TEXT` | the VM's configuration |
| `-root-id NAME` | the root context's id |
| `-name NAME` | the plugin's name (default: the addon's) |
| `-cluster NAME=HOST:PORT` | an upstream for `proxy_http_call` (repeatable); a cluster named `HOST:PORT` needs none |
| `-instances N` | plugin instances, requests at once (default: the CPUs) |
| `-log-level N` | `proxy_log`'s least level shown, 0 trace to 5 critical (default 2) |
| `-cache DIR` | compiled plugins are kept there (default `~/.cache/okena-wasm`; `""` none): a restart does not compile again |
| `-compile` | compile the plugin into the cache, then exit: run it when deploying, and the addon is ready at once |

A large plugin takes seconds to compile to machine code (a 2.6 MB plugin on
the Go SDK: about one second of a core); okena waits up to 5 s for an addon
to be ready, then serves its routes by `on_error` until it is.

**ABI.** 0.2.1, and 0.1.0's names (`proxy_continue_request`...). Logging,
time, ticks (`proxy_on_tick`), plugin and VM configuration, header maps,
properties (`request.path`, `request.url_path`, `request.query`,
`request.host`, `request.scheme`, `request.method`, `request.protocol`,
`source.address`, `plugin_name`, `plugin_root_id`, and what the plugin set),
local responses, HTTP callouts, shared data with CAS across the instances,
metrics (kept, not exported). gRPC callouts, shared queues and foreign
functions answer `Unimplemented`, as does any import the host does not
know: every plugin loads. Tested with plugins on the Go SDK
(github.com/proxy-wasm/proxy-wasm-go-sdk) and the Rust SDK (the
`proxy-wasm` crate).

With the addon's `phases request_body`, the plugin's `proxy_on_request_body`
gets the body (its first `body` bytes; `end_of_stream` false when there was
more) through `HttpRequestBody`; changing it is not supported. Responses are
not given to plugins yet.
