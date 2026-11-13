# Addons

An addon is a program okena starts, keeps running, and calls at phases of a
request: a WAF rule engine, a bot check, custom business rules, anything that
is not built in. It runs in a process of its own, in any language; it cannot
slow down a route that does not use it, and its crash or hang costs only its
own routes what their `on_error` says.

This page is the addon's side: how to configure one, what it can do, and the
protocol, for writing an SDK. The SDKs in `sdk/` implement it.

## Configuration

```nginx
addon waf {
    run /usr/local/bin/coraza-okena -rules /etc/crs   # absolute path, then its arguments
    phases request_headers       # the default (the only phase so far)
    timeout 50ms                 # a call's time (default 200ms)
    on_error allow               # or deny (the default): 503
    concurrency 1024             # calls waiting at once, the whole instance (default 1024)
    breaker errors=5 open=1s     # failures in a row that open the circuit (the defaults)
    poll 50us                    # the addon polls this long after a call before it sleeps
}

route /api/* {
    addon waf
    to pool api
}
```

A route may name several addons; they are asked one after the other, in the
order they are defined, and each sees the request as the ones before left it.
An addon is asked after the route's `allow`/`deny`, CORS, signed URLs, `auth`
and rate limits: the cheapest refusals come first, and an addon sees who the
client is (`auth` fields are on the request) and never a request a limit
refused.

**Polling.** After a call, an addon on okena's SDKs polls for the next one
for `poll` (default 50 µs) before it sleeps; a call that finds it asleep
pays a wakeup (around 10 µs, more on a core in a deep idle state). Under
steady traffic, or with a `poll` longer than the gaps between calls, an
addon that answers at once adds about 1 µs (p99 2 µs, docs/BENCHMARK.md); it
costs a core while it polls. `OKENA_ADDON_SPIN_US` in the addon's
environment overrides `poll`.

**The process.** okena starts every addon of the configuration before it
serves (waiting up to 5 s for each to say it is ready), as `user` when that is
set, in a process group of its own, with okena's environment plus
`OKENA_ADDON_FD` and `OKENA_ADDON_NAME`. One that exits is started again, 100
ms later, then 200, 400 ... up to 5 s apart (100 ms again after a run of 10
s); its exit is logged. When okena stops, its addons are killed.

**Reloads.** An addon whose name and `run` line are the same keeps its
process across a reload; one whose `run` changed gets a new process, and the
old one is stopped once the workers that knew it are gone. An addon dropped
from the configuration is stopped then too. okena makes its addon launcher
when it starts, so a reload can bring addons only into an okena that started
with at least one; otherwise the reload is rejected and says so (`okena
upgrade` starts okena again with no connection lost).

**Failures.** A call ends without an answer when: the addon says it could
not decide (an SDK's `Fail`: its own service is down, say); the addon does not answer
within `timeout`; its answer is not one (a field name that is not a token, a
value with a control character, a target that is not a path, a status
outside 200-599); the addon exits (its calls end at once, not at their
time); it is not ready (starting, or started again); `concurrency` calls wait
already; or its circuit is open. Then `on_error allow` lets the request go on
unchanged and `on_error deny` answers 503. `breaker errors=N open=T`: after
N calls in a row with no answer in time (or a bad one), a worker stops asking
for T: its calls end at once; after T, one call is let through, and its
answer closes the circuit again. The circuit and the concurrency limit are
each worker's (`concurrency` is split between the workers).

## What an addon can do

An answer is one of:

* **continue**, with changes to the request: fields set (replacing every
  field of that name), added, removed, and the request target (path and
  query) replaced. The head is rewritten before the request goes on, so the
  route's limits, the cache key, the backend, everything after sees the
  changed request; a changed path or Host is routed again. Content-Length,
  Transfer-Encoding, Connection, Keep-Alive, TE, Trailer, Upgrade and
  Proxy-Connection are okena's: changes to them are ignored.
* **respond**: okena answers the client with the addon's status (200-599),
  fields and body (up to about 16 KiB together). okena adds Content-Length
  (none on 204 and 304), the request id, CORS fields when the route has
  `cors`, and `Connection: close` when the request has a body it did not
  read. A HEAD gets the length and no body.

HTTP/1.1, HTTP/2 and HTTP/3 requests all go through the same stage: the addon
always sees an HTTP/1.1 head.

## SDKs and reference addons

| | |
|---|---|
| `sdk/python` | one module, the standard library only |
| `sdk/c` | one C file and its header, libc only |
| `sdk/go` | handlers on several goroutines at once (`Options.Workers`) |
| `sdk/rust` | `std` only |
| `addons/coraza` | a WAF: Coraza with the OWASP Core Rule Set ([README](../addons/coraza/README.md)) |
| `addons/wasm` | proxy-wasm plugins, the ABI Envoy, nginx and Traefik run, on wazero ([README](../addons/wasm/README.md)) |
| `addons/envoyext` | Envoy's `ext_authz` and `ext_proc` gRPC services ([README](../addons/envoyext/README.md)) |

Each SDK has a `hello` example that `tests/gateway/addon.py` runs against
okena; `tests/gateway/waf.py` runs the WAF, `tests/gateway/wasm.py` proxy-wasm
plugins built on the Go and Rust proxy-wasm SDKs, `tests/gateway/envoyext.py`
a gRPC service of both Envoy kinds.

`run`'s words go to the program as they are written, `name=value` ones
included.

## The protocol (version 1)

Everything is in one memfd per addon, which the addon maps whole (its size is
the file's). The addon finds it at the descriptor `OKENA_ADDON_FD` names
(3). All numbers are little-endian; offsets are from the start of the memory.

### Header (page 0)

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic, `OKADDON1` read as a little-endian u64 = `0x314E4F4444414B4F` |
| 8 | 4 | version: 1 |
| 12 | 4 | `nrings`: ring pairs (worker slots) |
| 16 | 4 | `rbytes`: bytes of each ring's data, a power of two (262144) |
| 20 | 4 | `hbytes`: the header page and each ring header's size (4096) |
| 24 | 8 | `stride`: bytes from one ring pair to the next (`2 * (hbytes + rbytes)`) |
| 32 | 4 | the bell's descriptor (4) |
| 36 | 4 | the first worker slot's eventfd (5); slot `i` is `wake0 + i` |
| 40 | 4 | phases okena calls (bit 0: request_headers) |
| 48 | 4 | `ready`: the addon writes 1 once it serves; okena writes 0 at each start |
| 52 | 4 | `epoch`: one more at each start and each exit of the addon (okena's) |
| 56 | 4 | the addon's pid (okena's) |
| 60 | 4 | `sleep`: 1 while the addon may block on the bell (okena then rings it) |
| 64 | 64 | the addon's name, NUL-terminated |
| 128 | 8 | `timeout` in µs (for the addon's information) |
| 136 | 4 | the largest head a call carries |
| 140 | 4 | `poll`: µs the addon should poll after a call before it sleeps (the configuration's) |

### Rings

Ring pair `i` starts at `hbytes + i * stride`:

| Offset in the pair | What |
|---|---|
| 0 | calls ring header: `head` (u64, at 0, okena's), `tail` (u64, at 64, the addon's) |
| `hbytes` | calls data (`rbytes`) |
| `hbytes + rbytes` | answers ring header: `head` (at 0, the addon's), `tail` (at 64, okena's), `awake` (u32 at 128, okena's: 1 while the worker polls for answers) |
| `2 * hbytes + rbytes` | answers data (`rbytes`) |

`head` and `tail` count bytes since the ring was made; they never wrap. A
record starts at `counter mod rbytes`, is a multiple of 8 bytes, and never
wraps: a producer with too little room before the end writes a padding
record (kind 0) to the end first. The producer writes the record, then the
new `head` (on x86, stores are seen in order); the consumer reads `head`,
the records, then writes `tail`. Room is `rbytes - (head - tail)`. A ring
has one producer at a time: a worker slot belongs to one worker process; a
worker that takes over a slot goes on from the counters it finds.

Every record begins with `len` (u32, the record's bytes) and `kind` (u16:
1 a call or an answer, 0 padding).

### A call (okena → addon)

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | len |
| 4 | 2 | kind: 1 |
| 6 | 2 | phase: 1 (request_headers) |
| 8 | 4 | id: echoed in the answer |
| 12 | 4 | flags: 1 TLS, 2 HTTP/2, 4 HTTP/3 |
| 16 | 4 | `hlen`: the head's bytes |
| 20 | 2 | `nhdr`: the fields in the index |
| 22 | 2 | the client's address family: 4, 6, 0 (a Unix socket) |
| 24 | 16 | the client's address (IPv4 in the first 4 bytes); with `trusted_proxies`, the client they name |
| 40 | 2+2 | the method: offset in the head, length |
| 44 | 2+2 | the target: offset, length |
| 48 | 4 | the route's action + 1 |
| 52 | 4 | reserved |
| 56 | 8 each | the index: name offset, name length, value offset, value length (u16 each) |
| 56 + 8 `nhdr` | `hlen` | the head: request line, fields, empty line, as okena would forward it |

### An answer (addon → okena)

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | len |
| 4 | 2 | kind: 1 |
| 6 | 2 | action: 0 continue, 1 respond, 2 fail (it could not decide: on_error at once, a failure for the circuit) |
| 8 | 4 | the call's id |
| 12 | 2 | respond: the status |
| 14 | 2 | `nops` |
| 16 | 4 | respond: the body's length |
| 20 | 4 | reserved |
| 24 | | `nops` ops, then the body |

An op is `op` (u8), 0 (u8), the name's length (u16), the value's length (u16),
then the name and the value, with no padding. Ops: 1 set a field, 2 add one,
3 remove every field of that name (no value), 4 the request target (no name).
For respond, ops 1 and 2 are the response's fields. An answer to a call that
is over (its time passed, or its addon's run ended) is ignored.

### Waking

A worker that posted calls writes 1 to the bell (an eventfd) before it
sleeps, when `sleep` is 1. An addon that polls sets `sleep` to 0 with a
sequentially consistent store, and before blocking sets it to 1 (again
sequentially consistent: an `xchg`), looks at every calls ring once more, and
only then reads the bell. An addon that never polls leaves it at 1 and reads
the bell whenever it has nothing to do (the counter makes a wakeup between
its last look and its read come back at once).

An addon that wrote answers into slot `i` writes 1 to that slot's eventfd
(`wake0 + i`), once a batch, unless the slot's `awake` is 1 (read after a
full fence that follows the new `head`): a worker that just asked an addon
that polls waits for the answer a few microseconds itself, and before it
sleeps sets `awake` to 0 and looks once more. An addon may also always write.

### Starting

Map the memory, check the magic and the version, set `sleep`, then `ready`
to 1. Calls a crashed run left in the rings are dropped by okena before the
next run starts; an addon starts with what it finds.
