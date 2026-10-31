# okena

L4/L7 load balancer, reverse proxy and API gateway in x86-64 assembly
(fasm2) for Linux. One static binary, no libc.

* [Architecture](docs/ARCHITECTURE.md): how it is built and why.
* [Configuration](docs/CONFIG.md): the `okena.conf` language.
* [Edge cases](docs/EDGE_CASES.md): what okena does where proxies break.
* [Roadmap](docs/ROADMAP.md): phases and exit criteria.
* [Benchmarks](docs/BENCHMARK.md): measurements and comparisons, with how to rerun them.

```
tcp :5432 {
    to 10.0.0.11:5432 10.0.0.12:5432
}

http :80 {
    route /* { to 127.0.0.1:3000 }
}
```

## Status

Early: L4, HTTP/1.1 and TLS (1.3 and 1.2, both ways). What works today:

* HTTP: redirects and header changes per route (`redirect 301 /new/{*}`,
  `header set|add|drop`, `response header ...`), host blocks with wildcards, routes matched on the normalized
  path, WebSocket and other upgrades, header/response timeouts (408/504),
  retries within a per-pool budget, outlier ejection, request ids,
  `trusted_proxies`, JSON access logs through a logger process, metrics
  by status class, idle connections that give their memory back;
* `least-request` (power of two choices) balancing by default, `peak-ewma`
  for latency (a backend that answers slower gets less), and
  `slow_start 30s` in a pool: a server that comes back is given a share
  of traffic that grows smoothly over the window;

* an HTTP/1.1 reverse proxy (`http :8080 { route /api/* { to pool api } }`):
  strict parsing, exact and prefix routes with method filters, heads
  written anew (hop-by-hop fields dropped, X-Forwarded-For from the real
  client), bodies streamed with Content-Length or chunked re-framed,
  keep-alive and pipelining towards clients, keep-alive pools towards
  backends (idle connections watched, so one the backend closed is
  never reused), 100-continue, 502 for unreachable or malformed
  backends;
* the configuration language with `okena check` (compiler-style
  diagnostics), configuration on the command line or in `OKENA_CONFIG`;
* the L4 TCP proxy on io_uring: one worker per CPU (cgroup quota aware),
  dual-stack and IPv6 listeners, IPv4/IPv6/unix backends, round-robin,
  least-conn and random balancing with weights and backups, connect
  timeouts with failover, passive ejection of failing backends, idle
  timeouts, half-close, graceful drain, workers restarted on crash with
  no lost queued connection;
* memory that follows the load: a worker uses under 1 MiB at rest;
* HTTP/2 towards clients (`http2 on`: ALPN h2 and prior knowledge, flow
  control) and towards backends (`protocol h2`: multiplexed connections);
  trailers pass, so gRPC's status reaches the client;
* `okena bench`, an open-loop load generator (HTTP, HTTPS, TCP
  echo) whose latency is corrected for coordinated omission:
  `okena bench https://localhost/ rate=50k conns=64 duration=30s`.

* backends by name (`to app:3000`): /etc/hosts and DNS with search
  domains, A and AAAA, every address of a name used, re-resolved by TTL
  and at once when a connect fails, last known addresses kept when DNS
  fails, names that appear later picked up without a restart;
* active health checks, TCP (`health tcp every=2s timeout=1s rise=2
  fall=3`) or HTTP (`health http GET /healthz expect=200..299`), run
  once per instance by a health process, with passive ejection on top
  and panic mode when every server is down;
* PROXY protocol v1 and v2 towards backends (`proxy_protocol send v2`),
  with the real source and destination, IPv4-mapped addresses
  normalized, and `limits { per_source N }` counted for the whole
  instance;
* `metrics ADDRESS`: Prometheus `/metrics`, `/live`, `/ready` (503 while
  draining) from an admin process, and `okena health` for Docker's
  HEALTHCHECK;
* a watchdog that replaces stuck workers;
* a seccomp filter for each kind of process (no execve, no ptrace, no
  executable memory anywhere; an io_uring worker may make eight system
  calls) and an io_uring opcode allowlist;
* reload on `SIGHUP` without dropping a connection, validated in a child
  process, rejected as a whole when anything is wrong;
* two I/O engines, io_uring and epoll, chosen automatically: where
  io_uring is blocked (Docker's default seccomp profile, Kubernetes,
  gVisor) okena runs on epoll and says why;
* `busy_poll` for the latency profile;
* a `FROM scratch` image of about 70 KB, non-root, aware of `--cpus`
  and `--cpuset-cpus`.

Next: the rest of phase 4 (HTTP/2 to backends, gRPC), then phase 5
(HTTP/3 and QUIC), in [ROADMAP.md](docs/ROADMAP.md).

## Docker

```
docker build -t okena .
docker run --network host okena tcp :5432 to 10.0.0.11:5432 10.0.0.12:5432
```

That runs on the epoll engine under Docker's default seccomp profile.
For io_uring, add `--security-opt seccomp=docker/okena.seccomp.json`
(Docker's default profile plus the three io_uring calls). A
configuration file goes to `/etc/okena/okena.conf`:

```
docker run --network host -v ./okena.conf:/etc/okena/okena.conf:ro okena
```

Use host networking (or disable the daemon's userland proxy) for
performance, and `--cpuset-cpus` rather than `--cpus` for steady
latency.

```
make          # build/okena (constants are `:=`: a name defined twice is a build error)
make test     # every suite at once (~10 s), each in its own network namespace
make test-serial   # the same, one after the other, with all output
python3 tests/run_all.py http l4   # only the suites whose name has a word
make docker-test   # the image under both seccomp profiles
make bench    # added latency of the L4 proxy
build/okena bench http://127.0.0.1:8080/ rate=100k   # open-loop load, any server
```

## License

okena is free software under the GNU Affero General Public License,
version 3 only ([LICENSE](LICENSE), SPDX `AGPL-3.0-only`). Anyone who
runs a modified okena as a network service must offer its source to the
users of that service.
