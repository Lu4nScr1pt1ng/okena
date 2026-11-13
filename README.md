# okena

**A load balancer, reverse proxy and API gateway for Linux, written in x86-64
assembly.** One static binary of about 850 KB, no libc, no dependencies. It
handles TCP, UDP, HTTP/1.1, HTTP/2, HTTP/3, gRPC and WebSocket, terminates TLS
with its own TLS 1.3 and 1.2, and can balance packets in the kernel with XDP.

```nginx
http :443 {
    tls { auto }                          # certificates from Let's Encrypt, renewed by okena
    host example.com {
        route /api/* { to 10.0.0.11:8080 10.0.0.12:8080 }
        route /*     { files /srv/site }
    }
}
```

## Performance

Two cores per proxy, the same machine, the same backend, each competitor
tuned by its own documentation. Requests per second, higher is better:

| | okena | HAProxy 3.2 | nginx 1.27 | Envoy 1.40 | Traefik 3.5 | Caddy 2.10 |
|---|---|---|---|---|---|---|
| HTTP/1.1 | **150,665** | 103,830 | 81,737 | 35,444 | 33,106 | 25,526 |
| HTTPS, TLS 1.3 | **142,775** | 77,865 | 73,544 | 30,826 | 30,386 | 23,848 |
| HTTP/2 | **193,296** | 97,235 | 71,363 | 38,764 | 24,210 | 20,405 |
| gRPC unary calls | **142,485** | 55,627 | 35,051 | 49,540 | 19,008 | 18,459 |
| HTTP/3 | **191,921** | 124,976 | 95,290 | | | |
| JWT-authenticated requests | **98,258** | 23,280 | | 24,608 | | |

And the latency that comes with it, HTTP/1.1 at 30,000 requests a second, p99:

| okena | HAProxy | nginx | Envoy | Traefik | Caddy |
|---|---|---|---|---|---|
| **52 µs** | 115 µs | 376 µs | 1.5 ms | 20 ms | 654 ms |

More of it, with the method and the cases where okena is *not* first:
[docs/BENCHMARK.md](docs/BENCHMARK.md). In short:

* **L4:** 95.2 Gbit/s of TCP bulk transfer on two cores, against Envoy's
  42.1 and HAProxy's 20.7.
* **Large responses:** 1 MB bodies at 76.6 Gbit/s, against Envoy's 33.3 and
  HAProxy's 26.0.
* **XDP:** 2.26 M packets a second on one core, against Katran's 2.05 M.
* **Memory:** 100,000 idle keep-alive connections in 73 MiB, against
  HAProxy's 184 MiB and nginx's 896 MiB.
* **Crypto:** faster than OpenSSL 3.5 at every primitive measured: Ed25519,
  ML-KEM-768, ECDSA signing, AES-GCM, X25519 and ChaCha20-Poly1305.

Why it's fast: one worker per core with no locks on the request path,
io_uring (or epoll where io_uring is blocked), configuration compiled into
lookup tables before the first request, memory reserved up front and touched
only as it is used, and no garbage collector or runtime between the kernel and
the code.

## What it does

**Load balancing.** Least-request (power of two choices, the default),
peak-EWMA, round-robin, least-connections, random, Maglev, ring hash, and
source hash, with weights, backups, slow start and bounded loads. Active
health checks (TCP, HTTP, gRPC), passive outlier ejection, retry budgets,
adaptive concurrency limits, sticky sessions.

**Reverse proxy.** HTTP/1.1, HTTP/2 and HTTP/3 to clients; HTTP/1.1, HTTP/2
and FastCGI to backends. Routing by host, path, regular expression, method,
header, query, cookie, client address or country. Header and path rewrites,
redirects, static files with zero-copy sendfile, PHP-FPM, WebSocket, gRPC and
gRPC-Web, compression (gzip, Brotli).

**API gateway.** JWT (ES256, RS256, PS256, EdDSA, HS256, keys from JWKS
URLs), API keys, Basic, mTLS and forward auth; rate limits and quotas per
client, key, user or token claim; CORS; idempotency keys; signed URLs;
traffic splitting, mirroring, hedged requests and fault injection.

**TLS.** TLS 1.3 and 1.2 in okena itself, post-quantum key exchange
(X25519MLKEM768), automatic certificates over ACME (HTTP-01, TLS-ALPN-01,
DNS-01 with Cloudflare, Route 53 or RFC 2136), OCSP stapling, Encrypted
Client Hello, SNI routing without decrypting, kTLS.

**Caching.** In memory and on disk, shared by every worker and process,
stale-while-revalidate, stale-if-error, range slicing for video, purge by
URL, prefix or tag across a fleet.

**L4 and the edge.** TCP and UDP proxying, PROXY protocol, XDP balancing with
direct server return, an XDP packet filter (drop lists, SYN rate per
source), VRRP, anycast through BIRD.

**Operations.** Reloads and binary upgrades without dropping a connection,
service discovery (DNS, SRV, files, Docker, Kubernetes, Consul), the
Kubernetes Gateway API, Prometheus metrics, a live dashboard, JSON access
logs to files, syslog or OpenTelemetry, OpenTelemetry tracing, alerts to
webhooks, Slack and Telegram, systemd notify and socket activation.

**Safety.** Every kind of process under its own seccomp filter (no `execve`,
no executable memory), privileges dropped for everything that touches the
network, Landlock around static files, strict HTTP parsing, a watchdog, and a
quarantine for requests that crash a worker.

## Getting started

okena needs Linux on x86-64. io_uring is used when the kernel allows it,
epoll otherwise.

**Build from source.** The Makefile downloads the fasm2 assembler the first
time:

```sh
git clone https://github.com/Lu4nScr1pt1ng/okena
cd okena
make                              # build/okena
build/okena tcp :5432 to 10.0.0.11:5432 10.0.0.12:5432
```

**Or with Docker.** The image is `FROM scratch`, under 1 MB, and runs as a
non-root user:

```sh
docker build -t okena .
docker run --network host -v ./okena.conf:/etc/okena/okena.conf:ro \
    --security-opt seccomp=docker/okena.seccomp.json okena
```

The seccomp profile is Docker's default plus io_uring; without it okena runs
on epoll. Ports below 1024 with host networking need an extra step, described
in [CONFIG.md](docs/CONFIG.md#docker).

**A configuration file.** okena reads `/etc/okena/okena.conf`, or `-c FILE`:

```nginx
pool api {
    server 10.0.1.10:8080
    server 10.0.1.11:8080
    health http GET /healthz
}

http :443 {
    tls { auto }
    http2 on
    host api.example.com {
        route /v1/* {
            limit 100/s key=client.ip
            to pool api
        }
    }
}
```

```sh
okena check okena.conf     # validate, with errors that point at the line
okena explain okena.conf   # the main settings, with every default filled in
okena -c okena.conf        # run
okena reload               # apply changes without dropping a connection
```

## Documentation

* [Configuration](docs/CONFIG.md): the language, every directive, recipes.
* [Benchmarks](docs/BENCHMARK.md): every number, its method, how to rerun it.
* [Architecture](docs/ARCHITECTURE.md): how okena is built and why.
* [Edge cases](docs/EDGE_CASES.md): what okena does where proxies often break.
* [Roadmap](docs/ROADMAP.md): what is done and what comes next.

## Development

```sh
make                 # build/okena
make test            # every test suite, each in its own network namespace (~40 s)
make test-serial     # the same, one at a time, with all output
make docker-test     # the image under both seccomp profiles
```

The tests include known-answer vectors for every cryptographic primitive
(Wycheproof among them), h2spec, the QUIC interop runner, and a fuzzer for the
configuration language.

## Status

okena is young: version 0.0.1, not yet used widely in production, and the
configuration language may still change between versions.

## License

[GNU Affero General Public License v3.0 only](LICENSE) (`AGPL-3.0-only`).
If you run a modified okena as a network service, you must offer its source to
the users of that service.
