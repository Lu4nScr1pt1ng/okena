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
| HTTP/1.1 | **151,974** | 100,434 | 97,071 | 35,352 | 36,118 | 27,799 |
| HTTPS, TLS 1.3 | **152,437** | 82,825 | 73,579 | 33,380 | 32,673 | 24,442 |
| HTTP/2 | **241,365** | 104,350 | 73,102 | 40,448 | 24,527 | 20,837 |
| gRPC unary calls | **155,925** | 55,450 | 34,959 | 51,396 | 19,728 | 19,438 |
| HTTP/3 | **192,004** | 132,061 | 101,657 | | | |
| JWT-authenticated requests | **103,084** | 23,498 | | 26,319 | | |

And the latency that comes with it, HTTP/1.1 at 30,000 requests a second, p99:

| okena | HAProxy | nginx | Envoy | Traefik | Caddy |
|---|---|---|---|---|---|
| **49 µs** | 73 µs | 100 µs | 1.0 ms | 21 ms | 310 ms |

More of it, with the method and the cases where okena is *not* first:
[docs/BENCHMARK.md](docs/BENCHMARK.md). In short:

* **L4:** 102.1 Gbit/s of TCP bulk transfer on two cores, against Envoy's
  39.1 and HAProxy's 20.7.
* **Large responses:** 1 MB bodies at 78.9 Gbit/s, against Envoy's 34.0 and
  HAProxy's 26.3.
* **XDP:** 2.30 M packets a second on one core, against Katran's 2.13 M.
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

**API gateway.** JWT (ES256, RS256/384/512, PS256/384/512, EdDSA, HS256, keys from JWKS
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

okena runs on Linux (6.1 or later) on x86-64. io_uring is used when the
kernel allows it, epoll otherwise. Releases are on the
[releases page](https://github.com/Lu4nScr1pt1ng/okena/releases).

**Install the binary.** One static file, checked against its published
SHA-256, into `/usr/local/bin`, with an example configuration in
`/etc/okena/okena.conf` when there is none:

```sh
curl -fsSL https://raw.githubusercontent.com/Lu4nScr1pt1ng/okena/main/scripts/install.sh | sh
okena tcp :5432 to 10.0.0.11:5432 10.0.0.12:5432     # or: okena -c /etc/okena/okena.conf
```

Add `-s -- --systemd` after `sh` to install and enable the systemd service
too. Or download `okena-VERSION-linux-x86_64.tar.gz` from the release by hand:
it holds the binary, the examples, the systemd units and the seccomp profile.

**Or run the container.** The image is `FROM scratch`, about 1 MB, and runs as
a non-root user. With no configuration it serves a page on :8080 that says it
runs:

```sh
docker run -p 8080:8080 ghcr.io/lu4nscr1pt1ng/okena
docker run --network host -v ./okena.conf:/etc/okena/okena.conf:ro \
    --security-opt seccomp=okena.seccomp.json ghcr.io/lu4nscr1pt1ng/okena
```

The seccomp profile (in the release archive, and `docker/okena.seccomp.json`
here) is Docker's default plus io_uring; without it okena runs on epoll. Ports
below 1024 with host networking need an extra step, described in
[CONFIG.md](docs/CONFIG.md#docker). On Kubernetes, the Helm chart in
[contrib/helm/okena](contrib/helm/okena) installs it as the Ingress controller.

**Or build from source.** The Makefile downloads the pinned fasm2 assembler
the first time; the result is the same binary as the release's:

```sh
git clone https://github.com/Lu4nScr1pt1ng/okena
cd okena
make                              # build/okena
sudo make install                 # /usr/local/bin/okena, /etc/okena/okena.conf
```

[examples/](examples) has configurations to start from: a reverse proxy,
automatic HTTPS, a static site with an API, an API gateway, TCP and UDP, and a
forward proxy.

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
okena reload               # apply changes without dropping a connection (with `admin unix:PATH`;
                           # a SIGHUP, or systemctl reload okena, does it too)
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

okena 0.1.0 is its first release. It is not yet used widely in production,
and until 1.0 the configuration language may still change between minor
versions; [CHANGELOG.md](CHANGELOG.md) says what changes and what to write
instead.

## License

[GNU Affero General Public License v3.0 only](LICENSE) (`AGPL-3.0-only`).
If you run a modified okena as a network service, you must offer its source to
the users of that service.
