# Changelog

okena follows [semantic versioning](https://semver.org). Until 1.0 the
configuration language may still change between minor versions; each change
is listed here, with what to write instead.

## 0.1.0 — 2026-11-19

The first release: one static binary of about 1 MB for Linux on x86-64, no
libc and no dependencies, and a container image built `FROM scratch`.

### Install

```sh
curl -fsSL https://raw.githubusercontent.com/Lu4nScr1pt1ng/okena/v0.1.0/scripts/install.sh | sh
docker run -p 8080:8080 ghcr.io/lu4nscr1pt1ng/okena:0.1.0
```

Or download `okena-0.1.0-linux-x86_64.tar.gz` below and check it against its
`.sha256`. Linux 6.1 or later (6.12 LTS for every feature); io_uring is used
when the kernel allows it, epoll otherwise.

### What it does

- **Load balancing (L4 and L7):** TCP and UDP proxying; least-request (the
  default), peak-EWMA, round-robin, least-connections, random, Maglev, ring
  hash and source hash; weights, backups, slow start, bounded loads;
  zone-aware balancing (`okena { zone }`, endpoints' zones from Kubernetes);
  active health checks (TCP, HTTP, gRPC, UDP, with `send=` and `match=`),
  outlier ejection, retry budgets, adaptive concurrency, sticky sessions;
  PROXY protocol v1/v2 in and out; XDP balancing with direct server return.
- **Reverse proxy:** HTTP/1.1, HTTP/2 and HTTP/3 to clients; HTTP/1.1, HTTP/2
  and FastCGI to backends; routing by host, path, regular expression, method,
  header, query, cookie, client address, country, ASN or TLS fingerprint
  (JA4); rewrites, redirects, static files with sendfile (and directory
  listings with `browse=on`), PHP-FPM, WebSocket, gRPC and gRPC-Web,
  gzip/Brotli/zstd compression, caching in memory and on disk.
- **API gateway:** JWT (ES256/384, RS256/384/512, PS256/384/512, EdDSA,
  HS256; JWKS by URL), API keys, Basic (bcrypt files too), mTLS, forward
  auth with login redirects; rate limits and quotas (per client, key, user
  or claim; shared across a fleet; `RateLimit-*` headers); CORS; idempotency
  keys; signed URLs; traffic splitting, mirroring, hedging, fault injection;
  addons in any language (Python, Go, Rust, C SDKs), proxy-wasm plugins,
  Envoy's ext_authz/ext_proc, a Coraza WAF, OIDC login, gRPC-JSON
  transcoding.
- **Forward proxy:** CONNECT tunnels to the destinations a route lists, with
  `Proxy-Authorization`; private and link-local addresses refused unless
  allowed.
- **TLS:** TLS 1.3 and 1.2 of its own, post-quantum key exchange
  (X25519MLKEM768), automatic certificates over ACME (HTTP-01, TLS-ALPN-01,
  DNS-01 with Cloudflare, Route 53 or RFC 2136), OCSP stapling, Encrypted
  Client Hello, SNI routing without decrypting, kTLS, TLS to backends.
- **Kubernetes:** Gateway API (HTTPRoute, GRPCRoute, TLSRoute, TCPRoute,
  UDPRoute) and Ingress, with ingress-nginx's common annotations (canary,
  auth-url, rewrite-target, ssl-redirect, CORS, limits...); a Helm chart.
- **Operations:** reloads and binary upgrades without dropping a connection;
  routes changed at runtime (CLI and HTTP API); service discovery (DNS, SRV,
  files, Docker, Kubernetes, Consul); Prometheus metrics and metrics pushed
  over OTLP; JSON access logs to files, syslog or OTLP; OpenTelemetry tracing
  (W3C Trace Context and B3); a live dashboard; alerts to webhooks, Slack and
  Telegram; systemd notify and socket activation.
- **Safety:** each kind of process under its own seccomp filter (no
  `execve`, no executable memory), privileges dropped, Landlock around files,
  strict HTTP parsing, a watchdog and a quarantine for requests that crash a
  worker.

See [docs/BENCHMARK.md](docs/BENCHMARK.md) for how it compares with HAProxy,
nginx, Envoy, Traefik and Caddy.
