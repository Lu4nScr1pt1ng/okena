# okena

L4/L7 load balancer, reverse proxy and API gateway in x86-64 assembly
(fasm2) for Linux. One static binary, no libc.

* [Architecture](docs/ARCHITECTURE.md): how it is built and why.
* [Configuration](docs/CONFIG.md): the `okena.conf` language.
* [Edge cases](docs/EDGE_CASES.md): what okena does where proxies break.
* [Roadmap](docs/ROADMAP.md): phases and exit criteria.

```
tcp :5432 {
    to 10.0.0.11:5432 10.0.0.12:5432
}

https example.com {
    to 127.0.0.1:3000
}
```

## Status

Early. What works today:

* the configuration language with `okena check` (compiler-style
  diagnostics), configuration on the command line or in `OKENA_CONFIG`;
* the L4 TCP proxy on io_uring: one worker per CPU (cgroup quota aware),
  dual-stack and IPv6 listeners, IPv4/IPv6/unix backends, round-robin,
  least-conn and random balancing with weights and backups, connect
  timeouts with failover, passive ejection of failing backends, idle
  timeouts, half-close, graceful drain, workers restarted on crash with
  no lost queued connection;
* memory that follows the load: a worker uses under 1 MiB at rest.

Next: the epoll engine, busy polling, the container image and its
seccomp profile, then the rest of phase 0 and 1 in
[ROADMAP.md](docs/ROADMAP.md).

```
make          # build/okena
make test     # golden config tests, fuzzing, L4 integration tests
make bench    # added latency of the L4 proxy
```

## License

okena is free software under the GNU Affero General Public License,
version 3 only ([LICENSE](LICENSE), SPDX `AGPL-3.0-only`). Anyone who
runs a modified okena as a network service must offer its source to the
users of that service.
