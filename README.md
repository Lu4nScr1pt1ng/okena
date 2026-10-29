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

* two I/O engines, io_uring and epoll, chosen automatically: where
  io_uring is blocked (Docker's default seccomp profile, Kubernetes,
  gVisor) okena runs on epoll and says why;
* `busy_poll` for the latency profile;
* a `FROM scratch` image of about 70 KB, non-root, aware of `--cpus`
  and `--cpuset-cpus`.

Next: the rest of phase 0 and 1 in [ROADMAP.md](docs/ROADMAP.md).

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
make          # build/okena
make test     # golden config tests, fuzzing, L4 tests on both engines
make docker-test   # the image under both seccomp profiles
make bench    # added latency of the L4 proxy
```

## License

okena is free software under the GNU Affero General Public License,
version 3 only ([LICENSE](LICENSE), SPDX `AGPL-3.0-only`). Anyone who
runs a modified okena as a network service must offer its source to the
users of that service.
