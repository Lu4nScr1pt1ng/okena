# okena

L4/L7 load balancer, reverse proxy and API gateway in x86-64 assembly
(fasm2) for Linux. One static binary, no libc.

* [Architecture](docs/ARCHITECTURE.md): how it is built and why.
* [Configuration](docs/CONFIG.md): the `okena.conf` language.
* [Roadmap](docs/ROADMAP.md): phases and exit criteria.

```
tcp :5432 {
    to 10.0.0.11:5432 10.0.0.12:5432
}

https example.com {
    to 127.0.0.1:3000
}
```
