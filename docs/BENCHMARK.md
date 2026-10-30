# Benchmarks

Measurements of okena, and comparisons with the established software for
each job (OpenSSL for crypto, HAProxy and nginx for proxying), kept so they
can be rerun and compared later. Every entry says when, on what, and how.
A number without its method is not recorded here.

The exit criteria in [ROADMAP.md](ROADMAP.md) compare against references
on the same machine, with cores pinned and open-loop load. Entries made
before that harness exists (`okena bench`, the two-host topology) say so.

## Machine

Unless an entry says otherwise:

| | |
|---|---|
| CPU | AMD Ryzen 7 5700G (Zen 3, 8 cores / 16 threads), VAES and VPCLMULQDQ on ymm, SHA-NI, no AVX-512 |
| Memory | 30 GiB |
| Kernel | Linux 7.2.11 |
| OpenSSL | 3.5.3 (16 Sep 2025) |
| Pinning | `taskset -c 3` for single-core crypto, unless stated |

## Crypto, one core

Microbenchmarks: one operation in a loop, single thread, the time per
operation. okena through `build/kat` mode `B` (op, count, input); OpenSSL
through `openssl speed` on the same core.

```
python3 - <<'EOF'
import os, subprocess, sys
sys.path.insert(0, "tests/kat"); import mlkem_ref as M
run = lambda d: int(subprocess.run(["taskset", "-c", "3", "build/kat"], input=b"B" + d, capture_output=True).stdout)
ek, dk = M.keygen(os.urandom(32), os.urandom(32)); k, c = M.encaps(ek, os.urandom(32)); n = 5000
print("encaps us", run(b"K" + n.to_bytes(4, "little") + ek + os.urandom(32)) / n / 1000)
EOF
taskset -c 3 openssl speed -seconds 2 ML-KEM-768
taskset -c 3 openssl speed -seconds 2 -bytes 16384 -evp chacha20-poly1305
```

| Operation | okena | OpenSSL 3.5.3 | Date | Notes |
|---|---|---|---|---|
| X25519 (variable base) | 25.6 us | ~25.6 us | 2026-10 | mulx/adcx/adox ladder |
| X25519 (fixed base, key generation) | 8.0 us | | 2026-10 | Edwards-form table |
| ECDSA P-256 sign (RFC 6979) | 15.6 us | ~15.6 us | 2026-10 | fixed-base table, blinded inversion |
| AES-128-GCM, 16 KiB records | 6.9 GB/s | 5.8 GB/s | 2026-10 | VAES + VPCLMULQDQ on ymm (4.3 GB/s on the SSE path) |
| ChaCha20-Poly1305 seal, 16 KiB records | 1.34 GB/s | 3.1 GB/s | 2026-10-30 | two blocks a ymm, scalar Poly1305; OpenSSL runs eight blocks and a vector Poly1305. Only without kTLS (the kernel seals otherwise) |
| Keccak-f[1600] | 368 ns | | 2026-10-30 | scalar; 490 ns before theta was fused into rho/pi |
| Keccak-f[1600], four at once | ~1.25 of one | | 2026-10-30 | AVX2 |
| ML-KEM-768 key generation | 12.9 us | 36 us | 2026-10-30 | AVX2 NTT, four-way Keccak |
| ML-KEM-768 encapsulation | 15.5 us | 25 us | 2026-10-30 | 49.7 us scalar, 36 us after the Keccak work, 22.4 us with the AVX2 NTT |
| ML-KEM-768 decapsulation | 16.6 us | 37 us | 2026-10-30 | |

## TLS handshakes

| Measure | Result | Date | How |
|---|---|---|---|
| `tls_hello` on a real ClientHello (x25519, ECDSA) | 57 us | 2026-10 | `tests/tls/server.asm`, mode P |
| Worker CPU per new HTTPS connection (x25519) | ~75 us (77 user + 61 kernel with the client on other cores) | 2026-10 | 4 workers, a route okena answers, new connection per request |
| Worker CPU saved by a session ticket | ~27 us | 2026-10 | same, resumed |

## HTTPS throughput (no reference yet)

4 workers, a route okena answers itself, `wrk` on other cores, keep-alive.

| Measure | Result | Date |
|---|---|---|
| HTTPS keep-alive, kTLS | 284k requests/s | 2026-10 |
| HTTPS keep-alive, user-space records | 302k requests/s | 2026-10 |
| Plain HTTP keep-alive | 406k requests/s | 2026-10 |
| 50 MB download, kTLS | 933 MB/s | 2026-10 |
| 50 MB download, user-space records | 1.05 GB/s (755 MB/s before the eight-block GCM) | 2026-10 |

## Handshake budget

One worker, 6000 TLS handshakes arriving at once (three Python clients,
500-connection bursts), and an open keep-alive HTTPS connection asking
meanwhile: the latency of that connection. okena on core 1, the asking
client on core 2, the flood on cores 3-7. The handshake throughput was the
same in every case, but the Python clients bound it, so the budget's cost
in handshakes per second is not measured here.

| `handshake_budget` | p50 | p99 | Date |
|---|---|---|---|
| off (`0us`) | 31 us | 1.62 ms | 2026-10-30 |
| 200 us | 31 us | 0.84 ms | 2026-10-30 |
| 100 us (default) | 30 us | 0.47 ms | 2026-10-30 |
| 50 us | 31 us | 0.33 ms | 2026-10-30 |

The maximum stayed at 1.5-3 ms in every mode, budget or not; its cause is
not isolated yet.

## Against HAProxy and nginx

Not measured yet. The phase exits need: added latency p50/p99/p99.9 for
`tcp` (HAProxy `mode tcp`), HTTP/1.1 keep-alive (HAProxy, nginx), and full
handshakes per second per core with ECDSA certificates (HAProxy on
OpenSSL), all on the same machine with cores pinned and open-loop load.
