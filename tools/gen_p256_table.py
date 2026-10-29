#!/usr/bin/env python3
"""Writes src/crypto/p256_table.bin: the fixed-base table of P-256.

k * G = sum over 37 windows of 7 bits, Booth-recoded into digits d_i in
[-64, 64]: sign(d_i) * T[i][|d_i|], T[i][j] = j * 2^(7i) * G for j = 1..64
(a zero digit adds nothing; a negative one negates y). Each entry is the
affine point (x, y) in Montgomery form (times 2^256 mod p), two 32-byte
little-endian numbers: 37 * 64 * 64 = 151,552 bytes (OpenSSL's layout). Exact integer arithmetic; the
signatures made with it are checked byte for byte against a reference
library in tests/kat."""
import pathlib

P = 2**256 - 2**224 + 2**192 + 2**96 - 1
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
R = 2**256
WINDOWS, BITS = 37, 7


def add(p1, p2):
    if p1 is None:
        return p2
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = (3 * x1 * x1 - 3) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return x3, (lam * (x1 - x3) - y1) % P


out = bytearray()
base = (GX, GY)
for i in range(WINDOWS):
    acc = None
    for j in range(1, 2**(BITS - 1) + 1):
        acc = add(acc, base)
        x, y = acc
        out += (x * R % P).to_bytes(32, "little") + (y * R % P).to_bytes(32, "little")
    for _ in range(BITS):                       # base = 2^6 * base
        base = add(base, base)
path = pathlib.Path(__file__).resolve().parents[1] / "src" / "crypto" / "p256_table.bin"
path.write_bytes(out)
print(f"{path}: {len(out)} bytes")
