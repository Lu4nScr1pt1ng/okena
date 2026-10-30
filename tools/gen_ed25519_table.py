#!/usr/bin/env python3
"""Writes src/crypto/ed25519_table.bin: the fixed-base table for X25519 key
generation (src/crypto/x25519.inc, x25519_base).

The X25519 base point (u = 9) is the Ed25519 base point B (y = 4/5) seen
through the birational map u = (1 + y) / (1 - y). So k * 9 is computed as
k * B on the twisted Edwards curve -x^2 + y^2 = 1 + d x^2 y^2, with k in
signed radix-16 digits e_0..e_63 in [-8, 8]: k * B = sum e_i 16^i B, the
odd digits first, then times 16, then the even ones (ref10's method). Row
i (0..31) holds j * 256^i * B for j = 1..8 as (y + x, y - x, 2 d x y) mod
p, three 32-byte little-endian numbers: 32 * 8 * 96 = 24,576 bytes.
Exact integer arithmetic; tests/kat checks the keys made with it against
k * 9 by the ladder and against the cryptography package."""
import pathlib

P = 2**255 - 19
D = -121665 * pow(121666, -1, P) % P


def recover_x(y):
    xx = (y * y - 1) * pow(D * y * y + 1, -1, P) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P:
        x = x * pow(2, (P - 1) // 4, P) % P
    assert (x * x - xx) % P == 0
    return P - x if x & 1 else x            # the even root: B's x is positive


def add(p1, p2):
    (x1, y1), (x2, y2) = p1, p2
    t = D * x1 * x2 * y1 * y2 % P
    x3 = (x1 * y2 + y1 * x2) * pow(1 + t, -1, P) % P
    y3 = (y1 * y2 + x1 * x2) * pow(1 - t, -1, P) % P
    return x3, y3


BY = 4 * pow(5, -1, P) % P
B = (recover_x(BY), BY)
assert (1 + BY) * pow(1 - BY, -1, P) % P == 9  # the map takes B to u = 9


def le(n):
    return (n % P).to_bytes(32, "little")


out = bytearray()
base = B
for i in range(32):
    pt = base
    for j in range(1, 9):
        x, y = pt
        out += le(y + x) + le(y - x) + le(2 * D * x * y)
        pt = add(pt, base)
    for _ in range(8):                       # 256 * base
        base = add(base, base)
assert len(out) == 32 * 8 * 96
dest = pathlib.Path(__file__).resolve().parents[1] / "src" / "crypto" / "ed25519_table.bin"
dest.write_bytes(out)
print(f"{dest}: {len(out)} bytes")
