#!/usr/bin/env python3
"""Handshake crypto speed, against OpenSSL on the same machine."""
import os
import pathlib
import re
import subprocess

KAT = pathlib.Path(__file__).resolve().parents[2] / "build" / "kat"


def ns(op, inp, n):
    out = subprocess.run([str(KAT)], input=b"B" + op + n.to_bytes(4, "little") + inp, capture_output=True)
    return int(out.stdout) / n


def openssl():
    try:
        out = subprocess.run(["openssl", "speed", "-seconds", "2", "ecdhx25519", "ecdsap256"],
                             capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.TimeoutExpired):
        return {}
    r = {}
    m = re.search(r"ecdsa \(nistp256\)\s+\S+\s+\S+\s+([\d.]+)", out)
    if m:
        r["sign"] = float(m.group(1))
    m = re.search(r"ecdh \(X25519\)\s+\S+\s+([\d.]+)", out)
    if m:
        r["x25519"] = float(m.group(1))
    return r


ref = openssl()
x = ns(b"x", os.urandom(32) + (9).to_bytes(32, "little"), 2000)
d = (0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721).to_bytes(32, "big")
e = ns(b"E", d + os.urandom(32), 2000)
u = ns(b"u", os.urandom(32), 2000)
for name, t, key in (("X25519", x, "x25519"), ("X25519 key gen", u, None), ("ECDSA P-256 sign", e, "sign")):
    mine = 1e9 / t
    other = ref.get(key) if key else None
    rel = f"   OpenSSL {other:,.0f}/s ({mine / other:.2f}x)" if other else ""
    print(f"{name:18} {t / 1000:7.1f} us  {mine:9,.0f}/s{rel}")
