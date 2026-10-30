#!/usr/bin/env python3
"""Crypto known-answer and differential tests (build/kat).

Published vectors first (FIPS 180-4, RFC 4231, RFC 5869, RFC 8448's
TLS 1.3 key schedule, RFC 7748), then random inputs against reference
implementations: hashlib/hmac for SHA-256 (both block paths, every
length around the block boundaries), HMAC and HKDF, and `cryptography`
for X25519."""
import hashlib
import hmac
import os
import pathlib
import random
import subprocess
import sys

KAT = pathlib.Path(__file__).resolve().parents[2] / "build" / "kat"
failures = 0
checks = 0


def run(mode, data):
    out = subprocess.run([str(KAT)], input=mode + data, capture_output=True)
    return out.stdout.decode().strip() if out.returncode == 0 else f"exit {out.returncode}"


def check(name, got, want):
    global failures, checks
    checks += 1
    if got != want:
        failures += 1
        print(f"FAIL {name}: got {got} want {want}")


def le16(n):
    return n.to_bytes(2, "little")


def hkdf_ref(salt, ikm, info, n):
    prk = hmac.new(salt, ikm, "sha256").digest()
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), "sha256").digest()
        out += t
        i += 1
    return out[:n]


def label_ref(secret, label, ctx, n):
    full = b"tls13 " + label
    info = n.to_bytes(2, "big") + bytes([len(full)]) + full + bytes([len(ctx)]) + ctx
    return hkdf_ref_expand(secret, info, n)


def hkdf_ref_expand(prk, info, n):
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), "sha256").digest()
        out += t
        i += 1
    return out[:n]


def hkdf(salt, ikm, info, n):
    return run(b"k", le16(len(salt)) + salt + le16(len(ikm)) + ikm + le16(len(info)) + info + le16(n))


def label(secret, lab, ctx, n):
    return run(b"l", secret + bytes([len(lab)]) + lab + bytes([len(ctx)]) + ctx + le16(n))


# --- published vectors
for mode in (b"s", b"S"):
    check("FIPS 180-4 abc", run(mode, b"abc"),
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    check("FIPS 180-4 448 bits", run(mode, b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
check("RFC 4231 case 2", run(b"h", le16(4) + b"Jefe" + b"what do ya want for nothing?"),
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
check("RFC 5869 case 1", hkdf(bytes(range(13)), b"\x0b" * 22, bytes(range(0xf0, 0xfa)), 42),
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
# RFC 8448 (simple 1-RTT): the handshake secret's server traffic secret
hs = bytes.fromhex("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")
th = bytes.fromhex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8")
check("RFC 8448 s hs traffic", label(hs, b"s hs traffic", th, 32),
      "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
check("RFC 8448 server handshake key",
      label(bytes.fromhex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"), b"key", b"", 16),
      "3fce516009c21727d0f2e4e86ee403bc")
check("RFC 7748 vector 1",
      run(b"x", bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
          + bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")),
      "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
# RFC 7748 iterated: k = u = 9, 1 and 1000 iterations
k = u = (9).to_bytes(32, "little")
for i in range(1, 1001):
    r = bytes.fromhex(run(b"x", k + u))
    u, k = k, r
    if i == 1:
        check("RFC 7748 iterated x1", r.hex(), "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
check("RFC 7748 iterated x1000", k.hex(), "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")

# --- differential
rng = random.Random(1)
sizes = list(range(0, 300)) + [rng.randrange(300, 400_000) for _ in range(20)]
for n in sizes:
    data = rng.randbytes(n)
    want = hashlib.sha256(data).hexdigest()
    check(f"sha256 SHA-NI length {n}", run(b"s", data), want)
    check(f"sha256 scalar length {n}", run(b"S", data), want)
for _ in range(200):
    key = rng.randbytes(rng.choice([0, 1, 31, 32, 63, 64, 65, 127, 128, rng.randrange(300)]))
    msg = rng.randbytes(rng.randrange(300))
    check(f"hmac key {len(key)} msg {len(msg)}", run(b"h", le16(len(key)) + key + msg),
          hmac.new(key, msg, "sha256").hexdigest())
for _ in range(150):
    salt, ikm, info = (rng.randbytes(rng.randrange(80)) for _ in range(3))
    n = rng.choice([1, 16, 31, 32, 33, 64, 100, rng.randrange(1, 8160)])
    check(f"hkdf out {n}", hkdf(salt, ikm, info, n), hkdf_ref(salt, ikm, info, n).hex())
for _ in range(100):
    secret = rng.randbytes(32)
    lab = rng.choice([b"key", b"iv", b"finished", b"derived", b"c hs traffic", b"s ap traffic"])
    ctx = rng.randbytes(rng.choice([0, 32, rng.randrange(64)]))
    n = rng.choice([12, 16, 32, 48])
    check(f"expand-label {lab.decode()} ctx {len(ctx)} out {n}", label(secret, lab, ctx, n), label_ref(secret, lab, ctx, n).hex())
try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives import serialization
    raw = serialization.Encoding.Raw
    for _ in range(300):
        a = X25519PrivateKey.generate()
        b = X25519PrivateKey.generate()
        a_raw = a.private_bytes(raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        b_pub = b.public_key().public_bytes(raw, serialization.PublicFormat.Raw)
        check("x25519 random pair", run(b"x", a_raw + b_pub), a.exchange(b.public_key()).hex())
    # the fixed-base key generation: the library's public key, and the ladder's
    for i in range(400):
        k = rng.randbytes(32) if i > 3 else (bytes(32), b"\xff" * 32, bytes(range(32)), b"\x08" + bytes(31))[i]
        pub = X25519PrivateKey.from_private_bytes(k).public_key().public_bytes(raw, serialization.PublicFormat.Raw)
        got = run(b"u", k)
        check("x25519_base = the public key", got, pub.hex())
        if i % 20 == 0:
            check("x25519_base = x25519(k, 9)", got, run(b"x", k + (9).to_bytes(32, "little")))
    # P-256 ECDH (secp256r1): the shared X against the library, and invalid
    # peer points rejected
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.hazmat.primitives.serialization import Encoding as _Enc, PublicFormat as _PF
    for _ in range(200):
        a = _ec.generate_private_key(_ec.SECP256R1())
        b = _ec.generate_private_key(_ec.SECP256R1())
        k = a.private_numbers().private_value.to_bytes(32, "big")
        peer = b.public_key().public_bytes(_Enc.X962, _PF.UncompressedPoint)
        check("p256 ecdh shared x", run(b"D", k + peer), a.exchange(_ec.ECDH(), b.public_key()).hex())
    good = _ec.generate_private_key(_ec.SECP256R1()).public_key().public_bytes(_Enc.X962, _PF.UncompressedPoint)
    bad_pt = bytearray(good)
    bad_pt[40] ^= 1                                     # a Y bit flipped: off the curve
    k = rng.randbytes(32)
    check("p256 ecdh: off-curve peer rejected", run(b"D", k + bytes(bad_pt)), "FAIL")
    check("p256 ecdh: compressed peer rejected", run(b"D", k + b"\x02" + rng.randbytes(32) + bytes(32)), "FAIL")

    # edge inputs: u with the top bit set (ignored), u = 0, u >= p
    for u in (bytes(31) + b"\x80", bytes(32), (2**255 - 19 + 5).to_bytes(32, "little"), b"\xff" * 32):
        a = X25519PrivateKey.generate()
        a_raw = a.private_bytes(raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        try:
            want = a.exchange(X25519PublicKey.from_public_bytes(u)).hex()
        except Exception:
            want = None                         # the library refuses an all-zero result
        got = run(b"x", a_raw + u)
        if want is not None:
            check(f"x25519 edge u {u.hex()[:8]}..", got, want)
except ImportError:
    print("note: python cryptography not installed; X25519 checked on RFC 7748 only")

# --- AES-128-GCM: McGrew-Viega test cases 1 and 2, then the library
def seal(key, iv, aad, pt):
    return run(b"g", key + iv + le16(len(aad)) + aad + pt)


def gopen(key, iv, aad, ct):
    return run(b"G", key + iv + le16(len(aad)) + aad + ct)


check("GCM test case 1 (empty)", seal(bytes(16), bytes(12), b"", b""), "58e2fccefa7e3061367f1d57a4e7455a")
check("GCM test case 2", seal(bytes(16), bytes(12), b"", bytes(16)),
      "0388dace60b6a392f328c2b971b2fe78" + "ab6e47d42cec13bdf53a67b21257bddf")
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    lens = list(range(0, 300)) + [rng.randrange(300, 60000) for _ in range(20)]
    for n in lens:
        key, iv = rng.randbytes(16), rng.randbytes(12)
        aad = rng.randbytes(rng.choice([0, 5, 13, 16, 17, 32, rng.randrange(80)]))
        pt = rng.randbytes(n)
        want = AESGCM(key).encrypt(iv, pt, aad)
        check(f"gcm seal {n} aad {len(aad)}", seal(key, iv, aad, pt), want.hex())
        if n % 7 == 0:
            check(f"gcm open {n}", gopen(key, iv, aad, want), pt.hex())
        if n % 3 == 0 or n > 299:            # the SSE paths too, where the CPU has VAES
            check(f"gcm seal {n} without VAES", run(b"vg", key + iv + le16(len(aad)) + aad + pt), want.hex())
            check(f"gcm open {n} without VAES", run(b"vG", key + iv + le16(len(aad)) + aad + want), pt.hex())
    key, iv, aad, pt = rng.randbytes(16), rng.randbytes(12), b"header", rng.randbytes(100)
    ct = bytearray(AESGCM(key).encrypt(iv, pt, aad))
    for name, k2, aad2, ct2 in [
        ("a flipped ciphertext bit", key, aad, bytes(ct[:10]) + bytes([ct[10] ^ 1]) + bytes(ct[11:])),
        ("a flipped tag bit", key, aad, bytes(ct[:-1]) + bytes([ct[-1] ^ 0x80])),
        ("other additional data", key, b"headeR", bytes(ct)),
        ("another key", rng.randbytes(16), aad, bytes(ct)),
    ]:
        check(f"gcm open refuses {name}", gopen(k2, iv, aad2, ct2), "FAIL")
except ImportError:
    print("note: python cryptography not installed; AES-GCM checked on the test cases only")

# --- P-256: field arithmetic, then keys and RFC 6979 signatures
P = 2**256 - 2**224 + 2**192 + 2**96 - 1
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
R = 2**256


def limbs(v):
    return v.to_bytes(32, "little")


def num(hexs):
    return int.from_bytes(bytes.fromhex(hexs), "little")


edge = [0, 1, 2, P - 1, P - 2, 2**255, 2**224, 2**64 - 1]
for _ in range(120):
    a = rng.choice(edge + [rng.randrange(P)])
    b = rng.choice(edge + [rng.randrange(P)])
    check(f"p256 mont_mul {a:x} {b:x}", num(run(b"M", limbs(a) + limbs(b))), a * b * pow(R, -1, P) % P)
    check(f"p256 sqr {a:x}", num(run(b"Q", limbs(a))), a * a * pow(R, -1, P) % P)
    check(f"p256 add {a:x} {b:x}", num(run(b"a", limbs(a) + limbs(b))), (a + b) % P)
    check(f"p256 sub {a:x} {b:x}", num(run(b"b", limbs(a) + limbs(b))), (a - b) % P)
    if a:
        check(f"p256 inv {a:x}", num(run(b"I", limbs(a * R % P))), pow(a, -1, P) * R % P)
d = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
sig = run(b"E", d.to_bytes(32, "big") + hashlib.sha256(b"sample").digest())
r = 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
s_ = 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8


def der_int(v):
    b_ = v.to_bytes(32, "big").lstrip(b"\0") or b"\0"
    if b_[0] & 0x80:
        b_ = b"\0" + b_
    return bytes([2, len(b_)]) + b_


body = der_int(r) + der_int(s_)
check("RFC 6979 A.2.5 P-256 SHA-256 'sample'", sig, (bytes([0x30, len(body)]) + body).hex())
check("p256 refuses d = 0", run(b"E", bytes(32) + bytes(32)), "FAIL")
check("p256 refuses d = n", run(b"E", N.to_bytes(32, "big") + bytes(32)), "FAIL")
try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes, serialization
    for i in range(150):
        k = ec.generate_private_key(ec.SECP256R1())
        dd = k.private_numbers().private_value.to_bytes(32, "big")
        pub = k.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        check("p256 public key", run(b"P", dd), pub.hex())
        msg = rng.randbytes(rng.randrange(200))
        want = k.sign(msg, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        check("p256 RFC 6979 signature, byte for byte", run(b"E", dd + hashlib.sha256(msg).digest()), want.hex())
except (ImportError, TypeError):
    print("note: deterministic ECDSA not in this cryptography; P-256 checked on RFC 6979 only")

print(f"kat: {'all passed' if not failures else f'{failures} failed'} ({checks} checks)")
sys.exit(1 if failures else 0)
