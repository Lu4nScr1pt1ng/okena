#!/usr/bin/env python3
"""Wycheproof (C2SP): the edge cases of every primitive okena implements,
through build/kat. The vectors are fetched once, at a pinned commit, into
build/wycheproof (or taken from $WYCHEPROOF); without them (no network)
the suite is skipped.

A "valid" case must give the expected result, an "invalid" one must be
refused; "acceptable" cases (behaviour the standard leaves open) are
counted, not failed, except where okena's choice is checked by name.

Families: AES-128-GCM (96-bit IV, 128-bit tag), ChaCha20-Poly1305, X25519,
ECDSA P-256/SHA-256 (IEEE P1363 signatures: the arithmetic; DER parsing
lives in the TLS and X.509 code), ECDH P-256 (uncompressed points), Ed25519,
RSA PKCS #1 v1.5 and PSS (2048, SHA-256), HMAC-SHA-256, HKDF-SHA-256, and
ML-KEM-768 (encapsulation with the modulus check; key generation from the
seed, then decapsulation with implicit rejection)."""
import concurrent.futures
import hashlib
import json
import os
import pathlib
import struct
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
KAT = ROOT / "build" / "kat"
COMMIT = "d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9"
DIR = pathlib.Path(os.environ.get("WYCHEPROOF", ROOT / "build" / "wycheproof"))
failures = []
counts = {}


def fetch():
    vec = DIR / "testvectors_v1"
    if vec.is_dir():
        return vec
    if "WYCHEPROOF" in os.environ:
        return None
    try:
        DIR.mkdir(parents=True, exist_ok=True)
        git = ["git", "-C", str(DIR)]
        subprocess.run(git + ["init", "-q"], check=True, capture_output=True)
        subprocess.run(git + ["remote", "add", "origin", "https://github.com/C2SP/wycheproof"], capture_output=True)
        subprocess.run(git + ["fetch", "-q", "--depth", "1", "origin", COMMIT], check=True, capture_output=True,
                       timeout=180)
        subprocess.run(git + ["checkout", "-q", "FETCH_HEAD"], check=True, capture_output=True)
    except (OSError, subprocess.SubprocessError):
        return None
    return vec if vec.is_dir() else None


def run(mode, data):
    out = subprocess.run([str(KAT)], input=mode + data, capture_output=True)
    return out.stdout.decode().strip() if out.returncode == 0 else f"exit {out.returncode}"


def le16(n):
    return n.to_bytes(2, "little")


def family(name, path, cases):
    """cases: an iterable of (tcId, result, a callable giving (ok, detail))."""
    jobs = list(cases)
    stats = {"valid": 0, "invalid": 0, "acceptable": 0, "skipped": 0}
    with concurrent.futures.ThreadPoolExecutor(os.cpu_count() or 4) as pool:
        for (tc, result, _), (ok, detail) in zip(jobs, pool.map(lambda j: j[2](), jobs)):
            if ok is None:
                stats["skipped"] += 1
                continue
            stats[result] += 1
            if not ok and result != "acceptable":
                failures.append(f"{name} tcId {tc} ({result}): {detail}")
    counts[name] = stats


def load(vec, name):
    return json.loads((vec / f"{name}.json").read_text())


def aead(vec, name, file, key_bits, seal, open_):
    d = load(vec, file)

    def case(g, t):
        key, iv, aad = (bytes.fromhex(t[k]) for k in ("key", "iv", "aad"))
        msg, ct, tag = (bytes.fromhex(t[k]) for k in ("msg", "ct", "tag"))
        head = key + iv + le16(len(aad)) + aad
        if t["result"] == "valid":
            got = run(seal, head + msg)
            if got != (ct + tag).hex():
                return False, f"seal {got[:32]}"
            got = run(open_, head + ct + tag)
            return got == msg.hex(), f"open {got[:32]}"
        got = run(open_, head + ct + tag)
        return got == "FAIL", f"opened: {got[:32]}"

    family(name, file, ((t["tcId"], t["result"], (lambda g=g, t=t: case(g, t)))
                        for g in d["testGroups"] if g["keySize"] == key_bits and g["ivSize"] == 96
                        and g["tagSize"] == 128 for t in g["tests"]))


def main():
    if not KAT.exists():
        print("skip wycheproof: build/kat missing (make build/kat)")
        return 0
    vec = fetch()
    if vec is None:
        print("skip wycheproof: no vectors (no network; or set WYCHEPROOF to a checkout)")
        return 0

    aead(vec, "aes-128-gcm", "aes_gcm_test", 128, b"g", b"G")
    aead(vec, "chacha20-poly1305", "chacha20_poly1305_test", 256, b"y", b"Z")

    d = load(vec, "x25519_test")

    def x25519(t):
        got = run(b"x", bytes.fromhex(t["private"]) + bytes.fromhex(t["public"]))
        return got == t["shared"], got[:16]
    family("x25519", "x25519_test", ((t["tcId"], t["result"], (lambda t=t: x25519(t)))
                                     for g in d["testGroups"] for t in g["tests"]))

    d = load(vec, "ecdsa_secp256r1_sha256_p1363_test")

    def ecdsa(pub, t):
        sig = bytes.fromhex(t["sig"])
        if len(sig) != 64:                      # not r | s of 32 bytes each: never verified
            return t["result"] != "valid", "length"
        got = run(b"V", pub + hashlib.sha256(bytes.fromhex(t["msg"])).digest() + sig)
        return got == ("01" if t["result"] == "valid" else "00"), got
    family("ecdsa-p256-sha256", "p1363", ((t["tcId"], t["result"],
                                           (lambda p=bytes.fromhex(g["publicKey"]["uncompressed"]), t=t: ecdsa(p, t)))
                                          for g in d["testGroups"] for t in g["tests"]))

    d = load(vec, "ecdh_secp256r1_ecpoint_test")

    def ecdh(t):
        pub, priv = bytes.fromhex(t["public"]), int(t["private"], 16)
        if len(pub) != 65 or pub[0] != 4:       # TLS key shares are uncompressed points
            return t["result"] != "valid", "encoding"
        if not 0 < priv < 2**256:
            return None, ""
        got = run(b"D", priv.to_bytes(32, "big") + pub)
        if t["result"] == "valid":
            return got == t["shared"], got[:16]
        return got == "FAIL", got[:16]
    family("ecdh-p256", "ecpoint", ((t["tcId"], t["result"], (lambda t=t: ecdh(t)))
                                    for g in d["testGroups"] for t in g["tests"]))

    d = load(vec, "ed25519_test")

    def ed(pk, t):
        sig = bytes.fromhex(t["sig"])
        if len(sig) != 64:
            return t["result"] != "valid", "length"
        got = run(b"f", pk + sig + bytes.fromhex(t["msg"]))
        return got == ("01" if t["result"] == "valid" else "00"), got
    family("ed25519", "ed25519_test", ((t["tcId"], t["result"], (lambda p=bytes.fromhex(g["publicKey"]["pk"]), t=t: ed(p, t)))
                                       for g in d["testGroups"] for t in g["tests"]))

    for name, file, mode in (("rsa-pkcs1-2048-sha256", "rsa_signature_2048_sha256_test", b"Y"),
                             ("rsa-pss-2048-sha256", "rsa_pss_2048_sha256_mgf1_32_test", b"W")):
        d = load(vec, file)

        def rsa(g, t, mode=mode):
            n, e = int(g["publicKey"]["modulus"], 16), int(g["publicKey"]["publicExponent"], 16)
            nb = (n.bit_length() + 7) // 8
            sig = bytes.fromhex(t["sig"])
            if len(sig) != nb:                  # the signature is the modulus' length, or wrong
                return t["result"] != "valid", "length"
            h = hashlib.sha256(bytes.fromhex(t["msg"])).digest()
            got = run(mode, struct.pack("<H", nb) + n.to_bytes(nb, "big") + sig + struct.pack("<I", e) + h)
            return got == ("01" if t["result"] == "valid" else "00"), got
        family(name, file, ((t["tcId"], t["result"], (lambda g=g, t=t: rsa(g, t)))
                            for g in d["testGroups"] for t in g["tests"]))

    d = load(vec, "hmac_sha256_test")

    def hmac(g, t):
        key, msg, tag = (bytes.fromhex(t[k]) for k in ("key", "msg", "tag"))
        got = run(b"h", le16(len(key)) + key + msg)[: g["tagSize"] // 4]
        return (got == tag.hex()) == (t["result"] == "valid"), got[:16]
    family("hmac-sha256", "hmac_sha256_test", ((t["tcId"], t["result"], (lambda g=g, t=t: hmac(g, t)))
                                               for g in d["testGroups"] for t in g["tests"]))

    d = load(vec, "hkdf_sha256_test")

    def hkdf(t):
        if t["size"] > 255 * 32:               # past HKDF's limit: callers never ask
            return None, ""
        ikm, salt, info = (bytes.fromhex(t[k]) for k in ("ikm", "salt", "info"))
        got = run(b"k", le16(len(salt)) + salt + le16(len(ikm)) + ikm + le16(len(info)) + info + le16(t["size"]))
        return (got == t["okm"]) == (t["result"] == "valid"), got[:16]
    family("hkdf-sha256", "hkdf_sha256_test", ((t["tcId"], t["result"], (lambda t=t: hkdf(t)))
                                               for g in d["testGroups"] for t in g["tests"]))

    d = load(vec, "mlkem_768_encaps_test")

    def encaps(t):
        ek, m = bytes.fromhex(t["ek"]), bytes.fromhex(t["m"])
        if len(ek) != 1184:                     # the TLS key share's length is checked first
            return t["result"] != "valid", "length"
        got = run(b"q", ek + m)
        if t["result"] == "valid":
            return got == t["c"] + t["K"], got[:16]
        return got == "exit 2", got[:16]        # the modulus check refuses the key
    family("ml-kem-768 encaps", "mlkem_768_encaps_test", ((t["tcId"], t["result"], (lambda t=t: encaps(t)))
                                                          for g in d["testGroups"] for t in g["tests"]))

    d = load(vec, "mlkem_768_test")

    def kem(t):
        seed, c = bytes.fromhex(t["seed"]), bytes.fromhex(t["c"])
        keys = run(b"L", seed)
        if t.get("ek") and keys[: 2 * 1184] != t["ek"]:
            return False, "keygen"
        if len(c) != 1088:                      # a ciphertext of the wrong length never reaches it
            return t["result"] != "valid", "length"
        got = run(b"O", bytes.fromhex(keys[2 * 1184:]) + c)
        return (got == t["K"]) == (t["result"] == "valid"), got[:16]
    family("ml-kem-768 keygen+decaps", "mlkem_768_test", ((t["tcId"], t["result"], (lambda t=t: kem(t)))
                                                          for g in d["testGroups"] for t in g["tests"]))

    for name, s in counts.items():
        print(f"{'ok  ' if not any(f.startswith(name + ' ') for f in failures) else 'FAIL'} {name:<26} "
              f"valid {s['valid']}, invalid {s['invalid']}, acceptable {s['acceptable']}"
              + (f", skipped {s['skipped']}" if s["skipped"] else ""))
    for f in failures[:40]:
        print("FAIL " + f)
    total = sum(sum(s.values()) for s in counts.values())
    print(f"wycheproof: {'all passed' if not failures else f'{len(failures)} failed'} ({total} cases)")
    return 1 if failures else 0


sys.exit(main())
