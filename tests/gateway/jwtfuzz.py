#!/usr/bin/env python3
"""Fuzzing what reads tokens, on one engine (argument) and a seed: mutated headers,
claims and framing, signed properly so that they reach what comes after the
signature too. Nothing may take a worker down, and okena may not take what a
strict JSON parser refuses: two readers must not disagree about a token.

    jwtfuzz.py [engine] [seed] [tokens]"""
import base64
import hashlib
import hmac
import json
import os
import pathlib
import random
import socket
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
SEED = int(sys.argv[2]) if len(sys.argv) > 2 else 1
COUNT = int(sys.argv[3]) if len(sys.argv) > 3 else 60000
LST = 24000 + os.getpid() % 700
SECRET = b"s" * 32
NOW = int(time.time())
rng = random.Random(SEED)


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def sign(head, claims):
    msg = b64(head) + "." + b64(claims)
    return msg + "." + b64(hmac.new(SECRET, msg.encode(), hashlib.sha256).digest())


HEAD = json.dumps({"alg": "HS256", "kid": "k1", "typ": "JWT"}).encode()
CLAIMS = json.dumps({"sub": "alice", "scope": "a b", "exp": NOW + 3600, "nbf": NOW - 10, "iss": "i", "aud": ["x", "a"]}).encode()
BITS = [b'"', b'\\', b'{', b'}', b'[', b']', b',', b':', b'\\u00', b'\\u0000', b'\\n', b'\\r\\n', b'null', b'true', b'1e9',
        b'-1', b'99999999999999999999', b'\x00', b'\xff', b'\x7f', b' ', b'\t', b'"exp"', b'"alg"', b'"sub":', b'[' * 40, b'{"a":' * 40]


def mutate(b):
    b = bytearray(b)
    for _ in range(rng.choice((1, 1, 1, 2, 3, 6))):
        k = rng.randrange(6)
        i = rng.randrange(len(b) + 1)
        if k == 0 and b:
            b[min(i, len(b) - 1)] = rng.randrange(256)
        elif k == 1:
            b[i:i] = rng.choice(BITS)
        elif k == 2:
            del b[i:i + rng.randrange(1, 12)]
        elif k == 3:
            b = b[:i]
        elif k == 4 and b:
            j = rng.randrange(len(b))
            b[i:i] = b[j:j + rng.randrange(1, 24)]
        elif k == 5 and b:
            b[min(i, len(b) - 1)] ^= 1 << rng.randrange(8)
    return bytes(b)


def case():
    k = rng.randrange(100)
    if k < 45:
        c = mutate(CLAIMS)
        return sign(HEAD, c), "claims", c
    if k < 70:
        return sign(mutate(HEAD), CLAIMS), "head", None
    t = sign(HEAD, CLAIMS)
    if k < 85:
        return mutate(t.encode()).decode("latin1"), "token", None
    return "".join(rng.choice("abcXYZ019-_.=+/ ") for _ in range(rng.randrange(0, 300))), "noise", None


def strict(c):
    """would a strict reader take these claims, with the same fields?"""
    dup = []

    def hook(pairs):		# (the last call is the outermost object: the claims)
        n = [k for k, _ in pairs]
        dup.append(len(n) != len(set(n)))
        return dict(pairs)
    try:
        d = json.loads(c.decode("utf-8"), object_pairs_hook=hook, parse_constant=lambda x: 1 / 0)
    except (ValueError, ZeroDivisionError, RecursionError):
        return False
    return isinstance(d, dict) and not dup[-1]


def clean(t):
    return all(32 <= ord(x) < 127 for x in t)


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-jfz-"))
    (tmp / "jwks.json").write_text(json.dumps({"keys": [{"kty": "oct", "kid": "k1", "alg": "HS256", "k": b64(SECRET)}]}))
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ drain delay=0s timeout=1s; workers 1; io_engine {ENGINE}; watchdog 5s }}
http 127.0.0.1:{LST} {{
    route /t {{ redirect 302 /z; auth jwt {{ jwks {tmp}/jwks.json; claims sub -> x-user-id, scope -> x-s, nothing -> x-n }} }}
}}
""")
    log = tmp / "log"
    p = subprocess.Popen(["timeout", "--foreground", "200", str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    for _ in range(100):
        try:
            s = socket.create_connection(("127.0.0.1", LST), timeout=1)
            break
        except OSError:
            time.sleep(0.05)
    bad = hard = disagree = sent = ok = 0
    examples = []
    tally = {}
    try:
        s.settimeout(10)
        while sent < COUNT:
            batch = []
            while len(batch) < 32:
                t, kind, c = case()
                if not clean(t):
                    continue
                batch.append((t, kind, c))
            s.sendall("".join(f"GET /t HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {t}\r\n\r\n" for t, _, _ in batch).encode("latin1"))
            buf = b""
            while buf.count(b"\r\n\r\n") < len(batch):
                d = s.recv(1 << 20)
                if not d:
                    raise ConnectionError(f"closed after {sent}")
                buf += d
            codes = [h[9:12] for h in buf.split(b"\r\n\r\n")[:len(batch)]]
            for (t, kind, c), code in zip(batch, codes):
                sent += 1
                tally[(kind, code)] = tally.get((kind, code), 0) + 1
                if code == b"302":
                    ok += 1
                    if c is not None and not strict(c):
                        disagree += 1
                        if len(examples) < 8:
                            examples.append(c[:140])
                elif code not in (b"401", b"431", b"400"):
                    bad += 1
    except (ConnectionError, OSError) as e:
        hard = 1
        print("connection:", e)
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    died = "killed" in t or "restarting" in t
    print(f"{sent} tokens, seed {SEED}: {ok} accepted, {sorted(tally.items())[:12]}")
    for e in examples:
        print("   took:", e)
    # (nothing accepted would make "no disagreement" mean nothing)
    few = ok < sent // 200
    print(f"jwt fuzz {ENGINE}: statuses odd {bad}, disagreements {disagree}, died {died}, too few accepted {few}")
    return 1 if bad or hard or disagree or died or few else 0


if __name__ == "__main__":
    sys.exit(main())
