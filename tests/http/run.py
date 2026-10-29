#!/usr/bin/env python3
"""HTTP/1.x parsing: a corpus of known cases (request smuggling among
them) and differential fuzzing against a reference written from the same
rules (src/http/parse.inc, src/http/chunk.inc). Any disagreement between
the assembly and the reference fails, with the input saved."""
import pathlib
import random
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
HARNESS = ROOT / "build" / "httpharness"

TCHAR = set(b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
TARGET_OK = {c for c in range(0x21, 0x7F)} - set(b'#"<>\\^`{|}')
HOP = {b"connection", b"keep-alive", b"te", b"trailer", b"proxy-connection",
       b"proxy-authorization", b"proxy-authenticate"}


class Err(Exception):
    def __init__(self, code):
        self.code = code


def head_end(d):
    line = 0
    i = 0
    while i < len(d):
        c = d[i]
        if c == 10:
            return -1
        if c == 13:
            if i + 1 >= len(d):
                return 0
            if d[i + 1] != 10:
                return -1
            if i == line:
                return -1 if i == 0 else i + 2
            line = i = i + 2
            continue
        i += 1
    return 0


def fields(h, i):
    out = []
    while True:
        if h[i:i + 2] == b"\r\n":
            return out
        if h[i] in (32, 9):
            raise Err(400)
        if len(out) >= 100:
            raise Err(431)
        j = i
        while h[j] != ord(":"):
            if h[j] not in TCHAR:
                raise Err(400)
            j += 1
        if j == i:
            raise Err(400)
        name = h[i:j]
        j += 1
        while h[j] in (32, 9):
            j += 1
        k = j
        while h[k] != 13:
            c = h[k]
            if c != 9 and (c < 32 or c == 0x7F):
                raise Err(400)
            k += 1
        v = h[j:k].rstrip(b" \t")
        out.append([name, v, False])
        i = k + 2


def content_length(v):
    vals, i = [], 0
    while i < len(v):
        if v[i] in b" \t,":
            i += 1
            continue
        j = i
        while j < len(v) and 48 <= v[j] <= 57:
            j += 1
        if j == i or j - i > 16:
            raise Err(400)
        n = int(v[i:j])
        if n > 1 << 53:
            raise Err(400)
        if j < len(v) and v[j] not in b", \t":
            raise Err(400)
        vals.append(n)
        i = j
    if not vals or any(x != vals[0] for x in vals):
        raise Err(400)
    return vals[0]


def valid_host(v):
    if not v:
        return False
    i = 0
    if v[0] == ord("["):
        i = 1
        while True:
            if i >= len(v):
                return False
            c = v[i]
            i += 1
            if c == ord("]"):
                break
            if c in b":." or chr(c | 0x20) in "0123456789abcdef":
                continue
            return False
    else:
        while i < len(v) and v[i] != ord(":"):
            if v[i] not in TCHAR and v[i] not in b"(),;=":
                return False
            i += 1
        if i < len(v):
            if i == 0:
                return False
            i += 1
            while i < len(v):
                if not 48 <= v[i] <= 57:
                    return False
                i += 1
            return True
        return True
    # after "]": optional ":" then digits
    if i < len(v) and v[i] == ord(":"):
        i += 1
    while i < len(v):
        if not 48 <= v[i] <= 57:
            return False
        i += 1
    return True


def common(m):
    flags, length, host = set(), None, None
    for idx, f in enumerate(m["fields"]):
        n = f[0].lower()
        if n == b"content-length":
            f[2] = True
            x = content_length(f[1])
            if length is not None and x != length:
                raise Err(400)
            length = x
        elif n == b"transfer-encoding":
            f[2] = True
            if "chunked" in flags:
                raise Err(400)
            if f[1].lower() != b"chunked":
                raise Err(501)
            flags.add("chunked")
        elif n == b"host":
            if host is not None:
                raise Err(400)
            host = idx
        elif n in HOP:
            f[2] = True
        elif n == b"upgrade":
            f[2] = True
            flags.add("has_upgrade")
        elif n == b"expect":
            if f[1].lower() == b"100-continue":
                flags.add("continue")
    for f in m["fields"]:
        if f[0].lower() != b"connection":
            continue
        for tok in f[1].replace(b"\t", b",").replace(b" ", b",").split(b","):
            if not tok:
                continue
            t = tok.lower()
            if t == b"close":
                flags.add("close")
            if t == b"keep-alive":
                flags.add("keepalive")
            if t == b"upgrade":
                flags.add("upgrade")
            for g in m["fields"]:
                if g[0].lower() == t and g[0].lower() != b"host":
                    g[2] = True
    if "chunked" in flags and length is not None:
        raise Err(400)
    m.update(flags=flags, length=length, host=host)


def parse_request(h):
    i = 0
    while h[i] != 32:
        if h[i] not in TCHAR:
            raise Err(400)
        i += 1
    if i == 0:
        raise Err(400)
    method = h[:i]
    i += 1
    t0, path = i, None
    while h[i] != 32:
        c = h[i]
        if c == ord("?") and path is None:
            path = i - t0
        if c not in TARGET_OK:
            raise Err(400)
        i += 1
    target = h[t0:i]
    if not target:
        raise Err(400)
    if path is None:
        path = len(target)
    if not (target[0] == ord("/") or target == b"*" or
            (len(target) >= 8 and bytes(c | 0x20 for c in target[:7]) == b"http://")):
        raise Err(400)
    i += 1
    if i + 10 > len(h):
        raise Err(400)
    v = h[i:i + 10]
    if v[:5] != b"HTTP/" or v[6] != ord(".") or v[8:] != b"\r\n" or \
            not (48 <= v[5] <= 57 and 48 <= v[7] <= 57):
        raise Err(400)
    if v[5:8] == b"1.1":
        version = 11
    elif v[5:8] == b"1.0":
        version = 10
    else:
        raise Err(505)
    m = {"version": version, "method": method, "target": target, "path": target[:path],
         "fields": fields(h, i + 10)}
    common(m)
    fl = m["flags"]
    if version == 10:
        if "chunked" in fl:
            raise Err(400)
        if "keepalive" not in fl:
            fl.add("close")
    elif m["host"] is None:
        raise Err(400)
    if m["host"] is not None and not valid_host(m["fields"][m["host"]][1]):
        raise Err(400)
    if not ("upgrade" in fl and "has_upgrade" in fl):
        fl.discard("upgrade")
    return m


def parse_response(h):
    if len(h) < 14 or h[:5] != b"HTTP/" or h[5:8] not in (b"1.1", b"1.0"):
        raise Err(400)
    version = 11 if h[5:8] == b"1.1" else 10
    if h[8] != 32 or not all(48 <= c <= 57 for c in h[9:12]):
        raise Err(400)
    status = int(h[9:12])
    if status < 100 or h[12] != 32:
        raise Err(400)
    i = 13
    while h[i] != 13:
        c = h[i]
        if c != 9 and (c < 32 or c == 0x7F):
            raise Err(400)
        i += 1
    if h[i + 1] != 10:
        raise Err(400)
    m = {"version": version, "status": status, "fields": fields(h, i + 2)}
    common(m)
    if version == 10 and "keepalive" not in m["flags"]:
        m["flags"].add("close")
    return m


def describe(kind, data):
    end = head_end(data)
    if end == -1:
        return "error 400\n"
    if end == 0:
        return "incomplete\n"
    try:
        m = parse_request(data[:end]) if kind == "Q" else parse_response(data[:end])
    except Err as e:
        return f"error {e.code}\n"
    except IndexError:
        return "error 400\n"
    out = ["ok", f"head {end}", f"version {m['version']}"]
    if kind == "Q":
        out += [b"method ".decode() + m["method"].decode("latin1"),
                "target " + m["target"].decode("latin1"), "path " + m["path"].decode("latin1")]
    else:
        out.append(f"status {m['status']}")
    out.append("length " + ("none" if m["length"] is None else str(m["length"])))
    out.append("flags" + "".join(" " + f for f in ("chunked", "close", "upgrade", "continue") if f in m["flags"]))
    if m["host"] is not None:
        out.append("host " + m["fields"][m["host"]][1].decode("latin1"))
    for n, v, hop in m["fields"]:
        if not hop:
            out.append("h " + n.decode("latin1") + ": " + v.decode("latin1"))
    return "\n".join(out) + "\n"


def chunk_ref(b):
    out, i = bytearray(), 0
    hexd = "0123456789abcdefABCDEF"
    while True:
        if i >= len(b):
            return "more", out
        if chr(b[i]) not in hexd:
            return "error", out
        size, digits = 0, 0
        while i < len(b) and chr(b[i]) in hexd:
            if digits >= 15:
                return "error", out
            size = size * 16 + int(chr(b[i]), 16)
            digits += 1
            i += 1
        if i >= len(b):
            return "more", out
        if b[i] == ord(";"):
            i += 1
            ext = 0
            while i < len(b) and b[i] != 13:
                c = b[i]
                if c != 9 and (c < 32 or c == 0x7F):
                    return "error", out
                ext += 1
                if ext > 4096:
                    return "error", out
                i += 1
            if i >= len(b):
                return "more", out
        if b[i] != 13:
            return "error", out
        i += 1
        if i >= len(b):
            return "more", out
        if b[i] != 10:
            return "error", out
        i += 1
        if size == 0:
            trail = 0
            while True:
                if i >= len(b):
                    return "more", out
                if b[i] == 13:
                    i += 1
                    if i >= len(b):
                        return "more", out
                    if b[i] != 10:
                        return "error", out
                    return ("end", i + 1), out
                while i < len(b) and b[i] != 13:
                    c = b[i]
                    if c != 9 and (c < 32 or c == 0x7F):
                        return "error", out
                    trail += 1
                    if trail > 8192:
                        return "error", out
                    i += 1
                if i >= len(b):
                    return "more", out
                i += 1
                if i >= len(b):
                    return "more", out
                if b[i] != 10:
                    return "error", out
                i += 1
        take = min(size, len(b) - i)
        out += b[i:i + take]
        i += take
        if take < size:
            return "more", out
        for want in (13, 10):
            if i >= len(b):
                return "more", out
            if b[i] != want:
                return "error", out
            i += 1


def chunk_describe(b):
    status, data = chunk_ref(b)
    s = "data " + data.decode("latin1") + "\n"
    if status == "more":
        return s + "more\n"
    if status == "error":
        return s + "error\n"
    return s + f"end {status[1]}\n"


def run_harness(blob):
    p = subprocess.run([str(HARNESS)], input=blob, capture_output=True, timeout=5)
    if p.returncode != 0:
        raise RuntimeError(f"harness exited {p.returncode}")
    return p.stdout.decode("latin1")


R = b"Host: example.com\r\n"
CORPUS = [
    # (kind, message, expected first line)
    ("Q", b"GET / HTTP/1.1\r\n" + R + b"\r\n", "ok"),
    ("Q", b"GET / HTTP/1.1\r\n\r\n", "error 400"),                                   # no Host
    ("Q", b"GET / HTTP/1.1\r\n" + R + R + b"\r\n", "error 400"),                      # two Hosts
    ("Q", b"GET / HTTP/1.0\r\n\r\n", "ok"),
    ("Q", b"GET / HTTP/2.0\r\n" + R + b"\r\n", "error 505"),
    ("Q", b"GET / HTTP/1.1\n" + R + b"\r\n", "error 400"),                            # bare LF
    ("Q", b"GET / HTTP/1.1\r\n" + R + b"X: a\rb\r\n\r\n", "error 400"),               # bare CR
    ("Q", b"GET / HTTP/1.1\r\n" + R + b"X : a\r\n\r\n", "error 400"),                 # space before colon
    ("Q", b"GET / HTTP/1.1\r\n" + R + b"X: a\r\n b\r\n\r\n", "error 400"),            # obs-fold
    ("Q", b"GET / HTTP/1.1\r\n" + R + b"X: a\x00b\r\n\r\n", "error 400"),             # NUL
    ("Q", b"POST / HTTP/1.1\r\n" + R + b"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n", "error 400"),
    ("Q", b"POST / HTTP/1.1\r\n" + R + b"Transfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n", "error 400"),
    ("Q", b"POST / HTTP/1.1\r\n" + R + b"Content-Length: 5\r\nContent-Length: 6\r\n\r\n", "error 400"),
    ("Q", b"POST / HTTP/1.1\r\n" + R + b"Content-Length: 5\r\nContent-Length: 5\r\n\r\n", "ok"),
    ("Q", b"POST / HTTP/1.1\r\n" + R + b"Content-Length: 5, 5\r\n\r\n", "ok"),
    ("Q", b"POST / HTTP/1.1\r\n" + R + b"Content-Length: 5, 6\r\n\r\n", "error 400"),
    ("Q", b"POST / HTTP/1.1\r\n" + R + b"Content-Length: +5\r\n\r\n", "error 400"),
    ("Q", b"POST / HTTP/1.1\r\n" + R + b"Content-Length: 0x5\r\n\r\n", "error 400"),
    ("Q", b"POST / HTTP/1.1\r\n" + R + b"Transfer-Encoding: gzip, chunked\r\n\r\n", "error 501"),
    ("Q", b"POST / HTTP/1.1\r\n" + R + b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n", "error 400"),
    ("Q", b"POST / HTTP/1.1\r\n" + R + b"Transfer-Encoding: xchunked\r\n\r\n", "error 501"),
    ("Q", b"POST / HTTP/1.1\r\n" + R + b"Transfer-Encoding : chunked\r\n\r\n", "error 400"),
    ("Q", b"POST / HTTP/1.1\r\n" + R + b"Transfer-Encoding:\tChunked \r\n\r\n", "ok"),
    ("Q", b"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n", "error 400"),
    ("Q", b"GET /a#frag HTTP/1.1\r\n" + R + b"\r\n", "error 400"),
    ("Q", b"GET http://x/y HTTP/1.1\r\n" + R + b"\r\n", "ok"),
    ("Q", b"GET x/y HTTP/1.1\r\n" + R + b"\r\n", "error 400"),
    ("Q", b"OPTIONS * HTTP/1.1\r\n" + R + b"\r\n", "ok"),
    ("Q", b"GET / HTTP/1.1\r\nHost: a b\r\n\r\n", "error 400"),
    ("Q", b"GET / HTTP/1.1\r\nHost: user@evil\r\n\r\n", "error 400"),
    ("Q", b"GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n", "ok"),
    ("Q", b"\r\nGET / HTTP/1.1\r\n" + R + b"\r\n", "error 400"),
    ("Q", b"G\x00T / HTTP/1.1\r\n" + R + b"\r\n", "error 400"),
    ("Q", b"GET / HTTP/1.1\r\n" + R + b"Connection: host\r\n\r\n", "ok"),            # cannot hide Host
    ("S", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n", "ok"),
    ("S", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n", "error 400"),
    ("S", b"HTTP/1.1 200\r\n\r\n", "error 400"),
    ("S", b"HTTP/1.1 200 \r\n\r\n", "ok"),
    ("S", b"HTTP/1.1 099 x\r\n\r\n", "error 400"),
    ("S", b"HTTP/1.0 204 No Content\r\n\r\n", "ok"),
]

CHUNKS = [
    (b"5\r\nhello\r\n0\r\n\r\n", "end"),
    (b"5;ext=1\r\nhello\r\n0\r\nTrailer: x\r\n\r\n", "end"),
    (b"5\nhello\r\n0\r\n\r\n", "error"),          # bare LF
    (b"5\r\nhelloXX0\r\n\r\n", "error"),          # no CRLF after data
    (b"-5\r\nhello\r\n0\r\n\r\n", "error"),
    (b"1" * 16 + b"\r\n", "error"),               # too many digits
    (b"5\r\nhel", "more"),
    (b" 5\r\nhello\r\n0\r\n\r\n", "error"),
]


def mutate(rng, b):
    b = bytearray(b)
    for _ in range(rng.randint(1, 4)):
        op = rng.randrange(9)
        pos = rng.randint(0, len(b))
        if op == 0 and b:
            del b[pos:pos + rng.randint(1, 4)]
        elif op == 1:
            b[pos:pos] = rng.choice([b" ", b"\t", b"\r", b"\n", b"\r\n", b":", b",", b"\x00", b"\x7f", b"\xff"])
        elif op == 2 and b:
            b[min(pos, len(b) - 1)] = rng.randrange(256)
        elif op == 3:
            b[pos:pos] = rng.choice([b"Content-Length: 3\r\n", b"Transfer-Encoding: chunked\r\n", b"Host: h\r\n",
                                     b"Connection: close, x-a\r\n", b"X-A: 1\r\n", b"Upgrade: ws\r\n",
                                     b"Connection: upgrade\r\n", b"Expect: 100-continue\r\n",
                                     b"Content-Length: 3, 3\r\n", b"TE: trailers\r\n"])
        elif op == 4:
            b = bytearray(b.replace(b"HTTP/1.1", rng.choice([b"HTTP/1.0", b"HTTP/2.0", b"HTTP/1.x", b"http/1.1"]), 1))
        elif op == 5:
            b = bytearray(b.upper() if rng.random() < 0.5 else b.lower())
        elif op == 6:
            b[pos:pos] = b"9" * rng.randint(1, 20)
        elif op == 7:
            b = bytearray(b.replace(b"\r\n\r\n", b"\r\n" + b"X: y\r\n" * rng.randint(95, 105) + b"\r\n", 1))
        else:
            b[pos:pos] = rng.choice([b"[::1]", b"%2e", b"?", b"#", b"http://", b"*", b" "])
    return bytes(b)


def main():
    cases = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
    failures = 0
    for kind, msg, want in CORPUS:
        got = run_harness(kind.encode() + msg)
        ref = describe(kind, msg)
        first = got.splitlines()[0]
        if got != ref or first != want:
            failures += 1
            print(f"FAIL corpus {msg!r}: want {want}, got {first}" + ("" if got == ref else f"\n  asm: {got!r}\n  ref: {ref!r}"))
    for body, want in CHUNKS:
        for piece in (1, 3, 255):
            got = run_harness(b"C" + bytes([piece]) + body)
            ref = chunk_describe(body)
            if got != ref or got.splitlines()[-1].split()[0] != want:
                failures += 1
                print(f"FAIL chunk {body!r} piece {piece}:\n  asm: {got!r}\n  ref: {ref!r}")
    rng = random.Random(7)
    seeds = [(k, m) for k, m, _ in CORPUS]
    for n in range(cases):
        if rng.random() < 0.25:
            body = mutate(rng, rng.choice(CHUNKS)[0])
            blob, ref = b"C" + bytes([rng.randint(1, 255)]) + body, chunk_describe(body)
        else:
            kind, msg = rng.choice(seeds)
            msg = mutate(rng, msg)
            blob, ref = kind.encode() + msg, describe(kind, msg)
        got = run_harness(blob)
        if got != ref:
            failures += 1
            path = ROOT / "tests" / "http" / f"diff-{n}.bin"
            path.write_bytes(blob)
            print(f"FAIL differential case {n} (saved {path.name}):\n  asm: {got!r}\n  ref: {ref!r}")
            if failures > 5:
                break
    print(f"http: {'all passed' if not failures else f'{failures} failed'} ({len(CORPUS)} corpus, {cases} differential)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
