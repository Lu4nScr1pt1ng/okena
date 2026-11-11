#!/usr/bin/env python3
"""Who the client is, and the fields that say so, on one engine (argument). From a
peer that is not in trusted_proxies, nothing the client claims about itself reaches
the backend (X-Forwarded-*, Forwarded, X-Real-IP, True-Client-IP, CF-Connecting-IP,
its X-Request-Id): okena writes its own. From a trusted one, the chain is extended
and the client is its rightmost untrusted address (ports, brackets, IPv4-mapped,
several lines, empty entries; an entry that is no address stops the walk), its other
fields kept. ${client.ip} in RFC 5952's form. A redirect built from the path cannot
be given a CR/LF or another host."""
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 29500 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
B, LU, LT = BASE, BASE + 1, BASE + 2
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


def backend():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", B))
    s.listen(128)

    def one(c):
        d = b""
        while b"\r\n\r\n" not in d:
            x = c.recv(65536)
            if not x:
                c.close()
                return
            d += x
        body = b"\n".join(x for x in d.split(b"\r\n")[1:] if x)
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
        c.close()
    while True:
        c, _ = s.accept()
        threading.Thread(target=one, args=(c,), daemon=True).start()


def go(port, extra=b"", target="/t"):
    k = socket.create_connection(("127.0.0.1", port))
    k.settimeout(3)
    k.sendall(b"GET " + target.encode() + b" HTTP/1.1\r\nHost: a.test\r\n" + extra + b"Connection: close\r\n\r\n")
    out = b""
    try:
        while True:
            x = k.recv(65536)
            if not x:
                break
            out += x
    except OSError:
        pass
    k.close()
    head, _, body = out.partition(b"\r\n\r\n")
    fields = {}
    lines = body.split(b"\n") if head.startswith(b"HTTP/1.1 200") else head.split(b"\r\n")[1:]
    for x in lines:
        n, _, v = x.partition(b":")
        fields.setdefault(n.strip().lower().decode(), []).append(v.strip().decode())
    return int(head[9:12] or 0), fields


CLAIMS = b"X-Forwarded-For: 1.2.3.4\r\nX-Forwarded-Proto: https\r\nX-Forwarded-Host: evil.test\r\nForwarded: for=1.2.3.4\r\n" \
         b"X-Real-IP: 1.2.3.4\r\nTrue-Client-IP: 1.2.3.4\r\nCF-Connecting-IP: 1.2.3.4\r\nX-Request-Id: abc-123\r\n"

# X-Forwarded-For from a trusted peer: the client okena takes from it
CHAINS = [
    ("1.2.3.4", "1.2.3.4"), ("1.2.3.4, 10.0.0.1", "10.0.0.1"), ("10.0.0.1, 127.0.0.9", "10.0.0.1"),
    ("unknown", "127.0.0.1"), ("1.2.3.4:5678", "1.2.3.4"), ("[2001:db8::1]:443", "2001:db8::1"),
    ("::ffff:1.2.3.4", "1.2.3.4"), ("1.2.3.4,,5.6.7.8", "5.6.7.8"), ("", "127.0.0.1"),
    ("2001:db8:0:1:0:0:0:1", "2001:db8:0:1::1"), ("1:0:0:2:0:0:3:4", "1::2:0:0:3:4"), ("fe80::", "fe80::"),
    ("0:0:0:0:0:0:0:0", "::"), ("2001:DB8::ABCD", "2001:db8::abcd"), ("1:0:2:3:4:5:6:7", "1:0:2:3:4:5:6:7"),
]


def main():
    threading.Thread(target=backend, daemon=True).start()
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-identity-"))
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE} }}
pool b {{ server 127.0.0.1:{B} }}
http 127.0.0.1:{LU} {{
    route /r/* {{ redirect 302 "https://{{host}}{{path}}" }}
    route /* {{ header set x-client "${{client.ip}}"; to pool b }}
}}
http 127.0.0.1:{LT} {{
    trusted_proxies 127.0.0.0/8
    route /* {{ header set x-client "${{client.ip}}"; to pool b }}
}}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", LT), 1).close()
                break
            except OSError:
                time.sleep(0.05)
        st, f = go(LU, CLAIMS)
        check("untrusted peer: what it claims is dropped, okena's own written",
              st == 200 and f.get("x-forwarded-for") == ["127.0.0.1"] and f.get("x-forwarded-proto") == ["http"]
              and f.get("x-client") == ["127.0.0.1"] and "x-forwarded-host" not in f
              and not {"forwarded", "x-real-ip", "true-client-ip", "cf-connecting-ip"} & set(f)
              and re.fullmatch(r"[0-9a-f]{16}", (f.get("x-request-id") or [""])[0]) is not None, f)
        st, f = go(LT, CLAIMS)
        check("trusted peer: its fields kept, the chain extended",
              f.get("x-forwarded-for") == ["1.2.3.4, 127.0.0.1"] and f.get("x-forwarded-proto") == ["https"]
              and f.get("x-forwarded-host") == ["evil.test"] and f.get("forwarded") == ["for=1.2.3.4"]
              and f.get("x-real-ip") == ["1.2.3.4"] and f.get("true-client-ip") == ["1.2.3.4"]
              and f.get("cf-connecting-ip") == ["1.2.3.4"] and f.get("x-request-id") == ["abc-123"]
              and f.get("x-client") == ["1.2.3.4"], f)
        st, f = go(LT, b"X-Request-Id: has space\r\n")
        check("  an X-Request-Id that is not one: replaced", f.get("x-request-id") != ["has space"], f)
        st, f = go(LT, b"X-Forwarded-For: 1.2.3.4\r\nX-Forwarded-For: 5.6.7.8\r\n")
        check("  two X-Forwarded-For lines: one chain, in order", f.get("x-client") == ["5.6.7.8"]
              and f.get("x-forwarded-for") == ["1.2.3.4, 5.6.7.8, 127.0.0.1"], f)
        for chain, client in CHAINS:
            st, f = go(LT, b"X-Forwarded-For: " + chain.encode() + b"\r\n")
            check(f"  X-Forwarded-For: {chain!r}: the client is {client}", f.get("x-client") == [client], f.get("x-client"))
        for target in ("/r/a%0D%0ALocation:x", "/r/a%0d%0aSet-Cookie:x", "/r/%2F%2Fevil.test"):
            st, f = go(LU, b"", target)
            check(f"redirect from {target}: 400", st == 400, (st, f))
        st, f = go(LU, b"", "/r//evil.test/x")
        check("redirect from //evil.test: stays on the host", st == 302 and f.get("location") == ["https://a.test/r/evil.test/x"], f)
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no worker died", "killed" not in t and "seccomp" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"identity {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
