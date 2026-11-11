#!/usr/bin/env python3
"""Paths, hosts and routing, on one engine (argument): which route each request
reaches (or 400/403/404), and that the target forwarded is the one the client sent.
Dot segments raw or encoded, encoded '/' and '\\', NUL, bad escapes, overlong UTF-8
and ".." hidden behind a segment parameter ("..;") are refused; unreserved
characters escaped, "//" and segment parameters (";jsessionid") do not get past a
route that denies (/%61dmin, //admin, /admin;x/y are /admin); the Host in any case,
with a port or a trailing dot; wildcard hosts; an unknown host to the default."""
import os
import pathlib
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
BASE = 29000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
L = BASE
PORTS = {"A": BASE + 1, "B": BASE + 2, "C": BASE + 3, "D": BASE + 4, "E": BASE + 5}
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


def backend(tag, port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(128)

    def one(c):
        d = b""
        while b"\r\n\r\n" not in d:
            x = c.recv(65536)
            if not x:
                c.close()
                return
            d += x
        body = tag.encode() + b" " + d.split(b"\r\n")[0].split(b" ")[1]
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
        c.close()

    def loop():
        while True:
            c, _ = s.accept()
            threading.Thread(target=one, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()


def go(target, host="example.com"):
    k = socket.create_connection(("127.0.0.1", L))
    k.settimeout(3)
    k.sendall(b"GET " + target.encode() + b" HTTP/1.1\r\nHost: " + host.encode("utf-8") + b"\r\nConnection: close\r\n\r\n")
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
    st = int(out.split(b" ")[1]) if out.startswith(b"HTTP/1.1 ") else 0
    return st, out.partition(b"\r\n\r\n")[2]


# (target, host or None, what: a pool's letter, or a status)
CASES = [
    ("/a", None, "A"), ("/a/", None, "B"), ("/a?q=1", None, "A"), ("/a/?q", None, "B"), ("/x/y", None, "C"),
    ("/x", None, 404), ("/x/", None, "C"), ("/X/y", None, 404), ("/x//y", None, "C"),
    ("/x/./y", None, 400), ("/x/a/../y", None, 400), ("/x/../a", None, 400), ("/x/..", None, 400), ("/x/%2e", None, 400),
    ("/x/%2e%2e/a", None, 400), ("/x/%2E/y", None, 400), ("/x/%2Fy", None, 400), ("/x/%2fy", None, 400),
    ("/x/a%2F..%2Fb", None, 400), ("/x/%00", None, 400), ("/x/%zz", None, 400), ("/x/%4", None, 400),
    ("/x/%C0%AE%C0%AE/a", None, 400), ("/x/%c1%9c", None, 400), ("/x/%E0%80%AE", None, 400), ("/x/%F0%80%80%AE", None, 400),
    ("/x/%E2%82%AC", None, "C"), ("/x/%F0%9F%98%80", None, "C"), ("/x/%E0%A4%85", None, "C"), ("/x/caf%c3%a9", None, "C"),
    ("/x/%FF", None, "C"), ("/x/%25", None, "C"), ("/x/y?a=1&a=2&b&=c", None, "C"),
    ("/x/;p=1/y", None, "C"), ("/x/y;jsessionid=1", None, "C"), ("/x;a=b/y", None, "C"), ("/a;b", None, "A"),
    ("/x/..;/admin/y", None, 400), ("/x/.;/y", None, 400),
    # a route that denies, and the ways around it
    ("/admin/x", None, 403), ("/admin", None, 403), ("/admin/", None, 403), ("/admin?x", None, 403),
    ("/%61dmin/x", None, 403), ("/%61%64%6d%69%6e/x", None, 403), ("//admin/x", None, 403),
    ("/admin;x/y", None, 403), ("/admin;/y", None, 403),
    ("/admin%2fx", None, 400), ("/admin%2F", None, 400), ("/admin#", None, 400), ("/admin/%2e%2e/x/y", None, 400),
    ("/x/%2e%2e/admin/y", None, 400), ("/x/..%2fadmin", None, 400), ("/x/%5c..%5cadmin", None, 400),
    ("/ADMIN/x", None, 404), ("/%41dmin/x", None, 404), ("/%2561dmin/x", None, 404), ("/admin%20/x", None, 404),
    ("/admin./x", None, 404),
    # hosts
    ("/a", "EXAMPLE.COM", "A"), ("/a", "example.com:80", "A"), ("/a", "example.com.", "A"), ("/a", "example.com:65536", 400),
    ("/a", "example.com::80", 400), ("/q", "a.wild.test", "D"), ("/q", "a.b.wild.test", "D"), ("/q", "wild.test", "E"),
    ("/q", "unknown.test", "E"), ("/q", "[::1]", "E"), ("/q", "[::1]:80", "E"), ("/q", "127.0.0.1", "E"),
    ("/q", "xn--caf-dma.test", "E"), ("/q", "café.test", 400), ("/a", "example.com, evil.com", 400),
]


def main():
    for t, port in PORTS.items():
        backend(t, port)
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-routing-"))
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE} }}
pool pa {{ server 127.0.0.1:{PORTS['A']} }}
pool pb {{ server 127.0.0.1:{PORTS['B']} }}
pool pc {{ server 127.0.0.1:{PORTS['C']} }}
pool pd {{ server 127.0.0.1:{PORTS['D']} }}
pool pe {{ server 127.0.0.1:{PORTS['E']} }}
http 127.0.0.1:{L} {{
    host example.com {{
        route /a {{ to pool pa }}
        route /a/ {{ to pool pb }}
        route /x/* {{ to pool pc }}
        route /admin/* {{ respond 403 }}
        route /admin {{ respond 403 }}
    }}
    host *.wild.test {{ route /* {{ to pool pd }} }}
    route /* {{ to pool pe }}
}}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", L), 1).close()
                break
            except OSError:
                time.sleep(0.05)
        got = {}

        def one(i, target, host):
            got[i] = go(target, host or "example.com")
        ts = [threading.Thread(target=one, args=(i, t, h)) for i, (t, h, _) in enumerate(CASES)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        for i, (target, host, want) in enumerate(CASES):
            st, body = got[i]
            where = f"{target}" + (f" (Host: {host})" if host else "")
            if isinstance(want, str):
                # the pool, and the target as the client sent it
                check(f"{where}: pool {want}", st == 200 and body == want.encode() + b" " + target.encode(), (st, body[:60]))
            else:
                check(f"{where}: {want}", st == want, (st, body[:60]))
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no worker died", "killed" not in t and "seccomp" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"routing {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
