#!/usr/bin/env python3
"""The metrics address at its edges: the token (wrong, a prefix of it, longer,
in the query, Basic) refused, /live and /ready open; HEAD answered as GET with no
body; a path that is not served, or a method, 404; a silent connection closed in
two seconds; and a crowd of silent connections (more than its slots) does not
keep a health check waiting: requests are read as they come, the one waiting
longest giving way."""
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 33500 + os.getpid() % 90 * 10
M, L = BASE, BASE + 1
TOKEN = b"s3cret-token-0123456789abcd"
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


def go(raw, wait=3):
    k = socket.create_connection(("127.0.0.1", M))
    k.settimeout(wait)
    t0 = time.time()
    try:
        k.sendall(raw)
    except OSError:
        pass
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
    st = int(out[9:12]) if out.startswith(b"HTTP/1.1 ") else 0
    return st, out, time.time() - t0


def req(path, extra=b"", method=b"GET"):
    return method + b" " + path + b" HTTP/1.1\r\nHost: a\r\n" + extra + b"\r\n"


AUTH = b"Authorization: Bearer " + TOKEN + b"\r\n"


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-admedges-"))
    (tmp / "tok").write_bytes(TOKEN + b"\n")
    conf = tmp / "okena.conf"
    conf.write_text(f"okena {{ workers 1; metrics 127.0.0.1:{M} token={tmp}/tok }}\n"
                    f"http 127.0.0.1:{L} {{ route /* {{ respond 404 }} }}\n")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", M), 1).close()
                break
            except OSError:
                time.sleep(0.05)
        check("/live without the token: 200", go(req(b"/live"))[0] == 200)
        check("/metrics with it: 200", go(req(b"/metrics", AUTH))[0] == 200)
        for name, extra in (("none", b""), ("wrong", b"Authorization: Bearer " + TOKEN[:-1] + b"X\r\n"),
                            ("a prefix", b"Authorization: Bearer " + TOKEN[:6] + b"\r\n"),
                            ("longer", b"Authorization: Bearer " + TOKEN + b"XX\r\n"), ("Basic, wrong", b"Authorization: Basic czNj\r\n")):
            check(f"/metrics, token {name}: 401", go(req(b"/metrics", extra))[0] == 401)
        check("/metrics, the token in the query: 401", go(req(b"/metrics?token=" + TOKEN))[0] == 401)
        st, out, _ = go(req(b"/live", method=b"HEAD"))
        check("HEAD /live: 200, the head alone", st == 200 and out.endswith(b"\r\n\r\n"), out)
        st, out, _ = go(req(b"/status", AUTH, method=b"HEAD"))
        check("HEAD /status: 200, no body", st == 200 and out.endswith(b"\r\n\r\n") and b"Content-Length" in out, out[-80:])
        check("a path not served: 404", go(req(b"/../etc/passwd", AUTH))[0] == 404)
        check("DELETE /live: 404", go(req(b"/live", method=b"DELETE"))[0] == 404)
        st, out, took = go(b"", wait=5)
        check("a silent connection: closed in two seconds", out == b"" and 1.5 < took < 3.5, took)
        crowd = []
        for _ in range(400):                    # past the slots (128)
            try:
                crowd.append(socket.create_connection(("127.0.0.1", M), timeout=1))
            except OSError:
                break
        st, out, took = go(req(b"/ready"))
        check(f"{len(crowd)} silent connections held: /ready answered at once", st == 200 and took < 1, (st, took))
        for c in crowd:
            c.close()
        check("still answering after them", go(req(b"/live"))[0] == 200)
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no process died", "killed" not in t and "seccomp" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print("admin edges: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
