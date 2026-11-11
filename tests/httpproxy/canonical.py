#!/usr/bin/env python3
"""`canonical NAME`, on one engine (argument): www.NAME goes to NAME with a
301 (scheme, port and target kept; a body's request closes after it); with
canonical www.NAME, NAME goes to www.NAME; NAME itself, other names and an
address are served as they are; a tcp listener after it is not touched."""
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 46000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
LA, LW = BASE, BASE + 1
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


def ask(port, host, target="/a/b?x=1", body=b""):
    k = socket.create_connection(("127.0.0.1", port), 5)
    extra = b"Content-Length: %d\r\n" % len(body) if body else b""
    k.sendall(b"POST " if body else b"GET ")
    k.sendall(target.encode() + b" HTTP/1.1\r\nHost: " + host.encode() + b"\r\n" + extra + b"\r\n" + body)
    k.settimeout(3)
    d = b""
    try:
        while b"\r\n\r\n" not in d:
            x = k.recv(4096)
            if not x:
                break
            d += x
    except OSError:
        pass
    k.close()
    return d


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-canon-"))
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE} }}
http 127.0.0.1:{LA} {{ canonical example.com; route /* {{ respond 200 "here" }} }}
http 127.0.0.1:{LW} {{ canonical www.example.org; route /* {{ respond 200 "here" }} }}
tcp 127.0.0.1:{BASE + 2} {{ to 127.0.0.1:9 }}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", LA), 1).close()
                break
            except OSError:
                time.sleep(0.05)
        r = ask(LA, f"WWW.Example.com:{LA}")
        check("www.NAME: 301 to NAME, port and target kept", r.startswith(b"HTTP/1.1 301 Moved Permanently")
              and f"Location: http://example.com:{LA}/a/b?x=1\r\n".encode() in r, r)
        r = ask(LA, "www.example.com", body=b"abc")
        check("  a request with a body: and closed after", b"Location: http://example.com/a/b?x=1" in r and b"Connection: close" in r, r)
        r = ask(LA, "example.com")
        check("NAME itself: served", r.startswith(b"HTTP/1.1 200"), r)
        r = ask(LA, "other.example.net")
        check("another name: served as it is", r.startswith(b"HTTP/1.1 200"), r)
        r = ask(LA, "127.0.0.1")
        check("an address: served as it is", r.startswith(b"HTTP/1.1 200"), r)
        r = ask(LA, "www.example.com.", "/")
        check("www.NAME. (a final dot): moved too", b"Location: http://example.com/\r\n" in r, r)
        r = ask(LW, "example.org", "/z")
        check("canonical www.NAME: the apex goes to www", b"Location: http://www.example.org/z\r\n" in r, r)
        r = ask(LW, "www.example.org", "/z")
        check("  and www itself is served", r.startswith(b"HTTP/1.1 200"), r)
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no worker died", "killed" not in t and "seccomp" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"canonical {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
