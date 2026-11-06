#!/usr/bin/env python3
"""`files` on a route, on one engine (argument). First that nothing outside the root
is reached, by any path a client can write, or a link can make; then that it serves:
types, validators, ranges, compressed variants, a single-page app's fallback."""
import email.utils
import hashlib
import http.client
import os
import pathlib
import random
import socket
import stat
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
BIN = HERE.parents[1] / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 11000 + os.getpid() % 90 * 4 + (2 if ENGINE == "epoll" else 0)	# ports 11000-11360: this suite's own
LST, TLS = BASE, BASE + 1
fails = 0
BIG = random.Random(3).randbytes(1 << 21)


def check(name, ok, more=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {more}"), flush=True)
    fails += 0 if ok else 1


def get(path, method="GET", **hdr):
    c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
    c.putrequest(method, path, skip_accept_encoding=True, skip_host=False)
    for k, v in hdr.items():
        c.putheader(k.replace("_", "-"), v)
    c.endheaders()
    r = c.getresponse()
    b = r.read()
    c.close()
    return r.status, b, {k.lower(): v for k, v in r.getheaders()}


def raw(line):
    """a request as written, not as a library would clean it"""
    s = socket.create_connection(("127.0.0.1", LST), 3)
    s.settimeout(3)
    s.sendall(line.encode() + b"\r\nHost: x\r\nConnection: close\r\n\r\n")
    d = b""
    try:
        while True:
            x = s.recv(65536)
            if not x:
                break
            d += x
    except OSError:
        pass
    s.close()
    return int(d.split()[1]) if d else 0, d


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-files."))
    root, spa = tmp / "root", tmp / "spa"
    root.mkdir()
    spa.mkdir()
    (tmp / "secret.txt").write_text("the secret outside\n")
    (root / "index.html").write_text("<h1>home</h1>")
    (root / "a.css").write_text("body{}")
    (root / "UP.PNG").write_bytes(b"\x89PNG")
    (root / "noext").write_text("n")
    (root / "weird.xyz").write_text("x")
    (root / "with space.txt").write_text("spaced")
    (root / "empty.txt").write_text("")
    (root / "big.bin").write_bytes(BIG)
    (root / "sub").mkdir()
    (root / "sub" / "index.html").write_text("sub index")
    (root / "noindex").mkdir()
    (root / ".env").write_text("TOKEN=1")
    (root / ".git").mkdir()
    (root / ".git" / "config").write_text("[core]")
    (root / "sub" / ".hidden").write_text("h")
    (root / ".well-known").mkdir()
    (root / ".well-known" / "acme").write_text("challenge")
    os.symlink(tmp / "secret.txt", root / "abs-link")
    os.symlink("../secret.txt", root / "rel-link")
    os.symlink("a.css", root / "in-link")
    os.symlink(str(tmp), root / "out-dir")
    os.mkfifo(root / "fifo")
    (root / "c.js").write_text("plain js")
    (root / "c.js.gz").write_bytes(b"GZ!")
    (root / "c.js.br").write_bytes(b"BR!")
    (root / "c.js.zst").write_bytes(b"ZS!")
    (root / "nogz.js").write_text("only plain")
    (spa / "index.html").write_text("<app>")
    (spa / "app.js").write_text("js")
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 2; io_engine {ENGINE} }}
http 127.0.0.1:{LST} {{
    route /spa/* {{ files {tmp}/spa2 fallback=/index.html }}
    route /pre/* {{ files {root} precompressed=br,zst,gz cache=immutable }}
    route /cached/* {{ files {root} cache=1h }}
    route /* {{ files {root} }}
}}
http 127.0.0.1:{TLS} {{
    tls {{ cert {tmp}/c.pem; key {tmp}/k.pem }}
    http2 on
    http3 on
    route /* {{ files {root} }}
}}
""")
    (tmp / "spa2").mkdir()
    (tmp / "spa2" / "spa").mkdir()
    (tmp / "spa2" / "index.html").write_text("<app>")
    (tmp / "spa2" / "spa" / "app.js").write_text("js")
    (root / "pre").mkdir()
    (root / "pre" / "c.js").write_text("plain js")
    (root / "pre" / "c.js.gz").write_bytes(b"GZ!")
    (root / "pre" / "c.js.br").write_bytes(b"BR!")
    (root / "pre" / "c.js.zst").write_bytes(b"ZS!")
    (root / "pre" / "n.js").write_text("only plain")
    (root / "cached").mkdir()
    (root / "cached" / "x.txt").write_text("c")
    subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", tmp / "k.pem"], check=True)
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", tmp / "k.pem", "-subj", "/CN=localhost", "-days", "2", "-out", tmp / "c.pem"], check=True)
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for i in range(50):
            try:
                socket.create_connection(("127.0.0.1", LST), 1).close()
                break
            except OSError:
                time.sleep(0.1)
        # out of the root
        secret = b"the secret outside"
        for path in ("/../secret.txt", "/%2e%2e/secret.txt", "/.%2e/secret.txt", "/sub/../../secret.txt", "/sub/%2e%2e/%2e%2e/secret.txt",
                     "//../secret.txt", "/..%2fsecret.txt", "/..%5csecret.txt", "/%252e%252e/secret.txt", "/sub/..%00/secret.txt",
                     "/abs-link", "/rel-link", "/out-dir/secret.txt", str(tmp / "secret.txt")):
            st, d = raw(f"GET {path} HTTP/1.1")
            check(f"outside: {path[:32]}", st in (400, 404) and secret not in d, (st, d[:80]))
        for what, path in ((".env", "/.env"), (".git", "/.git/config"), ("deeper", "/sub/.hidden"), ("encoded", "/%2eenv"), ("encoded deeper", "/.git%2fconfig")):
            st, d = raw(f"GET {path} HTTP/1.1")
            check(f"dot name, {what}: not served", st in (400, 404) and b"TOKEN" not in d and b"core" not in d, (st, d[:60]))
        check(".well-known is", get("/.well-known/acme")[:2] == (200, b"challenge"))
        t = time.time()
        check("a FIFO: refused, at once, not waited on", get("/fifo")[0] == 404 and time.time() - t < 1, time.time() - t)
        check("a link that stays inside is fine", get("/in-link")[:2] == (200, b"body{}"))

        r = get("/a.css")
        check("a file, its type, its length", r[:2] == (200, b"body{}") and r[2]["content-type"].startswith("text/css") and r[2]["content-length"] == "6", r[2])
        check("  the case of an extension does not count", get("/UP.PNG")[2]["content-type"] == "image/png")
        check("  no extension, or an unknown one", get("/noext")[2]["content-type"] == "application/octet-stream" and get("/weird.xyz")[2]["content-type"] == "application/octet-stream")
        check("a space in a name", get("/with%20space.txt")[:2] == (200, b"spaced"))
        check("an empty file", get("/empty.txt")[:2] == (200, b""))
        check("the index", get("/")[:2] == (200, b"<h1>home</h1>") and get("/sub/")[1] == b"sub index")
        r = get("/sub?x=1")
        check("a directory with no slash: there", r[0] == 301 and r[2]["location"] == "/sub/?x=1", r[:3])
        check("  no index: 404", get("/noindex/")[0] == 404)
        check("nothing there: 404", get("/nosuch")[0] == 404)
        r = get("/a.css", "HEAD")
        check("HEAD", r[0] == 200 and r[1] == b"" and r[2]["content-length"] == "6", r)
        c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
        c.request("POST", "/a.css", body=b"x")
        r = c.getresponse()
        r.read()
        check("POST: 405, and what is allowed", r.status == 405 and "GET" in r.getheader("allow", ""), r.status)
        c.close()
        r = get("/big.bin")
        check("2 MiB, byte for byte", hashlib.sha256(r[1]).digest() == hashlib.sha256(BIG).digest(), len(r[1]))
        c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
        ok = True
        for i in range(4):
            c.request("GET", "/a.css")
            ok &= c.getresponse().read() == b"body{}"
        check("one connection, many files", ok)
        c.close()

        # validators
        r = get("/a.css")
        e, lm = r[2]["etag"], r[2]["last-modified"]
        check("Last-Modified is a real date", email.utils.parsedate_to_datetime(lm).timestamp() == int(os.stat(root / "a.css").st_mtime), lm)
        check("If-None-Match: 304, no body", get("/a.css", If_None_Match=e)[:2] == (304, b""))
        r = get("/a.css", If_None_Match=e)
        check("  it says the same tag", r[2].get("etag") == e, r[2])
        check("  weak, and in a list", get("/a.css", If_None_Match=f'"x", W/{e}')[0] == 304)
        check("  another: 200", get("/a.css", If_None_Match='"nope"')[0] == 200)
        check("  *", get("/a.css", If_None_Match="*")[0] == 304)
        check("If-Modified-Since", get("/a.css", If_Modified_Since=lm)[0] == 304)
        check("  If-None-Match wins", get("/a.css", If_None_Match='"nope"', If_Modified_Since=lm)[0] == 200)
        time.sleep(1.1)
        (root / "a.css").write_text("body{x}")
        check("a file that changed has another tag", get("/a.css", If_None_Match=e)[:2] == (200, b"body{x}"))

        # ranges
        n = len(BIG)
        r = get("/big.bin", Range="bytes=100-199")
        check("a range", r[0] == 206 and r[1] == BIG[100:200] and r[2]["content-range"] == f"bytes 100-199/{n}", r[0::2])
        check("  to the end", get("/big.bin", Range=f"bytes={n - 5}-")[1] == BIG[-5:])
        check("  the last N", get("/big.bin", Range="bytes=-7")[1] == BIG[-7:])
        check("  past the end is cut", get("/big.bin", Range=f"bytes={n - 2}-{n + 100}")[1] == BIG[-2:])
        check("  all of it, bigger than N", get("/a.css", Range="bytes=-1000")[0] == 206)
        check("  1 MiB in", get("/big.bin", Range="bytes=1048576-3145727")[1] == BIG[1048576:])
        r = get("/big.bin", Range=f"bytes={n}-")
        check("  none of it: 416", r[0] == 416 and r[2]["content-range"] == f"bytes */{n}", r[0::2])
        check("  several: the whole file", get("/a.css", Range="bytes=0-0,2-3")[0] == 200)
        check("  nonsense: the whole file", get("/a.css", Range="bytes=a-b")[0] == 200 and get("/a.css", Range="lines=1-2")[0] == 200)
        r = get("/big.bin")
        check("If-Range, its tag: the range", get("/big.bin", Range="bytes=0-1", If_Range=r[2]["etag"])[0] == 206)
        check("  another: all of it", len(get("/big.bin", Range="bytes=0-1", If_Range='"x"')[1]) == n)
        check("HEAD with a range", get("/big.bin", "HEAD", Range="bytes=0-9")[1] == b"")

        # compressed variants
        r = get("/pre/c.js", Accept_Encoding="gzip")
        check("gz on disk", r[1] == b"GZ!" and r[2].get("content-encoding") == "gzip" and r[2]["content-type"].startswith("text/javascript"), r[0::2])
        check("  it varies", r[2].get("vary") == "Accept-Encoding")
        check("  it has its own tag", r[2]["etag"] != get("/pre/c.js")[2]["etag"])
        check("  the order configured", get("/pre/c.js", Accept_Encoding="gzip, zstd, br")[1] == b"BR!")
        check("  zstd", get("/pre/c.js", Accept_Encoding="gzip, zstd")[1] == b"ZS!")
        check("  q=0 says no", get("/pre/c.js", Accept_Encoding="br;q=0, gzip")[1] == b"GZ!")
        check("  a name inside another is not it", get("/pre/c.js", Accept_Encoding="xbr, gzipped")[1] == b"plain js")
        check("  none: the file", get("/pre/c.js")[1] == b"plain js" and "content-encoding" not in get("/pre/c.js")[2])
        check("  none on disk: the file", get("/pre/n.js", Accept_Encoding="gzip")[1] == b"only plain")
        r = get("/pre/c.js", Accept_Encoding="gzip", Range="bytes=0-0")
        check("  no ranges of a variant", r[0] == 200 and r[1] == b"GZ!", r[:2])
        check("cache=immutable", "immutable" in get("/pre/n.js")[2]["cache-control"])
        check("cache=1h", get("/cached/x.txt")[2]["cache-control"] == "public, max-age=3600")

        # a single-page app
        check("fallback: a client route gets the app", get("/spa/users/7")[:2] == (200, b"<app>"))
        check("  a real file is itself", get("/spa/app.js")[:2] == (200, b"js"))
        for i in range(3):
            q = subprocess.run(["timeout", "--foreground", "8", "curl", "-q", "-sk", "--http2", "-o", "-", "-w", " %{http_code} %{http_version}", f"https://localhost:{TLS}/sub/"], capture_output=True, text=True)
        check("over HTTP/2", q.stdout == "sub index 200 2", q.stdout)
        q = subprocess.run(["timeout", "8", str(BIN), "bench", f"https://127.0.0.1:{TLS}/big.bin", "proto=h3", "conns=2", "workers=1", "rate=40", "duration=1s", "warmup=0s", "format=kv"],
                           capture_output=True, text=True, stdin=subprocess.DEVNULL)
        kv = dict(x.split("=", 1) for x in q.stdout.split() if "=" in x)
        check("over HTTP/3", kv.get("errors") == "0" and int(kv.get("ok", 0)) > 0, q.stdout[:100])

        # no descriptor stays
        wpid = int(subprocess.run(["pgrep", "-P", str(p.pid)], capture_output=True, text=True).stdout.split()[0])
        kids = subprocess.run(["pgrep", "-P", str(p.pid), "okena-worker"], capture_output=True, text=True).stdout.split()
        before = [len(os.listdir(f"/proc/{k}/fd")) for k in kids]
        for i in range(300):
            get("/a.css")
            if i % 30 == 0:
                s = socket.create_connection(("127.0.0.1", LST))
                s.sendall(b"GET /big.bin HTTP/1.1\r\nHost: x\r\n\r\n")
                s.recv(100)
                s.close()
        time.sleep(0.3)
        after = [len(os.listdir(f"/proc/{k}/fd")) for k in kids]
        check("no descriptor stays, nor from clients that left", after == before, (before, after))
    finally:
        p.terminate()
        p.wait(10)
    check("no worker died", "killed" not in log.read_text() and "restarting" not in log.read_text(), log.read_text()[-300:])
    c = tmp / "bad.conf"
    for what, line in (("a root that is not there", f"files {tmp}/nosuch"), ("a relative root", "files root"),
                       ("a bad variant", f"files {root} precompressed=lz4"), ("a fallback with no slash", f"files {root} fallback=x")):
        c.write_text(f"http 127.0.0.1:{LST} {{ route /* {{ {line} }} }}\n")
        q = subprocess.run(["timeout", "5", str(BIN), "-c", str(c)], capture_output=True, text=True, timeout=8)
        check(f"{what}: refused", q.returncode not in (0, 124) and q.stderr != "", f"{q.returncode} {q.stderr[-140:]}")
    print(f"files {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
