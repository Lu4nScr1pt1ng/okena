#!/usr/bin/env python3
"""FastCGI and `php ROOT`, on one engine (argument), against a FastCGI responder
of the test's own (PHP-FPM's protocol: FCGI_BEGIN_REQUEST, PARAMS, STDIN; STDOUT,
STDERR, END_REQUEST; the connection kept): the params a script gets (its name and
file beneath the root, PATH_INFO, the query, the client, the fields as HTTP_*,
never HTTP_PROXY), a directory's index and its 301, a file that is there served
as files serves it (the responder not asked), anything else to the front
controller; a body, as STDIN (chunked: 411); the CGI head turned into a status
line (Status:, a Location: alone, \\n alone), a long answer and its STDERR, HEAD;
one connection kept for many requests; a unix socket."""
import hashlib
import http.client
import json
import os
import pathlib
import shutil
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
BIN = HERE.parents[1] / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 55400 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
FPM, LST, ULST = BASE, BASE + 1, BASE + 2
fails = 0
CONNS = []


def check(name, ok, detail=""):
    global fails
    print(("ok  " if ok else "FAIL"), name, detail if not ok else "", flush=True)
    fails += 0 if ok else 1


def record(t, content, pad=None):
    pad = (-len(content)) % 8 if pad is None else pad
    return struct.pack(">BBHHBB", 1, t, 1, len(content), pad, 0) + content + b"\0" * pad


def pairs(data):
    out, i = {}, 0
    while i < len(data):
        lens = []
        for _ in range(2):
            n = data[i]
            if n & 0x80:
                n = struct.unpack(">I", data[i:i + 4])[0] & 0x7FFFFFFF
                i += 4
            else:
                i += 1
            lens.append(n)
        k = data[i:i + lens[0]].decode()
        i += lens[0]
        out[k] = data[i:i + lens[1]].decode(errors="replace")
        i += lens[1]
    return out


def answer(params, stdin):
    s = params.get("SCRIPT_NAME", "")
    if s == "/status.php":
        return b"Status: 404 Not Found\r\nX-A: 1\r\nContent-Length: 4\r\n\r\nnope", b""
    if s == "/redirect.php":
        return b"Location: /elsewhere\r\n\r\n", b""
    if s == "/lf.php":
        return b"Content-Type: text/plain\nX-B: 2\n\nlf body", b""
    if s == "/big.php":
        return b"Content-Type: application/octet-stream\r\n\r\n" + bytes(range(256)) * 800, b"a warning from PHP\nmore"
    body = json.dumps({"params": params, "stdin": len(stdin), "sha": hashlib.sha256(stdin).hexdigest()}).encode()
    return b"Content-Type: application/json\r\nX-Script: " + s.encode() + b"\r\n\r\n" + body, b""


class FPMHandler(socketserver.BaseRequestHandler):
    def handle(self):
        CONNS.append(1)
        f = self.request.makefile("rb")
        while True:
            params, stdin, keep = b"", b"", False
            while True:
                h = f.read(8)
                if len(h) < 8:
                    return
                _, t, _, n, pad, _ = struct.unpack(">BBHHBB", h)
                c = f.read(n)
                f.read(pad)
                if t == 1:
                    keep = bool(c[2] & 1)
                elif t == 4:
                    params += c
                elif t == 5:
                    if n == 0:
                        break
                    stdin += c
            p = pairs(params)
            out, err = answer(p, stdin)
            data = b""
            if err:
                data += record(7, err)
            for i in range(0, len(out), 30000):          # several records, odd padding
                data += record(6, out[i:i + 30000], pad=3 if i else None)
            data += record(3, b"\0" * 8)
            self.request.sendall(data)
            if not keep:
                return


class TCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class UnixServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-fastcgi-", dir="/tmp"))
    www = tmp / "www"
    (www / "blog").mkdir(parents=True)
    (www / "sub").mkdir()
    for n in ("index.php", "app.php", "status.php", "redirect.php", "lf.php", "big.php", "blog/index.php"):
        (www / n).write_text("<?php // the responder answers for it\n")
    (www / "static.css").write_text("body { color: red }\n")
    threading.Thread(target=TCPServer(("127.0.0.1", FPM), FPMHandler).serve_forever, daemon=True).start()
    sock = tmp / "fpm.sock"
    threading.Thread(target=UnixServer(str(sock), FPMHandler).serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE}; drain delay=0s timeout=1s }}
pool fpm {{ server 127.0.0.1:{FPM}; protocol fastcgi }}
pool ufpm {{ server unix:{sock}; protocol fastcgi }}
http 127.0.0.1:{LST} {{ route /* {{ php {www}; to pool fpm }} }}
http 127.0.0.1:{ULST} {{ route /* {{ php {www}; to pool ufpm }} }}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=open(log, "w"))

    def req(method, path, body=None, headers=None, port=LST, conn=None):
        c = conn or http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        h = {"Host": "site.test"}
        h.update(headers or {})
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read()
        if not conn:
            c.close()
        return r, data

    def params(path, **kw):
        r, d = req("GET", path, **kw)
        try:
            return r, json.loads(d)
        except ValueError:
            return r, d
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", LST), 1).close()
                break
            except OSError:
                time.sleep(0.05)
        r, j = params("/app.php?x=1&y=2", headers={"X-Thing": "yes", "Proxy": "http://evil"})
        pr = j["params"] if isinstance(j, dict) else {}
        check("a script: its params", r.status == 200 and pr.get("SCRIPT_NAME") == "/app.php"
              and pr.get("SCRIPT_FILENAME") == f"{www}/app.php" and pr.get("DOCUMENT_ROOT") == str(www)
              and pr.get("QUERY_STRING") == "x=1&y=2" and pr.get("REQUEST_URI") == "/app.php?x=1&y=2"
              and pr.get("REQUEST_METHOD") == "GET" and pr.get("SERVER_PORT") == str(LST)
              and pr.get("REMOTE_ADDR") == "127.0.0.1" and pr.get("SERVER_NAME") == "site.test"
              and pr.get("HTTP_HOST") == "site.test" and pr.get("HTTP_X_THING") == "yes"
              and pr.get("GATEWAY_INTERFACE") == "CGI/1.1" and pr.get("REDIRECT_STATUS") == "200", (r.status, j))
        check("  never HTTP_PROXY (httpoxy)", "HTTP_PROXY" not in pr, pr.get("HTTP_PROXY"))
        check("  its own headers through", r.getheader("X-Script") == "/app.php", r.getheaders())
        r, j = params("/app.php/a/b")
        pr = j["params"] if isinstance(j, dict) else {}
        check("PATH_INFO after the script", pr.get("SCRIPT_NAME") == "/app.php" and pr.get("PATH_INFO") == "/a/b", pr)
        r, j = params("/blog/")
        pr = j["params"] if isinstance(j, dict) else {}
        check("a directory: its index.php", pr.get("SCRIPT_NAME") == "/blog/index.php", (r.status, j))
        r, d = req("GET", "/blog")
        check("  without its slash: 301", r.status == 301 and r.getheader("Location") == "/blog/", (r.status, r.getheaders()))
        n = len(CONNS)
        r, d = req("GET", "/static.css")
        check("a file there: served as files serves it, PHP not asked",
              r.status == 200 and d == b"body { color: red }\n" and r.getheader("X-Script") is None, (r.status, d))
        r, j = params("/no/such/page?q=1")
        pr = j["params"] if isinstance(j, dict) else {}
        check("anything else: the front controller", pr.get("SCRIPT_NAME") == "/index.php"
              and pr.get("REQUEST_URI") == "/no/such/page?q=1" and not pr.get("PATH_INFO"), (r.status, j))
        r, j = params("/missing.php")
        pr = j["params"] if isinstance(j, dict) else {}
        check("  a script that is not there: the front controller too", pr.get("SCRIPT_NAME") == "/index.php", j)
        body = os.urandom(100000)
        r, d = req("POST", "/app.php", body=body, headers={"Content-Type": "application/x-test"})
        j = json.loads(d) if r.status == 200 else {}
        check("a body: as FCGI_STDIN, its length and type",
              j.get("stdin") == len(body) and j.get("sha") == hashlib.sha256(body).hexdigest()
              and j["params"].get("CONTENT_LENGTH") == str(len(body)) and j["params"].get("CONTENT_TYPE") == "application/x-test",
              (r.status, d[:200]))
        c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
        c.putrequest("POST", "/app.php", skip_host=True)
        c.putheader("Host", "site.test")
        c.putheader("Transfer-Encoding", "chunked")
        c.endheaders()
        c.send(b"5\r\nhello\r\n0\r\n\r\n")
        r = c.getresponse()
        r.read()
        c.close()
        check("  chunked: 411", r.status == 411, r.status)
        r, d = req("GET", "/status.php")
        check("Status: 404: the status line, its fields, its body", r.status == 404 and r.getheader("X-A") == "1"
              and d == b"nope", (r.status, d, r.getheaders()))
        r, d = req("GET", "/redirect.php")
        check("a Location: alone: 302", r.status == 302 and r.getheader("Location") == "/elsewhere", (r.status, r.getheaders()))
        r, d = req("GET", "/lf.php")
        check("a head of \\n alone", r.status == 200 and r.getheader("X-B") == "2" and d == b"lf body", (r.status, d))
        r, d = req("GET", "/big.php")
        check("a long answer, in several records", r.status == 200 and d == bytes(range(256)) * 800, (r.status, len(d)))
        check("  its STDERR in the log", "fastcgi: a warning from PHP" in log.read_text(), log.read_text()[-300:])
        r, d = req("HEAD", "/app.php")
        check("HEAD: the head alone", r.status == 200 and d == b"", (r.status, d))
        n = len(CONNS)
        c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
        good = 0
        for i in range(10):
            r, j = req("GET", f"/app.php?i={i}", conn=c)
            good += r.status == 200 and json.loads(j)["params"]["QUERY_STRING"] == f"i={i}"
        c.close()
        check("ten requests: one FastCGI connection, kept", good == 10 and len(CONNS) - n <= 1, (good, len(CONNS) - n))
        r, j = params("/app.php?u=1", port=ULST)
        pr = j["params"] if isinstance(j, dict) else {}
        check("a unix socket", r.status == 200 and pr.get("QUERY_STRING") == "u=1", (r.status, j))
    except Exception as e:
        check("(no exception)", False, repr(e))
    finally:
        if os.environ.get("FCGI_DEBUG"):
            print(log.read_text()[-3000:])
        p.terminate()
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()
    t = log.read_text()
    check("no process died", "seccomp" not in t and "killed by signal" not in t and "exited with status" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"fastcgi {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


main()
