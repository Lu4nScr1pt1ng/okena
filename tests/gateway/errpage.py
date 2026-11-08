#!/usr/bin/env python3
"""`errors` on one engine (argument): okena's own errors answered with a
page of one's own (by status and class, the route's before its listener's),
a backend's errors replaced with `backend` (its status kept, its body never
reaching the client), the page's type and placeholders, HEAD, HTTP/2, a
reload, and what the configuration refuses."""
import http.client
import http.server
import json
import os
import pathlib
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 37000 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
LST, TLSL, BACK = BASE, BASE + 1, BASE + 2
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok  " if ok else "FAIL"), name, detail if not ok else "", flush=True)
    fails += 0 if ok else 1


def until(fn, seconds=8):
    t = time.time()
    while time.time() - t < seconds:
        try:
            if fn():
                return True
        except OSError:
            pass
        time.sleep(0.05)
    return False


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        code = 500 if "boom" in self.path else 403 if "deny" in self.path else 200
        body = b"SECRET backend trace" if code != 200 else b"fine"
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
    do_HEAD = do_GET

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, *a):
        pass


def req(path, method="GET", port=LST):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request(method, path)
    r = c.getresponse()
    b = r.read()
    c.close()
    return r.status, {k.lower(): v for k, v in r.getheaders()}, b


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-errpage-", dir="/tmp"))
    threading.Thread(target=S(("127.0.0.1", BACK), H).serve_forever, daemon=True).start()
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", tmp / "k.pem",
                    "-out", tmp / "c.pem", "-subj", "/CN=localhost", "-days", "2"], check=True, capture_output=True)
    (tmp / "down.html").write_text("<h1>{status} {reason}</h1><p>ref {request_id}</p>\n")
    (tmp / "api.json").write_text('{"error":{status},"reason":"{reason}","id":"{request_id}"}\n')
    (tmp / "nf.txt").write_text("nothing here ({status})\n")
    (tmp / "four.html").write_text("<p>client error {status}</p>\n")
    conf = tmp / "okena.conf"
    good = f"""okena {{ workers 2; io_engine {ENGINE} }}
pool gone {{ server 127.0.0.1:1 }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{LST} {{
    errors 502 503 504 file={tmp}/down.html
    errors 404 file={tmp}/nf.txt
    route /api/* {{ errors 5xx backend file={tmp}/api.json; to pool b }}
    route /gone/* {{ to pool gone }}
    route /web/* {{ errors 4xx backend file={tmp}/four.html; to pool b }}
    route /other/* {{ errors 500 file={tmp}/down.html; to pool b }}
}}
http 127.0.0.1:{TLSL} {{
    tls {{ cert {tmp}/c.pem; key {tmp}/k.pem }}
    http2 on
    errors 5xx file={tmp}/down.html
    route /* {{ to pool gone }}
}}
"""
    conf.write_text(good)
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        check("okena starts", until(lambda: req("/other/x")[0] == 200), log.read_text()[-300:])

        # okena's own error, the listener's page
        st, h, b = req("/gone/x")
        rid = h.get("x-request-id", "")
        check("okena's 502: the listener's page, filled in", st == 502 and b == f"<h1>502 Bad Gateway</h1><p>ref {rid}</p>\n".encode()
              and len(rid) == 16, (st, b))
        check("  as HTML, never cached, its length right", h.get("content-type") == "text/html; charset=utf-8"
              and h.get("cache-control") == "no-store" and int(h.get("content-length", -1)) == len(b), h)
        st, h, b = req("/gone/x", "HEAD")
        check("  HEAD: the head alone, the length the page's", st == 502 and b == b"" and int(h.get("content-length", -1)) == len(
            f"<h1>502 Bad Gateway</h1><p>ref {h.get('x-request-id')}</p>\n"), h)
        st, h, b = req("/nowhere")
        check("no route: the 404 page, as text", st == 404 and h.get("content-type") == "text/plain; charset=utf-8" and b == b"nothing here (404)\n",
              (st, h.get("content-type"), b))

        # a backend's errors, replaced where `backend` says so
        st, h, b = req("/api/boom")
        doc = json.loads(b) if b.startswith(b"{") else {}
        check("a backend's 500 under `backend`: its status, our page", st == 500 and h.get("content-type") == "application/json"
              and doc == {"error": 500, "reason": "Internal Server Error", "id": h.get("x-request-id")}, (st, b))
        check("  its body never reaches the client", b"SECRET" not in b)
        nxt = req("/api/fine")
        check("  and the next request goes on (the upstream connection was not kept)", (nxt[0], nxt[2]) == (200, b"fine"), nxt)
        st, h, b = req("/web/deny")
        check("  a class: 4xx, a 403 too", st == 403 and b == b"<p>client error 403</p>\n", (st, b))
        st, h, b = req("/other/boom")
        check("a page for 500 without `backend`: the backend's 500 as it sent it", st == 500 and b == b"SECRET backend trace", (st, b))
        st, h, b = req("/api/deny")
        check("  nor a status the page is not for", st == 403 and b == b"SECRET backend trace", (st, b))

        # over HTTP/2
        q = subprocess.run(["timeout", "8", "curl", "-q", "-sk", "--http2", "-w", "\n%{http_version} %{http_code} %{content_type}",
                            f"https://localhost:{TLSL}/x"], capture_output=True, text=True)
        body, _, tail = q.stdout.rpartition("\n")
        check("over HTTP/2: the page", tail == "2 502 text/html; charset=utf-8" and body.startswith("<h1>502 Bad Gateway</h1>"), q.stdout[-200:])

        # a reload: the new page
        (tmp / "down2.html").write_text("<p>new page {status}</p>\n")
        conf.write_text(good.replace(f"errors 502 503 504 file={tmp}/down.html", f"errors 502 503 504 file={tmp}/down2.html"))
        p.send_signal(signal.SIGHUP)
        check("a reload: the new page", until(lambda: req("/gone/x")[2] == b"<p>new page 502</p>\n"), req("/gone/x"))
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no process died", "seccomp" not in t and "killed by signal" not in t, t[-300:])

    def bad(what, line):
        g = tmp / "bad.conf"
        g.write_text(f"pool b {{ server 127.0.0.1:1 }}\nhttp 127.0.0.1:1 {{ {line}; route /* {{ to pool b }} }}\n")
        r = subprocess.run([str(BIN), "check", str(g)], capture_output=True, text=True, timeout=10)
        check(f"{what}: refused", r.returncode != 0, r.stderr[-200:])
    (tmp / "big.html").write_text("x" * (17 << 10))
    bad("a status that is not one", f"errors 600 file={tmp}/down.html")
    bad("a class that is not one", f"errors 6xx file={tmp}/down.html")
    bad("a 2xx", f"errors 200 file={tmp}/down.html")
    bad("no file", "errors 502")
    bad("a file that is not there", f"errors 502 file={tmp}/nothing.html")
    bad("a page over 16 KiB", f"errors 502 file={tmp}/big.html")
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"errpage {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


main()
