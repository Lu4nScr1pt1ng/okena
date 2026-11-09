#!/usr/bin/env python3
"""Maintenance on one engine (argument): `okena maintenance on|off [ROUTE]`
answers 503 with a Retry-After and the page (one's own, or a short text),
lets through the listener's `allow` clients and `except` paths, keeps
/ready as it is, survives a reload, shows in /status; and what is refused."""
import http.client
import http.server
import json
import os
import pathlib
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 38000 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
LST, PLAIN, METRICS, BACK = BASE, BASE + 1, BASE + 2, BASE + 3
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
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "4")
        self.end_headers()
        self.wfile.write(b"fine")

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, *a):
        pass


def req(path, port=LST, source="127.0.0.1"):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5, source_address=(source, 0))
    c.request("GET", path)
    r = c.getresponse()
    b = r.read()
    c.close()
    return r.status, {k.lower(): v for k, v in r.getheaders()}, b


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-maint-", dir="/tmp"))
    threading.Thread(target=S(("127.0.0.1", BACK), H).serve_forever, daemon=True).start()
    (tmp / "maint.html").write_text("<h1>Back soon</h1><p>{status}, ref {request_id}</p>\n")
    conf = tmp / "okena.conf"
    good = f"""okena {{ drain delay=0s timeout=1s; workers 2; io_engine {ENGINE}; metrics 127.0.0.1:{METRICS}; admin unix:{tmp}/admin.sock }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{LST} {{
    maintenance file={tmp}/maint.html retry=2m allow=127.0.0.2/32 except=/healthz,/status/*
    route /api/* {{ to pool b }}
    route /* {{ to pool b }}
}}
http 127.0.0.1:{PLAIN} {{ route /* {{ to pool b }} }}
"""
    conf.write_text(good)
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    cli = lambda *a: subprocess.run([str(BIN), "maintenance", *a, "-c", str(conf)], capture_output=True, text=True, timeout=10)

    def status():
        c = http.client.HTTPConnection("127.0.0.1", METRICS, timeout=5)
        c.request("GET", "/status")
        return json.loads(c.getresponse().read())
    try:
        check("okena starts, out of maintenance", until(lambda: req("/x")[0] == 200) and cli().stdout == "off\n", log.read_text()[-300:])

        r = cli("on")
        check("okena maintenance on: said", r.returncode == 0 and r.stdout == "on\n", (r.stdout, r.stderr))
        st, h, b = req("/x")
        check("every request: 503, its Retry-After, the listener's page", st == 503 and h.get("retry-after") == "120"
              and b == f"<h1>Back soon</h1><p>503, ref {h.get('x-request-id')}</p>\n".encode(), (st, h, b))
        st, h, b = req("/x", PLAIN)
        check("  a listener with no rules of its own: 30 s, the short text", st == 503 and h.get("retry-after") == "30"
              and b.startswith(b"Under maintenance: back soon.\nrequest id: "), (st, h, b))
        check("  `except`: a path still served, exact or by prefix", req("/healthz")[0] == 200 and req("/status/deep")[0] == 200
              and req("/healthz/more")[0] == 503, (req("/healthz")[0], req("/status/deep")[0]))
        check("  `allow`: a client still let in", req("/x", source="127.0.0.2")[0] == 200 and req("/x", source="127.0.0.3")[0] == 503)
        c = http.client.HTTPConnection("127.0.0.1", METRICS, timeout=5)
        c.request("GET", "/ready")
        check("  /ready as it was: the instance is up", c.getresponse().status == 200)
        check("  /status says so", status()["maintenance"] == {"on": True, "routes": []})

        # a reload keeps it
        conf.write_text(good + "# again\n")
        p.send_signal(signal.SIGHUP)
        time.sleep(1.5)
        check("a reload keeps it", req("/x")[0] == 503 and cli().stdout == "on\n")
        conf.write_text(good)

        r = cli("off")
        check("off: served again", r.stdout == "off\n" and req("/x")[0] == 200 and req("/x", PLAIN)[0] == 200, r.stdout)

        # a route only
        r = cli("on", "/api/*")
        check("a route only: on", r.stdout == "off /api/*\n", r.stdout)
        check("  its requests 503, the others served", req("/api/v1")[0] == 503 and req("/web")[0] == 200)
        check("  /status lists it", status()["maintenance"] == {"on": False, "routes": ["/api/*"]})
        check("  on twice: once", cli("on", "/api/*").stdout == "off /api/*\n")
        cli("on", "/*")
        check("  two routes", cli().stdout == "off /api/* /*\n" and req("/web")[0] == 503)
        cli("off", "/api/*")
        check("  one off: the other stays", cli().stdout == "off /*\n" and req("/web")[0] == 503 and req("/api/v1")[0] == 200)
        cli("off")
        check("  off with nothing: all of it off", cli().stdout == "off\n" and req("/web")[0] == 200)
        cli("on", "/api/x")                    # no route is written so: /api/* is not it
        check("  a name that is no route's: nothing in maintenance", req("/api/x")[0] == 200 and req("/api/v1")[0] == 200)
        cli("off")
        r = cli("on", "api")
        check("  a route not as written: refused", r.returncode != 0 and "/api/*" in r.stderr, (r.returncode, r.stderr))
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
    bad("a path that is not one", "maintenance except=healthz")
    bad("a time that is not one", "maintenance retry=soon")
    bad("an address that is not one", "maintenance allow=10.0.0.0/99")
    bad("a page that is not there", f"maintenance file={tmp}/nothing.html")
    bad("twice", "maintenance retry=1s; maintenance retry=2s")
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"maint {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


main()
