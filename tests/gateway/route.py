#!/usr/bin/env python3
"""`okena route`: what it says must be what a running okena does. Each request goes
to both, and the pool it named must be the one that answers."""
import http.client
import http.server
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
BIN = HERE.parents[1] / "build" / "okena"
BASE = 8000 + os.getpid() % 90 * 4	# ports 8000-8360: this suite's own
A, B, LST, LS2 = BASE, BASE + 1, BASE + 2, BASE + 3
fails = 0


def check(name, ok, more=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {more}"), flush=True)
    fails += 0 if ok else 1


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        b = self.server.tag.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    do_POST = do_GET

    def log_message(self, *a):
        pass


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-route."))
    for port, tag in ((A, "one"), (B, "two")):
        s = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
        s.tag = tag
        threading.Thread(target=s.serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1 }}
pool one {{ server 127.0.0.1:{A} }}
pool two {{ server 127.0.0.1:{B} }}
http 127.0.0.1:{LST} {{
    route /a/* {{ to pool one }}
    route /b/* {{
        match header:x-c=yes {{ to pool two }}
        match query:v=2 {{ to pool two }}
        match method=POST {{ redirect 303 /done }}
        to pool one
    }}
    host api.test {{
        route /* {{ to pool two }}
    }}
    route /* {{ to pool one }}
}}
http 127.0.0.1:{LS2} {{
    route /* {{ to pool two }}
}}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for i in range(50):
            try:
                socket.create_connection(("127.0.0.1", LST), 1).close()
                break
            except OSError:
                time.sleep(0.1)
        def said(spec):
            q = subprocess.run([str(BIN), "route", spec, "-c", str(conf)], capture_output=True, text=True, timeout=5)
            return q.returncode, dict(l.split(None, 1) for l in q.stdout.splitlines() if " " in l)
        for method, path, host, port, hdr in (("GET", "/a/x", "x", LST, {}), ("GET", "/b/x", "x", LST, {}), ("GET", "/b/x", "x", LST, {"x-c": "yes"}),
                                              ("GET", "/b/x?v=2", "x", LST, {}), ("GET", "/b/x?v=3", "x", LST, {}), ("GET", "/q", "api.test", LST, {}),
                                              ("GET", "/q", "other.test", LST, {}), ("GET", "/q", "x", LS2, {})):
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request(method, path, headers=dict(Host=host, **hdr))
            r = c.getresponse().read().decode()
            c.close()
            spec = f"{method} http://{host}:{port}{path} " + " ".join(f"{k}:{v}" for k, v in hdr.items())
            rc, d = said(spec.strip())
            check(f"{spec.strip()[-44:]}: {r}", rc == 0 and d.get("pool") == r, d)
        rc, d = said(f"POST http://x:{LST}/b/x")
        check("a block's redirect", d.get("redirect") == "303 /done", d)
        rc, d = said(f"GET http://x:{LST}/b/x x-c:no")
        check("a condition not met", d.get("pool") == "one" and "match" not in d, d)
        q = subprocess.run([str(BIN), "route", "nonsense", "-c", str(conf)], capture_output=True, text=True, timeout=5)
        check("nonsense: usage", q.returncode == 2 and "usage" in q.stderr, q.stderr)
        q = subprocess.run([str(BIN), "route", f"GET http://x:{LST}/a/x", "-c", str(tmp / "nosuch")], capture_output=True, text=True, timeout=5)
        check("no configuration: an error", q.returncode != 0, q.stdout)
    finally:
        p.terminate()
        p.wait(10)
    print("route: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
