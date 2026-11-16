#!/usr/bin/env python3
"""addons/grpcjson (grpcjson-okena), on one engine (argument), in front of a
gRPC service without generated code (build/grpcjson-test-server): rules of
google.api.http (GET with a path variable, POST with a body field and a
pattern {parent=shops/*}, GET with query parameters into fields, enums and
repeated ones, an additional binding, DELETE), POST /package.Service/Method
for any method, the client's Authorization as metadata, gRPC errors as HTTP
statuses with a JSON body (404, 400), a bad body 400, a path no method
answers goes on to the route's backend, HTTP/2."""
import http.client
import http.server
import json
import os
import pathlib
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ADDON = ROOT / "build" / "grpcjson-okena"
SERVER = ROOT / "build" / "grpcjson-test-server"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "auto"
if not ADDON.exists() or not SERVER.exists():
    print("skip grpcjson: no build/grpcjson-okena or its test server (Go or the modules missing)")
    sys.exit(0)
BASE = 28600 + os.getpid() % 40 * 12 + (6 if ENGINE == "epoll" else 0)
G, BACK, L = BASE, BASE + 1, BASE + 2
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"))
    fails += not ok


class Back(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        b = b"rest:" + self.path.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


srv = http.server.ThreadingHTTPServer(("127.0.0.1", BACK), Back)
threading.Thread(target=srv.serve_forever, daemon=True).start()


def call(method, path, body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", L, timeout=10)
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    c.request(method, path, body=json.dumps(body) if isinstance(body, (dict, list)) else body, headers=h)
    r = c.getresponse()
    b = r.read()
    ct = r.getheader("content-type") or ""
    c.close()
    try:
        return r.status, json.loads(b) if "json" in ct else b.decode()
    except ValueError:
        return r.status, b.decode()


tmp = pathlib.Path(tempfile.mkdtemp())
subprocess.run([str(SERVER), "-write", str(tmp / "api.pb")], check=True)
gs = subprocess.Popen([str(SERVER), "-listen", f"127.0.0.1:{G}"])
conf = tmp / "okena.conf"
conf.write_text(f"""
okena {{ workers 1; io_engine {ENGINE}; drain delay=0s timeout=1s }}
addon grpcjson {{
    run {ADDON} -descriptors {tmp}/api.pb -backend 127.0.0.1:{G}
    phases request_body
    body 1MiB
    timeout 5s
}}
http 127.0.0.1:{L} {{
    http2 on
    route /* {{ addon grpcjson; to 127.0.0.1:{BACK} }}
}}
""")
log = open(tmp / "log", "w+")
p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)
try:
    for port in (G, L):
        for _ in range(200):
            try:
                socket.create_connection(("127.0.0.1", port), 1).close()
                break
            except OSError:
                time.sleep(0.05)
    log.seek(0)
    st, it = call("POST", "/v1/shops/s1/items", {"name": "lamp", "priceCents": "1999", "tags": ["home", "light"], "color": "RED"})
    check("POST with a body field and {parent=shops/*}: created, as JSON",
          st == 200 and it.get("id") == "i1" and it.get("priceCents") == "1999" and it.get("color") == "RED", (st, it))
    call("POST", "/v1/shops/s1/items", {"name": "mug", "color": "BLUE"})
    call("POST", "/v1/shops/s2/items", {"name": "desk"})
    st, got = call("GET", "/v1/items/i1")
    check("GET with a path variable", st == 200 and got.get("name") == "lamp", (st, got))
    st, ls = call("GET", "/v1/shops/s1/items?pageSize=5&color=BLUE&tags=a&tags=b")
    check("GET: the pattern's variable, query parameters into fields (an enum by name, a repeated one)",
          st == 200 and [i["name"] for i in ls.get("items", [])] == ["mug"] and ls.get("echo") == "shops/s1|a,b", (st, ls))
    st, ls = call("GET", "/v1/all-items?page_size=2")
    check("an additional binding, a field by its proto name", st == 200 and len(ls.get("items", [])) == 2, (st, ls))
    st, pong = call("POST", "/shop.v1.Shop/Ping", {"id": "x"}, {"Authorization": "Bearer t0k"})
    check("POST /package.Service/Method for any method; Authorization as metadata",
          st == 200 and pong == {"id": "pong:x", "seenBy": "Bearer t0k"}, (st, pong))
    st, e = call("GET", "/v1/items/nope")
    check("NotFound: 404, its code and message as JSON", st == 404 and e.get("code") == 5 and "nope" in e.get("message", ""), (st, e))
    st, e = call("POST", "/v1/shops/s1/items", {"priceCents": "5"})
    check("InvalidArgument: 400", st == 400 and e.get("code") == 3, (st, e))
    st, e = call("POST", "/v1/shops/s1/items", "{not json")
    check("a body that is not JSON: 400", st == 400, (st, e))
    st, e = call("POST", "/v1/shops/s1/items", {"nosuch": 1})
    check("a field the message has not: 400", st == 400, (st, e))
    st, d = call("DELETE", "/v1/items/i3")
    check("DELETE", st == 200 and d.get("name") == "desk" and call("GET", "/v1/items/i3")[0] == 404, (st, d))
    st, b = call("GET", "/static/app.js")
    check("a path no method answers: on to the route's backend", (st, b) == (200, "rest:/static/app.js"), (st, b))
    q = subprocess.run(["curl", "-sS", "--http2-prior-knowledge", "-H", "content-type: application/json", "-d", '{"id":"h2"}',
                        f"http://127.0.0.1:{L}/shop.v1.Shop/Ping"], capture_output=True, text=True, timeout=10)
    check("over HTTP/2", '"pong:h2"' in q.stdout, q.stdout + q.stderr)
    log.seek(0)
    check("no crash", "killed by signal" not in log.read())
finally:
    p.send_signal(signal.SIGTERM)
    gs.kill()
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
    if fails:
        log.seek(0)
        print(log.read()[-2000:])
print(f"grpcjson ({ENGINE}): {'all passed' if not fails else f'{fails} failed'}")
sys.exit(1 if fails else 0)
