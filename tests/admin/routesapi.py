#!/usr/bin/env python3
"""`okena routes-api` (an HTTP API for `routes FILE`, a process of its own),
on one engine (argument): over a unix socket (0600) and a loopback port, with
the token: list, show, put (served at once), a route the configuration does
not take refused with its errors (422) and the file as it was, delete, a name
or a head not there 404; without the token or with another 401 (the same
length too); a body of several lines, a name that is not one, a method not
taken, chunked, a body too large refused; a non-loopback address and a short
token refused at start; through okena itself in front (TLS-like: a route to
its socket); its process is not the admin one."""
import http.client
import http.server
import os
import pathlib
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "auto"
BASE = 25400 + os.getpid() % 40 * 12 + (6 if ENGINE == "epoll" else 0)
BA, L, AP, FR = BASE, BASE + 1, BASE + 2, BASE + 3
TOKEN = "t" * 8 + os.urandom(16).hex()
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"))
    fails += not ok


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "1")
        self.end_headers()
        self.wfile.write(b"a")

    def log_message(self, *a):
        pass


threading.Thread(target=http.server.ThreadingHTTPServer(("127.0.0.1", BA), H).serve_forever, daemon=True).start()


class UnixConn(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=60)
        self.path_ = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(60)
        self.sock.connect(self.path_)


def api(method, path, body=None, token=TOKEN, unix=True, headers=None):
    c = UnixConn(str(sock)) if unix else http.client.HTTPConnection("127.0.0.1", AP, timeout=60)
    h = dict(headers or {})
    if token is not None:
        h["Authorization"] = "Bearer " + token
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    b = r.read().decode(errors="replace")
    c.close()
    return r.status, b


def get(path, port=L):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("GET", path, headers={"Host": "x.test"})
    r = c.getresponse()
    b = r.read()
    c.close()
    return r.status, b.decode(errors="replace")


tmp = pathlib.Path(tempfile.mkdtemp())
rf = tmp / "api.conf"
sock = tmp / "routes.sock"
(tmp / "token").write_text(TOKEN + "\n")
conf = tmp / "okena.conf"
conf.write_text(f"""
okena {{ overload off; workers 1; io_engine {ENGINE}; admin unix:{tmp}/admin.sock; drain delay=0s timeout=1s }}
pool a {{ server 127.0.0.1:{BA} }}
http 127.0.0.1:{L} {{
    routes {rf}
    route /static {{ respond 200 "static" }}
}}
http 127.0.0.1:{FR} {{
    route /api/routes/* {{ allow 127.0.0.0/8; rewrite path /api/routes/{{*}} -> /routes/{{*}}; to unix:{sock} }}
}}
""")
log = open(tmp / "log", "w+")
alog = open(tmp / "api.log", "w+")
p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)
ap = subprocess.Popen([str(BIN), "routes-api", f"unix:{sock}", f"token={tmp}/token", "-c", str(conf)], stderr=alog)
ap2 = subprocess.Popen([str(BIN), "routes-api", f"127.0.0.1:{AP}", f"token={tmp}/token", "-c", str(conf)], stderr=alog)
try:
    for _ in range(200):
        log.seek(0)
        alog.seek(0)
        a = alog.read()
        if "started with" in log.read() and a.count("routes-api on") == 2:
            break
        time.sleep(0.05)
    else:
        log.seek(0)
        alog.seek(0)
        sys.exit("did not start:\n" + log.read() + alog.read())
    check("the socket is the owner's only (0600)", stat.S_IMODE(os.stat(sock).st_mode) == 0o600, oct(os.stat(sock).st_mode))
    st, b = api("GET", "/routes")
    check("GET /routes: the names and their files", st == 200 and f"api\t{rf}" in b, (st, b))
    st, b = api("PUT", "/routes/api", "route /v1/* { to pool a }\n")
    check("PUT: checked, written, reloaded; served at once", st == 200 and "reloaded" in b and get("/v1/x") == (200, "a"), (st, b))
    st, b = api("PUT", "/routes/api", 'route /v2 { respond 200 "two" }', unix=False)
    check("  over the loopback port too", st == 200 and get("/v2") == (200, "two"), (st, b))
    before = rf.read_text()
    st, b = api("PUT", "/routes/api", "route /v3 { to pool nosuch }")
    check("a route the configuration does not take: 422 with its error, nothing changed",
          st == 422 and "nosuch" in b and rf.read_text() == before and get("/v3")[0] == 404, (st, b))
    st, b = api("GET", "/routes/api")
    check("GET /routes/NAME: what it holds", st == 200 and b == before, (st, b))
    st, b = api("DELETE", "/routes/api", "/v1/*")
    check("DELETE (a head): gone", st == 200 and get("/v1/x")[0] == 404 and get("/v2") == (200, "two"), (st, b))
    st, b = api("DELETE", "/routes/api", "/v1/*")
    check("  again: 404", st == 404, (st, b))
    st, b = api("GET", "/routes/nosuch")
    check("a name not there: 404", st == 404, (st, b))
    st, b = api("PUT", "/routes/api", "route /x { to pool a }", token=None)
    check("no token: 401, nothing run", st == 401 and get("/x")[0] == 404, (st, b))
    st, b = api("GET", "/routes", token="x" * len(TOKEN))
    check("another token of the same length: 401", st == 401, (st, b))
    st, b = api("GET", "/routes", token=TOKEN[:-1])
    check("  a prefix of it: 401", st == 401, (st, b))
    for what, args, want in (("a body of two lines", ("PUT", "/routes/api", "route /a { to pool a }\nroute /b { to pool a }"), 400),
                             ("a body with a control character", ("PUT", "/routes/api", "route /a \x01{ to pool a }"), 400),
                             ("a body like a flag", ("PUT", "/routes/api", "-c /etc/passwd"), 400),
                             ("a name that is not one", ("GET", "/routes/../etc"), 404),
                             ("a name like a flag", ("GET", "/routes/-c"), 404),
                             ("POST", ("POST", "/routes/api", "route /a { to pool a }"), 405),
                             ("another path", ("GET", "/admin"), 404),
                             ("a body too large", ("PUT", "/routes/api", "route /a { respond 200 \"" + "x" * 20000 + "\" }"), 413)):
        st, b = api(*args)
        check(f"{what}: {want}", st == want, (st, b[:200]))
    c = UnixConn(str(sock))
    c.putrequest("PUT", "/routes/api")
    c.putheader("Authorization", "Bearer " + TOKEN)
    c.putheader("Transfer-Encoding", "chunked")
    c.endheaders()
    c.send(b"5\r\nhello\r\n0\r\n\r\n")
    r = c.getresponse()
    check("chunked: 411", r.status == 411, r.status)
    c.close()
    # through okena in front of it (where TLS, allow lists and limits would be)
    c = http.client.HTTPConnection("127.0.0.1", FR, timeout=60)
    c.request("PUT", "/api/routes/api", body='route /v4 { respond 200 "four" }', headers={"Authorization": "Bearer " + TOKEN})
    r = c.getresponse()
    b = r.read().decode()
    c.close()
    check("through a route of okena to its socket", r.status == 200 and get("/v4") == (200, "four"), (r.status, b))
    alog.seek(0)
    a = alog.read()
    check("each request logged: method, target, status", "routes-api: PUT /routes/api: 200" in a
          and "routes-api: PUT /routes/api: 422" in a, a[-600:])
    # its process is its own, not okena's admin one
    check("a process of its own (not a child of the running okena)", os.getpid() == int(open(f"/proc/{ap.pid}/stat").read().split()[3])
          and ap.pid not in [int(x) for x in subprocess.run(["pgrep", "-P", str(p.pid)], capture_output=True, text=True).stdout.split()])
    # refused at start
    for what, args, msg in (("a non-loopback address", ["10.0.0.1:9", f"token={tmp}/token"], "loopback"),
                            ("a short token", [f"unix:{tmp}/x.sock", f"token={tmp}/short"], "32 to 512")):
        (tmp / "short").write_text("abc\n")
        q = subprocess.run([str(BIN), "routes-api", *args, "-c", str(conf)], capture_output=True, text=True, timeout=10)
        check(f"{what}: refused at start", q.returncode != 0 and msg in q.stderr, q.stderr[-200:])
    log.seek(0)
    check("no crash", "killed by signal" not in log.read())
finally:
    for x in (ap, ap2):
        x.kill()
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
    if fails:
        log.seek(0)
        alog.seek(0)
        print(log.read()[-2000:], alog.read()[-2000:])
print(f"routes-api ({ENGINE}): {'all passed' if not fails else f'{fails} failed'}")
sys.exit(1 if fails else 0)
