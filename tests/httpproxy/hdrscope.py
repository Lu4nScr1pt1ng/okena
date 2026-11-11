#!/usr/bin/env python3
"""`header` and `response header` on a listener and in a host block, on one
engine (argument): they apply to every route below, the listener's first,
then the host block's, then the route's (a route's set wins); a route with
nothing of its own gets them; okena's own answers (respond) get the response
ones."""
import http.client
import http.server
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
L = 47000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        b = "\n".join(f"{k.lower()}={v}" for k, v in self.headers.items()).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("X-Who", "backend")
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


def get(path, host="a"):
    c = http.client.HTTPConnection("127.0.0.1", L, timeout=5)
    c.request("GET", path, headers={"Host": host})
    r = c.getresponse()
    b = r.read().decode()
    h = {k.lower(): v for k, v in r.getheaders()}
    c.close()
    return r.status, h, b


def main():
    s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    B = s.server_address[1]
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-hdrscope-"))
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE} }}
http 127.0.0.1:{L} {{
    header set x-from listener
    response header set strict-transport-security "max-age=60"
    response header set x-who listener
    host h.test {{
        header set x-host yes
        route /* {{ to 127.0.0.1:{B} }}
    }}
    route /plain {{ to 127.0.0.1:{B} }}
    route /own {{ to 127.0.0.1:{B}; header set x-from route; response header set x-who route }}
    route /self {{ respond 200 "here" }}
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
        st, h, b = get("/plain")
        check("a route with nothing of its own: the listener's request header", "x-from=listener" in b, b)
        check("  and its response headers", h.get("strict-transport-security") == "max-age=60" and h.get("x-who") == "listener", h)
        st, h, b = get("/own")
        check("a route's own set wins, both ways", "x-from=route" in b and h.get("x-who") == "route"
              and h.get("strict-transport-security") == "max-age=60", (b, h))
        st, h, b = get("/x", "h.test")
        check("a host block: its own and the listener's", "x-host=yes" in b and "x-from=listener" in b and h.get("x-who") == "listener", (b, h))
        st, h, b = get("/self")
        check("okena's own answer: the response headers too", st == 200 and h.get("strict-transport-security") == "max-age=60", h)
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no worker died", "killed" not in t and "seccomp" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"hdrscope {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
