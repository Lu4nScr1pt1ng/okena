#!/usr/bin/env python3
"""Zone-aware balancing, on one engine (argument): with `okena { zone a }`
requests (and tcp connections) go to the pool's servers of zone a while one
is up, under least-request and round robin alike; `zone prefer min=2` spreads
as soon as fewer than two are; with none up, every zone takes them; `zone off`
spreads always; an instance with no zone ignores servers' zones."""
import collections
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

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 16400 + os.getpid() % 40 * 10 + (5 if ENGINE == "epoll" else 0)
BACK, LST, TCP = BASE, BASE + 1, BASE + 2
NAMES = {"127.0.0.11": "a1", "127.0.0.12": "a2", "127.0.0.13": "b1", "127.0.0.14": "c1"}
sick = set()
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += 0 if ok else 1


class Back(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        name = self.server.name
        st = 500 if self.path == "/h" and name in sick else 200
        b = name.encode()
        self.send_response(st)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128

    def handle_error(self, *a):
        pass


def who(path, n=40):
    c = collections.Counter()
    for i in range(n):
        h = http.client.HTTPConnection("127.0.0.1", LST, timeout=3)
        h.request("GET", path)
        r = h.getresponse()
        c[r.read().decode()] += 1
        h.close()
    return c


def tcp_who(n=20):
    c = collections.Counter()
    for i in range(n):
        s = socket.create_connection(("127.0.0.1", TCP), 3)
        s.sendall(b"GET /x HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
        d = b""
        while True:
            g = s.recv(4096)
            if not g:
                break
            d += g
        s.close()
        c[d.split(b"\r\n\r\n", 1)[-1].decode()] += 1
    return c


def until(fn, seconds=5):
    t = time.time()
    while time.time() - t < seconds:
        if fn():
            return True
        time.sleep(0.1)
    return False


SERVERS = "".join(f"    server {ip}:{BACK} zone={NAMES[ip][0]}\n" for ip in NAMES)
HEALTH = "    health http GET /h every=100ms timeout=1s rise=1 fall=1\n"


def conf(zone):
    z = f"zone {zone}; " if zone else ""
    return f"""okena {{ {z}drain delay=0s timeout=1s; workers 2; io_engine {ENGINE}; overload off }}
pool p {{
{SERVERS}{HEALTH}}}
pool q {{
{SERVERS}{HEALTH}    zone prefer min=2
}}
pool r {{
{SERVERS}    zone off
}}
pool rr {{
{SERVERS}{HEALTH}    balance round-robin
}}
http 127.0.0.1:{LST} {{
    route /p {{ to pool p }}
    route /q {{ to pool q }}
    route /r {{ to pool r }}
    route /rr {{ to pool rr }}
}}
tcp 127.0.0.1:{TCP} {{ to pool p }}
"""


def start(tmp, text, name):
    c = tmp / (name + ".conf")
    c.write_text(text)
    p = subprocess.Popen([str(BIN), "-c", str(c)], stderr=open(tmp / (name + ".log"), "w"))
    for i in range(50):
        try:
            socket.create_connection(("127.0.0.1", LST), 1).close()
            break
        except OSError:
            time.sleep(0.1)
    return p


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-zone."))
    for ip, name in NAMES.items():
        s = S((ip, BACK), Back)
        s.name = name
        threading.Thread(target=s.serve_forever, daemon=True).start()
    p = start(tmp, conf("a"), "zoned")
    try:
        c = who("/p")
        check("zone a: only its servers, both of them", set(c) == {"a1", "a2"}, c)
        c = who("/rr")
        check("  round robin too", set(c) == {"a1", "a2"}, c)
        c = tcp_who()
        check("  a tcp listener too", set(c) == {"a1", "a2"}, c)
        c = who("/r")
        check("zone off: every zone", set(c) == set(NAMES.values()), c)
        sick.add("a2")
        check("one of zone a down: the other takes it all", until(lambda: set(who("/p", 20)) == {"a1"}), who("/p"))
        c = who("/q")
        check("  min=2 with one up: every zone", {"b1", "c1"} <= set(c), c)
        sick.add("a1")
        check("none of zone a up: the other zones", until(lambda: set(who("/p", 20)) == {"b1", "c1"}), who("/p"))
        sick.clear()
        check("back: zone a again", until(lambda: set(who("/p", 20)) == {"a1", "a2"}), who("/p"))
    finally:
        p.terminate()
        p.wait(10)
    p = start(tmp, conf(None), "plain")
    try:
        c = who("/p")
        check("no zone of its own: servers' zones mean nothing", set(c) == set(NAMES.values()), c)
    finally:
        p.terminate()
        p.wait(10)
    p = start(tmp, conf("z"), "elsewhere")
    try:
        c = who("/p")
        check("a zone no server is in: every zone", set(c) == set(NAMES.values()), c)
    finally:
        p.terminate()
        p.wait(10)
    logs = "".join(f.read_text() for f in tmp.glob("*.log"))
    check("no worker died", "killed" not in logs and "restarting" not in logs, logs[-300:])
    print(f"zone {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
