#!/usr/bin/env python3
"""`policy` and `use`, on one engine (argument): what a policy says holds on each
route that uses it, what a route writes overrides it, and a reload changes it for
all of them. Authorization is what is at stake: a route that lost its policy's
`auth` on the way would be open."""
import http.client
import http.server
import os
import pathlib
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 29960 + os.getpid() % 3 * 8 + (4 if ENGINE == "epoll" else 0)
BACK, LST = BASE, BASE + 1
fails = 0


def check(name, ok, more=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {more}"), flush=True)
    fails += 0 if ok else 1


class Back(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        who = self.headers.get("x-user-id", "-").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(who)))
        self.end_headers()
        self.wfile.write(who)

    def log_message(self, *a):
        pass


def get(path, **hdr):
    c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
    try:
        c.request("GET", path, headers={k.replace("_", "-"): v for k, v in hdr.items()})
        r = c.getresponse()
        return r.status, r.read().decode(), dict((k.lower(), v) for k, v in r.getheaders())
    finally:
        c.close()


CONF = """okena {{ drain delay=0s timeout=1s; workers 2; io_engine {engine} }}
policy partners {{
    auth api_key header=x-api-key keys={tmp}/keys
    cors origins=https://a.test
}}
policy slow {{ limit 2/s burst=1 key=client.ip }}
pool b {{ server 127.0.0.1:{back} }}
http 127.0.0.1:{lst} {{
    route /one {{ use partners; to pool b }}
    route /two {{ to pool b; use partners }}
    route /both {{ use partners; use slow; to pool b }}
    route /mine {{ use partners; auth api_key header=x-other keys={tmp}/other; to pool b }}
    route /limited {{ use slow; limit 1000/s key=client.ip; to pool b }}
    route /open {{ to pool b }}
}}
"""


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-policy."))
    (tmp / "keys").write_text("alice:partner-key\n")
    (tmp / "other").write_text("bob:other-key\n")
    s = http.server.ThreadingHTTPServer(("127.0.0.1", BACK), Back)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    args = dict(engine=ENGINE, tmp=tmp, back=BACK, lst=LST)
    conf.write_text(CONF.format(**args))
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for i in range(50):
            try:
                socket.create_connection(("127.0.0.1", LST), 1).close()
                break
            except OSError:
                time.sleep(0.1)
        for route in ("/one", "/two", "/both"):
            check(f"{route}: no key, refused", get(route)[0] == 401, get(route)[:2])
            r = get(route, x_api_key="partner-key")
            check(f"{route}: the policy's key, and who it is", r[:2] == (200, "alice"), r[:2])
        check("  `use` after `to` works the same", get("/two", x_api_key="wrong")[0] == 401)
        r = get("/one", x_api_key="partner-key", Origin="https://a.test")
        check("  the rest of the policy holds: cors", r[2].get("access-control-allow-origin") == "https://a.test", r[2])
        check("a route's own auth overrides it: the policy's key is no good",
              get("/mine", x_api_key="partner-key")[0] == 401)
        check("  its own is", get("/mine", x_other="other-key")[:2] == (200, "bob"))
        check("  the rest of the policy stays",
              "access-control-allow-origin" in get("/mine", x_other="other-key", Origin="https://a.test")[2])
        time.sleep(1.1)
        codes = [get("/both", x_api_key="partner-key")[0] for i in range(12)]
        check("two policies on a route: the second holds too", 429 in codes and 200 in codes, codes)
        time.sleep(1.1)
        codes = [get("/limited")[0] for i in range(12)]
        check("a route's own `limit` replaces the policy's", set(codes) == {200}, codes)
        check("a route with none is as it was", get("/open")[0] == 200)
        # the policy changes for all of them at once
        conf.write_text(CONF.format(**args).replace("cors origins=https://a.test", "cors origins=https://b.test"))
        os.kill(p.pid, signal.SIGHUP)
        for i in range(50):
            if "configuration reloaded" in log.read_text():
                break
            time.sleep(0.1)
        time.sleep(0.3)
        for route in ("/one", "/two"):
            r = get(route, x_api_key="partner-key", Origin="https://b.test")
            check(f"reloaded, {route} has the new policy", r[2].get("access-control-allow-origin") == "https://b.test", r[2])
    finally:
        p.terminate()
        p.wait(10)
    check("no worker died", "killed" not in log.read_text(), log.read_text()[-200:])
    print(f"policy {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
