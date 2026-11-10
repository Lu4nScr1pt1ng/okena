#!/usr/bin/env python3
"""`match` inside a route, on one engine (argument): each kind of condition, that a
block changes only what it says, and above all that it cannot open what the route
closes: an `auth` on the route must hold in every block."""
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
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 12000 + os.getpid() % 90 * 6 + (3 if ENGINE == "epoll" else 0)	# ports 12000-12540: this suite's own
MAIN, CANARY, LST = BASE, BASE + 1, BASE + 2
fails = 0


def check(name, ok, more=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {more}"), flush=True)
    fails += 0 if ok else 1


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def go(self):
        n = int(self.headers.get("content-length", 0))
        if n:
            self.rfile.read(n)
        b = (self.server.tag + " " + self.path + " " + (self.headers.get("x-set") or "-")).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    do_GET = do_POST = go

    def log_message(self, *a):
        pass


def get(path, method="GET", **hdr):
    c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
    c.request(method, path, body=b"x" if method == "POST" else None, headers={k.replace("_", "-"): v for k, v in hdr.items()})
    r = c.getresponse()
    b = r.read().decode()
    c.close()
    return r.status, b, {k.lower(): v for k, v in r.getheaders()}


CONF = """okena {{ drain delay=0s timeout=1s; workers 2; io_engine {engine} }}
pool main {{ server 127.0.0.1:{main} }}
pool canary {{ server 127.0.0.1:{canary} }}
http 127.0.0.1:{lst} {{
    trusted_proxies 127.0.0.2
    route /h/* {{
        match header:x-canary=yes {{ to pool canary }}
        match header:x-prefix=ab* {{ to pool canary }}
        match header:x-there {{ to pool canary }}
        to pool main
    }}
    route /m/* {{ match method=POST {{ to pool canary }}; to pool main }}
    route /q/* {{ match query:v=2 {{ to pool canary }}; to pool main }}
    route /k/* {{ match cookie:beta=1 {{ to pool canary }}; to pool main }}
    route /ip/* {{ match client.ip=127.0.0.0/8 {{ to pool canary }}; to pool main }}
    route /nip/* {{ match client.ip=10.0.0.0/8 {{ to pool canary }}; to pool main }}
    route /ip6/* {{ match client.ip=7f00::/8 {{ to pool canary }}; to pool main }}
    route /and/* {{ match header:a=1 header:b=2 {{ to pool canary }}; to pool main }}
    route /first/* {{
        match header:a=1 {{ header set x-set one }}
        match header:a=1 {{ header set x-set two }}
        to pool main
    }}
    route /auth/* {{
        auth api_key header=x-api-key keys={tmp}/keys
        match header:x-canary=yes {{ to pool canary }}
        to pool main
    }}
    route /swap/* {{
        auth api_key header=x-api-key keys={tmp}/keys
        match header:x-other=yes {{ auth api_key header=x-other-key keys={tmp}/keys }}
        to pool main
    }}
    route /set/* {{ header set x-set route; match header:a=1 {{ header set x-set block }}; to pool main }}
    route /keep/* {{ header set x-set route; match header:a=1 {{ to pool canary }}; to pool main }}
    route /red/* {{ match header:a=1 {{ redirect 302 /else }}; to pool main }}
    route /unred/* {{ match header:a=1 {{ to pool main }}; redirect 302 /else }}
    route /resp/* {{ match header:a=1 {{ to pool main }}; respond 404 }}
    route /up/* {{ redirect 308 "https://{{host}}:8443/n/{{*}}" }}
    route /rew/* {{ match header:a=1 {{ rewrite path /rew/{{*}} -> /new/{{*}} }}; to pool main }}
    route /lim/* {{
        limit 1000/s key=client.ip
        match header:slow=1 {{ limit 1/s burst=1 key=client.ip }}
        to pool main
    }}
    route /fence/* {{
        limit 2/s burst=1 key=client.ip
        match header:fast=1 {{ limit 1000/s key=client.ip }}
        to pool main
    }}
    route /a/one /a/two {{ match header:a=1 {{ to pool canary }}; to pool main }}
}}
"""


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-match."))
    (tmp / "keys").write_text("alice:good\n")
    for port, tag in ((MAIN, "main"), (CANARY, "canary")):
        s = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
        s.tag = tag
        threading.Thread(target=s.serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    text = CONF.format(engine=ENGINE, main=MAIN, canary=CANARY, lst=LST, tmp=tmp)
    conf.write_text(text)
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for i in range(50):
            try:
                socket.create_connection(("127.0.0.1", LST), 1).close()
                break
            except OSError:
                time.sleep(0.1)
        def on(path="/h/", method="GET", **h):
            return get(path, method, **h)[1].split()[0]
        check("no condition holds: the route", on("/h/x") == "main")
        check("header=value", on("/h/x", x_canary="yes") == "canary")
        check("  exact: not another", on("/h/x", x_canary="yesterday") == "main")
        check("  the case of a value counts", on("/h/x", x_canary="YES") == "main")
        check("  the case of a name does not", on("/h/x", X_CANARY="yes") == "canary")
        check("value*", on("/h/x", x_prefix="abc") == "canary" and on("/h/x", x_prefix="xab") == "main")
        check("  ab* takes ab", on("/h/x", x_prefix="ab") == "canary")
        check("name alone", on("/h/x", x_there="anything") == "canary")
        check("method", on("/m/x", "POST") == "canary" and on("/m/x") == "main")
        check("query", on("/q/x?a=1&v=2&b=3") == "canary" and on("/q/x?v=22") == "main" and on("/q/x") == "main")
        check("  not a name that ends in it", on("/q/x?xv=2") == "main")
        check("cookie", on("/k/x", Cookie="a=1; beta=1") == "canary" and on("/k/x", Cookie="beta=2") == "main" and on("/k/x") == "main")
        check("client.ip", on("/ip/x") == "canary" and on("/nip/x") == "main")
        check("  IPv6 range, IPv4 client", on("/ip6/x") == "main")
        check("all of them must hold", on("/and/x", a="1", b="2") == "canary" and on("/and/x", a="1") == "main" and on("/and/x", b="2") == "main")
        check("the first that fits", get("/first/x", a="1")[1].split()[2] == "one", get("/first/x", a="1")[1])

        check("auth on the route holds in a block", get("/auth/x", x_canary="yes")[0] == 401)
        check("  with the key, it goes there", on("/auth/x", x_canary="yes", x_api_key="good") == "canary")
        r = get("/swap/x", x_other="yes", x_api_key="good")
        check("a block's auth replaces it: the other key is what counts", r[0] == 401, r[:2])
        check("  that one passes", get("/swap/x", x_other="yes", x_other_key="good")[0] == 200)
        check("  and the route's holds outside the block", get("/swap/x", x_other_key="good")[0] == 401)
        check("what it says replaces", get("/set/x", a="1")[1].split()[2] == "block")
        check("what it does not stays", get("/keep/x", a="1")[1].split()[0::2] == ["canary", "route"], get("/keep/x", a="1")[1])
        r = get("/red/x", a="1")
        check("a redirect in a block", r[0] == 302 and r[2].get("location") == "/else", r[:3])
        check("  not outside it", get("/red/x")[0] == 200)
        check("a `to` undoes the route's redirect", get("/unred/x", a="1")[0] == 200 and get("/unred/x")[0] == 302)
        r = get("/resp/x")
        check("respond 404: the code, no Location, the connection kept", r[0] == 404 and "location" not in r[2]
              and r[2].get("connection") != "close", r[:3])
        check("  a block's `to` undoes it", get("/resp/x", a="1")[0] == 200)
        r = get("/up/a/b?q=1", Host="Shop.example.com:8080")
        check("redirect to {host}: the request's name, without its port", r[0] == 308
              and r[2].get("location") == "https://Shop.example.com:8443/n/a/b?q=1", r[:3])
        r = get("/up/a", Host="[::1]:8080")
        check("  an IPv6 one in brackets", r[2].get("location") == "https://[::1]:8443/n/a", r[:3])
        check("rewrite in a block", get("/rew/x", a="1")[1].split()[1] == "/new/x" and get("/rew/x")[1].split()[1] == "/rew/x", get("/rew/x", a="1")[1])
        codes = [get("/lim/x", slow="1")[0] for i in range(5)]
        check("a block's limit counts", 429 in codes, codes)
        time.sleep(1.1)
        codes = [get("/fence/x", fast="1")[0] for i in range(8)]
        check("a block's limit does not loosen the route's", 429 in codes, codes)
        check("each path of a route", on("/a/one", a="1") == "canary" and on("/a/two", a="1") == "canary" and on("/a/two") == "main")
    finally:
        p.terminate()
        p.wait(10)
    check("no worker died", "killed" not in log.read_text(), log.read_text()[-200:])
    for what, old, bad in (("no condition", "match header:x-canary=yes {{ to pool canary }}".replace("{{", "{").replace("}}", "}"), "match { to pool canary }"),
                           ("an unknown one", "match method=POST", "match nosuch=1"),
                           ("a bad address", "match client.ip=10.0.0.0/8", "match client.ip=nope"),
                           ("method with no value", "match method=POST", "match method"),
                           ("a pool that is not there", "match method=POST { to pool canary }", "match method=POST { to pool nosuch }"),
                           ("a match in a match", "match method=POST { to pool canary }", "match method=POST { match method=GET { to pool main } }")):
        c = tmp / "bad.conf"
        assert old in text, old
        c.write_text(text.replace(old, bad))
        q = subprocess.run(["timeout", "5", str(BIN), "-c", str(c)], capture_output=True, text=True, timeout=8)
        check(f"{what}: refused", q.returncode not in (0, 124) and q.stderr != "", f"{q.returncode} {q.stderr[-160:]}")
    print(f"match {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
