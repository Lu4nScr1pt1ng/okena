#!/usr/bin/env python3
"""`discover consul` on one engine (argument), against a fake agent's HTTP API:
the instances whose checks pass (passing=1 asked), at the service's address or
else the node's, IPv4 and IPv6, by their weight, dc= and tag= passed on, the ACL
token read from its file as it is rotated; followed as they come and go, and kept
when Consul goes wrong."""
import collections
import http.client
import http.server
import json
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
LST, AGENT, TAGGED = 18750, 18751, 18752
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok  " if ok else "FAIL"), name, detail if not ok else "", flush=True)
    fails += 0 if ok else 1


class Back(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    disable_nagle_algorithm = True

    def do_GET(self):
        b = self.server.name.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True


class S6(S):
    address_family = socket.AF_INET6


def backend(name, ip, port):
    s = (S6 if ":" in ip else S)((ip, port), Back)
    s.name = name
    threading.Thread(target=s.serve_forever, daemon=True).start()


# the fake agent
services = {"web": [], "api": []}
mode = {"how": "ok"}
asked = []


def instance(name, svc_addr, port, node_addr="10.0.0.1", weight=None, passing=True, tags=()):
    s = {"ID": name, "Service": "web", "Tags": list(tags), "Address": svc_addr, "Port": port,
         "Meta": {"note": "a \"quoted\" {value}"}, "EnableTagOverride": False}
    if weight is not None:
        s["Weights"] = {"Passing": weight, "Warning": 1}
    return {"Node": {"ID": "n-" + name, "Node": "node-" + name, "Address": node_addr, "Datacenter": "dc1",
                     "TaggedAddresses": {"lan": node_addr}},
            "Service": s,
            "Checks": [{"Node": "node-" + name, "CheckID": "serfHealth", "Status": "passing" if passing else "critical"}],
            "_passing": passing}


class Agent(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        asked.append((self.path, self.headers.get("X-Consul-Token")))
        name = u.path.rsplit("/", 1)[-1]
        if mode["how"] == "500" or not u.path.startswith("/v1/health/service/") or name not in services:
            self.send_response(500)
            self.end_headers()
            return
        if mode["how"] == "403":
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"ACL not found")
            return
        out = [{k: v for k, v in e.items() if k != "_passing"} for e in services[name]
               if e["_passing"] or q.get("passing") != ["1"]]
        body = json.dumps(out, indent=2).encode() if mode["how"] != "garbage" else b'[{"Node": {"Address": "1.2'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Consul-Index", "42")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def get(port=LST):
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        c.request("GET", "/")
        r = c.getresponse()
        b = r.read().decode()
        c.close()
        return r.status, b
    except OSError as e:
        return 0, repr(e)


def spread(n=30, port=LST):
    return collections.Counter(get(port)[1] for i in range(n))


def until(fn, seconds=4):
    t = time.time()
    while time.time() - t < seconds:
        if fn():
            return time.time() - t
        time.sleep(0.05)
    return None


def asked_more(k=2):
    """until okena has asked k more times (each second): what it would do with them is done"""
    n = len(asked)
    until(lambda: len(asked) >= n + k, 5)
    time.sleep(0.2)                         # (and the workers have what it published)


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-consul-", dir="/tmp"))
    agent = S(("127.0.0.1", AGENT), Agent)
    threading.Thread(target=agent.serve_forever, daemon=True).start()
    for name, ip, port in (("a", "127.0.0.2", 8080), ("b", "127.0.0.3", 8080), ("c", "127.0.0.4", 8080),
                           ("d", "127.0.0.5", 8080), ("p", "127.0.0.7", 7000), ("six", "::1", 8086),
                           ("t", "127.0.0.7", 8080)):
        backend(name, ip, port)
    services["web"][:] = [instance("a", "127.0.0.2", 8080),
                          instance("b", "", 8080, node_addr="127.0.0.3"),
                          instance("c", "127.0.0.4", 8080, passing=False),
                          instance("h", "db.service.consul", 8080)]
    services["api"][:] = [instance("t", "127.0.0.7", 8080, tags=["v2"])]
    token = tmp / "token"
    token.write_text("secret-one\n")
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ drain delay=0s timeout=1s; workers 2; io_engine {ENGINE} }}
pool web {{ balance round-robin; discover consul service=web api=127.0.0.1:{AGENT} token={token} }}
pool api {{ discover consul service=api dc=dc2 tag=v2 api=127.0.0.1:{AGENT} port=7000 }}
http 127.0.0.1:{LST} {{ route /* {{ to pool web }} }}
http 127.0.0.1:{TAGGED} {{ route /* {{ to pool api }} }}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        until(lambda: get()[0] == 200, 5)
        n = spread()
        check("those passing: a at its service's address, b (none of its own) at its node's", set(n) == {"a", "b"}, n)
        check("  not one failing its checks, nor one whose address is a name", "c" not in n, n)
        web = [a for a in asked if "/web" in a[0]]
        check("  passing=1 asked, the token from its file", web and "/v1/health/service/web?passing=1" == web[-1][0]
              and web[-1][1] == "secret-one", web[-1:])
        api = [a for a in asked if "/api" in a[0]]
        check("dc= and tag= passed on, no token when none is given",
              api and api[-1][0] == "/v1/health/service/api?passing=1&dc=dc2&tag=v2" and api[-1][1] is None, api[-1:])
        check("  its instance, at its port", set(spread(10, TAGGED)) == {"t"}, spread(10, TAGGED))
        services["api"][0]["Service"]["Port"] = 0
        t = until(lambda: set(spread(10, TAGGED)) == {"p"})
        check("  one that registered no port: port=", t is not None, (t, spread(10, TAGGED)))

        token.write_text("secret-two")
        t = until(lambda: [a for a in asked if "/web" in a[0]][-1][1] == "secret-two")
        check("the token rotated: read again", t is not None, asked[-1:])

        services["web"][2]["_passing"] = True
        services["web"][2]["Checks"][0]["Status"] = "passing"
        t = until(lambda: "c" in spread(20))
        check("passing now: served", t is not None and t < 3, t)
        services["web"][:] = [instance("a", "127.0.0.2", 8080), instance("d", "127.0.0.5", 8080, weight=3),
                              instance("six", "::1", 8086)]
        t = until(lambda: set(spread(30)) == {"a", "d", "six"})
        n = spread(100)
        check("gone and come, an IPv6 one, a weight of 3", t is not None and 2.2 <= n["d"] / max(n["a"], 1) <= 3.8, (t, n))

        # Consul going wrong changes nothing
        good = set(spread(30))
        for how in ("500", "garbage", "403"):
            mode["how"] = how
            asked_more()
            check(f"Consul answering {how}: the servers stay", set(spread(30)) == good, spread(30))
        mode["how"] = "ok"
        agent.shutdown()
        agent.server_close()
        time.sleep(2.2)                     # (nobody to count the questions)
        check("the agent gone: the servers stay", set(spread(30)) == good, spread(30))
        t = log.read_text()
        w = "discover consul web: "
        check("  and each is said once, a 403 as the token's", t.count(w + "Consul refused") == 1
              and t.count(w + "an answer that cannot") == 1 and t.count(w + "Consul said 403: the ACL token") == 1
              and t.count(w + "no answer from the agent") == 1, [l for l in t.splitlines() if "consul" in l])
        agent = S(("127.0.0.1", AGENT), Agent)
        threading.Thread(target=agent.serve_forever, daemon=True).start()
        services["web"][:] = [instance("b", "127.0.0.3", 8080)]
        t = until(lambda: set(spread(10)) == {"b"})
        check("back: followed again", t is not None, (t, spread(10)))
        services["web"][:] = []
        t = until(lambda: get()[0] == 502)
        check("none passing: Consul is believed", t is not None, t)
    finally:
        p.terminate()
        p.wait(10)
        agent.shutdown()
    text = log.read_text()
    check("no process died", "killed" not in text and "seccomp" not in text and "control process exited" not in text, text[-300:])

    def bad(what, line):
        g = tmp / "bad.conf"
        g.write_text(f"pool p {{ {line} }}\nhttp 127.0.0.1:1 {{ route /* {{ to pool p }} }}\n")
        r = subprocess.run([str(BIN), "check", str(g)], capture_output=True, text=True, timeout=10)
        check(f"{what}: refused", r.returncode != 0 and "discover consul" in r.stderr, r.stderr[-200:])
    bad("no service", "discover consul dc=dc1")
    bad("a relative token", "discover consul service=web token=token")
    bad("an agent by name", "discover consul service=web api=consul:8500")
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"consul {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"), flush=True)
    sys.exit(1 if fails else 0)


main()
