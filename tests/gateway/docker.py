#!/usr/bin/env python3
"""`discover docker` on one engine (argument), against a fake Engine API on a
unix socket: running, healthy containers with the label, on their network and
port, followed as they come and go, and kept when Docker goes wrong."""
import collections
import http.client
import http.server
import json
import pathlib
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
LST, NET = 18700, 18701
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


def backend(name, ip, port):
    s = S((ip, port), Back)
    s.name = name
    threading.Thread(target=s.serve_forever, daemon=True).start()


# the fake Docker: its containers, and how it answers
containers = []
mode = {"how": "ok"}
asked = []


def container(name, ip, labels, ports=(), status="Up 3 minutes", state="running", nets=None):
    return {"Id": name * 8, "Names": [f"/{name}"], "Image": "app:1", "Command": "run \"it\"",
            "State": state, "Status": status, "Labels": labels,
            "Ports": [{"IP": "0.0.0.0", "PrivatePort": p, "PublicPort": 30000 + p, "Type": t} for p, t in ports],
            "Mounts": [], "HostConfig": {"NetworkMode": "default"},
            "NetworkSettings": {"Networks": nets or {"bridge": {"IPAMConfig": None, "Links": None, "IPAddress": ip,
                                                              "Gateway": "127.0.0.1", "Aliases": ["a\\\\b"]}}}}


class Docker(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        asked.append(self.path)
        u = urllib.parse.urlparse(self.path)
        if mode["how"] == "500" or u.path != "/containers/json":
            self.send_response(500)
            self.end_headers()
            return
        f = json.loads(urllib.parse.parse_qs(u.query)["filters"][0])
        want = f["label"][0]
        k, _, v = want.partition("=")
        out = [c for c in containers if k in c["Labels"] and (not v or c["Labels"][k] == v)]
        body = json.dumps(out, indent=1).encode() if mode["how"] != "garbage" else b'[{"State": "running", "Labels": {'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class U(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


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
        time.sleep(0.1)
    return None


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-docker-", dir="/tmp"))
    sock = tmp / "docker.sock"
    d = U(str(sock), Docker)
    threading.Thread(target=d.serve_forever, daemon=True).start()
    for name, ip, port in (("a", "127.0.0.2", 8080), ("b", "127.0.0.3", 8080), ("c", "127.0.0.4", 9090),
                           ("d", "127.0.0.5", 8080), ("n", "127.0.0.6", 8080), ("w", "127.0.0.7", 8080)):
        backend(name, ip, port)
    L = {"okena.pool": "web", "com.docker.compose.service": "web"}
    containers[:] = [container("a", "127.0.0.2", dict(L), [(8080, "tcp")]),
                     container("b", "127.0.0.3", dict(L, **{"okena.port": "8080"}), [(8080, "tcp"), (8443, "tcp")]),
                     container("c", "127.0.0.4", dict(L, **{"okena.port": "9090"}), status="Up 1 second (health: starting)"),
                     container("x", "127.0.0.9", {"okena.pool": "other"}, [(8080, "tcp")]),
                     container("n", "", {"okena.pool": "net"}, [(8080, "tcp")],
                               nets={"front": {"IPAddress": "10.9.9.9"}, "back": {"IPAddress": "127.0.0.6"}})]
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ drain delay=0s timeout=1s; workers 2; io_engine {ENGINE} }}
pool web {{ balance round-robin; discover docker label=okena.pool=web socket={sock} }}
pool net {{ discover docker label=okena.pool=net network=back socket={sock} }}
http 127.0.0.1:{LST} {{ route /* {{ to pool web }} }}
http 127.0.0.1:{NET} {{ route /* {{ to pool net }} }}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for i in range(100):
            if get()[0]:
                break
            time.sleep(0.05)
        n = spread()
        check("the running ones with the label: a by the one port it exposes, b by okena.port", set(n) == {"a", "b"}, n)
        check("  the label sent in the filter, as Docker wants it", any("filters=%7B%22label%22%3A%5B%22okena.pool%3Dweb%22%5D%7D" in a for a in asked), asked[:2])
        check("  not one with another label, nor one that is starting", "x" not in n and "c" not in n, n)
        check("network=back: its address there", set(spread(port=NET)) == {"n"}, spread(port=NET))

        containers[2]["Status"] = "Up 30 seconds (healthy)"
        t = until(lambda: "c" in spread(20))
        check("healthy now: served, on its okena.port", t is not None and t < 3, t)
        containers[2]["Status"] = "Up 40 seconds (unhealthy)"
        t = until(lambda: "c" not in spread(20))
        check("unhealthy: no more", t is not None, t)

        containers.append(container("d", "127.0.0.5", dict(L, **{"okena.weight": "3"}), [(8080, "tcp")]))
        del containers[1]                       # b goes, d comes
        t = until(lambda: set(spread(20)) == {"a", "d"})
        n = spread(80)
        check("one gone, one come, with weight 3", t is not None and 2.4 <= n["d"] / max(n["a"], 1) <= 3.6, (t, n))
        containers.append(container("e", "127.0.0.8", dict(L), [(8080, "tcp"), (9000, "tcp")]))
        containers.append(container("f", "127.0.0.8", dict(L), [], state="exited", status="Exited (0) 1 minute ago"))
        time.sleep(2.2)
        check("one with two ports and no okena.port, one exited: left out, the others served", set(spread(20)) == {"a", "d"}, spread(20))

        # Docker going wrong changes nothing
        good = spread(20)
        for how in ("500", "garbage"):
            mode["how"] = how
            time.sleep(2.2)
            check(f"Docker answering {how}: the servers stay", set(spread(20)) == set(good), spread(20))
        mode["how"] = "ok"
        d.shutdown()
        d.server_close()
        sock.unlink()
        time.sleep(2.2)
        check("Docker gone: the servers stay", set(spread(20)) == set(good))
        t = log.read_text()
        w = "docker okena.pool=web: "
        check("  and each is said once", t.count(w + "Docker refused") == 1 and t.count(w + "an answer that cannot") == 1 and t.count(w + "no answer on the socket") == 1, t[-500:])
        d = U(str(sock), Docker)
        threading.Thread(target=d.serve_forever, daemon=True).start()
        containers[:] = [container("w", "127.0.0.7", dict(L), [(8080, "tcp")])]
        t = until(lambda: set(spread(10)) == {"w"})
        check("back: followed again", t is not None, (t, spread(10)))
        containers[:] = []
        t = until(lambda: get()[0] == 502)
        check("none left: Docker is believed", t is not None, t)
    finally:
        p.terminate()
        p.wait(10)
        d.shutdown()
    text = log.read_text()
    check("no process died", "killed" not in text and "seccomp" not in text and "control process exited" not in text, text[-300:])

    def bad(what, line):
        g = tmp / "bad.conf"
        g.write_text(f"pool p {{ {line} }}\nhttp 127.0.0.1:1 {{ route /* {{ to pool p }} }}\n")
        r = subprocess.run([str(BIN), "check", str(g)], capture_output=True, text=True, timeout=10)
        check(f"{what}: refused", r.returncode != 0, r.stderr[-200:])
    bad("no label", "discover docker port=80")
    bad("a relative socket", "discover docker label=x socket=docker.sock")
    bad("a label with a quote", 'discover docker label=a"b')
    bad("a file with no path", "discover file port=80")
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"docker {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"), flush=True)
    sys.exit(1 if fails else 0)


main()
