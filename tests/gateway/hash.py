#!/usr/bin/env python3
"""`balance maglev`, `ring-hash` and `source-hash` on one engine (argument):
the same key to the same server on every worker, shares by weight, and few
keys moving when a server goes."""
import collections
import http.client
import http.server
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
MAG, RING, PATHS, COOK, TCP, UDP, RW, QRY, HOT, COLD = 18620, 18621, 18622, 18623, 18624, 18625, 18626, 18627, 18628, 18629
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok  " if ok else "FAIL"), name, detail if not ok else "", flush=True)
    fails += 0 if ok else 1


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    disable_nagle_algorithm = True

    def do_GET(self):
        sv = self.server
        with sv.lock:
            sv.now += 1
            sv.most = max(sv.most, sv.now)
        if "s=" in self.path:
            time.sleep(float(self.path.split("s=")[1].split("&")[0]))
        with sv.lock:
            sv.now -= 1
        b = self.server.name.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 256


def backend(name):
    s = S(("127.0.0.1", 0), H)
    s.name, s.now, s.most, s.lock = name, 0, 0, threading.Lock()
    SERVERS[name + str(s.server_address[1])] = s
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return f"127.0.0.1:{s.server_address[1]}"


SERVERS = {}


def tcp_backend(name):
    l = socket.socket()
    l.bind(("127.0.0.1", 0))
    l.listen(64)

    def run():
        while True:
            c, a = l.accept()
            try:
                c.sendall(name.encode())
            except OSError:
                pass
            c.close()
    threading.Thread(target=run, daemon=True).start()
    return f"127.0.0.1:{l.getsockname()[1]}"


def udp_backend(name):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("127.0.0.1", 0))

    def run():
        while True:
            m, a = u.recvfrom(100)
            u.sendto(name.encode(), a)
    threading.Thread(target=run, daemon=True).start()
    return f"127.0.0.1:{u.getsockname()[1]}"


def get(port, path="/", **h):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("GET", path, headers={k.replace("_", "-"): v for k, v in h.items()})
    r = c.getresponse()
    b = r.read().decode()
    c.close()
    return r.status, b


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-hash-", dir="/tmp"))
    conf = tmp / "okena.conf"
    names = [f"s{i}" for i in range(6)]
    web = {n: backend(n) for n in names}
    heavy = {n: backend(n) for n in ("w3", "w1")}
    tcp = {n: tcp_backend(n) for n in names[:4]}
    udp = {n: udp_backend(n) for n in names[:4]}
    hot = {n: backend(n) for n in ("h0", "h1", "h2", "h3")}
    cold = {n: backend(n) for n in ("c0", "c1", "c2", "c3")}

    def text(skip=()):
        lines = lambda d: "".join(f" server {a};" for n, a in d.items() if n not in skip)
        return f"""okena {{ workers 4; io_engine {ENGINE}; admin unix:{tmp}/a.sock }}
pool mag {{ balance maglev key=header:x-user;{lines(web)} }}
pool ring {{ balance ring-hash key=header:x-user;{lines(web)} }}
pool paths {{ balance ring-hash key=path;{lines(web)} }}
pool cook {{ balance maglev key=cookie:sid;{lines(web)} }}
pool heavy {{ balance maglev key=header:x-user; server {heavy['w3']} weight=3; server {heavy['w1']} }}
pool t {{ balance source-hash;{lines(tcp)} }}
pool u {{ balance source-hash;{lines(udp)} }}
pool qry {{ balance maglev key=query:id;{lines(web)} }}
pool hot {{ balance maglev key=header:x-user bound=125%;{lines(hot)} }}
pool cold {{ balance maglev key=header:x-user;{lines(cold)} }}
http 127.0.0.1:{MAG} {{ route /* {{ to pool mag }} }}
http 127.0.0.1:{RING} {{ route /* {{ to pool ring }} }}
http 127.0.0.1:{PATHS} {{ route /* {{ to pool paths }} }}
http 127.0.0.1:{COOK} {{ route /* {{ to pool cook }} }}
http 127.0.0.1:{RW} {{ route /* {{ to pool heavy }} }}
tcp 127.0.0.1:{TCP} {{ to pool t }}
udp 127.0.0.1:{UDP} {{ to pool u; responses 1 }}
http 127.0.0.1:{QRY} {{ route /* {{ to pool qry }} }}
http 127.0.0.1:{HOT} {{ route /* {{ to pool hot }} }}
http 127.0.0.1:{COLD} {{ route /* {{ to pool cold }} }}
"""
    conf.write_text(text())
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))

    def ctl(*a):
        return subprocess.run([str(BIN), *a, "-c", str(conf)], capture_output=True, text=True, timeout=40)

    def users(port, n=300, **kw):
        return {u: get(port, x_user=u, **kw)[1] for u in (f"user{i}" for i in range(n))}

    try:
        for i in range(100):
            try:
                if get(MAG)[0] == 200:
                    break
            except OSError:
                time.sleep(0.05)
        for port, name in ((MAG, "maglev"), (RING, "ring-hash")):
            a = users(port)
            again = [get(port, x_user=u)[1] == s for u, s in list(a.items())[:60] for k in range(3)]
            check(f"{name}: a key goes to one server, whatever the connection and worker", all(again), again.count(False))
            n = collections.Counter(a.values())
            check(f"  and the keys are shared out ({name})", len(n) == 6 and min(n.values()) >= 300 / 6 * (0.5 if name == "maglev" else 0.4), n)
        a = users(MAG)
        b = users(RING)
        st, body = get(MAG)
        check("no key: served all the same", st == 200 and body in names, (st, body))
        n = collections.Counter(get(MAG)[1] for i in range(60))
        check("  and drawn at random", len(n) >= 4, n)

        # one goes: by the admin's drain, and by the file
        gone = "s2"
        ctl("backend", "drain", "mag", web[gone])
        ctl("backend", "drain", "ring", web[gone])
        time.sleep(0.05)
        a2, b2 = users(MAG), users(RING)
        for name, x, y in (("maglev", a, a2), ("ring-hash", b, b2)):
            moved = [u for u in x if x[u] != y[u]]
            check(f"{name}, a server drained: only its keys move", all(x[u] == gone for u in moved) and all(y[u] != gone for u in y),
                  [(u, x[u], y[u]) for u in moved if x[u] != gone][:5])
        ctl("backend", "up", "mag", web[gone])
        ctl("backend", "up", "ring", web[gone])
        check("  up again: they come back", users(MAG) == a and users(RING) == b)
        conf.write_text(text(skip=(gone,)))
        r = ctl("reload")
        a3, b3 = users(MAG), users(RING)
        for name, x, y, slack in (("maglev", a, a3, 0.08), ("ring-hash", b, b3, 0.0)):
            stray = sum(1 for u in x if x[u] != gone and x[u] != y[u])
            check(f"{name}, a server out of the file: few others move", r.returncode == 0 and stray <= len(x) * slack, (stray, len(x)))
        conf.write_text(text())
        ctl("reload")
        check("  and the same file again gives the same", users(MAG) == a and users(RING) == b)

        # other keys
        n = {f"/item/{i}": get(PATHS, f"/item/{i}")[1] for i in range(120)}
        same = all(get(PATHS, f"/item/{i}?v={i}")[1] == n[f"/item/{i}"] for i in range(40))
        check("key=path: the path, not the query", same and len(set(n.values())) >= 4, collections.Counter(n.values()))
        c = {s: get(COOK, cookie=f"theme=dark; sid={s}; x=1")[1] for s in ("a", "b", "c", "d", "e", "f", "g", "h")}
        check("key=cookie:sid: that cookie only", all(get(COOK, cookie=f"sid={s}")[1] == c[s] for s in c), c)
        q = {i: get(QRY, f"/x?a=1&id={i}&b=2")[1] for i in range(60)}
        check("key=query:id: that parameter only", all(get(QRY, f"/y?id={i}")[1] == q[i] for i in range(30)) and len(set(q.values())) >= 4,
              collections.Counter(q.values()))
        st, w0 = get(QRY, "/x?a=1")
        check("  a request without it: served", st == 200 and w0 in names, (st, w0))

        # a hot key: bounded, it spills; unbounded, it does not
        one = {get(HOT, x_user="hot")[1] for i in range(20)}
        check("bound=125%: light, a key stays on its server", len(one) == 1, one)
        from concurrent.futures import ThreadPoolExecutor

        def burst(port):
            with ThreadPoolExecutor(40) as ex:
                return collections.Counter(ex.map(lambda i: get(port, "/?s=0.5", x_user="hot")[1], range(40)))
        h, c = burst(HOT), burst(COLD)
        most_h = max(SERVERS[k].most for k in SERVERS if k[:2] in ("h0", "h1", "h2", "h3"))
        most_c = max(SERVERS[k].most for k in SERVERS if k[:2] in ("c0", "c1", "c2", "c3"))
        check("  40 at once on one key: it spills, only as far as it must", len(h) >= 3 and most_h <= 20, (h, most_h))
        check("  where without bound it all goes to one", len(c) == 1 and most_c >= 30, (c, most_c))
        w = collections.Counter(users(RW, 400).values())
        check("weights: 3 to 1", 2.0 <= w["w3"] / max(w["w1"], 1) <= 4.5, w)

        # source-hash, on stream and datagrams: the client's address
        def tcp_from(ip):
            s = socket.socket()
            s.bind((ip, 0))
            s.settimeout(3)
            s.connect(("127.0.0.1", TCP))
            r = s.recv(10).decode()
            s.close()
            return r

        def udp_from(ip):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((ip, 0))
            s.settimeout(2)
            s.sendto(b"q", ("127.0.0.1", UDP))
            r = s.recv(10).decode()
            s.close()
            return r
        ips = [f"127.0.{i // 200}.{i % 200 + 2}" for i in range(80)]
        t = {ip: tcp_from(ip) for ip in ips}
        check("source-hash, tcp: one server for an address, from any port", all(tcp_from(ip) == t[ip] for ip in ips[:20]) and len(set(t.values())) == 4,
              collections.Counter(t.values()))
        u = {ip: udp_from(ip) for ip in ips}
        check("source-hash, udp: the same", all(udp_from(ip) == u[ip] for ip in ips[:20]) and len(set(u.values())) == 4, collections.Counter(u.values()))
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no worker died", "killed" not in t and "restarting" not in t and "seccomp" not in t, t[-300:])

    def bad(what, body, word):
        f = tmp / "bad.conf"
        f.write_text(f"pool p {{ {body}; server 127.0.0.1:1 }}\nhttp 127.0.0.1:1 {{ route /* {{ to pool p }} }}\n")
        r = subprocess.run([str(BIN), "check", str(f)], capture_output=True, text=True, timeout=10)
        check(f"{what}: refused", r.returncode != 0 and word in r.stderr, r.stderr[-200:])
    bad("a key that is no key", "balance maglev key=nothing", "key")
    bad("a key for round-robin", "balance round-robin key=source", "key")
    bad("a header with no name", "balance maglev key=header:", "key")
    bad("bound for round-robin", "balance round-robin bound=125%", "bound")
    bad("bound of 100%", "balance maglev bound=100%", "bound")
    bad("bound with no %", "balance maglev bound=125", "bound")
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"hash {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"), flush=True)
    sys.exit(1 if fails else 0)


main()
