#!/usr/bin/env python3
"""A shield tier, on one engine (argument): edges whose pool is two shields,
`balance maglev key=url`, so each object is fetched from the origin by one shield
only, whichever edge asks; Cache-Status says what each cache did, the nearest the
origin first; CDN-Loop (RFC 8586) names the CDN once per hop, and a request that has
gone round in circles gets 508 instead of going round again."""
import http.client
import http.server
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import time

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 55000 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
ORIGIN, S1, S2, E1, E2, LOOP = (BASE + i for i in range(6))
fails = 0
hits = {}
loops = []
lock = threading.Lock()


def check(name, ok, detail=""):
    global fails
    print(("ok  " if ok else "FAIL"), name, detail if not ok else "", flush=True)
    fails += 0 if ok else 1


def until(fn, seconds=8):
    t = time.time()
    while time.time() - t < seconds:
        try:
            if fn():
                return True
        except OSError:
            pass
        time.sleep(0.05)
    return False


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        with lock:
            hits[self.path] = hits.get(self.path, 0) + 1
            loops.append(self.headers.get_all("CDN-Loop") or [])
        b = f"object {self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def get(port, path, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
    c.request("GET", path, headers={"Host": "cdn.example", **(headers or {})})
    r = c.getresponse()
    b = r.read()
    c.close()
    get.shield = r.getheader("x-shield")
    return r.status, b, r.msg.get_all("Cache-Status") or []


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-shield-", dir="/tmp"))
    threading.Thread(target=S(("127.0.0.1", ORIGIN), H).serve_forever, daemon=True).start()
    base = f"okena {{ workers 2; io_engine {ENGINE}; drain delay=0s timeout=1s; cdn_loop examplecdn }}\n"
    one = base.replace("workers 2", "workers 1")      # (a shield: one memory, so a hit is a hit)
    confs = {
        "s1": one + f"pool o {{ server 127.0.0.1:{ORIGIN} }}\nhttp 127.0.0.1:{S1} {{ route /* {{ cache 1h; response header set x-shield s1; to pool o }} }}\n",
        "s2": one + f"pool o {{ server 127.0.0.1:{ORIGIN} }}\nhttp 127.0.0.1:{S2} {{ route /* {{ cache 1h; response header set x-shield s2; to pool o }} }}\n",
        "e1": base + f"pool sh {{ balance maglev key=url; server 127.0.0.1:{S1}; server 127.0.0.1:{S2} }}\n"
              f"http 127.0.0.1:{E1} {{ route /* {{ cache 1h; to pool sh }} }}\n",
        "e2": base + f"pool sh {{ balance maglev key=url; server 127.0.0.1:{S1}; server 127.0.0.1:{S2} }}\n"
              f"http 127.0.0.1:{E2} {{ route /* {{ cache 1h; to pool sh }} }}\n",
        "loop": base + f"pool self {{ server 127.0.0.1:{LOOP} }}\nhttp 127.0.0.1:{LOOP} {{ route /* {{ to pool self }} }}\n",
    }
    procs = []
    for name, text in confs.items():
        (tmp / f"{name}.conf").write_text(text)
        procs.append(subprocess.Popen([str(BIN), "-c", str(tmp / f"{name}.conf")], stdout=subprocess.DEVNULL,
                                      stderr=open(tmp / f"{name}.log", "w")))
    try:
        check("five okenas start", all(until(lambda p=p: get(p, "/up")[0] in (200, 508)) for p in (S1, S2, E1, E2, LOOP)))
        paths = [f"/obj/{i}" for i in range(24)]
        by = {}
        for q in paths:
            get(E1, q)
            by[q] = get.shield
        once = all(hits.get(q) == 1 for q in paths)
        out = [get(E2, q) for q in paths]
        check("each object fetched from the origin once, whichever edge asks (each has one shield)",
              once and all(hits.get(q) == 1 for q in paths) and all(o[0] == 200 for o in out),
              {q: hits.get(q) for q in paths if hits.get(q) != 1})
        again = {}
        for q in paths:
            get(E2, q)
            again[q] = get.shield
        check("  the key spreads them over both shields, the same one for an object from every edge",
              set(by.values()) == {"s1", "s2"} and by == again, (by, again))
        s, b, cs = get(E1, "/fresh/1")
        check("Cache-Status: the shield's, then the edge's", s == 200 and cs == ["okena; fwd=miss; stored", "okena; fwd=miss; stored"], cs)
        s, b, cs = get(E2, "/fresh/1")
        check("  another edge: a miss of its own, a hit at the shield", cs[:1] and cs[0].startswith("okena; hit") and cs[-1] == "okena; fwd=miss; stored", cs)
        last = loops[-1] if loops else []
        names = [x.strip() for f in last for x in f.split(",")]
        check("the origin sees CDN-Loop: the CDN once per hop (edge, shield)", names == ["examplecdn", "examplecdn"], last)
        s, b, cs = get(LOOP, "/round")
        check("a node pointed at itself: 508 after max hops, not round for ever", s == 508, (s, b[:60]))
        s, b, cs = get(E1, "/other", {"CDN-Loop": "someothercdn, someothercdn, someothercdn"})
        check("  another CDN's names do not count", s == 200, s)
        s, b, cs = get(E1, "/came-round", {"CDN-Loop": "examplecdn; v=1, examplecdn, ExampleCDN"})
        check("  ours, with parameters, in any case, three times: 508", s == 508, s)
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            p.wait(10)
    t = "".join((tmp / f"{n}.log").read_text() for n in confs)
    check("no process died", "seccomp" not in t and "killed by signal" not in t, t[-400:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"shield {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


main()
