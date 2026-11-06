#!/usr/bin/env python3
"""`okena upgrade`, on one engine (argument): a new okena takes the listening sockets from
the running one with clients connecting all the while, and none is refused or lost. If
the new one cannot start, the old one must not notice."""
import http.client
import http.server
import os
import pathlib
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
BIN = HERE.parents[1] / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 3000 + os.getpid() % 90 * 6 + (3 if ENGINE == "epoll" else 0)
BACK, LST, MET, OTHER = BASE, BASE + 1, BASE + 2, BASE + 3
fails = 0


def check(name, ok, more=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {more}"), flush=True)
    fails += 0 if ok else 1


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path == "/slow":
            time.sleep(1.5)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 256
    allow_reuse_address = True


def get(path="/", port=LST):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
    c.request("GET", path)
    r = c.getresponse()
    b = r.read()
    c.close()
    return r.status, b


CONF = """okena {{ workers 2; io_engine {engine}; upgrade {tmp}/up.sock; metrics 127.0.0.1:{met} }}
pool b {{ server 127.0.0.1:{back} }}
http 127.0.0.1:{lst} {{ route /* {{ to pool b }} }}
"""


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-up."))
    threading.Thread(target=S(("127.0.0.1", BACK), H).serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    args = dict(engine=ENGINE, tmp=tmp, met=MET, back=BACK, lst=LST)
    conf.write_text(CONF.format(**args))
    log, log2, log3 = tmp / "log", tmp / "log2", tmp / "log3"
    a = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    procs = [a]
    stop = threading.Event()
    bad = []
    n = [0]
    def clients():
        while not stop.is_set():
            try:
                r = get()
                if r != (200, b"ok"):
                    bad.append(r)
                n[0] += 1
            except Exception as e:
                bad.append(repr(e))
    try:
        for i in range(50):
            try:
                socket.create_connection(("127.0.0.1", LST), 1).close()
                break
            except OSError:
                time.sleep(0.1)
        s = os.stat(tmp / "up.sock")
        check("the path is its owner's only", stat.S_IMODE(s.st_mode) == 0o600, oct(s.st_mode))
        th = [threading.Thread(target=clients) for i in range(4)]
        [t.start() for t in th]
        time.sleep(0.3)

        # one that cannot start
        conf.write_text("okena { nonsense }\n")
        q = subprocess.run(["timeout", "5", str(BIN), "upgrade", "-c", str(conf)], capture_output=True, text=True, timeout=8)
        check("a bad configuration: it does not start", q.returncode not in (0, 124) and q.stderr != "", q.stderr[-100:])
        conf.write_text(CONF.format(**args))
        time.sleep(0.3)
        check("  the running one goes on", a.poll() is None and not bad, bad[:2])

        # the real one, with a request in the middle of being answered
        res = {}
        slow = threading.Thread(target=lambda: res.update(s=get("/slow")))
        slow.start()
        time.sleep(0.2)
        b = subprocess.Popen([str(BIN), "upgrade", "-c", str(conf)], stderr=open(log2, "w"))
        procs.append(b)
        for i in range(60):
            if "taken over" in log2.read_text():
                break
            time.sleep(0.1)
        check("the new one took over", "taken over" in log2.read_text(), log2.read_text()[-300:])
        for i in range(80):
            if a.poll() is not None:
                break
            time.sleep(0.1)
        check("  the old one left", a.poll() == 0, (a.poll(), log.read_text()[-300:]))
        slow.join()
        check("  the request it was answering was answered", res.get("s") == (200, b"ok"), res)
        check("  not one client refused or lost", not bad and n[0] > 50, (len(bad), bad[:2], n[0]))
        m = get("/metrics", MET)
        check("  metrics are the new one's", m[0] == 200, m[:1])
        check("  and it answers", get() == (200, b"ok"))

        # and again: the new one can be replaced
        c = subprocess.Popen([str(BIN), "upgrade", "-c", str(conf)], stderr=open(log3, "w"))
        procs.append(c)
        for i in range(80):
            if b.poll() is not None:
                break
            time.sleep(0.1)
        check("a third takes over from the second", b.poll() == 0 and "taken over" in log3.read_text(), (b.poll(), log3.read_text()[-300:]))
        check("  not one lost", not bad, bad[:2])
        stop.set()
        [t.join() for t in th]
        # a listener only the new configuration has, and one it no longer has
        conf.write_text(CONF.format(**args).replace(f"http 127.0.0.1:{LST}", f"http 127.0.0.1:{OTHER} {{ route /* {{ to pool b }} }}\nhttp 127.0.0.1:{LST}"))
        log4 = tmp / "log4"
        d = subprocess.Popen([str(BIN), "upgrade", "-c", str(conf)], stderr=open(log4, "w"))
        procs.append(d)
        for i in range(80):
            if c.poll() is not None:
                break
            time.sleep(0.1)
        check("a new listener opens, the one that stays stays", get(port=OTHER) == (200, b"ok") and get() == (200, b"ok"))
        check("no worker died", all("killed" not in f.read_text() for f in (log, log2, log3, log4)))
    finally:
        stop.set()
        for x in procs:
            if x.poll() is None:
                x.terminate()
        for x in procs:
            try:
                x.wait(10)
            except subprocess.TimeoutExpired:
                x.kill()
    q = subprocess.run(["timeout", "5", str(BIN), "upgrade", "-c", str(conf)], capture_output=True, text=True, timeout=8)
    check("no okena to take over from: an error", q.returncode not in (0, 124) and "no okena" in q.stderr, q.stderr[-140:])
    (tmp / "nopath.conf").write_text(f"pool b {{ server 127.0.0.1:1 }}\nhttp 127.0.0.1:{LST} {{ route /* {{ to pool b }} }}\n")
    q = subprocess.run(["timeout", "5", str(BIN), "upgrade", "-c", str(tmp / "nopath.conf")], capture_output=True, text=True, timeout=8)
    check("no `upgrade` path: an error", q.returncode not in (0, 124) and "upgrade" in q.stderr, q.stderr[-140:])
    print(f"upgrade {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
