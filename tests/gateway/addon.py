#!/usr/bin/env python3
"""Addons (phase 13), on one engine (argument). The addon is a Python program
on the SDK (tests/gateway/addon_peer.py) whose answer depends on the path:

  continue as is; fields set, added, removed (content-length left to okena);
  the target rewritten (the backend sees the new path); an answer of its own
  (403 with fields and body, 204 with none, HEAD without the body); a bad
  answer, no answer in time, and a crash: on_error allow lets the request go
  on, deny is 503; the addon is started again and serves; over HTTP/2 too;
  a route without the addon never waits for it, even while it hangs; the
  circuit opens after failures in a row (calls end at once, not at their
  time); a reload keeps the addon's process when its run line is the same and
  starts a new one when it changed; what it is told (client, method, target,
  host); the checker refuses an addon without `run`, a relative program, a
  name used twice, and a route naming none."""
import concurrent.futures
import os
import pathlib
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import http.server

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
PEER = ROOT / "tests" / "gateway" / "addon_peer.py"
L = 41000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
B = L + 1
M = L + 2
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


class Echo(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    wbufsize = -1			# head and body in one write (no Nagle wait)

    def do_GET(self):
        b = (self.requestline + "\n" + str(self.headers)).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(b)
    do_POST = do_HEAD = do_GET

    def log_message(self, *a):
        pass


def get(path, headers=(), method="GET", timeout=5):
    k = socket.create_connection(("127.0.0.1", L), timeout)
    req = f"{method} {path} HTTP/1.1\r\nHost: t\r\n" + "".join(f"{a}: {b}\r\n" for a, b in headers) + "Connection: close\r\n\r\n"
    k.sendall(req.encode())
    d = b""
    try:
        while True:
            x = k.recv(65536)
            if not x:
                break
            d += x
    except OSError:
        pass
    k.close()
    head, _, body = d.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1]) if lines and len(lines[0].split()) > 1 else 0
    hs = {}
    for l in lines[1:]:
        if ":" in l:
            a, b = l.split(":", 1)
            hs.setdefault(a.strip().lower(), []).append(b.strip())
    return status, hs, body


def timed(path):
    t = time.monotonic()
    s, h, b = get(path)
    return s, time.monotonic() - t, b


def wait_started(log, n=1, t=10):
    end = time.time() + t
    while time.time() < end:
        if log.read_text().count("started with") >= n:
            return True
        time.sleep(0.02)
    return False


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-addon-"))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", B), Echo)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    run = f"/usr/bin/python3 {PEER}"
    # the SDKs' examples, built by make (when their toolchains are there)
    hello, ghello, rhello = (ROOT / "build" / f"addon-hello-{x}" for x in ("c", "go", "rust"))
    cbuilt, gbuilt, rbuilt = (os.access(x, os.X_OK) for x in (hello, ghello, rhello))
    if not cbuilt:
        hello = pathlib.Path("/bin/false")
    if not gbuilt:
        ghello = pathlib.Path("/bin/false")
    if not rbuilt:
        rhello = pathlib.Path("/bin/false")
    base = f"""okena {{ workers 2; io_engine {ENGINE}; drain delay=0s timeout=1s; metrics 127.0.0.1:{M} }}
addon chello {{
    run {hello}
    timeout 150ms
}}
addon ghello {{
    run {ghello}
    timeout 150ms
}}
addon rhello {{
    run {rhello}
    timeout 150ms
    poll 200us
}}
addon tagger {{
    run {run}
    timeout 150ms
    on_error allow
    breaker errors=3 open=2s
}}
addon strict {{
    run {run} strict
    timeout 150ms
}}
addon flaky {{
    run {run} flaky
    timeout 100ms
    on_error allow
    breaker errors=3 open=5s
}}
addon brk {{
    run {run} brk
    timeout 100ms
    on_error allow
    breaker errors=3 open=5s
}}
pool echo {{ server 127.0.0.1:{B} }}
http 127.0.0.1:{L} {{
    http2 on
    route /a/* {{ addon tagger; to pool echo }}
    route /s/* {{ addon strict; to pool echo }}
    route /f/* {{ addon flaky; to pool echo }}
    route /k/* {{ addon brk; to pool echo }}
    route /c/* {{ addon chello; to pool echo }}
    route /g/* {{ addon ghello; to pool echo }}
    route /r/* {{ addon rhello; to pool echo }}
    route /both/* {{ addon tagger; addon strict; to pool echo }}
    route /* {{ to pool echo }}
}}
"""
    conf.write_text(base)
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        check("okena starts with addons", wait_started(log), log.read_text()[-400:])
        s, h, b = get("/a/pass", [("X-Drop", "1")])
        check("continue: the backend answers, the request as it was", s == 200 and b"GET /a/pass HTTP/1.1" in b and b"X-Drop: 1" in b, (s, b))
        s, h, b = get("/a/set", [("X-Drop", "1"), ("X-Addon", "client")])
        check("fields set (the client's replaced), added twice, removed", s == 200 and b"x-addon: yes" in b and b"X-Addon: client" not in b
              and b.count(b"x-multi:") == 2 and b"X-Drop" not in b, b)
        check("  content-length is okena's: the addon's is left out", b"content-length: 999" not in b.lower(), b)
        s, h, b = get("/a/target")
        check("the target rewritten: the backend sees the new path", s == 200 and b"GET /rewritten?q=1 HTTP/1.1" in b, b)
        s, h, b = get("/a/deny")
        check("the addon answers itself: 403, its fields, its body", s == 403 and h.get("x-why") == ["test"]
              and b == b"denied by addon\n" and h.get("content-length") == ["16"] and "x-request-id" in h, (s, h, b))
        s, h, b = get("/a/deny", method="HEAD")
        check("  HEAD: its length, no body", s == 403 and b == b"" and h.get("content-length") == ["16"], (s, h, b))
        s, h, b = get("/a/empty")
        check("  204: no body, no length", s == 204 and b == b"" and "content-length" not in h and h.get("x-why") == ["empty"], (s, h, b))
        s, h, b = get("/a/info")
        check("what the addon is told: client, method, target, host", s == 200 and h.get("x-client") == ["127.0.0.1"]
              and h.get("x-method") == ["GET"] and h.get("x-target") == ["/a/info"] and h.get("x-host") == ["t"], h)
        s, d, b = timed("/a/none")
        check("no answer: on_error allow after the timeout", s == 200 and 0.12 < d < 1.0 and b"GET /a/none" in b, (s, d))
        s, d, b = timed("/s/none")
        check("no answer: on_error deny is 503", s == 503 and 0.12 < d < 1.0, (s, d))
        s, h, b = get("/a/bad")
        check("a bad answer (a field that is not one): on_error allow", s == 200 and b"bad name" not in b, (s, b))
        s, h, b = get("/s/bad")
        check("  and deny: 503", s == 503, s)
        s, h, b = get("/both/set")
        check("two addons, in order: both asked, both changes kept", s == 200 and b.count(b"x-addon: yes") == 1 and b.count(b"x-multi") == 4, b)
        s, h, b = get("/both/deny")
        check("  the first answering itself: the second is not asked", s == 403, s)
        s, h, b = get("/plain")
        check("a route without addons: as before", s == 200 and b"GET /plain" in b, (s, b))
        if not cbuilt:
            print("skip the C SDK: no build/addon-hello-c", flush=True)
        if cbuilt:
            s, h, b = get("/c/x", [("X-Debug", "1")])
            check("the C SDK: continue with a field set, one removed", s == 200 and b"x-checked: yes" in b and b"X-Debug" not in b, b)
            s, h, b = get("/c/blocked")
            check("  its own answer", s == 403 and b == b"blocked by the addon\n" and h.get("content-type") == ["text/plain"], (s, h, b))
            s, h, b = get("/c/pass", [("X-Debug", "1")])
            check("  continue as is", s == 200 and b"X-Debug: 1" in b, b)
        for name, pre, built in (("Go", "/g", gbuilt), ("Rust", "/r", rbuilt)):
            if not built:
                print(f"skip the {name} SDK: no toolchain", flush=True)
                continue
            s1, h1, b1 = get(pre + "/x", [("X-Debug", "1")])
            s2, h2, b2 = get(pre + "/blocked")
            s3, h3, b3 = get(pre + "/pass", [("X-Debug", "1")])
            check(f"the {name} SDK: a field set and one removed, its own answer, continue as is",
                  s1 == 200 and b"x-checked: yes" in b1 and b"X-Debug" not in b1 and s2 == 403 and b2 == b"blocked by the addon\n"
                  and s3 == 200 and b"X-Debug: 1" in b3, (s1, b1, s2, b2, s3, b3))
        # HTTP/2 through the same stage
        if shutil.which("curl"):
            c = subprocess.run(["curl", "-q", "-s", "--http2-prior-knowledge", "-D", "-", "-H", "X-Drop: 1",
                                f"http://127.0.0.1:{L}/a/set", f"http://127.0.0.1:{L}/a/deny"], capture_output=True, timeout=10)
            o = c.stdout
            check("HTTP/2: continue with fields, and the addon's own answer", b"HTTP/2 200" in o and b"x-addon: yes" in o
                  and b"HTTP/2 403" in o and b"denied by addon" in o and b"X-Drop" not in o.split(b"HTTP/2 403")[0], o[:600])
        # many at once
        with concurrent.futures.ThreadPoolExecutor(16) as ex:
            r = list(ex.map(lambda i: get(f"/a/set?{i}")[0], range(100)))
        check("100 requests, 16 at a time: all through the addon", r.count(200) == 100, {x: r.count(x) for x in set(r)})
        # a hanging addon: routes without it never wait
        hang = threading.Thread(target=lambda: [get("/f/slow") for _ in range(3)])
        hang.start()
        time.sleep(0.05)
        t = time.monotonic()
        r = [get("/plain")[0] for _ in range(20)]
        d = time.monotonic() - t
        hang.join()
        check("an addon that hangs: other routes go on (20 requests)", r.count(200) == 20 and d < 0.5, (r.count(200), d))
        # the circuit (each worker's own): on one connection, so one worker,
        # three calls past their time in a row, then calls end at once
        k = socket.create_connection(("127.0.0.1", L), 5)
        k.settimeout(5)
        took = []
        for _ in range(4):
            t = time.monotonic()
            k.sendall(b"GET /k/none HTTP/1.1\r\nHost: t\r\n\r\n")
            d = b""
            while b"\r\n\r\n" not in d or len(d.partition(b"\r\n\r\n")[2]) < int(d.split(b"Content-Length: ")[1].split(b"\r\n")[0]):
                d += k.recv(65536)
            took.append(time.monotonic() - t)
        k.close()
        check("the circuit opens after errors=3: the next call ends at once", all(x > 0.09 for x in took[:3]) and took[3] < 0.05, took)
        # a crash: on_error at once, then started again
        pid0 = get("/a/pid")[1].get("x-addon-pid")
        s, d, b = timed("/a/crash")
        check("an addon that crashes: its call ends at once, on_error allow", s == 200 and d < 0.14, (s, d))
        s, d, b = timed("/s/crash")
        check("  and on_error deny: 503", s == 503, s)
        end = time.time() + 5
        pid1 = None
        while time.time() < end:
            pid1 = get("/a/pid")[1].get("x-addon-pid")
            if pid1 and pid1 != pid0:
                break
            time.sleep(0.05)
        check("  started again: a new process serves", pid1 is not None and pid1 != pid0, (pid0, pid1))
        t = log.read_text()
        check("  its exit is logged", "addon tagger exited with status 3" in t, t[-500:])
        s, h, b = get("/a/set")
        check("  and answers as before", s == 200 and b"x-addon: yes" in b, b)
        k = socket.create_connection(("127.0.0.1", M), 5)
        k.sendall(b"GET /metrics HTTP/1.1\r\nHost: m\r\nConnection: close\r\n\r\n")
        mt = b""
        while True:
            x = k.recv(65536)
            if not x:
                break
            mt += x
        k.close()
        mt = mt.decode()

        def metric(line):
            for l in mt.splitlines():
                if l.startswith(line + " "):
                    return int(l.rsplit(" ", 1)[1])
            return -1
        check("/metrics: calls answered, timeouts, crashes, errors", metric('okena_addon_calls_total{addon="tagger",result="answered"}') > 10
              and metric('okena_addon_calls_total{addon="tagger",result="timeout"}') >= 1
              and metric('okena_addon_calls_total{addon="tagger",result="crashed"}') >= 1
              and metric('okena_addon_calls_total{addon="tagger",result="error"}') >= 1, mt[-2500:])
        check("  on_error allow and deny, its own answers, the circuit", metric('okena_addon_on_error_total{addon="tagger",action="allow"}') >= 3
              and metric('okena_addon_on_error_total{addon="strict",action="deny"}') >= 3
              and metric('okena_addon_responses_total{addon="tagger"}') >= 3
              and metric('okena_addon_circuit_opened_total{addon="brk"}') >= 1, mt[-2500:])
        check("  starts (twice after its crash) and up", metric('okena_addon_starts_total{addon="tagger"}') == 2
              and metric('okena_addon_up{addon="tagger"}') == 1, mt[-2500:])
        # a reload: the same run line keeps the process; a new one starts another
        pid_t = get("/a/pid")[1].get("x-addon-pid")
        pid_s = get("/s/pid")[1].get("x-addon-pid")
        conf.write_text(base.replace(f"run {run} strict", f"run {run} strict2"))
        p.send_signal(signal.SIGHUP)
        end = time.time() + 10
        while time.time() < end and "configuration reloaded" not in log.read_text():
            time.sleep(0.02)
        check("reload", "configuration reloaded" in log.read_text(), log.read_text()[-300:])
        pid_t2 = get("/a/pid")[1].get("x-addon-pid")
        pid_s2 = get("/s/pid")[1].get("x-addon-pid")
        check("  the same run line: the same process", pid_t2 == pid_t and pid_t is not None, (pid_t, pid_t2))
        check("  a changed run line: a new process", pid_s2 is not None and pid_s2 != pid_s, (pid_s, pid_s2))
        s, h, b = get("/s/deny")
        check("  and it serves", s == 403, s)
        # the old one goes once the old workers are gone
        end = time.time() + 6
        gone = False
        while time.time() < end:
            try:
                os.kill(int(pid_s[0]), 0)
            except (OSError, TypeError, ValueError):
                gone = True
                break
            time.sleep(0.05)
        check("  the dropped one stopped once no old worker is left", gone, pid_s)
        apids = [int(x[0]) for x in (pid_t2, pid_s2) if x]
    finally:
        p.terminate()
        p.wait(10)
    time.sleep(0.2)
    alive = []
    for x in apids if 'apids' in dir() else []:
        try:
            os.kill(x, 0)
            alive.append(x)
        except OSError:
            pass
    check("okena stopped: its addons are gone", not alive, alive)
    t = log.read_text()
    check("no worker died", "killed" not in t and "seccomp" not in t and "crashed" not in t, t[-500:])
    # okena started with no addon: a reload that brings one is refused (the
    # launcher can only be made at the start), and okena serves on
    conf2 = tmp / "none.conf"
    conf2.write_text(f"""okena {{ workers 1; io_engine {ENGINE}; drain delay=0s timeout=1s }}
pool echo {{ server 127.0.0.1:{B} }}
http 127.0.0.1:{L} {{ route /* {{ to pool echo }} }}
""")
    log2 = tmp / "log2"
    p = subprocess.Popen([str(BIN), "-c", str(conf2)], stderr=open(log2, "w"))
    try:
        wait_started(log2)
        kids = [int(c) for t in os.listdir(f"/proc/{p.pid}/task") for c in open(f"/proc/{p.pid}/task/{t}/children").read().split()]
        check("no addon: no launcher process", all(open(f"/proc/{k}/comm").read().strip() == "okena-worker" for k in kids), kids)
        conf2.write_text(base)
        p.send_signal(signal.SIGHUP)
        end = time.time() + 5
        while time.time() < end and "reload rejected" not in log2.read_text():
            time.sleep(0.02)
        check("a reload bringing the first addon: rejected, said why", "okena started with no addon" in log2.read_text(), log2.read_text()[-300:])
        check("  and the old configuration serves", get("/a/set")[0] == 200 and b"x-addon" not in get("/a/set")[2])
    finally:
        p.terminate()
        p.wait(10)
    # the checker
    for bad, why in ((f"addon x {{ timeout 1s }}\nhttp 127.0.0.1:{L} {{ route /* {{ addon x; to 127.0.0.1:1 }} }}\n", "run"),
                     (f"addon x {{ run python3 x.py }}\nhttp 127.0.0.1:{L} {{ route /* {{ addon x; to 127.0.0.1:1 }} }}\n", "absolute"),
                     (f"addon x {{ run /bin/true }}\naddon x {{ run /bin/true }}\nhttp 127.0.0.1:{L} {{ route /* {{ to 127.0.0.1:1 }} }}\n", "already"),
                     (f"http 127.0.0.1:{L} {{ route /* {{ addon nope; to 127.0.0.1:1 }} }}\n", "no addon named")):
        f = tmp / "bad.conf"
        f.write_text(bad)
        r = subprocess.run([str(BIN), "check", str(f)], capture_output=True, text=True)
        check(f"checker refuses: {why}", r.returncode == 2 and why in r.stderr, r.stderr)
    srv.shutdown()
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"addon {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
