#!/usr/bin/env python3
"""make soak: okena under steady load for a long time, reloaded and upgraded
(a new binary taking over) again and again, losing no request.

    SOAK_SECONDS  how long (600; a week is 604800)
    SOAK_RELOAD   seconds between reloads (60), each changing the configuration
    SOAK_UPGRADE  seconds between upgrades (60), each a new okena process
    SOAK_ENGINE   io_uring or epoll

Load: HTTP/1.1 kept alive and on a new connection each time, HTTPS kept
alive, POSTs with a body, slow requests (so that a reload or an upgrade finds
them in flight), and an L4 TCP echo. A request on a kept-alive connection the
server closed just as it was reused is sent once more on a new one, as
browsers and SDKs do; anything else that is not the right answer is a loss.

It passes with no loss, every reload and upgrade taken, and memory and file
descriptors that do not grow with time (after a warm-up, the last samples
against the first)."""
import collections
import http.client
import http.server
import os
import pathlib
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
SECONDS = int(os.environ.get("SOAK_SECONDS", "600"))
RELOAD = int(os.environ.get("SOAK_RELOAD", "60"))
UPGRADE = int(os.environ.get("SOAK_UPGRADE", "60"))
ENGINE = os.environ.get("SOAK_ENGINE", "io_uring")
LST, TLS, TCP, MET, B1, B2, ECHO = 18080, 18443, 18081, 18094, 18091, 18092, 18093
RETRYABLE = (http.client.RemoteDisconnected, ConnectionResetError, BrokenPipeError, ConnectionAbortedError)


def inside():
    if os.environ.get("OKENA_SOAK_NS") == "1":
        return
    env = dict(os.environ, OKENA_SOAK_NS="1")
    os.execvpe("unshare", ["unshare", "-rn", "sh", "-c", 'ip link set lo up && exec "$0" "$@"', sys.executable, "-I", __file__], env)


def say(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def answer(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        got = self.rfile.read(n) if n else b""
        if "slow" in self.path:
            time.sleep(0.2)
        body = b"ok:" + self.path.encode() + b":" + str(len(got)).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    do_GET = do_POST = answer

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 512

    def handle_error(self, *a):
        pass


def echo_server():
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", ECHO))
    ls.listen(256)

    def serve(c):
        try:
            while True:
                d = c.recv(4096)
                if not d:
                    break
                c.sendall(d)
        except OSError:
            pass
        c.close()
    while True:
        c, _ = ls.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.n = collections.Counter()      # by kind
        self.retried = collections.Counter()
        self.lost = []

    def ok(self, kind):
        with self.lock:
            self.n[kind] += 1

    def retry(self, kind):
        with self.lock:
            self.retried[kind] += 1

    def loss(self, kind, what):
        with self.lock:
            self.n[kind] += 1
            self.lost.append((time.time(), kind, what))


def http_client(stats, stop, kind, port, keep, ctx=None, slow=False, post=False):
    conn = None

    def fresh():
        if ctx:
            return http.client.HTTPSConnection("127.0.0.1", port, timeout=10, context=ctx)
        return http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    i = 0
    while not stop.is_set():
        i += 1
        path = f"/{'slow' if slow else 'x'}/{kind.replace(' ', '-')}/{i}"
        body = (b"p" * (1000 + i % 5000)) if post else None
        want = b"ok:" + path.encode() + b":" + str(len(body) if body else 0).encode()
        reused = conn is not None
        for attempt in (0, 1):
            try:
                if conn is None:
                    conn = fresh()
                conn.request("POST" if post else "GET", path, body=body)
                r = conn.getresponse()
                got = r.read()
                if not keep or r.getheader("connection", "").lower() == "close":
                    conn.close()
                    conn = None
                if r.status == 200 and got == want:
                    stats.ok(kind)
                else:
                    stats.loss(kind, (r.status, got[:60]))
                break
            except RETRYABLE as e:
                if conn:
                    conn.close()
                conn = None
                if attempt == 0 and reused:
                    stats.retry(kind)          # (closed as it was reused: once more, on a new one)
                    reused = False
                    continue
                stats.loss(kind, repr(e))
                break
            except (OSError, http.client.HTTPException) as e:
                if conn:
                    conn.close()
                conn = None
                stats.loss(kind, repr(e))
                break
        time.sleep(0.005)


def tcp_client(stats, stop):
    i = 0
    while not stop.is_set():
        i += 1
        try:
            s = socket.create_connection(("127.0.0.1", TCP), timeout=10)
            for k in range(5):
                msg = f"ping {i}.{k}\n".encode()
                s.sendall(msg)
                got = b""
                while len(got) < len(msg):
                    d = s.recv(4096)
                    if not d:
                        break
                    got += d
                if got != msg:
                    stats.loss("tcp", got[:40])
                    break
            else:
                stats.ok("tcp")
            s.close()
        except OSError as e:
            stats.loss("tcp", repr(e))
        time.sleep(0.01)


def family(sup):
    """The supervisor and its children: their pids."""
    out = [sup]
    for d in pathlib.Path("/proc").iterdir():
        if d.name.isdigit():
            try:
                if f"PPid:\t{sup}\n" in (d / "status").read_text():
                    out.append(int(d.name))
            except OSError:
                pass
    return out


def rss_kb(pids):
    t = 0
    for p in pids:
        try:
            for line in pathlib.Path(f"/proc/{p}/status").read_text().splitlines():
                if line.startswith("VmRSS:"):
                    t += int(line.split()[1])
        except OSError:
            pass
    return t


def fds(pid):
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return -1


def main():
    inside()
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-soak-", dir="/tmp"))
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", tmp / "k.pem", "-out", tmp / "c.pem", "-subj", "/CN=localhost", "-days", "30"], check=True, capture_output=True)
    for port in (B1, B2):
        threading.Thread(target=S(("127.0.0.1", port), H).serve_forever, daemon=True).start()
    threading.Thread(target=echo_server, daemon=True).start()
    conf = tmp / "okena.conf"

    def config(gen):
        # each generation changes something real: weights, a route, the worker count
        w = 1 + gen % 3
        extra = f"    route /gen{gen}/* {{ to pool web }}\n" if gen % 2 else ""
        return f"""okena {{ workers {2 + gen % 2}; io_engine {ENGINE}; upgrade {tmp}/up.sock; metrics 127.0.0.1:{MET}; drain delay=0s timeout=5s }}
pool web {{ health tcp every=1s; server 127.0.0.1:{B1} weight={w}; server 127.0.0.1:{B2} }}
pool echo {{ server 127.0.0.1:{ECHO} }}
http 127.0.0.1:{LST} {{
    access_log {tmp}/access.log
{extra}    route /* {{ to pool web }}
}}
http 127.0.0.1:{TLS} {{
    tls {{ cert {tmp}/c.pem; key {tmp}/k.pem }}
    route /* {{ to pool web }}
}}
tcp 127.0.0.1:{TCP} {{ to pool echo }}
"""
    gen = 0
    conf.write_text(config(gen))
    logs = [tmp / "log0"]
    cur = subprocess.Popen([str(BIN), "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=open(logs[0], "w"))
    procs = [cur]
    stats, stop = Stats(), threading.Event()
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    reloads = upgrades = 0
    failed = []
    samples = []
    events = []
    try:
        t0 = time.time()
        while time.time() - t0 < 10:
            try:
                socket.create_connection(("127.0.0.1", LST), 1).close()
                break
            except OSError:
                time.sleep(0.1)
        threads = [threading.Thread(target=http_client, args=a, daemon=True) for a in (
            (stats, stop, "h1 kept", LST, True), (stats, stop, "h1 kept", LST, True),
            (stats, stop, "h1 new", LST, False), (stats, stop, "h1 new", LST, False),
            (stats, stop, "https kept", TLS, True, ctx), (stats, stop, "https new", TLS, False, ctx),
            (stats, stop, "slow", LST, True, None, True), (stats, stop, "post", LST, True, None, False, True))]
        threads += [threading.Thread(target=tcp_client, args=(stats, stop), daemon=True) for _ in range(2)]
        for t in threads:
            t.start()
        say(f"soak: {SECONDS} s on {ENGINE}, a reload every {RELOAD} s, an upgrade every {UPGRADE} s")
        start = time.time()
        next_reload, next_upgrade, next_sample = start + RELOAD, start + UPGRADE, start + 5
        while time.time() - start < SECONDS:
            now = time.time()
            if now >= next_sample:
                fam = family(cur.pid)
                samples.append((now - start, rss_kb(fam), fds(cur.pid), len(fam)))
                next_sample = now + 5
            if now >= next_upgrade:
                next_upgrade = now + UPGRADE
                gen += 1
                conf.write_text(config(gen))
                log = tmp / f"log{len(logs)}"
                logs.append(log)
                events.append((time.time(), "upgrade"))
                new = subprocess.Popen([str(BIN), "upgrade", "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=open(log, "w"))
                procs.append(new)
                old = cur
                end = time.time() + 15
                while time.time() < end and old.poll() is None:
                    time.sleep(0.1)
                if old.poll() == 0 and new.poll() is None and "taken over" in log.read_text():
                    upgrades += 1
                    cur = new
                    say(f"upgrade {upgrades}: pid {cur.pid} took over")
                else:
                    failed.append(("upgrade", old.poll(), new.poll(), log.read_text()[-300:]))
                    say("upgrade FAILED", failed[-1])
                    break
            elif now >= next_reload:
                next_reload = now + RELOAD
                gen += 1
                conf.write_text(config(gen))
                log = logs[-1]
                before = log.read_text().count("configuration reloaded")
                events.append((time.time(), "reload"))
                cur.send_signal(signal.SIGHUP)
                end = time.time() + 10
                while time.time() < end and log.read_text().count("configuration reloaded") == before:
                    time.sleep(0.1)
                if log.read_text().count("configuration reloaded") > before:
                    reloads += 1
                else:
                    failed.append(("reload", log.read_text()[-300:]))
                    say("reload FAILED", failed[-1])
                    break
            time.sleep(0.2)
        stop.set()
        for t in threads:
            t.join(15)
    finally:
        stop.set()
        for p in procs:
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(15)
            except subprocess.TimeoutExpired:
                p.kill()

    total = sum(stats.n.values())
    say(f"requests: {total} ({dict(stats.n)}); sent again after a close on reuse: {dict(stats.retried)}")
    say(f"reloads: {reloads}, upgrades: {upgrades}, lost: {len(stats.lost)}")
    ok = True
    if stats.lost:
        ok = False
        by = collections.Counter((k, str(w)[:80]) for _, k, w in stats.lost)
        say("LOST:", by.most_common(8))
        for t, k, w in stats.lost[:12]:
            near = min(events, key=lambda e: abs(e[0] - t), default=(t, "-"))
            say(f"  {k}: {str(w)[:50]} ({t - near[0]:+.2f} s from a {near[1]})")
    if failed:
        ok = False
    # growth: the last quarter of the samples against the second (past the warm-up)
    if len(samples) >= 8:
        q = len(samples) // 4
        early = samples[q:2 * q]
        late = samples[-q:]
        avg = lambda xs, i: sum(x[i] for x in xs) / len(xs)
        r0, r1 = avg(early, 1), avg(late, 1)
        f0, f1 = avg(early, 2), avg(late, 2)
        say(f"memory (all its processes): {r0 / 1024:.1f} MB -> {r1 / 1024:.1f} MB; supervisor fds: {f0:.0f} -> {f1:.0f}")
        if r1 > r0 * 1.25 + 8 * 1024:
            ok = False
            say("MEMORY GREW")
        if f1 > f0 + 8:
            ok = False
            say("FDS GREW")
    for log in logs:
        t = log.read_text()
        if "seccomp" in t or "killed by signal" in t:
            ok = False
            say("a process died:", log, t[-300:])
    wanted_reloads = (SECONDS // RELOAD) // 2
    if reloads + upgrades < max(1, wanted_reloads):
        ok = False
        say(f"too few reloads and upgrades: {reloads + upgrades}")
    shutil.rmtree(tmp, ignore_errors=True)
    say("soak:", "passed" if ok else "FAILED")
    sys.exit(0 if ok else 1)


main()
