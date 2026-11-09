#!/usr/bin/env python3
"""systemd, played by this test, on one engine (argument): socket activation
(the sockets it opened, on fds from 3, taken by the listeners of their address
and kind, a reload with more workers still on them, one no listener wants
closed and said, LISTEN_PID of another ignored) and the notify protocol
(READY=1 with MAINPID, RELOADING=1 with MONOTONIC_USEC then READY=1,
WATCHDOG=1, STOPPING=1)."""
import http.client
import http.server
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

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 42000 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
HTTP, UDP, SPARE, BACK, ECHO = BASE, BASE + 1, BASE + 2, BASE + 3, BASE + 4
fails = 0


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
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def get():
    c = http.client.HTTPConnection("127.0.0.1", HTTP, timeout=3)
    c.request("GET", "/")
    r = c.getresponse()
    r.read()
    c.close()
    return r.status


def udp_ask(msg):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(2)
    u.sendto(msg, ("127.0.0.1", UDP))
    d = u.recv(100)
    u.close()
    return d


def sockets():
    """What systemd would open: no SO_REUSEPORT, so only a socket handed over
    can serve these ports while they are held here."""
    t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    t.bind(("127.0.0.1", HTTP))
    t.listen(128)
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("127.0.0.1", UDP))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", SPARE))
    s.listen(16)
    return [t, u, s]


def start(conf, log, held, env, listen_pid="$$"):
    fds = [x.fileno() for x in held]

    def onto_3():
        # (as systemd does: from fd 3 on, in order)
        tmp = [os.dup(f) for f in fds]
        for i, f in enumerate(tmp):
            os.dup2(f, 3 + i)
            os.close(f)
    cmd = ["sh", "-c", f'LISTEN_PID={listen_pid} LISTEN_FDS={len(fds)} exec "$0" "$@"', str(BIN), "-c", str(conf)]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=open(log, "w"), env=env,
                            preexec_fn=onto_3, pass_fds=tuple(range(3, 3 + len(fds))))


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-systemd-", dir="/tmp"))
    threading.Thread(target=http.server.ThreadingHTTPServer(("127.0.0.1", BACK), H).serve_forever, daemon=True).start()

    def echo():
        e = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        e.bind(("127.0.0.1", ECHO))
        while True:
            d, a = e.recvfrom(2048)
            e.sendto(b"echo:" + d, a)
    threading.Thread(target=echo, daemon=True).start()
    notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    npath = str(tmp / "notify")
    notify.bind(npath)
    notify.settimeout(0.1)
    said = []

    def drain():
        while True:
            try:
                said.append(notify.recv(4096).decode())
            except OSError:
                return
    conf = tmp / "okena.conf"
    good = f"""okena {{ drain delay=0s timeout=1s; workers 2; io_engine {ENGINE} }}
pool b {{ server 127.0.0.1:{BACK} }}
pool e {{ server 127.0.0.1:{ECHO} }}
http 127.0.0.1:{HTTP} {{ route /* {{ to pool b }} }}
udp 127.0.0.1:{UDP} {{ to pool e }}
"""
    conf.write_text(good)
    log = tmp / "log"
    held = sockets()
    env = dict(os.environ, NOTIFY_SOCKET=npath, WATCHDOG_USEC="2000000")
    p = start(conf, log, held, env)
    try:
        check("okena serves on the sockets systemd gave (it holds the ports: no bind of okena's could)",
              until(lambda: get() == 200) and udp_ask(b"hi") == b"echo:hi", log.read_text()[-400:])
        t = log.read_text()
        check("  and says so", "socket activation: 3 sockets from systemd" in t, t[-400:])
        check("  a socket no listener wants: closed, said", "socket activation: fd 5 is no listener's" in t, t[-400:])
        until(lambda: (drain(), any("READY=1" in m for m in said))[1], 4)
        ready = [m for m in said if "READY=1" in m]
        check("READY=1 once the workers serve, with MAINPID", ready and f"MAINPID={p.pid}" in ready[0], said)
        dogs = lambda: sum(m.strip() == "WATCHDOG=1" for m in said)
        n0 = dogs()
        check("WATCHDOG=1 while WATCHDOG_USEC asks", until(lambda: (drain(), dogs() >= n0 + 2)[1], 4), said[-3:])

        # a reload with a worker more: its socket is a dup of systemd's again
        said.clear()
        conf.write_text(good.replace("workers 2", "workers 3"))
        p.send_signal(signal.SIGHUP)
        until(lambda: (drain(), any("READY=1" in m for m in said))[1], 6)
        msgs = [m for m in said if "WATCHDOG" not in m]
        check("a reload: RELOADING=1 with MONOTONIC_USEC, then READY=1",
              len(msgs) >= 2 and "RELOADING=1" in msgs[0] and "MONOTONIC_USEC=" in msgs[0] and "READY=1" in msgs[-1], msgs)
        check("  with more workers, still on systemd's sockets", "configuration reloaded" in log.read_text()
              and all(get() == 200 for _ in range(20)) and udp_ask(b"again") == b"echo:again", log.read_text()[-300:])
        said.clear()
        p.send_signal(signal.SIGTERM)
        p.wait(10)
        drain()
        check("STOPPING=1 when it stops", any("STOPPING=1" in m for m in said), said)
    finally:
        if p.poll() is None:
            p.kill()
            p.wait(10)
    t = log.read_text()
    check("no process died", "seccomp" not in t and "killed by signal" not in t, t[-300:])

    # LISTEN_PID of another process: they are not for this one
    log2 = tmp / "log2"
    q = start(conf, log2, held, dict(os.environ), listen_pid="1")
    try:
        q.wait(10)
    except subprocess.TimeoutExpired:
        q.kill()
        q.wait(5)
    t = log2.read_text()
    check("LISTEN_PID of another: not taken (and the port, held, cannot be okena's)", q.returncode != 0
          and "socket activation" not in t and ("in use" in t or "cannot listen" in t), t[-300:])
    for x in held:
        x.close()
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"systemd {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


main()
