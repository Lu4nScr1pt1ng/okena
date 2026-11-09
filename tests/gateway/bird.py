#!/usr/bin/env python3
"""`bird`, on one engine (argument): the anycast address announced while okena can
take traffic and withdrawn when it cannot, through BIRD's control socket (played
here): enabled at the start, disabled by `okena drain` and enabled by `okena
resume`, disabled when pool= has no server up and enabled when one is back,
said again to a BIRD that restarted, an error said once, and withdrawn on a stop
before okena is gone."""
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
BASE = 56000 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
BACK, LST = BASE, BASE + 1
fails = 0
said = []                                       # (time, command)


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


class Bird:
    """BIRD's control socket, as birdc sees it: a greeting, a command a line."""

    def __init__(self, path):
        self.path = path
        self.start()

    def start(self):
        if os.path.exists(self.path):
            os.unlink(self.path)
        self.s = socket.socket(socket.AF_UNIX)
        self.s.bind(self.path)
        self.s.listen(8)
        self.on = True
        threading.Thread(target=self.serve, args=(self.s,), daemon=True).start()

    def stop(self):
        self.on = False
        self.s.close()
        os.unlink(self.path)

    def serve(self, s):
        while self.on:
            try:
                c, _ = s.accept()
            except OSError:
                return
            try:
                c.sendall(b"0001 BIRD 2.15 ready.\n")
                line = b""
                while not line.endswith(b"\n"):
                    d = c.recv(100)
                    if not d:
                        break
                    line += d
                cmd = line.decode().strip()
                said.append((time.time(), cmd))
                verb, _, proto = cmd.partition(" ")
                if proto != "anycast":
                    c.sendall(b"8003 No protocols match\n")
                else:
                    c.sendall(f"0011-{proto}: {verb}d\n0000 \n".encode())
            except OSError:
                pass
            c.close()


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def last():
    return said[-1][1] if said else None


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-bird-", dir="/tmp"))
    bird = Bird(str(tmp / "bird.ctl"))
    back = http.server.ThreadingHTTPServer(("127.0.0.1", BACK), H)
    threading.Thread(target=back.serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE}; drain delay=3s timeout=1s; admin unix:{tmp}/a.sock
    bird {tmp}/bird.ctl protocol=anycast pool=web }}
pool web {{ server 127.0.0.1:{BACK}; health tcp every=200ms fall=1 rise=1 }}
http 127.0.0.1:{LST} {{ route /* {{ to pool web }} }}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=open(log, "w"))
    cli = lambda *a: subprocess.run([str(BIN), *a, "-c", str(conf)], capture_output=True, text=True, timeout=10)
    try:
        check("at the start, ready: enable anycast", until(lambda: last() == "enable anycast"), (said[-3:], log.read_text()[-300:]))
        check("  and said in the log", until(lambda: "bird: anycast enabled" in log.read_text(), 2))
        cli("drain")
        check("okena drain: disable anycast", until(lambda: last() == "disable anycast", 4), said[-3:])
        cli("resume")
        check("okena resume: enable anycast", until(lambda: last() == "enable anycast", 4), said[-3:])
        back.shutdown()
        back.server_close()
        check("the pool with no server up: disable", until(lambda: last() == "disable anycast", 6), said[-3:])
        back = http.server.ThreadingHTTPServer(("127.0.0.1", BACK), H)
        threading.Thread(target=back.serve_forever, daemon=True).start()
        check("  one back: enable", until(lambda: last() == "enable anycast", 6), said[-3:])
        bird.stop()
        check("a BIRD that went: said in the log (okena tries again every second)",
              until(lambda: "did not take" in log.read_text(), 8), log.read_text()[-300:])
        time.sleep(1.5)
        n = len(said)
        bird.start()
        check("  back: told again at once", until(lambda: len(said) > n and last() == "enable anycast", 3), said[-3:])
        check("  and its absence said once, not every second", log.read_text().count("did not take") == 1, log.read_text().count("did not take"))
        n = len(said)
        t0 = time.time()
        p.send_signal(signal.SIGTERM)
        check("a stop: disable, during the drain delay, before okena is gone",
              until(lambda: any(c == "disable anycast" for _, c in said[n:]), 3) and p.poll() is None, (said[n:], p.poll()))
        p.wait(10)
    finally:
        if p.poll() is None:
            p.kill()
            p.wait(5)
    # a protocol BIRD does not know: said, not taken
    conf2 = tmp / "two.conf"
    conf2.write_text(conf.read_text().replace("protocol=anycast", "protocol=nosuch"))
    log2 = tmp / "log2"
    q = subprocess.Popen([str(BIN), "-c", str(conf2)], stdout=subprocess.DEVNULL, stderr=open(log2, "w"))
    try:
        check("a protocol BIRD does not know: an error, said", until(lambda: "did not take `nosuch`" in log2.read_text(), 6), log2.read_text()[-300:])
    finally:
        q.terminate()
        q.wait(10)
    t = log.read_text() + log2.read_text()
    check("no process died", "seccomp" not in t and "killed by signal" not in t, t[-400:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"bird {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


main()
