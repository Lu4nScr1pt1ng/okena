#!/usr/bin/env python3
"""Integration tests for the L4 TCP proxy.

Starts echo backends and okena on loopback ports, then checks data
integrity, half-close, balancing, failover, connect timeouts, idle
timeouts, worker crashes and graceful drain.
"""
import hashlib
import os
import pathlib
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
# below the ephemeral range (32768+), so outgoing connections never hold
# our ports; varied by pid so parallel runs do not collide
# ports 20000-20999: this suite's own range (none overlap)
BASE = 20000 + os.getpid() % 99 * 10


def echo_backend(port: int, tag: bytes) -> None:
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(1024)

    def handle(c):
        try:
            while True:
                d = c.recv(65536)
                if not d:
                    c.shutdown(socket.SHUT_WR)
                    break
                c.sendall(tag + b"\n" if d == b"who\n" else d)
        except OSError:
            pass
        finally:
            c.close()

    def loop():
        while True:
            c, _ = s.accept()
            threading.Thread(target=handle, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()


def who(port: int, host: str = "127.0.0.1") -> bytes:
    c = socket.create_connection((host, port), timeout=5)
    c.sendall(b"who\n")
    r = c.recv(100).strip()
    c.close()
    return r


class Okena:
    def __init__(self, conf: str):
        self.dir = tempfile.TemporaryDirectory()
        path = pathlib.Path(self.dir.name) / "okena.conf"
        path.write_text(conf)
        self.log = open(pathlib.Path(self.dir.name) / "log", "w+")
        self.p = subprocess.Popen([str(BIN), "-c", str(path)], stderr=self.log)
        for _ in range(100):
            self.log.seek(0)
            if "started with" in self.log.read():
                return
            time.sleep(0.02)
        raise RuntimeError("okena did not start: " + self.text())

    def text(self) -> str:
        self.log.seek(0)
        return self.log.read()

    def workers(self):
        out = subprocess.check_output(["pgrep", "-P", str(self.p.pid)]).split()
        return [int(x) for x in out]

    def stop(self):
        if self.p.poll() is None:
            self.p.send_signal(signal.SIGTERM)
            try:
                self.p.wait(10)
            except subprocess.TimeoutExpired:
                self.p.kill()


failures = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global failures
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail else ""))
    failures += not ok


def main() -> int:
    engine = sys.argv[1] if len(sys.argv) > 1 else "auto"
    print(f"engine: {engine}")
    b0, b1, dead, lst, lst2 = BASE, BASE + 1, BASE + 2, BASE + 3, BASE + 4
    echo_backend(b0, b"b0")
    echo_backend(b1, b"b1")
    ok = Okena(f"""
okena {{
    workers 2
    io_engine {engine}
    drain delay=0s timeout=3s
}}
pool web {{
    server 127.0.0.1:{b0}
    server 127.0.0.1:{b1}
    server 127.0.0.1:{dead}
    server 192.0.2.1:9
    connect timeout=200ms
}}
tcp 127.0.0.1:{lst} {{ to pool web }}
tcp :{lst2} {{
    to 127.0.0.1:{b0}
    timeout {{ idle 1s }}
}}
""")
    try:
        # integrity in both directions with half-close
        data = os.urandom(8_000_000)
        c = socket.create_connection(("127.0.0.1", lst2), timeout=10)
        got = bytearray()
        t = threading.Thread(target=lambda: [got.extend(d) for d in iter(lambda: c.recv(1 << 20), b"")])
        t.start()
        c.sendall(data)
        c.shutdown(socket.SHUT_WR)
        t.join()
        c.close()
        check("8 MB echo through the proxy, half-close", hashlib.sha256(got).digest() == hashlib.sha256(data).digest())

        # failover past a refusing and a black-holed server, balanced
        seen = {}
        errors = 0
        start = time.time()
        for _ in range(200):
            try:
                r = who(lst)
                seen[r] = seen.get(r, 0) + 1
            except OSError:
                errors += 1
        check("no client error with 2 of 4 servers dead", errors == 0, f"{errors} errors")
        check("traffic spread over the live servers", set(seen) == {b"b0", b"b1"} and min(seen.values()) > 50, str(seen))
        check("dead servers ejected (log)", "ejected" in ok.text())
        check("connect timeouts do not stall the pool", time.time() - start < 10, f"{time.time() - start:.1f}s")

        # a second instance on the same port must refuse, not share it
        p = subprocess.run([str(BIN), "tcp", f"127.0.0.1:{lst}", "to", f"127.0.0.1:{b0}"],
                           capture_output=True, text=True, timeout=10)
        check("second instance on a used port refuses to start",
              p.returncode == 1 and "another program is listening" in p.stderr, p.stderr.strip()[-80:])

        # dual stack listener
        check("IPv6 client on :port", who(lst2, "::1") == b"b0")

        # idle timeout: never early
        c = socket.create_connection(("127.0.0.1", lst2), timeout=10)
        t0 = time.time()
        c.recv(10)
        idle = time.time() - t0
        check("idle connection closed after its timeout, not before", 1.0 <= idle < 3.0, f"{idle:.2f}s")

        # every worker killed under load: no failed connection
        errors = 0
        n = 0
        killed = ok.workers()
        for pid in killed:
            os.kill(pid, signal.SIGKILL)
        # kill(2) returns before the process is gone: a connection a dying
        # worker accepted dies with it (a crash costs that worker's
        # connections). Measure from the moment the old ones are gone.
        while any(os.path.exists(f"/proc/{pid}/stat") and open(f"/proc/{pid}/stat").read().split()[2] != "Z"
                  for pid in killed):
            time.sleep(0.001)
        t0 = time.time()
        while time.time() - t0 < 1.0:
            try:
                n += who(lst2) == b"b0"
            except OSError:
                errors += 1
        check("all workers SIGKILLed: queued connections served by replacements", errors == 0 and n > 100, f"{n} ok, {errors} failed")

        # a stuck worker (SIGSTOP) is found by the watchdog and replaced
        victim = ok.workers()[0]
        os.kill(victim, signal.SIGSTOP)
        t0 = time.time()
        while time.time() - t0 < 6 and victim in ok.workers():
            time.sleep(0.1)
        replaced = victim not in ok.workers() and len(ok.workers()) == 2
        check("stuck worker killed by the watchdog and replaced (and nothing else was)",
              replaced and ok.text().count("has not made progress") == 1,
              f"{time.time() - t0:.1f}s")
        time.sleep(0.5)
        errors = 0
        for _ in range(50):
            try:
                who(lst2)
            except OSError:
                errors += 1
        check("service whole again after the replacement", errors == 0, f"{errors} errors")

        # a replacement that cannot start (here: no descriptors left) is
        # retried with a growing delay instead of stopping the service
        if engine == "io_uring":
            soft_hard = subprocess.check_output(["prlimit", "--pid", str(ok.p.pid), "--nofile", "-o", "SOFT,HARD",
                                                 "--noheadings"]).split()
            subprocess.check_call(["prlimit", "--pid", str(ok.p.pid), "--nofile=40:" + soft_hard[1].decode()])
            victim = ok.workers()[0]
            os.kill(victim, signal.SIGKILL)
            time.sleep(1.2)
            retrying = "could not start (see above), retrying" in ok.text()
            check("replacement that cannot start is retried, not fatal", retrying and ok.p.poll() is None)
            # the kernel still hashes some connections to the missing worker's
            # socket: they wait in its queue; the others are served at once
            served, queued = 0, []
            for _ in range(12):
                c = socket.create_connection(("127.0.0.1", lst2), timeout=5)
                c.settimeout(0.5)
                c.sendall(b"who\n")
                try:
                    served += c.recv(10).strip() == b"b0"
                    c.close()
                except TimeoutError:
                    queued.append(c)
            check("the other worker keeps serving meanwhile", served > 0, f"{served} served, {len(queued)} queued")
            subprocess.check_call(["prlimit", "--pid", str(ok.p.pid), "--nofile=" + b":".join(soft_hard).decode()])
            t0 = time.time()
            while time.time() - t0 < 8 and len(ok.workers()) < 2:
                time.sleep(0.1)
            check("it starts once the cause is gone", len(ok.workers()) == 2, f"{time.time() - t0:.1f}s")
            late = 0
            for c in queued:
                c.settimeout(5)
                try:
                    late += c.recv(10).strip() == b"b0"
                except OSError:
                    pass
                c.close()
            check("connections queued meanwhile are served then, not lost", late == len(queued), f"{late}/{len(queued)}")

        # graceful drain keeps in-flight connections
        c = socket.create_connection(("127.0.0.1", lst2), timeout=5)
        ok.p.send_signal(signal.SIGTERM)
        time.sleep(0.2)
        c.sendall(b"draining\n")
        check("in-flight connection keeps working during drain", c.recv(100) == b"draining\n")
        c.close()
        try:
            ok.p.wait(5)
            check("exits once the last connection closes", ok.p.returncode == 0, f"status {ok.p.returncode}")
        except subprocess.TimeoutExpired:
            check("exits once the last connection closes", False, "still running")
    except BaseException:
        print(ok.text())
        raise
    finally:
        ok.stop()
        if failures:
            print(ok.text())
    print(f"l4 ({engine}): {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
