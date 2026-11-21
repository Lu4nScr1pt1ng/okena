#!/usr/bin/env python3
"""Timeouts of a fraction of a second, on one engine (argument): a route's
`timeout try=300ms` answers 504 in about 300 ms, or retries on the next server
in time; `total=` stops retries; a listener's `response 400ms` and
`header 500ms`; a tcp listener's `header` bounds a PROXY header that never
completes. Whole seconds still time on the tick, never early."""
import os
import pathlib
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "auto"
BASE = 13400 + os.getpid() % 40 * 12 + (6 if ENGINE == "epoll" else 0)
SLOW, FAST, L, LR, LT, SLOW2, SLOWER = (BASE + i for i in range(7))

failures = 0


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail else ""))
    failures += not ok


def backend(port, delay):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(128)

    def handle(c):
        try:
            d = b""
            while b"\r\n\r\n" not in d:
                x = c.recv(4096)
                if not x:
                    return
                d += x
            time.sleep(delay)
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            c.recv(10)
        except OSError:
            pass
        finally:
            c.close()

    def loop():
        while True:
            c, _ = s.accept()
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()


def timed_get(port, path):
    t0 = time.time()
    c = socket.create_connection(("127.0.0.1", port), timeout=5)
    c.sendall(f"GET {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n".encode())
    r = b""
    try:
        while (d := c.recv(4096)):
            r += d
    except OSError:
        pass
    c.close()
    st = int(r.split(b" ")[1]) if r.startswith(b"HTTP/") else 0
    return st, time.time() - t0


def closed_after(port, data):
    t0 = time.time()
    c = socket.create_connection(("127.0.0.1", port), timeout=5)
    c.sendall(data)
    r = b""
    try:
        while (d := c.recv(4096)):
            r += d
    except OSError:
        pass
    c.close()
    return r, time.time() - t0


backend(SLOW, 1.2)
backend(SLOW2, 1.2)
backend(SLOWER, 3)
backend(FAST, 0)
tmp = pathlib.Path(tempfile.mkdtemp())
conf = tmp / "okena.conf"
conf.write_text(f"""
okena {{ overload off; workers 2; io_engine {ENGINE}; drain delay=0s timeout=1s }}
pool slow {{ server 127.0.0.1:{SLOW} }}
pool slowfast {{ balance first; server 127.0.0.1:{SLOW}; server 127.0.0.1:{FAST} }}
pool slow2 {{ balance round-robin; server 127.0.0.1:{SLOW}; server 127.0.0.1:{SLOW2} }}
pool slower {{ server 127.0.0.1:{SLOWER} }}
http 127.0.0.1:{L} {{
    timeout {{ header 500ms }}
    route /try {{ to pool slow; retry 0; timeout try=300ms }}
    route /retry {{ to pool slowfast; retry 1 on=timeout; timeout try=300ms }}
    route /total {{ to pool slow2; retry 5 on=timeout; timeout try=250ms total=400ms }}
    route /whole {{ to pool slower; retry 0; timeout try=1s }}
}}
http 127.0.0.1:{LR} {{
    timeout {{ response 400ms }}
    route /* {{ to pool slow; retry 0 }}
}}
tcp 127.0.0.1:{LT} {{
    to 127.0.0.1:{FAST}
    proxy_protocol accept
    timeout {{ header 600ms }}
}}
""")
log = open(tmp / "log", "w+")
p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)
try:
    for _ in range(100):
        log.seek(0)
        if "started with" in log.read():
            break
        time.sleep(0.05)
    else:
        log.seek(0)
        sys.exit("okena did not start:\n" + log.read())

    pool = ThreadPoolExecutor(8)
    f_try = pool.submit(timed_get, L, "/try")
    f_retry = pool.submit(timed_get, L, "/retry")
    f_total = pool.submit(timed_get, L, "/total")
    f_whole = pool.submit(timed_get, L, "/whole")
    f_resp = pool.submit(timed_get, LR, "/x")
    f_head = pool.submit(closed_after, L, b"GET / HTTP/1.1\r\nHost: t\r\n")
    f_pp = pool.submit(closed_after, LT, b"PROXY TCP4 1.2.3.4 ")

    st, t = f_try.result()
    check("try=300ms: 504 in about 300 ms", st == 504 and 0.29 <= t < 0.6, f"{st} {t:.3f}")
    st, t = f_retry.result()
    check("try=300ms, retry on=timeout: the next server answers in time", st == 200 and 0.29 <= t < 0.7,
          f"{st} {t:.3f}")
    st, t = f_total.result()
    check("total=400ms: no retry starts past it (two tries, not six)", st == 504 and 0.45 <= t < 0.9, f"{st} {t:.3f}")
    st, t = f_whole.result()
    check("try=1s: a whole second, on the tick, never early", st == 504 and 1.0 <= t < 2.2, f"{st} {t:.3f}")
    st, t = f_resp.result()
    check("listener response 400ms: 504 in about 400 ms", st == 504 and 0.39 <= t < 0.7, f"{st} {t:.3f}")
    r, t = f_head.result()
    check("listener header 500ms: 408 for a head that does not finish", r.startswith(b"HTTP/1.1 408") and 0.49 <= t < 0.8,
          f"{r[:20]} {t:.3f}")
    r, t = f_pp.result()
    check("tcp header 600ms: a PROXY header that never completes is closed", r == b"" and 0.59 <= t < 0.9, f"{t:.3f}")
    log.seek(0)
    check("no crash", "killed by signal" not in log.read())
finally:
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
    if failures or sys.exc_info()[0]:
        log.seek(0)
        print(log.read())
print(f"subsecond timeouts ({ENGINE}): {'all passed' if not failures else f'{failures} failed'}")
sys.exit(1 if failures else 0)
