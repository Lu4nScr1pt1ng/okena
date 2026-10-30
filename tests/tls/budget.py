#!/usr/bin/env python3
"""The handshake budget: a burst of ClientHellos is run a budget at a time
per loop iteration, the rest wait in a bounded queue, and an open
connection keeps being served in between.

Many ClientHellos are sent at once (memory-BIO handshakes over non-blocking
sockets, so the burst arrives together) at a worker whose budget is small:
some must be deferred (okena_tls_handshakes_deferred_total), all must
still complete, and a keep-alive HTTPS connection opened before the burst
answers during it. With `wait=` shorter than the queue takes to drain, the
oldest waiting hellos are closed instead (okena_tls_handshakes_shed_total)
and the connection is closed, never left hanging."""
import atexit
import os
import pathlib
import select
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 35000 + os.getpid() % 40 * 10 + (5 if ENGINE == "epoll" else 0)
LST, MET, LST2, MET2 = BASE, BASE + 1, BASE + 2, BASE + 3
BURST = 300
tmp = pathlib.Path(tempfile.mkdtemp())
atexit.register(shutil.rmtree, tmp, True)
failures = 0


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail and not ok else ""))
    failures += not ok


def sh(*a):
    subprocess.run(a, check=True, capture_output=True, cwd=tmp)


def metrics(port):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(b"GET /metrics HTTP/1.1\r\nHost: m\r\nConnection: close\r\n\r\n")
        data = b""
        while chunk := s.recv(65536):
            data += chunk
    out = {}
    for line in data.decode().split("\r\n\r\n", 1)[-1].splitlines():
        if line and not line.startswith("#"):
            k, _, v = line.rpartition(" ")
            out[k] = int(v)
    return out


def ctx():
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def burst(port, n, timeout=10):
    """n handshakes started at once; (completed, closed by okena)."""
    c = ctx()
    conns = []
    for _ in range(n):
        s = socket.socket()
        s.setblocking(False)
        s.connect_ex(("127.0.0.1", port))
        conns.append([s, ssl.MemoryBIO(), ssl.MemoryBIO(), None])
    for cn in conns:
        cn[3] = c.wrap_bio(cn[1], cn[2], server_hostname="okena.test")
        try:
            cn[3].do_handshake()
        except ssl.SSLWantReadError:
            pass
    select.select([], [cn[0] for cn in conns], [], 5)
    for cn in conns:                        # every ClientHello, back to back
        cn[0].setblocking(True)
        cn[0].sendall(cn[2].read())
        cn[0].setblocking(False)
    done = closed = 0
    live = {cn[0]: cn for cn in conns}
    end = time.time() + timeout
    while live and time.time() < end:
        r, _, _ = select.select(list(live), [], [], 0.5)
        for s in r:
            cn = live[s]
            try:
                data = s.recv(65536)
            except OSError:
                data = b""
            if not data:
                closed += 1
                del live[s]
                s.close()
                continue
            cn[1].write(data)
            try:
                cn[3].do_handshake()
                done += 1
            except ssl.SSLWantReadError:
                pass
            except ssl.SSLError:
                closed += 1
            else:
                del live[s]
                s.close()
                continue
            out = cn[2].read()
            if out:
                s.setblocking(True)
                s.sendall(out)
                s.setblocking(False)
    for s in live:
        s.close()
    return done, closed, len(live)


def start(conf):
    log = open(tmp / (conf.stem + ".log"), "w+")
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)
    atexit.register(p.kill)
    for _ in range(100):
        log.seek(0)
        if "started with" in log.read():
            break
        time.sleep(0.05)
    return p, log


def main():
    if not shutil.which("openssl"):
        print("skip budget: openssl not found")
        return 0
    sh("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", "k.pem")
    sh("openssl", "req", "-new", "-x509", "-key", "k.pem", "-subj", "/CN=okena.test",
       "-addext", "subjectAltName=DNS:okena.test", "-days", "2", "-out", "c.pem")
    route = "route /* { redirect 302 https://okena.test/x }"
    a = tmp / "a.conf"
    a.write_text(f"""okena {{ workers 1; io_engine {ENGINE}; metrics 127.0.0.1:{MET}; handshake_budget 100us }}
http 127.0.0.1:{LST} {{ tls {{ cert {tmp}/c.pem; key {tmp}/k.pem }}
    {route}
}}
""")
    b = tmp / "b.conf"
    b.write_text(f"""okena {{ workers 1; io_engine {ENGINE}; metrics 127.0.0.1:{MET2}; handshake_budget 1us wait=1ms }}
http 127.0.0.1:{LST2} {{ tls {{ cert {tmp}/c.pem; key {tmp}/k.pem }}
    {route}
}}
""")
    for conf in (a, b):
        r = subprocess.run([str(BIN), "check", str(conf)], capture_output=True, text=True)
        check(f"okena check: {conf.name}", r.returncode == 0, r.stderr[-300:])

    # both up before any burst: its client ports must not take theirs
    pa, loga = start(a)
    pb, logb = start(b)
    # a keep-alive HTTPS connection, open before the burst
    keep = ctx().wrap_socket(socket.create_connection(("127.0.0.1", LST), timeout=5),
                             server_hostname="okena.test")
    kf = keep.makefile("rwb")

    def ask():
        kf.write(b"GET /k HTTP/1.1\r\nHost: okena.test\r\n\r\n")
        kf.flush()
        status = kf.readline()
        while kf.readline() not in (b"\r\n", b""):
            pass
        return status.split()[1:2] == [b"302"]

    check("keep-alive connection answers before the burst", ask())
    done, closed, hung = burst(LST, BURST)
    check(f"{BURST} handshakes at once all complete", done == BURST,
          f"done={done} closed={closed} hung={hung}")
    time.sleep(1.3)                         # workers publish counters once a second
    m = metrics(MET)
    deferred = m.get("okena_tls_handshakes_deferred_total", -1)
    check("some hellos waited for the budget", deferred > 0, f"deferred={deferred}")
    check("none shed with the default wait", m.get("okena_tls_handshakes_shed_total", -1) == 0, str(m.get("okena_tls_handshakes_shed_total")))
    check("keep-alive connection still answers after the burst", ask())
    keep.close()

    done, closed, hung = burst(LST2, BURST)
    time.sleep(1.3)                         # workers publish counters once a second
    m = metrics(MET2)
    shed = m.get("okena_tls_handshakes_shed_total", -1)
    check("wait=1ms: stale hellos are shed", shed > 0, f"shed={shed} done={done}")
    check("shed connections are closed, none left hanging", hung == 0 and done + closed == BURST,
          f"done={done} closed={closed} hung={hung}")
    done, closed, hung = burst(LST2, 1)
    check("after the burst a new client gets through", done == 1, f"done={done} closed={closed}")

    for p, log in ((pa, loga), (pb, logb)):
        p.terminate()
        p.wait(10)
        log.seek(0)
        text = log.read()
        check("no worker died", "exited with status" not in text, text[-300:])
    print(f"budget {ENGINE}: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
