#!/usr/bin/env python3
"""okena bench: counts, framing, schedules and coordinated omission.

Python backends answer in every framing okena bench must follow
(Content-Length, chunked, HEAD, 204, Connection: close), and the
key=value report is checked: no errors, the exact request count at a
fixed rate, latency from the schedule far above the service time when
the backend stalls, TCP echo, HTTPS through okena (with kTLS), and
refusals for bad arguments and an unreachable target."""
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
# ports 23000-23999: this suite's own range
BASE = 23000 + os.getpid() % 99 * 10
HTTP, ECHO, HTTPS, BACK = BASE, BASE + 1, BASE + 2, BASE + 3
tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-bench-"))
failures = 0
stall = {"every": 0, "n": 0}


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"))
    if not ok:
        failures += 1


def answer(path, method):
    body = b"hello, bench"
    if path == "/chunked":
        return (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"5\r\nhello\r\n7;ext=1\r\n, bench\r\n0\r\nX-Trailer: 1\r\n\r\n")
    if path == "/close":
        return b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
    if path == "/nocontent":
        return b"HTTP/1.1 204 No Content\r\n\r\n"
    if path == "/unavailable":
        return b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"
    if path == "/continue":
        return b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"
    if path == "/big":
        body = b"x" * 200000
    if path == "/stall":
        stall["n"] += 1
        if stall["every"] and stall["n"] % stall["every"] == 0:
            time.sleep(0.3)
    head = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body)
    return head if method == "HEAD" else head + body


def http_backend(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(512)

    def handle(c):
        c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        buf = b""
        try:
            while True:
                while b"\r\n\r\n" not in buf:
                    d = c.recv(65536)
                    if not d:
                        return
                    buf += d
                head, buf = buf.split(b"\r\n\r\n", 1)
                line = head.split(b"\r\n", 1)[0].split()
                method, path = line[0].decode(), line[1].decode()
                for f in head.split(b"\r\n")[1:]:
                    if f.lower().startswith(b"content-length:"):
                        n = int(f.split(b":", 1)[1])
                        while len(buf) < n:
                            buf += c.recv(65536)
                        buf = buf[n:]
                r = answer(path, method)
                c.sendall(r)
                if b"Connection: close" in r:
                    return
        except OSError:
            pass
        finally:
            c.close()

    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


def echo_backend():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", ECHO))
    s.listen(64)

    def handle(c):
        try:
            while (d := c.recv(65536)):
                c.sendall(d)
        except OSError:
            pass
        finally:
            c.close()

    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


def bench(*args, timeout=30):
    r = subprocess.run([str(BIN), "bench", *args, "format=kv"], capture_output=True, text=True, timeout=timeout)
    kv = {}
    for word in r.stdout.split():
        if "=" in word:
            k, v = word.split("=", 1)
            kv[k] = float(v) if "." in v else int(v)
    return r.returncode, kv, r.stderr


def clean(name, kv, rc, err):
    n = kv.get("requests", 0)
    check(name, rc == 0 and n > 0 and kv["errors"] == 0 and kv["ok"] == n, f"rc={rc} {kv} {err}")


def have_ktls():
    return pathlib.Path("/sys/module/tls").exists()


def main():
    for p in (HTTP, BACK):
        threading.Thread(target=http_backend, args=(p,), daemon=True).start()
    threading.Thread(target=echo_backend, daemon=True).start()
    time.sleep(0.2)
    short = ["duration=400ms", "warmup=100ms", "conns=4"]
    url = f"http://127.0.0.1:{HTTP}"

    rc, kv, err = bench(f"{url}/", *short)
    clean("closed loop, Content-Length", kv, rc, err)
    rc, kv, err = bench(f"{url}/chunked", *short)
    clean("chunked with an extension and a trailer", kv, rc, err)
    rc, kv, err = bench(f"{url}/", *short, "method=HEAD")
    clean("HEAD: a Content-Length and no body", kv, rc, err)
    rc, kv, err = bench(f"{url}/nocontent", *short)
    clean("204 without a length", kv, rc, err)
    rc, kv, err = bench(f"{url}/continue", *short)
    clean("100 Continue, then the answer", kv, rc, err)
    rc, kv, err = bench(f"{url}/big", *short)
    clean("a 200 KB body over many reads", kv, rc, err)
    rc, kv, err = bench(f"{url}/close", *short)
    clean("Connection: close, then a new connection", kv, rc, err)
    check("  reconnects counted", kv.get("reconnects", 0) >= kv.get("requests", 1), str(kv))
    rc, kv, err = bench(f"{url}/", *short, "method=POST", "body=0123456789", "header=X-Bench: 1")
    clean("POST with a body and a header", kv, rc, err)
    rc, kv, err = bench(f"{url}/unavailable", *short)
    check("503s counted as other", rc == 0 and kv["errors"] == 0 and kv["other"] == kv["requests"] > 0
          and kv["ok"] == 0, str(kv))
    rc, kv, err = bench(f"http://localhost:{HTTP}/", *short, "workers=2")
    clean("localhost, two workers", kv, rc, err)

    # a fixed rate gives exactly rate * duration answers
    rc, kv, err = bench(f"{url}/", "rate=2000", "duration=1s", "warmup=200ms", "conns=8", "workers=2")
    check("rate=2000 for 1 s: 2000 requests", rc == 0 and kv["requests"] == 2000 and kv["behind"] == 0
          and kv["errors"] == 0, str(kv))
    check("  the sender's own lag is small", rc == 0 and kv.get("l_p99_ns", 10**9) < 2_000_000, str(kv))

    # a stall of 300 ms every 100 requests, one connection at 200/s: the
    # schedule's latency shows the stall for every request held back
    stall["every"], stall["n"] = 100, 0
    rc, kv, err = bench(f"{url}/stall", "rate=200", "duration=2s", "warmup=100ms", "conns=1")
    stall["every"] = 0
    check("coordinated omission: corrected p90 >> service p90",
          rc == 0 and kv["c_p90_ns"] > 50_000_000 and kv["s_p90_ns"] < 20_000_000
          and kv["c_max_ns"] >= 290_000_000, str(kv))

    # a rate the server cannot reach is reported as behind
    stall["every"], stall["n"] = 1, 0
    rc, kv, err = bench(f"{url}/stall", "rate=1000", "duration=1s", "warmup=0s", "conns=1")
    stall["every"] = 0
    check("an unreachable rate: requests behind", rc == 0 and kv["behind"] > 500, str(kv))

    rc, kv, err = bench(f"tcp://127.0.0.1:{ECHO}", *short, "size=1000")
    clean("tcp echo, 1000 bytes", kv, rc, err)
    rc, kv, err = bench(f"tcp://127.0.0.1:{ECHO}", "rate=1000", "duration=500ms", "warmup=0s", "conns=2", "size=64")
    check("tcp echo at a rate", rc == 0 and kv["requests"] == 500 and kv["errors"] == 0, str(kv))

    if have_ktls():
        subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out",
                        tmp / "k.pem"], check=True, capture_output=True)
        subprocess.run(["openssl", "req", "-new", "-x509", "-key", tmp / "k.pem", "-subj", "/CN=localhost",
                        "-days", "2", "-out", tmp / "c.pem"], check=True, capture_output=True)
        conf = (f"okena {{ workers 1 }}\nhttp 127.0.0.1:{HTTPS} {{\n"
                f"    tls {{ cert {tmp / 'c.pem'}; key {tmp / 'k.pem'} }}\n"
                f"    route /* {{ to 127.0.0.1:{BACK} }}\n}}\n")
        (tmp / "okena.conf").write_text(conf)
        ok = subprocess.Popen([str(BIN), "-c", str(tmp / "okena.conf")], stderr=subprocess.DEVNULL)
        try:
            time.sleep(0.4)
            rc, kv, err = bench(f"https://127.0.0.1:{HTTPS}/", *short)
            clean("https through okena (tickets in its flight, then kTLS)", kv, rc, err)
            rc, kv, err = bench(f"https://localhost:{HTTPS}/chunked", "rate=1000", "duration=500ms",
                                "warmup=100ms", "conns=4")
            check("https at a rate", rc == 0 and kv["requests"] == 500 and kv["errors"] == 0, str(kv))
        finally:
            ok.terminate()
            ok.wait()
    else:
        print("skip https: the tls module is not loaded")

    r = subprocess.run([str(BIN), "bench", f"{url}/", "speed=9"], capture_output=True, text=True)
    check("an unknown option is refused", r.returncode == 1 and "unknown option `speed`" in r.stderr, r.stderr)
    r = subprocess.run([str(BIN), "bench", "ftp://127.0.0.1:1/"], capture_output=True, text=True)
    check("an unknown scheme is refused", r.returncode == 1 and "URL" in r.stderr, r.stderr)
    r = subprocess.run([str(BIN), "bench", f"{url}/", "workers=8", "conns=2"], capture_output=True, text=True)
    check("more workers than connections is refused", r.returncode == 1, r.stderr)
    r = subprocess.run([str(BIN), "bench", f"http://127.0.0.1:{BASE + 9}/", "duration=1s"],
                       capture_output=True, text=True, timeout=10)
    check("an unreachable target fails fast", r.returncode == 1 and "could not connect" in r.stderr, r.stderr)

    print(f"{'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
