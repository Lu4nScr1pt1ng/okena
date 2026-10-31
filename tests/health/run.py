#!/usr/bin/env python3
"""Active health checks: down, up, black holes, panic, and the health
process itself dying."""
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
# ports 24000-24999: this suite's own range (none overlap)
BASE = 24000 + os.getpid() % 99 * 10
B0, B1, LST = BASE, BASE + 1, BASE + 2


class Backend:
    def __init__(self, port, tag):
        self.port, self.tag, self.sock = port, tag, None
        self.start()

    def start(self):
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", self.port))
        s.listen(1024)
        self.sock = s

        def loop():
            while True:
                try:
                    c, _ = s.accept()
                except OSError:
                    return
                try:
                    if c.recv(10):
                        c.sendall(self.tag)
                finally:
                    c.close()
        threading.Thread(target=loop, daemon=True).start()

    def stop(self):
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()


def who():
    t0 = time.time()
    c = socket.create_connection(("127.0.0.1", LST), timeout=3)
    c.sendall(b"who")
    r = c.recv(10)
    c.close()
    return r, time.time() - t0


failures = 0


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail else ""))
    failures += not ok


b0 = Backend(B0, b"b0")
b1 = Backend(B1, b"b1")
tmp = pathlib.Path(tempfile.mkdtemp())
conf = tmp / "okena.conf"
conf.write_text(f"""
okena {{ workers 2 }}
pool web {{
    server 127.0.0.1:{B0}
    server 127.0.0.1:{B1}
    server 192.0.2.1:9          # never answers
    connect timeout=1s
    health tcp every=200ms timeout=200ms rise=2 fall=2
}}
tcp 127.0.0.1:{LST} {{ to pool web }}
""")
log = open(tmp / "log", "w+")


def text():
    log.seek(0)
    return log.read()


def wait_log(needle, count=1, seconds=5):
    t0 = time.time()
    while time.time() - t0 < seconds:
        if text().count(needle) >= count:
            return time.time() - t0
        time.sleep(0.05)
    return None


p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log)
try:
    assert wait_log("started with") is not None, text()
    t = wait_log("backend 192.0.2.1:9 is down")
    check("black hole found by the health check", t is not None and t < 2, f"{t:.2f}s" if t else text())
    times = [who()[1] for _ in range(50)]
    check("requests no longer wait for the black hole", max(times) < 0.5, f"max {max(times) * 1000:.0f} ms")

    errors, seen = 0, set()
    error_kinds = []
    T0 = time.time()
    stop = threading.Event()

    STOP_AT = [None]

    def error(kind):
        # A connection okena already made to b1 when b1 stops (in its
        # accept queue) is reset by the kernel: no L4 proxy can save it
        # (the client's bytes went out). Only those, at the stop, are
        # forgiven; any error later counts.
        global errors
        at = time.time() - T0
        if STOP_AT[0] is not None and STOP_AT[0] <= at < STOP_AT[0] + 0.1:
            return
        errors += 1
        error_kinds.append(f"{kind} at {at:.2f}s")

    def hammer():
        # paced below what the single-threaded test backend accepts
        global errors
        while not stop.is_set():
            try:
                r = who()[0]
                if r:
                    seen.add(r)
                else:
                    error(f"empty answer")
            except OSError as e:
                error(repr(e))
            time.sleep(0.002)
    th = threading.Thread(target=hammer)
    th.start()
    STOP_AT[0] = time.time() - T0
    b1.stop()
    t = wait_log(f"backend 127.0.0.1:{B1} is down")
    check("stopped backend marked down", t is not None and t < 2, f"{t:.2f}s" if t else "")
    time.sleep(0.3)
    seen.clear()
    time.sleep(0.5)
    check("traffic only to the live backend", seen == {b"b0"}, str(seen))
    b1.start()
    t = wait_log(f"backend 127.0.0.1:{B1} is up")
    check("backend back up after rise checks", t is not None and t < 2, f"{t:.2f}s" if t else "")
    time.sleep(0.1)
    seen.clear()
    time.sleep(0.5)
    check("traffic returns to it at once", seen == {b"b0", b"b1"}, str(seen))
    if "-v" in sys.argv:
        print("errors so far", errors)
    stop.set()
    th.join()
    check("no client error through all of it", errors == 0, f"{errors} errors {error_kinds[:3]}")

    hp = int(subprocess.check_output(["pgrep", "-P", str(p.pid), "-x", "okena-health"]))
    os.kill(hp, signal.SIGKILL)
    t = wait_log("health process exited, restarting it")
    time.sleep(0.5)
    again = subprocess.run(["pgrep", "-P", str(p.pid), "-x", "okena-health"], capture_output=True).stdout.split()
    check("health process restarted after SIGKILL", t is not None and len(again) == 1)
    check("still serving", who()[0] in (b"b0", b"b1"))

    # everything down: panic, try them anyway rather than refuse
    b0.stop()
    b1.stop()
    wait_log(f"backend 127.0.0.1:{B0} is down")
    b0.start()
    r = who()[0]
    check("all marked down: servers are tried anyway (panic)", r == b"b0", str(r))
    check("each transition logged once", text().count(f"127.0.0.1:{B1} is down") == 2
          and text().count(f"127.0.0.1:{B1} is up") == 1, "")
finally:
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
    if failures or sys.exc_info()[0] or "-v" in sys.argv:
        print(text())
# HTTP checks: a backend whose /healthz answer the test controls
H0, H1, HL = BASE + 3, BASE + 4, BASE + 5
seen_checks = []


def http_backend(port, tag, state):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(256)

    def handle(c):
        try:
            data = c.recv(4096)
            if data.startswith(b"GET /healthz") or data.startswith(b"HEAD /healthz"):
                seen_checks.append(data)
                if state["mode"] == "garbage":
                    c.sendall(b"nope, not http\r\n")
                else:
                    c.sendall(b"HTTP/1.1 %d X\r\nContent-Length: 0\r\n\r\n" % state["status"])
            elif data:
                c.sendall(tag)
        except OSError:
            pass
        finally:
            c.close()

    def loop():
        while True:
            c, _ = s.accept()
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()


h0 = {"status": 200, "mode": "http"}
http_backend(H0, b"h0", h0)
http_backend(H1, b"h1", {"status": 200, "mode": "http"})
conf2 = tmp / "okena-http.conf"
conf2.write_text(f"""
okena {{ workers 2 }}
pool app {{
    server 127.0.0.1:{H0}
    server 127.0.0.1:{H1}
    health http GET /healthz every=150ms timeout=300ms rise=2 fall=2 expect=200..299 host=svc.internal
}}
tcp 127.0.0.1:{HL} {{ to pool app }}
""")
log2 = open(tmp / "log2", "w+")
p2 = subprocess.Popen([str(BIN), "-c", str(conf2)], stderr=log2)


def text2():
    log2.seek(0)
    return log2.read()


def wait2(needle, count=1, seconds=5):
    t0 = time.time()
    while time.time() - t0 < seconds:
        if text2().count(needle) >= count:
            return time.time() - t0
        time.sleep(0.05)
    return None


def who2():
    c = socket.create_connection(("127.0.0.1", HL), timeout=3)
    c.sendall(b"who")
    r = c.recv(10)
    c.close()
    return r


try:
    wait2("started with")
    t0 = time.time()
    while not seen_checks and time.time() - t0 < 3:
        time.sleep(0.05)
    first = seen_checks[0] if seen_checks else b""
    check("http check: GET /healthz with the configured Host",
          first.startswith(b"GET /healthz HTTP/1.1\r\n") and b"\r\nHost: svc.internal\r\n" in first
          and b"Connection: close" in first, repr(first[:120]))
    h0["status"] = 503
    t = wait2(f"backend 127.0.0.1:{H0} is down (health check: HTTP status 503")
    check("a 503 takes the server out, saying why", t is not None and t < 2, f"{t}")
    seen = {who2() for _ in range(30)}
    check("then traffic only to the healthy one", seen == {b"h1"}, str(seen))
    h0["status"] = 204
    t = wait2(f"backend 127.0.0.1:{H0} is up")
    check("a status in expect brings it back", t is not None and t < 2, f"{t}")
    seen = {who2() for _ in range(40)}
    check("and traffic returns to it", seen == {b"h0", b"h1"}, str(seen))
    h0["mode"] = "garbage"
    t = wait2(f"backend 127.0.0.1:{H0} is down", 2)
    check("an answer that is not HTTP fails the check", t is not None and t < 2, f"{t}")
finally:
    p2.send_signal(signal.SIGTERM)
    try:
        p2.wait(10)
    except subprocess.TimeoutExpired:
        p2.kill()
    if failures:
        print(text2())

# gRPC checks: grpc.health.v1.Health/Check over HTTP/2, answered by a
# server written with the h2 package, the status the test sets
try:
    import h2.config
    import h2.connection
    import h2.events
except ImportError:
    h2 = None
G0, G1, GL = BASE + 6, BASE + 7, BASE + 8
grpc_seen = []


def grpc_backend(port, tag, state):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(256)

    def handle(c):
        conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=False, header_encoding=None))
        try:
            first = c.recv(65536)
            if not first.startswith(b"PRI * HTTP/2.0"):
                c.sendall(tag)                      # traffic, not a check
                return
            conn.initiate_connection()
            data, heads, body = first, {}, {}
            while data:
                for e in conn.receive_data(data):
                    if isinstance(e, h2.events.RequestReceived):
                        heads[e.stream_id] = [(k.decode(), v.decode()) for k, v in e.headers]
                        body[e.stream_id] = b""
                    elif isinstance(e, h2.events.DataReceived):
                        body[e.stream_id] += e.data
                        conn.acknowledge_received_data(e.flow_controlled_length, e.stream_id)
                    elif isinstance(e, h2.events.StreamEnded):
                        sid, b = e.stream_id, body[e.stream_id]
                        service = b[7:7 + b[6]].decode() if len(b) > 6 else ""
                        grpc_seen.append((heads[sid], service))
                        st = state["status"].get(service)
                        if st is None:              # Trailers-Only: NOT_FOUND
                            conn.send_headers(sid, [(":status", "200"), ("content-type", "application/grpc"),
                                                    ("grpc-status", "5")], end_stream=True)
                        else:
                            conn.send_headers(sid, [(":status", "200"), ("content-type", "application/grpc")])
                            conn.send_data(sid, b"\0\0\0\0\2\x08" + bytes([st]))
                            conn.send_headers(sid, [("grpc-status", "0")], end_stream=True)
                c.sendall(conn.data_to_send())
                data = c.recv(65536)
        except Exception:
            pass
        finally:
            c.close()

    def loop():
        while True:
            c, _ = s.accept()
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()


if h2 is None:
    print("skip gRPC checks: pip install h2")
else:
    g0 = {"status": {"app.Svc": 1}}
    grpc_backend(G0, b"g0", g0)
    grpc_backend(G1, b"g1", {"status": {"app.Svc": 1}})
    conf3 = tmp / "okena-grpc.conf"
    conf3.write_text(f"""
okena {{ workers 2 }}
pool rpc {{
    protocol h2
    server 127.0.0.1:{G0}
    server 127.0.0.1:{G1}
    health grpc app.Svc every=150ms timeout=300ms rise=2 fall=2 host=rpc.internal
}}
tcp 127.0.0.1:{GL} {{ to pool rpc }}
""")
    log3 = open(tmp / "log3", "w+")
    p3 = subprocess.Popen([str(BIN), "-c", str(conf3)], stderr=log3)

    def text3():
        log3.seek(0)
        return log3.read()

    def wait3(needle, count=1, seconds=5):
        t0 = time.time()
        while time.time() - t0 < seconds:
            if text3().count(needle) >= count:
                return time.time() - t0
            time.sleep(0.05)
        return None

    def who3():
        c = socket.create_connection(("127.0.0.1", GL), timeout=3)
        c.sendall(b"who")
        r = c.recv(10)
        c.close()
        return r

    try:
        t0 = time.time()
        while not grpc_seen and time.time() - t0 < 3:
            time.sleep(0.05)
        hdrs, service = grpc_seen[0] if grpc_seen else ([], "")
        check("grpc check: Health/Check for the service, its pseudo-fields first",
              service == "app.Svc" and hdrs[:4] == [(":method", "POST"), (":scheme", "http"),
                                                    (":path", "/grpc.health.v1.Health/Check"),
                                                    (":authority", "rpc.internal")]
              and ("content-type", "application/grpc") in hdrs and ("te", "trailers") in hdrs, str(grpc_seen[:1]))
        g0["status"]["app.Svc"] = 2
        t = wait3(f"backend 127.0.0.1:{G0} is down (health check: gRPC serving status 2")
        check("NOT_SERVING takes the server out, saying why", t is not None and t < 2, f"{t}")
        seen = {who3() for _ in range(30)}
        check("then traffic only to the serving one", seen == {b"g1"}, str(seen))
        g0["status"]["app.Svc"] = 1
        t = wait3(f"backend 127.0.0.1:{G0} is up")
        check("SERVING brings it back", t is not None and t < 2, f"{t}")
        del g0["status"]["app.Svc"]
        t = wait3(f"backend 127.0.0.1:{G0} is down (health check: the gRPC call failed", 1)
        check("a service the server does not know (Trailers-Only) fails the check", t is not None and t < 2, f"{t}")
    finally:
        p3.send_signal(signal.SIGTERM)
        try:
            p3.wait(10)
        except subprocess.TimeoutExpired:
            p3.kill()
        if failures:
            print(text3())

print(f"health: {'all passed' if not failures else f'{failures} failed'}")
sys.exit(1 if failures else 0)
