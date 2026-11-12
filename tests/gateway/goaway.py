#!/usr/bin/env python3
"""GOAWAY on a drain, HTTP/2, on one engine (argument): `okena drain` tells
each client's connection to go (GOAWAY, NO_ERROR, the last stream taken), the
request in flight still gets its whole answer, a new stream is refused
(REFUSED_STREAM: safe to send again), an idle connection closes, `okena
resume` serves again; and a shutdown no longer waits its drain timeout out
for idle HTTP/2 connections."""
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

import h2.config
import h2.connection
import h2.events

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 43000 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
LST, BACK = BASE, BASE + 1
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
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if "slow" in self.path:
            time.sleep(1.5)
        body = b"answer of " + self.path.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, *a):
        pass


class Client:
    """HTTP/2 by prior knowledge; what came, by kind."""

    def __init__(self):
        self.s = socket.create_connection(("127.0.0.1", LST), timeout=5)
        self.c = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True))
        self.c.initiate_connection()
        self.s.sendall(self.c.data_to_send())
        self.events, self.closed = [], False

    def get(self, path):
        sid = self.c.get_next_available_stream_id()
        self.c.send_headers(sid, [(":method", "GET"), (":path", path), (":scheme", "http"), (":authority", "t")], end_stream=True)
        self.s.sendall(self.c.data_to_send())
        return sid

    def pump(self, seconds):
        """Read what comes for this long, or until the server closes."""
        end = time.time() + seconds
        while time.time() < end and not self.closed:
            self.s.settimeout(max(end - time.time(), 0.01))
            try:
                d = self.s.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                self.closed = True
                break
            if not d:
                self.closed = True
                break
            self.events += self.c.receive_data(d)
            out = self.c.data_to_send()
            if out:
                try:
                    self.s.sendall(out)
                except OSError:
                    pass

    def kinds(self, cls):
        return [e for e in self.events if isinstance(e, cls)]

    def body(self, sid):
        return b"".join(e.data for e in self.kinds(h2.events.DataReceived) if e.stream_id == sid)

    def ended(self, sid):
        return any(e.stream_id == sid for e in self.kinds(h2.events.StreamEnded))


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-goaway-", dir="/tmp"))
    threading.Thread(target=S(("127.0.0.1", BACK), H).serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE}; admin unix:{tmp}/admin.sock; drain delay=0s timeout=20s }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{LST} {{ http2 on; route /* {{ to pool b }} }}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=open(log, "w"))
    cli = lambda *a: subprocess.run([str(BIN), *a, "-c", str(conf)], capture_output=True, text=True, timeout=10)
    try:
        check("okena starts", until(lambda: socket.create_connection(("127.0.0.1", LST), 1).close() is None), log.read_text()[-300:])
        busy, idle = Client(), Client()
        idle.get("/warm")
        idle.pump(0.5)
        sid = busy.get("/slow")
        time.sleep(0.2)
        r = cli("drain")
        check("okena drain", r.returncode == 0, r.stderr)
        end = time.time() + 3                           # (the next tick: the GOAWAY goes,
        while time.time() < end and not busy.kinds(h2.events.ConnectionTerminated):
            busy.pump(0.1)                              # a second at most, more on a loaded host)
        ga = busy.kinds(h2.events.ConnectionTerminated)
        check("a connection with a request in flight: GOAWAY, NO_ERROR, the last stream it took",
              ga and ga[0].error_code == 0 and ga[0].last_stream_id == sid, [(e.error_code, e.last_stream_id) for e in ga])
        # a stream after it, sent anyway as a racing client may (raw: h2 would not)
        import hpack
        late = sid + 2
        block = hpack.Encoder().encode([(":method", "GET"), (":path", "/late"), (":scheme", "http"), (":authority", "t")])
        busy.s.sendall(len(block).to_bytes(3, "big") + bytes([1, 0x05]) + late.to_bytes(4, "big") + block)
        busy.raw = b""
        end = time.time() + 3
        while time.time() < end:
            busy.s.settimeout(max(end - time.time(), 0.01))
            try:
                d = busy.s.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            if not d:
                busy.closed = True
                break
            busy.raw += d
        frames, i = [], 0
        while i + 9 <= len(busy.raw):
            n = int.from_bytes(busy.raw[i:i + 3], "big")
            frames.append((busy.raw[i + 3], int.from_bytes(busy.raw[i + 5:i + 9], "big") & 0x7FFFFFFF, busy.raw[i + 9:i + 9 + n]))
            i += 9 + n
        data = b"".join(f[2] for f in frames if f[0] == 0 and f[1] == sid)
        check("  the request in flight gets its whole answer", data == b"answer of /slow" or busy.body(sid) == b"answer of /slow",
              (data, [(t, sid_) for t, sid_, _ in frames]))
        rst = [int.from_bytes(f[2][:4], "big") for f in frames if f[0] == 3 and f[1] == late]
        check("  a stream after it: refused (REFUSED_STREAM, safe to send again), never answered", rst == [7]
              and not any(f[0] == 1 and f[1] == late for f in frames), [(t, x) for t, x, _ in frames])
        check("  and the connection closes, nothing left", busy.closed)
        idle.pump(1.5)
        ga = idle.kinds(h2.events.ConnectionTerminated)
        check("an idle connection: GOAWAY, then closed", ga and ga[0].error_code == 0 and idle.closed, (ga, idle.closed))

        r = cli("resume")
        fresh = Client()
        s2 = fresh.get("/again")
        fresh.pump(1.5)
        check("okena resume: served, and no GOAWAY", fresh.ended(s2) and not fresh.kinds(h2.events.ConnectionTerminated) and not fresh.closed,
              (fresh.events[-3:], fresh.closed))

        # stopping: an idle HTTP/2 connection no longer holds it for its drain timeout (20 s)
        import http.client
        h1 = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
        h1.request("GET", "/h1")
        h1.getresponse().read()
        t0 = time.time()
        p.send_signal(signal.SIGTERM)
        # HTTP/1.1 kept alive: once the worker drains, its next answer is whole and says close
        said = None
        while time.time() - t0 < 3 and said is None:
            try:
                h1.request("GET", "/h1")
                r = h1.getresponse()
                body = r.read()
                if r.getheader("connection", "").lower() == "close":
                    said = (r.status, body)
            except (OSError, http.client.HTTPException) as e:
                said = repr(e)
        check("a stop: HTTP/1.1 kept alive gets its answer whole, with Connection: close",
              said == (200, b"answer of /h1"), said)
        h1.close()
        fresh.pump(4)
        p.wait(15)
        took = time.time() - t0
        ga = fresh.kinds(h2.events.ConnectionTerminated)
        check("a shutdown: GOAWAY to the idle connection, and okena leaves at once, not after 20 s",
              ga and ga[0].error_code == 0 and took < 4, (took, ga))
    finally:
        if p.poll() is None:
            p.kill()
            p.wait(10)
    t = log.read_text()
    check("no process died", "seccomp" not in t and "killed by signal" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"goaway {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


main()
