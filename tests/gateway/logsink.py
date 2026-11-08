#!/usr/bin/env python3
"""Access logs over the network, on one engine (argument): syslog (RFC 5424)
over UDP, TCP (octet counting) and TLS (verified), and OTLP/HTTP logs (JSON,
plain and TLS); a destination that goes away and comes back; what the
configuration refuses."""
import http.client
import http.server
import json
import os
import pathlib
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
BASE = 31000 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
L_UDP, L_TCP, L_TLS, L_OTLP, L_OTLPS, L_FORGED = (BASE + i for i in range(6))
S_UDP, S_TCP, S_TLS, S_OTLP, S_OTLPS = (BASE + 6 + i for i in range(5))
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok  " if ok else "FAIL"), name, detail if not ok else "", flush=True)
    fails += 0 if ok else 1


def until(fn, seconds=8):
    t = time.time()
    while time.time() - t < seconds:
        if fn():
            return True
        time.sleep(0.05)
    return False


def get(port, path):
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("GET", path)
        r = c.getresponse()
        r.read()
        c.close()
        return r.status
    except OSError:
        return None


SYSLOG = re.compile(r"^<190>1 (\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z) (\S+) okena (\d+) access - (\{.*\})$")
udp_msgs, tcp_msgs, tls_msgs = [], [], []


def udp_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", S_UDP))
    while True:
        udp_msgs.append(s.recv(65536).decode())


def frames(conn, out):
    """RFC 6587 octet counting: LENGTH SP MESSAGE, again and again."""
    buf = b""
    while True:
        try:
            d = conn.recv(65536)
        except OSError:
            return
        if not d:
            return
        buf += d
        while True:
            sp = buf.find(b" ")
            if sp < 0:
                break
            n = int(buf[:sp])
            if len(buf) < sp + 1 + n:
                break
            out.append(buf[sp + 1:sp + 1 + n].decode())
            buf = buf[sp + 1 + n:]


class Stream:
    """A syslog stream server that can be stopped and started again; drop()
    closes the connections it holds and keeps listening."""

    def __init__(self, port, out, ctx=None):
        self.port, self.out, self.ctx, self.conns, self.ls = port, out, ctx, [], None
        self.accepted = 0

    def start(self):
        ls = socket.socket()
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ls.bind(("127.0.0.1", self.port))
        ls.listen(8)
        self.ls = ls
        threading.Thread(target=self.loop, args=(ls,), daemon=True).start()

    def loop(self, ls):
        while True:
            try:
                c, _ = ls.accept()
            except OSError:
                return
            if self.ctx:
                try:
                    c = self.ctx.wrap_socket(c, server_side=True)
                except (ssl.SSLError, OSError):
                    c.close()
                    continue
            self.accepted += 1
            self.conns.append(c)
            threading.Thread(target=frames, args=(c, self.out), daemon=True).start()

    def drop(self):
        for c in self.conns:
            try:
                c.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            c.close()
        self.conns = []

    def stop(self):
        self.drop()
        try:
            self.ls.shutdown(socket.SHUT_RDWR)      # (wakes the accept: close alone does not)
        except OSError:
            pass
        self.ls.close()


posts = {}


class Collector(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", 0)))
        posts.setdefault(self.server.name, []).append((self.path, self.headers.get("content-type"), body))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def collector(name, port, ctx=None):
    s = S(("127.0.0.1", port), Collector)
    s.name = name
    if ctx:
        s.socket = ctx.wrap_socket(s.socket, server_side=True)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s


def records(name):
    out = []
    for path, ct, body in posts.get(name, []):
        doc = json.loads(body)
        for rl in doc["resourceLogs"]:
            for sl in rl["scopeLogs"]:
                out.extend(sl["logRecords"])
    return out


def attrs(rec):
    return {a["key"]: a["value"] for a in rec["attributes"]}


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-logsink-", dir="/tmp"))
    run = lambda *a: subprocess.run(["openssl", *a], check=True, capture_output=True)
    run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", tmp / "ca.key",
        "-out", tmp / "ca.crt", "-subj", "/CN=logs-ca", "-days", "2", "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign")
    run("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", tmp / "s.key",
        "-out", tmp / "s.csr", "-subj", "/CN=localhost")
    (tmp / "ext").write_text("subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\n")
    run("x509", "-req", "-in", tmp / "s.csr", "-CA", tmp / "ca.crt", "-CAkey", tmp / "ca.key", "-CAcreateserial",
        "-out", tmp / "s.crt", "-days", "1", "-extfile", tmp / "ext")
    run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", tmp / "other.key",
        "-out", tmp / "other.crt", "-subj", "/CN=another-ca", "-days", "2", "-addext", "basicConstraints=critical,CA:TRUE")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(tmp / "s.crt", tmp / "s.key")
    (tmp / "www").mkdir()
    (tmp / "www" / "index.html").write_text("hello\n")

    threading.Thread(target=udp_server, daemon=True).start()
    tcp = Stream(S_TCP, tcp_msgs)
    tcp.start()
    tls = Stream(S_TLS, tls_msgs, ctx)
    tls.start()
    otlps = collector("otlps", S_OTLPS, ctx)
    # the plain collector starts down: what comes meanwhile waits for it

    def site(port, dest):
        return f"""http 127.0.0.1:{port} {{
    access_log {dest}
    route /bad/* {{ to pool gone }}
    route /* {{ files {tmp}/www }}
}}
"""
    conf = tmp / "okena.conf"
    conf.write_text(f"okena {{ workers 2; io_engine {ENGINE} }}\npool gone {{ server 127.0.0.1:1 }}\n"
                    + site(L_UDP, f"syslog://127.0.0.1:{S_UDP}")
                    + site(L_TCP, f"syslog+tcp://127.0.0.1:{S_TCP}")
                    + site(L_TLS, f"syslog+tls://localhost:{S_TLS} trust={tmp}/ca.crt")
                    + site(L_OTLP, f"otlp://127.0.0.1:{S_OTLP}")
                    + site(L_OTLPS, f"otlp+https://localhost:{S_OTLPS}/in/logs trust={tmp}/ca.crt")
                    + site(L_FORGED, f"syslog+tls://localhost:{S_TLS} trust={tmp}/other.crt"))
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        check("okena starts", until(lambda: get(L_UDP, "/index.html") == 200), log.read_text()[-400:])
        sup = p.pid

        # syslog over UDP: one datagram a line, RFC 5424, the line's own time
        get(L_UDP, "/index.html?x=1")
        ok = until(lambda: any("/index.html?x=1" in m for m in udp_msgs))
        m = SYSLOG.match(udp_msgs[-1]) if udp_msgs else None
        check("syslog over UDP: an RFC 5424 message a line", ok and m is not None, udp_msgs[-2:])
        if m:
            line = json.loads(m.group(4))
            check("  its time is the line's, its PROCID the supervisor, its HOSTNAME the host's",
                  m.group(1) == line["time"] and m.group(3) == str(sup) and m.group(2) == socket.gethostname(), m.groups()[:3])

        # syslog over TCP: octet-counted frames on one connection
        for i in range(20):
            get(L_TCP, f"/index.html?n={i}")
        check("syslog over TCP: each line a frame", until(lambda: sum("/index.html?n=" in m for m in tcp_msgs) == 20),
              len(tcp_msgs))
        check("  all well formed, on one connection", all(SYSLOG.match(m) for m in tcp_msgs) and tcp.accepted == 1,
              (tcp.accepted, tcp_msgs[:2]))
        # the collector closes the connection: seen before lines go to it, nothing lost
        tcp.drop()
        time.sleep(0.3)
        get(L_TCP, "/index.html?after=close")
        check("  a connection the collector closed: a new one, the line not lost",
              until(lambda: any("after=close" in m for m in tcp_msgs)) and tcp.accepted == 2, (tcp.accepted, tcp_msgs[-2:]))
        # the collector goes away: said once; back: said, and lines go again
        tcp.stop()
        time.sleep(0.3)
        for i in range(3):
            get(L_TCP, f"/index.html?gone={i}")
        check("  a collector gone: said once", until(lambda: log.read_text().count(f"syslog+tcp://127.0.0.1:{S_TCP}: cannot reach it") == 1),
              log.read_text()[-400:])
        tcp.start()
        ok = until(lambda: (get(L_TCP, "/index.html?back=1") and any("back=1" in m for m in tcp_msgs)), 10)
        check("  back: lines go to it again, and it is said", ok and "reached again" in log.read_text(), log.read_text()[-300:])

        # syslog over TLS, the collector verified with trust=
        get(L_TLS, "/index.html?tls=1")
        check("syslog over TLS: verified with trust=, framed", until(lambda: any("tls=1" in m and SYSLOG.match(m) for m in tls_msgs)),
              tls_msgs[-2:])
        get(L_FORGED, "/index.html?forged=1")
        check("  never to a collector that trust= did not sign", until(lambda: f"syslog+tls://localhost:{S_TLS}: cannot reach it (it is not who it should be)" in log.read_text())
              and not any("forged=1" in m for m in tls_msgs), log.read_text()[-300:])

        # OTLP over https: a record per line, the fields as attributes
        get(L_OTLPS, "/index.html?q=a%22b")
        get(L_OTLPS, "/nothing")
        get(L_OTLPS, "/bad/x")
        ok = until(lambda: len(records("otlps")) >= 3)
        check("OTLP over https: records POSTed to the URL's path, as JSON", ok and posts["otlps"][0][0] == "/in/logs"
              and posts["otlps"][0][1] == "application/json", [x[:2] for x in posts.get("otlps", [])])
        if ok:
            doc = json.loads(posts["otlps"][0][2])
            res = {a["key"]: a["value"]["stringValue"] for a in doc["resourceLogs"][0]["resource"]["attributes"]}
            check("  the resource: service.name okena, host.name", res == {"service.name": "okena", "host.name": socket.gethostname()}, res)
            recs = records("otlps")
            by = {attrs(r)["url.path"]["stringValue"]: r for r in recs}
            r = by.get("/index.html")
            a = attrs(r) if r else {}
            check("  OpenTelemetry's names: method, status (an int), path, query", r is not None
                  and a["http.request.method"] == {"stringValue": "GET"} and a["http.response.status_code"] == {"intValue": "200"}
                  and a["url.query"] == {"stringValue": "q=a%22b"} and a["client.address"] == {"stringValue": "127.0.0.1"}
                  and a["okena.retried"] == {"boolValue": False} and "okena.request_id" not in a
                  and a["okena.source"] == {"stringValue": "okena"} and "okena.upstream" not in a
                  and isinstance(a["okena.duration_ms"]["doubleValue"], float), a)
            check("  its time the line's, in nanoseconds", r is not None and abs(int(r["timeUnixNano"]) / 1e9 - time.time()) < 30
                  and int(r["timeUnixNano"]) % 1000000 == 0, r and r["timeUnixNano"])
            check("  severity from the status: 200 INFO, 404 WARN, 502 ERROR", r is not None and r["severityText"] == "INFO"
                  and by.get("/nothing", {}).get("severityText") == "WARN" and by.get("/bad/x", {}).get("severityText") == "ERROR"
                  and by["/bad/x"]["body"]["stringValue"] == "GET /bad/x 502", {k: v.get("severityText") for k, v in by.items()})

        # OTLP to a collector that is not there yet: kept, sent when it comes
        for i in range(5):
            get(L_OTLP, f"/index.html?wait={i}")
        check("OTLP, the collector not there: said", until(lambda: f"otlp://127.0.0.1:{S_OTLP}: cannot reach it; its lines are kept" in log.read_text()),
              log.read_text()[-300:])
        collector("otlp", S_OTLP)
        ok = until(lambda: sum("wait=" in attrs(r).get("url.query", {}).get("stringValue", "") for r in records("otlp")) == 5, 12)
        check("  it comes: what waited is sent, once", ok and posts["otlp"][0][0] == "/v1/logs", len(records("otlp")))

        # a reload: the logger starts again, its destinations with it
        before = len(udp_msgs)
        p.send_signal(signal.SIGHUP)
        time.sleep(1)
        get(L_UDP, "/index.html?reloaded=1")
        check("a reload: lines still go out", until(lambda: any("reloaded=1" in m for m in udp_msgs[before:])), udp_msgs[-1:])
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no process died", "seccomp" not in t and "killed by signal" not in t and "exited" not in t, t[-400:])

    def bad(what, dest):
        g = tmp / "bad.conf"
        g.write_text(f"http 127.0.0.1:1 {{ access_log {dest}; route /* {{ files {tmp}/www }} }}\n")
        r = subprocess.run([str(BIN), "check", str(g)], capture_output=True, text=True, timeout=10)
        check(f"{what}: refused", r.returncode != 0, r.stderr[-200:])
    bad("a scheme that is not one", "ftp://127.0.0.1/")
    bad("no host", "syslog://")
    bad("port 0", "syslog://127.0.0.1:0")
    bad("a port too big", "syslog+tcp://127.0.0.1:65536")
    bad("a path on syslog", "syslog://127.0.0.1:514/x")
    bad("trust= where there is no TLS", f"syslog://127.0.0.1:514 trust={tmp}/ca.crt")
    bad("a trust= file that is not a certificate", f"syslog+tls://localhost:6514 trust={tmp}/www/index.html")
    bad("a relative path", "logs/access.log")
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"logsink {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


main()
