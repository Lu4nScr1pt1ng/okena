#!/usr/bin/env python3
"""`alerts` on one engine (argument): events that are told (a backend down and
back, a reload refused, a worker restarted), gathered, filtered, sent to a
webhook (http and https), Slack and Telegram as each wants them, and kept when
a target cannot be reached."""
import http.server
import json
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

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
LST, HOOK, SHOOK, SLACK, TG, LATE, FAKE = 18760, 18761, 18762, 18763, 18764, 18765, 18766
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok  " if ok else "FAIL"), name, detail if not ok else "", flush=True)
    fails += 0 if ok else 1


got = {}


class Hook(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        body = self.rfile.read(n)
        got.setdefault(self.server.name, []).append((self.path, self.headers.get("content-type"), body))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True


def hook(name, port, ctx=None):
    s = S(("127.0.0.1", port), Hook)
    s.name = name
    if ctx:
        s.socket = ctx.wrap_socket(s.socket, server_side=True)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s


class Back(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def texts(name):
    out = []
    for path, ct, body in got.get(name, []):
        if name in ("hook", "hooks", "late"):
            out += [e["text"] for e in json.loads(body)["events"]]
        else:
            out.append(json.loads(body)["text"])
    return out


def until(fn, seconds=8):
    t = time.time()
    while time.time() - t < seconds:
        if fn():
            return True
        time.sleep(0.1)
    return False


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-alerts-", dir="/tmp"))
    run = lambda *a: subprocess.run(["openssl", *a], check=True, capture_output=True)
    run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", tmp / "ca.key",
        "-out", tmp / "ca.crt", "-subj", "/CN=alerts-ca", "-days", "2", "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign")
    run("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", tmp / "s.key",
        "-out", tmp / "s.csr", "-subj", "/CN=localhost")
    (tmp / "ext").write_text("subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\n")
    run("x509", "-req", "-in", tmp / "s.csr", "-CA", tmp / "ca.crt", "-CAkey", tmp / "ca.key", "-CAcreateserial",
        "-out", tmp / "s.crt", "-days", "1", "-extfile", tmp / "ext")
    run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", tmp / "other.key",
        "-out", tmp / "other.crt", "-subj", "/CN=another-ca", "-days", "2", "-addext", "basicConstraints=critical,CA:TRUE")
    # an impostor: a CA with the same name as one in the store, another key
    run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", tmp / "fake.key",
        "-out", tmp / "fake.crt", "-subj", "/CN=alerts-ca", "-days", "2", "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign")
    run("x509", "-req", "-in", tmp / "s.csr", "-CA", tmp / "fake.crt", "-CAkey", tmp / "fake.key", "-CAcreateserial",
        "-out", tmp / "fs.crt", "-days", "1", "-extfile", tmp / "ext")
    fctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    fctx.minimum_version = ssl.TLSVersion.TLSv1_3
    fctx.load_cert_chain(tmp / "fs.crt", tmp / "s.key")
    hook("fake", FAKE, fctx)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(tmp / "s.crt", tmp / "s.key")
    hook("hook", HOOK)
    hook("hooks", SHOOK, ctx)
    hook("slack", SLACK, ctx)
    hook("tg", TG, ctx)
    b = socket.socket()
    b.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    b.bind(("127.0.0.1", 0))
    bport = b.getsockname()[1]
    b.close()                                   # the backend starts down
    conf = tmp / "okena.conf"
    good = f"""okena {{ drain delay=0s timeout=1s; workers 2; io_engine {ENGINE} }}
alerts {{
    webhook http://127.0.0.1:{HOOK}/okena/events
    webhook https://localhost:{SHOOK}/in trust={tmp}/ca.crt
    slack https://localhost:{SLACK}/services/T/B/X trust={tmp}/ca.crt
    telegram token=123:ABC chat=-100123 api=https://localhost:{TG} trust={tmp}/ca.crt
    webhook http://127.0.0.1:{LATE}/late
    webhook https://localhost:{SHOOK}/forged trust={tmp}/other.crt
    webhook https://localhost:{SHOOK}/store
    webhook https://localhost:{FAKE}/impostor
    on backend reload worker
    every 1s
    name "edge 1"
}}
pool p {{ health tcp every=200ms fall=1 rise=1; server 127.0.0.1:{bport} }}
pool d {{ discover file {tmp}/nothing.list }}
http 127.0.0.1:{LST} {{ route /* {{ to pool p }} }}
"""
    conf.write_text(good)
    log = tmp / "log"
    # the system's store, as SSL_CERT_FILE names it: several roots, ours among them
    (tmp / "bundle.pem").write_text((tmp / "other.crt").read_text() + (tmp / "ca.crt").read_text())
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"), env=dict(os.environ, SSL_CERT_FILE=str(tmp / "bundle.pem")))
    try:
        ok = until(lambda: any("is down" in t for t in texts("hook")))
        check("a backend down: told to the webhook", ok, (got.get("hook"), log.read_text()[-400:]))
        path, ct, body = got["hook"][0]
        doc = json.loads(body)
        check("  POST of JSON to its path, as documented", path == "/okena/events" and ct == "application/json" and doc["source"] == "okena"
              and doc["name"] == "edge 1" and doc["events"][0]["kind"] == "backend" and doc["events"][0]["count"] >= 1, doc)
        check("  over https too, verified with trust=", until(lambda: any("is down" in t for t in texts("hooks"))))
        check("  with no trust=, the system's roots (SSL_CERT_FILE): the one that signed it found among them",
              until(lambda: any(x[0] == "/store" for x in got.get("hooks", []))), [x[0] for x in got.get("hooks", [])])
        refused = until(lambda: log.read_text().count("(it is not who it should be)") == 2)
        check("  nor to one signed by a key that only takes a stored root's name", refused and not got.get("fake"), log.read_text()[-300:])
        check("  never to a server the trust= CA did not sign", not any(x[0] == "/forged" for x in got.get("hooks", []))
              and "(it is not who it should be)" in log.read_text(), log.read_text()[-300:])
        check("  to Slack, as its text", until(lambda: any("okena edge 1:" in t and "is down" in t for t in texts("slack"))), texts("slack"))
        check("  to Telegram, its Bot API with the chat", until(lambda: got.get("tg") and got["tg"][0][0] == "/bot123:ABC/sendMessage"
                                                                and json.loads(got["tg"][0][2])["chat_id"] == "-100123"), got.get("tg"))
        check("  discovery is not told: `on` leaves it out", not any("discover" in t for t in texts("hook")), texts("hook"))
        check("  the target that is not there: said once, no alert of it", log.read_text().count("alerts: cannot reach 127.0.0.1") == 1
              and not any("alerts:" in t for t in texts("hook")), log.read_text()[-400:])

        # it comes back
        srv = S(("127.0.0.1", bport), Back)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        check("back: told", until(lambda: any("is up" in t for t in texts("hook"))), texts("hook"))
        late = hook("late", LATE)
        check("a target that was down gets what it missed", until(lambda: any("is down" in t for t in texts("late"))
                                                                  and any("is up" in t for t in texts("late"))), texts("late"))

        # a reload that takes: a new control process, which tells nothing again
        before = len(texts("hook"))
        conf.write_text(good + "# again\n")
        p.send_signal(signal.SIGHUP)
        time.sleep(3)
        check("a reload (a new control process): nothing told twice", len(texts("hook")) == before, texts("hook")[before:])
        conf.write_text(good)

        # a reload refused
        conf.write_text(good + "nonsense\n")
        p.send_signal(signal.SIGHUP)
        check("a reload refused: told", until(lambda: any("reload rejected" in t for t in texts("hook"))), texts("hook")[-3:])
        conf.write_text(good)

        # a worker that dies: one line, from the supervisor
        kids = subprocess.run(["pgrep", "-P", str(p.pid), "-x", "okena-worker"], capture_output=True, text=True).stdout.split()
        n0 = len(got.get("hook", []))
        os.kill(int(kids[0]), signal.SIGKILL)
        check("a worker killed: told", until(lambda: any("killed by signal 9" in t for t in texts("hook"))), texts("hook")[-3:])
        msgs = [json.loads(b) for _, _, b in got["hook"]]
        check("  every message is JSON, every event once a message", all(len({e["text"] for e in m["events"]}) == len(m["events"]) for m in msgs))
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no process died but the one killed", "seccomp" not in t and t.count("killed by signal") == 1, t[-300:])

    def bad(what, body):
        g = tmp / "bad.conf"
        g.write_text(f"alerts {{ {body} }}\npool p {{ server 127.0.0.1:1 }}\nhttp 127.0.0.1:1 {{ route /* {{ to pool p }} }}\n")
        r = subprocess.run([str(BIN), "check", str(g)], capture_output=True, text=True, timeout=10)
        check(f"{what}: refused", r.returncode != 0, r.stderr[-200:])
    bad("no target", "every 1s")
    bad("a URL that is not one", "webhook ftp://x/")
    bad("telegram with no chat", "telegram token=1:A")
    bad("a token with a slash", "telegram token=1/2 chat=3")
    bad("an event that is not one", "webhook http://127.0.0.1:1/; on everything")
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"alerts {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"), flush=True)
    sys.exit(1 if fails else 0)


main()
