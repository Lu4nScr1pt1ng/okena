#!/usr/bin/env python3
"""${env:NAME} and ${env:NAME:-DEFAULT} in the configuration, on one engine
(argument): values from okena's environment in a word, in a quoted string,
in key=value; a default when the name is not set; a reload compiles with
okena's own environment, not the caller's; `okena fmt` and last_good's copy
keep what was written (a secret stays out of files); an unset name without a
default, and an unclosed one, are errors at their place."""
import http.client
import http.server
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "auto"
BASE = 25600 + os.getpid() % 40 * 12 + (6 if ENGINE == "epoll" else 0)
BACK, L = BASE, BASE + 1
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"))
    fails += not ok


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        b = (self.headers.get("x-key") or "-").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


def get(path):
    c = http.client.HTTPConnection("127.0.0.1", L, timeout=5)
    c.request("GET", path)
    r = c.getresponse()
    b = r.read().decode()
    c.close()
    return r.status, b


s = http.server.ThreadingHTTPServer(("127.0.0.1", BACK), H)
threading.Thread(target=s.serve_forever, daemon=True).start()
tmp = pathlib.Path(tempfile.mkdtemp())
conf = tmp / "okena.conf"
text = f"""
okena {{ workers 1; io_engine {ENGINE}; admin unix:{tmp}/admin.sock; last_good on; drain delay=0s timeout=1s }}
pool p {{ server ${{env:OK_BACKEND}} }}
http 127.0.0.1:${{env:OK_PORT}} {{
    route /hi {{ respond 200 "${{env:OK_GREETING:-hello}}, ${{env:OK_WHO}}" }}
    route /key {{ header set x-key ${{env:OK_SECRET}}; to pool p }}
    route /limited {{ limit ${{env:OK_RATE:-1}}/m burst=${{env:OK_BURST}} key=client.ip; respond 200 "in" }}
}}
"""
conf.write_text(text)
env = dict(os.environ, OK_BACKEND=f"127.0.0.1:{BACK}", OK_PORT=str(L), OK_WHO="world", OK_SECRET="s3cr3t-value",
           OK_BURST="2")
env.pop("OK_GREETING", None)
env.pop("OK_RATE", None)
log = open(tmp / "log", "w+")
p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log, env=env)
try:
    for _ in range(100):
        log.seek(0)
        if "started with" in log.read():
            break
        time.sleep(0.05)
    else:
        log.seek(0)
        sys.exit("okena did not start:\n" + log.read())
    check("in a word: the listener's port, the pool's server", get("/key")[0] == 200)
    check("in a quoted string, with a default for one not set", get("/hi") == (200, "hello, world"), str(get("/hi")))
    check("a secret into a header", get("/key") == (200, "s3cr3t-value"), str(get("/key")))
    codes = [get("/limited")[0] for _ in range(3)]
    check("in key=value (burst=2) and next to text (1/m)", codes == [200, 200, 429], str(codes))
    # a reload from a shell whose environment says otherwise: okena's own is used
    other = dict(env, OK_WHO="someone else", OK_PORT="1")
    q = subprocess.run([str(BIN), "reload", "-c", str(conf)], capture_output=True, text=True, timeout=30, env=other)
    check("a reload compiles with okena's environment, not the caller's", q.returncode == 0 and get("/hi") == (200, "hello, world"),
          q.stdout + q.stderr + str(get("/hi")))
    q = subprocess.run([str(BIN), "fmt", str(conf)], capture_output=True, text=True, timeout=10, env={})
    check("okena fmt: as written, with no environment at all", q.returncode == 0 and "${env:OK_SECRET}" in q.stdout
          and "s3cr3t" not in q.stdout, q.stdout[-300:] + q.stderr)
    good = tmp / "okena.conf.good"
    g = good.read_text() if good.exists() else ""
    check("last_good's copy: as written, the secret not in it", "${env:OK_SECRET}" in g and "s3cr3t" not in g, g[-300:])
    q = subprocess.run([str(BIN), "check", str(conf)], capture_output=True, text=True, timeout=10,
                       env={k: v for k, v in env.items() if k != "OK_WHO"})
    check("an unset name without a default: an error at its place", q.returncode != 0 and "the environment has no OK_WHO" in q.stderr
          and ":5:" in q.stderr, q.stderr[-300:])
    bad = tmp / "bad.conf"
    bad.write_text('http 127.0.0.1:1 {\n    route /x { respond 200 "${env:" }\n}\n')
    q = subprocess.run([str(BIN), "check", str(bad)], capture_output=True, text=True, timeout=10)
    check("an unclosed one: an error", q.returncode != 0 and "not closed" in q.stderr, q.stderr[-200:])
    bad.write_text('http 127.0.0.1:1 {\n    route /x { respond 200 "$5 {x} ${HOME}" }\n}\n')
    q = subprocess.run([str(BIN), "check", str(bad)], capture_output=True, text=True, timeout=10)
    check("other $ and ${...} text: left alone", q.returncode == 0, q.stderr[-200:])
    log.seek(0)
    check("no crash", "killed by signal" not in log.read())
finally:
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
    if fails:
        log.seek(0)
        print(log.read()[-2000:])
print(f"env ({ENGINE}): {'all passed' if not fails else f'{fails} failed'}")
sys.exit(1 if fails else 0)
