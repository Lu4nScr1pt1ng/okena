#!/usr/bin/env python3
"""Metrics a request leaves behind, on one engine (argument): refusals by why
(auth, acl, limit, body_size), each server's answers by class and their
time, the routes named by `metrics` with their own counts and histogram;
families each in one piece, as Prometheus' text format wants."""
import base64
import http.server
import os
import pathlib
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "auto"
BASE = 18400 + os.getpid() % 40 * 12 + (6 if ENGINE == "epoll" else 0)
BACK, L, M = BASE, BASE + 1, BASE + 2

failures = 0


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail else ""))
    failures += not ok


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        code = 500 if "fail" in self.path else 200
        self.send_response(code)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    do_POST = do_GET

    def log_message(self, *a):
        pass


def req(path, method="GET", body=b"", headers=""):
    c = socket.create_connection(("127.0.0.1", L), timeout=5)
    c.sendall(f"{method} {path} HTTP/1.1\r\nHost: t\r\nContent-Length: {len(body)}\r\n{headers}Connection: close\r\n\r\n"
              .encode() + body)
    r = b""
    try:
        while (d := c.recv(4096)):
            r += d
    except OSError:
        pass
    c.close()
    return int(r.split(b" ")[1]) if r.startswith(b"HTTP/") else 0


srv = http.server.ThreadingHTTPServer(("127.0.0.1", BACK), H)
srv.handle_error = lambda *a: None
threading.Thread(target=srv.serve_forever, daemon=True).start()
tmp = pathlib.Path(tempfile.mkdtemp())
(tmp / "keys").write_text("app:secret-key-1\n")
conf = tmp / "okena.conf"
conf.write_text(f"""
okena {{ workers 2; io_engine {ENGINE}; metrics 127.0.0.1:{M}; drain delay=0s timeout=1s }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{L} {{
    route /api/* {{ metrics api; to pool b }}
    route /also/* {{ metrics api; to pool b }}
    route /key {{ auth api_key header=x-api-key keys={tmp}/keys; to pool b }}
    route /lan {{ allow 10.0.0.0/8; to pool b }}
    route /slow {{ limit 1/s burst=1; to pool b }}
    route /up {{ body_size 10B; to pool b }}
    route /* {{ to pool b }}
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
    codes = [req("/api/a"), req("/api/b"), req("/also/c"), req("/api/fail"), req("/x")]
    codes += [req("/key"), req("/key", headers="x-api-key: wrong\r\n"), req("/key", headers="x-api-key: secret-key-1\r\n")]
    codes += [req("/lan"), req("/slow"), req("/slow"), req("/slow"), req("/up", "POST", b"x" * 100)]
    check("the requests themselves", codes == [200, 200, 200, 500, 200, 401, 401, 200, 403, 200, 429, 429, 413],
          str(codes))
    time.sleep(1.3)                        # (workers publish each second)
    m = urllib.request.urlopen(f"http://127.0.0.1:{M}/metrics", timeout=5).read().decode()

    def val(prefix, *parts):
        for line in m.splitlines():
            if line.startswith(prefix + "{") and all(x in line for x in parts):
                return float(line.split()[-1])
        return None

    lst = f'listener="127.0.0.1:{L}"'
    check("refused by why: auth 2, acl 1, limit 2, body_size 1",
          val("okena_http_refused_total", lst, 'reason="auth"') == 2 and val("okena_http_refused_total", lst, 'reason="acl"') == 1
          and val("okena_http_refused_total", lst, 'reason="limit"') == 2
          and val("okena_http_refused_total", lst, 'reason="body_size"') == 1
          and val("okena_http_refused_total", lst, 'reason="forbidden"') == 0, m[m.find("okena_http_refused"):][:600])
    srvl = f'server="127.0.0.1:{BACK}"'
    check("the server's answers by class: 6 2xx, 1 5xx",
          val("okena_backend_responses_total", srvl, 'class="2xx"') == 6
          and val("okena_backend_responses_total", srvl, 'class="5xx"') == 1, m[m.find("okena_backend_responses"):][:400])
    check("  and their time: a count of 7, a sum", val("okena_backend_response_seconds_count", srvl) == 7
          and (val("okena_backend_response_seconds_sum", srvl) or 0) > 0)
    check("routes named api (two of them): 3 2xx, 1 5xx",
          val("okena_route_requests_total", 'route="api"', 'class="2xx"') == 3
          and val("okena_route_requests_total", 'route="api"', 'class="5xx"') == 1)
    check("  its histogram: +Inf holds all 4, the count says 4",
          val("okena_route_request_duration_seconds_bucket", 'route="api"', 'le="+Inf"') == 4
          and val("okena_route_request_duration_seconds_count", 'route="api"') == 4)
    # every family in one piece: a name met again after another is a break
    seen, last, broken = set(), None, []
    for line in m.splitlines():
        if not line or line.startswith("#"):
            continue
        name = line.split("{")[0].split(" ")[0]
        for suffix in ("_bucket", "_sum", "_count"):
            if name.endswith(suffix):
                name = name[: -len(suffix)]
        if name != last:
            if name in seen:
                broken.append(name)
            seen.add(name)
            last = name
    check("each metric family in one piece", not broken, str(broken[:5]))
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
print(f"observability ({ENGINE}): {'all passed' if not failures else f'{failures} failed'}")
sys.exit(1 if failures else 0)
