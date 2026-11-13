#!/usr/bin/env python3
"""proxy-wasm plugins through okena's wasm addon (addons/wasm, wazero), on
one engine (argument). A plugin on the proxy-wasm Go SDK: fields added and
removed, its configuration, properties (source.address, request.method),
shared data counted across its instances, a local answer, :path rewritten,
and a proxy_http_call to a service it pauses for (yes: on, with what the
service said; no: 401); over HTTP/2 too. A plugin on the Rust SDK (the
proxy-wasm crate), when it was built. A file that is not a plugin: the
addon exits, its route follows on_error, and the log says why. Skipped
without build/wasm-okena."""
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import http.server

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
HOST = ROOT / "build" / "wasm-okena"
GOP = ROOT / "build" / "test-plugin-go.wasm"
RUSTP = ROOT / "build" / "test-plugin-rust.wasm"
CACHE = ROOT / "build" / "wasm-cache"
L = 44000 + os.getpid() % 90 * 10 + (5 if ENGINE == "epoll" else 0)
B, A = L + 1, L + 2
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


class Echo(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    wbufsize = -1

    def do_GET(self):
        n = int(self.headers.get("content-length") or 0)
        got = self.rfile.read(n) if n else b""
        b = (self.requestline + "\n" + str(self.headers)).encode() + b"body: " + got
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    do_POST = do_GET

    def log_message(self, *a):
        pass


class Auth(Echo):
    def do_GET(self):
        ok = self.headers.get("authorization") == "Bearer good"
        b = b"alice" if ok else b"nope"
        self.send_response(200 if ok else 403)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


def get(path, headers=(), body=None):
    k = socket.create_connection(("127.0.0.1", L), 5)
    hs = list(headers) + ([("Content-Length", str(len(body)))] if body is not None else [])
    k.sendall((f"{'POST' if body is not None else 'GET'} {path} HTTP/1.1\r\nHost: t\r\n" + "".join(f"{a}: {b}\r\n" for a, b in hs)
               + "Connection: close\r\n\r\n").encode() + (body or b""))
    d = b""
    while True:
        x = k.recv(65536)
        if not x:
            break
        d += x
    k.close()
    head, _, body = d.partition(b"\r\n\r\n")
    hs = {}
    for l in head.decode("latin-1").split("\r\n")[1:]:
        if ":" in l:
            a, b = l.split(":", 1)
            hs[a.strip().lower()] = b.strip()
    return (int(head.split()[1]) if head else 0), hs, body


def main():
    if not (os.access(HOST, os.X_OK) and GOP.exists()):
        print("wasm: skipped (no build/wasm-okena or build/test-plugin-go.wasm: Go or the modules missing)")
        return
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-wasm-"))
    for port, h in ((B, Echo), (A, Auth)):
        s = http.server.ThreadingHTTPServer(("127.0.0.1", port), h)
        threading.Thread(target=s.serve_forever, daemon=True).start()
    bad = tmp / "bad.wasm"
    bad.write_bytes(b"\0asm not really")
    rust = RUSTP.exists()
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 2; io_engine {ENGINE}; drain delay=0s timeout=1s }}
addon plug {{
    run {HOST} -plugin {GOP} -config hello-config -cluster authsvc=127.0.0.1:{A} -instances 2 -cache {CACHE}
    timeout 2s
}}
addon bplug {{
    run {HOST} -plugin {GOP} -instances 1 -cache {CACHE}
    phases request_body
    body 1KiB
    timeout 2s
}}
addon rplug {{
    run {HOST} -plugin {RUSTP if rust else GOP} -instances 1 -cache {CACHE}
    timeout 2s
}}
addon broken {{
    run {HOST} -plugin {bad} -cache ""
    timeout 200ms
    on_error allow
}}
pool echo {{ server 127.0.0.1:{B} }}
http 127.0.0.1:{L} {{
    http2 on
    route /r/* {{ addon rplug; to pool echo }}
    route /bd/* {{ addon bplug; to pool echo }}
    route /b/* {{ addon broken; to pool echo }}
    route /* {{ addon plug; to pool echo }}
}}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        end = time.time() + 15
        while time.time() < end and "started with" not in log.read_text():
            time.sleep(0.02)
        # (okena waits 5 s for an addon; a loaded host may take longer to
        # instantiate plugins: until then their routes answer 503)
        while time.time() < end and get("/deny")[0] == 503:
            time.sleep(0.05)
        s, h, b = get("/x", [("X-Drop", "1")])
        check("fields added and removed, the configuration, properties", s == 200 and b"x-wasm: yes" in b and b"X-Drop" not in b
              and b"x-config: hello-config" in b and b"x-source: 127.0.0.1:0" in b and b"x-method: GET" in b, b)
        counts = []
        for _ in range(4):
            s, h, b = get("/x")
            counts += [int(l.split(b":")[1]) for l in b.split(b"\n") if l.startswith(b"x-count:")]
        check("shared data: one counter over the instances", len(counts) == 4 and counts == sorted(counts) and len(set(counts)) == 4, counts)
        s, h, b = get("/deny")
        check("a local answer: 403, its fields and body", s == 403 and h.get("x-plugin") == "test" and b == b"denied by wasm\n", (s, h, b))
        s, h, b = get("/rewrite")
        check(":path rewritten: the backend sees the new target", s == 200 and b"GET /rewritten?by=wasm HTTP/1.1" in b, b)
        s, h, b = get("/auth", [("Authorization", "Bearer good")])
        check("http_call: the service says yes, the request goes on with its answer", s == 200 and b"x-user: alice" in b, (s, b))
        s, h, b = get("/auth", [("Authorization", "Bearer bad")])
        check("  it says no: the plugin's 401", s == 401 and h.get("x-auth") == "refused", (s, h))
        if shutil.which("curl"):
            c = subprocess.run(["curl", "-q", "-s", "--http2-prior-knowledge", "-o", "/dev/null", "-w", "%{http_code}",
                                f"http://127.0.0.1:{L}/deny"], capture_output=True, text=True, timeout=10)
            check("HTTP/2: the local answer", c.stdout == "403", c.stdout)
        if rust:
            s, h, b = get("/r/x", [("X-Drop", "1")])
            s2, h2, b2 = get("/r/rust-deny")
            check("a plugin on the Rust SDK: a field set, one removed, a local answer",
                  s == 200 and b"x-rust: yes" in b and b"X-Drop" not in b and s2 == 451 and b2 == b"unavailable\n", (s, b, s2, b2))
        else:
            print("skip the Rust plugin: not built (rustup target add wasm32-wasip1)")
        s, h, b = get("/bd/x", body=b"hello wasm")
        check("request_body: proxy_on_request_body sees the body", s == 200 and b"x-body-size: 10" in b and b"x-body-more" not in b, (s, b))
        s, h, b = get("/bd/x", body=b"this is forbidden")
        check("  and answers from it", s == 413 and h.get("x-plugin") == "body", (s, h))
        s, h, b = get("/bd/x", body=b"y" * 3000)
        check("  past `body 1KiB`: its first bytes, end_of_stream false", s == 200 and b"x-body-size: 1024" in b and b"x-body-more: yes" in b, (s, b[-300:]))
        s, h, b = get("/b/x")
        check("not a plugin: the addon exits, on_error allow lets the request on", s == 200 and b"GET /b/x" in b, (s, b))
        check("  and the log says why", "compiling the plugin" in log.read_text(), log.read_text()[-500:])
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no worker died", "killed" not in t and "seccomp" not in t, t[-400:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"wasm {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
