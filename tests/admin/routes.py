#!/usr/bin/env python3
"""`routes FILE` and `okena routes`, on one engine (argument): routes added,
replaced, listed and deleted at runtime through the running okena (the file
written whole, the configuration compiled, a reload); a route the
configuration does not take is refused with its error, the file and what
runs left as they were; a reload keeps them; `routes` in a host; last_good's
copy keeps the line, not the routes; names that clash and paths that are not
absolute are refused."""
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
BASE = 24600 + os.getpid() % 40 * 12 + (6 if ENGINE == "epoll" else 0)
BA, BB, L = BASE, BASE + 1, BASE + 2
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"))
    fails += not ok


def backend(port, name):
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            b = name.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def log_message(self, *a):
            pass
    s = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=s.serve_forever, daemon=True).start()


def get(path, host="x.test"):
    c = http.client.HTTPConnection("127.0.0.1", L, timeout=5)
    c.request("GET", path, headers={"Host": host})
    r = c.getresponse()
    b = r.read()
    c.close()
    return r.status, b.decode(errors="replace")


backend(BA, "a")
backend(BB, "b")
tmp = pathlib.Path(tempfile.mkdtemp())
rf = tmp / "api.conf"
hf = tmp / "shop.conf"
conf = tmp / "okena.conf"
conf.write_text(f"""
okena {{ overload off; workers 1; io_engine {ENGINE}; admin unix:{tmp}/admin.sock; last_good on; drain delay=0s timeout=1s }}
pool a {{ server 127.0.0.1:{BA} }}
pool b {{ server 127.0.0.1:{BB} }}
http 127.0.0.1:{L} {{
    host shop.test {{
        routes {hf}
        route /home {{ respond 200 "home" }}
    }}
    routes {rf}
    route /static {{ respond 200 "static" }}
}}
""")


def okena(*a):
    q = subprocess.run([str(BIN), "routes", *a, "-c", str(conf)], capture_output=True, text=True, timeout=60)
    return q.returncode, q.stdout, q.stderr


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
    check("no file yet: its routes are none, the others served", get("/v1/x")[0] == 404 and get("/static") == (200, "static"))
    rc, out, err = okena()
    check("okena routes: the names and their files", rc == 0 and f"api\t{rf}" in out and f"shop\t{hf}" in out, out + err)
    rc, out, err = okena("api", "put", "route /v1/* { to pool a }")
    check("put: written, compiled, reloaded", rc == 0 and "reloaded" in out, out + err)
    check("  served at once", get("/v1/x") == (200, "a"), str(get("/v1/x")))
    check("  the file: the route on a line", rf.read_text() == "route /v1/* { to pool a }\n", rf.read_text())
    rc, out, err = okena("api", "put", "route   /v1/*   {   to pool b }")
    check("put of the same head: it replaces it", rc == 0 and get("/v1/x") == (200, "b")
          and rf.read_text().count("route") == 1, rf.read_text())
    rc, out, err = okena("api", "put", 'route /v2 { respond 200 "two" }')
    check("put of another: both there", rc == 0 and get("/v2") == (200, "two") and get("/v1/x") == (200, "b"),
          rf.read_text())
    before = rf.read_text()
    rc, out, err = okena("api", "put", "route /v3 { to pool nosuch }")
    check("a route the configuration does not take: refused, its error said", rc == 1 and "nosuch" in err, err)
    check("  the file as it was, and what runs", rf.read_text() == before and get("/v3")[0] == 404
          and get("/v1/x") == (200, "b"), rf.read_text())
    rc, out, err = okena("api", "put", "header x y")
    check("not a route: refused", rc != 0 and "one route" in err, err)
    rc, out, err = okena("api")
    check("okena routes NAME: what it holds", rc == 0 and out == before, out)
    rc, out, err = okena("shop", "put", 'route /cart { respond 200 "cart" }')
    check("in a host: its routes there only", rc == 0 and get("/cart", "shop.test") == (200, "cart")
          and get("/home", "shop.test") == (200, "home") and get("/cart")[0] == 404, out + err)
    rc, out, err = okena("api", "delete", "/v1/*")
    check("delete (the paths alone): gone", rc == 0 and get("/v1/x")[0] == 404 and get("/v2") == (200, "two"),
          out + err + rf.read_text())
    rc, out, err = okena("api", "delete", "route /v1/*")
    check("  again: no such route", rc == 1 and "no route" in err, err)
    rc, out, err = okena("nosuch")
    check("a name not in the configuration", rc == 1 and "okena routes" in err, err)
    q = subprocess.run([str(BIN), "reload", "-c", str(conf)], capture_output=True, text=True, timeout=60)
    check("a reload keeps them (the file read again)", q.returncode == 0 and get("/v2") == (200, "two")
          and get("/cart", "shop.test") == (200, "cart"), q.stdout + q.stderr)
    check("no temporary file left", not (tmp / "api.conf.tmp").exists())
    good = (tmp / "okena.conf.good").read_text() if (tmp / "okena.conf.good").exists() else ""
    check("last_good's copy: the `routes` line, not its routes (the file stays the one to read)",
          f"routes {rf}" in good and "/v2" not in good, good[-300:])
    for what, extra in (("two files of one name", f"routes {tmp}/x/api.conf"),
                        ("a path not absolute", "routes api.conf")):
        bad = tmp / "bad.conf"
        bad.write_text(f"http 127.0.0.1:{L} {{\n    host b.test {{ {extra} }}\n    routes {rf}\n}}\n")
        q = subprocess.run([str(BIN), "check", str(bad)], capture_output=True, text=True, timeout=10)
        check(f"{what}: refused", q.returncode != 0 and "routes" in q.stderr, q.stderr[-200:])
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
        print(log.read()[-3000:])
print(f"routes ({ENGINE}): {'all passed' if not fails else f'{fails} failed'}")
sys.exit(1 if fails else 0)
