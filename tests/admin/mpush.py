#!/usr/bin/env python3
"""`metrics_push`, on one engine (argument): /metrics' families pushed over
OTLP/HTTP as JSON every `every=`: counters and histograms as cumulative
monotonic sums, the rest gauges, labels as attributes, the same numbers
Prometheus reads; a collector that refuses gets the next snapshot later;
what the configuration refuses."""
import http.client
import http.server
import json
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
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 17400 + os.getpid() % 40 * 10 + (5 if ENGINE == "epoll" else 0)
LST, BACK, COLL, MET = BASE, BASE + 1, BASE + 2, BASE + 3
fails = 0
posts = []
refuse = {"n": 0}


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += 0 if ok else 1


class Back(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


class Coll(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        b = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if refuse["n"] > 0:
            refuse["n"] -= 1
            self.send_response(503)
            self.end_headers()
            return
        posts.append((self.path, self.headers.get("Content-Type"), b))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True


def metrics(doc):
    out = {}
    for rm in doc["resourceMetrics"]:
        for sm in rm["scopeMetrics"]:
            for m in sm["metrics"]:
                out[m["name"]] = m
    return out


def attrs(p):
    return {a["key"]: a["value"]["stringValue"] for a in p["attributes"]}


def until(fn, seconds=6):
    t = time.time()
    while time.time() - t < seconds:
        if fn():
            return True
        time.sleep(0.1)
    return False


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-mpush."))
    for port, h in ((BACK, Back), (COLL, Coll)):
        threading.Thread(target=S(("127.0.0.1", port), h).serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{
    drain delay=0s timeout=1s; workers 2; io_engine {ENGINE}
    metrics 127.0.0.1:{MET}
    metrics_push otlp://127.0.0.1:{COLL} every=1s
}}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{LST} {{ route /* {{ to pool b }} }}
""")
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(tmp / "log", "w"))
    try:
        until(lambda: _up(LST))
        for i in range(25):
            c = http.client.HTTPConnection("127.0.0.1", LST, timeout=3)
            c.request("GET", "/x")
            c.getresponse().read()
            c.close()
        n = len(posts)
        check("pushed every second", until(lambda: len(posts) >= n + 2, 5), len(posts))
        path, ctype, body = posts[-1]
        try:
            doc = json.loads(body)
        except ValueError as e:
            doc = None
            check("valid JSON", False, (str(e), body[:300]))
        if doc:
            check("to /v1/metrics, as JSON", path == "/v1/metrics" and ctype == "application/json", (path, ctype))
            rm = doc["resourceMetrics"][0]
            check("  okena as the service", {"key": "service.name", "value": {"stringValue": "okena"}} in rm["resource"]["attributes"])
            ms = metrics(doc)
            reloads = ms.get("okena_reloads_total", {})
            check("a counter: a cumulative monotonic sum", reloads.get("sum", {}).get("isMonotonic") is True
                  and reloads["sum"].get("aggregationTemporality") == 2, reloads)
            check("a gauge: a gauge", "gauge" in ms.get("okena_workers", {}), ms.get("okena_workers"))
            # the same numbers /metrics shows, labels as attributes
            prom = http.client.HTTPConnection("127.0.0.1", MET, timeout=3)
            prom.request("GET", "/metrics")
            text = prom.getresponse().read().decode()
            fam = next((l.split()[2] for l in text.splitlines() if l.startswith("# TYPE ") and "{listener=" in text
                        and l.split()[3] == "counter" and any(x.startswith(l.split()[2] + "{listener=") for x in text.splitlines())), None)
            m = ms.get(fam, {})
            pts = m.get("sum", {}).get("dataPoints", [])
            check(f"labels as attributes ({fam})", pts and all("listener" in attrs(x) for x in pts), (fam, pts[:2]))
            hist = [k for k in ms if k.endswith("_bucket")]
            check("histograms: their buckets as sums, le an attribute", hist and any("le" in attrs(x) for x in ms[hist[0]]["sum"]["dataPoints"]),
                  hist[:3])
            check("every point timed", all(x.get("timeUnixNano", "").isdigit() for m in ms.values()
                                          for x in (m.get("sum") or m.get("gauge"))["dataPoints"]))
        refuse["n"] = 2
        n = len(posts)
        check("a collector that refused: the next snapshot later", until(lambda: len(posts) > n, 8), len(posts))
    finally:
        p.terminate()
        p.wait(10)
    t = (tmp / "log").read_text()
    check("no process died", "killed" not in t and "restarting" not in t, t[-400:])
    for what, bad in (("not OTLP", "metrics_push syslog://127.0.0.1:514"), ("a period of 0", f"metrics_push otlp://127.0.0.1:{COLL} every=0s")):
        c = tmp / "bad.conf"
        c.write_text(f"okena {{ {bad} }}\nhttp 127.0.0.1:{LST} {{ route /* {{ respond 200 }} }}\n")
        q = subprocess.run([str(BIN), "check", str(c)], capture_output=True, text=True, timeout=10)
        q2 = subprocess.run(["timeout", "5", str(BIN), "-c", str(c)], capture_output=True, text=True)
        check(f"{what}: refused", q2.returncode not in (0, 124) and "metrics_push" in q2.stderr, q2.stderr[-200:])
    print(f"mpush {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


def _up(port):
    try:
        socket.create_connection(("127.0.0.1", port), 1).close()
        return True
    except OSError:
        return False


main()
