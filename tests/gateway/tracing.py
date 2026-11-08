#!/usr/bin/env python3
"""`tracing` on one engine (argument): W3C Trace Context in and out, server
spans over OTLP/HTTP, sampling (parent-based, then sample=), the access log's
records tied to their spans, copies (mirror) carrying the trace without a
span of their own, and what the configuration refuses."""
import http.client
import http.server
import json
import os
import pathlib
import re
import shutil
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
BASE = 33000 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
L_ALL, L_NONE, L_OFF, L_HALF, L_TLS, BACK, SHADOW, COLL = (BASE + i for i in range(8))
fails = 0
TP = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-(0[01])$")


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


seen = {}            # the request's mark -> the traceparent fields the backend got
shadow = {}


def backend(store, port):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            mark = self.path.split("m=")[-1]
            store[mark] = self.headers.get_all("traceparent") or []
            if "slow" in self.path:
                time.sleep(0.06)
            body = b"ok\n"
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
    s = S(("127.0.0.1", port), H)
    threading.Thread(target=s.serve_forever, daemon=True).start()


posts = []


class Collector(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", 0)))
        posts.append((self.path, json.loads(body)))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


def spans():
    out = []
    for path, doc in list(posts):
        if path == "/v1/traces":
            for rs in doc["resourceSpans"]:
                for ss in rs["scopeSpans"]:
                    out.extend(ss["spans"])
    return out


def logs():
    out = []
    for path, doc in list(posts):
        if path == "/v1/logs":
            for rl in doc["resourceLogs"]:
                for sl in rl["scopeLogs"]:
                    out.extend(sl["logRecords"])
    return out


def attrs(x):
    return {a["key"]: list(a["value"].values())[0] for a in x["attributes"]}


def span_of(mark):
    return [s for s in spans() if attrs(s).get("url.query") == f"m={mark}"]


def get(port, path, tp=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("GET", path, headers={"traceparent": tp} if tp else {})
    r = c.getresponse()
    r.read()
    c.close()
    return r.status


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-tracing-", dir="/tmp"))
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", tmp / "k.pem", "-out", tmp / "c.pem", "-subj", "/CN=localhost", "-days", "2"],
                   check=True, capture_output=True)
    backend(seen, BACK)
    backend(shadow, SHADOW)
    coll = http.server.ThreadingHTTPServer(("127.0.0.1", COLL), Collector)
    coll.daemon_threads = True
    threading.Thread(target=coll.serve_forever, daemon=True).start()

    def site(port, extra):
        return f"""http 127.0.0.1:{port} {{
    {extra}
    route /bad/* {{ to pool gone }}
    route /copy/* {{ mirror pool shadow 100%; to pool b }}
    route /copydead/* {{ mirror pool gone 100%; to pool b }}
    route /* {{ to pool b }}
}}
"""
    conf = tmp / "okena.conf"
    conf.write_text(f"okena {{ workers 2; io_engine {ENGINE} }}\n"
                    f"pool b {{ server 127.0.0.1:{BACK} }}\npool shadow {{ server 127.0.0.1:{SHADOW} }}\npool gone {{ server 127.0.0.1:1 }}\n"
                    + site(L_ALL, f"tracing otlp://127.0.0.1:{COLL}; access_log otlp://127.0.0.1:{COLL}")
                    + site(L_NONE, f"tracing otlp://127.0.0.1:{COLL} sample=0%")
                    + site(L_OFF, "")
                    + site(L_HALF, f"tracing otlp://127.0.0.1:{COLL} sample=50%")
                    + f"""http 127.0.0.1:{L_TLS} {{
    tls {{ cert {tmp}/c.pem; key {tmp}/k.pem }}
    http2 on
    tracing otlp://127.0.0.1:{COLL}
    route /* {{ to pool b }}
}}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        check("okena starts", until(lambda: _try(lambda: get(L_OFF, "/?m=up") == 200)), log.read_text()[-400:])

        # a new trace: okena's span is the backend's parent; sampled, sent
        get(L_ALL, "/slow?m=a1")
        tps = seen.get("a1", [])
        m = TP.match(tps[0]) if len(tps) == 1 else None
        check("a request with no trace: the backend gets one traceparent, sampled", m is not None and m.group(3) == "01", tps)
        ok = until(lambda: span_of("a1"))
        s = span_of("a1")[0] if ok else {}
        check("  its span is sent to /v1/traces", ok, [x[0] for x in posts])
        if s and m:
            a = attrs(s)
            check("  the backend's parent is that span, in that trace", s["traceId"] == m.group(1) and s["spanId"] == m.group(2)
                  and "parentSpanId" not in s, (s.get("traceId"), s.get("spanId"), m.groups()))
            dur = (int(s["endTimeUnixNano"]) - int(s["startTimeUnixNano"])) / 1e6
            check("  a server span named by its method, as long as the exchange", s["name"] == "GET" and s["kind"] == 2
                  and 55 <= dur < 2000 and abs(int(s["startTimeUnixNano"]) / 1e9 - time.time()) < 30, (s["name"], s["kind"], dur))
            check("  with the exchange's attributes", a.get("http.request.method") == "GET" and a.get("url.path") == "/slow"
                  and a.get("http.response.status_code") == "200" and "status" not in s and "okena.trace_id" not in a, a)
            ok = until(lambda: any(r.get("spanId") == s["spanId"] for r in logs()))
            rec = [r for r in logs() if r.get("spanId") == s["spanId"]]
            check("  and its access log record carries the span's ids", ok and rec[0]["traceId"] == s["traceId"], [r.get("spanId") for r in logs()][-3:])
            res = {x["key"]: x["value"]["stringValue"] for x in [d for p_, d in posts if p_ == "/v1/traces"][0]["resourceSpans"][0]["resource"]["attributes"]}
            check("  the resource: service.name okena", res.get("service.name") == "okena", res)

        # the client's trace goes on: its span is okena's parent
        T, P = "4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7"
        get(L_ALL, "/?m=a2", f"00-{T}-{P}-01")
        tps = seen.get("a2", [])
        m = TP.match(tps[0]) if len(tps) == 1 else None
        check("a client's traceparent: its trace goes on, okena's span between", m is not None and m.group(1) == T and m.group(2) != P
              and m.group(3) == "01", tps)
        ok = until(lambda: span_of("a2"))
        s = span_of("a2")[0] if ok else {}
        check("  the span's parent is the client's", s.get("traceId") == T and s.get("parentSpanId") == P and m and s.get("spanId") == m.group(2), s)

        for i, bad in enumerate(("00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01", "00-" + "0" * 32 + "-00f067aa0ba902b7-01",
                                 f"00-{T}-0000000000000000-01", f"ff-{T}-{P}-01", f"00-{T}-{P}-01-extra", f"00-{T}-{P}", "garbage")):
            get(L_ALL, f"/?m=bad{i}", bad)
        bads = [seen.get(f"bad{i}", ["?"]) for i in range(7)]
        ids = [T.upper(), "0" * 32, T, T, T, T, ""]               # the trace each one names
        check("  one that is not valid: a trace of okena's own instead",
              all(len(t) == 1 and TP.match(t[0]) and TP.match(t[0]).group(1) != i for t, i in zip(bads, ids)), bads)
        get(L_ALL, f"/?m=v1", f"01-{T}-{P}-01-whatever")
        check("  a later version with more fields: taken", (seen.get("v1") or [""])[0].startswith(f"00-{T}-"), seen.get("v1"))

        # a 5xx is an error, a 404 is not
        get(L_ALL, "/bad/x?m=e5")
        check("a 502: the span's status is an error", until(lambda: span_of("e5")) and span_of("e5")[0].get("status") == {"code": 2}, span_of("e5"))

        # sampling: sample=0% keeps no new trace, but the trace is still sent on
        get(L_NONE, "/?m=n1")
        get(L_NONE, "/?m=n2", f"00-{T}-{P}-01")
        get(L_NONE, "/?m=n3", f"00-{T}-{P}-00")
        time.sleep(1.5)
        n1, n2, n3 = (seen.get(k, [""])[0] for k in ("n1", "n2", "n3"))
        check("sample=0%: a new trace not kept, sent on unsampled", n1.endswith("-00") and not span_of("n1"), (n1, span_of("n1")))
        check("  a parent that keeps it: kept (parent-based)", n2.endswith("-01") and n2.startswith(f"00-{T}-") and until(lambda: span_of("n2")), n2)
        check("  a parent that does not: not kept", n3.endswith("-00") and not span_of("n3"), (n3, span_of("n3")))
        for i in range(400):
            get(L_HALF, f"/?m=h{i}")
        kept = sum(seen.get(f"h{i}", [""])[0].endswith("-01") for i in range(400))
        until(lambda: sum(1 for x in spans() if attrs(x).get("url.query", "").startswith("m=h")) == kept, 5)
        sent = sum(1 for x in spans() if attrs(x).get("url.query", "").startswith("m=h"))
        check("sample=50%: about half kept (5 sd), every kept one sent", 150 <= kept <= 250 and sent == kept, (kept, sent))

        # no tracing: the client's traceparent goes through untouched
        get(L_OFF, "/?m=o1", f"00-{T}-{P}-01")
        check("no tracing: the client's traceparent as it was", seen.get("o1") == [f"00-{T}-{P}-01"], seen.get("o1"))

        # a mirror's copy: the same traceparent, one span
        get(L_ALL, "/copy/x?m=c1")
        until(lambda: "c1" in shadow)
        check("a mirror's copy carries the same trace", shadow.get("c1") == seen.get("c1") and len(seen.get("c1", [])) == 1,
              (shadow.get("c1"), seen.get("c1")))
        until(lambda: span_of("c1"))
        time.sleep(1.5)                     # (a copy's would have come by now)
        check("  and sends no span of its own", len(span_of("c1")) == 1, len(span_of("c1")))

        get(L_ALL, "/copydead/x?m=c2")          # a copy that fails: still not a span
        until(lambda: span_of("c2"))
        time.sleep(1.5)
        check("  nor one that fails", len(span_of("c2")) == 1, [x["spanId"] for x in span_of("c2")])

        # HTTP/2 streams
        q = subprocess.run(["timeout", "8", "curl", "-q", "-sk", "--http2", "-o", "/dev/null", "-w", "%{http_version}",
                            f"https://localhost:{L_TLS}/?m=t2"], capture_output=True, text=True)
        tp = seen.get("t2", [""])
        check("over HTTP/2: a trace and its span", q.stdout == "2" and TP.match(tp[0]) and until(lambda: span_of("t2"))
              and span_of("t2")[0]["spanId"] == TP.match(tp[0]).group(2), (q.stdout, tp))
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no process died", "seccomp" not in t and "killed by signal" not in t, t[-400:])

    def bad(what, line):
        g = tmp / "bad.conf"
        g.write_text(f"pool b {{ server 127.0.0.1:1 }}\nhttp 127.0.0.1:1 {{ {line}; route /* {{ to pool b }} }}\n")
        r = subprocess.run([str(BIN), "check", str(g)], capture_output=True, text=True, timeout=10)
        check(f"{what}: refused", r.returncode != 0, r.stderr[-200:])
    bad("tracing to syslog", "tracing syslog://127.0.0.1:514")
    bad("tracing to a file", "tracing /tmp/x")
    bad("a share that is not one", "tracing otlp://127.0.0.1:4318 sample=half")
    bad("a share over 100%", "tracing otlp://127.0.0.1:4318 sample=150%")
    bad("trust= without TLS", f"tracing otlp://127.0.0.1:4318 trust={tmp}/c.pem")
    bad("twice", "tracing otlp://127.0.0.1:4318; tracing otlp://127.0.0.1:4319")
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"tracing {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


def _try(fn):
    try:
        return fn()
    except OSError:
        return False


main()
