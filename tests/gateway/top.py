#!/usr/bin/env python3
"""`okena top` and the dashboard, on one engine (argument): the admin
process's own samples give rates that match the traffic; servers up, down
(health) and drained; the metrics address behind its token (Bearer, or
Basic with it as the password) but /live and /ready open; what the
configuration refuses."""
import base64
import http.client
import http.server
import json
import os
import pathlib
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
BASE = 35000 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
LST, TCPL, METRICS, BACK, TLSL, UDPL, ECHO, SLOWL = BASE, BASE + 1, BASE + 2, BASE + 3, BASE + 4, BASE + 5, BASE + 6, BASE + 7
TOKEN = "s3cret-token-of-32-bytes-ok-1234"
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
    def do_GET(self):
        if "slow" in self.path:
            time.sleep(0.05)
        self.send_response(404 if "missing" in self.path else 200)
        self.send_header("Content-Length", "3")
        self.end_headers()
        self.wfile.write(b"ok\n")

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, *a):
        pass


def admin(path, auth=None):
    c = http.client.HTTPConnection("127.0.0.1", METRICS, timeout=5)
    c.request("GET", path, headers={"Authorization": auth} if auth else {})
    r = c.getresponse()
    body = r.read()
    c.close()
    return r.status, dict((k.lower(), v) for k, v in r.getheaders()), body


def status():
    st, _, body = admin("/status", f"Bearer {TOKEN}")
    return json.loads(body) if st == 200 else None


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-top-", dir="/tmp"))
    (tmp / "token").write_text(TOKEN + "\n")
    (tmp / "found.list").write_text(f"127.0.0.1:{BACK}\n")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", tmp / "k.pem",
                    "-out", tmp / "c.pem", "-subj", "/CN=top.test", "-addext", "subjectAltName=DNS:top.test,DNS:www.top.test", "-days", "30"],
                   check=True, capture_output=True)
    threading.Thread(target=S(("127.0.0.1", BACK), H).serve_forever, daemon=True).start()

    def echo():
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.bind(("127.0.0.1", ECHO))
        while True:
            d, a = u.recvfrom(2048)
            u.sendto(d, a)
    threading.Thread(target=echo, daemon=True).start()
    dead = socket.socket()
    dead.bind(("127.0.0.1", 0))
    dport = dead.getsockname()[1]
    dead.close()
    sock = tmp / "admin.sock"
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 2; io_engine {ENGINE}; metrics 127.0.0.1:{METRICS} token={tmp}/token; admin unix:{sock} }}
pool api {{ health tcp every=200ms fall=1 rise=1; server 127.0.0.1:{BACK}; server localhost:{BACK}; server 127.0.0.1:{dport} }}
pool found {{ discover file {tmp}/found.list }}
pool echo {{ server 127.0.0.1:{ECHO} }}
udp 127.0.0.1:{UDPL} {{ to pool echo }}
http 127.0.0.1:{SLOWL} {{ route /* {{ to pool api }} }}
http 127.0.0.1:{LST} {{ route /* {{ to pool api }}; route /f/* {{ to pool found }} }}
tcp 127.0.0.1:{TCPL} {{ to pool api }}
http 127.0.0.1:{TLSL} {{
    tls {{ cert {tmp}/c.pem; key {tmp}/k.pem }}
    http2 on
    http3 retry
    route /old {{ redirect 301 /new }}
    route /api/* GET POST {{ limit 100/s; mirror pool found 10%; to pool api }}
}}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    cli = lambda *a: subprocess.run([str(BIN), *a, "-c", str(conf)], capture_output=True, text=True, timeout=10)
    try:
        check("okena starts", until(lambda: admin("/ready")[0] == 200), log.read_text()[-300:])  # (serving: /live is up before)

        # the token: /live and /ready open, the rest behind it
        check("/live and /ready need no token", admin("/live")[0] == 200 and admin("/ready")[0] == 200)
        st, h, _ = admin("/status")
        check("/status without the token: 401, asking for Basic", st == 401 and h.get("www-authenticate", "").startswith("Basic realm="), (st, h))
        check("  /metrics too", admin("/metrics")[0] == 401 and admin("/dashboard")[0] == 401)
        check("  the token as Bearer: in", admin("/status", f"Bearer {TOKEN}")[0] == 200 and admin("/metrics", f"bearer {TOKEN}")[0] == 200)
        t0 = time.time()
        admin("/status", f"Bearer {TOKEN}")
        check("  answered at once: the head's end is seen, not waited past", time.time() - t0 < 0.5, time.time() - t0)
        basic = lambda u, pw: "Basic " + base64.b64encode(f"{u}:{pw}".encode()).decode()
        check("  as Basic's password (a browser's prompt): in", admin("/status", basic("anyone", TOKEN))[0] == 200)
        wrong = TOKEN[:-1] + ("x" if TOKEN[-1] != "x" else "y")
        check("  a wrong one, of the same length: out", admin("/status", f"Bearer {wrong}")[0] == 401
              and admin("/status", basic("anyone", wrong))[0] == 401 and admin("/status", f"Bearer {TOKEN}x")[0] == 401
              and admin("/status", "Basic !!!")[0] == 401)

        # traffic at a known rate: what the samples say
        stop = time.time() + 4
        sent = [0]

        def load():
            while time.time() < stop:
                c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
                c.request("GET", "/")
                c.getresponse().read()
                c.close()
                sent[0] += 1
                time.sleep(0.02)
        t = threading.Thread(target=load)
        t.start()
        time.sleep(2.5)
        s = status()
        rate = time.time()
        t.join()
        lst = {l["address"]: l for l in s["listeners"]} if s else {}
        hl = lst.get(f"127.0.0.1:{LST}", {})
        expect = sent[0] / 4
        check("a request rate that is the traffic's", s is not None and 0.5 * expect <= hl.get("req_rate", 0) <= 1.5 * expect,
              (hl.get("req_rate"), expect))
        check("  connections a second too (one a request)", abs(hl.get("conn_rate", 0) - hl.get("req_rate", 0)) <= 0.3 * expect + 2, hl)
        time.sleep(1.2)
        s = status()
        hl = {l["address"]: l for l in s["listeners"]}[f"127.0.0.1:{LST}"]
        check("  and the totals: every request counted, kinds named", hl["requests"] == sent[0] and hl["kind"] == "http"
              and len(hl["routes"]) == 2 and {l["address"]: l for l in s["listeners"]}[f"127.0.0.1:{TCPL}"]["kind"] == "tcp", (hl["requests"], sent[0]))
        time.sleep(2.2)
        hl = {l["address"]: l for l in status()["listeners"]}[f"127.0.0.1:{LST}"]
        check("  rates fall back to 0 when it stops", hl["req_rate"] == 0, hl["req_rate"])

        # what it is set up to do: where each listener goes, who uses each pool
        tl = {l["address"]: l for l in s["listeners"]}[f"127.0.0.1:{TCPL}"]
        pools = {pl["name"]: pl for pl in s["pools"]}
        check("where a listener goes: its routes to their pools, an L4 one to its pool",
              [(r["path"], r["pool"]) for r in hl["routes"]] == [("/*", "api"), ("/f/*", "found")] and tl["pool"] == "api"
              and hl["protocols"] == ["http/1.1"] and hl["tls"] is None, (hl["routes"], tl.get("pool")))
        check("  and who uses a pool", sorted((u["listener"], u.get("route")) for u in pools["api"]["used_by"])
              == sorted([(f"127.0.0.1:{LST}", "/*"), (f"127.0.0.1:{TCPL}", None), (f"127.0.0.1:{TLSL}", "/api/*"), (f"127.0.0.1:{SLOWL}", "/*")]), pools["api"]["used_by"])
        check("  a pool's balancing and health check", pools["api"]["balance"] == "least-request"
              and pools["api"]["health"] == {"kind": "tcp", "every_ms": 200, "timeout_ms": pools["api"]["health"]["timeout_ms"], "rise": 1, "fall": 1},
              (pools["api"]["balance"], pools["api"]["health"]))
        sl = {l["address"]: l for l in s["listeners"]}[f"127.0.0.1:{TLSL}"]
        cert = sl["tls"]["certificates"][0] if sl.get("tls") else {}
        check("TLS: its certificate's names, key and days left", cert.get("names") == ["top.test", "www.top.test"] and cert.get("key") == "P-256"
              and cert.get("days_left") in (29, 30) and sl["protocols"] == ["http/1.1", "h2", "h3"] and sl["quic"]["retry"] is True, sl.get("tls"))
        rt = {r["path"]: r for r in sl["routes"]}
        check("  routes: what answers them, what they pass through", rt["/old"]["pool"] is None and rt["/old"]["answer"] == "redirect 301 /new"
              and rt["/api/*"]["methods"] == ["GET", "POST"] and rt["/api/*"]["filters"] == ["limit", "mirror found 10%"], rt)
        check("  a mirror counts as a use", {"listener": f"127.0.0.1:{TLSL}", "route": "/api/*", "as": "mirror"} in pools["found"]["used_by"],
              pools["found"]["used_by"])
        check("  the instance: engine and uptime", s["engine"] == ("epoll" if ENGINE == "epoll" else "io_uring") and s["uptime_s"] >= 1, (s["engine"], s["uptime_s"]))

        # servers: up, down (health), drained (the API)
        until(lambda: any(v["state"] == "down" for v in status()["pools"][0]["servers"]))
        cli("backend", "drain", "api", f"127.0.0.1:{BACK}")
        sv = {v["server"]: v for v in status()["pools"][0]["servers"]}
        check("servers: up, down by health, drained by the API", sv[f"127.0.0.1:{BACK}"]["state"] == "drain"
              and sv[f"localhost:{BACK}"]["state"] == "up" and sv[f"127.0.0.1:{dport}"]["state"] == "down", {k: v["state"] for k, v in sv.items()})
        found = lambda: [v for pl in status()["pools"] if pl["name"] == "found" for v in pl["servers"]]
        check("servers the control process found (a name, discovery): shown, with their address",
              until(lambda: found()) and found()[0].get("address") == "127.0.0.1", found())
        (tmp / "found.list").write_text(f"127.0.0.2:{BACK}\n")     # it moves: /status alone sees it
        check("  and where it is now, not where it was", until(lambda: found() and found()[0].get("address") == "127.0.0.2"), found())
        cli("drain")
        check("the instance drained: said", status()["draining"] is True)
        cli("resume")

        # what the workers count: by protocol, status, handshake, datagram; latency
        took = []
        for i in range(10):                     # (a listener of their own: its latency theirs alone)
            t0 = time.time()
            c = http.client.HTTPConnection("127.0.0.1", SLOWL, timeout=5)
            c.request("GET", "/slow")
            c.getresponse().read()
            c.close()
            took.append((time.time() - t0) * 1000)
        c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
        c.request("GET", "/missing")
        c.getresponse().read()
        c.close()
        h2 = subprocess.run(["timeout", "8", "curl", "-q", "-sk", "--http2", "-o", "/dev/null", "-o", "/dev/null", "-w", "%{http_version} ",
                             f"https://127.0.0.1:{TLSL}/api/x", f"https://127.0.0.1:{TLSL}/api/y"], capture_output=True, text=True)
        tctx = ssl.create_default_context()
        tctx.check_hostname, tctx.verify_mode = False, ssl.CERT_NONE
        tctx.maximum_version = ssl.TLSVersion.TLSv1_3
        sess = None
        for i in range(2):                  # the second resumes the first's session
            raw = socket.create_connection(("127.0.0.1", TLSL), timeout=5)
            t = tctx.wrap_socket(raw, server_hostname="top.test", session=sess)
            t.sendall(b"GET /api/z HTTP/1.1\r\nHost: top.test\r\n\r\n")
            d = b""
            while not d.endswith(b"ok\n"):    # (an EOF with no close_notify makes OpenSSL drop the session)
                x = t.recv(4096)
                if not x:
                    break
                d += x
            sess = t.session
            t.close()
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(2)
        for i in range(12):
            u.sendto(b"ping", ("127.0.0.1", UDPL))
            u.recv(100)
        time.sleep(1.3)
        s = status()
        L = {l["address"]: l for l in s["listeners"]}
        hl, sl, ul = L[f"127.0.0.1:{LST}"], L[f"127.0.0.1:{TLSL}"], L[f"127.0.0.1:{UDPL}"]
        lat = L[f"127.0.0.1:{SLOWL}"].get("latency_ms") or {}
        # (the backend sleeps 50 ms; on a loaded host each request takes some ms
        # more, and okena must say what the client saw: its p50 within a bucket
        # (1/8) of the client's own median, never under the backend's 50 ms)
        mid = sorted(took)[len(took) // 2]
        check("latency: percentiles that are what the client saw (p50 its median within 1/8, p99 under 100)",
              50 <= lat.get("p50", 0) <= max(60, mid * 1.125 + 1) and lat["p50"] <= lat["p90"] <= lat["p99"] < 100,
              (lat, sorted(took)))
        check("  a 404 counted as such, requests by protocol", hl["statuses"]["404"] == 1 and hl["by_protocol"]["http/1.1"] == hl["requests"]
              and sl["by_protocol"]["h2"] == 2 and h2.stdout.split() == ["2", "2"], (hl["statuses"], hl["by_protocol"], sl["by_protocol"], h2.stdout))
        tl = sl.get("tls_handshakes", {})
        check("  TLS handshakes: 1.3, the second resumed", tl.get("1.3", 0) >= 3 and tl.get("resumed") == 1 and tl.get("1.2") == 0, tl)
        check("UDP: datagrams in and out, a flow", ul["datagrams_in"] == 12 and ul["datagrams_out"] == 12 and ul["kind"] == "udp"
              and ul["pool"] == "echo" and ul["responses"] == "any" and s["udp_dropped"] == 0, ul)
        m = admin("/metrics", f"Bearer {TOKEN}")[2].decode()
        cnt = [x for x in m.splitlines() if x.startswith("okena_http_request_duration_seconds_count") and f":{SLOWL}" in x]
        inf = [x for x in m.splitlines() if 'le="+Inf"' in x and f":{SLOWL}" in x]
        b50 = [x for x in m.splitlines() if 'le="0.050000"' in x and f":{SLOWL}" in x]
        check("/metrics: the durations as a histogram, its count the requests'", cnt and int(cnt[0].split()[-1]) == 10
              and inf and inf[0].split()[-1] == "10" and b50 and int(b50[0].split()[-1]) == 0, (cnt, inf, b50))
        check("  and the rest: by protocol, statuses, handshakes, datagrams, drops",
              all(k in m for k in ('okena_http_requests_by_protocol_total{', 'code="404"} 1', 'okena_tls_handshakes_total{', 'result="resumed"} 1',
                                   'okena_udp_datagrams_total{', 'direction="in"} 12', 'okena_udp_dropped_total 0')), m[-600:])

        # okena top, once: the table
        r = cli("top", "once")
        out = r.stdout
        check("okena top once: the table", r.returncode == 0 and "LISTENER" in out and f"127.0.0.1:{LST}" in out and "http" in out
              and "POOL" in out and " drain " in out and " down " in out and "localhost:" in out and "found" in out and "127.0.0.2" in out and "\x1b" not in out, out[-600:])
        check("  rows line up under their heads", all(len(l) <= 90 for l in out.splitlines()), max(len(l) for l in out.splitlines()))
        # and live: it clears the screen and goes on
        q = subprocess.Popen([str(BIN), "top", "-c", str(conf)], stdout=subprocess.PIPE)
        time.sleep(2.5)
        q.terminate()
        live = q.communicate(timeout=5)[0]
        check("okena top: a fresh frame a second", live.count(b"\x1b[H\x1b[2J") >= 2 and live.count(b"LISTENER") >= 2, live[:80])

        # the page
        st, h, body = admin("/dashboard", basic("me", TOKEN))
        check("/dashboard: a page that reads /status", st == 200 and h.get("content-type", "").startswith("text/html")
              and b'fetch("/status"' in body and h.get("cache-control") == "no-store", (st, h))
        check("  / is the page too", admin("/", f"Bearer {TOKEN}")[2] == body)
        check("/status: JSON, never cached", admin("/status", f"Bearer {TOKEN}")[1].get("content-type") == "application/json")
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no process died", "seccomp" not in t and "killed by signal" not in t, t[-300:])

    def bad(what, token):
        (tmp / "t2").write_text(token)
        g = tmp / "bad.conf"
        g.write_text(f"okena {{ metrics 127.0.0.1:1 token={tmp}/t2 }}\npool b {{ server 127.0.0.1:1 }}\nhttp 127.0.0.1:2 {{ route /* {{ to pool b }} }}\n")
        r = subprocess.run([str(BIN), "check", str(g)], capture_output=True, text=True, timeout=10)
        check(f"{what}: refused", r.returncode != 0, r.stderr[-200:])
    bad("a token too short to guard", "short\n")
    bad("a token with a space", "this has a space in it, too long\n")
    bad("an empty file", "")
    g = tmp / "bad.conf"
    g.write_text(f"okena {{ metrics 127.0.0.1:1 token={tmp}/nothing }}\npool b {{ server 127.0.0.1:1 }}\nhttp 127.0.0.1:2 {{ route /* {{ to pool b }} }}\n")
    check("a token file that is not there: refused", subprocess.run([str(BIN), "check", str(g)], capture_output=True).returncode != 0)
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"top {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


main()
