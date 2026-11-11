#!/usr/bin/env python3
"""`gateway kubernetes` on one engine (argument), against a fake API server over
TLS: the Gateways of okena's class and the HTTPRoutes attached to them become
okena's configuration, written, then reloaded. Paths (Exact, PathPrefix),
conditions (headers, method, query), hostnames, filters (header modifiers,
redirects, rewrites; one okena cannot do: 500), backends by weight, a Service
missing (500), HTTPS from a Secret; a route from a namespace the listener does
not take, or for another class, left out; what a route's author writes cannot
reach okena's configuration as anything but a value; changes followed, the API
server going wrong changes nothing."""
import base64
import collections
import http.client
import http.server
import json
import pathlib
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
LST, GWH, GWS, API = 18780, 18781, 18782, 18783
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok  " if ok else "FAIL"), name, detail if not ok else "", flush=True)
    fails += 0 if ok else 1


class Back(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    disable_nagle_algorithm = True

    def do_GET(self):
        b = f"{self.server.name} {self.path} {self.headers.get('x-added', '-')}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("x-back", self.server.name)
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, *a):             # (a client gone mid-answer: okena reloading)
        pass


def backend(name, ip, port):
    s = S((ip, port), Back)
    s.name = name
    threading.Thread(target=s.serve_forever, daemon=True).start()


state = {"gateways": [], "routes": [], "services": {}, "secrets": {}, "slices": [], "status": 200, "seen": []}


class Api(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def answer(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        state["seen"].append(self.path)
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        parts = u.path.split("/")
        if state["status"] != 200:
            return self.answer(state["status"], {"kind": "Status", "code": state["status"]})
        if u.path == "/apis/gateway.networking.k8s.io/v1/gateways":
            return self.answer(200, {"kind": "GatewayList", "metadata": {"resourceVersion": "1"}, "items": state["gateways"]})
        if u.path == "/apis/gateway.networking.k8s.io/v1/httproutes":
            return self.answer(200, {"kind": "HTTPRouteList", "metadata": {"resourceVersion": "1"}, "items": state["routes"]})
        if len(parts) == 7 and parts[1:4] == ["api", "v1", "namespaces"]:
            ns, kind, name = parts[4], parts[5], parts[6]
            table = state["services"] if kind == "services" else state["secrets"] if kind == "secrets" else {}
            if (ns, name) in table:
                return self.answer(200, table[(ns, name)])
            return self.answer(404, {"kind": "Status", "code": 404})
        if "endpointslices" in u.path:
            ns = parts[5]
            svc = q["labelSelector"][0].split("=", 1)[1]
            items = [x for x in state["slices"] if x["metadata"]["namespace"] == ns
                     and x["metadata"]["labels"]["kubernetes.io/service-name"] == svc]
            return self.answer(200, {"kind": "EndpointSliceList", "metadata": {"resourceVersion": "1"}, "items": items})
        self.answer(404, {"kind": "Status", "code": 404})

    def log_message(self, *a):
        pass


def service(ns, name, ports):
    state["services"][(ns, name)] = {"kind": "Service", "metadata": {"namespace": ns, "name": name},
                                     "spec": {"ports": ports}}


def slice_(ns, svc, ips, ports):
    state["slices"].append({"metadata": {"name": svc + "-1", "namespace": ns, "labels": {"kubernetes.io/service-name": svc}},
                            "addressType": "IPv4", "endpoints": [{"addresses": [ip], "conditions": {"ready": True}} for ip in ips],
                            "ports": ports})


def gateway(ns, name, listeners, cls="okena"):
    return {"metadata": {"namespace": ns, "name": name}, "spec": {"gatewayClassName": cls, "listeners": listeners}}


def route(ns, name, rules, parents=None, hostnames=None):
    spec = {"parentRefs": parents or [{"name": "gw", "namespace": "infra"}], "rules": rules}
    if hostnames:
        spec["hostnames"] = hostnames
    return {"metadata": {"namespace": ns, "name": name}, "spec": spec}


def ref(name, port, weight=None):
    r = {"name": name, "port": port}
    if weight is not None:
        r["weight"] = weight
    return r


def prefix(p):
    return {"path": {"type": "PathPrefix", "value": p}}


def get(path, port=GWH, host="x.test", headers=None):
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        c.request("GET", path, headers=dict({"Host": host}, **(headers or {})))
        r = c.getresponse()
        b = r.read().decode()
        c.close()
        return r.status, b, {k.lower(): v for k, v in r.getheaders()}
    except OSError as e:
        return 0, repr(e), {}


def until(fn, seconds=6):
    t = time.time()
    while time.time() - t < seconds:
        if fn():
            return time.time() - t
        time.sleep(0.1)
    return None


def certs(d):
    run = lambda *a: subprocess.run(["openssl", *a], check=True, capture_output=True)
    run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", d / "ca.key",
        "-out", d / "ca.crt", "-subj", "/CN=kube-ca", "-days", "2", "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    run("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", d / "api.key",
        "-out", d / "api.csr", "-subj", "/CN=kube-apiserver")
    (d / "ext").write_text("subjectAltName=DNS:kubernetes.default.svc,IP:127.0.0.1\nbasicConstraints=CA:FALSE\n")
    run("x509", "-req", "-in", d / "api.csr", "-CA", d / "ca.crt", "-CAkey", d / "ca.key", "-CAcreateserial",
        "-out", d / "api.crt", "-days", "1", "-extfile", d / "ext")
    run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", d / "site.key",
        "-out", d / "site.crt", "-subj", "/CN=secure.test", "-days", "2", "-addext", "subjectAltName=DNS:secure.test")


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-gwapi-", dir="/tmp"))
    certs(tmp)
    tok = tmp / "token"
    tok.write_text("the-token\n")
    for name, ip, port in (("a", "127.0.0.2", 8080), ("b", "127.0.0.3", 8080), ("api", "127.0.0.4", 9000),
                           ("v2", "127.0.0.5", 8080), ("canary", "127.0.0.6", 8080)):
        backend(name, ip, port)
    H = [{"name": "http", "port": 8080, "protocol": "TCP"}]
    service("shop", "web", [{"name": "http", "port": 80, "targetPort": 8080}])
    slice_("shop", "web", ["127.0.0.2", "127.0.0.3"], H)
    service("shop", "api", [{"port": 9000}])
    slice_("shop", "api", ["127.0.0.4"], [{"port": 9000, "protocol": "TCP", "name": ""}])
    service("shop", "v2", [{"name": "http", "port": 80}])
    slice_("shop", "v2", ["127.0.0.5"], H)
    service("shop", "canary", [{"name": "http", "port": 80}])
    slice_("shop", "canary", ["127.0.0.6"], H)
    site = {"tls.crt": base64.b64encode((tmp / "site.crt").read_bytes()).decode(),
            "tls.key": base64.b64encode((tmp / "site.key").read_bytes()).decode()}
    state["secrets"][("infra", "site")] = {"kind": "Secret", "type": "kubernetes.io/tls", "data": site}
    state["gateways"] = [
        gateway("infra", "gw", [{"name": "http", "port": GWH, "protocol": "HTTP", "allowedRoutes": {"namespaces": {"from": "All"}}},
                                {"name": "https", "port": GWS, "protocol": "HTTPS", "hostname": "secure.test",
                                 "tls": {"mode": "Terminate", "certificateRefs": [{"kind": "Secret", "name": "site"}]},
                                 "allowedRoutes": {"namespaces": {"from": "All"}}}]),
        gateway("infra", "own", [{"name": "same", "port": GWH + 10, "protocol": "HTTP"}]),
        gateway("infra", "theirs", [{"name": "x", "port": GWH + 20, "protocol": "HTTP"}], cls="nginx")]
    state["routes"] = [
        route("shop", "main", [
            {"matches": [prefix("/web")], "backendRefs": [ref("web", 80)]},
            {"matches": [{"path": {"type": "Exact", "value": "/exact"}}], "backendRefs": [ref("api", 9000)]},
            {"matches": [dict(prefix("/hdr"), headers=[{"name": "X-V", "value": "2"}])], "backendRefs": [ref("v2", 80)]},
            {"matches": [prefix("/hdr")], "backendRefs": [ref("web", 80)]},
            {"matches": [dict(prefix("/m"), method="POST")], "backendRefs": [ref("v2", 80)]},
            {"matches": [prefix("/redir")], "filters": [{"type": "RequestRedirect", "requestRedirect": {"scheme": "https", "statusCode": 301}}]},
            {"matches": [prefix("/rw")], "filters": [{"type": "URLRewrite", "urlRewrite": {"path": {"type": "ReplacePrefixMatch", "replacePrefixMatch": "/new"}}}],
             "backendRefs": [ref("v2", 80)]},
            {"matches": [prefix("/split")], "backendRefs": [ref("v2", 80, 1), ref("canary", 80, 3)]},
            {"matches": [prefix("/missing")], "backendRefs": [ref("nosuch", 80)]},
            {"matches": [prefix("/ext")], "filters": [{"type": "ExtensionRef", "extensionRef": {"group": "x", "kind": "Y", "name": "z"}}],
             "backendRefs": [ref("web", 80)]},
            {"matches": [prefix("/hm")], "filters": [{"type": "RequestHeaderModifier", "requestHeaderModifier": {
                "set": [{"name": "X-Added", "value": 'say "hi" \\ $HOME'}, {"name": "Host", "value": "evil"},
                        {"name": "x-file", "value": "${file:/etc/passwd}"}]}},
                {"type": "ResponseHeaderModifier", "responseHeaderModifier": {"remove": ["x-back"]}}],
             "backendRefs": [ref("web", 80)]},
            {"matches": [prefix("/in}jected { respond 200 }")], "backendRefs": [ref("web", 80)]},
        ]),
        route("shop", "hosted", [{"backendRefs": [ref("v2", 80)]}], hostnames=["shop.test"]),
        route("shop", "secure", [{"backendRefs": [ref("api", 9000)]}], hostnames=["secure.test"],
              parents=[{"name": "gw", "namespace": "infra", "sectionName": "https"}]),
        route("shop", "not-same", [{"backendRefs": [ref("web", 80)]}], parents=[{"name": "own", "namespace": "infra"}]),
        route("infra", "same", [{"matches": [prefix("/own")], "backendRefs": [ref("web", 80)]}],
              parents=[{"name": "own"}]),
        route("shop", "other-class", [{"backendRefs": [ref("web", 80)]}], parents=[{"name": "theirs", "namespace": "infra"}]),
    ]
    state["services"][("infra", "web")] = state["services"][("shop", "web")]
    slice_("infra", "web", ["127.0.0.2"], H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(tmp / "api.crt", tmp / "api.key")
    srv = S(("127.0.0.1", API), Api)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    gwdir = tmp / "gw"
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{
    drain delay=0s timeout=1s; workers 2; io_engine {ENGINE}
    gateway kubernetes dir={gwdir} api=127.0.0.1:{API} ca={tmp}/ca.crt token={tok}
}}
http 127.0.0.1:{LST} {{ route /* {{ respond 404 }} }}
include "{gwdir}/*.conf"
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        t = until(lambda: get("/web/x")[0] == 200, 10)
        check("the Gateway's listener comes up, with its routes", t is not None, (get("/web/x"), log.read_text()[-900:]))
        gen = (gwdir / "gateway.conf").read_text() if (gwdir / "gateway.conf").exists() else ""
        # (the pool fills from its EndpointSlices once the reload is done: waited for)
        both = lambda: set(get("/web/x")[1].split()[0] for i in range(20)) == {"a", "b"}
        check("PathPrefix /web: the Service's endpoints, by its port's name", until(both) is not None,
              collections.Counter(get("/web/x")[1].split()[0] for i in range(20)))
        check("  /web itself too, and not /webx", get("/web")[0] == 200 and get("/webx")[0] == 404, (get("/web"), get("/webx")))
        check("Exact /exact, a Service with one port, unnamed", get("/exact")[1].startswith("api ") and get("/exact/x")[0] == 404,
              (get("/exact"), get("/exact/x")))
        check("a header condition first, then the rule without it", get("/hdr/a", headers={"x-v": "2"})[1].startswith("v2 ")
              and get("/hdr/a")[1].split()[0] in ("a", "b"), (get("/hdr/a", headers={"x-v": "2"}), get("/hdr/a")))
        check("a method: POST only; GET: 404", get("/m")[0] == 404, get("/m"))
        r = get("/redir/x?q=1", host="x.test:18781")
        check("RequestRedirect https, 301: to the request's host, the path and query kept", r[0] == 301
              and r[2].get("location") == "https://x.test/redir/x?q=1", r)
        check("URLRewrite ReplacePrefixMatch /new", get("/rw/a/b")[1].split()[1] == "/new/a/b", get("/rw/a/b"))
        n = collections.Counter(get("/split")[1].split()[0] for i in range(200))
        check("weights 1:3", 0.15 <= n["v2"] / 200 <= 0.35 and n["v2"] + n["canary"] == 200, n)
        check("a Service that is not there: 500", get("/missing")[0] == 500, get("/missing"))
        check("a filter okena does not have: 500", get("/ext")[0] == 500, get("/ext"))
        r = get("/hm")
        check("RequestHeaderModifier: the value as it was (quotes, \\, $), Host left alone", r[0] == 200
              and r[1].endswith('say "hi" \\ $HOME'), r)
        check("  ${file:...} in a value: that header left out, nothing read", "passwd" not in gen and "x-file" not in gen and "root:" not in r[1], gen[:0])
        check("  ResponseHeaderModifier remove", "x-back" not in r[2], r[2])
        check("a path that would break out of its line: left out", "injected" not in gen and get("/web/x")[0] == 200, gen[-300:])
        check("hostnames: shop.test gets its own route, others not", get("/", host="shop.test")[1].startswith("v2 ")
              and get("/", host="other.test")[0] == 404, (get("/", host="shop.test"), get("/", host="other.test")))
        check("  and the routes of no hostname under it too", get("/web/x", host="shop.test")[1].split()[0] in ("a", "b"))
        check("a listener of its own namespace only: a route from another left out, its own taken",
              get("/", port=GWH + 10)[0] == 404 and get("/own", port=GWH + 10)[0] == 200,
              (get("/", port=GWH + 10), get("/own", port=GWH + 10)))
        check("a Gateway of another class: not served", get("/", port=GWH + 20)[0] == 0)
        q = subprocess.run(["curl", "-q", "-sS", "--cacert", str(tmp / "site.crt"), "--resolve", f"secure.test:{GWS}:127.0.0.1",
                            f"https://secure.test:{GWS}/x"], capture_output=True, text=True, timeout=10)
        check("HTTPS from a Secret: its certificate, its route", q.stdout.startswith("api "), (q.stdout, q.stderr))
        check("  the Secret's files are the owner's only", oct((gwdir / "certs" / "infra.site.key").stat().st_mode & 0o777) == "0o600")

        # changes are followed
        state["routes"].append(route("shop", "late", [{"matches": [prefix("/late")], "backendRefs": [ref("v2", 80)]}]))
        t = until(lambda: get("/late")[1].startswith("v2 "))
        check("a route added: served", t is not None, (t, get("/late"), log.read_text()[-500:]))
        state["routes"].pop()
        t = until(lambda: get("/late")[0] == 404)
        check("and taken out", t is not None, t)
        before = (gwdir / "gateway.conf").read_text()
        state["status"] = 500
        n = len(state["seen"])
        until(lambda: len(state["seen"]) > n + 3, 6)
        check("the API server going wrong: nothing changes", get("/web/x")[0] == 200 and (gwdir / "gateway.conf").read_text() == before)
        w = "gateway kubernetes: the API server refused"
        until(lambda: w in log.read_text(), 3)      # (the logger writes it)
        state["status"] = 200
        t = log.read_text()
        check("  and it is said once", t.count(w) == 1, [l for l in t.splitlines() if "gateway k" in l][-8:])
        check("asked with the token, from okena's cache (resourceVersion=0)",
              any(s == "/apis/gateway.networking.k8s.io/v1/httproutes?resourceVersion=0" for s in state["seen"]))
    finally:
        p.terminate()
        p.wait(10)
    text = log.read_text()
    check("no process died", "killed" not in text and "seccomp" not in text and "exited" not in text, text[-500:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"gwapi {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"), flush=True)
    sys.exit(1 if fails else 0)


main()
