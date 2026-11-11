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

import h2.config
import h2.connection
import h2.events

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


state = {"gateways": [], "routes": [], "services": {}, "secrets": {}, "slices": [], "status": 200, "seen": [],
         "classes": {}, "patches": [], "bad_patches": [], "grpcroutes": [], "grants": None}


def grpc_backend(name, ip, port):
    """an HTTP/2 (h2c) server that answers any gRPC call with its name"""
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, port))
    s.listen(16)

    def handle(c):
        conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=False, header_encoding=None))
        conn.initiate_connection()
        c.sendall(conn.data_to_send())
        while True:
            d = c.recv(65536)
            if not d:
                return
            for e in conn.receive_data(d):
                if isinstance(e, h2.events.StreamEnded):
                    conn.send_headers(e.stream_id, [(":status", "200"), ("content-type", "application/grpc"), ("x-back", name)])
                    conn.send_headers(e.stream_id, [("grpc-status", "0")], end_stream=True)
            c.sendall(conn.data_to_send())

    def loop():
        while True:
            c, _ = s.accept()
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()


def grpc_call(path, port=GWH, host="x.test"):
    """a gRPC call over HTTP/2 (prior knowledge): the answer's x-back, or its status"""
    try:
        s = socket.create_connection(("127.0.0.1", port), 3)
        conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True, header_encoding=None))
        conn.initiate_connection()
        conn.send_headers(1, [(":method", "POST"), (":path", path), (":scheme", "http"), (":authority", host),
                              ("content-type", "application/grpc"), ("te", "trailers")])
        conn.send_data(1, b"\0\0\0\0\0", end_stream=True)
        s.sendall(conn.data_to_send())
        heads = {}
        t0 = time.time()
        while time.time() - t0 < 3:
            d = s.recv(65536)
            if not d:
                break
            for e in conn.receive_data(d):
                if isinstance(e, h2.events.ResponseReceived):
                    heads = {k.decode(): v.decode() for k, v in e.headers}
                if isinstance(e, (h2.events.StreamEnded, h2.events.StreamReset)):
                    s.close()
                    return heads.get("x-back") or heads.get(":status")
            s.sendall(conn.data_to_send())
        s.close()
        return heads.get("x-back") or heads.get(":status")
    except OSError as e:
        return repr(e)


def merge(dst, patch):
    """RFC 7386"""
    if not isinstance(patch, dict):
        return patch
    dst = dict(dst) if isinstance(dst, dict) else {}
    for k, v in patch.items():
        if v is None:
            dst.pop(k, None)
        else:
            dst[k] = merge(dst.get(k), v)
    return dst


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
        if u.path.startswith("/apis/gateway.networking.k8s.io/v1/gatewayclasses/"):
            c = state["classes"].get(parts[-1])
            return self.answer(200, c) if c else self.answer(404, {"kind": "Status", "code": 404})
        if u.path == "/apis/gateway.networking.k8s.io/v1/gateways":
            return self.answer(200, {"kind": "GatewayList", "metadata": {"resourceVersion": "1"}, "items": state["gateways"]})
        if u.path == "/apis/gateway.networking.k8s.io/v1/httproutes":
            return self.answer(200, {"kind": "HTTPRouteList", "metadata": {"resourceVersion": "1"}, "items": state["routes"]})
        if u.path == "/apis/gateway.networking.k8s.io/v1/grpcroutes":
            return self.answer(200, {"kind": "GRPCRouteList", "metadata": {"resourceVersion": "1"}, "items": state["grpcroutes"]})
        if u.path == "/apis/gateway.networking.k8s.io/v1beta1/referencegrants":
            if state["grants"] is None:
                return self.answer(404, {"kind": "Status", "code": 404})
            return self.answer(200, {"kind": "ReferenceGrantList", "metadata": {"resourceVersion": "1"}, "items": state["grants"]})
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

    def do_PATCH(self):
        u = urllib.parse.urlparse(self.path)
        raw = self.rfile.read(int(self.headers["Content-Length"]))
        try:
            body = json.loads(raw)
        except ValueError:
            state["bad_patches"].append(raw)
            return self.answer(400, {"kind": "Status", "code": 400})
        state["patches"].append((u.path, self.headers.get("Content-Type"), body))
        parts = u.path.split("/")
        obj = None
        if parts[-1] == "status" and parts[4] == "gatewayclasses":
            obj = state["classes"].get(parts[5])
        elif parts[-1] == "status" and len(parts) == 9:
            ns, kind, name = parts[5], parts[6], parts[7]
            table = state["gateways"] if kind == "gateways" else state["grpcroutes"] if kind == "grpcroutes" else state["routes"]
            obj = next((x for x in table if x["metadata"]["namespace"] == ns and x["metadata"]["name"] == name), None)
        if obj is None:
            return self.answer(404, {"kind": "Status", "code": 404})
        obj["status"] = merge(obj.get("status"), body.get("status"))
        self.answer(200, obj)

    def log_message(self, *a):
        pass


def cond(obj, typ, path=None):
    for c in (obj or {}).get("conditions", []):
        if c["type"] == typ:
            return c["status"], c["reason"]
    return None


def service(ns, name, ports):
    state["services"][(ns, name)] = {"kind": "Service", "metadata": {"namespace": ns, "name": name},
                                     "spec": {"ports": ports}}


def slice_(ns, svc, ips, ports):
    state["slices"].append({"metadata": {"name": svc + "-1", "namespace": ns, "labels": {"kubernetes.io/service-name": svc}},
                            "addressType": "IPv4", "endpoints": [{"addresses": [ip], "conditions": {"ready": True}} for ip in ips],
                            "ports": ports})


def gw(name):
    return next(g for g in state["gateways"] if g["metadata"]["name"] == name)


def gateway(ns, name, listeners, cls="okena"):
    return {"metadata": {"namespace": ns, "name": name, "generation": 3},
            "spec": {"gatewayClassName": cls, "listeners": listeners}}


def route(ns, name, rules, parents=None, hostnames=None):
    spec = {"parentRefs": parents or [{"name": "gw", "namespace": "infra"}], "rules": rules}
    if hostnames:
        spec["hostnames"] = hostnames
    return {"metadata": {"namespace": ns, "name": name, "generation": 2}, "spec": spec}


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
    grpc_backend("grpcb", "127.0.0.8", 50051)
    grpc_backend("grpcc", "127.0.0.9", 50051)
    G = [{"name": "grpc", "port": 50051, "protocol": "TCP"}]
    service("shop", "grpcb", [{"name": "grpc", "port": 50051}])
    slice_("shop", "grpcb", ["127.0.0.8"], G)
    service("shop", "grpcc", [{"name": "grpc", "port": 50051}])
    slice_("shop", "grpcc", ["127.0.0.9"], G)
    backend("far", "127.0.0.10", 8080)
    service("other", "far", [{"name": "http", "port": 80}])
    slice_("other", "far", ["127.0.0.10"], H)
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
        gateway("infra", "own", [{"name": "same", "port": GWH + 10, "protocol": "HTTP"},
                                 {"name": "tcp", "port": GWH + 11, "protocol": "TCP"},
                                 {"name": "nocert", "port": GWH + 12, "protocol": "HTTPS",
                                  "tls": {"certificateRefs": [{"name": "nosuch"}]}}]),
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
            {"matches": [{"path": {"type": "RegularExpression", "value": "/items/[0-9]+"}}], "backendRefs": [ref("v2", 80)]},
            {"matches": [{"path": {"type": "RegularExpression", "value": "/bad(["}}], "backendRefs": [ref("v2", 80)]},
            {"matches": [dict(prefix("/hrx"), headers=[{"type": "RegularExpression", "name": "x-ver", "value": "v[0-9]+"}])],
             "backendRefs": [ref("v2", 80)]},
            {"matches": [prefix("/far")], "backendRefs": [{"name": "far", "namespace": "other", "port": 80}]},
        ]),
        route("shop", "hosted", [{"backendRefs": [ref("v2", 80)]}], hostnames=["shop.test"]),
        route("shop", "secure", [{"backendRefs": [ref("api", 9000)]}], hostnames=["secure.test"],
              parents=[{"name": "gw", "namespace": "infra", "sectionName": "https"},
                       {"name": "gw", "namespace": "infra", "sectionName": "shared"}]),
        route("shop", "not-same", [{"backendRefs": [ref("web", 80)]}], parents=[{"name": "own", "namespace": "infra"}]),
        route("infra", "same", [{"matches": [prefix("/own")], "backendRefs": [ref("web", 80)]}],
              parents=[{"name": "own"}]),
        route("shop", "other-class", [{"backendRefs": [ref("web", 80)]}], parents=[{"name": "theirs", "namespace": "infra"}]),
        route("shop", "no-section", [{"backendRefs": [ref("web", 80)]}], parents=[{"name": "gw", "namespace": "infra", "sectionName": "nope"}]),
        route("shop", "no-host", [{"backendRefs": [ref("web", 80)]}], hostnames=["other.test"],
              parents=[{"name": "gw", "namespace": "infra", "sectionName": "https"}]),
    ]
    state["services"][("infra", "web")] = state["services"][("shop", "web")]
    state["grpcroutes"] = [
        {"metadata": {"namespace": "shop", "name": "echo", "generation": 1},
         "spec": {"parentRefs": [{"name": "gw", "namespace": "infra", "sectionName": "http"}],
                  "rules": [{"matches": [{"method": {"service": "pkg.Echo", "method": "Say"}}], "backendRefs": [ref("grpcb", 50051)]},
                            {"matches": [{"method": {"method": "Health"}}], "backendRefs": [ref("grpcc", 50051)]},
                            {"matches": [{"method": {"service": "pkg.Other"}}], "backendRefs": [ref("grpcc", 50051)]}]}}]
    state["secrets"][("certs", "shared")] = {"kind": "Secret", "type": "kubernetes.io/tls", "data": site}
    gw("gw")["spec"]["listeners"].append({"name": "shared", "port": GWS + 20, "protocol": "HTTPS", "hostname": "secure.test",
                                          "tls": {"certificateRefs": [{"name": "shared", "namespace": "certs"}]},
                                          "allowedRoutes": {"namespaces": {"from": "All"}}})
    state["classes"]["okena"] = {"metadata": {"name": "okena", "generation": 1},
                                 "spec": {"controllerName": "okena.dev/gateway-controller"}}
    hosted = next(r for r in state["routes"] if r["metadata"]["name"] == "hosted")
    hosted["status"] = {"parents": [{"parentRef": {"name": "elsewhere"}, "controllerName": "example.com/other",
                                     "conditions": [{"type": "Accepted", "status": "True", "reason": "Accepted"}]}]}
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
        check("RegularExpression path: matched whole", get("/items/42")[1].startswith("v2 ") and get("/items/42x")[0] == 404,
              (get("/items/42"), get("/items/42x")))
        check("  one okena cannot read: left out, the rest served", "bad([" not in gen and get("/web/x")[0] == 200)
        check("a header by a regular expression", get("/hrx", headers={"x-ver": "v12"})[1].startswith("v2 ")
              and get("/hrx", headers={"x-ver": "vx"})[0] == 404, (get("/hrx", headers={"x-ver": "v12"}), get("/hrx", headers={"x-ver": "vx"})))
        check("a Service of another namespace, no ReferenceGrant: 500", get("/far")[0] == 500, get("/far"))
        check("GRPCRoute: service and method, over HTTP/2 to an h2 pool", grpc_call("/pkg.Echo/Say") == "grpcb", grpc_call("/pkg.Echo/Say"))
        check("  a method of any service", grpc_call("/a.B/Health") == "grpcc", grpc_call("/a.B/Health"))
        check("  every method of a service", grpc_call("/pkg.Other/Anything") == "grpcc", grpc_call("/pkg.Other/Anything"))
        check("  what it does not name: not it", grpc_call("/pkg.Echo/Other") != "grpcb", grpc_call("/pkg.Echo/Other"))
        check("  its pools speak HTTP/2", "protocol h2" in gen and "gw_shop_grpcb_50051_h2" in gen, gen[-600:])
        q = subprocess.run(["curl", "-q", "-sS", "--cacert", str(tmp / "site.crt"), "--resolve", f"secure.test:{GWS + 20}:127.0.0.1",
                            f"https://secure.test:{GWS + 20}/x"], capture_output=True, text=True, timeout=10)
        check("a Secret of another namespace, no ReferenceGrant: not served", q.returncode != 0, q.stdout)
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

        # ReferenceGrants: the backend and the Secret, granted
        state["grants"] = [
            {"metadata": {"namespace": "other", "name": "g1"},
             "spec": {"from": [{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute", "namespace": "shop"}],
                      "to": [{"group": "", "kind": "Service"}]}},
            {"metadata": {"namespace": "certs", "name": "g2"},
             "spec": {"from": [{"group": "gateway.networking.k8s.io", "kind": "Gateway", "namespace": "infra"}],
                      "to": [{"group": "", "kind": "Secret", "name": "shared"}]}}]
        t = until(lambda: get("/far")[1].startswith("far "), 8)
        check("ReferenceGrant: the Service of another namespace served", t is not None, get("/far"))

        def tls_ok():
            q = subprocess.run(["curl", "-q", "-sS", "--cacert", str(tmp / "site.crt"), "--resolve", f"secure.test:{GWS + 20}:127.0.0.1",
                                f"https://secure.test:{GWS + 20}/x"], capture_output=True, text=True, timeout=10)
            return q.stdout.startswith("api ")
        check("  and the Secret of another namespace", until(tls_ok, 8) is not None)

        # the status written back
        def rt(name):
            return next(r for r in state["routes"] if r["metadata"]["name"] == name)

        def listener(g, name):
            return next((l for l in g.get("status", {}).get("listeners", []) if l["name"] == name), {})

        def mine(r):
            return next((p for p in r.get("status", {}).get("parents", []) if p["controllerName"] == "okena.dev/gateway-controller"), {})
        t = until(lambda: "status" in gw("gw") and mine(rt("no-host")))
        g = gw("gw").get("status", {})
        check("the GatewayClass: Accepted", cond(state["classes"]["okena"].get("status"), "Accepted") == ("True", "Accepted"),
              state["classes"]["okena"].get("status"))
        check("a Gateway: Accepted, Programmed, of its generation", cond(g, "Accepted") == ("True", "Accepted")
              and cond(g, "Programmed") == ("True", "Programmed") and g["conditions"][0]["observedGeneration"] == 3
              and g["conditions"][0]["lastTransitionTime"].endswith("Z"), g)
        h = listener(gw("gw"), "http")
        check("  a listener: its routes counted (a GRPCRoute too), Accepted, ResolvedRefs, Programmed", h.get("attachedRoutes") == 3
              and cond(h, "Accepted")[0] == "True" and cond(h, "ResolvedRefs")[0] == "True" and cond(h, "Programmed")[0] == "True", h)
        check("  HTTPS with its certificate: ResolvedRefs", cond(listener(gw("gw"), "https"), "ResolvedRefs") == ("True", "ResolvedRefs"))
        check("  TCP: UnsupportedProtocol", cond(listener(gw("own"), "tcp"), "Accepted") == ("False", "UnsupportedProtocol"),
              listener(gw("own"), "tcp"))
        check("  a Secret that is not there: InvalidCertificateRef, not Programmed",
              cond(listener(gw("own"), "nocert"), "ResolvedRefs") == ("False", "InvalidCertificateRef")
              and cond(listener(gw("own"), "nocert"), "Programmed")[0] == "False", listener(gw("own"), "nocert"))
        check("  another class's Gateway: not touched", "status" not in gw("theirs"))
        m = mine(rt("main"))
        check("a route: Accepted; a Service not there: ResolvedRefs BackendNotFound", cond(m, "Accepted") == ("True", "Accepted")
              and cond(m, "ResolvedRefs") == ("False", "BackendNotFound") and m.get("parentRef") == {"name": "gw", "namespace": "infra"}, m)
        check("  from a namespace not allowed: NotAllowedByListeners", cond(mine(rt("not-same")), "Accepted") == ("False", "NotAllowedByListeners"),
              mine(rt("not-same")))
        check("  a sectionName that is not there: NoMatchingParent", cond(mine(rt("no-section")), "Accepted") == ("False", "NoMatchingParent"))
        check("  no hostname in common: NoMatchingListenerHostname", cond(mine(rt("no-host")), "Accepted") == ("False", "NoMatchingListenerHostname"))
        ps = rt("hosted")["status"]["parents"]
        check("  what another controller wrote is kept", [p["controllerName"] for p in ps] == ["example.com/other", "okena.dev/gateway-controller"], ps)
        g = next(r for r in state["grpcroutes"] if r["metadata"]["name"] == "echo")
        check("a GRPCRoute: its status too", cond(mine(g), "Accepted") == ("True", "Accepted"), g.get("status"))
        check("  as merge patches", all(c == "application/merge-patch+json" for _, c, _ in state["patches"]))
        n = len(state["patches"])
        k = len(state["seen"])
        until(lambda: len(state["seen"]) > k + 6, 5)
        check("  and not again while nothing changes", len(state["patches"]) == n, state["patches"][n:][:2])

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
        state["classes"]["okena"]["spec"]["controllerName"] = "example.com/other"
        t = until(lambda: get("/web/x")[0] == 0, 8)
        check("a GatewayClass of that name that another controller owns: its Gateways not served", t is not None, (t, get("/web/x")))
        state["classes"]["okena"]["spec"]["controllerName"] = "okena.dev/gateway-controller"
        # (the port is still held by the workers draining it: asked again until it is free)
        t = until(lambda: get("/web/x")[0] == 200, 15)
        check("  ours again: served again (once the port is let go)", t is not None,
              (t, [l for l in log.read_text().splitlines() if "listen" in l or "gateway:" in l][-6:]))
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
