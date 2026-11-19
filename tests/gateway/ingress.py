#!/usr/bin/env python3
"""Kubernetes Ingress (`gateway kubernetes ... ingress=CLASS`), on one engine
(argument), against a fake API server over TLS that has no Gateway API at all:
Ingresses of the class served (Prefix, Exact, ImplementationSpecific, hosts,
the default backend, a Service's port by number and by name, HTTPS from the
Secret of spec.tls), the older annotation as the class, Ingresses of another
class or none left out, a path that could only break the file left out, and
changes followed. nginx's annotations (rewrite-target with groups, use-regex,
ssl-redirect by default and forced, backend-protocol HTTPS, permanent-redirect,
app-root, allowlists, proxy-body-size, CORS, affinity, timeouts and limits),
values that do not pass left out; status written back (address=, then
publish_service=)."""
import base64
import http.client
import http.server
import json
import pathlib
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
LST, HTTP, HTTPS, API = 19780, 19781, 19782, 19783
fails = 0
state = {"ingresses": [], "services": {}, "secrets": {}, "slices": [], "patches": 0, "ing_status": {}}


def check(name, ok, detail=""):
    global fails
    print(("ok  " if ok else "FAIL"), name, detail if not ok else "", flush=True)
    fails += 0 if ok else 1


class Back(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        b = f"{self.server.name} {self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


class Tls(Back):
    pass


class Sso(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        ok = self.headers.get("Cookie") == "s=ok"
        self.send_response(200 if ok else 401)
        if ok:
            self.send_header("X-User", "alice")
        else:
            self.send_header("Set-Cookie", "state=1")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, *a):
        pass


def backend(name, ip, port):
    s = S((ip, port), Back)
    s.name = name
    threading.Thread(target=s.serve_forever, daemon=True).start()


class Api(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def answer(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        parts = u.path.split("/")
        if u.path == "/apis/networking.k8s.io/v1/ingresses":
            return self.answer(200, {"kind": "IngressList", "metadata": {"resourceVersion": "1"},
                                     "items": state["ingresses"]})
        if len(parts) == 7 and parts[1:4] == ["api", "v1", "namespaces"]:
            ns, kind, name = parts[4], parts[5], parts[6]
            table = state["services"] if kind == "services" else state["secrets"] if kind == "secrets" else {}
            if (ns, name) in table:
                return self.answer(200, table[(ns, name)])
        if "endpointslices" in u.path:
            ns = parts[5]
            svc = q["labelSelector"][0].split("=", 1)[1]
            items = [x for x in state["slices"] if x["metadata"]["namespace"] == ns
                     and x["metadata"]["labels"]["kubernetes.io/service-name"] == svc]
            return self.answer(200, {"kind": "EndpointSliceList", "metadata": {"resourceVersion": "1"}, "items": items})
        self.answer(404, {"kind": "Status", "code": 404})        # (no Gateway API here)

    def do_PATCH(self):
        state["patches"] += 1
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n)
        parts = self.path.split("/")
        if len(parts) == 9 and parts[1:4] == ["apis", "networking.k8s.io", "v1"] and parts[6] == "ingresses":
            state["ing_status"][(parts[5], parts[7])] = json.loads(body)
            return self.answer(200, {})
        self.answer(404, {"kind": "Status", "code": 404})

    def log_message(self, *a):
        pass


def service(ns, name, ports):
    state["services"][(ns, name)] = {"kind": "Service", "metadata": {"namespace": ns, "name": name},
                                     "spec": {"ports": ports}}


def slice_(ns, svc, ips, ports):
    state["slices"].append({"metadata": {"name": svc + "-1", "namespace": ns,
                                         "labels": {"kubernetes.io/service-name": svc}},
                            "addressType": "IPv4",
                            "endpoints": [{"addresses": [ip], "conditions": {"ready": True}} for ip in ips],
                            "ports": ports})


def svc_backend(name, port=None, port_name=None):
    p = {"number": port} if port else {"name": port_name}
    return {"service": {"name": name, "port": p}}


def ingress(ns, name, rules=None, tls=None, cls="okena", annotation=None, default=None, ann=None):
    meta = {"namespace": ns, "name": name}
    spec = {}
    if cls:
        spec["ingressClassName"] = cls
    if annotation:
        meta["annotations"] = {"kubernetes.io/ingress.class": annotation}
    if ann:
        meta.setdefault("annotations", {}).update({"nginx.ingress.kubernetes.io/" + k: v for k, v in ann.items()})
    if rules is not None:
        spec["rules"] = rules
    if tls:
        spec["tls"] = tls
    if default:
        spec["defaultBackend"] = default
    return {"metadata": meta, "spec": spec}


def path(p, back, typ="Prefix"):
    return {"path": p, "pathType": typ, "backend": back}


def get(port, p, host, tls=False, method="GET", headers=None, body=None, full=False):
    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            c = http.client.HTTPSConnection("127.0.0.1", port, timeout=3, context=ctx)
        else:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        c.request(method, p, body=body, headers={"Host": host, **(headers or {})})
        r = c.getresponse()
        b = r.read().decode()
        c.close()
        return (r.status, b, {k.lower(): v for k, v in r.getheaders()}) if full else (r.status, b)
    except OSError as e:
        return 0, repr(e)


def until(fn, seconds=8):
    t = time.time()
    while time.time() - t < seconds:
        if fn():
            return True
        time.sleep(0.1)
    return False


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
        "-out", d / "site.crt", "-subj", "/CN=shop.test", "-days", "2", "-addext", "subjectAltName=DNS:shop.test")


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-ingress-"))
    certs(tmp)
    tok = tmp / "token"
    tok.write_text("the-token\n")
    H = [{"name": "http", "port": 8080, "protocol": "TCP"}]
    for name, ip in (("web", "127.0.0.2"), ("api", "127.0.0.3"), ("fallback", "127.0.0.4"), ("legacy", "127.0.0.5"),
                     ("other", "127.0.0.6")):
        backend(name, ip, 8080)
        service("shop", name, [{"name": "http", "port": 80, "targetPort": 8080}])
        slice_("shop", name, [ip], H)
    # a backend over TLS (backend-protocol HTTPS)
    sec = S(("127.0.0.7", 8443), Back)
    sec.name = "secure"
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(tmp / "site.crt", tmp / "site.key")
    sec.socket = sctx.wrap_socket(sec.socket, server_side=True)
    threading.Thread(target=sec.serve_forever, daemon=True).start()
    service("shop", "secure", [{"name": "https", "port": 443, "targetPort": 8443}])
    # a Service whose endpoints are in two zones (okena's is z1)
    for name, ip in (("za", "127.0.0.9"), ("zb", "127.0.0.10")):
        backend(name, ip, 8080)
    service("shop", "zoned", [{"name": "http", "port": 80, "targetPort": 8080}])
    state["slices"].append({"metadata": {"name": "zoned-1", "namespace": "shop", "labels": {"kubernetes.io/service-name": "zoned"}},
                            "addressType": "IPv4", "ports": H,
                            "endpoints": [{"addresses": ["127.0.0.9"], "conditions": {"ready": True}, "zone": "z1"},
                                          {"addresses": ["127.0.0.10"], "conditions": {"ready": True}, "zone": "z2"}]})
    sso = S(("127.0.0.8", 8080), Sso)
    threading.Thread(target=sso.serve_forever, daemon=True).start()
    service("auth", "sso", [{"name": "http", "port": 80, "targetPort": 8080}])
    slice_("auth", "sso", ["127.0.0.8"], H)
    slice_("shop", "secure", ["127.0.0.7"], [{"name": "https", "port": 8443, "protocol": "TCP"}])
    state["services"][("ingress", "edge")] = {"kind": "Service", "metadata": {"namespace": "ingress", "name": "edge"},
                                              "spec": {"ports": []},
                                              "status": {"loadBalancer": {"ingress": [{"ip": "198.51.100.9"},
                                                                                      {"hostname": "edge.lb.test"}]}}}
    web = svc_backend("web", port=80)

    def one(name, host, paths, ann=None, tls=None):
        return ingress("shop", name, rules=[{"host": host, "http": {"paths": paths}}], ann=ann, tls=tls)
    site = {"tls.crt": base64.b64encode((tmp / "site.crt").read_bytes()).decode(),
            "tls.key": base64.b64encode((tmp / "site.key").read_bytes()).decode()}
    state["secrets"][("shop", "shop-tls")] = {"kind": "Secret", "type": "kubernetes.io/tls", "data": site}
    state["ingresses"] = [
        ingress("shop", "main", rules=[{"host": "shop.test", "http": {"paths": [
            path("/api", svc_backend("api", port=80)),
            path("/exact", svc_backend("web", port_name="http"), "Exact"),
            path("/", svc_backend("web", port_name="http"), "ImplementationSpecific")]}}],
            tls=[{"hosts": ["shop.test"], "secretName": "shop-tls"}],
            default=svc_backend("fallback", port=80), ann={"ssl-redirect": "false"}),
        ingress("shop", "old", cls=None, annotation="okena",
                rules=[{"host": "legacy.test", "http": {"paths": [path("/", svc_backend("legacy", port=80))]}}]),
        ingress("shop", "theirs", cls="nginx",
                rules=[{"host": "other.test", "http": {"paths": [path("/", svc_backend("other", port=80))]}}]),
        ingress("shop", "nocls", cls=None,
                rules=[{"host": "none.test", "http": {"paths": [path("/", svc_backend("other", port=80))]}}]),
        ingress("shop", "evil", rules=[{"host": "evil.test", "http": {"paths": [
            path('/x"; } route /* { respond 200 "pwned', svc_backend("web", port=80)),
            path("/fine", svc_backend("web", port=80))]}}]),
        one("anno", "anno.test", [path("/svc(/|$)(.*)", web)], ann={"rewrite-target": "/$2"},
            tls=[{"hosts": ["anno.test"], "secretName": "shop-tls"}]),
        one("rx", "rx.test", [path("/v[0-9]+/items", web)], ann={"use-regex": "true"}),
        one("force", "force.test", [path("/", web)], ann={"force-ssl-redirect": "true"}),
        one("tlsback", "tlsback.test", [path("/", svc_backend("secure", port=443))], ann={"backend-protocol": "HTTPS"}),
        one("moved", "moved.test", [path("/", web)], ann={"permanent-redirect": "https://example.com/new",
                                                           "permanent-redirect-code": "308"}),
        one("misc", "misc.test", [path("/", web)], ann={
            "app-root": "/app", "proxy-body-size": "1k", "enable-cors": "true",
            "cors-allow-origin": 'https://a.test, https://evil"x', "proxy-read-timeout": "4", "limit-rps": "1000",
            "affinity": "cookie", "session-cookie-name": "SRV", "session-cookie-max-age": "3600",
            "configuration-snippet": "return 200 pwned;", "denylist-source-range": "10.9.9.9/32"}),
        one("walled", "walled.test", [path("/", web)], ann={"whitelist-source-range": "10.0.0.0/8, 192.0.2.0/24"}),
        # canaries: by header, then cookie, then weight
        one("cmain", "canary.test", [path("/", web)]),
        one("ccan", "canary.test", [path("/", svc_backend("api", port=80))],
            ann={"canary": "true", "canary-by-header": "X-Canary", "canary-by-cookie": "beta", "canary-weight": "0"}),
        one("hmain", "hv.test", [path("/", web)]),
        one("hcan", "hv.test", [path("/", svc_backend("api", port=80))],
            ann={"canary": "true", "canary-by-header": "X-Env", "canary-by-header-value": "beta"}),
        one("pmain", "pat.test", [path("/", web)]),
        one("pcan", "pat.test", [path("/", svc_backend("api", port=80))],
            ann={"canary": "true", "canary-by-header": "X-Env", "canary-by-header-pattern": "^stag"}),
        one("wmain", "weight.test", [path("/", web)]),
        one("wcan", "weight.test", [path("/", svc_backend("api", port=80))],
            ann={"canary": "true", "canary-weight": "5", "canary-weight-total": "10"}),
        one("amain", "all.test", [path("/", web)]),
        one("acan", "all.test", [path("/", svc_backend("api", port=80))], ann={"canary": "true", "canary-weight": "100"}),
        one("lonely", "lonely.test", [path("/", svc_backend("api", port=80))], ann={"canary": "true"}),
        # auth-url
        one("authd", "auth.test", [path("/", web)], ann={
            "auth-url": "http://sso.auth.svc.cluster.local/verify", "auth-response-headers": "X-User, b@d",
            "auth-signin": "https://login.test/start?rd=$scheme://$host$escaped_request_uri"}),
        one("authx", "authx.test", [path("/", web)], ann={"auth-url": "http://127.0.0.8:8080/verify?x=1",
                                                          "auth-cache-key": "$cookie_s", "auth-cache-duration": "200 30s"}),
        one("authns", "authns.test", [path("/", web)], ann={"auth-url": "http://nosuch.auth.svc/verify"}),
        one("authbad", "authbad.test", [path("/", web)], ann={"auth-url": "ftp://sso/verify"}),
        one("zoned", "zoned.test", [path("/", svc_backend("zoned", port=80))]),
        one("bogus", "bogus.test", [path("/", web)], ann={"whitelist-source-range": "bogus, 1.2.3.4/99\"; respond 200",
                                                          "proxy-body-size": "1x"}),
    ]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp / "api.crt", tmp / "api.key")
    srv = S(("127.0.0.1", API), Api)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    gwdir = tmp / "gw"
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{
    drain delay=0s timeout=1s; workers 2; io_engine {ENGINE}; zone z1
    gateway kubernetes dir={gwdir} api=127.0.0.1:{API} ca={tmp}/ca.crt token={tok} ingress=okena http={HTTP} https={HTTPS}
}}
http 127.0.0.1:{LST} {{ route /* {{ respond 404 }} }}
include "{gwdir}/*.conf"
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        ok = until(lambda: get(HTTP, "/api/x", "shop.test")[1].startswith("api "), 12)
        check("an Ingress of the class: its Prefix path to its Service (no Gateway API in the cluster)", ok,
              (get(HTTP, "/api/x", "shop.test"), log.read_text()[-1200:]))
        check("  Prefix /api: /api itself, not /apix", get(HTTP, "/api", "shop.test")[1].startswith("api ")
              and not get(HTTP, "/apix", "shop.test")[1].startswith("api "), (get(HTTP, "/apix", "shop.test")))
        check("Exact /exact, the Service's port by its name", get(HTTP, "/exact", "shop.test")[1].startswith("web ")
              and get(HTTP, "/exact/y", "shop.test")[1].startswith("web /exact/y"), get(HTTP, "/exact", "shop.test"))
        check("ImplementationSpecific / as a prefix", get(HTTP, "/z/q", "shop.test")[1].startswith("web /z/q"))
        check("the default backend for a host no rule names", get(HTTP, "/x", "unknown.test")[1].startswith("fallback "),
              get(HTTP, "/x", "unknown.test"))
        r = get(HTTPS, "/api/s", "shop.test", tls=True)
        check("HTTPS on its port with the Secret of spec.tls", r[0] == 200 and r[1].startswith("api "), r)
        check("the older kubernetes.io/ingress.class annotation", get(HTTP, "/", "legacy.test")[1].startswith("legacy "))
        check("another class, and none: not served",
              not get(HTTP, "/", "other.test")[1].startswith("other ") and not get(HTTP, "/", "none.test")[1].startswith("other "),
              (get(HTTP, "/", "other.test"), get(HTTP, "/", "none.test")))
        gen = (gwdir / "gateway.conf").read_text()
        check("a path that could break the file: left out, its sibling served",
              "pwned" not in gen and get(HTTP, "/fine", "evil.test")[1].startswith("web "), gen[-600:])
        check("no status written for what Ingresses made, without an address", state["patches"] == 0, state["patches"])
        # annotations
        r = get(HTTP, "/svc/a/b?q=1", "anno.test", full=True)
        check("ssl-redirect, by default for a host spec.tls covers: 308 to https", r[0] == 308
              and r[2].get("location") == "https://anno.test/svc/a/b?q=1", r)
        r = get(HTTPS, "/svc/a/b", "anno.test", tls=True)
        check("rewrite-target /$2 with the path's groups", r[0] == 200 and r[1] == "web /a/b", r)
        r = get(HTTPS, "/SVC", "anno.test", tls=True)
        check("  any case, as nginx; /svc alone to /", r[0] == 200 and r[1] == "web /", r)
        check("use-regex: the path an expression, anchored at its start",
              get(HTTP, "/v12/items/3", "rx.test")[1] == "web /v12/items/3" and not get(HTTP, "/vx/items", "rx.test")[1].startswith("web")
              and not get(HTTP, "/a/v1/items", "rx.test")[1].startswith("web"), (get(HTTP, "/v12/items/3", "rx.test"), get(HTTP, "/vx/items", "rx.test")))
        r = get(HTTP, "/x", "force.test", full=True)
        check("force-ssl-redirect, with no TLS", r[0] == 308 and r[2].get("location") == "https://force.test/x", r)
        r = get(HTTP, "/t", "tlsback.test")
        check("backend-protocol HTTPS: to the Service over TLS", r == (200, "secure /t"), r)
        r = get(HTTP, "/a", "moved.test", full=True)
        check("permanent-redirect with its code", r[0] == 308 and r[2].get("location") == "https://example.com/new", r)
        r = get(HTTP, "/", "misc.test", full=True)
        check("app-root: / alone to it", r[0] == 302 and r[2].get("location", "").endswith("/app")
              and get(HTTP, "/app", "misc.test")[1] == "web /app", r)
        check("proxy-body-size 1k: 413 past it", get(HTTP, "/up", "misc.test", method="POST", body=b"x" * 2000)[0] == 413
              and get(HTTP, "/up", "misc.test", method="POST", body=b"x" * 500)[0] in (200, 501), get(HTTP, "/up", "misc.test", method="POST", body=b"x" * 2000))
        r = get(HTTP, "/c", "misc.test", method="OPTIONS", headers={"Origin": "https://a.test", "Access-Control-Request-Method": "PUT"}, full=True)
        check("enable-cors: a preflight answered for an origin let in", r[0] == 204
              and r[2].get("access-control-allow-origin") == "https://a.test" and "PUT" in r[2].get("access-control-allow-methods", ""), r)
        r = get(HTTP, "/c", "misc.test", full=True)
        check("affinity cookie: its cookie, its max age", "SRV=" in r[2].get("set-cookie", "") and r[1] == "web /c", r)
        check("allowlist: a client not in it refused", get(HTTP, "/", "walled.test")[0] == 403, get(HTTP, "/", "walled.test"))
        check("  one with no entry that passes: nobody", get(HTTP, "/", "bogus.test")[0] == 403, get(HTTP, "/", "bogus.test"))
        gen = (gwdir / "gateway.conf").read_text()
        check("timeouts rounded to a step, limits with nginx's burst, a deny list",
              "timeout try=5s" in gen and "limit 1000/s burst=5000 key=client.ip" in gen and "deny 10.9.9.9/32" in gen, gen[-1500:])
        check("what does not pass left out: a snippet, a bad origin, a bad range, a bad size",
              "pwned" not in gen and "https://evil" not in gen and "bogus" not in gen.replace("bogus.test", "") and "1.2.3.4/99" not in gen
              and "body_size 1x" not in gen and "allow 255.255.255.255/32" in gen, gen[-1500:])
        # canaries
        c = lambda host, **h: get(HTTP, "/x", host, headers=h)[1].split(" ")[0]
        check("canary: not without a reason", c("canary.test") == "web", get(HTTP, "/x", "canary.test"))
        check("  by header: always to it, never not, even with its cookie",
              c("canary.test", **{"X-Canary": "always"}) == "api" and c("canary.test", **{"X-Canary": "never", "Cookie": "beta=always"}) == "web",
              (c("canary.test", **{"X-Canary": "always"}), c("canary.test", **{"X-Canary": "never", "Cookie": "beta=always"})))
        check("  by cookie", c("canary.test", Cookie="beta=always") == "api" and c("canary.test", Cookie="beta=never") == "web",
              c("canary.test", Cookie="beta=always"))
        check("  by a header's value", c("hv.test", **{"X-Env": "beta"}) == "api" and c("hv.test", **{"X-Env": "prod"}) == "web")
        check("  by a pattern", c("pat.test", **{"X-Env": "staging"}) == "api" and c("pat.test", **{"X-Env": "prod"}) == "web")
        seen = [c("weight.test") for i in range(60)]
        check("  by weight (of a total)", 10 < seen.count("api") < 50 and seen.count("web") + seen.count("api") == 60,
              (seen.count("api"), seen.count("web")))
        check("  all of the weight: all to it", all(c("all.test") == "api" for i in range(10)))
        check("  a canary alone is not served", c("lonely.test") != "api", c("lonely.test"))
        # zones from EndpointSlices
        z = [get(HTTP, "/", "zoned.test")[1].split(" ")[0] for i in range(20)]
        check("an EndpointSlice's zones: okena's zone's endpoint first", set(z) == {"za"}, z)
        # auth-url
        r = get(HTTP, "/a?b=1", "auth.test", full=True)
        check("auth-url: refused, to auth-signin with nginx's variables as okena's", r[0] == 302 and r[2].get("location")
              == "https://login.test/start?rd=http://auth.test/a%3Fb%3D1" and r[2].get("set-cookie") == "state=1", r)
        r = get(HTTP, "/a", "auth.test", headers={"Cookie": "s=ok"})
        check("  let in by the Service it names", r[0] == 200 and r[1].startswith("web "), r)
        check("  a URL by name, its own pool", get(HTTP, "/a", "authx.test")[0] == 401
              and get(HTTP, "/a", "authx.test", headers={"Cookie": "s=ok"})[0] == 200)
        gen = (gwdir / "gateway.conf").read_text()
        check("  copy= the names that pass, cache= from the duration", "copy=X-User signin=" in gen and "cache=30s" in gen
              and "b@d" not in gen, [x for x in gen.splitlines() if "auth forward" in x])
        check("  a Service that is not there, a URL okena cannot ask: 500, never let in",
              get(HTTP, "/a", "authns.test")[0] == 500 and get(HTTP, "/a", "authbad.test")[0] == 500,
              (get(HTTP, "/a", "authns.test"), get(HTTP, "/a", "authbad.test")))
        # status, once there is an address
        conf.write_text(conf.read_text().replace("ingress=okena", "ingress=okena address=203.0.113.7,lb.okena.test"))
        p.send_signal(1)
        want = {"status": {"loadBalancer": {"ingress": [{"ip": "203.0.113.7"}, {"hostname": "lb.okena.test"}]}}}
        check("address=: each Ingress's status.loadBalancer written",
              until(lambda: state["ing_status"].get(("shop", "main")) == want and state["ing_status"].get(("shop", "misc")) == want, 12),
              state["ing_status"].get(("shop", "main")))
        check("  not those of another class", ("shop", "theirs") not in state["ing_status"])
        state["ing_status"].clear()
        conf.write_text(conf.read_text().replace("address=203.0.113.7,lb.okena.test", "publish_service=ingress/edge"))
        p.send_signal(1)
        want = {"status": {"loadBalancer": {"ingress": [{"ip": "198.51.100.9"}, {"hostname": "edge.lb.test"}]}}}
        check("publish_service=: its load balancer's addresses",
              until(lambda: state["ing_status"].get(("shop", "main")) == want, 12), state["ing_status"].get(("shop", "main")))
        state["ingresses"][0]["spec"]["rules"][0]["http"]["paths"][0]["backend"] = svc_backend("legacy", port=80)
        check("a change followed", until(lambda: get(HTTP, "/api/x", "shop.test")[1].startswith("legacy ")),
              get(HTTP, "/api/x", "shop.test"))
        # the cluster's default class: Ingresses that name none are ours too
        conf.write_text(conf.read_text().replace("https=" + str(HTTPS), "https=" + str(HTTPS) + " ingress_default=on"))
        p.send_signal(1)
        check("ingress_default=on: an Ingress of no class served",
              until(lambda: get(HTTP, "/", "none.test")[1].startswith("other "), 12), get(HTTP, "/", "none.test"))
        check("  one of another class still not", not get(HTTP, "/", "other.test")[1].startswith("other "))
        check("no crash", "killed by signal" not in log.read_text())
    finally:
        p.terminate()
        p.wait(10)
    if fails:
        print(log.read_text()[-3000:])
        g = gwdir / "gateway.conf"
        print(g.read_text()[-3000:] if g.exists() else "(nothing written)")
    print(f"ingress {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
