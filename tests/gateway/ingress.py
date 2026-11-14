#!/usr/bin/env python3
"""Kubernetes Ingress (`gateway kubernetes ... ingress=CLASS`), on one engine
(argument), against a fake API server over TLS that has no Gateway API at all:
Ingresses of the class served (Prefix, Exact, ImplementationSpecific, hosts,
the default backend, a Service's port by number and by name, HTTPS from the
Secret of spec.tls), the older annotation as the class, Ingresses of another
class or none left out, a path that could only break the file left out, and
changes followed."""
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
state = {"ingresses": [], "services": {}, "secrets": {}, "slices": [], "patches": 0}


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


def ingress(ns, name, rules=None, tls=None, cls="okena", annotation=None, default=None):
    meta = {"namespace": ns, "name": name}
    spec = {}
    if cls:
        spec["ingressClassName"] = cls
    if annotation:
        meta["annotations"] = {"kubernetes.io/ingress.class": annotation}
    if rules is not None:
        spec["rules"] = rules
    if tls:
        spec["tls"] = tls
    if default:
        spec["defaultBackend"] = default
    return {"metadata": meta, "spec": spec}


def path(p, back, typ="Prefix"):
    return {"path": p, "pathType": typ, "backend": back}


def get(port, p, host, tls=False):
    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            c = http.client.HTTPSConnection("127.0.0.1", port, timeout=3, context=ctx)
        else:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        c.request("GET", p, headers={"Host": host})
        r = c.getresponse()
        b = r.read().decode()
        c.close()
        return r.status, b
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
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-ingress-", dir="/tmp"))
    certs(tmp)
    tok = tmp / "token"
    tok.write_text("the-token\n")
    H = [{"name": "http", "port": 8080, "protocol": "TCP"}]
    for name, ip in (("web", "127.0.0.2"), ("api", "127.0.0.3"), ("fallback", "127.0.0.4"), ("legacy", "127.0.0.5"),
                     ("other", "127.0.0.6")):
        backend(name, ip, 8080)
        service("shop", name, [{"name": "http", "port": 80, "targetPort": 8080}])
        slice_("shop", name, [ip], H)
    site = {"tls.crt": base64.b64encode((tmp / "site.crt").read_bytes()).decode(),
            "tls.key": base64.b64encode((tmp / "site.key").read_bytes()).decode()}
    state["secrets"][("shop", "shop-tls")] = {"kind": "Secret", "type": "kubernetes.io/tls", "data": site}
    state["ingresses"] = [
        ingress("shop", "main", rules=[{"host": "shop.test", "http": {"paths": [
            path("/api", svc_backend("api", port=80)),
            path("/exact", svc_backend("web", port_name="http"), "Exact"),
            path("/", svc_backend("web", port_name="http"), "ImplementationSpecific")]}}],
            tls=[{"hosts": ["shop.test"], "secretName": "shop-tls"}],
            default=svc_backend("fallback", port=80)),
        ingress("shop", "old", cls=None, annotation="okena",
                rules=[{"host": "legacy.test", "http": {"paths": [path("/", svc_backend("legacy", port=80))]}}]),
        ingress("shop", "theirs", cls="nginx",
                rules=[{"host": "other.test", "http": {"paths": [path("/", svc_backend("other", port=80))]}}]),
        ingress("shop", "nocls", cls=None,
                rules=[{"host": "none.test", "http": {"paths": [path("/", svc_backend("other", port=80))]}}]),
        ingress("shop", "evil", rules=[{"host": "evil.test", "http": {"paths": [
            path('/x"; } route /* { respond 200 "pwned', svc_backend("web", port=80)),
            path("/fine", svc_backend("web", port=80))]}}]),
    ]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp / "api.crt", tmp / "api.key")
    srv = S(("127.0.0.1", API), Api)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    gwdir = tmp / "gw"
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{
    drain delay=0s timeout=1s; workers 2; io_engine {ENGINE}
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
        check("no status written for what Ingresses made", state["patches"] == 0, state["patches"])
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
