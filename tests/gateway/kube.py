#!/usr/bin/env python3
"""`discover kubernetes` on one engine (argument), against a fake API server
over TLS 1.3 (an EC and an RSA CA, as kubeadm makes): ready endpoints by the
port's name, terminating ones when nothing is ready, the token as rotated,
and nothing believed from a server that is not the one it should be."""
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
LST, RSA, BADCA, BADNAME, NUM = 18720, 18721, 18722, 18723, 18724
API_EC, API_RSA = 18730, 18731
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok  " if ok else "FAIL"), name, detail if not ok else "", flush=True)
    fails += 0 if ok else 1


class Back(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    disable_nagle_algorithm = True

    def do_GET(self):
        b = self.server.name.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True


def backend(name, ip, port):
    s = S((ip, port), Back)
    s.name = name
    threading.Thread(target=s.serve_forever, daemon=True).start()


def ep(ip, ready=True, serving=None, terminating=None):
    c = {"ready": ready}
    if serving is not None:
        c["serving"] = serving
    if terminating is not None:
        c["terminating"] = terminating
    return {"addresses": [ip], "conditions": c, "nodeName": "node-1", "targetRef": {"kind": "Pod", "name": f"pod-{ip}"}}


state = {"slices": [], "status": 200, "seen": []}


class Api(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self):
        state["seen"].append((self.path, self.headers.get("Authorization")))
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        if state["status"] != 200:
            self.send_response(state["status"])
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"kind":"Status","status":"Failure","reason":"Forbidden","code":403}')
            return
        ns = u.path.split("/")[5]
        svc = q["labelSelector"][0].split("=", 1)[1]
        items = [x for x in state["slices"] if x["metadata"]["namespace"] == ns and x["metadata"]["labels"]["kubernetes.io/service-name"] == svc]
        body = json.dumps({"kind": "EndpointSliceList", "apiVersion": "discovery.k8s.io/v1",
                           "metadata": {"resourceVersion": "12345"}, "items": items}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def slice_(name, svc, endpoints, ports, ns="shop", kind="IPv4"):
    return {"metadata": {"name": name, "namespace": ns, "labels": {"kubernetes.io/service-name": svc}},
            "addressType": kind, "endpoints": endpoints, "ports": ports}


def certs(d, kind):
    """A CA and a certificate for kubernetes.default.svc (and 127.0.0.1)."""
    key = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"] if kind == "ec" else ["-newkey", "rsa:2048"]
    run = lambda *a: subprocess.run(["openssl", *a], check=True, capture_output=True)
    run("req", "-x509", *key, "-nodes", "-keyout", d / f"{kind}-ca.key", "-out", d / f"{kind}-ca.crt",
        "-subj", f"/CN={kind}-kubernetes-ca", "-days", "2", "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    run("req", "-new", *key, "-nodes", "-keyout", d / f"{kind}.key", "-out", d / f"{kind}.csr", "-subj", "/CN=kube-apiserver")
    (d / "ext").write_text("subjectAltName=DNS:kubernetes,DNS:kubernetes.default,DNS:kubernetes.default.svc,IP:127.0.0.1\n"
                           "basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n")
    run("x509", "-req", "-in", d / f"{kind}.csr", "-CA", d / f"{kind}-ca.crt", "-CAkey", d / f"{kind}-ca.key",
        "-CAcreateserial", "-out", d / f"{kind}.crt", "-days", "1", "-extfile", d / "ext")


def api(d, kind, port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(d / f"{kind}.crt", d / f"{kind}.key")
    s = S(("127.0.0.1", port), Api)
    s.socket = ctx.wrap_socket(s.socket, server_side=True)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s


def get(port=LST):
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        c.request("GET", "/")
        r = c.getresponse()
        b = r.read().decode()
        c.close()
        return r.status, b
    except OSError as e:
        return 0, repr(e)


def spread(n=30, port=LST):
    return collections.Counter(get(port)[1] for i in range(n))


def until(fn, seconds=5):
    t = time.time()
    while time.time() - t < seconds:
        if fn():
            return time.time() - t
        time.sleep(0.1)
    return None


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-kube-", dir="/tmp"))
    certs(tmp, "ec")
    certs(tmp, "rsa")
    (tmp / "o").mkdir()
    certs(tmp / "o", "ec")                      # a CA that is not the API server's
    tok = tmp / "token"
    tok.write_text("first-token\n")
    for name, ip in (("a", "127.0.0.2"), ("b", "127.0.0.3"), ("c", "127.0.0.4"), ("t", "127.0.0.5"), ("u", "127.0.0.6")):
        backend(name, ip, 8080)
        backend(name + "-metrics", ip, 9090)
    P = [{"name": "metrics", "port": 9090, "protocol": "TCP"}, {"name": "http", "port": 8080, "protocol": "TCP"}]
    state["slices"] = [slice_("web-1", "web", [ep("127.0.0.2"), ep("127.0.0.3", ready=False)], P),
                       slice_("web-2", "web", [ep("127.0.0.4")], P),
                       slice_("other-1", "other", [ep("127.0.0.6")], P),
                       slice_("web-x", "web", [ep("127.0.0.6")], P, ns="elsewhere")]
    sa = api(tmp, "ec", API_EC)
    sr = api(tmp, "rsa", API_RSA)
    common = f"token={tok}"
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ drain delay=0s timeout=1s; workers 2; io_engine {ENGINE} }}
pool web {{ balance round-robin; discover kubernetes service=shop/web port=http api=127.0.0.1:{API_EC} ca={tmp}/ec-ca.crt {common} }}
pool rsa {{ discover kubernetes service=shop/web port=http api=127.0.0.1:{API_RSA} ca={tmp}/rsa-ca.crt {common} }}
pool badca {{ discover kubernetes service=shop/web port=http api=127.0.0.1:{API_EC} ca={tmp}/o/ec-ca.crt {common} }}
pool badname {{ discover kubernetes service=shop/web port=http api=127.0.0.1:{API_EC} ca={tmp}/ec-ca.crt name=api.example.com {common} }}
pool num {{ discover kubernetes service=shop/web port=9090 api=127.0.0.1:{API_EC} ca={tmp}/ec-ca.crt {common} }}
http 127.0.0.1:{LST} {{ route /* {{ to pool web }} }}
http 127.0.0.1:{RSA} {{ route /* {{ to pool rsa }} }}
http 127.0.0.1:{BADCA} {{ route /* {{ to pool badca }} }}
http 127.0.0.1:{BADNAME} {{ route /* {{ to pool badname }} }}
http 127.0.0.1:{NUM} {{ route /* {{ to pool num }} }}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for i in range(100):
            if get()[0]:
                break
            time.sleep(0.05)
        # (under load a backend can be ejected for a moment by a slow connect:
        # each set is waited for, not taken from one sample)
        def seen(port, want):
            return until(lambda: set(spread(20, port)) == want, 6) is not None
        check("the ready endpoints of the service, every slice, on the port named http", seen(LST, {"a", "c"}), (spread(), log.read_text()[-400:]))
        check("  asked as the API wants it, with the token", any("/apis/discovery.k8s.io/v1/namespaces/shop/endpointslices?labelSelector=kubernetes.io%2Fservice-name%3Dweb&resourceVersion=0" in s and a == "Bearer first-token"
                                                                for s, a in state["seen"]), state["seen"][:2])
        check("an RSA CA and server, as kubeadm makes them: the same", seen(RSA, {"a", "c"}), (spread(port=RSA), log.read_text()[-600:]))
        check("port=9090: that number", seen(NUM, {"a-metrics", "c-metrics"}), spread(port=NUM))
        check("a CA that did not sign the server: nothing believed", all(x[0] == 502 for x in (get(BADCA) for i in range(5))))
        check("a name the certificate does not have: nothing believed", all(x[0] == 502 for x in (get(BADNAME) for i in range(5))))
        t = log.read_text()
        check("  and it says why, once", t.count("not who it should be") == 2, t[-400:])

        state["slices"][0]["endpoints"][1]["conditions"]["ready"] = True
        t = until(lambda: "b" in spread(20))
        check("a pod becomes ready: served", t is not None and t < 3, (t, p.poll(), log.read_text()[-700:]))

        # a rollout: none ready, those terminating that still serve take it
        state["slices"] = [slice_("web-1", "web", [ep("127.0.0.2", ready=False, serving=False, terminating=True),
                                                   ep("127.0.0.5", ready=False, serving=True, terminating=True)], P)]
        t = until(lambda: set(spread(20)) == {"t"})
        check("nothing ready: the terminating one that still serves", t is not None, (t, spread(20)))
        state["slices"] = [slice_("web-1", "web", [ep("127.0.0.5", ready=False, serving=True, terminating=True), ep("127.0.0.6")], P)]
        t = until(lambda: set(spread(20)) == {"u"})
        check("  and once one is ready, only it", t is not None, (t, spread(20)))

        # the token, rotated
        tok.write_text("second-token\n")
        t = until(lambda: state["seen"][-1][1] == "Bearer second-token")
        check("a rotated token is the one sent", t is not None, state["seen"][-1])

        # what goes wrong keeps the servers
        good = spread(20)
        state["status"] = 403
        time.sleep(2.2)
        check("403: the servers stay", set(spread(20)) == set(good), spread(20))
        state["status"] = 200
        sa.shutdown()
        sa.server_close()
        time.sleep(2.2)
        check("the API server gone: the servers stay", set(spread(20)) == set(good), spread(20))
        t = log.read_text()
        w = "discover kubernetes shop/web: "
        check("  each said once", t.count(w + "the API server refused") >= 1 and t.count(w + "no answer from the API server") >= 1, t[-500:])
    finally:
        p.terminate()
        p.wait(10)
    text = log.read_text()
    check("no process died", "killed" not in text and "seccomp" not in text and "control process exited" not in text, text[-300:])

    def bad(what, line):
        g = tmp / "bad.conf"
        g.write_text(f"pool p {{ {line} }}\nhttp 127.0.0.1:1 {{ route /* {{ to pool p }} }}\n")
        r = subprocess.run([str(BIN), "check", str(g)], capture_output=True, text=True, timeout=10, env={"PATH": "/usr/bin"})
        check(f"{what}: refused", r.returncode != 0, r.stderr[-200:])
    bad("no service", f"discover kubernetes api=127.0.0.1:1 ca={tmp}/ec-ca.crt")
    bad("a service with no namespace", f"discover kubernetes service=web api=127.0.0.1:1 ca={tmp}/ec-ca.crt")
    bad("upper case in it", f"discover kubernetes service=Shop/web api=127.0.0.1:1 ca={tmp}/ec-ca.crt")
    bad("no API and not in a pod", f"discover kubernetes service=shop/web ca={tmp}/ec-ca.crt")
    bad("a CA that is no certificate", f"discover kubernetes service=shop/web api=127.0.0.1:1 ca={tok}")
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"kube {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"), flush=True)
    sys.exit(1 if fails else 0)


main()
