#!/usr/bin/env python3
"""`gateway kubernetes` at scale, on one engine (argument): a fake API server
with 3000 HTTPRoutes, each its own host name, over 600 Services, past the
controller's old tables (1024 routes, 512 pools) and the old 256 discovery
sources. The last route and one in the middle are served by their own
Service; the configuration okena writes is taken whole."""
import os
import pathlib
import sys
import tempfile
import threading
import time
import ssl
import subprocess
import http.server

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
HERE = pathlib.Path(__file__).resolve()
NR, NS = 3000, 600
sys.argv = [sys.argv[0], ENGINE]
# the fake API server, its certificates and helpers are the gwapi suite's
src = (HERE.parent / "gwapi.py").read_text().replace("\nmain()\n", "\n").replace("__file__", repr(str(HERE.parent / "gwapi.py")))
exec(compile(src, "gwapi.py", "exec"))


class Where(http.server.BaseHTTPRequestHandler):
    """Answers with the address it was reached at: which Service."""
    protocol_version = "HTTP/1.0"

    def do_GET(self):
        b = self.connection.getsockname()[0].encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


def scale():
    ip = lambda i: f"127.20.{i // 250}.{i % 250 + 1}"
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-gwscale-", dir="/tmp"))
    certs(tmp)
    tok = tmp / "token"
    tok.write_text("t\n")
    wb = S(("0.0.0.0", 0), Where)
    threading.Thread(target=wb.serve_forever, daemon=True).start()
    port = wb.server_address[1]
    H = [{"name": "http", "port": port, "protocol": "TCP"}]
    for s in range(NS):
        service("shop", f"svc{s}", [{"name": "http", "port": 80, "targetPort": port}])
        slice_("shop", f"svc{s}", [ip(s)], H)
    state["classes"]["okena"] = {"metadata": {"name": "okena", "generation": 1},
                                 "spec": {"controllerName": "okena.dev/gateway-controller"}}
    state["gateways"] = [gateway("infra", "gw", [{"name": "web", "port": GWH, "protocol": "HTTP",
                                                  "allowedRoutes": {"namespaces": {"from": "All"}}}])]
    state["routes"] = [route("shop", f"r{i}", [{"backendRefs": [ref(f"svc{i % NS}", 80)]}], hostnames=[f"r{i}.test"])
                       for i in range(NR)]
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
        t = until(lambda: get("/", host=f"r{NR - 1}.test")[1] == ip((NR - 1) % NS), 60)
        check(f"{NR} HTTPRoutes over {NS} Services: the last served by its own", t is not None,
              (get("/", host=f"r{NR - 1}.test")[:2], log.read_text()[-500:]))
        r = get("/", host=f"r{NR // 2 + 7}.test")
        check("  and one in the middle", r[1] == ip((NR // 2 + 7) % NS), r[:2])
        check("  nothing refused", "needs more than this build holds" not in log.read_text(), log.read_text()[-300:])
    finally:
        p.terminate()
        p.wait(10)
    print(f"gwscale {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"), flush=True)
    sys.exit(1 if fails else 0)


scale()
