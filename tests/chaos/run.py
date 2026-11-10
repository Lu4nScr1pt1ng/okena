#!/usr/bin/env python3
"""make chaos: okena under steady load while what it depends on fails, one
thing at a time, each put right before the next: a worker killed, a worker
stopped, the control process and the logger killed, a backend killed, a
backend black-holed (it takes the connection and never answers), the JWKS
provider gone, the discovery file made garbage, the access log's disk full,
the local ports run out, the DNS server silent (its names were resolved
before: the servers known stay), and the ACME CA failing in turn, a renewal
asked of it each time (rate-limited, down, answering garbage): the
certificate served is never taken away, TLS clients verified throughout.

It passes when every request got a right answer or a fast, explicit error,
never a hang (a client waits 4 s at most); when each fault, once undone,
leaves nothing behind (the requests after it go well again); and when okena
is still up at the end with no process of it killed by its own filters.

In a namespace of its own (network, mounts, users), so that a tiny tmpfs and
the port range are this test's alone; `tc` (netem: loss and delay) is used
when it is there."""
import base64
import collections
import http.client
import json
import os
import pathlib
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "gateway"))
import acme as A  # noqa: E402  (its test CA)
import datetime  # noqa: E402
import http.server  # noqa: E402
import ssl  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
LST, B1, B2, JWKS, MET, LTLS, CAP = 18080, 18091, 18092, 18093, 18094, 18443, 18095
NAME = "chaos.example.test"
CLIENT_WAIT = 4.0
fails = 0


def inside():
    if os.environ.get("OKENA_CHAOS_NS") == "1":
        return
    env = dict(os.environ, OKENA_CHAOS_NS="1")
    os.execvpe("unshare", ["unshare", "--map-auto", "--map-root-user", "-n", "-m", "sh", "-c",
                           'ip link set lo up && exec "$0" "$@"', sys.executable, "-I", __file__, ENGINE], env)


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


BACKEND = r'''
import http.server, sys
name, port = sys.argv[1], int(sys.argv[2])
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        b = name.encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    def handle_error(self, *a): pass
S(("127.0.0.1", port), H).serve_forever()
'''


dns_up = threading.Event()
dns_up.set()


def dns_server():
    """A records for *.chaos.test: 127.0.0.1, TTL 1 s; silent while down."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 53))
    while True:
        q, peer = s.recvfrom(512)
        if not dns_up.is_set():
            continue
        qid = int.from_bytes(q[:2], "big")
        i = 12
        while q[i]:
            i += 1 + q[i]
        qtype = int.from_bytes(q[i + 1:i + 3], "big")
        question = q[12:i + 5]
        ans = b"\xc0\x0c" + (1).to_bytes(2, "big") + (1).to_bytes(2, "big") + (1).to_bytes(4, "big") + (4).to_bytes(2, "big") \
            + socket.inet_aton("127.0.0.1") if qtype == 1 else b""
        hdr = qid.to_bytes(2, "big") + (0x8180).to_bytes(2, "big") + (1).to_bytes(2, "big") + (1 if ans else 0).to_bytes(2, "big") + b"\0\0\0\0"
        s.sendto(hdr + question + ans, peer)


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def es256():
    """A key, its JWKS, and a token it signed."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    k = ec.generate_private_key(ec.SECP256R1())
    n = k.public_key().public_numbers()
    jwks = {"keys": [{"kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "use": "sig",
                      "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}]}
    head = b64u(json.dumps({"alg": "ES256", "kid": "k1", "typ": "JWT"}).encode())
    body = b64u(json.dumps({"sub": "chaos", "exp": int(time.time()) + 3600}).encode())
    r, s = decode_dss_signature(k.sign(f"{head}.{body}".encode(), ec.ECDSA(hashes.SHA256())))
    return json.dumps(jwks).encode(), f"{head}.{body}.{b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


class Load:
    """Clients asking all the time; every request's outcome, timed."""

    def __init__(self, token, cafile, threads=10):
        self.token, self.cafile, self.stop, self.log = token, cafile, threading.Event(), []
        self.lock = threading.Lock()
        self.threads = [threading.Thread(target=self.run, args=(i,), daemon=True) for i in range(threads)]

    def start(self):
        for t in self.threads:
            t.start()

    def run(self, i):
        if i >= 8:
            return self.run_tls()
        path, hdr = (("/api/x", {"authorization": f"Bearer {self.token}"}), ("/", {}), ("/dns/x", {}))[i % 3]
        # (kept alive, as browsers and SDKs keep theirs: a new connection only
        # after an error, so a fault on okena's side is not one of the client's)
        c = None
        while not self.stop.is_set():
            t0 = time.time()
            try:
                if c is None:
                    c = http.client.HTTPConnection("127.0.0.1", LST, timeout=CLIENT_WAIT)
                c.request("GET", path, headers=hdr)
                r = c.getresponse()
                body = r.read()
                if r.getheader("connection", "").lower() == "close":
                    c.close()
                    c = None
                what = "ok" if r.status == 200 and body in (b"one", b"two") else f"status {r.status}"
            except socket.timeout:
                what = "hang"
                c = None
            except (OSError, http.client.HTTPException) as e:
                what = f"error {type(e).__name__}"
                if c:
                    c.close()
                c = None
            with self.lock:
                self.log.append((t0, time.time() - t0, what))
            time.sleep(0.01)

    def run_tls(self):
        """the ACME name over TLS, verified against the CA, a new handshake each time"""
        ctx = ssl.create_default_context(cafile=self.cafile)
        while not self.stop.is_set():
            t0 = time.time()
            try:
                with socket.create_connection(("127.0.0.1", LTLS), timeout=CLIENT_WAIT) as s:
                    with ctx.wrap_socket(s, server_hostname=NAME) as t:
                        t.sendall(f"GET / HTTP/1.1\r\nHost: {NAME}\r\nConnection: close\r\n\r\n".encode())
                        head = t.recv(100)
                what = "ok" if head.startswith(b"HTTP/1.1 200") else f"tls {head[:12]!r}"
            except socket.timeout:
                what = "hang"
            except ssl.SSLCertVerificationError as e:
                what = f"certificate {e.verify_message}"
            except (OSError, ssl.SSLError) as e:
                what = f"tls error {type(e).__name__}"
            with self.lock:
                self.log.append((t0, time.time() - t0, what))
            time.sleep(0.02)

    def between(self, a, b):
        with self.lock:
            return [x for x in self.log if a <= x[0] < b]


def kids(sup, comm):
    out = []
    for d in pathlib.Path("/proc").iterdir():
        if d.name.isdigit():
            try:
                if (d / "comm").read_text().strip() == comm and f"PPid:\t{sup}\n" in (d / "status").read_text():
                    out.append(int(d.name))
            except OSError:
                pass
    return sorted(out)


def main():
    inside()
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-chaos-", dir="/tmp"))
    disk = tmp / "disk"
    disk.mkdir()
    subprocess.run(["mount", "-t", "tmpfs", "-o", "size=256k", "tmpfs", str(disk)], check=True)
    jwks, token = es256()
    (tmp / "jwks.json").write_bytes(jwks)
    procs = {}

    def backend(name, port):
        procs[name] = subprocess.Popen([sys.executable, "-c", BACKEND, name, str(port)])
    backend("one", B1)
    backend("two", B2)
    procs["jwks"] = subprocess.Popen([sys.executable, "-m", "http.server", str(JWKS), "--bind", "127.0.0.1", "--directory", str(tmp)],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # its own resolver, for this namespace alone
    (tmp / "resolv.conf").write_text("nameserver 127.0.0.1\noptions timeout:1 attempts:1\n")
    subprocess.run(["mount", "--bind", str(tmp / "resolv.conf"), "/etc/resolv.conf"], check=True)
    threading.Thread(target=dns_server, daemon=True).start()
    # the ACME CA (the acme suite's), and a certificate from it two thirds gone:
    # a renewal is asked of it at each start of the acme process
    ca_k, ca_c = A.make_ca()
    (tmp / "ca.pem").write_bytes(ca_c.public_bytes(serialization.Encoding.PEM))
    now = datetime.datetime.now(datetime.timezone.utc)
    sk = ec.generate_private_key(ec.SECP256R1())
    sc = A.issue(ca_k, ca_c, sk.public_key(), ["localhost"], now - datetime.timedelta(days=1), now + datetime.timedelta(days=5))
    (tmp / "srv.pem").write_bytes(sc.public_bytes(serialization.Encoding.PEM))
    (tmp / "srv.key").write_bytes(sk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()))
    ca_st = A.CAState(ca_k, ca_c, CAP)
    ca_st.bad_nonce_once = False
    ca_st.fail_orders = (429, "rateLimited")      # (from the start: the one served stays)
    ca_srv = {}

    def ca_up():
        s = http.server.ThreadingHTTPServer(("127.0.0.1", CAP), A.H)
        s.st = ca_st
        s.daemon_threads = True
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(tmp / "srv.pem", tmp / "srv.key")
        s.socket = sctx.wrap_socket(s.socket, server_side=True)
        threading.Thread(target=s.serve_forever, daemon=True).start()
        ca_srv["s"] = s

    def ca_down():
        ca_srv["s"].shutdown()
        ca_srv["s"].server_close()
    ca_up()
    adir = tmp / "acme" / NAME
    adir.mkdir(parents=True)
    lk = ec.generate_private_key(ec.SECP256R1())
    lc = A.issue(ca_k, ca_c, lk.public_key(), [NAME], now - datetime.timedelta(days=20), now + datetime.timedelta(days=10))
    (adir / "cert.pem").write_bytes(lc.public_bytes(serialization.Encoding.PEM))
    (adir / "key.pem").write_bytes(lk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                    serialization.NoEncryption()))
    servers = tmp / "servers.list"
    servers.write_text(f"127.0.0.1:{B1}\n127.0.0.1:{B2}\n")
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 3; io_engine {ENGINE}; watchdog 2s; drain delay=0s timeout=2s; metrics 127.0.0.1:{MET}
    acme {tmp}/acme ca=https://localhost:{CAP}/dir trust={tmp}/ca.pem }}
pool web {{ health tcp every=300ms fall=2 rise=1; discover file {servers} }}
pool named {{ server api.chaos.test:{B1} }}
http 127.0.0.1:{LST} {{
    access_log {disk}/access.log
    timeout {{ response 1s }}
    route /dns/* {{ to pool named }}
    route /api/* {{ auth jwt {{ jwks http://localhost:{JWKS}/jwks.json refresh=1s }}; to pool web }}
    route /* {{ to pool web }}
}}
http 127.0.0.1:{LTLS} {{
    tls {{ acme {NAME} }}
    route /* {{ to pool web }}
}}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=open(log, "w"))
    load = None
    try:
        def answering():
            c = http.client.HTTPConnection("127.0.0.1", LST, timeout=2)
            c.request("GET", "/api/x", headers={"authorization": f"Bearer {token}"})
            return c.getresponse().status == 200
        if not until(answering, 10):
            check("okena starts and serves, its token taken", False, log.read_text()[-400:])
            return
        check("okena starts and serves, its token taken", True)
        load = Load(token, str(tmp / "ca.pem"))
        load.start()
        time.sleep(1.5)
        windows = []

        def fault(name, do, undo, hold=2.0, settle=1.5):
            t0 = time.time()
            do()
            time.sleep(hold)
            undo()
            t1 = time.time()
            time.sleep(settle)
            windows.append((name, t0, t1, time.time()))

        def kill_one(comm, sig=signal.SIGKILL):
            ks = kids(p.pid, comm)
            if ks:
                os.kill(ks[0], sig)
            return ks[0] if ks else None
        stopped = {}
        fault("a worker killed", lambda: kill_one("okena-worker"), lambda: None)
        fault("a worker stopped (SIGSTOP: its watchdog)", lambda: stopped.update(w=kill_one("okena-worker", signal.SIGSTOP)),
              lambda: None, hold=3.0)
        fault("the control process killed", lambda: kill_one("okena-control"), lambda: None)
        fault("the logger killed", lambda: kill_one("okena-logger"), lambda: None)
        fault("a backend killed", lambda: procs["one"].kill(), lambda: backend("one", B1))
        fault("a backend black-holed (it takes the connection, never answers)",
              lambda: procs["two"].send_signal(signal.SIGSTOP), lambda: procs["two"].send_signal(signal.SIGCONT))
        fault("the JWKS provider gone", lambda: procs["jwks"].kill(), lambda: None)
        fault("the discovery file made garbage", lambda: servers.write_text("not an address at all\n"),
              lambda: servers.write_text(f"127.0.0.1:{B1}\n127.0.0.1:{B2}\n"))
        fault("the access log's disk full",
              lambda: subprocess.run(["dd", "if=/dev/zero", f"of={disk}/filler", "bs=4k", "count=200"], capture_output=True),
              lambda: (disk / "filler").unlink())
        prange = "/proc/sys/net/ipv4/ip_local_port_range"
        old = pathlib.Path(prange).read_text().split()
        fault("the local ports run out (10 of them)", lambda: pathlib.Path(prange).write_text("40000 40009"),
              lambda: pathlib.Path(prange).write_text(f"{old[0]} {old[1]}"))
        fault("the DNS server silent (a name resolved before)", lambda: dns_up.clear(), lambda: dns_up.set(), hold=3.0)
        # the ACME CA failing in turn, a renewal asked each time (a reload starts
        # the acme process again, and the certificate is due)
        fault("the ACME CA rate-limiting (429), a renewal asked",
              lambda: (setattr(ca_st, "fail_orders", (429, "rateLimited")), p.send_signal(signal.SIGHUP)), lambda: None)
        fault("the ACME CA down, a renewal asked", lambda: (ca_down(), p.send_signal(signal.SIGHUP)), ca_up)
        fault("the ACME CA answering garbage, a renewal asked",
              lambda: (setattr(ca_st, "garbage", True), p.send_signal(signal.SIGHUP)), lambda: setattr(ca_st, "garbage", False))
        if shutil.which("tc"):
            fault("loss and delay (netem: 2% lost, 20 ms)",
                  lambda: subprocess.run(["tc", "qdisc", "add", "dev", "lo", "root", "netem", "delay", "20ms", "loss", "2%"]),
                  lambda: subprocess.run(["tc", "qdisc", "del", "dev", "lo", "root"]))
        else:
            print("note: no tc here: loss and delay (netem) not tried", flush=True)
        load.stop.set()
        for t in load.threads:
            t.join(CLIENT_WAIT + 1)

        # never a hang; errors only in a fault's window, and fast; each one undone leaves nothing behind
        allr = load.between(0, time.time() + 1)
        hangs = [x for x in allr if x[2] == "hang"]
        check(f"{len(allr)} requests, none hung ({CLIENT_WAIT:.0f} s)", not hangs and len(allr) > 500, hangs[:5])
        # (a stopped worker holds its requests until its watchdog, 2 s, and a tick, kills it)
        slow_errors = [x for x in allr if x[2] != "ok" and x[1] > 3.5]
        check("  every error fast and explicit (under 3.5 s: the watchdog and a tick)", not slow_errors, slow_errors[:5])
        for name, t0, t1, t2 in windows:
            during = load.between(t0, t1)
            # (a moment to see it: a health check, a tick; and done before the next fault began)
            after = [x for x in load.between(t1 + 0.7, t2) if x[0] + x[1] < t2]
            bad = collections.Counter(x[2] for x in after if x[2] != "ok")
            okd = sum(x[2] == "ok" for x in during)
            check(f"{name}: served through it ({okd} of {len(during)}), and right again after it", after and not bad,
                  (dict(collections.Counter(x[2] for x in during)), dict(bad)))
        st = p.poll()
        check("okena still up", st is None, st)
        check("  its workers all there again (one was killed, one stopped)", until(lambda: len(kids(p.pid, "okena-worker")) == 3, 5),
              kids(p.pid, "okena-worker"))
        check("  and the access log written again once its disk had room", until(lambda: (disk / "access.log").stat().st_size > 0, 3))
        tls = [x for x in allr if x[2] != "ok" and not x[2].startswith(("status", "error"))]
        n_tls = len([x for x in load.log if x[2] == "ok"])
        check("the ACME certificate never taken away: every TLS client verified it", not [x for x in tls if x[2].startswith("certificate")],
              collections.Counter(x[2] for x in tls))
        t = log.read_text()
        check("  each renewal asked and failed, said", t.count(f"acme: {NAME}: the order failed") >= 4
              and any(e[0] == "order refused" for e in ca_st.log), (t.count("the order failed"), n_tls))
    finally:
        if load:
            load.stop.set()
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()
        for q in procs.values():
            try:
                q.send_signal(signal.SIGCONT)
                q.kill()
            except OSError:
                pass
        subprocess.run(["umount", str(disk)], capture_output=True)
        subprocess.run(["umount", "/etc/resolv.conf"], capture_output=True)
    t = log.read_text()
    check("no process of okena died of its own filters", "seccomp" not in t, t[-400:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"chaos {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


main()
