#!/usr/bin/env python3
"""HTTPS end to end on one engine (argument): okena terminates TLS 1.3 on
an http listener, hands the connection to kTLS and proxies plaintext to a
backend. Checks requests, keep-alive, large bodies both ways, a request
sent in the same segment as the client Finished, many clients at once,
curl, the header timeout over a stalled handshake, and the refusals."""
import atexit
import hashlib
import json
import os
import pathlib
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
USER = len(sys.argv) > 2 and sys.argv[2] == "user"   # records sealed in user space, not kTLS
BASE = 27000 + os.getpid() % 99 * 20 + (5 if ENGINE == "epoll" else 0) + (10 if USER else 0)
BACK, LST, ECHO, TLST = BASE, BASE + 1, BASE + 2, BASE + 3
tmp = pathlib.Path(tempfile.mkdtemp())
atexit.register(shutil.rmtree, tmp, True)
failures = 0


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name + (f": {detail}" if detail and not ok else ""))
    failures += not ok


def have_ktls():
    s = socket.socket()
    try:
        s.setsockopt(socket.IPPROTO_TCP, 31, b"tls")
    except OSError as e:
        return e.errno != 2
    finally:
        s.close()
    return True


def sh(*args):
    subprocess.run(args, check=True, capture_output=True, cwd=tmp)


sh("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", "ca.key")
sh("openssl", "req", "-new", "-x509", "-key", "ca.key", "-subj", "/CN=okena test ca", "-days", "2",
   "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", "ca.pem")
sh("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", "leaf.key")
sh("openssl", "req", "-new", "-key", "leaf.key", "-subj", "/CN=okena.test", "-out", "leaf.csr")
(tmp / "ext").write_text("subjectAltName=DNS:okena.test\nkeyUsage=critical,digitalSignature\n"
                         "extendedKeyUsage=serverAuth\nauthorityKeyIdentifier=keyid\n")
sh("openssl", "x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
   "-days", "2", "-extfile", "ext", "-out", "leaf.pem")
(tmp / "chain.pem").write_text((tmp / "leaf.pem").read_text() + (tmp / "ca.pem").read_text())


# ------------------------------------------------------------ backend
def backend():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", BACK))
    srv.listen(256)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()


def serve(c):
    f = c.makefile("rb")
    try:
        while True:
            start = f.readline()
            if not start:
                return
            fields = {}
            while True:
                line = f.readline()
                if line in (b"\r\n", b""):
                    break
                k, _, v = line.decode("latin1").partition(":")
                fields[k.strip().lower()] = v.strip()
            body = f.read(int(fields.get("content-length", 0)))
            method, target, _ = start.decode().split(" ", 2)
            if target.startswith("/big/"):
                n = int(target[5:])
                out = (b"0123456789abcdef" * (n // 16 + 1))[:n]
            else:
                out = json.dumps({"method": method, "target": target, "xfp": fields.get("x-forwarded-proto"),
                                  "len": len(body), "sha": hashlib.sha256(body).hexdigest()}).encode()
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(out) + out)
    except OSError:
        pass
    finally:
        c.close()


def echo_backend():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", ECHO))
    srv.listen(64)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=echo_serve, args=(c,), daemon=True).start()


def echo_serve(c):
    try:
        while True:
            data = c.recv(1 << 16)
            if not data:
                break
            c.sendall(data)
    except OSError:
        pass
    finally:
        c.close()


def read_response(t):
    f = t.makefile("rb")
    start = f.readline()
    fields = {}
    while True:
        line = f.readline()
        if line in (b"\r\n", b""):
            break
        k, _, v = line.decode("latin1").partition(":")
        fields[k.strip().lower()] = v.strip()
    body = f.read(int(fields.get("content-length", 0)))
    return start, body


def context(alpn=("h2", "http/1.1")):
    ctx = ssl.create_default_context(cafile=str(tmp / "ca.pem"))
    if alpn:
        ctx.set_alpn_protocols(list(alpn))
    return ctx


def connect(ctx=None):
    s = socket.create_connection(("127.0.0.1", LST), timeout=10)
    return (ctx or context()).wrap_socket(s, server_hostname="okena.test")


def request(t, method, target, body=b""):
    t.sendall(f"{method} {target} HTTP/1.1\r\nHost: okena.test\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)
    return read_response(t)


def main():
    if not USER and not have_ktls():
        print("skip https with kTLS: the tls module is not loaded (sudo modprobe tls)")
        return 0
    threading.Thread(target=backend, daemon=True).start()
    threading.Thread(target=echo_backend, daemon=True).start()
    tls = f"tls {{ cert {tmp / 'chain.pem'}; key {tmp / 'leaf.key'} }}"
    tcp = f"tcp 127.0.0.1:{TLST} {{\n    {tls}\n    to 127.0.0.1:{ECHO}\n}}\n"
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 2; io_engine {ENGINE} }}
http 127.0.0.1:{LST} {{
    {tls}
    timeout {{ header 1s }}
    route /* {{ to 127.0.0.1:{BACK} }}
}}
""" + ("" if USER else tcp))
    log = open(tmp / "okena.log", "w+")
    env = dict(os.environ, OKENA_KTLS="off") if USER else None
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=log, env=env)
    atexit.register(p.kill)
    for _ in range(100):
        log.seek(0)
        if "started with" in log.read():
            break
        time.sleep(0.05)

    with connect() as t:
        start, body = request(t, "GET", "/hello")
        info = json.loads(body)
        check("GET over TLS 1.3: 200 from the backend", start.startswith(b"HTTP/1.1 200") and info["target"] == "/hello",
              start)
        check("ALPN http/1.1, TLS_AES_128_GCM_SHA256", (t.selected_alpn_protocol(), t.cipher()[0])
              == ("http/1.1", "TLS_AES_128_GCM_SHA256"), str((t.selected_alpn_protocol(), t.cipher())))
        check("the backend is told X-Forwarded-Proto: https", info["xfp"] == "https", info["xfp"])
        if shutil.which("ss"):
            ss = subprocess.run(["ss", "-tni", f"( sport = :{LST} )"], capture_output=True, text=True).stdout
            ulp = "tcp-ulp-tls" in ss
            check("records sealed in user space (no kTLS on the socket)" if USER else
                  "the kernel has the connection (kTLS on the socket)", ulp != USER, ss[-200:])
        ok = all(json.loads(request(t, "GET", f"/n/{i}")[1])["target"] == f"/n/{i}" for i in range(20))
        check("20 more requests on the same connection", ok)
        body = os.urandom(2 << 20)
        info = json.loads(request(t, "POST", "/upload", body)[1])
        check("a 2 MiB request body reaches the backend intact",
              info["len"] == len(body) and info["sha"] == hashlib.sha256(body).hexdigest(), str(info))
        n = 8 << 20
        start, got = request(t, "GET", f"/big/{n}")
        check("an 8 MiB response arrives intact", got == (b"0123456789abcdef" * (n // 16 + 1))[:n], f"{len(got)}")

    # session tickets: resumed, on whichever worker takes the connection
    def resumed_get(sess, target):
        s = socket.create_connection(("127.0.0.1", LST), timeout=10)
        with context().wrap_socket(s, server_hostname="okena.test", session=sess) as t:
            start, body = request(t, "GET", target)
            return t.session_reused, start.startswith(b"HTTP/1.1 200") and json.loads(body)["target"] == target, t.session
    ctx = context()
    s = socket.create_connection(("127.0.0.1", LST), timeout=10)
    with ctx.wrap_socket(s, server_hostname="okena.test") as t:
        request(t, "GET", "/first")
        sess = t.session
    results = []
    for i in range(8):
        s = socket.create_connection(("127.0.0.1", LST), timeout=10)
        with ctx.wrap_socket(s, server_hostname="okena.test", session=sess) as t:
            start, body = request(t, "GET", f"/r/{i}")
            results.append(t.session_reused and json.loads(body)["target"] == f"/r/{i}")
    check("resumed with a ticket, 8 connections (both workers open each other's tickets)", all(results), str(results))

    # the first request in the same segment as the client Finished
    inc, outg = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = context().wrap_bio(inc, outg, server_hostname="okena.test")
    s = socket.create_connection(("127.0.0.1", LST), timeout=5)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    s.sendall(outg.read())
    while True:
        inc.write(s.recv(1 << 16))
        try:
            obj.do_handshake()
            break
        except ssl.SSLWantReadError:
            pass
    obj.write(b"GET /together HTTP/1.1\r\nHost: okena.test\r\n\r\n")
    s.sendall(outg.read())                  # CCS, Finished and the request: one write
    reply = b""
    deadline = time.time() + 5
    while b"/together" not in reply and time.time() < deadline:
        data = s.recv(1 << 16)
        if not data:
            break
        inc.write(data)
        try:
            while True:                 # one record per read
                reply += obj.read(1 << 16)
        except ssl.SSLWantReadError:
            pass
    s.close()
    check("a request sent with the Finished, in one segment", b"200 OK" in reply and b"/together" in reply,
          reply[:80])

    # many clients at once
    results = []

    def one(i):
        try:
            with connect() as t:
                results.append(json.loads(request(t, "GET", f"/c/{i}")[1])["target"] == f"/c/{i}")
        except Exception as e:
            results.append(False)
    threads = [threading.Thread(target=one, args=(i,)) for i in range(64)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    check("64 clients at once", sum(results) == 64, f"{sum(results)}/64")

    if shutil.which("curl"):
        r = subprocess.run(["curl", "-s", "--cacert", str(tmp / "ca.pem"), "--resolve",
                            f"okena.test:{LST}:127.0.0.1", f"https://okena.test:{LST}/curl", f"https://okena.test:{LST}/curl2",
                            "--max-time", "5"], capture_output=True, timeout=10)
        check("curl, two requests on one connection", b'"/curl"' in r.stdout and b'"/curl2"' in r.stdout, r.stdout[:200])
        r = subprocess.run(["curl", "-s", "--curves", "P-256:X25519", "--cacert", str(tmp / "ca.pem"), "--resolve",
                            f"okena.test:{LST}:127.0.0.1", f"https://okena.test:{LST}/retry", "--max-time", "5"],
                           capture_output=True, timeout=10)
        check("curl sharing P-256 first: HelloRetryRequest, then 200", b'"/retry"' in r.stdout, r.stdout[:200])

    # a handshake that stalls is closed by the header timeout
    s = socket.create_connection(("127.0.0.1", LST), timeout=5)
    s.sendall(b"\x16\x03\x01\x00\x80")      # a record header, and nothing more
    t0 = time.time()
    try:
        closed = s.recv(10) == b""
    except ConnectionResetError:
        closed = True
    except socket.timeout:
        closed = False
    took = time.time() - t0
    s.close()
    check("a stalled handshake is closed by the header timeout", closed and took < 4, f"{took:.1f}s")

    ctx = context()
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    try:
        with connect(ctx):
            err = None
    except ssl.SSLError as e:
        err = str(e)
    check("a TLS 1.2-only client: protocol_version", err is not None and "PROTOCOL_VERSION" in err.upper(), err)
    with socket.create_connection(("127.0.0.1", LST), timeout=3) as s:
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        reply = s.recv(100)
    check("plain HTTP on the HTTPS port: an alert, not a page", reply == b"\x15\x03\x03\x00\x02\x02\x0a", reply.hex())
    with connect() as t:
        check("still serving after all that", request(t, "GET", "/last")[0].startswith(b"HTTP/1.1 200"))

    if USER:
        # tcp listeners: kTLS or nothing
        bad = tmp / "tcp.conf"
        bad.write_text(tcp)
        r = subprocess.run([str(BIN), "-c", str(bad)], capture_output=True, text=True, timeout=10,
                           env=dict(os.environ, OKENA_KTLS="off"))
        check("tls on a tcp listener without kTLS: refused at the start",
              r.returncode != 0 and "needs kernel TLS" in r.stderr, r.stderr[-200:])
    else:
        def tls_tcp():
            s = socket.create_connection(("127.0.0.1", TLST), timeout=10)
            return context(alpn=None).wrap_socket(s, server_hostname="okena.test")

        def echo(t, data):
            t.sendall(data)
            got = b""
            while len(got) < len(data):
                chunk = t.recv(1 << 16)
                if not chunk:
                    break
                got += chunk
            return got == data
        with tls_tcp() as t:
            check("tcp listener: TLS 1.3 to okena, bytes to the backend and back",
                  t.version() == "TLSv1.3" and echo(t, b"tcp over tls"))
            check("tcp listener: 4 MiB each way", echo(t, os.urandom(4 << 20)))
        inc, outg = ssl.MemoryBIO(), ssl.MemoryBIO()
        obj = context(alpn=None).wrap_bio(inc, outg, server_hostname="okena.test")
        s = socket.create_connection(("127.0.0.1", TLST), timeout=5)
        try:
            obj.do_handshake()
        except ssl.SSLWantReadError:
            pass
        s.sendall(outg.read())
        while True:
            inc.write(s.recv(1 << 16))
            try:
                obj.do_handshake()
                break
            except ssl.SSLWantReadError:
                pass
        obj.write(b"first words")
        s.sendall(outg.read())              # the Finished and the first bytes together
        got = b""
        try:
            while b"first words" not in got:
                data = s.recv(1 << 16)
                if not data:
                    break
                inc.write(data)
                try:
                    while True:
                        got += obj.read(1 << 16)
                except ssl.SSLWantReadError:
                    pass
        except TimeoutError:
            pass
        s.close()
        check("tcp listener: bytes sent with the Finished reach the backend", b"first words" in got, got)
        res = []

        def one(i):
            try:
                with tls_tcp() as t:
                    res.append(echo(t, b"n%d" % i))
            except Exception:
                res.append(False)
        ths = [threading.Thread(target=one, args=(i,)) for i in range(32)]
        for th in ths:
            th.start()
        for th in ths:
            th.join()
        check("tcp listener: 32 clients at once", sum(res) == 32, f"{sum(res)}/32")

    if ENGINE == "io_uring" and not USER:
        # ticket keys rotate (here every second): a ticket resumes within a
        # period (at most one rotation: the previous key still opens it),
        # not after two
        rconf = tmp / "rotate.conf"
        RL = BASE + 4
        rconf.write_text(f"""okena {{ workers 2; io_engine {ENGINE} }}
http 127.0.0.1:{RL} {{
    {tls}
    route /* {{ to 127.0.0.1:{BACK} }}
}}
""")
        rlog = open(tmp / "rotate.log", "w+")
        rp = subprocess.Popen([str(BIN), "-c", str(rconf)], stderr=rlog,
                              env=dict(os.environ, OKENA_TICKET_ROTATE="1"))
        atexit.register(rp.kill)
        for _ in range(100):
            rlog.seek(0)
            if "started with" in rlog.read():
                break
            time.sleep(0.05)

        rctx = context()

        def rget(sess=None):
            s = socket.create_connection(("127.0.0.1", RL), timeout=10)
            with rctx.wrap_socket(s, server_hostname="okena.test", session=sess) as t:
                request(t, "GET", "/rot")
                return t.session_reused, t.session
        _, sess = rget()
        time.sleep(0.9)
        check("ticket keys rotate: a ticket resumes within its period", rget(sess)[0])
        time.sleep(2.3)
        reused, fresh = rget(sess)
        check("ticket keys rotate: two rotations later it does not (a full handshake)", not reused)
        check("ticket keys rotate: the new key's tickets resume", rget(fresh)[0])
        rp.terminate()
        rp.wait(10)

        # a fleet: two instances, one ticket_keys file; an operator's rotation
        import base64
        keyfile = tmp / "tickets.key"
        k1, k2, k3 = (base64.b64encode(os.urandom(32)).decode() for _ in range(3))
        keyfile.write_text(k1 + "\n")
        fleet = []
        for i, port in enumerate((BASE + 6, BASE + 7)):
            fc = tmp / f"fleet{i}.conf"
            fc.write_text(f"""okena {{ workers 1; io_engine {ENGINE}; ticket_keys {keyfile} }}
http 127.0.0.1:{port} {{
    {tls}
    route /* {{ to 127.0.0.1:{BACK} }}
}}
""")
            flog = open(tmp / f"fleet{i}.log", "w+")
            fp = subprocess.Popen([str(BIN), "-c", str(fc)], stderr=flog,
                                  env=dict(os.environ, OKENA_TICKET_ROTATE="1"))
            atexit.register(fp.kill)
            fleet.append((fp, flog, port))
        for fp, flog, _ in fleet:
            for _ in range(100):
                flog.seek(0)
                if "started with" in flog.read():
                    break
                time.sleep(0.05)

        def fget(port, sess=None):
            s = socket.create_connection(("127.0.0.1", port), timeout=10)
            with rctx.wrap_socket(s, server_hostname="okena.test", session=sess) as t:
                request(t, "GET", "/fleet")
                return t.session_reused, t.session

        def reload_all():
            for fp, flog, _ in fleet:
                flog.seek(0)
                n = flog.read().count("configuration reloaded")
                fp.send_signal(signal.SIGHUP)
                for _ in range(100):
                    flog.seek(0)
                    if flog.read().count("configuration reloaded") > n:
                        break
                    time.sleep(0.05)
        (pa, _, porta), (pb, _, portb) = fleet
        _, t1 = fget(porta)
        check("ticket_keys: a ticket from one instance resumes on the other", fget(portb, t1)[0])
        time.sleep(2.5)
        check("ticket_keys: no rotation of its own (with OKENA_TICKET_ROTATE=1)", fget(portb, t1)[0])
        keyfile.write_text(k2 + "\n" + k1 + "\n")
        reload_all()
        reused, t2 = fget(porta, t1)
        check("ticket_keys: after a rotation and a reload, the previous key still opens it", reused)
        _, t2 = fget(porta)
        keyfile.write_text(k3 + "\n" + k2 + "\n")
        reload_all()
        check("ticket_keys: two rotations later it does not", not fget(portb, t1)[0])
        check("ticket_keys: the newer one does, on either instance", fget(portb, t2)[0] and fget(porta, t2)[0])
        for fp, _, _ in fleet:
            fp.terminate()
            fp.wait(10)

    p.terminate()
    p.wait(10)
    log.seek(0)
    text = log.read()
    check("no worker died", "exited with status" not in text and "seccomp" not in text, text[-300:])
    print(f"https {ENGINE}{' user-space records' if USER else ''}: {'all passed' if not failures else f'{failures} failed'}")
    return 1 if failures else 0


sys.exit(main())
