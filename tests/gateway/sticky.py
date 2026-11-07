#!/usr/bin/env python3
"""`sticky cookie=` on a pool, on one engine (argument): a client kept on its
server, through drains, and moved, with a new cookie, when it is gone."""
import collections
import http.client
import http.server
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
LST, OTHER, WS = 18640, 18641, 18642
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok  " if ok else "FAIL"), name, detail if not ok else "", flush=True)
    fails += 0 if ok else 1


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    disable_nagle_algorithm = True

    def do_GET(self):
        if getattr(self.server, "dead", False):     # a server that went: no answer
            self.close_connection = True
            self.connection.shutdown(socket.SHUT_RDWR)
            return
        b = self.server.name.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 256


def backend(name):
    s = S(("127.0.0.1", 0), H)
    s.name = name
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s, f"127.0.0.1:{s.server_address[1]}"


def ws_backend(name):
    """Answers an upgrade with 101 and its name, anything else with 200."""
    l = socket.socket()
    l.bind(("127.0.0.1", 0))
    l.listen(16)

    def one(c):
        d = b""
        while b"\r\n\r\n" not in d:
            x = c.recv(4096)
            if not x:
                return
            d += x
        if b"upgrade: websocket" in d.lower():
            c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n" + name.encode())
        else:
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n" + name.encode())
        time.sleep(0.2)
        c.close()

    def run():
        while True:
            c, a = l.accept()
            threading.Thread(target=one, args=(c,), daemon=True).start()
    threading.Thread(target=run, daemon=True).start()
    return f"127.0.0.1:{l.getsockname()[1]}"


def upgrade(cookie=None):
    s = socket.create_connection(("127.0.0.1", WS), 3)
    h = "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
    h += "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
    if cookie:
        h += f"Cookie: {cookie}\r\n"
    s.sendall((h + "\r\n").encode())
    d = b""
    try:
        while True:
            x = s.recv(4096)
            if not x:
                break
            d += x
    except OSError:
        pass
    s.close()
    d = d.decode(errors="replace")
    m = re.search(r"\r\nSet-Cookie: srv=([0-9a-f]{16})", d)
    return d.split("\r\n")[0], d[-1:], m and m.group(1)


def get(port=LST, path="/x", cookie=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("GET", path, headers={"Cookie": cookie} if cookie else {})
    r = c.getresponse()
    b = r.read().decode()
    sc = r.getheader("set-cookie")
    c.close()
    return r.status, b, sc


def value(sc, name="srv"):
    m = re.match(rf"{name}=([0-9a-f]{{16}})(;|$)", sc or "")
    return m and m.group(1)


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-sticky-", dir="/tmp"))
    conf = tmp / "okena.conf"
    srv = {n: backend(n) for n in ("a", "b", "c")}
    other = backend("z")
    conf.write_text(f"""okena {{ workers 4; io_engine {ENGINE}; admin unix:{tmp}/a.sock }}
pool p {{ sticky cookie=srv ttl=1h; {''.join(f'server {a}; ' for s, a in srv.values())}}}
pool q {{ sticky cookie=srv samesite=none; server {other[1]} }}
http 127.0.0.1:{LST} {{ route /x {{ to pool p }} }}
http 127.0.0.1:{OTHER} {{ route /* {{ to pool q }} }}
pool w {{ sticky cookie=srv; server {ws_backend("a")}; server {ws_backend("b")} }}
http 127.0.0.1:{WS} {{ route /* {{ to pool w }} }}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))

    def ctl(*a):
        return subprocess.run([str(BIN), *a, "-c", str(conf)], capture_output=True, text=True, timeout=40)
    try:
        for i in range(100):
            try:
                get()
                break
            except OSError:
                time.sleep(0.05)
        st, who, sc = get()
        v = value(sc)
        check("a new client gets the cookie", st == 200 and v, sc)
        check("  Path=/, HttpOnly, Max-Age of the ttl, SameSite=Lax; not Secure on plain http",
              sc and "; Path=/" in sc and "; HttpOnly" in sc and "; Max-Age=3600" in sc and "SameSite=Lax" in sc and "Secure" not in sc, sc)
        r = [get(cookie=f"srv={v}") for i in range(30)]
        check("  with it: the same server every time, on any worker", {x[1] for x in r} == {who}, collections.Counter(x[1] for x in r))
        check("  and no cookie again", all(x[2] is None for x in r), [x[2] for x in r][:3])
        r = get(cookie=f"theme=dark; srv={v}; other=1")
        check("  among other cookies too", r[1] == who and r[2] is None, r)
        # many clients: shared out by the balance, each one kept
        cl = {}
        for i in range(60):
            st, w, sc = get()
            cl[value(sc)] = w
        check("clients are shared out", len(set(cl.values())) == 3, collections.Counter(cl.values()))
        check("  three servers, three names", len(cl) == 3, list(cl))
        name = {w: k for k, w in cl.items()}

        # drain: those it has stay, new ones go elsewhere
        ctl("backend", "drain", "p", srv["a"][1])
        time.sleep(0.05)
        r = [get(cookie=f"srv={name['a']}")[1] for i in range(20)]
        check("drained: a client on it stays", set(r) == {"a"}, collections.Counter(r))
        r = [get()[1] for i in range(30)]
        check("  a new one does not go there", "a" not in r, collections.Counter(r))
        ctl("backend", "up", "p", srv["a"][1])

        # gone: moved, and told
        srv["b"][0].dead = True
        srv["b"][0].shutdown()
        srv["b"][0].server_close()
        time.sleep(0.05)
        r = [get(cookie=f"srv={name['b']}") for i in range(12)]
        ok = [x for x in r if x[0] == 200]
        check("its server gone: served elsewhere", len(ok) >= 9 and all(x[1] in ("a", "c") for x in ok), [x[:2] for x in r])
        check("  with a cookie for where it went", all(value(x[2]) == name[x[1]] for x in ok), [(x[1], x[2]) for x in ok][:3])

        # cookies that name nothing
        for what, ck in (("forged", "srv=0123456789abcdef"), ("too short", "srv=abc"), ("not hex", "srv=zzzzzzzzzzzzzzzz"),
                         ("upper case", "srv=" + name["a"].upper()), ("another pool's", None), ("empty", "srv=")):
            if ck is None:
                ck = "srv=" + value(get(OTHER, "/")[2])
            st, w, sc = get(cookie=ck)
            check(f"a cookie {what}: the balance picks, and sets it", st == 200 and value(sc) == name.get(w, value(sc)) and value(sc) in name.values(), (st, w, sc))

        st, w, sc = get(OTHER, "/")
        check("samesite=none: and Secure, as browsers want", sc and "SameSite=None; Secure" in sc and "Max-Age" not in sc, sc)
        r = [upgrade() for i in range(10)]
        check("a WebSocket upgrade with no cookie gets one on its 101", all(x[0] == "HTTP/1.1 101 Switching Protocols" and x[2] for x in r), r[:2])
        first = r[0]
        r = [upgrade(f"srv={first[2]}") for i in range(10)]
        check("  and with it, upgrades go to that server, setting none", {x[1] for x in r} == {first[1]} and all(x[2] is None for x in r), r[:3])
        st, w, sc = get(LST, "/nowhere")
        check("okena's own answers set none", st == 404 and sc is None, (st, sc))
    finally:
        p.terminate()
        p.wait(10)
    t = log.read_text()
    check("no worker died", "killed" not in t and "restarting" not in t, t[-300:])

    def bad(what, body):
        f = tmp / "bad.conf"
        f.write_text(f"pool p {{ {body}; server 127.0.0.1:1 }}\nhttp 127.0.0.1:1 {{ route /* {{ to pool p }} }}\n")
        r = subprocess.run([str(BIN), "check", str(f)], capture_output=True, text=True, timeout=10)
        check(f"{what}: refused", r.returncode != 0 and "sticky" in r.stderr, r.stderr[-200:])
    bad("no cookie=", "sticky ttl=1h")
    bad("a name that is not a token", "sticky cookie=a;b")
    bad("samesite of no kind", "sticky cookie=s samesite=sometimes")
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"sticky {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"), flush=True)
    sys.exit(1 if fails else 0)


main()
