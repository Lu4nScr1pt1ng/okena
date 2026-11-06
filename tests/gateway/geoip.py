#!/usr/bin/env python3
"""`geoip`, on one engine (argument). .mmdb files are written here, as MaxMind's format
says: each record size, IPv4 and IPv6 trees, pointers. Then broken ones: a file that
lies must give no country, and must not stop a worker."""
import http.client
import http.server
import ipaddress
import os
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
BIN = HERE.parents[1] / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 4000 + os.getpid() % 90 * 6 + (3 if ENGINE == "epoll" else 0)
BACK, LST = BASE, BASE + 1
fails = 0
MARK = b"\xab\xcd\xefMaxMind.com"


def check(name, ok, more=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {more}"), flush=True)
    fails += 0 if ok else 1


def ctrl(t, n):
    """a control byte and its size, for type t and size n"""
    if n < 29:
        s, e = bytes([n]), b""
    elif n < 285:
        s, e = bytes([29]), bytes([n - 29])
    elif n < 65821:
        s, e = bytes([30]), struct.pack(">H", n - 285)
    else:
        s, e = bytes([31]), (n - 65821).to_bytes(3, "big")
    if t < 8:
        return bytes([t << 5 | s[0]]) + e
    return bytes([s[0], t - 7]) + e


def v(x):
    if isinstance(x, Raw):
        return x.b
    if isinstance(x, str):
        b = x.encode()
        return ctrl(2, len(b)) + b
    if isinstance(x, bool):
        return ctrl(14, int(x))
    if isinstance(x, float):
        return ctrl(3, 8) + struct.pack(">d", x)
    if isinstance(x, int):
        b = x.to_bytes((x.bit_length() + 7) // 8, "big")
        return ctrl(6 if len(b) <= 4 else 9, len(b)) + b
    if isinstance(x, dict):
        return ctrl(7, len(x)) + b"".join(v(k) + v(w) for k, w in x.items())
    if isinstance(x, list):
        return ctrl(11, len(x)) + b"".join(v(w) for w in x)


class Raw:
    def __init__(self, b):
        self.b = b


def pointer(off):
    if off < 2048:
        return Raw(bytes([1 << 5 | off >> 8, off & 255]))
    if off < 526336:
        o = off - 2048
        return Raw(bytes([1 << 5 | 1 << 3 | o >> 16]) + struct.pack(">H", o & 65535))
    return Raw(bytes([1 << 5 | 3 << 3]) + struct.pack(">I", off))


def build(nets, rec=24, ver=6, data_of=None, meta_extra=None):
    """nets: (cidr, country)"""
    bits = 128 if ver == 6 else 32
    tree = [[None, None]]
    data = bytearray()
    # something for pointers to point to, in front
    shared = len(data)
    data += v("iso_code")
    offs = {}
    for cidr, cc in nets:
        if cc not in offs:
            offs[cc] = len(data)
            d = {"continent": {"code": "SA", "names": {"en": "x" * 40, "pt": ["a", 1, True, 1.5]}},
                 "country": {"geoname_id": 3469034, pointer(shared): cc, "names": {"en": cc}}} if data_of is None else data_of(cc)
            data += b"".join([ctrl(7, len(d))] + [v(k) + v(w) for k, w in d.items()])
    for cidr, cc in nets:
        n = ipaddress.ip_network(cidr)
        a = int(n.network_address)
        if n.version == 4:
            if ver == 6:
                pl, a = 96 + n.prefixlen, a
            else:
                pl = n.prefixlen
            ab = bits
        else:
            pl, ab = n.prefixlen, 128
        node = 0
        for i in range(pl):
            b = a >> (ab - 1 - i) & 1
            if i == pl - 1:
                tree[node][b] = ("d", offs[cc])
            else:
                if tree[node][b] is None:
                    tree.append([None, None])
                    tree[node][b] = len(tree) - 1
                node = tree[node][b]
    nc = len(tree)
    def val(x):
        if x is None:
            return nc
        if isinstance(x, tuple):
            return nc + 16 + x[1]
        return x
    out = bytearray()
    for l, r in tree:
        l, r = val(l), val(r)
        if rec == 24:
            out += l.to_bytes(3, "big") + r.to_bytes(3, "big")
        elif rec == 28:
            out += (l & 0xFFFFFF).to_bytes(3, "big") + bytes([l >> 24 << 4 | r >> 24]) + (r & 0xFFFFFF).to_bytes(3, "big")
        else:
            out += l.to_bytes(4, "big") + r.to_bytes(4, "big")
    meta = {"binary_format_major_version": 2, "binary_format_minor_version": 0, "build_epoch": 1700000000, "database_type": "GeoLite2-Country",
            "description": {"en": "t"}, "ip_version": ver, "languages": ["en"], "node_count": nc, "record_size": rec}
    meta.update(meta_extra or {})
    return bytes(out) + bytes(16) + bytes(data) + MARK + v(meta) + bytes(1100)


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


NETS = [("127.0.0.0/8", "BR"), ("10.0.0.0/8", "PT"), ("192.0.2.0/24", "RU"), ("2001:db8::/32", "AR")]


def run(tmp, name, db, routes, fn):
    (tmp / "db.mmdb").write_bytes(db)
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 2; io_engine {ENGINE}; geoip {tmp}/db.mmdb }}
pool b {{ server 127.0.0.1:{BACK} }}
pool c {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{LST} {{
{routes}
}}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stderr=open(log, "w"))
    try:
        for i in range(200):
            try:
                socket.create_connection(("127.0.0.1", LST), 0.5).close()
                break
            except OSError:
                time.sleep(0.05)
        else:
            print("did not start:", p.poll(), log.read_text()[-300:], flush=True)
        fn()
    finally:
        p.terminate()
        p.wait(10)
        # a ring lets its sockets go after the process has left: until then a
        # connect succeeds, and the next instance would look started
        for i in range(200):
            try:
                socket.create_connection(("127.0.0.1", LST), 0.5).close()
                time.sleep(0.02)
            except OSError:
                break
    check(f"{name}: no worker died", "killed" not in log.read_text(), log.read_text()[-160:])


def st(path, **h):
    c = http.client.HTTPConnection("127.0.0.1", LST, timeout=4)
    c.request("GET", path, headers={k.replace("_", "-"): v for k, v in h.items()})
    r = c.getresponse()
    b = r.read()
    c.close()
    return r.status, r.getheader("location")


ROUTES = """    trusted_proxies 127.0.0.0/8
    route /yes {{ allow country:BR; to pool b }}
    route /no {{ allow country:PT,AR; to pool b }}
    route /deny {{ deny country:RU,BR; to pool b }}
    route /m {{ match client.country=PT,BR {{ redirect 302 /hit }}; to pool b }}
    route /n {{ match client.country=AR {{ redirect 302 /hit }}; to pool b }}
    route /p {{ to pool b }}
""".replace("{{", "{").replace("}}", "}")


def main():
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-geo."))
    threading.Thread(target=http.server.ThreadingHTTPServer(("127.0.0.1", BACK), H).serve_forever, daemon=True).start()
    for rec in (24, 28, 32):
        for ver in (6, 4):
            def t():
                check(f"{rec}-bit, IPv{ver}: allow by country", st("/yes")[0] == 200, st("/yes"))
                check("  not in it", st("/no")[0] == 403)
                check("  deny", st("/deny")[0] == 403)
                check("  match, in a list", st("/m") == (302, "/hit"), st("/m"))
                check("  match, not", st("/n")[0] == 200)
                x = st("/yes", x_forwarded_for="10.1.1.1")
                check("  the client as trusted_proxies says", x[0] == 403, x)
                check("  x-forwarded-for of Portugal", st("/no", x_forwarded_for="10.1.1.1")[0] == 200)
                check("  an address in no network", st("/no", x_forwarded_for="8.8.8.8")[0] == 403 and st("/deny", x_forwarded_for="8.8.8.8")[0] == 200)
                if ver == 6:
                    check("  IPv6", st("/no", x_forwarded_for="2001:db8::1")[0] == 200)
                else:
                    check("  IPv6 in an IPv4 file: none", st("/no", x_forwarded_for="2001:db8::1")[0] == 403)
            nets = NETS if ver == 6 else NETS[:3]
            run(tmp, f"{rec}/{ver}", build(nets, rec, ver), ROUTES, t)

    # a file that lies: no country, and the worker goes on
    def nothing():
        for i in range(6):
            r = st("/yes")
            check_bad.append(r[0])
        check_ok.append(st("/p")[0])
    deep = {"a": 1}
    for i in range(40):
        deep = {"x": deep}
    for what, d in (("no country", lambda cc: {"other": 1}), ("a string for a map", lambda cc: {"country": "BR"}),
                    ("a number for its code", lambda cc: {"country": {"iso_code": 7}}), ("a code too long", lambda cc: {"country": {"iso_code": "BRA"}}),
                    ("nested 40 deep, before it", lambda cc: {"z": deep, "country": {"iso_code": "BR"}}),
                    ("a pointer to itself", lambda cc: {"country": pointer(0)}), ("a pointer far outside", lambda cc: {"country": pointer(1 << 30)}),
                    ("a key that is a pointer outside", lambda cc: {pointer(1 << 30): "x", "country": {"iso_code": "BR"}}),
                    ("a size past the end", lambda cc: {"z": Raw(ctrl(2, 1 << 24)), "country": {"iso_code": "BR"}}),
                    ("a map that says it is huge", lambda cc: {"country": Raw(ctrl(7, 1 << 24))})):
        check_bad, check_ok = [], []
        run(tmp, what, build(NETS, 24, 6, data_of=d), ROUTES, nothing)
        check(f"{what}: no country, others served", 200 not in check_bad and check_ok == [200], (check_bad, check_ok))
    # a tree that points out of the file
    db = bytearray(build(NETS, 24, 6))
    db[0:6] = b"\xff\xff\xff\xff\xff\xff"
    check_bad, check_ok = [], []
    run(tmp, "a tree that points outside", bytes(db), ROUTES, nothing)
    check("  no country", 200 not in check_bad and check_ok == [200], (check_bad, check_ok))

    c = tmp / "bad.conf"
    def refused(what, text):
        c.write_text(text)
        q = subprocess.run(["timeout", "5", str(BIN), "-c", str(c)], capture_output=True, text=True, timeout=8)
        check(f"{what}: refused", q.returncode not in (0, 124) and q.stderr != "", f"{q.returncode} {q.stderr[-140:]}")
    (tmp / "junk").write_bytes(b"x" * 5000)
    (tmp / "short").write_bytes(MARK)
    (tmp / "norec").write_bytes(build(NETS, 24, 6, meta_extra={"record_size": 20}))
    (tmp / "big").write_bytes(build(NETS, 24, 6, meta_extra={"node_count": 1 << 30}))
    P = f"pool b {{ server 127.0.0.1:1 }}\nhttp 127.0.0.1:{LST} {{ route /* {{ to pool b }} }}\n"
    for f, what in (("junk", "not an mmdb"), ("short", "too short"), ("norec", "a record size that does not exist"), ("big", "more nodes than the file holds"), ("nosuch", "no file")):
        refused(what, f"okena {{ geoip {tmp}/{f} }}\n" + P)
    (tmp / "db.mmdb").write_bytes(build(NETS, 24, 6))
    refused("client.country with no geoip", f"pool b {{ server 127.0.0.1:1 }}\nhttp 127.0.0.1:{LST} {{ route /* {{ match client.country=BR {{ to pool b }}; to pool b }} }}\n")
    refused("country: with no geoip", f"pool b {{ server 127.0.0.1:1 }}\nhttp 127.0.0.1:{LST} {{ route /* {{ allow country:BR; to pool b }} }}\n")
    refused("a bad list", f"okena {{ geoip {tmp}/db.mmdb }}\npool b {{ server 127.0.0.1:1 }}\nhttp 127.0.0.1:{LST} {{ route /* {{ allow country:BRA; to pool b }} }}\n")
    print(f"geoip {ENGINE}: " + ("all passed" if not fails else f"{fails} failed"))
    sys.exit(1 if fails else 0)


main()
