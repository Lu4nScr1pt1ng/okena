#!/usr/bin/env python3
"""Regular expressions, on one engine (argument): the engine against Python's re,
on regexes made at random from the syntax okena takes (classes, groups, (?:),
alternation, * + ? {n,m} greedy and lazy, ^ $, \\d \\w \\s, (?i)) and texts made at
random: the same match and the same groups, every time; a regex that would take
a backtracking engine exponential time, at once. Then routes: `route ~REGEX`
(after an exact path, before a prefix, in the order written, methods), `rewrite
path ~REGEX -> /x/$1`, `match path=~...` and `header:...=~...`, and a regex
refused at load with why."""
import http.client
import http.server
import os
import pathlib
import random
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
BIN = HERE.parents[1] / "build" / "okena"
ENGINE = sys.argv[1] if len(sys.argv) > 1 else "io_uring"
BASE = 57400 + os.getpid() % 90 * 20 + (10 if ENGINE == "epoll" else 0)
BACK, LST = BASE, BASE + 1
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok  " if ok else "FAIL"), name, detail if not ok else "", flush=True)
    fails += 0 if ok else 1


def okena_regex(pattern, texts):
    r = subprocess.run([str(BIN), "regex", pattern, *texts], capture_output=True, text=True, timeout=10)
    if r.returncode:
        return None, r.stderr
    return r.stdout.splitlines(), ""


def python_says(pattern, text):
    m = re.search(pattern, text, re.A | re.S)
    if not m:
        return "no"
    out = []
    for g in range(0, (m.re.groups or 0) + 1):
        s, e = m.span(g)
        out.append("-" if s < 0 else f"{s}-{e}")
    return " ".join(out)


def gen(rng, depth=0):
    """a regex of okena's syntax (and Python's, the same meaning)"""
    def atom():
        k = rng.random()
        if depth < 3 and k < 0.18:
            inner = gen(rng, depth + 1)
            return ("(?:" if rng.random() < 0.3 else "(") + inner + ")"
        if k < 0.30:
            body = "".join(rng.choice(["a", "b", "c", "0-9", "a-c", "\\d", "/", "x"]) for _ in range(rng.randint(1, 3)))
            return "[" + ("^" if rng.random() < 0.25 else "") + body + "]"
        if k < 0.38:
            return rng.choice(["\\d", "\\w", "\\s", "\\D", "\\W", "."])
        if k < 0.42:
            return rng.choice(["\\.", "\\/", "\\-", "\\+"])
        return rng.choice("abcx/0129")

    def quant(a):
        k = rng.random()
        if k < 0.55:
            return a
        q = rng.choice(["*", "+", "?", "{2}", "{1,3}", "{0,2}", "{2,}"])
        if rng.random() < 0.3:
            q += "?"
        return a + q
    alts = []
    for _ in range(rng.choice([1, 1, 1, 2, 3])):
        seq = "".join(quant(atom()) for _ in range(rng.randint(1, 4)))
        alts.append(seq)
    r = "|".join(alts)
    if depth == 0:
        if rng.random() < 0.2:
            r = "^" + r
        if rng.random() < 0.2:
            r = r + "$"
    return r


class Back(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        b = self.path.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    do_POST = do_GET


def main():
    rng = random.Random(int(os.environ.get("REGEX_SEED", "1")))
    # the engine, against Python's re
    bad = []
    n = 0
    for i in range(400):
        p = gen(rng)
        if rng.random() < 0.1:
            p = "(?i)" + p
        try:
            if re.compile(p, re.A | re.S).groups > 9:
                continue                                # (9 groups at most: refused)
        except re.error:
            continue
        texts = ["".join(rng.choice("abcABCx/019 .-+") for _ in range(rng.randint(0, 12))) for _ in range(8)]
        texts = [t if t else "z" for t in texts]          # (an empty argument: the shell's)
        got, err = okena_regex(p, texts)
        if got is None:
            bad.append((p, "refused: " + err.strip()))
            continue
        for t, g in zip(texts, got):
            n += 1
            want = python_says(p, t)
            if g != want:
                bad.append((p, t, g, want))
    check(f"the engine against Python's re: {n} matches, the same spans and groups", not bad, bad[:5])
    t0 = time.time()
    got, _ = okena_regex("(a*)*b", ["a" * 5000 + "c"])
    got2, _ = okena_regex("(a|aa)+$", ["a" * 5000 + "!"])
    took = time.time() - t0
    check("regexes that make a backtracking engine take forever: at once (linear)",
          got == ["no"] and got2 == ["no"] and took < 2, (got, got2, took))
    r = subprocess.run([str(BIN), "regex", "a(b", "x"], capture_output=True, text=True, timeout=5)
    check("  one that does not read: refused, and why", r.returncode != 0 and "no ) after it" in r.stderr, r.stderr)

    # routes
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-regex-", dir="/tmp"))
    threading.Thread(target=http.server.ThreadingHTTPServer(("127.0.0.1", BACK), Back).serve_forever, daemon=True).start()
    conf = tmp / "okena.conf"
    conf.write_text(f"""okena {{ workers 1; io_engine {ENGINE}; drain delay=0s timeout=1s }}
pool b {{ server 127.0.0.1:{BACK} }}
http 127.0.0.1:{LST} {{
    route /users/me {{ redirect 302 /exact }}
    route "~^/users/([0-9]+)$" GET {{ rewrite path "~^/users/([0-9]+)$" -> /api/user/$1; to pool b }}
    route "~^/users/[a-z]+$" {{ redirect 302 /letters }}
    route "~\\\\.(png|jpe?g)$" {{ rewrite path "~^/(.*)/([^/]+)\\\\.(png|jpe?g)$" -> /img/$2/$1/$3; to pool b }}
    route "~^/v[0-9]+/" {{
        match path=~^/v2/ {{ redirect 302 /two }}
        match header:x-tier=~^(gold|silver)$ {{ redirect 302 /tier }}
        to pool b
    }}
    route /users/* {{ redirect 302 /prefix }}
    route /* {{ to pool b }}
}}
""")
    log = tmp / "log"
    p = subprocess.Popen([str(BIN), "-c", str(conf)], stdout=subprocess.DEVNULL, stderr=open(log, "w"))

    def req(path, method="GET", headers=None):
        c = http.client.HTTPConnection("127.0.0.1", LST, timeout=5)
        c.request(method, path, headers=headers or {})
        r = c.getresponse()
        d = r.read()
        c.close()
        return r.status, r.getheader("Location"), d
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", LST), 1).close()
                break
            except OSError:
                time.sleep(0.05)
        check("an exact path before any regex", req("/users/me")[1] == "/exact", req("/users/me"))
        s, _, d = req("/users/42?x=1")
        check("~^/users/([0-9]+)$ and rewrite ~ -> /api/user/$1: the backend sees /api/user/42?x=1",
              s == 200 and d == b"/api/user/42?x=1", (s, d))
        s, loc, _ = req("/users/42", method="POST")
        check("  its methods: POST is not GET, on to the next that fits (the prefix)", loc == "/prefix", (s, loc))
        check("the next regex, in the order written", req("/users/bob")[1] == "/letters", req("/users/bob"))
        check("regexes before a prefix", req("/users/x9")[1] == "/prefix", req("/users/x9"))
        s, _, d = req("/a/b/cat.jpeg")
        check("groups anywhere in TO: /img/$2/$1/$3", s == 200 and d == b"/img/cat/a/b/jpeg", (s, d))
        check("match path=~", req("/v2/x")[1] == "/two", req("/v2/x"))
        check("match header:...=~", req("/v3/x", headers={"x-tier": "gold"})[1] == "/tier", req("/v3/x", headers={"x-tier": "gold"}))
        s, loc, d = req("/v3/x", headers={"x-tier": "bronze"})
        check("  neither: the route itself", s == 200 and d == b"/v3/x", (s, loc, d))
        s, _, d = req("/other")
        check("nothing else: the catch-all", s == 200 and d == b"/other", (s, d))
    finally:
        p.terminate()
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()
    bad = tmp / "bad.conf"
    bad.write_text(conf.read_text().replace('"~^/users/[a-z]+$"', '"~^/users/[a-z+$"'))
    r = subprocess.run([str(BIN), "check", "-c", str(bad)], capture_output=True, text=True, timeout=10)
    check("a route's regex that does not read: refused at load, and why",
          r.returncode != 0 and "[ with no ] after it" in r.stderr, r.stderr[-300:])
    t = log.read_text()
    check("no process died", "seccomp" not in t and "killed by signal" not in t, t[-300:])
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"regex {ENGINE}: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


main()
