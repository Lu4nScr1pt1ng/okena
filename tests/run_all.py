#!/usr/bin/env python3
"""Run every test suite at once and report like one suite.

The suites are independent, so they run in parallel and the whole run
takes about as long as the slowest one. Each runs in its own network
namespace (unshare -rn, loopback only): its own ports, its own TIME_WAIT
space and no connection tracking. On the host, tens of thousands of test
connections in half a minute fill the conntrack table (each closed one is
kept up to two minutes), and the kernel then drops new connections of
every program, the tests included. Where user namespaces are not
allowed, the suites run on the host network, still in parallel. The
output of a suite is shown only when it fails; a summary line per suite
gives its time. Exit status: 0 when every suite passed.

    tests/run_all.py            all suites
    tests/run_all.py l4 http    only the suites whose name contains a word
"""
import os
import pathlib
import subprocess
import sys
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]

SUITES = [
    ("httpproxy io_uring", ["tests/httpproxy/run.py", "io_uring"]),
    ("httpproxy epoll", ["tests/httpproxy/run.py", "epoll"]),
    ("l4 io_uring core", ["tests/l4/run.py", "io_uring", "core"]),
    ("l4 io_uring faults", ["tests/l4/run.py", "io_uring", "faults"]),
    ("l4 epoll core", ["tests/l4/run.py", "epoll", "core"]),
    ("l4 epoll faults", ["tests/l4/run.py", "epoll", "faults"]),
    ("dns", ["tests/dns/run.py"]),
    ("overload io_uring", ["tests/overload/run.py", "io_uring"]),
    ("overload epoll", ["tests/overload/run.py", "epoll"]),
    ("reload", ["tests/reload/run.py"]),
    ("health", ["tests/health/run.py"]),
    ("lb", ["tests/lb/run.py"]),
    ("admin io_uring", ["tests/admin/run.py", "io_uring"]),
    ("admin epoll", ["tests/admin/run.py", "epoll"]),
    ("http parser", ["tests/http/run.py", "5000"]),
    ("crypto kat", ["tests/kat/run.py"]),
    ("wycheproof", ["tests/wycheproof/run.py"]),
    ("tls certs", ["tests/tls/run.py"]),
    ("tls handshake", ["tests/tls/handshake.py"]),
    ("https io_uring", ["tests/tls/https.py", "io_uring"]),
    ("https epoll", ["tests/tls/https.py", "epoll"]),
    ("https io_uring user", ["tests/tls/https.py", "io_uring", "user"]),
    ("https epoll user", ["tests/tls/https.py", "epoll", "user"]),
    ("passthrough io_uring", ["tests/tls/passthrough.py", "io_uring"]),
    ("passthrough epoll", ["tests/tls/passthrough.py", "epoll"]),
    ("tls client", ["tests/tls/client.py"]),
    ("tls 1.2 client", ["tests/tls/client12.py"]),
    ("tlsfuzzer", ["tests/tls/tlsfuzz.py"]),
    ("tls12 server", ["tests/tls/server12.py"]),
    ("tls12 io_uring", ["tests/tls/tls12.py", "io_uring"]),
    ("tls12 epoll", ["tests/tls/tls12.py", "epoll"]),
    ("uptls io_uring", ["tests/tls/uptls.py", "io_uring"]),
    ("uptls epoll", ["tests/tls/uptls.py", "epoll"]),
    ("ed25519 io_uring", ["tests/tls/ed25519.py", "io_uring"]),
    ("ed25519 epoll", ["tests/tls/ed25519.py", "epoll"]),
    ("budget io_uring", ["tests/tls/budget.py", "io_uring"]),
    ("budget epoll", ["tests/tls/budget.py", "epoll"]),
    ("peer io_uring", ["tests/peer/run.py", "io_uring"]),
    ("peer epoll", ["tests/peer/run.py", "epoll"]),
    ("config fuzz", ["tests/config/fuzz.py", "2000"]),
    ("config", ["tests/config/run.py"]),
    ("bench", ["tests/bench/run.py"]),
    ("hpack", ["tests/h2/hpack_suite.py"]),
    ("h2 io_uring", ["tests/h2/run.py", "io_uring"]),
    ("h2 epoll", ["tests/h2/run.py", "epoll"]),
    ("h2 fuzz io_uring", ["tests/h2/fuzz.py", "io_uring", "300"]),
    ("h2 fuzz epoll", ["tests/h2/fuzz.py", "epoll", "300"]),
]


def netns_ok():
    try:
        return subprocess.run(["unshare", "-rn", "true"], capture_output=True).returncode == 0
    except OSError:
        return False


# a private network with loopback up, then the suite
NETNS = ["unshare", "-rn", "sh", "-c", 'ip link set lo up && exec "$0" "$@"']


def main():
    words = sys.argv[1:]
    isolate = netns_ok()
    if not isolate:
        print("note: no user namespaces here; the suites share the host network")
    chosen = [s for s in SUITES if not words or any(w in s[0] for w in words)]
    start = time.time()
    results = []                    # in the order they finish
    lock = threading.Lock()

    def run(name, cmd):
        argv = [sys.executable, "-I", *cmd]
        # the DNS suite makes its own namespace (with /etc mounts); Wycheproof
        # fetches its vectors once and touches no network after that
        if isolate and name not in ("dns", "wycheproof"):
            argv = NETNS + argv
        p = subprocess.Popen(argv, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out, _ = p.communicate()              # read as it comes: a full pipe never stalls a suite
        with lock:
            results.append((name, p.returncode == 0, time.time() - start, out.decode(errors="replace")))
            print(f"{'ok  ' if p.returncode == 0 else 'FAIL'} {name:<20} {time.time() - start:5.1f}s", flush=True)

    threads = [threading.Thread(target=run, args=suite) for suite in chosen]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    failed = [(name, out) for name, ok, _, out in results if not ok]
    for name, out in failed:
        print(f"\n===== {name} =====\n{out}")
    total = time.time() - start
    print(f"\n{len(chosen) - len(failed)}/{len(chosen)} suites passed in {total:.1f}s")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
