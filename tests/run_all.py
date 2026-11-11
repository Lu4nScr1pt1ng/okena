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
import signal
import subprocess
import sys
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]

SUITES = [
    ("httpproxy io_uring", ["tests/httpproxy/run.py", "io_uring"]),
    ("httpproxy epoll", ["tests/httpproxy/run.py", "epoll"]),
    ("edge io_uring", ["tests/httpproxy/edge.py", "io_uring"]),
    ("edge epoll", ["tests/httpproxy/edge.py", "epoll"]),
    ("upstream io_uring", ["tests/httpproxy/upstream.py", "io_uring"]),
    ("upstream epoll", ["tests/httpproxy/upstream.py", "epoll"]),
    ("routing io_uring", ["tests/httpproxy/routing.py", "io_uring"]),
    ("routing epoll", ["tests/httpproxy/routing.py", "epoll"]),
    ("identity io_uring", ["tests/httpproxy/identity.py", "io_uring"]),
    ("identity epoll", ["tests/httpproxy/identity.py", "epoll"]),
    ("failures io_uring", ["tests/httpproxy/failures.py", "io_uring"]),
    ("failures epoll", ["tests/httpproxy/failures.py", "epoll"]),
    ("streaming io_uring", ["tests/httpproxy/streaming.py", "io_uring"]),
    ("streaming epoll", ["tests/httpproxy/streaming.py", "epoll"]),
    ("cachedge io_uring", ["tests/gateway/cachedge.py", "io_uring"]),
    ("cachedge epoll", ["tests/gateway/cachedge.py", "epoll"]),
    ("l4 edges io_uring", ["tests/l4/edges.py", "io_uring"]),
    ("l4 edges epoll", ["tests/l4/edges.py", "epoll"]),
    ("admin edges", ["tests/admin/edges.py"]),
    ("fdlimit io_uring", ["tests/httpproxy/fdlimit.py", "io_uring"]),
    ("fdlimit epoll", ["tests/httpproxy/fdlimit.py", "epoll"]),
    ("h3 edges io_uring", ["tests/h3/edges.py", "io_uring"]),
    ("h3 edges epoll", ["tests/h3/edges.py", "epoll"]),
    ("hello io_uring", ["tests/tls/hello.py", "io_uring"]),
    ("hello epoll", ["tests/tls/hello.py", "epoll"]),
    ("retry io_uring", ["tests/gateway/retry.py", "io_uring"]),
    ("retry epoll", ["tests/gateway/retry.py", "epoll"]),
    ("outlier io_uring", ["tests/gateway/outlier.py", "io_uring"]),
    ("outlier epoll", ["tests/gateway/outlier.py", "epoll"]),
    ("source io_uring", ["tests/l4/source.py", "io_uring"]),
    ("source epoll", ["tests/l4/source.py", "epoll"]),
    ("mss io_uring", ["tests/l4/mss.py", "io_uring"]),
    ("mss epoll", ["tests/l4/mss.py", "epoll"]),
    ("aes256 io_uring", ["tests/tls/aes256.py", "io_uring"]),
    ("aes256 epoll", ["tests/tls/aes256.py", "epoll"]),
    ("h2 abuse io_uring", ["tests/h2/abuse.py", "io_uring"]),
    ("h2 abuse epoll", ["tests/h2/abuse.py", "epoll"]),
    ("l4 io_uring core", ["tests/l4/run.py", "io_uring", "core"]),
    ("l4 io_uring faults", ["tests/l4/run.py", "io_uring", "faults"]),
    ("l4 epoll core", ["tests/l4/run.py", "epoll", "core"]),
    ("l4 epoll faults", ["tests/l4/run.py", "epoll", "faults"]),
    ("dns", ["tests/dns/run.py"]),
    ("overload io_uring", ["tests/overload/run.py", "io_uring"]),
    ("overload epoll", ["tests/overload/run.py", "epoll"]),
    ("reload", ["tests/reload/run.py"]),
    ("lastgood", ["tests/reload/lastgood.py"]),
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
    ("certcomp io_uring", ["tests/tls/certcomp.py", "io_uring"]),
    ("certcomp epoll", ["tests/tls/certcomp.py", "epoll"]),
    ("ech io_uring", ["tests/tls/ech.py", "io_uring"]),
    ("ech epoll", ["tests/tls/ech.py", "epoll"]),
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
    ("h2 upstream io_uring", ["tests/h2/upstream.py", "io_uring"]),
    ("h2 upstream epoll", ["tests/h2/upstream.py", "epoll"]),
    ("h2 fuzz io_uring", ["tests/h2/fuzz.py", "io_uring", "300"]),
    ("h2 fuzz epoll", ["tests/h2/fuzz.py", "epoll", "300"]),
    ("h2spec io_uring", ["tests/h2/h2spec.py", "io_uring"]),
    ("h2spec epoll", ["tests/h2/h2spec.py", "epoll"]),
    ("websocket h2 io_uring", ["tests/h2/websocket.py", "io_uring"]),
    ("websocket h2 epoll", ["tests/h2/websocket.py", "epoll"]),
    ("h3 io_uring", ["tests/h3/run.py", "io_uring"]),
    ("h3 epoll", ["tests/h3/run.py", "epoll"]),
    ("h3 steering io_uring", ["tests/h3/steer.py", "io_uring"]),
    ("h3 steering epoll", ["tests/h3/steer.py", "epoll"]),
    ("h3 bbr io_uring", ["tests/h3/bbr.py", "io_uring"]),
    ("h3 bbr epoll", ["tests/h3/bbr.py", "epoll"]),
    ("h3 bench io_uring", ["tests/h3/bench.py", "io_uring"]),
    ("h3 bench epoll", ["tests/h3/bench.py", "epoll"]),
    ("fault io_uring", ["tests/gateway/fault.py", "io_uring"]),
    ("fault epoll", ["tests/gateway/fault.py", "epoll"]),
    ("limit io_uring", ["tests/gateway/limit.py", "io_uring"]),
    ("limit epoll", ["tests/gateway/limit.py", "epoll"]),
    ("cors io_uring", ["tests/gateway/cors.py", "io_uring"]),
    ("cors epoll", ["tests/gateway/cors.py", "epoll"]),
    ("split io_uring", ["tests/gateway/split.py", "io_uring"]),
    ("split epoll", ["tests/gateway/split.py", "epoll"]),
    ("mirror io_uring", ["tests/gateway/mirror.py", "io_uring"]),
    ("mirror epoll", ["tests/gateway/mirror.py", "epoll"]),
    ("hedge io_uring", ["tests/gateway/hedge.py", "io_uring"]),
    ("hedge epoll", ["tests/gateway/hedge.py", "epoll"]),
    ("overload io_uring", ["tests/gateway/overload.py", "io_uring"]),
    ("overload epoll", ["tests/gateway/overload.py", "epoll"]),
    ("auth io_uring", ["tests/gateway/auth.py", "io_uring"]),
    ("auth epoll", ["tests/gateway/auth.py", "epoll"]),
    ("jwt io_uring", ["tests/gateway/jwt.py", "io_uring"]),
    ("jwt epoll", ["tests/gateway/jwt.py", "epoll"]),
    ("jwks io_uring", ["tests/gateway/jwks.py", "io_uring"]),
    ("jwks epoll", ["tests/gateway/jwks.py", "epoll"]),
    ("upgrade io_uring", ["tests/gateway/upgrade.py", "io_uring"]),
    ("upgrade epoll", ["tests/gateway/upgrade.py", "epoll"]),
    ("admin io_uring", ["tests/gateway/admin.py", "io_uring"]),
    ("admin epoll", ["tests/gateway/admin.py", "epoll"]),
    ("udp io_uring", ["tests/gateway/udp.py", "io_uring"]),
    ("udp epoll", ["tests/gateway/udp.py", "epoll"]),
    ("hash io_uring", ["tests/gateway/hash.py", "io_uring"]),
    ("hash epoll", ["tests/gateway/hash.py", "epoll"]),
    ("sticky io_uring", ["tests/gateway/sticky.py", "io_uring"]),
    ("sticky epoll", ["tests/gateway/sticky.py", "epoll"]),
    ("maxconn io_uring", ["tests/gateway/maxconn.py", "io_uring"]),
    ("maxconn epoll", ["tests/gateway/maxconn.py", "epoll"]),
    ("discover io_uring", ["tests/gateway/discover.py", "io_uring"]),
    ("discover epoll", ["tests/gateway/discover.py", "epoll"]),
    ("docker io_uring", ["tests/gateway/docker.py", "io_uring"]),
    ("docker epoll", ["tests/gateway/docker.py", "epoll"]),
    ("kube io_uring", ["tests/gateway/kube.py", "io_uring"]),
    ("kube epoll", ["tests/gateway/kube.py", "epoll"]),
    ("fleet io_uring", ["tests/gateway/fleet.py", "io_uring"]),
    ("fleet epoll", ["tests/gateway/fleet.py", "epoll"]),
    ("alerts io_uring", ["tests/gateway/alerts.py", "io_uring"]),
    ("alerts epoll", ["tests/gateway/alerts.py", "epoll"]),
    ("logsink io_uring", ["tests/gateway/logsink.py", "io_uring"]),
    ("logsink epoll", ["tests/gateway/logsink.py", "epoll"]),
    ("tracing io_uring", ["tests/gateway/tracing.py", "io_uring"]),
    ("tracing epoll", ["tests/gateway/tracing.py", "epoll"]),
    ("top io_uring", ["tests/gateway/top.py", "io_uring"]),
    ("top epoll", ["tests/gateway/top.py", "epoll"]),
    ("errpage io_uring", ["tests/gateway/errpage.py", "io_uring"]),
    ("errpage epoll", ["tests/gateway/errpage.py", "epoll"]),
    ("maint io_uring", ["tests/gateway/maint.py", "io_uring"]),
    ("maint epoll", ["tests/gateway/maint.py", "epoll"]),
    ("landlock io_uring", ["tests/gateway/landlock.py", "io_uring"]),
    ("landlock epoll", ["tests/gateway/landlock.py", "epoll"]),
    ("privdrop io_uring", ["tests/gateway/privdrop.py", "io_uring"]),
    ("privdrop epoll", ["tests/gateway/privdrop.py", "epoll"]),
    ("systemd io_uring", ["tests/gateway/systemd.py", "io_uring"]),
    ("systemd epoll", ["tests/gateway/systemd.py", "epoll"]),
    ("goaway io_uring", ["tests/gateway/goaway.py", "io_uring"]),
    ("goaway epoll", ["tests/gateway/goaway.py", "epoll"]),
    ("geoip io_uring", ["tests/gateway/geoip.py", "io_uring"]),
    ("geoip epoll", ["tests/gateway/geoip.py", "epoll"]),
    ("acl io_uring", ["tests/gateway/acl.py", "io_uring"]),
    ("acl epoll", ["tests/gateway/acl.py", "epoll"]),
    ("idem io_uring", ["tests/gateway/idem.py", "io_uring"]),
    ("idem epoll", ["tests/gateway/idem.py", "epoll"]),
    ("rmaphold io_uring", ["tests/gateway/rmaphold.py", "io_uring"]),
    ("rmaphold epoll", ["tests/gateway/rmaphold.py", "epoll"]),
    ("hints io_uring", ["tests/gateway/hints.py", "io_uring"]),
    ("hints epoll", ["tests/gateway/hints.py", "epoll"]),
    ("route", ["tests/gateway/route.py"]),
    ("compress io_uring", ["tests/gateway/compress.py", "io_uring"]),
    ("compress epoll", ["tests/gateway/compress.py", "epoll"]),
    ("files io_uring", ["tests/gateway/files.py", "io_uring"]),
    ("files epoll", ["tests/gateway/files.py", "epoll"]),
    ("match io_uring", ["tests/gateway/match.py", "io_uring"]),
    ("match epoll", ["tests/gateway/match.py", "epoll"]),
    ("cache io_uring", ["tests/gateway/cache.py", "io_uring"]),
    ("cache epoll", ["tests/gateway/cache.py", "epoll"]),
    ("cachedisk io_uring", ["tests/gateway/cachedisk.py", "io_uring"]),
    ("cachedisk epoll", ["tests/gateway/cachedisk.py", "epoll"]),
    ("zerocopy io_uring", ["tests/gateway/zerocopy.py", "io_uring"]),
    ("zerocopy epoll", ["tests/gateway/zerocopy.py", "epoll"]),
    ("cachekeys io_uring", ["tests/gateway/cachekeys.py", "io_uring"]),
    ("cachekeys epoll", ["tests/gateway/cachekeys.py", "epoll"]),
    ("purge io_uring", ["tests/gateway/purge.py", "io_uring"]),
    ("purge epoll", ["tests/gateway/purge.py", "epoll"]),
    ("slice io_uring", ["tests/gateway/slice.py", "io_uring"]),
    ("slice epoll", ["tests/gateway/slice.py", "epoll"]),
    ("signed io_uring", ["tests/gateway/signed.py", "io_uring"]),
    ("signed epoll", ["tests/gateway/signed.py", "epoll"]),
    ("ranges io_uring", ["tests/gateway/ranges.py", "io_uring"]),
    ("ranges epoll", ["tests/gateway/ranges.py", "epoll"]),
    ("originpull io_uring", ["tests/gateway/originpull.py", "io_uring"]),
    ("originpull epoll", ["tests/gateway/originpull.py", "epoll"]),
    ("shield io_uring", ["tests/gateway/shield.py", "io_uring"]),
    ("shield epoll", ["tests/gateway/shield.py", "epoll"]),
    ("bird io_uring", ["tests/gateway/bird.py", "io_uring"]),
    ("bird epoll", ["tests/gateway/bird.py", "epoll"]),
    ("vrrp io_uring", ["tests/gateway/vrrp.py", "io_uring"]),
    ("vrrp epoll", ["tests/gateway/vrrp.py", "epoll"]),
    ("vrrp6 io_uring", ["tests/gateway/vrrp6.py", "io_uring"]),
    ("vrrp6 epoll", ["tests/gateway/vrrp6.py", "epoll"]),
    ("certgen io_uring", ["tests/gateway/certgen.py", "io_uring"]),
    ("certgen epoll", ["tests/gateway/certgen.py", "epoll"]),
    ("acme io_uring", ["tests/gateway/acme.py", "io_uring"]),
    ("acme epoll", ["tests/gateway/acme.py", "epoll"]),
    ("acmefb io_uring", ["tests/gateway/acmefb.py", "io_uring"]),
    ("acmefb epoll", ["tests/gateway/acmefb.py", "epoll"]),
    ("ocsp io_uring", ["tests/gateway/ocsp.py", "io_uring"]),
    ("ocsp epoll", ["tests/gateway/ocsp.py", "epoll"]),
    ("acmeod io_uring", ["tests/gateway/acmeod.py", "io_uring"]),
    ("acmeod epoll", ["tests/gateway/acmeod.py", "epoll"]),
    ("acmefleet io_uring", ["tests/gateway/acmefleet.py", "io_uring"]),
    ("acmefleet epoll", ["tests/gateway/acmefleet.py", "epoll"]),
    ("localca io_uring", ["tests/gateway/localca.py", "io_uring"]),
    ("localca epoll", ["tests/gateway/localca.py", "epoll"]),
    ("acmeauto io_uring", ["tests/gateway/acmeauto.py", "io_uring"]),
    ("acmeauto epoll", ["tests/gateway/acmeauto.py", "epoll"]),
    ("certexpiry io_uring", ["tests/gateway/certexpiry.py", "io_uring"]),
    ("certexpiry epoll", ["tests/gateway/certexpiry.py", "epoll"]),
    ("mtlsca io_uring", ["tests/gateway/mtlsca.py", "io_uring"]),
    ("mtlsca epoll", ["tests/gateway/mtlsca.py", "epoll"]),
    ("fastcgi io_uring", ["tests/gateway/fastcgi.py", "io_uring"]),
    ("fastcgi epoll", ["tests/gateway/fastcgi.py", "epoll"]),
    ("regex io_uring", ["tests/gateway/regex.py", "io_uring"]),
    ("regex epoll", ["tests/gateway/regex.py", "epoll"]),
    ("grpcweb io_uring", ["tests/gateway/grpcweb.py", "io_uring"]),
    ("grpcweb epoll", ["tests/gateway/grpcweb.py", "epoll"]),
    ("brotli io_uring", ["tests/gateway/brotli.py", "io_uring"]),
    ("brotli epoll", ["tests/gateway/brotli.py", "epoll"]),
    ("consul io_uring", ["tests/gateway/consul.py", "io_uring"]),
    ("consul epoll", ["tests/gateway/consul.py", "epoll"]),
    ("gwapi io_uring", ["tests/gateway/gwapi.py", "io_uring"]),
    ("gwapi epoll", ["tests/gateway/gwapi.py", "epoll"]),
    ("forward io_uring", ["tests/gateway/forward.py", "io_uring"]),
    ("forward epoll", ["tests/gateway/forward.py", "epoll"]),
    ("mtls io_uring", ["tests/gateway/mtls.py", "io_uring"]),
    ("mtls epoll", ["tests/gateway/mtls.py", "epoll"]),
    ("chain io_uring", ["tests/gateway/chain.py", "io_uring"]),
    ("chain epoll", ["tests/gateway/chain.py", "epoll"]),
    ("policy io_uring", ["tests/gateway/policy.py", "io_uring"]),
    ("policy epoll", ["tests/gateway/policy.py", "epoll"]),
    ("jwt fuzz io_uring", ["tests/gateway/jwtfuzz.py", "io_uring", "7", "15000"]),
    ("jwt fuzz epoll", ["tests/gateway/jwtfuzz.py", "epoll", "8", "15000"]),
]


def netns_ok():
    try:
        return subprocess.run(["unshare", "-rn", "true"], capture_output=True).returncode == 0
    except OSError:
        return False


# a private network with loopback up, then the suite
NETNS = ["unshare", "-rn", "sh", "-c", 'ip link set lo up && exec "$0" "$@"']


# a suite takes about a minute at most; past this it is stuck
SUITE_TIMEOUT = int(os.environ.get("OKENA_SUITE_TIMEOUT", "150"))
running = []


def kill_group(p):
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except OSError:
        pass


def main():
    words = sys.argv[1:]
    # stopped (make's timeout, ^C): every suite with it, not orphans
    def stop(sig, frame):
        for p in list(running):
            kill_group(p)
        sys.exit(128 + sig)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
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
        # (privdrop makes one with uids to spare, unshare --map-auto)
        if isolate and name not in ("dns", "wycheproof") and not name.startswith("privdrop"):
            argv = NETNS + argv
        # a session of its own: a suite that hangs is killed whole (its okena,
        # its backends), never left running
        p = subprocess.Popen(argv, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        with lock:
            running.append(p)
        try:
            out, _ = p.communicate(timeout=SUITE_TIMEOUT)   # read as it comes: a full pipe never stalls a suite
            ok = p.returncode == 0
        except subprocess.TimeoutExpired:
            kill_group(p)
            out, _ = p.communicate()
            out += f"\nrun_all: timed out after {SUITE_TIMEOUT} s, killed with all it started\n".encode()
            ok = False
        with lock:
            running.remove(p)
            results.append((name, ok, time.time() - start, out.decode(errors="replace")))
            print(f"{'ok  ' if ok else 'FAIL'} {name:<20} {time.time() - start:5.1f}s", flush=True)

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
