#!/usr/bin/env python3
"""Worker affinity. `pin_workers auto` (the default): an idle worker may run on
every CPU okena was given (pinned on a shared host, a worker waited for
whatever took its core: p99.9 ten times worse), one under load is on a core
of its own (free under load, two workers shared a core: p99 five times worse),
and lets go when the load goes; `on` always pinned, `off` never."""
import os
import pathlib
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build" / "okena"
PORT = 47000 + os.getpid() % 900
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


def workers(p):
    return [int(c) for t in os.listdir(f"/proc/{p.pid}/task")
            for c in open(f"/proc/{p.pid}/task/{t}/children").read().split()]


def cpu(k):
    """A process's CPU time, seconds."""
    f = open(f"/proc/{k}/stat").read().rsplit(")", 1)[1].split()
    return (int(f[11]) + int(f[12])) / os.sysconf("SC_CLK_TCK")


def affinities(p):
    kids = []
    for _ in range(100):
        kids = [int(c) for t in os.listdir(f"/proc/{p.pid}/task")
                for c in open(f"/proc/{p.pid}/task/{t}/children").read().split()]
        if len(kids) == 2 and all(open(f"/proc/{k}/comm").read().strip() == "okena-worker" for k in kids):
            break
        time.sleep(0.05)
    return sorted(sorted(os.sched_getaffinity(k)) for k in kids)


def run(pin, load=False):
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="okena-pin-"))
    conf = tmp / "okena.conf"
    conf.write_text(f"okena {{ workers 2{'; pin_workers ' + pin if pin else ''} }}\n"
                    f"http 127.0.0.1:{PORT} {{ route /* {{ respond 200 \"ok\" }} }}\n")
    p = subprocess.Popen(["taskset", "-c", "0,1", str(BIN), "-c", str(conf)], stderr=subprocess.DEVNULL)
    try:
        time.sleep(0.5)
        idle = affinities(p)
        busy = after = None
        if load:
            # as much as two cores take, for 3 s: each worker past half its time
            # (two cores for the load, not more: the other suites run beside)
            b = subprocess.Popen(["taskset", "-c", "2,3", str(BIN), "bench", f"http://127.0.0.1:{PORT}/",
                                  "conns=16", "workers=2", "duration=3s", "warmup=0s"], stdout=subprocess.DEVNULL)
            t = time.time()
            ks = workers(p)
            c0 = {k: cpu(k) for k in ks}
            while time.time() - t < 3 and busy != [[0], [1]]:
                time.sleep(0.25)
                busy = affinities(p)
            share = min((cpu(k) - c0[k]) / (time.time() - t) for k in ks)
            b.wait(15)
            t = time.time()
            while time.time() - t < 6 and after != [[0, 1], [0, 1]]:
                time.sleep(0.25)
                after = affinities(p)
        return idle, busy, after, share if load else None
    finally:
        p.terminate()
        p.wait(10)


idle, busy, after, share = run(None, load=True)
check("auto, idle: each worker may run on every CPU it was given", idle == [[0, 1], [0, 1]], idle)
# (a host loaded by other work leaves each worker less than half its time:
# then it stays free, which is the point)
if share > 0.6:
    check(f"  under load ({share:.0%} of a core each): each on a core of its own", busy == [[0], [1]], busy)
elif share < 0.4:
    check(f"  under load on a busy host ({share:.0%} of a core each): free still", busy == [[0, 1], [0, 1]], busy)
check("  the load gone: free again", after == [[0, 1], [0, 1]], after)
idle = run("on")[0]
check("on: each on a core of its own from the start", idle == [[0], [1]], idle)
idle, busy, _, _ = run("off", load=True)
check("off: free, under load too", idle == [[0, 1], [0, 1]] and busy == [[0, 1], [0, 1]], (idle, busy))
print("pinning: " + ("all passed" if not fails else f"{fails} failed"))
sys.exit(1 if fails else 0)
