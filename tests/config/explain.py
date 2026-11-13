#!/usr/bin/env python3
"""`okena explain FILE`: the configuration as okena will run it, defaults
written out (pools, listeners, routes, retries, timeouts), compared with what
it should say for tests/config/explain.conf.in; a file with errors: exit 2."""
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
BIN = HERE.parent.parent / "build" / "okena"
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


r = subprocess.run([str(BIN), "explain", str(HERE / "explain.conf.in")], capture_output=True, text=True, timeout=10)
want = (HERE / "explain.want").read_text()
if r.stdout != want:
    import difflib
    sys.stdout.writelines(difflib.unified_diff(want.splitlines(True), r.stdout.splitlines(True), "want", "got"))
check("defaults written out, as compiled", r.returncode == 0 and r.stdout == want, r.stderr[-300:])
with tempfile.NamedTemporaryFile("w", suffix=".conf") as f:
    f.write("http :8080 {\n")
    f.flush()
    r = subprocess.run([str(BIN), "explain", f.name], capture_output=True, text=True, timeout=10)
    check("a file with errors: its errors, exit 2", r.returncode == 2 and "error" in r.stderr, r.returncode)
def explain(text):
    with tempfile.NamedTemporaryFile("w", suffix=".conf") as f:
        f.write(text)
        f.flush()
        return subprocess.run([str(BIN), "explain", f.name], capture_output=True, text=True, timeout=10).stdout


base = "pool p { server 127.0.0.1:9 }\nhttp 127.0.0.1:9000 { route /* { to pool p } }\n"
o = explain("okena { workers 1; profile latency }\n" + base)
check("profile latency: busy_poll 50us", "profile latency" in o and "busy_poll 50us" in o, o[:300])
o = explain("okena { workers 1; profile latency; busy_poll 10us }\n" + base)
check("  a busy_poll of its own wins", "busy_poll 10us" in o, o[:300])
o = explain("okena { workers 1; profile memory-lean }\n" + base)
check("profile memory-lean: 32 idle connections a server", "max=32 " in o and "busy_poll 0s" in o, o)
o = explain("okena { workers 1; profile memory-lean }\npool p { server 127.0.0.1:9; connect max=100 }\nhttp 127.0.0.1:9000 { route /* { to pool p } }\n")
check("  a pool's own max= wins", "max=100 " in o, o)
o = explain("okena { workers 1 }\n" + base)
check("no profile: balanced, busy_poll auto", "profile balanced" in o and "max=512 " in o and "busy_poll auto" in o, o[:300])
o = explain("okena { workers 1; busy_poll 0us }\n" + base)
check("  busy_poll 0us: off", "busy_poll 0s" in o, o[:300])
o = explain("okena { workers 1; profile throughput }\n" + base)
check("profile throughput: no polling", "busy_poll 0s" in o, o[:300])
o = explain("okena { workers 1; profile latency; busy_poll auto }\n" + base)
check("busy_poll auto, written: auto whatever the profile", "busy_poll auto" in o, o[:300])
o = explain("okena { }\n" + base)
check("workers auto: what this host gives, never 0", "workers 0\n" not in o and "workers " in o, o[:100])

# explain is a view, not all of a file (no route filters, no certificates,
# inline pools as `pool (inline N)`), but what it prints of a configuration
# with named pools and no filters is configuration again: it checks, and
# explaining it gives it back (every default it writes out can be written)
full = """okena { workers 2; profile latency; busy_poll auto }
pool api { server 127.0.0.1:3000; health http HEAD /healthz expect=200..204 host=api.internal }
pool g { server 127.0.0.1:9000; protocol h2; health grpc my.Svc }
pool t { server 127.0.0.1:5000; health tcp every=1s }
tcp 127.0.0.1:9432 { to pool t; limits { connections 5000 } }
udp 127.0.0.1:9053 { to pool t; responses 1 }
http 127.0.0.1:9080 { http2 on; route /api/* { to pool api }; route /g/* { to pool g } }
"""
once = explain(full)
with tempfile.NamedTemporaryFile("w", suffix=".conf") as f:
    f.write(once)
    f.flush()
    r = subprocess.run([str(BIN), "check", f.name], capture_output=True, text=True, timeout=10)
check("its output is configuration that checks", r.returncode == 0, r.stdout[-300:] + r.stderr[-300:])
check("  and explaining it again gives the same", explain(once) == once, once[:300])
check("  a health check keeps its method, path, expect and host",
      "health http HEAD /healthz every=2s timeout=1s rise=2 fall=3 expect=200..204 host=api.internal" in once
      and "health grpc my.Svc " in once, once)
print("explain: " + ("all passed" if not fails else f"{fails} failed"))
sys.exit(1 if fails else 0)
