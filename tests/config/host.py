#!/usr/bin/env python3
"""`okena check --host [FILE]`: a line for each thing of the host, ok or warn,
and the exit status 1 exactly when something warns; with a configuration that
holds more than the descriptors allow, the open files line warns and says
how many it needs."""
import pathlib
import subprocess
import sys
import tempfile

BIN = pathlib.Path(__file__).resolve().parents[2] / "build" / "okena"
fails = 0


def check(name, ok, detail=""):
    global fails
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f": {detail}"), flush=True)
    fails += not ok


r = subprocess.run([str(BIN), "check", "--host"], capture_output=True, text=True, timeout=10)
lines = r.stdout.splitlines()
want = ["conntrack:", "net.core.somaxconn", "net.ipv4.tcp_max_syn_backlog", "ip_local_port_range", "open files:", "kTLS:", "io_uring:"]
check("a line for each check", all(any(w in x for x in lines) for w in want if w != "ip_local_port_range" or pathlib.Path("/proc/sys/net/ipv4/ip_local_port_range").exists()), r.stdout)
check("  each ok or warn", all(x.startswith(("ok    ", "warn  ")) for x in lines), r.stdout)
check("  exit 1 exactly when something warns", r.returncode == (1 if any(x.startswith("warn") for x in lines) else 0), (r.returncode, r.stdout))
with tempfile.NamedTemporaryFile("w", suffix=".conf") as f:
    f.write("pool p { server 127.0.0.1:9 }\nhttp 127.0.0.1:443 { limits { connections 100000000 }; route /* { to pool p } }\n")
    f.flush()
    r = subprocess.run([str(BIN), "check", "--host", f.name], capture_output=True, text=True, timeout=10)
    o = next((x for x in r.stdout.splitlines() if "open files" in x), "")
    check("a configuration past the descriptors: open files warns, with the need", o.startswith("warn") and "200000000" in o and r.returncode == 1, r.stdout)
print("host: " + ("all passed" if not fails else f"{fails} failed"))
sys.exit(1 if fails else 0)
