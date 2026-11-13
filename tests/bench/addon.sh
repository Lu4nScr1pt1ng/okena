#!/bin/bash
# Phase 13's exit: what an addon that answers at once adds to a request.
#
# okena (2 workers) in front of l4bench http; two routes to the same backend,
# one through an addon in C (sdk/c/examples/hello.c: continue, nothing
# changed), one without. okena bench drives each in open loop at fixed rates
# (coordinated omission corrected) and the difference of the percentiles is
# the addon's cost. Cores pinned: okena, its addon, the backend and the load
# each on their own.
#
#   tests/bench/addon.sh                  RATES="5000 20000 50000" DUR=10s CONNS=32 REPS=3
#   SPIN_US=2000 tests/bench/addon.sh     the addon polls 2 ms after a call (`poll`, default 50 us)
#
# Each rate runs the two routes alternately REPS times; each percentile is the
# median of its runs (a single run's p99 moves by 10-15 us on a desktop).
#
# Output: one line a route and rate, then markdown rows for docs/BENCHMARK.md.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OKENA=$ROOT/build/okena
RATES=${RATES:-5000 20000 50000}
DUR=${DUR:-10s}
CONNS=${CONNS:-32}
OKENA_CPUS=${OKENA_CPUS:-1,2}
ADDON_CPU=${ADDON_CPU:-3}
BACKEND_CPUS=${BACKEND_CPUS:-4,5}
BENCH_CPUS=${BENCH_CPUS:-6,7}
SPIN_US=${SPIN_US:-50}
REPS=${REPS:-3}
P=${PORT:-47300}
W=$(mktemp -d)
PIDS=()
trap 'for p in "${PIDS[@]}"; do kill $p 2>/dev/null || true; done; rm -rf "$W"' EXIT

cc -O2 -o "$W/l4bench" "$ROOT/tests/bench/l4bench.c" -lpthread
cc -O2 -o "$W/hello" "$ROOT/sdk/c/examples/hello.c" "$ROOT/sdk/c/okena_addon.c" -I"$ROOT/sdk/c"
taskset -c "$BACKEND_CPUS" "$W/l4bench" http $((P + 1)) 2 & PIDS+=($!)
cat > "$W/okena.conf" <<EOF
okena { workers 2; pin_workers off; metrics 127.0.0.1:$((P + 2)) }
addon hello {
    run /usr/bin/taskset -c $ADDON_CPU $W/hello
    poll ${SPIN_US}us
    timeout 100ms
}
pool b { server 127.0.0.1:$((P + 1)) }
http 127.0.0.1:$P {
    route /addon/* { addon hello; to pool b }
    route /* { to pool b }
}
EOF
taskset -c "$OKENA_CPUS" "$OKENA" -c "$W/okena.conf" 2>"$W/log" & PIDS+=($!)
for _ in $(seq 100); do grep -q "started with" "$W/log" && break; sleep 0.05; done
curl -q -sf "http://127.0.0.1:$P/addon/pass" >/dev/null || { cat "$W/log"; exit 1; }

us() { awk -v n="$1" 'BEGIN { printf "%.1f", n / 1000 }'; }
# the addon's round trips (okena_addon_call_seconds), between two scrapes
hist() { curl -q -s "http://127.0.0.1:$((P + 2))/metrics" | grep '^okena_addon_call_seconds_bucket{addon="hello"'; }
quant() {
	python3 -c '
import sys
a = [l.split() for l in open(sys.argv[1]).read().splitlines()]
b = [l.split() for l in open(sys.argv[2]).read().splitlines()]
les = [x[0].split("le=\"")[1].split("\"")[0] for x in a]
d = [int(y[1]) - int(x[1]) for x, y in zip(a, b)]
n = d[-1]
out = []
for q in (0.5, 0.99, 0.999):
    le = next(les[i] for i in range(len(d)) if d[i] >= q * n)
    out.append("+Inf" if le == "+Inf" else "%.1f" % (float(le) * 1e6))
print(n, *out)' "$1" "$2"
}
declare -A R
med() { tr ' ' '\n' | grep . | sort -n | awk '{ a[NR] = $1 } END { print a[int((NR + 1) / 2)] }'; }
for rate in $RATES; do
	declare -A S=()
	for rep in $(seq "$REPS"); do
		for route in direct addon; do
			path=/direct/pass
			[ $route = addon ] && path=/addon/pass
			[ $route = addon ] && hist > "$W/h0"
			out=$(taskset -c "$BENCH_CPUS" "$OKENA" bench "http://127.0.0.1:$P$path" rate=$rate conns=$CONNS \
				duration=$DUR warmup=2s workers=2 format=kv 2>&1 | tail -1)
			if [ $route = addon ]; then
				hist > "$W/h1"
				read -r hn h50 h99 h999 <<<"$(quant "$W/h0" "$W/h1")"
				S[rt.50]+="$h50 "
				S[rt.99]+="$h99 "
				S[rt.999]+="$h999 "
				echo "  the addon's round trip: $hn calls, p50 <= ${h50}us p99 <= ${h99}us p99.9 <= ${h999}us"
			fi
			eval "$(echo "$out" | tr ' ' '\n' | grep -E '^(c_p50_ns|c_p99_ns|c_p999_ns|rps|errors)=' | sed 's/^/local_/')"
			S[$route.50]+="$local_c_p50_ns "
			S[$route.99]+="$local_c_p99_ns "
			S[$route.999]+="$local_c_p999_ns "
			echo "$route rate=$rate rps=$local_rps errors=$local_errors p50=$(us $local_c_p50_ns)us p99=$(us $local_c_p99_ns)us p99.9=$(us $local_c_p999_ns)us"
		done
	done
	for route in direct addon rt; do
		R[$rate.$route]="$(echo ${S[$route.50]} | med) $(echo ${S[$route.99]} | med) $(echo ${S[$route.999]} | med)"
	done
done
echo
echo "| Rate | p50 without / with (added) | p99 without / with (added) | p99.9 without / with (added) | the call's round trip p50 / p99 / p99.9 (at most) |"
echo "|---|---|---|---|---|"
for rate in $RATES; do
	read -r a50 a99 a999 <<<"${R[$rate.direct]}"
	read -r b50 b99 b999 <<<"${R[$rate.addon]}"
	read -r r50 r99 r999 <<<"${R[$rate.rt]}"
	echo "| $rate/s | $(us $a50) / $(us $b50) µs ($(us $((b50 - a50)))) | $(us $a99) / $(us $b99) µs ($(us $((b99 - a99)))) | $(us $a999) / $(us $b999) µs ($(us $((b999 - a999)))) | $r50 / $r99 / $r999 µs |"
done
