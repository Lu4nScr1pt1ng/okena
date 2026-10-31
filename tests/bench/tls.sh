#!/bin/bash
# HTTPS against HAProxy, open loop: okena and HAProxy 3.2 (official image,
# host network) on the same two cores in front of the same backend
# (l4bench http, answers "ok"), loaded by `okena bench` on cores of its
# own. Keep-alive requests and a new connection (a full handshake,
# X25519MLKEM768 and ECDSA P-256) per request: the ceiling closed loop,
# then fixed rates open loop. Output: markdown rows for docs/BENCHMARK.md.
#
#   tests/bench/tls.sh            (needs docker for HAProxy, gcc, openssl)
#
# Cores (8 cores / 16 threads, SMT siblings i and i + 8): the proxy on 1-2
# (siblings 9-10 left idle), the backend on 4-5 (12-13 idle), the load on
# the four other physical cores, both threads of each.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OKENA=$ROOT/build/okena
HAPROXY_IMAGE=${HAPROXY_IMAGE:-haproxy:3.2}
PROXY_CPUS=${PROXY_CPUS:-1,2}
BACK_CPUS=${BACK_CPUS:-4,5}
LOAD_CPUS=${LOAD_CPUS:-0,3,6,7,8,11,14,15}
LOAD_WORKERS=${LOAD_WORKERS:-8}
DUR=${DUR:-10s}
KA_RATES=${KA_RATES:-50000 100000}
NEW_RATES=${NEW_RATES:-2000 5000 10000}
W=$(mktemp -d)
chmod 755 "$W"
BPID= OKPID=
trap 'docker rm -f okb-haproxy >/dev/null 2>&1 || true; for p in $OKPID $BPID; do kill $p 2>/dev/null; done; rm -rf "$W"' EXIT
cd "$W"

gcc -O2 -pthread -o l4bench "$ROOT/tests/bench/l4bench.c"
taskset -c "$BACK_CPUS" ./l4bench http 28300 2 & BPID=$!
openssl ecparam -genkey -name prime256v1 -noout -out key.pem 2>/dev/null
openssl req -new -x509 -key key.pem -subj /CN=localhost -addext subjectAltName=DNS:localhost \
	-days 2 -out cert.pem 2>/dev/null
cat cert.pem key.pem > combined.pem
chmod 644 ./*.pem
cat > okena.conf <<EOF
okena { workers 2 }
http 127.0.0.1:28302 {
	tls { cert $W/cert.pem; key $W/key.pem }
	route /* { to 127.0.0.1:28300 }
}
EOF
cat > haproxy.cfg <<EOF
global
	nbthread 2
	maxconn 100000
	ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256
defaults
	timeout connect 5s
	timeout client 30s
	timeout server 30s
frontend f_https
	mode http
	bind 127.0.0.1:28402 ssl crt /w/combined.pem alpn http/1.1
	default_backend b_http
backend b_http
	mode http
	http-reuse always
	server s1 127.0.0.1:28300
EOF
chmod 644 okena.conf haproxy.cfg

# bench URL ARGS...: "rps behind p50 p99 p99.9 max" (latency in us, from the schedule)
bench() {
	taskset -c "$LOAD_CPUS" "$OKENA" bench "$@" workers="$LOAD_WORKERS" duration="$DUR" format=kv |
		awk '{ for (i = 1; i <= NF; i++) { split($i, kv, "="); v[kv[1]] = kv[2] }
			printf "%s %s %d %d %d %d %s\n", v["rps"], v["behind"], v["c_p50_ns"] / 1000,
				v["c_p99_ns"] / 1000, v["c_p999_ns"] / 1000, v["c_max_ns"] / 1000, v["errors"] + v["other"] }'
}
row() {	# scenario server rps behind p50 p99 p999 max bad
	printf '| %s | %s | %s | %s | %s / %s / %s / %s | %s |\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9"
}
scenarios() {	# label url
	local s=$1 u=$2 r
	read -ra r < <(bench "$u" conns=64)
	row "keep-alive, closed loop" "$s" "${r[@]}"
	for rate in $KA_RATES; do
		read -ra r < <(bench "$u" conns=64 rate="$rate")
		row "keep-alive, $rate/s" "$s" "${r[@]}"
	done
	read -ra r < <(bench "$u" conns=64 new=on)
	row "new connection each, closed loop" "$s" "${r[@]}"
	for rate in $NEW_RATES; do
		read -ra r < <(bench "$u" conns=256 new=on rate="$rate")
		row "new connection each, $rate/s" "$s" "${r[@]}"
	done
}

echo "| Scenario | Server | req/s | behind | p50 / p99 / p99.9 / max (us) | errors |"
echo "|---|---|---|---|---|---|"
taskset -c "$PROXY_CPUS" "$OKENA" -c "$W/okena.conf" 2> okena.log & OKPID=$!
sleep 1
scenarios "okena, 2 cores" https://localhost:28302/
kill $OKPID; wait $OKPID 2>/dev/null || true; OKPID=

docker run -d --rm --name okb-haproxy --network host --cpuset-cpus "$PROXY_CPUS" \
	-v "$W:/w:ro" "$HAPROXY_IMAGE" haproxy -f /w/haproxy.cfg >/dev/null
sleep 1.5
scenarios "HAProxy 3.2, 2 threads" https://localhost:28402/
docker rm -f okb-haproxy >/dev/null
