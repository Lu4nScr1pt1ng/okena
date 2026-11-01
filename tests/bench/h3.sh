#!/bin/bash
# HTTP/3 against HAProxy and nginx: okena, HAProxy 3.2 and nginx 1.27
# (official images, host network) on the same two cores in front of the
# same backend (l4bench http, answers "ok"), loaded by h2load built with
# HTTP/3 (tests/bench/h3/Dockerfile: nghttp2, ngtcp2, nghttp3, OpenSSL
# 3.5) on cores of its own. ECDSA P-256, X25519 for every server.
#
#   many streams: 64 connections, 10 requests in flight on each, closed
#     loop: requests/s and the requests' p50 / p99 / p99.9 / max
#   handshakes: a new connection per request at fixed rates (h2load
#     --rate): the rate reached, the requests' latency after the
#     handshake, time to the first byte (connect included), failures
#   flood: 60 connections at 300 requests/s each, quiet and then while
#     two senders replay real client Initials that are never answered
#     (tests/bench/h3flood.py, about 300k a second)
#
# Output: markdown rows for docs/BENCHMARK.md.
#
#   tests/bench/h3.sh            (needs docker, gcc, openssl)
#
# Cores (8 cores / 16 threads, SMT siblings i and i + 8): the proxy on 1-2,
# the backend on 4-5, the load on the four other physical cores.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OKENA=$ROOT/build/okena
H2LOAD_IMAGE=${H2LOAD_IMAGE:-okena-h2load-h3}
HAPROXY_IMAGE=${HAPROXY_IMAGE:-haproxy:3.2}
NGINX_IMAGE=${NGINX_IMAGE:-nginx:1.27-alpine}
PROXY_CPUS=${PROXY_CPUS:-1,2}
BACK_CPUS=${BACK_CPUS:-4,5}
LOAD_CPUS=${LOAD_CPUS:-0,3,6,7,8,11,14,15}
DUR=${DUR:-10}
NEW_RATES=${NEW_RATES:-2000 5000 10000}
W=$(mktemp -d)
chmod 777 "$W"
BPID= OKPID=
trap 'docker rm -f okb-h3hap okb-h3ngx >/dev/null 2>&1 || true; for p in $OKPID $BPID; do kill $p 2>/dev/null; done; rm -rf "$W"' EXIT
cd "$W"
docker rm -f okb-h3hap okb-h3ngx >/dev/null 2>&1 || true

docker image inspect "$H2LOAD_IMAGE" >/dev/null 2>&1 ||
	docker build -q -t "$H2LOAD_IMAGE" "$ROOT/tests/bench/h3" >/dev/null
gcc -O2 -pthread -o l4bench "$ROOT/tests/bench/l4bench.c"
taskset -c "$BACK_CPUS" ./l4bench http 28310 2 & BPID=$!
openssl ecparam -genkey -name prime256v1 -noout -out key.pem 2>/dev/null
openssl req -new -x509 -key key.pem -subj /CN=localhost -addext subjectAltName=DNS:localhost \
	-days 2 -out cert.pem 2>/dev/null
cat cert.pem key.pem > combined.pem
chmod 644 ./*.pem
cat > okena.conf <<EOF
okena { workers 2 }
http 127.0.0.1:28302 {
	http3 on
	tls { cert $W/cert.pem; key $W/key.pem }
	route /* { to 127.0.0.1:28310 }
}
EOF
cat > haproxy.cfg <<EOF
global
	nbthread 2
	maxconn 200000
defaults
	timeout connect 5s
	timeout client 30s
	timeout server 30s
frontend f_h3
	mode http
	bind quic4@127.0.0.1:28402 ssl crt /w/combined.pem alpn h3
	default_backend b_http
backend b_http
	mode http
	http-reuse always
	server s1 127.0.0.1:28310
EOF
cat > nginx.conf <<EOF
worker_processes 2;
error_log /dev/stderr error;
events { worker_connections 65535; }
http {
	access_log off;
	http3_max_concurrent_streams 128;
	keepalive_requests 1000000;
	upstream b { server 127.0.0.1:28310; keepalive 512; }
	server {
		listen 127.0.0.1:28502 quic reuseport;
		ssl_certificate /w/cert.pem;
		ssl_certificate_key /w/key.pem;
		ssl_protocols TLSv1.3;
		location / { proxy_pass http://b; proxy_http_version 1.1; proxy_set_header Connection ""; }
	}
}
EOF
chmod 644 okena.conf haproxy.cfg nginx.conf

taskset -c "$PROXY_CPUS" "$OKENA" -c okena.conf 2>okena.log & OKPID=$!
docker run -d --name okb-h3hap --network host --cpuset-cpus "$PROXY_CPUS" --ulimit nofile=1048576 \
	-v "$W":/w:ro "$HAPROXY_IMAGE" haproxy -f /w/haproxy.cfg >/dev/null
docker run -d --name okb-h3ngx --network host --cpuset-cpus "$PROXY_CPUS" --ulimit nofile=1048576 \
	-v "$W":/w:ro "$NGINX_IMAGE" nginx -c /w/nginx.conf -g 'daemon off;' >/dev/null
sleep 2

# load ARGS...: h2load's summary in $W/out, its request log in $W/req.log
load() {
	rm -f req.log
	docker run --rm --network host --cpuset-cpus "$LOAD_CPUS" --ulimit nofile=1048576 \
		--user "$(id -u):$(id -g)" -v "$W":/out "$H2LOAD_IMAGE" --alpn-list=h3 -t 8 \
		--log-file=/out/req.log "$@" >out 2>&1 || true
}
# "rps p50 p99 p99.9 max failed" (latency in us, from the request log)
stats() {
	local rps failed
	rps=$(awk '/^finished in/ { print $4 }' out)
	failed=$(awk '/^requests:/ { print $10 + $12 + $14 }' out)
	sort -n -k3 req.log | awk -v rps="$rps" -v failed="$failed" '{ d[NR] = $3 }
		END { if (NR == 0) { print rps, "-", "-", "-", "-", failed; exit }
			printf "%s %d %d %d %d %s\n", rps, d[int(NR * .5) + 1], d[int(NR * .99) + 1],
				d[int(NR * .999) + 1], d[NR], failed }'
}
ttfb() {	# time to 1st byte: "mean max"
	awk '/^time to 1st byte:/ { print $7, $6 }' out
}
row() {	# scenario server rps p50 p99 p999 max failed [ttfb]
	printf '| %s | %s | %s | %s / %s / %s / %s | %s |%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "${9:+ $9 |}"
}

echo '| HTTP/3, many streams (64 x 10) | server | requests/s | p50 / p99 / p99.9 / max (µs) | failed |'
echo '|---|---|---|---|---|'
for s in "okena, 2 workers:28302" "HAProxy 3.2, 2 threads:28402" "nginx 1.27, 2 workers:28502"; do
	load -c 64 -m 10 -D "$DUR" "https://127.0.0.1:${s##*:}/"
	read -ra r < <(stats)
	row "closed loop" "${s%:*}" "${r[@]}"
done
echo
echo '| HTTP/3, a new connection each | server | requests/s | p50 / p99 / p99.9 / max (µs) | failed | first byte, mean / max |'
echo '|---|---|---|---|---|---|'
for rate in $NEW_RATES; do
	for s in "okena, 2 workers:28302" "HAProxy 3.2, 2 threads:28402" "nginx 1.27, 2 workers:28502"; do
		n=$((rate * DUR))
		load -c "$n" -n "$n" --rate $((rate / 10)) --rate-period 100ms "https://127.0.0.1:${s##*:}/"
		read -ra r < <(stats)
		read -ra t < <(ttfb)
		row "$rate/s" "${s%:*}" "${r[@]}" "${t[0]:-} / ${t[1]:-}"
	done
done
echo
echo '| HTTP/3, keep-alive at 18k/s (60 x 300/s) | server | requests/s | p50 / p99 / p99.9 / max (µs) | failed |'
echo '|---|---|---|---|---|'
# the Initial flood: two senders of real client Initials, never answered
# (tests/bench/h3flood.py), on two load cores of their own
FLOOD_CPUS=${FLOOD_CPUS:-7,15}
KA_CPUS=${KA_CPUS:-0,3,6,8,11,14}
for s in "okena, 2 workers:28302" "HAProxy 3.2, 2 threads:28402" "nginx 1.27, 2 workers:28502"; do
	for flood in no yes; do
		pids=
		if [ $flood = yes ]; then
			for c in ${FLOOD_CPUS//,/ }; do
				taskset -c "$c" "$ROOT/tests/bench/h3flood.py" 127.0.0.1 "${s##*:}" $((DUR + 8)) >/dev/null & pids="$pids $!"
			done
			sleep 4
		fi
		LOAD_CPUS=$KA_CPUS load -c 60 -m 1 --rps 300 -D "$DUR" "https://127.0.0.1:${s##*:}/"
		read -ra r < <(stats)
		row "$([ $flood = yes ] && echo 'under an Initial flood' || echo 'quiet')" "${s%:*}" "${r[@]}"
		for p in $pids; do wait "$p" 2>/dev/null || true; done
	done
done
