#!/bin/bash
# HTTP/1.1 reverse proxy against Envoy, HAProxy and nginx: the same two cores,
# the same backend (nginx answering "ok" from memory), plain HTTP, keep-alive
# both sides, a small answer: what a proxy costs per request. Each proxy tuned
# by its own documentation: upstream keep-alive (nginx `keepalive`, HAProxy
# `http-reuse always`), Envoy's circuit breakers out of the way, each with as
# many threads as cores. First the most each does (closed loop, wrk), then the
# latency each gives at fixed rates (open loop, okena bench: from the
# schedule, as wrk2), each point REPEAT times and the median of each
# percentile given (on a host that is not quiet, one bad run moves a tail).
# Output: markdown rows for docs/BENCHMARK.md.
#
#   tests/bench/http.sh             (needs docker, the three images, wrk)
#
# Every one of them in a container (host network, the same --cpuset-cpus):
# okena from this tree's image (docker build, `okena:bench`), with the seccomp
# profile it ships (docker/okena.seccomp.json: Docker's default blocks
# io_uring; ENGINE=epoll runs it without), the others from their images.
#
# Cores (8 cores / 16 threads, SMT siblings i and i + 8): the proxy on 1-2
# (9-10 idle), the backend on 4-5 (12-13 idle), the load on the others.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OKENA=$ROOT/build/okena
OKENA_IMAGE=${OKENA_IMAGE:-okena:bench}
ENGINE=${ENGINE:-io_uring}
ENVOY_IMAGE=${ENVOY_IMAGE:-envoyproxy/envoy:v1.40-latest}
HAPROXY_IMAGE=${HAPROXY_IMAGE:-haproxy:3.2}
NGINX_IMAGE=${NGINX_IMAGE:-nginx:1.27-alpine}
PROXY_CPUS=${PROXY_CPUS:-1,2}
NPROXY=${NPROXY:-2}
BACK_CPUS=${BACK_CPUS:-4,5,12,13}
LOAD_CPUS=${LOAD_CPUS:-0,3,6,7,8,11,14,15}
DUR=${DUR:-10s}
CONNS=${CONNS:-256}
RATES=${RATES:-}
REPEAT=${REPEAT:-3}		# each latency point this many times: the median of each percentile
ONLY=${ONLY:-okena envoy haproxy nginx}
B=28600 OK=28601 EN=28602 HA=28603 NG=28604
W=$(mktemp -d)
chmod 755 "$W"
trap 'docker rm -f okh-back okh-okena okh-envoy okh-haproxy okh-nginx >/dev/null 2>&1 || true; rm -rf "$W"' EXIT
docker build -q -t "$OKENA_IMAGE" "$ROOT" >/dev/null

cat > "$W/back.conf" <<EOF
worker_processes 4;
events { worker_connections 65536; }
http {
	access_log off;
	keepalive_requests 1000000;
	server { listen 127.0.0.1:$B reuseport backlog=65535; location / { return 200 "ok"; } }
}
EOF
cat > "$W/okena.conf" <<EOF
okena { workers $NPROXY; io_engine $ENGINE }
pool b { server 127.0.0.1:$B }
http 127.0.0.1:$OK { route /* { to pool b } }
EOF
cat > "$W/envoy.yaml" <<EOF
static_resources:
  listeners:
  - address: { socket_address: { address: 127.0.0.1, port_value: $EN } }
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: h
          codec_type: HTTP1
          generate_request_id: false
          route_config:
            virtual_hosts:
            - name: all
              domains: ["*"]
              routes:
              - match: { prefix: "/" }
                route: { cluster: b }
          http_filters:
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
              dynamic_stats: false
  clusters:
  - name: b
    type: STATIC
    circuit_breakers:
      thresholds:
      - { max_connections: 1000000, max_pending_requests: 1000000, max_requests: 1000000 }
    load_assignment:
      cluster_name: b
      endpoints:
      - lb_endpoints:
        - endpoint: { address: { socket_address: { address: 127.0.0.1, port_value: $B } } }
EOF
cat > "$W/haproxy.cfg" <<EOF
global
	nbthread $NPROXY
	maxconn 200000
	tune.bufsize 16384
defaults
	mode http
	timeout connect 5s
	timeout client 30s
	timeout server 30s
	http-reuse always
frontend f
	bind 127.0.0.1:$HA
	default_backend b
backend b
	server s 127.0.0.1:$B
EOF
cat > "$W/nginx.conf" <<EOF
worker_processes $NPROXY;
events { worker_connections 65536; }
http {
	access_log off;
	keepalive_requests 1000000;
	upstream b { server 127.0.0.1:$B; keepalive 1024; keepalive_requests 1000000; }
	server {
		listen 127.0.0.1:$NG reuseport backlog=65535;
		location / { proxy_pass http://b; proxy_http_version 1.1; proxy_set_header Connection ""; }
	}
}
EOF
chmod 644 "$W"/*

docker run -d --rm --name okh-back --network host --cpuset-cpus "$BACK_CPUS" \
	-v "$W/back.conf:/etc/nginx/nginx.conf:ro" "$NGINX_IMAGE" >/dev/null
sleep 1

# max PORT: requests a second, closed loop (wrk)
max() {
	taskset -c "$LOAD_CPUS" wrk -t8 -c"$CONNS" -d"$DUR" "http://127.0.0.1:$1/" 2>&1 |
		awk '/Requests\/sec/ { printf "%d", $2 }'
}
# lat PORT RATE: "p50 p99 p99.9 max behind errors" (us), open loop
lat() {
	taskset -c "$LOAD_CPUS" "$OKENA" bench "http://127.0.0.1:$1/" rate="$2" conns=64 workers=4 duration="$DUR" format=kv 2>&1 |
		tr ' ' '\n' | awk -F= '{ v[$1] = $2 } END { printf "%d %d %d %d %d %d", v["c_p50_ns"] / 1000, v["c_p99_ns"] / 1000,
			v["c_p999_ns"] / 1000, v["c_max_ns"] / 1000, v["behind"], v["errors"] + v["timeouts"] }' ; echo
}

start() {	# name
	case $1 in
	okena) docker run -d --rm --name okh-okena --network host --cpuset-cpus "$PROXY_CPUS" \
		--security-opt seccomp="$ROOT/docker/okena.seccomp.json" \
		-v "$W/okena.conf:/etc/okena/okena.conf:ro" "$OKENA_IMAGE" >/dev/null ;;
	envoy) docker run -d --rm --name okh-envoy --network host --cpuset-cpus "$PROXY_CPUS" -v "$W:/w:ro" \
		"$ENVOY_IMAGE" envoy -c /w/envoy.yaml --concurrency "$NPROXY" -l warn >/dev/null ;;
	haproxy) docker run -d --rm --name okh-haproxy --network host --cpuset-cpus "$PROXY_CPUS" \
		-v "$W/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro" "$HAPROXY_IMAGE" >/dev/null ;;
	nginx) docker run -d --rm --name okh-nginx --network host --cpuset-cpus "$PROXY_CPUS" \
		-v "$W/nginx.conf:/etc/nginx/nginx.conf:ro" "$NGINX_IMAGE" >/dev/null ;;
	esac
	sleep 2
}
stop() { docker rm -f "okh-$1" >/dev/null; }
port() { case $1 in okena) echo $OK ;; envoy) echo $EN ;; haproxy) echo $HA ;; nginx) echo $NG ;; esac; }

MAXRUN=${MAXRUN:-1}
if [ "$MAXRUN" = 1 ]; then
echo "direct to the backend: $(max $B) req/s"
echo
echo "| Proxy ($NPROXY cores) | most req/s | per core |"
echo "|---|---|---|"
declare -A MOST
for p in $ONLY; do
	start "$p"
	MOST[$p]=$(max "$(port "$p")")
	printf '| %s | %s | %s |\n' "$p" "${MOST[$p]}" $(( ${MOST[$p]} / NPROXY ))
	stop "$p"
done
fi
if [ -n "$RATES" ]; then
	echo
	echo "| Proxy | rate | p50 / p99 / p99.9 / max (us) | behind | errors |"
	echo "|---|---|---|---|---|"
	for p in $ONLY; do
		start "$p"
		for r in $RATES; do
			read -ra v < <(for i in $(seq "$REPEAT"); do lat "$(port "$p")" "$r"; done |
				awk '{ for (i = 1; i <= NF; i++) c[i, NR] = $i } END { for (i = 1; i <= 6; i++) {
					n = 0; for (j = 1; j <= NR; j++) a[++n] = c[i, j]
					for (x = 1; x <= n; x++) for (y = x + 1; y <= n; y++) if (a[y] < a[x]) { t = a[x]; a[x] = a[y]; a[y] = t }
					printf "%s ", a[int((n + 1) / 2)] } print "" }')
			printf '| %s | %s/s | %s / %s / %s / %s | %s | %s |\n' "$p" "$r" "${v[0]}" "${v[1]}" "${v[2]}" "${v[3]}" "${v[4]}" "${v[5]}"
		done
		stop "$p"
	done
fi
