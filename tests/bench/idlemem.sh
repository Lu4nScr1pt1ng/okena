#!/bin/bash
# Memory a proxy holds for idle keep-alive HTTP connections: okena, HAProxy
# 3.2, nginx 1.27 and Envoy 1.40, each in a container on the host network, in
# front of the same backend (l4bench httpbig, 100-byte answers). N clients
# connect (from 127.0.0.2.. as sources), make one request each, read its
# answer and stay connected, idle. Measured from the container's cgroup:
# `anon` (the proxy's own memory, what it allocated and touched; the
# kernel's socket buffers are left out, the same for all), before the
# connections, and after them once idle for SETTLE seconds. Output: bytes a
# connection, markdown.
#
#   tests/bench/idlemem.sh            (N=100000 by default; needs gcc, docker)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OKENA_IMAGE=${OKENA_IMAGE:-okena:bench}
ENVOY_IMAGE=${ENVOY_IMAGE:-envoyproxy/envoy:v1.40-latest}
HAPROXY_IMAGE=${HAPROXY_IMAGE:-haproxy:3.2}
NGINX_IMAGE=${NGINX_IMAGE:-nginx:1.27-alpine}
PROXY_CPUS=${PROXY_CPUS:-1,2}
NPROXY=${NPROXY:-2}
N=${N:-100000}
SETTLE=${SETTLE:-5}
ONLY=${ONLY:-okena haproxy nginx envoy}
B=29900
W=$(mktemp -d)
chmod 755 "$W"
BPID= HPID=
trap 'docker rm -f oki-okena oki-haproxy oki-nginx oki-envoy >/dev/null 2>&1 || true; for p in $BPID $HPID; do kill $p 2>/dev/null; done; rm -rf "$W"' EXIT

gcc -O2 -pthread -o "$W/l4bench" "$ROOT/tests/bench/l4bench.c"
docker build -q -t "$OKENA_IMAGE" "$ROOT" >/dev/null
taskset -c 4,5,12,13 "$W/l4bench" httpbig $B 100 & BPID=$!

cat > "$W/okena.conf" <<EOF
okena { workers $NPROXY }
pool b { server 127.0.0.1:$B }
http 127.0.0.1:29910 { route /* { to pool b }; timeout { idle 10m } }
EOF
cat > "$W/haproxy.cfg" <<EOF
global
	nbthread $NPROXY
	maxconn 500000
defaults
	mode http
	timeout connect 5s
	timeout client 10m
	timeout server 10m
	timeout http-keep-alive 10m
	http-reuse always
frontend f
	bind 127.0.0.1:29911
	default_backend b
backend b
	server s 127.0.0.1:$B
EOF
cat > "$W/nginx.conf" <<EOF
worker_processes $NPROXY;
worker_rlimit_nofile 1048576;
events { worker_connections 1000000; }
http {
	access_log off;
	keepalive_timeout 10m;
	keepalive_requests 1000000;
	upstream b { server 127.0.0.1:$B; keepalive 64; }
	server { listen 127.0.0.1:29912 reuseport backlog=65535;
		location / { proxy_pass http://b; proxy_http_version 1.1; proxy_set_header Connection ""; } }
}
EOF
cat > "$W/envoy.yaml" <<EOF
static_resources:
  listeners:
  - address: { socket_address: { address: 127.0.0.1, port_value: 29913 } }
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: h
          generate_request_id: false
          common_http_protocol_options: { idle_timeout: 600s }
          route_config:
            virtual_hosts:
            - name: all
              domains: ["*"]
              routes:
              - match: { prefix: "/" }
                route: { cluster: b, timeout: 0s }
          http_filters:
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
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
chmod 644 "$W"/*.conf "$W"/*.cfg "$W"/*.yaml

port() { case $1 in okena) echo 29910 ;; haproxy) echo 29911 ;; nginx) echo 29912 ;; envoy) echo 29913 ;; esac; }
start() {
	case $1 in
	okena) docker run -d --rm --name oki-okena --network host --cpuset-cpus "$PROXY_CPUS" --ulimit nofile=1048576 \
		--security-opt seccomp="$ROOT/docker/okena.seccomp.json" \
		-v "$W/okena.conf:/etc/okena/okena.conf:ro" "$OKENA_IMAGE" >/dev/null ;;
	haproxy) docker run -d --rm --name oki-haproxy --network host --cpuset-cpus "$PROXY_CPUS" --ulimit nofile=1048576 \
		-v "$W/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro" "$HAPROXY_IMAGE" >/dev/null ;;
	nginx) docker run -d --rm --name oki-nginx --network host --cpuset-cpus "$PROXY_CPUS" --ulimit nofile=1048576 \
		-v "$W/nginx.conf:/etc/nginx/nginx.conf:ro" "$NGINX_IMAGE" >/dev/null ;;
	envoy) docker run -d --rm --name oki-envoy --network host --cpuset-cpus "$PROXY_CPUS" --ulimit nofile=1048576 \
		-v "$W:/w:ro" "$ENVOY_IMAGE" envoy -c /w/envoy.yaml --concurrency "$NPROXY" -l warn >/dev/null ;;
	esac
	sleep 3
}
anon() {	# the container's anon bytes
	local id
	id=$(docker inspect -f '{{.Id}}' "oki-$1")
	awk '$1 == "anon" { print $2 }' "/sys/fs/cgroup/system.slice/docker-$id.scope/memory.stat"
}

echo "| Proxy ($NPROXY workers) | idle connections | memory before | after | per connection |"
echo "|---|---|---|---|---|"
for p in $ONLY; do
	start "$p"
	curl -q -s -o /dev/null "http://127.0.0.1:$(port "$p")/" || true
	a=$(anon "$p")
	(ulimit -n "$(ulimit -Hn)"; exec "$W/l4bench" hold 127.0.0.1 "$(port "$p")" "$N" 600) > "$W/hold.out" & HPID=$!
	t0=$(date +%s)
	until grep -q held "$W/hold.out" 2>/dev/null || [ $(( $(date +%s) - t0 )) -gt 300 ]; do sleep 1; done
	sleep "$SETTLE"
	b=$(anon "$p")
	held=$(awk '/held/ { gsub(",", "", $2); print $2 }' "$W/hold.out")
	printf '| %s | %s | %s MiB | %s MiB | %s B |\n' "$p" "$held" $((a >> 20)) $((b >> 20)) \
		$(( held > 0 ? (b - a) / held : 0 ))
	kill $HPID; wait $HPID 2>/dev/null || true; HPID=
	docker rm -f "oki-$p" >/dev/null
	sleep 2
done
