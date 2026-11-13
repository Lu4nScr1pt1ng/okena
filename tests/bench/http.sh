#!/bin/bash
# HTTP/1.1 reverse proxy against Envoy, HAProxy, nginx, Caddy and Traefik: the same two cores,
# the same backend (nginx answering "ok" from memory), plain HTTP, keep-alive
# both sides, a small answer: what a proxy costs per request. Each proxy tuned
# by its own documentation: upstream keep-alive (nginx `keepalive`, HAProxy
# `http-reuse always`, Caddy's and Traefik's idle connections per host raised
# to 1024), Envoy's circuit breakers out of the way, each with as many threads
# as cores (GOMAXPROCS for the two in Go). First the most each does (closed loop, wrk), then the
# latency each gives at fixed rates (open loop, okena bench: from the
# schedule, as wrk2), each point REPEAT times and the median of each
# percentile given (on a host that is not quiet, one bad run moves a tail).
# Output: markdown rows for docs/BENCHMARK.md.
#
#   tests/bench/http.sh             (needs docker, the three images, wrk)
#   H2=1 tests/bench/http.sh        HTTP/2 from the clients (h2c, prior knowledge),
#                                   HTTP/1.1 to the backend; the most from h2load
#                                   (H2_CONNS connections of H2_STREAMS streams),
#                                   latency from okena bench proto=h2
#   TLS=1.3 tests/bench/http.sh     HTTPS: every proxy terminates TLS 1.3 (or
#                                   TLS=1.2), one ECDSA P-256 certificate, ALPN
#                                   http/1.1, each with its defaults (session
#                                   tickets and all); the backend stays plain.
#                                   Adds handshakes a second (a new connection
#                                   each request), and latency comes from oha
#                                   (its client speaks 1.2, okena bench's not).
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
CADDY_IMAGE=${CADDY_IMAGE:-caddy:2.10-alpine}
TRAEFIK_IMAGE=${TRAEFIK_IMAGE:-traefik:v3.5}
PROXY_CPUS=${PROXY_CPUS:-1,2}
NPROXY=${NPROXY:-2}
BACK_CPUS=${BACK_CPUS:-4,5,12,13}
LOAD_CPUS=${LOAD_CPUS:-0,3,6,7,8,11,14,15}
DUR=${DUR:-10s}
CONNS=${CONNS:-256}
RATES=${RATES:-}
REPEAT=${REPEAT:-3}		# each latency point this many times: the median of each percentile
TLS=${TLS:-}			# 1.3 or 1.2: HTTPS
H2=${H2:-}			# 1: HTTP/2 from the clients
H2_CONNS=${H2_CONNS:-64}
H2_STREAMS=${H2_STREAMS:-16}
H2LOAD_IMAGE=${H2LOAD_IMAGE:-okena-h2load-h3}
SCHEME=http
[ -n "$TLS" ] && SCHEME=https
ONLY=${ONLY:-okena envoy haproxy nginx caddy traefik}
B=28600 OK=28601 EN=28602 HA=28603 NG=28604 CA=28605 TR=28606
W=$(mktemp -d)
chmod 755 "$W"
trap 'docker rm -f okh-back okh-okena okh-envoy okh-haproxy okh-nginx okh-caddy okh-traefik >/dev/null 2>&1 || true; rm -rf "$W"' EXIT
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
OKTLS= ENTLS= HATLS= NGTLS= CATLS= TRTLS= TRROUTE= CASCHEME=http
if [ -n "$TLS" ]; then
	openssl ecparam -genkey -name prime256v1 -noout -out "$W/key.pem" 2>/dev/null
	openssl req -new -x509 -key "$W/key.pem" -subj /CN=localhost -addext subjectAltName=DNS:localhost \
		-days 2 -out "$W/cert.pem" 2>/dev/null
	cat "$W/cert.pem" "$W/key.pem" > "$W/combined.pem"
	V=${TLS/./_}				# 1_3
	OKTLS="tls { cert /w/cert.pem; key /w/key.pem; versions $TLS }"
	HATLS="ssl crt /w/combined.pem ssl-min-ver TLSv$TLS ssl-max-ver TLSv$TLS alpn http/1.1"
	NGTLS="ssl; ssl_certificate /w/cert.pem; ssl_certificate_key /w/key.pem; ssl_protocols TLSv$TLS"
	CASCHEME=https
	CATLS="tls /w/cert.pem /w/key.pem {
		protocols tls$TLS tls$TLS
	}"
	TRROUTE=", tls: {}"
	TRTLS="tls:
  certificates: [ { certFile: /w/cert.pem, keyFile: /w/key.pem } ]
  stores: { default: { defaultCertificate: { certFile: /w/cert.pem, keyFile: /w/key.pem } } }
  options: { default: { minVersion: VersionTLS${TLS/./}, maxVersion: VersionTLS${TLS/./}, alpnProtocols: [http/1.1] } }"
	ENTLS="
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          \"@type\": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          common_tls_context:
            alpn_protocols: [http/1.1]
            tls_params: { tls_minimum_protocol_version: TLSv$V, tls_maximum_protocol_version: TLSv$V }
            tls_certificates:
            - certificate_chain: { filename: /w/cert.pem }
              private_key: { filename: /w/key.pem }"
fi
OKH2= ENCODEC=HTTP1 HAH2= NGH2= CAPROTO=h1
if [ -n "$H2" ]; then
	OKH2="http2 on" ENCODEC=AUTO HAH2="proto h2" NGH2="http2 on;" CAPROTO="h1 h2c"
fi
cat > "$W/okena.conf" <<EOF
okena { workers $NPROXY; io_engine $ENGINE }
pool b { server 127.0.0.1:$B }
http 127.0.0.1:$OK {
	$OKTLS
	$OKH2
	route /* { to pool b }
}
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
          codec_type: $ENCODEC
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
              dynamic_stats: false$ENTLS
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
	bind 127.0.0.1:$HA $HATLS $HAH2
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
		listen 127.0.0.1:$NG reuseport backlog=65535 ${NGTLS%%;*};
		${NGTLS#*;}${NGTLS:+;} $NGH2
		location / { proxy_pass http://b; proxy_http_version 1.1; proxy_set_header Connection ""; }
	}
}
EOF
# Caddy: no admin endpoint, no automatic HTTPS; access logs are off unless asked
cat > "$W/Caddyfile" <<EOF
{
	admin off
	auto_https disable_redirects
	persist_config off
	default_sni localhost
	servers {
		protocols $CAPROTO
	}
}
$CASCHEME://127.0.0.1:$CA, $CASCHEME://localhost:$CA {
	bind 127.0.0.1
	$CATLS
	reverse_proxy 127.0.0.1:$B {
		transport http {
			keepalive 120s
			keepalive_idle_conns 1024
			keepalive_idle_conns_per_host 1024
		}
	}
}
EOF
# Traefik: a file provider, no access log (its default), h2c served by itself
cat > "$W/traefik.yml" <<EOF
global: { checkNewVersion: false, sendAnonymousUsage: false }
log: { level: ERROR }
entryPoints:
  web: { address: "127.0.0.1:$TR" }
serversTransport: { maxIdleConnsPerHost: 1024 }
providers: { file: { filename: /w/traefik-dyn.yml } }
EOF
cat > "$W/traefik-dyn.yml" <<EOF
http:
  routers:
    r: { entryPoints: [web], rule: "PathPrefix(\`/\`)", service: s$TRROUTE }
  services:
    s: { loadBalancer: { servers: [ { url: "http://127.0.0.1:$B" } ] } }
$TRTLS
EOF
chmod 644 "$W"/*

docker run -d --rm --name okh-back --network host --cpuset-cpus "$BACK_CPUS" \
	-v "$W/back.conf:/etc/nginx/nginx.conf:ro" "$NGINX_IMAGE" >/dev/null
sleep 1

# max PORT: requests a second, closed loop (wrk)
max() {	# PORT [SCHEME]
	if [ -n "$H2" ] && [ "${2:-}" != http ]; then
		docker run --rm --network host --cpuset-cpus "$LOAD_CPUS" "$H2LOAD_IMAGE" -t8 -c"$H2_CONNS" \
			-m"$H2_STREAMS" -D"${DUR%s}" "http://127.0.0.1:$1/" 2>&1 |
			awk '/^finished in/ { gsub(",", ""); r = $4 } /^status codes:/ { ok = $3 + 0 }
			     /^requests:/ { n = $2 + 0 } /Application protocol: *h2c/ { proto = "h2c" }
			     END { if (proto != "h2c" || ok < n * 0.99) r = 0; printf "%d", r }	# (threads write lines into each other: h2c anywhere)'
		return
	fi
	taskset -c "$LOAD_CPUS" wrk -t8 -c"$CONNS" -d"$DUR" "${2:-$SCHEME}://127.0.0.1:$1/" 2>&1 |
		awk '/Requests\/sec/ { printf "%d", $2 }'
}
# hs PORT NAME: "full handshakes a second, and per second of the proxy's CPU".
# openssl s_time -new, two processes on each load core: a new connection each
# time and never a resumption (wrk resumes nearly every one: its "handshakes"
# are abbreviated ones). The first number is a floor where the clients are the
# limit (okena's is, at about 14k here); the second, from the container's
# cgroup (cpu.stat), is what a handshake costs the proxy, whoever is the limit.
hs() {
	local c k pids= t cg u0 u1
	t=$(mktemp -d)
	cg=/sys/fs/cgroup/system.slice/docker-$(docker inspect -f '{{.Id}}' "okh-$2").scope/cpu.stat
	u0=$(awk '/^usage_usec/ { print $2 }' "$cg")
	for c in ${LOAD_CPUS//,/ }; do
		for k in 1 2; do
			taskset -c "$c" timeout 30 openssl s_time -connect "127.0.0.1:$1" -new -time "${DUR%s}" "-tls${TLS/./_}" \
				> "$t/$c.$k" 2>/dev/null & pids="$pids $!"
		done
	done
	wait $pids || true
	u1=$(awk '/^usage_usec/ { print $2 }' "$cg")
	cat "$t"/* | awk -v cpu=$((u1 - u0)) '/real seconds/ { n += $1; s = $4 } END { printf "%d %d", s ? n / s : 0, cpu ? n / (cpu / 1e6) : 0 }'
	rm -rf "$t"
}

# lat PORT RATE: "p50 p99 p99.9 max behind errors" (us), open loop
lat() {
	if [ -n "$TLS" ]; then
		taskset -c "$LOAD_CPUS" oha -z "$DUR" -q "$2" -c 64 --latency-correction --insecure --no-tui -j \
			"https://127.0.0.1:$1/" 2>/dev/null | python3 -c '
import json, sys
d = json.load(sys.stdin); p = d["latencyPercentiles"]; us = lambda x: int((x or 0) * 1e6)
ok = d["statusCodeDistribution"].get("200", 0); n = sum(d["statusCodeDistribution"].values())
print(us(p["p50"]), us(p["p99"]), us(p["p99.9"]), us(d["summary"]["slowest"]), 0, n - ok + sum(d.get("errorDistribution", {}).values()))'
		return
	fi
	taskset -c "$LOAD_CPUS" "$OKENA" bench "http://127.0.0.1:$1/" rate="$2" conns=64 workers=4 duration="$DUR" \
		${H2:+proto=h2} format=kv 2>&1 |
		tr ' ' '\n' | awk -F= '{ v[$1] = $2 } END { printf "%d %d %d %d %d %d", v["c_p50_ns"] / 1000, v["c_p99_ns"] / 1000,
			v["c_p999_ns"] / 1000, v["c_max_ns"] / 1000, v["behind"], v["errors"] + v["timeouts"] }' ; echo
}

start() {	# name
	case $1 in
	okena) docker run -d --rm --name okh-okena --network host --cpuset-cpus "$PROXY_CPUS" \
		--security-opt seccomp="$ROOT/docker/okena.seccomp.json" \
		-v "$W/okena.conf:/etc/okena/okena.conf:ro" -v "$W:/w:ro" "$OKENA_IMAGE" >/dev/null ;;
	envoy) docker run -d --rm --name okh-envoy --network host --cpuset-cpus "$PROXY_CPUS" -v "$W:/w:ro" \
		"$ENVOY_IMAGE" envoy -c /w/envoy.yaml --concurrency "$NPROXY" -l warn >/dev/null ;;
	haproxy) docker run -d --rm --name okh-haproxy --network host --cpuset-cpus "$PROXY_CPUS" \
		-v "$W/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro" -v "$W:/w:ro" "$HAPROXY_IMAGE" >/dev/null ;;
	nginx) docker run -d --rm --name okh-nginx --network host --cpuset-cpus "$PROXY_CPUS" \
		-v "$W/nginx.conf:/etc/nginx/nginx.conf:ro" -v "$W:/w:ro" "$NGINX_IMAGE" >/dev/null ;;
	caddy) docker run -d --rm --name okh-caddy --network host --cpuset-cpus "$PROXY_CPUS" -e GOMAXPROCS="$NPROXY" \
		-v "$W:/w:ro" "$CADDY_IMAGE" caddy run --config /w/Caddyfile --adapter caddyfile >/dev/null ;;
	traefik) docker run -d --rm --name okh-traefik --network host --cpuset-cpus "$PROXY_CPUS" -e GOMAXPROCS="$NPROXY" \
		-v "$W:/w:ro" "$TRAEFIK_IMAGE" --configFile=/w/traefik.yml >/dev/null ;;
	esac
	sleep 2
}
stop() { docker rm -f "okh-$1" >/dev/null; }
port() { case $1 in okena) echo $OK ;; envoy) echo $EN ;; haproxy) echo $HA ;; nginx) echo $NG ;; caddy) echo $CA ;; traefik) echo $TR ;; esac; }

MAXRUN=${MAXRUN:-1}
if [ "$MAXRUN" = 1 ]; then
echo "direct to the backend: $(max $B http) req/s"
echo
if [ -n "$TLS" ]; then
	echo "| Proxy ($NPROXY cores, TLS $TLS) | most req/s, keep-alive | per core | full handshakes/s | handshakes per CPU-second |"
	echo "|---|---|---|---|---|"
else
	echo "| Proxy ($NPROXY cores) | most req/s | per core |"
	echo "|---|---|---|"
fi
declare -A MOST
for p in $ONLY; do
	start "$p"
	MOST[$p]=$(max "$(port "$p")")
	if [ -n "$TLS" ]; then
		read -ra h < <(hs "$(port "$p")" "$p"; echo)
		printf '| %s | %s | %s | %s | %s |\n' "$p" "${MOST[$p]}" $(( ${MOST[$p]} / NPROXY )) "${h[0]}" "${h[1]}"
	else
		printf '| %s | %s | %s |\n' "$p" "${MOST[$p]}" $(( ${MOST[$p]} / NPROXY ))
	fi
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
