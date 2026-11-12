#!/bin/bash
# Gateway features against Envoy, HAProxy and nginx: what each costs, the
# same two cores, each proxy in a container on the host network, in front of
# the same backend (l4bench httpbig: 100-byte answers, keep-alive, cacheable
# for an hour). Each proxy has a listener a scenario, so that one feature
# never touches another's numbers:
#
#   none    the plain proxy
#   jwt     ES256 bearer tokens checked (signature, exp, iss, aud): 100000
#           tokens, a different one each request in turn (users), each used
#           some 15 times in a run. nginx: no JWT outside NGINX Plus
#   limit   a per-client-address rate limit that is never reached (its cost,
#           not its refusals)
#   cache   every request a hit (the first fills it)
#
# The load: wrk, CONNS connections, closed loop, DUR; the jwt runs pick their
# token in a Lua script. REPEAT runs each, the median. Output: markdown rows.
#
#   tests/bench/gw.sh            (needs gcc, wrk, python3 cryptography, docker)
#
# Cores (8 cores / 16 threads, SMT siblings i and i + 8): the proxy on 1-2
# (9-10 idle), the backend on 4-5 and 12-13, the load on the others.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OKENA_IMAGE=${OKENA_IMAGE:-okena:bench}
ENVOY_IMAGE=${ENVOY_IMAGE:-envoyproxy/envoy:v1.40-latest}
HAPROXY_IMAGE=${HAPROXY_IMAGE:-haproxy:3.2}
NGINX_IMAGE=${NGINX_IMAGE:-nginx:1.27-alpine}
PROXY_CPUS=${PROXY_CPUS:-1,2}
NPROXY=${NPROXY:-2}
BACK_CPUS=${BACK_CPUS:-4,5,12,13}
LOAD_CPUS=${LOAD_CPUS:-0,3,6,7,8,11,14,15}
DUR=${DUR:-8s}
CONNS=${CONNS:-256}
REPEAT=${REPEAT:-3}
TOKENS=${TOKENS:-100000}
ONLY=${ONLY:-okena envoy haproxy nginx}
SCEN=${SCEN:-none jwt limit cache}
B=29800
W=$(mktemp -d)
chmod 755 "$W"
BPID=
trap 'docker rm -f okg2-okena okg2-envoy okg2-haproxy okg2-nginx >/dev/null 2>&1 || true; [ -n "$BPID" ] && kill $BPID 2>/dev/null; rm -rf "$W"' EXIT

gcc -O2 -pthread -o "$W/l4bench" "$ROOT/tests/bench/l4bench.c"
docker build -q -t "$OKENA_IMAGE" "$ROOT" >/dev/null
taskset -c "$BACK_CPUS" "$W/l4bench" httpbig $B 100 & BPID=$!

# the key, its JWK set and PEM, the tokens
python3 - "$W" "$TOKENS" <<'EOF'
import base64, json, sys, time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
w, n = sys.argv[1], int(sys.argv[2])
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
k = ec.generate_private_key(ec.SECP256R1())
pub = k.public_key().public_numbers()
jwk = {"kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "use": "sig",
       "x": b64(pub.x.to_bytes(32, "big")), "y": b64(pub.y.to_bytes(32, "big"))}
open(f"{w}/jwks.json", "w").write(json.dumps({"keys": [jwk]}))
open(f"{w}/pub.pem", "wb").write(k.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
head = b64(json.dumps({"alg": "ES256", "typ": "JWT", "kid": "k1"}).encode())
exp = int(time.time()) + 86400
with open(f"{w}/tokens.txt", "w") as f:
    for i in range(n):
        body = b64(json.dumps({"sub": f"user{i}", "iss": "bench", "aud": "api", "exp": exp}).encode())
        r, s = decode_dss_signature(k.sign(f"{head}.{body}".encode(), ec.ECDSA(hashes.SHA256())))
        f.write(f"{head}.{body}.{b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}\n")
EOF
cat > "$W/jwt.lua" <<EOF
local toks = {}
for l in io.lines("$W/tokens.txt") do toks[#toks + 1] = l end
local i = math.random(#toks)
request = function()
	i = i % #toks + 1
	return wrk.format("GET", "/", { ["Authorization"] = "Bearer " .. toks[i] })
end
EOF

# ports: a proxy's base + 0 none, + 1 jwt, + 2 limit, + 3 cache
base() { case $1 in direct) echo $B ;; okena) echo 29810 ;; envoy) echo 29820 ;; haproxy) echo 29830 ;; nginx) echo 29840 ;; esac; }
off() { case $1 in none) echo 0 ;; jwt) echo 1 ;; limit) echo 2 ;; cache) echo 3 ;; esac; }

cat > "$W/okena.conf" <<EOF
okena { workers $NPROXY }
pool b { server 127.0.0.1:$B }
http 127.0.0.1:29810 { route /* { to pool b } }
http 127.0.0.1:29811 { route /* { to pool b; auth jwt { jwks $W/jwks.json; issuer bench; audience api } } }
http 127.0.0.1:29812 { route /* { to pool b; limit 1000000/s key=client.ip } }
http 127.0.0.1:29813 { route /* { to pool b; cache 1h } }
EOF
cat > "$W/haproxy.cfg" <<EOF
global
	nbthread $NPROXY
	maxconn 200000
defaults
	mode http
	timeout connect 5s
	timeout client 60s
	timeout server 60s
	http-reuse always
cache c
	total-max-size 256
	max-object-size 100000
	max-age 3600
backend b
	server s 127.0.0.1:$B
frontend none
	bind 127.0.0.1:29830
	default_backend b
frontend jwt
	bind 127.0.0.1:29831
	http-request set-var(txn.bearer) http_auth_bearer
	http-request set-var(txn.alg) var(txn.bearer),jwt_header_query('\$.alg')
	http-request deny deny_status 401 unless { var(txn.alg) -m str ES256 }
	http-request deny deny_status 401 unless { var(txn.bearer),jwt_verify(txn.alg,"/w/pub.pem") -m int 1 }
	http-request deny deny_status 401 unless { var(txn.bearer),jwt_payload_query('\$.iss') -m str bench }
	http-request deny deny_status 401 unless { var(txn.bearer),jwt_payload_query('\$.aud') -m str api }
	http-request set-var(txn.exp) var(txn.bearer),jwt_payload_query('\$.exp','int')
	http-request set-var(txn.now) date
	http-request deny deny_status 401 if { var(txn.exp),sub(txn.now) -m int lt 0 }
	default_backend b
frontend limit
	bind 127.0.0.1:29832
	stick-table type ip size 100k expire 10s store http_req_rate(1s)
	http-request track-sc0 src
	http-request deny deny_status 429 if { sc_http_req_rate(0) gt 1000000 }
	default_backend b
frontend cache
	bind 127.0.0.1:29833
	http-request cache-use c
	http-response cache-store c
	default_backend b
EOF
cat > "$W/nginx.conf" <<EOF
worker_processes $NPROXY;
events { worker_connections 65536; }
http {
	access_log off;
	keepalive_requests 1000000;
	upstream b { server 127.0.0.1:$B; keepalive 1024; keepalive_requests 1000000; }
	limit_req_zone \$binary_remote_addr zone=z:10m rate=1000000r/s;
	proxy_cache_path /tmp/c keys_zone=c:10m;
	proxy_http_version 1.1;
	proxy_set_header Connection "";
	server { listen 127.0.0.1:29840 reuseport backlog=65535; location / { proxy_pass http://b; } }
	server { listen 127.0.0.1:29842 reuseport backlog=65535; location / { limit_req zone=z burst=100000 nodelay; proxy_pass http://b; } }
	server { listen 127.0.0.1:29843 reuseport backlog=65535; location / { proxy_cache c; proxy_cache_valid 200 1h; proxy_pass http://b; } }
}
EOF
# Envoy: a listener a scenario
elistener() {	# port filters...
	cat <<EOF
  - address: { socket_address: { address: 127.0.0.1, port_value: $1 } }
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: h$1
          generate_request_id: false
          route_config:
            virtual_hosts:
            - name: all
              domains: ["*"]
              routes:
              - match: { prefix: "/" }
                route: { cluster: b, timeout: 0s }
          http_filters:
EOF
	cat
	cat <<EOF
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
              dynamic_stats: false
EOF
}
JWKS=$(cat "$W/jwks.json")
{
	echo "static_resources:"
	echo "  listeners:"
	elistener 29820 </dev/null
	elistener 29821 <<EOF
          - name: envoy.filters.http.jwt_authn
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication
              providers:
                p:
                  issuer: bench
                  audiences: [api]
                  local_jwks: { inline_string: '$JWKS' }
                  jwt_cache_config: { jwt_cache_size: 200000 }
              rules:
              - match: { prefix: "/" }
                requires: { provider_name: p }
EOF
	elistener 29822 <<EOF
          - name: envoy.filters.http.local_ratelimit
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit
              stat_prefix: rl
              token_bucket: { max_tokens: 1000000, tokens_per_fill: 1000000, fill_interval: 1s }
              filter_enabled: { default_value: { numerator: 100, denominator: HUNDRED } }
              filter_enforced: { default_value: { numerator: 100, denominator: HUNDRED } }
              descriptors:
              - entries: [ { key: remote_address } ]
                token_bucket: { max_tokens: 1000000, tokens_per_fill: 1000000, fill_interval: 1s }
EOF
	elistener 29823 <<EOF
          - name: envoy.filters.http.cache
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.cache.v3.CacheConfig
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.http.cache.simple_http_cache.v3.SimpleHttpCacheConfig
EOF
	cat <<EOF
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
} > "$W/envoy.yaml"
chmod 644 "$W"/*

start() {
	case $1 in
	okena) docker run -d --rm --name okg2-okena --network host --cpuset-cpus "$PROXY_CPUS" --ulimit nofile=1048576 \
		--security-opt seccomp="$ROOT/docker/okena.seccomp.json" \
		-v "$W/okena.conf:/etc/okena/okena.conf:ro" -v "$W:$W:ro" "$OKENA_IMAGE" >/dev/null ;;
	envoy) docker run -d --rm --name okg2-envoy --network host --cpuset-cpus "$PROXY_CPUS" --ulimit nofile=1048576 \
		-v "$W:/w:ro" "$ENVOY_IMAGE" envoy -c /w/envoy.yaml --concurrency "$NPROXY" -l warn >/dev/null ;;
	haproxy) docker run -d --rm --name okg2-haproxy --network host --cpuset-cpus "$PROXY_CPUS" --ulimit nofile=1048576 \
		-v "$W:/w:ro" -v "$W/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro" "$HAPROXY_IMAGE" >/dev/null ;;
	nginx) docker run -d --rm --name okg2-nginx --network host --cpuset-cpus "$PROXY_CPUS" --ulimit nofile=1048576 \
		-v "$W/nginx.conf:/etc/nginx/nginx.conf:ro" "$NGINX_IMAGE" >/dev/null ;;
	esac
	sleep 2
}
stop() { [ "$1" = direct ] || docker rm -f "okg2-$1" >/dev/null; }

# one run: requests/s and p99 (ms, wrk's), 0 when any answer was not 2xx
one() {	# port scenario
	local s=()
	[ "$2" = jwt ] && s=(-s "$W/jwt.lua")
	taskset -c "$LOAD_CPUS" wrk -t8 -c"$CONNS" -d"$DUR" --latency "${s[@]}" "http://127.0.0.1:$1/" 2>&1 |
		awk '/Requests\/sec/ { r = $2 } /Non-2xx/ { bad = $NF } / 99% / { p = $2 }
		     /Socket errors/ { err = 1 } END { if (bad > 0) r = 0; printf "%d %s\n", r, p }'
}
# is the scenario doing its work? (jwt: a bad token refused; cache: a hit)
probe() {	# port scenario
	case $2 in
	jwt) curl -q -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer x.y.z" "http://127.0.0.1:$1/" ;;
	*) echo - ;;
	esac
}

echo "| Proxy ($NPROXY cores) | scenario | requests/s | p99 (wrk) | check |"
echo "|---|---|---|---|---|"
for p in $ONLY; do
	[ "$p" = direct ] || start "$p"
	for sc in $SCEN; do
		[ "$p:$sc" = nginx:jwt ] && { printf '| %s | %s | (NGINX Plus only) | | |\n' "$p" "$sc"; continue; }
		[ "$p" = direct ] && [ "$sc" != none ] && continue
		port=$(( $(base "$p") + $(off "$sc") ))
		[ "$sc" = cache ] && curl -q -s -o /dev/null "http://127.0.0.1:$port/"
		chk=$(probe "$port" "$sc")
		read -r r lat < <(for i in $(seq "$REPEAT"); do one "$port" "$sc"; done | sort -n | awk '{ l[NR] = $0 } END { print l[int((NR + 1) / 2)] }')
		printf '| %s | %s | %s | %s | %s |\n' "$p" "$sc" "$r" "$lat" "$chk"
	done
	stop "$p"
done
