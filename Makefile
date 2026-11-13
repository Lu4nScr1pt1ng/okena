TOOLCHAIN := .toolchain/fasm2
FASMG     := $(TOOLCHAIN)/fasmg.x64
SOURCES   := $(shell find src -name '*.asm' -o -name '*.inc' -o -name '*.html') $(wildcard contrib/ranges/*.txt)
BIN       := build/okena
HTTPH     := build/httpharness
KAT       := build/kat
TLSH      := build/tlsserver
TLSC      := build/tlsclient
TLS12S    := build/tlsserver12
TLSC12    := build/tlsclient12

.PHONY: all toolchain test test-serial fuzz bench chaos soak image docker-test clean

all: $(BIN)

toolchain: $(FASMG)

$(FASMG):
	./scripts/fetch-fasm2.sh $(TOOLCHAIN)

$(BIN): $(SOURCES) | $(FASMG)
	@mkdir -p build
	INCLUDE="$(TOOLCHAIN)/include" $(FASMG) -e100 -i "Include 'fasm2.inc'" src/main.asm $@.tmp
	@chmod +x $@.tmp
	@mv -f $@.tmp $@

$(HTTPH): tests/http/harness.asm $(SOURCES) | $(FASMG)
	@mkdir -p build
	INCLUDE="$(TOOLCHAIN)/include" $(FASMG) -e100 -i "Include 'fasm2.inc'" tests/http/harness.asm $@.tmp
	@chmod +x $@.tmp
	@mv -f $@.tmp $@

# every suite at once, each in its own network namespace (tests/run_all.py)
$(KAT): tests/kat/kat.asm $(SOURCES) | $(FASMG)
	@mkdir -p build
	INCLUDE="$(TOOLCHAIN)/include" $(FASMG) -e100 -i "Include 'fasm2.inc'" tests/kat/kat.asm $@.tmp
	@chmod +x $@.tmp
	@mv -f $@.tmp $@

$(TLSH): tests/tls/server.asm $(SOURCES) | $(FASMG)
	@mkdir -p build
	INCLUDE="$(TOOLCHAIN)/include" $(FASMG) -e100 -i "Include 'fasm2.inc'" tests/tls/server.asm $@.tmp
	@chmod +x $@.tmp
	@mv -f $@.tmp $@

$(TLSC): tests/tls/client_test.asm $(SOURCES) | $(FASMG)
	@mkdir -p build
	INCLUDE="$(TOOLCHAIN)/include" $(FASMG) -e100 -i "Include 'fasm2.inc'" tests/tls/client_test.asm $@.tmp
	@chmod +x $@.tmp
	@mv -f $@.tmp $@

$(TLS12S): tests/tls/server12.asm $(SOURCES) | $(FASMG)
	@mkdir -p build
	INCLUDE="$(TOOLCHAIN)/include" $(FASMG) -e100 -i "Include 'fasm2.inc'" tests/tls/server12.asm $@.tmp
	@chmod +x $@.tmp
	@mv -f $@.tmp $@

$(TLSC12): tests/tls/client12.asm $(SOURCES) | $(FASMG)
	@mkdir -p build
	INCLUDE="$(TOOLCHAIN)/include" $(FASMG) -e100 -i "Include 'fasm2.inc'" tests/tls/client12.asm $@.tmp
	@chmod +x $@.tmp
	@mv -f $@.tmp $@

# the addon SDKs' examples (tests/gateway/addon.py), each when its toolchain is here
ADDON_EX  := build/addon-hello-c build/addon-hello-go build/addon-hello-rust

build/addon-hello-c: sdk/c/okena_addon.c sdk/c/okena_addon.h sdk/c/examples/hello.c
	@mkdir -p build
	-cc -O2 -o $@ sdk/c/examples/hello.c sdk/c/okena_addon.c -Isdk/c

build/addon-hello-go: $(wildcard sdk/go/*.go sdk/go/go.mod sdk/go/examples/hello/*.go)
	@mkdir -p build
	-command -v go >/dev/null && cd sdk/go && GOFLAGS=-mod=mod GOPROXY=off go build -o ../../$@ ./examples/hello

build/addon-hello-rust: $(wildcard sdk/rust/src/*.rs sdk/rust/Cargo.toml sdk/rust/examples/*.rs)
	@mkdir -p build
	-command -v cargo >/dev/null && cd sdk/rust && cargo build -q --release --example hello && cp target/release/examples/hello ../../$@

# the reference WAF addon (addons/coraza): its modules must be in Go's cache
# (go mod download in addons/coraza, once, with a network)
build/coraza-okena: $(wildcard addons/coraza/*.go addons/coraza/go.mod addons/coraza/go.sum sdk/go/*.go)
	@mkdir -p build
	-command -v go >/dev/null && cd addons/coraza && GOFLAGS=-mod=mod GOPROXY=off go build -o ../../$@ .

# proxy-wasm: the host addon (addons/wasm) and two plugins for its tests, on
# the Go SDK and on the Rust one (when wasm32-wasip1 is installed)
WASM_T    := build/wasm-okena build/test-plugin-go.wasm build/test-plugin-rust.wasm

build/wasm-okena: $(wildcard addons/wasm/*.go addons/wasm/go.mod addons/wasm/go.sum sdk/go/*.go)
	@mkdir -p build
	-command -v go >/dev/null && cd addons/wasm && GOFLAGS=-mod=mod GOPROXY=off go build -o ../../$@ .

build/test-plugin-go.wasm: $(wildcard tests/wasm/plugin/*.go tests/wasm/plugin/go.mod tests/wasm/plugin/go.sum)
	@mkdir -p build
	-command -v go >/dev/null && cd tests/wasm/plugin && GOFLAGS=-mod=mod GOPROXY=off GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o ../../../$@ .

build/test-plugin-rust.wasm: $(wildcard tests/wasm/rust/src/*.rs tests/wasm/rust/Cargo.toml tests/wasm/rust/Cargo.lock)
	@mkdir -p build
	-command -v cargo >/dev/null && cd tests/wasm/rust && cargo build -q --release --target wasm32-wasip1 && cp target/wasm32-wasip1/release/okena_test_plugin.wasm ../../../$@

# the test plugins compiled once into a cache of their own, not by each run
build/wasm-cache/.made: $(WASM_T)
	@mkdir -p build/wasm-cache
	-[ -x build/wasm-okena ] && for p in build/test-plugin-go.wasm build/test-plugin-rust.wasm; do \
		[ -f $$p ] && build/wasm-okena -plugin $$p -cache build/wasm-cache -compile; done; touch $@

# Envoy's ext_authz and ext_proc for okena (addons/envoyext), and a service of
# both kinds for its tests
build/ext-okena: $(wildcard addons/envoyext/*.go addons/envoyext/go.mod addons/envoyext/go.sum sdk/go/*.go)
	@mkdir -p build
	-command -v go >/dev/null && cd addons/envoyext && GOFLAGS=-mod=mod GOPROXY=off go build -o ../../$@ .

build/envoyext-test-server: $(wildcard tests/envoyext/*.go tests/envoyext/go.mod tests/envoyext/go.sum)
	@mkdir -p build
	-command -v go >/dev/null && cd tests/envoyext && GOFLAGS=-mod=mod GOPROXY=off go build -o ../../$@ .

test: $(BIN) $(HTTPH) $(KAT) $(TLSH) $(TLSC) $(TLS12S) $(TLSC12) $(ADDON_EX) build/coraza-okena $(WASM_T) build/wasm-cache/.made \
	build/ext-okena build/envoyext-test-server
	python3 -I tests/run_all.py

# one after the other, all output shown (slower; for reading a suite's log)
test-serial: $(BIN) $(HTTPH) $(KAT) $(TLSH)
	python3 -I tests/kat/run.py
	python3 -I tests/http/run.py 5000
	python3 -I tests/config/run.py
	python3 -I tests/config/host.py
	python3 -I tests/config/fmt.py
	python3 -I tests/config/explain.py
	python3 -I tests/config/fuzz.py 2000
	python3 -I tests/tls/run.py
	python3 -I tests/tls/handshake.py
	python3 -I tests/tls/https.py io_uring
	python3 -I tests/tls/https.py epoll
	python3 -I tests/tls/https.py io_uring user
	python3 -I tests/tls/https.py epoll user
	python3 -I tests/tls/certcomp.py io_uring
	python3 -I tests/tls/certcomp.py epoll
	python3 -I tests/tls/ech.py io_uring
	python3 -I tests/tls/ech.py epoll
	python3 -I tests/tls/passthrough.py io_uring
	python3 -I tests/tls/passthrough.py epoll
	python3 -I tests/tls/client.py
	python3 -I tests/l4/run.py io_uring
	python3 -I tests/l4/run.py epoll
	python3 -I tests/dns/run.py
	python3 -I tests/reload/run.py
	python3 -I tests/reload/lastgood.py
	python3 -I tests/reload/onchange.py
	python3 -I tests/reload/diff.py
	python3 -I tests/health/run.py
	python3 -I tests/lb/run.py
	python3 -I tests/peer/run.py io_uring
	python3 -I tests/peer/run.py epoll
	python3 -I tests/admin/run.py io_uring
	python3 -I tests/admin/run.py epoll
	python3 -I tests/overload/run.py io_uring
	python3 -I tests/overload/run.py epoll
	python3 -I tests/httpproxy/run.py io_uring
	python3 -I tests/httpproxy/run.py epoll
	python3 -I tests/httpproxy/edge.py io_uring
	python3 -I tests/httpproxy/edge.py epoll
	python3 -I tests/httpproxy/upstream.py io_uring
	python3 -I tests/httpproxy/upstream.py epoll
	python3 -I tests/httpproxy/routing.py io_uring
	python3 -I tests/httpproxy/routing.py epoll
	python3 -I tests/httpproxy/identity.py io_uring
	python3 -I tests/httpproxy/identity.py epoll
	python3 -I tests/httpproxy/failures.py io_uring
	python3 -I tests/httpproxy/failures.py epoll
	python3 -I tests/httpproxy/streaming.py io_uring
	python3 -I tests/httpproxy/streaming.py epoll
	python3 -I tests/gateway/cachedge.py io_uring
	python3 -I tests/gateway/cachedge.py epoll
	python3 -I tests/l4/edges.py io_uring
	python3 -I tests/l4/edges.py epoll
	python3 -I tests/admin/edges.py
	python3 -I tests/httpproxy/fdlimit.py io_uring
	python3 -I tests/httpproxy/fdlimit.py epoll
	python3 -I tests/h3/edges.py io_uring
	python3 -I tests/h3/edges.py epoll
	python3 -I tests/tls/hello.py io_uring
	python3 -I tests/tls/hello.py epoll
	python3 -I tests/gateway/quarantine.py io_uring
	python3 -I tests/gateway/quarantine.py epoll
	python3 -I tests/gateway/concurrency.py io_uring
	python3 -I tests/gateway/concurrency.py epoll
	python3 -I tests/gateway/rtimeout.py io_uring
	python3 -I tests/gateway/rtimeout.py epoll
	python3 -I tests/gateway/connect.py io_uring
	python3 -I tests/gateway/connect.py epoll
	python3 -I tests/httpproxy/hdrscope.py io_uring
	python3 -I tests/httpproxy/hdrscope.py epoll
	python3 -I tests/httpproxy/canonical.py io_uring
	python3 -I tests/httpproxy/canonical.py epoll
	python3 -I tests/httpproxy/respond.py io_uring
	python3 -I tests/httpproxy/respond.py epoll
	python3 -I tests/gateway/retry.py io_uring
	python3 -I tests/gateway/retry.py epoll
	python3 -I tests/gateway/outlier.py io_uring
	python3 -I tests/gateway/outlier.py epoll
	python3 -I tests/l4/source.py io_uring
	python3 -I tests/l4/source.py epoll
	python3 -I tests/l4/mss.py io_uring
	python3 -I tests/l4/mss.py epoll
	python3 -I tests/tls/policy.py io_uring
	python3 -I tests/tls/policy.py epoll
	python3 -I tests/tls/aes256.py io_uring
	python3 -I tests/tls/aes256.py epoll
	python3 -I tests/h2/abuse.py io_uring
	python3 -I tests/h2/abuse.py epoll
	python3 -I tests/bench/run.py
	python3 -I tests/h2/hpack_suite.py
	python3 -I tests/h2/run.py io_uring
	python3 -I tests/h2/run.py epoll
	python3 -I tests/h2/upstream.py io_uring
	python3 -I tests/h2/upstream.py epoll
	python3 -I tests/h2/fuzz.py io_uring 300
	python3 -I tests/h2/fuzz.py epoll 300
	python3 -I tests/h2/h2spec.py io_uring
	python3 -I tests/h2/h2spec.py epoll
	python3 -I tests/h2/websocket.py io_uring
	python3 -I tests/h2/websocket.py epoll
	python3 -I tests/h3/run.py io_uring
	python3 -I tests/h3/run.py epoll
	python3 -I tests/h3/steer.py io_uring
	python3 -I tests/h3/steer.py epoll
	python3 -I tests/h3/bbr.py io_uring
	python3 -I tests/h3/bbr.py epoll
	python3 -I tests/h3/bench.py io_uring
	python3 -I tests/h3/bench.py epoll
	python3 -I tests/gateway/fault.py io_uring
	python3 -I tests/gateway/fault.py epoll
	python3 -I tests/gateway/limit.py io_uring
	python3 -I tests/gateway/limit.py epoll
	python3 -I tests/gateway/cors.py io_uring
	python3 -I tests/gateway/cors.py epoll
	python3 -I tests/gateway/split.py io_uring
	python3 -I tests/gateway/split.py epoll
	python3 -I tests/gateway/mirror.py io_uring
	python3 -I tests/gateway/mirror.py epoll
	python3 -I tests/gateway/hedge.py io_uring
	python3 -I tests/gateway/hedge.py epoll
	python3 -I tests/gateway/overload.py io_uring
	python3 -I tests/gateway/overload.py epoll
	python3 -I tests/gateway/auth.py io_uring
	python3 -I tests/gateway/auth.py epoll
	python3 -I tests/gateway/jwt.py io_uring
	python3 -I tests/gateway/jwt.py epoll
	python3 -I tests/gateway/jwks.py io_uring
	python3 -I tests/gateway/jwks.py epoll
	python3 -I tests/gateway/upgrade.py io_uring
	python3 -I tests/gateway/upgrade.py epoll
	python3 -I tests/gateway/admin.py io_uring
	python3 -I tests/gateway/admin.py epoll
	python3 -I tests/gateway/udp.py io_uring
	python3 -I tests/gateway/udp.py epoll
	python3 -I tests/gateway/hash.py io_uring
	python3 -I tests/gateway/hash.py epoll
	python3 -I tests/gateway/sticky.py io_uring
	python3 -I tests/gateway/sticky.py epoll
	python3 -I tests/gateway/maxconn.py io_uring
	python3 -I tests/gateway/maxconn.py epoll
	python3 -I tests/gateway/discover.py io_uring
	python3 -I tests/gateway/discover.py epoll
	python3 -I tests/gateway/docker.py io_uring
	python3 -I tests/gateway/docker.py epoll
	python3 -I tests/gateway/kube.py io_uring
	python3 -I tests/gateway/kube.py epoll
	python3 -I tests/gateway/fleet.py io_uring
	python3 -I tests/gateway/fleet.py epoll
	python3 -I tests/gateway/alerts.py io_uring
	python3 -I tests/gateway/alerts.py epoll
	python3 -I tests/gateway/logsink.py io_uring
	python3 -I tests/gateway/logsink.py epoll
	python3 -I tests/gateway/tracing.py io_uring
	python3 -I tests/gateway/tracing.py epoll
	python3 -I tests/gateway/top.py io_uring
	python3 -I tests/gateway/top.py epoll
	python3 -I tests/gateway/errpage.py io_uring
	python3 -I tests/gateway/errpage.py epoll
	python3 -I tests/gateway/maint.py io_uring
	python3 -I tests/gateway/maint.py epoll
	python3 -I tests/gateway/landlock.py io_uring
	python3 -I tests/gateway/landlock.py epoll
	python3 -I tests/gateway/privdrop.py io_uring
	python3 -I tests/gateway/privdrop.py epoll
	python3 -I tests/gateway/systemd.py io_uring
	python3 -I tests/gateway/systemd.py epoll
	python3 -I tests/gateway/goaway.py io_uring
	python3 -I tests/gateway/goaway.py epoll
	python3 -I tests/gateway/geoip.py io_uring
	python3 -I tests/gateway/geoip.py epoll
	python3 -I tests/gateway/acl.py io_uring
	python3 -I tests/gateway/acl.py epoll
	python3 -I tests/gateway/idem.py io_uring
	python3 -I tests/gateway/idem.py epoll
	python3 -I tests/gateway/rmaphold.py io_uring
	python3 -I tests/gateway/rmaphold.py epoll
	python3 -I tests/gateway/hints.py io_uring
	python3 -I tests/gateway/hints.py epoll
	python3 -I tests/gateway/route.py
	python3 -I tests/gateway/compress.py io_uring
	python3 -I tests/gateway/compress.py epoll
	python3 -I tests/gateway/files.py io_uring
	python3 -I tests/gateway/files.py epoll
	python3 -I tests/gateway/match.py io_uring
	python3 -I tests/gateway/match.py epoll
	python3 -I tests/gateway/cache.py io_uring
	python3 -I tests/gateway/cache.py epoll
	python3 -I tests/gateway/cachedisk.py io_uring
	python3 -I tests/gateway/cachedisk.py epoll
	python3 -I tests/gateway/zerocopy.py io_uring
	python3 -I tests/gateway/zerocopy.py epoll
	python3 -I tests/gateway/cachekeys.py io_uring
	python3 -I tests/gateway/cachekeys.py epoll
	python3 -I tests/gateway/purge.py io_uring
	python3 -I tests/gateway/purge.py epoll
	python3 -I tests/gateway/slice.py io_uring
	python3 -I tests/gateway/slice.py epoll
	python3 -I tests/gateway/signed.py io_uring
	python3 -I tests/gateway/signed.py epoll
	python3 -I tests/gateway/ranges.py io_uring
	python3 -I tests/gateway/ranges.py epoll
	python3 -I tests/gateway/originpull.py io_uring
	python3 -I tests/gateway/originpull.py epoll
	python3 -I tests/gateway/shield.py io_uring
	python3 -I tests/gateway/shield.py epoll
	python3 -I tests/gateway/bird.py io_uring
	python3 -I tests/gateway/bird.py epoll
	python3 -I tests/gateway/vrrp.py io_uring
	python3 -I tests/gateway/vrrp.py epoll
	python3 -I tests/gateway/vrrp6.py io_uring
	python3 -I tests/gateway/vrrp6.py epoll
	python3 -I tests/gateway/certgen.py io_uring
	python3 -I tests/gateway/certgen.py epoll
	python3 -I tests/gateway/acme.py io_uring
	python3 -I tests/gateway/acme.py epoll
	python3 -I tests/gateway/acmefb.py io_uring
	python3 -I tests/gateway/acmefb.py epoll
	python3 -I tests/gateway/ocsp.py io_uring
	python3 -I tests/gateway/ocsp.py epoll
	python3 -I tests/gateway/acmeod.py io_uring
	python3 -I tests/gateway/acmeod.py epoll
	python3 -I tests/gateway/acmefleet.py io_uring
	python3 -I tests/gateway/acmefleet.py epoll
	python3 -I tests/gateway/localca.py io_uring
	python3 -I tests/gateway/localca.py epoll
	python3 -I tests/gateway/acmeauto.py io_uring
	python3 -I tests/gateway/acmeauto.py epoll
	python3 -I tests/gateway/certexpiry.py io_uring
	python3 -I tests/gateway/certexpiry.py epoll
	python3 -I tests/gateway/mtlsca.py io_uring
	python3 -I tests/gateway/mtlsca.py epoll
	python3 -I tests/gateway/fastcgi.py io_uring
	python3 -I tests/gateway/fastcgi.py epoll
	python3 -I tests/gateway/regex.py io_uring
	python3 -I tests/gateway/regex.py epoll
	python3 -I tests/gateway/grpcweb.py io_uring
	python3 -I tests/gateway/grpcweb.py epoll
	python3 -I tests/gateway/brotli.py io_uring
	python3 -I tests/gateway/brotli.py epoll
	python3 -I tests/gateway/consul.py io_uring
	python3 -I tests/gateway/consul.py epoll
	python3 -I tests/gateway/gwapi.py io_uring
	python3 -I tests/gateway/gwapi.py epoll
	python3 -I tests/gateway/forward.py io_uring
	python3 -I tests/gateway/forward.py epoll
	python3 -I tests/gateway/mtls.py io_uring
	python3 -I tests/gateway/mtls.py epoll
	python3 -I tests/gateway/chain.py io_uring
	python3 -I tests/gateway/chain.py epoll
	python3 -I tests/gateway/policy.py io_uring
	python3 -I tests/gateway/policy.py epoll
	python3 -I tests/gateway/jwtfuzz.py io_uring 7 15000
	python3 -I tests/gateway/jwtfuzz.py epoll 8 15000

image:
	docker build -t okena .

docker-test:
	./tests/docker.sh

bench: $(BIN)
	./tests/bench/l4.sh

# okena under load while what it depends on fails, one thing at a time (~40 s an engine)
chaos: $(BIN)
	timeout 300 python3 -I tests/chaos/run.py io_uring
	timeout 300 python3 -I tests/chaos/run.py epoll

# Longer runs: make fuzz FUZZ_CASES=1000000
FUZZ_CASES ?= 100000
fuzz: $(BIN) $(HTTPH)
	python3 -I tests/config/fuzz.py $(FUZZ_CASES)
	python3 -I tests/http/run.py $(FUZZ_CASES)
	python3 -I tests/h2/fuzz.py io_uring $$(( $(FUZZ_CASES) / 20 ))
	python3 -I tests/h2/fuzz.py epoll $$(( $(FUZZ_CASES) / 20 ))

clean:
	rm -rf build

# a long run under load, reloaded and upgraded again and again: SOAK_SECONDS (600), SOAK_RELOAD, SOAK_UPGRADE
soak: $(BIN)
	SOAK_ENGINE=io_uring python3 -I tests/soak/run.py
	SOAK_ENGINE=epoll python3 -I tests/soak/run.py
