TOOLCHAIN := .toolchain/fasm2
FASMG     := $(TOOLCHAIN)/fasmg.x64
SOURCES   := $(shell find src -name '*.asm' -o -name '*.inc' -o -name '*.html')
BIN       := build/okena
HTTPH     := build/httpharness
KAT       := build/kat
TLSH      := build/tlsserver
TLSC      := build/tlsclient
TLS12S    := build/tlsserver12
TLSC12    := build/tlsclient12

.PHONY: all toolchain test test-serial fuzz bench chaos image docker-test clean

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

test: $(BIN) $(HTTPH) $(KAT) $(TLSH) $(TLSC) $(TLS12S) $(TLSC12)
	python3 -I tests/run_all.py

# one after the other, all output shown (slower; for reading a suite's log)
test-serial: $(BIN) $(HTTPH) $(KAT) $(TLSH)
	python3 -I tests/kat/run.py
	python3 -I tests/http/run.py 5000
	python3 -I tests/config/run.py
	python3 -I tests/config/fuzz.py 2000
	python3 -I tests/tls/run.py
	python3 -I tests/tls/handshake.py
	python3 -I tests/tls/https.py io_uring
	python3 -I tests/tls/https.py epoll
	python3 -I tests/tls/https.py io_uring user
	python3 -I tests/tls/https.py epoll user
	python3 -I tests/tls/passthrough.py io_uring
	python3 -I tests/tls/passthrough.py epoll
	python3 -I tests/tls/client.py
	python3 -I tests/l4/run.py io_uring
	python3 -I tests/l4/run.py epoll
	python3 -I tests/dns/run.py
	python3 -I tests/reload/run.py
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
