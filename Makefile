TOOLCHAIN := .toolchain/fasm2
FASMG     := $(TOOLCHAIN)/fasmg.x64
SOURCES   := $(shell find src -name '*.asm' -o -name '*.inc')
BIN       := build/okena
HTTPH     := build/httpharness
KAT       := build/kat
TLSH      := build/tlsserver
TLSC      := build/tlsclient
TLS12S    := build/tlsserver12
TLSC12    := build/tlsclient12

.PHONY: all toolchain test test-serial fuzz bench image docker-test clean

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

image:
	docker build -t okena .

docker-test:
	./tests/docker.sh

bench: $(BIN)
	./tests/bench/l4.sh

# Longer runs: make fuzz FUZZ_CASES=1000000
FUZZ_CASES ?= 100000
fuzz: $(BIN) $(HTTPH)
	python3 -I tests/config/fuzz.py $(FUZZ_CASES)
	python3 -I tests/http/run.py $(FUZZ_CASES)

clean:
	rm -rf build
