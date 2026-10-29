TOOLCHAIN := .toolchain/fasm2
FASMG     := $(TOOLCHAIN)/fasmg.x64
SOURCES   := $(shell find src -name '*.asm' -o -name '*.inc')
BIN       := build/okena

.PHONY: all toolchain test fuzz bench image docker-test clean

all: $(BIN)

toolchain: $(FASMG)

$(FASMG):
	./scripts/fetch-fasm2.sh $(TOOLCHAIN)

$(BIN): $(SOURCES) | $(FASMG)
	@mkdir -p build
	INCLUDE="$(TOOLCHAIN)/include" $(FASMG) -e100 -i "Include 'fasm2.inc'" src/main.asm $@.tmp
	@chmod +x $@.tmp
	@mv -f $@.tmp $@

test: $(BIN)
	python3 -I tests/config/run.py
	python3 -I tests/config/fuzz.py 2000
	python3 -I tests/l4/run.py io_uring
	python3 -I tests/l4/run.py epoll
	python3 -I tests/dns/run.py
	python3 -I tests/reload/run.py

image:
	docker build -t okena .

docker-test:
	./tests/docker.sh

bench: $(BIN)
	./tests/bench/l4.sh

# Longer runs: make fuzz FUZZ_CASES=1000000
FUZZ_CASES ?= 100000
fuzz: $(BIN)
	python3 -I tests/config/fuzz.py $(FUZZ_CASES)

clean:
	rm -rf build
