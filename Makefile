# Workshop 2 - Secure Channel with libsodium
#   make            build everything
#   make test       required checkpoints (Tasks 1-5), unchanged from the brief
#   make check      make test + extended C tests + OpenSSL comparison
#   make openssl    Task 6: OpenSSL CLI comparison
#   make demo       interactive terminal menu
#   make present    terminal guided tour, press Enter between steps
#   make audit      terminal security audit dashboard
#   make mitm       stretch: MITM attack + signed handshake
#   make benchmark  stretch: AEAD speed on this machine
#   make tcp-server / make tcp-client   stretch: localhost TCP mode
#   make output     save `make test` output to docs/output.txt
#   make clean      delete binaries and generated keys
# The web dashboard runs from Windows/Node: `npm run dev` (see README).
# Recipe lines must start with a TAB character.

SHELL    := /bin/bash
CC       = gcc
CPPFLAGS = -D_POSIX_C_SOURCE=200809L -D_FORTIFY_SOURCE=2
CFLAGS   = -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 -O2 \
           -fstack-protector-strong $(shell pkg-config --cflags libsodium 2>/dev/null)
LDLIBS   = $(shell pkg-config --libs libsodium 2>/dev/null || echo -lsodium)

# Core library: file I/O, AEAD packets, terminal UI, handshake/re-key,
# key wrapping, session state machine, JSON output.
COMMON   = src/keyio.c src/aead.c src/ui.c src/handshake.c src/wrap.c src/session.c src/json.c
HEADERS  = src/common.h src/ui.h src/handshake.h src/wrap.h src/session.h src/json.h
NET      = src/net.c src/net.h
REQUIRED = keygen kx_demo keywrap test_attacks
EXTRA    = secure_demo mitm_demo aead_bench sc_engine sc_server sc_client test_extended
BUILD    = $(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(filter %.c,$^) $(LDLIBS)

all: $(REQUIRED) $(EXTRA)

keygen: src/keygen.c $(COMMON) $(HEADERS)
	$(BUILD)
kx_demo: src/kx_demo.c $(COMMON) $(HEADERS)
	$(BUILD)
keywrap: src/keywrap.c $(COMMON) $(HEADERS)
	$(BUILD)
test_attacks: tests/test_attacks.c $(COMMON) $(HEADERS)
	$(BUILD)
test_extended: tests/test_extended.c $(COMMON) $(HEADERS)
	$(BUILD)
secure_demo: src/demo.c $(COMMON) $(HEADERS)
	$(BUILD)
mitm_demo: src/mitm_demo.c $(COMMON) $(HEADERS)
	$(BUILD)
aead_bench: src/benchmark.c $(COMMON) $(HEADERS)
	$(BUILD)
sc_engine: src/engine.c $(COMMON) $(HEADERS)
	$(BUILD)
sc_server: src/tcp_server.c $(NET) $(COMMON) $(HEADERS)
	$(BUILD)
sc_client: src/tcp_client.c $(NET) $(COMMON) $(HEADERS)
	$(BUILD)

test: all
	./keygen && ls -l keys/
	./kx_demo
	./test_attacks
	./keywrap

check: test
	./test_extended
	bash scripts/openssl_compare.sh --quiet && echo "OpenSSL comparison: OK"

openssl: test_attacks
	bash scripts/openssl_compare.sh

demo: all
	./secure_demo

present: all
	./secure_demo --present

auto: all
	./secure_demo --auto

audit: all
	./secure_demo --audit

mitm: mitm_demo
	./mitm_demo

benchmark: aead_bench
	./aead_bench

tcp-server: sc_server
	./sc_server --rekey 3

tcp-client: sc_client
	./sc_client

output: all
	set -o pipefail; NO_COLOR=1 $(MAKE) --no-print-directory test 2>&1 | tee docs/output.txt

env:
	@echo "gcc       : $$(gcc --version | head -n1)"
	@echo "libsodium : $$(pkg-config --modversion libsodium)"
	@echo "openssl   : $$(openssl version)"

clean:
	rm -f $(REQUIRED) $(EXTRA) keys/*.bin keys/*.wrapped
	rm -rf openssl_demo

.PHONY: all test check openssl demo present auto audit mitm benchmark tcp-server tcp-client output env clean
