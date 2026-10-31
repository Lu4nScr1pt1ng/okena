; okena: L4/L7 load balancer, reverse proxy and API gateway.
; x86-64 assembly (fasm2) for Linux: static ELF, no libc, raw syscalls.
;
; SPDX-License-Identifier: AGPL-3.0-only

format ELF64 executable 3
entry start

include 'core/sections.inc'
include 'sys/linux.inc'
include 'sys/uring.inc'
include 'core/limits.inc'

segment readable executable

include 'core/util.inc'
include 'core/arena.inc'
include 'core/file.inc'
include 'http/parse.inc'
include 'http/chunk.inc'
include 'http/hpack_tables.inc'
include 'http/hpack.inc'
include 'config/parse.inc'
include 'config/values.inc'
include 'config/schema.inc'
include 'config/check.inc'
include 'plan/compile.inc'
include 'core/base64.inc'
include 'crypto/ct.inc'
include 'crypto/sha256.inc'
include 'crypto/sha512.inc'
include 'crypto/keccak.inc'
include 'crypto/mlkem.inc'
include 'crypto/hmac.inc'
include 'crypto/hkdf.inc'
include 'crypto/x25519.inc'
include 'crypto/ed25519.inc'
include 'crypto/aesgcm.inc'
include 'crypto/chacha.inc'
include 'crypto/p256.inc'
include 'crypto/rsa.inc'
include 'tls/layout.inc'
include 'tls/x509.inc'
include 'tls/keyschedule.inc'
include 'tls/certs.inc'
include 'tls/handshake.inc'
include 'tls/client.inc'
include 'tls/tls12.inc'
include 'tls/tls12_server.inc'
include 'core/cpu.inc'
include 'net/resolve.inc'
include 'core/control.inc'
include 'core/health.inc'
include 'core/stats.inc'
include 'admin/admin.inc'
include 'core/seccomp.inc'
include 'core/supervisor.inc'
include 'core/reload.inc'
include 'core/ring.inc'
include 'core/worker.inc'
include 'l4/tcp.inc'
include 'l4/tcp_epoll.inc'
include 'l4/peer.inc'
include 'l4/upstream.inc'
include 'http/proxy.inc'
include 'http/engine.inc'
include 'http/tls.inc'
include 'http/hsbudget.inc'
include 'http/tls12_srv.inc'
include 'http/uptls.inc'
include 'http/h2.inc'
include 'core/accesslog.inc'
include 'bench/bench.inc'
include 'cli.inc'

start:
	; At entry: [rsp] = argc, then argv[], NULL, envp[], NULL.
	mov	rax,[rsp]
	mov	[g_argc],rax
	lea	rcx,[rsp+8]
	mov	[g_argv],rcx
	lea	rcx,[rcx+rax*8+8]
	mov	[g_envp],rcx
	and	rsp,-16
	mov	dword [g_out_fd],2
	call	cpu_require
	call	crypto_init
	jmp	cli_main

segment readable
	rodata_emit

segment readable writeable
	bss_emit

segment gnustack
