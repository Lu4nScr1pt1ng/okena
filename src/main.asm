; okena: L4/L7 load balancer, reverse proxy and API gateway.
; x86-64 assembly (fasm2) for Linux: static ELF, no libc, raw syscalls.
;
; SPDX-License-Identifier: AGPL-3.0-only

format ELF64 executable 3
entry start

BSS_FIXED := 0x10000000		; where the zero-initialised state is mapped (start)

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
include 'config/policy.inc'
include 'config/check.inc'
include 'config/index.inc'
include 'plan/compile.inc'
include 'core/base64.inc'
include 'crypto/ct.inc'
include 'crypto/sha256.inc'
include 'crypto/sha512.inc'
include 'crypto/rand.inc'
include 'crypto/sha384.inc'
include 'crypto/sha1.inc'
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
include 'quic/crypto.inc'
include 'tls/certs.inc'
include 'tls/handshake.inc'
include 'tls/clientauth.inc'
include 'tls/clientca.inc'
include 'tls/client.inc'
include 'tls/clientcert.inc'
include 'tls/x509w.inc'
include 'tls/tls12.inc'
include 'tls/tls12_server.inc'
include 'core/cpu.inc'
include 'net/resolve.inc'
include 'core/control.inc'
include 'core/discover.inc'
include 'core/docker.inc'
include 'core/client.inc'
include 'core/kube.inc'
include 'core/consul.inc'
include 'core/gateway.inc'
include 'core/gwgen.inc'
include 'core/gwstatus.inc'
include 'tls/ech.inc'
include 'core/alerts.inc'
include 'core/upgrade.inc'
include 'core/health.inc'
include 'core/stats.inc'
include 'admin/admin.inc'
include 'admin/api.inc'
include 'admin/top.inc'
include 'core/landlock.inc'
include 'core/privdrop.inc'
include 'core/systemd.inc'
include 'core/seccomp.inc'
include 'core/supervisor.inc'
include 'core/reload.inc'
include 'core/lastgood.inc'
include 'core/cfgwatch.inc'
include 'core/hostcheck.inc'
include 'core/quarantine.inc'
include 'core/ring.inc'
include 'core/worker.inc'
include 'l4/maxconn.inc'
include 'l4/tcp.inc'
include 'l4/bulk.inc'
include 'l4/udp.inc'
include 'l4/hash.inc'
include 'l4/tcp_epoll.inc'
include 'l4/peer.inc'
include 'l4/upstream.inc'
include 'http/proxy.inc'
include 'http/counted.inc'
include 'gw/limit.inc'
include 'gw/cors.inc'
include 'gw/split.inc'
include 'gw/sticky.inc'
include 'gw/mirror.inc'
include 'gw/hedge.inc'
include 'gw/overload.inc'
include 'gw/auth.inc'
include 'gw/json.inc'
include 'gw/jwt.inc'
include 'gw/jwks.inc'
include 'gw/forward.inc'
include 'gw/cache.inc'
include 'gw/match.inc'
include 'gw/files.inc'
include 'gw/cdisk.inc'
include 'gw/ckeep.inc'
include 'gw/purge.inc'
include 'gw/slice.inc'
include 'gw/signed.inc'
include 'gw/ranges.inc'
include 'gw/cdnloop.inc'
include 'admin/bird.inc'
include 'core/vrrp.inc'
include 'core/regex.inc'
include 'core/acme.inc'
include 'core/acmefleet.inc'
include 'core/acmeauto.inc'
include 'tls/ocsp.inc'
include 'tls/ondemand.inc'
include 'tls/certscli.inc'
include 'tls/localca.inc'
include 'tls/certexpiry.inc'
include 'http/zc.inc'
include 'gw/compress.inc'
include 'gw/brotli.inc'
include 'tls/certcomp.inc'
include 'gw/hints.inc'
include 'gw/rmap.inc'
include 'gw/canonical.inc'
include 'gw/concurrency.inc'
include 'gw/acl.inc'
include 'gw/geoip.inc'
include 'gw/idem.inc'
include 'http/engine.inc'
include 'http/tls.inc'
include 'http/hsbudget.inc'
include 'http/tls12_srv.inc'
include 'http/uptls.inc'
include 'http/fastcgi.inc'
include 'http/grpcweb.inc'
include 'http/h2.inc'
include 'http/h2u.inc'
include 'quic/server.inc'
include 'quic/http3.inc'
include 'core/accesslog.inc'
include 'http/trace.inc'
include 'http/errpage.inc'
include 'http/maint.inc'
include 'core/logsink.inc'
include 'bench/bench.inc'
include 'bench/h3.inc'
include 'cli.inc'
include 'cli_route.inc'
include 'cli_fmt.inc'
include 'cli_explain.inc'

start:
	; The zero-initialised state is sized for the largest configuration, a
	; few hundred MiB of it, and touched sparsely. As the executable's bss the
	; kernel would account all of it at exec, and refuse to start on a host
	; with less memory than that (overcommit's heuristic refuses any one
	; mapping larger than RAM and swap): mapped here, reserved, it costs what
	; is touched. And on 4 KiB pages: with transparent huge pages "always",
	; each sparse touch would make 2 MiB resident (the hot pools that gain
	; from huge pages are mappings of their own).
	mov	edi,BSS_FIXED
	mov	esi,BSS_PAGES
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_FIXED_NOREPLACE or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,BSS_FIXED
	jne	.no_state
	mov	edi,BSS_FIXED
	mov	esi,BSS_PAGES
	mov	edx,MADV_NOHUGEPAGE
	mov	eax,SYS_madvise
	syscall
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
	xor	esi,esi
	call	rnd_init			; the random pool's page, wiped in every child
	jmp	cli_main
.no_state:
	mov	edi,2
	lea	rsi,[str_no_state]
	mov	edx,str_no_state.len
	mov	eax,SYS_write
	syscall
	mov	edi,1
	mov	eax,SYS_exit_group
	syscall

cstring str_no_state, 'okena: cannot reserve its memory (address space at 0x10000000 taken?)',10

segment readable
	rodata_emit

segment readable writeable
	bss_emit
	BSS_PAGES := (BSS.size + 4095) and not 4095
	assert BSS_FIXED + BSS_PAGES <= 0x7FFF0000	; (absolute addresses: 32 bits, signed)
	assert g_acme_chain - g_tls_store = TLS_STORE	; (a TL_CHAIN offset reaches it)
	assert g_od_chain - g_tls_store = TLS_STORE + AX_CHAINMAX

segment gnustack
