; Compile the checked configuration tree into the plan: flat, fixed-size
; tables the workers read and never write. Addresses become sockaddr
; structures here, so the data path never parses text.

MAX_LISTENERS	:= 64
MAX_POOLS	:= 512
MAX_SERVERS	:= 1024

; Listener
LS_SA		:= 0		; sockaddr_in6 / sockaddr_in (28 bytes)
LS_SALEN	:= 28		; d
LS_FAMILY	:= 32		; d: AF_INET, AF_INET6, or 0 for ":port" (dual stack)
LS_POOL		:= 36		; d
LS_IDLE		:= 40		; d: idle timeout in seconds
LS_MAXCONN	:= 44		; d: per worker
LS_TEXT		:= 48		; q: address as written
LS_TLEN		:= 56		; d
LS_PORT		:= 60		; d
LS_FLAGS	:= 64		; d: LSF_*
LS_PER_SOURCE	:= 68		; d: connections per client address, 0 = no limit
LS_KIND		:= 72		; d: LK_*
LS_RFIRST	:= 76		; d: first route (http)
LS_RCOUNT	:= 80		; d
LS_HFIRST	:= 84		; d: first host block (http)
LS_HCOUNT	:= 88		; d
LS_T_HEADER	:= 92		; d: http: seconds for a whole request head
LS_T_RESPONSE	:= 96		; d: http: seconds a backend has for its response head
LS_ALOG		:= 100		; d: http: access log destination + 1, 0 = none
LS_TFIRST	:= 104		; d: http: first trusted_proxies range
LS_TCOUNT	:= 108		; d
LS_T_BODY	:= 112		; d: http: seconds between bytes of a request body
LS_PT		:= 116		; d: tls passthrough: names group | (default pool + 1) << 16, 0 = none
LS_TLS		:= 120		; d: its tls entry + 1 (certificate, key), 0 = none
LS_SIZE		:= 128

; Host block name (http): routes for requests to that host
HO_NAME		:= 0		; q: the name; for "*.example.com", ".example.com"
HO_NLEN		:= 8		; d
HO_WILD		:= 12		; d: 1 for a wildcard (matched as a suffix)
HO_RFIRST	:= 16		; d
HO_RCOUNT	:= 20		; d
HO_SIZE		:= 24

; Host names are found through one open-addressing table for the whole
; plan: key = (the listener's first host entry, wildcard or not, the
; name in lower case), value = host entry + 1 (0 = empty slot). Load is
; at most 1/4, so a probe sequence is short.
HHASH_SIZE	:= MAX_HOSTS * 4
MAX_HOSTS	:= 1024
MAX_TRUST	:= 1024		; trusted_proxies ranges, all listeners

LK_TCP		:= 0
LK_HTTP		:= 1

; Route (http)
RT_PATH		:= 0		; q: path; for a prefix route, without the "*"
RT_PLEN		:= 8		; d
RT_PREFIX	:= 12		; d: 1 for "/x/*" routes
RT_METHODS	:= 16		; d: RM_* bits, 0 = any
RT_POOL		:= 20		; d: -1 for a route that redirects
RT_ACT		:= 24		; d: its action + 1 (redirect, header changes), 0 = none
RT_SIZE		:= 32

; Route actions: a redirect, and the header changes of requests and of
; responses (ranges of g_hdrops).
RA_CODE		:= 0		; d: redirect status, 0 = forward
RA_TLEN		:= 4		; d
RA_TGT		:= 8		; q: redirect target
RA_QFIRST	:= 16		; d: request header changes
RA_QCOUNT	:= 20
RA_PFIRST	:= 24		; d: response header changes
RA_PCOUNT	:= 28
RA_WFROM	:= 32		; q: rewrite: the prefix it replaces (FROM without {*}), 0 = none
RA_WFLEN	:= 40		; d
RA_WTLEN	:= 44		; d
RA_WTO		:= 48		; q: what replaces it
RA_SIZE		:= 64
MAX_ACTS	:= MAX_ROUTES
HD_KIND		:= 0		; d: HOP_SET, HOP_ADD, HOP_DROP
HD_PREFIX	:= 4		; d: 1 when the name ends with * (drop)
HD_NLEN		:= 8		; d: name length (without the *)
HD_VLEN		:= 12		; d
HD_NAME		:= 16		; q
HD_VAL		:= 24		; q
HD_VARS		:= 32		; d: ${...} in the value (how many), 0 = literal
HD_SIZE		:= 40
MAX_HDROPS	:= 4096
HOP_SET		:= 1
HOP_ADD		:= 2
HOP_DROP	:= 3

; Routes are found through one open-addressing table: key = (the route
; set's first entry, exact or prefix, the path), value = route entry + 1.
; Routes that share a path with different methods share a key: a lookup
; walks every entry of its probe sequence.
RHASH_SIZE	:= MAX_ROUTES * 4
MAX_ROUTES	:= 1024

LSF_PEER	:= 1		; sessions need the client's address
LSF_PP_V1	:= 2		; send a PROXY protocol v1 header upstream
LSF_PP_V2	:= 4		; send a PROXY protocol v2 header upstream
LSF_WILDCARD	:= 8		; bound to every address: the local one comes from getsockname
LSF_KTLS	:= 16		; http: the kernel seals and opens the records (`ktls on`)

; Pool
PL_FIRST	:= 0		; d: first server
PL_COUNT	:= 4		; d
PL_BALANCE	:= 8		; d: BAL_*
PL_PRIMARY	:= 12		; d: servers that are not backups
PL_TIMEOUT	:= 16		; 16 bytes: connect timeout as __kernel_timespec
PL_NAME		:= 32		; q
PL_NLEN		:= 40		; d
PL_HEALTH	:= 44		; d: 1 when active checks run
PL_H_EVERY	:= 48		; d: milliseconds
PL_H_TIMEOUT	:= 52		; d: milliseconds
PL_H_RISE	:= 56		; d
PL_H_FALL	:= 60		; d
PL_H_HTTP	:= 64		; d: 1 for an HTTP check (0: TCP)
PL_H_PLEN	:= 68		; d
PL_H_PATH	:= 72		; q
PL_H_LO		:= 80		; d: statuses that pass
PL_H_HI		:= 84		; d
PL_H_HOST	:= 88		; q: Host of the check, 0 = the server as written
PL_H_HLEN	:= 96		; d
PL_H_HEAD	:= 100		; d: 1 for HEAD
PL_SLOW		:= 104		; d: slow start window in seconds, 0 = none
PL_TLS		:= 108		; d: 1 when this pool's upstreams speak TLS
PL_TLS_SNI	:= 112		; q: SNI / hostname to verify, 0 = the server as written
PL_TLS_SNILEN	:= 120		; d
PL_TLS_HASANCHOR := 124		; d: 1 when an anchor key was loaded
PL_TLS_ANCHOR	:= 128		; the trust anchor's public key, a PK blob (EC or RSA)
PL_SIZE		:= 704		; room for PL_TLS_ANCHOR + a PK blob (16 + 528)

; Server
SV_SA		:= 0		; sockaddr (sockaddr_un is 110 bytes)
SV_SALEN	:= 112		; d
SV_FAMILY	:= 116		; d
SV_WEIGHT	:= 120		; d
SV_BACKUP	:= 124		; d
SV_TEXT		:= 128		; q
SV_TLEN		:= 136		; d
SV_ACTIVE	:= 140		; d: holds an address (names: once resolved)
SV_GROUP	:= 144		; d: name group + 1, or 0 for an address
SV_SIZE		:= 160

BAL_ROUND_ROBIN	:= 0
BAL_LEAST_CONN	:= 1
BAL_RANDOM	:= 2
BAL_LEAST_REQ	:= 3		; the default: power of two choices
BAL_PEAK_EWMA	:= 4		; power of two choices on latency x load

DEFAULT_CONNECTIONS	:= 65536		; per listener, whole instance
DEFAULT_IDLE_SECS	:= 3600
DEFAULT_HTTP_IDLE_SECS	:= 60
DEFAULT_HEADER_SECS	:= 10		; slow clients (slowloris) get 408
DEFAULT_RESPONSE_SECS	:= 30		; slow backends get 504
DEFAULT_BODY_SECS	:= 30		; a request body that stops coming gets 408
DEFAULT_CONNECT_US	:= 2000000
DEFAULT_DRAIN_US	:= 8000000
DEFAULT_HS_BUDGET_US	:= 100		; handshake_budget: asymmetric crypto per loop iteration
DEFAULT_HS_WAIT_US	:= 1000000	; and how long a queued ClientHello may wait

bss
	align 8
	g_plan_listeners	dd ?
	g_plan_pools		dd ?
	g_plan_servers		dd ?
	g_plan_workers		dd ?		; 0 = auto
	g_plan_engine		dd ?		; 0 auto, 1 io_uring, 2 epoll
	g_plan_drain_delay	dq ?		; microseconds
	g_plan_drain_timeout	dq ?
	g_plan_watchdog		dq ?
	g_plan_busy_poll	dq ?		; microseconds, 0 = off
	g_plan_hs_budget	dq ?		; microseconds per loop iteration, 0 = off
	g_plan_hs_wait		dq ?		; microseconds a queued hello may wait
	g_plan_health		dd ?		; pools with active checks
	g_plan_metrics		dd ?		; 1 when an admin address is set
	g_plan_metrics_salen	dd ?
	g_plan_metrics_text	dq ?
	g_plan_metrics_tlen	dd ?
	g_plan_metrics_sa:	rb 28
	g_listeners:	rb LS_SIZE * MAX_LISTENERS
	g_pools:	rb PL_SIZE * MAX_POOLS
	g_trust_path:	rb 4096			; a trust file's path, NUL-terminated
	g_trust_der:	rb 1 shl 14		; the first certificate's DER
	g_trust_pub:	rb 544			; a scratch anchor key blob (config check)
	g_servers:	rb SV_SIZE * MAX_SERVERS
	g_cmp_addr:	rb AD_SIZE
	g_cmp_flags	dd ?
	g_cmp_per_source dd ?
	g_cmp_t_header	dd ?
	g_cmp_pt	dd ?
	g_cmp_alog	dd ?
	g_cmp_tlsi	dd ?
	g_cmp_tfirst	dd ?
	g_cmp_tcount	dd ?
	g_cmp_t_response dd ?
	g_cmp_t_body	dd ?
	g_cmp_rfirst	dd ?
	g_cmp_rcount	dd ?
	g_plan_routes	dd ?
	g_routes:	rb RT_SIZE * MAX_ROUTES
	g_plan_trust	dd ?
	g_trust:	rb TR_SIZE * MAX_TRUST
	g_hhash:	rq HHASH_SIZE
	g_rhash:	rq RHASH_SIZE
	g_plan_acts	dd ?
	g_acts:		rb RA_SIZE * MAX_ACTS
	g_plan_hdrops	dd ?
	g_hdrops:	rb HD_SIZE * MAX_HDROPS
	g_cmp_act	dd ?
	g_plan_hosts	dd ?
	g_hosts:	rb HO_SIZE * MAX_HOSTS
	g_cmp_hfirst	dd ?
	g_cmp_hcount	dd ?
end bss

; Exits with EXIT_CONFIG when something valid in the language cannot be
; served by this build (host names, table limits).
plan_compile:
	push	rbx
	push	r12
	mov	qword [g_plan_drain_timeout],DEFAULT_DRAIN_US
	mov	qword [g_plan_watchdog],2000000
	mov	qword [g_plan_hs_budget],DEFAULT_HS_BUDGET_US
	mov	qword [g_plan_hs_wait],DEFAULT_HS_WAIT_US
	; pools first, so listeners can refer to them
	mov	rax,[g_cfg_root]
	mov	rbx,[rax+N_CHILD]
.pools:
	test	rbx,rbx
	jz	.pools_done
	mov	rax,[rbx+N_DEF]
	lea	rcx,[dir_table + D_SIZE*DIR_POOL]
	cmp	rax,rcx
	jne	@f
	mov	rdi,rbx
	call	compile_pool
@@:
	lea	rcx,[dir_table + D_SIZE*DIR_OKENA]
	cmp	rax,rcx
	jne	@f
	mov	rdi,rbx
	call	compile_settings
@@:
	mov	rbx,[rbx+N_NEXT]
	jmp	.pools
.pools_done:
	mov	rax,[g_cfg_root]
	mov	rbx,[rax+N_CHILD]
.listeners:
	test	rbx,rbx
	jz	.done
	mov	rax,[rbx+N_DEF]
	lea	rcx,[dir_table + D_SIZE*DIR_TCP]
	cmp	rax,rcx
	je	.listener
	lea	rcx,[dir_table + D_SIZE*DIR_HTTP]
	cmp	rax,rcx
	jne	@f
.listener:
	mov	rdi,rbx
	call	compile_listener
@@:
	mov	rbx,[rbx+N_NEXT]
	jmp	.listeners
.done:
	pop	r12
	pop	rbx
	ret

; Value helpers: rdi = node; first positional value parsed.
node_duration:
	mov	rax,[rdi+N_ARGS]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	jmp	parse_duration

node_decimal:
	mov	rax,[rdi+N_ARGS]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	jmp	parse_decimal

; rdi = node, rsi = NUL-terminated key. rax = the arg holding it (key=value
; on the line or "key value" in the block), or 0.
node_option:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	mov	r13,rsi
	mov	rbx,[r12+N_ARGS]
	mov	ecx,[r12+N_ARGC]
.args:
	test	ecx,ecx
	jz	.block
	cmp	dword [rbx+A_KIND],ARG_KV
	jne	.next_arg
	push	rcx
	mov	rdi,[rbx+A_KEY]
	mov	esi,[rbx+A_KLEN]
	mov	rdx,r13
	call	mem_eq_cstr
	pop	rcx
	test	eax,eax
	jnz	.found
.next_arg:
	add	rbx,A_SIZE
	dec	ecx
	jmp	.args
.block:
	mov	rbx,[r12+N_CHILD]
.child:
	test	rbx,rbx
	jz	.none
	mov	rdi,[rbx+N_NAME]
	mov	esi,[rbx+N_NLEN]
	mov	rdx,r13
	call	mem_eq_cstr
	test	eax,eax
	jnz	.found_child
	mov	rbx,[rbx+N_NEXT]
	jmp	.child
.found_child:
	mov	rax,[rbx+N_ARGS]
	jmp	.out
.found:
	mov	rax,rbx
	jmp	.out
.none:
	xor	eax,eax
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

cstring str_key_delay, 'delay',0
cstring str_key_wait, 'wait',0
cstring str_key_timeout, 'timeout',0
cstring str_key_weight, 'weight',0
cstring str_key_every, 'every',0
cstring str_key_rise, 'rise',0
cstring str_key_expect, 'expect',0
cstring str_key_host, 'host',0
cstring str_key_trust, 'trust',0
cstring str_key_sni, 'sni',0
cstring str_key_fall, 'fall',0

; rdi = `okena` node.
compile_settings:
	push	rbx
	push	r12
	mov	r12,rdi
	mov	rbx,[r12+N_CHILD]
.next:
	test	rbx,rbx
	jz	.done
	mov	rax,[rbx+N_DEF]
	lea	rcx,[dir_table + D_SIZE*DIR_WORKERS]
	cmp	rax,rcx
	je	.workers
	lea	rcx,[dir_table + D_SIZE*DIR_IO_ENGINE]
	cmp	rax,rcx
	je	.engine
	lea	rcx,[dir_table + D_SIZE*DIR_WATCHDOG]
	cmp	rax,rcx
	je	.watchdog
	lea	rcx,[dir_table + D_SIZE*DIR_DRAIN]
	cmp	rax,rcx
	je	.drain
	lea	rcx,[dir_table + D_SIZE*DIR_BUSY_POLL]
	cmp	rax,rcx
	je	.busy_poll
	lea	rcx,[dir_table + D_SIZE*DIR_METRICS]
	cmp	rax,rcx
	je	.metrics
	lea	rcx,[dir_table + D_SIZE*DIR_HS_BUDGET]
	cmp	rax,rcx
	je	.hs_budget
	lea	rcx,[dir_table + D_SIZE*DIR_TICKET_KEYS]
	cmp	rax,rcx
	jne	.advance
	mov	rdi,rbx
	call	compile_ticket_keys
	jmp	.advance
.metrics:
	mov	rax,[rbx+N_ARGS]
	mov	rdi,[rax+A_VAL]
	mov	[g_plan_metrics_text],rdi
	mov	esi,[rax+A_VLEN]
	mov	[g_plan_metrics_tlen],esi
	lea	rdx,[g_cmp_addr]
	xor	ecx,ecx
	call	parse_address
	lea	rdi,[g_plan_metrics_sa]
	lea	rsi,[g_cmp_addr]
	call	sockaddr_build
	mov	[g_plan_metrics_salen],eax
	mov	dword [g_plan_metrics],1
	jmp	.advance
.busy_poll:
	mov	rdi,rbx
	call	node_duration
	mov	[g_plan_busy_poll],rax
	jmp	.advance
.hs_budget:
	mov	rdi,rbx
	call	node_duration
	mov	[g_plan_hs_budget],rax
	mov	rdi,rbx
	lea	rsi,[str_key_wait]
	call	node_option
	test	rax,rax
	jz	.advance
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_duration
	mov	[g_plan_hs_wait],rax
	jmp	.advance
.workers:
	mov	rdi,rbx
	call	node_decimal
	jc	.advance			; "auto"
	mov	[g_plan_workers],eax
	jmp	.advance
.engine:
	mov	rax,[rbx+N_ARGS]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	lea	rdx,[e_io_engine]
	call	list_index
	mov	[g_plan_engine],eax
	jmp	.advance
.watchdog:
	mov	rdi,rbx
	call	node_duration
	mov	[g_plan_watchdog],rax
	jmp	.advance
.drain:
	mov	rdi,rbx
	lea	rsi,[str_key_delay]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_duration
	mov	[g_plan_drain_delay],rax
@@:
	mov	rdi,rbx
	lea	rsi,[str_key_timeout]
	call	node_option
	test	rax,rax
	jz	.advance
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_duration
	mov	[g_plan_drain_timeout],rax
.advance:
	mov	rbx,[rbx+N_NEXT]
	jmp	.next
.done:
	pop	r12
	pop	rbx
	ret

; New pool. rdi/esi = name (or 0 for an inline pool). rax = pool entry,
; ecx = its index.
pool_new:
	mov	ecx,[g_plan_pools]
	cmp	ecx,MAX_POOLS
	jae	plan_too_many
	inc	dword [g_plan_pools]
	imul	rax,rcx,PL_SIZE
	lea	rax,[g_pools+rax]
	mov	[rax+PL_NAME],rdi
	mov	[rax+PL_NLEN],esi
	mov	edx,[g_plan_servers]
	mov	[rax+PL_FIRST],edx
	mov	qword [rax+PL_TIMEOUT],DEFAULT_CONNECT_US / 1000000
	mov	qword [rax+PL_TIMEOUT+8],(DEFAULT_CONNECT_US mod 1000000) * 1000
	mov	dword [rax+PL_BALANCE],BAL_LEAST_REQ
	ret

; Access log destinations. The table only grows while the supervisor
; lives: a destination keeps its number across reloads, so lines from
; workers still draining an older configuration reach the right file.
ALOG_MAX	:= 32
ALOG_PATH	:= 256

bss
	g_alog_dest	rb ALOG_MAX * ALOG_PATH	; NUL-terminated: stdout, stderr or a path
	g_alog_count	dd ?
end bss

; rdi/esi = `access_log` argument. eax = destination + 1, or 0 for off.
alog_dest_id:
	cmp	esi,3
	jne	@f
	cmp	word [rdi],'of'
	jne	@f
	cmp	byte [rdi+2],'f'
	jne	@f
	xor	eax,eax
	ret
@@:
	push	rbx
	xor	ebx,ebx
.find:
	cmp	ebx,[g_alog_count]
	jae	.add
	imul	r8,rbx,ALOG_PATH
	lea	r8,[g_alog_dest+r8]
	xor	ecx,ecx
.cmp:
	cmp	ecx,esi
	je	.end
	mov	al,[rdi+rcx]
	cmp	al,[r8+rcx]
	jne	.other
	inc	ecx
	jmp	.cmp
.end:
	cmp	byte [r8+rcx],0
	je	.found
.other:
	inc	ebx
	jmp	.find
.add:
	cmp	ebx,ALOG_MAX
	jae	.too_many
	imul	r8,rbx,ALOG_PATH
	lea	r8,[g_alog_dest+r8]
	xor	ecx,ecx
@@:
	mov	al,[rdi+rcx]
	mov	[r8+rcx],al
	inc	ecx
	cmp	ecx,esi
	jb	@b
	mov	byte [r8+rcx],0
	inc	dword [g_alog_count]
.found:
	lea	eax,[rbx+1]
	pop	rbx
	ret
.too_many:
	call	log_begin
	out_lit 'more than 32 different access log destinations since okena started'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; rdi = route node. eax = its action + 1, or 0 when it only forwards.
compile_route_action:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	; anything to do?
	mov	rbx,[r12+N_CHILD]
@@:
	test	rbx,rbx
	jz	.none
	mov	rax,[rbx+N_DEF]
	lea	rcx,[dir_table + D_SIZE*DIR_REDIRECT]
	cmp	rax,rcx
	je	@f
	lea	rcx,[dir_table + D_SIZE*DIR_RHEADER]
	cmp	rax,rcx
	je	@f
	lea	rcx,[dir_table + D_SIZE*DIR_RRESPONSE]
	cmp	rax,rcx
	je	@f
	lea	rcx,[dir_table + D_SIZE*DIR_REWRITE]
	cmp	rax,rcx
	je	@f
	mov	rbx,[rbx+N_NEXT]
	jmp	@b
@@:
	mov	ecx,[g_plan_acts]
	cmp	ecx,MAX_ACTS
	jae	plan_too_many
	inc	dword [g_plan_acts]
	push	rcx
	imul	r13,rcx,RA_SIZE
	lea	r13,[g_acts+r13]
	mov	rdi,r12
	mov	ecx,DIR_REDIRECT
	call	find_child
	test	rax,rax
	jz	.ops
	mov	rbx,[rax+N_ARGS]
	mov	rdi,[rbx+A_VAL]
	mov	esi,[rbx+A_VLEN]
	call	parse_decimal
	mov	[r13+RA_CODE],eax
	mov	rax,[rbx+A_SIZE+A_VAL]
	mov	[r13+RA_TGT],rax
	mov	eax,[rbx+A_SIZE+A_VLEN]
	mov	[r13+RA_TLEN],eax
.ops:
	mov	rdi,r12
	mov	ecx,DIR_REWRITE
	call	find_child
	test	rax,rax
	jz	@f
	mov	rbx,[rax+N_ARGS]
	mov	rax,[rbx+A_SIZE+A_VAL]
	mov	[r13+RA_WFROM],rax
	mov	eax,[rbx+A_SIZE+A_VLEN]
	sub	eax,3				; without {*}
	mov	[r13+RA_WFLEN],eax
	mov	rax,[rbx+3*A_SIZE+A_VAL]
	mov	[r13+RA_WTO],rax
	mov	eax,[rbx+3*A_SIZE+A_VLEN]
	mov	[r13+RA_WTLEN],eax
@@:
	mov	eax,[g_plan_hdrops]
	mov	[r13+RA_QFIRST],eax
	mov	ecx,DIR_RHEADER
	xor	edx,edx
	call	.collect
	mov	eax,[g_plan_hdrops]
	sub	eax,[r13+RA_QFIRST]
	mov	[r13+RA_QCOUNT],eax
	mov	eax,[g_plan_hdrops]
	mov	[r13+RA_PFIRST],eax
	mov	ecx,DIR_RRESPONSE
	mov	edx,1				; after "header"
	call	.collect
	mov	eax,[g_plan_hdrops]
	sub	eax,[r13+RA_PFIRST]
	mov	[r13+RA_PCOUNT],eax
	pop	rax
	inc	eax
	jmp	.out
.none:
	xor	eax,eax
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret
; ecx = directive, edx = arguments before the operation: one entry per
; such line of the route, in order.
.collect:
	push	r14
	push	r15
	imul	ecx,ecx,D_SIZE
	lea	r14,[dir_table+rcx]
	mov	r15d,edx
	mov	rbx,[r12+N_CHILD]
.line:
	test	rbx,rbx
	jz	.collected
	cmp	[rbx+N_DEF],r14
	jne	.next_line
	mov	ecx,[g_plan_hdrops]
	cmp	ecx,MAX_HDROPS
	jae	plan_too_many
	inc	dword [g_plan_hdrops]
	imul	r8,rcx,HD_SIZE
	lea	r8,[g_hdrops+r8]
	imul	r9,r15,A_SIZE
	add	r9,[rbx+N_ARGS]			; the operation
	mov	rax,[r9+A_VAL]
	mov	ecx,HOP_SET
	cmp	byte [rax],'s'
	je	@f
	mov	ecx,HOP_ADD
	cmp	byte [rax],'a'
	je	@f
	mov	ecx,HOP_DROP
@@:
	mov	[r8+HD_KIND],ecx
	mov	rax,[r9+A_SIZE+A_VAL]
	mov	[r8+HD_NAME],rax
	mov	eax,[r9+A_SIZE+A_VLEN]
	mov	dword [r8+HD_PREFIX],0
	mov	rdx,[r9+A_SIZE+A_VAL]
	cmp	byte [rdx+rax-1],'*'
	jne	@f
	dec	eax
	mov	dword [r8+HD_PREFIX],1
@@:
	mov	[r8+HD_NLEN],eax
	cmp	ecx,HOP_DROP
	je	.next_line
	mov	rax,[r9+2*A_SIZE+A_VAL]
	mov	[r8+HD_VAL],rax
	mov	eax,[r9+2*A_SIZE+A_VLEN]
	mov	[r8+HD_VLEN],eax
	; count the ${...} (checked already)
	mov	dword [r8+HD_VARS],0
	mov	rdx,rax
	mov	rax,[r8+HD_VAL]
	xor	ecx,ecx
@@:
	lea	r10d,[rcx+1]
	cmp	r10d,edx
	jae	@f
	cmp	word [rax+rcx],'${'
	jne	.no_var
	inc	dword [r8+HD_VARS]
.no_var:
	inc	ecx
	jmp	@b
@@:
.next_line:
	mov	rbx,[rbx+N_NEXT]
	jmp	.line
.collected:
	pop	r15
	pop	r14
	ret

; rcx = route entry, edx = its index: into g_rhash.
route_insert:
	push	rcx
	push	rdx
	mov	edi,[g_cmp_rfirst]
	call	rhash_seed
	mov	rsi,[rcx+RT_PATH]
	mov	edx,[rcx+RT_PLEN]
	call	rhash_bytes
	mov	rcx,[rsp+8]
	mov	ecx,[rcx+RT_PREFIX]
	call	rhash_final
	pop	rdx
	pop	rcx
	mov	r8d,eax
.probe:
	and	r8d,RHASH_SIZE - 1
	cmp	qword [g_rhash+r8*8],0
	je	.slot
	inc	r8d
	jmp	.probe
.slot:
	lea	r9d,[rdx+1]
	shl	r9,32
	or	r9,rax
	mov	[g_rhash+r8*8],r9
	ret

; Path hashing (FNV-1a), in three steps so a request path is hashed in one
; pass: the state after each '/' is the hash of that prefix.
; edi = route set's first entry. eax = the initial state.
rhash_seed:
	mov	eax,2166136261
	xor	eax,edi
	imul	eax,eax,16777619
	ret
; eax = state, rsi/edx = bytes. eax = state after them. Clobbers r8, r9.
rhash_bytes:
	xor	r8d,r8d
@@:
	cmp	r8d,edx
	jae	@f
	movzx	r9d,byte [rsi+r8]
	xor	eax,r9d
	imul	eax,eax,16777619
	inc	r8d
	jmp	@b
@@:
	ret
; eax = state, ecx = 1 for a prefix, 0 for an exact path. eax = the key.
rhash_final:
	xor	eax,ecx
	imul	eax,eax,16777619
	xor	eax,0x5BD1E995
	imul	eax,eax,16777619
	ret

; edi = seed (a listener's first host entry), rsi/edx = name, ecx = 1
; for a wildcard suffix. eax = FNV-1a hash of it all, A-Z folded to
; lower case. Clobbers r8-r10.
host_hash:
	mov	eax,2166136261
	xor	eax,edi
	imul	eax,eax,16777619
	xor	eax,ecx
	imul	eax,eax,16777619
	xor	r8d,r8d
.byte:
	cmp	r8d,edx
	jae	.done
	movzx	r9d,byte [rsi+r8]
	lea	r10d,[r9-'A']
	cmp	r10d,25
	ja	@f
	or	r9d,0x20
@@:
	xor	eax,r9d
	imul	eax,eax,16777619
	inc	r8d
	jmp	.byte
.done:
	ret

; rdi = timeout block, ecx = directive. eax = its duration in whole
; seconds (at least one), or CF when absent.
timeout_secs:
	call	find_child
	test	rax,rax
	jz	.absent
	mov	rdi,rax
	call	node_duration
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	test	eax,eax
	jnz	@f
	inc	eax
@@:
	clc
	ret
.absent:
	stc
	ret

plan_too_many:
	call	log_begin
	out_lit 'the configuration needs more than this build holds: at most '
	mov	eax,MAX_LISTENERS
	call	out_u64
	out_lit ' listener addresses, '
	mov	eax,MAX_POOLS
	call	out_u64
	out_lit ' pools, '
	mov	eax,MAX_SERVERS
	call	out_u64
	out_lit ' servers, '
	mov	eax,MAX_ROUTES
	call	out_u64
	out_lit ' route paths, '
	mov	eax,MAX_HOSTS
	call	out_u64
	out_lit ' host names'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; rdi = pool node.
compile_pool:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	mov	rax,[r12+N_ARGS]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	pool_new
	mov	r13,rax
	mov	rbx,[r12+N_CHILD]
.next:
	test	rbx,rbx
	jz	.done
	mov	rax,[rbx+N_DEF]
	lea	rcx,[dir_table + D_SIZE*DIR_SERVER]
	cmp	rax,rcx
	je	.server
	lea	rcx,[dir_table + D_SIZE*DIR_BALANCE]
	cmp	rax,rcx
	je	.balance
	lea	rcx,[dir_table + D_SIZE*DIR_SLOW_START]
	cmp	rax,rcx
	je	.slow_start
	lea	rcx,[dir_table + D_SIZE*DIR_CONNECT]
	cmp	rax,rcx
	je	.connect
	lea	rcx,[dir_table + D_SIZE*DIR_HEALTH]
	cmp	rax,rcx
	je	.health
	lea	rcx,[dir_table + D_SIZE*DIR_UPTLS]
	cmp	rax,rcx
	je	.uptls
	jmp	.advance
.health:
	mov	dword [r13+PL_HEALTH],1
	inc	dword [g_plan_health]
	mov	dword [r13+PL_H_EVERY],2000
	mov	dword [r13+PL_H_TIMEOUT],1000
	mov	dword [r13+PL_H_RISE],2
	mov	dword [r13+PL_H_FALL],3
	; http: [GET|HEAD] PATH, expect=, host=
	mov	rax,[rbx+N_ARGS]
	mov	rdi,[rax+A_VAL]
	cmp	byte [rdi],'h'
	jne	.health_keys
	mov	dword [r13+PL_H_HTTP],1
	mov	dword [r13+PL_H_LO],200
	mov	dword [r13+PL_H_HI],399
	push	rax
	mov	rdi,rbx
	call	positional_count
	mov	ecx,eax
	pop	rax
	cmp	ecx,3
	jne	@f
	mov	rdx,[rax+A_SIZE+A_VAL]
	cmp	byte [rdx],'H'
	jne	@f
	mov	dword [r13+PL_H_HEAD],1
@@:
	dec	ecx
	imul	rcx,rcx,A_SIZE
	add	rax,rcx
	mov	rdx,[rax+A_VAL]
	mov	[r13+PL_H_PATH],rdx
	mov	edx,[rax+A_VLEN]
	mov	[r13+PL_H_PLEN],edx
	mov	rdi,rbx
	lea	rsi,[str_key_expect]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_statuses
	mov	[r13+PL_H_LO],eax
	mov	[r13+PL_H_HI],edx
@@:
	mov	rdi,rbx
	lea	rsi,[str_key_host]
	call	node_option
	test	rax,rax
	jz	.health_keys
	mov	rdx,[rax+A_VAL]
	mov	[r13+PL_H_HOST],rdx
	mov	edx,[rax+A_VLEN]
	mov	[r13+PL_H_HLEN],edx
.health_keys:
	mov	rdi,rbx
	lea	rsi,[str_key_every]
	call	node_option
	test	rax,rax
	jz	@f
	call	.ms
	mov	[r13+PL_H_EVERY],eax
@@:
	mov	rdi,rbx
	lea	rsi,[str_key_timeout]
	call	node_option
	test	rax,rax
	jz	@f
	call	.ms
	mov	[r13+PL_H_TIMEOUT],eax
@@:
	mov	rdi,rbx
	lea	rsi,[str_key_rise]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_decimal
	mov	[r13+PL_H_RISE],eax
@@:
	mov	rdi,rbx
	lea	rsi,[str_key_fall]
	call	node_option
	test	rax,rax
	jz	.advance
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_decimal
	mov	[r13+PL_H_FALL],eax
	jmp	.advance
; rax = arg with a duration: eax = milliseconds (at least 1)
.ms:
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_duration
	xor	edx,edx
	mov	ecx,1000
	div	rcx
	test	eax,eax
	jnz	@f
	inc	eax
@@:
	ret
.server:
	mov	rdi,r13
	mov	rsi,rbx
	call	compile_server
	jmp	.advance
.slow_start:
	mov	rax,[rbx+N_ARGS]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_duration
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	test	eax,eax
	jnz	@f
	inc	eax				; at least a second
@@:
	mov	[r13+PL_SLOW],eax
	jmp	.advance
.balance:
	mov	rax,[rbx+N_ARGS]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	lea	rdx,[e_balance]
	call	list_index
	mov	[r13+PL_BALANCE],eax
	jmp	.advance
.connect:
	mov	rdi,rbx
	lea	rsi,[str_key_timeout]
	call	node_option
	test	rax,rax
	jz	.advance
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_duration
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	mov	[r13+PL_TIMEOUT],rax
	imul	rdx,rdx,1000
	mov	[r13+PL_TIMEOUT+8],rdx
	jmp	.advance
.uptls:
	mov	dword [r13+PL_TLS],1
	mov	rdi,rbx				; sni = SNI + the name verified (optional)
	lea	rsi,[str_key_sni]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rdx,[rax+A_VAL]
	mov	[r13+PL_TLS_SNI],rdx
	mov	edx,[rax+A_VLEN]
	mov	[r13+PL_TLS_SNILEN],edx
@@:
	mov	rdi,rbx				; trust = a PEM file of trust anchors
	lea	rsi,[str_key_trust]
	call	node_option
	test	rax,rax
	jz	.advance			; (check requires it; absence is handled there)
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,4095
	ja	.advance
	mov	rsi,[rax+A_VAL]			; copy the path, NUL-terminated
	lea	rdi,[g_trust_path]
	push	rcx
	rep	movsb
	pop	rcx
	mov	byte [g_trust_path+rcx],0
	lea	rdi,[g_trust_path]
	lea	rsi,[g_ar_text]			; read_file allocates from this arena
	call	read_file			; rax = contents, rdx = length, or rax < 0
	test	rax,rax
	js	.advance
	mov	rsi,rax				; the first CERTIFICATE -> DER
	mov	edx,edx
	lea	rdi,[g_trust_der]
	call	pem_first_cert
	test	eax,eax
	jz	.advance
	lea	rsi,[g_trust_der]		; -> the anchor's public key (EC or RSA)
	mov	edx,eax
	lea	rdi,[r13+PL_TLS_ANCHOR]
	call	cert_pubkey
	test	eax,eax
	jz	.advance
	mov	dword [r13+PL_TLS_HASANCHOR],1
.advance:
	mov	rbx,[rbx+N_NEXT]
	jmp	.next
.done:
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = pool entry, rsi = server node.
compile_server:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	mov	r13,rsi
	mov	rbx,[r13+N_ARGS]
	mov	rdi,rbx
	mov	rsi,r12
	call	server_new			; rax = server
	mov	rbx,rax
	; flags and weight
	mov	rcx,[r13+N_ARGS]
	mov	edx,[r13+N_ARGC]
.args:
	add	rcx,A_SIZE
	dec	edx
	jz	.weight
	cmp	dword [rcx+A_KIND],ARG_WORD
	jne	.args
	mov	dword [rbx+SV_BACKUP],1		; the only flag is `backup`
	jmp	.args
.weight:
	mov	rdi,r13
	lea	rsi,[str_key_weight]
	call	node_option
	test	rax,rax
	jz	.counted
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_decimal
	mov	[rbx+SV_WEIGHT],eax
.counted:
	cmp	dword [rbx+SV_BACKUP],0
	jne	@f
	inc	dword [r12+PL_PRIMARY]
@@:
	; a name's other slots take the same weight and role
	cmp	dword [rbx+SV_GROUP],0
	je	.out
	mov	eax,[rbx+SV_WEIGHT]
	mov	ecx,[rbx+SV_BACKUP]
	mov	edx,DNS_MAX_ADDRS - 1
	lea	r8,[rbx+SV_SIZE]
@@:
	mov	[r8+SV_WEIGHT],eax
	mov	[r8+SV_BACKUP],ecx
	add	r8,SV_SIZE
	dec	edx
	jnz	@b
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

cstring str_localhost, 'localhost',0

; rdi = address arg, rsi = pool entry. rax = new server (weight 1).
server_new:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	mov	r13,rsi
	mov	ecx,[g_plan_servers]
	cmp	ecx,MAX_SERVERS
	jae	plan_too_many
	inc	dword [g_plan_servers]
	inc	dword [r13+PL_COUNT]
	imul	rbx,rcx,SV_SIZE
	lea	rbx,[g_servers+rbx]
	mov	dword [rbx+SV_WEIGHT],1
	mov	rax,[r12+A_VAL]
	mov	[rbx+SV_TEXT],rax
	mov	eax,[r12+A_VLEN]
	mov	[rbx+SV_TLEN],eax
	mov	rdi,[r12+A_VAL]
	mov	esi,[r12+A_VLEN]
	lea	rdx,[g_cmp_addr]
	mov	ecx,1
	call	parse_address
	mov	eax,[g_cmp_addr+AD_KIND]
	cmp	eax,ADDR_NAME
	jne	.build
	; "localhost" is the loopback address by definition (RFC 6761)
	mov	rdi,[g_cmp_addr+AD_NAME]
	mov	esi,[g_cmp_addr+AD_NLEN]
	lea	rdx,[str_localhost]
	call	mem_eq_cstr
	test	eax,eax
	jz	.name
	mov	dword [g_cmp_addr+AD_KIND],ADDR_V4
	mov	dword [g_cmp_addr+AD_IP],0x0100007F
.build:
	lea	rdi,[rbx+SV_SA]
	lea	rsi,[g_cmp_addr]
	call	sockaddr_build
	mov	[rbx+SV_SALEN],eax
	mov	[rbx+SV_FAMILY],edx
	mov	dword [rbx+SV_ACTIVE],1
	mov	rax,rbx
	pop	r13
	pop	r12
	pop	rbx
	ret
.name:
	; a name: DNS_MAX_ADDRS slots, filled in when it resolves
	mov	ecx,[g_plan_groups]
	cmp	ecx,MAX_GROUPS
	jae	plan_too_many
	inc	dword [g_plan_groups]
	imul	rax,rcx,GR_SIZE
	lea	rax,[g_groups+rax]
	mov	rdx,[g_cmp_addr+AD_NAME]
	mov	[rax+GR_NAME],rdx
	mov	edx,[g_cmp_addr+AD_NLEN]
	mov	[rax+GR_NLEN],edx
	mov	edx,[g_cmp_addr+AD_PORT]
	mov	[rax+GR_PORT],edx
	mov	edx,[g_plan_servers]
	dec	edx				; this slot is the first
	mov	[rax+GR_FIRST],edx
	inc	ecx
	mov	[rbx+SV_GROUP],ecx
	mov	dword [rbx+SV_ACTIVE],0
	mov	r8d,DNS_MAX_ADDRS - 1
.more_slots:
	mov	edx,[g_plan_servers]
	cmp	edx,MAX_SERVERS
	jae	plan_too_many
	inc	dword [g_plan_servers]
	inc	dword [r13+PL_COUNT]
	imul	rdx,rdx,SV_SIZE
	lea	rdx,[g_servers+rdx]
	mov	dword [rdx+SV_WEIGHT],1
	mov	rax,[rbx+SV_TEXT]
	mov	[rdx+SV_TEXT],rax
	mov	eax,[rbx+SV_TLEN]
	mov	[rdx+SV_TLEN],eax
	mov	[rdx+SV_GROUP],ecx
	dec	r8d
	jnz	.more_slots
	mov	rax,rbx
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = sockaddr output, rsi = parsed address.
; eax = sockaddr length, edx = family.
sockaddr_build:
	mov	ecx,[rsi+AD_KIND]
	cmp	ecx,ADDR_V4
	je	.v4
	cmp	ecx,ADDR_UNIX
	je	.unix
	; IPv6, or ":port" bound as dual-stack IPv6
	mov	word [rdi],AF_INET6
	mov	eax,[rsi+AD_PORT]
	xchg	al,ah
	mov	[rdi+2],ax
	mov	dword [rdi+4],0
	mov	rax,[rsi+AD_IP]
	mov	[rdi+8],rax
	mov	rax,[rsi+AD_IP+8]
	mov	[rdi+16],rax
	mov	dword [rdi+24],0
	mov	eax,28
	mov	edx,AF_INET6
	ret
.v4:
	mov	word [rdi],AF_INET
	mov	eax,[rsi+AD_PORT]
	xchg	al,ah
	mov	[rdi+2],ax
	mov	eax,[rsi+AD_IP]
	mov	[rdi+4],eax
	mov	qword [rdi+8],0
	mov	eax,16
	mov	edx,AF_INET
	ret
.unix:
	mov	word [rdi],AF_UNIX
	push	rsi
	push	rdi
	mov	ecx,[rsi+AD_NLEN]
	mov	rsi,[rsi+AD_NAME]
	add	rdi,2
	rep	movsb
	mov	byte [rdi],0
	pop	rdi
	pop	rsi
	mov	eax,[rsi+AD_NLEN]
	add	eax,3				; family + path + NUL
	mov	edx,AF_UNIX
	ret

cstring str_word_pool, 'pool',0

; rdi = tcp node: one listener per address.
compile_listener:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rdi
	mov	r14d,-1				; http: routes choose the pool
	mov	dword [g_cmp_pt],0
	lea	rax,[dir_table + D_SIZE*DIR_HTTP]
	cmp	[r12+N_DEF],rax
	je	.http
	mov	rdi,r12
	call	listener_passthrough
	test	rax,rax
	jz	@f
	mov	rdi,r12
	call	compile_passthrough		; the pools from its sni lines
	mov	r14d,eax
	jmp	.settings
@@:
	mov	rdi,r12
	call	compile_target
	mov	r14d,eax
	jmp	.settings
.http:
	mov	rdi,r12
	call	compile_hosts			; g_cmp_hfirst/hcount
	mov	rdi,r12
	call	compile_routes			; g_cmp_rfirst/rcount: the default routes
.settings:
	; limits and timeouts
	mov	r15d,DEFAULT_CONNECTIONS
	mov	rdi,r12
	mov	ecx,DIR_LIMITS
	call	find_child
	test	rax,rax
	jz	@f
	mov	rdi,rax
	mov	ecx,DIR_CONNECTIONS
	call	find_child
	test	rax,rax
	jz	@f
	mov	rdi,rax
	call	node_decimal
	mov	r15d,eax
@@:
	; client address features
	xor	eax,eax
	mov	[g_cmp_flags],eax
	mov	[g_cmp_per_source],eax
	mov	rdi,r12
	mov	ecx,DIR_LIMITS
	call	find_child
	test	rax,rax
	jz	@f
	mov	rdi,rax
	mov	ecx,DIR_PER_SOURCE
	call	find_child
	test	rax,rax
	jz	@f
	mov	rdi,rax
	call	node_decimal
	mov	[g_cmp_per_source],eax
	or	dword [g_cmp_flags],LSF_PEER
@@:
	mov	rdi,r12
	mov	ecx,DIR_PROXY_PROTOCOL
	call	find_child
	test	rax,rax
	jz	@f
	mov	rax,[rax+N_ARGS]
	add	rax,A_SIZE			; the version
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	lea	rdx,[e_pp_version]
	call	list_index
	mov	ecx,LSF_PEER or LSF_PP_V1
	test	eax,eax
	jz	.pp
	mov	ecx,LSF_PEER or LSF_PP_V2
.pp:
	or	[g_cmp_flags],ecx
@@:
	mov	ebx,DEFAULT_IDLE_SECS
	lea	rax,[dir_table + D_SIZE*DIR_HTTP]
	cmp	[r12+N_DEF],rax
	jne	@f
	mov	ebx,DEFAULT_HTTP_IDLE_SECS	; keep-alive clients
@@:
	mov	rdi,r12
	call	compile_tls			; reads and checks the files
	mov	[g_cmp_tlsi],eax
	mov	rdi,r12				; `ktls on`: records in the kernel
	mov	ecx,DIR_TLS
	call	find_child
	test	rax,rax
	jz	@f
	mov	rdi,rax
	mov	ecx,DIR_KTLS
	call	find_child
	test	rax,rax
	jz	@f
	mov	rax,[rax+N_ARGS]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	lea	rdx,[e_onoff]
	call	list_index
	test	eax,eax
	jnz	@f
	or	dword [g_cmp_flags],LSF_KTLS
@@:
	mov	dword [g_cmp_alog],0
	mov	rdi,r12
	mov	ecx,DIR_ACCESS_LOG
	call	find_child
	test	rax,rax
	jz	@f
	mov	rax,[rax+N_ARGS]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	alog_dest_id
	mov	[g_cmp_alog],eax
@@:
	; trusted_proxies
	mov	eax,[g_plan_trust]
	mov	[g_cmp_tfirst],eax
	mov	dword [g_cmp_tcount],0
	mov	rdi,r12
	mov	ecx,DIR_TRUSTED
	call	find_child
	test	rax,rax
	jz	.trust_done
	push	rbx
	push	r13
	mov	rbx,rax
	xor	r13d,r13d
.trust:
	cmp	r13d,[rbx+N_ARGC]
	jae	.trust_end
	mov	ecx,[g_plan_trust]
	cmp	ecx,MAX_TRUST
	jae	plan_too_many
	inc	dword [g_plan_trust]
	inc	dword [g_cmp_tcount]
	imul	rdx,rcx,TR_SIZE
	lea	rdx,[g_trust+rdx]
	imul	rax,r13,A_SIZE
	add	rax,[rbx+N_ARGS]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_cidr			; checked already
	inc	r13d
	jmp	.trust
.trust_end:
	pop	r13
	pop	rbx
.trust_done:
	mov	dword [g_cmp_t_header],DEFAULT_HEADER_SECS
	mov	dword [g_cmp_t_response],DEFAULT_RESPONSE_SECS
	mov	dword [g_cmp_t_body],DEFAULT_BODY_SECS
	mov	rdi,r12
	mov	ecx,DIR_TIMEOUT
	call	find_child
	test	rax,rax
	jz	.addresses
	push	rax
	mov	rdi,rax
	mov	ecx,DIR_HEADER
	call	timeout_secs
	jc	@f
	mov	[g_cmp_t_header],eax
@@:
	mov	rdi,[rsp]
	mov	ecx,DIR_RESPONSE
	call	timeout_secs
	jc	@f
	mov	[g_cmp_t_response],eax
@@:
	mov	rdi,[rsp]
	mov	ecx,DIR_BODY_IDLE
	call	timeout_secs
	jc	@f
	mov	[g_cmp_t_body],eax
@@:
	pop	rdi
	mov	ecx,DIR_IDLE
	call	timeout_secs
	jc	.addresses
	mov	ebx,eax
.addresses:
	xor	r13d,r13d
.address:
	cmp	r13d,[r12+N_ARGC]
	jae	.done
	mov	ecx,[g_plan_listeners]
	cmp	ecx,MAX_LISTENERS
	jae	plan_too_many
	inc	dword [g_plan_listeners]
	imul	rcx,rcx,LS_SIZE
	lea	rcx,[g_listeners+rcx]
	mov	[rcx+LS_POOL],r14d
	mov	[rcx+LS_IDLE],ebx
	mov	eax,[g_cmp_t_header]
	mov	[rcx+LS_T_HEADER],eax
	mov	eax,[g_cmp_t_response]
	mov	[rcx+LS_T_RESPONSE],eax
	mov	eax,[g_cmp_t_body]
	mov	[rcx+LS_T_BODY],eax
	mov	eax,[g_cmp_alog]
	mov	[rcx+LS_ALOG],eax
	mov	eax,[g_cmp_tlsi]
	mov	[rcx+LS_TLS],eax
	mov	eax,[g_cmp_pt]
	mov	[rcx+LS_PT],eax
	mov	eax,[g_cmp_tfirst]
	mov	[rcx+LS_TFIRST],eax
	mov	eax,[g_cmp_tcount]
	mov	[rcx+LS_TCOUNT],eax
	mov	[rcx+LS_MAXCONN],r15d		; whole instance; split per worker later
	imul	rax,r13,A_SIZE
	add	rax,[r12+N_ARGS]
	mov	rdx,[rax+A_VAL]
	mov	[rcx+LS_TEXT],rdx
	mov	edx,[rax+A_VLEN]
	mov	[rcx+LS_TLEN],edx
	push	rcx
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	lea	rdx,[g_cmp_addr]
	xor	ecx,ecx
	call	parse_address
	pop	rdi
	push	rdi
	lea	rsi,[g_cmp_addr]
	call	sockaddr_build
	pop	rcx
	mov	[rcx+LS_SALEN],eax
	mov	[rcx+LS_FAMILY],edx
	cmp	dword [g_cmp_addr+AD_KIND],ADDR_ANY
	jne	@f
	mov	dword [rcx+LS_FAMILY],0		; dual stack
@@:
	mov	eax,[g_cmp_addr+AD_PORT]
	mov	[rcx+LS_PORT],eax
	mov	eax,[g_cmp_flags]
	cmp	dword [g_cmp_addr+AD_KIND],ADDR_ANY
	je	.wild
	push	rcx
	lea	rdi,[g_cmp_addr+AD_IP]
	call	ip_is_unspecified
	pop	rcx
	jnc	@f
.wild:
	or	eax,LSF_WILDCARD
@@:
	mov	[rcx+LS_FLAGS],eax
	mov	eax,[g_cmp_per_source]
	mov	[rcx+LS_PER_SOURCE],eax
	xor	eax,eax
	lea	rdx,[dir_table + D_SIZE*DIR_HTTP]
	cmp	[r12+N_DEF],rdx
	jne	@f
	inc	eax
@@:
	mov	[rcx+LS_KIND],eax
	test	eax,eax
	jz	@f
	or	dword [rcx+LS_FLAGS],LSF_PEER	; X-Forwarded-For needs the client
@@:
	mov	eax,[g_cmp_rfirst]
	mov	[rcx+LS_RFIRST],eax
	mov	eax,[g_cmp_rcount]
	mov	[rcx+LS_RCOUNT],eax
	mov	eax,[g_cmp_hfirst]
	mov	[rcx+LS_HFIRST],eax
	mov	eax,[g_cmp_hcount]
	mov	[rcx+LS_HCOUNT],eax
	inc	r13d
	jmp	.address
.done:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = 16 address bytes (IPv4 in the first 4). CF when all zero.
; Keeps rax.
ip_is_unspecified:
	mov	rdx,[rdi]
	or	rdx,[rdi+8]
	jnz	.no
	stc
	ret
.no:
	clc
	ret

; rdi = node with a `to` child (tcp listener or route). eax = its pool:
; a named one, or a new anonymous pool for `to ADDR...`.
compile_target:
	push	rbx
	push	r12
	push	r13
	push	r15
	mov	r12,rdi
	mov	ecx,DIR_TO
	call	find_child
	mov	rbx,rax
	mov	r13,[rbx+N_ARGS]
	mov	rdi,[r13+A_VAL]
	mov	esi,[r13+A_VLEN]
	lea	rdx,[str_word_pool]
	call	mem_eq_cstr
	test	eax,eax
	jz	.inline
	add	r13,A_SIZE
	mov	rdi,[r13+A_VAL]
	mov	esi,[r13+A_VLEN]
	call	plan_pool_index
	jmp	.out
.inline:
	; the same addresses as an earlier inline target: the same pool, so
	; routes to one backend share its warm connections and its load
	call	inline_pool_find
	cmp	eax,-1
	jne	.out
	xor	edi,edi
	xor	esi,esi
	call	pool_new
	push	rcx
	mov	r15,rax
	xor	ecx,ecx
.inline_server:
	cmp	ecx,[rbx+N_ARGC]
	jae	.inline_done
	push	rcx
	imul	rdi,rcx,A_SIZE
	add	rdi,[rbx+N_ARGS]
	mov	rsi,r15
	call	server_new
	inc	dword [r15+PL_PRIMARY]
	pop	rcx
	inc	ecx
	jmp	.inline_server
.inline_done:
	pop	rax
.out:
	pop	r15
	pop	r13
	pop	r12
	pop	rbx
	ret

; rbx = `to` node with addresses. eax = an inline pool (no name) with
; exactly these addresses in this order, or -1.
inline_pool_find:
	push	r12
	push	r13
	xor	r12d,r12d
.pool:
	cmp	r12d,[g_plan_pools]
	jae	.none
	imul	r13,r12,PL_SIZE
	lea	r13,[g_pools+r13]
	cmp	qword [r13+PL_NAME],0
	jne	.next
	mov	eax,[r13+PL_COUNT]
	cmp	eax,[rbx+N_ARGC]
	jne	.next
	xor	ecx,ecx
.server:
	cmp	ecx,[rbx+N_ARGC]
	jae	.found
	mov	eax,[r13+PL_FIRST]
	add	eax,ecx
	imul	rax,rax,SV_SIZE
	lea	r8,[g_servers+rax]
	imul	rax,rcx,A_SIZE
	add	rax,[rbx+N_ARGS]
	mov	edx,[rax+A_VLEN]
	cmp	edx,[r8+SV_TLEN]
	jne	.next
	mov	rsi,[rax+A_VAL]
	mov	rdi,[r8+SV_TEXT]
	push	rcx
	xor	r9d,r9d
@@:
	cmp	r9d,edx
	jae	@f
	mov	al,[rsi+r9]
	cmp	al,[rdi+r9]
	jne	.differ
	inc	r9d
	jmp	@b
@@:
	pop	rcx
	inc	ecx
	jmp	.server
.differ:
	pop	rcx
.next:
	inc	r12d
	jmp	.pool
.found:
	mov	eax,r12d
	jmp	.out
.none:
	mov	eax,-1
.out:
	pop	r13
	pop	r12
	ret

; rdi = http node: a host entry per name of each host block, with that
; block's routes. g_cmp_hfirst/hcount = the range.
compile_hosts:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r12,rdi
	mov	eax,[g_plan_hosts]
	mov	[g_cmp_hfirst],eax
	mov	dword [g_cmp_hcount],0
	mov	rbx,[r12+N_CHILD]
.block:
	test	rbx,rbx
	jz	.done
	lea	rax,[dir_table + D_SIZE*DIR_HOST]
	cmp	[rbx+N_DEF],rax
	jne	.next
	mov	rdi,rbx
	call	compile_routes
	xor	r13d,r13d
.name:
	cmp	r13d,[rbx+N_ARGC]
	jae	.next
	mov	ecx,[g_plan_hosts]
	cmp	ecx,MAX_HOSTS
	jae	plan_too_many
	inc	dword [g_plan_hosts]
	inc	dword [g_cmp_hcount]
	imul	r14,rcx,HO_SIZE
	lea	r14,[g_hosts+r14]
	imul	rax,r13,A_SIZE
	add	rax,[rbx+N_ARGS]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	mov	dword [r14+HO_WILD],0
	cmp	esi,2
	jb	@f
	cmp	word [rdi],'*.'
	jne	@f
	inc	rdi				; keep the dot: ".example.com"
	dec	esi
	mov	dword [r14+HO_WILD],1
@@:
	mov	[r14+HO_NAME],rdi
	mov	[r14+HO_NLEN],esi
	; into the lookup table
	push	rcx
	mov	edx,esi
	mov	rsi,rdi
	mov	edi,[g_cmp_hfirst]
	mov	ecx,[r14+HO_WILD]
	call	host_hash
	pop	rcx
	mov	edx,HHASH_SIZE - 1
	mov	r8d,eax
.probe:
	and	r8d,edx
	cmp	qword [g_hhash+r8*8],0
	je	.slot
	inc	r8d
	jmp	.probe
.slot:
	lea	r9d,[rcx+1]
	shl	r9,32
	or	r9,rax
	mov	[g_hhash+r8*8],r9
	mov	eax,[g_cmp_rfirst]
	mov	[r14+HO_RFIRST],eax
	mov	eax,[g_cmp_rcount]
	mov	[r14+HO_RCOUNT],eax
	inc	r13d
	jmp	.name
.next:
	mov	rbx,[rbx+N_NEXT]
	jmp	.block
.done:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = http node: one route entry per path of each route.
; g_cmp_rfirst/rcount = its range.
compile_routes:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rdi
	mov	eax,[g_plan_routes]
	mov	[g_cmp_rfirst],eax
	mov	dword [g_cmp_rcount],0
	mov	rbx,[r12+N_CHILD]
.route:
	test	rbx,rbx
	jz	.done
	lea	rax,[dir_table + D_SIZE*DIR_ROUTE]
	cmp	[rbx+N_DEF],rax
	jne	.next
	mov	r13d,-1				; a redirect has no pool
	mov	rdi,rbx
	mov	ecx,DIR_REDIRECT
	call	find_child
	test	rax,rax
	jnz	@f
	mov	rdi,rbx
	call	compile_target
	mov	r13d,eax			; pool
@@:
	mov	rdi,rbx
	call	compile_route_action
	mov	[g_cmp_act],eax
	mov	rdi,rbx
	call	route_methods
	mov	r14d,eax
	xor	r15d,r15d
.arg:
	cmp	r15d,[rbx+N_ARGC]
	jae	.next
	imul	rsi,r15,A_SIZE
	add	rsi,[rbx+N_ARGS]
	mov	rdi,[rsi+A_VAL]
	cmp	byte [rdi],'/'
	jne	.arg_next
	mov	ecx,[g_plan_routes]
	cmp	ecx,MAX_ROUTES
	jae	plan_too_many
	inc	dword [g_plan_routes]
	inc	dword [g_cmp_rcount]
	imul	rcx,rcx,RT_SIZE
	lea	rcx,[g_routes+rcx]
	mov	[rcx+RT_PATH],rdi
	mov	eax,[rsi+A_VLEN]
	mov	dword [rcx+RT_PREFIX],0
	cmp	byte [rdi+rax-1],'*'
	jne	@f
	dec	eax				; "/api/*" matches what starts with "/api/"
	mov	dword [rcx+RT_PREFIX],1
@@:
	mov	[rcx+RT_PLEN],eax
	mov	[rcx+RT_METHODS],r14d
	mov	[rcx+RT_POOL],r13d
	mov	eax,[g_cmp_act]
	mov	[rcx+RT_ACT],eax
	push	rsi
	push	rdi
	mov	edx,[g_plan_routes]
	dec	edx
	call	route_insert
	pop	rdi
	pop	rsi
.arg_next:
	inc	r15d
	jmp	.arg
.next:
	mov	rbx,[rbx+N_NEXT]
	jmp	.route
.done:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi/esi = pool name. eax = index (the checker made sure it exists).
plan_pool_index:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	mov	r13d,esi
	xor	ebx,ebx
.next:
	cmp	ebx,[g_plan_pools]
	jae	.none
	imul	rax,rbx,PL_SIZE
	lea	rax,[g_pools+rax]
	cmp	[rax+PL_NLEN],r13d
	jne	.skip
	mov	rdi,[rax+PL_NAME]
	mov	rsi,r12
	mov	edx,r13d
	call	mem_eq
	test	eax,eax
	jnz	.found
.skip:
	inc	ebx
	jmp	.next
.found:
	mov	eax,ebx
	jmp	.out
.none:
	xor	eax,eax
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret
