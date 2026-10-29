; Compile the checked configuration tree into the plan: flat, fixed-size
; tables the workers read and never write. Addresses become sockaddr
; structures here, so the data path never parses text.

MAX_LISTENERS	= 64
MAX_POOLS	= 64
MAX_SERVERS	= 1024

; Listener
LS_SA		= 0		; sockaddr_in6 / sockaddr_in (28 bytes)
LS_SALEN	= 28		; d
LS_FAMILY	= 32		; d: AF_INET, AF_INET6, or 0 for ":port" (dual stack)
LS_POOL		= 36		; d
LS_IDLE		= 40		; d: idle timeout in seconds
LS_MAXCONN	= 44		; d: per worker
LS_TEXT		= 48		; q: address as written
LS_TLEN		= 56		; d
LS_PORT		= 60		; d
LS_SIZE		= 64

; Pool
PL_FIRST	= 0		; d: first server
PL_COUNT	= 4		; d
PL_BALANCE	= 8		; d: BAL_*
PL_PRIMARY	= 12		; d: servers that are not backups
PL_TIMEOUT	= 16		; 16 bytes: connect timeout as __kernel_timespec
PL_NAME		= 32		; q
PL_NLEN		= 40		; d
PL_HEALTH	= 44		; d: 1 when active checks run
PL_H_EVERY	= 48		; d: milliseconds
PL_H_TIMEOUT	= 52		; d: milliseconds
PL_H_RISE	= 56		; d
PL_H_FALL	= 60		; d
PL_SIZE		= 64

; Server
SV_SA		= 0		; sockaddr (sockaddr_un is 110 bytes)
SV_SALEN	= 112		; d
SV_FAMILY	= 116		; d
SV_WEIGHT	= 120		; d
SV_BACKUP	= 124		; d
SV_TEXT		= 128		; q
SV_TLEN		= 136		; d
SV_ACTIVE	= 140		; d: holds an address (names: once resolved)
SV_GROUP	= 144		; d: name group + 1, or 0 for an address
SV_SIZE		= 160

BAL_ROUND_ROBIN	= 0
BAL_LEAST_CONN	= 1
BAL_RANDOM	= 2

DEFAULT_CONNECTIONS	= 65536		; per listener, whole instance
DEFAULT_IDLE_SECS	= 3600
DEFAULT_CONNECT_US	= 2000000
DEFAULT_DRAIN_US	= 8000000

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
	g_plan_health		dd ?		; pools with active checks
	g_listeners:	rb LS_SIZE * MAX_LISTENERS
	g_pools:	rb PL_SIZE * MAX_POOLS
	g_servers:	rb SV_SIZE * MAX_SERVERS
	g_cmp_addr:	rb AD_SIZE
end bss

; Exits with EXIT_CONFIG when something valid in the language cannot be
; served by this build (host names, table limits).
plan_compile:
	push	rbx
	push	r12
	mov	qword [g_plan_drain_timeout],DEFAULT_DRAIN_US
	mov	qword [g_plan_watchdog],2000000
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
	jne	@f
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
cstring str_key_timeout, 'timeout',0
cstring str_key_weight, 'weight',0
cstring str_key_every, 'every',0
cstring str_key_rise, 'rise',0
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
	jmp	.advance
.busy_poll:
	mov	rdi,rbx
	call	node_duration
	mov	[g_plan_busy_poll],rax
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
	ret

plan_too_many:
	call	log_begin
	out_lit 'the configuration has more listeners, pools or servers than this build supports'
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
	lea	rcx,[dir_table + D_SIZE*DIR_CONNECT]
	cmp	rax,rcx
	je	.connect
	lea	rcx,[dir_table + D_SIZE*DIR_HEALTH]
	cmp	rax,rcx
	je	.health
	jmp	.advance
.health:
	mov	dword [r13+PL_HEALTH],1
	inc	dword [g_plan_health]
	mov	dword [r13+PL_H_EVERY],2000
	mov	dword [r13+PL_H_TIMEOUT],1000
	mov	dword [r13+PL_H_RISE],2
	mov	dword [r13+PL_H_FALL],3
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
	; pool
	mov	rdi,r12
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
	mov	r14d,eax
	jmp	.settings
.inline:
	xor	edi,edi
	xor	esi,esi
	call	pool_new
	mov	r14d,ecx
	mov	r15,rax
	xor	ecx,ecx
.inline_server:
	cmp	ecx,[rbx+N_ARGC]
	jae	.settings
	push	rcx
	imul	rdi,rcx,A_SIZE
	add	rdi,[rbx+N_ARGS]
	mov	rsi,r15
	call	server_new
	inc	dword [r15+PL_PRIMARY]
	pop	rcx
	inc	ecx
	jmp	.inline_server
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
	mov	ebx,DEFAULT_IDLE_SECS
	mov	rdi,r12
	mov	ecx,DIR_TIMEOUT
	call	find_child
	test	rax,rax
	jz	.addresses
	mov	rdi,rax
	mov	ecx,DIR_IDLE
	call	find_child
	test	rax,rax
	jz	.addresses
	mov	rdi,rax
	call	node_duration
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	test	eax,eax
	jnz	@f
	inc	eax				; at least one second
@@:
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
	inc	r13d
	jmp	.address
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
