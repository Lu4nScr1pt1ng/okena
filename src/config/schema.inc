; Configuration schema: which directives exist, where, and what they take.
;
; One table drives the checker. An entry says in which contexts the
; directive may appear, what its block contains, how many positional
; arguments it takes and of which type, and which key=value options it
; accepts. A directive with options and F_KEYS_BLOCK may also be written
; as a block with the same keys: `connect timeout=1s` = `connect { timeout 1s }`.

; Contexts (a directive's block opens one of these)
CTX_TOP		:= 1
CTX_OKENA	:= 2
CTX_TCP		:= 3
CTX_POOL	:= 4
CTX_LIMITS	:= 5
CTX_TIMEOUT	:= 6
CTX_HTTP	:= 7
CTX_ROUTE	:= 8
CTX_HOST	:= 9
CTX_TLS		:= 10

; Flags
F_BLOCK_REQ	:= 1		; must have a block
F_UNIQUE	:= 2		; at most once per block
F_KEYS_BLOCK	:= 4		; options may be written as a block

; Value types. Values of 4096 and above are pointers to enum lists.
T_NONE		:= 0
T_ANY		:= 1
T_NAME		:= 2
T_UINT		:= 3		; 0 .. 2^31
T_COUNT		:= 4		; 1 .. 100 000 000
T_WEIGHT	:= 5		; 1 .. 1000
T_DURATION	:= 6
T_SIZE		:= 7
T_RATE		:= 8
T_PERCENT	:= 9
T_LISTEN	:= 10		; listen address
T_BACKEND	:= 11		; backend address (names and unix paths too)
T_WORKERS	:= 12		; auto or 1 .. 256
T_TARGET	:= 13		; `to pool NAME` or `to ADDR...`
T_FUTURE	:= 14		; an option of the language not implemented yet
T_HOSTNAME	:= 16		; a host name, or *.example.com
T_ROUTE		:= 15		; a path ("/x", "/x/*", "/*") or a method (GET, POST...)
T_LOGDEST	:= 17		; stdout, stderr, off, or an absolute file path
T_CIDR		:= 18		; an IP address or a range: 10.0.0.0/8, 2001:db8::/32
T_STATUSES	:= 19		; an HTTP status or a range: 200, 200..299

; Directive entry
D_NAME		:= 0		; 24 bytes, NUL-padded
D_CTX		:= 24		; d: mask of contexts (1 shl CTX_*)
D_CHILD		:= 28		; d: context of its block, 0 = none
D_FLAGS		:= 32		; d
D_MINP		:= 36		; w
D_MAXP		:= 38		; w
D_TYPE1		:= 40		; q: type of the first positional argument
D_TYPEN		:= 48		; q: type of the others
D_KEYS		:= 56		; q: options table or 0
D_SIZE		:= 64

; Option entry
K_NAME		:= 0		; 24 bytes
K_TYPE		:= 24		; q
K_SIZE		:= 32

macro enumdef label*, items&
	rodata
		align 8
		label:
		iterate item, items
			db item,0
		end iterate
		db 0
	end rodata
end macro

macro keysdef label*, pairs&
	rodata
		align 8
		label:
		iterate <kname,ktype>, pairs
			db kname
			db (24 - lengthof kname) dup 0
			dq ktype
		end iterate
		dq 0,0,0,0
	end rodata
end macro

DIR_COUNT = 0

; id becomes the entry's index, for code that looks for one directive.
macro dirdef id*, name*, ctxmask*, child*, flags*, minp*, maxp*, type1*, typen*, keys*
	id = DIR_COUNT
	DIR_COUNT = DIR_COUNT + 1
	rodata
		db name
		db (24 - lengthof name) dup 0
		dd ctxmask, child, flags
		dw minp, maxp
		dq type1, typen, keys
	end rodata
end macro

M_TOP		:= 1 shl CTX_TOP
M_OKENA		:= 1 shl CTX_OKENA
M_TCP		:= 1 shl CTX_TCP
M_POOL		:= 1 shl CTX_POOL
M_LIMITS	:= 1 shl CTX_LIMITS
M_TIMEOUT	:= 1 shl CTX_TIMEOUT
M_HTTP		:= 1 shl CTX_HTTP
M_ROUTE		:= 1 shl CTX_ROUTE
M_HOST		:= 1 shl CTX_HOST
M_TLS		:= 1 shl CTX_TLS

enumdef e_io_engine, 'auto', 'io_uring', 'epoll'
enumdef e_balance, 'round-robin', 'least-conn', 'random', 'least-request', 'peak-ewma'
enumdef e_server_flags, 'backup'
enumdef e_health, 'tcp', 'http'
enumdef e_pp_mode, 'send'
enumdef e_redirect_codes, '301', '302', '303', '307', '308'
enumdef e_header_ops, 'set', 'add', 'drop'
enumdef e_response_what, 'header'
enumdef e_rewrite_what, 'path'
enumdef e_pp_version, 'v1', 'v2'
enumdef e_tls_mode, 'passthrough'

keysdef k_drain, 'delay', T_DURATION, 'timeout', T_DURATION
keysdef k_hs_budget, 'wait', T_DURATION
keysdef k_server, 'weight', T_WEIGHT
keysdef k_cert, 'key', T_ANY
keysdef k_health, 'every', T_DURATION, 'timeout', T_DURATION, 'rise', T_COUNT, 'fall', T_COUNT, \
	'expect', T_STATUSES, 'host', T_HOSTNAME
keysdef k_uptls, 'trust', T_ANY, 'sni', T_HOSTNAME
keysdef k_connect, 'timeout', T_DURATION, 'max', T_FUTURE, 'idle', T_FUTURE, \
	'warm', T_FUTURE, 'rate', T_FUTURE

; Names of the contexts, for messages, in CTX_* order starting at 1.
enumdef ctx_names, 'the top level', '`okena`', '`tcp`', '`pool`', '`limits`', '`timeout`', '`http`', '`route`', '`host`', '`tls`'

; Directives of the language that this version does not implement yet.
enumdef future_names, 'udp', 'xdp', 'policy', 'use', \
	'addon', 'alerts', 'include', 'admin', 'log', 'reload', 'profile', \
	'acme', 'discover', 'split', 'mirror', 'header', 'headers', 'cache', \
	'cors', 'limit', 'auth', 'match', 'source', \
	'concurrency', 'retry_budget', 'retry', 'outlier', 'protocol', \
	'fault', 'files', 'compress', 'canonical', 'idempotency', 'hold', \
	'body', 'early_hints', 'signed_urls', 'priority', 'hedge', \
	'response', 'alpn', 'cert', 'warm'

rodata
	align 8
	dir_table:
end rodata
dirdef DIR_OKENA, 'okena',       M_TOP,     CTX_OKENA,   F_BLOCK_REQ or F_UNIQUE, 0, 0, T_NONE, T_NONE, 0
dirdef DIR_WORKERS, 'workers',     M_OKENA,   0,           F_UNIQUE, 1, 1, T_WORKERS, T_NONE, 0
dirdef DIR_IO_ENGINE, 'io_engine',   M_OKENA,   0,           F_UNIQUE, 1, 1, e_io_engine, T_NONE, 0
dirdef DIR_WATCHDOG, 'watchdog',    M_OKENA,   0,           F_UNIQUE, 1, 1, T_DURATION, T_NONE, 0
dirdef DIR_METRICS, 'metrics',     M_OKENA,   0,           F_UNIQUE, 1, 1, T_LISTEN, T_NONE, 0
dirdef DIR_BUSY_POLL, 'busy_poll',   M_OKENA,   0,           F_UNIQUE, 1, 1, T_DURATION, T_NONE, 0
dirdef DIR_TICKET_KEYS, 'ticket_keys', M_OKENA, 0,       F_UNIQUE, 1, 1, T_ANY, T_NONE, 0
dirdef DIR_DRAIN, 'drain',       M_OKENA,   0,           F_UNIQUE or F_KEYS_BLOCK, 0, 0, T_NONE, T_NONE, k_drain
dirdef DIR_HS_BUDGET, 'handshake_budget', M_OKENA, 0,    F_UNIQUE or F_KEYS_BLOCK, 1, 1, T_DURATION, T_NONE, k_hs_budget
dirdef DIR_TCP, 'tcp',         M_TOP,     CTX_TCP,     F_BLOCK_REQ, 1, 16, T_LISTEN, T_LISTEN, 0
dirdef DIR_HTTP, 'http',        M_TOP,     CTX_HTTP,    F_BLOCK_REQ, 1, 16, T_LISTEN, T_LISTEN, 0
dirdef DIR_HOST, 'host',        M_HTTP,    CTX_HOST,    F_BLOCK_REQ, 1, 64, T_HOSTNAME, T_HOSTNAME, 0
dirdef DIR_ROUTE, 'route',      M_HTTP or M_HOST,    CTX_ROUTE,   F_BLOCK_REQ, 1, 32, T_ROUTE, T_ROUTE, 0
dirdef DIR_POOL, 'pool',        M_TOP,     CTX_POOL,    F_BLOCK_REQ, 1, 1, T_NAME, T_NONE, 0
dirdef DIR_TO, 'to',          M_TCP or M_ROUTE, 0,           F_UNIQUE, 1, 64, T_TARGET, T_TARGET, 0
dirdef DIR_PROXY_PROTOCOL, 'proxy_protocol', M_TCP, 0,      F_UNIQUE, 2, 2, e_pp_mode, e_pp_version, 0
dirdef DIR_LIMITS, 'limits',      M_TCP or M_HTTP,     CTX_LIMITS,  F_BLOCK_REQ or F_UNIQUE, 0, 0, T_NONE, T_NONE, 0
dirdef DIR_CONNECTIONS, 'connections', M_LIMITS,  0,           F_UNIQUE, 1, 1, T_COUNT, T_NONE, 0
dirdef DIR_PER_SOURCE, 'per_source', M_LIMITS,  0,           F_UNIQUE, 1, 1, T_COUNT, T_NONE, 0
dirdef DIR_TIMEOUT, 'timeout',     M_TCP or M_HTTP,     CTX_TIMEOUT, F_BLOCK_REQ or F_UNIQUE, 0, 0, T_NONE, T_NONE, 0
dirdef DIR_IDLE, 'idle',        M_TIMEOUT, 0,           F_UNIQUE, 1, 1, T_DURATION, T_NONE, 0
dirdef DIR_TRUSTED, 'trusted_proxies', M_HTTP, 0,         F_UNIQUE, 1, 64, T_CIDR, T_CIDR, 0
dirdef DIR_REDIRECT, 'redirect',  M_ROUTE,   0,           F_UNIQUE, 2, 2, e_redirect_codes, T_ANY, 0
dirdef DIR_REWRITE, 'rewrite',    M_ROUTE,   0,           F_UNIQUE, 4, 4, e_rewrite_what, T_ANY, 0
dirdef DIR_RHEADER, 'header',      M_ROUTE,   0,           0, 2, 3, e_header_ops, T_ANY, 0
dirdef DIR_RRESPONSE, 'response',  M_ROUTE,   0,           0, 3, 4, e_response_what, T_ANY, 0
dirdef DIR_TLS, 'tls',          M_TCP or M_HTTP, CTX_TLS,   F_BLOCK_REQ or F_UNIQUE, 0, 1, e_tls_mode, T_NONE, 0
dirdef DIR_SNI, 'sni',          M_TLS,     0,           0, 4, 64, T_ANY, T_ANY, 0
dirdef DIR_DEFAULT, 'default',  M_TLS,     0,           F_UNIQUE, 1, 3, T_ANY, T_ANY, 0
dirdef DIR_CERT, 'cert',        M_TLS,     0,           0, 1, 1, T_ANY, T_NONE, k_cert
dirdef DIR_KEY, 'key',          M_TLS,     0,           F_UNIQUE, 1, 1, T_ANY, T_NONE, 0
dirdef DIR_ACCESS_LOG, 'access_log', M_HTTP,   0,           F_UNIQUE, 1, 1, T_LOGDEST, T_NONE, 0
dirdef DIR_HEADER, 'header',      M_TIMEOUT, 0,           F_UNIQUE, 1, 1, T_DURATION, T_NONE, 0
dirdef DIR_RESPONSE, 'response',  M_TIMEOUT, 0,           F_UNIQUE, 1, 1, T_DURATION, T_NONE, 0
dirdef DIR_BODY_IDLE, 'body_idle', M_TIMEOUT, 0,           F_UNIQUE, 1, 1, T_DURATION, T_NONE, 0
dirdef DIR_SERVER, 'server',      M_POOL,    0,           0, 1, 2, T_BACKEND, e_server_flags, k_server
dirdef DIR_SLOW_START, 'slow_start', M_POOL,   0,           F_UNIQUE, 1, 1, T_DURATION, T_NONE, 0
dirdef DIR_BALANCE, 'balance',     M_POOL,    0,           F_UNIQUE, 1, 1, e_balance, T_NONE, 0
dirdef DIR_CONNECT, 'connect',     M_POOL,    0,           F_UNIQUE or F_KEYS_BLOCK, 0, 0, T_NONE, T_NONE, k_connect
dirdef DIR_HEALTH, 'health',      M_POOL,    0,           F_UNIQUE or F_KEYS_BLOCK, 1, 3, e_health, T_ANY, k_health
dirdef DIR_UPTLS, 'tls',         M_POOL,    0,           F_UNIQUE or F_KEYS_BLOCK, 0, 0, T_NONE, T_NONE, k_uptls
rodata
	dir_table_end:
end rodata

; Find a directive. rdi/esi = name, edx = context mask to accept (or -1
; for any). rax = entry or 0.
dir_lookup:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r12,rdi
	mov	r13d,esi
	mov	r14d,edx
	lea	rbx,[dir_table]
.next:
	lea	rax,[dir_table_end]
	cmp	rbx,rax
	jae	.none
	test	[rbx+D_CTX],r14d
	jz	.skip
	mov	rdi,r12
	mov	esi,r13d
	lea	rdx,[rbx+D_NAME]
	call	mem_eq_cstr
	test	eax,eax
	jnz	.found
.skip:
	add	rbx,D_SIZE
	jmp	.next
.found:
	mov	rax,rbx
	jmp	.out
.none:
	xor	eax,eax
.out:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi/esi = key, rdx = options table. rax = entry or 0.
key_lookup:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	mov	r13d,esi
	mov	rbx,rdx
	test	rbx,rbx
	jz	.none
.next:
	cmp	byte [rbx+K_NAME],0
	je	.none
	mov	rdi,r12
	mov	esi,r13d
	lea	rdx,[rbx+K_NAME]
	call	mem_eq_cstr
	test	eax,eax
	jnz	.found
	add	rbx,K_SIZE
	jmp	.next
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

; rdi/esi = word, rdx = NUL-separated list ending with an empty string.
; rax = index or -1.
list_index:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r12,rdi
	mov	r13d,esi
	mov	rbx,rdx
	xor	r14d,r14d
.next:
	cmp	byte [rbx],0
	je	.none
	mov	rdi,r12
	mov	esi,r13d
	mov	rdx,rbx
	call	mem_eq_cstr
	test	eax,eax
	jnz	.found
@@:
	inc	rbx
	cmp	byte [rbx-1],0
	jne	@b
	inc	r14d
	jmp	.next
.found:
	mov	eax,r14d
	jmp	.out
.none:
	mov	rax,-1
.out:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; ecx = index into a list (rdx). rsi/edx = that item.
list_item:
	mov	rsi,rdx
.skip:
	test	ecx,ecx
	jz	.measure
@@:
	inc	rsi
	cmp	byte [rsi-1],0
	jne	@b
	dec	ecx
	jmp	.skip
.measure:
	xor	edx,edx
@@:
	cmp	byte [rsi+rdx],0
	je	@f
	inc	edx
	jmp	@b
@@:
	ret

; Suggestions: the closest candidate within a small edit distance.
bss
	g_sug_word	dq ?
	g_sug_len	dd ?
	g_sug_best	dd ?
	g_sug_ptr	dq ?
	g_sug_plen	dd ?
end bss

; rdi/esi = the word that was not found.
suggest_begin:
	mov	[g_sug_word],rdi
	mov	[g_sug_len],esi
	; accept at most 1 edit for short words, 2 from 5 bytes, 3 from 9
	mov	eax,1
	cmp	esi,5
	jb	@f
	mov	eax,2
	cmp	esi,9
	jb	@f
	mov	eax,3
@@:
	inc	eax
	mov	[g_sug_best],eax		; best distance + 1
	mov	qword [g_sug_ptr],0
	ret

; rdx = candidate (NUL-terminated).
suggest_offer:
	push	rbx
	mov	rbx,rdx
	xor	ecx,ecx
@@:
	cmp	byte [rbx+rcx],0
	je	@f
	inc	ecx
	jmp	@b
@@:
	push	rcx
	mov	rdi,[g_sug_word]
	mov	esi,[g_sug_len]
	mov	rdx,rbx
	call	edit_distance
	pop	rcx
	cmp	eax,[g_sug_best]
	jae	.done
	mov	[g_sug_best],eax
	mov	[g_sug_ptr],rbx
	mov	[g_sug_plen],ecx
.done:
	pop	rbx
	ret

; rdx = NUL-separated list.
suggest_offer_list:
	push	rbx
	mov	rbx,rdx
.next:
	cmp	byte [rbx],0
	je	.done
	mov	rdx,rbx
	call	suggest_offer
@@:
	inc	rbx
	cmp	byte [rbx-1],0
	jne	@b
	jmp	.next
.done:
	pop	rbx
	ret

; Print "= help: did you mean `x`?" when there is a suggestion.
suggest_note:
	cmp	qword [g_sug_ptr],0
	je	.none
	call	cfg_note
	out_lit 'help: did you mean '
	mov	rsi,[g_sug_ptr]
	mov	edx,[g_sug_plen]
	call	cfg_quote
	out_lit '?'
	call	cfg_note_end
.none:
	ret
