; Rate limits: `limit RATE burst=N key=K instances=N` on a route. Every limit
; is for the whole instance, never per worker (docs/ARCHITECTURE.md).
;
; GCRA in a shared table, one bucket a cache line: a key is its theoretical
; arrival time (TAT), in ns, and a token moves it on by T, the time between two
; requests at the rate. A request fits while TAT is at most `tolerance` ahead
; of now. A worker takes tokens by the batch with one lock cmpxchg and spends
; them from a table of its own, so the atomic (and the clock) is paid once a
; batch, not once a request: as many as a share of what is left, one at a time
; near the limit, where it stays exact, and at most 20 ms of the rate. What a
; batch leaves unused goes back when it runs out of time. A refused request
; only reads the bucket: a client over its limit writes nothing shared.
;
; The table has a fixed size. A key that finds its neighbourhood taken pushes
; out the one with the oldest TAT if that is in the past: such a bucket is
; full, so it carries no information. If all are in use the key shares the
; limit's own bucket: a flood of new keys cannot get past the limit, and only
; what is in that flood pays for it. Keys are hashed with a random seed, so
; clients cannot aim at collisions. The table outlives reloads.

LM_T		:= 0				; q: ns a token
LM_TOL		:= 8				; q: ns ahead TAT may be
LM_NAME		:= 16				; q: header:, query:, cookie: the name
LM_NLEN		:= 24				; d
LM_KIND		:= 28				; d: LK_*
LM_ID		:= 32				; d: its index, and its bucket past the table
LM_CAP		:= 36				; d: a batch, at most
LM_SIZE		:= 40

LK_ROUTE	:= 0				; no key: one bucket
LK_IP		:= 1
LK_METHOD	:= 2
LK_HEADER	:= 3
LK_QUERY	:= 4
LK_COOKIE	:= 5

LB_BITS		:= 18				; 256k keys, 16 MiB of address space
LB_N		:= 1 shl LB_BITS
LB_PROBE	:= 4
LB_KEY		:= 0				; q: 0 free
LB_TAT		:= 8				; q
LB_SIZE		:= 64

LR_N		:= 4096				; a worker's batches, by the key's low bits
LR_KEY		:= 0				; q
LR_T		:= 8				; q
LR_LEFT		:= 16				; d: tokens
LR_EXP		:= 20				; d: g_tick
LR_B		:= 24				; q: its bucket
LR_SIZE		:= 32

MAX_LIMITS	:= 256
LEASE_SECS	:= 2

bss
	align 8
	g_lim_tbl	dq ?			; shared
	g_lim_seed	rq 2
	g_lim_retry	dq ?			; refused: seconds to wait
	g_lim_status	dd ?			; and with what
	g_lr:		rb LR_N * LR_SIZE
end bss

; Supervisor, once: the table, its random key.
limit_global_init:
	xor	edi,edi
	mov	esi,(LB_N + MAX_LIMITS) * LB_SIZE
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	mov	[g_lim_tbl],rax
	lea	rdi,[g_lim_seed]
	mov	esi,16
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	ret

; rax = hash so far, rsi = bytes, ecx = how many: the hash with them. Keeps
; all but rax, rcx, rdx, rsi.
limit_mix:
	mov	rdx,0x9E3779B97F4A7C15
.word:
	cmp	ecx,8
	jb	.tail
	xor	rax,[rsi]
	imul	rax,rdx
	rol	rax,29
	add	rsi,8
	sub	ecx,8
	jmp	.word
.tail:
	test	ecx,ecx
	jz	.out
	push	rbx
	xor	ebx,ebx
.byte:
	shl	rbx,8
	mov	bl,[rsi]
	inc	rsi
	dec	ecx
	jnz	.byte
	xor	rax,rbx
	imul	rax,rdx
	rol	rax,29
	pop	rbx
.out:
	ret

; rsi = "a=1&b=2" (or "a=1; b=2"), rdx = its end, r8b = the separator, rdi =
; the name, ecx = its length: rsi = its value, ecx = its length (0, none).
limit_field:
	push	r12
	mov	r12d,ecx
.field:
	cmp	r8b,';'				; (cookies: spaces after the separator)
	jne	.at
.space:
	cmp	rsi,rdx
	jae	.none
	cmp	byte [rsi],' '
	jne	.at
	inc	rsi
	jmp	.space
.at:
	cmp	rsi,rdx
	jae	.none
	lea	rax,[rsi+r12]
	cmp	rax,rdx
	jae	.next
	cmp	byte [rax],'='
	jne	.next
	push	rsi
	push	rdi
	mov	rcx,r12
	repe	cmpsb
	pop	rdi
	pop	rsi
	jne	.next
	lea	rsi,[rsi+r12+1]
	xor	ecx,ecx
.value:
	lea	rax,[rsi+rcx]
	cmp	rax,rdx
	jae	.found
	cmp	[rax],r8b
	je	.found
	inc	ecx
	jmp	.value
.next:
	cmp	rsi,rdx
	jae	.none
	lodsb
	cmp	al,r8b
	jne	.next
	jmp	.field
.none:
	xor	ecx,ecx
.found:
	pop	r12
	ret

; r12 = a limit, g_hm = the request, r15 = record, ebx = session: rax = the
; request's key (never 0). A request without the field has the empty key: to
; leave it out is no way around the limit.
limit_key:
	mov	eax,[r12+LM_ID]
	mov	rdx,0x100000001B3
	imul	rax,rdx
	xor	rax,[g_lim_seed]
	push	rax
	mov	eax,[r12+LM_KIND]
	cmp	eax,LK_IP
	je	.ip
	cmp	eax,LK_METHOD
	je	.method
	cmp	eax,LK_HEADER
	je	.header
	cmp	eax,LK_COOKIE
	je	.cookie
	cmp	eax,LK_QUERY
	je	.query
	jmp	.mixed
.ip:
	call	http_client_resolve
	lea	rsi,[r15+H_CLIENT]
	mov	ecx,16
	jmp	.mix
.method:
	lea	rax,[g_hm]
	mov	rsi,[rax+HM_METHOD]
	mov	ecx,[rax+HM_MLEN]
	jmp	.mix
.header:
	mov	rdi,[r12+LM_NAME]
	mov	esi,[r12+LM_NLEN]
	call	limit_find
	jmp	.mix
.cookie:
	lea	rdi,[.cookie_name]
	mov	esi,6
	call	limit_find
	test	ecx,ecx
	jz	.mixed
	lea	rdx,[rsi+rcx]
	mov	rdi,[r12+LM_NAME]
	mov	ecx,[r12+LM_NLEN]
	mov	r8b,';'
	call	limit_field
	jmp	.mix
.query:
	lea	rax,[g_hm]
	mov	rsi,[rax+HM_TARGET]
	mov	ecx,[rax+HM_TLEN]
	mov	edx,[rax+HM_PLEN]
	sub	ecx,edx
	jbe	.mixed				; no query
	add	rsi,rdx
	inc	rsi				; past '?'
	dec	ecx
	lea	rdx,[rsi+rcx]
	mov	rdi,[r12+LM_NAME]
	mov	ecx,[r12+LM_NLEN]
	mov	r8b,'&'
	call	limit_field
.mix:
	mov	rax,[rsp]
	call	limit_mix
	mov	[rsp],rax
.mixed:
	pop	rax
	mov	rdx,0xC4CEB9FE1A85EC53
	imul	rax,rdx
	mov	rcx,rax
	shr	rcx,33
	xor	rax,rcx
	test	rax,rax
	jnz	@f
	inc	rax
@@:
	ret
.cookie_name	db 'cookie'

; rdi = a name, esi = its length: rsi = that header's value, ecx = its length
limit_find:
	push	r13
	push	r14
	lea	r13,[g_hm+HM_HDRS]
	mov	r14d,[g_hm+HM_NHDR]
	push	rsi
	push	rdi
.next:
	test	r14d,r14d
	jz	.none
	dec	r14d
	mov	eax,[rsp+8]
	cmp	eax,[r13+HF_NLEN]
	jne	.skip
	mov	rdi,[r13+HF_NAME]
	mov	rsi,[rsp]
	mov	edx,eax
	call	mem_eq_nocase
	test	eax,eax
	jnz	.found
.skip:
	add	r13,HF_SIZE
	jmp	.next
.found:
	mov	rsi,[r13+HF_VALUE]
	mov	ecx,[r13+HF_VLEN]
	jmp	.out
.none:
	xor	ecx,ecx
.out:
	add	rsp,16
	pop	r14
	pop	r13
	ret

; r13 = the key, r14 = now (ns), r12 = the limit: r8 = its bucket
limit_bucket:
	mov	rax,r13
	shr	rax,20
	and	eax,LB_N - 1
	and	eax,not (LB_PROBE - 1)		; a neighbourhood
	shl	rax,6				; LB_SIZE
	mov	r8,[g_lim_tbl]
	add	r8,rax
	mov	ecx,LB_PROBE
	mov	r9,r8
	xor	r10d,r10d			; a free one
	xor	r11d,r11d			; the oldest idle one
	mov	rsi,r14
.look:
	mov	rax,[r9+LB_KEY]
	cmp	rax,r13
	je	.found
	test	rax,rax
	jnz	.taken
	test	r10,r10
	cmovz	r10,r9
	jmp	.next
.taken:
	mov	rax,[r9+LB_TAT]
	cmp	rax,rsi
	jae	.next
	mov	rsi,rax				; (the oldest yet, and in the past)
	mov	r11,r9
.next:
	add	r9,LB_SIZE
	dec	ecx
	jnz	.look
	test	r10,r10
	jz	.evict
	xor	eax,eax
	lock cmpxchg [r10+LB_KEY],r13
	mov	r9,r10
	je	.new
	cmp	rax,r13				; (another worker, this very key)
	je	.found
	jmp	.shared
.evict:
	test	r11,r11
	jz	.shared
	mov	rax,[r11+LB_KEY]
	lock cmpxchg [r11+LB_KEY],r13
	mov	r9,r11
	jne	.shared
.new:
	mov	qword [r9+LB_TAT],0
.found:
	mov	r8,r9
	ret
.shared:
	mov	eax,[r12+LM_ID]			; all in use: the limit's own bucket
	add	eax,LB_N
	shl	rax,6
	mov	r8,[g_lim_tbl]
	add	r8,rax
	ret

; r12 = a limit: CF when the request is over it (g_lim_retry set)
limit_one:
	push	r13
	push	r14
	call	limit_key
	mov	r13,rax
	mov	r9,rax
	and	r9d,LR_N - 1
	shl	r9,5				; LR_SIZE
	lea	r9,[g_lr+r9]
	mov	eax,[r9+LR_LEFT]
	cmp	[r9+LR_KEY],r13
	jne	.other
	test	eax,eax
	jz	.other
	mov	ecx,[g_tick]
	cmp	ecx,[r9+LR_EXP]
	ja	.other
	dec	dword [r9+LR_LEFT]		; from the batch: nothing shared
	clc
	jmp	.out
.other:
	; what the slot held and did not use goes back
	test	eax,eax
	jz	.take
	mov	dword [r9+LR_LEFT],0
	imul	rax,[r9+LR_T]
	mov	rcx,[r9+LR_B]
	mov	rdx,[r9+LR_KEY]
	cmp	[rcx+LB_KEY],rdx
	jne	.take				; (not its bucket any more)
	neg	rax
	lock xadd [rcx+LB_TAT],rax
.take:
	push	r9
	call	qs_clock
	imul	r14,[g_qnow],1000
	call	limit_bucket
	pop	r9
	mov	r10,[r12+LM_T]
.again:
	mov	rax,[r8+LB_TAT]
	mov	rcx,rax
	cmp	rcx,r14
	cmovb	rcx,r14				; TAT, or now when it is in the past
	mov	rdx,r14
	add	rdx,[r12+LM_TOL]		; the latest it may be
	mov	r11,rdx
	sub	r11,rcx
	jc	.over
	; what fits: those, a share a worker, one when few are left
	push	rax
	mov	rax,r11
	xor	edx,edx
	div	r10
	inc	rax				; (the one that fits exactly)
	xor	edx,edx
	mov	r11d,[g_workers]
	add	r11,r11
	div	r11
	cmp	rax,1
	jae	@f
	mov	eax,1
@@:
	mov	edx,[r12+LM_CAP]
	cmp	rax,rdx
	cmova	rax,rdx
	mov	r11,rax				; tokens
	imul	rax,r10
	add	rcx,rax				; the new TAT
	pop	rax
	lock cmpxchg [r8+LB_TAT],rcx
	jne	.again
	dec	r11d
	mov	[r9+LR_LEFT],r11d
	mov	[r9+LR_KEY],r13
	mov	[r9+LR_T],r10
	mov	[r9+LR_B],r8
	mov	eax,[g_tick]
	add	eax,LEASE_SECS
	mov	[r9+LR_EXP],eax
	clc
	jmp	.out
.over:
	; seconds until one fits, rounded up
	mov	rax,rcx
	sub	rax,r14
	sub	rax,[r12+LM_TOL]
	add	rax,999999999
	xor	edx,edx
	mov	ecx,1000000000
	div	rcx
	mov	[g_lim_retry],rax
	stc
.out:
	pop	r14
	pop	r13
	ret

; edi = the route's first limit, esi = how many, g_hm = the request, r15 =
; record, ebx = session: CF when one refuses it
limit_request:
	push	r12
	push	r13
	mov	r12d,edi
	imul	r12,r12,LM_SIZE
	lea	r12,[g_limits+r12]
	mov	r13d,esi
.next:
	test	r13d,r13d
	jz	.fits
	call	limit_one
	jc	.out
	add	r12,LM_SIZE
	dec	r13d
	jmp	.next
.fits:
	clc
.out:
	pop	r13
	pop	r12
	ret

; refused: 429 and how long to wait. The connection stays: a client told to
; slow down should not have to make a new one, with its handshake, to hear it
; again. As with a redirect its body, if any, is not read: then it closes.
limit_over:
	mov	dword [g_lim_status],429
limit_refuse:
	test	dword [r15+H_FLAGS],HX_GRPC
	jz	@f
	mov	edi,[g_lim_status]		; (gRPC: its status in trailers)
	jmp	http_error
@@:
	or	dword [r15+H_FLAGS],HX_SELF or HX_STARTED
	test	dword [r15+H_FLAGS],HX_NOBODY
	jnz	@f
	or	dword [r15+H_FLAGS],HX_CLOSE
@@:
	cmp	dword [r15+H_RIDLEN],0
	jne	@f
	call	rid_new
@@:
	mov	edi,[g_lim_status]
	mov	[r15+H_STATUS],edi
	mov	esi,5
	call	http_count
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_OUT]
	memit_x 'HTTP/1.1 '
	mov	eax,[g_lim_status]
	call	fmt_u64
	mov	byte [rdi],' '
	inc	rdi
	mov	eax,[g_lim_status]
	call	http_reason
	call	fmt_cstr
	memit_x 13,10,'Retry-After: '
	mov	rax,[g_lim_retry]
	call	fmt_u64
	memit_x 13,10
	call	cors_emit
	memit_x 'Content-Length: 0',13,10,'X-Request-Id: '
	lea	rsi,[r15+H_RID]
	mov	ecx,[r15+H_RIDLEN]
	rep	movsb
	memit_x 13,10
	test	dword [r15+H_FLAGS],HX_CLOSE
	jz	@f
	memit_x 'Connection: close',13,10
@@:
	memit_x 13,10
	mov	rsi,[r15+H_BUF]
	lea	rsi,[rsi+HB_OUT]
	sub	rdi,rsi
	mov	dword [r15+H_STATE],HS_SELF_SEND
	mov	ecx,SIDE_CLIENT
	xchg	rsi,rdi				; rdi = OUT, esi = its length
	jmp	h_send
