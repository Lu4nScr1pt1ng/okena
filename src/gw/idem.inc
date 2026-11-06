; `idempotency header=idempotency-key ttl=24h lock=60s` on a route: a request that
; changes something, sent twice with the same key, reaches the backend once; the
; second gets the first's answer. This must hold across workers, so it is the one
; state here that workers share, in slots of a fixed size mapped before they fork:
; no allocator to leave half done, and nothing a worker that dies can hold but its
; own slot, until `lock` runs out. It outlives a reload.
;
; A slot is claimed with one compare-and-swap of a word that is the key's hash and
; a state together, so of two workers with one key, one gets it. The key is taken with
; the route and who `auth` proved: someone else's key is no way to their answers.
;
; While the first runs, others get a 409. A key used with another method, target,
; length or type gets a 422; the body is not compared. An answer past ID_BMAX cannot be
; replayed: a retry gets a 409 and not a second run.
;
; The key is let go only when the backend surely did not do the work: no connection,
; or its 502, 503 or 504. With a request sent and no answer it stays locked until
; `lock` runs out: a 409 can be retried, a double charge cannot be undone.

SF_IDEMF	:= 134217728			; S_FLAGS: its answer goes into a slot
SF_IDEMS	:= 268435456			; its answer comes from one

ID_SLOTS	:= 4096
ID_SIZE		:= 65536
ID_PROBE	:= 64
ID_GRACE	:= 300000000			; µs an expired slot stays, for who still reads it
ID_WORD		:= 0				; q: the key's hash | IS_*, 0 free
ID_GEN		:= 8				; d: changes each time it is claimed
ID_STATUS	:= 12				; d
ID_EXP		:= 16				; q: µs, 0 being set
ID_HLEN		:= 24				; d
ID_BLEN		:= 28				; d
ID_FP		:= 32				; 32: what the request was
ID_HEAD		:= 64
ID_BODY		:= 16384
ID_HMAX		:= ID_BODY - ID_HEAD - 64
ID_BMAX		:= ID_SIZE - ID_BODY
IS_CLAIM	:= 1
IS_DONE		:= 2
IS_BIG		:= 3				; done, and not kept

MAX_IDEMS	:= 64
IC_HDR		:= 0				; q
IC_HLEN		:= 8				; d
IC_TTL		:= 12				; d: seconds
IC_LOCK		:= 16				; d: seconds
IC_SIZE		:= 24

IF_HEAD		:= 1				; HB_CPASS: its head is in the slot
IF_OVER		:= 2				; its body did not fit, or has no sure end

bss
	align 8
	g_idem_tbl	dq ?
	g_idems:	rb IC_SIZE * MAX_IDEMS
	g_plan_idems	dd ?
	g_id_dig:	rb 32
	g_id_fp:	rb 32
end bss

; once, in the supervisor, as soon as a plan asks: it stays over reloads
idem_table_init:
	cmp	dword [g_plan_idems],0
	je	.none
	cmp	qword [g_idem_tbl],0
	jne	.none
	xor	edi,edi
	mov	esi,ID_SLOTS * ID_SIZE
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	test	rax,rax
	js	.none
	mov	[g_idem_tbl],rax
.none:
	ret

; eax = a slot: rax = it
macro id_ptr
	shl	rax,16				; ID_SIZE
	add	rax,[g_idem_tbl]
end macro
assert ID_SIZE = 65536

; g_hm, r15, r12 = its `idempotency`: g_id_dig the key, g_id_fp the request's print
idem_keys:
	lea	rdi,[g_fc_sha]
	call	sha256_init
	lea	rsi,[r15+H_ACT]
	mov	edx,4
	lea	rdi,[g_fc_sha]
	call	sha256_update
	; who, if the route knows
	mov	eax,[r15+H_ACT]
	dec	eax
	imul	rax,rax,RA_SIZE
	cmp	dword [g_acts+rax+RA_AUTH],0
	je	.anyone
	mov	rax,[r15+H_BUF]
	lea	rsi,[rax+HB_AUTHL]
	mov	edx,[rax+HB_AUTHL]
	add	edx,4
	lea	rdi,[g_fc_sha]
	call	sha256_update
.anyone:
	mov	rdi,[r12+IC_HDR]
	mov	esi,[r12+IC_HLEN]
	call	limit_find
	mov	edx,ecx
	lea	rdi,[g_fc_sha]
	call	sha256_update
	lea	rdi,[g_fc_sha]
	lea	rsi,[g_id_dig]
	call	sha256_final
	; the request
	lea	rdi,[g_fc_sha]
	call	sha256_init
	mov	rsi,[g_hm+HM_METHOD]
	mov	edx,[g_hm+HM_MLEN]
	call	.field
	mov	rsi,[g_hm+HM_TARGET]
	mov	edx,[g_hm+HM_TLEN]
	call	.field
	lea	rsi,[g_hm+HM_LENGTH]
	mov	edx,8
	call	.field
	lea	rdi,[hn_content_type_raw]
	mov	esi,12
	call	limit_find
	mov	edx,ecx
	call	.field
	lea	rdi,[g_fc_sha]
	lea	rsi,[g_id_fp]
	jmp	sha256_final
.field:
	push	rsi
	push	rdx
	mov	[g_id_fp],edx
	lea	rsi,[g_id_fp]
	mov	edx,4
	lea	rdi,[g_fc_sha]
	call	sha256_update
	pop	rdx
	pop	rsi
	lea	rdi,[g_fc_sha]
	jmp	sha256_update
hn_content_type_raw db 'content-type'

; ebx, r15, g_hm: eax = 1 taken care of, 0 it goes on (SF_IDEMF if it is the first).
; Keeps rbx, r12-r15.
idem_check:
	mov	eax,[r15+H_ACT]
	test	eax,eax
	jz	.pass0
	dec	eax
	imul	rax,rax,RA_SIZE
	mov	eax,[g_acts+rax+RA_IDEM]
	test	eax,eax
	jnz	.routed
.pass0:
	xor	eax,eax
	ret
.routed:
	test	dword [r15+H_FLAGS],HX_HEAD or HX_MIRROR
	jnz	.pass0
	mov	rcx,[g_hm+HM_METHOD]
	mov	edx,[g_hm+HM_MLEN]
	cmp	edx,3
	jne	@f
	mov	esi,[rcx]
	and	esi,0xFFFFFF
	cmp	esi,'GET'
	je	.pass0
@@:
	cmp	edx,7
	jne	@f
	cmp	dword [rcx],'OPTI'
	je	.pass0
@@:
	push	r12
	push	r13
	push	r14
	dec	eax
	imul	r12,rax,IC_SIZE
	lea	r12,[g_idems+r12]
	mov	rdi,[r12+IC_HDR]
	mov	esi,[r12+IC_HLEN]
	call	limit_find
	test	ecx,ecx
	jz	.on				; no key: a request like any other
	cmp	ecx,255
	ja	.bad_key
	cmp	qword [g_idem_tbl],0
	je	.busy
	call	idem_keys
	call	qs_clock
	mov	r13,[g_id_dig]
	and	r13,not 3
	or	r13,4				; (never 0, whatever the hash)
	mov	r14d,ID_PROBE
	mov	r8,r13
	shr	r8,3
.probe:
	mov	eax,r8d
	and	eax,ID_SLOTS - 1
	id_ptr
	mov	r9,rax
.again:
	mov	rax,[r9+ID_WORD]
	test	rax,rax
	jnz	.taken
	; free
	lea	rcx,[r13+IS_CLAIM]
	lock cmpxchg [r9+ID_WORD],rcx
	jne	.again
	jmp	.claimed
.taken:
	mov	rcx,rax
	and	rcx,not 3
	cmp	rcx,r13
	je	.same
	; another key's: if its time is long over it goes
	mov	rcx,[r9+ID_EXP]
	test	rcx,rcx
	jz	.next
	add	rcx,ID_GRACE
	cmp	rcx,[g_qnow]
	jae	.next
	mov	qword [r9+ID_EXP],0		; (being set, to whoever looks next)
	xor	ecx,ecx
	lock cmpxchg [r9+ID_WORD],rcx
	jmp	.again
.next:
	inc	r8d
	dec	r14d
	jnz	.probe
.busy:
	mov	edi,503				; full: not without the guarantee
	jmp	.refuse
.same:
	mov	ecx,eax
	and	ecx,3
	cmp	ecx,IS_CLAIM
	jne	.done
	; someone is at it. Unless their time ran out
	mov	rax,[r9+ID_EXP]
	test	rax,rax
	jz	.in_flight
	cmp	rax,[g_qnow]
	ja	.in_flight
	mov	rcx,[g_qnow]
	lock cmpxchg [r9+ID_EXP],rcx		; (one takes it over)
	jne	.in_flight
	jmp	.claimed
.done:
	mov	rax,[r9+ID_EXP]
	cmp	rax,[g_qnow]
	ja	.alive
	; over: as if it had never been
	mov	qword [r9+ID_EXP],0
	mov	rax,[r9+ID_WORD]
	xor	ecx,ecx
	lock cmpxchg [r9+ID_WORD],rcx
	jmp	.again
.alive:
	lea	rdi,[r9+ID_FP]
	lea	rsi,[g_id_fp]
	mov	ecx,4
	repe	cmpsq
	jne	.other_request
	mov	rax,[r9+ID_WORD]
	and	eax,3
	cmp	eax,IS_BIG
	je	.in_flight
	mov	rdi,r9
	call	idem_replay
	mov	eax,1
	jmp	.out
.claimed:
	lock inc dword [r9+ID_GEN]
	mov	eax,[r12+IC_LOCK]
	imul	rax,rax,1000000
	add	rax,[g_qnow]
	lea	rdi,[r9+ID_FP]
	lea	rsi,[g_id_fp]
	mov	ecx,4
	rep	movsq
	mov	dword [r9+ID_HLEN],0
	mov	dword [r9+ID_BLEN],0
	mov	[r9+ID_EXP],rax
	mov	rcx,r9
	sub	rcx,[g_idem_tbl]
	shr	rcx,16
	mov	rdx,[r15+H_BUF]
	mov	[rdx+HB_CE],ecx
	mov	eax,[r9+ID_GEN]
	mov	[rdx+HB_CW],eax
	mov	dword [rdx+HB_CPOS],0
	mov	dword [rdx+HB_CPASS],0
	call	session_ptr
	or	dword [rax+S_FLAGS],SF_IDEMF
.on:
	xor	eax,eax
.out:
	pop	r14
	pop	r13
	pop	r12
	ret
.in_flight:
	mov	edi,409
	jmp	.refuse
.other_request:
	mov	edi,422
	jmp	.refuse
.bad_key:
	mov	edi,400
.refuse:
	pop	r14
	pop	r13
	pop	r12
	call	http_error
	mov	eax,1
	ret

; rdi = a slot with an answer: this request gets it
idem_replay:
	push	r12
	mov	r12,rdi
	mov	rax,[r15+H_BUF]
	mov	rcx,r12
	sub	rcx,[g_idem_tbl]
	shr	rcx,16
	mov	[rax+HB_CE],ecx
	mov	ecx,[r12+ID_GEN]
	mov	[rax+HB_CW],ecx
	mov	dword [rax+HB_CPOS],0
	mov	ecx,[r12+ID_BLEN]
	mov	[rax+HB_CLEFT],ecx
	mov	qword [rax+HB_HT0],0
	lea	rdi,[rax+HB_UP]
	lea	rsi,[r12+ID_HEAD]
	mov	ecx,[r12+ID_HLEN]
	rep	movsb
	memit_x 'Idempotency-Replayed: true',13,10,13,10
	mov	rax,[r15+H_BUF]
	lea	rax,[rax+HB_UP]
	sub	rdi,rax
	mov	[r15+H_UPLEN],edi
	mov	dword [r15+H_UPOFF],0
	test	dword [r15+H_FLAGS],HX_NOBODY
	jnz	@f
	or	dword [r15+H_FLAGS],HX_CLOSE	; (its body is not read)
@@:
	call	session_ptr
	or	dword [rax+S_FLAGS],SF_IDEMS
	mov	dword [rax+S_SERVER],NIL
	mov	qword [r15+H_UPT0],0
	mov	dword [r15+H_STATE],HS_RESP_HEAD
	mov	edi,ebx
	mov	esi,PH_RESPONSE
	call	ph_arm
	pop	r12
	jmp	http_resp_head

; h_recv on the upstream side of a replay: ebx, rdi = buffer, esi = room
idem_recv:
	h_rec
	mov	r8,[r15+H_BUF]
	mov	eax,[r8+HB_CE]
	id_ptr
	mov	r9d,[r8+HB_CW]
	cmp	[rax+ID_GEN],r9d
	jne	.gone				; (a slot past its grace: rather cut than wrong)
	mov	ecx,[r8+HB_CLEFT]
	cmp	ecx,esi
	cmova	ecx,esi
	sub	[r8+HB_CLEFT],ecx
	mov	edx,[r8+HB_CPOS]
	add	[r8+HB_CPOS],ecx
	lea	rsi,[rax+ID_BODY+rdx]
	mov	eax,ecx
	rep	movsb
	jmp	.done
.gone:
	mov	rax,-5
.done:
	mov	edx,1
	mov	ecx,SIDE_UP
	jmp	hep_queue

; ebx, r15: is the slot it claimed still its own? rax = it. ZF yes. Keeps rcx.
idem_mine:
	mov	r8,[r15+H_BUF]
	mov	eax,[r8+HB_CE]
	id_ptr
	mov	r8d,[r8+HB_CW]
	cmp	[rax+ID_GEN],r8d
	ret

; g_hm = the answer's head: ebx, r15
idem_head:
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_IDEMF
	jz	.none
	mov	eax,[g_hm+HM_STATUS]
	cmp	eax,502
	jb	.keep
	cmp	eax,504
	jbe	idem_release
.keep:
	push	r12
	push	r13
	push	r14
	call	idem_mine
	jne	.out
	mov	r12,rax
	mov	r8,[r15+H_BUF]
	or	dword [r8+HB_CPASS],IF_HEAD
	cmp	dword [r15+H_RBODY],BK_CLOSE
	jne	@f
	or	dword [r8+HB_CPASS],IF_OVER
@@:
	mov	eax,[g_hm+HM_STATUS]
	mov	[r12+ID_STATUS],eax
	lea	rdi,[r12+ID_HEAD]
	memit_x 'HTTP/1.1 '
	mov	eax,[g_hm+HM_STATUS]
	call	fmt_u64
	memit_x ' Replayed',13,10
	xor	r13d,r13d
.field:
	cmp	r13d,[g_hm+HM_NHDR]
	jae	.fields
	imul	r14,r13,HF_SIZE
	lea	r14,[g_hm+HM_HDRS+r14]
	inc	r13d
	push	rdi
	mov	rdi,[r14+HF_NAME]
	mov	esi,[r14+HF_NLEN]
	lea	rdx,[cache_fields.dropped]
	call	name_in
	pop	rdi
	jnz	.field
	mov	eax,[r14+HF_NLEN]
	add	eax,[r14+HF_VLEN]
	lea	rcx,[rdi+rax+4]
	lea	rax,[r12+ID_HEAD+ID_HMAX]
	cmp	rcx,rax
	ja	.too_big
	mov	rsi,[r14+HF_NAME]
	mov	ecx,[r14+HF_NLEN]
	rep	movsb
	mov	word [rdi],': '
	add	rdi,2
	mov	rsi,[r14+HF_VALUE]
	mov	ecx,[r14+HF_VLEN]
	rep	movsb
	mov	word [rdi],0x0A0D
	add	rdi,2
	jmp	.field
.too_big:
	mov	r8,[r15+H_BUF]
	or	dword [r8+HB_CPASS],IF_OVER
.fields:
	lea	rax,[r12+ID_HEAD]
	sub	rdi,rax
	mov	[r12+ID_HLEN],edi
.out:
	pop	r14
	pop	r13
	pop	r12
.none:
	ret

; rsi = body bytes passing, ecx = how many: ebx, r15, its flag set. Keeps all.
idem_tee:
	push	rax
	push	rcx
	push	rdx
	push	rsi
	push	rdi
	push	r8
	call	idem_mine
	jne	.out
	mov	r8,[r15+H_BUF]
	mov	edx,[r8+HB_CPOS]
	lea	edi,[rdx+rcx]
	cmp	edi,ID_BMAX
	ja	.over
	mov	[r8+HB_CPOS],edi
	lea	rdi,[rax+ID_BODY+rdx]
	rep	movsb
	jmp	.out
.over:
	or	dword [r8+HB_CPASS],IF_OVER
.out:
	pop	r8
	pop	rdi
	pop	rsi
	pop	rdx
	pop	rcx
	pop	rax
	ret

; the answer has gone: ebx, r15. It is kept for its ttl.
idem_commit:
	call	session_ptr
	and	dword [rax+S_FLAGS],not SF_IDEMF
	call	idem_mine
	jne	.out
	mov	r9,rax
	mov	r8,[r15+H_BUF]
	mov	edx,[r8+HB_CPASS]
	mov	dword [r8+HB_CPASS],0
	test	edx,IF_HEAD
	jz	.out				; no answer: it stays locked, for `lock`
	push	rdx
	mov	eax,[r15+H_ACT]
	dec	eax
	imul	rax,rax,RA_SIZE
	mov	eax,[g_acts+rax+RA_IDEM]
	dec	eax
	imul	rax,rax,IC_SIZE
	mov	eax,[g_idems+rax+IC_TTL]
	imul	rax,rax,1000000
	push	rax
	call	qs_clock
	pop	rax
	add	rax,[g_qnow]
	mov	[r9+ID_EXP],rax
	pop	rdx
	mov	ecx,IS_BIG
	test	edx,IF_OVER
	jnz	.state
	; its length, last of the head
	mov	r8,[r15+H_BUF]
	mov	eax,[r8+HB_CPOS]
	mov	[r9+ID_BLEN],eax
	mov	edx,[r9+ID_HLEN]
	lea	rdi,[r9+ID_HEAD+rdx]
	memit_x 'Content-Length: '
	mov	r8,[r15+H_BUF]
	mov	eax,[r8+HB_CPOS]
	call	fmt_u64
	memit_x 13,10
	lea	rax,[r9+ID_HEAD]
	sub	rdi,rax
	mov	[r9+ID_HLEN],edi
	mov	ecx,IS_DONE
.state:
	; (the word last: a reader that sees it done finds all the rest there)
	mov	rax,[r9+ID_WORD]
	mov	rdx,rax
	and	rdx,not 3
	or	rdx,rcx
	lock cmpxchg [r9+ID_WORD],rdx
.out:
	ret

; the backend surely did not do it: ebx, r15. The key is free again.
idem_release:
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_IDEMF
	jz	.none
	and	dword [rax+S_FLAGS],not SF_IDEMF
	call	idem_mine
	jne	.none
	mov	r9,rax
	mov	rax,[r9+ID_WORD]
	xor	ecx,ecx
	lock cmpxchg [r9+ID_WORD],rcx
.none:
	ret

; a session is closing with a claim, r15 its record: an answer begun is an answer the
; backend gave: done, not kept. None: it stays locked.
idem_gone:
	push	rax
	mov	rax,[r15+H_BUF]
	or	dword [rax+HB_CPASS],IF_OVER
	pop	rax
	jmp	idem_commit

; r12 = a route's node, r13 = the action
compile_idem:
	push	rbx
	mov	rdi,r12
	mov	ecx,DIR_IDEMPOTENCY
	call	find_child
	test	rax,rax
	jz	.none
	mov	rbx,rax
	mov	eax,[g_plan_idems]
	cmp	eax,MAX_IDEMS
	jae	plan_bad_idem
	inc	dword [g_plan_idems]
	lea	ecx,[rax+1]
	mov	[r13+RA_IDEM],ecx
	imul	r8,rax,IC_SIZE
	lea	r8,[g_idems+r8]
	push	r8
	mov	rdi,rbx
	lea	rsi,[.k_header]
	call	node_option
	mov	r8,[rsp]
	test	rax,rax
	jz	plan_bad_idem
	mov	rcx,[rax+A_VAL]
	mov	[r8+IC_HDR],rcx
	mov	ecx,[rax+A_VLEN]
	mov	[r8+IC_HLEN],ecx
	mov	dword [r8+IC_TTL],86400
	mov	dword [r8+IC_LOCK],60
	mov	rdi,rbx
	lea	rsi,[.k_ttl]
	call	node_option
	mov	r8,[rsp]
	test	rax,rax
	jz	@f
	lea	rcx,[r8+IC_TTL]
	call	.seconds
@@:
	mov	rdi,rbx
	lea	rsi,[.k_lock]
	call	node_option
	mov	r8,[rsp]
	test	rax,rax
	jz	@f
	lea	rcx,[r8+IC_LOCK]
	call	.seconds
@@:
	pop	r8
.none:
	pop	rbx
	ret
.seconds:
	push	rcx
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_duration
	pop	rcx
	jc	plan_bad_idem
	xor	edx,edx
	mov	r8d,1000000
	div	r8
	test	eax,eax
	jz	plan_bad_idem
	mov	[rcx],eax
	ret
cstring .k_header, 'header',0
cstring .k_ttl, 'ttl',0
cstring .k_lock, 'lock',0

plan_bad_idem:
	call	log_begin
	out_lit 'idempotency needs header=NAME; ttl= and lock= are times; at most 64 routes'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
