; The handshake budget. A full TLS handshake costs ~60 us of asymmetric
; crypto (key share, ECDH, a signature), about a hundred requests' worth;
; a flood of ClientHellos run as they arrive would hold the loop for
; milliseconds while every open connection waits. So each worker spends at
; most `handshake_budget` (TSC time) per loop iteration on server hellos;
; past it a ClientHello waits in a bounded FIFO, and the loop goes back to
; the ring (without sleeping) between batches. A flood then slows new
; clients down, never the connections already open.
;
; * A ClientHello that offers a resumption (pre_shared_key) skips the
;   queue while the iteration has spent less than twice the budget: the
;   clients that already know us get in first, and a flood of fake
;   tickets is still bounded.
; * An entry that waited longer than `wait` (default 1 s) is closed
;   without its crypto: its client has likely given up, and the work goes
;   to the fresher ones. So does a ClientHello that finds the queue full.
; * The header timeout armed at accept still bounds the whole handshake.
;
; Counted in okena_tls_handshakes_deferred_total and
; okena_tls_handshakes_shed_total.

HS_TLS_QUEUED	:= 32		; the ClientHello waits in the budget queue
HSQ_CAP		:= 1024		; entries per worker (a power of two)
HSQ_SHIFT	:= 4		; 16 bytes: session, generation, TSC when queued
EXT_PSK		:= 41		; pre_shared_key
assert H_TLS_ROOM >= CH_MAX

bss
	align 8
	g_hs_budget_tsc	dq ?		; 0 = no budget
	g_hs_wait_tsc	dq ?
	g_hs_spent	dq ?		; TSC spent on hellos this iteration
	g_hs_head	dd ?
	g_hs_count	dd ?
	align 16
	g_hs_queue:	rb HSQ_CAP shl HSQ_SHIFT
end bss

; The worker's budget in TSC ticks, from the plan.
hs_init:
	mov	rax,[g_plan_hs_budget]
	imul	rax,[g_tsc_per_us]
	mov	[g_hs_budget_tsc],rax
	mov	rax,[g_plan_hs_wait]
	imul	rax,[g_tsc_per_us]
	mov	[g_hs_wait_tsc],rax
	ret

; rax = the TSC.
hs_tsc:
	rdtsc
	shl	rdx,32
	or	rax,rdx
	ret

; ebx = session, r15 = its record, IN holding the ClientHello so far
; (http_tls_hello_in): run the handshake now, or queue it.
http_tls_hello_budget:
	mov	rax,[g_hs_budget_tsc]
	test	rax,rax
	jz	http_tls_hello_go		; no budget: as it comes
	cmp	[g_hs_spent],rax
	jb	hs_run
	; over budget: is it whole, and a resumption?
	mov	rdi,[r15+H_BUF]
	mov	esi,[r15+H_INLEN]
	lea	rdx,[rdi+HB_OUT]
	mov	r8d,EXT_PSK
	call	tls_ext_peek
	cmp	eax,TH_DONE
	jne	hs_run				; incomplete or not one: cheap either way
	test	rsi,rsi
	jz	.queue
	mov	rax,[g_hs_budget_tsc]
	add	rax,rax
	cmp	[g_hs_spent],rax
	jb	hs_run
.queue:
	cmp	dword [g_hs_count],HSQ_CAP
	jae	.shed
	mov	eax,[g_hs_head]
	add	eax,[g_hs_count]
	and	eax,HSQ_CAP - 1
	shl	eax,HSQ_SHIFT
	lea	rcx,[g_hs_queue+rax]
	mov	[rcx],ebx
	call	session_ptr
	mov	eax,[rax+S_GEN]
	mov	[rcx+4],eax
	push	rcx
	call	hs_tsc
	pop	rcx
	mov	[rcx+8],rax
	inc	dword [g_hs_count]
	mov	dword [r15+H_STATE],HS_TLS_QUEUED
	inc	qword [g_st_tls_deferred]
	ret
.shed:
	inc	qword [g_st_tls_shed]
	jmp	http_tls_close

; ebx = session, r15 = its record: the handshake step, its time charged
; to the iteration's budget.
hs_run:
	call	hs_tsc
	push	rax
	push	rax
	call	http_tls_hello_go
	call	hs_tsc
	pop	rcx
	pop	rcx
	sub	rax,rcx
	add	[g_hs_spent],rax
	ret

; Main loop, once an iteration (both engines): a new budget, spent first
; on the hellos that waited. eax = nonzero when some still wait (the loop
; must not sleep then).
hs_drain:
	mov	qword [g_hs_spent],0
	cmp	dword [g_hs_count],0
	je	.idle
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
.next:
	cmp	dword [g_hs_count],0
	je	.done
	mov	rax,[g_hs_spent]
	cmp	rax,[g_hs_budget_tsc]
	jae	.done
	mov	eax,[g_hs_head]
	mov	ecx,eax
	inc	ecx
	and	ecx,HSQ_CAP - 1
	mov	[g_hs_head],ecx
	dec	dword [g_hs_count]
	shl	eax,HSQ_SHIFT
	lea	r12,[g_hs_queue+rax]
	mov	ebx,[r12]
	call	session_ptr			; still the session that queued?
	mov	ecx,[r12+4]
	cmp	ecx,[rax+S_GEN]
	jne	.next
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.next
	h_rec
	cmp	dword [r15+H_STATE],HS_TLS_QUEUED
	jne	.next
	call	hs_tsc
	sub	rax,[r12+8]
	cmp	rax,[g_hs_wait_tsc]
	ja	.stale
	mov	dword [r15+H_STATE],HS_TLS_HELLO
	call	hs_run
	jmp	.next
.stale:
	inc	qword [g_st_tls_shed]
	mov	edi,ebx
	call	session_close
	jmp	.next
.done:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
.idle:
	mov	eax,[g_hs_count]
	ret
