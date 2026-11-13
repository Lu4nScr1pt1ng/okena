; Addons in a worker: calls posted on the request path, answers taken each turn
; of the loop, deadlines, the circuit, and what an answer does to the request.
;
; A route's addons run after its access checks, auth and rate limits: the
; cheapest refusals come first. The request is held as for `fault delay=` (its
; head waits where it was read, no read is posted) for the addon's `timeout`; an
; answer makes it go on at once, through its head again:
;
;   continue    the head is rewritten in place first (fields set, added,
;               removed, the target changed), so routing, limits, the cache and
;               the backend all see the request as the addon left it;
;   respond     okena answers the client with the addon's status, fields and body;
;   no answer   (in time, a bad one, an addon that exited, a full ring, an open
;               circuit) `on_error`: allow lets the request go on, deny is 503.
;
; Each worker keeps a FIFO of its calls per addon: all of an addon's calls have
; the same timeout, so the oldest is always the first due. Its length is the
; worker's share of `concurrency`. What a session waits for is in a side table
; (one entry a session), with the generation it is for: a session that went
; meanwhile is never answered.

FD_ADDON	:= 0x04000000			; FD_SESS: a request waits for an addon
OP_ADDON	:= 48				; io_uring: an addon wrote this worker's eventfd
EK_ADDON	:= 7				; epoll: the same
AD_FIFO_MAX	:= 4096
AD_STASH_MAX	:= H_OUT_CAP - 4096		; an addon's own answer: fields and body
AD_WSPIN_US	:= 20				; a worker that just asked a polling addon waits this
						; long for the answer before it sleeps

; the worker's state for each addon
ADW_HDR		:= 0				; q: the addon's header page
ADW_REQ		:= 8				; q: this worker's ring pair
ADW_HEAD		:= 16				; q: calls written (ours)
ADW_TAIL		:= 24				; q: answers read (ours)
ADW_FIFO		:= 32				; q
ADW_OPEN		:= 40				; q: µs the circuit is open until, 0 closed
ADW_SEQ		:= 48				; d: the next call's id
ADW_FHEAD	:= 52				; d: the oldest not yet over
ADW_CAP		:= 56				; d: a power of two
ADW_EPOCH	:= 60				; d: the addon's run we call
ADW_FAILS	:= 64				; d: failures in a row
ADW_DIRTY	:= 68				; d: calls posted since the bell
ADW_LIVE		:= 72				; d
ADW_SIZE		:= 80

; a call in the FIFO
AFE_SEQ		:= 0				; d
AFE_SESS		:= 4				; d
AFE_SGEN		:= 8				; d
AFE_STATE	:= 12				; d: 1 waiting, 0 over
AFE_DUE		:= 16				; q: µs
AFE_T0		:= 24				; q: TSC when it was posted
AFE_SIZE		:= 32

; what a session waits for (g_ad_side)
ADSE_GEN		:= 0				; d: the session's generation this is for
ADSE_STATE	:= 4				; b: ADS_*
ADSE_ADDON	:= 5				; b: which addon
ADSE_DONE		:= 8				; d: addons this request is through
ADSE_SEQ		:= 12				; d: the call waited for
ADSE_STATUS	:= 16				; d: respond: the status
ADSE_HLEN		:= 20				; d: its fields' bytes (rendered, in HB_OUT's end)
ADSE_BLEN		:= 24				; d: its body's
ADSE_FLAGS	:= 28				; d: ADSF_*
ADSE_RDONE	:= 32				; d: addons the response is through
ADSE_HSTART	:= 36				; d: the response head's start in HB_UP
ADSE_RHLEN	:= 40				; d: and its length
ADSE_SIZE		:= 64				; (ADSE_SHIFT)
ADS_NONE	:= 0
ADS_WAIT	:= 1
ADS_CONT	:= 2
ADS_RESP	:= 3
ADS_FAIL	:= 4
ADSE_POOL	:= 6				; w: the pool an addon chose + 1, 0 the route's
HS_ADBODY	:= 48				; H_STATE: the request's body read for an addon
HS_ADRBODY	:= 49				; H_STATE: a response's body read for an addon
ADSF_FWD		:= 1				; `auth forward` said yes to this request
ADSF_RESP	:= 2				; the call waited for is about the response

; ADR_HEAD's line holds the next id too: a worker that takes a ring another
; left starts past every id that one may still get answers for
ADR_NEXTID	:= 8

; the histogram's upper bounds, ns (the last bucket: above them all)
rodata
	align 8
	ad_hbounds	dq 500, 1000, 1500, 2000, 2500, 3000, 4000, 5000, 6000, 8000, 10000, 12500, 15000
			dq 20000, 25000, 30000, 40000, 50000, 75000, 100000, 150000, 200000, 300000
			dq 500000, 1000000, 2500000, 5000000, 10000000, 25000000, 50000000, 100000000
end rodata

bss
	align 8
	g_ad_side	dq ?			; the side table, 0 when the plan has no addons
	g_ad_ri		dd ?			; this worker's slot (its rings, its eventfd)
	g_ad_wfd	dd ?			; that eventfd
	g_ad_pid	dd ?
	g_ad_any	dd ?			; calls may be waiting: look at the answers
	g_ad_posted	dd ?			; calls posted since the loop last slept
	g_rw_head	dq ?			; ad_rebuild: the head, its length, what follows,
	g_rw_hlen	dd ?			; the room from the head on, whether the target
	g_rw_tail	dd ?			; may change
	g_rw_cap	dd ?
	g_rw_tgt	dd ?
	g_ad_resp	dd ?			; addon_call: about the response, not the request
	g_ad_blen	dd ?			; ad_post: the body the call carries
	g_ad_bflags	dd ?
	g_ad_wbuf	dq ?
	g_ad_one	dq ?
	align 8
	g_aw:		rb ADW_SIZE * MAX_ADDONS
	g_ad_tmp:	rb H_IN_CAP
	g_ad_log_ix:	rb 64
	g_cur_log_sess	dd ?
end bss

; ------------------------------------------------------------------ setup

; worker, before its engine and its filter: a slot, the side table, the FIFOs
addon_worker_init:
	mov	qword [g_ad_side],0
	mov	dword [g_ad_any],0
	cmp	dword [g_plan_addons],0
	je	.none
	cmp	dword [g_ad_nrw],0
	je	.none
	push	rbx
	push	r12
	push	r13
	mov	eax,SYS_getpid
	syscall
	mov	[g_ad_pid],eax
	; a slot no live worker holds
	mov	rdi,[g_ad_claim]
	xor	ecx,ecx
.claim:
	cmp	ecx,[g_ad_nrw]
	jae	.full
	mov	edx,[g_ad_pid]
	xor	eax,eax
	lock cmpxchg [rdi+rcx*4],edx
	je	.claimed
	inc	ecx
	jmp	.claim
.full:
	call	log_begin
	out_lit 'no addon slot left for this worker: its addon calls follow on_error'
	call	log_end
	mov	dword [g_ad_ri],-1
	jmp	.side
.claimed:
	mov	[g_ad_ri],ecx
	mov	eax,[g_ad_wake+rcx*4]
	mov	[g_ad_wfd],eax
.side:
	; the side table: address space only until used
	mov	esi,[g_sessions]
	shl	rsi,6				; ADSE_SIZE
	add	rsi,4095
	and	rsi,not 4095
	xor	edi,edi
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.no_memory
	mov	[g_ad_side],rax
	; the FIFOs
	xor	r12d,r12d			; addon
	xor	r13d,r13d			; their bytes
.size:
	cmp	r12d,[g_plan_addons]
	jae	.sized
	imul	rbx,r12,ADE_SIZE
	mov	eax,[g_addons+rbx+ADE_CONC]
	add	eax,[g_workers]
	dec	eax
	xor	edx,edx
	div	dword [g_workers]
	mov	ecx,4
@@:
	cmp	ecx,eax
	jae	@f
	cmp	ecx,AD_FIFO_MAX
	jae	@f
	add	ecx,ecx
	jmp	@b
@@:
	imul	rbx,r12,ADW_SIZE
	mov	[g_aw+rbx+ADW_CAP],ecx
	shl	ecx,5				; AFE_SIZE
	add	r13d,ecx
	inc	r12d
	jmp	.size
.sized:
	lea	rsi,[r13+4095]
	and	rsi,not 4095
	xor	edi,edi
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.no_memory
	mov	r13,rax				; the next FIFO
	xor	r12d,r12d
.addon:
	cmp	r12d,[g_plan_addons]
	jae	.done
	imul	rbx,r12,ADW_SIZE
	lea	rbx,[g_aw+rbx]
	mov	[rbx+ADW_FIFO],r13
	mov	eax,[rbx+ADW_CAP]
	shl	rax,5
	add	r13,rax
	mov	dword [rbx+ADW_LIVE],0
	cmp	dword [g_ad_ri],-1
	je	.next
	imul	rax,r12,ADE_SIZE
	mov	eax,[g_addons+rax+ADE_SLOT]
	cmp	eax,-1
	je	.next
	imul	rax,rax,ADPR_SIZE
	mov	rdx,[g_adrt+rax+ADPR_BASE]
	test	rdx,rdx
	jz	.next
	mov	[rbx+ADW_HDR],rdx
	mov	eax,[g_ad_ri]
	imul	rax,rax,AD_STRIDE
	lea	rax,[rdx+AD_HDR+rax]
	mov	[rbx+ADW_REQ],rax
	mov	rcx,[rax+ADR_HEAD]
	mov	[rbx+ADW_HEAD],rcx
	mov	rcx,[rax+ADR_ANS+ADR_TAIL]
	mov	[rbx+ADW_TAIL],rcx
	mov	ecx,[rax+ADR_NEXTID]
	add	ecx,65536			; (past what the last owner asked)
	mov	[rbx+ADW_SEQ],ecx
	mov	[rbx+ADW_FHEAD],ecx
	mov	[rax+ADR_NEXTID],ecx
	mov	ecx,[g_ad_pid]
	mov	[rax+ADR_OWNER],ecx
	mov	ecx,[rdx+ADH_EPOCH]
	mov	[rbx+ADW_EPOCH],ecx
	mov	qword [rbx+ADW_OPEN],0
	mov	dword [rbx+ADW_FAILS],0
	mov	dword [rbx+ADW_DIRTY],0
	mov	dword [rbx+ADW_LIVE],1
.next:
	inc	r12d
	jmp	.addon
.done:
	pop	r13
	pop	r12
	pop	rbx
.none:
	ret
.no_memory:
	call	log_begin
	out_lit 'addons: cannot reserve memory'
	call	log_end
	mov	edi,EXIT_FATAL
	jmp	exit_process

; io_uring: this worker's eventfd read (an addon answered)
addon_arm:
	cmp	qword [g_ad_side],0
	je	.none
	cmp	dword [g_ad_ri],-1
	je	.none
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_READ
	mov	ecx,[g_ad_wfd]
	mov	[rax+SQE_FD],ecx
	lea	rcx,[g_ad_wbuf]
	mov	[rax+SQE_ADDR],rcx
	mov	dword [rax+SQE_LEN],8
	mov	rcx,(OP_ADDON shl 56) or 0xFFFFFFFF
	mov	[rax+SQE_USER_DATA],rcx
.none:
	ret

on_addon:
	jmp	addon_arm			; (what came is read at the turn's end)

; epoll: the same eventfd in the set
addon_ep_add:
	cmp	qword [g_ad_side],0
	je	.none
	cmp	dword [g_ad_ri],-1
	je	.none
	mov	edi,[g_ad_wfd]
	mov	esi,EPOLLIN
	mov	rdx,EK_ADDON shl 56
	jmp	ep_add
.none:
	ret

addon_ep_ready:
	mov	edi,[g_ad_wfd]
	lea	rsi,[g_ad_wbuf]
	mov	edx,8
	xor	eax,eax				; SYS_read
	syscall
	ret

; ----------------------------------------------------------- each turn

; Before the loop sleeps: an addon that may be asleep is told calls came.
addon_bells:
	cmp	qword [g_ad_side],0
	je	.none
	push	rbx
	xor	ebx,ebx
.next:
	cmp	ebx,[g_plan_addons]
	jae	.done
	imul	rax,rbx,ADW_SIZE
	lea	rax,[g_aw+rax]
	cmp	dword [rax+ADW_DIRTY],0
	je	.skip
	mov	dword [rax+ADW_DIRTY],0
	mfence					; (the heads are out before the look)
	mov	rcx,[rax+ADW_HDR]
	cmp	dword [rcx+ADH_SLEEP],0
	je	.skip				; it polls: it sees them
	imul	rdx,rbx,ADE_SIZE
	mov	edx,[g_addons+rdx+ADE_SLOT]
	imul	rdx,rdx,ADPR_SIZE
	mov	edi,[g_adrt+rdx+ADPR_BELL]
	mov	qword [g_ad_one],1
	lea	rsi,[g_ad_one]
	mov	edx,8
	mov	eax,SYS_write
	syscall
.skip:
	inc	ebx
	jmp	.next
.done:
	pop	rbx
.none:
	ret

; The loop is about to sleep, having just asked addons that poll: their answer
; usually comes within a few microseconds, sooner than a sleep and a wakeup.
; The worker polls for it AD_WSPIN_US at most, saying so in its answer rings
; (the addon then writes no eventfd). eax = 1 when an answer came (do not
; sleep), 0 otherwise. Keeps rdi, rbx, r12-r15.
addon_spin:
	xor	eax,eax
	cmp	dword [g_ad_posted],0
	je	.none
	mov	dword [g_ad_posted],0
	mov	rcx,[g_tsc_per_us]
	test	rcx,rcx
	jz	.none
	push	rbx
	push	r12
	imul	r12,rcx,AD_WSPIN_US
	rdtsc
	shl	rdx,32
	or	rax,rdx
	add	r12,rax				; until
	mov	edx,1
	call	.say				; polling, where the addon polls too
	test	ebx,ebx
	jz	.asleep				; none does: nothing to wait for
.spin:
	call	.look
	jnz	.came
	pause
	rdtsc
	shl	rdx,32
	or	rax,rdx
	cmp	rax,r12
	jb	.spin
.asleep:
	xor	edx,edx				; asleep from now on: said, then one more look
	call	.say
	mfence
	call	.look
	jnz	.came2
	xor	eax,eax
	jmp	.out
.came:
	xor	edx,edx
	call	.say
.came2:
	mov	eax,1
.out:
	pop	r12
	pop	rbx
.none:
	ret
; edx = 1 polling, 0 not: into the answer rings of addons with calls out;
; ebx = how many of them poll themselves
.say:
	xor	ebx,ebx
	xor	ecx,ecx
.say_next:
	cmp	ecx,[g_plan_addons]
	jae	.said
	imul	rax,rcx,ADW_SIZE
	lea	rax,[g_aw+rax]
	cmp	dword [rax+ADW_LIVE],0
	je	.say_skip
	push	rcx
	mov	ecx,[rax+ADW_SEQ]
	cmp	ecx,[rax+ADW_FHEAD]
	pop	rcx
	je	.say_skip
	mov	r8,[rax+ADW_REQ]
	mov	[r8+ADR_ANS+ADR_WAWAKE],edx
	mov	r8,[rax+ADW_HDR]
	cmp	dword [r8+ADH_SLEEP],0
	jne	.say_skip
	inc	ebx
.say_skip:
	inc	ecx
	jmp	.say_next
.said:
	ret
; ZF clear when an addon's answers ring has something new
.look:
	xor	ecx,ecx
.look_next:
	cmp	ecx,[g_plan_addons]
	jae	.nothing
	imul	rax,rcx,ADW_SIZE
	lea	rax,[g_aw+rax]
	cmp	dword [rax+ADW_LIVE],0
	je	.look_skip
	mov	r8,[rax+ADW_REQ]
	mov	r8,[r8+ADR_ANS+ADR_HEAD]
	cmp	r8,[rax+ADW_TAIL]
	jne	.something
.look_skip:
	inc	ecx
	jmp	.look_next
.nothing:
	cmp	eax,eax				; ZF set
.something:
	ret

; Each turn, before held requests are looked at: answers taken, calls past
; their time ended, and a run of an addon that is over ends its calls.
addon_flush:
	cmp	dword [g_ad_any],0
	je	.none
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	call	qs_clock
	xor	ebp,ebp				; calls still waiting, all addons
	xor	r12d,r12d
.addon:
	cmp	r12d,[g_plan_addons]
	jae	.done
	imul	r13,r12,ADW_SIZE
	lea	r13,[g_aw+r13]
	cmp	dword [r13+ADW_LIVE],0
	je	.next
	mov	eax,[r13+ADW_SEQ]
	cmp	eax,[r13+ADW_FHEAD]
	je	.next				; nothing asked
	mov	r14,[r13+ADW_REQ]
	mov	rax,[r13+ADW_HDR]
	mov	eax,[rax+ADH_EPOCH]
	cmp	eax,[r13+ADW_EPOCH]
	je	@f
	call	ad_epoch_over
@@:
	call	ad_answers
	call	ad_expire
	mov	eax,[r13+ADW_SEQ]
	sub	eax,[r13+ADW_FHEAD]
	add	ebp,eax
.next:
	inc	r12d
	jmp	.addon
.done:
	mov	[g_ad_any],ebp
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
.none:
	ret

; r12d = addon, r13 = its state: the answers that came
ad_answers:
	mov	r14,[r13+ADW_REQ]
	mov	rax,[r14+ADR_ANS+ADR_HEAD]
	cmp	rax,[r13+ADW_TAIL]
	je	.none
.next:
	mov	rcx,[r13+ADW_TAIL]
	mov	rax,[r14+ADR_ANS+ADR_HEAD]
	cmp	rcx,rax
	je	.out
	sub	rax,rcx				; what is there
	mov	edx,ecx
	and	edx,AD_RING - 1
	lea	r15,[r14+ADR_ANSD+rdx]		; the record
	mov	r8d,[r15+ANS_LEN]
	cmp	r8d,8
	jb	.corrupt
	test	r8d,7
	jnz	.corrupt
	cmp	r8,rax
	ja	.corrupt
	mov	r9d,AD_RING
	sub	r9d,edx
	cmp	r8d,r9d
	ja	.corrupt
	cmp	word [r15+ANS_KIND],1
	jne	.skip				; padding
	push	r8
	call	ad_answer
	pop	r8
.skip:
	add	[r13+ADW_TAIL],r8
	jmp	.next
.corrupt:
	; an addon that writes what is not a record: what it wrote is dropped
	; (those calls end at their time)
	mov	rax,[r14+ADR_ANS+ADR_HEAD]
	mov	[r13+ADW_TAIL],rax
	inc	qword [r14+ADR_COUNT+ADC_ERROR]
.out:
	mov	rax,[r13+ADW_TAIL]
	mov	[r14+ADR_ANS+ADR_TAIL],rax
.none:
	ret

; r15 = an answer, r8d = its length; r12d, r13, r14 as above
ad_answer:
	mov	eax,[r15+ANS_ID]
	mov	ecx,[r13+ADW_CAP]
	dec	ecx
	and	ecx,eax
	shl	rcx,5
	add	rcx,[r13+ADW_FIFO]
	cmp	[rcx+AFE_SEQ],eax
	jne	.stale
	cmp	dword [rcx+AFE_STATE],1
	jne	.stale				; (its time was up)
	mov	dword [rcx+AFE_STATE],0
	cmp	word [r15+ANS_ACTION],ANA_FAIL
	je	.fail
	inc	qword [r14+ADR_COUNT+ADC_OK]
	call	ad_timed
	mov	dword [r13+ADW_FAILS],0
	mov	qword [r13+ADW_OPEN],0
	push	rbx
	mov	ebx,[rcx+AFE_SESS]
	mov	r9d,[rcx+AFE_SGEN]
	call	ad_waiter
	jc	.gone
	; it is that call's: what it says, its ops within it
	call	ad_ops_fit
	jc	.bad
	movzx	eax,word [r15+ANS_ACTION]
	cmp	eax,ANA_CONTINUE
	je	.cont
	cmp	eax,ANA_RESPOND
	je	.resp
	jmp	.bad
.cont:
	cmp	word [r15+ANS_NOPS],0
	je	.cont_ok
	test	dword [r10+ADSE_FLAGS],ADSF_RESP
	jnz	.cont_resp
	call	ad_pool_op
	jc	.bad
	call	ad_rewrite
	jc	.bad
	jmp	.cont_ok
.cont_resp:
	call	ad_rewrite_resp
	jc	.bad
.cont_ok:
	mov	byte [r10+ADSE_STATE],ADS_CONT
	jmp	.due
.resp:
	call	ad_stash
	jc	.bad
	mov	byte [r10+ADSE_STATE],ADS_RESP
	inc	qword [r14+ADR_COUNT+ADC_RESPOND]
	jmp	.due
.bad:
	inc	qword [r14+ADR_COUNT+ADC_ERROR]
.failed:
	mov	byte [r10+ADSE_STATE],ADS_FAIL
.due:
	mov	r9d,[r10+ADSE_GEN]
	call	ad_due
.gone:
	pop	rbx
.stale:
	ret
; the addon said it could not decide: on_error at once, a failure for the circuit
.fail:
	inc	qword [r14+ADR_COUNT+ADC_ERROR]
	call	ad_failed			; (g_qnow: addon_flush's)
	push	rbx
	mov	ebx,[rcx+AFE_SESS]
	mov	r9d,[rcx+AFE_SGEN]
	call	ad_waiter
	jc	.gone
	jmp	.failed

; r15 = an answer: CF unless its ops (and a respond's body) lie within it.
; Keeps all but rax, rcx, rdx, r8.
ad_ops_fit:
	mov	edx,[r15+ANS_LEN]
	movzx	ecx,word [r15+ANS_NOPS]
	mov	r8d,ANS_OPS
.op:
	test	ecx,ecx
	jz	.body
	dec	ecx
	lea	eax,[r8+ANO_HDR]
	cmp	eax,edx
	ja	.no
	movzx	eax,word [r15+r8+2]		; the name's length
	add	eax,ANO_HDR
	push	rax
	movzx	eax,word [r15+r8+4]		; the value's
	add	[rsp],eax
	pop	rax
	add	r8d,eax
	cmp	r8d,edx
	ja	.no
	jmp	.op
.body:
	mov	eax,[r15+ANS_BLEN]
	add	rax,r8
	cmp	rax,rdx
	ja	.no
	clc
	ret
.no:
	stc
	ret

; rcx = a call answered, r14 = its rings: its round trip into the histogram.
; Keeps all but rax, rdx, r8.
ad_timed:
	mov	r8,[g_tsc_per_us]
	test	r8,r8
	jz	.out
	rdtsc
	shl	rdx,32
	or	rax,rdx
	sub	rax,[rcx+AFE_T0]
	imul	rax,rax,1000
	xor	edx,edx
	div	r8				; ns
	add	[r14+ADR_COUNT+ADC_HSUM],rax
	xor	edx,edx
.b:
	cmp	edx,AD_NB - 1
	jae	.in
	cmp	rax,[ad_hbounds+rdx*8]
	jbe	.in
	inc	edx
	jmp	.b
.in:
	inc	qword [r14+ADR_HIST+rdx*8]
.out:
	ret

; ebx = a session, r9d = the generation a call was for, r12d = the addon,
; [rcx+AFE_SEQ] = the call: CF unless that session is still there, held, and
; waiting for that very call; if so r10 = its side entry and r15 kept.
; Keeps r12-r15, rcx.
ad_waiter:
	cmp	ebx,[g_sessions]
	jae	.no
	call	session_ptr
	cmp	[rax+S_GEN],r9d
	jne	.no
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.no
	mov	r10d,ebx
	shl	r10,H_SHIFT
	add	r10,[g_http_base]
	cmp	dword [r10+H_STATE],HS_FAULT
	jne	.no
	mov	r10d,ebx
	shl	r10,6
	add	r10,[g_ad_side]
	cmp	[r10+ADSE_GEN],r9d
	jne	.no
	cmp	byte [r10+ADSE_STATE],ADS_WAIT
	jne	.no
	cmp	[r10+ADSE_ADDON],r12b
	jne	.no
	mov	eax,[rcx+AFE_SEQ]
	cmp	[r10+ADSE_SEQ],eax
	jne	.no
	clc
	ret
.no:
	stc
	ret

; ebx = a held session, r9d = its generation: it goes on in this turn
; (fault_flush takes it, through addon_resume). Keeps all but rax, rcx, rdx, r8.
ad_due:
	mov	r8d,ebx
	or	r8d,FD_ADDON
	mov	edx,[g_fd_n]
	xor	eax,eax
.find:
	test	edx,edx
	jz	.out				; (none: its time is up already, and it goes)
	cmp	[g_fd+rax+FD_SESS],r8d
	jne	.other
	cmp	[g_fd+rax+FD_GEN],r9d
	je	.now
.other:
	add	rax,FD_SIZE
	dec	edx
	jmp	.find
.now:
	mov	qword [g_fd+rax+FD_AT],1
	mov	qword [g_fd_next],1
.out:
	ret

; r12d, r13, r14: calls past their time are over (their requests, still held,
; find so when their own time comes: the same, as all of an addon's calls have
; the same timeout); the FIFO's head moves past what is over
ad_expire:
	mov	rdi,[r13+ADW_FIFO]
.next:
	mov	eax,[r13+ADW_FHEAD]
	cmp	eax,[r13+ADW_SEQ]
	je	.out
	mov	ecx,[r13+ADW_CAP]
	dec	ecx
	and	ecx,eax
	shl	rcx,5
	cmp	dword [rdi+rcx+AFE_STATE],0
	je	.over
	mov	rdx,[rdi+rcx+AFE_DUE]
	cmp	rdx,[g_qnow]
	ja	.out
	mov	dword [rdi+rcx+AFE_STATE],0
	inc	qword [r14+ADR_COUNT+ADC_TIMEOUT]
	call	ad_failed
.over:
	inc	dword [r13+ADW_FHEAD]
	jmp	.next
.out:
	ret

; r13 = an addon's state: one more failure in a row; the circuit opens at its
; limit. Keeps all but rax, rdx.
ad_failed:
	inc	dword [r13+ADW_FAILS]
	imul	rax,r12,ADE_SIZE
	mov	edx,[g_addons+rax+ADE_BREAK]
	cmp	[r13+ADW_FAILS],edx
	jb	.out
	cmp	qword [r13+ADW_OPEN],0
	jne	@f
	mov	rdx,[r13+ADW_REQ]
	inc	qword [rdx+ADR_COUNT+ADC_OPENED]
@@:
	mov	rdx,[g_addons+rax+ADE_OPEN]
	add	rdx,[g_qnow]
	mov	[r13+ADW_OPEN],rdx
.out:
	ret

; r12d, r13, r14: the addon exited or started again: its calls are over now,
; their requests follow on_error at once
ad_epoch_over:
	mov	rax,[r13+ADW_HDR]
	mov	eax,[rax+ADH_EPOCH]
	mov	[r13+ADW_EPOCH],eax
	mov	r15d,[r13+ADW_FHEAD]
.next:
	cmp	r15d,[r13+ADW_SEQ]
	je	.out
	mov	ecx,[r13+ADW_CAP]
	dec	ecx
	and	ecx,r15d
	shl	rcx,5
	add	rcx,[r13+ADW_FIFO]
	cmp	dword [rcx+AFE_STATE],1
	jne	.skip
	mov	dword [rcx+AFE_STATE],0
	inc	qword [r14+ADR_COUNT+ADC_CRASHED]
	push	rbx
	mov	ebx,[rcx+AFE_SESS]
	mov	r9d,[rcx+AFE_SGEN]
	call	ad_waiter
	jc	@f
	mov	byte [r10+ADSE_STATE],ADS_FAIL
	call	ad_due
@@:
	pop	rbx
.skip:
	inc	r15d
	jmp	.next
.out:
	ret

; ----------------------------------------------------------- the request

; r15 = an answer to continue, r10 = the side entry: an ANO_POOL op's pool,
; looked up by name, into ADSE_POOL. CF: no pool of that name. Keeps rbx,
; r10, r12-r15.
ad_pool_op:
	movzx	ecx,word [r15+ANS_NOPS]
	lea	r8,[r15+ANS_OPS]
.op:
	test	ecx,ecx
	jz	.done
	dec	ecx
	movzx	eax,word [r8+2]
	movzx	edx,word [r8+4]
	lea	r9,[r8+ANO_HDR+rax]		; the value
	cmp	byte [r8],ANO_POOL
	jne	.next
	push	rcx
	push	r8
	xor	r11d,r11d
.pool:
	cmp	r11d,[g_plan_pools]
	jae	.unknown
	imul	rax,r11,PL_SIZE
	cmp	[g_pools+rax+PL_NLEN],edx
	jne	.other
	push	rdx
	mov	rsi,[g_pools+rax+PL_NAME]
	mov	rdi,r9
	mov	ecx,edx
	repe	cmpsb
	pop	rdx
	je	.found
.other:
	inc	r11d
	jmp	.pool
.found:
	inc	r11d
	mov	[r10+ADSE_POOL],r11w
	pop	r8
	pop	rcx
.next:
	movzx	eax,word [r8+2]
	movzx	edx,word [r8+4]
	lea	r8,[r8+ANO_HDR+rax]
	add	r8,rdx
	jmp	.op
.unknown:
	pop	r8
	pop	rcx
	stc
	ret
.done:
	clc
	ret

; http_request, the pool chosen: CF when an addon chose another, eax = it.
; Keeps all but rax.
addon_pool:
	push	rcx
	call	ad_side_cur
	jc	.none
	movzx	eax,word [rcx+ADSE_POOL]
	test	eax,eax
	jz	.none
	dec	eax
	pop	rcx
	stc
	ret
.none:
	pop	rcx
	clc
	ret

; http_request, a request's first pass (not one back from waiting): nothing
; is through any addon yet. ebx = session. Keeps all but rax, rcx.
addon_fresh:
	mov	rcx,[g_ad_side]
	test	rcx,rcx
	jz	.none
	call	session_ptr
	mov	eax,[rax+S_GEN]
	push	rdx
	mov	edx,ebx
	shl	rdx,6
	add	rcx,rdx
	pop	rdx
	mov	[rcx+ADSE_GEN],eax
	mov	dword [rcx+ADSE_STATE],0
	mov	dword [rcx+ADSE_DONE],0
	mov	dword [rcx+ADSE_FLAGS],0
	mov	dword [rcx+ADSE_RDONE],0
.none:
	ret

; `auth forward` and addons: a request back from waiting for an addon is not
; asked about again. CF when the service said yes to it already. Keeps all
; but rax, rcx.
addon_fwd_passed:
	call	ad_side_cur
	jc	.no
	test	dword [rcx+ADSE_FLAGS],ADSF_FWD
	jz	.no
	stc
	ret
.no:
	clc
	ret

addon_fwd_mark:
	call	ad_side_cur
	jc	.out
	or	dword [rcx+ADSE_FLAGS],ADSF_FWD
.out:
	ret

; ebx = session: rcx = its side entry, CF when there is none for it
ad_side_cur:
	mov	rcx,[g_ad_side]
	test	rcx,rcx
	jz	.no
	call	session_ptr
	mov	eax,[rax+S_GEN]
	push	rdx
	mov	edx,ebx
	shl	rdx,6
	add	rcx,rdx
	pop	rdx
	cmp	[rcx+ADSE_GEN],eax
	jne	.no
	clc
	ret
.no:
	stc
	ret

; The route's addons (edi = its mask), ebx = session, r15 = record, g_hm = the
; request. CF clear: through them all, go on. CF set: they have it, r8d says
; how: 0 held (or answered already), 1 the addon's own answer (addon_respond),
; else a status for http_error. Keeps rbx, r12-r15.
addon_stage:
	push	r12
	push	r13
	push	r14
	mov	r13d,edi
	call	ad_side_cur
	jnc	@f
	call	addon_fresh			; (never had a first pass: one now)
	call	ad_side_cur
	jc	.through			; no side table: no addons in this worker
@@:
	mov	r14,rcx
	mov	eax,[r14+ADSE_DONE]
	not	eax
	and	r13d,eax
.next:
	bsf	r12d,r13d
	jz	.through
	imul	rax,r12,ADE_SIZE
	test	dword [g_addons+rax+ADE_PHASES],ADP_REQ
	jz	.done_one			; (asked about the response only, or for the log)
	cmp	byte [r14+ADSE_STATE],ADS_NONE
	je	.ask
	cmp	[r14+ADSE_ADDON],r12b
	jne	.ask
	movzx	eax,byte [r14+ADSE_STATE]
	mov	byte [r14+ADSE_STATE],ADS_NONE
	cmp	eax,ADS_CONT
	je	.done_one
	cmp	eax,ADS_RESP
	je	.respond
	cmp	eax,ADS_FAIL
	je	.error
	; still waiting (back for another reason): its own time brings it back
	mov	byte [r14+ADSE_STATE],al
	xor	r8d,r8d
	jmp	.taken
.ask:
	mov	dword [g_ad_resp],0
	call	addon_call
	jnc	.held
.error:
	imul	rax,r12,ADE_SIZE
	imul	rcx,r12,ADW_SIZE
	mov	rcx,[g_aw+rcx+ADW_REQ]
	cmp	dword [g_addons+rax+ADE_ONERR],0
	je	.deny
	test	rcx,rcx
	jz	.done_one
	inc	qword [rcx+ADR_COUNT+ADC_ALLOWED]
.done_one:
	bts	dword [r14+ADSE_DONE],r12d
	btr	r13d,r12d
	jmp	.next
.deny:
	test	rcx,rcx
	jz	@f
	inc	qword [rcx+ADR_COUNT+ADC_DENIED]
@@:
	bts	dword [r14+ADSE_DONE],r12d
	mov	r8d,503
	jmp	.taken
.respond:
	bts	dword [r14+ADSE_DONE],r12d
	mov	r8d,1
	jmp	.taken
.held:
	xor	r8d,r8d
.taken:
	stc
	jmp	.out
.through:
	clc
.out:
	pop	r14
	pop	r13
	pop	r12
	ret

; r12d = an addon, r14 = the side entry, ebx, r15, g_hm: the call posted and the
; request held. CF: it could not be (the side entry untouched). Keeps rbx,
; r12-r15.
addon_call:
	push	r13
	imul	r13,r12,ADW_SIZE
	lea	r13,[g_aw+r13]
	cmp	dword [r13+ADW_LIVE],0
	je	.no
	mov	rax,[r13+ADW_HDR]
	mov	ecx,[rax+ADH_EPOCH]
	cmp	ecx,[r13+ADW_EPOCH]
	je	@f
	push	r14
	push	r15
	mov	r14,[r13+ADW_REQ]
	call	ad_epoch_over			; (its calls end; this one goes to the new run)
	pop	r15
	pop	r14
	mov	rax,[r13+ADW_HDR]
@@:
	cmp	dword [rax+ADH_READY],1
	jne	.error
	cmp	dword [g_fd_n],FD_MAX
	jae	.error
	call	qs_clock
	mov	rax,[r13+ADW_OPEN]
	test	rax,rax
	jz	.closed
	cmp	rax,[g_qnow]
	ja	.error				; open
	imul	rax,r12,ADE_SIZE		; half open: this one goes, none other
	mov	rax,[g_addons+rax+ADE_OPEN]	; until it is answered or its time is up
	add	rax,[g_qnow]
	mov	[r13+ADW_OPEN],rax
.closed:
	mov	eax,[r13+ADW_SEQ]
	sub	eax,[r13+ADW_FHEAD]
	cmp	eax,[r13+ADW_CAP]
	jae	.error				; concurrency
	cmp	dword [g_ad_resp],0
	jne	.response
	imul	rax,r12,ADE_SIZE
	test	dword [g_addons+rax+ADE_PHASES],ADP_REQ_BODY
	jz	@f
	call	ad_body_ready			; its body first
	jnc	@f
	clc					; held while it comes (its own clock: body_idle)
	jmp	.out
@@:
	call	ad_post
	jc	.error
	jmp	.posted
.response:
	imul	rax,r12,ADE_SIZE
	test	dword [g_addons+rax+ADE_PHASES],ADP_RESP_BODY
	jz	@f
	call	ad_rbody_ready			; the response's body first
	jnc	@f
	clc
	jmp	.out
@@:
	call	ad_post_resp
	jc	.error
.posted:
	; the FIFO
	mov	eax,[r13+ADW_SEQ]
	mov	ecx,[r13+ADW_CAP]
	dec	ecx
	and	ecx,eax
	shl	rcx,5
	add	rcx,[r13+ADW_FIFO]
	mov	[rcx+AFE_SEQ],eax
	mov	[rcx+AFE_SESS],ebx
	push	rax
	call	session_ptr
	mov	edx,[rax+S_GEN]
	pop	rax
	mov	[rcx+AFE_SGEN],edx
	mov	dword [rcx+AFE_STATE],1
	push	rax
	push	rdx
	rdtsc
	shl	rdx,32
	or	rax,rdx
	mov	[rcx+AFE_T0],rax
	pop	rdx
	pop	rax
	imul	rdx,r12,ADE_SIZE
	mov	r8,[g_addons+rdx+ADE_TIMEOUT]
	mov	r9,r8
	add	r9,[g_qnow]
	mov	[rcx+AFE_DUE],r9
	mov	[r14+ADSE_SEQ],eax
	inc	eax
	mov	[r13+ADW_SEQ],eax
	mov	rdx,[r13+ADW_REQ]
	mov	[rdx+ADR_NEXTID],eax
	inc	qword [rdx+ADR_COUNT+ADC_CALLS]
	mov	byte [r14+ADSE_STATE],ADS_WAIT
	mov	[r14+ADSE_ADDON],r12b
	and	dword [r14+ADSE_FLAGS],not ADSF_RESP
	cmp	dword [g_ad_resp],0
	je	@f
	or	dword [r14+ADSE_FLAGS],ADSF_RESP
@@:
	mov	dword [r13+ADW_DIRTY],1
	mov	dword [g_ad_any],1
	mov	dword [g_ad_posted],1
	; held, for as long as it is given
	mov	rax,r8
	call	fault_hold
	or	dword [g_fd+rcx+FD_SESS],FD_ADDON
	clc
	jmp	.out
.error:
	mov	rax,[r13+ADW_REQ]
	inc	qword [rax+ADR_COUNT+ADC_ERROR]
.no:
	stc
.out:
	pop	r13
	ret

; r12d = an addon whose call carries the body, ebx, r15, g_hm: CF when the body is
; not in yet (what the call carries of it: the whole, or `body`, or what the
; buffer holds); its reading is then posted and the request waits in
; HS_ADBODY. A body the client sends only after 100 Continue is not waited for
; (ADQF_UNREAD). Keeps rbx, r12-r15.
ad_body_ready:
	call	ad_body_want			; eax = bytes wanted, ecx = bytes there
	cmp	ecx,eax
	jae	.ready
	mov	eax,[r15+H_INLEN]
	cmp	eax,H_IN_CAP
	jae	.ready				; (full: as much as it holds)
	mov	rdi,[r15+H_BUF]			; chunked: the last chunk came already?
	mov	esi,[r15+H_INOFF]
	lea	rsi,[rdi+HB_IN+rsi]
	call	ad_chunked_end
	jnc	.ready
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	dword [r15+H_STATE],HS_ADBODY
	mov	edi,ebx
	mov	esi,PH_BODY
	call	ph_arm
	h_rec
	mov	ecx,SIDE_CLIENT
	mov	esi,H_IN_CAP
	sub	esi,[r15+H_INLEN]
	mov	eax,[r15+H_INLEN]
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_IN+rax]
	call	h_recv
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	stc
	ret
.ready:
	clc
	ret

; r12d = the addon, r15, g_hm: eax = the body's bytes a call wants (0: no body,
; or one not to wait for), ecx = those in the buffer. Keeps rbx, rsi, r8-r15.
ad_body_want:
	mov	ecx,[r15+H_INLEN]
	sub	ecx,[r15+H_INOFF]
	xor	eax,eax
	cmp	dword [r15+H_BODY],BK_LENGTH
	je	.length
	cmp	dword [r15+H_BODY],BK_CHUNKED
	jne	.out
	test	dword [g_hm+HM_FLAGS],HMF_CONTINUE
	jnz	.out
	call	.max
	ret
.length:
	test	dword [g_hm+HM_FLAGS],HMF_CONTINUE
	jnz	.out
	call	.max
	cmp	rax,[g_hm+HM_LENGTH]
	jbe	.out
	mov	rax,[g_hm+HM_LENGTH]
.out:
	ret
; eax = `body`, within what the buffer holds after the head
.max:
	imul	rax,r12,ADE_SIZE
	mov	eax,[g_addons+rax+ADE_BODY]
	mov	edx,H_IN_CAP
	sub	edx,[r15+H_INOFF]
	cmp	eax,edx
	jbe	@f
	mov	eax,edx
@@:
	ret

; rsi = a chunked body's start, r15: CF unless its last chunk (0 CRLF CRLF)
; is in the buffer. Keeps rbx, r12-r15.
ad_chunked_end:
	cmp	dword [r15+H_BODY],BK_CHUNKED
	jne	.no
	mov	rdi,[r15+H_BUF]
	mov	ecx,[r15+H_INLEN]
	lea	rdi,[rdi+HB_IN+rcx]		; the end
	mov	rcx,rdi
	sub	rcx,rsi
	cmp	rcx,5
	jb	.no
	cmp	dword [rsi],0x0D0A0D30		; "0\r\n\r" at the start: an empty body
	jne	.scan
	cmp	byte [rsi+4],10
	je	.yes
.scan:
	lea	rdi,[rdi-7]
.at:
	cmp	rsi,rdi
	ja	.no
	cmp	word [rsi],0x0A0D
	jne	.next
	cmp	dword [rsi+2],0x0D0A0D30
	jne	.next
	cmp	byte [rsi+6],10
	je	.yes
.next:
	inc	rsi
	jmp	.at
.yes:
	clc
	ret
.no:
	stc
	ret

; http_recv_plain, HS_ADBODY: more of the body came (rax). Through the request
; again: its addon finds the body in, or waits for more.
addon_body_in:
	test	rax,rax
	jle	.gone
	add	[r15+H_INLEN],eax
	mov	edi,ebx
	call	idle_touch
	h_rec
	or	dword [r15+H_FLAGS],HX_FAULTED	; (a request back, not a new one)
	mov	eax,[r15+H_INOFF]
	jmp	http_request
.gone:
	mov	edi,ebx				; the client went in the middle of its body
	jmp	session_close

; r13 = the addon's state, ebx, r15, g_hm: the call into its ring. CF: no room.
; Keeps rbx, r12-r15.
ad_post:
	push	rbx
	push	r12
	push	r14
	call	http_client_resolve		; (who the client is: the peer, or what trusted proxies say)
	; its size: the fixed part, the index, the head
	; the body it carries, when its addon asks for it (r12d = the addon)
	xor	eax,eax
	xor	r8d,r8d				; flags
	imul	rdx,r12,ADE_SIZE
	test	dword [g_addons+rdx+ADE_PHASES],ADP_REQ_BODY
	jz	.sized_body
	call	ad_body_want
	cmp	dword [r15+H_BODY],BK_NONE
	je	.sized_body
	test	dword [g_hm+HM_FLAGS],HMF_CONTINUE
	jz	@f
	mov	r8d,ADQF_UNREAD
	xor	eax,eax
	jmp	.sized_body
@@:
	cmp	eax,ecx
	jbe	@f
	mov	eax,ecx				; (what is there: as much as the buffer holds)
@@:
	cmp	dword [r15+H_BODY],BK_CHUNKED
	jne	.counted
	or	r8d,ADQF_CHUNKED
	jmp	.sized_body
.counted:
	mov	ecx,eax
	cmp	rcx,[g_hm+HM_LENGTH]
	jae	.sized_body
	or	r8d,ADQF_TRUNC
.sized_body:
	mov	[g_ad_blen],eax
	mov	[g_ad_bflags],r8d
	mov	r12d,[g_hm+HM_NHDR]
	lea	eax,[ADQ_INDEX+r12*8]
	add	eax,[r15+H_INOFF]
	add	eax,[g_ad_blen]
	add	eax,7
	and	eax,not 7
	mov	r10d,eax			; the record
	mov	r14,[r13+ADW_REQ]
	mov	rcx,[r13+ADW_HEAD]
	mov	edx,ecx
	and	edx,AD_RING - 1
	mov	r9d,AD_RING
	sub	r9d,edx				; to the ring's end
	xor	r11d,r11d			; padding first
	cmp	r9d,r10d
	jae	@f
	mov	r11d,r9d
@@:
	mov	rax,rcx
	sub	rax,[r14+ADR_TAIL]
	mov	r8d,AD_RING
	sub	r8,rax				; room
	lea	eax,[r10+r11]
	cmp	rax,r8
	ja	.full
	test	r11d,r11d
	jz	.at
	lea	rdi,[r14+ADR_CALLS+rdx]
	mov	[rdi+ADQ_LEN],r11d
	mov	dword [rdi+ADQ_KIND],0
	add	rcx,r11
	xor	edx,edx
.at:
	lea	rdi,[r14+ADR_CALLS+rdx]
	push	rcx
	mov	[rdi+ADQ_LEN],r10d
	mov	word [rdi+ADQ_KIND],1
	mov	word [rdi+ADQ_PHASE],ADP_REQ_HEADERS
	cmp	dword [g_ad_blen],0
	je	@f
	mov	word [rdi+ADQ_PHASE],ADP_REQ_BODY
@@:
	mov	eax,[r13+ADW_SEQ]
	mov	[rdi+ADQ_ID],eax
	; what the client spoke
	mov	r8d,[g_ad_bflags]
	push	rax
	push	rdi
	call	session_ptr
	pop	rdi
	mov	edx,[rax+S_FLAGS]
	mov	ecx,[rax+S_LST]
	pop	rax
	test	edx,SF_H2S
	jz	@f
	or	r8d,ADQF_H2
@@:
	test	edx,SF_H3S
	jz	@f
	or	r8d,ADQF_H3 or ADQF_TLS
@@:
	imul	rcx,rcx,LS_SIZE
	cmp	dword [g_listeners+rcx+LS_TLS],0
	je	@f
	or	r8d,ADQF_TLS
@@:
	mov	[rdi+ADQ_FLAGS],r8d
	mov	eax,[r15+H_INOFF]
	mov	[rdi+ADQ_HLEN],eax
	mov	[rdi+ADQ_NHDR],r12w
	mov	eax,[r15+H_CKIND]
	mov	[rdi+ADQ_FAMILY],ax
	mov	rax,[r15+H_CLIENT]
	mov	[rdi+ADQ_CLIENT],rax
	mov	rax,[r15+H_CLIENT+8]
	mov	[rdi+ADQ_CLIENT+8],rax
	mov	rsi,[r15+H_BUF]			; the head: offsets from here
	lea	rsi,[rsi+HB_IN]
	mov	rax,[g_hm+HM_METHOD]
	sub	rax,rsi
	mov	[rdi+ADQ_METHOD],ax
	mov	eax,[g_hm+HM_MLEN]
	mov	[rdi+ADQ_METHOD+2],ax
	mov	rax,[g_hm+HM_TARGET]
	sub	rax,rsi
	mov	[rdi+ADQ_TARGET],ax
	mov	eax,[g_hm+HM_TLEN]
	mov	[rdi+ADQ_TARGET+2],ax
	mov	eax,[r15+H_ACT]
	mov	[rdi+ADQ_ROUTE],eax
	mov	rax,[r15+H_LT0]			; (when its head was read: one request's)
	mov	[rdi+ADQ_STREAM],rax
	mov	eax,[g_ad_blen]
	mov	[rdi+ADQ_BLEN],eax
	; the index
	lea	r9,[g_hm+HM_HDRS]
	lea	r8,[rdi+ADQ_INDEX]
	mov	ecx,r12d
.field:
	test	ecx,ecx
	jz	.fields
	mov	rax,[r9+HF_NAME]
	sub	rax,rsi
	mov	[r8],ax
	mov	eax,[r9+HF_NLEN]
	mov	[r8+2],ax
	mov	rax,[r9+HF_VALUE]
	sub	rax,rsi
	mov	[r8+4],ax
	mov	eax,[r9+HF_VLEN]
	mov	[r8+6],ax
	add	r9,HF_SIZE
	add	r8,8
	dec	ecx
	jmp	.field
.fields:
	mov	rdi,r8
	mov	ecx,[r15+H_INOFF]
	add	ecx,[g_ad_blen]			; the head, then the body after it
	rep	movsb
	pop	rcx
	add	rcx,r10
	mov	[r13+ADW_HEAD],rcx
	mov	[r14+ADR_HEAD],rcx		; published (the stores before it are seen first)
	clc
	jmp	.out
.full:
	stc
.out:
	pop	r14
	pop	r12
	pop	rbx
	ret

; fault_flush: a request held for an addon, its time come (or an answer made it
; due). ebx, r15, r9 = its time.
addon_resume:
	cmp	dword [r15+H_STATE],HS_FAULT
	jne	.none
	call	ad_side_cur
	jc	.go
	cmp	byte [rcx+ADSE_STATE],ADS_WAIT
	jne	.go
	; no answer in time
	mov	byte [rcx+ADSE_STATE],ADS_FAIL
	movzx	eax,byte [rcx+ADSE_ADDON]
	mov	edx,[rcx+ADSE_SEQ]
	imul	rax,rax,ADW_SIZE
	lea	r8,[g_aw+rax]
	mov	eax,[r8+ADW_CAP]
	dec	eax
	and	eax,edx
	shl	rax,5
	add	rax,[r8+ADW_FIFO]
	cmp	[rax+AFE_SEQ],edx
	jne	.go
	cmp	dword [rax+AFE_STATE],1
	jne	.go
	mov	dword [rax+AFE_STATE],0
	mov	rdx,[r8+ADW_REQ]
	inc	qword [rdx+ADR_COUNT+ADC_TIMEOUT]
	push	r12
	push	r13
	movzx	r12d,byte [rcx+ADSE_ADDON]
	mov	r13,r8
	call	qs_clock
	call	ad_failed
	pop	r13
	pop	r12
.go:
	call	ad_side_cur
	jc	@f
	test	dword [rcx+ADSE_FLAGS],ADSF_RESP
	jnz	http_resp_again
@@:
	mov	eax,[r15+H_INOFF]
	jmp	http_request
.none:
	ret

; ------------------------------------------------- what an answer does

; r15 = an answer to continue with fields to change, ebx = the session (held):
; its head rewritten in place. CF: the answer is not fit (a field that is not
; one, a target that is not a path) or the head would not fit.
; Keeps rbx, r12-r15, r10.
ad_rewrite:
	mov	r8d,ebx
	shl	r8,H_SHIFT
	add	r8,[g_http_base]		; the request's record
	mov	rax,[r8+H_BUF]
	lea	rax,[rax+HB_IN]
	mov	[g_rw_head],rax
	mov	eax,[r8+H_INOFF]
	mov	[g_rw_hlen],eax
	mov	ecx,[r8+H_INLEN]
	sub	ecx,eax
	mov	[g_rw_tail],ecx
	mov	dword [g_rw_cap],H_IN_CAP
	mov	dword [g_rw_tgt],1
	push	r8
	call	ad_rebuild
	pop	r8
	jc	.out
	mov	[r8+H_INOFF],eax
	add	eax,[g_rw_tail]
	mov	[r8+H_INLEN],eax
	clc
.out:
	ret

; the same, of a response held for an addon: its head at ADSE_HSTART in HB_UP
; (r10 = the side entry). Keeps rbx, r10, r12-r15.
ad_rewrite_resp:
	mov	r8d,ebx
	shl	r8,H_SHIFT
	add	r8,[g_http_base]
	mov	eax,[r10+ADSE_HSTART]
	mov	rdx,[r8+H_BUF]
	lea	rdx,[rdx+HB_UP+rax]
	mov	[g_rw_head],rdx
	mov	ecx,H_UP_CAP
	sub	ecx,eax
	mov	[g_rw_cap],ecx
	mov	ecx,[r10+ADSE_RHLEN]
	mov	[g_rw_hlen],ecx
	add	ecx,eax
	mov	edx,[r8+H_UPLEN]
	sub	edx,ecx
	mov	[g_rw_tail],edx
	mov	dword [g_rw_tgt],0
	push	r8
	call	ad_rebuild
	pop	r8
	jc	.out
	mov	[r10+ADSE_RHLEN],eax
	add	eax,[r10+ADSE_HSTART]
	add	eax,[g_rw_tail]
	mov	[r8+H_UPLEN],eax
	clc
.out:
	ret

; g_rw_*: a head (and what follows it) rebuilt with the ops of the answer at
; r15: eax = the head's new length. CF: not fit, or it would not fit.
; Keeps rbx, r10, r12-r15.
ad_rebuild:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	push	rbp
	push	r10
	mov	r12,[g_rw_head]			; the head
	lea	rdi,[g_ad_tmp]
	lea	rbp,[g_ad_tmp+H_IN_CAP-2]	; the room
	; its first line, or one with the target the addon gives
	mov	rsi,r12
	mov	ecx,[g_rw_hlen]
	call	ad_line
	jc	.bad
	mov	r13,rax				; the next line
	cmp	dword [g_rw_tgt],0
	je	.line_as_is
	movzx	ecx,word [r15+ANS_NOPS]
	lea	r8,[r15+ANS_OPS]
	call	ad_op_find_target
	test	r9,r9
	jz	.line_as_is
	; METHOD SP target SP VERSION
	mov	rsi,r12
@@:
	lodsb
	stosb
	cmp	al,' '
	jne	@b
	mov	r10,rsi				; past the method
	movzx	ecx,word [r9+4]			; the target
	lea	rsi,[r9+ANO_HDR]
	movzx	eax,word [r9+2]
	add	rsi,rax
	test	ecx,ecx
	jz	.bad
	cmp	byte [rsi],'/'
	jne	.bad
	lea	rax,[rdi+rcx+16]
	cmp	rax,rbp
	ja	.bad
.target:
	lodsb
	cmp	al,0x21
	jb	.bad
	cmp	al,0x7E
	ja	.bad
	cmp	al,'#'
	je	.bad
	stosb
	dec	ecx
	jnz	.target
	; the version: after the old target
	mov	rsi,r10
@@:
	lodsb
	cmp	al,' '
	jne	@b
	mov	byte [rdi],' '
	inc	rdi
@@:
	lodsb
	stosb
	cmp	al,10
	jne	@b
	jmp	.fields
.line_as_is:
	mov	rsi,r12
	mov	rcx,r13
	sub	rcx,r12
	rep	movsb
.fields:
	; each field, unless an op sets or removes it
	mov	rsi,r13
	mov	ecx,[g_rw_hlen]
	add	rcx,r12
	sub	rcx,rsi
	call	ad_line
	jc	.bad
	mov	r10,rax				; the next
	mov	rcx,rax
	sub	rcx,r13
	cmp	byte [r13],13
	je	.own
	cmp	byte [r13],10
	je	.own
	; its name
	xor	edx,edx
@@:
	cmp	edx,ecx
	jae	.bad
	cmp	byte [r13+rdx],':'
	je	@f
	inc	edx
	jmp	@b
@@:
	push	rcx
	push	rdi
	mov	rsi,r13				; rsi/edx = the name
	movzx	ecx,word [r15+ANS_NOPS]
	lea	r8,[r15+ANS_OPS]
	call	ad_op_drops
	pop	rdi
	pop	rcx
	jc	.dropped
	lea	rax,[rdi+rcx]
	cmp	rax,rbp
	ja	.bad
	mov	rsi,r13
	rep	movsb
.dropped:
	mov	r13,r10
	jmp	.fields
.own:
	; then what the ops set and add
	movzx	ebx,word [r15+ANS_NOPS]
	lea	r8,[r15+ANS_OPS]
.op:
	test	ebx,ebx
	jz	.end
	dec	ebx
	movzx	eax,byte [r8]
	movzx	ecx,word [r8+2]			; name
	movzx	edx,word [r8+4]			; value
	lea	rsi,[r8+ANO_HDR]
	lea	r9,[rsi+rcx]
	lea	r9,[r9+rdx]			; the next op
	cmp	eax,ANO_SET
	je	.emit
	cmp	eax,ANO_ADD
	jne	.op_next
.emit:
	push	rcx
	push	rdx
	call	ad_field_ok
	pop	rdx
	pop	rcx
	jc	.bad
	jz	.op_next			; (one an addon may not change: left as it is)
	lea	rax,[rdi+rcx]
	lea	rax,[rax+rdx+4]
	cmp	rax,rbp
	ja	.bad
	rep	movsb
	mov	word [rdi],': '
	add	rdi,2
	mov	ecx,edx
	rep	movsb
	mov	word [rdi],0x0A0D
	add	rdi,2
.op_next:
	mov	r8,r9
	jmp	.op
.end:
	mov	word [rdi],0x0A0D
	add	rdi,2
	; into the buffer, the body (or what was pipelined) moved after it
	lea	rax,[g_ad_tmp]
	sub	rdi,rax
	mov	r13d,edi			; the new head
	mov	ecx,[g_rw_tail]			; what follows it
	lea	eax,[r13+rcx]
	cmp	eax,[g_rw_cap]
	ja	.bad
	mov	esi,[g_rw_hlen]
	add	rsi,r12
	lea	rdi,[r12+r13]
	cmp	rdi,rsi
	jbe	.down
	lea	rsi,[rsi+rcx-1]			; up: from the end
	lea	rdi,[rdi+rcx-1]
	std
	rep	movsb
	cld
	jmp	.moved
.down:
	rep	movsb
.moved:
	mov	rdi,r12
	lea	rsi,[g_ad_tmp]
	mov	ecx,r13d
	rep	movsb
	mov	eax,r13d
	clc
	jmp	.out
.bad:
	stc
.out:
	pop	r10
	pop	rbp
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rsi = a line, ecx = what is left of the head: rax = past its LF. CF: none.
; Keeps rdi, rsi, r8-r15.
ad_line:
	test	ecx,ecx
	jz	.no
	xor	eax,eax
@@:
	cmp	byte [rsi+rax],10
	je	@f
	inc	eax
	cmp	eax,ecx
	jb	@b
.no:
	stc
	ret
@@:
	lea	rax,[rsi+rax+1]
	clc
	ret

; r8 = the ops, ecx = how many: r9 = the last ANO_TARGET, or 0. Keeps rdi, rsi.
ad_op_find_target:
	xor	r9d,r9d
.next:
	test	ecx,ecx
	jz	.out
	dec	ecx
	cmp	byte [r8],ANO_TARGET
	jne	@f
	mov	r9,r8
@@:
	movzx	eax,word [r8+2]
	movzx	edx,word [r8+4]
	lea	r8,[r8+rax+ANO_HDR]
	add	r8,rdx
	jmp	.next
.out:
	ret

; rsi/edx = a field's name in the head, r8 = the ops, ecx = how many: CF when
; one sets or removes it (it is not copied). Keeps rdi, rsi, rdx.
ad_op_drops:
.next:
	test	ecx,ecx
	jz	.keep
	dec	ecx
	movzx	eax,byte [r8]
	cmp	eax,ANO_SET
	je	.cmp
	cmp	eax,ANO_REMOVE
	jne	.skip
.cmp:
	movzx	eax,word [r8+2]
	cmp	eax,edx
	jne	.skip
	push	rcx
	push	rdi
	push	rsi
	push	rdx
	lea	rdi,[r8+ANO_HDR]
	call	mem_eq_nocase_n
	pop	rdx
	pop	rsi
	pop	rdi
	pop	rcx
	jnz	.skip
	; not one an addon may change
	push	rsi
	push	rdx
	mov	ecx,edx
	call	ad_name_fixed
	pop	rdx
	pop	rsi
	jz	.keep
	stc
	ret
.skip:
	movzx	eax,word [r8+2]
	movzx	r9d,word [r8+4]
	lea	r8,[r8+rax+ANO_HDR]
	add	r8,r9
	jmp	.next
.keep:
	clc
	ret

; rdi, rsi = names, edx = their length: ZF when equal but for case
mem_eq_nocase_n:
	test	edx,edx
	jz	.eq
.ch:
	mov	al,[rdi]
	mov	ah,[rsi]
	or	ax,0x2020
	cmp	al,ah
	jne	.out
	inc	rdi
	inc	rsi
	dec	edx
	jnz	.ch
.eq:
	xor	eax,eax
.out:
	ret

; rsi = a name, ecx = its length: ZF when an addon may not set it (the body's
; framing, the connection's own fields). Keeps rdi, r8-r15.
ad_name_fixed:
	push	rdi
	push	rbx
	mov	ebx,ecx
	lea	rdi,[.names]
.next:
	movzx	ecx,byte [rdi]
	test	ecx,ecx
	jz	.free
	cmp	ecx,ebx
	jne	.skip
	push	rsi
	push	rdi
	inc	rdi
	mov	edx,ecx
	call	mem_eq_nocase_n
	pop	rdi
	pop	rsi
	jz	.fixed
.skip:
	movzx	ecx,byte [rdi]
	lea	rdi,[rdi+rcx+1]
	jmp	.next
.free:
	or	eax,1				; ZF clear
	jmp	.out
.fixed:
	xor	eax,eax
.out:
	pop	rbx
	pop	rdi
	ret
.names	db 14,'content-length'
	db 17,'transfer-encoding'
	db 10,'connection'
	db 10,'keep-alive'
	db 2,'te'
	db 7,'trailer'
	db 7,'upgrade'
	db 16,'proxy-connection'
	db 0

; rsi = a name, ecx = its length, rdx = its value's (after it): CF when it is
; not a field (a name that is no token, a value with a control character); ZF
; when it is one an addon may not set. Keeps rdi, rsi, r8-r15.
ad_field_ok:
	test	ecx,ecx
	jz	.bad
	cmp	ecx,256
	ja	.bad
	cmp	edx,8192
	ja	.bad
	xor	eax,eax
.name:
	movzx	r10d,byte [rsi+rax]
	cmp	byte [http_tchar+r10],0
	je	.bad
	inc	eax
	cmp	eax,ecx
	jb	.name
	lea	r11,[rsi+rcx]			; the value
	xor	eax,eax
.value:
	cmp	eax,edx
	jae	.valid
	movzx	r10d,byte [r11+rax]
	cmp	r10d,9
	je	@f
	cmp	r10d,0x20
	jb	.bad
	cmp	r10d,0x7F
	je	.bad
@@:
	inc	eax
	jmp	.value
.valid:
	push	rdx
	push	rcx
	call	ad_name_fixed
	pop	rcx
	pop	rdx
	clc
	ret
.bad:
	stc
	ret

; r15 = an answer to respond with, ebx = the session (held): its fields and body
; put at the end of HB_OUT until the request comes back to answer. CF: not fit.
; Keeps rbx, r12-r15, r10.
ad_stash:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r10
	movzx	eax,word [r15+ANS_STATUS]
	cmp	eax,200
	jb	.bad
	cmp	eax,599
	ja	.bad
	mov	[r10+ADSE_STATUS],eax
	mov	r14d,ebx
	shl	r14,H_SHIFT
	add	r14,[g_http_base]
	; how much: each field rendered, the body
	movzx	ebx,word [r15+ANS_NOPS]
	lea	r8,[r15+ANS_OPS]
	xor	r12d,r12d			; fields' bytes
.size:
	test	ebx,ebx
	jz	.sized
	dec	ebx
	movzx	ecx,word [r8+2]
	movzx	edx,word [r8+4]
	cmp	byte [r8],ANO_SET
	je	@f
	cmp	byte [r8],ANO_ADD
	jne	.bad
@@:
	lea	r12d,[r12+rcx+4]
	add	r12d,edx
	lea	r8,[r8+rcx+ANO_HDR]
	add	r8,rdx
	jmp	.size
.sized:
	mov	r13d,[r15+ANS_BLEN]
	; the body is within the record
	mov	rax,r8
	sub	rax,r15
	add	rax,r13
	cmp	eax,[r15+ANS_LEN]
	ja	.bad
	lea	eax,[r12+r13]
	cmp	eax,AD_STASH_MAX
	ja	.bad
	mov	rdi,[r14+H_BUF]
	lea	rdi,[rdi+HB_OUT+H_OUT_CAP]
	sub	rdi,rax
	push	r8				; (the body)
	movzx	ebx,word [r15+ANS_NOPS]
	lea	r8,[r15+ANS_OPS]
	xor	r11d,r11d			; fields kept
.field:
	test	ebx,ebx
	jz	.fields
	dec	ebx
	movzx	ecx,word [r8+2]
	movzx	edx,word [r8+4]
	lea	rsi,[r8+ANO_HDR]
	lea	r9,[rsi+rcx]
	add	r9,rdx
	push	rcx
	push	rdx
	call	ad_field_ok
	pop	rdx
	pop	rcx
	jc	.bad_pop
	jz	.next_field			; (okena writes those itself)
	rep	movsb
	mov	word [rdi],': '
	add	rdi,2
	mov	ecx,edx
	rep	movsb
	mov	word [rdi],0x0A0D
	add	rdi,2
.next_field:
	mov	r8,r9
	jmp	.field
.fields:
	; the fields kept may be fewer: the body follows them at once
	pop	rsi
	mov	ecx,r13d
	rep	movsb
	mov	r10,[rsp]
	; where they begin, and how long they are
	mov	rax,[r14+H_BUF]
	lea	rax,[rax+HB_OUT+H_OUT_CAP]
	sub	rax,rdi				; what was not used (dropped fields)
	mov	ecx,r12d
	sub	ecx,eax
	mov	[r10+ADSE_HLEN],ecx
	mov	[r10+ADSE_BLEN],r13d
	; moved to the end, so the start is found from the lengths alone
	test	eax,eax
	jz	.ok
	mov	ecx,[r10+ADSE_HLEN]
	add	ecx,r13d
	lea	rsi,[rdi-1]
	lea	rdi,[rdi+rax-1]
	std
	rep	movsb
	cld
.ok:
	clc
	jmp	.out
.bad_pop:
	pop	rax
.bad:
	stc
.out:
	pop	r10
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; http_request, an addon's own answer: ebx, r15. Its fields and body wait at
; the end of HB_OUT (ad_stash).
addon_respond:
	call	ad_side_cur
	jc	.lost
	mov	r8d,[rcx+ADSE_STATUS]
	mov	r9d,[rcx+ADSE_HLEN]
	mov	r10d,[rcx+ADSE_BLEN]
	push	r8
	push	r9
	push	r10
	or	dword [r15+H_FLAGS],HX_SELF or HX_STARTED
	test	dword [r15+H_FLAGS],HX_NOBODY
	jnz	@f
	or	dword [r15+H_FLAGS],HX_CLOSE	; (a body it will not read)
@@:
	mov	[r15+H_STATUS],r8d
	mov	edi,r8d
	mov	esi,5
	call	http_count
	cmp	dword [r15+H_RIDLEN],0
	jne	@f
	call	rid_new
@@:
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_OUT]
	memit_x 'HTTP/1.1 '
	mov	eax,[rsp+16]
	call	fmt_u64
	mov	byte [rdi],' '
	inc	rdi
	mov	eax,[rsp+16]
	call	http_reason
	call	fmt_cstr
	memit_x 13,10
	; its fields (the source is further on: copied forward)
	mov	rsi,[r15+H_BUF]
	lea	rsi,[rsi+HB_OUT+H_OUT_CAP]
	mov	eax,[rsp+8]
	add	eax,[rsp]
	sub	rsi,rax
	mov	ecx,[rsp+8]
	rep	movsb
	push	rsi				; (the body)
	call	cors_emit
	mov	eax,[rsp+24]
	cmp	eax,204
	je	@f
	cmp	eax,304
	je	@f
	memit_x 'Content-Length: '
	mov	eax,[rsp+8]
	call	fmt_u64
	memit_x 13,10
@@:
	memit_x 'X-Request-Id: '
	lea	rsi,[r15+H_RID]
	mov	ecx,[r15+H_RIDLEN]
	rep	movsb
	memit_x 13,10
	test	dword [r15+H_FLAGS],HX_CLOSE
	jz	@f
	memit_x 'Connection: close',13,10
@@:
	memit_x 13,10
	pop	rsi
	mov	ecx,[rsp]
	test	dword [r15+H_FLAGS],HX_HEAD
	jnz	@f
	cmp	dword [rsp+16],204
	je	@f
	cmp	dword [rsp+16],304
	je	@f
	rep	movsb
@@:
	add	rsp,24
	mov	rsi,[r15+H_BUF]
	lea	rsi,[rsi+HB_OUT]
	sub	rdi,rsi
	mov	dword [r15+H_STATE],HS_SELF_SEND
	mov	ecx,SIDE_CLIENT
	xchg	rsi,rdi
	jmp	h_send
.lost:
	mov	edi,503
	jmp	http_error

; ------------------------------------------------------------ the response

; http_resp_head, a final response's head parsed (g_hm), the backend's status
; counted: the route's addons with a response phase. CF clear: through them
; all. CF set: r8d = 0 held, 1 the addon's own answer, else a status.
; ebx, r15. Keeps rbx, r12-r15.
addon_resp_stage:
	mov	eax,[r15+H_ACT]
	test	eax,eax
	jz	.none
	dec	eax
	imul	rax,rax,RA_SIZE
	mov	edi,[g_acts+rax+RA_ADDONS]
	test	edi,edi
	jz	.none
	push	r12
	push	r13
	push	r14
	mov	r13d,edi
	call	ad_side_cur
	jc	.through
	mov	r14,rcx
	mov	eax,[r15+H_UPOFF]		; where the head is (each pass: it is parsed again)
	sub	eax,[g_hm+HM_HEADLEN]
	mov	[r14+ADSE_HSTART],eax
	mov	eax,[g_hm+HM_HEADLEN]
	mov	[r14+ADSE_RHLEN],eax
	mov	eax,[r14+ADSE_RDONE]
	not	eax
	and	r13d,eax
.next:
	bsf	r12d,r13d
	jz	.through
	imul	rax,r12,ADE_SIZE
	test	dword [g_addons+rax+ADE_PHASES],ADP_RESP
	jz	.done_one
	test	dword [r14+ADSE_FLAGS],ADSF_RESP
	jz	.ask
	cmp	byte [r14+ADSE_STATE],ADS_NONE
	je	.ask
	cmp	[r14+ADSE_ADDON],r12b
	jne	.ask
	movzx	eax,byte [r14+ADSE_STATE]
	mov	byte [r14+ADSE_STATE],ADS_NONE
	and	dword [r14+ADSE_FLAGS],not ADSF_RESP
	cmp	eax,ADS_CONT
	je	.done_one
	cmp	eax,ADS_RESP
	je	.respond
	cmp	eax,ADS_FAIL
	je	.error
	mov	byte [r14+ADSE_STATE],al	; still waiting
	or	dword [r14+ADSE_FLAGS],ADSF_RESP
	xor	r8d,r8d
	jmp	.taken
.ask:
	mov	dword [g_ad_resp],1
	call	addon_call
	mov	dword [g_ad_resp],0
	jnc	.held
.error:
	imul	rax,r12,ADE_SIZE
	imul	rcx,r12,ADW_SIZE
	mov	rcx,[g_aw+rcx+ADW_REQ]
	cmp	dword [g_addons+rax+ADE_ONERR],0
	je	.deny
	test	rcx,rcx
	jz	.done_one
	inc	qword [rcx+ADR_COUNT+ADC_ALLOWED]
.done_one:
	bts	dword [r14+ADSE_RDONE],r12d
	btr	r13d,r12d
	jmp	.next
.deny:
	test	rcx,rcx
	jz	@f
	inc	qword [rcx+ADR_COUNT+ADC_DENIED]
@@:
	bts	dword [r14+ADSE_RDONE],r12d
	mov	r8d,502
	jmp	.taken
.respond:
	bts	dword [r14+ADSE_RDONE],r12d
	mov	r8d,1
	jmp	.taken
.held:
	xor	r8d,r8d
.taken:
	pop	r14
	pop	r13
	pop	r12
	stc
	ret
.through:
	pop	r14
	pop	r13
	pop	r12
.none:
	clc
	ret

; a response held for an addon goes on: its head parsed again (with what the
; addon changed), back into http_resp_head after the backend's status was
; counted. ebx, r15.
http_resp_again:
	call	ad_side_cur
	jc	.bad
	mov	eax,[rcx+ADSE_HSTART]
	mov	[r15+H_UPOFF],eax
	mov	esi,[rcx+ADSE_RHLEN]
	push	rsi
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_UP+rax]
	lea	rdx,[g_hm]
	call	http_parse_response
	pop	rcx
	test	eax,eax
	jnz	.bad
	h_rec
	add	[r15+H_UPOFF],ecx
	mov	eax,[g_hm+HM_STATUS]
	jmp	http_resp_head.addons
.bad:
	mov	edi,502
	jmp	http_error

; r12d = an addon with response_body, ebx, r15, g_hm (the response), r14 = the
; side entry: CF when a counted body that the call may carry is not all in
; yet; its reading is then posted (HS_ADRBODY). Keeps rbx, r12-r15.
ad_rbody_ready:
	call	ad_rbody_want			; eax = wanted, ecx = there
	cmp	ecx,eax
	jae	.ready
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	dword [r15+H_STATE],HS_ADRBODY
	mov	edi,ebx
	mov	esi,PH_RESPONSE
	call	ph_arm
	h_rec
	mov	ecx,SIDE_UP
	mov	esi,H_UP_CAP
	sub	esi,[r15+H_UPLEN]
	mov	eax,[r15+H_UPLEN]
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_UP+rax]
	call	h_recv
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	stc
	ret
.ready:
	clc
	ret

; eax = the response body's bytes a call carries (0: none: no body, chunked,
; or more than `body` or the buffer holds), ecx = those in. Keeps rbx, r8-r15.
ad_rbody_want:
	mov	ecx,[r15+H_UPLEN]
	sub	ecx,[r14+ADSE_HSTART]
	sub	ecx,[r14+ADSE_RHLEN]
	xor	eax,eax
	test	dword [r15+H_FLAGS],HX_HEAD
	jnz	.out
	mov	edx,[g_hm+HM_STATUS]
	cmp	edx,204
	je	.out
	cmp	edx,304
	je	.out
	test	dword [g_hm+HM_FLAGS],HMF_CHUNKED
	jnz	.out
	mov	rdx,[g_hm+HM_LENGTH]
	cmp	rdx,-1
	je	.out
	imul	rax,r12,ADE_SIZE
	mov	eax,[g_addons+rax+ADE_BODY]
	mov	esi,H_UP_CAP
	sub	esi,[r14+ADSE_HSTART]
	sub	esi,[r14+ADSE_RHLEN]
	cmp	eax,esi
	jbe	@f
	mov	eax,esi
@@:
	cmp	rdx,rax
	ja	.none				; larger: not carried
	mov	eax,edx
.out:
	ret
.none:
	xor	eax,eax
	ret

; http_recv_plain, HS_ADRBODY: more of the response's body (rax)
addon_rbody_in:
	test	rax,rax
	jle	.short
	add	[r15+H_UPLEN],eax
	mov	edi,ebx
	call	idle_touch
	h_rec
	jmp	http_resp_again
.short:
	mov	edi,502				; the backend went before its body's end
	jmp	http_error

; r13 = the addon's state, r12d = the addon, r14 = the side entry, ebx, r15,
; g_hm = the response: the call into its ring: the response head, then the
; request's method and target, then the body when response_body carries it.
; CF: no room. Keeps rbx, r12-r15.
ad_post_resp:
	push	rbx
	push	r12
	push	r14
	mov	r8d,ADP_RESP_HEADERS
	xor	eax,eax
	imul	rdx,r12,ADE_SIZE
	test	dword [g_addons+rdx+ADE_PHASES],ADP_RESP_BODY
	jz	@f
	call	ad_rbody_want
	mov	r8d,ADP_RESP_BODY
	cmp	ecx,eax
	jae	@f
	xor	eax,eax
@@:
	mov	[g_ad_blen],eax			; the body carried
	mov	[g_ad_bflags],r8d		; (the phase, here)
	mov	r11,r14				; the side entry
	mov	r12d,[g_hm+HM_NHDR]
	lea	eax,[ADQ_INDEX+r12*8]
	add	eax,[r11+ADSE_RHLEN]
	add	eax,[r15+H_LMLEN]
	add	eax,[r15+H_LTLEN]
	add	eax,[g_ad_blen]
	add	eax,7
	and	eax,not 7
	mov	r10d,eax			; the record
	push	r11
	call	ad_ring_room			; rdi = where, rcx = the new head; CF: none
	pop	r11
	jc	.full
	push	rcx
	mov	[rdi+ADQ_LEN],r10d
	mov	word [rdi+ADQ_KIND],1
	mov	eax,[g_ad_bflags]
	mov	[rdi+ADQ_PHASE],ax
	mov	eax,[r13+ADW_SEQ]
	mov	[rdi+ADQ_ID],eax
	push	rdi
	push	r11
	call	ad_who				; eax = flags; the client into the record
	pop	r11
	pop	rdi
	mov	[rdi+ADQ_FLAGS],eax
	mov	eax,[r11+ADSE_RHLEN]
	mov	[rdi+ADQ_HLEN],eax
	mov	[rdi+ADQ_NHDR],r12w
	mov	edx,eax				; offsets past the head: method, target
	mov	[rdi+ADQ_METHOD],dx
	mov	ecx,[r15+H_LMLEN]
	mov	[rdi+ADQ_METHOD+2],cx
	add	edx,ecx
	mov	[rdi+ADQ_TARGET],dx
	mov	ecx,[r15+H_LTLEN]
	mov	[rdi+ADQ_TARGET+2],cx
	mov	eax,[r15+H_ACT]
	mov	[rdi+ADQ_ROUTE],eax
	mov	rax,[r15+H_LT0]			; (when its head was read: one request's)
	mov	[rdi+ADQ_STREAM],rax
	mov	eax,[r15+H_LMLEN]
	add	eax,[r15+H_LTLEN]
	add	eax,[g_ad_blen]
	mov	[rdi+ADQ_BLEN],eax
	; the index, from the head's start
	mov	rsi,[r15+H_BUF]
	mov	eax,[r11+ADSE_HSTART]
	lea	rsi,[rsi+HB_UP+rax]
	lea	r9,[g_hm+HM_HDRS]
	lea	r8,[rdi+ADQ_INDEX]
	mov	ecx,r12d
.field:
	test	ecx,ecx
	jz	.fields
	mov	rax,[r9+HF_NAME]
	sub	rax,rsi
	mov	[r8],ax
	mov	eax,[r9+HF_NLEN]
	mov	[r8+2],ax
	mov	rax,[r9+HF_VALUE]
	sub	rax,rsi
	mov	[r8+4],ax
	mov	eax,[r9+HF_VLEN]
	mov	[r8+6],ax
	add	r9,HF_SIZE
	add	r8,8
	dec	ecx
	jmp	.field
.fields:
	mov	rdi,r8
	push	rsi
	mov	ecx,[r11+ADSE_RHLEN]
	rep	movsb				; the head
	mov	rsi,[r15+H_BUF]
	lea	rsi,[rsi+HB_LTEXT_M]
	mov	ecx,[r15+H_LMLEN]
	rep	movsb				; the request's method
	mov	rsi,[r15+H_BUF]
	lea	rsi,[rsi+HB_LTEXT_T]
	mov	ecx,[r15+H_LTLEN]
	rep	movsb				; and target
	pop	rsi
	mov	eax,[r11+ADSE_RHLEN]
	add	rsi,rax
	mov	ecx,[g_ad_blen]
	rep	movsb				; the body after the head
	pop	rcx
	mov	[r13+ADW_HEAD],rcx
	mov	r14,[r13+ADW_REQ]
	mov	[r14+ADR_HEAD],rcx		; published
	clc
	jmp	.out
.full:
	stc
.out:
	pop	r14
	pop	r12
	pop	rbx
	ret

; r13 = the addon's state, r10d = a record's size: rdi = where it goes in the
; calls ring (a padding record first when it would not fit before the end),
; rcx = the head after it. CF: no room. Keeps rbx, r10, r12-r15.
ad_ring_room:
	mov	r9,[r13+ADW_REQ]
	mov	rcx,[r13+ADW_HEAD]
	mov	edx,ecx
	and	edx,AD_RING - 1
	mov	eax,AD_RING
	sub	eax,edx				; to the ring's end
	xor	r11d,r11d
	cmp	eax,r10d
	jae	@f
	mov	r11d,eax
@@:
	mov	rax,rcx
	sub	rax,[r9+ADR_TAIL]
	mov	r8d,AD_RING
	sub	r8,rax				; room
	lea	eax,[r10+r11]
	cmp	rax,r8
	ja	.full
	test	r11d,r11d
	jz	.at
	lea	rdi,[r9+ADR_CALLS+rdx]
	mov	[rdi+ADQ_LEN],r11d
	mov	dword [rdi+ADQ_KIND],0
	add	rcx,r11
	xor	edx,edx
.at:
	lea	rdi,[r9+ADR_CALLS+rdx]
	add	rcx,r10
	clc
	ret
.full:
	stc
	ret

; ebx, r15, rdi = a record: its client's address in it; eax = ADQF_* of the
; connection (TLS, HTTP/2, HTTP/3). Keeps rbx, rdi, r10-r15.
ad_who:
	call	session_ptr
	mov	edx,[rax+S_FLAGS]
	mov	ecx,[rax+S_LST]
	xor	eax,eax
	test	edx,SF_H2S
	jz	@f
	or	eax,ADQF_H2
@@:
	test	edx,SF_H3S
	jz	@f
	or	eax,ADQF_H3 or ADQF_TLS
@@:
	imul	rcx,rcx,LS_SIZE
	cmp	dword [g_listeners+rcx+LS_TLS],0
	je	@f
	or	eax,ADQF_TLS
@@:
	mov	ecx,[r15+H_CKIND]
	mov	[rdi+ADQ_FAMILY],cx
	mov	rcx,[r15+H_CLIENT]
	mov	[rdi+ADQ_CLIENT],rcx
	mov	rcx,[r15+H_CLIENT+8]
	mov	[rdi+ADQ_CLIENT+8],rcx
	ret

; --------------------------------------------------------------- the log

; an exchange is over (its access log line written): the route's addons with
; the log phase get what came of it, never waited for: a head of the request
; line, its host and okena-status, okena-bytes, okena-us fields. ebx, r15.
; Keeps all.
addon_log:
	cmp	qword [g_ad_side],0
	je	.none
	mov	[g_cur_log_sess],ebx
	push	rax
	mov	eax,[r15+H_ACT]
	test	eax,eax
	jz	.out
	dec	eax
	imul	rax,rax,RA_SIZE
	mov	eax,[g_acts+rax+RA_ADDONS]
	test	eax,eax
	jz	.out
	push	rbx
	push	rcx
	push	rdx
	push	rsi
	push	rdi
	push	r8
	push	r9
	push	r10
	push	r11
	push	r12
	push	r13
	push	r14
	mov	r14d,eax
.next:
	bsf	r12d,r14d
	jz	.done
	btr	r14d,r12d
	imul	rax,r12,ADE_SIZE
	test	dword [g_addons+rax+ADE_PHASES],ADP_LOG
	jz	.next
	imul	r13,r12,ADW_SIZE
	lea	r13,[g_aw+r13]
	cmp	dword [r13+ADW_LIVE],0
	je	.next
	mov	rax,[r13+ADW_HDR]
	cmp	dword [rax+ADH_READY],1
	jne	.next
	call	ad_post_log
	jmp	.next
.done:
	pop	r14
	pop	r13
	pop	r12
	pop	r11
	pop	r10
	pop	r9
	pop	r8
	pop	rdi
	pop	rsi
	pop	rdx
	pop	rcx
	pop	rbx
.out:
	pop	rax
.none:
	ret

; r13, ebx, r15: the log's record, built in g_ad_tmp, then into the ring
ad_post_log:
	lea	rdi,[g_ad_tmp]
	mov	rsi,[r15+H_BUF]
	lea	rsi,[rsi+HB_LTEXT_M]
	mov	ecx,[r15+H_LMLEN]
	rep	movsb
	mov	byte [rdi],' '
	inc	rdi
	mov	rsi,[r15+H_BUF]
	lea	rsi,[rsi+HB_LTEXT_T]
	mov	ecx,[r15+H_LTLEN]
	rep	movsb
	memit_x ' HTTP/1.1',13,10,'host: '
	mov	rsi,[r15+H_BUF]
	lea	rsi,[rsi+HB_LTEXT_H]
	mov	ecx,[r15+H_LHLEN]
	rep	movsb
	memit_x 13,10,'okena-status: '
	mov	eax,[r15+H_STATUS]
	call	fmt_u64
	memit_x 13,10,'okena-bytes: '
	mov	rax,[r15+H_XBYTES]
	call	fmt_u64
	memit_x 13,10,'okena-us: '
	xor	eax,eax
	mov	rcx,[g_tsc_per_us]
	test	rcx,rcx
	jz	@f
	cmp	qword [r15+H_LT0],0
	je	@f
	push	rdi
	rdtsc
	shl	rdx,32
	or	rax,rdx
	sub	rax,[r15+H_LT0]
	xor	edx,edx
	div	rcx
	pop	rdi
@@:
	call	fmt_u64
	memit_x 13,10,13,10
	lea	rax,[g_ad_tmp]
	sub	rdi,rax
	mov	ebx,edi				; its length (the session: g_cur_log_sess)
	; index it: the request line, then each "name: value" line
	xor	r12d,r12d			; fields
	lea	r8,[g_ad_tmp]
	lea	r9,[g_ad_log_ix]
.line:
	cmp	byte [r8],10
	je	.first_seen
	inc	r8
	jmp	.line
.first_seen:
	inc	r8
.field:
	cmp	byte [r8],13
	je	.indexed
	mov	rax,r8
	lea	rcx,[g_ad_tmp]
	sub	rax,rcx
	mov	[r9],ax				; name
	xor	edx,edx
@@:
	cmp	byte [r8+rdx],':'
	je	@f
	inc	edx
	jmp	@b
@@:
	mov	[r9+2],dx
	lea	rax,[rax+rdx+2]
	mov	[r9+4],ax			; value
	lea	r8,[r8+rdx+2]
	xor	edx,edx
@@:
	cmp	byte [r8+rdx],13
	je	@f
	inc	edx
	jmp	@b
@@:
	mov	[r9+6],dx
	lea	r8,[r8+rdx+2]
	add	r9,8
	inc	r12d
	jmp	.field
.indexed:
	lea	eax,[ADQ_INDEX+r12*8]
	add	eax,ebx
	add	eax,7
	and	eax,not 7
	mov	r10d,eax
	call	ad_ring_room
	jc	.full
	push	rcx
	mov	[rdi+ADQ_LEN],r10d
	mov	word [rdi+ADQ_KIND],1
	mov	word [rdi+ADQ_PHASE],ADP_LOG
	mov	dword [rdi+ADQ_ID],0
	mov	[rdi+ADQ_HLEN],ebx
	mov	[rdi+ADQ_NHDR],r12w
	mov	dword [rdi+ADQ_BLEN],0
	push	rdi
	push	rbx
	mov	ebx,[g_cur_log_sess]
	call	ad_who
	pop	rbx
	pop	rdi
	mov	[rdi+ADQ_FLAGS],eax
	mov	eax,[r15+H_ACT]
	mov	[rdi+ADQ_ROUTE],eax
	mov	rax,[r15+H_LT0]			; (when its head was read: one request's)
	mov	[rdi+ADQ_STREAM],rax
	mov	rsi,[r15+H_BUF]
	mov	eax,[r15+H_LMLEN]
	mov	dword [rdi+ADQ_METHOD],0
	mov	[rdi+ADQ_METHOD+2],ax
	inc	eax
	mov	[rdi+ADQ_TARGET],ax
	mov	eax,[r15+H_LTLEN]
	mov	[rdi+ADQ_TARGET+2],ax
	lea	rsi,[g_ad_log_ix]
	lea	rdi,[rdi+ADQ_INDEX]
	lea	ecx,[r12*8]
	rep	movsb
	lea	rsi,[g_ad_tmp]
	mov	ecx,ebx
	rep	movsb
	pop	rcx
	mov	[r13+ADW_HEAD],rcx
	mov	rax,[r13+ADW_REQ]
	mov	[rax+ADR_HEAD],rcx
	mov	dword [r13+ADW_DIRTY],1
	mov	ebx,[g_cur_log_sess]
	ret
.full:
	mov	rax,[r13+ADW_REQ]
	inc	qword [rax+ADR_COUNT+ADC_ERROR]
	mov	ebx,[g_cur_log_sess]
	ret
