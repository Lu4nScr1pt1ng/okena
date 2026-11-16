; `limit_rate RATE [after=SIZE]` on a route: its answers go out at RATE bytes
; a second, the first `after` bytes at once (nginx's limit_rate and
; limit_rate_after): downloads that share a link, or a client that would take
; all of one.
;
; Every piece of a body the pump writes is weighed first (pace_check): when it
; would put the answer ahead of its rate, the session waits on a timing wheel
; (1024 slots of a millisecond, one list a slot: a wait and a wake are each
; O(1), however many answers are paced) and the piece goes when its time
; comes. Such answers go through the pump, never the zero-copy paths (their
; bytes would leave at the link's speed). The engines' wait is bounded by the
; wheel's next slot. A worker with nothing paced pays nothing; routes without
; limit_rate pay one compare a piece.
;
; On a tcp listener, `limit_rate RATE [upload=RATE] [after=SIZE]`: each
; direction a clock of its own, in microseconds, of when its bytes so far may
; have gone (the time it was idle is not saved up); its next read waits on the
; same wheel until then, and reads at most a sixteenth of a second's worth.
; Such directions are not moved by bulk.inc's loop. A session has two records:
; 2 * session + direction (0 the client's bytes, 1 the upstream's; an HTTP
; exchange's: 0).

PW_N		:= 1024
PC_PTR		:= 0				; q: the piece that waits
PC_LEN		:= 8				; d
PC_GEN		:= 12				; d: the session's generation then
PC_PREV		:= 16				; d: in its slot's list, NIL none
PC_NEXT		:= 20				; d
PC_SLOT		:= 24				; d: -1 not on the wheel
PC_B0		:= 28				; d: bytes sent when the pacing began (H_XBYTES, low)
PC_T0		:= 32				; q: g_now_ms then
PC_X		:= 40				; q: the exchange it is of (H_LT0)
PC_KIND		:= 48				; b: 0 an HTTP answer, 1 a tcp direction
PC_FREE		:= PC_T0			; q: tcp: us, when its bytes so far may have gone
PC_SENT		:= PC_X				; q: tcp: its bytes so far (for after=)
PC_SHIFT	:= 6
HS_PACED	:= 54				; (H_STATE: a piece waits on the wheel)

bss
	align 8
	g_pc_base	dq ?
	g_pc_due	dq ?			; ms: the wheel's next slot with someone, 0 none
	g_pw_ms		dq ?			; ms: the last slot run
	g_pc_n		dd ?			; sessions on the wheel
	g_plan_pace	dd ?			; some route says limit_rate
	g_pw_head	rd PW_N
	g_ls_rate	rd MAX_LISTENERS * 2	; tcp: bytes a second, the client's, the upstream's (0 free)
	g_ls_rafter	rd MAX_LISTENERS	; tcp: after=
	g_ls_rcap	rd MAX_LISTENERS * 2	; tcp: a read's most, 0 any
end bss

; Worker: the side table and the wheel, when some route paces. eax = 0 or -errno.
pace_worker_init:
	xor	eax,eax
	cmp	dword [g_plan_pace],0
	je	.done
	xor	ecx,ecx
@@:
	mov	dword [g_pw_head+rcx*4],NIL
	inc	ecx
	cmp	ecx,PW_N
	jb	@b
	xor	edi,edi
	mov	esi,[g_sessions]
	shl	rsi,PC_SHIFT + 1		; (two a session)
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.done
	mov	[g_pc_base],rax
	; every record off the wheel (a fresh mapping is zeros: slot 0 is a slot)
	mov	ecx,[g_sessions]
	add	ecx,ecx
	mov	rdx,rax
@@:
	mov	dword [rdx+PC_SLOT],-1
	add	rdx,1 shl PC_SHIFT
	dec	ecx
	jnz	@b
	xor	eax,eax
.done:
	ret

; ebx = session, r15 = record, rdi/esi = a piece of its answer about to go:
; CF when its route paces it and it has to wait (it waits: nothing to do but
; return). Keeps all but rax, rcx, rdx when it goes (NC).
pace_check:
	mov	eax,[r15+H_ACT]
	test	eax,eax
	jz	.go
	dec	eax
	imul	rax,rax,RA_SIZE
	cmp	dword [g_acts+rax+RA_RATE],0
	je	.go
	cmp	qword [g_pc_base],0
	je	.go
	push	r8
	push	r9
	lea	r9,[g_acts+rax]			; the route
	mov	r8d,ebx
	shl	r8,PC_SHIFT + 1
	add	r8,[g_pc_base]
	; this exchange's start
	mov	rax,[r15+H_LT0]
	cmp	byte [r8+PC_KIND],0
	jne	.fresh				; (a tcp session's before)
	cmp	rax,[r8+PC_X]
	je	@f
.fresh:
	mov	byte [r8+PC_KIND],0
	mov	[r8+PC_X],rax
	mov	rax,[g_now_ms]
	mov	[r8+PC_T0],rax
	mov	eax,dword [r15+H_XBYTES]
	mov	[r8+PC_B0],eax
@@:
	; its bytes past after=, with this piece: when they may have gone
	mov	eax,dword [r15+H_XBYTES]
	sub	eax,[r8+PC_B0]
	add	eax,esi
	sub	eax,[r9+RA_RATEAFTER]
	jbe	.go_pop
	imul	rax,rax,1000
	xor	edx,edx
	mov	ecx,[r9+RA_RATE]
	div	rcx				; ms after the start
	add	rax,[r8+PC_T0]
	cmp	rax,[g_now_ms]
	jbe	.go_pop
	; not yet: on the wheel
	mov	[r8+PC_PTR],rdi
	mov	[r8+PC_LEN],esi
	call	session_ptr
	mov	ecx,[rax+S_GEN]
	mov	[r8+PC_GEN],ecx
	mov	rax,[r8+PC_T0]			; (recomputed: the due ms)
	mov	eax,dword [r15+H_XBYTES]
	sub	eax,[r8+PC_B0]
	add	eax,esi
	sub	eax,[r9+RA_RATEAFTER]
	imul	rax,rax,1000
	xor	edx,edx
	mov	ecx,[r9+RA_RATE]
	div	rcx
	add	rax,[r8+PC_T0]
	call	pace_park			; rax = due ms, r8 = record
	mov	dword [r15+H_STATE],HS_PACED
	pop	r9
	pop	r8
	stc
	ret
.go_pop:
	pop	r9
	pop	r8
.go:
	clc
	ret

; rax = due ms, r8 = a record (its index its link): on the wheel (off it first,
; should a stale link of an earlier session in this slot remain).
pace_park:
	push	rax
	call	pace_unlink
	pop	rax
	push	r10
	mov	r10,r8				; its link: its index
	sub	r10,[g_pc_base]
	shr	r10,PC_SHIFT
	cmp	qword [g_pw_ms],0
	jne	@f
	mov	rcx,[g_now_ms]
	mov	[g_pw_ms],rcx
@@:
	mov	rcx,[g_pw_ms]
	lea	rdx,[rcx+1]
	cmp	rax,rdx
	jae	@f
	mov	rax,rdx				; (due now: the next slot)
@@:
	add	rcx,PW_N - 1
	cmp	rax,rcx
	jbe	@f
	mov	rax,rcx				; (beyond the wheel: its last slot, looked at again then)
@@:
	mov	rcx,[g_pc_due]
	test	rcx,rcx
	jz	.earliest
	cmp	rax,rcx
	jae	@f
.earliest:
	mov	[g_pc_due],rax
@@:
	and	eax,PW_N - 1
	mov	[r8+PC_SLOT],eax
	mov	dword [r8+PC_PREV],NIL
	mov	ecx,[g_pw_head+rax*4]
	mov	[r8+PC_NEXT],ecx
	cmp	ecx,NIL
	je	@f
	shl	rcx,PC_SHIFT
	add	rcx,[g_pc_base]
	mov	[rcx+PC_PREV],r10d
@@:
	mov	[g_pw_head+rax*4],r10d
	inc	dword [g_pc_n]
	pop	r10
	ret

; r8 = a session's record (ebx): off the wheel, if on it. Keeps all but rax, rcx, rdx.
pace_unlink:
	mov	eax,[r8+PC_SLOT]
	cmp	eax,-1
	je	.out
	mov	dword [r8+PC_SLOT],-1
	dec	dword [g_pc_n]
	mov	ecx,[r8+PC_PREV]
	mov	edx,[r8+PC_NEXT]
	cmp	ecx,NIL
	jne	@f
	mov	[g_pw_head+rax*4],edx
	jmp	.next
@@:
	shl	rcx,PC_SHIFT
	add	rcx,[g_pc_base]
	mov	[rcx+PC_NEXT],edx
	mov	ecx,[r8+PC_PREV]
.next:
	cmp	edx,NIL
	je	.out
	shl	rdx,PC_SHIFT
	add	rdx,[g_pc_base]
	mov	[rdx+PC_PREV],ecx
.out:
	ret

; Every turn of the loop (both engines, after the clock): the slots whose
; time came, their pieces sent (or, early from the wheel's end, parked again).
pace_run:
	cmp	dword [g_pc_n],0
	je	.none
	mov	rax,[g_pc_due]
	cmp	rax,[g_now_ms]
	ja	.none
	push	rbx
	push	r12
	push	r13
	push	r15
	mov	r12,[g_pw_ms]
	mov	r13,[g_now_ms]
	mov	rax,r13				; at most the wheel once round
	sub	rax,r12
	cmp	rax,PW_N
	jbe	.slot
	lea	r12,[r13-PW_N]
.slot:
	cmp	r12,r13
	jae	.ran
	inc	r12
	mov	[g_pw_ms],r12			; (one parked again goes past this slot)
	mov	eax,r12d
	and	eax,PW_N - 1
.take:
	mov	ebx,[g_pw_head+rax*4]
	cmp	ebx,NIL
	je	.slot
	push	rax
	mov	r8d,ebx
	shl	r8,PC_SHIFT
	add	r8,[g_pc_base]
	call	pace_unlink
	mov	esi,ebx
	and	esi,1				; (the direction)
	shr	ebx,1				; the session
	cmp	byte [r8+PC_KIND],0
	jne	.l4
	call	pace_wake
	jmp	.woke
.l4:
	call	pace_l4_wake
.woke:
	mov	r12,[g_pw_ms]
	mov	r13,[g_now_ms]
	pop	rax
	jmp	.take
.ran:
	mov	[g_pw_ms],r13
	; the next slot with someone
	mov	qword [g_pc_due],0
	cmp	dword [g_pc_n],0
	je	.out
	lea	rcx,[r13+1]
	lea	rdx,[r13+PW_N]
.find:
	cmp	rcx,rdx
	ja	.out
	mov	eax,ecx
	and	eax,PW_N - 1
	cmp	dword [g_pw_head+rax*4],NIL
	jne	.found
	inc	rcx
	jmp	.find
.found:
	mov	[g_pc_due],rcx
.out:
	pop	r15
	pop	r13
	pop	r12
	pop	rbx
.none:
	ret

; ebx = a session off the wheel, r8 = its record: its piece, if it still
; waits (the same session, the same state).
pace_wake:
	call	session_ptr
	mov	ecx,[rax+S_GEN]
	cmp	ecx,[r8+PC_GEN]
	jne	.out
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.out
	h_rec
	cmp	dword [r15+H_STATE],HS_PACED
	jne	.out
	mov	rdi,[r8+PC_PTR]
	mov	esi,[r8+PC_LEN]
	call	pace_check			; (early, from the wheel's end: again)
	jc	.out
	mov	dword [r15+H_STATE],HS_RESP_SEND
	mov	ecx,SIDE_CLIENT
	call	h_send
.out:
	ret

; r15 = record: CF when its route paces its answers. Keeps all but rax.
pace_route:
	mov	eax,[r15+H_ACT]
	test	eax,eax
	jz	.no
	dec	eax
	imul	rax,rax,RA_SIZE
	cmp	dword [g_acts+rax+RA_RATE],0
	je	.no
	stc
	ret
.no:
	clc
	ret

; ebx = a tcp session, esi = a direction (0 the client's bytes, 1 the
; upstream's), ecx = its listener, rax = bytes just read: its clock on.
; Keeps all but rax, rcx, rdx.
pace_l4_note:
	lea	rdx,[rcx*2+rsi]
	mov	edx,[g_ls_rate+rdx*4]
	test	edx,edx
	jz	.out
	cmp	qword [g_pc_base],0
	je	.out
	push	r8
	push	r9
	push	r10
	push	r11
	mov	r9d,edx				; the rate
	mov	r10,rax				; the bytes
	mov	r11d,[g_ls_rafter+rcx*4]
	mov	r8d,ebx
	lea	r8,[r8*2+rsi]
	shl	r8,PC_SHIFT
	add	r8,[g_pc_base]
	call	session_ptr
	mov	ecx,[rax+S_GEN]
	cmp	byte [r8+PC_KIND],1
	jne	.fresh
	cmp	ecx,[r8+PC_GEN]
	je	.known
.fresh:						; (this session's first)
	mov	byte [r8+PC_KIND],1
	mov	[r8+PC_GEN],ecx
	mov	qword [r8+PC_FREE],0
	mov	qword [r8+PC_SENT],0
.known:
	mov	rax,[r8+PC_SENT]
	add	rax,r10
	mov	[r8+PC_SENT],rax
	sub	rax,r11				; past after=
	jbe	.done
	cmp	rax,r10
	cmova	rax,r10
	imul	rax,rax,1000000
	xor	edx,edx
	div	r9				; us
	mov	rcx,[g_now_ms]
	imul	rcx,rcx,1000
	cmp	rcx,[r8+PC_FREE]
	jb	@f
	mov	[r8+PC_FREE],rcx		; (idle time is not saved up)
@@:
	add	[r8+PC_FREE],rax
.done:
	pop	r11
	pop	r10
	pop	r9
	pop	r8
.out:
	ret

; ebx = a tcp session, esi = a direction, about to read: CF when it waits
; (on the wheel; pace_l4_wake reads when it is time). Keeps all but rax, rcx, rdx.
pace_l4_wait:
	call	session_ptr
	mov	ecx,[rax+S_LST]
	lea	rcx,[rcx*2+rsi]
	cmp	dword [g_ls_rate+rcx*4],0
	je	.go
	cmp	qword [g_pc_base],0
	je	.go
	push	r8
	mov	r8d,ebx
	lea	r8,[r8*2+rsi]
	shl	r8,PC_SHIFT
	add	r8,[g_pc_base]
	cmp	byte [r8+PC_KIND],1
	jne	.go_pop
	mov	ecx,[rax+S_GEN]
	cmp	ecx,[r8+PC_GEN]
	jne	.go_pop				; (nothing read yet)
	mov	rax,[r8+PC_FREE]
	add	rax,999
	xor	edx,edx
	mov	ecx,1000
	div	rcx				; its due ms
	cmp	rax,[g_now_ms]
	jbe	.go_pop
	call	pace_park
	pop	r8
	stc
	ret
.go_pop:
	pop	r8
.go:
	clc
	ret

; ebx = a tcp session, esi = its direction, r8 = the record, off the wheel:
; its next read, if the session and the direction are still there.
pace_l4_wake:
	call	session_ptr
	mov	ecx,[rax+S_GEN]
	cmp	ecx,[r8+PC_GEN]
	jne	.out
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.out
	mov	ecx,SF_C_EOF
	test	esi,esi
	jz	@f
	mov	ecx,SF_U_EOF
@@:
	test	[rax+S_FLAGS],ecx
	jnz	.out
	mov	edi,ebx
	cmp	dword [g_engine],ENGINE_EPOLL
	je	.epoll
	test	esi,esi
	jz	post_recv_c
	jmp	post_recv_u
.epoll:
	mov	eax,EK_CLIENT
	test	esi,esi
	jz	@f
	mov	eax,EK_UPSTREAM
@@:
	mov	esi,eax
	jmp	ep_pump
.out:
	ret
