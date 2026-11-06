; The overload manager: each worker knows how hard it is pressed, a level from 0
; to 4, looked at once a tick, and answers in steps, each undone as it eases:
;
;   1  idle connections go sooner (idle_expire, by the listener's own pressure)
;   2  responses say `Connection: close`: slots come back
;   3  `priority bulk` routes are refused, 503 and Retry-After
;   4  so are normal ones: only `priority critical` gets through
;
; Two things press it: how full a listener's sessions are, and how late the tick
; comes, which is how far behind the loop is (it costs nothing per request). The
; level rises at once and falls one step at a time, after OV_HOLD quiet ticks and
; a little below where it rose: no flapping at a threshold.

OV_HOLD		:= 3

RP_NORMAL	:= 0
RP_CRITICAL	:= 1
RP_BULK		:= 2

bss
	g_overload	dd ?			; the level
	g_ov_calm	dd ?			; ticks below it
	align 8
	g_ov_last	dq ?			; µs of the last tick
end bss

; once a tick
overload_tick:
	push	rbx
	push	r12
	call	qs_clock
	mov	rax,[g_qnow]
	mov	rcx,rax
	xchg	rax,[g_ov_last]
	xor	ebx,ebx				; the level things ask for
	test	rax,rax
	jz	.sessions
	sub	rcx,rax				; a tick apart: its lateness
	sub	rcx,1000000
	jle	.sessions
	mov	eax,1
	cmp	rcx,50000
	cmovae	ebx,eax
	mov	eax,2
	cmp	rcx,100000
	cmovae	ebx,eax
	mov	eax,3
	cmp	rcx,250000
	cmovae	ebx,eax
	mov	eax,4
	cmp	rcx,1000000
	cmovae	ebx,eax
.sessions:
	; the fullest listener; 5 points less to stay up than to get there
	xor	r8d,r8d				; its percent
	xor	r12d,r12d
.listener:
	cmp	r12d,[g_plan_listeners]
	jae	.fullest
	mov	ecx,[g_ls_cap+r12*4]
	test	ecx,ecx
	jz	.next
	mov	eax,[g_ls_active+r12*4]
	imul	eax,eax,100
	xor	edx,edx
	div	ecx
	cmp	eax,r8d
	cmova	r8d,eax
.next:
	inc	r12d
	jmp	.listener
.fullest:
	; what they ask for, and what is enough to stay where it is
	mov	eax,r8d
	call	.level_of
	mov	r9d,ecx
	lea	eax,[r8+5]
	call	.level_of			; (5 points less to stay than to get there)
	cmp	ecx,[g_overload]
	cmova	ecx,[g_overload]
	cmp	ecx,r9d
	cmovb	ecx,r9d
	cmp	ecx,ebx
	cmovb	ecx,ebx
	mov	eax,[g_overload]
	cmp	ecx,eax
	jae	.rise
	; lower: one step, after a while
	inc	dword [g_ov_calm]
	cmp	dword [g_ov_calm],OV_HOLD
	jb	.out
	lea	ecx,[rax-1]
	jmp	.set
.rise:
	mov	dword [g_ov_calm],0
	je	.out
.set:
	mov	dword [g_ov_calm],0
	mov	[g_overload],ecx
	mov	ebx,ecx
	call	log_begin
	out_lit 'overload: worker '
	mov	eax,[g_worker_id]
	call	out_u64
	out_lit ' at level '
	mov	eax,ebx
	call	out_u64
	call	log_end
.out:
	pop	r12
	pop	rbx
	ret

.level_of:
	xor	ecx,ecx
	cmp	eax,80
	jb	.level
	inc	ecx
	cmp	eax,85
	jb	.level
	inc	ecx
	cmp	eax,90
	jb	.level
	inc	ecx
	cmp	eax,97
	jb	.level
	inc	ecx
.level:
	ret

; edx = H_ACT (the action + 1, 0 none), g_overload >= 3: CF to refuse the request
overload_refuses:
	xor	eax,eax
	test	edx,edx
	jz	.prio
	dec	edx
	imul	rdx,rdx,RA_SIZE
	mov	eax,[g_acts+rdx+RA_PRIO]
.prio:
	cmp	eax,RP_CRITICAL
	je	.pass
	cmp	eax,RP_BULK
	je	.refuse				; (3 and up)
	cmp	dword [g_overload],4
	jae	.refuse
.pass:
	clc
	ret
.refuse:
	stc
	ret
