; Hedging: `hedge after=50ms max=1` (or `after=p95`) on a route: an idempotent
; request with no body that has no answer by then is sent again, to another
; server, and the first answer goes to the client. It cuts the tail a slow
; server gives: most requests never hedge.
;
; The second try is a session with no client, as for `mirror`. When its answer
; comes first the request drops its backend and what the copy writes goes out
; through it (HS_HEDGED), so nothing has to move between sessions with I/O in
; flight. An answer of 5xx does not win, nor does one after the request has
; started its own. Hedges spend the pool's retry budget, so a backend in trouble
; does not get twice the load, and the pool must have another server.
;
; after=pNN is that percentile of the pool's answers lately, in this worker: a
; histogram of about 19% steps, halved now and then. Until HL_MIN answers have
; been seen nothing is hedged.

SF_HEDGE	:= 524288			; S_FLAGS: a mirror session whose answer counts
SF_HSTRM	:= 1048576			; and its request is a stream (no chunks)

FD_HEDGE	:= 0x80000000			; FD_SESS: a hedge's time, not a held request

HL_N		:= 64
HL_MIN		:= 64
HL_HALVE	:= 4096

bss
	g_hl_n		rd MAX_POOLS
	g_hl:		rd MAX_POOLS * HL_N
end bss

; edi = pool, rsi = µs: one more answer
hl_observe:
	mov	rax,rsi
	cmp	rax,4
	jb	.bucket
	bsr	rcx,rax
	mov	rdx,rax
	sub	ecx,2
	shr	rdx,cl
	and	edx,3
	lea	eax,[rcx*4+rdx+4]
	cmp	eax,HL_N
	jb	.bucket
	mov	eax,HL_N - 1
.bucket:
	imul	ecx,edi,HL_N
	add	ecx,eax
	inc	dword [g_hl+rcx*4]
	inc	dword [g_hl_n+rdi*4]
	cmp	dword [g_hl_n+rdi*4],HL_HALVE
	jb	.out
	imul	ecx,edi,HL_N
	lea	rsi,[g_hl+rcx*4]
	mov	ecx,HL_N
	xor	edx,edx
.halve:
	mov	eax,[rsi]
	shr	eax,1
	mov	[rsi],eax
	add	edx,eax
	add	rsi,4
	dec	ecx
	jnz	.halve
	mov	[g_hl_n+rdi*4],edx
.out:
	ret

; edi = pool, esi = a percentile: rax = its µs, 0 when too few are known
hl_percentile:
	mov	eax,[g_hl_n+rdi*4]
	cmp	eax,HL_MIN
	jb	.none
	imul	eax,esi
	xor	edx,edx
	mov	ecx,100
	div	ecx
	mov	esi,eax				; how many are at or below it
	imul	ecx,edi,HL_N
	lea	r8,[g_hl+rcx*4]
	xor	ecx,ecx
	xor	edx,edx
.next:
	add	edx,[r8+rcx*4]
	cmp	edx,esi
	jae	.found
	inc	ecx
	cmp	ecx,HL_N
	jb	.next
	dec	ecx
.found:
	mov	eax,ecx
	cmp	ecx,4
	jb	.up				; (exact below 4 µs)
	; the bucket's top: (5 + its step) shl (its octave)
	mov	eax,ecx
	and	eax,3
	add	eax,5
	shr	ecx,2
	dec	ecx
	shl	rax,cl
	ret
.up:
	inc	eax
	ret
.none:
	xor	eax,eax
	ret

; ebx = session, r15 = record, r13d = its pool, rdi = the action: its hedge's
; time is set, if it is a request for it. Keeps r12-r15, rbx.
hedge_arm:
	mov	rax,[r15+H_BUF]
	mov	qword [rax+HB_HT0],0
	mov	dword [rax+HB_HLIVE],0
	mov	eax,[r15+H_FLAGS]
	and	eax,HX_NOBODY or HX_IDEMPOTENT or HX_UPGRADE
	cmp	eax,HX_NOBODY or HX_IDEMPOTENT
	jne	.none
	imul	rax,r13,PL_SIZE
	cmp	dword [g_pools+rax+PL_COUNT],2
	jb	.none
	cmp	dword [g_fd_n],FD_MAX
	jae	.none
	push	r12
	mov	r12,[rdi+RA_HAFTER]
	mov	esi,[rdi+RA_HPCT]
	test	esi,esi
	jz	.after
	mov	edi,r13d
	call	hl_percentile
	mov	r12,rax
.after:
	call	qs_clock
	mov	rax,[r15+H_BUF]
	mov	rcx,[g_qnow]
	mov	[rax+HB_HT0],rcx
	test	r12,r12
	jz	.out				; (not enough answers known yet)
	add	rcx,r12
	mov	[rax+HB_HDUE],rcx
	mov	eax,[g_fd_n]
	inc	dword [g_fd_n]
	shl	rax,4
	mov	[g_fd+rax+FD_AT],rcx
	mov	edx,ebx
	or	edx,FD_HEDGE
	mov	[g_fd+rax+FD_SESS],edx
	mov	rdx,[g_fd_next]
	test	rdx,rdx
	jz	.first
	cmp	rcx,rdx
	jae	.kept
.first:
	mov	[g_fd_next],rcx
.kept:
	push	rax
	call	session_ptr
	pop	rcx
	mov	eax,[rax+S_GEN]
	mov	[g_fd+rcx+FD_GEN],eax
	or	dword [r15+H_FLAGS],HX_HEDGEW
.out:
	pop	r12
.none:
	ret

; the time of a hedge: ebx = the request, r15 = its record, r9 = the time it was
; given, still its own?
hedge_fire:
	test	dword [r15+H_FLAGS],HX_HEDGEW
	jz	.none
	mov	rax,[r15+H_BUF]
	cmp	[rax+HB_HDUE],r9
	jne	.none
	test	dword [r15+H_FLAGS],HX_STARTED
	jnz	.none
	cmp	dword [g_mir_n],MIR_MAX
	jae	.none
	cmp	dword [g_fd_n],FD_MAX
	jae	.none
	push	r12
	call	session_ptr
	mov	r12,rax				; the request's session
	mov	edi,[r12+S_POOL]
	cmp	dword [g_retry_tokens+rdi*4],RETRY_COST
	jb	.out				; the pool's budget: no more load on it
	sub	dword [g_retry_tokens+rdi*4],RETRY_COST
	mov	esi,SF_HEDGE
	test	dword [r12+S_FLAGS],SF_H2S or SF_H3S
	jz	@f
	or	esi,SF_HSTRM
@@:
	mov	edx,[r15+H_FLAGS]
	and	edx,HX_CORS or HX_SPLIT
	or	edx,HX_HEDGE or HX_AVOID
	mov	r9d,[r15+H_INOFF]
	mov	r10d,r9d
	call	mirror_new
	cmp	eax,NIL
	je	.out
	; they know each other; what the answer's head needs comes along
	push	rbx
	mov	r8d,ebx
	mov	r9d,[r12+S_GEN]
	mov	r10d,[r12+S_SERVER]
	mov	rdx,r15
	mov	ebx,eax
	call	session_ptr
	mov	[rax+S_SERVER],r10d		; (HX_AVOID: not that one again)
	mov	r11d,[rax+S_GEN]
	h_rec
	mov	rcx,[r15+H_BUF]
	mov	[rcx+HB_HPS],r8d
	mov	[rcx+HB_HPG],r9d
	mov	rsi,[g_qnow]
	mov	[rcx+HB_HT0],rsi
	mov	eax,[rdx+H_RIDLEN]
	mov	[r15+H_RIDLEN],eax
	lea	rsi,[rdx+H_RID]
	lea	rdi,[r15+H_RID]
	mov	ecx,eax
	rep	movsb
	mov	rsi,[rdx+H_BUF]
	mov	rdi,[r15+H_BUF]
	lea	rsi,[rsi+HB_CORS]
	lea	rdi,[rdi+HB_CORS]
	mov	ecx,HB_MIRS - HB_CORS		; the origin let in, the split's number
	rep	movsb
	mov	rax,[rdx+H_BUF]
	mov	[rax+HB_MIRS],ebx		; the request finds its copy
	mov	[rax+HB_MIRG],r11d
	mov	dword [rax+HB_HLIVE],1
	mov	r15,rdx
	pop	rbx
.out:
	pop	r12
.none:
	ret

; ebx = a session, ecx = the generation it had: ZF when it is still that one
hedge_alive:
	call	session_ptr
	cmp	[rax+S_GEN],ecx
	jne	.out
	cmp	dword [rax+S_STATE],ST_OPEN
.out:
	ret

; an answer's head has come, on a hedged request or its copy (r15 = record):
; its time goes in the histogram; the request's own answer ends the race
hedge_answer:
	mov	eax,[r15+H_ACT]
	test	eax,eax
	jz	.none
	dec	eax
	imul	rax,rax,RA_SIZE
	mov	rcx,[g_acts+rax+RA_HAFTER]
	or	ecx,[g_acts+rax+RA_HPCT]
	jz	.none
	mov	rax,[r15+H_BUF]
	cmp	qword [rax+HB_HT0],0
	je	.none				; (not one that is timed)
	push	r12
	call	qs_clock
	mov	r12,[r15+H_BUF]
	mov	rsi,[g_qnow]
	sub	rsi,[r12+HB_HT0]
	mov	qword [r12+HB_HT0],0
	call	session_ptr
	mov	edi,[rax+S_POOL]
	call	hl_observe
	test	dword [r15+H_FLAGS],HX_HEDGEW
	jz	.out
	btr	dword [r15+H_FLAGS],31
	cmp	dword [r12+HB_HLIVE],0
	je	.out
	mov	dword [r12+HB_HLIVE],0
	push	rbx
	mov	ecx,[r12+HB_MIRG]
	mov	ebx,[r12+HB_MIRS]
	call	hedge_alive
	jne	@f
	mov	edi,ebx				; it lost: gone, its backend's work cut
	call	session_close
@@:
	pop	rbx
	h_rec
.out:
	pop	r12
.none:
	ret

; h_send of a copy that may win: ebx = it, rdi = bytes, esi = how many
hedge_send:
	h_rec
	mov	rax,[r15+H_BUF]
	mov	r8d,[rax+HB_HPS]
	mov	ecx,[rax+HB_HPG]
	test	dword [r15+H_FLAGS],HX_HWON
	jnz	.relay
	; the first bytes: does it win?
	cmp	dword [r15+H_STATUS],500
	jae	.lost
	push	rbx
	mov	ebx,r8d
	call	hedge_alive
	pop	rbx
	jne	.lost
	mov	r9d,r8d
	shl	r9,H_SHIFT
	add	r9,[g_http_base]
	test	dword [r9+H_FLAGS],HX_STARTED
	jnz	.lost
	test	dword [r9+H_FLAGS],HX_HEDGEW
	jz	.lost
	; it does: the request lets go of its backend, its client hears this
	or	dword [r15+H_FLAGS],HX_HWON
	mov	eax,[r15+H_STATUS]
	push	rdi
	push	rsi
	push	rbx
	push	r8
	mov	ebx,r8d
	mov	r15,r9
	mov	[r15+H_STATUS],eax
	or	dword [r15+H_FLAGS],HX_STARTED
	btr	dword [r15+H_FLAGS],31
	and	dword [r15+H_FLAGS],not HX_UPKEEP
	mov	dword [r15+H_STATE],HS_HEDGED
	mov	edi,ebx
	call	ph_disarm
	call	h_upclose
	pop	r8
	pop	rbx
	pop	rsi
	pop	rdi
.relay:
	mov	ebx,r8d
	mov	ecx,SIDE_CLIENT
	jmp	h_send
.lost:
	mov	edi,ebx
	jmp	session_close

; the request's bytes went to its client: ebx = the request, in HS_HEDGED; its
; copy goes on
hedge_sent:
	mov	rax,[r15+H_BUF]
	mov	ecx,[rax+HB_MIRG]
	mov	ebx,[rax+HB_MIRS]
	call	hedge_alive
	jne	.out
	xor	eax,eax
	mov	edx,2
	xor	ecx,ecx
	jmp	hep_queue
.out:
	ret

; a copy's answer is over: ebx = it, r15 = its record
hedge_done:
	test	dword [r15+H_FLAGS],HX_HWON
	jz	.close
	mov	rax,[r15+H_BUF]
	mov	r12d,[rax+HB_HPS]
	mov	r13d,[rax+HB_HPG]
	mov	edi,ebx
	call	session_close
	mov	ebx,r12d
	mov	ecx,r13d
	call	hedge_alive
	jne	.out
	jmp	http_exchange_done		; the request's exchange is over with it
.close:
	mov	edi,ebx
	jmp	session_close
.out:
	ret
