; `concurrency N` / `concurrency adaptive [min=] [max=]` on a pool: how many
; requests may be at its servers at once, the instance's (shared out among
; the workers); past it a request is answered 503 at once, so a spike sheds at
; the edge instead of collapsing the backend. Adaptive is a gradient limiter
; (Netflix concurrency-limits' Gradient2, Envoy's adaptive concurrency): each
; second, from the time to the answer's head, limit = limit * clamp(2 *
; usual / now, 0.5, 1) + sqrt(limit), between min and max, where the usual time
; is a slow average of the seconds before (1/16 of each new one): the noise of
; a loaded host does not shrink it, a backend slowing down halves it each
; second, and one that became slower for good is its usual in time. In flight:
; this worker's connections in use to the pool.

CC_FIXED	:= 1
CC_ADAPTIVE	:= 2
CC_INITIAL	:= 32			; adaptive: the instance's limit to start from
CC_MIN		:= 4
CC_MAX		:= 1024

bss
	g_ccy_limit	rd MAX_POOLS		; this worker's limit, 0 not set yet
	g_ccy_n		rd MAX_POOLS		; answers timed this second
	g_ccy_best	rd MAX_POOLS		; µs: the usual time (a slow average), 0 none yet
	align 8
	g_ccy_sum	rq MAX_POOLS		; µs this second
end bss

; eax = the instance's, edi = pool: this worker's share, 1 at least. Keeps rdi.
cc_share:
	push	rcx
	push	rdx
	mov	ecx,[g_workers]
	test	ecx,ecx
	jnz	@f
	inc	ecx
@@:
	add	eax,ecx
	dec	eax
	xor	edx,edx
	div	ecx
	test	eax,eax
	jnz	@f
	inc	eax
@@:
	pop	rdx
	pop	rcx
	ret

; edi = pool: CF when a request may go to it now. Keeps all but rax.
cc_admit:
	cmp	edi,[g_plan_pools]
	jae	.yes
	push	rcx
	imul	rcx,rdi,PL_SIZE
	cmp	dword [g_pools+rcx+PL_CCMODE],0
	je	.yes_pop
	mov	eax,[g_ccy_limit+rdi*4]
	test	eax,eax
	jnz	.have
	mov	eax,[g_pools+rcx+PL_CCN]	; fixed: N; adaptive: where it starts
	call	cc_share
	mov	[g_ccy_limit+rdi*4],eax
.have:
	cmp	[g_pl_active+rdi*4],eax
	pop	rcx
	jb	.yes
	clc
	ret
.yes_pop:
	pop	rcx
.yes:
	stc
	ret

; edi = pool, esi = µs from the request sent to its answer's head
cc_observe:
	cmp	edi,[g_plan_pools]
	jae	.out
	imul	rax,rdi,PL_SIZE
	cmp	dword [g_pools+rax+PL_CCMODE],CC_ADAPTIVE
	jne	.out
	inc	dword [g_ccy_n+rdi*4]
	mov	eax,esi
	add	[g_ccy_sum+rdi*8],rax
.out:
	ret

; worker tick: each adaptive pool's limit, from this second's answers
cc_tick:
	push	rbx
	push	r12
	xor	ebx,ebx
.pool:
	cmp	ebx,[g_plan_pools]
	jae	.done
	imul	r12,rbx,PL_SIZE
	lea	r12,[g_pools+r12]
	cmp	dword [r12+PL_CCMODE],CC_ADAPTIVE
	jne	.next
	mov	ecx,[g_ccy_n+rbx*4]
	test	ecx,ecx
	jz	.next				; nothing timed: as it was
	mov	rax,[g_ccy_sum+rbx*8]
	xor	edx,edx
	div	rcx				; this second's time, µs
	mov	qword [g_ccy_sum+rbx*8],0
	mov	dword [g_ccy_n+rbx*4],0
	cmp	dword [g_ccy_limit+rbx*4],0
	je	.next				; (not used yet)
	test	rax,rax
	jnz	@f
	inc	eax
@@:
	mov	ecx,[g_ccy_best+rbx*4]		; the usual time, before this second
	test	ecx,ecx
	jnz	@f
	mov	ecx,eax
@@:
	mov	edx,eax				; and moved 1/16 toward this second's
	sub	edx,ecx
	sar	edx,4
	add	edx,ecx
	jnz	@f
	inc	edx
@@:
	mov	[g_ccy_best+rbx*4],edx
	; the gradient, in thousandths: 2 * usual / now, between 500 and 1000
	imul	rcx,rcx,2000
	xchg	rax,rcx
	xor	edx,edx
	div	rcx
	cmp	rax,500
	jae	@f
	mov	eax,500
@@:
	cmp	rax,1000
	jbe	@f
	mov	eax,1000
@@:
	mov	ecx,[g_ccy_limit+rbx*4]
	imul	rax,rcx
	xor	edx,edx
	mov	r8d,1000
	div	r8
	cvtsi2sd xmm0,rcx			; + sqrt(limit): room to find more
	sqrtsd	xmm0,xmm0
	cvttsd2si rdx,xmm0
	add	rax,rdx
	push	rax
	mov	edi,ebx
	mov	eax,[r12+PL_CCMIN]
	call	cc_share
	mov	r8d,eax
	mov	eax,[r12+PL_CCMAX]
	call	cc_share
	mov	r9d,eax
	pop	rax
	cmp	eax,r8d
	jae	@f
	mov	eax,r8d
@@:
	cmp	eax,r9d
	jbe	@f
	mov	eax,r9d
@@:
	mov	[g_ccy_limit+rbx*4],eax
.next:
	inc	ebx
	jmp	.pool
.done:
	pop	r12
	pop	rbx
	ret
