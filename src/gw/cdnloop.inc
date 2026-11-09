; `okena { cdn_loop NAME [max=N] }` (RFC 8586): what okena calls itself in
; CDN-Loop. Every request to a backend says it, after what the request said there
; already; a request that comes saying it N times (3 by default) has gone round in
; circles (edges, shields, an origin pointed back at the edges) and gets 508 Loop
; Detected instead of going round once more.

bss
	align 8
	g_plan_cdnl	dq ?			; the name, 0 none
	g_plan_cdnll	dd ?
	g_plan_cdnmax	dd ?
end bss

; g_hm = a request: CF when it has been through okena's name max times or more.
; Keeps rbx, r12-r15.
cdnloop_check:
	cmp	qword [g_plan_cdnl],0
	je	.no
	push	rbx
	push	r12
	push	r13
	push	r14
	xor	r13d,r13d			; times
	xor	ebx,ebx
.field:
	cmp	ebx,[g_hm+HM_NHDR]
	jae	.counted
	imul	r12,rbx,HF_SIZE
	lea	r12,[g_hm+HM_HDRS+r12]
	inc	ebx
	cmp	dword [r12+HF_NLEN],8
	jne	.field
	mov	rdi,[r12+HF_NAME]
	lea	rsi,[.n]
	mov	edx,8
	call	mem_eq_nocase
	test	eax,eax
	jz	.field
	; its members: a cdn-id, then ;parameters, commas between
	mov	rsi,[r12+HF_VALUE]
	mov	eax,[r12+HF_VLEN]
	lea	r14,[rsi+rax]
.member:
	cmp	rsi,r14
	jae	.field
	cmp	byte [rsi],' '
	je	.sp
	cmp	byte [rsi],','
	jne	.id
.sp:
	inc	rsi
	jmp	.member
.id:
	mov	rdi,rsi
@@:
	cmp	rsi,r14
	jae	@f
	mov	al,[rsi]
	cmp	al,';'
	je	@f
	cmp	al,','
	je	@f
	cmp	al,' '
	je	@f
	inc	rsi
	jmp	@b
@@:
	mov	rcx,rsi
	sub	rcx,rdi
	cmp	ecx,[g_plan_cdnll]
	jne	.rest
	push	rsi
	mov	rsi,[g_plan_cdnl]
	mov	edx,ecx
	call	mem_eq_nocase
	pop	rsi
	add	r13d,eax
.rest:
	cmp	rsi,r14
	jae	.field
	cmp	byte [rsi],','
	je	.member
	inc	rsi
	jmp	.rest
.counted:
	cmp	r13d,[g_plan_cdnmax]
	cmc					; CF when times >= max
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
.no:
	clc
	ret
.n	db 'cdn-loop'

; the request to a backend, rdi = output: CDN-Loop: NAME. Keeps rbx, r12-r15.
cdnloop_emit:
	cmp	qword [g_plan_cdnl],0
	je	.none
	memit_x 'CDN-Loop: '
	mov	rsi,[g_plan_cdnl]
	mov	ecx,[g_plan_cdnll]
	rep	movsb
	memit_x 13,10
.none:
	ret

; okena { cdn_loop NAME [max=N] }, rbx = the node
compile_cdnloop:
	mov	rax,[rbx+N_ARGS]
	mov	rcx,[rax+A_VAL]
	mov	edx,[rax+A_VLEN]
	test	edx,edx
	jz	.bad
	cmp	edx,64
	ja	.bad
	; a token: no space, comma, semicolon
	xor	esi,esi
@@:
	movzx	eax,byte [rcx+rsi]
	cmp	al,' '
	jbe	.bad
	cmp	al,','
	je	.bad
	cmp	al,';'
	je	.bad
	cmp	al,0x7F
	jae	.bad
	inc	esi
	cmp	esi,edx
	jb	@b
	mov	[g_plan_cdnl],rcx
	mov	[g_plan_cdnll],edx
	mov	dword [g_plan_cdnmax],3
	mov	rdi,rbx
	cstring .k_max, 'max',0
	lea	rsi,[.k_max]
	call	node_option
	test	rax,rax
	jz	.ok
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_decimal
	jc	.bad
	cmp	eax,1
	jb	.bad
	cmp	eax,64
	ja	.bad
	mov	[g_plan_cdnmax],eax
.ok:
	ret
.bad:
	call	log_begin
	out_lit 'cdn_loop takes a name (a token: no spaces, commas or semicolons; 64 bytes at most), and max= from 1 to 64'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
