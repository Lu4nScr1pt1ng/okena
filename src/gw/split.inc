; Traffic splitting on a route: `split api=95% canary=5% sticky=cookie:NAME`.
;
; A request gets a number from 0 to 99 and goes to the pool whose share covers
; it. Without `sticky=` the number is new each time. With `sticky=cookie:NAME` a
; client without the cookie is given its number in one, and the number itself is
; what the cookie holds: raising a canary from 5% to 10% then leaves everyone in
; it where they are, and only moves the next 5%. A hash of pools would shuffle
; them all. A cookie that is not such a number, and `sticky=header:NAME`, are
; hashed, with no seed: the same value lands the same after a restart. A client
; can choose its pool with the cookie: this is no security boundary.

SL_N		:= 0				; d: pools
SL_KIND		:= 4				; d: SK_*
SL_NAME		:= 8				; q: the cookie's or header's name
SL_NLEN		:= 16				; d
SL_P		:= 20				; SL_MAX of (pool d, shares up to here d)
SL_MAX		:= 8
SL_SIZE		:= SL_P + SL_MAX * 8
MAX_SPLITS	:= 16384
SK_NONE		:= 0
SK_COOKIE	:= 1
SK_HEADER	:= 2

; edi = the entry + 1, g_hm = the request, r15 = record: eax = the pool
split_pick:
	push	r12
	dec	edi
	imul	r12,rdi,SL_SIZE
	lea	r12,[g_splits+r12]
	mov	eax,[r12+SL_KIND]
	cmp	eax,SK_HEADER
	je	.header
	cmp	eax,SK_COOKIE
	jne	.random
	lea	rdi,[.n_cookie]
	mov	esi,6
	call	limit_find
	test	ecx,ecx
	jz	.give
	lea	rdx,[rsi+rcx]
	mov	rdi,[r12+SL_NAME]
	mov	ecx,[r12+SL_NLEN]
	mov	r8b,';'
	call	limit_field
	test	ecx,ecx
	jz	.give
	; its number, when it is one we gave
	cmp	ecx,2
	ja	.hash
	xor	eax,eax
	xor	edx,edx
.digit:
	cmp	edx,ecx
	jae	.have
	movzx	r8d,byte [rsi+rdx]
	sub	r8d,'0'
	cmp	r8d,9
	ja	.hash
	imul	eax,eax,10
	add	eax,r8d
	inc	edx
	jmp	.digit
.header:
	mov	rdi,[r12+SL_NAME]
	mov	esi,[r12+SL_NLEN]
	call	limit_find
	test	ecx,ecx
	jz	.random
.hash:
	mov	rax,0x9E3779B97F4A7C15
	call	limit_mix
	shr	rax,20
	xor	edx,edx
	mov	ecx,100
	div	rcx
	mov	eax,edx
	jmp	.have
.give:
	call	.number
	mov	rcx,[r15+H_BUF]
	mov	[rcx+HB_SPLIT],eax
	or	dword [r15+H_FLAGS],HX_SPLIT
	jmp	.have
.random:
	call	.number
.have:
	lea	rcx,[r12+SL_P]
	mov	edx,[r12+SL_N]
.pool:
	cmp	eax,[rcx+4]
	jb	.found
	add	rcx,8
	dec	edx
	jnz	.pool
	sub	rcx,8				; (never: they add up to 100)
.found:
	mov	eax,[rcx]
	pop	r12
	ret
.number:
	rdtsc
	imul	eax,eax,0x9E3779B1
	mov	ecx,100
	mul	ecx
	mov	eax,edx
	ret
.n_cookie	db 'cookie'

; rdi = where in a head, r15 = record: the cookie a new client gets. rdi
; advanced; keeps rbx, r12-r15.
split_emit:
	test	dword [r15+H_FLAGS],HX_SPLIT
	jz	.out
	push	r12
	mov	eax,[r15+H_ACT]
	dec	eax
	imul	rax,rax,RA_SIZE
	mov	eax,[g_acts+rax+RA_SPLIT]
	dec	eax
	imul	r12,rax,SL_SIZE
	lea	r12,[g_splits+r12]
	memit_x 'Set-Cookie: '
	mov	rsi,[r12+SL_NAME]
	mov	ecx,[r12+SL_NLEN]
	rep	movsb
	mov	byte [rdi],'='
	inc	rdi
	mov	rax,[r15+H_BUF]
	mov	eax,[rax+HB_SPLIT]
	call	fmt_u64
	memit_x '; Path=/; HttpOnly; SameSite=Lax',13,10
	pop	r12
.out:
	ret
