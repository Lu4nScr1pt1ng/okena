; RSA private operations by the Chinese remainder theorem (RFC 8017 5.1.2,
; 2b): two exponentiations modulo p and q, each half the size, in place of
; one modulo n, about four times less work. A fixed 5-bit window: 32
; Montgomery powers, one of them taken each five squarings, picked by
; reading all 32 with a mask (AVX2), so no branch and no address depends on
; the private exponent.
;
; The key's CRT block (rsa_crt_load, when its certificate is loaded) keeps
; p, q, dp, dq, qinv as little-endian limbs, with -p^-1, -q^-1 mod 2^64 and
; R^2, R^3 mod each prime. A caller that has one sets g_rsa_crt before the
; signature; rsa_priv takes it once, and without one it is bn_modexp.

CRT_OK		:= 0				; d: CRT_MAGIC when the block is good
CRT_H		:= 4				; d: limbs of each prime (n's / 2)
CRT_P0		:= 8				; q: -p^-1 mod 2^64
CRT_Q0		:= 16				; q: -q^-1 mod 2^64
CRT_P		:= 32				; then each CRT_LIMBS limbs
CRT_LIMBS	:= 32				; (keys up to 4096 bits)
CRT_Q		:= CRT_P + CRT_LIMBS * 8
CRT_DP		:= CRT_Q + CRT_LIMBS * 8
CRT_DQ		:= CRT_DP + CRT_LIMBS * 8
CRT_QI		:= CRT_DQ + CRT_LIMBS * 8
CRT_RRP		:= CRT_QI + CRT_LIMBS * 8
CRT_RRQ		:= CRT_RRP + CRT_LIMBS * 8
CRT_R3P		:= CRT_RRQ + CRT_LIMBS * 8
CRT_R3Q		:= CRT_R3P + CRT_LIMBS * 8
CRT_SIZE	:= CRT_R3Q + CRT_LIMBS * 8
CRT_MAGIC	:= 0x31545243			; 'CRT1'

bss
	align 8
	g_rsa_crt	dq ?			; the next private operation's CRT block, 0 none
	g_crt_tmp:	rb CRT_LIMBS * 8	; rsa_crt_load: one integer, big-endian
end bss

; rdi = a CRT block, rsi = RSAPrivateKey DER (PKCS#1), edx = its length, ecx
; = the modulus' bytes: p, q, dp, dq, qinv read and the block made good, or
; left not good (CRT_OK 0: the full-width exponentiation signs) when the key
; is not one this takes (primes not half of n, n's limbs not a multiple of
; eight). Keeps rbx, rbp, r12-r15.
rsa_crt_load:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	mov	rbx,rdi
	mov	dword [rbx+CRT_OK],0
	mov	r12,rsi
	lea	r13,[rsi+rdx]			; the DER's end
	mov	eax,ecx
	test	eax,15
	jnz	.out
	shr	eax,4				; limbs a prime
	test	eax,3
	jnz	.out
	cmp	eax,CRT_LIMBS
	ja	.out
	mov	[rbx+CRT_H],eax
	mov	ebp,eax
	mov	rsi,r12
	mov	rdx,r13
	call	der_read			; SEQUENCE
	jc	.out
	cmp	al,0x30
	jne	.out
	mov	r14,r8				; its end
	; version, n, e, d: skipped
	mov	r15d,4
.skip:
	mov	rdx,r14
	call	der_read
	jc	.out
	cmp	al,2
	jne	.out
	mov	rsi,r8
	dec	r15d
	jnz	.skip
	; p, q, dp, dq, qinv, each into its limbs
	lea	r12,[.where]
	mov	r15d,5
.int:
	push	rsi
	mov	rdx,r14
	call	der_read
	pop	rdx
	jc	.out
	cmp	al,2
	jne	.out
	push	r8
	cmp	ecx,0				; a leading sign byte goes
	je	.bad_int
	cmp	byte [rsi],0
	jne	@f
	inc	rsi
	dec	ecx
@@:
	lea	eax,[rbp*8]			; at most a prime's bytes
	cmp	ecx,eax
	ja	.bad_int
	; right-aligned in the prime's bytes, then limbs
	push	rsi
	push	rcx
	lea	rdi,[g_crt_tmp]
	mov	ecx,eax
	xor	eax,eax
	rep	stosb
	pop	rcx
	pop	rsi
	lea	rdi,[g_crt_tmp+rbp*8]
	sub	rdi,rcx
	rep	movsb
	movzx	eax,word [r12]
	lea	rdi,[rbx+rax]
	lea	rsi,[g_crt_tmp]
	lea	edx,[rbp*8]
	call	bn_from_be
	pop	rsi				; the next element
	add	r12,2
	dec	r15d
	jnz	.int
	; the primes odd, their Montgomery constants
	test	byte [rbx+CRT_P],1
	jz	.out
	test	byte [rbx+CRT_Q],1
	jz	.out
	lea	rdi,[rbx+CRT_P]
	call	bn_n0inv
	mov	[rbx+CRT_P0],rax
	lea	rdi,[rbx+CRT_Q]
	call	bn_n0inv
	mov	[rbx+CRT_Q0],rax
	lea	rdi,[rbx+CRT_RRP]
	lea	rsi,[rbx+CRT_P]
	mov	edx,ebp
	call	bn_rr
	lea	rdi,[rbx+CRT_RRQ]
	lea	rsi,[rbx+CRT_Q]
	mov	edx,ebp
	call	bn_rr
	lea	rdi,[rbx+CRT_R3P]		; R^3 = R^2 R^2 / R
	lea	rsi,[rbx+CRT_RRP]
	mov	rdx,rsi
	lea	rcx,[rbx+CRT_P]
	mov	r8,[rbx+CRT_P0]
	mov	r9d,ebp
	call	bn_mont_mul
	lea	rdi,[rbx+CRT_R3Q]
	lea	rsi,[rbx+CRT_RRQ]
	mov	rdx,rsi
	lea	rcx,[rbx+CRT_Q]
	mov	r8,[rbx+CRT_Q0]
	mov	r9d,ebp
	call	bn_mont_mul
	mov	dword [rbx+CRT_OK],CRT_MAGIC
	jmp	.out
.bad_int:
	pop	r8
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret
.where	dw CRT_P, CRT_Q, CRT_DP, CRT_DQ, CRT_QI

; bn_modexp's arguments (rdi = out, rsi = base, rdx = d big-endian, ecx = its
; length, r8 = n, r9d = n's limbs, all little-endian limbs): out = base^d mod
; n, by the CRT block in g_rsa_crt when there is a good one for this size
; (then g_rsa_crt is cleared), else bn_modexp.
rsa_priv:
	mov	rax,[g_rsa_crt]
	test	rax,rax
	jz	bn_modexp
	mov	qword [g_rsa_crt],0
	cmp	dword [rax+CRT_OK],CRT_MAGIC
	jne	bn_modexp
	mov	r10d,[rax+CRT_H]
	add	r10d,r10d
	cmp	r10d,r9d
	jne	bn_modexp
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	mov	rbx,rax				; the block
	mov	r12,rdi				; out
	mov	r13,rsi				; c
	mov	ebp,[rbx+CRT_H]			; h
	; frame: m1 | m2 | t | u, h limbs each, then 2h for the product
	lea	eax,[rbp*8]
	imul	eax,eax,6
	add	eax,15
	and	eax,-16
	mov	r15d,eax
	sub	rsp,rax
	; m1 = c^dp mod p, m2 = c^dq mod q
	mov	rdi,rsp
	mov	rsi,r13
	lea	rdx,[rbx+CRT_P]
	mov	rcx,rbx
	xor	r8d,r8d				; (p's)
	call	crt_half
	lea	rdi,[rsp+rbp*8]
	mov	rsi,r13
	lea	rdx,[rbx+CRT_Q]
	mov	rcx,rbx
	mov	r8d,1				; (q's)
	call	crt_half
	; t = m2 mod p (q < 2p: one subtraction at most)
	lea	rdi,[rsp+rbp*8]
	imul	rdi,rdi,1
	lea	rax,[rbp*2]
	lea	rdi,[rsp+rax*8]			; t
	lea	rsi,[rsp+rbp*8]			; m2
	lea	rdx,[rbx+CRT_P]
	mov	ecx,ebp
	call	crt_sub_cond
	; u = m1 - t mod p
	lea	rax,[rbp*2]
	lea	rsi,[rsp+rax*8]			; t
	mov	rdi,rsp				; m1 (u in place)
	lea	rdx,[rbx+CRT_P]
	mov	ecx,ebp
	call	crt_sub_mod
	; u = qinv u mod p: (u qinv / R) R^2 / R
	lea	rax,[rbp*2]
	lea	rdi,[rsp+rax*8]			; t = u qinv / R
	mov	rsi,rsp
	lea	rdx,[rbx+CRT_QI]
	lea	rcx,[rbx+CRT_P]
	mov	r8,[rbx+CRT_P0]
	mov	r9d,ebp
	call	bn_mont_mul
	mov	rdi,rsp				; m1 slot = t R^2 / R
	lea	rax,[rbp*2]
	lea	rsi,[rsp+rax*8]
	lea	rdx,[rbx+CRT_RRP]
	lea	rcx,[rbx+CRT_P]
	mov	r8,[rbx+CRT_P0]
	mov	r9d,ebp
	call	bn_mont_mul
	; out = m2 + h q
	mov	rdi,r12
	mov	rsi,rsp				; h
	lea	rdx,[rbx+CRT_Q]
	mov	ecx,ebp
	call	crt_mul
	mov	rdi,r12
	lea	rsi,[rsp+rbp*8]			; m2
	mov	ecx,ebp
	call	crt_add_into
	; nothing of it left on the stack
	mov	rdi,rsp
	mov	ecx,r15d
	call	secure_zero
	add	rsp,r15
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

; rdi = out (h limbs), rsi = c (2h limbs), rdx = the prime, rcx = the CRT
; block, r8d = 0 for p, 1 for q: out = c^(dp or dq) mod the prime.
; Frame: the 32 powers, the result, a scratch, the base. Keeps rbx, rbp,
; r12-r15.
crt_half:
	cmp	dword [rcx+CRT_H],16		; 1024-bit primes: vectors (vmont.inc)
	je	crt_half_v
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	mov	rbx,rcx
	mov	ebp,[rbx+CRT_H]
	mov	r12,rdx				; the prime
	push	rdi				; [rsp+frame]: out
	; its constants
	lea	rax,[rbx+CRT_P0]
	lea	r9,[rbx+CRT_RRP]
	lea	r10,[rbx+CRT_R3P]
	lea	r11,[rbx+CRT_DP]
	test	r8d,r8d
	jz	@f
	lea	rax,[rbx+CRT_Q0]
	lea	r9,[rbx+CRT_RRQ]
	lea	r10,[rbx+CRT_R3Q]
	lea	r11,[rbx+CRT_DQ]
@@:
	mov	r13,[rax]			; n0inv
	mov	r14,r11				; the exponent
	push	r9				; RR
	push	r10				; R^3
	push	rsi				; c
	; frame: table (32 h) | res (h) | tmp (h) | one (h)
	lea	eax,[rbp*8]
	imul	eax,eax,35
	add	eax,15
	and	eax,-16
	mov	r15d,eax
	sub	rsp,rax
	; S = the frame's slots: [rsp+r15] c, +8 R^3, +16 RR, +24 out
	lea	rax,[rbp*8]
	shl	rax,5				; 32 h * 8
	lea	rcx,[rsp+rax]			; res
	; one = 1
	lea	rdx,[rbp*8]
	lea	rdi,[rcx+rdx*2]			; one
	push	rcx
	mov	ecx,ebp
	xor	eax,eax
	push	rdi
	rep	stosq
	pop	rdi
	mov	qword [rdi],1
	pop	rcx
	; base in Montgomery form, < p: lo RR / R + hi R^3 / R (into table[1])
	; table[0] (scratch) = c_lo RR / R
	mov	rdi,rsp
	mov	rsi,[rsp+r15]			; c_lo
	mov	rdx,[rsp+r15+16]		; RR
	mov	rcx,r12
	mov	r8,r13
	mov	r9d,ebp
	call	bn_mont_mul
	lea	rdi,[rsp+rbp*8]			; table[1] = c_hi R^3 / R
	mov	rsi,[rsp+r15]
	lea	rsi,[rsi+rbp*8]			; c_hi
	mov	rdx,[rsp+r15+8]			; R^3
	mov	rcx,r12
	mov	r8,r13
	mov	r9d,ebp
	call	bn_mont_mul
	lea	rdi,[rsp+rbp*8]			; table[1] += table[0] mod p
	mov	rsi,rsp
	mov	rdx,r12
	mov	ecx,ebp
	call	crt_add_mod
	; table[0] = R mod p = RR 1 / R
	mov	rdi,rsp
	mov	rsi,[rsp+r15+16]
	lea	rax,[rbp*8]
	shl	rax,5
	lea	rdx,[rsp+rax]
	lea	rdx,[rdx+rbp*8]
	lea	rdx,[rdx+rbp*8]			; one
	mov	rcx,r12
	mov	r8,r13
	mov	r9d,ebp
	call	bn_mont_mul
	; table[i] = table[i-1] table[1] / R
	mov	ebx,2
.pow:
	mov	eax,ebx
	imul	eax,ebp
	lea	rdi,[rsp+rax*8]
	lea	rsi,[rdi+0]
	mov	rdx,rbp
	shl	rdx,3
	sub	rsi,rdx				; table[i-1]
	lea	rdx,[rsp+rbp*8]			; table[1]
	mov	rcx,r12
	mov	r8,r13
	mov	r9d,ebp
	call	bn_mont_mul
	inc	ebx
	cmp	ebx,32
	jb	.pow
	; the windows, from the top: bits mod 5 first (or 5)
	mov	eax,ebp
	shl	eax,6				; bits
	xor	edx,edx
	mov	ecx,5
	div	ecx
	test	edx,edx
	jnz	@f
	mov	edx,5
@@:
	mov	ebx,ebp
	shl	ebx,6
	sub	ebx,edx				; ebx = the first window's low bit
	mov	eax,ebx
	call	.window				; eax = its value
	lea	rdi,[rsp+0]			; res = table[w]
	lea	rcx,[rbp*8]
	shl	rcx,5
	lea	rdi,[rsp+rcx]
	call	.select
.next:
	test	ebx,ebx
	jz	.done
	sub	ebx,5
	mov	r8d,5
.sq:
	push	r8
	lea	rax,[rbp*8]
	shl	rax,5
	lea	rsi,[rsp+8+rax]			; res
	lea	rdi,[rsi+rbp*8]			; tmp = res^2 / R
	mov	rdx,rsi
	mov	rcx,r12
	mov	r8,r13
	mov	r9d,ebp
	call	bn_mont_mul
	lea	rax,[rbp*8]
	shl	rax,5
	lea	rdi,[rsp+8+rax]			; res = tmp
	lea	rsi,[rdi+rbp*8]
	mov	ecx,ebp
	rep	movsq
	pop	r8
	dec	r8d
	jnz	.sq
	mov	eax,ebx
	call	.window
	lea	rax,[rbp*8]			; tmp = table[w]
	shl	rax,5
	lea	rdi,[rsp+rax]
	lea	rdi,[rdi+rbp*8]
	mov	eax,[rsp-4]			; (the window, kept by .window)
	mov	eax,[g_crt_w]
	call	.select
	lea	rax,[rbp*8]			; res = res tmp / R
	shl	rax,5
	lea	rsi,[rsp+rax]
	lea	rdx,[rsi+rbp*8]
	lea	rdi,[rdx+rbp*8]			; into "one"'s room, then back
	mov	rcx,r12
	mov	r8,r13
	mov	r9d,ebp
	call	bn_mont_mul
	lea	rax,[rbp*8]
	shl	rax,5
	lea	rdi,[rsp+rax]
	lea	rsi,[rdi+rbp*8]
	lea	rsi,[rsi+rbp*8]
	mov	ecx,ebp
	rep	movsq
	jmp	.next
.done:
	; out of Montgomery form: res 1 / R
	lea	rax,[rbp*8]
	shl	rax,5
	lea	rsi,[rsp+rax]			; res
	lea	rdx,[rsi+rbp*8]			; tmp = 1
	push	rsi
	push	rdx
	mov	rdi,rdx
	mov	ecx,ebp
	xor	eax,eax
	rep	stosq
	pop	rdx
	pop	rsi
	mov	qword [rdx],1
	mov	rdi,[rsp+r15+24]		; out
	mov	rcx,r12
	mov	r8,r13
	mov	r9d,ebp
	call	bn_mont_mul
	; the powers (secrets) wiped
	mov	rdi,rsp
	mov	ecx,r15d
	call	secure_zero
	add	rsp,r15
	add	rsp,32				; c, R^3, RR, out
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret
; eax = a bit index: g_crt_w = the exponent's 5 bits there (r14 = its limbs,
; ebp = h). Keeps all but rax, rcx, rdx.
.window:
	mov	ecx,eax
	shr	eax,6				; the limb
	and	ecx,63
	mov	rdx,[r14+rax*8]
	shr	rdx,cl
	inc	eax
	cmp	eax,ebp
	jae	@f
	cmp	ecx,59
	jbe	@f
	push	rdx
	mov	rdx,[r14+rax*8]
	neg	ecx
	add	ecx,64
	shl	rdx,cl
	pop	rax
	or	rdx,rax
@@:
	and	edx,31
	mov	[g_crt_w],edx
	ret
; rdi = where (h limbs), g_crt_w = which: table[w], every entry read and
; masked (AVX2, four limbs a register; h a multiple of 4). Keeps all but
; rax, rcx, rdx, ymm0-ymm7.
.select:
	vpbroadcastq ymm7,[g_crt_w64]
	mov	eax,[g_crt_w]
	mov	[g_crt_w64],rax
	vpbroadcastq ymm7,[g_crt_w64]
	xor	edx,edx				; the limb group
.group:
	vpxor	ymm0,ymm0,ymm0
	xor	ecx,ecx				; the entry
	lea	rax,[rsp+8+rdx*8]		; (the call's return address above)
.entry:
	mov	[g_crt_e64],rcx
	vpbroadcastq ymm6,[g_crt_e64]
	vpcmpeqq ymm6,ymm6,ymm7
	vpand	ymm5,ymm6,[rax]
	vpor	ymm0,ymm0,ymm5
	lea	rax,[rax+rbp*8]
	inc	ecx
	cmp	ecx,32
	jb	.entry
	vmovdqu	[rdi+rdx*8],ymm0
	add	edx,4
	cmp	edx,ebp
	jb	.group
	vpxor	ymm0,ymm0,ymm0
	vpxor	ymm5,ymm5,ymm5
	vzeroupper
	ret

bss
	align 8
	g_crt_w		dd ?, ?
	g_crt_w64	dq ?
	g_crt_e64	dq ?
end bss

; rdi = out, rsi = a, rdx = mod, ecx = limbs: out = a >= mod ? a - mod : a
; (the subtraction always done, the result picked by mask). Keeps rbx, rbp,
; r12-r15.
crt_sub_cond:
	push	rbx
	xor	r8d,r8d
	clc
	pushf
.s:
	popf
	mov	rax,[rsi+r8*8]
	sbb	rax,[rdx+r8*8]
	pushf
	mov	[rdi+r8*8],rax
	inc	r8d
	cmp	r8d,ecx
	jb	.s
	popf
	sbb	rbx,rbx				; -1 when a < mod: keep a
	xor	r8d,r8d
.k:
	mov	rax,[rsi+r8*8]
	mov	r9,[rdi+r8*8]
	xor	rax,r9
	and	rax,rbx
	xor	r9,rax				; a when the mask is set, else a - mod
	mov	[rdi+r8*8],r9
	inc	r8d
	cmp	r8d,ecx
	jb	.k
	pop	rbx
	ret

; rdi = a (and out), rsi = b, rdx = mod, ecx = limbs, a, b < mod:
; a = a - b mod mod. Keeps rbx, rbp, r12-r15.
crt_sub_mod:
	push	rbx
	xor	r8d,r8d
	xor	ebx,ebx				; (CF clear)
.s:
	mov	rax,[rdi+r8*8]
	bt	ebx,0
	sbb	rax,[rsi+r8*8]
	setc	bl
	mov	[rdi+r8*8],rax
	inc	r8d
	cmp	r8d,ecx
	jb	.s
	neg	rbx				; -1 on a borrow: add mod back
	xor	r8d,r8d
	xor	r9d,r9d
.a:
	mov	rax,[rdx+r8*8]
	and	rax,rbx
	bt	r9d,0
	adc	[rdi+r8*8],rax
	setc	r9b
	inc	r8d
	cmp	r8d,ecx
	jb	.a
	pop	rbx
	ret

; rdi = a (and out), rsi = b, rdx = mod, ecx = limbs, a, b < mod:
; a = a + b mod mod. Keeps rbx, rbp, r12-r15.
crt_add_mod:
	push	rbx
	push	r12
	sub	rsp,CRT_LIMBS * 8
	xor	r8d,r8d
	xor	r9d,r9d
.a:
	mov	rax,[rdi+r8*8]
	bt	r9d,0
	adc	rax,[rsi+r8*8]
	setc	r9b
	mov	[rdi+r8*8],rax
	inc	r8d
	cmp	r8d,ecx
	jb	.a
	mov	r12d,r9d			; the carry out
	; minus mod, into the scratch
	xor	r8d,r8d
	xor	r9d,r9d
.s:
	mov	rax,[rdi+r8*8]
	bt	r9d,0
	sbb	rax,[rdx+r8*8]
	setc	r9b
	mov	[rsp+r8*8],rax
	inc	r8d
	cmp	r8d,ecx
	jb	.s
	; keep the sum when it did not carry and the subtraction borrowed
	sub	r9d,r12d			; 1: borrowed without a carry
	neg	r9d
	movsxd	rbx,r9d				; -1: keep the sum
	xor	r8d,r8d
.k:
	mov	rax,[rdi+r8*8]
	mov	r10,[rsp+r8*8]
	xor	rax,r10
	and	rax,rbx
	xor	r10,rax
	mov	[rdi+r8*8],r10
	inc	r8d
	cmp	r8d,ecx
	jb	.k
	add	rsp,CRT_LIMBS * 8
	pop	r12
	pop	rbx
	ret

; rdi = out (2h limbs), rsi = a, rdx = b (h limbs each), ecx = h: out = a b.
; Keeps rbx, rbp, r12-r15.
crt_mul:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r12,rsi
	mov	r13,rdx
	mov	r14d,ecx
	push	rdi
	lea	ecx,[r14*2]
	xor	eax,eax
	rep	stosq
	pop	rdi
	xor	r8d,r8d				; i
.i:
	mov	r9,[r13+r8*8]
	xor	r10d,r10d			; carry
	xor	r11d,r11d			; j
.j:
	mov	rax,[r12+r11*8]
	mul	r9
	lea	rbx,[r8+r11]
	add	rax,[rdi+rbx*8]
	adc	rdx,0
	add	rax,r10
	adc	rdx,0
	mov	[rdi+rbx*8],rax
	mov	r10,rdx
	inc	r11d
	cmp	r11d,r14d
	jb	.j
	lea	rbx,[r8+r14]
	mov	[rdi+rbx*8],r10
	inc	r8d
	cmp	r8d,r14d
	jb	.i
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = x (2h limbs), rsi = y (h limbs), ecx = h: x += y (the carry runs
; through x's upper half; the result fits). Keeps rbx, rbp, r12-r15.
crt_add_into:
	xor	r8d,r8d
	xor	r9d,r9d
.a:
	mov	rax,[rsi+r8*8]
	bt	r9d,0
	adc	[rdi+r8*8],rax
	setc	r9b
	inc	r8d
	cmp	r8d,ecx
	jb	.a
	lea	edx,[rcx*2]
.c:
	cmp	r8d,edx
	jae	.out
	bt	r9d,0
	adc	qword [rdi+r8*8],0
	setc	r9b
	inc	r8d
	jmp	.c
.out:
	ret
