; ECDSA verification on P-384 with SHA-384 (FIPS 186-5): JWT's ES384.
;
; Only public data passes here (a key, a digest, a signature), so plain
; variable-time code: six 64-bit limbs, little endian, a generic CIOS
; Montgomery multiply for both moduli (the field p and the group order n),
; Jacobian points (a = -3), u1*G + u2*Q by Shamir's trick, inversions by
; Fermat. A point not on the curve, r or s out of [1, n-1], or a sum at
; infinity is no signature.
;
;   p384_verify(rdi Q[97] = 04|X|Y, rsi digest[48], rdx r[48], rcx s[48])
;            eax = 1 valid, 0 not

M6_M		:= 0				; the modulus, 6 limbs
M6_N0		:= 48				; -m^-1 mod 2^64
M6_RR		:= 56				; R^2 mod m
M6_ONE		:= 104				; R mod m
M6_E		:= 152				; m - 2
P6_X		:= 0				; a point: X, Y, Z (Z = 0: at infinity)
P6_Y		:= 48
P6_Z		:= 96
P6_SIZE		:= 144

rodata
	align 16
	p384_p:
	dq 0x00000000FFFFFFFF, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF
	dq 0x0000000100000001
	dq 0xFFFFFFFE00000001, 0x0000000200000000, 0xFFFFFFFE00000000, 0x0000000200000000, 0x0000000000000001, 0x0000000000000000
	dq 0xFFFFFFFF00000001, 0x00000000FFFFFFFF, 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000
	dq 0x00000000FFFFFFFD, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF
	p384_n:
	dq 0xECEC196ACCC52973, 0x581A0DB248B0A77A, 0xC7634D81F4372DDF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF
	dq 0x6ED46089E88FDC45
	dq 0x2D319B2419B409A9, 0xFF3D81E5DF1AA419, 0xBC3E483AFCB82947, 0xD40D49174AAB1CC5, 0x3FB05B7A28266895, 0x0C84EE012B39BF21
	dq 0x1313E695333AD68D, 0xA7E5F24DB74F5885, 0x389CB27E0BC8D220, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000
	dq 0xECEC196ACCC52971, 0x581A0DB248B0A77A, 0xC7634D81F4372DDF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF
	p384_b_m:
	dq 0x081188719D412DCC, 0xF729ADD87A4C32EC, 0x77F2209B1920022E, 0xE3374BEE94938AE2, 0xB62B21F41F022094, 0xCD08114B604FBFF9
	p384_g_m:				; G = (x : y : 1), Montgomery form
	dq 0x3DD0756649C0B528, 0x20E378E2A0D6CE38, 0x879C3AFC541B4D6E, 0x6454868459A30EFF, 0x812FF723614EDE2B, 0x4D3AADC2299E1513
	dq 0x23043DAD4B03A4FE, 0xA1BFA8BF7BB4A9AC, 0x8BADE7562E83B050, 0xC6C3521968F4FFD9, 0xDD8002263969A840, 0x2B78ABC25A15C5E9
	dq 0xFFFFFFFF00000001, 0x00000000FFFFFFFF, 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000
	p384_one:
	dq 1, 0, 0, 0, 0, 0
end rodata

; rdi = out, rsi = a, rdx = b, rcx = a modulus record: a*b/R mod m (a, b
; below m). out may be a or b.
m6_mul:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,64				; t[0..7]
	mov	r8,rdx				; b
	mov	r9,rcx				; m
	xor	eax,eax
	mov	ecx,8
@@:
	mov	[rsp+rcx*8-8],rax
	dec	ecx
	jnz	@b
	xor	r10d,r10d			; i
.outer:
	mov	r11,[r8+r10*8]			; b[i]
	xor	r12d,r12d			; carry
	xor	r13d,r13d			; j
.mul:
	mov	rax,[rsi+r13*8]
	mul	r11
	add	rax,[rsp+r13*8]
	adc	rdx,0
	add	rax,r12
	adc	rdx,0
	mov	[rsp+r13*8],rax
	mov	r12,rdx
	inc	r13d
	cmp	r13d,6
	jb	.mul
	xor	r14d,r14d
	add	[rsp+48],r12
	adc	r14,0
	mov	[rsp+56],r14
	; reduce: t + m*M, one limb down
	mov	rbp,[rsp]
	imul	rbp,[r9+M6_N0]
	mov	rax,rbp
	mul	qword [r9]
	add	rax,[rsp]
	adc	rdx,0
	mov	r12,rdx
	mov	r13d,1
.red:
	mov	rax,[r9+r13*8]
	mul	rbp
	add	rax,[rsp+r13*8]
	adc	rdx,0
	add	rax,r12
	adc	rdx,0
	mov	[rsp+r13*8-8],rax
	mov	r12,rdx
	inc	r13d
	cmp	r13d,6
	jb	.red
	mov	rax,[rsp+48]
	add	rax,r12
	mov	[rsp+40],rax
	mov	rax,[rsp+56]
	adc	rax,0
	mov	[rsp+48],rax
	inc	r10d
	cmp	r10d,6
	jb	.outer
	; t - m, kept unless it borrows
	mov	rax,[rsp]
	sub	rax,[r9]
	mov	[rdi],rax
	repeat 5, i:1
		mov	rax,[rsp+i*8]
		sbb	rax,[r9+i*8]
		mov	[rdi+i*8],rax
	end repeat
	mov	rax,[rsp+48]
	sbb	rax,0
	jnc	.done
	mov	ecx,6
	xor	edx,edx
@@:
	mov	rax,[rsp+rdx*8]
	mov	[rdi+rdx*8],rax
	inc	edx
	dec	ecx
	jnz	@b
.done:
	add	rsp,64
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

; rdi = out, rsi = a, rdx = b, rcx = modulus: a + b mod m
m6_add:
	sub	rsp,48
	mov	rax,[rsi]
	add	rax,[rdx]
	mov	[rdi],rax
	repeat 5, i:1
		mov	rax,[rsi+i*8]
		adc	rax,[rdx+i*8]
		mov	[rdi+i*8],rax
	end repeat
	setc	r8b
	; minus m, unless that borrows past the carry
	mov	rax,[rdi]
	sub	rax,[rcx]
	mov	[rsp],rax
	repeat 5, i:1
		mov	rax,[rdi+i*8]
		sbb	rax,[rcx+i*8]
		mov	[rsp+i*8],rax
	end repeat
	sbb	r8b,0
	jc	.kept
	repeat 6, i:0
		mov	rax,[rsp+i*8]
		mov	[rdi+i*8],rax
	end repeat
.kept:
	add	rsp,48
	ret

; rdi = out, rsi = a, rdx = b, rcx = modulus: a - b mod m
m6_sub:
	mov	rax,[rsi]
	sub	rax,[rdx]
	mov	[rdi],rax
	repeat 5, i:1
		mov	rax,[rsi+i*8]
		sbb	rax,[rdx+i*8]
		mov	[rdi+i*8],rax
	end repeat
	jnc	.out
	mov	rax,[rcx]			; it borrowed: plus m
	add	[rdi],rax
	repeat 5, i:1
		mov	rax,[rcx+i*8]
		adc	[rdi+i*8],rax
	end repeat
.out:
	ret

; rdi = out, rsi = a (Montgomery), rcx = modulus: a^(m-2), its inverse
m6_inv:
	push	rbx
	push	r12
	push	r13
	push	r14
	sub	rsp,96
	mov	r12,rdi
	mov	r13,rcx
	lea	rdi,[rsp+48]			; a, kept
	mov	ecx,6
	rep	movsq
	lea	rsi,[r13+M6_ONE]		; the result: 1
	mov	rdi,rsp
	mov	ecx,6
	rep	movsq
	mov	ebx,383				; the bit
.bit:
	mov	rdi,rsp
	mov	rsi,rsp
	mov	rdx,rsp
	mov	rcx,r13
	call	m6_mul
	mov	eax,ebx
	shr	eax,6
	mov	rax,[r13+M6_E+rax*8]
	bt	rax,rbx
	jnc	@f
	mov	rdi,rsp
	mov	rsi,rsp
	lea	rdx,[rsp+48]
	mov	rcx,r13
	call	m6_mul
@@:
	dec	ebx
	jns	.bit
	mov	rsi,rsp
	mov	rdi,r12
	mov	ecx,6
	rep	movsq
	add	rsp,96
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = 6 limbs: ZF when all are zero
m6_zero:
	mov	rax,[rdi]
	or	rax,[rdi+8]
	or	rax,[rdi+16]
	or	rax,[rdi+24]
	or	rax,[rdi+32]
	or	rax,[rdi+40]
	ret

; rdi = 6 limbs out, rsi = 48 bytes big endian
be6_to_limbs:
	mov	ecx,5
@@:
	mov	rax,[rsi]
	bswap	rax
	mov	[rdi+rcx*8],rax
	add	rsi,8
	dec	ecx
	jns	@b
	ret

; rdi = a, rsi = b (6 limbs): CF when a < b, ZF when equal
m6_cmp:
	mov	ecx,5
@@:
	mov	rax,[rdi+rcx*8]
	cmp	rax,[rsi+rcx*8]
	jne	.out
	dec	ecx
	jns	@b
	xor	eax,eax				; (equal: ZF, no CF)
.out:
	ret

; field operations on the frame (rbp): F op, d, a, b
macro F6 op*, d*, a*, b*
	lea	rdi,[d]
	lea	rsi,[a]
	lea	rdx,[b]
	lea	rcx,[p384_p]
	call	op
end macro

; rdi = out, rsi = P (Jacobian, Montgomery): 2P (a = -3, dbl-2001-b)
D6_D		:= 0
D6_G		:= 48
D6_B		:= 96
D6_A		:= 144
D6_T		:= 192
D6_U		:= 240
D6_P		:= 288				; P, copied (out may be P)
D6_SIZE		:= 288 + P6_SIZE
p384_dbl:
	push	rbx
	push	rbp
	sub	rsp,D6_SIZE
	mov	rbp,rsp
	mov	rbx,rdi
	lea	rdi,[rbp+D6_P]
	mov	ecx,P6_SIZE / 8
	rep	movsq
	lea	rdi,[rbp+D6_P+P6_Z]
	call	m6_zero
	jnz	@f
	mov	rdi,rbx				; at infinity: so is 2P
	lea	rsi,[rbp+D6_P]
	mov	ecx,P6_SIZE / 8
	rep	movsq
	jmp	.out
@@:
	F6 m6_mul, rbp+D6_D, rbp+D6_P+P6_Z, rbp+D6_P+P6_Z	; delta = Z^2
	F6 m6_mul, rbp+D6_G, rbp+D6_P+P6_Y, rbp+D6_P+P6_Y	; gamma = Y^2
	F6 m6_mul, rbp+D6_B, rbp+D6_P+P6_X, rbp+D6_G		; beta = X gamma
	F6 m6_sub, rbp+D6_T, rbp+D6_P+P6_X, rbp+D6_D
	F6 m6_add, rbp+D6_U, rbp+D6_P+P6_X, rbp+D6_D
	F6 m6_mul, rbp+D6_T, rbp+D6_T, rbp+D6_U
	F6 m6_add, rbp+D6_A, rbp+D6_T, rbp+D6_T
	F6 m6_add, rbp+D6_A, rbp+D6_A, rbp+D6_T			; alpha = 3 (X-d)(X+d)
	; Z3 = (Y + Z)^2 - gamma - delta
	F6 m6_add, rbp+D6_T, rbp+D6_P+P6_Y, rbp+D6_P+P6_Z
	F6 m6_mul, rbp+D6_T, rbp+D6_T, rbp+D6_T
	F6 m6_sub, rbp+D6_T, rbp+D6_T, rbp+D6_G
	F6 m6_sub, rbx+P6_Z, rbp+D6_T, rbp+D6_D
	; X3 = alpha^2 - 8 beta
	F6 m6_add, rbp+D6_U, rbp+D6_B, rbp+D6_B			; 2b
	F6 m6_add, rbp+D6_U, rbp+D6_U, rbp+D6_U			; 4b
	F6 m6_add, rbp+D6_T, rbp+D6_U, rbp+D6_U			; 8b
	F6 m6_mul, rbx+P6_X, rbp+D6_A, rbp+D6_A
	F6 m6_sub, rbx+P6_X, rbx+P6_X, rbp+D6_T
	; Y3 = alpha (4 beta - X3) - 8 gamma^2
	F6 m6_sub, rbp+D6_U, rbp+D6_U, rbx+P6_X
	F6 m6_mul, rbp+D6_U, rbp+D6_A, rbp+D6_U
	F6 m6_mul, rbp+D6_G, rbp+D6_G, rbp+D6_G
	F6 m6_add, rbp+D6_G, rbp+D6_G, rbp+D6_G
	F6 m6_add, rbp+D6_G, rbp+D6_G, rbp+D6_G
	F6 m6_add, rbp+D6_G, rbp+D6_G, rbp+D6_G
	F6 m6_sub, rbx+P6_Y, rbp+D6_U, rbp+D6_G
.out:
	add	rsp,D6_SIZE
	pop	rbp
	pop	rbx
	ret

; rdi = out, rsi = P, rdx = Q (Jacobian, Montgomery): P + Q (add-1998-cmo-2;
; P = Q doubles, P = -Q is infinity)
A6_Z1		:= 0
A6_Z2		:= 48
A6_U1		:= 96
A6_U2		:= 144
A6_S1		:= 192
A6_S2		:= 240
A6_H		:= 288
A6_R		:= 336
A6_T		:= 384
A6_P		:= 432
A6_Q		:= 432 + P6_SIZE
A6_SIZE		:= 432 + 2 * P6_SIZE
p384_add:
	push	rbx
	push	rbp
	sub	rsp,A6_SIZE
	mov	rbp,rsp
	mov	rbx,rdi
	push	rdx
	lea	rdi,[rbp+A6_P]
	mov	ecx,P6_SIZE / 8
	rep	movsq
	pop	rsi
	lea	rdi,[rbp+A6_Q]
	mov	ecx,P6_SIZE / 8
	rep	movsq
	lea	rdi,[rbp+A6_P+P6_Z]
	call	m6_zero
	jz	.is_q
	lea	rdi,[rbp+A6_Q+P6_Z]
	call	m6_zero
	jz	.is_p
	F6 m6_mul, rbp+A6_Z1, rbp+A6_P+P6_Z, rbp+A6_P+P6_Z
	F6 m6_mul, rbp+A6_Z2, rbp+A6_Q+P6_Z, rbp+A6_Q+P6_Z
	F6 m6_mul, rbp+A6_U1, rbp+A6_P+P6_X, rbp+A6_Z2
	F6 m6_mul, rbp+A6_U2, rbp+A6_Q+P6_X, rbp+A6_Z1
	F6 m6_mul, rbp+A6_S1, rbp+A6_P+P6_Y, rbp+A6_Q+P6_Z
	F6 m6_mul, rbp+A6_S1, rbp+A6_S1, rbp+A6_Z2
	F6 m6_mul, rbp+A6_S2, rbp+A6_Q+P6_Y, rbp+A6_P+P6_Z
	F6 m6_mul, rbp+A6_S2, rbp+A6_S2, rbp+A6_Z1
	F6 m6_sub, rbp+A6_H, rbp+A6_U2, rbp+A6_U1
	F6 m6_sub, rbp+A6_R, rbp+A6_S2, rbp+A6_S1
	lea	rdi,[rbp+A6_H]
	call	m6_zero
	jnz	.general
	lea	rdi,[rbp+A6_R]
	call	m6_zero
	jnz	.infinity
	mov	rdi,rbx				; the same point: doubled
	lea	rsi,[rbp+A6_P]
	call	p384_dbl
	jmp	.out
.infinity:
	mov	rdi,rbx
	xor	eax,eax
	mov	ecx,P6_SIZE / 8
	rep	stosq
	jmp	.out
.general:
	; Z3 = Z1 Z2 H
	F6 m6_mul, rbp+A6_T, rbp+A6_P+P6_Z, rbp+A6_Q+P6_Z
	F6 m6_mul, rbx+P6_Z, rbp+A6_T, rbp+A6_H
	; HH = H^2 (in Z1), HHH = H HH (in Z2), V = U1 HH (in U2)
	F6 m6_mul, rbp+A6_Z1, rbp+A6_H, rbp+A6_H
	F6 m6_mul, rbp+A6_Z2, rbp+A6_H, rbp+A6_Z1
	F6 m6_mul, rbp+A6_U2, rbp+A6_U1, rbp+A6_Z1
	; X3 = r^2 - HHH - 2V
	F6 m6_mul, rbp+A6_T, rbp+A6_R, rbp+A6_R
	F6 m6_sub, rbp+A6_T, rbp+A6_T, rbp+A6_Z2
	F6 m6_sub, rbp+A6_T, rbp+A6_T, rbp+A6_U2
	F6 m6_sub, rbx+P6_X, rbp+A6_T, rbp+A6_U2
	; Y3 = r (V - X3) - S1 HHH
	F6 m6_sub, rbp+A6_T, rbp+A6_U2, rbx+P6_X
	F6 m6_mul, rbp+A6_T, rbp+A6_R, rbp+A6_T
	F6 m6_mul, rbp+A6_S1, rbp+A6_S1, rbp+A6_Z2
	F6 m6_sub, rbx+P6_Y, rbp+A6_T, rbp+A6_S1
	jmp	.out
.is_q:
	lea	rsi,[rbp+A6_Q]
	jmp	@f
.is_p:
	lea	rsi,[rbp+A6_P]
@@:
	mov	rdi,rbx
	mov	ecx,P6_SIZE / 8
	rep	movsq
.out:
	add	rsp,A6_SIZE
	pop	rbp
	pop	rbx
	ret

; the frame of p384_verify
V6_R		:= 0				; r, s, e: plain
V6_S		:= 48
V6_E		:= 96
V6_W		:= 144				; s^-1 (Montgomery, mod n)
V6_U1		:= 192				; plain
V6_U2		:= 240
V6_T		:= 288
V6_T2		:= 336
V6_Q		:= 384				; Q
V6_GQ		:= 384 + P6_SIZE		; G + Q
V6_ACC		:= 384 + 2 * P6_SIZE		; the sum
V6_G		:= 384 + 3 * P6_SIZE		; G
V6_SIZE		:= 384 + 4 * P6_SIZE

; rdi = Q[97], rsi = digest[48], rdx = r[48], rcx = s[48]: eax = 1 when
; (r, s) is Q's signature of the digest
p384_verify:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,V6_SIZE
	mov	rbp,rsp
	mov	r12,rdi
	mov	r13,rsi
	mov	r14,rdx
	mov	r15,rcx
	cmp	byte [r12],4
	jne	.bad
	; r, s in [1, n-1]
	lea	rdi,[rbp+V6_R]
	mov	rsi,r14
	call	be6_to_limbs
	lea	rdi,[rbp+V6_S]
	mov	rsi,r15
	call	be6_to_limbs
	lea	rdi,[rbp+V6_R]
	call	.scalar_ok
	jc	.bad
	lea	rdi,[rbp+V6_S]
	call	.scalar_ok
	jc	.bad
	; e = digest mod n (below 2n: one subtraction at most)
	lea	rdi,[rbp+V6_E]
	mov	rsi,r13
	call	be6_to_limbs
	lea	rdi,[rbp+V6_E]
	lea	rsi,[p384_n]
	call	m6_cmp
	jc	@f
	lea	rdi,[rbp+V6_E]
	mov	rsi,rdi
	lea	rdx,[p384_n]
	lea	rcx,[p384_zero]
	call	m6_sub
@@:
	; w = s^-1 mod n, in Montgomery form; u1 = e w, u2 = r w, plain
	lea	rdi,[rbp+V6_W]
	lea	rsi,[rbp+V6_S]
	lea	rdx,[p384_n+M6_RR]
	lea	rcx,[p384_n]
	call	m6_mul
	lea	rdi,[rbp+V6_W]
	mov	rsi,rdi
	lea	rcx,[p384_n]
	call	m6_inv
	lea	rdi,[rbp+V6_U1]
	lea	rsi,[rbp+V6_E]
	lea	rdx,[rbp+V6_W]
	lea	rcx,[p384_n]
	call	m6_mul
	lea	rdi,[rbp+V6_U2]
	lea	rsi,[rbp+V6_R]
	lea	rdx,[rbp+V6_W]
	lea	rcx,[p384_n]
	call	m6_mul
	; Q: below p, on the curve; Montgomery form
	lea	rdi,[rbp+V6_Q+P6_X]
	lea	rsi,[r12+1]
	call	be6_to_limbs
	lea	rdi,[rbp+V6_Q+P6_Y]
	lea	rsi,[r12+49]
	call	be6_to_limbs
	lea	rdi,[rbp+V6_Q+P6_X]
	lea	rsi,[p384_p]
	call	m6_cmp
	jnc	.bad
	lea	rdi,[rbp+V6_Q+P6_Y]
	lea	rsi,[p384_p]
	call	m6_cmp
	jnc	.bad
	F6 m6_mul, rbp+V6_Q+P6_X, rbp+V6_Q+P6_X, p384_p+M6_RR
	F6 m6_mul, rbp+V6_Q+P6_Y, rbp+V6_Q+P6_Y, p384_p+M6_RR
	lea	rsi,[p384_p+M6_ONE]
	lea	rdi,[rbp+V6_Q+P6_Z]
	mov	ecx,6
	rep	movsq
	F6 m6_mul, rbp+V6_T, rbp+V6_Q+P6_X, rbp+V6_Q+P6_X	; x^3 - 3x + b
	F6 m6_mul, rbp+V6_T, rbp+V6_T, rbp+V6_Q+P6_X
	F6 m6_add, rbp+V6_T2, rbp+V6_Q+P6_X, rbp+V6_Q+P6_X
	F6 m6_add, rbp+V6_T2, rbp+V6_T2, rbp+V6_Q+P6_X
	F6 m6_sub, rbp+V6_T, rbp+V6_T, rbp+V6_T2
	F6 m6_add, rbp+V6_T, rbp+V6_T, p384_b_m
	F6 m6_mul, rbp+V6_T2, rbp+V6_Q+P6_Y, rbp+V6_Q+P6_Y	; y^2
	lea	rdi,[rbp+V6_T]
	lea	rsi,[rbp+V6_T2]
	call	m6_cmp
	jne	.bad
	; G, G + Q
	lea	rsi,[p384_g_m]
	lea	rdi,[rbp+V6_G]
	mov	ecx,P6_SIZE / 8
	rep	movsq
	lea	rdi,[rbp+V6_GQ]
	lea	rsi,[rbp+V6_G]
	lea	rdx,[rbp+V6_Q]
	call	p384_add
	; u1 G + u2 Q, from the top bit
	lea	rdi,[rbp+V6_ACC]
	xor	eax,eax
	mov	ecx,P6_SIZE / 8
	rep	stosq
	mov	ebx,383
.bit:
	lea	rdi,[rbp+V6_ACC]
	mov	rsi,rdi
	call	p384_dbl
	mov	eax,ebx
	shr	eax,6
	mov	rcx,[rbp+V6_U1+rax*8]
	mov	rdx,[rbp+V6_U2+rax*8]
	xor	r8d,r8d
	bt	rcx,rbx
	adc	r8d,0				; 1: G
	bt	rdx,rbx
	jnc	@f
	add	r8d,2				; 2: Q, 3: both
@@:
	test	r8d,r8d
	jz	.next
	lea	rdx,[rbp+V6_G]
	cmp	r8d,1
	je	.add
	lea	rdx,[rbp+V6_Q]
	cmp	r8d,2
	je	.add
	lea	rdx,[rbp+V6_GQ]
.add:
	lea	rdi,[rbp+V6_ACC]
	mov	rsi,rdi
	call	p384_add
.next:
	dec	ebx
	jns	.bit
	; not at infinity; its x, affine, mod n, is r
	lea	rdi,[rbp+V6_ACC+P6_Z]
	call	m6_zero
	jz	.bad
	lea	rdi,[rbp+V6_T]
	lea	rsi,[rbp+V6_ACC+P6_Z]
	lea	rcx,[p384_p]
	call	m6_inv
	F6 m6_mul, rbp+V6_T, rbp+V6_T, rbp+V6_T			; Z^-2
	F6 m6_mul, rbp+V6_T, rbp+V6_ACC+P6_X, rbp+V6_T
	F6 m6_mul, rbp+V6_T, rbp+V6_T, p384_one			; out of Montgomery form
	lea	rdi,[rbp+V6_T]
	lea	rsi,[p384_n]
	call	m6_cmp
	jc	@f
	lea	rdi,[rbp+V6_T]
	mov	rsi,rdi
	lea	rdx,[p384_n]
	lea	rcx,[p384_zero]
	call	m6_sub
@@:
	lea	rdi,[rbp+V6_T]
	lea	rsi,[rbp+V6_R]
	call	m6_cmp
	jne	.bad
	mov	eax,1
	jmp	.out
.bad:
	xor	eax,eax
.out:
	add	rsp,V6_SIZE
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret
; rdi = a scalar: CF unless 1 <= it < n
.scalar_ok:
	push	rdi
	call	m6_zero
	pop	rdi
	jz	.no
	lea	rsi,[p384_n]
	call	m6_cmp
	cmc					; (below n: no CF)
	ret
.no:
	stc
	ret

rodata
	align 8
	p384_zero	dq 0, 0, 0, 0, 0, 0	; (a modulus for a plain subtraction that cannot borrow)
end rodata
