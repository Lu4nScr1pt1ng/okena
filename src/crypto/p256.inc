; ECDSA on P-256 with SHA-256 (FIPS 186-5, SEC 1), deterministic nonces
; (RFC 6979): the signature of a TLS 1.3 CertificateVerify.
;
; Numbers are four 64-bit limbs, little endian, in Montgomery form for
; both moduli (the field p and the group order n); one CIOS multiply
; serves both and ends with a masked subtraction. Points are projective
; (X:Y:Z) and added with the complete formulas of Renes, Costello and
; Batina (2015, algorithm 4, a = -3): no exceptional case, so doubling is
; P + P and the point at infinity (0:1:0) needs no branch. k*G is a
; Montgomery ladder that swaps with masks. Inversions are by Fermat with
; the public exponents p - 2 and n - 2. Nothing secret picks a branch or
; an address; every intermediate is wiped.
;
;   p256_public(rdi out[65] = 04|X|Y, rsi d[32] big endian)
;   p256_sign(rdi rs[64] = r|s big endian, rsi d[32], rdx digest[32]);
;            eax = 1, or 0 for a key out of range
;   ecdsa_der(rdi out, rsi rs[64]): eax = the length of the DER
;            SEQUENCE { INTEGER r, INTEGER s }

MOD_M		:= 0				; the modulus, 4 limbs
MOD_N0		:= 32				; -m^-1 mod 2^64
MOD_RR		:= 40				; R^2 mod m
MOD_ONE		:= 72				; R mod m
MOD_E		:= 104				; m - 2 (the inversion's exponent)
MOD_SIZE	:= 136

rodata
	align 16
	p256_p:
	dq 0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFF, 0x0000000000000000, 0xFFFFFFFF00000001
	dq 0x1
	dq 0x0000000000000003, 0xFFFFFFFBFFFFFFFF, 0xFFFFFFFFFFFFFFFE, 0x00000004FFFFFFFD
	dq 0x0000000000000001, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFE
	dq 0xFFFFFFFFFFFFFFFD, 0x00000000FFFFFFFF, 0x0000000000000000, 0xFFFFFFFF00000001
	p256_n:
	dq 0xF3B9CAC2FC632551, 0xBCE6FAADA7179E84, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF00000000
	dq 0xCCD1C8AAEE00BC4F
	dq 0x83244C95BE79EEA2, 0x4699799C49BD6FA6, 0x2845B2392B6BEC59, 0x66E12D94F3D95620
	dq 0x0C46353D039CDAAF, 0x4319055258E8617B, 0x0000000000000000, 0x00000000FFFFFFFF
	dq 0xF3B9CAC2FC63254F, 0xBCE6FAADA7179E84, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF00000000
	p256_b_m:					; b, Montgomery form
	dq 0xD89CDF6229C4BDDF, 0xACF005CD78843090, 0xE5A220ABF7212ED6, 0xDC30061D04874834
	p256_g_m:					; G = (x : y : 1), Montgomery form
	dq 0x79E730D418A9143C, 0x75BA95FC5FEDB601, 0x79FB732B77622510, 0x18905F76A53755C6
	dq 0xDDF25357CE95560A, 0x8B4AB8E4BA19E45C, 0xD2E88688DD21F325, 0x8571FF1825885D85
	dq 0x0000000000000001, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFE
	p256_one:					; the plain 1
	dq 1, 0, 0, 0
end rodata

; rdi = out, rsi = a (below p, Montgomery): a^2 / R mod p. The square in
; registers (6 cross products doubled, 4 squares; mulx only), then four
; reduction rounds of p's shape.
mont_sqr_p256:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	xor	r13d,r13d
	xor	r14d,r14d
	xor	r15d,r15d
	mov	rdx,[rsi]
	mulx	r10,r9,[rsi+8]			; a0 a1
	mulx	r11,rax,[rsi+16]		; a0 a2
	add	r10,rax
	mulx	r12,rax,[rsi+24]		; a0 a3
	adc	r11,rax
	adc	r12,0
	mov	rdx,[rsi+8]
	mulx	rbx,rax,[rsi+16]		; a1 a2
	add	r11,rax
	adc	r12,rbx
	adc	r13,0
	mulx	rbx,rax,[rsi+24]		; a1 a3
	add	r12,rax
	adc	r13,rbx
	adc	r14,0
	mov	rdx,[rsi+16]
	mulx	rbx,rax,[rsi+24]		; a2 a3
	add	r13,rax
	adc	r14,rbx
	adc	r15,0
	add	r9,r9
	adc	r10,r10
	adc	r11,r11
	adc	r12,r12
	adc	r13,r13
	adc	r14,r14
	adc	r15,r15
	mov	rdx,[rsi]
	mulx	rax,r8,rdx
	mov	rdx,[rsi+8]
	mulx	rcx,rbx,rdx
	add	r9,rax
	adc	r10,rbx
	adc	r11,rcx
	mov	rdx,[rsi+16]
	mulx	rcx,rbx,rdx
	adc	r12,rbx
	adc	r13,rcx
	mov	rdx,[rsi+24]
	mulx	rcx,rbx,rdx
	adc	r14,rbx
	adc	r15,rcx
	mov	rbp,0xFFFFFFFF00000001
	xor	ecx,ecx				; above t7
	; reduction round 0: m = t0, t += m * p (two shifts and m * p3)
	mov	rdx,r8
	mov	rax,rdx
	shl	rax,32
	mov	rbx,rdx
	shr	rbx,32
	mulx	rsi,rdx,rbp
	add	r9,rax
	adc	r10,rbx
	adc	r11,rdx
	adc	r12,rsi
	adc	r13,0
	adc	r14,0
	adc	r15,0
	adc	rcx,0
	; reduction round 1: m = t1, t += m * p (two shifts and m * p3)
	mov	rdx,r9
	mov	rax,rdx
	shl	rax,32
	mov	rbx,rdx
	shr	rbx,32
	mulx	rsi,rdx,rbp
	add	r10,rax
	adc	r11,rbx
	adc	r12,rdx
	adc	r13,rsi
	adc	r14,0
	adc	r15,0
	adc	rcx,0
	; reduction round 2: m = t2, t += m * p (two shifts and m * p3)
	mov	rdx,r10
	mov	rax,rdx
	shl	rax,32
	mov	rbx,rdx
	shr	rbx,32
	mulx	rsi,rdx,rbp
	add	r11,rax
	adc	r12,rbx
	adc	r13,rdx
	adc	r14,rsi
	adc	r15,0
	adc	rcx,0
	; reduction round 3: m = t3, t += m * p (two shifts and m * p3)
	mov	rdx,r11
	mov	rax,rdx
	shl	rax,32
	mov	rbx,rdx
	shr	rbx,32
	mulx	rsi,rdx,rbp
	add	r12,rax
	adc	r13,rbx
	adc	r14,rdx
	adc	r15,rsi
	adc	rcx,0
	; t = r12 r13 r14 r15 (+ rcx), below 2p: t - p unless that borrows
	mov	rax,r12
	sub	rax,[p256_p]
	mov	rbx,r13
	sbb	rbx,[p256_p+8]
	mov	rdx,r14
	sbb	rdx,[p256_p+16]
	mov	rsi,r15
	sbb	rsi,[p256_p+24]
	sbb	rcx,0
	sbb	rcx,rcx
	xor	r12,rax
	and	r12,rcx
	xor	r12,rax
	xor	r13,rbx
	and	r13,rcx
	xor	r13,rbx
	xor	r14,rdx
	and	r14,rcx
	xor	r14,rdx
	xor	r15,rsi
	and	r15,rcx
	xor	r15,rsi
	mov	[rdi],r12
	mov	[rdi+8],r13
	mov	[rdi+16],r14
	mov	[rdi+24],r15
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

; rdi = out, rsi = a (below m, Montgomery), rcx = modulus: a^2 / R mod m,
; for any modulus (the order n here): the square in registers, then four
; generic reduction rounds on both carry chains.
mont_sqr_any:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	push	rdi
	mov	rbp,rcx				; modulus
	xor	r13d,r13d
	xor	r14d,r14d
	xor	r15d,r15d
	mov	rdx,[rsi]
	mulx	r10,r9,[rsi+8]			; a0 a1
	mulx	r11,rax,[rsi+16]		; a0 a2
	add	r10,rax
	mulx	r12,rax,[rsi+24]		; a0 a3
	adc	r11,rax
	adc	r12,0
	mov	rdx,[rsi+8]
	mulx	rbx,rax,[rsi+16]		; a1 a2
	add	r11,rax
	adc	r12,rbx
	adc	r13,0
	mulx	rbx,rax,[rsi+24]		; a1 a3
	add	r12,rax
	adc	r13,rbx
	adc	r14,0
	mov	rdx,[rsi+16]
	mulx	rbx,rax,[rsi+24]		; a2 a3
	add	r13,rax
	adc	r14,rbx
	adc	r15,0
	add	r9,r9
	adc	r10,r10
	adc	r11,r11
	adc	r12,r12
	adc	r13,r13
	adc	r14,r14
	adc	r15,r15
	mov	rdx,[rsi]
	mulx	rax,r8,rdx
	mov	rdx,[rsi+8]
	mulx	rcx,rbx,rdx
	add	r9,rax
	adc	r10,rbx
	adc	r11,rcx
	mov	rdx,[rsi+16]
	mulx	rcx,rbx,rdx
	adc	r12,rbx
	adc	r13,rcx
	mov	rdx,[rsi+24]
	mulx	rcx,rbx,rdx
	adc	r14,rbx
	adc	r15,rcx
	mov	rdi,rbp				; (the modulus, for the rounds)
	xor	ecx,ecx				; above t7
	; reduction round 0: m = t0 * n0, t += m * mod * 2^(64 * 0)
	mov	rdx,r8
	imul	rdx,[rdi+MOD_N0]
	xor	eax,eax				; (clears CF and OF)
	mulx	rbx,rax,[rdi]
	adcx	r8,rax
	adox	r9,rbx
	mulx	rbx,rax,[rdi+8]
	adcx	r9,rax
	adox	r10,rbx
	mulx	rbx,rax,[rdi+16]
	adcx	r10,rax
	adox	r11,rbx
	mulx	rbx,rax,[rdi+24]
	adcx	r11,rax
	adox	r12,rbx
	mov	eax,0
	adcx	r12,rax
	adcx	r13,rax
	adcx	r14,rax
	adcx	r15,rax
	adcx	rcx,rax
	adox	r13,rax
	adox	r14,rax
	adox	r15,rax
	adox	rcx,rax
	; reduction round 1: m = t1 * n0, t += m * mod * 2^(64 * 1)
	mov	rdx,r9
	imul	rdx,[rdi+MOD_N0]
	xor	eax,eax				; (clears CF and OF)
	mulx	rbx,rax,[rdi]
	adcx	r9,rax
	adox	r10,rbx
	mulx	rbx,rax,[rdi+8]
	adcx	r10,rax
	adox	r11,rbx
	mulx	rbx,rax,[rdi+16]
	adcx	r11,rax
	adox	r12,rbx
	mulx	rbx,rax,[rdi+24]
	adcx	r12,rax
	adox	r13,rbx
	mov	eax,0
	adcx	r13,rax
	adcx	r14,rax
	adcx	r15,rax
	adcx	rcx,rax
	adox	r14,rax
	adox	r15,rax
	adox	rcx,rax
	; reduction round 2: m = t2 * n0, t += m * mod * 2^(64 * 2)
	mov	rdx,r10
	imul	rdx,[rdi+MOD_N0]
	xor	eax,eax				; (clears CF and OF)
	mulx	rbx,rax,[rdi]
	adcx	r10,rax
	adox	r11,rbx
	mulx	rbx,rax,[rdi+8]
	adcx	r11,rax
	adox	r12,rbx
	mulx	rbx,rax,[rdi+16]
	adcx	r12,rax
	adox	r13,rbx
	mulx	rbx,rax,[rdi+24]
	adcx	r13,rax
	adox	r14,rbx
	mov	eax,0
	adcx	r14,rax
	adcx	r15,rax
	adcx	rcx,rax
	adox	r15,rax
	adox	rcx,rax
	; reduction round 3: m = t3 * n0, t += m * mod * 2^(64 * 3)
	mov	rdx,r11
	imul	rdx,[rdi+MOD_N0]
	xor	eax,eax				; (clears CF and OF)
	mulx	rbx,rax,[rdi]
	adcx	r11,rax
	adox	r12,rbx
	mulx	rbx,rax,[rdi+8]
	adcx	r12,rax
	adox	r13,rbx
	mulx	rbx,rax,[rdi+16]
	adcx	r13,rax
	adox	r14,rbx
	mulx	rbx,rax,[rdi+24]
	adcx	r14,rax
	adox	r15,rbx
	mov	eax,0
	adcx	r15,rax
	adcx	rcx,rax
	adox	rcx,rax
	; t = r12 r13 r14 r15 (+ rcx), below 2m
	mov	rax,r12
	sub	rax,[rdi]
	mov	rbx,r13
	sbb	rbx,[rdi+8]
	mov	rdx,r14
	sbb	rdx,[rdi+16]
	mov	rsi,r15
	sbb	rsi,[rdi+24]
	sbb	rcx,0
	sbb	rcx,rcx
	xor	r12,rax
	and	r12,rcx
	xor	r12,rax
	xor	r13,rbx
	and	r13,rcx
	xor	r13,rbx
	xor	r14,rdx
	and	r14,rcx
	xor	r14,rdx
	xor	r15,rsi
	and	r15,rcx
	xor	r15,rsi
	pop	rdi
	mov	[rdi],r12
	mov	[rdi+8],r13
	mov	[rdi+16],r14
	mov	[rdi+24],r15
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

; rdi = out, rsi = a, rcx = modulus: a^2 (the square routine for p).
mont_sqr:
	cmp	byte [g_cpu_adx],0		; (mulx is enough, but it goes with the
	je	.mul				;  ADX path that mont_mul_p256 is part of)
	lea	rax,[p256_p]
	cmp	rcx,rax
	je	mont_sqr_p256
	jmp	mont_sqr_any
.mul:
	mov	rdx,rsi
	jmp	mont_mul

; mont_mul for p itself, its shape used: no multiply for m, and m * p is
; two shifts and one multiply by p3 = 0xFFFFFFFF00000001 (the structure of
; OpenSSL's ecp_nistz256_mul_mont). Same contract as mont_mul.
mont_mul_p256:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	mov	rcx,rdx				; b
	xor	ebp,ebp
	mov	r15,0xFFFFFFFF00000001
	xor	r8d,r8d
	xor	r9d,r9d
	xor	r10d,r10d
	xor	r11d,r11d
	xor	r12d,r12d
	; round 0: t += a * b[0]
	mov	rdx,[rcx+0]
	xor	r13,r13
	mulx	rbx,rax,[rsi]
	adcx	r8,rax
	adox	r9,rbx
	mulx	rbx,rax,[rsi+8]
	adcx	r9,rax
	adox	r10,rbx
	mulx	rbx,rax,[rsi+16]
	adcx	r10,rax
	adox	r11,rbx
	mulx	rbx,rax,[rsi+24]
	adcx	r11,rax
	adox	r12,rbx
	adcx	r12,rbp
	adox	r13,rbp
	adcx	r13,rbp
	; then m = t0 (-p^-1 = 1): t += m * p, as m * 2^96 + m * p3 * 2^192
	mov	rdx,r8
	mov	rax,rdx
	shl	rax,32
	mov	rbx,rdx
	shr	rbx,32
	mulx	r14,rdx,r15
	add	r9,rax
	adc	r10,rbx
	adc	r11,rdx
	adc	r12,r14
	adc	r13,0
	; round 1: t += a * b[1]
	mov	rdx,[rcx+8]
	xor	r8,r8
	mulx	rbx,rax,[rsi]
	adcx	r9,rax
	adox	r10,rbx
	mulx	rbx,rax,[rsi+8]
	adcx	r10,rax
	adox	r11,rbx
	mulx	rbx,rax,[rsi+16]
	adcx	r11,rax
	adox	r12,rbx
	mulx	rbx,rax,[rsi+24]
	adcx	r12,rax
	adox	r13,rbx
	adcx	r13,rbp
	adox	r8,rbp
	adcx	r8,rbp
	; then m = t0 (-p^-1 = 1): t += m * p, as m * 2^96 + m * p3 * 2^192
	mov	rdx,r9
	mov	rax,rdx
	shl	rax,32
	mov	rbx,rdx
	shr	rbx,32
	mulx	r14,rdx,r15
	add	r10,rax
	adc	r11,rbx
	adc	r12,rdx
	adc	r13,r14
	adc	r8,0
	; round 2: t += a * b[2]
	mov	rdx,[rcx+16]
	xor	r9,r9
	mulx	rbx,rax,[rsi]
	adcx	r10,rax
	adox	r11,rbx
	mulx	rbx,rax,[rsi+8]
	adcx	r11,rax
	adox	r12,rbx
	mulx	rbx,rax,[rsi+16]
	adcx	r12,rax
	adox	r13,rbx
	mulx	rbx,rax,[rsi+24]
	adcx	r13,rax
	adox	r8,rbx
	adcx	r8,rbp
	adox	r9,rbp
	adcx	r9,rbp
	; then m = t0 (-p^-1 = 1): t += m * p, as m * 2^96 + m * p3 * 2^192
	mov	rdx,r10
	mov	rax,rdx
	shl	rax,32
	mov	rbx,rdx
	shr	rbx,32
	mulx	r14,rdx,r15
	add	r11,rax
	adc	r12,rbx
	adc	r13,rdx
	adc	r8,r14
	adc	r9,0
	; round 3: t += a * b[3]
	mov	rdx,[rcx+24]
	xor	r10,r10
	mulx	rbx,rax,[rsi]
	adcx	r11,rax
	adox	r12,rbx
	mulx	rbx,rax,[rsi+8]
	adcx	r12,rax
	adox	r13,rbx
	mulx	rbx,rax,[rsi+16]
	adcx	r13,rax
	adox	r8,rbx
	mulx	rbx,rax,[rsi+24]
	adcx	r8,rax
	adox	r9,rbx
	adcx	r9,rbp
	adox	r10,rbp
	adcx	r10,rbp
	; then m = t0 (-p^-1 = 1): t += m * p, as m * 2^96 + m * p3 * 2^192
	mov	rdx,r11
	mov	rax,rdx
	shl	rax,32
	mov	rbx,rdx
	shr	rbx,32
	mulx	r14,rdx,r15
	add	r12,rax
	adc	r13,rbx
	adc	r8,rdx
	adc	r9,r14
	adc	r10,0
	; t = r12 r13 r8 r9 (+ r10), below 2p: t - p unless that borrows
	mov	rax,r12
	sub	rax,[p256_p]
	mov	rbx,r13
	sbb	rbx,[p256_p+8]
	mov	rdx,r8
	sbb	rdx,[p256_p+16]
	mov	r14,r9
	sbb	r14,[p256_p+24]
	sbb	r10,0
	sbb	r10,r10
	xor	r12,rax
	and	r12,r10
	xor	r12,rax
	xor	r13,rbx
	and	r13,r10
	xor	r13,rbx
	xor	r8,rdx
	and	r8,r10
	xor	r8,rdx
	xor	r9,r14
	and	r9,r10
	xor	r9,r14
	mov	[rdi],r12
	mov	[rdi+8],r13
	mov	[rdi+16],r8
	mov	[rdi+24],r9
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

; rdi = out, rsi = a, rdx = b (both below m), rcx = modulus: a * b / R
; mod m, below m. out may be a or b. With ADX: CIOS in registers, the six
; accumulator limbs rotating by one each round, both carry chains busy;
; otherwise the version below in memory.
mont_mul:
	cmp	byte [g_cpu_adx],0
	je	mont_mul_generic
	lea	rax,[p256_p]
	cmp	rcx,rax
	je	mont_mul_p256
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r14,rcx				; modulus
	mov	rcx,rdx				; b
	xor	ebp,ebp				; zero, for the carries
	xor	r8d,r8d
	xor	r9d,r9d
	xor	r10d,r10d
	xor	r11d,r11d
	xor	r12d,r12d
	; round 0: t += a * b[0], then t = (t + m * mod) / 2^64
	mov	rdx,[rcx+0]
	xor	r13,r13
	mulx	rbx,rax,[rsi]
	adcx	r8,rax
	adox	r9,rbx
	mulx	rbx,rax,[rsi+8]
	adcx	r9,rax
	adox	r10,rbx
	mulx	rbx,rax,[rsi+16]
	adcx	r10,rax
	adox	r11,rbx
	mulx	rbx,rax,[rsi+24]
	adcx	r11,rax
	adox	r12,rbx
	adcx	r12,rbp
	adcx	r13,rbp
	adox	r13,rbp
	mov	rdx,r8
	imul	rdx,[r14+MOD_N0]
	xor	eax,eax				; (clears CF and OF)
	mulx	rbx,rax,[r14]
	adcx	r8,rax			; zero by construction
	adox	r9,rbx
	mulx	rbx,rax,[r14+8]
	adcx	r9,rax
	adox	r10,rbx
	mulx	rbx,rax,[r14+16]
	adcx	r10,rax
	adox	r11,rbx
	mulx	rbx,rax,[r14+24]
	adcx	r11,rax
	adox	r12,rbx
	adcx	r12,rbp
	adox	r13,rbp
	adcx	r13,rbp
	; round 1: t += a * b[1], then t = (t + m * mod) / 2^64
	mov	rdx,[rcx+8]
	xor	r8,r8
	mulx	rbx,rax,[rsi]
	adcx	r9,rax
	adox	r10,rbx
	mulx	rbx,rax,[rsi+8]
	adcx	r10,rax
	adox	r11,rbx
	mulx	rbx,rax,[rsi+16]
	adcx	r11,rax
	adox	r12,rbx
	mulx	rbx,rax,[rsi+24]
	adcx	r12,rax
	adox	r13,rbx
	adcx	r13,rbp
	adcx	r8,rbp
	adox	r8,rbp
	mov	rdx,r9
	imul	rdx,[r14+MOD_N0]
	xor	eax,eax				; (clears CF and OF)
	mulx	rbx,rax,[r14]
	adcx	r9,rax			; zero by construction
	adox	r10,rbx
	mulx	rbx,rax,[r14+8]
	adcx	r10,rax
	adox	r11,rbx
	mulx	rbx,rax,[r14+16]
	adcx	r11,rax
	adox	r12,rbx
	mulx	rbx,rax,[r14+24]
	adcx	r12,rax
	adox	r13,rbx
	adcx	r13,rbp
	adox	r8,rbp
	adcx	r8,rbp
	; round 2: t += a * b[2], then t = (t + m * mod) / 2^64
	mov	rdx,[rcx+16]
	xor	r9,r9
	mulx	rbx,rax,[rsi]
	adcx	r10,rax
	adox	r11,rbx
	mulx	rbx,rax,[rsi+8]
	adcx	r11,rax
	adox	r12,rbx
	mulx	rbx,rax,[rsi+16]
	adcx	r12,rax
	adox	r13,rbx
	mulx	rbx,rax,[rsi+24]
	adcx	r13,rax
	adox	r8,rbx
	adcx	r8,rbp
	adcx	r9,rbp
	adox	r9,rbp
	mov	rdx,r10
	imul	rdx,[r14+MOD_N0]
	xor	eax,eax				; (clears CF and OF)
	mulx	rbx,rax,[r14]
	adcx	r10,rax			; zero by construction
	adox	r11,rbx
	mulx	rbx,rax,[r14+8]
	adcx	r11,rax
	adox	r12,rbx
	mulx	rbx,rax,[r14+16]
	adcx	r12,rax
	adox	r13,rbx
	mulx	rbx,rax,[r14+24]
	adcx	r13,rax
	adox	r8,rbx
	adcx	r8,rbp
	adox	r9,rbp
	adcx	r9,rbp
	; round 3: t += a * b[3], then t = (t + m * mod) / 2^64
	mov	rdx,[rcx+24]
	xor	r10,r10
	mulx	rbx,rax,[rsi]
	adcx	r11,rax
	adox	r12,rbx
	mulx	rbx,rax,[rsi+8]
	adcx	r12,rax
	adox	r13,rbx
	mulx	rbx,rax,[rsi+16]
	adcx	r13,rax
	adox	r8,rbx
	mulx	rbx,rax,[rsi+24]
	adcx	r8,rax
	adox	r9,rbx
	adcx	r9,rbp
	adcx	r10,rbp
	adox	r10,rbp
	mov	rdx,r11
	imul	rdx,[r14+MOD_N0]
	xor	eax,eax				; (clears CF and OF)
	mulx	rbx,rax,[r14]
	adcx	r11,rax			; zero by construction
	adox	r12,rbx
	mulx	rbx,rax,[r14+8]
	adcx	r12,rax
	adox	r13,rbx
	mulx	rbx,rax,[r14+16]
	adcx	r13,rax
	adox	r8,rbx
	mulx	rbx,rax,[r14+24]
	adcx	r8,rax
	adox	r9,rbx
	adcx	r9,rbp
	adox	r10,rbp
	adcx	r10,rbp
	; t = r12 r13 r8 r9 (+ r10 above), below 2m: t - m unless that borrows
	mov	rax,r12
	sub	rax,[r14]
	mov	rbx,r13
	sbb	rbx,[r14+8]
	mov	rdx,r8
	sbb	rdx,[r14+16]
	mov	r15,r9
	sbb	r15,[r14+24]
	sbb	r10,0
	sbb	r10,r10				; all ones: t < m, keep t
	xor	r12,rax
	and	r12,r10
	xor	r12,rax
	xor	r13,rbx
	and	r13,r10
	xor	r13,rbx
	xor	r8,rdx
	and	r8,r10
	xor	r8,rdx
	xor	r9,r15
	and	r9,r10
	xor	r9,r15
	mov	[rdi],r12
	mov	[rdi+8],r13
	mov	[rdi+16],r8
	mov	[rdi+24],r9
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

; The same, in memory with mul (CPUs without ADX).
mont_mul_generic:
	push	rbx
	push	r12
	push	r13
	push	r14
	sub	rsp,48
	mov	rbx,rdx
	mov	r14,rcx
	xor	eax,eax
	repeat 6, i:0
		mov	[rsp+i*8],rax
	end repeat
	repeat 4, i:0
		; t += a * b[i]
		xor	r12d,r12d
		repeat 4, j:0
			mov	rax,[rsi+j*8]
			mul	qword [rbx+i*8]
			add	rax,r12
			adc	rdx,0
			add	[rsp+j*8],rax
			adc	rdx,0
			mov	r12,rdx
		end repeat
		add	[rsp+32],r12
		adc	qword [rsp+40],0
		; m = t0 * n0; t = (t + m * mod) / 2^64
		mov	r13,[rsp]
		imul	r13,[r14+MOD_N0]
		mov	rax,r13
		mul	qword [r14]
		add	rax,[rsp]			; zero by construction
		adc	rdx,0
		mov	r12,rdx
		repeat 3, j:1
			mov	rax,r13
			mul	qword [r14+j*8]
			add	rax,r12
			adc	rdx,0
			add	rax,[rsp+j*8]
			adc	rdx,0
			mov	[rsp+(j-1)*8],rax
			mov	r12,rdx
		end repeat
		mov	rax,[rsp+32]
		add	rax,r12
		mov	[rsp+24],rax
		mov	rax,[rsp+40]
		adc	rax,0
		mov	[rsp+32],rax
		mov	qword [rsp+40],0
	end repeat
	; t < 2m: t - m unless that borrows
	mov	r8,[rsp]
	mov	r9,[rsp+8]
	mov	r10,[rsp+16]
	mov	r11,[rsp+24]
	mov	rax,r8
	sub	rax,[r14]
	mov	rcx,r9
	sbb	rcx,[r14+8]
	mov	rdx,r10
	sbb	rdx,[r14+16]
	mov	r12,r11
	sbb	r12,[r14+24]
	mov	r13,[rsp+32]
	sbb	r13,0				; borrow: t < m, keep t
	sbb	r13,r13				; all ones then
	xor	r8,rax
	and	r8,r13
	xor	r8,rax
	xor	r9,rcx
	and	r9,r13
	xor	r9,rcx
	xor	r10,rdx
	and	r10,r13
	xor	r10,rdx
	xor	r11,r12
	and	r11,r13
	xor	r11,r12
	mov	[rdi],r8
	mov	[rdi+8],r9
	mov	[rdi+16],r10
	mov	[rdi+24],r11
	xor	eax,eax
	repeat 6, i:0
		mov	[rsp+i*8],rax
	end repeat
	add	rsp,48
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = out, rsi = a, rdx = b (below m), rcx = modulus: a + b mod m.
mod_add:
	push	rbx
	mov	r8,[rsi]
	add	r8,[rdx]
	mov	r9,[rsi+8]
	adc	r9,[rdx+8]
	mov	r10,[rsi+16]
	adc	r10,[rdx+16]
	mov	r11,[rsi+24]
	adc	r11,[rdx+24]
	sbb	rbx,rbx				; carry out: all ones
	mov	rax,r8
	sub	rax,[rcx]
	mov	rsi,r9
	sbb	rsi,[rcx+8]
	mov	rdx,r10
	sbb	rdx,[rcx+16]
	push	r12
	mov	r12,r11
	sbb	r12,[rcx+24]
	sbb	rcx,rcx				; borrow: all ones
	not	rbx
	and	rcx,rbx				; keep the sum: no carry and a borrow
	xor	r8,rax
	and	r8,rcx
	xor	r8,rax
	xor	r9,rsi
	and	r9,rcx
	xor	r9,rsi
	xor	r10,rdx
	and	r10,rcx
	xor	r10,rdx
	xor	r11,r12
	and	r11,rcx
	xor	r11,r12
	pop	r12
	mov	[rdi],r8
	mov	[rdi+8],r9
	mov	[rdi+16],r10
	mov	[rdi+24],r11
	pop	rbx
	ret

; rdi = out, rsi = a, rdx = b (below m), rcx = modulus: a - b mod m.
mod_sub:
	mov	r8,[rsi]
	sub	r8,[rdx]
	mov	r9,[rsi+8]
	sbb	r9,[rdx+8]
	mov	r10,[rsi+16]
	sbb	r10,[rdx+16]
	mov	r11,[rsi+24]
	sbb	r11,[rdx+24]
	sbb	rax,rax				; borrow: add m back
	push	rbx
	push	r12
	mov	rdx,[rcx]			; the masked modulus first: an 'and'
	and	rdx,rax				; in the add chain would clear its carry
	mov	rsi,[rcx+8]
	and	rsi,rax
	mov	rbx,[rcx+16]
	and	rbx,rax
	mov	r12,[rcx+24]
	and	r12,rax
	add	r8,rdx
	adc	r9,rsi
	adc	r10,rbx
	adc	r11,r12
	pop	r12
	pop	rbx
	mov	[rdi],r8
	mov	[rdi+8],r9
	mov	[rdi+16],r10
	mov	[rdi+24],r11
	ret

; rdi = out, rsi = a (Montgomery), rcx = modulus: a^(m-2) = 1/a, by 4-bit
; windows over the public exponent: a^1..a^15 first, then four squarings
; and at most one multiplication per nibble.
MI_POW		:= 0				; a^1 .. a^15 (a^j at (j - 1) * 32)
MI_R		:= 15 * 32
MI_SIZE		:= 16 * 32
mod_inv:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,MI_SIZE
	mov	r12,rdi
	mov	r14,rcx
	lea	rdi,[rsp+MI_POW]
	mov	ecx,4
	rep	movsq				; a^1
	mov	ebx,1
.powers:
	lea	rdi,[rsp+MI_POW+rbx*8]		; (rbx * 32 below)
	imul	rdi,rbx,32
	lea	rdi,[rsp+MI_POW+rdi]
	lea	rsi,[rdi-32]
	lea	rdx,[rsp+MI_POW]
	mov	rcx,r14
	call	mont_mul			; a^(j+1) = a^j * a
	inc	ebx
	cmp	ebx,15
	jb	.powers
	; r = 1 (Montgomery)
	lea	rsi,[r14+MOD_ONE]
	lea	rdi,[rsp+MI_R]
	mov	ecx,4
	rep	movsq
	mov	r15d,63				; nibble, from the top
.nibble:
	mov	ebx,4
.square:
	lea	rdi,[rsp+MI_R]
	mov	rsi,rdi
	mov	rcx,r14
	call	mont_sqr
	dec	ebx
	jnz	.square
	mov	eax,r15d
	shr	eax,4				; limb
	mov	rax,[r14+MOD_E+rax*8]
	mov	ecx,r15d
	and	ecx,15
	shl	ecx,2
	shr	rax,cl
	and	eax,15				; the exponent's nibble (public)
	jz	.next
	dec	eax
	shl	eax,5
	lea	rdi,[rsp+MI_R]
	mov	rsi,rdi
	lea	rdx,[rsp+MI_POW+rax]
	mov	rcx,r14
	call	mont_mul
.next:
	dec	r15d
	jns	.nibble
	mov	rdi,r12
	lea	rsi,[rsp+MI_R]
	mov	ecx,4
	rep	movsq
	mov	rdi,rsp
	mov	ecx,MI_SIZE
	call	secure_zero
	add	rsp,MI_SIZE
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

macro mod_add_inline
	push	rbx
	mov	r8,[rsi]
	add	r8,[rdx]
	mov	r9,[rsi+8]
	adc	r9,[rdx+8]
	mov	r10,[rsi+16]
	adc	r10,[rdx+16]
	mov	r11,[rsi+24]
	adc	r11,[rdx+24]
	sbb	rbx,rbx				; carry out: all ones
	mov	rax,r8
	sub	rax,[rcx]
	mov	rsi,r9
	sbb	rsi,[rcx+8]
	mov	rdx,r10
	sbb	rdx,[rcx+16]
	push	r12
	mov	r12,r11
	sbb	r12,[rcx+24]
	sbb	rcx,rcx				; borrow: all ones
	not	rbx
	and	rcx,rbx				; keep the sum: no carry and a borrow
	xor	r8,rax
	and	r8,rcx
	xor	r8,rax
	xor	r9,rsi
	and	r9,rcx
	xor	r9,rsi
	xor	r10,rdx
	and	r10,rcx
	xor	r10,rdx
	xor	r11,r12
	and	r11,rcx
	xor	r11,r12
	pop	r12
	mov	[rdi],r8
	mov	[rdi+8],r9
	mov	[rdi+16],r10
	mov	[rdi+24],r11
	pop	rbx
end macro

macro mod_sub_inline
	mov	r8,[rsi]
	sub	r8,[rdx]
	mov	r9,[rsi+8]
	sbb	r9,[rdx+8]
	mov	r10,[rsi+16]
	sbb	r10,[rdx+16]
	mov	r11,[rsi+24]
	sbb	r11,[rdx+24]
	sbb	rax,rax				; borrow: add m back
	push	rbx
	push	r12
	mov	rdx,[rcx]			; the masked modulus first: an 'and'
	and	rdx,rax				; in the add chain would clear its carry
	mov	rsi,[rcx+8]
	and	rsi,rax
	mov	rbx,[rcx+16]
	and	rbx,rax
	mov	r12,[rcx+24]
	and	r12,rax
	add	r8,rdx
	adc	r9,rsi
	adc	r10,rbx
	adc	r11,r12
	pop	r12
	pop	rbx
	mov	[rdi],r8
	mov	[rdi+8],r9
	mov	[rdi+16],r10
	mov	[rdi+24],r11
end macro

; Field operations on p, for the point formulas below (additions and
; subtractions inline, multiplications called).
macro F op*, d*, a*, b
	lea	rdi,[d]
	lea	rsi,[a]
	match any, b
		lea	rdx,[b]
	end match
	lea	rcx,[p256_p]
	match =mod_add, op
		mod_add_inline
	else match =mod_sub, op
		mod_sub_inline
	else
		call	op
	end match
end macro

PT_X		:= 0
PT_Y		:= 32
PT_Z		:= 64
PT_SIZE		:= 96

; rdi = out, rsi = P, rdx = Q (projective, Montgomery): P + Q, complete
; (P = Q and the point at infinity included). out may be P or Q.
PA_T0		:= 0
PA_T1		:= 32
PA_T2		:= 64
PA_T3		:= 96
PA_T4		:= 128
PA_X3		:= 160
PA_Y3		:= 192
PA_Z3		:= 224
PA_SIZE		:= 256
p256_add:
	push	rbx
	push	r12
	push	r13
	push	r14
	sub	rsp,PA_SIZE
	mov	rbx,rsp
	mov	r14,rdi
	mov	r12,rsi
	mov	r13,rdx
	F mont_mul, rbx+PA_T0, r12+PT_X, r13+PT_X	; t0 = X1 X2
	F mont_mul, rbx+PA_T1, r12+PT_Y, r13+PT_Y	; t1 = Y1 Y2
	F mont_mul, rbx+PA_T2, r12+PT_Z, r13+PT_Z	; t2 = Z1 Z2
	F mod_add, rbx+PA_T3, r12+PT_X, r12+PT_Y	; t3 = X1 + Y1
	F mod_add, rbx+PA_T4, r13+PT_X, r13+PT_Y	; t4 = X2 + Y2
	F mont_mul, rbx+PA_T3, rbx+PA_T3, rbx+PA_T4	; t3 = t3 t4
	F mod_add, rbx+PA_T4, rbx+PA_T0, rbx+PA_T1	; t4 = t0 + t1
	F mod_sub, rbx+PA_T3, rbx+PA_T3, rbx+PA_T4	; t3 = t3 - t4
	F mod_add, rbx+PA_T4, r12+PT_Y, r12+PT_Z	; t4 = Y1 + Z1
	F mod_add, rbx+PA_X3, r13+PT_Y, r13+PT_Z	; X3 = Y2 + Z2
	F mont_mul, rbx+PA_T4, rbx+PA_T4, rbx+PA_X3	; t4 = t4 X3
	F mod_add, rbx+PA_X3, rbx+PA_T1, rbx+PA_T2	; X3 = t1 + t2
	F mod_sub, rbx+PA_T4, rbx+PA_T4, rbx+PA_X3	; t4 = t4 - X3
	F mod_add, rbx+PA_X3, r12+PT_X, r12+PT_Z	; X3 = X1 + Z1
	F mod_add, rbx+PA_Y3, r13+PT_X, r13+PT_Z	; Y3 = X2 + Z2
	F mont_mul, rbx+PA_X3, rbx+PA_X3, rbx+PA_Y3	; X3 = X3 Y3
	F mod_add, rbx+PA_Y3, rbx+PA_T0, rbx+PA_T2	; Y3 = t0 + t2
	F mod_sub, rbx+PA_Y3, rbx+PA_X3, rbx+PA_Y3	; Y3 = X3 - Y3
	F mont_mul, rbx+PA_Z3, p256_b_m, rbx+PA_T2	; Z3 = b t2
	F mod_sub, rbx+PA_X3, rbx+PA_Y3, rbx+PA_Z3	; X3 = Y3 - Z3
	F mod_add, rbx+PA_Z3, rbx+PA_X3, rbx+PA_X3	; Z3 = X3 + X3
	F mod_add, rbx+PA_X3, rbx+PA_X3, rbx+PA_Z3	; X3 = X3 + Z3
	F mod_sub, rbx+PA_Z3, rbx+PA_T1, rbx+PA_X3	; Z3 = t1 - X3
	F mod_add, rbx+PA_X3, rbx+PA_T1, rbx+PA_X3	; X3 = t1 + X3
	F mont_mul, rbx+PA_Y3, p256_b_m, rbx+PA_Y3	; Y3 = b Y3
	F mod_add, rbx+PA_T1, rbx+PA_T2, rbx+PA_T2	; t1 = t2 + t2
	F mod_add, rbx+PA_T2, rbx+PA_T1, rbx+PA_T2	; t2 = t1 + t2
	F mod_sub, rbx+PA_Y3, rbx+PA_Y3, rbx+PA_T2	; Y3 = Y3 - t2
	F mod_sub, rbx+PA_Y3, rbx+PA_Y3, rbx+PA_T0	; Y3 = Y3 - t0
	F mod_add, rbx+PA_T1, rbx+PA_Y3, rbx+PA_Y3	; t1 = Y3 + Y3
	F mod_add, rbx+PA_Y3, rbx+PA_T1, rbx+PA_Y3	; Y3 = t1 + Y3
	F mod_add, rbx+PA_T1, rbx+PA_T0, rbx+PA_T0	; t1 = t0 + t0
	F mod_add, rbx+PA_T0, rbx+PA_T1, rbx+PA_T0	; t0 = t1 + t0
	F mod_sub, rbx+PA_T0, rbx+PA_T0, rbx+PA_T2	; t0 = t0 - t2
	F mont_mul, rbx+PA_T1, rbx+PA_T4, rbx+PA_Y3	; t1 = t4 Y3
	F mont_mul, rbx+PA_T2, rbx+PA_T0, rbx+PA_Y3	; t2 = t0 Y3
	F mont_mul, rbx+PA_Y3, rbx+PA_X3, rbx+PA_Z3	; Y3 = X3 Z3
	F mod_add, rbx+PA_Y3, rbx+PA_Y3, rbx+PA_T2	; Y3 = Y3 + t2
	F mont_mul, rbx+PA_X3, rbx+PA_T3, rbx+PA_X3	; X3 = t3 X3
	F mod_sub, rbx+PA_X3, rbx+PA_X3, rbx+PA_T1	; X3 = X3 - t1
	F mont_mul, rbx+PA_Z3, rbx+PA_T4, rbx+PA_Z3	; Z3 = t4 Z3
	F mont_mul, rbx+PA_T1, rbx+PA_T3, rbx+PA_T0	; t1 = t3 t0
	F mod_add, rbx+PA_Z3, rbx+PA_Z3, rbx+PA_T1	; Z3 = Z3 + t1
	mov	rdi,r14
	lea	rsi,[rbx+PA_X3]
	mov	ecx,12
	rep	movsq
	mov	rdi,rsp
	mov	ecx,PA_SIZE
	call	secure_zero
	add	rsp,PA_SIZE
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = a, rsi = b (PT_SIZE each), rdx = 0 or all ones: swapped then.
pt_cswap:
	repeat 12, i:0
		mov	rax,[rdi+i*8]
		mov	rcx,[rsi+i*8]
		mov	r8,rax
		xor	r8,rcx
		and	r8,rdx
		xor	rax,r8
		xor	rcx,r8
		mov	[rdi+i*8],rax
		mov	[rsi+i*8],rcx
	end repeat
	ret

; rdi = out x[4] and out y[4] (affine, plain), rsi = k (4 limbs): k * G
; by the Montgomery ladder (kept for multiplying other points).
ML_R0		:= 0
ML_R1		:= PT_SIZE
ML_ZI		:= 2 * PT_SIZE
ML_SIZE		:= 2 * PT_SIZE + 32
p256_mul_g_ladder:
	push	rbx
	push	r12
	push	r13
	push	r14
	sub	rsp,ML_SIZE
	mov	r12,rdi
	mov	r13,rsi
	; R0 = infinity (0 : 1 : 0), R1 = G
	xor	eax,eax
	repeat 12, i:0
		mov	[rsp+ML_R0+i*8],rax
	end repeat
	lea	rsi,[p256_p+MOD_ONE]
	lea	rdi,[rsp+ML_R0+PT_Y]
	mov	ecx,4
	rep	movsq
	lea	rsi,[p256_g_m]
	lea	rdi,[rsp+ML_R1]
	mov	ecx,12
	rep	movsq
	mov	ebx,255
.bit:
	mov	eax,ebx
	shr	eax,6
	mov	rax,[r13+rax*8]
	mov	ecx,ebx
	shr	rax,cl
	and	eax,1
	neg	rax				; 0 or all ones: this bit, as a mask
	mov	r14,rax
	lea	rdi,[rsp+ML_R0]
	lea	rsi,[rsp+ML_R1]
	mov	rdx,r14
	call	pt_cswap
	lea	rdi,[rsp+ML_R1]
	lea	rsi,[rsp+ML_R0]
	lea	rdx,[rsp+ML_R1]
	call	p256_add			; R1 = R0 + R1
	lea	rdi,[rsp+ML_R0]
	lea	rsi,[rsp+ML_R0]
	lea	rdx,[rsp+ML_R0]
	call	p256_add			; R0 = 2 R0
	lea	rdi,[rsp+ML_R0]
	lea	rsi,[rsp+ML_R1]
	mov	rdx,r14
	call	pt_cswap
	dec	ebx
	jns	.bit
	; affine: x = X / Z, y = Y / Z, out of Montgomery form
	lea	rdi,[rsp+ML_ZI]
	lea	rsi,[rsp+ML_R0+PT_Z]
	lea	rcx,[p256_p]
	call	mod_inv
	F mont_mul, rsp+ML_R0+PT_X, rsp+ML_R0+PT_X, rsp+ML_ZI
	F mont_mul, rsp+ML_R0+PT_Y, rsp+ML_R0+PT_Y, rsp+ML_ZI
	F mont_mul, r12, rsp+ML_R0+PT_X, p256_one
	F mont_mul, r12+32, rsp+ML_R0+PT_Y, p256_one
	mov	rdi,rsp
	mov	ecx,ML_SIZE
	call	secure_zero
	add	rsp,ML_SIZE
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; The fixed-base table (tools/gen_p256_table.py): for each of 37 windows
; of 7 bits, j * 2^(7i) * G for j = 1..64, affine, Montgomery form (the
; layout of OpenSSL's ecp_nistz256).
TW_COUNT	:= 37
TW_ENTRIES	:= 64
TW_ENTRY	:= 64				; x, y
TW_SIZE		:= TW_ENTRIES * TW_ENTRY
rodata
	align 64
	p256_table:
	file 'p256_table.bin'
	assert $ - p256_table = TW_COUNT * TW_SIZE
	align 32
	p256_zero	dq 0, 0, 0, 0
end rodata

; rdi = out (x, y), esi = |digit| (0..64), rdx = its window: the entry for
; the digit, zero for 0. Reads every entry whatever the digit.
p256_select:
	mov	eax,esi
	vmovq	xmm0,rax
	vpbroadcastq ymm0,xmm0			; the digit
	mov	eax,1
	vmovq	xmm4,rax
	vpbroadcastq ymm4,xmm4			; 1
	vmovdqa	ymm3,ymm4			; j
	vpxor	ymm1,ymm1,ymm1
	vpxor	ymm2,ymm2,ymm2
	mov	ecx,TW_ENTRIES
.entry:
	vpcmpeqq ymm5,ymm3,ymm0			; all ones when j = digit
	vpand	ymm6,ymm5,[rdx]
	vpor	ymm1,ymm1,ymm6
	vpand	ymm6,ymm5,[rdx+32]
	vpor	ymm2,ymm2,ymm6
	vpaddq	ymm3,ymm3,ymm4
	add	rdx,TW_ENTRY
	dec	ecx
	jnz	.entry
	vmovdqu	[rdi],ymm1
	vmovdqu	[rdi+32],ymm2
	vpxor	ymm1,ymm1,ymm1
	vpxor	ymm2,ymm2,ymm2
	vzeroupper
	ret

; 12 qwords at [rsp+d] = mask ? [rsp+a] : [rsp+d] (rax = 0 or all ones).
macro pt_select_into d*, a*
	repeat 12, q:0
		mov	rcx,[rsp+d+q*8]
		mov	rdx,[rsp+a+q*8]
		xor	rdx,rcx
		and	rdx,rax
		xor	rcx,rdx
		mov	[rsp+d+q*8],rcx
	end repeat
end macro

; rdi = out x[4] and out y[4] (affine, plain), rsi = k (4 limbs): k * G as
; the sum of one signed table entry per window: 37 constant-time
; selections and Jacobian mixed additions (7M + 4S), no doubling. The
; addition's special cases are handled by masks where they can occur (a
; zero digit; the accumulator still at infinity); P = +-Q cannot occur
; for the scalars signed here (uniform nonces, private keys) but with
; probability 2^-256.
MG_ACC		:= 0				; Jacobian X, Y, Z
MG_SUM		:= 96
MG_JS		:= 192				; the selected entry as (x : y : 1)
MG_SEL		:= MG_JS			; (x, y in its first 64 bytes)
MG_K2		:= 288				; 2k, 6 limbs (bit -1 of the windows = 0)
MG_NY		:= 336				; -y
MG_Z1Z1		:= 368
MG_U2		:= 400
MG_S2		:= 432
MG_H		:= 464
MG_HH		:= 496
MG_I		:= 528
MG_J		:= 560
MG_R		:= 592
MG_V		:= 624
MG_T		:= 656
MG_INF		:= 688				; all ones while acc is still infinity
MG_DIG		:= 696				; |digit|, sign mask
MG_SIGN		:= 704
MG_SIZE		:= 712
macro M op*, d*, a*, b
	F op, rsp+d, rsp+a, b
end macro
p256_mul_g:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,MG_SIZE
	mov	r12,rdi
	; 2k, so the window i reads bits 7i - 1 .. 7i + 6 of k at offset 7i
	mov	rax,[rsi]
	mov	rcx,[rsi+8]
	mov	rdx,[rsi+16]
	mov	r8,[rsi+24]
	xor	r9d,r9d
	shld	r9,r8,1
	shld	r8,rdx,1
	shld	rdx,rcx,1
	shld	rcx,rax,1
	shl	rax,1
	mov	[rsp+MG_K2],rax
	mov	[rsp+MG_K2+8],rcx
	mov	[rsp+MG_K2+16],rdx
	mov	[rsp+MG_K2+24],r8
	mov	[rsp+MG_K2+32],r9
	mov	qword [rsp+MG_K2+40],0
	mov	qword [rsp+MG_INF],-1
	; the selected entry's Z is always 1
	lea	rsi,[p256_p+MOD_ONE]
	lea	rdi,[rsp+MG_JS+PT_Z]
	mov	ecx,4
	rep	movsq
	xor	eax,eax
	repeat 12, q:0
		mov	[rsp+MG_ACC+q*8],rax
	end repeat
	xor	ebx,ebx				; window
	lea	r13,[p256_table]
.window:
	; Booth recoding of 8 bits (OpenSSL's _booth_recode_w7), constant time
	imul	eax,ebx,7
	mov	ecx,eax
	shr	eax,6
	mov	rdx,[rsp+MG_K2+rax*8]
	mov	r8,[rsp+MG_K2+rax*8+8]
	and	ecx,63
	shrd	rdx,r8,cl
	and	edx,0xFF			; in
	mov	eax,edx
	shr	eax,7
	dec	eax
	not	eax				; s: all ones when in >= 128
	mov	ecx,255
	sub	ecx,edx				; 255 - in
	and	ecx,eax
	not	eax
	and	edx,eax
	not	eax
	or	ecx,edx				; d
	mov	edx,ecx
	shr	ecx,1
	and	edx,1
	add	ecx,edx				; |digit|, 0 .. 64
	and	eax,1				; sign
	mov	[rsp+MG_DIG],ecx
	neg	rax
	mov	[rsp+MG_SIGN],rax
	; the entry, y negated for a negative digit
	lea	rdi,[rsp+MG_SEL]
	mov	esi,ecx
	mov	rdx,r13
	call	p256_select
	F mod_sub, rsp+MG_NY, p256_zero, rsp+MG_SEL+32	; -y = 0 - y
	mov	rax,[rsp+MG_SIGN]
	repeat 4, q:0
		mov	rcx,[rsp+MG_SEL+32+q*8]
		mov	rdx,[rsp+MG_NY+q*8]
		xor	rdx,rcx
		and	rdx,rax
		xor	rcx,rdx
		mov	[rsp+MG_SEL+32+q*8],rcx
	end repeat
	; SUM = ACC + (x2, y2): madd-2007-bl
	M mont_sqr, MG_Z1Z1, MG_ACC+PT_Z
	M mont_mul, MG_U2, MG_SEL, rsp+MG_Z1Z1
	M mont_mul, MG_T, MG_ACC+PT_Z, rsp+MG_Z1Z1
	M mont_mul, MG_S2, MG_SEL+32, rsp+MG_T
	M mod_sub, MG_H, MG_U2, rsp+MG_ACC+PT_X
	M mont_sqr, MG_HH, MG_H
	M mod_add, MG_I, MG_HH, rsp+MG_HH
	M mod_add, MG_I, MG_I, rsp+MG_I
	M mont_mul, MG_J, MG_H, rsp+MG_I
	M mod_sub, MG_R, MG_S2, rsp+MG_ACC+PT_Y
	M mod_add, MG_R, MG_R, rsp+MG_R
	M mont_mul, MG_V, MG_ACC+PT_X, rsp+MG_I
	M mont_sqr, MG_SUM+PT_X, MG_R
	M mod_sub, MG_SUM+PT_X, MG_SUM+PT_X, rsp+MG_J
	M mod_sub, MG_SUM+PT_X, MG_SUM+PT_X, rsp+MG_V
	M mod_sub, MG_SUM+PT_X, MG_SUM+PT_X, rsp+MG_V
	M mod_sub, MG_T, MG_V, rsp+MG_SUM+PT_X
	M mont_mul, MG_SUM+PT_Y, MG_R, rsp+MG_T
	M mont_mul, MG_T, MG_ACC+PT_Y, rsp+MG_J
	M mod_add, MG_T, MG_T, rsp+MG_T
	M mod_sub, MG_SUM+PT_Y, MG_SUM+PT_Y, rsp+MG_T
	M mod_add, MG_T, MG_ACC+PT_Z, rsp+MG_H
	M mont_sqr, MG_SUM+PT_Z, MG_T
	M mod_sub, MG_SUM+PT_Z, MG_SUM+PT_Z, rsp+MG_Z1Z1
	M mod_sub, MG_SUM+PT_Z, MG_SUM+PT_Z, rsp+MG_HH
	; acc still infinity: the sum is the entry itself
	mov	rax,[rsp+MG_INF]
	pt_select_into MG_SUM, MG_JS
	; a zero digit: acc unchanged
	mov	eax,[rsp+MG_DIG]
	neg	eax
	sbb	rax,rax				; all ones when the digit is not 0
	pt_select_into MG_ACC, MG_SUM
	not	rax
	and	[rsp+MG_INF],rax		; infinity only while digits are 0
	add	r13,TW_SIZE
	inc	ebx
	cmp	ebx,TW_COUNT
	jb	.window
	; affine: x = X / Z^2, y = Y / Z^3, out of Montgomery form
	lea	rdi,[rsp+MG_T]
	lea	rsi,[rsp+MG_ACC+PT_Z]
	lea	rcx,[p256_p]
	call	mod_inv
	M mont_sqr, MG_Z1Z1, MG_T			; 1/Z^2
	M mont_mul, MG_U2, MG_Z1Z1, rsp+MG_T		; 1/Z^3
	M mont_mul, MG_ACC+PT_X, MG_ACC+PT_X, rsp+MG_Z1Z1
	M mont_mul, MG_ACC+PT_Y, MG_ACC+PT_Y, rsp+MG_U2
	F mont_mul, r12, rsp+MG_ACC+PT_X, p256_one
	F mont_mul, r12+32, rsp+MG_ACC+PT_Y, p256_one
	mov	rdi,rsp
	mov	ecx,MG_SIZE
	call	secure_zero
	add	rsp,MG_SIZE
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = 4 limbs, rsi = 32 bytes big endian.
be_to_limbs:
	repeat 4, i:0
		mov	rax,[rsi+(3-i)*8]
		bswap	rax
		mov	[rdi+i*8],rax
	end repeat
	ret

; rdi = 32 bytes big endian, rsi = 4 limbs.
limbs_to_be:
	repeat 4, i:0
		mov	rax,[rsi+i*8]
		bswap	rax
		mov	[rdi+(3-i)*8],rax
	end repeat
	ret

; rdi = a (4 limbs, in place), rsi = modulus: a - m when a >= m (a < 2m).
mod_reduce_once:
	mov	r8,[rdi]
	sub	r8,[rsi]
	mov	r9,[rdi+8]
	sbb	r9,[rsi+8]
	mov	r10,[rdi+16]
	sbb	r10,[rsi+16]
	mov	r11,[rdi+24]
	sbb	r11,[rsi+24]
	sbb	rax,rax				; borrow: a < m, keep a
	irp <off,reg>, 0,r8, 8,r9, 16,r10, 24,r11
		mov	rcx,[rdi+off]
		xor	rcx,reg
		and	rcx,rax
		xor	rcx,reg
		mov	[rdi+off],rcx
	end irp
	ret

; rdi = 4 limbs: eax = 1 when 0 < a < n.
scalar_in_range:
	mov	rax,[rdi]
	or	rax,[rdi+8]
	or	rax,[rdi+16]
	or	rax,[rdi+24]
	jz	.no
	mov	r8,[rdi]
	sub	r8,[p256_n]
	mov	r8,[rdi+8]
	sbb	r8,[p256_n+8]
	mov	r8,[rdi+16]
	sbb	r8,[p256_n+16]
	mov	r8,[rdi+24]
	sbb	r8,[p256_n+24]
	jnc	.no				; a >= n
	mov	eax,1
	ret
.no:
	xor	eax,eax
	ret

; rdi = out[65], rsi = d[32] (big endian).
p256_public:
	push	rbx
	push	r12
	sub	rsp,96
	mov	rbx,rdi
	lea	rdi,[rsp+64]
	call	be_to_limbs
	mov	rdi,rsp
	lea	rsi,[rsp+64]
	call	p256_mul_g
	mov	byte [rbx],4
	lea	rdi,[rbx+1]
	mov	rsi,rsp
	call	limbs_to_be
	lea	rdi,[rbx+33]
	lea	rsi,[rsp+32]
	call	limbs_to_be
	mov	rdi,rsp
	mov	ecx,96
	call	secure_zero
	add	rsp,96
	pop	r12
	pop	rbx
	ret

; rdi = out x[32] big endian (the shared secret), rsi = scalar[32] big
; endian (in [1, n-1]), rdx = peer point 04|X|Y (65 bytes, big endian): the
; x coordinate of scalar * peer, for TLS secp256r1 ECDHE. eax = 1, or 0
; when the point is invalid (not uncompressed, a coordinate >= p, or off
; the curve). The ladder uses the complete addition formula, so no branch
; depends on the scalar. Everything on the stack is wiped.
EC_R1		:= 0				; peer, Montgomery projective (X : Y : Z)
EC_R0		:= PT_SIZE			; accumulator: infinity, then the result
EC_ZI		:= 2 * PT_SIZE
EC_K		:= 2 * PT_SIZE + 32		; the scalar, limbs
EC_T0		:= 2 * PT_SIZE + 64
EC_T1		:= 2 * PT_SIZE + 96
EC_OUT		:= 2 * PT_SIZE + 128		; q
EC_SCA		:= 2 * PT_SIZE + 136		; q
EC_SIZE		:= 2 * PT_SIZE + 160
macro E op*, d*, a*, b
	F op, rsp+d, rsp+a, rsp+b
end macro
p256_ecdh:
	push	rbx
	push	r12
	push	r13
	push	r14
	sub	rsp,EC_SIZE
	mov	[rsp+EC_OUT],rdi
	mov	[rsp+EC_SCA],rsi
	mov	r13,rdx
	cmp	byte [r13],4			; uncompressed only
	jne	.bad
	lea	rdi,[rsp+EC_R1+PT_X]
	lea	rsi,[r13+1]
	call	be_to_limbs
	lea	rdi,[rsp+EC_R1+PT_X]
	call	.below_p
	jc	.bad
	lea	rdi,[rsp+EC_R1+PT_Y]
	lea	rsi,[r13+33]
	call	be_to_limbs
	lea	rdi,[rsp+EC_R1+PT_Y]
	call	.below_p
	jc	.bad
	; to Montgomery, Z = Montgomery one
	lea	rdi,[rsp+EC_R1+PT_X]
	mov	rsi,rdi
	lea	rdx,[p256_p+40]
	lea	rcx,[p256_p]
	call	mont_mul
	lea	rdi,[rsp+EC_R1+PT_Y]
	mov	rsi,rdi
	lea	rdx,[p256_p+40]
	lea	rcx,[p256_p]
	call	mont_mul
	lea	rsi,[p256_p+MOD_ONE]
	lea	rdi,[rsp+EC_R1+PT_Z]
	mov	ecx,4
	rep	movsq
	; on the curve: Y^2 == X^3 - 3X + b (Montgomery)
	E mont_mul, EC_T0, EC_R1+PT_X, EC_R1+PT_X
	E mont_mul, EC_T0, EC_T0, EC_R1+PT_X		; X^3
	E mod_add, EC_T1, EC_R1+PT_X, EC_R1+PT_X
	E mod_add, EC_T1, EC_T1, EC_R1+PT_X		; 3X
	E mod_sub, EC_T0, EC_T0, EC_T1
	F mod_add, rsp+EC_T0, rsp+EC_T0, p256_b_m	; rhs = X^3 - 3X + b
	E mont_mul, EC_T1, EC_R1+PT_Y, EC_R1+PT_Y	; lhs = Y^2
	lea	rsi,[rsp+EC_T0]
	lea	rdi,[rsp+EC_T1]
	xor	eax,eax
	repeat 4, i:0
		mov	r8,[rsi+i*8]
		xor	r8,[rdi+i*8]
		or	rax,r8
	end repeat
	test	rax,rax
	jnz	.bad				; off the curve
	; R0 = infinity (0 : 1 : 0); the scalar to limbs
	xor	eax,eax
	repeat 12, i:0
		mov	[rsp+EC_R0+i*8],rax
	end repeat
	lea	rsi,[p256_p+MOD_ONE]
	lea	rdi,[rsp+EC_R0+PT_Y]
	mov	ecx,4
	rep	movsq
	lea	rdi,[rsp+EC_K]
	mov	rsi,[rsp+EC_SCA]
	call	be_to_limbs
	; the Montgomery ladder over R1 = the peer point
	mov	ebx,255
.bit:
	mov	eax,ebx
	shr	eax,6
	mov	rax,[rsp+EC_K+rax*8]
	mov	ecx,ebx
	shr	rax,cl
	and	eax,1
	neg	rax				; this bit, as a mask
	mov	r14,rax
	lea	rdi,[rsp+EC_R0]
	lea	rsi,[rsp+EC_R1]
	mov	rdx,r14
	call	pt_cswap
	lea	rdi,[rsp+EC_R1]
	lea	rsi,[rsp+EC_R0]
	lea	rdx,[rsp+EC_R1]
	call	p256_add			; R1 = R0 + R1
	lea	rdi,[rsp+EC_R0]
	lea	rsi,[rsp+EC_R0]
	lea	rdx,[rsp+EC_R0]
	call	p256_add			; R0 = 2 R0
	lea	rdi,[rsp+EC_R0]
	lea	rsi,[rsp+EC_R1]
	mov	rdx,r14
	call	pt_cswap
	dec	ebx
	jns	.bit
	; x = X / Z, out of Montgomery form, big endian
	lea	rdi,[rsp+EC_ZI]
	lea	rsi,[rsp+EC_R0+PT_Z]
	lea	rcx,[p256_p]
	call	mod_inv
	E mont_mul, EC_R0+PT_X, EC_R0+PT_X, EC_ZI
	lea	rdi,[rsp+EC_R0+PT_X]
	mov	rsi,rdi
	lea	rdx,[p256_one]
	lea	rcx,[p256_p]
	call	mont_mul
	mov	rdi,[rsp+EC_OUT]
	lea	rsi,[rsp+EC_R0+PT_X]
	call	limbs_to_be
	mov	eax,1
	jmp	.out
.bad:
	xor	eax,eax
.out:
	push	rax
	mov	rdi,rsp
	mov	ecx,EC_SIZE
	add	rdi,8				; keep the pushed rax
	call	secure_zero
	pop	rax
	add	rsp,EC_SIZE
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = 4 limbs: CF set when the value is >= p (invalid coordinate).
.below_p:
	mov	r8,[rdi]
	sub	r8,[p256_p]
	mov	r8,[rdi+8]
	sbb	r8,[p256_p+8]
	mov	r8,[rdi+16]
	sbb	r8,[p256_p+16]
	mov	r8,[rdi+24]
	sbb	r8,[p256_p+24]
	cmc					; borrow (value<p) -> CF clear
	ret

; rdi = out projective (96, Montgomery), rsi = scalar limbs, rdx = base
; projective (96, Montgomery): scalar * base by the Montgomery ladder,
; reusing p256_add and pt_cswap.
VL_R0		:= 0
VL_R1		:= PT_SIZE
VL_SIZE		:= 2 * PT_SIZE
p256_ladder:
	push	rbx
	push	r12
	push	r13
	push	r14
	sub	rsp,VL_SIZE
	mov	r12,rdi
	mov	r13,rsi
	lea	rdi,[rsp+VL_R1]			; R1 = base
	mov	rsi,rdx
	mov	ecx,12
	rep	movsq
	xor	eax,eax				; R0 = infinity (0 : 1 : 0)
	repeat 12, i:0
		mov	[rsp+VL_R0+i*8],rax
	end repeat
	lea	rsi,[p256_p+MOD_ONE]
	lea	rdi,[rsp+VL_R0+PT_Y]
	mov	ecx,4
	rep	movsq
	mov	ebx,255
.bit:
	mov	eax,ebx
	shr	eax,6
	mov	rax,[r13+rax*8]
	mov	ecx,ebx
	shr	rax,cl
	and	eax,1
	neg	rax
	mov	r14,rax
	lea	rdi,[rsp+VL_R0]
	lea	rsi,[rsp+VL_R1]
	mov	rdx,r14
	call	pt_cswap
	lea	rdi,[rsp+VL_R1]
	lea	rsi,[rsp+VL_R0]
	lea	rdx,[rsp+VL_R1]
	call	p256_add
	lea	rdi,[rsp+VL_R0]
	lea	rsi,[rsp+VL_R0]
	lea	rdx,[rsp+VL_R0]
	call	p256_add
	lea	rdi,[rsp+VL_R0]
	lea	rsi,[rsp+VL_R1]
	mov	rdx,r14
	call	pt_cswap
	dec	ebx
	jns	.bit
	mov	rdi,r12
	lea	rsi,[rsp+VL_R0]
	mov	ecx,12
	rep	movsq
	add	rsp,VL_SIZE
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; ECDSA P-256 / SHA-256 verification (FIPS 186-5). rdi = public key
; 04|X|Y (65 bytes), rsi = digest[32] big endian, rdx = r[32] big endian,
; rcx = s[32] big endian. eax = 1 when the signature is valid, else 0.
; w = s^-1 mod n; u1 = e w, u2 = r w; R = u1 G + u2 Q; valid iff
; x(R) mod n == r. Public data: variable time throughout (u1 G by the
; fixed-base table, u2 Q by a NAF in Jacobian coordinates).
VF_QP		:= 0				; Q projective Montgomery
VF_P1		:= PT_SIZE			; u1 * G
VF_P2		:= 2 * PT_SIZE			; u2 * Q
VF_SUM		:= 3 * PT_SIZE			; their sum
VF_R		:= 4 * PT_SIZE			; r limbs
VF_S		:= VF_R + 32
VF_E		:= VF_R + 64			; e (digest mod n)
VF_W		:= VF_R + 96			; s^-1
VF_U		:= VF_R + 128			; a scalar (u1, then u2)
VF_ZI		:= VF_R + 160
VF_X		:= VF_R + 192			; x(R) limbs
VF_T		:= VF_R + 224
VF_SIZE		:= ((VF_R + 256 + 15) and not 15) + 8
p256_verify:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,VF_SIZE
	mov	rbx,rdi				; Q
	mov	r14,rdx				; r be
	mov	r15,rcx				; s be
	mov	r13,rsi				; digest be
	lea	rdi,[rsp+VF_R]
	mov	rsi,r14
	call	be_to_limbs
	lea	rdi,[rsp+VF_R]
	call	scalar_in_range
	test	eax,eax
	jz	.bad
	lea	rdi,[rsp+VF_S]
	mov	rsi,r15
	call	be_to_limbs
	lea	rdi,[rsp+VF_S]
	call	scalar_in_range
	test	eax,eax
	jz	.bad
	lea	rdi,[rsp+VF_E]			; e = digest mod n
	mov	rsi,r13
	call	be_to_limbs
	lea	rdi,[rsp+VF_E]
	lea	rsi,[p256_n]
	call	mod_reduce_once
	lea	rdi,[rsp+VF_W]			; w = s^-1 mod n (rdi out, rsi in)
	lea	rsi,[rsp+VF_S]
	call	mod_inv_n_vartime
	cmp	byte [rbx],4			; load and validate Q
	jne	.bad
	lea	rdi,[rsp+VF_QP+PT_X]
	lea	rsi,[rbx+1]
	call	be_to_limbs
	lea	rdi,[rsp+VF_QP+PT_X]
	call	vf_below_p
	jc	.bad
	lea	rdi,[rsp+VF_QP+PT_Y]
	lea	rsi,[rbx+33]
	call	be_to_limbs
	lea	rdi,[rsp+VF_QP+PT_Y]
	call	vf_below_p
	jc	.bad
	lea	rdi,[rsp+VF_QP+PT_X]
	mov	rsi,rdi
	lea	rdx,[p256_p+40]
	lea	rcx,[p256_p]
	call	mont_mul
	lea	rdi,[rsp+VF_QP+PT_Y]
	mov	rsi,rdi
	lea	rdx,[p256_p+40]
	lea	rcx,[p256_p]
	call	mont_mul
	lea	rsi,[p256_p+MOD_ONE]
	lea	rdi,[rsp+VF_QP+PT_Z]
	mov	ecx,4
	rep	movsq
	E mont_mul, VF_T, VF_QP+PT_X, VF_QP+PT_X		; on the curve?
	E mont_mul, VF_T, VF_T, VF_QP+PT_X
	E mod_add, VF_ZI, VF_QP+PT_X, VF_QP+PT_X
	E mod_add, VF_ZI, VF_ZI, VF_QP+PT_X
	E mod_sub, VF_T, VF_T, VF_ZI
	F mod_add, rsp+VF_T, rsp+VF_T, p256_b_m
	E mont_mul, VF_ZI, VF_QP+PT_Y, VF_QP+PT_Y
	lea	rsi,[rsp+VF_T]
	lea	rdi,[rsp+VF_ZI]
	xor	eax,eax
	repeat 4, i:0
		mov	r8,[rsi+i*8]
		xor	r8,[rdi+i*8]
		or	rax,r8
	end repeat
	test	rax,rax
	jnz	.bad
	lea	r12,[p256_n]			; u1 = e w mod n, then u1 G
	lea	rdi,[rsp+VF_U]
	lea	rsi,[rsp+VF_E]
	lea	rdx,[r12+MOD_RR]
	mov	rcx,r12
	call	mont_mul
	lea	rdi,[rsp+VF_U]
	lea	rsi,[rsp+VF_U]
	lea	rdx,[rsp+VF_W]
	mov	rcx,r12
	call	mont_mul
	vt_iszero rsp+VF_U			; u1 G by the fixed-base table, as
	jnz	@f				; (x : y : 1); u1 = 0 is infinity
	xor	eax,eax
	lea	rdi,[rsp+VF_P1]
	mov	ecx,12
	rep	stosq
	jmp	.u2
@@:
	lea	rdi,[rsp+VF_P1]
	lea	rsi,[rsp+VF_U]
	call	p256_mul_g
	lea	rdi,[rsp+VF_P1+PT_X]
	mov	rsi,rdi
	lea	rdx,[p256_p+MOD_RR]
	lea	rcx,[p256_p]
	call	mont_mul
	lea	rdi,[rsp+VF_P1+PT_Y]
	mov	rsi,rdi
	lea	rdx,[p256_p+MOD_RR]
	lea	rcx,[p256_p]
	call	mont_mul
	lea	rsi,[p256_p+MOD_ONE]
	lea	rdi,[rsp+VF_P1+PT_Z]
	mov	ecx,4
	rep	movsq
.u2:
	lea	r12,[p256_n]			; u2 = r w mod n, then u2 Q
	lea	rdi,[rsp+VF_U]
	lea	rsi,[rsp+VF_R]
	lea	rdx,[r12+MOD_RR]
	mov	rcx,r12
	call	mont_mul
	lea	rdi,[rsp+VF_U]
	lea	rsi,[rsp+VF_U]
	lea	rdx,[rsp+VF_W]
	mov	rcx,r12
	call	mont_mul
	lea	rdi,[rsp+VF_P2]			; u2 Q, variable time
	lea	rsi,[rsp+VF_U]
	lea	rdx,[rsp+VF_QP]
	call	p256_mul_vt
	lea	rdi,[rsp+VF_SUM]		; R = u1 G + u2 Q
	lea	rsi,[rsp+VF_P1]
	lea	rdx,[rsp+VF_P2]
	call	p256_jadd
	mov	rax,[rsp+VF_SUM+PT_Z]		; infinity -> invalid
	or	rax,[rsp+VF_SUM+PT_Z+8]
	or	rax,[rsp+VF_SUM+PT_Z+16]
	or	rax,[rsp+VF_SUM+PT_Z+24]
	jz	.bad
	lea	rdi,[rsp+VF_ZI]			; x(R) = X / Z^2, out of Montgomery
	lea	rsi,[rsp+VF_SUM+PT_Z]
	lea	rcx,[p256_p]
	call	mod_inv
	F mont_sqr, rsp+VF_ZI, rsp+VF_ZI
	E mont_mul, VF_SUM+PT_X, VF_SUM+PT_X, VF_ZI
	lea	rdi,[rsp+VF_X]
	lea	rsi,[rsp+VF_SUM+PT_X]
	lea	rdx,[p256_one]
	lea	rcx,[p256_p]
	call	mont_mul
	lea	rdi,[rsp+VF_X]
	lea	rsi,[p256_n]
	call	mod_reduce_once			; x mod n
	lea	rsi,[rsp+VF_X]			; valid iff x == r
	lea	rdi,[rsp+VF_R]
	xor	eax,eax
	repeat 4, i:0
		mov	r8,[rsi+i*8]
		xor	r8,[rdi+i*8]
		or	rax,r8
	end repeat
	test	rax,rax
	jnz	.bad
	mov	eax,1
	jmp	.out
.bad:
	xor	eax,eax
.out:
	add	rsp,VF_SIZE
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; -------------------------------------------- variable time (public data)
;
; Verification multiplies public scalars by public points, so it may
; branch on them: Jacobian coordinates (x = X/Z^2, y = Y/Z^3, Montgomery
; form, Z = 0 for infinity), a doubling for a = -3, a general addition
; with its special cases taken by branches, and u * Q by a width-5 NAF.

; rdi = 4 limbs: ZF set when all zero. Clobbers rax.
macro vt_iszero addr*
	mov	rax,[addr]
	or	rax,[addr+8]
	or	rax,[addr+16]
	or	rax,[addr+24]
end macro

; rdi = out, rsi = P (Jacobian): 2P, dbl-2001-b (3M + 5S). out may be P.
JD_D		:= 0				; delta = Z^2
JD_G		:= 32				; gamma = Y^2
JD_B		:= 64				; beta = X gamma
JD_A		:= 96				; alpha = 3 (X - delta)(X + delta)
JD_T		:= 128
JD_U		:= 160
JD_X		:= 192
JD_Y		:= 224
JD_Z		:= 256
JD_SIZE		:= 296
p256_jdbl:
	push	rbx
	push	r12
	sub	rsp,JD_SIZE
	mov	rbx,rdi
	mov	r12,rsi
	F mont_sqr, rsp+JD_D, r12+PT_Z
	F mont_sqr, rsp+JD_G, r12+PT_Y
	F mont_mul, rsp+JD_B, r12+PT_X, rsp+JD_G
	F mod_sub, rsp+JD_T, r12+PT_X, rsp+JD_D
	F mod_add, rsp+JD_U, r12+PT_X, rsp+JD_D
	F mont_mul, rsp+JD_A, rsp+JD_T, rsp+JD_U
	F mod_add, rsp+JD_T, rsp+JD_A, rsp+JD_A
	F mod_add, rsp+JD_A, rsp+JD_A, rsp+JD_T
	F mont_sqr, rsp+JD_X, rsp+JD_A
	F mod_add, rsp+JD_T, rsp+JD_B, rsp+JD_B
	F mod_add, rsp+JD_T, rsp+JD_T, rsp+JD_T		; 4 beta
	F mod_add, rsp+JD_U, rsp+JD_T, rsp+JD_T		; 8 beta
	F mod_sub, rsp+JD_X, rsp+JD_X, rsp+JD_U		; X3 = alpha^2 - 8 beta
	F mod_add, rsp+JD_Z, r12+PT_Y, r12+PT_Z
	F mont_sqr, rsp+JD_Z, rsp+JD_Z
	F mod_sub, rsp+JD_Z, rsp+JD_Z, rsp+JD_G
	F mod_sub, rsp+JD_Z, rsp+JD_Z, rsp+JD_D		; Z3 = (Y + Z)^2 - gamma - delta
	F mod_sub, rsp+JD_T, rsp+JD_T, rsp+JD_X
	F mont_mul, rsp+JD_Y, rsp+JD_A, rsp+JD_T
	F mont_sqr, rsp+JD_G, rsp+JD_G
	F mod_add, rsp+JD_G, rsp+JD_G, rsp+JD_G
	F mod_add, rsp+JD_G, rsp+JD_G, rsp+JD_G
	F mod_add, rsp+JD_G, rsp+JD_G, rsp+JD_G		; 8 gamma^2
	F mod_sub, rsp+JD_Y, rsp+JD_Y, rsp+JD_G		; Y3 = alpha (4 beta - X3) - 8 gamma^2
	lea	rsi,[rsp+JD_X]
	mov	rdi,rbx
	mov	ecx,12
	rep	movsq
	add	rsp,JD_SIZE
	pop	r12
	pop	rbx
	ret

; rdi = out, rsi = P, rdx = Q (Jacobian): P + Q, add-2007-bl (11M + 5S),
; P = Q, P = -Q and infinity by branches. out may be P or Q.
JA_Z1Z1		:= 0
JA_Z2Z2		:= 32
JA_U1		:= 64
JA_U2		:= 96
JA_S1		:= 128
JA_S2		:= 160
JA_H		:= 192
JA_R		:= 224
JA_I		:= 256
JA_J		:= 288
JA_V		:= 320
JA_T		:= 352
JA_X		:= 384
JA_Y		:= 416
JA_Z		:= 448
JA_SIZE		:= 480
p256_jadd:
	push	rbx
	push	r12
	push	r13
	sub	rsp,JA_SIZE
	mov	rbx,rdi
	mov	r12,rsi
	mov	r13,rdx
	vt_iszero r12+PT_Z
	jz	.q
	vt_iszero r13+PT_Z
	jz	.p
	F mont_sqr, rsp+JA_Z1Z1, r12+PT_Z
	F mont_sqr, rsp+JA_Z2Z2, r13+PT_Z
	F mont_mul, rsp+JA_U1, r12+PT_X, rsp+JA_Z2Z2
	F mont_mul, rsp+JA_U2, r13+PT_X, rsp+JA_Z1Z1
	F mont_mul, rsp+JA_T, r13+PT_Z, rsp+JA_Z2Z2
	F mont_mul, rsp+JA_S1, r12+PT_Y, rsp+JA_T
	F mont_mul, rsp+JA_T, r12+PT_Z, rsp+JA_Z1Z1
	F mont_mul, rsp+JA_S2, r13+PT_Y, rsp+JA_T
	F mod_sub, rsp+JA_H, rsp+JA_U2, rsp+JA_U1
	F mod_sub, rsp+JA_R, rsp+JA_S2, rsp+JA_S1
	vt_iszero rsp+JA_H
	jnz	.general
	vt_iszero rsp+JA_R
	jnz	.infinity			; P = -Q
	mov	rdi,rbx				; P = Q
	mov	rsi,r12
	call	p256_jdbl
	jmp	.out
.general:
	F mod_add, rsp+JA_R, rsp+JA_R, rsp+JA_R		; r = 2 (S2 - S1)
	F mod_add, rsp+JA_I, rsp+JA_H, rsp+JA_H
	F mont_sqr, rsp+JA_I, rsp+JA_I			; I = (2H)^2
	F mont_mul, rsp+JA_J, rsp+JA_H, rsp+JA_I
	F mont_mul, rsp+JA_V, rsp+JA_U1, rsp+JA_I
	F mont_sqr, rsp+JA_X, rsp+JA_R
	F mod_sub, rsp+JA_X, rsp+JA_X, rsp+JA_J
	F mod_sub, rsp+JA_X, rsp+JA_X, rsp+JA_V
	F mod_sub, rsp+JA_X, rsp+JA_X, rsp+JA_V		; X3 = r^2 - J - 2V
	F mod_sub, rsp+JA_T, rsp+JA_V, rsp+JA_X
	F mont_mul, rsp+JA_Y, rsp+JA_R, rsp+JA_T
	F mont_mul, rsp+JA_T, rsp+JA_S1, rsp+JA_J
	F mod_add, rsp+JA_T, rsp+JA_T, rsp+JA_T
	F mod_sub, rsp+JA_Y, rsp+JA_Y, rsp+JA_T		; Y3 = r (V - X3) - 2 S1 J
	F mod_add, rsp+JA_Z, r12+PT_Z, r13+PT_Z
	F mont_sqr, rsp+JA_Z, rsp+JA_Z
	F mod_sub, rsp+JA_Z, rsp+JA_Z, rsp+JA_Z1Z1
	F mod_sub, rsp+JA_Z, rsp+JA_Z, rsp+JA_Z2Z2
	F mont_mul, rsp+JA_Z, rsp+JA_Z, rsp+JA_H	; Z3 = ((Z1 + Z2)^2 - Z1Z1 - Z2Z2) H
	lea	rsi,[rsp+JA_X]
	jmp	.copy
.infinity:
	xor	eax,eax
	mov	rdi,rbx
	mov	ecx,12
	rep	stosq
	jmp	.out
.q:
	mov	rsi,r13
	jmp	.copy
.p:
	mov	rsi,r12
.copy:
	cmp	rsi,rbx
	je	.out
	mov	rdi,rbx
	mov	ecx,12
	rep	movsq
.out:
	add	rsp,JA_SIZE
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = out (Jacobian), rsi = k (4 limbs, plain), rdx = Q (Jacobian,
; Montgomery): k Q, by a width-5 NAF over Q, 3Q .. 15Q. Variable time.
MV_TAB		:= 0				; Q, 3Q, .. 15Q
MV_Q2		:= 8 * PT_SIZE
MV_ACC		:= MV_Q2 + PT_SIZE
MV_NEG		:= MV_ACC + PT_SIZE
MV_DIG		:= MV_NEG + PT_SIZE		; the digits, least significant first
MV_SIZE		:= MV_DIG + 272
p256_mul_vt:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,MV_SIZE
	mov	rbx,rdi
	mov	r12,rsi
	mov	rsi,rdx				; the table
	lea	rdi,[rsp+MV_TAB]
	mov	ecx,12
	rep	movsq
	lea	rdi,[rsp+MV_Q2]
	lea	rsi,[rsp+MV_TAB]
	call	p256_jdbl
	xor	r13d,r13d
.table:
	inc	r13d
	cmp	r13d,8
	jae	.recode
	imul	eax,r13d,PT_SIZE
	lea	rdi,[rsp+MV_TAB+rax]
	lea	rsi,[rdi-PT_SIZE]
	lea	rdx,[rsp+MV_Q2]
	call	p256_jadd
	jmp	.table
.recode:
	mov	r8,[r12]
	mov	r9,[r12+8]
	mov	r10,[r12+16]
	mov	r11,[r12+24]
	xor	r15d,r15d			; a fifth limb: k + 15 may carry
	xor	r14d,r14d			; digits
.digit:
	mov	rax,r8
	or	rax,r9
	or	rax,r10
	or	rax,r11
	or	rax,r15
	jz	.recoded
	xor	ecx,ecx
	test	r8d,1
	jz	.put
	mov	ecx,r8d
	and	ecx,31
	cmp	ecx,16
	jb	.pos
	sub	ecx,32				; -15 .. -1
	mov	eax,ecx
	neg	eax
	add	r8,rax
	adc	r9,0
	adc	r10,0
	adc	r11,0
	adc	r15,0
	jmp	.put
.pos:
	sub	r8,rcx
	sbb	r9,0
	sbb	r10,0
	sbb	r11,0
	sbb	r15,0
.put:
	mov	[rsp+MV_DIG+r14],cl
	inc	r14d
	shrd	r8,r9,1
	shrd	r9,r10,1
	shrd	r10,r11,1
	shrd	r11,r15,1
	shr	r15,1
	jmp	.digit
.recoded:
	xor	eax,eax				; acc = infinity
	lea	rdi,[rsp+MV_ACC]
	mov	ecx,12
	rep	stosq
	xor	r13d,r13d			; 1 once acc holds a point
.eval:
	test	r14d,r14d
	jz	.done
	dec	r14d
	test	r13d,r13d
	jz	@f
	lea	rdi,[rsp+MV_ACC]
	lea	rsi,[rsp+MV_ACC]
	call	p256_jdbl
@@:
	movsx	eax,byte [rsp+MV_DIG+r14]
	test	eax,eax
	jz	.eval
	mov	ecx,eax
	sar	ecx,31
	xor	eax,ecx
	sub	eax,ecx				; |digit|
	shr	eax,1
	imul	eax,eax,PT_SIZE
	lea	rdx,[rsp+MV_TAB+rax]
	test	ecx,ecx
	jz	.add
	push	rdx				; -P = (X, -Y, Z)
	lea	rdi,[rsp+8+MV_NEG]
	mov	rsi,rdx
	mov	ecx,12
	rep	movsq
	pop	rdx
	F mod_sub, rsp+MV_NEG+PT_Y, p256_zero, rdx+PT_Y
	lea	rdx,[rsp+MV_NEG]
.add:
	lea	rdi,[rsp+MV_ACC]
	lea	rsi,[rsp+MV_ACC]
	call	p256_jadd
	mov	r13d,1
	jmp	.eval
.done:
	lea	rsi,[rsp+MV_ACC]
	mov	rdi,rbx
	mov	ecx,12
	rep	movsq
	add	rsp,MV_SIZE
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = 4 limbs: CF set when the value is >= p.
vf_below_p:
	mov	r8,[rdi]
	sub	r8,[p256_p]
	mov	r8,[rdi+8]
	sbb	r8,[p256_p+8]
	mov	r8,[rdi+16]
	sbb	r8,[p256_p+16]
	mov	r8,[rdi+24]
	sbb	r8,[p256_p+24]
	cmc
	ret

; RFC 6979 for P-256 / SHA-256. rdi = k (4 limbs), rsi = x = d[32] (big
; endian), rdx = h = (z mod n)[32] (big endian).
NC_K		:= 0				; HMAC key K
NC_V		:= 32
NC_MSG		:= 64				; V | byte | x | h (97 bytes)
NC_SIZE		:= 64 + 112
rfc6979_k:
	push	rbx
	push	r12
	push	r13
	push	r14
	sub	rsp,NC_SIZE
	mov	rbx,rdi
	mov	r12,rsi
	mov	r13,rdx
	mov	r14,rcx				; where the next candidate goes (0: none)
	; V = 0x01 * 32, K = 0x00 * 32
	xor	eax,eax
	mov	rcx,0x0101010101010101
	repeat 4, i:0
		mov	[rsp+NC_K+i*8],rax
		mov	[rsp+NC_V+i*8],rcx
	end repeat
	xor	edx,edx
	call	.kv				; K = HMAC_K(V | 0 | x | h), V = HMAC_K(V)
	mov	edx,1
	call	.kv				; K = HMAC_K(V | 1 | x | h), V = HMAC_K(V)
.try:
	call	.v				; V = HMAC_K(V)
	mov	rdi,rbx
	lea	rsi,[rsp+NC_V]			; k = bits2int(V)
	call	be_to_limbs
	mov	rdi,rbx
	call	scalar_in_range
	test	eax,eax
	jz	.reject
	; found; the caller may want the generator's next candidate as well
	; (a secret uniform value: the inversion's blinding)
	test	r14,r14
	jz	.done
	mov	rbx,r14
	xor	r14d,r14d
.reject:
	; K = HMAC_K(V | 0), V = HMAC_K(V)
	lea	rdi,[rsp+NC_MSG]
	lea	rsi,[rsp+NC_V]
	mov	ecx,32
	rep	movsb
	mov	byte [rdi],0
	lea	rdi,[rsp+NC_K]
	lea	rsi,[rsp+NC_K]
	mov	edx,32
	lea	rcx,[rsp+NC_MSG]
	mov	r8d,33
	call	hmac_sha256
	call	.v
	jmp	.try
.done:
	mov	rdi,rsp
	mov	ecx,NC_SIZE
	call	secure_zero
	add	rsp,NC_SIZE
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
; edx = the separator byte: K = HMAC_K(V | b | x | h), then V = HMAC_K(V)
.kv:
	lea	rdi,[rsp+8+NC_MSG]
	lea	rsi,[rsp+8+NC_V]
	mov	ecx,32
	rep	movsb
	mov	[rdi],dl
	inc	rdi
	mov	rsi,r12
	mov	ecx,32
	rep	movsb
	mov	rsi,r13
	mov	ecx,32
	rep	movsb
	lea	rdi,[rsp+8+NC_K]
	lea	rsi,[rsp+8+NC_K]
	mov	edx,32
	lea	rcx,[rsp+8+NC_MSG]
	mov	r8d,97
	call	hmac_sha256
.v:
	; (called with one return address on the stack, or reached from .kv
	; with one: the frame is 8 bytes deeper either way)
	lea	rdi,[rsp+8+NC_V]
	lea	rsi,[rsp+8+NC_K]
	mov	edx,32
	lea	rcx,[rsp+8+NC_V]
	mov	r8d,32
	call	hmac_sha256
	ret

; rdi = out, rsi = a (0 < a < n, plain): 1/a mod n by the binary
; extended Euclid. Variable time: only for values that tell nothing about
; a secret (the blinded nonce).
IVT_X1		:= 0
IVT_X2		:= 32
IVT_SIZE	:= 64
macro ivt_halve x*
	; x / 2 mod n: x + n first when x is odd (five limbs), then a shift
	local even
	test	byte [rsp+x],1
	mov	eax,0
	jz	even
	mov	rax,[p256_n]
	add	[rsp+x],rax
	mov	rax,[p256_n+8]
	adc	[rsp+x+8],rax
	mov	rax,[p256_n+16]
	adc	[rsp+x+16],rax
	mov	rax,[p256_n+24]
	adc	[rsp+x+24],rax
	setc	al
	movzx	eax,al
even:
	mov	rdx,[rsp+x+8]
	shrd	[rsp+x],rdx,1
	mov	rdx,[rsp+x+16]
	shrd	[rsp+x+8],rdx,1
	mov	rdx,[rsp+x+24]
	shrd	[rsp+x+16],rdx,1
	shrd	[rsp+x+24],rax,1
end macro
macro ivt_sub x*, y*
	; x = x - y mod n
	local done
	mov	rax,[rsp+y]
	sub	[rsp+x],rax
	mov	rax,[rsp+y+8]
	sbb	[rsp+x+8],rax
	mov	rax,[rsp+y+16]
	sbb	[rsp+x+16],rax
	mov	rax,[rsp+y+24]
	sbb	[rsp+x+24],rax
	jnc	done
	mov	rax,[p256_n]
	add	[rsp+x],rax
	mov	rax,[p256_n+8]
	adc	[rsp+x+8],rax
	mov	rax,[p256_n+16]
	adc	[rsp+x+16],rax
	mov	rax,[p256_n+24]
	adc	[rsp+x+24],rax
done:
end macro
mod_inv_n_vartime:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,IVT_SIZE
	push	rdi
	; a = r8..r11, b = n = r12..r15, x1 = 1, x2 = 0
	mov	r8,[rsi]
	mov	r9,[rsi+8]
	mov	r10,[rsi+16]
	mov	r11,[rsi+24]
	mov	r12,[p256_n]
	mov	r13,[p256_n+8]
	mov	r14,[p256_n+16]
	mov	r15,[p256_n+24]
	xor	eax,eax
	repeat 4, q:0
		mov	[rsp+8+IVT_X1+q*8],rax
		mov	[rsp+8+IVT_X2+q*8],rax
	end repeat
	mov	byte [rsp+8+IVT_X1],1
.loop:
	test	r8b,1
	jnz	.a_odd
	shrd	r8,r9,1
	shrd	r9,r10,1
	shrd	r10,r11,1
	shr	r11,1
	ivt_halve 8+IVT_X1
	jmp	.loop
.a_odd:
	test	r12b,1
	jnz	.both_odd
	shrd	r12,r13,1
	shrd	r13,r14,1
	shrd	r14,r15,1
	shr	r15,1
	ivt_halve 8+IVT_X2
	jmp	.loop
.both_odd:
	; done when a or b is 1
	cmp	r8,1
	jne	@f
	mov	rax,r9
	or	rax,r10
	or	rax,r11
	jz	.got_x1
@@:
	cmp	r12,1
	jne	@f
	mov	rax,r13
	or	rax,r14
	or	rax,r15
	jz	.got_x2
@@:
	; the larger loses the smaller
	cmp	r11,r15
	jne	@f
	cmp	r10,r14
	jne	@f
	cmp	r9,r13
	jne	@f
	cmp	r8,r12
@@:
	jb	.b_larger
	sub	r8,r12
	sbb	r9,r13
	sbb	r10,r14
	sbb	r11,r15
	ivt_sub 8+IVT_X1, 8+IVT_X2
	jmp	.loop
.b_larger:
	sub	r12,r8
	sbb	r13,r9
	sbb	r14,r10
	sbb	r15,r11
	ivt_sub 8+IVT_X2, 8+IVT_X1
	jmp	.loop
.got_x2:
	lea	rsi,[rsp+8+IVT_X2]
	jmp	.out
.got_x1:
	lea	rsi,[rsp+8+IVT_X1]
.out:
	pop	rdi
	mov	ecx,4
	rep	movsq
	mov	rdi,rsp
	mov	ecx,IVT_SIZE
	call	secure_zero
	add	rsp,IVT_SIZE
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = rs[64], rsi = d[32], rdx = digest[32]. eax = 1, or 0 when d is
; not in [1, n).
SG_D		:= 0				; d, limbs
SG_Z		:= 32				; z mod n
SG_K		:= 64
SG_X		:= 96				; x of k G, then r
SG_Y		:= 128
SG_DM		:= 160				; Montgomery forms mod n
SG_ZM		:= 192
SG_RM		:= 224
SG_KM		:= 256
SG_T		:= 288
SG_HB		:= 320				; h as bytes
SG_B		:= 352				; the blinding value
SG_BM		:= 384
SG_U		:= 416
SG_SIZE		:= 448
p256_sign:
	push	rbx
	push	r12
	push	r13
	push	r14
	sub	rsp,SG_SIZE
	mov	rbx,rdi
	mov	r12,rsi
	mov	r13,rdx
	lea	rdi,[rsp+SG_D]
	mov	rsi,r12
	call	be_to_limbs
	lea	rdi,[rsp+SG_D]
	call	scalar_in_range
	test	eax,eax
	jz	.out
	lea	rdi,[rsp+SG_Z]
	mov	rsi,r13
	call	be_to_limbs
	lea	rdi,[rsp+SG_Z]
	lea	rsi,[p256_n]
	call	mod_reduce_once			; z mod n (z < 2^256 < 2n)
	lea	rdi,[rsp+SG_HB]
	lea	rsi,[rsp+SG_Z]
	call	limbs_to_be
.retry:
	lea	rdi,[rsp+SG_K]
	mov	rsi,r12
	lea	rdx,[rsp+SG_HB]
	lea	rcx,[rsp+SG_B]
	call	rfc6979_k
	lea	rdi,[rsp+SG_X]
	lea	rsi,[rsp+SG_K]
	call	p256_mul_g
	lea	rdi,[rsp+SG_X]
	lea	rsi,[p256_n]
	call	mod_reduce_once			; r = x mod n (x < p < 2n)
	; r = 0 has probability 2^-256: not worth a branch on secrets
	; s = k^-1 (z + r d) mod n, in Montgomery form mod n
	lea	r14,[p256_n]
	irp v, SG_D:SG_DM, SG_Z:SG_ZM, SG_X:SG_RM, SG_K:SG_KM
		match src:dst, v
			lea	rdi,[rsp+dst]
			lea	rsi,[rsp+src]
			lea	rdx,[r14+MOD_RR]
			mov	rcx,r14
			call	mont_mul
		end match
	end irp
	lea	rdi,[rsp+SG_T]
	lea	rsi,[rsp+SG_RM]
	lea	rdx,[rsp+SG_DM]
	mov	rcx,r14
	call	mont_mul			; r d
	lea	rdi,[rsp+SG_T]
	lea	rsi,[rsp+SG_ZM]
	lea	rdx,[rsp+SG_T]
	mov	rcx,r14
	call	mod_add				; z + r d
	; 1/k, blinded: u = k b is uniform and independent of k, so a fast
	; variable-time inversion of u leaks nothing; then 1/k = b / u
	lea	rdi,[rsp+SG_BM]
	lea	rsi,[rsp+SG_B]
	lea	rdx,[r14+MOD_RR]
	mov	rcx,r14
	call	mont_mul			; b R
	lea	rdi,[rsp+SG_U]
	lea	rsi,[rsp+SG_KM]
	lea	rdx,[rsp+SG_BM]
	mov	rcx,r14
	call	mont_mul			; k b R
	lea	rdi,[rsp+SG_U]
	lea	rsi,[rsp+SG_U]
	lea	rdx,[p256_one]
	mov	rcx,r14
	call	mont_mul			; u = k b
	lea	rdi,[rsp+SG_U]
	lea	rsi,[rsp+SG_U]
	call	mod_inv_n_vartime		; 1/u
	lea	rdi,[rsp+SG_U]
	lea	rsi,[rsp+SG_U]
	lea	rdx,[r14+MOD_RR]
	mov	rcx,r14
	call	mont_mul			; R / u
	lea	rdi,[rsp+SG_KM]
	lea	rsi,[rsp+SG_U]
	lea	rdx,[rsp+SG_BM]
	mov	rcx,r14
	call	mont_mul			; R b / u = R / k
	lea	rdi,[rsp+SG_T]
	lea	rsi,[rsp+SG_KM]
	lea	rdx,[rsp+SG_T]
	mov	rcx,r14
	call	mont_mul
	lea	rdi,[rsp+SG_T]
	lea	rsi,[rsp+SG_T]
	lea	rdx,[p256_one]
	mov	rcx,r14
	call	mont_mul			; s, out of Montgomery form
	mov	rdi,rbx
	lea	rsi,[rsp+SG_X]
	call	limbs_to_be
	lea	rdi,[rbx+32]
	lea	rsi,[rsp+SG_T]
	call	limbs_to_be
	mov	eax,1
.out:
	push	rax
	lea	rdi,[rsp+8]
	mov	ecx,SG_SIZE
	call	secure_zero
	pop	rax
	add	rsp,SG_SIZE
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = out, rsi = rs[64]: SEQUENCE { INTEGER r, INTEGER s }. eax = its
; length (at most 72).
ecdsa_der:
	push	rbx
	mov	rbx,rdi
	mov	byte [rdi],0x30
	add	rdi,2
	call	.int
	add	rsi,32
	call	.int
	mov	rax,rdi
	sub	rax,rbx
	lea	ecx,[rax-2]
	mov	[rbx+1],cl
	pop	rbx
	ret
; rsi = 32 bytes: INTEGER at rdi, minimal, with a 0 before a high bit.
.int:
	push	rsi
	mov	ecx,32
@@:
	cmp	ecx,1
	je	@f
	cmp	byte [rsi],0
	jne	@f
	inc	rsi
	dec	ecx
	jmp	@b
@@:
	mov	byte [rdi],2
	xor	edx,edx
	test	byte [rsi],0x80
	jz	@f
	inc	edx
@@:
	lea	eax,[rcx+rdx]
	mov	[rdi+1],al
	add	rdi,2
	test	edx,edx
	jz	@f
	mov	byte [rdi],0
	inc	rdi
@@:
	rep	movsb
	pop	rsi
	ret
