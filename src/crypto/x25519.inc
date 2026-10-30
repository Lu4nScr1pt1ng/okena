; X25519 (RFC 7748): Diffie-Hellman on Curve25519, for the TLS 1.3 key
; exchange.
;
; Field elements are four 64-bit limbs, little endian, kept below 2^256
; (reduced modulo p = 2^255 - 19 only when encoded): 2^256 = 38 mod p, so
; a carry out of the top limb comes back as 38. Every step that touches
; secret data runs the same instructions whatever the data: the ladder
; swaps with masks, never with branches, and no table is indexed by a
; secret. The inversion's exponent (p - 2) is public.
;
; Multiplication: in registers with mulx and the two carry chains of
; adcx/adox where the CPU has ADX (all since Broadwell / Zen), else with
; mul in memory. Squaring has its own routine (6 cross products doubled
; plus 4 squares) on mulx alone. The inversion is the usual addition
; chain for 2^255 - 21: 254 squarings and 11 multiplications.

FE_SIZE		:= 32

; rdi = out, rsi = a, rdx = b (out may be a or b): a * b, below 2^256.
fe_mul:
	cmp	byte [g_cpu_adx],0
	jne	fe_mul_adx
fe_mul_generic:
	push	rbx
	push	r12
	push	r13
	sub	rsp,64
	mov	rbx,rdx
	xor	eax,eax
	repeat 8, i:0
		mov	[rsp+i*8],rax
	end repeat
	repeat 4, i:0
		xor	r12d,r12d		; carry
		repeat 4, j:0
			mov	rax,[rsi+j*8]
			mul	qword [rbx+i*8]
			add	rax,r12
			adc	rdx,0
			add	[rsp+(i+j)*8],rax
			adc	rdx,0
			mov	r12,rdx
		end repeat
		mov	[rsp+(i+4)*8],r12
	end repeat
	; low half + 38 * high half
	mov	r12d,38
	xor	r13d,r13d
	repeat 4, k:0
		mov	rax,[rsp+(4+k)*8]
		mul	r12
		add	rax,r13
		adc	rdx,0
		add	rax,[rsp+k*8]
		adc	rdx,0
		mov	[rsp+k*8],rax
		mov	r13,rdx
	end repeat
	imul	r13,r13,38			; what is left above 2^256, folded
	mov	rax,[rsp]
	add	rax,r13
	mov	rcx,[rsp+8]
	adc	rcx,0
	mov	rdx,[rsp+16]
	adc	rdx,0
	mov	r8,[rsp+24]
	adc	r8,0
	sbb	r9,r9				; one more carry: at most once
	and	r9,38
	add	rax,r9				; (cannot carry: rax is small here)
	mov	[rdi],rax
	mov	[rdi+8],rcx
	mov	[rdi+16],rdx
	mov	[rdi+24],r8
	add	rsp,64
	pop	r13
	pop	r12
	pop	rbx
	ret

; out = r8..r11 + 38 * r12..r15 (an eight-limb product), below 2^256.
; Clobbers rax, rbx, rdx, r12.
macro fe_reduce_store
	local plain, fold
	mov	edx,38
	cmp	byte [g_cpu_adx],0
	je	plain
	; with ADX: 38 * high half added on both carry chains
	xor	ebx,ebx				; (clears CF and OF)
	mulx	rbx,rax,r12
	adcx	r8,rax
	adox	r9,rbx
	mulx	rbx,rax,r13
	adcx	r9,rax
	adox	r10,rbx
	mulx	rbx,rax,r14
	adcx	r10,rax
	adox	r11,rbx
	mulx	r12,rax,r15
	adcx	r11,rax
	mov	ebx,0
	adox	r12,rbx
	adcx	r12,rbx				; r12 = what is above 2^256 (small)
	jmp	fold
plain:
	mulx	rbx,rax,r12
	add	r8,rax
	adc	r9,rbx
	mulx	rbx,rax,r14
	adc	r10,rax
	adc	r11,rbx
	mov	r12d,0
	adc	r12,0				; carry above limb 3
	mulx	rbx,rax,r13
	add	r9,rax
	adc	r10,rbx
	mulx	rbx,rax,r15
	adc	r11,rax
	adc	r12,rbx				; r12 = what is above 2^256 (small)
fold:
	imul	r12,r12,38
	add	r8,r12
	adc	r9,0
	adc	r10,0
	adc	r11,0
	sbb	rax,rax				; one more carry: at most once
	and	eax,38
	add	r8,rax
	mov	[rdi],r8
	mov	[rdi+8],r9
	mov	[rdi+16],r10
	mov	[rdi+24],r11
end macro

; fe_mul with mulx/adcx/adox: rows of a[i] * b added on two carry chains
; (adcx for the low halves, adox for the high halves), all in registers.
fe_mul_adx:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	call	fe_mul_core
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; fe_mul_adx's body for callers that saved rbx and r12-r15 themselves
; (the ladder): clobbers them.
fe_mul_core:
	mov	rcx,rdx				; b
	; row 0
	mov	rdx,[rsi]
	mulx	r9,r8,[rcx]
	mulx	r10,rax,[rcx+8]
	add	r9,rax
	mulx	r11,rax,[rcx+16]
	adc	r10,rax
	mulx	r12,rax,[rcx+24]
	adc	r11,rax
	adc	r12,0
	; rows 1..3: acc[i..i+4] += a[i] * b
	irp <ai,c0,c1,c2,c3,c4>, 8,r9,r10,r11,r12,r13, 16,r10,r11,r12,r13,r14, 24,r11,r12,r13,r14,r15
		mov	rdx,[rsi+ai]
		xor	c4,c4				; also clears CF and OF
		mulx	rbx,rax,[rcx]
		adcx	c0,rax
		adox	c1,rbx
		mulx	rbx,rax,[rcx+8]
		adcx	c1,rax
		adox	c2,rbx
		mulx	rbx,rax,[rcx+16]
		adcx	c2,rax
		adox	c3,rbx
		mulx	rbx,rax,[rcx+24]
		adcx	c3,rax
		adox	c4,rbx
		mov	eax,0
		adcx	c4,rax
	end irp
	fe_reduce_store
	ret

; rdi = out, rsi = a: a^2, below 2^256 (mulx, no ADX needed).
fe_sq:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	call	fe_sq_core
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; fe_sq's body: clobbers rbx and r12-r15.
fe_sq_core:
	; cross products a_i a_j (i < j) at positions 1..7
	xor	r13d,r13d
	xor	r14d,r14d
	xor	r15d,r15d
	mov	rdx,[rsi]
	mulx	r10,r9,[rsi+8]			; a0 a1: 1, 2
	mulx	r11,rax,[rsi+16]		; a0 a2: 2, 3
	add	r10,rax
	mulx	r12,rax,[rsi+24]		; a0 a3: 3, 4
	adc	r11,rax
	adc	r12,0
	mov	rdx,[rsi+8]
	mulx	rbx,rax,[rsi+16]		; a1 a2: 3, 4
	add	r11,rax
	adc	r12,rbx
	adc	r13,0
	mulx	rbx,rax,[rsi+24]		; a1 a3: 4, 5
	add	r12,rax
	adc	r13,rbx
	adc	r14,0
	mov	rdx,[rsi+16]
	mulx	rbx,rax,[rsi+24]		; a2 a3: 5, 6
	add	r13,rax
	adc	r14,rbx
	adc	r15,0
	cmp	byte [g_cpu_adx],0
	je	.plain
	; doubled (adcx) and the squares added (adox) on two chains at once
	mov	rdx,[rsi]
	mulx	rax,r8,rdx			; a0^2
	mov	rdx,[rsi+8]
	mulx	rcx,rbx,rdx			; a1^2
	xor	edx,edx				; (clears CF and OF)
	adcx	r9,r9
	adox	r9,rax
	adcx	r10,r10
	adox	r10,rbx
	adcx	r11,r11
	adox	r11,rcx
	mov	rdx,[rsi+16]
	mulx	rcx,rbx,rdx			; a2^2
	adcx	r12,r12
	adox	r12,rbx
	adcx	r13,r13
	adox	r13,rcx
	mov	rdx,[rsi+24]
	mulx	rcx,rbx,rdx			; a3^2
	adcx	r14,r14
	adox	r14,rbx
	adcx	r15,r15
	adox	r15,rcx
	fe_reduce_store
	ret
.plain:
	; doubled
	add	r9,r9
	adc	r10,r10
	adc	r11,r11
	adc	r12,r12
	adc	r13,r13
	adc	r14,r14
	adc	r15,r15
	; plus the squares a_i^2 at positions 2i, 2i+1
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
	fe_reduce_store
	ret

; rdi = a (in place), ecx = n: a^(2^n).
fe_sqn:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	mov	ebp,ecx				; (the core keeps rbp and rdi)
@@:
	mov	rsi,rdi
	call	fe_sq_core
	dec	ebp
	jnz	@b
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

; The ladder's multiply: the core when the CPU has ADX (its caller saved
; the registers), else the generic one.
fe_mul_l:
	cmp	byte [g_cpu_adx],0
	jne	fe_mul_core
	jmp	fe_mul_generic

; rdi = out, rsi = a, rdx = b: a + b.
fe_add:
	mov	rax,[rsi]
	add	rax,[rdx]
	mov	rcx,[rsi+8]
	adc	rcx,[rdx+8]
	mov	r8,[rsi+16]
	adc	r8,[rdx+16]
	mov	r9,[rsi+24]
	adc	r9,[rdx+24]
	sbb	r10,r10
	and	r10,38
	add	rax,r10
	adc	rcx,0
	adc	r8,0
	adc	r9,0
	sbb	r10,r10
	and	r10,38
	add	rax,r10
	mov	[rdi],rax
	mov	[rdi+8],rcx
	mov	[rdi+16],r8
	mov	[rdi+24],r9
	ret

; rdi = out, rsi = a, rdx = b: a - b (a borrow out of 2^256 is -38).
fe_sub:
	mov	rax,[rsi]
	sub	rax,[rdx]
	mov	rcx,[rsi+8]
	sbb	rcx,[rdx+8]
	mov	r8,[rsi+16]
	sbb	r8,[rdx+16]
	mov	r9,[rsi+24]
	sbb	r9,[rdx+24]
	sbb	r10,r10
	and	r10,38
	sub	rax,r10
	sbb	rcx,0
	sbb	r8,0
	sbb	r9,0
	sbb	r10,r10
	and	r10,38
	sub	rax,r10
	mov	[rdi],rax
	mov	[rdi+8],rcx
	mov	[rdi+16],r8
	mov	[rdi+24],r9
	ret

; rdi = out, rsi = a: a * 121665 ((A - 2) / 4, the ladder's constant).
fe_mul_a24:
	push	rbx
	mov	edx,121665
	mulx	r9,r8,[rsi]
	mulx	r10,rax,[rsi+8]
	add	r9,rax
	mulx	r11,rax,[rsi+16]
	adc	r10,rax
	mulx	rcx,rax,[rsi+24]
	adc	r11,rax
	adc	rcx,0				; above 2^256
	imul	rcx,rcx,38
	add	r8,rcx
	adc	r9,0
	adc	r10,0
	adc	r11,0
	sbb	rax,rax
	and	eax,38
	add	r8,rax
	mov	[rdi],r8
	mov	[rdi+8],r9
	mov	[rdi+16],r10
	mov	[rdi+24],r11
	pop	rbx
	ret

; rdi = a, rsi = b, rdx = 0 or all ones: swapped when all ones.
fe_cswap:
	repeat 4, i:0
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

; rdi = a (in place): the canonical value, below p.
fe_canon:
	repeat 2
		; bit 255 = 19 (2^255 = 19 mod p)
		mov	rax,[rdi+24]
		mov	rcx,rax
		shr	rcx,63
		btr	rax,63
		mov	[rdi+24],rax
		imul	rcx,rcx,19
		add	[rdi],rcx
		adc	qword [rdi+8],0
		adc	qword [rdi+16],0
		adc	qword [rdi+24],0
	end repeat
	; now below 2^255: subtract p when a + 19 reaches 2^255
	mov	rax,[rdi]
	add	rax,19
	mov	rcx,[rdi+8]
	adc	rcx,0
	mov	r8,[rdi+16]
	adc	r8,0
	mov	r9,[rdi+24]
	adc	r9,0
	mov	r10,r9
	sar	r10,63				; all ones when a >= p
	btr	r9,63				; a + 19 - 2^255 = a - p
	; select a - p or a, without a branch
	mov	r11,[rdi]
	xor	rax,r11
	and	rax,r10
	xor	rax,r11
	mov	[rdi],rax
	mov	r11,[rdi+8]
	xor	rcx,r11
	and	rcx,r10
	xor	rcx,r11
	mov	[rdi+8],rcx
	mov	r11,[rdi+16]
	xor	r8,r11
	and	r8,r10
	xor	r8,r11
	mov	[rdi+16],r8
	mov	r11,[rdi+24]
	xor	r9,r11
	and	r9,r10
	xor	r9,r11
	mov	[rdi+24],r9
	ret

; rdi = out, rsi = a: a^(p-2) = 1/a, by the addition chain for 2^255 - 21
; (254 squarings, 11 multiplications).
IV_Z2		:= 0
IV_Z9		:= 32
IV_Z11		:= 64
IV_T		:= 96				; 2^5-1, 2^10-1, ... as the chain goes
IV_U		:= 128
IV_A		:= 160
IV_Z50		:= 192
IV_Z10		:= 224
IV_SIZE		:= 256
macro iv_op op*, d*, a*, b
	lea	rdi,[rsp+d]
	lea	rsi,[rsp+a]
	match any, b
		lea	rdx,[rsp+b]
	end match
	call	op
end macro
macro iv_copy d*, a*
	lea	rdi,[rsp+d]
	lea	rsi,[rsp+a]
	mov	ecx,4
	rep	movsq
end macro
macro iv_sqn d*, n*
	lea	rdi,[rsp+d]
	mov	ecx,n
	call	fe_sqn
end macro
fe_inv:
	push	r12
	push	r13
	sub	rsp,IV_SIZE
	mov	r12,rdi
	lea	rdi,[rsp+IV_A]
	mov	ecx,4
	rep	movsq				; a
	iv_op fe_sq, IV_Z2, IV_A		; z^2
	iv_op fe_sq, IV_T, IV_Z2		; z^4
	iv_op fe_sq, IV_T, IV_T			; z^8
	iv_op fe_mul, IV_Z9, IV_T, IV_A		; z^9
	iv_op fe_mul, IV_Z11, IV_Z9, IV_Z2	; z^11
	iv_op fe_sq, IV_T, IV_Z11		; z^22
	iv_op fe_mul, IV_T, IV_T, IV_Z9		; z^(2^5 - 1)
	iv_copy IV_U, IV_T
	iv_sqn IV_U, 5
	iv_op fe_mul, IV_Z10, IV_U, IV_T	; 2^10 - 1
	iv_copy IV_U, IV_Z10
	iv_sqn IV_U, 10
	iv_op fe_mul, IV_T, IV_U, IV_Z10	; 2^20 - 1
	iv_copy IV_U, IV_T
	iv_sqn IV_U, 20
	iv_op fe_mul, IV_U, IV_U, IV_T		; 2^40 - 1
	iv_sqn IV_U, 10
	iv_op fe_mul, IV_Z50, IV_U, IV_Z10	; 2^50 - 1
	iv_copy IV_U, IV_Z50
	iv_sqn IV_U, 50
	iv_op fe_mul, IV_T, IV_U, IV_Z50	; 2^100 - 1
	iv_copy IV_U, IV_T
	iv_sqn IV_U, 100
	iv_op fe_mul, IV_U, IV_U, IV_T		; 2^200 - 1
	iv_sqn IV_U, 50
	iv_op fe_mul, IV_U, IV_U, IV_Z50	; 2^250 - 1
	iv_sqn IV_U, 5				; 2^255 - 2^5
	mov	rdi,r12
	lea	rsi,[rsp+IV_U]
	lea	rdx,[rsp+IV_Z11]
	call	fe_mul				; 2^255 - 21
	mov	rdi,rsp
	mov	ecx,IV_SIZE
	call	secure_zero
	add	rsp,IV_SIZE
	pop	r13
	pop	r12
	ret

; The ladder's working set.
XL_K		:= 0				; the clamped scalar
XL_X1		:= 32
XL_X2		:= 64
XL_Z2		:= 96
XL_X3		:= 128
XL_Z3		:= 160
XL_A		:= 192
XL_AA		:= 224
XL_B		:= 256
XL_BB		:= 288
XL_E		:= 320
XL_C		:= 352
XL_D		:= 384
XL_DA		:= 416
XL_CB		:= 448
XL_OUT		:= 480				; q
XL_BIT		:= 488				; d
XL_SWAP		:= 492				; d
XL_SIZE		:= 512

macro fe_add_inline
	mov	rax,[rsi]
	add	rax,[rdx]
	mov	rcx,[rsi+8]
	adc	rcx,[rdx+8]
	mov	r8,[rsi+16]
	adc	r8,[rdx+16]
	mov	r9,[rsi+24]
	adc	r9,[rdx+24]
	sbb	r10,r10
	and	r10,38
	add	rax,r10
	adc	rcx,0
	adc	r8,0
	adc	r9,0
	sbb	r10,r10
	and	r10,38
	add	rax,r10
	mov	[rdi],rax
	mov	[rdi+8],rcx
	mov	[rdi+16],r8
	mov	[rdi+24],r9
end macro

macro fe_sub_inline
	mov	rax,[rsi]
	sub	rax,[rdx]
	mov	rcx,[rsi+8]
	sbb	rcx,[rdx+8]
	mov	r8,[rsi+16]
	sbb	r8,[rdx+16]
	mov	r9,[rsi+24]
	sbb	r9,[rdx+24]
	sbb	r10,r10
	and	r10,38
	sub	rax,r10
	sbb	rcx,0
	sbb	r8,0
	sbb	r9,0
	sbb	r10,r10
	and	r10,38
	sub	rax,r10
	mov	[rdi],rax
	mov	[rdi+8],rcx
	mov	[rdi+16],r8
	mov	[rdi+24],r9
end macro

; x2/x3 and z2/z3 at [rsp+XL_*] swapped when rdx is all ones, a whole
; field element per ymm register.
macro ladder_cswap
	irp <a,b>, XL_X2,XL_X3, XL_Z2,XL_Z3
		repeat 4, i:0
			mov	rax,[rsp+a+i*8]
			mov	rcx,[rsp+b+i*8]
			mov	r8,rax
			xor	r8,rcx
			and	r8,rdx
			xor	rax,r8
			xor	rcx,r8
			mov	[rsp+a+i*8],rax
			mov	[rsp+b+i*8],rcx
		end repeat
	end irp
end macro

; rdi = out[32], rsi = scalar[32], rdx = u[32] (RFC 7748 encodings).
x25519:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,XL_SIZE
	mov	[rsp+XL_OUT],rdi
	; k: clamped
	lea	rdi,[rsp+XL_K]
	push	rdx
	mov	ecx,32
	rep	movsb
	pop	rdx
	and	byte [rsp+XL_K],248
	and	byte [rsp+XL_K+31],127
	or	byte [rsp+XL_K+31],64
	; x1 = u, top bit ignored
	lea	rdi,[rsp+XL_X1]
	mov	rsi,rdx
	mov	ecx,32
	rep	movsb
	btr	qword [rsp+XL_X1+24],63
	; x2 = 1, z2 = 0, x3 = u, z3 = 1
	xor	eax,eax
	repeat 4, i:0
		mov	[rsp+XL_X2+i*8],rax
		mov	[rsp+XL_Z2+i*8],rax
		mov	[rsp+XL_Z3+i*8],rax
		mov	rcx,[rsp+XL_X1+i*8]
		mov	[rsp+XL_X3+i*8],rcx
	end repeat
	mov	byte [rsp+XL_X2],1
	mov	byte [rsp+XL_Z3],1
	mov	dword [rsp+XL_SWAP],0
	mov	dword [rsp+XL_BIT],254
.step:
	; k_t, without a branch on it
	mov	eax,[rsp+XL_BIT]
	mov	ecx,eax
	shr	eax,3
	movzx	eax,byte [rsp+XL_K+rax]
	and	ecx,7
	shr	eax,cl
	and	eax,1				; k_t
	mov	edx,[rsp+XL_SWAP]
	mov	[rsp+XL_SWAP],eax		; swap = k_t (for the next step)
	xor	edx,eax				; swap ^ k_t
	neg	rdx				; 0 or all ones
	ladder_cswap
	; the order of OpenSSL's ladder: additions first, then independent
	; multiplications next to each other, so they overlap in the CPU
	lea	rdi,[rsp+XL_A]
	lea	rsi,[rsp+XL_X2]
	lea	rdx,[rsp+XL_Z2]
	fe_add_inline
	lea	rdi,[rsp+XL_B]
	lea	rsi,[rsp+XL_X2]
	lea	rdx,[rsp+XL_Z2]
	fe_sub_inline
	lea	rdi,[rsp+XL_C]
	lea	rsi,[rsp+XL_X3]
	lea	rdx,[rsp+XL_Z3]
	fe_add_inline
	lea	rdi,[rsp+XL_D]
	lea	rsi,[rsp+XL_X3]
	lea	rdx,[rsp+XL_Z3]
	fe_sub_inline
	lea	rdi,[rsp+XL_DA]
	lea	rsi,[rsp+XL_D]
	lea	rdx,[rsp+XL_A]
	call	fe_mul_l
	lea	rdi,[rsp+XL_CB]
	lea	rsi,[rsp+XL_C]
	lea	rdx,[rsp+XL_B]
	call	fe_mul_l
	lea	rdi,[rsp+XL_AA]
	lea	rsi,[rsp+XL_A]
	call	fe_sq_core
	lea	rdi,[rsp+XL_BB]
	lea	rsi,[rsp+XL_B]
	call	fe_sq_core
	lea	rdi,[rsp+XL_X3]
	lea	rsi,[rsp+XL_DA]
	lea	rdx,[rsp+XL_CB]
	fe_add_inline
	lea	rdi,[rsp+XL_Z3]
	lea	rsi,[rsp+XL_DA]
	lea	rdx,[rsp+XL_CB]
	fe_sub_inline
	lea	rdi,[rsp+XL_E]
	lea	rsi,[rsp+XL_AA]
	lea	rdx,[rsp+XL_BB]
	fe_sub_inline
	lea	rdi,[rsp+XL_X2]
	lea	rsi,[rsp+XL_AA]
	lea	rdx,[rsp+XL_BB]
	call	fe_mul_l
	lea	rdi,[rsp+XL_X3]
	lea	rsi,[rsp+XL_X3]
	call	fe_sq_core
	lea	rdi,[rsp+XL_Z3]
	lea	rsi,[rsp+XL_Z3]
	call	fe_sq_core
	lea	rdi,[rsp+XL_Z2]
	lea	rsi,[rsp+XL_E]
	call	fe_mul_a24
	lea	rdi,[rsp+XL_Z2]
	lea	rsi,[rsp+XL_AA]
	lea	rdx,[rsp+XL_Z2]
	fe_add_inline
	lea	rdi,[rsp+XL_Z3]
	lea	rsi,[rsp+XL_Z3]
	lea	rdx,[rsp+XL_X1]
	call	fe_mul_l
	lea	rdi,[rsp+XL_Z2]
	lea	rsi,[rsp+XL_E]
	lea	rdx,[rsp+XL_Z2]
	call	fe_mul_l
	dec	dword [rsp+XL_BIT]
	jns	.step
	mov	edx,[rsp+XL_SWAP]
	neg	rdx
	ladder_cswap
	; x2 / z2, canonical, little endian
	lea	rdi,[rsp+XL_Z2]
	lea	rsi,[rsp+XL_Z2]
	call	fe_inv
	lea	rdi,[rsp+XL_X2]
	lea	rsi,[rsp+XL_X2]
	lea	rdx,[rsp+XL_Z2]
	call	fe_mul_l
	lea	rdi,[rsp+XL_X2]
	call	fe_canon
	mov	rdi,[rsp+XL_OUT]
	lea	rsi,[rsp+XL_X2]
	mov	ecx,4
	rep	movsq
	mov	rdi,rsp
	mov	ecx,XL_SIZE
	call	secure_zero			; the scalar and every intermediate
	add	rsp,XL_SIZE
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; ------------------------------------------- fixed-base key generation
;
; x25519_base(rdi out[32], rsi scalar[32]) = x25519(out, scalar, 9), about
; four times fewer multiplications: u = 9 is the Ed25519 base point B
; through u = (1 + y) / (1 - y) = (Z + Y) / (Z - Y), so k * B is computed
; on the twisted Edwards curve (extended coordinates, ref10's formulas)
; from a table of 32 rows of j * 256^i * B, j = 1..8 (tools/
; gen_ed25519_table.py). k is the clamped scalar in signed radix-16 digits
; e_0..e_63 in [-8, 8]: the odd digits are added (one row each), the sum
; multiplied by 16, then the even digits added. Each addition reads a
; whole row and keeps the entry with masks; a negative digit swaps y + x
; and y - x and negates 2dxy, also with masks. One inversion at the end.

XB_ROW		:= 8 * 96			; a row: 8 entries of (y + x, y - x, 2dxy)

rodata
	align 32
	ed25519_table:
	file 'ed25519_table.bin'
	assert $ - ed25519_table = 32 * XB_ROW
	align 32
	fe_one		dq 1, 0, 0, 0
	fe_zero		dq 0, 0, 0, 0
end rodata

XB_E		:= 0				; 64 signed digits
XB_X		:= 64				; the sum: extended (X : Y : Z : T)
XB_Y		:= 96
XB_Z		:= 128
XB_T		:= 160
XB_RX		:= 192				; a completed point
XB_RY		:= 224
XB_RZ		:= 256
XB_RT		:= 288
XB_QP		:= 320				; the entry: y + x
XB_QM		:= 352				; y - x
XB_QD		:= 384				; 2dxy
XB_T0		:= 416
XB_K		:= 448				; the clamped scalar
XB_OUT		:= 480
XB_SIZE		:= 496

; f out, a[, b] on frame offsets
macro xb_op f*, o*, a*, b
	lea	rdi,[rsp+8+o]
	lea	rsi,[rsp+8+a]
	match any, b
		lea	rdx,[rsp+8+b]
	end match
	call	f
end macro

; [rsp+XB_X..] += the entry in XB_Q* (mixed addition, then to extended)
xb_madd:
	xb_op	fe_add, XB_RX, XB_Y, XB_X
	xb_op	fe_sub, XB_RY, XB_Y, XB_X
	xb_op	fe_mul, XB_RZ, XB_RX, XB_QP
	xb_op	fe_mul, XB_RY, XB_RY, XB_QM
	xb_op	fe_mul, XB_RT, XB_QD, XB_T
	xb_op	fe_add, XB_T0, XB_Z, XB_Z
	xb_op	fe_sub, XB_RX, XB_RZ, XB_RY
	xb_op	fe_add, XB_RY, XB_RZ, XB_RY
	xb_op	fe_add, XB_RZ, XB_T0, XB_RT
	xb_op	fe_sub, XB_RT, XB_T0, XB_RT
; completed R to the extended sum
xb_to_p3:
	xb_op	fe_mul, XB_T, XB_RX, XB_RY
xb_to_p2:
	xb_op	fe_mul, XB_X, XB_RX, XB_RT
	xb_op	fe_mul, XB_Y, XB_RY, XB_RZ
	xb_op	fe_mul, XB_Z, XB_RZ, XB_RT
	ret

; the sum (X : Y : Z) doubled into the completed R
xb_dbl:
	xb_op	fe_sq, XB_RX, XB_X
	xb_op	fe_sq, XB_RZ, XB_Y
	xb_op	fe_sq, XB_RT, XB_Z
	xb_op	fe_add, XB_RT, XB_RT, XB_RT
	xb_op	fe_add, XB_RY, XB_X, XB_Y
	xb_op	fe_sq, XB_T0, XB_RY
	xb_op	fe_add, XB_RY, XB_RZ, XB_RX
	xb_op	fe_sub, XB_RZ, XB_RZ, XB_RX
	xb_op	fe_sub, XB_RX, XB_T0, XB_RY
	xb_op	fe_sub, XB_RT, XB_RT, XB_RZ
	ret

; r12d = digit index: XB_Q* = e * (row i/2's base), i = r12d. Reads the
; whole row.
xb_select:
	movsx	ecx,byte [rsp+8+XB_E+r12]
	mov	edx,ecx
	sar	edx,31				; all ones when negative
	xor	ecx,edx
	sub	ecx,edx				; |e|
	mov	eax,r12d
	shr	eax,1
	imul	rax,rax,XB_ROW
	lea	rax,[ed25519_table+rax]
	vmovq	xmm7,rcx
	vpbroadcastq ymm7,xmm7			; |e|
	mov	ecx,1
	vmovq	xmm4,rcx
	vpbroadcastq ymm4,xmm4			; 1
	vmovdqa	ymm3,ymm4			; j
	vmovdqa	ymm0,yword [fe_one]			; |e| = 0: the neutral entry (1, 1, 0)
	vmovdqa	ymm1,ymm0
	vpxor	ymm2,ymm2,ymm2
	mov	ecx,8
.entry:
	vpcmpeqq ymm5,ymm3,ymm7
	vpblendvb ymm0,ymm0,yword [rax],ymm5
	vpblendvb ymm1,ymm1,yword [rax+32],ymm5
	vpblendvb ymm2,ymm2,yword [rax+64],ymm5
	vpaddq	ymm3,ymm3,ymm4
	add	rax,96
	dec	ecx
	jnz	.entry
	vmovdqu	[rsp+8+XB_QD],ymm2
	; negative: swap y + x and y - x, negate 2dxy
	movsxd	rdx,edx				; the mask on all 64 bits
	vmovq	xmm6,rdx
	vpbroadcastq ymm6,xmm6
	vpblendvb ymm5,ymm0,ymm1,ymm6
	vpblendvb ymm1,ymm1,ymm0,ymm6
	vmovdqu	[rsp+8+XB_QP],ymm5
	vmovdqu	[rsp+8+XB_QM],ymm1
	vmovdqu	[rsp+8+XB_T0],ymm6		; the mask, past the call below
	vzeroupper
	lea	rdi,[rsp+8+XB_RX]
	lea	rsi,[fe_zero]
	lea	rdx,[rsp+8+XB_QD]
	call	fe_sub				; -2dxy
	vmovdqu	ymm6,[rsp+8+XB_T0]
	vmovdqu	ymm2,[rsp+8+XB_QD]
	vpblendvb ymm2,ymm2,yword [rsp+8+XB_RX],ymm6
	vmovdqu	[rsp+8+XB_QD],ymm2
	vpxor	ymm5,ymm5,ymm5
	vpxor	ymm6,ymm6,ymm6
	vzeroupper
	ret

; [rsp+XB_K] = a scalar below 2^255: k * B into the extended sum
; [rsp+XB_X..XB_T], in constant time (the frame of x25519_base)
macro xb_mult_body
	; radix 16, then signed: each digit in [-8, 8)
	xor	ecx,ecx
@@:
	movzx	eax,byte [rsp+XB_K+rcx]
	mov	edx,eax
	and	eax,15
	shr	edx,4
	mov	[rsp+XB_E+rcx*2],al
	mov	[rsp+XB_E+rcx*2+1],dl
	inc	ecx
	cmp	ecx,32
	jb	@b
	xor	ecx,ecx				; ecx = the carry
	xor	r8d,r8d
@@:
	movsx	eax,byte [rsp+XB_E+r8]
	add	eax,ecx
	lea	ecx,[rax+8]
	sar	ecx,4
	mov	edx,ecx
	shl	edx,4
	sub	eax,edx
	mov	[rsp+XB_E+r8],al
	inc	r8d
	cmp	r8d,63
	jb	@b
	add	[rsp+XB_E+63],cl
	; the neutral point (0 : 1 : 1 : 0)
	lea	rdi,[rsp+XB_X]
	xor	eax,eax
	mov	ecx,16
	rep	stosq
	mov	qword [rsp+XB_Y],1
	mov	qword [rsp+XB_Z],1
	mov	r12d,1				; the odd digits
.odd:
	call	xb_select
	call	xb_madd
	add	r12d,2
	cmp	r12d,64
	jb	.odd
	mov	r13d,3				; times 16
.times16:
	call	xb_dbl
	call	xb_to_p2
	dec	r13d
	jnz	.times16
	call	xb_dbl
	call	xb_to_p3
	xor	r12d,r12d			; the even digits
.even:
	call	xb_select
	call	xb_madd
	add	r12d,2
	cmp	r12d,64
	jb	.even
end macro

x25519_base:
	push	rbx
	push	r12
	push	r13
	sub	rsp,XB_SIZE
	mov	[rsp+XB_OUT],rdi
	lea	rdi,[rsp+XB_K]
	mov	ecx,32
	rep	movsb
	and	byte [rsp+XB_K],248		; clamped as X25519 does
	and	byte [rsp+XB_K+31],127
	or	byte [rsp+XB_K+31],64
	xb_mult_body
	; u = (Z + Y) / (Z - Y)
	lea	rdi,[rsp+XB_T0]
	lea	rsi,[rsp+XB_Z]
	lea	rdx,[rsp+XB_Y]
	call	fe_add
	lea	rdi,[rsp+XB_RX]
	lea	rsi,[rsp+XB_Z]
	lea	rdx,[rsp+XB_Y]
	call	fe_sub
	lea	rdi,[rsp+XB_RY]
	lea	rsi,[rsp+XB_RX]
	call	fe_inv
	lea	rdi,[rsp+XB_RZ]
	lea	rsi,[rsp+XB_T0]
	lea	rdx,[rsp+XB_RY]
	call	fe_mul
	lea	rdi,[rsp+XB_RZ]
	call	fe_canon
	mov	rdi,[rsp+XB_OUT]
	lea	rsi,[rsp+XB_RZ]
	mov	ecx,32
	rep	movsb
	mov	rdi,rsp				; the scalar, its digits, the sum
	mov	ecx,XB_OUT
	call	secure_zero
	add	rsp,XB_SIZE
	pop	r13
	pop	r12
	pop	rbx
	ret
