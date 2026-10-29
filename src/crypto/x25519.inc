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
; This first version multiplies with plain mul in memory: simple to check
; against the reference. A mulx version is the measured follow-up.

FE_SIZE		:= 32

; rdi = out, rsi = a, rdx = b (out may be a or b): a * b, below 2^256.
fe_mul:
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
	mov	ebx,121665
	mov	rax,[rsi]
	mul	rbx
	mov	r8,rax
	mov	r9,rdx
	mov	rax,[rsi+8]
	mul	rbx
	add	r9,rax
	adc	rdx,0
	mov	r10,rdx
	mov	rax,[rsi+16]
	mul	rbx
	add	r10,rax
	adc	rdx,0
	mov	r11,rdx
	mov	rax,[rsi+24]
	mul	rbx
	add	r11,rax
	adc	rdx,0				; rdx = above 2^256
	imul	rdx,rdx,38
	add	r8,rdx
	adc	r9,0
	adc	r10,0
	adc	r11,0
	sbb	rax,rax
	and	rax,38
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

; rdi = out, rsi = a: a^(p-2) = 1/a. Square and multiply over the public
; exponent 2^255 - 21 (bits 254..8 set, then 11101011).
fe_inv:
	push	rbx
	push	r12
	push	r13
	sub	rsp,64
	mov	r12,rdi
	mov	r13,rsi
	; r = a (bit 254)
	lea	rdi,[rsp]
	mov	rsi,r13
	mov	ecx,4
	rep	movsq
	mov	ebx,253
.bit:
	lea	rdi,[rsp]
	lea	rsi,[rsp]
	lea	rdx,[rsp]
	call	fe_mul				; square
	; bit ebx of 2^255 - 21
	cmp	ebx,8
	jae	.one
	mov	eax,0xEB
	bt	eax,ebx
	jnc	.next
.one:
	lea	rdi,[rsp]
	lea	rsi,[rsp]
	mov	rdx,r13
	call	fe_mul
.next:
	dec	ebx
	jns	.bit
	mov	rdi,r12
	lea	rsi,[rsp]
	mov	ecx,4
	rep	movsq
	mov	rdi,rsp
	mov	ecx,64
	call	secure_zero
	add	rsp,64
	pop	r13
	pop	r12
	pop	rbx
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
XL_SIZE		:= 480

; rdi = out[32], rsi = scalar[32], rdx = u[32] (RFC 7748 encodings).
x25519:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,XL_SIZE
	mov	r12,rdi
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
	xor	r14d,r14d			; swap
	mov	r13d,254			; bit
.step:
	; k_t, without a branch on it
	mov	eax,r13d
	shr	eax,3
	movzx	ecx,byte [rsp+XL_K+rax]
	mov	eax,r13d
	and	eax,7
	xchg	eax,ecx
	shr	eax,cl
	and	eax,1				; k_t
	mov	r15d,eax
	xor	r14d,eax			; swap ^= k_t
	mov	rdx,r14
	neg	rdx				; 0 or all ones
	push	rdx
	lea	rdi,[rsp+8+XL_X2]
	lea	rsi,[rsp+8+XL_X3]
	call	fe_cswap
	pop	rdx
	lea	rdi,[rsp+XL_Z2]
	lea	rsi,[rsp+XL_Z3]
	call	fe_cswap
	mov	r14d,r15d			; swap = k_t
	; A = x2 + z2, AA = A^2, B = x2 - z2, BB = B^2, E = AA - BB
	lea	rdi,[rsp+XL_A]
	lea	rsi,[rsp+XL_X2]
	lea	rdx,[rsp+XL_Z2]
	call	fe_add
	lea	rdi,[rsp+XL_AA]
	lea	rsi,[rsp+XL_A]
	lea	rdx,[rsp+XL_A]
	call	fe_mul
	lea	rdi,[rsp+XL_B]
	lea	rsi,[rsp+XL_X2]
	lea	rdx,[rsp+XL_Z2]
	call	fe_sub
	lea	rdi,[rsp+XL_BB]
	lea	rsi,[rsp+XL_B]
	lea	rdx,[rsp+XL_B]
	call	fe_mul
	lea	rdi,[rsp+XL_E]
	lea	rsi,[rsp+XL_AA]
	lea	rdx,[rsp+XL_BB]
	call	fe_sub
	; C = x3 + z3, D = x3 - z3, DA = D * A, CB = C * B
	lea	rdi,[rsp+XL_C]
	lea	rsi,[rsp+XL_X3]
	lea	rdx,[rsp+XL_Z3]
	call	fe_add
	lea	rdi,[rsp+XL_D]
	lea	rsi,[rsp+XL_X3]
	lea	rdx,[rsp+XL_Z3]
	call	fe_sub
	lea	rdi,[rsp+XL_DA]
	lea	rsi,[rsp+XL_D]
	lea	rdx,[rsp+XL_A]
	call	fe_mul
	lea	rdi,[rsp+XL_CB]
	lea	rsi,[rsp+XL_C]
	lea	rdx,[rsp+XL_B]
	call	fe_mul
	; x3 = (DA + CB)^2
	lea	rdi,[rsp+XL_X3]
	lea	rsi,[rsp+XL_DA]
	lea	rdx,[rsp+XL_CB]
	call	fe_add
	lea	rdi,[rsp+XL_X3]
	lea	rsi,[rsp+XL_X3]
	lea	rdx,[rsp+XL_X3]
	call	fe_mul
	; z3 = x1 * (DA - CB)^2
	lea	rdi,[rsp+XL_Z3]
	lea	rsi,[rsp+XL_DA]
	lea	rdx,[rsp+XL_CB]
	call	fe_sub
	lea	rdi,[rsp+XL_Z3]
	lea	rsi,[rsp+XL_Z3]
	lea	rdx,[rsp+XL_Z3]
	call	fe_mul
	lea	rdi,[rsp+XL_Z3]
	lea	rsi,[rsp+XL_Z3]
	lea	rdx,[rsp+XL_X1]
	call	fe_mul
	; x2 = AA * BB
	lea	rdi,[rsp+XL_X2]
	lea	rsi,[rsp+XL_AA]
	lea	rdx,[rsp+XL_BB]
	call	fe_mul
	; z2 = E * (AA + a24 * E)
	lea	rdi,[rsp+XL_Z2]
	lea	rsi,[rsp+XL_E]
	call	fe_mul_a24
	lea	rdi,[rsp+XL_Z2]
	lea	rsi,[rsp+XL_AA]
	lea	rdx,[rsp+XL_Z2]
	call	fe_add
	lea	rdi,[rsp+XL_Z2]
	lea	rsi,[rsp+XL_E]
	lea	rdx,[rsp+XL_Z2]
	call	fe_mul
	dec	r13d
	jns	.step
	mov	rdx,r14
	neg	rdx
	push	rdx
	lea	rdi,[rsp+8+XL_X2]
	lea	rsi,[rsp+8+XL_X3]
	call	fe_cswap
	pop	rdx
	lea	rdi,[rsp+XL_Z2]
	lea	rsi,[rsp+XL_Z3]
	call	fe_cswap
	; x2 / z2, canonical, little endian
	lea	rdi,[rsp+XL_Z2]
	lea	rsi,[rsp+XL_Z2]
	call	fe_inv
	lea	rdi,[rsp+XL_X2]
	lea	rsi,[rsp+XL_X2]
	lea	rdx,[rsp+XL_Z2]
	call	fe_mul
	lea	rdi,[rsp+XL_X2]
	call	fe_canon
	mov	rdi,r12
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
