; Modular inversion for 256-bit odd moduli in constant time, by Bernstein
; and Yang's divsteps ("Fast constant-time gcd computation and modular
; inversion", 2019) in the shape libsecp256k1 gives them (modinv64): the
; numbers as five signed 62-bit limbs, 10 batches of 59 divsteps (590, enough
; for 256 bits with the half-delta variant), each batch worked out on the
; low 64 bits alone (a 2x2 matrix scaled by 2^62) and then applied to f, g
; (the gcd's pair) and d, e (the cofactors, kept in (-2m, m) by adding
; multiples of m that zero their low 62 bits). Nothing branches on, or
; indexes by, the value.
;
; About a microsecond where Fermat's a^(m-2) takes 250-odd squarings.
;
;   minv(rdi out[4 limbs], rsi x[4 limbs] (below m), rdx the modulus' info):
;           out = 1/x mod m (0 for 0); out may be x

MNV_M		:= 0				; the modulus, 5 signed 62-bit limbs
MNV_INV		:= 40				; m^-1 mod 2^62
MNV_R3		:= 48				; R^3 mod m (R = 2^256: Montgomery forms)

rodata
	align 16
	minv_p25519:
	dq 0x3FFFFFFFFFFFFFED, 0x3FFFFFFFFFFFFFFF, 0x3FFFFFFFFFFFFFFF, 0x3FFFFFFFFFFFFFFF, 0x000000000000007F
	dq 0x39435E50D79435E5
	dq 0x000000000000D658, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000
	minv_p256p:
	dq 0x3FFFFFFFFFFFFFFF, 0x00000003FFFFFFFF, 0x0000000000000000, 0x3FFFFFC000000040, 0x00000000000000FF
	dq 0x3FFFFFFFFFFFFFFF
	dq 0xFFFFFFFD0000000A, 0xFFFFFFEDFFFFFFF7, 0x00000005FFFFFFFC, 0x0000001800000001
	minv_p256n:
	dq 0x33B9CAC2FC632551, 0x339BEAB69C5E7A13, 0x3FFFFFFFFFFFFFFB, 0x3FFFFFC00000003F, 0x00000000000000FF
	dq 0x332E375511FF43B1
	dq 0xAC8EBEC90B65A624, 0x111F28AE0C0555C9, 0x2543B9246BA5E93F, 0x503A54E76407BE65
end rodata

MNV_F		:= 0				; the frame: f, g, d, e (5 limbs each)
MNV_G		:= 40
MNV_D		:= 80
MNV_E		:= 120
MNV_T		:= 160				; the batch's matrix: u, v, q, r
MNV_MD		:= 192				; d's and e's multiples of m
MNV_ME		:= 200
MNV_OUT		:= 208
MNV_N		:= 216				; batches left
MNV_SIZE		:= 224

; reg = reg mod 2^62 (the top two bits cleared)
macro mv_low62 reg*
	shl	reg,2
	shr	reg,2
end macro

; 59 divsteps on f = r8, g = r9 (their low 64 bits), zeta = r15: the matrix
; (u, v, q, r) = (r10, r11, r12, r13), scaled by 2^62
macro mv_divsteps
	mov	r10d,8
	xor	r11d,r11d
	xor	r12d,r12d
	mov	r13d,8
	repeat 59
		mov	rax,r15
		sar	rax,63				; zeta < 0
		mov	edx,r9d
		and	edx,1
		neg	rdx				; g odd
		mov	rcx,r8
		xor	rcx,rax
		sub	rcx,rax				; f, negated when zeta < 0
		mov	rsi,r10
		xor	rsi,rax
		sub	rsi,rax
		mov	rdi,r11
		xor	rdi,rax
		sub	rdi,rax
		and	rcx,rdx				; added to g when g is odd
		add	r9,rcx
		and	rsi,rdx
		add	r12,rsi
		and	rdi,rdx
		add	r13,rdi
		and	rax,rdx				; both: f takes g's old value, zeta negated
		xor	r15,rax
		dec	r15
		mov	rcx,r9
		and	rcx,rax
		add	r8,rcx
		mov	rcx,r12
		and	rcx,rax
		add	r10,rcx
		mov	rcx,r13
		and	rcx,rax
		add	r11,rcx
		shr	r9,1
		add	r10,r10
		add	r11,r11
	end repeat
end macro

; acc (lo:hi) += [a] * mreg (signed); clobbers rax, rdx
macro mv_mac lo*, hi*, a*, mreg*
	mov	rax,a
	imul	mreg
	add	lo,rax
	adc	hi,rdx
end macro

; (lo:hi) >>= 62, arithmetic
macro mv_shr62 lo*, hi*
	shrd	lo,hi,62
	sar	hi,62
end macro

minv:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,MNV_SIZE
	mov	rbx,rdx				; the modulus' info
	mov	[rsp+MNV_OUT],rdi
	; g = x, five 62-bit limbs; f = m; d = 0; e = 1
	mov	r8,[rsi]
	mov	r9,[rsi+8]
	mov	r10,[rsi+16]
	mov	r11,[rsi+24]
	mov	rax,r8
	mv_low62 rax
	mov	[rsp+MNV_G],rax
	mov	rax,r9
	shld	rax,r8,2
	mv_low62 rax
	mov	[rsp+MNV_G+8],rax
	mov	rax,r10
	shld	rax,r9,4
	mv_low62 rax
	mov	[rsp+MNV_G+16],rax
	mov	rax,r11
	shld	rax,r10,6
	mv_low62 rax
	mov	[rsp+MNV_G+24],rax
	shr	r11,56
	mov	[rsp+MNV_G+32],r11
	repeat 5, i:0
		mov	rax,[rbx+MNV_M+i*8]
		mov	[rsp+MNV_F+i*8],rax
		mov	qword [rsp+MNV_D+i*8],0
		mov	qword [rsp+MNV_E+i*8],0
	end repeat
	mov	qword [rsp+MNV_E],1
	mov	r15,-1				; zeta
	mov	dword [rsp+MNV_N],10
.batch:
	mov	r8,[rsp+MNV_F]
	mov	r9,[rsp+MNV_G]
	mv_divsteps
	mov	[rsp+MNV_T],r10
	mov	[rsp+MNV_T+8],r11
	mov	[rsp+MNV_T+16],r12
	mov	[rsp+MNV_T+24],r13
	; [d, e] = (t [d, e] + m [md, me]) / 2^62, md and me chosen to make the
	; low 62 bits 0 (and to bring a negative d or e back up)
	mov	rax,[rsp+MNV_D+32]
	sar	rax,63				; sd
	mov	rcx,[rsp+MNV_E+32]
	sar	rcx,63				; se
	mov	rsi,r10
	and	rsi,rax
	mov	rdi,r11
	and	rdi,rcx
	add	rsi,rdi				; md = (u & sd) + (v & se)
	and	rax,r12
	and	rcx,r13
	add	rax,rcx
	mov	rdi,rax				; me = (q & sd) + (r & se)
	xor	r8d,r8d				; cd
	xor	r9d,r9d
	xor	r14d,r14d			; ce
	xor	ebp,ebp
	mv_mac	r8, r9, [rsp+MNV_D], r10
	mv_mac	r8, r9, [rsp+MNV_E], r11
	mv_mac	r14, rbp, [rsp+MNV_D], r12
	mv_mac	r14, rbp, [rsp+MNV_E], r13
	mov	rax,[rbx+MNV_INV]		; md -= (m^-1 cd + md) mod 2^62
	imul	rax,r8
	add	rax,rsi
	mv_low62 rax
	sub	rsi,rax
	mov	rax,[rbx+MNV_INV]
	imul	rax,r14
	add	rax,rdi
	mv_low62 rax
	sub	rdi,rax
	mov	[rsp+MNV_MD],rsi
	mov	[rsp+MNV_ME],rdi
	mv_mac	r8, r9, [rbx+MNV_M], rsi
	mv_mac	r14, rbp, [rbx+MNV_M], rdi
	mv_shr62 r8, r9
	mv_shr62 r14, rbp
	repeat 4, i:1
		mov	rsi,[rsp+MNV_MD]
		mov	rdi,[rsp+MNV_ME]
		mv_mac	r8, r9, [rsp+MNV_D+i*8], r10
		mv_mac	r8, r9, [rsp+MNV_E+i*8], r11
		mv_mac	r8, r9, [rbx+MNV_M+i*8], rsi
		mv_mac	r14, rbp, [rsp+MNV_D+i*8], r12
		mv_mac	r14, rbp, [rsp+MNV_E+i*8], r13
		mv_mac	r14, rbp, [rbx+MNV_M+i*8], rdi
		mov	rax,r8
		mv_low62 rax
		mov	[rsp+MNV_D+(i-1)*8],rax
		mov	rax,r14
		mv_low62 rax
		mov	[rsp+MNV_E+(i-1)*8],rax
		mv_shr62 r8, r9
		mv_shr62 r14, rbp
	end repeat
	mov	[rsp+MNV_D+32],r8
	mov	[rsp+MNV_E+32],r14
	; [f, g] = t [f, g] / 2^62 (exact)
	xor	r8d,r8d
	xor	r9d,r9d
	xor	r14d,r14d
	xor	ebp,ebp
	mv_mac	r8, r9, [rsp+MNV_F], r10
	mv_mac	r8, r9, [rsp+MNV_G], r11
	mv_mac	r14, rbp, [rsp+MNV_F], r12
	mv_mac	r14, rbp, [rsp+MNV_G], r13
	mv_shr62 r8, r9
	mv_shr62 r14, rbp
	repeat 4, i:1
		mv_mac	r8, r9, [rsp+MNV_F+i*8], r10
		mv_mac	r8, r9, [rsp+MNV_G+i*8], r11
		mv_mac	r14, rbp, [rsp+MNV_F+i*8], r12
		mv_mac	r14, rbp, [rsp+MNV_G+i*8], r13
		mov	rax,r8
		mv_low62 rax
		mov	[rsp+MNV_F+(i-1)*8],rax
		mov	rax,r14
		mv_low62 rax
		mov	[rsp+MNV_G+(i-1)*8],rax
		mv_shr62 r8, r9
		mv_shr62 r14, rbp
	end repeat
	mov	[rsp+MNV_F+32],r8
	mov	[rsp+MNV_G+32],r14
	dec	dword [rsp+MNV_N]
	jnz	.batch
	; f = +-1: d (in (-2m, m)) into [0, m), negated when f is -1
	mov	r8,[rsp+MNV_D]
	mov	r9,[rsp+MNV_D+8]
	mov	r10,[rsp+MNV_D+16]
	mov	r11,[rsp+MNV_D+24]
	mov	r12,[rsp+MNV_D+32]
	mov	rax,r12
	sar	rax,63				; negative: + m
	irp reg, r8,r9,r10,r11,r12
		mov	rcx,[rbx+MNV_M+(%-1)*8]
		and	rcx,rax
		add	reg,rcx
	end irp
	mov	rax,[rsp+MNV_F+32]
	sar	rax,63				; f = -1: negated
	irp reg, r8,r9,r10,r11,r12
		xor	reg,rax
		sub	reg,rax
	end irp
	call	.carry
	mov	rax,r12
	sar	rax,63				; still negative: + m
	irp reg, r8,r9,r10,r11,r12
		mov	rcx,[rbx+MNV_M+(%-1)*8]
		and	rcx,rax
		add	reg,rcx
	end irp
	call	.carry
	; back to four 64-bit limbs
	mov	rdi,[rsp+MNV_OUT]
	mov	rax,r9
	shl	rax,62
	or	rax,r8
	mov	[rdi],rax
	mov	rax,r10
	shl	rax,60
	shr	r9,2
	or	rax,r9
	mov	[rdi+8],rax
	mov	rax,r11
	shl	rax,58
	shr	r10,4
	or	rax,r10
	mov	[rdi+16],rax
	shl	r12,56
	shr	r11,6
	or	r12,r11
	mov	[rdi+24],r12
	; the frame held the value's cofactors
	lea	rdi,[rsp]
	mov	ecx,MNV_OUT
	call	secure_zero
	add	rsp,MNV_SIZE
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret
; r8..r12: each limb's bits past 62 into the next (arithmetic)
.carry:
	mov	rax,r8
	sar	rax,62
	add	r9,rax
	mv_low62 r8
	mov	rax,r9
	sar	rax,62
	add	r10,rax
	mv_low62 r9
	mov	rax,r10
	sar	rax,62
	add	r11,rax
	mv_low62 r10
	mov	rax,r11
	sar	rax,62
	add	r12,rax
	mv_low62 r11
	ret
