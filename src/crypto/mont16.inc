; Montgomery products of 16 limbs (1024 bits: the halves of an RSA-2048
; private operation by CRT), on BMI2 and ADX: mulx leaves the flags alone,
; and adcx and adox each carry on one flag, so a row of a*b[i] adds its low
; halves on CF and its high halves on OF at once - two carry chains where
; mul and adc have one, and no rdx:rax to wait on. Every row is unrolled
; (repeat). The accumulator, 18 limbs, lives on the stack (in L1 all along).
;
; The result is reduced below the modulus by a subtraction kept or not by a
; mask: no branch and no address depends on the values (they are the private
; exponent's powers).
;
; Taken by bn_mont_mul for 16 limbs when the CPU has both (g_cpu_adx).

M16		:= 16

; one step of a row: lo of rdx * [src] onto [acc] (CF chain), with the high
; half of the step before (OF chain); the high halves alternate between r9 and
; r10 by the step's parity, so none is moved (odd: the high half before is in
; r9, this one goes to r10). [dst] gets the sum.
macro m16_step par*, src*, acc*, dst*
	if par = 0
		mulx	r9,r8,src
		adcx	r8,acc
		adox	r8,r10
	else
		mulx	r10,r8,src
		adcx	r8,acc
		adox	r8,r9
	end if
	mov	dst,r8
end macro
M16_T		:= (M16 + 2) * 8		; the accumulator's bytes

; a row of mont16_mul: T (rbp, 18 limbs) = (T + a b[i] + m mod) / 2^64, a in
; r12, b[i] at r13 (moved on), mod r14, n0 r15
macro m16_mul_row
	; T += a * b[i]: low halves on CF into T[j], high halves on OF into T[j+1]
	mov	rdx,[r13]
	add	r13,8
	xor	eax,eax				; (CF = OF = 0)
	xor	r10d,r10d			; the high half before
	repeat M16, j:0
		m16_step j and 1, [r12+j*8], [rbp+j*8], [rbp+j*8]
	end repeat
	mov	r8,[rbp+M16*8]			; (M16 even: the last high half in r10)
	adcx	r8,rax
	adox	r8,r10
	mov	[rbp+M16*8],r8
	mov	r8,[rbp+M16*8+8]
	adcx	r8,rax
	adox	r8,rax
	mov	[rbp+M16*8+8],r8
	; T = (T + m mod) / 2^64, m = T[0] n0: T[0] becomes 0, all move down
	mov	rdx,[rbp]
	imul	rdx,r15
	xor	eax,eax
	xor	r10d,r10d
	mulx	r9,r8,[r14]
	adcx	r8,[rbp]			; (0 by m's choice: its carry is what counts)
	repeat M16 - 1, j:1
		m16_step j and 1, [r14+j*8], [rbp+j*8], [rbp+j*8-8]
	end repeat
	mov	r8,[rbp+M16*8]			; (j = 15 odd: its high half in r10)
	adcx	r8,rax
	adox	r8,r10
	mov	[rbp+M16*8-8],r8
	mov	r8,[rbp+M16*8+8]
	adcx	r8,rax
	adox	r8,rax
	mov	[rbp+M16*8],r8
	mov	qword [rbp+M16*8+8],0
end macro

; rdi = out, rsi = a, rdx = b, rcx = mod, r8 = -mod^-1 mod 2^64: out = a b /
; 2^1024 mod mod (a, b < mod; out may be a or b). Keeps rbx, rbp, r12-r15.
mont16_mul:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,M16_T + 8			; (16-aligned)
	mov	rbx,rdi				; out
	mov	r12,rsi				; a
	mov	r13,rdx				; b
	mov	r14,rcx				; mod
	mov	r15,r8				; n0
	mov	rbp,rsp				; T
	vpxor	xmm0,xmm0,xmm0
	vmovdqu	[rbp],ymm0
	vmovdqu	[rbp+32],ymm0
	vmovdqu	[rbp+64],ymm0
	vmovdqu	[rbp+96],ymm0
	vmovdqu	[rbp+128],xmm0
	vzeroupper
	mov	ecx,M16				; rows
.row:
	m16_mul_row
	dec	ecx
	jnz	.row
	call	mont16_final
	add	rsp,M16_T + 8
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

; mont16_mul's and mont16_sqr's end: T (rbp, 17 limbs, < 2 mod) less mod
; when not below it, into out (rbx), r14 = mod. Branch-free. Clobbers rax,
; rcx, rdx.
mont16_final:
	xor	ecx,ecx				; (CF = 0)
	repeat M16, j:0
		mov	rax,[rbp+j*8]
		sbb	rax,[r14+j*8]
		mov	[rbx+j*8],rax		; out = T - mod, tentatively
	end repeat
	mov	rax,[rbp+M16*8]
	sbb	rax,0				; borrow through T's top: CF = T < mod
	sbb	rcx,rcx				; all ones when T < mod: T itself
	repeat M16, j:0
		mov	rax,[rbp+j*8]
		mov	rdx,[rbx+j*8]
		xor	rax,rdx
		and	rax,rcx
		xor	rax,rdx
		mov	[rbx+j*8],rax
	end repeat
	ret

; rdi = out, rsi = a, rcx = mod, r8 = -mod^-1 mod 2^64: out = a^2 / 2^1024
; mod mod (a < mod; out may be a). Each cross product a[i] a[j] (i < j) once,
; then doubled with the squares added (adcx doubling, adox adding), then the
; 32 limbs reduced a row at a time (SOS): 392 mulx where a product takes 512.
; mont16_sqr's work: P (rbp, 34 limbs, zeroed) = a (r12) squared, reduced by
; mod (r14, n0 r15) into P[16..32]
macro m16_sqr_body
	; the cross products: row i adds a[i] a[j], j > i, at P[i+j] (low halves
	; on CF) and P[i+j+1] (high halves on OF); its last carry is P[i+16],
	; untouched before (the rows so far fit below 2^(64 (i+17)))
	repeat M16 - 1, i:0
		mov	rdx,[r12+i*8]
		xor	eax,eax
		xor	r10d,r10d
		repeat M16 - 1 - i, k:i+1
			m16_step (k - i - 1) and 1, [r12+k*8], [rbp+(i+k)*8], [rbp+(i+k)*8]
		end repeat
		mov	r8d,0
		if (M16 - 1 - i) and 1		; the last high half: r9 after an even step
			adcx	r8,r9
		else
			adcx	r8,r10
		end if
		adox	r8,rax
		mov	[rbp+(i+M16)*8],r8
	end repeat
	; twice them, and the squares: P[2i] = 2 P[2i] + lo(a[i]^2), P[2i+1] = 2
	; P[2i+1] + hi(a[i]^2), the doubling's carry on CF, the squares' on OF
	; (the whole is a^2 < 2^2048: nothing past P[31])
	xor	eax,eax
	repeat M16, i:0
		mov	rdx,[r12+i*8]
		mulx	r9,r8,rdx
		mov	r10,[rbp+(2*i)*8]
		adcx	r10,r10
		adox	r10,r8
		mov	[rbp+(2*i)*8],r10
		mov	r11,[rbp+(2*i+1)*8]
		adcx	r11,r11
		adox	r11,r9
		mov	[rbp+(2*i+1)*8],r11
	end repeat
	; reduced: row i adds m mod at P[i], m = P[i] n0 (P[i] becomes 0); its
	; last carry goes into P[i+16] with the one the row before left (r11)
	xor	r11d,r11d
	repeat M16, i:0
		mov	rdx,[rbp+i*8]
		imul	rdx,r15
		xor	eax,eax
		xor	r10d,r10d
		repeat M16, k:0
			m16_step k and 1, [r14+k*8], [rbp+(i+k)*8], [rbp+(i+k)*8]
		end repeat
		mov	r8,[rbp+(i+M16)*8]		; (M16 even: the last high half in r10)
		adcx	r8,r10
		adox	r8,r11
		mov	[rbp+(i+M16)*8],r8
		mov	r11d,0
		adcx	r11,rax
		adox	r11,rax
	end repeat
	mov	[rbp+2*M16*8],r11		; the top limb
end macro

M16_P		:= (2 * M16 + 2) * 8		; the double-width accumulator's bytes
mont16_sqr:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,M16_P + 8			; (16-aligned)
	mov	rbx,rdi				; out
	mov	r12,rsi				; a
	mov	r14,rcx				; mod
	mov	r15,r8				; n0
	mov	rbp,rsp				; P, 34 limbs
	vpxor	xmm0,xmm0,xmm0
	repeat 8, k:0
		vmovdqu	[rbp+k*32],ymm0
	end repeat
	vmovdqu	[rbp+256],xmm0
	vzeroupper
	m16_sqr_body
	add	rbp,M16*8			; T = P[16..32]
	call	mont16_final
	add	rsp,M16_P + 8
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret
