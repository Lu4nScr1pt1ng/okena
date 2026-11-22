; Montgomery products of 1024-bit numbers on AVX2 (vpmuludq: four 32x32-bit
; products an instruction, in the vector units, beside the integer ones).
;
; V37: a number as 37 digits of 28 bits, digit j in qword j + 4 of a 48-qword
; (384-byte) buffer whose other qwords are 0 (the products read the digits
; shifted by up to 3 places either way). A digit may run a little over 28 bits
; (up to 2^28 + 2^8): the sums are not carried to the last bit.
;
; v37_mul is an almost Montgomery product, R = 2^1036: out = a b / R mod q,
; below 2q when a and b are (4q < R: no subtraction, no branch, nothing that
; depends on the values). Digits of 28 bits keep the sums in 64-bit lanes: a
; lane gets at most 74 products below 2^56.
;
; The accumulator is a window of 10 registers (40 digits) that slides by 4
; digits every 4 steps: the registers are renamed instead of moved, and the
; operands are read shifted (unaligned loads) instead of the accumulator
; shifted. Step i adds a b[i] and y q, y = the low digit times -q^-1 mod 2^28;
; the low digit and its carry are worked out in xmm lane 0 from a copy of the
; digit taken before the step before added its y q - the chain from y to the
; next y is 4 instructions, the rest runs beside it.
;
; The modulus block: q as V37, -q^-1 mod 2^28 in its qword 0 (not read as a
; digit), then q shifted up 1, 2 and 3 digits (V37 each): every load of q
; aligned. a is shifted the same way once a product, on the stack.

V37_D		:= 37
V37_SZ		:= 384
V37_MB		:= 4 * V37_SZ			; the modulus block

; the window's register k in group m
macro v37_t k*, m*, body&
	repeat 1, r:((k) + (m)) mod 10
		v37T equ ymm#r
		v37X equ xmm#r
	end repeat
	body
	restore v37T
	restore v37X
end macro

macro v37_step i*
	local m, s, cur, nxt
	m = (i) shr 2
	s = (i) and 3
	if s = 0 & m > 0			; the window slides: its old bottom is its top
		v37_t 9, m, vpxor v37X,v37X,v37X
	end if
	if (i) and 1
		cur = 15
		nxt = 13
	else
		cur = 13
		nxt = 15
	end if
	vpbroadcastq ymm10,[v37B+((i)+4)*8]
	; the low digit: its copy + a[0] b[i] + q[1] y before + the carry
	repeat 1, u:cur
		vpmuludq xmm12,xmm14,[v37N+40]
		vpaddq	xmm#u,xmm#u,xmm12
		vpmuludq xmm12,xmm10,[v37A+32]
		vpaddq	xmm#u,xmm#u,xmm12
	end repeat
	; a b[i] at i
	repeat 10, k:0
		if s = 0
			vpmuludq ymm12,ymm10,[v37A+(4+4*k)*8]
		else
			vpmuludq ymm12,ymm10,[v37F+(s-1)*320+32*k]
		end if
		v37_t k, m, vpaddq v37T,v37T,ymm12
	end repeat
	if (i) > 0
		v37_yadd (i) - 1
	end if
	; the next low digit's copy, before y q is added
	repeat 1, u:nxt
		if (i) = V37_D - 1		; (the last: it gets only the carry out)
			vpxor	xmm#u,xmm#u,xmm#u
		else if s = 0
			v37_t 0, m, vpunpckhqdq xmm#u,v37X,v37X
		else if s = 1
			v37_t 0, m, vextracti128 xmm#u,v37T,1
		else if s = 2
			v37_t 0, m, vpermq ymm#u,v37T,3
		else
			v37_t 1, m, vmovq xmm#u,v37X
		end if
	end repeat
	; y, the carry out of the low digit
	repeat 1, u:cur
		vpmuludq xmm14,xmm#u,[v37N]
		vpand	xmm14,xmm14,dqword [v37_mask]
		vpbroadcastq ymm11,xmm14
		vpmuludq xmm12,xmm14,[v37N+32]
		vpaddq	xmm12,xmm#u,xmm12
		vpsrlq	xmm12,xmm12,28
	end repeat
	repeat 1, u:nxt				; the carry into the next low digit
		vpaddq	xmm#u,xmm#u,xmm12
	end repeat
end macro

; y q at i (after a b[i+1]: by then y is there). Its digits below i + 1 are
; not needed (the low digits are followed apart): at s = 3, none of T0's.
macro v37_yadd i*
	local m, s
	m = (i) shr 2
	s = (i) and 3
	repeat 10, k:0
		if k > 0 | s < 3
			vpmuludq ymm12,ymm11,[v37N+s*V37_SZ+(4+4*k)*8]
			v37_t k, m, vpaddq v37T,v37T,ymm12
		end if
	end repeat
end macro

; v37_mul's start: a (v37A) shifted into the frame (v37F), the window and
; the chain zeroed
macro v37_init
	repeat 3, s:1				; a shifted up 1, 2, 3 digits: aligned loads
		repeat 10, k:0			; after (none across a cache line)
			vmovdqu	ymm12,[v37A+(4+4*k-s)*8]
			vmovdqa	[v37F+(s-1)*320+32*k],ymm12
		end repeat
	end repeat
	repeat 10, k:0
		vpxor	xmm#k,xmm#k,xmm#k
	end repeat
	vpxor	xmm14,xmm14,xmm14		; y before: 0
	vpxor	xmm11,xmm11,xmm11		; (and broadcast)
	vpxor	xmm13,xmm13,xmm13		; the low digit's copy (and carry): 0
end macro

; its end, after the 37 steps and the last y q: into v37O; m = the window's
; base (9 unrolled, 0 rolled)
macro v37_finish m*
	; the window at its end holds the digits 36..75: the result is 37.. (the
	; last carry into 37); digit 36 is nothing, written as the pad's 0
	vpslldq	xmm12,xmm15,8			; (the last step's carry: V37_D - 1 even)
	v37_t 0, m, vpaddq v37T,v37T,ymm12
	vpxor	xmm10,xmm10,xmm10
	v37_t 0, m, vpblendd v37T,v37T,ymm10,3
	vpbroadcastq ymm15,qword [v37_mask]
	repeat 2				; two carry passes: digits < 2^28 + 2^8
		repeat 10, k:0
			v37_t k, m, vpsrlq ymm11,v37T,28
			v37_t k, m, vpand v37T,v37T,ymm15
			if k and 1
				vpermq	ymm13,ymm11,0x93
				vpblendd ymm14,ymm13,ymm12,3
			else
				vpermq	ymm12,ymm11,0x93
				if k = 0
					vpblendd ymm14,ymm12,ymm10,3
				else
					vpblendd ymm14,ymm12,ymm13,3
				end if
			end if
			v37_t k, m, vpaddq v37T,v37T,ymm14
		end repeat
	end repeat
	repeat 10, k:0
		v37_t k, m, vmovdqu [v37O+(4*k+3)*8],v37T
	end repeat
end macro


v37A equ rsi
v37B equ rdx
v37N equ rcx
v37F equ rsp
v37O equ rdi

; rdi = out, rsi = a, rdx = b, rcx = the modulus block (all V37; out may be a
; or b). Clobbers ymm0-ymm15 (upper halves zeroed after).
v37_mul:
	push	rbp
	mov	rbp,rsp
	sub	rsp,3*320
	and	rsp,-32
	v37_init
	repeat V37_D, i:0
		v37_step i
	end repeat
	v37_yadd V37_D - 1
	v37_finish 9
	vzeroupper
	mov	rsp,rbp
	pop	rbp
	ret

restore v37A, v37B, v37N, v37F, v37O

; crt_half (rsacrt.inc) for 1024-bit primes (RSA-2048), on v37_mul: rdi = out
; (16 limbs), rsi = c (32 limbs), rdx = the prime, rcx = the CRT block, r8d =
; 0 for p, 1 for q: out = c^(dp or dq) mod the prime. 5-bit windows over a
; table of 32 powers (in Montgomery form for R = 2^1036), each picked by a
; scan of all 32. The frame (powers: secrets) is wiped. Keeps rbx, rbp,
; r12-r15.
CV_TAB		:= 0				; 32 V37 powers
CV_RES		:= 32 * V37_SZ
CV_TMP		:= CV_RES + V37_SZ
CV_MB		:= CV_TMP + V37_SZ		; the modulus block
CV_ONE		:= CV_MB + V37_MB		; 1 (V37)
CV_S		:= CV_ONE + V37_SZ		; 3 x 16 limbs (scalar), 17 at the end
CV_SZ		:= CV_S + 3 * 128
CV_RR		:= CV_SZ			; R^2 mod p (R = 2^1024), R^3, the exponent
CV_R3		:= CV_SZ + 8
CV_EXP		:= CV_SZ + 16
crt_half_v:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rdx				; the prime
	mov	r13,rdi				; out
	mov	r14,rsi				; c
	lea	rax,[rcx+CRT_P0]
	lea	r9,[rcx+CRT_RRP]
	lea	r10,[rcx+CRT_R3P]
	lea	r11,[rcx+CRT_DP]
	test	r8d,r8d
	jz	@f
	lea	rax,[rcx+CRT_Q0]
	lea	r9,[rcx+CRT_RRQ]
	lea	r10,[rcx+CRT_R3Q]
	lea	r11,[rcx+CRT_DQ]
@@:
	mov	rbp,rsp
	sub	rsp,CV_SZ + 32
	and	rsp,-64
	mov	r15,[rax]			; -p^-1 mod 2^64
	mov	rdi,rsp				; (the pads are 0)
	mov	ecx,CV_SZ / 8
	xor	eax,eax
	rep	stosq
	mov	[rsp+CV_RR],r9
	mov	[rsp+CV_R3],r10
	mov	[rsp+CV_EXP],r11
	; x = c R mod p = c_lo RR / R + c_hi R^3 / R (scalar)
	lea	rdi,[rsp+CV_S+128]
	mov	rsi,r14
	mov	rdx,[rsp+CV_RR]
	call	.smul
	lea	rdi,[rsp+CV_S]
	lea	rsi,[r14+128]
	mov	rdx,[rsp+CV_R3]
	call	.smul
	lea	rdi,[rsp+CV_S]
	lea	rsi,[rsp+CV_S+128]
	mov	rdx,r12
	mov	ecx,16
	call	crt_add_mod
	; K = RR 2^24 / R = 2^1048 mod p: x K / 2^1036 = c 2^1036, the vector form
	mov	qword [rsp+CV_S+256],1 shl 24
	lea	rdi,[rsp+CV_S+128]
	mov	rsi,[rsp+CV_RR]
	lea	rdx,[rsp+CV_S+256]
	call	.smul
	lea	rdi,[rsp+CV_MB]
	mov	rsi,r12
	mov	rdx,r15
	call	v37_modblock
	lea	rdi,[rsp+CV_TMP]
	lea	rsi,[rsp+CV_S]
	mov	edx,16
	call	v37_from
	lea	rdi,[rsp+CV_RES]
	lea	rsi,[rsp+CV_S+128]
	mov	edx,16
	call	v37_from
	lea	rdi,[rsp+CV_TAB+V37_SZ]		; table[1] = c R'
	lea	rsi,[rsp+CV_TMP]
	lea	rdx,[rsp+CV_RES]
	lea	rcx,[rsp+CV_MB]
	call	v37_mul
	; table[0] = R' mod p = RR 2^12 / R
	mov	qword [rsp+CV_S+256],1 shl 12
	lea	rdi,[rsp+CV_S+128]
	mov	rsi,[rsp+CV_RR]
	lea	rdx,[rsp+CV_S+256]
	call	.smul
	lea	rdi,[rsp+CV_TAB]
	lea	rsi,[rsp+CV_S+128]
	mov	edx,16
	call	v37_from
	; table[i] = table[i-1] table[1]
	mov	ebx,2
.pow:
	imul	edi,ebx,V37_SZ
	lea	rdi,[rsp+rdi]
	lea	rsi,[rdi-V37_SZ]
	lea	rdx,[rsp+CV_TAB+V37_SZ]
	lea	rcx,[rsp+CV_MB]
	call	v37_mul
	inc	ebx
	cmp	ebx,32
	jb	.pow
	; the windows from the top: 1024 = 4 + 5 * 204
	mov	ebx,1020
	call	.window
	lea	rdi,[rsp+CV_RES]
	call	.select
.next:
	test	ebx,ebx
	jz	.done
	sub	ebx,5
	repeat 5
		lea	rdi,[rsp+CV_RES]
		mov	rsi,rdi
		mov	rdx,rdi
		lea	rcx,[rsp+CV_MB]
		call	v37_mul
	end repeat
	call	.window
	lea	rdi,[rsp+CV_TMP]
	call	.select
	lea	rdi,[rsp+CV_RES]
	mov	rsi,rdi
	lea	rdx,[rsp+CV_TMP]
	lea	rcx,[rsp+CV_MB]
	call	v37_mul
	jmp	.next
.done:
	; out of Montgomery form: res 1 / R' (at most p), then below p
	mov	qword [rsp+CV_ONE+32],1
	lea	rdi,[rsp+CV_TMP]
	lea	rsi,[rsp+CV_RES]
	lea	rdx,[rsp+CV_ONE]
	lea	rcx,[rsp+CV_MB]
	call	v37_mul
	lea	rdi,[rsp+CV_S]
	lea	rsi,[rsp+CV_TMP]
	call	v37_to
	mov	rdi,r13
	lea	rsi,[rsp+CV_S]
	mov	rdx,r12
	mov	ecx,16
	call	crt_sub_cond
	mov	rdi,rsp
	mov	ecx,CV_SZ
	call	secure_zero
	mov	rsp,rbp
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret
; rdi = out, rsi = a, rdx = b: a b / 2^1024 mod p (scalar)
.smul:
	mov	rcx,r12
	mov	r8,r15
	mov	r9d,16
	jmp	bn_mont_mul
; ebx = a bit: eax = the exponent's 5 bits there (bits past its top 0)
.window:
	mov	rdx,[rsp+8+CV_EXP]
	mov	ecx,ebx
	mov	eax,ebx
	shr	eax,6
	and	ecx,63
	mov	r8,[rdx+rax*8]
	shr	r8,cl
	inc	eax
	cmp	eax,16
	jae	@f
	cmp	ecx,59
	jbe	@f
	mov	r9,[rdx+rax*8]
	neg	ecx
	add	ecx,64
	shl	r9,cl
	or	r8,r9
@@:
	mov	eax,r8d
	and	eax,31
	ret
; rdi = a V37 buffer, eax = which: table[eax] into it (digits' qwords 4..43),
; every entry read and masked (rsp + 8: the frame)
.select:
	vmovd	xmm12,eax
	vpbroadcastq ymm12,xmm12
	vpxor	xmm11,xmm11,xmm11		; the entry, in each lane
	mov	eax,1
	vmovd	xmm13,eax
	vpbroadcastq ymm13,xmm13
	repeat 10, g:0
		vpxor	xmm#g,xmm#g,xmm#g
	end repeat
	lea	rsi,[rsp+8+CV_TAB+32]
	mov	ecx,32
.entry:
	vpcmpeqq ymm10,ymm11,ymm12
	repeat 10, g:0				; (the entry where the mask is set)
		vpblendvb ymm#g,ymm#g,[rsi+32*g],ymm10
	end repeat
	vpaddq	ymm11,ymm11,ymm13
	add	rsi,V37_SZ
	dec	ecx
	jnz	.entry
	repeat 10, g:0
		vmovdqu	[rdi+32+32*g],ymm#g
	end repeat
	vzeroupper
	ret

; rdi = the modulus block (V37_MB bytes, 32-aligned), rsi = q (16 limbs, odd),
; rdx = -q^-1 mod 2^64. Keeps all but rax, rcx, rdx, r8-r11.
v37_modblock:
	push	rdx
	push	rdi
	mov	edx,16
	call	v37_from
	pop	rdi
	pop	rax
	and	eax,0x0fffffff
	mov	[rdi],rax
	vpxor	xmm1,xmm1,xmm1
	repeat 3, s:1				; (slots 0..3 are not read)
		vmovdqa	[rdi+s*V37_SZ],ymm1
		repeat 11, j:1
			vmovdqu	ymm0,[rdi+(4*j-s)*8]
			vmovdqa	[rdi+s*V37_SZ+32*j],ymm0
		end repeat
	end repeat
	vzeroupper
	ret


; rdi = out (V37), rsi = a, edx = its limbs (16 or 17; below 2^1036). Keeps
; all but rax, rcx, rdx, r8-r11.
v37_from:
	push	rdi
	xor	eax,eax
	mov	ecx,V37_SZ / 8
	rep	stosq
	pop	rdi
	xor	r8d,r8d				; the digit
.d:
	imul	eax,r8d,28			; its bit
	mov	r9d,eax
	shr	r9d,6				; the limb
	mov	ecx,eax
	and	ecx,63
	xor	r10d,r10d
	cmp	r9d,edx
	jae	.put
	mov	r10,[rsi+r9*8]
	shr	r10,cl
	inc	r9d
	cmp	r9d,edx
	jae	.put
	cmp	ecx,36
	jbe	.put
	mov	r11,[rsi+r9*8]
	neg	ecx
	add	ecx,64
	shl	r11,cl
	or	r10,r11
.put:
	and	r10d,0x0fffffff
	mov	[rdi+r8*8+32],r10
	inc	r8d
	cmp	r8d,V37_D
	jb	.d
	ret

; rdi = out (17 limbs), rsi = a (V37, its digits carried here first: a is
; changed, its value kept). Keeps all but rax, rcx, rdx, r8-r11.
v37_to:
	xor	edx,edx				; the carry
	xor	r8d,r8d
.n:
	mov	rax,[rsi+r8*8+32]
	add	rax,rdx
	mov	rdx,rax
	shr	rdx,28
	cmp	r8d,V37_D - 1
	je	@f				; (the top digit keeps it all)
	and	eax,0x0fffffff
@@:
	mov	[rsi+r8*8+32],rax
	inc	r8d
	cmp	r8d,V37_D
	jb	.n
	push	rdi
	xor	eax,eax
	mov	ecx,17
	rep	stosq
	pop	rdi
	xor	r8d,r8d
.p:
	imul	eax,r8d,28
	mov	r9d,eax
	shr	r9d,6
	mov	ecx,eax
	and	ecx,63
	mov	r10,[rsi+r8*8+32]
	mov	r11,r10
	shl	r10,cl				; its low part
	neg	ecx
	add	ecx,64
	shr	r11,cl				; its high part (none at a limb's start)
	cmp	ecx,64
	jne	@f
	xor	r11d,r11d
@@:
	add	[rdi+r9*8],r10
	adc	[rdi+r9*8+8],r11
	jnc	.pn
	lea	r10d,[r9d+2]			; a carry on up
.cc:
	cmp	r10d,17
	jae	.pn
	add	qword [rdi+r10*8],1
	inc	r10d
	jc	.cc
.pn:
	inc	r8d
	cmp	r8d,V37_D
	jb	.p
	ret

rodata
	align 16
	v37_mask	dq 0x0fffffff, 0x0fffffff
end rodata
