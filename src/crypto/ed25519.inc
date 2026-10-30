; Ed25519 (RFC 8032): signatures for certificates and CertificateVerify.
;
; Points are on the twisted Edwards curve -x^2 + y^2 = 1 + d x^2 y^2 over
; GF(2^255 - 19), in extended coordinates (X : Y : Z : T), x = X/Z,
; y = Y/Z, xy = T/Z (GE_*, 128 bytes), with the field arithmetic of
; src/crypto/x25519.inc. Signing computes r * B and a * B with
; x25519_base's fixed-base table (constant time, xb_mult_body); the
; scalars mod L by Barrett (HAC 14.42) on 64-bit limbs, the same
; instructions whatever the values. Verification works on public data
; only (the key, the message, the signature) and takes the short paths:
; [k](-A) by signed radix-16 windows over a table of eight multiples,
; with branches.
;
;   ed25519_public(rdi pub[32], rsi seed[32])
;   ed25519_sign(rdi sig[64], rsi seed[32], rdx pub[32], rcx message,
;                r8 length)
;   ed25519_verify(rdi pub[32], rsi message, rdx length, rcx sig[64])
;       eax = 1 when the signature is valid (S below L, A on the curve,
;       [S]B = R + [k]A with R compared as encoded), 0 otherwise

GE_X		:= 0
GE_Y		:= 32
GE_Z		:= 64
GE_T		:= 96
GE_SIZE		:= 128
; a cached point, for additions: (Y + X, Y - X, Z, 2dT)
GC_YPX		:= 0
GC_YMX		:= 32
GC_Z		:= 64
GC_T2D		:= 96

rodata
	align 8
	ed_d		dq 0x75EB4DCA135978A3, 0x00700A4D4141D8AB, 0x8CC740797779E898, 0x52036CEE2B6FFE73
	ed_d2		dq 0xEBD69B9426B2F159, 0x00E0149A8283B156, 0x198E80F2EEF3D130, 0x2406D9DC56DFFCE7
	ed_sqrtm1	dq 0xC4EE1B274A0EA0B0, 0x2F431806AD2FE478, 0x2B4D00993DFBD7A7, 0x2B8324804FC1DF0B
	sc_l		dq 0x5812631A5CF5D3ED, 0x14DEF9DEA2F79CD6, 0x0000000000000000, 0x1000000000000000, 0
	sc_mu		dq 0xED9CE5A30A2C131B, 0x2106215D086329A7, 0xFFFFFFFFFFFFFFEB, 0xFFFFFFFFFFFFFFFF
			dq 0x000000000000000F
end rodata

; f out, a[, b]: field operations on rbp-frame offsets
macro ef f*, o*, a*, b
	lea	rdi,[rbp+o]
	lea	rsi,[rbp+a]
	match any, b
		lea	rdx,[rbp+b]
	end match
	call	f
end macro

; ---------------------------------------------------------------- scalars

; rdi = out (na + nb limbs), rsi = a, ecx = na, rdx = b, r8d = nb: a * b,
; schoolbook. Loops by the sizes only.
mp_mul:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rdi
	mov	r13,rsi
	mov	r14,rdx
	mov	r15d,ecx
	lea	ecx,[rcx+r8]
	xor	eax,eax
	rep	stosq
	xor	r9d,r9d				; i
.row:
	xor	r10d,r10d			; carry
	xor	r11d,r11d			; j
	lea	rbx,[r12+r9*8]
.col:
	mov	rax,[r13+r9*8]
	mul	qword [r14+r11*8]
	add	rax,r10
	adc	rdx,0
	add	[rbx+r11*8],rax
	adc	rdx,0
	mov	r10,rdx
	inc	r11d
	cmp	r11d,r8d
	jb	.col
	mov	[rbx+r11*8],r10
	inc	r9d
	cmp	r9d,r15d
	jb	.row
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = out[32], rsi = x[64] (little endian): x mod L, by Barrett with
; b = 2^64, k = 4: q3 = ((x >> 192) * mu) >> 320, r = (x - q3 L) mod
; 2^320, then two masked subtractions of L (r < 3L).
SR_Q2		:= 0				; 10 limbs
SR_T		:= 80				; 9 limbs
SR_R		:= 152				; 5 limbs
SR_U		:= 192				; 5 limbs
SR_X		:= 232				; q: x
SR_OUT		:= 240
SR_SIZE		:= 256
sc_reduce:
	push	rbx
	sub	rsp,SR_SIZE
	mov	[rsp+SR_X],rsi
	mov	[rsp+SR_OUT],rdi
	lea	rdi,[rsp+SR_Q2]
	add	rsi,24				; x >> 192: limbs 3..7
	mov	ecx,5
	lea	rdx,[sc_mu]
	mov	r8d,5
	call	mp_mul
	lea	rdi,[rsp+SR_T]			; q3 L, q3 = limbs 5..9 of q2
	lea	rsi,[rsp+SR_Q2+40]
	mov	ecx,5
	lea	rdx,[sc_l]
	mov	r8d,4
	call	mp_mul
	mov	rsi,[rsp+SR_X]			; r = x - q3 L, mod 2^320
	mov	rax,[rsi]
	sub	rax,[rsp+SR_T]
	mov	[rsp+SR_R],rax
	repeat 4, i:1
		mov	rax,[rsi+i*8]
		sbb	rax,[rsp+SR_T+i*8]
		mov	[rsp+SR_R+i*8],rax
	end repeat
	repeat 2
		; u = r - L; r = u unless that borrowed
		mov	rax,[rsp+SR_R]
		sub	rax,[sc_l]
		mov	[rsp+SR_U],rax
		repeat 4, i:1
			mov	rax,[rsp+SR_R+i*8]
			sbb	rax,[sc_l+i*8]
			mov	[rsp+SR_U+i*8],rax
		end repeat
		sbb	rbx,rbx				; all ones: r < L, keep r
		repeat 5, i:0
			mov	rax,[rsp+SR_R+i*8]
			xor	rax,[rsp+SR_U+i*8]
			and	rax,rbx
			xor	rax,[rsp+SR_U+i*8]
			mov	[rsp+SR_R+i*8],rax
		end repeat
	end repeat
	mov	rdi,[rsp+SR_OUT]
	repeat 4, i:0
		mov	rax,[rsp+SR_R+i*8]
		mov	[rdi+i*8],rax
	end repeat
	mov	rdi,rsp
	xor	eax,eax
	mov	ecx,SR_X / 8
	rep	stosq
	add	rsp,SR_SIZE
	pop	rbx
	ret

; rdi = out[32], rsi = a[32], rdx = b[32], rcx = c[32]: (a b + c) mod L.
sc_muladd:
	push	rbx
	push	r12
	sub	rsp,64 + 16
	mov	rbx,rdi
	mov	r12,rcx
	mov	rdi,rsp
	mov	ecx,4
	mov	r8d,4
	call	mp_mul
	mov	rax,[r12]
	add	[rsp],rax
	repeat 3, i:1
		mov	rax,[r12+i*8]
		adc	[rsp+i*8],rax
	end repeat
	repeat 4, i:4
		adc	qword [rsp+i*8],0
	end repeat
	mov	rdi,rbx
	mov	rsi,rsp
	call	sc_reduce
	mov	rdi,rsp
	xor	eax,eax
	mov	ecx,8
	rep	stosq
	add	rsp,64 + 16
	pop	r12
	pop	rbx
	ret

; ----------------------------------------------------------------- points

; rdi = out (a GE), rsi = scalar[32] below 2^255: scalar * B in constant
; time (the fixed-base table of x25519_base).
ed25519_base:
	push	rbx
	push	r12
	push	r13
	sub	rsp,XB_SIZE
	mov	[rsp+XB_OUT],rdi
	lea	rdi,[rsp+XB_K]
	mov	ecx,32
	rep	movsb
	xb_mult_body
	mov	rdi,[rsp+XB_OUT]
	lea	rsi,[rsp+XB_X]			; X, Y, Z, T are consecutive
	mov	ecx,GE_SIZE
	rep	movsb
	mov	rdi,rsp
	mov	ecx,XB_OUT
	call	secure_zero
	add	rsp,XB_SIZE
	pop	r13
	pop	r12
	pop	rbx
	ret

; ge frame: eight temporaries, then the operands' pointers
GF_A		:= 0
GF_B		:= 32
GF_C		:= 64
GF_D		:= 96
GF_E		:= 128
GF_F		:= 160
GF_G		:= 192
GF_H		:= 224
GF_R		:= 256				; q: the result
GF_P		:= 264
GF_Q		:= 272
GF_SIZE		:= 288

; the completed point (E, H, G, F) of the frame into the GE at [GF_R]
macro ge_from_completed
	mov	rdi,[rbp+GF_R]
	lea	rsi,[rbp+GF_E]
	lea	rdx,[rbp+GF_F]
	call	fe_mul				; X = E F
	mov	rdi,[rbp+GF_R]
	add	rdi,GE_Y
	lea	rsi,[rbp+GF_G]
	lea	rdx,[rbp+GF_H]
	call	fe_mul				; Y = G H
	mov	rdi,[rbp+GF_R]
	add	rdi,GE_Z
	lea	rsi,[rbp+GF_F]
	lea	rdx,[rbp+GF_G]
	call	fe_mul				; Z = F G
	mov	rdi,[rbp+GF_R]
	add	rdi,GE_T
	lea	rsi,[rbp+GF_E]
	lea	rdx,[rbp+GF_H]
	call	fe_mul				; T = E H
end macro

; rdi = R, rsi = P (a GE), rdx = Q (cached): R = P + Q (R may be P).
ge_add:
	push	rbp
	sub	rsp,GF_SIZE
	mov	rbp,rsp
	mov	[rbp+GF_R],rdi
	mov	[rbp+GF_P],rsi
	mov	[rbp+GF_Q],rdx
	lea	rdi,[rbp+GF_C]			; (Y1 + X1), (Y1 - X1)
	lea	rdx,[rsi+GE_X]
	lea	rsi,[rsi+GE_Y]
	call	fe_add
	mov	rsi,[rbp+GF_P]
	lea	rdi,[rbp+GF_D]
	lea	rdx,[rsi+GE_X]
	lea	rsi,[rsi+GE_Y]
	call	fe_sub
	lea	rdi,[rbp+GF_B]			; B = (Y1 + X1)(Y2 + X2)
	lea	rsi,[rbp+GF_C]
	mov	rdx,[rbp+GF_Q]
	call	fe_mul
	lea	rdi,[rbp+GF_A]			; A = (Y1 - X1)(Y2 - X2)
	lea	rsi,[rbp+GF_D]
	mov	rdx,[rbp+GF_Q]
	add	rdx,GC_YMX
	call	fe_mul
	lea	rdi,[rbp+GF_C]			; C = T1 2dT2
	mov	rsi,[rbp+GF_P]
	add	rsi,GE_T
	mov	rdx,[rbp+GF_Q]
	add	rdx,GC_T2D
	call	fe_mul
	lea	rdi,[rbp+GF_D]			; D = 2 Z1 Z2
	mov	rsi,[rbp+GF_P]
	add	rsi,GE_Z
	mov	rdx,[rbp+GF_Q]
	add	rdx,GC_Z
	call	fe_mul
	ef	fe_add, GF_D, GF_D, GF_D
	ef	fe_sub, GF_E, GF_B, GF_A
	ef	fe_add, GF_H, GF_B, GF_A
	ef	fe_sub, GF_F, GF_D, GF_C
	ef	fe_add, GF_G, GF_D, GF_C
	ge_from_completed
	add	rsp,GF_SIZE
	pop	rbp
	ret

; rdi = R, rsi = P (GEs, R may be P): R = 2P.
ge_dbl:
	push	rbp
	sub	rsp,GF_SIZE
	mov	rbp,rsp
	mov	[rbp+GF_R],rdi
	mov	[rbp+GF_P],rsi
	lea	rdi,[rbp+GF_A]			; X^2
	call	fe_sq
	mov	rsi,[rbp+GF_P]
	lea	rdi,[rbp+GF_B]			; Y^2
	add	rsi,GE_Y
	call	fe_sq
	mov	rsi,[rbp+GF_P]
	lea	rdi,[rbp+GF_C]			; 2 Z^2
	add	rsi,GE_Z
	call	fe_sq
	ef	fe_add, GF_C, GF_C, GF_C
	mov	rsi,[rbp+GF_P]			; (X + Y)^2
	lea	rdi,[rbp+GF_D]
	lea	rdx,[rsi+GE_Y]
	call	fe_add
	ef	fe_sq, GF_D, GF_D
	ef	fe_add, GF_H, GF_A, GF_B	; H = X^2 + Y^2
	ef	fe_sub, GF_E, GF_D, GF_H	; E = 2XY
	ef	fe_sub, GF_G, GF_B, GF_A	; G = Y^2 - X^2
	ef	fe_sub, GF_F, GF_C, GF_G	; F = 2Z^2 - G
	ge_from_completed
	add	rsp,GF_SIZE
	pop	rbp
	ret

; rdi = C (cached), rsi = P (a GE)
ge_to_cached:
	push	rbx
	push	r12
	mov	rbx,rdi
	mov	r12,rsi
	lea	rdx,[rsi+GE_X]
	lea	rsi,[rsi+GE_Y]
	call	fe_add
	lea	rdi,[rbx+GC_YMX]
	lea	rsi,[r12+GE_Y]
	lea	rdx,[r12+GE_X]
	call	fe_sub
	lea	rdi,[rbx+GC_Z]
	lea	rsi,[r12+GE_Z]
	mov	ecx,32
	rep	movsb
	lea	rdi,[rbx+GC_T2D]
	lea	rsi,[r12+GE_T]
	lea	rdx,[ed_d2]
	call	fe_mul
	pop	r12
	pop	rbx
	ret

; rdi = P: the neutral point (0 : 1 : 1 : 0)
ge_zero:
	push	rdi
	xor	eax,eax
	mov	ecx,GE_SIZE / 8
	rep	stosq
	pop	rdi
	mov	byte [rdi+GE_Y],1
	mov	byte [rdi+GE_Z],1
	ret

; rdi = out[32], rsi = P: the encoding, y with the sign of x on top.
GN_ZI		:= 0
GN_X		:= 32
GN_P		:= 64
GN_SIZE		:= 80
ge_encode:
	push	rbx
	push	rbp
	sub	rsp,GN_SIZE
	mov	rbp,rsp
	mov	rbx,rdi
	mov	[rbp+GN_P],rsi
	lea	rdi,[rbp+GN_ZI]
	add	rsi,GE_Z
	call	fe_inv
	lea	rdi,[rbp+GN_X]
	mov	rsi,[rbp+GN_P]
	lea	rdx,[rbp+GN_ZI]
	call	fe_mul
	lea	rdi,[rbp+GN_X]
	call	fe_canon
	mov	rdi,rbx
	mov	rsi,[rbp+GN_P]
	add	rsi,GE_Y
	lea	rdx,[rbp+GN_ZI]
	call	fe_mul
	mov	rdi,rbx
	call	fe_canon
	mov	al,[rbp+GN_X]
	shl	al,7
	or	[rbx+31],al
	add	rsp,GN_SIZE
	pop	rbp
	pop	rbx
	ret

; rdi = a (in place): a^(2^252 - 3), i.e. a^((p - 5) / 8), ref10's chain
GP_T0		:= 0
GP_T1		:= 32
GP_T2		:= 64
GP_Z		:= 96
GP_SIZE		:= 128
fe_pow22523:
	push	rbx
	push	rbp
	sub	rsp,GP_SIZE
	mov	rbp,rsp
	mov	rbx,rdi
	lea	rdi,[rbp+GP_Z]
	mov	rsi,rbx
	mov	ecx,32
	rep	movsb
	ef	fe_sq, GP_T0, GP_Z		; z^2
	ef	fe_sq, GP_T1, GP_T0
	ef	fe_sq, GP_T1, GP_T1		; z^8
	ef	fe_mul, GP_T1, GP_Z, GP_T1	; z^9
	ef	fe_mul, GP_T0, GP_T0, GP_T1	; z^11
	ef	fe_sq, GP_T0, GP_T0		; z^22
	ef	fe_mul, GP_T0, GP_T1, GP_T0	; 2^5 - 1
	; dst = src^(2^n) * mul, along ref10's chain (the exponent of z after
	; each step on the right)
	irp <src,n,dst,mul>, GP_T0,5,GP_T1,GP_T0, GP_T1,10,GP_T2,GP_T1, GP_T2,20,GP_T0,GP_T2, \
			     GP_T0,10,GP_T0,GP_T1, GP_T0,50,GP_T1,GP_T0, GP_T1,100,GP_T2,GP_T1, \
			     GP_T2,50,GP_T2,GP_T0
		; 2^10-1 in t1, 2^20-1 in t2, 2^40-1 in t0, 2^50-1 in t0,
		; 2^100-1 in t1, 2^200-1 in t2, 2^250-1 in t2
		if src <> dst
			lea	rdi,[rbp+dst]
			lea	rsi,[rbp+src]
			mov	ecx,32
			rep	movsb
		end if
		lea	rdi,[rbp+dst]
		mov	ecx,n
		call	fe_sqn
		ef	fe_mul, dst, dst, mul
	end irp
	ef	fe_sq, GP_T2, GP_T2
	ef	fe_sq, GP_T2, GP_T2		; 2^252 - 4
	lea	rdi,[rbx]
	lea	rsi,[rbp+GP_T2]
	lea	rdx,[rbp+GP_Z]
	call	fe_mul				; 2^252 - 3
	add	rsp,GP_SIZE
	pop	rbp
	pop	rbx
	ret

; rdi = a, rsi = b: ZF set when they are the same field element.
fe_equal:
	push	rbx
	push	r12
	sub	rsp,72
	mov	rbx,rdi
	mov	r12,rsi
	mov	rdi,rsp
	mov	rsi,rbx
	mov	ecx,32
	rep	movsb
	lea	rdi,[rsp+32]
	mov	rsi,r12
	mov	ecx,32
	rep	movsb
	mov	rdi,rsp
	call	fe_canon
	lea	rdi,[rsp+32]
	call	fe_canon
	mov	rax,[rsp]
	xor	rax,[rsp+32]
	mov	rcx,[rsp+8]
	xor	rcx,[rsp+40]
	or	rax,rcx
	mov	rcx,[rsp+16]
	xor	rcx,[rsp+48]
	or	rax,rcx
	mov	rcx,[rsp+24]
	xor	rcx,[rsp+56]
	or	rax,rcx
	add	rsp,72
	pop	r12
	pop	rbx
	test	rax,rax				; ZF, after the add that clobbers it
	ret

; rdi = P (out), rsi = enc[32]: the point decoded (RFC 8032 5.1.3).
; eax = 1, or 0 when it is not one (y >= p, no square root, x = 0 with
; the sign set). Public data: branches.
GD_Y		:= 0
GD_U		:= 32
GD_V		:= 64
GD_V3		:= 96
GD_X		:= 128
GD_T		:= 160
GD_OUT		:= 192
GD_SIGN		:= 200
GD_SIZE		:= 208
ge_decode:
	push	rbx
	push	rbp
	sub	rsp,GD_SIZE
	mov	rbp,rsp
	mov	[rbp+GD_OUT],rdi
	lea	rdi,[rbp+GD_Y]
	mov	ecx,32
	rep	movsb
	movzx	eax,byte [rbp+GD_Y+31]
	shr	eax,7
	mov	[rbp+GD_SIGN],eax
	and	byte [rbp+GD_Y+31],127
	lea	rdi,[rbp+GD_T]			; y < p: canon(y) = y
	lea	rsi,[rbp+GD_Y]
	mov	ecx,32
	rep	movsb
	lea	rdi,[rbp+GD_T]
	call	fe_canon
	lea	rdi,[rbp+GD_T]
	lea	rsi,[rbp+GD_Y]
	mov	ecx,32
	repe	cmpsb
	jne	.bad
	; u = y^2 - 1, v = d y^2 + 1
	ef	fe_sq, GD_U, GD_Y
	lea	rdi,[rbp+GD_V]
	lea	rsi,[rbp+GD_U]
	lea	rdx,[ed_d]
	call	fe_mul
	lea	rdi,[rbp+GD_V]
	lea	rsi,[rbp+GD_V]
	lea	rdx,[fe_one]
	call	fe_add
	lea	rdi,[rbp+GD_U]
	lea	rsi,[rbp+GD_U]
	lea	rdx,[fe_one]
	call	fe_sub
	; x = u v^3 (u v^7)^((p - 5) / 8)
	ef	fe_sq, GD_V3, GD_V
	ef	fe_mul, GD_V3, GD_V3, GD_V	; v^3
	ef	fe_sq, GD_X, GD_V3
	ef	fe_mul, GD_X, GD_X, GD_V	; v^7
	ef	fe_mul, GD_X, GD_X, GD_U	; u v^7
	lea	rdi,[rbp+GD_X]
	call	fe_pow22523
	ef	fe_mul, GD_X, GD_X, GD_V3
	ef	fe_mul, GD_X, GD_X, GD_U
	; v x^2 = u: x; = -u: x sqrt(-1); else not on the curve
	ef	fe_sq, GD_T, GD_X
	ef	fe_mul, GD_T, GD_T, GD_V
	lea	rdi,[rbp+GD_T]
	lea	rsi,[rbp+GD_U]
	call	fe_equal
	jz	.root
	lea	rdi,[rbp+GD_V]			; -u, in GD_V (v is done with)
	lea	rsi,[fe_zero]
	lea	rdx,[rbp+GD_U]
	call	fe_sub
	lea	rdi,[rbp+GD_T]
	lea	rsi,[rbp+GD_V]
	call	fe_equal
	jnz	.bad
	lea	rdi,[rbp+GD_X]
	lea	rsi,[rbp+GD_X]
	lea	rdx,[ed_sqrtm1]
	call	fe_mul
.root:
	lea	rdi,[rbp+GD_X]
	call	fe_canon
	mov	rax,[rbp+GD_X]
	or	rax,[rbp+GD_X+8]
	or	rax,[rbp+GD_X+16]
	or	rax,[rbp+GD_X+24]
	jnz	@f
	cmp	dword [rbp+GD_SIGN],0
	jne	.bad				; x = 0 has no negative
@@:
	movzx	eax,byte [rbp+GD_X]
	and	eax,1
	cmp	eax,[rbp+GD_SIGN]
	je	@f
	lea	rdi,[rbp+GD_X]
	lea	rsi,[fe_zero]
	lea	rdx,[rbp+GD_X]
	call	fe_sub
	lea	rdi,[rbp+GD_X]
	call	fe_canon
@@:
	mov	rbx,[rbp+GD_OUT]		; (x, y, 1, x y)
	lea	rdi,[rbx+GE_X]
	lea	rsi,[rbp+GD_X]
	mov	ecx,32
	rep	movsb
	lea	rdi,[rbx+GE_Y]
	lea	rsi,[rbp+GD_Y]
	mov	ecx,32
	rep	movsb
	lea	rdi,[rbx+GE_Z]
	lea	rsi,[fe_one]
	mov	ecx,32
	rep	movsb
	lea	rdi,[rbx+GE_T]
	lea	rsi,[rbp+GD_X]
	lea	rdx,[rbp+GD_Y]
	call	fe_mul
	mov	eax,1
	jmp	.out
.bad:
	xor	eax,eax
.out:
	add	rsp,GD_SIZE
	pop	rbp
	pop	rbx
	ret

; rdi = R (a GE), rsi = k[32] (below 2^255), rdx = P (a GE): R = k P,
; variable time (verification only): signed radix-16 digits over the
; cached multiples 1P..8P.
GV_TAB		:= 0				; 8 cached points
GV_NEG		:= GV_TAB + 8 * GE_SIZE		; a negated entry
GV_Q		:= GV_NEG + GE_SIZE		; the sum
GV_PJ		:= GV_Q + GE_SIZE		; jP while building the table
GV_E		:= GV_PJ + GE_SIZE		; 64 digits
GV_R		:= GV_E + 64
GV_SIZE		:= GV_R + 16
ge_mul_vartime:
	push	rbx
	push	rbp
	push	r12
	push	r13
	sub	rsp,GV_SIZE
	mov	rbp,rsp
	mov	[rbp+GV_R],rdi
	mov	r12,rdx
	xor	ecx,ecx				; the digits, as x25519_base makes them
@@:
	movzx	eax,byte [rsi+rcx]
	mov	edx,eax
	and	eax,15
	shr	edx,4
	mov	[rbp+GV_E+rcx*2],al
	mov	[rbp+GV_E+rcx*2+1],dl
	inc	ecx
	cmp	ecx,32
	jb	@b
	xor	ecx,ecx
	xor	r8d,r8d
@@:
	movsx	eax,byte [rbp+GV_E+r8]
	add	eax,ecx
	lea	ecx,[rax+8]
	sar	ecx,4
	mov	edx,ecx
	shl	edx,4
	sub	eax,edx
	mov	[rbp+GV_E+r8],al
	inc	r8d
	cmp	r8d,63
	jb	@b
	add	[rbp+GV_E+63],cl
	; the table: jP cached, j = 1..8
	lea	rdi,[rbp+GV_PJ]
	mov	rsi,r12
	mov	ecx,GE_SIZE
	rep	movsb
	lea	rdi,[rbp+GV_TAB]
	lea	rsi,[rbp+GV_PJ]
	call	ge_to_cached
	mov	ebx,1
.table:
	lea	rdi,[rbp+GV_PJ]			; (j + 1) P = jP + P
	lea	rsi,[rbp+GV_PJ]
	lea	rdx,[rbp+GV_TAB]
	call	ge_add
	mov	eax,ebx
	shl	eax,7				; * GE_SIZE
	lea	rdi,[rbp+GV_TAB+rax]
	lea	rsi,[rbp+GV_PJ]
	call	ge_to_cached
	inc	ebx
	cmp	ebx,8
	jb	.table
	lea	rdi,[rbp+GV_Q]
	call	ge_zero
	mov	r13d,63
.digit:
	repeat 4
		lea	rdi,[rbp+GV_Q]
		lea	rsi,[rbp+GV_Q]
		call	ge_dbl
	end repeat
	movsx	eax,byte [rbp+GV_E+r13]
	test	eax,eax
	jz	.next
	js	.negative
	dec	eax
	shl	eax,7
	lea	rdx,[rbp+GV_TAB+rax]
	jmp	.add
.negative:
	neg	eax
	dec	eax
	shl	eax,7
	lea	rsi,[rbp+GV_TAB+rax]		; -Q: swap Y + X and Y - X, negate 2dT
	lea	rdi,[rbp+GV_NEG+GC_YPX]
	push	rsi
	add	rsi,GC_YMX
	mov	ecx,32
	rep	movsb
	pop	rsi
	push	rsi
	lea	rdi,[rbp+GV_NEG+GC_YMX]
	mov	ecx,32
	rep	movsb
	pop	rsi
	push	rsi
	add	rsi,GC_Z
	lea	rdi,[rbp+GV_NEG+GC_Z]
	mov	ecx,32
	rep	movsb
	pop	rsi
	lea	rdi,[rbp+GV_NEG+GC_T2D]
	lea	rdx,[rsi+GC_T2D]
	lea	rsi,[fe_zero]
	call	fe_sub
	lea	rdx,[rbp+GV_NEG]
.add:
	lea	rdi,[rbp+GV_Q]
	lea	rsi,[rbp+GV_Q]
	call	ge_add
.next:
	dec	r13d
	jns	.digit
	mov	rdi,[rbp+GV_R]
	lea	rsi,[rbp+GV_Q]
	mov	ecx,GE_SIZE
	rep	movsb
	add	rsp,GV_SIZE
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

; ------------------------------------------------------------ signatures

; rdi = h[64] (in place): its first half clamped as RFC 8032 5.1.5
macro ed_clamp r
	and	byte [r],248
	and	byte [r+31],127
	or	byte [r+31],64
end macro

ed25519_public:
	push	rbx
	push	rbp
	sub	rsp,64 + GE_SIZE + 8
	mov	rbp,rsp
	mov	rbx,rdi
	mov	rdi,rbp				; h = SHA-512(seed)
	mov	rdx,32
	call	sha512
	ed_clamp rbp
	lea	rdi,[rbp+64]
	mov	rsi,rbp
	call	ed25519_base
	mov	rdi,rbx
	lea	rsi,[rbp+64]
	call	ge_encode
	mov	rdi,rbp
	mov	ecx,64 + GE_SIZE
	call	secure_zero
	add	rsp,64 + GE_SIZE + 8
	pop	rbp
	pop	rbx
	ret

ES_H		:= 0				; SHA-512(seed): a | prefix
ES_R		:= 64				; r (64, then reduced)
ES_K		:= 128				; k
ES_P		:= 192				; r B
ES_CTX		:= ES_P + GE_SIZE
ES_SIG		:= ES_CTX + SHA512_CTX_SIZE
ES_PUB		:= ES_SIG + 8
ES_MSG		:= ES_PUB + 8
ES_LEN		:= ES_MSG + 8
ES_SIZE		:= (ES_LEN + 8 + 15) and not 15
ed25519_sign:
	push	rbx
	push	rbp
	sub	rsp,ES_SIZE
	mov	rbp,rsp
	mov	[rbp+ES_SIG],rdi
	mov	[rbp+ES_PUB],rdx
	mov	[rbp+ES_MSG],rcx
	mov	[rbp+ES_LEN],r8
	lea	rdi,[rbp+ES_H]
	mov	edx,32
	call	sha512
	lea	rax,[rbp+ES_H]
	ed_clamp rax
	; r = SHA-512(prefix | M) mod L
	lea	rdi,[rbp+ES_CTX]
	call	sha512_init
	lea	rdi,[rbp+ES_CTX]
	lea	rsi,[rbp+ES_H+32]
	mov	edx,32
	call	sha512_update
	lea	rdi,[rbp+ES_CTX]
	mov	rsi,[rbp+ES_MSG]
	mov	rdx,[rbp+ES_LEN]
	call	sha512_update
	lea	rdi,[rbp+ES_CTX]
	lea	rsi,[rbp+ES_R]
	call	sha512_final
	lea	rdi,[rbp+ES_R]
	lea	rsi,[rbp+ES_R]
	call	sc_reduce
	; R = r B, the signature's first half
	lea	rdi,[rbp+ES_P]
	lea	rsi,[rbp+ES_R]
	call	ed25519_base
	mov	rdi,[rbp+ES_SIG]
	lea	rsi,[rbp+ES_P]
	call	ge_encode
	; k = SHA-512(R | A | M) mod L
	lea	rdi,[rbp+ES_CTX]
	call	sha512_init
	lea	rdi,[rbp+ES_CTX]
	mov	rsi,[rbp+ES_SIG]
	mov	edx,32
	call	sha512_update
	lea	rdi,[rbp+ES_CTX]
	mov	rsi,[rbp+ES_PUB]
	mov	edx,32
	call	sha512_update
	lea	rdi,[rbp+ES_CTX]
	mov	rsi,[rbp+ES_MSG]
	mov	rdx,[rbp+ES_LEN]
	call	sha512_update
	lea	rdi,[rbp+ES_CTX]
	lea	rsi,[rbp+ES_K]
	call	sha512_final
	lea	rdi,[rbp+ES_K]
	lea	rsi,[rbp+ES_K]
	call	sc_reduce
	; S = (r + k a) mod L
	mov	rdi,[rbp+ES_SIG]
	add	rdi,32
	lea	rsi,[rbp+ES_K]
	lea	rdx,[rbp+ES_H]
	lea	rcx,[rbp+ES_R]
	call	sc_muladd
	mov	rdi,rbp
	mov	ecx,ES_SIG
	call	secure_zero
	add	rsp,ES_SIZE
	pop	rbp
	pop	rbx
	ret

EV_A		:= 0				; -A
EV_P		:= GE_SIZE			; [S]B, then the sum
EV_Q		:= 2 * GE_SIZE			; [k](-A)
EV_C		:= 3 * GE_SIZE			; it cached
EV_K		:= 4 * GE_SIZE			; k (64)
EV_ENC		:= EV_K + 64
EV_CTX		:= EV_ENC + 32
EV_PUB		:= EV_CTX + SHA512_CTX_SIZE
EV_MSG		:= EV_PUB + 8
EV_LEN		:= EV_MSG + 8
EV_SIG		:= EV_LEN + 8
EV_SIZE		:= (EV_SIG + 8 + 15) and not 15
ed25519_verify:
	push	rbx
	push	rbp
	sub	rsp,EV_SIZE
	mov	rbp,rsp
	mov	[rbp+EV_PUB],rdi
	mov	[rbp+EV_MSG],rsi
	mov	[rbp+EV_LEN],rdx
	mov	[rbp+EV_SIG],rcx
	; S < L
	mov	rax,[rcx+32]
	sub	rax,[sc_l]
	mov	rax,[rcx+40]
	sbb	rax,[sc_l+8]
	mov	rax,[rcx+48]
	sbb	rax,[sc_l+16]
	mov	rax,[rcx+56]
	sbb	rax,[sc_l+24]
	jnc	.bad
	lea	rdi,[rbp+EV_A]
	mov	rsi,[rbp+EV_PUB]
	call	ge_decode
	test	eax,eax
	jz	.bad
	lea	rdi,[rbp+EV_A+GE_X]		; -A: x and t negated
	lea	rsi,[fe_zero]
	lea	rdx,[rbp+EV_A+GE_X]
	call	fe_sub
	lea	rdi,[rbp+EV_A+GE_T]
	lea	rsi,[fe_zero]
	lea	rdx,[rbp+EV_A+GE_T]
	call	fe_sub
	; k = SHA-512(R | A | M) mod L
	lea	rdi,[rbp+EV_CTX]
	call	sha512_init
	lea	rdi,[rbp+EV_CTX]
	mov	rsi,[rbp+EV_SIG]
	mov	edx,32
	call	sha512_update
	lea	rdi,[rbp+EV_CTX]
	mov	rsi,[rbp+EV_PUB]
	mov	edx,32
	call	sha512_update
	lea	rdi,[rbp+EV_CTX]
	mov	rsi,[rbp+EV_MSG]
	mov	rdx,[rbp+EV_LEN]
	call	sha512_update
	lea	rdi,[rbp+EV_CTX]
	lea	rsi,[rbp+EV_K]
	call	sha512_final
	lea	rdi,[rbp+EV_K]
	lea	rsi,[rbp+EV_K]
	call	sc_reduce
	; [S]B + [k](-A), encoded, against R
	lea	rdi,[rbp+EV_P]
	mov	rsi,[rbp+EV_SIG]
	add	rsi,32
	call	ed25519_base
	lea	rdi,[rbp+EV_Q]
	lea	rsi,[rbp+EV_K]
	lea	rdx,[rbp+EV_A]
	call	ge_mul_vartime
	lea	rdi,[rbp+EV_C]
	lea	rsi,[rbp+EV_Q]
	call	ge_to_cached
	lea	rdi,[rbp+EV_P]
	lea	rsi,[rbp+EV_P]
	lea	rdx,[rbp+EV_C]
	call	ge_add
	lea	rdi,[rbp+EV_ENC]
	lea	rsi,[rbp+EV_P]
	call	ge_encode
	lea	rsi,[rbp+EV_ENC]
	mov	rdi,[rbp+EV_SIG]
	mov	ecx,32
	repe	cmpsb
	jne	.bad
	mov	eax,1
	jmp	.out
.bad:
	xor	eax,eax
.out:
	add	rsp,EV_SIZE
	pop	rbp
	pop	rbx
	ret
