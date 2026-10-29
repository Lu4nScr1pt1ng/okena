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

; rdi = out, rsi = a, rdx = b (both below m), rcx = modulus: a * b / R
; mod m, below m. out may be a or b. CIOS on a six-limb accumulator.
mont_mul:
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

; rdi = out, rsi = a (Montgomery), rcx = modulus: a^(m-2) = 1/a.
mod_inv:
	push	rbx
	push	r12
	push	r13
	push	r14
	sub	rsp,32
	mov	r12,rdi
	mov	r13,rsi
	mov	r14,rcx
	lea	rsi,[r14+MOD_ONE]
	mov	rdi,rsp
	mov	ecx,4
	rep	movsq
	mov	ebx,255
.bit:
	mov	rdi,rsp
	mov	rsi,rsp
	mov	rdx,rsp
	mov	rcx,r14
	call	mont_mul
	mov	eax,ebx
	shr	eax,6
	mov	rax,[r14+MOD_E+rax*8]
	bt	rax,rbx				; (bit index mod 64: bt on a register)
	jnc	.next
	mov	rdi,rsp
	mov	rsi,rsp
	mov	rdx,r13
	mov	rcx,r14
	call	mont_mul
.next:
	dec	ebx
	jns	.bit
	mov	rdi,r12
	mov	rsi,rsp
	mov	ecx,4
	rep	movsq
	xor	eax,eax
	mov	[rsp],rax
	mov	[rsp+8],rax
	mov	[rsp+16],rax
	mov	[rsp+24],rax
	add	rsp,32
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; Field operations on p, for the point formulas below.
macro F op*, d*, a*, b
	lea	rdi,[d]
	lea	rsi,[a]
	match any, b
		lea	rdx,[b]
	end match
	lea	rcx,[p256_p]
	call	op
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

; rdi = out x[4] and out y[4] (affine, plain), rsi = k (4 limbs): k * G.
ML_R0		:= 0
ML_R1		:= PT_SIZE
ML_ZI		:= 2 * PT_SIZE
ML_SIZE		:= 2 * PT_SIZE + 32
p256_mul_g:
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
	sub	rsp,NC_SIZE
	mov	rbx,rdi
	mov	r12,rsi
	mov	r13,rdx
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
	jnz	.done
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
SG_SIZE		:= 352
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
	lea	rdi,[rsp+SG_KM]
	lea	rsi,[rsp+SG_KM]
	mov	rcx,r14
	call	mod_inv				; 1/k
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
