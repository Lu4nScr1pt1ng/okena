; SHA-512 (FIPS 180-4), for Ed25519 (RFC 8032 hashes with it). Scalar, on
; BMI2 (rorx); the message schedule kept as a rolling window of 16 words.
;
;   sha512_init(rdi ctx), sha512_update(rdi ctx, rsi data, rdx length),
;   sha512_final(rdi ctx, rsi out[64]), sha512(rdi out[64], rsi data,
;   rdx length)

S5_H		:= 0				; 8 words
S5_LEN		:= 64				; q: bytes so far
S5_BUF		:= 72				; a partial block (128)
SHA512_CTX_SIZE	:= S5_BUF + 128

rodata
	align 8
	sha512_k	dq 0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC
			dq 0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118
			dq 0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2
			dq 0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694
			dq 0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65
			dq 0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5
			dq 0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4
			dq 0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70
			dq 0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF
			dq 0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B
			dq 0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30
			dq 0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8
			dq 0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8
			dq 0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3
			dq 0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC
			dq 0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B
			dq 0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178
			dq 0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B
			dq 0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C
			dq 0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817
	sha512_iv	dq 0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1
			dq 0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
end rodata

; rdi = ctx, rsi = one 128-byte block: the compression. Keeps rdi, rsi.
sha512_block:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,128 + 64			; W[0..15], then a..h
	repeat 16, i:0
		mov	rax,[rsi+i*8]
		bswap	rax
		mov	[rsp+i*8],rax
	end repeat
	repeat 8, i:0
		mov	rax,[rdi+S5_H+i*8]
		mov	[rsp+128+i*8],rax
	end repeat
	xor	ecx,ecx				; t
.round:
	cmp	ecx,16
	jb	.w_ready
	; W[t] = s1(W[t-2]) + W[t-7] + s0(W[t-15]) + W[t-16], in place mod 16
	lea	eax,[rcx-2]
	and	eax,15
	mov	rdx,[rsp+rax*8]
	rorx	r8,rdx,19
	rorx	r9,rdx,61
	shr	rdx,6
	xor	rdx,r8
	xor	rdx,r9				; s1
	lea	eax,[rcx-7]
	and	eax,15
	add	rdx,[rsp+rax*8]
	lea	eax,[rcx-15]
	and	eax,15
	mov	r8,[rsp+rax*8]
	rorx	r9,r8,1
	rorx	r10,r8,8
	shr	r8,7
	xor	r8,r9
	xor	r8,r10				; s0
	add	rdx,r8
	mov	eax,ecx
	and	eax,15
	add	[rsp+rax*8],rdx
.w_ready:
	mov	eax,ecx
	and	eax,15
	mov	r15,[rsp+rax*8]			; W[t]
	lea	rax,[sha512_k]
	add	r15,[rax+rcx*8]			; + K[t]
	mov	r8,[rsp+128+4*8]		; e
	rorx	r9,r8,14
	rorx	r10,r8,18
	xor	r9,r10
	rorx	r10,r8,41
	xor	r9,r10				; S1(e)
	add	r15,r9
	mov	r9,[rsp+128+5*8]		; Ch(e, f, g) = (e & f) ^ (~e & g)
	and	r9,r8
	andn	r10,r8,[rsp+128+6*8]
	xor	r9,r10
	add	r15,r9
	add	r15,[rsp+128+7*8]		; T1 = h + S1 + Ch + K + W
	mov	r8,[rsp+128]			; a
	rorx	r9,r8,28
	rorx	r10,r8,34
	xor	r9,r10
	rorx	r10,r8,39
	xor	r9,r10				; S0(a)
	mov	r10,[rsp+128+8]			; Maj(a, b, c) = (a & b) ^ (c & (a ^ b))
	mov	r11,r8
	xor	r11,r10
	and	r10,r8
	and	r11,[rsp+128+16]
	xor	r10,r11
	add	r9,r10				; T2
	; h = g, g = f, f = e, e = d + T1, d = c, c = b, b = a, a = T1 + T2
	mov	rax,[rsp+128+6*8]
	mov	[rsp+128+7*8],rax
	mov	rax,[rsp+128+5*8]
	mov	[rsp+128+6*8],rax
	mov	rax,[rsp+128+4*8]
	mov	[rsp+128+5*8],rax
	mov	rax,[rsp+128+3*8]
	add	rax,r15
	mov	[rsp+128+4*8],rax
	mov	rax,[rsp+128+2*8]
	mov	[rsp+128+3*8],rax
	mov	rax,[rsp+128+8]
	mov	[rsp+128+2*8],rax
	mov	[rsp+128+8],r8
	add	r15,r9
	mov	[rsp+128],r15
	inc	ecx
	cmp	ecx,80
	jb	.round
	repeat 8, i:0
		mov	rax,[rsp+128+i*8]
		add	[rdi+S5_H+i*8],rax
	end repeat
	add	rsp,128 + 64
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

sha512_init:
	lea	rsi,[sha512_iv]
	mov	ecx,8
	push	rdi
	rep	movsq
	pop	rdi
	mov	qword [rdi+S5_LEN],0
	ret

sha512_update:
	push	rbx
	push	r12
	push	r13
	mov	rbx,rdi
	mov	r12,rsi
	mov	r13,rdx
.more:
	test	r13,r13
	jz	.done
	mov	rax,[rbx+S5_LEN]
	and	eax,127				; bytes in the buffer
	jnz	.fill
	cmp	r13,128
	jb	.fill
	mov	rdi,rbx				; a whole block straight from the input
	mov	rsi,r12
	call	sha512_block
	add	qword [rbx+S5_LEN],128
	add	r12,128
	sub	r13,128
	jmp	.more
.fill:
	mov	ecx,128
	sub	ecx,eax				; room in the buffer
	cmp	rcx,r13
	jbe	@f
	mov	rcx,r13
@@:
	lea	rdi,[rbx+S5_BUF+rax]
	mov	rsi,r12
	add	r12,rcx
	sub	r13,rcx
	add	[rbx+S5_LEN],rcx
	rep	movsb
	test	byte [rbx+S5_LEN],127
	jnz	.more
	mov	rdi,rbx
	lea	rsi,[rbx+S5_BUF]
	call	sha512_block
	jmp	.more
.done:
	pop	r13
	pop	r12
	pop	rbx
	ret

sha512_final:
	push	rbx
	push	r12
	mov	rbx,rdi
	mov	r12,rsi
	mov	r8,[rbx+S5_LEN]
	mov	eax,r8d
	and	eax,127
	mov	byte [rbx+S5_BUF+rax],0x80
	inc	eax
	cmp	eax,112
	jbe	.pad
	lea	rdi,[rbx+S5_BUF+rax]		; no room for the length: one more block
	mov	ecx,128
	sub	ecx,eax
	push	rax
	xor	eax,eax
	rep	stosb
	pop	rax
	mov	rdi,rbx
	lea	rsi,[rbx+S5_BUF]
	push	r8
	call	sha512_block
	pop	r8
	xor	eax,eax
.pad:
	lea	rdi,[rbx+S5_BUF+rax]
	mov	ecx,120
	sub	ecx,eax
	push	rax
	xor	eax,eax
	rep	stosb
	pop	rax
	shl	r8,3				; the length in bits, big endian
	bswap	r8
	mov	[rbx+S5_BUF+120],r8
	mov	rdi,rbx
	lea	rsi,[rbx+S5_BUF]
	call	sha512_block
	repeat 8, i:0
		mov	rax,[rbx+S5_H+i*8]
		bswap	rax
		mov	[r12+i*8],rax
	end repeat
	pop	r12
	pop	rbx
	ret

sha512:
	push	rbx
	push	r12
	push	r13
	sub	rsp,SHA512_CTX_SIZE
	mov	rbx,rdi
	mov	r12,rsi
	mov	r13,rdx
	mov	rdi,rsp
	call	sha512_init
	mov	rdi,rsp
	mov	rsi,r12
	mov	rdx,r13
	call	sha512_update
	mov	rdi,rsp
	mov	rsi,rbx
	call	sha512_final
	mov	rdi,rsp
	mov	ecx,SHA512_CTX_SIZE
	xor	eax,eax
	rep	stosb
	add	rsp,SHA512_CTX_SIZE
	pop	r13
	pop	r12
	pop	rbx
	ret
