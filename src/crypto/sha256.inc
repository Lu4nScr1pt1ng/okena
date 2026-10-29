; SHA-256 (FIPS 180-4). The block function comes in two forms, chosen
; once by crypto_init through CPUID: SHA-NI (Intel since Ice Lake / Goldmont,
; AMD since Zen; from fasm2Crud) and a scalar one on BMI2 (rorx, movbe) for
; x86-64-v3 CPUs without it. Both are checked against the same vectors.
;
; Streaming API over a SHA256_CTX:
;   sha256_init(rdi ctx)
;   sha256_update(rdi ctx, rsi data, rdx length)
;   sha256_final(rdi ctx, rsi digest[32])
; and sha256(rdi digest[32], rsi data, rdx length) for one-shot hashing.

SHA_STATE	:= 0		; 8 dwords, a..h
SHA_COUNT	:= 32		; bytes hashed so far
SHA_BUFLEN	:= 40
SHA_BUF		:= 48		; partial block
SHA256_CTX_SIZE	:= 112

rodata
	align 16
	sha256_k:
	dd 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
	dd 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
	dd 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
	dd 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
	dd 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
	dd 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
	dd 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
	dd 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
	dd 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
	dd 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
	dd 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
	dd 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
	dd 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
	dd 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
	dd 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
	dd 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	sha256_iv	dd 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
			dd 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	sha256_bswap	db 3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12
end rodata

; Four rounds, with the message schedule for later rounds interleaved
; (the structure of Intel's reference implementation).
; xmm0 = message + constants, xmm1 = ABEF, xmm2 = CDGH, xmm7 = scratch,
; xmm8 = byte-swap mask, rsi = block.
macro sha256_4rounds round*, m0*, m1*, m2*, m3*
	local i
	i = round				; evaluate once: callers pass expressions
	if i < 16
		movdqu		m0,[rsi+i*4]
		pshufb		m0,xmm8
	end if
	movdqa		xmm0,[sha256_k+i*4]
	paddd		xmm0,m0
	sha256rnds2	xmm2,xmm1,xmm0
	if i >= 12 & i < 60
		movdqa		xmm7,m0
		palignr		xmm7,m3,4
		paddd		m1,xmm7
		sha256msg2	m1,m0
	end if
	punpckhqdq	xmm0,xmm0
	sha256rnds2	xmm1,xmm2,xmm0
	if i >= 4 & i < 52
		sha256msg1	m3,m0
	end if
end macro

; rdi = state, rsi = data, rdx = number of 64-byte blocks (> 0).
sha256_blocks_ni:
	; Lanes listed high to low (Intel's ABEF/CDGH notation).
	movdqu		xmm1,[rdi]		; DCBA
	movdqu		xmm2,[rdi+16]		; HGFE
	movdqa		xmm7,xmm1
	punpcklqdq	xmm1,xmm2		; FEBA
	punpckhqdq	xmm2,xmm7		; DCHG
	pshufd		xmm1,xmm1,0x1B		; ABEF
	pshufd		xmm2,xmm2,0xB1		; CDGH
	movdqa		xmm8,xword [sha256_bswap]
.block:
	movdqa		xmm9,xmm1
	movdqa		xmm10,xmm2
	repeat 4, r:0
		sha256_4rounds r*16 + 0,  xmm3, xmm4, xmm5, xmm6
		sha256_4rounds r*16 + 4,  xmm4, xmm5, xmm6, xmm3
		sha256_4rounds r*16 + 8,  xmm5, xmm6, xmm3, xmm4
		sha256_4rounds r*16 + 12, xmm6, xmm3, xmm4, xmm5
	end repeat
	paddd		xmm1,xmm9
	paddd		xmm2,xmm10
	add		rsi,64
	dec		rdx
	jnz		.block
	; Lanes listed low to high from here on.
	pshufd		xmm1,xmm1,0x1B		; A B E F
	pshufd		xmm2,xmm2,0x1B		; C D G H
	movdqa		xmm7,xmm1
	punpcklqdq	xmm1,xmm2		; A B C D
	punpckhqdq	xmm7,xmm2		; E F G H
	movdqu		[rdi],xmm1
	movdqu		[rdi+16],xmm7
	ret


bss
	g_cpu_shani	db ?		; 1: SHA-NI blocks
end bss

; rdi = state, rsi = data, rdx = blocks: whichever this CPU runs best.
sha256_blocks:
	cmp	byte [g_cpu_shani],0
	jne	sha256_blocks_ni
	jmp	sha256_blocks_x86

; One round, a..h in registers (rotated by the caller), W[t] at [rsp+t*4].
macro sha256_round a*, b*, c*, d*, e*, f*, g*, h*, t*
	rorx	ecx,e,6
	rorx	edx,e,11
	xor	ecx,edx
	rorx	edx,e,25
	xor	ecx,edx				; S1(e)
	mov	edx,f
	xor	edx,g
	and	edx,e
	xor	edx,g				; Ch(e,f,g)
	add	h,ecx
	add	h,edx
	add	h,[sha256_k+(t)*4]
	add	h,[rsp+(t)*4]			; h = T1
	add	d,h				; d + T1: the next e
	rorx	ecx,a,2
	rorx	edx,a,13
	xor	ecx,edx
	rorx	edx,a,22
	xor	ecx,edx				; S0(a)
	add	h,ecx
	mov	edx,a
	or	edx,b
	and	edx,c
	mov	ecx,a
	and	ecx,b
	or	edx,ecx				; Maj(a,b,c)
	add	h,edx				; T1 + T2: the next a
end macro

; rdi = state, rsi = data, rdx = blocks (> 0). Scalar: a..h in r8d..r15d,
; the message schedule on the stack.
sha256_blocks_x86:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,256 + 16
	mov	[rsp+256],rdx
.block:
	; W[0..15]: the block, big endian
	repeat 16, i:0
		movbe	eax,[rsi+i*4]
		mov	[rsp+i*4],eax
	end repeat
	; W[16..63]
	mov	ebx,16
.schedule:
	mov	eax,[rsp+rbx*4-15*4]
	rorx	ecx,eax,7
	rorx	edx,eax,18
	xor	ecx,edx
	shr	eax,3
	xor	ecx,eax				; s0(W[t-15])
	mov	eax,[rsp+rbx*4-2*4]
	rorx	edx,eax,17
	rorx	ebp,eax,19
	xor	edx,ebp
	shr	eax,10
	xor	edx,eax				; s1(W[t-2])
	add	ecx,edx
	add	ecx,[rsp+rbx*4-7*4]
	add	ecx,[rsp+rbx*4-16*4]
	mov	[rsp+rbx*4],ecx
	inc	ebx
	cmp	ebx,64
	jb	.schedule
	mov	r8d,[rdi]
	mov	r9d,[rdi+4]
	mov	r10d,[rdi+8]
	mov	r11d,[rdi+12]
	mov	r12d,[rdi+16]
	mov	r13d,[rdi+20]
	mov	r14d,[rdi+24]
	mov	r15d,[rdi+28]
	repeat 8, r:0
		sha256_round r8d, r9d, r10d, r11d, r12d, r13d, r14d, r15d, r*8+0
		sha256_round r15d, r8d, r9d, r10d, r11d, r12d, r13d, r14d, r*8+1
		sha256_round r14d, r15d, r8d, r9d, r10d, r11d, r12d, r13d, r*8+2
		sha256_round r13d, r14d, r15d, r8d, r9d, r10d, r11d, r12d, r*8+3
		sha256_round r12d, r13d, r14d, r15d, r8d, r9d, r10d, r11d, r*8+4
		sha256_round r11d, r12d, r13d, r14d, r15d, r8d, r9d, r10d, r*8+5
		sha256_round r10d, r11d, r12d, r13d, r14d, r15d, r8d, r9d, r*8+6
		sha256_round r9d, r10d, r11d, r12d, r13d, r14d, r15d, r8d, r*8+7
	end repeat
	add	[rdi],r8d
	add	[rdi+4],r9d
	add	[rdi+8],r10d
	add	[rdi+12],r11d
	add	[rdi+16],r12d
	add	[rdi+20],r13d
	add	[rdi+24],r14d
	add	[rdi+28],r15d
	add	rsi,64
	dec	qword [rsp+256]
	jnz	.block
	; the schedule held message-derived data: wipe it
	mov	rdx,rdi
	mov	rdi,rsp
	mov	ecx,256
	xor	eax,eax
	rep	stosb
	mov	rdi,rdx
	add	rsp,256 + 16
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

sha256_init:
	movdqa	xmm0,xword [sha256_iv]
	movdqu	[rdi+SHA_STATE],xmm0
	movdqa	xmm0,xword [sha256_iv+16]
	movdqu	[rdi+SHA_STATE+16],xmm0
	xor	eax,eax
	mov	[rdi+SHA_COUNT],rax
	mov	[rdi+SHA_BUFLEN],eax
	ret

sha256_update:
	push	rbx
	push	r12
	push	r13
	mov	rbx,rdi
	mov	r12,rsi
	mov	r13,rdx
	add	[rbx+SHA_COUNT],rdx
	mov	eax,[rbx+SHA_BUFLEN]
	test	eax,eax
	jz	.blocks
	; Top up the partial block first.
	mov	ecx,64
	sub	ecx,eax
	cmp	rcx,r13
	jbe	@f
	mov	rcx,r13
@@:
	lea	rdi,[rbx+SHA_BUF+rax]
	mov	rsi,r12
	add	r12,rcx
	sub	r13,rcx
	add	eax,ecx
	mov	[rbx+SHA_BUFLEN],eax
	rep	movsb
	cmp	eax,64
	jb	.done
	mov	rdi,rbx
	lea	rsi,[rbx+SHA_BUF]
	mov	edx,1
	call	sha256_blocks
	mov	dword [rbx+SHA_BUFLEN],0
.blocks:
	mov	rdx,r13
	shr	rdx,6
	jz	.tail
	mov	rdi,rbx
	mov	rsi,r12
	call	sha256_blocks
	mov	rax,r13
	and	rax,-64
	add	r12,rax
	and	r13,63
.tail:
	test	r13,r13
	jz	.done
	lea	rdi,[rbx+SHA_BUF]
	mov	rsi,r12
	mov	rcx,r13
	rep	movsb
	mov	[rbx+SHA_BUFLEN],r13d
.done:
	pop	r13
	pop	r12
	pop	rbx
	ret

sha256_final:
	push	rbx
	push	r12
	mov	rbx,rdi
	mov	r12,rsi
	mov	eax,[rbx+SHA_BUFLEN]
	mov	byte [rbx+SHA_BUF+rax],0x80
	inc	eax
	cmp	eax,56
	jbe	.pad
	; No room for the length: finish this block with zeros first.
	lea	rdi,[rbx+SHA_BUF+rax]
	mov	ecx,64
	sub	ecx,eax
	xor	eax,eax
	rep	stosb
	mov	rdi,rbx
	lea	rsi,[rbx+SHA_BUF]
	mov	edx,1
	call	sha256_blocks
	xor	eax,eax
.pad:
	lea	rdi,[rbx+SHA_BUF+rax]
	mov	ecx,56
	sub	ecx,eax
	xor	eax,eax
	rep	stosb
	mov	rax,[rbx+SHA_COUNT]
	shl	rax,3				; length in bits, big endian
	bswap	rax
	mov	[rbx+SHA_BUF+56],rax
	mov	rdi,rbx
	lea	rsi,[rbx+SHA_BUF]
	mov	edx,1
	call	sha256_blocks
	xor	ecx,ecx
@@:
	mov	eax,[rbx+SHA_STATE+rcx*4]
	bswap	eax
	mov	[r12+rcx*4],eax
	inc	ecx
	cmp	ecx,8
	jb	@b
	pop	r12
	pop	rbx
	ret

; rdi = digest, rsi = data, rdx = length.
sha256:
	push	rbx
	sub	rsp,SHA256_CTX_SIZE
	mov	rbx,rdi
	push	rsi
	push	rdx
	lea	rdi,[rsp+16]
	call	sha256_init
	pop	rdx
	pop	rsi
	mov	rdi,rsp
	call	sha256_update
	mov	rdi,rsp
	mov	rsi,rbx
	call	sha256_final
	mov	rdi,rsp
	mov	ecx,SHA256_CTX_SIZE
	call	secure_zero
	add	rsp,SHA256_CTX_SIZE
	pop	rbx
	ret
