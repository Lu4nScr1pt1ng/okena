; SHA-1 (FIPS 180-4), one shot. Not for anything that must resist collisions:
; OCSP names a certificate by SHA-1 hashes of its issuer's name and key (RFC 5019
; asks clients for SHA-1 there), and that is all it is used for.

bss
	align 16
	g_sha1_pad	rb 128			; the last block(s), padded
end bss

; rdi = digest[20], rsi = data, rdx = length.
sha1:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	push	rbp
	sub	rsp,32
	mov	[rsp+24],rdi
	mov	r14,rsi
	mov	r15,rdx
	mov	dword [rsp],0x67452301		; h0..h4
	mov	dword [rsp+4],0xEFCDAB89
	mov	dword [rsp+8],0x98BADCFE
	mov	dword [rsp+12],0x10325476
	mov	dword [rsp+16],0xC3D2E1F0
	; whole blocks
	mov	rbp,rdx
.blocks:
	cmp	rbp,64
	jb	.tail
	mov	rsi,r14
	call	sha1_block
	add	r14,64
	sub	rbp,64
	jmp	.blocks
.tail:
	; the rest, 0x80, zeros, the length in bits (big endian): one block or two
	lea	rdi,[g_sha1_pad]
	xor	eax,eax
	mov	ecx,128
	rep	stosb
	lea	rdi,[g_sha1_pad]
	mov	rsi,r14
	mov	rcx,rbp
	rep	movsb
	mov	byte [rdi],0x80
	mov	rax,r15
	shl	rax,3
	bswap	rax
	lea	rsi,[g_sha1_pad]
	cmp	rbp,56
	jb	.one
	mov	qword [g_sha1_pad+120],rax
	call	sha1_block
	lea	rsi,[g_sha1_pad+64]
	call	sha1_block
	jmp	.out
.one:
	mov	qword [g_sha1_pad+56],rax
	call	sha1_block
.out:
	mov	rdi,[rsp+24]
	xor	ecx,ecx
@@:
	mov	eax,[rsp+rcx*4]
	bswap	eax
	mov	[rdi+rcx*4],eax
	inc	ecx
	cmp	ecx,5
	jb	@b
	add	rsp,32
	pop	rbp
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rsi = a 64-byte block; the state at [rsp+8] (the caller's [rsp]): updated.
; Keeps rbp, r14, r15.
sha1_block:
	push	rbp
	push	r14
	push	r15
	sub	rsp,320				; W[0..79]
	; W: the block's words, then W[t] = rol1(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16])
	xor	ecx,ecx
@@:
	mov	eax,[rsi+rcx*4]
	bswap	eax
	mov	[rsp+rcx*4],eax
	inc	ecx
	cmp	ecx,16
	jb	@b
@@:
	mov	eax,[rsp+rcx*4-12]
	xor	eax,[rsp+rcx*4-32]
	xor	eax,[rsp+rcx*4-56]
	xor	eax,[rsp+rcx*4-64]
	rol	eax,1
	mov	[rsp+rcx*4],eax
	inc	ecx
	cmp	ecx,80
	jb	@b
	lea	rbp,[rsp+320+32]		; the state (past our pushes and the return)
	mov	r8d,[rbp]			; a
	mov	r9d,[rbp+4]			; b
	mov	r10d,[rbp+8]			; c
	mov	r11d,[rbp+12]			; d
	mov	r12d,[rbp+16]			; e
	xor	ecx,ecx
.round:
	cmp	ecx,20
	jae	.f2
	mov	eax,r9d				; (b & c) | (~b & d)
	and	eax,r10d
	mov	edx,r9d
	not	edx
	and	edx,r11d
	or	eax,edx
	mov	edx,0x5A827999
	jmp	.mix
.f2:
	cmp	ecx,40
	jae	.f3
	mov	eax,r9d				; b ^ c ^ d
	xor	eax,r10d
	xor	eax,r11d
	mov	edx,0x6ED9EBA1
	jmp	.mix
.f3:
	cmp	ecx,60
	jae	.f4
	mov	eax,r9d				; (b & c) | (b & d) | (c & d)
	and	eax,r10d
	mov	edx,r9d
	and	edx,r11d
	or	eax,edx
	mov	edx,r10d
	and	edx,r11d
	or	eax,edx
	mov	edx,0x8F1BBCDC
	jmp	.mix
.f4:
	mov	eax,r9d
	xor	eax,r10d
	xor	eax,r11d
	mov	edx,0xCA62C1D6
.mix:
	add	eax,edx				; temp = rol5(a) + f + e + k + W[t]
	add	eax,r12d
	add	eax,[rsp+rcx*4]
	mov	edx,r8d
	rol	edx,5
	add	eax,edx
	mov	r12d,r11d			; e = d
	mov	r11d,r10d			; d = c
	mov	r10d,r9d			; c = rol30(b)
	rol	r10d,30
	mov	r9d,r8d				; b = a
	mov	r8d,eax				; a = temp
	inc	ecx
	cmp	ecx,80
	jb	.round
	add	[rbp],r8d
	add	[rbp+4],r9d
	add	[rbp+8],r10d
	add	[rbp+12],r11d
	add	[rbp+16],r12d
	add	rsp,320
	pop	r15
	pop	r14
	pop	rbp
	ret
