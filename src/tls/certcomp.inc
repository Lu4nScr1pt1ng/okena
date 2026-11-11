; Certificate compression (RFC 8879), TLS 1.3 server side: a client that offers
; compress_certificate with brotli (Chrome) or zlib (OpenSSL, Safari) gets
; CompressedCertificate in place of Certificate, its body compressed (brotli.inc's
; encoder, one stream; or compress.inc's DEFLATE in a zlib stream), brotli first. The
; transcript has the message as sent. What a chain (with its staple, when there
; is one) compresses to is kept per worker, by a hash of it, so a handshake
; compresses nothing it compressed before; a chain that would not get smaller
; goes as it is.

CCZ_SLOTS	:= 64
CCZ_HASH	:= 0			; q: the body's hash (0: empty)
CCZ_ULEN	:= 8			; d: its length
CCZ_LEN		:= 12			; d: compressed (0: it does not get smaller)
CCZ_DATA	:= 16
CCZ_CAP		:= 16384
CCZ_SIZE	:= CCZ_DATA + CCZ_CAP + 2048	; (the encoder may write past a bit)
assert H_UP_CAP <= CCZ_CAP

bss
	align 8
	g_ccz		dq ?			; the slots, made the first time
	g_ccz_msg	dq ?			; where the Certificate being written starts
	g_ccz_alg	dd ?			; 2 brotli, 1 zlib
	align 8
end bss

; rsi = a Certificate message, rdi = its end, g_ccz_alg = the algorithm: when it
; gets smaller,
; CompressedCertificate in its place; rdi = the end. Keeps rbx, rbp, r12-r15.
cert_compress:
	push	rbx
	push	r12
	push	r13
	mov	r12,rsi				; the message
	mov	r13,rdi
	lea	rsi,[r12+4]
	mov	rcx,r13
	sub	rcx,rsi				; its body
	cmp	ecx,CCZ_CAP
	ja	.as_is
	cmp	ecx,64
	jb	.as_is
	mov	ebx,ecx
	cmp	qword [g_ccz],0
	je	.as_is				; (none was to be had)
	; its hash, its slot
	lea	rsi,[r12+4]
	mov	ecx,ebx
	mov	rax,0xCBF29CE484222325
	mov	r8,0x100000001B3
@@:
	movzx	edx,byte [rsi]
	xor	rax,rdx
	imul	rax,r8
	inc	rsi
	dec	ecx
	jnz	@b
	mov	edx,[g_ccz_alg]			; (and by what it is compressed with)
	xor	rax,rdx
	or	rax,1				; (never 0: 0 is a free slot)
	mov	r8,rax
	and	eax,CCZ_SLOTS - 1
	imul	rax,rax,CCZ_SIZE
	add	rax,[g_ccz]
	mov	r9,rax				; the slot
	cmp	[r9+CCZ_HASH],r8
	jne	.compress
	cmp	[r9+CCZ_ULEN],ebx
	je	.have
.compress:
	push	r8
	push	r9
	lea	rsi,[r12+4]
	mov	ecx,ebx
	lea	rdi,[r9+CCZ_DATA]
	cmp	dword [g_ccz_alg],2
	jne	.zlib
	call	br_oneshot			; eax = its length
	jmp	.compressed
.zlib:
	call	zlib_oneshot
.compressed:
	pop	r9
	pop	r8
	jc	.as_is
	mov	[r9+CCZ_HASH],r8
	mov	[r9+CCZ_ULEN],ebx
	lea	ecx,[rax+8]
	cmp	ecx,ebx
	jb	@f
	xor	eax,eax				; not smaller
@@:
	mov	[r9+CCZ_LEN],eax
.have:
	mov	ecx,[r9+CCZ_LEN]
	test	ecx,ecx
	jz	.as_is
	; CompressedCertificate: brotli (2), the length it had, the bytes
	mov	byte [r12],25
	lea	eax,[rcx+8]
	put24	r12+1, eax
	mov	eax,[g_ccz_alg]
	xchg	al,ah
	mov	[r12+4],ax
	put24	r12+6, ebx
	put24	r12+9, ecx
	lea	rdi,[r12+12]
	lea	rsi,[r9+CCZ_DATA]
	rep	movsb
	jmp	.out
.as_is:
	mov	rdi,r13
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; a worker, at its start (seccomp allows no mmap after): the slots and the
; encoders' context, when it serves TLS
certcomp_init:
	cmp	dword [g_plan_tls],0
	je	.none
	xor	edi,edi
	mov	esi,CCZ_SIZE * CCZ_SLOTS
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.none
	mov	[g_ccz],rax
	push	r12
	call	br_one_context			; (made now)
	pop	r12
	jnc	.none
	mov	qword [g_ccz],0			; no context: no compression
.none:
	ret
