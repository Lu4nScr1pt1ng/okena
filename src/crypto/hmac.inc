; HMAC-SHA-256 (RFC 2104), from fasm2Crud.
;
; An HMAC_CTX keeps the inner hash running plus the outer state after the
; opad block, so a key is expanded once and the context can be copied to
; MAC many messages (HKDF-Expand).

HMAC_INNER	:= 0				; SHA256_CTX
HMAC_OUTER	:= SHA256_CTX_SIZE		; 8 dwords
HMAC_CTX_SIZE	:= SHA256_CTX_SIZE + 32

; rdi = ctx, rsi = key, rdx = key length.
hmac_sha256_init:
	push	rbx
	push	r12
	push	r13
	sub	rsp,64
	mov	rbx,rdi
	mov	r12,rsi
	mov	r13,rdx
	; K0: the key, hashed first when longer than a block, zero padded.
	mov	rdi,rsp
	mov	ecx,64
	call	secure_zero
	cmp	r13,64
	jbe	.copy
	mov	rdi,rsp
	mov	rsi,r12
	mov	rdx,r13
	call	sha256
	jmp	.pads
.copy:
	mov	rdi,rsp
	mov	rsi,r12
	mov	rcx,r13
	rep	movsb
.pads:
	; Inner: hash K0 ^ ipad.
	xor	ecx,ecx
@@:
	xor	byte [rsp+rcx],0x36
	inc	ecx
	cmp	ecx,64
	jb	@b
	lea	rdi,[rbx+HMAC_INNER]
	call	sha256_init
	lea	rdi,[rbx+HMAC_INNER]
	mov	rsi,rsp
	mov	edx,1
	call	sha256_blocks
	mov	qword [rbx+HMAC_INNER+SHA_COUNT],64
	; Outer: K0 ^ opad = (K0 ^ ipad) ^ (0x36 ^ 0x5c).
	xor	ecx,ecx
@@:
	xor	byte [rsp+rcx],0x36 xor 0x5C
	inc	ecx
	cmp	ecx,64
	jb	@b
	movdqa	xmm0,xword [sha256_iv]
	movdqu	[rbx+HMAC_OUTER],xmm0
	movdqa	xmm0,xword [sha256_iv+16]
	movdqu	[rbx+HMAC_OUTER+16],xmm0
	lea	rdi,[rbx+HMAC_OUTER]
	mov	rsi,rsp
	mov	edx,1
	call	sha256_blocks
	mov	rdi,rsp
	mov	ecx,64
	call	secure_zero
	add	rsp,64
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = ctx, rsi = data, rdx = length.
hmac_sha256_update:
	jmp	sha256_update			; HMAC_INNER is at offset 0

; rdi = ctx, rsi = mac[32]. The context is consumed.
hmac_sha256_final:
	push	rbx
	push	r12
	sub	rsp,SHA256_CTX_SIZE + 32
	mov	rbx,rdi
	mov	r12,rsi
	lea	rsi,[rsp+SHA256_CTX_SIZE]	; inner digest
	call	sha256_final
	; Outer hash: resume from the saved state after the opad block.
	movdqu	xmm0,[rbx+HMAC_OUTER]
	movdqu	[rsp+SHA_STATE],xmm0
	movdqu	xmm0,[rbx+HMAC_OUTER+16]
	movdqu	[rsp+SHA_STATE+16],xmm0
	mov	qword [rsp+SHA_COUNT],64
	mov	dword [rsp+SHA_BUFLEN],0
	mov	rdi,rsp
	lea	rsi,[rsp+SHA256_CTX_SIZE]
	mov	edx,32
	call	sha256_update
	mov	rdi,rsp
	mov	rsi,r12
	call	sha256_final
	mov	rdi,rsp
	mov	ecx,SHA256_CTX_SIZE + 32
	call	secure_zero
	add	rsp,SHA256_CTX_SIZE + 32
	pop	r12
	pop	rbx
	ret

; rdi = mac[32], rsi = key, rdx = key length, rcx = data, r8 = data length.
hmac_sha256:
	push	rbx
	push	r12
	push	r13
	sub	rsp,HMAC_CTX_SIZE
	mov	rbx,rdi
	mov	r12,rcx
	mov	r13,r8
	mov	rdi,rsp
	call	hmac_sha256_init
	mov	rdi,rsp
	mov	rsi,r12
	mov	rdx,r13
	call	hmac_sha256_update
	mov	rdi,rsp
	mov	rsi,rbx
	call	hmac_sha256_final
	mov	rdi,rsp
	mov	ecx,HMAC_CTX_SIZE
	call	secure_zero
	add	rsp,HMAC_CTX_SIZE
	pop	r13
	pop	r12
	pop	rbx
	ret

