; SHA-384 (FIPS 180-4: SHA-512 with its own initial words, the first 48 bytes
; of the result), HMAC-SHA-384 (RFC 2104) and HKDF-SHA-384 (RFC 5869) with the
; TLS 1.3 HKDF-Expand-Label, for TLS_AES_256_GCM_SHA384 and the TLS 1.2 suites
; with SHA-384. Built on sha512.inc.
;
;   sha384_init(rdi ctx), sha384_final(rdi ctx, rsi out[48]), sha384(rdi
;       out[48], rsi data, rdx length); updates are sha512_update's
;   hmac_sha384_init(rdi ctx, rsi key, rdx length), hmac_sha384_update(rdi,
;       rsi, rdx), hmac_sha384_final(rdi ctx, rsi mac[48]), hmac_sha384(rdi
;       mac, rsi key, rdx key length, rcx data, r8 data length)
;   hkdf384_extract = hmac_sha384 (rdi prk[48], rsi salt, rdx salt length,
;       rcx ikm, r8 ikm length); hkdf384_expand(rdi out, esi length, rdx
;       prk[48], rcx info, r8 info length); tls13_expand_label384 as
;       tls13_expand_label, with a 48-byte secret

SHA384_LEN	:= 48

rodata
	align 8
	sha384_iv	dq 0xCBBB9D5DC1059ED8, 0x629A292A367CD507, 0x9159015A3070DD17, 0x152FECD8F70E5939
			dq 0x67332667FFC00B31, 0x8EB44A8768581511, 0xDB0C2E0D64F98FA7, 0x47B5481DBEFA4FA4
end rodata

sha384_init:
	lea	rsi,[sha384_iv]
	mov	ecx,8
	push	rdi
	rep	movsq
	pop	rdi
	mov	qword [rdi+S5_LEN],0
	ret

; rdi = ctx, rsi = out[48]
sha384_final:
	push	rbx
	sub	rsp,64
	mov	rbx,rsi
	mov	rsi,rsp
	call	sha512_final
	mov	rsi,rsp
	mov	rdi,rbx
	mov	ecx,SHA384_LEN
	rep	movsb
	mov	rdi,rsp
	mov	ecx,64
	call	secure_zero
	add	rsp,64
	pop	rbx
	ret

sha384:
	push	rbx
	push	r12
	push	r13
	sub	rsp,SHA512_CTX_SIZE
	mov	rbx,rdi
	mov	r12,rsi
	mov	r13,rdx
	mov	rdi,rsp
	call	sha384_init
	mov	rdi,rsp
	mov	rsi,r12
	mov	rdx,r13
	call	sha512_update
	mov	rdi,rsp
	mov	rsi,rbx
	call	sha384_final
	add	rsp,SHA512_CTX_SIZE
	pop	r13
	pop	r12
	pop	rbx
	ret

; HMAC: the inner hash running, the outer state after its opad block
HM3_INNER	:= 0				; a SHA-512 context
HM3_OUTER	:= SHA512_CTX_SIZE		; 8 words
HMAC384_CTX_SIZE := SHA512_CTX_SIZE + 64

hmac_sha384_init:
	push	rbx
	push	r12
	push	r13
	sub	rsp,128
	mov	rbx,rdi
	mov	r12,rsi
	mov	r13,rdx
	mov	rdi,rsp
	mov	ecx,128
	call	secure_zero
	cmp	r13,128
	jbe	.copy
	mov	rdi,rsp				; longer than a block: its hash
	mov	rsi,r12
	mov	rdx,r13
	call	sha384
	jmp	.pads
.copy:
	mov	rdi,rsp
	mov	rsi,r12
	mov	rcx,r13
	rep	movsb
.pads:
	xor	ecx,ecx
@@:
	xor	byte [rsp+rcx],0x36
	inc	ecx
	cmp	ecx,128
	jb	@b
	lea	rdi,[rbx+HM3_INNER]
	call	sha384_init
	lea	rdi,[rbx+HM3_INNER]
	mov	rsi,rsp
	call	sha512_block
	mov	qword [rbx+HM3_INNER+S5_LEN],128
	xor	ecx,ecx
@@:
	xor	byte [rsp+rcx],0x36 xor 0x5C
	inc	ecx
	cmp	ecx,128
	jb	@b
	sub	rsp,SHA512_CTX_SIZE		; the outer state: one block from the IV
	mov	rdi,rsp
	call	sha384_init
	mov	rdi,rsp
	lea	rsi,[rsp+SHA512_CTX_SIZE]
	call	sha512_block
	lea	rdi,[rbx+HM3_OUTER]
	mov	rsi,rsp
	mov	ecx,64
	rep	movsb
	mov	rdi,rsp
	mov	ecx,SHA512_CTX_SIZE + 128
	call	secure_zero
	add	rsp,SHA512_CTX_SIZE + 128
	pop	r13
	pop	r12
	pop	rbx
	ret

hmac_sha384_update:
	jmp	sha512_update			; HM3_INNER is at offset 0

; rdi = ctx, rsi = mac[48]. The context is consumed.
hmac_sha384_final:
	push	rbx
	push	r12
	sub	rsp,SHA512_CTX_SIZE + 48
	mov	rbx,rdi
	mov	r12,rsi
	lea	rsi,[rsp+SHA512_CTX_SIZE]	; the inner digest
	call	sha384_final
	mov	rdi,rsp				; the outer hash, from its state
	lea	rsi,[rbx+HM3_OUTER]
	mov	ecx,64
	rep	movsb
	mov	qword [rsp+S5_LEN],128
	mov	rdi,rsp
	lea	rsi,[rsp+SHA512_CTX_SIZE]
	mov	edx,SHA384_LEN
	call	sha512_update
	mov	rdi,rsp
	mov	rsi,r12
	call	sha384_final
	mov	rdi,rsp
	mov	ecx,SHA512_CTX_SIZE + 48
	call	secure_zero
	add	rsp,SHA512_CTX_SIZE + 48
	pop	r12
	pop	rbx
	ret

hmac_sha384:
hkdf384_extract:
	push	rbx
	push	r12
	push	r13
	sub	rsp,HMAC384_CTX_SIZE
	mov	rbx,rdi
	mov	r12,rcx
	mov	r13,r8
	mov	rdi,rsp
	call	hmac_sha384_init
	mov	rdi,rsp
	mov	rsi,r12
	mov	rdx,r13
	call	hmac_sha384_update
	mov	rdi,rsp
	mov	rsi,rbx
	call	hmac_sha384_final
	add	rsp,HMAC384_CTX_SIZE
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = out, esi = length (<= 255 * 48), rdx = prk[48], rcx = info, r8 = its length
HK3_KEY		:= 0
HK3_WORK	:= HMAC384_CTX_SIZE
HK3_T		:= 2 * HMAC384_CTX_SIZE
HK3_SIZE	:= 2 * HMAC384_CTX_SIZE + 48 + 16
hkdf384_expand:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	push	rbp
	sub	rsp,HK3_SIZE
	mov	rbx,rdi
	mov	r12d,esi
	mov	r13,rcx
	mov	r14,r8
	lea	rdi,[rsp+HK3_KEY]
	mov	rsi,rdx
	mov	edx,SHA384_LEN
	call	hmac_sha384_init
	xor	ebp,ebp
.block:
	test	r12d,r12d
	jz	.done
	lea	rdi,[rsp+HK3_WORK]
	lea	rsi,[rsp+HK3_KEY]
	mov	ecx,HMAC384_CTX_SIZE
	rep	movsb
	test	ebp,ebp
	jz	@f
	lea	rdi,[rsp+HK3_WORK]
	lea	rsi,[rsp+HK3_T]
	mov	edx,SHA384_LEN
	call	hmac_sha384_update
@@:
	lea	rdi,[rsp+HK3_WORK]
	mov	rsi,r13
	mov	rdx,r14
	call	hmac_sha384_update
	inc	ebp
	mov	[rsp+HK3_T+48],bpl
	lea	rdi,[rsp+HK3_WORK]
	lea	rsi,[rsp+HK3_T+48]
	mov	edx,1
	call	hmac_sha384_update
	lea	rdi,[rsp+HK3_WORK]
	lea	rsi,[rsp+HK3_T]
	call	hmac_sha384_final
	mov	ecx,SHA384_LEN
	cmp	r12d,ecx
	jae	@f
	mov	ecx,r12d
@@:
	sub	r12d,ecx
	lea	rsi,[rsp+HK3_T]
	mov	rdi,rbx
	rep	movsb
	mov	rbx,rdi
	jmp	.block
.done:
	mov	rdi,rsp
	mov	ecx,HK3_SIZE
	call	secure_zero
	add	rsp,HK3_SIZE
	pop	rbp
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = out, esi = length, rdx = secret[48], rcx = label (NUL-terminated),
; r8 = context, r9d = context length (<= 64)
tls13_expand_label384:
	push	rbx
	push	r12
	push	r13
	sub	rsp,336
	mov	rbx,rdi
	mov	r12d,esi
	mov	r13,rdx
	mov	eax,esi
	xchg	al,ah
	mov	[rsp],ax
	lea	rdi,[rsp+3]
	mov	dword [rdi],'tls1'
	mov	word [rdi+4],'3 '
	add	rdi,6
	mov	rsi,rcx
@@:
	mov	al,[rsi]
	test	al,al
	jz	@f
	mov	[rdi],al
	inc	rdi
	inc	rsi
	jmp	@b
@@:
	lea	rax,[rsp+3]
	mov	rcx,rdi
	sub	rcx,rax
	mov	[rsp+2],cl
	mov	[rdi],r9b
	inc	rdi
	mov	rsi,r8
	mov	ecx,r9d
	rep	movsb
	mov	r8,rdi
	sub	r8,rsp
	mov	rdi,rbx
	mov	esi,r12d
	mov	rdx,r13
	mov	rcx,rsp
	call	hkdf384_expand
	add	rsp,336
	pop	r13
	pop	r12
	pop	rbx
	ret
