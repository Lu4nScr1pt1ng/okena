; AES-128-GCM (NIST SP 800-38D), for TLS_AES_128_GCM_SHA256: AES-NI for
; the cipher, PCLMULQDQ for GHASH (the carry-less multiply and reduction
; of Intel's "Carry-Less Multiplication and Its Usage for Computing the
; GCM Mode" white paper). No table lookups, no secret-dependent branches.
;
; One block at a time: records of established connections are meant for
; kTLS; this serves the handshake and the user-space fallback.
;
;   gcm_init(rdi ctx, rsi key[16])
;   gcm_seal(rdi ctx, rsi iv[12], rdx aad, ecx aad length, r8 buffer,
;            r9 length): encrypts the buffer in place, the 16-byte tag
;            right after it
;   gcm_open(same): eax = 1 and the buffer decrypted when the tag after
;            it is right; eax = 0 and the buffer untouched otherwise

GCM_RK		:= 0				; 11 round keys
GCM_H		:= 176				; H = E(K, 0), byte-reflected
GCM_SIZE	:= 192

rodata
	align 16
	gcm_bswap	db 15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0
end rodata

; xmm1 = the key so far, xmm2 = aeskeygenassist of it: the next round key
; in xmm1. Clobbers xmm3.
macro aes128_next
	pshufd	xmm2,xmm2,0xFF
	movdqa	xmm3,xmm1
	pslldq	xmm3,4
	pxor	xmm1,xmm3
	pslldq	xmm3,4
	pxor	xmm1,xmm3
	pslldq	xmm3,4
	pxor	xmm1,xmm3
	pxor	xmm1,xmm2
end macro

gcm_init:
	movdqu	xmm1,[rsi]
	movdqu	[rdi+GCM_RK],xmm1
	irp rcon, 0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36
		aeskeygenassist	xmm2,xmm1,rcon
		aes128_next
		movdqu	[rdi+GCM_RK+%*16],xmm1
	end irp
	; H = E(K, 0^128), kept byte-reflected for GHASH
	pxor	xmm0,xmm0
	call	gcm_encrypt_block
	pshufb	xmm0,xword [gcm_bswap]
	movdqu	[rdi+GCM_H],xmm0
	ret

; rdi = ctx, xmm0 = block: E(K, block) in xmm0. Clobbers xmm1.
gcm_encrypt_block:
	movdqu	xmm1,[rdi+GCM_RK]
	pxor	xmm0,xmm1
	repeat 9, r:1
		movdqu	xmm1,[rdi+GCM_RK+r*16]
		aesenc	xmm0,xmm1
	end repeat
	movdqu	xmm1,[rdi+GCM_RK+160]
	aesenclast xmm0,xmm1
	ret

; xmm0 = X, xmm1 = H (both byte-reflected): X * H in GF(2^128), in xmm0.
; Clobbers xmm2-xmm9.
gcm_gfmul:
	movdqa	xmm3,xmm0
	pclmulqdq xmm3,xmm1,0x00
	movdqa	xmm4,xmm0
	pclmulqdq xmm4,xmm1,0x10
	movdqa	xmm5,xmm0
	pclmulqdq xmm5,xmm1,0x01
	movdqa	xmm6,xmm0
	pclmulqdq xmm6,xmm1,0x11
	pxor	xmm4,xmm5
	movdqa	xmm5,xmm4
	psrldq	xmm4,8
	pslldq	xmm5,8
	pxor	xmm3,xmm5
	pxor	xmm6,xmm4			; xmm6:xmm3 = X * H, bit-reflected
	; one bit left (the reflection's off-by-one)
	movdqa	xmm7,xmm3
	movdqa	xmm8,xmm6
	pslld	xmm3,1
	pslld	xmm6,1
	psrld	xmm7,31
	psrld	xmm8,31
	movdqa	xmm9,xmm7
	pslldq	xmm8,4
	pslldq	xmm7,4
	psrldq	xmm9,12
	por	xmm3,xmm7
	por	xmm6,xmm8
	por	xmm6,xmm9
	; reduction modulo x^128 + x^7 + x^2 + x + 1
	movdqa	xmm7,xmm3
	movdqa	xmm8,xmm3
	movdqa	xmm9,xmm3
	pslld	xmm7,31
	pslld	xmm8,30
	pslld	xmm9,25
	pxor	xmm7,xmm8
	pxor	xmm7,xmm9
	movdqa	xmm8,xmm7
	pslldq	xmm7,12
	psrldq	xmm8,4
	pxor	xmm3,xmm7
	movdqa	xmm2,xmm3
	movdqa	xmm4,xmm3
	movdqa	xmm5,xmm3
	psrld	xmm2,1
	psrld	xmm4,2
	psrld	xmm5,7
	pxor	xmm2,xmm4
	pxor	xmm2,xmm5
	pxor	xmm2,xmm8
	pxor	xmm3,xmm2
	pxor	xmm6,xmm3
	movdqa	xmm0,xmm6
	ret

; rdi = ctx, rsi = data, rdx = length, xmm10 = X (byte-reflected): X after
; GHASH over the data, zero-padded to a block. Clobbers xmm0-xmm9, rax,
; rcx, rsi, rdx.
gcm_ghash:
	sub	rsp,16
.block:
	test	rdx,rdx
	jz	.done
	cmp	rdx,16
	jae	.whole
	; the last, partial block: zero-padded copy
	pxor	xmm0,xmm0
	movdqu	[rsp],xmm0
	mov	rcx,rdx
	push	rdi
	lea	rdi,[rsp+8]
	rep	movsb
	pop	rdi
	movdqu	xmm0,[rsp]
	xor	edx,edx
	jmp	.mix
.whole:
	movdqu	xmm0,[rsi]
	add	rsi,16
	sub	rdx,16
.mix:
	pshufb	xmm0,xword [gcm_bswap]
	pxor	xmm0,xmm10
	movdqu	xmm1,[rdi+GCM_H]
	call	gcm_gfmul
	movdqa	xmm10,xmm0
	jmp	.block
.done:
	add	rsp,16
	ret

; rdi = ctx, r8 = buffer, r9 = length, r10d = first counter (big-endian
; counter value), xmm11 = the IV in the first 12 bytes: the buffer XORed
; with E(K, IV | counter++) in place. Clobbers xmm0-xmm2, rax, rcx, r8, r9.
gcm_ctr:
	sub	rsp,16
.block:
	test	r9,r9
	jz	.done
	movdqa	xmm0,xmm11
	mov	eax,r10d
	bswap	eax
	pinsrd	xmm0,eax,3
	inc	r10d
	call	gcm_encrypt_block		; keystream
	cmp	r9,16
	jb	.partial
	movdqu	xmm2,[r8]
	pxor	xmm2,xmm0
	movdqu	[r8],xmm2
	add	r8,16
	sub	r9,16
	jmp	.block
.partial:
	movdqu	[rsp],xmm0
	xor	ecx,ecx
@@:
	mov	al,[rsp+rcx]
	xor	[r8+rcx],al
	inc	ecx
	cmp	rcx,r9
	jb	@b
.done:
	pxor	xmm0,xmm0
	movdqu	[rsp],xmm0			; no keystream left behind
	add	rsp,16
	ret

; Common to seal and open: rdi ctx, rsi iv, rdx aad, ecx aad length,
; r8 buffer, r9 length. Sets xmm11 = IV | 0, keeps the args on the stack.
GS_AAD		:= 0
GS_ALEN		:= 8
GS_BUF		:= 16
GS_LEN		:= 24
GS_TAG		:= 32				; the computed tag
GS_CTX		:= 48
GS_SIZE		:= 64

; rsp-relative GS_* filled; xmm10 = GHASH over AAD and the ciphertext at
; GS_BUF: the tag in xmm0 (E(K, J0) XOR GHASH). Clobbers xmm0-xmm10.
macro gcm_tag_of_ciphertext
	pxor	xmm10,xmm10
	mov	rsi,[rsp+GS_AAD]
	mov	rdx,[rsp+GS_ALEN]
	call	gcm_ghash
	mov	rsi,[rsp+GS_BUF]
	mov	rdx,[rsp+GS_LEN]
	call	gcm_ghash
	; lengths in bits, big endian: len(A) | len(C)
	mov	rax,[rsp+GS_ALEN]
	shl	rax,3
	movq	xmm0,rax
	mov	rax,[rsp+GS_LEN]
	shl	rax,3
	movq	xmm1,rax
	punpcklqdq xmm1,xmm0			; low: len(C), high: len(A) (reflected order)
	pxor	xmm1,xmm10
	movdqa	xmm0,xmm1
	movdqu	xmm1,[rdi+GCM_H]
	call	gcm_gfmul
	pshufb	xmm0,xword [gcm_bswap]
	movdqa	xmm10,xmm0
	; E(K, J0), J0 = IV | 1
	movdqa	xmm0,xmm11
	mov	eax,0x01000000
	pinsrd	xmm0,eax,3
	call	gcm_encrypt_block
	pxor	xmm0,xmm10
end macro

gcm_seal:
	sub	rsp,GS_SIZE
	mov	[rsp+GS_AAD],rdx
	mov	ecx,ecx
	mov	[rsp+GS_ALEN],rcx
	mov	[rsp+GS_BUF],r8
	mov	[rsp+GS_LEN],r9
	movq	xmm11,[rsi]
	pinsrd	xmm11,[rsi+8],2
	mov	r10d,2				; data counters start at J0 + 1
	call	gcm_ctr
	gcm_tag_of_ciphertext
	mov	rax,[rsp+GS_BUF]
	add	rax,[rsp+GS_LEN]
	movdqu	[rax],xmm0			; the tag after the ciphertext
	add	rsp,GS_SIZE
	ret

gcm_open:
	sub	rsp,GS_SIZE
	mov	[rsp+GS_CTX],rdi
	mov	[rsp+GS_AAD],rdx
	mov	ecx,ecx
	mov	[rsp+GS_ALEN],rcx
	mov	[rsp+GS_BUF],r8
	mov	[rsp+GS_LEN],r9
	movq	xmm11,[rsi]
	pinsrd	xmm11,[rsi+8],2
	gcm_tag_of_ciphertext
	movdqu	[rsp+GS_TAG],xmm0
	mov	rsi,[rsp+GS_BUF]
	add	rsi,[rsp+GS_LEN]
	lea	rdi,[rsp+GS_TAG]
	mov	edx,16
	call	ct_equal			; constant time
	pxor	xmm0,xmm0
	movdqu	[rsp+GS_TAG],xmm0
	test	eax,eax
	jz	.out				; wrong tag: nothing decrypted
	mov	rdi,[rsp+GS_CTX]
	mov	r8,[rsp+GS_BUF]
	mov	r9,[rsp+GS_LEN]
	mov	r10d,2
	call	gcm_ctr
	mov	eax,1
.out:
	add	rsp,GS_SIZE
	ret
