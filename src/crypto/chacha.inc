; ChaCha20-Poly1305 (RFC 8439), for TLS_CHACHA20_POLY1305_SHA256: the
; AEAD of clients without AES in hardware (they list it first).
;
; ChaCha20 on AVX2 two blocks at a time: the state's four rows in four
; ymm, block n in the low 128-bit lane and block n + 1 in the high one, so
; the diagonal shuffles (vpshufd) and the 16- and 8-bit rotations
; (vpshufb) stay within a lane and one instruction stream serves both.
; Poly1305 in radix 2^64 with mulx: h in three limbs (the top one a few
; bits), r clamped, 2^130 = 5 folded in as s1 = r1 + r1 / 4. Nothing
; branches on or indexes by secret data.
;
;   cp_init(rdi ctx, rsi key[32])
;   cp_seal(rdi ctx, rsi iv[12], rdx aad, ecx aad length, r8 buffer,
;           r9 length): encrypts the buffer in place, the 16-byte tag
;           right after it
;   cp_open(same): eax = 1 and the buffer decrypted when the tag after it
;           is right; eax = 0 and the buffer untouched otherwise (the tag
;           is checked before anything is decrypted)
;   chacha20_xor(rdi key[32], rsi nonce[12], edx counter, rcx buffer,
;           r8 length): the buffer XORed with the key stream

CP_KEY		:= 0
CP_SIZE		:= 32

rodata
	align 32
	chacha_sigma	db 'expand 32-byte k', 'expand 32-byte k'
	chacha_rot16	db 2,3,0,1, 6,7,4,5, 10,11,8,9, 14,15,12,13
			db 2,3,0,1, 6,7,4,5, 10,11,8,9, 14,15,12,13
	chacha_rot8	db 3,0,1,2, 7,4,5,6, 11,8,9,10, 15,12,13,14
			db 3,0,1,2, 7,4,5,6, 11,8,9,10, 15,12,13,14
	chacha_inc2	dd 0,0,0,0, 1,0,0,0		; the high lane's block: counter + 1
	chacha_add2	dd 2,0,0,0, 2,0,0,0
end rodata

; one ChaCha quarter round on the rows a, b, c, d (ymm0..ymm3), every
; column at once; ymm4 scratch, ymm14 = rot16, ymm15 = rot8
macro cc_quarter
	vpaddd	ymm0,ymm0,ymm1
	vpxor	ymm3,ymm3,ymm0
	vpshufb	ymm3,ymm3,ymm14
	vpaddd	ymm2,ymm2,ymm3
	vpxor	ymm1,ymm1,ymm2
	vpslld	ymm4,ymm1,12
	vpsrld	ymm1,ymm1,20
	vpor	ymm1,ymm1,ymm4
	vpaddd	ymm0,ymm0,ymm1
	vpxor	ymm3,ymm3,ymm0
	vpshufb	ymm3,ymm3,ymm15
	vpaddd	ymm2,ymm2,ymm3
	vpxor	ymm1,ymm1,ymm2
	vpslld	ymm4,ymm1,7
	vpsrld	ymm1,ymm1,25
	vpor	ymm1,ymm1,ymm4
end macro

; ymm8..ymm11 = the initial rows of two blocks: their key stream, 128
; bytes, in ymm0..ymm3 (block n then block n + 1). Clobbers ymm4, ecx.
cc_two_blocks:
	vmovdqa	ymm0,ymm8
	vmovdqa	ymm1,ymm9
	vmovdqa	ymm2,ymm10
	vmovdqa	ymm3,ymm11
	mov	ecx,10
.double:
	cc_quarter				; columns
	vpshufd	ymm1,ymm1,0x39
	vpshufd	ymm2,ymm2,0x4E
	vpshufd	ymm3,ymm3,0x93
	cc_quarter				; diagonals
	vpshufd	ymm1,ymm1,0x93
	vpshufd	ymm2,ymm2,0x4E
	vpshufd	ymm3,ymm3,0x39
	dec	ecx
	jnz	.double
	vpaddd	ymm0,ymm0,ymm8
	vpaddd	ymm1,ymm1,ymm9
	vpaddd	ymm2,ymm2,ymm10
	vpaddd	ymm3,ymm3,ymm11
	vperm2i128 ymm4,ymm0,ymm1,0x20		; block n: rows 0, 1
	vperm2i128 ymm5,ymm2,ymm3,0x20		; rows 2, 3
	vperm2i128 ymm6,ymm0,ymm1,0x31		; block n + 1
	vperm2i128 ymm7,ymm2,ymm3,0x31
	vmovdqa	ymm0,ymm4
	vmovdqa	ymm1,ymm5
	vmovdqa	ymm2,ymm6
	vmovdqa	ymm3,ymm7
	ret

chacha20_xor:
	push	rbp
	mov	rbp,rsp
	sub	rsp,128
	and	rsp,-32
	vmovdqa	ymm8,yword [chacha_sigma]
	vbroadcasti128 ymm9,[rdi]
	vbroadcasti128 ymm10,[rdi+16]
	mov	[rsp],edx			; counter | nonce
	mov	eax,[rsi]
	mov	[rsp+4],eax
	mov	rax,[rsi+4]
	mov	[rsp+8],rax
	vbroadcasti128 ymm11,[rsp]
	vpaddd	ymm11,ymm11,yword [chacha_inc2]
	vmovdqa	ymm14,yword [chacha_rot16]
	vmovdqa	ymm15,yword [chacha_rot8]
	mov	rsi,rcx				; the buffer
	mov	rdx,r8				; what is left
.two:
	test	rdx,rdx
	jz	.done
	call	cc_two_blocks
	vpaddd	ymm11,ymm11,yword [chacha_add2]
	cmp	rdx,128
	jb	.tail
	vpxor	ymm0,ymm0,[rsi]
	vpxor	ymm1,ymm1,[rsi+32]
	vpxor	ymm2,ymm2,[rsi+64]
	vpxor	ymm3,ymm3,[rsi+96]
	vmovdqu	[rsi],ymm0
	vmovdqu	[rsi+32],ymm1
	vmovdqu	[rsi+64],ymm2
	vmovdqu	[rsi+96],ymm3
	add	rsi,128
	sub	rdx,128
	jmp	.two
.tail:
	vmovdqa	[rsp],ymm0
	vmovdqa	[rsp+32],ymm1
	vmovdqa	[rsp+64],ymm2
	vmovdqa	[rsp+96],ymm3
	xor	ecx,ecx
@@:
	mov	al,[rsp+rcx]
	xor	[rsi+rcx],al
	inc	ecx
	cmp	rcx,rdx
	jb	@b
	vpxor	ymm0,ymm0,ymm0			; the key stream off the stack
	vmovdqa	[rsp],ymm0
	vmovdqa	[rsp+32],ymm0
	vmovdqa	[rsp+64],ymm0
	vmovdqa	[rsp+96],ymm0
.done:
	mov	rsp,rbp
	pop	rbp
	vzeroupper
	ret

; ---------------------------------------------------------------- Poly1305

PY_H0		:= 0
PY_H1		:= 8
PY_H2		:= 16
PY_R0		:= 24
PY_R1		:= 32
PY_S1		:= 40
PY_S		:= 48				; 16 bytes
PY_BUF		:= 64				; a padded block (16)
PY_SIZE		:= 80

; rdi = state, rsi = key[32] (r | s)
poly_init:
	xor	eax,eax
	mov	[rdi+PY_H0],rax
	mov	[rdi+PY_H1],rax
	mov	[rdi+PY_H2],rax
	mov	rax,0x0FFFFFFC0FFFFFFF
	and	rax,[rsi]
	mov	[rdi+PY_R0],rax
	mov	rax,0x0FFFFFFC0FFFFFFC
	and	rax,[rsi+8]
	mov	[rdi+PY_R1],rax
	mov	rcx,rax
	shr	rcx,2
	add	rax,rcx				; s1 = 5 r1 / 4
	mov	[rdi+PY_S1],rax
	mov	rax,[rsi+16]
	mov	[rdi+PY_S],rax
	mov	rax,[rsi+24]
	mov	[rdi+PY_S+8],rax
	ret

; rdi = state, rsi = data, rdx = length: Poly1305 over the data zero-padded
; to a multiple of 16 (RFC 8439's AEAD padding), every block a full one.
poly_padded:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	push	rbp
	mov	rbp,rdx
	mov	r8,[rdi+PY_H0]
	mov	r9,[rdi+PY_H1]
	mov	r10,[rdi+PY_H2]
	mov	r11,[rdi+PY_R0]
	mov	r12,[rdi+PY_R1]
	mov	r13,[rdi+PY_S1]
.block:
	cmp	rbp,16
	jb	.partial
	mov	rax,[rsi]
	mov	rcx,[rsi+8]
	add	rsi,16
	sub	rbp,16
.absorb:
	add	r8,rax				; h += m + 2^128
	adc	r9,rcx
	adc	r10,1
	; h * r, 2^130 folded back as 5
	mov	rdx,r8
	mulx	rbx,rax,r11			; h0 r0
	mulx	r15,r14,r12			; h0 r1
	mov	rdx,r9
	mulx	rdx,rcx,r13			; h1 s1
	add	rax,rcx
	adc	rbx,rdx
	mov	rdx,r9
	mulx	rdx,rcx,r11			; h1 r0
	add	r14,rcx
	adc	r15,rdx
	mov	rcx,r10
	imul	rcx,r13				; h2 s1 (h2 is a few bits)
	add	r14,rcx
	adc	r15,0
	imul	r10,r11				; h2 r0
	mov	r8,rax				; h0
	add	r14,rbx
	adc	r15,0
	mov	r9,r14				; h1
	add	r10,r15				; h2
	; partial reduction: h2 above 2 bits comes back times 5
	mov	rax,r10
	and	rax,-4
	mov	rcx,r10
	shr	rcx,2
	and	r10,3
	add	rax,rcx
	add	r8,rax
	adc	r9,0
	adc	r10,0
	jmp	.block
.partial:
	test	rbp,rbp
	jz	.done
	xor	eax,eax				; the rest, zero-padded
	mov	[rdi+PY_BUF],rax
	mov	[rdi+PY_BUF+8],rax
	xor	ecx,ecx
@@:
	mov	al,[rsi+rcx]
	mov	[rdi+PY_BUF+rcx],al
	inc	ecx
	cmp	rcx,rbp
	jb	@b
	xor	ebp,ebp
	mov	rax,[rdi+PY_BUF]
	mov	rcx,[rdi+PY_BUF+8]
	jmp	.absorb
.done:
	mov	[rdi+PY_H0],r8
	mov	[rdi+PY_H1],r9
	mov	[rdi+PY_H2],r10
	pop	rbp
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = state, rsi = out[16]: the tag, (h mod p) + s mod 2^128.
poly_final:
	mov	r8,[rdi+PY_H0]
	mov	r9,[rdi+PY_H1]
	mov	r10,[rdi+PY_H2]
	mov	rax,r8				; g = h + 5
	add	rax,5
	mov	rcx,r9
	adc	rcx,0
	mov	rdx,r10
	adc	rdx,0
	shr	rdx,2				; g >= 2^130: h >= p, take g
	neg	rdx				; mask
	xor	rax,r8
	xor	rcx,r9
	and	rax,rdx
	and	rcx,rdx
	xor	r8,rax
	xor	r9,rcx
	add	r8,[rdi+PY_S]
	adc	r9,[rdi+PY_S+8]
	mov	[rsi],r8
	mov	[rsi+8],r9
	ret

; ------------------------------------------------------------------- AEAD

CPS_POLY	:= 0
CPS_OTK		:= PY_SIZE			; the one-time Poly1305 key (64: a block)
CPS_LENS	:= CPS_OTK + 64
CPS_TAG		:= CPS_LENS + 16
CPS_ARGS	:= CPS_TAG + 16			; ctx, iv, aad, aad length, buffer, length
CPS_SIZE	:= CPS_ARGS + 48

cp_init:
	mov	rax,[rsi]
	mov	[rdi],rax
	mov	rax,[rsi+8]
	mov	[rdi+8],rax
	mov	rax,[rsi+16]
	mov	[rdi+16],rax
	mov	rax,[rsi+24]
	mov	[rdi+24],rax
	ret

; the MAC of (aad, ciphertext) into [rsp+CPS_TAG], frame set by the caller
macro cp_mac
	lea	rdi,[rsp+CPS_OTK]		; the one-time key: block 0's first 32 bytes
	xor	eax,eax
	mov	ecx,8
	rep	stosq
	mov	rdi,[rsp+CPS_ARGS]
	mov	rsi,[rsp+CPS_ARGS+8]
	xor	edx,edx
	lea	rcx,[rsp+CPS_OTK]
	mov	r8d,64
	call	chacha20_xor
	lea	rdi,[rsp+CPS_POLY]
	lea	rsi,[rsp+CPS_OTK]
	call	poly_init
	lea	rdi,[rsp+CPS_POLY]
	mov	rsi,[rsp+CPS_ARGS+16]
	mov	rdx,[rsp+CPS_ARGS+24]
	call	poly_padded
	lea	rdi,[rsp+CPS_POLY]
	mov	rsi,[rsp+CPS_ARGS+32]
	mov	rdx,[rsp+CPS_ARGS+40]
	call	poly_padded
	mov	rax,[rsp+CPS_ARGS+24]
	mov	[rsp+CPS_LENS],rax
	mov	rax,[rsp+CPS_ARGS+40]
	mov	[rsp+CPS_LENS+8],rax
	lea	rdi,[rsp+CPS_POLY]
	lea	rsi,[rsp+CPS_LENS]
	mov	edx,16
	call	poly_padded
	lea	rdi,[rsp+CPS_POLY]
	lea	rsi,[rsp+CPS_TAG]
	call	poly_final
end macro

macro cp_frame
	sub	rsp,CPS_SIZE + 8
	mov	[rsp+CPS_ARGS],rdi
	mov	[rsp+CPS_ARGS+8],rsi
	mov	[rsp+CPS_ARGS+16],rdx
	mov	ecx,ecx
	mov	[rsp+CPS_ARGS+24],rcx
	mov	[rsp+CPS_ARGS+32],r8
	mov	[rsp+CPS_ARGS+40],r9
end macro

; jumped to: the frame wiped (the one-time key, the Poly1305 state), then
; return eax
cp_leave:
	mov	r8d,eax
	mov	rdi,rsp
	xor	eax,eax
	mov	ecx,CPS_ARGS / 8
	rep	stosq
	mov	eax,r8d
	add	rsp,CPS_SIZE + 8
	ret

cp_seal:
	cp_frame
	mov	rdi,[rsp+CPS_ARGS]		; encrypt, block 1 on
	mov	rsi,[rsp+CPS_ARGS+8]
	mov	edx,1
	mov	rcx,[rsp+CPS_ARGS+32]
	mov	r8,[rsp+CPS_ARGS+40]
	call	chacha20_xor
	cp_mac
	mov	rdi,[rsp+CPS_ARGS+32]		; the tag after the ciphertext
	add	rdi,[rsp+CPS_ARGS+40]
	mov	rax,[rsp+CPS_TAG]
	mov	[rdi],rax
	mov	rax,[rsp+CPS_TAG+8]
	mov	[rdi+8],rax
	mov	eax,1
	jmp	cp_leave

cp_open:
	cp_frame
	cp_mac
	mov	rdi,[rsp+CPS_ARGS+32]		; the tag, in constant time
	add	rdi,[rsp+CPS_ARGS+40]
	mov	rax,[rsp+CPS_TAG]
	xor	rax,[rdi]
	mov	rcx,[rsp+CPS_TAG+8]
	xor	rcx,[rdi+8]
	or	rax,rcx
	jnz	.bad
	mov	rdi,[rsp+CPS_ARGS]		; right: decrypt
	mov	rsi,[rsp+CPS_ARGS+8]
	mov	edx,1
	mov	rcx,[rsp+CPS_ARGS+32]
	mov	r8,[rsp+CPS_ARGS+40]
	call	chacha20_xor
	mov	eax,1
	jmp	cp_leave
.bad:
	xor	eax,eax
	jmp	cp_leave

; ------------------------------------------------- the AEAD of a TLS suite
;
; One context for either AEAD: AES-128-GCM's (gcm_*) or ChaCha20-Poly1305's
; (cp_*), its type after it. aead_seal and aead_open take what gcm_seal and
; gcm_open take.

AEAD_TYPE	:= GCM_SIZE			; d: 0 AES-128-GCM, 1 ChaCha20-Poly1305
AEAD_SIZE	:= GCM_SIZE + 16
assert CP_SIZE <= GCM_SIZE

; rdi = ctx, rsi = key (16 or 32 bytes), edx = the type
aead_init:
	mov	[rdi+AEAD_TYPE],edx
	test	edx,edx
	jnz	cp_init
	jmp	gcm_init

aead_seal:
	cmp	dword [rdi+AEAD_TYPE],0
	jne	cp_seal
	jmp	gcm_seal

aead_open:
	cmp	dword [rdi+AEAD_TYPE],0
	jne	cp_open
	jmp	gcm_open
