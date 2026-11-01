; QUIC packet protection (RFC 9001 section 5; version 2: RFC 9369).
;
; Keys come from a secret as in TLS 1.3, with QUIC's labels: Initial
; secrets from the client's first Destination Connection ID and a salt of
; the version, the others from the TLS handshake. A packet's payload is
; sealed with the AEAD the handshake chose (AES-128-GCM or ChaCha20-
; Poly1305), its nonce the IV XOR the packet number; then the header is
; protected: a mask from a sample of the ciphertext (AES-ECB, or ChaCha20
; with the sample as counter and nonce) hides the first byte's low bits
; and the packet number.
;
;   quic_initial(rdi client QK, rsi server QK, rdx dcid, ecx its length,
;                r8d version)
;   quic_keys(rdi QK, rsi secret[32], edx version, ecx aead: 0 AES-128-GCM,
;             1 ChaCha20-Poly1305)
;   quic_seal(rdi QK, rsi packet, edx header length (the packet number
;             last), ecx packet number length, r8 packet number, r9d
;             payload length): eax = the protected packet's length (the
;             tag follows the payload)
;   quic_open(rdi QK, rsi packet, edx its length, ecx where the packet
;             number starts, r8 the largest packet number received, -1
;             none): eax = the payload's length, rdx = the packet number,
;             the payload decrypted in place after the header; eax = -1
;             when it does not open (the header is left unmasked)
;   quic_retry_tag(rdi out[16], rsi original dcid, edx its length, rcx
;             the Retry packet without its tag, r8d its length, r9d
;             version)

QUIC_V1		:= 0x00000001
QUIC_V2		:= 0x6b3343cf

QK_AEAD		:= 0				; the payload's AEAD context (AEAD_SIZE)
QK_HPC		:= QK_AEAD + AEAD_SIZE		; header protection: an AES context, or
						; the ChaCha20 key at its start
QK_IV		:= QK_HPC + GCM_SIZE
QK_SIZE		:= QK_IV + 16

rodata
	quic_salt_v1	db 0x38,0x76,0x2c,0xf7,0xf5,0x59,0x34,0xb3,0x4d,0x17
			db 0x9a,0xe6,0xa4,0xc8,0x0c,0xad,0xcc,0xbb,0x7f,0x0a
	quic_salt_v2	db 0x0d,0xed,0xe3,0xde,0xf7,0x00,0xa6,0xdb,0x81,0x93
			db 0x81,0xbe,0x6e,0x26,0x9d,0xcb,0xf9,0xbd,0x2e,0xd9
	quic_retry_v1	db 0xbe,0x0c,0x69,0x0b,0x9f,0x66,0x57,0x5a	; key
			db 0x1d,0x76,0x6b,0x54,0xe3,0x68,0xc8,0x4e
			db 0x46,0x15,0x99,0xd3,0x5d,0x63,0x2b,0xf2	; nonce
			db 0x23,0x98,0x25,0xbb
	quic_retry_v2	db 0x8f,0xb4,0xb0,0x1b,0x56,0xac,0x48,0xe2
			db 0x60,0xfb,0xcb,0xce,0xad,0x7c,0xcc,0x92
			db 0xd8,0x69,0x69,0xbc,0x2d,0x7c,0x6d,0x99
			db 0x90,0xef,0xb0,0x4a
	lbl_client_in	db 'client in',0
	lbl_server_in	db 'server in',0
	lbl_quic_key	db 'quic key',0
	lbl_quic_iv	db 'quic iv',0
	lbl_quic_hp	db 'quic hp',0
	lbl_quic2_key	db 'quicv2 key',0
	lbl_quic2_iv	db 'quicv2 iv',0
	lbl_quic2_hp	db 'quicv2 hp',0
	lbl_quic_ku	db 'quic ku',0		; key update (RFC 9001 6.1)
	lbl_quic2_ku	db 'quicv2 ku',0
end rodata

quic_initial:
	push	rbx
	push	r12
	push	r13
	push	r14
	sub	rsp,104
	mov	rbx,rdi
	mov	r12,rsi
	mov	r14d,r8d
	; initial_secret = HKDF-Extract(salt of the version, dcid)
	lea	rdi,[rsp]
	lea	rsi,[quic_salt_v1]
	cmp	r14d,QUIC_V2
	jne	@f
	lea	rsi,[quic_salt_v2]
@@:
	mov	r8d,ecx
	mov	rcx,rdx
	mov	edx,20
	call	hkdf_extract
	lea	rdi,[rsp+32]
	mov	esi,32
	lea	rdx,[rsp]
	lea	rcx,[lbl_client_in]
	xor	r8d,r8d
	xor	r9d,r9d
	call	tls13_expand_label
	lea	rdi,[rsp+64]
	mov	esi,32
	lea	rdx,[rsp]
	lea	rcx,[lbl_server_in]
	xor	r8d,r8d
	xor	r9d,r9d
	call	tls13_expand_label
	mov	rdi,rbx
	lea	rsi,[rsp+32]
	mov	edx,r14d
	xor	ecx,ecx
	call	quic_keys
	mov	rdi,r12
	lea	rsi,[rsp+64]
	mov	edx,r14d
	xor	ecx,ecx
	call	quic_keys
	; the secrets are done with
	lea	rdi,[rsp]
	xor	eax,eax
	mov	ecx,96 / 8
	rep	stosq
	add	rsp,104
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

quic_keys:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,64
	mov	rbx,rdi
	mov	r12,rsi
	mov	r13d,ecx			; the AEAD
	lea	r14,[lbl_quic_key]		; the labels of the version
	cmp	edx,QUIC_V2
	jne	@f
	lea	r14,[lbl_quic2_key]
@@:
	mov	r15d,16				; key and hp lengths: 16, or 32 (ChaCha20)
	test	r13d,r13d
	jz	@f
	mov	r15d,32
@@:
	; key
	lea	rdi,[rsp]
	mov	esi,r15d
	mov	rdx,r12
	mov	rcx,r14
	xor	r8d,r8d
	xor	r9d,r9d
	call	tls13_expand_label
	lea	rdi,[rbx+QK_AEAD]
	lea	rsi,[rsp]
	mov	edx,r13d
	call	aead_init
	; iv (the label after the key's)
	mov	rcx,r14
@@:
	inc	rcx
	cmp	byte [rcx-1],0
	jne	@b
	push	rcx
	lea	rdi,[rbx+QK_IV]
	mov	esi,12
	mov	rdx,r12
	xor	r8d,r8d
	xor	r9d,r9d
	call	tls13_expand_label
	pop	rcx
	; hp (after the iv's)
@@:
	inc	rcx
	cmp	byte [rcx-1],0
	jne	@b
	lea	rdi,[rsp]
	mov	esi,r15d
	mov	rdx,r12
	xor	r8d,r8d
	xor	r9d,r9d
	call	tls13_expand_label
	test	r13d,r13d
	jnz	.chacha
	lea	rdi,[rbx+QK_HPC]
	lea	rsi,[rsp]
	call	gcm_init			; (for its AES round keys)
	jmp	.wipe
.chacha:
	movdqu	xmm0,[rsp]
	movdqu	[rbx+QK_HPC],xmm0
	movdqu	xmm0,[rsp+16]
	movdqu	[rbx+QK_HPC+16],xmm0
.wipe:
	pxor	xmm0,xmm0
	movdqu	[rsp],xmm0
	movdqu	[rsp+16],xmm0
	add	rsp,64
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = QK, rsi = sample[16]: the mask's five bytes in rax (low byte first).
; Keeps rdi, rsi.
quic_hp_mask:
	cmp	dword [rdi+QK_AEAD+AEAD_TYPE],0
	jne	.chacha
	push	rdi
	movdqu	xmm0,[rsi]
	lea	rdi,[rdi+QK_HPC]
	call	gcm_encrypt_block
	pop	rdi
	movq	rax,xmm0
	ret
.chacha:
	; the sample: a counter (4, little endian), then a nonce (12); the
	; mask is the key stream's first bytes (zeros XORed)
	push	rdi
	push	rsi
	sub	rsp,16
	mov	qword [rsp],0
	mov	edx,[rsi]
	lea	rsi,[rsi+4]
	lea	rdi,[rdi+QK_HPC]
	mov	rcx,rsp
	mov	r8d,8
	call	chacha20_xor
	mov	rax,[rsp]
	add	rsp,16
	pop	rsi
	pop	rdi
	ret

quic_seal:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,16
	mov	rbx,rdi
	mov	r12,rsi
	mov	r13d,edx			; header length
	mov	r14d,ecx			; packet number length
	mov	r15d,r9d			; payload length
	lea	rdi,[rsp]			; nonce = iv XOR the packet number
	lea	rsi,[rbx+QK_IV]
	mov	rdx,r8
	call	tls_nonce
	lea	rdi,[rbx+QK_AEAD]
	lea	rsi,[rsp]
	mov	rdx,r12				; aad: the header
	mov	ecx,r13d
	lea	r8,[r12+r13]
	mov	r9d,r15d
	call	aead_seal
	; header protection: the sample is 4 bytes past the packet number's start
	mov	rdi,rbx
	mov	eax,r13d
	sub	eax,r14d
	lea	rsi,[r12+rax+4]
	call	quic_hp_mask
	mov	cl,0x0F				; long header: 4 bits; short: 5
	test	byte [r12],0x80
	jnz	@f
	mov	cl,0x1F
@@:
	and	cl,al
	xor	[r12],cl
	mov	ecx,r13d
	sub	ecx,r14d			; the packet number's first byte
	xor	edx,edx
@@:
	shr	rax,8
	xor	[r12+rcx],al
	inc	ecx
	inc	edx
	cmp	edx,r14d
	jb	@b
	lea	eax,[r13+r15+16]
	add	rsp,16
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

quic_open:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	push	rbp
	sub	rsp,24
	mov	rbx,rdi
	mov	r12,rsi
	mov	r13d,edx			; packet length
	mov	r14d,ecx			; packet number offset
	mov	[rsp+16],r8			; the largest received
	lea	eax,[rcx+4+16]			; a sample, and a tag after the header
	cmp	eax,r13d
	ja	.bad
	mov	rdi,rbx
	lea	rsi,[r12+r14+4]
	call	quic_hp_mask
	mov	cl,0x0F
	test	byte [r12],0x80
	jnz	@f
	mov	cl,0x1F
@@:
	and	cl,al
	xor	[r12],cl
	movzx	r15d,byte [r12]
	and	r15d,3
	inc	r15d				; packet number length
	xor	ebp,ebp				; the truncated packet number
	lea	rdx,[r12+r14]
	lea	r8,[rdx+r15]
@@:
	shr	rax,8
	xor	[rdx],al
	shl	ebp,8
	movzx	ecx,byte [rdx]
	or	ebp,ecx
	inc	rdx
	cmp	rdx,r8
	jb	@b
	; the full packet number nearest the one expected (RFC 9000 A.3)
	mov	rax,[rsp+16]
	inc	rax				; expected = largest + 1 (0 when none)
	lea	ecx,[r15*8]
	mov	r8d,1
	shl	r8,cl				; window
	lea	r9,[r8-1]			; mask
	mov	r10,r8
	shr	r10,1				; half window
	mov	r11,rax
	not	r9
	and	r11,r9
	not	r9
	or	r11,rbp				; candidate
	mov	rcx,rax
	sub	rcx,r10				; expected - half
	cmp	r11,rcx
	jg	@f
	cmp	rcx,0				; (guard the negative case)
	jl	@f
	mov	rdx,(1 shl 62)
	sub	rdx,r8
	cmp	r11,rdx
	jge	@f
	add	r11,r8				; candidate + window
	jmp	.decoded
@@:
	lea	rcx,[rax+r10]			; expected + half
	cmp	r11,rcx
	jle	.decoded
	cmp	r11,r8
	jl	.decoded
	sub	r11,r8
.decoded:
	mov	[rsp+16],r11
	lea	rdi,[rsp]
	lea	rsi,[rbx+QK_IV]
	mov	rdx,r11
	call	tls_nonce
	lea	r14d,[r14+r15]			; the header's length
	mov	r9d,r13d
	sub	r9d,r14d
	sub	r9d,16				; the payload's
	js	.bad
	push	r9
	lea	rdi,[rbx+QK_AEAD]
	lea	rsi,[rsp+8]
	mov	rdx,r12
	mov	ecx,r14d
	lea	r8,[r12+r14]
	call	aead_open
	pop	r9
	test	eax,eax
	jz	.bad
	mov	eax,r9d
	mov	rdx,[rsp+16]
	jmp	.out
.bad:
	mov	eax,-1
.out:
	add	rsp,24
	pop	rbp
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; the pseudo-packet: original dcid length (1), the dcid, the Retry packet;
; the tag is AES-128-GCM's over it (as aad, nothing sealed) under the
; version's fixed key and nonce
quic_retry_tag:
	push	rbx
	push	r12
	push	rbp
	mov	rbp,rsp
	sub	rsp,GCM_SIZE + 1024 + 16
	and	rsp,-16
	mov	rbx,rdi
	cmp	r8d,1024 - 21
	ja	.out				; (a Retry is far smaller)
	lea	r12,[quic_retry_v1]
	cmp	r9d,QUIC_V2
	jne	@f
	lea	r12,[quic_retry_v2]
@@:
	lea	rdi,[rsp+GCM_SIZE]		; the pseudo-packet
	mov	[rdi],dl
	inc	rdi
	push	rcx
	mov	ecx,edx
	rep	movsb
	pop	rsi
	mov	ecx,r8d
	rep	movsb
	lea	rax,[rsp+GCM_SIZE]
	sub	rdi,rax
	push	rdi
	lea	rdi,[rsp+8]
	mov	rsi,r12
	call	gcm_init
	pop	rcx				; aad length
	lea	rdi,[rsp]
	lea	rsi,[r12+16]			; nonce
	lea	rdx,[rsp+GCM_SIZE]
	mov	r8,rbx				; nothing sealed: the tag lands at out
	xor	r9d,r9d
	call	gcm_seal
.out:
	mov	rsp,rbp
	pop	rbp
	pop	r12
	pop	rbx
	ret
