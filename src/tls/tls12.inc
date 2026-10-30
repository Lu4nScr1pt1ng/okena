; TLS 1.2 (RFC 5246), for older clients: ECDHE key exchange with AEAD
; (AES-128-GCM), the SHA-256 PRF. This file starts with the PRF; the
; handshake and the 1.2 record layer build on it.
;
; The PRF is P_SHA256 (RFC 5246 5): PRF(secret, label, seed) =
; P_SHA256(secret, label | seed), where
;   P_hash(secret, seed) = HMAC(secret, A(1) | seed)
;                        | HMAC(secret, A(2) | seed) | ...
;   A(0) = seed,  A(i) = HMAC(secret, A(i-1))
; Callers pass label|seed already joined as the seed.

; rdi = out, esi = output length, rdx = secret, ecx = secret length,
; r8 = seed (the label joined with the seed), r9d = seed length.
; Writes esi bytes of P_SHA256 to out. seed length must be <= 160.
p_sha256:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	push	rbp
	mov	r12,rdi				; out
	mov	r13d,esi			; bytes still wanted
	mov	r14,rdx				; secret
	mov	r15d,ecx			; secret length
	mov	ebx,r9d				; seed length
	mov	rbp,rsp
	sub	rsp,256
	and	rsp,-16
	; [rsp] = A (32), [rsp+32] = seed; [rsp+192] = one HMAC block
	lea	rdi,[rsp+32]
	mov	rsi,r8
	mov	ecx,ebx
	rep	movsb
	mov	rdi,rsp				; A(1) = HMAC(secret, seed)
	mov	rsi,r14
	mov	edx,r15d
	lea	rcx,[rsp+32]
	mov	r8d,ebx
	call	hmac_sha256
.block:
	lea	rdi,[rsp+192]			; HMAC(secret, A | seed)
	mov	rsi,r14
	mov	edx,r15d
	mov	rcx,rsp
	lea	r8d,[rbx+32]
	call	hmac_sha256
	mov	eax,32				; copy min(32, remaining)
	cmp	r13d,32
	cmovb	eax,r13d
	lea	rsi,[rsp+192]
	mov	rdi,r12
	mov	ecx,eax
	rep	movsb
	mov	r12,rdi
	sub	r13d,eax
	jz	.done
	mov	rdi,rsp				; A = HMAC(secret, A)
	mov	rsi,r14
	mov	edx,r15d
	mov	rcx,rsp
	mov	r8d,32
	call	hmac_sha256
	jmp	.block
.done:
	mov	rsp,rbp
	pop	rbp
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

rodata
	tls12_lbl_master	db 'master secret'
	tls12_lbl_keys		db 'key expansion'
	tls12_lbl_cfin		db 'client finished'
	tls12_lbl_sfin		db 'server finished'
end rodata

; rdi = out[48], rsi = premaster, edx = premaster length, rcx = client
; random[32], r8 = server random[32]: master_secret = PRF(premaster,
; "master secret", client_random | server_random).
tls12_master:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rdi
	mov	r13,rsi
	mov	r14d,edx
	mov	r15,rcx
	mov	rbx,r8
	sub	rsp,96
	lea	rdi,[rsp]
	lea	rsi,[tls12_lbl_master]
	mov	ecx,13
	rep	movsb
	mov	rsi,r15				; client random
	mov	ecx,32
	rep	movsb
	mov	rsi,rbx				; server random
	mov	ecx,32
	rep	movsb
	mov	rdi,r12
	mov	esi,48
	mov	rdx,r13
	mov	ecx,r14d
	lea	r8,[rsp]
	mov	r9d,77
	call	p_sha256
	add	rsp,96
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = out, esi = length, rdx = master_secret[48], rcx = server
; random[32], r8 = client random[32]: key_block = PRF(master,
; "key expansion", server_random | client_random).
tls12_key_block:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rdi
	mov	r13d,esi
	mov	r14,rdx
	mov	r15,rcx
	mov	rbx,r8
	sub	rsp,96
	lea	rdi,[rsp]
	lea	rsi,[tls12_lbl_keys]
	mov	ecx,13
	rep	movsb
	mov	rsi,r15				; server random
	mov	ecx,32
	rep	movsb
	mov	rsi,rbx				; client random
	mov	ecx,32
	rep	movsb
	mov	rdi,r12
	mov	esi,r13d
	mov	rdx,r14
	mov	ecx,48
	lea	r8,[rsp]
	mov	r9d,77
	call	p_sha256
	add	rsp,96
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = out[12], rsi = master_secret[48], rdx = label, ecx = label length,
; r8 = Hash(handshake_messages)[32]: verify_data = PRF(master, label,
; hash)[0..12], for a 1.2 Finished.
tls12_verify_data:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rdi
	mov	r13,rsi
	mov	r14,rdx
	mov	r15d,ecx
	mov	rbx,r8
	sub	rsp,64
	lea	rdi,[rsp]			; seed = label | hash
	mov	rsi,r14
	mov	ecx,r15d
	rep	movsb
	mov	rsi,rbx				; the transcript hash
	mov	ecx,32
	rep	movsb
	lea	r9d,[r15+32]			; seed length
	mov	rdi,r12
	mov	esi,12
	mov	rdx,r13
	mov	ecx,48
	lea	r8,[rsp]
	call	p_sha256
	add	rsp,64
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; The TLS 1.2 AEAD record layer (RFC 5288, AES-128-GCM): the record on the
; wire is explicit_nonce(8) | ciphertext | tag(16); the GCM nonce is
; write_IV(4 salt) | explicit_nonce(8), and the additional data is
; seq(8) | type(1) | version(2) | length(2), length being the plaintext
; length. The explicit nonce is the record sequence number.

; rdi = out, rsi = gcm ctx, rdx = write_IV (4-byte salt), rcx = sequence
; number, r8d = content type, r9 = plaintext, r10d = plaintext length:
; writes explicit_nonce | ciphertext | tag to out. eax = the record length.
tls12_seal:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rdi				; out
	mov	r13,rsi				; gcm
	mov	r14,r8				; content type (in r14b)
	mov	r15,r9				; plaintext
	mov	ebx,r10d			; plaintext length
	sub	rsp,48				; [rsp]=nonce(12), [rsp+16]=aad(13)
	mov	rax,rcx
	bswap	rax
	mov	[r12],rax			; explicit nonce = seq, big endian
	mov	[rsp+16],rax			; aad seq
	mov	eax,[rdx]			; nonce = salt | seq
	mov	[rsp],eax
	mov	rax,rcx
	bswap	rax
	mov	[rsp+4],rax
	mov	byte [rsp+16+8],r14b		; aad type
	mov	word [rsp+16+9],0x0303		; aad version
	mov	eax,ebx				; aad length, big endian u16
	rol	ax,8
	mov	[rsp+16+11],ax
	lea	rdi,[r12+8]			; copy the plaintext in place
	mov	rsi,r15
	mov	ecx,ebx
	rep	movsb
	mov	rdi,r13				; gcm_seal(ctx, nonce, aad, 13, out+8, ptlen)
	lea	rsi,[rsp]
	lea	rdx,[rsp+16]
	mov	ecx,13
	lea	r8,[r12+8]
	mov	r9d,ebx
	call	gcm_seal
	lea	eax,[rbx+24]			; 8 + ptlen + 16
	add	rsp,48
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = record (explicit_nonce | ciphertext | tag), esi = its length,
; rdx = gcm ctx, rcx = write_IV (salt), r8 = sequence number, r9d = content
; type: opens the record in place. eax = plaintext length (at record+8) on
; success, or -1 on a bad tag or a short record.
tls12_open:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rdi				; record
	mov	r13,rdx				; gcm
	mov	r14,r8				; sequence
	mov	r15d,r9d			; type
	mov	ebx,esi
	sub	ebx,24				; plaintext length = total - 8 - 16
	js	.bad
	sub	rsp,48
	mov	eax,[rcx]			; nonce = salt | explicit (= record[0..8])
	mov	[rsp],eax
	mov	rax,[r12]
	mov	[rsp+4],rax
	mov	rax,r14				; aad seq
	bswap	rax
	mov	[rsp+16],rax
	mov	byte [rsp+16+8],r15b		; aad type
	mov	word [rsp+16+9],0x0303
	mov	eax,ebx
	rol	ax,8
	mov	[rsp+16+11],ax
	mov	rdi,r13				; gcm_open(ctx, nonce, aad, 13, record+8, ptlen)
	lea	rsi,[rsp]
	lea	rdx,[rsp+16]
	mov	ecx,13
	lea	r8,[r12+8]
	mov	r9d,ebx
	call	gcm_open
	add	rsp,48
	test	eax,eax
	jz	.bad
	mov	eax,ebx
	jmp	.out
.bad:
	mov	eax,-1
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

