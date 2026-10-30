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
tls12_finished:
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
