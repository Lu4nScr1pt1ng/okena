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
