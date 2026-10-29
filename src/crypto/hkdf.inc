; HKDF-SHA-256 (RFC 5869) and the TLS 1.3 HKDF-Expand-Label (RFC 8446
; section 7.1).

; rdi = prk[32], rsi = salt, rdx = salt length, rcx = ikm, r8 = ikm length.
hkdf_extract:
	jmp	hmac_sha256			; PRK = HMAC(salt, IKM)

; rdi = out, esi = length (<= 255 * 32), rdx = prk[32], rcx = info,
; r8 = info length (< 1024). T(i) = HMAC(PRK, T(i-1) | info | i).
HKX_KEY		:= 0				; HMAC_CTX keyed with the PRK
HKX_WORK	:= HMAC_CTX_SIZE		; the copy MAC'ing one block
HKX_T		:= 2 * HMAC_CTX_SIZE		; T(i)
HKX_SIZE	:= 2 * HMAC_CTX_SIZE + 32 + 16
hkdf_expand:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	push	rbp
	sub	rsp,HKX_SIZE
	mov	rbx,rdi				; out
	mov	r12d,esi			; bytes left
	mov	r13,rcx				; info
	mov	r14,r8
	lea	rdi,[rsp+HKX_KEY]
	mov	rsi,rdx
	mov	edx,32
	call	hmac_sha256_init
	xor	ebp,ebp				; i - 1
.block:
	test	r12d,r12d
	jz	.done
	lea	rdi,[rsp+HKX_WORK]
	lea	rsi,[rsp+HKX_KEY]
	mov	ecx,HMAC_CTX_SIZE
	rep	movsb
	test	ebp,ebp
	jz	@f
	lea	rdi,[rsp+HKX_WORK]
	lea	rsi,[rsp+HKX_T]
	mov	edx,32
	call	hmac_sha256_update
@@:
	lea	rdi,[rsp+HKX_WORK]
	mov	rsi,r13
	mov	rdx,r14
	call	hmac_sha256_update
	inc	ebp
	mov	[rsp+HKX_T+32],bpl		; the counter byte
	lea	rdi,[rsp+HKX_WORK]
	lea	rsi,[rsp+HKX_T+32]
	mov	edx,1
	call	hmac_sha256_update
	lea	rdi,[rsp+HKX_WORK]
	lea	rsi,[rsp+HKX_T]
	call	hmac_sha256_final
	mov	ecx,32
	cmp	r12d,ecx
	jae	@f
	mov	ecx,r12d
@@:
	sub	r12d,ecx
	lea	rsi,[rsp+HKX_T]
	mov	rdi,rbx
	rep	movsb
	mov	rbx,rdi
	jmp	.block
.done:
	mov	rdi,rsp
	mov	ecx,HKX_SIZE
	call	secure_zero
	add	rsp,HKX_SIZE
	pop	rbp
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; HKDF-Expand-Label(Secret, Label, Context, Length) =
;   HKDF-Expand(Secret, HkdfLabel, Length), HkdfLabel = uint16 length |
;   opaque label<7..255> = "tls13 " + Label | opaque context<0..255>.
; rdi = out, esi = length, rdx = secret[32], rcx = label (NUL-terminated),
; r8 = context, r9d = context length (<= 64).
tls13_expand_label:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,336
	mov	rbx,rdi
	mov	r12d,esi
	mov	r13,rdx
	; build HkdfLabel at rsp
	mov	eax,esi
	xchg	al,ah
	mov	[rsp],ax			; length, big endian
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
	mov	[rsp+2],cl			; label length
	mov	[rdi],r9b			; context length
	inc	rdi
	mov	rsi,r8
	mov	ecx,r9d
	rep	movsb
	mov	r8,rdi
	sub	r8,rsp				; info length
	mov	rdi,rbx
	mov	esi,r12d
	mov	rdx,r13
	mov	rcx,rsp
	call	hkdf_expand
	add	rsp,336
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
