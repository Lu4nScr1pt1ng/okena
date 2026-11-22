; Constant-time and hygiene helpers for secrets.

; rdi = a, rsi = b, edx = length. eax = 1 when equal. The running time
; depends only on the length, never on where the first difference is.
ct_equal:
	cmp	edx,16
	je	.sixteen
	xor	eax,eax
	xor	ecx,ecx
	test	edx,edx
	jz	.done
.byte:
	mov	r8b,[rdi+rcx]
	xor	r8b,[rsi+rcx]
	or	al,r8b
	inc	ecx
	cmp	ecx,edx
	jb	.byte
.done:
	; eax = (al == 0) without a branch.
	movzx	eax,al
	sub	eax,1
	shr	eax,31
	ret
.sixteen:
	; an AEAD tag (every QUIC packet, every TLS record opened): two qwords,
	; the differences ORed, no branch on them
	mov	rax,[rdi]
	xor	rax,[rsi]
	mov	rcx,[rdi+8]
	xor	rcx,[rsi+8]
	or	rax,rcx
	sete	al
	movzx	eax,al
	ret

; rep movsb for short copies on CPUs without FSRM (Zen 2: tens of cycles to
; start one): rdi, rsi = after, rcx = 0, rax kept, only general registers
; (crypto and TLS code keep vector state around it); the flags clobbered.
; Not for overlapping buffers (a load can come after a store over it); past
; 256 bytes, rep movsb itself.
copy_rep:
	cmp	rcx,256
	ja	.rep
	push	rax
	cmp	ecx,16
	ja	.long
	cmp	ecx,8
	jb	.lt8
	mov	rax,[rsi]
	mov	[rdi],rax
	mov	rax,[rsi+rcx-8]
	mov	[rdi+rcx-8],rax
	jmp	.done
.lt8:
	cmp	ecx,4
	jb	.lt4
	mov	eax,[rsi]
	mov	[rdi],eax
	mov	eax,[rsi+rcx-4]
	mov	[rdi+rcx-4],eax
	jmp	.done
.lt4:
	test	ecx,ecx
	jz	.out
	mov	al,[rsi]
	mov	[rdi],al
	cmp	ecx,1
	je	.done
	mov	ax,[rsi+rcx-2]
	mov	[rdi+rcx-2],ax
	jmp	.done
.long:
	mov	rax,[rsi]
	mov	[rdi],rax
	add	rsi,8
	add	rdi,8
	sub	ecx,8
	cmp	ecx,8
	jae	.long
	test	ecx,ecx
	jz	.out
	mov	rax,[rsi+rcx-8]			; (the last, over what came before)
	mov	[rdi+rcx-8],rax
.done:
	add	rsi,rcx
	add	rdi,rcx
	xor	ecx,ecx
.out:
	pop	rax
	ret
.rep:
	rep	movsb
	ret

; rdi = buffer, ecx = length. Wipes secrets from memory; in assembly there
; is no optimizer that could drop the stores. 16 bytes a store (rep stosb
; costs more to start than these small frames take to clear); the last
; store overlaps when the length is not a multiple. Uses xmm15 (no other
; code does). eax = 0; rdi and rcx clobbered, as by rep stosb.
secure_zero:
	xor	eax,eax
	cmp	ecx,16
	jb	.bytes
	push	rdx
	pxor	xmm15,xmm15
	lea	rdx,[rdi+rcx-16]		; the last 16
.block:
	movdqu	[rdi],xmm15
	add	rdi,16
	cmp	rdi,rdx
	jb	.block
	movdqu	[rdx],xmm15
	pop	rdx
	ret
.bytes:
	rep	stosb
	ret

; Which crypto paths this CPU takes (once, before the workers start).
crypto_init:
	push	rbx
	mov	eax,7
	xor	ecx,ecx
	cpuid
	mov	eax,ebx
	shr	eax,19				; ADX (adcx, adox), with BMI2 (mulx) beside it
	and	eax,1
	mov	edx,ebx
	shr	edx,8
	and	eax,edx
	and	al,1
	mov	[g_cpu_adx],al
	shr	ebx,29				; SHA extensions
	and	bl,1
	mov	[g_cpu_shani],bl
	and	ecx,(1 shl 9) or (1 shl 10)	; VAES and VPCLMULQDQ, on ymm
	cmp	ecx,(1 shl 9) or (1 shl 10)
	sete	[g_cpu_vaes]
	pop	rbx
	ret
