; Constant-time and hygiene helpers for secrets.

; rdi = a, rsi = b, edx = length. eax = 1 when equal. The running time
; depends only on the length, never on where the first difference is.
ct_equal:
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

; rdi = buffer, ecx = length. Wipes secrets from memory; in assembly there
; is no optimizer that could drop the stores.
secure_zero:
	xor	eax,eax
	rep	stosb
	ret

; Which crypto paths this CPU takes (once, before the workers start).
crypto_init:
	push	rbx
	mov	eax,7
	xor	ecx,ecx
	cpuid
	shr	ebx,29				; SHA extensions
	and	bl,1
	mov	[g_cpu_shani],bl
	pop	rbx
	ret
