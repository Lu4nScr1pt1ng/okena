; Known-answer harness for src/crypto (not part of okena). Reads stdin:
; the first byte selects the function, the rest is its input; prints the
; result in hex on stdout.
;   's' SHA-256 of the rest              'S' the same on the scalar path
;   'h' HMAC: key length (2, LE), key, message
;   'k' HKDF: salt len (2), salt, ikm len (2), ikm, info len (2), info, out len (2)
;   'l' Expand-Label: secret (32), label len (1), label, ctx len (1), ctx, out len (2)
;   'x' X25519: scalar (32), u (32)

format ELF64 executable 3
entry start

include '../../src/core/sections.inc'
include '../../src/sys/linux.inc'
include '../../src/core/limits.inc'

segment readable executable

include '../../src/core/util.inc'
include '../../src/crypto/ct.inc'
include '../../src/crypto/sha256.inc'
include '../../src/crypto/hmac.inc'
include '../../src/crypto/hkdf.inc'
include '../../src/crypto/x25519.inc'

INPUT_MAX := 1 shl 22

bss
	align 16
	g_in_len	dq ?
	g_out:		rb 8192
	g_label:	rb 256
	g_in:		rb INPUT_MAX + 64
end bss

start:
	call	crypto_init
	xor	ebx,ebx
.read:
	xor	edi,edi
	lea	rsi,[g_in+rbx]
	mov	edx,INPUT_MAX
	sub	edx,ebx
	jz	.got
	xor	eax,eax
	syscall
	test	rax,rax
	jle	.got
	add	rbx,rax
	jmp	.read
.got:
	mov	[g_in_len],rbx
	test	rbx,rbx
	jz	.fail
	movzx	eax,byte [g_in]
	lea	rsi,[g_in+1]			; the input
	lea	rdx,[rbx-1]			; its length
	cmp	al,'s'
	je	.sha
	cmp	al,'S'
	je	.sha_scalar
	cmp	al,'h'
	je	.hmac
	cmp	al,'k'
	je	.hkdf
	cmp	al,'l'
	je	.label
	cmp	al,'x'
	je	.x25519
.fail:
	mov	edi,2
	mov	eax,SYS_exit_group
	syscall
.sha_scalar:
	mov	byte [g_cpu_shani],0
.sha:
	lea	rdi,[g_out]
	call	sha256
	mov	esi,32
	jmp	.print
.hmac:
	movzx	ecx,word [rsi]			; key length
	add	rsi,2
	sub	rdx,2
	lea	r8,[rdx]
	sub	r8,rcx				; message length
	lea	rdi,[g_out]
	mov	rax,rsi
	add	rax,rcx				; the message
	mov	rdx,rcx				; key length
	mov	rcx,rax
	call	hmac_sha256
	mov	esi,32
	jmp	.print
.hkdf:
	; salt
	movzx	edx,word [rsi]
	lea	rbx,[rsi+2]			; salt
	mov	r12,rdx
	lea	rsi,[rbx+rdx]
	movzx	ecx,word [rsi]			; ikm
	lea	r13,[rsi+2]
	mov	r14,rcx
	lea	rsi,[r13+rcx]
	movzx	ecx,word [rsi]			; info
	lea	r15,[rsi+2]
	mov	rbp,rcx
	lea	rsi,[r15+rcx]
	movzx	eax,word [rsi]			; out length
	push	rax
	sub	rsp,40
	mov	rdi,rsp				; prk
	mov	rsi,rbx
	mov	rdx,r12
	mov	rcx,r13
	mov	r8,r14
	call	hkdf_extract
	lea	rdi,[g_out]
	mov	esi,[rsp+40]
	mov	rdx,rsp
	mov	rcx,r15
	mov	r8,rbp
	call	hkdf_expand
	add	rsp,40
	pop	rsi
	jmp	.print
.label:
	mov	rbx,rsi				; secret
	movzx	ecx,byte [rsi+32]		; label
	lea	rsi,[rsi+33]
	lea	rdi,[g_label]
	rep	movsb
	mov	byte [rdi],0
	movzx	r9d,byte [rsi]			; context
	lea	r8,[rsi+1]
	movzx	esi,word [r8+r9]		; out length
	push	rsi
	lea	rdi,[g_out]
	mov	rdx,rbx
	lea	rcx,[g_label]
	call	tls13_expand_label
	pop	rsi
	jmp	.print
.x25519:
	lea	rdi,[g_out]
	lea	rdx,[rsi+32]
	call	x25519
	mov	esi,32
.print:
	; g_out, esi bytes, as hex
	lea	rdi,[g_in]
	lea	r8,[g_out]
	xor	ecx,ecx
.hex:
	cmp	ecx,esi
	jae	.write
	movzx	eax,byte [r8+rcx]
	mov	edx,eax
	shr	eax,4
	mov	al,[.digits+rax]
	mov	[rdi],al
	and	edx,15
	mov	dl,[.digits+rdx]
	mov	[rdi+1],dl
	add	rdi,2
	inc	ecx
	jmp	.hex
.write:
	mov	byte [rdi],10
	inc	rdi
	lea	rsi,[g_in]
	mov	rdx,rdi
	sub	rdx,rsi
	mov	edi,1
	mov	eax,SYS_write
	syscall
	xor	edi,edi
	mov	eax,SYS_exit_group
	syscall
.digits	db '0123456789abcdef'

segment readable
	rodata_emit

segment readable writeable
	bss_emit
