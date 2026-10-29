; Whole-file reads, used for configuration and certificates.

FILE_MAX := 64 shl 20			; refuse anything larger

; rdi = NUL-terminated path, rsi = arena.
; rax = contents (followed by 64 zero bytes) or -errno, rdx = length.
read_file:
	push	rbx
	push	r12
	push	r13
	push	r14
	sub	rsp,STAT_BYTES
	mov	r12,rsi
	mov	rsi,rdi
	mov	edi,AT_FDCWD
	mov	edx,O_RDONLY or O_CLOEXEC
	xor	r10d,r10d
	mov	eax,SYS_openat
	syscall
	test	rax,rax
	js	.out
	mov	ebx,eax
	mov	edi,ebx
	mov	rsi,rsp
	mov	eax,SYS_fstat
	syscall
	test	rax,rax
	js	.close_err
	mov	eax,[rsp+STAT_MODE]
	and	eax,S_IFMT
	cmp	eax,S_IFREG
	mov	rax,-EISDIR
	jne	.close_err
	mov	r13,[rsp+STAT_SIZE]
	cmp	r13,FILE_MAX
	mov	rax,-ENOMEM
	ja	.close_err
	mov	rdi,r12
	lea	rsi,[r13+64]
	call	arena_alloc
	mov	r14,rax
	xor	r12d,r12d			; bytes read
.read:
	cmp	r12,r13
	jae	.done
	mov	edi,ebx
	lea	rsi,[r14+r12]
	mov	rdx,r13
	sub	rdx,r12
	xor	eax,eax				; SYS_read
	syscall
	cmp	rax,-EINTR
	je	.read
	test	rax,rax
	js	.close_err
	jz	.done				; file shrank meanwhile
	add	r12,rax
	jmp	.read
.done:
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
	mov	rax,r14
	mov	rdx,r12
	jmp	.out
.close_err:
	push	rax
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
	pop	rax
.out:
	add	rsp,STAT_BYTES
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
