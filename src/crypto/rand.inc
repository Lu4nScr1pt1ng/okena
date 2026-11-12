; Random bytes from a pool: one getrandom of RND_DATA bytes serves many
; handshakes (each wanted two or three syscalls, each through two seccomp
; filters). The pool is a page of its own marked MADV_WIPEONFORK: a child
; finds it zeroed, its count of bytes left included, and fills it afresh, so
; no two processes ever share a byte (the supervisor forks workers, helpers
; and children of reloads; none of them has to say so). Bytes are wiped as
; they are handed out: what was used cannot be read back from the pool.

RND_LEFT	:= 0			; d: bytes still unused, at the end of the data
RND_DATA	:= 64
RND_SIZE	:= 4096 - RND_DATA
MADV_WIPEONFORK	:= 18

bss
	align 8
	g_rnd		dq ?		; the page, 0 until first used, -1 none (no WIPEONFORK)
end bss

; The page, before anything is forked or confined (the workers may not map
; memory): each child gets it wiped. Empty: filled at the first use.
rnd_init:
	push	rdi
	push	rsi
	jmp	rnd_bytes.map

; rdi = out, esi = length (1 .. RND_SIZE). CF when the kernel gave none.
; Keeps rbx, rbp, r12-r15.
rnd_bytes:
	mov	rax,[g_rnd]
	cmp	rax,-1
	je	.direct
	test	rax,rax
	jnz	.have
	push	rdi
	push	rsi
.map:
	xor	edi,edi
	mov	esi,4096
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.fail_pop
	push	rax
	mov	rdi,rax
	mov	esi,4096
	mov	edx,MADV_WIPEONFORK
	mov	eax,SYS_madvise
	syscall
	pop	rcx
	test	rax,rax
	jnz	.no_wipe			; (an old kernel: not this way)
	mov	[g_rnd],rcx
	pop	rsi
	pop	rdi
	test	esi,esi				; (rnd_init: nothing to give)
	jz	.inited
	mov	rax,rcx
.have:
	cmp	[rax+RND_LEFT],esi
	jae	.take
	; refill
	push	rdi
	push	rsi
	push	rax
	lea	rdi,[rax+RND_DATA]
	mov	esi,RND_SIZE
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	pop	rcx
	pop	rsi
	pop	rdi
	cmp	rax,RND_SIZE
	jne	.fail
	mov	dword [rcx+RND_LEFT],RND_SIZE
	mov	rax,rcx
.take:
	; from the end of what is left, wiped behind
	mov	ecx,[rax+RND_LEFT]
	sub	ecx,esi
	mov	[rax+RND_LEFT],ecx
	lea	r8,[rax+RND_DATA+rcx]
	mov	ecx,esi
	xor	edx,edx
@@:
	mov	al,[r8+rdx]
	mov	[rdi+rdx],al
	mov	byte [r8+rdx],0
	inc	edx
	cmp	edx,ecx
	jb	@b
	clc
	ret
.no_wipe:
	; no MADV_WIPEONFORK (before Linux 4.14): the syscall each time, as before
	mov	qword [g_rnd],-1
	pop	rsi
	pop	rdi
.direct:
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	cmp	rax,rsi
	jne	.fail
	clc
	ret
.fail_pop:
	pop	rsi
	pop	rdi
.fail:
	stc
	ret
.inited:
	clc
	ret
