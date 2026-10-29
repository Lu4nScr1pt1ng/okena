; Bump allocators over reserved address space.
;
; An arena is three quadwords: base, next free byte, end. The space is
; reserved once with MAP_NORESERVE, so an arena costs only the pages it
; touches. Allocations are 8-byte aligned and zeroed (fresh anonymous
; pages are zero, and arenas are never reused).

AR_BASE	:= 0
AR_NEXT	:= 8
AR_END	:= 16
AR_SIZE	:= 24

; rdi = arena, rsi = bytes to reserve. Exits when the kernel refuses.
arena_init:
	push	rbx
	push	r12
	mov	rbx,rdi
	mov	r12,rsi
	xor	edi,edi
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.fail
	mov	[rbx+AR_BASE],rax
	mov	[rbx+AR_NEXT],rax
	add	rax,r12
	mov	[rbx+AR_END],rax
	; small and cold: 4 KiB pages, or every touch would commit 2 MiB
	mov	rdi,[rbx+AR_BASE]
	mov	rsi,r12
	mov	edx,MADV_NOHUGEPAGE
	mov	eax,SYS_madvise
	syscall
	pop	r12
	pop	rbx
	ret
.fail:
	call	log_begin
	out_lit 'cannot reserve memory'
	call	log_end
	mov	edi,EXIT_FATAL
	jmp	exit_process

; rdi = arena, rsi = bytes. rax = zeroed memory. Exits when full.
arena_alloc:
	mov	rax,[rdi+AR_NEXT]
	lea	rdx,[rax+rsi+7]
	and	rdx,-8
	cmp	rdx,[rdi+AR_END]
	ja	.full
	mov	[rdi+AR_NEXT],rdx
	ret
.full:
	call	log_begin
	out_lit 'out of reserved memory (input too large)'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
