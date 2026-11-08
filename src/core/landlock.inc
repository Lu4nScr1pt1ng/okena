; Landlock: each process gives up the filesystem it does not need, beside
; its seccomp filter (which says which calls; this says on what). Set up
; before the filter, never undone, inherited by what a process forks.
;
;   worker            nothing, but its `files` roots, to read (files.inc)
;   health, admin     nothing
;   control, JWKS     to read, anywhere (resolv.conf, hosts, discovery files,
;                     a token, the system's roots): nothing written
;   logger            the same, and to write and create files in the
;                     directories of its access logs
;   reload compiler   to read, anywhere: the configuration and its files
;
; The rights handled are those of the kernel's Landlock version (1: the 13
; first; 2: refer; 3: truncate; 5: device ioctls); from version 6 a process
; also may not signal, nor reach the abstract UNIX sockets of, a process out
; of its domain. A kernel with no Landlock leaves seccomp alone to guard,
; and okena says so once at the start.

LANDLOCK_CREATE_RULESET_VERSION := 1
LLF_EXECUTE	:= 1
LLF_WRITE	:= 2
LLF_READ	:= 4
LLF_READ_DIR	:= 8
LLF_MAKE_REG	:= 256
LLF_TRUNCATE	:= 16384
LL_SCOPE_ALL	:= 3			; abstract UNIX sockets, signals
LL_READS	:= LLF_READ or LLF_READ_DIR
LL_WRITES	:= LLF_WRITE or LLF_MAKE_REG or LLF_TRUNCATE

bss
	align 8
	g_ll_abi	dd ?		; the kernel's Landlock version, 0 none, -1 not asked yet
	g_ll_fd		dd ?		; the ruleset being built, -1 none
	g_ll_rule	rb 16		; landlock_path_beneath_attr: allowed q, parent fd d
	g_ll_attr	rb 24		; landlock_ruleset_attr: fs q, net q, scoped q
end bss

; eax = the kernel's Landlock version (0 when it has none)
ll_abi:
	mov	eax,[g_ll_abi]
	test	eax,eax
	jns	.known
	xor	edi,edi
	xor	esi,esi
	mov	edx,LANDLOCK_CREATE_RULESET_VERSION
	mov	eax,SYS_ll_create
	syscall
	test	eax,eax
	jns	@f
	xor	eax,eax
@@:
	mov	[g_ll_abi],eax
.known:
	ret

; The supervisor, at the start: the version asked once (every process then
; knows it), and said when there is none.
ll_init:
	mov	dword [g_ll_abi],-1
	call	ll_abi
	test	eax,eax
	jnz	.done
	call	log_begin
	out_lit 'landlock: this kernel has none; each process is confined by seccomp alone'
	call	log_end
.done:
	ret

; rax = the filesystem rights this kernel's version handles
ll_handled:
	call	ll_abi
	mov	ecx,eax
	mov	eax,0x1FFF
	cmp	ecx,2
	jb	.out
	or	eax,1 shl 13			; refer
	cmp	ecx,3
	jb	.out
	or	eax,LLF_TRUNCATE
	cmp	ecx,5
	jb	.out
	or	eax,1 shl 15			; device ioctls
.out:
	ret

; A ruleset that handles every right this kernel knows (none granted yet).
; CF when there is no Landlock.
ll_begin:
	mov	dword [g_ll_fd],-1
	call	ll_abi
	test	eax,eax
	jz	.none
	push	rax
	call	ll_handled
	mov	qword [g_ll_attr],rax
	mov	qword [g_ll_attr+8],0		; (TCP is the seccomp filter's and the ring's)
	mov	qword [g_ll_attr+16],LL_SCOPE_ALL
	pop	rcx
	mov	esi,8				; the size this version takes
	cmp	ecx,4
	jb	@f
	mov	esi,16
	cmp	ecx,6
	jb	@f
	mov	esi,24
@@:
	lea	rdi,[g_ll_attr]
	xor	edx,edx
	mov	eax,SYS_ll_create
	syscall
	test	eax,eax
	js	.none
	mov	[g_ll_fd],eax
	clc
	ret
.none:
	stc
	ret

; rdi = a path (NUL-terminated), esi = rights: granted beneath it (as far as
; this version handles them; a file takes file rights only)
ll_path:
	cmp	dword [g_ll_fd],0
	jl	.out
	push	rsi
	mov	rsi,rdi
	mov	edi,AT_FDCWD
	mov	edx,O_PATH_ or O_CLOEXEC_
	xor	r10d,r10d
	mov	eax,SYS_openat
	syscall
	pop	rsi
	test	eax,eax
	js	.out				; (not there: nothing to grant)
	push	rax
	mov	edi,eax
	call	ll_fd
	pop	rdi
	mov	eax,SYS_close
	syscall
.out:
	ret

; edi = an O_PATH descriptor, esi = rights: granted beneath it
ll_fd:
	cmp	dword [g_ll_fd],0
	jl	.out
	push	rdi
	push	rsi
	call	ll_handled
	pop	rsi
	pop	rdi
	and	rax,rsi
	mov	qword [g_ll_rule],rax
	mov	dword [g_ll_rule+8],edi
	mov	edi,[g_ll_fd]
	mov	esi,1				; LANDLOCK_RULE_PATH_BENEATH
	lea	rdx,[g_ll_rule]
	xor	r10d,r10d
	mov	eax,SYS_ll_add
	syscall
	test	eax,eax
	jns	.out
	; a file, not a directory: its own rights only
	and	qword [g_ll_rule],LLF_EXECUTE or LLF_WRITE or LLF_READ or LLF_TRUNCATE
	mov	edi,[g_ll_fd]
	mov	esi,1
	lea	rdx,[g_ll_rule]
	xor	r10d,r10d
	mov	eax,SYS_ll_add
	syscall
.out:
	ret

; The ruleset, in force for this process and what it forks. eax = 0, or
; -errno (it stays as it was).
ll_end:
	mov	eax,-1
	cmp	dword [g_ll_fd],0
	jl	.out
	mov	edi,PR_SET_NO_NEW_PRIVS
	mov	esi,1
	xor	edx,edx
	xor	r10d,r10d
	xor	r8d,r8d
	mov	eax,SYS_prctl
	syscall
	mov	edi,[g_ll_fd]
	xor	esi,esi
	mov	eax,SYS_ll_restrict
	syscall
	push	rax
	mov	edi,[g_ll_fd]
	mov	eax,SYS_close
	syscall
	mov	dword [g_ll_fd],-1
	pop	rax
.out:
	ret

cstring str_ll_root, '/',0

; A process that needs no file: none at all
ll_confine_none:
	call	ll_begin
	jc	.out
	call	ll_end
.out:
	ret

; A process that reads, anywhere, and writes nothing
ll_confine_reader:
	call	ll_begin
	jc	.out
	lea	rdi,[str_ll_root]
	mov	esi,LL_READS
	call	ll_path
	call	ll_end
.out:
	ret

; The logger: to read anywhere, and to write and create files in its access
; logs' directories
ll_confine_logger:
	push	rbx
	call	ll_begin
	jc	.out
	lea	rdi,[str_ll_root]
	mov	esi,LL_READS
	call	ll_path
	xor	ebx,ebx
.dest:
	cmp	ebx,[g_alog_count]
	jae	.done
	imul	rsi,rbx,ALOG_PATH
	lea	rsi,[g_alog_dest+rsi]
	inc	ebx
	cmp	byte [rsi],'/'
	jne	.dest				; (stdout, stderr, the network)
	; its directory: up to its last '/'
	lea	rdi,[g_ll_dir]
	xor	ecx,ecx
	xor	edx,edx				; the last '/'
@@:
	mov	al,[rsi+rcx]
	test	al,al
	jz	@f
	mov	[rdi+rcx],al
	cmp	al,'/'
	jne	.not_slash
	mov	edx,ecx
.not_slash:
	inc	ecx
	cmp	ecx,ALOG_PATH - 1
	jb	@b
@@:
	test	edx,edx
	jnz	@f
	inc	edx				; "/x": the root itself
@@:
	mov	byte [rdi+rdx],0
	mov	esi,LL_READS or LL_WRITES
	call	ll_path
	jmp	.dest
.done:
	call	ll_end
.out:
	pop	rbx
	ret

bss
	g_ll_dir	rb ALOG_PATH
end bss
