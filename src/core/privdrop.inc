; `okena { user NAME[:GROUP] }`: the processes that face the network, or
; parse what it sends (workers, health checks, the control process and JWKS,
; the admin process, the logger), run as that user and group, with no
; capability left: the kernel clears them as a uid of 0 becomes another.
; The supervisor stays as it was started, as nginx's master does: a reload
; reads private keys only root may read and binds ports below 1024, and the
; reload's compiler (which reads them) is boxed in by seccomp and Landlock
; to read and nothing else. A name is looked up in /etc/passwd and
; /etc/group (an image with none takes numbers: `user 65532:65532`); with no
; group, the user's own. okena not started as root may only name itself.

SYS_setresuid	:= 117
SYS_setresgid	:= 119
SYS_setgroups	:= 116
SYS_geteuid_	:= 107

bss
	align 4
	g_plan_user	dd ?		; 1 when `user` is set
	g_plan_uid	dd ?
	g_plan_gid	dd ?
	g_pd_buf	rb 64
end bss

cstring str_etc_passwd, '/etc/passwd',0
cstring str_etc_group, '/etc/group',0

; rdi = the `user` node
compile_user:
	push	rbx
	push	r12
	push	r13
	mov	rax,[rdi+N_ARGS]
	mov	r12,[rax+A_VAL]
	mov	r13d,[rax+A_VLEN]
	; NAME or UID, then :GROUP or :GID
	xor	ebx,ebx
@@:
	cmp	ebx,r13d
	jae	@f
	cmp	byte [r12+rbx],':'
	je	@f
	inc	ebx
	jmp	@b
@@:
	test	ebx,ebx
	jz	.bad
	mov	rdi,r12
	mov	esi,ebx
	lea	rdx,[str_etc_passwd]
	call	pd_lookup			; eax = uid, edx = its group
	jc	.no_user
	mov	[g_plan_uid],eax
	mov	[g_plan_gid],edx
	cmp	ebx,r13d
	jae	.done
	; its group, named
	lea	rdi,[r12+rbx+1]
	mov	esi,r13d
	sub	esi,ebx
	dec	esi
	jz	.bad
	lea	rdx,[str_etc_group]
	call	pd_lookup
	jc	.no_group
	mov	[g_plan_gid],eax
.done:
	mov	dword [g_plan_user],1
	pop	r13
	pop	r12
	pop	rbx
	ret
.bad:
	call	log_begin
	out_lit 'user takes NAME, NAME:GROUP, UID or UID:GID'
	jmp	.fail
.no_user:
	call	log_begin
	out_lit 'user: no such user in /etc/passwd (a number is taken as it is)'
	jmp	.fail
.no_group:
	call	log_begin
	out_lit 'user: no such group in /etc/group (a number is taken as it is)'
.fail:
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; rdi/esi = a name or a number, rdx = /etc/passwd or /etc/group: eax = its
; id, edx = (passwd) its group. A number is its own (its group the same
; number, unless said). CF when the name is not there.
pd_lookup:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rdi
	mov	r13d,esi
	mov	rbx,rdx				; the file
	; a number?
	xor	eax,eax
	xor	ecx,ecx
.digit:
	cmp	ecx,r13d
	jae	.number
	movzx	edx,byte [r12+rcx]
	sub	edx,'0'
	cmp	edx,9
	ja	.name
	imul	eax,eax,10
	add	eax,edx
	inc	ecx
	cmp	ecx,10
	jbe	.digit
	jmp	.name
.number:
	mov	edx,eax
	clc
	jmp	.out
.name:
	mov	rdi,rbx
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	.none
	mov	r14,rax				; the text
	lea	r15,[rax+rdx]			; its end
.line:
	cmp	r14,r15
	jae	.none
	; "name:x:id:gid:..."
	mov	rdi,r14
	xor	ecx,ecx
@@:
	cmp	ecx,r13d
	jae	@f
	lea	rax,[rdi+rcx]
	cmp	rax,r15
	jae	.next
	mov	al,[rdi+rcx]
	cmp	al,[r12+rcx]
	jne	.next
	inc	ecx
	jmp	@b
@@:
	cmp	byte [rdi+rcx],':'
	jne	.next
	; past the name and the password: the id, then the group
	lea	rsi,[rdi+rcx+1]
	call	.field				; (the password)
	call	.number_at
	mov	ebx,eax
	call	.number_at
	mov	edx,eax
	mov	eax,ebx
	clc
	jmp	.out
.next:
	cmp	r14,r15
	jae	.none
	cmp	byte [r14],10
	je	@f
	inc	r14
	jmp	.next
@@:
	inc	r14
	jmp	.line
.none:
	stc
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
; rsi = a field: rsi = past its ':'
.field:
	cmp	rsi,r15
	jae	@f
	lodsb
	cmp	al,':'
	jne	.field
@@:
	ret
; rsi = a number field: eax = it, rsi = past its ':'
.number_at:
	xor	eax,eax
@@:
	cmp	rsi,r15
	jae	@f
	movzx	ecx,byte [rsi]
	inc	rsi
	sub	ecx,'0'
	cmp	ecx,9
	ja	@f
	imul	eax,eax,10
	add	eax,ecx
	jmp	@b
@@:
	ret

; The supervisor, starting: okena not run as root may only be itself
pd_check:
	cmp	dword [g_plan_user],0
	je	.fine
	mov	eax,SYS_geteuid_
	syscall
	test	eax,eax
	jz	.root
	cmp	eax,[g_plan_uid]
	je	.fine
	call	log_begin
	out_lit 'user: okena is not root here, so it cannot become uid '
	mov	eax,[g_plan_uid]
	call	out_u64
	out_lit ' (start it as root, or as that user)'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
.root:
	call	log_begin
	out_lit 'the processes facing the network run as uid '
	mov	eax,[g_plan_uid]
	call	out_u64
	out_lit ', gid '
	mov	eax,[g_plan_gid]
	call	out_u64
	out_lit ', with no capability'
	call	log_end
.fine:
	ret

; A child, set up, before its filters: the user and group of `user`, no
; supplementary group, no capability. One that cannot must not go on
; privileged: it exits (and the supervisor says why).
priv_drop:
	cmp	dword [g_plan_user],0
	je	.done
	mov	eax,SYS_geteuid_
	syscall
	test	eax,eax
	jnz	.done				; (not root: it is that user already, pd_check)
	lea	rsi,[g_plan_gid]
	mov	edi,1
	mov	eax,SYS_setgroups
	syscall
	test	eax,eax
	js	.failed
	mov	edi,[g_plan_gid]
	mov	esi,edi
	mov	edx,edi
	mov	eax,SYS_setresgid
	syscall
	test	eax,eax
	js	.failed
	mov	edi,[g_plan_uid]
	mov	esi,edi
	mov	edx,edi
	mov	eax,SYS_setresuid
	syscall
	test	eax,eax
	js	.failed
	; a change of credentials clears the parent-death signal: again, and
	; the parent looked at once more (it may have gone in between)
	mov	edi,PR_SET_PDEATHSIG
	mov	esi,SIGKILL
	mov	eax,SYS_prctl
	syscall
	mov	eax,SYS_getppid
	syscall
	cmp	eax,[g_sup_pid]
	je	.done
	xor	edi,edi
	jmp	exit_process
.done:
	ret
.failed:
	neg	eax
	push	rax
	call	log_begin
	out_lit 'user: cannot become uid '
	mov	eax,[g_plan_uid]
	call	out_u64
	out_lit ' (errno '
	pop	rax
	call	out_u64
	out_lit '): this process stops rather than run as root'
	call	log_end
	mov	edi,EXIT_FATAL
	jmp	exit_process
