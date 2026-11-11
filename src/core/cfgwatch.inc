; `okena { reload on-change }`: the supervisor looks at the configuration's
; files once a second (on its tick: no inotify to set up or to overflow): the
; file, every file it included, and their directories (a file added to a
; glob's directory changes that directory). A change seen twice in a row (its
; writer done) reloads, as SIGHUP does; whatever came of the reload, the files
; as they are then are the new reference, so a broken file is tried once.

CW_PATH		:= 512

bss
	g_plan_reload_watch dd ?
	g_cw_n		dd ?		; files known
	align 8
	g_cw_sig	dq ?		; their signature, as last loaded
	g_cw_seen	dq ?		; a different one seen at the last tick, 0 none
	g_cw_paths	rb (CFG_FILES + CFG_DIRS) * CW_PATH
	g_cw_st		rb STAT_BYTES
	g_cw_dir	rb CW_PATH
end bss

; After a start or a reload (either way): the files as the configuration knows
; them, and their signature now.
cw_snapshot:
	cmp	dword [g_plan_reload_watch],0
	je	.out
	cmp	qword [g_cli_text],0
	jne	.out
	push	rbx
	xor	ebx,ebx
.file:
	cmp	ebx,[g_cfg_nfiles]
	jae	.copied
	cmp	ebx,CFG_FILES
	jae	.copied
	imul	eax,ebx,24
	mov	rsi,[g_cfg_files+rax+16]	; its name
	test	ebx,ebx
	jnz	@f
	mov	rsi,[g_cli_path]		; (the first: as given, not a copy's)
@@:
	imul	edi,ebx,CW_PATH
	lea	rdi,[g_cw_paths+rdi]
	mov	ecx,CW_PATH - 1
@@:
	lodsb
	stosb
	test	al,al
	jz	@f
	dec	ecx
	jnz	@b
	mov	byte [rdi],0
@@:
	inc	ebx
	jmp	.file
.copied:
	xor	ecx,ecx				; then the directories globs looked in
.dirs:
	cmp	ecx,[g_cfg_ndirs]
	jae	.dirs_done
	mov	rsi,[g_cfg_dirs+rcx*8]
	imul	edi,ebx,CW_PATH
	lea	rdi,[g_cw_paths+rdi]
	mov	edx,CW_PATH - 1
@@:
	lodsb
	stosb
	test	al,al
	jz	@f
	dec	edx
	jnz	@b
	mov	byte [rdi],0
@@:
	inc	ebx
	inc	ecx
	jmp	.dirs
.dirs_done:
	mov	[g_cw_n],ebx
	pop	rbx
	call	cw_signature
	mov	[g_cw_sig],rax
	mov	qword [g_cw_seen],0
.out:
	ret

; rax = the signature of the files and their directories now
cw_signature:
	push	rbx
	push	r12
	xor	r12d,r12d			; the signature
	xor	ebx,ebx
.file:
	cmp	ebx,[g_cw_n]
	jae	.done
	imul	esi,ebx,CW_PATH
	lea	rsi,[g_cw_paths+rsi]
	push	rsi
	xor	edx,edx
	call	.stat
	pop	rsi
	; its directory: up to its last /
	lea	rdi,[g_cw_dir]
	xor	ecx,ecx				; where the last / is
	xor	edx,edx
@@:
	mov	al,[rsi+rdx]
	mov	[rdi+rdx],al
	test	al,al
	jz	@f
	inc	edx
	cmp	al,'/'
	jne	@b
	mov	ecx,edx
	jmp	@b
@@:
	test	ecx,ecx
	jnz	@f
	mov	word [rdi],'.'			; (".", NUL)
	jmp	.dir
@@:
	mov	byte [rdi+rcx],0
.dir:
	lea	rsi,[g_cw_dir]
	mov	edx,O_DIRECTORY_
	call	.stat
	inc	ebx
	jmp	.file
.done:
	mov	rax,r12
	pop	r12
	pop	rbx
	ret
; rsi = a path, edx = more open flags: folded into r12 (a path that cannot be
; opened folds as such)
.stat:
	mov	edi,AT_FDCWD
	or	edx,O_RDONLY or O_CLOEXEC
	xor	r10d,r10d
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	js	.gone
	push	rax
	mov	edi,eax
	lea	rsi,[g_cw_st]
	mov	eax,SYS_fstat
	syscall
	pop	rdi
	mov	eax,SYS_close
	syscall
	lea	rsi,[g_cw_st]
	mov	ecx,8				; inode
	call	.fold
	lea	rsi,[g_cw_st+STAT_SIZE]
	call	.fold
	lea	rsi,[g_cw_st+88]		; st_mtim: seconds, then nanoseconds
	call	.fold
	lea	rsi,[g_cw_st+96]
	call	.fold
	ret
.gone:
	mov	rax,0x9E3779B97F4A7C15
	xor	r12,rax
	imul	r12,r12,31
	ret
.fold:
	mov	rax,[rsi]
	xor	r12,rax
	mov	rax,0x100000001B3
	imul	r12,rax
	rol	r12,13
	ret

; Supervisor tick: eax = 1 when the configuration should be reloaded now.
cw_tick:
	xor	eax,eax
	cmp	dword [g_plan_reload_watch],0
	je	.out
	cmp	dword [g_cw_n],0
	je	.out
	call	cw_signature
	cmp	rax,[g_cw_sig]
	je	.same
	cmp	rax,[g_cw_seen]
	mov	[g_cw_seen],rax
	jne	.wait				; changed since the last tick: let it settle
	call	log_begin
	out_lit 'the configuration changed (reload on-change): reloading'
	call	log_end
	mov	eax,1
	ret
.same:
	mov	qword [g_cw_seen],0
.wait:
	xor	eax,eax
.out:
	ret
