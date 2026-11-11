; `okena { last_good on }`: the configuration as it last started or reloaded,
; kept beside the file as FILE.good (its includes written into it, so that it
; stands alone), and started from when FILE is not valid at startup. A reload
; that fails keeps the running one in any case.
;
; The copy is made while parsing: the text of each file goes out as it is,
; an `include` line replaced by the files it names (cfg_flat_*, called from
; parse.inc). Written only after a start or a reload went through.

LG_FLAT_CAP	:= 64 shl 20		; (the largest configuration read)

bss
	align 8
	g_flat		dq ?		; the copy, as parsed
	g_flat_len	dq ?
	g_flat_from	dq ?		; the current file's text not yet copied
	g_flat_bad	dd ?		; it did not fit: nothing saved
	g_plan_last_good dd ?
	g_lg_orig	dq ?		; the file given, when started from its copy
	g_lg_path	rb 4096 + 8
	g_lg_tmp	rb 4096 + 16
end bss

; rdi = where the main file's text starts
cfg_flat_begin:
	mov	[g_flat_from],rdi
	mov	qword [g_flat_len],0
	mov	dword [g_flat_bad],0
	cmp	qword [g_flat],0
	jne	.out
	push	rdi
	xor	edi,edi
	mov	esi,LG_FLAT_CAP
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	pop	rdi
	cmp	rax,-4096
	jbe	@f
	xor	eax,eax
	mov	dword [g_flat_bad],1
@@:
	mov	[g_flat],rax
.out:
	ret

; rdi = up to where the current file's text goes out (from g_flat_from)
cfg_flat_to:
	mov	rsi,[g_flat_from]
	mov	[g_flat_from],rdi
	mov	rcx,rdi
	sub	rcx,rsi
	jbe	.out
	cmp	qword [g_flat],0
	je	.bad
	mov	rax,[g_flat_len]
	lea	rdx,[rax+rcx+1]
	cmp	rdx,LG_FLAT_CAP
	ja	.bad
	mov	rdi,[g_flat]
	add	rdi,rax
	add	[g_flat_len],rcx
	rep	movsb
.out:
	ret
.bad:
	mov	dword [g_flat_bad],1
	ret

; a line's end, after an included file
cfg_flat_nl:
	cmp	qword [g_flat],0
	je	.out
	mov	rax,[g_flat_len]
	cmp	rax,LG_FLAT_CAP - 1
	jae	.out
	mov	rdx,[g_flat]
	mov	byte [rdx+rax],10
	inc	qword [g_flat_len]
.out:
	ret

; g_lg_path = FILE.good, for g_cli_path
lg_path:
	mov	rsi,[g_cli_path]
	lea	rdi,[g_lg_path]
	xor	ecx,ecx
@@:
	lodsb
	stosb
	inc	ecx
	cmp	ecx,4096
	jae	.long
	test	al,al
	jnz	@b
	mov	dword [rdi-1],'.goo'
	mov	word [rdi+3],'d'
	ret
.long:
	mov	byte [g_lg_path],0
	ret

; After a start or a reload that went through: FILE.good, when wanted.
lg_save:
	cmp	dword [g_plan_last_good],0
	je	.out
	cmp	qword [g_cli_text],0
	jne	.out				; (a configuration given inline)
	cmp	dword [g_flat_bad],0
	jne	.out
	push	rbx
	call	lg_path
	cmp	byte [g_lg_path],0
	je	.done
	lea	rsi,[g_lg_path]
	lea	rdi,[g_lg_tmp]
@@:
	lodsb
	stosb
	test	al,al
	jnz	@b
	mov	dword [rdi-1],'.new'
	mov	byte [rdi+3],0
	mov	edi,AT_FDCWD
	lea	rsi,[g_lg_tmp]
	mov	edx,O_WRONLY or O_CREAT or O_APPEND or O_CLOEXEC
	mov	r10d,0x180			; 0600: it may hold what the file holds
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	js	.failed
	mov	ebx,eax
	mov	edi,ebx
	xor	esi,esi
	mov	eax,SYS_ftruncate
	syscall
	mov	edi,ebx
	mov	rsi,[g_flat]
	mov	rdx,[g_flat_len]
	call	write_all
	jc	.close_failed
	mov	edi,ebx
	mov	eax,SYS_fdatasync
	syscall
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
	lea	rdi,[g_lg_tmp]
	lea	rsi,[g_lg_path]
	mov	eax,SYS_rename_
	syscall
	test	eax,eax
	jns	.done
	jmp	.failed
.close_failed:
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
.failed:
	call	log_begin
	out_lit 'last_good: cannot write '
	lea	rsi,[g_lg_path]
	call	out_cstr
	call	log_end
.done:
	pop	rbx
.out:
	ret

; Startup, before the file is loaded: when FILE.good is there and FILE does
; not compile (tried in a child, whose errors show), start from the copy.
lg_pick:
	cmp	qword [g_cli_text],0
	jne	.out
	call	lg_path
	cmp	byte [g_lg_path],0
	je	.out
	mov	edi,AT_FDCWD
	lea	rsi,[g_lg_path]
	mov	edx,O_RDONLY or O_CLOEXEC
	xor	r10d,r10d
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	js	.out				; no copy: as always
	mov	edi,eax
	mov	eax,SYS_close
	syscall
	mov	eax,SYS_fork
	syscall
	test	rax,rax
	jz	.child
	js	.out
	push	rbx
	sub	rsp,SIGINFO_SIZE
	mov	ebx,eax
.wait:
	mov	rdi,rsp
	xor	eax,eax
	mov	ecx,SIGINFO_SIZE/8
	rep	stosq
	mov	edi,1				; P_PID
	mov	esi,ebx
	mov	rdx,rsp
	mov	r10d,WEXITED
	xor	r8d,r8d
	mov	eax,SYS_waitid
	syscall
	cmp	rax,-EINTR
	je	.wait
	mov	ecx,[rsp+SI_CODE]
	mov	edx,[rsp+SI_STATUS]
	add	rsp,SIGINFO_SIZE
	pop	rbx
	cmp	ecx,CLD_EXITED
	jne	.fallback
	test	edx,edx
	jz	.out				; FILE is good
.fallback:
	mov	rax,[g_cli_path]
	mov	[g_lg_orig],rax
	lea	rax,[g_lg_path]
	mov	[g_cli_path],rax
	call	log_begin
	out_lit 'last_good: '
	mov	rsi,[g_lg_orig]
	call	out_cstr
	out_lit ' is not valid (above); starting on the last good configuration, '
	lea	rsi,[g_lg_path]
	call	out_cstr
	call	log_end
.out:
	ret
.child:
	call	cli_load_config			; (its errors show, as `okena check` says them)
	call	plan_compile
	xor	edi,edi
	jmp	exit_process

; After loading the copy: reloads read FILE again, so that a fix goes in
lg_loaded:
	mov	rax,[g_lg_orig]
	test	rax,rax
	jz	.out
	mov	[g_cli_path],rax
	mov	qword [g_lg_orig],0
.out:
	ret
