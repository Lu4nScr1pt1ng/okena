; `okena fmt [-w] FILE`: the file with its layout made canonical: each line
; indented four spaces a level (by the braces that open and close blocks,
; not those inside words, strings or comments), no trailing blanks, at most
; one empty line in a row, none at the start, one newline at the end. What
; is written stays as written, comments too. A file that does not parse is
; not touched (its errors, exit 2). -w writes it back (whole, then renamed
; over it, its mode kept); else it goes to stdout.

cstring str_cmd_fmt, 'fmt',0
cstring str_flag_w, '-w',0

bss
	g_fmt_w		dd ?
	g_fmt_out	dq ?
	g_fmt_len	dq ?
	g_fmt_tmp	rb 4096 + 8
	g_fmt_st	rb STAT_BYTES
end bss

cli_fmt:
	mov	rcx,[g_argc]
	cmp	rcx,3
	jb	cli_usage
	mov	rax,[g_argv]
	mov	rdi,[rax+16]
	lea	rsi,[str_flag_w]
	call	cstr_eq
	mov	ecx,2				; the file's place
	test	eax,eax
	jz	@f
	mov	dword [g_fmt_w],1
	inc	ecx
@@:
	lea	rax,[rcx+1]
	cmp	rax,[g_argc]
	jne	cli_usage
	mov	rax,[g_argv]
	mov	rax,[rax+rcx*8]
	mov	[g_cli_path],rax
	call	cli_load_config			; (exits with its errors when it does not parse)
	; room for the result: twice the source at most (indentation added)
	mov	rsi,[g_src_len]
	lea	rsi,[rsi*2+4096]
	xor	edi,edi
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.fail
	mov	[g_fmt_out],rax
	call	fmt_text
	cmp	dword [g_fmt_w],0
	jne	.write
	mov	edi,1
	mov	rsi,[g_fmt_out]
	mov	rdx,[g_fmt_len]
	call	write_all
	xor	edi,edi
	jmp	exit_process
.write:
	call	fmt_write
	jc	.fail
	xor	edi,edi
	jmp	exit_process
.fail:
	call	log_begin
	out_lit 'fmt: cannot write '
	mov	rsi,[g_cli_path]
	call	out_cstr
	call	log_end
	mov	edi,EXIT_FAILURE
	jmp	exit_process

; g_src_ptr/len -> g_fmt_out/len
fmt_text:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	push	rbp
	mov	rsi,[g_src_ptr]
	mov	r12,rsi
	add	r12,[g_src_len]			; the end
	mov	rdi,[g_fmt_out]
	xor	ebx,ebx				; depth
	xor	ebp,ebp				; empty lines waiting (0, or 1 once a line was out)
	xor	r15d,r15d			; a line has gone out
.line:
	cmp	rsi,r12
	jae	.end
	; the line: rsi .. r13 (its newline excluded)
	mov	r13,rsi
@@:
	cmp	r13,r12
	jae	@f
	cmp	byte [r13],10
	je	@f
	inc	r13
	jmp	@b
@@:
	; trim both ends
	mov	r14,r13
@@:
	cmp	rsi,r14
	jae	@f
	movzx	eax,byte [rsi]
	cmp	al,' '
	je	.lead
	cmp	al,9
	je	.lead
	cmp	al,13
	jne	@f
.lead:
	inc	rsi
	jmp	@b
@@:
	cmp	r14,rsi
	jbe	.empty
	movzx	eax,byte [r14-1]
	cmp	al,' '
	je	.trail
	cmp	al,9
	je	.trail
	cmp	al,13
	jne	.content
.trail:
	dec	r14
	jmp	@b
.empty:
	test	r15d,r15d
	jz	.next_line			; none at the start
	mov	ebp,1				; one, if a line follows
	jmp	.next_line
.content:
	test	ebp,ebp
	jz	@f
	mov	byte [rdi],10
	inc	rdi
	xor	ebp,ebp
@@:
	; its indentation: the depth, less the braces that close at its start
	mov	ecx,ebx
	mov	rdx,rsi
@@:
	cmp	rdx,r14
	jae	@f
	cmp	byte [rdx],'}'
	jne	@f
	dec	ecx
	inc	rdx
.skip_sp:
	cmp	rdx,r14
	jae	@f
	cmp	byte [rdx],' '
	je	.sp
	cmp	byte [rdx],9
	jne	@b
.sp:
	inc	rdx
	jmp	.skip_sp
@@:
	test	ecx,ecx
	jns	@f
	xor	ecx,ecx
@@:
	shl	ecx,2
	mov	al,' '
	rep	stosb
	; the line as written, its braces counted (at a token's start, outside
	; strings and comments)
	mov	edx,1				; at a token's start
.ch:
	cmp	rsi,r14
	jae	.line_done
	movzx	eax,byte [rsi]
	mov	[rdi],al
	inc	rdi
	inc	rsi
	cmp	al,'"'
	je	.string
	cmp	al,' '
	je	.sep
	cmp	al,9
	je	.sep
	cmp	al,';'
	je	.sep
	test	edx,edx
	jz	.in_word
	cmp	al,'#'
	je	.comment
	cmp	al,'{'
	jne	@f
	inc	ebx
	jmp	.sep				; (a brace is a token of its own)
@@:
	cmp	al,'}'
	jne	.word
	dec	ebx
	jmp	.sep
	; inside a word, as the lexer reads it: `{*}` and `{name}` belong to the
	; word (a redirect's placeholders); any other brace is a token of its own
	; (`{respond 200}`: `200` then `}`)
.in_word:
	cmp	al,'}'
	jne	@f
	dec	ebx
	jmp	.sep
@@:
	cmp	al,'{'
	jne	.word
	mov	rcx,rsi				; (rsi is past the '{')
	cmp	rcx,r14
	jae	.brace
	cmp	byte [rcx],'*'
	jne	.ph_name
	inc	rcx
	cmp	rcx,r14
	jae	.brace
	cmp	byte [rcx],'}'
	jne	.brace
	jmp	.ph_copy
.ph_name:
	cmp	rcx,r14
	jae	.brace
	movzx	eax,byte [rcx]
	cmp	al,'}'
	je	.ph_end
	cmp	al,'_'
	je	.ph_ok
	cmp	al,'.'
	je	.ph_ok
	cmp	al,'-'
	je	.ph_ok
	cmp	al,'0'
	jb	.brace
	cmp	al,'9'
	jbe	.ph_ok
	or	al,0x20
	cmp	al,'a'
	jb	.brace
	cmp	al,'z'
	ja	.brace
.ph_ok:
	inc	rcx
	lea	rax,[rsi+33]
	cmp	rcx,rax
	jb	.ph_name
	jmp	.brace
.ph_end:
	cmp	rcx,rsi
	je	.brace				; ("{}": not a name)
.ph_copy:					; rcx at its '}': the placeholder, as written
	inc	rcx
@@:
	cmp	rsi,rcx
	jae	.word
	movsb
	jmp	@b
.brace:
	inc	ebx
	jmp	.sep
.word:
	xor	edx,edx
	jmp	.ch
.sep:
	mov	edx,1
	jmp	.ch
.string:
	cmp	rsi,r14
	jae	.line_done
	movzx	eax,byte [rsi]
	mov	[rdi],al
	inc	rdi
	inc	rsi
	cmp	al,'\'
	jne	@f
	cmp	rsi,r14
	jae	.line_done
	movsb					; (the escaped one)
	jmp	.string
@@:
	cmp	al,'"'
	jne	.string
	xor	edx,edx
	jmp	.ch
.comment:
	mov	rcx,r14				; the rest, as written
	sub	rcx,rsi
	rep	movsb
.line_done:
	mov	byte [rdi],10
	inc	rdi
	mov	r15d,1
	test	ebx,ebx
	jns	.next_line
	xor	ebx,ebx				; (more closed than opened: parsed, so not here)
.next_line:
	mov	rsi,r13
	cmp	rsi,r12
	jae	.end
	inc	rsi				; past its newline
	jmp	.line
.end:
	sub	rdi,[g_fmt_out]
	mov	[g_fmt_len],rdi
	pop	rbp
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; -w: FILE.fmt beside it, its mode, then renamed over it. CF on failure.
fmt_write:
	push	rbx
	mov	edi,AT_FDCWD
	mov	rsi,[g_cli_path]
	mov	edx,O_RDONLY or O_CLOEXEC
	xor	r10d,r10d
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	js	.bad
	mov	ebx,eax
	mov	edi,ebx
	lea	rsi,[g_fmt_st]
	mov	eax,SYS_fstat
	syscall
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
	mov	rsi,[g_cli_path]
	lea	rdi,[g_fmt_tmp]
	xor	ecx,ecx
@@:
	lodsb
	stosb
	inc	ecx
	cmp	ecx,4096
	jae	.bad
	test	al,al
	jnz	@b
	mov	dword [rdi-1],'.fmt'
	mov	byte [rdi+3],0
	mov	edi,AT_FDCWD
	lea	rsi,[g_fmt_tmp]
	mov	edx,O_WRONLY or O_CREAT or O_TRUNC or O_CLOEXEC
	mov	r10d,dword [g_fmt_st+STAT_MODE]
	and	r10d,0xFFF
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	js	.bad
	mov	ebx,eax
	mov	edi,ebx
	mov	rsi,[g_fmt_out]
	mov	rdx,[g_fmt_len]
	call	write_all
	pushf
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
	popf
	jc	.bad
	lea	rdi,[g_fmt_tmp]
	mov	rsi,[g_cli_path]
	mov	eax,SYS_rename_
	syscall
	test	eax,eax
	js	.bad
	clc
	pop	rbx
	ret
.bad:
	stc
	pop	rbx
	ret
