; `routes FILE` in an http listener or a host block: routes kept in FILE,
; changed at runtime with `okena routes`, without editing the configuration.
; FILE need not be there; its routes are read right after the line, as an
; include would (parse.inc: cfg_routes_files), at the start and on every
; reload. Its name for `okena routes` is its last part, less `.conf`.
;
;   okena routes                       the names and their files
;   okena routes NAME                  what NAME holds
;   okena routes NAME put 'ROUTE'      ROUTE in (it replaces the route of the
;                                      same head: what comes before its `{`)
;   okena routes NAME delete 'HEAD'    the route of that head out
;
; The command does it all, as the user who runs it: under a lock it writes
; FILE anew (a temporary file renamed over it), compiles the whole
; configuration in a child (its errors printed as `okena check` prints them),
; and reloads the running okena through the admin socket, as `okena reload`
; does. When the configuration does not take it, or the reload does not, FILE
; is put back as it was. The admin process has no part in it but the reload
; it is asked for: nothing it says can change what okena serves.
;
; okena keeps FILE a route a line; one written by hand is read all the same,
; but routes split over lines are not changed by these commands.

RF_NLEN		:= 0			; d
RF_PLEN		:= 4			; d
RF_NAME		:= 8			; its name (60 at most)
RF_PATH		:= 72			; NUL-ended
RF_SIZE		:= 512
RF_PATH_MAX	:= RF_SIZE - RF_PATH - 8	; (room for .tmp, .lock)
MAX_RF		:= 64
RT_CAP		:= 4 shl 20		; a routes file's most
SYS_fsync_	:= 74

bss
	align 8
	g_plan_rf	dd ?
	g_rfiles	rb RF_SIZE * MAX_RF
	g_rt_old	dq ?			; FILE as it was
	g_rt_oldlen	dq ?
	g_rt_had	dd ?			; it was there
	g_rt_new	dq ?
	g_rt_newlen	dq ?
	g_rt_head	rb 4096			; the head looked for
	g_rt_hlen	dd ?
	g_rt_lh		rb 4096			; a line's
	g_rt_path	rb RF_SIZE
	g_rt_tmp	rb RF_SIZE
end bss

; rdi = an http listener's node: its `routes FILE` and its hosts', in the plan
compile_routes_files:
	push	rbx
	push	r12
	mov	rbx,rdi
	call	.one
	mov	r12,[rbx+N_CHILD]
.host:
	test	r12,r12
	jz	.out
	lea	rax,[dir_table + D_SIZE*DIR_HOST]
	cmp	[r12+N_DEF],rax
	jne	@f
	mov	rdi,r12
	call	.one
@@:
	mov	r12,[r12+N_NEXT]
	jmp	.host
.out:
	pop	r12
	pop	rbx
	ret
; rdi = a block
.one:
	mov	ecx,DIR_ROUTES
	call	find_child
	test	rax,rax
	jz	.none
	mov	rax,[rax+N_ARGS]
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,2
	jb	plan_bad_routes
	cmp	byte [rsi],'/'
	jne	plan_bad_routes
	cmp	ecx,RF_PATH_MAX
	jae	plan_bad_routes
	cmp	dword [g_plan_rf],MAX_RF
	jae	plan_bad_routes
	; its name: the last part, less .conf
	lea	r8,[rsi+rcx]			; the end
	mov	r9,r8
@@:
	cmp	byte [r9-1],'/'
	je	@f
	dec	r9
	jmp	@b
@@:
	mov	r10,r8
	sub	r10,r9				; its length
	cmp	r10,5
	jbe	@f
	cmp	dword [r8-5],'.con'
	jne	@f
	cmp	byte [r8-1],'f'
	jne	@f
	sub	r10,5
@@:
	test	r10,r10
	jz	plan_bad_routes
	cmp	r10,60
	ja	plan_bad_routes
	; one of that name already?
	xor	edx,edx
.same:
	cmp	edx,[g_plan_rf]
	jae	.new
	imul	rax,rdx,RF_SIZE
	lea	rax,[g_rfiles+rax]
	inc	edx
	cmp	[rax+RF_NLEN],r10d
	jne	.same
	push	rsi
	push	rcx
	lea	rdi,[rax+RF_NAME]
	mov	rsi,r9
	mov	rcx,r10
	repe	cmpsb
	pop	rcx
	pop	rsi
	je	plan_bad_routes_twice
	jmp	.same
.new:
	imul	rdi,rdx,RF_SIZE
	lea	rdi,[g_rfiles+rdi]
	inc	dword [g_plan_rf]
	mov	[rdi+RF_NLEN],r10d
	mov	[rdi+RF_PLEN],ecx
	push	rdi
	push	rsi
	push	rcx
	lea	rdi,[rdi+RF_NAME]
	mov	rsi,r9
	mov	rcx,r10
	rep	movsb
	pop	rcx
	pop	rsi
	pop	rdi
	lea	rdi,[rdi+RF_PATH]
	rep	movsb
	mov	byte [rdi],0
.none:
	ret

plan_bad_routes:
	call	log_begin
	out_lit '`routes` takes an absolute path to a file of routes (its name, for `okena routes`: its last part less .conf, 60 bytes at most; 64 such files at most)'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

plan_bad_routes_twice:
	call	log_begin
	out_lit 'two `routes` files have the same name (their last part, less .conf): `okena routes` would not know one from the other'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; `okena routes [NAME [put ROUTE | delete HEAD]] [-c FILE]`
cli_routes:
	mov	rcx,[g_argc]
	mov	r13d,2				; the words of its own: 2, 3 or 5
	cmp	rcx,3
	jb	.counted
	mov	rax,[g_argv]
	mov	rdi,[rax+16]
	lea	rsi,[str_flag_c]
	call	cstr_eq
	test	eax,eax
	jnz	.counted
	mov	r13d,3
	cmp	qword [g_argc],4
	jb	.counted
	mov	rax,[g_argv]
	mov	rdi,[rax+24]
	lea	rsi,[str_flag_c]
	call	cstr_eq
	test	eax,eax
	jnz	.counted
	mov	r13d,5
	cmp	qword [g_argc],5
	jb	cli_usage
.counted:
	mov	edi,r13d
	call	cli_source_from_args
	call	cli_load_config
	call	plan_compile
	call	rt_buffers
	cmp	r13d,2
	je	.list
	; NAME
	mov	rax,[g_argv]
	mov	rsi,[rax+16]
	call	rt_find				; rbx = its entry
	jc	.no_name
	lea	rdi,[rbx+RF_PATH]
	call	rt_read
	cmp	r13d,3
	je	.show
	mov	rax,[g_argv]
	mov	rdi,[rax+24]
	cstring str_rt_put, 'put',0
	lea	rsi,[str_rt_put]
	call	cstr_eq
	test	eax,eax
	jnz	.put
	mov	rax,[g_argv]
	mov	rdi,[rax+24]
	cstring str_rt_delete, 'delete',0
	lea	rsi,[str_rt_delete]
	call	cstr_eq
	test	eax,eax
	jz	cli_usage
	; delete HEAD
	mov	rax,[g_argv]
	mov	rsi,[rax+32]
	call	cstr_len
	lea	rdi,[g_rt_head]
	call	rt_head
	call	rt_route_head			; (`route ` before it when it lacks one)
	call	rt_lock
	lea	rdi,[rbx+RF_PATH]		; (as it is under the lock)
	call	rt_read
	xor	edx,edx				; (no text: the lines of that head go)
	xor	ecx,ecx
	call	rt_rebuild
	test	eax,eax
	jz	.not_there
	jmp	.change
.put:
	mov	rax,[g_argv]
	mov	rsi,[rax+32]
	call	cstr_len
	mov	r14,rsi
	mov	r15d,ecx
	call	rt_valid
	jc	.not_a_route
	mov	rsi,r14
	mov	ecx,r15d
	lea	rdi,[g_rt_head]
	call	rt_head
	call	rt_lock
	lea	rdi,[rbx+RF_PATH]
	call	rt_read
	mov	rdx,r14
	mov	ecx,r15d
	call	rt_rebuild
.change:
	lea	rdi,[rbx+RF_PATH]
	mov	rsi,[g_rt_new]
	mov	rdx,[g_rt_newlen]
	call	rt_write
	jc	.io
	; the whole configuration, with it: compiled in a child
	call	rt_compiles
	jc	.refused
	; the running okena
	cmp	qword [g_plan_api],0
	je	.saved
	call	rt_admin_buf
	call	cli_reload_wait			; CF: it did not take
	jc	.reload_failed
	mov	edi,1
	call	out_select
	out_lit 'ok: reloaded',10
	call	out_flush
	xor	edi,edi
	jmp	exit_process
.saved:
	mov	edi,1
	call	out_select
	out_lit 'ok: saved (no `admin` path to reload by: the next reload takes it)',10
	call	out_flush
	xor	edi,edi
	jmp	exit_process
.reload_failed:
	call	rt_restore
	call	log_begin
	out_lit 'the reload did not take: the routes are as they were, and okena',27h,'s log says why'
	call	log_end
	mov	edi,1
	jmp	exit_process
.refused:
	call	rt_restore
	call	log_begin
	out_lit 'the configuration does not take it (above): the routes are as they were'
	call	log_end
	mov	edi,1
	jmp	exit_process
.io:
	call	log_begin
	out_lit 'cannot write '
	lea	rsi,[rbx+RF_PATH]
	call	out_cstr
	call	log_end
	mov	edi,1
	jmp	exit_process
.not_a_route:
	call	log_begin
	out_lit 'put takes one route on one line: route PATH... { ... }'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
.not_there:
	call	log_begin
	out_lit 'no route of that head there'
	call	log_end
	mov	edi,1
	jmp	exit_process
.no_name:
	call	log_begin
	out_lit 'no `routes` file of that name in the configuration (`okena routes` lists them)'
	call	log_end
	mov	edi,1
	jmp	exit_process
.show:
	mov	rsi,[g_rt_old]
	mov	rdx,[g_rt_oldlen]
	mov	edi,1
	call	write_all
	xor	edi,edi
	jmp	exit_process
.list:
	cmp	dword [g_plan_rf],0
	jne	@f
	call	log_begin
	out_lit 'no `routes FILE` in this configuration: add one to an http listener or a host block, and okena routes NAME put ... can change it'
	call	log_end
	mov	edi,1
	jmp	exit_process
@@:
	mov	edi,1
	call	out_select
	xor	r12d,r12d
.entry:
	cmp	r12d,[g_plan_rf]
	jae	.listed
	imul	rbx,r12,RF_SIZE
	lea	rbx,[g_rfiles+rbx]
	lea	rsi,[rbx+RF_NAME]
	mov	edx,[rbx+RF_NLEN]
	call	out_str
	out_lit 9
	lea	rsi,[rbx+RF_PATH]
	call	out_cstr
	out_lit 10
	inc	r12d
	jmp	.entry
.listed:
	call	out_flush
	xor	edi,edi
	jmp	exit_process

; rsi = a NUL-ended string: ecx = its length
cstr_len:
	xor	ecx,ecx
@@:
	cmp	byte [rsi+rcx],0
	je	@f
	inc	ecx
	jmp	@b
@@:
	ret

; the buffers, once
rt_buffers:
	xor	edi,edi
	mov	esi,RT_CAP * 2 + 8192
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	mov	[g_rt_old],rax
	add	rax,RT_CAP
	mov	[g_rt_new],rax
	ret

; rsi = a NUL-ended name: rbx = its entry; CF none
rt_find:
	call	cstr_len
	xor	edx,edx
.e:
	cmp	edx,[g_plan_rf]
	jae	.no
	imul	rbx,rdx,RF_SIZE
	lea	rbx,[g_rfiles+rbx]
	inc	edx
	cmp	[rbx+RF_NLEN],ecx
	jne	.e
	push	rsi
	push	rcx
	lea	rdi,[rbx+RF_NAME]
	repe	cmpsb
	pop	rcx
	pop	rsi
	jne	.e
	clc
	ret
.no:
	stc
	ret

; rdi = a path: g_rt_old/len what it holds (none: nothing, g_rt_had 0)
rt_read:
	mov	qword [g_rt_oldlen],0
	mov	dword [g_rt_had],0
	mov	rsi,rdi
	mov	edi,AT_FDCWD
	mov	edx,O_RDONLY or O_CLOEXEC
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	js	.out
	mov	dword [g_rt_had],1
	push	rbx
	mov	ebx,eax
.more:
	mov	edi,ebx
	mov	rsi,[g_rt_old]
	add	rsi,[g_rt_oldlen]
	mov	edx,RT_CAP - 4096
	sub	rdx,[g_rt_oldlen]
	jle	.done
	xor	eax,eax
	syscall
	test	rax,rax
	jle	.done
	add	[g_rt_oldlen],rax
	jmp	.more
.done:
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
	pop	rbx
.out:
	ret

; rbx = an entry: FILE.lock taken (held until the command ends)
rt_lock:
	lea	rdi,[g_rt_path]
	lea	rsi,[rbx+RF_PATH]
	mov	ecx,[rbx+RF_PLEN]
	rep	movsb
	mov	dword [rdi],'.loc'
	mov	word [rdi+4],'k'
	mov	edi,AT_FDCWD
	lea	rsi,[g_rt_path]
	mov	edx,O_RDWR or O_CREAT or O_CLOEXEC
	mov	r10d,384			; 0600
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	js	.out				; (no lock to be had: on without it)
	mov	edi,eax
	mov	esi,LOCK_EX
	mov	eax,SYS_flock
	syscall
.out:
	ret

; rdi = a path, rsi/rdx = what it is to hold: written beside it, then renamed
; over it (a reader sees the old or the new, whole). CF when it cannot be.
rt_write:
	push	rbx
	push	r12
	push	r13
	mov	r12,rsi
	mov	r13,rdx
	mov	rsi,rdi				; the path, and PATH.tmp
	lea	rdi,[g_rt_path]
	lea	rdx,[g_rt_tmp]
@@:
	lodsb
	mov	[rdi],al
	mov	[rdx],al
	inc	rdi
	inc	rdx
	test	al,al
	jnz	@b
	mov	dword [rdx-1],'.tmp'
	mov	byte [rdx+3],0
	mov	edi,AT_FDCWD
	lea	rsi,[g_rt_tmp]
	mov	edx,O_WRONLY or O_CREAT or O_TRUNC or O_CLOEXEC
	mov	r10d,420			; 0644
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	js	.bad
	mov	ebx,eax
	mov	edi,ebx
	mov	rsi,r12
	mov	rdx,r13
	call	write_all
	mov	edi,ebx
	mov	eax,SYS_fsync_
	syscall
	push	rax
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
	pop	rax
	test	eax,eax
	js	.bad
	lea	rdi,[g_rt_tmp]
	lea	rsi,[g_rt_path]
	mov	eax,SYS_rename_
	syscall
	test	eax,eax
	js	.bad
	clc
	jmp	.out
.bad:
	stc
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; rbx = an entry: FILE as it was (gone, when it was not there)
rt_restore:
	cmp	dword [g_rt_had],0
	je	.gone
	lea	rdi,[rbx+RF_PATH]
	mov	rsi,[g_rt_old]
	mov	rdx,[g_rt_oldlen]
	jmp	rt_write
.gone:
	lea	rdi,[rbx+RF_PATH]
	mov	eax,SYS_unlink_
	syscall
	ret

; r14/r15d = put's text: CF when it is not one route on one line
rt_valid:
	mov	rsi,r14
	mov	ecx,r15d
	; no line ends
	xor	eax,eax
@@:
	cmp	eax,ecx
	jae	@f
	cmp	byte [rsi+rax],10
	je	.no
	cmp	byte [rsi+rax],13
	je	.no
	inc	eax
	jmp	@b
@@:
	; `route ` first, `}` last, a `{` between
@@:
	test	ecx,ecx
	jz	.no
	cmp	byte [rsi],' '
	ja	@f
	inc	rsi
	dec	ecx
	jmp	@b
@@:
	cmp	ecx,8
	jb	.no
	cmp	dword [rsi],'rout'
	jne	.no
	cmp	byte [rsi+4],'e'
	jne	.no
	cmp	byte [rsi+5],' '
	ja	.no
@@:
	cmp	byte [rsi+rcx-1],' '
	ja	@f
	dec	ecx
	jz	.no
	jmp	@b
@@:
	cmp	byte [rsi+rcx-1],'}'
	jne	.no
	mov	rdi,rsi
	mov	al,'{'
	repne	scasb
	jne	.no
	clc
	ret
.no:
	stc
	ret

; rsi/ecx = text, rdi = room (4096): its head there, what comes before its `{`
; with runs of spaces as one and none at either end; eax = its length.
; Keeps rbx, rdx, r12-r15.
rt_head:
	push	rdi
	mov	r8,rdi
	xor	r9d,r9d				; a space waits
.c:
	test	ecx,ecx
	jz	.end
	mov	al,[rsi]
	inc	rsi
	dec	ecx
	cmp	al,'{'
	je	.end
	cmp	al,' '
	jbe	.space
	test	r9d,r9d
	jz	@f
	cmp	rdi,r8
	je	@f
	mov	byte [rdi],' '
	inc	rdi
@@:
	xor	r9d,r9d
	mov	[rdi],al
	inc	rdi
	mov	rax,rdi
	sub	rax,r8
	cmp	eax,4000
	jae	.end
	jmp	.c
.space:
	mov	r9d,1
	jmp	.c
.end:
	mov	rax,rdi
	sub	rax,r8
	pop	rdi
	mov	[g_rt_hlen],eax
	ret

; g_rt_head: `route ` before it, when it does not start so (delete's HEAD may
; be the paths alone)
rt_route_head:
	mov	eax,[g_rt_hlen]
	cmp	eax,6
	jb	.add
	cmp	dword [g_rt_head],'rout'
	jne	.add
	cmp	word [g_rt_head+4],'e '
	je	.out
.add:
	cmp	eax,4000
	jae	.out
	lea	rsi,[g_rt_head+rax-1]
	lea	rdi,[g_rt_head+rax+5]
	mov	ecx,eax
	std
	rep	movsb
	cld
	mov	dword [g_rt_head],'rout'
	mov	word [g_rt_head+4],'e '
	add	dword [g_rt_hlen],6
.out:
	ret

; g_rt_old's lines into g_rt_new: those of g_rt_head's head out, rdx/ecx (a
; route; rdx 0: none) in the place of the first of them, or at the end when
; none was there. eax = how many there were.
rt_rebuild:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r14,rdx
	mov	r15d,ecx
	mov	r12,[g_rt_old]			; where in it
	mov	r13,r12
	add	r13,[g_rt_oldlen]		; its end
	mov	rbx,[g_rt_new]			; out
	push	0				; how many of that head
.line:
	cmp	r12,r13
	jae	.end
	mov	rsi,r12				; this line, without its LF
	xor	ecx,ecx
@@:
	lea	rax,[rsi+rcx]
	cmp	rax,r13
	jae	@f
	cmp	byte [rax],10
	je	@f
	inc	ecx
	jmp	@b
@@:
	push	rcx
	push	rsi
	lea	rdi,[g_rt_lh]
	push	qword [g_rt_hlen]
	call	rt_head				; (it writes g_rt_hlen: the line's)
	mov	r8d,eax
	pop	rax
	mov	[g_rt_hlen],eax
	pop	rsi
	pop	rcx
	lea	r12,[rsi+rcx+1]			; (the next)
	cmp	r8d,[g_rt_hlen]
	jne	.keep
	push	rsi
	push	rcx
	lea	rsi,[g_rt_lh]
	lea	rdi,[g_rt_head]
	mov	ecx,r8d
	repe	cmpsb
	pop	rcx
	pop	rsi
	jne	.keep
	; one of that head
	inc	qword [rsp]
	cmp	qword [rsp],1
	jne	.line				; (another: out)
	test	r14,r14
	jz	.line
	mov	rsi,r14
	mov	ecx,r15d
.keep:
	mov	rdi,rbx
	rep	movsb
	mov	byte [rdi],10
	lea	rbx,[rdi+1]
	jmp	.line
.end:
	cmp	qword [rsp],0
	jne	.done
	test	r14,r14
	jz	.done
	mov	rdi,rbx				; none was there: at the end
	mov	rsi,r14
	mov	ecx,r15d
	rep	movsb
	mov	byte [rdi],10
	lea	rbx,[rdi+1]
.done:
	sub	rbx,[g_rt_new]
	mov	[g_rt_newlen],rbx
	pop	rax
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; the whole configuration, as it is on disk now: CF when it does not compile
; (a child does it, its errors printed as `okena check` prints them)
rt_compiles:
	mov	eax,SYS_fork
	syscall
	test	rax,rax
	jz	.child
	js	.no
	mov	edi,eax
	sub	rsp,16
	mov	rsi,rsp
	xor	edx,edx
	xor	r10d,r10d
	mov	eax,SYS_wait4_
	syscall
	mov	eax,[rsp]
	add	rsp,16
	test	eax,eax				; exited, 0
	jnz	.no
	clc
	ret
.no:
	stc
	ret
.child:
	call	arenas_empty
	call	cfg_read_source
	test	rax,rax
	js	.unread
	call	cfg_parse_checked
	call	plan_reset
	call	plan_compile
	xor	edi,edi
	jmp	exit_process
.unread:
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; room for the admin socket's answers
rt_admin_buf:
	xor	edi,edi
	mov	esi,ADMIN_BUF
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	mov	[g_admin_buf],rax
	ret
