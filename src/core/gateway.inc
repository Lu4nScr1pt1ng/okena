; `okena { gateway kubernetes class=okena dir=/var/lib/okena/gateway [api=HOST:PORT]
; [token=PATH] [ca=PATH] [name=HOST] }`: okena as the Kubernetes Gateway API's
; implementation for the Gateways of that class.
;
; A process of its own, okena-gateway, reads the cluster's Gateways and
; HTTPRoutes from the API server once a second (over the TLS that `discover
; kubernetes` uses, with the same credentials) and writes them, translated,
; as okena's own configuration: DIR/gateway.conf, which the main file takes in
; with `include "DIR/*.conf"`. When what it writes changes, okena reloads, as
; for SIGHUP: so what okena serves is always a configuration that `okena check`
; would pass, and a translation that came out wrong is refused whole, the one
; before it served on. The Services behind the routes become pools that follow
; their EndpointSlices (`discover kubernetes`); the TLS Secrets of HTTPS
; listeners are written beside it, in DIR/certs.
;
; Everything a route's author wrote is checked before it goes into the file:
; names and paths by what they may be made of, values quoted and escaped, no
; ${...} in them, no header okena writes itself. A route that cannot be told in
; okena's terms is left out, or answers 500 as the Gateway API says, and the
; others are served. The API server not answering, or answering what cannot be
; read, changes nothing.

GWP_ON		:= 0			; d
GWP_CLASSLEN	:= 4			; d
GWP_CLASS	:= 8			; q
GWP_DIR		:= 16			; q
GWP_DIRLEN	:= 24			; d
GWP_APILEN	:= 28			; d: api= as written, for the pools' `discover`
GWP_API		:= 32			; q
GWP_TOKEN	:= 40			; q: token=
GWP_TOKENLEN	:= 48			; d
GWP_CALEN	:= 52			; d
GWP_CA		:= 56			; q: ca=
GWP_NAME	:= 64			; q: name=
GWP_NAMELEN	:= 72			; d
GWP_KB		:= 128			; the API server, as a KB block (kube.inc)
GWP_SIZE	:= GWP_KB + KB_SIZE

GW_ARENA	:= 64 shl 20
GW_LISTS	:= 0			; the Gateways, then the HTTPRoutes (as read)
GW_LISTS_CAP	:= 16 shl 20
GW_OUT		:= GW_LISTS + GW_LISTS_CAP	; what is written
GW_OUT_CAP	:= 8 shl 20
GW_LAST		:= GW_OUT + GW_OUT_CAP	; what was written last
GW_TEXT		:= GW_LAST + GW_OUT_CAP	; text made on the way (paths, names)
GW_TEXT_CAP	:= 4 shl 20
GW_FILE		:= GW_TEXT + GW_TEXT_CAP	; a file read back, a Secret decoded
GW_FILE_CAP	:= 4 shl 20
GW_TABLES	:= GW_FILE + GW_FILE_CAP
assert GW_TABLES + (16 shl 20) <= GW_ARENA

bss
	align 8
	g_plan_gw:	rb GWP_SIZE
	g_gw_page	dq ?			; shared with the supervisor: GH_*
	g_gw_pid	dd ?
	g_gw_base	dq ?
	g_gw_lastlen	dd ?
	g_gw_said	dd ?			; what went wrong, said once
	g_gw_path	rb 4096 + 512
	g_gw_tmp	rb 4096 + 512
	g_gw_reqpath	rb 1024
	g_gw_reqlen	dd ?
	g_gw_method	dd ?			; 0 GET, 1 PATCH (a merge patch: g_gw_body)
	g_gw_bodylen	dd ?
	g_gw_body	dq ?
	g_gw_retries	dd ?
	g_gw_retry_at	dq ?
end bss

GH_RELOAD	:= 0			; d: a new file: the supervisor reloads
GH_RESULT	:= 4			; d: how the last reload went: 0 not known, 1 taken, 2 refused

cstring gw_name, 'okena-gateway',0

; ------------------------------------------------------------- the plan

; rbx = the `gateway` node (in the okena block)
compile_gateway:
	push	r13
	mov	r13,rbx
	mov	rax,[rbx+N_ARGS]
	mov	rcx,[rax+A_VAL]
	cmp	dword [rax+A_VLEN],10
	jne	plan_bad_gateway
	mov	dword [g_plan_gw+GWP_ON],1
	; class=, else okena
	lea	rax,[str_gw_class_default]
	mov	[g_plan_gw+GWP_CLASS],rax
	mov	dword [g_plan_gw+GWP_CLASSLEN],str_gw_class_default.len
	mov	rdi,r13
	lea	rsi,[str_key_class]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rcx,[rax+A_VAL]
	mov	edx,[rax+A_VLEN]
	call	gw_label_ok
	jc	plan_bad_gateway
	mov	[g_plan_gw+GWP_CLASS],rcx
	mov	[g_plan_gw+GWP_CLASSLEN],edx
@@:
	; dir=: a whole path
	mov	rdi,r13
	lea	rsi,[str_key_dir]
	call	node_option
	test	rax,rax
	jz	plan_bad_gateway
	mov	rcx,[rax+A_VAL]
	mov	edx,[rax+A_VLEN]
	cmp	edx,2
	jb	plan_bad_gateway
	cmp	edx,200
	ja	plan_bad_gateway
	cmp	byte [rcx],'/'
	jne	plan_bad_gateway
	cmp	byte [rcx+rdx-1],'/'
	jne	@f
	dec	edx
@@:
	xor	eax,eax
@@:
	cmp	byte [rcx+rax],'"'		; (it goes into the file, quoted)
	je	plan_bad_gateway
	cmp	byte [rcx+rax],'\'
	je	plan_bad_gateway
	cmp	byte [rcx+rax],'$'
	je	plan_bad_gateway
	cmp	byte [rcx+rax],' '
	jbe	plan_bad_gateway
	inc	eax
	cmp	eax,edx
	jb	@b
	mov	[g_plan_gw+GWP_DIR],rcx
	mov	[g_plan_gw+GWP_DIRLEN],edx
	; the API's options as written, passed on to the pools
	mov	rdi,r13
	lea	rsi,[str_key_api]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rcx,[rax+A_VAL]
	mov	[g_plan_gw+GWP_API],rcx
	mov	ecx,[rax+A_VLEN]
	mov	[g_plan_gw+GWP_APILEN],ecx
@@:
	mov	rdi,r13
	lea	rsi,[str_key_token]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rcx,[rax+A_VAL]
	mov	[g_plan_gw+GWP_TOKEN],rcx
	mov	ecx,[rax+A_VLEN]
	mov	[g_plan_gw+GWP_TOKENLEN],ecx
@@:
	mov	rdi,r13
	lea	rsi,[str_key_ca]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rcx,[rax+A_VAL]
	mov	[g_plan_gw+GWP_CA],rcx
	mov	ecx,[rax+A_VLEN]
	mov	[g_plan_gw+GWP_CALEN],ecx
@@:
	mov	rdi,r13
	lea	rsi,[str_key_name]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rcx,[rax+A_VAL]
	mov	[g_plan_gw+GWP_NAME],rcx
	mov	ecx,[rax+A_VLEN]
	mov	[g_plan_gw+GWP_NAMELEN],ecx
@@:
	; none of them may hold what would break out of a quoted value
	irp f, API,TOKEN,CA,NAME
		mov	rcx,[g_plan_gw+GWP_#f]
		mov	edx,[g_plan_gw+GWP_#f#LEN]
		test	edx,edx
		jz	@f
		call	gw_value_ok
		jc	plan_bad_gateway
	@@:
	end irp
	; and as `discover kubernetes` reads them: the connection itself
	lea	r10,[g_plan_gw+GWP_KB]
	call	kube_api_options
	pop	r13
	ret

plan_bad_gateway:
	call	log_begin
	out_lit 'gateway takes kubernetes, dir=/PATH (where it writes; `include "DIR/*.conf"` takes it in), and may take class=NAME (okena when not said), api=HOST:PORT, token=/PATH, ca=PATH and name=HOST, as discover kubernetes does'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
cstring str_key_class, 'class',0
cstring str_key_dir, 'dir',0
cstring str_gw_class_default, 'okena'

; rcx/edx = a DNS label (1..63, a-z 0-9 -, no - at an end). CF when not.
gw_label_ok:
	test	edx,edx
	jz	.bad
	cmp	edx,63
	ja	.bad
	cmp	byte [rcx],'-'
	je	.bad
	cmp	byte [rcx+rdx-1],'-'
	je	.bad
	xor	eax,eax
.char:
	movzx	r8d,byte [rcx+rax]
	cmp	r8d,'-'
	je	.ok
	lea	r9d,[r8-'0']
	cmp	r9d,9
	jbe	.ok
	lea	r9d,[r8-'a']
	cmp	r9d,25
	ja	.bad
.ok:
	inc	eax
	cmp	eax,edx
	jb	.char
	clc
	ret
.bad:
	stc
	ret

; rcx/edx = a value for a quoted string: no control character, no ${. CF when it
; may not be one. Keeps all but rax, r8.
gw_value_ok:
	cmp	edx,1024
	ja	.bad
	xor	eax,eax
.char:
	cmp	eax,edx
	jae	.ok
	movzx	r8d,byte [rcx+rax]
	cmp	r8d,' '
	jb	.bad
	cmp	r8d,127
	je	.bad
	cmp	r8d,'$'
	jne	.next
	lea	r8d,[rax+1]
	cmp	r8d,edx
	jae	.next
	cmp	byte [rcx+r8],'{'
	je	.bad
.next:
	inc	eax
	jmp	.char
.ok:
	clc
	ret
.bad:
	stc
	ret

; --------------------------------------------------------- the supervisor

; the shared page, once, before any fork
gw_page_init:
	cmp	qword [g_gw_page],0
	jne	.out
	xor	edi,edi
	mov	esi,4096
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_ANONYMOUS
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.out
	mov	[g_gw_page],rax
.out:
	ret

spawn_gateway:
	cmp	dword [g_plan_gw+GWP_ON],0
	je	.none
	cmp	qword [g_gw_page],0
	je	.none
	mov	eax,SYS_fork
	syscall
	test	rax,rax
	jz	gw_main
	js	.none
	mov	[g_gw_pid],eax
.none:
	ret

; a reload: the one running goes, a new one reads the new plan (and what it
; wrote, so that the same answer is not written again)
gateway_reload:
	mov	edi,[g_gw_pid]
	test	edi,edi
	jz	spawn_gateway
	mov	dword [g_gw_pid],0
	call	acme_stop
	jmp	spawn_gateway

; edi = 1 a reload taken, 2 refused: said to the gateway process (for its status).
; Keeps all.
gw_reload_result:
	push	rax
	mov	rax,[g_gw_page]
	test	rax,rax
	jz	@f
	mov	[rax+GH_RESULT],edi
@@:
	pop	rax
	ret

; the supervisor's tick: eax = 1 when a new file waits to be read
gw_tick:
	mov	rcx,[g_gw_page]
	xor	eax,eax
	test	rcx,rcx
	jz	.out
	xchg	eax,[rcx+GH_RELOAD]
	test	eax,eax
	jz	.out
	push	rax
	call	log_begin
	out_lit 'gateway: the cluster changed: reloading'
	call	log_end
	pop	rax
.out:
	ret

; ------------------------------------------------------------ the process

; Never returns.
gw_main:
	mov	dword [g_is_worker],0
	mov	edi,PR_SET_PDEATHSIG
	mov	esi,SIGKILL
	mov	eax,SYS_prctl
	syscall
	mov	eax,SYS_getppid
	syscall
	cmp	eax,[g_sup_pid]
	je	@f
	xor	edi,edi
	jmp	exit_process
@@:
	mov	edi,PR_SET_NAME
	lea	rsi,[gw_name]
	mov	eax,SYS_prctl
	syscall
	call	helper_close_sockets
	call	cx_buffer
	jc	.idle
	xor	edi,edi
	mov	esi,GW_ARENA
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.idle
	mov	[g_gw_base],rax
	; its directories, while it may make them: DIR, DIR/certs
	cstring .certs, '/certs',0
	lea	rsi,[.certs]
	call	gw_dir_path
	lea	rsi,[g_gw_path]
	mov	edx,0x1C0			; 0700
	call	mkdir_p
	cmp	dword [g_plan_user],0
	je	@f
	mov	edi,AT_FDCWD			; (both: the user writes in them)
	lea	rsi,[g_gw_path]
	mov	edx,[g_plan_uid]
	mov	r10d,[g_plan_gid]
	xor	r8d,r8d
	mov	eax,SYS_fchownat_
	syscall
	cstring .none, '',0
	lea	rsi,[.none]
	call	gw_dir_path
	mov	edi,AT_FDCWD
	lea	rsi,[g_gw_path]
	mov	edx,[g_plan_uid]
	mov	r10d,[g_plan_gid]
	xor	r8d,r8d
	mov	eax,SYS_fchownat_
	syscall
@@:
	call	priv_drop
	call	gw_confine
	seccomp_for filter_gateway
	; what it wrote before: the same answer is not written again
	lea	rsi,[str_gw_conf]
	call	gw_dir_path
	mov	rdi,[g_gw_base]
	add	rdi,GW_LAST
	mov	esi,GW_OUT_CAP
	call	gw_read
	jnc	@f
	xor	eax,eax
@@:
	mov	[g_gw_lastlen],eax
	call	gs_load				; (and the status it wrote)
.loop:
	call	gw_render			; GW_OUT, eax = its length; CF: not now
	jc	.sleep
	mov	dword [g_gw_said],0
	mov	r12d,eax
	cmp	dword [g_gw_certs],0
	jne	.write				; a certificate changed: read again
	cmp	eax,[g_gw_lastlen]
	jne	.write
	mov	rsi,[g_gw_base]
	lea	rdi,[rsi+GW_LAST]
	add	rsi,GW_OUT
	mov	ecx,eax
	repe	cmpsb
	jne	.write
	call	gw_status			; as it is served: its status, where it changed
	call	gw_retry			; (refused: asked again, for a while)
	jmp	.sleep
.write:
	lea	rsi,[str_gw_conf]
	call	gw_dir_path
	mov	rsi,[g_gw_base]
	add	rsi,GW_OUT
	mov	edx,r12d
	call	gw_write
	jc	.unwritable
	mov	rsi,[g_gw_base]
	lea	rdi,[rsi+GW_LAST]
	add	rsi,GW_OUT
	mov	ecx,r12d
	rep	movsb
	mov	[g_gw_lastlen],r12d
	call	log_begin
	out_lit 'gateway: '
	lea	rsi,[g_gw_path]
	call	out_cstr
	out_lit ' written: '
	mov	eax,[g_gw_nroutes]
	call	out_u64
	out_lit ' routes on '
	mov	eax,[g_gw_nports]
	call	out_u64
	out_lit ' ports'
	call	log_end
	mov	rax,[g_gw_page]
	mov	dword [rax+GH_RESULT],0		; (what this reload does, not what one did before)
	mov	dword [rax+GH_RELOAD],1
	mov	dword [g_gw_retries],0
	jmp	.sleep
.unwritable:
	mov	eax,6
	cstring str_gw_unwritable, ': it cannot be written'
	lea	rsi,[str_gw_unwritable]
	mov	edx,str_gw_unwritable.len
	call	gw_tell
.sleep:
	lea	rdi,[ts_gw_sleep]
	xor	esi,esi
	mov	eax,SYS_nanosleep
	syscall
	jmp	.loop
.idle:
	lea	rdi,[ts_gw_idle]
	xor	esi,esi
	mov	eax,SYS_nanosleep
	syscall
	jmp	.idle

rodata
	align 8
	ts_gw_sleep	dq 1, 0
	ts_gw_idle	dq 3600, 0
end rodata
cstring str_gw_conf, '/gateway.conf',0

; The last reload was refused: asked again every 5 s, 12 times at most after
; what was written last. A port okena stopped listening on is still held by the
; workers that finish their connections there, and listening on it again is
; refused until they are gone; a configuration that is wrong stays wrong, and is
; not asked for for ever.
gw_retry:
	mov	rax,[g_gw_page]
	cmp	dword [rax+GH_RESULT],2
	jne	.out
	cmp	dword [g_gw_retries],12
	jae	.out
	call	monotonic_seconds
	cmp	rax,[g_gw_retry_at]
	jb	.out
	add	rax,5
	mov	[g_gw_retry_at],rax
	inc	dword [g_gw_retries]
	call	log_begin
	out_lit 'gateway: what it wrote was refused: asking for it again'
	call	log_end
	mov	rax,[g_gw_page]
	mov	dword [rax+GH_RESULT],0
	mov	dword [rax+GH_RELOAD],1
.out:
	ret

; landlock: everything read, DIR written
gw_confine:
	call	ll_begin
	jc	.out
	lea	rdi,[str_ll_root]
	mov	esi,LL_READS
	call	ll_path
	cstring .none, '',0
	lea	rsi,[.none]
	call	gw_dir_path
	lea	rdi,[g_gw_path]
	mov	esi,LL_READS or LL_WRITES or LLF_REMOVE_FILE or LLF_MAKE_DIR
	call	ll_path
	call	ll_end
.out:
	ret

; rsi = a NUL-ended name ('/gateway.conf'): DIR then it, in g_gw_path
gw_dir_path:
	lea	rdi,[g_gw_path]
	push	rsi
	mov	rsi,[g_plan_gw+GWP_DIR]
	mov	ecx,[g_plan_gw+GWP_DIRLEN]
	rep	movsb
	pop	rsi
@@:
	lodsb
	stosb
	test	al,al
	jnz	@b
	ret

; eax = what went wrong (a number), rsi/edx = it: said once, until it is
; something else or it goes right
gw_tell:
	cmp	[g_gw_said],eax
	je	.out
	mov	[g_gw_said],eax
	push	rsi
	push	rdx
	call	log_begin
	out_lit 'gateway kubernetes'
	pop	rdx
	pop	rsi
	call	out_str
	out_lit '; what okena serves stays as it is'
	call	log_end
.out:
	ret

; g_gw_path = a file, rdi = where, esi = room: eax = its length. CF when it
; cannot be read (or is larger).
gw_read:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	mov	r13d,esi
	mov	edi,AT_FDCWD
	lea	rsi,[g_gw_path]
	mov	edx,O_RDONLY or O_CLOEXEC
	xor	r10d,r10d
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	js	.bad
	mov	ebx,eax
	xor	ecx,ecx
.read:
	mov	edi,ebx
	lea	rsi,[r12+rcx]
	mov	edx,r13d
	sub	edx,ecx
	jz	.full
	push	rcx
	xor	eax,eax
	syscall
	pop	rcx
	cmp	rax,-EINTR
	je	.read
	test	rax,rax
	js	.close_bad
	jz	.done
	add	ecx,eax
	jmp	.read
.done:
	push	rcx
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
	pop	rax
	clc
	jmp	.out
.full:
.close_bad:
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
.bad:
	stc
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; g_gw_path = where, rsi/edx = what: written beside it and renamed over it
; (0600). CF when it could not be.
gw_write:
	push	rbx
	push	r12
	push	r13
	mov	r12,rsi
	mov	r13d,edx
	lea	rsi,[g_gw_path]
	lea	rdi,[g_gw_tmp]
@@:
	lodsb
	stosb
	test	al,al
	jnz	@b
	mov	dword [rdi-1],'.new'
	mov	byte [rdi+3],0
	mov	edi,AT_FDCWD
	lea	rsi,[g_gw_tmp]
	mov	edx,O_WRONLY or O_CREAT or O_APPEND or O_CLOEXEC
	mov	r10d,0x180			; 0600
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	js	.bad
	mov	ebx,eax
	mov	edi,ebx
	xor	esi,esi
	mov	eax,SYS_ftruncate
	syscall
	test	eax,eax
	js	.close_bad
	mov	edi,ebx
	mov	rsi,r12
	mov	edx,r13d
	call	write_all
	jc	.close_bad
	mov	edi,ebx
	mov	eax,SYS_fdatasync
	syscall
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
	lea	rdi,[g_gw_tmp]
	lea	rsi,[g_gw_path]
	mov	eax,SYS_rename_
	syscall
	test	eax,eax
	js	.bad
	clc
	jmp	.out
.close_bad:
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
.bad:
	stc
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; g_gw_path = a file, rsi/edx = what it should hold: written when it does not
; already. g_gw_certs set when it was. CF when it could not be.
gw_write_changed:
	push	rsi
	push	rdx
	mov	rdi,[g_gw_base]
	add	rdi,GW_FILE + GW_FILE_CAP / 2
	mov	esi,GW_FILE_CAP / 2
	call	gw_read
	pop	rdx
	pop	rsi
	jc	.write
	cmp	eax,edx
	jne	.write
	push	rsi
	mov	rdi,[g_gw_base]
	add	rdi,GW_FILE + GW_FILE_CAP / 2
	mov	ecx,edx
	repe	cmpsb
	pop	rsi
	jne	.write
	clc
	ret
.write:
	mov	dword [g_gw_certs],1
	jmp	gw_write

; ------------------------------------------------------------ the API

; g_gw_reqpath/g_gw_reqlen = a path (and its query): GET it. eax = its status,
; rsi/ecx = its body (in g_dk_buf). CF when there was no answer (said).
gw_get:
	push	rbx
	push	r12
	push	r13
	push	r14
	lea	r14,[g_plan_gw+GWP_KB]
	call	kb_token			; g_kb_tok, eax = its length or 0
	test	eax,eax
	jz	.no_token
	mov	ebx,eax
	lea	rsi,[r14+KB_SA]
	mov	edx,[r14+KB_SALEN]
	call	cx_connect
	jc	.no_answer
	lea	rdi,[r14+KB_ANCHOR]
	mov	rsi,[r14+KB_SNI]
	mov	edx,[r14+KB_SNILEN]
	call	cx_handshake
	jc	.not_verified
	; GET (or PATCH) PATH HTTP/1.0, Host, Accept, the token
	lea	rdi,[g_kb_req]
	cstring .get, 'GET '
	lea	rsi,[.get]
	mov	ecx,.get.len
	cmp	dword [g_gw_method],0
	je	@f
	cstring .patch, 'PATCH '
	lea	rsi,[.patch]
	mov	ecx,.patch.len
@@:
	rep	movsb
	lea	rsi,[g_gw_reqpath]
	mov	ecx,[g_gw_reqlen]
	rep	movsb
	cstring .http, ' HTTP/1.0',13,10,'Host: '
	lea	rsi,[.http]
	mov	ecx,.http.len
	rep	movsb
	mov	rsi,[r14+KB_SNI]
	mov	ecx,[r14+KB_SNILEN]
	rep	movsb
	lea	rsi,[str_kb_get4]		; Accept, Authorization: Bearer
	mov	ecx,str_kb_get4.len
	rep	movsb
	lea	rsi,[g_kb_tok]
	mov	ecx,ebx
	rep	movsb
	cmp	dword [g_gw_method],0
	je	@f
	cstring .ct, 13,10,'Content-Type: application/merge-patch+json',13,10,'Content-Length: '
	lea	rsi,[.ct]
	mov	ecx,.ct.len
	rep	movsb
	mov	eax,[g_gw_bodylen]
	call	dk_decimal
@@:
	mov	dword [rdi],0x0A0D0A0D
	add	rdi,4
	lea	rsi,[g_kb_req]
	mov	rdx,rdi
	sub	rdx,rsi
	call	cx_send
	jc	.no_answer_close
	cmp	dword [g_gw_method],0
	je	@f
	mov	rsi,[g_gw_body]			; the body after its head
	mov	edx,[g_gw_bodylen]
	call	cx_send
	jc	.no_answer_close
@@:
	call	cx_answer
	jc	.no_answer_close
	call	cx_close
	call	cx_status
	jc	.unreadable
	clc
	jmp	.out
.unreadable:
	mov	eax,2
	lea	rsi,[str_kb_bad]
	mov	edx,str_kb_bad.len
	jmp	.tell
.not_verified:
	cmp	eax,4
	jne	.no_answer_close
	call	cx_close
	mov	eax,4
	lea	rsi,[str_kb_cert]
	mov	edx,str_kb_cert.len
	jmp	.tell
.no_token:
	mov	eax,5
	lea	rsi,[str_kb_tok]
	mov	edx,str_kb_tok.len
	jmp	.tell
.no_answer_close:
	call	cx_close
.no_answer:
	mov	eax,1
	lea	rsi,[str_kb_gone]
	mov	edx,str_kb_gone.len
.tell:
	call	gw_tell
	stc
.out:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rsi = a NUL-ended text, then [rdx/ecx = more] ...: g_gw_reqpath built from
; pieces (gw_req_begin, gw_req_add, gw_req_cstr)
gw_req_begin:
	mov	dword [g_gw_reqlen],0
	ret
; rsi/ecx = bytes: added
gw_req_add:
	push	rdi
	mov	edi,[g_gw_reqlen]
	lea	eax,[rdi+rcx]
	cmp	eax,1000
	ja	.full
	mov	[g_gw_reqlen],eax
	lea	rdi,[g_gw_reqpath+rdi]
	rep	movsb
.full:
	pop	rdi
	ret
; rsi = NUL-ended: added
gw_req_cstr:
	push	rsi
	xor	ecx,ecx
@@:
	cmp	byte [rsi+rcx],0
	je	@f
	inc	ecx
	jmp	@b
@@:
	pop	rsi
	jmp	gw_req_add
