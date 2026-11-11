; `okena { admin unix:/run/okena/admin.sock }`: the running state changed
; without editing a file. One line asks, one answer, and the connection
; closes; the admin process answers, so nothing here touches a worker.
;
;   list                  ok, then a line per server
;   drain POOL SERVER     no new connection; those it has go on
;   up POOL SERVER        takes a drain back
;   weight POOL SERVER N  1..65535, 0 for the weight in the file
;   reload                as SIGHUP
;   state                 ok, reloads tried, reloads that worked
;
; SERVER is as written in the file, so a name means all its addresses. A
; drained server is not chosen at all, not even when every other is down.
;
; Workers read one shared table a generation, a load per decision. What it
; holds comes from a list by name that outlives generations: a reload keeps
; a drain, by pool and server, and forgets it with the server. The admin
; process only writes that list and asks for a reload through it, once the
; supervisor looks; it has no right to send a signal. An upgrade or a restart
; starts from the file.
;
; The socket is the owner's only, by mode and by a look at the caller, and
; takes its path only when this okena is up: until then, in an upgrade, the
; old one keeps answering there.

AP_WANT		:= 0		; d: a reload was asked for
AP_TRIED	:= 4		; d
AP_DONE		:= 8		; d: of those, or by signal, that went well
AP_DRAIN	:= 12		; d: `okena drain`: out of rotation
AP_ENT		:= 64
AO_USED		:= 0		; d
AO_DRAIN	:= 4		; d
AO_WEIGHT	:= 8		; d: 0 as in the file
AO_PLEN		:= 12		; d
AO_TLEN		:= 16		; d
AO_TEXT		:= 20		; pool, then server
AO_SIZE		:= 256
AO_TEXT_MAX	:= AO_SIZE - AO_TEXT
AO_N		:= 256
API_WEIGHT_MAX	:= 65535
API_POLL_TRIES	:= 300		; 30 s
SYS_ppoll_	:= 271

bss
	align 8
	g_plan_api	dq ?		; the path, 0 none
	g_plan_apilen	dd ?
	g_api_fd	dd ?		; -1 none
	g_api_uid	dd ?
	g_api_pl	dd ?
	g_api_pp	dq ?
	g_api_tp	dq ?
	g_api_tl	dd ?
	g_api_w		dd ?
	g_api_tbl	dq ?		; shared: drain d, weight d, per server
	g_api_ov	dq ?		; shared: the list
	g_api_sa:	rb 110
	g_api_tmp:	rb 110
	g_admin_pfd:	rq 2
	g_cli_t0	dd ?
	g_cli_d0	dd ?
	g_cli_dwait	dd ?
end bss

rodata
	align 8
	ts_api_poll	dq 0, 100000000
end rodata

; before any fork, and for each generation
api_table_init:
	call	acme_page_init			; (acme.inc: shared before any fork)
	call	gw_page_init			; (gateway.inc: the same)
	call	ocsp_page_init			; (ocsp.inc: the staples)
	cmp	qword [g_api_ov],0
	jne	.list_there
	xor	edi,edi
	mov	esi,AP_SIZE			; (and maintenance's routes, maint.inc)
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_ANONYMOUS
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	mov	[g_api_ov],rax
.list_there:
	xor	edi,edi
	mov	esi,MAX_SERVERS * 8
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_ANONYMOUS
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	mov	[g_api_tbl],rax
	; falls through

; the list, on the plan and the table of now. What no server answers to any
; more is forgotten. The list is the admin process's to write: nothing in it
; is believed.
api_apply:
	push	r13
	push	r14
	xor	r13d,r13d
.entry:
	cmp	r13d,AO_N
	jae	.out
	imul	r14,r13,AO_SIZE
	add	r14,[g_api_ov]
	add	r14,AP_ENT
	cmp	dword [r14+AO_USED],0
	je	.next
	mov	eax,[r14+AO_PLEN]
	cmp	eax,AO_TEXT_MAX
	ja	.drop
	mov	ecx,[r14+AO_TLEN]
	cmp	ecx,AO_TEXT_MAX
	ja	.drop
	add	eax,ecx
	cmp	eax,AO_TEXT_MAX
	ja	.drop
	call	api_mark
	test	eax,eax
	jnz	.next
.drop:
	mov	dword [r14+AO_USED],0
.next:
	inc	r13d
	jmp	.entry
.out:
	pop	r14
	pop	r13
	ret

; r14 = an entry: on every server it names. eax = how many.
api_mark:
	push	rbx
	push	r13
	xor	ebx,ebx
	xor	r13d,r13d
.next:
	cmp	ebx,[g_plan_servers]
	jae	.out
	call	api_same
	jne	.skip
	inc	r13d
	mov	rax,[g_api_tbl]
	mov	ecx,[r14+AO_DRAIN]
	mov	[rax+rbx*8],ecx
	mov	ecx,[r14+AO_WEIGHT]
	mov	[rax+rbx*8+4],ecx
.skip:
	inc	ebx
	jmp	.next
.out:
	mov	eax,r13d
	pop	r13
	pop	rbx
	ret

; ebx = server, r14 = entry: ZF when it names that one
api_same:
	push	r12
	call	hc_pool_of
	mov	ecx,[r14+AO_PLEN]
	cmp	ecx,[r12+PL_NLEN]
	jne	.out
	imul	rdx,rbx,SV_SIZE
	mov	eax,[r14+AO_TLEN]
	cmp	eax,[g_servers+rdx+SV_TLEN]
	jne	.out
	lea	rsi,[r14+AO_TEXT]
	mov	rdi,[r12+PL_NAME]
	repe	cmpsb
	jne	.out
	mov	ecx,eax
	mov	rdi,[g_servers+rdx+SV_TEXT]
	repe	cmpsb
.out:
	pop	r12
	ret

; the supervisor, once a second
api_tick:
	mov	rax,[g_api_ov]
	xor	ecx,ecx
	xchg	[rax+AP_WANT],ecx
	test	ecx,ecx
	jz	.none
	call	supervisor_reload
	mov	rax,[g_api_ov]
	inc	dword [rax+AP_TRIED]
.none:
	ret

api_reloaded:
	mov	rax,[g_api_ov]
	inc	dword [rax+AP_DONE]
	ret

; g_api_sa = sockaddr_un of the path, esi: its length. CF: too long for what
; has to fit next to it.
api_addr:
	mov	ecx,[g_plan_apilen]
	cmp	ecx,100
	ja	.bad
	mov	word [g_api_sa],AF_UNIX
	lea	rdi,[g_api_sa+2]
	mov	rsi,[g_plan_api]
	rep	movsb
	mov	byte [rdi],0
	mov	esi,[g_plan_apilen]
	add	esi,3
	clc
	ret
.bad:
	stc
	ret

api_listen:
	mov	dword [g_api_fd],-1
	cmp	qword [g_plan_api],0
	je	.none
	call	api_addr
	jc	.bad
	add	esi,4
	push	rsi
	mov	eax,[g_plan_apilen]
	mov	dword [g_api_sa+2+rax],'.new'
	mov	byte [g_api_sa+6+rax],0
	lea	rdi,[g_api_sa+2]
	mov	eax,SYS_unlink_
	syscall
	mov	edi,AF_UNIX
	mov	esi,SOCK_STREAM or SOCK_CLOEXEC
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	pop	rdx
	test	eax,eax
	js	.bad
	mov	[g_api_fd],eax
	mov	edi,eax
	lea	rsi,[g_api_sa]
	mov	eax,SYS_bind
	syscall
	test	eax,eax
	js	.bad
	lea	rdi,[g_api_sa+2]
	mov	esi,384				; 0600
	mov	eax,SYS_chmod_
	syscall
	test	eax,eax
	js	.bad
	mov	edi,[g_api_fd]
	mov	esi,16
	mov	eax,SYS_listen
	syscall
	test	eax,eax
	js	.bad
.none:
	ret
.bad:
	call	log_begin
	out_lit 'cannot listen on the `admin` path'
	call	log_end
	mov	edi,EXIT_FATAL
	jmp	exit_process

; all is up: the path is ours
api_ready:
	cmp	dword [g_api_fd],0
	jl	.none
	lea	rsi,[g_api_sa+2]
	lea	rdi,[g_api_tmp]
	mov	ecx,[g_plan_apilen]
	rep	movsb
	mov	byte [rdi],0
	lea	rdi,[g_api_sa+2]
	lea	rsi,[g_api_tmp]
	mov	eax,SYS_rename_
	syscall
.none:
	ret

; r13 = where it is in a NUL-terminated line. rsi/ecx = the next word, r13
; after it; no word: ecx = 0.
api_word:
	cmp	byte [r13],' '
	jne	@f
	inc	r13
	jmp	api_word
@@:
	mov	rsi,r13
	xor	ecx,ecx
.more:
	cmp	byte [r13],' '
	jbe	.end
	inc	r13
	inc	ecx
	jmp	.more
.end:
	ret

; r14/r15d = a word, rdi/edx = a literal: ZF when the same
api_is:
	cmp	r15d,edx
	jne	.out
	mov	rsi,r14
	mov	ecx,edx
	repe	cmpsb
.out:
	ret

macro api_cmd name*, target*
	local s
	cstring s, name
	lea	rdi,[s]
	mov	edx,s.len
	call	api_is
	je	target
end macro

; edi = connection: read one line, answer it
api_serve:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	ebx,edi
	; the same user, or nobody
	sub	rsp,32
	mov	dword [rsp+16],12
	mov	esi,SOL_SOCKET
	mov	edx,SO_PEERCRED_
	mov	r10,rsp
	lea	r8,[rsp+16]
	mov	eax,SYS_getsockopt
	syscall
	mov	edx,[rsp+4]
	add	rsp,32
	test	eax,eax
	js	.out
	cmp	edx,[g_api_uid]
	jne	.out
	xor	r12d,r12d
.read:
	mov	edi,ebx
	lea	rsi,[g_admin_req+r12]
	mov	edx,4095
	sub	edx,r12d
	jz	.out
	xor	eax,eax
	syscall
	test	rax,rax
	jle	.out
	add	r12d,eax
	xor	ecx,ecx
@@:
	cmp	ecx,r12d
	jae	.read
	cmp	byte [g_admin_req+rcx],10
	je	.line
	inc	ecx
	jmp	@b
.line:
	mov	byte [g_admin_req+r12],0
	lea	r13,[g_admin_req]
	call	api_word
	mov	r14,rsi
	mov	r15d,ecx
	mov	rdi,[g_admin_buf]
	push	rdi
	api_cmd 'list', .list
	api_cmd 'status', .status
	api_cmd 'maintenance', .maintenance
	api_cmd 'purge', .purge
	api_cmd 'top', .top
	api_cmd 'explain', .explain
	api_cmd 'state', .state
	api_cmd 'reload', .reload
	api_cmd 'drain', .drain_instance
	api_cmd 'resume', .resume
	api_cmd 'drain', .names
	api_cmd 'up', .names
	api_cmd 'weight', .names
.usage:
	pop	rdi
	memit 'err: not something okena knows',10
	jmp	.send
.list:
	pop	rdi
	call	api_list
	jmp	.send
.status:
	pop	rdi
	memit 'ok',10
	call	status_json
	jmp	.send
.maintenance:
	pop	rdi
	call	api_maintenance			; rdi = after its answer
	jmp	.send
.purge:
	pop	rdi
	call	api_purge
	jmp	.send
.top:
	pop	rdi
	memit 'ok',10
	call	top_table
	jmp	.send
.explain:
	; the plan this instance runs, as `okena explain` says it: straight onto
	; the socket (`okena check --diff` compares it with a file)
	pop	rdi
	mov	rsi,[g_admin_buf]
	mov	word [rsi],'ok'
	mov	byte [rsi+2],10
	mov	edi,ebx
	mov	edx,3
	call	write_all
	mov	edi,ebx
	call	out_select
	call	explain_print
	call	out_flush
	mov	edi,2
	call	out_select
	jmp	.out
.state:
	pop	rdi
	memit 'ok '
	mov	rax,[g_api_ov]
	mov	eax,[rax+AP_TRIED]
	call	fmt_u64
	memit ' '
	mov	rax,[g_api_ov]
	mov	eax,[rax+AP_DONE]
	call	fmt_u64
	memit ' '
	mov	rax,[g_api_ov]
	mov	eax,[rax+AP_DRAIN]
	call	fmt_u64
	call	api_active
	memit 10
	jmp	.send
.reload:
	mov	rax,[g_api_ov]
	mov	dword [rax+AP_WANT],1
	pop	rdi
	memit 'ok',10
	jmp	.send
.drain_instance:
	; (alone: `drain POOL SERVER` is the server's)
	push	r13
	call	api_word
	pop	r13
	test	ecx,ecx
	jnz	.names
	mov	rax,[g_api_ov]
	mov	dword [rax+AP_DRAIN],1
	pop	rdi
	memit 'ok',10
	jmp	.send
.resume:
	call	api_word
	test	ecx,ecx
	jnz	.usage
	mov	rax,[g_api_ov]
	mov	dword [rax+AP_DRAIN],0
	pop	rdi
	memit 'ok',10
	jmp	.send
.names:
	call	api_word
	mov	[g_api_pp],rsi
	mov	[g_api_pl],ecx
	test	ecx,ecx
	jz	.usage
	call	api_word
	mov	[g_api_tp],rsi
	mov	[g_api_tl],ecx
	test	ecx,ecx
	jz	.usage
	add	ecx,[g_api_pl]
	cmp	ecx,AO_TEXT_MAX
	ja	.usage
	mov	dword [g_api_w],0
	cstring str_api_weight, 'weight'
	lea	rdi,[str_api_weight]
	mov	edx,str_api_weight.len
	call	api_is
	jne	.no_number
	call	api_word
	test	ecx,ecx
	jz	.usage
	cmp	ecx,5
	ja	.usage
	xor	eax,eax
@@:
	movzx	edx,byte [rsi]
	inc	rsi
	sub	edx,'0'
	cmp	edx,9
	ja	.usage
	imul	eax,eax,10
	add	eax,edx
	dec	ecx
	jnz	@b
	cmp	eax,API_WEIGHT_MAX
	ja	.usage
	mov	[g_api_w],eax
.no_number:
	call	api_word
	test	ecx,ecx
	jnz	.usage
	call	api_entry
	jc	.full
	; which of the three
	mov	r12,rax
	cstring str_api_drain, 'drain'
	lea	rdi,[str_api_drain]
	mov	edx,str_api_drain.len
	call	api_is
	je	.drain
	cstring str_api_up, 'up'
	lea	rdi,[str_api_up]
	mov	edx,str_api_up.len
	call	api_is
	je	.up
	mov	eax,[g_api_w]
	mov	[r12+AO_WEIGHT],eax
	jmp	.mark
.drain:
	mov	dword [r12+AO_DRAIN],1
	jmp	.mark
.up:
	mov	dword [r12+AO_DRAIN],0
.mark:
	mov	r14,r12
	call	api_mark
	test	eax,eax
	jz	.unknown
	mov	eax,[r14+AO_DRAIN]
	or	eax,[r14+AO_WEIGHT]
	setnz	al
	movzx	eax,al
	mov	[r14+AO_USED],eax		; (as in the file again: nothing to keep)
	pop	rdi
	memit 'ok',10
	jmp	.send
.unknown:
	mov	dword [r14+AO_USED],0
	pop	rdi
	memit 'err: no such server in that pool',10
	jmp	.send
.full:
	pop	rdi
	memit 'err: too many servers changed',10
.send:
	mov	rsi,[g_admin_buf]
	mov	rdx,rdi
	sub	rdx,rsi
	mov	edi,ebx
	call	write_all
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; g_api_pp and g_api_tp name one: rax = its entry, a new one not in use yet
; and empty. CF: no room.
api_entry:
	push	rbx
	push	r14
	xor	ebx,ebx
	xor	r8d,r8d				; a free one
.next:
	cmp	ebx,AO_N
	jae	.new
	imul	r14,rbx,AO_SIZE
	add	r14,[g_api_ov]
	add	r14,AP_ENT
	cmp	dword [r14+AO_USED],0
	jne	.used
	test	r8,r8
	cmovz	r8,r14
	jmp	.skip
.used:
	mov	ecx,[r14+AO_PLEN]
	cmp	ecx,[g_api_pl]
	jne	.skip
	mov	eax,[r14+AO_TLEN]
	cmp	eax,[g_api_tl]
	jne	.skip
	lea	rsi,[r14+AO_TEXT]
	mov	rdi,[g_api_pp]
	repe	cmpsb
	jne	.skip
	mov	ecx,eax
	mov	rdi,[g_api_tp]
	repe	cmpsb
	jne	.skip
	mov	rax,r14
	clc
	jmp	.out
.skip:
	inc	ebx
	jmp	.next
.new:
	test	r8,r8
	jz	.none
	mov	dword [r8+AO_DRAIN],0
	mov	dword [r8+AO_WEIGHT],0
	mov	eax,[g_api_pl]
	mov	[r8+AO_PLEN],eax
	mov	eax,[g_api_tl]
	mov	[r8+AO_TLEN],eax
	lea	rdi,[r8+AO_TEXT]
	mov	rsi,[g_api_pp]
	mov	ecx,[g_api_pl]
	rep	movsb
	mov	rsi,[g_api_tp]
	mov	ecx,[g_api_tl]
	rep	movsb
	mov	rax,r8
	clc
	jmp	.out
.none:
	stc
.out:
	pop	r14
	pop	rbx
	ret

; rdi = output: ok, and a line per server with an address
api_list:
	push	rbx
	push	r12
	memit 'ok',10
	xor	ebx,ebx
.next:
	cmp	ebx,[g_plan_servers]
	jae	.out
	imul	rax,rbx,SV_SIZE
	cmp	dword [g_servers+rax+SV_ACTIVE],0
	je	.skip
	call	hc_pool_of
	mov	rsi,[r12+PL_NAME]
	mov	ecx,[r12+PL_NLEN]
	rep	movsb
	mov	byte [rdi],' '
	inc	rdi
	imul	rax,rbx,SV_SIZE
	mov	rsi,[g_servers+rax+SV_TEXT]
	mov	ecx,[g_servers+rax+SV_TLEN]
	rep	movsb
	imul	rax,rbx,SV_SIZE
	cmp	dword [g_servers+rax+SV_GROUP],0
	je	.plain
	mov	byte [rdi],' '
	inc	rdi
	cmp	word [g_servers+rax+SV_SA],AF_INET6
	je	.v6
	lea	rsi,[g_servers+rax+SV_SA+4]
	mov	edx,4
	call	fmt_ip
	jmp	.plain
.v6:
	lea	rsi,[g_servers+rax+SV_SA+8]
	mov	edx,6
	call	fmt_ip
.plain:
	memit ' weight='
	mov	rax,[g_api_tbl]
	mov	eax,[rax+rbx*8+4]
	test	eax,eax
	jnz	@f
	imul	rax,rbx,SV_SIZE
	mov	eax,[g_servers+rax+SV_WEIGHT]
@@:
	call	fmt_u64
	memit ' active='
	lea	rcx,[STP_SACTIVE+rbx*4]
	call	stats_sum_d
	call	fmt_u64
	mov	rax,[g_api_tbl]
	cmp	dword [rax+rbx*8],0
	jne	.drained
	mov	rax,[g_health_tbl]
	cmp	dword [rax+rbx*8],HC_UP
	jne	.down
	memit ' up',10
	jmp	.skip
.drained:
	memit ' drain',10
	jmp	.skip
.down:
	memit ' down',10
.skip:
	inc	ebx
	jmp	.next
.out:
	pop	r12
	pop	rbx
	ret

; r13 = the rest of a `maintenance` line, rdi = output: `on|off [ROUTE]`
; changes it (the route as written: "/api/*"); with nothing, how it is.
; Workers read the list as it is written: an entry's text first, then the
; count; one leaves by the last taking its place.
api_maintenance:
	push	rbx
	push	r12
	push	r14
	push	r15
	mov	rbx,[g_api_ov]
	push	rdi
	call	api_word
	mov	r14,rsi
	mov	r15d,ecx
	call	api_word			; the route, if any
	mov	r12,rsi
	mov	r8d,ecx
	pop	rdi
	test	r15d,r15d
	jz	.show
	; a route as a listener's routes write it
	test	r8d,r8d
	jz	@f
	cmp	r8d,MP_SIZE - 4
	jae	.bad
	cmp	byte [r12],'/'
	jne	.bad
@@:
	push	rdi
	push	r8
	cstring str_mt_on, 'on'
	lea	rdi,[str_mt_on]
	mov	edx,str_mt_on.len
	call	api_is
	pop	r8
	pop	rdi
	je	.on
	push	rdi
	push	r8
	cstring str_mt_off, 'off'
	lea	rdi,[str_mt_off]
	mov	edx,str_mt_off.len
	call	api_is
	pop	r8
	pop	rdi
	jne	.bad
	; off
	test	r8d,r8d
	jnz	.off_route
	mov	dword [rbx+AP_MNUM],0		; all of it, and every route
	mov	dword [rbx+AP_MAINT],0
	jmp	.show
.off_route:
	call	.find
	jc	.show				; (not in it)
	mov	eax,[rbx+AP_MNUM]
	dec	eax
	imul	rsi,rax,MP_SIZE
	lea	rsi,[rbx+AP_MPATHS+rsi]		; the last into its place
	push	rdi
	mov	rdi,r9
	mov	ecx,MP_SIZE
	rep	movsb
	pop	rdi
	dec	dword [rbx+AP_MNUM]
	jmp	.show
.on:
	test	r8d,r8d
	jnz	.on_route
	mov	dword [rbx+AP_MAINT],1
	jmp	.show
.on_route:
	call	.find
	jnc	.show				; (in it already)
	mov	eax,[rbx+AP_MNUM]
	cmp	eax,MAINT_ROUTES
	jae	.full
	imul	r9,rax,MP_SIZE
	lea	r9,[rbx+AP_MPATHS+r9]
	mov	[r9],r8d
	push	rdi
	lea	rdi,[r9+4]
	mov	rsi,r12
	mov	ecx,r8d
	rep	movsb
	pop	rdi
	inc	dword [rbx+AP_MNUM]		; (after its text)
.show:
	memit 'ok '
	cmp	dword [rbx+AP_MAINT],0
	jne	@f
	memit 'off'
	jmp	.routes
@@:
	memit 'on'
.routes:
	xor	ecx,ecx
.r:
	cmp	ecx,[rbx+AP_MNUM]
	jae	.shown
	imul	rsi,rcx,MP_SIZE
	lea	rsi,[rbx+AP_MPATHS+rsi]
	mov	byte [rdi],' '
	inc	rdi
	push	rcx
	mov	ecx,[rsi]
	add	rsi,4
	rep	movsb
	pop	rcx
	inc	ecx
	jmp	.r
.shown:
	mov	byte [rdi],10
	inc	rdi
	jmp	.out
.full:
	memit 'err: 16 routes in maintenance at most',10
	jmp	.out
.bad:
	memit 'err: maintenance [on|off [ROUTE]], a route as written: /api/*',10
.out:
	pop	r15
	pop	r14
	pop	r12
	pop	rbx
	ret
; r12/r8d = a route: r9 = its entry, or CF
.find:
	xor	ecx,ecx
.f:
	cmp	ecx,[rbx+AP_MNUM]
	jae	.not_there
	imul	r9,rcx,MP_SIZE
	lea	r9,[rbx+AP_MPATHS+r9]
	inc	ecx
	cmp	[r9],r8d
	jne	.f
	push	rcx
	push	rdi
	lea	rdi,[r9+4]
	mov	rsi,r12
	mov	ecx,r8d
	repe	cmpsb
	pop	rdi
	pop	rcx
	jne	.f
	clc
	ret
.not_there:
	stc
	ret

; `okena maintenance [on|off [ROUTE]]`: 503 and the maintenance page for all
; of it, or a route, until off; with nothing, how it is
cli_maintenance:
	mov	edi,2
	mov	rcx,[g_argc]
	; the words that are not -c FILE
	lea	rdi,[g_admin_req]
	cstring str_api_maint_w, 'maintenance'
	lea	rsi,[str_api_maint_w]
	mov	ecx,str_api_maint_w.len
	rep	movsb
	mov	r12d,2
	mov	r13d,2				; where -c's file name would be
.word:
	cmp	r12,[g_argc]
	jae	.line
	mov	rax,[g_argv]
	mov	rsi,[rax+r12*8]
	cmp	word [rsi],'-c'
	jne	@f
	cmp	byte [rsi+2],0
	jne	@f
	add	r12d,2				; (-c FILE: for cli_source_from_args)
	jmp	.word
@@:
	cmp	r12d,4
	jae	.next				; two words at most
	mov	byte [rdi],' '
	inc	rdi
@@:
	lodsb
	test	al,al
	jz	.next
	stosb
	jmp	@b
.next:
	inc	r12d
	inc	r13d
	jmp	.word
.line:
	mov	byte [rdi],10
	inc	rdi
	lea	rax,[g_admin_req]
	sub	rdi,rax
	push	rdi
	; -c FILE, wherever it was
	mov	edi,2
	mov	rcx,[g_argc]
	mov	rax,[g_argv]
	xor	r8d,r8d
.c:
	cmp	r8,rcx
	jae	.no_c
	mov	rsi,[rax+r8*8]
	inc	r8d
	cmp	word [rsi],'-c'
	jne	.c
	cmp	byte [rsi+2],0
	jne	.c
	lea	edi,[r8-1]
	jmp	.c_found
.no_c:
	mov	rdi,rcx				; no -c: the default or OKENA_CONFIG
.c_found:
	call	cli_source_from_args
	call	api_cli_open
	pop	rdx
	lea	rsi,[g_admin_req]
	call	api_call
	mov	rsi,[g_admin_buf]
	lea	rdx,[rax-3]
	add	rsi,3
	mov	edi,1
	call	write_all
	xor	edi,edi
	jmp	exit_process

; rdi = output: " CONNECTIONS", what every worker of now has open (the stats
; pages, at most a second old)
api_active:
	push	rbx
	push	rdi
	xor	eax,eax
	xor	ebx,ebx
.listener:
	cmp	ebx,[g_plan_listeners]
	jae	.done
	push	rax
	lea	rcx,[STP_LACTIVE+rbx*4]
	call	stats_sum_d
	mov	ecx,eax
	pop	rax
	add	eax,ecx
	inc	ebx
	jmp	.listener
.done:
	pop	rdi
	push	rax
	memit ' '
	pop	rax
	call	fmt_u64
	pop	rbx
	ret

; `okena drain`, `okena resume`: the instance out of rotation and back, for
; a fleet behind a balancer that asks /ready. Drained, /ready answers 503 and
; HTTP/1 connections close after the answer they carry, so that clients come
; back through the balancer to another instance; nothing in flight is cut,
; and new connections are still served (the balancer may take a moment to
; see it). `okena drain wait` returns once nothing is left open, or after
; 60 s. A reload keeps it; a restart or an upgrade starts in rotation.
cli_drain:
	mov	rcx,[g_argc]
	mov	edi,2
	mov	dword [g_cli_dwait],0
	cmp	rcx,3
	jb	.args
	mov	rax,[g_argv]
	mov	rdi,[rax+16]
	cstring str_drain_wait, 'wait',0
	lea	rsi,[str_drain_wait]
	call	cstr_eq
	mov	edi,2
	test	eax,eax
	jz	.args
	mov	dword [g_cli_dwait],1
	mov	edi,3
.args:
	call	cli_source_from_args
	call	api_cli_open
	cstring str_api_drain_l, 'drain',10
	lea	rsi,[str_api_drain_l]
	mov	edx,str_api_drain_l.len
	call	api_call
	cmp	dword [g_cli_dwait],0
	je	.said
	mov	r12d,600			; 60 s
.wait:
	lea	rsi,[str_api_state_l]
	mov	edx,str_api_state_l.len
	call	api_try
	test	eax,eax
	jz	.again
	mov	rsi,[g_admin_buf]		; "ok TRIED DONE DRAIN ACTIVE"
	add	rsi,3
	call	.skip_word
	call	.skip_word
	call	.skip_word
	cmp	byte [rsi],'0'
	jne	.again
	cmp	byte [rsi+1],' '
	jbe	.empty
.again:
	lea	rdi,[ts_api_poll]
	xor	esi,esi
	mov	eax,SYS_nanosleep
	syscall
	dec	r12d
	jnz	.wait
	call	log_begin
	out_lit 'drained, with connections still open after 60 s'
	call	log_end
	mov	edi,1
	jmp	exit_process
.empty:
	mov	edi,1
	call	out_select
	out_lit 'drained: nothing left open',10
	xor	edi,edi
	jmp	exit_process
.said:
	mov	edi,1
	call	out_select
	out_lit 'drained: /ready answers 503',10
	xor	edi,edi
	jmp	exit_process
.skip_word:
	cmp	byte [rsi],' '
	je	@f
	cmp	byte [rsi],0
	je	.skipped
	inc	rsi
	jmp	.skip_word
@@:
	inc	rsi
.skipped:
	ret

; `okena top [once]`: what the instance does now, a table a second (rates
; from the admin process's own samples); `once` prints it one time, plain
cli_top:
	mov	rcx,[g_argc]
	mov	edi,2
	xor	r12d,r12d
	cmp	rcx,3
	jb	.args
	mov	rax,[g_argv]
	mov	rdi,[rax+16]
	cstring str_top_once, 'once',0
	lea	rsi,[str_top_once]
	call	cstr_eq
	mov	edi,2
	test	eax,eax
	jz	.args
	mov	r12d,1
	mov	edi,3
.args:
	call	cli_source_from_args
	call	api_cli_open
.frame:
	cstring str_api_top_l, 'top',10
	lea	rsi,[str_api_top_l]
	mov	edx,str_api_top_l.len
	call	api_call
	push	rax
	test	r12d,r12d
	jnz	@f
	cstring str_top_clear, 27,'[H',27,'[2J'
	mov	edi,1
	lea	rsi,[str_top_clear]
	mov	edx,str_top_clear.len
	call	write_all
@@:
	pop	rdx
	mov	rsi,[g_admin_buf]
	add	rsi,3				; past its "ok"
	sub	edx,3
	mov	edi,1
	call	write_all
	test	r12d,r12d
	jnz	.done
	lea	rdi,[ts_admin_tick]
	xor	esi,esi
	mov	eax,SYS_nanosleep
	syscall
	jmp	.frame
.done:
	xor	edi,edi
	jmp	exit_process

cli_resume:
	mov	edi,2
	call	cli_source_from_args
	call	api_cli_open
	cstring str_api_resume_l, 'resume',10
	lea	rsi,[str_api_resume_l]
	mov	edx,str_api_resume_l.len
	call	api_call
	mov	edi,1
	call	out_select
	out_lit 'in rotation: /ready answers 200',10
	xor	edi,edi
	jmp	exit_process

; ------------------------------------------------------------ the commands

; `okena reload`: asks, and waits to hear how it went
cli_reload:
	mov	edi,2
	call	cli_source_from_args
	call	api_cli_open
	cstring str_api_state_l, 'state',10
	lea	rsi,[str_api_state_l]
	mov	edx,str_api_state_l.len
	call	api_call
	call	api_cli_state
	mov	[g_cli_t0],eax
	mov	[g_cli_d0],edx
	cstring str_api_reload_l, 'reload',10
	lea	rsi,[str_api_reload_l]
	mov	edx,str_api_reload_l.len
	call	api_call
	mov	r12d,API_POLL_TRIES
.wait:
	lea	rdi,[ts_api_poll]
	xor	esi,esi
	mov	eax,SYS_nanosleep
	syscall
	; (it is replaced as it reloads: not answering for a moment is no news)
	lea	rsi,[str_api_state_l]
	mov	edx,str_api_state_l.len
	call	api_try
	test	eax,eax
	jz	.again
	call	api_cli_state
	cmp	eax,[g_cli_t0]
	je	.again
	cmp	edx,[g_cli_d0]
	je	.failed
	mov	edi,1
	call	out_select
	out_lit 'reloaded',10
	xor	edi,edi
	jmp	exit_process
.again:
	dec	r12d
	jnz	.wait
.failed:
	call	log_begin
	out_lit 'the reload did not take: what runs goes on, and its log says why'
	call	log_end
	mov	edi,1
	jmp	exit_process

; the answer to `state`: eax = tried, edx = done
api_cli_state:
	mov	rsi,[g_admin_buf]
	add	rsi,3
	call	.number
	push	rax
	inc	rsi
	call	.number
	mov	edx,eax
	pop	rax
	ret
.number:
	xor	eax,eax
.digit:
	movzx	ecx,byte [rsi]
	sub	ecx,'0'
	cmp	ecx,9
	ja	.end
	imul	eax,eax,10
	add	eax,ecx
	inc	rsi
	jmp	.digit
.end:
	ret

; `okena backend list|drain|up|weight ...`
cli_backend:
	mov	rcx,[g_argc]
	cmp	rcx,3
	jb	cli_usage
	mov	rax,[g_argv]
	mov	r12,[rax+16]			; what
	mov	r13d,3				; the first word that is not of the line
	mov	rdi,r12
	cstring str_b_list, 'list',0
	lea	rsi,[str_b_list]
	call	cstr_eq
	test	eax,eax
	jnz	.counted
	mov	r13d,5
	mov	rdi,r12
	lea	rsi,[str_api_drain_z]
	call	cstr_eq
	test	eax,eax
	jnz	.counted
	mov	rdi,r12
	lea	rsi,[str_api_up_z]
	call	cstr_eq
	test	eax,eax
	jnz	.counted
	mov	r13d,6
	mov	rdi,r12
	lea	rsi,[str_api_weight_z]
	call	cstr_eq
	test	eax,eax
	jz	cli_usage
.counted:
	cmp	r13,[g_argc]
	ja	cli_usage
	mov	edi,r13d
	call	cli_source_from_args
	; the line
	lea	rdi,[g_admin_req]
	lea	r8,[g_admin_req+4000]
	mov	ecx,2
.word:
	cmp	ecx,r13d
	jae	.line
	mov	rax,[g_argv]
	mov	rsi,[rax+rcx*8]
@@:
	cmp	rdi,r8
	jae	cli_usage
	mov	al,[rsi]
	test	al,al
	jz	@f
	stosb
	inc	rsi
	jmp	@b
@@:
	mov	al,' '
	stosb
	inc	ecx
	jmp	.word
.line:
	mov	byte [rdi-1],10
	mov	r12,rdi
	lea	rax,[g_admin_req]
	sub	r12,rax
	push	r12
	call	api_cli_open
	pop	rdx
	lea	rsi,[g_admin_req]
	call	api_call
	; what it said, past its `ok`
	mov	rsi,[g_admin_buf]
	lea	rdx,[rax-3]
	add	rsi,3
	mov	edi,1
	call	write_all
	xor	edi,edi
	jmp	exit_process

str_api_drain_z	db 'drain',0
str_api_up_z	db 'up',0
str_api_weight_z db 'weight',0

; the configuration, for the path; room for an answer
api_cli_open:
	call	cli_load_config
	call	plan_compile
	cmp	qword [g_plan_api],0
	jne	@f
	call	log_begin
	out_lit 'this needs `admin unix:PATH` in the okena block'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
@@:
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

; rsi/edx = a line: its answer in g_admin_buf, rax = its length, or the
; command ends here saying why
api_call:
	call	api_try
	test	eax,eax
	jnz	@f
	call	log_begin
	out_lit 'no okena answers on the `admin` path'
	call	log_end
	mov	edi,1
	jmp	exit_process
@@:
	mov	rsi,[g_admin_buf]
	cmp	byte [rsi],'o'
	je	.good
	mov	edx,eax
	mov	edi,2
	call	write_all
	mov	edi,1
	jmp	exit_process
.good:
	ret

; rsi/edx = a line: rax = length of the answer, 0 none
api_try:
	push	rbx
	push	r12
	push	r13
	mov	r12,rsi
	mov	r13d,edx
	mov	edi,AF_UNIX
	mov	esi,SOCK_STREAM or SOCK_CLOEXEC
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	.none
	mov	ebx,eax
	mov	edi,ebx
	mov	esi,SOL_SOCKET
	mov	edx,SO_RCVTIMEO
	lea	r10,[ts_admin_io]
	mov	r8d,16
	mov	eax,SYS_setsockopt
	syscall
	call	api_addr
	mov	edx,esi
	mov	edi,ebx
	lea	rsi,[g_api_sa]
	mov	eax,SYS_connect
	syscall
	test	eax,eax
	js	.close
	mov	edi,ebx
	mov	rsi,r12
	mov	edx,r13d
	call	write_all
	xor	r12d,r12d
.read:
	mov	edi,ebx
	mov	rsi,[g_admin_buf]
	add	rsi,r12
	mov	edx,ADMIN_BUF
	sub	edx,r12d
	jz	.close_with
	xor	eax,eax
	syscall
	test	rax,rax
	jle	.close_with
	add	r12d,eax
	jmp	.read
.close_with:
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
	mov	eax,r12d
	jmp	.out
.close:
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
.none:
	xor	eax,eax
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret
