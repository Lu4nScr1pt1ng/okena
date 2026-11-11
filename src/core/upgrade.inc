; `okena upgrade -c FILE`: a new binary takes over with no connection refused or lost.
; execve is forbidden everywhere, so the running okena cannot replace itself: the new
; one is started apart and asks for the listening sockets, over `upgrade PATH` in the
; `okena` block, a Unix socket of mode 0600 that also looks at who is calling. A
; listening socket is the same socket in both, queue included.
;
; The new one has its configuration compiled before it asks for anything. It takes the
; sockets, starts its workers, and only then says it is ready: until that moment the
; old one has lost nothing, and if the new one fails it goes on. Then the old workers
; stop accepting, as in a reload, finish what they have, and the old okena leaves.
;
; A listener the new configuration does not have is closed. QUIC does not move: its
; UDP sockets are opened anew, and its connections do not survive.

MSG_DONTWAIT_	:= 0x40
SOCK_SEQPACKET_	:= 5
SOCK_NONBLOCK_	:= 0x800
SO_PEERCRED_	:= 17
SCM_RIGHTS_	:= 1
SYS_sendmsg_	:= 46
SYS_recvmsg_	:= 47
SYS_getuid_	:= 102
SYS_unlink_	:= 87
SYS_rename_	:= 82
SYS_chmod_	:= 90
UP_TEXT		:= 256

bss
	align 8
	g_plan_up	dq ?			; the path, 0 none
	g_plan_uplen	dd ?
	g_up_mode	dd ?			; 1: this one is taking over
	g_probe_tries	dd ?
	g_up_lfd	dd ?			; the socket it listens on + 1
	g_up_conn	dd ?			; the new one talking to it + 1; or, in the
						; new one, the old one
	g_up_metrics	dd ?			; a metrics socket handed over + 1
	g_up_newpid	dd ?			; the new okena's pid
	g_up_n		dd ?
	g_up_texts:	rb UP_TEXT * MAX_LISTENERS
	g_up_tlen	rd MAX_LISTENERS
	g_up_cnt	rd MAX_LISTENERS
	g_up_fds	rd MAX_LISTENERS * MAX_WORKERS
	g_up_sa:	rb 110
	g_up_tmp:	rb 110
	g_up_cmsg:	rb 16 + 4 * MAX_WORKERS + 8
	g_up_msg:	rq 8
	g_up_iov:	rq 2
	g_up_text:	rb UP_TEXT
	g_up_name:	rb UP_TEXT
end bss

rodata
	up_end		db 'end'
	up_metrics	db 'metrics'
	up_ready	db 'R'
end rodata

; r12d = a listener, rsi/edx = its address as written: what names it between
; two okenas. The same address can be tcp and udp.
up_name:
	imul	rax,r12,LS_SIZE
	cmp	dword [g_listeners+rax+LS_KIND],LK_UDP
	jne	.out
	lea	rdi,[g_up_name]
	mov	dword [rdi],'udp '
	add	rdi,4
	mov	ecx,edx
	cmp	ecx,UP_TEXT - 4
	jbe	@f
	mov	ecx,UP_TEXT - 4
@@:
	lea	edx,[rcx+4]
	rep	movsb
	lea	rsi,[g_up_name]
.out:
	ret

; a helper, starting: the listening sockets are no business of its own, and if it holds
; one past the supervisor's end a connection can land on it, to be reset as it dies
helper_close_sockets:
	call	sd_close_all			; (and systemd's, kept by the supervisor)
	push	rbx
	push	r12
	xor	r12d,r12d
.listener:
	cmp	r12d,[g_plan_listeners]
	jae	.out
	xor	ebx,ebx
.socket:
	cmp	ebx,[g_lsocks+r12*4]
	jae	.next
	mov	eax,r12d
	imul	eax,eax,MAX_WORKERS
	add	eax,ebx
	mov	edi,[g_lfd+rax*4]
	mov	eax,SYS_close
	syscall
	inc	ebx
	jmp	.socket
.next:
	inc	r12d
	jmp	.listener
.out:
	; and those of addresses a reload let go, that the supervisor closes once the
	; old workers are gone: a helper started meanwhile would hold them for ever,
	; and the address could not be listened on again
	xor	ebx,ebx
@@:
	cmp	ebx,[g_close_count]
	jae	@f
	mov	edi,[g_close_fd+rbx*4]
	mov	eax,SYS_close
	syscall
	inc	ebx
	jmp	@b
@@:
	pop	r12
	pop	rbx
	ret

; g_up_sa = sockaddr_un of the path, esi: its length. CF: too long.
up_addr:
	mov	ecx,[g_plan_uplen]
	cmp	ecx,100
	ja	.bad
	mov	word [g_up_sa],AF_UNIX
	lea	rdi,[g_up_sa+2]
	mov	rsi,[g_plan_up]
	rep	movsb
	mov	byte [rdi],0
	mov	esi,[g_plan_uplen]
	add	esi,3
	clc
	ret
.bad:
	stc
	ret

; supervisor, starting: the socket a later one will ask on. Taking over, under a name of
; its own until it is ready: the path must keep working if this one fails.
upgrade_listen:
	cmp	qword [g_plan_up],0
	je	.none
	call	up_addr
	jc	.bad
	push	rsi
	cmp	dword [g_up_mode],0
	je	.plain
	; path.new
	mov	eax,[g_plan_uplen]
	mov	dword [g_up_sa+2+rax],'.new'
	mov	byte [g_up_sa+6+rax],0
	add	dword [rsp],4
.plain:
	lea	rdi,[g_up_sa+2]
	mov	eax,SYS_unlink_
	syscall
	mov	edi,AF_UNIX
	mov	esi,SOCK_SEQPACKET_ or SOCK_CLOEXEC or SOCK_NONBLOCK_
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	pop	rdx
	test	eax,eax
	js	.bad
	mov	[g_up_lfd],eax
	mov	edi,eax
	lea	rsi,[g_up_sa]
	mov	eax,SYS_bind
	syscall
	test	eax,eax
	js	.bad
	lea	rdi,[g_up_sa+2]
	mov	esi,384				; 0600
	mov	eax,SYS_chmod_
	syscall
	mov	edi,[g_up_lfd]
	mov	esi,1
	mov	eax,SYS_listen
	syscall
	test	eax,eax
	js	.bad
	inc	dword [g_up_lfd]
.none:
	ret
.bad:
	call	log_begin
	out_lit 'cannot listen on the `upgrade` path'
	call	log_end
	mov	edi,EXIT_FATAL
	jmp	exit_process

; the supervisor, once a second: someone asking, or the answer of one who asked
upgrade_tick:
	mov	eax,[g_up_conn]
	test	eax,eax
	jnz	.answer
	mov	eax,[g_up_lfd]
	test	eax,eax
	jz	.none
	cmp	dword [g_shutdown],0
	jne	.none
	lea	edi,[rax-1]
	xor	esi,esi
	xor	edx,edx
	mov	r10d,SOCK_CLOEXEC or SOCK_NONBLOCK_
	mov	eax,SYS_accept4
	syscall
	test	eax,eax
	js	.none
	push	rbx
	mov	ebx,eax
	; the same user, or nobody
	sub	rsp,32
	mov	dword [rsp+16],12
	mov	edi,ebx
	mov	esi,SOL_SOCKET
	mov	edx,SO_PEERCRED_
	mov	r10,rsp
	lea	r8,[rsp+16]
	mov	eax,SYS_getsockopt
	syscall
	test	eax,eax
	js	.refuse
	mov	eax,SYS_getuid_
	syscall
	cmp	eax,[rsp+4]
	jne	.refuse
	mov	eax,[rsp]			; (its pid: systemd's MAINPID when it stands)
	mov	[g_up_newpid],eax
	add	rsp,32
	call	up_send_all
	lea	eax,[rbx+1]
	mov	[g_up_conn],eax
	pop	rbx
	call	log_begin
	out_lit 'upgrade: the sockets went to a new okena, which is starting'
	call	log_end
	ret
.refuse:
	add	rsp,32
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
	pop	rbx
	ret
.answer:
	lea	edi,[rax-1]
	lea	rsi,[g_up_text]
	mov	edx,1
	xor	eax,eax				; read
	syscall
	cmp	rax,-11				; EAGAIN
	je	.none
	test	rax,rax
	jle	.lost
	cmp	byte [g_up_text],'R'
	jne	.lost
	; it stands: these finish what they have
	call	log_begin
	out_lit 'upgrade: the new okena is ready: finishing'
	call	log_end
	mov	edi,[g_up_newpid]
	call	sd_mainpid			; (systemd follows the new one)
	mov	dword [g_shutdown],1
	mov	edi,[g_admin_pid]
	test	edi,edi
	jz	@f
	mov	dword [g_admin_pid],0
	mov	esi,SIGKILL
	mov	eax,SYS_kill
	syscall
@@:
	call	retire_workers
	cmp	dword [g_old_count],0
	jne	.none
	mov	edi,[g_exit_code]
	jmp	exit_process
.lost:
	mov	edi,[g_up_conn]
	dec	edi
	mov	dword [g_up_conn],0
	mov	eax,SYS_close
	syscall
	call	log_begin
	out_lit 'upgrade: the new okena is gone: this one goes on'
	call	log_end
.none:
	ret

; ebx = the connection: every listener's sockets, one message each
up_send_all:
	push	r12
	push	r13
	xor	r12d,r12d
.listener:
	cmp	r12d,[g_plan_listeners]
	jae	.metrics
	imul	rax,r12,LS_SIZE
	mov	rsi,[g_listeners+rax+LS_TEXT]
	mov	edx,[g_listeners+rax+LS_TLEN]
	call	up_name
	mov	eax,r12d
	imul	eax,eax,MAX_WORKERS
	lea	rdi,[g_lfd+rax*4]
	mov	ecx,[g_lsocks+r12*4]
	call	up_send
	inc	r12d
	jmp	.listener
.metrics:
	cmp	dword [g_metrics_fd],-1
	je	.end
	lea	rsi,[up_metrics]
	mov	edx,7
	lea	rdi,[g_metrics_fd]
	mov	ecx,1
	call	up_send
.end:
	lea	rsi,[up_end]
	mov	edx,3
	xor	ecx,ecx
	call	up_send
	pop	r13
	pop	r12
	ret

; ebx = connection, rsi/edx = text, rdi = descriptors, ecx = how many
up_send:
	mov	[g_up_iov],rsi
	mov	[g_up_iov+8],rdx
	lea	rax,[g_up_iov]
	xor	r8d,r8d
	mov	[g_up_msg],r8			; no name
	mov	[g_up_msg+8],r8
	mov	[g_up_msg+16],rax
	mov	qword [g_up_msg+24],1
	mov	[g_up_msg+32],r8
	mov	[g_up_msg+40],r8
	mov	[g_up_msg+48],r8
	test	ecx,ecx
	jz	.send
	mov	eax,ecx
	shl	eax,2
	add	eax,16
	mov	[g_up_cmsg],rax
	mov	dword [g_up_cmsg+8],SOL_SOCKET
	mov	dword [g_up_cmsg+12],SCM_RIGHTS_
	mov	rsi,rdi
	lea	rdi,[g_up_cmsg+16]
	rep	movsd
	lea	rcx,[g_up_cmsg]
	mov	[g_up_msg+32],rcx
	add	rax,7
	and	rax,not 7
	mov	[g_up_msg+40],rax
.send:
	mov	edi,ebx
	lea	rsi,[g_up_msg]
	xor	edx,edx
	mov	eax,SYS_sendmsg_
	syscall
	ret

; a new one, before it opens anything: the sockets of the old one
upgrade_receive:
	cmp	dword [g_up_mode],0
	je	.none
	push	r12
	cmp	qword [g_plan_up],0
	je	.no_path
	call	up_addr
	jc	.no_path
	push	rsi
	mov	edi,AF_UNIX
	mov	esi,SOCK_SEQPACKET_ or SOCK_CLOEXEC
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	pop	rdx
	test	eax,eax
	js	.no_old
	mov	r12d,eax
	lea	eax,[r12+1]
	mov	[g_up_conn],eax
	mov	edi,r12d
	lea	rsi,[g_up_sa]
	mov	eax,SYS_connect
	syscall
	test	eax,eax
	js	.no_old
.message:
	lea	rax,[g_up_text]
	mov	[g_up_iov],rax
	mov	qword [g_up_iov+8],UP_TEXT
	xor	eax,eax
	mov	[g_up_msg],rax
	mov	[g_up_msg+8],rax
	lea	rcx,[g_up_iov]
	mov	[g_up_msg+16],rcx
	mov	qword [g_up_msg+24],1
	lea	rcx,[g_up_cmsg]
	mov	[g_up_msg+32],rcx
	mov	qword [g_up_msg+40],16 + 4 * MAX_WORKERS + 8
	mov	[g_up_msg+48],rax
	mov	edi,r12d
	lea	rsi,[g_up_msg]
	xor	edx,edx
	mov	eax,SYS_recvmsg_
	syscall
	test	rax,rax
	jle	.no_old
	cmp	eax,3
	jne	@f
	mov	ecx,dword [g_up_text]
	and	ecx,0xFFFFFF
	cmp	ecx,'end'
	je	.done
@@:
	mov	ecx,eax				; the text's length
	mov	rax,[g_up_cmsg]
	sub	rax,16
	shr	rax,2				; how many
	mov	edx,eax
	cmp	ecx,7
	jne	.listener
	cmp	dword [g_up_text],'metr'
	jne	.listener
	cmp	dword [g_up_text+3],'rics'
	jne	.listener
	mov	eax,[g_up_cmsg+16]
	inc	eax
	mov	[g_up_metrics],eax
	jmp	.message
.listener:
	mov	eax,[g_up_n]
	cmp	eax,MAX_LISTENERS
	jae	.no_old
	inc	dword [g_up_n]
	mov	[g_up_tlen+rax*4],ecx
	mov	[g_up_cnt+rax*4],edx
	mov	r8d,eax
	shl	r8,8				; UP_TEXT
	lea	rdi,[g_up_texts+r8]
	lea	rsi,[g_up_text]
	rep	movsb
	imul	eax,eax,MAX_WORKERS
	lea	rdi,[g_up_fds+rax*4]
	lea	rsi,[g_up_cmsg+16]
	mov	ecx,edx
	rep	movsd
	jmp	.message
.done:
	pop	r12
.none:
	ret
.no_path:
	call	log_begin
	out_lit 'upgrade: this configuration has no `upgrade PATH`'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
.no_old:
	call	log_begin
	out_lit 'upgrade: no okena answers on the `upgrade` path'
	call	log_end
	mov	edi,EXIT_FATAL
	jmp	exit_process
assert UP_TEXT = 256

; edi = a listener: its sockets handed over go into g_lfd. eax = how many, 0 none.
upgrade_taken:
	cmp	dword [g_up_n],0
	je	.none
	push	r12
	mov	r12d,edi
	imul	rax,r12,LS_SIZE
	mov	rsi,[g_listeners+rax+LS_TEXT]
	mov	edx,[g_listeners+rax+LS_TLEN]
	call	up_name
	mov	r8,rsi
	mov	r9d,edx
	xor	r10d,r10d
.next:
	cmp	r10d,[g_up_n]
	jae	.not
	cmp	[g_up_tlen+r10*4],r9d
	jne	.other
	mov	eax,r10d
	shl	rax,8
	lea	rsi,[g_up_texts+rax]
	mov	rdi,r8
	mov	ecx,r9d
	repe	cmpsb
	je	.found
.other:
	inc	r10d
	jmp	.next
.found:
	mov	eax,[g_up_cnt+r10*4]
	mov	dword [g_up_cnt+r10*4],0
	mov	edx,r10d
	imul	edx,edx,MAX_WORKERS
	lea	rsi,[g_up_fds+rdx*4]
	mov	edx,r12d
	imul	edx,edx,MAX_WORKERS
	lea	rdi,[g_lfd+rdx*4]
	mov	ecx,eax
	rep	movsd
	jmp	.out
.not:
	xor	eax,eax
.out:
	pop	r12
	ret
.none:
	xor	eax,eax
	ret

; a new one, its workers started: what is left to the old one's, and the word
upgrade_ready:
	cmp	dword [g_up_mode],0
	je	.none
	; sockets of listeners this configuration does not have
	xor	ecx,ecx
.leftover:
	cmp	ecx,[g_up_n]
	jae	.closed
	mov	edx,[g_up_cnt+rcx*4]
	mov	r8d,ecx
	imul	r8d,r8d,MAX_WORKERS
.fd:
	test	edx,edx
	jz	.next
	dec	edx
	lea	eax,[r8+rdx]
	mov	edi,[g_up_fds+rax*4]
	push	rcx
	push	rdx
	push	r8
	mov	eax,SYS_close
	syscall
	pop	r8
	pop	rdx
	pop	rcx
	jmp	.fd
.next:
	inc	ecx
	jmp	.leftover
.closed:
	; the path, ours from now on
	call	up_addr
	lea	rsi,[g_up_sa+2]
	lea	rdi,[g_up_tmp]
	mov	ecx,[g_plan_uplen]
	rep	movsb
	mov	dword [rdi],'.new'
	mov	byte [rdi+4],0
	lea	rdi,[g_up_tmp]
	lea	rsi,[g_up_sa+2]
	mov	eax,SYS_rename_
	syscall
	mov	edi,[g_up_conn]
	dec	edi
	lea	rsi,[up_ready]
	mov	edx,1
	mov	eax,SYS_write
	syscall
	mov	edi,[g_up_conn]
	dec	edi
	mov	dword [g_up_conn],0
	mov	eax,SYS_close
	syscall
	mov	dword [g_up_mode],0
	call	log_begin
	out_lit 'upgrade: taken over'
	call	log_end
.none:
	ret
