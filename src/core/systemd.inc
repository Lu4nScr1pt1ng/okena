; systemd: socket activation and the notify protocol, with no libsystemd.
;
; Socket activation (LISTEN_PID, LISTEN_FDS): the sockets systemd opened,
; from fd 3 on, are taken by the listeners with the same address and kind
; (a stream for tcp and http, datagrams for udp; ":443" takes a socket on
; any address of that port). systemd's socket is kept as it is, and each
; worker's socket is a dup of it: they all accept from it (a reuseport group
; cannot be joined with another uid than the one that made it), and a reload
; that adds workers or a listener at that address dups it again. A socket
; no listener takes is closed and said; a listener none is there for opens
; its own as ever. QUIC's sockets are okena's.
;
; Notify (NOTIFY_SOCKET): READY=1 once the workers serve, RELOADING=1 (with
; MONOTONIC_USEC, as Type=notify-reload wants) and READY=1 around a reload,
; STOPPING=1 when it stops, WATCHDOG=1 once a second when WATCHDOG_USEC asks,
; and in an upgrade MAINPID= the new okena's, from the old one as it leaves.

SD_LISTEN_FDS_START := 3
SD_MAX		:= 64
SO_TYPE_	:= 3

bss
	align 8
	g_sd_n		dd ?		; sockets systemd gave
	g_sd_fd		rd SD_MAX	; each, -1 once given up
	g_sd_type	rd SD_MAX	; SOCK_STREAM, SOCK_DGRAM
	g_sd_salen	rd SD_MAX
	g_sd_sa		rb SD_MAX * 32
	g_sd_used	rb SD_MAX
	g_sd_nfd	dd ?		; the notify socket, connected; -1 none
	g_sd_dog	dd ?		; WATCHDOG=1 to send each tick
	g_sd_msg	rb 128
	g_sd_un		rb 110
end bss

cstring env_listen_pid, 'LISTEN_PID='
cstring env_listen_fds, 'LISTEN_FDS='
cstring env_notify_socket, 'NOTIFY_SOCKET='
cstring env_watchdog_usec, 'WATCHDOG_USEC='
cstring env_watchdog_pid, 'WATCHDOG_PID='

; rax = a decimal string (NUL-terminated): eax = its value, -1 when not one
sd_number:
	mov	rsi,rax
	xor	eax,eax
	xor	ecx,ecx
@@:
	movzx	edx,byte [rsi+rcx]
	test	edx,edx
	jz	.end
	sub	edx,'0'
	cmp	edx,9
	ja	.bad
	imul	eax,eax,10
	add	eax,edx
	inc	ecx
	cmp	ecx,10
	jb	@b
.bad:
	mov	eax,-1
	ret
.end:
	test	ecx,ecx
	jz	.bad
	ret

; The supervisor, before it opens a listener: what systemd gave, and the
; notify socket
sd_init:
	push	rbx
	mov	dword [g_sd_n],0
	mov	dword [g_sd_nfd],-1
	mov	dword [g_sd_dog],0
	; LISTEN_PID must be this process (else they are another's, inherited)
	lea	rdi,[env_listen_pid]
	mov	esi,env_listen_pid.len
	call	getenv
	test	rax,rax
	jz	.notify
	call	sd_number
	mov	ebx,eax
	mov	eax,SYS_getpid
	syscall
	cmp	eax,ebx
	jne	.notify
	lea	rdi,[env_listen_fds]
	mov	esi,env_listen_fds.len
	call	getenv
	test	rax,rax
	jz	.notify
	call	sd_number
	test	eax,eax
	jle	.notify
	cmp	eax,SD_MAX
	jbe	@f
	mov	eax,SD_MAX
@@:
	mov	[g_sd_n],eax
	xor	ebx,ebx
.fd:
	cmp	ebx,[g_sd_n]
	jae	.fds
	lea	eax,[rbx+SD_LISTEN_FDS_START]
	mov	[g_sd_fd+rbx*4],eax
	mov	byte [g_sd_used+rbx],0
	; its kind, and its address
	sub	rsp,16
	mov	dword [rsp+8],4
	mov	edi,eax
	mov	esi,SOL_SOCKET
	mov	edx,SO_TYPE_
	mov	r10,rsp
	lea	r8,[rsp+8]
	mov	eax,SYS_getsockopt
	syscall
	mov	ecx,[rsp]
	add	rsp,16
	test	eax,eax
	js	.not_socket
	mov	[g_sd_type+rbx*4],ecx
	mov	dword [g_sd_salen+rbx*4],32
	mov	edi,[g_sd_fd+rbx*4]
	imul	rsi,rbx,32
	lea	rsi,[g_sd_sa+rsi]
	lea	rdx,[g_sd_salen+rbx*4]
	mov	eax,SYS_getsockname
	syscall
	test	eax,eax
	js	.not_socket
	; nonblocking, as okena's own (the file description: its dups too)
	mov	edi,[g_sd_fd+rbx*4]
	mov	esi,F_SETFL
	mov	edx,O_NONBLOCK
	mov	eax,SYS_fcntl
	syscall
	inc	ebx
	jmp	.fd
.not_socket:
	mov	dword [g_sd_type+rbx*4],0	; (matches nothing)
	inc	ebx
	jmp	.fd
.fds:
	call	log_begin
	out_lit 'socket activation: '
	mov	eax,[g_sd_n]
	call	out_u64
	out_lit ' socket'
	cmp	dword [g_sd_n],1
	je	@f
	out_lit 's'
@@:
	out_lit ' from systemd'
	call	log_end
.notify:
	lea	rdi,[env_notify_socket]
	mov	esi,env_notify_socket.len
	call	getenv
	test	rax,rax
	jz	.out
	; its address: a path, or "@name" in the abstract namespace
	mov	rsi,rax
	lea	rdi,[g_sd_un]
	mov	word [rdi],AF_UNIX
	xor	ecx,ecx
@@:
	mov	al,[rsi+rcx]
	test	al,al
	jz	@f
	cmp	ecx,107
	jae	.out
	mov	[rdi+2+rcx],al
	inc	ecx
	jmp	@b
@@:
	test	ecx,ecx
	jz	.out
	cmp	byte [rdi+2],'@'
	jne	@f
	mov	byte [rdi+2],0
@@:
	lea	ebx,[rcx+2]			; its length
	mov	edi,AF_UNIX
	mov	esi,SOCK_DGRAM or SOCK_CLOEXEC
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	.out
	mov	[g_sd_nfd],eax
	mov	edi,eax
	lea	rsi,[g_sd_un]
	mov	edx,ebx
	mov	eax,SYS_connect
	syscall
	test	eax,eax
	jns	.dog
	mov	edi,[g_sd_nfd]
	mov	eax,SYS_close
	syscall
	mov	dword [g_sd_nfd],-1
	jmp	.out
.dog:
	; the watchdog: asked for this process (or for whichever is main)
	lea	rdi,[env_watchdog_usec]
	mov	esi,env_watchdog_usec.len
	call	getenv
	test	rax,rax
	jz	.out
	lea	rdi,[env_watchdog_pid]
	mov	esi,env_watchdog_pid.len
	push	rax
	call	getenv
	test	rax,rax
	jz	@f
	call	sd_number
	mov	ebx,eax
	mov	eax,SYS_getpid
	syscall
	cmp	eax,ebx
	jne	.no_dog
@@:
	pop	rax
	mov	dword [g_sd_dog],1
	jmp	.out
.no_dog:
	pop	rax
.out:
	pop	rbx
	ret

; edi = a listener: eax = a dup of systemd's socket for it, or -1 (none)
sd_socket:
	cmp	dword [g_sd_n],0
	jne	@f
	mov	eax,-1
	ret
@@:
	call	sd_find
	test	eax,eax
	js	.none
	mov	byte [g_sd_used+rax],1
	mov	edi,[g_sd_fd+rax*4]
	mov	eax,SYS_dup
	syscall
.none:
	ret

; edi = a listener: eax = the index of systemd's socket for it, or -1
sd_find:
	push	rbx
	push	r12
	imul	r12,rdi,LS_SIZE
	lea	r12,[g_listeners+r12]
	mov	ecx,SOCK_STREAM
	cmp	dword [r12+LS_KIND],LK_UDP
	jne	@f
	mov	ecx,SOCK_DGRAM
@@:
	xor	ebx,ebx
.next:
	cmp	ebx,[g_sd_n]
	jae	.none
	cmp	[g_sd_type+rbx*4],ecx
	jne	.other
	imul	rsi,rbx,32
	lea	rsi,[g_sd_sa+rsi]
	; the port first (both families keep it at 2)
	mov	ax,[rsi+2]
	cmp	ax,[r12+LS_SA+2]
	jne	.other
	cmp	dword [r12+LS_FAMILY],0
	je	.any				; ":port": a socket on any address
	movzx	eax,word [rsi]
	cmp	eax,[r12+LS_FAMILY]
	jne	.other
	cmp	eax,AF_INET
	jne	.v6
	mov	eax,[rsi+4]
	cmp	eax,[r12+LS_SA+4]
	jne	.other
	jmp	.found
.v6:
	mov	rax,[rsi+8]
	cmp	rax,[r12+LS_SA+8]
	jne	.other
	mov	rax,[rsi+16]
	cmp	rax,[r12+LS_SA+16]
	jne	.other
	jmp	.found
.any:
	cmp	word [rsi],AF_INET
	jne	@f
	cmp	dword [rsi+4],0
	je	.found
	jmp	.other
@@:
	mov	rax,[rsi+8]
	or	rax,[rsi+16]
	jz	.found
.other:
	inc	ebx
	jmp	.next
.found:
	mov	eax,ebx
	jmp	.out
.none:
	mov	eax,-1
.out:
	pop	r12
	pop	rbx
	ret

; The supervisor, its listeners open: systemd's sockets none took, closed
; and said
sd_leftovers:
	push	rbx
	xor	ebx,ebx
.next:
	cmp	ebx,[g_sd_n]
	jae	.out
	cmp	byte [g_sd_used+rbx],0
	jne	.used
	call	log_begin
	out_lit 'socket activation: fd '
	mov	eax,[g_sd_fd+rbx*4]
	call	out_u64
	out_lit ' is no listener'
	out_lit 0x27,'s (address and kind); closed'
	call	log_end
	mov	edi,[g_sd_fd+rbx*4]
	mov	eax,SYS_close
	syscall
	mov	dword [g_sd_type+rbx*4],0
.used:
	inc	ebx
	jmp	.next
.out:
	pop	rbx
	ret

; A helper, starting: systemd's sockets are none of its business
sd_close_all:
	xor	ecx,ecx
.next:
	cmp	ecx,[g_sd_n]
	jae	.out
	push	rcx
	mov	edi,[g_sd_fd+rcx*4]
	mov	eax,SYS_close
	syscall
	pop	rcx
	inc	ecx
	jmp	.next
.out:
	mov	dword [g_sd_n],0
	ret

; rsi/edx = a notify message: to systemd, when it listens
sd_notify:
	mov	edi,[g_sd_nfd]
	test	edi,edi
	js	.out
	mov	eax,SYS_write
	syscall
.out:
	ret

; The workers serve
sd_ready:
	cmp	dword [g_sd_nfd],0
	jl	.out
	lea	rdi,[g_sd_msg]
	memit 'READY=1',10,'MAINPID='
	mov	eax,[g_sup_pid]			; (no getpid: the supervisor's filter has it not)
	call	fmt_u64
	memit 10,'STATUS=serving with '
	mov	eax,[g_workers]
	call	fmt_u64
	memit ' workers'
	lea	rsi,[g_sd_msg]
	mov	rdx,rdi
	sub	rdx,rsi
	call	sd_notify
.out:
	ret

; A reload begins
sd_reloading:
	cmp	dword [g_sd_nfd],0
	jl	.out
	lea	rdi,[g_sd_msg]
	memit 'RELOADING=1',10,'STATUS=reloading',10,'MONOTONIC_USEC='
	push	rdi
	sub	rsp,16
	mov	edi,CLOCK_MONOTONIC
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	imul	rax,[rsp],1000000
	mov	rcx,[rsp+8]
	add	rsp,16
	push	rax
	mov	rax,rcx
	xor	edx,edx
	mov	ecx,1000
	div	rcx
	pop	rcx
	add	rax,rcx
	pop	rdi
	call	fmt_u64
	lea	rsi,[g_sd_msg]
	mov	rdx,rdi
	sub	rdx,rsi
	call	sd_notify
.out:
	ret

; It stops
sd_stopping:
	cstring sd_msg_stop, 'STOPPING=1',10,'STATUS=stopping'
	lea	rsi,[sd_msg_stop]
	mov	edx,sd_msg_stop.len
	jmp	sd_notify

; Each tick
sd_tick:
	cmp	dword [g_sd_dog],0
	je	.out
	cstring sd_msg_dog, 'WATCHDOG=1'
	lea	rsi,[sd_msg_dog]
	mov	edx,sd_msg_dog.len
	jmp	sd_notify
.out:
	ret

; edi = the new okena's pid (an upgrade, as the old one leaves): it is the
; main process now
sd_mainpid:
	cmp	dword [g_sd_nfd],0
	jl	.out
	push	rdi
	lea	rdi,[g_sd_msg]
	memit 'MAINPID='
	pop	rax
	call	fmt_u64
	memit 10,'STATUS=handed over to a new binary'
	lea	rsi,[g_sd_msg]
	mov	rdx,rdi
	sub	rdx,rsi
	call	sd_notify
.out:
	ret
