; `vrrp IFACE vrid=N priority=N address=A/N [advert=1s] [preempt=off] [track=POOL]`:
; a floating address for a pair (or more) of okenas without BGP, VRRP version 3
; (RFC 9568) as keepalived beside HAProxy does it. The master holds the address on
; the interface and says so every advert to 224.0.0.18 (IP protocol 112, TTL 255);
; when its adverts stop, the backup with the highest priority takes the address,
; and a gratuitous ARP tells the network where it is now. The real MAC answers for
; it (no virtual MAC), as keepalived does by default.
;
; Health decides too: okena that cannot take traffic (as /ready says: draining, or
; the track= pool with no server up, worked out by the admin process into the
; shared AP_VREADY) gives the address up with an advert of priority 0, so a backup
; takes it at once, and as a backup it does not take it.
;
; A process of its own, okena-vrrp, root (raw and packet sockets, the address
; added and removed over netlink) but confined like the others. A reload that
; leaves `vrrp` as it was keeps it, and its state; one that changes it starts a new
; one. A stop gives the address up first.

VR_BACKUP	:= 1
VR_MASTER	:= 2
VR_GROUP	:= 0x120000E0			; 224.0.0.18, network order
VR_PROTO	:= 112
VR_CHECK_MS	:= 100				; health looked at this often
AF_NETLINK_	:= 16
AF_PACKET_	:= 17
SOCK_RAW_	:= 3
IP_MCAST_IF	:= 32
IP_MCAST_TTL	:= 33
IP_MCAST_LOOP	:= 34
IP_ADD_MEMB	:= 35
SO_BINDDEV	:= 25
SIOCGIFINDEX_	:= 0x8933
SIOCGIFADDR_	:= 0x8915
SIOCGIFHWADDR_	:= 0x8927
RTM_NEWADDR_	:= 20
RTM_DELADDR_	:= 21
SYS_ioctl_	:= 16
AP_VREADY	:= 24				; (api.inc's page) 1 ready, 2 not, 0 not known yet

; the plan's
VC_ON		:= 0				; d
VC_IFLEN	:= 4				; d
VC_IF		:= 8				; 16, NUL-ended
VC_VRID		:= 24				; d
VC_PRIO		:= 28				; d
VC_ADDR		:= 32				; d, network order
VC_PLEN		:= 36				; d
VC_ADVERT	:= 40				; d: centiseconds
VC_PREEMPT	:= 44				; d
VC_TRACKL	:= 48				; d
VC_TRACK	:= 56				; q
VC_SIZE		:= 64

bss
	align 8
	g_plan_vrrp:	rb VC_SIZE
	g_vrrp_pid	dd ?			; supervisor: the vrrp process, 0 none
	g_vrrp_conf:	rb VC_SIZE		; supervisor: what the one running was started with
	g_vr_raw	dd ?
	g_vr_nl		dd ?
	g_vr_pkt	dd ?
	g_vr_sig	dd ?
	g_vr_ifindex	dd ?
	g_vr_me		dd ?			; the interface's own address
	g_vr_state	dd ?
	g_vr_mai	dd ?			; the master's advert interval, cs
	g_vr_seq	dd ?
	align 8
	g_vr_now	dq ?			; ms
	g_vr_down	dq ?			; ms: a backup takes over then
	g_vr_next	dq ?			; ms: a master's next advert
	g_vr_mac:	rb 8
	g_vr_ifr:	rb 40			; struct ifreq
	g_vr_buf:	rb 2048
	g_vr_pfd:	rq 2
	g_vr_ts		rq 2
	g_vr_sigset	dq ?
end bss

rodata
	vrrp_name	db 'okena-vrrp',0
end rodata

; ------------------------------------------------------------ supervisor

spawn_vrrp:
	cmp	dword [g_plan_vrrp+VC_ON],0
	je	.none
	lea	rsi,[g_plan_vrrp]
	lea	rdi,[g_vrrp_conf]
	mov	ecx,VC_SIZE
	rep	movsb
	mov	eax,SYS_fork
	syscall
	test	rax,rax
	jz	vrrp_main
	js	.none
	mov	[g_vrrp_pid],eax
.none:
	ret

; a reload: a vrrp that changed starts again; one as it was goes on
vrrp_reload:
	mov	edi,[g_vrrp_pid]
	test	edi,edi
	jz	spawn_vrrp
	lea	rsi,[g_plan_vrrp]
	lea	rdi,[g_vrrp_conf]
	mov	ecx,VC_SIZE - 16		; (the pool's name is a pointer: its text below)
	repe	cmpsb
	jne	.again
	mov	ecx,[g_plan_vrrp+VC_TRACKL]
	cmp	ecx,[g_vrrp_conf+VC_TRACKL]
	jne	.again
	ret					; (the same: the one running keeps its state)
.again:
	mov	edi,[g_vrrp_pid]
	mov	dword [g_vrrp_pid],0
	call	vrrp_stop_pid
	jmp	spawn_vrrp

; stopping: it gives the address up and goes (5 s at most)
vrrp_finish:
	mov	edi,[g_vrrp_pid]
	test	edi,edi
	jz	.none
	mov	dword [g_vrrp_pid],0
	jmp	vrrp_stop_pid
.none:
	ret

; edi = the pid: SIGTERM, then waited for
vrrp_stop_pid:
	push	rbx
	mov	ebx,edi
	mov	esi,SIGTERM
	mov	eax,SYS_kill
	syscall
	mov	ecx,500
.wait:
	push	rcx
	mov	edi,P_PID
	mov	esi,ebx
	lea	rdx,[g_siginfo]
	mov	r10d,WEXITED or WNOHANG
	xor	r8d,r8d
	mov	dword [g_siginfo+SI_PID],0
	mov	eax,SYS_waitid
	syscall
	pop	rcx
	test	rax,rax
	js	.gone
	cmp	dword [g_siginfo+SI_PID],0
	jne	.gone
	push	rcx
	lea	rdi,[keeper_finish.tick]
	xor	esi,esi
	mov	eax,SYS_nanosleep
	syscall
	pop	rcx
	dec	ecx
	jnz	.wait
	mov	edi,ebx
	mov	esi,SIGKILL
	mov	eax,SYS_kill
	syscall
.gone:
	pop	rbx
	ret

; ------------------------------------------------------- the admin process

; once a tick: AP_VREADY for the vrrp process
vrrp_ready_tick:
	cmp	dword [g_plan_vrrp+VC_ON],0
	je	.none
	mov	rax,[g_plan_vrrp+VC_TRACK]
	mov	ecx,[g_plan_vrrp+VC_TRACKL]
	push	qword [g_plan_birdpool]
	push	qword [g_plan_birdpooll]
	mov	[g_plan_birdpool],rax		; (bird_ready, on this pool)
	mov	[g_plan_birdpooll],ecx
	call	bird_ready
	pop	qword [g_plan_birdpooll]
	pop	qword [g_plan_birdpool]
	mov	ecx,2
	sub	ecx,eax
	mov	rdx,[g_api_ov]
	mov	[rdx+AP_VREADY],ecx
.none:
	ret

; ------------------------------------------------------------- the process

; g_vr_now = ms (monotonic)
vr_clock:
	sub	rsp,16
	mov	edi,CLOCK_MONOTONIC
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	imul	rax,[rsp],1000
	mov	rcx,rax
	mov	rax,[rsp+8]
	xor	edx,edx
	mov	r8d,1000000
	div	r8
	add	rax,rcx
	mov	[g_vr_now],rax
	add	rsp,16
	ret

; eax = an ioctl on the interface (g_vr_ifr, a datagram socket): CF failed
vr_ifioctl:
	push	rax
	mov	edi,AF_INET
	mov	esi,SOCK_DGRAM or SOCK_CLOEXEC
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	pop	rsi
	test	eax,eax
	js	.bad
	push	rax
	mov	edi,eax
	lea	rdx,[g_vr_ifr]
	mov	eax,SYS_ioctl_
	syscall
	pop	rdi
	push	rax
	mov	eax,SYS_close
	syscall
	pop	rax
	test	eax,eax
	js	.bad
	clc
	ret
.bad:
	stc
	ret

; ms of the master down interval: 3 * its interval + skew (RFC 9568 6.1)
vr_down_ms:
	mov	eax,256
	sub	eax,[g_plan_vrrp+VC_PRIO]
	imul	eax,[g_vr_mai]
	shr	eax,8				; skew, cs
	mov	ecx,[g_vr_mai]
	lea	ecx,[rcx*2+rcx]
	add	eax,ecx
	imul	eax,eax,10
	ret

; Never returns.
vrrp_main:
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
	lea	rsi,[vrrp_name]
	mov	eax,SYS_prctl
	syscall
	; told to go: a signalfd
	mov	qword [g_vr_sigset],(1 shl (SIGTERM-1)) or (1 shl (SIGINT-1))
	mov	edi,-1
	lea	rsi,[g_vr_sigset]
	mov	edx,8
	mov	r10d,SFD_CLOEXEC
	mov	eax,SYS_signalfd4
	syscall
	test	eax,eax
	js	.fatal
	mov	[g_vr_sig],eax
	; the interface: its index, its address, its MAC
	lea	rdi,[g_vr_ifr]
	xor	eax,eax
	mov	ecx,40
	rep	stosb
	lea	rdi,[g_vr_ifr]
	lea	rsi,[g_plan_vrrp+VC_IF]
	mov	ecx,16
	rep	movsb
	mov	eax,SIOCGIFINDEX_
	call	vr_ifioctl
	jc	.no_if
	mov	eax,[g_vr_ifr+16]
	mov	[g_vr_ifindex],eax
	mov	eax,SIOCGIFADDR_
	call	vr_ifioctl
	jc	.no_addr
	mov	eax,[g_vr_ifr+16+4]		; (sockaddr_in: its address)
	mov	[g_vr_me],eax
	mov	eax,SIOCGIFHWADDR_
	call	vr_ifioctl
	jc	.no_if
	mov	rax,[g_vr_ifr+16+2]
	mov	[g_vr_mac],rax
	; the adverts' socket: on this interface, in the group, TTL 255, not back to us
	mov	edi,AF_INET
	mov	esi,SOCK_RAW_ or SOCK_CLOEXEC
	mov	edx,VR_PROTO
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	.no_sock
	mov	[g_vr_raw],eax
	mov	edi,eax
	mov	esi,SOL_SOCKET
	mov	edx,SO_BINDDEV
	lea	r10,[g_plan_vrrp+VC_IF]
	mov	r8d,[g_plan_vrrp+VC_IFLEN]
	inc	r8d
	mov	eax,SYS_setsockopt
	syscall
	test	eax,eax
	js	.no_sock
	sub	rsp,16				; struct ip_mreqn: group, address, ifindex
	mov	dword [rsp],VR_GROUP
	mov	eax,[g_vr_me]
	mov	[rsp+4],eax
	mov	eax,[g_vr_ifindex]
	mov	[rsp+8],eax
	mov	edi,[g_vr_raw]
	mov	esi,IPPROTO_IP
	mov	edx,IP_ADD_MEMB
	mov	r10,rsp
	mov	r8d,12
	mov	eax,SYS_setsockopt
	syscall
	test	eax,eax
	js	.no_group
	mov	edi,[g_vr_raw]
	mov	esi,IPPROTO_IP
	mov	edx,IP_MCAST_IF
	mov	r10,rsp
	mov	r8d,12
	mov	eax,SYS_setsockopt
	syscall
	mov	dword [rsp],255
	mov	edi,[g_vr_raw]
	mov	esi,IPPROTO_IP
	mov	edx,IP_MCAST_TTL
	mov	r10,rsp
	mov	r8d,4
	mov	eax,SYS_setsockopt
	syscall
	mov	dword [rsp],0
	mov	edi,[g_vr_raw]
	mov	esi,IPPROTO_IP
	mov	edx,IP_MCAST_LOOP
	mov	r10,rsp
	mov	r8d,4
	mov	eax,SYS_setsockopt
	syscall
	add	rsp,16
	; the address, over netlink; gratuitous ARP, over a packet socket
	mov	edi,AF_NETLINK_
	mov	esi,SOCK_RAW_ or SOCK_CLOEXEC
	xor	edx,edx				; NETLINK_ROUTE
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	.no_sock
	mov	[g_vr_nl],eax
	mov	edi,AF_PACKET_
	mov	esi,SOCK_RAW_ or SOCK_CLOEXEC
	mov	edx,0x0608			; htons(ETH_P_ARP)
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	.no_sock
	mov	[g_vr_pkt],eax
	call	ll_confine_none
	seccomp_for filter_vrrp
	; Initialize (RFC 9568 6.4.1): a backup, the master's interval ours
	mov	eax,[g_plan_vrrp+VC_ADVERT]
	mov	[g_vr_mai],eax
	call	vr_clock
	call	vr_to_backup
	call	log_begin
	out_lit 'vrrp: '
	call	vr_out_name
	out_lit ' backup'
	call	log_end
	; (an owner of the address, priority 255, is the master at once)
	cmp	dword [g_plan_vrrp+VC_PRIO],255
	jne	.loop
	mov	rax,[g_vr_now]
	mov	[g_vr_down],rax
.loop:
	call	vr_clock
	call	vr_step
	; wait: a packet, a signal, or the next thing to do (VR_CHECK_MS at most)
	mov	eax,[g_vr_raw]
	mov	[g_vr_pfd],eax
	mov	word [g_vr_pfd+4],POLLIN_
	mov	word [g_vr_pfd+6],0
	mov	eax,[g_vr_sig]
	mov	[g_vr_pfd+8],eax
	mov	word [g_vr_pfd+12],POLLIN_
	mov	word [g_vr_pfd+14],0
	call	vr_wait_ms
	xor	edx,edx
	mov	ecx,1000
	div	rcx
	mov	[g_vr_ts],rax
	imul	rdx,rdx,1000000
	mov	[g_vr_ts+8],rdx
	lea	rdi,[g_vr_pfd]
	mov	esi,2
	lea	rdx,[g_vr_ts]
	xor	r10d,r10d
	xor	r8d,r8d
	mov	eax,SYS_ppoll_
	syscall
	test	eax,eax
	jle	.loop
	cmp	word [g_vr_pfd+14],0
	jne	.leave
	cmp	word [g_vr_pfd+6],0
	je	.loop
	call	vr_receive
	jmp	.loop
.leave:
	cmp	dword [g_vr_state],VR_MASTER
	jne	@f
	xor	ecx,ecx				; priority 0: the others take it now
	call	vr_send
	mov	esi,RTM_DELADDR_
	call	vr_address
	call	log_begin
	out_lit 'vrrp: '
	call	vr_out_name
	out_lit ' given up (stopping)'
	call	log_end
@@:
	xor	edi,edi
	jmp	exit_process
.no_if:
	call	log_begin
	out_lit 'vrrp: no such interface: '
	jmp	.say_if
.no_addr:
	call	log_begin
	out_lit 'vrrp: the interface has no IPv4 address of its own: '
.say_if:
	lea	rsi,[g_plan_vrrp+VC_IF]
	mov	edx,[g_plan_vrrp+VC_IFLEN]
	call	out_str
	jmp	.out_end
.no_group:
	add	rsp,16
.no_sock:
	call	log_begin
	out_lit 'vrrp: its sockets cannot be had (it needs to run as root)'
	jmp	.out_end
.fatal:
	call	log_begin
	out_lit 'vrrp: cannot start'
.out_end:
	call	log_end
	; (not started again and again: it waits to be told to go)
	mov	qword [g_ck_ts],3600
	mov	qword [g_ck_ts+8],0
@@:
	lea	rdi,[g_vr_sigset]
	xor	esi,esi
	lea	rdx,[g_ck_ts]
	mov	r10d,8
	mov	eax,SYS_rt_sigtimedwait
	syscall
	test	rax,rax
	jle	@b
	xor	edi,edi
	jmp	exit_process

; rax = ms until the next thing to do, VR_CHECK_MS at most
vr_wait_ms:
	mov	rax,[g_vr_down]
	cmp	dword [g_vr_state],VR_MASTER
	jne	@f
	mov	rax,[g_vr_next]
@@:
	sub	rax,[g_vr_now]
	jg	@f
	xor	eax,eax
@@:
	cmp	rax,VR_CHECK_MS
	jbe	@f
	mov	eax,VR_CHECK_MS
@@:
	ret

; eax = 1 when okena can take traffic (AP_VREADY)
macro vr_is_ready
	mov	rax,[g_api_ov]
	cmp	dword [rax+AP_VREADY],1
	sete	al
	movzx	eax,al
end macro

; the timers, and health
vr_step:
	vr_is_ready
	cmp	dword [g_vr_state],VR_MASTER
	jne	.backup
	test	eax,eax
	jnz	.adverts
	; a master that cannot take traffic gives the address up
	xor	ecx,ecx
	call	vr_send
	call	vr_to_backup
	call	log_begin
	out_lit 'vrrp: '
	call	vr_out_name
	out_lit ' given up: okena cannot take traffic'
	call	log_end
	ret
.adverts:
	mov	rax,[g_vr_now]
	cmp	rax,[g_vr_next]
	jb	.out
	mov	ecx,[g_plan_vrrp+VC_PRIO]
	call	vr_send
	mov	eax,[g_plan_vrrp+VC_ADVERT]
	imul	eax,eax,10
	add	rax,[g_vr_now]
	mov	[g_vr_next],rax
	ret
.backup:
	mov	rcx,[g_vr_now]
	cmp	rcx,[g_vr_down]
	jb	.out
	test	eax,eax
	jz	.wait_more			; (the master is gone, but this one cannot serve)
	jmp	vr_to_master
.wait_more:
	call	vr_down_ms
	add	rax,[g_vr_now]
	mov	[g_vr_down],rax
.out:
	ret

; a backup now: the address off, the master awaited
vr_to_backup:
	cmp	dword [g_vr_state],VR_MASTER
	jne	@f
	mov	esi,RTM_DELADDR_
	call	vr_address
@@:
	mov	dword [g_vr_state],VR_BACKUP
	call	vr_down_ms
	add	rax,[g_vr_now]
	mov	[g_vr_down],rax
	ret

; the master now: the address on, an advert, gratuitous ARP
vr_to_master:
	mov	dword [g_vr_state],VR_MASTER
	mov	esi,RTM_NEWADDR_
	call	vr_address
	mov	ecx,[g_plan_vrrp+VC_PRIO]
	call	vr_send
	call	vr_garp
	call	vr_garp
	mov	eax,[g_plan_vrrp+VC_ADVERT]
	imul	eax,eax,10
	add	rax,[g_vr_now]
	mov	[g_vr_next],rax
	call	log_begin
	out_lit 'vrrp: '
	call	vr_out_name
	out_lit ' master: the address is here'
	call	log_end
	ret

; the address and the vrid, for the log
vr_out_name:
	out_lit 'vrid '
	mov	eax,[g_plan_vrrp+VC_VRID]
	call	out_u64
	ret

; ecx = priority: an advert (RFC 9568 5.1), the address in it
vr_send:
	lea	rdi,[g_vr_buf]
	mov	byte [rdi],0x31			; version 3, advertisement
	mov	eax,[g_plan_vrrp+VC_VRID]
	mov	[rdi+1],al
	mov	[rdi+2],cl
	mov	byte [rdi+3],1			; one address
	mov	eax,[g_plan_vrrp+VC_ADVERT]
	and	eax,0x0FFF
	xchg	al,ah
	mov	[rdi+4],ax
	mov	word [rdi+6],0
	mov	eax,[g_plan_vrrp+VC_ADDR]
	mov	[rdi+8],eax
	; its checksum, over the pseudo-header too (version 3)
	mov	esi,12
	call	vr_checksum
	mov	[g_vr_buf+6],ax
	sub	rsp,16				; sockaddr_in: the group
	mov	word [rsp],AF_INET
	mov	word [rsp+2],0
	mov	dword [rsp+4],VR_GROUP
	mov	qword [rsp+8],0
	mov	edi,[g_vr_raw]
	lea	rsi,[g_vr_buf]
	mov	edx,12
	xor	r10d,r10d
	mov	r8,rsp
	mov	r9d,16
	mov	eax,SYS_sendto
	syscall
	add	rsp,16
	ret

; g_vr_buf/esi = a VRRP message (its checksum field 0), sent from g_vr_me to the
; group: ax = its checksum, network order
vr_checksum:
	xor	eax,eax
	mov	ecx,[g_vr_me]			; the pseudo-header: source, destination,
	call	.add32				; zero, protocol, length
	mov	ecx,VR_GROUP
	call	.add32
	add	eax,VR_PROTO shl 8		; (bytes 0, 112 as a big-endian word, swapped)
	mov	ecx,esi
	xchg	cl,ch
	add	eax,ecx
	lea	rdx,[g_vr_buf]
	xor	ecx,ecx
@@:
	cmp	ecx,esi
	jae	@f
	movzx	r8d,word [rdx+rcx]
	add	eax,r8d
	add	ecx,2
	jmp	@b
@@:
	; fold
	mov	ecx,eax
	shr	ecx,16
	and	eax,0xFFFF
	add	eax,ecx
	mov	ecx,eax
	shr	ecx,16
	add	eax,ecx
	not	eax
	and	eax,0xFFFF
	ret
; ecx = 4 bytes as they are in memory: their two words added
.add32:
	mov	r8d,ecx
	and	r8d,0xFFFF
	add	eax,r8d
	shr	ecx,16
	add	eax,ecx
	ret

; an advert came: what it says
vr_receive:
	mov	edi,[g_vr_raw]
	lea	rsi,[g_vr_buf]
	mov	edx,2048
	xor	r10d,r10d
	xor	r8d,r8d
	xor	r9d,r9d
	mov	eax,SYS_recvfrom
	syscall
	cmp	eax,20 + 8
	jl	.drop
	lea	rsi,[g_vr_buf]
	movzx	ecx,byte [rsi]
	and	ecx,15
	shl	ecx,2				; its IP header
	cmp	byte [rsi+8],255		; TTL 255: from this link (RFC 9568 7.1)
	jne	.drop
	cmp	byte [rsi+9],VR_PROTO
	jne	.drop
	mov	r9d,[rsi+12]			; who sent it
	cmp	r9d,[g_vr_me]
	je	.drop
	lea	edx,[ecx+8]
	cmp	edx,eax
	ja	.drop
	add	rsi,rcx				; the advert
	sub	eax,ecx
	cmp	byte [rsi],0x31
	jne	.drop
	movzx	edx,byte [rsi+1]
	cmp	edx,[g_plan_vrrp+VC_VRID]
	jne	.drop
	movzx	r10d,byte [rsi+2]		; its priority
	movzx	r11d,byte [rsi+4]
	and	r11d,0x0F
	shl	r11d,8
	movzx	ecx,byte [rsi+5]
	or	r11d,ecx			; its interval, cs
	cmp	dword [g_vr_state],VR_MASTER
	jne	.as_backup
	; a master: one with priority 0 is going; a higher one (or as high, from a
	; higher address) takes over
	test	r10d,r10d
	jnz	@f
	mov	ecx,[g_plan_vrrp+VC_PRIO]
	jmp	vr_send
@@:
	cmp	r10d,[g_plan_vrrp+VC_PRIO]
	ja	.yield
	jb	.drop
	bswap	r9d
	mov	eax,[g_vr_me]
	bswap	eax
	cmp	r9d,eax
	jbe	.drop
.yield:
	test	r11d,r11d
	jz	@f
	mov	[g_vr_mai],r11d
@@:
	call	vr_to_backup
	call	log_begin
	out_lit 'vrrp: '
	call	vr_out_name
	out_lit ' backup: a master of higher priority'
	call	log_end
	ret
.as_backup:
	test	r10d,r10d
	jnz	@f
	; the master is going: take over after the skew only
	mov	eax,256
	sub	eax,[g_plan_vrrp+VC_PRIO]
	imul	eax,[g_vr_mai]
	shr	eax,8
	imul	eax,eax,10
	add	rax,[g_vr_now]
	mov	[g_vr_down],rax
	ret
@@:
	cmp	dword [g_plan_vrrp+VC_PREEMPT],0
	je	.follow
	cmp	r10d,[g_plan_vrrp+VC_PRIO]
	jb	.drop				; a lower master: this one will take over
.follow:
	test	r11d,r11d
	jz	@f
	mov	[g_vr_mai],r11d
@@:
	call	vr_down_ms
	add	rax,[g_vr_now]
	mov	[g_vr_down],rax
.drop:
	ret

; esi = RTM_NEWADDR or RTM_DELADDR: the address on the interface, or off it
vr_address:
	lea	rdi,[g_vr_buf]
	mov	dword [rdi],40			; nlmsghdr: length
	mov	[rdi+4],si			; type
	mov	word [rdi+6],0x0001 or 0x0004 or 0x0400 or 0x0100	; REQUEST ACK CREATE REPLACE
	cmp	esi,RTM_DELADDR_
	jne	@f
	mov	word [rdi+6],0x0001 or 0x0004
@@:
	inc	dword [g_vr_seq]
	mov	eax,[g_vr_seq]
	mov	[rdi+8],eax
	mov	dword [rdi+12],0
	mov	byte [rdi+16],AF_INET		; ifaddrmsg
	mov	eax,[g_plan_vrrp+VC_PLEN]
	mov	[rdi+17],al
	mov	word [rdi+18],0			; flags, scope universe
	mov	eax,[g_vr_ifindex]
	mov	[rdi+20],eax
	mov	dword [rdi+24],0x00020008	; IFA_LOCAL, 8
	mov	eax,[g_plan_vrrp+VC_ADDR]
	mov	[rdi+28],eax
	mov	dword [rdi+32],0x00010008	; IFA_ADDRESS, 8
	mov	[rdi+36],eax
	sub	rsp,16				; sockaddr_nl: the kernel
	mov	word [rsp],AF_NETLINK_
	mov	word [rsp+2],0
	mov	qword [rsp+4],0
	mov	dword [rsp+12],0
	mov	edi,[g_vr_nl]
	lea	rsi,[g_vr_buf]
	mov	edx,40
	xor	r10d,r10d
	mov	r8,rsp
	mov	r9d,12
	mov	eax,SYS_sendto
	syscall
	add	rsp,16
	; its answer (there or not there already: the same)
	mov	edi,[g_vr_nl]
	lea	rsi,[g_vr_buf]
	mov	edx,512
	mov	r10d,MSG_DONTWAIT
	xor	r8d,r8d
	xor	r9d,r9d
	mov	eax,SYS_recvfrom
	syscall
	ret

; a gratuitous ARP for the address: who has it, from the one that has it now
vr_garp:
	lea	rdi,[g_vr_buf]
	mov	dword [rdi],-1			; to all
	mov	word [rdi+4],-1
	mov	eax,dword [g_vr_mac]
	mov	[rdi+6],eax
	mov	ax,word [g_vr_mac+4]
	mov	[rdi+10],ax
	mov	word [rdi+12],0x0608		; ARP
	mov	dword [rdi+14],0x00080100	; Ethernet, IPv4
	mov	dword [rdi+18],0x01000406	; 6, 4, request
	mov	eax,dword [g_vr_mac]
	mov	[rdi+22],eax
	mov	ax,word [g_vr_mac+4]
	mov	[rdi+26],ax
	mov	eax,[g_plan_vrrp+VC_ADDR]
	mov	[rdi+28],eax			; sender: the address
	mov	dword [rdi+32],0
	mov	word [rdi+36],0
	mov	[rdi+38],eax			; target: the address
	sub	rsp,24				; sockaddr_ll
	mov	word [rsp],AF_PACKET_
	mov	word [rsp+2],0x0608
	mov	eax,[g_vr_ifindex]
	mov	[rsp+4],eax
	mov	word [rsp+8],1			; ARPHRD_ETHER
	mov	byte [rsp+10],0
	mov	byte [rsp+11],6
	mov	qword [rsp+12],-1
	mov	edi,[g_vr_pkt]
	lea	rsi,[g_vr_buf]
	mov	edx,42
	xor	r10d,r10d
	mov	r8,rsp
	mov	r9d,20
	mov	eax,SYS_sendto
	syscall
	add	rsp,24
	ret

; ------------------------------------------------------------ compiling

; `vrrp IFACE vrid=N priority=N address=A/N [advert=T] [preempt=off] [track=POOL]`
compile_vrrp:
	push	r12
	lea	r12,[g_plan_vrrp]
	mov	dword [r12+VC_ON],1
	mov	rax,[rbx+N_ARGS]
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	test	ecx,ecx
	jz	.bad
	cmp	ecx,15
	ja	.bad
	mov	[r12+VC_IFLEN],ecx
	lea	rdi,[r12+VC_IF]
	rep	movsb
	mov	byte [rdi],0
	cstring .k_vrid, 'vrid',0
	lea	rsi,[.k_vrid]
	call	.number
	jc	.bad
	cmp	eax,1
	jb	.bad
	cmp	eax,255
	ja	.bad
	mov	[r12+VC_VRID],eax
	cstring .k_prio, 'priority',0
	lea	rsi,[.k_prio]
	call	.number
	jc	.bad
	cmp	eax,1
	jb	.bad
	cmp	eax,255
	ja	.bad
	mov	[r12+VC_PRIO],eax
	; the address, with its prefix
	mov	rdi,rbx
	cstring .k_addr, 'address',0
	lea	rsi,[.k_addr]
	call	node_option
	test	rax,rax
	jz	.bad
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	lea	rdx,[g_tr_tmp]
	call	parse_cidr
	jc	.bad
	cmp	dword [g_tr_tmp+TR_KIND],4
	jne	.bad				; (IPv4, for now)
	mov	eax,dword [g_tr_tmp+TR_IP]
	mov	[r12+VC_ADDR],eax
	mov	eax,[g_tr_tmp+TR_BITS]		; (a bare address: /32)
	mov	[r12+VC_PLEN],eax
	mov	dword [r12+VC_ADVERT],100	; 1 s
	mov	rdi,rbx
	cstring .k_advert, 'advert',0
	lea	rsi,[.k_advert]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_duration
	xor	edx,edx
	mov	ecx,10000
	div	rcx				; µs -> cs
	test	eax,eax
	jz	.bad
	cmp	eax,4095
	ja	.bad
	mov	[r12+VC_ADVERT],eax
@@:
	mov	dword [r12+VC_PREEMPT],1
	mov	rdi,rbx
	cstring .k_preempt, 'preempt',0
	lea	rsi,[.k_preempt]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	lea	rdx,[str_word_off]
	call	mem_eq_cstr
	xor	eax,1
	mov	[r12+VC_PREEMPT],eax
@@:
	mov	rdi,rbx
	cstring .k_track, 'track',0
	lea	rsi,[.k_track]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rcx,[rax+A_VAL]
	mov	[r12+VC_TRACK],rcx
	mov	ecx,[rax+A_VLEN]
	mov	[r12+VC_TRACKL],ecx
@@:
	pop	r12
	ret
; rsi = an option's name: eax = its number. CF: none, or not one
.number:
	mov	rdi,rbx
	call	node_option
	test	rax,rax
	jz	.nan
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	jmp	parse_decimal
.nan:
	stc
	ret
.bad:
	call	log_begin
	out_lit 'vrrp takes an interface (15 bytes at most), vrid= and priority= from 1 to 255, address=A.B.C.D/N (IPv4), advert= from 10ms to 40.95s, preempt=off and track=POOL if wanted'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
