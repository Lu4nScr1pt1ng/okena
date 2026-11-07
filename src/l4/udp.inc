; `udp ADDR... { to pool dns; responses 1; timeout { idle 5s } }`: datagrams
; between clients and a pool.
;
; Each worker has its own SO_REUSEPORT socket, so the kernel's hash keeps a
; client's datagrams on one worker and nothing here is shared or locked. A
; flow is a client on a listener, pinned to a server until it goes quiet. New
; flows are found in a hash keyed with this worker's secret, so that forged
; sources cannot aim at one chain.
;
; A flow that expects answers has a connected socket of its own: the kernel
; finds it from the backend's answer, takes only what comes from that backend,
; and hands back the ICMP that says it is not there. `responses 0` (syslog,
; metrics) expects none, and a flow is only a line in the table: its datagrams
; go through one socket per server and flood costs no descriptors. With
; `responses N` a flow ends at its Nth answer, which for DNS is at once.
;
; All sockets sit on one epoll of its own, which both engines watch as one
; thing that gets readable: one path, and closing a socket is all it takes to
; forget it. io_uring hears of that epoll only when something gets ready, so
; a turn that leaves datagrams in a socket says so (g_ud_pend), and the loop
; comes back before it sleeps. A turn reads each socket in batches and sends what it read in
; batches, by runs of one socket: the buffers go through unchanged, and the
; same sendmmsg carries the answers of many flows to one listening socket.
;
; A datagram costs two stores here: its flow's time, and only once a second a
; look at whether its server is still there. Expiry needs no scan: flows are
; queued by when they were last queued, and whichever reaches the head having
; been used since goes to the tail. When the table is full the head goes if it
; is idle; flows in use are never pushed out by new ones, which are dropped.
;
; A reload hands the listening sockets on with what they hold. A client's next
; datagram makes a flow in the new worker; the old one stays until the answers
; it waits for have come, within the drain timeout. Flows with no end expected
; do not hold it up.

UD_RX		:= 32			; datagrams in a batch
UD_BATCHES	:= 8			; batches a socket gets in a turn
UD_REPLY_RX	:= 8			; from a backend at a time
UD_EV		:= 128
UD_SLOT		:= 65536
UD_RCVBUF	:= 1048576
UD_EVICT_TRIES	:= 8
UD_EVICT_IDLE	:= 2			; seconds without traffic before it may be pushed out
UD_NO_LIMIT	:= -1

UDE_FLOW	:= 0			; epoll data, top two bits
UDE_LISTENER	:= 1
UDE_SHARED	:= 2

MM_SIZE		:= 64			; struct mmsghdr
MM_NAME		:= 0
MM_NAMELEN	:= 8
MM_IOV		:= 16
MM_IOVLEN	:= 24
MM_CTL		:= 32
MM_CTLLEN	:= 40
MM_LEN		:= 56
assert MM_LEN + 8 = MM_SIZE

IP_PKTINFO_	:= 8
IPV6_PKTINFO_	:= 50
IPV6_RECVPKTINFO_ := 49
UD_CTL		:= 64

FL_K1		:= 0			; q
FL_K2		:= 8			; q
FL_KC		:= 16			; q: port, listener, family
FL_NEXT		:= 24			; d: in its chain, or among the free, + 1
FL_GEN		:= 28			; d
FL_FD		:= 32			; d: to the backend
FL_SERVER	:= 36			; d
FL_LAST		:= 40			; d: tick of its last datagram
FL_LEFT		:= 44			; d: answers still to come, UD_NO_LIMIT
FL_PREV		:= 48			; d: in the queue, + 1
FL_QNEXT	:= 52			; d
FL_LFD		:= 56			; d: the listening socket it came on
FL_LST		:= 60			; d
FL_SA		:= 64			; 28: the client
FL_SALEN	:= 92			; d
FL_QUEUED	:= 96			; d: FL_LAST when it was queued
FL_CHK		:= 100			; d: tick its server was last looked at
FL_OWN		:= 104			; d: FL_FD is its own
FL_HASH		:= 108			; d
FL_CTLLEN	:= 112			; d: what the answer says of the source address
FL_WAITS	:= 116			; d: counted in g_active
FL_CTL		:= 120			; 40
FL_SIZE		:= 160
assert FL_CTL + 40 <= FL_SIZE

bss
	align 8
	g_ud_on		dd ?
	g_ud_pend	dd ?		; ran out of its turn: more to read
	g_ud_ep		dd ?
	g_ud_mask	dd ?
	g_ud_free	dd ?		; + 1
	g_ud_bump	dd ?		; flows never used yet start here
	g_ud_cap	dd ?
	g_ud_tn		dd ?		; datagrams waiting to go
	g_ud_tfd	dd ?		; to this socket
	align 8
	g_ud_tflow	dq ?		; (to the backend: whose)
	g_ud_tab	dq ?
	g_ud_heads	dq ?
	g_ud_buf	dq ?
	g_ud_k		rq 3
	g_ud_qh		rd MAX_LISTENERS	; the queues, + 1
	g_ud_qt		rd MAX_LISTENERS
	g_ud_shared	rd MAX_SERVERS		; `responses 0`: + 1
	g_st_ud_drops	dq ?		; datagrams with no flow to go in
	g_ud_ev:	rb EPOLL_EVENT * UD_EV
	align 8
	g_ud_rm:	rb MM_SIZE * UD_RX
	g_ud_tm:	rb MM_SIZE * UD_RX
	g_ud_rio:	rb 16 * UD_RX
	g_ud_tio:	rb 16 * UD_RX
	g_ud_rsa:	rb 32 * UD_RX
	g_ud_rctl:	rb UD_CTL * UD_RX
end bss

; ------------------------------------------------------------ setting up

; a worker, before it is confined. Keeps nothing to do when no listener is udp.
udp_worker_init:
	push	rbx
	push	r12
	xor	ebx,ebx
	xor	r12d,r12d
.count:
	cmp	ebx,[g_plan_listeners]
	jae	.counted
	imul	rax,rbx,LS_SIZE
	cmp	dword [g_listeners+rax+LS_KIND],LK_UDP
	jne	@f
	add	r12d,[g_ls_cap+rbx*4]
	mov	dword [g_ud_on],1
@@:
	inc	ebx
	jmp	.count
.counted:
	cmp	dword [g_ud_on],0
	je	.out
	mov	[g_ud_cap],r12d
	mov	dword [g_ud_free],0
	mov	dword [g_ud_bump],0
	mov	dword [g_ud_tn],0
	mov	dword [g_ud_pend],0
	lea	rdi,[g_ud_k]
	mov	esi,24
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	lea	rdi,[g_ud_shared]
	xor	eax,eax
	mov	ecx,MAX_SERVERS
	rep	stosd
	lea	rdi,[g_ud_qh]
	mov	ecx,MAX_LISTENERS * 2
	rep	stosd
	; the table
	imul	rsi,r12,FL_SIZE
	call	.map
	mov	[g_ud_tab],rax
	; twice as many chains, a power of two
	lea	eax,[r12+r12-1]
	bsr	ecx,eax
	inc	ecx
	mov	eax,1
	shl	rax,cl
	lea	edx,[rax-1]
	mov	[g_ud_mask],edx
	lea	rsi,[rax*4]
	call	.map
	mov	[g_ud_heads],rax
	mov	esi,UD_SLOT * UD_RX
	call	.map
	mov	[g_ud_buf],rax
	; what never changes in the batches
	xor	ecx,ecx
.slot:
	mov	rax,rcx
	shl	rax,16
	add	rax,[g_ud_buf]
	mov	rdx,rcx
	shl	rdx,4
	lea	rsi,[g_ud_rio+rdx]
	mov	[rsi],rax
	mov	qword [rsi+8],UD_SLOT
	lea	r8,[g_ud_tio+rdx]
	imul	rdx,rcx,MM_SIZE
	lea	rax,[g_ud_rm+rdx]
	mov	[rax+MM_IOV],rsi
	mov	qword [rax+MM_IOVLEN],1
	mov	rsi,rcx
	shl	rsi,5
	lea	rsi,[g_ud_rsa+rsi]
	mov	[rax+MM_NAME],rsi
	imul	rsi,rcx,UD_CTL
	lea	rsi,[g_ud_rctl+rsi]
	mov	[rax+MM_CTL],rsi
	lea	rax,[g_ud_tm+rdx]
	mov	[rax+MM_IOV],r8
	mov	qword [rax+MM_IOVLEN],1
	inc	ecx
	cmp	ecx,UD_RX
	jb	.slot
	mov	edi,EPOLL_CLOEXEC
	mov	eax,SYS_epoll_create1
	syscall
	test	eax,eax
	js	.fatal
	mov	[g_ud_ep],eax
	lea	rsi,[.add]
	call	udp_each_socket
	call	udp_watch
.out:
	pop	r12
	pop	rbx
	ret
.fatal:
	mov	edi,EXIT_FATAL
	jmp	exit_process
.map:
	xor	edi,edi
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.fatal_pop
	ret
.fatal_pop:
	add	rsp,8
	jmp	.fatal
; edi = socket, esi = listener
.add:
	mov	eax,esi
	mov	edx,edi
	shl	rax,32
	or	rdx,rax
	mov	rax,UDE_LISTENER shl 62
	or	rdx,rax
	mov	eax,EPOLL_CTL_ADD
	jmp	udp_ctl

; rsi = called with edi = each socket of this worker, esi = its listener
udp_each_socket:
	push	rbx
	push	r12
	push	r13
	mov	r13,rsi
	xor	ebx,ebx
.listener:
	cmp	ebx,[g_plan_listeners]
	jae	.done
	imul	rax,rbx,LS_SIZE
	cmp	dword [g_listeners+rax+LS_KIND],LK_UDP
	jne	.next
	mov	r12d,[g_worker_id]
.socket:
	cmp	r12d,[g_lsocks+rbx*4]
	jae	.next
	mov	eax,ebx
	imul	eax,eax,MAX_WORKERS
	add	eax,r12d
	mov	edi,[g_lfd+rax*4]
	mov	esi,ebx
	call	r13
	add	r12d,[g_workers]
	jmp	.socket
.next:
	inc	ebx
	jmp	.listener
.done:
	pop	r13
	pop	r12
	pop	rbx
	ret

; eax = EPOLL_CTL_*, edi = socket, rdx = data: on this worker's epoll
udp_ctl:
	sub	rsp,16
	mov	dword [rsp],EPOLLIN
	mov	[rsp+4],rdx
	mov	r10,rsp
	mov	edx,edi
	mov	esi,eax
	mov	edi,[g_ud_ep]
	mov	eax,SYS_epoll_ctl
	syscall
	add	rsp,16
	ret

; the engine watches that epoll
udp_watch:
	cmp	dword [g_engine],ENGINE_EPOLL
	jne	.ring
	mov	edi,[g_ud_ep]
	mov	esi,EPOLLIN
	mov	rdx,EK_UDP shl 56
	jmp	ep_add
.ring:
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_POLL_ADD
	mov	ecx,[g_ud_ep]
	mov	[rax+SQE_FD],ecx
	mov	dword [rax+SQE_OP_FLAGS],EPOLLIN
	mov	dword [rax+SQE_LEN],IORING_POLL_ADD_MULTI
	mov	rcx,OP_UPOLL shl 56
	mov	[rax+SQE_USER_DATA],rcx
	ret

on_upoll:
	push	r15
	call	udp_ready
	pop	r15
	test	r15d,IORING_CQE_F_MORE
	jnz	.out
	jmp	udp_watch
.out:
	ret

; a reload or a stop: nothing new. The sockets stay, as answers go out on them.
udp_stop:
	cmp	dword [g_ud_on],0
	je	.none
	lea	rsi,[.del]
	jmp	udp_each_socket
.del:
	mov	eax,EPOLL_CTL_DEL
	xor	edx,edx
	jmp	udp_ctl
.none:
	ret

; ------------------------------------------------------------ a turn

; before the engine sleeps
udp_resume:
	cmp	dword [g_ud_pend],0
	jne	udp_ready
	ret

; what is readable
udp_ready:
	push	rbx
	push	r12
	push	r13
	mov	dword [g_ud_pend],0
	mov	edi,[g_ud_ep]
	lea	rsi,[g_ud_ev]
	mov	edx,UD_EV
	xor	r10d,r10d
	mov	eax,SYS_epoll_wait
	syscall
	test	eax,eax
	jle	.out
	mov	r12d,eax
	cmp	eax,UD_EV
	jne	@f
	mov	dword [g_ud_pend],1
@@:
	xor	ebx,ebx
.event:
	cmp	ebx,r12d
	jae	.done
	imul	rax,rbx,EPOLL_EVENT
	mov	rsi,qword [g_ud_ev+rax+4]
	mov	rax,rsi
	shr	rax,62
	cmp	eax,UDE_FLOW
	je	.flow
	cmp	eax,UDE_LISTENER
	je	.listener
	mov	edi,esi				; a server's shared socket
	call	udp_shared_read
	jmp	.next
.flow:
	mov	rax,rsi
	shr	rax,32
	mov	edi,esi
	imul	rdi,rdi,FL_SIZE
	add	rdi,[g_ud_tab]
	cmp	[rdi+FL_GEN],eax
	jne	.next				; closed earlier in this batch
	call	udp_flow_read
	jmp	.next
.listener:
	push	rsi
	call	udp_flush			; (their names are in flows it may reuse)
	pop	rsi
	mov	rax,rsi
	shl	rax,2
	shr	rax,34
	mov	edi,esi
	mov	esi,eax
	call	udp_listener_read
.next:
	inc	ebx
	jmp	.event
.done:
	call	udp_flush
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; what waits, to its socket. Past a failure the rest of the run is lost, as
; datagrams may be.
udp_flush:
	mov	edx,[g_ud_tn]
	test	edx,edx
	jz	.none
	mov	dword [g_ud_tn],0
	mov	edi,[g_ud_tfd]
	lea	rsi,[g_ud_tm]
	mov	r10d,MSG_DONTWAIT
	mov	eax,SYS_sendmmsg
	syscall
	test	eax,eax
	jns	.none
	mov	rdi,[g_ud_tflow]
	test	rdi,rdi
	jz	.none				; to clients: nothing to learn
	cmp	eax,-ECONNREFUSED
	jne	.none
	mov	rsi,rax
	mov	eax,[rdi+FL_FD]
	cmp	eax,[g_ud_tfd]
	jne	.none
	push	rdi
	mov	edi,[rdi+FL_SERVER]
	call	server_failed
	pop	rdi
	cmp	dword [rdi+FL_OWN],0
	jne	udp_close
.none:
	ret

; edi = socket, esi = listener
udp_listener_read:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	mov	r12d,edi
	mov	r13d,esi
	mov	r14d,UD_BATCHES
	imul	rax,r13,LS_SIZE
	mov	ebp,UD_CTL
	test	dword [g_listeners+rax+LS_FLAGS],LSF_WILDCARD
	jnz	.batch
	xor	ebp,ebp				; (no address to learn)
.batch:
	xor	ecx,ecx
@@:
	imul	rax,rcx,MM_SIZE
	mov	dword [g_ud_rm+rax+MM_NAMELEN],32
	mov	[g_ud_rm+rax+MM_CTLLEN],rbp
	inc	ecx
	cmp	ecx,UD_RX
	jb	@b
	mov	edi,r12d
	lea	rsi,[g_ud_rm]
	mov	edx,UD_RX
	mov	r10d,MSG_DONTWAIT
	xor	r8d,r8d
	mov	eax,SYS_recvmmsg
	syscall
	test	eax,eax
	jle	.out
	push	rbp
	push	r14
	mov	ebp,eax
	xor	ebx,ebx
.dgram:
	cmp	ebx,ebp
	jae	.sent
	call	udp_in
	inc	ebx
	jmp	.dgram
.sent:
	call	udp_flush
	mov	eax,ebp
	pop	r14
	pop	rbp
	cmp	eax,UD_RX
	jne	.out
	dec	r14d
	jnz	.batch
	mov	dword [g_ud_pend],1		; the rest next turn: others have their go
.out:
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

; ebx = slot, r12d = its socket, r13d = its listener: on its way
udp_in:
	mov	rax,rbx
	shl	rax,5
	lea	rsi,[g_ud_rsa+rax]
	movzx	eax,word [rsi]
	movzx	r10d,word [rsi+2]
	mov	ecx,r13d
	shl	ecx,16
	or	r10d,ecx
	shl	rax,32
	or	r10,rax
	cmp	word [rsi],AF_INET6
	je	.v6
	mov	r8d,[rsi+4]
	xor	r9d,r9d
	jmp	.keyed
.v6:
	mov	r8,[rsi+8]
	mov	r9,[rsi+16]
.keyed:
	; a keyed multiply-and-fold
	mov	rax,r8
	xor	rax,[g_ud_k]
	mov	rdx,r9
	xor	rdx,[g_ud_k+8]
	mul	rdx
	xor	rax,rdx
	xor	rax,r10
	mov	rdx,[g_ud_k+16]
	mul	rdx
	xor	rax,rdx
	and	eax,[g_ud_mask]
	mov	r11d,eax
	mov	rcx,[g_ud_heads]
	mov	eax,[rcx+rax*4]
.chain:
	test	eax,eax
	jz	.new
	lea	rdi,[rax-1]
	imul	rdi,rdi,FL_SIZE
	add	rdi,[g_ud_tab]
	cmp	[rdi+FL_K1],r8
	jne	.other
	cmp	[rdi+FL_K2],r9
	jne	.other
	cmp	[rdi+FL_KC],r10
	je	.found
.other:
	mov	eax,[rdi+FL_NEXT]
	jmp	.chain
.found:
	mov	eax,[g_tick]
	mov	[rdi+FL_LAST],eax
	cmp	[rdi+FL_CHK],eax
	jne	.look
.send:
	mov	ecx,ebx
	imul	rax,rcx,MM_SIZE
	mov	edx,[g_ud_rm+rax+MM_LEN]
	add	[g_st_l_in+r13*8],rdx
	mov	eax,[rdi+FL_FD]
	cmp	dword [g_ud_tn],0
	je	.run
	cmp	eax,[g_ud_tfd]
	je	.joined
	push	rdi
	push	rdx
	call	udp_flush
	pop	rdx
	pop	rdi
	mov	eax,[rdi+FL_FD]
.run:
	mov	[g_ud_tfd],eax
	mov	[g_ud_tflow],rdi
.joined:
	mov	ecx,[g_ud_tn]
	inc	dword [g_ud_tn]
	imul	rax,rcx,MM_SIZE
	xor	esi,esi
	mov	[g_ud_tm+rax+MM_NAME],rsi
	mov	[g_ud_tm+rax+MM_NAMELEN],esi
	mov	[g_ud_tm+rax+MM_CTL],rsi
	mov	[g_ud_tm+rax+MM_CTLLEN],rsi
	shl	rcx,4
	mov	rsi,rbx
	shl	rsi,4
	mov	rsi,[g_ud_rio+rsi]
	mov	[g_ud_tio+rcx],rsi
	mov	[g_ud_tio+rcx+8],rdx
	ret
; once a second: is its server still there? A drain lets it stay.
.look:
	mov	[rdi+FL_CHK],eax
	mov	ecx,[rdi+FL_SERVER]
	mov	rdx,[g_health_tbl]
	cmp	dword [rdx+rcx*8],HC_UP
	jne	.move
	cmp	[g_sv_down+rcx*4],eax
	jbe	.send
.move:
	push	r8
	push	r9
	push	r10
	push	r11
	call	udp_close
	pop	r11
	pop	r10
	pop	r9
	pop	r8
.new:
	call	udp_new
	test	rdi,rdi
	jnz	.send
	inc	qword [g_st_ud_drops]
	ret

; ebx, r13d as for udp_in; r8, r9, r10 its key, r11d its chain. rdi = a new
; flow on its way, or 0.
udp_new:
	push	r14
	push	r15
	push	rbp
	push	r8
	push	r9
	push	r10
	push	r11
	imul	rax,r13,LS_SIZE
	lea	r14,[g_listeners+rax]
	mov	eax,[g_ls_active+r13*4]
	cmp	eax,[g_ls_cap+r13*4]
	jb	.room
	call	udp_evict
	test	eax,eax
	jz	.full
.room:
	mov	edi,[r14+LS_POOL]
	call	pool_hashes_source
	jnc	@f
	mov	rax,rbx				; the client's address picks
	shl	rax,5
	lea	rsi,[g_ud_rsa+rax]
	sub	rsp,16
	mov	rdi,rsp
	call	peer_normalize
	mov	rdi,rsp
	call	pick_key_ip
	add	rsp,16
@@:
	mov	edi,[r14+LS_POOL]
	mov	esi,NIL
	call	server_pick
	cmp	eax,NIL
	je	.no_server
	mov	ebp,eax
	mov	edi,eax
	call	sv_claim
	jnc	.no_server
	; an entry
	mov	eax,[g_ud_free]
	test	eax,eax
	jz	.fresh
	lea	r15,[rax-1]
	imul	r15,r15,FL_SIZE
	add	r15,[g_ud_tab]
	mov	eax,[r15+FL_NEXT]
	mov	[g_ud_free],eax
	jmp	.entry
.fresh:
	mov	eax,[g_ud_bump]
	cmp	eax,[g_ud_cap]
	jae	.full_claimed
	inc	dword [g_ud_bump]
	imul	r15,rax,FL_SIZE
	add	r15,[g_ud_tab]
	mov	dword [r15+FL_GEN],1
.entry:
	mov	dword [r15+FL_OWN],0
	cmp	dword [r14+LS_RESP],0
	jne	.own
	mov	edi,ebp
	call	udp_shared
	test	eax,eax
	js	.give_back
	jmp	.have
.own:
	call	udp_socket
	test	eax,eax
	js	.give_back
	mov	dword [r15+FL_OWN],1
	mov	[r15+FL_FD],eax
	mov	edi,eax
	mov	rax,r15
	sub	rax,[g_ud_tab]
	xor	edx,edx
	mov	ecx,FL_SIZE
	div	rcx
	mov	rdx,rax
	mov	eax,[r15+FL_GEN]
	shl	rax,32
	or	rdx,rax
	mov	eax,EPOLL_CTL_ADD
	call	udp_ctl
	mov	eax,[r15+FL_FD]
.have:
	mov	[r15+FL_FD],eax
	mov	[r15+FL_SERVER],ebp
	mov	[r15+FL_LFD],r12d
	mov	[r15+FL_LST],r13d
	mov	eax,[g_tick]
	mov	[r15+FL_LAST],eax
	mov	[r15+FL_QUEUED],eax
	mov	[r15+FL_CHK],eax
	mov	eax,[r14+LS_RESP]
	test	eax,eax
	jnz	@f
	mov	eax,UD_NO_LIMIT
@@:
	mov	[r15+FL_LEFT],eax
	mov	dword [r15+FL_WAITS],0
	cmp	eax,UD_NO_LIMIT
	je	@f
	mov	dword [r15+FL_WAITS],1
	inc	dword [g_active]
@@:
	; the client, and where it wrote to
	mov	rax,rbx
	shl	rax,5
	lea	rsi,[g_ud_rsa+rax]
	lea	rdi,[r15+FL_SA]
	mov	ecx,28
	rep	movsb
	imul	rax,rbx,MM_SIZE
	mov	eax,[g_ud_rm+rax+MM_NAMELEN]
	mov	[r15+FL_SALEN],eax
	mov	dword [r15+FL_CTLLEN],0
	test	dword [r14+LS_FLAGS],LSF_WILDCARD
	jz	@f
	call	udp_keep_address
@@:
	pop	r11
	pop	r10
	pop	r9
	pop	r8
	mov	[r15+FL_K1],r8
	mov	[r15+FL_K2],r9
	mov	[r15+FL_KC],r10
	mov	[r15+FL_HASH],r11d
	; in its chain
	mov	rax,r15
	sub	rax,[g_ud_tab]
	xor	edx,edx
	mov	ecx,FL_SIZE
	div	rcx
	inc	eax
	mov	rcx,[g_ud_heads]
	mov	edx,[rcx+r11*4]
	mov	[r15+FL_NEXT],edx
	mov	[rcx+r11*4],eax
	; at the tail of its queue
	mov	edx,[g_ud_qt+r13*4]
	mov	[r15+FL_PREV],edx
	mov	dword [r15+FL_QNEXT],0
	mov	[g_ud_qt+r13*4],eax
	test	edx,edx
	jz	.first
	dec	edx
	imul	rdx,rdx,FL_SIZE
	add	rdx,[g_ud_tab]
	mov	[rdx+FL_QNEXT],eax
	jmp	.counted
.first:
	mov	[g_ud_qh+r13*4],eax
.counted:
	inc	dword [g_ls_active+r13*4]
	inc	qword [g_st_l_accepted+r13*8]
	inc	qword [g_st_s_connects+rbp*8]
	mov	rdi,r15
	pop	rbp
	pop	r15
	pop	r14
	ret
.give_back:
	mov	edi,ebp
	call	sv_unclaim
	mov	rax,r15
	sub	rax,[g_ud_tab]
	xor	edx,edx
	mov	ecx,FL_SIZE
	div	rcx
	inc	eax
	mov	ecx,[g_ud_free]
	mov	[r15+FL_NEXT],ecx
	mov	[g_ud_free],eax
	jmp	.none
.full_claimed:
	mov	edi,ebp
	call	sv_unclaim
.no_server:
.full:
	inc	qword [g_st_l_full+r13*8]
.none:
	xor	edi,edi
	add	rsp,32
	pop	rbp
	pop	r15
	pop	r14
	ret

; rbx = slot, r15 = flow: the address the client wrote to, for its answers
udp_keep_address:
	imul	rax,rbx,MM_SIZE
	mov	rcx,[g_ud_rm+rax+MM_CTLLEN]
	lea	rsi,[g_ud_rctl]
	imul	rax,rbx,UD_CTL
	add	rsi,rax
	cmp	rcx,16
	jb	.out
	cmp	dword [rsi+8],IPPROTO_IP
	jne	.v6
	cmp	dword [rsi+12],IP_PKTINFO_
	jne	.out
	lea	rdi,[r15+FL_CTL]
	mov	ecx,32
	rep	movsb
	mov	eax,[r15+FL_CTL+24]		; ipi_addr
	mov	[r15+FL_CTL+20],eax		; is ipi_spec_dst
	mov	dword [r15+FL_CTL+16],0		; any interface that gets there
	mov	dword [r15+FL_CTLLEN],32
	ret
.v6:
	cmp	dword [rsi+8],IPPROTO_IPV6
	jne	.out
	cmp	dword [rsi+12],IPV6_PKTINFO_
	jne	.out
	lea	rdi,[r15+FL_CTL]
	mov	ecx,40
	rep	movsb
	mov	dword [r15+FL_CTLLEN],40
.out:
	ret

; ebp = server. eax = a socket connected to it, or < 0. Keeps r8-r11? No: all
; are saved by the caller.
udp_socket:
	imul	rcx,rbp,SV_SIZE
	mov	edi,[g_servers+rcx+SV_FAMILY]
	mov	esi,SOCK_DGRAM or SOCK_NONBLOCK or SOCK_CLOEXEC
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	.out
	push	rax
	mov	edi,eax
	imul	rcx,rbp,SV_SIZE
	lea	rsi,[g_servers+rcx+SV_SA]
	mov	edx,[g_servers+rcx+SV_SALEN]
	mov	eax,SYS_connect
	syscall
	test	eax,eax
	js	.failed
	pop	rax
.out:
	ret
.failed:
	mov	rsi,rax
	mov	edi,ebp
	call	server_failed
	pop	rdi
	mov	eax,SYS_close
	syscall
	mov	eax,-1
	ret

; edi = server: its shared socket. eax = it, or < 0.
udp_shared:
	mov	eax,[g_ud_shared+rdi*4]
	test	eax,eax
	jz	.open
	dec	eax
	ret
.open:
	call	udp_socket
	test	eax,eax
	js	.out
	push	rax
	lea	edx,[rax+1]
	mov	[g_ud_shared+rbp*4],edx
	mov	edi,eax
	mov	edx,ebp
	mov	rax,UDE_SHARED shl 62
	or	rdx,rax
	mov	eax,EPOLL_CTL_ADD
	call	udp_ctl
	pop	rax
.out:
	ret

; edi = server: its shared socket has something: it says nobody is there, or
; a backend answered what nobody asked
udp_shared_read:
	mov	eax,[g_ud_shared+rdi*4]
	test	eax,eax
	jz	.none
	push	rbx
	mov	ebx,edi
	lea	edi,[rax-1]
	mov	rsi,[g_ud_buf]
	mov	edx,UD_SLOT
	mov	r10d,MSG_DONTWAIT
	xor	r8d,r8d
	xor	r9d,r9d
	mov	eax,SYS_recvfrom
	syscall
	test	rax,rax
	js	.error
	mov	dword [g_ud_pend],1		; (there may be more)
	jmp	@f
.error:
	cmp	rax,-ECONNREFUSED
	jne	@f
	mov	rsi,rax
	mov	edi,ebx
	call	server_failed
@@:
	pop	rbx
.none:
	ret

; rdi = flow: its backend has answers
udp_flow_read:
	push	rbx
	push	r12
	mov	r12,rdi
	cmp	dword [g_ud_tn],0
	je	.room
	mov	eax,[r12+FL_LFD]
	cmp	eax,[g_ud_tfd]
	je	.joined
.flush:
	call	udp_flush
	jmp	.room
.joined:
	cmp	dword [g_ud_tn],UD_RX
	jae	.flush
.room:
	mov	ebx,[g_ud_tn]			; the slots from here on
	mov	edx,UD_RX
	sub	edx,ebx
	cmp	edx,UD_REPLY_RX
	jbe	@f
	mov	edx,UD_REPLY_RX
@@:
	xor	ecx,ecx
@@:
	lea	eax,[rbx+rcx]
	imul	rax,rax,MM_SIZE
	mov	dword [g_ud_rm+rax+MM_NAMELEN],32
	mov	qword [g_ud_rm+rax+MM_CTLLEN],0
	inc	ecx
	cmp	ecx,edx
	jb	@b
	mov	edi,[r12+FL_FD]
	imul	rsi,rbx,MM_SIZE
	lea	rsi,[g_ud_rm+rsi]
	mov	r10d,MSG_DONTWAIT
	xor	r8d,r8d
	push	rdx
	mov	eax,SYS_recvmmsg
	syscall
	pop	rdx
	test	eax,eax
	jle	.nothing
	cmp	eax,edx
	jne	@f
	mov	dword [g_ud_pend],1		; it may have more: io_uring hears of a socket
@@:						; when it gets ready, not while it is
	mov	edi,eax
	mov	eax,[r12+FL_LFD]
	mov	[g_ud_tfd],eax
	mov	qword [g_ud_tflow],0
	mov	eax,[g_tick]
	mov	[r12+FL_LAST],eax
	mov	ecx,[r12+FL_SERVER]
	mov	eax,[g_sv_fails+rcx*4]
	or	eax,[g_sv_down+rcx*4]
	jz	@f
	push	rdi
	mov	edi,ecx
	call	server_ok
	pop	rdi
@@:
	; no more than it may have
	mov	eax,[r12+FL_LEFT]
	cmp	eax,UD_NO_LIMIT
	je	.counted
	cmp	edi,eax
	cmova	edi,eax
	sub	[r12+FL_LEFT],edi
.counted:
	mov	r8d,[r12+FL_LST]
	xor	ecx,ecx
.reply:
	cmp	ecx,edi
	jae	.queued
	lea	edx,[rbx+rcx]
	imul	rax,rdx,MM_SIZE
	mov	r9d,[g_ud_rm+rax+MM_LEN]
	add	[g_st_l_out+r8*8],r9
	lea	r10,[r12+FL_SA]
	mov	[g_ud_tm+rax+MM_NAME],r10
	mov	r10d,[r12+FL_SALEN]
	mov	[g_ud_tm+rax+MM_NAMELEN],r10d
	lea	r10,[r12+FL_CTL]
	mov	[g_ud_tm+rax+MM_CTL],r10
	mov	r10d,[r12+FL_CTLLEN]
	mov	[g_ud_tm+rax+MM_CTLLEN],r10
	mov	rax,rdx
	shl	rax,4
	mov	r10,[g_ud_rio+rax]
	mov	[g_ud_tio+rax],r10
	mov	[g_ud_tio+rax+8],r9
	inc	ecx
	jmp	.reply
.queued:
	add	[g_ud_tn],edi
	cmp	dword [r12+FL_LEFT],0
	jne	.out
	mov	rdi,r12
	call	udp_close
	jmp	.out
.nothing:
	cmp	eax,-ECONNREFUSED
	jne	.out
	mov	rsi,rax
	mov	edi,[r12+FL_SERVER]
	call	server_failed
	mov	rdi,r12
	call	udp_close
.out:
	pop	r12
	pop	rbx
	ret

; rdi = flow: gone. Keeps nothing but the callee's own. Its name stays readable
; until something new takes it, which is after the next flush.
udp_close:
	push	rbx
	mov	rbx,rdi
	; out of its chain
	mov	eax,[rbx+FL_HASH]
	mov	rcx,[g_ud_heads]
	lea	rcx,[rcx+rax*4]
	mov	rax,rbx
	sub	rax,[g_ud_tab]
	xor	edx,edx
	mov	esi,FL_SIZE
	div	rsi
	lea	r8d,[rax+1]			; its name in lists
.chain:
	mov	eax,[rcx]
	test	eax,eax
	jz	.unchained
	cmp	eax,r8d
	je	.found
	dec	eax
	imul	rax,rax,FL_SIZE
	add	rax,[g_ud_tab]
	lea	rcx,[rax+FL_NEXT]
	jmp	.chain
.found:
	mov	eax,[rbx+FL_NEXT]
	mov	[rcx],eax
.unchained:
	mov	edi,[rbx+FL_LST]
	mov	eax,[rbx+FL_PREV]
	mov	ecx,[rbx+FL_QNEXT]
	call	udp_unqueue
	dec	dword [g_ls_active+rdi*4]
	mov	eax,[rbx+FL_SERVER]
	sv_count_dec rax
	cmp	dword [rbx+FL_WAITS],0
	je	@f
	dec	dword [g_active]
@@:
	cmp	dword [rbx+FL_OWN],0
	je	@f
	push	r8
	mov	edi,[rbx+FL_FD]
	mov	eax,SYS_close
	syscall
	pop	r8
@@:
	inc	dword [rbx+FL_GEN]		; what epoll said of it is old
	mov	eax,[g_ud_free]
	mov	[rbx+FL_NEXT],eax
	mov	[g_ud_free],r8d
	pop	rbx
	ret

; eax = FL_PREV, ecx = FL_QNEXT, edi = listener: closes the gap. Keeps rdi, r8.
udp_unqueue:
	test	eax,eax
	jz	.was_head
	lea	edx,[rax-1]
	imul	rdx,rdx,FL_SIZE
	add	rdx,[g_ud_tab]
	mov	[rdx+FL_QNEXT],ecx
	jmp	.back
.was_head:
	mov	[g_ud_qh+rdi*4],ecx
.back:
	test	ecx,ecx
	jz	.was_tail
	lea	edx,[rcx-1]
	imul	rdx,rdx,FL_SIZE
	add	rdx,[g_ud_tab]
	mov	[rdx+FL_PREV],eax
	ret
.was_tail:
	mov	[g_ud_qt+rdi*4],eax
	ret

; rbx = flow, r8d = its name, edi = listener: from wherever it is to the tail
udp_requeue:
	mov	eax,[rbx+FL_PREV]
	mov	ecx,[rbx+FL_QNEXT]
	call	udp_unqueue
	mov	eax,[g_ud_qt+rdi*4]
	mov	[rbx+FL_PREV],eax
	mov	dword [rbx+FL_QNEXT],0
	mov	[g_ud_qt+rdi*4],r8d
	test	eax,eax
	jz	.only
	dec	eax
	imul	rax,rax,FL_SIZE
	add	rax,[g_ud_tab]
	mov	[rax+FL_QNEXT],r8d
	jmp	.out
.only:
	mov	[g_ud_qh+rdi*4],r8d
.out:
	mov	eax,[rbx+FL_LAST]
	mov	[rbx+FL_QUEUED],eax
	ret

; r13d = listener, full: room, from its idlest flow. eax = 1 when it made some.
; Keeps r8-r11? No: the caller saved them.
udp_evict:
	push	rbx
	push	r12
	mov	r12d,UD_EVICT_TRIES
.try:
	mov	eax,[g_ud_qh+r13*4]
	test	eax,eax
	jz	.no
	lea	r8d,[rax]
	dec	eax
	imul	rbx,rax,FL_SIZE
	add	rbx,[g_ud_tab]
	mov	eax,[g_tick]
	sub	eax,[rbx+FL_LAST]
	cmp	eax,UD_EVICT_IDLE
	jae	.go
	mov	edi,r13d
	call	udp_requeue
	dec	r12d
	jnz	.try
.no:
	xor	eax,eax
	jmp	.out
.go:
	mov	rdi,rbx
	call	udp_close
	inc	qword [g_st_l_evicted+r13*8]
	mov	eax,1
.out:
	pop	r12
	pop	rbx
	ret

; a worker, once a second: flows that went quiet, from the head of each queue
udp_tick:
	cmp	dword [g_ud_on],0
	je	.none
	push	rbx
	push	r12
	push	r13
	xor	r13d,r13d
.listener:
	cmp	r13d,[g_plan_listeners]
	jae	.done
	imul	rax,r13,LS_SIZE
	cmp	dword [g_listeners+rax+LS_KIND],LK_UDP
	jne	.next
	mov	r12d,[g_listeners+rax+LS_IDLE]
.head:
	mov	eax,[g_ud_qh+r13*4]
	test	eax,eax
	jz	.next
	mov	r8d,eax
	dec	eax
	imul	rbx,rax,FL_SIZE
	add	rbx,[g_ud_tab]
	mov	eax,[g_tick]
	sub	eax,[rbx+FL_LAST]
	cmp	eax,r12d
	jae	.quiet
	mov	eax,[rbx+FL_LAST]
	cmp	eax,[rbx+FL_QUEUED]
	je	.next				; used before all behind it: nothing is due
	mov	edi,r13d
	call	udp_requeue
	jmp	.head
.quiet:
	mov	rdi,rbx
	call	udp_close
	jmp	.head
.next:
	inc	r13d
	jmp	.listener
.done:
	pop	r13
	pop	r12
	pop	rbx
.none:
	ret
