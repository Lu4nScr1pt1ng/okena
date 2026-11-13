; The four HTTP primitives (src/http/proxy.inc) on both engines.

; ---------------------------------------------------------------- io_uring

; h_recv, but the bytes stay in the socket (MSG_PEEK).
h_recv_peek:
	mov	dword [g_h_peek],MSG_PEEK

; ebx = session, ecx = side, rdi = buffer, esi = room.
h_recv:
	test	ecx,ecx
	jnz	h_recv_up
	test	byte [g_ad_rep+rbx],ADREP_Q
	jnz	addon_replay			; (a body an addon held: from its buffer first)
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_H2S
	jnz	h2s_recv			; an HTTP/2 stream: its connection serves it
	test	dword [rax+S_FLAGS],SF_H3S
	jnz	h3s_recv			; an HTTP/3 stream
	test	dword [rax+S_FLAGS],SF_MIR
	jnz	mirror_recv			; a copy: what the request's body tees
	mov	eax,ebx
	shl	rax,H_SHIFT
	add	rax,[g_http_base]
	cmp	dword [rax+H_UTLS],0
	jne	utls_recv
	jmp	h_recv_raw
; the upstream side: a socket, or a stream on an HTTP/2 connection
h_recv_up:
	test	byte [g_ad_rep+rbx],ADREP_P
	jnz	addon_replay
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_CACHED
	jnz	cache_recv			; the backend is a block of memory
	test	dword [rax+S_FLAGS],SF_FILE
	jnz	file_recv			; or a file
	test	dword [rax+S_FLAGS],SF_IDEMS
	jnz	idem_recv			; or a kept answer
	test	dword [rax+S_FLAGS],SF_UPH2
	jnz	h2u_recv
	call	fcgi_active
	test	eax,eax
	jnz	fcgi_recv			; FastCGI: records, read back as HTTP/1.1
; the socket itself, whatever TLS is above it
h_recv_raw:
	cmp	dword [g_engine],ENGINE_EPOLL
	je	hep_recv
	test	ecx,ecx				; remember an upstream recv, for a kTLS drain retry
	jz	@f
	mov	eax,ebx
	shl	rax,H_SHIFT
	add	rax,[g_http_base]
	mov	[rax+H_URBUF],rdi
	mov	[rax+H_URROOM],esi
@@:
	push	rdi
	push	rsi
	push	rcx
	mov	edi,OP_H_RECV_C
	test	ecx,ecx
	jz	@f
	mov	edi,OP_H_RECV_U
@@:
	mov	esi,ebx
	call	sess_sqe			; rax = SQE, rdx = session
	pop	rcx
	pop	rsi
	pop	rdi
	mov	byte [rax+SQE_OPCODE],IORING_OP_RECV
	mov	[rax+SQE_ADDR],rdi
	mov	[rax+SQE_LEN],esi
	mov	r8d,[g_h_peek]
	mov	[rax+SQE_OP_FLAGS],r8d
	mov	dword [g_h_peek],0
	jmp	h_sqe_fd

; ebx = session, ecx = side, rdi = bytes, esi = length.
h_send:
	test	ecx,ecx
	jnz	h_send_up
	mov	eax,ebx				; bytes towards the client (access log)
	shl	rax,H_SHIFT
	add	rax,[g_http_base]
	mov	r8d,esi
	add	[rax+H_XBYTES],r8
	call	h_send_clock			; (HTTP/2 and 3 streams too: their windows)
	push	rax
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_H3S
	jnz	.h3
	test	dword [rax+S_FLAGS],SF_MIR
	jnz	.copy
	test	dword [rax+S_FLAGS],SF_H2S
	pop	rax
	jnz	h2s_send			; an HTTP/2 stream: frames on its connection
	cmp	dword [rax+H_UTLS],0
	jne	utls_send
	jmp	h_send_raw

.h3:
	pop	rax
	jmp	h3s_send			; an HTTP/3 stream: frames on its connection
.copy:
	pop	rax				; a copy's answer: as if sent
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_HEDGE
	jnz	hedge_send			; (or to the client, if it wins)
	xor	eax,eax
	mov	edx,2
	xor	ecx,ecx
	jmp	hep_queue
; the upstream side: a socket, or a stream on an HTTP/2 connection
h_send_up:
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_UPH2
	jz	@f
	mov	eax,ebx				; gRPC-Web text: its body decoded first
	shl	rax,H_SHIFT
	add	rax,[g_http_base]
	cmp	dword [rax+H_STATE],HS_SEND_HEAD
	je	h2u_send
	mov	rax,[rax+H_BUF]
	cmp	byte [rax+HB_GWEB],4
	je	gweb_send_up
	jmp	h2u_send
@@:
	call	fcgi_active
	test	eax,eax
	jnz	fcgi_send			; FastCGI: in records
; the socket itself
h_send_raw:
	cmp	dword [g_engine],ENGINE_EPOLL
	je	hep_send
	mov	eax,ebx
	shl	rax,H_SHIFT
	add	rax,[g_http_base]
	mov	[rax+H_SPTR],rdi
	mov	[rax+H_SLEN],esi
	mov	[rax+H_SSIDE],ecx

; post (the rest of) the session's pending send
h_send_more:
	mov	r8d,ebx
	shl	r8,H_SHIFT
	add	r8,[g_http_base]
	mov	ecx,[r8+H_SSIDE]
	push	r8
	push	rcx
	mov	edi,OP_H_SEND_C
	test	ecx,ecx
	jz	@f
	mov	edi,OP_H_SEND_U
@@:
	mov	esi,ebx
	call	sess_sqe
	pop	rcx
	pop	r8
	mov	byte [rax+SQE_OPCODE],IORING_OP_SEND
	mov	rsi,[r8+H_SPTR]
	mov	[rax+SQE_ADDR],rsi
	mov	esi,[r8+H_SLEN]
	mov	[rax+SQE_LEN],esi
	mov	dword [rax+SQE_OP_FLAGS],MSG_NOSIGNAL

; rax = SQE, rdx = session, ecx = side: the descriptor and its flags.
h_sqe_fd:
	test	ecx,ecx
	jnz	.upstream
	mov	ecx,[rdx+S_CLIENT]
	mov	[rax+SQE_FD],ecx
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE
	client_sqe rdx
	ret
.upstream:
	mov	ecx,[g_upslot+rbx*4]
	mov	[rax+SQE_FD],ecx
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE
	ret

; ebx = session: a connection to a server of its pool, an idle one from
; that server's pool when there is one.
h_connect:
	mov	byte [g_up_peek+rbx],0
	call	session_ptr
	mov	ecx,[rax+S_POOL]
	imul	rcx,rcx,PL_SIZE
	lea	rdx,[g_pools]
	cmp	dword [rdx+rcx+PL_H2],0
	je	@f
	mov	dword [rax+S_STATE],ST_CONNECTING
	jmp	h2u_connect			; `protocol h2`: a stream on a shared connection
@@:
	push	r12
	push	r13
	call	session_ptr
	mov	r12,rax
	mov	dword [r12+S_STATE],ST_CONNECTING
	h_rec
	mov	dword [r15+H_UPKTLS],0
	call	pick_key_http
	call	sticky_pick			; a client kept on its server
	cmp	eax,NIL
	je	.balanced
	test	dword [r15+H_FLAGS],HX_NOPOOL
	jz	.picked
	mov	[g_force_server],eax		; (an upgrade, say: its own connection)
	jmp	.connect
.balanced:
	test	dword [r15+H_FLAGS],HX_NOPOOL
	jnz	.connect
	mov	edi,[r12+S_POOL]
	mov	esi,NIL
	test	dword [r15+H_FLAGS],HX_AVOID
	jz	@f
	and	dword [r15+H_FLAGS],not HX_AVOID
	mov	esi,[r12+S_SERVER]		; a retry: another server if there is one
@@:
	call	server_pick
.picked:
	cmp	eax,NIL
	je	.none
	mov	r13d,eax
	mov	edi,eax
	call	sv_claim			; full since chosen: it waits its turn
	jc	.claimed
.none:
	cmp	dword [g_pick_full],0
	je	.connect			; (no address yet: the connect path says why)
	pop	r13				; full, or others wait first: in line
	pop	r12
	jmp	http_connect_failed
.claimed:
	mov	edi,r13d
	call	pool_take
	cmp	eax,NIL
	jne	.reuse
	mov	edi,r13d
	call	sv_unclaim			; a new connection claims its own
	jmp	.fresh
.reuse:
	mov	[r12+S_SERVER],r13d
	call	h_stamp_gen
	or	dword [r12+S_FLAGS],SF_COUNTED or SF_UP_OPEN
	mov	dword [r12+S_STATE],ST_OPEN
	h_rec
	or	dword [r15+H_FLAGS],HX_REUSED
	mov	r8d,[r12+S_POOL]		; a reused TLS upstream is already a kTLS socket
	imul	r8,r8,PL_SIZE
	lea	rcx,[g_pools]
	cmp	dword [rcx+r8+PL_TLS],0
	je	@f
	mov	dword [r15+H_UPKTLS],1
@@:
	cmp	dword [g_engine],ENGINE_EPOLL
	je	.epoll_reuse
	mov	[g_upslot+rbx*4],eax
	pop	r13
	pop	r12
	cmp	byte [g_take_peek],0
	je	http_connected
	; parked since the last tick, so not watched: whether the backend
	; closed it or wrote to it meanwhile (on_h_peek). A request without a
	; body goes in the same submission, right behind the peek (it may be
	; sent again: http_send_plain); one with a body waits for it.
	h_rec
	mov	byte [g_up_peek+rbx],UPK_WAIT
	test	dword [r15+H_FLAGS],HX_NOBODY
	jz	@f
	mov	byte [g_up_peek+rbx],UPK_BESIDE
	call	.peek
	jmp	http_connected
@@:
.peek:
	mov	edi,OP_H_PEEK
	mov	esi,ebx
	call	sess_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_RECV
	lea	rcx,[g_peek_byte]
	mov	[rax+SQE_ADDR],rcx
	mov	dword [rax+SQE_LEN],1
	mov	dword [rax+SQE_OP_FLAGS],MSG_PEEK or MSG_DONTWAIT
	mov	ecx,SIDE_UP
	jmp	h_sqe_fd
.epoll_reuse:
	mov	[r12+S_UPFD],eax
	; its epoll registration still names the session that parked it
	mov	edi,eax
	mov	edx,EK_UPSTREAM
	call	ep_session_data
	mov	esi,EPOLLIN or EPOLLOUT or EPOLLRDHUP or EPOLLET
	call	ep_mod
	pop	r13
	pop	r12
	jmp	http_connected
.fresh:
	mov	[g_force_server],r13d		; the server just picked, not another
	call	h_stamp_gen
.connect:
	h_rec
	and	dword [r15+H_FLAGS],not HX_REUSED
	pop	r13
	pop	r12
	cmp	dword [g_engine],ENGINE_EPOLL
	je	hep_connect
	mov	edi,ebx
	jmp	session_connect

; ebx = session: its upstream connection goes to its server's pool (or
; is closed when the pool is full). Keeps rbx.
h_park:
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_UPH2
	jnz	h2u_detach			; a stream: it leaves its connection
	push	r12
	call	session_ptr
	mov	r12,rax
	test	dword [r12+S_FLAGS],SF_UP_OPEN
	jz	.done
	mov	esi,[g_upslot+rbx*4]
	cmp	dword [g_engine],ENGINE_EPOLL
	jne	@f
	mov	esi,[r12+S_UPFD]
@@:
	mov	edi,[r12+S_SERVER]
	mov	eax,ebx
	shl	rax,HB_SHIFT
	add	rax,[g_hbuf_base]
	mov	eax,[rax+HB_SVGEN]
	cmp	eax,[g_sv_gen+rdi*4]
	jne	.full				; its slot has another address now: not kept
	call	pool_put
	jc	.full
	and	dword [r12+S_FLAGS],not SF_UP_OPEN
	call	session_uncount
.done:
	pop	r12
	ret
.full:
	pop	r12
	jmp	h_upclose

; ebx = session, r13d = the server its upstream is for: the slot's
; generation, so that a connection made for an address its slot no longer has
; is never kept for reuse. Keeps all.
h_stamp_gen:
	push	rcx
	push	rdx
	mov	ecx,[g_sv_gen+r13*4]
	mov	edx,ebx
	shl	rdx,HB_SHIFT
	add	rdx,[g_hbuf_base]
	mov	[rdx+HB_SVGEN],ecx
	pop	rdx
	pop	rcx
	ret

; ebx = session: close its upstream connection (nothing in flight on it).
; Keeps rbx.
h_upclose:
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_UPH2
	jnz	h2u_detach
	push	r12
	call	session_ptr
	mov	r12,rax
	test	dword [r12+S_FLAGS],SF_UP_OPEN
	jz	.done
	and	dword [r12+S_FLAGS],not SF_UP_OPEN
	call	session_uncount
	cmp	dword [g_engine],ENGINE_EPOLL
	je	.epoll
	; a read may still wait on it (a timeout): cancel it, then close;
	; a close alone would leave that read hanging on the socket. Not
	; linked: a cancel runs at submission, while a linked close would wait
	; for task work, after the slot (freed below) may hold a new socket.
	; (by user_data, the upstream's ops in flight, the kernel finds them at
	; once; by descriptor, it looks at every request of the ring, only when
	; the session has more in flight than it knows of)
	mov	rdx,SOPS_UP
	mov	ecx,OP_IGNORE
	call	sess_cancel_ops
	jnc	.cancelled
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_ASYNC_CANCEL
	mov	ecx,[g_upslot+rbx*4]
	mov	[rax+SQE_FD],ecx
	mov	dword [rax+SQE_OP_FLAGS],IORING_ASYNC_CANCEL_FD or IORING_ASYNC_CANCEL_FD_FIXED or IORING_ASYNC_CANCEL_ALL
	mov	rcx,OP_IGNORE shl 56
	mov	[rax+SQE_USER_DATA],rcx
.cancelled:
	mov	edi,OP_S_CLOSE
	mov	esi,ebx
	call	sess_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_CLOSE
	mov	ecx,[g_upslot+rbx*4]
	inc	ecx
	mov	[rax+SQE_FILE_INDEX],ecx
	mov	edi,[g_upslot+rbx*4]
	call	upslot_free
	jmp	.done
.epoll:
	mov	edi,[r12+S_UPFD]
	mov	eax,SYS_close
	syscall
.done:
	pop	r12
	ret

bss
	g_peek_byte	db ?
	g_up_peek	rb 1 shl 20	; a session's peek of its pooled connection: UPK_*
end bss
UPK_WAIT	:= 1		; the request waits for it
UPK_BESIDE	:= 2		; the request went right behind it
UPK_BAD		:= 3		; and the connection was closed or dirty: send it again

; A pooled connection's peek (h_connect): -EAGAIN, nothing there, and the
; request goes (or went); a FIN, an error or bytes the backend had no reason
; to send, and it is closed and another one found (for a request already
; sent behind the peek: when that send is done, http_send_plain).
on_h_peek:
	mov	[g_cur_sess],ebx
	call	sess_complete
	jc	.out
	cmp	dword [rax+S_STATE],ST_CLOSING
	je	.closing
	movzx	eax,byte [g_up_peek+rbx]
	mov	byte [g_up_peek+rbx],0
	cmp	r14,-EAGAIN
	je	.clean
	cmp	eax,UPK_BESIDE
	jne	.another
	mov	byte [g_up_peek+rbx],UPK_BAD
	ret
.clean:
	cmp	eax,UPK_WAIT
	je	http_connected
	ret
.another:
	cmp	eax,UPK_WAIT
	jne	.out
	call	h_upclose
	h_rec
	and	dword [r15+H_FLAGS],not HX_REUSED
	mov	dword [r15+H_STATE],HS_CONNECT
	jmp	h_connect
.closing:
	mov	edi,ebx
	jmp	session_maybe_free
.out:
	ret

; completions: ebx = session, r12d = generation, r14 = res
on_h_recv_c:
	xor	ecx,ecx
	jmp	on_h_recv
on_h_recv_u:
	mov	ecx,SIDE_UP
on_h_recv:
	mov	[g_cur_sess],ebx		; (for quarantine.inc, should it crash)
	push	rcx
	call	sess_complete
	pop	rcx
	jc	.out
	cmp	dword [rax+S_STATE],ST_CLOSING
	je	.closing
	test	ecx,ecx
	jz	.deliver
	cmp	r14,-5				; -EIO: a kTLS control record is next
	jne	.deliver
	h_rec
	cmp	dword [r15+H_UPKTLS],0
	je	.deliver
	jmp	http_updrain
.deliver:
	mov	rax,r14
	jmp	http_recv_done
.closing:
	mov	edi,ebx
	jmp	session_maybe_free
.out:
	ret

on_h_send_c:
on_h_send_u:
	mov	[g_cur_sess],ebx		; (for quarantine.inc, should it crash)
	call	sess_complete
	jc	.out
	cmp	dword [rax+S_STATE],ST_CLOSING
	je	.closing
	mov	r8d,ebx
	shl	r8,H_SHIFT
	add	r8,[g_http_base]
	mov	ecx,[r8+H_SSIDE]
	test	r14,r14
	jle	.failed
	add	[r8+H_SPTR],r14
	sub	[r8+H_SLEN],r14d
	jnz	h_send_more			; partly sent: the rest
	xor	eax,eax
	jmp	http_send_done
.failed:
	mov	rax,-1
	jmp	http_send_done
.closing:
	mov	edi,ebx
	jmp	session_maybe_free
.out:
	ret

; ------------------------------------------------------------------ epoll
;
; An operation is tried at once; when the socket is not ready it waits
; for the event. A result available at once is queued and delivered by
; the main loop (ep_http_ready), never from inside the call, so a long
; body does not turn into deep recursion.

H_SSIDE		:= 68		; d: side of the pending send
H_EPOP		:= 136		; d: 0 none, 1 recv waiting, 2 send waiting, 3 sendfile waiting (zc.inc)
H_EPSIDE	:= 140
H_EPBUF		:= 144		; q: receive buffer
H_EPLEN		:= 152		; d: its room
H_READY		:= 156		; d: queued result's kind (1 recv, 2 send), 0 none
H_RSIDE		:= 160
H_RESULT	:= 168		; q
H_RNEXT		:= 176		; d: ready queue link
H_EPPEEK	:= 392		; d: MSG_PEEK for the waiting receive, or 0
H_RGEN		:= 180		; d: generation when queued
assert H_RCK + CK_SIZE <= H_EPOP

bss
	g_hready_head	dd ?
	g_hready_tail	dd ?
	g_hlater_head	dd ?			; hep_later: for the next turn
	g_hlater_tail	dd ?
	g_hr_left	dd ?			; ep_http_ready: deliveries left this turn
	g_hq_later	dd ?			; 1: hep_queue delivers on the next turn of the
						; loop, not in this one's ep_http_ready: a body
						; sent a share at a time (zero copy with epoll) to
						; a client that keeps up would otherwise keep the
						; loop from its events and its tick for as long as
						; it goes (ticks 250 ms late, the overload manager
						; shedding)
	g_force_server	dd ?		; NIL, or the server the next connect uses
	g_h_peek	dd ?		; MSG_PEEK for the next h_recv, once
end bss

; edi = fd, esi = events, rdx = data: change a registration.
ep_mod:
	sub	rsp,16
	mov	[rsp],esi
	mov	[rsp+4],rdx
	mov	r10,rsp
	mov	edx,edi
	mov	edi,[g_epfd]
	mov	esi,3				; EPOLL_CTL_MOD
	mov	eax,SYS_epoll_ctl
	syscall
	add	rsp,16
	ret

; ebx = session, ecx = side: the socket.
hep_fd:
	call	session_ptr
	test	ecx,ecx
	jnz	@f
	mov	eax,[rax+S_CLIENT]
	ret
@@:
	mov	eax,[rax+S_UPFD]
	ret

hep_recv:
	h_rec
	mov	eax,[g_h_peek]
	mov	[r15+H_EPPEEK],eax
	mov	dword [g_h_peek],0
	mov	dword [r15+H_EPOP],1
	mov	[r15+H_EPSIDE],ecx
	mov	[r15+H_EPBUF],rdi
	mov	[r15+H_EPLEN],esi
	jmp	hep_try_recv

; Try the waiting receive of session ebx. Queues the result unless the
; socket has nothing yet.
hep_try_recv:
	h_rec
	mov	ecx,[r15+H_EPSIDE]
	call	hep_fd
	mov	edi,eax
	mov	rsi,[r15+H_EPBUF]
	mov	edx,[r15+H_EPLEN]
	mov	r10d,[r15+H_EPPEEK]
	xor	r8d,r8d
	xor	r9d,r9d
	mov	eax,SYS_recvfrom		; a read, or a peek
	syscall
	cmp	rax,-EAGAIN
	je	.wait
	cmp	rax,-EINTR
	je	hep_try_recv
	cmp	rax,-5				; -EIO: a kTLS control record is next
	je	.control
.result:
	mov	dword [r15+H_EPOP],0
	mov	edx,1
	mov	ecx,[r15+H_EPSIDE]
	jmp	hep_queue
.wait:
	ret
; on a kTLS upstream, a NewSessionTicket: consume it with recvmsg (a
; control buffer makes the kernel hand the record over), discard it and
; read again (as http_updrain on io_uring)
.control:
	cmp	dword [r15+H_EPSIDE],0
	je	.result
	cmp	dword [r15+H_UPKTLS],0
	je	.result
	call	session_ptr
	mov	edi,[rax+S_UPFD]
	mov	r8,[r15+H_BUF]
	lea	rax,[r8+HB_UDISC]		; iovec -> the discard buffer
	mov	[r8+HB_UIOV],rax
	mov	qword [r8+HB_UIOV+8],4096
	mov	qword [r8+HB_UMSG],0		; msg_name
	mov	qword [r8+HB_UMSG+8],0		; msg_namelen
	lea	rax,[r8+HB_UIOV]
	mov	[r8+HB_UMSG+16],rax		; msg_iov
	mov	qword [r8+HB_UMSG+24],1		; msg_iovlen
	lea	rax,[r8+HB_UCTL]
	mov	[r8+HB_UMSG+32],rax		; msg_control
	mov	qword [r8+HB_UMSG+40],64	; msg_controllen
	mov	dword [r8+HB_UMSG+48],0		; msg_flags
	lea	rsi,[r8+HB_UMSG]
	mov	edx,MSG_DONTWAIT
	mov	eax,SYS_recvmsg
	syscall
	cmp	rax,-EAGAIN
	je	.wait
	cmp	rax,-EINTR
	je	.control
	test	rax,rax
	jns	hep_try_recv			; consumed: the read the proxy wanted
	mov	rax,-5
	jmp	.result

hep_send:
	h_rec
	mov	[r15+H_SPTR],rdi
	mov	[r15+H_SLEN],esi
	mov	[r15+H_SSIDE],ecx
	mov	dword [r15+H_EPOP],2
	mov	[r15+H_EPSIDE],ecx

; Write what is pending; queue the result once all is written or on an
; error.
hep_try_send:
	h_rec
.again:
	cmp	dword [r15+H_SLEN],0
	je	.done
	mov	ecx,[r15+H_EPSIDE]
	call	hep_fd
	mov	edi,eax
	mov	rsi,[r15+H_SPTR]
	mov	edx,[r15+H_SLEN]
	mov	eax,SYS_write
	syscall
	cmp	rax,-EAGAIN
	je	.wait
	cmp	rax,-EINTR
	je	.again
	test	rax,rax
	jle	.failed
	add	[r15+H_SPTR],rax
	sub	[r15+H_SLEN],eax
	jmp	.again
.done:
	xor	eax,eax
	jmp	.queue
.failed:
	mov	rax,-1
.queue:
	mov	dword [r15+H_EPOP],0
	mov	edx,2
	mov	ecx,[r15+H_EPSIDE]
	jmp	hep_queue
.wait:
	ret

; Queue a result: ebx = session, edx = kind, ecx = side, rax = result.
hep_queue:
	h_rec
	mov	r8d,[r15+H_READY]		; queued already (a slot freed and reused
	mov	[r15+H_READY],edx		; before its delivery): it carries this one
	mov	[r15+H_RSIDE],ecx
	mov	[r15+H_RESULT],rax
	call	session_ptr
	mov	eax,[rax+S_GEN]
	mov	[r15+H_RGEN],eax
	xor	r9d,r9d
	xchg	r9d,[g_hq_later]		; for the next turn (hep_later)
	test	r8d,r8d
	jnz	.queued
	mov	dword [r15+H_RNEXT],NIL
	test	r9d,r9d
	jz	@f
	mov	eax,[g_hlater_tail]
	cmp	dword [g_hlater_head],NIL
	jne	.later
	mov	[g_hlater_head],ebx
	mov	[g_hlater_tail],ebx
	ret
.later:
	shl	rax,H_SHIFT
	add	rax,[g_http_base]
	mov	[rax+H_RNEXT],ebx
	mov	[g_hlater_tail],ebx
	ret
@@:
	mov	eax,[g_hready_tail]
	cmp	dword [g_hready_head],NIL
	jne	@f
	mov	[g_hready_head],ebx
	mov	[g_hready_tail],ebx
	ret
@@:
	shl	rax,H_SHIFT
	add	rax,[g_http_base]
	mov	[rax+H_RNEXT],ebx
	mov	[g_hready_tail],ebx
.queued:
	ret

; Main loop: deliver the queued results, and what they queue in turn, up to
; HR_BUDGET of them: the rest on the next turn of the loop (which does not sleep
; then). A body copied to a client that keeps up is a delivery for each piece, each
; queueing the next: without a bound the loop kept from its events and its tick for
; as long as it went (ticks 250 ms late, the overload manager shedding).
HR_BUDGET	:= 1024

ep_http_ready:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	dword [g_hr_left],HR_BUDGET
.next:
	mov	ebx,[g_hready_head]
	cmp	ebx,NIL
	je	.done
	dec	dword [g_hr_left]
	js	.done
	h_rec
	mov	eax,[r15+H_RNEXT]
	mov	[g_hready_head],eax
	cmp	eax,NIL
	jne	@f
	mov	[g_hready_tail],eax
@@:
	mov	edx,[r15+H_READY]
	mov	dword [r15+H_READY],0
	call	session_ptr
	mov	ecx,[rax+S_GEN]
	cmp	ecx,[r15+H_RGEN]
	jne	.next				; that session is gone
	cmp	dword [rax+S_STATE],ST_FREE
	je	.next
	cmp	dword [rax+S_STATE],ST_CLOSING
	je	.next
	mov	ecx,[r15+H_RSIDE]
	mov	rax,[r15+H_RESULT]
	cmp	edx,2
	je	.send
	cmp	edx,3
	je	.plain_recv
	cmp	edx,4
	je	.plain_send
	cmp	edx,5
	je	.counted
	call	http_recv_done
	jmp	.next
.counted:					; a body by splice: on, or done
	test	rax,rax
	jz	.counted_on
	call	http_counted_done
	jmp	.next
.counted_on:
	call	hep_counted_pump
	jmp	.next
.send:
	call	http_send_done
	jmp	.next
.plain_recv:					; user-space TLS: plaintext
	call	http_recv_plain
	jmp	.next
.plain_send:
	call	http_send_plain
	jmp	.next
.done:
	mov	eax,[g_hlater_head]		; what waited for this turn: the next one's
	cmp	eax,NIL
	je	.none_later
	mov	ecx,[g_hready_tail]
	cmp	dword [g_hready_head],NIL
	jne	@f
	mov	[g_hready_head],eax
	jmp	.joined
@@:
	shl	rcx,H_SHIFT
	add	rcx,[g_http_base]
	mov	[rcx+H_RNEXT],eax
.joined:
	mov	eax,[g_hlater_tail]
	mov	[g_hready_tail],eax
	mov	dword [g_hlater_head],NIL
	mov	dword [g_hlater_tail],NIL
.none_later:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; ep_dispatch, for a session of an http listener: edi = events, r8d = side.
hep_event:
	h_rec
	cmp	dword [r15+H_STATE],HS_H2
	je	h2_ep_event			; an HTTP/2 connection reads and writes at once
	test	dword [r15+H_FLAGS],HX_TSEND	; WebSocket over a stream: the backend's
	jz	@f				; socket has room again
	cmp	r8d,SIDE_UP
	jne	@f
	test	edi,EPOLLOUT or EPOLLERR or EPOLLHUP
	jz	@f
	push	rdi
	push	r8
	and	dword [r15+H_FLAGS],not HX_TSEND
	call	http_h2tun_pump
	pop	r8
	pop	rdi
	h_rec
@@:
	cmp	dword [r15+H_EPOP],0
	je	.out
	cmp	[r15+H_EPSIDE],r8d
	jne	.out
	cmp	dword [r15+H_EPOP],1
	je	.recv
	cmp	dword [r15+H_EPOP],4
	je	.counted
	test	edi,EPOLLOUT or EPOLLERR or EPOLLHUP
	jz	.out
	cmp	dword [r15+H_EPOP],3
	je	zc_ep_try			; zero copy: sendfile on (zc.inc)
	jmp	hep_try_send
.recv:
	test	edi,EPOLLIN or EPOLLRDHUP or EPOLLHUP or EPOLLERR
	jz	.out
	jmp	hep_try_recv
.counted:					; the body by splice (counted.inc)
	mov	dword [r15+H_EPOP],0
	jmp	hep_counted_pump
.out:
	ret

; ebx = session: connect (state set by h_connect).
hep_connect:
	mov	edi,ebx
	jmp	ep_connect

; rax = record of a client (HTTP/1.1, or a stream of 2 or 3): writing an answer,
; each piece starts the clock of body_idle again: a client that takes no byte
; (or gives no window) for that long is closed, or its stream (a slow read holds
; the connection and its backend's). Keeps the registers.
h_send_clock:
	mov	edx,[rax+H_STATE]
	cmp	edx,HS_RESP_SEND
	je	.arm
	cmp	edx,HS_ERROR_SEND
	je	.arm
	cmp	edx,HS_SELF_SEND
	je	.arm
	cmp	edx,HS_ADSEND
	je	.arm
	cmp	edx,HS_SELF_TAIL
	je	.arm
	cmp	edx,HS_INTERIM_SEND
	jne	.out
.arm:
	push	rax
	push	rcx
	push	rsi
	push	rdi
	push	r8
	mov	edi,ebx
	mov	esi,PH_BODY
	call	ph_arm
	pop	r8
	pop	rdi
	pop	rsi
	pop	rcx
	pop	rax
.out:
	ret
