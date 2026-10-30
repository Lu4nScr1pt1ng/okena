; L4 TCP proxy on epoll: the engine for hosts where io_uring is blocked
; (Docker, containerd and Kubernetes default seccomp profiles, gVisor,
; kernel.io_uring_disabled) and the automatic fallback.
;
; Sessions, balancing, failover, idle lists and drain are shared with the
; io_uring engine; only the I/O differs. Sockets are non-blocking and
; edge-triggered. Each direction holds at most one buffer: bytes read
; from one side are written to the other before the next read, so a slow
; reader stops us reading from its peer (backpressure as with io_uring).
; Buffers come from a LIFO stack over the same reserved region, the most
; recently used first, and only when bytes are there to read.
;
; epoll data: index | generation << 32 | kind << 56. Kinds: client side,
; upstream side, listener, signalfd. The generation drops events that
; were already fetched for a session closed earlier in the same batch.

S_UPFD		:= 76		; upstream fd (epoll engine)
S_DEADLINE	:= 80		; q: connect deadline, monotonic ms
S_CPREV		:= 88		; pool connect list
S_CNEXT		:= 92

EK_CLIENT	:= 0
EK_UPSTREAM	:= 1
EK_LISTENER	:= 2
EK_SIGNAL	:= 3

ENGINE_URING	:= 0
ENGINE_EPOLL	:= 1

EP_EVENTS	:= 256
ACCEPT_BATCH	:= 64

bss
	align 8
	g_engine	dd ?
	g_epfd		dd ?
	g_now_ms	dq ?
	g_next_tick_ms	dq ?
	g_buf_top	dd ?		; free buffer stack
	g_buf_hwm	dd ?		; buffers ever used
	g_cl_head	rd MAX_POOLS	; connecting sessions, oldest first
	g_cl_tail	rd MAX_POOLS
	g_buf_stack	rd BUF_MAX
	g_ep_events:	rb EPOLL_EVENT * EP_EVENTS
	g_ep_sa:	rb 28
	g_ep_salen	dd ?
end bss

; Never returns.
ep_main:
	mov	dword [g_engine],ENGINE_EPOLL
	xor	ecx,ecx
@@:
	mov	dword [g_cl_head+rcx*4],NIL
	mov	dword [g_cl_tail+rcx*4],NIL
	inc	ecx
	cmp	ecx,MAX_POOLS
	jb	@b
	mov	dword [g_hready_head],NIL
	mov	dword [g_hready_tail],NIL
	mov	edi,EPOLL_CLOEXEC
	mov	eax,SYS_epoll_create1
	syscall
	test	eax,eax
	js	.no_epoll
	mov	[g_epfd],eax
	call	ep_add_listeners
	mov	edi,[g_sigfd]
	mov	esi,EPOLLIN
	mov	rdx,EK_SIGNAL shl 56
	call	ep_add
	call	ep_clock
	mov	rax,[g_now_ms]
	add	rax,1000
	mov	[g_next_tick_ms],rax
	seccomp_for filter_worker_epoll
.loop:
	cmp	dword [g_draining],2
	jne	@f
	cmp	dword [g_active],0
	je	.drained
@@:
	call	ep_wait_timeout			; edx = ms
	mov	edi,[g_epfd]
	lea	rsi,[g_ep_events]
	mov	r10d,edx
	mov	edx,EP_EVENTS
	mov	eax,SYS_epoll_wait
	syscall
	mov	r12,rax
	call	ep_clock
	test	r12,r12
	jle	.timers
	xor	ebx,ebx
.event:
	cmp	rbx,r12
	jae	.timers
	imul	rax,rbx,EPOLL_EVENT
	lea	rax,[g_ep_events+rax]
	mov	edi,[rax]			; events
	mov	rsi,[rax+4]			; data
	push	rbx
	push	r12
	call	ep_dispatch
	pop	r12
	pop	rbx
	inc	ebx
	jmp	.event
.timers:
	call	ep_http_ready
	call	ep_wake_waiters
	call	ep_connect_deadlines
	mov	rax,[g_now_ms]
	cmp	rax,[g_next_tick_ms]
	jb	.loop
	add	qword [g_next_tick_ms],1000
	cmp	rax,[g_next_tick_ms]
	jb	@f
	lea	rcx,[rax+1000]			; slept long: do not replay missed ticks
	mov	[g_next_tick_ms],rcx
@@:
	call	tick_work
	jmp	.loop
.drained:
	call	alog_flush
	mov	edi,EXIT_OK
	jmp	exit_process
.no_epoll:
	push	rax
	call	log_begin
	out_lit 'epoll_create1 failed (errno '
	pop	rax
	neg	rax
	call	out_u64
	out_lit ')'
	call	log_end
	mov	edi,EXIT_FATAL
	jmp	exit_process

; g_now_ms = monotonic milliseconds.
ep_clock:
	sub	rsp,24
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
	mov	[g_now_ms],rax
	add	rsp,24
	ret

; edx = milliseconds until the next tick or connect deadline.
ep_wait_timeout:
	mov	r8,[g_next_tick_ms]
	xor	ecx,ecx
.pool:
	cmp	ecx,[g_plan_pools]
	jae	.done
	mov	eax,[g_cl_head+rcx*4]
	cmp	eax,NIL
	je	.next
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	mov	rax,[rax+S_DEADLINE]
	cmp	rax,r8
	cmovb	r8,rax
.next:
	inc	ecx
	jmp	.pool
.done:
	mov	rax,r8
	sub	rax,[g_now_ms]
	jge	@f
	xor	eax,eax
@@:
	inc	eax				; round up: never wake before a deadline
	mov	edx,eax
	ret

; edi = fd, esi = events, rdx = data.
ep_add:
	sub	rsp,16
	mov	[rsp],esi
	mov	[rsp+4],rdx
	mov	r10,rsp
	mov	edx,edi
	mov	edi,[g_epfd]
	mov	esi,EPOLL_CTL_ADD
	mov	eax,SYS_epoll_ctl
	syscall
	add	rsp,16
	ret

ep_add_listeners:
	lea	rsi,[ep_add_socket]
	jmp	for_each_socket

; edi = socket id.
ep_add_socket:
	mov	edx,edi
	mov	rcx,EK_LISTENER shl 56
	or	rdx,rcx
	push	rdx
	call	listener_fd
	pop	rdx
	mov	edi,eax
	mov	esi,EPOLLIN			; level-triggered: accept in batches
	jmp	ep_add

; Drain: stop watching the listeners (connections wait in the kernel queue).
ep_stop_accepting:
	lea	rsi,[ep_del_socket]
	jmp	for_each_socket

ep_del_socket:
	call	listener_fd
	mov	edx,eax
	mov	edi,[g_epfd]
	mov	esi,EPOLL_CTL_DEL
	xor	r10d,r10d
	mov	eax,SYS_epoll_ctl
	syscall
	ret

; edi = events, rsi = data.
ep_dispatch:
	mov	rax,rsi
	shr	rax,56
	cmp	eax,EK_LISTENER
	je	.listener
	cmp	eax,EK_SIGNAL
	je	.signal
	cmp	eax,EK_POOL
	je	.pooled
	; a session side: check the generation
	mov	r8d,eax				; side
	mov	r9,rsi
	shr	r9,32
	and	r9d,0xFFFFFF
	mov	ebx,esi
	call	session_ptr
	mov	ecx,[rax+S_GEN]
	and	ecx,0xFFFFFF
	cmp	ecx,r9d
	jne	.stale
	cmp	dword [rax+S_STATE],ST_CONNECTING
	je	.connecting
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.stale
	test	dword [rax+S_FLAGS],SF_TLS_HS
	jnz	hep_event			; a tcp session in its TLS handshake
	mov	ecx,[rax+S_LST]
	imul	rcx,rcx,LS_SIZE
	cmp	dword [g_listeners+rcx+LS_KIND],LK_HTTP
	jne	@f
	test	dword [rax+S_FLAGS],SF_TUNNEL
	jz	hep_event
@@:
	; writable first: a flushed buffer lets the source be read again
	mov	r12d,edi
	mov	r13d,r8d
	test	r12d,EPOLLOUT
	jz	.readable
	mov	edi,ebx
	mov	esi,r13d			; destination side
	call	ep_resume
	call	session_ptr
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.stale
.readable:
	test	r12d,EPOLLIN or EPOLLRDHUP or EPOLLHUP or EPOLLERR
	jz	.stale
	mov	edi,ebx
	mov	esi,r13d			; source side
	jmp	ep_pump
.connecting:
	cmp	r8d,EK_UPSTREAM
	jne	.stale				; client bytes wait until connected
	test	edi,EPOLLOUT or EPOLLERR or EPOLLHUP
	jz	.stale
	mov	edi,ebx
	jmp	ep_connect_result
.listener:
	mov	edi,esi
	jmp	ep_accept
.pooled:
	; an idle pooled connection: the backend closed it or sent something
	mov	edi,esi
	jmp	pool_drop_handle
.signal:
	sub	rsp,8
	mov	edi,[g_sigfd]
	lea	rsi,[g_sig_buf]
	mov	edx,SIGINFO_SIZE
	xor	eax,eax
	syscall
	add	rsp,8
	jmp	drain_begin
.stale:
	ret

; edi = socket id: accept a batch.
ep_accept:
	push	rbx
	push	r12
	push	r13
	push	r15
	call	listener_fd
	mov	r15d,eax
	and	edi,0xFF
	mov	r13d,edi			; listener
	mov	r12d,ACCEPT_BATCH
.next:
	dec	r12d
	js	.done
	mov	edi,r15d
	xor	esi,esi
	xor	edx,edx
	imul	rax,r13,LS_SIZE
	test	dword [g_listeners+rax+LS_FLAGS],LSF_PEER
	jz	@f
	mov	dword [g_ep_salen],28
	lea	rsi,[g_ep_sa]
	lea	rdx,[g_ep_salen]
@@:
	mov	r10d,SOCK_NONBLOCK or SOCK_CLOEXEC
	mov	eax,SYS_accept4
	syscall
	test	eax,eax
	js	.done				; EAGAIN, or an error for this one only
	mov	r14d,eax
	mov	eax,[g_ls_active+r13*4]
	cmp	eax,[g_ls_cap+r13*4]
	jae	.refuse
	call	session_alloc
	cmp	eax,NIL
	je	.refuse
	mov	ebx,eax
	inc	dword [g_ls_active+r13*4]
	inc	qword [g_st_l_accepted+r13*8]
	inc	dword [g_active]
	call	session_ptr
	mov	dword [rax+S_STATE],ST_CONNECTING
	mov	dword [rax+S_FLAGS],0
	mov	[rax+S_CLIENT],r14d
	mov	[rax+S_LST],r13d
	mov	dword [rax+S_TRIES],0
	mov	dword [rax+S_SERVER],NIL
	mov	dword [rax+S_CU_BID],NIL
	mov	dword [rax+S_UC_BID],NIL
	mov	ecx,[g_tick]
	mov	[rax+S_LAST],ecx
	imul	rcx,r13,LS_SIZE
	mov	ecx,[g_listeners+rcx+LS_POOL]
	mov	[rax+S_POOL],ecx
	mov	edi,ebx
	call	idle_append
	mov	edi,r14d
	mov	esi,EPOLLIN or EPOLLOUT or EPOLLRDHUP or EPOLLET
	mov	edx,EK_CLIENT
	call	ep_session_data
	call	ep_add
	imul	rax,r13,LS_SIZE
	test	dword [g_listeners+rax+LS_FLAGS],LSF_PEER
	jz	.connect
	call	session_ptr
	or	dword [rax+S_FLAGS],SF_PEER
	call	peer_ptr
	mov	rdi,rax
	lea	rsi,[g_ep_sa]
	mov	ecx,28
	rep	movsb
	call	peer_admit			; per_source, PROXY header
	jc	.over
	imul	rax,r13,LS_SIZE
	cmp	dword [g_listeners+rax+LS_KIND],LK_HTTP
	jne	.connect
	push	r12
	push	r13
	push	r14
	push	r15
	call	http_start
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	jmp	.next
.over:
	inc	qword [g_st_l_source+r13*8]
	dec	qword [g_st_l_accepted+r13*8]	; refused, not admitted
	mov	edi,ebx
	call	ep_close
	jmp	.next
.connect:
	call	tcp_tls_wanted
	test	rax,rax
	jz	.plain
	push	r12
	push	r13
	push	r14
	push	r15
	call	tcp_tls_start			; TLS first, then the upstream
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	jmp	.next
.plain:
	mov	edi,ebx
	call	ep_connect
	jmp	.next
.refuse:
	inc	qword [g_st_l_full+r13*8]
	mov	edi,r14d
	mov	eax,SYS_close
	syscall
	jmp	.next
.done:
	pop	r15
	pop	r13
	pop	r12
	pop	rbx
	ret

; ebx = session, edx = kind. rdx = epoll data. Keeps edi, esi.
ep_session_data:
	shl	rdx,56
	call	session_ptr
	mov	eax,[rax+S_GEN]
	and	eax,0xFFFFFF
	shl	rax,32
	or	rdx,rax
	mov	eax,ebx
	or	rdx,rax
	ret

; edi = session: connect to a server of its pool.
ep_connect:
	push	rbx
	push	r12
	push	r13
	mov	ebx,edi
	call	session_ptr
	mov	r12,rax
	inc	dword [r12+S_TRIES]
	call	session_uncount
	test	dword [r12+S_FLAGS],SF_UP_OPEN
	jz	@f
	and	dword [r12+S_FLAGS],not SF_UP_OPEN
	mov	edi,[r12+S_UPFD]
	mov	eax,SYS_close
	syscall
@@:
	mov	eax,[g_force_server]
	mov	dword [g_force_server],NIL
	cmp	eax,NIL
	jne	@f
	call	pick_avoid_tried
	mov	edi,[r12+S_POOL]
	mov	esi,[r12+S_SERVER]
	call	server_pick
@@:
	cmp	eax,NIL
	je	.no_socket			; nowhere to go: close
	mov	ecx,[r12+S_SERVER]
	mov	[r12+S_SERVER2],ecx
	mov	[r12+S_SERVER],eax
	call	sv_connect_start
	inc	dword [g_sv_active+rax*4]
	or	dword [r12+S_FLAGS],SF_COUNTED
	imul	r13,rax,SV_SIZE
	lea	r13,[g_servers+r13]
	mov	edi,[r13+SV_FAMILY]
	mov	esi,SOCK_STREAM or SOCK_NONBLOCK or SOCK_CLOEXEC
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	.no_socket
	mov	[r12+S_UPFD],eax
	or	dword [r12+S_FLAGS],SF_UP_OPEN
	cmp	dword [r13+SV_FAMILY],AF_UNIX
	je	@f
	mov	edi,eax
	mov	esi,IPPROTO_TCP
	mov	edx,TCP_NODELAY
	lea	r10,[one_int]
	mov	r8d,4
	mov	eax,SYS_setsockopt
	syscall
@@:
	mov	edi,[r12+S_UPFD]
	mov	esi,EPOLLIN or EPOLLOUT or EPOLLRDHUP or EPOLLET
	mov	edx,EK_UPSTREAM
	call	ep_session_data
	call	ep_add
	mov	edi,[r12+S_UPFD]
	lea	rsi,[r13+SV_SA]
	mov	edx,[r13+SV_SALEN]
	mov	eax,SYS_connect
	syscall
	test	eax,eax
	jz	.connected
	cmp	eax,-EINPROGRESS
	jne	.failed
	; wait for writability, with the pool's connect timeout
	mov	eax,[r12+S_POOL]
	imul	rcx,rax,PL_SIZE
	imul	rdx,[g_pools+rcx+PL_TIMEOUT],1000
	mov	r8,rax
	mov	rax,[g_pools+rcx+PL_TIMEOUT+8]
	push	rdx
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	pop	rdx
	add	rax,rdx
	add	rax,[g_now_ms]
	mov	[r12+S_DEADLINE],rax
	mov	edi,ebx
	mov	esi,r8d
	call	connect_list_append
	jmp	.out
.connected:
	mov	edi,ebx
	call	ep_connected
	jmp	.out
.failed:
	mov	edi,ebx
	movsxd	rsi,eax
	call	ep_connect_failed
	jmp	.out
.no_socket:
	mov	edi,ebx
	call	ep_close
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; edi = session, esi = pool: append to the pool's connect list.
connect_list_append:
	mov	eax,edi
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	mov	edx,[g_cl_tail+rsi*4]
	mov	[rax+S_CPREV],edx
	mov	dword [rax+S_CNEXT],NIL
	mov	[g_cl_tail+rsi*4],edi
	cmp	edx,NIL
	je	.first
	shl	rdx,S_SHIFT
	add	rdx,[g_sess_base]
	mov	[rdx+S_CNEXT],edi
	ret
.first:
	mov	[g_cl_head+rsi*4],edi
	ret

; edi = session: unlink from its pool's connect list, if on it.
connect_list_remove:
	mov	eax,edi
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	cmp	dword [rax+S_DEADLINE],0
	jne	@f
	cmp	dword [rax+S_DEADLINE+4],0
	je	.done				; not on a list
@@:
	mov	qword [rax+S_DEADLINE],0
	mov	ecx,[rax+S_POOL]
	mov	edx,[rax+S_CPREV]
	mov	r8d,[rax+S_CNEXT]
	cmp	edx,NIL
	je	.head
	mov	r9d,edx
	shl	r9,S_SHIFT
	add	r9,[g_sess_base]
	mov	[r9+S_CNEXT],r8d
	jmp	.next
.head:
	mov	[g_cl_head+rcx*4],r8d
.next:
	cmp	r8d,NIL
	je	.tail
	mov	r9d,r8d
	shl	r9,S_SHIFT
	add	r9,[g_sess_base]
	mov	[r9+S_CPREV],edx
	ret
.tail:
	mov	[g_cl_tail+rcx*4],edx
.done:
	ret

; Sessions whose connect took too long: oldest first per pool.
ep_connect_deadlines:
	push	rbx
	push	r12
	xor	r12d,r12d
.pool:
	cmp	r12d,[g_plan_pools]
	jae	.done
.head:
	mov	ebx,[g_cl_head+r12*4]
	cmp	ebx,NIL
	je	.next
	call	session_ptr
	mov	rcx,[rax+S_DEADLINE]
	cmp	rcx,[g_now_ms]
	ja	.next
	mov	edi,ebx
	mov	rsi,-ECANCELED			; reported as "timed out"
	call	ep_connect_failed
	jmp	.head
.next:
	inc	r12d
	jmp	.pool
.done:
	pop	r12
	pop	rbx
	ret

; edi = session in ST_CONNECTING whose upstream became writable.
ep_connect_result:
	push	rbx
	mov	ebx,edi
	call	session_ptr
	sub	rsp,16
	mov	dword [rsp],0
	mov	dword [rsp+8],4
	mov	edi,[rax+S_UPFD]
	mov	esi,SOL_SOCKET
	mov	edx,SO_ERROR
	mov	r10,rsp
	lea	r8,[rsp+8]
	mov	eax,SYS_getsockopt
	syscall
	mov	ecx,[rsp]
	add	rsp,16
	test	eax,eax
	js	.failed
	test	ecx,ecx
	jnz	.error
	mov	edi,ebx
	call	ep_connected
	pop	rbx
	ret
.error:
	neg	ecx
	movsxd	rax,ecx
.failed:
	mov	edi,ebx
	mov	rsi,rax
	call	ep_connect_failed
	pop	rbx
	ret

; edi = session: connected. Start moving bytes; the client may have sent
; some already (its edge passed while we were connecting).
ep_connected:
	push	rbx
	mov	ebx,edi
	call	connect_list_remove
	call	session_ptr
	mov	dword [rax+S_STATE],ST_OPEN
	mov	edi,[rax+S_SERVER]
	call	server_ok
	call	sv_connect_sample
	call	session_ptr
	mov	ecx,[rax+S_LST]
	imul	rcx,rcx,LS_SIZE
	cmp	dword [g_listeners+rcx+LS_KIND],LK_HTTP
	jne	@f
	call	http_connected
	pop	rbx
	ret
@@:
	; a PROXY protocol header goes first; on a fresh connection it fits
	; the send buffer, so one write sends it all or the session ends
	call	session_ptr
	mov	ecx,[rax+S_LST]
	imul	rcx,rcx,LS_SIZE
	test	dword [g_listeners+rcx+LS_FLAGS],LSF_PP_V1 or LSF_PP_V2
	jz	.relay
	mov	edi,[rax+S_UPFD]
	call	peer_ptr
	lea	rsi,[rax+P_HDR]
	mov	edx,[rax+P_HLEN]
	push	rdx
	mov	eax,SYS_write
	syscall
	pop	rdx
	cmp	eax,edx
	je	.relay
	mov	edi,ebx
	call	ep_close
	pop	rbx
	ret
.relay:
	; tls passthrough: the ClientHello read before connecting goes first
	; (a fresh connection's buffer takes it whole, as the PROXY header)
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_PREFIX
	jz	.pump
	and	dword [rax+S_FLAGS],not SF_PREFIX
	mov	edi,[rax+S_UPFD]
	mov	r8d,ebx
	shl	r8,H_SHIFT
	add	r8,[g_http_base]
	mov	rsi,[r8+H_BUF]
	mov	edx,[r8+H_INLEN]
	push	rdx
	mov	eax,SYS_write
	syscall
	pop	rdx
	cmp	eax,edx
	je	.pump
	mov	edi,ebx
	call	ep_close
	pop	rbx
	ret
.pump:
	mov	edi,ebx
	mov	esi,EK_CLIENT
	call	ep_pump
	call	session_ptr
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	@f
	mov	edi,ebx
	mov	esi,EK_UPSTREAM
	call	ep_pump
@@:
	pop	rbx
	ret

; edi = session, rsi = -errno: try another server or give up.
ep_connect_failed:
	push	rbx
	push	r12
	mov	ebx,edi
	call	connect_list_remove
	call	session_ptr
	mov	r12,rax
	mov	edi,[r12+S_SERVER]
	call	server_failed
	cmp	dword [r12+S_TRIES],MAX_TRIES
	jae	.give_up
	mov	eax,[r12+S_POOL]
	imul	rax,rax,PL_SIZE
	mov	ecx,[g_pools+rax+PL_COUNT]
	cmp	[r12+S_TRIES],ecx
	jae	.give_up
	mov	edi,ebx
	call	ep_connect
	jmp	.out
.give_up:
	call	session_ptr
	mov	ecx,[rax+S_LST]
	imul	rcx,rcx,LS_SIZE
	cmp	dword [g_listeners+rcx+LS_KIND],LK_HTTP
	jne	@f
	call	http_connect_failed
	jmp	.out
@@:
	mov	edi,ebx
	call	ep_close
.out:
	pop	r12
	pop	rbx
	ret

; ---------------------------------------------------------------- buffers

; eax = buffer id or NIL.
ep_buf_get:
	mov	ecx,[g_buf_top]
	test	ecx,ecx
	jz	.fresh
	dec	ecx
	mov	[g_buf_top],ecx
	mov	eax,[g_buf_stack+rcx*4]
	ret
.fresh:
	mov	eax,[g_buf_hwm]
	cmp	eax,BUF_MAX
	jae	.none
	inc	dword [g_buf_hwm]
	ret
.none:
	mov	eax,NIL
	ret

; edi = buffer id.
ep_buf_put:
	mov	ecx,[g_buf_top]
	mov	[g_buf_stack+rcx*4],edi
	inc	ecx
	mov	[g_buf_top],ecx
	ret

; Sessions that waited for a buffer: pump them while buffers are free.
ep_wake_waiters:
	push	rbx
.client:
	mov	ebx,[g_waitq_c_head]
	cmp	ebx,NIL
	je	.upstream
	call	ep_buf_available
	jc	.done
	call	session_ptr
	mov	ecx,[rax+S_WAIT_C]
	mov	[g_waitq_c_head],ecx
	test	dword [rax+S_FLAGS],SF_C_WAIT
	jz	.client
	and	dword [rax+S_FLAGS],not SF_C_WAIT
	mov	edi,ebx
	mov	esi,EK_CLIENT
	call	ep_pump
	jmp	.client
.upstream:
	mov	ebx,[g_waitq_u_head]
	cmp	ebx,NIL
	je	.done
	call	ep_buf_available
	jc	.done
	call	session_ptr
	mov	ecx,[rax+S_WAIT_U]
	mov	[g_waitq_u_head],ecx
	test	dword [rax+S_FLAGS],SF_U_WAIT
	jz	.upstream
	and	dword [rax+S_FLAGS],not SF_U_WAIT
	mov	edi,ebx
	mov	esi,EK_UPSTREAM
	call	ep_pump
	jmp	.upstream
.done:
	pop	rbx
	ret

; CF when no buffer can be had.
ep_buf_available:
	cmp	dword [g_buf_top],0
	jne	.yes
	cmp	dword [g_buf_hwm],BUF_MAX
	jb	.yes
	stc
	ret
.yes:
	clc
	ret

; ------------------------------------------------------------- data path

; Direction registers for a source side esi of session ebx:
;   r12 = session, r13d = source fd, r14d = destination fd,
;   r15 = offset of the direction's BID field (LEN at +4, OFF at +8),
;   ebp = its EOF flag, and the waiting flag in [rsp] (pushed).
macro ep_direction
	call	session_ptr
	mov	r12,rax
	mov	r13d,[r12+S_CLIENT]
	mov	r14d,[r12+S_UPFD]
	mov	r15d,S_CU_BID
	mov	ebp,SF_C_EOF
	cmp	esi,EK_CLIENT
	je	@f
	xchg	r13d,r14d
	mov	r15d,S_UC_BID
	mov	ebp,SF_U_EOF
@@:
end macro

; edi = session, esi = source side: read from it and write to the other
; side until the source has nothing more, or the destination is full.
ep_pump:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	mov	ebx,edi
	push	rsi
	ep_direction
.again:
	cmp	dword [r12+S_STATE],ST_OPEN
	jne	.out
	cmp	dword [r12+r15],NIL
	jne	.out				; a buffer is still being written
	test	[r12+S_FLAGS],ebp
	jnz	.out				; source already ended
	call	ep_buf_get
	cmp	eax,NIL
	je	.wait
	mov	[r12+r15],eax
	mov	edi,r13d
	mov	esi,eax
	shl	rsi,BUF_SHIFT
	add	rsi,[g_buf_base]
	mov	edx,BUF_SIZE
	xor	eax,eax				; SYS_read
	syscall
	test	rax,rax
	jle	.no_data
	mov	ecx,[r12+S_LST]
	lea	rdx,[g_st_l_in+rcx*8]
	cmp	dword [rsp],EK_CLIENT
	je	@f
	lea	rdx,[g_st_l_out+rcx*8]
@@:
	add	[rdx],rax
	mov	[r12+r15+4],eax			; LEN
	mov	dword [r12+r15+8],0		; OFF
	mov	edi,ebx
	call	idle_touch
	call	ep_flush_dir
	jnc	.again				; written out: read more
	jmp	.out
.no_data:
	push	rax
	mov	edi,[r12+r15]
	mov	dword [r12+r15],NIL
	call	ep_buf_put
	pop	rax
	test	rax,rax
	jz	.eof
	cmp	rax,-EAGAIN
	je	.out
	cmp	rax,-EINTR
	je	.again
	mov	edi,ebx
	call	ep_close
	jmp	.out
.eof:
	; pass the FIN on and keep the other direction open
	or	[r12+S_FLAGS],ebp
	mov	eax,[r12+S_FLAGS]
	and	eax,SF_C_EOF or SF_U_EOF
	cmp	eax,SF_C_EOF or SF_U_EOF
	je	.both
	mov	edi,r14d
	mov	esi,SHUT_WR
	mov	eax,SYS_shutdown
	syscall
	jmp	.out
.both:
	mov	edi,ebx
	call	ep_close
	jmp	.out
.wait:
	; no buffer: queue the session, ep_wake_waiters pumps it later
	cmp	dword [rsp],EK_CLIENT
	jne	.wait_u
	test	dword [r12+S_FLAGS],SF_C_WAIT
	jnz	.out
	or	dword [r12+S_FLAGS],SF_C_WAIT
	mov	dword [r12+S_WAIT_C],NIL
	mov	eax,[g_waitq_c_head]
	cmp	eax,NIL
	jne	@f
	mov	[g_waitq_c_head],ebx
	mov	[g_waitq_c_tail],ebx
	jmp	.out
@@:
	mov	eax,[g_waitq_c_tail]
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	mov	[rax+S_WAIT_C],ebx
	mov	[g_waitq_c_tail],ebx
	jmp	.out
.wait_u:
	test	dword [r12+S_FLAGS],SF_U_WAIT
	jnz	.out
	or	dword [r12+S_FLAGS],SF_U_WAIT
	mov	dword [r12+S_WAIT_U],NIL
	mov	eax,[g_waitq_u_head]
	cmp	eax,NIL
	jne	@f
	mov	[g_waitq_u_head],ebx
	mov	[g_waitq_u_tail],ebx
	jmp	.out
@@:
	mov	eax,[g_waitq_u_tail]
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	mov	[rax+S_WAIT_U],ebx
	mov	[g_waitq_u_tail],ebx
.out:
	pop	rsi
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

; Write the direction's buffer (registers as in ep_pump). CF when it is
; not all written yet (the destination is full) or the session closed.
ep_flush_dir:
.again:
	mov	eax,[r12+r15+8]			; OFF
	mov	edx,[r12+r15+4]			; LEN
	sub	edx,eax
	jz	.done
	mov	esi,[r12+r15]
	shl	rsi,BUF_SHIFT
	add	rsi,[g_buf_base]
	add	rsi,rax
	mov	edi,r14d
	mov	eax,SYS_write
	syscall
	test	rax,rax
	jle	.short
	add	[r12+r15+8],eax
	jmp	.again
.short:
	cmp	rax,-EINTR
	je	.again
	cmp	rax,-EAGAIN
	je	.pending
	mov	edi,ebx
	call	ep_close
.pending:
	stc
	ret
.done:
	mov	edi,[r12+r15]
	mov	dword [r12+r15],NIL
	call	ep_buf_put
	clc
	ret

; edi = session, esi = side that became writable: finish the buffer that
; was waiting for it, then read its source again (edge-triggered).
ep_resume:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	mov	ebx,edi
	; the buffer waiting for side esi belongs to the other side's direction
	xor	esi,1
	push	rsi
	ep_direction
	cmp	dword [r12+r15],NIL
	je	.out
	call	ep_flush_dir
	jc	.out
	mov	edi,ebx
	mov	esi,[rsp]
	call	ep_pump
.out:
	pop	rsi
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

; edi = session: close both sockets and free it at once.
ep_close:
	push	rbx
	push	r12
	mov	ebx,edi
	call	session_ptr
	mov	r12,rax
	mov	eax,[r12+S_STATE]
	cmp	eax,ST_FREE
	je	.done
	cmp	eax,ST_CLOSING
	je	.done
	mov	dword [r12+S_STATE],ST_CLOSING
	mov	edi,ebx
	call	idle_remove
	mov	edi,ebx
	call	ph_disarm
	mov	edi,ebx
	call	connect_list_remove
	mov	edi,[r12+S_CLIENT]
	mov	eax,SYS_close
	syscall
	test	dword [r12+S_FLAGS],SF_UP_OPEN
	jz	@f
	mov	edi,[r12+S_UPFD]
	mov	eax,SYS_close
	syscall
@@:
	mov	edi,[r12+S_CU_BID]
	cmp	edi,NIL
	je	@f
	call	ep_buf_put
@@:
	mov	edi,[r12+S_UC_BID]
	cmp	edi,NIL
	je	@f
	call	ep_buf_put
@@:
	mov	dword [r12+S_CU_BID],NIL
	mov	dword [r12+S_UC_BID],NIL
	call	session_uncount
	test	dword [r12+S_FLAGS],SF_PEER
	jz	@f
	call	src_release
@@:
	and	dword [r12+S_FLAGS],0
	mov	dword [r12+S_STATE],ST_FREE
	inc	dword [r12+S_GEN]
	mov	eax,[r12+S_LST]
	dec	dword [g_ls_active+rax*4]
	dec	dword [g_active]
	mov	eax,[g_sess_free]
	mov	[r12+S_NEXT],eax
	mov	[g_sess_free],ebx
.done:
	pop	r12
	pop	rbx
	ret
