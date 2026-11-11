; Upstream connections that outlive their session: slots and pools.
;
; io_uring: upstream sockets live in direct descriptor slots taken from
; upslot_alloc (the table's last two thirds), so a connection can move
; from a session to a pool and to the next session. epoll: they are
; plain descriptors.
;
; Pools (http keep-alive): per worker, per server, a LIFO stack of idle
; connections, the most recently used first (warm in the kernel's and
; the backend's caches). At most POOL_MAX per server per worker; the
; oldest ones are closed after POOL_IDLE seconds, below the usual
; backend keep-alive timeouts so okena closes first, not the backend in
; the middle of a reuse.

POOL_MAX	:= 512
POOL_IDLE	:= 50
UPSLOT_MAX	:= 2 shl 20

bss
	align 8
	g_upslot	rd 1 shl 20		; session -> its upstream slot
	g_us_stack	rd UPSLOT_MAX		; free slots
	g_us_top	dd ?
	g_us_hwm	dd ?
	g_pool_n	rd MAX_SERVERS		; idle connections per server
	g_sv_gen	rd MAX_SERVERS		; a slot's address changes: what it was made for is old
	g_pool_h	rd MAX_SERVERS * POOL_MAX	; their slots or descriptors
	g_pool_t	rd MAX_SERVERS * POOL_MAX	; tick each was parked at
	g_us_wgen	rd UPSLOT_MAX		; io_uring: watch generation per slot
	g_hd_server	rd UPSLOT_MAX		; pooled handle -> its server
end bss

; An idle connection is watched while it sits in a pool: when the
; backend closes it or sends anything, it leaves the pool at once
; instead of failing the next request that would reuse it.
;   io_uring: a POLL_ADD (POLLIN, POLLRDHUP) that reads nothing; taking
;   the connection cancels it, and a late completion is recognised by
;   the slot's watch generation.
;   epoll: the descriptor's registration names the pool (EK_POOL).

EK_POOL		:= 4

; edi = server, esi = handle: watch it.
pool_watch:
	mov	[g_hd_server+rsi*4],edi
	cmp	dword [g_engine],ENGINE_EPOLL
	je	.epoll
	push	rsi
	call	ring_get_sqe
	pop	rsi
	mov	byte [rax+SQE_OPCODE],IORING_OP_POLL_ADD
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE
	mov	[rax+SQE_FD],esi
	mov	dword [rax+SQE_OP_FLAGS],POLLIN_ or POLLRDHUP_
	mov	ecx,[g_us_wgen+rsi*4]
	and	ecx,0xFFFFFF
	shl	rcx,32
	or	rcx,rsi
	mov	rdx,OP_POOL_WATCH shl 56
	or	rcx,rdx
	mov	[rax+SQE_USER_DATA],rcx
	ret
.epoll:
	mov	edi,esi
	mov	edx,esi
	mov	rcx,EK_POOL shl 56
	or	rdx,rcx
	mov	esi,EPOLLIN or EPOLLRDHUP or EPOLLET
	jmp	ep_mod

; eax = handle just taken from a pool: stop watching it.
pool_unwatch:
	cmp	dword [g_engine],ENGINE_EPOLL
	je	.done				; the session's ep_mod replaces it
	push	rax
	mov	ecx,eax
	inc	dword [g_us_wgen+rcx*4]		; a late completion is now stale
	call	ring_get_sqe
	pop	rcx
	push	rcx
	mov	byte [rax+SQE_OPCODE],IORING_OP_ASYNC_CANCEL
	; cancel by user_data: the watch as it was posted
	mov	edx,[g_us_wgen+rcx*4]
	dec	edx
	and	edx,0xFFFFFF
	shl	rdx,32
	or	rdx,rcx
	mov	rcx,OP_POOL_WATCH shl 56
	or	rdx,rcx
	mov	[rax+SQE_ADDR],rdx
	mov	rcx,OP_IGNORE shl 56
	mov	[rax+SQE_USER_DATA],rcx
	pop	rax
.done:
	ret

; io_uring completion of a watch: ebx = slot, r12d = generation.
on_pool_watch:
	mov	eax,[g_us_wgen+rbx*4]
	and	eax,0xFFFFFF
	cmp	eax,r12d
	jne	.stale				; taken since; the cancel or its use won
	cmp	r14,-ECANCELED
	je	.stale
	mov	edi,ebx
	jmp	pool_drop_handle
.stale:
	ret

; edi = handle that died while pooled: out of its pool, closed.
pool_drop_handle:
	push	rbx
	mov	ebx,[g_hd_server+rdi*4]
	mov	ecx,[g_pool_n+rbx*4]
	imul	edx,ebx,POOL_MAX
	xor	eax,eax
.find:
	cmp	eax,ecx
	jae	.absent
	lea	r8d,[rdx+rax]
	cmp	[g_pool_h+r8*4],edi
	je	.found
	inc	eax
	jmp	.find
.found:
	; shift the entries above it down
	dec	ecx
	mov	[g_pool_n+rbx*4],ecx
	sub	ecx,eax
	push	rdi
	lea	rsi,[g_pool_h+r8*4+4]
	lea	rdi,[g_pool_h+r8*4]
	push	rcx
	rep	movsd
	pop	rcx
	lea	rsi,[g_pool_t+r8*4+4]
	lea	rdi,[g_pool_t+r8*4]
	rep	movsd
	pop	rdi
	inc	dword [g_us_wgen+rdi*4]
	call	pool_close_handle
.absent:
	pop	rbx
	ret

; eax = a free upstream slot, or NIL.
upslot_alloc:
	mov	eax,[g_us_top]
	test	eax,eax
	jz	.fresh
	dec	eax
	mov	[g_us_top],eax
	mov	eax,[g_us_stack+rax*4]
	ret
.fresh:
	mov	eax,[g_us_hwm]
	mov	ecx,[g_sessions]
	add	ecx,ecx
	cmp	eax,ecx
	jae	.none
	inc	dword [g_us_hwm]
	add	eax,[g_sessions]		; after the client slots
	ret
.none:
	mov	eax,NIL
	ret

; edi = slot back to the free stack.
upslot_free:
	mov	eax,[g_us_top]
	mov	[g_us_stack+rax*4],edi
	inc	dword [g_us_top]
	ret

; edi = server, esi = handle (slot or descriptor). CF when the pool is
; full (the caller closes the connection then).
pool_put:
	mov	eax,[g_sv_pool+rdi*4]		; the pool's `connect max=`
	imul	rax,rax,PL_SIZE
	mov	ecx,[g_pools+rax+PL_CMAX]
	mov	eax,[g_pool_n+rdi*4]
	cmp	eax,ecx
	jae	.full
	imul	ecx,edi,POOL_MAX
	add	ecx,eax
	mov	[g_pool_h+rcx*4],esi
	mov	edx,[g_tick]
	mov	[g_pool_t+rcx*4],edx
	inc	dword [g_pool_n+rdi*4]
	call	pool_watch
	clc
	ret
.full:
	stc
	ret

; edi = server. eax = the most recently parked handle, or NIL.
pool_take:
	mov	eax,[g_pool_n+rdi*4]
	test	eax,eax
	jz	.none
	dec	eax
	mov	[g_pool_n+rdi*4],eax
	imul	ecx,edi,POOL_MAX
	add	ecx,eax
	mov	eax,[g_pool_h+rcx*4]
	call	pool_unwatch
	cmp	dword [g_engine],ENGINE_EPOLL
	jne	.ok
	; epoll: make sure it is still idle (nothing to read, no FIN)
	push	rdi
	push	rax
	sub	rsp,8
	mov	edi,eax
	mov	rsi,rsp
	mov	edx,1
	mov	r10d,MSG_PEEK or MSG_DONTWAIT
	xor	r8d,r8d
	xor	r9d,r9d
	mov	eax,SYS_recvfrom
	syscall
	add	rsp,8
	cmp	rax,-EAGAIN
	pop	rax
	pop	rdi
	je	.ok
	; closed or holding stray bytes: drop it, try the next one
	push	rdi
	mov	edi,eax
	call	pool_close_handle
	pop	rdi
	jmp	pool_take
.ok:
	ret
.none:
	mov	eax,NIL
	ret

; edi = handle: close an idle connection nobody owns.
pool_close_handle:
	cmp	dword [g_engine],ENGINE_EPOLL
	je	.epoll
	push	rdi
	call	ring_get_sqe
	pop	rdi
	mov	byte [rax+SQE_OPCODE],IORING_OP_CLOSE
	lea	ecx,[rdi+1]
	mov	[rax+SQE_FILE_INDEX],ecx
	mov	rcx,OP_IGNORE shl 56
	mov	[rax+SQE_USER_DATA],rcx
	jmp	upslot_free
.epoll:
	mov	eax,SYS_close
	syscall
	ret

; Tick: close idle connections parked longer than their pool's `connect idle=`
; (POOL_IDLE; they sit at the bottom of each stack).
pool_expire:
	push	rbx
	push	r12
	xor	ebx,ebx
.server:
	cmp	ebx,[g_plan_servers]
	jae	.done
.oldest:
	cmp	dword [g_pool_n+rbx*4],0
	je	.next
	imul	r12d,ebx,POOL_MAX
	mov	eax,[g_sv_pool+rbx*4]		; the pool's `connect idle=`
	imul	rax,rax,PL_SIZE
	mov	ecx,[g_pools+rax+PL_CIDLE]
	mov	eax,[g_tick]
	sub	eax,[g_pool_t+r12*4]
	cmp	eax,ecx
	jbe	.next
	mov	edi,[g_pool_h+r12*4]
	push	rdi
	cmp	dword [g_engine],ENGINE_EPOLL
	je	@f
	mov	eax,edi
	call	pool_unwatch
@@:
	pop	rdi
	call	pool_close_handle
	; shift the stack down by one
	dec	dword [g_pool_n+rbx*4]
	mov	ecx,[g_pool_n+rbx*4]
	lea	rsi,[g_pool_h+r12*4+4]
	lea	rdi,[g_pool_h+r12*4]
	push	rcx
	rep	movsd
	pop	rcx
	lea	rsi,[g_pool_t+r12*4+4]
	lea	rdi,[g_pool_t+r12*4]
	rep	movsd
	jmp	.oldest
.next:
	inc	ebx
	jmp	.server
.done:
	pop	r12
	pop	rbx
	ret

; Tick: `connect warm=N`: each server of such a pool (plain HTTP/1.1, up and
; chosen by the balancer's rules) has N connections open in each worker
; before any request needs one. Opened here and parked at once: one whose
; connect fails is seen by its watch (an error) and leaves the pool, as one
; the backend closed; one taken before its connect is done waits for it.
pool_warm:
	push	rbx
	push	r12
	push	r13
	xor	r12d,r12d			; pool
.pool:
	cmp	r12d,[g_plan_pools]
	jae	.done
	imul	r13,r12,PL_SIZE
	lea	r13,[g_pools+r13]
	cmp	dword [r13+PL_CWARM],0
	je	.next_pool
	mov	eax,[r13+PL_TLS]
	or	eax,[r13+PL_H2]
	or	eax,[r13+PL_FCGI]
	jnz	.next_pool			; (a handshake or a preface first: not here)
	mov	ebx,[r13+PL_FIRST]
.server:
	mov	eax,[r13+PL_FIRST]
	add	eax,[r13+PL_COUNT]
	cmp	ebx,eax
	jae	.next_pool
	mov	edi,ebx
	mov	esi,2
	call	server_eligible			; up, not drained, not ejected
	jnc	.next_server
	imul	rax,rbx,SV_SIZE
	cmp	dword [g_servers+rax+SV_FAMILY],AF_UNIX
	je	@f
	cmp	dword [g_servers+rax+SV_SALEN],0
	je	.next_server			; (a name not resolved yet)
@@:
	mov	eax,[g_pool_n+rbx*4]
	cmp	eax,[r13+PL_CWARM]
	jae	.next_server
	mov	edi,ebx				; warm ones spend `rate=` too
	call	sv_rate_per
	test	eax,eax
	jz	.warm
	call	sv_rate_fill
	cmp	eax,1000
	jb	.next_server
	call	sv_rate_take
.warm:
	call	warm_one
	jnc	@b
.next_server:
	inc	ebx
	jmp	.server
.next_pool:
	inc	r12d
	jmp	.pool
.done:
	pop	r13
	pop	r12
	pop	rbx
	ret

; edi = server: a connection to it, into its pool. CF when none could be made.
warm_one:
	push	rbx
	push	r12
	push	r13
	mov	ebx,edi
	imul	r13,rbx,SV_SIZE
	lea	r13,[g_servers+r13]
	cmp	dword [g_engine],ENGINE_EPOLL
	je	.epoll
	call	upslot_alloc
	cmp	eax,NIL
	je	.fail
	mov	r12d,eax
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_SOCKET
	mov	byte [rax+SQE_FLAGS],IOSQE_IO_LINK
	mov	ecx,[r13+SV_FAMILY]
	mov	[rax+SQE_FD],ecx
	mov	qword [rax+SQE_OFF],SOCK_STREAM
	lea	ecx,[r12+1]
	mov	[rax+SQE_FILE_INDEX],ecx
	mov	rcx,OP_IGNORE shl 56
	mov	[rax+SQE_USER_DATA],rcx
	cmp	dword [r13+SV_FAMILY],AF_UNIX
	je	.u_connect
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_URING_CMD
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE or IOSQE_IO_HARDLINK
	mov	[rax+SQE_FD],r12d
	mov	dword [rax+SQE_CMD_OP],SOCKET_URING_OP_SETSOCKOPT
	mov	dword [rax+SQE_LEVEL],IPPROTO_TCP
	mov	dword [rax+SQE_OPTNAME],TCP_NODELAY
	mov	dword [rax+SQE_OPTLEN],4
	lea	rcx,[one_int]
	mov	[rax+SQE_OPTVAL],rcx
	mov	rcx,OP_IGNORE shl 56
	mov	[rax+SQE_USER_DATA],rcx
	cmp	dword [g_uring_bind],0
	je	.u_connect
	mov	edi,[g_sv_pool+rbx*4]
	mov	esi,[r13+SV_FAMILY]
	call	pool_source
	test	rax,rax
	jz	.u_connect
	push	rax
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_URING_CMD
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE or IOSQE_IO_HARDLINK
	mov	[rax+SQE_FD],r12d
	mov	dword [rax+SQE_CMD_OP],SOCKET_URING_OP_SETSOCKOPT
	mov	dword [rax+SQE_LEVEL],IPPROTO_IP
	mov	dword [rax+SQE_OPTNAME],IP_BIND_ADDRESS_NO_PORT
	mov	dword [rax+SQE_OPTLEN],4
	lea	rcx,[one_int]
	mov	[rax+SQE_OPTVAL],rcx
	mov	rcx,OP_IGNORE shl 56
	mov	[rax+SQE_USER_DATA],rcx
	call	ring_get_sqe
	pop	rcx
	mov	byte [rax+SQE_OPCODE],IORING_OP_BIND
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE or IOSQE_IO_LINK
	mov	[rax+SQE_FD],r12d
	mov	[rax+SQE_ADDR],rcx
	mov	edx,[rcx+28]
	mov	[rax+SQE_ADDR2],rdx
	mov	rcx,OP_IGNORE shl 56
	mov	[rax+SQE_USER_DATA],rcx
.u_connect:
	; the connect, then (hard-linked: whatever it gave) the pool's watch, which
	; would see a socket not yet connecting as hung up if it ran first
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_CONNECT
	mov	byte [rax+SQE_FLAGS],IOSQE_FIXED_FILE or IOSQE_IO_HARDLINK
	mov	[rax+SQE_FD],r12d
	lea	rcx,[r13+SV_SA]
	mov	[rax+SQE_ADDR],rcx
	mov	ecx,[r13+SV_SALEN]
	mov	[rax+SQE_OFF],rcx
	mov	rcx,OP_IGNORE shl 56
	mov	[rax+SQE_USER_DATA],rcx
	mov	edi,ebx
	mov	esi,r12d
	call	pool_put			; (its watch: the next SQE, linked)
	jnc	.ok
	mov	edi,r12d			; (not reached: room was looked at)
	call	pool_close_handle
	jmp	.fail
.epoll:
	mov	edi,[r13+SV_FAMILY]
	mov	esi,SOCK_STREAM or SOCK_NONBLOCK or SOCK_CLOEXEC
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	.fail
	mov	r12d,eax
	cmp	dword [r13+SV_FAMILY],AF_UNIX
	je	.e_connect
	mov	edi,r12d
	mov	esi,IPPROTO_TCP
	mov	edx,TCP_NODELAY
	lea	r10,[one_int]
	mov	r8d,4
	mov	eax,SYS_setsockopt
	syscall
	mov	edi,[g_sv_pool+rbx*4]
	mov	esi,[r13+SV_FAMILY]
	call	pool_source
	test	rax,rax
	jz	.e_connect
	push	rax
	mov	edi,r12d
	mov	esi,IPPROTO_IP
	mov	edx,IP_BIND_ADDRESS_NO_PORT
	lea	r10,[one_int]
	mov	r8d,4
	mov	eax,SYS_setsockopt
	syscall
	pop	rsi
	mov	edi,r12d
	mov	edx,[rsi+28]
	mov	eax,SYS_bind
	syscall
	test	eax,eax
	jnz	.e_close
.e_connect:
	mov	edi,r12d
	lea	rsi,[r13+SV_SA]
	mov	edx,[r13+SV_SALEN]
	mov	eax,SYS_connect
	syscall
	test	eax,eax
	jz	@f
	cmp	eax,-EINPROGRESS
	jne	.e_close
@@:
	mov	edi,r12d			; registered as a pooled one (EK_POOL)
	mov	esi,EPOLLIN or EPOLLRDHUP or EPOLLET
	mov	edx,r12d
	mov	rcx,EK_POOL shl 56
	or	rdx,rcx
	call	ep_add
	mov	[g_hd_server+r12*4],ebx
	mov	edi,ebx
	mov	esi,r12d
	call	pool_put			; (its ep_mod: the same registration)
	jnc	.ok
.e_close:
	mov	edi,r12d
	mov	eax,SYS_close
	syscall
.fail:
	stc
	jmp	.out
.ok:
	clc
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret
