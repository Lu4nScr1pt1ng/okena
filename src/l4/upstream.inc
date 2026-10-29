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

POOL_MAX	= 64
POOL_IDLE	= 50
UPSLOT_MAX	= 2 shl 20

bss
	align 8
	g_upslot	rd 1 shl 20		; session -> its upstream slot
	g_us_stack	rd UPSLOT_MAX		; free slots
	g_us_top	dd ?
	g_us_hwm	dd ?
	g_pool_n	rd MAX_SERVERS		; idle connections per server
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

EK_POOL		= 4

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
	mov	eax,[g_pool_n+rdi*4]
	cmp	eax,POOL_MAX
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

; Tick: close idle connections parked longer than POOL_IDLE (they sit at
; the bottom of each stack).
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
	mov	eax,[g_tick]
	sub	eax,[g_pool_t+r12*4]
	cmp	eax,POOL_IDLE
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
