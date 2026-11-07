; `server ADDR max=N`: no more than N connections in use to that server, for
; the whole instance; `queue timeout=5s` on its pool: how long an http request
; waits for a place (the pool's connect timeout unless told). `balance first`
; fills the servers in their order, each up to its max, so that the last ones
; may be stopped while traffic is low.
;
; Each worker counts its own connections in a row of a table that every
; worker of the generation shares, and a server's count is the sum of the
; rows: no atomic, no line written by two workers, and a worker that is
; replaced starts its row again from nothing. Connections of a generation a
; reload replaced are not in it, so for the length of a drain a server can
; have more than its max. Idle connections kept in the pool do not count.
;
; A full server is not chosen, by any pass, not even when all else is down.
; With all of them full an http request queues: first in, first out in each
; worker. One that leaves a server lets the first one waiting in that worker
; go at once; places given back in other workers are looked for every
; millisecond while anyone waits, and as many go as there are places. Waiting longer than the queue's time is a
; 503. A tcp connection does not queue: it is closed, as when no server is up.

SQ_CAP		:= 1024			; waiting requests a pool can have, in a worker
SQ_POLL_US	:= 1000
QPOLL_SESS	:= 0x0FFFFFFF		; FD_SESS of the queue's own clock

bss
	align 8
	g_sv_live	dq ?		; shared: MAX_WORKERS rows of MAX_SERVERS dwords
	g_sv_row	dq ?		; this worker's row
	g_wq		dq ?		; the queues: MAX_POOLS rings of SQ_CAP entries
	g_pick_full	dd ?		; the last pick skipped a server for being full
	g_wq_waiting	dd ?
	g_wq_polling	dd ?
	g_wq_head	rd MAX_POOLS
	g_wq_tail	rd MAX_POOLS
end bss

; supervisor: a table for each generation (the old one stays with its workers)
sv_live_init:
	xor	edi,edi
	mov	esi,MAX_WORKERS * MAX_SERVERS * 4
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_ANONYMOUS
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	mov	[g_sv_live],rax
	ret

; a worker, starting: its row, from nothing; its queues
sv_live_worker:
	mov	eax,[g_worker_id]
	imul	rax,rax,MAX_SERVERS * 4
	add	rax,[g_sv_live]
	mov	[g_sv_row],rax
	mov	rdi,rax
	mov	ecx,MAX_SERVERS
	xor	eax,eax
	rep	stosd
	mov	dword [g_wq_waiting],0
	mov	dword [g_wq_polling],0
	lea	rdi,[g_wq_head]
	mov	ecx,MAX_POOLS * 2
	rep	stosd
	xor	edi,edi
	mov	esi,MAX_POOLS * SQ_CAP * 8
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.fatal
	mov	[g_wq],rax
	ret
.fatal:
	mov	edi,EXIT_FATAL
	jmp	exit_process

macro sv_count_dec r*
	dec	dword [g_sv_active+r*4]
	push	rsi
	mov	rsi,[g_sv_row]
	dec	dword [rsi+r*4]
	pop	rsi
end macro

; edi = server: eax = its connections in use, all workers'. Keeps all but rax.
sv_live_sum:
	push	rcx
	push	rdx
	mov	rdx,[g_sv_live]
	lea	rdx,[rdx+rdi*4]
	xor	eax,eax
	mov	ecx,[g_workers]
.row:
	test	ecx,ecx
	jz	.summed
	add	eax,[rdx]
	add	rdx,MAX_SERVERS * 4
	dec	ecx
	jmp	.row
.summed:
	pop	rdx
	pop	rcx
	ret

; edi = server with a max: CF when it has room; eax = its connections in
; use. Keeps all but rax.
sv_has_room:
	call	sv_live_sum
	push	rcx
	imul	rcx,rdi,SV_SIZE
	cmp	eax,[g_servers+rcx+SV_MAX]
	pop	rcx
	jb	.room
	mov	dword [g_pick_full],1
	clc
	ret
.room:
	stc
	ret

; edi = server, about to have a connection: CF when it is counted, clear
; when it has no room (then g_pick_full). A place is taken before the count
; is looked at, with a locked add, which no load can pass: of two workers
; that race for the last place one at least sees the other, and none goes
; past the max (both may step back, and wait their turn). Keeps all.
sv_claim:
	push	rax
	push	rsi
	mov	rsi,[g_sv_row]
	lock inc dword [rsi+rdi*4]
	imul	rax,rdi,SV_SIZE
	mov	eax,[g_servers+rax+SV_MAX]
	test	eax,eax
	jz	.counted
	push	rcx
	mov	ecx,eax
	call	sv_live_sum			; ours in it
	cmp	eax,ecx
	pop	rcx
	jbe	.counted
	lock dec dword [rsi+rdi*4]
	mov	dword [g_pick_full],1
	pop	rsi
	pop	rax
	clc
	ret
.counted:
	inc	dword [g_sv_active+rdi*4]
	pop	rsi
	pop	rax
	stc
	ret

; edi = server: a claim given back before it was used. Keeps all.
sv_unclaim:
	push	rsi
	mov	rsi,[g_sv_row]
	lock dec dword [rsi+rdi*4]
	dec	dword [g_sv_active+rdi*4]
	pop	rsi
	ret

; ------------------------------------------------------------ the queue

; ebx = session, r15 = record: no server had room. CF when it waits.
queue_wait:
	cmp	dword [g_pick_full],0
	je	.no
	test	dword [r15+H_FLAGS],HX_STARTED or HX_MIRROR
	jnz	.no
	cmp	dword [g_fd_n],FD_MAX - 1
	jae	.no
	call	session_ptr
	mov	r8d,[rax+S_POOL]
	mov	r9d,[rax+S_GEN]
	; its time
	imul	rcx,r8,PL_SIZE
	lea	rcx,[g_pools+rcx]
	mov	r10,[rcx+PL_QTIMEOUT]
	test	r10,r10
	jnz	@f
	imul	r10,[rcx+PL_TIMEOUT],1000000
	mov	rax,[rcx+PL_TIMEOUT+8]
	xor	edx,edx
	mov	r11d,1000
	div	r11
	add	r10,rax
@@:
	push	r8
	push	r9
	push	r10
	call	qs_clock
	pop	r10
	pop	r9
	pop	r8
	mov	rdx,[r15+H_BUF]
	mov	rax,[rdx+HB_HOLD]
	test	rax,rax
	jnz	@f
	mov	rax,[g_qnow]
	add	rax,r10
	mov	[rdx+HB_HOLD],rax
@@:
	mov	r10,rax
	sub	r10,[g_qnow]
	jbe	.no				; it has waited all it may
	; at the end of its pool's line
	mov	eax,[g_wq_tail+r8*4]
	mov	ecx,eax
	sub	ecx,[g_wq_head+r8*4]
	cmp	ecx,SQ_CAP
	jae	.no
	mov	ecx,eax
	and	ecx,SQ_CAP - 1
	mov	rdx,r8
	imul	rdx,rdx,SQ_CAP * 8
	add	rdx,[g_wq]
	mov	r11d,r9d
	shl	r11,32
	or	r11,rbx
	mov	[rdx+rcx*8],r11
	inc	dword [g_wq_tail+r8*4]
	inc	dword [g_wq_waiting]
	push	r10
	call	h_upclose			; (what the try left)
	h_rec
	call	session_ptr
	mov	dword [rax+S_STATE],ST_OPEN
	pop	rax
	call	fault_hold			; until its time is up, if nothing comes
	or	dword [g_fd+rcx+FD_SESS],FD_HOLD
	call	queue_poll_arm
	stc
	ret
.no:
	clc
	ret

; edi = pool: its first waiting request goes now. Keeps all.
queue_wake:
	push	rax
	push	rcx
	push	rdx
	push	r8
	push	r9
	push	r10
.next:
	mov	eax,[g_wq_head+rdi*4]
	cmp	eax,[g_wq_tail+rdi*4]
	je	.out
	inc	dword [g_wq_head+rdi*4]
	dec	dword [g_wq_waiting]
	and	eax,SQ_CAP - 1
	mov	rdx,rdi
	imul	rdx,rdx,SQ_CAP * 8
	add	rdx,[g_wq]
	mov	r8,[rdx+rax*8]
	mov	r9,r8
	shr	r9,32				; its generation
	or	r8d,FD_HOLD			; and its wait
	; its place on the clock, made due
	mov	ecx,[g_fd_n]
	xor	eax,eax
.find:
	test	ecx,ecx
	jz	.next				; gone, or its time came: the next one
	cmp	[g_fd+rax+FD_SESS],r8d
	jne	.other
	cmp	[g_fd+rax+FD_GEN],r9d
	je	.due
.other:
	add	rax,FD_SIZE
	dec	ecx
	jmp	.find
.due:
	mov	qword [g_fd+rax+FD_AT],1
	mov	qword [g_fd_next],1
.out:
	pop	r10
	pop	r9
	pop	r8
	pop	rdx
	pop	rcx
	pop	rax
	ret

; the queue's clock, while anyone waits
queue_poll_arm:
	cmp	dword [g_wq_polling],0
	jne	.out
	mov	eax,[g_fd_n]
	cmp	eax,FD_MAX
	jae	.out
	mov	dword [g_wq_polling],1
	inc	dword [g_fd_n]
	shl	rax,4
	mov	rcx,[g_qnow]
	add	rcx,SQ_POLL_US
	mov	[g_fd+rax+FD_AT],rcx
	mov	dword [g_fd+rax+FD_SESS],QPOLL_SESS
	mov	dword [g_fd+rax+FD_GEN],0
	mov	rdx,[g_fd_next]
	test	rdx,rdx
	jz	@f
	cmp	rcx,rdx
	jae	.out
@@:
	mov	[g_fd_next],rcx
.out:
	ret

; its time: places other workers gave back, for those who wait here
queue_poll:
	mov	dword [g_wq_polling],0
	cmp	dword [g_wq_waiting],0
	je	.none
	push	rbx
	push	r12
	xor	r12d,r12d
.pool:
	cmp	r12d,[g_plan_pools]
	jae	.done
	mov	eax,[g_wq_head+r12*4]
	cmp	eax,[g_wq_tail+r12*4]
	je	.next
	; how many places there are now: as many go
	imul	rbx,r12,PL_SIZE
	lea	rbx,[g_pools+rbx]
	mov	ecx,[rbx+PL_FIRST]
	mov	edx,ecx
	add	edx,[rbx+PL_COUNT]
	xor	r8d,r8d				; places
.server:
	cmp	ecx,edx
	jae	.counted
	push	rcx
	push	rdx
	push	r8
	mov	edi,ecx
	mov	esi,2
	call	server_eligible
	pop	r8
	pop	rdx
	pop	rcx
	jnc	.full
	imul	rax,rcx,SV_SIZE
	mov	r9d,[g_servers+rax+SV_MAX]
	test	r9d,r9d
	jz	.all				; a server with no max: room for all
	mov	edi,ecx
	call	sv_has_room			; eax = in use
	sub	r9d,eax
	jbe	.full
	add	r8d,r9d
.full:
	inc	ecx
	jmp	.server
.all:
	mov	r8d,SQ_CAP
.counted:
	test	r8d,r8d
	jz	.next				; full everywhere: they wait on
	mov	eax,[g_wq_tail+r12*4]
	cmp	eax,[g_wq_head+r12*4]
	je	.next
	mov	edi,r12d
	call	queue_wake
	dec	r8d
	jmp	.counted
.next:
	inc	r12d
	jmp	.pool
.done:
	pop	r12
	pop	rbx
	cmp	dword [g_wq_waiting],0
	je	.none
	call	qs_clock
	jmp	queue_poll_arm
.none:
	ret
