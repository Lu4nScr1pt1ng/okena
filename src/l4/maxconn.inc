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
; With all of them full an http request queues, first in, first out across
; all workers, as a ticket lock: it takes the pool's next ticket from a counter
; the generation's workers share, and a place goes to the ticket being served,
; whichever worker has it. While anyone waits, a new request may not take a
; place: it queues too, behind them. A place freed in a worker goes to its own
; line at once when that holds the ticket being served; else the worker that
; holds it, which looks every millisecond while it waits, takes it. A ticket
; whose request gave up (its time ran out, its client went) is passed over when
; its turn comes. Should the turn not move for 50 ms while there is room (a
; worker that holds it gone, say), it moves on. Waiting longer than the
; queue's time is a 503. A tcp connection does not queue: it is closed, as when
; no server is up.

SQ_CAP		:= 1024			; waiting requests a pool can have, in a worker
SQ_POLL_US	:= 1000
SQ_STUCK_US	:= 50000		; a turn that does not move, with room: it moves on
WT_NEXT		:= 0			; q: the next ticket
WT_SERV		:= 8			; q: the ticket being served
WT_AT		:= 16			; q: µs when it last moved
WT_SIZE		:= 32
QPOLL_SESS	:= 0x0FFFFFFF		; FD_SESS of the queue's own clock

bss
	align 8
	g_sv_live	dq ?		; shared: MAX_WORKERS rows of MAX_SERVERS dwords
	g_sv_row	dq ?		; this worker's row
	g_wq		dq ?		; the queues: MAX_POOLS rings of SQ_CAP entries
	g_wq_tk		dq ?		; and each one's ticket
	g_wq_turn	dq ?		; shared: WT_SIZE per pool
	g_pick_adm	dd ?		; the next pick is a new http request's: it may not pass
					; those who wait
	g_pick_full	dd ?		; the last pick skipped a server for being full
	g_wq_waiting	dd ?
	g_wq_polling	dd ?
	g_wq_head	rd MAX_POOLS
	g_pl_active	rd MAX_POOLS	; this worker's connections in use, by pool
	g_sv_pool	rd MAX_SERVERS	; each server's pool
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
	xor	edi,edi
	mov	esi,MAX_POOLS * WT_SIZE
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_ANONYMOUS
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	mov	[g_wq_turn],rax
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
	; each server's pool
	xor	ecx,ecx
.pool:
	cmp	ecx,[g_plan_pools]
	jae	.pools
	imul	rax,rcx,PL_SIZE
	mov	edx,[g_pools+rax+PL_FIRST]
	mov	r8d,edx
	add	r8d,[g_pools+rax+PL_COUNT]
@@:
	cmp	edx,r8d
	jae	@f
	mov	[g_sv_pool+rdx*4],ecx
	inc	edx
	jmp	@b
@@:
	inc	ecx
	jmp	.pool
.pools:
	lea	rdi,[g_pl_active]
	mov	ecx,MAX_POOLS
	xor	eax,eax
	rep	stosd
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
	mov	[g_wq_tk],rax
	ret
.fatal:
	mov	edi,EXIT_FATAL
	jmp	exit_process

macro sv_count_dec r*
	dec	dword [g_sv_active+r*4]
	push	rsi
	mov	rsi,[g_sv_row]
	dec	dword [rsi+r*4]
	mov	esi,[g_sv_pool+r*4]
	dec	dword [g_pl_active+rsi*4]
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
	mov	esi,[g_sv_pool+rdi*4]
	inc	dword [g_pl_active+rsi*4]
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
	mov	esi,[g_sv_pool+rdi*4]
	dec	dword [g_pl_active+rsi*4]
	pop	rsi
	ret

; ------------------------------------------------------------ the queue

; edi = pool: rax = its turn's record (shared). Keeps all but rax.
queue_turn_ptr:
	mov	eax,edi
	shl	rax,5				; WT_SIZE
	add	rax,[g_wq_turn]
	ret

; rbx = pool: CF when someone waits for it, anywhere. Keeps all but rax.
queue_anyone:
	push	rcx
	mov	rax,rbx
	lea	rcx,[g_pools]
	sub	rax,rcx
	push	rdx
	xor	edx,edx
	mov	ecx,PL_SIZE
	div	rcx
	pop	rdx
	shl	rax,5
	add	rax,[g_wq_turn]
	mov	rcx,[rax+WT_NEXT]
	cmp	rcx,[rax+WT_SERV]
	pop	rcx
	jbe	.no
	stc
	ret
.no:
	clc
	ret

; ebx = session, r15 = record: no server had room, or others wait. CF when it
; waits.
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
	; room in its pool's line?
	mov	eax,[g_wq_tail+r8*4]
	sub	eax,[g_wq_head+r8*4]
	cmp	eax,SQ_CAP
	jae	.no
	; what the try left goes first, and it is seen to wait, before it is in
	; line: closing that may free a place, and the line is looked at then
	push	r8
	push	r9
	push	r10
	call	h_upclose
	h_rec
	call	session_ptr
	mov	dword [rax+S_STATE],ST_OPEN
	mov	rax,[rsp]
	call	fault_hold			; until its time is up, if nothing comes
	or	dword [g_fd+rcx+FD_SESS],FD_HOLD
	pop	r10
	pop	r9
	pop	r8
	; at the end of its pool's line, with the next ticket
	mov	eax,[g_wq_tail+r8*4]
	mov	ecx,eax
	and	ecx,SQ_CAP - 1
	mov	rdx,r8
	imul	rdx,rdx,SQ_CAP * 8
	add	rdx,[g_wq]
	mov	r11d,r9d
	shl	r11,32
	or	r11,rbx
	mov	[rdx+rcx*8],r11
	mov	edi,r8d
	call	queue_turn_ptr
	mov	r11d,1
	lock xadd [rax+WT_NEXT],r11
	mov	rdx,r8
	imul	rdx,rdx,SQ_CAP * 8
	add	rdx,[g_wq_tk]
	mov	[rdx+rcx*8],r11
	inc	dword [g_wq_tail+r8*4]
	inc	dword [g_wq_waiting]
	push	r8
	call	queue_poll_arm
	pop	rdi
	call	queue_places			; (room already: its turn may be now)
	call	queue_serve
	stc
	ret
.no:
	clc
	ret

; edi = pool: as many of its line go as the turn allows and there are places
; (esi). Keeps all.
queue_serve:
	push	rax
	push	rcx
	push	rdx
	push	rbx
	push	r8
	push	r9
	push	r15
	call	queue_turn_ptr
	mov	r9,rax				; the turn
.head:
	mov	eax,[g_wq_head+rdi*4]
	cmp	eax,[g_wq_tail+rdi*4]
	je	.out				; nobody waits here
	and	eax,SQ_CAP - 1
	mov	rdx,rdi
	imul	rdx,rdx,SQ_CAP * 8
	mov	r8,rdx
	add	rdx,[g_wq]
	add	r8,[g_wq_tk]
	mov	r8,[r8+rax*8]			; its ticket
	mov	rdx,[rdx+rax*8]			; gen << 32 | session
	mov	rcx,[r9+WT_SERV]
	cmp	r8,rcx
	jb	.passed				; its turn went by
	ja	.not_yet
	; its turn: alive?
	call	.alive
	jnc	.pass
	test	esi,esi
	jz	.out				; no room: it waits on
	lock inc qword [r9+WT_SERV]
	call	.moved
	call	.go
	dec	esi
	jmp	.head
.passed:
	; moved on while it waited (its worker was slow to look): it is still
	; first in its line, and goes as soon as there is room
	call	.alive
	jnc	.drop
	test	esi,esi
	jz	.out
	call	.go
	dec	esi
	jmp	.head
.pass:
	; gave up: its turn goes to the next ticket
	lea	rax,[r8+1]
	xchg	rax,r8
	lock cmpxchg [r9+WT_SERV],r8
	call	.moved
.drop:
	inc	dword [g_wq_head+rdi*4]
	dec	dword [g_wq_waiting]
	jmp	.head
.not_yet:
	; another worker's ticket is served before this one; if it does not move
	; while there is room, it is moved on
	test	esi,esi
	jz	.out
	mov	rax,[g_qnow]
	sub	rax,[r9+WT_AT]
	cmp	rax,SQ_STUCK_US
	jb	.out
	mov	rax,rcx
	lea	r8,[rcx+1]
	lock cmpxchg [r9+WT_SERV],r8
	call	.moved
	jmp	.head
.out:
	pop	r15
	pop	r9
	pop	r8
	pop	rbx
	pop	rdx
	pop	rcx
	pop	rax
	ret
.moved:
	mov	rax,[g_qnow]
	mov	[r9+WT_AT],rax
	ret
; rdx = an entry: CF when its request still waits for this
.alive:
	mov	ebx,edx
	mov	r8,rdx
	shr	r8,32
	push	rax
	call	session_ptr
	cmp	[rax+S_GEN],r8d
	jne	.dead
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.dead
	h_rec
	cmp	dword [r15+H_STATE],HS_FAULT
	jne	.dead
	pop	rax
	stc
	ret
.dead:
	pop	rax
	clc
	ret
; rdx = the entry being served: it goes now
.go:
	inc	dword [g_wq_head+rdi*4]
	dec	dword [g_wq_waiting]
	mov	ebx,edx				; (the session)
	h_rec
	mov	rax,[r15+H_BUF]
	mov	dword [rax+HB_WOKEN],1		; it passes those still waiting
	mov	r8,rdx
	shr	r8,32				; its generation
	mov	eax,edx
	or	eax,FD_HOLD			; and its wait
	mov	ecx,[g_fd_n]
	xor	edx,edx
.find:
	test	ecx,ecx
	jz	.found
	cmp	[g_fd+rdx+FD_SESS],eax
	jne	.other
	cmp	[g_fd+rdx+FD_GEN],r8d
	je	.due
.other:
	add	rdx,FD_SIZE
	dec	ecx
	jmp	.find
.due:
	mov	qword [g_fd+rdx+FD_AT],1
	mov	qword [g_fd_next],1
.found:
	ret

; a place left a server of pool edi in this worker. Keeps all.
queue_wake:
	push	rsi
	call	queue_places
	call	queue_serve
	pop	rsi
	ret

; edi = pool: esi = the places its servers have now (SQ_CAP when one of
; them has no max). Keeps all but rsi.
queue_places:
	push	rax
	push	rcx
	push	rdx
	push	rbx
	push	r8
	push	r9
	push	rdi
	imul	rbx,rdi,PL_SIZE
	lea	rbx,[g_pools+rbx]
	mov	ecx,[rbx+PL_FIRST]
	mov	edx,ecx
	add	edx,[rbx+PL_COUNT]
	xor	r8d,r8d
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
	mov	esi,r8d
	pop	rdi
	pop	r9
	pop	r8
	pop	rbx
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

; its time: the turns, and places other workers gave back
queue_poll:
	mov	dword [g_wq_polling],0
	cmp	dword [g_wq_waiting],0
	je	.none
	push	r12
	call	qs_clock
	xor	r12d,r12d
.pool:
	cmp	r12d,[g_plan_pools]
	jae	.done
	mov	eax,[g_wq_head+r12*4]
	cmp	eax,[g_wq_tail+r12*4]
	je	.next
	mov	edi,r12d
	call	queue_places
	call	queue_serve
.next:
	inc	r12d
	jmp	.pool
.done:
	pop	r12
	cmp	dword [g_wq_waiting],0
	je	.none
	jmp	queue_poll_arm
.none:
	ret
