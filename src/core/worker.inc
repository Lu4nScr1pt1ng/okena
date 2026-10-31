; Worker process: one per CPU, shared-nothing, single-threaded event loop.

bss
	g_sigfd		dd ?
	g_tick		dd ?
	g_draining	dd ?		; 0 serving, 1 drain delay, 2 draining
	g_drain_until	dd ?		; tick that ends the current phase
	g_sig_buf:	rb SIGINFO_SIZE
	align 8
	g_tsc_per_us	dq ?
	g_spin_ticks	dq ?
	g_spin_until	dq ?
	g_reaped_mark	dd ?
end bss

rodata
	align 8
	ts_tick		dq 1, 0			; __kernel_timespec: one second
	ts_calibrate	dq 0, 10000000		; 10 ms
	worker_name	db 'okena-worker',0
end rodata

; edi = worker index. Never returns.
worker_main:
	mov	[g_worker_id],edi
	mov	dword [g_is_worker],1
	mov	ebx,edi
	; Die with the supervisor, and never outlive one we lost the race with.
	mov	edi,PR_SET_PDEATHSIG
	mov	esi,SIGKILL
	mov	eax,SYS_prctl
	syscall
	mov	eax,SYS_getppid
	syscall
	cmp	eax,[g_sup_pid]
	je	@f
	mov	edi,EXIT_OK
	jmp	exit_process
@@:
	mov	edi,PR_SET_NAME
	lea	rsi,[worker_name]
	mov	eax,SYS_prctl
	syscall
	mov	edi,ebx
	call	pin_to_cpu
	; sockets a reload is about to close are not ours to keep open
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

	; SIGTERM/SIGINT stay blocked (inherited) and arrive through a signalfd
	; read on the ring. It is a blocking fd on purpose: io_uring then waits
	; for it with an internal poll instead of failing with EAGAIN.
	mov	qword [g_sigmask],(1 shl (SIGTERM-1)) or (1 shl (SIGINT-1)) or (1 shl (SIGUSR1-1))
	mov	edi,-1
	lea	rsi,[g_sigmask]
	mov	edx,8
	mov	r10d,SFD_CLOEXEC
	mov	eax,SYS_signalfd4
	syscall
	test	eax,eax
	js	.no_signalfd
	mov	[g_sigfd],eax

	call	sessions_init
	test	eax,eax
	js	.no_memory
	call	groups_refresh
	call	hs_init
	cmp	dword [g_plan_engine],2
	je	ep_main
	; io_uring, with epoll as the fallback unless io_engine says io_uring
	lea	r12,[str_why_setup]
	call	ring_init
	test	eax,eax
	js	.no_uring
	lea	r12,[str_why_files]
	call	ring_register_files
	test	eax,eax
	js	.no_uring
	lea	r12,[str_why_pbuf]
	call	pbuf_register
	test	eax,eax
	js	.no_uring
	lea	r12,[str_why_lockdown]
	call	ring_lockdown
	test	eax,eax
	js	.no_uring

	call	arm_accepts
	call	arm_timer
	call	arm_signal
	mov	rax,[g_plan_busy_poll]
	test	rax,rax
	jz	.confine
	push	rax
	call	tsc_calibrate
	pop	rax
	imul	rax,[g_tsc_per_us]
	mov	[g_spin_ticks],rax
.confine:
	; set up: from here on only what serving needs
	seccomp_for filter_worker_uring

	; With busy_poll set, keep polling the ring for that long after the
	; last completion instead of sleeping: a sleep and a wakeup per
	; message cost more than the message. When the window passes, block.
.loop:
	cmp	dword [g_draining],2
	jne	.poll
	cmp	dword [g_active],0
	je	.drained
.poll:
	cmp	qword [g_spin_ticks],0
	je	.block
	rdtsc
	shl	rdx,32
	or	rax,rdx
	add	rax,[g_spin_ticks]
	mov	[g_spin_until],rax
.spin:
	mov	eax,[g_reaped]
	mov	[g_reaped_mark],eax
	xor	edi,edi
	call	ring_enter
	call	ring_reap
	call	ep_http_ready			; user-space TLS deliveries
	call	h2_flush			; HTTP/2: one send a connection an iteration
	call	hs_drain			; hellos that waited for the budget
	mov	eax,[g_reaped]
	cmp	eax,[g_reaped_mark]
	jne	.loop				; progress: restart the window
	pause
	rdtsc
	shl	rdx,32
	or	rax,rdx
	cmp	rax,[g_spin_until]
	jb	.spin
.block:
	xor	edi,edi				; hellos waiting: do not sleep
	cmp	dword [g_hs_count],0
	jne	@f
	mov	edi,1
@@:
	call	ring_enter
	call	ring_reap
	call	ep_http_ready			; user-space TLS deliveries
	call	h2_flush			; HTTP/2: one send a connection an iteration
	call	hs_drain			; hellos that waited for the budget
	jmp	.loop
.drained:
	call	alog_flush
	mov	edi,EXIT_OK
	jmp	exit_process

.no_signalfd:
	push	rax
	call	log_begin
	out_lit 'signalfd failed (errno '
	jmp	.fatal
.no_memory:
	push	rax
	call	log_begin
	out_lit 'cannot reserve memory (errno '
	jmp	.fatal
.no_uring:
	; r12 = which step failed, eax = -errno
	mov	r13d,eax
	cmp	dword [g_plan_engine],1
	je	.uring_required
	mov	edi,[g_ring_fd]
	test	edi,edi
	jz	@f
	mov	eax,SYS_close			; drop the half-built ring
	syscall
@@:
	cmp	dword [g_worker_id],0
	jne	ep_main				; one line for the whole service
	call	log_begin
	out_lit 'io_uring unavailable ('
	call	.why
	out_lit '): using the epoll engine'
	call	log_end
	jmp	ep_main
.uring_required:
	call	log_begin
	out_lit 'io_uring unavailable ('
	call	.why
	out_lit ') and io_engine is io_uring'
	call	log_end
	mov	edi,EXIT_FATAL
	jmp	exit_process
.why:
	mov	rsi,r12
	call	out_cstr
	out_lit ', errno '
	mov	eax,r13d
	neg	eax
	push	rax
	call	out_u64
	pop	rax
	cmp	eax,EPERM
	jne	@f
	out_lit ': blocked by seccomp or kernel.io_uring_disabled'
@@:
	cmp	eax,ENOSYS
	jne	@f
	out_lit ': blocked by seccomp or not in this kernel'
@@:
	ret
.fatal:
	pop	rax
	neg	rax
	call	out_u64
	out_lit ')'
	call	log_end
	mov	edi,EXIT_FATAL
	jmp	exit_process

; TSC ticks per microsecond (the TSC is invariant on every x86-64-v3 CPU).
tsc_calibrate:
	cmp	qword [g_tsc_per_us],0
	jne	.known				; measured by the supervisor, inherited
	rdtsc
	shl	rdx,32
	or	rax,rdx
	push	rax
	lea	rdi,[ts_calibrate]
	xor	esi,esi
	mov	eax,SYS_nanosleep
	syscall
	rdtsc
	shl	rdx,32
	or	rax,rdx
	pop	rcx
	sub	rax,rcx
	xor	edx,edx
	mov	ecx,10000
	div	rcx
	mov	[g_tsc_per_us],rax
.known:
	ret

; Multishot one-second tick: idle timeouts and drain deadlines.
arm_timer:
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_TIMEOUT
	lea	rcx,[ts_tick]
	mov	[rax+SQE_ADDR],rcx
	mov	dword [rax+SQE_LEN],1
	mov	dword [rax+SQE_OP_FLAGS],IORING_TIMEOUT_MULTISHOT
	mov	rcx,OP_TIMER shl 56
	mov	[rax+SQE_USER_DATA],rcx
	ret

cstring str_why_setup, 'io_uring_setup',0
cstring str_why_files, 'registering descriptors',0
cstring str_why_pbuf, 'registering provided buffers, kernel 5.19+',0
cstring str_why_lockdown, 'restricting operations',0

on_timer:
	test	r15d,IORING_CQE_F_MORE
	jnz	tick_work
	call	arm_timer

; Once a second, both engines: heartbeat, idle timeouts, drain deadlines.
tick_work:
	inc	dword [g_tick]
	call	groups_refresh
	call	health_follow
	call	pool_expire
	call	stats_publish
	mov	eax,[g_hb_slot]
	add	rax,[g_hb]
	inc	qword [rax]
	call	idle_expire
	call	ph_expire
	call	retry_budget_tick
	call	alog_tick
	cmp	dword [g_draining],0
	je	.done
	mov	eax,[g_tick]
	cmp	eax,[g_drain_until]
	jb	.done
	cmp	dword [g_draining],1
	je	stop_accepting
	; drain timeout: close what is left
	call	sessions_close_all
.done:
	ret

arm_signal:
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_READ
	mov	ecx,[g_sigfd]
	mov	[rax+SQE_FD],ecx
	lea	rcx,[g_sig_buf]
	mov	[rax+SQE_ADDR],rcx
	mov	dword [rax+SQE_LEN],SIGINFO_SIZE
	mov	rcx,OP_SIGNAL shl 56
	mov	[rax+SQE_USER_DATA],rcx
	ret

; SIGTERM/SIGINT: keep serving for the drain delay, then stop accepting
; and give open connections until the drain timeout.
on_signal:
	call	arm_signal

drain_begin:
	; SIGUSR1: a reload replaced this worker; stop accepting right away
	cmp	dword [g_sig_buf],SIGUSR1
	jne	.term
	cmp	dword [g_draining],2
	jae	.done
	mov	dword [g_draining],1
	jmp	stop_accepting
.term:
	cmp	dword [g_draining],0
	jne	.done
	mov	dword [g_draining],1
	mov	rax,[g_plan_drain_delay]
	call	us_to_ticks
	add	eax,[g_tick]
	mov	[g_drain_until],eax
	cmp	qword [g_plan_drain_delay],0
	je	stop_accepting
.done:
	ret

; rax = microseconds. eax = whole ticks, rounded up.
us_to_ticks:
	add	rax,999999
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	ret

stop_accepting:
	mov	dword [g_draining],2
	mov	rax,[g_plan_drain_timeout]
	call	us_to_ticks
	add	eax,[g_tick]
	mov	[g_drain_until],eax
	cmp	dword [g_engine],ENGINE_EPOLL
	je	ep_stop_accepting
	lea	rsi,[cancel_accept]
	jmp	for_each_socket

; edi = socket id: cancel its multishot accept.
cancel_accept:
	push	rdi
	call	ring_get_sqe
	pop	rdi
	push	rax
	call	listener_fd
	mov	ecx,eax
	pop	rax
	mov	byte [rax+SQE_OPCODE],IORING_OP_ASYNC_CANCEL
	mov	[rax+SQE_FD],ecx
	mov	dword [rax+SQE_OP_FLAGS],IORING_ASYNC_CANCEL_FD or IORING_ASYNC_CANCEL_ALL
	mov	rcx,OP_IGNORE shl 56
	mov	[rax+SQE_USER_DATA],rcx
	ret
