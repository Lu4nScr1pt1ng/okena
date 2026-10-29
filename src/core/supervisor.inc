; Supervisor: owns the listening sockets, forks one worker per CPU and keeps
; them alive.
;
; Every listener gets one SO_REUSEPORT socket per worker, created here
; before any fork. Because the supervisor keeps them all open, a worker
; that crashes does not take its accept queues with it: connections the
; kernel already routed to its sockets wait there for the replacement.

LISTEN_BACKLOG	= 4096

bss
	g_sup_pid	dd ?
	g_sup_sigfd	dd ?
	g_alive		dd ?
	g_shutdown	dd ?
	g_exit_code	dd ?
	g_sigmask	dq ?
	g_worker_pid	rd MAX_WORKERS
	g_worker_born	rq MAX_WORKERS
	g_spawned	rd MAX_WORKERS		; starts of each worker index
	g_spawn_delay	rd MAX_WORKERS		; current retry delay (ms)
	g_hb_seen	rq MAX_WORKERS		; heartbeat at the last check
	g_hb_stale	rd MAX_WORKERS		; checks without progress
	g_hb		dq ?			; shared page: one cache line per worker
	g_watchdog_s	dd ?
	g_lfd		rd MAX_LISTENERS * MAX_WORKERS	; [listener * MAX_WORKERS + socket]
	g_lsocks	rd MAX_LISTENERS		; sockets of each listener
	g_siginfo:	rb SIGINFO_SIZE
end bss

rodata
	align 8
	sigact_ignore	dq SIG_IGN, 0, 0, 0	; handler, flags, restorer, mask
	ts_respawn_delay dq 0, 250000000	; 250 ms
	one_int		dd 1
	zero_int	dd 0
end rodata

supervisor_main:
	call	cpu_discover
	call	cpu_worker_count
	mov	[g_workers],eax
	call	raise_nofile_limit

	; Writes to closed sockets must return EPIPE, never kill the process.
	mov	edi,SIGPIPE
	lea	rsi,[sigact_ignore]
	xor	edx,edx
	mov	r10d,8
	mov	eax,SYS_rt_sigaction
	syscall

	; Heartbeats: workers write theirs, the supervisor reads them. Shared
	; and mapped before any fork; each worker's counter has its own cache
	; line, so no two cores ever write the same line.
	xor	edi,edi
	mov	esi,MAX_WORKERS * 64 * 2		; two generations side by side
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_ANONYMOUS
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.no_signalfd
	mov	[g_hb],rax
	mov	rax,[g_plan_watchdog]
	add	rax,999999
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	cmp	eax,2
	jae	@f
	mov	eax,2				; a tick is one second: less would misfire
@@:
	mov	[g_watchdog_s],eax
	call	dns_table_init
	call	groups_resolve_all
	call	health_table_init
	call	peer_global_init		; per_source table: lives across reloads
	call	stats_table_init
	call	metrics_open

	; TERM, INT, CHLD and ALRM (the watchdog) arrive through a signalfd.
	; Blocking them here also makes workers inherit the blocked mask.
	mov	qword [g_sigmask],(1 shl (SIGTERM-1)) or (1 shl (SIGINT-1)) or (1 shl (SIGCHLD-1)) or (1 shl (SIGALRM-1)) or (1 shl (SIGHUP-1)) or (1 shl (SIGUSR1-1))
	mov	edi,SIG_BLOCK
	lea	rsi,[g_sigmask]
	xor	edx,edx
	mov	r10d,8
	mov	eax,SYS_rt_sigprocmask
	syscall
	mov	edi,-1
	lea	rsi,[g_sigmask]
	mov	edx,8
	mov	r10d,SFD_CLOEXEC
	mov	eax,SYS_signalfd4
	syscall
	test	eax,eax
	js	.no_signalfd
	mov	[g_sup_sigfd],eax
	mov	eax,SYS_getpid
	syscall
	mov	[g_sup_pid],eax

	; one socket per worker for each listener
	xor	r12d,r12d
.listener:
	cmp	r12d,[g_plan_listeners]
	jae	.opened
	mov	edi,r12d
	call	listener_probe
	xor	ebx,ebx
.socket:
	mov	edi,r12d
	call	listener_open
	mov	ecx,r12d
	imul	ecx,ecx,MAX_WORKERS
	add	ecx,ebx
	mov	[g_lfd+rcx*4],eax
	inc	ebx
	cmp	ebx,[g_workers]
	jb	.socket
	mov	eax,[g_workers]
	mov	[g_lsocks+r12*4],eax
	call	log_listener
	inc	r12d
	jmp	.listener
.opened:
	call	log_begin
	out_lit 'started with '
	mov	eax,[g_workers]
	call	out_u64
	out_lit ' worker'
	cmp	dword [g_workers],1
	je	@f
	out_lit 's'
@@:
	mov	eax,[g_cpu_quota]
	test	eax,eax
	jz	@f
	cmp	eax,[g_cpu_count]
	jae	@f
	out_lit ' (cgroup CPU quota of '
	mov	eax,[g_cpu_quota]
	call	out_u64
	out_lit '; pin cores with --cpuset-cpus for unthrottled latency)'
@@:
	call	log_end

	; from here on the supervisor and everything it forks are confined
	call	seccomp_supervisor
	xor	ebx,ebx
.spawn_all:
	mov	edi,ebx
	call	spawn_worker
	inc	ebx
	cmp	ebx,[g_workers]
	jb	.spawn_all

	call	spawn_control
	call	spawn_health
	call	spawn_admin

	; check the heartbeats once a second
	sub	rsp,32
	mov	qword [rsp],1			; it_interval
	mov	qword [rsp+8],0
	mov	qword [rsp+16],1		; it_value
	mov	qword [rsp+24],0
	mov	edi,ITIMER_REAL
	mov	rsi,rsp
	xor	edx,edx
	mov	eax,SYS_setitimer
	syscall
	add	rsp,32

.wait_signal:
	mov	edi,[g_sup_sigfd]
	lea	rsi,[g_siginfo]
	mov	edx,SIGINFO_SIZE
	xor	eax,eax
	syscall
	cmp	rax,-EINTR
	je	.wait_signal
	test	rax,rax
	js	.no_signalfd
	mov	eax,[g_siginfo]			; ssi_signo
	cmp	eax,SIGCHLD
	je	.child
	cmp	eax,SIGALRM
	je	.watchdog
	cmp	eax,SIGHUP
	je	.reload
	cmp	eax,SIGUSR1
	je	.wait_signal
	call	begin_shutdown
	jmp	.wait_signal
.child:
	call	reap_workers
	jmp	.wait_signal
.watchdog:
	call	watchdog_check
	call	old_workers_check
	jmp	.wait_signal
.reload:
	call	supervisor_reload
	jmp	.wait_signal

.no_signalfd:
	call	log_begin
	out_lit 'signalfd failed'
	call	log_end
	mov	edi,EXIT_FAILURE
	jmp	exit_process

; "listening on :5432 (tcp, to pool pg: 3 servers)"
log_listener:
	push	rbx
	imul	rbx,r12,LS_SIZE
	lea	rbx,[g_listeners+rbx]
	call	log_begin
	out_lit 'listening on '
	mov	rsi,[rbx+LS_TEXT]
	mov	edx,[rbx+LS_TLEN]
	call	out_str
	out_lit ' (tcp, to '
	mov	eax,[rbx+LS_POOL]
	imul	rax,rax,PL_SIZE
	lea	rcx,[g_pools+rax]
	push	rcx
	cmp	dword [rcx+PL_NLEN],0
	je	@f
	out_lit 'pool '
	mov	rcx,[rsp]
	mov	rsi,[rcx+PL_NAME]
	mov	edx,[rcx+PL_NLEN]
	call	out_str
	out_lit ': '
@@:
	pop	rcx
	call	pool_written_count
	push	rax
	call	out_u64
	out_lit ' server'
	pop	rax
	cmp	eax,1
	je	@f
	out_lit 's'
@@:
	out_lit ')'
	call	log_end
	pop	rbx
	ret

; Refuse to share a port with another program. SO_REUSEPORT lets any
; process of the same user bind next to us, and the kernel would then
; split new connections between the two: a second okena started by
; mistake, or an old one still draining, would silently take part of the
; traffic. A probe socket without SO_REUSEPORT fails to bind when anyone
; is listening there. edi = listener.
listener_probe:
	push	rbx
	push	r12
	push	r13
	push	r14
	imul	rbx,rdi,LS_SIZE
	lea	rbx,[g_listeners+rbx]
	mov	r13d,[rbx+LS_FAMILY]
	mov	r14d,r13d
	test	r13d,r13d
	jnz	@f
	mov	r13d,AF_INET6
@@:
	mov	edi,r13d
	mov	esi,SOCK_STREAM or SOCK_CLOEXEC
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	.done				; listener_open will report it
	mov	r12d,eax
	cmp	r13d,AF_INET6
	jne	@f
	mov	edi,r12d
	mov	esi,IPPROTO_IPV6
	mov	edx,IPV6_V6ONLY
	lea	r10,[zero_int]
	test	r14d,r14d
	jz	.v6only
	lea	r10,[one_int]
.v6only:
	mov	r8d,4
	mov	eax,SYS_setsockopt
	syscall
@@:
	mov	edi,r12d
	mov	esi,SOL_SOCKET
	mov	edx,SO_REUSEADDR		; TIME_WAIT leftovers are fine
	lea	r10,[one_int]
	mov	r8d,4
	mov	eax,SYS_setsockopt
	syscall
	mov	edi,r12d
	lea	rsi,[rbx+LS_SA]
	mov	edx,[rbx+LS_SALEN]
	mov	eax,SYS_bind
	syscall
	push	rax
	mov	edi,r12d
	mov	eax,SYS_close
	syscall
	pop	rax
	cmp	eax,-EADDRINUSE
	jne	.done
	call	log_begin
	out_lit 'cannot listen on '
	mov	rsi,[rbx+LS_TEXT]
	mov	edx,[rbx+LS_TLEN]
	call	out_str
	out_lit ': another program is listening there (another okena still running?)'
	call	log_end
	cmp	dword [g_reloading],0
	jne	.busy
	mov	edi,EXIT_FAILURE
	jmp	exit_process
.busy:
	mov	eax,1
	jmp	.out
.done:
	xor	eax,eax
.out:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rcx = pool. eax = servers as written: a name counts once, not as the
; slots reserved for its addresses.
pool_written_count:
	mov	edx,[rcx+PL_FIRST]
	mov	r8d,edx
	add	r8d,[rcx+PL_COUNT]
	xor	eax,eax
.next:
	cmp	edx,r8d
	jae	.done
	imul	r9,rdx,SV_SIZE
	mov	r10d,[g_servers+r9+SV_GROUP]
	test	r10d,r10d
	jz	.count
	dec	r10d
	imul	r10,r10,GR_SIZE
	cmp	[g_groups+r10+GR_FIRST],edx
	jne	.skip
.count:
	inc	eax
.skip:
	inc	edx
	jmp	.next
.done:
	ret

; edi = listener index. eax = socket. Exits on failure: a listener that
; cannot be opened is a configuration the host cannot serve.
; ":port" is dual stack: an IPv6 socket that takes IPv4 too, or plain IPv4
; when the kernel has no IPv6.
listener_open:
	push	rbx
	push	r12
	push	r13
	push	r14
	imul	rbx,rdi,LS_SIZE
	lea	rbx,[g_listeners+rbx]
	mov	r12d,-1
	mov	r13d,[rbx+LS_FAMILY]
	mov	r14d,r13d
	test	r13d,r13d
	jnz	@f
	mov	r13d,AF_INET6
@@:
	mov	edi,r13d
	mov	esi,SOCK_STREAM or SOCK_CLOEXEC or SOCK_NONBLOCK
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	jns	.created
	test	r14d,r14d
	jnz	.failed
	; no IPv6: bind ":port" on IPv4 only
	mov	r13d,AF_INET
	mov	word [rbx+LS_SA],AF_INET
	mov	dword [rbx+LS_SA+4],0
	mov	dword [rbx+LS_SALEN],16
	mov	edi,AF_INET
	mov	esi,SOCK_STREAM or SOCK_CLOEXEC or SOCK_NONBLOCK
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	.failed
.created:
	mov	r12d,eax
	cmp	r13d,AF_INET6
	jne	.opts
	; ":port" takes IPv4 too; an explicit IPv6 address takes only IPv6
	mov	esi,IPPROTO_IPV6
	mov	edx,IPV6_V6ONLY
	lea	r10,[zero_int]
	test	r14d,r14d
	jz	@f
	lea	r10,[one_int]
@@:
	call	.setsockopt
.opts:
	mov	esi,SOL_SOCKET
	mov	edx,SO_REUSEADDR
	lea	r10,[one_int]
	call	.setsockopt
	mov	esi,SOL_SOCKET
	mov	edx,SO_REUSEPORT
	lea	r10,[one_int]
	call	.setsockopt
	; accepted sockets inherit TCP_NODELAY from the listener
	mov	esi,IPPROTO_TCP
	mov	edx,TCP_NODELAY
	lea	r10,[one_int]
	call	.setsockopt
	mov	edi,r12d
	lea	rsi,[rbx+LS_SA]
	mov	edx,[rbx+LS_SALEN]
	mov	eax,SYS_bind
	syscall
	test	eax,eax
	js	.failed
	mov	edi,r12d
	mov	esi,LISTEN_BACKLOG
	mov	eax,SYS_listen
	syscall
	test	eax,eax
	js	.failed
	mov	eax,r12d
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

.setsockopt:
	mov	edi,r12d
	mov	r8d,4
	mov	eax,SYS_setsockopt
	syscall
	test	eax,eax
	js	.failed_pop
	ret
.failed_pop:
	add	rsp,8
.failed:
	push	rax
	call	log_begin
	out_lit 'cannot listen on '
	mov	rsi,[rbx+LS_TEXT]
	mov	edx,[rbx+LS_TLEN]
	call	out_str
	pop	rax
	neg	rax
	cmp	eax,EADDRINUSE
	jne	@f
	out_lit ': address already in use'
	jmp	.reported
@@:
	cmp	eax,EACCES
	jne	@f
	out_lit ': permission denied (ports below 1024 need CAP_NET_BIND_SERVICE)'
	jmp	.reported
@@:
	cmp	eax,EADDRNOTAVAIL
	jne	@f
	out_lit ': no such address on this host'
	jmp	.reported
@@:
	out_lit ' (errno '
	call	out_u64
	out_lit ')'
.reported:
	call	log_end
	cmp	dword [g_reloading],0
	jne	.soft
	mov	edi,EXIT_FAILURE
	jmp	exit_process
.soft:
	test	r12d,r12d
	js	@f
	mov	edi,r12d
	mov	eax,SYS_close
	syscall
@@:
	mov	eax,-1
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; A worker whose heartbeat has not moved for the watchdog time is stuck
; (a loop, a syscall that never returns, SIGSTOP): kill it, and the reaper
; starts a replacement. Its tick moves the heartbeat every second even
; when idle, so silence means stuck, not quiet.
watchdog_check:
	push	rbx
	xor	ebx,ebx
.next:
	cmp	ebx,[g_workers]
	jae	.done
	cmp	dword [g_worker_pid+rbx*4],0
	je	.skip
	call	hb_line
	add	rax,[g_hb]
	mov	rax,[rax]
	cmp	rax,[g_hb_seen+rbx*8]
	je	.stale
	mov	[g_hb_seen+rbx*8],rax
	mov	dword [g_hb_stale+rbx*4],0
	jmp	.skip
.stale:
	inc	dword [g_hb_stale+rbx*4]
	mov	eax,[g_hb_stale+rbx*4]
	cmp	eax,[g_watchdog_s]
	jne	.skip				; exactly once per stall
	call	log_begin
	out_lit 'worker '
	mov	eax,ebx
	call	out_u64
	out_lit ' (pid '
	mov	eax,[g_worker_pid+rbx*4]
	call	out_u64
	out_lit ') has not made progress for '
	mov	eax,[g_watchdog_s]
	call	out_u64
	out_lit ' s, killing it'
	call	log_end
	mov	edi,[g_worker_pid+rbx*4]
	mov	esi,SIGKILL
	mov	eax,SYS_kill
	syscall
.skip:
	inc	ebx
	jmp	.next
.done:
	pop	rbx
	ret

; ebx = worker index. rax = offset of its heartbeat line in this
; generation (old and new generations of a reload use different lines).
hb_line:
	mov	eax,[g_gen]
	and	eax,1
	imul	eax,eax,MAX_WORKERS
	add	eax,ebx
	shl	rax,6
	ret

; eax = previous delay (ms): the next one, 250 ms doubling up to 5 s, kept
; for worker ebx. eax = it.
start_backoff:
	test	eax,eax
	jnz	@f
	mov	eax,125
@@:
	add	eax,eax
	cmp	eax,5000
	jbe	@f
	mov	eax,5000
@@:
	mov	[g_spawn_delay+rbx*4],eax
	ret

; eax = milliseconds.
sleep_ms:
	sub	rsp,16
	xor	edx,edx
	mov	ecx,1000
	div	ecx
	mov	[rsp],rax
	imul	rdx,rdx,1000000
	mov	[rsp+8],rdx
	mov	rdi,rsp
	xor	esi,esi
	mov	eax,SYS_nanosleep
	syscall
	add	rsp,16
	ret

; edi = worker index.
spawn_worker:
	push	rbx
	mov	ebx,edi
	inc	dword [g_spawned+rbx*4]
	; a new worker starts with a clean slate, and one check of grace: its
	; first tick comes a second after its setup, not after the fork
	mov	dword [g_hb_stale+rbx*4],-1
	call	hb_line
	mov	[g_hb_slot],eax			; inherited by the worker
	add	rax,[g_hb]
	mov	rax,[rax]
	mov	[g_hb_seen+rbx*8],rax
	call	monotonic_seconds
	mov	[g_worker_born+rbx*8],rax
	mov	eax,SYS_fork
	syscall
	test	rax,rax
	jz	.child
	js	.failed
	mov	[g_worker_pid+rbx*4],eax
	inc	dword [g_alive]
	pop	rbx
	ret
.child:
	mov	edi,ebx
	jmp	worker_main
.failed:
	call	log_begin
	out_lit 'fork failed, shutting down'
	call	log_end
	mov	dword [g_exit_code],EXIT_FAILURE
	call	begin_shutdown
	pop	rbx
	ret

; Collect every exited worker and replace it, unless we are shutting down.
reap_workers:
	push	rbx
	push	r12
.next:
	lea	rdi,[g_siginfo]
	xor	eax,eax
	mov	ecx,SIGINFO_SIZE/8
	rep	stosq
	mov	edi,P_ALL
	xor	esi,esi
	lea	rdx,[g_siginfo]
	mov	r10d,WEXITED or WNOHANG
	xor	r8d,r8d
	mov	eax,SYS_waitid
	syscall
	test	rax,rax
	js	.done
	mov	r12d,[g_siginfo+SI_PID]
	test	r12d,r12d
	jz	.done
	cmp	r12d,[g_admin_pid]
	jne	.not_admin
	mov	dword [g_admin_pid],0
	cmp	dword [g_shutdown],0
	jne	.next
	lea	rdi,[ts_respawn_delay]
	xor	esi,esi
	mov	eax,SYS_nanosleep
	syscall
	call	spawn_admin
	jmp	.next
.not_admin:
	cmp	r12d,[g_health_pid]
	jne	.not_health
	mov	dword [g_health_pid],0
	cmp	dword [g_shutdown],0
	jne	.next
	call	log_begin
	out_lit 'health process exited, restarting it (servers keep their last state)'
	call	log_end
	lea	rdi,[ts_respawn_delay]
	xor	esi,esi
	mov	eax,SYS_nanosleep
	syscall
	call	spawn_health
	jmp	.next
.not_health:
	cmp	r12d,[g_control_pid]
	jne	.worker
	; the control process: workers keep the last published addresses
	; meanwhile; start a new one unless stopping
	mov	dword [g_control_pid],0
	cmp	dword [g_shutdown],0
	jne	.next
	call	log_begin
	out_lit 'control process exited, restarting it'
	call	log_end
	lea	rdi,[ts_respawn_delay]
	xor	esi,esi
	mov	eax,SYS_nanosleep
	syscall
	call	spawn_control
	jmp	.next
.worker:
	mov	edi,r12d
	call	reap_old
	jnc	.current
	cmp	dword [g_shutdown],0
	jne	.stopping
	jmp	.next
.current:
	xor	ebx,ebx
.find:
	cmp	ebx,[g_workers]
	jae	.next
	cmp	[g_worker_pid+rbx*4],r12d
	je	.found
	inc	ebx
	jmp	.find
.found:
	mov	dword [g_worker_pid+rbx*4],0
	dec	dword [g_alive]
	cmp	dword [g_shutdown],0
	jne	.stopping
	cmp	dword [g_siginfo+SI_CODE],CLD_EXITED
	jne	.crashed
	cmp	dword [g_siginfo+SI_STATUS],EXIT_FATAL
	jne	.crashed
	; A worker that cannot start at all, on the very first start, means
	; this host cannot run the configuration: stop. Later (a replacement
	; or a reload), it is most likely passing (memory, the kernel still
	; tearing down a dead worker's ring): keep retrying, slower each time.
	cmp	dword [g_gen],0
	jne	.retry_start
	cmp	dword [g_spawned+rbx*4],1
	ja	.retry_start
	call	log_begin
	out_lit 'worker '
	mov	eax,ebx
	call	out_u64
	out_lit ' could not start, shutting down'
	call	log_end
	mov	dword [g_exit_code],EXIT_FAILURE
	call	begin_shutdown
	jmp	.next
.retry_start:
	call	log_begin
	out_lit 'worker '
	mov	eax,ebx
	call	out_u64
	out_lit ' could not start (see above), retrying in '
	mov	eax,[g_spawn_delay+rbx*4]
	call	start_backoff
	call	out_u64
	out_lit ' ms'
	call	log_end
	mov	eax,[g_spawn_delay+rbx*4]
	call	sleep_ms
	mov	edi,ebx
	call	spawn_worker
	jmp	.next
.crashed:
	mov	dword [g_spawn_delay+rbx*4],0
	call	log_begin
	out_lit 'worker '
	mov	eax,ebx
	call	out_u64
	out_lit ' (pid '
	mov	eax,r12d
	call	out_u64
	cmp	dword [g_siginfo+SI_CODE],CLD_EXITED
	jne	.by_signal
	out_lit ') exited with status '
	jmp	.status
.by_signal:
	out_lit ') killed by signal '
.status:
	mov	eax,[g_siginfo+SI_STATUS]
	call	out_u64
	out_lit ', restarting'
	call	log_end
	mov	edi,SG_RESTARTS
	call	stats_global_inc
	; A worker that dies right after starting is crash-looping; slow the
	; restarts down so the supervisor does not spin.
	call	monotonic_seconds
	sub	rax,[g_worker_born+rbx*8]
	cmp	rax,1
	jae	.respawn
	lea	rdi,[ts_respawn_delay]
	xor	esi,esi
	mov	eax,SYS_nanosleep
	syscall
.respawn:
	mov	edi,ebx
	call	spawn_worker
	jmp	.next
.stopping:
	cmp	dword [g_alive],0
	jne	.next
	cmp	dword [g_old_count],0
	jne	.next
	mov	edi,[g_control_pid]
	test	edi,edi
	jz	@f
	mov	esi,SIGKILL			; nothing to drain there
	mov	eax,SYS_kill
	syscall
@@:
	mov	edi,[g_health_pid]
	test	edi,edi
	jz	@f
	mov	esi,SIGKILL
	mov	eax,SYS_kill
	syscall
@@:
	mov	edi,[g_admin_pid]
	test	edi,edi
	jz	@f
	mov	esi,SIGKILL
	mov	eax,SYS_kill
	syscall
@@:
	call	log_begin
	out_lit 'all workers stopped'
	call	log_end
	mov	edi,[g_exit_code]
	jmp	exit_process
.done:
	pop	r12
	pop	rbx
	ret

; First TERM/INT: ask workers to drain. A second one forces them down.
begin_shutdown:
	push	rbx
	push	r12
	mov	r12d,SIGTERM
	cmp	dword [g_shutdown],0
	je	.first
	mov	r12d,SIGKILL
	jmp	.signal
.first:
	mov	dword [g_shutdown],1
	mov	rax,[g_stats_tbl]
	mov	qword [rax+SG_OFF+SG_DRAINING],1	; /ready answers 503 from now on
	call	log_begin
	out_lit 'shutting down: draining connections'
	call	log_end
	cmp	dword [g_alive],0
	jne	.signal
	cmp	dword [g_old_count],0
	jne	.signal
	mov	edi,[g_exit_code]
	jmp	exit_process
.signal:
	xor	ebx,ebx
.old:
	cmp	ebx,[g_old_count]
	jae	.current
	mov	edi,[g_old_pid+rbx*4]
	mov	esi,r12d
	mov	eax,SYS_kill
	syscall
	inc	ebx
	jmp	.old
.current:
	xor	ebx,ebx
.each:
	cmp	ebx,[g_workers]
	jae	.done
	mov	edi,[g_worker_pid+rbx*4]
	test	edi,edi
	jz	.skip
	mov	esi,r12d
	mov	eax,SYS_kill
	syscall
.skip:
	inc	ebx
	jmp	.each
.done:
	pop	r12
	pop	rbx
	ret

; Lift the soft open-file limit to the hard limit: each worker's table of
; direct descriptors counts against RLIMIT_NOFILE.
bss
	g_nofile	dq ?
end bss

raise_nofile_limit:
	sub	rsp,24
	xor	edi,edi
	mov	esi,RLIMIT_NOFILE
	xor	edx,edx
	mov	r10,rsp
	mov	eax,SYS_prlimit64
	syscall
	test	rax,rax
	js	.done
	mov	rax,[rsp+8]
	mov	[rsp],rax
	mov	[g_nofile],rax
	xor	edi,edi
	mov	esi,RLIMIT_NOFILE
	mov	rdx,rsp
	xor	r10d,r10d
	mov	eax,SYS_prlimit64
	syscall
.done:
	add	rsp,24
	ret
