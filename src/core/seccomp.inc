; Seccomp filters, one per kind of process.
;
; Filters are inherited across fork and can only get stricter, so they
; are layered:
;   supervisor  before the first fork: what it needs from then on (reload
;               included), plus what every child needs to start
;   worker      once set up: the I/O of its engine
;   control     DNS and read-only access to resolv.conf and hosts
;   health      check connections
;   compiler    the reload's configuration compiler: almost nothing
; Never allowed anywhere: execve, ptrace, clone/clone3/vfork (fork only),
; open (openat only, read-only outside the supervisor), executable
; mappings, the x32 ABI, foreign architectures.
;
; A refused call raises SIGSYS; the handler logs which call it was and
; exits, and the supervisor restarts the process like after a crash.
; io_uring operations do not go through seccomp: the ring has its own
; allowlist (IORING_REGISTER_RESTRICTIONS, src/core/ring.inc).
;
; Derived from fasm2crud's filters.

SECCOMP_RET_TRAP = 0x00030000
SA_SIGINFO	= 4
SA_RESTORER	= 0x04000000
SIGSYS		= 31
SI_SYSCALL	= 24		; siginfo_t, SIGSYS: si_syscall
X32_SYSCALL_BIT	= 0x40000000

; BPF over struct seccomp_data: nr at 0, arch at 4, args[i] at 16 + 8 * i.
macro bpf_ld off*
	dw 0x20
	db 0, 0
	dd off
end macro

macro bpf_ret k*
	dw 0x06
	db 0, 0
	dd k
end macro

; Conditional jumps to labels further down.
macro bpf_jeq k*, t*, f*
	local here
	here:
	dw 0x15
	db (t - here) / 8 - 1, (f - here) / 8 - 1
	dd k
end macro

macro bpf_jge k*, t*, f*
	local here
	here:
	dw 0x35
	db (t - here) / 8 - 1, (f - here) / 8 - 1
	dd k
end macro

macro bpf_jset k*, t*, f*
	local here
	here:
	dw 0x45
	db (t - here) / 8 - 1, (f - here) / 8 - 1
	dd k
end macro

; A filter: sc_begin name, sc_allow / sc_check lines, sc_end name.
macro sc_begin f*
	align 8
	f:
	bpf_ld 4
	bpf_jeq AUDIT_ARCH_X86_64, f#.nr, f#.kill
	f#.nr:
	bpf_ld 0
	bpf_jge X32_SYSCALL_BIT, f#.kill, f#.list
	f#.list:
end macro

macro sc_allow f*, nr*
	local next
	bpf_jeq nr, f#.allow, next
	next:
end macro

macro sc_check f*, nr*, block*
	local next
	bpf_jeq nr, f#.#block, next
	next:
end macro

macro sc_end f*
	bpf_jeq 0, f#.trap, f#.trap		; anything else
	; argument checks (BPF jumps only forward: the returns come last)
	f#.no_exec:				; mmap, mprotect: prot is args[2]
	bpf_ld 32
	bpf_jset PROT_EXEC, f#.trap, f#.allow
	f#.prctl:
	bpf_ld 16
	bpf_jeq PR_SET_PDEATHSIG, f#.allow, f#.p1
	f#.p1:
	bpf_jeq PR_SET_NAME, f#.allow, f#.p2
	f#.p2:
	bpf_jeq PR_SET_NO_NEW_PRIVS, f#.allow, f#.p3
	f#.p3:
	bpf_jeq PR_SET_SECCOMP, f#.allow, f#.trap
	f#.socket:				; families in use only
	bpf_ld 16
	bpf_jeq AF_INET, f#.allow, f#.s1
	f#.s1:
	bpf_jeq AF_INET6, f#.allow, f#.s2
	f#.s2:
	bpf_jeq AF_UNIX, f#.allow, f#.trap
	f#.read_only:				; openat: flags are args[2]
	bpf_ld 32
	bpf_jset O_WRONLY or O_RDWR or O_CREAT or O_TRUNC or O_APPEND, f#.trap, f#.allow
	f#.append_only:				; openat: read, or write at the end only
	bpf_ld 32
	bpf_jset O_RDWR or O_TRUNC, f#.trap, f#.ap1
	f#.ap1:
	bpf_jset O_WRONLY, f#.ap2, f#.allow
	f#.ap2:
	bpf_jset O_APPEND, f#.allow, f#.trap
	f#.trap:
	bpf_ret SECCOMP_RET_TRAP
	f#.kill:
	bpf_ret SECCOMP_RET_KILL_PROCESS
	f#.allow:
	bpf_ret SECCOMP_RET_ALLOW
	f#.end:
	f#.len = (f#.end - f) / 8
	assert f#.len <= 256			; jump offsets are 8 bits
end macro

macro sc_common f*
	sc_allow f, SYS_write			; logs
	sc_allow f, SYS_rt_sigreturn
	sc_allow f, SYS_exit
	sc_allow f, SYS_exit_group
end macro

rodata
	sc_begin filter_supervisor
	sc_common filter_supervisor
	; the supervisor: signals, children, reload, DNS before forking
	sc_allow filter_supervisor, SYS_read
	sc_allow filter_supervisor, SYS_close
	sc_allow filter_supervisor, SYS_fstat
	sc_check filter_supervisor, SYS_openat, append_only	; config; access logs (logger)
	sc_check filter_supervisor, SYS_mmap, no_exec
	sc_allow filter_supervisor, SYS_madvise
	sc_allow filter_supervisor, SYS_fork
	sc_allow filter_supervisor, SYS_waitid
	sc_allow filter_supervisor, SYS_kill
	sc_allow filter_supervisor, SYS_setitimer
	sc_allow filter_supervisor, SYS_nanosleep
	sc_allow filter_supervisor, SYS_clock_gettime
	sc_allow filter_supervisor, SYS_getrandom
	sc_check filter_supervisor, SYS_socket, socket
	sc_allow filter_supervisor, SYS_bind
	sc_allow filter_supervisor, SYS_listen
	sc_allow filter_supervisor, SYS_connect
	sc_allow filter_supervisor, SYS_setsockopt
	; children starting
	sc_check filter_supervisor, SYS_prctl, prctl
	sc_allow filter_supervisor, SYS_getppid
	sc_allow filter_supervisor, SYS_sched_setaffinity
	sc_allow filter_supervisor, SYS_signalfd4
	sc_allow filter_supervisor, SYS_io_uring_setup
	sc_allow filter_supervisor, SYS_io_uring_register
	sc_allow filter_supervisor, SYS_io_uring_enter
	sc_allow filter_supervisor, SYS_epoll_create1
	sc_allow filter_supervisor, SYS_epoll_ctl
	sc_allow filter_supervisor, SYS_epoll_wait
	sc_allow filter_supervisor, SYS_accept4
	sc_allow filter_supervisor, SYS_getsockopt
	sc_allow filter_supervisor, SYS_shutdown
	sc_allow filter_supervisor, SYS_getsockname
	sc_allow filter_supervisor, SYS_recvfrom
	sc_end filter_supervisor

	; io_uring worker: the ring does the I/O
	sc_begin filter_worker_uring
	sc_common filter_worker_uring
	sc_allow filter_worker_uring, SYS_io_uring_enter
	sc_allow filter_worker_uring, SYS_madvise
	sc_allow filter_worker_uring, SYS_getsockname	; PROXY protocol, wildcard listeners
	sc_allow filter_worker_uring, SYS_clock_gettime	; once a tick: access log time
	sc_end filter_worker_uring

	; epoll worker
	sc_begin filter_worker_epoll
	sc_common filter_worker_epoll
	sc_allow filter_worker_epoll, SYS_epoll_wait
	sc_allow filter_worker_epoll, SYS_epoll_ctl
	sc_allow filter_worker_epoll, SYS_read
	sc_allow filter_worker_epoll, SYS_accept4
	sc_allow filter_worker_epoll, SYS_close
	sc_check filter_worker_epoll, SYS_socket, socket
	sc_allow filter_worker_epoll, SYS_connect
	sc_allow filter_worker_epoll, SYS_setsockopt
	sc_allow filter_worker_epoll, SYS_getsockopt
	sc_allow filter_worker_epoll, SYS_shutdown
	sc_allow filter_worker_epoll, SYS_clock_gettime
	sc_allow filter_worker_epoll, SYS_madvise
	sc_allow filter_worker_epoll, SYS_getsockname
	sc_allow filter_worker_epoll, SYS_recvfrom	; liveness peek of pooled connections
	sc_end filter_worker_epoll

	; control process: DNS over UDP, resolv.conf and hosts read-only
	sc_begin filter_control
	sc_common filter_control
	sc_check filter_control, SYS_openat, read_only
	sc_allow filter_control, SYS_read
	sc_allow filter_control, SYS_close
	sc_check filter_control, SYS_socket, socket
	sc_allow filter_control, SYS_connect
	sc_allow filter_control, SYS_setsockopt
	sc_allow filter_control, SYS_getrandom
	sc_allow filter_control, SYS_nanosleep
	sc_allow filter_control, SYS_clock_gettime
	sc_end filter_control

	; health process: check connections
	sc_begin filter_health
	sc_common filter_health
	sc_check filter_health, SYS_socket, socket
	sc_allow filter_health, SYS_connect
	sc_allow filter_health, SYS_getsockopt
	sc_allow filter_health, SYS_close
	sc_allow filter_health, SYS_epoll_ctl
	sc_allow filter_health, SYS_epoll_wait
	sc_allow filter_health, SYS_read		; HTTP checks: the status line
	sc_allow filter_health, SYS_clock_gettime
	sc_end filter_health

	; admin process: one connection at a time on the metrics socket
	sc_begin filter_admin
	sc_common filter_admin
	sc_allow filter_admin, SYS_accept4
	sc_allow filter_admin, SYS_read
	sc_allow filter_admin, SYS_close
	sc_allow filter_admin, SYS_setsockopt
	sc_end filter_admin

	; logger: access log lines from the pipe to their files
	sc_begin filter_logger
	sc_common filter_logger
	sc_allow filter_logger, SYS_read
	sc_allow filter_logger, SYS_close
	sc_check filter_logger, SYS_openat, append_only
	sc_allow filter_logger, SYS_epoll_wait
	sc_end filter_logger

	; reload compiler: parses bytes already in memory, prints, exits
	sc_begin filter_compiler
	sc_common filter_compiler
	sc_check filter_compiler, SYS_mmap, no_exec
	sc_allow filter_compiler, SYS_madvise
	sc_end filter_compiler

	align 8
	sigact_sigsys	dq on_sigsys, SA_SIGINFO or SA_RESTORER, sigsys_restorer, 0
end rodata

; rsi = filter, edx = its length. Exits when it cannot be installed: a
; process meant to be confined must not run unconfined.
seccomp_install:
	sub	rsp,16
	mov	word [rsp],dx
	mov	[rsp+8],rsi
	mov	edi,PR_SET_NO_NEW_PRIVS
	mov	esi,1
	xor	edx,edx
	xor	r10d,r10d
	xor	r8d,r8d
	mov	eax,SYS_prctl
	syscall
	test	eax,eax
	js	.failed
	mov	edi,PR_SET_SECCOMP
	mov	esi,SECCOMP_MODE_FILTER
	mov	rdx,rsp
	mov	eax,SYS_prctl
	syscall
	test	eax,eax
	js	.failed
	add	rsp,16
	ret
.failed:
	push	rax
	call	log_begin
	out_lit 'cannot install the seccomp filter (errno '
	pop	rax
	neg	rax
	call	out_u64
	out_lit ')'
	call	log_end
	mov	edi,EXIT_FATAL
	jmp	exit_process

macro seccomp_for name*
	lea	rsi,[name]
	mov	edx,name#.len
	call	seccomp_install
end macro

; Supervisor, before the first fork: the SIGSYS handler (inherited by
; every process) and the outer filter.
seccomp_supervisor:
	mov	edi,SIGSYS
	lea	rsi,[sigact_sigsys]
	xor	edx,edx
	mov	r10d,8
	mov	eax,SYS_rt_sigaction
	syscall
	seccomp_for filter_supervisor
	ret

; SIGSYS: rsi = siginfo_t. Log the call and exit.
on_sigsys:
	mov	ebx,[rsi+SI_SYSCALL]
	call	log_begin
	out_lit 'seccomp refused system call '
	mov	eax,ebx
	call	out_u64
	out_lit ', exiting'
	call	log_end
	mov	edi,EXIT_FAILURE
	jmp	exit_process

sigsys_restorer:
	mov	eax,SYS_rt_sigreturn
	syscall
