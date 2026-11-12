; Seccomp filters, one per kind of process.
;
; Filters are inherited across fork and can only get stricter, so they
; are layered:
;   supervisor  before the first fork: what it needs from then on (reload
;               included), plus what every child needs to start
;   worker      once set up: the I/O of its engine
;   control     DNS and read-only access to resolv.conf and hosts (okena-keys too)
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

SECCOMP_RET_TRAP := 0x00030000
SA_SIGINFO	:= 4
SA_RESTORER	:= 0x04000000
SIGSYS		:= 31
SI_SYSCALL	:= 24		; siginfo_t, SIGSYS: si_syscall
X32_SYSCALL_BIT	:= 0x40000000

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
	f#.socket_net:				; the supervisor's (vrrp's): netlink, packets too
	bpf_ld 16
	bpf_jeq AF_INET, f#.allow, f#.n1
	f#.n1:
	bpf_jeq AF_INET6, f#.allow, f#.n2
	f#.n2:
	bpf_jeq AF_UNIX, f#.allow, f#.n3
	f#.n3:
	bpf_jeq AF_NETLINK_, f#.allow, f#.n4
	f#.n4:
	bpf_jeq AF_PACKET_, f#.allow, f#.trap
	f#.ifreq:				; ioctl: an interface's index, address, MAC
	bpf_ld 24
	bpf_jeq SIOCGIFINDEX_, f#.allow, f#.i1
	f#.i1:
	bpf_jeq SIOCGIFADDR_, f#.allow, f#.i2
	f#.i2:
	bpf_jeq SIOCGIFHWADDR_, f#.allow, f#.trap
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
	f#.bpf_map:				; bpf: on maps only (args[0], the command:
	bpf_ld 16				; lookup, update, delete, next key, batch
	bpf_jeq 1, f#.allow, f#.bm1		; update); making maps and loading programs
	f#.bm1:					; happen before any filter (xdpctl.inc)
	bpf_jeq 2, f#.allow, f#.bm2
	f#.bm2:
	bpf_jeq 3, f#.allow, f#.bm3
	f#.bm3:
	bpf_jeq 4, f#.allow, f#.bm4
	f#.bm4:
	bpf_jeq 26, f#.allow, f#.trap
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
	sc_allow filter_supervisor, 217			; getdents64: `include "DIR/*.conf"`
	sc_check filter_supervisor, SYS_bpf, bpf_map	; (okena-xdp: the balancer's maps)
	sc_check filter_supervisor, SYS_mmap, no_exec
	sc_allow filter_supervisor, SYS_madvise
	sc_allow filter_supervisor, SYS_fork
	sc_allow filter_supervisor, SYS_waitid
	sc_allow filter_supervisor, SYS_kill
	sc_allow filter_supervisor, SYS_setitimer
	sc_allow filter_supervisor, SYS_nanosleep
	sc_allow filter_supervisor, SYS_poll		; (io_uring workers: accept_watch, timeout 0)
	sc_allow filter_supervisor, SYS_clock_gettime
	sc_allow filter_supervisor, SYS_getrandom
	sc_allow filter_supervisor, SYS_recvmmsg		; (QUIC, in workers)
	sc_allow filter_supervisor, SYS_sendmmsg
	sc_check filter_supervisor, SYS_socket, socket_net	; (the vrrp process: netlink, packets)
	sc_check filter_supervisor, SYS_ioctl_, ifreq
	sc_allow filter_supervisor, SYS_sendto
	sc_allow filter_supervisor, SYS_bind
	sc_allow filter_supervisor, SYS_listen
	sc_allow filter_supervisor, SYS_sendmsg_	; an upgrade: sockets to the new binary
	sc_allow filter_supervisor, SYS_rename_
	sc_allow filter_supervisor, SYS_getuid_
	sc_allow filter_supervisor, SYS_geteuid_	; children become `user` (privdrop.inc)
	sc_allow filter_supervisor, SYS_setgroups
	sc_allow filter_supervisor, SYS_setresgid
	sc_allow filter_supervisor, SYS_setresuid
	sc_allow filter_supervisor, SYS_ppoll_		; (the admin process)
	sc_allow filter_supervisor, SYS_connect
	sc_allow filter_supervisor, SYS_setsockopt
	; children starting
	sc_check filter_supervisor, SYS_prctl, prctl
	sc_allow filter_supervisor, SYS_rt_sigaction	; a worker's crash handlers (quarantine.inc)
	sc_allow filter_supervisor, SYS_sigaltstack
	sc_allow filter_supervisor, SYS_getppid
	sc_allow filter_supervisor, SYS_sched_setaffinity
	sc_allow filter_supervisor, SYS_signalfd4
	sc_allow filter_supervisor, SYS_ll_create	; a worker confines itself (files.inc)
	sc_allow filter_supervisor, SYS_ll_add
	sc_allow filter_supervisor, SYS_ll_restrict
	sc_allow filter_supervisor, SYS_openat2
	sc_allow filter_supervisor, SYS_fstat
	sc_allow filter_supervisor, SYS_lseek_
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
	sc_allow filter_supervisor, SYS_dup		; systemd's sockets, one a worker (systemd.inc)
	sc_allow filter_supervisor, SYS_fcntl
	sc_allow filter_supervisor, SYS_recvfrom
	sc_allow filter_supervisor, SYS_recvmsg	; epoll workers: kTLS control records
	sc_allow filter_supervisor, SYS_flock		; cache_disk: a worker opens the store (cdisk.inc)
	sc_allow filter_supervisor, SYS_ftruncate
	sc_allow filter_supervisor, SYS_getpid
	sc_allow filter_supervisor, SYS_pread64
	sc_allow filter_supervisor, SYS_pwritev
	sc_allow filter_supervisor, SYS_fdatasync
	sc_allow filter_supervisor, SYS_msync
	sc_allow filter_supervisor, SYS_pipe2		; zero copy: a worker's pipes (zc.inc)
	sc_allow filter_supervisor, SYS_sendfile	; (and an epoll worker's sendfile: filters stack)
	sc_allow filter_supervisor, SYS_pwrite64	; the cache keeper (ckeep.inc)
	sc_allow filter_supervisor, SYS_copy_file_range
	sc_allow filter_supervisor, SYS_rt_sigtimedwait
	sc_allow filter_supervisor, SYS_futex		; a worker wakes the cache keeper
	sc_allow filter_supervisor, SYS_mkdirat_	; the acme process: its directories
	sc_allow filter_supervisor, SYS_fchownat_
	sc_allow filter_supervisor, SYS_link_		; (its lock, shared=on: acmefleet.inc)
	sc_allow filter_supervisor, SYS_unlink_
	sc_end filter_supervisor

	; io_uring worker: the ring does the I/O
	sc_begin filter_worker_uring
	sc_common filter_worker_uring
	sc_allow filter_worker_uring, SYS_sendfile	; zero copy, on a descriptor the ring made (zc.inc)
	sc_allow filter_worker_uring, SYS_fcntl		; (made non-blocking)
	sc_allow filter_worker_uring, SYS_pread64		; cache_disk: a head read, a record written
	sc_allow filter_worker_uring, SYS_pwritev
	sc_allow filter_worker_uring, SYS_fdatasync		; (the last one out)
	sc_allow filter_worker_uring, SYS_msync
	sc_allow filter_worker_uring, SYS_futex		; (wakes the cache keeper)
	sc_allow filter_worker_uring, SYS_io_uring_enter
	sc_allow filter_worker_uring, SYS_madvise
	sc_allow filter_worker_uring, SYS_getsockname	; PROXY protocol, wildcard listeners
	sc_allow filter_worker_uring, SYS_clock_gettime	; once a tick: access log time
	sc_allow filter_worker_uring, SYS_getrandom	; TLS: server random, ephemeral keys
	sc_allow filter_worker_uring, SYS_recvmmsg	; QUIC datagrams
	sc_allow filter_worker_uring, SYS_sendmmsg
	sc_allow filter_worker_uring, SYS_poll		; (a listening socket nobody takes from: accept_watch)
	sc_allow filter_worker_uring, SYS_recvfrom	; bulk: reads and writes in the loop (bulk.inc)
	sc_allow filter_worker_uring, SYS_sendto
	sc_allow filter_worker_uring, SYS_sched_setaffinity	; (pin_workers auto: pinned under load)
	sc_end filter_worker_uring

	; io_uring worker with `udp` listeners (and whatever `files` needs): their
	; flows' sockets are opened, and forgotten, at the speed of a datagram
	sc_begin filter_worker_uring_u
	sc_common filter_worker_uring_u
	sc_allow filter_worker_uring_u, SYS_sendfile	; zero copy, on a descriptor the ring made (zc.inc)
	sc_allow filter_worker_uring_u, SYS_fcntl		; (made non-blocking)
	sc_allow filter_worker_uring_u, SYS_pread64		; cache_disk: a head read, a record written
	sc_allow filter_worker_uring_u, SYS_pwritev
	sc_allow filter_worker_uring_u, SYS_fdatasync		; (the last one out)
	sc_allow filter_worker_uring_u, SYS_msync
	sc_allow filter_worker_uring_u, SYS_futex		; (wakes the cache keeper)
	sc_allow filter_worker_uring_u, SYS_io_uring_enter
	sc_allow filter_worker_uring_u, SYS_madvise
	sc_allow filter_worker_uring_u, SYS_getsockname
	sc_allow filter_worker_uring_u, SYS_clock_gettime
	sc_allow filter_worker_uring_u, SYS_getrandom
	sc_allow filter_worker_uring_u, SYS_recvmmsg
	sc_allow filter_worker_uring_u, SYS_sendmmsg
	sc_allow filter_worker_uring_u, SYS_recvfrom
	sc_check filter_worker_uring_u, SYS_socket, socket
	sc_allow filter_worker_uring_u, SYS_connect
	sc_allow filter_worker_uring_u, SYS_setsockopt
	sc_allow filter_worker_uring_u, SYS_epoll_ctl
	sc_allow filter_worker_uring_u, SYS_epoll_wait
	sc_allow filter_worker_uring_u, SYS_openat2
	sc_allow filter_worker_uring_u, SYS_fstat
	sc_allow filter_worker_uring_u, SYS_lseek_
	sc_allow filter_worker_uring_u, SYS_close
	sc_allow filter_worker_uring_u, SYS_poll		; (a listening socket nobody takes from: accept_watch)
	sc_allow filter_worker_uring_u, SYS_sendto	; bulk (bulk.inc)
	sc_allow filter_worker_uring_u, SYS_sched_setaffinity	; (pin_workers auto: pinned under load)
	sc_end filter_worker_uring_u

	; epoll worker
	sc_begin filter_worker_epoll
	sc_common filter_worker_epoll
	sc_allow filter_worker_epoll, SYS_sendfile	; zero copy (zc.inc)
	sc_allow filter_worker_epoll, SYS_pread64		; cache_disk: a head read, a record written
	sc_allow filter_worker_epoll, SYS_pwritev
	sc_allow filter_worker_epoll, SYS_fdatasync		; (the last one out)
	sc_allow filter_worker_epoll, SYS_msync
	sc_allow filter_worker_epoll, SYS_futex		; (wakes the cache keeper)
	sc_allow filter_worker_epoll, SYS_epoll_wait
	sc_allow filter_worker_epoll, SYS_epoll_ctl
	sc_allow filter_worker_epoll, SYS_read
	sc_allow filter_worker_epoll, SYS_accept4
	sc_allow filter_worker_epoll, SYS_close
	sc_check filter_worker_epoll, SYS_socket, socket
	sc_allow filter_worker_epoll, SYS_connect
	sc_allow filter_worker_epoll, SYS_bind		; (a pool's `source`)
	sc_allow filter_worker_epoll, SYS_setsockopt
	sc_allow filter_worker_epoll, SYS_getsockopt
	sc_allow filter_worker_epoll, SYS_shutdown
	sc_allow filter_worker_epoll, SYS_clock_gettime
	sc_allow filter_worker_epoll, SYS_madvise
	sc_allow filter_worker_epoll, SYS_getsockname
	sc_allow filter_worker_epoll, SYS_recvfrom	; peeks: pooled connections, TLS Finished
	sc_allow filter_worker_epoll, SYS_getrandom	; TLS: server random, ephemeral keys
	sc_allow filter_worker_epoll, SYS_recvmmsg	; QUIC datagrams
	sc_allow filter_worker_epoll, SYS_sendmmsg
	sc_allow filter_worker_epoll, SYS_recvmsg	; kTLS upstream: control records (tickets)
	sc_allow filter_worker_epoll, SYS_sched_setaffinity	; (pin_workers auto: pinned under load)
	sc_end filter_worker_epoll

	; workers with `files` routes: they open beneath their roots (files.inc)
	sc_begin filter_worker_uring_f
	sc_common filter_worker_uring_f
	sc_allow filter_worker_uring_f, SYS_sendfile	; zero copy, on a descriptor the ring made (zc.inc)
	sc_allow filter_worker_uring_f, SYS_fcntl		; (made non-blocking)
	sc_allow filter_worker_uring_f, SYS_pread64		; cache_disk: a head read, a record written
	sc_allow filter_worker_uring_f, SYS_pwritev
	sc_allow filter_worker_uring_f, SYS_fdatasync		; (the last one out)
	sc_allow filter_worker_uring_f, SYS_msync
	sc_allow filter_worker_uring_f, SYS_futex		; (wakes the cache keeper)
	sc_allow filter_worker_uring_f, SYS_io_uring_enter
	sc_allow filter_worker_uring_f, SYS_madvise
	sc_allow filter_worker_uring_f, SYS_getsockname
	sc_allow filter_worker_uring_f, SYS_clock_gettime
	sc_allow filter_worker_uring_f, SYS_getrandom
	sc_allow filter_worker_uring_f, SYS_recvmmsg
	sc_allow filter_worker_uring_f, SYS_sendmmsg
	sc_allow filter_worker_uring_f, SYS_openat2
	sc_allow filter_worker_uring_f, SYS_fstat
	sc_allow filter_worker_uring_f, SYS_lseek_
	sc_allow filter_worker_uring_f, SYS_close
	sc_allow filter_worker_uring_f, SYS_poll		; (a listening socket nobody takes from: accept_watch)
	sc_allow filter_worker_uring_f, SYS_recvfrom	; bulk: reads and writes in the loop (bulk.inc)
	sc_allow filter_worker_uring_f, SYS_sendto
	sc_allow filter_worker_uring_f, SYS_sched_setaffinity	; (pin_workers auto: pinned under load)
	sc_end filter_worker_uring_f

	sc_begin filter_worker_epoll_f
	sc_common filter_worker_epoll_f
	sc_allow filter_worker_epoll_f, SYS_sendfile
	sc_allow filter_worker_epoll_f, SYS_pread64		; cache_disk: a head read, a record written
	sc_allow filter_worker_epoll_f, SYS_pwritev
	sc_allow filter_worker_epoll_f, SYS_fdatasync		; (the last one out)
	sc_allow filter_worker_epoll_f, SYS_msync
	sc_allow filter_worker_epoll_f, SYS_futex		; (wakes the cache keeper)
	sc_allow filter_worker_epoll_f, SYS_epoll_wait
	sc_allow filter_worker_epoll_f, SYS_epoll_ctl
	sc_allow filter_worker_epoll_f, SYS_read
	sc_allow filter_worker_epoll_f, SYS_accept4
	sc_allow filter_worker_epoll_f, SYS_close
	sc_check filter_worker_epoll_f, SYS_socket, socket
	sc_allow filter_worker_epoll_f, SYS_connect
	sc_allow filter_worker_epoll_f, SYS_bind		; (a pool's `source`)
	sc_allow filter_worker_epoll_f, SYS_setsockopt
	sc_allow filter_worker_epoll_f, SYS_getsockopt
	sc_allow filter_worker_epoll_f, SYS_shutdown
	sc_allow filter_worker_epoll_f, SYS_clock_gettime
	sc_allow filter_worker_epoll_f, SYS_madvise
	sc_allow filter_worker_epoll_f, SYS_getsockname
	sc_allow filter_worker_epoll_f, SYS_recvfrom
	sc_allow filter_worker_epoll_f, SYS_getrandom
	sc_allow filter_worker_epoll_f, SYS_recvmmsg
	sc_allow filter_worker_epoll_f, SYS_sendmmsg
	sc_allow filter_worker_epoll_f, SYS_recvmsg
	sc_allow filter_worker_epoll_f, SYS_openat2
	sc_allow filter_worker_epoll_f, SYS_fstat
	sc_allow filter_worker_epoll_f, SYS_lseek_
	sc_allow filter_worker_epoll_f, SYS_sched_setaffinity	; (pin_workers auto: pinned under load)
	sc_end filter_worker_epoll_f

	; control process: DNS over UDP, resolv.conf and hosts read-only
	sc_begin filter_control
	sc_common filter_control
	sc_check filter_control, SYS_openat, read_only
	sc_allow filter_control, SYS_read
	sc_allow filter_control, SYS_fstat		; `discover file`: did it change
	sc_allow filter_control, SYS_close
	sc_check filter_control, SYS_socket, socket
	sc_allow filter_control, SYS_connect
	sc_allow filter_control, SYS_setsockopt
	sc_allow filter_control, SYS_getrandom
	sc_allow filter_control, SYS_nanosleep
	sc_allow filter_control, SYS_clock_gettime
	sc_end filter_control

	; health process: check connections
	; the cache keeper: records read, copied kernel to kernel, a head written
	sc_begin filter_keeper
	sc_common filter_keeper
	sc_allow filter_keeper, SYS_pread64
	sc_allow filter_keeper, SYS_pwrite64
	sc_allow filter_keeper, SYS_copy_file_range
	sc_allow filter_keeper, SYS_rt_sigtimedwait	; told to go?
	sc_allow filter_keeper, SYS_futex		; asleep until a writer wakes it
	sc_allow filter_keeper, SYS_kill		; is another keeper still there (signal 0)
	sc_allow filter_keeper, SYS_clock_gettime
	sc_allow filter_keeper, SYS_fdatasync		; (the last one out)
	sc_allow filter_keeper, SYS_msync
	sc_end filter_keeper

	; vrrp: its sockets made, adverts in and out, the address over netlink
	sc_begin filter_vrrp
	sc_common filter_vrrp
	sc_allow filter_vrrp, SYS_sendto
	sc_allow filter_vrrp, SYS_recvfrom
	sc_allow filter_vrrp, SYS_recvmsg		; (IPv6: the hop limit)
	sc_allow filter_vrrp, SYS_ppoll_
	sc_allow filter_vrrp, SYS_read
	sc_allow filter_vrrp, SYS_close
	sc_allow filter_vrrp, SYS_clock_gettime
	sc_end filter_vrrp

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

	; okena-xdp: the XDP balancer's maps, each tick (xdpctl.inc)
	sc_begin filter_xdpctl
	sc_common filter_xdpctl
	sc_check filter_xdpctl, SYS_bpf, bpf_map
	sc_allow filter_xdpctl, SYS_nanosleep
	sc_allow filter_xdpctl, SYS_clock_gettime
	sc_end filter_xdpctl

	; admin process: one connection at a time on the metrics socket
	sc_begin filter_admin
	sc_common filter_admin
	sc_allow filter_admin, SYS_accept4
	sc_allow filter_admin, SYS_recvfrom		; (requests read as they come, many at once)
	sc_allow filter_admin, SYS_read
	sc_allow filter_admin, SYS_close
	sc_allow filter_admin, SYS_setsockopt
	sc_allow filter_admin, SYS_getsockopt
	sc_allow filter_admin, SYS_ppoll_
	sc_allow filter_admin, SYS_clock_gettime	; (`top`: a sample a second)
	sc_check filter_admin, SYS_socket, socket	; `bird`: its control socket (bird.inc)
	sc_allow filter_admin, SYS_connect
	sc_end filter_admin

	; logger: access log lines from the pipe to their files
	sc_begin filter_logger
	sc_common filter_logger
	sc_allow filter_logger, SYS_read
	sc_allow filter_logger, SYS_close
	sc_check filter_logger, SYS_openat, append_only
	sc_allow filter_logger, SYS_epoll_wait
	; syslog and OTLP: connections, names resolved, TLS
	sc_check filter_logger, SYS_socket, socket
	sc_allow filter_logger, SYS_connect
	sc_allow filter_logger, SYS_setsockopt
	sc_allow filter_logger, SYS_recvfrom
	sc_allow filter_logger, SYS_getrandom
	sc_allow filter_logger, SYS_clock_gettime
	sc_end filter_logger

	; reload compiler: parses bytes already in memory, prints, exits
	sc_begin filter_compiler
	sc_common filter_compiler
	sc_check filter_compiler, SYS_mmap, no_exec
	sc_allow filter_compiler, SYS_madvise
	sc_check filter_compiler, SYS_openat, read_only	; certificates and keys
	sc_allow filter_compiler, 217			; getdents64: `include "DIR/*.conf"`
	sc_allow filter_compiler, SYS_read
	sc_allow filter_compiler, SYS_fstat
	sc_allow filter_compiler, SYS_close
	sc_check filter_compiler, SYS_socket, socket		; the kTLS probe
	sc_allow filter_compiler, SYS_setsockopt
	sc_allow filter_compiler, SYS_getrandom		; acme: a key until the CA's certificate comes
	sc_allow filter_compiler, SYS_clock_gettime	; (and its certificate's validity, from now)
	sc_end filter_compiler

	; ocsp: the responders asked over HTTP (names resolved), nothing written
	sc_begin filter_ocsp
	sc_common filter_ocsp
	sc_check filter_ocsp, SYS_openat, read_only
	sc_allow filter_ocsp, SYS_read
	sc_allow filter_ocsp, SYS_fstat
	sc_allow filter_ocsp, SYS_close
	sc_check filter_ocsp, SYS_socket, socket
	sc_allow filter_ocsp, SYS_connect
	sc_allow filter_ocsp, SYS_setsockopt
	sc_allow filter_ocsp, SYS_getrandom
	sc_allow filter_ocsp, SYS_nanosleep
	sc_allow filter_ocsp, SYS_clock_gettime
	sc_allow filter_ocsp, SYS_futex		; the acme process woken (revoked)
	sc_end filter_ocsp

	; gateway: the API server asked over HTTPS, its directory written
	sc_begin filter_gateway
	sc_common filter_gateway
	sc_check filter_gateway, SYS_openat, append_only
	sc_allow filter_gateway, SYS_read
	sc_allow filter_gateway, SYS_close
	sc_allow filter_gateway, SYS_fstat
	sc_check filter_gateway, SYS_socket, socket
	sc_allow filter_gateway, SYS_connect
	sc_allow filter_gateway, SYS_setsockopt
	sc_allow filter_gateway, SYS_getrandom
	sc_allow filter_gateway, SYS_nanosleep
	sc_allow filter_gateway, SYS_clock_gettime
	sc_allow filter_gateway, SYS_ftruncate
	sc_allow filter_gateway, SYS_fdatasync
	sc_allow filter_gateway, SYS_rename_
	sc_end filter_gateway

	; acme: the CA asked over HTTPS, its directory written
	sc_begin filter_acme
	sc_common filter_acme
	sc_check filter_acme, SYS_openat, append_only
	sc_allow filter_acme, SYS_read
	sc_allow filter_acme, SYS_close
	sc_allow filter_acme, SYS_fstat
	sc_check filter_acme, SYS_socket, socket
	sc_allow filter_acme, SYS_connect
	sc_allow filter_acme, SYS_setsockopt
	sc_allow filter_acme, SYS_getrandom
	sc_allow filter_acme, SYS_nanosleep
	sc_allow filter_acme, SYS_clock_gettime
	sc_allow filter_acme, SYS_ftruncate
	sc_allow filter_acme, SYS_fdatasync
	sc_allow filter_acme, SYS_rename_
	sc_allow filter_acme, SYS_futex		; asleep until a revocation, or a request
	sc_allow filter_acme, SYS_mkdirat_	; (an on-demand certificate's directory)
	sc_allow filter_acme, SYS_link_		; a fleet's lock (acmefleet.inc)
	sc_allow filter_acme, SYS_unlink_
	sc_end filter_acme

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
