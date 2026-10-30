; Linux x86-64 kernel ABI: syscall numbers, flags and structure layouts.
; Syscall convention: rax = number, args in rdi, rsi, rdx, r10, r8, r9;
; the kernel clobbers rcx and r11 and returns -errno in rax on failure.

SYS_read		= 0
SYS_write		= 1
SYS_close		= 3
SYS_mmap		= 9
SYS_mprotect		= 10
SYS_madvise		= 28
SYS_rt_sigaction	= 13
SYS_rt_sigprocmask	= 14
SYS_rt_sigreturn	= 15
SYS_nanosleep		= 35
SYS_getpid		= 39
SYS_socket		= 41
SYS_sendto		= 44
SYS_connect		= 42
SYS_bind		= 49
SYS_listen		= 50
SYS_socketpair		= 53
SYS_setsockopt		= 54
SYS_fork		= 57
SYS_exit		= 60
SYS_kill		= 62
SYS_getppid		= 110
SYS_setpriority		= 141
SYS_prctl		= 157
SYS_sched_setaffinity	= 203
SYS_sched_getaffinity	= 204
SYS_clock_gettime	= 228
SYS_exit_group		= 231
SYS_waitid		= 247
SYS_signalfd4		= 289
SYS_dup3		= 292
SYS_prlimit64		= 302
SYS_getrandom		= 318
SYS_io_uring_setup	= 425
SYS_io_uring_enter	= 426
SYS_io_uring_register	= 427
SYS_close_range		= 436

; errno
EINTR		:= 4
EAGAIN		:= 11
EBUSY		:= 16
ENFILE		:= 23
EMFILE		:= 24
ETIME		:= 62
ECANCELED	:= 125

; mmap / mprotect
PROT_NONE	:= 0
PROT_READ	:= 1
PROT_WRITE	:= 2
PROT_EXEC	:= 4
MAP_SHARED	:= 0x01
MAP_PRIVATE	:= 0x02
MAP_ANONYMOUS	:= 0x20
MAP_NORESERVE	:= 0x4000
MAP_POPULATE	:= 0x8000
MADV_DONTNEED	:= 4
PAGE_SIZE	:= 4096

; signals
SIGINT		:= 2
SIGKILL		:= 9
SIGPIPE		:= 13
SIGTERM		:= 15
SIGCHLD		:= 17
SIG_BLOCK	:= 0
SIG_IGN		:= 1
SFD_CLOEXEC	:= 0x80000
SIGINFO_SIZE	:= 128		; signalfd_siginfo and siginfo_t are both 128 bytes

; waitid
P_ALL		:= 0
WNOHANG		:= 1
WEXITED		:= 4
CLD_EXITED	:= 1
SI_CODE		:= 8		; siginfo_t field offsets
SI_PID		:= 16
SI_STATUS	:= 24

; prctl
PR_SET_PDEATHSIG := 1
PR_SET_DUMPABLE	 := 4
PR_SET_NAME	 := 15
PR_SET_SECCOMP	 := 22
PR_SET_NO_NEW_PRIVS := 38
SECCOMP_MODE_FILTER := 2
SECCOMP_RET_KILL_PROCESS := 0x80000000
SECCOMP_RET_ALLOW := 0x7FFF0000
AUDIT_ARCH_X86_64 := 0xC000003E
PRIO_PROCESS	 := 0

; resource limits
RLIMIT_NOFILE	:= 7

; clocks
CLOCK_REALTIME	:= 0
CLOCK_MONOTONIC	:= 1

; sockets
AF_UNIX		:= 1
AF_INET		:= 2
AF_INET6	:= 10
IPPROTO_IPV6	:= 41
IPV6_V6ONLY	:= 26
SOCK_STREAM	:= 1
SOCK_SEQPACKET	:= 5
SOCK_CLOEXEC	:= 0x80000
SOL_SOCKET	:= 1
SO_REUSEADDR	:= 2
SO_REUSEPORT	:= 15
SO_RCVTIMEO	:= 20
SO_SNDTIMEO	:= 21
SO_KEEPALIVE	:= 9
IPPROTO_TCP	:= 6
TCP_NODELAY	:= 1
TCP_DEFER_ACCEPT := 9
TCP_KEEPIDLE	:= 4
TCP_KEEPINTVL	:= 5
TCP_KEEPCNT	:= 6
TCP_USER_TIMEOUT := 18
SHUT_WR		:= 1
MSG_DONTWAIT	:= 0x40
MSG_NOSIGNAL	:= 0x4000
INADDR_LOOPBACK	:= 0x0100007F	; 127.0.0.1 in network byte order

; files
SYS_fstat	= 5
SYS_openat	= 257
AT_FDCWD	:= -100
O_RDONLY	:= 0
O_CLOEXEC	:= 0x80000
ENOENT		:= 2
EACCES		:= 13
EISDIR		:= 21
ENOMEM		:= 12
STAT_SIZE	:= 48		; st_size offset in struct stat
STAT_MODE	:= 24
STAT_BYTES	:= 144
S_IFMT		:= 0xF000
S_IFREG		:= 0x8000

; more sockets
SOCK_NONBLOCK	:= 0x800
SO_RCVBUF	:= 8
SO_SNDBUF	:= 7
TCP_FASTOPEN_CONNECT := 30
SHUT_RD		:= 0
SHUT_RDWR	:= 2
ECONNREFUSED	:= 111
ETIMEDOUT	:= 110
ENOBUFS		:= 105
ECONNRESET	:= 104
EPIPE		:= 32
EBADF		:= 9
ENOENT_	:= 2
EADDRINUSE	:= 98
EADDRNOTAVAIL	:= 99
EINVAL		:= 22
EOPNOTSUPP	:= 95
ENOSYS		:= 38
EPERM		:= 1
EALREADY	:= 114
EINPROGRESS	:= 115
SIGHUP		:= 1
SIGQUIT		:= 3
MADV_HUGEPAGE	:= 14
MADV_NOHUGEPAGE	:= 15
SYS_madvise_	= 28

; epoll engine
SYS_shutdown	= 48
SYS_getsockopt	= 55
SYS_epoll_wait	= 232
SYS_epoll_ctl	= 233
SYS_accept4	= 288
SYS_epoll_create1 = 291
EPOLL_CLOEXEC	:= 0x80000
EPOLL_CTL_ADD	:= 1
EPOLL_CTL_DEL	:= 2
EPOLLIN		:= 0x001
EPOLLOUT	:= 0x004
EPOLLERR	:= 0x008
EPOLLHUP	:= 0x010
EPOLLRDHUP	:= 0x2000
EPOLLET		:= 1 shl 31
EPOLL_EVENT	:= 12		; struct epoll_event is packed on x86-64
SO_ERROR	:= 4
SYS_setitimer	= 38
ITIMER_REAL	:= 0
SIGALRM		:= 14
SIGSTOP		:= 19
SOCK_DGRAM	:= 2
SYS_recvfrom	= 45
SYS_recvmsg	= 47
SYS_getrandom_	= 318
SIGUSR1		:= 10
O_WRONLY	:= 1
O_RDWR		:= 2
O_CREAT		:= 0x40
O_TRUNC		:= 0x200
O_APPEND	:= 0x400
SYS_getsockname	= 51
MSG_PEEK	:= 0x02

SYS_pipe2	= 293
SYS_fcntl	= 72
F_SETPIPE_SZ	:= 1031
O_NONBLOCK	:= 0x800
SFD_NONBLOCK	:= 0x800
EPROTO		:= 71
EPOLL_CTL_MOD	:= 3
ENAMETOOLONG	:= 36
