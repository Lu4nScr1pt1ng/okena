; The addon launcher (okena-addons): runs the addons' programs, and again when
; they exit, slower each time (100 ms doubling to 5 s; back to 100 ms after a
; run of 10 s). Forked by the supervisor before its seccomp filter, so that
; it can execve; it has no filter and no Landlock of its own, since what it
; runs would inherit them, and does nothing but fork, execve, wait and kill.
; It runs as `user` when that is set, so the addons do too.
;
; An addon gets: descriptor 3 its memfd, 4 its bell, 5... the worker slots'
; eventfds (the header says how many); OKENA_ADDON_FD=3 and
; OKENA_ADDON_NAME=name in its environment, after okena's own; its own process
; group; SIGKILL when the launcher goes (and the launcher when okena goes).
;
; At each start and each exit the launcher clears AH_READY and moves AH_EPOCH
; on: workers end the calls of a run that is over at once.

ALN_BACKOFF0	:= 100000000			; ns
ALN_BACKOFF_MAX	:= 5000000000
ALN_STEADY	:= 10000000000			; a run this long resets the backoff
ALN_KILL_AFTER	:= 5000000000			; told to stop, SIGKILL after this
MAX_LN		:= 128

ALN_STATE	:= 0				; d: 0 free, 1 wanted running, 2 stopping
ALN_ID		:= 4				; d: the supervisor's entry
ALN_PID		:= 8				; d
ALN_MEMFD	:= 12				; d
ALN_BELL		:= 16				; d
ALN_ARGC		:= 20				; d
ALN_HDR		:= 24				; q: its header page
ALN_DUE		:= 32				; q: ns: start again (1), or kill (2), 0 none
ALN_BACKOFF	:= 40				; q
ALN_T0		:= 48				; q: when it started
ALN_NAME		:= 56				; 64
ALN_LEN		:= 120				; q: its memory's size
ALN_BLOB		:= 128				; ALM_BLOB_MAX
ALN_SIZE		:= ALN_BLOB + ALM_BLOB_MAX

SYS_setpgid_	:= 109
SIG_SETMASK_	:= 2
F_SETFD_	:= 2
F_DUPFD_	:= 0
MSG_CMSG_CLOEXEC_ := 0x40000000
CLOCK_MONOTONIC_ := 1

bss
	align 8
	g_ln_slots:	rb ALN_SIZE * MAX_LN
	g_ln_wake	rd AD_MAXW
	g_ln_nwake	dd ?
	g_ln_sock	dd ?
	g_ln_sigfd	dd ?
	g_ln_me		dd ?
	g_ln_tmp	rd AD_MAXW + 2
	align 8
	g_ln_now	dq ?
	g_ln_ts		rq 2
	g_ln_poll	rq 2
	g_ln_set	dq ?
	g_ln_msg	rq 7
	g_ln_iov	rq 2
	g_ln_cmsg:	rb 16 + 4 * AD_LAUNCH_FDS + 8
	g_ln_si:	rb SIGINFO_SIZE
	g_ln_argv	rq 66
	g_ln_envp	rq 1024
	g_ln_env0:	rb 32
	g_ln_env1:	rb 96
	align 8
	g_ln_lm:	rb ALM_SIZE
end bss

cstring str_cmd_launcher, '--addon-launcher',0
cstring str_proc_exe, '/proc/self/exe',0

; the supervisor's child, edi = its end of the socket pair: okena run anew as
; `okena-addons --addon-launcher FD PID USER UID GID`. Returns when it cannot.
ln_exec:
	push	rbx
	mov	ebx,edi
	mov	esi,F_SETFD_
	xor	edx,edx				; (kept across exec)
	mov	eax,SYS_fcntl
	syscall
	lea	rdi,[g_ln_env1]			; its words, one after the other
	lea	rax,[.argv0]
	mov	[g_ln_argv],rax
	lea	rax,[str_cmd_launcher]
	mov	[g_ln_argv+8],rax
	mov	eax,ebx
	lea	rcx,[g_ln_argv+16]
	call	.num
	mov	eax,[g_sup_pid]
	lea	rcx,[g_ln_argv+24]
	call	.num
	mov	eax,[g_plan_user]
	lea	rcx,[g_ln_argv+32]
	call	.num
	mov	eax,[g_plan_uid]
	lea	rcx,[g_ln_argv+40]
	call	.num
	mov	eax,[g_plan_gid]
	lea	rcx,[g_ln_argv+48]
	call	.num
	mov	qword [g_ln_argv+56],0
	lea	rdi,[str_proc_exe]
	lea	rsi,[g_ln_argv]
	mov	rdx,[g_envp]
	mov	eax,SYS_execve_
	syscall
	pop	rbx
	ret
; eax = a number, rdi = where: written there, NUL after, [rcx] = it; rdi past it
.num:
	mov	[rcx],rdi
	push	rcx
	call	fmt_u64
	pop	rcx
	mov	byte [rdi],0
	inc	rdi
	ret
.argv0	db 'okena-addons',0

; okena-addons --addon-launcher FD PID USER UID GID (ln_exec)
launcher_exec_main:
	mov	rax,[g_argc]
	cmp	rax,7
	jb	.bad
	mov	rbx,[g_argv]
	mov	rdi,[rbx+16]
	call	.dec
	mov	r12d,eax
	mov	rdi,[rbx+24]
	call	.dec
	mov	[g_sup_pid],eax
	mov	rdi,[rbx+32]
	call	.dec
	mov	[g_plan_user],eax
	mov	rdi,[rbx+40]
	call	.dec
	mov	[g_plan_uid],eax
	mov	rdi,[rbx+48]
	call	.dec
	mov	[g_plan_gid],eax
	mov	edi,r12d
	jmp	launcher_main
.bad:
	mov	edi,EXIT_FAILURE
	jmp	exit_process
; rdi = a C string of digits: eax
.dec:
	xor	eax,eax
@@:
	movzx	ecx,byte [rdi]
	sub	ecx,'0'
	cmp	ecx,9
	ja	@f
	imul	eax,eax,10
	add	eax,ecx
	inc	rdi
	jmp	@b
@@:
	ret

; Never returns. edi = its end of the socket pair.
launcher_main:
	mov	[g_ln_sock],edi
	mov	dword [g_is_worker],0
	mov	edi,PR_SET_PDEATHSIG
	mov	esi,SIGKILL
	mov	eax,SYS_prctl
	syscall
	mov	eax,SYS_getppid
	syscall
	cmp	eax,[g_sup_pid]
	je	@f
	xor	edi,edi
	jmp	exit_process
@@:
	mov	edi,PR_SET_NAME
	lea	rsi,[launcher_name]
	mov	eax,SYS_prctl
	syscall
	; nothing of the supervisor's but its socket and the standard three
	mov	edi,3
	mov	esi,[g_ln_sock]
	dec	esi
	cmp	esi,edi
	jb	@f
	xor	edx,edx
	mov	eax,SYS_close_range
	syscall
@@:
	mov	edi,[g_ln_sock]
	inc	edi
	mov	esi,-1
	xor	edx,edx
	mov	eax,SYS_close_range
	syscall
	; its children and its end come through a signalfd (all blocked already)
	mov	qword [g_ln_set],(1 shl (SIGCHLD-1)) or (1 shl (SIGTERM-1)) or (1 shl (SIGINT-1))
	mov	edi,-1
	lea	rsi,[g_ln_set]
	mov	edx,8
	mov	r10d,SFD_CLOEXEC
	mov	eax,SYS_signalfd4
	syscall
	test	eax,eax
	js	ln_leave
	mov	[g_ln_sigfd],eax
	mov	eax,SYS_getpid
	syscall
	mov	[g_ln_me],eax
	call	priv_drop
.loop:
	call	ln_clock
	; until the next thing due
	mov	rax,-1
	xor	ecx,ecx
.earliest:
	imul	rdx,rcx,ALN_SIZE
	mov	rdx,[g_ln_slots+rdx+ALN_DUE]
	test	rdx,rdx
	jz	@f
	cmp	rdx,rax
	jae	@f
	mov	rax,rdx
@@:
	inc	ecx
	cmp	ecx,MAX_LN
	jb	.earliest
	xor	r12d,r12d			; no timeout
	cmp	rax,-1
	je	.wait
	sub	rax,[g_ln_now]
	jns	@f
	xor	eax,eax
@@:
	xor	edx,edx
	mov	ecx,1000000000
	div	rcx
	mov	[g_ln_ts],rax
	mov	[g_ln_ts+8],rdx
	lea	r12,[g_ln_ts]
.wait:
	mov	eax,[g_ln_sock]
	mov	dword [g_ln_poll],eax
	mov	dword [g_ln_poll+4],POLLIN_
	mov	eax,[g_ln_sigfd]
	mov	dword [g_ln_poll+8],eax
	mov	dword [g_ln_poll+12],POLLIN_
	lea	rdi,[g_ln_poll]
	mov	esi,2
	mov	rdx,r12				; the timeout, or none
	xor	r10d,r10d
	mov	r8d,8
	mov	eax,SYS_ppoll_
	syscall
	cmp	rax,-EINTR
	je	.loop
	test	rax,rax
	js	ln_leave
	call	ln_clock
	movzx	eax,word [g_ln_poll+14]
	test	eax,eax
	jz	@f
	call	ln_signal
@@:
	movzx	eax,word [g_ln_poll+6]
	test	eax,eax
	jz	@f
	call	ln_receive
@@:
	call	ln_due
	jmp	.loop

ln_clock:
	mov	edi,CLOCK_MONOTONIC_
	lea	rsi,[g_ln_ts]
	mov	eax,SYS_clock_gettime
	syscall
	mov	rax,[g_ln_ts]
	imul	rax,rax,1000000000
	add	rax,[g_ln_ts+8]
	mov	[g_ln_now],rax
	ret

; a message from the supervisor; none (it went): leave
ln_receive:
	lea	rax,[g_ln_lm]
	mov	[g_ln_iov],rax
	mov	qword [g_ln_iov+8],ALM_SIZE
	xor	eax,eax
	mov	[g_ln_msg],rax
	mov	[g_ln_msg+8],rax
	lea	rcx,[g_ln_iov]
	mov	[g_ln_msg+16],rcx
	mov	qword [g_ln_msg+24],1
	lea	rcx,[g_ln_cmsg]
	mov	[g_ln_msg+32],rcx
	mov	qword [g_ln_msg+40],16 + 4 * AD_LAUNCH_FDS + 8
	mov	[g_ln_msg+48],rax
	mov	qword [g_ln_cmsg],0
	mov	edi,[g_ln_sock]
	lea	rsi,[g_ln_msg]
	mov	edx,MSG_CMSG_CLOEXEC_
	mov	eax,SYS_recvmsg_
	syscall
	cmp	rax,-EINTR
	je	.out
	test	rax,rax
	jle	ln_leave
	; the descriptors, if any
	xor	ecx,ecx
	cmp	qword [g_ln_msg+40],16
	jb	@f
	mov	rcx,[g_ln_cmsg]
	sub	rcx,16
	shr	rcx,2
@@:
	mov	eax,[g_ln_lm+ALM_OP]
	cmp	eax,ALMO_WAKE
	je	.wake
	cmp	eax,ALMO_START
	je	.start
	cmp	eax,ALMO_STOP
	je	.stop
.out:
	ret
.wake:
	mov	edx,[g_ln_lm+ALM_FIRST]
	lea	rax,[rdx+rcx]
	cmp	eax,AD_MAXW
	ja	.out
	lea	rsi,[g_ln_cmsg+16]
	lea	rdi,[g_ln_wake+rdx*4]
	mov	r8d,ecx
	rep	movsd
	lea	eax,[rdx+r8]
	cmp	eax,[g_ln_nwake]
	jb	.out
	mov	[g_ln_nwake],eax
	ret
.start:
	cmp	ecx,2
	jb	.out
	xor	edx,edx
.free:
	imul	rax,rdx,ALN_SIZE
	cmp	dword [g_ln_slots+rax+ALN_STATE],0
	je	.take
	inc	edx
	cmp	edx,MAX_LN
	jb	.free
	ret
.take:
	push	rbx
	lea	rbx,[g_ln_slots+rax]
	mov	eax,[g_ln_cmsg+16]
	mov	[rbx+ALN_MEMFD],eax
	mov	eax,[g_ln_cmsg+20]
	mov	[rbx+ALN_BELL],eax
	mov	eax,[g_ln_lm+ALM_ID]
	mov	[rbx+ALN_ID],eax
	mov	eax,[g_ln_lm+ALM_ARGC]
	cmp	eax,64
	jbe	@f
	mov	eax,64
@@:
	mov	[rbx+ALN_ARGC],eax
	lea	rdi,[rbx+ALN_NAME]
	lea	rsi,[g_ln_lm+ALM_NAME]
	mov	ecx,64
	rep	movsb
	mov	byte [rbx+ALN_NAME+63],0
	lea	rdi,[rbx+ALN_BLOB]
	lea	rsi,[g_ln_lm+ALM_BLOB]
	mov	ecx,ALM_BLOB_MAX
	rep	movsb
	mov	byte [rbx+ALN_BLOB+ALM_BLOB_MAX-1],0
	; its memory: the header, to say when it starts and ends, and the rings,
	; to drop the calls a run that crashed left (the next would take them)
	sub	rsp,144
	mov	edi,[rbx+ALN_MEMFD]
	mov	rsi,rsp
	mov	eax,SYS_fstat
	syscall
	mov	rsi,[rsp+48]			; st_size
	add	rsp,144
	test	eax,eax
	js	.no_map
	mov	[rbx+ALN_LEN],rsi
	xor	edi,edi
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_NORESERVE
	mov	r8d,[rbx+ALN_MEMFD]
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.no_map
	mov	[rbx+ALN_HDR],rax
	mov	dword [rbx+ALN_STATE],1
	mov	qword [rbx+ALN_BACKOFF],ALN_BACKOFF0
	mov	dword [rbx+ALN_PID],0
	call	ln_spawn
	pop	rbx
	ret
.no_map:
	mov	edi,[rbx+ALN_MEMFD]
	mov	eax,SYS_close
	syscall
	mov	edi,[rbx+ALN_BELL]
	mov	eax,SYS_close
	syscall
	pop	rbx
	ret
.stop:
	mov	edx,[g_ln_lm+ALM_ID]
	xor	ecx,ecx
.find:
	imul	rax,rcx,ALN_SIZE
	cmp	dword [g_ln_slots+rax+ALN_STATE],1
	jne	@f
	cmp	[g_ln_slots+rax+ALN_ID],edx
	je	.found
@@:
	inc	ecx
	cmp	ecx,MAX_LN
	jb	.find
	ret
.found:
	push	rbx
	lea	rbx,[g_ln_slots+rax]
	mov	dword [rbx+ALN_STATE],2
	cmp	dword [rbx+ALN_PID],0
	jne	@f
	call	ln_free
	pop	rbx
	ret
@@:
	mov	edi,[rbx+ALN_PID]
	mov	esi,SIGTERM
	mov	eax,SYS_kill
	syscall
	mov	rax,ALN_KILL_AFTER
	add	rax,[g_ln_now]
	mov	[rbx+ALN_DUE],rax
	pop	rbx
	ret

; rbx = an entry: its program started. Keeps rbx.
ln_spawn:
	mov	qword [rbx+ALN_DUE],0
	mov	rax,[rbx+ALN_HDR]
	mov	dword [rax+ADH_READY],0
	mov	dword [rax+ADH_SLEEP],1
	lock inc dword [rax+ADH_EPOCH]
	mov	rax,[g_ln_now]
	mov	[rbx+ALN_T0],rax
	mov	eax,SYS_fork
	syscall
	test	rax,rax
	jz	ln_child
	js	.failed
	mov	[rbx+ALN_PID],eax
	mov	rcx,[rbx+ALN_HDR]
	mov	[rcx+ADH_PID],eax
	ret
.failed:
	; tried again as after an exit
	mov	rax,[g_ln_now]
	add	rax,[rbx+ALN_BACKOFF]
	mov	[rbx+ALN_DUE],rax
	ret

; the child: rbx = its entry. Never returns.
ln_child:
	xor	edi,edi
	xor	esi,esi
	mov	eax,SYS_setpgid_
	syscall
	mov	edi,PR_SET_PDEATHSIG
	mov	esi,SIGKILL
	mov	eax,SYS_prctl
	syscall
	mov	eax,SYS_getppid
	syscall
	cmp	eax,[g_ln_me]
	jne	.quit
	; signals as a new program expects them
	mov	qword [g_ln_set],0
	mov	edi,SIG_SETMASK_
	lea	rsi,[g_ln_set]
	xor	edx,edx
	mov	r10d,8
	mov	eax,SYS_rt_sigprocmask
	syscall
	sub	rsp,32
	xor	eax,eax
	mov	[rsp],rax			; SIG_DFL
	mov	[rsp+8],rax
	mov	[rsp+16],rax
	mov	[rsp+24],rax
	mov	edi,SIGPIPE
	mov	rsi,rsp
	xor	edx,edx
	mov	r10d,8
	mov	eax,SYS_rt_sigaction
	syscall
	add	rsp,32
	; its descriptors at 3, 4, 5...: first all of them past where they go, then
	; each in its place, then nothing else
	mov	eax,[rbx+ALN_MEMFD]
	mov	[g_ln_tmp],eax
	mov	eax,[rbx+ALN_BELL]
	mov	[g_ln_tmp+4],eax
	lea	rdi,[g_ln_tmp+8]
	lea	rsi,[g_ln_wake]
	mov	ecx,[g_ln_nwake]
	rep	movsd
	mov	r12d,[g_ln_nwake]
	add	r12d,2				; how many
	lea	r13d,[r12+3]			; past where they go
	xor	r14d,r14d
.high:
	cmp	r14d,r12d
	jae	.place
	mov	edi,[g_ln_tmp+r14*4]
	mov	esi,F_DUPFD_
	mov	edx,r13d
	mov	eax,SYS_fcntl
	syscall
	test	eax,eax
	js	.quit
	mov	[g_ln_tmp+r14*4],eax
	inc	r14d
	jmp	.high
.place:
	xor	r14d,r14d
.low:
	cmp	r14d,r12d
	jae	.closed
	mov	edi,[g_ln_tmp+r14*4]
	lea	esi,[r14+3]
	xor	edx,edx
	mov	eax,SYS_dup3
	syscall
	test	eax,eax
	js	.quit
	inc	r14d
	jmp	.low
.closed:
	mov	edi,r13d
	mov	esi,-1
	xor	edx,edx
	mov	eax,SYS_close_range
	syscall
	; its words
	lea	rsi,[rbx+ALN_BLOB]
	lea	rdi,[g_ln_argv]
	mov	ecx,[rbx+ALN_ARGC]
.arg:
	test	ecx,ecx
	jz	.args
	mov	[rdi],rsi
	add	rdi,8
@@:
	lodsb
	test	al,al
	jnz	@b
	dec	ecx
	jmp	.arg
.args:
	mov	qword [rdi],0
	; its environment: okena's, then where its memory is and its name
	lea	rdi,[g_ln_env0]
	lea	rsi,[.fd]
	mov	ecx,.fd_len
	rep	movsb
	lea	rdi,[g_ln_env1]
	lea	rsi,[.name]
	mov	ecx,.name_len
	rep	movsb
	lea	rsi,[rbx+ALN_NAME]
@@:
	lodsb
	stosb
	test	al,al
	jnz	@b
	lea	rdi,[g_ln_envp]
	lea	rax,[g_ln_env0]
	mov	[rdi],rax
	lea	rax,[g_ln_env1]
	mov	[rdi+8],rax
	add	rdi,16
	mov	rsi,[g_envp]
	mov	ecx,1020
.env:
	test	rsi,rsi
	jz	.env_done
	mov	rax,[rsi]
	test	rax,rax
	jz	.env_done
	cmp	dword [rax],'OKEN'		; (ours above: not twice)
	jne	@f
	cmp	dword [rax+4],'A_AD'
	je	.env_skip
@@:
	mov	[rdi],rax
	add	rdi,8
	dec	ecx
	jz	.env_done
.env_skip:
	add	rsi,8
	jmp	.env
.env_done:
	mov	qword [rdi],0
	mov	rdi,[g_ln_argv]
	lea	rsi,[g_ln_argv]
	lea	rdx,[g_ln_envp]
	mov	eax,SYS_execve_
	syscall
	push	rax
	call	log_begin
	out_lit 'addon '
	lea	rsi,[rbx+ALN_NAME]
	call	out_cstr
	out_lit ': cannot run '
	mov	rsi,[g_ln_argv]
	call	out_cstr
	out_lit ' (errno '
	pop	rax
	neg	rax
	call	out_u64
	out_lit ')'
	call	log_end
.quit:
	mov	edi,127
	jmp	exit_process
.fd	db 'OKENA_ADDON_FD=3',0
.fd_len = $ - .fd
.name	db 'OKENA_ADDON_NAME='
.name_len = $ - .name

; children gone, or the end asked
ln_signal:
	mov	edi,[g_ln_sigfd]
	lea	rsi,[g_ln_si]
	mov	edx,SIGINFO_SIZE
	xor	eax,eax
	syscall
	test	rax,rax
	jle	.out
	mov	eax,[g_ln_si]
	cmp	eax,SIGCHLD
	je	ln_reap
	jmp	ln_leave
.out:
	ret

ln_reap:
	push	rbx
.next:
	lea	rdi,[g_ln_si]
	xor	eax,eax
	mov	ecx,SIGINFO_SIZE/8
	rep	stosq
	mov	edi,P_ALL
	xor	esi,esi
	lea	rdx,[g_ln_si]
	mov	r10d,WEXITED or WNOHANG
	xor	r8d,r8d
	mov	eax,SYS_waitid
	syscall
	test	rax,rax
	js	.done
	mov	eax,[g_ln_si+SI_PID]
	test	eax,eax
	jz	.done
	xor	ecx,ecx
.find:
	imul	rbx,rcx,ALN_SIZE
	lea	rbx,[g_ln_slots+rbx]
	cmp	dword [rbx+ALN_STATE],0
	je	@f
	cmp	[rbx+ALN_PID],eax
	je	.found
@@:
	inc	ecx
	cmp	ecx,MAX_LN
	jb	.find
	jmp	.next
.found:
	mov	dword [rbx+ALN_PID],0
	mov	qword [rbx+ALN_DUE],0
	mov	rax,[rbx+ALN_HDR]
	mov	dword [rax+ADH_READY],0
	mov	dword [rax+ADH_PID],0
	lock inc dword [rax+ADH_EPOCH]
	call	ln_skip_calls
	call	ln_wake_all			; (their calls end now, not at their time)
	cmp	dword [rbx+ALN_STATE],2
	jne	.again
	call	ln_free
	jmp	.next
.again:
	; slower each time, unless it ran a while
	mov	rax,[g_ln_now]
	sub	rax,[rbx+ALN_T0]
	mov	rcx,ALN_STEADY
	cmp	rax,rcx
	jb	@f
	mov	qword [rbx+ALN_BACKOFF],ALN_BACKOFF0
@@:
	call	log_begin
	out_lit 'addon '
	lea	rsi,[rbx+ALN_NAME]
	call	out_cstr
	cmp	dword [g_ln_si+SI_CODE],CLD_EXITED
	jne	.killed
	out_lit ' exited with status '
	jmp	.how
.killed:
	out_lit ' was killed by signal '
.how:
	mov	eax,[g_ln_si+SI_STATUS]
	call	out_u64
	out_lit ', starting it again in '
	mov	rax,[rbx+ALN_BACKOFF]
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	call	out_u64
	out_lit ' ms'
	call	log_end
	mov	rax,[g_ln_now]
	add	rax,[rbx+ALN_BACKOFF]
	mov	[rbx+ALN_DUE],rax
	mov	rax,[rbx+ALN_BACKOFF]
	add	rax,rax
	mov	rcx,ALN_BACKOFF_MAX
	cmp	rax,rcx
	jbe	@f
	mov	rax,rcx
@@:
	mov	[rbx+ALN_BACKOFF],rax
	jmp	.next
.done:
	pop	rbx
	ret

; rbx = an entry whose program exited: the calls it left are dropped (their
; requests followed on_error already). Nobody reads them meanwhile: it is gone,
; and workers post no call until the next run says it is ready.
ln_skip_calls:
	mov	rdx,[rbx+ALN_HDR]
	mov	r8,[rdx+ADH_STRIDE]
	mov	ecx,[rdx+ADH_NRINGS]
	lea	rdx,[rdx+AD_HDR]
.ring:
	test	ecx,ecx
	jz	.done
	mov	rax,[rdx+ADR_HEAD]
	mov	[rdx+ADR_TAIL],rax
	add	rdx,r8
	dec	ecx
	jmp	.ring
.done:
	ret

; every worker slot's eventfd written: workers look at the addons now
ln_wake_all:
	push	rbx
	xor	ebx,ebx
.each:
	cmp	ebx,[g_ln_nwake]
	jae	.done
	mov	edi,[g_ln_wake+rbx*4]
	mov	qword [g_ln_ts],1
	lea	rsi,[g_ln_ts]
	mov	edx,8
	mov	eax,SYS_write
	syscall
	inc	ebx
	jmp	.each
.done:
	pop	rbx
	ret

; what is due: a start again, or a stop that took too long
ln_due:
	push	rbx
	xor	ecx,ecx
.each:
	imul	rbx,rcx,ALN_SIZE
	lea	rbx,[g_ln_slots+rbx]
	mov	rax,[rbx+ALN_DUE]
	test	rax,rax
	jz	.next
	cmp	rax,[g_ln_now]
	ja	.next
	push	rcx
	mov	qword [rbx+ALN_DUE],0
	cmp	dword [rbx+ALN_STATE],1
	jne	.kill
	cmp	dword [rbx+ALN_PID],0
	jne	@f
	call	ln_spawn
	jmp	@f
.kill:
	mov	edi,[rbx+ALN_PID]
	test	edi,edi
	jz	@f
	mov	esi,SIGKILL
	mov	eax,SYS_kill
	syscall
@@:
	pop	rcx
.next:
	inc	ecx
	cmp	ecx,MAX_LN
	jb	.each
	pop	rbx
	ret

; rbx = an entry stopped: what it held given back
ln_free:
	mov	rdi,[rbx+ALN_HDR]
	mov	rsi,[rbx+ALN_LEN]
	mov	eax,SYS_munmap_
	syscall
	mov	edi,[rbx+ALN_MEMFD]
	mov	eax,SYS_close
	syscall
	mov	edi,[rbx+ALN_BELL]
	mov	eax,SYS_close
	syscall
	mov	dword [rbx+ALN_STATE],0
	mov	qword [rbx+ALN_DUE],0
	ret

; the supervisor went, or okena stops: the addons are told, then killed
; after a while; then the launcher goes
ln_leave:
	xor	ecx,ecx
.term:
	imul	rax,rcx,ALN_SIZE
	mov	edi,[g_ln_slots+rax+ALN_PID]
	test	edi,edi
	jz	@f
	push	rcx
	mov	esi,SIGTERM
	mov	eax,SYS_kill
	syscall
	pop	rcx
@@:
	inc	ecx
	cmp	ecx,MAX_LN
	jb	.term
	mov	ebx,200				; 2 s, 10 ms at a time
.wait:
	call	ln_clock
	call	ln_reap_quiet
	test	eax,eax
	jz	.gone
	lea	rdi,[.tick]
	xor	esi,esi
	mov	eax,SYS_nanosleep
	syscall
	dec	ebx
	jnz	.wait
	xor	ecx,ecx
.kill:
	imul	rax,rcx,ALN_SIZE
	mov	edi,[g_ln_slots+rax+ALN_PID]
	test	edi,edi
	jz	@f
	push	rcx
	mov	esi,SIGKILL
	mov	eax,SYS_kill
	syscall
	pop	rcx
@@:
	inc	ecx
	cmp	ecx,MAX_LN
	jb	.kill
.gone:
	xor	edi,edi
	jmp	exit_process
.tick	dq 0, 10000000

; leaving: children reaped, none started again. eax = how many are left.
ln_reap_quiet:
.next:
	lea	rdi,[g_ln_si]
	xor	eax,eax
	mov	ecx,SIGINFO_SIZE/8
	rep	stosq
	mov	edi,P_ALL
	xor	esi,esi
	lea	rdx,[g_ln_si]
	mov	r10d,WEXITED or WNOHANG
	xor	r8d,r8d
	mov	eax,SYS_waitid
	syscall
	test	rax,rax
	js	.count
	mov	eax,[g_ln_si+SI_PID]
	test	eax,eax
	jz	.count
	xor	ecx,ecx
.find:
	imul	rdx,rcx,ALN_SIZE
	cmp	[g_ln_slots+rdx+ALN_PID],eax
	jne	@f
	mov	dword [g_ln_slots+rdx+ALN_PID],0
@@:
	inc	ecx
	cmp	ecx,MAX_LN
	jb	.find
	jmp	.next
.count:
	xor	eax,eax
	xor	ecx,ecx
.c:
	imul	rdx,rcx,ALN_SIZE
	cmp	dword [g_ln_slots+rdx+ALN_PID],0
	je	@f
	inc	eax
@@:
	inc	ecx
	cmp	ecx,MAX_LN
	jb	.c
	ret
