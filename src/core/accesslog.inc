; Access logs: one JSON line per HTTP exchange, written by a logger
; process so that no worker ever waits on a disk.
;
; Workers build lines in a private 4 KiB buffer and hand it over with one
; non-blocking write to a pipe the supervisor made at start (writes of at
; most PIPE_BUF bytes are atomic, so lines of different workers never mix;
; the pipe holds 1 MiB). When the pipe is full the lines are dropped and
; counted (okena_access_log_dropped_total): a slow disk costs log lines,
; never latency. Buffers go out when full and once a tick.
;
; Each line starts with its destination's number (one byte, 1 .. 32): the
; logger strips it and appends the line to that file. A reload or SIGUSR1
; makes the logger reopen its files (logrotate).

P_PID		= 1
ALOG_BUF	= 4096
LG_IN		= 1 shl 16
LG_OUT		= 1 shl 16

bss
	align 8
	g_alog_rfd	dd ?
	g_alog_wfd	dd ?
	g_logger_pid	dd ?
	g_alog_len	dd ?		; worker: bytes waiting in the buffer
	g_alog_lines	dd ?		; and how many lines they are
	g_alog_base_ns	dq ?		; wall clock at the last tick
	g_alog_base_tsc	dq ?		; and the TSC then
	g_alog_buf	rb ALOG_BUF
	g_alog_line	rb ALOG_BUF
	; logger
	g_lg_fd		rd ALOG_MAX
	g_lg_sigfd	dd ?
	g_lg_ep		dd ?
	g_lg_carry	dd ?		; bytes of an unfinished record kept in front
	g_lg_cur	dd ?		; destination of what is in OUT
	g_lg_outlen	dd ?
	g_lg_si		rb 128
	g_lg_ev		rb EPOLL_EVENT * 4
	g_lg_in		rb LG_IN
	g_lg_out	rb LG_OUT
end bss

rodata
	logger_name	db 'okena-logger',0
	str_stdout	db 'stdout',0
	str_stderr	db 'stderr',0
end rodata

; ------------------------------------------------------------ supervisor

; At start, before the filters: the pipe.
alog_pipe_init:
	sub	rsp,8
	mov	rdi,rsp
	mov	esi,O_NONBLOCK or O_CLOEXEC
	mov	eax,SYS_pipe2
	syscall
	test	eax,eax
	js	.none
	mov	eax,[rsp]
	mov	[g_alog_rfd],eax
	mov	eax,[rsp+4]
	mov	[g_alog_wfd],eax
	mov	edi,[g_alog_rfd]
	mov	esi,F_SETPIPE_SZ
	mov	edx,1 shl 20
	mov	eax,SYS_fcntl
	syscall				; best effort: 64 KiB is the default
.none:
	add	rsp,8
	ret

spawn_logger:
	cmp	dword [g_alog_count],0
	je	.none
	cmp	dword [g_logger_pid],0
	jne	.none
	mov	eax,SYS_fork
	syscall
	test	rax,rax
	jz	logger_main
	js	.none
	mov	[g_logger_pid],eax
.none:
	ret

; Reload: a new logger with the current destinations (the reaper starts
; it once the old one has written what it holds).
logger_restart:
	mov	edi,[g_logger_pid]
	test	edi,edi
	jz	spawn_logger
	mov	esi,SIGTERM
	mov	eax,SYS_kill
	syscall
	ret

; Shutdown, every worker gone: let the logger empty the pipe, wait for it.
logger_finish:
	mov	esi,[g_logger_pid]
	test	esi,esi
	jz	.done
	mov	edi,esi
	mov	esi,SIGTERM
	mov	eax,SYS_kill
	syscall
	mov	edi,P_PID
	mov	esi,[g_logger_pid]
	lea	rdx,[g_siginfo]
	mov	r10d,WEXITED
	xor	r8d,r8d
	mov	eax,SYS_waitid
	syscall
	mov	dword [g_logger_pid],0
.done:
	ret

; ---------------------------------------------------------------- logger

; Never returns.
logger_main:
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
	lea	rsi,[logger_name]
	mov	eax,SYS_prctl
	syscall
	call	logger_open_all
	; TERM and USR1 are blocked (inherited): read them from a signalfd
	sub	rsp,8
	mov	qword [rsp],(1 shl (SIGTERM-1)) or (1 shl (SIGUSR1-1))
	mov	edi,-1
	mov	rsi,rsp
	mov	edx,8
	mov	r10d,SFD_NONBLOCK or SFD_CLOEXEC
	mov	eax,SYS_signalfd4
	syscall
	add	rsp,8
	mov	[g_lg_sigfd],eax
	mov	edi,EPOLL_CLOEXEC
	mov	eax,SYS_epoll_create1
	syscall
	mov	[g_lg_ep],eax
	mov	edi,[g_alog_rfd]
	call	logger_watch
	mov	edi,[g_lg_sigfd]
	call	logger_watch
	mov	dword [g_lg_cur],0
	seccomp_for filter_logger
.loop:
	mov	edi,[g_lg_ep]
	lea	rsi,[g_lg_ev]
	mov	edx,4
	mov	r10d,-1
	mov	eax,SYS_epoll_wait
	syscall
	call	logger_drain
	mov	edi,[g_lg_sigfd]
	lea	rsi,[g_lg_si]
	mov	edx,128
	xor	eax,eax				; SYS_read
	syscall
	test	rax,rax
	jle	.loop
	cmp	dword [g_lg_si],SIGUSR1
	jne	.term
	call	logger_close_all
	call	logger_open_all
	jmp	.loop
.term:
	call	logger_drain			; what is left, then out
	xor	edi,edi
	jmp	exit_process

; edi = descriptor: readable events wake the logger.
logger_watch:
	sub	rsp,16
	mov	dword [rsp],EPOLLIN
	mov	[rsp+4],edi
	mov	edx,edi
	mov	edi,[g_lg_ep]
	mov	esi,EPOLL_CTL_ADD
	mov	r10,rsp
	mov	eax,SYS_epoll_ctl
	syscall
	add	rsp,16
	ret

logger_open_all:
	push	rbx
	xor	ebx,ebx
.next:
	cmp	ebx,[g_alog_count]
	jae	.done
	imul	rdi,rbx,ALOG_PATH
	lea	rdi,[g_alog_dest+rdi]
	mov	dword [g_lg_fd+rbx*4],1
	lea	rsi,[str_stdout]
	call	cstr_eq
	test	eax,eax
	jnz	.opened
	mov	dword [g_lg_fd+rbx*4],2
	lea	rsi,[str_stderr]
	call	cstr_eq
	test	eax,eax
	jnz	.opened
	mov	rsi,rdi
	mov	edi,AT_FDCWD
	mov	edx,O_WRONLY or O_APPEND or O_CREAT or O_CLOEXEC
	mov	r10d,0644o
	mov	eax,SYS_openat
	syscall
	mov	[g_lg_fd+rbx*4],eax
	test	eax,eax
	jns	.opened
	push	rax
	call	log_begin
	out_lit 'access log '
	imul	rsi,rbx,ALOG_PATH
	lea	rsi,[g_alog_dest+rsi]
	call	out_cstr
	out_lit ': cannot open it (errno '
	pop	rax
	neg	rax
	call	out_u64
	out_lit '); its lines are dropped'
	call	log_end
	mov	dword [g_lg_fd+rbx*4],-1
.opened:
	inc	ebx
	jmp	.next
.done:
	pop	rbx
	ret

logger_close_all:
	push	rbx
	xor	ebx,ebx
.next:
	cmp	ebx,[g_alog_count]
	jae	.done
	mov	edi,[g_lg_fd+rbx*4]
	cmp	edi,2
	jle	@f
	mov	eax,SYS_close
	syscall
@@:
	inc	ebx
	jmp	.next
.done:
	pop	rbx
	ret

; Read the pipe until it is empty; write each run of lines for one
; destination with one write.
logger_drain:
	push	rbx
	push	r12
	push	r13
.read:
	mov	edi,[g_alog_rfd]
	mov	eax,[g_lg_carry]
	lea	rsi,[g_lg_in+rax]
	mov	edx,LG_IN
	sub	edx,eax
	xor	eax,eax				; SYS_read
	syscall
	test	rax,rax
	jle	.done				; empty (EAGAIN) or no writer left
	lea	r12,[g_lg_in]			; record start
	mov	r13d,[g_lg_carry]
	add	r13,rax
	add	r13,r12				; end
.record:
	mov	rdi,r12
	mov	rcx,r13
	sub	rcx,rdi
	jz	.consumed
	mov	al,10
	repne	scasb
	jne	.partial			; no newline: the rest comes next read
	; [r12] = destination, r12+1 .. rdi = the line with its newline
	movzx	ebx,byte [r12]
	cmp	ebx,[g_lg_cur]
	je	@f
	push	rdi
	call	logger_flush
	pop	rdi
	mov	[g_lg_cur],ebx
@@:
	lea	rsi,[r12+1]
	mov	rcx,rdi
	sub	rcx,rsi
	mov	eax,[g_lg_outlen]
	add	eax,ecx
	cmp	eax,LG_OUT
	jbe	@f
	push	rdi
	push	rsi
	push	rcx
	call	logger_flush
	pop	rcx
	pop	rsi
	pop	rdi
@@:
	mov	r12,rdi				; next record
	mov	eax,[g_lg_outlen]
	lea	rdi,[g_lg_out+rax]
	add	[g_lg_outlen],ecx
	rep	movsb
	jmp	.record
.partial:
	mov	rcx,r13
	sub	rcx,r12
	mov	[g_lg_carry],ecx
	mov	rsi,r12
	lea	rdi,[g_lg_in]
	rep	movsb
	call	logger_flush
	jmp	.read
.consumed:
	mov	dword [g_lg_carry],0
	call	logger_flush
	jmp	.read
.done:
	call	logger_flush
	pop	r13
	pop	r12
	pop	rbx
	ret

; OUT to its destination's file (all of it, even in pieces).
logger_flush:
	push	rbx
	mov	ebx,[g_lg_cur]
	mov	ecx,[g_lg_outlen]
	mov	dword [g_lg_outlen],0
	test	ecx,ecx
	jz	.done
	dec	ebx
	cmp	ebx,[g_alog_count]
	jae	.done				; not a destination: dropped
	mov	edi,[g_lg_fd+rbx*4]
	test	edi,edi
	js	.done
	lea	rsi,[g_lg_out]
	mov	edx,ecx
.write:
	mov	eax,SYS_write
	push	rdi
	push	rsi
	push	rdx
	syscall
	pop	rdx
	pop	rsi
	pop	rdi
	cmp	rax,-EINTR
	je	.write
	test	rax,rax
	jle	.done				; a broken file: drop the batch
	add	rsi,rax
	sub	edx,eax
	jnz	.write
.done:
	pop	rbx
	ret

; ---------------------------------------------------------------- worker

; Tick (and before the first line): the wall clock and the TSC together,
; so a line's time costs no system call.
alog_clock:
	sub	rsp,16
	mov	edi,CLOCK_REALTIME
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	rdtsc
	shl	rdx,32
	or	rax,rdx
	mov	[g_alog_base_tsc],rax
	imul	rax,[rsp],1000000000
	add	rax,[rsp+8]
	mov	[g_alog_base_ns],rax
	add	rsp,16
	ret

alog_tick:
	call	alog_clock
	jmp	alog_flush

; The buffer to the pipe. Keeps rbx and r12-r15.
alog_flush:
	mov	edx,[g_alog_len]
	test	edx,edx
	jz	.done
	mov	edi,[g_alog_wfd]
	lea	rsi,[g_alog_buf]
	mov	eax,SYS_write
	syscall
	cmp	eax,[g_alog_len]
	je	@f
	mov	eax,[g_alog_lines]		; pipe full: these lines are lost
	add	[g_st_alog_dropped],rax
@@:
	mov	dword [g_alog_len],0
	mov	dword [g_alog_lines],0
.done:
	ret

; ebx = session: what the request was, while it is still parsed in g_hm.
alog_request:
	call	session_ptr
	mov	eax,[rax+S_LST]
	imul	rax,rax,LS_SIZE
	cmp	dword [g_listeners+rax+LS_ALOG],0
	je	.done
	push	r15
	h_rec
	rdtsc
	shl	rdx,32
	or	rax,rdx
	mov	[r15+H_LT0],rax
	lea	r8,[g_hm]
	mov	rsi,[r8+HM_METHOD]
	mov	ecx,[r8+HM_MLEN]
	mov	edx,H_LTEXT_M_CAP
	lea	rdi,[r15+H_LTEXT_M]
	call	.copy
	mov	[r15+H_LMLEN],ecx
	xor	ecx,ecx
	mov	eax,[r8+HM_HOST]
	cmp	eax,-1
	je	@f
	shl	eax,5				; HF_SIZE
	lea	rax,[r8+HM_HDRS+rax]
	mov	rsi,[rax+HF_VALUE]
	mov	ecx,[rax+HF_VLEN]
	mov	edx,H_LTEXT_H_CAP
	lea	rdi,[r15+H_LTEXT_H]
	call	.copy
@@:
	mov	[r15+H_LHLEN],ecx
	mov	rsi,[r8+HM_TARGET]
	mov	ecx,[r8+HM_TLEN]
	mov	edx,H_LTEXT_T_CAP
	lea	rdi,[r15+H_LTEXT_T]
	call	.copy
	mov	[r15+H_LTLEN],ecx
	pop	r15
.done:
	ret
; rsi/ecx = text, rdi = room of edx bytes. ecx = bytes kept.
.copy:
	cmp	ecx,edx
	jbe	@f
	mov	ecx,edx
@@:
	push	rcx
	rep	movsb
	pop	rcx
	ret

; ebx = session, esi = 0 when the backend answered, 1 when okena did:
; one line for the exchange that just ended. Keeps rbx.
alog_exchange:
	call	session_ptr
	mov	ecx,[rax+S_LST]
	imul	rcx,rcx,LS_SIZE
	mov	edx,[g_listeners+rcx+LS_ALOG]
	test	edx,edx
	jz	.none
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	lea	r14,[g_listeners+rcx]
	mov	r12d,esi
	mov	r13,rax				; the session
	h_rec
	lea	rdi,[g_alog_line]
	mov	[rdi],dl
	inc	rdi
	memit '{"time":"'
	call	alog_fmt_time
	memit '","listener":"'
	mov	rsi,[r14+LS_TEXT]
	mov	edx,[r14+LS_TLEN]
	mov	ecx,256
	call	json_text
	memit '","client":"'
	call	peer_ptr
	push	rdi
	lea	rdi,[g_ip_a]
	lea	rsi,[rax+P_PEER]
	call	peer_normalize
	pop	rdi
	push	rax
	lea	rsi,[g_ip_a]
	mov	edx,eax
	cmp	dword [r15+H_CKIND],0
	je	@f
	lea	rsi,[r15+H_CLIENT]		; what trusted proxies said
	mov	edx,[r15+H_CKIND]
@@:
	call	fmt_ip
	memit '","peer":"'
	pop	rdx
	lea	rsi,[g_ip_a]
	call	fmt_ip
	memit '","method":"'
	lea	rsi,[r15+H_LTEXT_M]
	mov	edx,[r15+H_LMLEN]
	mov	ecx,128
	call	json_text
	memit '","host":"'
	lea	rsi,[r15+H_LTEXT_H]
	mov	edx,[r15+H_LHLEN]
	mov	ecx,768
	call	json_text
	memit '","target":"'
	lea	rsi,[r15+H_LTEXT_T]
	mov	edx,[r15+H_LTLEN]
	mov	ecx,1600
	call	json_text
	memit '","status":'
	mov	eax,[r15+H_STATUS]
	call	fmt_u64
	memit ',"bytes":'
	mov	rax,[r15+H_XBYTES]
	call	fmt_u64
	memit ',"duration_ms":'
	call	alog_fmt_duration
	memit ',"upstream":'
	test	r12d,r12d
	jnz	.no_upstream
	mov	eax,[r13+S_SERVER]
	cmp	eax,NIL
	je	.no_upstream
	imul	rax,rax,SV_SIZE
	mov	byte [rdi],'"'
	inc	rdi
	mov	rsi,[g_servers+rax+SV_TEXT]
	mov	edx,[g_servers+rax+SV_TLEN]
	mov	ecx,256
	call	json_text
	mov	byte [rdi],'"'
	inc	rdi
	jmp	.source
.no_upstream:
	memit 'null'
.source:
	test	r12d,r12d
	jnz	@f
	memit ',"source":"backend"'
	jmp	.retried
@@:
	memit ',"source":"okena"'
.retried:
	test	dword [r15+H_FLAGS],HX_RETRIED
	jz	@f
	memit ',"retried":true}',10
	jmp	.line
@@:
	memit ',"retried":false}',10
.line:
	lea	rsi,[g_alog_line]
	mov	rcx,rdi
	sub	rcx,rsi
	mov	eax,[g_alog_len]
	add	eax,ecx
	cmp	eax,ALOG_BUF
	jbe	@f
	push	rcx
	call	alog_flush
	pop	rcx
	lea	rsi,[g_alog_line]
@@:
	mov	eax,[g_alog_len]
	lea	rdi,[g_alog_buf+rax]
	add	[g_alog_len],ecx
	inc	dword [g_alog_lines]
	rep	movsb
	; this exchange is logged; the next one on the connection starts clean
	mov	qword [r15+H_LT0],0
	mov	qword [r15+H_XBYTES],0
	mov	dword [r15+H_LMLEN],0
	mov	dword [r15+H_LHLEN],0
	mov	dword [r15+H_LTLEN],0
	mov	dword [r15+H_CKIND],0
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
.none:
	ret

; rdi = output, rsi/edx = text, ecx = most bytes to write. JSON string
; content: " \ and control or non-ASCII bytes escaped. rdi = after it.
json_text:
	lea	r8,[rdi+rcx-6]			; room for the widest escape
	xor	ecx,ecx
.next:
	cmp	ecx,edx
	jae	.done
	cmp	rdi,r8
	jae	.done				; cut: the line stays bounded
	movzx	eax,byte [rsi+rcx]
	inc	ecx
	cmp	al,'"'
	je	.slash
	cmp	al,'\'
	je	.slash
	cmp	al,0x20
	jb	.hex
	cmp	al,0x7F
	jae	.hex
	mov	[rdi],al
	inc	rdi
	jmp	.next
.slash:
	mov	byte [rdi],'\'
	mov	[rdi+1],al
	add	rdi,2
	jmp	.next
.hex:
	mov	dword [rdi],'\u00'
	mov	r9d,eax
	shr	r9d,4
	mov	r9b,[hex_digits+r9]
	mov	[rdi+4],r9b
	and	eax,15
	mov	al,[hex_digits+rax]
	mov	[rdi+5],al
	add	rdi,6
	jmp	.next
.done:
	ret

rodata
	hex_digits	db '0123456789abcdef'
end rodata

; rdi = output, rax = value, ecx = digits (zero-padded). rdi = after it.
fmt_pad:
	add	rdi,rcx
	mov	r8,rdi
	mov	r9d,10
@@:
	xor	edx,edx
	div	r9
	add	dl,'0'
	dec	r8
	mov	[r8],dl
	dec	ecx
	jnz	@b
	ret

; rdi = output: the wall clock now, 2026-10-29T12:34:56.789Z.
alog_fmt_time:
	cmp	qword [g_alog_base_ns],0
	jne	@f
	push	rdi
	call	alog_clock
	pop	rdi
@@:
	rdtsc
	shl	rdx,32
	or	rax,rdx
	sub	rax,[g_alog_base_tsc]
	imul	rax,rax,1000
	xor	edx,edx
	div	qword [g_tsc_per_us]		; ns since the tick
	add	rax,[g_alog_base_ns]
	xor	edx,edx
	mov	ecx,1000000000
	div	rcx
	push	rdx				; ns of the second
	xor	edx,edx
	mov	ecx,86400
	div	rcx
	push	rdx				; seconds of the day
	; days since 1970-01-01 -> civil date (H. Hinnant's algorithm)
	add	rax,719468
	xor	edx,edx
	mov	ecx,146097
	div	rcx				; rax = era, rdx = day of era
	mov	r10,rax
	mov	r11,rdx				; doe
	mov	rax,r11
	xor	edx,edx
	mov	ecx,1460
	div	rcx
	mov	rsi,r11
	sub	rsi,rax
	mov	rax,r11
	xor	edx,edx
	mov	ecx,36524
	div	rcx
	add	rsi,rax
	mov	rax,r11
	xor	edx,edx
	mov	ecx,146096
	div	rcx
	sub	rsi,rax
	mov	rax,rsi
	xor	edx,edx
	mov	ecx,365
	div	rcx				; yoe
	mov	rsi,rax
	imul	r10,r10,400
	add	r10,rsi				; year (March-based)
	; doy = doe - (365 yoe + yoe/4 - yoe/100)
	imul	rax,rsi,365
	mov	rcx,rsi
	shr	rcx,2
	add	rax,rcx
	push	rax
	mov	rax,rsi
	xor	edx,edx
	mov	ecx,100
	div	rcx
	pop	rcx
	sub	rcx,rax
	mov	rax,r11
	sub	rax,rcx				; doy
	mov	r11,rax
	imul	rax,rax,5
	add	rax,2
	xor	edx,edx
	mov	ecx,153
	div	rcx				; mp
	mov	rsi,rax
	imul	rax,rax,153
	add	rax,2
	xor	edx,edx
	mov	ecx,5
	div	rcx
	sub	r11,rax
	inc	r11				; day
	lea	rax,[rsi+3]			; month
	cmp	rsi,10
	jb	@f
	sub	rax,12
@@:
	cmp	rax,2
	ja	@f
	inc	r10
@@:
	push	rax
	mov	rax,r10
	mov	ecx,4
	call	fmt_pad
	mov	byte [rdi],'-'
	inc	rdi
	pop	rax
	mov	ecx,2
	call	fmt_pad
	mov	byte [rdi],'-'
	inc	rdi
	mov	rax,r11
	mov	ecx,2
	call	fmt_pad
	mov	byte [rdi],'T'
	inc	rdi
	pop	rax				; seconds of the day
	xor	edx,edx
	mov	ecx,3600
	div	rcx
	push	rdx
	mov	ecx,2
	call	fmt_pad
	mov	byte [rdi],':'
	inc	rdi
	pop	rax
	xor	edx,edx
	mov	ecx,60
	div	rcx
	push	rdx
	mov	ecx,2
	call	fmt_pad
	mov	byte [rdi],':'
	inc	rdi
	pop	rax
	mov	ecx,2
	call	fmt_pad
	mov	byte [rdi],'.'
	inc	rdi
	pop	rax				; ns
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	mov	ecx,3
	call	fmt_pad
	mov	byte [rdi],'Z'
	inc	rdi
	ret

; rdi = output, r15 = record: milliseconds since the request head, three
; decimals.
alog_fmt_duration:
	mov	rcx,[r15+H_LT0]
	test	rcx,rcx
	jz	.zero
	rdtsc
	shl	rdx,32
	or	rax,rdx
	sub	rax,rcx
	xor	edx,edx
	div	qword [g_tsc_per_us]		; microseconds
	xor	edx,edx
	mov	ecx,1000
	div	rcx
	push	rdx
	call	fmt_u64
	mov	byte [rdi],'.'
	inc	rdi
	pop	rax
	mov	ecx,3
	jmp	fmt_pad
.zero:
	mov	dword [rdi],'0.00'
	mov	byte [rdi+4],'0'
	add	rdi,5
	ret
