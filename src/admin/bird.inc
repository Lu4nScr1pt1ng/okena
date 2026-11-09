; `okena { bird /run/bird/bird.ctl protocol=anycast [pool=NAME] }`: the anycast
; address is announced while this okena can take traffic, and withdrawn when it
; cannot, through the routing daemon's control socket: `enable PROTOCOL` and
; `disable PROTOCOL`, the protocol being BIRD's that announces the address (a
; static route exported over BGP, say).
;
; It can take traffic as /ready says: not draining (`okena drain`, a stop, an
; upgrade's old process), and, with pool=, while that pool has a server up. The
; admin process looks once a second, tells BIRD at once when that changes, and says
; it again every 5 s (a BIRD that restarted learns it), or every second while BIRD
; does not answer. A stop withdraws during the drain delay: a `drain delay=` of a
; few seconds lets the route go before the connections do.
;
; BIRD answers in lines, a code of 4 digits each, the last with a space after it;
; codes from 8000 are errors.

BIRD_AGAIN_MS	:= 5000
BIRD_RETRY_MS	:= 1000

bss
	align 8
	g_plan_bird	dq ?			; the control socket's path, 0 none
	g_plan_birdl	dd ?
	g_plan_birdpl	dd ?
	g_plan_birdp	dq ?			; the protocol
	g_plan_birdpool	dq ?			; pool=, 0 none
	g_plan_birdpooll dd ?
	g_bird_said	dd ?			; 0 nothing yet, 1 announced, 2 withdrawn
	g_bird_fail	dd ?			; the last try failed (said once)
	g_bird_next	dq ?			; ms: when to say it again
	g_bird_sa:	rb 112
	g_bird_buf:	rb 1024
end bss

; eax = 1 when this okena can take traffic
bird_ready:
	mov	rax,[g_stats_tbl]
	cmp	qword [rax+SG_OFF+SG_DRAINING],0
	jne	.no
	mov	rax,[g_api_ov]
	cmp	dword [rax+AP_DRAIN],0
	jne	.no
	cmp	qword [g_plan_birdpool],0
	je	.yes
	; that pool: a server of it up
	push	rbx
	push	r12
	xor	r12d,r12d
.pool:
	cmp	r12d,[g_plan_pools]
	jae	.none_up
	imul	rax,r12,PL_SIZE
	lea	r8,[g_pools+rax]
	inc	r12d
	mov	ecx,[r8+PL_NLEN]
	cmp	ecx,[g_plan_birdpooll]
	jne	.pool
	mov	rsi,[r8+PL_NAME]
	mov	rdi,[g_plan_birdpool]
	repe	cmpsb
	jne	.pool
	mov	ebx,[r8+PL_FIRST]
	mov	ecx,[r8+PL_COUNT]
	add	ecx,ebx
.server:
	cmp	ebx,ecx
	jae	.none_up
	push	rcx
	call	top_state
	pop	rcx
	inc	ebx
	test	eax,eax
	jnz	.server
	pop	r12
	pop	rbx
.yes:
	mov	eax,1
	ret
.none_up:
	pop	r12
	pop	rbx
.no:
	xor	eax,eax
	ret

; the admin process, every turn of its loop
bird_tick:
	cmp	qword [g_plan_bird],0
	je	.none
	push	rbx
	sub	rsp,16
	mov	edi,CLOCK_MONOTONIC
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	imul	rbx,[rsp],1000
	mov	rax,[rsp+8]
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	add	rbx,rax				; ms
	add	rsp,16
	call	bird_ready
	mov	ecx,2
	sub	ecx,eax				; 1 announce, 2 withdraw
	cmp	ecx,[g_bird_said]
	jne	.tell
	cmp	rbx,[g_bird_next]
	jb	.out
.tell:
	push	rcx
	call	bird_say
	pop	rcx
	jc	.failed
	cmp	ecx,[g_bird_said]
	je	@f
	push	rcx
	call	log_begin
	out_lit 'bird: '
	mov	rsi,[g_plan_birdp]
	mov	edx,[g_plan_birdpl]
	call	out_str
	pop	rcx
	push	rcx
	cmp	ecx,1
	jne	.withdrawn
	out_lit ' enabled: the address is announced'
	jmp	.said
.withdrawn:
	out_lit ' disabled: the address is withdrawn'
.said:
	call	log_end
	pop	rcx
@@:
	mov	[g_bird_said],ecx
	mov	dword [g_bird_fail],0
	lea	rax,[rbx+BIRD_AGAIN_MS]
	mov	[g_bird_next],rax
	jmp	.out
.failed:
	lea	rax,[rbx+BIRD_RETRY_MS]
	mov	[g_bird_next],rax
	mov	dword [g_bird_said],0		; (not known: said again at once when it answers)
	cmp	dword [g_bird_fail],0
	jne	.out
	mov	dword [g_bird_fail],1
	call	log_begin
	out_lit 'bird: the control socket did not take `'
	mov	rsi,[g_plan_birdp]
	mov	edx,[g_plan_birdpl]
	call	out_str
	out_lit '` (not there, or an error): trying again every second'
	call	log_end
.out:
	pop	rbx
.none:
	ret

; ecx = 1 enable, 2 disable: told to BIRD. CF: it did not take it.
bird_say:
	push	r12
	push	r13
	mov	r13d,ecx
	mov	edi,AF_UNIX
	mov	esi,SOCK_STREAM or SOCK_CLOEXEC
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	.fail_nofd
	mov	r12d,eax
	mov	edi,eax
	mov	esi,SOL_SOCKET
	mov	edx,SO_RCVTIMEO
	lea	r10,[ts_admin_io]
	mov	r8d,16
	mov	eax,SYS_setsockopt
	syscall
	mov	word [g_bird_sa],AF_UNIX
	lea	rdi,[g_bird_sa+2]
	mov	rsi,[g_plan_bird]
	mov	ecx,[g_plan_birdl]
	rep	movsb
	mov	byte [rdi],0
	mov	edi,r12d
	lea	rsi,[g_bird_sa]
	mov	edx,[g_plan_birdl]
	add	edx,3
	mov	eax,SYS_connect
	syscall
	test	eax,eax
	js	.fail
	call	.answer				; its greeting
	jc	.fail
	; the command
	lea	rdi,[g_bird_buf]
	lea	rsi,[.enable]
	cmp	r13d,1
	je	@f
	lea	rsi,[.disable]
@@:
	lodsb
	test	al,al
	jz	@f
	stosb
	jmp	@b
@@:
	mov	rsi,[g_plan_birdp]
	mov	ecx,[g_plan_birdpl]
	rep	movsb
	mov	byte [rdi],10
	inc	rdi
	lea	rsi,[g_bird_buf]
	mov	rdx,rdi
	sub	rdx,rsi
	mov	edi,r12d
	call	write_all
	call	.answer
	jc	.fail
	mov	edi,r12d
	mov	eax,SYS_close
	syscall
	clc
	jmp	.out
.fail:
	mov	edi,r12d
	mov	eax,SYS_close
	syscall
.fail_nofd:
	stc
.out:
	pop	r13
	pop	r12
	ret
; read up to a line whose code has a space after it: CF when a code was an error
; (8000 and up) or nothing came. Keeps r12, r13.
.answer:
	push	rbx
	xor	ebx,ebx				; bytes
	xor	r8d,r8d				; an error seen
.more:
	cmp	ebx,1000
	jae	.bad
	mov	edi,r12d
	lea	rsi,[g_bird_buf+rbx]
	mov	edx,1000
	sub	edx,ebx
	xor	eax,eax				; read
	push	r8
	syscall
	pop	r8
	test	rax,rax
	jle	.bad
	add	ebx,eax
	; each whole line: its code
	xor	ecx,ecx				; the line's start
.line:
	mov	edx,ecx
@@:
	cmp	edx,ebx
	jae	.partial
	cmp	byte [g_bird_buf+rdx],10
	je	@f
	inc	edx
	jmp	@b
@@:
	lea	eax,[rcx+5]
	cmp	eax,edx
	ja	.next_line			; (shorter than a code)
	cmp	byte [g_bird_buf+rcx],'8'
	jb	@f
	mov	r8d,1				; 8xxx, 9xxx: an error
@@:
	cmp	byte [g_bird_buf+rcx+4],' '
	je	.last
.next_line:
	lea	ecx,[rdx+1]
	jmp	.line
.partial:
	; what is left is a part of a line: to the front, and read on
	mov	edx,ebx
	sub	edx,ecx
	lea	rsi,[g_bird_buf+rcx]
	lea	rdi,[g_bird_buf]
	push	rcx
	mov	ecx,edx
	rep	movsb
	pop	rcx
	sub	ebx,ecx
	jmp	.more
.last:
	pop	rbx
	cmp	r8d,1
	cmc					; CF when an error was seen
	ret
.bad:
	pop	rbx
	stc
	ret
.enable		db 'enable ',0
.disable	db 'disable ',0

; okena { bird PATH protocol=NAME [pool=NAME] }, rbx = the node
compile_bird:
	mov	rax,[rbx+N_ARGS]
	mov	rcx,[rax+A_VAL]
	mov	edx,[rax+A_VLEN]
	test	edx,edx
	jz	.bad
	cmp	edx,100
	ja	.bad
	cmp	byte [rcx],'/'
	jne	.bad
	mov	[g_plan_bird],rcx
	mov	[g_plan_birdl],edx
	mov	rdi,rbx
	cstring .k_proto, 'protocol',0
	lea	rsi,[.k_proto]
	call	node_option
	test	rax,rax
	jz	.bad
	mov	rcx,[rax+A_VAL]
	mov	edx,[rax+A_VLEN]
	test	edx,edx
	jz	.bad
	cmp	edx,64
	ja	.bad
	xor	esi,esi				; a name: letters, digits, _ and -
@@:
	movzx	eax,byte [rcx+rsi]
	cmp	al,'_'
	je	.ch
	cmp	al,'-'
	je	.ch
	cmp	al,'0'
	jb	.bad
	cmp	al,'9'
	jbe	.ch
	or	al,0x20
	cmp	al,'a'
	jb	.bad
	cmp	al,'z'
	ja	.bad
.ch:
	inc	esi
	cmp	esi,edx
	jb	@b
	mov	[g_plan_birdp],rcx
	mov	[g_plan_birdpl],edx
	mov	rdi,rbx
	cstring .k_pool, 'pool',0
	lea	rsi,[.k_pool]
	call	node_option
	test	rax,rax
	jz	.ok
	mov	rcx,[rax+A_VAL]
	mov	[g_plan_birdpool],rcx
	mov	ecx,[rax+A_VLEN]
	mov	[g_plan_birdpooll],ecx
.ok:
	ret
.bad:
	call	log_begin
	out_lit 'bird takes the control socket''s whole path (100 bytes at most), protocol=NAME (BIRD''s, that announces the address) and, if wanted, pool=NAME (a server of it up)'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
