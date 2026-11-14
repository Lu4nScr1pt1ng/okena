; Access logs on tcp and udp listeners: one JSON line per connection (when it
; closes) or per flow (when it ends), through the same logger as HTTP's:
;   {"time":..., "listener":..., "proto":"tcp", "client":..., "client_port":...,
;    "upstream":..., "bytes_in":..., "bytes_out":..., "duration_ms":...}
; A connection refused before it reached a backend (allow/deny, per_source)
; has "upstream":null.
;
; A tcp session's clock and counts sit in a side table, mapped only when
; some listener logs (g_plan_l4log) and touched only for its sessions; the
; relay pays one byte compared per read (l4log_add). A flow carries its own
; (FL_T0, FL_BIN, FL_BOUT).

L4L_T0		:= 0				; q: TSC at accept
L4L_IN		:= 8				; q: bytes from the client
L4L_OUT		:= 16				; q: and to it
L4L_SHIFT	:= 5

bss
	align 8
	g_l4l_base	dq ?
	g_plan_l4log	dd ?			; some tcp or udp listener logs
	g_ls_l4log	rb MAX_LISTENERS	; which (1)
	align 8
	g_l4_t0		dq ?			; alog_l4's line
	g_l4_in		dq ?
	g_l4_out	dq ?
	g_l4_sa		dq ?			; the client's sockaddr
	g_l4_lst	dd ?
	g_l4_sv		dd ?			; its server, NIL none
	g_l4_udp	dd ?
	g_l4_ip		rb 16
end bss

; Worker: the side table, when it is needed. eax = 0 or -errno.
l4log_worker_init:
	xor	eax,eax
	cmp	dword [g_plan_l4log],0
	je	.done
	xor	edi,edi
	mov	esi,[g_sessions]
	shl	rsi,L4L_SHIFT
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.done
	mov	[g_l4l_base],rax
	xor	eax,eax
.done:
	ret

; ebx = a new session, r13d = its listener: its clock starts, its counts
; are zero (when the listener logs). Keeps all but rax.
l4log_open:
	cmp	byte [g_ls_l4log+r13],0
	je	.out
	push	rdx
	push	rcx
	mov	ecx,ebx
	shl	rcx,L4L_SHIFT
	add	rcx,[g_l4l_base]
	rdtsc
	shl	rdx,32
	or	rax,rdx
	mov	[rcx+L4L_T0],rax
	xor	eax,eax
	mov	[rcx+L4L_IN],rax
	mov	[rcx+L4L_OUT],rax
	pop	rcx
	pop	rdx
.out:
	ret

; ebx = a session closing, r12 = it: a tcp listener's line. Keeps all but rax.
l4log_session:
	mov	eax,[r12+S_LST]
	cmp	byte [g_ls_l4log+rax],0
	je	.out
	push	rcx
	imul	rcx,rax,LS_SIZE
	cmp	dword [g_listeners+rcx+LS_KIND],LK_TCP
	pop	rcx
	jne	.out
	mov	[g_l4_lst],eax
	push	rcx
	mov	ecx,ebx
	shl	rcx,L4L_SHIFT
	add	rcx,[g_l4l_base]
	mov	rax,[rcx+L4L_T0]
	mov	[g_l4_t0],rax
	mov	rax,[rcx+L4L_IN]
	mov	[g_l4_in],rax
	mov	rax,[rcx+L4L_OUT]
	mov	[g_l4_out],rax
	pop	rcx
	mov	eax,[r12+S_SERVER]
	test	dword [r12+S_FLAGS],SF_COUNTED or SF_UP_OPEN
	jnz	@f
	cmp	qword [g_l4_out],0		; (no upstream ever: refused, or none up)
	jne	@f
	mov	eax,NIL
@@:
	mov	[g_l4_sv],eax
	call	peer_ptr
	add	rax,P_PEER
	mov	[g_l4_sa],rax
	mov	dword [g_l4_udp],0
	jmp	alog_l4
.out:
	ret

; rbx = a udp flow that ends: its listener's line. Keeps all but rax.
l4log_flow:
	mov	eax,[rbx+FL_LST]
	cmp	byte [g_ls_l4log+rax],0
	je	.out
	mov	[g_l4_lst],eax
	mov	rax,[rbx+FL_T0]
	mov	[g_l4_t0],rax
	mov	rax,[rbx+FL_BIN]
	mov	[g_l4_in],rax
	mov	rax,[rbx+FL_BOUT]
	mov	[g_l4_out],rax
	mov	eax,[rbx+FL_SERVER]
	mov	[g_l4_sv],eax
	lea	rax,[rbx+FL_SA]
	mov	[g_l4_sa],rax
	mov	dword [g_l4_udp],1
	jmp	alog_l4
.out:
	ret

; The line g_l4_* describe, into the logger's buffer. Keeps all but rax.
alog_l4:
	push	rbx
	push	rcx
	push	rdx
	push	rsi
	push	rdi
	push	r8
	push	r9
	push	r10
	push	r11
	push	r12
	push	r13
	push	r14
	push	r15
	mov	eax,[g_l4_lst]
	imul	rax,rax,LS_SIZE
	lea	r14,[g_listeners+rax]
	mov	edx,[r14+LS_ALOG]
	test	edx,edx
	jz	.out
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
	cmp	dword [g_l4_udp],0
	jne	@f
	memit '","proto":"tcp","client":"'
	jmp	.client
@@:
	memit '","proto":"udp","client":"'
.client:
	mov	rsi,[g_l4_sa]
	push	rdi
	lea	rdi,[g_l4_ip]
	call	peer_normalize
	pop	rdi
	push	rdx				; (its port)
	lea	rsi,[g_l4_ip]
	mov	edx,eax
	call	fmt_ip
	memit '","client_port":'
	pop	rax
	call	fmt_u64
	memit ',"upstream":'
	mov	eax,[g_l4_sv]
	cmp	eax,NIL
	je	.none
	imul	rax,rax,SV_SIZE
	mov	byte [rdi],'"'
	inc	rdi
	mov	rsi,[g_servers+rax+SV_TEXT]
	mov	edx,[g_servers+rax+SV_TLEN]
	mov	ecx,256
	call	json_text
	mov	byte [rdi],'"'
	inc	rdi
	jmp	.bytes
.none:
	memit 'null'
.bytes:
	memit ',"bytes_in":'
	mov	rax,[g_l4_in]
	call	fmt_u64
	memit ',"bytes_out":'
	mov	rax,[g_l4_out]
	call	fmt_u64
	memit ',"duration_ms":'
	rdtsc
	shl	rdx,32
	or	rax,rdx
	sub	rax,[g_l4_t0]
	xor	edx,edx
	mov	rcx,[g_tsc_per_us]
	test	rcx,rcx
	jnz	@f
	inc	ecx
@@:
	div	rcx				; microseconds
	xor	edx,edx
	mov	ecx,1000
	div	rcx
	push	rdx
	call	fmt_u64
	mov	byte [rdi],'.'
	inc	rdi
	pop	rax
	mov	ecx,3
	call	fmt_pad
	memit '}',10
	call	alog_exchange.append
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	r11
	pop	r10
	pop	r9
	pop	r8
	pop	rdi
	pop	rsi
	pop	rdx
	pop	rcx
	pop	rbx
	ret
