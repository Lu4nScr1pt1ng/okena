; Access logs out over the network, from the logger process: syslog (RFC
; 5424) over UDP (RFC 5426), TCP (RFC 6587, octet counting) and TLS (RFC
; 5425), and OpenTelemetry logs over OTLP/HTTP with JSON (plain or TLS).
;
; Workers know nothing of this: their lines reach the logger through the
; pipe as for a file, and it is the logger that waits on the network, so a
; collector that is slow or gone costs lines, never a request's latency.
;
; Syslog: one message a line, `<190>1 TIME HOST okena PID access - LINE`
; (local7.info, as nginx sends; TIME is the line's own). Over UDP one
; datagram each; over TCP and TLS one connection kept, frames written in one
; go for a batch of lines, its closing noticed before it is written to.
; OTLP: lines are turned into log records (the line's fields as attributes,
; under OpenTelemetry's names where there are some), gathered for a second
; or 512 KiB, and POSTed to /v1/logs (or the URL's path). What a collector
; does not take is kept for the next try, until 1 MiB is waiting.
;
; A destination that cannot be reached is said once, tried again after 1,
; 2, 4 ... 30 s, and said again when it is back; its lines meanwhile are
; dropped (syslog) or kept as far as they fit (OTLP). Names are resolved at
; each connection. A TLS destination is verified as alerts' targets are:
; `trust=FILE`, or the system's roots.

LKS_FILE		:= 0
LKS_UDP		:= 1
LKS_TCP		:= 2
LKS_TLS		:= 3
LKS_OTLP		:= 4
LKS_OTLPS	:= 5
LKS_DEAD		:= 6			; could not be set up: its lines are dropped

LN_KIND		:= 0			; d
LN_PORT		:= 4			; d
LN_HOST		:= 8			; q (in g_alog_dest)
LN_HLEN		:= 16			; d
LN_FD		:= 20			; d: -1 when not connected
LN_PATH		:= 24			; q
LN_PLEN		:= 32			; d
LN_DOWN		:= 36			; d: its being down was said
LN_RETRY	:= 40			; q: monotonic seconds: not tried before
LN_BACK		:= 48			; d: the wait after the next failure
LN_HASTRUST	:= 52			; d
LN_BLEN		:= 56			; d: OTLP: bytes in the batch
LN_BN		:= 60			; d: and records
LN_BUF		:= 64			; q: the batch
LN_BAT		:= 72			; q: monotonic ms when it started
LN_TRACES	:= 80			; d: spans (`tracing`), not log lines
LN_TRUST	:= 88			; PK_SIZE
LN_TC		:= (LN_TRUST + PK_SIZE + 63) and not 63
LN_SIZE		:= (LN_TC + TC_FULL + 63) and not 63

LN_BUF_CAP	:= 1 shl 20
LN_BUF_SEND	:= 512 shl 10
LN_SEND_CAP	:= 1 shl 17
LN_FRAME	:= ALOG_BUF + 512
LN_PAIRS	:= 32			; fields of a line
LP_KEY		:= 0			; q, d: the key's text
LP_KLEN		:= 8
LP_TYPE		:= 12			; d: 's' 'i' 'd' 'b' 'n'
LP_VAL		:= 16			; q, d: the value as written (a string's inside)
LP_VLEN		:= 24
LP_SIZE		:= 32

bss
	align 8
	g_ln		dq ?		; ALOG_MAX entries, mapped when one is not a file
	g_ln_now_ns	dq ?		; the wall clock for this batch of lines
	g_ln_hlen	dd ?
	g_ln_slen	dd ?
	g_ln_np		dd ?
	g_ln_host	rb 256		; " HOST okena PID access - "
	g_ln_frame	rb LN_FRAME
	g_ln_req	rb 1024
	g_ln_drain	rb 512
	align 8
	g_ln_pairs	rb LN_PAIRS * LP_SIZE
	g_ln_send	rb LN_SEND_CAP
end bss

rodata
	; scheme: length, kind, default port, text
	ln_schemes	db 9, LKS_UDP
			dw 514
			db 'syslog://'
			db 13, LKS_UDP
			dw 514
			db 'syslog+udp://'
			db 13, LKS_TCP
			dw 601
			db 'syslog+tcp://'
			db 13, LKS_TLS
			dw 6514
			db 'syslog+tls://'
			db 7, LKS_OTLP
			dw 4318
			db 'otlp://'
			db 12, LKS_OTLP
			dw 4318
			db 'otlp+http://'
			db 13, LKS_OTLPS
			dw 4318
			db 'otlp+https://'
			db 0
	; a line's field, and its attribute's name (OpenTelemetry's when it has one)
	ln_names	db 'listener',0,'okena.listener',0
			db 'client',0,'client.address',0
			db 'peer',0,'network.peer.address',0
			db 'request_id',0,'okena.request_id',0
			db 'method',0,'http.request.method',0
			db 'host',0,'server.address',0
			db 'status',0,'http.response.status_code',0
			db 'bytes',0,'http.response.size',0
			db 'duration_ms',0,'okena.duration_ms',0
			db 'upstream',0,'okena.upstream',0
			db 'source',0,'okena.source',0
			db 'retried',0,'okena.retried',0
			db 0
	ln_v1logs	db '/v1/logs'
	ln_v1logs.len = $ - ln_v1logs
	ln_v1traces	db '/v1/traces'
	ln_v1traces.len = $ - ln_v1traces
	ln_traces	db 'traces '		; a `tracing` destination's mark
end rodata

; rsi/ecx = an access_log destination, rdi = out (LN_KIND .. LN_PLEN): the
; URL read. CF when it is not one. Also what the configuration check uses.
alog_url:
	push	rbx
	lea	rbx,[ln_schemes]
.scheme:
	movzx	edx,byte [rbx]
	test	edx,edx
	jz	.bad
	cmp	ecx,edx
	jb	.other
	push	rcx
	push	rsi
	push	rdi
	lea	rdi,[rbx+4]
	mov	ecx,edx
	repe	cmpsb
	pop	rdi
	pop	rsi
	pop	rcx
	je	.found
.other:
	lea	rbx,[rbx+rdx+4]
	jmp	.scheme
.found:
	movzx	eax,byte [rbx+1]
	mov	[rdi+LN_KIND],eax
	movzx	eax,word [rbx+2]
	mov	[rdi+LN_PORT],eax
	add	rsi,rdx
	sub	ecx,edx
	; the host, up to a port or a path; a port after a ':' out of brackets
	mov	[rdi+LN_HOST],rsi
	xor	edx,edx
	xor	r9d,r9d
.hchar:
	cmp	edx,ecx
	jae	.hend
	movzx	eax,byte [rsi+rdx]
	cmp	al,'/'
	je	.hend
	cmp	al,'['
	jne	@f
	mov	r9d,1
@@:
	cmp	al,']'
	jne	@f
	xor	r9d,r9d
@@:
	cmp	al,':'
	jne	@f
	test	r9d,r9d
	jz	.port
@@:
	cmp	al,' '
	jbe	.bad
	cmp	al,'"'
	je	.bad
	cmp	al,'\'
	je	.bad
	cmp	al,0x7F
	jae	.bad
	inc	edx
	jmp	.hchar
.port:
	mov	[rdi+LN_HLEN],edx
	inc	edx
	xor	eax,eax
	xor	r9d,r9d
.digit:
	cmp	edx,ecx
	jae	.ported
	movzx	r10d,byte [rsi+rdx]
	cmp	r10d,'/'
	je	.ported
	sub	r10d,'0'
	cmp	r10d,9
	ja	.bad
	imul	eax,eax,10
	add	eax,r10d
	inc	edx
	inc	r9d
	cmp	r9d,5
	ja	.bad
	jmp	.digit
.ported:
	test	eax,eax
	jz	.bad
	cmp	eax,65535
	ja	.bad
	mov	[rdi+LN_PORT],eax
	jmp	.path
.hend:
	mov	[rdi+LN_HLEN],edx
.path:
	mov	eax,[rdi+LN_HLEN]
	test	eax,eax
	jz	.bad
	cmp	eax,253
	ja	.bad
	lea	rax,[rsi+rdx]
	sub	ecx,edx
	mov	[rdi+LN_PATH],rax
	mov	[rdi+LN_PLEN],ecx
	cmp	dword [rdi+LN_KIND],LKS_OTLP
	jae	.otlp
	; syslog: no path, or "/"
	cmp	ecx,1
	ja	.bad
	jb	.ok
	cmp	byte [rax],'/'
	jne	.bad
	jmp	.ok
.otlp:
	test	ecx,ecx
	jnz	@f
	lea	rax,[ln_v1logs]
	mov	[rdi+LN_PATH],rax
	mov	dword [rdi+LN_PLEN],ln_v1logs.len
	jmp	.ok
@@:
	cmp	ecx,512
	ja	.bad
	xor	edx,edx
@@:
	cmp	byte [rax+rdx],' '
	jbe	.bad
	cmp	byte [rax+rdx],0x7F
	jae	.bad
	inc	edx
	cmp	edx,ecx
	jb	@b
.ok:
	pop	rbx
	clc
	ret
.bad:
	pop	rbx
	stc
	ret

; ---------------------------------------------------------------- setting up

; The logger, starting (before its filter): each destination that is not a
; file read, its trust loaded, the buffers mapped. A TLS one without
; trust= loads the system's roots.
ln_setup:
	push	rbx
	push	r12
	push	r14
	xor	ebx,ebx
.find:
	cmp	ebx,[g_alog_count]
	jae	.none
	imul	rdi,rbx,ALOG_PATH
	lea	rdi,[g_alog_dest+rdi]
	cmp	byte [rdi],'/'
	je	.next_find
	lea	rsi,[str_stdout]
	call	cstr_eq
	test	eax,eax
	jnz	.next_find
	lea	rsi,[str_stderr]
	call	cstr_eq
	test	eax,eax
	jz	.map
.next_find:
	inc	ebx
	jmp	.find
.map:
	xor	edi,edi
	mov	esi,ALOG_MAX * LN_SIZE
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.none
	mov	[g_ln],rax
	call	cx_buffer
	call	ln_hostline
	xor	ebx,ebx
.dest:
	cmp	ebx,[g_alog_count]
	jae	.none
	imul	r14,rbx,LN_SIZE
	add	r14,[g_ln]
	mov	dword [r14+LN_FD],-1
	imul	r12,rbx,ALOG_PATH
	lea	r12,[g_alog_dest+r12]
	cmp	byte [r12],'/'
	je	.next
	mov	rdi,r12
	lea	rsi,[str_stdout]
	call	cstr_eq
	test	eax,eax
	jnz	.next
	mov	rdi,r12
	lea	rsi,[str_stderr]
	call	cstr_eq
	test	eax,eax
	jnz	.next
	; "[traces ]URL[ trust=PATH]"
	mov	eax,dword [ln_traces]
	cmp	[r12],eax
	jne	@f
	mov	eax,dword [ln_traces+3]
	cmp	[r12+3],eax
	jne	@f
	mov	dword [r14+LN_TRACES],1
	add	r12,7
@@:
	xor	ecx,ecx
@@:
	cmp	byte [r12+rcx],' '
	jbe	@f
	inc	ecx
	jmp	@b
@@:
	mov	rsi,r12
	mov	rdi,r14
	push	rcx
	call	alog_url
	pop	rcx
	jc	.dead
	cmp	dword [r14+LN_TRACES],0
	je	@f
	lea	rax,[ln_v1logs]
	cmp	[r14+LN_PATH],rax
	jne	@f
	lea	rax,[ln_v1traces]			; (its own default path)
	mov	[r14+LN_PATH],rax
	mov	dword [r14+LN_PLEN],ln_v1traces.len
@@:
	cmp	byte [r12+rcx],' '
	jne	.trusted
	lea	rdi,[r12+rcx+7]			; " trust="
	lea	rsi,[r14+LN_TRUST]
	call	ln_trust
	jc	.dead
	mov	dword [r14+LN_HASTRUST],1
.trusted:
	mov	eax,[r14+LN_KIND]
	cmp	eax,LKS_TLS
	je	.tls
	cmp	eax,LKS_OTLPS
	jne	@f
.tls:
	cmp	dword [r14+LN_HASTRUST],0
	jne	@f
	call	cx_store_load
@@:
	cmp	dword [r14+LN_KIND],LKS_OTLP
	jb	.next
	xor	edi,edi
	mov	esi,LN_BUF_CAP
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.dead
	mov	[r14+LN_BUF],rax
	jmp	.next
.dead:
	mov	dword [r14+LN_KIND],LKS_DEAD
	call	log_begin
	out_lit 'access log '
	mov	rsi,r12
	call	out_cstr
	out_lit ': cannot be set up (its trust= file?); its lines are dropped'
	call	log_end
.next:
	inc	ebx
	jmp	.dest
.none:
	pop	r14
	pop	r12
	pop	rbx
	ret

; rdi = a trust file's path (NUL-terminated), rsi = out (PK_SIZE): its first
; certificate's key. CF when it has none.
ln_trust:
	push	rsi
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	.bad
	mov	rsi,rax
	lea	rdi,[g_trust_der]
	call	pem_first_cert
	test	eax,eax
	jz	.bad
	lea	rsi,[g_trust_der]
	mov	edx,eax
	pop	rdi
	call	cert_pubkey
	test	eax,eax
	jz	.bad2
	clc
	ret
.bad:
	pop	rsi
.bad2:
	stc
	ret

; g_ln_host = " HOST okena PID access - ", and HOST alone at its start + 1
; for OTLP's host.name (g_ln_hlen).
ln_hostline:
	lea	rdi,[g_ln_host]
	mov	byte [rdi],' '
	mov	edi,AT_FDCWD
	lea	rsi,[str_al_hostname]
	mov	edx,O_RDONLY or O_CLOEXEC
	xor	r10d,r10d
	mov	eax,SYS_openat
	syscall
	xor	ecx,ecx
	test	eax,eax
	js	.named
	push	rax
	mov	edi,eax
	lea	rsi,[g_ln_host+1]
	mov	edx,200
	xor	eax,eax
	syscall
	mov	ecx,eax
	pop	rdi
	push	rcx
	mov	eax,SYS_close
	syscall
	pop	rcx
	test	ecx,ecx
	jns	.trim
	xor	ecx,ecx
.trim:
	test	ecx,ecx
	jz	.named
	cmp	byte [g_ln_host+rcx],' '
	ja	.check
	dec	ecx
	jmp	.trim
.check:
	; printable, no space (RFC 5424's HOSTNAME); else "-"
	xor	edx,edx
@@:
	movzx	eax,byte [g_ln_host+1+rdx]
	cmp	al,' '
	jbe	.unnamed
	cmp	al,0x7F
	jae	.unnamed
	cmp	al,'"'
	je	.unnamed
	cmp	al,'\'
	je	.unnamed
	inc	edx
	cmp	edx,ecx
	jb	@b
	jmp	.named
.unnamed:
	xor	ecx,ecx
.named:
	test	ecx,ecx
	jnz	@f
	mov	byte [g_ln_host+1],'-'
	mov	ecx,1
@@:
	mov	[g_ln_hlen],ecx
	lea	rdi,[g_ln_host+1+rcx]
	memit ' okena '
	mov	eax,[g_sup_pid]
	call	fmt_u64
	memit ' access - '
	lea	rax,[g_ln_host]
	sub	rdi,rax
	mov	[g_ln_slen],edi
	ret

; ------------------------------------------------------------------ out

; ebx = destination (from 0), rsi/edx = whole lines for it. Keeps rbx and
; r12-r15.
ln_out:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	imul	r14,rbx,LN_SIZE
	add	r14,[g_ln]
	mov	r12,rsi
	lea	r13,[rsi+rdx]
	sub	rsp,16
	mov	edi,CLOCK_REALTIME
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	imul	rax,[rsp],1000000000
	add	rax,[rsp+8]
	mov	[g_ln_now_ns],rax
	add	rsp,16
	mov	eax,[r14+LN_KIND]
	cmp	eax,LKS_DEAD
	je	.out
	cmp	eax,LKS_OTLP
	jae	.otlp
	call	ln_connect
	jc	.out				; down: these lines are lost
	xor	r15d,r15d			; bytes waiting in g_ln_send
.line:
	cmp	r12,r13
	jae	.flush
	mov	rdi,r12
	mov	rcx,r13
	sub	rcx,rdi
	mov	al,10
	repne	scasb
	mov	rsi,r12
	mov	rdx,rdi
	sub	rdx,rsi
	dec	rdx				; without its newline
	mov	r12,rdi
	cmp	rdx,ALOG_BUF
	ja	.line
	call	ln_frame			; g_ln_frame, ecx = its length
	cmp	dword [r14+LN_KIND],LKS_UDP
	jne	.stream
	mov	edi,[r14+LN_FD]
	lea	rsi,[g_ln_frame]
	mov	edx,ecx
	mov	eax,SYS_write
	syscall					; a datagram not taken is lost, as UDP goes
	jmp	.line
.stream:
	; "LENGTH SP FRAME"
	lea	eax,[r15+rcx+16]
	cmp	eax,LN_SEND_CAP
	jbe	@f
	push	rcx
	mov	edx,r15d
	call	ln_stream
	pop	rcx
	xor	r15d,r15d
	jc	.out
@@:
	lea	rdi,[g_ln_send+r15]
	mov	eax,ecx
	push	rcx
	call	fmt_u64
	mov	byte [rdi],' '
	inc	rdi
	pop	rcx
	lea	rsi,[g_ln_frame]
	rep	movsb
	lea	rax,[g_ln_send]
	sub	rdi,rax
	mov	r15d,edi
	jmp	.line
.flush:
	cmp	dword [r14+LN_KIND],LKS_UDP
	je	.out
	mov	edx,r15d
	call	ln_stream
	jmp	.out
.otlp:
	cmp	r12,r13
	jae	.gathered
	mov	rdi,r12
	mov	rcx,r13
	sub	rcx,rdi
	mov	al,10
	repne	scasb
	mov	rsi,r12
	mov	rdx,rdi
	sub	rdx,rsi
	dec	rdx
	mov	r12,rdi
	cmp	rdx,ALOG_BUF
	ja	.otlp
	call	ln_record
	jmp	.otlp
.gathered:
	cmp	dword [r14+LN_BLEN],LN_BUF_SEND
	jb	.out
	call	ln_post
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rsi/rdx = a line: g_ln_frame = its syslog message, ecx = its length.
ln_frame:
	push	rsi
	push	rdx
	lea	rdi,[g_ln_frame]
	memit '<190>1 '
	pop	rdx
	pop	rsi
	; the line's time, when it starts as access lines do
	cmp	rdx,40
	jb	.no_time
	cmp	dword [rsi],'{"ti'
	jne	.no_time
	cmp	dword [rsi+4],'me":'
	jne	.no_time
	cmp	byte [rsi+8],'"'
	jne	.no_time
	xor	ecx,ecx
@@:
	mov	al,[rsi+9+rcx]
	cmp	al,'"'
	je	@f
	cmp	al,' '
	jbe	.no_time
	mov	[rdi+rcx],al
	inc	ecx
	cmp	ecx,32
	jb	@b
	jmp	.no_time
@@:
	test	ecx,ecx
	jz	.no_time
	add	rdi,rcx
	jmp	.timed
.no_time:
	mov	byte [rdi],'-'
	inc	rdi
.timed:
	push	rsi
	lea	rsi,[g_ln_host]
	mov	ecx,[g_ln_slen]
	rep	movsb
	pop	rsi
	mov	rcx,rdx
	rep	movsb
	lea	rcx,[g_ln_frame]
	sub	rdi,rcx
	mov	ecx,edi
	ret

; r14 = destination, edx = bytes in g_ln_send: written. CF when the
; connection broke (it is closed, said, tried again later).
ln_stream:
	test	edx,edx
	jz	.sent
	cmp	dword [r14+LN_KIND],LKS_TLS
	je	.tls
	mov	edi,[r14+LN_FD]
	lea	rsi,[g_ln_send]
	call	dk_write_all
	jc	.broken
.sent:
	clc
	ret
.tls:
	push	rdx
	lea	rsi,[r14+LN_TC]
	call	ln_tls_in
	pop	rdx
	lea	rsi,[g_ln_send]
	call	cx_send
	pushf
	call	ln_tls_out
	popf
	jc	.broken
	clc
	ret
.broken:
	mov	eax,1
	jmp	ln_failed

; r14 = destination: its TLS state into the client's, and back
ln_tls_in:
	lea	rdi,[g_cx_tc]
	lea	rsi,[r14+LN_TC]
	mov	ecx,TC_FULL / 8
	rep	movsq
	mov	eax,[r14+LN_FD]
	mov	[g_cx_fd],eax
	mov	dword [g_cx_tls],1
	ret
ln_tls_out:
	lea	rdi,[r14+LN_TC]
	lea	rsi,[g_cx_tc]
	mov	ecx,TC_FULL / 8
	rep	movsq
	ret

; r14 = a syslog destination: connected (UDP: an address to write to). CF
; when it is down, or waiting before it is tried again.
ln_connect:
	cmp	dword [r14+LN_FD],0
	jl	.connect
	cmp	dword [r14+LN_KIND],LKS_UDP
	je	.up
	; still there? (a peer that closed is seen before lines go to it)
.peek:
	mov	edi,[r14+LN_FD]
	lea	rsi,[g_ln_drain]
	mov	edx,512
	mov	r10d,MSG_DONTWAIT
	xor	r8d,r8d
	xor	r9d,r9d
	mov	eax,SYS_recvfrom
	syscall
	test	rax,rax
	jg	.peek				; a ticket, an alert: not ours to read
	jz	.closed
	cmp	rax,-EAGAIN
	je	.up
	cmp	rax,-EINTR
	je	.peek
.closed:
	mov	edi,[r14+LN_FD]
	mov	eax,SYS_close
	syscall
	mov	dword [r14+LN_FD],-1
.connect:
	call	monotonic_seconds
	cmp	rax,[r14+LN_RETRY]
	jb	.wait
	sub	rsp,32
	mov	rsi,[r14+LN_HOST]
	mov	ecx,[r14+LN_HLEN]
	mov	edx,[r14+LN_PORT]
	mov	rdi,rsp
	call	cx_address
	jc	.no_address
	cmp	dword [r14+LN_KIND],LKS_UDP
	je	.udp
	mov	rsi,rsp
	call	cx_connect
	jc	.no_address
	add	rsp,32
	mov	eax,[g_cx_fd]
	mov	[r14+LN_FD],eax
	cmp	dword [r14+LN_KIND],LKS_TLS
	jne	.reached
	call	ln_handshake
	jc	.not_tls
	call	ln_tls_out
	jmp	.reached
.not_tls:
	push	rax
	call	cx_close
	mov	dword [r14+LN_FD],-1
	pop	rax
	jmp	ln_failed
.udp:
	movzx	edi,word [rsp]
	push	rdx
	mov	esi,SOCK_DGRAM or SOCK_CLOEXEC
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	pop	rdx
	test	eax,eax
	js	.no_address
	mov	[r14+LN_FD],eax
	mov	edi,eax
	mov	rsi,rsp
	mov	eax,SYS_connect
	syscall
	test	eax,eax
	js	.udp_bad
	add	rsp,32
	jmp	.reached
.udp_bad:
	mov	edi,[r14+LN_FD]
	mov	eax,SYS_close
	syscall
	mov	dword [r14+LN_FD],-1
.no_address:
	add	rsp,32
	mov	eax,1
	jmp	ln_failed
.reached:
	mov	dword [r14+LN_BACK],0
	cmp	dword [r14+LN_DOWN],0
	je	.up
	mov	dword [r14+LN_DOWN],0
	call	log_begin
	call	ln_name
	out_lit ': reached again'
	call	log_end
.up:
	clc
	ret
.wait:
	stc
	ret

; r14 = a TLS destination, connected in g_cx_fd: the handshake, the server
; verified (trust= or the system's roots). CF, eax as cx_handshake.
ln_handshake:
	xor	edi,edi
	cmp	dword [r14+LN_HASTRUST],0
	je	@f
	lea	rdi,[r14+LN_TRUST]
@@:
	; the name for SNI and the certificate: the host without brackets
	mov	rsi,[r14+LN_HOST]
	mov	edx,[r14+LN_HLEN]
	cmp	byte [rsi],'['
	jne	@f
	inc	rsi
	sub	edx,2
@@:
	jmp	cx_handshake

; r14 = destination, eax = why (4: not who it should be): closed, said once,
; tried again after a wait that doubles up to 30 s. Always CF.
ln_failed:
	push	rax
	mov	edi,[r14+LN_FD]
	test	edi,edi
	js	@f
	mov	eax,SYS_close
	syscall
	mov	dword [r14+LN_FD],-1
@@:
	mov	eax,[r14+LN_BACK]
	add	eax,eax
	jnz	@f
	inc	eax
@@:
	cmp	eax,30
	jbe	@f
	mov	eax,30
@@:
	mov	[r14+LN_BACK],eax
	call	monotonic_seconds
	mov	ecx,[r14+LN_BACK]
	add	rax,rcx
	mov	[r14+LN_RETRY],rax
	pop	rax
	cmp	dword [r14+LN_DOWN],0
	jne	.said
	mov	dword [r14+LN_DOWN],1
	push	rax
	call	log_begin
	call	ln_name
	out_lit ': cannot reach it'
	pop	rax
	cmp	eax,4
	jne	@f
	out_lit ' (it is not who it should be)'
	jmp	.why
@@:
	cmp	eax,5
	jne	.why
	out_lit ' (it did not take the lines)'
.why:
	cmp	dword [r14+LN_KIND],LKS_OTLP
	jb	@f
	out_lit '; its lines are kept while they fit, and sent when it is back'
	jmp	.end
@@:
	out_lit '; its lines are dropped until it is back'
.end:
	call	log_end
.said:
	stc
	ret

; r14 = destination: what it is and its URL into the log line
ln_name:
	cmp	dword [r14+LN_TRACES],0
	jne	.traces
	out_lit 'access log '
	jmp	.url
.traces:
	out_lit 'tracing '
.url:
	mov	rax,r14
	sub	rax,[g_ln]
	xor	edx,edx
	mov	ecx,LN_SIZE
	div	rcx
	imul	rsi,rax,ALOG_PATH
	lea	rsi,[g_alog_dest+rsi]
	cmp	dword [r14+LN_TRACES],0
	je	@f
	add	rsi,7
@@:
	xor	edx,edx
@@:
	cmp	byte [rsi+rdx],' '
	jbe	@f
	inc	edx
	jmp	@b
@@:
	jmp	out_str

; ------------------------------------------------------------------ OTLP

; r14 = an OTLP destination, rsi/rdx = a line: one log record more in its
; batch. A full batch whose collector does not answer is let go.
ln_record:
	push	rbx
	push	r12
	push	r13
	push	r15
	mov	r12,rsi
	mov	r13,rdx
	mov	eax,[r14+LN_BLEN]
	add	eax,ALOG_BUF * 4 + 1024
	cmp	eax,LN_BUF_CAP
	jbe	.room
	call	ln_post
	mov	eax,[r14+LN_BLEN]
	add	eax,ALOG_BUF * 4 + 1024
	cmp	eax,LN_BUF_CAP
	jbe	.room
	mov	dword [r14+LN_BLEN],0		; it is not coming back soon enough
	mov	dword [r14+LN_BN],0
.room:
	; the line's fields
	mov	rsi,r12
	mov	rdx,r13
	call	ln_fields
	jc	.done				; not a line of ours: left out
	mov	rdi,[r14+LN_BUF]
	mov	eax,[r14+LN_BLEN]
	test	eax,eax
	jnz	.more
	push	rdi
	call	ln_ms
	mov	[r14+LN_BAT],rax
	pop	rdi
	call	ln_prefix
	jmp	.record
.more:
	add	rdi,rax
	mov	byte [rdi],','
	inc	rdi
.record:
	cmp	dword [r14+LN_TRACES],0
	jne	.span
	memit '{"timeUnixNano":"'
	lea	rsi,[str_lnk_time]
	call	ln_find
	jc	.now
	call	ln_iso_ns
	jnc	.timed
.now:
	mov	rax,[g_ln_now_ns]
.timed:
	call	fmt_u64
	memit '","observedTimeUnixNano":"'
	mov	rax,[g_ln_now_ns]
	call	fmt_u64
	mov	byte [rdi],'"'
	inc	rdi
	; its span, when it has one
	lea	rsi,[str_lnk_trace]
	call	ln_find
	jc	@f
	memit ',"traceId":"'
	lea	rsi,[str_lnk_trace]
	call	ln_copyval
	memit '","spanId":"'
	lea	rsi,[str_lnk_span]
	call	ln_copyval
	mov	byte [rdi],'"'
	inc	rdi
@@:
	; the severity, from the status
	lea	rsi,[str_lnk_status]
	call	ln_find
	mov	eax,0
	jc	@f
	call	ln_number
@@:
	cmp	eax,500
	jae	.error
	cmp	eax,400
	jae	.warn
	memit ',"severityNumber":9,"severityText":"INFO"'
	jmp	.body
.warn:
	memit ',"severityNumber":13,"severityText":"WARN"'
	jmp	.body
.error:
	memit ',"severityNumber":17,"severityText":"ERROR"'
.body:
	; "METHOD TARGET STATUS"
	memit ',"body":{"stringValue":"'
	lea	rsi,[str_lnk_method]
	call	ln_copyval
	mov	byte [rdi],' '
	inc	rdi
	lea	rsi,[str_lnk_target]
	call	ln_copyval
	mov	byte [rdi],' '
	inc	rdi
	lea	rsi,[str_lnk_status]
	call	ln_copyval
	memit '"},"attributes":['
	jmp	.attributes
.span:
	; a server span: its ids, its method for a name, its times
	memit '{"traceId":"'
	lea	rsi,[str_lnk_trace]
	call	ln_copyval
	memit '","spanId":"'
	lea	rsi,[str_lnk_span]
	call	ln_copyval
	mov	byte [rdi],'"'
	inc	rdi
	lea	rsi,[str_lnk_parent]
	call	ln_find
	jc	@f
	memit ',"parentSpanId":"'
	lea	rsi,[str_lnk_parent]
	call	ln_copyval
	mov	byte [rdi],'"'
	inc	rdi
@@:
	memit ',"name":"'
	lea	rsi,[str_lnk_method]
	call	ln_copyval
	memit '","kind":2,"startTimeUnixNano":"'
	lea	rsi,[str_lnk_start]
	call	ln_copyval
	memit '","endTimeUnixNano":"'
	lea	rsi,[str_lnk_end]
	call	ln_copyval
	memit '","attributes":['
.attributes:
	xor	ebx,ebx
	xor	r15d,r15d			; attributes written
.attr:
	cmp	ebx,[g_ln_np]
	jae	.attrs
	imul	r8,rbx,LP_SIZE
	lea	r8,[g_ln_pairs+r8]
	inc	ebx
	cmp	dword [r8+LP_TYPE],'n'
	je	.attr
	cmp	dword [r8+LP_VLEN],0
	je	.attr				; nothing said: no attribute
	; what the record has as its own; target is url.path and url.query
	call	ln_own
	je	.attr
	lea	rsi,[str_lnk_target]
	call	ln_is
	je	.target
	call	ln_comma
	memit '{"key":"'
	call	ln_attr_name
	memit '","value":{'
	call	ln_value
	memit '}}'
	jmp	.attr
.target:
	; the path up to '?', the query after it
	mov	rsi,[r8+LP_VAL]
	mov	ecx,[r8+LP_VLEN]
	xor	edx,edx
@@:
	cmp	edx,ecx
	jae	@f
	cmp	byte [rsi+rdx],'?'
	je	@f
	inc	edx
	jmp	@b
@@:
	push	rsi
	push	rcx
	push	rdx
	call	ln_comma
	memit '{"key":"url.path","value":{"stringValue":"'
	mov	rsi,[rsp+16]
	mov	rcx,[rsp]
	rep	movsb
	memit '"}}'
	pop	rdx
	pop	rcx
	pop	rsi
	inc	edx
	cmp	edx,ecx
	ja	.attr
	push	rsi
	push	rcx
	push	rdx
	memit ',{"key":"url.query","value":{"stringValue":"'
	pop	rdx
	pop	rcx
	pop	rsi
	add	rsi,rdx
	sub	ecx,edx
	rep	movsb
	memit '"}}'
	jmp	.attr
.attrs:
	mov	byte [rdi],']'
	inc	rdi
	; a span that ended in a 5xx is in error (a 4xx is the client's)
	cmp	dword [r14+LN_TRACES],0
	je	.closed
	lea	rsi,[str_lnk_status]
	call	ln_find
	jc	.closed
	call	ln_number
	cmp	eax,500
	jb	.closed
	memit ',"status":{"code":2}'
.closed:
	mov	byte [rdi],'}'
	inc	rdi
	mov	rax,rdi
	sub	rax,[r14+LN_BUF]
	mov	[r14+LN_BLEN],eax
	inc	dword [r14+LN_BN]
.done:
	pop	r15
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = output: a comma before every attribute but the first (r15d counts)
ln_comma:
	test	r15d,r15d
	jz	@f
	mov	byte [rdi],','
	inc	rdi
@@:
	inc	r15d
	ret

cstring str_lnk_time, 'time',0
cstring str_lnk_trace, 'trace_id',0
cstring str_lnk_span, 'span_id',0
cstring str_lnk_parent, 'parent_span_id',0
cstring str_lnk_start, 'start_ns',0
cstring str_lnk_end, 'end_ns',0

; r8 = pair: ZF when the record carries it as its own field, not an attribute
ln_own:
	irp key, str_lnk_time, str_lnk_trace, str_lnk_span, str_lnk_parent, str_lnk_start, str_lnk_end
		lea	rsi,[key]
		call	ln_is
		je	.yes
	end irp
.yes:
	ret
cstring str_lnk_status, 'status',0
cstring str_lnk_method, 'method',0
cstring str_lnk_target, 'target',0

; rdi = output: the start of an OTLP logs request, up to its records
ln_prefix:
	cmp	dword [r14+LN_TRACES],0
	je	@f
	memit '{"resourceSpans":[{"resource":{"attributes":['
	jmp	.resource
@@:
	memit '{"resourceLogs":[{"resource":{"attributes":['
.resource:
	memit '{"key":"service.name","value":{"stringValue":"okena"}},{"key":"host.name","value":{"stringValue":"'
	lea	rsi,[g_ln_host+1]
	mov	ecx,[g_ln_hlen]
	rep	movsb
	cmp	dword [r14+LN_TRACES],0
	je	@f
	memit '"}}]},"scopeSpans":[{"scope":{"name":"okena"},"spans":['
	ret
@@:
	memit '"}}]},"scopeLogs":[{"scope":{"name":"okena"},"logRecords":['
	ret

; rsi/rdx = a line, flat JSON as okena writes it: g_ln_pairs, g_ln_np. CF when
; it is not that.
ln_fields:
	lea	r9,[rsi+rdx]			; end
	mov	dword [g_ln_np],0
	cmp	rsi,r9
	jae	.bad
	cmp	byte [rsi],'{'
	jne	.bad
	inc	rsi
.pair:
	cmp	rsi,r9
	jae	.bad
	cmp	byte [rsi],'}'
	je	.ok
	cmp	byte [rsi],'"'
	jne	.bad
	inc	rsi
	mov	eax,[g_ln_np]
	cmp	eax,LN_PAIRS
	jae	.bad
	imul	r8,rax,LP_SIZE
	lea	r8,[g_ln_pairs+r8]
	mov	[r8+LP_KEY],rsi
@@:
	cmp	rsi,r9
	jae	.bad
	cmp	byte [rsi],'"'
	je	@f
	cmp	byte [rsi],'\'
	je	.bad				; keys are plain words
	inc	rsi
	jmp	@b
@@:
	mov	rax,rsi
	sub	rax,[r8+LP_KEY]
	mov	[r8+LP_KLEN],eax
	inc	rsi
	cmp	rsi,r9
	jae	.bad
	cmp	byte [rsi],':'
	jne	.bad
	inc	rsi
	cmp	rsi,r9
	jae	.bad
	cmp	byte [rsi],'"'
	je	.string
	; a word: a number, true, false or null
	mov	[r8+LP_VAL],rsi
	mov	dword [r8+LP_TYPE],'i'
.wchar:
	cmp	rsi,r9
	jae	.bad
	movzx	eax,byte [rsi]
	cmp	al,','
	je	.word
	cmp	al,'}'
	je	.word
	cmp	al,'.'
	jne	.not_dot
	mov	dword [r8+LP_TYPE],'d'
.not_dot:
	cmp	al,'t'
	je	.bool
	cmp	al,'f'
	jne	.not_bool
.bool:
	mov	dword [r8+LP_TYPE],'b'
.not_bool:
	cmp	al,'n'
	jne	@f
	mov	dword [r8+LP_TYPE],'n'
@@:
	inc	rsi
	jmp	.wchar
.word:
	mov	rax,rsi
	sub	rax,[r8+LP_VAL]
	jz	.bad
	mov	[r8+LP_VLEN],eax
	jmp	.next
.string:
	inc	rsi
	mov	[r8+LP_VAL],rsi
	mov	dword [r8+LP_TYPE],'s'
@@:
	cmp	rsi,r9
	jae	.bad
	movzx	eax,byte [rsi]
	cmp	al,'"'
	je	@f
	inc	rsi
	cmp	al,'\'
	jne	@b
	inc	rsi				; an escape: its next byte is its own
	jmp	@b
@@:
	mov	rax,rsi
	sub	rax,[r8+LP_VAL]
	mov	[r8+LP_VLEN],eax
	inc	rsi
.next:
	inc	dword [g_ln_np]
	cmp	rsi,r9
	jae	.bad
	cmp	byte [rsi],','
	jne	.pair
	inc	rsi
	jmp	.pair
.ok:
	clc
	ret
.bad:
	stc
	ret

; rsi = a key (NUL-terminated): r8 = its pair. CF when the line has none.
ln_find:
	xor	ecx,ecx
.next:
	cmp	ecx,[g_ln_np]
	jae	.none
	imul	r8,rcx,LP_SIZE
	lea	r8,[g_ln_pairs+r8]
	inc	ecx
	push	rcx
	call	ln_is
	pop	rcx
	jne	.next
	clc
	ret
.none:
	stc
	ret

; r8 = pair, rsi = a key (NUL-terminated): ZF when it is that key. Keeps rdi.
ln_is:
	push	rdi
	mov	rdi,[r8+LP_KEY]
	mov	ecx,[r8+LP_KLEN]
	xor	edx,edx
@@:
	cmp	edx,ecx
	je	.end
	mov	al,[rsi+rdx]
	cmp	al,[rdi+rdx]
	jne	.out
	inc	edx
	jmp	@b
.end:
	cmp	byte [rsi+rdx],0
.out:
	pop	rdi
	ret

; rsi = a key, rdi = output: its value as written, if the line has it
ln_copyval:
	call	ln_find
	jc	.none
	mov	rsi,[r8+LP_VAL]
	mov	ecx,[r8+LP_VLEN]
	cmp	dword [r8+LP_TYPE],'s'
	je	@f
	cmp	dword [r8+LP_TYPE],'i'
	jne	.none
@@:
	rep	movsb
.none:
	ret

; r8 = an integer pair: eax = its value (up to nine digits)
ln_number:
	mov	rsi,[r8+LP_VAL]
	mov	ecx,[r8+LP_VLEN]
	xor	eax,eax
	cmp	ecx,9
	ja	.done
@@:
	test	ecx,ecx
	jz	.done
	movzx	edx,byte [rsi]
	sub	edx,'0'
	cmp	edx,9
	ja	.done
	imul	eax,eax,10
	add	eax,edx
	inc	rsi
	dec	ecx
	jmp	@b
.done:
	ret

; r8 = pair, rdi = output: its attribute's name
ln_attr_name:
	lea	rsi,[ln_names]
.next:
	cmp	byte [rsi],0
	je	.own
	push	rsi
	call	ln_is
	pop	rsi
	je	.found
@@:
	lodsb					; past the field
	test	al,al
	jnz	@b
@@:
	lodsb					; and its name
	test	al,al
	jnz	@b
	jmp	.next
.found:
	lodsb
	test	al,al
	jnz	.found
	jmp	fmt_cstr
.own:
	memit 'okena.'
	mov	rsi,[r8+LP_KEY]
	mov	ecx,[r8+LP_KLEN]
	rep	movsb
	ret

; r8 = pair, rdi = output: its AnyValue's inside
ln_value:
	mov	eax,[r8+LP_TYPE]
	cmp	eax,'i'
	je	.int
	cmp	eax,'d'
	je	.double
	cmp	eax,'b'
	je	.bool
	memit '"stringValue":"'
	mov	rsi,[r8+LP_VAL]
	mov	ecx,[r8+LP_VLEN]
	rep	movsb
	mov	byte [rdi],'"'
	inc	rdi
	ret
.int:
	memit '"intValue":"'
	mov	rsi,[r8+LP_VAL]
	mov	ecx,[r8+LP_VLEN]
	rep	movsb
	mov	byte [rdi],'"'
	inc	rdi
	ret
.double:
	memit '"doubleValue":'
	jmp	.raw
.bool:
	memit '"boolValue":'
.raw:
	mov	rsi,[r8+LP_VAL]
	mov	ecx,[r8+LP_VLEN]
	rep	movsb
	ret

; r8 = the time pair ("2026-10-29T12:34:56.789Z"): rax = nanoseconds since
; the epoch. CF when it is not written so. Keeps rdi.
ln_iso_ns:
	cmp	dword [r8+LP_VLEN],24
	jne	.bad
	mov	rsi,[r8+LP_VAL]
	cmp	byte [rsi+4],'-'
	jne	.bad
	cmp	byte [rsi+10],'T'
	jne	.bad
	cmp	byte [rsi+23],'Z'
	jne	.bad
	push	rbx
	push	rdi
	mov	ecx,4
	xor	edx,edx
	call	.digits				; year
	mov	r9,rax
	lea	rsi,[rsi+5]
	mov	ecx,2
	call	.digits				; month
	mov	r10,rax
	lea	rsi,[rsi+3]
	mov	ecx,2
	call	.digits				; day
	mov	r11,rax
	; days since 1970-01-01 (H. Hinnant's days_from_civil)
	cmp	r10,2
	ja	@f
	dec	r9
@@:
	mov	rax,r9
	xor	edx,edx
	mov	ecx,400
	div	rcx
	mov	rbx,rax				; era
	imul	rax,rax,400
	mov	rcx,r9
	sub	rcx,rax				; yoe
	mov	rax,r10
	cmp	rax,2
	ja	@f
	add	rax,9
	jmp	.mp
@@:
	sub	rax,3
.mp:
	imul	rax,rax,153
	add	rax,2
	xor	edx,edx
	push	rcx
	mov	ecx,5
	div	rcx
	pop	rcx
	add	rax,r11
	dec	rax				; doy
	imul	rdi,rcx,365
	add	rdi,rax
	mov	rax,rcx
	shr	rax,2
	add	rdi,rax
	mov	rax,rcx
	xor	edx,edx
	push	rcx
	mov	ecx,100
	div	rcx
	pop	rcx
	sub	rdi,rax				; doe
	imul	rax,rbx,146097
	add	rax,rdi
	sub	rax,719468			; days
	imul	rbx,rax,86400
	lea	rsi,[rsi+3]
	mov	ecx,2
	call	.digits
	imul	rax,rax,3600
	add	rbx,rax
	lea	rsi,[rsi+3]
	mov	ecx,2
	call	.digits
	imul	rax,rax,60
	add	rbx,rax
	lea	rsi,[rsi+3]
	mov	ecx,2
	call	.digits
	add	rbx,rax
	imul	rbx,rbx,1000000000
	lea	rsi,[rsi+3]
	mov	ecx,3
	call	.digits
	imul	rax,rax,1000000
	add	rax,rbx
	pop	rdi
	pop	rbx
	clc
	ret
.bad:
	stc
	ret
; rsi = digits, ecx = how many: rax = their value (rsi is kept)
.digits:
	xor	eax,eax
	xor	edx,edx
@@:
	movzx	r8d,byte [rsi+rdx]
	sub	r8d,'0'
	cmp	r8d,9
	ja	@f
	imul	rax,rax,10
	add	rax,r8
	inc	edx
	cmp	edx,ecx
	jb	@b
@@:
	ret

; r14 = an OTLP destination: its batch POSTed. Kept when it is not taken.
ln_post:
	cmp	dword [r14+LN_BN],0
	je	.none
	call	monotonic_seconds
	cmp	rax,[r14+LN_RETRY]
	jb	.none				; waiting before trying again
	push	rbx
	sub	rsp,32
	mov	rsi,[r14+LN_HOST]
	mov	ecx,[r14+LN_HLEN]
	mov	edx,[r14+LN_PORT]
	mov	rdi,rsp
	call	cx_address
	mov	eax,1
	jc	.failed
	mov	rsi,rsp
	call	cx_connect
	mov	eax,1
	jc	.failed
	cmp	dword [r14+LN_KIND],LKS_OTLPS
	jne	.plain
	call	ln_handshake
	jc	.close
.plain:
	; the head; then the records, and their end
	lea	rdi,[g_ln_req]
	memit 'POST '
	mov	rsi,[r14+LN_PATH]
	mov	ecx,[r14+LN_PLEN]
	rep	movsb
	memit ' HTTP/1.0',13,10,'Host: '
	mov	rsi,[r14+LN_HOST]
	mov	ecx,[r14+LN_HLEN]
	rep	movsb
	memit 13,10,'User-Agent: okena',13,10,'Content-Type: application/json',13,10,'Content-Length: '
	mov	eax,[r14+LN_BLEN]
	add	eax,ln_suffix.len
	call	fmt_u64
	memit 13,10,13,10
	lea	rsi,[g_ln_req]
	mov	rdx,rdi
	sub	rdx,rsi
	call	cx_send
	mov	eax,1
	jc	.close
	mov	rsi,[r14+LN_BUF]
	mov	edx,[r14+LN_BLEN]
	call	cx_send
	mov	eax,1
	jc	.close
	lea	rsi,[ln_suffix]
	mov	edx,ln_suffix.len
	call	cx_send
	mov	eax,1
	jc	.close
	call	cx_answer
	mov	eax,1
	jc	.close
	call	cx_close
	call	cx_status
	mov	ecx,eax
	mov	eax,5
	jc	.failed
	sub	ecx,200
	cmp	ecx,100
	jae	.failed
	; taken
	mov	dword [r14+LN_BLEN],0
	mov	dword [r14+LN_BN],0
	mov	dword [r14+LN_FD],-1
	mov	dword [r14+LN_BACK],0
	add	rsp,32
	pop	rbx
	cmp	dword [r14+LN_DOWN],0
	je	.none
	mov	dword [r14+LN_DOWN],0
	call	log_begin
	call	ln_name
	out_lit ': reached again'
	call	log_end
.none:
	ret
.close:
	push	rax
	call	cx_close
	pop	rax
.failed:
	mov	dword [r14+LN_FD],-1
	add	rsp,32
	pop	rbx
	jmp	ln_failed

cstring ln_suffix, ']}]}]}'

; The logger, each turn: batches that have waited a second go out. eax = how
; long it may sleep (ms; -1 when nothing waits).
ln_tick:
	mov	eax,-1
	cmp	qword [g_ln],0
	je	.done
	push	rbx
	push	r14
	push	r12
	mov	r12d,-1
	xor	ebx,ebx
.dest:
	cmp	ebx,[g_alog_count]
	jae	.out
	imul	r14,rbx,LN_SIZE
	add	r14,[g_ln]
	inc	ebx
	cmp	dword [r14+LN_KIND],LKS_OTLP
	jb	.dest
	cmp	dword [r14+LN_KIND],LKS_DEAD
	je	.dest
	cmp	dword [r14+LN_BN],0
	je	.dest
	call	ln_ms
	mov	rcx,[r14+LN_BAT]
	add	rcx,1000			; its second is up then
	sub	rcx,rax
	jg	.later
	call	monotonic_seconds
	cmp	rax,[r14+LN_RETRY]
	jb	.again				; (waiting to try again)
	call	ln_post
	cmp	dword [r14+LN_BN],0
	je	.dest
.again:
	mov	ecx,1000
.later:
	cmp	ecx,r12d
	jae	.dest				; (unsigned: -1 is no limit)
	mov	r12d,ecx
	jmp	.dest
.out:
	mov	eax,r12d
	pop	r12
	pop	r14
	pop	rbx
.done:
	ret

; rax = CLOCK_MONOTONIC in milliseconds
ln_ms:
	sub	rsp,16
	mov	edi,CLOCK_MONOTONIC
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	mov	rax,[rsp+8]
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	imul	rcx,[rsp],1000
	add	rax,rcx
	add	rsp,16
	ret

; The logger, leaving: what OTLP batches hold, one last try
ln_finish:
	cmp	qword [g_ln],0
	je	.done
	push	rbx
	push	r14
	xor	ebx,ebx
.dest:
	cmp	ebx,[g_alog_count]
	jae	.out
	imul	r14,rbx,LN_SIZE
	add	r14,[g_ln]
	inc	ebx
	cmp	dword [r14+LN_KIND],LKS_OTLP
	jb	.dest
	cmp	dword [r14+LN_KIND],LKS_DEAD
	je	.dest
	mov	qword [r14+LN_RETRY],0
	call	ln_post
	jmp	.dest
.out:
	pop	r14
	pop	rbx
.done:
	ret
