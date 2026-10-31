; TLS towards the backends (the client side), on both engines. When a request's
; pool has a `tls { }` block, the upstream connection runs a TLS 1.3 client
; handshake (src/tls/client.inc) before the request goes out, and the
; application keys are handed to the kernel's TLS (kTLS) so the proxy data
; path writes and reads plaintext exactly as on a plain backend.
;
;   HS_UTLS_HELLO   the ClientHello has been sent
;   HS_UTLS_FLIGHT  reading and decrypting the server's flight
;   HS_UTLS_FIN     the client Finished has been sent
;   HS_UTLS_KTLS    the keys are going to the kernel
;
; The server certificate is verified: the CertificateVerify and the server
; Finished (tlsc_verify), the chain up to the pool's trust anchor
; (cert_chain_verify), the validity window (cert_time_valid) and, when an
; SNI is configured, the host name (cert_match_host). Any failure answers
; the client 502 rather than proxying over an unverified connection.
;
; The handshake workspace lives in the session's buffers past the
; downstream TLS area (HB_UPTLS), so a client on user-space records and a
; TLS backend work together; its pages are touched only by this.

HS_UTLS_HELLO	:= 23
HS_UTLS_FLIGHT	:= 24
HS_UTLS_FIN	:= 25
HS_UTLS_KTLS	:= 26
HS_UTLS12_FIN	:= 30				; 1.2: our flight sent, reading the server's
HS_UTLS12_RX	:= 31				; 1.2: the server's CCS + Finished are in

HB_UPTLS	:= 1 shl 17			; past the downstream TLS area (records, 1.2 state)
assert HB_C12 + C12_SIZE <= HB_UPTLS
HB_UTC		:= HB_UPTLS			; the upstream handshake TC block
HB_USNAP	:= HB_UTC + TC_FULL		; the post-ClientHello transcript snapshot
HB_UWORK	:= HB_USNAP + SHA256_CTX_SIZE	; ClientHello (~1.7 KB) / Finished / crypto_info / time
HB_UDEC		:= HB_UWORK + 2048		; the decrypted server handshake
assert HB_UDEC + H_UP_CAP <= 1 shl HB_SHIFT		; the flight is opened into it whole
; after the handshake the area is free; the control-record drain reuses it
HB_UMSG		:= HB_UTC			; struct msghdr (56)
HB_UIOV		:= HB_UMSG + 56			; struct iovec (16)
HB_UCTL		:= HB_UIOV + 16			; cmsg buffer (64)
HB_UDISC	:= HB_UCTL + 64			; the discarded record payload (4096)

; reached from on_s_connect (http listeners): a plain pool goes straight on
http_up_ready:
	call	session_ptr
	mov	eax,[rax+S_POOL]
	imul	rax,rax,PL_SIZE
	lea	rcx,[g_pools]
	cmp	dword [rcx+rax+PL_TLS],0
	je	http_connected
	jmp	http_uptls_start

; the upstream is connected: build and send the ClientHello
http_uptls_start:
	h_rec
	cmp	dword [g_no_ktls],0		; upstream TLS needs the kernel tls module
	jne	.unavail
	mov	r14,[r15+H_BUF]
	call	session_ptr
	mov	eax,[rax+S_POOL]
	imul	rax,rax,PL_SIZE
	lea	rcx,[g_pools]
	add	rcx,rax
	lea	rdi,[r14+HB_UTC]
	lea	rsi,[r14+HB_UWORK]
	mov	eax,[rcx+PL_H2]			; `protocol h2`: ALPN offers h2
	mov	[g_tlsc_h2],eax
	mov	rdx,[rcx+PL_TLS_SNI]
	mov	ecx,[rcx+PL_TLS_SNILEN]
	call	tlsc_client_hello
	mov	dword [g_tlsc_h2],0
	test	eax,eax
	jz	.unavail
	h_rec
	mov	[r15+H_UHLEN],eax
	mov	r14,[r15+H_BUF]
	lea	rsi,[r14+HB_UTC+TC_SHA]		; snapshot the transcript for re-runs
	lea	rdi,[r14+HB_USNAP]
	mov	ecx,SHA256_CTX_SIZE
	rep	movsb
	mov	dword [r15+H_UPLEN],0		; the flight accumulator
	mov	dword [r15+H_STATE],HS_UTLS_HELLO
	mov	esi,[r15+H_UHLEN]
	lea	rdi,[r14+HB_UWORK]
	mov	ecx,SIDE_UP
	jmp	h_send
.unavail:
	mov	edi,ebx
	call	uptls_log_fail
	jmp	http_connect_failed

; the ClientHello went out: read the server's flight
http_uptls_hello_sent:
	h_rec
	mov	dword [r15+H_STATE],HS_UTLS_FLIGHT
	mov	r14,[r15+H_BUF]
	lea	rdi,[r14+HB_UP]
	mov	esi,H_UP_CAP
	mov	ecx,SIDE_UP
	jmp	h_recv

; more of the server's flight arrived: process it, and when it is whole,
; verify the certificate and send the client Finished
http_uptls_flight_in:
	h_rec
	test	rax,rax
	jle	.gone
	add	[r15+H_UPLEN],eax
	mov	r14,[r15+H_BUF]
	lea	rsi,[r14+HB_USNAP]		; restore the post-ClientHello transcript
	lea	rdi,[r14+HB_UTC+TC_SHA]
	mov	ecx,SHA256_CTX_SIZE
	rep	movsb
	lea	rsi,[r14+HB_UP]			; a TLS 1.2 server takes a different path
	mov	edx,[r15+H_UPLEN]
	call	tlsc_is_tls12
	test	eax,eax
	jnz	.tls12
	lea	rdi,[r14+HB_UTC]		; (re)process whatever is present
	lea	rsi,[r14+HB_UP]
	mov	edx,[r15+H_UPLEN]
	lea	rcx,[r14+HB_UDEC]
	call	tlsc_server_flight
	test	eax,eax
	jz	.more
	mov	r13d,eax
	mov	[r14+HB_UTC+TC_FEND],edx
	lea	rsi,[r14+HB_UDEC]
	mov	edx,eax
	call	tlsc_flight_complete
	test	eax,eax
	jz	.more
	; what came after the server Finished (a NewSessionTicket) must be
	; whole records: they are opened here, the kernel takes what follows
	mov	ecx,[r14+HB_UTC+TC_FEND]
.after:
	cmp	ecx,[r15+H_UPLEN]
	je	.flight
	lea	eax,[rcx+5]
	cmp	eax,[r15+H_UPLEN]
	ja	.more
	movzx	eax,word [r14+HB_UP+rcx+3]
	xchg	al,ah
	lea	ecx,[rcx+rax+5]
	cmp	ecx,[r15+H_UPLEN]
	ja	.more
	jmp	.after
.flight:
	lea	rdi,[r14+HB_UTC]		; CertificateVerify + server Finished
	lea	rsi,[r14+HB_UDEC]
	mov	edx,r13d
	call	tlsc_verify
	test	eax,eax
	jz	.badcert
	call	session_ptr			; chain to the pool's trust anchor
	mov	eax,[rax+S_POOL]
	imul	rax,rax,PL_SIZE
	lea	rcx,[g_pools]
	add	rcx,rax
	cmp	dword [rcx+PL_TLS_HASANCHOR],0
	je	.badcert
	lea	rdi,[rcx+PL_TLS_ANCHOR]
	mov	rsi,[r14+HB_UTC+TC_CLIST]
	mov	edx,[r14+HB_UTC+TC_CLISTLEN]
	call	cert_chain_verify
	test	eax,eax
	jz	.badcert
	lea	rdi,[r14+HB_UWORK]		; the validity window
	call	alog_fmt_time
	h_rec
	mov	r14,[r15+H_BUF]
	lea	rsi,[r14+HB_UWORK]		; ISO time -> 14 digits YYYYMMDDHHMMSS
	lea	rdi,[r14+HB_UWORK+32]
	lea	r9,[uptls_tdig]
	xor	ecx,ecx
.compact:
	movzx	eax,byte [r9+rcx]
	mov	al,[rsi+rax]
	mov	[rdi+rcx],al
	inc	ecx
	cmp	ecx,14
	jb	.compact
	mov	rsi,[r14+HB_UTC+TC_LEAF]
	mov	edx,[r14+HB_UTC+TC_LEAFLEN]
	lea	rdi,[r14+HB_UWORK+32]
	call	cert_time_valid
	test	eax,eax
	jz	.badcert
	call	session_ptr			; the host name, when an SNI is set
	mov	eax,[rax+S_POOL]
	imul	rax,rax,PL_SIZE
	lea	rcx,[g_pools]
	add	rcx,rax
	mov	edx,[rcx+PL_TLS_SNILEN]
	test	edx,edx
	jz	.verified
	mov	rdi,[rcx+PL_TLS_SNI]
	mov	ecx,edx
	mov	rsi,[r14+HB_UTC+TC_LEAF]
	mov	edx,[r14+HB_UTC+TC_LEAFLEN]
	call	cert_match_host
	test	eax,eax
	jz	.badcert
.verified:
	lea	rdi,[r14+HB_UTC]		; the client Finished
	lea	rsi,[r14+HB_UWORK]
	call	tlsc_finish
	h_rec
	mov	[r15+H_UHLEN],eax
	mov	r14,[r15+H_BUF]			; the records after the server Finished:
	mov	r13d,[r14+HB_UTC+TC_FEND]	; tickets (not kept), nothing else
.ticket:
	cmp	r13d,[r15+H_UPLEN]
	jae	.tickets_done
	movzx	eax,word [r14+HB_UP+r13+3]
	xchg	al,ah
	push	rax
	lea	rdi,[r14+HB_UTC]
	lea	rsi,[r14+HB_UP+r13]
	call	tlsc_open
	pop	rdx
	test	eax,eax
	jz	.badcert
	cmp	r8d,22				; application data before our Finished:
	jne	.badcert			; not taken
	h_rec
	mov	r14,[r15+H_BUF]
	lea	r13d,[r13+rdx+5]
	jmp	.ticket
.tickets_done:
	mov	dword [r15+H_STATE],HS_UTLS_FIN
	mov	esi,[r15+H_UHLEN]
	mov	r14,[r15+H_BUF]
	lea	rdi,[r14+HB_UWORK]
	mov	ecx,SIDE_UP
	jmp	h_send
.tls12:
	; a TLS 1.2 backend: tlsc12_flight parses ServerHello..ServerHelloDone,
	; verifies the ServerKeyExchange, derives the keys and writes our flight
	; (ClientKeyExchange + CCS + Finished) to HB_UDEC
	lea	rdi,[r14+HB_UTC]
	lea	rsi,[r14+HB_UP]
	mov	edx,[r15+H_UPLEN]
	lea	rcx,[r14+HB_UDEC]
	call	tlsc12_flight
	test	eax,eax
	jz	.more
	mov	[r15+H_UHLEN],eax
	; the chain to the pool's trust anchor (the 1.2 list reframed to 1.3)
	call	session_ptr
	mov	eax,[rax+S_POOL]
	imul	rax,rax,PL_SIZE
	lea	rcx,[g_pools]
	add	rcx,rax
	cmp	dword [rcx+PL_TLS_HASANCHOR],0
	je	.badcert
	mov	r14,[r15+H_BUF]
	push	rcx
	lea	rdi,[r14+HB_UDEC+4096]
	mov	rsi,[r14+HB_UTC+TC_CLIST]
	mov	edx,[r14+HB_UTC+TC_CLISTLEN]
	call	tlsc12_reframe_chain
	pop	rcx
	lea	rdi,[rcx+PL_TLS_ANCHOR]
	lea	rsi,[r14+HB_UDEC+4096]
	mov	edx,eax
	call	cert_chain_verify
	test	eax,eax
	jz	.badcert
	lea	rdi,[r14+HB_UWORK]		; the validity window (HB_UWORK is free here)
	call	alog_fmt_time
	h_rec
	mov	r14,[r15+H_BUF]
	lea	rsi,[r14+HB_UWORK]
	lea	rdi,[r14+HB_UWORK+32]
	lea	r9,[uptls_tdig]
	xor	ecx,ecx
.compact12:
	movzx	eax,byte [r9+rcx]
	mov	al,[rsi+rax]
	mov	[rdi+rcx],al
	inc	ecx
	cmp	ecx,14
	jb	.compact12
	mov	rsi,[r14+HB_UTC+TC_LEAF]
	mov	edx,[r14+HB_UTC+TC_LEAFLEN]
	lea	rdi,[r14+HB_UWORK+32]
	call	cert_time_valid
	test	eax,eax
	jz	.badcert
	call	session_ptr			; the host name, when an SNI is set
	mov	eax,[rax+S_POOL]
	imul	rax,rax,PL_SIZE
	lea	rcx,[g_pools]
	add	rcx,rax
	mov	edx,[rcx+PL_TLS_SNILEN]
	test	edx,edx
	jz	.send12
	mov	rdi,[rcx+PL_TLS_SNI]
	mov	ecx,edx
	mov	rsi,[r14+HB_UTC+TC_LEAF]
	mov	edx,[r14+HB_UTC+TC_LEAFLEN]
	call	cert_match_host
	test	eax,eax
	jz	.badcert
.send12:
	mov	r14,[r15+H_BUF]
	lea	rsi,[r14+HB_UTC+TC_SHA]		; snapshot the transcript through the
	lea	rdi,[r14+HB_USNAP]		; client Finished (for the server Finished)
	mov	ecx,SHA256_CTX_SIZE
	rep	movsb
	mov	dword [r15+H_STATE],HS_UTLS12_FIN
	mov	esi,[r15+H_UHLEN]
	lea	rdi,[r14+HB_UDEC]		; ClientKeyExchange + CCS + Finished
	mov	ecx,SIDE_UP
	jmp	h_send
.more:
	mov	eax,[r15+H_UPLEN]
	cmp	eax,H_UP_CAP
	jae	.badcert
	mov	r14,[r15+H_BUF]
	lea	rdi,[r14+HB_UP]
	add	rdi,rax
	mov	esi,H_UP_CAP
	sub	esi,eax
	mov	ecx,SIDE_UP
	jmp	h_recv
.badcert:
.gone:
	mov	edi,ebx
	call	uptls_log_fail
	jmp	http_connect_failed

; the client Finished went out: hand the application keys to the kernel
http_uptls_fin_sent:
	h_rec
	mov	r14,[r15+H_BUF]
	lea	rdi,[r14+HB_UTC]
	lea	rsi,[r14+HB_UWORK]		; TX crypto_info
	lea	rdx,[r14+HB_UWORK+KTLS_INFO]	; RX crypto_info
	call	tlsc_ktls_info
.ktls_chain:					; TLS 1.2 joins here, crypto_info already filled
	h_rec
	mov	dword [r15+H_STATE],HS_UTLS_KTLS
	cmp	dword [g_engine],ENGINE_EPOLL
	je	.epoll
	mov	dword [r15+H_ULPERR],0
	mov	edi,OP_H_ULP			; the TLS ULP (its errno kept)
	mov	r9d,IPPROTO_TCP
	mov	r10d,TCP_ULP
	lea	r11,[ktls_ulp]
	mov	r8d,4
	call	.sqe
	mov	r14,[r15+H_BUF]
	lea	r11,[r14+HB_UWORK]		; the TX keys
	mov	edi,OP_S_OPT
	mov	r9d,SOL_TLS
	mov	r10d,TLS_TX
	mov	r8d,KTLS_INFO
	call	.sqe
	mov	r14,[r15+H_BUF]
	lea	r11,[r14+HB_UWORK+KTLS_INFO]	; the RX keys (the chain ends here)
	mov	edi,OP_H_UKTLS
	mov	r9d,SOL_TLS
	mov	r10d,TLS_RX
	mov	r8d,KTLS_INFO
	call	.sqe
	and	byte [rax+SQE_FLAGS],not IOSQE_IO_LINK
	ret

; epoll: the same three options, set at once on the upstream socket
.epoll:
	call	session_ptr
	mov	edi,[rax+S_UPFD]
	push	rdi
	mov	esi,IPPROTO_TCP
	mov	edx,TCP_ULP
	lea	r10,[ktls_ulp]
	mov	r8d,4
	mov	eax,SYS_setsockopt
	syscall
	pop	rdi
	cmp	eax,-ENOENT
	jne	@f
	mov	dword [g_no_ktls],1		; no tls module on this host
@@:
	test	eax,eax
	jnz	.efail
	push	rdi
	mov	esi,SOL_TLS
	mov	edx,TLS_TX
	mov	r10,[r15+H_BUF]
	add	r10,HB_UWORK
	mov	r8d,KTLS_INFO
	mov	eax,SYS_setsockopt
	syscall
	pop	rdi
	test	eax,eax
	jnz	.efail
	mov	esi,SOL_TLS
	mov	edx,TLS_RX
	mov	r10,[r15+H_BUF]
	add	r10,HB_UWORK + KTLS_INFO
	mov	r8d,KTLS_INFO
	mov	eax,SYS_setsockopt
	syscall
	test	eax,eax
	jnz	.efail
	mov	dword [r15+H_UPKTLS],1		; the upstream is a kTLS socket now
	mov	dword [r15+H_UPLEN],0
	jmp	http_connected
.efail:
	mov	edi,ebx
	call	uptls_log_fail
	jmp	http_connect_failed

; edi = op, r9d = level, r10d = option, r11 = value, r8d = length: one
; linked setsockopt on the upstream socket. rax = the SQE.
.sqe:
	push	r8
	push	r9
	push	r10
	push	r11
	mov	esi,ebx
	call	sess_sqe			; rax = SQE, rdx = session
	mov	ecx,SIDE_UP
	push	rax
	call	h_sqe_fd
	pop	rax
	pop	r11
	pop	r10
	pop	r9
	pop	r8
	or	byte [rax+SQE_FLAGS],IOSQE_IO_LINK
	mov	byte [rax+SQE_OPCODE],IORING_OP_URING_CMD
	mov	dword [rax+SQE_CMD_OP],SOCKET_URING_OP_SETSOCKOPT
	mov	[rax+SQE_LEVEL],r9d
	mov	[rax+SQE_OPTNAME],r10d
	mov	[rax+SQE_OPTLEN],r8d
	mov	[rax+SQE_OPTVAL],r11
	ret

; TLS 1.2 upstream: our ClientKeyExchange + CCS + Finished went out; read
; the server's ChangeCipherSpec + Finished
http_uptls12_fin_sent:
	h_rec
	mov	dword [r15+H_STATE],HS_UTLS12_RX
	mov	dword [r15+H_UPLEN],0
	mov	r14,[r15+H_BUF]
	lea	rdi,[r14+HB_UP]
	mov	esi,H_UP_CAP
	mov	ecx,SIDE_UP
	jmp	h_recv

; the server's CCS + Finished arrived: verify it and hand the keys to kTLS
http_uptls12_rx:
	h_rec
	test	rax,rax
	jle	.gone12
	add	[r15+H_UPLEN],eax
	mov	r14,[r15+H_BUF]
	lea	rsi,[r14+HB_USNAP]		; restore the transcript (idempotent re-runs)
	lea	rdi,[r14+HB_UTC+TC_SHA]
	mov	ecx,SHA256_CTX_SIZE
	rep	movsb
	lea	rdi,[r14+HB_UTC]
	lea	rsi,[r14+HB_UP]
	mov	edx,[r15+H_UPLEN]
	call	tlsc12_server_finished
	test	eax,eax
	jnz	.ok12
	mov	eax,[r15+H_UPLEN]		; incomplete (or bad): read more, up to a cap
	cmp	eax,H_UP_CAP
	jae	.gone12
	mov	r14,[r15+H_BUF]
	lea	rdi,[r14+HB_UP]
	add	rdi,rax
	mov	esi,H_UP_CAP
	sub	esi,eax
	mov	ecx,SIDE_UP
	jmp	h_recv
.ok12:
	mov	r14,[r15+H_BUF]
	lea	rdi,[r14+HB_UTC]
	lea	rsi,[r14+HB_UWORK]		; TX crypto_info
	lea	rdx,[r14+HB_UWORK+KTLS_INFO]	; RX crypto_info
	call	tlsc12_ktls_info
	jmp	http_uptls_fin_sent.ktls_chain
.gone12:
	mov	edi,ebx
	call	uptls_log_fail
	jmp	http_connect_failed

; completion of the RX key: the upstream is now a kTLS socket
; ebx = session, r12d = generation, r14 = res (-ECANCELED if a link failed)
on_h_uktls:
	call	sess_complete
	jc	.out
	cmp	dword [rax+S_STATE],ST_CLOSING
	je	.closing
	h_rec
	test	r14,r14
	jns	.ok
	cmp	r14,-ECANCELED
	jne	.fail				; the RX key alone failed
	mov	eax,[r15+H_ULPERR]
	cmp	eax,-ENOENT
	jne	.fail
	mov	dword [g_no_ktls],1		; no tls module on this host
.fail:
	mov	edi,ebx
	call	uptls_log_fail
	jmp	http_connect_failed
.ok:
	mov	dword [r15+H_UPKTLS],1		; the upstream is a kTLS socket now
	mov	dword [r15+H_UPLEN],0		; the response buffer starts empty
	jmp	http_connected
.closing:
	mov	edi,ebx
	jmp	session_maybe_free
.out:
	ret

; edi = session: note an upstream TLS failure. Keeps rbx.
uptls_log_fail:
	push	rbx
	call	log_begin
	out_lit 'upstream TLS handshake failed'
	call	log_end
	pop	rbx
	ret

; a kTLS upstream recv returned -EIO: a control record (a NewSessionTicket)
; is next. Consume it with recvmsg -- which needs a control buffer, so the
; kernel hands the record over instead of refusing it -- and discard it.
http_updrain:
	h_rec
	mov	r14,[r15+H_BUF]
	lea	rax,[r14+HB_UDISC]		; iovec -> the discard buffer
	mov	[r14+HB_UIOV],rax
	mov	qword [r14+HB_UIOV+8],4096
	mov	qword [r14+HB_UMSG],0		; msg_name
	mov	qword [r14+HB_UMSG+8],0		; msg_namelen
	lea	rax,[r14+HB_UIOV]
	mov	[r14+HB_UMSG+16],rax		; msg_iov
	mov	qword [r14+HB_UMSG+24],1		; msg_iovlen
	lea	rax,[r14+HB_UCTL]
	mov	[r14+HB_UMSG+32],rax		; msg_control
	mov	qword [r14+HB_UMSG+40],64	; msg_controllen
	mov	dword [r14+HB_UMSG+48],0		; msg_flags
	mov	edi,OP_H_UDRAIN
	mov	esi,ebx
	call	sess_sqe			; rax = SQE, rdx = session
	mov	ecx,SIDE_UP
	push	rax
	call	h_sqe_fd
	pop	rax
	mov	byte [rax+SQE_OPCODE],IORING_OP_RECVMSG
	mov	r14,[r15+H_BUF]
	lea	rcx,[r14+HB_UMSG]
	mov	[rax+SQE_ADDR],rcx
	mov	dword [rax+SQE_LEN],0
	mov	dword [rax+SQE_OP_FLAGS],0
	ret

; the control record is consumed: retry the upstream recv the proxy wanted
; ebx = session, r12d = generation, r14 = res
on_h_udrain:
	call	sess_complete
	jc	.out
	cmp	dword [rax+S_STATE],ST_CLOSING
	je	.closing
	h_rec
	test	r14,r14
	js	.err
	mov	rdi,[r15+H_URBUF]
	mov	esi,[r15+H_URROOM]
	mov	ecx,SIDE_UP
	jmp	h_recv
.err:
	mov	edi,502
	jmp	http_error
.closing:
	mov	edi,ebx
	jmp	session_maybe_free
.out:
	ret

rodata
	uptls_tdig	db 0,1,2,3,5,6,8,9,11,12,14,15,17,18
end rodata
