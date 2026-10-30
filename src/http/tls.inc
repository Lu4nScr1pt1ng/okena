; HTTPS: the TLS 1.3 handshake of an http listener with tls { }, before
; its first request, then the connection handed to the kernel's TLS
; (kTLS): from there on the kernel seals and opens the records and the
; exchange state machine (proxy.inc) reads and writes plaintext as on any
; connection, on both engines.
;
;   HS_TLS_HELLO   reading the ClientHello into IN
;   HS_TLS_FLIGHT  writing the server's flight (from OUT)
;   HS_TLS_FIN     peeking at what the client sent after it
;   HS_TLS_TAKE    taking it, up to the end of its Finished and no further:
;                  what follows (often the first request, sent with the
;                  Finished) stays in the socket for the kernel to open
;   HS_TLS_KTLS    the keys going to the kernel (io_uring)
;   HS_TLS_RETRY   writing a HelloRetryRequest, then a second ClientHello
;   HS_TLS_ALERT   writing an alert, then closing
;
; Without kTLS (no tls module on the host, or the kernel refused the keys)
; the records are sealed and opened here instead: h_recv and h_send on the
; client side go through utls_recv / utls_send, which hand plaintext to
; the exchange the way the socket would (results queued, delivered by the
; main loop), so proxy.inc does not know the difference.
;
; The handshake's state (TS_*) and the keys for the kernel live at the end
; of the session's buffers, unused before the first request; they are
; wiped once the kernel has the keys. The header timeout (PH_HEAD), armed
; when the connection arrives, bounds the handshake too.

HS_TLS_HELLO	:= 15
HS_TLS_FLIGHT	:= 16
HS_TLS_FIN	:= 17
HS_TLS_TAKE	:= 18
HS_TLS_KTLS	:= 19
HS_TLS_RETRY	:= 20
HS_TLS_ALERT	:= 21
HS_PT_HELLO	:= 22				; tls passthrough: reading the ClientHello
HS_TLS_LAST	:= 22				; the last of them (phase expiry)

HB_TLS		:= 1 shl 16			; the TLS area, after the HTTP buffers
HB_TS		:= HB_TLS			; the handshake, then the record keys
HB_KTLS		:= HB_TS + TS_SIZE		; the kernel's crypto_info: TX, then RX
KTLS_INFO	:= 40				; tls12_crypto_info_aes_gcm_128
KTLS_INFO_CP	:= 56				; tls12_crypto_info_chacha20_poly1305
KTLS_SLOT	:= KTLS_INFO_CP			; TX and RX slots of a TLS 1.3 connection
HB_RXC		:= HB_TLS + 1536		; user-space records: ciphertext in
UTLS_RX_CAP	:= TLS_RECORD_MAX + 256 + 5 + 251	; one whole record (17 KiB)
HB_TXC		:= HB_RXC + UTLS_RX_CAP	; and out, two records at a time
UTLS_TX_RECS	:= 2
UTLS_TX_CAP	:= UTLS_TX_RECS * (TLS_RECORD_MAX + 22)
H_TLS_ROOM	:= HB_TLS - HB_OUT		; the flight is built in OUT and after it
assert HB_KTLS + 2 * KTLS_SLOT <= HB_RXC
assert HB_TXC + UTLS_TX_CAP <= 1 shl HB_SHIFT
assert H_TLS_ROOM >= 2 * (TLS_CHAIN_MAX + 192) + 512

SOL_TLS		:= 282
TLS_TX		:= 1
TLS_RX		:= 2
TCP_ULP		:= 31
ENOTCONN	:= 107

bss
	align 4
	g_no_ktls	dd ?			; this worker saw the kernel refuse kTLS
	g_no_ktls_cp	dd ?			; ... refuse ChaCha20-Poly1305 keys only
end bss

rodata
	ktls_ulp	db 'tls',0
end rodata
cstring env_okena_ktls, 'OKENA_KTLS='

; ebx = session: rax = its listener's credentials (a TL entry), or 0 when
; the listener has no tls. Keeps everything but rax and rcx.
http_tls_cred:
	call	session_ptr
	mov	eax,[rax+S_LST]
	imul	rax,rax,LS_SIZE
	mov	eax,[g_listeners+rax+LS_TLS]
	test	eax,eax
	jz	.none
	dec	eax
	imul	rax,rax,TL_SIZE
	lea	rax,[g_tls+rax]
.none:
	ret

; ebx = session: rax = nonzero when its tcp listener has tls (termination
; or passthrough). Keeps everything but rax and rcx.
tcp_tls_wanted:
	call	session_ptr
	mov	eax,[rax+S_LST]
	imul	rax,rax,LS_SIZE
	mov	ecx,[g_listeners+rax+LS_PT]
	mov	eax,[g_listeners+rax+LS_TLS]
	or	eax,ecx
	ret

; ebx = session: a new connection on a tcp listener with tls. The
; handshake runs on the http machinery (this file), then the session goes
; on as an L4 one over kTLS. The header timeout bounds the handshake.
tcp_tls_start:
	call	session_ptr
	mov	dword [rax+S_STATE],ST_OPEN	; no upstream yet
	or	dword [rax+S_FLAGS],SF_TLS_HS
	h_rec
	mov	eax,ebx
	shl	rax,HB_SHIFT
	add	rax,[g_hbuf_base]
	mov	[r15+H_BUF],rax
	xor	eax,eax
	mov	[r15+H_INLEN],eax
	mov	[r15+H_INOFF],eax
	mov	[r15+H_FLAGS],eax
	mov	[r15+H_UTLS],eax
	mov	edi,ebx
	mov	esi,PH_HEAD
	call	ph_arm
	call	session_ptr
	mov	eax,[rax+S_LST]
	imul	rax,rax,LS_SIZE
	h_rec
	cmp	dword [g_listeners+rax+LS_PT],0
	je	http_tls_start
	mov	dword [r15+H_STATE],HS_PT_HELLO	; passthrough: just its ClientHello
	jmp	http_tls_read

; ebx = session, r15 = its record, a new connection on a tls listener.
http_tls_start:
	mov	rdi,[r15+H_BUF]
	add	rdi,HB_TS
	mov	ecx,TS_SIZE
	xor	eax,eax
	rep	stosb
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_TLS_HS
	jnz	@f				; tcp: no application protocol to name
	mov	rax,[r15+H_BUF]
	mov	dword [rax+HB_TS+TS_FLAGS],TF_ALPN_H1
@@:
	mov	dword [r15+H_STATE],HS_TLS_HELLO
; read more of the ClientHello
http_tls_read:
	mov	esi,H_IN_CAP
	sub	esi,[r15+H_INLEN]
	jz	http_tls_close
	mov	edi,[r15+H_INLEN]
	add	rdi,[r15+H_BUF]			; HB_IN is at 0
	mov	ecx,SIDE_CLIENT
	jmp	h_recv

http_tls_close:
	mov	edi,ebx
	jmp	session_close

; ebx = session, rax = bytes read (http_recv_done in HS_TLS_HELLO).
http_tls_hello_in:
	test	rax,rax
	jle	http_tls_close
	add	[r15+H_INLEN],eax
	mov	edi,ebx
	call	idle_touch
	h_rec
	jmp	http_tls_hello_budget		; now, or queued (hsbudget.inc)

; ebx = session, r15 = its record: the handshake on what IN holds
http_tls_hello_go:
	call	http_tls_cred
	mov	rsi,rax
	mov	rdi,[r15+H_BUF]
	mov	rdx,rdi
	lea	r8,[rdi+HB_OUT]
	add	rdi,HB_TS
	mov	ecx,[r15+H_INLEN]
	mov	r9d,H_TLS_ROOM
	call	tls_hello
	cmp	eax,TH_MORE
	je	http_tls_read
	cmp	eax,TH_TLS12
	je	http_tls12_hello
	mov	ecx,HS_TLS_FLIGHT
	cmp	eax,TH_SEND
	je	@f
	mov	ecx,HS_TLS_RETRY
	cmp	eax,TH_RETRY
	je	@f
	mov	ecx,HS_TLS_ALERT
@@:
	mov	[r15+H_STATE],ecx
	test	edx,edx
	jz	http_tls_close			; refused, and nothing to say
	mov	esi,edx
	mov	rdi,[r15+H_BUF]
	add	rdi,HB_OUT
	mov	ecx,SIDE_CLIENT
	jmp	h_send

; a HelloRetryRequest is out (http_send_done in HS_TLS_RETRY): the client's
; second ClientHello
http_tls_retry_sent:
	mov	dword [r15+H_INLEN],0
	mov	dword [r15+H_STATE],HS_TLS_HELLO
	jmp	http_tls_read

; the flight is out (http_send_done in HS_TLS_FLIGHT): the client's turn
http_tls_flight_sent:
	mov	dword [r15+H_INLEN],0
; peek at what the client sent after what IN holds
http_tls_peek:
	mov	dword [r15+H_STATE],HS_TLS_FIN
	mov	esi,H_IN_CAP
	sub	esi,[r15+H_INLEN]
	jz	http_tls_close
	mov	edi,[r15+H_INLEN]
	add	rdi,[r15+H_BUF]
	mov	ecx,SIDE_CLIENT
	jmp	h_recv_peek

; rax = bytes peeked after IN's H_INLEN (http_recv_done in HS_TLS_FIN):
; take them up to the end of the first record that is not a
; ChangeCipherSpec (the Finished), or all of them while that record's end
; is not known yet.
http_tls_fin_peeked:
	test	rax,rax
	jle	http_tls_close
	mov	edi,ebx
	push	rax
	call	idle_touch
	pop	rax
	h_rec
	mov	rsi,[r15+H_BUF]
	mov	edx,[r15+H_INLEN]
	add	edx,eax				; edx = the end of what is there
	xor	ecx,ecx				; ecx = a record's start
.record:
	mov	eax,edx
	sub	eax,ecx
	cmp	eax,5
	jb	.all
	movzx	eax,word [rsi+rcx+3]
	rol	ax,8
	lea	eax,[rcx+rax+5]			; its end
	cmp	eax,H_IN_CAP
	ja	http_tls_close
	cmp	byte [rsi+rcx],20
	jne	.finished
	mov	ecx,eax
	cmp	ecx,edx
	jb	.record
.all:
	mov	eax,edx
	jmp	.take
.finished:
	cmp	eax,edx
	jbe	.take
	mov	eax,edx
.take:
	mov	esi,eax
	sub	esi,[r15+H_INLEN]
	mov	dword [r15+H_STATE],HS_TLS_TAKE
	mov	edi,[r15+H_INLEN]
	add	rdi,[r15+H_BUF]
	mov	ecx,SIDE_CLIENT
	jmp	h_recv

; rax = bytes taken (http_recv_done in HS_TLS_TAKE)
http_tls_fin_in:
	test	rax,rax
	jle	http_tls_close
	add	[r15+H_INLEN],eax
	mov	rdi,[r15+H_BUF]
	mov	rsi,rdi
	add	rdi,HB_TS
	mov	ecx,[r15+H_INLEN]
	call	tls_finished
	cmp	eax,TH_MORE
	je	http_tls_peek
	cmp	eax,TH_DONE
	jne	http_tls_close			; forged, or an alert
	cmp	edx,[r15+H_INLEN]
	jne	http_tls_close
	mov	rax,[r15+H_BUF]
	mov	rax,[rax+HB_TS+TS_CERT]		; what SNI chose: Host is checked against it
	mov	[r15+H_SNICERT],rax

	; The keys for the kernel: struct tls12_crypto_info_aes_gcm_128
	; { version, cipher, iv[8] (the IV's last 8), key[16], salt[4] (its
	; first 4), rec_seq[8] }, or tls12_crypto_info_chacha20_poly1305
	; { version, cipher, iv[12], key[32], rec_seq[8] }.
	mov	r8,[r15+H_BUF]
	lea	rsi,[r8+HB_TS+TS_TX_KEY]
	lea	rdi,[r8+HB_KTLS]
	mov	rdx,[r8+HB_TS+TS_TX_SEQ]	; 1 after a ticket
	call	.info
	lea	rsi,[r8+HB_TS+TS_RX_KEY]
	lea	rdi,[r8+HB_KTLS+KTLS_SLOT]
	mov	rdx,[r8+HB_TS+TS_RX_SEQ]
	call	.info
	cmp	dword [g_no_ktls],0
	jne	http_utls_start
	cmp	dword [r8+HB_TS+TS_SUITE],0
	je	@f
	cmp	dword [g_no_ktls_cp],0		; the kernel has no ChaCha20-Poly1305
	jne	http_utls_start
@@:
	cmp	dword [g_engine],ENGINE_EPOLL
	je	.epoll

	; io_uring: three socket commands, linked: the ULP, TX, then RX,
	; whose completion goes on
	mov	dword [r15+H_STATE],HS_TLS_KTLS
	mov	dword [r15+H_ULPERR],0
	mov	edi,OP_H_ULP
	mov	r9d,IPPROTO_TCP
	mov	r10d,TCP_ULP
	lea	r11,[ktls_ulp]
	mov	r8d,4
	call	.sqe
	mov	r11,[r15+H_BUF]
	add	r11,HB_KTLS
	mov	edi,OP_S_OPT
	mov	r9d,SOL_TLS
	mov	r10d,TLS_TX
	call	.len
	call	.sqe
	mov	r11,[r15+H_BUF]
	add	r11,HB_KTLS + KTLS_SLOT
	mov	edi,OP_H_KTLS
	mov	r9d,SOL_TLS
	mov	r10d,TLS_RX
	call	.len
	call	.sqe
	and	byte [rax+SQE_FLAGS],not IOSQE_IO_LINK	; the chain ends here
	ret

; r8d = the length of this connection's crypto_info. Keeps the rest.
.len:
	mov	r8,[r15+H_BUF]
	cmp	dword [r8+HB_TS+TS_SUITE],0
	mov	r8d,KTLS_INFO
	je	@f
	mov	r8d,KTLS_INFO_CP
@@:
	ret

; edi = op, r9d = level, r10d = option, r11 = value, r8d = its length:
; one setsockopt on the client, linked to the next. rax = the SQE.
.sqe:
	push	r8
	push	r9
	push	r10
	push	r11
	mov	esi,ebx
	call	sess_sqe			; rax = SQE, rdx = session
	xor	ecx,ecx
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

; rsi = key (16 or 32), IV (12) at +TS_IVOFF; rdx = the next record's
; sequence number; rdi = the crypto info to fill; r8 = the session's
; buffers (the suite). Keeps r8.
.info:
	bswap	rdx				; rec_seq, big endian
	cmp	dword [r8+HB_TS+TS_SUITE],0
	jne	.info_cp
	mov	dword [rdi],0x00330304		; TLS 1.3, TLS_CIPHER_AES_GCM_128
	mov	rax,[rsi+TS_IVOFF+4]
	mov	[rdi+4],rax
	movdqu	xmm0,[rsi]
	movdqu	[rdi+12],xmm0
	mov	eax,[rsi+TS_IVOFF]
	mov	[rdi+28],eax
	mov	[rdi+32],rdx
	ret
.info_cp:
	mov	dword [rdi],0x00360304		; TLS 1.3, TLS_CIPHER_CHACHA20_POLY1305
	mov	rax,[rsi+TS_IVOFF]		; iv[12]
	mov	[rdi+4],rax
	mov	eax,[rsi+TS_IVOFF+8]
	mov	[rdi+12],eax
	movdqu	xmm0,[rsi]			; key[32]
	movdqu	[rdi+16],xmm0
	movdqu	xmm0,[rsi+16]
	movdqu	[rdi+32],xmm0
	mov	[rdi+48],rdx
	ret

.epoll:
	call	session_ptr
	mov	edi,[rax+S_CLIENT]
	push	rdi
	mov	esi,IPPROTO_TCP
	mov	edx,TCP_ULP
	lea	r10,[ktls_ulp]
	mov	r8d,4
	mov	eax,SYS_setsockopt
	syscall
	pop	rdi
	cmp	eax,-ENOENT
	je	.refused			; no tls module: records here from now on
	test	eax,eax
	jnz	http_tls_close			; this connection is gone (ENOTCONN...)
	push	rdi
	mov	esi,SOL_TLS
	mov	edx,TLS_TX
	mov	r10,[r15+H_BUF]
	add	r10,HB_KTLS
	call	.len
	mov	eax,SYS_setsockopt
	syscall
	pop	rdi
	test	eax,eax
	jnz	.tx_refused			; no TX: the socket is still plain TCP
	mov	esi,SOL_TLS
	mov	edx,TLS_RX
	mov	r10,[r15+H_BUF]
	add	r10,HB_KTLS + KTLS_SLOT
	call	.len
	mov	eax,SYS_setsockopt
	syscall
	test	eax,eax
	jnz	http_tls_close			; TX is the kernel's already: no way back
	jmp	http_tls_established
.refused:
	mov	dword [g_no_ktls],1
	jmp	http_utls_start
; the kernel took the ULP but not the keys: no kTLS for this suite, then
.tx_refused:
	mov	rax,[r15+H_BUF]
	cmp	dword [rax+HB_TS+TS_SUITE],0
	je	.refused
	mov	dword [g_no_ktls_cp],1		; ChaCha20-Poly1305 only: AES still goes
	jmp	http_utls_start

; completion of the RX key (io_uring): ebx = session, r12d = generation,
; r14 = res (-ECANCELED when an earlier link failed)
on_h_ktls:
	call	sess_complete
	jc	.out
	cmp	dword [rax+S_STATE],ST_CLOSING
	je	.closing
	h_rec
	test	r14,r14
	jns	http_tls_established
	cmp	r14,-ECANCELED
	jne	http_tls_close			; RX alone failed: TX is the kernel's
	mov	eax,[r15+H_ULPERR]
	cmp	eax,-ENOENT
	je	.no_module
	test	eax,eax
	jnz	http_tls_close			; the ULP failed for this connection only
	mov	rax,[r15+H_BUF]			; (ENOTCONN: the client left); else TX
	cmp	dword [rax+HB_TS+TS_SUITE],0	; refused: for every suite, or for
	je	.no_module			; ChaCha20-Poly1305 only
	mov	dword [g_no_ktls_cp],1
	jmp	http_utls_start
.no_module:
	mov	dword [g_no_ktls],1
	jmp	http_utls_start
.closing:
	mov	edi,ebx
	jmp	session_maybe_free
.out:
	ret

; completion of the TLS ULP (io_uring): its result, for on_h_ktls (the
; chain's last completion) to tell a kernel without kTLS (ENOENT) from a
; connection already gone (ENOTCONN).
on_h_ulp:
	call	sess_complete
	jc	.out
	cmp	dword [rax+S_STATE],ST_CLOSING
	je	.closing
	h_rec
	mov	[r15+H_ULPERR],r14d
	ret
.closing:
	mov	edi,ebx
	jmp	session_maybe_free
.out:
	ret

; ebx = session: the kernel has the keys; requests from here on.
http_tls_established:
	h_rec
	mov	rdi,[r15+H_BUF]
	add	rdi,HB_TS			; the kernel has the keys: none kept here
	mov	ecx,TS_SIZE + 2 * KTLS_SLOT
	call	secure_zero
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_TLS_HS
	jnz	.tcp
	h_rec
	xor	eax,eax
	mov	[r15+H_INLEN],eax
	mov	[r15+H_INOFF],eax
	jmp	http_next_request
.tcp:
	; a tcp listener: now the upstream, bytes both ways in plaintext
	and	dword [rax+S_FLAGS],not SF_TLS_HS
	mov	dword [r15+H_STATE],0
	mov	edi,ebx
	call	ph_disarm
	call	session_ptr
	mov	dword [rax+S_STATE],ST_CONNECTING	; as accept leaves it: the connect's
	mov	edi,ebx					; completion is told apart by it
	cmp	dword [g_engine],ENGINE_EPOLL
	je	ep_connect
	jmp	session_connect

; Before serving: tls without the kernel's TLS (the module, "tls") works
; on http listeners, slower (said once), and not on tcp ones (exits with
; EXIT_CONFIG and why: their bytes move without okena seeing them).
tls_serve_check:
	push	rbx
	xor	ecx,ecx
	xor	edx,edx				; edx = listeners with tls
	xor	ebx,ebx				; ebx = tcp ones
.listener:
	cmp	ecx,[g_plan_listeners]
	jae	.scanned
	imul	rax,rcx,LS_SIZE
	inc	ecx
	cmp	dword [g_listeners+rax+LS_TLS],0
	je	.listener
	inc	edx
	cmp	dword [g_listeners+rax+LS_KIND],LK_HTTP
	je	.listener
	inc	ebx
	jmp	.listener
.scanned:
	test	edx,edx
	jz	.ok
	push	rdx
	call	tls_tickets_init		; before the workers fork: one key for all
	pop	rdx
	; OKENA_KTLS=off: records in user space even with the module (tests,
	; comparisons)
	lea	rdi,[env_okena_ktls]
	mov	esi,env_okena_ktls.len
	call	getenv
	test	rax,rax
	jz	.probe
	cmp	dword [rax],'off'
	je	.no_ktls
.probe:
	; TCP_ULP "tls" on a socket not connected: ENOTCONN when the kernel
	; has it, ENOENT when the module is not loaded
	mov	edi,AF_INET
	mov	esi,SOCK_STREAM
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	.ok				; no socket here: the workers will say
	push	rax
	mov	edi,eax
	mov	esi,IPPROTO_TCP
	mov	edx,TCP_ULP
	lea	r10,[ktls_ulp]
	mov	r8d,4
	mov	eax,SYS_setsockopt
	syscall
	pop	rdi
	push	rax
	mov	eax,SYS_close
	syscall
	pop	rax
	cmp	eax,-ENOENT
	je	.no_ktls
.ok:
	pop	rbx
	ret
.no_ktls:
	mov	dword [g_no_ktls],1		; the workers forked from here know
	test	ebx,ebx
	jnz	.tcp
	call	log_begin
	out_lit 'no kernel TLS (modprobe tls): TLS records are sealed in user space, which costs more CPU'
	pop	rbx
	jmp	log_end
.tcp:
	call	log_begin
	out_lit 'tls { } on a tcp listener needs kernel TLS, and its module is not loaded: modprobe tls (on the host, for a container)'
.refuse:
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; ------------------------------------------------- user-space records

; ebx = session, r15 = record, the handshake done: records here from now on.
http_utls_start:
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_TLS_HS
	jnz	http_tls_close			; tcp: kTLS or nothing (refused at the start)
	mov	rdi,[r15+H_BUF]
	add	rdi,HB_KTLS			; the keys meant for the kernel
	mov	ecx,2 * KTLS_SLOT
	call	secure_zero
	mov	rdi,[r15+H_BUF]
	add	rdi,HB_TS
	call	tls_records
	h_rec
	xor	eax,eax
	mov	[r15+H_RXC],eax
	mov	[r15+H_PTLEN],eax
	mov	[r15+H_TXLEN],eax
	mov	[r15+H_INLEN],eax
	mov	[r15+H_INOFF],eax
	mov	dword [r15+H_UTLS],1
	jmp	http_next_request

; ebx = session, rax = result: delivered to http_recv_plain (edx = 3) or
; http_send_plain (edx = 4) by the main loop.
macro utls_deliver kind
	mov	edx,kind
	xor	ecx,ecx
	jmp	hep_queue
end macro

; h_recv on the client of a user-space TLS session: rdi = buffer, esi =
; room. Plaintext goes there; the result comes like a socket's.
utls_recv:
	h_rec
	mov	[r15+H_UDST],rdi
	mov	[r15+H_UROOM],esi
; hand over plaintext, open a record, or read ciphertext
utls_rx_step:
	h_rec
	mov	ecx,[r15+H_PTLEN]
	test	ecx,ecx
	jnz	.hand_over
	mov	rdi,[r15+H_BUF]
	lea	rsi,[rdi+HB_RXC]
	add	rdi,HB_TS
	mov	edx,[r15+H_RXC]
	call	tls_open
	h_rec
	cmp	eax,TH_MORE
	je	.read
	cmp	eax,TH_FAIL
	je	.fail
	cmp	r8d,23				; application_data
	jne	.control
	mov	rax,[r15+H_BUF]
	lea	rax,[rax+HB_RXC]
	sub	rsi,rax
	mov	[r15+H_PTOFF],esi
	mov	[r15+H_PTLEN],ecx
	mov	[r15+H_PTEND],edx
	test	ecx,ecx
	jz	.drop				; an empty record
.hand_over:
	cmp	ecx,[r15+H_UROOM]
	jbe	@f
	mov	ecx,[r15+H_UROOM]
@@:
	mov	rdi,[r15+H_UDST]
	mov	rsi,[r15+H_BUF]
	mov	eax,[r15+H_PTOFF]
	lea	rsi,[rsi+HB_RXC+rax]
	add	[r15+H_PTOFF],ecx
	sub	[r15+H_PTLEN],ecx
	mov	eax,ecx
	rep	movsb
	push	rax
	cmp	dword [r15+H_PTLEN],0
	jne	@f
	call	.drop_record
@@:
	pop	rax
	utls_deliver 3
.drop:
	call	.drop_record
	jmp	utls_rx_step
.read:
	mov	esi,UTLS_RX_CAP
	sub	esi,[r15+H_RXC]
	jz	.fail
	mov	edi,[r15+H_RXC]
	add	rdi,[r15+H_BUF]
	add	rdi,HB_RXC
	xor	ecx,ecx
	jmp	h_recv_raw
.control:
	cmp	r8d,21				; an alert: close_notify, or worse
	jne	.fail				; post-handshake messages: not taken
	xor	eax,eax				; the end of the stream
	utls_deliver 3
.fail:
	mov	rax,-1
	utls_deliver 3
; the record whose plaintext is handed over leaves the buffer
.drop_record:
	mov	edx,[r15+H_PTEND]
	mov	ecx,[r15+H_RXC]
	sub	ecx,edx
	mov	[r15+H_RXC],ecx
	mov	rdi,[r15+H_BUF]
	add	rdi,HB_RXC
	lea	rsi,[rdi+rdx]
	rep	movsb
	mov	dword [r15+H_PTLEN],0
	ret

; ciphertext arrived (http_recv_done on the client side): rax = bytes
utls_rx_done:
	test	rax,rax
	jle	.end
	add	[r15+H_RXC],eax
	mov	edi,ebx
	call	idle_touch
	jmp	utls_rx_step
.end:
	utls_deliver 3				; the end of the stream, or an error

; h_send on the client of a user-space TLS session: rdi = bytes, esi =
; length. Sealed into records, two at a time, and sent.
utls_send:
	h_rec
	mov	[r15+H_TXP],rdi
	mov	[r15+H_TXLEN],esi
utls_tx_step:
	h_rec
	cmp	dword [r15+H_TXLEN],0
	je	.all_sent
	push	r12
	push	r13
	mov	r12,[r15+H_BUF]
	add	r12,HB_TXC			; r12 = the next record
	mov	r13d,UTLS_TX_RECS
.record:
	mov	ecx,[r15+H_TXLEN]
	cmp	ecx,TLS_RECORD_MAX
	jbe	@f
	mov	ecx,TLS_RECORD_MAX
@@:
	sub	[r15+H_TXLEN],ecx
	mov	edx,ecx
	lea	rdi,[r12+5]
	mov	rsi,[r15+H_TXP]
	add	[r15+H_TXP],rcx
	rep	movsb
	mov	rdi,[r15+H_BUF]
	add	rdi,HB_TS
	mov	rsi,r12
	mov	ecx,23
	call	tls_seal
	h_rec
	add	r12,rax
	cmp	dword [r15+H_TXLEN],0
	je	.send
	dec	r13d
	jnz	.record
.send:
	mov	rdi,[r15+H_BUF]
	add	rdi,HB_TXC
	mov	rsi,r12
	sub	rsi,rdi
	pop	r13
	pop	r12
	xor	ecx,ecx
	jmp	h_send_raw
.all_sent:
	xor	eax,eax
	utls_deliver 4

; records went out (http_send_done on the client side): rax = 0 or < 0
utls_tx_done:
	test	rax,rax
	jns	utls_tx_step
	utls_deliver 4

; ebx = session, r15 = record, g_hm = a request: CF when the client sent
; SNI and the certificate it got does not name the request's Host
; (domain fronting, or a connection reused for another host): 421.
; Keeps rbx and r12-r15.
http_sni_host_check:
	mov	rax,[r15+H_SNICERT]
	test	rax,rax
	jz	.ok
	lea	rcx,[g_hm]
	mov	edx,[rcx+HM_HOST]
	cmp	edx,-1
	je	.ok
	imul	rdx,rdx,HF_SIZE
	lea	rdx,[rcx+HM_HDRS+rdx]
	mov	rsi,[rdx+HF_VALUE]
	mov	edx,[rdx+HF_VLEN]
	mov	ecx,edx				; without the port
@@:
	test	ecx,ecx
	jz	.portless
	dec	ecx
	cmp	byte [rsi+rcx],']'
	je	.portless
	cmp	byte [rsi+rcx],':'
	jne	@b
	mov	edx,ecx
.portless:
	test	edx,edx
	jz	.ok
	cmp	byte [rsi+rdx-1],'.'
	jne	@f
	dec	edx
@@:
	push	rax
	mov	rdi,rax
	call	tls_cert_named
	pop	rcx
	cmp	rax,rcx
	je	.ok
	stc
	ret
.ok:
	clc
	ret

; ebx = session, rax = bytes read (http_recv_done in HS_PT_HELLO): once the
; ClientHello is whole, the pool its server_name names, a connection
; there, and what was read goes first (SF_PREFIX).
http_pt_in:
	test	rax,rax
	jle	http_tls_close
	add	[r15+H_INLEN],eax
	mov	edi,ebx
	call	idle_touch
	h_rec
	mov	rdi,[r15+H_BUF]
	mov	esi,[r15+H_INLEN]
	lea	rdx,[rdi+HB_OUT]
	call	tls_sni_peek
	h_rec
	cmp	eax,TH_MORE
	je	http_tls_read
	cmp	eax,TH_DONE
	jne	http_tls_close			; not TLS
	push	rsi
	push	rcx
	call	session_ptr
	mov	edx,[rax+S_LST]
	imul	rdx,rdx,LS_SIZE
	mov	edi,[g_listeners+rdx+LS_PT]
	pop	rcx
	pop	rsi
	call	tls_passthrough_pool
	cmp	eax,-1
	je	http_tls_close			; no line for that name: default reject
	mov	r8d,eax
	call	session_ptr
	mov	[rax+S_POOL],r8d
	and	dword [rax+S_FLAGS],not SF_TLS_HS
	or	dword [rax+S_FLAGS],SF_PREFIX
	h_rec
	mov	dword [r15+H_STATE],0
	mov	dword [r15+H_INOFF],0
	mov	edi,ebx
	call	ph_disarm
	call	session_ptr
	mov	dword [rax+S_STATE],ST_CONNECTING	; as accept leaves it: the connect's
	mov	edi,ebx					; completion is told apart by it
	cmp	dword [g_engine],ENGINE_EPOLL
	je	ep_connect
	jmp	session_connect
