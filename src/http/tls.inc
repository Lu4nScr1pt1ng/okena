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
HS_TLS_ALERT	:= 20

HB_TLS		:= 1 shl 16			; the TLS area, after the HTTP buffers
HB_TS		:= HB_TLS			; the handshake, then the record keys
HB_KTLS		:= HB_TS + TS_SIZE		; tls12_crypto_info_aes_gcm_128: TX, then RX
KTLS_INFO	:= 40
HB_RXC		:= HB_TLS + 1024		; user-space records: ciphertext in
UTLS_RX_CAP	:= TLS_RECORD_MAX + 256 + 5 + 251	; one whole record (17 KiB)
HB_TXC		:= HB_RXC + UTLS_RX_CAP	; and out, two records at a time
UTLS_TX_RECS	:= 2
UTLS_TX_CAP	:= UTLS_TX_RECS * (TLS_RECORD_MAX + 22)
H_TLS_ROOM	:= HB_TLS - HB_OUT		; the flight is built in OUT and after it
assert HB_KTLS + 2 * KTLS_INFO <= HB_RXC
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

; ebx = session, r15 = its record, a new connection on a tls listener.
http_tls_start:
	mov	rdi,[r15+H_BUF]
	add	rdi,HB_TS
	mov	ecx,TS_SIZE
	xor	eax,eax
	rep	stosb
	mov	rax,[r15+H_BUF]
	mov	dword [rax+HB_TS+TS_FLAGS],TF_ALPN_H1
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
	mov	ecx,HS_TLS_FLIGHT
	cmp	eax,TH_SEND
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

	; The keys for the kernel: struct tls12_crypto_info_aes_gcm_128
	; { version, cipher, iv[8] (the IV's last 8), key[16], salt[4] (its
	; first 4), rec_seq[8] }.
	mov	r8,[r15+H_BUF]
	lea	rsi,[r8+HB_TS+TS_TX_KEY]
	lea	rdi,[r8+HB_KTLS]
	call	.info
	lea	rsi,[r8+HB_TS+TS_RX_KEY]
	lea	rdi,[r8+HB_KTLS+KTLS_INFO]
	call	.info
	cmp	dword [g_no_ktls],0
	jne	http_utls_start
	cmp	dword [g_engine],ENGINE_EPOLL
	je	.epoll

	; io_uring: three socket commands, linked: the ULP, TX, then RX,
	; whose completion goes on
	mov	dword [r15+H_STATE],HS_TLS_KTLS
	mov	edi,OP_S_OPT
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
	mov	r8d,KTLS_INFO
	call	.sqe
	mov	r11,[r15+H_BUF]
	add	r11,HB_KTLS + KTLS_INFO
	mov	edi,OP_H_KTLS
	mov	r9d,SOL_TLS
	mov	r10d,TLS_RX
	mov	r8d,KTLS_INFO
	call	.sqe
	and	byte [rax+SQE_FLAGS],not IOSQE_IO_LINK	; the chain ends here
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

; rsi = key (16), IV (12) at +16; rdi = the crypto info to fill.
.info:
	mov	dword [rdi],0x00330304		; TLS 1.3, TLS_CIPHER_AES_GCM_128
	mov	rax,[rsi+16+4]
	mov	[rdi+4],rax
	movdqu	xmm0,[rsi]
	movdqu	[rdi+12],xmm0
	mov	eax,[rsi+16]
	mov	[rdi+28],eax
	mov	qword [rdi+32],0
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
	test	eax,eax
	jnz	.refused
	push	rdi
	mov	esi,SOL_TLS
	mov	edx,TLS_TX
	mov	r10,[r15+H_BUF]
	add	r10,HB_KTLS
	mov	r8d,KTLS_INFO
	mov	eax,SYS_setsockopt
	syscall
	pop	rdi
	test	eax,eax
	jnz	.refused			; no TX: the socket is still plain TCP
	mov	esi,SOL_TLS
	mov	edx,TLS_RX
	mov	r10,[r15+H_BUF]
	add	r10,HB_KTLS + KTLS_INFO
	mov	r8d,KTLS_INFO
	mov	eax,SYS_setsockopt
	syscall
	test	eax,eax
	jnz	http_tls_close			; TX is the kernel's already: no way back
	jmp	http_tls_established
.refused:
	mov	dword [g_no_ktls],1
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
	mov	dword [g_no_ktls],1		; the ULP or TX was refused
	jmp	http_utls_start
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
	mov	ecx,TS_SIZE + 2 * KTLS_INFO
	call	secure_zero
	xor	eax,eax
	mov	[r15+H_INLEN],eax
	mov	[r15+H_INOFF],eax
	jmp	http_next_request

; Before serving: tls on a tcp listener is not built yet (exits with
; EXIT_CONFIG and why); tls on an http listener without the kernel's TLS
; (the module, "tls") works, slower: said once.
tls_serve_check:
	xor	ecx,ecx
	xor	edx,edx				; edx = an http listener has tls
.listener:
	cmp	ecx,[g_plan_listeners]
	jae	.scanned
	imul	rax,rcx,LS_SIZE
	inc	ecx
	cmp	dword [g_listeners+rax+LS_TLS],0
	je	.listener
	cmp	dword [g_listeners+rax+LS_KIND],LK_HTTP
	jne	.tcp
	inc	edx
	jmp	.listener
.scanned:
	test	edx,edx
	jz	.ok
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
	ret
.no_ktls:
	mov	dword [g_no_ktls],1		; the workers forked from here know
	call	log_begin
	out_lit 'no kernel TLS (modprobe tls): TLS records are sealed in user space, which costs more CPU'
	jmp	log_end
.tcp:
	call	log_begin
	out_lit 'tls { } on a tcp listener is read and checked, but not served yet (it is on http listeners): refusing to serve it in plaintext'
	jmp	.refuse
.refuse:
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; ------------------------------------------------- user-space records

; ebx = session, r15 = record, the handshake done: records here from now on.
http_utls_start:
	mov	rdi,[r15+H_BUF]
	add	rdi,HB_KTLS			; the keys meant for the kernel
	mov	ecx,2 * KTLS_INFO
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
