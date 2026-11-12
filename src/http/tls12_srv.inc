; TLS 1.2 for older clients, server side (io_uring). When tls_hello sees a
; ClientHello that offers no TLS 1.3, it returns TH_TLS12 and the handshake
; runs here with tls12_hello / tls12_finished (src/tls/tls12_server.inc):
; ServerHello, Certificate, a signed ServerKeyExchange and ServerHelloDone;
; then the client's ClientKeyExchange, ChangeCipherSpec and Finished; then
; the server's ChangeCipherSpec and Finished; then the keys go to kTLS 1.2
; and the connection proceeds as any other; without kTLS the records are
; sealed and opened here (utls12_seal / utls12_open), as for TLS 1.3.
;
;   HS_TLS12_FLIGHT  the ServerHello flight is out
;   HS_TLS12_FIN     reading ClientKeyExchange + ChangeCipherSpec + Finished
;   HS_TLS12_FIN2    the server ChangeCipherSpec + Finished is out
;   HS_TLS12_RFIN    resumed: peeking at the ChangeCipherSpec + Finished
;   HS_TLS12_RTAKE   and taking them, no further (as TLS 1.3's HS_TLS_FIN and
;                    HS_TLS_TAKE): in an abbreviated handshake the client's
;                    Finished is its last word, its request may come with it

HS_TLS12_FLIGHT	:= 27
HS_TLS12_FIN	:= 28
HS_TLS12_FIN2	:= 29
HS_TLS12_RFIN	:= 46
HS_TLS12_RTAKE	:= 47

HB_T2		:= HB_TXC + UTLS_TX_CAP		; the 1.2 handshake state
HB_C12		:= HB_T2 + T2_FULL		; the credentials block
assert HB_C12 + C12_SIZE <= 1 shl HB_SHIFT

; from TH_TLS12 in http_tls_hello_in: build the credentials and the server
; flight (ServerHello..ServerHelloDone)
http_tls12_hello:
	mov	rdi,[r15+H_BUF]			; a fresh T2 block
	add	rdi,HB_T2
	mov	ecx,T2_FULL
	xor	eax,eax
	rep	stosb
	mov	r14,[r15+H_BUF]			; the certificate SNI chose (0 = none)
	mov	rax,[r14+HB_TS+TS_CERT]
	mov	[r15+H_SNICERT],rax		; for the Host-vs-certificate 421 check
	test	rax,rax
	jnz	.havecert
	call	http_tls_cred			; else the default certificate
.havecert:
	test	rax,rax
	jz	http_tls_close
	call	tls12_cert_fit			; (its sibling of the other key, when the
	mov	[g_t12_tl],rax			; client's suites take that one only)
	cmp	dword [rax+TL_KEYTYPE],2	; TLS 1.2 here signs with ECDSA or RSA
	je	http_tls_close			; only: an Ed25519 certificate needs 1.3
	mov	r14,[r15+H_BUF]
	lea	rcx,[r14+HB_C12]
	mov	edx,[rax+TL_CHAIN]		; certificate_list in the store
	lea	rdx,[g_tls_store+rdx]
	mov	[rcx+C12_LIST],rdx
	mov	edx,[rax+TL_CLEN]
	mov	[rcx+C12_LEN],edx
	lea	rdx,[rax+TL_KEY]		; the private key
	mov	[rcx+C12_KEY],rdx
	mov	rdx,[rax+TL_PUB+1]		; what a ticket names: 8 bytes of its key
	cmp	dword [rax+TL_KEYTYPE],1
	jne	@f
	mov	rdx,[rax+TL_RSA_N]
@@:
	mov	[rcx+C12_CERTID],rdx
	lea	rdx,[r14+HB_TS]			; client certificates (client_ca): the TS has
	mov	[rcx+C12_TS],rdx		; the anchors, and gets who the client is
	xor	edx,edx
	test	dword [r14+HB_TS+TS_FLAGS],TF_CCA
	jz	@f
	inc	edx
	test	dword [r14+HB_TS+TS_FLAGS],TF_CCA_REQ
	jz	@f
	inc	edx
@@:
	mov	[rcx+C12_CCA],edx
	mov	edx,[rax+TL_KEYTYPE]		; EC or RSA, with the RSA key material
	mov	[rcx+C12_KEYTYPE],edx
	cmp	edx,1
	jne	@f
	lea	rdx,[rax+TL_RSA_N]
	mov	[rcx+C12_RSA_N],rdx
	mov	edx,[rax+TL_RSA_NLEN]
	mov	[rcx+C12_RSA_NLEN],edx
	lea	rdx,[rax+TL_RSA_D]
	mov	[rcx+C12_RSA_D],rdx
@@:
	; ALPN as for TLS 1.3 (the listener's `alpn`, `http2`): HTTP/2 over TLS
	; 1.2 (RFC 9113 9.2: ECDHE and AEAD, which is all this offers) or
	; http/1.1, named back; offered and nothing in common: refused
	mov	dword [rcx+C12_ALPN],0
	push	rcx
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_TLS_HS
	jnz	.alpn_done			; (tcp: no application protocol)
	mov	eax,[rax+S_LST]
	imul	rax,rax,LS_SIZE
	mov	r9d,[g_listeners+rax+LS_FLAGS]
	lea	rsi,[r14+HB_IN]
	mov	edx,[r15+H_INLEN]
	push	r9
	call	tls12_alpn
	pop	r9
	mov	rcx,[rsp]
	test	eax,4
	jz	.alpn_done			; no ALPN: http/1.1, unnamed
	test	r9d,LSF_H1FIRST
	jz	.alpn_h2
	test	eax,2
	jnz	.alpn_h1
.alpn_h2:
	test	r9d,LSF_H2
	jz	.alpn_h1
	test	eax,1
	jz	.alpn_h1
	mov	dword [rcx+C12_ALPN],1
	or	dword [r14+HB_TS+TS_FLAGS],TF_GOT_H2	; (http_tls_established reads it)
	jmp	.alpn_done
.alpn_h1:
	test	r9d,LSF_NOH1
	jnz	.alpn_none
	test	eax,2
	jz	.alpn_none
	mov	dword [rcx+C12_ALPN],2
	jmp	.alpn_done
.alpn_none:
	pop	rcx				; no_application_protocol (RFC 7301)
	mov	rdi,[r15+H_BUF]
	mov	dword [rdi+HB_OUT],0x00030315
	mov	word [rdi+HB_OUT+4],0x0202
	mov	byte [rdi+HB_OUT+6],120
	mov	dword [r15+H_STATE],HS_TLS_ALERT
	mov	esi,7
	add	rdi,HB_OUT
	mov	ecx,SIDE_CLIENT
	jmp	h_send
.alpn_done:
	; OCSP: its staple, when the client asks (status_request)
	mov	rcx,[rsp]
	mov	dword [rcx+C12_OCSP],0
	lea	rsi,[r14+HB_IN]
	mov	edx,[r15+H_INLEN]
	call	tls12_status_req
	test	eax,eax
	jz	@f
	mov	rdi,[g_t12_tl]
	call	ocsp_staple
	mov	rcx,[rsp]
	mov	eax,[g_oc_n]
	mov	[rcx+C12_OCSP],eax
@@:
	pop	rcx
	lea	rdi,[r14+HB_T2]
	mov	rsi,rcx
	lea	rdx,[r14+HB_IN]
	mov	ecx,[r15+H_INLEN]
	lea	r8,[r14+HB_OUT]
	call	tls12_hello
	test	eax,eax
	jz	http_tls_close
	js	.refused
	mov	dword [r15+H_STATE],HS_TLS12_FLIGHT
	mov	esi,eax
	mov	rdi,[r15+H_BUF]
	add	rdi,HB_OUT
	mov	ecx,SIDE_CLIENT
	jmp	h_send
.refused:
	mov	dword [r15+H_STATE],HS_TLS_ALERT	; its alert, then closed
	neg	eax
	mov	esi,eax
	mov	rdi,[r15+H_BUF]
	add	rdi,HB_OUT
	mov	ecx,SIDE_CLIENT
	jmp	h_send

; the ServerHello flight is out (http_send_done in HS_TLS12_FLIGHT): read
; the client's ClientKeyExchange, ChangeCipherSpec and Finished
http_tls12_flight_sent:
	mov	dword [r15+H_INLEN],0
	mov	rax,[r15+H_BUF]
	cmp	dword [rax+HB_T2+T2_RESUMED],0
	jne	http_tls12_rpeek
	mov	dword [r15+H_STATE],HS_TLS12_FIN
http_tls12_read:
	mov	esi,H_IN_CAP
	sub	esi,[r15+H_INLEN]
	jz	http_tls_close
	mov	edi,[r15+H_INLEN]
	add	rdi,[r15+H_BUF]
	mov	ecx,SIDE_CLIENT
	jmp	h_recv

; more of the client's second flight arrived (http_recv_done in
; HS_TLS12_FIN): once three records are whole, finish the handshake
http_tls12_fin:
	test	rax,rax
	jle	http_tls_close
	add	[r15+H_INLEN],eax
	mov	edi,ebx
	call	idle_touch
	h_rec
	; whole records, up to the client's ChangeCipherSpec and the one after it
	; (its Finished): before it, [Certificate,] ClientKeyExchange,
	; [CertificateVerify] in as many records as it took; nothing before it
	; in an abbreviated handshake
	mov	r14,[r15+H_BUF]
	xor	ecx,ecx				; offset
	xor	edx,edx				; 1 once the ChangeCipherSpec is whole
.count:
	lea	eax,[rcx+5]
	cmp	eax,[r15+H_INLEN]
	ja	.need
	movzx	r8d,byte [r14+rcx]
	movzx	eax,word [r14+rcx+3]
	rol	ax,8
	lea	ecx,[rcx+rax+5]
	cmp	ecx,[r15+H_INLEN]
	ja	.need
	test	edx,edx
	jnz	.flight				; the record after it: all here
	cmp	r8d,20
	jne	.count
	mov	edx,1
	jmp	.count
.flight:
	cmp	dword [r14+HB_T2+T2_RESUMED],0
	je	.whole
	lea	rdi,[r14+HB_T2]
	lea	rsi,[r14+HB_IN]
	mov	ecx,[r15+H_INLEN]
	call	tls12_resumed_fin
	test	eax,eax
	jz	http_tls_close
	or	dword [r14+HB_TS+TS_FLAGS],TF_RESUMED
	xor	eax,eax				; TLS 1.2, resumed
	call	tls_count
	jmp	http_tls12_fin2_sent		; the keys go in at once
.whole:
	; the flight is whole: finish
	lea	rdi,[r14+HB_T2]
	lea	rsi,[r14+HB_IN]
	mov	ecx,[r15+H_INLEN]
	lea	r8,[r14+HB_OUT]
	call	tls12_finished
	test	eax,eax
	jz	http_tls_close
	push	rax
	xor	eax,eax				; TLS 1.2, done
	call	tls_count
	pop	rax
	mov	dword [r15+H_STATE],HS_TLS12_FIN2
	mov	esi,eax
	mov	rdi,[r15+H_BUF]
	add	rdi,HB_OUT
	mov	ecx,SIDE_CLIENT
	jmp	h_send
.need:
	cmp	dword [r15+H_INLEN],H_IN_CAP
	jae	http_tls_close
	cmp	dword [r14+HB_T2+T2_RESUMED],0
	je	http_tls12_read
http_tls12_rpeek:
	mov	dword [r15+H_STATE],HS_TLS12_RFIN
	jmp	http_tls_peek_on

; no kTLS: the records sealed and opened here, as for TLS 1.3 (tls_seal and
; tls_open, seeing TF_T12, come to utls12_seal / utls12_open)
http_utls12_start:
	mov	r8,[r15+H_BUF]
	or	dword [r8+HB_TS+TS_FLAGS],TF_T12
	mov	qword [r8+HB_T2+T2_TXSEQ],1	; (the Finished each way was 0)
	mov	qword [r8+HB_T2+T2_RXSEQ],1
	mov	rdi,[r15+H_BUF]
	add	rdi,HB_KTLS			; the keys meant for the kernel
	mov	ecx,2 * KTLS_SLOT
	call	secure_zero
	xor	eax,eax
	mov	[r15+H_RXC],eax
	mov	[r15+H_PTLEN],eax
	mov	[r15+H_TXLEN],eax
	mov	[r15+H_INLEN],eax
	mov	[r15+H_INOFF],eax
	mov	dword [r15+H_UTLS],1
	mov	rax,[r15+H_BUF]
	test	dword [rax+HB_TS+TS_FLAGS],TF_GOT_H2
	jz	http_next_request
	xor	edi,edi				; ALPN chose h2
	jmp	h2_start

; tls_seal for a 1.2 session: rdi = ts, rsi = record (5 for the header, then the
; plaintext), edx = its length, ecx = content type. eax = the record's length.
utls12_seal:
	push	rbx
	push	r12
	push	r13
	push	r14
	lea	rbx,[rdi+HB_T2-HB_TS]		; the 1.2 state
	mov	r12,rsi
	mov	r13d,edx
	mov	r14d,ecx
	mov	[r12],cl			; the header: type, 1.2, length (after)
	mov	word [r12+1],0x0303
	lea	r9,[r12+5]			; the plaintext where it is (ChaCha20)
	cmp	dword [rbx+T2_SUITE],T12_CHACHA
	je	@f
	std					; AES-GCM: 8 up for the explicit nonce
	lea	rsi,[r12+5+r13-1]
	lea	rdi,[r12+13+r13-1]
	mov	ecx,r13d
	rep	movsb
	cld
	lea	r9,[r12+13]
@@:
	lea	rdi,[r12+5]
	lea	rsi,[rbx+T2_TXGCM]
	lea	rdx,[rbx+T2_SWIV]
	mov	rcx,[rbx+T2_TXSEQ]
	mov	r8d,r14d
	mov	r10d,r13d
	call	tls12_aseal
	inc	qword [rbx+T2_TXSEQ]
	mov	ecx,eax
	rol	cx,8
	mov	[r12+3],cx
	add	eax,5
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; tls_open for a 1.2 session: rdi = ts, rsi = received bytes, edx = their length.
; eax = TH_MORE, TH_FAIL, or TH_DONE with rsi = the plaintext, ecx = its
; length, r8d = the content type (application_data or alert), edx = the bytes
; it took.
utls12_open:
	push	rbx
	push	r12
	push	r13
	lea	rbx,[rdi+HB_T2-HB_TS]
	mov	r12,rsi
	cmp	edx,5
	jb	.more
	movzx	eax,byte [rsi]
	cmp	eax,23
	je	@f
	cmp	eax,21
	jne	.fail				; (a handshake: renegotiation, never taken)
@@:
	movzx	ecx,word [rsi+3]
	rol	cx,8
	cmp	ecx,TLS_RECORD_MAX + 2048
	ja	.fail
	lea	r13d,[rcx+5]
	cmp	edx,r13d
	jb	.more
	lea	rdi,[r12+5]
	mov	esi,ecx
	lea	rdx,[rbx+T2_RXGCM]
	lea	rcx,[rbx+T2_CWIV]
	mov	r8,[rbx+T2_RXSEQ]
	movzx	r9d,byte [r12]
	call	tls12_aopen
	test	eax,eax
	js	.fail
	inc	qword [rbx+T2_RXSEQ]
	mov	ecx,eax
	mov	rsi,rdx
	movzx	r8d,byte [r12]
	mov	edx,r13d
	mov	eax,TH_DONE
	jmp	.out
.more:
	mov	eax,TH_MORE
	jmp	.out
.fail:
	mov	eax,TH_FAIL
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; the server ChangeCipherSpec + Finished is out (http_send_done in
; HS_TLS12_FIN2): hand the keys to the kernel (kTLS 1.2)
http_tls12_fin2_sent:
	mov	r8,[r15+H_BUF]
	lea	rsi,[r8+HB_KTLS]
	lea	rdx,[r8+HB_KTLS+KTLS_SLOT]
	lea	rdi,[r8+HB_T2]
	call	tls12_ktls_info
	mov	[g_t12_klen],eax		; (40 AES-128-GCM, 56 ChaCha20-Poly1305 or AES-256-GCM)
	cmp	dword [g_no_ktls],0
	jne	http_utls12_start		; no module: the records here
	; as TLS 1.3's: an http listener keeps the records here unless `ktls on`
	; (on kTLS, 1.2 did 16% less keep-alive traffic than 1.3 in user space)
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_TLS_HS
	jnz	.kernel
	mov	eax,[rax+S_LST]
	imul	rax,rax,LS_SIZE
	test	dword [g_listeners+rax+LS_FLAGS],LSF_KTLS
	jz	http_utls12_start
.kernel:
	cmp	dword [g_engine],ENGINE_EPOLL
	je	.epoll
	mov	dword [r15+H_STATE],HS_TLS_KTLS
	mov	dword [r15+H_ULPERR],0
	mov	edi,OP_H_ULP			; ULP, then TX, then RX, linked
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
	mov	r8d,[g_t12_klen]
	call	.sqe
	mov	r11,[r15+H_BUF]
	add	r11,HB_KTLS + KTLS_SLOT
	mov	edi,OP_H_KTLS12
	mov	r9d,SOL_TLS
	mov	r10d,TLS_RX
	mov	r8d,[g_t12_klen]
	call	.sqe
	and	byte [rax+SQE_FLAGS],not IOSQE_IO_LINK
	ret
.epoll:
	; epoll: set the three options directly on the client socket
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
	cmp	eax,-ENOENT			; no tls module: the records here
	jne	@f
	mov	dword [g_no_ktls],1
	jmp	http_utls12_start
@@:
	test	eax,eax
	jnz	http_tls_close
	push	rdi
	mov	esi,SOL_TLS
	mov	edx,TLS_TX
	mov	r10,[r15+H_BUF]
	add	r10,HB_KTLS
	mov	r8d,[g_t12_klen]
	mov	eax,SYS_setsockopt
	syscall
	pop	rdi
	test	eax,eax
	jnz	http_tls_close
	mov	esi,SOL_TLS
	mov	edx,TLS_RX
	mov	r10,[r15+H_BUF]
	add	r10,HB_KTLS + KTLS_SLOT
	mov	r8d,[g_t12_klen]
	mov	eax,SYS_setsockopt
	syscall
	test	eax,eax
	jnz	http_tls_close
	jmp	http_tls_established
; edi = op, r9d = level, r10d = option, r11 = value, r8d = length: one
; linked setsockopt on the client socket. rax = the SQE.
.sqe:
	push	r8
	push	r9
	push	r10
	push	r11
	mov	esi,ebx
	call	sess_sqe
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

; completion of the RX key for a TLS 1.2 server connection: established on
; success, closed on failure (no user-space 1.2 fallback).
; ebx = session, r12d = generation, r14 = res
on_h_ktls12:
	call	sess_complete
	jc	.out
	cmp	dword [rax+S_STATE],ST_CLOSING
	je	.closing
	h_rec
	test	r14,r14
	jns	http_tls_established
	cmp	r14,-ECANCELED			; an earlier link failed: which one?
	jne	.close
	cmp	dword [r15+H_ULPERR],-ENOENT	; the ULP: no tls module on this host
	jne	.close				; else this connection only (ENOTCONN: the
	mov	dword [g_no_ktls],1		; client left before the keys went in)
	jmp	http_utls12_start		; (no ULP on the socket: the records here)
.close:
	mov	edi,ebx
	jmp	session_close
.closing:
	mov	edi,ebx
	jmp	session_maybe_free
.out:
	ret

; rax = the entry SNI chose: rax = it, or its sibling (`cert` lines of both key
; types for one name) when the client's 1.2 suites take only the sibling's key
; (ECDHE_RSA alone, an ECDSA certificate first). Keeps rbx, r12-r15.
tls12_cert_fit:
	push	rax
	mov	ecx,[rax+TL_KEYTYPE]
	call	.suits
	test	eax,eax
	jnz	.keep
	mov	rdi,[rsp]
	call	tls_cert_sibling
	test	rax,rax
	jz	.keep
	push	rax
	mov	ecx,[rax+TL_KEYTYPE]
	call	.suits
	pop	rcx
	test	eax,eax
	jz	.keep
	add	rsp,8
	mov	rax,rcx
	ret
.keep:
	pop	rax
	ret
; ecx = a key type: eax = 1 when the ClientHello (IN) offers a suite for it
.suits:
	xor	eax,eax
	cmp	ecx,1
	ja	.out
	mov	rsi,[r15+H_BUF]
	add	rsi,HB_IN
	mov	edx,[r15+H_INLEN]
	lea	r8,[rsi+rdx]
	lea	rdx,[rsi+5+4+2+32]
	cmp	rdx,r8
	jae	.out
	movzx	r9d,byte [rdx]			; session id
	lea	rdx,[rdx+1+r9]
	lea	r9,[rdx+2]
	cmp	r9,r8
	ja	.out
	movzx	r9d,word [rdx]			; cipher suites
	rol	r9w,8
	add	rdx,2
	lea	r9,[rdx+r9]
	cmp	r9,r8
	jbe	@f
	mov	r9,r8
@@:
	imul	r10d,ecx,T12_SUITES * 2		; the key type's suites in the table
.suite:
	lea	r8,[rdx+2]
	cmp	r8,r9
	ja	.out
	movzx	ecx,word [rdx]
	xchg	cl,ch
	add	rdx,2
	xor	r11d,r11d
.ours:
	cmp	cx,[tls12_suites+r10+r11*2]
	je	.yes
	inc	r11d
	cmp	r11d,T12_SUITES
	jb	.ours
	jmp	.suite
.yes:
	mov	eax,1
.out:
	ret

; rsi = a ClientHello record, edx = its length: eax = 1 when its ALPN
; offers h2. Keeps rbx, r12-r15.
bss
	align 8
	g_t12_tl	dq ?
	g_t12_klen	dd ?
end bss

; rsi/edx = the ClientHello record: eax = 1 when it asks for an OCSP staple
; (status_request, type ocsp)
tls12_status_req:
	lea	r8,[rsi+rdx]
	lea	rcx,[rsi+5+4+2+32]
	cmp	rcx,r8
	jae	.no
	movzx	eax,byte [rcx]			; session id
	lea	rcx,[rcx+1+rax]
	lea	rax,[rcx+2]
	cmp	rax,r8
	ja	.no
	movzx	eax,word [rcx]			; cipher suites
	xchg	al,ah
	lea	rcx,[rcx+2+rax]
	cmp	rcx,r8
	jae	.no
	movzx	eax,byte [rcx]			; compression methods
	lea	rcx,[rcx+1+rax]
	lea	rax,[rcx+2]
	cmp	rax,r8
	ja	.no
	movzx	eax,word [rcx]			; extensions
	xchg	al,ah
	add	rcx,2
	lea	r9,[rcx+rax]
	cmp	r9,r8
	jbe	.ext
	mov	r9,r8
.ext:
	lea	rax,[rcx+4]
	cmp	rax,r9
	ja	.no
	movzx	eax,word [rcx+2]
	xchg	al,ah
	lea	r10,[rcx+4+rax]
	cmp	r10,r9
	ja	.no
	cmp	word [rcx],0x0500		; status_request
	jne	.next
	test	eax,eax
	jz	.no
	cmp	byte [rcx+4],1			; ocsp
	jne	.no
	mov	eax,1
	ret
.next:
	mov	rcx,r10
	jmp	.ext
.no:
	xor	eax,eax
	ret

; rsi/edx = the ClientHello's record: eax = 4 when it has ALPN, | 1 for h2,
; | 2 for http/1.1 in it
tls12_alpn:
	xor	r11d,r11d			; (the answer, built)
	push	rbx
	xor	ebx,ebx
	lea	r8,[rsi+rdx]			; the end
	lea	rcx,[rsi+5+4+2+32]		; past record, handshake header, version, random
	cmp	rcx,r8
	jae	.no
	movzx	eax,byte [rcx]			; session id
	lea	rcx,[rcx+1+rax]
	lea	rax,[rcx+2]
	cmp	rax,r8
	ja	.no
	movzx	eax,word [rcx]			; cipher suites
	xchg	al,ah
	lea	rcx,[rcx+2+rax]
	cmp	rcx,r8
	jae	.no
	movzx	eax,byte [rcx]			; compression methods
	lea	rcx,[rcx+1+rax]
	lea	rax,[rcx+2]
	cmp	rax,r8
	ja	.no
	movzx	eax,word [rcx]			; extensions
	xchg	al,ah
	add	rcx,2
	lea	r9,[rcx+rax]
	cmp	r9,r8
	jbe	.ext
	mov	r9,r8
.ext:
	lea	rax,[rcx+4]
	cmp	rax,r9
	ja	.no
	movzx	eax,word [rcx+2]		; its length
	xchg	al,ah
	lea	r10,[rcx+4+rax]			; its end
	cmp	r10,r9
	ja	.no
	cmp	word [rcx],0x1000		; ALPN
	jne	.next
	or	ebx,4
	lea	r11,[rcx+6]			; past the list's u16 length
.proto:
	cmp	r11,r10
	jae	.no
	movzx	eax,byte [r11]
	cmp	eax,2
	jne	@f
	cmp	word [r11+1],'h2'
	jne	@f
	or	ebx,1
@@:
	cmp	eax,8
	jne	@f
	mov	rdx,'http/1.1'
	cmp	[r11+1],rdx
	jne	@f
	or	ebx,2
@@:
	lea	r11,[r11+1+rax]
	jmp	.proto
.next:
	mov	rcx,r10
	jmp	.ext
.no:
	mov	eax,ebx
	pop	rbx
	ret
