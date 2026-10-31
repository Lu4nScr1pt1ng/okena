; TLS 1.2 for older clients, server side (io_uring). When tls_hello sees a
; ClientHello that offers no TLS 1.3, it returns TH_TLS12 and the handshake
; runs here with tls12_hello / tls12_finished (src/tls/tls12_server.inc):
; ServerHello, Certificate, a signed ServerKeyExchange and ServerHelloDone;
; then the client's ClientKeyExchange, ChangeCipherSpec and Finished; then
; the server's ChangeCipherSpec and Finished; then the keys go to kTLS 1.2
; and the connection proceeds as any other. kTLS only (no user-space 1.2
; records); without the module the connection closes.
;
;   HS_TLS12_FLIGHT  the ServerHello flight is out
;   HS_TLS12_FIN     reading ClientKeyExchange + ChangeCipherSpec + Finished
;   HS_TLS12_FIN2    the server ChangeCipherSpec + Finished is out

HS_TLS12_FLIGHT	:= 27
HS_TLS12_FIN	:= 28
HS_TLS12_FIN2	:= 29

HB_T2		:= HB_TXC + UTLS_TX_CAP		; the 1.2 handshake state
HB_C12		:= HB_T2 + T2_FULL		; the credentials block
assert HB_C12 + C12_SIZE <= 1 shl HB_SHIFT

; from TH_TLS12 in http_tls_hello_in: build the credentials and the server
; flight (ServerHello..ServerHelloDone)
http_tls12_hello:
	cmp	dword [g_no_ktls],0		; the 1.2 path is kTLS-only
	jne	http_tls_close
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
	; HTTP/2 over TLS 1.2 (RFC 9113 9.2: ECDHE and AEAD, which is all this
	; offers): ALPN h2 when the listener takes it and the client asks
	mov	dword [rcx+C12_ALPN],0
	push	rcx
	call	session_ptr
	mov	eax,[rax+S_LST]
	imul	rax,rax,LS_SIZE
	test	dword [g_listeners+rax+LS_FLAGS],LSF_H2
	jz	@f
	lea	rsi,[r14+HB_IN]
	mov	edx,[r15+H_INLEN]
	call	tls12_alpn_h2
	mov	rcx,[rsp]
	mov	[rcx+C12_ALPN],eax
	test	eax,eax
	jz	@f
	or	dword [r14+HB_TS+TS_FLAGS],TF_GOT_H2	; (http_tls_established reads it)
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
	mov	dword [r15+H_STATE],HS_TLS12_FLIGHT
	mov	esi,eax
	mov	rdi,[r15+H_BUF]
	add	rdi,HB_OUT
	mov	ecx,SIDE_CLIENT
	jmp	h_send

; the ServerHello flight is out (http_send_done in HS_TLS12_FLIGHT): read
; the client's ClientKeyExchange, ChangeCipherSpec and Finished
http_tls12_flight_sent:
	mov	dword [r15+H_INLEN],0
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
	; count whole records; the client sends three (CKE, CCS, Finished)
	mov	r14,[r15+H_BUF]
	xor	ecx,ecx				; offset
	xor	edx,edx				; whole records
.count:
	lea	eax,[rcx+5]
	cmp	eax,[r15+H_INLEN]
	ja	.need
	movzx	eax,word [r14+rcx+3]
	rol	ax,8
	lea	ecx,[rcx+rax+5]
	cmp	ecx,[r15+H_INLEN]
	ja	.need
	inc	edx
	cmp	edx,3
	jb	.count
	; the flight is whole: finish
	lea	rdi,[r14+HB_T2]
	lea	rsi,[r14+HB_IN]
	mov	ecx,[r15+H_INLEN]
	lea	r8,[r14+HB_OUT]
	call	tls12_finished
	test	eax,eax
	jz	http_tls_close
	mov	dword [r15+H_STATE],HS_TLS12_FIN2
	mov	esi,eax
	mov	rdi,[r15+H_BUF]
	add	rdi,HB_OUT
	mov	ecx,SIDE_CLIENT
	jmp	h_send
.need:
	cmp	dword [r15+H_INLEN],H_IN_CAP
	jae	http_tls_close
	jmp	http_tls12_read

; the server ChangeCipherSpec + Finished is out (http_send_done in
; HS_TLS12_FIN2): hand the keys to the kernel (kTLS 1.2)
http_tls12_fin2_sent:
	mov	r8,[r15+H_BUF]
	lea	rsi,[r8+HB_KTLS]
	lea	rdx,[r8+HB_KTLS+KTLS_INFO]
	lea	rdi,[r8+HB_T2]
	call	tls12_ktls_info
	cmp	dword [g_no_ktls],0
	jne	http_tls_close			; no module: no user-space 1.2 path (v1)
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
	mov	r8d,KTLS_INFO
	call	.sqe
	mov	r11,[r15+H_BUF]
	add	r11,HB_KTLS + KTLS_INFO
	mov	edi,OP_H_KTLS12
	mov	r9d,SOL_TLS
	mov	r10d,TLS_RX
	mov	r8d,KTLS_INFO
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
	test	eax,eax
	jnz	http_tls_close
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
	jnz	http_tls_close
	mov	esi,SOL_TLS
	mov	edx,TLS_RX
	mov	r10,[r15+H_BUF]
	add	r10,HB_KTLS + KTLS_INFO
	mov	r8d,KTLS_INFO
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
.close:
	mov	edi,ebx
	jmp	session_close
.closing:
	mov	edi,ebx
	jmp	session_maybe_free
.out:
	ret

; rsi = a ClientHello record, edx = its length: eax = 1 when its ALPN
; offers h2. Keeps rbx, r12-r15.
tls12_alpn_h2:
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
	lea	r11,[rcx+6]			; past the list's u16 length
.proto:
	cmp	r11,r10
	jae	.no
	movzx	eax,byte [r11]
	cmp	eax,2
	jne	@f
	cmp	word [r11+1],'h2'
	je	.yes
@@:
	lea	r11,[r11+1+rax]
	jmp	.proto
.next:
	mov	rcx,r10
	jmp	.ext
.yes:
	mov	eax,1
	ret
.no:
	xor	eax,eax
	ret
