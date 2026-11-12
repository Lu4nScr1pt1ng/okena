; A client for HTTPS (and plain HTTP), for the control process: what it asks
; of other services (Kubernetes' API, alerts' webhooks, and later ACME). It
; blocks, with two-second timeouts, as the control process does nothing else
; in the meantime; workers never use it.
;
; TLS 1.3 only, the server verified as uptls does for backends: the
; CertificateVerify and Finished, the chain, each certificate in date, the
; name. The chain ends either at one anchor given (a cluster's CA), or at a
; root of the system's store (SSL_CERT_FILE when set, as OpenSSL reads it,
; else /etc/ssl/certs/ca-certificates.crt and its usual other places), found
; by the last certificate's issuer: the server's
; chain as sent, or the shortest start of it that a root in the store signs
; (a chain may end with a certificate cross-signed by an older root).

CX_IN_CAP	:= 16 shl 20
CX_ROOTS	:= 512
CXR_HASH	:= 0			; q: the subject Name's hash
CXR_KEY		:= 8			; its key (PK_SIZE)
CXR_SIZE	:= (CXR_KEY + PK_SIZE + 7) and not 7
CX_BUNDLE_MAX	:= 4 shl 20

bss
	align 8
	g_cx_tc:	rb TC_FULL
	g_cx_snap:	rb SHA256_CTX_SIZE
	g_cx_out:	rb 20480
	g_cx_in:	rb CX_IN_CAP
	g_cx_dec:	rb CX_IN_CAP
	g_cx_now:	rb 64
	g_cx_fd		dd ?
	g_cx_inlen	dd ?
	g_cx_plain	dd ?		; the answer so far in g_dk_buf
	g_cx_tls	dd ?		; this connection is TLS
	g_cx_nroots	dd ?		; the store, once loaded; -1 none to be had
	align 8
	g_cx_roots	dq ?
	g_cx_sni	dq ?
	g_cx_snilen	dd ?
end bss

rodata
	cx_bundles	db '/etc/ssl/certs/ca-certificates.crt',0
			db '/etc/pki/tls/certs/ca-bundle.crt',0
			db '/etc/ssl/ca-bundle.pem',0
			db '/etc/ssl/cert.pem',0
			db 0
	cx_cert_label	db 'CERTIFICATE',0
	str_ssl_cert_file db 'SSL_CERT_FILE='
	str_ssl_cert_file.len = $ - str_ssl_cert_file
end rodata

; the answer buffer (g_dk_buf), mapped once. CF when it cannot be.
cx_buffer:
	cmp	qword [g_dk_buf],0
	jne	.have
	xor	edi,edi
	mov	esi,DK_BUF
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.bad
	mov	[g_dk_buf],rax
.have:
	clc
	ret
.bad:
	stc
	ret

; rsi = sockaddr, edx = its length: a connection in g_cx_fd. CF when not.
cx_connect:
	push	rsi
	push	rdx
	call	cx_buffer
	movzx	edi,word [rsi]
	mov	esi,SOCK_STREAM or SOCK_CLOEXEC
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	pop	rdx
	pop	rsi
	test	eax,eax
	js	.bad
	mov	[g_cx_fd],eax
	mov	dword [g_cx_tls],0
	push	rsi
	push	rdx
	mov	edi,eax
	mov	esi,SOL_SOCKET
	mov	edx,SO_RCVTIMEO
	lea	r10,[ts_dk_io]
	mov	r8d,16
	mov	eax,SYS_setsockopt
	syscall
	mov	edi,[g_cx_fd]
	mov	esi,SOL_SOCKET
	mov	edx,SO_SNDTIMEO
	lea	r10,[ts_dk_io]
	mov	r8d,16
	mov	eax,SYS_setsockopt
	syscall
	pop	rdx
	pop	rsi
	mov	edi,[g_cx_fd]
	mov	eax,SYS_connect
	syscall
	test	eax,eax
	js	.close
	clc
	ret
.close:
	call	cx_close
.bad:
	stc
	ret

cx_close:
	mov	edi,[g_cx_fd]
	mov	eax,SYS_close
	syscall
	ret

; g_cx_fd connected; rdi = the anchor's key, or 0 for the system's store; rsi/
; edx = the server's name: the TLS 1.3 handshake, the server verified. CF
; when it failed (eax 1) or the server is not who it should be (eax 4).
cx_handshake:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r14,rdi
	mov	[g_cx_sni],rsi
	mov	[g_cx_snilen],edx
	lea	rdi,[g_cx_tc]
	mov	rdx,rsi
	mov	ecx,[g_cx_snilen]
	lea	rsi,[g_cx_out]
	call	tlsc_client_hello
	test	eax,eax
	jz	.fail
	mov	edx,eax
	lea	rsi,[g_cx_out]
	mov	edi,[g_cx_fd]
	call	dk_write_all
	jc	.fail
	lea	rsi,[g_cx_tc+TC_SHA]		; the transcript through the ClientHello
	lea	rdi,[g_cx_snap]
	mov	ecx,SHA256_CTX_SIZE
	rep	movsb
	xor	r12d,r12d			; bytes received
	xor	r13d,r13d			; the records tried end here
.read:
	call	cx_recv
	jc	.fail
.rec:
	lea	eax,[r13+5]
	cmp	eax,r12d
	ja	.read
	movzx	eax,word [g_cx_in+r13+3]
	xchg	al,ah
	lea	eax,[r13+rax+5]
	cmp	eax,r12d
	ja	.read
	mov	r13d,eax
	lea	rsi,[g_cx_in]
	mov	edx,r13d
	call	tlsc_is_tls12
	test	eax,eax
	jnz	.fail
	lea	rsi,[g_cx_snap]
	lea	rdi,[g_cx_tc+TC_SHA]
	mov	ecx,SHA256_CTX_SIZE
	rep	movsb
	lea	rdi,[g_cx_tc]
	lea	rsi,[g_cx_in]
	mov	edx,r13d
	lea	rcx,[g_cx_dec]
	call	tlsc_server_flight
	test	eax,eax
	jz	.rec
	mov	r15d,eax
	lea	rsi,[g_cx_dec]
	mov	edx,eax
	call	tlsc_flight_complete
	test	eax,eax
	jz	.rec
	lea	rdi,[g_cx_tc]
	lea	rsi,[g_cx_dec]
	mov	edx,r15d
	call	tlsc_verify
	test	eax,eax
	jz	.refused
	; the chain: to the anchor, or to a root of the store
	test	r14,r14
	jz	.store
	mov	rdi,r14
	mov	rsi,[g_cx_tc+TC_CLIST]
	mov	edx,[g_cx_tc+TC_CLISTLEN]
	call	cert_chain_verify
	test	eax,eax
	jz	.refused
	mov	edx,[g_cx_tc+TC_CLISTLEN]
	jmp	.chained
.store:
	call	cx_store_verify			; edx = the length of the list that verified
	jc	.refused
.chained:
	; each in date (of the part that verified)
	push	rdx
	lea	rdi,[g_cx_now]
	call	alog_fmt_time
	lea	rsi,[g_cx_now]
	lea	rdi,[g_cx_now+32]
	lea	r9,[uptls_tdig]
	xor	ecx,ecx
@@:
	movzx	eax,byte [r9+rcx]
	mov	al,[rsi+rax]
	mov	[rdi+rcx],al
	inc	ecx
	cmp	ecx,14
	jb	@b
	pop	rdx
	mov	rsi,[g_cx_tc+TC_CLIST]
	lea	rdi,[g_cx_now+32]
	call	cert_chain_times
	test	eax,eax
	jz	.refused
	mov	rdi,[g_cx_sni]
	mov	ecx,[g_cx_snilen]
	mov	rsi,[g_cx_tc+TC_LEAF]
	mov	edx,[g_cx_tc+TC_LEAFLEN]
	call	cert_match_host
	test	eax,eax
	jz	.refused
	lea	rdi,[g_cx_tc]
	lea	rsi,[g_cx_out]
	call	tlsc_finish
	mov	edx,eax
	lea	rsi,[g_cx_out]
	mov	edi,[g_cx_fd]
	call	dk_write_all
	jc	.fail
	; what came after the flight's last record is the answer's start
	mov	eax,r13d
	mov	ecx,r12d
	sub	ecx,eax
	lea	rsi,[g_cx_in+rax]
	lea	rdi,[g_cx_in]
	mov	[g_cx_inlen],ecx
	rep	movsb
	mov	dword [g_cx_tls],1
	clc
	jmp	.out
.refused:
	mov	eax,4
	stc
	jmp	.out
.fail:
	mov	eax,1
	stc
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; r12d = bytes in g_cx_in: more. CF when it closed, failed, or is full.
cx_recv:
	mov	edx,CX_IN_CAP
	sub	edx,r12d
	jz	.bad
	mov	edi,[g_cx_fd]
	lea	rsi,[g_cx_in+r12]
	xor	eax,eax
	syscall
	cmp	rax,-EINTR
	je	cx_recv
	test	rax,rax
	jle	.bad
	add	r12d,eax
	clc
	ret
.bad:
	stc
	ret

; rsi/edx = what to send: sealed when the connection is TLS. CF when not sent.
cx_send:
	cmp	dword [g_cx_tls],0
	jne	.sealed
	mov	edi,[g_cx_fd]
	jmp	dk_write_all
.sealed:
	push	r12
	mov	r12d,edx
	mov	rdx,rsi
.record:
	test	r12d,r12d
	jz	.sent
	mov	ecx,r12d
	cmp	ecx,16000
	jbe	@f
	mov	ecx,16000
@@:
	sub	r12d,ecx
	push	rdx
	push	rcx
	lea	rdi,[g_cx_tc]
	lea	rsi,[g_cx_out]
	call	tlsc_seal
	mov	edx,eax
	lea	rsi,[g_cx_out]
	mov	edi,[g_cx_fd]
	call	dk_write_all
	pop	rcx
	pop	rdx
	jc	.bad
	add	rdx,rcx
	jmp	.record
.sent:
	clc
	pop	r12
	ret
.bad:
	stc
	pop	r12
	ret

; the whole answer, until the server closes: into g_dk_buf, g_cx_plain bytes.
; CF when it is cut short or does not open.
cx_answer:
	mov	dword [g_cx_plain],0
	cmp	dword [g_cx_tls],0
	jne	.tls
.plain:
	mov	edi,[g_cx_fd]
	mov	rsi,[g_dk_buf]
	mov	eax,[g_cx_plain]
	add	rsi,rax
	mov	edx,DK_BUF - 1
	sub	edx,eax
	jz	.full
	xor	eax,eax
	syscall
	cmp	rax,-EINTR
	je	.plain
	test	rax,rax
	js	.cut
	jz	.done
	add	[g_cx_plain],eax
	jmp	.plain
.full:
.cut:
	stc
	ret
.done:
	clc
	ret
.tls:
	push	r12
	push	r13
	mov	r12d,[g_cx_inlen]
	xor	r13d,r13d			; where the next record starts
.rec:
	lea	eax,[r13+5]
	cmp	eax,r12d
	ja	.more
	movzx	eax,word [g_cx_in+r13+3]
	xchg	al,ah
	lea	eax,[r13+rax+5]
	cmp	eax,r12d
	ja	.more
	push	rax
	lea	rdi,[g_cx_tc]
	lea	rsi,[g_cx_in+r13]
	call	tlsc_open
	pop	r13				; (the next record)
	test	eax,eax
	jz	.bad
	cmp	r8d,21
	je	.closed				; an alert: close_notify, it is over
	cmp	r8d,23
	jne	.rec				; (a ticket)
	mov	eax,[g_cx_plain]
	lea	edx,[rax+rcx]
	cmp	edx,DK_BUF - 1
	ja	.bad
	mov	rdi,[g_dk_buf]
	add	rdi,rax
	mov	[g_cx_plain],edx
	rep	movsb
	jmp	.rec
.more:
	mov	ecx,r12d
	sub	ecx,r13d
	lea	rsi,[g_cx_in+r13]
	lea	rdi,[g_cx_in]
	mov	r12d,ecx
	rep	movsb
	xor	r13d,r13d
	call	cx_recv
	jnc	.rec
	test	r12d,r12d
	jnz	.bad
.closed:
	clc
	jmp	.tls_out
.bad:
	stc
.tls_out:
	pop	r13
	pop	r12
	ret

; rsi/edx = an answer of g_dk_buf (g_cx_plain bytes): eax = its status, rsi
; = its body, ecx = the body's length. CF when it is not an HTTP answer.
cx_status:
	mov	rsi,[g_dk_buf]
	mov	ecx,[g_cx_plain]
	cmp	ecx,16
	jb	.bad
	cmp	dword [rsi],'HTTP'
	jne	.bad
	movzx	eax,byte [rsi+9]
	sub	eax,'0'
	imul	eax,eax,100
	movzx	edx,byte [rsi+10]
	sub	edx,'0'
	imul	edx,edx,10
	add	eax,edx
	movzx	edx,byte [rsi+11]
	sub	edx,'0'
	add	eax,edx
.head:
	cmp	ecx,4
	jb	.bad
	cmp	dword [rsi],0x0A0D0A0D
	je	.body
	inc	rsi
	dec	ecx
	jmp	.head
.body:
	add	rsi,4
	sub	ecx,4
	clc
	ret
.bad:
	stc
	ret

; ------------------------------------------------------------ the store

; the system's roots, once: g_cx_roots, g_cx_nroots. CF when there are none.
cx_store_load:
	cmp	dword [g_cx_nroots],0
	jg	.have
	jl	.none
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	xor	edi,edi
	mov	esi,CX_ROOTS * CXR_SIZE + CX_BUNDLE_MAX
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.failed
	mov	[g_cx_roots],rax
	lea	rdi,[str_ssl_cert_file]
	mov	esi,str_ssl_cert_file.len
	call	getenv
	test	rax,rax
	jz	.system
	mov	edi,AT_FDCWD
	mov	rsi,rax
	mov	edx,O_RDONLY or O_CLOEXEC
	xor	r10d,r10d
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	jns	.open
	jmp	.failed				; (named and not there: not another one instead)
.system:
	lea	rbx,[cx_bundles]
.bundle:
	cmp	byte [rbx],0
	je	.failed
	mov	edi,AT_FDCWD
	mov	rsi,rbx
	mov	edx,O_RDONLY or O_CLOEXEC
	xor	r10d,r10d
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	jns	.open
@@:
	inc	rbx
	cmp	byte [rbx-1],0
	jne	@b
	jmp	.bundle
.open:
	mov	r12d,eax
	mov	r13,[g_cx_roots]
	add	r13,CX_ROOTS * CXR_SIZE		; the text goes after the roots
	xor	r14d,r14d
.read:
	mov	edi,r12d
	lea	rsi,[r13+r14]
	mov	edx,CX_BUNDLE_MAX - 1
	sub	edx,r14d
	jz	.read_done
	xor	eax,eax
	syscall
	test	rax,rax
	jle	.read_done
	add	r14d,eax
	jmp	.read
.read_done:
	mov	edi,r12d
	mov	eax,SYS_close
	syscall
	; each CERTIFICATE: its subject's hash and its key
	mov	rsi,r13
	lea	r15,[r13+r14]			; the end
.cert:
	cmp	dword [g_cx_nroots],CX_ROOTS
	jae	.loaded
	mov	rdx,r15
	lea	rdi,[cx_cert_label]
	call	pem_next			; g_tls_der, eax = its length
	cmp	eax,-1
	je	.loaded
	test	eax,eax
	js	.cert				; (one that is broken: the next)
	push	rsi
	mov	r12d,eax
	lea	rsi,[g_tls_der]
	mov	edx,r12d
	call	x509_locate
	test	eax,eax
	jz	.skip
	mov	rsi,[g_x509_subj]
	mov	rcx,[g_x509_subjend]
	sub	rcx,rsi
	call	hash_bytes
	mov	ecx,[g_cx_nroots]
	imul	rdi,rcx,CXR_SIZE
	add	rdi,[g_cx_roots]
	mov	[rdi+CXR_HASH],rax
	add	rdi,CXR_KEY
	lea	rsi,[g_tls_der]
	mov	edx,r12d
	call	cert_pubkey
	test	eax,eax
	jz	.skip
	inc	dword [g_cx_nroots]
.skip:
	pop	rsi
	jmp	.cert
.loaded:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	cmp	dword [g_cx_nroots],0
	jg	.have
	mov	dword [g_cx_nroots],-1
.none:
	stc
	ret
.have:
	clc
	ret
.failed:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	mov	dword [g_cx_nroots],-1
	stc
	ret

; the chain in g_cx_tc to a root of the store: edx = the length of the start of
; the list that verified. CF when none does.
cx_store_verify:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	call	cx_store_load
	jc	.no
	; the ends of the entries, leaf first
	mov	rsi,[g_cx_tc+TC_CLIST]
	mov	r8d,[g_cx_tc+TC_CLISTLEN]
	add	r8,rsi
	xor	ebx,ebx				; entries
	sub	rsp,8 * 16
.entry:
	cmp	rsi,r8
	jae	.counted
	cmp	ebx,16
	jae	.counted
	call	chain_entry
	jc	.counted
	mov	[rsp+rbx*8],rdx			; where the next starts
	inc	ebx
	mov	rsi,rdx
	jmp	.entry
.counted:
	; the longest start whose last certificate a root signs
.try:
	test	ebx,ebx
	jz	.none
	mov	rax,[rsp+rbx*8-8]		; this start's end
	sub	rax,[g_cx_tc+TC_CLIST]
	mov	r12d,eax			; its length
	; its last certificate's issuer
	mov	rsi,[g_cx_tc+TC_CLIST]
	mov	r8,rsi
	add	r8,r12
	lea	ecx,[rbx-1]
.walk:
	push	rcx
	call	chain_entry			; rax = the DER, ecx = its length
	pop	r9
	test	r9d,r9d
	jz	.last
	mov	rsi,rdx
	lea	ecx,[r9-1]
	jmp	.walk
.last:
	mov	rsi,rax
	mov	edx,ecx
	call	x509_locate
	test	eax,eax
	jz	.shorter
	mov	rsi,[g_x509_iss]
	mov	rcx,[g_x509_issend]
	sub	rcx,rsi
	call	hash_bytes
	mov	r13,rax
	; every root with that subject (most often one)
	xor	r14d,r14d
.root:
	cmp	r14d,[g_cx_nroots]
	jae	.shorter
	imul	r15,r14,CXR_SIZE
	add	r15,[g_cx_roots]
	cmp	[r15+CXR_HASH],r13
	jne	.next_root
	lea	rdi,[r15+CXR_KEY]
	mov	rsi,[g_cx_tc+TC_CLIST]
	mov	edx,r12d
	call	cert_chain_verify
	test	eax,eax
	jnz	.found
.next_root:
	inc	r14d
	jmp	.root
.shorter:
	dec	ebx
	jmp	.try
.found:
	add	rsp,8 * 16
	mov	edx,r12d
	clc
	jmp	.out
.none:
	add	rsp,8 * 16
.no:
	stc
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rsi/ecx = a host as a URL has it (a name, an IPv4 address, [an IPv6 one]),
; edx = port, rdi = out: the sockaddr, edx = its length. CF when the host has
; no address. A name is resolved each time: no cache to go stale.
cx_address:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	rbx,rdi
	mov	r12,rsi
	mov	r13d,ecx
	mov	r14d,edx
	; an address as written ("10.0.0.5", "[::1]"): the URL had it so
	sub	rsp,AD_SIZE + 128
	mov	rsi,r12
	mov	ecx,r13d
	lea	rdi,[rsp+AD_SIZE]
	xor	r8d,r8d
	cmp	byte [rsi],'['
	je	.bracketed
	rep	movsb
	jmp	.port
.bracketed:
	rep	movsb
	mov	r8d,1
.port:
	mov	byte [rdi],':'
	inc	rdi
	mov	eax,r14d
	call	dk_decimal
	lea	rsi,[rsp+AD_SIZE]
	sub	rdi,rsi
	mov	esi,edi
	lea	rdi,[rsp+AD_SIZE]
	mov	rdx,rsp
	xor	ecx,ecx
	call	parse_address
	jc	.name
	mov	eax,[rsp+AD_KIND]
	cmp	eax,ADDR_V4
	je	.built
	cmp	eax,ADDR_V6
	je	.built
.name:
	; a name: resolved now (and again for each send: no cache to go stale)
	mov	rdi,r12
	mov	esi,r13d
	call	rs_lookup
	cmp	eax,RS_OK
	jne	.none
	mov	dword [rsp+AD_KIND],ADDR_V6
	cmp	byte [g_rs_result+RR_FAMILY],4
	jne	@f
	mov	dword [rsp+AD_KIND],ADDR_V4
@@:
	mov	rax,[g_rs_result+RR_ADDRS]
	mov	[rsp+AD_IP],rax
	mov	rax,[g_rs_result+RR_ADDRS+8]
	mov	[rsp+AD_IP+8],rax
	mov	[rsp+AD_PORT],r14d
.built:
	mov	rdi,rbx
	mov	rsi,rsp
	call	sockaddr_build
	mov	edx,eax
	add	rsp,AD_SIZE + 128
	clc
	jmp	.out
.none:
	add	rsp,AD_SIZE + 128
	stc
.out:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

