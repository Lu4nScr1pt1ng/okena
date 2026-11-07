; `discover kubernetes service=NAMESPACE/NAME [port=NAME|N] [api=HOST:PORT]
; [token=PATH] [ca=PATH] [name=HOST] [max=64]`: a pool's servers are the
; endpoints of a Kubernetes Service, from its EndpointSlices.
;
; The control process asks the API server once a second, over TLS 1.3 that it
; verifies (the chain to `ca`, each certificate in date, the server's name),
; with the service account's token, read again each time as it is rotated.
; It lists with resourceVersion=0, which the API server answers from its own
; cache and not from etcd, so that many okenas asking cost it little. The
; defaults are those of a pod: the API at KUBERNETES_SERVICE_HOST and _PORT,
; the token and the CA under /var/run/secrets/kubernetes.io/serviceaccount,
; the name kubernetes.default.svc.
;
; An endpoint is served when it is ready; when none is, those still serving
; while they terminate are (as kube-proxy does), so that a rollout that takes
; every pod down at once still has somewhere to go. Its port is the slice's
; port named by `port=`, or the number `port=` gives, or the slice's only
; port. An API server that does not answer, refuses, or answers what cannot
; be read changes nothing: the servers known go on, and it is said once.
; The service account needs `get` and `list` on endpointslices of the
; namespace.

KB_NS		:= 0			; q
KB_NSLEN	:= 8			; d
KB_PNUM		:= 12			; d: port= as a number, 0 none
KB_SVC		:= 16			; q
KB_SVCLEN	:= 24			; d
KB_PNLEN	:= 28			; d
KB_PNAME	:= 32			; q: port= as a name
KB_TOKEN	:= 40			; q: the token's path
KB_TOKLEN	:= 48			; d
KB_SNILEN	:= 52			; d
KB_SNI		:= 56			; q
KB_SALEN	:= 64			; d
KB_SA		:= 72			; 28
KB_ANCHOR	:= 104			; the CA's key (PK_SIZE)
KB_SIZE		:= (KB_ANCHOR + PK_SIZE + 63) and not 63
KB_IN_CAP	:= 1 shl 16
KB_TOKEN_MAX	:= 8192

bss
	align 8
	g_plan_kb:	rb KB_SIZE * DISC_SOURCES	; per source (plan)
	g_kb_tc:	rb TC_FULL
	g_kb_snap:	rb SHA256_CTX_SIZE
	g_kb_out:	rb 20480
	g_kb_in:	rb KB_IN_CAP
	g_kb_dec:	rb KB_IN_CAP
	g_kb_tok:	rb KB_TOKEN_MAX + 8
	g_kb_req:	rb KB_TOKEN_MAX + 1024
	g_kb_path:	rb 4096 + 8
	g_kb_now:	rb 64
	g_kb_fd		dd ?
	g_kb_inlen	dd ?
	g_kb_plain	dd ?		; plaintext so far in g_dk_buf
end bss

cstring str_kb_token, '/var/run/secrets/kubernetes.io/serviceaccount/token'
cstring str_kb_ca, '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'
cstring str_kb_sni, 'kubernetes.default.svc'

; ebx = a kubernetes group: ask, and publish. eax = seconds to the next look.
disc_kube_poll:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	imul	r12,rbx,GR_SIZE
	lea	r12,[g_groups+r12]
	mov	r13d,[r12+GR_DISC]
	imul	r14,r13,KB_SIZE
	lea	r14,[g_plan_kb+r14]		; this source
	cmp	qword [g_dk_buf],0
	jne	@f
	xor	edi,edi
	mov	esi,DK_BUF
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.no_answer
	mov	[g_dk_buf],rax
@@:
	call	kb_token			; g_kb_tok, eax = its length or 0
	test	eax,eax
	jz	.no_token
	mov	r15d,eax
	call	kb_connect			; g_kb_fd; CF when not
	jc	.no_answer
	call	kb_handshake			; CF: refused, or not who it should be
	jc	.not_verified
	mov	edx,r15d
	call	kb_request			; sealed and sent; CF when not
	jc	.no_answer_close
	call	kb_answer			; g_dk_buf, g_kb_plain bytes; CF when cut
	jc	.no_answer_close
	mov	edi,[g_kb_fd]
	mov	eax,SYS_close
	syscall
	; 200, then the body
	mov	rsi,[g_dk_buf]
	mov	ecx,[g_kb_plain]
	cmp	ecx,16
	jb	.unreadable
	cmp	dword [rsi+8],' 200'
	jne	.status
	mov	rdi,rsi
.head:
	cmp	ecx,4
	jb	.unreadable
	cmp	dword [rdi],0x0A0D0A0D
	je	.body
	inc	rdi
	dec	ecx
	jmp	.head
.body:
	push	r13
	mov	r13,[g_dk_buf]
	mov	eax,[g_kb_plain]
	add	r13,rax				; (the parser's end)
	lea	rsi,[rdi+4]
	call	kb_parse
	pop	r13
	jc	.unreadable
	call	disc_publish
	mov	dword [g_disc_said+r13*4],0
	jmp	.out
.status:
	mov	eax,3
	cstring str_kb_status, ': the API server refused the question (not 200: is the service account allowed to list endpointslices?)'
	lea	rsi,[str_kb_status]
	mov	edx,str_kb_status.len
	jmp	.tell
.unreadable:
	mov	eax,2
	cstring str_kb_bad, ': an answer that cannot be read'
	lea	rsi,[str_kb_bad]
	mov	edx,str_kb_bad.len
	jmp	.tell
.not_verified:
	mov	edi,[g_kb_fd]
	mov	eax,SYS_close
	syscall
	mov	eax,4
	cstring str_kb_cert, ': the API server is not who it should be (its certificate, or its name)'
	lea	rsi,[str_kb_cert]
	mov	edx,str_kb_cert.len
	jmp	.tell
.no_token:
	mov	eax,5
	cstring str_kb_tok, ': no token to read'
	lea	rsi,[str_kb_tok]
	mov	edx,str_kb_tok.len
	jmp	.tell
.no_answer_close:
	mov	edi,[g_kb_fd]
	mov	eax,SYS_close
	syscall
.no_answer:
	mov	eax,1
	cstring str_kb_gone, ': no answer from the API server'
	lea	rsi,[str_kb_gone]
	mov	edx,str_kb_gone.len
.tell:
	cmp	[g_disc_said+r13*4],eax
	je	.out
	mov	[g_disc_said+r13*4],eax
	push	rsi
	push	rdx
	call	log_begin
	out_lit 'discover kubernetes '
	mov	rsi,[r14+KB_NS]
	mov	edx,[r14+KB_NSLEN]
	call	out_str
	out_lit '/'
	mov	rsi,[r14+KB_SVC]
	mov	edx,[r14+KB_SVCLEN]
	call	out_str
	pop	rdx
	pop	rsi
	call	out_str
	out_lit '; keeping the servers known so far'
	call	log_end
.out:
	mov	eax,1
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; r14 = source: g_kb_tok, eax = its length (blanks at its end left out), 0
; when it cannot be read
kb_token:
	mov	rsi,[r14+KB_TOKEN]
	mov	ecx,[r14+KB_TOKLEN]
	lea	rdi,[g_kb_path]
	rep	movsb
	mov	byte [rdi],0
	mov	edi,AT_FDCWD
	lea	rsi,[g_kb_path]
	mov	edx,O_RDONLY or O_CLOEXEC
	xor	r10d,r10d
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	js	.none
	push	rax
	xor	ecx,ecx
.read:
	mov	edi,[rsp]
	lea	rsi,[g_kb_tok+rcx]
	mov	edx,KB_TOKEN_MAX
	sub	edx,ecx
	jz	.read_done
	push	rcx
	xor	eax,eax
	syscall
	pop	rcx
	test	rax,rax
	jle	.read_done
	add	ecx,eax
	jmp	.read
.read_done:
	pop	rdi
	push	rcx
	mov	eax,SYS_close
	syscall
	pop	rcx
	cmp	ecx,KB_TOKEN_MAX
	jae	.none				; (too long to be a token)
.trim:
	test	ecx,ecx
	jz	.none
	cmp	byte [g_kb_tok+rcx-1],' '
	ja	.check
	dec	ecx
	jmp	.trim
.check:
	; a header value: nothing that could end it
	xor	eax,eax
@@:
	cmp	byte [g_kb_tok+rax],' '
	jbe	.none
	cmp	byte [g_kb_tok+rax],127
	jae	.none
	inc	eax
	cmp	eax,ecx
	jb	@b
	mov	eax,ecx
	ret
.none:
	xor	eax,eax
	ret

; r14 = source: a connection to the API server in g_kb_fd. CF when not.
kb_connect:
	movzx	edi,word [r14+KB_SA]
	mov	esi,SOCK_STREAM or SOCK_CLOEXEC
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	.bad
	mov	[g_kb_fd],eax
	mov	edi,eax
	mov	esi,SOL_SOCKET
	mov	edx,SO_RCVTIMEO
	lea	r10,[ts_dk_io]
	mov	r8d,16
	mov	eax,SYS_setsockopt
	syscall
	mov	edi,[g_kb_fd]
	mov	esi,SOL_SOCKET
	mov	edx,SO_SNDTIMEO
	lea	r10,[ts_dk_io]
	mov	r8d,16
	mov	eax,SYS_setsockopt
	syscall
	mov	edi,[g_kb_fd]
	lea	rsi,[r14+KB_SA]
	mov	edx,[r14+KB_SALEN]
	mov	eax,SYS_connect
	syscall
	test	eax,eax
	js	.close
	clc
	ret
.close:
	mov	edi,[g_kb_fd]
	mov	eax,SYS_close
	syscall
.bad:
	stc
	ret

; r14 = source, g_kb_fd connected: the TLS 1.3 handshake, the server
; verified. CF when it is not, or it failed.
kb_handshake:
	push	rbx
	push	r12
	push	r13
	push	r15
	lea	rdi,[g_kb_tc]
	lea	rsi,[g_kb_out]
	mov	rdx,[r14+KB_SNI]
	mov	ecx,[r14+KB_SNILEN]
	call	tlsc_client_hello
	test	eax,eax
	jz	.fail
	mov	edx,eax
	lea	rsi,[g_kb_out]
	mov	edi,[g_kb_fd]
	call	dk_write_all
	jc	.fail
	lea	rsi,[g_kb_tc+TC_SHA]		; the transcript through the ClientHello
	lea	rdi,[g_kb_snap]
	mov	ecx,SHA256_CTX_SIZE
	rep	movsb
	xor	r12d,r12d			; bytes received
	xor	r13d,r13d			; the records tried end here
.read:
	call	kb_recv
	jc	.fail
.rec:
	lea	eax,[r13+5]
	cmp	eax,r12d
	ja	.read
	movzx	eax,word [g_kb_in+r13+3]
	xchg	al,ah
	lea	eax,[r13+rax+5]
	cmp	eax,r12d
	ja	.read
	mov	r13d,eax
	lea	rsi,[g_kb_in]
	mov	edx,r13d
	call	tlsc_is_tls12
	test	eax,eax
	jnz	.fail				; (an API server speaks 1.3)
	lea	rsi,[g_kb_snap]
	lea	rdi,[g_kb_tc+TC_SHA]
	mov	ecx,SHA256_CTX_SIZE
	rep	movsb
	lea	rdi,[g_kb_tc]
	lea	rsi,[g_kb_in]
	mov	edx,r13d
	lea	rcx,[g_kb_dec]
	call	tlsc_server_flight
	test	eax,eax
	jz	.rec
	mov	r15d,eax
	lea	rsi,[g_kb_dec]
	mov	edx,eax
	call	tlsc_flight_complete
	test	eax,eax
	jz	.rec
	lea	rdi,[g_kb_tc]
	lea	rsi,[g_kb_dec]
	mov	edx,r15d
	call	tlsc_verify
	test	eax,eax
	jz	.refused
	; the chain to the CA, each one in date, the name
	lea	rdi,[r14+KB_ANCHOR]
	mov	rsi,[g_kb_tc+TC_CLIST]
	mov	edx,[g_kb_tc+TC_CLISTLEN]
	call	cert_chain_verify
	test	eax,eax
	jz	.refused
	lea	rdi,[g_kb_now]
	call	alog_fmt_time
	lea	rsi,[g_kb_now]
	lea	rdi,[g_kb_now+32]
	lea	r9,[uptls_tdig]
	xor	ecx,ecx
@@:
	movzx	eax,byte [r9+rcx]
	mov	al,[rsi+rax]
	mov	[rdi+rcx],al
	inc	ecx
	cmp	ecx,14
	jb	@b
	mov	rsi,[g_kb_tc+TC_CLIST]
	mov	edx,[g_kb_tc+TC_CLISTLEN]
	lea	rdi,[g_kb_now+32]
	call	cert_chain_times
	test	eax,eax
	jz	.refused
	mov	rdi,[r14+KB_SNI]
	mov	ecx,[r14+KB_SNILEN]
	mov	rsi,[g_kb_tc+TC_LEAF]
	mov	edx,[g_kb_tc+TC_LEAFLEN]
	call	cert_match_host
	test	eax,eax
	jz	.refused
	lea	rdi,[g_kb_tc]
	lea	rsi,[g_kb_out]
	call	tlsc_finish
	mov	edx,eax
	lea	rsi,[g_kb_out]
	mov	edi,[g_kb_fd]
	call	dk_write_all
	jc	.fail
	; what came after the flight's last record is the answer's start
	mov	eax,r13d
	mov	ecx,r12d
	sub	ecx,eax
	lea	rsi,[g_kb_in+rax]
	lea	rdi,[g_kb_in]
	mov	[g_kb_inlen],ecx
	rep	movsb
	clc
	jmp	.out
.refused:
.fail:
	stc
.out:
	pop	r15
	pop	r13
	pop	r12
	pop	rbx
	ret

; r12d = bytes in g_kb_in: more. CF when it closed, failed, or is full.
kb_recv:
	mov	edx,KB_IN_CAP
	sub	edx,r12d
	jz	.bad
	mov	edi,[g_kb_fd]
	lea	rsi,[g_kb_in+r12]
	xor	eax,eax
	syscall
	cmp	rax,-EINTR
	je	kb_recv
	test	rax,rax
	jle	.bad
	add	r12d,eax
	clc
	ret
.bad:
	stc
	ret

; r14 = source, edx = token length: the question, sealed. CF when not sent.
kb_request:
	push	r12
	lea	rdi,[g_kb_req]
	cstring str_kb_get1, 'GET /apis/discovery.k8s.io/v1/namespaces/'
	lea	rsi,[str_kb_get1]
	mov	ecx,str_kb_get1.len
	rep	movsb
	mov	rsi,[r14+KB_NS]
	mov	ecx,[r14+KB_NSLEN]
	rep	movsb
	cstring str_kb_get2, '/endpointslices?labelSelector=kubernetes.io%2Fservice-name%3D'
	lea	rsi,[str_kb_get2]
	mov	ecx,str_kb_get2.len
	rep	movsb
	mov	rsi,[r14+KB_SVC]
	mov	ecx,[r14+KB_SVCLEN]
	rep	movsb
	cstring str_kb_get3, '&resourceVersion=0 HTTP/1.0',13,10,'Host: '
	lea	rsi,[str_kb_get3]
	mov	ecx,str_kb_get3.len
	rep	movsb
	mov	rsi,[r14+KB_SNI]
	mov	ecx,[r14+KB_SNILEN]
	rep	movsb
	cstring str_kb_get4, 13,10,'Accept: application/json',13,10,'Authorization: Bearer '
	lea	rsi,[str_kb_get4]
	mov	ecx,str_kb_get4.len
	rep	movsb
	lea	rsi,[g_kb_tok]
	mov	ecx,edx
	rep	movsb
	mov	dword [rdi],0x0A0D0A0D
	add	rdi,4
	lea	rax,[g_kb_req]
	sub	rdi,rax
	mov	r12d,edi			; to go
	lea	rdx,[g_kb_req]
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
	lea	rdi,[g_kb_tc]
	lea	rsi,[g_kb_out]
	call	tlsc_seal
	mov	edx,eax
	lea	rsi,[g_kb_out]
	mov	edi,[g_kb_fd]
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

; the answer's records, opened, into g_dk_buf (g_kb_plain bytes) until the
; server closes. CF when it is cut short or does not open.
kb_answer:
	push	r12
	push	r13
	mov	dword [g_kb_plain],0
	mov	r12d,[g_kb_inlen]
	xor	r13d,r13d			; where the next record starts
.rec:
	lea	eax,[r13+5]
	cmp	eax,r12d
	ja	.more
	movzx	eax,word [g_kb_in+r13+3]
	xchg	al,ah
	lea	eax,[r13+rax+5]
	cmp	eax,r12d
	ja	.more
	push	rax
	lea	rdi,[g_kb_tc]
	lea	rsi,[g_kb_in+r13]
	call	tlsc_open
	pop	r13				; (the next record)
	test	eax,eax
	jz	.bad
	cmp	r8d,21
	je	.done				; an alert: close_notify, it is over
	cmp	r8d,23
	jne	.rec				; (a ticket)
	mov	eax,[g_kb_plain]
	lea	edx,[rax+rcx]
	cmp	edx,DK_BUF - 1
	ja	.bad
	mov	rdi,[g_dk_buf]
	add	rdi,rax
	mov	[g_kb_plain],edx
	rep	movsb
	jmp	.rec
.more:
	; the rest to the front, then more
	mov	ecx,r12d
	sub	ecx,r13d
	lea	rsi,[g_kb_in+r13]
	lea	rdi,[g_kb_in]
	mov	r12d,ecx
	rep	movsb
	xor	r13d,r13d
	call	kb_recv
	jnc	.rec
	; closed: a whole answer if nothing was cut
	test	r12d,r12d
	jnz	.bad
.done:
	clc
	jmp	.out
.bad:
	stc
.out:
	pop	r13
	pop	r12
	ret

; ------------------------------------------------------------ the list

; rsi = the body, r13 = its end, r12 = group, r14 = source: g_disc_new from
; the slices. CF when it is not an EndpointSliceList.
kb_parse:
	push	rbx
	push	r15
	mov	dword [g_disc_new+DX_COUNT],0
	mov	rbx,rsi
	xor	r15d,r15d			; pass: 0 the ready ones, 1 the terminating that serve
.pass:
	mov	rsi,rbx
	js_key 'items'
	call	js_find
	jc	.bad
	call	js_ws
	cmp	rsi,r13
	jae	.bad
	cmp	byte [rsi],'n'			; null: none
	je	.done
	cmp	byte [rsi],'['
	jne	.bad
	inc	rsi
.slice:
	call	js_ws
	cmp	rsi,r13
	jae	.bad
	cmp	byte [rsi],']'
	je	.passed
	push	rsi
	call	kb_slice
	pop	rsi
	call	js_skip
	jc	.bad
	call	js_ws
	cmp	rsi,r13
	jae	.bad
	cmp	byte [rsi],','
	jne	@f
	inc	rsi
	jmp	.slice
@@:
	cmp	byte [rsi],']'
	jne	.bad
.passed:
	cmp	dword [g_disc_new+DX_COUNT],0
	jne	.done
	inc	r15d
	cmp	r15d,2
	jb	.pass
.done:
	clc
	jmp	.out
.bad:
	stc
.out:
	pop	r15
	pop	rbx
	ret

; rsi = a slice, r15d = the pass: its endpoints into g_disc_new
kb_slice:
	push	rbx
	push	rbp
	mov	rbx,rsi
	; IPv4 or IPv6 (FQDN slices are left out)
	js_key 'addressType'
	call	js_find
	jc	.out
	call	js_str
	jc	.out
	cmp	ecx,4
	jne	.out
	cmp	word [rdi],'IP'
	jne	.out
	; its port
	mov	ebp,[r14+KB_PNUM]
	test	ebp,ebp
	jnz	.ported
	call	kb_port				; eax, or 0
	test	eax,eax
	jz	.out
	mov	ebp,eax
.ported:
	mov	rsi,rbx
	js_key 'endpoints'
	call	js_find
	jc	.out
	call	js_ws
	cmp	rsi,r13
	jae	.out
	cmp	byte [rsi],'['
	jne	.out
	inc	rsi
.endpoint:
	call	js_ws
	cmp	rsi,r13
	jae	.out
	cmp	byte [rsi],']'
	je	.out
	push	rsi
	call	kb_endpoint
	pop	rsi
	call	js_skip
	jc	.out
	call	js_ws
	cmp	rsi,r13
	jae	.out
	cmp	byte [rsi],','
	jne	.out
	inc	rsi
	jmp	.endpoint
.out:
	pop	rbp
	pop	rbx
	ret

; rbx = a slice: eax = the port to use (by name, or its only one), 0 none
kb_port:
	push	r12
	xor	r12d,r12d			; found
	xor	r8d,r8d				; how many
	mov	rsi,rbx
	js_key 'ports'
	call	js_find
	jc	.out
	call	js_ws
	cmp	rsi,r13
	jae	.out
	cmp	byte [rsi],'['
	jne	.out
	inc	rsi
.port:
	call	js_ws
	cmp	rsi,r13
	jae	.out
	cmp	byte [rsi],']'
	je	.out
	inc	r8d
	push	r8
	push	rsi
	js_key 'port'
	call	js_find
	jc	.next
	call	js_port
	jc	.next
	mov	r9d,eax
	cmp	dword [r14+KB_PNLEN],0
	jne	.named
	; no name asked: the only one
	pop	rsi
	pop	r8
	push	r8
	push	rsi
	mov	r12d,r9d
	jmp	.next
.named:
	mov	rsi,[rsp]
	push	r9
	js_key 'name'
	call	js_find
	pop	r9
	jc	.next
	push	r9
	call	js_str
	pop	r9
	jc	.next
	cmp	ecx,[r14+KB_PNLEN]
	jne	.next
	mov	rsi,[r14+KB_PNAME]
	repe	cmpsb
	jne	.next
	mov	r12d,r9d
	mov	r8d,-1000			; (found by name: how many does not matter)
	mov	[rsp+8],r8
.next:
	pop	rsi
	pop	r8
	call	js_skip
	jc	.out
	call	js_ws
	cmp	rsi,r13
	jae	.out
	cmp	byte [rsi],','
	jne	.out
	inc	rsi
	jmp	.port
.out:
	mov	eax,r12d
	cmp	dword [r14+KB_PNLEN],0
	jne	.by_name
	cmp	r8d,1
	je	.done
	xor	eax,eax				; more than one, none named: which?
	jmp	.done
.by_name:
	cmp	r8d,0
	jl	.done
	xor	eax,eax				; that name is not there
.done:
	pop	r12
	ret

; rsi = an endpoint, ebp = port, r15d = the pass: its addresses, when it is
; ready (pass 0), or serving while it terminates (pass 1)
kb_endpoint:
	push	rbx
	mov	rbx,rsi
	mov	rsi,rbx
	js_key 'conditions'
	call	js_find
	jc	.ready				; no conditions: ready (unknown is ready)
	push	rsi
	js_key 'ready'
	call	js_find
	mov	eax,1
	jc	@f
	call	kb_bool				; eax: 1 true, 0 false, 1 null
@@:
	pop	rsi
	test	r15d,r15d
	jnz	.terminating
	test	eax,eax
	jz	.out
	jmp	.ready
.terminating:
	test	eax,eax
	jnz	.out				; (ready: taken in the first pass)
	push	rsi
	js_key 'serving'
	call	js_find
	mov	eax,0
	jc	@f
	call	kb_bool
@@:
	pop	rsi
	test	eax,eax
	jz	.out
	js_key 'terminating'
	call	js_find
	jc	.out
	call	kb_bool
	test	eax,eax
	jz	.out
.ready:
	mov	rsi,rbx
	js_key 'addresses'
	call	js_find
	jc	.out
	call	js_ws
	cmp	rsi,r13
	jae	.out
	cmp	byte [rsi],'['
	jne	.out
	inc	rsi
.address:
	call	js_ws
	cmp	rsi,r13
	jae	.out
	cmp	byte [rsi],'"'
	jne	.out
	call	js_str
	jc	.out
	push	rsi
	call	kb_add				; rdi/ecx = the address
	pop	rsi
	call	js_ws
	cmp	rsi,r13
	jae	.out
	cmp	byte [rsi],','
	jne	.out
	inc	rsi
	jmp	.address
.out:
	pop	rbx
	ret

; rsi at a value: eax = 1 for true or null, 0 for false
kb_bool:
	call	js_ws
	mov	eax,1
	cmp	rsi,r13
	jae	.out
	cmp	byte [rsi],'f'
	jne	.out
	xor	eax,eax
.out:
	ret

; rdi/ecx = an address, ebp = port: into g_disc_new
kb_add:
	mov	eax,[g_disc_new+DX_COUNT]
	cmp	eax,[r12+GR_SLOTS]
	jae	.out
	cmp	ecx,45
	ja	.out
	; "a.b.c.d:P" or "[v6]:P"
	mov	rsi,rdi
	lea	rdi,[g_disc_tok]
	xor	r8d,r8d
	xor	edx,edx
@@:
	cmp	edx,ecx
	jae	@f
	cmp	byte [rsi+rdx],':'
	sete	al
	or	r8b,al
	inc	edx
	jmp	@b
@@:
	test	r8b,r8b
	jz	@f
	mov	byte [rdi],'['
	inc	rdi
@@:
	rep	movsb
	test	r8b,r8b
	jz	@f
	mov	byte [rdi],']'
	inc	rdi
@@:
	mov	byte [rdi],':'
	inc	rdi
	mov	eax,ebp
	call	dk_decimal
	lea	rsi,[g_disc_tok]
	sub	rdi,rsi
	mov	esi,edi
	lea	rdi,[g_disc_tok]
	lea	rdx,[g_disc_ad]
	xor	ecx,ecx
	call	parse_address
	jc	.out
	mov	eax,[g_disc_ad+AD_KIND]
	cmp	eax,ADDR_V4
	je	@f
	cmp	eax,ADDR_V6
	jne	.out
@@:
	mov	eax,[g_disc_new+DX_COUNT]
	inc	dword [g_disc_new+DX_COUNT]
	imul	rax,rax,DE_SIZE
	lea	rdi,[g_disc_new+DX_E+rax]
	mov	rcx,[g_disc_ad+AD_IP]
	mov	[rdi+DE_ADDR],rcx
	mov	rcx,[g_disc_ad+AD_IP+8]
	mov	[rdi+DE_ADDR+8],rcx
	mov	dword [rdi+DE_FAMILY],6
	cmp	dword [g_disc_ad+AD_KIND],ADDR_V4
	jne	@f
	mov	dword [rdi+DE_FAMILY],4
@@:
	mov	[rdi+DE_PORT],ebp
	mov	dword [rdi+DE_WEIGHT],1
	mov	dword [rdi+DE_BACKUP],0
.out:
	ret
