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
	g_kb_tok:	rb KB_TOKEN_MAX + 8
	g_kb_req:	rb KB_TOKEN_MAX + 1024
	g_kb_path:	rb 4096 + 8
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
	lea	rsi,[r14+KB_SA]
	mov	edx,[r14+KB_SALEN]
	call	cx_connect			; g_cx_fd; CF when not
	jc	.no_answer
	lea	rdi,[r14+KB_ANCHOR]
	mov	rsi,[r14+KB_SNI]
	mov	edx,[r14+KB_SNILEN]
	call	cx_handshake			; CF: refused, or not who it should be
	jc	.not_verified
	mov	edx,r15d
	call	kb_request			; sealed and sent; CF when not
	jc	.no_answer_close
	call	cx_answer			; g_dk_buf, g_cx_plain bytes; CF when cut
	jc	.no_answer_close
	call	cx_close
	; 200, then the body
	call	cx_status
	jc	.unreadable
	cmp	eax,200
	jne	.status
	push	r13
	lea	r13,[rsi+rcx]			; (the parser's end)
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
	cmp	eax,4
	jne	.no_answer_close		; (it failed, it did not lie)
	call	cx_close
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
	call	cx_close
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
	mov	edi,AL_DISCOVERY
	call	log_end_alert
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

; r14 = source, edx = token length: the question, sent. CF when not.
kb_request:
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
	lea	rsi,[g_kb_req]
	mov	rdx,rdi
	sub	rdx,rsi
	jmp	cx_send

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
