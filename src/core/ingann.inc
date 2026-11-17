; nginx's annotations on an Ingress (nginx.ingress.kubernetes.io/...), in
; okena's terms (ingress.inc writes them into the made-up HTTPRoutes; gwgen.inc
; reads what only a made-up route can carry: "x-okena" lines, a backendRef's
; "x-okena-proto" and "x-okena-sticky", an "x-okena-regex" rewrite):
;
;   rewrite-target T     paths become expressions (as nginx: anchored at their
;                        start, any case) and the path is rewritten to T; $1..$9
;                        are their groups
;   use-regex "true"     paths as expressions, without a rewrite
;   ssl-redirect         on by default for a rule whose host spec.tls covers:
;                        HTTP answers 308 to https; "false" turns it off
;   force-ssl-redirect   "true": every rule, TLS or not
;   backend-protocol     HTTPS, GRPC, GRPCS (HTTP, AUTO_HTTP: as without)
;   permanent-redirect U, temporal-redirect U, with -code: every path redirected
;   app-root /P          / alone redirected (302) to /P
;   whitelist-source-range, allowlist-source-range, denylist-source-range: CIDRs
;   proxy-body-size      8m, 1g, 0 (no cap)
;   enable-cors "true", cors-allow-origin, -methods, -headers, -credentials,
;                        cors-expose-headers, cors-max-age
;   proxy-read-timeout, proxy-send-timeout: seconds, for each try (rounded up to
;                        one of a dozen steps: okena keeps 32 try= clocks)
;   limit-rps, limit-rpm (per client, a burst of five times as nginx's)
;   affinity "cookie", session-cookie-name, session-cookie-max-age
;
; Every value is checked here before it is written: what does not pass is left
; out (an allowlist with no entry that passes lets nobody in). Snippets
; (configuration-snippet, server-snippet) are never taken.

bss
	align 8
	g_ing_meta	dq ?
	g_ing_spec	dq ?
	g_ing_ann	dq ?		; its annotations (an object), 0 none
	g_ing_host	dq ?		; the rule's host, 0 none
	g_ing_hostlen	dd ?
	g_ing_mode	dd ?		; the route: 0 every listener, 1 HTTP's (to HTTPS), 2 HTTPS's
	g_ia_regex	dd ?
	g_ia_ssl	dd ?
	g_ia_force	dd ?
	g_ia_proto	dd ?
	g_ia_rwlen	dd ?
	g_ia_rwcap	dd ?		; T has $N
	g_ia_rootlen	dd ?
	g_ia_rdlen	dd ?
	g_ia_stklen	dd ?
	g_ia_ttl	dd ?
	g_ia_lineslen	dd ?
	g_ia_nlines	dd ?
	g_ia_n		dd ?		; items in a list, so far
	g_ia_sep	dd ?		; and their separator
	g_ia_rw		dq ?
	g_ia_root	dq ?
	g_ia_rd		dq ?		; a requestRedirect (JSON), made
	g_ia_stk	dq ?
	g_ia_lines	dq ?		; "line","line" (JSON), made
	g_ia_undo	dq ?		; where a line began (taken back when it has nothing)
	g_ia_tr		rb 32		; parse_cidr's record
	g_ia_buf	rb 65536	; what is made (not GW_TEXT: a value read with escapes goes there)
end bss

macro ia_str key*
	mov	rsi,[g_ing_ann]
	gk	key
	call	gj_str
end macro

cstring ia_cookie, 'INGRESSCOOKIE'
cstring ia_methods, 'GET, PUT, POST, DELETE, PATCH, OPTIONS'
cstring ia_headers, 'DNT,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization'
cstring ia_star, '*'
	align 4
ia_steps	dd 1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 1800, 3600

; g_ing_meta = the Ingress's metadata: g_ia_*. Keeps rbx, r12-r15.
ing_annotations:
	push	rbx
	push	r12
	push	r14
	push	r15
	xor	eax,eax
	irp v, regex,force,proto,rwlen,rwcap,rootlen,rdlen,stklen,ttl,lineslen,nlines
		mov	[g_ia_#v],eax
	end irp
	mov	dword [g_ia_ssl],1
	mov	qword [g_ing_ann],0
	mov	rsi,[g_ing_meta]
	gk	'annotations'
	call	gj_get
	jc	.out
	cmp	byte [rsi],'{'
	jne	.out
	mov	[g_ing_ann],rsi
	lea	r15,[g_ia_buf]			; (what is made: copied into each route)
	; use-regex, ssl-redirect, force-ssl-redirect
	ia_str	'nginx.ingress.kubernetes.io/use-regex'
	jc	@f
	call	ia_true
	jne	@f
	mov	dword [g_ia_regex],1
@@:
	ia_str	'nginx.ingress.kubernetes.io/ssl-redirect'
	jc	@f
	cmp	ecx,5
	jne	@f
	cmp	dword [rdi],'fals'
	jne	@f
	cmp	byte [rdi+4],'e'
	jne	@f
	mov	dword [g_ia_ssl],0
@@:
	ia_str	'nginx.ingress.kubernetes.io/force-ssl-redirect'
	jc	@f
	call	ia_true
	jne	@f
	mov	dword [g_ia_force],1
@@:
	; backend-protocol: bits 1 HTTP/2, 2 TLS
	ia_str	'nginx.ingress.kubernetes.io/backend-protocol'
	jc	.bp_done
	cmp	ecx,4
	jb	.bp_done
	mov	eax,[rdi]
	or	eax,0x20202020
	cmp	ecx,5
	jne	.bp4
	cmp	eax,'http'
	jne	.bp_grpcs
	mov	al,[rdi+4]
	or	al,0x20
	cmp	al,'s'
	jne	.bp_done
	mov	dword [g_ia_proto],2
	jmp	.bp_done
.bp_grpcs:
	cmp	eax,'grpc'
	jne	.bp_done
	mov	al,[rdi+4]
	or	al,0x20
	cmp	al,'s'
	jne	.bp_done
	mov	dword [g_ia_proto],3
	jmp	.bp_done
.bp4:
	cmp	ecx,4
	jne	.bp_done
	cmp	eax,'grpc'
	jne	.bp_done
	mov	dword [g_ia_proto],1
.bp_done:
	; rewrite-target
	ia_str	'nginx.ingress.kubernetes.io/rewrite-target'
	jc	@f
	call	ia_target_ok			; eax = 1 with $N
	jc	@f
	mov	[g_ia_rw],rdi
	mov	[g_ia_rwlen],ecx
	mov	[g_ia_rwcap],eax
	mov	dword [g_ia_regex],1		; (nginx: its paths are expressions)
@@:
	; app-root
	ia_str	'nginx.ingress.kubernetes.io/app-root'
	jc	@f
	push	rdi
	push	rcx
	mov	edx,ecx
	mov	rcx,rdi
	call	gw_path_ok
	pop	rcx
	pop	rdi
	jc	@f
	mov	[g_ia_root],rdi
	mov	[g_ia_rootlen],ecx
@@:
	; permanent-redirect, temporal-redirect
	mov	r14d,301
	ia_str	'nginx.ingress.kubernetes.io/permanent-redirect'
	jnc	.rd
	mov	r14d,302
	ia_str	'nginx.ingress.kubernetes.io/temporal-redirect'
	jc	.rd_done
.rd:
	push	rdi
	push	rcx
	cmp	r14d,301
	jne	.rd_t
	ia_str	'nginx.ingress.kubernetes.io/permanent-redirect-code'
	jmp	.rd_code
.rd_t:
	ia_str	'nginx.ingress.kubernetes.io/temporal-redirect-code'
.rd_code:
	jc	.rd_url
	push	rdi
	mov	esi,ecx
	pop	rdi
	call	parse_decimal
	jc	.rd_url
	irp c, 301,302,303,307,308
		cmp	eax,c
		je	.rd_is
	end irp
	jmp	.rd_url
.rd_is:
	mov	r14d,eax
.rd_url:
	pop	rcx
	pop	rdi
	call	ia_url				; g_ia_rd, from rdi/ecx and r14d
.rd_done:
	; affinity
	ia_str	'nginx.ingress.kubernetes.io/affinity'
	jc	.aff_done
	cmp	ecx,6
	jne	.aff_done
	cmp	dword [rdi],'cook'
	jne	.aff_done
	cmp	word [rdi+4],'ie'
	jne	.aff_done
	lea	rax,[ia_cookie]
	mov	[g_ia_stk],rax
	mov	dword [g_ia_stklen],ia_cookie.len
	ia_str	'nginx.ingress.kubernetes.io/session-cookie-name'
	jc	@f
	mov	rsi,rdi
	call	iv_header			; (a token: a cookie's name too)
	jc	@f
	mov	[g_ia_stk],rdi
	mov	[g_ia_stklen],ecx
@@:
	ia_str	'nginx.ingress.kubernetes.io/session-cookie-max-age'
	jc	.aff_done
	mov	esi,ecx
	call	parse_decimal
	jc	.aff_done
	cmp	eax,31536000
	ja	.aff_done
	mov	[g_ia_ttl],eax
.aff_done:
	; the lines
	mov	[g_ia_lines],r15
	; allow, deny
	ia_str	'nginx.ingress.kubernetes.io/allowlist-source-range'
	jnc	.allow
	ia_str	'nginx.ingress.kubernetes.io/whitelist-source-range'
	jc	.deny
.allow:
	push	rdi
	push	rcx
	call	ia_line
	go_lit	'allow '
	pop	rcx
	pop	rsi
	mov	dword [g_ia_sep],' '
	lea	rdx,[iv_cidr]
	call	ia_list
	test	eax,eax
	jnz	@f
	go_lit	'255.255.255.255/32'		; (none passed: nobody)
@@:
	call	ia_line_end
.deny:
	ia_str	'nginx.ingress.kubernetes.io/denylist-source-range'
	jc	.body
	push	rdi
	push	rcx
	call	ia_line
	go_lit	'deny '
	pop	rcx
	pop	rsi
	mov	dword [g_ia_sep],' '
	lea	rdx,[iv_cidr]
	call	ia_list
	test	eax,eax
	jnz	@f
	call	ia_line_undo
	jmp	.body
@@:
	call	ia_line_end
.body:
	; proxy-body-size
	ia_str	'nginx.ingress.kubernetes.io/proxy-body-size'
	jc	.cors
	call	ia_size				; out, as a line
.cors:
	ia_str	'nginx.ingress.kubernetes.io/enable-cors'
	jc	.timeout
	call	ia_true
	jne	.timeout
	call	ia_cors
.timeout:
	ia_str	'nginx.ingress.kubernetes.io/proxy-read-timeout'
	jnc	@f
	ia_str	'nginx.ingress.kubernetes.io/proxy-send-timeout'
	jc	.limit
@@:
	mov	esi,ecx
	call	parse_decimal
	jc	.limit
	test	eax,eax
	jz	.limit
	xor	ecx,ecx
@@:
	mov	edx,[ia_steps+rcx*4]
	cmp	eax,edx
	jbe	@f
	inc	ecx
	cmp	ecx,11
	jb	@b
	mov	edx,3600
@@:
	call	ia_line
	go_lit	'timeout try='
	mov	eax,edx
	call	go_u
	go_lit	's'
	call	ia_line_end
.limit:
	mov	r14d,'s'
	ia_str	'nginx.ingress.kubernetes.io/limit-rps'
	jnc	@f
	mov	r14d,'m'
	ia_str	'nginx.ingress.kubernetes.io/limit-rpm'
	jc	.lines_done
@@:
	mov	esi,ecx
	call	parse_decimal
	jc	.lines_done
	test	eax,eax
	jz	.lines_done
	cmp	eax,1000000
	ja	.lines_done
	push	rax
	call	ia_line
	go_lit	'limit '
	mov	eax,[rsp]
	call	go_u
	mov	byte [r15],'/'
	mov	[r15+1],r14b
	add	r15,2
	go_lit	' burst='
	pop	rax
	imul	eax,eax,5
	call	go_u
	go_lit	' key=client.ip'
	call	ia_line_end
.lines_done:
	mov	rax,r15
	sub	rax,[g_ia_lines]
	mov	[g_ia_lineslen],eax
.out:
	pop	r15
	pop	r14
	pop	r12
	pop	rbx
	ret

; rdi/ecx: ZF when "true"
ia_true:
	cmp	ecx,4
	jne	@f
	cmp	dword [rdi],'true'
@@:
	ret

; a line begins (r15: GW_TEXT)
ia_line:
	mov	[g_ia_undo],r15
	cmp	dword [g_ia_nlines],0
	je	@f
	mov	byte [r15],','
	inc	r15
@@:
	mov	byte [r15],'"'
	inc	r15
	ret
ia_line_end:
	mov	byte [r15],'"'
	inc	r15
	inc	dword [g_ia_nlines]
	ret
; the line begun: taken back
ia_line_undo:
	mov	r15,[g_ia_undo]
	ret

; rsi/ecx = a list (by commas, spaces around them), rdx = a check (rsi/ecx:
; CF when not one): those that pass, out, g_ia_sep between them. eax = how
; many. At most 64.
ia_list:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdx
	lea	r13,[rsi+rcx]			; (the end)
	mov	dword [g_ia_n],0
.item:
	cmp	rsi,r13
	jae	.done
	cmp	byte [rsi],' '
	je	.skip
	cmp	byte [rsi],','
	je	.skip
	mov	rbx,rsi				; its start
@@:
	inc	rsi
	cmp	rsi,r13
	jae	@f
	cmp	byte [rsi],','
	je	@f
	cmp	byte [rsi],' '
	jne	@b
@@:
	push	rsi
	mov	rcx,rsi
	sub	rcx,rbx
	mov	rsi,rbx
	push	rcx
	call	r12
	pop	rcx
	jc	@f
	cmp	dword [g_ia_n],64
	jae	@f
	cmp	dword [g_ia_n],0
	je	.first
	mov	eax,[g_ia_sep]
	mov	[r15],al
	inc	r15
.first:
	mov	rsi,rbx
	call	go_bytes
	inc	dword [g_ia_n]
@@:
	pop	rsi
	jmp	.item
.skip:
	inc	rsi
	jmp	.item
.done:
	mov	eax,[g_ia_n]
	pop	r13
	pop	r12
	pop	rbx
	ret

; checks: rsi/ecx = an item, CF when it is not one. Keep rbx, r12-r15.
iv_cidr:
	cmp	ecx,43
	ja	.bad
	xor	eax,eax
@@:
	movzx	edx,byte [rsi+rax]
	cmp	dl,'/'
	je	.ok
	cmp	dl,'.'
	je	.ok
	cmp	dl,':'
	je	.ok
	sub	dl,'0'
	cmp	dl,9
	jbe	.ok
	movzx	edx,byte [rsi+rax]
	or	dl,0x20
	sub	dl,'a'
	cmp	dl,5
	ja	.bad
.ok:
	inc	eax
	cmp	eax,ecx
	jb	@b
	push	rsi
	push	rcx
	mov	rdi,rsi
	mov	esi,ecx
	lea	rdx,[g_ia_tr]
	call	parse_cidr
	pop	rcx
	pop	rsi
	ret
.bad:
	stc
	ret
iv_method:
	test	ecx,ecx
	jz	iv_cidr.bad
	cmp	ecx,16
	ja	iv_cidr.bad
	xor	eax,eax
@@:
	movzx	edx,byte [rsi+rax]
	or	dl,0x20
	sub	dl,'a'
	cmp	dl,25
	ja	iv_cidr.bad
	inc	eax
	cmp	eax,ecx
	jb	@b
	clc
	ret
iv_header:
	test	ecx,ecx
	jz	iv_cidr.bad
	cmp	ecx,64
	ja	iv_cidr.bad
	xor	eax,eax
@@:
	movzx	edx,byte [rsi+rax]
	cmp	dl,'-'
	je	.ok
	cmp	dl,'_'
	je	.ok
	lea	r8d,[rdx-'0']
	cmp	r8d,9
	jbe	.ok
	or	dl,0x20
	sub	dl,'a'
	cmp	dl,25
	ja	iv_cidr.bad
.ok:
	inc	eax
	cmp	eax,ecx
	jb	@b
	clc
	ret
; "*", or http[s]://[*.]host[:port]
iv_origin:
	cmp	ecx,1
	jne	@f
	cmp	byte [rsi],'*'
	je	.yes
@@:
	cmp	ecx,200
	ja	iv_cidr.bad
	xor	eax,eax
	cmp	ecx,8
	jb	iv_cidr.bad
	cmp	dword [rsi],'http'
	jne	iv_cidr.bad
	mov	eax,4
	cmp	byte [rsi+4],'s'
	jne	@f
	inc	eax
@@:
	cmp	byte [rsi+rax],':'
	jne	iv_cidr.bad
	cmp	word [rsi+rax+1],'//'
	jne	iv_cidr.bad
	add	eax,3
	lea	edx,[rax+2]
	cmp	edx,ecx
	jae	@f
	cmp	word [rsi+rax],'*.'
	jne	@f
	add	eax,2
@@:
	mov	edx,eax				; the host's start
.host:
	cmp	eax,ecx
	jae	.end
	movzx	r8d,byte [rsi+rax]
	cmp	r8b,':'
	je	.port
	cmp	r8b,'.'
	je	.h_ok
	cmp	r8b,'-'
	je	.h_ok
	lea	r9d,[r8-'0']
	cmp	r9d,9
	jbe	.h_ok
	or	r8b,0x20
	sub	r8b,'a'
	cmp	r8b,25
	ja	iv_cidr.bad
.h_ok:
	inc	eax
	jmp	.host
.port:
	cmp	eax,edx
	je	iv_cidr.bad
	inc	eax
	cmp	eax,ecx
	jae	iv_cidr.bad
@@:
	movzx	r8d,byte [rsi+rax]
	sub	r8b,'0'
	cmp	r8b,9
	ja	iv_cidr.bad
	inc	eax
	cmp	eax,ecx
	jb	@b
.yes:
	clc
	ret
.end:
	cmp	eax,edx
	je	iv_cidr.bad
	clc
	ret

; rdi/ecx = a rewrite-target: CF when not a path okena can write; eax = 1 when
; it has groups ($1..$9). Keeps rdi, rcx.
ia_target_ok:
	test	ecx,ecx
	jz	.bad
	cmp	ecx,512
	ja	.bad
	cmp	byte [rdi],'/'
	jne	.bad
	xor	r8d,r8d				; groups
	xor	eax,eax
.c:
	movzx	edx,byte [rdi+rax]
	cmp	dl,'$'
	jne	.plain
	inc	eax
	cmp	eax,ecx
	jae	.bad
	movzx	edx,byte [rdi+rax]
	sub	dl,'1'
	cmp	dl,8
	ja	.bad
	mov	r8d,1
	jmp	.next
.plain:
	lea	esi,[rdx-'0']
	cmp	esi,9
	jbe	.next
	mov	esi,edx
	or	esi,0x20
	sub	esi,'a'
	cmp	esi,25
	jbe	.next
	push	rdi
	push	rcx
	push	rax
	lea	rdi,[gw_path_ok.allowed]
	mov	ecx,gw_path_ok.allowed.len
	mov	eax,edx
	repne	scasb
	pop	rax
	pop	rcx
	pop	rdi
	jne	.bad
.next:
	inc	eax
	cmp	eax,ecx
	jb	.c
	mov	eax,r8d
	clc
	ret
.bad:
	stc
	ret

; rdi/ecx = a URL (http[s]://host[:port][/path]), r14d = the code: g_ia_rd, a
; requestRedirect. Left out when it is not one okena can write.
ia_url:
	cmp	ecx,8
	jb	.out
	cmp	dword [rdi],'http'
	jne	.out
	mov	eax,4
	xor	r9d,r9d				; https
	cmp	byte [rdi+4],'s'
	jne	@f
	inc	eax
	inc	r9d
@@:
	cmp	byte [rdi+rax],':'
	jne	.out
	cmp	word [rdi+rax+1],'//'
	jne	.out
	add	eax,3
	mov	r10d,eax			; the host's start
@@:
	cmp	eax,ecx
	jae	@f
	cmp	byte [rdi+rax],'/'
	je	@f
	cmp	byte [rdi+rax],':'
	je	@f
	inc	eax
	jmp	@b
@@:
	mov	r11d,eax			; its end
	push	rdi
	push	rcx
	push	rax
	push	r9
	lea	rcx,[rdi+r10]
	mov	edx,r11d
	sub	edx,r10d
	call	gw_sub_ok			; (a name)
	pop	r9
	pop	rax
	pop	rcx
	pop	rdi
	jc	.out
	xor	r8d,r8d				; the port
	cmp	eax,ecx
	jae	.parsed
	cmp	byte [rdi+rax],':'
	jne	.path
	inc	eax
@@:
	cmp	eax,ecx
	jae	.port_end
	movzx	edx,byte [rdi+rax]
	cmp	dl,'/'
	je	.port_end
	sub	dl,'0'
	cmp	dl,9
	ja	.out
	imul	r8d,r8d,10
	add	r8d,edx
	cmp	r8d,65535
	ja	.out
	inc	eax
	jmp	@b
.port_end:
	test	r8d,r8d
	jz	.out
.path:
.parsed:
	; the path: what is left, or /
	push	rdi
	push	rcx
	lea	rsi,[rdi+rax]
	sub	ecx,eax
	jnz	@f
	lea	rsi,[.slash]
	mov	ecx,1
@@:
	push	rsi
	push	rcx
	push	r8
	push	r9
	mov	edx,ecx
	mov	rcx,rsi
	call	gw_path_ok
	pop	r9
	pop	r8
	pop	rcx
	pop	rsi
	pop	rdx				; (the URL)
	pop	rdi
	jc	.out
	push	rsi
	push	rcx
	mov	[g_ia_rd],r15
	go_lit	'{"scheme":"http'
	test	r9d,r9d
	jz	@f
	go_lit	's'
@@:
	go_lit	'","hostname":"'
	lea	rsi,[rdi+r10]
	mov	ecx,r11d
	sub	ecx,r10d
	call	go_bytes
	go_lit	'"'
	test	r8d,r8d
	jz	@f
	go_lit	',"port":'
	mov	eax,r8d
	call	go_u
@@:
	go_lit	',"path":{"type":"ReplaceFullPath","replaceFullPath":"'
	pop	rcx
	pop	rsi
	call	go_bytes
	go_lit	'"},"statusCode":'
	mov	eax,r14d
	call	go_u
	go_lit	'}'
	mov	rax,r15
	sub	rax,[g_ia_rd]
	mov	[g_ia_rdlen],eax
.out:
	ret
.slash	db '/'

; rdi/ecx = proxy-body-size (8m, 512k, 1g, 1024, 0): a body_size line
ia_size:
	test	ecx,ecx
	jz	.out
	cmp	ecx,12
	ja	.out
	xor	edx,edx				; its unit
	movzx	eax,byte [rdi+rcx-1]
	or	al,0x20
	cmp	al,'k'
	je	.unit
	cmp	al,'m'
	je	.unit
	cmp	al,'g'
	jne	.number
.unit:
	mov	edx,eax
	dec	ecx
	jz	.out
.number:
	push	rdx
	push	rdi
	push	rcx
	mov	esi,ecx
	call	parse_decimal
	pop	rcx
	pop	rdi
	pop	rdx
	jc	.out
	call	ia_line
	test	rax,rax
	jnz	@f
	go_lit	'body_size off'
	jmp	.end
@@:
	go_lit	'body_size '
	call	go_u
	cmp	dl,'k'
	jne	@f
	go_lit	'KiB'
	jmp	.end
@@:
	cmp	dl,'m'
	jne	@f
	go_lit	'MiB'
	jmp	.end
@@:
	cmp	dl,'g'
	jne	@f
	go_lit	'GiB'
	jmp	.end
@@:
	go_lit	'B'
.end:
	call	ia_line_end
.out:
	ret

; enable-cors: a cors line, nginx's defaults for what is not said
ia_cors:
	push	r12
	call	ia_line
	go_lit	'cors origins='
	ia_str	'nginx.ingress.kubernetes.io/cors-allow-origin'
	jnc	@f
	lea	rdi,[ia_star]
	mov	ecx,1
@@:
	mov	rsi,rdi
	mov	dword [g_ia_sep],','
	lea	rdx,[iv_origin]
	call	ia_list
	test	eax,eax
	jz	.none				; (none that pass: no CORS)
	; * alone: no credentials (okena, as the Fetch standard, refuses both)
	xor	r12d,r12d
	cmp	byte [r15-1],'*'
	jne	@f
	cmp	byte [r15-2],'='
	jne	@f
	inc	r12d
@@:
	go_lit	' methods='
	ia_str	'nginx.ingress.kubernetes.io/cors-allow-methods'
	jnc	@f
	lea	rdi,[ia_methods]
	mov	ecx,ia_methods.len
@@:
	mov	rsi,rdi
	lea	rdx,[iv_method]
	call	ia_list
	test	eax,eax
	jz	.none
	go_lit	' headers='
	ia_str	'nginx.ingress.kubernetes.io/cors-allow-headers'
	jnc	@f
	lea	rdi,[ia_headers]
	mov	ecx,ia_headers.len
@@:
	mov	rsi,rdi
	lea	rdx,[iv_header]
	call	ia_list
	test	eax,eax
	jz	.none
	ia_str	'nginx.ingress.kubernetes.io/cors-expose-headers'
	jc	.age
	push	rdi
	push	rcx
	go_lit	' expose='
	pop	rcx
	pop	rsi
	lea	rdx,[iv_header]
	call	ia_list
	test	eax,eax
	jnz	.age
	sub	r15,8				; (none: no expose=)
.age:
	mov	eax,1728000
	push	rax
	ia_str	'nginx.ingress.kubernetes.io/cors-max-age'
	jc	@f
	mov	esi,ecx
	call	parse_decimal
	jc	@f
	cmp	eax,1728000
	ja	@f
	test	eax,eax
	jz	@f
	mov	[rsp],rax
@@:
	go_lit	' max_age='
	pop	rax
	call	go_u
	go_lit	's'
	test	r12d,r12d
	jnz	.done
	ia_str	'nginx.ingress.kubernetes.io/cors-allow-credentials'
	jc	@f
	cmp	ecx,5
	jne	@f
	cmp	dword [rdi],'fals'
	je	.done
@@:
	go_lit	' credentials'
.done:
	call	ia_line_end
	pop	r12
	ret
.none:
	call	ia_line_undo
	pop	r12
	ret

; ----------------------------------------------------------- writing them

; does HTTP go to HTTPS for the rule's host (g_ing_host)? eax = 1 when so.
; Keeps rbx, r12-r15.
ing_redirects:
	mov	eax,1
	cmp	dword [g_ia_force],0
	jne	.out
	xor	eax,eax
	cmp	dword [g_ia_ssl],0
	je	.out
	push	r12
	mov	rsi,[g_ing_spec]
	gk	'tls'
	call	gj_get
	jc	.no
	call	gj_first
	jc	.no
.tls:
	mov	r12,rsi
	gk	'hosts'
	call	gj_get
	jc	.yes				; (no hosts: every one)
	call	gj_first
	jc	.yes
.host:
	push	rsi
	call	ing_str_here
	jc	@f
	mov	rsi,[g_ing_host]
	mov	edx,[g_ing_hostlen]
	test	rsi,rsi
	jz	@f
	call	gw_same
	jne	@f
	pop	rsi
	jmp	.yes
@@:
	pop	rsi
	call	gj_next
	jnc	.host
	mov	rsi,r12
	call	gj_next
	jnc	.tls
.no:
	xor	eax,eax
	pop	r12
	ret
.yes:
	mov	eax,1
	pop	r12
.out:
	ret

; ebx = rules so far: app-root's (/ alone to it), when there is one. Keeps
; r12-r14.
ing_approot:
	cmp	dword [g_ia_rootlen],0
	je	.out
	cmp	dword [g_ing_mode],1
	je	.out
	test	ebx,ebx
	jz	@f
	go_lit	','
@@:
	inc	ebx
	go_lit	'{"matches":[{"path":{"type":"Exact","value":"/"}}],"filters":[{"type":"RequestRedirect","requestRedirect":{"path":{"type":"ReplaceFullPath","replaceFullPath":"'
	mov	rsi,[g_ia_root]
	mov	ecx,[g_ia_rootlen]
	call	go_bytes
	go_lit	'"},"statusCode":302}}]}'
.out:
	ret

; rsi/ecx = a path, r8d = 1 Exact (0 a prefix), r10d = 1 when it may be an
; expression (a rule's, not the default backend's), rdx/r9d = its backendRef:
; one rule, out. Keeps rbx, r12-r14.
ing_rule:
	push	r12
	push	r13
	mov	r12,rdx
	mov	r13d,r9d
	push	rsi
	push	rcx
	go_lit	'{"matches":[{"path":{"type":"'
	xor	r11d,r11d			; an expression
	test	r8d,r8d
	jz	@f
	go_lit	'Exact","value":"'
	jmp	.value
@@:
	test	r10d,r10d
	jz	.prefix
	cmp	dword [g_ia_regex],0
	je	.prefix
	inc	r11d
	go_lit	'RegularExpression","value":"(?i)'
	jmp	.value
.prefix:
	go_lit	'PathPrefix","value":"'
.value:
	pop	rcx
	pop	rsi
	call	go_bytes
	test	r11d,r11d
	jz	@f
	go_lit	'.*'
@@:
	go_lit	'"}}]'
	; the annotations' lines
	cmp	dword [g_ia_lineslen],0
	je	@f
	go_lit	',"x-okena":['
	mov	rsi,[g_ia_lines]
	mov	ecx,[g_ia_lineslen]
	call	go_bytes
	go_lit	']'
@@:
	; HTTP's side of an ssl-redirect: only that
	cmp	dword [g_ing_mode],1
	jne	@f
	go_lit	',"filters":[{"type":"RequestRedirect","requestRedirect":{"scheme":"https","statusCode":308}}]}'
	jmp	.out
@@:
	cmp	dword [g_ia_rdlen],0
	je	.rewrite
	go_lit	',"filters":[{"type":"RequestRedirect","requestRedirect":'
	mov	rsi,[g_ia_rd]
	mov	ecx,[g_ia_rdlen]
	call	go_bytes
	go_lit	'}]}'
	jmp	.out
.rewrite:
	cmp	dword [g_ia_rwlen],0
	je	.backend
	cmp	dword [g_ia_rwcap],0
	je	.full
	test	r11d,r11d
	jz	.backend			; (groups, of no expression: none)
	go_lit	',"filters":[{"type":"URLRewrite","urlRewrite":{"path":{"type":"x-okena-regex","replaceFullPath":"'
	jmp	.target
.full:
	go_lit	',"filters":[{"type":"URLRewrite","urlRewrite":{"path":{"type":"ReplaceFullPath","replaceFullPath":"'
.target:
	mov	rsi,[g_ia_rw]
	mov	ecx,[g_ia_rwlen]
	call	go_bytes
	go_lit	'"}}}]'
.backend:
	go_lit	',"backendRefs":['
	mov	rsi,r12
	mov	ecx,r13d
	call	go_bytes
	go_lit	']}'
.out:
	pop	r13
	pop	r12
	ret
