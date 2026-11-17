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
;   auth-url             `auth forward` to that URL's pool: a Service when its
;                        host is NAME, NAME.NS.svc[.DOMAIN], else the name (a
;                        $host in it is the rule's); auth-signin (nginx's
;                        variables as okena's), auth-response-headers as copy=,
;                        auth-cache-key with auth-cache-duration as cache=. One
;                        okena cannot serve: the rule answers 500, never opens
;   canary "true"        the Ingress is not served itself: its paths join those
;                        of the same host and path in its namespace, as nginx's
;                        canary-weight (and -total), canary-by-header (always,
;                        never), -by-header-value, -by-header-pattern and
;                        canary-by-cookie (always, never), in that order
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
	g_ing_list	dq ?		; the IngressList read (for canaries)
	g_ia_auth	dq ?		; auth-url, auth-signin, auth-response-headers
	g_ia_asign	dq ?
	g_ia_ahdr	dq ?
	g_ia_authlen	dd ?
	g_ia_asignlen	dd ?
	g_ia_ahdrlen	dd ?
	g_ia_acache	dd ?		; seconds, 0 not kept
	; a canary for the rule being written (ing_canary_find)
	g_ic_ref	dq ?		; its backendRef (JSON)
	g_ic_item	dq ?
	g_ic_hdr	dq ?
	g_ic_val	dq ?
	g_ic_pat	dq ?
	g_ic_cook	dq ?
	g_ic_reflen	dd ?		; 0: none
	g_ic_w		dd ?
	g_ic_total	dd ?
	g_ic_hlen	dd ?
	g_ic_vlen	dd ?
	g_ic_plen	dd ?
	g_ic_clen	dd ?
	g_icp_exact	dd ?
	g_icp_path	dq ?
	g_icp_len	dd ?
	; ing_rule's arguments, and the condition of the rule ing_rule_one writes
	g_ira_exact	dd ?
	g_ira_rx	dd ?
	g_ira_len	dd ?
	g_ira_rlen	dd ?
	g_ira_path	dq ?
	g_ira_ref	dq ?
	g_ir_cond	dd ?		; 0 none, 1 header=, 2 header~, 3 cookie
	g_ir_cnlen	dd ?
	g_ir_cvlen	dd ?
	g_ir_cname	dq ?
	g_ir_cval	dq ?
	; auth-url taken apart (ia_auth_obj)
	g_iau_host	dq ?
	g_iau_path	dq ?
	g_iau_svc	dq ?
	g_iau_ns	dq ?
	g_iau_hlen	dd ?
	g_iau_plen	dd ?
	g_iau_svclen	dd ?
	g_iau_nslen	dd ?
	g_iau_port	dd ?
	g_iau_tls	dd ?
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
	irp v, regex,force,proto,rwlen,rwcap,rootlen,rdlen,stklen,ttl,lineslen,nlines,authlen,asignlen,ahdrlen,acache
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
	; auth-url and its company (written per rule: ia_auth_obj)
	ia_str	'nginx.ingress.kubernetes.io/auth-url'
	jc	.auth_done
	mov	[g_ia_auth],rdi
	mov	[g_ia_authlen],ecx
	ia_str	'nginx.ingress.kubernetes.io/auth-signin'
	jc	@f
	mov	[g_ia_asign],rdi
	mov	[g_ia_asignlen],ecx
@@:
	ia_str	'nginx.ingress.kubernetes.io/auth-response-headers'
	jc	@f
	mov	[g_ia_ahdr],rdi
	mov	[g_ia_ahdrlen],ecx
@@:
	ia_str	'nginx.ingress.kubernetes.io/auth-cache-key'
	jc	.auth_done
	mov	dword [g_ia_acache],300		; (nginx: 200 202 401 5m)
	ia_str	'nginx.ingress.kubernetes.io/auth-cache-duration'
	jc	.auth_done
	call	ia_cache_time
.auth_done:
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
; its rules, out: one, or with a canary of the same host and path those that
; send to it first (header, then cookie), and the rule itself split by weight.
; Keeps rbx, r12-r14.
ing_rule:
	mov	dword [g_ir_cond],0
	mov	dword [g_ic_reflen],0
	test	r10d,r10d
	jz	ing_rule_one
	cmp	dword [g_ing_mode],1
	je	ing_rule_one
	cmp	dword [g_ia_rdlen],0
	jne	ing_rule_one
	mov	[g_ira_path],rsi
	mov	[g_ira_len],ecx
	mov	[g_ira_exact],r8d
	mov	[g_ira_rx],r10d
	mov	[g_ira_ref],rdx
	mov	[g_ira_rlen],r9d
	call	ing_canary_find
	cmp	dword [g_ic_reflen],0
	jne	.canary
	call	.args
	mov	rdx,[g_ira_ref]
	mov	r9d,[g_ira_rlen]
	jmp	ing_rule_one
.canary:
	cmp	dword [g_ic_hlen],0
	je	.cookie
	mov	rax,[g_ic_hdr]
	mov	[g_ir_cname],rax
	mov	eax,[g_ic_hlen]
	mov	[g_ir_cnlen],eax
	cmp	dword [g_ic_vlen],0
	je	@f
	mov	dword [g_ir_cond],1		; that value: the canary
	mov	rax,[g_ic_val]
	mov	ecx,[g_ic_vlen]
	call	.to_canary
	jmp	.cookie
@@:
	cmp	dword [g_ic_plen],0
	je	@f
	mov	dword [g_ir_cond],2		; a value it matches: the canary
	mov	rax,[g_ic_pat]
	mov	ecx,[g_ic_plen]
	call	.to_canary
	jmp	.cookie
@@:
	mov	dword [g_ir_cond],1		; always: the canary; never: not
	lea	rax,[.always]
	mov	ecx,6
	call	.to_canary
	lea	rax,[.never]
	mov	ecx,5
	call	.to_main
.cookie:
	cmp	dword [g_ic_clen],0
	je	.weighted
	mov	dword [g_ir_cond],3
	mov	rax,[g_ic_cook]
	mov	[g_ir_cname],rax
	mov	eax,[g_ic_clen]
	mov	[g_ir_cnlen],eax
	lea	rax,[.always]
	mov	ecx,6
	call	.to_canary
	lea	rax,[.never]
	mov	ecx,5
	call	.to_main
.weighted:
	mov	dword [g_ir_cond],0
	call	.args
	mov	rdx,[g_ira_ref]
	mov	r9d,[g_ira_rlen]
	mov	eax,[g_ic_w]
	test	eax,eax
	jz	ing_rule_one			; (none of it by weight)
	cmp	eax,[g_ic_total]
	jb	.both
	mov	rdx,[g_ic_ref]			; all of it
	mov	r9d,[g_ic_reflen]
	jmp	ing_rule_one
.both:
	; {main..., "weight": total - w}, {canary..., "weight": w}, in the text
	push	r15
	mov	r15,[g_gw_txt]
	push	r15
	mov	rsi,[g_ira_ref]
	mov	ecx,[g_ira_rlen]
	dec	ecx				; (its closing brace)
	call	go_bytes
	go_lit	',"weight":'
	mov	eax,[g_ic_total]
	sub	eax,[g_ic_w]
	call	go_u
	go_lit	'},'
	mov	rsi,[g_ic_ref]
	mov	ecx,[g_ic_reflen]
	dec	ecx
	call	go_bytes
	go_lit	',"weight":'
	mov	eax,[g_ic_w]
	call	go_u
	go_lit	'}'
	pop	rdx
	mov	r9,r15
	sub	r9,rdx
	mov	[g_gw_txt],r15
	pop	r15
	call	.args
	jmp	ing_rule_one
; rax/ecx = the condition's value: a rule to the canary, then a comma
.to_canary:
	mov	[g_ir_cval],rax
	mov	[g_ir_cvlen],ecx
	call	.args
	mov	rdx,[g_ic_ref]
	mov	r9d,[g_ic_reflen]
	jmp	.one
.to_main:
	mov	[g_ir_cval],rax
	mov	[g_ir_cvlen],ecx
	call	.args
	mov	rdx,[g_ira_ref]
	mov	r9d,[g_ira_rlen]
.one:
	call	ing_rule_one
	go_lit	','
	ret
.args:
	mov	rsi,[g_ira_path]
	mov	ecx,[g_ira_len]
	mov	r8d,[g_ira_exact]
	mov	r10d,[g_ira_rx]
	ret
.always	db 'always'
.never	db 'never'

; ing_rule's one rule: its arguments, and g_ir_cond's condition. Keeps rbx,
; r12-r14.
ing_rule_one:
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
	go_lit	'"}'
	call	ing_cond
	go_lit	'}]'
	; the annotations' lines
	cmp	dword [g_ia_lineslen],0
	je	@f
	go_lit	',"x-okena":['
	mov	rsi,[g_ia_lines]
	mov	ecx,[g_ia_lineslen]
	call	go_bytes
	go_lit	']'
@@:
	call	ia_auth_obj
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

; g_ir_cond: the match's condition, out (after its path)
ing_cond:
	mov	eax,[g_ir_cond]
	test	eax,eax
	jz	.out
	cmp	eax,3
	je	.cookie
	go_lit	',"headers":[{'
	cmp	eax,2
	jne	@f
	go_lit	'"type":"RegularExpression",'
@@:
	go_lit	'"name":"'
	mov	rsi,[g_ir_cname]
	mov	ecx,[g_ir_cnlen]
	call	go_bytes
	go_lit	'","value":"'
	cmp	dword [g_ir_cond],2
	jne	@f
	go_lit	'.*(?:'				; (nginx: anywhere in the value)
@@:
	mov	rsi,[g_ir_cval]
	mov	ecx,[g_ir_cvlen]
	call	go_bytes
	cmp	dword [g_ir_cond],2
	jne	@f
	go_lit	').*'
@@:
	go_lit	'"}]'
	ret
.cookie:
	go_lit	',"x-okena-cookies":[{"name":"'
	mov	rsi,[g_ir_cname]
	mov	ecx,[g_ir_cnlen]
	call	go_bytes
	go_lit	'","value":"'
	mov	rsi,[g_ir_cval]
	mov	ecx,[g_ir_cvlen]
	call	go_bytes
	go_lit	'"}]'
.out:
	ret

; rsi = an Ingress's metadata: ZF when it is a canary. Keeps all but rax, rcx,
; rdi, flags.
ing_is_canary:
	push	rsi
	gk	'annotations'
	call	gj_get
	jc	.no
	gk	'nginx.ingress.kubernetes.io/canary'
	call	gj_str
	jc	.no
	call	ia_true
	pop	rsi
	ret
.no:
	pop	rsi
	or	al,1				; (ZF clear)
	ret

; g_ira_path/len/exact, g_ing_host, g_ing_ns: the first canary Ingress of the
; class in that namespace with that host and path: g_ic_*. Keeps rbx, r12-r15.
ing_canary_find:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	qword [g_ic_item]
	mov	rsi,[g_ing_list]
	test	rsi,rsi
	jz	.out
	gk	'items'
	call	gj_get
	jc	.out
	cmp	byte [rsi],'['
	jne	.out
	call	gj_first
	jc	.out
.item:
	mov	[g_ic_item],rsi
	mov	rbx,rsi
	gk	'metadata'
	call	gj_get
	jc	.next
	mov	r12,rsi
	call	ing_is_canary
	jne	.next
	mov	rsi,r12
	gk	'namespace'
	call	gj_str
	jc	.next
	mov	rsi,[g_ing_ns]
	mov	edx,[g_ing_nslen]
	call	gw_same
	jne	.next
	call	ing_class_ok
	jc	.next
	mov	rsi,rbx
	gk	'spec'
	call	gj_get
	jc	.next
	gk	'rules'
	call	gj_get
	jc	.next
	call	gj_first
	jc	.next
.rule:
	mov	r14,rsi
	gk	'host'
	call	gj_str
	jc	.hostless
	mov	rsi,[g_ing_host]
	test	rsi,rsi
	jz	.rule_next
	mov	edx,[g_ing_hostlen]
	call	gw_same
	jne	.rule_next
	jmp	.paths
.hostless:
	cmp	qword [g_ing_host],0
	jne	.rule_next
.paths:
	mov	rsi,r14
	gk	'http'
	call	gj_get
	jc	.rule_next
	gk	'paths'
	call	gj_get
	jc	.rule_next
	call	gj_first
	jc	.rule_next
.path:
	push	rsi
	xor	r8d,r8d
	gk	'pathType'
	call	gj_str
	jc	@f
	cmp	ecx,5
	jne	@f
	cmp	dword [rdi],'Exac'
	jne	@f
	mov	r8d,1
@@:
	cmp	r8d,[g_ira_exact]
	jne	.path_next
	mov	rsi,[rsp]
	gk	'path'
	call	gj_str
	jnc	@f
	lea	rdi,[ing_path.slash]
	mov	ecx,1
@@:
	mov	rsi,[g_ira_path]
	mov	edx,[g_ira_len]
	call	gw_same
	jne	.path_next
	mov	rsi,[rsp]
	gk	'backend'
	call	gj_get
	jc	.path_next
	push	rbx
	mov	rbx,rsi
	call	ing_backend_ref
	pop	rbx
	jc	.path_next
	mov	[g_ic_ref],rdi
	mov	[g_ic_reflen],ecx
	pop	rsi
	mov	rsi,r12
	call	ic_annotations
	jmp	.out
.path_next:
	pop	rsi
	call	gj_next
	jnc	.path
.rule_next:
	mov	rsi,r14
	call	gj_next
	jnc	.rule
.next:
	mov	rsi,[g_ic_item]
	call	gj_next
	jnc	.item
.out:
	pop	qword [g_ic_item]
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rsi = a canary's metadata: its canary-* annotations, checked, in g_ic_*.
; Keeps rbx, r12-r15.
ic_annotations:
	push	r12
	xor	eax,eax
	mov	[g_ic_w],eax
	mov	[g_ic_hlen],eax
	mov	[g_ic_vlen],eax
	mov	[g_ic_plen],eax
	mov	[g_ic_clen],eax
	mov	dword [g_ic_total],100
	gk	'annotations'
	call	gj_get
	jc	.out
	mov	r12,rsi
	gk	'nginx.ingress.kubernetes.io/canary-weight-total'
	call	gj_str
	jc	@f
	mov	esi,ecx
	call	parse_decimal
	jc	@f
	test	eax,eax
	jz	@f
	cmp	rax,1000000
	ja	@f
	mov	[g_ic_total],eax
@@:
	mov	rsi,r12
	gk	'nginx.ingress.kubernetes.io/canary-weight'
	call	gj_str
	jc	@f
	mov	esi,ecx
	call	parse_decimal
	jc	@f
	cmp	rax,1000000
	ja	@f
	cmp	eax,[g_ic_total]
	jbe	.w
	mov	eax,[g_ic_total]
.w:
	mov	[g_ic_w],eax
@@:
	mov	rsi,r12
	gk	'nginx.ingress.kubernetes.io/canary-by-header'
	call	gj_str
	jc	.cookie
	mov	rsi,rdi
	call	iv_header
	jc	.cookie
	mov	[g_ic_hdr],rsi
	mov	[g_ic_hlen],ecx
	mov	rsi,r12
	gk	'nginx.ingress.kubernetes.io/canary-by-header-value'
	call	gj_str
	jc	@f
	call	iv_text
	jc	@f
	mov	[g_ic_val],rdi
	mov	[g_ic_vlen],ecx
@@:
	mov	rsi,r12
	gk	'nginx.ingress.kubernetes.io/canary-by-header-pattern'
	call	gj_str
	jc	.cookie
	call	iv_text
	jc	.cookie
	mov	[g_ic_pat],rdi
	mov	[g_ic_plen],ecx
.cookie:
	mov	rsi,r12
	gk	'nginx.ingress.kubernetes.io/canary-by-cookie'
	call	gj_str
	jc	.out
	mov	rsi,rdi
	call	iv_header
	jc	.out
	mov	[g_ic_cook],rsi
	mov	[g_ic_clen],ecx
.out:
	pop	r12
	ret

; rdi/ecx = a value written into JSON and okena's file: CF when empty, past
; 256 bytes, or holding a control character, a quote or a backslash. Keeps all
; but rax, flags.
iv_text:
	test	ecx,ecx
	jz	.bad
	cmp	ecx,256
	ja	.bad
	xor	eax,eax
.c:
	cmp	byte [rdi+rax],' '
	jb	.bad
	cmp	byte [rdi+rax],0x7F
	jae	.bad
	cmp	byte [rdi+rax],'"'
	je	.bad
	cmp	byte [rdi+rax],'\'
	je	.bad
	inc	eax
	cmp	eax,ecx
	jb	.c
	clc
	ret
.bad:
	stc
	ret

; rdi/ecx = auth-cache-duration ("200 202 401 5m"): its last word as seconds,
; in g_ia_acache when it is one (1s .. 1d)
ia_cache_time:
	test	ecx,ecx
	jz	.out
	lea	rsi,[rdi+rcx]			; the end
	mov	rdx,rsi
@@:
	cmp	rdx,rdi
	jbe	@f
	cmp	byte [rdx-1],' '
	je	@f
	dec	rdx
	jmp	@b
@@:
	mov	rcx,rsi
	sub	rcx,rdx
	jz	.out
	mov	r8d,1				; its unit
	movzx	eax,byte [rdx+rcx-1]
	cmp	al,'s'
	je	.unit
	mov	r8d,60
	cmp	al,'m'
	je	.unit
	mov	r8d,3600
	cmp	al,'h'
	je	.unit
	mov	r8d,86400
	cmp	al,'d'
	je	.unit
	mov	r8d,1
	jmp	.num
.unit:
	dec	ecx
.num:
	push	r8
	mov	rdi,rdx
	mov	esi,ecx
	call	parse_decimal
	pop	r8
	jc	.out
	test	rax,rax
	jz	.out
	cmp	rax,86400
	ja	.out
	imul	eax,r8d
	cmp	eax,86400
	ja	.out
	mov	[g_ia_acache],eax
.out:
	ret

; with an auth-url, and a rule that does not only redirect: its
; ,"x-okena-auth":{...} (gwgen.inc: gw_auth_line), {"bad":1} when the URL is not
; one okena can ask (so the rule answers 500, never lets in unasked)
ia_auth_obj:
	cmp	dword [g_ia_authlen],0
	je	.none
	cmp	dword [g_ing_mode],1
	je	.none
	cmp	dword [g_ia_rdlen],0
	jne	.none
	push	rbx
	push	r12
	go_lit	',"x-okena-auth":{'
	call	ia_auth_parse
	jc	.bad
	cmp	dword [g_iau_svclen],0
	je	.named
	go_lit	'"svc":"'
	mov	rsi,[g_iau_svc]
	mov	ecx,[g_iau_svclen]
	call	go_bytes
	go_lit	'","ns":"'
	mov	rsi,[g_iau_ns]
	mov	ecx,[g_iau_nslen]
	call	go_bytes
	jmp	.port
.named:
	go_lit	'"host":"'
	mov	rsi,[g_iau_host]
	mov	ecx,[g_iau_hlen]
	call	go_bytes
.port:
	go_lit	'","port":'
	mov	eax,[g_iau_port]
	call	go_u
	go_lit	',"tls":'
	mov	eax,[g_iau_tls]
	call	go_u
	go_lit	',"path":"'
	mov	rsi,[g_iau_path]
	mov	ecx,[g_iau_plen]
	call	go_bytes
	go_lit	'"'
	; copy= (auth-response-headers): the names that pass
	cmp	dword [g_ia_ahdrlen],0
	je	.signin
	mov	rbx,r15
	go_lit	',"copy":"'
	mov	rsi,[g_ia_ahdr]
	mov	ecx,[g_ia_ahdrlen]
	mov	dword [g_ia_sep],','
	lea	rdx,[iv_header]
	call	ia_list
	test	eax,eax
	jnz	@f
	mov	r15,rbx
	jmp	.signin
@@:
	go_lit	'"'
.signin:
	cmp	dword [g_ia_asignlen],0
	je	.cache
	mov	rbx,r15
	go_lit	',"signin":"'
	call	ia_signin
	jnc	@f
	mov	r15,rbx				; (one okena cannot write: a 401 instead)
	jmp	.cache
@@:
	go_lit	'"'
.cache:
	mov	eax,[g_ia_acache]
	test	eax,eax
	jz	.close
	go_lit	',"cache":'
	call	go_u
.close:
	go_lit	'}'
	pop	r12
	pop	rbx
.none:
	ret
.bad:
	go_lit	'"bad":1}'
	pop	r12
	pop	rbx
	ret

; g_ia_auth (http[s]://host[:port][/path]): g_iau_*. CF when it is not one.
ia_auth_parse:
	mov	rdi,[g_ia_auth]
	mov	ecx,[g_ia_authlen]
	cmp	ecx,8
	jb	.bad
	cmp	ecx,2048
	ja	.bad
	cmp	dword [rdi],'http'
	jne	.bad
	mov	eax,4
	xor	edx,edx
	mov	dword [g_iau_port],80
	cmp	byte [rdi+4],'s'
	jne	@f
	inc	eax
	inc	edx
	mov	dword [g_iau_port],443
@@:
	mov	[g_iau_tls],edx
	cmp	byte [rdi+rax],':'
	jne	.bad
	cmp	word [rdi+rax+1],'//'
	jne	.bad
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
	lea	rsi,[rdi+r10]
	mov	edx,eax
	sub	edx,r10d
	mov	[g_iau_host],rsi
	mov	[g_iau_hlen],edx
	; $host: the rule's
	cmp	edx,5
	jne	.host_check
	cmp	dword [rsi],'$hos'
	jne	.host_check
	cmp	byte [rsi+4],'t'
	jne	.host_check
	mov	rsi,[g_ing_host]
	test	rsi,rsi
	jz	.bad
	cmp	byte [rsi],'*'
	je	.bad
	mov	[g_iau_host],rsi
	mov	edx,[g_ing_hostlen]
	mov	[g_iau_hlen],edx
.host_check:
	push	rcx
	push	rax
	push	rdi
	mov	rcx,[g_iau_host]
	mov	edx,[g_iau_hlen]
	call	gw_sub_ok
	pop	rdi
	pop	rax
	pop	rcx
	jc	.bad
	; :port
	cmp	eax,ecx
	jae	.path
	cmp	byte [rdi+rax],':'
	jne	.path
	inc	eax
	xor	r8d,r8d
@@:
	cmp	eax,ecx
	jae	@f
	movzx	edx,byte [rdi+rax]
	cmp	dl,'/'
	je	@f
	sub	dl,'0'
	cmp	dl,9
	ja	.bad
	imul	r8d,r8d,10
	add	r8d,edx
	cmp	r8d,65535
	ja	.bad
	inc	eax
	jmp	@b
@@:
	test	r8d,r8d
	jz	.bad
	mov	[g_iau_port],r8d
.path:
	lea	rsi,[rdi+rax]
	sub	ecx,eax
	jnz	@f
	lea	rsi,[ia_auth_slash]
	mov	ecx,1
@@:
	mov	[g_iau_path],rsi
	mov	[g_iau_plen],ecx
	cmp	byte [rsi],'/'
	jne	.bad
	push	rdi
	mov	rdi,rsi
	call	iv_text
	pop	rdi
	jc	.bad
	xor	eax,eax				; (no space either: one word)
@@:
	cmp	byte [rsi+rax],' '
	je	.bad
	inc	eax
	cmp	eax,ecx
	jb	@b
	; the host: a Service (NAME, NAME.NS.svc...), or a name
	mov	dword [g_iau_svclen],0
	mov	rsi,[g_iau_host]
	mov	ecx,[g_iau_hlen]
	xor	eax,eax
@@:
	cmp	eax,ecx
	jae	.one_label
	cmp	byte [rsi+rax],'.'
	je	@f
	inc	eax
	jmp	@b
.one_label:
	mov	[g_iau_svc],rsi
	mov	[g_iau_svclen],ecx
	mov	rax,[g_ing_ns]
	mov	[g_iau_ns],rax
	mov	eax,[g_ing_nslen]
	mov	[g_iau_nslen],eax
	jmp	.labels
@@:
	mov	r8d,eax				; the first dot
	lea	r9d,[rax+1]
@@:
	cmp	r9d,ecx
	jae	.name
	cmp	byte [rsi+r9],'.'
	je	@f
	inc	r9d
	jmp	@b
@@:
	; NAME.NS.svc, alone or before a domain
	lea	eax,[r9+4]
	cmp	eax,ecx
	ja	.name
	cmp	dword [rsi+r9],'.svc'
	jne	.name
	cmp	eax,ecx
	je	@f
	cmp	byte [rsi+rax],'.'
	jne	.name
@@:
	mov	[g_iau_svc],rsi
	mov	[g_iau_svclen],r8d
	lea	rax,[rsi+r8+1]
	mov	[g_iau_ns],rax
	mov	eax,r9d
	sub	eax,r8d
	dec	eax
	mov	[g_iau_nslen],eax
.labels:
	mov	rcx,[g_iau_svc]
	mov	edx,[g_iau_svclen]
	call	gw_label_ok
	jc	.bad
	mov	rcx,[g_iau_ns]
	mov	edx,[g_iau_nslen]
	call	gw_label_ok
	jc	.bad
.name:
	clc
	ret
.bad:
	mov	dword [g_iau_svclen],0
	stc
	ret
ia_auth_slash	db '/'

; g_ia_asign, out: nginx's variables as okena's ($host, $http_host,
; $best_http_host: ${host}; $scheme, $pass_access_scheme: ${scheme};
; $escaped_request_uri, $request_uri). CF when it is not a URL okena writes
; (http://, https:// or /, no space, quote or backslash, no other variable).
ia_signin:
	push	rbx
	push	r12
	mov	rdi,[g_ia_asign]
	mov	ecx,[g_ia_asignlen]
	call	iv_text
	jc	.out
	cmp	byte [rdi],'/'
	je	.ok_start
	cmp	ecx,8
	jb	.bad
	cmp	dword [rdi],'http'
	jne	.bad
	cmp	dword [rdi+4],'s://'
	je	.ok_start
	cmp	word [rdi+4],':/'
	jne	.bad
	cmp	byte [rdi+6],'/'
	jne	.bad
.ok_start:
	mov	rsi,rdi
	lea	rbx,[rdi+rcx]
.c:
	cmp	rsi,rbx
	jae	.done
	movzx	eax,byte [rsi]
	cmp	al,' '
	je	.bad
	cmp	al,'$'
	je	.var
	mov	[r15],al
	inc	r15
	inc	rsi
	jmp	.c
.var:
	inc	rsi
	lea	r12,[ia_vars]
.v:
	movzx	ecx,byte [r12]
	test	ecx,ecx
	jz	.bad
	mov	rax,rbx
	sub	rax,rsi
	cmp	rax,rcx
	jb	.v_next
	push	rsi
	lea	rdi,[r12+2]
	repe	cmpsb
	mov	rdx,rsi
	pop	rsi
	jne	.v_next
	cmp	rdx,rbx				; (a whole name: no letter after it)
	jae	@f
	movzx	eax,byte [rdx]
	cmp	al,'_'
	je	.v_next
	lea	r8d,[rax-'0']
	cmp	r8d,9
	jbe	.v_next
	or	al,0x20
	sub	al,'a'
	cmp	al,25
	jbe	.v_next
@@:
	mov	rsi,rdx
	movzx	eax,byte [r12+1]
	lea	rdx,[ia_okv]
	mov	rdx,[rdx+rax*8]
	push	rsi
	movzx	ecx,byte [rdx]
	lea	rsi,[rdx+1]
	call	go_bytes
	pop	rsi
	jmp	.c
.v_next:
	movzx	ecx,byte [r12]
	lea	r12,[r12+rcx+2]
	jmp	.v
.done:
	clc
	jmp	.out
.bad:
	stc
.out:
	pop	r12
	pop	rbx
	ret

ia_vars:
	db 19,2,'escaped_request_uri'
	db 11,3,'request_uri'
	db 14,0,'best_http_host'
	db 9,0,'http_host'
	db 4,0,'host'
	db 18,1,'pass_access_scheme'
	db 6,1,'scheme'
	db 0
	align 8
ia_okv	dq ia_ok0, ia_ok1, ia_ok2, ia_ok3
ia_ok0	db 7,'${host}'
ia_ok1	db 9,'${scheme}'
ia_ok2	db 22,'${request.uri.escaped}'
ia_ok3	db 14,'${request.uri}'
