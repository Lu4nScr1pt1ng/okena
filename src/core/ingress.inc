; Kubernetes Ingress (networking.k8s.io/v1), beside the Gateway API: `okena {
; gateway kubernetes ... ingress=CLASS [http=PORT] [https=PORT] }`.
;
; The Ingresses of that class (spec.ingressClassName, or the older
; kubernetes.io/ingress.class annotation; with ingress_default=on, those that
; name no class too) are put in the Gateway API's terms
; and then read by the same code as the cluster's own Gateways and
; HTTPRoutes: so what the rest of gwgen.inc checks and writes (names, hosts,
; paths, Services as pools that follow their EndpointSlices, TLS Secrets)
; holds for them too, and nothing of an Ingress reaches okena's file without
; it. Each Ingress becomes, in its own namespace and under its own name:
;
;   a Gateway: an HTTP listener on `http=` (80), and for each host of each
;   spec.tls an HTTPS one on `https=` (443) with that Secret (the same
;   namespace: no grant needed). Ports shared by many are one okena listener.
;   an HTTPRoute a rule: its host, its paths (Exact; Prefix and
;   ImplementationSpecific as PathPrefix, element by element, as both APIs
;   say), each to its Service's port, by number or by name;
;   one for spec.defaultBackend: no host, PathPrefix /, below every rule.
;
; Their status is not written (they are not objects of the cluster).

bss
	align 8
	g_ing_gws	dq ?		; the made-up GatewayList, 0 none
	g_ing_hrs	dq ?		; and HTTPRouteList
	g_ing_pass	dd ?		; 0 writing Gateways, 1 HTTPRoutes
	g_ing_first	dd ?		; no item written yet in the list
	g_ing_ns	dq ?		; the Ingress being read
	g_ing_nslen	dd ?
	g_ing_nmlen	dd ?
	g_ing_nm	dq ?
	g_gw_ng_real	dd ?		; Gateways and routes read from the cluster
	g_gw_nr_real	dd ?		; (the rest are made up: no status for them)
end bss

; In gw_render, after the cluster's own lists (g_gl_cur past them): the
; Ingresses read and their made-up lists written after them. CF when the
; API server cannot be had now.
ing_lists:
	mov	qword [g_ing_gws],0
	mov	qword [g_ing_hrs],0
	mov	qword [g_ing_list],0
	cmp	dword [g_plan_gw+GWP_ING],0
	je	.none
	push	r13
	push	r15
	cstring .path, '/apis/networking.k8s.io/v1/ingresses?resourceVersion=0',0
	lea	rsi,[.path]
	mov	edx,1
	call	gw_list
	jc	.out
	mov	rsi,rax
	mov	r13,[g_gl_cur]			; the list's end, for the reader
	mov	r15,r13				; what is made goes after it
	mov	rax,r13				; room for four times the list, or nothing
	sub	rax,rsi
	shl	rax,2
	add	rax,r13
	mov	rcx,[g_gw_base]
	add	rcx,GW_LISTS + GW_LISTS_CAP
	cmp	rax,rcx
	jae	.large
	push	rsi
	mov	[g_ing_gws],r15
	mov	dword [g_ing_pass],0
	call	.list
	mov	rsi,[rsp]
	mov	[g_ing_hrs],r15
	mov	dword [g_ing_pass],1
	call	.list
	add	rsp,8
	mov	[g_gl_cur],r15
	clc
.out:
	pop	r15
	pop	r13
	ret
.large:
	mov	eax,8
	lea	rsi,[str_gw_lists]
	mov	edx,str_gw_lists.len
	call	gw_tell
	stc
	jmp	.out
.none:
	clc
	ret
; rsi = the IngressList: one made-up list (g_ing_pass) at r15
.list:
	mov	[g_ing_list],rsi
	go_lit '{"items":['
	mov	dword [g_ing_first],1
	gk	'items'
	call	gj_get
	jc	.list_end
	cmp	byte [rsi],'n'
	je	.list_end
	call	gj_first
	jc	.list_end
.item:
	push	rsi
	call	ing_one
	pop	rsi
	call	gj_next
	jnc	.item
.list_end:
	go_lit ']}'
	ret

; rsi = an Ingress: written as its Gateway or its HTTPRoutes (g_ing_pass),
; when it is of the class and its names can be names. Keeps rbx, r12-r14.
ing_one:
	push	rbx
	push	r12
	mov	rbx,rsi
	gk	'metadata'
	call	gj_get
	jc	.out
	mov	r12,rsi
	mov	[g_ing_meta],rsi
	gk	'namespace'
	call	gj_str
	jc	.out
	mov	[g_ing_ns],rdi
	mov	[g_ing_nslen],ecx
	call	ing_label
	jc	.out
	mov	rsi,r12
	gk	'name'
	call	gj_str
	jc	.out
	mov	[g_ing_nm],rdi
	mov	[g_ing_nmlen],ecx
	call	ing_label
	jc	.out
	call	ing_class_ok
	jc	.out
	; a canary is not served itself: its paths join those it shadows
	mov	rsi,r12
	call	ing_is_canary			; (ingann.inc)
	je	.out
	mov	rsi,rbx
	gk	'spec'
	call	gj_get
	mov	r12,rsi				; the spec
	cmp	dword [g_ing_pass],0
	jne	.routes
	call	ing_gateway
	jmp	.out
.routes:
	mov	[g_ing_spec],r12
	call	ing_annotations			; (ingann.inc)
	call	ing_routes
.out:
	pop	r12
	pop	rbx
	ret

; rbx = an Ingress, r12 = its metadata: CF unless of the class (its
; spec.ingressClassName, else the older annotation; none: ours when we are the
; default). Keeps rbx, r12-r15.
ing_class_ok:
	mov	rsi,rbx
	gk	'spec'
	call	gj_get
	jc	.no
	push	rsi
	gk	'ingressClassName'
	call	gj_str
	pop	rsi
	jnc	.class
	mov	rsi,r12
	gk	'annotations'
	call	gj_get
	jc	.classless
	gk	'kubernetes.io/ingress.class'
	call	gj_str
	jnc	.class
.classless:
	cmp	dword [g_plan_gw+GWP_INGDEF],0
	je	.no
	clc
	ret
.class:
	mov	rsi,[g_plan_gw+GWP_INGCLASS]
	mov	edx,[g_plan_gw+GWP_INGLEN]
	call	gw_same
	jne	.no
	clc
	ret
.no:
	stc
	ret

; rdi/ecx = a name: CF unless a DNS label (and so safe in JSON). Keeps all
; but rax, flags.
ing_label:
	push	rcx
	push	rdx
	mov	edx,ecx
	mov	rcx,rdi
	call	gw_label_ok
	pop	rdx
	pop	rcx
	ret

; r12 = the spec: the Ingress's Gateway. Keeps rbx, r12-r14.
ing_gateway:
	push	rbx
	push	r14
	call	ing_comma
	go_lit '{"metadata":{"namespace":"'
	mov	rsi,[g_ing_ns]
	mov	ecx,[g_ing_nslen]
	call	go_bytes
	go_lit '","name":"'
	mov	rsi,[g_ing_nm]
	mov	ecx,[g_ing_nmlen]
	call	go_bytes
	go_lit '","generation":1},"spec":{"gatewayClassName":"'
	mov	rsi,[g_plan_gw+GWP_CLASS]
	mov	ecx,[g_plan_gw+GWP_CLASSLEN]
	call	go_bytes
	go_lit '","listeners":[{"name":"http","protocol":"HTTP","port":'
	mov	eax,[g_plan_gw+GWP_P80]
	call	go_u
	go_lit ',"allowedRoutes":{"namespaces":{"from":"Same"}}}'
	; an HTTPS listener a host of each spec.tls with a secretName
	mov	rsi,r12
	gk	'tls'
	call	gj_get
	jc	.done
	call	gj_first
	jc	.done
	xor	ebx,ebx				; listeners written (their names)
.tls:
	mov	r14,rsi
	gk	'secretName'
	call	gj_str
	jc	.tls_next
	call	ing_label
	jc	.tls_next
	push	rdi
	push	rcx
	mov	rsi,r14
	gk	'hosts'
	call	gj_get
	jc	.hostless
	call	gj_first
	jc	.hostless
.host:
	push	rsi
	call	ing_str_here			; rdi/ecx = this string
	jc	.host_next
	mov	rdx,[rsp+16]			; the secret
	mov	r8d,[rsp+8]
	call	ing_https
.host_next:
	pop	rsi
	call	gj_next
	jnc	.host
	add	rsp,16
	jmp	.tls_next
.hostless:
	pop	r8				; (secret: rcx, rdi)
	pop	rdx
	xor	ecx,ecx				; no hostname: the port's default
	call	ing_https
.tls_next:
	mov	rsi,r14
	call	gj_next
	jnc	.tls
.done:
	go_lit ']}}'
	pop	r14
	pop	rbx
	ret

; rdi/ecx = a host (ecx 0: none), rdx/r8d = its Secret, ebx = listeners so
; far: an HTTPS listener. CF-free; a host that is not a host is left out.
ing_https:
	test	ecx,ecx
	jz	@f
	call	ing_clean
	jc	.out
@@:
	inc	ebx
	go_lit ',{"name":"https-'
	mov	eax,ebx
	call	go_u
	go_lit '","protocol":"HTTPS","port":'
	mov	eax,[g_plan_gw+GWP_P443]
	call	go_u
	test	ecx,ecx
	jz	@f
	go_lit ',"hostname":"'
	mov	rsi,rdi
	call	go_bytes
	go_lit '"'
@@:
	go_lit ',"tls":{"mode":"Terminate","certificateRefs":[{"kind":"Secret","name":"'
	mov	rsi,rdx
	mov	ecx,r8d
	call	go_bytes
	go_lit '"}]},"allowedRoutes":{"namespaces":{"from":"Same"}}}'
.out:
	ret

; r12 = the spec: an HTTPRoute a rule, and one for the default backend.
; Keeps rbx, r12-r14.
ing_routes:
	push	rbx
	push	r14
	mov	rsi,r12
	gk	'rules'
	call	gj_get
	jc	.default
	call	gj_first
	jc	.default
.rule:
	mov	r14,rsi
	call	ing_route_of_rule
	mov	rsi,r14
	call	gj_next
	jnc	.rule
.default:
	mov	rsi,r12
	gk	'defaultBackend'
	call	gj_get
	jc	.out
	mov	rbx,rsi
	call	ing_backend_ref			; into the text: rdi/ecx, CF none
	jc	.out
	mov	r14,rdi
	mov	ebx,ecx
	mov	qword [g_ing_host],0
	cmp	dword [g_ia_force],0		; (to HTTPS: only when forced, for no host)
	je	.dmode0
	mov	dword [g_ing_mode],1
	call	.droute
	mov	dword [g_ing_mode],2
	call	.droute
	jmp	.dend
.dmode0:
	mov	dword [g_ing_mode],0
	call	.droute
.dend:
	mov	dword [g_ing_mode],0
.out:
	pop	r14
	pop	rbx
	ret
; r14/ebx = the default backend's ref: its route
.droute:
	push	rbx
	call	ing_route_head
	go_lit '"rules":['
	xor	ebx,ebx
	call	ing_approot
	test	ebx,ebx
	jz	@f
	go_lit ','
@@:
	lea	rsi,[ing_path.slash]
	mov	ecx,1
	xor	r8d,r8d
	xor	r10d,r10d
	mov	rdx,r14
	mov	r9d,[rsp]
	call	ing_rule
	go_lit ']}}'
	pop	rbx
	ret

; the head of a made-up HTTPRoute, up to its spec's first key
ing_route_head:
	call	ing_comma
	go_lit '{"metadata":{"namespace":"'
	mov	rsi,[g_ing_ns]
	mov	ecx,[g_ing_nslen]
	call	go_bytes
	go_lit '","name":"'
	mov	rsi,[g_ing_nm]
	mov	ecx,[g_ing_nmlen]
	call	go_bytes
	go_lit '","generation":1},"spec":{"parentRefs":[{"name":"'
	mov	rsi,[g_ing_nm]
	mov	ecx,[g_ing_nmlen]
	call	go_bytes
	go_lit '"'
	cmp	dword [g_ing_mode],1		; (an ssl-redirect: HTTP's listener, then HTTPS's)
	jne	@f
	go_lit ',"sectionName":"http"'
@@:
	cmp	dword [g_ing_mode],2
	jne	@f
	go_lit ',"port":'
	mov	eax,[g_plan_gw+GWP_P443]
	call	go_u
@@:
	go_lit '}],'
	ret

; r14 = a rule: its HTTPRoute (its host, its paths). Keeps rbx, r12-r14.
ing_route_of_rule:
	push	rbx
	push	r12
	mov	rsi,r14
	gk	'http'
	call	gj_get
	jc	.out
	gk	'paths'
	call	gj_get
	jc	.out
	call	gj_first
	jc	.out
	mov	r12,rsi				; the first path
	mov	qword [g_ing_host],0
	mov	rsi,r14
	gk	'host'
	call	gj_str
	jc	.no_host
	call	ing_clean
	jc	.no_host			; (a host not to be written: the rule's paths for none)
	mov	[g_ing_host],rdi
	mov	[g_ing_hostlen],ecx
.no_host:
	call	ing_redirects			; HTTP to HTTPS: a route for each side
	test	eax,eax
	jz	.one
	mov	dword [g_ing_mode],1
	call	.route
	mov	dword [g_ing_mode],2
	call	.route
	jmp	.done
.one:
	mov	dword [g_ing_mode],0
	call	.route
.done:
	mov	dword [g_ing_mode],0
.out:
	pop	r12
	pop	rbx
	ret
.route:
	call	ing_route_head
	cmp	qword [g_ing_host],0
	je	@f
	go_lit '"hostnames":["'
	mov	rsi,[g_ing_host]
	mov	ecx,[g_ing_hostlen]
	call	go_bytes
	go_lit '"],'
@@:
	go_lit '"rules":['
	xor	ebx,ebx				; rules written
	call	ing_approot
	mov	rsi,r12
.path:
	push	rsi
	call	ing_path
	pop	rsi
	call	gj_next
	jnc	.path
	go_lit ']}}'
	ret

; rsi = an Ingress path, ebx = rules written so far: one rule. Keeps r12-r14.
ing_path:
	push	r14
	mov	r14,rsi
	gk	'backend'
	call	gj_get
	jc	.out
	push	rbx
	mov	rbx,rsi
	call	ing_backend_ref
	pop	rbx
	jc	.out				; (a resource backend, or no port: left out)
	push	rdi
	push	rcx
	; its type and path
	xor	r8d,r8d				; 1: Exact
	mov	rsi,r14
	gk	'pathType'
	call	gj_str
	jc	@f
	cmp	ecx,5
	jne	@f
	cmp	dword [rdi],'Exac'
	jne	@f
	mov	r8d,1
@@:
	mov	rsi,r14
	gk	'path'
	call	gj_str
	jnc	@f
	lea	rdi,[.slash]			; (none: /)
	mov	ecx,1
@@:
	call	ing_clean
	jc	.skip
	test	ebx,ebx
	jz	@f
	go_lit ','
@@:
	inc	ebx
	mov	rsi,rdi
	pop	r9				; (its backendRef)
	pop	rdx
	mov	r10d,1
	call	ing_rule			; (ingann.inc)
	jmp	.out
.skip:
	add	rsp,16
.out:
	pop	r14
	ret
.slash	db '/'

; rbx = an Ingress backend: its backendRef as JSON, in GW_TEXT: rdi/ecx. CF
; when it names no Service, or a port that cannot be had. Keeps r12-r14.
ing_backend_ref:
	push	r12
	push	r14
	mov	rsi,rbx
	gk	'service'
	call	gj_get
	jc	.no
	mov	r14,rsi
	gk	'name'
	call	gj_str
	jc	.no
	call	ing_label
	jc	.no
	push	rdi
	push	rcx
	mov	rsi,r14
	gk	'port'
	call	gj_get
	jc	.no2
	mov	r12,rsi
	gk	'number'
	call	gj_num
	jnc	.number
	mov	rsi,r12
	gk	'name'
	call	gj_str
	jc	.no2
	mov	rdx,[rsp+8]			; the Service: its port by that name
	mov	r8d,[rsp]
	call	ing_port_by_name
	jc	.no2
.number:
	test	eax,eax
	jz	.no2
	cmp	eax,65535
	ja	.no2
	; {"name":"SVC","port":N} into the text
	push	r15
	mov	r15,[g_gw_txt]
	mov	r8,r15
	go_lit '{"name":"'
	mov	rsi,[rsp+16]
	mov	ecx,[rsp+8]
	call	go_bytes
	go_lit '","port":'
	call	go_u
	mov	eax,[g_ia_proto]		; (annotations: backend-protocol, affinity)
	test	eax,eax
	jz	@f
	go_lit ',"x-okena-proto":'
	call	go_u
@@:
	cmp	dword [g_ia_stklen],0
	je	@f
	go_lit ',"x-okena-sticky":"'
	mov	rsi,[g_ia_stk]
	mov	ecx,[g_ia_stklen]
	call	go_bytes
	go_lit '","x-okena-ttl":'
	mov	eax,[g_ia_ttl]
	call	go_u
@@:
	go_lit '}'
	mov	rdi,r8
	mov	rcx,r15
	sub	rcx,r8
	mov	[g_gw_txt],r15
	pop	r15
	add	rsp,16
	clc
	jmp	.out
.no2:
	add	rsp,16
.no:
	stc
.out:
	pop	r14
	pop	r12
	ret

; rdx/r8d = a Service of the Ingress's namespace, rdi/ecx = a port's name:
; eax = its number. CF when it is not there (now).
ing_port_by_name:
	push	r13
	push	rbx
	push	rdi
	push	rcx
	call	gw_req_begin
	cstring .p1, '/api/v1/namespaces/',0
	lea	rsi,[.p1]
	call	gw_req_cstr
	mov	rsi,[g_ing_ns]
	mov	ecx,[g_ing_nslen]
	call	gw_req_add
	cstring .p2, '/services/',0
	lea	rsi,[.p2]
	call	gw_req_cstr
	mov	rsi,rdx
	mov	ecx,r8d
	call	gw_req_add
	call	gw_get
	jc	.no
	cmp	eax,200
	jne	.no
	lea	r13,[rsi+rcx]			; (its end, for the reader)
	gk	'spec'
	call	gj_get
	jc	.no
	gk	'ports'
	call	gj_get
	jc	.no
	call	gj_first
	jc	.no
.port:
	mov	rbx,rsi
	gk	'name'
	call	gj_str
	jc	.next
	mov	rsi,[rsp+8]
	mov	edx,[rsp]
	call	gw_same
	jne	.next
	mov	rsi,rbx
	gk	'port'
	call	gj_num
	jc	.no
	add	rsp,16
	pop	rbx
	pop	r13
	clc
	ret
.next:
	mov	rsi,rbx
	call	gj_next
	jnc	.port
.no:
	add	rsp,16
	pop	rbx
	pop	r13
	stc
	ret

; rsi at a JSON string (an array's element): rdi/ecx = it. CF when not one.
ing_str_here:
	call	js_ws
	call	js_str
	jc	.no
	xor	eax,eax
@@:
	cmp	eax,ecx
	jae	.yes
	cmp	byte [rdi+rax],'\'
	je	.no				; (an escape in a host: not a host)
	inc	eax
	jmp	@b
.yes:
	clc
	ret
.no:
	stc
	ret

; rdi/ecx = a host or a path: CF when it holds what JSON would need escaped,
; or a space (neither API lets one in). Keeps all.
ing_clean:
	push	rax
	push	rcx
	test	ecx,ecx
	jz	.bad
.c:
	mov	al,[rdi+rcx-1]
	cmp	al,' '
	jbe	.bad
	cmp	al,'"'
	je	.bad
	cmp	al,'\'
	je	.bad
	cmp	al,0x7E
	ja	.bad
	dec	ecx
	jnz	.c
	pop	rcx
	pop	rax
	clc
	ret
.bad:
	pop	rcx
	pop	rax
	stc
	ret

; a comma before an item but the first of its list
ing_comma:
	cmp	dword [g_ing_first],0
	jne	@f
	go_lit ','
	ret
@@:
	mov	dword [g_ing_first],0
	ret
