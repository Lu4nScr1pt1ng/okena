; The Gateway API's status, written back (gateway.inc's process).
;
; Each second, after what it read was written as okena's configuration (and
; taken: the supervisor says how the reload went), the status of what it serves:
;
;   the GatewayClass (when its controllerName is okena's): Accepted;
;   each Gateway: Accepted, Programmed (not when okena refused what was written
;     for it), and each listener: its attachedRoutes, Accepted (or
;     UnsupportedProtocol, Invalid), ResolvedRefs (or InvalidCertificateRef),
;     Programmed;
;   each HTTPRoute, for each of its parentRefs that names one of these Gateways:
;     Accepted (or NoMatchingParent, NotAllowedByListeners,
;     NoMatchingListenerHostname), ResolvedRefs (or BackendNotFound,
;     RefNotPermitted, InvalidKind); what other controllers wrote in its
;     status.parents is kept as it is.
;
; Each as a merge patch of its status subresource, and only when it changed: what
; was written last is remembered by a hash (in DIR/status.state, as the process
; starts anew with each reload), so an API server is not asked to write the same
; thing every second. A status that cannot be written is tried again the next
; second, and the configuration does not wait on it.

GW_CONTROLLER	equ 'okena.dev/gateway-controller'

bss
	align 8
	g_gs_n		dd ?			; status hashes known
	g_gs_dirty	dd ?
	g_gs_tlen	dd ?			; 0: hashing (no time in it), 20: writing
	g_gs_prog	dd ?			; what was written is served
	g_gs_time	rb 24
	g_gs_key	dq ?
	g_gs_count	dd ?
end bss

cstring str_gs_state, '/status.state',0
cstring str_gs_ctl, GW_CONTROLLER

; once, as the process starts: what status it wrote before
gs_load:
	lea	rsi,[str_gs_state]
	call	gw_dir_path
	mov	rdi,[g_gw_base]
	add	rdi,GW_T_KEYS
	mov	esi,16 * GW_KEYS
	call	gw_read
	jnc	@f
	xor	eax,eax
@@:
	shr	eax,4
	mov	[g_gs_n],eax
	ret

; rsi/ecx = bytes, rax = a hash so far (FNV-1a, 64): rax = it with them. Keeps
; all but rax, rdx.
gs_fnv:
	push	rsi
	push	rcx
	mov	rdx,0x100000001B3
.b:
	test	ecx,ecx
	jz	.out
	push	rdx
	movzx	edx,byte [rsi]
	xor	rax,rdx
	pop	rdx
	imul	rax,rdx
	inc	rsi
	dec	ecx
	jmp	.b
.out:
	pop	rcx
	pop	rsi
	ret

; the status of all of it, written where it changed
gw_status:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r13,[g_gw_lend]			; (raw JSON is copied: the lists' end)
	mov	dword [g_gs_dirty],0
	; now, as RFC 3339
	sub	rsp,16
	mov	edi,CLOCK_REALTIME
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	mov	rax,[rsp]
	add	rsp,16
	call	x5_utctime			; g_x5_time: YYMMDDHHMMSSZ
	lea	rdi,[g_gs_time]
	mov	word [rdi],'20'
	mov	ax,word [g_x5_time]
	mov	[rdi+2],ax
	mov	byte [rdi+4],'-'
	mov	ax,word [g_x5_time+2]
	mov	[rdi+5],ax
	mov	byte [rdi+7],'-'
	mov	ax,word [g_x5_time+4]
	mov	[rdi+8],ax
	mov	byte [rdi+10],'T'
	mov	ax,word [g_x5_time+6]
	mov	[rdi+11],ax
	mov	byte [rdi+13],':'
	mov	ax,word [g_x5_time+8]
	mov	[rdi+14],ax
	mov	byte [rdi+16],':'
	mov	ax,word [g_x5_time+10]
	mov	[rdi+17],ax
	mov	byte [rdi+19],'Z'
	; what the supervisor said of the last reload
	mov	dword [g_gs_prog],1
	mov	rax,[g_gw_page]
	cmp	dword [rax+GH_RESULT],2
	jne	@f
	mov	dword [g_gs_prog],0
@@:
	; the class
	cmp	dword [g_gw_classok],1
	jne	.gateways
	xor	edx,edx
	xor	ebx,ebx
	call	gs_put
	jc	.out
.gateways:
	xor	ebx,ebx
.gateway:
	cmp	ebx,[g_gw_ng]
	jae	.routes
	mov	edx,1
	call	gs_put
	jc	.out
	inc	ebx
	jmp	.gateway
.routes:
	xor	ebx,ebx
.route:
	cmp	ebx,[g_gw_nr]
	jae	.saved
	call	gs_route_ours			; CF: none of its parents are ours
	jc	@f
	imul	rax,rbx,GWR_SIZE		; 2 an HTTPRoute, 3 a GRPCRoute
	add	rax,[g_gw_base]
	mov	edx,[rax+GW_T_R+GWR_KIND]
	add	edx,2
	call	gs_put
	jc	.out
@@:
	inc	ebx
	jmp	.route
.saved:
	cmp	dword [g_gs_dirty],0
	je	.out
	lea	rsi,[str_gs_state]
	call	gw_dir_path
	mov	rsi,[g_gw_base]
	add	rsi,GW_T_KEYS
	mov	edx,[g_gs_n]
	shl	edx,4
	call	gw_write
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; ebx = a route: CF when no parentRef of it names one of our Gateways
gs_route_ours:
	xor	ecx,ecx
.pr:
	cmp	ecx,[g_gw_npr]
	jae	.no
	imul	rax,rcx,GWPR_SIZE
	add	rax,[g_gw_base]
	add	rax,GW_T_PR
	cmp	[rax+GWPR_ROUTE],ebx
	jne	.next
	cmp	dword [rax+GWPR_GWI],-1
	jne	.yes
.next:
	inc	ecx
	jmp	.pr
.yes:
	clc
	ret
.no:
	stc
	ret

; edx = 0 the class, 1 a Gateway, 2 a route; ebx = which: its status, made, then
; written when it is not what was written last. CF when the API server did not
; answer (the rest waits for the next second).
gs_put:
	push	r12
	mov	r12d,edx
	; the key: kind, namespace, name
	call	gs_key				; g_gs_key
	; hashed without the time
	mov	dword [g_gs_tlen],0
	mov	r15,[g_gw_base]
	add	r15,GW_T_PATCH
	call	gs_build
	mov	rsi,[g_gw_base]
	add	rsi,GW_T_PATCH
	mov	rcx,r15
	sub	rcx,rsi
	mov	rax,0xCBF29CE484222325
	call	gs_fnv
	mov	r14,rax				; its hash
	; what was written for it
	mov	rdi,[g_gw_base]
	add	rdi,GW_T_KEYS
	xor	ecx,ecx
.known:
	cmp	ecx,[g_gs_n]
	jae	.write
	mov	rax,[g_gs_key]
	cmp	[rdi],rax
	je	.found
	add	rdi,16
	inc	ecx
	jmp	.known
.found:
	cmp	[rdi+8],r14
	je	.same
.write:
	push	rdi				; (its slot, or past the last)
	mov	dword [g_gs_tlen],20
	mov	r15,[g_gw_base]
	add	r15,GW_T_PATCH
	call	gs_build
	mov	rax,[g_gw_base]
	add	rax,GW_T_PATCH
	mov	[g_gw_body],rax
	mov	rcx,r15
	sub	rcx,rax
	mov	[g_gw_bodylen],ecx
	call	gs_path
	mov	dword [g_gw_method],1
	call	gw_get
	mov	dword [g_gw_method],0
	pop	rdi
	jc	.unanswered
	cmp	eax,200
	je	.written
	cmp	eax,201
	je	.written
	cmp	eax,403
	jne	.same				; (gone, or a conflict: the next second)
	push	rax
	mov	eax,7
	cstring str_gs_403, ': the API server refused a status (403: may the service account patch gatewayclasses/status, gateways/status and httproutes/status?)'
	lea	rsi,[str_gs_403]
	mov	edx,str_gs_403.len
	call	gw_tell
	pop	rax
	jmp	.same
.written:
	mov	rax,[g_gs_key]
	mov	[rdi],rax
	mov	[rdi+8],r14
	mov	rax,[g_gw_base]
	add	rax,GW_T_KEYS
	sub	rdi,rax
	shr	edi,4
	cmp	edi,[g_gs_n]
	jb	@f
	cmp	dword [g_gs_n],GW_KEYS - 1
	jae	@f
	inc	dword [g_gs_n]
@@:
	mov	dword [g_gs_dirty],1
.same:
	clc
	pop	r12
	ret
.unanswered:
	stc
	pop	r12
	ret

; r12d = kind, ebx = which: g_gs_key
gs_key:
	mov	rax,0xCBF29CE484222325
	movzx	edx,r12b
	xor	rax,rdx
	mov	rdx,0x100000001B3
	imul	rax,rdx
	cmp	r12d,1
	je	.gateway
	ja	.route
	mov	rsi,[g_plan_gw+GWP_CLASS]
	mov	ecx,[g_plan_gw+GWP_CLASSLEN]
	call	gs_fnv
	jmp	.out
.gateway:
	imul	r8,rbx,GWG_SIZE
	add	r8,[g_gw_base]
	add	r8,GW_T_G
	mov	rsi,[r8+GWG_NS]
	mov	ecx,[r8+GWG_NSLEN]
	call	gs_fnv
	mov	rsi,[r8+GWG_NAME]
	mov	ecx,[r8+GWG_NLEN]
	call	gs_fnv_slash
	jmp	.out
.route:
	imul	r8,rbx,GWR_SIZE
	add	r8,[g_gw_base]
	add	r8,GW_T_R
	mov	rsi,[r8+GWR_NS]
	mov	ecx,[r8+GWR_NSLEN]
	call	gs_fnv
	mov	rsi,[r8+GWR_NAME]
	mov	ecx,[r8+GWR_NLEN]
	call	gs_fnv_slash
.out:
	mov	[g_gs_key],rax
	ret
; '/' then rsi/ecx
gs_fnv_slash:
	push	rsi
	push	rcx
	lea	rsi,[str_gw_slash]
	mov	ecx,1
	call	gs_fnv
	pop	rcx
	pop	rsi
	jmp	gs_fnv

; r12d = kind, ebx = which: g_gw_reqpath = its status subresource
gs_path:
	call	gw_req_begin
	cstring .api, '/apis/gateway.networking.k8s.io/v1/',0
	lea	rsi,[.api]
	cmp	r12d,4
	jb	@f
	cstring .alpha, '/apis/gateway.networking.k8s.io/v1alpha2/',0
	lea	rsi,[.alpha]			; (TLSRoute, TCPRoute)
@@:
	call	gw_req_cstr
	test	r12d,r12d
	jnz	.namespaced
	cstring .classes, 'gatewayclasses/',0
	lea	rsi,[.classes]
	call	gw_req_cstr
	mov	rsi,[g_plan_gw+GWP_CLASS]
	mov	ecx,[g_plan_gw+GWP_CLASSLEN]
	call	gw_req_add
	jmp	.status
.namespaced:
	cstring .ns, 'namespaces/',0
	lea	rsi,[.ns]
	call	gw_req_cstr
	cmp	r12d,1
	jne	.route
	imul	r8,rbx,GWG_SIZE
	add	r8,[g_gw_base]
	add	r8,GW_T_G
	mov	rsi,[r8+GWG_NS]
	mov	ecx,[r8+GWG_NSLEN]
	call	gw_req_add
	cstring .gws, '/gateways/',0
	lea	rsi,[.gws]
	call	gw_req_cstr
	mov	rsi,[r8+GWG_NAME]
	mov	ecx,[r8+GWG_NLEN]
	call	gw_req_add
	jmp	.status
.route:
	imul	r8,rbx,GWR_SIZE
	add	r8,[g_gw_base]
	add	r8,GW_T_R
	mov	rsi,[r8+GWR_NS]
	mov	ecx,[r8+GWR_NSLEN]
	call	gw_req_add
	cstring .hrs, '/httproutes/',0
	lea	rsi,[.hrs]
	cmp	r12d,3
	jne	@f
	cstring .grs, '/grpcroutes/',0
	lea	rsi,[.grs]
@@:
	cmp	r12d,4
	jne	@f
	cstring .tlr, '/tlsroutes/',0
	lea	rsi,[.tlr]
@@:
	cmp	r12d,5
	jne	@f
	cstring .tcr, '/tcproutes/',0
	lea	rsi,[.tcr]
@@:
	call	gw_req_cstr
	mov	rsi,[r8+GWR_NAME]
	mov	ecx,[r8+GWR_NLEN]
	call	gw_req_add
.status:
	cstring .st, '/status',0
	lea	rsi,[.st]
	jmp	gw_req_cstr

; ------------------------------------------------------------ the JSON

macro gs_lit text&
	go_lit	text
end macro

; r8 = type, r9d = 1 True / 0 False, r10 = reason, r11 = message (all NUL-ended),
; eax = observedGeneration: one condition, out (r15)
gs_cond:
	push	rax
	gs_lit	'{"type":"'
	mov	rsi,r8
	call	gs_cstr
	gs_lit	'","status":"'
	test	r9d,r9d
	jz	@f
	gs_lit	'True'
	jmp	.reason
@@:
	gs_lit	'False'
.reason:
	gs_lit	'","reason":"'
	mov	rsi,r10
	call	gs_cstr
	gs_lit	'","message":"'
	mov	rsi,r11
	call	gs_cstr
	gs_lit	'","observedGeneration":'
	pop	rax
	call	go_u
	gs_lit	',"lastTransitionTime":"'
	lea	rsi,[g_gs_time]
	mov	ecx,[g_gs_tlen]
	call	go_bytes
	gs_lit	'"}'
	ret

; rsi = NUL-ended: out
gs_cstr:
	push	rcx
	xor	ecx,ecx
@@:
	cmp	byte [rsi+rcx],0
	je	@f
	inc	ecx
	jmp	@b
@@:
	call	go_bytes
	pop	rcx
	ret

cstring gs_t_accepted, 'Accepted',0
cstring gs_t_programmed, 'Programmed',0
cstring gs_t_resolved, 'ResolvedRefs',0
cstring gs_r_invalid, 'Invalid',0
cstring gs_r_unsupported, 'UnsupportedProtocol',0
cstring gs_r_badcert, 'InvalidCertificateRef',0
cstring gs_r_nomatch, 'NoMatchingParent',0
cstring gs_r_notallowed, 'NotAllowedByListeners',0
cstring gs_r_nohost, 'NoMatchingListenerHostname',0
cstring gs_r_notfound, 'BackendNotFound',0
cstring gs_r_notpermitted, 'RefNotPermitted',0
cstring gs_r_kind, 'InvalidKind',0
cstring gs_m_none, '',0
cstring gs_m_refused, 'okena refused the configuration written for it: see its log',0

; r12d = kind, ebx = which: {"status":{...}}, out
gs_build:
	gs_lit	'{"status":{'
	test	r12d,r12d
	jz	.class
	cmp	r12d,1
	je	.gateway
	call	gs_route
	jmp	.end
.class:
	gs_lit	'"conditions":['
	lea	r8,[gs_t_accepted]
	mov	r9d,1
	mov	r10,r8
	lea	r11,[gs_m_none]
	mov	eax,[g_gw_classgen]
	call	gs_cond
	gs_lit	']'
	jmp	.end
.gateway:
	call	gs_gateway
.end:
	gs_lit	'}}'
	ret

; ebx = a Gateway: its conditions and its listeners'
gs_gateway:
	push	r13
	push	r14
	imul	r14,rbx,GWG_SIZE
	add	r14,[g_gw_base]
	add	r14,GW_T_G
	gs_lit	'"conditions":['
	lea	r8,[gs_t_accepted]
	mov	r9d,1
	mov	r10,r8
	lea	r11,[gs_m_none]
	mov	eax,[r14+GWG_GEN]
	call	gs_cond
	gs_lit	','
	lea	r8,[gs_t_programmed]
	mov	r9d,[g_gs_prog]
	mov	r10,r8
	lea	r11,[gs_m_none]
	test	r9d,r9d
	jnz	@f
	lea	r10,[gs_r_invalid]
	lea	r11,[gs_m_refused]
@@:
	mov	eax,[r14+GWG_GEN]
	call	gs_cond
	gs_lit	'],"listeners":['
	mov	r13d,[r14+GWG_FIRSTL]
	mov	ecx,[r14+GWG_NL]
	add	ecx,r13d
	push	rcx				; (past its last)
.listener:
	cmp	r13d,[rsp]
	jae	.done
	cmp	r13d,[r14+GWG_FIRSTL]
	je	@f
	gs_lit	','
@@:
	imul	rax,r13,GWL_SIZE
	add	rax,[g_gw_base]
	add	rax,GW_T_L
	push	rax
	gs_lit	'{"name":"'
	mov	rax,[rsp]
	mov	rsi,[rax+GWL_NAME]
	mov	ecx,[rax+GWL_NAMELEN]
	call	go_bytes
	gs_lit	'","supportedKinds":['
	mov	rax,[rsp]
	mov	eax,[rax+GWL_PROTO]
	cmp	eax,3
	je	.k_tls
	cmp	eax,4
	je	.k_tcp
	gs_lit	'{"group":"gateway.networking.k8s.io","kind":"HTTPRoute"},{"group":"gateway.networking.k8s.io","kind":"GRPCRoute"}'
	jmp	.kinds
.k_tls:
	gs_lit	'{"group":"gateway.networking.k8s.io","kind":"TLSRoute"}'
	jmp	.kinds
.k_tcp:
	gs_lit	'{"group":"gateway.networking.k8s.io","kind":"TCPRoute"}'
.kinds:
	gs_lit	'],"attachedRoutes":'
	mov	rax,[rsp]
	mov	eax,[rax+GWL_ROUTES]
	call	go_u
	gs_lit	',"conditions":['
	; Accepted
	mov	rax,[rsp]
	lea	r8,[gs_t_accepted]
	xor	r9d,r9d
	lea	r10,[gs_r_unsupported]
	cmp	dword [rax+GWL_STATE],1
	je	@f
	lea	r10,[gs_r_invalid]
	cmp	dword [rax+GWL_STATE],2
	je	@f
	mov	r9d,1
	mov	r10,r8
@@:
	lea	r11,[gs_m_none]
	mov	eax,[r14+GWG_GEN]
	call	gs_cond
	gs_lit	','
	; ResolvedRefs: an HTTPS listener's certificate
	mov	rax,[rsp]
	lea	r8,[gs_t_resolved]
	mov	r9d,1
	mov	r10,r8
	cmp	dword [rax+GWL_PROTO],2
	jne	@f
	cmp	dword [rax+GWL_STATE],0
	jne	@f
	cmp	dword [rax+GWL_CERTOK],0
	jne	@f
	xor	r9d,r9d
	lea	r10,[gs_r_badcert]
@@:
	push	r9				; (programmed needs it)
	lea	r11,[gs_m_none]
	mov	eax,[r14+GWG_GEN]
	call	gs_cond
	gs_lit	','
	; Programmed: accepted, its references had, and the file taken
	pop	r9
	mov	rax,[rsp]
	cmp	dword [rax+GWL_STATE],0
	je	@f
	xor	r9d,r9d
@@:
	and	r9d,[g_gs_prog]
	lea	r8,[gs_t_programmed]
	mov	r10,r8
	lea	r11,[gs_m_none]
	test	r9d,r9d
	jnz	@f
	lea	r10,[gs_r_invalid]
@@:
	mov	eax,[r14+GWG_GEN]
	call	gs_cond
	gs_lit	']}'
	pop	rax
	inc	r13d
	jmp	.listener
.done:
	pop	rcx
	gs_lit	']'
	pop	r14
	pop	r13
	ret

; ebx = a route: its parents (others' first, as they are; then ours)
gs_route:
	push	r14
	imul	r14,rbx,GWR_SIZE
	add	r14,[g_gw_base]
	add	r14,GW_T_R
	gs_lit	'"parents":['
	mov	dword [g_gs_count],0		; written so far
	; other controllers' entries, as they are
	mov	rsi,[r14+GWR_STATUS]
	test	rsi,rsi
	jz	.ours
	call	gj_first
	jc	.ours
.other:
	push	rsi
	gk	'controllerName'
	call	gj_str
	pop	rsi
	jc	.copy
	push	rsi
	lea	rsi,[str_gs_ctl]
	mov	edx,str_gs_ctl.len
	call	gw_same
	pop	rsi
	je	.other_next			; (ours: made anew below)
.copy:
	push	rsi
	call	js_skip
	mov	rcx,rsi
	pop	rsi
	jc	.ours
	sub	rcx,rsi
	cmp	dword [g_gs_count],0
	jz	@f
	gs_lit	','
@@:
	call	go_bytes
	inc	dword [g_gs_count]
.other_next:
	call	gj_next
	jnc	.other
.ours:
	xor	ecx,ecx
.pr:
	cmp	ecx,[g_gw_npr]
	jae	.done
	imul	rax,rcx,GWPR_SIZE
	add	rax,[g_gw_base]
	add	rax,GW_T_PR
	cmp	[rax+GWPR_ROUTE],ebx
	jne	.pr_next
	cmp	dword [rax+GWPR_GWI],-1
	je	.pr_next
	push	rcx
	push	rax
	cmp	dword [g_gs_count],0
	jz	@f
	gs_lit	','
@@:
	inc	dword [g_gs_count]
	gs_lit	'{"parentRef":'
	mov	rax,[rsp]
	mov	rsi,[rax+GWPR_RAW]
	mov	ecx,[rax+GWPR_RAWLEN]
	call	go_bytes
	gs_lit	',"controllerName":"'
	lea	rsi,[str_gs_ctl]
	mov	ecx,str_gs_ctl.len
	call	go_bytes
	gs_lit	'","conditions":['
	; Accepted, or why not
	mov	rax,[rsp]
	mov	edx,[rax+GWPR_WHY]
	lea	r8,[gs_t_accepted]
	mov	r9d,1
	mov	r10,r8
	test	edx,edx
	jz	@f
	xor	r9d,r9d
	lea	r10,[gs_r_nohost]
	cmp	edx,1
	je	@f
	lea	r10,[gs_r_notallowed]
	cmp	edx,2
	je	@f
	lea	r10,[gs_r_nomatch]
@@:
	lea	r11,[gs_m_none]
	mov	eax,[r14+GWR_GEN]
	call	gs_cond
	gs_lit	','
	; ResolvedRefs
	mov	edx,[r14+GWR_REFS]
	lea	r8,[gs_t_resolved]
	mov	r9d,1
	mov	r10,r8
	test	edx,edx
	jz	@f
	xor	r9d,r9d
	lea	r10,[gs_r_notfound]
	cmp	edx,GRF_NOTFOUND
	je	@f
	lea	r10,[gs_r_notpermitted]
	cmp	edx,GRF_NOTPERMITTED
	je	@f
	lea	r10,[gs_r_kind]
@@:
	lea	r11,[gs_m_none]
	mov	eax,[r14+GWR_GEN]
	call	gs_cond
	gs_lit	']}'
	pop	rax
	pop	rcx
.pr_next:
	inc	ecx
	jmp	.pr
.done:
	gs_lit	']'
	pop	r14
	ret

; ------------------------------------------------------------ the class

; before the lists are read: g_gw_classok (0 no GatewayClass of that name, 1 one
; whose controllerName is okena's, 2 another's: its Gateways are not served).
; CF when the API server did not answer.
gw_class:
	push	r13
	mov	dword [g_gw_classok],0
	mov	dword [g_gw_classgen],0
	call	gw_req_begin
	cstring .p, '/apis/gateway.networking.k8s.io/v1/gatewayclasses/',0
	lea	rsi,[.p]
	call	gw_req_cstr
	mov	rsi,[g_plan_gw+GWP_CLASS]
	mov	ecx,[g_plan_gw+GWP_CLASSLEN]
	call	gw_req_add
	lea	rsi,[str_gw_rv0]
	call	gw_req_cstr
	call	gw_get
	jc	.out
	cmp	eax,200
	jne	.none				; (404: none; another error: none either)
	lea	r13,[rsi+rcx]
	push	rsi
	gk	'metadata'
	call	gj_get
	jc	@f
	gk	'generation'
	call	gj_num
	jc	@f
	mov	[g_gw_classgen],eax
@@:
	pop	rsi
	mov	dword [g_gw_classok],2
	gk	'spec'
	call	gj_get
	jc	.none
	gk	'controllerName'
	call	gj_str
	jc	.none
	lea	rsi,[str_gs_ctl]
	mov	edx,str_gs_ctl.len
	call	gw_same
	jne	.none
	mov	dword [g_gw_classok],1
.none:
	clc
.out:
	pop	r13
	ret
