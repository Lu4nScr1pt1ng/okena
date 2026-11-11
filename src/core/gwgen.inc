; The Gateway API in okena's terms (gateway.inc's process).
;
; A Gateway of the class gives its listeners (HTTP and HTTPS; a port, maybe a
; hostname, which namespaces' routes it takes). An HTTPRoute attached to one
; (parentRefs: the Gateway, maybe a listener's name or port) gives, for each
; hostname both allow, for each rule and each of its matches, an entry: a path
; (Exact: that path; PathPrefix /p: the routes /p and /p/*), and conditions
; (method, headers, query parameters). Entries become okena's routes, by port,
; then by host: every host a block, with the entries of the wildcards and of no
; hostname that cover it too, below its own; by path; and in a route, the more
; precise first, as the Gateway API orders them (the exact host, then the
; longest wildcard, then none; an Exact path before a prefix's own; more
; conditions; then the route's place in the list). Conditions are `match`
; blocks; the first entry with none is the route's own, and those after it can
; never be chosen. A route with no entry that has no condition answers 404,
; and so does a port's or a host's `/*` that no route took.
;
; A rule's filters: RequestHeaderModifier and ResponseHeaderModifier (`header`,
; `response header`), RequestRedirect (`redirect`, its host the request's when
; not said), URLRewrite's path (`rewrite path`), RequestMirror (`mirror`); any
; other makes the rule answer 500. Its backendRefs, Services of its own
; namespace, become pools (`discover kubernetes`, the Service's port by its
; name) shared by weight (`split`); none to be had: 500. Not here: regular
; expressions in paths and query parameters, URLRewrite's hostname, filters of
; a single backendRef, ReferenceGrants (so nothing across namespaces), status.

GWL_NS		:= 0			; q: the Gateway's namespace
GWL_NSLEN	:= 8			; d
GWL_PORT		:= 12			; d
GWL_GW		:= 16			; q: its name
GWL_GWLEN	:= 24			; d
GWL_PROTO	:= 28			; d: 1 HTTP, 2 HTTPS
GWL_NAME		:= 32			; q: the listener's name
GWL_NAMELEN	:= 40			; d
GWL_ALL		:= 44			; d: routes from all namespaces (else its own)
GWL_HOST		:= 48			; q: its hostname, 0 none
GWL_HOSTLEN	:= 56			; d
GWL_TLS		:= 64			; q: certificateRefs (the JSON array)
GWL_STATE	:= 72			; d: 0 served, 1 not a protocol okena serves, 2 invalid
GWL_GWI		:= 76			; d: its Gateway (GW_T_G)
GWL_ROUTES	:= 80			; d: routes attached
GWL_CERTOK	:= 84			; d: HTTPS: a certificate was had
GWL_SIZE		:= 96
GW_MAXL		:= 256

GWE_PORT		:= 0			; d
GWE_ORIGIN	:= 4			; d: 0 Exact, 1 a prefix's own path, 2 a prefix's /*
GWE_HOST		:= 8			; q (0: none)
GWE_HOSTLEN	:= 16			; d
GWE_OPLEN	:= 20			; d
GWE_OPATH	:= 24			; q: okena's path
GWE_PFX		:= 32			; q: the prefix (no / at its end; empty for /)
GWE_PFXLEN	:= 40			; d
GWE_NCOND	:= 44			; d
GWE_METHOD	:= 48			; q (0: any)
GWE_MLEN		:= 56			; d
GWE_NH		:= 60			; d
GWE_HDRS		:= 64			; q: headers (JSON array)
GWE_QUERY	:= 72			; q: queryParams (JSON array)
GWE_NQ		:= 80			; d
GWE_SEQ		:= 84			; d
GWE_RULE		:= 88			; q: the rule (JSON object)
GWE_NS		:= 96			; q: the route's namespace
GWE_NSLEN	:= 104			; d
GWE_PROTO	:= 108			; d: its listener's
GWE_ROUTE	:= 112			; d: its route (GW_T_R)
GWE_SIZE		:= 120
GW_MAXE		:= 4096

GWP2_NS		:= 0			; q
GWP2_NSLEN	:= 8			; d
GWP2_PORT		:= 12			; d
GWP2_SVC		:= 16			; q
GWP2_SVCLEN	:= 24			; d
GWP2_STATE	:= 28			; d: 1 served, 2 not to be had
GWP2_PN		:= 32			; q: the Service port's name (0: none)
GWP2_PNLEN	:= 40			; d
GWP2_SIZE		:= 48
GW_MAXP		:= 512

GW_MAXH		:= 1024			; hosts on a port

GWG_NS		:= 0			; q
GWG_NSLEN	:= 8			; d
GWG_NLEN	:= 12			; d
GWG_NAME	:= 16			; q
GWG_GEN		:= 24			; d: metadata.generation
GWG_FIRSTL	:= 28			; d: its listeners in GW_T_L
GWG_NL		:= 32			; d
GWG_SIZE	:= 40
GW_MAXG		:= 64

GWR_NS		:= 0			; q: a route
GWR_NSLEN	:= 8			; d
GWR_NLEN	:= 12			; d
GWR_NAME	:= 16			; q
GWR_GEN		:= 24			; d
GWR_REFS	:= 28			; d: 0 its backends resolved, else why not (GRF_*)
GWR_STATUS	:= 32			; q: its status.parents (JSON), 0 none
GWR_SIZE	:= 40
GW_MAXR		:= 1024
GRF_NOTFOUND	:= 1			; BackendNotFound
GRF_NOTPERMITTED := 2			; RefNotPermitted
GRF_KIND	:= 3			; InvalidKind

GWPR_ROUTE	:= 0			; d: a parentRef: its route
GWPR_GWI	:= 4			; d: our Gateway it names, -1 none
GWPR_RAW	:= 8			; q: it, as written (JSON)
GWPR_RAWLEN	:= 16			; d
GWPR_WHY	:= 20			; d: 0 accepted, 1 NoMatchingListenerHostname, 2 NotAllowedByListeners, 3 NoMatchingParent (the more precise the lower)
GWPR_SIZE	:= 24
GW_MAXPR	:= 4096

GW_T_L		:= GW_TABLES
GW_T_E		:= GW_T_L + GWL_SIZE * GW_MAXL
GW_T_P		:= GW_T_E + GWE_SIZE * GW_MAXE
GW_T_SEL	:= GW_T_P + GWP2_SIZE * GW_MAXP
GW_T_H		:= GW_T_SEL + 4 * GW_MAXE
GW_T_G		:= GW_T_H + 16 * GW_MAXH
GW_T_R		:= GW_T_G + GWG_SIZE * GW_MAXG
GW_T_PR		:= GW_T_R + GWR_SIZE * GW_MAXR
GW_T_PATCH	:= GW_T_PR + GWPR_SIZE * GW_MAXPR
GW_T_PATCH_CAP	:= 2 shl 20
GW_T_KEYS	:= GW_T_PATCH + GW_T_PATCH_CAP	; what status was written: key, hash
GW_KEYS		:= 8192
GW_T_END	:= GW_T_KEYS + 16 * GW_KEYS
assert GW_T_END <= GW_ARENA

bss
	align 8
	g_gw_nl		dd ?
	g_gw_ne		dd ?
	g_gw_np		dd ?
	g_gw_nh		dd ?
	g_gw_nsel	dd ?
	g_gw_certs	dd ?		; a certificate was written anew
	g_gw_fail	dd ?		; a question went unanswered: nothing written
	g_gw_nroutes	dd ?
	g_gw_nports	dd ?
	g_gw_seq	dd ?
	g_gw_port	dd ?		; the port being written
	g_gw_proto	dd ?
	g_gw_txt	dq ?		; GW_TEXT's cursor
	; the route being read
	g_gr_ns		dq ?
	g_gr_nslen	dd ?
	g_gr_li		dd ?
	g_gr_spec	dq ?
	g_gr_hn		dq ?
	g_gr_host	dq ?
	g_gr_hostlen	dd ?
	g_gr_rule	dq ?
	g_gp_name	dq ?
	g_gp_nlen	dd ?
	g_gr_nhosts	dd ?
	; the host being written
	g_gh_host	dq ?
	g_gh_len	dd ?
	g_gh_ind	dd ?
	g_gw_tag	rb 256
	; a rule's actions
	g_ga_redirect	dq ?
	g_ga_rewrite	dq ?
	g_ga_mirror	dq ?
	g_ga_scheme	dq ?
	g_ga_slen	dd ?
	g_ga_hlen	dd ?
	g_ga_host	dq ?
	g_ga_port	dd ?
	g_ga_ptype	dd ?
	g_ga_pv		dq ?
	g_ga_pvlen	dd ?
	g_ga_nb		dd ?
	g_ga_bp		rd 8
	g_ga_bw		rd 8
	; certificates
	g_gw_ncert	dd ?
	g_gc_nlen	dd ?
	g_gc_name	dq ?
	g_gc_seen	rq 64
	g_gc_seenl	rd 64
	g_gp_idx	dd ?
	g_ga_code	dd ?
	g_ga_sum	dd ?
	g_gh_op		dq ?
	g_gh_nlen	dd ?
	g_gw_ng		dd ?
	g_gw_gwi	dd ?
	g_gw_nr		dd ?
	g_gw_npr	dd ?
	g_gw_rti	dd ?
	g_gw_pri	dd ?
	g_gw_classok	dd ?		; the GatewayClass: 0 not there, 1 okena's, 2 another's
	g_gw_classgen	dd ?
	g_gw_lend	dq ?		; the lists' end (the status reads them after)
end bss

macro go_lit text&
	local s
	cstring s, text
	push	rsi
	push	rcx
	lea	rsi,[s]
	mov	ecx,s.len
	call	go_bytes
	pop	rcx
	pop	rsi
end macro

; rsi/ecx = bytes: out (r15). Keeps all but r15.
go_bytes:
	push	rdi
	push	rsi
	push	rcx
	mov	rdi,r15
	rep	movsb
	mov	r15,rdi
	pop	rcx
	pop	rsi
	pop	rdi
	ret

; rsi/ecx = a value (gw_value_ok): out quoted, \ " and $ escaped. Keeps all
; but r15.
go_q:
	mov	byte [r15],'"'
	inc	r15
	call	go_qin
	mov	byte [r15],'"'
	inc	r15
	ret
; the same, without the quotes
go_qin:
	push	rax
	push	rsi
	push	rcx
.char:
	test	ecx,ecx
	jz	.end
	mov	al,[rsi]
	cmp	al,'"'
	je	.esc
	cmp	al,'\'
	je	.esc
	cmp	al,'$'
	jne	.plain
.esc:
	mov	byte [r15],'\'
	inc	r15
.plain:
	mov	[r15],al
	inc	r15
	inc	rsi
	dec	ecx
	jmp	.char
.end:
	pop	rcx
	pop	rsi
	pop	rax
	ret

; eax = a number: out. Keeps all but r15.
go_u:
	push	rax
	push	rcx
	push	rdx
	push	rdi
	push	r9
	mov	rdi,r15
	call	dk_decimal
	mov	r15,rdi
	pop	r9
	pop	rdi
	pop	rdx
	pop	rcx
	pop	rax
	ret

; ecx = spaces: out. Keeps all but r15.
go_ind:
	push	rcx
@@:
	test	ecx,ecx
	jz	@f
	mov	byte [r15],' '
	inc	r15
	dec	ecx
	jmp	@b
@@:
	pop	rcx
	ret

go_nl:
	mov	byte [r15],10
	inc	r15
	ret

; ------------------------------------------------------------ JSON

; rsi = an object, rdi/edx = a key: rdi/ecx = its string (none with escapes).
; CF when not there, or not such a string. Keeps rbx, r12-r15, rsi.
gj_str:
	push	rsi
	call	js_find
	jc	.no
	call	js_ws
	call	js_str
	jc	.no
	xor	eax,eax
@@:
	cmp	eax,ecx
	jae	.yes
	cmp	byte [rdi+rax],'\'
	je	.escaped
	inc	eax
	jmp	@b
.escaped:
	call	gj_unescape
	jc	.no
.yes:
	pop	rsi
	clc
	ret
.no:
	pop	rsi
	stc
	ret

; rdi/ecx = a JSON string's bytes with escapes: rdi/ecx = it decoded, in
; GW_TEXT (\uXXXX as UTF-8). CF when it holds a control character, a lone
; surrogate, or what is not an escape. Keeps rbx, r12-r15, rsi.
gj_unescape:
	push	rsi
	push	rbx
	mov	rsi,rdi
	lea	rbx,[rsi+rcx]			; its end
	mov	rdi,[g_gw_txt]
	push	rdi
.c:
	cmp	rsi,rbx
	jae	.done
	lodsb
	cmp	al,'\'
	je	.esc
	stosb
	jmp	.c
.esc:
	cmp	rsi,rbx
	jae	.bad
	lodsb
	mov	ah,'"'
	cmp	al,'"'
	je	.put
	cmp	al,'\'
	je	.put
	cmp	al,'/'
	je	.put
	cmp	al,'u'
	jne	.bad				; (\b \f \n \r \t: control characters)
	lea	rax,[rsi+4]
	cmp	rax,rbx
	ja	.bad
	xor	edx,edx
	mov	ecx,4
.hex:
	lodsb
	shl	edx,4
	sub	al,'0'
	cmp	al,9
	jbe	.digit
	or	al,0x20
	sub	al,'a' - '0'
	cmp	al,5
	ja	.bad
	add	al,10
.digit:
	movzx	eax,al
	or	edx,eax
	dec	ecx
	jnz	.hex
	cmp	edx,0x20
	jb	.bad
	cmp	edx,0xD800
	jb	@f
	cmp	edx,0xDFFF
	jbe	.bad
@@:
	cmp	edx,0x80
	jae	@f
	mov	al,dl
	stosb
	jmp	.c
@@:
	cmp	edx,0x800
	jae	@f
	mov	eax,edx
	shr	eax,6
	or	al,0xC0
	stosb
	mov	eax,edx
	and	al,0x3F
	or	al,0x80
	stosb
	jmp	.c
@@:
	mov	eax,edx
	shr	eax,12
	or	al,0xE0
	stosb
	mov	eax,edx
	shr	eax,6
	and	al,0x3F
	or	al,0x80
	stosb
	mov	eax,edx
	and	al,0x3F
	or	al,0x80
	stosb
	jmp	.c
.put:
	stosb
	jmp	.c
.done:
	mov	[g_gw_txt],rdi
	mov	rcx,rdi
	pop	rdi
	sub	rcx,rdi
	pop	rbx
	pop	rsi
	clc
	ret
.bad:
	pop	rdi
	pop	rbx
	pop	rsi
	stc
	ret

; rsi = an object, rdi/edx = a key: eax = its number (0 .. 999 999 999). CF when
; not there, or not one. Keeps rbx, r12-r15, rsi.
gj_num:
	push	rsi
	call	js_find
	jc	.no
	call	js_ws
	xor	eax,eax
	xor	ecx,ecx
.digit:
	cmp	rsi,r13
	jae	.end
	movzx	edx,byte [rsi]
	sub	edx,'0'
	cmp	edx,9
	ja	.end
	imul	eax,eax,10
	add	eax,edx
	inc	rsi
	inc	ecx
	cmp	ecx,9
	ja	.no
	jmp	.digit
.end:
	test	ecx,ecx
	jz	.no
	pop	rsi
	clc
	ret
.no:
	pop	rsi
	stc
	ret

; rsi = an object, rdi/edx = a key: rsi at its value. CF (rsi kept) when not there.
gj_get:
	push	rsi
	call	js_find
	jc	.no
	call	js_ws
	add	rsp,8
	clc
	ret
.no:
	pop	rsi
	stc
	ret

; rsi at a value: rsi at the first element of the array. CF when it is not
; one, or it is empty.
gj_first:
	call	js_ws
	cmp	rsi,r13
	jae	.no
	cmp	byte [rsi],'['
	jne	.no
	inc	rsi
	call	js_ws
	cmp	rsi,r13
	jae	.no
	cmp	byte [rsi],']'
	je	.no
	clc
	ret
.no:
	stc
	ret

; rsi at an element: rsi at the next one. CF at the end (or what cannot be read).
gj_next:
	call	js_skip
	jc	.no
	call	js_ws
	cmp	rsi,r13
	jae	.no
	cmp	byte [rsi],','
	jne	.no
	inc	rsi
	call	js_ws
	clc
	ret
.no:
	stc
	ret

macro gk name*
	js_key name
end macro

; rdi/ecx vs rsi/edx: ZF when the same. Keeps all but flags.
gw_same:
	cmp	ecx,edx
	jne	.out
	push	rsi
	push	rdi
	push	rcx
	repe	cmpsb
	pop	rcx
	pop	rdi
	pop	rsi
.out:
	ret

; rcx/edx = a DNS subdomain (a-z 0-9 . -, 1..253). CF when not.
gw_sub_ok:
	test	edx,edx
	jz	.bad
	cmp	edx,253
	ja	.bad
	xor	eax,eax
.char:
	movzx	r8d,byte [rcx+rax]
	cmp	r8d,'-'
	je	.ok
	cmp	r8d,'.'
	je	.ok
	lea	r9d,[r8-'0']
	cmp	r9d,9
	jbe	.ok
	lea	r9d,[r8-'a']
	cmp	r9d,25
	ja	.bad
.ok:
	inc	eax
	cmp	eax,edx
	jb	.char
	clc
	ret
.bad:
	stc
	ret

; rcx/edx = a hostname: maybe *. then a subdomain with a dot in it, or not. CF
; when not.
gw_host_ok:
	cmp	edx,2
	jb	gw_sub_ok
	cmp	word [rcx],'*.'
	jne	gw_sub_ok
	push	rcx
	push	rdx
	add	rcx,2
	sub	edx,2
	call	gw_sub_ok
	pop	rdx
	pop	rcx
	ret

; rcx/edx = a path: / then what a path may hold that okena's routes, rewrites
; and redirects read as itself. CF when not.
gw_path_ok:
	test	edx,edx
	jz	.bad
	cmp	edx,1000
	ja	.bad
	cmp	byte [rcx],'/'
	jne	.bad
	xor	eax,eax
.char:
	movzx	r8d,byte [rcx+rax]
	lea	r9d,[r8-'a']
	cmp	r9d,25
	jbe	.ok
	lea	r9d,[r8-'A']
	cmp	r9d,25
	jbe	.ok
	lea	r9d,[r8-'0']
	cmp	r9d,9
	jbe	.ok
	push	rdi
	push	rcx
	push	rax
	lea	rdi,[.allowed]
	mov	ecx,.allowed.len
	mov	eax,r8d
	repne	scasb
	pop	rax
	pop	rcx
	pop	rdi
	jne	.bad
.ok:
	inc	eax
	cmp	eax,edx
	jb	.char
	clc
	ret
.bad:
	stc
	ret
.allowed db '-._~/%!&()+,=:@'
.allowed.len = $ - .allowed

; rcx/edx = a header's name (an HTTP token): CF when not
gw_token_ok:
	test	edx,edx
	jz	.bad
	cmp	edx,200
	ja	.bad
	xor	eax,eax
@@:
	movzx	r8d,byte [rcx+rax]
	cmp	byte [http_tchar+r8],0
	je	.bad
	cmp	r8d,'*'
	je	.bad
	inc	eax
	cmp	eax,edx
	jb	@b
	clc
	ret
.bad:
	stc
	ret

; rsi/ecx = text: copied into GW_TEXT, rdi = there. Keeps rcx.
gw_keep:
	mov	rdi,[g_gw_txt]
	push	rdi
	push	rcx
	rep	movsb
	pop	rcx
	mov	[g_gw_txt],rdi
	pop	rdi
	ret

; ------------------------------------------------------------ the render

; GW_OUT: the configuration, eax = its length. CF when it cannot be made now.
gw_render:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	dword [g_gw_fail],0
	mov	dword [g_gw_certs],0
	mov	dword [g_gw_nl],0
	mov	dword [g_gw_ne],0
	mov	dword [g_gw_np],0
	mov	dword [g_gw_ng],0
	mov	dword [g_gw_nr],0
	mov	dword [g_gw_npr],0
	mov	dword [g_gw_seq],0
	mov	dword [g_gw_nroutes],0
	mov	dword [g_gw_nports],0
	mov	rax,[g_gw_base]
	add	rax,GW_TEXT
	mov	[g_gw_txt],rax
	; the class: okena's, or another's (then nothing of it is served)
	call	gw_class
	jc	.not_now
	; the Gateways, then the HTTPRoutes, side by side
	call	gw_req_begin
	cstring .gws, '/apis/gateway.networking.k8s.io/v1/gateways?resourceVersion=0',0
	lea	rsi,[.gws]
	call	gw_req_cstr
	call	gw_get
	jc	.not_now
	cmp	eax,200
	jne	.refused
	mov	rdi,[g_gw_base]
	add	rdi,GW_LISTS
	cmp	ecx,GW_LISTS_CAP / 2
	ja	.unreadable
	mov	r12,rdi				; the Gateways
	rep	movsb
	mov	r14,rdi				; the HTTPRoutes
	call	gw_req_begin
	cstring .hrs, '/apis/gateway.networking.k8s.io/v1/httproutes?resourceVersion=0',0
	lea	rsi,[.hrs]
	call	gw_req_cstr
	call	gw_get
	jc	.not_now
	cmp	eax,200
	jne	.refused
	cmp	ecx,GW_LISTS_CAP / 2
	ja	.unreadable
	mov	rdi,r14
	rep	movsb
	mov	r13,rdi				; (the end, for the parser)
	mov	[g_gw_lend],rdi
	mov	rsi,r12
	call	gw_listeners
	jc	.unreadable
	mov	rsi,r14
	call	gw_routes
	jc	.unreadable
	mov	r15,[g_gw_base]
	add	r15,GW_OUT
	call	gw_emit
	cmp	dword [g_gw_fail],0
	jne	.not_now
	mov	rax,r15
	sub	rax,[g_gw_base]
	sub	rax,GW_OUT
	clc
	jmp	.out
.refused:
	mov	eax,3
	cstring str_gw_refused, ': the API server refused the question (not 200: are the Gateway API CRDs installed, and may the service account list gateways, httproutes, get services and secrets?)'
	lea	rsi,[str_gw_refused]
	mov	edx,str_gw_refused.len
	call	gw_tell
	jmp	.not_now
.unreadable:
	mov	eax,8
	cstring str_gw_lists, ': the Gateways or the HTTPRoutes cannot be read (not such a list, or too large)'
	lea	rsi,[str_gw_lists]
	mov	edx,str_gw_lists.len
	call	gw_tell
.not_now:
	stc
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; ------------------------------------------------------------ the listeners

; rsi = the GatewayList: the listeners of the class's Gateways. CF when it
; cannot be read.
gw_listeners:
	push	rbx
	push	r12
	push	r14
	gk	'items'
	call	gj_get
	jc	.bad
	cmp	dword [g_gw_classok],2
	je	.done				; (the class is another controller's)
	cmp	byte [rsi],'n'			; null: none
	je	.done
	call	gj_first
	jc	.done
.gateway:
	mov	rbx,rsi
	gk	'spec'
	call	gj_get
	jc	.next
	mov	r12,rsi
	gk	'gatewayClassName'
	call	gj_str
	jc	.next
	mov	rsi,[g_plan_gw+GWP_CLASS]
	mov	edx,[g_plan_gw+GWP_CLASSLEN]
	call	gw_same
	jne	.next
	mov	rsi,rbx
	gk	'metadata'
	call	gj_get
	jc	.next
	mov	r14,rsi
	gk	'namespace'
	call	gj_str
	jc	.next
	push	rdi
	push	rcx
	mov	rcx,rdi
	mov	edx,[rsp]
	call	gw_label_ok
	pop	rcx
	pop	rdi
	jc	.next
	mov	[g_gr_ns],rdi
	mov	[g_gr_nslen],ecx
	mov	rsi,r14
	gk	'name'
	call	gj_str
	jc	.next
	push	rdi
	push	rcx
	mov	rcx,rdi
	mov	edx,[rsp]
	call	gw_sub_ok
	pop	rcx
	pop	rdi
	jc	.next
	mov	r14,rdi				; (the Gateway's name)
	mov	[g_gw_tag],cl			; (its length: a scratch)
	; the Gateway itself, for its status
	mov	eax,[g_gw_ng]
	cmp	eax,GW_MAXG
	jae	.next
	mov	[g_gw_gwi],eax
	inc	dword [g_gw_ng]
	imul	rax,rax,GWG_SIZE
	mov	r8,[g_gw_base]
	lea	r8,[r8+GW_T_G+rax]
	mov	rax,[g_gr_ns]
	mov	[r8+GWG_NS],rax
	mov	eax,[g_gr_nslen]
	mov	[r8+GWG_NSLEN],eax
	mov	[r8+GWG_NAME],r14
	mov	[r8+GWG_NLEN],ecx
	mov	eax,[g_gw_nl]
	mov	[r8+GWG_FIRSTL],eax
	mov	dword [r8+GWG_GEN],0
	push	r8
	mov	rsi,rbx
	gk	'metadata'
	call	gj_get
	jc	@f
	gk	'generation'
	call	gj_num
	jc	@f
	mov	r8,[rsp]
	mov	[r8+GWG_GEN],eax
@@:
	pop	r8
	mov	rsi,r12
	gk	'listeners'
	call	gj_get
	jc	.listened
	call	gj_first
	jc	.listened
.listener:
	push	rsi
	call	gw_listener
	pop	rsi
	call	gj_next
	jnc	.listener
.listened:
	mov	eax,[g_gw_gwi]
	imul	rax,rax,GWG_SIZE
	add	rax,[g_gw_base]
	mov	ecx,[g_gw_nl]
	sub	ecx,[rax+GW_T_G+GWG_FIRSTL]
	mov	[rax+GW_T_G+GWG_NL],ecx
.next:
	mov	rsi,rbx
	call	gj_next
	jnc	.gateway
.done:
	clc
	jmp	.out
.bad:
	stc
.out:
	pop	r14
	pop	r12
	pop	rbx
	ret
; rsi = a listener, r14/g_gw_tag = its Gateway's name, g_gr_ns its namespace:
; into GW_T_L when okena can serve it
gw_listener:
	mov	eax,[g_gw_nl]
	cmp	eax,GW_MAXL
	jae	.no
	push	rbx
	push	r12
	mov	rbx,rsi				; the listener
	imul	rax,rax,GWL_SIZE
	mov	r12,[g_gw_base]
	lea	r12,[r12+GW_T_L+rax]		; its slot
	mov	rax,[g_gr_ns]
	mov	[r12+GWL_NS],rax
	mov	eax,[g_gr_nslen]
	mov	[r12+GWL_NSLEN],eax
	mov	[r12+GWL_GW],r14
	movzx	eax,byte [g_gw_tag]
	mov	[r12+GWL_GWLEN],eax
	gk	'name'
	call	gj_str
	jc	.drop
	mov	[r12+GWL_NAME],rdi
	mov	[r12+GWL_NAMELEN],ecx
	mov	edx,ecx				; (it goes into its status, as JSON)
	mov	rcx,rdi
	call	gw_sub_ok
	jc	.drop
	mov	rsi,rbx
	gk	'port'
	call	gj_num
	jc	.invalid
	test	eax,eax
	jz	.invalid
	cmp	eax,65535
	ja	.invalid
	mov	[r12+GWL_PORT],eax
	mov	rsi,rbx
	gk	'protocol'
	call	gj_str
	jc	.unsupported
	mov	dword [r12+GWL_PROTO],1
	cmp	ecx,4
	jne	@f
	cmp	dword [rdi],'HTTP'
	je	.proto
@@:
	mov	dword [r12+GWL_PROTO],2
	cmp	ecx,5
	jne	.unsupported
	cmp	dword [rdi],'HTTP'
	jne	.unsupported
	cmp	byte [rdi+4],'S'
	jne	.unsupported
.proto:
	mov	qword [r12+GWL_HOST],0
	mov	dword [r12+GWL_HOSTLEN],0
	mov	rsi,rbx
	gk	'hostname'
	call	gj_str
	jc	.no_host
	mov	[r12+GWL_HOST],rdi
	mov	[r12+GWL_HOSTLEN],ecx
	mov	edx,ecx
	mov	rcx,rdi
	call	gw_host_ok
	jc	.invalid
.no_host:
	mov	dword [r12+GWL_ALL],0
	mov	rsi,rbx
	gk	'allowedRoutes'
	call	gj_get
	jc	.allowed
	gk	'namespaces'
	call	gj_get
	jc	.allowed
	gk	'from'
	call	gj_str
	jc	.allowed
	cmp	ecx,3
	jne	.allowed
	cmp	word [rdi],'Al'
	jne	.allowed
	cmp	byte [rdi+2],'l'
	jne	.allowed
	mov	dword [r12+GWL_ALL],1
.allowed:
	mov	qword [r12+GWL_TLS],0
	cmp	dword [r12+GWL_PROTO],2
	jne	.taken
	mov	rsi,rbx
	gk	'tls'
	call	gj_get
	jc	.invalid
	gk	'mode'
	call	gj_str
	jc	@f
	cmp	ecx,9
	jne	.unsupported				; (Passthrough is not this)
@@:
	gk	'certificateRefs'
	call	gj_get
	jc	.invalid
	mov	[r12+GWL_TLS],rsi
.taken:
	mov	dword [r12+GWL_STATE],0
	jmp	.counted
.unsupported:
	mov	dword [r12+GWL_STATE],1		; (said in its status: UnsupportedProtocol)
	jmp	.counted
.invalid:
	mov	dword [r12+GWL_STATE],2		; (Invalid)
.counted:
	mov	eax,[g_gw_gwi]
	mov	[r12+GWL_GWI],eax
	mov	dword [r12+GWL_ROUTES],0
	mov	dword [r12+GWL_CERTOK],0
	inc	dword [g_gw_nl]
.drop:
	pop	r12
	pop	rbx
.no:
	ret


; ------------------------------------------------------------ the routes

; rsi = the HTTPRouteList: the entries of those attached. CF when it cannot be read.
gw_routes:
	push	rbx
	push	r12
	push	r14
	gk	'items'
	call	gj_get
	jc	.bad
	cmp	byte [rsi],'n'
	je	.done
	call	gj_first
	jc	.done
.route:
	mov	rbx,rsi
	gk	'metadata'
	call	gj_get
	jc	.next
	gk	'namespace'
	call	gj_str
	jc	.next
	push	rdi
	push	rcx
	mov	rcx,rdi
	mov	edx,[rsp]
	call	gw_label_ok
	pop	rcx
	pop	rdi
	jc	.next
	mov	[g_gr_ns],rdi
	mov	[g_gr_nslen],ecx
	; the route, for its status
	mov	eax,[g_gw_nr]
	cmp	eax,GW_MAXR
	jae	.next
	mov	[g_gw_rti],eax
	inc	dword [g_gw_nr]
	imul	r12,rax,GWR_SIZE
	add	r12,[g_gw_base]
	add	r12,GW_T_R
	mov	[r12+GWR_NS],rdi
	mov	[r12+GWR_NSLEN],ecx
	mov	qword [r12+GWR_NAME],0
	mov	dword [r12+GWR_NLEN],0
	mov	dword [r12+GWR_GEN],0
	mov	dword [r12+GWR_REFS],0
	mov	qword [r12+GWR_STATUS],0
	mov	rsi,rbx
	gk	'metadata'
	call	gj_get
	jc	.unnamed
	push	rsi
	gk	'generation'
	call	gj_num
	jc	@f
	mov	[r12+GWR_GEN],eax
@@:
	pop	rsi
	gk	'name'
	call	gj_str
	jc	.unnamed
	mov	edx,ecx
	push	rdi
	push	rcx
	mov	rcx,rdi
	call	gw_sub_ok
	pop	rcx
	pop	rdi
	jc	.unnamed
	mov	[r12+GWR_NAME],rdi
	mov	[r12+GWR_NLEN],ecx
.unnamed:
	mov	rsi,rbx
	gk	'status'
	call	gj_get
	jc	@f
	gk	'parents'
	call	gj_get
	jc	@f
	mov	[r12+GWR_STATUS],rsi
@@:
	mov	rsi,rbx
	gk	'spec'
	call	gj_get
	jc	.next
	mov	[g_gr_spec],rsi
	mov	r12,rsi
	mov	qword [g_gr_hn],0
	gk	'hostnames'
	call	gj_get
	jc	@f
	call	gj_first
	jc	@f
	mov	[g_gr_hn],rsi
@@:
	mov	rsi,r12
	gk	'parentRefs'
	call	gj_get
	jc	.next
	call	gj_first
	jc	.next
.parent:
	mov	r14,rsi
	; the parentRef, as written, for the route's status
	mov	eax,[g_gw_npr]
	cmp	eax,GW_MAXPR
	jae	.parent_next
	mov	[g_gw_pri],eax
	inc	dword [g_gw_npr]
	imul	rax,rax,GWPR_SIZE
	add	rax,[g_gw_base]
	add	rax,GW_T_PR
	mov	ecx,[g_gw_rti]
	mov	[rax+GWPR_ROUTE],ecx
	mov	dword [rax+GWPR_GWI],-1
	mov	dword [rax+GWPR_WHY],3
	mov	[rax+GWPR_RAW],rsi
	push	rax
	call	js_skip
	pop	rax
	jc	.parent_next
	sub	rsi,r14
	mov	[rax+GWPR_RAWLEN],esi
	mov	rsi,r14
	call	gw_parent
.parent_next:
	mov	rsi,r14
	call	gj_next
	jnc	.parent
.next:
	mov	rsi,rbx
	call	gj_next
	jnc	.route
.done:
	clc
	jmp	.out
.bad:
	stc
.out:
	pop	r14
	pop	r12
	pop	rbx
	ret

; rsi = a parentRef: the listeners it names, that take the route
gw_parent:
	push	rbx
	push	r12
	push	r14
	mov	r12,rsi
	; a Gateway (of the Gateway API's group)
	gk	'kind'
	call	gj_str
	jc	@f
	cmp	ecx,7
	jne	.out
	cmp	dword [rdi],'Gate'
	jne	.out
@@:
	mov	rsi,r12
	gk	'group'
	call	gj_str
	jc	@f
	cmp	ecx,25
	jne	.out
	cmp	dword [rdi],'gate'
	jne	.out
@@:
	mov	rsi,r12
	gk	'name'
	call	gj_str
	jc	.out
	mov	[g_gp_name],rdi
	mov	[g_gp_nlen],ecx
	xor	ebx,ebx
.listener:
	cmp	ebx,[g_gw_nl]
	jae	.out
	imul	r14,rbx,GWL_SIZE
	add	r14,[g_gw_base]
	add	r14,GW_T_L
	cmp	dword [r14+GWL_STATE],0
	jne	.other
	; its Gateway: the name, the namespace (the route's when not said)
	mov	rdi,[g_gp_name]
	mov	ecx,[g_gp_nlen]
	mov	rsi,[r14+GWL_GW]
	mov	edx,[r14+GWL_GWLEN]
	call	gw_same
	jne	.other
	mov	rsi,r12
	gk	'namespace'
	call	gj_str
	jnc	@f
	mov	rdi,[g_gr_ns]
	mov	ecx,[g_gr_nslen]
@@:
	mov	rsi,[r14+GWL_NS]
	mov	edx,[r14+GWL_NSLEN]
	call	gw_same
	jne	.other
	mov	eax,[r14+GWL_GWI]		; (it names our Gateway)
	call	gw_pr_of
	mov	[rax+GWPR_GWI],ecx
	; sectionName, port
	mov	rsi,r12
	gk	'sectionName'
	call	gj_str
	jc	@f
	mov	rsi,[r14+GWL_NAME]
	mov	edx,[r14+GWL_NAMELEN]
	call	gw_same
	jne	.other
@@:
	mov	rsi,r12
	gk	'port'
	call	gj_num
	jc	@f
	cmp	eax,[r14+GWL_PORT]
	jne	.other
@@:
	; the listener takes routes from here?
	cmp	dword [r14+GWL_ALL],0
	jne	.takes
	mov	rdi,[g_gr_ns]
	mov	ecx,[g_gr_nslen]
	mov	rsi,[r14+GWL_NS]
	mov	edx,[r14+GWL_NSLEN]
	call	gw_same
	je	.takes
	mov	edx,2				; NotAllowedByListeners
	call	gw_pr_why
	jmp	.other
.takes:
	mov	[g_gr_li],ebx
	mov	dword [g_gr_nhosts],0
	call	gw_attach
	mov	edx,1				; NoMatchingListenerHostname
	cmp	dword [g_gr_nhosts],0
	je	@f
	inc	dword [r14+GWL_ROUTES]
	xor	edx,edx				; attached
@@:
	call	gw_pr_why
.other:
	inc	ebx
	jmp	.listener
.out:
	pop	r14
	pop	r12
	pop	rbx
	ret

; eax = a Gateway: rax = the parentRef being read, ecx = that Gateway. Keeps rbx,
; rdx, rsi, rdi, r8-r15.
gw_pr_of:
	mov	ecx,eax
	mov	eax,[g_gw_pri]
	imul	rax,rax,GWPR_SIZE
	add	rax,[g_gw_base]
	add	rax,GW_T_PR
	ret

; edx = a reason: the parentRef being read keeps it when it is better (lower)
; than what it has. Keeps all but rax, rcx.
gw_pr_why:
	call	gw_pr_of
	cmp	edx,[rax+GWPR_WHY]
	jae	@f
	mov	[rax+GWPR_WHY],edx
@@:
	ret

; g_gr_li = a listener that takes the route: for each hostname both allow, its rules
gw_attach:
	push	rbx
	push	r12
	mov	eax,[g_gr_li]
	imul	r12,rax,GWL_SIZE
	add	r12,[g_gw_base]
	add	r12,GW_T_L
	mov	rsi,[g_gr_hn]
	test	rsi,rsi
	jnz	.hostnames
	mov	rax,[r12+GWL_HOST]		; none: the listener's (or none)
	mov	[g_gr_host],rax
	mov	eax,[r12+GWL_HOSTLEN]
	mov	[g_gr_hostlen],eax
	inc	dword [g_gr_nhosts]
	call	gw_rules
	jmp	.out
.hostnames:
	mov	rbx,rsi
	call	js_ws
	call	js_str
	jc	.next
	mov	r8,rdi
	mov	r9d,ecx
	mov	rcx,rdi
	mov	edx,r9d
	push	r8
	push	r9
	call	gw_host_ok
	pop	r9
	pop	r8
	jc	.next
	; the intersection with the listener's
	mov	rsi,r8
	mov	ecx,r9d
	mov	rdi,[r12+GWL_HOST]
	mov	edx,[r12+GWL_HOSTLEN]
	call	gw_hosts_meet			; rsi/ecx = it; CF none
	jc	.next
	mov	[g_gr_host],rsi
	mov	[g_gr_hostlen],ecx
	inc	dword [g_gr_nhosts]
	call	gw_rules
.next:
	mov	rsi,rbx
	call	gj_next
	mov	rbx,rsi
	jnc	.hostnames
.out:
	pop	r12
	pop	rbx
	ret

; rsi/ecx = a route's hostname, rdi/edx = a listener's (0: none): rsi/ecx = the
; one both allow (the more precise). CF when they do not meet.
gw_hosts_meet:
	test	edx,edx
	jz	.route				; no listener's: the route's
	cmp	ecx,edx
	jne	@f
	push	rsi
	push	rdi
	push	rcx
	repe	cmpsb
	pop	rcx
	pop	rdi
	pop	rsi
	je	.route
@@:
	; a wildcard of one covering the other
	push	rsi
	push	rcx
	push	rdi
	push	rdx
	call	gw_covers			; does rdi/edx (a pattern) cover rsi/ecx?
	pop	rdx
	pop	rdi
	pop	rcx
	pop	rsi
	jnc	.route				; the listener's covers the route's
	xchg	rsi,rdi
	xchg	ecx,edx
	push	rsi
	push	rcx
	push	rdi
	push	rdx
	call	gw_covers
	pop	rdx
	pop	rdi
	pop	rcx
	pop	rsi
	jnc	.listener			; (rsi/ecx is the route's now)
	stc
	ret
.listener:
	mov	rsi,rdi				; the listener's is the more precise
	mov	ecx,edx
.route:
	clc
	ret

; rdi/edx = a hostname (maybe *.s), rsi/ecx = another: CF clear when the first
; covers the second (the same, or it is *.s and the other ends in .s with more
; before). Keeps rbx, r12-r15.
gw_covers:
	test	edx,edx
	jz	.yes				; none: every one
	cmp	ecx,edx
	jne	@f
	push	rsi
	push	rdi
	push	rcx
	repe	cmpsb
	pop	rcx
	pop	rdi
	pop	rsi
	je	.yes
@@:
	cmp	edx,2
	jb	.no
	cmp	word [rdi],'*.'
	jne	.no
	; the other ends in .s (s = the pattern past its *), longer than it
	lea	eax,[rdx-1]			; ".s"
	cmp	ecx,eax
	jbe	.no
	lea	rsi,[rsi+rcx]
	sub	rsi,rax
	lea	rdi,[rdi+1]
	mov	ecx,eax
	repe	cmpsb
	jne	.no
.yes:
	clc
	ret
.no:
	stc
	ret

; the route (g_gr_spec), on listener g_gr_li, for host g_gr_host: its rules' entries
gw_rules:
	push	rbx
	push	r12
	mov	rsi,[g_gr_spec]
	gk	'rules'
	call	gj_get
	jc	.default_rule
	call	gj_first
	jc	.out
.rule:
	mov	rbx,rsi
	mov	[g_gr_rule],rsi
	gk	'matches'
	call	gj_get
	jc	.no_matches
	call	gj_first
	jc	.no_matches
.match:
	mov	r12,rsi
	call	gw_match
	mov	rsi,r12
	call	gj_next
	jnc	.match
	jmp	.next
.no_matches:
	xor	esi,esi				; (PathPrefix /)
	call	gw_match
.next:
	mov	rsi,rbx
	call	gj_next
	jnc	.rule
	jmp	.out
.default_rule:
	; (no rules: nothing to serve)
.out:
	pop	r12
	pop	rbx
	ret

; rsi = a match (0: the default, PathPrefix /): its entries
gw_match:
	push	rbx
	push	r12
	push	r14
	mov	r12,rsi
	sub	rsp,64				; [rsp]: path, [+8] len, [+16] type: 0 Exact 1 Prefix
	lea	rax,[str_gw_slash]
	mov	[rsp],rax
	mov	dword [rsp+8],1
	mov	dword [rsp+16],1
	mov	qword [rsp+24],0		; method
	mov	dword [rsp+32],0
	mov	qword [rsp+40],0		; headers
	mov	dword [rsp+48],0		; their number
	mov	qword [rsp+56],0		; query
	xor	r14d,r14d			; its number
	test	r12,r12
	jz	.add
	mov	rsi,r12
	gk	'path'
	call	gj_get
	jc	.method
	mov	rbx,rsi
	gk	'type'
	call	gj_str
	jc	.value
	cmp	ecx,5
	jne	@f
	cmp	dword [rdi],'Exac'
	jne	@f
	mov	dword [rsp+16],0
	jmp	.value
@@:
	cmp	ecx,10
	jne	.no				; (RegularExpression: not here)
	cmp	dword [rdi],'Path'
	jne	.no
.value:
	mov	rsi,rbx
	gk	'value'
	call	gj_str
	jc	.method
	mov	[rsp],rdi
	mov	[rsp+8],ecx
.method:
	mov	rsi,r12
	gk	'method'
	call	gj_str
	jc	.headers
	cmp	ecx,10
	ja	.no
	xor	eax,eax
@@:
	movzx	edx,byte [rdi+rax]
	sub	edx,'A'
	cmp	edx,25
	ja	.no
	inc	eax
	cmp	eax,ecx
	jb	@b
	mov	[rsp+24],rdi
	mov	[rsp+32],ecx
.headers:
	mov	rsi,r12
	gk	'headers'
	call	gj_get
	jc	.query
	call	gj_first
	jc	.query
	mov	[rsp+40],rsi
.header:
	mov	rbx,rsi
	call	gw_cond_ok			; CF: one okena cannot tell
	jc	.no
	inc	dword [rsp+48]
	mov	rsi,rbx
	call	gj_next
	jnc	.header
.query:
	mov	rsi,r12
	gk	'queryParams'
	call	gj_get
	jc	.add
	call	gj_first
	jc	.add
	mov	[rsp+56],rsi
.param:
	mov	rbx,rsi
	call	gw_cond_ok
	jc	.no
	cmp	eax,1
	je	.no				; (a regular expression: not here, for these)
	inc	r14d
	mov	rsi,rbx
	call	gj_next
	jnc	.param
.add:
	; the path
	mov	rcx,[rsp]
	mov	edx,[rsp+8]
	call	gw_path_ok
	jc	.no
	cmp	dword [rsp+16],0
	je	.exact
	; a prefix: no / at its end
	mov	ecx,[rsp+8]
@@:
	cmp	ecx,1
	jbe	@f
	mov	rax,[rsp]
	cmp	byte [rax+rcx-1],'/'
	jne	@f
	dec	ecx
	jmp	@b
@@:
	mov	[rsp+8],ecx
	cmp	ecx,1
	jne	.prefix
	; / : the route /*, with no prefix
	lea	rsi,[str_gw_all]
	mov	ecx,2
	call	gw_keep
	mov	r8,rdi
	mov	r9d,2
	mov	eax,2
	xor	r10d,r10d			; (the prefix: empty)
	call	.entry
	jmp	.no
.prefix:
	; /p, then /p/*
	mov	rsi,[rsp]
	mov	ecx,[rsp+8]
	mov	r8,rsi
	mov	r9d,ecx
	mov	eax,1
	mov	r10d,ecx
	call	.entry
	mov	rsi,[rsp]
	mov	ecx,[rsp+8]
	call	gw_keep
	mov	r8,rdi
	push	rcx
	lea	rsi,[str_gw_all]
	mov	ecx,2
	call	gw_keep
	pop	rcx
	lea	r9d,[rcx+2]
	mov	eax,2
	mov	r10d,ecx
	call	.entry
	jmp	.no
.exact:
	mov	r8,[rsp]
	mov	r9d,[rsp+8]
	xor	eax,eax
	xor	r10d,r10d
	call	.entry
.no:
	add	rsp,64
	pop	r14
	pop	r12
	pop	rbx
	ret
; eax = origin, r8/r9d = okena's path, r10d = the prefix's length (of [rsp+8+8])
.entry:
	mov	ecx,[g_gw_ne]
	cmp	ecx,GW_MAXE
	jae	.full
	inc	dword [g_gw_ne]
	imul	rcx,rcx,GWE_SIZE
	add	rcx,[g_gw_base]
	add	rcx,GW_T_E
	mov	[rcx+GWE_ORIGIN],eax
	mov	[rcx+GWE_OPATH],r8
	mov	[rcx+GWE_OPLEN],r9d
	mov	rax,[rsp+8]			; (the caller's frame: the path)
	mov	[rcx+GWE_PFX],rax
	mov	[rcx+GWE_PFXLEN],r10d
	mov	eax,[g_gr_li]
	imul	rax,rax,GWL_SIZE
	add	rax,[g_gw_base]
	mov	edx,[rax+GW_T_L+GWL_PORT]
	mov	[rcx+GWE_PORT],edx
	mov	edx,[rax+GW_T_L+GWL_PROTO]
	mov	[rcx+GWE_PROTO],edx
	mov	rax,[g_gr_host]
	mov	[rcx+GWE_HOST],rax
	mov	eax,[g_gr_hostlen]
	mov	[rcx+GWE_HOSTLEN],eax
	mov	rax,[rsp+8+24]
	mov	[rcx+GWE_METHOD],rax
	mov	eax,[rsp+8+32]
	mov	[rcx+GWE_MLEN],eax
	mov	rax,[rsp+8+40]
	mov	[rcx+GWE_HDRS],rax
	mov	eax,[rsp+8+48]
	mov	[rcx+GWE_NH],eax
	mov	rax,[rsp+8+56]
	mov	[rcx+GWE_QUERY],rax
	mov	[rcx+GWE_NQ],r14d
	mov	eax,[rsp+8+48]
	add	eax,r14d
	cmp	dword [rsp+8+32],0
	je	@f
	inc	eax
@@:
	mov	[rcx+GWE_NCOND],eax
	mov	eax,[g_gw_seq]
	inc	dword [g_gw_seq]
	mov	[rcx+GWE_SEQ],eax
	mov	rax,[g_gr_rule]
	mov	[rcx+GWE_RULE],rax
	mov	rax,[g_gr_ns]
	mov	[rcx+GWE_NS],rax
	mov	eax,[g_gr_nslen]
	mov	[rcx+GWE_NSLEN],eax
	mov	eax,[g_gw_rti]
	mov	[rcx+GWE_ROUTE],eax
.full:
	ret
cstring str_gw_slash, '/'
cstring str_gw_all, '/*'
; rsi = a header or query parameter match ({name, value, type}): CF when okena
; cannot tell it; eax = 1 when it is a regular expression. Keeps rbx, r12-r15.
gw_cond_ok:
	push	rsi
	gk	'name'
	call	gj_str
	jc	.no
	mov	edx,ecx
	mov	rcx,rdi
	call	gw_token_ok
	jc	.no
	mov	rsi,[rsp]
	gk	'value'
	call	gj_str
	jc	.no
	mov	edx,ecx
	mov	rcx,rdi
	call	gw_value_ok
	jc	.no
	xor	r10d,r10d
	mov	rsi,[rsp]
	gk	'type'
	call	gj_str
	jc	.yes				; Exact
	cmp	ecx,5
	jne	@f
	cmp	dword [rdi],'Exac'
	je	.yes
@@:
	cmp	ecx,17
	jne	.no
	cmp	dword [rdi],'Regu'
	jne	.no
	mov	r10d,1
.yes:
	mov	eax,r10d
	pop	rsi
	clc
	ret
.no:
	pop	rsi
	stc
	ret


; --------------------------------------------------------------- writing

; r15 = out: every port, then the pools
gw_emit:
	push	rbx
	push	r12
	go_lit	'# written by okena-gateway from the cluster'
	go_lit	"'s Gateways and HTTPRoutes: it is written over",10
	mov	dword [g_gw_port],0
.port:
	; the next port up
	mov	r8d,65536
	xor	ebx,ebx
	mov	r12d,-1
.find:
	cmp	ebx,[g_gw_nl]
	jae	.found
	imul	rax,rbx,GWL_SIZE
	add	rax,[g_gw_base]
	cmp	dword [rax+GW_T_L+GWL_STATE],0
	jne	@f
	mov	ecx,[rax+GW_T_L+GWL_PORT]
	cmp	ecx,[g_gw_port]
	jbe	@f
	cmp	ecx,r8d
	jae	@f
	mov	r8d,ecx
	mov	edx,[rax+GW_T_L+GWL_PROTO]	; (the first one's protocol is the port's)
	mov	r12d,edx
@@:
	inc	ebx
	jmp	.find
.found:
	cmp	r8d,65536
	je	.pools
	mov	[g_gw_port],r8d
	mov	[g_gw_proto],r12d
	call	gw_emit_port
	jmp	.port
.pools:
	call	gw_emit_pools
	pop	r12
	pop	rbx
	ret

; g_gw_port, g_gw_proto: the http block
gw_emit_port:
	push	rbx
	push	r12
	mov	r12,r15				; (taken back if it cannot be)
	go_lit	10,'http :'
	mov	eax,[g_gw_port]
	call	go_u
	go_lit	' {',10
	cmp	dword [g_gw_proto],2
	jne	@f
	call	gw_emit_tls
	jnc	@f
	mov	r15,r12				; no certificate to be had: not this port
	jmp	.out
@@:
	inc	dword [g_gw_nports]
	; its hosts: none, then each
	mov	dword [g_gw_nh],0
	xor	ebx,ebx
.host:
	cmp	ebx,[g_gw_ne]
	jae	.hosts
	imul	rax,rbx,GWE_SIZE
	add	rax,[g_gw_base]
	add	rax,GW_T_E
	mov	ecx,[rax+GWE_PORT]
	cmp	ecx,[g_gw_port]
	jne	.host_next
	mov	ecx,[rax+GWE_PROTO]
	cmp	ecx,[g_gw_proto]
	jne	.host_next
	mov	ecx,[rax+GWE_HOSTLEN]
	test	ecx,ecx
	jz	.host_next
	mov	rdi,[rax+GWE_HOST]
	call	gw_host_add
.host_next:
	inc	ebx
	jmp	.host
.hosts:
	mov	qword [g_gh_host],0
	mov	dword [g_gh_len],0
	mov	dword [g_gh_ind],4
	call	gw_emit_host
	xor	ebx,ebx
.each:
	cmp	ebx,[g_gw_nh]
	jae	.closed
	mov	rax,[g_gw_base]
	add	rax,GW_T_H
	mov	rdi,[rax+rbx*8+0]
	mov	ecx,[rax+rbx*8+GW_MAXH*8]
	mov	[g_gh_host],rdi
	mov	[g_gh_len],ecx
	mov	dword [g_gh_ind],8
	go_lit	10,'    host '
	mov	rsi,rdi
	call	go_q
	go_lit	' {',10
	call	gw_emit_host
	go_lit	'    }',10
	inc	ebx
	jmp	.each
.closed:
	go_lit	'}',10
.out:
	pop	r12
	pop	rbx
	ret

; rdi/ecx = a host: into the port's list, once
gw_host_add:
	mov	rax,[g_gw_base]
	add	rax,GW_T_H
	xor	edx,edx
.seen:
	cmp	edx,[g_gw_nh]
	jae	.new
	cmp	ecx,[rax+rdx*8+GW_MAXH*8]
	jne	.other
	push	rsi
	push	rdi
	push	rcx
	mov	rsi,[rax+rdx*8]
	repe	cmpsb
	pop	rcx
	pop	rdi
	pop	rsi
	je	.out
.other:
	inc	edx
	jmp	.seen
.new:
	cmp	edx,GW_MAXH
	jae	.out
	mov	[rax+rdx*8],rdi
	mov	[rax+rdx*8+GW_MAXH*8],ecx
	inc	dword [g_gw_nh]
.out:
	ret

; g_gh_host/len (0: none), g_gh_ind: the routes of that host on the port
gw_emit_host:
	push	rbx
	push	r12
	push	r14
	; the entries that cover it
	mov	dword [g_gw_nsel],0
	xor	ebx,ebx
.pick:
	cmp	ebx,[g_gw_ne]
	jae	.picked
	imul	r12,rbx,GWE_SIZE
	add	r12,[g_gw_base]
	add	r12,GW_T_E
	mov	eax,[r12+GWE_PORT]
	cmp	eax,[g_gw_port]
	jne	.skip
	mov	eax,[r12+GWE_PROTO]
	cmp	eax,[g_gw_proto]
	jne	.skip
	mov	rdi,[r12+GWE_HOST]
	mov	edx,[r12+GWE_HOSTLEN]
	mov	rsi,[g_gh_host]
	mov	ecx,[g_gh_len]
	test	ecx,ecx
	jnz	@f
	test	edx,edx				; (no host: only those of none)
	jnz	.skip
@@:
	call	gw_covers
	jc	.skip
	mov	eax,[g_gw_nsel]
	mov	rcx,[g_gw_base]
	mov	[rcx+GW_T_SEL+rax*4],ebx
	inc	dword [g_gw_nsel]
.skip:
	inc	ebx
	jmp	.pick
.picked:
	call	gw_sort
	; by path: a route each
	xor	ebx,ebx
	xor	r14d,r14d			; a /* was written
.group:
	cmp	ebx,[g_gw_nsel]
	jae	.groups
	mov	rax,[g_gw_base]
	mov	eax,[rax+GW_T_SEL+rbx*4]
	imul	r12,rax,GWE_SIZE
	add	r12,[g_gw_base]
	add	r12,GW_T_E
	cmp	dword [r12+GWE_OPLEN],2
	jne	@f
	mov	rax,[r12+GWE_OPATH]
	cmp	word [rax],'/*'
	jne	@f
	mov	r14d,1
@@:
	mov	ecx,[g_gh_ind]
	call	go_ind
	go_lit	'route '
	mov	rsi,[r12+GWE_OPATH]
	mov	ecx,[r12+GWE_OPLEN]
	call	go_bytes
	go_lit	' {',10
	inc	dword [g_gw_nroutes]
	push	r12
	xor	r12d,r12d			; its own was written
.in_group:
	cmp	ebx,[g_gw_nsel]
	jae	.group_end
	mov	rax,[g_gw_base]
	mov	eax,[rax+GW_T_SEL+rbx*4]
	imul	rax,rax,GWE_SIZE
	add	rax,[g_gw_base]
	add	rax,GW_T_E
	mov	rcx,[rsp]			; (the group's first)
	mov	rdi,[rcx+GWE_OPATH]
	mov	ecx,[rcx+GWE_OPLEN]
	mov	rsi,[rax+GWE_OPATH]
	mov	edx,[rax+GWE_OPLEN]
	call	gw_same
	jne	.group_end
	inc	ebx
	test	r12d,r12d
	jnz	.in_group			; (behind its own: never chosen)
	cmp	dword [rax+GWE_NCOND],0
	jne	.conditional
	mov	r12d,1
	mov	ecx,[g_gh_ind]
	add	ecx,4
	call	gw_actions
	jmp	.in_group
.conditional:
	mov	ecx,[g_gh_ind]
	add	ecx,4
	call	go_ind
	go_lit	'match'
	call	gw_conds
	go_lit	' {',10
	mov	ecx,[g_gh_ind]
	add	ecx,8
	call	gw_actions
	mov	ecx,[g_gh_ind]
	add	ecx,4
	call	go_ind
	go_lit	'}',10
	jmp	.in_group
.group_end:
	pop	rax
	test	r12d,r12d
	jnz	@f
	mov	ecx,[g_gh_ind]
	add	ecx,4
	call	go_ind
	go_lit	'respond 404',10
@@:
	mov	ecx,[g_gh_ind]
	call	go_ind
	go_lit	'}',10
	jmp	.group
.groups:
	test	r14d,r14d
	jnz	.out
	mov	ecx,[g_gh_ind]			; nothing for the rest: 404
	call	go_ind
	go_lit	'route /* {',10
	mov	ecx,[g_gh_ind]
	add	ecx,4
	call	go_ind
	go_lit	'respond 404',10
	mov	ecx,[g_gh_ind]
	call	go_ind
	go_lit	'}',10
.out:
	pop	r14
	pop	r12
	pop	rbx
	ret

; the picked entries (GW_T_SEL) in the order they are written: by path, then
; the more precise host, an Exact path first, more conditions, the earlier
gw_sort:
	push	rbx
	push	r12
	push	r14
	mov	r14,[g_gw_base]
	add	r14,GW_T_SEL
	mov	ebx,1
.outer:
	cmp	ebx,[g_gw_nsel]
	jae	.out
	mov	r12d,[r14+rbx*4]		; the one placed
	mov	ecx,ebx
.inner:
	test	ecx,ecx
	jz	.place
	mov	eax,[r14+rcx*4-4]
	push	rcx
	mov	edi,eax
	mov	esi,r12d
	call	gw_before			; CF: edi goes before esi
	pop	rcx
	jc	.place
	mov	eax,[r14+rcx*4-4]
	mov	[r14+rcx*4],eax
	dec	ecx
	jmp	.inner
.place:
	mov	[r14+rcx*4],r12d
	inc	ebx
	jmp	.outer
.out:
	pop	r14
	pop	r12
	pop	rbx
	ret

; edi, esi = entries: CF when edi goes first (or they are equal: it stays)
gw_before:
	push	rbx
	push	r12
	imul	rbx,rdi,GWE_SIZE
	add	rbx,[g_gw_base]
	add	rbx,GW_T_E
	imul	r12,rsi,GWE_SIZE
	add	r12,[g_gw_base]
	add	r12,GW_T_E
	; the path
	mov	rsi,[rbx+GWE_OPATH]
	mov	rdi,[r12+GWE_OPATH]
	mov	ecx,[rbx+GWE_OPLEN]
	mov	edx,[r12+GWE_OPLEN]
	cmp	ecx,edx
	jbe	@f
	mov	ecx,edx
@@:
	repe	cmpsb
	jb	.first
	ja	.second
	mov	eax,[rbx+GWE_OPLEN]
	cmp	eax,[r12+GWE_OPLEN]
	jb	.first
	ja	.second
	; the host's precision
	mov	rdi,rbx
	call	.rank
	mov	ecx,eax
	mov	rdi,r12
	call	.rank
	cmp	ecx,eax
	ja	.first
	jb	.second
	mov	eax,[rbx+GWE_ORIGIN]
	cmp	eax,[r12+GWE_ORIGIN]
	jb	.first
	ja	.second
	mov	eax,[rbx+GWE_NCOND]
	cmp	eax,[r12+GWE_NCOND]
	ja	.first
	jb	.second
	mov	eax,[rbx+GWE_SEQ]
	cmp	eax,[r12+GWE_SEQ]
	ja	.second
.first:
	stc
	jmp	.out
.second:
	clc
.out:
	pop	r12
	pop	rbx
	ret
; rdi = an entry: eax = its host's precision for the host written
.rank:
	mov	eax,[rdi+GWE_HOSTLEN]
	test	eax,eax
	jz	.r_none
	cmp	eax,[g_gh_len]
	jne	.r_wild
	push	rcx
	push	rsi
	push	rdi
	mov	rsi,[rdi+GWE_HOST]
	mov	rdi,[g_gh_host]
	mov	ecx,eax
	repe	cmpsb
	pop	rdi
	pop	rsi
	pop	rcx
	jne	.r_wild
	mov	eax,1 shl 20			; the host itself
	ret
.r_wild:
	add	eax,1000			; a wildcard: the longer the more precise
	ret
.r_none:
	ret

; rax = an entry: its conditions, each after a space
gw_conds:
	push	rbx
	push	r12
	mov	rbx,rax
	cmp	dword [rbx+GWE_MLEN],0
	je	@f
	go_lit	' method='
	mov	rsi,[rbx+GWE_METHOD]
	mov	ecx,[rbx+GWE_MLEN]
	call	go_bytes
@@:
	cmp	dword [rbx+GWE_NH],0
	je	.query
	mov	rsi,[rbx+GWE_HDRS]
	mov	r12d,[rbx+GWE_NH]
.header:
	push	rsi
	go_lit	' header:'
	call	gw_cond_out
	pop	rsi
	dec	r12d
	jz	.query
	call	gj_next
	jmp	.header
.query:
	cmp	dword [rbx+GWE_NQ],0
	je	.out
	mov	rsi,[rbx+GWE_QUERY]
	mov	r12d,[rbx+GWE_NQ]
.param:
	push	rsi
	go_lit	' query:'
	call	gw_cond_out
	pop	rsi
	dec	r12d
	jz	.out
	call	gj_next
	jmp	.param
.out:
	mov	rax,rbx
	pop	r12
	pop	rbx
	ret

; rsi = a {name, value, type} (checked): NAME="VALUE" (lower-case name; ~ before
; a regular expression)
gw_cond_out:
	push	rbx
	mov	rbx,rsi
	gk	'name'
	call	gj_str
	mov	rsi,rdi
.lower:
	test	ecx,ecx
	jz	.name_done
	mov	al,[rsi]
	lea	edx,[rax-'A']
	cmp	dl,25
	ja	@f
	or	al,0x20
@@:
	mov	[r15],al
	inc	r15
	inc	rsi
	dec	ecx
	jmp	.lower
.name_done:
	mov	byte [r15],'='
	inc	r15
	mov	rsi,rbx
	call	gw_cond_ok			; (eax: a regular expression)
	push	rax
	mov	rsi,rbx
	gk	'value'
	call	gj_str
	pop	rax
	mov	rsi,rdi
	test	eax,eax
	jz	.plain
	mov	word [r15],'"~'			; "~REGEX"
	add	r15,2
	call	go_qin
	mov	byte [r15],'"'
	inc	r15
	jmp	.out
.plain:
	call	go_q
.out:
	pop	rbx
	ret

; ------------------------------------------------------------ a rule's actions

; rax = an entry, ecx = its indent: what its rule does (filters, then where it goes)
gw_actions:
	push	rbx
	push	r12
	push	r14
	mov	rbx,rax
	mov	r14d,ecx
	mov	qword [g_ga_redirect],0
	mov	qword [g_ga_rewrite],0
	mov	qword [g_ga_mirror],0
	; the filters: one okena cannot do and the rule answers 500
	mov	rsi,[rbx+GWE_RULE]
	gk	'filters'
	call	gj_get
	jc	.filtered
	call	gj_first
	jc	.filtered
.scan:
	mov	r12,rsi
	gk	'type'
	call	gj_str
	jc	.unsupported
	cmp	ecx,21
	jne	@f
	cmp	dword [rdi],'Requ'
	jne	.unsupported
	cmp	dword [rdi+7],'Head'
	je	.scan_next			; RequestHeaderModifier
	jmp	.unsupported
@@:
	cmp	ecx,22
	jne	@f
	cmp	dword [rdi],'Resp'
	je	.scan_next			; ResponseHeaderModifier
	jmp	.unsupported
@@:
	cmp	ecx,15
	jne	@f
	cmp	dword [rdi+7],'Redi'
	jne	.unsupported
	cmp	qword [g_ga_redirect],0
	jne	.scan_next
	mov	rsi,r12
	gk	'requestRedirect'
	call	gj_get
	jc	.unsupported
	mov	[g_ga_redirect],rsi
	jmp	.scan_next
@@:
	cmp	ecx,10
	jne	@f
	cmp	dword [rdi],'URLR'
	jne	.unsupported
	cmp	qword [g_ga_rewrite],0
	jne	.scan_next
	mov	rsi,r12
	gk	'urlRewrite'
	call	gj_get
	jc	.unsupported
	mov	[g_ga_rewrite],rsi
	jmp	.scan_next
@@:
	cmp	ecx,13
	jne	.unsupported
	cmp	dword [rdi+7],'Mirr'
	jne	.unsupported
	cmp	qword [g_ga_mirror],0
	jne	.scan_next
	mov	rsi,r12
	gk	'requestMirror'
	call	gj_get
	jc	.unsupported
	mov	[g_ga_mirror],rsi
.scan_next:
	mov	rsi,r12
	call	gj_next
	jnc	.scan
.filtered:
	cmp	qword [g_ga_redirect],0
	je	@f
	call	gw_redirect
	jnc	.out
	jmp	.unsupported
@@:
	; the header modifiers
	mov	rsi,[rbx+GWE_RULE]
	gk	'filters'
	call	gj_get
	jc	.rewrite
	call	gj_first
	jc	.rewrite
.hdr:
	mov	r12,rsi
	gk	'requestHeaderModifier'
	call	gj_get
	jc	@f
	xor	edx,edx				; (the request's)
	call	gw_hdr_mod
	jmp	.hdr_next
@@:
	mov	rsi,r12
	gk	'responseHeaderModifier'
	call	gj_get
	jc	.hdr_next
	mov	edx,1
	call	gw_hdr_mod
.hdr_next:
	mov	rsi,r12
	call	gj_next
	jnc	.hdr
.rewrite:
	cmp	qword [g_ga_rewrite],0
	je	@f
	call	gw_rewrite
	jc	.unsupported
@@:
	cmp	qword [g_ga_mirror],0
	je	@f
	mov	rsi,[g_ga_mirror]
	gk	'backendRef'
	call	gj_get
	jc	@f
	call	gw_ref_pool			; eax = pool, -1 none
	cmp	eax,-1
	je	@f
	push	rax
	mov	ecx,r14d
	call	go_ind
	go_lit	'mirror pool '
	pop	rax
	call	gw_pool_name
	go_lit	' 100%',10
@@:
	call	gw_backends
	jmp	.out
.unsupported:
	mov	ecx,r14d
	call	go_ind
	go_lit	'respond 500',10
.out:
	pop	r14
	pop	r12
	pop	rbx
	ret

; rsi = a {set, add, remove} header modifier, edx = 0 the request's, 1 the
; answer's; r14d = indent: okena's `header` lines, those okena may write
gw_hdr_mod:
	push	rbx
	push	r12
	push	r13
	mov	r12,rsi
	mov	ebx,edx
	mov	rsi,r12
	gk	'set'
	call	gj_get
	jc	.set_done
	call	gj_first
	jc	.set_done
.set_each:
	push	rsi
	lea	rdx,[.w_set]
	call	gw_hdr_line
	pop	rsi
	call	gj_next
	jnc	.set_each
.set_done:
	mov	rsi,r12
	gk	'add'
	call	gj_get
	jc	.add_done
	call	gj_first
	jc	.add_done
.add_each:
	push	rsi
	lea	rdx,[.w_add]
	call	gw_hdr_line
	pop	rsi
	call	gj_next
	jnc	.add_each
.add_done:
	mov	rsi,r12
	gk	'remove'
	call	gj_get
	jc	.out
	call	gj_first
	jc	.out
.remove:
	push	rsi
	call	js_str
	jc	@f
	mov	rsi,rdi
	call	gw_hdr_name			; g_gw_tag/ecx, CF: not one okena may touch
	jc	@f
	push	rcx
	mov	ecx,r14d
	call	go_ind
	call	.prefix
	go_lit	'drop '
	pop	rcx
	lea	rsi,[g_gw_tag]
	call	go_bytes
	call	go_nl
@@:
	pop	rsi
	call	gj_next
	jnc	.remove
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret
.prefix:
	test	ebx,ebx
	jz	@f
	go_lit	'response '
@@:
	go_lit	'header '
	ret
; rsi = a {name, value}, rdx = 'set ' or 'add ': its line
gw_hdr_line:
	mov	[g_gh_op],rdx
	push	rsi
	gk	'name'
	call	gj_str
	pop	rsi
	jc	.no
	push	rsi
	mov	rsi,rdi
	call	gw_hdr_name
	pop	rsi
	jc	.no
	mov	[g_gh_nlen],ecx
	gk	'value'
	call	gj_str
	jc	.no
	push	rdi
	push	rcx
	mov	edx,ecx
	mov	rcx,rdi
	call	gw_value_ok
	pop	rcx
	pop	rdi
	jc	.no
	push	rdi
	push	rcx
	mov	ecx,r14d
	call	go_ind
	call	gw_hdr_mod.prefix
	mov	rsi,[g_gh_op]
	mov	ecx,4
	call	go_bytes
	mov	ecx,[g_gh_nlen]
	lea	rsi,[g_gw_tag]
	call	go_bytes
	mov	byte [r15],' '
	inc	r15
	pop	rcx
	pop	rsi
	call	go_q
	call	go_nl
.no:
	ret
gw_hdr_mod.w_set db 'set '
gw_hdr_mod.w_add db 'add '

; rsi/ecx = a header's name: lower-cased in g_gw_tag, ecx its length. CF when it
; is not a token, or is one okena writes itself.
gw_hdr_name:
	cmp	ecx,200
	ja	.no
	push	rcx
	push	rsi
	mov	edx,ecx
	mov	rcx,rsi
	call	gw_token_ok
	pop	rsi
	pop	rcx
	jc	.no
	lea	rdi,[g_gw_tag]
	push	rcx
@@:
	test	ecx,ecx
	jz	@f
	lodsb
	lea	edx,[rax-'A']
	cmp	dl,25
	ja	.keep
	or	al,0x20
.keep:
	stosb
	dec	ecx
	jmp	@b
@@:
	pop	rcx
	push	rcx
	lea	rdi,[g_gw_tag]
	mov	esi,ecx
	lea	rdx,[e_owned_headers]
	call	list_index
	pop	rcx
	test	eax,eax
	jns	.no
	clc
	ret
.no:
	stc
	ret

; ------------------------------------------------------------ redirects, rewrites

; g_ga_redirect, rbx = the entry, r14d = indent: `redirect CODE "TARGET"`. CF
; when it cannot be told.
gw_redirect:
	push	r12
	push	r13
	mov	r12,[g_ga_redirect]
	; its parts, checked, before anything is written
	mov	rsi,r12
	gk	'scheme'
	call	gj_str
	mov	qword [g_ga_scheme],0
	jc	@f
	cmp	ecx,4
	jne	.s5
	cmp	dword [rdi],'http'
	jne	.bad
	jmp	.s_ok
.s5:
	cmp	ecx,5
	jne	.bad
	cmp	dword [rdi],'http'
	jne	.bad
	cmp	byte [rdi+4],'s'
	jne	.bad
.s_ok:
	mov	[g_ga_scheme],rdi
	mov	[g_ga_slen],ecx
@@:
	mov	qword [g_ga_host],0
	mov	rsi,r12
	gk	'hostname'
	call	gj_str
	jc	@f
	mov	[g_ga_host],rdi
	mov	[g_ga_hlen],ecx
	mov	edx,ecx
	mov	rcx,rdi
	call	gw_sub_ok			; (a name, not a wildcard)
	jc	.bad
@@:
	mov	dword [g_ga_port],0
	mov	rsi,r12
	gk	'port'
	call	gj_num
	jc	@f
	test	eax,eax
	jz	.bad
	cmp	eax,65535
	ja	.bad
	mov	[g_ga_port],eax
@@:
	mov	dword [g_ga_code],302
	mov	rsi,r12
	gk	'statusCode'
	call	gj_num
	jc	@f
	cmp	eax,301
	je	.code
	cmp	eax,302
	je	.code
	cmp	eax,303
	je	.code
	cmp	eax,307
	je	.code
	cmp	eax,308
	jne	@f
.code:
	mov	[g_ga_code],eax
@@:
	mov	rsi,r12
	call	gw_path_mod			; g_ga_ptype (0 none, 1 full, 2 prefix), g_ga_pv
	jc	.bad
	; out
	mov	ecx,r14d
	call	go_ind
	go_lit	'redirect '
	mov	eax,[g_ga_code]
	call	go_u
	go_lit	' "'
	; scheme://host[:port], when one of them was said
	cmp	qword [g_ga_scheme],0
	jne	.absolute
	cmp	qword [g_ga_host],0
	jne	.absolute
	cmp	dword [g_ga_port],0
	je	.path
.absolute:
	xor	r12d,r12d			; 1: https
	cmp	qword [g_ga_scheme],0
	je	.listener_scheme
	cmp	dword [g_ga_slen],5
	jne	.scheme
	inc	r12d
	jmp	.scheme
.listener_scheme:
	cmp	dword [rbx+GWE_PROTO],2
	jne	.scheme
	inc	r12d
.scheme:
	go_lit	'http'
	test	r12d,r12d
	jz	@f
	go_lit	's'
@@:
	go_lit	'://'
	cmp	qword [g_ga_host],0
	je	.req_host
	mov	rsi,[g_ga_host]
	mov	ecx,[g_ga_hlen]
	call	go_bytes
	jmp	.port
.req_host:
	go_lit	'{host}'
.port:
	mov	eax,[g_ga_port]
	test	eax,eax
	jnz	.port_is
	cmp	qword [g_ga_scheme],0
	jne	.path				; a scheme said: its own port
	mov	eax,[rbx+GWE_PORT]		; else the listener's
.port_is:
	mov	ecx,80
	test	r12d,r12d
	jz	@f
	mov	ecx,443
@@:
	cmp	eax,ecx
	je	.path
	go_lit	':'
	call	go_u
.path:
	call	gw_path_out			; the path, as the rule wants it
	go_lit	'"',10
	clc
	jmp	.out
.bad:
	stc
.out:
	pop	r13
	pop	r12
	ret

; rsi = a filter's object with an optional path {type, replaceFullPath |
; replacePrefixMatch}: g_ga_ptype, g_ga_pv/g_ga_pvlen (no / at its end; empty for
; /). CF when it is not one okena can tell.
gw_path_mod:
	mov	dword [g_ga_ptype],0
	gk	'path'
	call	gj_get
	jc	.ok
	push	rsi
	gk	'type'
	call	gj_str
	pop	rsi
	jc	.bad
	cmp	ecx,15
	jne	.prefix
	gk	'replaceFullPath'
	mov	dword [g_ga_ptype],1
	jmp	.value
.prefix:
	cmp	ecx,18
	jne	.bad
	gk	'replacePrefixMatch'
	mov	dword [g_ga_ptype],2
.value:
	call	gj_str
	jc	.bad
	mov	[g_ga_pv],rdi
	push	rdi
	push	rcx
	mov	edx,ecx
	mov	rcx,rdi
	call	gw_path_ok
	pop	rcx
	pop	rdi
	jc	.bad
@@:
	cmp	ecx,1				; no / at its end
	jb	@f
	cmp	byte [rdi+rcx-1],'/'
	jne	@f
	dec	ecx
	jmp	@b
@@:
	mov	[g_ga_pvlen],ecx
.ok:
	clc
	ret
.bad:
	stc
	ret

; rbx = an entry: the path a redirect gives (g_ga_ptype, g_ga_pv), out
gw_path_out:
	cmp	dword [g_ga_ptype],1
	je	.full
	cmp	dword [g_ga_ptype],2
	je	.prefix
	; as asked: the route's own path, or its prefix and the rest
	cmp	dword [rbx+GWE_ORIGIN],2
	je	.rest
	mov	rsi,[rbx+GWE_OPATH]
	mov	ecx,[rbx+GWE_OPLEN]
	jmp	go_bytes
.rest:
	mov	rsi,[rbx+GWE_PFX]
	mov	ecx,[rbx+GWE_PFXLEN]
	call	go_bytes
	go_lit	'/{*}'
	ret
.full:
	mov	rsi,[g_ga_pv]
	mov	ecx,[g_ga_pvlen]
	test	ecx,ecx
	jz	.slash
	jmp	go_bytes
.prefix:
	mov	rsi,[g_ga_pv]
	mov	ecx,[g_ga_pvlen]
	call	go_bytes
	cmp	dword [rbx+GWE_ORIGIN],2
	je	.prefix_rest
	test	ecx,ecx
	jnz	.done
.slash:
	go_lit	'/'
.done:
	ret
.prefix_rest:
	go_lit	'/{*}'
	ret

; g_ga_rewrite, rbx = the entry, r14d = indent: `rewrite path FROM -> "TO"`.
; CF when it cannot be told.
gw_rewrite:
	mov	rsi,[g_ga_rewrite]
	call	gw_path_mod
	jc	.bad
	cmp	dword [g_ga_ptype],0
	je	.none				; (only a hostname: not here)
	mov	ecx,r14d
	call	go_ind
	go_lit	'rewrite path '
	cmp	dword [g_ga_ptype],2
	jne	.whole
	cmp	dword [rbx+GWE_ORIGIN],2
	jne	.whole
	; a prefix for a prefix: FROM/{*} -> TO/{*}
	mov	rsi,[rbx+GWE_PFX]
	mov	ecx,[rbx+GWE_PFXLEN]
	call	go_bytes
	go_lit	'/{*} -> "'
	call	gw_path_out
	go_lit	'"',10
	jmp	.none
.whole:
	; the whole path, whatever it was (a full path; a prefix's own path)
	go_lit	'"~^.*\$" -> "'
	mov	rsi,[g_ga_pv]
	mov	ecx,[g_ga_pvlen]
	call	go_bytes
	test	ecx,ecx
	jnz	@f
	go_lit	'/'
@@:
	go_lit	'"',10
.none:
	clc
	ret
.bad:
	stc
	ret

; ------------------------------------------------------------ backends

; rbx = the entry, r14d = indent: `to pool`, `split`, or `respond 500`
gw_backends:
	push	r12
	push	r13
	mov	dword [g_ga_nb],0
	mov	dword [g_ga_sum],0
	mov	rsi,[rbx+GWE_RULE]
	gk	'backendRefs'
	call	gj_get
	jc	.chosen
	call	gj_first
	jc	.chosen
.ref:
	mov	r12,rsi
	mov	eax,1
	gk	'weight'
	call	gj_num
	jnc	@f
	mov	eax,1
@@:
	test	eax,eax
	jz	.next				; (0: none of the traffic)
	cmp	eax,1000000
	ja	.next
	push	rax
	mov	rsi,r12
	call	gw_ref_pool
	pop	rcx
	cmp	eax,-1
	je	.next
	mov	edx,[g_ga_nb]
	cmp	edx,8
	jae	.next
	mov	[g_ga_bp+rdx*4],eax
	mov	[g_ga_bw+rdx*4],ecx
	add	[g_ga_sum],ecx
	inc	dword [g_ga_nb]
.next:
	mov	rsi,r12
	call	gj_next
	jnc	.ref
.chosen:
	mov	ecx,r14d
	call	go_ind
	cmp	dword [g_ga_nb],0
	jne	@f
	go_lit	'respond 500',10
	jmp	.out
@@:
	; the shares, in percent: what rounding leaves goes to the first
	xor	ecx,ecx
	xor	r8d,r8d				; their sum
.pct:
	cmp	ecx,[g_ga_nb]
	jae	.pcts
	mov	eax,[g_ga_bw+rcx*4]
	imul	eax,eax,100
	xor	edx,edx
	div	dword [g_ga_sum]
	mov	[g_ga_bw+rcx*4],eax
	add	r8d,eax
	inc	ecx
	jmp	.pct
.pcts:
	mov	eax,100
	sub	eax,r8d
	add	[g_ga_bw],eax
	; those left with none go
	xor	ecx,ecx
	xor	edx,edx
.keep:
	cmp	ecx,[g_ga_nb]
	jae	.kept
	mov	eax,[g_ga_bw+rcx*4]
	test	eax,eax
	jz	@f
	mov	[g_ga_bw+rdx*4],eax
	mov	eax,[g_ga_bp+rcx*4]
	mov	[g_ga_bp+rdx*4],eax
	inc	edx
@@:
	inc	ecx
	jmp	.keep
.kept:
	mov	[g_ga_nb],edx
	cmp	edx,1
	jne	.split
	go_lit	'to pool '
	mov	eax,[g_ga_bp]
	call	gw_pool_name
	call	go_nl
	jmp	.out
.split:
	go_lit	'split'
	xor	r12d,r12d
@@:
	cmp	r12d,[g_ga_nb]
	jae	@f
	go_lit	' '
	mov	eax,[g_ga_bp+r12*4]
	call	gw_pool_name
	go_lit	'='
	mov	eax,[g_ga_bw+r12*4]
	call	go_u
	go_lit	'%'
	inc	r12d
	jmp	@b
@@:
	call	go_nl
.out:
	pop	r13
	pop	r12
	ret

; rsi = a backendRef, rbx = the entry (its namespace): eax = its pool, -1 when
; it is not one okena can serve (another kind, another namespace, no port, no
; such Service)
gw_ref_pool:
	push	r12
	mov	r12,rsi
	gk	'group'
	call	gj_str
	jc	@f
	test	ecx,ecx
	jnz	.kind
@@:
	mov	rsi,r12
	gk	'kind'
	call	gj_str
	jc	@f
	cmp	ecx,7
	jne	.kind
	cmp	dword [rdi],'Serv'
	jne	.kind
@@:
	mov	rsi,r12
	gk	'namespace'
	call	gj_str
	jc	@f
	mov	rsi,[rbx+GWE_NS]
	mov	edx,[rbx+GWE_NSLEN]
	call	gw_same
	jne	.not_permitted			; (no ReferenceGrants here)
@@:
	mov	rsi,r12
	gk	'port'
	call	gj_num
	jc	.no
	test	eax,eax
	jz	.no
	cmp	eax,65535
	ja	.no
	push	rax
	mov	rsi,r12
	gk	'name'
	call	gj_str
	pop	r8
	jc	.no
	push	rdi
	push	rcx
	push	r8
	mov	edx,ecx
	mov	rcx,rdi
	call	gw_label_ok
	pop	r8
	pop	rcx
	pop	rdi
	jc	.no
	call	gw_pool
	cmp	eax,-1
	jne	.out
.no:
	mov	edx,GRF_NOTFOUND
	jmp	.why
.kind:
	mov	edx,GRF_KIND
	jmp	.why
.not_permitted:
	mov	edx,GRF_NOTPERMITTED
.why:
	mov	eax,[rbx+GWE_ROUTE]		; the route says why (the first reason)
	imul	rax,rax,GWR_SIZE
	add	rax,[g_gw_base]
	cmp	dword [rax+GW_T_R+GWR_REFS],0
	jne	@f
	mov	[rax+GW_T_R+GWR_REFS],edx
@@:
	mov	eax,-1
.out:
	pop	r12
	ret

; eax = a pool: its name, out
gw_pool_name:
	push	rbx
	imul	rbx,rax,GWP2_SIZE
	add	rbx,[g_gw_base]
	add	rbx,GW_T_P
	go_lit	'gw_'				; (labels have no _: no two alike)
	mov	rsi,[rbx+GWP2_NS]
	mov	ecx,[rbx+GWP2_NSLEN]
	call	go_bytes
	go_lit	'_'
	mov	rsi,[rbx+GWP2_SVC]
	mov	ecx,[rbx+GWP2_SVCLEN]
	call	go_bytes
	go_lit	'_'
	mov	eax,[rbx+GWP2_PORT]
	call	go_u
	pop	rbx
	ret

; rdi/ecx = a Service's name, r8d = its port, rbx = the entry (its namespace):
; eax = the pool, made the first time (the Service asked for its port's name),
; -1 when there is no such Service or port. g_gw_fail when it went unanswered.
gw_pool:
	push	r12
	push	r13
	push	r14
	mov	r14d,r8d
	xor	r12d,r12d
.find:
	cmp	r12d,[g_gw_np]
	jae	.new
	imul	rax,r12,GWP2_SIZE
	add	rax,[g_gw_base]
	add	rax,GW_T_P
	cmp	[rax+GWP2_PORT],r14d
	jne	.other
	mov	rsi,[rax+GWP2_SVC]
	mov	edx,[rax+GWP2_SVCLEN]
	call	gw_same
	jne	.other
	push	rdi
	push	rcx
	mov	rdi,[rax+GWP2_NS]
	mov	ecx,[rax+GWP2_NSLEN]
	mov	rsi,[rbx+GWE_NS]
	mov	edx,[rbx+GWE_NSLEN]
	call	gw_same
	pop	rcx
	pop	rdi
	jne	.other
	cmp	dword [rax+GWP2_STATE],1
	jne	.none
	mov	eax,r12d
	jmp	.out
.other:
	inc	r12d
	jmp	.find
.new:
	cmp	r12d,GW_MAXP
	jae	.none
	inc	dword [g_gw_np]
	mov	[g_gp_idx],r12d
	imul	r13,r12,GWP2_SIZE
	add	r13,[g_gw_base]
	add	r13,GW_T_P
	mov	rax,[rbx+GWE_NS]
	mov	[r13+GWP2_NS],rax
	mov	eax,[rbx+GWE_NSLEN]
	mov	[r13+GWP2_NSLEN],eax
	mov	[r13+GWP2_SVC],rdi
	mov	[r13+GWP2_SVCLEN],ecx
	mov	[r13+GWP2_PORT],r14d
	mov	dword [r13+GWP2_STATE],2
	mov	qword [r13+GWP2_PN],0
	mov	dword [r13+GWP2_PNLEN],0
	; GET /api/v1/namespaces/NS/services/NAME
	call	gw_req_begin
	cstring .p1, '/api/v1/namespaces/',0
	lea	rsi,[.p1]
	call	gw_req_cstr
	mov	rsi,[r13+GWP2_NS]
	mov	ecx,[r13+GWP2_NSLEN]
	call	gw_req_add
	cstring .p2, '/services/',0
	lea	rsi,[.p2]
	call	gw_req_cstr
	mov	rsi,[r13+GWP2_SVC]
	mov	ecx,[r13+GWP2_SVCLEN]
	call	gw_req_add
	lea	rsi,[str_gw_rv0]
	call	gw_req_cstr
	push	r15
	call	gw_get
	pop	r15
	jc	.fail
	cmp	eax,404
	je	.none
	cmp	eax,200
	jne	.fail
	; spec.ports: the one of this number, its name
	push	r13				; the slot
	lea	r13,[rsi+rcx]			; (this answer's end; the lists' comes back at .out)
	gk	'spec'
	call	gj_get
	jc	.no_port
	gk	'ports'
	call	gj_get
	jc	.no_port
	call	gj_first
	jc	.no_port
.port:
	mov	r12,rsi
	gk	'port'
	call	gj_num
	jc	.port_next
	cmp	eax,r14d
	jne	.port_next
	mov	rax,[rsp]
	mov	dword [rax+GWP2_STATE],1
	mov	rsi,r12
	gk	'name'
	call	gj_str
	jc	.no_port
	test	ecx,ecx
	jz	.no_port
	push	rdi
	push	rcx
	mov	edx,ecx
	mov	rcx,rdi
	call	gw_label_ok
	pop	rcx
	pop	rsi
	jc	.bad_name
	call	gw_keep				; (the answer goes: kept)
	mov	rax,[rsp]
	mov	[rax+GWP2_PN],rdi
	mov	[rax+GWP2_PNLEN],ecx
	jmp	.no_port
.bad_name:
	mov	rax,[rsp]
	mov	dword [rax+GWP2_STATE],2
	jmp	.no_port
.port_next:
	mov	rsi,r12
	call	gj_next
	jnc	.port
.no_port:
	pop	rax
	cmp	dword [rax+GWP2_STATE],1
	jne	.none
	mov	eax,[g_gp_idx]
	jmp	.out
.fail:
	mov	dword [g_gw_fail],1
.none:
	mov	eax,-1
.out:
	pop	r14
	pop	r13
	pop	r12
	ret
cstring str_gw_rv0, '?resourceVersion=0',0

; the pools served: `pool gw.NS.NAME.PORT { discover kubernetes ... }`
gw_emit_pools:
	push	rbx
	push	r12
	xor	ebx,ebx
.pool:
	cmp	ebx,[g_gw_np]
	jae	.out
	imul	r12,rbx,GWP2_SIZE
	add	r12,[g_gw_base]
	add	r12,GW_T_P
	cmp	dword [r12+GWP2_STATE],1
	jne	.next
	go_lit	10,'pool '
	mov	eax,ebx
	call	gw_pool_name
	go_lit	' {',10,'    discover kubernetes service='
	mov	rsi,[r12+GWP2_NS]
	mov	ecx,[r12+GWP2_NSLEN]
	call	go_bytes
	go_lit	'/'
	mov	rsi,[r12+GWP2_SVC]
	mov	ecx,[r12+GWP2_SVCLEN]
	call	go_bytes
	cmp	dword [r12+GWP2_PNLEN],0
	je	@f
	go_lit	' port='
	mov	rsi,[r12+GWP2_PN]
	mov	ecx,[r12+GWP2_PNLEN]
	call	go_bytes
@@:
	cmp	dword [g_plan_gw+GWP_APILEN],0
	je	@f
	go_lit	' api='
	mov	rsi,[g_plan_gw+GWP_API]
	mov	ecx,[g_plan_gw+GWP_APILEN]
	call	go_q
@@:
	cmp	dword [g_plan_gw+GWP_TOKENLEN],0
	je	@f
	go_lit	' token='
	mov	rsi,[g_plan_gw+GWP_TOKEN]
	mov	ecx,[g_plan_gw+GWP_TOKENLEN]
	call	go_q
@@:
	cmp	dword [g_plan_gw+GWP_CALEN],0
	je	@f
	go_lit	' ca='
	mov	rsi,[g_plan_gw+GWP_CA]
	mov	ecx,[g_plan_gw+GWP_CALEN]
	call	go_q
@@:
	cmp	dword [g_plan_gw+GWP_NAMELEN],0
	je	@f
	go_lit	' name='
	mov	rsi,[g_plan_gw+GWP_NAME]
	mov	ecx,[g_plan_gw+GWP_NAMELEN]
	call	go_q
@@:
	go_lit	10,'}',10
.next:
	inc	ebx
	jmp	.pool
.out:
	pop	r12
	pop	rbx
	ret

; ------------------------------------------------------------ TLS

; g_gw_port: the `tls` block of its HTTPS listeners, a certificate for each
; Secret they name (of their own namespace). CF when there is none.
gw_emit_tls:
	push	rbx
	push	r12
	push	r14
	go_lit	'    tls {',10
	mov	dword [g_gw_ncert],0
	xor	ebx,ebx
.listener:
	cmp	ebx,[g_gw_nl]
	jae	.done
	imul	r12,rbx,GWL_SIZE
	add	r12,[g_gw_base]
	add	r12,GW_T_L
	cmp	dword [r12+GWL_STATE],0
	jne	.next
	mov	eax,[r12+GWL_PORT]
	cmp	eax,[g_gw_port]
	jne	.next
	cmp	dword [r12+GWL_PROTO],2
	jne	.next
	mov	rsi,[r12+GWL_TLS]
	test	rsi,rsi
	jz	.next
	call	gj_first
	jc	.next
.ref:
	mov	r14,rsi
	call	gw_cert_ref			; eax = 1: it has its certificate
	or	[r12+GWL_CERTOK],eax
	mov	rsi,r14
	call	gj_next
	jnc	.ref
.next:
	inc	ebx
	jmp	.listener
.done:
	go_lit	'    }',10
	cmp	dword [g_gw_ncert],0
	jne	@f
	stc
	jmp	.out
@@:
	clc
.out:
	pop	r14
	pop	r12
	pop	rbx
	ret

; rsi = a certificateRef, r12 = its listener: the Secret's files, and its line
gw_cert_ref:
	push	rbx
	push	r13
	mov	rbx,rsi
	gk	'kind'
	call	gj_str
	jc	@f
	cmp	ecx,6
	jne	.no
	cmp	dword [rdi],'Secr'
	jne	.no
@@:
	mov	rsi,rbx
	gk	'group'
	call	gj_str
	jc	@f
	test	ecx,ecx
	jnz	.no
@@:
	mov	rsi,rbx
	gk	'namespace'
	call	gj_str
	jc	@f
	mov	rsi,[r12+GWL_NS]
	mov	edx,[r12+GWL_NSLEN]
	call	gw_same
	jne	.no
@@:
	mov	rsi,rbx
	gk	'name'
	call	gj_str
	jc	.no
	mov	[g_gc_name],rdi
	mov	[g_gc_nlen],ecx
	mov	edx,ecx
	mov	rcx,rdi
	call	gw_sub_ok
	jc	.no
	; written already for this port?
	xor	eax,eax
.seen:
	cmp	eax,[g_gw_ncert]
	jae	.fetch
	mov	rdi,[g_gc_seen+rax*8]
	mov	ecx,[g_gc_seenl+rax*4]
	mov	rsi,[g_gc_name]
	mov	edx,[g_gc_nlen]
	call	gw_same
	je	.had
	inc	eax
	jmp	.seen
.fetch:
	cmp	dword [g_gw_ncert],64
	jae	.no
	; GET the Secret
	call	gw_req_begin
	lea	rsi,[gw_pool.p1]
	call	gw_req_cstr
	mov	rsi,[r12+GWL_NS]
	mov	ecx,[r12+GWL_NSLEN]
	call	gw_req_add
	cstring .p2, '/secrets/',0
	lea	rsi,[.p2]
	call	gw_req_cstr
	mov	rsi,[g_gc_name]
	mov	ecx,[g_gc_nlen]
	call	gw_req_add
	lea	rsi,[str_gw_rv0]
	call	gw_req_cstr
	push	r15
	call	gw_get
	pop	r15
	jc	.fail
	cmp	eax,404
	je	.no
	cmp	eax,200
	jne	.fail
	lea	r13,[rsi+rcx]			; (this answer's end; the lists' comes back at .no)
	gk	'data'
	call	gj_get
	jc	.no
	push	rsi
	gk	'tls.crt'
	lea	r8,[str_gw_crt]
	call	gw_cert_file
	pop	rsi
	jc	.no
	gk	'tls.key'
	lea	r8,[str_gw_key]
	call	gw_cert_file
	jc	.no
	; the line
	mov	eax,[g_gw_ncert]
	mov	rcx,[g_gc_name]
	mov	[g_gc_seen+rax*8],rcx
	mov	ecx,[g_gc_nlen]
	mov	[g_gc_seenl+rax*4],ecx
	inc	dword [g_gw_ncert]
	go_lit	'        cert "'
	lea	r8,[str_gw_crt]
	call	gw_cert_path_out
	go_lit	'" key="'
	lea	r8,[str_gw_key]
	call	gw_cert_path_out
	go_lit	'"',10
.had:
	mov	eax,1
	jmp	.out
.fail:
	mov	dword [g_gw_fail],1
.no:
	xor	eax,eax
.out:
	pop	r13
	pop	rbx
	ret
cstring str_gw_crt, '.crt',0
cstring str_gw_key, '.key',0

; r12 = the listener, g_gc_name, r8 = '.crt' or '.key': DIR/certs/NS.NAME.ext, out
gw_cert_path_out:
	mov	rsi,[g_plan_gw+GWP_DIR]
	mov	ecx,[g_plan_gw+GWP_DIRLEN]
	call	go_bytes
	go_lit	'/certs/'
	mov	rsi,[r12+GWL_NS]
	mov	ecx,[r12+GWL_NSLEN]
	call	go_bytes
	go_lit	'.'
	mov	rsi,[g_gc_name]
	mov	ecx,[g_gc_nlen]
	call	go_bytes
	mov	rsi,r8
	mov	ecx,4
	jmp	go_bytes

; rsi = the Secret's data, rdi/edx = a key, r8 = the file's ending, r12 = the
; listener: its value decoded (PEM) into DIR/certs/NS.NAME.ext. CF when it is
; not there, not PEM, or cannot be written.
gw_cert_file:
	push	r8
	call	gj_str
	pop	r8
	jc	.bad
	cmp	ecx,(GW_FILE_CAP / 4) * 4 / 3
	ja	.bad
	push	r8
	mov	rdx,rcx
	mov	rsi,rdi
	mov	rdi,[g_gw_base]
	add	rdi,GW_FILE
	call	base64_decode
	pop	r8
	cmp	rax,-1
	je	.bad
	cmp	eax,11
	jb	.bad
	mov	rdi,[g_gw_base]
	cmp	dword [rdi+GW_FILE],'----'
	jne	.bad
	push	rax
	; the path
	lea	rdi,[g_gw_path]
	mov	rsi,[g_plan_gw+GWP_DIR]
	mov	ecx,[g_plan_gw+GWP_DIRLEN]
	rep	movsb
	mov	rax,'/certs/'
	mov	[rdi],rax
	add	rdi,7
	mov	rsi,[r12+GWL_NS]
	mov	ecx,[r12+GWL_NSLEN]
	rep	movsb
	mov	byte [rdi],'.'
	inc	rdi
	mov	rsi,[g_gc_name]
	mov	ecx,[g_gc_nlen]
	rep	movsb
	mov	eax,[r8]
	mov	[rdi],eax
	mov	byte [rdi+4],0
	pop	rdx
	mov	rsi,[g_gw_base]
	add	rsi,GW_FILE
	call	gw_write_changed
	ret
.bad:
	stc
	ret
