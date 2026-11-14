; `response rewrite`: what a backend says of itself, put the way the client
; sees it (nginx's proxy_redirect, proxy_cookie_domain, proxy_cookie_path).
;
;   response rewrite location FROM -> TO      Location / Content-Location
;                                             starting with FROM: TO instead
;   response rewrite location auto            an absolute URL naming the
;       backend (the pool's host, the server as written, or the client's
;       own Host on another scheme) becomes the client's scheme and Host;
;       the route's `rewrite path` is undone on its path
;   response rewrite cookie_domain FROM -> TO a Set-Cookie's Domain=FROM
;   response rewrite cookie_path FROM -> TO   a Set-Cookie's Path from FROM
;
; A route takes its own lines, then its host block's, then its listener's;
; the first that applies to a field is used. Fields that none changes are
; copied as they came.

LW_KIND		:= 0				; d: LWK_*
LW_FLEN		:= 4				; d
LW_FROM		:= 8				; q
LW_TO		:= 16				; q
LW_TLEN		:= 24				; d
LW_SIZE		:= 32
MAX_LRW		:= 16384
LWK_LOCATION	:= 1
LWK_AUTO	:= 2
LWK_CDOMAIN	:= 3
LWK_CPATH	:= 4
RW_MAX		:= 8192				; a rewritten value, at most (a value of 4 KiB and
						; two TOs of 1 KiB, a Host of 255: room)

bss
	align 8
	g_lrw:		rb LW_SIZE * MAX_LRW
	g_plan_lrw	dd ?
	g_rw_buf:	rb RW_MAX + 16
end bss

cstring hn_location_t, 'location',0
cstring hn_content_location_t, 'content-location',0
cstring hn_set_cookie_t, 'set-cookie',0

; ------------------------------------------------------------ compiling

; rdi = route node: its `response rewrite` lines, then its host block's,
; then its listener's, into g_lrw. Keeps rbx, r12-r15.
compile_resp_rewrites:
	push	rbx
	push	r12
	mov	r12,rdi
.node:
	test	r12,r12
	jz	.out
	cmp	qword [r12+N_DEF],0
	je	.out				; (the top)
	mov	rdi,r12				; its `response` lines, by the index
	lea	rdx,[dir_table + D_SIZE*DIR_RRESPONSE]
	call	kids_first			; (a listener's 20000 routes: not walked)
	mov	rbx,rax
.kid:
	test	rbx,rbx
	jz	.up
	mov	rax,[rbx+N_ARGS]
	mov	rcx,[rax+A_VAL]
	cmp	byte [rcx],'r'
	jne	.next				; (response header ...)
	mov	ecx,[g_plan_lrw]
	cmp	ecx,MAX_LRW
	jae	.next				; (checked: a plan this large is not made)
	inc	dword [g_plan_lrw]
	imul	r8,rcx,LW_SIZE
	lea	r8,[g_lrw+r8]
	mov	rcx,[rax+A_SIZE+A_VAL]		; location, cookie_domain, cookie_path
	mov	edx,LWK_LOCATION
	cmp	byte [rcx],'l'
	je	.kind
	mov	edx,LWK_CPATH
	cmp	byte [rcx+7],'p'		; cookie_path
	je	.kind
	mov	edx,LWK_CDOMAIN
.kind:
	mov	[r8+LW_KIND],edx
	cmp	dword [rbx+N_ARGC],3
	jne	.from_to
	mov	dword [r8+LW_KIND],LWK_AUTO	; location auto
	jmp	.next
.from_to:
	mov	rcx,[rax+2*A_SIZE+A_VAL]
	mov	[r8+LW_FROM],rcx
	mov	ecx,[rax+2*A_SIZE+A_VLEN]
	mov	[r8+LW_FLEN],ecx
	mov	rcx,[rax+4*A_SIZE+A_VAL]
	mov	[r8+LW_TO],rcx
	mov	ecx,[rax+4*A_SIZE+A_VLEN]
	mov	[r8+LW_TLEN],ecx
.next:
	call	kids_next
	mov	rbx,rax
	jmp	.kid
.up:
	mov	r12,[r12+N_PARENT]
	jmp	.node
.out:
	pop	r12
	pop	rbx
	ret

; ------------------------------------------------------------ requests

; ebx = session, r15 = record, g_hm = the request, H_ACT its route: when the
; route rewrites locations, the client's Host is kept where the response can
; read it (the access log's copy: HB_LTEXT_H). Keeps all but rax, rcx, rsi.
resp_rewrite_keep_host:
	mov	eax,[r15+H_ACT]
	test	eax,eax
	jz	.out
	dec	eax
	imul	rax,rax,RA_SIZE
	cmp	dword [g_acts+rax+RA_WRN],0
	je	.out
	cmp	dword [r15+H_LHLEN],0
	jne	.out				; (the access log kept it already)
	mov	eax,[g_hm+HM_HOST]
	cmp	eax,-1
	je	.out
	push	rdi
	imul	rax,rax,HF_SIZE
	lea	rax,[g_hm+HM_HDRS+rax]
	mov	rsi,[rax+HF_VALUE]
	mov	ecx,[rax+HF_VLEN]
	cmp	ecx,H_LTEXT_H_CAP
	jbe	@f
	mov	ecx,H_LTEXT_H_CAP
@@:
	mov	[r15+H_LHLEN],ecx
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_LTEXT_H]
	rep	movsb
	pop	rdi
.out:
	ret

; ------------------------------------------------------------ responses

; r14 = a field of the response, rdi = where its line goes (r13 the room's
; end), rcx = the session, r15 = record, its route's RA_WRN > 0: a Location,
; Content-Location or Set-Cookie some line rewrites is written, rewritten,
; rdi past it. CF: not one of those, or nothing applied (rdi as it was).
; Keeps rbx, r12-r15.
resp_rewrite_field:
	push	rbx
	push	r12
	push	rbp
	mov	rbp,rcx				; the session
	mov	r12,rdi
	cmp	dword [r14+HF_VLEN],4096
	ja	.no
	mov	eax,[r14+HF_NLEN]		; room for the longest it can become
	add	eax,RW_MAX + 4
	lea	rax,[rdi+rax]
	cmp	rax,r13
	ja	.no
	mov	rdi,r14
	lea	rsi,[hn_location_t]
	call	hf_is
	je	.location
	mov	rdi,r14
	lea	rsi,[hn_content_location_t]
	call	hf_is
	je	.location
	mov	rdi,r14
	lea	rsi,[hn_set_cookie_t]
	call	hf_is
	je	.cookie
.no:
	mov	rdi,r12
	stc
	jmp	.out
.location:
	call	rw_location			; g_rw_buf/eax, CF none applied
	jc	.no
	jmp	.emit
.cookie:
	call	rw_cookie
	jc	.no
.emit:
	; name: the new value
	mov	ebx,eax
	mov	rdi,r12
	mov	rsi,[r14+HF_NAME]
	mov	ecx,[r14+HF_NLEN]
	rep	movsb
	mov	word [rdi],': '
	add	rdi,2
	lea	rsi,[g_rw_buf]
	mov	ecx,ebx
	rep	movsb
	mov	word [rdi],0x0A0D
	add	rdi,2
	clc
.out:
	pop	rbp
	pop	r12
	pop	rbx
	ret

; rbp = session, r14 = a Location field: its value rewritten into g_rw_buf,
; eax = its length. CF when no line applies.
rw_location:
	push	r13
	call	rw_lines			; r8 = first line, r9d = how many
	mov	rsi,[r14+HF_VALUE]
	mov	ecx,[r14+HF_VLEN]
.line:
	test	r9d,r9d
	jz	.none
	dec	r9d
	mov	eax,[r8+LW_KIND]
	cmp	eax,LWK_AUTO
	je	.auto
	cmp	eax,LWK_LOCATION
	jne	.next
	; FROM -> TO, a prefix
	mov	edx,[r8+LW_FLEN]
	cmp	ecx,edx
	jb	.next
	push	rsi
	push	rcx
	mov	rdi,[r8+LW_FROM]
	mov	ecx,edx
	repe	cmpsb
	pop	rcx
	pop	rsi
	jne	.next
	lea	rdi,[g_rw_buf]
	push	rsi
	push	rcx
	mov	rsi,[r8+LW_TO]
	mov	ecx,[r8+LW_TLEN]
	rep	movsb
	pop	rcx
	pop	rsi
	add	rsi,rdx				; the rest after FROM
	sub	ecx,edx
	rep	movsb
	jmp	.done
.auto:
	call	rw_auto
	jnc	.done
.next:
	add	r8,LW_SIZE
	jmp	.line
.done:
	lea	rax,[g_rw_buf]
	sub	rdi,rax
	mov	eax,edi
	clc
	pop	r13
	ret
.none:
	stc
	pop	r13
	ret

; rbp = session: r8 = its route's first rewrite line, r9d = how many
rw_lines:
	mov	eax,[r15+H_ACT]
	dec	eax
	imul	rax,rax,RA_SIZE
	mov	r9d,[g_acts+rax+RA_WRN]
	mov	r8d,[g_acts+rax+RA_WRFIRST]
	imul	r8,r8,LW_SIZE
	lea	r8,[g_lrw+r8]
	ret

; rsi/ecx = a Location's value, rbp = session: rdi past what `auto` makes of
; it in g_rw_buf; CF when it changes nothing. Keeps rsi, rcx, r8, r9.
rw_auto:
	push	rsi
	push	rcx
	push	r8
	push	r9
	push	r12
	push	r13
	mov	r12,rsi
	mov	r13d,ecx
	lea	rdi,[g_rw_buf]
	xor	r11d,r11d			; changed
	; an absolute URL? its authority the backend's?
	mov	eax,7
	cmp	r13d,7
	jb	.path
	mov	rdx,[r12]
	mov	r10,0x00FFFFFFFFFFFFFF
	and	rdx,r10
	mov	r10,'http://'
	cmp	rdx,r10
	je	.authority
	cmp	r13d,8
	jb	.path
	mov	rdx,'https://'
	cmp	[r12],rdx
	jne	.path
	mov	eax,8
.authority:
	lea	rsi,[r12+rax]			; the authority, to / ? # or the end
	mov	ecx,r13d
	sub	ecx,eax
	xor	edx,edx
@@:
	cmp	edx,ecx
	jae	@f
	mov	r10b,[rsi+rdx]
	cmp	r10b,'/'
	je	@f
	cmp	r10b,'?'
	je	@f
	cmp	r10b,'#'
	je	@f
	inc	edx
	jmp	@b
@@:
	push	rax
	call	rw_is_backend			; rsi/edx: CF when not the backend's
	pop	rax
	jc	.path				; someone else's URL: as it is
	; the client's scheme and Host instead
	mov	r11d,1
	add	eax,edx				; past scheme and authority
	add	r12,rax
	sub	r13d,eax
	mov	dword [rdi],'http'
	add	rdi,4
	call	rw_client_tls
	jnc	@f
	mov	byte [rdi],'s'
	inc	rdi
@@:
	mov	dword [rdi],'://'
	add	rdi,3
	mov	rsi,[r15+H_BUF]
	lea	rsi,[rsi+HB_LTEXT_H]
	mov	ecx,[r15+H_LHLEN]
	rep	movsb
.path:
	; the route's rewrite path, undone: TO's prefix back to FROM's
	mov	eax,[r15+H_ACT]
	dec	eax
	imul	rax,rax,RA_SIZE
	lea	r10,[g_acts+rax]
	cmp	qword [r10+RA_WFROM],0
	je	.rest
	cmp	dword [r10+RA_WRX],0
	jne	.rest				; (a regex: not undone)
	mov	rsi,[r10+RA_WTO]
	mov	edx,[r10+RA_WTLEN]
	cmp	edx,3
	jb	@f
	cmp	word [rsi+rdx-3],'{*'
	jne	@f
	sub	edx,3				; its prefix
@@:
	cmp	r13d,edx
	jb	.rest
	push	rdi
	mov	rdi,r12
	mov	ecx,edx
	repe	cmpsb
	pop	rdi
	jne	.rest
	cmp	edx,1				; ("/" alone: every path; FROM goes first)
	mov	r11d,1
	add	r12,rdx
	sub	r13d,edx
	mov	rsi,[r10+RA_WFROM]
	mov	ecx,[r10+RA_WFLEN]
	rep	movsb
	cmp	byte [rdi-1],'/'		; (FROM "/v1/" and a rest "/x": one slash)
	jne	.rest
	test	r13d,r13d
	jz	.rest
	cmp	byte [r12],'/'
	jne	.rest
	dec	rdi
.rest:
	test	r11d,r11d
	jz	.same
	mov	rsi,r12
	mov	ecx,r13d
	rep	movsb
	clc
	jmp	.out
.same:
	stc
.out:
	pop	r13
	pop	r12
	pop	r9
	pop	r8
	pop	rcx
	pop	rsi
	ret

; rsi/edx = an authority from a Location, rbp = session: CF unless it is the
; backend's: the pool's host, the server as written, or the client's Host
; (an app behind TLS here that writes http://). Keeps rsi, rdx, rdi, r8-r13.
rw_is_backend:
	push	rcx
	mov	rax,rbp
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	push	rax
	mov	ecx,[rax+S_POOL]
	cmp	ecx,-1
	je	.server
	imul	rcx,rcx,PL_SIZE
	mov	rax,[g_pools+rcx+PL_HOSTN]
	mov	ecx,[g_pools+rcx+PL_HOSTL]
	call	.same
	je	.yes
.server:
	mov	rax,[rsp]
	mov	ecx,[rax+S_SERVER]
	cmp	ecx,NIL
	je	.client
	imul	rcx,rcx,SV_SIZE
	mov	rax,[g_servers+rcx+SV_TEXT]
	mov	ecx,[g_servers+rcx+SV_TLEN]
	call	.same
	je	.yes
.client:
	mov	rax,[r15+H_BUF]
	lea	rax,[rax+HB_LTEXT_H]
	mov	ecx,[r15+H_LHLEN]
	call	.same
	je	.yes
	add	rsp,8
	pop	rcx
	stc
	ret
.yes:
	add	rsp,8
	pop	rcx
	clc
	ret
; rax/ecx = a name (case aside): ZF when it is rsi/edx
.same:
	test	ecx,ecx
	jz	.differs
	cmp	ecx,edx
	jne	.differs
	push	rdi
	push	rsi
	push	rdx
	mov	rdi,rax
	call	mem_eq_nocase
	pop	rdx
	pop	rsi
	pop	rdi
	test	eax,eax
	jz	.differs
	cmp	eax,eax				; (ZF)
	ret
.differs:
	or	eax,1				; (NZ)
	ret

; rbp = session: CF when the client came over TLS (the scheme it uses)
rw_client_tls:
	push	rbx
	mov	ebx,ebp
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_H3S	; HTTP/3: always TLS
	jnz	.tls
	call	http_tls_cred
	test	rax,rax
	jnz	.tls
	pop	rbx
	clc
	ret
.tls:
	pop	rbx
	stc
	ret

; rbp = session, r14 = a Set-Cookie field: its Domain= and Path= rewritten
; into g_rw_buf, eax = the length. CF when no line applies.
rw_cookie:
	push	r12
	push	r13
	mov	r12,[r14+HF_VALUE]
	mov	r13d,[r14+HF_VLEN]
	lea	r10,[r12+r13]			; its end
	lea	rdi,[g_rw_buf]
	xor	r11d,r11d			; changed
.scan:
	; up to the next ';' as it is
	mov	rsi,r12
@@:
	cmp	r12,r10
	jae	.copy_tail
	cmp	byte [r12],';'
	je	@f
	inc	r12
	jmp	@b
@@:
	inc	r12				; past ';'
	mov	rcx,r12
	sub	rcx,rsi
	rep	movsb
	; spaces, then an attribute's name
	mov	rsi,r12
@@:
	cmp	r12,r10
	jae	.copy_tail
	cmp	byte [r12],' '
	jne	@f
	inc	r12
	jmp	@b
@@:
	mov	rcx,r12
	sub	rcx,rsi
	rep	movsb
	mov	rax,r10
	sub	rax,r12
	cmp	rax,7
	jb	.path_attr
	mov	eax,[r12]
	or	eax,0x20202020
	cmp	eax,'doma'
	jne	.path_attr
	mov	ax,[r12+4]
	or	ax,0x2020
	cmp	ax,'in'
	jne	.path_attr
	cmp	byte [r12+6],'='
	jne	.path_attr
	mov	edx,LWK_CDOMAIN
	mov	ecx,7
	jmp	.attr
.path_attr:
	mov	rax,r10
	sub	rax,r12
	cmp	rax,5
	jb	.scan
	mov	eax,[r12]
	or	eax,0x20202020
	cmp	eax,'path'
	jne	.scan
	cmp	byte [r12+4],'='
	jne	.scan
	mov	edx,LWK_CPATH
	mov	ecx,5
.attr:
	; "domain=" / "path=" as written, then its value through the lines
	mov	rsi,r12
	rep	movsb
	mov	r12,rsi
	mov	rsi,r12				; the value, to ';' or the end
	xor	ecx,ecx
@@:
	lea	rax,[r12+rcx]
	cmp	rax,r10
	jae	@f
	cmp	byte [r12+rcx],';'
	je	@f
	inc	ecx
	jmp	@b
@@:
	call	rw_attr				; edx = kind, rsi/ecx = value: rdi on
	add	r12,rcx
	jmp	.scan
.copy_tail:
	mov	rcx,r10
	sub	rcx,rsi
	rep	movsb
	test	r11d,r11d
	jz	.same
	lea	rax,[g_rw_buf]
	sub	rdi,rax
	mov	eax,edi
	clc
	jmp	.out
.same:
	stc
.out:
	pop	r13
	pop	r12
	ret

; edx = LWK_CDOMAIN or LWK_CPATH, rsi/ecx = the attribute's value, rdi = out:
; the first line of that kind that applies writes its TO (and, for a path,
; the rest), else the value as it is. r11d = 1 when rewritten. Keeps rbx,
; rcx, r10, r12.
rw_attr:
	push	rbx
	push	rcx
	push	r12
	push	r13
	mov	r12,rsi
	mov	r13d,ecx
	call	rw_lines
.line:
	test	r9d,r9d
	jz	.as_is
	dec	r9d
	cmp	[r8+LW_KIND],edx
	jne	.next
	mov	eax,[r8+LW_FLEN]
	cmp	edx,LWK_CDOMAIN
	jne	.prefix
	; a domain: the same name, a leading dot either side aside
	mov	rsi,r12
	mov	ecx,r13d
	test	ecx,ecx
	jz	.next
	cmp	byte [rsi],'.'
	jne	@f
	inc	rsi
	dec	ecx
@@:
	mov	rax,[r8+LW_FROM]
	mov	ebx,[r8+LW_FLEN]
	test	ebx,ebx
	jz	.next
	cmp	byte [rax],'.'
	jne	@f
	inc	rax
	dec	ebx
@@:
	cmp	ecx,ebx
	jne	.next
	push	rdi
	push	rdx
	push	r8				; (mem_eq_nocase uses r8)
	mov	rdi,rax
	mov	edx,ecx
	call	mem_eq_nocase
	pop	r8
	pop	rdx
	pop	rdi
	test	eax,eax
	jz	.next
	mov	rsi,[r8+LW_TO]
	mov	ecx,[r8+LW_TLEN]
	rep	movsb
	mov	r11d,1
	jmp	.out
.prefix:
	cmp	r13d,eax
	jb	.next
	push	rdi
	mov	rsi,r12
	mov	rdi,[r8+LW_FROM]
	mov	ecx,eax
	repe	cmpsb
	pop	rdi
	jne	.next
	mov	rsi,[r8+LW_TO]
	mov	ecx,[r8+LW_TLEN]
	rep	movsb
	mov	rsi,r12
	add	rsi,rax
	mov	ecx,r13d
	sub	ecx,eax
	rep	movsb
	mov	r11d,1
	jmp	.out
.next:
	add	r8,LW_SIZE
	jmp	.line
.as_is:
	mov	rsi,r12
	mov	ecx,r13d
	rep	movsb
.out:
	pop	r13
	pop	r12
	pop	rcx
	pop	rbx
	ret
