; CORS on a route: `cors origins=... methods=... headers=... expose=...
; max_age=... credentials`.
;
; A preflight (OPTIONS with Origin and Access-Control-Request-Method) is
; answered here: the backend is not asked and no rate limit is spent. For a
; request, the Origin that was let in is kept in the session's buffers, since
; g_hm holds the response by the time its head is written, and every answer
; goes out with the headers: the backend's, a 429, okena's own errors. Without
; them a script sees an opaque failure, not the status. Headers of that family
; from the backend are dropped, so there is one answer to the question.
;
; An origin is matched whole, as the Fetch standard says: scheme, host, port. An
; entry may have one `*` where a host's labels go (`https://*.example.com`),
; which only matches letters, digits, `-` and `.`. `*` alone is any origin, and
; cannot go with credentials: the schema of the web forbids it for good reason.
; Unless any origin is taken the answer depends on Origin, so it says Vary.

CO_ORIG		:= 0				; q: the list, comma separated
CO_METH		:= 8				; q
CO_HDRS		:= 16				; q
CO_EXP		:= 24				; q
CO_OLEN		:= 32				; d
CO_MLEN		:= 36				; d
CO_HLEN		:= 40				; d
CO_ELEN		:= 44				; d
CO_AGE		:= 48				; d: seconds, 0 not said
CO_CRED		:= 52				; d
CO_ANY		:= 56				; d: origins=*
CO_SIZE		:= 64
MAX_CORS	:= 65536
CORS_ORIGIN_MAX	:= 256

; g_acts + eax - 1 = an action: rsi = its cors entry, ZF when it has none.
; Keeps all but rax, rsi.
macro cors_of_h
	local done
	xor	esi,esi
	mov	eax,[r15+H_ACT]
	test	eax,eax
	jz	done
	dec	eax
	imul	rax,rax,RA_SIZE
	mov	eax,[g_acts+rax+RA_CORS]
	test	eax,eax
	jz	done
	dec	eax
	imul	rax,rax,CO_SIZE
	lea	rsi,[g_cors+rax]
done:
	test	rsi,rsi
end macro

; rdi = an origin, esi = its length, r8 = one entry, r9d = its length: ZF on a
; match. Keeps rdi, esi, r8, r9.
cors_entry:
	xor	eax,eax
.star:
	cmp	eax,r9d
	jae	.whole
	cmp	byte [r8+rax],'*'
	je	.wild
	inc	eax
	jmp	.star
.whole:
	cmp	esi,r9d
	jne	.no
	xor	eax,eax
.byte:
	cmp	eax,esi
	jae	.yes
	mov	cl,[rdi+rax]
	cmp	cl,[r8+rax]
	jne	.no
	inc	eax
	jmp	.byte
.wild:
	; eax = where the star is: before it, after it, and between them a host
	lea	edx,[r9-1]			; the entry without the star
	cmp	esi,edx
	jbe	.no				; (at least one byte for it)
	xor	ecx,ecx
.head:
	cmp	ecx,eax
	jae	.head_ok
	mov	dl,[rdi+rcx]
	cmp	dl,[r8+rcx]
	jne	.no
	inc	ecx
	jmp	.head
.head_ok:
	; the tail, from the end
	mov	r10d,r9d
	sub	r10d,eax
	dec	r10d				; its length
	mov	r11d,esi
	sub	r11d,r10d			; where it starts in the origin
	lea	edx,[rax+1]
	xor	ecx,ecx
.tail:
	cmp	ecx,r10d
	jae	.tail_ok
	push	rax
	lea	eax,[r11+rcx]
	mov	al,[rdi+rax]
	push	rbx
	lea	ebx,[rdx+rcx]
	cmp	al,[r8+rbx]
	pop	rbx
	pop	rax
	jne	.no
	inc	ecx
	jmp	.tail
.tail_ok:
	; between them: host characters only
	mov	ecx,eax
.middle:
	cmp	ecx,r11d
	jae	.yes
	movzx	edx,byte [rdi+rcx]
	inc	ecx
	cmp	dl,'-'
	je	.middle
	cmp	dl,'.'
	je	.middle
	lea	eax,[rdx-'0']
	cmp	eax,9
	jbe	.middle
	or	dl,0x20
	lea	eax,[rdx-'a']
	cmp	eax,25
	jbe	.middle
.no:
	or	eax,1				; (ZF clear)
	ret
.yes:
	xor	eax,eax
	ret

; rdi = an origin, esi = its length, r12 = a cors entry: ZF when it is let in
cors_allowed:
	cmp	dword [r12+CO_ANY],0
	jne	.yes
	push	r13
	push	r14
	mov	r13,[r12+CO_ORIG]
	mov	r14d,[r12+CO_OLEN]
.next:
	test	r14d,r14d
	jz	.none
	xor	r9d,r9d
.end:
	cmp	r9d,r14d
	jae	.have
	cmp	byte [r13+r9],','
	je	.have
	inc	r9d
	jmp	.end
.have:
	mov	r8,r13
	call	cors_entry
	je	.found
	lea	eax,[r9+1]
	cmp	eax,r14d
	jae	.none
	add	r13,rax
	sub	r14d,eax
	jmp	.next
.none:
	or	eax,1
	jmp	.out
.found:
	xor	eax,eax
.out:
	pop	r14
	pop	r13
	ret
.yes:
	xor	eax,eax
	ret

; edi = the entry's index, g_hm = the request, r15 = record: eax = 1 for a
; preflight. The origin, let in, is kept. Keeps rbx.
cors_request:
	push	r12
	push	r13
	imul	r12,rdi,CO_SIZE
	lea	r12,[g_cors+r12]
	lea	rdi,[.n_origin]
	mov	esi,6
	call	limit_find
	xor	r13d,r13d			; a preflight?
	test	ecx,ecx
	jz	.no_origin
	cmp	ecx,CORS_ORIGIN_MAX
	ja	.no_origin
	mov	rdi,rsi
	mov	esi,ecx
	call	cors_allowed
	jne	.refused
	mov	rax,[r15+H_BUF]
	lea	rax,[rax+HB_CORS]
	mov	[rax],esi
	lea	r8,[rax+4]
	mov	ecx,esi
	mov	rsi,rdi
	mov	rdi,r8
	rep	movsb
	or	dword [r15+H_FLAGS],HX_CORS
.refused:
	lea	rax,[g_hm]
	cmp	dword [rax+HM_MLEN],7
	jne	.no_origin
	mov	rsi,[rax+HM_METHOD]
	cmp	dword [rsi],'OPTI'
	jne	.no_origin
	cmp	dword [rsi+3],'IONS'
	jne	.no_origin
	lea	rdi,[.n_acrm]
	mov	esi,29
	call	limit_find
	test	ecx,ecx
	jz	.no_origin
	inc	r13d
.no_origin:
	mov	eax,r13d
	pop	r13
	pop	r12
	ret
.n_origin	db 'origin'
.n_acrm		db 'access-control-request-method'

; rdi = where in a head, r15 = record: the lines a response of this route has.
; rdi advanced; keeps rbx, r12-r15.
cors_emit:
	cors_of_h
	jz	.out
	push	r12
	mov	r12,rsi
	cmp	dword [r12+CO_ANY],0
	jne	@f
	memit_x 'Vary: Origin',13,10
@@:
	test	dword [r15+H_FLAGS],HX_CORS
	jz	.done
	call	.allow_origin
	mov	ecx,[r12+CO_ELEN]
	test	ecx,ecx
	jz	.done
	memit_x 'Access-Control-Expose-Headers: '
	mov	rsi,[r12+CO_EXP]
	mov	ecx,[r12+CO_ELEN]
	rep	movsb
	memit_x 13,10
.done:
	pop	r12
.out:
	ret
; r12 = the entry
.allow_origin:
	memit_x 'Access-Control-Allow-Origin: '
	cmp	dword [r12+CO_ANY],0
	je	.echo
	cmp	dword [r12+CO_CRED],0
	jne	.echo
	mov	byte [rdi],'*'
	inc	rdi
	jmp	.origin_end
.echo:
	mov	rax,[r15+H_BUF]
	lea	rsi,[rax+HB_CORS+4]
	mov	ecx,[rax+HB_CORS]
	rep	movsb
.origin_end:
	memit_x 13,10
	cmp	dword [r12+CO_CRED],0
	je	.no_cred
	memit_x 'Access-Control-Allow-Credentials: true',13,10
.no_cred:
	ret

; a preflight, answered here: 204, the rest for the browser to judge
cors_preflight:
	or	dword [r15+H_FLAGS],HX_SELF or HX_STARTED
	test	dword [r15+H_FLAGS],HX_NOBODY
	jnz	@f
	or	dword [r15+H_FLAGS],HX_CLOSE
@@:
	cmp	dword [r15+H_RIDLEN],0
	jne	@f
	call	rid_new
@@:
	mov	dword [r15+H_STATUS],204
	mov	edi,204
	mov	esi,2
	call	http_count
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_OUT]
	memit_x 'HTTP/1.1 204 No Content',13,10
	cors_of_h
	push	r12
	mov	r12,rsi
	memit_x 'Vary: Origin, Access-Control-Request-Method, Access-Control-Request-Headers',13,10
	test	dword [r15+H_FLAGS],HX_CORS
	jz	.refused
	call	cors_emit.allow_origin
	memit_x 'Access-Control-Allow-Methods: '
	mov	ecx,[r12+CO_MLEN]
	mov	rsi,[r12+CO_METH]
	test	ecx,ecx
	jnz	@f
	lea	rsi,[.methods]
	mov	ecx,.methods_len
@@:
	rep	movsb
	memit_x 13,10
	mov	ecx,[r12+CO_HLEN]
	mov	rsi,[r12+CO_HDRS]
	test	ecx,ecx
	jnz	.headers
	; no list: what it asks for
	push	rdi
	lea	rdi,[.n_acrh]
	mov	esi,30
	call	limit_find
	pop	rdi
	test	ecx,ecx
	jz	.no_headers
.headers:
	push	rsi
	push	rcx
	memit_x 'Access-Control-Allow-Headers: '
	pop	rcx
	pop	rsi
	rep	movsb
	memit_x 13,10
.no_headers:
	mov	eax,[r12+CO_AGE]
	test	eax,eax
	jz	.refused
	memit_x 'Access-Control-Max-Age: '
	mov	eax,[r12+CO_AGE]
	call	fmt_u64
	memit_x 13,10
.refused:
	pop	r12
	memit_x 'Content-Length: 0',13,10,'X-Request-Id: '
	lea	rsi,[r15+H_RID]
	mov	ecx,[r15+H_RIDLEN]
	rep	movsb
	memit_x 13,10
	test	dword [r15+H_FLAGS],HX_CLOSE
	jz	@f
	memit_x 'Connection: close',13,10
@@:
	memit_x 13,10
	mov	rsi,[r15+H_BUF]
	lea	rsi,[rsi+HB_OUT]
	sub	rdi,rsi
	mov	dword [r15+H_STATE],HS_SELF_SEND
	mov	ecx,SIDE_CLIENT
	xchg	rsi,rdi
	jmp	h_send
.methods	db 'GET, HEAD, POST'
.methods_len = $ - .methods
.n_acrh		db 'access-control-request-headers'
