; `sticky cookie=NAME [ttl=1h] [samesite=lax|strict|none]` on a pool: a
; client stays on the server it got, by a cookie that names that server.
;
; The name is 16 hex digits of a hash of the server's address, the same in
; every worker, after a reload and on every okena with that server: no
; secret to share. It does not give the address away by itself, but one who
; holds it can guess an address by trying them (as nginx's, as HAProxy's
; server names): that is all it is good for.
;
; A request whose cookie names a server of its pool that is up goes there,
; past the pool's balance, and also when the server is drained: a drain is
; for the sessions it has to end there, while new clients go elsewhere. A
; server that is down, ejected or gone, a retry, a cookie that names nothing,
; and no cookie: the balance picks, and the answer sets the cookie anew. It
; is set on the answers of the server it names, not on okena's own (errors,
; cache hits), with Path=/, HttpOnly, SameSite (Lax by default), Max-Age
; when there is a ttl, and Secure on a TLS listener, or with SameSite=None.
;
; Only http has cookies: a tcp or udp listener on such a pool uses its
; balance, and source-hash is what keeps a stream client in place.

SF_STKOK	:= 1 shl 29			; S_FLAGS: the cookie names the server it went to
SS_LAX		:= 0
SS_STRICT	:= 1
SS_NONE		:= 2

; edi = server: rax = its name in the cookie. Keeps rbx, r12-r15.
sticky_id:
	imul	rax,rdi,SV_SIZE
	lea	rsi,[g_servers+rax+SV_SA]
	mov	ecx,[g_servers+rax+SV_SALEN]
	call	hash_bytes
	ret

; edi = server: CF when a client that has it may stay on it (an address,
; health checks passing, not ejected here; a drain does not count)
sticky_usable:
	imul	rax,rdi,SV_SIZE
	cmp	dword [g_servers+rax+SV_ACTIVE],0
	je	.no
	mov	rax,[g_health_tbl]
	cmp	dword [rax+rdi*8],HC_UP
	jne	.no
	mov	eax,[g_sv_down+rdi*4]
	cmp	eax,[g_tick]
	ja	.no
	stc
	ret
.no:
	clc
	ret

; an http request's connect: ebx = session, r15 = record, r12 = its session
; record. eax = the server its cookie names, or NIL for the balance to
; choose. Keeps rbx, r12-r15.
sticky_pick:
	and	dword [r12+S_FLAGS],not SF_STKOK
	mov	eax,[r12+S_POOL]
	imul	rax,rax,PL_SIZE
	lea	r8,[g_pools+rax]
	cmp	qword [r8+PL_SNAME],0
	je	.none
	test	dword [r15+H_FLAGS],HX_AVOID or HX_MIRROR
	jnz	.none				; a retry goes elsewhere
	mov	rax,[g_hm+HM_TARGET]
	mov	rcx,[r15+H_BUF]
	cmp	rax,rcx
	jb	.none
	add	rcx,H_IN_CAP
	cmp	rax,rcx
	jae	.none				; another request's head
	push	r13
	push	r14
	mov	r13,r8
	lea	rdi,[.cookie]
	mov	esi,6
	call	limit_find
	test	ecx,ecx
	jz	.nothing
	lea	rdx,[rsi+rcx]
	mov	rdi,[r13+PL_SNAME]
	mov	ecx,[r13+PL_SNLEN]
	mov	r8b,';'
	call	limit_field
	cmp	ecx,16
	jne	.nothing
	; 16 hex digits
	xor	r14d,r14d
@@:
	movzx	eax,byte [rsi]
	inc	rsi
	sub	eax,'0'
	cmp	eax,9
	jbe	.digit
	sub	eax,'a' - '0'
	cmp	eax,5
	ja	.nothing
	add	eax,10
.digit:
	shl	r14,4
	or	r14,rax
	dec	ecx
	jnz	@b
	; which of the pool's servers
	mov	ecx,[r13+PL_FIRST]
	mov	edx,ecx
	add	edx,[r13+PL_COUNT]
.server:
	cmp	ecx,edx
	jae	.nothing
	push	rcx
	push	rdx
	mov	edi,ecx
	call	sticky_id
	pop	rdx
	pop	rcx
	cmp	rax,r14
	je	.named
	inc	ecx
	jmp	.server
.named:
	mov	edi,ecx
	call	sticky_usable
	jnc	.nothing
	or	dword [r12+S_FLAGS],SF_STKOK
	mov	dword [g_pick_hashed],0		; (the balance is not asked)
	mov	eax,edi
	pop	r14
	pop	r13
	ret
.nothing:
	pop	r14
	pop	r13
.none:
	mov	eax,NIL
	ret
.cookie	db 'cookie'

; rdi = where in a head, eax = session, r15 = its record: the cookie, when
; the answer comes from a server its client was not on. rdi advanced; keeps
; rbx, r12-r15.
sticky_emit_for:
	push	r12
	push	r13
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	mov	r12,rax
	test	dword [r12+S_FLAGS],SF_STKOK or SF_CACHED or SF_FILE
	jnz	.out
	test	dword [r15+H_FLAGS],HX_SELF
	jnz	.out
	mov	eax,[r12+S_SERVER]
	cmp	eax,NIL
	je	.out
	mov	ecx,[r12+S_POOL]
	imul	rcx,rcx,PL_SIZE
	lea	r13,[g_pools+rcx]
	cmp	qword [r13+PL_SNAME],0
	je	.out
	; the server must be of this pool (a hedge's copy answering: its own)
	cmp	eax,[r13+PL_FIRST]
	jb	.out
	mov	ecx,[r13+PL_FIRST]
	add	ecx,[r13+PL_COUNT]
	cmp	eax,ecx
	jae	.out
	push	rdi
	mov	edi,eax
	call	sticky_id
	pop	rdi
	push	rax
	memit_x 'Set-Cookie: '
	mov	rsi,[r13+PL_SNAME]
	mov	ecx,[r13+PL_SNLEN]
	rep	movsb
	mov	byte [rdi],'='
	inc	rdi
	pop	rdx
	mov	ecx,16
@@:
	rol	rdx,4
	mov	eax,edx
	and	eax,15
	add	eax,'0'
	cmp	eax,'9'
	jbe	.hex
	add	eax,'a' - '0' - 10
.hex:
	stosb
	dec	ecx
	jnz	@b
	memit_x '; Path=/; HttpOnly'
	mov	eax,[r13+PL_STTL]
	test	eax,eax
	jz	@f
	push	rax
	memit_x '; Max-Age='
	pop	rax
	call	fmt_u64
@@:
	mov	eax,[r13+PL_SSAME]
	cmp	eax,SS_STRICT
	je	.strict
	cmp	eax,SS_NONE
	je	.none
	memit_x '; SameSite=Lax'
	jmp	.secure
.strict:
	memit_x '; SameSite=Strict'
	jmp	.secure
.none:
	memit_x '; SameSite=None; Secure'
	jmp	.done
.secure:
	mov	eax,[r12+S_LST]
	imul	rax,rax,LS_SIZE
	cmp	dword [g_listeners+rax+LS_TLS],0
	je	.done
	memit_x '; Secure'
.done:
	memit_x 13,10
.out:
	pop	r13
	pop	r12
	ret
