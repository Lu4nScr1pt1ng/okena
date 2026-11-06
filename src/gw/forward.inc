; `auth forward pool=sso path=/verify copy=x-user-id,x-user-role cache=30s timeout=2s`
; on a route: another service decides. The request waits, held, and a session with
; no client, as for `mirror`, asks: GET path on that pool, with the client's Cookie
; and Authorization, and what it is after in X-Forwarded-Method, -Uri and -Host.
;
; A 2xx lets the request go on, the fields of `copy` told to the backend, in place
; of whatever the client sent under those names. A 3xx or 4xx is the client's
; answer, with its Location, WWW-Authenticate and Set-Cookie: that is how a login
; page gets to it. Anything else, no answer, or no answer in time is 503: when the
; one who decides cannot be asked, nobody gets in.
;
; A verdict reaches the request through its buffer: which one, and for which
; generation of the session, so that it is never read by whoever has that session
; next, and it is taken once. It goes through the request's head again, as after a
; `fault` delay, and limits and faults run then: they come after who it is.
;
; `cache` keeps a 2xx in each worker by the method, host, target, Cookie and
; Authorization together, as the service may decide by any of them. For that long,
; a revoked session goes on working. No credentials, no cache: there is nothing
; that tells such clients apart.

SF_FWD		:= 2097152			; S_FLAGS: a copy that asks `auth forward`
FD_FWD		:= 0x40000000			; FD_SESS: its time is up

FR_OK		:= 1
FR_DENY		:= 2
FR_FAIL		:= 3
FA_HELD		:= 4				; g_fa_mode: no answer yet

FC_N		:= 1024
FC_KEY		:= 0				; 32
FC_EXP		:= 32				; q: µs; 0 free
FC_AU		:= 40				; d
FC_HLEN		:= 44				; d
FC_NAMEL	:= 48				; d
FC_NAME		:= 52				; (AUTH_NAME_MAX)
FC_HDR		:= 72
FC_SIZE		:= 512
assert FC_HDR + JWT_HDR_MAX <= FC_SIZE
assert FC_NAME + AUTH_NAME_MAX <= FC_HDR

bss
	g_fa_mode	dd ?			; why auth_check said no
	align 8
	g_fc_slot	dq ?
	g_fc_dig:	rb 32
	g_fc_sha:	rb SHA256_CTX_SIZE
	g_fc:		rb FC_N * FC_SIZE
end bss

; r12 = the auth, r15 = record, ebx = session: as auth_check, g_fa_mode saying why.
; Keeps rbx, r12-r15.
fwd_check:
	mov	rax,[r15+H_BUF]
	mov	ecx,[rax+HB_FST]
	test	ecx,ecx
	jz	.first
	mov	r8d,[rax+HB_FGEN]
	mov	r9,rax
	call	session_ptr
	mov	eax,[rax+S_GEN]
	cmp	eax,r8d
	mov	rax,r9
	jne	.first				; someone else's: nothing to do with this one
	mov	dword [rax+HB_FST],0
	mov	qword [rax+HB_FDUE],0
	and	dword [r15+H_FLAGS],not HX_FAULTED	; (limits and faults are ahead)
	cmp	ecx,FR_OK
	je	.good
	mov	[g_fa_mode],ecx
	stc
	ret
.good:
	clc
	ret
.first:
	mov	dword [rax+HB_FST],0
	mov	dword [rax+HB_AUTHL],0
	mov	dword [rax+HB_JHLEN],0
	mov	qword [rax+HB_FKEYP],0
	cmp	dword [r12+AU_TTL],0
	je	.ask
	call	fc_lookup
	jnc	.good
	cmp	qword [g_fc_slot],0		; (for when the answer comes)
	je	.ask
	mov	rax,[r15+H_BUF]
	mov	rcx,[g_fc_slot]
	mov	[rax+HB_FKEYP],rcx
	lea	rdi,[rax+HB_FKEY]
	lea	rsi,[g_fc_dig]
	mov	ecx,32
	rep	movsb
.ask:
	cmp	dword [g_mir_n],MIR_MAX
	jae	.busy
	mov	eax,[g_fd_n]
	add	eax,2				; (the hold and the copy's start)
	cmp	eax,FD_MAX
	ja	.busy
	; what it takes must fit a head
	push	r13
	push	r14
	call	fwd_head_size
	cmp	eax,H_IN_CAP
	ja	.too_big
	mov	edi,[r12+AU_POOL]
	mov	esi,SF_FWD
	xor	edx,edx
	xor	r9d,r9d
	xor	r10d,r10d
	call	mirror_new
	cmp	eax,NIL
	je	.too_big
	mov	r13d,eax			; the copy
	mov	r14d,eax
	shl	r14,H_SHIFT
	add	r14,[g_http_base]
	mov	rdi,[r14+H_BUF]
	call	fwd_head
	mov	rdx,[r14+H_BUF]
	sub	rdi,rdx
	mov	[r14+H_INLEN],edi
	mov	[r14+H_INOFF],edi
	; they know each other
	call	session_ptr
	mov	eax,[rax+S_GEN]
	mov	[rdx+HB_HPS],ebx
	mov	[rdx+HB_HPG],eax
	push	rbx
	mov	ebx,r13d
	call	session_ptr
	pop	rbx
	mov	eax,[rax+S_GEN]
	mov	rdx,[r15+H_BUF]
	mov	[rdx+HB_MIRS],r13d
	mov	[rdx+HB_MIRG],eax
	pop	r14
	pop	r13
	; held, for as long as it is given
	mov	rax,[r12+AU_TIMEOUT]
	call	fault_hold
	or	dword [g_fd+rcx+FD_SESS],FD_FWD
	mov	rax,[g_fd+rcx+FD_AT]
	mov	rdx,[r15+H_BUF]
	mov	[rdx+HB_FDUE],rax
	mov	dword [g_fa_mode],FA_HELD
	stc
	ret
.too_big:
	pop	r14
	pop	r13
.busy:
	mov	dword [g_fa_mode],FR_FAIL
	stc
	ret

; eax = how long the question will be, at most. Keeps r12-r15, rbx.
fwd_head_size:
	mov	eax,[r12+AU_PLEN]
	add	eax,[g_hm+HM_MLEN]
	add	eax,[g_hm+HM_TLEN]
	push	rbx
	mov	ebx,eax
	lea	rdi,[.host]
	mov	esi,4
	call	limit_find
	lea	ebx,[rbx+rcx*2]
	lea	rdi,[.cookie]
	mov	esi,6
	call	limit_find
	add	ebx,ecx
	lea	rdi,[.auth]
	mov	esi,13
	call	limit_find
	add	ebx,ecx
	lea	eax,[rbx+256]
	pop	rbx
	ret
.host	db 'host'
.cookie	db 'cookie'
.auth	db 'authorization'

; rdi = where: the question, from g_hm. rdi = its end. Keeps rbx, r12-r15.
fwd_head:
	memit_x 'GET '
	mov	rsi,[r12+AU_PATH]
	mov	ecx,[r12+AU_PLEN]
	rep	movsb
	memit_x ' HTTP/1.1',13,10,'Host: '
	push	rdi
	lea	rdi,[fwd_head_size.host]
	mov	esi,4
	call	limit_find
	pop	rdi
	mov	r8,rsi
	mov	r9d,ecx
	rep	movsb
	memit_x 13,10,'X-Forwarded-Host: '
	mov	rsi,r8
	mov	ecx,r9d
	rep	movsb
	memit_x 13,10,'X-Forwarded-Method: '
	mov	rsi,[g_hm+HM_METHOD]
	mov	ecx,[g_hm+HM_MLEN]
	rep	movsb
	memit_x 13,10,'X-Forwarded-Uri: '
	mov	rsi,[g_hm+HM_TARGET]
	mov	ecx,[g_hm+HM_TLEN]
	rep	movsb
	memit_x 13,10
	push	rdi
	lea	rdi,[fwd_head_size.cookie]
	mov	esi,6
	call	limit_find
	pop	rdi
	test	ecx,ecx
	jz	@f
	mov	r8,rsi
	mov	r9d,ecx
	memit_x 'Cookie: '
	mov	rsi,r8
	mov	ecx,r9d
	rep	movsb
	memit_x 13,10
@@:
	push	rdi
	lea	rdi,[fwd_head_size.auth]
	mov	esi,13
	call	limit_find
	pop	rdi
	test	ecx,ecx
	jz	@f
	mov	r8,rsi
	mov	r9d,ecx
	memit_x 'Authorization: '
	mov	rsi,r8
	mov	ecx,r9d
	rep	movsb
	memit_x 13,10
@@:
	memit_x 13,10
	ret

; r12 = the auth, g_hm = the request: g_fc_dig its key, rax = its place in g_fc.
; CF: it has no credentials. Keeps rbx, r12-r15.
fc_key:
	push	rbx
	xor	ebx,ebx				; credentials seen
	lea	rdi,[g_fc_sha]
	call	sha256_init
	lea	rsi,[r12+AU_ID]
	mov	edx,4
	call	.add
	mov	rsi,[g_hm+HM_METHOD]
	mov	edx,[g_hm+HM_MLEN]
	call	.field
	mov	rsi,[g_hm+HM_TARGET]
	mov	edx,[g_hm+HM_TLEN]
	call	.field
	lea	rdi,[fwd_head_size.host]
	mov	esi,4
	call	limit_find
	mov	edx,ecx
	call	.field
	lea	rdi,[fwd_head_size.cookie]
	mov	esi,6
	call	limit_find
	add	ebx,ecx
	mov	edx,ecx
	call	.field
	lea	rdi,[fwd_head_size.auth]
	mov	esi,13
	call	limit_find
	add	ebx,ecx
	mov	edx,ecx
	call	.field
	test	ebx,ebx
	jnz	@f
	stc
	jmp	.out
@@:
	lea	rdi,[g_fc_sha]
	lea	rsi,[g_fc_dig]
	call	sha256_final
	mov	eax,[g_fc_dig]
	and	eax,FC_N - 1
	shl	rax,9				; FC_SIZE
	lea	rax,[g_fc+rax]
	clc
.out:
	pop	rbx
	ret
; a field and its length, so that two fields cannot pass for two others
.field:
	push	rsi
	push	rdx
	mov	[g_fc_dig],edx
	lea	rsi,[g_fc_dig]
	mov	edx,4
	call	.add
	pop	rdx
	pop	rsi
.add:
	lea	rdi,[g_fc_sha]
	jmp	sha256_update

; r12 = the auth: CF unless a verdict is kept for this request; if so its record
; has it. Keeps rbx, r12-r15.
fc_lookup:
	mov	qword [g_fc_slot],0
	call	fc_key
	jc	.out
	mov	[g_fc_slot],rax
	mov	r8,rax
	mov	rax,[r8+FC_EXP]
	test	rax,rax
	jz	.miss
	mov	ecx,[r12+AU_ID]
	cmp	[r8+FC_AU],ecx
	jne	.miss
	push	r8
	call	qs_clock
	pop	r8
	mov	rax,[r8+FC_EXP]
	cmp	rax,[g_qnow]
	jbe	.miss
	push	r8
	mov	rdi,r8
	lea	rsi,[g_fc_dig]
	mov	edx,32
	call	ct_equal
	pop	r8
	test	eax,eax
	jz	.miss
	mov	rdx,[r15+H_BUF]
	mov	ecx,[r8+FC_NAMEL]
	mov	[rdx+HB_AUTHL],ecx
	lea	rdi,[rdx+HB_AUTHN]
	lea	rsi,[r8+FC_NAME]
	rep	movsb
	mov	ecx,[r8+FC_HLEN]
	mov	[rdx+HB_JHLEN],ecx
	lea	rdi,[rdx+HB_JHDR]
	lea	rsi,[r8+FC_HDR]
	rep	movsb
	clc
	ret
.miss:
	stc
.out:
	ret

; an answer's head is in g_hm: ebx = a session, r15 = its record, eax = the status.
; A copy that asks: its verdict goes to the request, and it reads on, discarding,
; so that the connection to the service can be used again.
fwd_answer:
	test	dword [r15+H_FLAGS],HX_MIRROR
	jz	.none
	push	rax
	call	session_ptr
	mov	ecx,[rax+S_FLAGS]
	pop	rax
	test	ecx,SF_FWD
	jz	.none
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r14d,eax
	mov	rax,[r15+H_BUF]
	mov	r12d,[rax+HB_HPS]
	mov	ecx,[rax+HB_HPG]
	mov	ebx,r12d
	call	hedge_alive
	jne	.out
	mov	r13d,ebx
	shl	r13,H_SHIFT
	add	r13,[g_http_base]
	cmp	dword [r13+H_STATE],HS_FAULT
	jne	.out
	mov	rcx,[r13+H_BUF]
	cmp	dword [rcx+HB_FST],0
	jne	.out
	mov	eax,[rsp+24]			; (the copy)
	cmp	[rcx+HB_MIRS],eax
	jne	.out				; an earlier request's
	mov	eax,[r13+H_ACT]
	test	eax,eax
	jz	.out
	dec	eax
	imul	rax,rax,RA_SIZE
	mov	eax,[g_acts+rax+RA_AUTH]
	test	eax,eax
	jz	.out
	dec	eax
	imul	rax,rax,AU_SIZE
	lea	r12,[g_auths+rax]
	mov	[rcx+HB_FSTAT],r14d
	mov	eax,r14d
	cmp	eax,200
	jb	.fail
	cmp	eax,300
	jb	.allow
	cmp	eax,500
	jb	.deny
.fail:
	mov	eax,FR_FAIL
	jmp	.verdict
.allow:
	call	fwd_told
	jc	.fail
	cmp	dword [r12+AU_TTL],0
	je	.allowed
	call	fc_store
.allowed:
	mov	eax,FR_OK
	jmp	.verdict
.deny:
	call	fwd_denied
	mov	eax,FR_DENY
.verdict:
	mov	edi,eax
	call	fwd_verdict
.out:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
.none:
	ret

; ebx = the request, edi = what was decided: it goes on in the loop's next turn
fwd_verdict:
	mov	edx,ebx
	shl	rdx,HB_SHIFT
	add	rdx,[g_hbuf_base]
	mov	[rdx+HB_FST],edi
	call	session_ptr
	mov	ecx,[rax+S_GEN]
	mov	[rdx+HB_FGEN],ecx
	; its time becomes now: what stays in the table is only what waits
	mov	r8d,ebx
	or	r8d,FD_FWD
	mov	r9d,[g_fd_n]
	xor	eax,eax
.find:
	cmp	r9d,0
	je	.add
	cmp	[g_fd+rax+FD_SESS],r8d
	jne	.other
	cmp	[g_fd+rax+FD_GEN],ecx
	je	.now
.other:
	add	rax,1 shl 4
	dec	r9d
	jmp	.find
.add:
	mov	eax,[g_fd_n]			; (its time came, and that is why)
	cmp	eax,FD_MAX
	jae	.out
	inc	dword [g_fd_n]
	shl	rax,4
	mov	[g_fd+rax+FD_GEN],ecx
.now:
	mov	qword [g_fd+rax+FD_AT],1
	mov	[g_fd+rax+FD_SESS],ebx
	mov	qword [g_fd_next],1
.out:
	ret

; r12 = the auth, r13 = the request's record, g_hm = the answer: its `copy` fields
; rendered for the backend. CF: they do not fit, or are not fit for a header.
fwd_told:
	push	rbx
	push	r14
	push	r15
	mov	r14,[r13+H_BUF]
	lea	r15,[r14+HB_JHDR]		; the cursor
	mov	ebx,[r12+AU_CN]
	mov	eax,[r12+AU_CFIRST]
	imul	rax,rax,CM_SIZE
	lea	rax,[g_claims+rax]
.next:
	test	ebx,ebx
	jz	.done
	dec	ebx
	push	rax
	mov	rdi,[rax+CM_HDR]
	mov	esi,[rax+CM_HLEN]
	call	limit_find
	pop	rax
	test	ecx,ecx
	jz	.skip
	push	rax
	mov	edx,[rax+CM_HLEN]
	lea	r8,[r15+rdx]
	lea	r8,[r8+rcx+4]
	lea	r9,[r14+HB_JHDR+JWT_HDR_MAX]
	cmp	r8,r9
	ja	.bad
	; the first says who, for `limit key=auth.user`
	cmp	dword [r14+HB_AUTHL],0
	jne	@f
	push	rcx
	push	rsi
	mov	rdx,r14
	call	auth_name
	pop	rsi
	pop	rcx
@@:
	mov	r8d,ecx
	mov	r9,rsi
.check:
	mov	al,[r9]
	cmp	al,0x20
	jb	.bad
	cmp	al,0x7F
	je	.bad
	inc	r9
	dec	r8d
	jnz	.check
	mov	rax,[rsp]
	mov	r8,rsi
	mov	r9d,ecx
	mov	rsi,[rax+CM_HDR]
	mov	ecx,[rax+CM_HLEN]
	mov	rdi,r15
	rep	movsb
	mov	word [rdi],': '
	add	rdi,2
	mov	rsi,r8
	mov	ecx,r9d
	rep	movsb
	mov	word [rdi],0x0A0D
	lea	r15,[rdi+2]
	pop	rax
.skip:
	add	rax,CM_SIZE
	jmp	.next
.done:
	lea	rax,[r14+HB_JHDR]
	sub	r15,rax
	mov	[r14+HB_JHLEN],r15d
	clc
	jmp	.out
.bad:
	pop	rax
	mov	dword [r14+HB_AUTHL],0
	stc
.out:
	pop	r15
	pop	r14
	pop	rbx
	ret

; r13 = the request's record, g_hm = the answer: what the client needs of a refusal
fwd_denied:
	push	rbx
	push	r14
	push	r15
	mov	r14,[r13+H_BUF]
	lea	r15,[r14+HB_JHDR]
	lea	rbx,[.names]
.next:
	movzx	esi,byte [rbx]
	test	esi,esi
	jz	.done
	lea	rdi,[rbx+1]
	call	limit_find
	movzx	edx,byte [rbx]
	test	ecx,ecx
	jz	.skip
	lea	r8,[r15+rdx]
	lea	r8,[r8+rcx+4]
	lea	r9,[r14+HB_JHDR+JWT_HDR_MAX]
	cmp	r8,r9
	ja	.skip
	mov	r8,rsi
	mov	r9d,ecx
	mov	r10,r8
	mov	eax,ecx
.check:
	cmp	byte [r10],0x20
	jb	.skip
	inc	r10
	dec	eax
	jnz	.check
	lea	rsi,[rbx+1]
	mov	ecx,edx
	mov	rdi,r15
	rep	movsb
	mov	word [rdi],': '
	add	rdi,2
	mov	rsi,r8
	mov	ecx,r9d
	rep	movsb
	mov	word [rdi],0x0A0D
	lea	r15,[rdi+2]
.skip:
	movzx	eax,byte [rbx]
	lea	rbx,[rbx+rax+1]
	jmp	.next
.done:
	lea	rax,[r14+HB_JHDR]
	sub	r15,rax
	mov	[r14+HB_JHLEN],r15d
	pop	r15
	pop	r14
	pop	rbx
	ret
.names	db 8,'location'
	db 16,'www-authenticate'
	db 10,'set-cookie'
	db 0

; r12 = the auth, r13 = the request's record, its request's verdict rendered: kept
; for AU_TTL. Its head is not in g_hm any more, so the key comes from the question.
fc_store:
	mov	rdx,[r13+H_BUF]
	cmp	qword [rdx+HB_FKEYP],0
	je	.out
	mov	r8,[rdx+HB_FKEYP]
	lea	rsi,[rdx+HB_FKEY]
	mov	rdi,r8
	mov	ecx,32
	rep	movsb
	mov	eax,[r12+AU_ID]
	mov	[r8+FC_AU],eax
	mov	ecx,[rdx+HB_AUTHL]
	mov	[r8+FC_NAMEL],ecx
	lea	rsi,[rdx+HB_AUTHN]
	lea	rdi,[r8+FC_NAME]
	rep	movsb
	mov	ecx,[rdx+HB_JHLEN]
	mov	[r8+FC_HLEN],ecx
	lea	rsi,[rdx+HB_JHDR]
	lea	rdi,[r8+FC_HDR]
	rep	movsb
	push	r8
	call	qs_clock
	pop	r8
	mov	eax,[r12+AU_TTL]
	imul	rax,rax,1000000
	add	rax,[g_qnow]
	mov	[r8+FC_EXP],rax
.out:
	ret

; the time of a request that waits: ebx = it, r15 = record, r9 = the time it was
; given, still its own?
fwd_timeout:
	cmp	dword [r15+H_STATE],HS_FAULT
	jne	.none
	mov	rax,[r15+H_BUF]
	cmp	[rax+HB_FDUE],r9
	jne	.none
	cmp	dword [rax+HB_FST],0
	jne	.go				; (a verdict that found no room)
	mov	edi,FR_FAIL
	call	fwd_verdict
	push	rbx
	mov	rax,[r15+H_BUF]
	mov	ecx,[rax+HB_MIRG]
	mov	ebx,[rax+HB_MIRS]
	call	hedge_alive
	jne	@f
	mov	edi,ebx
	call	session_close
@@:
	pop	rbx
	ret
.go:
	mov	eax,[r15+H_INOFF]
	jmp	http_request
.none:
	ret

; a session is closing: ebx = it, r12 = it. A copy that asks and got no answer: its
; request hears now, and does not wait for its time. Keeps all.
fwd_gone:
	test	dword [r12+S_FLAGS],SF_FWD
	jz	.none
	push	rax
	push	rcx
	push	rdx
	push	rdi
	push	r8
	push	r9
	push	rbx
	mov	eax,ebx
	shl	rax,HB_SHIFT
	add	rax,[g_hbuf_base]
	mov	r8,rax
	mov	r9d,ebx
	mov	ebx,[r8+HB_HPS]
	mov	ecx,[r8+HB_HPG]
	call	hedge_alive
	jne	.out
	mov	eax,ebx
	shl	rax,H_SHIFT
	add	rax,[g_http_base]
	cmp	dword [rax+H_STATE],HS_FAULT
	jne	.out
	mov	rax,[rax+H_BUF]
	cmp	dword [rax+HB_FST],0
	jne	.out
	cmp	[rax+HB_MIRS],r9d
	jne	.out				; it decided an earlier request: its body came late
	mov	edi,FR_FAIL
	call	fwd_verdict
.out:
	pop	rbx
	pop	r9
	pop	r8
	pop	rdi
	pop	rdx
	pop	rcx
	pop	rax
.none:
	ret

; r12 = the auth, rbx = its node: the rest of `auth forward`
compile_forward:
	push	r13
	push	r14
	push	r15
	mov	r15,rbx
	mov	rdi,r15
	lea	rsi,[str_key_pool]
	call	node_option
	test	rax,rax
	jz	plan_bad_forward
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	plan_pool_index
	cmp	eax,-1
	je	plan_bad_forward
	mov	[r12+AU_POOL],eax
	mov	rdi,r15
	lea	rsi,[str_key_path]
	call	node_option
	test	rax,rax
	jz	plan_bad_forward
	mov	rcx,[rax+A_VAL]
	mov	edx,[rax+A_VLEN]
	test	edx,edx
	jz	plan_bad_forward
	cmp	byte [rcx],'/'
	jne	plan_bad_forward
	cmp	edx,1024
	ja	plan_bad_forward
	mov	[r12+AU_PATH],rcx
	mov	[r12+AU_PLEN],edx
.path:
	cmp	byte [rcx],' '
	jbe	plan_bad_forward
	cmp	byte [rcx],0x7F
	jae	plan_bad_forward
	inc	rcx
	dec	edx
	jnz	.path
	mov	qword [r12+AU_TIMEOUT],2000000
	mov	rdi,r15
	lea	rsi,[str_key_timeout]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_duration
	jc	plan_bad_forward
	test	rax,rax
	jz	plan_bad_forward
	mov	[r12+AU_TIMEOUT],rax
@@:
	mov	rdi,r15
	lea	rsi,[str_key_cache]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_duration
	jc	plan_bad_forward
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	test	eax,eax
	jz	plan_bad_forward
	mov	[r12+AU_TTL],eax
@@:
	; copy=a,b: told to the backend, and whatever the client says of them dropped
	mov	eax,[g_plan_claims]
	mov	[r12+AU_CFIRST],eax
	mov	rdi,r15
	lea	rsi,[str_key_copy]
	call	node_option
	test	rax,rax
	jz	.done
	mov	r13,[rax+A_VAL]
	mov	r14d,[rax+A_VLEN]
	lea	r14,[r13+r14]
.name:
	mov	rcx,r13
.scan:
	cmp	rcx,r14
	jae	.end_name
	cmp	byte [rcx],','
	je	.end_name
	inc	rcx
	jmp	.scan
.end_name:
	mov	rdx,rcx
	sub	rdx,r13
	jz	plan_bad_forward
	mov	eax,[g_plan_claims]
	cmp	eax,MAX_CLAIMS
	jae	plan_bad_forward
	inc	dword [g_plan_claims]
	imul	rax,rax,CM_SIZE
	lea	r8,[g_claims+rax]
	mov	[r8+CM_HDR],r13
	mov	[r8+CM_HLEN],edx
	inc	dword [r12+AU_CN]
	lea	r13,[rcx+1]
	cmp	rcx,r14
	jb	.name
.done:
	pop	r15
	pop	r14
	pop	r13
	ret

plan_bad_forward:
	call	log_begin
	out_lit 'auth forward needs pool=NAME of a pool that exists and path=/PATH; timeout= and cache= are times; copy= is a list of up to 64 fields'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

cstring str_key_pool, 'pool',0
cstring str_key_path, 'path',0
cstring str_key_timeout, 'timeout',0
cstring str_key_cache, 'cache',0
cstring str_key_copy, 'copy',0
