; Authentication on a route, before the backend hears of the request:
;
;   auth api_key header=x-api-key keys=FILE [identity=x-user-id] [forward=on]
;   auth basic users=FILE realm=NAME [identity=x-user-id] [forward=on]
;
; A keys file has a line `name:key`, a users file `name:SALT:SHA256HEX`, where
; the hash is of SALT and the password together. Lines starting with # are
; skipped. The plan keeps hashes only: a dump of a process gives no key.
;
; Comparing goes by hash, in constant time, and an unknown name costs what a
; wrong password does. Bcrypt and the like are not used for Basic on purpose:
; they would stop the worker for tens of ms a try, and nothing stops the loop.
; So those passwords must be long and random; people belong behind OIDC.
;
; The client's own `identity` field is never passed on: anyone could say who
; they are otherwise. The name that was proved goes in its place. The credential
; itself stays here unless `forward=on`: no backend, and no mirror, collects it.

AU_KIND		:= 0				; d: AK_*
AU_ID		:= 4				; d: its index
AU_HDR		:= 8				; q: the field that carries it
AU_HLEN		:= 16				; d
AU_ILEN		:= 20				; d
AU_IDENT	:= 24				; q: the field that says who
AU_REALM	:= 32				; q
AU_RLEN		:= 40				; d
AU_FWD		:= 44				; d: the credential goes on to the backend
AU_SIZE		:= 48
MAX_AUTHS	:= 256
AK_APIKEY	:= 1
AK_BASIC	:= 2

; the table of keys and users, all routes': open addressing on the hash
AT_KEY		:= 0				; 32: SHA-256 of the key, or of the name
AT_HASH		:= 32				; 32: Basic: of the salt and the password
AT_SALT		:= 64				; 32: its salt
AT_SLEN		:= 96				; d
AT_AU		:= 100				; d: which auth
AT_NLEN		:= 104				; d: 0 a free slot
AT_NAME		:= 108				; 20: who
AT_SIZE		:= 128
AT_N		:= 8192
AT_MAX		:= 4096
AUTH_NAME_MAX	:= 20
AUTH_B64_MAX	:= 1024

bss
	g_au_digest:	rb 32
	g_au_dummy:	rb AT_SIZE		; what an unknown name is checked against
	g_au_dec:	rb AUTH_B64_MAX
	g_au_path:	rb 1024
end bss

; rsi = a digest (its table's key), edx = the auth: rax = the slot, 0 none.
; Keeps rbx, r12-r15.
auth_slot:
	push	r12
	push	r13
	push	r14
	mov	r12,rsi
	mov	r13d,edx
	mov	r14d,[r12]
	imul	eax,r13d,0x9E3779B1
	add	r14d,eax
.probe:
	and	r14d,AT_N - 1
	mov	eax,r14d
	shl	rax,7				; AT_SIZE
	lea	r8,[g_auth_tab+rax]
	cmp	dword [r8+AT_NLEN],0
	je	.none
	cmp	[r8+AT_AU],r13d
	jne	.next
	mov	rdi,r8
	mov	rsi,r12
	mov	edx,32
	push	r8
	call	ct_equal
	pop	r8
	test	eax,eax
	jnz	.found
.next:
	inc	r14d
	jmp	.probe
.none:
	xor	r8d,r8d
.found:
	mov	rax,r8
	pop	r14
	pop	r13
	pop	r12
	ret

; edi = the auth's index, g_hm = the request, r15 = record: CF when refused;
; otherwise who it is sits in HB_AUTHN. Keeps rbx, r12-r15.
auth_check:
	push	r12
	imul	r12,rdi,AU_SIZE
	lea	r12,[g_auths+r12]
	mov	rax,[r15+H_BUF]
	mov	dword [rax+HB_AUTHL],0
	mov	rdi,[r12+AU_HDR]
	mov	esi,[r12+AU_HLEN]
	call	limit_find
	test	ecx,ecx
	jz	.refused
	cmp	dword [r12+AU_KIND],AK_BASIC
	je	.basic
	lea	rdi,[g_au_digest]
	mov	edx,ecx
	call	sha256
	lea	rsi,[g_au_digest]
	mov	edx,[r12+AU_ID]
	call	auth_slot
	test	rax,rax
	jz	.refused
	jmp	.who
.basic:
	; Basic base64(name:password)
	cmp	ecx,7
	jb	.refused
	mov	eax,[rsi]
	or	eax,0x20202020
	cmp	eax,'basi'
	jne	.refused
	movzx	eax,word [rsi+4]
	or	al,0x20
	cmp	ax,'c '
	jne	.refused
	add	rsi,6
	sub	ecx,6
	cmp	ecx,AUTH_B64_MAX * 4 / 3 - 8
	ja	.refused
	lea	rdi,[g_au_dec]
	mov	edx,ecx
	call	base64_decode
	test	rax,rax
	jle	.refused
	lea	rdi,[g_au_dec]
	mov	ecx,eax
	mov	edx,eax
	mov	al,':'
	mov	r8,rdi
	repne	scasb
	jne	.refused
	mov	r8,rdi				; past the colon
	lea	rcx,[g_au_dec]
	sub	rdi,rcx
	sub	edx,edi				; the password's length
	dec	edi				; the name's
	push	r8
	push	rdx
	mov	edx,edi
	lea	rsi,[g_au_dec]
	lea	rdi,[g_au_digest]
	call	sha256
	lea	rsi,[g_au_digest]
	mov	edx,[r12+AU_ID]
	call	auth_slot
	pop	rdx
	pop	r8
	mov	r9,rax				; its entry, or nothing to compare to:
	test	rax,rax				; an unknown name costs the same
	jnz	@f
	lea	r9,[g_au_dummy]
@@:
	; SHA-256 of the salt and the password
	push	r9
	mov	ecx,[r9+AT_SLEN]
	lea	rax,[rcx+rdx]
	cmp	rax,AUTH_B64_MAX
	ja	.too_long
	mov	r10,rdx
	mov	rsi,r8
	lea	rdi,[g_au_dec+AUTH_B64_MAX]
	sub	rsp,AUTH_B64_MAX
	mov	rdi,rsp
	lea	rsi,[r9+AT_SALT]
	rep	movsb
	mov	rsi,r8
	mov	rcx,r10
	rep	movsb
	mov	rdx,rdi
	sub	rdx,rsp
	mov	rsi,rsp
	lea	rdi,[g_au_digest]
	call	sha256
	add	rsp,AUTH_B64_MAX
	pop	r9
	mov	rdi,r9
	add	rdi,AT_HASH
	lea	rsi,[g_au_digest]
	mov	edx,32
	push	r9
	call	ct_equal
	pop	r9
	test	eax,eax
	jz	.refused
	mov	rax,r9
	lea	rcx,[g_au_dummy]
	cmp	rax,rcx
	je	.refused
	jmp	.who
.too_long:
	pop	r9
.refused:
	stc
	jmp	.out
.who:
	mov	ecx,[rax+AT_NLEN]
	lea	rsi,[rax+AT_NAME]
	mov	rdx,[r15+H_BUF]
	mov	[rdx+HB_AUTHL],ecx
	lea	rdi,[rdx+HB_AUTHN]
	rep	movsb
	clc
.out:
	pop	r12
	ret

; r15 = record, rdi = a field of the request (HF_*): ZF when the route's auth
; keeps it from the backend. Keeps rbx, r12-r15, rdi.
auth_hides:
	mov	eax,[r15+H_ACT]
	test	eax,eax
	jz	.no
	dec	eax
	imul	rax,rax,RA_SIZE
	mov	eax,[g_acts+rax+RA_AUTH]
	test	eax,eax
	jz	.no
	dec	eax
	imul	rax,rax,AU_SIZE
	push	r12
	lea	r12,[g_auths+rax]
	push	rdi
	mov	rsi,[r12+AU_IDENT]
	mov	edx,[r12+AU_ILEN]
	call	.same
	je	.yes
	cmp	dword [r12+AU_FWD],0
	jne	.other
	mov	rdi,[rsp]
	mov	rsi,[r12+AU_HDR]
	mov	edx,[r12+AU_HLEN]
	call	.same
	je	.yes
.other:
	or	eax,1
.yes:
	pop	rdi
	pop	r12
	ret
.no:
	or	eax,1
	ret
; rdi = field, rsi = name, edx = its length: ZF when the same
.same:
	cmp	[rdi+HF_NLEN],edx
	jne	.differ
	mov	rdi,[rdi+HF_NAME]
	call	mem_eq_nocase
	test	eax,eax
	jnz	.equal
.differ:
	or	eax,1
	ret
.equal:
	xor	eax,eax
	ret

; rdi = where in the head for the backend: who it is. rdi advanced; keeps rbx,
; r12-r15.
auth_emit:
	mov	eax,[r15+H_ACT]
	test	eax,eax
	jz	.out
	dec	eax
	imul	rax,rax,RA_SIZE
	mov	eax,[g_acts+rax+RA_AUTH]
	test	eax,eax
	jz	.out
	dec	eax
	imul	rax,rax,AU_SIZE
	lea	r8,[g_auths+rax]
	mov	rax,[r15+H_BUF]
	mov	edx,[rax+HB_AUTHL]
	test	edx,edx
	jz	.out
	mov	rsi,[r8+AU_IDENT]
	mov	ecx,[r8+AU_ILEN]
	rep	movsb
	mov	word [rdi],': '
	add	rdi,2
	lea	rsi,[rax+HB_AUTHN]
	mov	ecx,edx
	rep	movsb
	mov	word [rdi],0x0A0D
	add	rdi,2
.out:
	ret

; refused: 401, and how to prove it. The connection stays, as for a 429.
auth_refuse:
	test	dword [r15+H_FLAGS],HX_GRPC
	jz	@f
	mov	edi,401
	jmp	http_error
@@:
	or	dword [r15+H_FLAGS],HX_SELF or HX_STARTED
	test	dword [r15+H_FLAGS],HX_NOBODY
	jnz	@f
	or	dword [r15+H_FLAGS],HX_CLOSE
@@:
	cmp	dword [r15+H_RIDLEN],0
	jne	@f
	call	rid_new
@@:
	mov	dword [r15+H_STATUS],401
	mov	edi,401
	mov	esi,5
	call	http_count
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_OUT]
	memit_x 'HTTP/1.1 401 Unauthorized',13,10,'WWW-Authenticate: '
	mov	eax,[r15+H_ACT]
	dec	eax
	imul	rax,rax,RA_SIZE
	mov	eax,[g_acts+rax+RA_AUTH]
	dec	eax
	imul	rax,rax,AU_SIZE
	push	r12
	lea	r12,[g_auths+rax]
	cmp	dword [r12+AU_KIND],AK_BASIC
	je	.basic
	memit_x 'ApiKey'
	jmp	.challenged
.basic:
	memit_x 'Basic realm="'
	mov	rsi,[r12+AU_REALM]
	mov	ecx,[r12+AU_RLEN]
	rep	movsb
	memit_x '", charset="UTF-8"'
.challenged:
	pop	r12
	memit_x 13,10
	call	cors_emit
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
