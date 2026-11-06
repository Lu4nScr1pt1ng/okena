; JWT on a route: `auth jwt { jwks SRC; issuer X; audience Y; leeway T;
; claims sub -> x-user-id, scope -> x-user-scope }`.
;
; A bearer token is three parts. Before its signature is checked only the first
; is read, for its algorithm and key id, and that is decided by what the keys are:
; a key says what it may verify, so a token cannot have an RSA public key taken
; for a shared secret, and `none` is no algorithm. Then, signed: exp, which is
; required, nbf, iss and aud. A `crit` header is refused: nothing here is known
; to understand it.
;
; A signature costs tens of µs, so a token is verified once: each worker keeps
; it by its hash until it expires. What is told to the backend is rendered then.
; A claim that would put a control byte in a header is refused with the token: an
; escaped \r\n is a line break once decoded, and that would be a header forged by
; whoever can get a claim of their choosing signed.
;
; ES256, RS256, PS256, EdDSA, HS256. Keys come from a JWK set; a key with `use`
; other than sig, or of a kind not known here, is left out.

; a key
JK_KIND		:= 0				; d: JA_* it verifies (RSA: either)
JK_ALG		:= 4				; d: what the set says, 0 not said
JK_LEN		:= 8				; d: of JK_KEY
JK_E		:= 12				; d: RSA's exponent
JK_KIDL		:= 16				; d
JK_KID		:= 20				; 60
JK_KEY		:= 80				; 04|x|y, n, the public key, the secret
JK_KEYCAP	:= 512
JK_SIZE		:= JK_KEY + JK_KEYCAP
MAX_JWK		:= 64
JA_ES256	:= 1
JA_RS256	:= 2
JA_PS256	:= 3
JA_EDDSA	:= 4
JA_HS256	:= 5

; a claim told to the backend
CM_CLAIM	:= 0				; q
CM_HDR		:= 8				; q
CM_CLEN		:= 16				; d
CM_HLEN		:= 20				; d
CM_SIZE		:= 24
MAX_CLAIMS	:= 64

; a token verified
JC_N		:= 1024
JC_KEY		:= 0				; 32: SHA-256 of the token
JC_EXP		:= 32				; q: seconds, leeway included; 0 free
JC_AU		:= 40				; d
JC_HLEN		:= 44				; d
JC_NAMEL	:= 48				; d
JC_NAME		:= 52				; 20
JC_HDR		:= 72				; what the backend is told
JC_SIZE		:= 512
JWT_HDR_MAX	:= 256
JWT_MAX		:= 12288

bss
	g_jwt_now	dq ?			; seconds, wall clock, by the tick
	g_jt_dig:	rb 32
	g_jt_dig2:	rb 32
	g_jt_buf:	rb 512
	g_jt_h:		rb 2048
	g_jt_p:		rb 12288
	g_jt_s:		rb 1024
	g_jt_a:		rb 512
	g_jt_q:		rb 65
	g_jc:		rb JC_N * JC_SIZE
end bss

; once a tick
jwt_tick:
	sub	rsp,16
	mov	edi,CLOCK_REALTIME
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	mov	rax,[rsp]
	mov	[g_jwt_now],rax
	add	rsp,16
	ret

; rsi = a number's text, r8 = its end: rax = its whole part. CF: not a number.
json_seconds:
	xor	eax,eax
	cmp	rsi,r8
	jae	.bad
	movzx	ecx,byte [rsi]
	sub	ecx,'0'
	cmp	ecx,9
	ja	.bad
.digit:
	cmp	rsi,r8
	jae	.ok
	movzx	ecx,byte [rsi]
	cmp	cl,'.'
	je	.ok
	sub	ecx,'0'
	cmp	ecx,9
	ja	.bad
	mov	r9,rax
	shr	r9,40
	jnz	.bad
	imul	rax,rax,10
	add	rax,rcx
	inc	rsi
	jmp	.digit
.ok:
	clc
	ret
.bad:
	stc
	ret

; r12 = the auth, g_jt_h = the header (edx bytes): r9 = the key, r10d = JA_*.
; CF: none. The token's alg must be one the key is for.
jwt_key:
	push	rbx
	push	r13
	push	r14
	push	r15
	lea	rsi,[g_jt_h]
	lea	rdx,[g_jt_h+rdx]
	mov	r13,rsi
	mov	r14,rdx
	call	json_valid
	jc	.none
	mov	rsi,r13
	mov	rdx,r14
	; crit: not understood
	lea	rdi,[.n_crit]
	mov	ecx,4
	call	json_get
	jc	.none
	test	rax,rax
	jnz	.none
	; alg
	mov	rsi,r13
	mov	rdx,r14
	lea	rdi,[.n_alg]
	mov	ecx,3
	call	json_get
	jc	.none
	test	rax,rax
	jz	.none
	mov	rsi,rax
	lea	rdi,[g_jt_buf]
	mov	ecx,16
	call	json_string
	jc	.none
	mov	ebx,eax
	lea	r15,[g_jt_buf]
	xor	r10d,r10d
	cmp	ebx,5
	jne	.named
	mov	eax,[r15]
	cmp	eax,'ES25'
	je	.es
	cmp	eax,'RS25'
	je	.rs
	cmp	eax,'PS25'
	je	.ps
	cmp	eax,'HS25'
	je	.hs
	cmp	eax,'EdDS'
	jne	.none
	cmp	byte [r15+4],'A'
	jne	.none
	mov	r10d,JA_EDDSA
	jmp	.alg_done
.es:
	mov	r10d,JA_ES256
	jmp	.six
.rs:
	mov	r10d,JA_RS256
	jmp	.six
.ps:
	mov	r10d,JA_PS256
	jmp	.six
.hs:
	mov	r10d,JA_HS256
.six:
	cmp	byte [r15+4],'6'
	jne	.none
	jmp	.alg_done
.named:
	jmp	.none
.alg_done:
	; kid, if any
	xor	ebx,ebx				; its length, 0 none
	push	r10
	mov	rsi,r13
	mov	rdx,r14
	lea	rdi,[.n_kid]
	mov	ecx,3
	call	json_get
	pop	r10
	jc	.none
	test	rax,rax
	jz	.search
	mov	rsi,rax
	lea	rdi,[g_jt_buf]
	mov	ecx,60
	push	r10
	call	json_string
	pop	r10
	jc	.none
	mov	ebx,eax
	test	ebx,ebx
	jz	.none
.search:
	mov	eax,[r12+AU_JSRC]
	test	eax,eax
	jnz	.by_url
	mov	eax,[r12+AU_JFIRST]
	imul	rax,rax,JK_SIZE
	lea	r9,[g_jwk+rax]
	mov	r13d,[r12+AU_JN]
	jmp	.key
.by_url:
	dec	eax
	mov	r13d,[g_jl_n+rax*4]
	imul	rax,rax,JK_PER_SET * JK_SIZE
	lea	r9,[g_jl_keys+rax]
.key:
	test	r13d,r13d
	jz	.not_here
	dec	r13d
	; what kind of key it needs
	mov	eax,[r9+JK_KIND]
	cmp	eax,r10d
	je	.fits
	cmp	eax,JA_RS256
	jne	.next
	cmp	r10d,JA_PS256
	jne	.next
.fits:
	mov	eax,[r9+JK_ALG]
	test	eax,eax
	jz	.alg_fits
	cmp	eax,r10d
	jne	.next
.alg_fits:
	test	ebx,ebx
	jz	.found				; no kid: the first of its kind
	cmp	[r9+JK_KIDL],ebx
	jne	.next
	lea	rsi,[r9+JK_KID]
	lea	rdi,[g_jt_buf]
	mov	ecx,ebx
	repe	cmpsb
	je	.found
.next:
	add	r9,JK_SIZE
	jmp	.key
.found:
	clc
	jmp	.out
.not_here:
	mov	eax,[r12+AU_JSRC]		; (from a set by URL: maybe a new key)
	test	eax,eax
	jz	.none
	dec	eax
	imul	rax,rax,KT_SIZE
	add	rax,[g_jwks_tbl]
	mov	dword [rax+KT_WANT],1
.none:
	stc
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	rbx
	ret
.n_crit	db 'crit'
.n_alg	db 'alg'
.n_kid	db 'kid'

; rsi = the signed bytes, edx = how many, r9 = the key, r10d = JA_*, ebx = the
; signature's length in g_jt_s: eax = 1 when it holds
jwt_signature:
	cmp	r10d,JA_EDDSA
	je	.ed
	push	r9
	push	r10
	cmp	r10d,JA_HS256
	je	.hs
	lea	rdi,[g_jt_dig2]
	call	sha256
	pop	r10
	pop	r9
	cmp	r10d,JA_ES256
	je	.es
	; RSA
	cmp	ebx,[r9+JK_LEN]
	jne	.no
	lea	rdi,[r9+JK_KEY]
	mov	esi,[r9+JK_LEN]
	lea	rdx,[g_jt_s]
	mov	ecx,[r9+JK_E]
	lea	r8,[g_jt_dig2]
	cmp	r10d,JA_PS256
	je	rsa_pss_verify
	jmp	rsa_pkcs1_verify
.es:
	cmp	ebx,64
	jne	.no
	lea	rdi,[r9+JK_KEY]
	lea	rsi,[g_jt_dig2]
	lea	rdx,[g_jt_s]
	lea	rcx,[g_jt_s+32]
	jmp	p256_verify
.hs:
	pop	r10
	pop	r9
	cmp	ebx,32
	jne	.no
	mov	rcx,rsi
	mov	r8d,edx
	lea	rdi,[g_jt_dig2]
	lea	rsi,[r9+JK_KEY]
	mov	edx,[r9+JK_LEN]
	call	hmac_sha256
	lea	rdi,[g_jt_dig2]
	lea	rsi,[g_jt_s]
	mov	edx,32
	jmp	ct_equal
.ed:
	cmp	ebx,64
	jne	.no
	mov	edx,edx
	lea	rdi,[r9+JK_KEY]
	lea	rcx,[g_jt_s]
	jmp	ed25519_verify
.no:
	xor	eax,eax
	ret

; r12 = the auth, g_jt_p = the claims (edx bytes): CF unless they hold. rax = exp,
; plus leeway. On success the entry (rbx) has what the backend is told.
jwt_claims:
	push	r13
	push	r14
	push	r15
	lea	r13,[g_jt_p]
	lea	r14,[g_jt_p+rdx]
	mov	rsi,r13
	mov	rdx,r14
	call	json_valid
	jc	.bad
	mov	r15d,[r12+AU_LEEWAY]
	mov	rsi,r13
	mov	rdx,r14
	lea	rdi,[.n_exp]
	mov	ecx,3
	call	json_get
	jc	.bad
	test	rax,rax
	jz	.bad				; (a token for ever: not here)
	mov	rsi,rax
	call	json_seconds
	jc	.bad
	add	rax,r15
	cmp	rax,[g_jwt_now]
	jbe	.bad
	mov	[rbx+JC_EXP],rax
	; nbf
	mov	rsi,r13
	mov	rdx,r14
	lea	rdi,[.n_nbf]
	mov	ecx,3
	call	json_get
	jc	.bad
	test	rax,rax
	jz	.iss
	mov	rsi,rax
	call	json_seconds
	jc	.bad
	sub	rax,r15
	jc	.iss
	cmp	rax,[g_jwt_now]
	ja	.bad
.iss:
	cmp	dword [r12+AU_ILEN2],0
	je	.aud
	mov	rsi,r13
	mov	rdx,r14
	lea	rdi,[.n_iss]
	mov	ecx,3
	call	json_get
	jc	.bad
	test	rax,rax
	jz	.bad
	mov	rsi,rax
	lea	rdi,[g_jt_a]
	mov	ecx,512
	call	json_string
	jc	.bad
	cmp	eax,[r12+AU_ILEN2]
	jne	.bad
	mov	ecx,eax
	lea	rdi,[g_jt_a]
	mov	rsi,[r12+AU_ISS]
	repe	cmpsb
	jne	.bad
.aud:
	cmp	dword [r12+AU_ALEN],0
	je	.told
	mov	rsi,r13
	mov	rdx,r14
	lea	rdi,[.n_aud]
	mov	ecx,3
	call	json_get
	jc	.bad
	test	rax,rax
	jz	.bad
	mov	rsi,rax
	cmp	byte [rsi],'['
	je	.aud_list
	call	.aud_is
	jc	.bad
	jne	.bad
	jmp	.told
.aud_list:
	; an array: one of them; rdx = its end
	mov	rdx,r8
	inc	rsi
.aud_next:
	call	json_ws
	cmp	rsi,rdx
	jae	.bad
	cmp	byte [rsi],']'
	je	.bad
	mov	rcx,rsi
	push	rcx
	call	json_skip_string
	pop	rcx
	jc	.bad
	mov	r8,rsi
	push	rsi
	push	rdx
	mov	rsi,rcx
	call	.aud_is
	pop	rdx
	pop	rsi
	jc	.bad
	je	.told
	call	json_ws
	cmp	rsi,rdx
	jae	.bad
	cmp	byte [rsi],','
	jne	.bad
	inc	rsi
	jmp	.aud_next
.told:
	; what the backend hears
	xor	eax,eax
	mov	[rbx+JC_HLEN],eax
	mov	[rbx+JC_NAMEL],eax
	push	rbp
	mov	ebp,[r12+AU_CN]
	mov	eax,[r12+AU_CFIRST]
	imul	rax,rax,CM_SIZE
	lea	r15,[g_claims+rax]
.claim:
	test	ebp,ebp
	jz	.claimed
	dec	ebp
	mov	rsi,r13
	mov	rdx,r14
	mov	rdi,[r15+CM_CLAIM]
	mov	ecx,[r15+CM_CLEN]
	call	json_get
	jc	.bad_rbp
	test	rax,rax
	jz	.claim_next			; not in this token: nothing said
	mov	rsi,rax
	lea	rdi,[g_jt_a]
	cmp	byte [rsi],'"'
	je	.text
	; a number or a word as it stands; objects and lists are not told
	cmp	byte [rsi],'{'
	je	.claim_next
	cmp	byte [rsi],'['
	je	.claim_next
	mov	rcx,r8
	sub	rcx,rsi
	cmp	rcx,512
	ja	.bad_rbp
	mov	rax,rcx
	rep	movsb
	jmp	.got
.text:
	mov	ecx,512
	call	json_string
	jc	.bad_rbp
.got:
	; no byte that could end a line or a field
	xor	ecx,ecx
.check:
	cmp	ecx,eax
	jae	.clean
	mov	dl,[g_jt_a+rcx]
	cmp	dl,0x20
	jb	.bad_rbp
	cmp	dl,0x7F
	je	.bad_rbp
	inc	ecx
	jmp	.check
.clean:
	; its name, for key=auth.user: the first claim told
	cmp	dword [rbx+JC_HLEN],0
	jne	.line
	mov	ecx,eax
	cmp	ecx,AUTH_NAME_MAX
	jbe	@f
	mov	ecx,AUTH_NAME_MAX
@@:
	mov	[rbx+JC_NAMEL],ecx
	lea	rdi,[rbx+JC_NAME]
	lea	rsi,[g_jt_a]
	push	rax
	rep	movsb
	pop	rax
.line:
	mov	ecx,[rbx+JC_HLEN]
	lea	rdx,[rcx+rax+4]
	mov	ecx,[r15+CM_HLEN]
	add	rdx,rcx
	cmp	rdx,JWT_HDR_MAX
	ja	.bad_rbp			; (more than it can carry: told nothing false)
	mov	edx,[rbx+JC_HLEN]
	lea	rdi,[rbx+JC_HDR+rdx]
	mov	rsi,[r15+CM_HDR]
	rep	movsb
	mov	word [rdi],': '
	add	rdi,2
	lea	rsi,[g_jt_a]
	mov	ecx,eax
	rep	movsb
	mov	word [rdi],0x0A0D
	add	rdi,2
	lea	rax,[rbx+JC_HDR]
	sub	rdi,rax
	mov	[rbx+JC_HLEN],edi
.claim_next:
	add	r15,CM_SIZE
	jmp	.claim
.claimed:
	pop	rbp
	clc
	jmp	.out
.bad_rbp:
	pop	rbp
.bad:
	stc
.out:
	pop	r15
	pop	r14
	pop	r13
	ret
; rsi at a string, r8 its end: ZF when it is the audience. CF: not a string.
.aud_is:
	lea	rdi,[g_jt_a]
	mov	ecx,512
	call	json_string
	jc	.aud_out
	cmp	eax,[r12+AU_ALEN]
	jne	.aud_differs
	mov	ecx,eax
	lea	rdi,[g_jt_a]
	mov	rsi,[r12+AU_AUD]
	repe	cmpsb
	clc
.aud_out:
	ret
.aud_differs:
	or	eax,1
	clc
	ret
.n_exp	db 'exp'
.n_nbf	db 'nbf'
.n_iss	db 'iss'
.n_aud	db 'aud'

; r12 = the auth, rsi = the field's value, ecx = its length, r15 = record: CF
; when refused. Keeps r12-r15.
jwt_check:
	push	rbx
	push	r13
	push	r14
	cmp	ecx,8
	jbe	.bad
	cmp	ecx,JWT_MAX
	ja	.bad
	mov	eax,[rsi]
	or	eax,0x20202020
	cmp	eax,'bear'
	jne	.bad
	mov	ax,[rsi+4]
	or	ax,0x2020
	cmp	ax,'er'
	jne	.bad
	cmp	byte [rsi+6],' '
	jne	.bad
	add	rsi,7
	sub	ecx,7
	mov	r13,rsi				; the token
	mov	r14d,ecx
	cmp	qword [g_jwt_now],0
	jne	@f
	call	jwt_tick
	call	jwks_tick
@@:
	lea	rdi,[g_jt_dig]
	mov	rsi,r13
	mov	edx,r14d
	call	sha256
	; seen?
	mov	eax,[g_jt_dig]
	and	eax,JC_N - 1
	shl	rax,9				; JC_SIZE
	lea	rbx,[g_jc+rax]
	mov	rax,[rbx+JC_EXP]
	test	rax,rax
	jz	.verify
	mov	ecx,[r12+AU_ID]
	cmp	[rbx+JC_AU],ecx
	jne	.verify
	mov	rdi,rbx
	lea	rsi,[g_jt_dig]
	mov	edx,32
	call	ct_equal
	test	eax,eax
	jz	.verify
	mov	rax,[rbx+JC_EXP]
	cmp	rax,[g_jwt_now]
	jbe	.expired
	jmp	.good
.expired:
	mov	qword [rbx+JC_EXP],0
	jmp	.bad
.verify:
	mov	qword [rbx+JC_EXP],0
	; head.claims.signature
	mov	rdi,r13
	mov	ecx,r14d
	mov	al,'.'
	repne	scasb
	jne	.bad
	mov	r8,rdi				; the claims
	mov	eax,r14d
	lea	rdx,[r13+rax]			; the end
	mov	rcx,rdx
	sub	rcx,rdi
	mov	al,'.'
	repne	scasb
	jne	.bad
	mov	r9,rdi				; the signature
	push	rdx
	push	r8
	push	r9
	; the head, first: it says which key
	lea	rdx,[r8-1]
	sub	rdx,r13
	cmp	rdx,2048
	ja	.bad3
	lea	rdi,[g_jt_h]
	mov	rsi,r13
	call	base64url_decode
	cmp	rax,-1
	je	.bad3
	mov	rdx,rax
	call	jwt_key
	jc	.bad3
	pop	rax				; the signature
	pop	r8
	pop	rcx				; the end
	push	r9				; the key
	push	r10				; JA_*
	push	r8
	push	rax
	; the signature's bytes
	mov	rsi,rax
	mov	rdx,rcx
	sub	rdx,rax
	cmp	rdx,1360
	ja	.bad4
	lea	rdi,[g_jt_s]
	call	base64url_decode
	cmp	rax,-1
	je	.bad4
	mov	edx,eax
	mov	rcx,[rsp]			; the signature's start
	mov	r10,[rsp+16]
	mov	r9,[rsp+24]
	push	rbx
	mov	ebx,edx
	lea	rdx,[rcx-1]
	sub	rdx,r13				; head.claims
	mov	rsi,r13
	call	jwt_signature
	pop	rbx
	cmp	eax,1
	jne	.bad4
	; signed: the claims can be read
	pop	rax
	pop	r8
	add	rsp,16
	mov	rsi,r8
	mov	rdx,rax
	dec	rdx
	sub	rdx,r8
	cmp	rdx,12288
	ja	.bad
	lea	rdi,[g_jt_p]
	call	base64url_decode
	cmp	rax,-1
	je	.bad
	mov	rdx,rax
	call	jwt_claims
	jc	.bad_entry
	; kept
	mov	rdi,rbx
	lea	rsi,[g_jt_dig]
	mov	ecx,32
	rep	movsb
	mov	eax,[r12+AU_ID]
	mov	[rbx+JC_AU],eax
.good:
	; what the head to the backend needs
	mov	rdx,[r15+H_BUF]
	mov	ecx,[rbx+JC_NAMEL]
	mov	[rdx+HB_AUTHL],ecx
	lea	rdi,[rdx+HB_AUTHN]
	lea	rsi,[rbx+JC_NAME]
	rep	movsb
	mov	ecx,[rbx+JC_HLEN]
	mov	[rdx+HB_JHLEN],ecx
	lea	rdi,[rdx+HB_JHDR]
	lea	rsi,[rbx+JC_HDR]
	rep	movsb
	clc
	jmp	.out
.bad_entry:
	mov	qword [rbx+JC_EXP],0
	jmp	.bad
.bad4:
	add	rsp,32
	jmp	.bad
.bad3:
	add	rsp,24
.bad:
	stc
.out:
	pop	r14
	pop	r13
	pop	rbx
	ret

; ------------------------------------------------------------ the configuration

; r12 = the auth, rbx = its `auth jwt` node
compile_jwt:
	push	r13
	push	r14
	push	r15
	lea	rax,[str_authorization]
	mov	[r12+AU_HDR],rax
	mov	dword [r12+AU_HLEN],13
	mov	rdi,rbx
	mov	ecx,DIR_ISSUER
	call	find_child
	test	rax,rax
	jz	@f
	mov	rax,[rax+N_ARGS]
	mov	rcx,[rax+A_VAL]
	mov	[r12+AU_ISS],rcx
	mov	ecx,[rax+A_VLEN]
	mov	[r12+AU_ILEN2],ecx
@@:
	mov	rdi,rbx
	mov	ecx,DIR_AUDIENCE
	call	find_child
	test	rax,rax
	jz	@f
	mov	rax,[rax+N_ARGS]
	mov	rcx,[rax+A_VAL]
	mov	[r12+AU_AUD],rcx
	mov	ecx,[rax+A_VLEN]
	mov	[r12+AU_ALEN],ecx
@@:
	mov	dword [r12+AU_LEEWAY],30
	mov	rdi,rbx
	mov	ecx,DIR_LEEWAY
	call	find_child
	test	rax,rax
	jz	@f
	mov	rdi,rax
	call	node_duration			; µs
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	mov	[r12+AU_LEEWAY],eax
@@:
	; claims a -> b, c -> d
	mov	eax,[g_plan_claims]
	mov	[r12+AU_CFIRST],eax
	mov	rdi,rbx
	mov	ecx,DIR_CLAIMS
	call	find_child
	test	rax,rax
	jz	.keys
	mov	r13,[rax+N_ARGS]
	mov	r14d,[rax+N_ARGC]
.claim:
	cmp	r14d,3
	jb	.claims_end
	mov	eax,[g_plan_claims]
	cmp	eax,MAX_CLAIMS
	jae	plan_bad_jwt
	inc	dword [g_plan_claims]
	imul	rax,rax,CM_SIZE
	lea	r8,[g_claims+rax]
	mov	rcx,[r13+A_VAL]
	mov	[r8+CM_CLAIM],rcx
	mov	ecx,[r13+A_VLEN]
	mov	[r8+CM_CLEN],ecx
	mov	rcx,[r13+A_SIZE+A_VAL]
	cmp	dword [r13+A_SIZE+A_VLEN],2
	jne	plan_bad_jwt
	cmp	word [rcx],'->'
	jne	plan_bad_jwt
	mov	rcx,[r13+2*A_SIZE+A_VAL]
	mov	[r8+CM_HDR],rcx
	mov	edx,[r13+2*A_SIZE+A_VLEN]
	cmp	byte [rcx+rdx-1],','		; (the comma between them)
	jne	@f
	dec	edx
@@:
	test	edx,edx
	jz	plan_bad_jwt
	mov	[r8+CM_HLEN],edx
	inc	dword [r12+AU_CN]
	add	r13,3 * A_SIZE
	sub	r14d,3
	jmp	.claim
.claims_end:
	test	r14d,r14d
	jnz	plan_bad_jwt
.keys:
	mov	rdi,rbx
	mov	ecx,DIR_JWKS
	call	find_child
	test	rax,rax
	jz	plan_bad_jwt
	mov	rcx,[rax+N_ARGS]
	mov	rsi,[rcx+A_VAL]
	cmp	dword [rcx+A_VLEN],5
	jb	.file
	cmp	dword [rsi],'http'
	jne	.file
	call	jwks_source
	pop	r15
	pop	r14
	pop	r13
	ret
.file:
	mov	rax,rcx
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,1000
	ja	plan_bad_jwt
	lea	rdi,[g_au_path]
	rep	movsb
	mov	byte [rdi],0
	lea	rdi,[g_au_path]
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	plan_bad_jwt
	lea	rdx,[rax+rdx]
	mov	rsi,rax
	mov	eax,[g_plan_jwk]
	mov	[r12+AU_JFIRST],eax
	call	jwks_load
	cmp	dword [r12+AU_JN],0
	je	plan_bad_jwt
	pop	r15
	pop	r14
	pop	r13
	ret

; rsi = a JWK set, rdx = its end, r12 = the auth: its keys
jwks_load:
	push	r13
	push	r14
	mov	r14,rdx
	mov	r13,rsi
	call	json_valid
	jc	plan_bad_jwt
	mov	rsi,r13
	mov	rdx,r14
	lea	rdi,[.n_keys]
	mov	ecx,4
	call	json_get
	jc	plan_bad_jwt
	test	rax,rax
	jz	plan_bad_jwt
	mov	rsi,rax
	cmp	byte [rsi],'['
	jne	plan_bad_jwt
	lea	r14,[r8-1]			; its ']'
	inc	rsi
.next:
	mov	rdx,r14
	call	json_ws
	cmp	rsi,r14
	jae	.done
	mov	r13,rsi
	call	json_skip_value
	jc	plan_bad_jwt
	push	rsi
	mov	rdx,rsi
	mov	rsi,r13
	call	jwk_load
	pop	rsi
	mov	rdx,r14
	call	json_ws
	cmp	rsi,r14
	jae	.done
	cmp	byte [rsi],','
	jne	plan_bad_jwt
	inc	rsi
	jmp	.next
.done:
	pop	r14
	pop	r13
	ret
.n_keys	db 'keys'

; rsi = a key's object, rdx = its end, r12 = the auth: one more, if it is for us
jwk_load:
	push	rbx
	push	r13
	push	r14
	push	r15
	mov	r13,rsi
	mov	r14,rdx
	mov	eax,[g_plan_jwk]
	cmp	eax,MAX_JWK
	jae	plan_bad_jwt
	imul	rax,rax,JK_SIZE
	lea	rbx,[g_jwk+rax]
	; use: sig, or not said
	lea	rsi,[.use]
	mov	ecx,3
	call	.text
	jc	.next_key
	test	eax,eax
	jz	.kty
	cmp	eax,3
	jne	.skip
	cmp	word [g_jw_t],'si'
	jne	.skip
	cmp	byte [g_jw_t+2],'g'
	jne	.skip
.kty:
	lea	rsi,[.kty_]
	mov	ecx,3
	call	.text
	jc	plan_bad_jwt
	mov	r15d,eax
	lea	r8,[g_jw_t]
	cmp	r15d,2
	jne	@f
	cmp	word [r8],'EC'
	je	.ec
@@:
	cmp	r15d,3
	jne	@f
	cmp	word [r8],'RS'
	jne	.not_rsa
	cmp	byte [r8+2],'A'
	je	.rsa
.not_rsa:
	cmp	word [r8],'OK'
	jne	.not_okp
	cmp	byte [r8+2],'P'
	je	.okp
.not_okp:
	cmp	word [r8],'oc'
	jne	@f
	cmp	byte [r8+2],'t'
	je	.oct
@@:
.skip:
	jmp	.next_key
.ec:
	lea	rsi,[.crv]
	mov	ecx,3
	call	.text
	jc	.skip
	cmp	eax,5
	jne	.skip
	cmp	dword [g_jw_t],'P-25'
	jne	.skip
	cmp	byte [g_jw_t+4],'6'
	jne	.skip
	mov	byte [rbx+JK_KEY],4
	lea	rsi,[.x]
	lea	rdi,[rbx+JK_KEY+1]
	mov	ecx,1
	mov	edx,32
	call	.bytes
	cmp	rax,32
	jne	plan_bad_jwt
	lea	rsi,[.y]
	lea	rdi,[rbx+JK_KEY+33]
	mov	ecx,1
	mov	edx,32
	call	.bytes
	cmp	rax,32
	jne	plan_bad_jwt
	mov	dword [rbx+JK_KIND],JA_ES256
	mov	dword [rbx+JK_LEN],65
	jmp	.common
.okp:
	lea	rsi,[.crv]
	mov	ecx,3
	call	.text
	jc	.skip
	cmp	eax,7
	jne	.skip
	cmp	dword [g_jw_t],'Ed25'
	jne	.skip
	lea	rsi,[.x]
	lea	rdi,[rbx+JK_KEY]
	mov	ecx,1
	mov	edx,32
	call	.bytes
	cmp	rax,32
	jne	plan_bad_jwt
	mov	dword [rbx+JK_KIND],JA_EDDSA
	mov	dword [rbx+JK_LEN],32
	jmp	.common
.rsa:
	lea	rsi,[.n]
	lea	rdi,[g_jw_k]
	mov	ecx,1
	mov	edx,520
	call	.bytes
	cmp	rax,-1
	je	plan_bad_jwt
	lea	rsi,[g_jw_k]
	cmp	byte [rsi],0			; (a leading zero, the sign's)
	jne	@f
	inc	rsi
	dec	rax
@@:
	test	eax,7
	jnz	plan_bad_jwt
	cmp	eax,256
	jb	plan_bad_jwt			; (under 2048 bits: not here)
	cmp	eax,JK_KEYCAP
	ja	plan_bad_jwt
	mov	[rbx+JK_LEN],eax
	lea	rdi,[rbx+JK_KEY]
	mov	ecx,eax
	rep	movsb
	lea	rsi,[.e]
	lea	rdi,[g_jw_k]
	mov	ecx,1
	mov	edx,8
	call	.bytes
	cmp	rax,4
	ja	plan_bad_jwt
	test	rax,rax
	jz	plan_bad_jwt
	xor	edx,edx
	xor	ecx,ecx
.e_byte:
	shl	edx,8
	movzx	r8d,byte [g_jw_k+rcx]
	or	edx,r8d
	inc	ecx
	cmp	ecx,eax
	jb	.e_byte
	mov	[rbx+JK_E],edx
	mov	dword [rbx+JK_KIND],JA_RS256
	jmp	.common
.oct:
	lea	rsi,[.k]
	lea	rdi,[rbx+JK_KEY]
	mov	ecx,1
	mov	edx,JK_KEYCAP
	call	.bytes
	cmp	rax,32				; (a shorter secret is guessed)
	jl	plan_bad_jwt
	mov	[rbx+JK_LEN],eax
	mov	dword [rbx+JK_KIND],JA_HS256
.common:
	; alg, kid
	lea	rsi,[.alg]
	mov	ecx,3
	call	.text
	jc	plan_bad_jwt
	xor	edx,edx
	cmp	eax,5
	jne	.alg_set
	mov	eax,[g_jw_t]
	mov	edx,JA_ES256
	cmp	eax,'ES25'
	je	.alg_set
	mov	edx,JA_RS256
	cmp	eax,'RS25'
	je	.alg_set
	mov	edx,JA_PS256
	cmp	eax,'PS25'
	je	.alg_set
	mov	edx,JA_HS256
	cmp	eax,'HS25'
	je	.alg_set
	mov	edx,JA_EDDSA
	cmp	eax,'EdDS'
	je	.alg_set
	xor	edx,edx
.alg_set:
	mov	[rbx+JK_ALG],edx
	cmp	dword [rbx+JK_KIND],JA_HS256	; a secret says what it is for
	jne	@f
	cmp	edx,JA_HS256
	jne	plan_bad_jwt
@@:
	lea	rsi,[.kid]
	mov	ecx,3
	call	.text
	jc	plan_bad_jwt
	cmp	eax,60
	ja	plan_bad_jwt
	mov	[rbx+JK_KIDL],eax
	lea	rdi,[rbx+JK_KID]
	lea	rsi,[g_jw_t]
	mov	ecx,eax
	rep	movsb
	inc	dword [g_plan_jwk]
	inc	dword [r12+AU_JN]
.next_key:
	pop	r15
	pop	r14
	pop	r13
	pop	rbx
	ret
; rsi = a name, ecx = its length: eax = its text's length in g_jw_t, 0 not there
.text:
	mov	rdi,rsi
	mov	rsi,r13
	mov	rdx,r14
	call	json_get
	jc	.text_bad
	test	rax,rax
	jz	.text_none
	mov	rsi,rax
	lea	rdi,[g_jw_t]
	mov	ecx,1024
	jmp	json_string
.text_none:
	xor	eax,eax
	clc
	ret
.text_bad:
	stc
	ret
; rsi = a name, rdi = out, edx = its room: rax = the bytes, -1 not good
.bytes:
	push	rdi
	mov	ecx,1
	push	rdx
	call	.text
	pop	rdx
	pop	rdi
	jc	.bytes_bad
	test	eax,eax
	jz	.bytes_bad
	mov	rcx,rax
	imul	rax,rdx,4
	push	rdx
	xor	edx,edx
	mov	r8d,3
	div	r8
	pop	rdx
	add	rax,4
	cmp	rcx,rax
	ja	.bytes_bad
	lea	rsi,[g_jw_t]
	mov	edx,ecx
	jmp	base64url_decode
.bytes_bad:
	mov	rax,-1
	ret
.use	db 'use'
.kty_	db 'kty'
.crv	db 'crv'
.alg	db 'alg'
.kid	db 'kid'
.x	db 'x'
.y	db 'y'
.n	db 'n'
.e	db 'e'
.k	db 'k'

plan_bad_jwt:
	cmp	qword [g_jf_sp],0
	jne	jf_parse_bad
	call	log_begin
	out_lit 'auth jwt: jwks FILE is needed, a JWK set with a key this can use: EC P-256, RSA of 2048 bits and up, Ed25519, or oct of 32 bytes and up with its alg; claims as a -> b, c -> d'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

bss
	g_jw_t:		rb 1024
	g_jw_k:		rb 528
end bss
