; Automatic HTTPS: certificates from an ACME CA (RFC 8555: Let's Encrypt, ZeroSSL,
; a CA of one's own), asked for, proven, stored and renewed by okena.
;
;   okena { acme /var/lib/okena/acme ca=https://acme-v02.api.letsencrypt.org/directory
;           [email=ops@example.com] [trust=FILE] }
;   http :443 { tls { acme example.com www.example.com } ... }
;
; Each `acme NAME...` line of a tls block is one certificate for those names,
; kept in DIR/NAME/cert.pem and DIR/NAME/key.pem (NAME the first). When they are
; there, the listener loads them as it loads `cert`; until they are, it serves a
; certificate it signs itself (7 days), so the listener is up from the start.
;
; A process of its own, okena-acme, does the asking: an account key (P-256,
; DIR/account.key, made once), requests signed as JWS (ES256), an order for the
; names, each name proven with HTTP-01, a new key and a CSR, the chain fetched.
; The proof is the workers' to give: the token and its key authorization go in a
; page the supervisor shares with every process, and any http listener (port 80,
; as the CA asks there) answers /.well-known/acme-challenge/TOKEN with it. A
; path with no token being asked for goes on to the routes.
;
; Written beside and renamed over (a reload never reads half a file), the key
; first. Then the supervisor is asked to reload, on that page: the new
; certificate is served without dropping a connection. A certificate is renewed
; when 2/3 of its life has gone; a failed order is tried again after a minute,
; then twice as long each time, up to 6 hours. The CA's address is verified as
; the control process verifies its servers (the system's roots, or trust=).

ACME_CERTS	:= 16
ACME_ALL	:= ACME_CERTS + OD_MAX	; and the on-demand ones (ondemand.inc), after them
ACME_NAMES	:= 15
ACME_URL	:= 512
ACME_BACK_MIN	:= 60
ACME_BACK_MAX	:= 6 * 3600
ACME_DAYS_SELF	:= 7

; the shared page
AH_RELOAD	:= 0			; d: the acme process asks for a reload
AH_REVSEQ	:= 4			; d: OCSP said a certificate is revoked (a futex)
AH_REVN		:= 8			; d: how many it said, ever
AH_REV		:= 16			; their tags, a ring of AH_REVS (ocsp.inc's ocsp_tag)
AH_REVS		:= 5
AH_SLOT		:= 64
AS_TLEN		:= 0			; d: the token's length, 0 a free slot (written last)
AS_KLEN		:= 4			; d
AS_TOK		:= 8
AS_KA		:= 108
AS_SIZE		:= 256
AS_TOKMAX	:= 100
ACME_TSLOT	:= 8192			; TLS-ALPN-01: a certificate a name
ACME_HSLOTS	:= ACME_NAMES * 2	; HTTP-01's: this instance's, then a fleet's (acmefleet.inc)
assert AH_SLOT + ACME_HSLOTS * AS_SIZE <= ACME_TSLOT
AX_NLEN		:= 0			; d: the name's length, 0 a free slot (written last)
AX_CLEN		:= 4			; d: the certificate_list's
AX_KEY		:= 8			; 32: d
AX_PUB		:= 40			; 65
AX_NAME		:= 112			; 256
AX_CHAIN	:= 368			; the certificate_list (one entry)
AX_SIZE		:= 1024
AX_CHAINMAX	:= AX_SIZE - AX_CHAIN
ACME_PAGE	:= (ACME_TSLOT + ACME_NAMES * AX_SIZE + 4095) and not 4095

; the plan's
ACM_ON		:= 0			; d
ACM_DIRL		:= 4			; d
ACM_DIR		:= 8			; q
ACM_CA		:= 16			; q
ACM_CAL		:= 24			; d
ACM_EMAILL	:= 28			; d
ACM_EMAIL	:= 32			; q
ACM_HASTRUST	:= 40			; d
ACM_NCERT	:= 44			; d
ACM_CERT		:= 48			; per certificate: q its names (arguments), d how many, d the https port
				; plain http redirects them to (0: not)
ACM_TRUST	:= ACM_CERT + ACME_CERTS * 16
ACM_CHAL		:= ACM_TRUST + PK_SIZE	; d: 0 HTTP-01, 1 TLS-ALPN-01, 2 DNS-01
ACM_DNS		:= ACM_CHAL + 4		; d: DNS-01's provider: 1 Cloudflare
ACM_DNSWAIT	:= ACM_CHAL + 8		; d: ms, the records left to spread
ACM_DNSAPIL	:= ACM_CHAL + 12	; d
ACM_DNSAPI	:= ACM_CHAL + 16	; q: the API's base URL
ACM_DNSTOKL	:= ACM_CHAL + 24	; d
ACM_DNSHASTRUST	:= ACM_CHAL + 28	; d
ACM_DNSTOK	:= ACM_CHAL + 32	; 256: the API token
ACM_DNSTRUST	:= ACM_CHAL + 288	; the API's anchor, dns_trust=
ACM_D2		:= ACM_DNSTRUST + PK_SIZE	; RFC 2136's:
ACM_DNSSRVL	:= ACM_D2		; d
ACM_DNSKEYNL	:= ACM_D2 + 4		; d
ACM_DNSSECL	:= ACM_D2 + 8		; d
ACM_DNSSRV	:= ACM_D2 + 16		; q: the server, HOST:PORT
ACM_DNSKEYN	:= ACM_D2 + 24		; 256: the TSIG key's name, as wire
ACM_DNSSEC	:= ACM_D2 + 280		; 64: its secret
ACM_D3		:= ACM_D2 + 344		; Route 53's: (the key id in ACM_DNSTOK, the secret in ACM_DNSSEC)
ACM_DNSSTL	:= ACM_D3		; d
ACM_DNSST	:= ACM_D3 + 8		; 2048: a session token, if one
ACM_D4		:= ACM_D3 + 8 + 2048	; the fallback CA, and the external accounts:
ACM_FBL		:= ACM_D4		; d: fallback=, 0 none
ACM_FBHASTRUST	:= ACM_D4 + 4		; d
ACM_FB		:= ACM_D4 + 8		; q
ACM_EABKL	:= ACM_D4 + 16		; d: eab='s key id, 0 none
ACM_EABHL	:= ACM_D4 + 20		; d: its HMAC key's
ACM_FBEABKL	:= ACM_D4 + 24		; d: fallback_eab='s
ACM_FBEABHL	:= ACM_D4 + 28		; d
ACM_EABK	:= ACM_D4 + 32		; 128
ACM_EABH	:= ACM_D4 + 160		; 64
ACM_FBEABK	:= ACM_D4 + 224		; 128
ACM_FBEABH	:= ACM_D4 + 352		; 64
ACM_FBTRUST	:= ACM_D4 + 416		; fallback_trust='s anchor
ACM_SHARED	:= ACM_FBTRUST + PK_SIZE	; d: shared=on (acmefleet.inc)
ACM_REDIRN	:= ACM_SHARED + 4	; d: certificates whose names plain http redirects
ACM_STGL	:= ACM_REDIRN + 4	; d: staging='s (acmeauto.inc), 0 none
ACM_STG		:= ACM_REDIRN + 8	; q
ACM_SIZE		:= (ACM_STG + 8 + 7) and not 7

SYS_fchownat_	:= 260
LLF_REMOVE_FILE	:= 32
LLF_MAKE_DIR	:= 128

bss
	align 8
	g_plan_acme:	rb ACM_SIZE
	g_acme_page	dq ?			; shared: the reload asked for, the challenges
	g_acme_pid	dd ?
	; the compiler's: a certificate's files, or the one signed here
	g_ac_carg:	rb A_SIZE
	g_ac_karg:	rb A_SIZE
	g_ac_cpath:	rb 600
	g_ac_kpath:	rb 600
	g_ac_kpem:	rb 600
	g_ac_cur	dq ?			; compile_tls_acme: a certificate's names
	g_ac_curn	dd ?
	g_ac_redir	dd ?
	g_ac_names:	rb 4096			; NUL between them, an empty one at the end
	; the acme process's
	align 8
	g_ac_due	rq ACME_ALL		; realtime second: when to renew, -1 to look
	g_ac_back	rq ACME_ALL		; the last wait after a failure
	g_ac_end	rq ACME_ALL		; its certificate's notAfter
	g_ac_why	dq ?			; what failed (NUL-ended)
	g_ac_auth	dq ?			; the URL being asked: host[:port]
	g_ac_path	dq ?			; and its path
	g_ac_rb		dq ?			; the answer's body
	g_ac_authl	dd ?
	g_ac_pathl	dd ?
	g_ac_hostl	dd ?
	g_ac_port	dd ?
	g_ac_st		dd ?			; the answer's status
	g_ac_rbl	dd ?
	g_ac_payl	dd ?
	g_ac_jwkl	dd ?
	g_ac_noncel	dd ?
	g_ac_locl	dd ?
	g_ac_kidl	dd ?
	g_ac_unoncel	dd ?
	g_ac_uacctl	dd ?
	g_ac_uorderl	dd ?
	g_ac_ordl	dd ?
	g_ac_finl	dd ?
	g_ac_crtl	dd ?
	g_ac_chall	dd ?
	g_ac_tokl	dd ?
	g_ac_nauthz	dd ?
	g_ac_reload	dd ?
	g_ac_authzl	rd ACME_NAMES
	g_ac_d:		rb 32			; the account's key
	g_ac_pub:	rb 65
	g_ac_hash:	rb 32
	g_ac_sig:	rb 64
	g_ac_word:	rb 32
	g_ac_thumb:	rb 48
	g_ac_kah:	rb 32			; TLS-ALPN-01: the key authorization's hash
	g_ac_identl	dd ?
	g_ac_ident:	rb 256			; the authorization's name
	g_ac_ka:	rb 256
	; DNS-01: per authorization, its record (zone and id) and its challenge
	g_ac_dns	dd ?			; this request is the DNS API's
	align 8
	g_ac_meth	dq ?			; its method (cstr), 0: GET or POST
	g_ac_dzonel	rd ACME_NAMES
	g_ac_didl	rd ACME_NAMES
	g_ac_dpost	rd ACME_NAMES
	g_ac_dchall	rd ACME_NAMES
	g_ac_dzone:	rb 64 * ACME_NAMES
	g_ac_did:	rb 64 * ACME_NAMES
	g_ac_dchal:	rb ACME_URL * ACME_NAMES
	g_ac_txt:	rb 64
	g_ac_dnamel	rd ACME_NAMES
	g_ac_failed:	rb ACME_ALL		; the last order failed: staging first
	g_ac_cai	dd ?			; the CA being asked: 0 ca=, 1 fallback=, 2 staging= (nothing kept)
	; ARI (RFC 9773): per certificate, its CertID and when to ask again
	align 8
	g_ac_arinext	rq ACME_ALL
	g_ac_retry	dq ?			; the answer's Retry-After (s), 0 none
	g_ac_certidl	rd ACME_ALL
	g_ac_arigot	rd ACME_ALL		; the CA answered for it: an order "replaces" it
	g_ac_derl	dd ?
	g_ac_rinfol	dd ?
	g_ac_certid:	rb 128 * ACME_ALL
	g_ac_rinfo:	rb ACME_URL
	g_ac_t14:	rb 16
	g_ac_tag	rq ACME_ALL		; each certificate's tag (its leaf's SHA-256, 8 bytes)
	g_ac_revdone	rq ACME_ALL		; a revocation already acted on
	g_ac_eabreq	dd ?			; its directory says externalAccountRequired
	g_ac_dchgl	rd ACME_NAMES
	g_ac_dchg:	rb 64 * ACME_NAMES	; (Route 53: each change, until INSYNC)
	align 8
	g_ac_xhdr	dq ?			; the DNS API's own header lines, and its
	g_ac_ctype	dq ?			; content type (cstr)
	g_ac_xhdrl	dd ?
	g_r53_date:	rb 20			; YYYYMMDDTHHMMSSZ
	g_r53_key:	rb 80
	g_r53_mac:	rb 32
	g_r53_sig:	rb 72
	g_r53_creq:	rb 4096
	g_r53_sts:	rb 256
	g_ac_xbuf:	rb 4096
	g_ac_dname:	rb 256 * ACME_NAMES	; (RFC 2136: each authorization's name)
	g_dn_idx	dd ?			; the authorization being updated
	g_dn_mode	dd ?			; 0 add, 1 delete
	g_dn_zone	dq ?			; its zone
	g_dn_zonel	dd ?
	g_dn_len	dd ?			; the message's (and then the answer's) length
	g_dn_id		dw ?
	g_dn_rmac:	rb 32			; the request's MAC
	g_dn_hash:	rb 32
	g_dn_msg:	rb 2048			; (2 bytes of length first: TCP)
	g_dn_resp:	rb 4096
	g_dn_dig:	rb 4200
	g_ac_rname:	rb 300
	g_ac_durl:	rb 1024
	g_acme_tl:	rb TL_SIZE		; a worker: the challenge's certificate, copied
	g_ac_jwk:	rb 160
	g_ac_host:	rb 256
	g_ac_sa:	rb 128
	g_ac_nonce:	rb 256
	g_ac_tok:	rb 128
	g_ac_loc:	rb ACME_URL
	g_ac_kid:	rb ACME_URL
	g_ac_unonce:	rb ACME_URL
	g_ac_uacct:	rb ACME_URL
	g_ac_uorder:	rb ACME_URL
	g_ac_ord:	rb ACME_URL
	g_ac_fin:	rb ACME_URL
	g_ac_crt:	rb ACME_URL
	g_ac_chal:	rb ACME_URL
	g_ac_authz:	rb ACME_URL * ACME_NAMES
	g_ac_fpath:	rb 600
	g_ac_tmp:	rb 600
	g_ac_prot:	rb 2048
	g_ac_pay:	rb 8192
	g_ac_b64:	rb 16384
	g_ac_body:	rb 24576
	g_ac_req:	rb 32768
	g_ac_file:	rb 65536
	g_ac_der:	rb 16384
end bss

rodata
	acme_name	db 'okena-acme',0
	acme_wk		db '/.well-known/acme-challenge/'
	acme_wk.len = $ - acme_wk
end rodata

; ------------------------------------------------------------ the supervisor

; the shared page, once, before any fork
acme_page_init:
	cmp	qword [g_od_page],0
	jne	@f
	xor	edi,edi				; (ondemand.inc's)
	mov	esi,OD_PAGE
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_ANONYMOUS
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	@f
	mov	[g_od_page],rax
@@:
	cmp	qword [g_acme_page],0
	jne	.out
	xor	edi,edi
	mov	esi,ACME_PAGE
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_ANONYMOUS
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.out
	mov	[g_acme_page],rax
.out:
	ret

spawn_acme:
	cmp	dword [g_plan_acme+ACM_ON],0
	je	.none
	mov	eax,[g_plan_acme+ACM_NCERT]
	or	eax,[g_plan_odn]
	jz	.none
	cmp	qword [g_acme_page],0
	je	.none
	mov	eax,SYS_fork
	syscall
	test	rax,rax
	jz	acme_main
	js	.none
	mov	[g_acme_pid],eax
.none:
	ret

; a reload: the one running goes (its work is on disk), a new one looks again
acme_reload:
	mov	edi,[g_acme_pid]
	test	edi,edi
	jz	spawn_acme
	mov	dword [g_acme_pid],0
	call	acme_stop
	jmp	spawn_acme

; edi = the pid: gone (its signals are blocked, as the supervisor's: SIGKILL)
acme_stop:
	push	rbx
	mov	ebx,edi
	mov	esi,SIGKILL
	mov	eax,SYS_kill
	syscall
@@:
	mov	edi,P_PID
	mov	esi,ebx
	lea	rdx,[g_siginfo]
	mov	r10d,WEXITED
	xor	r8d,r8d
	mov	eax,SYS_waitid
	syscall
	cmp	rax,-EINTR
	je	@b
	pop	rbx
	ret

; once a second: eax = 1 when the acme process asks for a reload
acme_tick:
	mov	rcx,[g_acme_page]
	xor	eax,eax
	test	rcx,rcx
	jz	.out
	xchg	eax,[rcx+AH_RELOAD]
	test	eax,eax
	jz	.out
	push	rax
	call	log_begin
	out_lit 'acme: a new certificate: reloading'
	call	log_end
	pop	rax
.out:
	ret

; ---------------------------------------------------------------- workers

; ebx = session, r15 = state, g_hm the request: rax = the challenge's slot when
; it is a GET (or HEAD) of /.well-known/acme-challenge/TOKEN for a token being
; asked for, else 0. Keeps rbx, rdx, r10-r15.
acme_challenge:
	xor	eax,eax
	cmp	dword [g_plan_acme+ACM_ON],0
	je	.out
	mov	r9,[g_acme_page]
	test	r9,r9
	jz	.out
	lea	r8,[g_hm]
	mov	ecx,[r8+HM_TLEN]
	sub	ecx,acme_wk.len
	jbe	.out
	cmp	ecx,AS_TOKMAX
	ja	.out
	mov	rsi,[r8+HM_METHOD]
	cmp	dword [r8+HM_MLEN],3
	jne	@f
	cmp	word [rsi],'GE'
	jne	.out
	cmp	byte [rsi+2],'T'
	jne	.out
	jmp	.method
@@:
	test	dword [r15+H_FLAGS],HX_HEAD
	jz	.out
.method:
	mov	rsi,[r8+HM_TARGET]
	lea	rdi,[acme_wk]
	push	rcx
	mov	ecx,acme_wk.len
	repe	cmpsb
	pop	rcx
	jne	.out
	; rsi/ecx = the token asked for
	lea	r9,[r9+AH_SLOT]
	mov	r8d,ACME_HSLOTS
.slot:
	cmp	[r9+AS_TLEN],ecx
	jne	.next
	push	rsi
	push	rcx
	lea	rdi,[r9+AS_TOK]
	repe	cmpsb
	pop	rcx
	pop	rsi
	jne	.next
	mov	rax,r9
	ret
.next:
	add	r9,AS_SIZE
	dec	r8d
	jnz	.slot
	xor	eax,eax
.out:
	ret

; TLS-ALPN-01, in a handshake that offers ALPN acme-tls/1: rsi/edx = the SNI.
; rax = an entry (g_acme_tl, its chain past g_tls_store) with the certificate
; the acme process made for that name, or 0. Keeps rbx, rbp, r10-r15.
acme_tls_cert:
	xor	eax,eax
	cmp	dword [g_plan_acme+ACM_ON],0
	je	.out
	mov	r9,[g_acme_page]
	test	r9,r9
	jz	.out
	lea	r9,[r9+ACME_TSLOT]
	mov	r8d,ACME_NAMES
.slot:
	cmp	[r9+AX_NLEN],edx
	jne	.next
	push	rsi
	mov	ecx,edx
	lea	rdi,[r9+AX_NAME]
	repe	cmpsb
	pop	rsi
	jne	.next
	mov	ecx,[r9+AX_CLEN]
	cmp	ecx,AX_CHAINMAX
	ja	.next
	lea	rdi,[g_acme_tl]
	mov	[rdi+TL_CLEN],ecx
	mov	dword [rdi+TL_CHAIN],TLS_STORE
	mov	dword [rdi+TL_KEYTYPE],0
	mov	dword [rdi+TL_ALT],-1
	mov	dword [rdi+TL_GROUP],-1
	push	rsi
	lea	rsi,[r9+AX_CHAIN]
	lea	rdi,[g_acme_chain]
	rep	movsb
	lea	rsi,[r9+AX_KEY]
	lea	rdi,[g_acme_tl+TL_KEY]
	mov	ecx,32
	rep	movsb
	lea	rsi,[r9+AX_PUB]
	lea	rdi,[g_acme_tl+TL_PUB]
	mov	ecx,65
	rep	movsb
	pop	rsi
	cmp	[r9+AX_NLEN],edx		; (not rewritten while it was copied)
	jne	.next
	lea	rax,[g_acme_tl]
	ret
.next:
	add	r9,AX_SIZE
	dec	r8d
	jnz	.slot
	xor	eax,eax
.out:
	ret

; rax = the slot: its key authorization, as text/plain, the connection kept.
; ebx = session, r15 = state.
acme_answer:
	push	r12
	mov	r12,rax
	or	dword [r15+H_FLAGS],HX_SELF or HX_STARTED
	cmp	dword [r15+H_RIDLEN],0
	jne	@f
	call	rid_new
@@:
	mov	dword [r15+H_STATUS],200
	mov	edi,200
	mov	esi,5
	call	http_count
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_OUT]
	memit_x 'HTTP/1.1 200 OK',13,10,'Content-Type: text/plain',13,10,'Cache-Control: no-store',13,10,'Content-Length: '
	mov	eax,[r12+AS_KLEN]
	call	fmt_u64
	memit_x 13,10,'X-Request-Id: '
	lea	rsi,[r15+H_RID]
	mov	ecx,[r15+H_RIDLEN]
	rep	movsb
	memit_x 13,10
	test	dword [r15+H_FLAGS],HX_CLOSE
	jz	@f
	memit_x 'Connection: close',13,10
@@:
	memit_x 13,10
	test	dword [r15+H_FLAGS],HX_HEAD
	jnz	@f
	lea	rsi,[r12+AS_KA]
	mov	ecx,[r12+AS_KLEN]
	rep	movsb
@@:
	mov	rsi,[r15+H_BUF]
	lea	rsi,[rsi+HB_OUT]
	sub	rdi,rsi
	mov	dword [r15+H_STATE],HS_SELF_SEND
	mov	ecx,SIDE_CLIENT
	xchg	rsi,rdi
	pop	r12
	jmp	h_send

; --------------------------------------------------------------- compiling

; okena { acme DIR ca=URL [email=ADDRESS] [trust=FILE] }, rbx = the node
compile_acme:
	mov	rax,[rbx+N_ARGS]
	mov	rcx,[rax+A_VAL]
	mov	edx,[rax+A_VLEN]
	cmp	edx,2
	jb	.bad
	cmp	edx,200
	ja	.bad
	cmp	byte [rcx],'/'
	jne	.bad
	cmp	byte [rcx+rdx-1],'/'
	jne	@f
	dec	edx				; (no '/' at its end)
@@:
	mov	[g_plan_acme+ACM_DIR],rcx
	mov	[g_plan_acme+ACM_DIRL],edx
	mov	rdi,rbx
	cstring .k_ca, 'ca',0
	lea	rsi,[.k_ca]
	call	node_option
	test	rax,rax
	jz	.bad
	mov	rcx,[rax+A_VAL]
	mov	edx,[rax+A_VLEN]
	cmp	edx,ACME_URL - 1
	ja	.bad
	cmp	edx,9
	jb	.bad
	mov	rsi,'https://'
	cmp	[rcx],rsi
	jne	.bad
	mov	rsi,rcx
	mov	ecx,edx
	call	acme_safe
	jc	.bad
	mov	rcx,[rax+A_VAL]
	mov	[g_plan_acme+ACM_CA],rcx
	mov	[g_plan_acme+ACM_CAL],edx
	mov	rdi,rbx
	cstring .k_email, 'email',0
	lea	rsi,[.k_email]
	call	node_option
	test	rax,rax
	jz	.trust
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	test	ecx,ecx
	jz	.bad
	cmp	ecx,200
	ja	.bad
	mov	[g_plan_acme+ACM_EMAIL],rsi
	mov	[g_plan_acme+ACM_EMAILL],ecx
	call	acme_safe
	jc	.bad
.trust:
	mov	rdi,rbx
	lea	rsi,[str_key_trust]
	call	node_option
	test	rax,rax
	jz	.chal
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,4096
	jae	.bad
	lea	rdi,[g_trust_path]
	push	rcx
	rep	movsb
	pop	rcx
	mov	byte [g_trust_path+rcx],0
	lea	rdi,[g_trust_path]
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	plan_bad_trust
	mov	rsi,rax
	lea	rdi,[g_trust_der]
	call	pem_first_cert
	test	eax,eax
	jz	plan_bad_trust
	lea	rsi,[g_trust_der]
	mov	edx,eax
	lea	rdi,[g_plan_acme+ACM_TRUST]
	call	cert_pubkey
	test	eax,eax
	jz	plan_bad_trust
	mov	dword [g_plan_acme+ACM_HASTRUST],1
.chal:
	call	compile_acme_more		; fallback=, fallback_trust=, eab=, fallback_eab=
	mov	rdi,rbx				; challenge=http-01 (by default) or tls-alpn-01
	cstring .k_chal, 'challenge',0
	lea	rsi,[.k_chal]
	call	node_option
	test	rax,rax
	jz	.ok
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,7
	jne	.not_http
	cmp	dword [rsi],'http'
	jne	.bad
	cmp	word [rsi+4],'-0'
	jne	.bad
	cmp	byte [rsi+6],'1'
	jne	.bad
	jmp	.ok
.not_http:
	cmp	ecx,6
	jne	.not_dns
	cmp	dword [rsi],'dns-'
	jne	.bad
	cmp	word [rsi+4],'01'
	jne	.bad
	mov	dword [g_plan_acme+ACM_CHAL],2
	call	compile_acme_dns
	jmp	.ok
.not_dns:
	cmp	ecx,11
	jne	.bad
	mov	rdx,'tls-alpn'
	cmp	[rsi],rdx
	jne	.bad
	cmp	word [rsi+8],'-0'
	jne	.bad
	cmp	byte [rsi+10],'1'
	jne	.bad
	mov	dword [g_plan_acme+ACM_CHAL],1
	cmp	dword [g_plan_acme+ACM_SHARED],0
	je	.ok
	call	log_begin
	out_lit 'acme: challenge=tls-alpn-01 cannot be shared (the handshake',39,'s certificate is on one instance): http-01 or dns-01 with shared=on'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
.ok:
	mov	dword [g_plan_acme+ACM_ON],1
	ret
.bad:
	call	log_begin
	out_lit 'acme takes a directory (its whole path, 200 bytes at most), ca=URL (https://, the CA',39,'s directory), and, if wanted, email=ADDRESS, trust=FILE and challenge=http-01|tls-alpn-01|dns-01'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; rbx = the acme node: fallback=URL (another CA, asked when the first fails),
; fallback_trust=FILE, eab=FILE and fallback_eab=FILE (KID:HMAC_KEY, base64url:
; an external account binding, RFC 8555 7.3.4, as ZeroSSL and others ask)
compile_acme_more:
	mov	rdi,rbx
	cstring .k_fb, 'fallback',0
	lea	rsi,[.k_fb]
	call	node_option
	test	rax,rax
	jz	.eab
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,9
	jb	.bad
	cmp	ecx,ACME_URL - 1
	ja	.bad
	mov	rdx,'https://'
	cmp	[rsi],rdx
	jne	.bad
	call	acme_safe
	jc	.bad
	mov	[g_plan_acme+ACM_FB],rsi
	mov	[g_plan_acme+ACM_FBL],ecx
	mov	rdi,rbx
	cstring .k_fbt, 'fallback_trust',0
	lea	rsi,[.k_fbt]
	call	node_option
	test	rax,rax
	jz	.eab
	lea	rdi,[g_plan_acme+ACM_FBTRUST]
	call	acme_anchor
	mov	dword [g_plan_acme+ACM_FBHASTRUST],1
.eab:
	mov	rdi,rbx
	cstring .k_eab, 'eab',0
	lea	rsi,[.k_eab]
	call	node_option
	test	rax,rax
	jz	@f
	lea	rdi,[g_plan_acme+ACM_EABK]
	call	acme_eab_file
	mov	[g_plan_acme+ACM_EABKL],ecx
	mov	[g_plan_acme+ACM_EABHL],edx
@@:
	mov	rdi,rbx
	cstring .k_fbeab, 'fallback_eab',0
	lea	rsi,[.k_fbeab]
	call	node_option
	test	rax,rax
	jz	@f
	cmp	dword [g_plan_acme+ACM_FBL],0
	je	.bad
	lea	rdi,[g_plan_acme+ACM_FBEABK]
	call	acme_eab_file
	mov	[g_plan_acme+ACM_FBEABKL],ecx
	mov	[g_plan_acme+ACM_FBEABHL],edx
@@:
	call	compile_acme_staging		; staging=URL (acmeauto.inc)
	mov	rdi,rbx				; shared=on: a fleet's directory (acmefleet.inc)
	cstring .k_shared, 'shared',0
	lea	rsi,[.k_shared]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rsi,[rax+A_VAL]
	cmp	dword [rax+A_VLEN],3
	je	.shared_off
	cmp	dword [rax+A_VLEN],2
	jne	.bad_shared
	cmp	word [rsi],'on'
	jne	.bad_shared
	mov	dword [g_plan_acme+ACM_SHARED],1
	jmp	@f
.shared_off:
	cmp	word [rsi],'of'
	jne	.bad_shared
	cmp	byte [rsi+2],'f'
	jne	.bad_shared
@@:
	ret
.bad_shared:
	call	log_begin
	out_lit 'acme: shared= is on or off'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
.bad:
	call	log_begin
	out_lit 'acme: fallback= is another CA',39,'s directory (https://), and fallback_trust= and fallback_eab= go with it'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; rax = an option naming a PEM file: its first certificate's key into rdi (an
; anchor). Exits when it cannot be.
acme_anchor:
	push	rdi
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,4096
	jae	plan_bad_trust
	lea	rdi,[g_trust_path]
	push	rcx
	rep	movsb
	pop	rcx
	mov	byte [g_trust_path+rcx],0
	lea	rdi,[g_trust_path]
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	plan_bad_trust
	mov	rsi,rax
	lea	rdi,[g_trust_der]
	call	pem_first_cert
	test	eax,eax
	jz	plan_bad_trust
	lea	rsi,[g_trust_der]
	mov	edx,eax
	pop	rdi
	call	cert_pubkey
	test	eax,eax
	jz	plan_bad_trust
	ret

; rax = an option naming a file, KID:HMAC_KEY (the key base64url, or base64),
; rdi = where: the key id there, the key 128 bytes on. ecx = the id's length,
; edx = the key's. Exits when it is not one.
acme_eab_file:
	push	rbx
	push	r12
	mov	r12,rdi
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,4096
	jae	.bad
	lea	rdi,[g_trust_path]
	push	rcx
	rep	movsb
	pop	rcx
	mov	byte [g_trust_path+rcx],0
	lea	rdi,[g_trust_path]
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	.bad
	mov	rsi,rax
	xor	ecx,ecx				; the line
@@:
	cmp	ecx,edx
	jae	@f
	cmp	byte [rsi+rcx],0x21
	jb	@f
	inc	ecx
	jmp	@b
@@:
	xor	ebx,ebx				; KID up to ':'
@@:
	cmp	ebx,ecx
	jae	.bad
	cmp	byte [rsi+rbx],':'
	je	@f
	inc	ebx
	jmp	@b
@@:
	test	ebx,ebx
	jz	.bad
	cmp	ebx,127
	ja	.bad
	push	rcx
	mov	ecx,ebx
	call	acme_safe
	pop	rcx
	jc	.bad
	push	rsi
	push	rcx
	mov	rdi,r12
	push	rcx
	mov	ecx,ebx
	rep	movsb
	pop	rcx
	pop	rcx
	pop	rsi
	lea	rsi,[rsi+rbx+1]
	sub	ecx,ebx
	dec	ecx
	jz	.bad
	cmp	ecx,90
	ja	.bad
	push	rsi
	push	rcx
	lea	rdi,[r12+128]
	mov	edx,ecx
	call	base64url_decode
	pop	rcx
	pop	rsi
	test	rax,rax
	jg	.ok
	lea	rdi,[r12+128]
	mov	edx,ecx
	call	base64_decode
	test	rax,rax
	jle	.bad
.ok:
	cmp	eax,64
	ja	.bad
	mov	edx,eax
	mov	ecx,ebx
	pop	r12
	pop	rbx
	ret
.bad:
	call	log_begin
	out_lit 'acme: eab= and fallback_eab= name a file with one line, KID:HMAC_KEY (the key base64url, 64 bytes at most), as the CA gave them'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; challenge=dns-01's options, rbx = the node: dns=cloudflare, dns_token=FILE (the
; API token, alone in it), dns_api=URL, dns_wait=TIME (20 s), dns_trust=FILE
compile_acme_dns:
	mov	rdi,rbx
	cstring .k_dns, 'dns',0
	lea	rsi,[.k_dns]
	call	node_option
	test	rax,rax
	jz	.bad
	mov	rsi,[rax+A_VAL]
	cmp	dword [rax+A_VLEN],7
	jne	@f
	cmp	dword [rsi],'rout'
	jne	.not_r53
	cmp	word [rsi+4],'e5'
	jne	.bad
	cmp	byte [rsi+6],'3'
	jne	.bad
	jmp	compile_acme_route53
.not_r53:
	cmp	dword [rsi],'rfc2'
	jne	.bad
	cmp	word [rsi+4],'13'
	jne	.bad
	cmp	byte [rsi+6],'6'
	jne	.bad
	jmp	compile_acme_rfc2136
@@:
	cmp	dword [rax+A_VLEN],10
	jne	.bad
	mov	rdx,'cloudfla'
	cmp	[rsi],rdx
	jne	.bad
	cmp	word [rsi+8],'re'
	jne	.bad
	mov	dword [g_plan_acme+ACM_DNS],1
	cstring .api_cf, 'https://api.cloudflare.com/client/v4'
	lea	rax,[.api_cf]
	mov	[g_plan_acme+ACM_DNSAPI],rax
	mov	dword [g_plan_acme+ACM_DNSAPIL],36
	mov	dword [g_plan_acme+ACM_DNSWAIT],20000
	mov	rdi,rbx
	cstring .k_api, 'dns_api',0
	lea	rsi,[.k_api]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,9
	jb	.bad
	cmp	ecx,200
	ja	.bad
	mov	rdx,'https://'
	cmp	[rsi],rdx
	jne	.bad
	call	acme_safe
	jc	.bad
	cmp	byte [rsi+rcx-1],'/'		; (no '/' at its end)
	jne	.api
	dec	ecx
.api:
	mov	[g_plan_acme+ACM_DNSAPI],rsi
	mov	[g_plan_acme+ACM_DNSAPIL],ecx
@@:
	mov	rdi,rbx
	cstring .k_wait, 'dns_wait',0
	lea	rsi,[.k_wait]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_duration
	jc	.bad
	xor	edx,edx
	mov	ecx,1000
	div	rcx				; us -> ms
	cmp	rax,600000
	ja	.bad
	mov	[g_plan_acme+ACM_DNSWAIT],eax
@@:
	; the token: a file's first line
	mov	rdi,rbx
	cstring .k_tok, 'dns_token',0
	lea	rsi,[.k_tok]
	call	node_option
	test	rax,rax
	jz	.bad
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,4096
	jae	.bad
	lea	rdi,[g_trust_path]
	push	rcx
	rep	movsb
	pop	rcx
	mov	byte [g_trust_path+rcx],0
	lea	rdi,[g_trust_path]
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	.no_token
	xor	ecx,ecx
@@:
	cmp	ecx,edx
	jae	@f
	cmp	byte [rax+rcx],0x21
	jb	@f
	cmp	byte [rax+rcx],0x7E
	ja	.no_token
	inc	ecx
	jmp	@b
@@:
	test	ecx,ecx
	jz	.no_token
	cmp	ecx,255
	ja	.no_token
	mov	[g_plan_acme+ACM_DNSTOKL],ecx
	mov	rsi,rax
	lea	rdi,[g_plan_acme+ACM_DNSTOK]
	rep	movsb
	; dns_trust=: the API's anchor (else the system's roots)
.dns_trust:
	mov	rdi,rbx
	cstring .k_dtrust, 'dns_trust',0
	lea	rsi,[.k_dtrust]
	call	node_option
	test	rax,rax
	jz	.ok
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,4096
	jae	.bad
	lea	rdi,[g_trust_path]
	push	rcx
	rep	movsb
	pop	rcx
	mov	byte [g_trust_path+rcx],0
	lea	rdi,[g_trust_path]
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	plan_bad_trust
	mov	rsi,rax
	lea	rdi,[g_trust_der]
	call	pem_first_cert
	test	eax,eax
	jz	plan_bad_trust
	lea	rsi,[g_trust_der]
	mov	edx,eax
	lea	rdi,[g_plan_acme+ACM_DNSTRUST]
	call	cert_pubkey
	test	eax,eax
	jz	plan_bad_trust
	mov	dword [g_plan_acme+ACM_DNSHASTRUST],1
.ok:
	ret
.no_token:
	call	log_begin
	out_lit 'acme: dns_token= names a file that holds the DNS API',39,'s token (its first line, 255 bytes at most)'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
.bad:
	call	log_begin
	out_lit 'acme challenge=dns-01 takes dns=cloudflare and dns_token=FILE, and, if wanted, dns_api=https://URL, dns_wait= (10 min at most) and dns_trust=FILE'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; dns=rfc2136 dns_server=HOST:PORT dns_key=FILE [dns_wait=TIME], rbx = the node.
; The key file: one line, [hmac-sha256:]NAME:SECRET (base64), as nsupdate -y.
compile_acme_rfc2136:
	mov	dword [g_plan_acme+ACM_DNS],2
	mov	dword [g_plan_acme+ACM_DNSWAIT],20000
	mov	rdi,rbx
	lea	rsi,[compile_acme_dns.k_wait]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_duration
	jc	.bad
	xor	edx,edx
	mov	ecx,1000
	div	rcx
	cmp	rax,600000
	ja	.bad
	mov	[g_plan_acme+ACM_DNSWAIT],eax
@@:
	mov	rdi,rbx
	cstring .k_srv, 'dns_server',0
	lea	rsi,[.k_srv]
	call	node_option
	test	rax,rax
	jz	.bad
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,3
	jb	.bad
	cmp	ecx,255
	ja	.bad
	mov	[g_plan_acme+ACM_DNSSRV],rsi
	mov	[g_plan_acme+ACM_DNSSRVL],ecx
	; the key
	mov	rdi,rbx
	cstring .k_key, 'dns_key',0
	lea	rsi,[.k_key]
	call	node_option
	test	rax,rax
	jz	.bad
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,4096
	jae	.bad
	lea	rdi,[g_trust_path]
	push	rcx
	rep	movsb
	pop	rcx
	mov	byte [g_trust_path+rcx],0
	lea	rdi,[g_trust_path]
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	.no_key
	mov	rsi,rax
	xor	ecx,ecx				; the line
@@:
	cmp	ecx,edx
	jae	@f
	cmp	byte [rsi+rcx],0x21
	jb	@f
	inc	ecx
	jmp	@b
@@:
	cmp	ecx,12
	jb	@f
	mov	rax,'hmac-sha'
	cmp	[rsi],rax
	jne	@f
	cmp	dword [rsi+8],'256:'
	jne	@f
	add	rsi,12
	sub	ecx,12
@@:
	; NAME:SECRET
	xor	edx,edx
@@:
	cmp	edx,ecx
	jae	.no_key
	cmp	byte [rsi+rdx],':'
	je	@f
	inc	edx
	jmp	@b
@@:
	test	edx,edx
	jz	.no_key
	cmp	edx,200
	ja	.no_key
	push	rsi
	push	rcx
	push	rdx
	lea	rdi,[g_plan_acme+ACM_DNSKEYN]
	mov	ecx,edx
	call	dns_wire_name
	lea	rax,[g_plan_acme+ACM_DNSKEYN]
	sub	rdi,rax
	mov	[g_plan_acme+ACM_DNSKEYNL],edi
	pop	rdx
	pop	rcx
	pop	rsi
	lea	rsi,[rsi+rdx+1]
	sub	ecx,edx
	dec	ecx
	jz	.no_key
	cmp	ecx,88
	ja	.no_key
	lea	rdi,[g_plan_acme+ACM_DNSSEC]
	mov	edx,ecx
	call	base64_decode
	test	rax,rax
	jle	.no_key
	mov	[g_plan_acme+ACM_DNSSECL],eax
	ret
.no_key:
	call	log_begin
	out_lit 'acme: dns_key= names a file with one line, [hmac-sha256:]NAME:SECRET (base64, 64 bytes at most), as nsupdate -y takes it'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
.bad:
	call	log_begin
	out_lit 'acme dns=rfc2136 takes dns_server=HOST:PORT and dns_key=FILE, and, if wanted, dns_wait= (10 min at most)'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; dns=route53 dns_key=FILE [dns_api=URL] [dns_wait=TIME] [dns_trust=FILE], rbx =
; the node. The key file: one line, ACCESS_KEY_ID:SECRET[:SESSION_TOKEN].
compile_acme_route53:
	mov	dword [g_plan_acme+ACM_DNS],3
	cstring .api_r53, 'https://route53.amazonaws.com'
	lea	rax,[.api_r53]
	mov	[g_plan_acme+ACM_DNSAPI],rax
	mov	dword [g_plan_acme+ACM_DNSAPIL],29
	mov	dword [g_plan_acme+ACM_DNSWAIT],20000
	mov	rdi,rbx
	lea	rsi,[compile_acme_dns.k_api]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,9
	jb	.bad
	cmp	ecx,200
	ja	.bad
	mov	rdx,'https://'
	cmp	[rsi],rdx
	jne	.bad
	call	acme_safe
	jc	.bad
	cmp	byte [rsi+rcx-1],'/'
	jne	.api
	dec	ecx
.api:
	mov	[g_plan_acme+ACM_DNSAPI],rsi
	mov	[g_plan_acme+ACM_DNSAPIL],ecx
@@:
	mov	rdi,rbx
	lea	rsi,[compile_acme_dns.k_wait]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_duration
	jc	.bad
	xor	edx,edx
	mov	ecx,1000
	div	rcx
	cmp	rax,600000
	ja	.bad
	mov	[g_plan_acme+ACM_DNSWAIT],eax
@@:
	mov	rdi,rbx
	lea	rsi,[compile_acme_rfc2136.k_key]
	call	node_option
	test	rax,rax
	jz	.bad
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,4096
	jae	.bad
	lea	rdi,[g_trust_path]
	push	rcx
	rep	movsb
	pop	rcx
	mov	byte [g_trust_path+rcx],0
	lea	rdi,[g_trust_path]
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	.no_key
	mov	rsi,rax
	xor	ecx,ecx				; the line
@@:
	cmp	ecx,edx
	jae	@f
	cmp	byte [rsi+rcx],0x21
	jb	@f
	cmp	byte [rsi+rcx],0x7E
	ja	.no_key
	inc	ecx
	jmp	@b
@@:
	; the key id
	call	.field
	jc	.no_key
	cmp	edx,255
	ja	.no_key
	mov	[g_plan_acme+ACM_DNSTOKL],edx
	lea	rdi,[g_plan_acme+ACM_DNSTOK]
	call	.take
	; the secret
	call	.field
	jc	.no_key
	cmp	edx,60
	ja	.no_key
	mov	[g_plan_acme+ACM_DNSSECL],edx
	lea	rdi,[g_plan_acme+ACM_DNSSEC]
	call	.take
	; a session token, if one
	mov	dword [g_plan_acme+ACM_DNSSTL],0
	test	ecx,ecx
	jz	.trust
	call	.field
	jc	.no_key
	cmp	edx,2040
	ja	.no_key
	mov	[g_plan_acme+ACM_DNSSTL],edx
	lea	rdi,[g_plan_acme+ACM_DNSST]
	call	.take
.trust:
	jmp	compile_acme_dns.dns_trust
; rsi/ecx = what is left: edx = the next field's length (to ':' or the end). CF: empty.
.field:
	xor	edx,edx
@@:
	cmp	edx,ecx
	jae	@f
	cmp	byte [rsi+rdx],':'
	je	@f
	inc	edx
	jmp	@b
@@:
	test	edx,edx
	jz	.empty
	clc
	ret
.empty:
	stc
	ret
; rdi = where: the field (edx bytes) copied, and past it and its ':'
.take:
	push	rcx
	mov	ecx,edx
	rep	movsb
	pop	rcx
	sub	ecx,edx
	jz	@f
	inc	rsi
	dec	ecx
@@:
	ret
.no_key:
	call	log_begin
	out_lit 'acme: dns_key= names a file with one line, ACCESS_KEY_ID:SECRET[:SESSION_TOKEN] (an AWS key that may change the zone',39,'s records)'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
.bad:
	call	log_begin
	out_lit 'acme dns=route53 takes dns_key=FILE, and, if wanted, dns_api=https://URL, dns_wait= (10 min at most) and dns_trust=FILE'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; rdi = out, rsi/ecx = a name (no dot at its end): in wire form, lower case, the
; root's 0 at its end; rdi past it
dns_wire_name:
.label:
	mov	r8,rdi
	inc	rdi
	xor	r9d,r9d
.ch:
	test	ecx,ecx
	jz	.last
	lodsb
	dec	ecx
	cmp	al,'.'
	je	.dot
	cmp	al,'A'
	jb	@f
	cmp	al,'Z'
	ja	@f
	or	al,0x20
@@:
	stosb
	inc	r9d
	jmp	.ch
.dot:
	mov	[r8],r9b
	jmp	.label
.last:
	mov	[r8],r9b
	test	r9d,r9d
	jz	.out
	mov	byte [rdi],0
	inc	rdi
.out:
	ret

; rsi/ecx = text: CF when it has a byte a JSON string would need escaped (or a
; space, or past ASCII). Keeps all but r8.
acme_safe:
	xor	r8d,r8d
.byte:
	cmp	r8d,ecx
	jae	.ok
	cmp	byte [rsi+r8],'"'
	je	.bad
	cmp	byte [rsi+r8],'\'
	je	.bad
	cmp	byte [rsi+r8],0x21
	jb	.bad
	cmp	byte [rsi+r8],0x7E
	ja	.bad
	inc	r8d
	jmp	.byte
.ok:
	clc
	ret
.bad:
	stc
	ret

; rdi = a tls block, edx = its group: each `acme NAME...` line, a certificate
; (its files, or one signed here until they come). rbx is the line, for
; diagnostics.
compile_tls_acme:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rdi
	mov	r13d,edx
	mov	dword [g_ac_redir],0		; plain http to https for its names, unless
	mov	rdi,r12				; `redirect off`: the listener's port
	mov	ecx,DIR_TLSREDIR
	call	find_child
	test	rax,rax
	jz	@f
	mov	rax,[rax+N_ARGS]
	mov	rsi,[rax+A_VAL]
	cmp	word [rsi],'of'
	je	.redir_set
@@:
	mov	rdi,[r12+N_PARENT]
	call	acme_listener_port
	mov	[g_ac_redir],eax
.redir_set:
	mov	rbx,[r12+N_CHILD]
.line:
	test	rbx,rbx
	jz	.auto
	lea	rax,[dir_table + D_SIZE*DIR_TLSACME]
	cmp	[rbx+N_DEF],rax
	jne	.next
	mov	rax,[rbx+N_ARGS]
	mov	[g_ac_cur],rax
	mov	eax,[rbx+N_ARGC]
	mov	[g_ac_curn],eax
	call	.one
	jmp	.next
	; `auto`: a certificate for each name of the listener's host blocks (a
	; wildcard's with DNS-01 only), from okena's acme, or Let's Encrypt
.auto:
	mov	rdi,r12
	mov	ecx,DIR_TLSAUTO
	call	find_child
	test	rax,rax
	jz	.done
	call	acme_auto_defaults
	mov	rax,[r12+N_PARENT]
	mov	rbx,[rax+N_CHILD]
.host:
	test	rbx,rbx
	jz	.done
	lea	rax,[dir_table + D_SIZE*DIR_HOST]
	cmp	[rbx+N_DEF],rax
	jne	.host_next
	mov	rax,[rbx+N_ARGS]
	mov	ecx,[rbx+N_ARGC]
.host_name:
	push	rax
	push	rcx
	mov	rsi,[rax+A_VAL]
	cmp	word [rsi],'*.'
	jne	@f
	cmp	dword [g_plan_acme+ACM_CHAL],2
	jne	.host_skip
@@:
	mov	[g_ac_cur],rax
	mov	dword [g_ac_curn],1
	call	.one
.host_skip:
	pop	rcx
	pop	rax
	add	rax,A_SIZE
	dec	ecx
	jnz	.host_name
.host_next:
	mov	rbx,[rbx+N_NEXT]
	jmp	.host
.one:
	cmp	dword [g_plan_acme+ACM_ON],0
	je	.no_acme
	mov	eax,[g_plan_acme+ACM_NCERT]
	cmp	eax,ACME_CERTS
	jae	.too_many
	inc	dword [g_plan_acme+ACM_NCERT]
	shl	eax,4
	mov	rcx,[g_ac_cur]
	mov	[g_plan_acme+ACM_CERT+rax],rcx
	mov	ecx,[g_ac_curn]
	mov	[g_plan_acme+ACM_CERT+rax+8],ecx
	mov	ecx,[g_ac_redir]
	mov	[g_plan_acme+ACM_CERT+rax+12],ecx
	test	ecx,ecx
	jz	@f
	inc	dword [g_plan_acme+ACM_REDIRN]
@@:
	; the names: letters, digits, '-' and '.', as a CA takes them
	mov	r14,[g_ac_cur]
	mov	r15d,[g_ac_curn]
.name:
	mov	rsi,[r14+A_VAL]
	mov	ecx,[r14+A_VLEN]
	test	ecx,ecx
	jz	.bad_name
	cmp	ecx,253
	ja	.bad_name
	cmp	ecx,3
	jb	@f
	cmp	word [rsi],'*.'			; a wildcard: DNS-01 proves it
	jne	@f
	cmp	dword [g_plan_acme+ACM_CHAL],2
	jne	.bad_name
	add	rsi,2
	sub	ecx,2
@@:
	cmp	byte [rsi],'.'
	je	.bad_name
	cmp	byte [rsi],'-'
	je	.bad_name
@@:
	mov	al,[rsi]
	inc	rsi
	cmp	al,'-'
	je	.ch
	cmp	al,'.'
	je	.ch
	cmp	al,'0'
	jb	.bad_name
	cmp	al,'9'
	jbe	.ch
	or	al,0x20
	cmp	al,'a'
	jb	.bad_name
	cmp	al,'z'
	ja	.bad_name
.ch:
	dec	ecx
	jnz	@b
	add	r14,A_SIZE
	dec	r15d
	jnz	.name
	; DIR/NAME/cert.pem and key.pem: there?
	mov	r14,[g_ac_cur]
	lea	rdi,[g_ac_cpath]
	lea	rsi,[.f_cert]
	call	.path
	lea	rdi,[g_ac_kpath]
	lea	rsi,[.f_key]
	call	.path
	lea	rsi,[g_ac_cpath]
	call	.there
	jc	.selfsigned
	lea	rsi,[g_ac_kpath]
	call	.there
	jc	.selfsigned
	lea	rdi,[g_ac_carg]
	lea	rsi,[g_ac_cpath]
	mov	edx,ARG_WORD
	call	.arg
	lea	rdi,[g_ac_karg]
	lea	rsi,[g_ac_kpath]
	mov	edx,ARG_WORD
	call	.arg
	mov	byte [g_cc_from],1		; (okena certs: from the CA's files)
	jmp	.load
.selfsigned:
	mov	byte [g_cc_from],2		; (signed here meanwhile)
	; until the CA's comes: one signed here, for the names, 7 days
	lea	rdi,[g_ac_names]
	mov	rsi,[g_ac_cur]
	mov	edx,[g_ac_curn]
	call	acme_names
	call	x5_keygen
	jc	.no_key
	lea	rsi,[g_ac_names]
	mov	edx,ACME_DAYS_SELF
	call	x5_selfsigned
	jc	.no_key
	mov	ecx,eax
	lea	rsi,[g_x5_der2]
	lea	rdx,[pem_l_cert]
	lea	rdi,[g_x5_pem]
	call	x5_pem
	mov	byte [rdi],0
	lea	rdi,[g_ac_carg]
	lea	rsi,[g_x5_pem]
	mov	edx,ARG_MEM
	call	.arg
	call	x5_sec1
	mov	ecx,eax
	lea	rsi,[g_x5_der]
	lea	rdx,[pem_l_ec]
	lea	rdi,[g_ac_kpem]
	call	x5_pem
	mov	byte [rdi],0
	lea	rdi,[g_ac_karg]
	lea	rsi,[g_ac_kpem]
	mov	edx,ARG_MEM
	call	.arg
.load:
	lea	rdi,[g_ac_carg]
	lea	rsi,[g_ac_karg]
	mov	edx,r13d
	call	compile_cert
	mov	eax,[g_plan_tls]		; (okena certs: where it comes from)
	dec	eax
	mov	cl,[g_cc_from]
	mov	[g_tls_src+rax],cl
	mov	ecx,[g_plan_acme+ACM_NCERT]
	dec	ecx
	mov	[g_tls_acme+rax],cl
	ret
.next:
	mov	rbx,[rbx+N_NEXT]
	jmp	.line
.done:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
; rdi = out, rsi = the file's name: DIR/NAME/file, NUL-ended (r14 = the names)
.path:
	push	rsi
	mov	rsi,[g_plan_acme+ACM_DIR]
	mov	ecx,[g_plan_acme+ACM_DIRL]
	rep	movsb
	mov	byte [rdi],'/'
	inc	rdi
	mov	rsi,[r14+A_VAL]
	mov	ecx,[r14+A_VLEN]
	rep	movsb
	pop	rsi
@@:
	lodsb
	stosb
	test	al,al
	jnz	@b
	ret
; rsi = a path: CF when it cannot be opened to read
.there:
	mov	edi,AT_FDCWD
	mov	edx,O_RDONLY or O_CLOEXEC
	xor	r10d,r10d
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	js	.not_there
	mov	edi,eax
	mov	eax,SYS_close
	syscall
	clc
	ret
.not_there:
	stc
	ret
; rdi = an argument made up, rsi = its text (NUL-ended), edx = its kind: the
; line's first name is where a diagnostic points
.arg:
	mov	[rdi+A_KIND],edx
	mov	[rdi+A_VAL],rsi
	xor	ecx,ecx
@@:
	cmp	byte [rsi+rcx],0
	je	@f
	inc	ecx
	jmp	@b
@@:
	mov	[rdi+A_VLEN],ecx
	mov	eax,[r14+A_LINE]
	mov	[rdi+A_LINE],eax
	mov	rax,[r14+A_RAW]
	mov	[rdi+A_RAW],rax
	mov	eax,[r14+A_RAWLEN]
	mov	[rdi+A_RAWLEN],eax
	mov	dword [rdi+A_QUOTED],0
	ret
.f_cert	db '/cert.pem',0
.f_key	db '/key.pem',0
.no_acme:
	mov	rdi,rbx
	call	tls_error_at
	out_lit 'tls { acme NAME... } needs the CA: okena { acme DIR ca=URL }'
	jmp	tls_error_end
.too_many:
	mov	rdi,rbx
	call	tls_error_at
	out_lit 'acme: 16 certificates at most'
	jmp	tls_error_end
.bad_name:
	mov	rdi,rbx
	call	tls_error_at
	out_lit 'acme: a name is letters, digits, - and . (a wildcard *.NAME with challenge=dns-01 only)'
	jmp	tls_error_end
.no_key:
	mov	rdi,rbx
	call	tls_error_at
	out_lit 'acme: no randomness for a key'
	jmp	tls_error_end

; rdi = out, rsi = the names (arguments), edx = how many: NUL after each, an
; empty one at the end (as x5_csr and x5_selfsigned take them)
acme_names:
	mov	r8,rsi
@@:
	mov	rsi,[r8+A_VAL]
	mov	ecx,[r8+A_VLEN]
	rep	movsb
	mov	byte [rdi],0
	inc	rdi
	add	r8,A_SIZE
	dec	edx
	jnz	@b
	mov	byte [rdi],0
	ret

; ------------------------------------------------------- the acme process

; Never returns.
acme_main:
	mov	dword [g_is_worker],0
	mov	edi,PR_SET_PDEATHSIG
	mov	esi,SIGKILL
	mov	eax,SYS_prctl
	syscall
	mov	eax,SYS_getppid
	syscall
	cmp	eax,[g_sup_pid]
	je	@f
	xor	edi,edi
	jmp	exit_process
@@:
	mov	edi,PR_SET_NAME
	lea	rsi,[acme_name]
	mov	eax,SYS_prctl
	syscall
	call	helper_close_sockets
	call	cx_buffer
	jc	.idle
	; its directories, while it may make them: the user's
	mov	ebx,-1
.dirs:
	lea	rdi,[g_ac_fpath]
	mov	rsi,[g_plan_acme+ACM_DIR]
	mov	ecx,[g_plan_acme+ACM_DIRL]
	rep	movsb
	cmp	ebx,-1
	je	@f
	mov	byte [rdi],'/'
	inc	rdi
	mov	eax,ebx
	shl	eax,4
	mov	rsi,[g_plan_acme+ACM_CERT+rax]
	mov	ecx,[rsi+A_VLEN]
	mov	rsi,[rsi+A_VAL]
	rep	movsb
@@:
	mov	byte [rdi],0
	lea	rsi,[g_ac_fpath]		; (and its parents: /var/lib/okena)
	mov	edx,0x1C0			; 0700
	call	mkdir_p
	cmp	dword [g_plan_user],0
	je	@f
	mov	edi,AT_FDCWD
	lea	rsi,[g_ac_fpath]
	mov	edx,[g_plan_uid]
	mov	r10d,[g_plan_gid]
	xor	r8d,r8d
	mov	eax,SYS_fchownat_
	syscall
@@:
	inc	ebx
	cmp	ebx,[g_plan_acme+ACM_NCERT]
	jb	.dirs
	call	acme_account
	jc	.idle
	call	priv_drop
	call	acme_confine
	seccomp_for filter_acme
	xor	ebx,ebx
@@:
	mov	qword [g_ac_due+rbx*8],-1
	mov	qword [g_ac_back+rbx*8],0
	inc	ebx
	cmp	ebx,ACME_ALL
	jb	@b
	call	od_load				; the on-demand ones kept from before
	call	acme_failed_load		; (and which failed last: their status)
.loop:
	mov	dword [g_ac_reload],0
	mov	rax,[g_acme_page]
	mov	r14d,[rax+AH_REVSEQ]		; (what the sleep waits on)
	call	acme_revoked
	call	od_requests			; names the workers ask for
	call	acme_now
	lea	r13,[rax+3600]			; the next to look at
	xor	ebx,ebx
.cert:
	call	acme_more			; (the configured, then the on-demand ones)
	jc	.pass
	cmp	qword [g_ac_due+rbx*8],-1
	jne	@f
	call	acme_file_due
@@:
	cmp	dword [g_ac_certidl+rbx*4],0	; ARI: the CA's window, when it gives one
	je	@f
	call	acme_now
	cmp	rax,[g_ac_arinext+rbx*8]
	jb	@f
	call	acme_ari
@@:
	call	acme_now
	cmp	rax,[g_ac_due+rbx*8]
	jb	.later
	cmp	dword [g_plan_acme+ACM_SHARED],0
	je	.order
	call	acme_fleet_turn			; a fleet's directory: whose order (acmefleet.inc)
	test	eax,eax
	jz	.order
	cmp	eax,1
	je	.taken
	call	acme_now			; another instance ordering it: looked at again
	inc	rax
	mov	[g_ac_due+rbx*8],rax
	jmp	.later
.taken:
	mov	qword [g_ac_back+rbx*8],0
	cmp	ebx,ACME_CERTS
	jb	@f
	call	od_publish
	jmp	.taken_said
@@:
	mov	dword [g_ac_reload],1
.taken_said:
	call	log_begin
	out_lit 'acme: '
	call	acme_out_name
	out_lit ': renewed by another instance (the shared directory): taken'
	call	log_end
	jmp	.later
.order:
	cmp	byte [g_ac_failed+rbx],0	; it failed last: the staging CA first
	je	.order_ca
	cmp	dword [g_plan_acme+ACM_STGL],0
	je	.order_ca
	mov	dword [g_ac_cai],2
	call	acme_issue
	mov	dword [g_ac_cai],0
	jnc	@f
	call	log_begin
	out_lit 'acme: '
	call	acme_out_name
	out_lit ': the staging CA first (the last order failed): it fails too ('
	mov	rsi,[g_ac_why]
	call	out_cstr
	out_lit ')'
	call	log_end
	jmp	.failed
@@:
	call	log_begin
	out_lit 'acme: '
	call	acme_out_name
	out_lit ': the staging CA issued it: now the CA'
	call	log_end
.order_ca:
	mov	dword [g_ac_cai],0
	call	acme_issue
	jnc	.issued
	cmp	dword [g_plan_acme+ACM_FBL],0
	je	.failed
	; the first CA failed: said, and the fallback asked at once
	call	log_begin
	out_lit 'acme: '
	call	acme_out_name
	out_lit ': the CA failed ('
	mov	rsi,[g_ac_why]
	call	out_cstr
	cmp	dword [g_ac_st],0
	je	@f
	out_lit ', HTTP '
	mov	eax,[g_ac_st]
	call	out_u64
@@:
	out_lit '): asking the fallback CA'
	call	log_end
	mov	dword [g_ac_cai],1
	call	acme_issue
	mov	dword [g_ac_cai],0
	jc	.failed
.issued:
	mov	byte [g_ac_failed+rbx],0
	call	acme_unlock
	mov	qword [g_ac_back+rbx*8],0
	call	acme_file_due
	mov	edx,1
	call	acme_status_write		; (okena certs reads it)
	cmp	ebx,ACME_CERTS
	jb	.reload
	call	od_publish			; on demand: the workers take it from the store
	jmp	@f
.reload:
	mov	dword [g_ac_reload],1
@@:
	call	log_begin
	out_lit 'acme: '
	call	acme_out_name
	out_lit ': a certificate from the CA, renewed in '
	call	acme_now
	mov	rcx,rax
	mov	rax,[g_ac_due+rbx*8]
	sub	rax,rcx
	xor	edx,edx
	mov	ecx,86400
	div	rcx
	call	out_u64
	out_lit ' days'
	call	log_end
	jmp	.later
.failed:
	mov	byte [g_ac_failed+rbx],1
	call	acme_unlock
	cmp	ebx,ACME_CERTS			; on demand, and none yet: refused for a while
	jb	.backoff
	cmp	qword [g_ac_end+rbx*8],0
	jne	.backoff
	lea	eax,[rbx-ACME_CERTS]
	mov	byte [g_od_active+rax],0
	call	od_slot
	jc	@f
	mov	edx,3
	call	od_slot_state
@@:
	call	log_begin
	out_lit 'acme: on demand: '
	call	acme_out_name
	out_lit ': the order failed ('
	mov	rsi,[g_ac_why]
	call	out_cstr
	out_lit '): refused for 10 minutes'
	call	log_end
	jmp	.later
.backoff:
	mov	rax,[g_ac_back+rbx*8]
	add	rax,rax
	jnz	@f
	mov	eax,ACME_BACK_MIN
@@:
	cmp	rax,ACME_BACK_MAX
	jbe	@f
	mov	eax,ACME_BACK_MAX
@@:
	mov	[g_ac_back+rbx*8],rax
	push	rax
	call	acme_now
	add	rax,[rsp]
	mov	[g_ac_due+rbx*8],rax
	xor	edx,edx
	call	acme_status_write
	call	log_begin
	out_lit 'acme: '
	call	acme_out_name
	out_lit ': the order failed ('
	mov	rsi,[g_ac_why]
	call	out_cstr
	cmp	dword [g_ac_st],0
	je	@f
	out_lit ', HTTP '
	mov	eax,[g_ac_st]
	call	out_u64
@@:
	out_lit '): again in '
	pop	rax
	call	out_u64
	out_lit ' s'
	call	log_end
.later:
	mov	rax,[g_ac_due+rbx*8]
	cmp	rax,r13
	jae	@f
	mov	r13,rax
@@:
	cmp	dword [g_ac_certidl+rbx*4],0
	je	@f
	mov	rax,[g_ac_arinext+rbx*8]
	cmp	rax,r13
	jae	@f
	mov	r13,rax
@@:
	inc	ebx
	jmp	.cert
.pass:
	call	acme_clear
	cmp	dword [g_plan_acme+ACM_SHARED],0
	je	@f
	call	acme_fleet_poll			; a fleet's challenges, taken again
@@:
	cmp	dword [g_ac_reload],0
	je	@f
	mov	rax,[g_acme_page]
	mov	dword [rax+AH_RELOAD],1		; (the supervisor looks once a second)
@@:
	call	acme_now
	sub	r13,rax
	jg	@f
	mov	r13d,1
@@:
	cmp	dword [g_plan_acme+ACM_SHARED],0
	je	@f
	mov	r13d,1				; a fleet's: its challenges looked at each second
@@:
	cmp	r13,3600
	jbe	@f
	mov	r13d,3600
@@:
	push	0				; asleep until then, or a revocation
	push	r13
	mov	rdi,[g_acme_page]
	add	rdi,AH_REVSEQ
	mov	esi,FUTEX_WAIT			; (shared: not private)
	mov	edx,r14d
	mov	r10,rsp
	xor	r8d,r8d
	xor	r9d,r9d
	mov	eax,SYS_futex
	syscall
	add	rsp,16
	jmp	.loop
.idle:
	; it cannot work (said why): it waits, rather than be started again and again
	push	0
	push	3600
@@:
	mov	rdi,rsp
	xor	esi,esi
	mov	eax,SYS_nanosleep
	syscall
	jmp	@b

; the certificates OCSP says are revoked (the ring in the page): due now, once
acme_revoked:
	push	rbx
	mov	r8,[g_acme_page]
	mov	r9d,[r8+AH_REVN]
	cmp	r9d,AH_REVS
	jbe	@f
	mov	r9d,AH_REVS
@@:
	xor	ebx,ebx
.cert:
	call	acme_more
	jc	.out
	mov	rax,[g_ac_tag+rbx*8]
	test	rax,rax
	jz	.next
	cmp	rax,[g_ac_revdone+rbx*8]
	je	.next
	xor	ecx,ecx
.ring:
	cmp	ecx,r9d
	jae	.next
	cmp	rax,[r8+AH_REV+rcx*8]
	je	.it
	inc	ecx
	jmp	.ring
.it:
	mov	[g_ac_revdone+rbx*8],rax
	mov	qword [g_ac_due+rbx*8],0
	push	r8
	push	r9
	call	log_begin
	out_lit 'acme: '
	call	acme_out_name
	out_lit ': OCSP says its certificate is revoked: renewing it now'
	call	log_end
	pop	r9
	pop	r8
.next:
	inc	ebx
	jmp	.cert
.out:
	pop	rbx
	ret

; Landlock: to read anywhere, to write in its directory only
acme_confine:
	call	ll_begin
	jc	.out
	lea	rdi,[str_ll_root]
	mov	esi,LL_READS
	call	ll_path
	lea	rdi,[g_ac_fpath]
	mov	rsi,[g_plan_acme+ACM_DIR]
	mov	ecx,[g_plan_acme+ACM_DIRL]
	rep	movsb
	mov	byte [rdi],0
	lea	rdi,[g_ac_fpath]
	mov	esi,LL_READS or LL_WRITES or LLF_REMOVE_FILE or LLF_MAKE_DIR
	call	ll_path
	call	ll_end
.out:
	ret

; rax = seconds since 1970
acme_now:
	sub	rsp,16
	mov	edi,CLOCK_REALTIME
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	mov	rax,[rsp]
	add	rsp,16
	ret

; ebx = a certificate: its first name, said
acme_out_name:
	call	acme_cert_args
	mov	rsi,[rax+A_VAL]
	mov	edx,[rax+A_VLEN]
	jmp	out_str

; ebx = a certificate, rsi = a file's name ('/cert.pem'; '' for the directory;
; with ebx = -1 the acme directory's own): g_ac_fpath, NUL-ended
acme_path:
	lea	rdi,[g_ac_fpath]
	push	rsi
	mov	rsi,[g_plan_acme+ACM_DIR]
	mov	ecx,[g_plan_acme+ACM_DIRL]
	rep	movsb
	cmp	ebx,-1
	je	@f
	mov	byte [rdi],'/'
	inc	rdi
	push	rdi
	call	acme_cert_args
	pop	rdi
	mov	rsi,rax
	mov	ecx,[rsi+A_VLEN]
	mov	rsi,[rsi+A_VAL]
	rep	movsb
@@:
	pop	rsi
@@:
	lodsb
	stosb
	test	al,al
	jnz	@b
	ret

; g_ac_fpath: read into g_ac_file, eax its length. CF: it cannot be (eax -errno).
acme_read:
	mov	edi,AT_FDCWD
	lea	rsi,[g_ac_fpath]
	mov	edx,O_RDONLY or O_CLOEXEC
	xor	r10d,r10d
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	js	.bad
	push	rbx
	mov	ebx,eax
	xor	r8d,r8d
.more:
	mov	edi,ebx
	lea	rsi,[g_ac_file+r8]
	mov	edx,65535
	sub	edx,r8d
	jz	.full
	xor	eax,eax
	push	r8
	syscall
	pop	r8
	test	rax,rax
	js	.close
	jz	.close
	add	r8d,eax
	jmp	.more
.full:
	mov	eax,-27				; (EFBIG)
.close:
	push	rax
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
	pop	rax
	pop	rbx
	test	eax,eax
	js	.bad
	mov	byte [g_ac_file+r8],0
	mov	eax,r8d
	clc
	ret
.bad:
	stc
	ret

; g_ac_fpath = where, rsi/edx = what: written beside it and renamed over it (0600).
; CF when it could not be.
acme_write:
	push	rbx
	push	r12
	push	r13
	mov	r12,rsi
	mov	r13d,edx
	lea	rsi,[g_ac_fpath]
	lea	rdi,[g_ac_tmp]
@@:
	lodsb
	stosb
	test	al,al
	jnz	@b
	mov	dword [rdi-1],'.new'
	mov	byte [rdi+3],0
	mov	edi,AT_FDCWD
	lea	rsi,[g_ac_tmp]
	mov	edx,O_WRONLY or O_CREAT or O_APPEND or O_CLOEXEC
	mov	r10d,0x180			; 0600
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	js	.bad
	mov	ebx,eax
	mov	edi,ebx
	xor	esi,esi
	mov	eax,SYS_ftruncate
	syscall
	test	eax,eax
	js	.close_bad
	mov	edi,ebx
	mov	rsi,r12
	mov	edx,r13d
	call	write_all
	jc	.close_bad
	mov	edi,ebx
	mov	eax,SYS_fdatasync
	syscall
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
	lea	rdi,[g_ac_tmp]
	lea	rsi,[g_ac_fpath]
	mov	eax,SYS_rename_
	syscall
	test	eax,eax
	js	.bad
	clc
	jmp	.out
.close_bad:
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
.bad:
	stc
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; The account's key: DIR/account.key, or a new one written there. Its JWK and
; thumbprint (RFC 7638). CF: none to be had (said).
acme_account:
	push	rbx
	mov	ebx,-1
	cstring .f_acct, '/account.key',0
	lea	rsi,[.f_acct]
	call	acme_path
	call	acme_read
	jnc	.read
	cmp	eax,-ENOENT
	jne	.broken
	call	x5_keygen
	jc	.broken
	lea	rsi,[g_x5_d]
	lea	rdi,[g_ac_d]
	mov	ecx,32
	rep	movsb
	call	x5_sec1
	mov	ecx,eax
	lea	rsi,[g_x5_der]
	lea	rdx,[pem_l_ec]
	lea	rdi,[g_x5_pem]
	call	x5_pem
	lea	rsi,[g_x5_pem]
	mov	rdx,rdi
	sub	rdx,rsi
	call	acme_write
	jc	.broken
	call	log_begin
	out_lit 'acme: a new account key, in '
	lea	rsi,[g_ac_fpath]
	call	out_cstr
	call	log_end
	jmp	.have
.read:
	lea	rsi,[g_ac_file]
	lea	rdx,[g_ac_file+rax]
	lea	rdi,[pem_ec_key]
	call	pem_next
	test	eax,eax
	jle	.broken
	lea	rsi,[g_tls_der]
	mov	edx,eax
	call	key_sec1
	test	eax,eax
	jnz	.broken
	lea	rsi,[g_tls_d]
	lea	rdi,[g_ac_d]
	mov	ecx,32
	rep	movsb
.have:
	lea	rdi,[g_ac_pub]
	lea	rsi,[g_ac_d]
	call	p256_public
	; {"crv":"P-256","kty":"EC","x":"..","y":".."}: its members in this order
	lea	rdi,[g_ac_jwk]
	memit_x '{"crv":"P-256","kty":"EC","x":"'
	lea	rsi,[g_ac_pub+1]
	mov	edx,32
	call	base64url_encode
	memit_x '","y":"'
	lea	rsi,[g_ac_pub+33]
	mov	edx,32
	call	base64url_encode
	memit_x '"}'
	lea	rsi,[g_ac_jwk]
	mov	rdx,rdi
	sub	rdx,rsi
	mov	[g_ac_jwkl],edx
	lea	rdi,[g_ac_hash]
	call	sha256
	lea	rdi,[g_ac_thumb]
	lea	rsi,[g_ac_hash]
	mov	edx,32
	call	base64url_encode
	clc
	pop	rbx
	ret
.broken:
	call	log_begin
	out_lit 'acme: the account key '
	lea	rsi,[g_ac_fpath]
	call	out_cstr
	out_lit ' cannot be read or made: no certificates will be asked for'
	call	log_end
	stc
	pop	rbx
	ret

; ebx = a certificate: g_ac_due[ebx], when 2/3 of its certificate's life has
; gone; 0 (now) when it has none that can be read.
acme_file_due:
	push	r12
	mov	qword [g_ac_due+rbx*8],0
	mov	qword [g_ac_end+rbx*8],0
	mov	dword [g_ac_certidl+rbx*4],0
	mov	qword [g_ac_tag+rbx*8],0
	mov	dword [g_ac_arigot+rbx*4],0
	mov	qword [g_ac_arinext+rbx*8],0
	cstring .f_cert, '/cert.pem',0
	lea	rsi,[.f_cert]
	call	acme_path
	call	acme_read
	jc	.out
	lea	rsi,[g_ac_file]
	mov	edx,eax
	lea	rdi,[g_ac_der]
	call	pem_first_cert
	test	eax,eax
	jz	.out
	mov	[g_ac_derl],eax
	imul	edi,ebx,128			; its CertID, for ARI
	lea	rdi,[g_ac_certid+rdi]
	lea	rsi,[g_ac_der]
	mov	edx,eax
	call	acme_certid
	jnc	@f
	xor	eax,eax
@@:
	mov	[g_ac_certidl+rbx*4],eax
	lea	rdi,[g_ac_hash]			; its tag, as OCSP's
	lea	rsi,[g_ac_der]
	mov	edx,[g_ac_derl]
	call	sha256
	mov	rax,qword [g_ac_hash]
	or	rax,1
	mov	[g_ac_tag+rbx*8],rax
	lea	rsi,[g_ac_der]
	mov	edx,[g_ac_derl]
	call	x509_locate
	test	eax,eax
	jz	.out
	mov	rsi,[g_x509_val]
	mov	rdx,[g_x509_valend]
	call	der_read			; notBefore
	jc	.out
	mov	r12,r8
	lea	rdi,[g_time_a]
	call	x509_time_norm
	jc	.out
	mov	rsi,r12
	mov	rdx,[g_x509_valend]
	call	der_read			; notAfter
	jc	.out
	lea	rdi,[g_time_b]
	call	x509_time_norm
	jc	.out
	lea	rsi,[g_time_a]
	call	acme_epoch
	mov	r12,rax
	lea	rsi,[g_time_b]
	call	acme_epoch
	mov	[g_ac_end+rbx*8],rax
	sub	rax,r12
	jbe	.out
	push	rax
	add	rax,rax
	xor	edx,edx
	mov	ecx,3
	div	rcx
	add	rax,r12
	mov	r12,rax
	; jitter: up to a twentieth of the life earlier, so that certificates got
	; together (a fleet, a restart) are not all renewed in the same second
	sub	rsp,8
	mov	rdi,rsp
	mov	esi,8
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	pop	rax
	pop	rcx
	push	rax
	mov	rax,rcx
	xor	edx,edx
	mov	ecx,20
	div	rcx
	lea	rcx,[rax+1]
	pop	rax
	xor	edx,edx
	div	rcx
	sub	r12,rdx
	mov	[g_ac_due+rbx*8],r12
.out:
	pop	r12
	ret

; rsi = YYYYMMDDHHMMSS: rax = seconds since 1970 (days from the civil date, the
; year counted from March)
acme_epoch:
	push	rbx
	mov	ecx,4
	call	.num
	mov	r8,rax				; y
	mov	ecx,2
	call	.num
	mov	r9,rax				; m
	mov	ecx,2
	call	.num
	mov	r10,rax				; d
	cmp	r9,2
	ja	@f
	dec	r8
	add	r9,12
@@:
	sub	r9,3				; March = 0
	imul	rax,r9,153
	add	rax,2
	xor	edx,edx
	mov	ecx,5
	div	rcx
	lea	rbx,[rax+r10-1]			; day of the year
	mov	rax,r8				; years: 365, a leap day each 4 but 100, but 400
	imul	rcx,r8,365
	add	rbx,rcx
	shr	rax,2
	add	rbx,rax
	mov	rax,r8
	xor	edx,edx
	mov	ecx,100
	div	rcx
	sub	rbx,rax
	shr	rax,2
	add	rbx,rax
	sub	rbx,719468			; (to 1970-01-01)
	imul	rbx,rbx,86400
	mov	ecx,2
	call	.num
	imul	rax,rax,3600
	add	rbx,rax
	mov	ecx,2
	call	.num
	imul	rax,rax,60
	add	rbx,rax
	mov	ecx,2
	call	.num
	add	rax,rbx
	pop	rbx
	ret
; ecx digits at rsi: rax, rsi past them
.num:
	xor	eax,eax
@@:
	movzx	edx,byte [rsi]
	inc	rsi
	sub	edx,'0'
	imul	rax,rax,10
	add	rax,rdx
	dec	ecx
	jnz	@b
	ret

; ------------------------------------------------------------------ ARI

; rsi = a certificate's DER, edx = its length, rdi = out: its ARI CertID,
; base64url(the authority key identifier) "." base64url(the serial's bytes);
; eax its length. CF: it has no AKI (or one too long).
acme_certid:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rdi
	mov	rbx,rsi
	mov	r13d,edx
	; the serial: Certificate, TBSCertificate, [0] version, INTEGER
	lea	rdx,[rsi+rdx]
	call	der_read
	jc	.bad
	cmp	al,0x30
	jne	.bad
	lea	rdx,[rsi+rcx]
	call	der_read
	jc	.bad
	cmp	al,0x30
	jne	.bad
	lea	rdx,[rsi+rcx]
	call	der_read
	jc	.bad
	cmp	al,0xA0
	jne	@f
	mov	rsi,r8
	call	der_read
	jc	.bad
@@:
	cmp	al,2
	jne	.bad
	cmp	ecx,32
	ja	.bad
	mov	r14,rsi
	mov	r15d,ecx
	; the AKI: extension 2.5.29.35, [0] keyIdentifier
	mov	rsi,rbx
	mov	edx,r13d
	call	x509_locate
	test	eax,eax
	jz	.bad
	mov	rsi,[g_x509_ext]
	test	rsi,rsi
	jz	.bad
.ext:
	cmp	rsi,[g_x509_extend]
	jae	.bad
	mov	rdx,[g_x509_extend]
	call	der_read			; Extension
	jc	.bad
	cmp	al,0x30
	jne	.bad
	push	r8				; (the next)
	lea	rdx,[rsi+rcx]
	call	der_read			; its OID
	jc	.next
	cmp	al,6
	jne	.next
	cmp	ecx,3
	jne	.next
	cmp	word [rsi],0x1D55
	jne	.next
	cmp	byte [rsi+2],0x23
	jne	.next
	mov	rsi,r8
	call	der_read
	jc	.next
	cmp	al,1				; (critical)
	jne	@f
	mov	rsi,r8
	call	der_read
	jc	.next
@@:
	cmp	al,4
	jne	.next
	lea	rdx,[rsi+rcx]
	call	der_read			; AuthorityKeyIdentifier
	jc	.next
	cmp	al,0x30
	jne	.next
	lea	rdx,[rsi+rcx]
	call	der_read
	jc	.next
	cmp	al,0x80				; [0] keyIdentifier
	jne	.next
	add	rsp,8
	test	ecx,ecx
	jz	.bad
	cmp	ecx,64
	ja	.bad
	mov	rdi,r12
	mov	edx,ecx
	call	base64url_encode
	mov	byte [rdi],'.'
	inc	rdi
	mov	rsi,r14
	mov	edx,r15d
	call	base64url_encode
	mov	rax,rdi
	sub	rax,r12
	clc
	jmp	.out
.next:
	pop	rsi
	jmp	.ext
.bad:
	stc
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rsi/ecx = an RFC 3339 time (YYYY-MM-DDTHH:MM:SS, a fraction if wanted, Z or
; +00:00): rax = seconds since 1970. CF: not one.
acme_rfc3339:
	cmp	ecx,20
	jb	.bad
	cmp	byte [rsi+4],'-'
	jne	.bad
	cmp	byte [rsi+7],'-'
	jne	.bad
	mov	al,[rsi+10]
	or	al,0x20
	cmp	al,'t'
	jne	.bad
	cmp	byte [rsi+13],':'
	jne	.bad
	cmp	byte [rsi+16],':'
	jne	.bad
	lea	rdi,[g_ac_t14]
	xor	edx,edx
.digits:
	movzx	eax,byte [.at+rdx]
	mov	al,[rsi+rax]
	cmp	al,'0'
	jb	.bad
	cmp	al,'9'
	ja	.bad
	mov	[rdi+rdx],al
	inc	edx
	cmp	edx,14
	jb	.digits
	; past the seconds: a fraction, then Z (or +00:00)
	lea	r8,[rsi+19]
	lea	r9,[rsi+rcx]
	cmp	byte [r8],'.'
	jne	.zone
@@:
	inc	r8
	cmp	r8,r9
	jae	.bad
	cmp	byte [r8],'0'
	jb	.zone
	cmp	byte [r8],'9'
	jbe	@b
.zone:
	mov	al,[r8]
	or	al,0x20
	cmp	al,'z'
	je	.utc
	lea	rax,[r8+6]
	cmp	rax,r9
	ja	.bad
	cmp	dword [r8],'+00:'
	jne	.bad
	cmp	word [r8+4],'00'
	jne	.bad
.utc:
	lea	rsi,[g_ac_t14]
	call	acme_epoch
	clc
	ret
.bad:
	stc
	ret
.at	db 0,1,2,3, 5,6, 8,9, 11,12, 14,15, 17,18

; ebx = a certificate with a CertID: the first CA's renewalInfo for it; its
; suggested window, a time in it chosen at random, is when it is renewed. Asked
; again after Retry-After (an hour to a day; 6 hours when none). A CA with no
; ARI, or no answer: the due date stays (2/3 of the life).
acme_ari:
	push	r12
	push	r13
	mov	qword [g_ac_arinext+rbx*8],0
	mov	r12d,21600			; (when to ask again)
	mov	dword [g_ac_cai],0
	mov	rsi,[g_plan_acme+ACM_CA]
	mov	ecx,[g_plan_acme+ACM_CAL]
	xor	edx,edx
	call	acme_request
	jc	.again
	cmp	dword [g_ac_st],200
	jne	.again
	cstring .n_ri, 'renewalInfo',0
	lea	rdi,[.n_ri]
	lea	r9,[g_ac_rinfo]
	mov	r10d,ACME_URL - 130
	call	acme_field
	jc	.none				; (no ARI at this CA: once a day)
	mov	[g_ac_rinfol],eax
	lea	rdi,[g_ac_durl]
	lea	rsi,[g_ac_rinfo]
	mov	ecx,eax
	rep	movsb
	cmp	byte [rdi-1],'/'
	je	@f
	mov	byte [rdi],'/'
	inc	rdi
@@:
	imul	esi,ebx,128
	lea	rsi,[g_ac_certid+rsi]
	mov	ecx,[g_ac_certidl+rbx*4]
	rep	movsb
	lea	rsi,[g_ac_durl]
	mov	rcx,rdi
	sub	rcx,rsi
	xor	edx,edx
	call	acme_request
	jc	.again
	mov	rax,[g_ac_retry]
	test	rax,rax
	jz	@f
	cmp	rax,3600
	jae	.ra_min
	mov	eax,3600
.ra_min:
	cmp	rax,86400
	jbe	.ra_max
	mov	eax,86400
.ra_max:
	mov	r12,rax
@@:
	cmp	dword [g_ac_st],200
	jne	.again
	; suggestedWindow: start, end
	mov	rsi,[g_ac_rb]
	mov	edx,[g_ac_rbl]
	add	rdx,rsi
	cstring .n_sw, 'suggestedWindow'
	lea	rdi,[.n_sw]
	mov	ecx,15
	call	json_get
	jc	.again
	test	rax,rax
	jz	.again
	cmp	byte [rax],'{'
	jne	.again
	mov	[g_ac_rb],rax			; (the body, from here: the window)
	sub	r8,rax
	mov	[g_ac_rbl],r8d
	cstring .n_start, 'start',0
	lea	rdi,[.n_start]
	lea	r9,[g_ac_word]
	mov	r10d,31
	call	acme_field
	jc	.again
	lea	rsi,[g_ac_word]
	mov	ecx,eax
	call	acme_rfc3339
	jc	.again
	mov	r13,rax
	cstring .n_end, 'end',0
	lea	rdi,[.n_end]
	lea	r9,[g_ac_word]
	mov	r10d,31
	call	acme_field
	jc	.again
	lea	rsi,[g_ac_word]
	mov	ecx,eax
	call	acme_rfc3339
	jc	.again
	sub	rax,r13
	jb	.again
	; a time in it, at random (so a fleet does not renew all at once)
	lea	rcx,[rax+1]
	push	rcx
	push	0
	mov	rdi,rsp
	mov	esi,8
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	pop	rax
	pop	rcx
	xor	edx,edx
	div	rcx
	add	rdx,r13
	mov	[g_ac_due+rbx*8],rdx
	mov	dword [g_ac_arigot+rbx*4],1
	call	acme_now
	cmp	rax,[g_ac_due+rbx*8]
	jb	.again
	call	log_begin
	out_lit 'acme: '
	call	acme_out_name
	out_lit ': the CA asks for it to be renewed now (ARI)'
	call	log_end
	jmp	.again
.none:
	mov	r12d,86400
.again:
	call	acme_now
	add	rax,r12
	mov	[g_ac_arinext+rbx*8],rax
	pop	r13
	pop	r12
	ret

; the challenges' slots, free
acme_clear:
	mov	rax,[g_acme_page]
	lea	rdi,[rax+AH_SLOT]
	lea	rsi,[rax+ACME_TSLOT]
	mov	ecx,ACME_NAMES
@@:
	mov	dword [rdi+AS_TLEN],0
	mov	dword [rsi+AX_NLEN],0
	add	rdi,AS_SIZE
	add	rsi,AX_SIZE
	dec	ecx
	jnz	@b
	ret

; ------------------------------------------------------------- HTTP, JWS

; rsi/ecx = an https URL: g_ac_host (its length, g_ac_port), g_ac_auth (host
; and port as written), g_ac_path. CF: not one.
acme_url:
	cmp	ecx,9
	jb	.bad
	mov	rax,'https://'
	cmp	[rsi],rax
	jne	.bad
	add	rsi,8
	sub	ecx,8
	mov	[g_ac_auth],rsi
	xor	edx,edx
@@:
	cmp	edx,ecx
	jae	@f
	cmp	byte [rsi+rdx],'/'
	je	@f
	inc	edx
	jmp	@b
@@:
	test	edx,edx
	jz	.bad
	cmp	edx,255
	ja	.bad
	mov	[g_ac_authl],edx
	lea	rax,[rsi+rdx]
	mov	[g_ac_path],rax
	sub	ecx,edx
	mov	[g_ac_pathl],ecx
	mov	dword [g_ac_port],443
	mov	r8d,edx				; the host's length
	mov	r9d,edx
.colon:
	dec	r9d
	js	.host
	cmp	byte [rsi+r9],']'
	je	.host
	cmp	byte [rsi+r9],':'
	jne	.colon
	push	rsi
	push	rdx
	lea	rdi,[rsi+r9+1]
	mov	esi,edx
	sub	esi,r9d
	dec	esi
	call	parse_decimal
	pop	rdx
	pop	rsi
	jc	.bad
	test	eax,eax
	jz	.bad
	cmp	eax,65535
	ja	.bad
	mov	[g_ac_port],eax
	mov	r8d,r9d
.host:
	test	r8d,r8d
	jz	.bad
	mov	[g_ac_hostl],r8d
	lea	rdi,[g_ac_host]
	mov	ecx,r8d
	rep	movsb
	clc
	ret
.bad:
	stc
	ret

; rsi/ecx = a URL, rdx = a body to POST (r8d its length), or 0 to GET: the
; answer's status in g_ac_st, its body in g_ac_rb/rbl (chunks joined), and
; Replay-Nonce and Location kept. CF: no answer (g_ac_why).
acme_request:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdx
	mov	r13d,r8d
	mov	dword [g_ac_st],0
	cstring .w_url, 'a URL that is not https',0
	lea	rax,[.w_url]
	mov	[g_ac_why],rax
	call	acme_url
	jc	.out
	lea	rdi,[g_ac_req]
	mov	rsi,[g_ac_meth]
	test	rsi,rsi
	jz	@f
	call	fmt_cstr
	jmp	.path
@@:
	test	r12,r12
	jz	.get
	memit_x 'POST '
	jmp	.path
.get:
	memit_x 'GET '
.path:
	mov	rsi,[g_ac_path]
	mov	ecx,[g_ac_pathl]
	test	ecx,ecx
	jnz	@f
	mov	byte [rdi],'/'
	inc	rdi
@@:
	rep	movsb
	memit_x ' HTTP/1.1',13,10,'Host: '
	mov	rsi,[g_ac_auth]
	mov	ecx,[g_ac_authl]
	rep	movsb
	memit_x 13,10,'User-Agent: okena',13,10,'Accept: */*',13,10,'Connection: close',13,10
	cmp	dword [g_ac_dns],0
	je	@f
	mov	rsi,[g_ac_xhdr]
	mov	ecx,[g_ac_xhdrl]
	rep	movsb
@@:
	test	r12,r12
	jz	.head_end
	cmp	dword [g_ac_dns],0
	je	.jose
	memit_x 'Content-Type: '
	mov	rsi,[g_ac_ctype]
	call	fmt_cstr
	memit_x 13,10
	jmp	.length
.jose:
	memit_x 'Content-Type: application/jose+json',13,10
.length:
	memit_x 'Content-Length: '
	mov	eax,r13d
	call	fmt_u64
	memit_x 13,10
.head_end:
	memit_x 13,10
	test	r12,r12
	jz	@f
	mov	rsi,r12
	mov	ecx,r13d
	rep	movsb
@@:
	mov	rbx,rdi
	cstring .w_conn, 'the CA cannot be reached',0
	lea	rax,[.w_conn]
	mov	[g_ac_why],rax
	lea	rdi,[g_ac_sa]
	lea	rsi,[g_ac_host]
	mov	ecx,[g_ac_hostl]
	mov	edx,[g_ac_port]
	call	cx_address
	jc	.out
	lea	rsi,[g_ac_sa]
	call	cx_connect
	jc	.out
	xor	edi,edi
	cmp	dword [g_ac_dns],0
	jne	.dns_anchor
	cmp	dword [g_ac_cai],1		; (staging: ca='s anchor)
	je	.fb_anchor
	cmp	dword [g_plan_acme+ACM_HASTRUST],0
	je	@f
	lea	rdi,[g_plan_acme+ACM_TRUST]
	jmp	@f
.fb_anchor:
	cmp	dword [g_plan_acme+ACM_FBHASTRUST],0
	je	@f
	lea	rdi,[g_plan_acme+ACM_FBTRUST]
	jmp	@f
.dns_anchor:
	cmp	dword [g_plan_acme+ACM_DNSHASTRUST],0
	je	@f
	lea	rdi,[g_plan_acme+ACM_DNSTRUST]
@@:
	lea	rsi,[g_ac_host]
	mov	edx,[g_ac_hostl]
	call	cx_handshake
	jc	.not_verified
	lea	rsi,[g_ac_req]
	mov	rdx,rbx
	sub	rdx,rsi
	call	cx_send
	jc	.close
	call	cx_answer
	jc	.close
	call	cx_close
	cstring .w_ans, 'the CA',39,'s answer is not HTTP',0
	lea	rax,[.w_ans]
	mov	[g_ac_why],rax
	call	cx_status
	jc	.out
	mov	[g_ac_st],eax
	mov	[g_ac_rb],rsi
	mov	[g_ac_rbl],ecx
	call	acme_heads
	jmp	.out
.not_verified:
	cstring .w_tls, 'the CA',39,'s certificate is not trusted, or the TLS handshake failed',0
	lea	rax,[.w_tls]
	mov	[g_ac_why],rax
.close:
	call	cx_close
	stc
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; the answer's head (g_dk_buf up to g_ac_rb): Replay-Nonce, Location, and a
; chunked body joined. CF: broken.
acme_heads:
	push	rbx
	mov	dword [g_ac_locl],0
	mov	qword [g_ac_retry],0
	xor	ebx,ebx				; chunked
	mov	rsi,[g_dk_buf]
	mov	rdx,[g_ac_rb]
	sub	rdx,2				; (the empty line's CR LF)
	call	.eol				; (the status line)
.line:
	cmp	rsi,rdx
	jae	.done
	lea	rdi,[.n_nonce]
	mov	ecx,13
	call	.is
	je	.nonce
	lea	rdi,[.n_loc]
	mov	ecx,9
	call	.is
	je	.loc
	lea	rdi,[.n_te]
	mov	ecx,18
	call	.is
	je	.te
	lea	rdi,[.n_ra]
	mov	ecx,12
	call	.is
	je	.ra
.next:
	call	.eol
	jmp	.line
.ra:
	call	.value				; delay-seconds (an HTTP date: not taken)
	xor	eax,eax
	xor	r8d,r8d
@@:
	cmp	r8d,ecx
	jae	@f
	movzx	r9d,byte [r10+r8]
	sub	r9d,'0'
	cmp	r9d,9
	ja	.next
	imul	rax,rax,10
	add	rax,r9
	inc	r8d
	cmp	r8d,9
	ja	.next
	jmp	@b
@@:
	mov	[g_ac_retry],rax
	jmp	.next
.nonce:
	call	.value
	cmp	ecx,250
	ja	.next
	xor	r8d,r8d				; base64url only
@@:
	cmp	r8d,ecx
	jae	@f
	movzx	eax,byte [r10+r8]
	inc	r8d
	cmp	al,'-'
	je	@b
	cmp	al,'_'
	je	@b
	cmp	al,'0'
	jb	.next
	cmp	al,'9'
	jbe	@b
	or	al,0x20
	cmp	al,'a'
	jb	.next
	cmp	al,'z'
	jbe	@b
	jmp	.next
@@:
	mov	[g_ac_noncel],ecx
	push	rsi
	mov	rsi,r10
	lea	rdi,[g_ac_nonce]
	rep	movsb
	pop	rsi
	jmp	.next
.loc:
	call	.value
	cmp	ecx,ACME_URL - 1
	ja	.next
	push	rsi
	mov	rsi,r10
	call	acme_safe
	jc	@f
	mov	[g_ac_locl],ecx
	lea	rdi,[g_ac_loc]
	rep	movsb
@@:
	pop	rsi
	jmp	.next
.te:
	call	.value
	cmp	ecx,7
	jb	.next
	mov	eax,[r10+rcx-7]
	or	eax,0x20202020
	cmp	eax,'chun'
	jne	.next
	mov	eax,[r10+rcx-4]
	or	eax,0x20202020
	cmp	eax,'nked'
	jne	.next
	mov	ebx,1
	jmp	.next
.done:
	test	ebx,ebx
	jz	.whole
	call	acme_dechunk
	pop	rbx
	ret
.whole:
	clc
	pop	rbx
	ret
; rsi = a line: ZF when it starts with the name rdi (ecx bytes, lower case)
.is:
	xor	r8d,r8d
@@:
	mov	al,[rsi+r8]
	or	al,0x20
	cmp	al,[rdi+r8]
	jne	@f
	inc	r8d
	cmp	r8d,ecx
	jb	@b
	xor	eax,eax
@@:
	ret
; rsi = a line, ecx = its name's length: r10/ecx = the value, trimmed
.value:
	lea	r10,[rsi+rcx]
@@:
	cmp	byte [r10],' '
	je	.sp
	cmp	byte [r10],9
	jne	@f
.sp:
	inc	r10
	jmp	@b
@@:
	mov	rcx,r10
@@:
	cmp	rcx,rdx
	jae	@f
	cmp	byte [rcx],13
	je	@f
	inc	rcx
	jmp	@b
@@:
	sub	rcx,r10
@@:
	test	ecx,ecx
	jz	@f
	cmp	byte [r10+rcx-1],' '
	jne	@f
	dec	ecx
	jmp	@b
@@:
	ret
; rsi past the next LF
.eol:
	cmp	rsi,rdx
	jae	@f
	lodsb
	cmp	al,10
	jne	.eol
@@:
	ret
.n_nonce	db 'replay-nonce:'
.n_loc		db 'location:'
.n_te		db 'transfer-encoding:'
.n_ra		db 'retry-after:'

; g_ac_rb/rbl, chunked: joined in place. CF: broken.
acme_dechunk:
	mov	rsi,[g_ac_rb]
	mov	rdi,rsi
	mov	edx,[g_ac_rbl]
	add	rdx,rsi
.chunk:
	xor	eax,eax
	xor	ecx,ecx				; digits
.hex:
	cmp	rsi,rdx
	jae	.bad
	movzx	r8d,byte [rsi]
	sub	r8d,'0'
	cmp	r8d,9
	jbe	.digit
	movzx	r8d,byte [rsi]
	or	r8d,0x20
	sub	r8d,'a'
	cmp	r8d,5
	ja	.hex_end
	add	r8d,10
.digit:
	shl	eax,4
	or	eax,r8d
	inc	rsi
	inc	ecx
	cmp	ecx,7
	ja	.bad
	jmp	.hex
.hex_end:
	test	ecx,ecx
	jz	.bad
@@:
	cmp	rsi,rdx				; (extensions) to the line's end
	jae	.bad
	cmp	byte [rsi],10
	je	@f
	inc	rsi
	jmp	@b
@@:
	inc	rsi
	test	eax,eax
	jz	.end
	lea	r8,[rsi+rax+2]
	cmp	r8,rdx
	ja	.bad
	mov	ecx,eax
	rep	movsb
	add	rsi,2
	jmp	.chunk
.end:
	mov	rax,rdi
	sub	rax,[g_ac_rb]
	mov	[g_ac_rbl],eax
	clc
	ret
.bad:
	stc
	ret

; rsi/ecx = a URL, g_ac_pay/payl = the payload (0 bytes: POST-as-GET): a JWS
; (ES256, the account's key: its JWK until it has a kid), the nonce fresh. A
; badNonce is tried again (at most three times). As acme_request.
acme_post:
	push	rbx
	push	r12
	push	r13
	mov	r12,rsi
	mov	r13d,ecx
	mov	ebx,3
.try:
	cmp	dword [g_ac_noncel],0
	jne	.nonce
	lea	rsi,[g_ac_unonce]
	mov	ecx,[g_ac_unoncel]
	xor	edx,edx
	call	acme_request
	jc	.out
	cmp	dword [g_ac_noncel],0
	jne	.nonce
	cstring .w_nonce, 'no nonce from newNonce',0
	lea	rax,[.w_nonce]
	mov	[g_ac_why],rax
	stc
	jmp	.out
.nonce:
	lea	rdi,[g_ac_prot]
	memit_x '{"alg":"ES256",'
	cmp	dword [g_ac_kidl],0
	je	.jwk
	memit_x '"kid":"'
	lea	rsi,[g_ac_kid]
	mov	ecx,[g_ac_kidl]
	rep	movsb
	memit_x '",'
	jmp	.url
.jwk:
	memit_x '"jwk":'
	lea	rsi,[g_ac_jwk]
	mov	ecx,[g_ac_jwkl]
	rep	movsb
	mov	byte [rdi],','
	inc	rdi
.url:
	memit_x '"nonce":"'
	lea	rsi,[g_ac_nonce]
	mov	ecx,[g_ac_noncel]
	rep	movsb
	memit_x '","url":"'
	mov	rsi,r12
	mov	ecx,r13d
	rep	movsb
	memit_x '"}'
	mov	dword [g_ac_noncel],0		; (spent)
	; protected.payload, signed
	lea	rsi,[g_ac_prot]
	mov	rdx,rdi
	sub	rdx,rsi
	lea	rdi,[g_ac_b64]
	call	base64url_encode
	push	rdi				; the protected part's end
	mov	byte [rdi],'.'
	inc	rdi
	lea	rsi,[g_ac_pay]
	mov	edx,[g_ac_payl]
	test	edx,edx
	jz	@f
	call	base64url_encode
@@:
	push	rdi				; the payload's end
	lea	rsi,[g_ac_b64]
	mov	rdx,rdi
	sub	rdx,rsi
	lea	rdi,[g_ac_hash]
	call	sha256
	lea	rdi,[g_ac_sig]
	lea	rsi,[g_ac_d]
	lea	rdx,[g_ac_hash]
	call	p256_sign
	pop	r9
	pop	r8
	cstring .w_sign, 'the request could not be signed',0
	lea	rcx,[.w_sign]
	mov	[g_ac_why],rcx
	test	eax,eax
	jz	.bad
	; the flattened JSON serialization
	lea	rdi,[g_ac_body]
	memit_x '{"protected":"'
	lea	rsi,[g_ac_b64]
	mov	rcx,r8
	sub	rcx,rsi
	rep	movsb
	memit_x '","payload":"'
	lea	rsi,[r8+1]
	mov	rcx,r9
	sub	rcx,rsi
	rep	movsb
	memit_x '","signature":"'
	lea	rsi,[g_ac_sig]
	mov	edx,64
	call	base64url_encode
	memit_x '"}'
	lea	rdx,[g_ac_body]
	mov	r8,rdi
	sub	r8,rdx
	mov	rsi,r12
	mov	ecx,r13d
	call	acme_request
	jc	.out
	cmp	dword [g_ac_st],400
	jne	.ok
	mov	rsi,[g_ac_rb]
	mov	ecx,[g_ac_rbl]
	cstring .bad_nonce, 'badNonce'
	lea	rdi,[.bad_nonce]
	mov	edx,8
	call	find_sub
	test	rax,rax
	jz	.ok
	dec	ebx
	jnz	.try
.ok:
	clc
	jmp	.out
.bad:
	stc
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; the answer's body, a JSON object: rdi = a member's name (NUL-ended), r9 =
; out, r10d = room: its string value, eax its length. CF: not there, not a
; string, or a byte a JSON string here should not have.
acme_field:
	push	r9
	push	r10
	xor	ecx,ecx
@@:
	cmp	byte [rdi+rcx],0
	je	@f
	inc	ecx
	jmp	@b
@@:
	mov	rsi,[g_ac_rb]
	mov	edx,[g_ac_rbl]
	add	rdx,rsi
	call	json_get
	pop	rcx				; (the room)
	pop	r9
	jc	.bad
	test	rax,rax
	jz	.bad
	mov	rsi,rax
	mov	rdi,r9
	push	r9
	call	json_string
	pop	rsi
	jc	.bad
	mov	ecx,eax
	jmp	acme_safe
.bad:
	stc
	ret

; the answer's "status" in g_ac_word. CF: none.
acme_status:
	cstring .n_status, 'status',0
	lea	rdi,[.n_status]
	lea	r9,[g_ac_word]
	mov	r10d,31
	call	acme_field
	jc	@f
	mov	byte [g_ac_word+rax],0
@@:
	ret

; rsi = a status (NUL-ended): ZF when it is g_ac_word
acme_is:
	lea	rdi,[g_ac_word]
	push	rcx
	call	cstr_eq
	pop	rcx
	test	eax,eax
	setz	al
	test	al,al
	ret

; rsi/ecx = an order or an authorization's URL: asked again while it is
; "pending" or "processing" (a while between, 40 times at most): its last status
; in g_ac_word. CF: no answer, or not 200.
acme_poll:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r12,rsi
	mov	r13d,ecx
	mov	ebx,40
	mov	r14d,100			; ms
.again:
	mov	dword [g_ac_payl],0
	mov	rsi,r12
	mov	ecx,r13d
	call	acme_post
	jc	.out
	cmp	dword [g_ac_st],200
	jne	.bad_status
	call	acme_status
	jc	.bad_status
	cstring .s_pending, 'pending',0
	lea	rsi,[.s_pending]
	call	acme_is
	je	.wait
	cstring .s_processing, 'processing',0
	lea	rsi,[.s_processing]
	call	acme_is
	jne	.done
.wait:
	dec	ebx
	jz	.too_long
	mov	eax,r14d
	call	acme_sleep_ms
	add	r14d,r14d
	cmp	r14d,2000
	jbe	.again
	mov	r14d,2000
	jmp	.again
.done:
	clc
	jmp	.out
.too_long:
	cstring .w_long, 'the CA took too long',0
	lea	rax,[.w_long]
	mov	[g_ac_why],rax
	stc
	jmp	.out
.bad_status:
	cstring .w_status, 'an order or authorization the CA would not show',0
	lea	rax,[.w_status]
	mov	[g_ac_why],rax
	stc
.out:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; ---------------------------------------------------------------- DNS-01

; the DNS API: rsi/ecx = URL, rdx/r8d = a JSON body (0: GET), r9 = the method
; (cstr) or 0. As acme_request.
dns_request:
	mov	dword [g_ac_dns],1
	mov	[g_ac_meth],r9
	cmp	dword [g_plan_acme+ACM_DNS],3
	jne	.bearer
	push	rsi
	push	rcx
	push	rdx
	push	r8
	call	r53_sign
	pop	r8
	pop	rdx
	pop	rcx
	pop	rsi
	jmp	.send
.bearer:
	; Cloudflare: its token
	push	rsi
	push	rcx
	lea	rdi,[g_ac_xbuf]
	memit_x 'Authorization: Bearer '
	lea	rsi,[g_plan_acme+ACM_DNSTOK]
	mov	ecx,[g_plan_acme+ACM_DNSTOKL]
	rep	movsb
	memit_x 13,10
	lea	rax,[g_ac_xbuf]
	mov	[g_ac_xhdr],rax
	sub	rdi,rax
	mov	[g_ac_xhdrl],edi
	cstring .ct_json, 'application/json',0
	lea	rax,[.ct_json]
	mov	[g_ac_ctype],rax
	pop	rcx
	pop	rsi
.send:
	call	acme_request
	mov	dword [g_ac_dns],0
	mov	qword [g_ac_meth],0
	ret

; rdi = out: the API's base URL, rdi past it
dns_base:
	mov	rsi,[g_plan_acme+ACM_DNSAPI]
	mov	ecx,[g_plan_acme+ACM_DNSAPIL]
	rep	movsb
	ret

; Cloudflare's answer (g_ac_rb): "result", an object, or an array's first; its
; "id" into rdi (63 bytes at most: letters, digits, - and _), eax its length.
; CF: none.
dns_result_id:
	push	rbx
	mov	rbx,rdi
	mov	rsi,[g_ac_rb]
	mov	edx,[g_ac_rbl]
	add	rdx,rsi
	cstring .n_result, 'result'
	lea	rdi,[.n_result]
	mov	ecx,6
	call	json_get
	jc	.none
	test	rax,rax
	jz	.none
	mov	rsi,rax
	mov	rdx,r8
	cmp	byte [rsi],'['
	jne	.object
	inc	rsi
	call	json_ws
	cmp	rsi,rdx
	jae	.none
	cmp	byte [rsi],'{'
	jne	.none
	push	rsi
	call	json_skip_value
	mov	rdx,rsi
	pop	rsi
	jc	.none
.object:
	cmp	byte [rsi],'{'
	jne	.none
	cstring .n_id, 'id'
	lea	rdi,[.n_id]
	mov	ecx,2
	call	json_get
	jc	.none
	test	rax,rax
	jz	.none
	mov	rsi,rax
	mov	rdi,rbx
	mov	ecx,63
	call	json_string
	jc	.none
	test	eax,eax
	jz	.none
	xor	ecx,ecx
@@:
	movzx	edx,byte [rbx+rcx]
	inc	ecx
	cmp	dl,'-'
	je	.ch
	cmp	dl,'_'
	je	.ch
	cmp	dl,'0'
	jb	.none
	cmp	dl,'9'
	jbe	.ch
	or	dl,0x20
	cmp	dl,'a'
	jb	.none
	cmp	dl,'z'
	ja	.none
.ch:
	cmp	ecx,eax
	jb	@b
	clc
	pop	rbx
	ret
.none:
	stc
	pop	rbx
	ret

; r12d = the authorization, g_ac_ident its name, g_ac_txt the value: the record
; made (its zone found: the name, then each parent, the first the account
; holds), kept in g_ac_dzone/g_ac_did. CF: failed (g_ac_why).
dns_create:
	cmp	dword [g_plan_acme+ACM_DNS],2
	je	rfc_create
	cmp	dword [g_plan_acme+ACM_DNS],3
	je	r53_create
	push	rbx
	push	r13
	cstring .w_zone, 'no DNS zone of the account holds the name',0
	lea	rax,[.w_zone]
	mov	[g_ac_why],rax
	xor	r13d,r13d			; the candidate: g_ac_ident + r13
.zone:
	; (a zone has a dot in it)
	lea	rsi,[g_ac_ident+r13]
	mov	ecx,[g_ac_identl]
	sub	ecx,r13d
	mov	rdi,rsi
	mov	al,'.'
	push	rcx
	repne	scasb
	pop	rcx
	jne	.fail
	lea	rdi,[g_ac_durl]
	call	dns_base
	memit_x '/zones?name='
	lea	rsi,[g_ac_ident+r13]
	mov	ecx,[g_ac_identl]
	sub	ecx,r13d
	rep	movsb
	lea	rsi,[g_ac_durl]
	mov	rcx,rdi
	sub	rcx,rsi
	xor	edx,edx
	xor	r9d,r9d
	call	dns_request
	jc	.out
	cmp	dword [g_ac_st],200
	jne	.api_bad
	imul	edi,r12d,64
	lea	rdi,[g_ac_dzone+rdi]
	call	dns_result_id
	jnc	.zone_found
	; the parent
@@:
	inc	r13d
	cmp	r13d,[g_ac_identl]
	jae	.fail
	cmp	byte [g_ac_ident+r13-1],'.'
	jne	@b
	jmp	.zone
.zone_found:
	mov	[g_ac_dzonel+r12*4],eax
	; the record: POST zones/ZONE/dns_records
	lea	rdi,[g_ac_durl]
	call	dns_base
	memit_x '/zones/'
	imul	esi,r12d,64
	lea	rsi,[g_ac_dzone+rsi]
	mov	ecx,[g_ac_dzonel+r12*4]
	rep	movsb
	memit_x '/dns_records'
	mov	rbx,rdi
	lea	rdi,[g_ac_pay]
	memit_x '{"type":"TXT","name":"_acme-challenge.'
	lea	rsi,[g_ac_ident]
	mov	ecx,[g_ac_identl]
	rep	movsb
	memit_x '","content":"'
	lea	rsi,[g_ac_txt]
	mov	ecx,43
	rep	movsb
	memit_x '","ttl":60}'
	lea	rdx,[g_ac_pay]
	mov	r8,rdi
	sub	r8,rdx
	lea	rsi,[g_ac_durl]
	mov	rcx,rbx
	sub	rcx,rsi
	xor	r9d,r9d
	call	dns_request
	jc	.out
	cstring .w_rec, 'the DNS API would not make the TXT record',0
	lea	rax,[.w_rec]
	mov	[g_ac_why],rax
	mov	eax,[g_ac_st]
	sub	eax,200
	cmp	eax,2
	jae	.fail
	imul	edi,r12d,64
	lea	rdi,[g_ac_did+rdi]
	call	dns_result_id
	jc	.fail
	mov	[g_ac_didl+r12*4],eax
	clc
	jmp	.out
.api_bad:
	cstring .w_api, 'the DNS API refused (its token?)',0
	lea	rax,[.w_api]
	mov	[g_ac_why],rax
.fail:
	stc
.out:
	pop	r13
	pop	rbx
	ret

; ------------------------------------------------------------- Route 53

; rdi = out, rsi = bytes, ecx = how many: lower-case hex, rdi past it
r53_hex:
	test	ecx,ecx
	jz	.out
	movzx	eax,byte [rsi]
	inc	rsi
	mov	edx,eax
	shr	edx,4
	mov	dl,[hex_digits+rdx]
	mov	[rdi],dl
	and	eax,15
	mov	al,[hex_digits+rax]
	mov	[rdi+1],al
	add	rdi,2
	dec	ecx
	jmp	r53_hex
.out:
	ret

; rsi/ecx = a URL, rdx/r8d = the body (0: none), g_ac_meth 0: AWS Signature
; Version 4 (us-east-1, route53): g_ac_xhdr its header lines, g_ac_ctype text/xml.
r53_sign:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rsi
	mov	r13d,ecx
	mov	r14,rdx
	mov	r15d,r8d
	call	acme_now
	call	x5_utctime			; YYMMDDHHMMSSZ
	lea	rdi,[g_r53_date]
	mov	word [rdi],'20'
	mov	eax,dword [g_x5_time]
	mov	[rdi+2],eax
	mov	ax,word [g_x5_time+4]
	mov	[rdi+6],ax
	mov	byte [rdi+8],'T'
	mov	eax,dword [g_x5_time+6]
	mov	[rdi+9],eax
	mov	ax,word [g_x5_time+10]
	mov	[rdi+13],ax
	mov	byte [rdi+15],'Z'
	mov	rsi,r12
	mov	ecx,r13d
	call	acme_url
	jc	.out
	; the canonical request
	lea	rdi,[g_r53_creq]
	test	r14,r14
	jz	.get
	memit_x 'POST',10
	jmp	.uri
.get:
	memit_x 'GET',10
.uri:
	mov	rsi,[g_ac_path]
	mov	ecx,[g_ac_pathl]
	test	ecx,ecx
	jnz	@f
	mov	byte [rdi],'/'
	inc	rdi
@@:
	test	ecx,ecx
	jz	.query
	lodsb
	dec	ecx
	cmp	al,'?'
	je	.query
	stosb
	jmp	@b
.query:
	mov	byte [rdi],10
	inc	rdi
	rep	movsb				; (built in order, nothing to escape)
	memit_x 10,'host:'
	mov	rsi,[g_ac_auth]
	mov	ecx,[g_ac_authl]
	rep	movsb
	memit_x 10,'x-amz-date:'
	lea	rsi,[g_r53_date]
	mov	ecx,16
	rep	movsb
	mov	byte [rdi],10
	inc	rdi
	cmp	dword [g_plan_acme+ACM_DNSSTL],0
	je	@f
	memit_x 'x-amz-security-token:'
	lea	rsi,[g_plan_acme+ACM_DNSST]
	mov	ecx,[g_plan_acme+ACM_DNSSTL]
	rep	movsb
	mov	byte [rdi],10
	inc	rdi
@@:
	memit_x 10
	call	.signed
	mov	byte [rdi],10
	inc	rdi
	push	rdi
	lea	rdi,[g_r53_mac]
	mov	rsi,r14
	mov	edx,r15d
	test	r14,r14
	jnz	@f
	xor	edx,edx
	lea	rsi,[g_r53_mac]
@@:
	call	sha256
	pop	rdi
	lea	rsi,[g_r53_mac]
	mov	ecx,32
	call	r53_hex
	; the string to sign
	lea	rsi,[g_r53_creq]
	mov	rdx,rdi
	sub	rdx,rsi
	lea	rdi,[g_r53_mac]
	call	sha256
	lea	rdi,[g_r53_sts]
	memit_x 'AWS4-HMAC-SHA256',10
	lea	rsi,[g_r53_date]
	mov	ecx,16
	rep	movsb
	mov	byte [rdi],10
	inc	rdi
	call	.scope
	mov	byte [rdi],10
	inc	rdi
	lea	rsi,[g_r53_mac]
	mov	ecx,32
	call	r53_hex
	mov	rbx,rdi				; its end
	; the key: HMAC("AWS4" secret, date), then region, service, aws4_request
	lea	rdi,[g_r53_key]
	mov	dword [rdi],'AWS4'
	add	rdi,4
	lea	rsi,[g_plan_acme+ACM_DNSSEC]
	mov	ecx,[g_plan_acme+ACM_DNSSECL]
	rep	movsb
	lea	rdi,[g_r53_mac]
	lea	rsi,[g_r53_key]
	mov	edx,[g_plan_acme+ACM_DNSSECL]
	add	edx,4
	lea	rcx,[g_r53_date]
	mov	r8d,8
	call	hmac_sha256
	cstring .s_region, 'us-east-1'
	lea	rcx,[.s_region]
	mov	r8d,9
	call	.step
	cstring .s_service, 'route53'
	lea	rcx,[.s_service]
	mov	r8d,7
	call	.step
	cstring .s_req, 'aws4_request'
	lea	rcx,[.s_req]
	mov	r8d,12
	call	.step
	lea	rcx,[g_r53_sts]
	mov	r8,rbx
	sub	r8,rcx
	call	.step
	lea	rdi,[g_r53_sig]
	lea	rsi,[g_r53_mac]
	mov	ecx,32
	call	r53_hex
	; the header lines
	lea	rdi,[g_ac_xbuf]
	memit_x 'X-Amz-Date: '
	lea	rsi,[g_r53_date]
	mov	ecx,16
	rep	movsb
	memit_x 13,10
	cmp	dword [g_plan_acme+ACM_DNSSTL],0
	je	@f
	memit_x 'X-Amz-Security-Token: '
	lea	rsi,[g_plan_acme+ACM_DNSST]
	mov	ecx,[g_plan_acme+ACM_DNSSTL]
	rep	movsb
	memit_x 13,10
@@:
	memit_x 'Authorization: AWS4-HMAC-SHA256 Credential='
	lea	rsi,[g_plan_acme+ACM_DNSTOK]
	mov	ecx,[g_plan_acme+ACM_DNSTOKL]
	rep	movsb
	mov	byte [rdi],'/'
	inc	rdi
	call	.scope
	memit_x ', SignedHeaders='
	call	.signed
	memit_x ', Signature='
	lea	rsi,[g_r53_sig]
	mov	ecx,64
	rep	movsb
	memit_x 13,10
	lea	rax,[g_ac_xbuf]
	mov	[g_ac_xhdr],rax
	sub	rdi,rax
	mov	[g_ac_xhdrl],edi
	cstring .ct_xml, 'text/xml',0
	lea	rax,[.ct_xml]
	mov	[g_ac_ctype],rax
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
; rcx/r8 = data: g_r53_mac = HMAC(g_r53_mac, it)
.step:
	lea	rdi,[g_r53_key]
	push	rcx
	push	r8
	lea	rsi,[g_r53_mac]
	mov	ecx,32
	rep	movsb
	pop	r8
	pop	rcx
	lea	rdi,[g_r53_mac]
	lea	rsi,[g_r53_key]
	mov	edx,32
	jmp	hmac_sha256
; rdi: DATE/us-east-1/route53/aws4_request
.scope:
	lea	rsi,[g_r53_date]
	mov	ecx,8
	rep	movsb
	memit_x '/us-east-1/route53/aws4_request'
	ret
; rdi: the signed headers' names
.signed:
	memit_x 'host;x-amz-date'
	cmp	dword [g_plan_acme+ACM_DNSSTL],0
	je	@f
	memit_x ';x-amz-security-token'
@@:
	ret

; the answer's body: rdi = "<Tag>" (cstr), rsi = where to look from: rax = its
; text, ecx its length (to the next '<'). CF: not there.
r53_xml:
	push	rsi
	xor	edx,edx
@@:
	cmp	byte [rdi+rdx],0
	je	@f
	inc	edx
	jmp	@b
@@:
	pop	rsi
	push	rdx
	mov	rcx,[g_ac_rb]
	mov	eax,[g_ac_rbl]
	add	rcx,rax
	sub	rcx,rsi
	jbe	.none_pop
	call	find_sub
	pop	rdx
	test	rax,rax
	jz	.none
	add	rax,rdx
	mov	rcx,[g_ac_rb]
	mov	edx,[g_ac_rbl]
	add	rdx,rcx				; the end
	xor	ecx,ecx
@@:
	lea	r8,[rax+rcx]
	cmp	r8,rdx
	jae	.none
	cmp	byte [r8],'<'
	je	@f
	inc	ecx
	jmp	@b
@@:
	clc
	ret
.none_pop:
	pop	rdx
.none:
	stc
	ret

; rax/ecx = "/hostedzone/ID" or "/change/ID", rdi = out (63): the ID (letters
; and digits), eax its length. CF: not one.
r53_id:
	lea	rsi,[rax+rcx]			; from the last '/'
@@:
	cmp	rsi,rax
	je	@f
	cmp	byte [rsi-1],'/'
	je	@f
	dec	rsi
	jmp	@b
@@:
	lea	rdx,[rax+rcx]
	sub	rdx,rsi
	jz	.bad
	cmp	edx,63
	ja	.bad
	mov	ecx,edx
	push	rdx
@@:
	lodsb
	stosb
	cmp	al,'0'
	jb	.bad_pop
	cmp	al,'9'
	jbe	.ch
	or	al,0x20
	cmp	al,'a'
	jb	.bad_pop
	cmp	al,'z'
	ja	.bad_pop
.ch:
	dec	ecx
	jnz	@b
	pop	rax
	clc
	ret
.bad_pop:
	pop	rdx
.bad:
	stc
	ret

; r12d, ebx = two authorizations: ZF when theirs is the same name
r53_same:
	mov	ecx,[g_ac_dnamel+r12*4]
	cmp	ecx,[g_ac_dnamel+rbx*4]
	jne	.out
	imul	esi,r12d,256
	lea	rsi,[g_ac_dname+rsi]
	imul	edi,ebx,256
	lea	rdi,[g_ac_dname+rdi]
	repe	cmpsb
.out:
	ret

; r12d = the authorization, g_ac_ident its name, g_ac_txt the value: its zone
; (one already found for that name, or the first of the name and its parents
; that the account holds), and the record set UPSERT. CF: failed.
r53_create:
	push	rbx
	push	r13
	imul	edi,r12d,256
	lea	rdi,[g_ac_dname+rdi]
	lea	rsi,[g_ac_ident]
	mov	ecx,[g_ac_identl]
	mov	[g_ac_dnamel+r12*4],ecx
	rep	movsb
	imul	edi,r12d,64
	lea	rdi,[g_ac_did+rdi]
	lea	rsi,[g_ac_txt]
	mov	ecx,43
	rep	movsb
	xor	ebx,ebx
.earlier:
	cmp	ebx,r12d
	jae	.find
	cmp	dword [g_ac_didl+rbx*4],0
	je	.earlier_next
	call	r53_same
	jne	.earlier_next
	imul	esi,ebx,64
	lea	rsi,[g_ac_dzone+rsi]
	imul	edi,r12d,64
	lea	rdi,[g_ac_dzone+rdi]
	mov	ecx,[g_ac_dzonel+rbx*4]
	mov	[g_ac_dzonel+r12*4],ecx
	rep	movsb
	jmp	.change
.earlier_next:
	inc	ebx
	jmp	.earlier
.find:
	xor	r13d,r13d
.zone:
	lea	rsi,[g_ac_ident+r13]
	mov	ecx,[g_ac_identl]
	sub	ecx,r13d
	mov	rdi,rsi
	mov	al,'.'
	push	rcx
	repne	scasb
	pop	rcx
	jne	.no_zone
	lea	rdi,[g_ac_durl]
	call	dns_base
	memit_x '/2013-04-01/hostedzonesbyname?dnsname='
	lea	rsi,[g_ac_ident+r13]
	mov	ecx,[g_ac_identl]
	sub	ecx,r13d
	rep	movsb
	memit_x '&maxitems=1'
	lea	rsi,[g_ac_durl]
	mov	rcx,rdi
	sub	rcx,rsi
	xor	edx,edx
	xor	r8d,r8d
	xor	r9d,r9d
	call	dns_request
	jc	.out
	cstring .w_api, 'the Route 53 API refused (the key, or its rights?)',0
	lea	rax,[.w_api]
	mov	[g_ac_why],rax
	cmp	dword [g_ac_st],200
	jne	.fail
	; the first zone from that name on: it, when its Name is the name
	cstring .x_hz, '<HostedZone>',0
	lea	rdi,[.x_hz]
	mov	rsi,[g_ac_rb]
	call	r53_xml
	jc	.parent
	mov	rbx,rax				; (in it)
	cstring .x_name, '<Name>',0
	lea	rdi,[.x_name]
	mov	rsi,rbx
	call	r53_xml
	jc	.parent
	mov	edx,[g_ac_identl]
	sub	edx,r13d
	inc	edx
	cmp	ecx,edx
	jne	.parent
	dec	ecx
	cmp	byte [rax+rcx],'.'
	jne	.parent
	lea	rsi,[g_ac_ident+r13]
	mov	rdi,rax
	repe	cmpsb
	jne	.parent
	cstring .x_id, '<Id>',0
	lea	rdi,[.x_id]
	mov	rsi,rbx
	call	r53_xml
	jc	.parent
	imul	edi,r12d,64
	lea	rdi,[g_ac_dzone+rdi]
	call	r53_id
	jc	.fail
	mov	[g_ac_dzonel+r12*4],eax
	jmp	.change
.parent:
	inc	r13d
	cmp	r13d,[g_ac_identl]
	jae	.no_zone
	cmp	byte [g_ac_ident+r13-1],'.'
	jne	.parent
	jmp	.zone
.change:
	cstring .a_upsert, 'UPSERT',0
	lea	rsi,[.a_upsert]
	call	r53_change
	jc	.out
	mov	dword [g_ac_didl+r12*4],43
	clc
	jmp	.out
.no_zone:
	cstring .w_zone, 'no hosted zone of the account holds the name',0
	lea	rax,[.w_zone]
	mov	[g_ac_why],rax
.fail:
	stc
.out:
	pop	r13
	pop	rbx
	ret

; r12d = an authorization, rsi = the action (cstr): its name's record set, with
; every value made for that name (and its own), changed; the change kept to
; wait on. CF: failed.
r53_change:
	push	rbx
	push	r13
	mov	r13,rsi
	lea	rdi,[g_ac_pay]
	memit_x '<?xml version="1.0" encoding="UTF-8"?>',10,'<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ChangeBatch><Changes><Change><Action>'
	mov	rsi,r13
	call	fmt_cstr
	memit_x '</Action><ResourceRecordSet><Name>_acme-challenge.'
	imul	esi,r12d,256
	lea	rsi,[g_ac_dname+rsi]
	mov	ecx,[g_ac_dnamel+r12*4]
	rep	movsb
	memit_x '.</Name><Type>TXT</Type><TTL>60</TTL><ResourceRecords>'
	xor	ebx,ebx
.value:
	cmp	ebx,ACME_NAMES
	jae	.values
	cmp	ebx,r12d
	je	.it
	cmp	dword [g_ac_didl+rbx*4],0
	je	.next
	push	rdi
	call	r53_same
	pop	rdi
	jne	.next
.it:
	memit_x '<ResourceRecord><Value>"'
	imul	esi,ebx,64
	lea	rsi,[g_ac_did+rsi]
	mov	ecx,43
	rep	movsb
	memit_x '"</Value></ResourceRecord>'
.next:
	inc	ebx
	jmp	.value
.values:
	memit_x '</ResourceRecords></ResourceRecordSet></Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>'
	lea	rdx,[g_ac_pay]
	mov	r8,rdi
	sub	r8,rdx
	push	rdx
	push	r8
	lea	rdi,[g_ac_durl]
	call	dns_base
	memit_x '/2013-04-01/hostedzone/'
	imul	esi,r12d,64
	lea	rsi,[g_ac_dzone+rsi]
	mov	ecx,[g_ac_dzonel+r12*4]
	rep	movsb
	memit_x '/rrset'
	lea	rsi,[g_ac_durl]
	mov	rcx,rdi
	sub	rcx,rsi
	pop	r8
	pop	rdx
	xor	r9d,r9d
	call	dns_request
	jc	.out
	cstring .w_rec, 'Route 53 would not change the TXT record',0
	lea	rax,[.w_rec]
	mov	[g_ac_why],rax
	cmp	dword [g_ac_st],200
	jne	.fail
	cstring .x_ci, '<ChangeInfo>',0
	lea	rdi,[.x_ci]
	mov	rsi,[g_ac_rb]
	call	r53_xml
	jc	.fail
	cstring .x_id, '<Id>',0
	lea	rdi,[.x_id]
	mov	rsi,rax
	call	r53_xml
	jc	.fail
	imul	edi,r12d,64
	lea	rdi,[g_ac_dchg+rdi]
	call	r53_id
	jc	.fail
	mov	[g_ac_dchgl+r12*4],eax
	clc
	jmp	.out
.fail:
	stc
.out:
	pop	r13
	pop	rbx
	ret

; each change made, asked after until INSYNC (a while between, 40 times at
; most). CF: failed.
r53_insync:
	push	r12
	push	r13
	push	r14
	xor	r12d,r12d
.change:
	cmp	r12d,ACME_NAMES
	jae	.done
	cmp	dword [g_ac_dchgl+r12*4],0
	je	.next
	mov	r13d,40
	mov	r14d,200
.ask:
	lea	rdi,[g_ac_durl]
	call	dns_base
	memit_x '/2013-04-01/change/'
	imul	esi,r12d,64
	lea	rsi,[g_ac_dchg+rsi]
	mov	ecx,[g_ac_dchgl+r12*4]
	rep	movsb
	lea	rsi,[g_ac_durl]
	mov	rcx,rdi
	sub	rcx,rsi
	xor	edx,edx
	xor	r8d,r8d
	xor	r9d,r9d
	call	dns_request
	jc	.out
	cstring .w_chg, 'Route 53 would not show its change',0
	lea	rax,[.w_chg]
	mov	[g_ac_why],rax
	cmp	dword [g_ac_st],200
	jne	.fail
	cstring .x_st, '<Status>',0
	lea	rdi,[.x_st]
	mov	rsi,[g_ac_rb]
	call	r53_xml
	jc	.fail
	cmp	ecx,6
	jne	.wait
	cmp	dword [rax],'INSY'
	jne	.wait
	cmp	word [rax+4],'NC'
	je	.next
.wait:
	dec	r13d
	jz	.too_long
	mov	eax,r14d
	call	acme_sleep_ms
	add	r14d,r14d
	cmp	r14d,5000
	jbe	.ask
	mov	r14d,5000
	jmp	.ask
.next:
	mov	dword [g_ac_dchgl+r12*4],0
	inc	r12d
	jmp	.change
.done:
	clc
	jmp	.out
.too_long:
	cstring .w_long, 'Route 53 took too long to apply the record',0
	lea	rax,[.w_long]
	mov	[g_ac_why],rax
.fail:
	stc
.out:
	pop	r14
	pop	r13
	pop	r12
	ret

; r12d = an authorization with its record made: its name's record set deleted
; (every value made for that name), once for them all
r53_remove:
	push	rbx
	cstring .a_delete, 'DELETE',0
	lea	rsi,[.a_delete]
	call	r53_change
	xor	ebx,ebx
.same:
	cmp	ebx,ACME_NAMES
	jae	.done
	cmp	ebx,r12d
	je	.next
	call	r53_same
	jne	.next
	mov	dword [g_ac_didl+rbx*4],0
.next:
	inc	ebx
	jmp	.same
.done:
	mov	dword [g_ac_didl+r12*4],0
	mov	dword [g_ac_dchgl+r12*4],0
	pop	rbx
	ret

; RFC 2136: r12d = the authorization, g_ac_ident its name, g_ac_txt the value:
; the record added, in the zone that takes it (the name, then each parent: one
; that is not the server's answers NOTAUTH or NOTZONE). CF: failed.
rfc_create:
	push	r13
	; this authorization's own: its name and value, for the removal
	imul	edi,r12d,256
	lea	rdi,[g_ac_dname+rdi]
	lea	rsi,[g_ac_ident]
	mov	ecx,[g_ac_identl]
	mov	[g_ac_dnamel+r12*4],ecx
	rep	movsb
	imul	edi,r12d,64
	lea	rdi,[g_ac_did+rdi]
	lea	rsi,[g_ac_txt]
	mov	ecx,43
	rep	movsb
	mov	[g_dn_idx],r12d
	mov	dword [g_dn_mode],0
	xor	r13d,r13d
.zone:
	lea	rsi,[g_ac_ident+r13]
	mov	ecx,[g_ac_identl]
	sub	ecx,r13d
	mov	rdi,rsi
	mov	al,'.'
	push	rcx
	repne	scasb
	pop	rcx
	jne	.no_zone
	mov	[g_dn_zone],rsi
	mov	[g_dn_zonel],ecx
	call	rfc_update
	jc	.out
	test	eax,eax
	jz	.made
	cmp	eax,9				; NOTAUTH
	je	.parent
	cmp	eax,10				; NOTZONE
	je	.parent
	cmp	eax,5				; REFUSED
	je	.parent
	cstring .w_rcode, 'the DNS server refused the update',0
	lea	rax,[.w_rcode]
	mov	[g_ac_why],rax
	stc
	jmp	.out
.parent:
	inc	r13d
	cmp	r13d,[g_ac_identl]
	jae	.no_zone
	cmp	byte [g_ac_ident+r13-1],'.'
	jne	.parent
	jmp	.zone
.made:
	mov	[g_ac_dzonel+r12*4],r13d
	mov	dword [g_ac_didl+r12*4],43
	clc
	jmp	.out
.no_zone:
	cstring .w_zone, 'no zone of the DNS server takes the name',0
	lea	rax,[.w_zone]
	mov	[g_ac_why],rax
	stc
.out:
	pop	r13
	ret

; g_dn_idx/mode/zone: an UPDATE to the server (TCP), signed with TSIG
; (HMAC-SHA256, RFC 8945), adding (or removing) TXT _acme-challenge.NAME with the
; value. The answer's own TSIG verified: eax = its RCODE. CF: no answer, or
; one not signed with the key (g_ac_why).
rfc_update:
	push	rbx
	push	r12
	push	r13
	push	r14
	cstring .w_conn, 'the DNS server cannot be reached',0
	lea	rax,[.w_conn]
	mov	[g_ac_why],rax
	mov	dword [g_ac_st],0
	; the header: an id, UPDATE, one zone, one update
	lea	rbx,[g_dn_msg+2]
	mov	rdi,rbx
	mov	esi,2
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	mov	ax,[rbx]
	mov	[g_dn_id],ax
	mov	word [rbx+2],0x0028		; opcode 5
	mov	word [rbx+4],0x0100		; ZOCOUNT 1
	mov	word [rbx+6],0
	mov	word [rbx+8],0x0100		; UPCOUNT 1
	mov	word [rbx+10],0
	lea	rdi,[rbx+12]
	mov	rsi,[g_dn_zone]
	mov	ecx,[g_dn_zonel]
	call	dns_wire_name
	mov	dword [rdi],0x01000600		; SOA, IN
	add	rdi,4
	; the record: _acme-challenge.NAME TXT
	mov	r12d,[g_dn_idx]
	mov	byte [rdi],15
	inc	rdi
	mov	rax,'_acme-ch'
	mov	[rdi],rax
	mov	rax,'allenge'
	mov	[rdi+8],rax			; (its 8th byte the next label's: written below)
	add	rdi,15
	imul	esi,r12d,256
	lea	rsi,[g_ac_dname+rsi]
	mov	ecx,[g_ac_dnamel+r12*4]
	call	dns_wire_name
	mov	dword [rdi],0x01001000		; TXT, IN
	mov	dword [rdi+4],0x3C000000	; TTL 60
	cmp	dword [g_dn_mode],0
	je	@f
	mov	word [rdi+2],0xFE00		; class NONE: this record removed
	mov	dword [rdi+4],0
@@:
	mov	word [rdi+8],0x2C00		; RDLENGTH 44
	mov	byte [rdi+10],43
	add	rdi,11
	imul	esi,r12d,64
	lea	rsi,[g_ac_did+rsi]
	mov	ecx,43
	rep	movsb
	mov	r12,rdi				; the message's end
	; signed: the message, then TSIG's variables (written where its record goes)
	call	acme_now
	mov	r13,rax				; time signed
	mov	rdi,r12
	xor	r14d,r14d
	call	.vars_head			; key name, ANY, TTL 0, algorithm
	call	.time
	mov	dword [rdi],0x00002C01		; fudge 300, error 0
	mov	word [rdi+4],0			; other: none
	add	rdi,6
	lea	rax,[g_dn_rmac]
	push	rdi
	mov	rdi,rax
	lea	rsi,[g_plan_acme+ACM_DNSSEC]
	mov	edx,[g_plan_acme+ACM_DNSSECL]
	mov	rcx,rbx
	pop	r8
	sub	r8,rbx
	call	hmac_sha256
	; the TSIG record
	mov	rdi,r12
	mov	r14d,1
	call	.vars_head
	mov	r14,rdi				; (its RDLENGTH: patched below)
	sub	r14,13				; (back over the algorithm's name)
	call	.time
	mov	dword [rdi],0x20002C01		; fudge 300, MAC size 32
	add	rdi,4
	lea	rsi,[g_dn_rmac]
	mov	ecx,32
	rep	movsb
	mov	ax,[g_dn_id]
	mov	[rdi],ax			; original id
	mov	dword [rdi+2],0			; error, other length
	add	rdi,6
	mov	word [r14-2],0x3D00		; RDLENGTH 61
	mov	word [rbx+10],0x0100		; ARCOUNT 1
	mov	rax,rdi
	sub	rax,rbx
	mov	[g_dn_len],eax
	xchg	al,ah
	mov	[g_dn_msg],ax
	; to the server: HOST:PORT
	mov	rsi,[g_plan_acme+ACM_DNSSRV]
	mov	ecx,[g_plan_acme+ACM_DNSSRVL]
	mov	r8d,ecx
.colon:
	dec	r8d
	js	.fail
	cmp	byte [rsi+r8],':'
	jne	.colon
	push	rsi
	push	r8
	lea	rdi,[rsi+r8+1]
	mov	esi,ecx
	sub	esi,r8d
	dec	esi
	call	parse_decimal
	pop	r8
	pop	rsi
	jc	.fail
	test	eax,eax
	jz	.fail
	cmp	eax,65535
	ja	.fail
	mov	edx,eax
	mov	ecx,r8d				; (the host as a URL has it: [v6] too)
	lea	rdi,[g_ac_sa]
	call	cx_address
	jc	.fail
	lea	rsi,[g_ac_sa]
	call	cx_connect
	jc	.fail
	mov	edi,[g_cx_fd]
	lea	rsi,[g_dn_msg]
	mov	edx,[g_dn_len]
	add	edx,2
	call	write_all
	lea	rdi,[g_dn_resp]
	mov	edx,2
	call	.read
	jc	.closed
	movzx	edx,word [g_dn_resp]
	xchg	dl,dh
	cmp	edx,12
	jb	.closed
	cmp	edx,4096
	ja	.closed
	mov	[g_dn_len],edx
	lea	rdi,[g_dn_resp]
	call	.read
	jc	.closed
	call	cx_close
	call	rfc_verify
	jmp	.out
.closed:
	call	cx_close
.fail:
	stc
.out:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
; rdi: the key's name, class ANY, TTL 0, and (r14d = 1: as the record, its type
; and RDLENGTH's room; 0: as the variables, none) the algorithm
.vars_head:
	lea	rsi,[g_plan_acme+ACM_DNSKEYN]
	mov	ecx,[g_plan_acme+ACM_DNSKEYNL]
	rep	movsb
	test	r14d,r14d
	jnz	@f
	; (the variables)
	mov	dword [rdi],0xFF00		; ANY, and TTL's first half
	mov	word [rdi+4],0
	add	rdi,6
	jmp	.alg
@@:
	mov	dword [rdi],0xFF00FA00		; TSIG, ANY
	mov	dword [rdi+4],0			; TTL 0
	add	rdi,10				; (and RDLENGTH)
.alg:
	lea	rsi,[.alg_name]
	mov	ecx,13
	rep	movsb
	ret
; rdi: r13 as 48 bits
.time:
	mov	word [rdi],0
	mov	eax,r13d
	bswap	eax
	mov	[rdi+2],eax
	add	rdi,6
	ret
; rdi = out, edx = bytes: read exactly. CF: short.
.read:
	push	rbx
	mov	rbx,rdi
	mov	r8d,edx
.more:
	test	r8d,r8d
	jz	.read_done
	push	r8
	mov	edi,[g_cx_fd]
	mov	rsi,rbx
	mov	edx,r8d
	xor	eax,eax
	syscall
	pop	r8
	cmp	rax,-EINTR
	je	.more
	test	rax,rax
	jle	.read_short
	add	rbx,rax
	sub	r8d,eax
	jmp	.more
.read_done:
	clc
	pop	rbx
	ret
.read_short:
	stc
	pop	rbx
	ret
.alg_name	db 11,'hmac-sha256',0

; The answer (g_dn_resp, g_dn_len): ours, and its TSIG the key's over the
; request's MAC and it. eax = its RCODE. CF: not.
rfc_verify:
	push	rbx
	push	r12
	push	r13
	cstring .w_sig, 'the DNS server',39,'s answer is not signed with the key (dns_key?)',0
	lea	rax,[.w_sig]
	mov	[g_ac_why],rax
	lea	rbx,[g_dn_resp]
	mov	edx,[g_dn_len]
	lea	rdx,[rbx+rdx]			; the end
	mov	ax,[rbx]
	cmp	ax,[g_dn_id]
	jne	.bad
	mov	al,[rbx+2]
	and	al,0xF8
	cmp	al,0xA8				; QR, UPDATE
	jne	.bad
	movzx	eax,word [rbx+10]
	xchg	al,ah
	test	eax,eax
	jz	.bad				; (unsigned)
	; past the zone section and every record but the last
	movzx	eax,word [rbx+4]
	xchg	al,ah
	mov	r12d,eax
	lea	rsi,[rbx+12]
.zones:
	test	r12d,r12d
	jz	.records
	call	.skip_name
	jc	.bad
	add	rsi,4
	dec	r12d
	jmp	.zones
.records:
	movzx	eax,word [rbx+6]
	xchg	al,ah
	mov	r12d,eax
	movzx	eax,word [rbx+8]
	xchg	al,ah
	add	r12d,eax
	movzx	eax,word [rbx+10]
	xchg	al,ah
	lea	r12d,[r12+rax-1]
.rr:
	test	r12d,r12d
	jz	.tsig
	call	.skip_name
	jc	.bad
	lea	rax,[rsi+10]
	cmp	rax,rdx
	ja	.bad
	movzx	eax,word [rsi+8]
	xchg	al,ah
	lea	rsi,[rsi+rax+10]
	dec	r12d
	jmp	.rr
.tsig:
	mov	r13,rsi				; the TSIG record
	call	.skip_name
	jc	.bad
	lea	rax,[rsi+10]
	cmp	rax,rdx
	ja	.bad
	cmp	word [rsi],0xFA00
	jne	.bad
	add	rsi,10				; its RDATA: algorithm, time, fudge, MAC...
	mov	r8,rsi
	call	.skip_name
	jc	.bad
	lea	rax,[rsi+10+32+6]
	cmp	rax,rdx
	ja	.bad
	cmp	word [rsi+8],0x2000		; a 32-byte MAC
	jne	.bad
	mov	r9,rsi				; time and fudge
	; what was signed: the request's MAC, the answer without its TSIG (ARCOUNT
	; one less), the variables
	lea	rdi,[g_dn_dig]
	mov	word [rdi],0x2000
	add	rdi,2
	lea	rsi,[g_dn_rmac]
	mov	ecx,32
	rep	movsb
	mov	r10,rdi
	mov	rsi,rbx
	mov	rcx,r13
	sub	rcx,rbx
	rep	movsb
	movzx	eax,word [r10+10]
	xchg	al,ah
	dec	eax
	xchg	al,ah
	mov	[r10+10],ax
	lea	rsi,[g_plan_acme+ACM_DNSKEYN]
	mov	ecx,[g_plan_acme+ACM_DNSKEYNL]
	rep	movsb
	mov	dword [rdi],0xFF00		; ANY, TTL 0
	mov	word [rdi+4],0
	add	rdi,6
	mov	rsi,r8				; the algorithm, time, fudge (as sent)
	mov	rcx,r9
	add	rcx,8
	sub	rcx,r8
	rep	movsb
	lea	rsi,[r9+10+32+2]		; error, other length, other
	movzx	ecx,word [rsi+2]
	xchg	cl,ch
	add	ecx,4
	lea	rax,[rsi+rcx]
	cmp	rax,rdx
	ja	.bad
	rep	movsb
	lea	rax,[g_dn_dig]
	sub	rdi,rax
	mov	r8,rdi
	lea	rdi,[g_dn_hash]
	lea	rsi,[g_plan_acme+ACM_DNSSEC]
	mov	edx,[g_plan_acme+ACM_DNSSECL]
	lea	rcx,[g_dn_dig]
	call	hmac_sha256
	lea	rsi,[g_dn_hash]
	lea	rdi,[r9+10]
	mov	ecx,32
	repe	cmpsb
	jne	.bad
	movzx	eax,byte [rbx+3]
	and	eax,15
	clc
	jmp	.out
.bad:
	stc
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret
; rsi at a name (rdx the end): rsi past it. CF: broken.
.skip_name:
	cmp	rsi,rdx
	jae	.sn_bad
	movzx	eax,byte [rsi]
	test	eax,eax
	jz	.sn_root
	cmp	eax,0xC0
	jae	.sn_ptr
	cmp	eax,63
	ja	.sn_bad
	lea	rsi,[rsi+rax+1]
	jmp	.skip_name
.sn_root:
	inc	rsi
	clc
	ret
.sn_ptr:
	add	rsi,2
	clc
	ret
.sn_bad:
	stc
	ret

; the records there: dns_wait for them to reach the name's servers, then each
; challenge answered ("{}"). CF: failed.
dns_go:
	push	r12
	cmp	dword [g_plan_acme+ACM_DNS],3
	jne	@f
	call	r53_insync			; Route 53: its changes applied first
	jc	.out
@@:
	mov	eax,[g_plan_acme+ACM_DNSWAIT]
	call	acme_sleep_ms
	xor	r12d,r12d
.chal:
	cmp	r12d,[g_ac_nauthz]
	jae	.done
	cmp	dword [g_ac_dpost+r12*4],0
	je	.next
	mov	word [g_ac_pay],'{}'
	mov	dword [g_ac_payl],2
	imul	esi,r12d,ACME_URL
	lea	rsi,[g_ac_dchal+rsi]
	mov	ecx,[g_ac_dchall+r12*4]
	call	acme_post
	jc	.out
	cstring .w_chal, 'the challenge',0
	lea	rax,[.w_chal]
	mov	[g_ac_why],rax
	cmp	dword [g_ac_st],200
	jne	.bad
.next:
	inc	r12d
	jmp	.chal
.done:
	clc
	jmp	.out
.bad:
	stc
.out:
	pop	r12
	ret

; the records made, removed (DELETE zones/ZONE/dns_records/ID)
dns_clean:
	push	r12
	xor	r12d,r12d
.rec:
	cmp	r12d,ACME_NAMES
	jae	.done
	cmp	dword [g_ac_didl+r12*4],0
	je	.next
	cmp	dword [g_plan_acme+ACM_DNS],3
	jne	@f
	call	r53_remove
	jmp	.next
@@:
	cmp	dword [g_plan_acme+ACM_DNS],2
	jne	.api
	mov	[g_dn_idx],r12d
	mov	dword [g_dn_mode],1
	mov	eax,[g_ac_dzonel+r12*4]
	imul	ecx,r12d,256
	lea	rsi,[g_ac_dname+rcx+rax]
	mov	[g_dn_zone],rsi
	mov	ecx,[g_ac_dnamel+r12*4]
	sub	ecx,eax
	mov	[g_dn_zonel],ecx
	call	rfc_update
	mov	dword [g_ac_didl+r12*4],0
	jmp	.next
.api:
	lea	rdi,[g_ac_durl]
	call	dns_base
	memit_x '/zones/'
	imul	esi,r12d,64
	lea	rsi,[g_ac_dzone+rsi]
	mov	ecx,[g_ac_dzonel+r12*4]
	rep	movsb
	memit_x '/dns_records/'
	imul	esi,r12d,64
	lea	rsi,[g_ac_did+rsi]
	mov	ecx,[g_ac_didl+r12*4]
	rep	movsb
	lea	rsi,[g_ac_durl]
	mov	rcx,rdi
	sub	rcx,rsi
	xor	edx,edx
	cstring .m_delete, 'DELETE ',0
	lea	r9,[.m_delete]
	call	dns_request
	mov	dword [g_ac_didl+r12*4],0
.next:
	inc	r12d
	jmp	.rec
.done:
	pop	r12
	ret

; ------------------------------------------------------------ the order

; ebx = a certificate: asked for, proven, fetched and stored. CF: failed
; (g_ac_why, and g_ac_st the last status).
acme_issue:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	dword [g_ac_kidl],0
	mov	dword [g_ac_noncel],0
	mov	dword [g_ac_nauthz],0
	lea	rdi,[g_ac_didl]
	xor	eax,eax
	mov	ecx,ACME_NAMES * 2		; (g_ac_didl, g_ac_dpost)
	rep	stosd
	call	acme_cert_args
	mov	r14,rax				; the names
	mov	r15d,ecx
	; the directory
	mov	rsi,[g_plan_acme+ACM_CA]
	mov	ecx,[g_plan_acme+ACM_CAL]
	cmp	dword [g_ac_cai],1
	jb	@f
	mov	rsi,[g_plan_acme+ACM_FB]
	mov	ecx,[g_plan_acme+ACM_FBL]
	je	@f
	mov	rsi,[g_plan_acme+ACM_STG]
	mov	ecx,[g_plan_acme+ACM_STGL]
@@:
	xor	edx,edx
	call	acme_request
	jc	.out
	cstring .w_dir, 'the CA',39,'s directory',0
	lea	rax,[.w_dir]
	mov	[g_ac_why],rax
	cmp	dword [g_ac_st],200
	jne	.bad
	cstring .n_nonce, 'newNonce',0
	lea	rdi,[.n_nonce]
	lea	r9,[g_ac_unonce]
	call	.url_field
	jc	.bad
	mov	[g_ac_unoncel],eax
	cstring .n_acct, 'newAccount',0
	lea	rdi,[.n_acct]
	lea	r9,[g_ac_uacct]
	call	.url_field
	jc	.bad
	mov	[g_ac_uacctl],eax
	cstring .n_order, 'newOrder',0
	lea	rdi,[.n_order]
	lea	r9,[g_ac_uorder]
	call	.url_field
	jc	.bad
	mov	[g_ac_uorderl],eax
	; meta.externalAccountRequired
	mov	dword [g_ac_eabreq],0
	mov	rsi,[g_ac_rb]
	mov	edx,[g_ac_rbl]
	add	rdx,rsi
	cstring .n_meta, 'meta'
	lea	rdi,[.n_meta]
	mov	ecx,4
	call	json_get
	jc	.meta_done
	test	rax,rax
	jz	.meta_done
	cmp	byte [rax],'{'
	jne	.meta_done
	mov	rsi,rax
	mov	rdx,r8
	cstring .n_ear, 'externalAccountRequired'
	lea	rdi,[.n_ear]
	mov	ecx,23
	call	json_get
	jc	.meta_done
	test	rax,rax
	jz	.meta_done
	cmp	byte [rax],'t'
	jne	.meta_done
	mov	dword [g_ac_eabreq],1
.meta_done:
	; the account: made, or found (the same key)
	call	acme_eab_of			; rsi = KID, ecx its length (0 none), rdx = key, r8d its
	test	ecx,ecx
	jnz	@f
	cstring .w_eab, 'the CA asks for an external account binding (eab=)',0
	lea	rax,[.w_eab]
	mov	[g_ac_why],rax
	cmp	dword [g_ac_eabreq],0
	jne	.bad
@@:
	lea	rdi,[g_ac_pay]
	memit_x '{"termsOfServiceAgreed":true'
	cmp	dword [g_plan_acme+ACM_EMAILL],0
	je	@f
	memit_x ',"contact":["mailto:'
	mov	rsi,[g_plan_acme+ACM_EMAIL]
	mov	ecx,[g_plan_acme+ACM_EMAILL]
	rep	movsb
	memit_x '"]'
@@:
	call	acme_eab			; ,"externalAccountBinding":{...}, when one
	memit_x '}'
	call	.payload
	lea	rsi,[g_ac_uacct]
	mov	ecx,[g_ac_uacctl]
	call	acme_post
	jc	.out
	cstring .w_acct, 'the account',0
	lea	rax,[.w_acct]
	mov	[g_ac_why],rax
	mov	eax,[g_ac_st]
	cmp	eax,200
	je	@f
	cmp	eax,201
	jne	.bad
@@:
	mov	ecx,[g_ac_locl]
	test	ecx,ecx
	jz	.bad
	mov	[g_ac_kidl],ecx
	lea	rsi,[g_ac_loc]
	lea	rdi,[g_ac_kid]
	rep	movsb
	; the order
	lea	rdi,[g_ac_pay]
	memit_x '{"identifiers":['
	mov	rsi,r14
	mov	ecx,r15d
.ident:
	push	rcx
	push	rsi
	memit_x '{"type":"dns","value":"'
	mov	rsi,[rsp]
	mov	ecx,[rsi+A_VLEN]
	mov	rsi,[rsi+A_VAL]
	rep	movsb
	memit_x '"}'
	pop	rsi
	pop	rcx
	add	rsi,A_SIZE
	dec	ecx
	jz	@f
	mov	byte [rdi],','
	inc	rdi
	jmp	.ident
@@:
	mov	byte [rdi],']'
	inc	rdi
	cmp	dword [g_ac_cai],0		; ARI: the certificate it replaces
	jne	@f
	cmp	dword [g_ac_arigot+rbx*4],0
	je	@f
	memit_x ',"replaces":"'
	imul	esi,ebx,128
	lea	rsi,[g_ac_certid+rsi]
	mov	ecx,[g_ac_certidl+rbx*4]
	rep	movsb
	mov	byte [rdi],'"'
	inc	rdi
@@:
	mov	byte [rdi],'}'
	inc	rdi
	call	.payload
	lea	rsi,[g_ac_uorder]
	mov	ecx,[g_ac_uorderl]
	call	acme_post
	jc	.out
	cstring .w_order, 'the order',0
	lea	rax,[.w_order]
	mov	[g_ac_why],rax
	mov	eax,[g_ac_st]
	cmp	eax,200
	je	@f
	cmp	eax,201
	jne	.bad
@@:
	mov	ecx,[g_ac_locl]
	test	ecx,ecx
	jz	.bad
	mov	[g_ac_ordl],ecx
	lea	rsi,[g_ac_loc]
	lea	rdi,[g_ac_ord]
	rep	movsb
	cstring .n_fin, 'finalize',0
	lea	rdi,[.n_fin]
	lea	r9,[g_ac_fin]
	call	.url_field
	jc	.bad
	mov	[g_ac_finl],eax
	call	acme_authz_list
	jc	.bad
	; each authorization: its HTTP-01 challenge, answered by the workers
	xor	r12d,r12d
.authz:
	cmp	r12d,[g_ac_nauthz]
	jae	.proven
	call	acme_prove
	jc	.out
	inc	r12d
	jmp	.authz
.proven:
	cmp	dword [g_plan_acme+ACM_CHAL],2
	jne	@f
	call	dns_go
	jc	.out
@@:
	xor	r12d,r12d
.wait_authz:
	cmp	r12d,[g_ac_nauthz]
	jae	.authorized
	imul	esi,r12d,ACME_URL
	lea	rsi,[g_ac_authz+rsi]
	mov	ecx,[g_ac_authzl+r12*4]
	call	acme_poll
	jc	.out
	cstring .w_invalid, 'a name not proven (is port 80 this okena',39,'s?)',0
	lea	rax,[.w_invalid]
	mov	[g_ac_why],rax
	cstring .s_valid, 'valid',0
	lea	rsi,[.s_valid]
	call	acme_is
	jne	.bad
	inc	r12d
	jmp	.wait_authz
.authorized:
	; the order, ready
	lea	rsi,[g_ac_ord]
	mov	ecx,[g_ac_ordl]
	call	acme_poll
	jc	.out
	cstring .w_ready, 'the order is not ready',0
	lea	rax,[.w_ready]
	mov	[g_ac_why],rax
	cstring .s_ready, 'ready',0
	lea	rsi,[.s_ready]
	call	acme_is
	jne	.bad
	; a new key, and its CSR
	cstring .w_key, 'a key or a CSR',0
	lea	rax,[.w_key]
	mov	[g_ac_why],rax
	call	x5_keygen
	jc	.bad
	lea	rdi,[g_ac_names]
	mov	rsi,r14
	mov	edx,r15d
	call	acme_names
	lea	rsi,[g_ac_names]
	call	x5_csr
	jc	.bad
	push	rax
	lea	rdi,[g_ac_pay]
	memit_x '{"csr":"'
	lea	rsi,[g_x5_der2]
	pop	rdx
	call	base64url_encode
	memit_x '"}'
	call	.payload
	lea	rsi,[g_ac_fin]
	mov	ecx,[g_ac_finl]
	call	acme_post
	jc	.out
	cstring .w_fin, 'the CSR (finalize)',0
	lea	rax,[.w_fin]
	mov	[g_ac_why],rax
	cmp	dword [g_ac_st],200
	jne	.bad
	; issued
	lea	rsi,[g_ac_ord]
	mov	ecx,[g_ac_ordl]
	call	acme_poll
	jc	.out
	cstring .w_issued, 'the certificate was not issued',0
	lea	rax,[.w_issued]
	mov	[g_ac_why],rax
	lea	rsi,[.s_valid]
	call	acme_is
	jne	.bad
	cstring .n_cert, 'certificate',0
	lea	rdi,[.n_cert]
	lea	r9,[g_ac_crt]
	call	.url_field
	jc	.bad
	mov	[g_ac_crtl],eax
	mov	dword [g_ac_payl],0
	lea	rsi,[g_ac_crt]
	mov	ecx,[g_ac_crtl]
	call	acme_post
	jc	.out
	cstring .w_chain, 'the certificate chain',0
	lea	rax,[.w_chain]
	mov	[g_ac_why],rax
	cmp	dword [g_ac_st],200
	jne	.bad
	; a chain of PEM, the first for the key just made
	mov	rsi,[g_ac_rb]
	mov	edx,[g_ac_rbl]
	lea	rdi,[g_ac_der]
	call	pem_first_cert
	test	eax,eax
	jz	.bad
	lea	rsi,[g_ac_der]
	mov	edx,eax
	call	x509_locate
	test	eax,eax
	jz	.bad
	cmp	dword [g_ac_cai],2		; the staging CA's: only to know it would work
	je	.staged
	; stored: the key, then the certificate
	cstring .w_write, 'the files could not be written',0
	lea	rax,[.w_write]
	mov	[g_ac_why],rax
	call	x5_sec1
	mov	ecx,eax
	lea	rsi,[g_x5_der]
	lea	rdx,[pem_l_ec]
	lea	rdi,[g_x5_pem]
	call	x5_pem
	push	rdi
	cstring .f_key, '/key.pem',0
	lea	rsi,[.f_key]
	call	acme_path
	pop	rdx
	lea	rsi,[g_x5_pem]
	sub	rdx,rsi
	call	acme_write
	jc	.bad
	cstring .f_cert, '/cert.pem',0
	lea	rsi,[.f_cert]
	call	acme_path
	mov	rsi,[g_ac_rb]
	mov	edx,[g_ac_rbl]
	call	acme_write
	jc	.bad
.staged:
	clc
	jmp	.out
.bad:
	stc
.out:
	pushfq					; (as it went, whatever the cleaning does)
	cmp	dword [g_plan_acme+ACM_CHAL],2
	jne	@f
	push	qword [g_ac_why]
	push	qword [g_ac_st]
	call	dns_clean
	pop	qword [g_ac_st]
	pop	qword [g_ac_why]
@@:
	popfq
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
; rdi = the payload's end: its length
.payload:
	lea	rax,[g_ac_pay]
	sub	rdi,rax
	mov	[g_ac_payl],edi
	ret
; rdi = a member's name, r9 = out (ACME_URL): a URL. eax its length.
.url_field:
	mov	r10d,ACME_URL - 1
	jmp	acme_field

; the CA being asked's external account: rsi = its key id, ecx its length (0:
; none), rdx = its HMAC key, r8d that one's length
acme_eab_of:
	lea	rsi,[g_plan_acme+ACM_EABK]
	mov	ecx,[g_plan_acme+ACM_EABKL]
	lea	rdx,[g_plan_acme+ACM_EABH]
	mov	r8d,[g_plan_acme+ACM_EABHL]
	cmp	dword [g_ac_cai],1
	jne	@f
	lea	rsi,[g_plan_acme+ACM_FBEABK]
	mov	ecx,[g_plan_acme+ACM_FBEABKL]
	lea	rdx,[g_plan_acme+ACM_FBEABH]
	mov	r8d,[g_plan_acme+ACM_FBEABHL]
@@:
	ret

; rdi = the newAccount payload so far: ,"externalAccountBinding":{"protected":
; base64url({"alg":"HS256","kid":KID,"url":newAccount}), "payload": base64url(the
; account's JWK), "signature": HMAC-SHA256 with the external account's key}, when
; there is one. rdi past it.
acme_eab:
	push	rbx
	push	r12
	push	r13
	mov	rbx,rdi
	call	acme_eab_of
	test	ecx,ecx
	jz	.none
	mov	r12,rdx
	mov	r13d,r8d
	lea	rdi,[g_ac_prot]
	push	rsi
	push	rcx
	memit_x '{"alg":"HS256","kid":"'
	pop	rcx
	pop	rsi
	rep	movsb
	memit_x '","url":"'
	lea	rsi,[g_ac_uacct]
	mov	ecx,[g_ac_uacctl]
	rep	movsb
	memit_x '"}'
	lea	rsi,[g_ac_prot]
	mov	rdx,rdi
	sub	rdx,rsi
	lea	rdi,[g_ac_b64]
	call	base64url_encode
	push	rdi				; the protected part's end
	mov	byte [rdi],'.'
	inc	rdi
	lea	rsi,[g_ac_jwk]
	mov	edx,[g_ac_jwkl]
	call	base64url_encode
	push	rdi				; the payload's end
	lea	rdi,[g_ac_hash]
	mov	rsi,r12
	mov	edx,r13d
	lea	rcx,[g_ac_b64]
	mov	r8,[rsp]
	sub	r8,rcx
	call	hmac_sha256
	pop	r9
	pop	r8
	mov	rdi,rbx
	memit_x ',"externalAccountBinding":{"protected":"'
	lea	rsi,[g_ac_b64]
	mov	rcx,r8
	sub	rcx,rsi
	rep	movsb
	memit_x '","payload":"'
	lea	rsi,[r8+1]
	mov	rcx,r9
	sub	rcx,rsi
	rep	movsb
	memit_x '","signature":"'
	lea	rsi,[g_ac_hash]
	mov	edx,32
	call	base64url_encode
	memit_x '"}'
	jmp	.out
.none:
	mov	rdi,rbx
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; the order's "authorizations" (its body): g_ac_authz, g_ac_nauthz. CF: none,
; or more than names.
acme_authz_list:
	push	rbx
	mov	dword [g_ac_nauthz],0
	mov	rsi,[g_ac_rb]
	mov	edx,[g_ac_rbl]
	add	rdx,rsi
	cstring .n_authz, 'authorizations'
	lea	rdi,[.n_authz]
	mov	ecx,14
	call	json_get
	jc	.bad
	test	rax,rax
	jz	.bad
	mov	rsi,rax
	mov	rdx,r8
	cmp	byte [rsi],'['
	jne	.bad
	inc	rsi
.item:
	call	json_ws
	cmp	rsi,rdx
	jae	.bad
	cmp	byte [rsi],']'
	je	.done
	mov	rbx,rsi
	call	json_skip_value
	jc	.bad
	mov	eax,[g_ac_nauthz]
	cmp	eax,ACME_NAMES
	jae	.bad
	mov	r8,rsi
	push	rsi
	push	rdx
	mov	rsi,rbx
	imul	edi,eax,ACME_URL
	lea	rdi,[g_ac_authz+rdi]
	mov	ecx,ACME_URL - 1
	call	json_string
	pop	rdx
	pop	rsi
	jc	.bad
	mov	ecx,[g_ac_nauthz]
	mov	[g_ac_authzl+rcx*4],eax
	imul	edi,ecx,ACME_URL
	push	rsi
	lea	rsi,[g_ac_authz+rdi]
	mov	ecx,eax
	call	acme_safe
	pop	rsi
	jc	.bad
	inc	dword [g_ac_nauthz]
	call	json_ws
	cmp	rsi,rdx
	jae	.bad
	cmp	byte [rsi],','
	jne	.item
	inc	rsi
	jmp	.item
.done:
	cmp	dword [g_ac_nauthz],0
	je	.bad
	clc
	pop	rbx
	ret
.bad:
	stc
	pop	rbx
	ret

; r12d = an authorization: asked for, and when it is not valid yet, its HTTP-01
; challenge in slot r12d and answered ("{}"). CF: failed.
acme_prove:
	push	rbx
	mov	dword [g_ac_payl],0
	imul	esi,r12d,ACME_URL
	lea	rsi,[g_ac_authz+rsi]
	mov	ecx,[g_ac_authzl+r12*4]
	call	acme_post
	jc	.out
	cstring .w_authz, 'an authorization',0
	lea	rax,[.w_authz]
	mov	[g_ac_why],rax
	cmp	dword [g_ac_st],200
	jne	.bad
	call	acme_status
	jc	.bad
	cstring .s_valid, 'valid',0
	lea	rsi,[.s_valid]
	call	acme_is
	je	.ok				; (proven before, for this account)
	; its name: identifier.value
	mov	rsi,[g_ac_rb]
	mov	edx,[g_ac_rbl]
	add	rdx,rsi
	cstring .n_ident, 'identifier'
	lea	rdi,[.n_ident]
	mov	ecx,10
	call	json_get
	jc	.bad
	test	rax,rax
	jz	.bad
	mov	rsi,rax
	mov	rdx,r8
	cstring .n_value, 'value'
	lea	rdi,[.n_value]
	mov	ecx,5
	call	json_get
	jc	.bad
	test	rax,rax
	jz	.bad
	mov	rsi,rax
	lea	rdi,[g_ac_ident]
	mov	ecx,253
	call	json_string
	jc	.bad
	mov	[g_ac_identl],eax
	lea	rsi,[g_ac_ident]
	mov	ecx,eax
	call	acme_safe
	jc	.bad
	; the challenges: the one of the type wanted
	cstring .w_http01, 'the CA offers no challenge of the type wanted',0
	lea	rax,[.w_http01]
	mov	[g_ac_why],rax
	mov	rsi,[g_ac_rb]
	mov	edx,[g_ac_rbl]
	add	rdx,rsi
	cstring .n_ch, 'challenges'
	lea	rdi,[.n_ch]
	mov	ecx,10
	call	json_get
	jc	.bad
	test	rax,rax
	jz	.bad
	mov	rsi,rax
	mov	rdx,r8
	cmp	byte [rsi],'['
	jne	.bad
	inc	rsi
.item:
	call	json_ws
	cmp	rsi,rdx
	jae	.bad
	cmp	byte [rsi],']'
	je	.bad
	mov	rbx,rsi				; this one
	call	json_skip_value
	jc	.bad
	push	rsi
	push	rdx
	mov	rdx,rsi				; its end
	mov	rsi,rbx
	cstring .n_type, 'type'
	lea	rdi,[.n_type]
	mov	ecx,4
	call	json_get
	jc	.not_it
	test	rax,rax
	jz	.not_it
	mov	rcx,r8
	sub	rcx,rax
	cmp	dword [g_plan_acme+ACM_CHAL],1
	je	.want_tls
	ja	.want_dns
	cmp	rcx,9
	jne	.not_it
	mov	rcx,'"http-01'
	cmp	[rax],rcx
	jne	.not_it
	jmp	.found
.want_dns:
	cmp	rcx,8
	jne	.not_it
	mov	rcx,'"dns-01"'
	cmp	[rax],rcx
	jne	.not_it
	jmp	.found
.want_tls:
	cmp	rcx,13
	jne	.not_it
	mov	rcx,'"tls-alp'
	cmp	[rax],rcx
	jne	.not_it
	cmp	dword [rax+8],'n-01'
	jne	.not_it
.found:
	; it: its url and token
	mov	[g_ac_rb],rbx			; (the body, from here: this object)
	mov	rax,rdx
	sub	rax,rbx
	mov	[g_ac_rbl],eax
	add	rsp,16
	cstring .n_url, 'url',0
	lea	rdi,[.n_url]
	lea	r9,[g_ac_chal]
	mov	r10d,ACME_URL - 1
	call	acme_field
	jc	.bad
	mov	[g_ac_chall],eax
	cstring .n_token, 'token',0
	lea	rdi,[.n_token]
	lea	r9,[g_ac_tok]
	mov	r10d,AS_TOKMAX
	call	acme_field
	jc	.bad
	mov	[g_ac_tokl],eax
	test	eax,eax
	jz	.bad
	xor	ecx,ecx				; base64url
@@:
	movzx	edx,byte [g_ac_tok+rcx]
	inc	ecx
	cmp	dl,'-'
	je	.tch
	cmp	dl,'_'
	je	.tch
	cmp	dl,'0'
	jb	.bad
	cmp	dl,'9'
	jbe	.tch
	or	dl,0x20
	cmp	dl,'a'
	jb	.bad
	cmp	dl,'z'
	ja	.bad
.tch:
	cmp	ecx,eax
	jb	@b
	; the key authorization: token.thumbprint
	lea	rdi,[g_ac_ka]
	lea	rsi,[g_ac_tok]
	mov	ecx,[g_ac_tokl]
	rep	movsb
	mov	byte [rdi],'.'
	inc	rdi
	lea	rsi,[g_ac_thumb]
	mov	ecx,43
	rep	movsb
	lea	rax,[g_ac_ka]
	sub	rdi,rax
	push	rdi				; its length
	cmp	dword [g_plan_acme+ACM_CHAL],1
	je	.tls_slot
	ja	.dns_record
	; HTTP-01's slot: the token and it, the length last
	mov	rax,[g_acme_page]
	imul	ecx,r12d,AS_SIZE
	lea	rbx,[rax+AH_SLOT+rcx]
	mov	dword [rbx+AS_TLEN],0
	lea	rdi,[rbx+AS_TOK]
	lea	rsi,[g_ac_tok]
	mov	ecx,[g_ac_tokl]
	rep	movsb
	pop	rcx
	mov	[rbx+AS_KLEN],ecx
	lea	rdi,[rbx+AS_KA]
	lea	rsi,[g_ac_ka]
	rep	movsb
	mov	eax,[g_ac_tokl]
	mov	[rbx+AS_TLEN],eax
	cmp	dword [g_plan_acme+ACM_SHARED],0
	je	.ready
	push	rbx
	mov	rbx,[rsp+8]			; (the certificate)
	call	acme_fleet_publish		; for the other instances too
	pop	rbx
	jmp	.ready
.dns_record:
	; DNS-01's: a TXT record _acme-challenge.NAME = base64url(SHA-256(it)); the
	; challenge is answered once every record is there and has spread
	pop	rdx
	lea	rdi,[g_ac_kah]
	lea	rsi,[g_ac_ka]
	call	sha256
	lea	rdi,[g_ac_txt]
	lea	rsi,[g_ac_kah]
	mov	edx,32
	call	base64url_encode
	call	dns_create
	jc	.bad
	imul	edi,r12d,ACME_URL
	lea	rdi,[g_ac_dchal+rdi]
	lea	rsi,[g_ac_chal]
	mov	ecx,[g_ac_chall]
	mov	[g_ac_dchall+r12*4],ecx
	rep	movsb
	mov	dword [g_ac_dpost+r12*4],1
	jmp	.ok
.tls_slot:
	; TLS-ALPN-01's: a certificate for the name that carries its hash
	pop	rdx
	lea	rdi,[g_ac_kah]
	lea	rsi,[g_ac_ka]
	call	sha256
	cstring .w_tlscert, 'the TLS-ALPN-01 certificate',0
	lea	rax,[.w_tlscert]
	mov	[g_ac_why],rax
	call	x5_keygen
	jc	.bad
	lea	rdi,[g_ac_names]
	lea	rsi,[g_ac_ident]
	mov	ecx,[g_ac_identl]
	rep	movsb
	mov	word [rdi],0
	lea	rax,[g_ac_kah]
	mov	[g_x5_acmeid],rax
	lea	rsi,[g_ac_names]
	mov	edx,ACME_DAYS_SELF
	call	x5_selfsigned
	mov	qword [g_x5_acmeid],0
	jc	.bad
	cmp	eax,AX_CHAINMAX - 5
	ja	.bad
	mov	rcx,[g_acme_page]
	imul	edx,r12d,AX_SIZE
	lea	rbx,[rcx+ACME_TSLOT+rdx]
	mov	dword [rbx+AX_NLEN],0
	lea	ecx,[rax+5]
	mov	[rbx+AX_CLEN],ecx
	mov	ecx,eax				; the certificate_list: one entry, no extensions
	bswap	eax
	shr	eax,8
	mov	[rbx+AX_CHAIN],ax
	shr	eax,16
	mov	[rbx+AX_CHAIN+2],al
	lea	rdi,[rbx+AX_CHAIN+3]
	lea	rsi,[g_x5_der2]
	rep	movsb
	mov	word [rdi],0
	lea	rsi,[g_x5_d]
	lea	rdi,[rbx+AX_KEY]
	mov	ecx,32
	rep	movsb
	lea	rsi,[g_x5_pub]
	lea	rdi,[rbx+AX_PUB]
	mov	ecx,65
	rep	movsb
	lea	rsi,[g_ac_ident]
	lea	rdi,[rbx+AX_NAME]
	mov	ecx,[g_ac_identl]
	rep	movsb
	mov	eax,[g_ac_identl]
	mov	[rbx+AX_NLEN],eax
.ready:
	; ready: told so
	mov	word [g_ac_pay],'{}'
	mov	dword [g_ac_payl],2
	lea	rsi,[g_ac_chal]
	mov	ecx,[g_ac_chall]
	call	acme_post
	jc	.out
	cstring .w_chal, 'the challenge',0
	lea	rax,[.w_chal]
	mov	[g_ac_why],rax
	cmp	dword [g_ac_st],200
	jne	.bad
.ok:
	clc
	jmp	.out
.not_it:
	pop	rdx
	pop	rsi
	call	json_ws
	cmp	rsi,rdx
	jae	.bad
	cmp	byte [rsi],','
	jne	.item
	inc	rsi
	jmp	.item
.bad:
	stc
.out:
	pop	rbx
	ret
