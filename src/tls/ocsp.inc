; OCSP stapling (RFC 6960, 6066, 8446 4.4.2.1): a client that asks (status_request)
; gets, with the certificate, the CA's own word that it is not revoked, so it need
; not ask the CA itself (slow, and the CA learns where it goes).
;
; A process of its own, okena-ocsp, asks: for each certificate of a listener whose
; chain names its issuer and whose leaf names an OCSP responder (http://, in its
; Authority Information Access), a request for it by CertID (SHA-1 of the issuer's
; name and key, and the serial: RFC 5019's), POSTed. The answer is taken only when
; it is signed by the issuer, or by a responder the issuer delegated to (its own
; certificate, signed by the issuer, for OCSPSigning), names this certificate, says
; "good", and is current (thisUpdate passed, nextUpdate to come). It is asked for
; again halfway to its nextUpdate (a day when it has none); on failure after 5
; minutes, then twice as long up to an hour, the last good one kept until its
; nextUpdate. A revoked certificate is said in the log, and nothing is stapled.
;
; The answers go in a page the supervisor shares, a slot per certificate entry,
; under a seqlock, with the SHA-256 of the leaf they are for: a reload that moves
; the entries staples nothing wrong. Workers copy one in the TLS 1.3 handshake
; when the client asked, into the leaf's CertificateEntry extensions.
; `tls { ocsp off }` keeps a block's certificates out of it.

OS_SEQ		:= 0				; d: odd while written
OS_LEN		:= 4				; d: the answer's length, 0 none
OS_TAG		:= 8				; q: the leaf's SHA-256, first 8 bytes
OS_UNTIL	:= 16				; q: its nextUpdate (seconds since 1970)
OS_DER		:= 24
OS_SIZE		:= 4096
OS_MAX		:= OS_SIZE - OS_DER
OCSP_PAGE	:= OS_SIZE * MAX_TLS

bss
	align 8
	g_ocsp_page	dq ?			; shared: the answers
	g_ocsp_pid	dd ?
	g_oc_n		dd ?			; a worker: the answer to staple now, 0 none
	g_oc_tag	rq MAX_TLS		; each entry's leaf's tag (0: not yet worked out)
	g_plan_ocspoff	rb MAX_TLS		; `ocsp off` for that entry
	g_oc_tmp:	rb OS_MAX
	; the ocsp process's
	align 8
	g_oc_due	rq MAX_TLS
	g_oc_back	rq MAX_TLS
	g_oc_said	rb MAX_TLS		; revoked: said once
	g_oc_until	dq ?
	g_oc_leaf	dq ?
	g_oc_iss	dq ?
	g_oc_serial	dq ?
	g_oc_issname	dq ?			; the leaf's issuer Name, whole (TLV)
	g_oc_leafl	dd ?
	g_oc_issl	dd ?
	g_oc_seriall	dd ?
	g_oc_issnamel	dd ?
	g_oc_hostl	dd ?
	g_oc_port	dd ?
	g_oc_urll	dd ?
	g_oc_reql	dd ?
	g_oc_basicl	dd ?
	g_oc_basic	dq ?
	g_oc_namehash:	rb 20
	g_oc_keyhash:	rb 20
	g_oc_dig:	rb 32
	g_oc_t14:	rb 16
	g_oc_url:	rb 256
	g_oc_host:	rb 256
	g_oc_sa:	rb 128
	g_oc_req:	rb 2048
	g_oc_issuer:	rb PK_SIZE
	g_oc_resp:	rb PK_SIZE
end bss

rodata
	ocsp_name	db 'okena-ocsp',0
	oc_oid_aia	db 0x2B,0x06,0x01,0x05,0x05,0x07,0x01,0x01	; 1.3.6.1.5.5.7.1.1
	oc_oid_ocsp	db 0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x01	; 1.3.6.1.5.5.7.48.1
	oc_oid_basic	db 0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x01,0x01	; ...48.1.1
	oc_eku_sign	db 0x06,0x08,0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x09	; OCSPSigning
	oc_sha1_alg	db 0x30,0x09,0x06,0x05,0x2B,0x0E,0x03,0x02,0x1A,0x05,0x00
	oc_sha1_alg.len = $ - oc_sha1_alg
end rodata

; ------------------------------------------------------------ the supervisor

; the shared page, once, before any fork
ocsp_page_init:
	cmp	qword [g_ocsp_page],0
	jne	.out
	xor	edi,edi
	mov	esi,OCSP_PAGE
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.out
	mov	[g_ocsp_page],rax
.out:
	ret

; a process for it, when a certificate of a listener names a responder
spawn_ocsp:
	cmp	qword [g_ocsp_page],0
	je	.none
	push	rbx
	xor	ebx,ebx
.entry:
	cmp	ebx,[g_plan_tls]
	jae	.no_work
	call	ocsp_entry			; (eligible?)
	jnc	.work
	inc	ebx
	jmp	.entry
.no_work:
	pop	rbx
.none:
	ret
.work:
	pop	rbx
	mov	eax,SYS_fork
	syscall
	test	rax,rax
	jz	ocsp_main
	js	.none
	mov	[g_ocsp_pid],eax
	ret

; a reload: the one running goes, a new one looks at the new plan
ocsp_reload:
	mov	edi,[g_ocsp_pid]
	test	edi,edi
	jz	spawn_ocsp
	mov	dword [g_ocsp_pid],0
	call	acme_stop
	jmp	spawn_ocsp

; ------------------------------------------------------------------ an entry

; ebx = a tls entry: g_oc_leaf/leafl, g_oc_iss/issl (the next in its chain) and
; g_oc_url (its responder, http://). CF: not one to ask for (`ocsp off`, a pool's
; client certificate, no issuer in the chain, no responder).
ocsp_entry:
	cmp	byte [g_plan_ocspoff+rbx],0
	jne	.no
	imul	rax,rbx,TL_SIZE
	lea	r9,[g_tls+rax]
	cmp	dword [r9+TL_GROUP],0x40000000	; (an upstream client certificate)
	jae	.no
	mov	esi,[r9+TL_CHAIN]
	lea	rsi,[g_tls_store+rsi]
	mov	r8d,[r9+TL_CLEN]
	add	r8,rsi
	call	chain_entry
	jc	.no
	mov	[g_oc_leaf],rax
	mov	[g_oc_leafl],ecx
	mov	rsi,rdx
	cmp	rsi,r8
	jae	.no
	call	chain_entry
	jc	.no
	mov	[g_oc_iss],rax
	mov	[g_oc_issl],ecx
	; the leaf's AIA: an access description id-ad-ocsp, its URI
	mov	rsi,[g_oc_leaf]
	mov	edx,[g_oc_leafl]
	call	x509_locate
	test	eax,eax
	jz	.no
	mov	rsi,[g_x509_ext]
	test	rsi,rsi
	jz	.no
.ext:
	cmp	rsi,[g_x509_extend]
	jae	.no
	mov	rdx,[g_x509_extend]
	call	der_read			; Extension
	jc	.no
	cmp	al,0x30
	jne	.no
	push	r8
	lea	rdx,[rsi+rcx]
	call	der_read			; its OID
	jc	.ext_next
	cmp	al,6
	jne	.ext_next
	cmp	ecx,8
	jne	.ext_next
	mov	rax,[rsi]
	cmp	rax,qword [oc_oid_aia]
	jne	.ext_next
	mov	rsi,r8
	call	der_read
	jc	.ext_next
	cmp	al,1
	jne	@f
	mov	rsi,r8
	call	der_read
	jc	.ext_next
@@:
	cmp	al,4
	jne	.ext_next
	lea	rdx,[rsi+rcx]
	call	der_read			; AuthorityInfoAccessSyntax
	jc	.ext_next
	cmp	al,0x30
	jne	.ext_next
	lea	rdx,[rsi+rcx]
.ad:
	cmp	rsi,rdx
	jae	.ext_next
	call	der_read			; AccessDescription
	jc	.ext_next
	cmp	al,0x30
	jne	.ext_next
	push	r8
	push	rdx
	lea	rdx,[rsi+rcx]
	call	der_read			; accessMethod
	jc	.ad_next
	cmp	al,6
	jne	.ad_next
	cmp	ecx,8
	jne	.ad_next
	mov	rax,[rsi]
	cmp	rax,qword [oc_oid_ocsp]
	jne	.ad_next
	mov	rsi,r8
	call	der_read			; accessLocation
	jc	.ad_next
	cmp	al,0x86				; [6] uniformResourceIdentifier
	jne	.ad_next
	cmp	ecx,8
	jb	.ad_next
	cmp	ecx,250
	ja	.ad_next
	mov	rax,'http://'
	shl	rax,8
	mov	rdx,[rsi]
	shl	rdx,8
	cmp	rax,rdx
	jne	.ad_next
	mov	[g_oc_urll],ecx
	lea	rdi,[g_oc_url]
	rep	movsb
	add	rsp,24
	clc
	ret
.ad_next:
	pop	rdx
	pop	rsi
	jmp	.ad
.ext_next:
	pop	rsi
	jmp	.ext
.no:
	stc
	ret

; rbx = an entry: rax = its leaf's tag (the first 8 bytes of its SHA-256), once
ocsp_tag:
	mov	rax,[g_oc_tag+rbx*8]
	test	rax,rax
	jnz	.out
	imul	rax,rbx,TL_SIZE
	lea	r9,[g_tls+rax]
	mov	esi,[r9+TL_CHAIN]
	lea	rsi,[g_tls_store+rsi]
	mov	r8d,[r9+TL_CLEN]
	add	r8,rsi
	call	chain_entry
	jc	.none
	lea	rdi,[g_oc_dig]
	mov	rsi,rax
	mov	edx,ecx
	call	sha256
	mov	rax,qword [g_oc_dig]
	or	rax,1				; (never 0)
	mov	[g_oc_tag+rbx*8],rax
.out:
	ret
.none:
	mov	eax,1
	ret

; ----------------------------------------------------------------- workers

; rdi = the handshake's certificate entry: its answer, if current, copied into
; g_oc_tmp; g_oc_n its length (0: none). Keeps rbx, rbp, r12-r15.
ocsp_staple:
	mov	dword [g_oc_n],0
	mov	rax,[g_ocsp_page]
	test	rax,rax
	jz	.out
	lea	rcx,[g_tls]
	mov	rax,rdi
	sub	rax,rcx
	jb	.out				; (TLS-ALPN-01's: not one of the plan's)
	xor	edx,edx
	mov	ecx,TL_SIZE
	div	rcx
	cmp	eax,[g_plan_tls]
	jae	.out
	push	rbx
	mov	ebx,eax
	call	ocsp_tag
	mov	r9,rax
	imul	r8,rbx,OS_SIZE
	add	r8,[g_ocsp_page]
	pop	rbx
	push	r12
	mov	r12d,3				; tries, while it is being written
.try:
	mov	r10d,[r8+OS_SEQ]
	test	r10d,1
	jnz	.again
	cmp	[r8+OS_TAG],r9
	jne	.none
	mov	ecx,[r8+OS_LEN]
	test	ecx,ecx
	jz	.none
	cmp	ecx,OS_MAX
	ja	.none
	mov	r11,[r8+OS_UNTIL]
	lea	rsi,[r8+OS_DER]
	lea	rdi,[g_oc_tmp]
	push	rcx
	rep	movsb
	pop	rcx
	cmp	r10d,[r8+OS_SEQ]
	jne	.again
	push	rcx
	push	r8
	push	r11
	call	acme_now			; (not past its nextUpdate)
	pop	r11
	pop	r8
	pop	rcx
	cmp	rax,r11
	jae	.none
	mov	[g_oc_n],ecx
	jmp	.none
.again:
	dec	r12d
	jnz	.try
.none:
	pop	r12
.out:
	ret

; ------------------------------------------------------------- the process

; Never returns.
ocsp_main:
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
	lea	rsi,[ocsp_name]
	mov	eax,SYS_prctl
	syscall
	call	helper_close_sockets
	call	cx_buffer
	call	priv_drop
	call	ll_confine_reader
	seccomp_for filter_ocsp
.loop:
	call	acme_now
	lea	r13,[rax+3600]			; the next to look at
	xor	ebx,ebx
.entry:
	cmp	ebx,[g_plan_tls]
	jae	.sleep
	call	acme_now
	cmp	rax,[g_oc_due+rbx*8]
	jb	.later
	call	ocsp_entry
	jc	.never
	call	ocsp_fetch			; eax: 0 good, 1 revoked, 2 failed
	cmp	eax,1
	je	.revoked
	ja	.failed
	mov	qword [g_oc_back+rbx*8],0
	mov	byte [g_oc_said+rbx],0
	; again halfway to its nextUpdate (an hour at least)
	call	acme_now
	mov	rcx,[g_oc_until]
	sub	rcx,rax
	shr	rcx,1
	cmp	rcx,3600
	jae	@f
	mov	ecx,3600
@@:
	add	rax,rcx
	mov	[g_oc_due+rbx*8],rax
	jmp	.later
.revoked:
	call	ocsp_clear
	cmp	byte [g_oc_said+rbx],0
	jne	@f
	mov	byte [g_oc_said+rbx],1
	call	log_begin
	out_lit 'ocsp: the CA says the certificate of '
	call	ocsp_out_name
	out_lit ' is REVOKED: replace it (nothing is stapled)'
	call	log_end
	call	ocsp_tell_acme			; (one of its own: renewed at once)
@@:
	call	acme_now
	add	rax,3600
	mov	[g_oc_due+rbx*8],rax
	jmp	.later
.failed:
	mov	rax,[g_oc_back+rbx*8]
	add	rax,rax
	jnz	@f
	mov	eax,300
@@:
	cmp	rax,3600
	jbe	@f
	mov	eax,3600
@@:
	mov	[g_oc_back+rbx*8],rax
	push	rax
	call	acme_now
	add	rax,[rsp]
	mov	[g_oc_due+rbx*8],rax
	pop	rax
	call	log_begin
	out_lit 'ocsp: no good answer for the certificate of '
	call	ocsp_out_name
	out_lit ' from '
	lea	rsi,[g_oc_url]
	mov	edx,[g_oc_urll]
	call	out_str
	out_lit ': asking again in '
	mov	rax,[g_oc_back+rbx*8]
	call	out_u64
	out_lit ' s'
	call	log_end
	jmp	.later
.never:
	mov	qword [g_oc_due+rbx*8],-1
.later:
	mov	rax,[g_oc_due+rbx*8]
	cmp	rax,r13
	jae	@f
	mov	r13,rax
@@:
	inc	ebx
	jmp	.entry
.sleep:
	call	acme_now
	sub	r13,rax
	jg	@f
	mov	r13d,1
@@:
	cmp	r13,3600
	jbe	@f
	mov	r13d,3600
@@:
	push	0
	push	r13
	mov	rdi,rsp
	xor	esi,esi
	mov	eax,SYS_nanosleep
	syscall
	add	rsp,16
	jmp	.loop

; ebx = an entry: its leaf's first name (or the entry's number), said
ocsp_out_name:
	mov	rsi,[g_oc_leaf]
	mov	edx,[g_oc_leafl]
	call	x509_locate
	test	eax,eax
	jz	.number
	; (the subject, as raw as it is: its last printable run)
	mov	rsi,[g_x509_subjend]
	mov	rcx,[g_x509_subj]
	mov	rdx,rsi
@@:
	cmp	rsi,rcx
	jbe	@f
	cmp	byte [rsi-1],0x20
	jb	@f
	cmp	byte [rsi-1],0x7E
	ja	@f
	dec	rsi
	jmp	@b
@@:
	sub	rdx,rsi
	jz	.number
	jmp	out_str
.number:
	out_lit 'entry '
	mov	eax,ebx
	jmp	out_u64

; ebx = a revoked entry: its tag told to the acme process (a ring in its page),
; and it woken
ocsp_tell_acme:
	mov	r8,[g_acme_page]
	test	r8,r8
	jz	.out
	call	ocsp_tag
	mov	r8,[g_acme_page]
	mov	eax,[r8+AH_REVN]
	xor	edx,edx
	mov	ecx,AH_REVS
	div	ecx				; (the ring's next)
	mov	rax,[g_oc_tag+rbx*8]
	mov	[r8+AH_REV+rdx*8],rax
	inc	dword [r8+AH_REVN]
	lock inc dword [r8+AH_REVSEQ]
	lea	rdi,[r8+AH_REVSEQ]
	mov	esi,FUTEX_WAKE
	mov	edx,0x7FFFFFFF
	mov	eax,SYS_futex
	syscall
.out:
	ret

; ebx = an entry: its slot emptied
ocsp_clear:
	imul	r8,rbx,OS_SIZE
	add	r8,[g_ocsp_page]
	inc	dword [r8+OS_SEQ]
	mov	dword [r8+OS_LEN],0
	inc	dword [r8+OS_SEQ]
	ret

; ebx = an entry (ocsp_entry done): asked, verified, stapled. eax = 0 good (its
; nextUpdate in g_oc_until), 1 revoked, 2 no good answer.
ocsp_fetch:
	push	r12
	push	r13
	push	r14
	push	r15
	; the leaf: its serial and its issuer Name (TLV)
	mov	rsi,[g_oc_leaf]
	mov	edx,[g_oc_leafl]
	lea	rdx,[rsi+rdx]
	call	der_read			; Certificate
	jc	.fail
	lea	rdx,[rsi+rcx]
	call	der_read			; TBSCertificate
	jc	.fail
	lea	rdx,[rsi+rcx]
	call	der_read
	jc	.fail
	cmp	al,0xA0
	jne	@f
	mov	rsi,r8
	call	der_read
	jc	.fail
@@:
	cmp	al,2
	jne	.fail
	cmp	ecx,32
	ja	.fail
	mov	[g_oc_serial],rsi
	mov	[g_oc_seriall],ecx
	mov	rsi,r8
	call	der_read			; signature
	jc	.fail
	mov	rsi,r8
	mov	r12,rsi
	call	der_read			; issuer
	jc	.fail
	mov	[g_oc_issname],r12
	mov	rax,r8
	sub	rax,r12
	mov	[g_oc_issnamel],eax
	lea	rdi,[g_oc_namehash]
	mov	rsi,r12
	mov	edx,eax
	call	sha1
	; the issuer: its key (the BIT STRING's bits) and its key for verifying
	mov	rsi,[g_oc_iss]
	mov	edx,[g_oc_issl]
	call	x509_locate
	test	eax,eax
	jz	.fail
	mov	rsi,[g_x509_subjend]		; subjectPublicKeyInfo follows the subject
	mov	rdx,[g_oc_iss]
	mov	eax,[g_oc_issl]
	add	rdx,rax
	call	der_read
	jc	.fail
	cmp	al,0x30
	jne	.fail
	lea	rdx,[rsi+rcx]
	call	der_read			; AlgorithmIdentifier
	jc	.fail
	mov	rsi,r8
	call	der_read			; subjectPublicKey
	jc	.fail
	cmp	al,3
	jne	.fail
	test	ecx,ecx
	jz	.fail
	inc	rsi
	dec	ecx
	lea	rdi,[g_oc_keyhash]
	mov	edx,ecx
	call	sha1
	mov	rsi,[g_oc_iss]
	mov	edx,[g_oc_issl]
	lea	rdi,[g_oc_issuer]
	call	cert_pubkey
	test	eax,eax
	jz	.fail
	; the request: OCSPRequest { TBSRequest { requestList { Request { CertID } } } }
	lea	rdi,[g_oc_req]
	call	dw_start
	mov	al,0x30
	call	dw_open
	mov	al,0x30
	call	dw_open
	mov	al,0x30
	call	dw_open
	mov	al,0x30
	call	dw_open
	call	ocsp_certid
	call	dw_close
	call	dw_close
	call	dw_close
	call	dw_close
	mov	rax,[g_dw_p]
	lea	rcx,[g_oc_req]
	sub	rax,rcx
	mov	[g_oc_reql],eax
	; POSTed to the responder
	call	ocsp_post			; rsi/ecx = the answer's body. CF: none.
	jc	.fail
	mov	r15,rsi				; (the whole of it is what is stapled)
	mov	r14d,ecx
	; OCSPResponse { ENUMERATED successful, [0] { ResponseBytes { basic, OCTET STRING } } }
	lea	rdx,[rsi+rcx]
	call	der_read
	jc	.fail
	cmp	al,0x30
	jne	.fail
	lea	rdx,[rsi+rcx]
	call	der_read			; responseStatus
	jc	.fail
	cmp	al,0x0A
	jne	.fail
	cmp	ecx,1
	jne	.fail
	cmp	byte [rsi],0
	jne	.fail
	mov	rsi,r8
	call	der_read
	jc	.fail
	cmp	al,0xA0
	jne	.fail
	lea	rdx,[rsi+rcx]
	call	der_read			; ResponseBytes
	jc	.fail
	cmp	al,0x30
	jne	.fail
	lea	rdx,[rsi+rcx]
	call	der_read			; responseType
	jc	.fail
	cmp	al,6
	jne	.fail
	cmp	ecx,9
	jne	.fail
	mov	rax,[rsi]
	cmp	rax,qword [oc_oid_basic]
	jne	.fail
	cmp	byte [rsi+8],1
	jne	.fail
	mov	rsi,r8
	call	der_read			; response OCTET STRING
	jc	.fail
	cmp	al,4
	jne	.fail
	mov	[g_oc_basic],rsi
	mov	[g_oc_basicl],ecx
	; who signed it: the issuer, or a responder it delegated to
	call	ocsp_signed
	jc	.fail
	; its answer for this certificate
	call	ocsp_status			; eax 0 good, 1 revoked, 2 none
	cmp	eax,2
	je	.fail
	cmp	eax,1
	je	.out
	; stapled
	cmp	r14d,OS_MAX
	ja	.fail
	call	ocsp_tag
	imul	r8,rbx,OS_SIZE
	add	r8,[g_ocsp_page]
	inc	dword [r8+OS_SEQ]
	mov	[r8+OS_TAG],rax
	mov	rax,[g_oc_until]
	mov	[r8+OS_UNTIL],rax
	mov	[r8+OS_LEN],r14d
	lea	rdi,[r8+OS_DER]
	mov	rsi,r15
	mov	ecx,r14d
	rep	movsb
	inc	dword [r8+OS_SEQ]
	xor	eax,eax
	jmp	.out
.fail:
	mov	eax,2
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	ret

; CertID { hashAlgorithm SHA-1, issuerNameHash, issuerKeyHash, serialNumber } at g_dw_p
ocsp_certid:
	mov	al,0x30
	call	dw_open
	mov	rdi,[g_dw_p]
	lea	rsi,[oc_sha1_alg]
	mov	ecx,oc_sha1_alg.len
	rep	movsb
	mov	[g_dw_p],rdi
	mov	al,4
	lea	rsi,[g_oc_namehash]
	mov	ecx,20
	call	dw_prim
	mov	al,4
	lea	rsi,[g_oc_keyhash]
	mov	ecx,20
	call	dw_prim
	mov	al,2
	mov	rsi,[g_oc_serial]
	mov	ecx,[g_oc_seriall]
	call	dw_prim
	jmp	dw_close

; g_oc_req: POSTed to g_oc_url (http://HOST[:PORT]/PATH). rsi/ecx = the answer's
; body (200, application/ocsp-response). CF: none.
ocsp_post:
	push	rbx
	; the URL: host, port, path
	lea	rsi,[g_oc_url+7]
	mov	ecx,[g_oc_urll]
	sub	ecx,7
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
	mov	ebx,edx				; the authority's length
	mov	dword [g_oc_port],80
	mov	r8d,edx
	mov	r9d,edx
.colon:
	dec	r9d
	js	.host
	cmp	byte [rsi+r9],']'
	je	.host
	cmp	byte [rsi+r9],':'
	jne	.colon
	push	rsi
	lea	rdi,[rsi+r9+1]
	mov	esi,ebx
	sub	esi,r9d
	dec	esi
	call	parse_decimal
	pop	rsi
	jc	.bad
	test	eax,eax
	jz	.bad
	cmp	eax,65535
	ja	.bad
	mov	[g_oc_port],eax
	mov	r8d,r9d
.host:
	mov	[g_oc_hostl],r8d
	lea	rdi,[g_oc_host]
	mov	ecx,r8d
	push	rsi
	rep	movsb
	pop	rsi
	; the request: POST PATH, Host, the body
	lea	rdi,[g_ac_req]
	memit_x 'POST '
	lea	rsi,[g_oc_url+7+rbx]
	mov	ecx,[g_oc_urll]
	sub	ecx,7
	sub	ecx,ebx
	jnz	@f
	mov	byte [rdi],'/'
	inc	rdi
@@:
	rep	movsb
	memit_x ' HTTP/1.1',13,10,'Host: '
	lea	rsi,[g_oc_url+7]
	mov	ecx,ebx
	rep	movsb
	memit_x 13,10,'User-Agent: okena',13,10,'Content-Type: application/ocsp-request',13,10,'Connection: close',13,10,'Content-Length: '
	mov	eax,[g_oc_reql]
	call	fmt_u64
	memit_x 13,10,13,10
	lea	rsi,[g_oc_req]
	mov	ecx,[g_oc_reql]
	rep	movsb
	mov	rbx,rdi
	lea	rdi,[g_oc_sa]
	lea	rsi,[g_oc_host]
	mov	ecx,[g_oc_hostl]
	mov	edx,[g_oc_port]
	call	cx_address
	jc	.bad
	lea	rsi,[g_oc_sa]
	call	cx_connect
	jc	.bad
	lea	rsi,[g_ac_req]
	mov	rdx,rbx
	sub	rdx,rsi
	call	cx_send
	jc	.closed
	call	cx_answer
	jc	.closed
	call	cx_close
	call	cx_status
	jc	.bad
	cmp	eax,200
	jne	.bad
	test	ecx,ecx
	jz	.bad
	clc
	pop	rbx
	ret
.closed:
	call	cx_close
.bad:
	stc
	pop	rbx
	ret

; g_oc_basic/basicl = BasicOCSPResponse { tbsResponseData, signatureAlgorithm,
; signature, [0] certs }: signed by the issuer (g_oc_issuer), or by one of its
; certs that the issuer signed for OCSPSigning. CF: neither.
ocsp_signed:
	push	rbx
	; the BasicOCSPResponse, from its tag
	call	ocsp_basic_tlv			; rsi/edx
	lea	rdi,[g_oc_issuer]
	call	cert_verify			; (the same shape as a certificate)
	test	eax,eax
	jnz	.ok
	; the certs it carries: one the issuer signed, for OCSPSigning, that signed it
	mov	rsi,[g_oc_basic]
	mov	edx,[g_oc_basicl]
	lea	rdx,[rsi+rdx]
	call	der_read			; BasicOCSPResponse
	jc	.bad
	lea	rdx,[rsi+rcx]
	call	der_read			; tbsResponseData
	jc	.bad
	mov	rsi,r8
	call	der_read			; signatureAlgorithm
	jc	.bad
	mov	rsi,r8
	call	der_read			; signature
	jc	.bad
	mov	rsi,r8
	call	der_read			; [0] certs
	jc	.bad
	cmp	al,0xA0
	jne	.bad
	lea	rdx,[rsi+rcx]
	call	der_read			; SEQUENCE OF Certificate
	jc	.bad
	cmp	al,0x30
	jne	.bad
	lea	rdx,[rsi+rcx]
.cert:
	cmp	rsi,rdx
	jae	.bad
	mov	rbx,rsi				; this one, from its tag
	push	rdx
	call	der_read
	pop	rdx
	jc	.bad
	push	r8
	push	rdx
	mov	rsi,rbx
	mov	rdx,r8
	sub	rdx,rbx				; (its whole length)
	push	rdx
	lea	rdi,[g_oc_issuer]
	call	cert_verify			; the issuer's
	pop	rdx
	test	eax,eax
	jz	.next
	mov	rsi,rbx				; for OCSPSigning
	mov	ecx,edx
	push	rdx
	lea	rdi,[oc_eku_sign]
	mov	edx,10
	call	find_sub
	pop	rdx
	test	rax,rax
	jz	.next
	mov	rsi,rbx
	lea	rdi,[g_oc_resp]
	call	cert_pubkey
	test	eax,eax
	jz	.next
	call	ocsp_basic_tlv
	lea	rdi,[g_oc_resp]
	call	cert_verify
	test	eax,eax
	jz	.next
	add	rsp,16
.ok:
	clc
	pop	rbx
	ret
.next:
	pop	rdx
	pop	rsi
	jmp	.cert
.bad:
	stc
	pop	rbx
	ret

; rsi/edx = the BasicOCSPResponse's whole DER (the OCTET STRING's content)
ocsp_basic_tlv:
	mov	rsi,[g_oc_basic]
	mov	edx,[g_oc_basicl]
	ret

; rax = the response's SingleResponse for this certificate (by serial and
; issuerKeyHash): eax = 0 good (g_oc_until its nextUpdate, current), 1
; revoked, 2 none, or not current
ocsp_status:
	push	rbx
	push	r12
	mov	rsi,[g_oc_basic]
	mov	edx,[g_oc_basicl]
	lea	rdx,[rsi+rdx]
	call	der_read			; BasicOCSPResponse
	jc	.none
	lea	rdx,[rsi+rcx]
	call	der_read			; tbsResponseData
	jc	.none
	cmp	al,0x30
	jne	.none
	lea	rdx,[rsi+rcx]
	call	der_read
	jc	.none
	cmp	al,0xA0				; [0] version
	jne	@f
	mov	rsi,r8
	call	der_read
	jc	.none
@@:
	mov	rsi,r8				; (past responderID)
	call	der_read			; producedAt
	jc	.none
	mov	rsi,r8
	call	der_read			; responses
	jc	.none
	cmp	al,0x30
	jne	.none
	lea	rdx,[rsi+rcx]
.single:
	cmp	rsi,rdx
	jae	.none
	call	der_read			; SingleResponse
	jc	.none
	cmp	al,0x30
	jne	.none
	push	r8
	push	rdx
	lea	rdx,[rsi+rcx]
	call	der_read			; CertID
	jc	.next
	cmp	al,0x30
	jne	.next
	push	r8
	lea	rdx,[rsi+rcx]
	call	der_read			; hashAlgorithm
	jc	.next_pop
	mov	rsi,r8
	call	der_read			; issuerNameHash
	jc	.next_pop
	mov	rsi,r8
	call	der_read			; issuerKeyHash
	jc	.next_pop
	cmp	ecx,20
	jne	.next_pop
	push	rsi
	push	rcx
	lea	rdi,[g_oc_keyhash]
	repe	cmpsb
	pop	rcx
	pop	rsi
	jne	.next_pop
	mov	rsi,r8
	call	der_read			; serialNumber
	jc	.next_pop
	cmp	al,2
	jne	.next_pop
	cmp	ecx,[g_oc_seriall]
	jne	.next_pop
	mov	rdi,[g_oc_serial]
	repe	cmpsb
	jne	.next_pop
	; it: its status, thisUpdate, nextUpdate
	pop	rsi				; (past the CertID)
	mov	rdx,[rsp+8]			; (the SingleResponse's end)
	call	der_read			; certStatus
	jc	.next
	cmp	al,0x80				; good
	je	.good
	cmp	al,0xA1				; revoked
	jne	.next				; (unknown)
	add	rsp,16
	mov	eax,1
	jmp	.out
.good:
	mov	rsi,r8
	call	der_read			; thisUpdate
	jc	.next
	cmp	al,0x18
	jne	.next
	mov	r12,r8
	lea	rdi,[g_oc_t14]
	call	x509_time_norm
	jc	.next
	lea	rsi,[g_oc_t14]
	call	acme_epoch
	mov	rbx,rax
	call	acme_now
	add	rax,300				; (5 minutes of clock skew)
	cmp	rbx,rax
	ja	.next				; not yet
	mov	rax,rbx
	add	rax,86400			; (no nextUpdate: a day)
	mov	[g_oc_until],rax
	mov	rsi,r12
	cmp	rsi,[rsp+8]
	jae	.current
	call	der_read
	jc	.current
	cmp	al,0xA0				; [0] nextUpdate
	jne	.current
	lea	rdx,[rsi+rcx]
	call	der_read
	jc	.next
	cmp	al,0x18
	jne	.next
	lea	rdi,[g_oc_t14]
	call	x509_time_norm
	jc	.next
	lea	rsi,[g_oc_t14]
	call	acme_epoch
	mov	[g_oc_until],rax
.current:
	call	acme_now
	cmp	rax,[g_oc_until]
	jae	.next				; past it
	add	rsp,16
	xor	eax,eax
	jmp	.out
.next_pop:
	add	rsp,8
.next:
	pop	rdx
	pop	rsi
	jmp	.single
.none:
	mov	eax,2
.out:
	pop	r12
	pop	rbx
	ret
