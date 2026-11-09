; Writing keys and certificates: what ACME needs (a key, a CSR) and what serves a
; name until it has a certificate of its own (a self-signed one), and a local CA's.
; ECDSA P-256 only. DER as it must be (lengths in their shortest form): an element
; is opened with room for a 2-byte length and closed when its content is known,
; moved back by what the length did not need.

DW_DEPTH	:= 16

bss
	align 8
	g_dw_p		dq ?			; where the next byte goes
	g_dw_sp		dd ?
	align 8
	g_dw_stack	rq DW_DEPTH
	g_x5_d:		rb 32			; a private key (big endian)
	g_x5_pub:	rb 65			; 04 | X | Y
	align 8
	g_x5_limbs	rq 4
	g_x5_hash:	rb 32
	g_x5_sig:	rb 64
	g_x5_sigder:	rb 80
	g_x5_der:	rb 8192			; what is being built
	g_x5_der2:	rb 8192			; and what it is put in
	g_x5_time:	rb 16
	g_x5_pem:	rb 16384
	g_x5_csrflag	dd ?			; okena cert csr
end bss

SYS_mkdirat_	:= 258

rodata
	x5w_ecpub	db 0x06,7, 0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01
	x5w_p256	db 0x06,8, 0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07
	x5w_ecdsa256	db 0x06,8, 0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x02
	x5w_cn		db 0x06,3, 0x55,0x04,0x03
	x5w_extreq	db 0x06,9, 0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x0E
	x5w_san		db 0x06,3, 0x55,0x1D,0x11
	x5w_bc		db 0x06,3, 0x55,0x1D,0x13
	x5w_ku		db 0x06,3, 0x55,0x1D,0x0F
	x5w_eku		db 0x06,3, 0x55,0x1D,0x25
	x5w_serverauth	db 0x06,8, 0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x01
	pem_l_ec	db 'EC PRIVATE KEY',0
	pem_l_cert	db 'CERTIFICATE',0
	pem_l_csr	db 'CERTIFICATE REQUEST',0
end rodata

; rdi = where the DER goes
dw_start:
	mov	[g_dw_p],rdi
	mov	dword [g_dw_sp],0
	ret

; al = a constructed tag: opened
dw_open:
	mov	rdi,[g_dw_p]
	mov	[rdi],al
	mov	ecx,[g_dw_sp]
	mov	[g_dw_stack+rcx*8],rdi
	inc	dword [g_dw_sp]
	add	rdi,4				; (tag, 0x82, two length bytes)
	mov	[g_dw_p],rdi
	ret

; the last one opened: closed, its length in its shortest form
dw_close:
	dec	dword [g_dw_sp]
	mov	ecx,[g_dw_sp]
	mov	r8,[g_dw_stack+rcx*8]		; its tag
	mov	rcx,[g_dw_p]
	lea	rsi,[r8+4]
	sub	rcx,rsi				; its content's length
	cmp	ecx,128
	jb	.one
	cmp	ecx,256
	jb	.two
	mov	byte [r8+1],0x82
	mov	eax,ecx
	xchg	al,ah
	mov	[r8+2],ax
	ret
.one:
	mov	[r8+1],cl
	lea	rdi,[r8+2]
	sub	qword [g_dw_p],2
	rep	movsb
	ret
.two:
	mov	byte [r8+1],0x81
	mov	[r8+2],cl
	lea	rdi,[r8+3]
	dec	qword [g_dw_p]
	rep	movsb
	ret

; al = a tag, rsi/ecx = its content: written
dw_prim:
	mov	rdi,[g_dw_p]
	stosb
	cmp	ecx,128
	jb	.one
	cmp	ecx,256
	jb	.two
	mov	byte [rdi],0x82
	mov	[rdi+1],ch
	mov	[rdi+2],cl
	add	rdi,3
	jmp	.data
.two:
	mov	byte [rdi],0x81
	mov	[rdi+1],cl
	add	rdi,2
	jmp	.data
.one:
	mov	[rdi],cl
	inc	rdi
.data:
	rep	movsb
	mov	[g_dw_p],rdi
	ret

; rsi = bytes that are DER already (an OID as above: tag, length, value): copied
dw_raw_oid:
	movzx	ecx,byte [rsi+1]
	add	ecx,2
	mov	rdi,[g_dw_p]
	rep	movsb
	mov	[g_dw_p],rdi
	ret

; rsi/ecx = a big-endian unsigned number: an INTEGER
dw_uint:
	; no leading zeros, one 0 when the top bit is set
@@:
	cmp	ecx,1
	jbe	@f
	cmp	byte [rsi],0
	jne	@f
	inc	rsi
	dec	ecx
	jmp	@b
@@:
	mov	rdi,[g_dw_p]
	mov	byte [rdi],2
	xor	eax,eax
	test	byte [rsi],0x80
	jz	@f
	inc	eax
@@:
	lea	edx,[rcx+rax]
	mov	[rdi+1],dl			; (numbers here are short)
	add	rdi,2
	test	eax,eax
	jz	@f
	mov	byte [rdi],0
	inc	rdi
@@:
	rep	movsb
	mov	[g_dw_p],rdi
	ret

; ----------------------------------------------------------------- pieces

; a new key: g_x5_d, g_x5_pub. CF: no randomness.
x5_keygen:
.again:
	lea	rdi,[g_x5_d]
	mov	esi,32
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	cmp	eax,32
	jne	.bad
	lea	rdi,[g_x5_limbs]
	lea	rsi,[g_x5_d]
	call	be_to_limbs
	lea	rdi,[g_x5_limbs]
	call	scalar_in_range
	test	eax,eax
	jz	.again
	lea	rdi,[g_x5_pub]
	lea	rsi,[g_x5_d]
	call	p256_public
	clc
	ret
.bad:
	stc
	ret

; SubjectPublicKeyInfo of g_x5_pub
x5_spki:
	mov	al,0x30
	call	dw_open
	mov	al,0x30
	call	dw_open
	lea	rsi,[x5w_ecpub]
	call	dw_raw_oid
	lea	rsi,[x5w_p256]
	call	dw_raw_oid
	call	dw_close
	; BIT STRING: no unused bits, the point
	mov	rdi,[g_dw_p]
	mov	dword [rdi],0x00004203		; 03 42 00
	add	rdi,3
	lea	rsi,[g_x5_pub]
	mov	ecx,65
	rep	movsb
	mov	[g_dw_p],rdi
	jmp	dw_close

; rsi/ecx = a name: Name, CN=it
x5_name:
	push	rsi
	push	rcx
	mov	al,0x30
	call	dw_open
	mov	al,0x31
	call	dw_open
	mov	al,0x30
	call	dw_open
	lea	rsi,[x5w_cn]
	call	dw_raw_oid
	pop	rcx
	pop	rsi
	cmp	ecx,64
	jbe	@f
	mov	ecx,64				; (a CN of 64 at most; the names are in the SAN)
@@:
	mov	al,0x0C				; UTF8String
	call	dw_prim
	call	dw_close
	call	dw_close
	jmp	dw_close

; rsi = names, NUL between them, an empty one at the end: GeneralNames of dNSName
x5_san_value:
	push	rbx
	mov	rbx,rsi
	mov	al,0x30
	call	dw_open
.name:
	cmp	byte [rbx],0
	je	.done
	mov	rsi,rbx
	xor	ecx,ecx
@@:
	cmp	byte [rbx+rcx],0
	je	@f
	inc	ecx
	jmp	@b
@@:
	lea	rbx,[rbx+rcx+1]
	mov	al,0x82				; [2] dNSName
	call	dw_prim
	jmp	.name
.done:
	pop	rbx
	jmp	dw_close

; rsi = names (as above): Extension subjectAltName
x5_ext_san:
	push	rsi
	mov	al,0x30
	call	dw_open
	lea	rsi,[x5w_san]
	call	dw_raw_oid
	mov	al,0x04				; OCTET STRING { GeneralNames }
	call	dw_open
	pop	rsi
	call	x5_san_value
	call	dw_close
	jmp	dw_close

; rsi/ecx = bytes signed: the signature, DER (g_x5_sigder), eax its length. CF:
; it could not be made.
x5_sign:
	mov	edx,ecx
	lea	rdi,[g_x5_hash]
	call	sha256
	lea	rdi,[g_x5_sig]
	lea	rsi,[g_x5_d]
	lea	rdx,[g_x5_hash]
	call	p256_sign
	test	eax,eax
	jz	.bad
	lea	rdi,[g_x5_sigder]
	lea	rsi,[g_x5_sig]
	call	ecdsa_der
	clc
	ret
.bad:
	stc
	ret

; the signature algorithm and the signature (eax its DER's length), after what
; was signed
x5_sig_tail:
	push	rax
	mov	al,0x30
	call	dw_open
	lea	rsi,[x5w_ecdsa256]
	call	dw_raw_oid
	call	dw_close
	pop	rcx
	mov	rdi,[g_dw_p]
	mov	byte [rdi],0x03			; BIT STRING
	lea	eax,[rcx+1]
	mov	[rdi+1],al
	mov	byte [rdi+2],0
	add	rdi,3
	lea	rsi,[g_x5_sigder]
	rep	movsb
	mov	[g_dw_p],rdi
	ret

; ----------------------------------------------------------------- CSR

; rsi = names (as above), g_x5_d/pub the key: a CSR in g_x5_der2, eax its length.
; CF: not signed.
x5_csr:
	push	rbx
	mov	rbx,rsi
	; CertificationRequestInfo, in g_x5_der
	lea	rdi,[g_x5_der]
	call	dw_start
	mov	al,0x30
	call	dw_open
	mov	rdi,[g_dw_p]
	mov	dword [rdi],0x000102		; INTEGER 0
	add	qword [g_dw_p],3
	mov	rsi,rbx
	call	.first
	call	x5_name
	call	x5_spki
	mov	al,0xA0				; attributes
	call	dw_open
	mov	al,0x30
	call	dw_open
	lea	rsi,[x5w_extreq]
	call	dw_raw_oid
	mov	al,0x31
	call	dw_open
	mov	al,0x30				; Extensions
	call	dw_open
	mov	rsi,rbx
	call	x5_ext_san
	call	dw_close
	call	dw_close
	call	dw_close
	call	dw_close
	call	dw_close
	lea	rsi,[g_x5_der]
	mov	rcx,[g_dw_p]
	sub	rcx,rsi
	push	rcx
	call	x5_sign
	pop	rcx
	jc	.bad
	; CertificationRequest: the info, the algorithm, the signature
	push	rax
	push	rcx
	lea	rdi,[g_x5_der2]
	call	dw_start
	mov	al,0x30
	call	dw_open
	pop	rcx
	lea	rsi,[g_x5_der]
	mov	rdi,[g_dw_p]
	rep	movsb
	mov	[g_dw_p],rdi
	pop	rax
	call	x5_sig_tail
	call	dw_close
	mov	rax,[g_dw_p]
	lea	rcx,[g_x5_der2]
	sub	rax,rcx
	clc
	pop	rbx
	ret
.bad:
	pop	rbx
	stc
	ret
; rsi = names: rsi/ecx = the first
.first:
	xor	ecx,ecx
@@:
	cmp	byte [rsi+rcx],0
	je	@f
	inc	ecx
	jmp	@b
@@:
	ret

; ---------------------------------------------------- self-signed certificate

; rax = seconds since the epoch: g_x5_time = YYMMDDHHMMSSZ (UTCTime, to 2049)
x5_utctime:
	push	rbx
	lea	rbx,[g_x5_time]
	xor	edx,edx
	mov	ecx,86400
	div	rcx
	push	rdx				; seconds of the day
	; civil from days (H. Hinnant)
	add	rax,719468
	xor	edx,edx
	mov	ecx,146097
	div	rcx
	mov	r8,rax				; era
	mov	r9,rdx				; day of era
	mov	rax,r9
	xor	edx,edx
	mov	ecx,1460
	div	rcx
	mov	r10,r9
	sub	r10,rax
	mov	rax,r9
	xor	edx,edx
	mov	ecx,36524
	div	rcx
	add	r10,rax
	mov	rax,r9
	xor	edx,edx
	mov	ecx,146096
	div	rcx
	sub	r10,rax
	mov	rax,r10
	xor	edx,edx
	mov	ecx,365
	div	rcx
	mov	r10,rax				; year of era
	imul	r11,r8,400
	add	r11,rax				; y
	imul	rcx,r10,365
	mov	rax,r10
	shr	rax,2
	add	rcx,rax
	mov	rax,r10
	push	rcx
	xor	edx,edx
	mov	ecx,100
	div	rcx
	pop	rcx
	sub	rcx,rax
	mov	rax,r9
	sub	rax,rcx				; day of the year, from March
	mov	r9,rax
	imul	rax,rax,5
	add	rax,2
	xor	edx,edx
	mov	ecx,153
	div	rcx
	mov	r10,rax				; month, from March
	imul	rax,rax,153
	add	rax,2
	xor	edx,edx
	mov	ecx,5
	div	rcx
	mov	rcx,r9
	sub	rcx,rax
	inc	rcx				; day
	lea	rax,[r10+3]
	cmp	rax,12
	jbe	@f
	sub	rax,12
@@:
	cmp	rax,2
	ja	@f
	inc	r11
@@:
	mov	r10,rax				; month
	mov	rax,r11
	xor	edx,edx
	push	rcx
	mov	ecx,100
	div	rcx
	pop	rcx
	mov	rax,rdx
	call	.two				; YY
	mov	rax,r10
	call	.two				; MM
	mov	rax,rcx
	call	.two				; DD
	pop	rax				; seconds of the day
	xor	edx,edx
	mov	ecx,3600
	div	rcx
	push	rdx
	call	.two				; HH
	pop	rax
	xor	edx,edx
	mov	ecx,60
	div	rcx
	push	rdx
	call	.two				; MM
	pop	rax
	call	.two				; SS
	mov	byte [rbx],'Z'
	pop	rbx
	ret
.two:
	push	rcx
	push	rdx
	xor	edx,edx
	mov	ecx,10
	div	rcx
	add	al,'0'
	add	dl,'0'
	mov	[rbx],al
	mov	[rbx+1],dl
	add	rbx,2
	pop	rdx
	pop	rcx
	ret

; rsi = names (as above), edx = days it is good for, g_x5_d/pub its key: a
; self-signed certificate for them in g_x5_der2, eax its length. CF: not signed.
x5_selfsigned:
	push	rbx
	push	r12
	mov	rbx,rsi
	mov	r12d,edx
	lea	rdi,[g_x5_der]
	call	dw_start
	mov	al,0x30				; TBSCertificate
	call	dw_open
	mov	rdi,[g_dw_p]
	mov	dword [rdi],0x010203A0		; [0] { INTEGER 2 }: v3
	mov	byte [rdi+4],2
	add	qword [g_dw_p],5
	; a serial: 16 random bytes, positive
	sub	rsp,16
	mov	rdi,rsp
	mov	esi,16
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	and	byte [rsp],0x7F
	or	byte [rsp],0x01
	mov	rsi,rsp
	mov	ecx,16
	call	dw_uint
	add	rsp,16
	mov	al,0x30
	call	dw_open
	lea	rsi,[x5w_ecdsa256]
	call	dw_raw_oid
	call	dw_close
	mov	rsi,rbx
	call	x5_csr.first
	push	rsi
	push	rcx
	call	x5_name				; issuer: itself
	; validity: an hour ago, for the days asked
	mov	al,0x30
	call	dw_open
	sub	rsp,24
	mov	edi,CLOCK_REALTIME
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	mov	rax,[rsp]
	add	rsp,24
	push	rax
	sub	rax,3600
	call	x5_utctime
	lea	rsi,[g_x5_time]
	mov	ecx,13
	mov	al,0x17				; UTCTime
	call	dw_prim
	pop	rax
	mov	ecx,r12d
	imul	rcx,rcx,86400
	add	rax,rcx
	call	x5_utctime
	lea	rsi,[g_x5_time]
	mov	ecx,13
	mov	al,0x17
	call	dw_prim
	call	dw_close
	pop	rcx
	pop	rsi
	call	x5_name				; subject
	call	x5_spki
	mov	al,0xA3				; [3] { Extensions }
	call	dw_open
	mov	al,0x30
	call	dw_open
	mov	rsi,rbx
	call	x5_ext_san
	; basicConstraints, critical: not a CA
	mov	rdi,[g_dw_p]
	lea	rsi,[.bc]
	mov	ecx,.bc_len
	rep	movsb
	; keyUsage, critical: digitalSignature; extKeyUsage: serverAuth
	lea	rsi,[.ku]
	mov	ecx,.ku_len
	rep	movsb
	mov	[g_dw_p],rdi
	mov	al,0x30
	call	dw_open
	lea	rsi,[x5w_eku]
	call	dw_raw_oid
	mov	al,0x04
	call	dw_open
	mov	al,0x30
	call	dw_open
	lea	rsi,[x5w_serverauth]
	call	dw_raw_oid
	call	dw_close
	call	dw_close
	call	dw_close
	call	dw_close
	call	dw_close
	call	dw_close			; (the TBSCertificate)
	lea	rsi,[g_x5_der]
	mov	rcx,[g_dw_p]
	sub	rcx,rsi
	push	rcx
	call	x5_sign
	pop	rcx
	jc	.bad
	push	rax
	push	rcx
	lea	rdi,[g_x5_der2]
	call	dw_start
	mov	al,0x30
	call	dw_open
	pop	rcx
	lea	rsi,[g_x5_der]
	mov	rdi,[g_dw_p]
	rep	movsb
	mov	[g_dw_p],rdi
	pop	rax
	call	x5_sig_tail
	call	dw_close
	mov	rax,[g_dw_p]
	lea	rcx,[g_x5_der2]
	sub	rax,rcx
	clc
	jmp	.out
.bad:
	stc
.out:
	pop	r12
	pop	rbx
	ret
.bc	db 0x30,0x0C, 0x06,0x03,0x55,0x1D,0x13, 0x01,0x01,0xFF, 0x04,0x02,0x30,0x00
.bc_len = $ - .bc
.ku	db 0x30,0x0E, 0x06,0x03,0x55,0x1D,0x0F, 0x01,0x01,0xFF, 0x04,0x04,0x03,0x02,0x07,0x80
.ku_len = $ - .ku

; ----------------------------------------------------------------- PEM

; the key g_x5_d/pub as SEC1 DER (ECPrivateKey) in g_x5_der, eax its length
x5_sec1:
	lea	rdi,[g_x5_der]
	call	dw_start
	mov	al,0x30
	call	dw_open
	mov	rdi,[g_dw_p]
	mov	dword [rdi],0x00010102		; INTEGER 1
	add	qword [g_dw_p],3
	lea	rsi,[g_x5_d]
	mov	ecx,32
	mov	al,0x04
	call	dw_prim
	mov	al,0xA0
	call	dw_open
	lea	rsi,[x5w_p256]
	call	dw_raw_oid
	call	dw_close
	mov	al,0xA1
	call	dw_open
	mov	rdi,[g_dw_p]
	mov	dword [rdi],0x00004203
	add	rdi,3
	lea	rsi,[g_x5_pub]
	mov	ecx,65
	rep	movsb
	mov	[g_dw_p],rdi
	call	dw_close
	call	dw_close
	mov	rax,[g_dw_p]
	lea	rcx,[g_x5_der]
	sub	rax,rcx
	ret

; rdi = out, rsi/ecx = DER, rdx = the label (NUL-ended): PEM, rdi past it
x5_pem:
	push	rbx
	push	r12
	push	r13
	mov	rbx,rsi
	mov	r12d,ecx
	mov	r13,rdx
	mov	rax,'-----BEG'
	stosq
	mov	dword [rdi],'IN '
	add	rdi,3
	call	.label
	mov	rax,'-----'
	mov	[rdi],rax
	mov	byte [rdi+5],10
	add	rdi,6
.line:
	test	r12d,r12d
	jz	.end
	mov	edx,48
	cmp	edx,r12d
	jbe	@f
	mov	edx,r12d
@@:
	sub	r12d,edx
	mov	rsi,rbx
	add	rbx,rdx
	call	base64_encode			; (rdi moves past them)
	mov	byte [rdi],10
	inc	rdi
	jmp	.line
.end:
	mov	rax,'-----END'
	stosq
	mov	byte [rdi],' '
	inc	rdi
	call	.label
	mov	rax,'-----'
	mov	[rdi],rax
	mov	byte [rdi+5],10
	add	rdi,6
	pop	r13
	pop	r12
	pop	rbx
	ret
.label:
	mov	rsi,r13
@@:
	lodsb
	test	al,al
	jz	@f
	stosb
	jmp	@b
@@:
	ret

; ------------------------------------------------------------------ CLI

; `okena cert selfsigned DIR NAME... [days=N]`: DIR/key.pem and DIR/cert.pem, a
; key and a certificate for the names that signs itself (90 days unless said)
cli_cert:
	cmp	qword [g_argc],5
	jb	.usage
	mov	rax,[g_argv]
	mov	rdi,[rax+16]
	mov	dword [g_x5_csrflag],0
	cstring .w_self, 'selfsigned',0
	lea	rsi,[.w_self]
	push	rdi
	call	cstr_eq
	pop	rdi
	test	eax,eax
	jnz	@f
	cstring .w_csr, 'csr',0
	lea	rsi,[.w_csr]
	call	cstr_eq
	test	eax,eax
	jz	.usage
	mov	dword [g_x5_csrflag],1
@@:
	; the names, NUL between them; days=
	mov	r12d,90
	lea	rdi,[g_x5_der2]			; (a place for them, until the DER needs it)
	mov	r13d,4
.arg:
	cmp	r13,[g_argc]
	jae	.args
	mov	rax,[g_argv]
	mov	rsi,[rax+r13*8]
	inc	r13d
	cmp	dword [rsi],'days'
	jne	.name
	cmp	byte [rsi+4],'='
	jne	.name
	push	rdi
	lea	rdi,[rsi+5]
	xor	esi,esi
@@:
	cmp	byte [rdi+rsi],0
	je	@f
	inc	esi
	jmp	@b
@@:
	call	parse_decimal
	pop	rdi
	jc	.usage
	test	eax,eax
	jz	.usage
	cmp	eax,3650
	ja	.usage
	mov	r12d,eax
	jmp	.arg
.name:
	lodsb
	stosb
	test	al,al
	jnz	.name
	jmp	.arg
.args:
	mov	byte [rdi],0
	lea	rsi,[g_x5_der2]
	cmp	byte [rsi],0
	je	.usage
	lea	rdi,[g_sg_msg]			; (copied: x5_selfsigned builds in g_x5_der2)
	mov	ecx,2048
	rep	movsb
	call	x5_keygen
	jc	.failed
	lea	rsi,[g_sg_msg]
	cmp	dword [g_x5_csrflag],0
	jne	.make_csr
	mov	edx,r12d
	call	x5_selfsigned
	jc	.failed
	jmp	.made
.make_csr:
	call	x5_csr
	jc	.failed
.made:
	; the certificate, then the key
	mov	rax,[g_argv]
	mov	rsi,[rax+24]			; DIR
	mov	edi,AT_FDCWD
	mov	edx,0x1C0			; 0700
	mov	eax,SYS_mkdirat_
	syscall
	lea	rbx,[g_x5_pem]			; (a place for the PEM)
	mov	rax,[g_dw_p]
	lea	rcx,[g_x5_der2]
	sub	rax,rcx
	mov	ecx,eax
	lea	rsi,[g_x5_der2]
	lea	rdx,[pem_l_cert]
	lea	r8,[.f_cert]
	cmp	dword [g_x5_csrflag],0
	je	@f
	lea	rdx,[pem_l_csr]
	lea	r8,[.f_csr]
@@:
	push	r8
	mov	rdi,rbx
	call	x5_pem
	mov	rdx,rdi
	sub	rdx,rbx
	pop	r8
	call	.file
	jc	.failed
	call	x5_sec1
	mov	ecx,eax
	lea	rsi,[g_x5_der]
	lea	rdx,[pem_l_ec]
	mov	rdi,rbx
	call	x5_pem
	mov	rdx,rdi
	sub	rdx,rbx
	lea	r8,[.f_key]
	call	.file
	jc	.failed
	xor	edi,edi
	jmp	exit_process
; rbx/rdx = what, r8 = the file's name in DIR: written (0600)
.file:
	push	rdx
	mov	rax,[g_argv]
	mov	rsi,[rax+24]
	lea	rdi,[g_sg_msg]
@@:
	lodsb
	test	al,al
	jz	@f
	stosb
	jmp	@b
@@:
	mov	byte [rdi],'/'
	inc	rdi
	mov	rsi,r8
@@:
	lodsb
	stosb
	test	al,al
	jnz	@b
	mov	edi,AT_FDCWD
	lea	rsi,[g_sg_msg]
	mov	edx,O_WRONLY or O_CREAT or O_TRUNC or O_CLOEXEC
	mov	r10d,0x180			; 0600
	mov	eax,SYS_openat
	syscall
	pop	rdx
	test	eax,eax
	js	.file_bad
	push	rax
	mov	edi,eax
	mov	rsi,rbx
	call	write_all
	pop	rdi
	mov	eax,SYS_close
	syscall
	clc
	ret
.file_bad:
	stc
	ret
.f_cert	db 'cert.pem',0
.f_csr	db 'csr.pem',0
.f_key	db 'key.pem',0
.failed:
	call	log_begin
	out_lit 'okena cert: the key or the certificate could not be made or written'
	call	log_end
	mov	edi,1
	jmp	exit_process
.usage:
	call	log_begin
	out_lit 'okena cert selfsigned DIR NAME... [days=N]: DIR/key.pem and DIR/cert.pem, a certificate for the names that signs itself (ECDSA P-256, 90 days unless said); okena cert csr DIR NAME...: DIR/key.pem and DIR/csr.pem'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
