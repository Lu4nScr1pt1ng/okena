; X.509 (DER): the generic parser, the OIDs okena knows, and the ECDSA
; P-256 certificate-signature check (used by certificate loading in
; src/tls/certs.inc and, later, by TLS towards upstreams). No dependency
; on the configuration layer, so a test harness can include this alone.

rodata
	oid_ec_public_key	db 0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01		; 1.2.840.10045.2.1
	oid_prime256v1		db 0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07	; 1.2.840.10045.3.1.7
	oid_rsa_encryption	db 0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01	; 1.2.840.113549.1.1.1
	oid_ecdsa_sha256	db 0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x02	; 1.2.840.10045.4.3.2
	oid_san			db 0x55,0x1D,0x11				; 2.5.29.17 subjectAltName
	oid_cn			db 0x55,0x04,0x03				; 2.5.4.3 commonName
end rodata

; rsi = element, rdx = end of the enclosing content. al = tag, rsi = its
; content, ecx = content length, r8 = the next element. CF when it does
; not fit or the length is not a definite one of at most 3 bytes.
der_read:
	lea	rax,[rsi+2]
	cmp	rax,rdx
	ja	.bad
	movzx	eax,byte [rsi]
	movzx	ecx,byte [rsi+1]
	add	rsi,2
	test	cl,0x80
	jz	.content
	and	ecx,0x7F
	jz	.bad				; indefinite: not DER
	cmp	ecx,3
	ja	.bad
	lea	r8,[rsi+rcx]
	cmp	r8,rdx
	ja	.bad
	mov	r9d,ecx
	xor	ecx,ecx
@@:
	shl	ecx,8
	mov	cl,[rsi]
	inc	rsi
	dec	r9d
	jnz	@b
.content:
	lea	r8,[rsi+rcx]
	cmp	r8,rdx
	ja	.bad
	clc
	ret
.bad:
	stc
	ret

; rsi/ecx = an OID's content, rdi/edx = the expected bytes: ZF when equal.
der_oid_is:
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

; rsi = a DER INTEGER's content, ecx = its length, rdi = out[32]: the
; integer right-aligned big-endian in 32 bytes (a leading sign zero
; dropped, shorter values left-padded). CF when it does not fit in 32.
der_int_32:
	push	rdi
	xor	eax,eax				; zero the 32 bytes
	mov	r9,rdi
	mov	r10d,ecx
	repeat 4, i:0
		mov	qword [r9+i*8],0
	end repeat
	mov	ecx,r10d
	cmp	ecx,0
	je	.ok				; zero-length integer: leaves 0
	cmp	byte [rsi],0			; a leading 0x00 sign byte
	jne	@f
	inc	rsi
	dec	ecx
@@:
	cmp	ecx,32
	ja	.bad
	pop	rdi
	lea	rdi,[rdi+32]
	sub	rdi,rcx				; right-aligned
	rep	movsb
	clc
	ret
.ok:
	pop	rdi
	clc
	ret
.bad:
	pop	rdi
	stc
	ret

bss
	align 8
	g_x509_tbs	dq ?			; the TBSCertificate's bytes
	g_x509_tbslen	dd ?
	g_x509_dig	rb 32			; its SHA-256
	g_x509_r	rb 32
	g_x509_s	rb 32
	g_x509_val	dq ?			; validity: content start / end
	g_x509_valend	dq ?
	g_x509_subj	dq ?			; subject Name: content start / end
	g_x509_subjend	dq ?
	g_x509_ext	dq ?			; extensions SEQUENCE: content / end (0 if none)
	g_x509_extend	dq ?
	g_time_a	rb 14			; normalised YYYYMMDDHHMMSS scratch
	g_time_b	rb 14
	g_x509_issuer	rb 65			; an issuer key pulled from the chain
end bss

; rsi = certificate DER, edx = its length, rdi = the issuer's public key
; (04|X|Y, 65 bytes): eax = 1 when the certificate's ECDSA P-256 / SHA-256
; signature verifies under that key, else 0 (also for RSA or any shape
; okena does not check). Hashes the TBSCertificate, decodes the signature
; and calls p256_verify.
cert_verify:
	push	rbx
	push	r12
	push	r13
	push	r14
	sub	rsp,8
	mov	r14,rdi				; issuer pub
	lea	rdx,[rsi+rdx]			; end of the certificate
	call	der_read			; Certificate SEQUENCE
	jc	.bad
	cmp	al,0x30
	jne	.bad
	mov	r13,r8				; the certificate's end
	mov	rdx,r8
	mov	rbx,rsi				; tbsCertificate starts here (with its header)
	call	der_read			; tbsCertificate
	jc	.bad
	cmp	al,0x30
	jne	.bad
	mov	r12,r8				; and ends here (= signatureAlgorithm start)
	; hash the TBSCertificate's raw DER [rbx, r12)
	mov	[g_x509_tbs],rbx
	mov	eax,r12d
	sub	eax,ebx
	mov	[g_x509_tbslen],eax
	lea	rdi,[g_x509_dig]
	mov	rsi,rbx
	mov	edx,eax
	call	sha256
	; signatureAlgorithm must be ecdsa-with-SHA256
	mov	rsi,r12
	mov	rdx,r13
	call	der_read			; AlgorithmIdentifier SEQUENCE
	jc	.bad
	cmp	al,0x30
	jne	.bad
	mov	r12,r8				; signatureValue starts here
	mov	rdx,r8
	call	der_read			; its OID
	jc	.bad
	cmp	al,6
	jne	.bad
	lea	rdi,[oid_ecdsa_sha256]
	mov	edx,8
	call	der_oid_is
	jne	.bad				; not ECDSA-SHA256 (maybe RSA): not checked
	; signatureValue: BIT STRING of 00 | SEQUENCE { INTEGER r, INTEGER s }
	mov	rsi,r12
	mov	rdx,r13
	call	der_read
	jc	.bad
	cmp	al,3
	jne	.bad
	cmp	ecx,1
	jb	.bad
	cmp	byte [rsi],0			; no unused bits
	jne	.bad
	inc	rsi				; past the unused-bits octet
	mov	rdx,r8				; the BIT STRING's end
	call	der_read			; SEQUENCE { r, s }
	jc	.bad
	cmp	al,0x30
	jne	.bad
	mov	rdx,r8
	call	der_read			; INTEGER r
	jc	.bad
	cmp	al,2
	jne	.bad
	lea	rdi,[g_x509_r]
	push	r8
	call	der_int_32
	pop	r8
	jc	.bad
	mov	rsi,r8
	call	der_read			; INTEGER s
	jc	.bad
	cmp	al,2
	jne	.bad
	lea	rdi,[g_x509_s]
	call	der_int_32
	jc	.bad
	; verify
	mov	rdi,r14
	lea	rsi,[g_x509_dig]
	lea	rdx,[g_x509_r]
	lea	rcx,[g_x509_s]
	call	p256_verify
	jmp	.out
.bad:
	xor	eax,eax
.out:
	add	rsp,8
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rsi = certificate DER, edx = its length, rdi = out[65]: the subject EC
; P-256 public key (04|X|Y) written to out. eax = 1, or 0 when the cert is
; not an uncompressed P-256 key (RSA, another curve, or unparsable).
cert_extract_pubkey:
	push	rbx
	push	r12
	mov	r12,rdi				; out
	lea	rdx,[rsi+rdx]
	call	der_read			; Certificate SEQUENCE
	jc	.no
	cmp	al,0x30
	jne	.no
	mov	rdx,r8
	call	der_read			; tbsCertificate
	jc	.no
	cmp	al,0x30
	jne	.no
	mov	rdx,r8
	call	der_read			; [0] version, or the serial
	jc	.no
	mov	ebx,5
	cmp	al,0xA0
	jne	@f
	inc	ebx
@@:
	mov	rsi,r8
	dec	ebx
	jz	.spki
@@:
	call	der_read
	jc	.no
	mov	rsi,r8
	dec	ebx
	jnz	@b
.spki:
	call	der_read			; SubjectPublicKeyInfo
	jc	.no
	cmp	al,0x30
	jne	.no
	mov	rdx,r8
	call	der_read			; AlgorithmIdentifier
	jc	.no
	cmp	al,0x30
	jne	.no
	mov	rbx,r8				; the BIT STRING follows
	mov	rdx,r8
	call	der_read			; algorithm OID
	jc	.no
	cmp	al,6
	jne	.no
	lea	rdi,[oid_ec_public_key]
	mov	edx,7
	call	der_oid_is
	jne	.no
	mov	rsi,r8
	mov	rdx,rbx
	call	der_read			; the named curve
	jc	.no
	lea	rdi,[oid_prime256v1]
	mov	edx,8
	call	der_oid_is
	jne	.no
	mov	rsi,rbx
	mov	rdx,rbx				; (bounded by the SPKI already read)
	add	rdx,256
	call	der_read			; BIT STRING: 00 04 X Y
	jc	.no
	cmp	al,3
	jne	.no
	cmp	ecx,66
	jne	.no
	cmp	word [rsi],0x0400
	jne	.no
	inc	rsi
	mov	rdi,r12
	mov	ecx,65
	rep	movsb
	mov	eax,1
	jmp	.out
.no:
	xor	eax,eax
.out:
	pop	r12
	pop	rbx
	ret

; rsi = certificate DER, edx = its length. Parses the TBSCertificate and
; records, as (start, end) pairs of raw DER content, the validity
; (g_x509_val/g_x509_valend), the subject Name (g_x509_subj/..end) and the
; extensions SEQUENCE (g_x509_ext/..end, both 0 when absent). eax = 1, or 0
; when the certificate does not parse. Shared by cert_time_valid and
; cert_match_host; uses der_read, preserves r14/r15 for its callers.
x509_locate:
	push	rbx
	push	r12
	push	r13
	lea	rdx,[rsi+rdx]
	call	der_read			; Certificate SEQUENCE
	jc	.no
	cmp	al,0x30
	jne	.no
	mov	rdx,r8
	call	der_read			; tbsCertificate
	jc	.no
	cmp	al,0x30
	jne	.no
	mov	r13,r8				; the bound for the TBS children
	mov	rdx,r13
	call	der_read			; [0] version, or serialNumber
	jc	.no
	cmp	al,0xA0
	jne	.haveserial
	mov	rsi,r8				; skip the explicit version
	mov	rdx,r13
	call	der_read			; serialNumber
	jc	.no
.haveserial:
	mov	rsi,r8
	mov	rdx,r13
	call	der_read			; signature AlgorithmIdentifier
	jc	.no
	mov	rsi,r8
	mov	rdx,r13
	call	der_read			; issuer
	jc	.no
	mov	rsi,r8
	mov	rdx,r13
	call	der_read			; validity SEQUENCE
	jc	.no
	cmp	al,0x30
	jne	.no
	mov	[g_x509_val],rsi
	mov	[g_x509_valend],r8
	mov	rsi,r8
	mov	rdx,r13
	call	der_read			; subject
	jc	.no
	mov	[g_x509_subj],rsi
	mov	[g_x509_subjend],r8
	mov	rsi,r8
	mov	rdx,r13
	call	der_read			; subjectPublicKeyInfo
	jc	.no
	mov	qword [g_x509_ext],0
	mov	qword [g_x509_extend],0
.opt:
	mov	rsi,r8
	cmp	rsi,r13
	jae	.ok
	mov	rdx,r13
	call	der_read			; issuerUniqueID / subjectUniqueID / extensions
	jc	.ok
	cmp	al,0xA3				; extensions [3]
	jne	.opt
	mov	rdx,r8
	call	der_read			; the Extensions SEQUENCE
	jc	.ok
	cmp	al,0x30
	jne	.ok
	mov	[g_x509_ext],rsi
	mov	[g_x509_extend],r8
.ok:
	mov	eax,1
	jmp	.out
.no:
	xor	eax,eax
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; al = tag, rsi = content, ecx = length, rdi = out[14]: writes the time as
; 14 ASCII digits YYYYMMDDHHMMSS. UTCTime (0x17) gets its century from the
; RFC 5280 rule (YY < 50 => 20xx, else 19xx); GeneralizedTime (0x18) is
; copied as is. CF on an unexpected tag or a short value.
x509_time_norm:
	cmp	al,0x17
	je	.utc
	cmp	al,0x18
	je	.gen
	stc
	ret
.utc:
	cmp	ecx,12
	jb	.err
	mov	word [rdi],0x3032		; "20"
	cmp	byte [rsi],'5'
	jb	@f
	mov	word [rdi],0x3931		; "19"
@@:
	add	rdi,2
	mov	ecx,12
	rep	movsb
	clc
	ret
.gen:
	cmp	ecx,14
	jb	.err
	mov	ecx,14
	rep	movsb
	clc
	ret
.err:
	stc
	ret

; rsi = a[14], rdi = b[14]: eax = -1/0/1 for a <, =, > b (ASCII order).
x509_time_cmp:
	xor	eax,eax
.l:
	cmp	eax,14
	jae	.eq
	movzx	edx,byte [rsi+rax]
	movzx	ecx,byte [rdi+rax]
	cmp	dl,cl
	jb	.lt
	ja	.gt
	inc	eax
	jmp	.l
.eq:
	xor	eax,eax
	ret
.lt:
	mov	eax,-1
	ret
.gt:
	mov	eax,1
	ret

; rsi = certificate DER, edx = its length, rdi = now[14] (YYYYMMDDHHMMSS):
; eax = 1 when notBefore <= now <= notAfter, else 0 (also on a parse error).
cert_time_valid:
	push	rbx
	push	r13
	mov	r13,rdi				; now
	call	x509_locate
	test	eax,eax
	jz	.no
	mov	rsi,[g_x509_val]
	mov	rdx,[g_x509_valend]
	call	der_read			; notBefore
	jc	.no
	mov	rbx,r8
	lea	rdi,[g_time_a]
	call	x509_time_norm
	jc	.no
	mov	rsi,rbx
	mov	rdx,[g_x509_valend]
	call	der_read			; notAfter
	jc	.no
	lea	rdi,[g_time_b]
	call	x509_time_norm
	jc	.no
	lea	rsi,[g_time_a]
	mov	rdi,r13
	call	x509_time_cmp			; notBefore vs now
	test	eax,eax
	jg	.no				; not yet valid
	lea	rsi,[g_time_b]
	mov	rdi,r13
	call	x509_time_cmp			; notAfter vs now
	test	eax,eax
	jl	.no				; expired
	mov	eax,1
	jmp	.out
.no:
	xor	eax,eax
.out:
	pop	r13
	pop	rbx
	ret

; rdi = host, ecx = host length, rsi = candidate, r8d = candidate length:
; eax = 1 when the candidate DNS name matches the host, case-insensitively,
; with a single leftmost "*." wildcard that matches exactly one label.
; A leaf helper: it preserves rbx, r12, r14, r15 for cert_match_host.
x509_host_eq:
	cmp	r8d,2
	jb	.plain
	cmp	word [rsi],0x2E2A		; "*."
	jne	.plain
	add	rsi,2				; the candidate past "*."
	sub	r8d,2
	xor	eax,eax				; find the host's first dot
.find:
	cmp	eax,ecx
	jae	.no
	cmp	byte [rdi+rax],'.'
	je	.dot
	inc	eax
	jmp	.find
.dot:
	test	eax,eax
	jz	.no				; an empty first label
	inc	eax				; move past the dot
	add	rdi,rax
	sub	ecx,eax
.plain:
	cmp	ecx,r8d
	jne	.no
	xor	eax,eax
.cmp:
	cmp	eax,ecx
	jae	.yes
	movzx	edx,byte [rdi+rax]
	movzx	r9d,byte [rsi+rax]
	or	dl,0x20				; fold ASCII case
	or	r9b,0x20
	cmp	dl,r9b
	jne	.no
	inc	eax
	jmp	.cmp
.yes:
	mov	eax,1
	ret
.no:
	xor	eax,eax
	ret

; rsi = certificate DER, edx = its length, rdi = host, ecx = host length:
; eax = 1 when the certificate identifies the host. A subjectAltName, when
; present, is authoritative (its dNSName entries are matched and the CN is
; ignored); otherwise the subject commonName is matched. 0 otherwise.
cert_match_host:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r14,rdi				; host
	mov	r15d,ecx			; host length
	call	x509_locate
	test	eax,eax
	jz	.no
	cmp	qword [g_x509_ext],0
	je	.cn
	xor	r13d,r13d			; "a SAN was seen"
	mov	r12,[g_x509_ext]
.ext:
	cmp	r12,[g_x509_extend]
	jae	.after
	mov	rsi,r12
	mov	rdx,[g_x509_extend]
	call	der_read			; Extension SEQUENCE
	jc	.after
	cmp	al,0x30
	jne	.after
	mov	rbx,r8				; the next extension
	mov	rdx,r8
	call	der_read			; extnID
	jc	.nextext
	cmp	al,6
	jne	.nextext
	lea	rdi,[oid_san]
	mov	edx,3
	push	r8
	call	der_oid_is
	pop	r8
	jne	.nextext
	mov	r13b,1
	mov	rsi,r8				; the critical BOOLEAN or the value
	mov	rdx,rbx
	call	der_read
	jc	.no
	cmp	al,1				; skip an optional critical BOOLEAN
	jne	@f
	mov	rsi,r8
	mov	rdx,rbx
	call	der_read
	jc	.no
@@:
	cmp	al,4				; extnValue OCTET STRING
	jne	.no
	mov	rdx,r8
	call	der_read			; GeneralNames SEQUENCE
	jc	.no
	cmp	al,0x30
	jne	.no
	mov	rbx,rsi				; iterate the names
	mov	r12,r8
.gn:
	cmp	rbx,r12
	jae	.no				; SAN present, no dNSName matched
	mov	rsi,rbx
	mov	rdx,r12
	call	der_read
	jc	.no
	mov	rbx,r8
	cmp	al,0x82				; dNSName [2]
	jne	.gn
	mov	r8d,ecx				; candidate length
	mov	ecx,r15d
	mov	rdi,r14
	call	x509_host_eq
	test	eax,eax
	jnz	.yes
	jmp	.gn
.nextext:
	mov	r12,rbx
	jmp	.ext
.after:
	test	r13b,r13b
	jnz	.no				; a SAN existed but nothing matched
.cn:
	mov	rsi,[g_x509_subj]
	mov	r12,[g_x509_subjend]
.rdn:
	cmp	rsi,r12
	jae	.no
	mov	rdx,r12
	call	der_read			; RelativeDistinguishedName SET
	jc	.no
	mov	rbx,r8
	cmp	al,0x31
	jne	.rdnnext
	mov	rdx,r8
	call	der_read			; AttributeTypeAndValue SEQUENCE
	jc	.rdnnext
	cmp	al,0x30
	jne	.rdnnext
	mov	rdx,r8
	call	der_read			; the attribute type
	jc	.rdnnext
	cmp	al,6
	jne	.rdnnext
	lea	rdi,[oid_cn]
	mov	edx,3
	push	r8
	call	der_oid_is
	pop	r8
	jne	.rdnnext
	mov	rsi,r8
	mov	rdx,rbx
	call	der_read			; the attribute value (a string)
	jc	.rdnnext
	mov	r8d,ecx
	mov	ecx,r15d
	mov	rdi,r14
	call	x509_host_eq
	test	eax,eax
	jnz	.yes
.rdnnext:
	mov	rsi,rbx
	jmp	.rdn
.yes:
	mov	eax,1
	jmp	.out
.no:
	xor	eax,eax
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rsi = ptr, r8 = end: reads one TLS CertificateEntry (opaque cert<1..2^24-1>
; then an Extensions vector). rax = certificate DER, ecx = its length,
; rdx = the next entry. CF when it runs past the end.
chain_entry:
	lea	r9,[rsi+3]
	cmp	r9,r8
	ja	.bad
	movzx	ecx,byte [rsi]
	shl	ecx,16
	movzx	eax,byte [rsi+1]
	shl	eax,8
	or	ecx,eax
	movzx	eax,byte [rsi+2]
	or	ecx,eax				; the certificate length
	mov	rax,r9				; the certificate DER
	lea	r9,[rax+rcx]			; its end
	cmp	r9,r8
	ja	.bad
	lea	r10,[r9+2]
	cmp	r10,r8
	ja	.bad
	movzx	edx,word [r9]			; the Extensions length
	rol	dx,8
	movzx	edx,dx
	lea	rdx,[r10+rdx]			; the next entry
	cmp	rdx,r8
	ja	.bad
	clc
	ret
.bad:
	stc
	ret

; rdi = trust-anchor public key (04|X|Y, 65), rsi = the CertificateEntry
; list, edx = its length: eax = 1 when the chain verifies, that is the leaf
; is signed by the next certificate's key, each in turn, and the last by
; the anchor. 0 on any signature or parse failure. The list is leaf first,
; as sent in the TLS Certificate message (the anchor itself is not in it).
cert_chain_verify:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r14,rdi				; the anchor
	lea	r13,[rsi+rdx]			; the list end
	mov	r15,rsi				; the current entry
	cmp	r15,r13
	jae	.no				; an empty chain
.loop:
	mov	rsi,r15
	mov	r8,r13
	call	chain_entry
	jc	.no
	mov	rbx,rax				; the certificate to check
	mov	r12d,ecx
	mov	r15,rdx				; the next entry
	cmp	r15,r13
	jae	.anchor
	; the issuer key comes from the next certificate in the chain
	mov	rsi,r15
	mov	r8,r13
	call	chain_entry
	jc	.no
	lea	rdi,[g_x509_issuer]
	mov	rsi,rax
	mov	edx,ecx
	call	cert_extract_pubkey
	test	eax,eax
	jz	.no
	lea	rdi,[g_x509_issuer]
	jmp	.check
.anchor:
	mov	rdi,r14
.check:
	mov	rsi,rbx
	mov	edx,r12d
	call	cert_verify
	test	eax,eax
	jz	.no
	cmp	r15,r13
	jb	.loop
	mov	eax,1
	jmp	.out
.no:
	xor	eax,eax
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
