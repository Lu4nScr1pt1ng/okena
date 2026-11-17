; JA4 (FoxIO's TLS client fingerprint) of each TLS client: its first
; ClientHello, as it came (the outer one, with ECH), over TCP or QUIC:
;
;   t13d1516h2_8daaf6152771_e5627efa2ab1
;   | | | | | |  |            the extensions but SNI and ALPN, sorted, "_",
;   | | | | | |  |            the signature algorithms in their order: SHA-256, 12 hex
;   | | | | | |  the cipher suites, sorted: SHA-256, 12 hex
;   | | | | | the first ALPN's first and last characters (00: none)
;   | | | | extensions (2 digits, at most 99)   | cipher suites (2 digits)
;   | | | d: SNI sent, i: none
;   | | the highest TLS version offered (supported_versions, else the hello's)
;   | t: TCP, q: QUIC
;
; GREASE values (RFC 8701) are left out everywhere. The extensions' order is
; not in it (browsers shuffle them), so one browser build has one JA4.
;
; Computed only when the configuration uses it (`${tls.ja4}`, `match
; tls.ja4=`, `limit key=tls.ja4`) or asks for it (`okena { ja4 on }`, for the
; access log's "ja4"): tls_hello leaves it in g_ja4, its caller makes it the
; session's (ja4_take), an HTTP/2 or HTTP/3 stream takes its connection's.

JA_GEN		:= 0				; d: the session's generation then
JA_OK		:= 4				; d
JA_TEXT		:= 8				; 36
JA_SHIFT	:= 6
JA_LEN		:= 36
JA_MAXV		:= 256				; cipher suites, extensions, signature algorithms

bss
	align 8
	g_ja4_base	dq ?			; the sessions' records, 0 none
	g_ja4_ok	dd ?			; g_ja4 holds the hello tls_hello just read
	g_ja4_nc	dd ?
	g_ja4_ne	dd ?
	g_ja4_ns	dd ?
	g_ja4_next	dd ?			; extensions in the count (SNI and ALPN too)
	g_ja4_ver	dd ?
	g_ja4_sni	dd ?
	g_ja4_alpn	dw ?
	g_ja4		rb JA_LEN
	align 8
	g_ja4_c		rw JA_MAXV
	g_ja4_e		rw JA_MAXV
	g_ja4_s		rw JA_MAXV
	g_ja4_dig	rb 32
	g_ja4_txt	rb JA_MAXV * 10 + 8
end bss

; worker start: the records, when the plan computes JA4. eax = 0
ja4_worker_init:
	cmp	dword [g_plan_ja4],0
	je	.none
	xor	edi,edi
	mov	esi,[g_sessions]
	shl	rsi,JA_SHIFT
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.none				; (none: no fingerprints, nothing else lost)
	mov	[g_ja4_base],rax
.none:
	xor	eax,eax
	ret

; ax = a value: ZF when it is GREASE (0x?A?A, both bytes alike)
macro ja4_grease
	local skip
	push	rdx
	mov	edx,eax
	and	edx,0x0F0F
	cmp	edx,0x0A0A
	jne	skip
	cmp	al,ah
skip:
	pop	rdx
end macro

; r12 = a ClientHello (its 4-byte header first), ecx = its length, edx = 1
; over QUIC: g_ja4 and g_ja4_ok = 1, or 0 when it is not well made. Keeps all.
ja4_hello:
	push	rax
	push	rbx
	push	rcx
	push	rdx
	push	rsi
	push	rdi
	push	r8
	push	r9
	push	r10
	push	r11
	push	r13
	push	r14
	mov	dword [g_ja4_ok],0
	mov	r14d,edx
	xor	eax,eax
	mov	[g_ja4_nc],eax
	mov	[g_ja4_ne],eax
	mov	[g_ja4_ns],eax
	mov	[g_ja4_next],eax
	mov	[g_ja4_sni],eax
	mov	[g_ja4_alpn],ax
	lea	r13,[r12+rcx]			; the end
	lea	rsi,[r12+4]
	lea	rax,[rsi+35]
	cmp	rax,r13
	ja	.bad
	movzx	eax,word [rsi]			; legacy_version
	xchg	al,ah
	mov	[g_ja4_ver],eax
	add	rsi,34				; version, random
	movzx	eax,byte [rsi]			; session id
	lea	rsi,[rsi+rax+1]
	lea	rax,[rsi+2]
	cmp	rax,r13
	ja	.bad
	movzx	ecx,word [rsi]			; cipher suites
	xchg	cl,ch
	add	rsi,2
	lea	rax,[rsi+rcx]
	cmp	rax,r13
	ja	.bad
	test	ecx,1
	jnz	.bad
	shr	ecx,1
.cipher:
	test	ecx,ecx
	jz	.ciphers_done
	movzx	eax,word [rsi]
	xchg	al,ah
	add	rsi,2
	dec	ecx
	ja4_grease
	je	.cipher
	mov	edx,[g_ja4_nc]
	cmp	edx,JA_MAXV
	jae	.bad
	mov	[g_ja4_c+rdx*2],ax
	inc	dword [g_ja4_nc]
	jmp	.cipher
.ciphers_done:
	cmp	rsi,r13
	jae	.bad
	movzx	eax,byte [rsi]			; compression methods
	lea	rsi,[rsi+rax+1]
	cmp	rsi,r13
	ja	.bad
	je	.exts_done			; (no extensions at all)
	lea	rax,[rsi+2]
	cmp	rax,r13
	ja	.bad
	movzx	ecx,word [rsi]
	xchg	cl,ch
	add	rsi,2
	lea	rbx,[rsi+rcx]			; the extensions' end
	cmp	rbx,r13
	ja	.bad
.ext:
	lea	rax,[rsi+4]
	cmp	rax,rbx
	ja	.exts_done
	movzx	eax,word [rsi]			; type
	xchg	al,ah
	movzx	ecx,word [rsi+2]		; length
	xchg	cl,ch
	add	rsi,4
	lea	rdi,[rsi+rcx]
	cmp	rdi,rbx
	ja	.bad
	ja4_grease
	je	.ext_next
	inc	dword [g_ja4_next]
	test	eax,eax
	jz	.sni
	cmp	eax,0x10
	je	.alpn
	mov	edx,[g_ja4_ne]			; (in the hash: all but SNI and ALPN)
	cmp	edx,JA_MAXV
	jae	.bad
	mov	[g_ja4_e+rdx*2],ax
	inc	dword [g_ja4_ne]
	cmp	eax,0x2B
	je	.versions
	cmp	eax,0x0D
	je	.sigalgs
	jmp	.ext_next
.sni:
	mov	dword [g_ja4_sni],1
	jmp	.ext_next
.alpn:						; u16 list length, u8 length, the first
	cmp	ecx,3
	jb	.ext_next
	movzx	edx,byte [rsi+2]
	test	edx,edx
	jz	.ext_next
	lea	r8d,[rdx+3]
	cmp	r8d,ecx
	ja	.ext_next
	movzx	r8d,byte [rsi+3]		; its first and last characters
	movzx	r9d,byte [rsi+rdx+2]
	mov	r10d,r8d
	call	.alnum
	jc	.alpn_hex
	mov	r10d,r9d
	call	.alnum
	jc	.alpn_hex
	mov	byte [g_ja4_alpn],r8b
	mov	byte [g_ja4_alpn+1],r9b
	jmp	.ext_next
.alpn_hex:					; their hex: the first's first digit, the last's last
	shr	r8d,4
	and	r9d,15
	mov	r8b,[ja4_hex+r8]
	mov	r9b,[ja4_hex+r9]
	mov	byte [g_ja4_alpn],r8b
	mov	byte [g_ja4_alpn+1],r9b
	jmp	.ext_next
.versions:					; u8 length, u16s: the highest not GREASE
	test	ecx,ecx
	jz	.ext_next
	movzx	edx,byte [rsi]
	lea	r8d,[rdx+1]
	cmp	r8d,ecx
	ja	.ext_next
	shr	edx,1
	lea	r8,[rsi+1]
	xor	r9d,r9d
.version:
	test	edx,edx
	jz	.versions_done
	movzx	eax,word [r8]
	xchg	al,ah
	add	r8,2
	dec	edx
	ja4_grease
	je	.version
	cmp	eax,r9d
	jbe	.version
	cmp	eax,0xFE00			; (DTLS counts down: as is)
	jae	.version
	mov	r9d,eax
	jmp	.version
.versions_done:
	test	r9d,r9d
	jz	.ext_next
	mov	[g_ja4_ver],r9d
	jmp	.ext_next
.sigalgs:					; u16 length, u16s, in their order
	cmp	ecx,2
	jb	.ext_next
	movzx	edx,word [rsi]
	xchg	dl,dh
	lea	r8d,[rdx+2]
	cmp	r8d,ecx
	ja	.ext_next
	shr	edx,1
	lea	r8,[rsi+2]
.sigalg:
	test	edx,edx
	jz	.ext_next
	movzx	eax,word [r8]
	xchg	al,ah
	add	r8,2
	dec	edx
	ja4_grease
	je	.sigalg
	mov	r9d,[g_ja4_ns]
	cmp	r9d,JA_MAXV
	jae	.bad
	mov	[g_ja4_s+r9*2],ax
	inc	dword [g_ja4_ns]
	jmp	.sigalg
.ext_next:
	mov	rsi,rdi
	jmp	.ext
.exts_done:
	; a: t13d1516h2
	lea	rdi,[g_ja4]
	mov	al,'t'
	test	r14d,r14d
	jz	@f
	mov	al,'q'
@@:
	stosb
	mov	eax,[g_ja4_ver]
	mov	dx,'00'
	cmp	eax,0x0304
	jne	@f
	mov	dx,'13'
@@:
	cmp	eax,0x0303
	jne	@f
	mov	dx,'12'
@@:
	cmp	eax,0x0302
	jne	@f
	mov	dx,'11'
@@:
	cmp	eax,0x0301
	jne	@f
	mov	dx,'10'
@@:
	cmp	eax,0x0300
	jne	@f
	mov	dx,'s3'
@@:
	mov	[rdi],dx
	add	rdi,2
	mov	al,'i'
	cmp	dword [g_ja4_sni],0
	je	@f
	mov	al,'d'
@@:
	stosb
	mov	eax,[g_ja4_nc]
	call	.two
	mov	eax,[g_ja4_next]
	call	.two
	mov	ax,[g_ja4_alpn]
	test	ax,ax
	jnz	@f
	mov	ax,'00'
@@:
	stosw
	; b: the cipher suites, sorted
	mov	byte [rdi],'_'
	inc	rdi
	lea	rsi,[g_ja4_c]
	mov	ecx,[g_ja4_nc]
	call	.sort
	push	rdi
	lea	rdi,[g_ja4_txt]
	mov	ecx,[g_ja4_nc]
	call	.list
	mov	rdx,rdi
	pop	rdi
	cmp	dword [g_ja4_nc],0
	je	.zeros_b
	call	.hash12
	jmp	.c
.zeros_b:
	call	.zeros
.c:
	; c: the extensions (but SNI and ALPN), sorted, then the signature algorithms
	mov	byte [rdi],'_'
	inc	rdi
	lea	rsi,[g_ja4_e]
	mov	ecx,[g_ja4_ne]
	call	.sort
	cmp	dword [g_ja4_ne],0
	je	.zeros_c
	push	rdi
	lea	rdi,[g_ja4_txt]
	lea	rsi,[g_ja4_e]
	mov	ecx,[g_ja4_ne]
	call	.list
	cmp	dword [g_ja4_ns],0
	je	@f
	mov	byte [rdi],'_'
	inc	rdi
	lea	rsi,[g_ja4_s]
	mov	ecx,[g_ja4_ns]
	call	.list
@@:
	mov	rdx,rdi
	pop	rdi
	call	.hash12
	jmp	.done
.zeros_c:
	call	.zeros
.done:
	mov	dword [g_ja4_ok],1
.bad:
	pop	r14
	pop	r13
	pop	r11
	pop	r10
	pop	r9
	pop	r8
	pop	rdi
	pop	rsi
	pop	rdx
	pop	rcx
	pop	rbx
	pop	rax
	ret
; r10d = a byte: CF unless an ASCII letter or digit
.alnum:
	lea	eax,[r10-'0']
	cmp	eax,9
	jbe	.yes
	mov	eax,r10d
	or	eax,0x20
	sub	eax,'a'
	cmp	eax,25
	jbe	.yes
	stc
	ret
.yes:
	clc
	ret
; eax = a count: two digits (99 at most), at rdi
.two:
	cmp	eax,99
	jbe	@f
	mov	eax,99
@@:
	xor	edx,edx
	mov	ecx,10
	div	ecx
	add	al,'0'
	add	dl,'0'
	mov	[rdi],al
	mov	[rdi+1],dl
	add	rdi,2
	ret
; rsi = u16s, ecx = how many: sorted (insertion: a few dozen)
.sort:
	cmp	ecx,2
	jb	.sorted
	mov	r8d,1
.outer:
	movzx	eax,word [rsi+r8*2]
	mov	r9d,r8d
.inner:
	test	r9d,r9d
	jz	.place
	movzx	edx,word [rsi+r9*2-2]
	cmp	edx,eax
	jbe	.place
	mov	[rsi+r9*2],dx
	dec	r9d
	jmp	.inner
.place:
	mov	[rsi+r9*2],ax
	inc	r8d
	cmp	r8d,ecx
	jb	.outer
.sorted:
	ret
; rsi = u16s, ecx = how many (1 or more): "002f,0035,..." at rdi, rdi after
.list:
	test	ecx,ecx
	jz	.listed
.item:
	movzx	eax,word [rsi]
	add	rsi,2
	mov	edx,eax
	shr	edx,12
	mov	dl,[ja4_hex+rdx]
	mov	[rdi],dl
	mov	edx,eax
	shr	edx,8
	and	edx,15
	mov	dl,[ja4_hex+rdx]
	mov	[rdi+1],dl
	mov	edx,eax
	shr	edx,4
	and	edx,15
	mov	dl,[ja4_hex+rdx]
	mov	[rdi+2],dl
	and	eax,15
	mov	al,[ja4_hex+rax]
	mov	[rdi+3],al
	mov	byte [rdi+4],','
	add	rdi,5
	dec	ecx
	jnz	.item
	dec	rdi				; (no comma after the last)
.listed:
	ret
; g_ja4_txt up to rdx: the first 6 bytes of its SHA-256 as 12 hex, at rdi
.hash12:
	push	rdi
	lea	rsi,[g_ja4_txt]
	sub	rdx,rsi
	lea	rdi,[g_ja4_dig]
	call	sha256
	pop	rdi
	xor	ecx,ecx
@@:
	movzx	eax,byte [g_ja4_dig+rcx]
	mov	edx,eax
	shr	edx,4
	and	eax,15
	mov	dl,[ja4_hex+rdx]
	mov	al,[ja4_hex+rax]
	mov	[rdi],dl
	mov	[rdi+1],al
	add	rdi,2
	inc	ecx
	cmp	ecx,6
	jb	@b
	ret
.zeros:
	mov	rax,'00000000'
	mov	[rdi],rax
	mov	dword [rdi+8],'0000'
	add	rdi,12
	ret

rodata
	ja4_hex		db '0123456789abcdef'
end rodata

; ebx = session, after tls_hello: the fingerprint it read, the session's (a
; hello not read yet, or a second one after a retry: nothing changes). Keeps
; all but flags.
ja4_take:
	cmp	dword [g_ja4_ok],0
	je	.out
	push	rax
	push	rcx
	push	rsi
	push	rdi
	mov	rdi,[g_ja4_base]
	test	rdi,rdi
	jz	.none
	mov	eax,ebx
	shl	rax,JA_SHIFT
	add	rdi,rax
	call	session_ptr
	mov	eax,[rax+S_GEN]
	mov	[rdi+JA_GEN],eax
	mov	dword [rdi+JA_OK],1
	add	rdi,JA_TEXT
	lea	rsi,[g_ja4]
	mov	ecx,JA_LEN
	rep	movsb
.none:
	mov	dword [g_ja4_ok],0
	pop	rdi
	pop	rsi
	pop	rcx
	pop	rax
.out:
	ret

; ebx = session: rax = its fingerprint (JA_LEN bytes), 0 none. Keeps all but
; rax, rcx.
ja4_rec:
	mov	rax,[g_ja4_base]
	test	rax,rax
	jz	.out
	mov	ecx,ebx
	shl	rcx,JA_SHIFT
	add	rax,rcx
	cmp	dword [rax+JA_OK],0
	je	.none
	push	rax
	call	session_ptr
	mov	ecx,[rax+S_GEN]
	pop	rax
	cmp	ecx,[rax+JA_GEN]
	jne	.none
	add	rax,JA_TEXT
	ret
.none:
	xor	eax,eax
.out:
	ret

; edi = a stream's session, esi = its connection's: the connection's
; fingerprint the stream's too. Keeps all but rax, rcx, flags.
ja4_inherit:
	cmp	qword [g_ja4_base],0
	je	.out
	push	rbx
	push	rsi
	push	rdi
	mov	ebx,esi
	call	ja4_rec
	mov	ebx,edi
	mov	edi,edi
	shl	rdi,JA_SHIFT
	add	rdi,[g_ja4_base]
	test	rax,rax
	jz	.none
	mov	rsi,rax
	push	rdi
	call	session_ptr
	pop	rdi
	mov	eax,[rax+S_GEN]
	mov	[rdi+JA_GEN],eax
	mov	dword [rdi+JA_OK],1
	add	rdi,JA_TEXT
	mov	ecx,JA_LEN
	rep	movsb
	jmp	.done
.none:
	mov	dword [rdi+JA_OK],0
.done:
	pop	rdi
	pop	rsi
	pop	rbx
.out:
	ret

; ebx = session, rdi = out: its fingerprint, rax = after it. CF: none. Keeps
; all but rax, rcx, rdi, flags.
ja4_value:
	call	ja4_rec
	test	rax,rax
	jz	.no
	push	rsi
	mov	rsi,rax
	mov	ecx,JA_LEN
	rep	movsb
	pop	rsi
	mov	rax,rdi
	clc
	ret
.no:
	stc
	ret

; rdi = a log line, ebx = session: ,"ja4":"..." when it has one; rdi after.
; Keeps all but rax, rcx, flags.
ja4_log:
	call	ja4_rec
	test	rax,rax
	jz	.out
	push	rsi
	mov	rsi,rax
	mov	dword [rdi],',"ja'
	mov	dword [rdi+4],'4":"'
	add	rdi,8
	mov	ecx,JA_LEN
	rep	movsb
	mov	byte [rdi],'"'
	inc	rdi
	pop	rsi
.out:
	ret
