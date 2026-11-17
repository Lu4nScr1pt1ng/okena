; PROXY protocol v2 TLVs (proxy_protocol accept): what the balancer in front
; says of the connection besides its addresses, kept for the session and its
; streams, and given to routes and logs:
;
;   proxy.authority     PP2_TYPE_AUTHORITY: the host name the client asked for (its SNI)
;   proxy.unique_id     PP2_TYPE_UNIQUE_ID: the balancer's id of the connection (hex)
;   proxy.alpn          PP2_TYPE_ALPN
;   proxy.ssl_version   PP2_TYPE_SSL / PP2_SUBTYPE_SSL_VERSION: TLS the client spoke to it
;   proxy.aws_vpce      AWS (0xEA), PP2_SUBTYPE_AWS_VPCE_ID: the VPC endpoint it came by
;   proxy.azure_linkid  Azure (0xEE), its Private Link ID
;   proxy.gcp_psc       GCP (0xE0), the Private Service Connect connection ID
;
; as ${proxy.NAME} in a header's value, `match proxy.NAME=VALUE` and the
; access logs' "proxy" object. A text TLV with a byte that is not printable
; ASCII is not kept (no header gets a CR or an LF from the network).

PV_GEN		:= 0				; d: the session's generation then
PV_HAS		:= 4				; d: 1 shl kind, of those there
PV_AUTHL	:= 8
PV_AUTH		:= 12				; 128
PV_UIDL		:= 140
PV_UID		:= 144				; 128, raw
PV_ALPNL	:= 272
PV_ALPN		:= 276				; 32
PV_SSLVL	:= 308
PV_SSLV		:= 312				; 32
PV_VPCEL	:= 344
PV_VPCE		:= 348				; 64
PV_AZURE	:= 412				; d
PV_GCP		:= 416				; q
PV_SIZE		:= 512
PV_SHIFT	:= 9
PQ_AUTH		:= 1
PQ_UID		:= 2
PQ_ALPN		:= 3
PQ_SSLV		:= 4
PQ_VPCE		:= 5
PQ_AZURE	:= 6
PQ_GCP		:= 7
PQ_N		:= 8
LK_PPT		:= 10				; `match proxy.NAME` (match.inc)

bss
	align 8
	g_ppt_base	dq ?			; the sessions' records, 0 none
	g_ppt_tmp:	rb PV_SIZE		; the header being read
	g_ppt_val:	rb 300			; a value as text (match)
end bss

rodata
	; kind: its name after "proxy.", its record's length and bytes (0: a number)
	ppt_names	db 9,'authority', 9,'unique_id', 4,'alpn', 11,'ssl_version', 8,'aws_vpce'
			db 12,'azure_linkid', 7,'gcp_psc', 0
	ppt_lens	dw 0, PV_AUTHL, PV_UIDL, PV_ALPNL, PV_SSLVL, PV_VPCEL, 0, 0
end rodata

; worker start: the records, when a listener takes PROXY headers. eax = 0
ppt_worker_init:
	xor	ecx,ecx
.l:
	cmp	ecx,[g_plan_listeners]
	jae	.none
	imul	rax,rcx,LS_SIZE
	inc	ecx
	test	dword [g_listeners+rax+LS_FLAGS],LSF_PP_IN
	jz	.l
	xor	edi,edi
	mov	esi,[g_sessions]
	shl	rsi,PV_SHIFT
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.none				; (none: no TLVs kept, nothing else lost)
	mov	[g_ppt_base],rax
.none:
	xor	eax,eax				; (the worker's start: 0 or -errno)
	ret

; rsi = a name (after "proxy."), ecx = its length: eax = its kind, 0 none.
; Keeps rbx, r8-r15.
ppt_kind:
	push	rdi
	lea	rdi,[ppt_names]
	xor	eax,eax
.k:
	inc	eax
	movzx	edx,byte [rdi]
	test	edx,edx
	jz	.no
	cmp	edx,ecx
	jne	.next
	push	rsi
	push	rdi
	push	rcx
	inc	rdi
	repe	cmpsb
	pop	rcx
	pop	rdi
	pop	rsi
	je	.out
.next:
	movzx	edx,byte [rdi]
	lea	rdi,[rdi+rdx+1]
	jmp	.k
.no:
	xor	eax,eax
.out:
	pop	rdi
	ret

; rsi = the TLVs, ecx = their length: g_ppt_tmp from them (what is not
; understood, or not well made, left out). Keeps rbx, r12-r15.
pp_tlvs:
	mov	dword [g_ppt_tmp+PV_HAS],0
.tlv:
	cmp	ecx,3
	jb	.out
	movzx	eax,byte [rsi]			; type
	movzx	edx,word [rsi+1]
	xchg	dl,dh				; length
	add	rsi,3
	sub	ecx,3
	cmp	edx,ecx
	ja	.out				; (cut short: no more)
	push	rsi
	push	rcx
	push	rdx
	call	.one
	pop	rdx
	pop	rcx
	pop	rsi
	add	rsi,rdx
	sub	ecx,edx
	jmp	.tlv
.out:
	ret
; eax = type, rsi/edx = value
.one:
	cmp	eax,0x02
	je	.authority
	cmp	eax,0x05
	je	.uid
	cmp	eax,0x01
	je	.alpn
	cmp	eax,0x20
	je	.ssl
	cmp	eax,0xEA
	je	.aws
	cmp	eax,0xEE
	je	.azure
	cmp	eax,0xE0
	je	.gcp
	ret
.authority:
	mov	r8d,PQ_AUTH
	mov	r9d,PV_AUTHL
	mov	r10d,128
	jmp	.text
.alpn:
	mov	r8d,PQ_ALPN
	mov	r9d,PV_ALPNL
	mov	r10d,32
	jmp	.text
.uid:
	cmp	edx,128
	ja	.r
	test	edx,edx
	jz	.r
	mov	[g_ppt_tmp+PV_UIDL],edx
	lea	rdi,[g_ppt_tmp+PV_UID]
	mov	ecx,edx
	rep	movsb
	or	dword [g_ppt_tmp+PV_HAS],1 shl PQ_UID
.r:
	ret
.ssl:						; client (1), verify (4), then sub-TLVs
	cmp	edx,5
	jb	.r
	add	rsi,5
	sub	edx,5
.sub:
	cmp	edx,3
	jb	.r
	movzx	eax,byte [rsi]
	movzx	ecx,word [rsi+1]
	xchg	cl,ch
	add	rsi,3
	sub	edx,3
	cmp	ecx,edx
	ja	.r
	cmp	eax,0x21			; PP2_SUBTYPE_SSL_VERSION
	jne	@f
	push	rsi
	push	rdx
	push	rcx
	mov	edx,ecx
	mov	r8d,PQ_SSLV
	mov	r9d,PV_SSLVL
	mov	r10d,32
	call	.text
	pop	rcx
	pop	rdx
	pop	rsi
@@:
	add	rsi,rcx
	sub	edx,ecx
	jmp	.sub
.aws:
	test	edx,edx
	jz	.r
	cmp	byte [rsi],0x01			; PP2_SUBTYPE_AWS_VPCE_ID
	jne	.r
	inc	rsi
	dec	edx
	mov	r8d,PQ_VPCE
	mov	r9d,PV_VPCEL
	mov	r10d,64
	jmp	.text
.azure:						; subtype 1: the LinkID, 4 bytes little endian
	cmp	edx,5
	jne	.r
	cmp	byte [rsi],0x01
	jne	.r
	mov	eax,[rsi+1]
	mov	[g_ppt_tmp+PV_AZURE],eax
	or	dword [g_ppt_tmp+PV_HAS],1 shl PQ_AZURE
	ret
.gcp:						; 8 bytes, big endian
	cmp	edx,8
	jne	.r
	mov	rax,[rsi]
	bswap	rax
	mov	[g_ppt_tmp+PV_GCP],rax
	or	dword [g_ppt_tmp+PV_HAS],1 shl PQ_GCP
	ret
; rsi/edx = text, r8d = kind, r9d = its length's place, r10d = room: kept
; when it is all printable ASCII
.text:
	test	edx,edx
	jz	.r
	cmp	edx,r10d
	ja	.r
	xor	ecx,ecx
@@:
	mov	al,[rsi+rcx]
	cmp	al,0x21
	jb	.r
	cmp	al,0x7E
	ja	.r
	inc	ecx
	cmp	ecx,edx
	jb	@b
	mov	[g_ppt_tmp+r9],edx
	lea	rdi,[g_ppt_tmp+r9+4]
	mov	ecx,edx
	rep	movsb
	bts	dword [g_ppt_tmp+PV_HAS],r8d
	ret

; ebx = session, its PROXY header applied: its TLVs its own (none, for a v1
; header or a LOCAL one: g_ppt_tmp says none). Keeps all but rax, rcx, rsi, rdi.
ppt_take:
	mov	rdi,[g_ppt_base]
	test	rdi,rdi
	jz	.out
	mov	eax,ebx
	shl	rax,PV_SHIFT
	add	rdi,rax
	cmp	dword [g_ppt_tmp+PV_HAS],0
	jne	.copy
	mov	dword [rdi+PV_HAS],0
	ret
.copy:
	push	rdi
	lea	rsi,[g_ppt_tmp]
	mov	ecx,PV_SIZE / 8
	rep	movsq
	pop	rdi
	push	rdi
	call	session_ptr
	pop	rdi
	mov	eax,[rax+S_GEN]
	mov	[rdi+PV_GEN],eax
.out:
	ret

; ebx = session: rax = its TLVs' record, 0 none. Keeps all but rax, rcx.
ppt_rec:
	mov	rax,[g_ppt_base]
	test	rax,rax
	jz	.out
	mov	ecx,ebx
	shl	rcx,PV_SHIFT
	add	rax,rcx
	cmp	dword [rax+PV_HAS],0
	je	.none
	push	rax
	call	session_ptr
	mov	ecx,[rax+S_GEN]
	pop	rax
	cmp	ecx,[rax+PV_GEN]
	je	.out
.none:
	xor	eax,eax
.out:
	ret

; edi = a stream's session, esi = its connection's: the connection's TLVs
; the stream's too. Keeps rbx, r8-r15.
ppt_inherit:
	mov	r10,[g_ppt_base]
	test	r10,r10
	jz	.out
	push	rbx
	mov	ebx,esi
	call	ppt_rec
	mov	ebx,edi
	mov	edi,edi
	shl	rdi,PV_SHIFT
	add	rdi,r10
	test	rax,rax
	jz	.none
	push	rdi
	mov	rsi,rax
	mov	ecx,PV_SIZE / 8
	rep	movsq
	call	session_ptr
	pop	rdi
	mov	eax,[rax+S_GEN]
	mov	[rdi+PV_GEN],eax
	pop	rbx
	ret
.none:
	mov	dword [rdi+PV_HAS],0
	pop	rbx
.out:
	ret

; ebx = session, ecx = a kind, rdi = out: its value as text, rax = after it.
; CF: not there. Keeps rbx, r12-r15.
ppt_value:
	push	rcx
	call	ppt_rec
	pop	rcx
	test	rax,rax
	jz	.no
	bt	dword [rax+PV_HAS],ecx
	jnc	.no
	cmp	ecx,PQ_UID
	je	.hex
	cmp	ecx,PQ_AZURE
	je	.azure
	cmp	ecx,PQ_GCP
	je	.gcp
	movzx	edx,word [ppt_lens+rcx*2]
	mov	ecx,[rax+rdx]
	lea	rsi,[rax+rdx+4]
	rep	movsb
	mov	rax,rdi
	clc
	ret
.hex:
	mov	ecx,[rax+PV_UIDL]
	lea	rsi,[rax+PV_UID]
@@:
	movzx	eax,byte [rsi]
	mov	edx,eax
	shr	eax,4
	and	edx,15
	movzx	eax,byte [ppt_hexd+rax]
	movzx	edx,byte [ppt_hexd+rdx]
	mov	[rdi],al
	mov	[rdi+1],dl
	add	rdi,2
	inc	rsi
	dec	ecx
	jnz	@b
	mov	rax,rdi
	clc
	ret
.azure:
	mov	eax,[rax+PV_AZURE]
	call	fmt_u64
	mov	rax,rdi
	clc
	ret
.gcp:
	mov	rax,[rax+PV_GCP]
	call	fmt_u64
	mov	rax,rdi
	clc
	ret
.no:
	stc
	ret

; rdi = a log line, ebx = session: `,"proxy":{...}` when its header had TLVs;
; rdi after. Keeps rbx, r12-r15.
ppt_log:
	call	ppt_rec
	test	rax,rax
	jz	.out
	push	r12
	push	r13
	memit ',"proxy":{'
	mov	r12d,1				; the kind
	xor	r13d,r13d			; one written
	lea	r8,[ppt_names]
.k:
	movzx	edx,byte [r8]
	test	edx,edx
	jz	.end
	push	r8
	push	rdx
	mov	ecx,r12d
	push	rdi
	lea	rdi,[g_ppt_val]
	call	ppt_value
	pop	rdi
	pop	rdx
	pop	r8
	jc	.next
	push	rax				; (its end, in g_ppt_val)
	test	r13d,r13d
	jz	@f
	mov	byte [rdi],','
	inc	rdi
@@:
	mov	r13d,1
	mov	byte [rdi],'"'
	inc	rdi
	lea	rsi,[r8+1]
	mov	ecx,edx
	rep	movsb
	mov	dword [rdi],'":"'
	add	rdi,3
	pop	rax
	lea	rsi,[g_ppt_val]
	sub	rax,rsi
	mov	edx,eax
	push	r8
	mov	ecx,300 * 6
	call	json_text
	pop	r8
	mov	byte [rdi],'"'
	inc	rdi
.next:
	movzx	edx,byte [r8]
	lea	r8,[r8+rdx+1]
	inc	r12d
	jmp	.k
.end:
	mov	byte [rdi],'}'
	inc	rdi
	pop	r13
	pop	r12
.out:
	ret

rodata
	ppt_hexd	db '0123456789abcdef'
end rodata
