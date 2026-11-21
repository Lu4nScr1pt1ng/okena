; Our QPACK encoder's dynamic table (RFC 9204 2.1, 3.2, 4.3): the fields our
; answers say again and again (the date, a content type the static table
; does not have, server, vary...) are inserted through our encoder stream
; (id 11) and, once the client says it has them (Insert Count Increment, on
; its decoder stream), named by their index: a byte or two in place of the
; whole line, and the client decodes no string. Only entries the client has
; are named, so no stream ever waits for an insert (no blocked streams).
;
; Each connection's state lies past its frames table (qfx_slot): the counts,
; the entries (where their bytes are), their bytes, and the encoder stream's
; bytes not yet acknowledged, a ring. Nothing is evicted: once the table is
; full, the fields go as the static table has them (a long-lived connection
; whose date changes each second fills a 4 KiB table in about a minute).

QE_CAP		:= 0				; d: the table's capacity, 0: none (no SETTINGS yet)
QE_INS		:= 4				; d: entries inserted
QE_KRC		:= 8				; d: and known to the client (Known Received Count)
QE_USED		:= 12				; d: the table's size (RFC 9204 3.2.1)
QE_DUSED	:= 16				; d: its bytes kept
QE_MAXE		:= 20				; d: the client's MaxEntries (its capacity / 32)
QE_CAPSENT	:= 24				; d: the stream type and Set Dynamic Table Capacity written
QE_END		:= 32				; q: encoder stream bytes written
QE_SENT		:= 40				; q: sent
QE_ACK		:= 48				; q: acknowledged
QE_QSEND	:= 64				; 32: the request streams that may have something
						; to send, a bit each (QC_QREQ's): set when it may,
						; cleared when found with nothing (qsend_*)
QE_HDR		:= 128
QE_EMAX		:= 128				; entries, at most
QE_ENT		:= QE_HDR			; QE_EMAX of (bytes w, name length w, value length w, w)
QE_DATA		:= QE_ENT + QE_EMAX * 8
QE_DCAP		:= 4096
QE_RING		:= QE_DATA + QE_DCAP
QE_RCAP		:= 8192				; (a power of two)
QE_SIZE		:= QE_RING + QE_RCAP
QE_OFF		:= ((SP_N + 1) * QFX_SLOT + 63) and not 63
assert QE_OFF + QE_SIZE <= 1 shl QFX_SHIFT
; the stream table's ring headers (http3.inc), past QE
QTH_OFF		:= (QE_OFF + QE_SIZE + 63) and not 63
assert QTH_OFF + QST_N * QTH_SIZE <= 1 shl QFX_SHIFT
; r8 = an entry of the stream table (r15 = connection): rax = its ring's
; header. Keeps all but rax.
qth_of:
	push	rcx
	mov	rcx,r8
	sub	rcx,r15
	sub	rcx,QC_QST
	imul	ecx,ecx,683			; / QST_SIZE (96): exact for entries below 2048
	shr	ecx,16
	imul	ecx,ecx,QTH_SIZE
	call	qe_ptr
	lea	rax,[rax-QE_OFF+QTH_OFF+rcx]
	pop	rcx
	ret
QE_MARK		:= 0xFFFFFFF0			; a packet's frame of our encoder stream (QFX_SESS)
QE_FIELD_MAX	:= 200				; a field inserted, name and value, at most

bss
	align 8
	g_qe		dq ?			; h3_head_out: the connection's encoder state, 0 none
	g_qe_base	dd ?			; the section's base: the inserts known when it began
	g_qe_ric	dd ?			; its Required Insert Count so far
	g_qe_tmp	rb QE_FIELD_MAX + 32
end bss

; r15 = a connection (its QC): rax = its encoder state. Keeps all but rax.
qe_ptr:
	push	rcx
	mov	rax,r15
	sub	rax,[g_hbuf_base]
	shr	rax,HB_SHIFT
	shl	rax,QFX_SHIFT
	add	rax,[g_qfx_base]
	add	rax,QE_OFF
	pop	rcx
	ret

; the client's SETTINGS (r15 = connection): rax = its QPACK_MAX_TABLE_CAPACITY.
; Our table is that large, up to QE_DCAP; its MaxEntries count its own.
; Keeps all but rax.
qe_settings:
	push	rcx
	push	rdx
	mov	rcx,rax
	call	qe_ptr
	cmp	dword [rax+QE_CAP],0
	jne	.out				; (once)
	mov	rdx,rcx
	shr	rdx,5
	cmp	rdx,1 shl 30
	jb	@f
	mov	edx,1 shl 30
@@:
	mov	[rax+QE_MAXE],edx
	cmp	rcx,QE_DCAP
	jbe	@f
	mov	ecx,QE_DCAP
@@:
	mov	[rax+QE_CAP],ecx
.out:
	pop	rdx
	pop	rcx
	ret

; an Insert Count Increment from the client (r15 = connection): rax = by how
; much. Keeps all but rax.
qe_increment:
	push	rcx
	push	rdx
	mov	rcx,rax
	call	qe_ptr
	mov	edx,[rax+QE_KRC]
	add	rdx,rcx
	mov	ecx,[rax+QE_INS]
	cmp	rdx,rcx				; (more than was inserted: as many)
	jbe	@f
	mov	edx,ecx
@@:
	mov	[rax+QE_KRC],edx
	pop	rdx
	pop	rcx
	ret

; h3_head_out, a section's start: r12 = the stream's record. g_qe = its
; connection's encoder state when it has a table, the base its references
; count from. Keeps all but rax.
qe_section:
	mov	qword [g_qe],0
	mov	dword [g_qe_ric],0
	push	rcx
	push	r15
	mov	eax,[r12+H_H3C]			; the connection, still that one?
	mov	ecx,eax
	shl	rcx,S_SHIFT
	add	rcx,[g_sess_base]
	push	rdx
	mov	edx,[rcx+S_GEN]
	cmp	edx,[r12+H_H3CG]
	pop	rdx
	jne	.out
	test	dword [rcx+S_FLAGS],SF_QC
	jz	.out
	mov	r15d,eax
	shl	r15,HB_SHIFT
	add	r15,[g_hbuf_base]
	call	qe_ptr
	cmp	dword [rax+QE_CAP],0
	je	.out
	mov	[g_qe],rax
	mov	ecx,[rax+QE_KRC]
	mov	[g_qe_base],ecx
.out:
	pop	r15
	pop	rcx
	ret

; r8 = a request stream's entry, r15 = its connection: it may have something
; to send (QE_QSEND). Keeps all but rax.
qsend_set:
	push	rcx
	mov	rcx,r8
	sub	rcx,r15
	sub	rcx,QC_QST
	imul	ecx,ecx,683			; / QST_SIZE (96): exact for entries below 2048
	shr	ecx,16
	call	qe_ptr
	bts	[rax+QE_QSEND],rcx
	pop	rcx
	ret
assert QST_SIZE = 96 & QST_N <= 2048 & QE_QSEND + QST_W * 8 <= QE_HDR
; every request stream may (a loss, the connection's window). Keeps all but rax.
qsend_all:
	push	rcx
	call	qe_ptr
	push	rdx
	xor	edx,edx
@@:
	mov	rcx,[r15+QC_QREQ+rdx*8]
	mov	[rax+QE_QSEND+rdx*8],rcx
	inc	edx
	cmp	edx,QST_W
	jb	@b
	pop	rdx
	pop	rcx
	ret

; qp_encode, a field the static table has not whole: rdi = out, rsi = name,
; edx = its length, rcx = value, r8d = its length, r9d = its static name or
; -1. A field the table has and the client knows: its indexed line (rax = out
; after it). Not known yet: inserted when it is one that comes again and
; there is room, and CF (written as before). Keeps rbx, rbp, r12-r15.
qe_field:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	mov	rbp,rdi
	mov	r12,rsi
	mov	r13d,edx
	mov	r14,rcx
	mov	r15d,r8d
	mov	ebx,r9d
	lea	eax,[r13+r15]
	cmp	eax,QE_FIELD_MAX
	ja	.no
	mov	rdi,r12
	mov	esi,r13d
	lea	rdx,[ht_names]			; (those HTTP/2 indexes too)
	call	name_in
	jz	.no
	mov	r11,[g_qe]
	; in the table? the newest first: a field that changes (the date, each
	; second) is there once a value, its current one last
	mov	r10d,[r11+QE_INS]
.find:
	sub	r10d,1
	jb	.absent
	movzx	eax,word [r11+QE_ENT+r10*8+2]
	cmp	eax,r13d
	jne	.find_next
	movzx	eax,word [r11+QE_ENT+r10*8+4]
	cmp	eax,r15d
	jne	.find_next
	movzx	eax,word [r11+QE_ENT+r10*8]
	lea	rdi,[r11+QE_DATA+rax]
	mov	rsi,r12
	mov	edx,r13d
	push	r10
	push	r11
	call	mem_eq
	pop	r11
	pop	r10
	test	eax,eax
	jz	.find_next
	movzx	eax,word [r11+QE_ENT+r10*8]
	add	eax,r13d
	lea	rdi,[r11+QE_DATA+rax]
	mov	rsi,r14
	mov	edx,r15d
	push	r10
	push	r11
	call	mem_eq
	pop	r11
	pop	r10
	test	eax,eax
	jnz	.found
.find_next:
	jmp	.find
.found:
	cmp	r10d,[g_qe_base]
	jae	.no				; (inserted, the client has not said so yet)
	; indexed field line, dynamic (1 T=0, 6-bit relative index = base - 1 - it)
	lea	eax,[r10+1]
	cmp	eax,[g_qe_ric]
	jbe	@f
	mov	[g_qe_ric],eax
@@:
	mov	eax,[g_qe_base]
	sub	eax,r10d
	dec	eax
	mov	rdi,rbp
	mov	cl,6
	mov	dl,0x80
	call	hp_put_int
	mov	rax,rdi
	clc
	jmp	.out
.absent:
	; inserted, when there is room for it in the table, its bytes, the ring
	cmp	dword [r11+QE_INS],QE_EMAX
	jae	.no
	lea	eax,[r13+r15+32]
	add	eax,[r11+QE_USED]
	cmp	eax,[r11+QE_CAP]
	ja	.no
	lea	eax,[r13+r15]
	add	eax,[r11+QE_DUSED]
	cmp	eax,QE_DCAP
	ja	.no
	mov	rax,[r11+QE_END]
	sub	rax,[r11+QE_ACK]
	add	rax,QE_FIELD_MAX + 32
	cmp	rax,QE_RCAP
	ja	.no
	; the instruction, into g_qe_tmp, then the ring
	lea	rdi,[g_qe_tmp]
	cmp	dword [r11+QE_CAPSENT],0
	jne	.insert
	mov	byte [rdi],2			; the stream's type: QPACK encoder
	inc	rdi
	mov	eax,[r11+QE_CAP]		; Set Dynamic Table Capacity (001, 5 bits)
	mov	cl,5
	mov	dl,0x20
	call	hp_put_int
	mov	dword [r11+QE_CAPSENT],1
.insert:
	cmp	ebx,-1
	je	.literal_name
	mov	eax,ebx				; Insert With Name Reference, static (1 T=1)
	mov	cl,6
	mov	dl,0xC0
	call	hp_put_int
	jmp	.value
.literal_name:
	mov	eax,r13d			; Insert With Literal Name (01 H=0, 5 bits)
	mov	cl,5
	mov	dl,0x40
	call	hp_put_int
	mov	rsi,r12
	mov	ecx,r13d
	rep	movsb
.value:
	mov	r11,[g_qe]
	mov	rsi,r14
	mov	ecx,r15d
	call	hp_put_str
	mov	r11,[g_qe]
	lea	rcx,[g_qe_tmp]
	mov	r10,rdi
	sub	r10,rcx				; its length
	xor	r9d,r9d
.ring:
	cmp	r9,r10
	jae	.rung
	mov	rax,[r11+QE_END]
	and	eax,QE_RCAP - 1
	mov	cl,[g_qe_tmp+r9]
	mov	[r11+QE_RING+rax],cl
	inc	qword [r11+QE_END]
	inc	r9
	jmp	.ring
.rung:
	; the entry: its bytes kept, counted
	mov	eax,[r11+QE_INS]
	mov	ecx,[r11+QE_DUSED]
	mov	[r11+QE_ENT+rax*8],cx
	mov	[r11+QE_ENT+rax*8+2],r13w
	mov	[r11+QE_ENT+rax*8+4],r15w
	lea	rdi,[r11+QE_DATA+rcx]
	mov	rsi,r12
	mov	ecx,r13d
	rep	movsb
	mov	rsi,r14
	mov	ecx,r15d
	rep	movsb
	lea	eax,[r13+r15]
	add	[r11+QE_DUSED],eax
	add	eax,32
	add	[r11+QE_USED],eax
	inc	dword [r11+QE_INS]
.no:
	stc
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

; h3_head_out, the section written: rdi = its end, g_h3tmp+8 its start (two
; bytes kept there for the prefix). With references: Required Insert Count
; (encoded, RFC 9204 4.5.1.1) and Delta Base, the section moved when they
; take more than two bytes; rdi = its end. Keeps rbx, rsi, rbp, r12-r15.
qe_prefix:
	cmp	qword [g_qe],0
	je	.out
	mov	eax,[g_qe_ric]
	test	eax,eax
	jz	.out
	push	rsi
	push	rdi
	mov	r11,[g_qe]
	mov	ecx,[r11+QE_MAXE]
	add	ecx,ecx
	xor	edx,edx
	div	ecx
	lea	eax,[rdx+1]			; (RIC mod 2 MaxEntries) + 1
	lea	rdi,[g_qe_tmp]
	mov	cl,8
	xor	edx,edx
	call	hp_put_int
	mov	eax,[g_qe_base]			; Delta Base: base - RIC, sign 0
	sub	eax,[g_qe_ric]
	mov	cl,7
	xor	edx,edx
	call	hp_put_int
	lea	r8,[g_qe_tmp]
	mov	r9,rdi
	sub	r9,r8				; the prefix's length
	pop	rdi
	cmp	r9,2
	je	.in_place
	; longer: the fields move up (from the end: overlapping)
	lea	r10,[rdi+r9-2]			; the new end
	lea	rsi,[rdi-1]
	lea	rcx,[g_h3tmp+10]
	mov	rdx,rdi
	sub	rdx,rcx				; the fields' length
	lea	rdi,[rsi+r9-2]
	mov	rcx,rdx
	std
	rep	movsb
	cld
	mov	rdi,r10
.in_place:
	lea	rsi,[g_qe_tmp]
	lea	r8,[g_h3tmp+8]
	mov	ecx,r9d
@@:
	mov	al,[rsi]
	mov	[r8],al
	inc	rsi
	inc	r8
	dec	ecx
	jnz	@b
	pop	rsi
.out:
	ret

; qc_app_write (r15 = connection, rdi = out, r14 = the limit): our encoder
; stream's bytes not sent yet, as a STREAM frame (id 11), kept as one of the
; packet's frames past the first (QE_MARK). CF when it wrote one.
qe_write:
	call	qe_ptr
	mov	r11,rax
	mov	rax,[r11+QE_END]
	sub	rax,[r11+QE_SENT]
	jbe	.none
	mov	rcx,r14
	sub	rcx,rdi
	sub	rcx,1 + 1 + 8 + 2 + 16
	jle	.none
	cmp	dword [g_qfx_n],QFX_MAX		; (signed: -1 before the first frame)
	jge	.none
	cmp	rax,rcx
	jbe	@f
	mov	rax,rcx
@@:
	cmp	rax,16383			; (its length in 2 bytes)
	jbe	@f
	mov	eax,16383
@@:
	mov	r10,rax				; how many
	mov	byte [rdi],0x0E			; STREAM, OFF|LEN
	cmp	qword [r11+QE_SENT],0
	jne	@f
	mov	byte [rdi],0x0A			; (its first bytes: no offset)
@@:
	mov	byte [rdi+1],11
	add	rdi,2
	mov	rax,[r11+QE_SENT]
	test	rax,rax
	jz	@f
	call	qv_write
@@:
	mov	eax,r10d
	or	eax,0x4000
	xchg	al,ah
	mov	[rdi],ax
	add	rdi,2
	; its frame, for the packet's record
	cmp	dword [g_qfx_n],-1
	jne	@f
	mov	dword [g_qfx_n],0
@@:
	push	rdi
	mov	eax,SP_N
	call	qfx_slot
	mov	ecx,[g_qfx_n]
	imul	ecx,ecx,QFX_FR
	lea	rax,[rax+8+rcx]
	mov	dword [rax+QFX_SESS],QE_MARK
	mov	dword [rax+QFX_SGEN],0
	mov	dword [rax+QFX_FIN],0
	mov	rcx,[r11+QE_SENT]
	mov	[rax+QFX_OFF],rcx
	mov	[rax+QFX_LEN],r10d
	inc	dword [g_qfx_n]
	pop	rdi
	; the bytes, from the ring
	xor	ecx,ecx
@@:
	mov	rax,[r11+QE_SENT]
	add	rax,rcx
	and	eax,QE_RCAP - 1
	mov	dl,[r11+QE_RING+rax]
	mov	[rdi+rcx],dl
	inc	rcx
	cmp	rcx,r10
	jb	@b
	add	rdi,r10
	add	[r11+QE_SENT],r10
	stc
	ret
.none:
	clc
	ret

; qc_fr_acked / qc_fr_lost, a frame of our encoder stream (rdi = it -
; SP_SSESS, r15 = connection)
qe_acked:
	call	qe_ptr
	mov	rcx,[rdi+SP_SOFF]
	cmp	rcx,[rax+QE_ACK]
	ja	.out				; (past a gap: when it is sent again)
	mov	edx,[rdi+SP_SLEN]
	add	rcx,rdx
	cmp	rcx,[rax+QE_ACK]
	jbe	.out
	mov	[rax+QE_ACK],rcx
.out:
	ret
qe_lost:
	call	qe_ptr
	mov	rcx,[rax+QE_ACK]		; all of it not acknowledged goes again
	cmp	rcx,[rax+QE_SENT]
	jae	.out
	mov	[rax+QE_SENT],rcx
.out:
	ret
