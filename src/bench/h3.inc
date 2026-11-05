; okena bench proto=h3: a small HTTP/3 client, for load. One request at a
; time on each connection, a new bidirectional stream each.
;
; The handshake is blocking, before the clock starts (as TLS's): an Initial
; with the ClientHello (of src/tls/client.inc), the server's flight from
; CRYPTO frames, no certificate check, TLS_AES_128_GCM_SHA256 only, no Retry.
; After it, what the client keeps is little. Stream data goes by offset:
; data past what was had is not held, its whole packet is dropped unacknowledged
; and the server sends it again. An ACK names one range, the last run of
; packet numbers. A request lost on the way goes again after 200 ms; the
; status comes from the HEADERS frame's first field (no dynamic table: we
; announce none), and a Huffman-coded one counts as "other".

BQ_TXK		:= 0
BQ_RXK		:= BQ_TXK + QK_SIZE
BQ_DCID		:= BQ_RXK + QK_SIZE		; 20: the server's connection ID
BQ_DCIDL	:= BQ_DCID + 20			; d
BQ_ST		:= BQ_DCIDL + 4			; d: 0, 1 a frame's type, length; 2 its payload
BQ_PN		:= BQ_ST + 4			; q: our next packet number
BQ_RXL		:= BQ_PN + 8			; q: the largest received, -1 none
BQ_ACKH		:= BQ_RXL + 8			; q: the run to acknowledge: its top
BQ_ACKL		:= BQ_ACKH + 8			; q: and bottom
BQ_SID		:= BQ_ACKL + 8			; q: the next stream
BQ_CUR		:= BQ_SID + 8			; q: the stream in flight
BQ_RXO		:= BQ_CUR + 8			; q: its data had so far
BQ_FT		:= BQ_RXO + 8			; q: the frame being read: its type
BQ_FL		:= BQ_FT + 8			; q: its payload still to come
BQ_V		:= BQ_FL + 8			; q: a variable-length integer so far
BQ_VN		:= BQ_V + 8			; d: its bytes, 0 none begun
BQ_VG		:= BQ_VN + 4			; d: bytes had
BQ_HDN		:= BQ_VG + 4			; d: of HEADERS' payload, in BQ_HD
BQ_HDW		:= BQ_HDN + 4			; d: wanted there
BQ_HD		:= BQ_HDW + 4			; 8
BQ_NEEDACK	:= BQ_HD + 8			; d
BQ_DONE		:= BQ_NEEDACK + 4		; d: HANDSHAKE_DONE came
BQ_FIN		:= BQ_DONE + 4			; d: the stream's end came
BQ_BAD		:= BQ_FIN + 4			; d: reset, or the connection closed
BQ_RECV		:= BQ_BAD + 4			; q: stream bytes received
BQ_CREDIT	:= BQ_RECV + 8			; q: MAX_DATA given
BQ_RESENT	:= BQ_CREDIT + 8		; q: when the request last went
BQ_END		:= BQ_RESENT + 8
assert BQ_END <= BC_CCAP
BC_Q		:= BC_CBUF			; (https's new=on only otherwise)

BQ_WINDOW	:= 1 shl 30
BQ_REQ_CAP	:= 1100
BQ_TRIES	:= 25				; of 200 ms, the handshake

bss
	g_b_h3		dd ?			; proto=h3
	g_bq_reqlen	dd ?
	g_bq_chlen	dd ?
	g_bq_have	rd 2			; CRYPTO bytes had, Initial and Handshake
	g_bq_pn		rd 2			; our packet numbers there
	g_bq_ack	rd 2			; something to acknowledge there
	g_bq_keys	dd ?			; handshake keys in
	g_bq_fin	dd ?			; our Finished sent
	g_bq_flight	dd ?			; bytes of the server's flight, whole
	align 8
	g_bq_lg		rq 2			; largest received there
	g_bq_next	dq ?			; bench_h3_sweep: next look
	g_bq_ms200	dq ?			; 200 ms in ticks
	g_bq_scid	rb 8
	g_bq_ikc	rb QK_SIZE
	g_bq_iks	rb QK_SIZE
	g_bq_hkc	rb QK_SIZE
	g_bq_hks	rb QK_SIZE
	g_bq_req	rb BQ_REQ_CAP
	g_bq_cr0	rb 4096			; CRYPTO data, Initial
	g_bq_cr1	rb 16384		; Handshake
	g_bq_rec	rb 4096 + 5
	g_bq_scr	rb 2048
	g_bq_pl		rb 2048
	g_bq_tx		rb 2048
	g_bq_rx		rb 65536
end bss

; ---------------------------------------------------------------- the request

; the request's frames, once (bench_parse's checks done). CF: too long.
bench_h3_block:
	push	r12
	push	r13
	lea	rdi,[g_bq_scr]
	mov	word [rdi],0			; required insert count, base
	add	rdi,2
	mov	rcx,[g_b_method]
	cmp	qword [g_b_methodlen],3
	jne	.other
	cmp	word [rcx],'GE'
	jne	.other
	cmp	byte [rcx+2],'T'
	jne	.other
	mov	byte [rdi],0xD1			; :method GET
	inc	rdi
	jmp	.scheme
.other:
	mov	word [rdi],0x005F		; :method, a value of its own
	add	rdi,2
	mov	rsi,[g_b_method]
	mov	rcx,[g_b_methodlen]
	call	.str
.scheme:
	mov	byte [rdi],0xD7			; :scheme https
	mov	byte [rdi+1],0x50		; :authority
	add	rdi,2
	mov	rsi,[g_b_auth]
	mov	rcx,[g_b_authlen]
	call	.str
	mov	byte [rdi],0x51			; :path
	inc	rdi
	mov	rsi,[g_b_path]
	mov	rcx,[g_b_pathlen]
	call	.str
	xor	r12d,r12d
.hdr:
	cmp	r12d,[g_b_nhdr]
	jae	.frames
	mov	r13,[g_b_hdr+r12*8]		; "Name: value", lower-cased name
	inc	r12d
	xor	edx,edx
.name:
	mov	al,[r13+rdx]
	test	al,al
	jz	.hdr				; no colon: skipped
	cmp	al,':'
	je	.named
	cmp	al,'A'
	jb	.lower
	cmp	al,'Z'
	ja	.lower
	or	byte [r13+rdx],0x20
.lower:
	inc	edx
	jmp	.name
.named:
	cmp	edx,7				; a literal name, 3 bits of length
	jae	.long_name
	lea	eax,[rdx+0x20]
	stosb
	jmp	.name_bytes
.long_name:
	mov	byte [rdi],0x27
	lea	eax,[rdx-7]
	cmp	eax,127
	jae	.toolong
	mov	[rdi+1],al
	add	rdi,2
.name_bytes:
	mov	rsi,r13
	mov	ecx,edx
	rep	movsb
	lea	rsi,[r13+rdx+1]
.spaces:
	cmp	byte [rsi],' '
	jne	.value
	inc	rsi
	jmp	.spaces
.value:
	xor	ecx,ecx
@@:
	cmp	byte [rsi+rcx],0
	je	@f
	inc	ecx
	jmp	@b
@@:
	call	.str
	jmp	.hdr
.frames:
	; HEADERS, the block, DATA and the body
	lea	rcx,[g_bq_scr]
	sub	rdi,rcx
	mov	r12,rdi				; the block's length
	lea	rax,[r12+8]
	add	rax,[g_b_bodylen]
	cmp	rax,BQ_REQ_CAP
	ja	.toolong
	lea	rdi,[g_bq_req]
	mov	byte [rdi],1
	mov	eax,r12d
	or	eax,0x4000
	xchg	al,ah
	mov	[rdi+1],ax
	add	rdi,3
	lea	rsi,[g_bq_scr]
	mov	rcx,r12
	rep	movsb
	cmp	qword [g_b_body],0
	je	.whole
	mov	byte [rdi],0
	mov	rax,[g_b_bodylen]
	or	eax,0x4000
	xchg	al,ah
	mov	[rdi+1],ax
	add	rdi,3
	mov	rsi,[g_b_body]
	mov	rcx,[g_b_bodylen]
	rep	movsb
.whole:
	lea	rcx,[g_bq_req]
	sub	rdi,rcx
	mov	[g_bq_reqlen],edi
	clc
	jmp	.out
.toolong:
	stc
.out:
	pop	r13
	pop	r12
	ret
; rsi = a string, rcx its length: QPACK's, 7 bits of length, no Huffman.
.str:
	cmp	rcx,127
	jae	.str_long
	mov	al,cl
	stosb
	rep	movsb
	ret
.str_long:
	mov	byte [rdi],0x7F
	inc	rdi
	mov	rax,rcx
	sub	rax,127
@@:
	cmp	rax,128
	jb	@f
	mov	dl,al
	or	dl,0x80
	mov	[rdi],dl
	inc	rdi
	shr	rax,7
	jmp	@b
@@:
	stosb
	rep	movsb
	ret

; ---------------------------------------------------------------- packets

; rdi = where, rax = a value below 2^30: its four bytes. rdi advanced.
macro bq_v4
	bswap	eax
	or	eax,0x80
	stosd
end macro

; rbx = connection, edx = the payload's length in g_bq_pl: a 1-RTT packet.
; Keeps r12-r15.
bench_h3_out:
	lea	rdi,[g_bq_tx]
	mov	byte [rdi],0x43			; short, 4 bytes of packet number
	inc	rdi
	lea	rsi,[rbx+BC_Q+BQ_DCID]
	mov	ecx,[rbx+BC_Q+BQ_DCIDL]
	rep	movsb
	mov	rax,[rbx+BC_Q+BQ_PN]
	inc	qword [rbx+BC_Q+BQ_PN]
	mov	r8,rax
	bswap	eax
	stosd
	lea	rsi,[g_bq_pl]
	mov	r9d,edx
	mov	ecx,edx
	rep	movsb
	lea	rsi,[g_bq_tx]
	mov	edx,[rbx+BC_Q+BQ_DCIDL]
	add	edx,5
	lea	rdi,[rbx+BC_Q+BQ_TXK]
	mov	ecx,4
	call	quic_seal
	mov	edx,eax
; edx = bytes in g_bq_tx: they go
bench_h3_tx:
	mov	edi,[rbx+BC_FD]
	lea	rsi,[g_bq_tx]
	mov	r10d,MSG_DONTWAIT
	xor	r8d,r8d
	xor	r9d,r9d
	mov	eax,SYS_sendto
	syscall
	ret

; rbx = connection: what the last packets ask: an ACK, MAX_DATA
bench_h3_flush:
	cmp	dword [rbx+BC_Q+BQ_NEEDACK],0
	je	.out
	mov	dword [rbx+BC_Q+BQ_NEEDACK],0
	lea	rdi,[g_bq_pl]
	mov	byte [rdi],2
	inc	rdi
	mov	rax,[rbx+BC_Q+BQ_ACKH]
	bq_v4
	mov	word [rdi],0			; no delay, no more ranges
	add	rdi,2
	mov	rax,[rbx+BC_Q+BQ_ACKH]
	sub	rax,[rbx+BC_Q+BQ_ACKL]
	bq_v4
	mov	rax,[rbx+BC_Q+BQ_RECV]
	add	rax,BQ_WINDOW / 2
	cmp	rax,[rbx+BC_Q+BQ_CREDIT]
	jb	.sent
	add	qword [rbx+BC_Q+BQ_CREDIT],BQ_WINDOW
	mov	byte [rdi],0x10			; MAX_DATA
	inc	rdi
	mov	rax,[rbx+BC_Q+BQ_CREDIT]
	bswap	rax
	or	al,0xC0
	stosq
.sent:
	lea	rdx,[g_bq_pl]
	sub	rdi,rdx
	mov	edx,edi
	jmp	bench_h3_out
.out:
	ret

; rbx = connection: its request, on the stream in flight
bench_h3_request:
	lea	rdi,[g_bq_pl]
	mov	byte [rdi],0x0B			; STREAM, a length, FIN
	inc	rdi
	mov	rax,[rbx+BC_Q+BQ_CUR]
	bq_v4
	mov	eax,[g_bq_reqlen]
	or	eax,0x4000
	xchg	al,ah
	stosw
	lea	rsi,[g_bq_req]
	mov	ecx,[g_bq_reqlen]
	rep	movsb
	lea	rdx,[g_bq_pl]
	sub	rdi,rdx
	mov	edx,edi
	jmp	bench_h3_out

; rbx = connection, rax = now (the common part done by bench_send)
bench_h3_send:
	mov	[rbx+BC_Q+BQ_RESENT],rax
	mov	rax,[rbx+BC_Q+BQ_SID]
	mov	[rbx+BC_Q+BQ_CUR],rax
	add	qword [rbx+BC_Q+BQ_SID],4
	xor	eax,eax
	mov	[rbx+BC_Q+BQ_RXO],rax
	mov	[rbx+BC_Q+BQ_ST],eax
	mov	[rbx+BC_Q+BQ_VN],eax
	mov	[rbx+BC_Q+BQ_FIN],eax
	call	bench_h3_request
	cmp	rax,-EAGAIN			; (the sweep sends it again)
	je	@f
	test	rax,rax
	js	bench_fail
@@:
	mov	eax,[g_b_reqlen]
	mov	[rbx+BC_SOFF],eax
	ret

; from the loop, often: requests not answered go again. Keeps r12-r15.
bench_h3_sweep:
	bench_now
	cmp	rax,[g_bq_next]
	jb	.out
	mov	rdx,[g_bq_ms200]
	lea	rcx,[rax+rdx]
	mov	[g_bq_next],rcx
	push	rbx
	push	r12
	push	r13
	mov	r13,rax
	mov	rbx,[g_b_conn]
	mov	r12d,[g_b_nc]
.next:
	test	r12d,r12d
	jz	.done
	dec	r12d
	cmp	dword [rbx+BC_STATE],BCS_FLIGHT
	jne	.skip
	cmp	qword [rbx+BC_Q+BQ_RXO],0
	jne	.skip
	mov	rax,r13
	sub	rax,[rbx+BC_Q+BQ_RESENT]
	cmp	rax,[g_bq_ms200]
	jb	.skip
	mov	[rbx+BC_Q+BQ_RESENT],r13
	call	bench_h3_request
.skip:
	add	rbx,BC_SIZE
	jmp	.next
.done:
	pop	r13
	pop	r12
	pop	rbx
.out:
	ret

; ---------------------------------------------------------------- reading

; rbx = connection, r8 = stream bytes, r9 = how many: HEADERS' status, the
; rest counted through. Keeps r12-r15.
bench_h3_feed:
.next:
	test	r9,r9
	jz	.out
	cmp	dword [rbx+BC_Q+BQ_ST],2
	je	.payload
	movzx	eax,byte [r8]
	inc	r8
	dec	r9
	cmp	dword [rbx+BC_Q+BQ_VN],0
	jne	.more
	mov	ecx,eax				; the first byte: its top two bits
	shr	ecx,6
	mov	edx,1
	shl	edx,cl
	mov	[rbx+BC_Q+BQ_VN],edx
	mov	dword [rbx+BC_Q+BQ_VG],1
	and	eax,0x3F
	mov	[rbx+BC_Q+BQ_V],rax
	jmp	.got
.more:
	mov	rcx,[rbx+BC_Q+BQ_V]
	shl	rcx,8
	or	rax,rcx
	mov	[rbx+BC_Q+BQ_V],rax
	inc	dword [rbx+BC_Q+BQ_VG]
.got:
	mov	eax,[rbx+BC_Q+BQ_VG]
	cmp	eax,[rbx+BC_Q+BQ_VN]
	jb	.next
	mov	dword [rbx+BC_Q+BQ_VN],0
	mov	rax,[rbx+BC_Q+BQ_V]
	cmp	dword [rbx+BC_Q+BQ_ST],0
	jne	.length
	mov	[rbx+BC_Q+BQ_FT],rax
	mov	dword [rbx+BC_Q+BQ_ST],1
	jmp	.next
.length:
	mov	[rbx+BC_Q+BQ_FL],rax
	mov	dword [rbx+BC_Q+BQ_HDN],0
	mov	ecx,8
	cmp	rax,8
	cmovb	ecx,eax
	mov	[rbx+BC_Q+BQ_HDW],ecx
	mov	dword [rbx+BC_Q+BQ_ST],2
	test	rax,rax
	jnz	.next
	mov	dword [rbx+BC_Q+BQ_ST],0
	jmp	.next
.payload:
	cmp	qword [rbx+BC_Q+BQ_FT],1
	jne	.skim
	mov	eax,[rbx+BC_Q+BQ_HDN]
	cmp	eax,[rbx+BC_Q+BQ_HDW]
	jae	.skim
	movzx	ecx,byte [r8]			; the block's first bytes
	inc	r8
	dec	r9
	mov	[rbx+BC_Q+BQ_HD+rax],cl
	inc	eax
	mov	[rbx+BC_Q+BQ_HDN],eax
	dec	qword [rbx+BC_Q+BQ_FL]
	cmp	eax,[rbx+BC_Q+BQ_HDW]
	jb	.fl
	call	.status
.fl:
	cmp	qword [rbx+BC_Q+BQ_FL],0
	jne	.next
	mov	dword [rbx+BC_Q+BQ_ST],0
	jmp	.next
.skim:
	mov	rax,[rbx+BC_Q+BQ_FL]
	cmp	rax,r9
	cmova	rax,r9
	add	r8,rax
	sub	r9,rax
	sub	[rbx+BC_Q+BQ_FL],rax
	jmp	.fl
.out:
	ret
; BQ_HD: required insert count, base, the first field line
.status:
	cmp	dword [rbx+BC_STATUS],0
	jne	.st_out
	movzx	eax,byte [rbx+BC_Q+BQ_HD+2]
	mov	ecx,eax
	and	ecx,0xC0
	cmp	ecx,0xC0
	jne	.literal
	and	eax,0x3F
	cmp	eax,63
	jne	@f
	movzx	ecx,byte [rbx+BC_Q+BQ_HD+3]	; (6 bits of index, then more)
	add	eax,ecx
@@:
	sub	eax,24
	cmp	eax,48
	jae	.st_out
	movzx	eax,word [.static+rax*2]
	mov	[rbx+BC_STATUS],eax
	ret
.literal:
	cmp	eax,0x5F			; a static name past 15, the 3-digit value
	jne	.st_out
	cmp	byte [rbx+BC_Q+BQ_HD+4],3
	jne	.st_out
	xor	ecx,ecx
	xor	eax,eax
@@:
	imul	eax,eax,10
	movzx	edx,byte [rbx+BC_Q+BQ_HD+5+rcx]
	sub	edx,'0'
	cmp	edx,9
	ja	.st_out
	add	eax,edx
	inc	ecx
	cmp	ecx,3
	jb	@b
	mov	[rbx+BC_STATUS],eax
.st_out:
	ret
.static	dw 103,200,304,404,503			; RFC 9204's static table: 24-28
	dw 34 dup 0				; 29-62: not :status
	dw 100,204,206,302,400,403,421,425,500	; 63-71

; rax = the ACK frame's type, rsi past it, rdx its packet's end: past the frame.
; CF: it does not fit.
bench_h3_skip_ack:
	push	r12
	mov	r12d,eax
	call	qv_read				; largest
	jc	.out
	call	qv_read				; delay
	jc	.out
	call	qv_read				; ranges
	jc	.out
	push	rax
	call	qv_read				; the first
	pop	rcx
	jc	.out
	push	rcx
.range:
	mov	rax,[rsp]
	test	rax,rax
	jz	.ecn
	dec	qword [rsp]
	call	qv_read
	jc	.pop
	call	qv_read
	jc	.pop
	jmp	.range
.ecn:
	pop	rcx
	cmp	r12d,3
	jne	.ok
	call	qv_read
	jc	.out
	call	qv_read
	jc	.out
	call	qv_read
	jmp	.out
.pop:
	pop	rcx
	stc
	jmp	.out
.ok:
	clc
.out:
	pop	r12
	ret

; rbx = connection, rsi = a datagram, edx = its length: a 1-RTT packet.
; Keeps r12-r15.
bench_h3_packet:
	push	r12
	push	r13
	push	r14
	mov	r12,rsi
	lea	rdi,[rbx+BC_Q+BQ_RXK]
	mov	ecx,9				; (our connection ID: 8)
	mov	r8,[rbx+BC_Q+BQ_RXL]
	call	quic_open
	cmp	eax,-1
	je	.out
	mov	r13,rdx				; the packet number
	mov	ecx,eax
	movzx	edx,byte [r12]
	and	edx,3
	lea	rsi,[r12+10+rdx]		; the payload
	lea	rdx,[rsi+rcx]
.frame:
	cmp	rsi,rdx
	jae	.whole
	call	qv_read
	jc	.whole
	cmp	rax,0
	je	.frame
	cmp	rax,1
	je	.frame
	cmp	rax,2
	je	.ack
	cmp	rax,3
	je	.ack
	mov	rcx,rax
	and	rcx,not 7
	cmp	rcx,8
	je	.stream
	cmp	rax,6
	je	.crypto
	cmp	rax,4
	je	.reset
	cmp	rax,5
	je	.two
	cmp	rax,7
	je	.bytes
	cmp	rax,0x10
	je	.one
	cmp	rax,0x11
	je	.two
	cmp	rax,0x15
	je	.two
	cmp	rax,0x18
	je	.ncid
	cmp	rax,0x1A
	je	.eight
	cmp	rax,0x1B
	je	.eight
	cmp	rax,0x1C
	je	.closed
	cmp	rax,0x1D
	je	.closed
	cmp	rax,0x1E
	je	.done
	cmp	rax,0x19
	jbe	.one				; MAX_STREAMS, the *_BLOCKED, RETIRE
	jmp	.closed				; nothing we know
.ack:
	call	bench_h3_skip_ack
	jc	.whole
	jmp	.frame
.done:
	mov	dword [rbx+BC_Q+BQ_DONE],1
	jmp	.frame
.eight:
	add	rsi,8
	jmp	.frame
.ncid:
	call	qv_read
	call	qv_read
	cmp	rsi,rdx
	jae	.whole
	movzx	eax,byte [rsi]
	lea	rsi,[rsi+rax+1+16]
	jmp	.frame
.crypto:
	call	qv_read				; (session tickets: not kept)
	jc	.whole
.bytes:
	call	qv_read
	jc	.whole
	add	rsi,rax
	jmp	.frame
.two:
	call	qv_read
	jc	.whole
.one:
	call	qv_read
	jc	.whole
	jmp	.frame
.reset:
	call	qv_read
	jc	.whole
	cmp	rax,[rbx+BC_Q+BQ_CUR]
	jne	.reset_rest
	mov	dword [rbx+BC_Q+BQ_BAD],1
.reset_rest:
	call	qv_read
	jc	.whole
	call	qv_read
	jc	.whole
	jmp	.frame
.closed:
	mov	dword [rbx+BC_Q+BQ_BAD],1
	jmp	.whole
.stream:
	mov	r14d,eax			; flags: OFF 4, LEN 2, FIN 1
	call	qv_read				; id
	jc	.whole
	mov	r9,rax
	xor	r8d,r8d
	test	r14d,4
	jz	@f
	push	r9
	call	qv_read
	pop	r9
	jc	.whole
	mov	r8,rax
@@:
	mov	rcx,rdx
	sub	rcx,rsi
	test	r14d,2
	jz	@f
	push	r8
	push	r9
	call	qv_read
	pop	r9
	pop	r8
	jc	.whole
	mov	rcx,rax
@@:
	lea	rax,[rsi+rcx]
	cmp	rax,rdx
	ja	.whole
	cmp	r9,[rbx+BC_Q+BQ_CUR]
	je	.ours
	mov	rsi,rax				; (the server's streams: not read)
	jmp	.frame
.ours:
	mov	r10,rax				; past it
	mov	rax,[rbx+BC_Q+BQ_RXO]
	cmp	r8,rax
	ja	.out				; a gap: dropped, not acknowledged
	sub	rax,r8				; what we had of it
	cmp	rax,rcx
	jbe	@f
	mov	rax,rcx
@@:
	add	rsi,rax
	sub	rcx,rax
	mov	r8,rsi
	mov	r9,rcx
	add	[rbx+BC_Q+BQ_RXO],rcx
	add	[rbx+BC_Q+BQ_RECV],rcx
	push	rdx
	push	r10
	call	bench_h3_feed
	pop	rsi
	pop	rdx
	test	r14d,1
	jz	.frame
	mov	dword [rbx+BC_Q+BQ_FIN],1
	jmp	.frame
.whole:
	cmp	r13,[rbx+BC_Q+BQ_RXL]
	jle	@f
	mov	[rbx+BC_Q+BQ_RXL],r13
@@:
	mov	rax,[rbx+BC_Q+BQ_ACKH]
	inc	rax
	cmp	rax,r13
	je	@f
	mov	[rbx+BC_Q+BQ_ACKL],r13
@@:
	mov	[rbx+BC_Q+BQ_ACKH],r13
	mov	dword [rbx+BC_Q+BQ_NEEDACK],1
.out:
	pop	r14
	pop	r13
	pop	r12
	ret

; rbx = connection, readable
bench_h3_readable:
	push	r12
	xor	r12d,r12d
.read:
	mov	edi,[rbx+BC_FD]
	lea	rsi,[g_bq_rx]
	mov	edx,65536
	mov	r10d,MSG_DONTWAIT
	xor	r8d,r8d
	xor	r9d,r9d
	mov	eax,SYS_recvfrom
	syscall
	cmp	rax,-EAGAIN
	je	.drained
	test	rax,rax
	js	.failed
	jz	.drained
	test	byte [g_bq_rx],0x80
	jnz	.read				; long: a handshake's stragglers
	lea	rsi,[g_bq_rx]
	mov	edx,eax
	call	bench_h3_packet
	inc	r12d
	test	r12d,31
	jnz	.read
	call	bench_h3_flush
	jmp	.read
.drained:
	call	bench_h3_flush
	pop	r12
	cmp	dword [rbx+BC_Q+BQ_BAD],0
	jne	bench_fail
	cmp	dword [rbx+BC_Q+BQ_FIN],0
	je	.ret
	mov	dword [rbx+BC_Q+BQ_FIN],0
	cmp	dword [rbx+BC_STATE],BCS_FLIGHT
	je	bench_complete
.ret:
	ret
.failed:
	pop	r12
	jmp	bench_fail

; ---------------------------------------------------------------- handshake

; r8d = 0 Initial, 1 Handshake, edx = the payload's length in g_bq_pl: a
; packet in a datagram of its own, an Initial filling 1200 bytes.
bench_h3_long:
	lea	rdi,[g_bq_tx]
	mov	eax,0xC3
	test	r8d,r8d
	jz	@f
	mov	eax,0xE3
@@:
	stosb
	mov	eax,0x01000000			; version 1
	stosd
	mov	eax,[rbx+BC_Q+BQ_DCIDL]
	stosb
	lea	rsi,[rbx+BC_Q+BQ_DCID]
	mov	ecx,eax
	rep	movsb
	mov	al,8
	stosb
	lea	rsi,[g_bq_scid]
	movsq
	test	r8d,r8d
	jnz	@f
	mov	al,0				; no token
	stosb
	lea	rax,[g_bq_tx]
	mov	rcx,rdi
	sub	rcx,rax
	mov	eax,1200 - 2 - 4 - 16		; the room to 1200
	sub	eax,ecx
	cmp	edx,eax
	jae	@f
	push	rdi
	lea	rdi,[g_bq_pl+rdx]		; PADDING
	mov	ecx,eax
	sub	ecx,edx
	mov	edx,eax
	xor	eax,eax
	rep	stosb
	pop	rdi
@@:
	lea	eax,[rdx+4+16]
	or	eax,0x4000
	xchg	al,ah
	stosw
	mov	eax,[g_bq_pn+r8*4]
	inc	dword [g_bq_pn+r8*4]
	push	r8
	mov	r9d,edx
	mov	r10d,eax
	bswap	eax
	stosd
	lea	rsi,[g_bq_pl]
	mov	ecx,edx
	rep	movsb
	lea	rdx,[g_bq_tx]
	sub	rdi,rdx
	lea	rax,[r9+0]
	sub	rdi,rax
	mov	edx,edi				; the header
	pop	rax
	mov	r8d,r10d
	lea	rdi,[g_bq_ikc]
	test	eax,eax
	jz	@f
	lea	rdi,[g_bq_hkc]
@@:
	lea	rsi,[g_bq_tx]
	mov	ecx,4
	call	quic_seal
	mov	edx,eax
	jmp	bench_h3_tx

; the ClientHello, in Initials
bench_h3_hello:
	push	r12
	xor	r12d,r12d
.next:
	mov	eax,[g_bq_chlen]
	sub	eax,r12d
	jbe	.out
	cmp	eax,1100
	jbe	@f
	mov	eax,1100
@@:
	lea	rdi,[g_bq_pl]
	mov	byte [rdi],6
	inc	rdi
	mov	edx,eax
	mov	eax,r12d
	bq_v4
	mov	eax,edx
	bq_v4
	lea	rsi,[g_b_hout+5+r12]
	mov	ecx,edx
	add	r12d,edx
	rep	movsb
	lea	rdx,[g_bq_pl]
	sub	rdi,rdx
	mov	edx,edi
	xor	r8d,r8d
	call	bench_h3_long
	jmp	.next
.out:
	pop	r12
	ret

; an ACK of the largest received at level r8d
bench_h3_long_ack:
	mov	dword [g_bq_ack+r8*4],0
	lea	rdi,[g_bq_pl]
	mov	byte [rdi],2
	inc	rdi
	mov	rax,[g_bq_lg+r8*8]
	bq_v4
	mov	dword [rdi],0			; no delay, one range, of one
	add	rdi,2
	xor	eax,eax
	stosb
	lea	rdx,[g_bq_pl]
	sub	rdi,rdx
	mov	edx,edi
	jmp	bench_h3_long

; our Finished, and the first 1-RTT: our HTTP/3 control stream
bench_h3_finished:
	lea	rdi,[g_bq_pl]
	mov	byte [rdi],6
	mov	byte [rdi+1],0			; offset 0
	mov	byte [rdi+2],36
	mov	dword [rdi+3],0x20000014
	lea	rdi,[rdi+7]
	lea	rsi,[g_b_tc+TC_FIN]
	mov	ecx,32
	rep	movsb
	mov	edx,39
	mov	r8d,1
	call	bench_h3_long
	lea	rdi,[g_bq_pl]
	mov	dword [rdi],0x03020A		; STREAM 2, length 3:
	mov	dword [rdi+3],0x000400		; control, SETTINGS, empty
	mov	edx,6
	jmp	bench_h3_out

; the server's flight whole? g_bq_flight = its bytes.
bench_h3_flight:
	xor	eax,eax
.next:
	lea	ecx,[rax+4]
	cmp	ecx,[g_bq_have+4]
	ja	.no
	mov	edx,dword [g_bq_cr1+rax]
	bswap	edx
	mov	r8d,edx
	shr	r8d,24				; its type
	and	edx,0xFFFFFF
	add	ecx,edx
	cmp	ecx,[g_bq_have+4]
	ja	.no
	mov	eax,ecx
	cmp	r8d,20
	jne	.next
	mov	[g_bq_flight],eax
	mov	eax,1
	ret
.no:
	xor	eax,eax
	ret

; r13 = level, rsi = frames, rdx = their end, of a long packet. CF: closed.
bench_h3_hs_frames:
.frame:
	cmp	rsi,rdx
	jae	.done
	call	qv_read
	jc	.done
	cmp	rax,0
	je	.frame
	cmp	rax,1
	je	.frame
	cmp	rax,2
	je	.ack
	cmp	rax,3
	je	.ack
	cmp	rax,6
	je	.crypto
	stc					; CONNECTION_CLOSE, or nothing we know
	ret
.ack:
	call	bench_h3_skip_ack
	jc	.done
	jmp	.frame
.crypto:
	call	qv_read
	jc	.done
	mov	r8,rax
	call	qv_read
	jc	.done
	mov	rcx,rax
	lea	rax,[rsi+rcx]
	cmp	rax,rdx
	ja	.done
	mov	r9,rax				; past it
	cmp	r8d,[g_bq_have+r13*4]
	ja	.past
	lea	rax,[r8+rcx]
	lea	rdi,[g_bq_cr0+r8]
	cmp	eax,4096
	ja	.past
	test	r13d,r13d
	jz	@f
	cmp	eax,16384
	ja	.past
	lea	rdi,[g_bq_cr1+r8]
@@:
	cmp	eax,[g_bq_have+r13*4]
	jbe	@f
	mov	[g_bq_have+r13*4],eax
@@:
	rep	movsb
.past:
	mov	rsi,r9
	jmp	.frame
.done:
	clc
	ret

; rbx = connection, g_bq_cr0 has the ServerHello whole? The handshake's keys.
; CF: a bad one.
bench_h3_server_hello:
	cmp	dword [g_bq_keys],0
	jne	.ok
	cmp	dword [g_bq_have],4
	jb	.ok
	mov	eax,dword [g_bq_cr0]
	bswap	eax
	and	eax,0xFFFFFF
	add	eax,4
	cmp	eax,[g_bq_have]
	ja	.ok
	lea	rdi,[g_bq_rec]
	mov	dword [rdi],0x00030316
	mov	edx,eax
	xchg	al,ah
	mov	[rdi+3],ax
	add	rdi,5
	lea	rsi,[g_bq_cr0]
	mov	ecx,edx
	rep	movsb
	lea	rdi,[g_b_tc]
	lea	rsi,[g_bq_rec]
	add	edx,5
	lea	rcx,[g_bq_scr]
	call	tlsc_server_flight
	test	eax,eax
	jz	.bad
	lea	rdi,[g_bq_hkc]
	lea	rsi,[g_b_tc+TC_CHT]
	mov	edx,QUIC_V1
	xor	ecx,ecx
	call	quic_keys
	lea	rdi,[g_bq_hks]
	lea	rsi,[g_b_tc+TC_SHT]
	mov	edx,QUIC_V1
	xor	ecx,ecx
	call	quic_keys
	mov	dword [g_bq_keys],1
.ok:
	clc
	ret
.bad:
	stc
	ret

; rbx = connection, r12 = a datagram, r14 = its end. CF: the connection failed.
bench_h3_hs_datagram:
	push	r13
	push	r15
.packet:
	cmp	r12,r14
	jae	.ok
	mov	al,[r12]
	test	al,0x80
	jz	.short
	cmp	dword [r12+1],0x01000000
	jne	.ok
	xor	r13d,r13d
	mov	ecx,eax
	and	ecx,0x30
	jz	.level
	inc	r13d
	cmp	ecx,0x20
	jne	.ok				; (0-RTT, Retry: not for this client)
	cmp	dword [g_bq_keys],0
	je	.ok
.level:
	movzx	eax,byte [r12+5]
	lea	rsi,[r12+6+rax]			; past their idea of our ID
	lea	rax,[r14-1]
	cmp	rsi,rax
	jae	.ok
	movzx	ecx,byte [rsi]
	cmp	ecx,20
	ja	.ok
	mov	[rbx+BC_Q+BQ_DCIDL],ecx
	inc	rsi
	lea	rdi,[rbx+BC_Q+BQ_DCID]
	rep	movsb
	mov	rdx,r14
	test	r13d,r13d
	jnz	.length
	call	qv_read				; a token: past it
	jc	.ok
	add	rsi,rax
.length:
	call	qv_read
	jc	.ok
	mov	rcx,rsi
	sub	rcx,r12				; where the packet number starts
	lea	r15,[rsi+rax]			; the packet's end
	cmp	r15,r14
	ja	.ok
	lea	rdi,[g_bq_iks]
	test	r13d,r13d
	jz	@f
	lea	rdi,[g_bq_hks]
@@:
	mov	rsi,r12
	mov	rdx,r15
	sub	rdx,r12
	mov	r8,[g_bq_lg+r13*8]
	push	rcx
	call	quic_open
	pop	rcx
	cmp	eax,-1
	je	.next
	mov	[g_bq_lg+r13*8],rdx
	mov	dword [g_bq_ack+r13*4],1
	movzx	edx,byte [r12]
	and	edx,3
	lea	rsi,[r12+rcx+1]
	add	rsi,rdx
	mov	edx,eax
	add	rdx,rsi
	call	bench_h3_hs_frames
	jc	.bad
	test	r13d,r13d
	jnz	.next
	call	bench_h3_server_hello
	jc	.bad
.next:
	mov	r12,r15
	jmp	.packet
.short:
	cmp	dword [g_bq_fin],0
	je	.ok
	mov	rsi,r12
	mov	rdx,r14
	sub	rdx,r12
	call	bench_h3_packet
.ok:
	clc
	jmp	.out
.bad:
	stc
.out:
	pop	r15
	pop	r13
	ret

; rbx = connection, its socket connected: the handshake. eax = 1, or 0.
bench_h3_connect:
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,24
	mov	eax,200000
	call	bench_us_ticks
	mov	[g_bq_ms200],rax
	; our state
	lea	rdi,[rbx+BC_Q]
	mov	ecx,BQ_END
	xor	eax,eax
	rep	stosb
	mov	qword [rbx+BC_Q+BQ_RXL],-1
	mov	qword [rbx+BC_Q+BQ_ACKH],-2
	mov	qword [rbx+BC_Q+BQ_CREDIT],BQ_WINDOW
	mov	dword [rbx+BC_Q+BQ_DCIDL],8
	lea	rdi,[g_bq_have]
	mov	ecx,(g_bq_flight + 4 - g_bq_have) / 4
	xor	eax,eax
	rep	stosd
	mov	qword [g_bq_lg],-1
	mov	qword [g_bq_lg+8],-1
	; connection IDs, the Initial keys, the ClientHello
	lea	rdi,[rbx+BC_Q+BQ_DCID]
	mov	esi,8
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	lea	rdi,[g_bq_scid]
	mov	esi,8
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	lea	rdi,[g_tlsc_qtp + .tp_len]
	lea	rsi,[g_bq_scid]
	movsq
	lea	rdi,[g_tlsc_qtp]
	lea	rsi,[.tp]
	mov	ecx,.tp_len
	rep	movsb
	mov	dword [g_tlsc_qtplen],.tp_len + 8
	mov	dword [g_tlsc_quic],1
	lea	rdi,[g_bq_ikc]
	lea	rsi,[g_bq_iks]
	lea	rdx,[rbx+BC_Q+BQ_DCID]
	mov	ecx,8
	mov	r8d,QUIC_V1
	call	quic_initial
	lea	rdi,[g_b_tc]
	lea	rsi,[g_b_hout]
	mov	rdx,[g_b_sni]
	mov	ecx,[g_b_snilen]
	call	tlsc_client_hello
	test	eax,eax
	jz	.fail
	sub	eax,5
	mov	[g_bq_chlen],eax
	call	bench_h3_hello
	xor	r15d,r15d			; waits so far
.wait:
	mov	eax,[rbx+BC_FD]
	mov	[rsp],eax
	mov	dword [rsp+4],EPOLLIN		; (POLLIN)
	mov	rdi,rsp
	mov	esi,1
	mov	edx,200
	mov	eax,SYS_poll
	syscall
	test	eax,eax
	jnz	.read
	inc	r15d
	cmp	r15d,BQ_TRIES
	jae	.fail
	cmp	dword [g_bq_fin],0
	je	@f
	call	bench_h3_finished
	jmp	.wait
@@:
	cmp	dword [g_bq_keys],0
	jne	.wait				; (the server has the hello: it resends)
	call	bench_h3_hello
	jmp	.wait
.read:
	mov	edi,[rbx+BC_FD]
	lea	rsi,[g_bq_rx]
	mov	edx,65536
	mov	r10d,MSG_DONTWAIT
	xor	r8d,r8d
	xor	r9d,r9d
	mov	eax,SYS_recvfrom
	syscall
	cmp	rax,-EAGAIN
	je	.answer
	test	rax,rax
	js	.fail
	lea	r12,[g_bq_rx]
	lea	r14,[r12+rax]
	call	bench_h3_hs_datagram
	jc	.fail
	jmp	.read
.answer:
	cmp	dword [rbx+BC_Q+BQ_BAD],0
	jne	.fail
	cmp	dword [g_bq_ack],0
	je	@f
	xor	r8d,r8d
	call	bench_h3_long_ack
@@:
	cmp	dword [g_bq_ack+4],0
	je	@f
	mov	r8d,1
	call	bench_h3_long_ack
@@:
	call	bench_h3_flush
	cmp	dword [rbx+BC_Q+BQ_DONE],0
	jne	.ok
	cmp	dword [g_bq_fin],0
	jne	.wait
	call	bench_h3_flight
	test	eax,eax
	jz	.wait
	; the flight is whole (not verified: a load generator): our Finished
	lea	rdi,[g_b_tc+TC_SHA]
	lea	rsi,[g_bq_cr1]
	mov	edx,[g_bq_flight]
	call	sha256_update
	lea	rdi,[g_b_tc]
	lea	rsi,[g_bq_scr]
	call	tlsc_finish
	lea	rdi,[rbx+BC_Q+BQ_TXK]
	lea	rsi,[g_b_tc+TC_QCAP]
	mov	edx,QUIC_V1
	xor	ecx,ecx
	call	quic_keys
	lea	rdi,[rbx+BC_Q+BQ_RXK]
	lea	rsi,[g_b_tc+TC_QSAP]
	mov	edx,QUIC_V1
	xor	ecx,ecx
	call	quic_keys
	mov	dword [g_bq_fin],1
	call	bench_h3_finished
	jmp	.wait
.ok:
	mov	eax,1
	jmp	.out
.fail:
	xor	eax,eax
.out:
	add	rsp,24
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	ret
; our transport parameters: initial_max_data, stream data bidi local, 2^30;
; 3 unidirectional streams; initial_source_connection_id (ours follows)
.tp	db 0x04, 8, 0xC0, 0, 0, 0, 0x40, 0, 0, 0
	db 0x05, 8, 0xC0, 0, 0, 0, 0x40, 0, 0, 0
	db 0x09, 1, 3
	db 0x0F, 8
.tp_len = $ - .tp
