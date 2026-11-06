; HTTP/3 (RFC 9114) and QPACK (RFC 9204) on the QUIC connections of
; server.inc.
;
; Each request stream the client opens (bidirectional, ids 0, 4, 8, ...) is
; a session of its own (SF_H3S), as an HTTP/2 stream is: its HEADERS frame
; (QPACK, the static table only: we allow no dynamic table, so the client
; sends no encoder instructions) becomes an HTTP/1.1 head in its queue,
; its DATA frames the body (chunk-framed when it has no content-length),
; and the existing exchange runs on it (routing, pools, retries, logs). Its
; response comes back through h3s_send: the head into a HEADERS frame,
; the body into DATA frames, written into the stream's send ring, from
; where the connection sends STREAM frames as flow control and room in
; the packets allow, and again what is lost; acknowledged bytes free the
; ring. The client's unidirectional streams (control, QPACK) are read and
; ignored; ours is the control stream (id 3) with an empty SETTINGS.
;
; Stream data is taken in order: a STREAM frame beyond what came drops
; its packet unacknowledged, so the client sends it again.

SF_H3S		:= 131072			; S_FLAGS: an HTTP/3 request stream

; a request stream session's record (the HTTP/2 stream fields, reused)
H_H3C		:= H_H2C			; d: its connection's session
H_H3CG		:= H_H2CG			; d: that session's generation
H_H3SID		:= H_H2SID			; d: the stream id
H_H3F		:= H_H2F			; d: H3F_*
H_H3PP		:= H_H2PP			; q: response bytes waiting for room
H_H3PL		:= H_H2PL			; d: how many
H3F_HEAD	:= 1				; the final response head went into the ring
H3F_SENDING	:= 2				; an h_send is pending
H3F_FINISH	:= 4				; the exchange is over: FIN after the ring
H3F_ENDED	:= 8				; the client ended its request
H3F_HQ		:= 16				; hq-interop: the body alone, no frames

; its send ring, in its buffers past the HTTP/2 upstream area
HB_H3TX		:= 196864
TX_BASE		:= 0				; q: stream offset acknowledged (the ring's start)
TX_END		:= 8				; q: written
TX_SENT		:= 16				; q: next to send (back to what is lost)
TX_MAXSD	:= 24				; q: what the client lets us send (MAX_STREAM_DATA)
TX_HIGH		:= 32				; q: the highest sent (new data counts once)
TX_FIN		:= 40				; d: FIN after TX_END
TX_FINSENT	:= 44				; d
TX_FINACKED	:= 48				; d
TX_NACK		:= 52				; d: acknowledged ranges past the base
TX_ACK		:= 56				; TX_ACKMAX of (lo q, hi q)
TX_ACKMAX	:= 12
TX_CAPV		:= 248				; d: the ring's size (TX_CAP, or twice that)
TX_HDR		:= 256				; the header's size
; the bytes: the downstream TLS area (a stream session has no TLS of its
; own: the connection's QUIC carries it), 64 KiB, and the upstream TLS and
; HTTP/2 area after it when its pool uses neither, 128 KiB (a power of two
; either way): what a stream may have in flight, a window an RTT
TX_DATA		:= HB_TLS - HB_H3TX		; (from the header: before it)
TX_CAP		:= 65536
assert HB_TLS + TX_CAP <= HB_UPTLS
assert HB_TLS + TX_CAP * 2 <= HB_H3TX
assert TX_HDR <= 256
assert HB_U2Q + Q_DATA + Q_CAP <= HB_H3TX

; the connection's stream table
QST_N		:= 128
QST_ID		:= 0				; q
QST_KIND	:= 8				; d: QSK_*
QST_SESS	:= 12				; d: the request's session
QST_SGEN	:= 16				; d
QST_PHASE	:= 20				; d: 0 HEADERS next, 1 the body, 2 trailers done
QST_RXOFF	:= 24				; q: received in order
QST_FTYPE	:= 32				; q: the frame being read, -1 none
QST_FLEFT	:= 40				; q: its payload still to come
QST_FHAVE	:= 48				; d: header bytes gathered
QST_HBLEN	:= 52				; d: HEADERS payload gathered
QST_FHDR	:= 56				; 16: the header's bytes so far
QST_MSDPEND	:= 72				; d: a MAX_STREAM_DATA to send
QST_OPENED	:= 76				; d: when (g_tick)
QST_MSD		:= 80				; q: what we allow it
QST_FINHERE	:= 88				; d: these bytes end the stream; then, the head did
QST_EARLY	:= 92				; d: opened by 0-RTT data
QST_SIZE	:= 96
QSK_FREE	:= 0
QSK_REQ		:= 1
QSK_UNI		:= 2				; a client's unidirectional stream: read, ignored
QSK_UT		:= 3				; one whose type has not come yet
QSK_ENC		:= 4				; its QPACK encoder stream
QC_QST		:= QC_STREAMS
QC_H3HB		:= QC_QST + QST_N * QST_SIZE	; a HEADERS frame split across packets
; request stream data that came ahead of what is missing, held (and so
; acknowledged) until the gap is filled
QC_RA		:= QC_H3HB + H3_HEADERS_MAX
RA_N		:= 64
RA_ID		:= 0				; q
RA_OFF		:= 8				; q
RA_LEN		:= 16				; d
RA_FIN		:= 20				; d
RA_USED		:= 24				; d
RA_ESIZE	:= 32
RA_DCAP		:= 1400				; its bytes, at QC_RAD + slot * RA_DCAP
QC_RAD		:= QC_RA + RA_N * RA_ESIZE
assert QC_RAD + RA_N * RA_DCAP <= 1 shl HB_SHIFT
QC_KU		:= QC_RAD + RA_N * RA_DCAP	; the client's next 1-RTT keys (server.inc)
assert QC_KU and 15 = 0
assert QC_KU + QK_SIZE <= 1 shl HB_SHIFT
; QPACK's dynamic table (the client's inserts), its encoder stream's bytes
; not parsed yet, our decoder stream's not acknowledged yet
QP_CAPACITY	:= 2048				; what we announce
QP_MAXE		:= QP_CAPACITY / 32		; entries it can hold
QPE_OFF		:= 0				; w, in QC_QPD
QPE_NLEN	:= 2				; w
QPE_VLEN	:= 4				; w
QC_QPE		:= QC_KU + QK_SIZE		; QP_MAXE * 8, by absolute index modulo
QC_QPD		:= QC_QPE + QP_MAXE * 8		; the entries' bytes, in insertion order
QP_DCAP		:= 4096
QC_QPB		:= QC_QPD + QP_DCAP
QP_BCAP		:= 4096
QC_QDB		:= QC_QPB + QP_BCAP
QD_CAP		:= 512
assert QC_QDB + QD_CAP <= 1 shl HB_SHIFT
QC_K0		:= QC_QDB + QD_CAP		; the client's 0-RTT keys (server.inc)
assert QC_K0 and 15 = 0
assert QC_K0 + QK_SIZE <= 1 shl HB_SHIFT
assert QP_MAXE = 64
H3E_ENCODER_STREAM := 0x201

QF2_MAXD	:= 1				; MAX_DATA to send
QF2_MAXS	:= 2				; MAX_STREAMS (bidi)
QF2_PATH	:= 4				; PATH_RESPONSE
QF2_PCHAL	:= 16				; PATH_CHALLENGE (a new path to validate)
QF2_MSD		:= 8				; some stream has a MAX_STREAM_DATA
QF2_NCID	:= 32				; NEW_CONNECTION_IDs (QC_CIDS)
QF2_PALT	:= 64				; PATH_RESPONSE on another path (QC_ALT_*)

H3_WINDOW	:= 49152			; a request stream's window (the queue holds it)
QC_WINDOW	:= 1048576			; the connection's
H3_HEADERS_MAX	:= 16384			; a HEADERS frame (gathered in HB_OUT)
H3_FIELDS_MAX	:= 128

H3_RST_BUDGET	:= 200				; requests a client may cancel in a second
QUIC_ALT_BUDGET	:= 16				; probes from other paths answered in a second
H3E_NO_ERROR	:= 0x100
H3E_GENERAL	:= 0x101
H3E_FRAME_UNEXPECTED := 0x105
H3E_EXCESSIVE	:= 0x107
H3E_REQ_REJECTED := 0x10B
H3E_REQ_CANCELLED := 0x10C
H3E_INCOMPLETE	:= 0x10D
H3E_MESSAGE	:= 0x10E
QPACK_DECOMPRESSION := 0x200

include 'qpack_tables.inc'

bss
	align 16
	g_h3f:		rb H3_FIELDS_MAX * HP_SIZE	; decoded fields
	g_h3s:		rb 16384			; their Huffman-decoded strings
	g_h3tmp:	rb 20480			; a HEADERS frame being encoded
end bss

; edi = a session: r8 = its record, r9 = its buffers
macro h3_ptrs sess*
	mov	eax,sess
	mov	r8d,eax
	shl	r8,H_SHIFT
	add	r8,[g_http_base]
	mov	r9,[r8+H_BUF]
end macro

; ------------------------------------------------------- the connection

; r15 = connection, ebx = its session: the handshake is complete. The
; client's transport parameters (its limits on what we send), our control
; stream, our windows.
qc_established:
	push	r12
	mov	qword [r15+QC_MAXD_OURS],QC_WINDOW
	mov	qword [r15+QC_MAXS_OURS],100
	mov	qword [r15+QC_ACIDL],2		; (the default when it says nothing)
	mov	qword [r15+QC_PMAX],65527
	mov	dword [r15+QC_CTL_SENT],0
	mov	dword [r15+QC_CTL_ACKED],0
	lea	rdi,[r15+QC_QST]		; no streams yet
	mov	ecx,QST_N * QST_SIZE / 8
	xor	eax,eax
	rep	stosq
	lea	rdi,[r15+QC_RA]			; nothing held
	mov	ecx,RA_N * RA_ESIZE / 8
	rep	stosq
	mov	[r15+QC_HBOWN],rax
	mov	eax,[r15+QC_QT+QT_HQ]		; the protocol ALPN chose
	mov	[r15+QC_HQ],eax
	; the client's parameters: initial_max_data, stream data
	lea	rsi,[r15+QC_QT+QT_TPC]
	mov	edx,[r15+QC_QT+QT_TPCLEN]
	add	rdx,rsi
.param:
	cmp	rsi,rdx
	jae	.done
	call	qv_read				; id
	jc	.done
	mov	r12,rax
	call	qv_read				; length
	jc	.done
	lea	r8,[rsi+rax]
	cmp	r8,rdx
	ja	.done
	cmp	r12,4
	je	.maxd
	cmp	r12,5
	je	.bidi
	cmp	r12,7
	je	.uni
	cmp	r12,0x0E
	je	.acidl
	cmp	r12,3
	je	.pmax
	mov	rsi,r8
	jmp	.param
.pmax:
	call	qv_read
	jc	.done
	mov	[r15+QC_PMAX],rax
	mov	rsi,r8
	jmp	.param
.acidl:
	call	qv_read
	jc	.done
	mov	[r15+QC_ACIDL],rax
	mov	rsi,r8
	jmp	.param
.maxd:
	call	qv_read
	jc	.done
	mov	[r15+QC_MAXD_PEER],rax
	mov	rsi,r8
	jmp	.param
.bidi:
	call	qv_read
	jc	.done
	mov	[r15+QC_PSD_BIDI],rax
	mov	rsi,r8
	jmp	.param
.uni:
	call	qv_read
	jc	.done
	mov	[r15+QC_PSD_UNI],rax
	mov	rsi,r8
	jmp	.param
.done:
	call	qc_mtu_next			; this path's MTU: probes from now
	; spare connection IDs for the client (to change paths, or IDs): as
	; many as it takes past ours, at most 2; each names this worker too
	mov	rax,[r15+QC_ACIDL]
	sub	rax,1
	jbe	.no_cids
	cmp	rax,2
	jbe	@f
	mov	eax,2
@@:
	cmp	dword [r15+QC_PACID],0		; the first given already (preferred_address)
	je	@f
	cmp	eax,2
	jb	.no_cids
@@:
	mov	[r15+QC_NCIDS],eax
	lea	rdi,[r15+QC_CIDS+8]
	mov	esi,8
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	lea	rdi,[r15+QC_CIDS+8]
	call	qc_cid_brand
	cmp	dword [r15+QC_PACID],0
	jne	.second
	lea	rdi,[r15+QC_CIDS]
	mov	esi,8
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	lea	rdi,[r15+QC_CIDS]
	call	qc_cid_brand
	lea	rdi,[r15+QC_CIDS]
	mov	esi,8
	call	qh_add
.second:
	cmp	dword [r15+QC_NCIDS],2
	jb	@f
	lea	rdi,[r15+QC_CIDS+8]
	mov	esi,8
	call	qh_add
@@:
	or	dword [r15+QC_FL2],QF2_NCID
.no_cids:
	pop	r12
	jmp	qc_dirty

; ebx, r15 = connection, going: its request streams close
qc_streams_close:
	push	r12
	push	r13
	lea	r12,[r15+QC_QST]
	mov	r13d,QST_N
.next:
	cmp	dword [r12+QST_KIND],QSK_REQ
	jne	.skip
	mov	dword [r12+QST_KIND],QSK_FREE
	mov	edi,[r12+QST_SESS]
	cmp	edi,NIL
	je	.skip				; (opened, no request on it yet)
	mov	eax,edi
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	mov	ecx,[rax+S_GEN]
	cmp	ecx,[r12+QST_SGEN]
	jne	.skip
	push	rbx
	push	r15
	call	session_close
	pop	r15
	pop	rbx
.skip:
	add	r12,QST_SIZE
	dec	r13d
	jnz	.next
	pop	r13
	pop	r12
	ret

; rax = stream id (r15 = connection): r8 = its entry, or 0
qst_find:
	lea	r8,[r15+QC_QST]
	mov	ecx,QST_N
.next:
	cmp	dword [r8+QST_KIND],QSK_FREE
	je	.skip
	cmp	[r8+QST_ID],rax
	je	.found
.skip:
	add	r8,QST_SIZE
	dec	ecx
	jnz	.next
	xor	r8d,r8d
.found:
	ret

; rax = stream id: r8 = a free entry for it (zeroed but the id), or 0
qst_new:
	push	rax
	lea	r8,[r15+QC_QST]
	mov	ecx,QST_N
.next:
	cmp	dword [r8+QST_KIND],QSK_FREE
	je	.take
	add	r8,QST_SIZE
	dec	ecx
	jnz	.next
	pop	rax
	xor	r8d,r8d
	ret
.take:
	push	rdi
	mov	rdi,r8
	mov	ecx,QST_SIZE / 8
	xor	eax,eax
	rep	stosq
	pop	rdi
	pop	rax
	mov	[r8+QST_ID],rax
	mov	qword [r8+QST_FTYPE],-1
	ret

; ------------------------------------------------------- 1-RTT frames

; A frame of the application's space: rax = its type, rsi past the type,
; rdx = the payload's end, rdi = the packet's frame (QP_*), ebx/r15 = the
; connection. rsi past the frame; CF on an error (QC_ERR set).
qc_app_frame:
	push	r12
	push	r13
	mov	r12,rdi
	cmp	rax,0x08
	jb	.low
	cmp	rax,0x0F
	jbe	.stream
	cmp	rax,0x10
	je	.max_data
	cmp	rax,0x11
	je	.max_stream_data
	cmp	rax,0x12
	je	.one_value			; MAX_STREAMS: ours to open are few
	cmp	rax,0x13
	je	.one_value
	cmp	rax,0x14
	je	.one_value			; DATA_BLOCKED
	cmp	rax,0x15
	je	.two_values			; STREAM_DATA_BLOCKED
	cmp	rax,0x16
	je	.one_value			; STREAMS_BLOCKED
	cmp	rax,0x17
	je	.one_value
	cmp	rax,0x18
	je	.new_cid
	cmp	rax,0x19
	je	.retire_cid
	cmp	rax,0x1A
	je	.challenge
	cmp	rax,0x1B
	je	.response
	jmp	.violation			; NEW_TOKEN, HANDSHAKE_DONE, DATAGRAM, unknown
.low:
	cmp	rax,4
	je	.reset_stream
	cmp	rax,5
	je	.stop_sending
	jmp	.violation
.stream:
	mov	dword [r12+QP_ACKEL],1
	mov	r13d,eax			; its flags: OFF 4, LEN 2, FIN 1
	call	qv_read				; id
	jc	.encoding
	mov	r8,rax
	xor	r9d,r9d				; offset
	test	r13d,4
	jz	@f
	call	qv_read
	jc	.encoding
	mov	r9,rax
@@:
	mov	rcx,rdx
	sub	rcx,rsi				; length: to the end, or given
	test	r13d,2
	jz	@f
	call	qv_read
	jc	.encoding
	mov	rcx,rax
@@:
	lea	rax,[rsi+rcx]
	cmp	rax,rdx
	ja	.encoding
	push	rax
	push	rdx
	mov	rdi,r12
	mov	eax,r13d
	and	eax,1				; FIN
	call	qc_stream_in			; r8 id, r9 offset, rsi data, rcx length
	pop	rdx
	pop	rsi
	jc	.error
	jmp	.ok
.max_data:
	mov	dword [r12+QP_ACKEL],1
	call	qv_read
	jc	.encoding
	cmp	rax,[r15+QC_MAXD_PEER]
	jbe	.ok
	mov	[r15+QC_MAXD_PEER],rax
	call	qc_dirty
	jmp	.ok
.max_stream_data:
	mov	dword [r12+QP_ACKEL],1
	call	qv_read				; id
	jc	.encoding
	push	rax
	call	qv_read
	pop	rcx
	jc	.encoding
	push	rsi
	push	rdx
	mov	r13,rax
	mov	rax,rcx
	call	qst_find
	test	r8,r8
	jz	.msd_done
	cmp	dword [r8+QST_KIND],QSK_REQ
	jne	.msd_done
	cmp	dword [r8+QST_SESS],NIL
	je	.msd_done			; (no request on it yet)
	h3_ptrs	[r8+QST_SESS]
	cmp	r13,[r9+HB_H3TX+TX_MAXSD]
	jbe	.msd_done
	mov	[r9+HB_H3TX+TX_MAXSD],r13
	call	qc_dirty
.msd_done:
	pop	rdx
	pop	rsi
	jmp	.ok
.two_values:
	mov	dword [r12+QP_ACKEL],1
	call	qv_read
	jc	.encoding
.one_value:
	mov	dword [r12+QP_ACKEL],1
	call	qv_read
	jc	.encoding
	jmp	.ok
.retire_cid:
	; the client is done with one of our IDs: out of the hash
	mov	dword [r12+QP_ACKEL],1
	call	qv_read				; its sequence number
	jc	.encoding
	push	rsi
	push	rdx
	lea	rdi,[r15+QC_SCID]
	test	rax,rax
	jz	@f
	lea	rdi,[r15+QC_CIDS+rax*8-8]
	cmp	rax,[r15+QC_NCIDS]
	ja	.retire_bad
@@:
	mov	esi,8
	call	qh_del
	pop	rdx
	pop	rsi
	jmp	.ok
.retire_bad:
	pop	rdx
	pop	rsi
	jmp	.violation			; (never issued)
.new_cid:
	mov	dword [r12+QP_ACKEL],1
	call	qv_read				; sequence
	jc	.encoding
	call	qv_read				; retire prior to
	jc	.encoding
	cmp	rsi,rdx
	jae	.encoding
	movzx	eax,byte [rsi]			; its length, it, a reset token (16)
	lea	rsi,[rsi+rax+1+16]
	cmp	rsi,rdx
	ja	.encoding
	jmp	.ok				; (no migration: not used)
.challenge:
	mov	dword [r12+QP_ACKEL],1
	lea	rax,[rsi+8]
	cmp	rax,rdx
	ja	.encoding
	mov	rax,[rsi]
	add	rsi,8
	; on another path (a socket or an address not the connection's): the
	; answer goes on that path, the connection stays (unless the packet
	; moves it: server.inc)
	push	rsi
	push	rdx
	push	rax
	mov	eax,[g_qd_slot]
	cmp	eax,[r15+QC_SOCK]
	jne	.alt_path
	call	qc_peer_moved
	jnz	.alt_path
	pop	rax
	mov	[r15+QC_PCHAL],rax
	or	dword [r15+QC_FL2],QF2_PATH
	jmp	.challenged
.alt_path:
	; each answer goes where the packet says it came from, not validated:
	; a client sending them to another's address gets QUIC_ALT_BUDGET a second
	pop	rax
	mov	rcx,[g_qnow]
	sub	rcx,[r15+QC_ALT_WIN]
	cmp	rcx,1000000
	jb	.alt_count
	mov	rcx,[g_qnow]
	mov	[r15+QC_ALT_WIN],rcx
	mov	dword [r15+QC_ALT_CNT],0
.alt_count:
	inc	dword [r15+QC_ALT_CNT]
	cmp	dword [r15+QC_ALT_CNT],QUIC_ALT_BUDGET
	ja	.challenged
	mov	[r15+QC_ALT_DATA],rax
	mov	eax,[g_qd_slot]
	mov	[r15+QC_ALT_SLOT],eax
	mov	eax,[g_qd_salen]
	mov	[r15+QC_ALT_LEN],eax
	mov	eax,[r12+QP_DGRAM]		; (not validated: 3x what came from it)
	lea	eax,[rax*2+rax]
	mov	[r15+QC_ALT_MAX],eax
	mov	rsi,[g_qd_sa]
	lea	rdi,[r15+QC_ALT_SA]
	mov	ecx,28
	rep	movsb
	or	dword [r15+QC_FL2],QF2_PALT
.challenged:
	pop	rdx
	pop	rsi
	call	qc_dirty
	jmp	.ok
.response:
	mov	dword [r12+QP_ACKEL],1
	lea	rax,[rsi+8]
	cmp	rax,rdx
	ja	.encoding
	mov	rax,[rsi]			; ours back: the new path is good
	cmp	rax,[r15+QC_PCHALO]
	jne	@f
	mov	dword [r15+QC_PATHNV],0
	and	dword [r15+QC_FL2],not QF2_PCHAL
@@:
	add	rsi,8
	jmp	.ok
.reset_stream:
	mov	dword [r12+QP_ACKEL],1
	call	qv_read				; id
	jc	.encoding
	push	rax
	call	qv_read				; error
	jc	.pop_encoding
	call	qv_read				; final size
	jc	.pop_encoding
	pop	rax
	jmp	.stream_gone
.stop_sending:
	mov	dword [r12+QP_ACKEL],1
	call	qv_read				; id
	jc	.encoding
	push	rax
	call	qv_read				; error
	jc	.pop_encoding
	pop	rax
.stream_gone:
	; the client gave up on the stream: its exchange stops
	push	rsi
	push	rdx
	call	qst_find
	test	r8,r8
	jz	@f
	cmp	dword [r8+QST_KIND],QSK_REQ
	jne	@f
	mov	dword [r8+QST_KIND],QSK_FREE
	mov	edi,[r8+QST_SESS]
	cmp	edi,NIL
	je	@f				; (opened, no request on it yet)
	mov	eax,edi
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	mov	ecx,[rax+S_GEN]
	cmp	ecx,[r8+QST_SGEN]
	jne	@f
	push	rbx
	push	r15
	call	session_close
	pop	r15
	pop	rbx
	inc	qword [r15+QC_SDONE]
	mov	rax,[r15+QC_MAXS_OURS]		; (MAX_STREAMS: when half are used)
	sub	rax,[r15+QC_SDONE]
	cmp	rax,50
	jge	.maxs_kept
	or	dword [r15+QC_FL2],QF2_MAXS
.maxs_kept:
	; a request opened and cancelled costs a backend request each: past
	; H3_RST_BUDGET a second, the connection goes (as HTTP/2's rapid reset)
	mov	rax,[g_qnow]
	sub	rax,[r15+QC_RSTWIN]
	cmp	rax,1000000
	jb	.rst_count
	mov	rax,[g_qnow]
	mov	[r15+QC_RSTWIN],rax
	mov	dword [r15+QC_RSTCNT],0
.rst_count:
	inc	dword [r15+QC_RSTCNT]
	cmp	dword [r15+QC_RSTCNT],H3_RST_BUDGET
	jbe	@f
	pop	rdx
	pop	rsi
	mov	qword [r15+QC_ERR],H3E_EXCESSIVE
	or	dword [r15+QC_FLAGS],QF_APP_ERR
	jmp	.error
@@:
	pop	rdx
	pop	rsi
	jmp	.ok
.pop_encoding:
	pop	rax
.encoding:
	mov	qword [r15+QC_ERR],7		; FRAME_ENCODING_ERROR
	jmp	.error
.violation:
	mov	qword [r15+QC_ERR],0x0A		; PROTOCOL_VIOLATION
.error:
	stc
	jmp	.out
.ok:
	clc
.out:
	pop	r13
	pop	r12
	ret

bss
	g_h3_parked	dd ?			; h3_park: for qc_stream_one
	g_h3_stop	dd ?			; and for qc_stream_in: not read again now
end bss

; Stream data: r8 = id, r9 = offset, rsi = bytes, rcx = length, eax = FIN,
; rdi = the packet's frame. CF on an error (QC_ERR set).
QI_PKT		:= 0
QI_FIN		:= 8
QI_ID		:= 16
QI_OFF		:= 24
QI_DATA		:= 32
QI_LEN		:= 40
QI_SIZE		:= 56
qc_stream_in:
	push	rbp
	push	r13
	mov	rbp,r8				; the id
	mov	r13,rdi
	call	qc_stream_one
	jc	.out
.drain:
	cmp	dword [g_h3_stop],0		; (what just went back waits: it would
	je	.draining			; come back at once, for ever)
	mov	dword [g_h3_stop],0
	jmp	.fine
.draining:
	; what was held and is now next goes in, one piece at a time
	mov	rax,rbp
	call	qst_find
	test	r8,r8
	jz	.gone
	lea	rdi,[r15+QC_RA]
	xor	ecx,ecx
.scan:
	cmp	dword [rdi+RA_USED],0
	je	.skip
	cmp	[rdi+RA_ID],rbp
	jne	.skip
	mov	r9,[rdi+RA_OFF]
	cmp	r9,[r8+QST_RXOFF]
	ja	.skip
	cmp	dword [r8+QST_KIND],QSK_UNI
	je	.gone				; (refused meanwhile, or not read)
	mov	dword [rdi+RA_USED],0
	mov	eax,[rdi+RA_FIN]
	imul	esi,ecx,RA_DCAP
	lea	rsi,[r15+QC_RAD+rsi]
	mov	ecx,[rdi+RA_LEN]
	mov	r8,rbp
	mov	rdi,r13
	call	qc_stream_one
	jc	.out
	jmp	.drain
.skip:
	add	rdi,RA_ESIZE
	inc	ecx
	cmp	ecx,RA_N
	jb	.scan
	jmp	.kick
.gone:
	lea	rdi,[r15+QC_RA]			; the stream is gone: its pieces too
	mov	ecx,RA_N
.free:
	cmp	[rdi+RA_ID],rbp
	jne	@f
	mov	dword [rdi+RA_USED],0
@@:
	add	rdi,RA_ESIZE
	dec	ecx
	jnz	.free
.kick:
	; QC_H3HB free again: a stream that waited for it goes on
	test	dword [r15+QC_FLAGS],QF_PARKED
	jz	.fine
	mov	rax,[r15+QC_HBOWN]
	test	rax,rax
	jz	.kick_scan
	cmp	dword [rax+QST_KIND],QSK_REQ
	jne	.kick_scan
	cmp	dword [rax+QST_PHASE],0
	jne	.kick_scan
	cmp	dword [rax+QST_HBLEN],0
	je	.kick_scan
	mov	rdx,[rax+QST_ID]
	cmp	rdx,[r15+QC_HBOWNID]
	je	.fine				; still in use
.kick_scan:
	lea	rdi,[r15+QC_RA]
	mov	r9d,RA_N
.kick_next:
	cmp	dword [rdi+RA_USED],0
	je	.kick_skip
	mov	rax,[rdi+RA_ID]
	call	qst_find
	test	r8,r8
	jz	.kick_skip
	cmp	dword [r8+QST_KIND],QSK_REQ
	jne	.kick_skip
	mov	rax,[rdi+RA_OFF]
	cmp	rax,[r8+QST_RXOFF]
	ja	.kick_skip
	mov	rbp,[rdi+RA_ID]
	jmp	.drain
.kick_skip:
	add	rdi,RA_ESIZE
	dec	r9d
	jnz	.kick_next
	and	dword [r15+QC_FLAGS],not QF_PARKED
.fine:
	clc
.out:
	pop	r13
	pop	rbp
	ret

; qc_stream_in's work for one piece: in order, or held when it is ahead
qc_stream_one:
	push	r12
	push	r13
	push	r14
	sub	rsp,QI_SIZE
	mov	[rsp+QI_PKT],rdi
	mov	[rsp+QI_FIN],eax
	mov	[rsp+QI_ID],r8
	mov	[rsp+QI_OFF],r9
	mov	[rsp+QI_DATA],rsi
	mov	[rsp+QI_LEN],rcx
	mov	eax,r8d
	and	eax,3
	cmp	eax,1
	je	.state_error			; ours: never data from the client
	cmp	eax,3
	je	.state_error
	mov	rax,r8
	call	qst_find
	test	r8,r8
	jnz	.have
	; a new stream: above every one seen of its kind
	mov	rax,[rsp+QI_ID]
	test	eax,2
	jnz	.new_uni
	cmp	rax,[r15+QC_SMAX]
	jb	.ok				; a stream done already: ignored
	mov	rcx,rax
	shr	rcx,2
	cmp	rcx,[r15+QC_MAXS_OURS]
	jae	.limit
	; it opens every lower one not open yet too (RFC 9000 3.2): their
	; first bytes may come later
	mov	rax,[r15+QC_SMAX]
.open:
	lea	rcx,[rax+4]
	mov	[r15+QC_SMAX],rcx
	call	qst_new				; (keeps rax)
	test	r8,r8
	jz	.rejected
	mov	dword [r8+QST_KIND],QSK_REQ
	mov	ecx,[g_tick]
	mov	[r8+QST_OPENED],ecx
	mov	dword [r8+QST_SESS],NIL
	mov	qword [r8+QST_MSD],H3_WINDOW
	mov	rcx,[rsp+QI_PKT]		; (in 0-RTT: replayable)
	mov	ecx,[rcx+QP_EARLY]
	mov	[r8+QST_EARLY],ecx
	mov	rcx,[r15+QC_GOAWAY]		; past our GOAWAY: refused
	test	rcx,rcx
	jz	@f
	dec	rcx
	cmp	rax,rcx
	jb	@f
	push	rax
	push	r8
	mov	rdi,r8
	mov	eax,H3E_REQ_REJECTED
	call	qst_refuse
	pop	r8
	pop	rax
@@:
	cmp	rax,[rsp+QI_ID]
	je	.have
	add	rax,4
	jmp	.open
.new_uni:
	cmp	rax,[r15+QC_UMAX]
	jb	.ok
	lea	rcx,[rax+4]
	mov	[r15+QC_UMAX],rcx
	call	qst_new
	test	r8,r8
	jz	.ok				; (no room: its bytes are not needed)
	mov	dword [r8+QST_KIND],QSK_UT
	mov	qword [r8+QST_MSD],65536	; (initial_max_stream_data_uni)
.have:
	mov	r12,r8
	; in order only
	mov	rax,[rsp+QI_OFF]
	cmp	rax,[r12+QST_RXOFF]
	ja	.later
	add	rax,[rsp+QI_LEN]
	cmp	rax,[r12+QST_RXOFF]
	jb	.ok				; all seen already
	mov	r13,rax				; the new end
	mov	rcx,[r12+QST_RXOFF]
	sub	rcx,[rsp+QI_OFF]		; skip what came already
	mov	rsi,[rsp+QI_DATA]
	add	rsi,rcx
	mov	r14,r13
	sub	r14,[r12+QST_RXOFF]		; new bytes
	mov	[r12+QST_RXOFF],r13
	add	[r15+QC_DRECV],r14
	mov	rax,[r15+QC_DRECV]
	cmp	rax,[r15+QC_MAXD_OURS]
	ja	.flow
	; the connection's window: moved when half is used
	mov	rcx,[r15+QC_MAXD_OURS]
	sub	rcx,rax
	cmp	rcx,QC_WINDOW / 2
	jae	@f
	add	rax,QC_WINDOW
	mov	[r15+QC_MAXD_OURS],rax
	or	dword [r15+QC_FL2],QF2_MAXD
	call	qc_dirty
@@:
	cmp	dword [r12+QST_KIND],QSK_UNI
	je	.ok				; read and ignored
	cmp	r13,[r12+QST_MSD]
	ja	.flow
	cmp	dword [r12+QST_KIND],QSK_REQ
	je	@f
	mov	rdi,r12				; a type, then QPACK's encoder stream
	mov	rcx,r14
	call	qp_uni_bytes			; CF: an error (QC_ERR set)
	jc	.error
	jmp	.ok
@@:
	mov	eax,[rsp+QI_FIN]
	mov	[r12+QST_FINHERE],eax
	mov	rdi,r12
	mov	rcx,r14
	call	h3_req_bytes			; CF: an error (QC_ERR set)
	jc	.error
	cmp	dword [g_h3_parked],0		; its bytes (and end) wait: h3_park
	je	@f
	mov	dword [g_h3_parked],0
	jmp	.ok
@@:
	cmp	dword [r12+QST_KIND],QSK_REQ
	jne	.ok				; refused meanwhile: its end is nothing
	cmp	dword [rsp+QI_FIN],0
	je	.ok
	mov	rdi,r12
	call	h3_req_end
	jc	.error
	jmp	.ok
.later:
	cmp	dword [r12+QST_KIND],QSK_UNI
	je	.ok				; ignored anyway
	mov	rax,[rsp+QI_OFF]
	add	rax,[rsp+QI_LEN]
	cmp	rax,[r12+QST_MSD]
	ja	.flow
	cmp	qword [rsp+QI_LEN],RA_DCAP
	ja	.drop
	lea	rdi,[r15+QC_RA]
	xor	ecx,ecx
	xor	edx,edx				; a free slot, +1
.ra_scan:
	cmp	dword [rdi+RA_USED],0
	je	.ra_free
	mov	rax,[rsp+QI_ID]
	cmp	[rdi+RA_ID],rax
	jne	.ra_next
	mov	rax,[rsp+QI_OFF]
	cmp	[rdi+RA_OFF],rax
	jne	.ra_next
	mov	eax,[rdi+RA_LEN]
	cmp	rax,[rsp+QI_LEN]
	jae	.ok				; held already
	mov	dword [rdi+RA_USED],0		; (a shorter copy: replaced)
.ra_free:
	test	edx,edx
	jnz	.ra_next
	lea	edx,[ecx+1]
.ra_next:
	add	rdi,RA_ESIZE
	inc	ecx
	cmp	ecx,RA_N
	jb	.ra_scan
	test	edx,edx
	jz	.drop				; no room: it comes again
	dec	edx
	mov	eax,edx
	shl	eax,5
	lea	rdi,[r15+QC_RA+rax]
	mov	rax,[rsp+QI_ID]
	mov	[rdi+RA_ID],rax
	mov	rax,[rsp+QI_OFF]
	mov	[rdi+RA_OFF],rax
	mov	rcx,[rsp+QI_LEN]
	mov	[rdi+RA_LEN],ecx
	mov	eax,[rsp+QI_FIN]
	mov	[rdi+RA_FIN],eax
	mov	dword [rdi+RA_USED],1
	imul	edi,edx,RA_DCAP
	lea	rdi,[r15+QC_RAD+rdi]
	mov	rsi,[rsp+QI_DATA]
	rep	movsb
	jmp	.ok
.drop:
	mov	rdi,[rsp+QI_PKT]
	mov	dword [rdi+QP_DROP],1
	jmp	.ok
.limit:
	mov	qword [r15+QC_ERR],4		; STREAM_LIMIT_ERROR
	jmp	.error
.flow:
	mov	qword [r15+QC_ERR],3		; FLOW_CONTROL_ERROR
	jmp	.error
.rejected:
	mov	qword [r15+QC_ERR],1		; (no room for its state)
	jmp	.error
.state_error:
	mov	qword [r15+QC_ERR],5		; STREAM_STATE_ERROR
.error:
	stc
	jmp	.out
.ok:
	clc
.out:
	lea	rsp,[rsp+QI_SIZE]
	pop	r14
	pop	r13
	pop	r12
	ret

; ---------------------------------------------------- request streams

; rdi = the stream's entry, rsi = new bytes in order, rcx = how many: its
; frames, a byte at a time through their headers. CF on an error.
h3_req_bytes:
	cmp	dword [r15+QC_HQ],0
	jne	hq_req_bytes
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r12,rdi
	mov	r13,rsi
	lea	r14,[rsi+rcx]
.next:
	cmp	r13,r14
	jae	.done
	cmp	qword [r12+QST_FTYPE],-1
	jne	.payload
	; a frame header: type, then length, both varints
	mov	eax,[r12+QST_FHAVE]
	cmp	eax,16
	jae	.frame_error
	mov	cl,[r13]
	mov	[r12+QST_FHDR+rax],cl
	inc	dword [r12+QST_FHAVE]
	inc	r13
	lea	rsi,[r12+QST_FHDR]
	mov	edx,[r12+QST_FHAVE]
	add	rdx,rsi
	call	qv_read
	jc	.next				; the type is not whole yet
	mov	r8,rax
	call	qv_read
	jc	.next				; nor the length
	mov	dword [r12+QST_FHAVE],0
	mov	[r12+QST_FTYPE],r8
	mov	[r12+QST_FLEFT],rax
	mov	dword [r12+QST_HBLEN],0
	cmp	r8,1				; HEADERS
	jne	@f
	cmp	rax,H3_HEADERS_MAX
	ja	.excessive
@@:
	cmp	r8,0				; DATA before the head
	jne	@f
	cmp	dword [r12+QST_PHASE],1
	jne	.unexpected
@@:
	cmp	r8,1				; a third HEADERS
	jne	@f
	cmp	dword [r12+QST_PHASE],2
	je	.unexpected
@@:
	cmp	rax,0
	jne	.next
	jmp	.frame_end			; empty
.payload:
	mov	rcx,r14
	sub	rcx,r13
	cmp	rcx,[r12+QST_FLEFT]
	jbe	@f
	mov	rcx,[r12+QST_FLEFT]
@@:
	sub	[r12+QST_FLEFT],rcx
	mov	rax,[r12+QST_FTYPE]
	cmp	rax,1
	je	.headers
	test	rax,rax
	jnz	.skip				; another type: its payload ignored
	; DATA: into the queue
	push	rcx
	mov	rdi,r12
	mov	rsi,r13
	call	h3_body
	pop	rcx
	jc	.error_pop
	add	r13,rcx
	jmp	.check_end
.headers:
	cmp	dword [r12+QST_PHASE],1
	je	.skip				; trailers: their fields are not passed on
	; whole in these bytes: into g_h3tmp, parsed right away; split
	; across packets: gathered in the connection's QC_H3HB, one stream
	; at a time (another waits its turn: h3_park)
	mov	eax,[r12+QST_HBLEN]
	test	eax,eax
	jnz	.hb_more
	cmp	qword [r12+QST_FLEFT],0
	jne	.hb_split
	lea	rdi,[g_h3tmp]
	jmp	.hb_copy
.hb_split:
	call	h3_hb_take
	jc	.hb_busy
	xor	eax,eax
.hb_more:
	lea	rdi,[r15+QC_H3HB+rax]
.hb_copy:
	add	[r12+QST_HBLEN],ecx
	mov	rsi,r13
	add	r13,rcx
	rep	movsb
	jmp	.check_end
.hb_busy:
	mov	rcx,r14				; (all it has: the frame goes on past it)
	sub	rcx,r13
	add	[r12+QST_FLEFT],rcx
	call	h3_park
	jnc	.done
	mov	rdi,r12				; no room
	mov	eax,H3E_REQ_REJECTED
	call	qst_refuse
	jmp	.done
.skip:
	add	r13,rcx
.check_end:
	cmp	qword [r12+QST_FLEFT],0
	jne	.next
.frame_end:
	mov	rax,[r12+QST_FTYPE]
	mov	qword [r12+QST_FTYPE],-1
	cmp	rax,1
	jne	.next
	cmp	dword [r12+QST_PHASE],0
	jne	.trailers_done
	cmp	r13,r14				; the stream ends with its head: no body
	je	@f
	mov	dword [r12+QST_FINHERE],0
@@:
	cmp	[r15+QC_HBOWN],r12
	jne	@f
	mov	qword [r15+QC_HBOWN],0		; gathered: to g_h3tmp
	lea	rsi,[r15+QC_H3HB]
	lea	rdi,[g_h3tmp]
	mov	ecx,[r12+QST_HBLEN]
	rep	movsb
@@:
	mov	rdi,r12
	call	h3_request_new			; the request: its session, its exchange
	jc	.error
	cmp	dword [r12+QST_KIND],QSK_REQ
	jne	.done				; refused: what follows is not read
	mov	dword [r12+QST_PHASE],1
	jmp	.next
.trailers_done:
	mov	dword [r12+QST_PHASE],2
	jmp	.next
.done:
	clc
	jmp	.out
.error_pop:
.error:
	stc
	jmp	.out
.excessive:
	mov	qword [r15+QC_ERR],H3E_EXCESSIVE
	or	dword [r15+QC_FLAGS],QF_APP_ERR
	stc
	jmp	.out
.unexpected:
	mov	qword [r15+QC_ERR],H3E_FRAME_UNEXPECTED
	or	dword [r15+QC_FLAGS],QF_APP_ERR
	stc
	jmp	.out
.frame_error:
	mov	qword [r15+QC_ERR],0x106	; H3_FRAME_ERROR
	or	dword [r15+QC_FLAGS],QF_APP_ERR
	stc
.out:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; hq-interop (the interop runner's HTTP/0.9): rdi = the stream's entry,
; rsi = new bytes, rcx = how many. The request line ("GET /path", then
; CRLF or the stream's end) becomes a QPACK field section in g_h3tmp, and
; the request goes as an HTTP/3 one would; anything after it is ignored.
; Gathered like a split HEADERS frame when it spans packets. CF on an error.
hq_req_bytes:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r12,rdi
	mov	r13,rsi
	mov	r14,rcx
	cmp	dword [r12+QST_PHASE],0
	jne	.ok
	mov	rdi,r13				; complete in these bytes?
	mov	al,10
	repne	scasb
	setz	r10b			; (rbx is the connection's session)
	cmp	dword [r12+QST_FINHERE],0
	setne	al
	or	r10b,al
	mov	eax,[r12+QST_HBLEN]
	lea	edx,[rax+r14]
	cmp	edx,2048
	ja	.refuse
	test	eax,eax
	jnz	.gather
	test	r10b,r10b
	jnz	.parse				; whole: from the packet
	call	h3_hb_take
	jc	.refuse
	xor	eax,eax
.gather:
	lea	rdi,[r15+QC_H3HB+rax]
	mov	rsi,r13
	mov	rcx,r14
	add	[r12+QST_HBLEN],ecx
	rep	movsb
	test	r10b,r10b
	jz	.ok
	lea	r13,[r15+QC_H3HB]
	mov	r14d,[r12+QST_HBLEN]
	mov	qword [r15+QC_HBOWN],0
.parse:
	cmp	r14,5
	jb	.refuse
	cmp	dword [r13],'GET '
	jne	.refuse
	lea	rsi,[r13+4]			; the path: to a space, CR or LF
	lea	rdx,[r13+r14]
	mov	r8,rsi
@@:
	cmp	rsi,rdx
	jae	@f
	mov	al,[rsi]
	cmp	al,' '
	je	@f
	cmp	al,13
	je	@f
	cmp	al,10
	je	@f
	inc	rsi
	jmp	@b
@@:
	mov	r9,rsi
	sub	r9,r8
	jz	.refuse
	cmp	byte [r8],'/'
	jne	.refuse
	lea	rdi,[g_h3tmp]
	mov	word [rdi],0			; Required Insert Count 0, Delta Base 0
	add	rdi,2
	push	r8
	push	r9
	lea	rsi,[.n_method]
	mov	ecx,7
	lea	r8,[.v_get]
	mov	r9d,3
	call	h3_lit
	lea	rsi,[.n_scheme]
	mov	ecx,7
	lea	r8,[.v_https]
	mov	r9d,5
	call	h3_lit
	lea	rsi,[.n_auth]
	mov	ecx,10
	lea	r8,[.v_host]
	mov	r9d,9
	call	h3_lit
	pop	r9
	pop	r8
	lea	rsi,[.n_path]
	mov	ecx,5
	call	h3_lit
	lea	rax,[g_h3tmp]
	sub	rdi,rax
	mov	[r12+QST_HBLEN],edi
	mov	dword [r12+QST_FINHERE],1	; HTTP/0.9: never a body
	mov	rdi,r12
	call	h3_request_new			; the request: its session, its exchange
	jc	.error
	mov	dword [r12+QST_PHASE],1
.ok:
	clc
	jmp	.out
.refuse:
	mov	rdi,r12
	mov	eax,H3E_REQ_REJECTED
	call	qst_refuse
	jmp	.ok
.error:
	stc
.out:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
.n_method	db ':method'
.v_get		db 'GET'
.n_scheme	db ':scheme'
.v_https	db 'https'
.n_auth		db ':authority'
.v_host		db 'localhost'
.n_path		db ':path'

; rdi = a request stream's entry, eax = the error: refused (RESET_STREAM);
; its further bytes are read and ignored
qst_refuse:
	mov	rdx,[rdi+QST_ID]
	mov	dword [rdi+QST_KIND],QSK_UNI
	mov	ecx,[r15+QC_RSTN]
	cmp	ecx,8
	jae	@f
	shl	ecx,4
	mov	[r15+QC_RST+rcx],rdx
	mov	[r15+QC_RST+rcx+8],rax
	inc	dword [r15+QC_RSTN]
	jmp	qc_dirty
@@:
	ret

; r15 = connection, ebx its slot: once a second, requests whose head has not
; come within the listener's `timeout { header }` go (a slow client holds an
; entry of QST_N each; no session yet: nothing else to free)
qc_heads_expire:
	test	dword [r15+QC_FLAGS],QF_DONE	; (before that its streams are not set up:
	jz	.none				; a recycled buffer's bytes)
	mov	eax,[g_tick]
	cmp	eax,[r15+QC_HDR_TICK]
	je	.none
	mov	[r15+QC_HDR_TICK],eax
	mov	eax,[r15+QC_SOCK]
	mov	eax,[g_qs_lst+rax*4]
	imul	rax,rax,LS_SIZE
	mov	eax,[g_listeners+rax+LS_T_HEADER]
	test	eax,eax
	jz	.none
	push	r12
	push	r13
	push	r14
	mov	r14d,eax
	lea	r12,[r15+QC_QST]
	mov	r13d,QST_N
.next:
	cmp	dword [r12+QST_KIND],QSK_REQ
	jne	.skip
	cmp	dword [r12+QST_PHASE],0
	jne	.skip
	mov	eax,[g_tick]
	sub	eax,[r12+QST_OPENED]
	cmp	eax,r14d
	jbe	.skip				; never early
	mov	rdi,r12
	mov	eax,H3E_INCOMPLETE
	call	qst_refuse
.skip:
	add	r12,QST_SIZE
	dec	r13d
	jnz	.next
	pop	r14
	pop	r13
	pop	r12
.none:
	ret

; r12 = a stream's entry, r13-r14 = its bytes from a split HEADERS' payload on:
; QC_H3HB is another's, so they go back to wait in QC_RA, as data ahead of
; what is missing would, and so does all that comes after them. Clients do
; this (quiche in 0-RTT, a few bytes of many streams): refused, they would
; have to send it again. qc_stream_in picks them up. CF: no room.
h3_park:
	mov	rcx,r14
	sub	rcx,r13
	cmp	rcx,RA_DCAP
	ja	.full
	lea	rdi,[r15+QC_RA]
	xor	edx,edx
.scan:
	cmp	dword [rdi+RA_USED],0
	je	.free
	add	rdi,RA_ESIZE
	inc	edx
	cmp	edx,RA_N
	jb	.scan
.full:
	stc
	ret
.free:
	mov	rax,[r12+QST_RXOFF]
	sub	rax,rcx
	mov	[r12+QST_RXOFF],rax
	mov	[rdi+RA_OFF],rax
	mov	rax,[r12+QST_ID]
	mov	[rdi+RA_ID],rax
	mov	[rdi+RA_LEN],ecx
	mov	eax,[r12+QST_FINHERE]
	mov	[rdi+RA_FIN],eax
	mov	dword [rdi+RA_USED],1
	sub	[r15+QC_DRECV],rcx		; (counted when they come back)
	imul	edi,edx,RA_DCAP
	lea	rdi,[r15+QC_RAD+rdi]
	mov	rsi,r13
	rep	movsb
	or	dword [r15+QC_FLAGS],QF_PARKED
	mov	dword [g_h3_parked],1
	mov	dword [g_h3_stop],1
	clc
	ret

; r12 = a stream's entry: QC_H3HB is its to gather in (CF: another's)
h3_hb_take:
	mov	rax,[r15+QC_HBOWN]
	test	rax,rax
	jz	.take
	cmp	rax,r12
	je	.take
	cmp	dword [rax+QST_KIND],QSK_REQ	; the owner gone or past its head
	jne	.take
	cmp	dword [rax+QST_PHASE],0
	jne	.take
	cmp	dword [rax+QST_HBLEN],0
	je	.take
	mov	rdx,[rax+QST_ID]
	cmp	rdx,[r15+QC_HBOWNID]
	jne	.take
	stc
	ret
.take:
	mov	[r15+QC_HBOWN],r12
	mov	rax,[r12+QST_ID]
	mov	[r15+QC_HBOWNID],rax
	clc
	ret

; rdi = the stream's entry: the client ended the stream (FIN in order)
h3_req_end:
	cmp	dword [rdi+QST_PHASE],0
	je	.no_head			; ended before its HEADERS
	cmp	qword [rdi+QST_FTYPE],-1
	jne	.no_head			; in the middle of a frame
	push	r12
	mov	r12,rdi
	h3_ptrs	[r12+QST_SESS]
	mov	eax,[r8+H_H3F]
	test	eax,H3F_ENDED
	jnz	.ended
	or	dword [r8+H_H3F],H3F_ENDED
	push	rbx
	mov	ebx,[r12+QST_SESS]
	push	r14
	push	r15
	mov	r15,r8
	lea	r14,[r9+HB_H2Q]
	cmp	dword [r14+Q_CHUNKED],0
	je	@f
	mov	eax,[r14+Q_LEN]			; the last chunk
	mov	dword [r14+Q_DATA+rax],0x0D0A0D30
	mov	byte [r14+Q_DATA+rax+4],10
	add	dword [r14+Q_LEN],5
@@:
	mov	dword [r14+Q_ENDED],1
	mov	rax,[r14+Q_CLEN]
	cmp	rax,-1
	je	@f
	cmp	rax,[r14+Q_GOT]
	jne	.short_body
@@:
	call	h3q_serve
	pop	r15
	pop	r14
	pop	rbx
.ended:
	pop	r12
	clc
	ret
.short_body:
	pop	r15
	pop	r14
	pop	rbx
	pop	r12
	mov	qword [r15+QC_ERR],H3E_MESSAGE
	or	dword [r15+QC_FLAGS],QF_APP_ERR
	stc
	ret
.no_head:
	mov	qword [r15+QC_ERR],H3E_MESSAGE
	or	dword [r15+QC_FLAGS],QF_APP_ERR
	stc
	ret

; rdi = the stream's entry, rsi = DATA payload bytes, rcx = how many: into
; its session's queue. CF on an error.
h3_body:
	push	rbx
	push	r14
	push	r15
	mov	r10,rdi
	h3_ptrs	[r10+QST_SESS]
	mov	ebx,[r10+QST_SESS]
	mov	r15,r8
	lea	r14,[r9+HB_H2Q]
	add	[r14+Q_GOT],rcx
	mov	rax,[r14+Q_CLEN]
	cmp	rax,-1
	je	@f
	cmp	[r14+Q_GOT],rax
	ja	.message			; more than its content-length
	mov	eax,H3E_MESSAGE
@@:
	push	rsi
	push	rcx
	call	h2q_compact
	pop	rcx
	pop	rsi
	mov	eax,[r14+Q_LEN]
	lea	eax,[rax+rcx+32]
	cmp	eax,H2Q_CAP
	ja	.overflow			; (the window keeps it below)
	test	ecx,ecx
	jz	.done
	cmp	dword [r14+Q_CHUNKED],0
	je	.raw
	push	rsi
	push	rcx
	mov	eax,[r14+Q_LEN]
	lea	rdi,[r14+Q_DATA+rax]
	mov	eax,ecx
	call	fmt_hex32
	mov	word [rdi],0x0A0D
	add	rdi,2
	lea	rax,[r14+Q_DATA]
	sub	rdi,rax
	mov	[r14+Q_LEN],edi
	pop	rcx
	pop	rsi
.raw:
	mov	eax,[r14+Q_LEN]
	lea	rdi,[r14+Q_DATA+rax]
	add	[r14+Q_LEN],ecx
	rep	movsb
	cmp	dword [r14+Q_CHUNKED],0
	je	.done
	mov	word [rdi],0x0A0D
	add	dword [r14+Q_LEN],2
.done:
	call	h3q_serve
	clc
	jmp	.out
.overflow:
	mov	eax,3				; FLOW_CONTROL_ERROR
	jmp	.fail
.message:
	mov	eax,H3E_MESSAGE
.fail:
	pop	r15				; the connection's
	pop	r14
	pop	rbx
	mov	[r15+QC_ERR],rax
	cmp	eax,0x100
	jb	@f
	or	dword [r15+QC_FLAGS],QF_APP_ERR
@@:
	stc
	ret
.out:
	pop	r15
	pop	r14
	pop	rbx
	ret

; ebx = stream session, r15 = its record, r14 = its queue: a receive
; parked there gets what it holds
h3q_serve:
	cmp	dword [r14+Q_WAIT],0
	je	.out
	mov	ecx,[r14+Q_LEN]
	sub	ecx,[r14+Q_OFF]
	jnz	.give
	cmp	dword [r14+Q_ENDED],0
	je	.out
.give:
	mov	dword [r14+Q_WAIT],0
	mov	rdi,[r14+Q_DST]
	mov	esi,[r14+Q_ROOM]
	jmp	h3s_take
.out:
	ret

; ---------------------------------------------------------------- QPACK

; rsi = cursor, rdx = end, cl = prefix bits: an integer (the first byte's
; low bits, then 7 bits a byte); rax = it, rsi past it. CF when truncated
; or too large.
qp_int:
	cmp	rsi,rdx
	jae	.bad
	mov	r10d,1
	shl	r10d,cl
	dec	r10d
	movzx	eax,byte [rsi]
	inc	rsi
	and	eax,r10d
	cmp	eax,r10d
	jne	.ok
	xor	ecx,ecx				; shift
.more:
	cmp	rsi,rdx
	jae	.bad
	cmp	ecx,56
	ja	.bad
	movzx	r11d,byte [rsi]
	inc	rsi
	mov	r10d,r11d
	and	r10d,127
	shl	r10,cl
	add	rax,r10
	add	ecx,7
	test	r11d,128
	jnz	.more
.ok:
	clc
	ret
.bad:
	stc
	ret

; rsi = cursor, rdx = end, cl = the length's prefix bits (the Huffman flag
; is the bit above them): a string. rax = its bytes, ecx = its length (in
; g_h3s when Huffman-coded), rsi past it; CF on an error.
qp_string:
	movzx	eax,byte [rsi]
	push	rax
	push	rcx
	call	qp_int
	pop	rcx
	pop	r8
	jc	.bad
	lea	r9,[rsi+rax]
	cmp	r9,rdx
	ja	.bad
	mov	r10d,1
	shl	r10d,cl
	test	r8d,r10d			; Huffman?
	jnz	.huffman
	mov	ecx,eax
	mov	rax,rsi
	mov	rsi,r9
	clc
	ret
.huffman:
	push	rdx
	push	r9
	mov	ecx,eax
	mov	rdi,[g_h3sp]
	lea	r8,[g_h3s+16384]
	push	rdi
	call	huff_decode			; rax = the end written
	pop	r8				; the start
	pop	rsi
	pop	rdx
	jc	.bad
	mov	[g_h3sp],rax
	mov	rcx,rax
	sub	rcx,r8
	mov	rax,r8
	clc
	ret
.bad:
	stc
	ret

bss
	g_h3sp		dq ?
	g_qp_ric	dq ?			; the field section's Required Insert Count
	g_qp_base	dq ?			; and Base
	g_qptmp:	rb QP_CAPACITY
end bss

; rax = an absolute index below the section's Required Insert Count (r15 =
; connection): r8/r9d its name, r10/r11d its value; CF when it is not one
qp_ref:
	cmp	rax,[g_qp_ric]
	jae	.bad
; ... any entry in the table
qp_entry:
	cmp	rax,[r15+QC_QP_DROP]
	jb	qp_ref.bad
	cmp	rax,[r15+QC_QP_INS]
	jae	qp_ref.bad
	mov	ecx,eax
	and	ecx,QP_MAXE - 1
	lea	rcx,[r15+QC_QPE+rcx*8]
	movzx	r8d,word [rcx+QPE_OFF]
	movzx	r9d,word [rcx+QPE_NLEN]
	movzx	r11d,word [rcx+QPE_VLEN]
	lea	r8,[r15+QC_QPD+r8]
	lea	r10,[r8+r9]
	clc
	ret
qp_ref.bad:
	stc
	ret

; r15 = connection: the oldest entry goes
qp_evict:
	mov	rax,[r15+QC_QP_DROP]
	and	eax,QP_MAXE - 1
	lea	rcx,[r15+QC_QPE+rax*8]
	movzx	eax,word [rcx+QPE_NLEN]
	movzx	ecx,word [rcx+QPE_VLEN]
	lea	eax,[rax+rcx+32]
	sub	[r15+QC_QP_SIZE],eax
	inc	qword [r15+QC_QP_DROP]
	ret

; r8/r9d = a name, r10/r11d = a value (r15 = connection; they may be in the
; table): a new entry, evicting what its room takes. CF when it cannot fit.
; Keeps rsi, rdx.
qp_insert:
	lea	eax,[r9+r11+32]
	cmp	eax,[r15+QC_QP_CAP]
	ja	qp_ref.bad
	push	rsi
	push	rdx
	push	rbx
	mov	ebx,eax
	lea	rdi,[g_qptmp]			; a copy: what it names may be evicted
	mov	rsi,r8
	mov	ecx,r9d
	rep	movsb
	mov	rsi,r10
	mov	ecx,r11d
	rep	movsb
.room:
	lea	eax,[rbx]
	add	eax,[r15+QC_QP_SIZE]
	cmp	eax,[r15+QC_QP_CAP]
	jbe	.fits
	call	qp_evict
	jmp	.room
.fits:
	lea	edx,[rbx-32]			; its bytes
	mov	eax,[r15+QC_QP_TAIL]
	add	eax,edx
	cmp	eax,QP_DCAP
	jbe	.tail_ok
	; to the start, in order (the table holds less than half of the area)
	xor	edi,edi				; where the next goes
	mov	r8,[r15+QC_QP_DROP]
.compact:
	cmp	r8,[r15+QC_QP_INS]
	jae	.compacted
	mov	eax,r8d
	and	eax,QP_MAXE - 1
	lea	r10,[r15+QC_QPE+rax*8]
	movzx	esi,word [r10+QPE_OFF]
	movzx	ecx,word [r10+QPE_NLEN]
	movzx	eax,word [r10+QPE_VLEN]
	add	ecx,eax
	mov	[r10+QPE_OFF],di
	lea	rsi,[r15+QC_QPD+rsi]
	lea	r10,[r15+QC_QPD+rdi]
	add	edi,ecx
	xchg	rdi,r10
	rep	movsb
	mov	rdi,r10
	inc	r8
	jmp	.compact
.compacted:
	mov	[r15+QC_QP_TAIL],edi
.tail_ok:
	mov	rax,[r15+QC_QP_INS]
	and	eax,QP_MAXE - 1
	lea	r10,[r15+QC_QPE+rax*8]
	mov	eax,[r15+QC_QP_TAIL]
	mov	[r10+QPE_OFF],ax
	mov	[r10+QPE_NLEN],r9w
	mov	[r10+QPE_VLEN],r11w
	lea	rdi,[r15+QC_QPD+rax]
	lea	rsi,[g_qptmp]
	mov	ecx,edx
	rep	movsb
	add	[r15+QC_QP_TAIL],edx
	add	[r15+QC_QP_SIZE],ebx
	inc	qword [r15+QC_QP_INS]
	pop	rbx
	pop	rdx
	pop	rsi
	clc
	ret

; our decoder stream (r15 = connection): room for a short instruction at
; its end (its type first); rdi = there, or CF when what is unacknowledged
; fills the buffer
qd_room:
	mov	rax,[r15+QC_QD_END]
	sub	rax,[r15+QC_QD_BASE]
	cmp	rax,QD_CAP - 16
	jbe	.room
	mov	rcx,[r15+QC_QD_ACK]		; forget what is acknowledged
	sub	rcx,[r15+QC_QD_BASE]
	jz	.full
	lea	rdi,[r15+QC_QDB]
	lea	rsi,[rdi+rcx]
	add	[r15+QC_QD_BASE],rcx
	mov	rax,[r15+QC_QD_END]
	sub	rax,[r15+QC_QD_BASE]
	mov	rcx,rax
	rep	movsb
	cmp	rax,QD_CAP - 16
	ja	.full
.room:
	lea	rdi,[r15+QC_QDB+rax]
	cmp	qword [r15+QC_QD_END],0
	jne	.ok
	mov	byte [rdi],3			; the stream's type
	inc	rdi
	inc	qword [r15+QC_QD_END]
	inc	qword [r15+QC_DSENT]
.ok:
	clc
	ret
.full:
	stc
	ret

; rdi = past an instruction written after qd_room (r15 = connection, ebx
; its session): the decoder stream's end there
qd_written:
	lea	rax,[r15+QC_QDB]
	sub	rdi,rax
	add	rdi,[r15+QC_QD_BASE]
	mov	rax,rdi
	sub	rax,[r15+QC_QD_END]
	add	[r15+QC_DSENT],rax
	mov	[r15+QC_QD_END],rdi
	jmp	qc_dirty

; rax = a stream whose field section used the table: Section
; Acknowledgment, which also tells the client of the inserts it needed.
; (No room: skipped, the client only keeps its references longer.)
qd_section_ack:
	push	rax
	call	qd_room
	pop	rax
	jc	.out
	mov	cl,7
	mov	dl,0x80
	call	hp_put_int
	mov	rax,[g_qp_ric]
	cmp	rax,[r15+QC_QP_KNOWN]
	jbe	@f
	mov	[r15+QC_QP_KNOWN],rax
@@:
	jmp	qd_written
.out:
	ret

; rdi = a client's unidirectional stream's entry whose type has not come,
; or its encoder stream's; rsi = bytes in order, rcx = how many. The type
; decides: anything but QPACK's encoder stream is read and ignored; its
; instructions (RFC 9204 4.3) go into the table, whole ones (kept in QC_QPB
; meanwhile), and the client hears what was inserted. CF on an error.
QPE_SIZE	:= 32				; locals: a literal name
qp_uni_bytes:
	push	r12
	push	r13
	push	r14
	push	rbp
	sub	rsp,QPE_SIZE
	mov	r12,rdi
	test	rcx,rcx
	jz	.ok
	cmp	dword [r12+QST_KIND],QSK_ENC
	je	.append
	movzx	eax,byte [rsi]
	mov	dword [r12+QST_KIND],QSK_UNI
	cmp	eax,2
	jne	.ok
	mov	dword [r12+QST_KIND],QSK_ENC
	inc	rsi
	dec	rcx
.append:
	mov	eax,[r15+QC_QP_PART]
	lea	edx,[rax+rcx]
	cmp	edx,QP_BCAP
	ja	.stream_error
	lea	rdi,[r15+QC_QPB+rax]
	mov	[r15+QC_QP_PART],edx
	rep	movsb
	lea	rsi,[r15+QC_QPB]
	mov	rdx,rsi
	mov	eax,[r15+QC_QP_PART]
	add	rdx,rax
.instruction:
	mov	r13,rsi				; (back here when it is not whole)
	cmp	rsi,rdx
	jae	.parsed
	lea	rax,[g_h3s]
	mov	[g_h3sp],rax
	movzx	eax,byte [rsi]
	test	al,0x80
	jnz	.with_ref
	test	al,0x40
	jnz	.with_name
	test	al,0x20
	jnz	.capacity
	; 000 index(5): Duplicate
	mov	cl,5
	call	qp_int
	jc	.parsed
	mov	rcx,[r15+QC_QP_INS]
	dec	rcx
	sub	rcx,rax
	mov	rax,rcx
	call	qp_entry
	jc	.stream_error
	call	qp_insert
	jc	.stream_error
	jmp	.instruction
.capacity:					; 001 capacity(5)
	mov	cl,5
	call	qp_int
	jc	.parsed
	cmp	rax,QP_CAPACITY
	ja	.stream_error
	mov	[r15+QC_QP_CAP],eax
.shrink:
	mov	eax,[r15+QC_QP_SIZE]
	cmp	eax,[r15+QC_QP_CAP]
	jbe	.instruction
	call	qp_evict
	jmp	.shrink
.with_ref:					; 1 T index(6), value
	mov	r14d,eax
	mov	cl,6
	call	qp_int
	jc	.parsed
	mov	[rsp],rax
	mov	cl,7
	cmp	rsi,rdx
	jae	.parsed
	call	qp_string
	jc	.parsed
	mov	rbp,rax				; the value
	mov	[rsp+8],ecx
	mov	rax,[rsp]
	test	r14d,0x40
	jnz	.ref_static
	mov	rcx,[r15+QC_QP_INS]
	dec	rcx
	sub	rcx,rax
	mov	rax,rcx
	call	qp_entry
	jc	.stream_error
	jmp	.ref_named
.ref_static:
	call	qpack_decode.static
	jc	.stream_error
.ref_named:
	mov	r10,rbp
	mov	r11d,[rsp+8]
	call	qp_insert
	jc	.stream_error
	jmp	.instruction
.with_name:					; 01 H length(5), name, value
	mov	cl,5
	call	qp_string
	jc	.parsed
	mov	[rsp],rax
	mov	[rsp+8],ecx
	cmp	rsi,rdx
	jae	.parsed
	mov	cl,7
	call	qp_string
	jc	.parsed
	mov	r10,rax
	mov	r11d,ecx
	mov	r8,[rsp]
	mov	r9d,[rsp+8]
	call	qp_insert
	jc	.stream_error
	jmp	.instruction
.parsed:
	; what is left waits for more; the client hears of new entries
	lea	rdi,[r15+QC_QPB]
	mov	rcx,rdx
	sub	rcx,r13
	mov	[r15+QC_QP_PART],ecx
	mov	rsi,r13
	rep	movsb
	mov	rax,[r15+QC_QP_INS]
	sub	rax,[r15+QC_QP_KNOWN]
	jz	.credit
	push	rax
	call	qd_room
	pop	rax
	jc	.credit
	add	[r15+QC_QP_KNOWN],rax
	mov	cl,6				; Insert Count Increment
	xor	edx,edx
	call	hp_put_int
	call	qd_written
.credit:
	; its window: moved along (the stream lives as long as the connection)
	mov	rax,[r12+QST_RXOFF]
	add	rax,32768
	cmp	rax,[r12+QST_MSD]
	jbe	.ok
	add	rax,32768
	mov	[r12+QST_MSD],rax
	mov	dword [r12+QST_MSDPEND],1
	or	dword [r15+QC_FL2],QF2_MSD
	call	qc_dirty
.ok:
	clc
	jmp	.out
.stream_error:
	mov	qword [r15+QC_ERR],H3E_ENCODER_STREAM
	or	dword [r15+QC_FLAGS],QF_APP_ERR
	stc
.out:
	lea	rsp,[rsp+QPE_SIZE]
	pop	rbp
	pop	r14
	pop	r13
	pop	r12
	ret

; rsi = a field section, edx = its length: its field lines into g_h3f
; (HP_* entries). eax = how many, or -1 (a decompression error).
qpack_decode:
	push	rbx
	push	r12
	lea	rdx,[rsi+rdx]
	lea	rax,[g_h3s]
	mov	[g_h3sp],rax
	; the prefix: the Required Insert Count (RFC 9204 4.5.1.1), which no
	; blocked stream can exceed, and the Base
	mov	cl,8
	call	qp_int
	jc	.bad
	test	rax,rax
	jz	.ric_set
	cmp	rax,2 * QP_MAXE
	ja	.bad
	mov	r8,[r15+QC_QP_INS]		; (the largest it can be)
	lea	r8,[r8+QP_MAXE]
	mov	r9,r8
	shr	r9,7				; to a multiple of 2 * QP_MAXE = 128
	shl	r9,7
	lea	rax,[r9+rax-1]
	cmp	rax,r8
	jbe	@f
	cmp	rax,2 * QP_MAXE
	jbe	.bad
	sub	rax,2 * QP_MAXE
@@:
	test	rax,rax
	jz	.bad
	cmp	rax,[r15+QC_QP_INS]
	ja	.bad				; (blocked: we allow none)
.ric_set:
	mov	[g_qp_ric],rax
	cmp	rsi,rdx
	jae	.bad
	movzx	r8d,byte [rsi]			; S
	mov	cl,7
	call	qp_int
	jc	.bad
	mov	r9,[g_qp_ric]
	test	r8d,0x80
	jnz	.base_neg
	add	r9,rax
	jmp	.base_set
.base_neg:
	sub	r9,rax
	dec	r9
.base_set:
	mov	[g_qp_base],r9
	xor	ebx,ebx				; fields
.line:
	cmp	rsi,rdx
	jae	.done
	cmp	ebx,H3_FIELDS_MAX
	jae	.bad
	imul	r12d,ebx,HP_SIZE
	lea	r12,[g_h3f+r12]
	movzx	eax,byte [rsi]
	test	al,0x80
	jnz	.indexed
	test	al,0x40
	jnz	.name_ref
	test	al,0x20
	jnz	.literal
	test	al,0x10
	jnz	.post_indexed
	; 0000 N index(3), value: a name after the Base
	mov	cl,3
	call	qp_int
	jc	.bad
	add	rax,[g_qp_base]
	jmp	.dyn_name
.post_indexed:					; 0001 index(4): an entry after the Base
	mov	cl,4
	call	qp_int
	jc	.bad
	add	rax,[g_qp_base]
	jmp	.dyn_field
.indexed:					; 1 T index(6)
	test	al,0x40
	jnz	.indexed_static
	mov	cl,6
	call	qp_int
	jc	.bad
	mov	rcx,[g_qp_base]
	dec	rcx
	sub	rcx,rax
	mov	rax,rcx
.dyn_field:
	call	qp_ref				; r8/r9d, r10/r11d
	jc	.bad
	jmp	.field_out
.indexed_static:
	mov	cl,6
	call	qp_int
	jc	.bad
	call	.static				; r8 = name, r9d, r10 = value, r11d
	jc	.bad
.field_out:
	mov	[r12+HP_NAME],r8
	mov	[r12+HP_NLEN],r9d
	mov	[r12+HP_VALUE],r10
	mov	[r12+HP_VLEN],r11d
	inc	ebx
	jmp	.line
.name_ref:					; 01 N T index(4), value
	test	al,0x10
	jnz	.name_static
	mov	cl,4
	call	qp_int
	jc	.bad
	mov	rcx,[g_qp_base]
	dec	rcx
	sub	rcx,rax
	mov	rax,rcx
.dyn_name:
	call	qp_ref
	jc	.bad
	jmp	.name_out
.name_static:
	mov	cl,4
	call	qp_int
	jc	.bad
	call	.static
	jc	.bad
.name_out:
	mov	[r12+HP_NAME],r8
	mov	[r12+HP_NLEN],r9d
	mov	cl,7
	call	qp_string
	jc	.bad
	mov	[r12+HP_VALUE],rax
	mov	[r12+HP_VLEN],ecx
	inc	ebx
	jmp	.line
.literal:					; 001 N H length(3), name, value
	mov	cl,3
	call	qp_string
	jc	.bad
	mov	[r12+HP_NAME],rax
	mov	[r12+HP_NLEN],ecx
	mov	cl,7
	call	qp_string
	jc	.bad
	mov	[r12+HP_VALUE],rax
	mov	[r12+HP_VLEN],ecx
	inc	ebx
	jmp	.line
.done:
	mov	eax,ebx
	jmp	.out
.bad:
	mov	eax,-1
.out:
	pop	r12
	pop	rbx
	ret
; rax = static index: r8/r9d its name, r10/r11d its value; CF past the table
.static:
	cmp	rax,99
	jae	.static_bad
	lea	rcx,[qp_static+rax*8]
	movzx	r8d,word [rcx]
	movzx	r9d,word [rcx+2]
	movzx	r10d,word [rcx+4]
	movzx	r11d,word [rcx+6]
	lea	rax,[qp_pool]
	add	r8,rax
	add	r10,rax
	clc
	ret
.static_bad:
	stc
	ret

; ------------------------------------------------------ the request

; rdi = the stream's entry, its HEADERS payload in g_h3tmp (QST_HBLEN):
; decoded, checked (RFC 9114 4.3), written as an HTTP/1.1 head into a
; new session's queue, whose exchange starts. CF on a connection error;
; a malformed request resets the stream (the connection goes on).
H3N_ENTRY	:= 0
H3N_N		:= 8
H3N_METHOD	:= 16				; q, length at +8
H3N_PATH	:= 32
H3N_AUTH	:= 48
H3N_SCHEME	:= 64
H3N_CLEN	:= 80				; q
H3N_SESS	:= 88				; d
H3N_SIZE	:= 104
h3_request_new:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,H3N_SIZE
	mov	[rsp+H3N_ENTRY],rdi
	lea	rsi,[g_h3tmp]
	mov	edx,[rdi+QST_HBLEN]
	call	qpack_decode
	cmp	eax,-1
	je	.decompression
	mov	[rsp+H3N_N],eax
	cmp	qword [g_qp_ric],0		; the dynamic table used: the client hears
	je	@f
	mov	rax,[rsp+H3N_ENTRY]
	mov	rax,[rax+QST_ID]
	call	qd_section_ack
@@:
	xor	eax,eax
	mov	[rsp+H3N_METHOD],rax
	mov	[rsp+H3N_PATH],rax
	mov	[rsp+H3N_AUTH],rax
	mov	[rsp+H3N_SCHEME],rax
	mov	qword [rsp+H3N_CLEN],-1
	; the fields: pseudo first, each once; names lower case; no
	; connection-specific ones; values without CR, LF or NUL
	xor	ebp,ebp
	xor	r12d,r12d			; a regular field was seen
.check:
	cmp	ebp,[rsp+H3N_N]
	jae	.checked
	imul	eax,ebp,HP_SIZE
	lea	r8,[g_h3f+rax]
	inc	ebp
	mov	rsi,[r8+HP_VALUE]
	mov	ecx,[r8+HP_VLEN]
@@:
	test	ecx,ecx
	jz	@f
	dec	ecx
	movzx	eax,byte [rsi+rcx]
	cmp	al,13
	je	.malformed
	cmp	al,10
	je	.malformed
	test	al,al
	jz	.malformed
	jmp	@b
@@:
	mov	rsi,[r8+HP_NAME]
	mov	ecx,[r8+HP_NLEN]
	test	ecx,ecx
	jz	.malformed
	cmp	byte [rsi],':'
	je	.pseudo
	mov	r12d,1
	xor	edx,edx
@@:
	movzx	eax,byte [rsi+rdx]
	cmp	al,'A'
	jb	.namechar
	cmp	al,'Z'
	jbe	.malformed
.namechar:
	cmp	al,' '
	jbe	.malformed
	cmp	al,':'
	je	.malformed
	cmp	al,127
	jae	.malformed
	inc	edx
	cmp	edx,ecx
	jb	@b
	push	r8
	mov	rdi,rsi
	mov	esi,ecx
	lea	rdx,[h2_stream_new.n_conn]
	call	h2_name_in
	pop	r8
	jnc	.malformed
	mov	rdi,[r8+HP_NAME]
	mov	esi,[r8+HP_NLEN]
	cmp	esi,2
	jne	@f
	cmp	word [rdi],'te'
	jne	@f
	cmp	dword [r8+HP_VLEN],8
	jne	.malformed
	mov	rax,[r8+HP_VALUE]
	mov	rax,[rax]
	mov	rdx,'trailers'
	cmp	rax,rdx
	jne	.malformed
@@:
	cmp	esi,14
	jne	.check
	mov	rax,'content-'
	cmp	[rdi],rax
	jne	.check
	cmp	dword [rdi+8],'leng'
	jne	.check
	cmp	word [rdi+12],'th'
	jne	.check
	cmp	qword [rsp+H3N_CLEN],-1
	jne	.malformed
	mov	rdi,[r8+HP_VALUE]
	mov	esi,[r8+HP_VLEN]
	call	parse_decimal
	jc	.malformed
	mov	[rsp+H3N_CLEN],rax
	jmp	.check
.pseudo:
	test	r12d,r12d
	jnz	.malformed
	xor	edi,edi
	cmp	ecx,7
	jne	@f
	cmp	dword [rsi],':met'
	jne	.not_method
	cmp	word [rsi+4],'ho'
	jne	.not_method
	cmp	byte [rsi+6],'d'
	jne	.not_method
	mov	edi,H3N_METHOD
	jmp	.pseudo_set
.not_method:
	cmp	dword [rsi],':sch'
	jne	.malformed
	cmp	word [rsi+4],'em'
	jne	.malformed
	cmp	byte [rsi+6],'e'
	jne	.malformed
	mov	edi,H3N_SCHEME
	jmp	.pseudo_set
@@:
	cmp	ecx,5
	jne	@f
	cmp	dword [rsi],':pat'
	jne	.malformed
	cmp	byte [rsi+4],'h'
	jne	.malformed
	mov	edi,H3N_PATH
	jmp	.pseudo_set
@@:
	cmp	ecx,10
	jne	.malformed
	mov	rax,':authori'
	cmp	[rsi],rax
	jne	.malformed
	cmp	word [rsi+8],'ty'
	jne	.malformed
	mov	edi,H3N_AUTH
.pseudo_set:
	cmp	qword [rsp+rdi],0
	jne	.malformed
	mov	rax,[r8+HP_VALUE]
	mov	[rsp+rdi],rax
	mov	eax,[r8+HP_VLEN]
	mov	[rsp+rdi+8],rax
	jmp	.check
.checked:
	cmp	qword [rsp+H3N_METHOD],0
	je	.malformed
	cmp	qword [rsp+H3N_SCHEME],0
	je	.malformed
	cmp	qword [rsp+H3N_PATH],0
	je	.malformed
	cmp	qword [rsp+H3N_PATH+8],0
	je	.malformed
	mov	rax,[rsp+H3N_METHOD]		; CONNECT: not over HTTP/3 (yet)
	cmp	qword [rsp+H3N_METHOD+8],7
	jne	@f
	cmp	dword [rax],'CONN'
	je	.malformed
@@:
	; in 0-RTT (which may be replayed): only what is safe to do twice,
	; GET, HEAD, OPTIONS; anything else is refused unprocessed (the client
	; sends it again once the handshake is done)
	mov	rdi,[rsp+H3N_ENTRY]
	cmp	dword [rdi+QST_EARLY],0
	je	.safe
	mov	rax,[rsp+H3N_METHOD]
	mov	rcx,[rsp+H3N_METHOD+8]
	cmp	rcx,3
	jne	@f
	cmp	word [rax],'GE'
	jne	.too_early
	cmp	byte [rax+2],'T'
	je	.safe
	jmp	.too_early
@@:
	cmp	rcx,4
	jne	@f
	cmp	dword [rax],'HEAD'
	je	.safe
	jmp	.too_early
@@:
	cmp	rcx,7
	jne	.too_early
	cmp	dword [rax],'OPTI'
	jne	.too_early
	cmp	dword [rax+3],'IONS'
	jne	.too_early
.safe:
	; a session for it
	call	session_alloc
	cmp	eax,NIL
	je	.refused
	mov	[rsp+H3N_SESS],eax
	call	session_ptr			; the connection's
	mov	r12,rax
	mov	ecx,[r12+S_LST]
	inc	dword [g_ls_active+rcx*4]
	inc	dword [g_active]
	push	rbx
	mov	ebx,[rsp+8+H3N_SESS]
	call	session_ptr
	pop	rbx
	mov	dword [rax+S_STATE],ST_OPEN
	mov	dword [rax+S_INFL],0
	mov	dword [rax+S_FLAGS],SF_H3S
	mov	dword [rax+S_CLIENT],-1
	mov	ecx,[r12+S_LST]
	mov	[rax+S_LST],ecx
	mov	dword [rax+S_TRIES],0
	mov	dword [rax+S_SERVER],NIL
	mov	dword [rax+S_CU_BID],NIL
	mov	dword [rax+S_UC_BID],NIL
	mov	dword [rax+S_PH_KIND],0
	mov	ecx,[g_tick]
	mov	[rax+S_LAST],ecx
	mov	ecx,[r12+S_POOL]
	mov	[rax+S_POOL],ecx
	mov	r13d,[r12+S_GEN]		; the connection's generation
	push	rbx
	mov	ebx,[rsp+8+H3N_SESS]
	mov	edi,ebx
	call	idle_append
	call	peer_ptr			; the client's address: the connection's
	mov	rdi,rax
	mov	ebx,[rsp]
	call	peer_ptr
	mov	rsi,rax
	mov	ecx,P_SIZE
	rep	movsb
	pop	rbx
	; its record
	mov	edi,[rsp+H3N_SESS]
	h3_ptrs	edi
	mov	r14,r8				; the record
	mov	eax,[rsp+H3N_SESS]
	shl	rax,HB_SHIFT
	add	rax,[g_hbuf_base]
	mov	[r14+H_BUF],rax
	mov	rbp,rax				; its buffers
	xor	eax,eax
	mov	[r14+H_INLEN],eax
	mov	[r14+H_INOFF],eax
	mov	[r14+H_FLAGS],eax
	mov	[r14+H_UTLS],eax
	mov	[r14+H_EPOP],eax
	mov	rax,[r15+QC_TS+TS_CERT]		; the certificate the handshake chose
	cmp	dword [r15+QC_HQ],0		; (HTTP/0.9 names no host to check it against)
	je	@f
	xor	eax,eax
@@:
	mov	[r14+H_SNICERT],rax
	mov	[r14+H_H3C],ebx
	mov	[r14+H_H3CG],r13d
	mov	rdi,[rsp+H3N_ENTRY]
	mov	eax,[rdi+QST_ID]
	mov	[r14+H_H3SID],eax
	mov	eax,[r15+QC_HQ]
	shl	eax,4				; H3F_HQ
	mov	[r14+H_H3F],eax
	mov	dword [r14+H_H3PL],0
	mov	eax,[rsp+H3N_SESS]
	mov	[rdi+QST_SESS],eax
	push	rbx
	mov	ebx,eax
	call	session_ptr
	pop	rbx
	mov	eax,[rax+S_GEN]
	mov	[rdi+QST_SGEN],eax
	; its send ring
	lea	rdi,[rbp+HB_H3TX]
	mov	ecx,TX_HDR / 8
	xor	eax,eax
	rep	stosq
	mov	dword [rbp+HB_H3TX+TX_CAPV],TX_CAP
	mov	rax,[r15+QC_PSD_BIDI]
	mov	[rbp+HB_H3TX+TX_MAXSD],rax
	; its queue: the request head
	lea	r13,[rbp+HB_H2Q]
	xor	eax,eax
	mov	[r13+Q_LEN],eax
	mov	[r13+Q_OFF],eax
	mov	[r13+Q_WAIT],eax
	mov	[r13+Q_PEND],eax
	mov	[r13+Q_ENDED],eax
	mov	[r13+Q_CHUNKED],eax
	mov	qword [r13+Q_GOT],0
	mov	rax,[rsp+H3N_CLEN]
	mov	[r13+Q_CLEN],rax
	lea	rdi,[r13+Q_DATA]
	lea	r11,[r13+Q_DATA+H_IN_CAP-8]
	mov	rsi,[rsp+H3N_METHOD]
	mov	rcx,[rsp+H3N_METHOD+8]
	call	h2_stream_new.put
	mov	byte [rdi],' '
	inc	rdi
	mov	rsi,[rsp+H3N_PATH]
	mov	rcx,[rsp+H3N_PATH+8]
	call	h2_stream_new.put
	lea	rsi,[h2_stream_new.h11]
	mov	ecx,h2_stream_new.h11.len
	call	h2_stream_new.put
	cmp	qword [rsp+H3N_AUTH],0
	je	.fields
	lea	rsi,[h2_stream_new.host]
	mov	ecx,h2_stream_new.host.len
	call	h2_stream_new.put
	mov	rsi,[rsp+H3N_AUTH]
	mov	rcx,[rsp+H3N_AUTH+8]
	call	h2_stream_new.put
	mov	word [rdi],0x0A0D
	add	rdi,2
.fields:
	xor	r12d,r12d			; cookies seen
	xor	r8d,r8d
.field:
	cmp	r8d,[rsp+H3N_N]
	jae	.cookies
	imul	eax,r8d,HP_SIZE
	lea	r9,[g_h3f+rax]
	inc	r8d
	mov	rsi,[r9+HP_NAME]
	mov	ecx,[r9+HP_NLEN]
	cmp	byte [rsi],':'
	je	.field
	cmp	ecx,4
	jne	@f
	cmp	dword [rsi],'host'
	jne	@f
	cmp	qword [rsp+H3N_AUTH],0
	jne	.field
@@:
	cmp	ecx,6
	jne	@f
	cmp	dword [rsi],'cook'
	jne	@f
	cmp	word [rsi+4],'ie'
	jne	@f
	inc	r12d
	jmp	.field
@@:
	push	r8
	call	h2_stream_new.put
	mov	word [rdi],0x203A
	add	rdi,2
	mov	rsi,[r9+HP_VALUE]
	mov	ecx,[r9+HP_VLEN]
	call	h2_stream_new.put
	pop	r8
	mov	word [rdi],0x0A0D
	add	rdi,2
	jmp	.field
.cookies:
	test	r12d,r12d
	jz	.framing
	lea	rsi,[h2_stream_new.cookie]
	mov	ecx,h2_stream_new.cookie.len
	call	h2_stream_new.put
	xor	r8d,r8d
	xor	r10d,r10d
.cookie_next:
	cmp	r8d,[rsp+H3N_N]
	jae	.cookie_end
	imul	eax,r8d,HP_SIZE
	lea	r9,[g_h3f+rax]
	inc	r8d
	mov	rsi,[r9+HP_NAME]
	cmp	dword [r9+HP_NLEN],6
	jne	.cookie_next
	cmp	dword [rsi],'cook'
	jne	.cookie_next
	test	r10d,r10d
	jz	@f
	mov	word [rdi],0x203B
	add	rdi,2
@@:
	inc	r10d
	mov	rsi,[r9+HP_VALUE]
	mov	ecx,[r9+HP_VLEN]
	push	r8
	push	r10
	call	h2_stream_new.put
	pop	r10
	pop	r8
	jmp	.cookie_next
.cookie_end:
	mov	word [rdi],0x0A0D
	add	rdi,2
.framing:
	mov	rax,[rsp+H3N_ENTRY]		; in 0-RTT: the backend is told (RFC 8470)
	cmp	dword [rax+QST_EARLY],0
	je	@f
	lea	rsi,[.early_line]
	mov	ecx,.early_line.len
	call	h2_stream_new.put
@@:
	; a body of unknown length (no content-length) goes chunk-framed; the
	; stream may still end with nothing more (then "0" ends it)
	cmp	qword [r13+Q_CLEN],-1
	jne	.end_head
	mov	rax,[rsp+H3N_ENTRY]
	cmp	dword [rax+QST_FINHERE],0
	jne	.end_head			; ended with its head: no body at all
	lea	rsi,[h2_stream_new.chunked]
	mov	ecx,h2_stream_new.chunked.len
	call	h2_stream_new.put
	mov	dword [r13+Q_CHUNKED],1
.end_head:
	cmp	rdi,r11
	ja	.too_large
	mov	word [rdi],0x0A0D
	add	rdi,2
	lea	rax,[r13+Q_DATA]
	sub	rdi,rax
	mov	[r13+Q_LEN],edi
	push	rbx
	mov	ebx,[rsp+8+H3N_SESS]
	call	http_next_request		; reads its head from the queue
	pop	rbx
	qc_regs
	clc
	jmp	.out
.too_large:
	mov	edi,[rsp+H3N_SESS]
	push	rbx
	call	session_close
	pop	rbx
	qc_regs
.malformed:
.refused:
	; the stream is refused (RESET_STREAM H3_MESSAGE_ERROR / REQUEST_REJECTED)
	mov	rdi,[rsp+H3N_ENTRY]
	mov	eax,H3E_MESSAGE
	call	qst_refuse
	clc
	jmp	.out
.too_early:
	mov	rdi,[rsp+H3N_ENTRY]
	mov	eax,H3E_REQ_REJECTED
	call	qst_refuse
	clc
	jmp	.out
.early_line	db 'Early-Data: 1',13,10
.early_line.len = $ - .early_line
.decompression:
	mov	qword [r15+QC_ERR],QPACK_DECOMPRESSION
	or	dword [r15+QC_FLAGS],QF_APP_ERR
	stc
.out:
	lea	rsp,[rsp+H3N_SIZE]
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret

; ---------------------------------------------- the exchange's side

; h_recv on a request stream: ebx = stream, rdi = buffer, esi = room
h3s_recv:
	push	r14
	h_rec
	mov	r14,[r15+H_BUF]
	add	r14,HB_H2Q
	mov	ecx,[r14+Q_LEN]
	sub	ecx,[r14+Q_OFF]
	jnz	.take
	cmp	dword [r14+Q_ENDED],0
	jne	.take
	mov	[r14+Q_DST],rdi
	mov	[r14+Q_ROOM],esi
	mov	dword [r14+Q_WAIT],1
	pop	r14
	ret
.take:
	call	h3s_take
	pop	r14
	ret

; ebx = stream, r15 = record, r14 = queue, rdi = buffer, esi = room: copy
; what fits, deliver it; once the queue drains, the stream's window moves
h3s_take:
	mov	ecx,[r14+Q_LEN]
	mov	eax,[r14+Q_OFF]
	sub	ecx,eax
	cmp	ecx,esi
	jbe	@f
	mov	ecx,esi
@@:
	push	rcx
	lea	rsi,[r14+Q_DATA+rax]
	add	[r14+Q_OFF],ecx
	rep	movsb
	mov	eax,[r14+Q_OFF]
	cmp	eax,[r14+Q_LEN]
	jne	.deliver
	mov	dword [r14+Q_OFF],0
	mov	dword [r14+Q_LEN],0
	call	h3s_credit
.deliver:
	pop	rax
	mov	edx,1
	xor	ecx,ecx
	h_rec
	jmp	hep_queue

; ebx = stream (r15 its record): its queue drained: the client may send a
; window's worth past what came (MAX_STREAM_DATA)
h3s_credit:
	push	r15
	push	r14
	push	rbx
	call	h3s_conn			; rbx = the connection, r15 its QC, r8 the entry
	jc	.out
	test	dword [r15+QC_FLAGS],QF_DONE
	jz	.out
	mov	rax,[r8+QST_RXOFF]
	add	rax,H3_WINDOW
	cmp	rax,[r8+QST_MSD]
	jbe	.out
	sub	rax,[r8+QST_MSD]
	cmp	rax,H3_WINDOW / 2
	jb	.out				; (not worth a frame yet)
	add	rax,[r8+QST_MSD]
	mov	[r8+QST_MSD],rax
	mov	dword [r8+QST_MSDPEND],1
	or	dword [r15+QC_FL2],QF2_MSD
	call	qc_dirty
.out:
	pop	rbx
	pop	r14
	pop	r15
	ret

; ebx = stream session: rbx = its connection's session, r15 = its QC, r8 =
; the stream's entry, r9 = the stream's record; CF when the connection
; is gone or the stream is not in its table. Keeps r12-r14.
h3s_conn:
	mov	r9d,ebx
	shl	r9,H_SHIFT
	add	r9,[g_http_base]
	mov	r10d,ebx			; the stream
	mov	ebx,[r9+H_H3C]
	call	session_ptr
	mov	ecx,[rax+S_GEN]
	cmp	ecx,[r9+H_H3CG]
	jne	.gone
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.gone
	test	dword [rax+S_FLAGS],SF_QC
	jz	.gone
	mov	r15d,ebx
	shl	r15,HB_SHIFT
	add	r15,[g_hbuf_base]
	mov	eax,[r9+H_H3SID]
	push	r9
	push	r10
	call	qst_find
	pop	r10
	pop	r9
	test	r8,r8
	jz	.gone
	cmp	[r8+QST_SESS],r10d
	jne	.gone
	clc
	ret
.gone:
	stc
	ret

; h_send on a request stream: ebx = stream, rdi = bytes, esi = length.
; Into its ring as frames as far as room allows; the rest waits for
; acknowledgements.
h3s_send:
	h_rec
	mov	[r15+H_H3PP],rdi
	mov	[r15+H_H3PL],esi
	or	dword [r15+H_H3F],H3F_SENDING
	jmp	h3s_push

; ebx = stream: what it has to say into its ring; the exchange hears its
; send completed once all of it went in; the connection sends
h3s_push:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	h_rec
	mov	r12,r15				; the record
	mov	r13,[r12+H_BUF]
	add	r13,HB_H3TX			; the ring
	test	dword [r12+H_H3F],H3F_SENDING
	jz	.kick
.more:
	cmp	dword [r12+H_H3PL],0
	je	.sent
	test	dword [r12+H_H3F],H3F_HEAD
	jnz	.body
	; the first bytes: its route is known, so is the room its pool leaves
	cmp	qword [r13+TX_END],0
	jne	.ring_sized
	call	session_ptr
	mov	eax,[rax+S_POOL]
	cmp	eax,[g_plan_pools]		; (okena's own answer has no pool)
	jae	.ring_sized
	imul	rax,rax,PL_SIZE
	lea	rcx,[g_pools]
	mov	edx,[rcx+rax+PL_TLS]
	or	edx,[rcx+rax+PL_H2]
	jnz	.ring_sized
	mov	dword [r13+TX_CAPV],TX_CAP * 2
.ring_sized:
	test	dword [r12+H_H3F],H3F_HQ
	jnz	.hq_head
	call	h3_head_out			; HEADERS from the HTTP/1.1 head; CF: no room
	jc	.kick
	jmp	.more
.hq_head:
	; hq-interop: no head at all, the body follows
	mov	rsi,[r12+H_H3PP]
	mov	ecx,[r12+H_H3PL]
	xor	edx,edx
@@:
	lea	eax,[rdx+4]
	cmp	eax,ecx
	ja	.kick				; (the whole head comes in one send)
	cmp	dword [rsi+rdx],0x0A0D0A0D
	je	@f
	inc	edx
	jmp	@b
@@:
	add	edx,4
	add	[r12+H_H3PP],rdx
	sub	[r12+H_H3PL],edx
	or	dword [r12+H_H3F],H3F_HEAD
	jmp	.more
.body:
	mov	rax,[r13+TX_END]
	sub	rax,[r13+TX_BASE]
	mov	ecx,[r13+TX_CAPV]
	sub	rcx,rax				; room
	test	dword [r12+H_H3F],H3F_HQ
	jnz	.hq_body
	; DATA: a frame header (type, a 4-byte length) and what fits
	sub	rcx,5
	jle	.kick
	mov	eax,[r12+H_H3PL]
	cmp	rcx,rax
	jbe	@f
	mov	ecx,eax
@@:
	push	rcx
	mov	byte [g_h3tmp],0		; DATA
	mov	eax,ecx
	or	eax,0x80000000
	bswap	eax
	mov	[g_h3tmp+1],eax
	lea	rsi,[g_h3tmp]
	mov	ecx,5
	call	h3tx_put
	pop	rcx
	mov	rsi,[r12+H_H3PP]
	add	[r12+H_H3PP],rcx
	sub	[r12+H_H3PL],ecx
	call	h3tx_put
	jmp	.more
.hq_body:
	test	rcx,rcx
	jle	.kick
	mov	eax,[r12+H_H3PL]
	cmp	rcx,rax
	jbe	@f
	mov	ecx,eax
@@:
	mov	rsi,[r12+H_H3PP]
	add	[r12+H_H3PP],rcx
	sub	[r12+H_H3PL],ecx
	call	h3tx_put
	jmp	.more
.sent:
	and	dword [r12+H_H3F],not H3F_SENDING
	xor	eax,eax
	mov	edx,2
	xor	ecx,ecx
	call	hep_queue			; (ebx = the stream)
.kick:
	call	h3s_conn
	jc	.out
	call	qc_dirty
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rsi = bytes, ecx = length (room checked): at the ring's end (r13)
h3tx_put:
	test	ecx,ecx
	jz	.out
	mov	rax,[r13+TX_END]
	mov	edx,[r13+TX_CAPV]
	dec	edx
	and	eax,edx
	inc	edx
	sub	edx,eax				; to the wrap
	cmp	ecx,edx
	jbe	@f
	push	rcx
	sub	[rsp],edx
	lea	rdi,[r13+TX_DATA+rax]
	mov	ecx,edx
	add	[r13+TX_END],rcx
	rep	movsb
	pop	rcx
	xor	eax,eax
@@:
	lea	rdi,[r13+TX_DATA+rax]
	add	[r13+TX_END],rcx
	rep	movsb
.out:
	ret

; r12 = stream record, r13 = its ring: the HTTP/1.1 head at H_H3PP into a
; HEADERS frame (QPACK: :status by static name, the fields literal, no
; Huffman). CF when the ring has no room for it yet.
h3_head_out:
	push	rbx
	push	rbp
	mov	rsi,[r12+H_H3PP]
	mov	ecx,[r12+H_H3PL]
	xor	edx,edx
.find:
	lea	eax,[rdx+4]
	cmp	eax,ecx
	ja	.broken
	cmp	dword [rsi+rdx],0x0A0D0A0D
	je	.found
	inc	edx
	jmp	.find
.found:
	lea	ebp,[rdx+4]			; the head's length
	cmp	ebp,13
	jb	.broken
	lea	rdi,[g_h3tmp+8]			; the field section (the frame header after)
	mov	word [rdi],0			; Required Insert Count 0, Delta Base 0
	add	rdi,2
	; :status: literal with static name reference 24 (01 N=0 T=1 index)
	mov	byte [rdi],0x5F
	mov	byte [rdi+1],24 - 15
	mov	byte [rdi+2],3
	mov	ax,[rsi+9]
	mov	[rdi+3],ax
	mov	al,[rsi+11]
	mov	[rdi+5],al
	add	rdi,6
	movzx	ebx,byte [rsi+9]		; '1': an informational head
	; the fields
	xor	ecx,ecx
@@:
	cmp	word [rsi+rcx],0x0A0D
	je	@f
	inc	ecx
	jmp	@b
@@:
	add	ecx,2
.line:
	lea	eax,[rcx+2]
	cmp	eax,ebp
	jae	.block
	mov	edx,ecx
@@:
	cmp	byte [rsi+rdx],':'
	je	@f
	cmp	byte [rsi+rdx],13
	je	.broken
	inc	edx
	jmp	@b
@@:
	mov	r8d,edx				; the name's end
	inc	edx
@@:
	cmp	byte [rsi+rdx],' '
	jne	@f
	inc	edx
	jmp	@b
@@:
	mov	r10d,edx			; the value's start
@@:
	cmp	word [rsi+rdx],0x0A0D
	je	@f
	inc	edx
	jmp	@b
@@:
	; lower case the name in place
	push	rcx
@@:
	cmp	ecx,r8d
	jae	@f
	movzx	eax,byte [rsi+rcx]
	lea	r11d,[rax-'A']
	cmp	r11d,25
	ja	.lc
	or	byte [rsi+rcx],0x20
.lc:
	inc	ecx
	jmp	@b
@@:
	pop	rcx
	; skip connection-specific fields
	push	rsi
	push	rdx
	push	rcx
	push	rdi
	push	r8
	push	r10
	lea	rdi,[rsi+rcx]
	mov	esi,r8d
	sub	esi,ecx
	lea	rdx,[h2_stream_new.n_conn]
	call	h2_name_in
	pop	r10
	pop	r8
	pop	rdi
	pop	rcx
	pop	rdx
	pop	rsi
	jnc	.next_line
	lea	rax,[g_h3tmp+20480-600]
	cmp	rdi,rax
	ja	.broken
	; a literal field line, literal name
	push	rsi
	push	rcx
	push	rdx
	push	r8
	push	r10
	mov	r9d,edx
	sub	r9d,r10d			; value length
	lea	r8,[rsi+r10]			; value
	mov	eax,r8d
	lea	rax,[rsi+rcx]			; name
	mov	edx,[rsp+8]			; name end (r8)
	sub	edx,ecx
	mov	rsi,rax
	mov	ecx,edx
	call	h3_lit
	pop	r10
	pop	r8
	pop	rdx
	pop	rcx
	pop	rsi
.next_line:
	lea	ecx,[rdx+2]
	jmp	.line
.block:
	; the frame: HEADERS, its length (4-byte varint), the section
	lea	rax,[g_h3tmp+8]
	mov	rcx,rdi
	sub	rcx,rax				; the section's length
	mov	rax,[r13+TX_END]
	sub	rax,[r13+TX_BASE]
	mov	edx,[r13+TX_CAPV]
	sub	rdx,rax
	lea	rax,[rcx+5]
	cmp	rax,rdx
	ja	.full
	mov	byte [g_h3tmp+3],1		; HEADERS
	mov	eax,ecx
	or	eax,0x80000000
	bswap	eax
	mov	[g_h3tmp+4],eax
	lea	rsi,[g_h3tmp+3]
	add	ecx,5
	call	h3tx_put
	mov	rsi,[r12+H_H3PP]
	add	[r12+H_H3PP],rbp
	sub	[r12+H_H3PL],ebp
	cmp	bl,'1'
	je	@f
	or	dword [r12+H_H3F],H3F_HEAD
@@:
	clc
	jmp	.out
.broken:
	; not a head we wrote (cannot happen): dropped
	mov	dword [r12+H_H3PL],0
	or	dword [r12+H_H3F],H3F_HEAD
	clc
	jmp	.out
.full:
	stc
.out:
	pop	rbp
	pop	rbx
	ret

; rdi = out, rsi = name, ecx = its length, r8 = value, r9d = its length:
; a QPACK literal field line with a literal name (001 N=0 H=0, the name's
; length in 3 bits; the value's in 7, no Huffman). rdi past it. Clobbers
; rax, rcx, rdx, rsi, r10.
h3_lit:
	push	rsi
	push	rcx
	mov	eax,ecx
	mov	cl,3
	mov	dl,0x20
	call	hp_put_int
	pop	rcx
	pop	rsi
	rep	movsb
	mov	eax,r9d
	mov	cl,7
	xor	edx,edx
	call	hp_put_int
	mov	rsi,r8
	mov	ecx,r9d
	rep	movsb
	ret

; ebx = stream: its exchange is over (proxy.inc, as h2s_finish): trailers
; when the response had them, then FIN; the session goes once all of it
; is acknowledged
h3s_finish:
	push	r12
	push	r13
	h_rec
	mov	r12,r15
	mov	r13,[r12+H_BUF]
	add	r13,HB_H3TX
	or	dword [r12+H_H3F],H3F_FINISH
	test	dword [r12+H_H3F],H3F_HQ
	jnz	.fin				; (hq-interop has no trailers)
	cmp	dword [r12+H_RCK+CK_TLEN],0
	je	.fin
	call	h3_trailers_out
.fin:
	mov	dword [r13+TX_FIN],1
	pop	r13
	pop	r12
	push	rbx
	push	r15
	call	h3s_conn
	jc	@f
	call	qc_dirty
@@:
	pop	r15
	pop	rbx
	ret

; r12 = record, r13 = ring: the response's trailers (HB_TRAIL lines) as a
; HEADERS frame, when the ring has room (else they are dropped)
h3_trailers_out:
	push	rbx
	mov	rbx,[r12+H_BUF]
	add	rbx,HB_TRAIL
	mov	r11d,[r12+H_RCK+CK_TLEN]
	lea	rdi,[g_h3tmp+8]
	mov	word [rdi],0
	add	rdi,2
	xor	ecx,ecx
.line:
	cmp	ecx,r11d
	jae	.block
	mov	edx,ecx
@@:
	cmp	edx,r11d
	jae	.block
	cmp	byte [rbx+rdx],':'
	je	@f
	movzx	eax,byte [rbx+rdx]
	lea	r8d,[rax-'A']
	cmp	r8d,25
	ja	.lc
	or	byte [rbx+rdx],0x20
.lc:
	inc	edx
	jmp	@b
@@:
	mov	r8d,edx				; the name's end
	inc	edx
@@:
	cmp	byte [rbx+rdx],' '
	jne	@f
	inc	edx
	jmp	@b
@@:
	mov	r10d,edx
@@:
	cmp	edx,r11d
	jae	.block
	cmp	byte [rbx+rdx],13
	je	@f
	inc	edx
	jmp	@b
@@:
	lea	rax,[g_h3tmp+20480-600]
	cmp	rdi,rax
	ja	.block
	push	rdx
	push	r11
	mov	r9d,edx
	sub	r9d,r10d
	lea	rsi,[rbx+rcx]
	lea	r10,[rbx+r10]
	mov	eax,r8d
	sub	eax,ecx
	mov	ecx,eax
	mov	r8,r10
	call	h3_lit
	pop	r11
	pop	rdx
	lea	ecx,[rdx+2]			; past CR LF
	jmp	.line
.block:
	lea	rax,[g_h3tmp+8]
	mov	rcx,rdi
	sub	rcx,rax
	mov	rax,[r13+TX_END]
	sub	rax,[r13+TX_BASE]
	mov	edx,[r13+TX_CAPV]
	sub	rdx,rax
	lea	rax,[rcx+5]
	cmp	rax,rdx
	ja	.out
	mov	byte [g_h3tmp+3],1
	mov	eax,ecx
	or	eax,0x80000000
	bswap	eax
	mov	[g_h3tmp+4],eax
	lea	rsi,[g_h3tmp+3]
	add	ecx,5
	call	h3tx_put
.out:
	pop	rbx
	ret

; session_close of a request stream: out of its connection's table; a
; response cut short is a RESET_STREAM. ebx = stream; keeps rbx, r12.
h3s_closing:
	push	rbx
	push	r12
	push	r15
	h_rec
	mov	r12d,[r15+H_H3F]
	call	h3s_conn
	jc	.out
	mov	dword [r8+QST_KIND],QSK_FREE
	inc	qword [r15+QC_SDONE]
	mov	rax,[r15+QC_MAXS_OURS]		; (MAX_STREAMS: when half are used: a
	sub	rax,[r15+QC_SDONE]		; packet each answer otherwise)
	cmp	rax,50
	jge	.maxs_kept
	or	dword [r15+QC_FL2],QF2_MAXS
.maxs_kept:
	test	r12d,H3F_FINISH
	jnz	.done
	mov	ecx,[r15+QC_RSTN]		; cut short: RESET_STREAM
	cmp	ecx,8
	jae	.done
	shl	ecx,4
	mov	rax,[r8+QST_ID]
	mov	[r15+QC_RST+rcx],rax
	mov	qword [r15+QC_RST+rcx+8],H3E_REQ_CANCELLED
	inc	dword [r15+QC_RSTN]
.done:
	call	qc_dirty
.out:
	pop	r15
	pop	r12
	pop	rbx
	ret

; ------------------------------------------------------- sending

; r15 = connection: eax = our control stream's length (its type and
; SETTINGS, and GOAWAY when queued). Keeps all but rax, rcx.
qc_ctl_len:
	xor	eax,eax
	cmp	dword [r15+QC_HQ],0		; hq-interop: no control stream
	jne	.out
	mov	eax,6
	mov	rcx,[r15+QC_GOAWAY]
	test	rcx,rcx
	jz	.out
	dec	rcx
	add	eax,3				; type, length, a 1-byte id
	cmp	rcx,64
	jb	.out
	inc	eax
	cmp	rcx,16384
	jb	.out
	add	eax,2
	cmp	rcx,1 shl 30
	jb	.out
	add	eax,4
.out:
	ret

; ebx, r15 = connection, on the QUIC tick while the worker drains: GOAWAY
; once (the first stream not taken: none past those already open), then
; CONNECTION_CLOSE (H3_NO_ERROR) once it is delivered and no request is
; left
qc_drain:
	cmp	dword [r15+QC_STATE],QCS_EST
	jne	.out
	test	dword [r15+QC_FLAGS],QF_DONE
	jz	.out
	cmp	qword [r15+QC_GOAWAY],0
	jne	.wait
	mov	rax,[r15+QC_SMAX]
	inc	rax
	mov	[r15+QC_GOAWAY],rax
	jmp	qc_dirty
.wait:
	call	qc_ctl_len
	cmp	[r15+QC_CTL_ACKED],eax
	jb	.out
	lea	r8,[r15+QC_QST]
	mov	ecx,QST_N
.next:
	cmp	dword [r8+QST_KIND],QSK_REQ
	je	.out				; a request is still going
	add	r8,QST_SIZE
	dec	ecx
	jnz	.next
	mov	qword [r15+QC_ERR],H3E_NO_ERROR
	or	dword [r15+QC_FLAGS],QF_APP_ERR
	jmp	qc_fail
.out:
	ret

; eax = 1 when there is something to send on the streams (ebx, r15 =
; the connection)
qc_app_pending:
	test	dword [r15+QC_FLAGS],QF_DONE
	jz	.none
	call	qc_ctl_len
	cmp	[r15+QC_CTL_SENT],eax
	jb	.yes
	test	dword [r15+QC_FL2],QF2_MAXD or QF2_MAXS or QF2_PATH or QF2_MSD or QF2_NCID
	jnz	.yes
	mov	rax,[r15+QC_QD_SENT]		; the decoder stream's bytes go with an
	cmp	rax,[r15+QC_QD_END]		; ACK held for the answer, not before it
	jae	.no_decoder
	cmp	dword [r15+QC_PS+QL_APP*PS_SIZE+PS_ACKQ],1
	jne	.yes
	mov	rax,[r15+QC_PS+QL_APP*PS_SIZE+PS_ACKAT]
	test	rax,rax
	jz	.no_decoder
	cmp	rax,[g_qnow]
	jbe	.yes
.no_decoder:
	cmp	dword [r15+QC_RSTN],0
	jne	.yes
	lea	r8,[r15+QC_QST]
	mov	ecx,QST_N
.next:
	cmp	dword [r8+QST_KIND],QSK_REQ
	jne	.skip
	push	rcx
	push	r8
	call	qst_sendable			; eax = bytes it may send, edx = FIN to send
	pop	r8
	pop	rcx
	or	eax,edx
	jnz	.yes
.skip:
	add	r8,QST_SIZE
	dec	ecx
	jnz	.next
.none:
	xor	eax,eax
	ret
.yes:
	mov	eax,1
	ret

; r8 = a request stream's entry: eax = how many new or lost bytes it may
; send now (its ring, its window, the connection's), edx = 1 when only its
; FIN is left to send; r9 = its ring (0 when its session is gone)
qst_sendable:
	xor	eax,eax
	xor	edx,edx
	xor	r9d,r9d
	mov	r10d,[r8+QST_SESS]
	cmp	r10d,NIL
	je	.out
	mov	r11d,r10d
	shl	r11,S_SHIFT
	add	r11,[g_sess_base]
	mov	ecx,[r11+S_GEN]
	cmp	ecx,[r8+QST_SGEN]
	jne	.out
	push	r8
	h3_ptrs	r10d				; (takes r8, r9)
	pop	r8
	lea	r9,[r9+HB_H3TX]
	mov	rax,[r9+TX_END]
	cmp	rax,[r9+TX_MAXSD]
	jbe	@f
	mov	rax,[r9+TX_MAXSD]
@@:
	sub	rax,[r9+TX_SENT]
	jg	@f
	xor	eax,eax
@@:
	; new bytes count against the connection's window
	mov	rcx,[r9+TX_SENT]
	add	rcx,rax
	sub	rcx,[r9+TX_HIGH]
	jle	.conn_ok
	mov	r10,[r15+QC_MAXD_PEER]
	sub	r10,[r15+QC_DSENT]
	cmp	rcx,r10
	jbe	.conn_ok
	sub	rcx,r10				; over by this much
	sub	rax,rcx
	jg	.conn_ok
	xor	eax,eax
.conn_ok:
	test	eax,eax
	jnz	.out
	cmp	dword [r9+TX_FIN],0
	je	.out
	cmp	dword [r9+TX_FINSENT],0
	jne	.out
	mov	rcx,[r9+TX_SENT]
	cmp	rcx,[r9+TX_END]
	jne	.out
	mov	edx,1
.out:
	ret

; rdi = where, rsi = the limit (ebx, r15 = connection): control frames,
; our control stream, one request stream's data. rdi past them; eax = 1
; when any was written.
qc_app_write:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r14,rsi				; the limit
	xor	r12d,r12d			; written
	xor	eax,eax
	mov	[r15+QC_LW_LEN],eax
	mov	[r15+QC_LW_FIN],eax
	mov	[r15+QC_LW_CTL],eax
	mov	[r15+QC_LW_FR],eax
	mov	dword [r15+QC_LW_SESS],NIL
	; control frames
	mov	rax,r14
	sub	rax,rdi
	cmp	rax,64
	jb	.streams
	test	dword [r15+QC_FL2],QF2_MAXD
	jz	@f
	mov	byte [rdi],0x10			; MAX_DATA
	inc	rdi
	mov	rax,[r15+QC_MAXD_OURS]
	call	qv_write
	and	dword [r15+QC_FL2],not QF2_MAXD
	or	dword [r15+QC_LW_FR],QF2_MAXD
	mov	r12d,1
@@:
	test	dword [r15+QC_FL2],QF2_MAXS
	jz	@f
	mov	byte [rdi],0x12			; MAX_STREAMS (bidi)
	inc	rdi
	mov	rax,[r15+QC_SDONE]
	add	rax,100
	mov	[r15+QC_MAXS_OURS],rax
	call	qv_write
	and	dword [r15+QC_FL2],not QF2_MAXS
	or	dword [r15+QC_LW_FR],QF2_MAXS
	mov	r12d,1
@@:
	test	dword [r15+QC_FL2],QF2_PATH
	jz	@f
	mov	byte [rdi],0x1B			; PATH_RESPONSE
	mov	rax,[r15+QC_PCHAL]
	mov	[rdi+1],rax
	add	rdi,9
	and	dword [r15+QC_FL2],not QF2_PATH
	mov	r12d,1
@@:

	; NEW_CONNECTION_IDs: sequence 1.., none retired, 8 bytes, the reset token
	test	dword [r15+QC_FL2],QF2_NCID
	jz	.ncid_done
	mov	rax,r14
	sub	rax,rdi
	cmp	rax,64
	jb	.ncid_done
	and	dword [r15+QC_FL2],not QF2_NCID
	or	dword [r15+QC_LW_FR],QF2_NCID
	mov	ecx,[r15+QC_PACID]		; (sequence 1 went in preferred_address)
.ncid:
	cmp	ecx,[r15+QC_NCIDS]
	jae	.ncid_end
	lea	eax,[rcx+1]
	mov	byte [rdi],0x18
	mov	[rdi+1],al			; sequence (< 64)
	mov	word [rdi+2],0x0800		; retire prior to 0, length 8
	mov	rax,[r15+QC_CIDS+rcx*8]
	mov	[rdi+4],rax
	push	rcx
	lea	rsi,[r15+QC_CIDS+rcx*8]
	add	rdi,12
	push	rdi
	call	qs_reset_token
	pop	rdi
	add	rdi,16
	pop	rcx
	inc	ecx
	jmp	.ncid
.ncid_end:
	mov	r12d,1
.ncid_done:
	; RESET_STREAMs
	mov	ecx,[r15+QC_RSTN]
	test	ecx,ecx
	jz	.msd
	mov	rax,r14
	sub	rax,rdi
	cmp	rax,32 * 8
	jb	.msd
	xor	r13d,r13d
.rst:
	cmp	r13d,[r15+QC_RSTN]
	jae	.rst_done
	mov	eax,r13d
	shl	eax,4
	push	rax
	mov	byte [rdi],4
	inc	rdi
	mov	rax,[r15+QC_RST+rax]
	call	qv_write			; id
	mov	rax,[rsp]
	mov	rax,[r15+QC_RST+rax+8]
	call	qv_write			; error
	pop	rax
	mov	byte [rdi],0			; final size: what we sent (none counted)
	inc	rdi
	inc	r13d
	jmp	.rst
.rst_done:
	mov	dword [r15+QC_RSTN],0
	mov	r12d,1
.msd:
	test	dword [r15+QC_FL2],QF2_MSD
	jz	.control
	and	dword [r15+QC_FL2],not QF2_MSD
	lea	r8,[r15+QC_QST]
	mov	ecx,QST_N
.msd_next:
	cmp	dword [r8+QST_MSDPEND],0
	je	.msd_skip
	mov	rax,r14
	sub	rax,rdi
	cmp	rax,24
	jb	.msd_later
	mov	dword [r8+QST_MSDPEND],0
	mov	byte [rdi],0x11			; MAX_STREAM_DATA
	inc	rdi
	push	rcx
	mov	rax,[r8+QST_ID]
	call	qv_write
	mov	rax,[r8+QST_MSD]
	call	qv_write
	pop	rcx
	or	dword [r15+QC_LW_FR],QF2_MSD
	mov	r12d,1
	jmp	.msd_skip
.msd_later:
	or	dword [r15+QC_FL2],QF2_MSD
.msd_skip:
	add	r8,QST_SIZE
	dec	ecx
	jnz	.msd_next
.control:
	; our control stream (id 3): its type (0), SETTINGS (the QPACK table's
	; capacity, no blocked streams), then GOAWAY when draining; all of it
	; again when some was lost
	call	qc_ctl_len
	cmp	[r15+QC_CTL_SENT],eax
	jae	.streams
	mov	[r15+QC_CTL_SENT],eax
	mov	[r15+QC_LW_CTL],eax
	mov	dword [rdi],0x0000030E		; STREAM, OFF|LEN: id 3, offset 0,
	mov	[rdi+3],al			; the length
	mov	dword [rdi+4],0x01030400	; 00, SETTINGS of 3 bytes: id 1,
	mov	word [rdi+8],(QP_CAPACITY shr 8) or 0x40 or ((QP_CAPACITY and 255) shl 8)	; 2-byte value
	add	rdi,10
	mov	rax,[r15+QC_GOAWAY]
	test	rax,rax
	jz	@f
	dec	rax
	mov	byte [rdi],7			; GOAWAY: the first stream not taken
	push	rdi
	add	rdi,2
	call	qv_write
	pop	rcx
	mov	rax,rdi
	sub	rax,rcx
	sub	eax,2
	mov	[rcx+1],al
@@:
	mov	r12d,1
.streams:
	; our QPACK decoder stream (id 7)
	mov	rax,[r15+QC_QD_END]
	sub	rax,[r15+QC_QD_SENT]
	jbe	.qd_done
	mov	rcx,r14
	sub	rcx,rdi
	sub	rcx,1 + 1 + 8 + 2
	jle	.qd_done
	cmp	rax,rcx
	jbe	@f
	mov	rax,rcx
@@:
	mov	r10,rax				; how many
	mov	word [rdi],0x070E		; STREAM, OFF|LEN: id 7
	add	rdi,2
	mov	rax,[r15+QC_QD_SENT]
	call	qv_write
	mov	rax,r10
	call	qv_write
	mov	rsi,[r15+QC_QD_SENT]
	sub	rsi,[r15+QC_QD_BASE]
	lea	rsi,[r15+QC_QDB+rsi]
	mov	rcx,r10
	rep	movsb
	add	[r15+QC_QD_SENT],r10
	mov	eax,dword [r15+QC_QD_SENT]	; (its record: control length, this end)
	shl	eax,8
	or	[r15+QC_LW_CTL],eax
	mov	r12d,1
.qd_done:
	; one request stream's data, the next with something after the last
	mov	r13d,QST_N
	mov	ecx,[r15+QC_RR]
.pick:
	inc	ecx
	cmp	ecx,QST_N
	jb	@f
	xor	ecx,ecx
@@:
	imul	eax,ecx,QST_SIZE
	lea	r8,[r15+QC_QST+rax]
	cmp	dword [r8+QST_KIND],QSK_REQ
	jne	.pick_next
	push	rcx
	call	qst_sendable
	pop	rcx
	test	r9,r9
	jz	.pick_next
	mov	r10d,eax
	or	r10d,edx
	jnz	.write
.pick_next:
	dec	r13d
	jnz	.pick
	jmp	.done
.write:
	mov	[r15+QC_RR],ecx
	; STREAM, OFF|LEN(|FIN): id, offset (8-byte varint), length (2 bytes)
	mov	rcx,r14
	sub	rcx,rdi
	sub	rcx,1 + 8 + 8 + 2
	jle	.done
	cmp	rax,rcx
	jbe	@f
	mov	eax,ecx
@@:
	mov	r10,rax				; how many
	; FIN with the last byte?
	xor	r11d,r11d
	cmp	dword [r9+TX_FIN],0
	je	@f
	mov	rcx,[r9+TX_SENT]
	add	rcx,r10
	cmp	rcx,[r9+TX_END]
	jne	@f
	mov	r11d,1
@@:
	mov	al,0x0E
	or	al,r11b
	mov	[rdi],al
	inc	rdi
	push	r10
	push	r11
	mov	rax,[r8+QST_ID]
	call	qv_write
	mov	rax,[r9+TX_SENT]
	mov	rcx,0xC000000000000000
	or	rax,rcx
	bswap	rax
	mov	[rdi],rax
	add	rdi,8
	pop	r11
	pop	r10
	mov	eax,r10d
	or	eax,0x4000
	xchg	al,ah
	mov	[rdi],ax
	add	rdi,2
	; the bytes, from the ring (it may wrap)
	mov	rax,[r9+TX_SENT]
	mov	[r15+QC_LW_OFF],rax
	mov	[r15+QC_LW_LEN],r10d
	mov	[r15+QC_LW_FIN],r11d
	mov	eax,[r8+QST_SESS]
	mov	[r15+QC_LW_SESS],eax
	mov	eax,[r8+QST_SGEN]
	mov	[r15+QC_LW_SGEN],eax
	mov	rcx,r10
	mov	rax,[r9+TX_SENT]
	mov	edx,[r9+TX_CAPV]
	dec	edx
	and	eax,edx
	inc	edx
	sub	edx,eax
	cmp	ecx,edx
	jbe	@f
	push	rcx
	lea	rsi,[r9+TX_DATA+rax]
	mov	ecx,edx
	sub	[rsp],rcx
	rep	movsb
	pop	rcx
	xor	eax,eax
@@:
	lea	rsi,[r9+TX_DATA+rax]
	rep	movsb
	add	[r9+TX_SENT],r10
	mov	rax,[r9+TX_SENT]
	sub	rax,[r9+TX_HIGH]
	jle	@f
	add	[r15+QC_DSENT],rax
	mov	rax,[r9+TX_SENT]
	mov	[r9+TX_HIGH],rax
@@:
	test	r11d,r11d
	jz	@f
	mov	dword [r9+TX_FINSENT],1
@@:
	mov	r12d,1
.done:
	mov	eax,r12d
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = the sent packet's record (r15 = connection): what qc_app_write put in it
qc_app_sent:
	mov	eax,[r15+QC_LW_SESS]
	mov	[rdi+SP_SSESS],eax
	mov	eax,[r15+QC_LW_SGEN]
	mov	[rdi+SP_SGEN],eax
	mov	rax,[r15+QC_LW_OFF]
	mov	[rdi+SP_SOFF],rax
	mov	eax,[r15+QC_LW_LEN]
	mov	[rdi+SP_SLEN],eax
	mov	eax,[r15+QC_LW_FIN]
	mov	[rdi+SP_SFIN],eax
	mov	eax,[r15+QC_LW_CTL]
	mov	[rdi+SP_CTL],eax
	mov	eax,[r15+QC_LW_FR]
	mov	[rdi+SP_FR],eax
	mov	dword [r15+QC_LW_SESS],NIL
	mov	dword [r15+QC_LW_LEN],0
	mov	dword [r15+QC_LW_FIN],0
	mov	dword [r15+QC_LW_CTL],0
	mov	dword [r15+QC_LW_FR],0
	ret

; rdi = a sent packet's record: lost. Its stream data and FIN go again
; (from the lowest offset lost), our control stream, its control frames.
qc_app_lost:
	test	dword [rdi+SP_CTL],0xFF
	jz	@f
	mov	dword [r15+QC_CTL_SENT],0
@@:
	test	dword [rdi+SP_CTL],not 0xFF	; the decoder stream's: from what is known
	jz	@f
	mov	rax,[r15+QC_QD_ACK]
	mov	[r15+QC_QD_SENT],rax
@@:
	mov	eax,[rdi+SP_FR]
	and	eax,QF2_MAXD or QF2_MAXS or QF2_MSD or QF2_NCID
	or	[r15+QC_FL2],eax
	test	dword [rdi+SP_FR],QF2_PCHAL	; a challenge lost: again, while the
	jz	@f				; path is still not validated
	cmp	dword [r15+QC_PATHNV],0
	je	@f
	or	dword [r15+QC_FL2],QF2_PCHAL
@@:
	test	eax,QF2_MSD
	jz	.streams
	lea	r8,[r15+QC_QST]			; MAX_STREAM_DATA lost: each request
	mov	ecx,QST_N			; stream's current limit again
.msd:
	cmp	dword [r8+QST_KIND],QSK_REQ
	je	.msd_again
	cmp	dword [r8+QST_KIND],QSK_ENC
	jne	@f
.msd_again:
	mov	dword [r8+QST_MSDPEND],1
@@:
	add	r8,QST_SIZE
	dec	ecx
	jnz	.msd
.streams:
	mov	eax,[rdi+SP_SLEN]
	or	eax,[rdi+SP_SFIN]
	jz	.out
	call	sp_stream_ring			; r9 = the stream's ring, or CF
	jc	.out
	mov	rax,[rdi+SP_SOFF]
	cmp	rax,[r9+TX_SENT]
	jae	@f
	cmp	rax,[r9+TX_BASE]
	jae	.back
	mov	rax,[r9+TX_BASE]
.back:
	mov	[r9+TX_SENT],rax
@@:
	cmp	dword [rdi+SP_SFIN],0
	je	.out
	cmp	dword [r9+TX_FINACKED],0
	jne	.out
	mov	dword [r9+TX_FINSENT],0
.out:
	ret

; rdi = a sent packet's record: r9 = its stream's ring (r8 its record);
; CF when the stream session is gone
sp_stream_ring:
	mov	eax,[rdi+SP_SSESS]
	cmp	eax,NIL
	je	.gone
	mov	ecx,eax
	shl	rcx,S_SHIFT
	add	rcx,[g_sess_base]
	mov	edx,[rcx+S_GEN]
	cmp	edx,[rdi+SP_SGEN]
	jne	.gone
	cmp	dword [rcx+S_STATE],ST_FREE	; alive, whatever its exchange is doing
	je	.gone				; (connecting to a backend again, say)
	cmp	dword [rcx+S_STATE],ST_CLOSING
	je	.gone
	h3_ptrs	eax
	add	r9,HB_H3TX
	clc
	ret
.gone:
	stc
	ret

; rdi = a sent packet's record: acknowledged. Its stream bytes are
; delivered: the ring frees up to the first gap; a stream whose exchange
; is over and whose bytes and FIN are all delivered goes.
qc_app_acked:
	mov	eax,[rdi+SP_CTL]
	mov	ecx,eax
	and	eax,0xFF
	cmp	eax,[r15+QC_CTL_ACKED]
	jbe	@f
	mov	[r15+QC_CTL_ACKED],eax
@@:
	shr	ecx,8				; the decoder stream's end in it
	cmp	rcx,[r15+QC_QD_ACK]
	jbe	@f
	mov	[r15+QC_QD_ACK],rcx
@@:
	mov	eax,[rdi+SP_SLEN]
	or	eax,[rdi+SP_SFIN]
	jz	.out
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	call	sp_stream_ring
	jc	.done
	mov	r13,r9
	push	r8
	cmp	dword [r12+SP_SFIN],0
	je	@f
	mov	dword [r13+TX_FINACKED],1
@@:
	mov	rax,[r12+SP_SOFF]		; [lo, hi)
	mov	edx,[r12+SP_SLEN]
	lea	rdx,[rax+rdx]
	call	tx_acked
	pop	r8
	; room again: a waiting send goes on
	mov	ebx,[r12+SP_SSESS]
	test	dword [r8+H_H3F],H3F_SENDING
	jz	@f
	push	r8
	call	h3s_push
	pop	r8
@@:
	test	dword [r8+H_H3F],H3F_FINISH
	jz	.done
	cmp	dword [r13+TX_FINACKED],0
	je	.done
	mov	rax,[r13+TX_BASE]
	cmp	rax,[r13+TX_END]
	jne	.done
	mov	edi,ebx				; all delivered: the stream session goes
	push	r15
	call	session_close
	pop	r15
.done:
	pop	r13
	pop	r12
	pop	rbx
.out:
	ret

; [rax, rdx) of the ring (r13) acknowledged: merged into its ranges; the
; base moves past those that start at it
tx_acked:
	cmp	rdx,[r13+TX_BASE]
	jbe	.out				; old news
	cmp	rax,[r13+TX_BASE]
	jae	@f
	mov	rax,[r13+TX_BASE]
@@:
	; into the list (unsorted, merged on the way; full: the range is lost,
	; it is sent again and acknowledged then)
	mov	ecx,[r13+TX_NACK]
	lea	r8,[r13+TX_ACK]
	xor	r9d,r9d
.merge:
	cmp	r9d,ecx
	jae	.add
	mov	r10,[r8]			; lo
	mov	r11,[r8+8]			; hi
	cmp	rax,r11
	ja	.next
	cmp	rdx,r10
	jb	.next
	; overlapping or adjacent: absorb it, remove it, start over
	cmp	r10,rax
	jae	@f
	mov	rax,r10
@@:
	cmp	r11,rdx
	jbe	@f
	mov	rdx,r11
@@:
	dec	ecx
	mov	[r13+TX_NACK],ecx
	mov	r10d,ecx
	shl	r10d,4
	mov	r11,[r13+TX_ACK+r10]		; the last into its place
	mov	[r8],r11
	mov	r11,[r13+TX_ACK+r10+8]
	mov	[r8+8],r11
	lea	r8,[r13+TX_ACK]
	xor	r9d,r9d
	jmp	.merge
.next:
	add	r8,16
	inc	r9d
	jmp	.merge
.add:
	cmp	rax,[r13+TX_BASE]
	je	.base
	cmp	ecx,TX_ACKMAX
	jb	@f
	mov	rax,[r13+TX_BASE]		; full: forgotten, so what is not known
	mov	[r13+TX_SENT],rax		; delivered goes again (and is acknowledged)
	ret
@@:
	shl	ecx,4
	mov	[r13+TX_ACK+rcx],rax
	mov	[r13+TX_ACK+rcx+8],rdx
	inc	dword [r13+TX_NACK]
	ret
.base:
	mov	[r13+TX_BASE],rdx
	cmp	[r13+TX_SENT],rdx
	jae	.out
	mov	[r13+TX_SENT],rdx
.out:
	ret
