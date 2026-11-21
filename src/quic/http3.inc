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
H3F_TM		:= S2F_TM			; its head was its connection's H3Q text when
						; made (the parse memo compares it all the same)
assert H3F_TM > H3F_HQ

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
TX_ACKMAX	:= 10
; bytes the ring does not hold: a body in files' memory store (it never
; moves nor is written over), read from there to send and to send again
TX_XPTR		:= 216				; q: where stream offset TX_XLO is
TX_XLO		:= 224				; q: the offsets it covers (TX_XLO = TX_XHI: none)
TX_XHI		:= 232				; q
assert TX_ACK + TX_ACKMAX * 16 <= TX_XPTR
TX_CAPV		:= 248				; d: the ring's size (TX_CAP, or twice that)
TX_HDR		:= 256				; the header's size
; the bytes: the downstream TLS area (a stream session has no TLS of its
; own: the connection's QUIC carries it), 64 KiB, and the upstream TLS and
; HTTP/2 area after it when its pool uses neither, 128 KiB (a power of two
; either way): what a stream may have in flight, a window an RTT
TX_DATA		:= HB_TLS - HB_H3TX		; (the ring in a stream's buffers)
; The headers live with their connection, not in each stream's buffers: one
; for each entry of its stream table (QTH_OFF in its QFX area, qth_of), so
; that looking down the streams that may send reads lines near each other,
; not a cold one far into each stream's 256 KiB. The ring stays in the
; stream's buffers (TX_RING); the header says whose it is (TX_OWN, TX_OWNG)
TX_RING		:= 256				; q: the ring (the stream's HB_TLS)
TX_OWN		:= 264				; d: the stream session it belongs to
TX_OWNG		:= 268				; d: and that session's generation
QTH_SIZE	:= 320
H_H3TXH		:= H_TXP			; a stream's: its header (user-space TLS
						; is its connection's, never its own)
TX_CAP		:= 65536
assert HB_TLS + TX_CAP <= HB_UPTLS
assert HB_TLS + TX_CAP * 2 <= HB_H3TX
assert TX_HDR <= 256
assert HB_U2Q + Q_DATA + Q_CAP <= HB_H3TX

; the connection's stream table
QST_N		:= 256				; (what a client opens, MAX_STREAMS 100, and the
						; answers done but not yet acknowledged)
QST_W		:= QST_N / 64			; qwords of a bit each
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
QSK_CTL		:= 5				; its control stream
QSK_DEC		:= 6				; its QPACK decoder stream
QC_QST		:= QC_QSTAB			; (in the room before the crypto streams)
assert QC_QST + QST_N * QST_SIZE <= QC_CRX
assert QST_W = 4				; (QC_QSTM, QC_QREQ, QE_QSEND: 32 bytes each)

; Which entries are in use, and which hold a request, as bits (QC_QSTM,
; QC_QREQ), kept with every QST_KIND change: a lookup or a send looks at the
; streams there are, not at the table's 256 entries (24 KiB a look, several
; times a packet, was a quarter of a worker's own time under HTTP/3).
; reg = an entry of r15's table; mask = QC_QSTM or QC_QREQ. Keeps all but flags.
macro qst_bit op*, reg*, mask*
	push	rax
	push	rdx
	mov	rax,reg
	sub	rax,r15
	sub	rax,QC_QST
	shr	eax,5
	imul	eax,eax,43691			; / 3: the entry's index (96 bytes each)
	shr	eax,17
	mov	edx,eax
	shr	edx,6
	and	eax,63
	op	[r15+mask+rdx*8],rax
	pop	rdx
	pop	rax
end macro
QC_H3HB		:= QC_STREAMS			; a HEADERS frame split across packets
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
assert RA_N = 64 & RA_ESIZE = 32		; (QC_RAM, ra_bit)
; reg = an entry of QC_RA: its bit in QC_RAM (op bts or btr), kept with every
; RA_USED change, so that a stream frame with nothing held anywhere (nearly
; every one) does not read all 64 entries to find that out. Keeps all but flags.
macro ra_bit op*, reg*
	push	rax
	mov	rax,reg
	sub	rax,r15
	sub	rax,QC_RA
	shr	eax,5
	op	[r15+QC_RAM],rax
	pop	rax
end macro
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
QP_BCAP		:= 4096 - 512
QC_H3X		:= QC_QPB + QP_BCAP		; 512: the client's control stream (below)
QC_QDB		:= QC_H3X + 512
QD_CAP		:= 512
assert QC_QDB + QD_CAP <= 1 shl HB_SHIFT
QC_K0		:= QC_QDB + QD_CAP		; the client's 0-RTT keys (server.inc)
assert QC_K0 and 15 = 0
assert QC_K0 + QK_SIZE <= 1 shl HB_SHIFT
; the client's control stream: which of its critical streams came (1 control,
; 2 encoder, 4 decoder), the highest push ID it allows (+1, 0 none), its last
; GOAWAY (+1, 0 none), and a SETTINGS or a small frame gathered
QC_H3UNI	:= QC_H3X			; d
QC_MAXPUSH	:= QC_H3UNI + 8			; q
QC_GOAWAYRX	:= QC_H3UNI + 16		; q
QC_USEEN	:= QC_H3UNI + 24		; q: its unidirectional streams opened (bit id / 4)
QC_CTLB		:= QC_H3UNI + 32
H3_CTLB_CAP	:= 256				; a SETTINGS frame, at most (more: excessive)
assert QC_CTLB + H3_CTLB_CAP <= QC_H3X + 512
QC_QD_PS	:= QC_CTLB + H3_CTLB_CAP	; q: our decoder stream: a range acknowledged
QC_QD_PE	:= QC_QD_PS + 8			; q  past a gap (its end, 0 none)
assert QC_QD_PE + 8 <= QC_H3X + 512
H3E_STREAM_CREATION := 0x103
H3E_CLOSED_CRITICAL := 0x104
H3E_FRAME_ERROR	:= 0x106
H3E_ID		:= 0x108
H3E_SETTINGS	:= 0x109
H3E_MISSING_SETTINGS := 0x10A
H3E_DECODER_STREAM := 0x202
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
H3_MAXS		:= 100				; requests a client has going at once (its
						; initial_max_streams_bidi, server.inc)
H3_UNI_ROOM	:= 24				; stream entries kept for its unidirectional
						; streams (initial_max_streams_uni 16)
assert QST_N - H3_UNI_ROOM >= 2 * H3_MAXS	; (H3_MAXS going, as many answered)
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
include 'qe.inc'

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
	mov	qword [r15+QC_MAXS_OURS],H3_MAXS
	mov	qword [r15+QC_ACIDL],2		; (the default when it says nothing)
	mov	qword [r15+QC_PMAX],65527
	mov	dword [r15+QC_CTL_SENT],0
	mov	dword [r15+QC_CTL_ACKED],0
	xor	eax,eax
	lea	rdi,[r15+QC_QSTM]		; (QC_QREQ right after it)
	mov	ecx,QST_W * 2
	rep	stosq
	lea	rdi,[r15+QC_QST]		; no streams yet
	mov	ecx,QST_N * QST_SIZE / 8
	xor	eax,eax
	rep	stosq
	lea	rdi,[r15+QC_RA]			; nothing held
	mov	ecx,RA_N * RA_ESIZE / 8
	rep	stosq
	mov	[r15+QC_RAM],rax
	mov	[r15+QC_HBOWN],rax
	call	qe_ptr				; our QPACK encoder: no table until the client
	mov	rdi,rax				; says how large it may be
	mov	ecx,QE_HDR / 8
	xor	eax,eax
	rep	stosq
	mov	dword [r15+QC_H3UNI],eax	; (no critical stream of the client's yet)
	mov	[r15+QC_MAXPUSH],rax
	mov	[r15+QC_GOAWAYRX],rax
	mov	[r15+QC_USEEN],rax
	mov	[r15+QC_QD_PS],rax
	mov	[r15+QC_QD_PE],rax
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
	qst_bit	btr, r12, QC_QSTM
	qst_bit	btr, r12, QC_QREQ
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

; rsi = a field value, ecx = its length: CF when it has a CR, LF or NUL
; (RFC 9114 4.1.2: malformed). Sixteen bytes a compare once it is that long
; (the last sixteen over what came before). Clobbers rax, rcx, rdx, xmm0-xmm4.
field_value_ok:
	cmp	ecx,16
	jb	.bytes
	vpbroadcastb xmm1,byte [.cr]
	vpbroadcastb xmm2,byte [.lf]
	vpxor	xmm3,xmm3,xmm3
	lea	edx,[rcx-16]			; the last block's start
	xor	eax,eax
.block:
	cmp	eax,edx
	cmova	eax,edx
	vmovdqu	xmm0,[rsi+rax]
	vpcmpeqb xmm4,xmm0,xmm1
	vpcmpeqb xmm0,xmm0,xmm2
	vpor	xmm4,xmm4,xmm0
	vmovdqu	xmm0,[rsi+rax]
	vpcmpeqb xmm0,xmm0,xmm3
	vpor	xmm4,xmm4,xmm0
	vpmovmskb ecx,xmm4
	test	ecx,ecx
	jnz	.bad
	cmp	eax,edx
	je	.ok
	add	eax,16
	jmp	.block
.bytes:
	test	ecx,ecx
	jz	.ok
	dec	ecx
	movzx	eax,byte [rsi+rcx]
	cmp	al,13
	je	.bad
	cmp	al,10
	je	.bad
	test	al,al
	jz	.bad
	jmp	.bytes
.ok:
	clc
	ret
.bad:
	stc
	ret
.cr	db 13
.lf	db 10

; rax = stream id (r15 = connection): r8 = its entry, or 0
qst_find:
	; its home entry first (qst_new puts it there when free: ids go up by 4)
	mov	r8,rax
	shr	r8,2
	and	r8d,QST_N - 1
	bt	[r15+QC_QSTM],r8
	jnc	.scan
	imul	r8,r8,QST_SIZE
	lea	r8,[r15+QC_QST+r8]
	cmp	[r8+QST_ID],rax
	jne	.scan
	ret
.scan:
	push	r9
	push	r10
	xor	r10d,r10d			; the qword
.word:
	mov	r9,[r15+QC_QSTM+r10*8]
.bit:
	tzcnt	rcx,r9
	jc	.next_word
	btr	r9,rcx
	mov	r8,r10
	shl	r8,6
	add	r8,rcx
	imul	r8,r8,QST_SIZE
	lea	r8,[r15+QC_QST+r8]
	cmp	[r8+QST_ID],rax
	jne	.bit
	pop	r10
	pop	r9
	ret
.next_word:
	inc	r10d
	cmp	r10d,QST_W
	jb	.word
	xor	r8d,r8d
	pop	r10
	pop	r9
	ret

; ecx = an entry's index: ecx = the next request stream's after it, round
; the table (one there must be: QC_QREQ not empty). Clobbers rax, rdx, r10, r11.
qst_req_after:
	push	r9
	lea	r9,[r15+QC_QREQ]
	call	qst_bit_after
	pop	r9
	ret

; r9 = a bitmap of QST_W qwords (one bit set at least), ecx = an index: ecx
; = the next set bit's after it, round the table (it again when the only
; one). Clobbers rax, rdx, r10, r11.
qst_bit_after:
	inc	ecx
	and	ecx,QST_N - 1
	mov	edx,ecx
	shr	edx,6				; its qword
	and	ecx,63
	mov	r10,[r9+rdx*8]
	mov	r11,-1
	shl	r11,cl
	and	r10,r11				; from it on
	tzcnt	rax,r10
	jnc	.at
	mov	r11d,QST_W			; the others whole, then this one again
.word:
	inc	edx
	and	edx,QST_W - 1
	tzcnt	rax,[r9+rdx*8]
	jnc	.at
	dec	r11d
	jnz	.word
	xor	eax,eax				; (none at all: entry 0)
	xor	edx,edx
.at:
	shl	edx,6
	lea	ecx,[rdx+rax]
	ret

; ecx = an entry's index: ecx = the next one after it whose QE_QSEND bit is
; set, round the table (or the same when none other). Clobbers rax, rdx, r10, r11.
qst_send_after:
	push	r9
	call	qe_ptr
	lea	r9,[rax+QE_QSEND]
	call	qst_bit_after			; (none at all: entry 0, found empty)
	pop	r9
	ret

; rax = stream id: r8 = a free entry for it (zeroed but the id), or 0
qst_new:
	push	rax
	mov	rcx,rax				; its home entry, when free (qst_find)
	shr	rcx,2
	and	ecx,QST_N - 1
	bt	[r15+QC_QSTM],rcx
	jnc	.slot
	push	rdx
	xor	edx,edx				; else the first free
.free_word:
	mov	r8,[r15+QC_QSTM+rdx*8]
	not	r8
	tzcnt	rcx,r8
	jnc	.free_at
	inc	edx
	cmp	edx,QST_W
	jb	.free_word
	pop	rdx
	jmp	.none
.free_at:
	shl	edx,6
	add	ecx,edx
	pop	rdx
.slot:
	imul	r8,rcx,QST_SIZE
	lea	r8,[r15+QC_QST+r8]
	jmp	.take
.none:
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
	je	.stream_count			; MAX_STREAMS: ours to open are few
	cmp	rax,0x13
	je	.stream_count
	cmp	rax,0x14
	je	.one_value			; DATA_BLOCKED
	cmp	rax,0x15
	je	.two_values			; STREAM_DATA_BLOCKED
	cmp	rax,0x16
	je	.stream_count			; STREAMS_BLOCKED
	cmp	rax,0x17
	je	.stream_count
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
	call	qsend_all			; (the connection's window: any of them)
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
	mov	r8,rcx
	call	.ours_only			; (a stream we send on, that exists)
	jc	.state_error
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
	call	qth_of				; rax = its header
	cmp	r13,[rax+TX_MAXSD]
	jbe	.msd_done
	mov	[rax+TX_MAXSD],r13
	call	qsend_set
	call	qc_dirty
.msd_done:
	pop	rdx
	pop	rsi
	jmp	.ok
.stream_count:
	; a count of streams past 2^60 cannot be (RFC 9000 19.11, 19.14)
	mov	dword [r12+QP_ACKEL],1
	call	qv_read
	jc	.encoding
	mov	rcx,1 shl 60
	cmp	rax,rcx
	ja	.encoding
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
	mov	r8,rax
	call	qv_read				; retire prior to
	jc	.encoding
	cmp	rax,r8
	ja	.encoding			; (not past its own sequence)
	cmp	rsi,rdx
	jae	.encoding
	movzx	eax,byte [rsi]			; its length (1 to 20), it, a reset token (16)
	test	eax,eax
	jz	.encoding
	cmp	eax,20
	ja	.encoding
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
	mov	ecx,eax				; one we only send on, or ours that is
	and	ecx,3				; not there: no (RFC 9000 19.4)
	cmp	ecx,1
	je	.state_error
	cmp	ecx,3
	je	.state_error
	jmp	.stream_gone
.stop_sending:
	mov	dword [r12+QP_ACKEL],1
	call	qv_read				; id
	jc	.encoding
	push	rax
	call	qv_read				; error
	jc	.pop_encoding
	pop	rax
	mov	r8,rax				; one we receive only, or ours not there:
	call	.ours_only			; no (RFC 9000 19.5)
	jc	.state_error
.stream_gone:
	; the client gave up on the stream: its exchange stops
	push	rsi
	push	rdx
	call	qst_find
	test	r8,r8
	jz	@f
	cmp	dword [r8+QST_KIND],QSK_ENC	; its control or a QPACK stream reset:
	jae	.critical			; H3_CLOSED_CRITICAL_STREAM
	cmp	dword [r8+QST_KIND],QSK_REQ
	jne	@f
	mov	dword [r8+QST_KIND],QSK_FREE
	qst_bit	btr, r8, QC_QSTM
	qst_bit	btr, r8, QC_QREQ
	inc	qword [r15+QC_SDONE]		; its entry free: MAX_STREAMS counts it
	mov	edi,[r8+QST_SESS]
	cmp	edi,NIL
	je	.gone_unanswered		; (opened, no request on it yet)
	mov	eax,edi
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	mov	ecx,[rax+S_GEN]
	cmp	ecx,[r8+QST_SGEN]
	jne	.gone_unanswered
	mov	eax,edi				; its answer complete: counted then
	shl	rax,H_SHIFT			; (h3s_finish)
	add	rax,[g_http_base]
	test	dword [rax+H_H3F],H3F_FINISH
	jnz	.gone_counted
	inc	qword [r15+QC_SCRED]
.gone_counted:
	call	qc_maxs_check
	push	rbx
	push	r15
	call	session_close			; (h3s_closing: not in the table any more)
	pop	r15
	pop	rbx
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
.gone_unanswered:
	inc	qword [r15+QC_SCRED]		; (no answer to count it done)
	call	qc_maxs_check
@@:
	pop	rdx
	pop	rsi
	jmp	.ok
.critical:
	pop	rdx
	pop	rsi
	mov	qword [r15+QC_ERR],H3E_CLOSED_CRITICAL
	or	dword [r15+QC_FLAGS],QF_APP_ERR
	jmp	.error
.state_error:
	mov	qword [r15+QC_ERR],5		; STREAM_STATE_ERROR
	jmp	.error
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
; r8 = a stream ID a frame about our sending names (MAX_STREAM_DATA,
; STOP_SENDING): CF when we cannot send on it (the client's unidirectional
; ones) or it is ours and not open (we open no bidirectional stream, and
; three unidirectional ones: 3, 7, 11). Keeps all but flags.
.ours_only:
	test	r8d,2
	jz	@f
	test	r8d,1
	jz	.not_ours			; the client's unidirectional: we only read
	cmp	r8,11
	ja	.not_ours
	clc
	ret
@@:
	test	r8d,1
	jnz	.not_ours			; ours, bidirectional: none
	clc
	ret
.not_ours:
	stc
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
	cmp	qword [r15+QC_RAM],0
	je	.kick				; nothing held at all
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
	ra_bit	btr, rdi
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
	ra_bit	btr, rdi
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
	cmp	qword [r15+QC_RAM],0
	je	.unpark				; nothing held: none waits there
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
.unpark:
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
	; one at or past the highest opened of its kind is in no entry: not
	; looked for (each new request's first frame would look at them all)
	mov	rax,r8
	lea	rcx,[r15+QC_SMAX]
	lea	rdx,[r15+QC_UMAX]
	test	eax,2
	cmovnz	rcx,rdx
	cmp	rax,[rcx]
	jae	.new
	call	qst_find
	test	r8,r8
	jnz	.have
.new:
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
	qst_bit	bts, r8, QC_QSTM
	qst_bit	bts, r8, QC_QREQ
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
	jb	.uni_below
	lea	rcx,[rax+4]
	mov	[r15+QC_UMAX],rcx
.uni_open:
	mov	rcx,rax
	shr	rcx,2
	cmp	ecx,64
	jae	@f
	bts	[r15+QC_USEEN],rcx
@@:
	call	qst_new
	test	r8,r8
	jz	.ok				; (no room: its bytes are not needed)
	mov	dword [r8+QST_KIND],QSK_UT
	qst_bit	bts, r8, QC_QSTM
	mov	qword [r8+QST_MSD],65536	; (initial_max_stream_data_uni)
	jmp	.have
.uni_below:
	; below the highest: done with, or not opened yet (a higher one opened
	; it, RFC 9000 3.2: a client's encoder stream 6 after its decoder 10,
	; whose inserts were dropped and never acknowledged, so the client
	; never used the table)
	mov	rcx,rax
	shr	rcx,2
	cmp	ecx,64
	jae	.ok
	bt	[r15+QC_USEEN],rcx
	jc	.ok
	jmp	.uni_open
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
	cmp	dword [rsp+QI_FIN],0		; a control or QPACK stream that ends:
	je	.ok				; H3_CLOSED_CRITICAL_STREAM
	cmp	dword [r12+QST_KIND],QSK_ENC
	jb	.ok
	mov	qword [r15+QC_ERR],H3E_CLOSED_CRITICAL
	or	dword [r15+QC_FLAGS],QF_APP_ERR
	jmp	.error
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
	ra_bit	btr, rdi
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
	ra_bit	bts, rdi
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
	cmp	r8,0x0D				; a control stream's frames (CANCEL_PUSH,
	je	.unexpected			; SETTINGS, PUSH_PROMISE, GOAWAY,
	cmp	r8,9				; MAX_PUSH_ID) and HTTP/2's types: not on
	ja	@f				; a request stream (RFC 9114 7.2)
	cmp	r8,2
	jae	.unexpected
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
	; a HEADERS frame larger than we gather: that stream alone is refused
	; (H3_EXCESSIVE_LOAD), what more it sends ignored; the connection goes on
	; (nothing of QPACK's table changes in a field section)
	mov	rdi,r12
	mov	eax,H3E_EXCESSIVE
	call	qst_refuse
	jmp	.done
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
	qst_bit	btr, rdi, QC_QREQ
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
	ra_bit	bts, rdi
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
	jnc	@f
	cmp	eax,HPE_TOO_BIG
	jne	.bad
	mov	dword [g_qp_big],1		; (no room: larger than we take, not malformed)
	jmp	.bad
@@:
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
	g_qp_big	dd ?			; the section is larger than we take
	g_qd_wlen	dd ?			; qc_app_write: our decoder stream's bytes in the packet
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
	jz	.stuck
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
.stuck:
	; full of bytes not acknowledged as far as they go (one past a gap
	; that was not lost): all of them again, which acknowledges them in order
	mov	rax,[r15+QC_QD_ACK]
	mov	[r15+QC_QD_SENT],rax
	mov	qword [r15+QC_QD_PE],0
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

; rdi = the client's control stream, rsi = bytes in order, rcx = how many
; (RFC 9114 6.2.1, 7.2): SETTINGS first and once, valid; GOAWAY never up,
; MAX_PUSH_ID never down, CANCEL_PUSH only of a push it allowed; no DATA,
; HEADERS, PUSH_PROMISE or HTTP/2 type; other frames skipped, however long,
; never gathered. CF on an error (QC_ERR set).
h3_ctl_bytes:
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
	mov	eax,[r12+QST_FHAVE]		; a frame header: type, length
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
	jc	.next
	mov	r8,rax
	call	qv_read
	jc	.next
	mov	dword [r12+QST_FHAVE],0
	mov	[r12+QST_FTYPE],r8
	mov	[r12+QST_FLEFT],rax
	mov	dword [r12+QST_HBLEN],0
	cmp	dword [r12+QST_PHASE],0
	jne	.later_frame
	cmp	r8,4				; the first: SETTINGS
	jne	.missing
	mov	dword [r12+QST_PHASE],1
	cmp	rax,H3_CTLB_CAP
	ja	.excessive
	jmp	.sized
.later_frame:
	cmp	r8,4				; a second SETTINGS
	je	.unexpected
	cmp	r8,0x0D				; MAX_PUSH_ID
	je	.small
	cmp	r8,9
	ja	.sized				; another type: skipped
	cmp	r8,3				; CANCEL_PUSH
	je	.small
	cmp	r8,7				; GOAWAY
	je	.small
	jmp	.unexpected			; DATA, HEADERS, PUSH_PROMISE, HTTP/2's
.small:
	cmp	rax,16				; (one varint: a frame that says more
	ja	.excessive			; is not buffered)
.sized:
	test	rax,rax
	jnz	.next
	jmp	.frame_end
.payload:
	mov	rcx,r14
	sub	rcx,r13
	cmp	rcx,[r12+QST_FLEFT]
	jbe	@f
	mov	rcx,[r12+QST_FLEFT]
@@:
	sub	[r12+QST_FLEFT],rcx
	mov	rax,[r12+QST_FTYPE]
	cmp	rax,0x0D
	je	.gather
	cmp	rax,9
	ja	.skip
	cmp	rax,4
	je	.gather
	cmp	rax,3
	je	.gather
	cmp	rax,7
	je	.gather
.skip:
	add	r13,rcx
	jmp	.check_end
.gather:
	mov	eax,[r12+QST_HBLEN]
	lea	rdi,[r15+QC_CTLB+rax]
	add	[r12+QST_HBLEN],ecx
	mov	rsi,r13
	add	r13,rcx
	rep	movsb
.check_end:
	cmp	qword [r12+QST_FLEFT],0
	jne	.next
.frame_end:
	mov	rax,[r12+QST_FTYPE]
	mov	qword [r12+QST_FTYPE],-1
	lea	rsi,[r15+QC_CTLB]
	mov	edx,[r12+QST_HBLEN]
	add	rdx,rsi
	cmp	rax,4
	je	.settings
	cmp	rax,0x0D
	je	.max_push
	cmp	rax,7
	je	.goaway
	cmp	rax,3
	je	.cancel
	jmp	.next
.settings:
	; identifier and value pairs: HTTP/2's (2 to 5) and one twice are
	; SETTINGS_ERROR; one cut short FRAME_ERROR; the others are taken as
	; they come (reserved ones too, read past)
	mov	r9,rsi				; the first pair
.pair:
	cmp	rsi,rdx
	jae	.next
	mov	r10,rsi				; where this one begins
	call	qv_read				; (qv_read takes r11)
	jc	.frame_error
	mov	r8,rax				; its identifier
	call	qv_read
	jc	.frame_error
	cmp	r8,1				; QPACK_MAX_TABLE_CAPACITY: our encoder's
	jne	@f				; table, up to QE_DCAP
	call	qe_settings
@@:
	lea	rax,[r8-2]
	cmp	rax,3
	jbe	.settings_error
	push	rsi				; the next pair
	mov	rsi,r9
.dup:
	cmp	rsi,r10
	jae	.dup_done
	call	qv_read
	cmp	rax,r8
	je	.dup_found
	call	qv_read
	jmp	.dup
.dup_found:
	pop	rsi
	jmp	.settings_error
.dup_done:
	pop	rsi
	jmp	.pair
.max_push:
	call	.one
	jc	.frame_error
	mov	rcx,[r15+QC_MAXPUSH]
	test	rcx,rcx
	jz	@f
	dec	rcx
	cmp	rax,rcx
	jb	.id_error			; down
@@:
	inc	rax
	mov	[r15+QC_MAXPUSH],rax
	jmp	.next
.goaway:
	call	.one
	jc	.frame_error
	mov	rcx,[r15+QC_GOAWAYRX]
	test	rcx,rcx
	jz	@f
	dec	rcx
	cmp	rax,rcx
	ja	.id_error			; up
@@:
	inc	rax
	mov	[r15+QC_GOAWAYRX],rax
	jmp	.next
.cancel:
	call	.one
	jc	.frame_error
	mov	rcx,[r15+QC_MAXPUSH]		; a push it never allowed
	test	rcx,rcx
	jz	.id_error
	cmp	rax,rcx
	jae	.id_error
	jmp	.next
; rsi..rdx: one varint and nothing after it: rax, CF otherwise
.one:
	call	qv_read
	jc	.one_out
	cmp	rsi,rdx
	je	.one_out			; (CF clear: equal)
	stc
.one_out:
	ret
.done:
	clc
	jmp	.out
.missing:
	mov	eax,H3E_MISSING_SETTINGS
	jmp	.fail
.unexpected:
	mov	eax,H3E_FRAME_UNEXPECTED
	jmp	.fail
.excessive:
	mov	eax,H3E_EXCESSIVE
	jmp	.fail
.frame_error:
	mov	eax,H3E_FRAME_ERROR
	jmp	.fail
.settings_error:
	mov	eax,H3E_SETTINGS
	jmp	.fail
.id_error:
	mov	eax,H3E_ID
.fail:
	mov	[r15+QC_ERR],rax
	or	dword [r15+QC_FLAGS],QF_APP_ERR
	stc
.out:
	pop	r14
	pop	r13
	pop	r12
	ret

; rdi = the client's QPACK decoder stream, rsi = bytes in order, rcx = how
; many (RFC 9204 4.4): our encoder never inserts, so its instructions are
; read past, but an Insert Count Increment of 0 is QPACK_DECODER_STREAM_ERROR.
; QST_FHAVE: 1 inside an integer's continuation bytes. CF on an error.
qd_dec_bytes:
	; (QST_PHASE: 1 for an Insert Count Increment being read, its value in
	; QST_FTYPE, the next bits' shift in QST_FLEFT: what our encoder's
	; inserts the client has, the only references it then makes)
.byte:
	test	rcx,rcx
	jz	.ok
	movzx	eax,byte [rsi]
	inc	rsi
	dec	rcx
	cmp	dword [rdi+QST_FHAVE],0
	jne	.more
	test	eax,eax
	jz	.zero				; 00 000000: Insert Count Increment 0
	mov	dword [rdi+QST_PHASE],0
	mov	edx,0x7F			; Section Acknowledgment: 7-bit prefix,
	test	al,0x80				; the others 6
	jnz	@f
	mov	edx,0x3F
	test	al,0x40
	jnz	@f
	mov	dword [rdi+QST_PHASE],1		; 00: Insert Count Increment
@@:
	and	eax,edx
	mov	[rdi+QST_FTYPE],rax
	mov	qword [rdi+QST_FLEFT],0
	cmp	eax,edx
	jne	.whole				; whole in its first byte
	mov	dword [rdi+QST_FHAVE],1
	jmp	.byte
.more:
	mov	edx,eax
	and	edx,0x7F
	push	rcx
	mov	rcx,[rdi+QST_FLEFT]
	cmp	ecx,28
	ja	@f
	shl	rdx,cl
	add	[rdi+QST_FTYPE],rdx
@@:
	add	qword [rdi+QST_FLEFT],7
	pop	rcx
	test	al,0x80
	jnz	.byte
	mov	dword [rdi+QST_FHAVE],0
.whole:
	cmp	dword [rdi+QST_PHASE],1
	jne	.byte
	mov	rax,[rdi+QST_FTYPE]
	call	qe_increment
	jmp	.byte
.zero:
	mov	qword [r15+QC_ERR],H3E_DECODER_STREAM
	or	dword [r15+QC_FLAGS],QF_APP_ERR
	stc
	ret
.ok:
	clc
	ret

; rax = a stream whose field section used the table and was not taken: Stream
; Cancellation (RFC 9204 4.4.2), so the client's encoder lets its references go
qd_stream_cancel:
	push	rax
	call	qd_room
	pop	rax
	jc	.out
	mov	cl,6
	mov	dl,0x40
	call	hp_put_int
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
	cmp	dword [r12+QST_KIND],QSK_CTL
	je	.ctl
	cmp	dword [r12+QST_KIND],QSK_DEC
	je	.dec
	; its type, a varint (whole in its first bytes, else read and ignored):
	; one control stream, one encoder, one decoder; no push stream from a
	; client (RFC 9114 6.2, RFC 9204 4.2); any other type is read and ignored
	lea	rdx,[rsi+rcx]
	call	qv_read
	jc	.ignored
	mov	rcx,rdx
	sub	rcx,rsi				; what follows it
	test	rax,rax
	jz	.t_ctl
	cmp	rax,1
	je	.creation
	cmp	rax,2
	je	.t_enc
	cmp	rax,3
	je	.t_dec
.ignored:
	mov	dword [r12+QST_KIND],QSK_UNI
	jmp	.ok
.t_ctl:
	bts	dword [r15+QC_H3UNI],0
	jc	.creation
	mov	dword [r12+QST_KIND],QSK_CTL
	mov	qword [r12+QST_FTYPE],-1
	mov	dword [r12+QST_FHAVE],0
	mov	dword [r12+QST_PHASE],0		; (no SETTINGS yet)
.ctl:
	mov	rdi,r12
	call	h3_ctl_bytes
	jc	.failed
	jmp	.ok
.t_dec:
	bts	dword [r15+QC_H3UNI],2
	jc	.creation
	mov	dword [r12+QST_KIND],QSK_DEC
	mov	dword [r12+QST_FHAVE],0
.dec:
	mov	rdi,r12
	call	qd_dec_bytes
	jc	.failed
	jmp	.credit				; (its window moves too: a Section
						; Acknowledgment for each answer that used the table)
.creation:
	mov	qword [r15+QC_ERR],H3E_STREAM_CREATION
	or	dword [r15+QC_FLAGS],QF_APP_ERR
.failed:
	stc
	jmp	.out
.t_enc:
	bts	dword [r15+QC_H3UNI],1
	jc	.creation
	mov	dword [r12+QST_KIND],QSK_ENC
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
; (HP_* entries). eax = how many, -1 (a decompression error), or -2 (more than
; g_h3f or g_h3s hold: nothing of the table changes in a field section, so
; only that request is refused).
qpack_decode:
	push	rbx
	push	r12
	mov	dword [g_qp_big],0
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
	jae	.too_many
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
.too_many:
	mov	dword [g_qp_big],1
.bad:
	mov	eax,-1
	cmp	dword [g_qp_big],0
	je	@f
	mov	eax,-2				; larger than we take: the stream's alone
@@:
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

; The last request section a connection decoded and the head made of it
; (its checks passed): the same bytes, with the decoder's table as it was
; (only the client's inserts change it), are the same head. A section that
; used the table is acknowledged again (RFC 9204 4.4.1); 0-RTT is not kept.
H3Q_VALID	:= 0				; d
H3Q_BLEN	:= 4				; d
H3Q_INS		:= 8				; q: QC_QP_INS
H3Q_DROP	:= 16				; q: QC_QP_DROP
H3Q_CAP		:= 24				; d: QC_QP_CAP
H3Q_FIN		:= 28				; d: QST_FINHERE (its framing)
H3Q_RIC		:= 32				; d: it used the dynamic table
H3Q_LEN		:= 36				; d: the head's length
H3Q_CHUNKED	:= 40				; d
H3Q_CLEN	:= 48				; q
H3Q_BLOCK	:= 64
H3Q_BCAP	:= 512
H3Q_TEXT	:= H3Q_BLOCK + H3Q_BCAP
H3Q_TCAP	:= 512
H3Q_SIZE	:= H3Q_TEXT + H3Q_TCAP
assert QM_H3Q + H3Q_SIZE <= 1 shl QFX_SHIFT

; h3_request_new: rdi = the entry, its section in g_h3tmp (QST_HBLEN), r15 =
; connection. CF clear when it is H3Q's: rax = H3Q. CF set otherwise, the
; section staged in H3Q (when it may be kept) for h3_rq_keep. Keeps rdi.
h3_rq_same:
	mov	dword [g_h3q_staged],0
	cmp	dword [rdi+QST_EARLY],0
	jne	.no
	call	qe_ptr
	add	rax,QM_H3Q - QE_OFF
	mov	ecx,[rdi+QST_HBLEN]
	cmp	ecx,H3Q_BCAP
	ja	.no
	cmp	dword [rax+H3Q_VALID],0
	je	.stage
	cmp	ecx,[rax+H3Q_BLEN]
	jne	.stage
	mov	rdx,[r15+QC_QP_INS]
	cmp	rdx,[rax+H3Q_INS]
	jne	.stage
	mov	rdx,[r15+QC_QP_DROP]
	cmp	rdx,[rax+H3Q_DROP]
	jne	.stage
	mov	edx,[r15+QC_QP_CAP]
	cmp	edx,[rax+H3Q_CAP]
	jne	.stage
	mov	edx,[rdi+QST_FINHERE]
	cmp	edx,[rax+H3Q_FIN]
	jne	.stage
	push	rdi
	push	rax
	lea	rsi,[g_h3tmp]
	lea	rdi,[rax+H3Q_BLOCK]
	call	mem_same
	pop	rax
	pop	rdi
	jne	.stage
	clc
	ret
.stage:
	mov	dword [rax+H3Q_VALID],0
	mov	[rax+H3Q_BLEN],ecx
	mov	rdx,[r15+QC_QP_INS]
	mov	[rax+H3Q_INS],rdx
	mov	rdx,[r15+QC_QP_DROP]
	mov	[rax+H3Q_DROP],rdx
	mov	edx,[r15+QC_QP_CAP]
	mov	[rax+H3Q_CAP],edx
	mov	edx,[rdi+QST_FINHERE]
	mov	[rax+H3Q_FIN],edx
	push	rdi
	lea	rsi,[g_h3tmp]
	lea	rdi,[rax+H3Q_BLOCK]
	rep	movsb
	pop	rdi
	mov	dword [g_h3q_staged],1
.no:
	stc
	ret

; h3_request_new, its head written (Q_LEN, Q_CLEN, Q_CHUNKED at r13), r15 =
; connection: kept with the section staged, when the table is as it was.
; Keeps all but rax, rcx, rdx, rsi, flags.
h3_rq_keep:
	cmp	dword [g_h3q_staged],0
	je	.out
	mov	dword [g_h3q_staged],0
	mov	ecx,[r13+Q_LEN]
	cmp	ecx,H3Q_TCAP
	ja	.out
	call	qe_ptr
	add	rax,QM_H3Q - QE_OFF
	mov	rdx,[r15+QC_QP_INS]
	cmp	rdx,[rax+H3Q_INS]
	jne	.out
	mov	rdx,[r15+QC_QP_DROP]
	cmp	rdx,[rax+H3Q_DROP]
	jne	.out
	mov	[rax+H3Q_LEN],ecx
	mov	edx,[r13+Q_CHUNKED]
	mov	[rax+H3Q_CHUNKED],edx
	mov	rdx,[r13+Q_CLEN]
	mov	[rax+H3Q_CLEN],rdx
	mov	edx,[g_h3q_ric]
	mov	[rax+H3Q_RIC],edx
	push	rdi
	lea	rsi,[r13+Q_DATA]
	lea	rdi,[rax+H3Q_TEXT]
	rep	movsb
	pop	rdi
	mov	dword [rax+H3Q_VALID],1
	or	dword [r14+H_H3F],H3F_TM
.out:
	ret

bss
	g_h3q_staged	dd ?			; h3_rq_same staged the section
	g_h3q_ric	dd ?			; its decode used the dynamic table
end bss

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
H3N_TM		:= 92				; d: 1 when its head is H3Q's
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
	mov	dword [rsp+H3N_TM],0
	call	h3_rq_same			; the same section as the last: its head
	jnc	.same_head
	lea	rsi,[g_h3tmp]
	mov	edx,[rdi+QST_HBLEN]
	call	qpack_decode
	cmp	eax,-1
	je	.decompression
	cmp	eax,-2
	je	.too_big
	mov	[rsp+H3N_N],eax
	mov	rax,[g_qp_ric]			; (the memo's: a section ack again on a hit)
	mov	[g_h3q_ric],eax
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
	call	field_value_ok
	jc	.malformed
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
	cmp	qword [rsp+H3N_AUTH],0		; :authority, or a Host field (RFC 9114
	jne	.authority			; 4.3.1: http and https name their host)
	xor	ecx,ecx
.host:
	cmp	ecx,[rsp+H3N_N]
	jae	.malformed
	imul	eax,ecx,HP_SIZE
	inc	ecx
	cmp	dword [g_h3f+rax+HP_NLEN],4
	jne	.host
	mov	rax,[g_h3f+rax+HP_NAME]
	cmp	dword [rax],'host'
	jne	.host
.authority:
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
.alloc:
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
	call	copy_small
	mov	edi,[rsp+8+H3N_SESS]		; (access log: TLS 1.3)
	call	alx_h3
	mov	edi,[rsp+8+H3N_SESS]		; (its TLS fingerprint: the connection's)
	mov	esi,[rsp]
	call	ja4_inherit
	pop	rbx
	; its record
	mov	edi,[rsp+H3N_SESS]
	h3_ptrs	edi
	mov	r14,r8				; the record
	mov	eax,[rsp+H3N_SESS]
	shl	rax,HB_SHIFT
	add	rax,[g_hbuf_base]
	mov	[r14+H_BUF],rax
	mov	dword [rax+HB_CW],0		; (cache.inc: a stale copy kept, none)
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
	; its send ring: the header with the connection (qth_of), the counters
	; (the ACK ranges are read up to TX_NACK), the ring in its buffers
	push	r8
	mov	r8,rdi
	call	qth_of
	pop	r8
	mov	edx,[rdi+QST_SESS]
	mov	ecx,[rdi+QST_SGEN]
	mov	[rax+TX_OWN],edx
	mov	[rax+TX_OWNG],ecx
	mov	[r14+H_H3TXH],rax
	lea	rdx,[rbp+HB_TLS]
	mov	[rax+TX_RING],rdx
	mov	rdi,rax
	mov	ecx,TX_ACK / 8
	push	rax
	xor	eax,eax
	rep	stosq
	pop	rdi
	mov	[rdi+TX_XLO],rax
	mov	[rdi+TX_XHI],rax
	mov	dword [rdi+TX_CAPV],TX_CAP
	mov	rax,[r15+QC_PSD_BIDI]
	mov	[rdi+TX_MAXSD],rax
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
	cmp	dword [rsp+H3N_TM],0
	je	.head_new
	call	qe_ptr				; H3Q's head
	lea	rsi,[rax+QM_H3Q-QE_OFF+H3Q_TEXT]
	mov	ecx,[rax+QM_H3Q-QE_OFF+H3Q_LEN]
	mov	[r13+Q_LEN],ecx
	mov	edx,[rax+QM_H3Q-QE_OFF+H3Q_CHUNKED]
	mov	[r13+Q_CHUNKED],edx
	lea	rdi,[r13+Q_DATA]
	rep	movsb
	or	dword [r14+H_H3F],H3F_TM
	jmp	.head_done
.head_new:
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
	call	h3_rq_keep			; (the section it was made of staged: kept)
.head_done:
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
.too_big:
	; a head larger than we take: that stream reset (H3_EXCESSIVE_LOAD), the
	; connection goes on; the client's encoder told the section is abandoned
	cmp	qword [g_qp_ric],0
	je	@f
	mov	rax,[rsp+H3N_ENTRY]
	mov	rax,[rax+QST_ID]
	call	qd_stream_cancel
@@:
	mov	rdi,[rsp+H3N_ENTRY]
	mov	eax,H3E_EXCESSIVE
	call	qst_refuse
	clc
	jmp	.out
.same_head:
	; rax = H3Q: the head made of these bytes (its checks passed)
	mov	rdx,[rax+H3Q_CLEN]
	mov	[rsp+H3N_CLEN],rdx
	mov	dword [rsp+H3N_TM],1
	cmp	dword [rax+H3Q_RIC],0
	je	.alloc
	mov	rax,[rsp+H3N_ENTRY]		; it used the table: acknowledged again
	mov	rax,[rax+QST_ID]
	call	qd_section_ack
	jmp	.alloc
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
	call	copy_small
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
	call	qsend_set			; (it may have something to send now)
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
	mov	r13,[r12+H_H3TXH]		; its ring's header
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
	push	rdx
	push	rdi
	lea	rdi,[g_h3tmp+8]
	xor	edx,edx				; DATA
	call	h3_fhdr
	mov	ecx,eax
	call	h3tx_put
	pop	rdi
	pop	rdx
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

; rsi = bytes, ecx = length (room checked): at the ring's end (r13). From
; the memory store: not copied, the ring's external bytes (TX_X*) grow
; (they start afresh once those before are acknowledged)
h3tx_put:
	test	ecx,ecx
	jz	.out
	mov	rax,rsi
	sub	rax,[g_fm_base]
	jb	.copy
	sub	rax,FM_DATA			; (its contents: past the header and entries)
	jb	.copy
	cmp	rax,[g_fm_cap]
	jae	.copy
	cmp	qword [g_fm_base],0
	je	.copy
	mov	rax,[r13+TX_XHI]
	cmp	rax,[r13+TX_END]
	jne	.fresh
	sub	rax,[r13+TX_XLO]		; on from the last: the same bytes?
	add	rax,[r13+TX_XPTR]
	cmp	rax,rsi
	je	.grow
.fresh:
	mov	rax,[r13+TX_XHI]		; those before all acknowledged?
	cmp	rax,[r13+TX_BASE]
	ja	.copy
	mov	rax,[r13+TX_END]
	mov	[r13+TX_XLO],rax
	mov	[r13+TX_XHI],rax
	mov	[r13+TX_XPTR],rsi
.grow:
	add	[r13+TX_XHI],rcx
	add	[r13+TX_END],rcx
	add	rsi,rcx
	ret
.copy:
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
	mov	rdi,[r13+TX_RING]
	add	rdi,rax
	mov	ecx,edx
	add	[r13+TX_END],rcx
	call	copy_small
	pop	rcx
	xor	eax,eax
@@:
	mov	rdi,[r13+TX_RING]
	add	rdi,rax
	add	[r13+TX_END],rcx
	call	copy_small			; (an answer's few bytes: no rep movsb start-up)
.out:
	ret

; r9 = a stream's ring, rax = stream offset, rcx = length, rdi = where:
; its bytes copied (rdi past them), from the ring or the external bytes.
; Keeps all but rax, rcx, rdx, rsi.
tx_read:
	test	rcx,rcx
	jz	.out
	mov	rdx,[r9+TX_XHI]
	cmp	rdx,[r9+TX_XLO]
	je	.ring				; none outside
	cmp	rax,rdx
	jae	.ring				; past them
	mov	rsi,[r9+TX_XLO]
	cmp	rax,rsi
	jae	.outside
	push	rcx				; before them: up to where they start
	sub	rsi,rax
	cmp	rcx,rsi
	jbe	@f
	mov	rcx,rsi
@@:
	sub	[rsp],rcx
	push	rax
	push	rcx
	call	.ring_part
	pop	rcx
	pop	rax
	add	rax,rcx
	pop	rcx
	jmp	tx_read
.outside:
	push	rcx
	sub	rdx,rax				; within them
	cmp	rcx,rdx
	jbe	@f
	mov	rcx,rdx
@@:
	sub	[rsp],rcx
	mov	rsi,rax
	sub	rsi,[r9+TX_XLO]
	add	rsi,[r9+TX_XPTR]
	add	rax,rcx
	rep	movsb
	pop	rcx
	jmp	tx_read
.ring:
.ring_part:
	mov	edx,[r9+TX_CAPV]		; rax, rcx from the ring (it may wrap)
	dec	edx
	and	eax,edx
	inc	edx
	sub	edx,eax
	cmp	ecx,edx
	jbe	@f
	push	rcx
	mov	rsi,[r9+TX_RING]
	add	rsi,rax
	mov	ecx,edx
	sub	[rsp],rcx
	rep	movsb
	pop	rcx
	xor	eax,eax
@@:
	mov	rsi,[r9+TX_RING]
	add	rsi,rax
	rep	movsb
.out:
	ret

; r12 = a stream's record: rax = its connection's memos (QM_OFF in its
; QFX area), 0 when the connection is not the stream's any more. Keeps all
; but rax.
h3_qm:
	push	rcx
	push	rdx
	push	r15
	mov	eax,[r12+H_H3C]
	mov	ecx,eax
	shl	rcx,S_SHIFT
	add	rcx,[g_sess_base]
	mov	edx,[rcx+S_GEN]
	cmp	edx,[r12+H_H3CG]
	jne	.gone
	test	dword [rcx+S_FLAGS],SF_QC
	jz	.gone
	mov	r15d,eax
	shl	r15,HB_SHIFT
	add	r15,[g_hbuf_base]
	call	qe_ptr
	add	rax,QM_OFF - QE_OFF
	jmp	.out
.gone:
	xor	eax,eax
.out:
	pop	r15
	pop	rdx
	pop	rcx
	ret

; h3_head_out's memo (QM_H3R, H2RM_* as HTTP/2's): rsi = the head, ebp = its
; length, r12 = stream. CF clear on a hit: the section in g_h3tmp+8, rdi past
; it, bl its status' first character. CF set otherwise, the text kept aside
; with the encoder's state for h3_rm_keep. Keeps rsi, rbp, r12-r15.
h3_rm_look:
	mov	dword [g_rm_staged],0
	call	h3_qm
	test	rax,rax
	jz	.miss
	lea	rdx,[rax+QM_H3R-QM_OFF]
	xor	r9d,r9d				; the key: HEAD, okena's own answer
	test	dword [r12+H_FLAGS],HX_HEAD
	jz	@f
	or	r9d,2
@@:
	push	rax
	h_own_answer r12
	pop	rax
	jne	@f
	or	r9d,4
@@:
	mov	[g_rm_key],r9d
	; the encoder's state: capacity, inserts, known, size, its stream's bytes
	sub	rax,QM_OFF - QE_OFF
	mov	ecx,[rax+QE_CAP]
	mov	[g_h3rm_qe],ecx
	mov	ecx,[rax+QE_INS]
	mov	[g_h3rm_qe+4],ecx
	mov	ecx,[rax+QE_KRC]
	mov	[g_h3rm_qe+8],ecx
	mov	ecx,[rax+QE_USED]
	mov	[g_h3rm_qe+12],ecx
	mov	ecx,dword [rax+QE_END]
	mov	[g_h3rm_qe+16],ecx
	mov	[g_h3rm_qe_at],rax
	cmp	ebp,H2RM_TCAP
	ja	.miss
	cmp	dword [rdx+H2RM_VALID],0
	je	.stage
	cmp	ebp,[rdx+H2RM_TLEN]
	jne	.stage
	cmp	r9d,[rdx+H2RM_KEY]
	jne	.stage
	mov	ecx,5
@@:
	mov	eax,[g_h3rm_qe+rcx*4-4]
	cmp	eax,[rdx+H2RM_HT+rcx*4-4]
	jne	.stage
	dec	ecx
	jnz	@b
	push	rsi
	push	rdi
	lea	rdi,[rdx+H2RM_TEXT]
	mov	ecx,ebp
	call	mem_same
	pop	rdi
	pop	rsi
	jne	.stage
	push	rsi
	lea	rsi,[rdx+H2RM_BLOCK]
	lea	rdi,[g_h3tmp+8]
	mov	ecx,[rdx+H2RM_BLEN]
	rep	movsb
	pop	rsi
	movzx	ebx,byte [rdx+H2RM_ST]
	mov	qword [g_qe],0
	clc
	ret
.stage:
	mov	dword [rdx+H2RM_VALID],0
	push	rsi
	lea	rdi,[rdx+H2RM_TEXT]
	mov	ecx,ebp
	rep	movsb
	pop	rsi
	mov	[rdx+H2RM_TLEN],ebp
	mov	[g_h3rm_at],rdx
	mov	dword [g_rm_staged],1
.miss:
	stc
	ret

; h3_head_out, the section done (g_h3tmp+8 to rdi), bl its status: kept with
; the text h3_rm_look set aside when encoding it inserted nothing and wrote
; nothing on our encoder stream. Keeps all but rax, rcx, rdx, flags.
h3_rm_keep:
	cmp	dword [g_rm_staged],0
	je	.out
	mov	dword [g_rm_staged],0
	mov	rax,[g_h3rm_qe_at]
	mov	ecx,[rax+QE_INS]
	cmp	ecx,[g_h3rm_qe+4]
	jne	.out
	mov	ecx,dword [rax+QE_END]
	cmp	ecx,[g_h3rm_qe+16]
	jne	.out
	mov	ecx,[rax+QE_CAP]
	cmp	ecx,[g_h3rm_qe]
	jne	.out
	mov	ecx,[rax+QE_KRC]
	cmp	ecx,[g_h3rm_qe+8]
	jne	.out
	mov	ecx,[rax+QE_USED]
	cmp	ecx,[g_h3rm_qe+12]
	jne	.out
	lea	rcx,[g_h3tmp+8]
	mov	rax,rdi
	sub	rax,rcx				; its length
	cmp	eax,H2RM_BCAP
	ja	.out
	mov	rdx,[g_h3rm_at]
	mov	[rdx+H2RM_BLEN],eax
	mov	ecx,5
@@:
	mov	eax,[g_h3rm_qe+rcx*4-4]
	mov	[rdx+H2RM_HT+rcx*4-4],eax
	dec	ecx
	jnz	@b
	mov	eax,[g_rm_key]
	mov	[rdx+H2RM_KEY],eax
	mov	[rdx+H2RM_ST],bl
	push	rsi
	push	rdi
	lea	rsi,[g_h3tmp+8]
	lea	rdi,[rdx+H2RM_BLOCK]
	mov	ecx,[rdx+H2RM_BLEN]
	rep	movsb
	pop	rdi
	pop	rsi
	mov	dword [rdx+H2RM_VALID],1
.out:
	ret

bss
	align 8
	g_h3rm_qe_at	dq ?			; h3_rm_look: the connection's encoder state,
	g_h3rm_at	dq ?			; its memo,
	g_h3rm_qe	rd 5			; and that state as the section began
end bss

; r12 = stream record, r13 = its ring: the HTTP/1.1 head at H_H3PP into a
; HEADERS frame (QPACK: :status by static name, the fields literal, no
; Huffman). CF when the ring has no room for it yet.
h3_head_out:
	push	rbx
	push	rbp
	mov	rsi,[r12+H_H3PP]
	mov	ecx,[r12+H_H3PL]
	call	crlf2_find
	jc	.broken
.found:
	lea	ebp,[rdx+4]			; the head's length
	cmp	ebp,13
	jb	.broken
	call	h3_rm_look			; the same head as the last: its section
	jnc	.frame
	lea	rdi,[g_h3tmp+8]			; the field section (the frame header after)
	mov	word [rdi],0			; Required Insert Count 0, Delta Base 0
	add	rdi,2				; (until the table is used: qe_prefix)
	call	qe_section
	; :status: the static table's own line for it when it has one (200 is
	; one byte), else by its name
	push	rsi
	lea	rcx,[rsi+9]
	lea	rsi,[.n_status]
	mov	edx,7
	mov	r8d,3
	call	qp_encode
	pop	rsi
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
	call	head_line			; r8d name end, r10d value, edx its end
	jc	.broken
	; skip connection-specific fields
	push	rsi
	push	rdx
	push	rcx
	push	rdi
	lea	rdi,[rsi+rcx]
	mov	esi,r8d
	sub	esi,ecx
	call	h_conn_field
	pop	rdi
	pop	rcx
	pop	rdx
	pop	rsi
	jnc	.next_line
	; a small body's content-length goes unsaid, as on HTTP/2 (h2_head_out):
	; the stream's end ends the body; said for a HEAD, a larger body, and a
	; backend's answer
	test	dword [r12+H_FLAGS],HX_HEAD
	jnz	.say
	mov	eax,r8d
	sub	eax,ecx
	cmp	eax,14
	jne	.say
	mov	rax,qword [rsi+rcx]
	cmp	rax,qword [h2_head_out.n_cl]
	jne	.say
	mov	rax,qword [rsi+rcx+6]
	cmp	rax,qword [h2_head_out.n_cl+6]
	jne	.say
	push	rcx
	xor	eax,eax
	mov	ecx,r10d
.cl_digit:
	cmp	ecx,edx
	jae	.cl_value
	movzx	r11d,byte [rsi+rcx]
	sub	r11d,'0'
	cmp	r11d,9
	ja	.cl_say
	imul	eax,eax,10
	add	eax,r11d
	cmp	eax,H2_CL_QUIET
	ja	.cl_say
	inc	ecx
	jmp	.cl_digit
.cl_value:
	pop	rcx
	test	eax,eax
	jz	.say
	h_own_answer r12			; (okena's own answer only)
	je	.next_line
	jmp	.say
.cl_say:
	pop	rcx
.say:
	lea	rax,[g_h3tmp+20480-600]
	cmp	rdi,rax
	ja	.broken
	; a field line: by the static table when it can (qp_encode)
	push	rsi
	push	rcx
	push	rdx
	push	r8
	push	r10
	push	rbx
	mov	r9d,edx
	sub	r9d,r10d			; value length
	lea	rax,[rsi+r10]			; value
	mov	edx,[rsp+16]			; name end (r8)
	sub	edx,ecx
	lea	rsi,[rsi+rcx]			; name
	mov	rcx,rax
	mov	r8d,r9d
	call	qp_encode
	pop	rbx
	pop	r10
	pop	r8
	pop	rdx
	pop	rcx
	pop	rsi
.next_line:
	lea	ecx,[rdx+2]
	jmp	.line
.block:
	call	qe_prefix			; the prefix, once the references are known
	mov	qword [g_qe],0
	call	h3_rm_keep
.frame:
	; the frame: HEADERS, its length (h3_fhdr), the section
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
	push	rdi
	lea	rdi,[g_h3tmp+8]
	mov	edx,1				; HEADERS
	call	h3_fhdr
	add	ecx,eax
	pop	rdi
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
	mov	qword [g_qe],0
	mov	dword [r12+H_H3PL],0
	or	dword [r12+H_H3F],H3F_HEAD
	clc
	jmp	.out
.full:
	mov	qword [g_qe],0
	stc
.out:
	pop	rbp
	pop	rbx
	ret
.n_status db ':status'

; QPACK's static table by hash (sthash.inc)
rodata
	align 8
	qp_sd	dq qp_static, qp_pool
		dd 99, 0
		dq g_qph_name, g_qph_pair, g_qph_nid, g_qph_ok
end rodata
bss
	align 8
	g_qph_name	rw ST_SLOTS
	g_qph_pair	rw ST_SLOTS
	g_qph_nid	rb 99
	align 4
	g_qph_ok	dd ?
end bss

; rdi = out, rsi = a name (lower case), edx = its length, rcx = its value, r8d
; = its length: one QPACK field line (RFC 9204 4.5) by the static table: the
; whole line when the table has it (11T index: one byte for most), else its
; name by index and the value (Huffman when shorter), else all literal. rdi
; past it. Keeps rbx, rbp, r12-r15.
qp_encode:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rsi
	mov	r13d,edx
	mov	r14,rcx
	mov	r15d,r8d
	mov	rbp,rdi
	; the static table: the whole line, else the first entry with the name
	lea	r11,[qp_sd]
	call	st_find
	mov	ebx,edx
	cmp	eax,-1
	je	.searched
	; indexed field line, static (11 T=1 index, 6-bit prefix)
	mov	rdi,rbp
	mov	cl,6
	mov	dl,0xC0
	call	hp_put_int
	jmp	.out
.searched:
	; the dynamic table (qe.inc's part): a line the client has (indexed,
	; relative to the section's base), else kept for later
	cmp	qword [g_qe],0
	je	.no_dyn
	mov	rsi,r12
	mov	edx,r13d
	mov	rcx,r14
	mov	r8d,r15d
	mov	r9d,ebx				; (its static name, -1 none)
	mov	rdi,rbp
	call	qe_field
	jc	.no_dyn
	mov	rdi,rax
	jmp	.out
.no_dyn:
	cmp	ebx,-1
	je	.literal
	; literal with name reference, static (01 N=0 T=1 index, 4-bit prefix)
	mov	rdi,rbp
	mov	eax,ebx
	mov	cl,4
	mov	dl,0x50
	call	hp_put_int
	mov	rsi,r14
	mov	ecx,r15d
	call	hp_put_str			; (H, a 7-bit length: as HPACK's)
	jmp	.out
.literal:
	mov	rdi,rbp
	mov	rsi,r12
	mov	ecx,r13d
	mov	r8,r14
	mov	r9d,r15d
	call	h3_lit
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
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
	push	r14
	h_rec
	mov	r12,r15
	mov	r13,[r12+H_H3TXH]
	push	qword [r12+H_H3F]		; (finished before: counted then)
	or	dword [r12+H_H3F],H3F_FINISH
	test	dword [r12+H_H3F],H3F_HQ
	jnz	.fin				; (hq-interop has no trailers)
	cmp	dword [r12+H_RCK+CK_TLEN],0
	je	.fin
	call	h3_trailers_out
.fin:
	mov	dword [r13+TX_FIN],1
	pop	r14
	push	rbx
	push	r15
	call	h3s_conn			; (keeps r14)
	jc	@f
	test	r14d,H3F_FINISH
	jnz	.dirty
	inc	qword [r15+QC_SCRED]		; its answer complete: done for
	call	qc_maxs_check			; MAX_STREAMS, as HTTP/2 counts a stream
.dirty:						; whose END_STREAM is written
	call	qc_dirty
@@:
	pop	r15
	pop	rbx
	pop	r14
	pop	r13
	pop	r12
	ret

; r15 = connection: rax = the MAX_STREAMS (bidi) we allow: H3_MAXS past
; the streams whose answer is complete, so that a client never waits for
; the acknowledgement of answers it already has before it opens more; as
; far as the stream table holds them meanwhile (their entries go when
; acknowledged; room kept for the unidirectional ones); never less than
; already allowed. Keeps all but rax.
qc_maxs_value:
	push	rcx
	mov	rax,[r15+QC_SCRED]
	add	rax,H3_MAXS
	mov	rcx,[r15+QC_SDONE]
	add	rcx,QST_N - H3_UNI_ROOM
	cmp	rax,rcx
	cmova	rax,rcx
	cmp	rax,[r15+QC_MAXS_OURS]
	cmovb	rax,[r15+QC_MAXS_OURS]
	pop	rcx
	ret

; r15 = connection: a MAX_STREAMS to send once it allows ten more (it goes
; with the answers). Keeps all but rax.
qc_maxs_check:
	call	qc_maxs_value
	sub	rax,[r15+QC_MAXS_OURS]
	cmp	rax,10
	jb	@f
	or	dword [r15+QC_FL2],QF2_MAXS
@@:
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
	push	rdi
	lea	rdi,[g_h3tmp+8]
	mov	edx,1				; HEADERS
	call	h3_fhdr
	add	ecx,eax
	pop	rdi
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
	qst_bit	btr, r8, QC_QSTM
	qst_bit	btr, r8, QC_QREQ
	inc	qword [r15+QC_SDONE]		; its entry free (h3s_finish counted it
	test	r12d,H3F_FINISH			; done when its answer was complete)
	jnz	@f
	inc	qword [r15+QC_SCRED]
@@:
	call	qc_maxs_check
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
	call	qe_ptr				; our encoder stream's bytes
	mov	rcx,[rax+QE_END]
	cmp	rcx,[rax+QE_SENT]
	ja	.yes
	xor	ecx,ecx			; the streams that may, a qword at a time
.word:
	call	qe_ptr
	mov	rax,[rax+QE_QSEND+rcx*8]
.bit:
	tzcnt	rdx,rax
	jc	.next_word
	btr	rax,rdx
	push	rcx
	push	rax
	push	rdx
	shl	ecx,6
	add	ecx,edx
	imul	r8,rcx,QST_SIZE
	lea	r8,[r15+QC_QST+r8]
	call	qst_sendable			; eax = bytes it may send, edx = FIN to send
	or	eax,edx
	pop	rdx
	pop	rax
	pop	rcx
	jnz	.yes
	push	rax				; nothing: its bit goes
	call	qe_ptr
	push	rcx
	shl	ecx,6
	add	ecx,edx
	btr	[rax+QE_QSEND],rcx
	pop	rcx
	pop	rax
	jmp	.bit
.next_word:
	inc	ecx
	cmp	ecx,QST_W
	jb	.word
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
	call	qth_of				; its header, with the connection
	mov	r9,rax
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
; A frame's type and length, the length in as few bytes as it takes (a
; 4-byte one, always, cost each answer 6 bytes: HEADERS and DATA, read and
; decrypted by every client): dl = the type, ecx = the payload's length, rdi
; = where the payload starts, 5 bytes free before it. rsi = the frame's
; start, eax = the header's length; keeps the rest.
h3_fhdr:
	cmp	ecx,63
	ja	.two
	mov	[rdi-1],cl
	mov	[rdi-2],dl
	lea	rsi,[rdi-2]
	mov	eax,2
	ret
.two:
	cmp	ecx,16383
	ja	.four
	mov	eax,ecx
	or	eax,0x4000
	xchg	al,ah
	mov	[rdi-2],ax
	mov	[rdi-3],dl
	lea	rsi,[rdi-3]
	mov	eax,3
	ret
.four:
	mov	eax,ecx
	or	eax,0x80000000
	bswap	eax
	mov	[rdi-4],eax
	mov	[rdi-5],dl
	lea	rsi,[rdi-5]
	mov	eax,5
	ret

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
	mov	[g_qd_wlen],eax
	mov	dword [r15+QC_LW_SESS],NIL
	mov	dword [g_qfx_n],-1		; (no stream frame yet: the first goes in QC_LW_*)
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
	call	qc_maxs_value			; (lost: sent again, at least as much)
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
	mov	[g_qd_wlen],r10d		; (its length: the record's, qc_app_sent)
	mov	eax,dword [r15+QC_QD_SENT]	; (its record: control length, this end)
	shl	eax,8
	or	[r15+QC_LW_CTL],eax
	mov	r12d,1
.qd_done:
	call	qe_write			; our QPACK encoder stream (id 11)
	jnc	@f
	mov	r12d,1
@@:
	; one request stream's data, the next with something after the last
	; (the request streams there are, each once, from the one after QC_RR)
	call	qe_ptr				; (those that may have something to send)
	xor	r13d,r13d
	xor	edx,edx
@@:
	popcnt	rcx,[rax+QE_QSEND+rdx*8]
	add	r13d,ecx
	inc	edx
	cmp	edx,QST_W
	jb	@b
	test	r13d,r13d
	jz	.done
	mov	ecx,[r15+QC_RR]
.pick:
	call	qst_send_after			; ecx = the next one's index
	imul	eax,ecx,QST_SIZE
	lea	r8,[r15+QC_QST+rax]
	push	rcx
	call	qst_sendable
	pop	rcx
	test	r9,r9
	jz	.nothing
	mov	r10d,eax
	or	r10d,edx
	jnz	.write
.nothing:
	call	qe_ptr				; nothing to send: its bit goes
	btr	[rax+QE_QSEND],rcx
.pick_next:
	dec	r13d
	jnz	.pick
	jmp	.done
.write:
	mov	[r15+QC_RR],ecx
	; STREAM, OFF|LEN(|FIN): id, offset (8-byte varint), length (2 bytes)
	mov	rcx,r14
	sub	rcx,rdi
	sub	rcx,1 + 8 + 8 + 4
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
	; (no offset at all for a stream's first bytes, else its shortest varint)
	mov	al,0x0E
	cmp	qword [r9+TX_SENT],0
	jne	@f
	mov	al,0x0A
@@:
	or	al,r11b
	mov	[rdi],al
	inc	rdi
	push	r10
	push	r11
	mov	rax,[r8+QST_ID]
	call	qv_write
	mov	rax,[r9+TX_SENT]
	test	rax,rax
	jz	@f
	call	qv_write
@@:
	pop	r11
	pop	r10
	mov	eax,r10d			; its length: 2 bytes, 4 past 16383 (a
	cmp	eax,16383			; large datagram)
	ja	.len4
	or	eax,0x4000
	xchg	al,ah
	mov	[rdi],ax
	add	rdi,2
	jmp	.len_done
.len4:
	or	eax,0x80000000
	bswap	eax
	mov	[rdi],eax
	add	rdi,4
.len_done:
	; the bytes, from the ring (it may wrap); the frame kept for the packet's
	; record: the first in QC_LW_*, the others in the frames table's pending
	; slot (qfx_slot)
	cmp	dword [g_qfx_n],-1
	jne	.extra
	mov	rax,[r9+TX_SENT]
	mov	[r15+QC_LW_OFF],rax
	mov	[r15+QC_LW_LEN],r10d
	mov	[r15+QC_LW_FIN],r11d
	mov	eax,[r8+QST_SESS]
	mov	[r15+QC_LW_SESS],eax
	mov	eax,[r8+QST_SGEN]
	mov	[r15+QC_LW_SGEN],eax
	mov	dword [g_qfx_n],0
	jmp	.recorded
.extra:
	push	rdi
	mov	eax,SP_N
	call	qfx_slot			; rax = the pending slot
	mov	ecx,[g_qfx_n]
	imul	ecx,ecx,QFX_FR
	lea	rax,[rax+8+rcx]
	mov	ecx,[r8+QST_SESS]
	mov	[rax+QFX_SESS],ecx
	mov	ecx,[r8+QST_SGEN]
	mov	[rax+QFX_SGEN],ecx
	mov	[rax+QFX_FIN],r11d
	mov	rcx,[r9+TX_SENT]
	mov	[rax+QFX_OFF],rcx
	mov	[rax+QFX_LEN],r10d
	inc	dword [g_qfx_n]
	pop	rdi
.recorded:
	mov	rcx,r10
	mov	rax,[r9+TX_SENT]
	call	tx_read
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
	; room left: the next stream's in the same packet (a datagram carries
	; many small answers, as many as QFX_MAX past the first)
	cmp	dword [g_qfx_n],QFX_MAX
	jge	.done
	mov	rax,r14
	sub	rax,rdi
	cmp	rax,1 + 8 + 8 + 2 + 16
	jb	.done
	mov	ecx,[r15+QC_RR]			; (the one just written)
	jmp	.pick_next
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
	mov	eax,[g_qd_wlen]			; the decoder stream's bytes in it: their
	shl	eax,16				; length, past the flags (its start: the
	or	[rdi+SP_FL],eax			; end in SP_CTL less it)
	mov	eax,[r15+QC_LW_FR]
	mov	[rdi+SP_FR],eax
	; the frames past the first: from the pending slot into this record's
	push	rdi
	push	rsi
	push	rcx
	push	r8
	mov	ecx,[g_qfx_n]
	test	ecx,ecx
	jg	@f
	xor	ecx,ecx
@@:
	mov	r8d,ecx
	mov	rax,rdi				; this record's slot
	push	rcx
	mov	rcx,rax
	call	qsp_of
	sub	rcx,rax
	mov	rax,rcx
	pop	rcx
	shr	rax,6
	and	eax,SP_N - 1
	call	qfx_slot
	mov	[rax],r8d			; its count
	test	r8d,r8d
	jz	@f
	lea	rdi,[rax+8]
	mov	eax,SP_N
	call	qfx_slot
	lea	rsi,[rax+8]
	imul	ecx,r8d,QFX_FR
	rep	movsb
@@:
	mov	dword [g_qfx_n],-1
	pop	r8
	pop	rcx
	pop	rsi
	pop	rdi
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
	test	dword [rdi+SP_CTL],not 0xFF	; the decoder stream's: from where its
	jz	@f				; bytes in it began (what is acknowledged
	mov	eax,[rdi+SP_CTL]		; is contiguous, so they are still held)
	shr	eax,8
	mov	ecx,[rdi+SP_FL]
	shr	ecx,16
	sub	rax,rcx
	cmp	rax,[r15+QC_QD_ACK]
	jae	.qd_from
	mov	rax,[r15+QC_QD_ACK]
.qd_from:
	cmp	rax,[r15+QC_QD_SENT]
	jae	@f
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
	cmp	dword [r8+QST_KIND],QSK_DEC
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
	call	qc_fr_lost
	; and the frames past the first
	push	rdi
	push	rbx
	mov	rax,rdi
	push	rcx
	mov	rcx,rax
	call	qsp_of
	sub	rcx,rax
	mov	rax,rcx
	pop	rcx
	shr	rax,6
	and	eax,SP_N - 1
	call	qfx_slot
	mov	ebx,[rax]
	mov	dword [rax],0
	lea	rdi,[rax+8-SP_SSESS]		; (a frame's fields at the record's offsets)
.lost_x:
	test	ebx,ebx
	jle	.lost_done
	push	rdi
	call	qc_fr_lost
	pop	rdi
	add	rdi,QFX_FR
	dec	ebx
	jmp	.lost_x
.lost_done:
	pop	rbx
	pop	rdi
	ret

; rdi = a sent packet's record, or a frame of it at the record's offsets
; (SP_S*): its stream data and FIN go again, from the lowest offset lost
qc_fr_lost:
	cmp	dword [rdi+SP_SSESS],QE_MARK	; our encoder stream's bytes
	je	qe_lost
	call	qsend_all			; (what goes again: rare)
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

; The stream frames a packet carries past its first (QC_LW_*, SP_S*): for
; each connection a table, a slot for each sent-packet record of the
; application level and one being filled (SP_N), each a count then QFX_MAX
; frames whose fields line up with the record's (rdi = the frame - SP_SSESS
; reads one as qc_fr_acked and qc_fr_lost read a record).
QFX_SESS	:= 0				; d
QFX_SGEN	:= 4				; d
QFX_FIN		:= 8				; d
QFX_OFF		:= 12				; q
QFX_LEN		:= 20				; d
QFX_FR		:= 24
assert QFX_SESS = SP_SSESS - SP_SSESS & QFX_SGEN = SP_SGEN - SP_SSESS & QFX_FIN = SP_SFIN - SP_SSESS
assert QFX_OFF = SP_SOFF - SP_SSESS & QFX_LEN = SP_SLEN - SP_SSESS
QFX_MAX		:= 31
QFX_SLOT	:= 8 + QFX_MAX * QFX_FR
QFX_SHIFT	:= 19				; a connection's table: (SP_N + 1) slots
assert (SP_N + 1) * QFX_SLOT <= 1 shl QFX_SHIFT

bss
	align 8
	g_qfx_base	dq ?			; the tables, a connection's at its session's place
	g_qfx_n		dd ?			; frames in the pending slot (-1: none in the packet yet)
end bss

; eax = a slot (0..SP_N), r15 = the connection: rax = its place. Keeps all but rax.
qfx_slot:
	push	rcx
	imul	eax,eax,QFX_SLOT
	mov	rcx,r15
	sub	rcx,[g_hbuf_base]
	shr	rcx,HB_SHIFT
	shl	rcx,QFX_SHIFT
	add	rcx,[g_qfx_base]
	add	rax,rcx
	pop	rcx
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
	mov	r9,[r8+H_H3TXH]			; its header: still its own (the entry
	cmp	[r9+TX_OWN],eax			; not given to a later stream)
	jne	.gone
	cmp	[r9+TX_OWNG],edx
	jne	.gone
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
	jbe	.qd_acked
	; acknowledged as far as it goes on from what is (a packet acknowledged
	; past a lost one moved it beyond the lost bytes: never sent again, the
	; stream had a hole, and none of our acknowledgments after it reached
	; the client's QPACK: it stopped using its table for good)
	mov	edx,[rdi+SP_FL]
	shr	edx,16
	mov	rax,rcx
	sub	rax,rdx				; its start
	cmp	rax,[r15+QC_QD_ACK]
	ja	.qd_gap
	mov	[r15+QC_QD_ACK],rcx
	mov	rax,[r15+QC_QD_PE]		; and the range past the gap, when this
	cmp	rax,rcx				; reaches it
	jbe	.qd_pend_gone
	mov	rdx,[r15+QC_QD_PS]
	cmp	rdx,rcx
	ja	.qd_acked
	mov	[r15+QC_QD_ACK],rax
.qd_pend_gone:
	mov	qword [r15+QC_QD_PE],0
	jmp	.qd_acked
.qd_gap:
	mov	rdx,[r15+QC_QD_PE]		; past a gap: kept (one range; joined to
	test	rdx,rdx				; it when they touch, else the lower)
	jz	.qd_pend_new
	cmp	rax,rdx
	ja	.qd_pend_far
	cmp	rcx,[r15+QC_QD_PS]
	jb	.qd_pend_new
	cmp	rax,[r15+QC_QD_PS]
	jae	@f
	mov	[r15+QC_QD_PS],rax
@@:
	cmp	rcx,rdx
	jbe	.qd_acked
	mov	[r15+QC_QD_PE],rcx
	jmp	.qd_acked
.qd_pend_far:
	cmp	rax,[r15+QC_QD_PS]
	jae	.qd_acked
.qd_pend_new:
	mov	[r15+QC_QD_PS],rax
	mov	[r15+QC_QD_PE],rcx
.qd_acked:
	push	rdi
	call	qc_fr_acked
	pop	rdi
	; and the frames past the first
	push	rbx
	mov	rax,rdi
	push	rcx
	mov	rcx,rax
	call	qsp_of
	sub	rcx,rax
	mov	rax,rcx
	pop	rcx
	shr	rax,6
	and	eax,SP_N - 1
	call	qfx_slot
	mov	ebx,[rax]
	mov	dword [rax],0
	lea	rdi,[rax+8-SP_SSESS]
.acked_x:
	test	ebx,ebx
	jle	.acked_done
	push	rdi
	call	qc_fr_acked
	pop	rdi
	add	rdi,QFX_FR
	dec	ebx
	jmp	.acked_x
.acked_done:
	pop	rbx
	ret

; rdi = a sent packet's record, or a frame of it at the record's offsets
; (SP_S*): its stream bytes delivered
qc_fr_acked:
	cmp	dword [rdi+SP_SSESS],QE_MARK	; our encoder stream's bytes
	je	qe_acked
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
	call	qsend_all
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
