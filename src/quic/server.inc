; QUIC server (RFC 9000, 9001, 9002; version 2: RFC 9369), for `http3 on`.
;
; Every http listener with http3 has, besides its TCP sockets, one UDP
; socket per worker on the same address (SO_REUSEPORT: the kernel hashes
; a client's address and port to one of them, so its packets keep coming
; to the worker that holds its connection). A worker reads its sockets in
; batches (recvmmsg) when they are readable (epoll, or a multishot poll on
; the ring), and sends what its connections have at the end of each loop
; iteration, in batches (sendmmsg).
;
; A connection is a session (SF_QC) with no socket of its own: its 256 KiB
; buffer holds its state (QC_*), its TLS handshake (TS with TF_QUIC, and
; the QT block), the keys of the three levels, the packet number spaces
; and the crypto streams. Its connection IDs (ours, 8 random bytes; and
; until the handshake is done the client's original one) name it in a
; per-worker hash.
;
; The handshake: Initial CRYPTO frames reassemble the ClientHello, which
; goes to tls_hello; its ServerHello goes back in Initial packets, the
; rest of the flight in Handshake packets (at most three times what the
; client sent until its address is validated by a Handshake packet), and
; the client Finished, from Handshake CRYPTO frames, completes it:
; HANDSHAKE_DONE. Lost packets are found by a probe timeout (PTO), which
; sends again the crypto data not acknowledged.

QS_MAX		:= 16				; UDP sockets a worker reads
QRX_N		:= 32				; datagrams a recvmmsg takes
QRX_BUDGET	:= 8				; recvmmsgs a turn of the loop, then the
						; rest waits for the next (qs_resume)
QRX_SZ		:= 65536			; (GRO: several datagrams of a flow at once)
QTX_N		:= 64				; datagrams a sendmmsg sends
QTX_SZ		:= 1472
QUIC_DGRAM	:= 1350				; the largest datagram okena sends
QH_BITS		:= 17				; connection ID hash: 131072 entries
QH_N		:= 1 shl QH_BITS
QDIRTY_MAX	:= 512
EK_QUIC		:= 5				; epoll data: a QUIC socket (slot in the low bits)
IORING_POLL_ADD_MULTI := 1
SF_QC		:= 65536			; S_FLAGS: a QUIC connection

; levels (and packet number spaces)
QL_INIT		:= 0
QL_HS		:= 1
QL_APP		:= 2
QL_0RTT		:= 3				; (qc_packet's argument: 1-RTT's space, the early keys)

; a connection's buffer
QC_LINK		:= 0				; d: next in the worker's list (+ 1), 0 = none
QC_PLINK	:= 4				; d: previous
QC_SOCK		:= 8				; d: the socket slot it came on
QC_VER		:= 12				; d
QC_STATE	:= 16				; d: QCS_*
QC_FLAGS	:= 20				; d: QF_*
QC_PEER		:= 24				; its address (28)
QC_PEERLEN	:= 52				; d
QC_SCID		:= 56				; ours (8)
QC_DCIDLEN	:= 64				; d: the client's (what our packets carry)
QC_DCID		:= 68				; (20)
QC_ODCIDLEN	:= 88				; d: the client's first Destination Connection ID
QC_ODCID	:= 92				; (20)
QC_RXB		:= 112				; q: bytes received (the 3x rule before validation)
QC_TXB		:= 120				; q: bytes sent
QC_PTO_AT	:= 128				; q: µs, 0 = none
QC_PTOCNT	:= 136				; d
QC_DIRTY	:= 140				; d: in the flush list
QC_SRTT		:= 144				; q: µs
QC_RTTVAR	:= 152				; q
QC_CLOSE_AT	:= 160				; q: closing: when it goes
QC_ERR		:= 168				; q: the error CONNECTION_CLOSE carries
QC_CS_LEN	:= 176				; d * 3: crypto data to send, a level each
QC_CS_SENT	:= 188				; d * 3: sent so far (back to what is lost)
QC_CR_END	:= 200				; d * 3: crypto received in order
QC_PROBE	:= 212				; d * 3: a PING to send
QC_GEN		:= 224				; d: the session's generation
QC_ACKED_ALL	:= 228				; d * 3: 1 once all crypto sent is acknowledged
QC_MAXD_PEER	:= 240				; q: connection data we may send (MAX_DATA)
QC_DSENT	:= 248				; q: new stream data sent
QC_DRECV	:= 256				; q: stream data received (highest offsets)
QC_MAXD_OURS	:= 264				; q: what we allow (MAX_DATA)
QC_MAXS_OURS	:= 272				; q: bidi streams we allow (MAX_STREAMS)
QC_SDONE	:= 280				; q: request streams done
QC_PSD_BIDI	:= 288				; q: the client's initial_max_stream_data_bidi_local
QC_PSD_UNI	:= 296				; q
QC_FL2		:= 304				; d: QF2_*
QC_CTL_SENT	:= 308				; d: our control stream: bytes sent
QC_CTL_ACKED	:= 312				; d
QC_LW_SESS	:= 316				; d: the stream frame the packet being built carries
QC_LW_SGEN	:= 320				; d
QC_LW_FIN	:= 324				; d
QC_LW_OFF	:= 328				; q
QC_LW_LEN	:= 336				; d
QC_LW_CTL	:= 340				; d
QC_LW_FR	:= 344				; d
QC_RR		:= 348				; d: round robin over the streams
QC_SMAX		:= 352				; q: the highest client stream id seen + 4 (bidi)
QC_UMAX		:= 360				; q: (uni)
QC_PCHAL	:= 368				; q: a PATH_CHALLENGE to answer
QC_GOAWAY	:= 376				; q
QC_RSTN		:= 384				; d: RESET_STREAMs to send
QC_RST		:= 392				; 8 * (id q, error q)
QC_CWND		:= 520				; q: congestion window (NewReno, RFC 9002 7)
QC_INFL		:= 528				; q: bytes in flight
QC_SSTH		:= 536				; q: slow start threshold
QC_RECOV	:= 544				; q: recovery started (µs): losses of packets
						; sent before it are no new congestion
QC_LATEST	:= 552				; q: the latest RTT sample
QC_HBOWN	:= 560				; q: the stream entry gathering in QC_H3HB, 0 none
QC_HBOWNID	:= 568				; q: (its id)
QC_TODCIDLEN	:= 576				; d: after a Retry: the client's first
QC_TODCID	:= 580				; 20: Destination Connection ID (its token's)
QC_KPHASE	:= 600				; d: the 1-RTT key phase (0, 1)
QC_KUREADY	:= 604				; d: QC_KU holds the next receive keys
QC_KUSEC	:= 608				; 32: and their secret
QC_PATHNV	:= 640				; d: the client moved: its new path not validated
QC_PCHALO	:= 648				; q: our PATH_CHALLENGE on it
QC_HQ		:= 656				; d: ALPN hq-interop: HTTP/0.9 on the streams
QC_ECN		:= 664				; 3 * (ECT(0), ECT(1), CE) q: ECN marks received a space
QC_WMAX		:= 736				; q: CUBIC: the window before the last reduction
QC_EPOCH	:= 744				; q: µs its congestion avoidance began, 0 none yet
QC_K		:= 752				; q: ms to get back to QC_WMAX
QC_WEST		:= 760				; q: the Reno-friendly window
QC_LOSS_AT	:= 768				; q: µs a packet in flight passes the time threshold, 0 none
QC_LOSS_PN	:= 776				; q: (the largest acknowledged then)
QC_LOSS_LVL	:= 784				; d: (its space)
QC_RSTWIN	:= 792				; q: µs this second of client resets began
QC_RSTCNT	:= 800				; d: requests the client cancelled in it
QC_PACE_T	:= 808				; q: µs the pacing budget was last filled
QC_PACE_B	:= 816				; q: bytes it allows (signed)
QC_PACE_AT	:= 824				; q: µs data may go again, 0 not waiting
QC_CIDS		:= 832				; 2 * 8: connection IDs issued after ours (sequence 1, 2)
QC_NCIDS	:= 848				; d: how many (the client's active_connection_id_limit - 1, at most 2)
QC_ACIDL	:= 856				; q: the client's active_connection_id_limit
QC_MTU		:= 864				; d: the datagrams this path has shown it takes
QC_MTU_TRY	:= 868				; d: the size being probed, 0 none
QC_MTU_N	:= 872				; d: probes of it so far
QC_PMAX		:= 880				; q: the client's max_udp_payload_size
QC_MTU_AT	:= 888				; q: µs the next probe is due
QC_ECNOFF	:= 896				; d: the client or the path does not report ECN: no marks
QC_ECN_CE	:= 904				; q: the CE count it last reported at 1-RTT
QC_QP_INS	:= 912				; q: QPACK: entries the client has inserted
QC_QP_DROP	:= 920				; q: and evicted
QC_QP_SIZE	:= 928				; d: the table's size (RFC 9204 3.2.1)
QC_QP_CAP	:= 932				; d: its capacity (the client sets it)
QC_QP_TAIL	:= 936				; d: where the next entry's bytes go
QC_QP_PART	:= 940				; d: encoder stream bytes not parsed yet
QC_QP_KNOWN	:= 944				; q: inserts told to the client
QC_QD_BASE	:= 952				; q: the decoder stream: the buffer's first offset
QC_QD_END	:= 960				; q: written
QC_QD_SENT	:= 968				; q: sent (back to what is acknowledged)
QC_QD_ACK	:= 976				; q: acknowledged
QC_PACID	:= 984				; d: QC_CIDS's first went in preferred_address
QC_ALT_SLOT	:= 988				; d: a PATH_CHALLENGE on another path: its socket,
QC_ALT_DATA	:= 992				; q: its data,
QC_ALT_SA	:= 1000				; 28: and where it came from (the answer goes there)
QC_ALT_LEN	:= 1028				; d
QC_ALT_MAX	:= 1032				; d: at most this answers it (3x, RFC 9000 8.2.1)
QC_ALT_CNT	:= 1036				; d: answered in this second,
QC_ALT_WIN	:= 1040				; q: which began then
QC_HDR_TICK	:= 1048				; d: g_tick at the last look for late heads
QC_FIELDS_END	:= 1088
; BBR (qc_bbr_acked), in CUBIC's fields where it can: a connection has one
QB_BW		:= QC_WMAX			; q: bytes/s, the best sample of these rounds
QB_BW2		:= QC_EPOCH			; q: and of the rounds before
QB_RT		:= QC_K				; d: µs, the least round trip lately
QB_RT_TICK	:= QC_K + 4			; d: when (g_tick)
QB_FULL		:= QC_WEST			; d: KiB/s, startup's best
QB_FLAT		:= QC_WEST + 4			; d: rounds it has not grown
QB_ROUNDS	:= 1052				; d
QB_DELIV	:= 1056				; q: bytes acknowledged, ever
QB_SNAP_D	:= 1064				; q: as the round's packet went
QB_SNAP_T	:= 1072				; q: and when, 0 none out
QB_STATE	:= 1080				; d: BBR_*
QB_CYCLE	:= 1084				; d: rounds in the state
BBR_STARTUP	:= 0
BBR_DRAIN	:= 1
BBR_PROBE_BW	:= 2
BBR_PROBE_RTT	:= 3
assert QB_CYCLE + 4 <= QC_FIELDS_END
assert QC_HDR_TICK + 4 <= QB_ROUNDS
QUIC_MTU_MIN	:= 1200				; every QUIC path takes this (RFC 9000 14)
PACE_MIN_RTT	:= 4000				; µs: below it no pacing (the pacing timer: 0.2 ms at least)
assert QC_PCHALO + 8 <= QC_FIELDS_END
QUIC_RETRY_AT	:= 64				; connections not validated yet, a worker:
						; past it new ones get a Retry first
QTOK_LIFE	:= 10000000			; a Retry token is good 10 s (µs)
QUIC_CWND0	:= 14720			; the initial window
QUIC_CWNDMIN	:= 2 * QUIC_DGRAM

QCS_HS		:= 1				; handshaking
QCS_EST		:= 2				; established
QCS_CLOSING	:= 3				; CONNECTION_CLOSE sent or received: going

QF_VALID	:= 1				; address validated (a Handshake packet came)
QF_INIT_GONE	:= 2				; Initial keys discarded
QF_HELLO	:= 4				; tls_hello answered
QF_DONE		:= 8				; the handshake is complete
QF_HDONE	:= 16				; HANDSHAKE_DONE to send
QF_CLOSE	:= 32				; CONNECTION_CLOSE to send
QF_APP_ERR	:= 64				; ... of the application (0x1d)
QF_LINKED	:= 128				; in the list and the hash (until qc_closing)
QF_BBR		:= 512				; BBR's its congestion control (QB_*), not CUBIC
QF_EARLY	:= 256				; 0-RTT taken: its keys at QC_K0, the streams ready

; packet number spaces
QC_PS		:= QC_FIELDS_END
PS_NEXT		:= 0				; q: our next packet number
PS_LARGEST	:= 8				; q: the largest received, -1 none
PS_LTIME	:= 16				; q: when (µs)
PS_ACKQ		:= 24				; d: ack-eliciting packets not acknowledged yet
PS_NR		:= 28				; d: ranges received
PS_R		:= 32				; PS_RMAX of (hi q, lo q), the highest first
PS_RMAX		:= 12
PS_SIZE		:= 256

; sent packets, a ring a space
QC_SP		:= QC_PS + 3 * PS_SIZE
SP_N		:= 128
SP_PN		:= 0				; q
SP_TIME		:= 8				; q
SP_FL		:= 16				; d: SPF_*
SP_COFF		:= 20				; d: its crypto data
SP_CLEN		:= 24				; d
SP_SSESS	:= 28				; d: the stream session whose data it carried
SP_SGEN		:= 32				; d: (its generation)
SP_SFIN		:= 36				; d: and its FIN
SP_SOFF		:= 40				; q: the stream data's offset
SP_SLEN		:= 48				; d: and length
SP_CTL		:= 52				; d: our control stream's bytes in it
SP_FR		:= 56				; d: control frames (QF2_*) it carried
SP_BYTES	:= 60				; d: its size (in flight while ack-eliciting)
SP_SIZE		:= 64
SPF_SENT	:= 1				; a packet is recorded here
SPF_ACKEL	:= 2				; ack-eliciting
SPF_ACKED	:= 4
SPF_HDONE	:= 8				; it carried HANDSHAKE_DONE
SPF_MTU		:= 16				; a path MTU probe (QC_MTU_TRY)
SPF_RATE	:= 32				; BBR: the round's packet

QC_TS		:= QC_SP + 3 * SP_N * SP_SIZE	; the TLS state (TS_SIZE)
QC_QT		:= QC_TS + 2048			; QUIC's TLS block (QT_SIZE)
QC_KEYS		:= QC_QT + 2048			; 6 * QK: rx, tx a level
QC_CRX		:= 36864			; crypto received: Initial (CH_MAX)
QC_CRX_HS	:= QC_CRX + CH_MAX		; Handshake (2048)
QC_CRX_HSCAP	:= 2048
QC_CRBM		:= QC_CRX_HS + QC_CRX_HSCAP	; which bytes came: Initial
QC_CRBM_HS	:= QC_CRBM + CH_MAX / 8
QC_TLSOUT	:= 65536			; tls_hello's out: ServerHello | the flight
QC_TLSROOM	:= 65536
QC_STREAMS	:= 131072			; streams (http3.inc)
assert QC_KEYS + 6 * QK_SIZE <= QC_CRX
assert QC_CRBM_HS + QC_CRX_HSCAP / 8 <= QC_TLSOUT
assert TS_SIZE <= 2048
assert QT_SIZE <= 2048

bss
	align 16
	g_qfd		rd MAX_LISTENERS * MAX_WORKERS	; supervisor: the UDP sockets
	g_qfd4		rd MAX_LISTENERS * MAX_WORKERS	; and at preferred_address (0 none)
	g_qfd6		rd MAX_LISTENERS * MAX_WORKERS
	g_qls_tmp:	rb LS_SIZE			; a listener as at its preferred address
	g_qs_n		dd ?
	g_qs_pend	dd ?				; sockets with datagrams left (bits)
	g_qs_fd		rd QS_MAX
	g_qs_lst	rd QS_MAX
	g_qnow		dq ?				; µs (CLOCK_MONOTONIC)
	g_qc_head	dd ?				; connections (+ 1)
	g_qc_count	dd ?
	g_qc_unval	dd ?				; not validated yet (QUIC_RETRY_AT)
	g_qd_sa		dq ?				; the datagram qc_packet takes: its sender
	g_qd_salen	dd ?
	g_qd_slot	dd ?				; and the socket it came on
	g_qpace_next	dq ?				; µs the earliest paced connection may send, 0 none
	g_qpace_armed	dd ?				; io_uring: its timer is set
	g_qpace_ts	rq 2				; (that timer's timeout)
	g_qtx_ect	dd ?				; the next datagram is marked ECT(0)
	g_qgso_off	dd ?				; this worker's device cannot segment
	g_qgso_first	rd QTX_N			; a message's first datagram
	g_qgso_fd	rd QTX_N
	g_qgso_mm:	rb QTX_N * 64
	g_qgso_cm:	rb QTX_N * 48			; UDP_SEGMENT, the ECN mark
	g_qd_gro	dd ?				; GRO: its datagrams' size, 0 one datagram
	g_qd_ecn	dd ?				; and its ECN codepoint (0 none, 1 ECT(1), 2 ECT(0), 3 CE)
	g_qst_retry	dq ?				; Retries sent
	g_qtok_key	rb 16				; supervisor: Retry tokens' key
	align 8
	qs_steer_prog	rq 7				; (qs_steer: built in qs_open_all)
	g_qsr_key	rb 32				; and stateless resets' (right after it)
	g_qsr_win	dq ?				; resets sent: this second's start (µs)
	g_qsr_n		dd ?				; and how many
	g_qtok_buf	rb 64				; a token opened
	align 16
	g_qtok_gcm	rb GCM_SIZE
	g_qdirty_n	dd ?
	g_qdirty	rq QDIRTY_MAX			; session | generation << 32
	g_qtx_n		dd ?
	g_qtx_fds	rd QTX_N
	g_qtmp:	rb 64
	align 16
	g_qh:	rb QH_N * 16			; key (q), session + 1 (d), generation (d)
	g_qrx_mm:	rb QRX_N * 64
	g_qrx_iov:	rb QRX_N * 16
	g_qrx_sa:	rb QRX_N * 32
	g_qrx_cm:	rb QRX_N * 64			; control: the ECN mark (IP_TOS, IPV6_TCLASS)
	g_qtx_mm:	rb QTX_N * 64
	g_qtx_iov:	rb QTX_N * 16
	g_qtx_sa:	rb QTX_N * 32
	g_qrx_buf:	rb QRX_N * QRX_SZ
	g_qtx_buf:	rb QTX_N * QTX_SZ
end bss

rodata
	align 8
	ts_qtick	dq 0, 10000000			; 10 ms
	qs_bufsize	dd 4 shl 20			; UDP socket buffers (capped by the kernel)
	; a datagram's ECT(0), by control message (qtx_commit)
	align 8
	ecn_cm_ip	dq 20
			dd IPPROTO_IP, IP_TOS, 2, 0
	ecn_cm_ip6	dq 20
			dd IPPROTO_IPV6, IPV6_TCLASS, 2, 0
	; classic BPF for the UDP sockets' reuseport group (it sees the UDP
	; payload): the socket index (= the worker) is the first byte of the
	; Destination Connection ID, at 1 in a short header, at 6 in a long
	; one, modulo the workers: ours name their worker, a client's first
	; (random) spread evenly, the same one always to the same worker.
	; (The modulus is set when the sockets open.)
	align 8
	qs_steer	dw 7, 0, 0, 0			; struct sock_fprog
			dq qs_steer_prog
	; our transport parameters past the connection IDs: max_idle_timeout
	; 30 s, max_udp_payload_size 1472, initial_max_data 1 MiB, stream data
	; 256 KiB (bidi local), 48 KiB (bidi remote: a request's body; more as its
	; queue drains), 64 KiB (uni), 100 bidi streams,
	; 16 uni
	qtp_fixed	db 0x01,4, 0x80,0x00,0x75,0x30
			db 0x03,2, 0x45,0xC0
			db 0x04,4, 0x80,0x10,0x00,0x00
			db 0x05,4, 0x80,0x04,0x00,0x00
			db 0x06,4, 0x80,0x00,0xC0,0x00	; (H3_WINDOW: a request's queue holds it)
			db 0x07,4, 0x80,0x01,0x00,0x00
			db 0x08,2, 0x40,100
			db 0x09,1, 16
	qtp_fixed.len = $ - qtp_fixed
end rodata

; ------------------------------------------------------------- helpers

; rsi = cursor, rdx = end: rax = a varint, rsi past it; CF when truncated.
; Keeps rdx and everything but rax, rcx, rsi.
qv_read:
	cmp	rsi,rdx
	jae	.short
	movzx	eax,byte [rsi]
	mov	ecx,eax
	shr	ecx,6
	and	eax,0x3F
	mov	r11d,1
	shl	r11d,cl				; its length: 1, 2, 4 or 8
	lea	rcx,[rsi+r11]
	cmp	rcx,rdx
	ja	.short
	inc	rsi
	dec	r11d
	jz	.done
@@:
	shl	rax,8
	movzx	ecx,byte [rsi]
	or	rax,rcx
	inc	rsi
	dec	r11d
	jnz	@b
.done:
	clc
	ret
.short:
	stc
	ret

; rdi = out, rax = value (< 2^62): its shortest varint, rdi past it.
; Keeps everything but rax, rcx, rdi.
qv_write:
	cmp	rax,64
	jb	.one
	cmp	rax,16384
	jb	.two
	cmp	rax,1 shl 30
	jb	.four
	mov	rcx,0xC000000000000000
	or	rax,rcx
	bswap	rax
	mov	[rdi],rax
	add	rdi,8
	ret
.four:
	or	eax,0x80000000
	bswap	eax
	mov	[rdi],eax
	add	rdi,4
	ret
.two:
	or	eax,0x4000
	xchg	al,ah
	mov	[rdi],ax
	add	rdi,2
	ret
.one:
	mov	[rdi],al
	inc	rdi
	ret

; ebx = connection session: r14 = its buffer, r15 = its QC (the same).
macro qc_regs
	mov	r14d,ebx
	shl	r14,HB_SHIFT
	add	r14,[g_hbuf_base]
	mov	r15,r14
end macro

; ecx = level, edx = 0 rx / 1 tx: rax = that QK. Keeps the rest.
macro qc_key level*, dir*
	lea	eax,[level*2+dir]
	imul	eax,eax,QK_SIZE
	lea	rax,[r15+QC_KEYS+rax]
end macro

; µs now, into g_qnow
qs_clock:
	sub	rsp,24
	mov	edi,CLOCK_MONOTONIC
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	imul	rax,[rsp],1000000
	mov	rcx,rax
	mov	rax,[rsp+8]
	xor	edx,edx
	mov	r8d,1000
	div	r8
	add	rax,rcx
	mov	[g_qnow],rax
	add	rsp,24
	ret

; ---------------------------------------------------- sockets (supervisor)

; Before the workers fork: a UDP socket per worker for every listener
; with http3, bound where its TCP sockets are. eax < 0 on a failure (the
; listener's address is logged).
qs_open_all:
	push	rbx
	push	r12
	push	r13
	push	r14
	lea	rdi,[g_qtok_key]		; Retry tokens, stateless resets: keys
	mov	esi,16 + 32			; every worker shares
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	; the steering program, modulo this many workers
	lea	rdi,[qs_steer_prog]
	lea	rsi,[.prog]
	mov	ecx,7 * 8
	rep	movsb
	mov	eax,[g_workers]
	mov	dword [qs_steer_prog+5 * 8 + 4],eax
	mov	eax,[g_plan_qlb_len]		; the worker's byte after the server ID
	test	eax,eax
	jz	@f
	inc	eax
	add	dword [qs_steer_prog+2 * 8 + 4],eax
	add	dword [qs_steer_prog+4 * 8 + 4],eax
@@:
	xor	r12d,r12d			; listener
.listener:
	cmp	r12d,[g_plan_listeners]
	jae	.done
	imul	rbx,r12,LS_SIZE
	lea	rbx,[g_listeners+rbx]
	test	dword [rbx+LS_FLAGS],LSF_H3
	jz	.next
	xor	r13d,r13d			; worker
.socket:
	call	.open
	test	eax,eax
	js	.failed
	mov	ecx,r12d
	imul	ecx,ecx,MAX_WORKERS
	add	ecx,r13d
	mov	[g_qfd+rcx*4],eax
	inc	r13d
	cmp	r13d,[g_workers]
	jb	.socket
	; the group's steering: a packet goes to the worker its connection ID
	; names (RFC 9000's connection IDs; a client's first Initial, whose ID
	; it chose, falls back to the kernel's hash)
	mov	edi,r12d
	imul	edi,edi,MAX_WORKERS
	mov	edi,[g_qfd+rdi*4]
	mov	esi,SOL_SOCKET
	mov	edx,SO_ATTACH_REUSEPORT_CBPF
	lea	r10,[qs_steer]
	mov	r8d,16
	mov	eax,SYS_setsockopt
	syscall
	; at its preferred addresses too, their own groups steered the same way
	mov	r14,rbx
	lea	rsi,[r14+LS_PA4]
	mov	edx,16
	mov	ecx,AF_INET
	lea	r8,[g_qfd4]
	call	.preferred
	js	.failed
	lea	rsi,[r14+LS_PA6]
	mov	edx,28
	mov	ecx,AF_INET6
	lea	r8,[g_qfd6]
	call	.preferred
	js	.failed
	mov	rbx,r14
.next:
	inc	r12d
	jmp	.listener
.done:
	xor	eax,eax
.failed:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
.prog	dw 0x30
	db 0, 0
	dd 0					; ld  byte [0]
	dw 0x45
	db 0, 2
	dd 0x80					; jset #0x80: long, else short
	dw 0x30
	db 0, 0
	dd 6					; ld  byte [6]
	dw 0x05
	db 0, 0
	dd 1					; ja past the next
	dw 0x30
	db 0, 0
	dd 1					; ld  byte [1]
	dw 0x94
	db 0, 0
	dd 1					; mod #workers (set above)
	dw 0x16
	db 0, 0
	dd 0					; ret a

; r14 = listener, rsi = one of its preferred addresses (edx bytes, family
; ecx), r8 = where its sockets go: a socket a worker. eax < 0 on a failure.
.preferred:
	xor	eax,eax
	cmp	word [rsi],0
	je	.pa_out				; none
	push	r8
	push	rcx
	push	rdx
	push	rsi
	lea	rdi,[g_qls_tmp]			; the listener, at that address
	mov	rsi,r14
	mov	ecx,LS_SIZE
	rep	movsb
	lea	rdi,[g_qls_tmp+LS_SA]
	mov	ecx,28
	xor	eax,eax
	rep	stosb
	pop	rsi
	pop	rdx
	pop	rcx
	lea	rdi,[g_qls_tmp+LS_SA]
	push	rcx
	mov	ecx,edx
	rep	movsb
	pop	rcx
	mov	[g_qls_tmp+LS_SALEN],edx
	mov	[g_qls_tmp+LS_FAMILY],ecx	; (IPv6 only, for an IPv6 one)
	pop	r8
	lea	rbx,[g_qls_tmp]
	xor	r13d,r13d
.pa_socket:
	push	r8
	call	.open
	pop	r8
	test	eax,eax
	js	.pa_out
	mov	ecx,r12d
	imul	ecx,ecx,MAX_WORKERS
	add	ecx,r13d
	mov	[r8+rcx*4],eax
	inc	r13d
	cmp	r13d,[g_workers]
	jb	.pa_socket
	mov	edi,r12d
	imul	edi,edi,MAX_WORKERS
	mov	edi,[r8+rdi*4]
	mov	esi,SOL_SOCKET
	mov	edx,SO_ATTACH_REUSEPORT_CBPF
	lea	r10,[qs_steer]
	mov	r8d,16
	mov	eax,SYS_setsockopt
	syscall
	xor	eax,eax
.pa_out:
	test	eax,eax
	ret

; rbx = listener: eax = a bound socket, or -errno
.open:
	movzx	edi,word [rbx+LS_SA]		; the family its TCP sockets got
	mov	esi,SOCK_DGRAM or SOCK_CLOEXEC or SOCK_NONBLOCK
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	.ret
	push	rax
	cmp	word [rbx+LS_SA],AF_INET6
	jne	@f
	mov	edi,eax
	mov	esi,IPPROTO_IPV6
	mov	edx,IPV6_V6ONLY
	lea	r10,[zero_int]
	cmp	dword [rbx+LS_FAMILY],0
	je	.v6only
	lea	r10,[one_int]
.v6only:
	mov	r8d,4
	mov	eax,SYS_setsockopt
	syscall
	mov	rax,[rsp]
@@:
	mov	edi,eax
	mov	esi,SOL_SOCKET
	mov	edx,SO_REUSEADDR
	lea	r10,[one_int]
	mov	r8d,4
	mov	eax,SYS_setsockopt
	syscall
	mov	rdi,[rsp]
	mov	esi,SOL_SOCKET
	mov	edx,SO_REUSEPORT
	lea	r10,[one_int]
	mov	r8d,4
	mov	eax,SYS_setsockopt
	syscall
	mov	rdi,[rsp]			; room for bursts both ways
	mov	esi,SOL_SOCKET
	mov	edx,SO_SNDBUF
	lea	r10,[qs_bufsize]
	mov	r8d,4
	mov	eax,SYS_setsockopt
	syscall
	mov	rdi,[rsp]
	mov	esi,SOL_SOCKET
	mov	edx,SO_RCVBUF
	lea	r10,[qs_bufsize]
	mov	r8d,4
	mov	eax,SYS_setsockopt
	syscall
	; ECN: the marks of those that come, reported (either family: a
	; dual-stack socket carries IPv4 too)
	irp opt, <IPPROTO_IP,IP_RECVTOS,one_int>, <IPPROTO_IPV6,IPV6_RECVTCLASS,one_int>, \
		 <SOL_UDP,UDP_GRO,one_int>
		match lvl=,nm=,val, opt
			mov	rdi,[rsp]
			mov	esi,lvl
			mov	edx,nm
			lea	r10,[val]
			mov	r8d,4
			mov	eax,SYS_setsockopt
			syscall
		end match
	end irp
	mov	rdi,[rsp]
	lea	rsi,[rbx+LS_SA]
	mov	edx,[rbx+LS_SALEN]
	mov	eax,SYS_bind
	syscall
	pop	rcx
	test	eax,eax
	js	.ret
	mov	eax,ecx
.ret:
	ret

; ----------------------------------------------------- sockets (worker)

; This worker's sockets, watched; the batches' headers. After the engine
; is up (epoll set, or the ring), before seccomp.
qs_worker_init:
	push	rbx
	push	r12
	mov	dword [g_qs_n],0
	mov	dword [g_qs_pend],0
	mov	dword [g_qc_head],0
	mov	dword [g_qc_count],0
	mov	dword [g_qc_unval],0
	mov	dword [g_qdirty_n],0
	lea	rdi,[g_qtok_gcm]		; Retry tokens: the supervisor's key
	lea	rsi,[g_qtok_key]
	call	gcm_init
	mov	dword [g_qtx_n],0
	xor	ebx,ebx
.listener:
	cmp	ebx,[g_plan_listeners]
	jae	.headers
	imul	rax,rbx,LS_SIZE
	test	dword [g_listeners+rax+LS_FLAGS],LSF_H3
	jz	.next
	mov	eax,ebx
	imul	eax,eax,MAX_WORKERS
	add	eax,[g_worker_id]
	push	rax
	mov	eax,[g_qfd+rax*4]
	call	.add
	mov	rax,[rsp]
	mov	eax,[g_qfd4+rax*4]		; its preferred addresses' (0 none)
	call	.add
	pop	rax
	mov	eax,[g_qfd6+rax*4]
	call	.add
.next:
	inc	ebx
	jmp	.listener
	jmp	.headers
; eax = a socket (0 none), ebx = its listener: one of the worker's
.add:
	test	eax,eax
	jz	.add_out
	mov	ecx,[g_qs_n]
	cmp	ecx,QS_MAX
	jae	.add_out
	mov	[g_qs_fd+rcx*4],eax
	mov	[g_qs_lst+rcx*4],ebx
	inc	dword [g_qs_n]
	mov	edi,ecx
	call	qs_watch
.add_out:
	ret
.headers:
	cmp	dword [g_qs_n],0
	je	.out
	; receive slots: name, iovec, one buffer each
	xor	ecx,ecx
@@:
	mov	rax,rcx
	shl	rax,6
	lea	rdx,[g_qrx_mm+rax]
	mov	r8,rcx
	shl	r8,5
	lea	r8,[g_qrx_sa+r8]
	mov	[rdx],r8			; msg_name
	mov	dword [rdx+8],28		; msg_namelen
	mov	r8,rcx
	shl	r8,6
	lea	r8,[g_qrx_cm+r8]
	mov	[rdx+32],r8			; msg_control
	mov	r8,rcx
	shl	r8,4
	lea	r8,[g_qrx_iov+r8]
	mov	[rdx+16],r8			; msg_iov
	mov	qword [rdx+24],1
	imul	r9,rcx,QRX_SZ
	lea	r9,[g_qrx_buf+r9]
	mov	[r8],r9
	mov	qword [r8+8],QRX_SZ
	inc	ecx
	cmp	ecx,QRX_N
	jb	@b
	; the timer: a QUIC tick every 10 ms (io_uring; epoll waits that long)
	cmp	dword [g_engine],ENGINE_EPOLL
	je	.out
	call	qs_arm_timer
.out:
	pop	r12
	pop	rbx
	ret

; edi = socket slot: watch it (epoll: level-triggered; io_uring: a multishot poll)
qs_watch:
	mov	esi,edi
	mov	edi,[g_qs_fd+rdi*4]
	cmp	dword [g_engine],ENGINE_EPOLL
	jne	.ring
	mov	edx,esi
	mov	rcx,EK_QUIC shl 56
	or	rdx,rcx
	mov	esi,EPOLLIN
	jmp	ep_add
.ring:
	push	rdi
	push	rsi
	call	ring_get_sqe
	pop	rsi
	pop	rdi
	mov	byte [rax+SQE_OPCODE],IORING_OP_POLL_ADD
	mov	[rax+SQE_FD],edi
	mov	dword [rax+SQE_OP_FLAGS],EPOLLIN
	mov	dword [rax+SQE_LEN],IORING_POLL_ADD_MULTI
	mov	rcx,OP_QPOLL shl 56
	or	rcx,rsi
	mov	[rax+SQE_USER_DATA],rcx
	ret

qs_arm_timer:
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_TIMEOUT
	lea	rcx,[ts_qtick]
	mov	[rax+SQE_ADDR],rcx
	mov	dword [rax+SQE_LEN],1
	mov	dword [rax+SQE_OP_FLAGS],IORING_TIMEOUT_MULTISHOT
	mov	rcx,OP_QTIMER shl 56
	mov	[rax+SQE_USER_DATA],rcx
	ret

; io_uring: a socket is readable (ebx = slot, r15d = cqe flags)
on_qpoll:
	push	r15
	mov	edi,ebx
	call	qs_readable
	pop	r15
	test	r15d,IORING_CQE_F_MORE
	jnz	.out
	mov	edi,ebx				; the multishot poll ended: again
	jmp	qs_watch
.out:
	ret

; io_uring: pacing's timer (qs_pace_timer)
on_qpace:
	mov	dword [g_qpace_armed],0
	jmp	qs_tick

; after the loop's sends: a timer for the earliest data pacing holds, when
; it comes before the tick (io_uring; epoll's wait takes it: ep_wait_timeout)
qs_pace_timer:
	mov	rax,[g_qpace_next]
	test	rax,rax
	jz	.out
	cmp	dword [g_qpace_armed],0
	jne	.out
	cmp	dword [g_engine],ENGINE_EPOLL
	je	.out
	sub	rax,[g_qnow]
	cmp	rax,9000
	jae	.out				; the tick comes first
	cmp	rax,200
	jge	@f
	mov	eax,200
@@:
	imul	rax,rax,1000			; ns
	mov	qword [g_qpace_ts],0
	mov	[g_qpace_ts+8],rax
	mov	dword [g_qpace_armed],1
	call	ring_get_sqe
	mov	byte [rax+SQE_OPCODE],IORING_OP_TIMEOUT
	lea	rcx,[g_qpace_ts]
	mov	[rax+SQE_ADDR],rcx
	mov	dword [rax+SQE_LEN],1
	mov	dword [rax+SQE_OP_FLAGS],0
	mov	rcx,OP_QPACE shl 56
	mov	[rax+SQE_USER_DATA],rcx
.out:
	ret

on_qtimer:
	test	r15d,IORING_CQE_F_MORE
	jnz	qs_tick
	call	qs_arm_timer
	jmp	qs_tick

; ------------------------------------------------------------- receive

; edi = socket slot: every datagram waiting there
qs_readable:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r12d,edi
	btr	[g_qs_pend],edi
	mov	r14d,QRX_BUDGET
.batch:
	xor	ecx,ecx				; names: room again
@@:
	mov	rax,rcx
	shl	rax,6
	mov	dword [g_qrx_mm+rax+8],28
	mov	qword [g_qrx_mm+rax+40],64	; msg_controllen
	inc	ecx
	cmp	ecx,QRX_N
	jb	@b
	mov	edi,[g_qs_fd+r12*4]
	lea	rsi,[g_qrx_mm]
	mov	edx,QRX_N
	mov	r10d,MSG_DONTWAIT
	xor	r8d,r8d
	mov	eax,SYS_recvmmsg
	syscall
	test	eax,eax
	jle	.done
	mov	r13d,eax
	push	r13
	call	qs_clock
	pop	r13
	xor	ebx,ebx
.dgram:
	cmp	ebx,r13d
	jae	.more
	mov	rax,rbx
	shl	rax,6
	call	qs_ecn_of			; g_qd_ecn: its ECN mark
	mov	edx,[g_qrx_mm+rax+56]		; msg_len
	mov	r8d,[g_qrx_mm+rax+8]		; msg_namelen
	imul	rsi,rbx,QRX_SZ
	lea	rsi,[g_qrx_buf+rsi]
	mov	rcx,rbx
	shl	rcx,5
	lea	rcx,[g_qrx_sa+rcx]
	mov	edi,r12d
	push	rbx
	push	r13
	mov	eax,[g_qd_gro]			; several datagrams (GRO): one by one
	test	eax,eax
	jz	.whole
	cmp	edx,eax
	jbe	.whole
.segment:
	push	rdx
	push	rsi
	push	rcx
	push	r8
	push	rdi
	push	rax
	mov	edx,eax
	call	qs_datagram
	pop	rax
	pop	rdi
	pop	r8
	pop	rcx
	pop	rsi
	pop	rdx
	add	rsi,rax
	sub	edx,eax
	cmp	edx,eax
	ja	.segment
.whole:
	call	qs_datagram
	pop	r13
	pop	rbx
	inc	ebx
	jmp	.dgram
.more:
	cmp	r13d,QRX_N
	jne	.done
	dec	r14d				; maybe more waiting: within the budget,
	jnz	.batch				; or on the loop's next turn (the timers,
	bts	[g_qs_pend],r12d		; the sends and other sockets first)
.done:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rax = a receive slot's offset in g_qrx_mm: g_qd_ecn = the ECN codepoint
; its control messages carry (IP_TOS or IPV6_TCLASS), 0 without. Keeps rax.
qs_ecn_of:
	mov	dword [g_qd_ecn],0
	mov	dword [g_qd_gro],0
	mov	rsi,[g_qrx_mm+rax+32]		; msg_control
	mov	rdx,[g_qrx_mm+rax+40]		; msg_controllen
	add	rdx,rsi
.cmsg:
	lea	rcx,[rsi+16]
	cmp	rcx,rdx
	ja	.out
	mov	rcx,[rsi]			; cmsg_len
	cmp	rcx,16
	jb	.out
	cmp	dword [rsi+8],SOL_UDP		; GRO: the datagrams' size
	jne	@f
	cmp	dword [rsi+12],UDP_GRO
	jne	@f
	movzx	ecx,word [rsi+16]
	mov	[g_qd_gro],ecx
	mov	rcx,[rsi]
	jmp	.next
@@:
	cmp	dword [rsi+8],IPPROTO_IP
	jne	@f
	cmp	dword [rsi+12],IP_TOS
	je	.mark
@@:
	cmp	dword [rsi+8],IPPROTO_IPV6
	jne	.next
	cmp	dword [rsi+12],IPV6_TCLASS
	jne	.next
.mark:
	movzx	ecx,byte [rsi+16]
	and	ecx,3
	mov	[g_qd_ecn],ecx
	mov	rcx,[rsi]
	jmp	.next
.next:
	add	rcx,7				; aligned to 8
	and	rcx,not 7
	add	rsi,rcx
	jmp	.cmsg
.out:
	ret

; the loop's turn: the sockets qs_readable left datagrams in, read again
; (each once a turn)
qs_resume:
	push	rbx
	mov	ebx,[g_qs_pend]
.next:
	test	ebx,ebx
	jz	.done
	bsf	edi,ebx
	btr	ebx,edi
	call	qs_readable			; (clears its bit, may set it again)
	jmp	.next
.done:
	pop	rbx
	ret

; One datagram: edi = socket slot, rsi = bytes, edx = length, rcx = the
; sender's address, r8d = its length.
QD_SLOT		:= 0
QD_BUF		:= 8
QD_END		:= 16
QD_SA		:= 24
QD_SALEN	:= 32
QD_LEN		:= 36
QD_VER		:= 40
QD_TOK		:= 48				; q: an Initial's token
QD_TOKLEN	:= 56				; d
QD_RETRIED	:= 60				; d: its token is our Retry's: validated
QD_ODC		:= 64				; q: then the first Destination Connection ID
QD_ODCLEN	:= 72				; d
QD_NEW		:= 76				; d: its connection was made for it
QD_SIZE		:= 88
qs_datagram:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,QD_SIZE
	mov	[rsp+QD_SLOT],edi
	mov	[rsp+QD_BUF],rsi
	lea	rax,[rsi+rdx]
	mov	[rsp+QD_END],rax
	mov	[rsp+QD_SA],rcx
	mov	[rsp+QD_SALEN],r8d
	mov	[rsp+QD_LEN],edx
	mov	dword [rsp+QD_TOKLEN],0
	mov	dword [rsp+QD_RETRIED],0
	mov	dword [rsp+QD_NEW],0
	mov	r12,rsi				; the packet's start
	mov	ebx,NIL				; no connection yet
.packet:
	mov	rax,[rsp+QD_END]
	sub	rax,r12
	cmp	rax,7
	jb	.out
	movzx	eax,byte [r12]
	test	eax,0x80
	jz	.short
	test	eax,0x40			; the fixed bit
	jz	.out
	; long header: version, dcid, scid
	mov	r13d,[r12+1]
	bswap	r13d				; version
	mov	[rsp+QD_VER],r13d
	cmp	r13d,QUIC_V1
	je	@f
	cmp	r13d,QUIC_V2
	je	@f
	test	r13d,r13d
	jz	.out				; a Version Negotiation: not for a server
	cmp	r12,[rsp+QD_BUF]
	jne	.out
	cmp	dword [rsp+QD_LEN],1200
	jb	.out
	mov	rdi,rsp
	call	qs_send_vn
	jmp	.out
@@:
	lea	rsi,[r12+5]
	mov	rdx,[rsp+QD_END]
	movzx	ecx,byte [rsi]			; dcid
	cmp	ecx,20
	ja	.out
	inc	rsi
	mov	r8,rsi				; dcid
	mov	r9d,ecx
	add	rsi,rcx
	cmp	rsi,rdx
	jae	.out
	movzx	ecx,byte [rsi]			; scid
	cmp	ecx,20
	ja	.out
	inc	rsi
	mov	r10,rsi
	mov	r11d,ecx
	add	rsi,rcx
	cmp	rsi,rdx
	ja	.out
	; the type: v1 Initial 0, 0-RTT 1, Handshake 2, Retry 3; v2 rotates them
	movzx	ebp,byte [r12]
	shr	ebp,4
	and	ebp,3
	cmp	r13d,QUIC_V2
	jne	@f
	dec	ebp
	and	ebp,3
@@:
	cmp	ebp,3
	je	.out				; Retry: never to a server
	push	r8
	push	r9
	push	r10
	push	r11
	cmp	ebp,0
	jne	.no_token
	call	qv_read				; Initial: the token
	jc	.pop_out
	mov	[rsp+32+QD_TOK],rsi
	mov	[rsp+32+QD_TOKLEN],eax
	add	rsi,rax
	cmp	rsi,rdx
	ja	.pop_out
.no_token:
	call	qv_read				; the length: packet number and payload
	jc	.pop_out
	lea	r13,[rsi+rax]			; the packet's end
	cmp	r13,rdx
	ja	.pop_out
	mov	r15,rsi				; the packet number's start
	pop	r11
	pop	r10
	pop	r9
	pop	r8
	; its connection
	cmp	ebx,NIL
	jne	.have
	mov	rdi,r8
	mov	esi,r9d
	call	qh_find
	mov	ebx,eax
	cmp	ebx,NIL
	jne	.have
	test	ebp,ebp
	jnz	.out				; Handshake for nobody
	cmp	dword [rsp+QD_LEN],1200		; a client's first datagram is padded
	jb	.out
	cmp	r9d,8
	jb	.out
	; its address: validated by the token of our Retry, or not yet; past
	; QUIC_RETRY_AT not yet validated (or `http3 retry`), a Retry first
	cmp	dword [rsp+QD_TOKLEN],0
	je	@f
	push	r8
	push	r9
	push	r10
	push	r11
	lea	rdi,[rsp+32]
	call	qs_token_check			; QD_RETRIED, QD_ODC when it is good
	pop	r11
	pop	r10
	pop	r9
	pop	r8
@@:
	cmp	dword [rsp+QD_RETRIED],0
	jne	.create
	mov	eax,[rsp+QD_SLOT]
	mov	eax,[g_qs_lst+rax*4]
	imul	rax,rax,LS_SIZE
	test	dword [g_listeners+rax+LS_FLAGS],LSF_H3RETRY
	jnz	.retry
	cmp	dword [g_qc_unval],QUIC_RETRY_AT
	jb	.create
.retry:
	mov	rdi,rsp
	call	qs_send_retry			; r8/r9 dcid, r10/r11 scid
	jmp	.out
.create:
	mov	rdi,rsp				; a new connection
	call	qc_new				; r8/r9 dcid, r10/r11 scid
	cmp	eax,NIL
	je	.out
	mov	ebx,eax
	mov	dword [rsp+QD_NEW],1
.have:
	mov	edi,ebx
	mov	esi,ebp
	cmp	esi,2
	jne	@f
	mov	esi,QL_HS
@@:
	cmp	ebp,1
	jne	@f
	mov	esi,QL_0RTT			; (dropped unless the connection took 0-RTT)
@@:
	mov	rdx,r12
	mov	rcx,r13
	sub	rcx,r12				; the packet's length
	mov	r8,r15
	sub	r8,r12				; its packet number's offset
	mov	r9d,[rsp+QD_LEN]
	mov	rax,[rsp+QD_SA]			; where it came from (qc_migrate)
	mov	[g_qd_sa],rax
	mov	eax,[rsp+QD_SALEN]
	mov	[g_qd_salen],eax
	mov	eax,[rsp+QD_SLOT]
	mov	[g_qd_slot],eax
	call	qc_packet
	mov	dword [rsp+QD_LEN],0		; (the datagram is counted once)
	cmp	dword [rsp+QD_NEW],0
	je	.next_packet
	mov	dword [rsp+QD_NEW],0
	qc_regs					; made for a first packet that did not
	cmp	qword [r15+QC_PS+PS_LARGEST],-1	; open (noise, a forged Initial): gone
	jne	.next_packet			; now, not at its idle timeout
	call	qc_free
	jmp	.out
.next_packet:
	mov	r12,r13
	jmp	.packet
.pop_out:
	add	rsp,32
	jmp	.out
.short:
	test	eax,0x40
	jz	.out
	mov	rax,[rsp+QD_END]
	sub	rax,r12
	cmp	rax,1 + 8 + 20
	jb	.out
	lea	rdi,[r12+1]			; our connection IDs: 8 bytes
	mov	esi,8
	call	qh_find
	cmp	eax,NIL
	je	.reset
	cmp	ebx,NIL
	je	@f
	cmp	eax,ebx
	jne	.out				; coalesced with another connection's
@@:
	mov	edi,eax
	mov	esi,QL_APP
	mov	rdx,r12
	mov	rcx,[rsp+QD_END]
	sub	rcx,r12
	mov	r8d,9
	mov	r9d,[rsp+QD_LEN]
	mov	rax,[rsp+QD_SA]			; where it came from (qc_migrate)
	mov	[g_qd_sa],rax
	mov	eax,[rsp+QD_SALEN]
	mov	[g_qd_salen],eax
	mov	eax,[rsp+QD_SLOT]
	mov	[g_qd_slot],eax
	call	qc_packet
.out:
	add	rsp,QD_SIZE
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret
.reset:
	cmp	r12,[rsp+QD_BUF]
	jne	.out				; (only for a datagram's first packet)
	mov	rdi,rsp
	call	qs_send_reset
	jmp	.out

; rdi = the datagram's frame: its short header names no connection we
; hold (a worker restarted, a connection long gone): a Stateless Reset
; (RFC 9000 10.3), shorter than what came so two servers cannot loop,
; at most 1000 a second
qs_send_reset:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	mov	r13d,[r12+QD_LEN]
	dec	r13d				; shorter than the trigger
	cmp	r13d,21 + 20
	jb	.out				; too short to pass for a packet
	cmp	r13d,43
	jbe	@f
	mov	r13d,43
@@:
	mov	rax,[g_qnow]
	mov	rcx,rax
	sub	rcx,[g_qsr_win]
	cmp	rcx,1000000
	jb	@f
	mov	[g_qsr_win],rax
	mov	dword [g_qsr_n],0
@@:
	cmp	dword [g_qsr_n],1000
	jae	.out
	inc	dword [g_qsr_n]
	call	qtx_slot
	test	rax,rax
	jz	.out
	mov	rbx,rax
	rdtsc					; unpredictable enough bytes before the token
	shl	rdx,32
	or	rax,rdx
	mov	rdx,0x9E3779B97F4A7C15
	xor	ecx,ecx
@@:
	imul	rax,rdx
	ror	rax,29
	mov	[rbx+rcx],rax
	add	ecx,8
	cmp	ecx,32
	jb	@b
	mov	al,[rbx]
	and	al,0x3F
	or	al,0x40				; a short header's first byte
	mov	[rbx],al
	lea	rdi,[rbx+r13-16]
	mov	rsi,[r12+QD_BUF]
	inc	rsi				; the connection ID it named
	call	qs_reset_token
	mov	edi,[r12+QD_SLOT]
	mov	ecx,r13d
	mov	rsi,[r12+QD_SA]
	mov	r8d,[r12+QD_SALEN]
	call	qtx_commit
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = out[16], rsi = one of our connection IDs (8 bytes): its stateless
; reset token, HMAC-SHA256 with the shared key (the same in every worker)
qs_reset_token:
	push	rbx
	sub	rsp,32
	mov	rbx,rdi
	mov	rcx,rsi
	mov	rdi,rsp
	lea	rsi,[g_qsr_key]
	mov	edx,32
	mov	r8d,8
	call	hmac_sha256
	movdqu	xmm0,[rsp]
	movdqu	[rbx],xmm0
	add	rsp,32
	pop	rbx
	ret

; rdi = the datagram's frame (QD_*) of a client's first Initial, r8/r9d its
; Destination Connection ID, r10/r11d its Source: a Retry back (RFC 9000
; 17.2.5): a new connection ID to come back to, a token that proves the
; address (qs_token_make), the integrity tag
qs_send_retry:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	push	rbp
	mov	r12,rdi
	mov	r13,r8
	mov	r14d,r9d
	mov	r15,r10
	mov	ebp,r11d
	call	qtx_slot			; rax = buffer
	test	rax,rax
	jz	.out
	mov	rbx,rax
	rdtsc
	and	al,0x0F
	or	al,0xF0				; v1: type 3
	cmp	dword [r12+QD_VER],QUIC_V2
	jne	@f
	xor	al,0x30				; v2: type 0
@@:
	mov	[rbx],al
	mov	eax,[r12+QD_VER]
	bswap	eax
	mov	[rbx+1],eax
	lea	rdi,[rbx+5]
	mov	[rdi],bpl			; theirs, as they chose it
	inc	rdi
	mov	rsi,r15
	mov	ecx,ebp
	rep	movsb
	mov	byte [rdi],8			; ours: new
	inc	rdi
	mov	r15,rdi
	rdtsc					; (no syscall a packet under a flood; nothing
	shl	rdx,32				; secret in it, only different each time)
	or	rax,rdx
	mov	rdx,0x9E3779B97F4A7C15
	imul	rax,rdx
	xor	rax,qword [g_qsr_key]
	mov	[r15],rax
	mov	rdi,r15				; (this worker's: qs_steer)
	call	qc_cid_brand
	lea	rdi,[r15+8]
	call	qs_token_make			; rdi past it
	mov	r8,rdi
	sub	r8,rbx
	push	r8
	push	r8
	mov	rcx,rbx
	mov	rsi,r13
	mov	edx,r14d
	mov	r9d,[r12+QD_VER]
	call	quic_retry_tag			; after it
	pop	rcx
	pop	rcx
	add	ecx,16
	mov	edi,[r12+QD_SLOT]
	mov	rsi,[r12+QD_SA]
	mov	r8d,[r12+QD_SALEN]
	call	qtx_commit
	inc	qword [g_qst_retry]
.out:
	pop	rbp
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = out, r12 = the datagram's frame, r13/r14d = the client's first
; Destination Connection ID: a Retry token, rdi past it. 'R', a nonce
; (the TSC, the worker), then sealed with the key every worker shares
; (the client's address as associated data): when, the connection ID.
qs_token_make:
	push	rbx
	mov	rbx,rdi
	mov	byte [rbx],'R'
	rdtsc
	mov	[rbx+1],eax
	mov	[rbx+5],edx
	mov	eax,[g_worker_id]
	mov	[rbx+9],eax
	mov	rax,[g_qnow]
	mov	[rbx+13],rax
	mov	[rbx+21],r14b
	lea	rdi,[rbx+22]
	mov	rsi,r13
	mov	ecx,r14d
	rep	movsb
	lea	rdi,[g_qtok_gcm]
	lea	rsi,[rbx+1]
	mov	rdx,[r12+QD_SA]
	mov	ecx,[r12+QD_SALEN]
	lea	r8,[rbx+13]
	lea	r9d,[r14+9]
	call	gcm_seal
	lea	rdi,[rbx+13+9+16]
	add	rdi,r14
	pop	rbx
	ret

; rdi = the datagram's frame, its Initial's token (QD_TOK): when it is our
; Retry's, for this address and not stale, QD_RETRIED = 1 and QD_ODC the
; client's first Destination Connection ID (in g_qtok_buf)
qs_token_check:
	push	rbx
	mov	rbx,rdi
	mov	r9d,[rbx+QD_TOKLEN]
	sub	r9d,1 + 12 + 16
	cmp	r9d,9 + 8
	jb	.out
	cmp	r9d,9 + 20
	ja	.out
	mov	rsi,[rbx+QD_TOK]
	cmp	byte [rsi],'R'
	jne	.out
	push	r9
	push	r9
	lea	rsi,[rsi+13]			; a copy: the token is in the
	lea	rdi,[g_qtok_buf]		; packet's protected header
	lea	ecx,[r9+16]
	rep	movsb
	lea	rdi,[g_qtok_gcm]
	mov	rsi,[rbx+QD_TOK]
	inc	rsi
	mov	rdx,[rbx+QD_SA]
	mov	ecx,[rbx+QD_SALEN]
	lea	r8,[g_qtok_buf]
	call	gcm_open
	pop	r9
	pop	r9
	test	eax,eax
	jz	.out
	movzx	eax,byte [g_qtok_buf+8]
	add	eax,9
	cmp	eax,r9d
	jne	.out
	mov	rax,[g_qnow]
	sub	rax,qword [g_qtok_buf]
	cmp	rax,QTOK_LIFE
	ja	.out
	mov	dword [rbx+QD_RETRIED],1
	lea	rax,[g_qtok_buf+9]
	mov	[rbx+QD_ODC],rax
	movzx	eax,byte [g_qtok_buf+8]
	mov	[rbx+QD_ODCLEN],eax
.out:
	pop	rbx
	ret

; rdi = the datagram's frame (QD_*): a Version Negotiation back, listing
; v2 and v1 (RFC 9000 17.2.1)
qs_send_vn:
	push	rbx
	push	r12
	mov	r12,rdi
	call	qtx_slot			; rax = buffer, edx = slot
	test	rax,rax
	jz	.out
	mov	rbx,rax
	mov	rsi,[r12+QD_BUF]
	rdtsc
	or	al,0x80
	mov	[rbx],al
	mov	dword [rbx+1],0			; version 0
	lea	rdi,[rbx+5]
	movzx	ecx,byte [rsi+5]		; their dcid
	lea	r8,[rsi+6]			; (its bytes)
	lea	r9,[r8+rcx]
	movzx	eax,byte [r9]			; their scid: our dcid
	mov	[rdi],al
	inc	rdi
	push	rcx
	push	rsi
	lea	rsi,[r9+1]
	mov	ecx,eax
	rep	movsb
	pop	rsi
	pop	rcx
	mov	[rdi],cl			; their dcid: our scid
	inc	rdi
	mov	rsi,r8
	rep	movsb
	mov	dword [rdi],0xCF43336B		; 6b3343cf, 00000001
	mov	dword [rdi+4],0x01000000
	add	rdi,8
	sub	rdi,rbx
	mov	ecx,edi
	mov	edi,[r12+QD_SLOT]
	mov	rsi,[r12+QD_SA]
	mov	r8d,[r12+QD_SALEN]
	call	qtx_commit
.out:
	pop	r12
	pop	rbx
	ret

; ------------------------------------------------------------ the hash

; rdi = connection ID, esi = its length: eax = its connection, or NIL.
; Keeps rbx, rbp, r12-r15.
qh_find:
	push	r8
	push	r9
	push	r10
	call	qh_key				; rax = key, rdx = first slot
	mov	r10d,QH_N			; (never more probes than slots)
.probe:
	mov	ecx,[g_qh+rdx+8]
	test	ecx,ecx
	jz	.none
	cmp	[g_qh+rdx],rax
	jne	.skip
	dec	ecx				; still that session?
	mov	r8d,ecx
	shl	r8,S_SHIFT
	add	r8,[g_sess_base]
	mov	r9d,[r8+S_GEN]
	cmp	r9d,[g_qh+rdx+12]
	jne	.skip
	cmp	dword [r8+S_STATE],ST_OPEN
	jne	.skip
	mov	eax,ecx
	jmp	.out
.skip:
	add	edx,16
	and	edx,QH_N * 16 - 1
	dec	r10d
	jnz	.probe
.none:
	mov	eax,NIL
.out:
	pop	r10
	pop	r9
	pop	r8
	ret

; rdi = connection ID, esi = length: rax = its key, rdx = its home slot's offset
qh_key:
	xor	eax,eax
	cmp	esi,8
	jb	@f
	mov	rax,[rdi]
	jmp	.mixed
@@:
	; shorter: byte by byte
	mov	ecx,esi
@@:
	test	ecx,ecx
	jz	.mixed
	dec	ecx
	shl	rax,8
	movzx	edx,byte [rdi+rcx]
	or	rax,rdx
	jmp	@b
.mixed:
	mov	rcx,rsi
	shl	rcx,56
	xor	rax,rcx
	mov	rdx,rax
	mov	rcx,0x9E3779B97F4A7C15
	imul	rdx,rcx
	shr	rdx,64 - QH_BITS
	shl	edx,4
	ret

; rdi = connection ID, esi = length, ebx = session: in (linear probing,
; no tombstones: qh_del shifts back what follows). Not in when full.
qh_add:
	call	qh_key
	mov	r10d,QH_N
.probe:
	cmp	dword [g_qh+rdx+8],0
	je	.here
	add	edx,16
	and	edx,QH_N * 16 - 1
	dec	r10d
	jnz	.probe
	ret
.here:
	mov	[g_qh+rdx],rax
	lea	ecx,[rbx+1]
	mov	[g_qh+rdx+8],ecx
	call	session_ptr
	mov	ecx,[rax+S_GEN]
	mov	[g_qh+rdx+12],ecx
	ret

; rdi = connection ID, esi = length, ebx = session: out. The entries after
; it in its run move back where their probe would find them (backward
; shift deletion), so a run never holds holes nor tombstones.
qh_del:
	call	qh_key
	mov	r10d,QH_N
.probe:
	mov	ecx,[g_qh+rdx+8]
	test	ecx,ecx
	jz	.out
	cmp	[g_qh+rdx],rax
	jne	.skip
	dec	ecx
	cmp	ecx,ebx
	je	.found
.skip:
	add	edx,16
	and	edx,QH_N * 16 - 1
	dec	r10d
	jnz	.probe
.out:
	ret
.found:
	mov	r8d,edx				; the hole
	mov	r9d,edx				; the next entry looked at
.shift:
	mov	dword [g_qh+r8+8],0
.next:
	add	r9d,16
	and	r9d,QH_N * 16 - 1
	cmp	dword [g_qh+r9+8],0
	je	.out
	mov	rax,[g_qh+r9]			; its home slot
	mov	rcx,0x9E3779B97F4A7C15
	imul	rax,rcx
	shr	rax,64 - QH_BITS
	shl	eax,4
	; it stays when its home lies cyclically in (hole, it]
	mov	ecx,r9d
	sub	ecx,eax
	and	ecx,QH_N * 16 - 1		; its distance from home
	mov	edx,r9d
	sub	edx,r8d
	and	edx,QH_N * 16 - 1		; the hole's distance behind it
	cmp	ecx,edx
	jb	.next
	movdqu	xmm0,[g_qh+r9]			; into the hole
	movdqu	[g_qh+r8],xmm0
	mov	r8d,r9d
	jmp	.shift

; ------------------------------------------------------ connections

; A new connection for a client's first Initial: rdi = the datagram's
; frame (QD_*, its version at QD_VER), r8/r9d = its dcid, r10/r11d = its scid.
; eax = the session, or NIL.
qc_new:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	push	rbp
	mov	rbp,rdi
	push	r8
	push	r9
	push	r10
	push	r11
	call	session_alloc
	cmp	eax,NIL
	je	.none
	mov	ebx,eax
	mov	r12d,[rbp+QD_SLOT]
	mov	r12d,[g_qs_lst+r12*4]		; its listener
	call	session_ptr
	mov	dword [rax+S_STATE],ST_OPEN
	mov	dword [rax+S_INFL],0
	mov	dword [rax+S_FLAGS],SF_QC
	mov	dword [rax+S_CLIENT],-1
	mov	[rax+S_LST],r12d
	mov	dword [rax+S_TRIES],0
	mov	dword [rax+S_SERVER],NIL
	mov	dword [rax+S_CU_BID],NIL
	mov	dword [rax+S_UC_BID],NIL
	mov	dword [rax+S_PH_KIND],0
	mov	ecx,[g_tick]
	mov	[rax+S_LAST],ecx
	imul	rcx,r12,LS_SIZE
	mov	ecx,[g_listeners+rcx+LS_POOL]
	mov	[rax+S_POOL],ecx
	mov	ecx,[rax+S_GEN]
	push	rcx
	inc	dword [g_ls_active+r12*4]
	inc	dword [g_active]
	mov	edi,ebx
	call	idle_append
	qc_regs
	mov	rdi,r15				; the fields, the spaces, the logs: zero
	mov	ecx,QC_TS / 8
	xor	eax,eax
	rep	stosq
	mov	rdi,r15
	add	rdi,QC_TS
	mov	ecx,(QC_CRX - QC_TS) / 8
	rep	stosq
	lea	rdi,[r15+QC_CRBM]		; which crypto bytes came
	mov	ecx,(CH_MAX / 8 + QC_CRX_HSCAP / 8) / 8
	rep	stosq
	pop	rcx
	mov	[r15+QC_GEN],ecx
	mov	dword [r15+QC_LW_SESS],NIL	; no stream frame in the next packet
	mov	eax,ebx				; its record names its buffers
	shl	rax,H_SHIFT
	add	rax,[g_http_base]
	mov	[rax+H_BUF],r15
	mov	eax,[rbp+QD_SLOT]
	mov	[r15+QC_SOCK],eax
	mov	eax,[rbp+QD_VER]
	mov	[r15+QC_VER],eax
	mov	dword [r15+QC_STATE],QCS_HS
	mov	rsi,[rbp+QD_SA]			; the client's address
	lea	rdi,[r15+QC_PEER]
	mov	ecx,28
	rep	movsb
	mov	eax,[rbp+QD_SALEN]
	mov	[r15+QC_PEERLEN],eax
	call	peer_ptr			; its side record: the client's address
	mov	rdi,rax				; (request streams copy it)
	mov	rsi,[rbp+QD_SA]
	mov	ecx,28
	rep	movsb
	mov	dword [rax+P_SLOT],-1
	mov	dword [rax+P_HLEN],0
	mov	rax,-1
	mov	[r15+QC_PS+0*PS_SIZE+PS_LARGEST],rax
	mov	[r15+QC_PS+1*PS_SIZE+PS_LARGEST],rax
	mov	[r15+QC_PS+2*PS_SIZE+PS_LARGEST],rax
	mov	dword [r15+QC_MTU],QUIC_MTU_MIN
	mov	qword [r15+QC_CWND],QUIC_CWND0
	mov	rax,1 shl 62
	mov	[r15+QC_SSTH],rax
	mov	qword [r15+QC_SRTT],333000	; RFC 9002: the initial RTT
	mov	qword [r15+QC_RTTVAR],166500
	cmp	dword [g_plan_qcc],0
	je	@f
	or	dword [r15+QC_FLAGS],QF_BBR
@@:
	; connection IDs: ours random but its first byte, this worker (the
	; kernel steers by it: qs_steer), the client's as it chose them
	lea	rdi,[r15+QC_SCID]
	mov	esi,8
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	lea	rdi,[r15+QC_SCID]
	call	qc_cid_brand
	; a preferred_address to announce: its connection ID (sequence 1) now
	mov	eax,[rbp+QD_SLOT]
	mov	eax,[g_qs_lst+rax*4]
	imul	rax,rax,LS_SIZE
	mov	ecx,dword [g_listeners+rax+LS_PA4]
	or	ecx,dword [g_listeners+rax+LS_PA6]
	test	cx,cx
	jz	@f
	lea	rdi,[r15+QC_CIDS]
	mov	esi,8
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	lea	rdi,[r15+QC_CIDS]
	call	qc_cid_brand
	mov	dword [r15+QC_PACID],1
	mov	dword [r15+QC_NCIDS],1
	lea	rdi,[r15+QC_CIDS]
	mov	esi,8
	call	qh_add
@@:
	pop	r11
	pop	r10
	pop	r9
	pop	r8
	mov	[r15+QC_DCIDLEN],r11d
	lea	rdi,[r15+QC_DCID]
	mov	rsi,r10
	mov	ecx,r11d
	rep	movsb
	mov	[r15+QC_ODCIDLEN],r9d
	lea	rdi,[r15+QC_ODCID]
	mov	rsi,r8
	mov	ecx,r9d
	rep	movsb
	cmp	dword [rbp+QD_RETRIED],0	; its address proven by our Retry's token
	je	.unvalidated
	mov	ecx,[rbp+QD_ODCLEN]
	mov	[r15+QC_TODCIDLEN],ecx
	lea	rdi,[r15+QC_TODCID]
	mov	rsi,[rbp+QD_ODC]
	rep	movsb
	or	dword [r15+QC_FLAGS],QF_VALID
	jmp	@f
.unvalidated:
	inc	dword [g_qc_unval]
@@:
	; Initial keys from the client's dcid: rx are the client's
	qc_key	QL_INIT, 0
	mov	rdi,rax
	qc_key	QL_INIT, 1
	mov	rsi,rax
	lea	rdx,[r15+QC_ODCID]
	mov	ecx,[r15+QC_ODCIDLEN]
	mov	r8d,[r15+QC_VER]
	call	quic_initial
	; TLS: QUIC mode, our transport parameters
	lea	rax,[r15+QC_QT]
	mov	[r15+QC_TS+TS_QT],rax
	mov	eax,[rbp+QD_SLOT]		; early data where the listener takes it
	mov	eax,[g_qs_lst+rax*4]
	imul	rax,rax,LS_SIZE
	mov	ecx,TF_QUIC
	test	dword [g_listeners+rax+LS_FLAGS],LSF_0RTT
	jz	@f
	or	ecx,TF_0RTT
@@:
	mov	[r15+QC_TS+TS_FLAGS],ecx
	call	qc_tp_build
	; named by both IDs, listed
	lea	rdi,[r15+QC_SCID]
	mov	esi,8
	call	qh_add
	lea	rdi,[r15+QC_ODCID]
	mov	esi,[r15+QC_ODCIDLEN]
	call	qh_add
	mov	eax,[g_qc_head]
	mov	[r15+QC_LINK],eax
	mov	dword [r15+QC_PLINK],0
	test	eax,eax
	jz	@f
	dec	eax
	shl	rax,HB_SHIFT
	add	rax,[g_hbuf_base]
	lea	ecx,[rbx+1]
	mov	[rax+QC_PLINK],ecx
@@:
	lea	eax,[rbx+1]
	mov	[g_qc_head],eax
	inc	dword [g_qc_count]
	or	dword [r15+QC_FLAGS],QF_LINKED
	mov	eax,ebx
	jmp	.out
.none:
	add	rsp,32
	mov	eax,NIL
.out:
	pop	rbp
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; r15 = connection: QT_TPS = our transport parameters
qc_tp_build:
	lea	rdi,[r15+QC_QT+QT_TPS]
	mov	byte [rdi],0x00			; original_destination_connection_id
	mov	eax,[r15+QC_ODCIDLEN]
	lea	rsi,[r15+QC_ODCID]
	cmp	dword [r15+QC_TODCIDLEN],0
	je	@f
	mov	eax,[r15+QC_TODCIDLEN]		; (after a Retry: the first one)
	lea	rsi,[r15+QC_TODCID]
@@:
	mov	[rdi+1],al
	add	rdi,2
	mov	ecx,eax
	rep	movsb
	cmp	dword [r15+QC_TODCIDLEN],0
	je	@f
	mov	byte [rdi],0x10			; retry_source_connection_id: what the
	mov	eax,[r15+QC_ODCIDLEN]		; Retry gave, this Initial's
	mov	[rdi+1],al
	add	rdi,2
	lea	rsi,[r15+QC_ODCID]
	mov	ecx,eax
	rep	movsb
@@:
	mov	word [rdi],0x080F		; initial_source_connection_id, 8 bytes
	add	rdi,2
	mov	rax,[r15+QC_SCID]
	mov	[rdi],rax
	add	rdi,8
	mov	word [rdi],0x1002		; stateless_reset_token
	add	rdi,2
	push	rdi
	lea	rsi,[r15+QC_SCID]
	call	qs_reset_token
	pop	rdi
	add	rdi,16
	cmp	dword [r15+QC_PACID],0
	je	.no_pa
	; preferred_address: IPv4 address and port, IPv6 address and port (zero
	; for one not given), connection ID, its reset token
	mov	word [rdi],0x310D		; (49 bytes)
	add	rdi,2
	mov	eax,[r15+QC_SOCK]
	mov	eax,[g_qs_lst+rax*4]
	imul	rax,rax,LS_SIZE
	lea	rsi,[g_listeners+rax+LS_PA4]
	mov	ecx,[rsi+4]			; sockaddr_in: addr, port
	mov	[rdi],ecx
	mov	cx,[rsi+2]
	mov	[rdi+4],cx
	lea	rsi,[g_listeners+rax+LS_PA6]
	mov	rcx,[rsi+8]			; sockaddr_in6: addr, port
	mov	[rdi+6],rcx
	mov	rcx,[rsi+16]
	mov	[rdi+14],rcx
	mov	cx,[rsi+2]
	mov	[rdi+22],cx
	mov	byte [rdi+24],8
	mov	rax,[r15+QC_CIDS]
	mov	[rdi+25],rax
	push	rdi
	lea	rsi,[r15+QC_CIDS]
	add	rdi,33
	call	qs_reset_token
	pop	rdi
	add	rdi,49
.no_pa:
	mov	word [rdi],0x0C11		; version_information: the chosen one, then
	mov	eax,[r15+QC_VER]		; those we take (v2, v1)
	bswap	eax
	mov	[rdi+2],eax
	mov	dword [rdi+6],0xCF43336B
	mov	dword [rdi+10],0x01000000
	add	rdi,14
	lea	rsi,[qtp_fixed]
	mov	ecx,qtp_fixed.len
	rep	movsb
	lea	rax,[r15+QC_QT+QT_TPS]
	sub	rdi,rax
	mov	[r15+QC_QT+QT_TPSLEN],edi
	ret

; r15 = connection, rdx = its ClientHello so far, ecx = how much of it: a
; whole one from a v1 client whose version_information transport parameter
; offers v2 moves the connection to v2 before the answer (compatible
; version negotiation, RFC 9368) when the listener asks (`http3 v2`; else
; the client's choice stands): v2 Initial keys, our parameters again.
qc_compat_vn:
	cmp	dword [r15+QC_VER],QUIC_V1
	jne	.out
	mov	eax,[r15+QC_SOCK]
	mov	eax,[g_qs_lst+rax*4]
	imul	rax,rax,LS_SIZE
	test	dword [g_listeners+rax+LS_FLAGS],LSF_H3V2
	jz	.out
	mov	rsi,rdx
	lea	r8,[rdx+rcx]			; what came
	cmp	ecx,4
	jb	.out
	mov	eax,[rsi]
	bswap	eax
	and	eax,0xFFFFFF			; the message's length
	lea	rdx,[rsi+rax+4]
	cmp	rdx,r8
	ja	.out				; not whole yet
	add	rsi,4 + 2 + 32			; type, length, version, random
	call	.skip8				; session id
	jc	.out
	call	.skip16				; cipher suites
	jc	.out
	call	.skip8				; compression
	jc	.out
	add	rsi,2				; the extensions' length
.ext:
	lea	rax,[rsi+4]
	cmp	rax,rdx
	ja	.out
	movzx	eax,word [rsi]
	movzx	ecx,word [rsi+2]
	xchg	cl,ch
	add	rsi,4
	lea	r9,[rsi+rcx]
	cmp	r9,rdx
	ja	.out
	cmp	eax,0x3900			; quic_transport_parameters
	je	.tps
	mov	rsi,r9
	jmp	.ext
.tps:
	mov	rdx,r9
.tp:
	cmp	rsi,rdx
	jae	.out
	call	qv_read				; id
	jc	.out
	mov	r10,rax
	call	qv_read				; length
	jc	.out
	lea	r9,[rsi+rax]
	cmp	r9,rdx
	ja	.out
	cmp	r10,0x11
	je	.vi
	mov	rsi,r9
	jmp	.tp
.vi:
	add	rsi,4				; past the chosen version: those offered
.offered:
	lea	rax,[rsi+4]
	cmp	rax,r9
	ja	.out
	cmp	dword [rsi],0xCF43336B		; v2
	je	.v2
	add	rsi,4
	jmp	.offered
.v2:
	mov	dword [r15+QC_VER],QUIC_V2
	qc_key	QL_INIT, 0
	mov	rdi,rax
	qc_key	QL_INIT, 1
	mov	rsi,rax
	lea	rdx,[r15+QC_ODCID]
	mov	ecx,[r15+QC_ODCIDLEN]
	mov	r8d,QUIC_V2
	call	quic_initial
	jmp	qc_tp_build
.out:
	ret
.skip8:
	movzx	eax,byte [rsi]
	lea	rsi,[rsi+rax+1]
	cmp	rsi,rdx
	cmc
	ret
.skip16:
	movzx	eax,word [rsi]
	xchg	al,ah
	lea	rsi,[rsi+rax+2]
	cmp	rsi,rdx
	cmc
	ret

; rdi = one of our connection IDs (8 random bytes): its first ones name
; this instance (QUIC-LB plaintext: a first octet, the server ID; with
; quic_server_id) and this worker, for the load balancer and the kernel's
; steering. Keeps all but rax, rcx.
qc_cid_brand:
	mov	ecx,[g_plan_qlb_len]
	test	ecx,ecx
	jz	.worker
	lea	eax,[rcx+1]			; config rotation 0, the length
	mov	byte [rdi],7
	mov	al,[g_plan_qlb_sid]
	mov	[rdi+1],al
	cmp	ecx,2
	jb	@f
	mov	al,[g_plan_qlb_sid+1]
	mov	[rdi+2],al
@@:
	inc	ecx
	mov	eax,[g_worker_id]
	mov	[rdi+rcx],al
	ret
.worker:
	mov	eax,[g_worker_id]
	mov	[rdi],al
	ret

; r15 = connection, g_qd_sa/g_qd_salen = where a packet came from: ZF
; when that is the client's address
qc_peer_moved:
	mov	ecx,[g_qd_salen]
	cmp	ecx,[r15+QC_PEERLEN]
	jne	.out
	cmp	ecx,28
	jbe	@f
	mov	ecx,28
@@:
	mov	rsi,[g_qd_sa]
	lea	rdi,[r15+QC_PEER]
	repe	cmpsb
.out:
	ret

; r15 = connection, ebx = its session, edi = the datagram's length: the
; client is at g_qd_sa now (RFC 9000 9). Packets go there; until a
; PATH_CHALLENGE comes back, three times what came from it at most; a new
; IP address (not only a new port) starts congestion control and the RTT
; afresh.
qc_migrate:
	push	r12
	mov	r12d,edi
	mov	rsi,[g_qd_sa]
	xor	eax,eax				; IP changed?
	cmp	word [rsi],AF_INET6
	je	.v6
	mov	ecx,[rsi+4]
	cmp	ecx,[r15+QC_PEER+4]
	setne	al
	jmp	.copy
.v6:
	mov	rcx,[rsi+8]
	mov	rdx,[rsi+16]
	cmp	rcx,[r15+QC_PEER+8]
	setne	al
	cmp	rdx,[r15+QC_PEER+16]
	setne	cl
	or	al,cl
.copy:
	push	rax
	lea	rdi,[r15+QC_PEER]
	mov	ecx,28
	rep	movsb
	mov	eax,[g_qd_salen]
	mov	[r15+QC_PEERLEN],eax
	call	peer_ptr			; new streams see the new address
	mov	rdi,rax
	mov	rsi,[g_qd_sa]
	mov	ecx,28
	rep	movsb
	pop	rax
	test	eax,eax
	jz	@f
	mov	qword [r15+QC_CWND],QUIC_CWND0
	mov	rax,1 shl 62
	mov	[r15+QC_SSTH],rax
	mov	qword [r15+QC_SRTT],333000
	mov	qword [r15+QC_RTTVAR],166500
	call	qc_bbr_reset
	mov	dword [r15+QC_MTU],QUIC_MTU_MIN	; another path: its MTU is not known
	call	qc_mtu_next
	mov	rax,[g_qnow]
	mov	[r15+QC_RECOV],rax		; (what is lost on the old path is no event)
@@:
	mov	[r15+QC_RXB],r12
	mov	qword [r15+QC_TXB],0
	mov	dword [r15+QC_PATHNV],1
	rdtsc
	shl	rdx,32
	or	rax,rdx
	mov	rdx,0x9E3779B97F4A7C15
	imul	rax,rdx
	xor	rax,[r15+QC_SCID]
	mov	[r15+QC_PCHALO],rax
	or	dword [r15+QC_FL2],QF2_PCHAL
	pop	r12
	jmp	qc_dirty

; r15 = connection: QC_KU = the next generation of the client's 1-RTT
; keys (RFC 9001 6: secret' = HKDF-Expand-Label(secret, "quic ku"), the
; header protection key unchanged), QC_KUSEC its secret. Once a phase.
qc_ku_prepare:
	cmp	dword [r15+QC_KUREADY],0
	jne	.out
	lea	rdi,[r15+QC_KUSEC]
	lea	rdx,[r15+QC_QT+QT_CAP]
	call	qc_ku_secret
	lea	rdi,[r15+QC_KU]
	lea	rsi,[r15+QC_KUSEC]
	qc_key	QL_APP, 0
	mov	r8,rax
	call	qc_ku_keys
	mov	dword [r15+QC_KUREADY],1
.out:
	ret

; the next keys opened a packet: they are the client's now, and ours the
; next generation of the server's
qc_ku_commit:
	qc_key	QL_APP, 0
	mov	rdi,rax
	lea	rsi,[r15+QC_KU]
	mov	ecx,QK_SIZE
	rep	movsb
	lea	rsi,[r15+QC_KUSEC]
	lea	rdi,[r15+QC_QT+QT_CAP]
	mov	ecx,32
	rep	movsb
	lea	rdi,[r15+QC_QT+QT_SAP]
	mov	rdx,rdi
	call	qc_ku_secret
	lea	rdi,[r15+QC_KU]
	lea	rsi,[r15+QC_QT+QT_SAP]
	qc_key	QL_APP, 1
	mov	r8,rax
	call	qc_ku_keys
	qc_key	QL_APP, 1
	mov	rdi,rax
	lea	rsi,[r15+QC_KU]
	mov	ecx,QK_SIZE
	rep	movsb
	xor	dword [r15+QC_KPHASE],1
	mov	dword [r15+QC_KUREADY],0
	lea	rdi,[r15+QC_KUSEC]
	mov	ecx,32
	jmp	secure_zero

; rdi = out[32], rdx = a 1-RTT secret: the next one
qc_ku_secret:
	mov	esi,32
	lea	rcx,[lbl_quic_ku]
	cmp	dword [r15+QC_VER],QUIC_V2
	jne	@f
	lea	rcx,[lbl_quic2_ku]
@@:
	xor	r8d,r8d
	xor	r9d,r9d
	jmp	tls13_expand_label

; rdi = QK, rsi = secret, r8 = the QK whose header protection it keeps
qc_ku_keys:
	push	r8
	push	rdi
	mov	edx,[r15+QC_VER]
	mov	ecx,[r15+QC_QT+QT_AEAD]
	call	quic_keys
	pop	rdi
	pop	rsi
	add	rdi,QK_HPC
	add	rsi,QK_HPC
	mov	ecx,GCM_SIZE
	rep	movsb
	ret

; ebx = connection: on the flush list (sends at the iteration's end).
; Keeps every register but rax, rcx.
qc_dirty:
	push	r15
	push	r14
	qc_regs
	cmp	dword [r15+QC_DIRTY],0
	jne	.out
	mov	eax,[g_qdirty_n]
	cmp	eax,QDIRTY_MAX
	jae	.now
	mov	dword [r15+QC_DIRTY],1
	inc	dword [g_qdirty_n]
	mov	ecx,[r15+QC_GEN]
	shl	rcx,32
	or	rcx,rbx
	mov	[g_qdirty+rax*8],rcx
.out:
	pop	r14
	pop	r15
	ret
.now:
	pop	r14
	pop	r15
	jmp	qc_send

; ------------------------------------------------------------ packets

; edi = connection, esi = level, rdx = the packet, rcx = its length (to
; its end, for a short header the datagram's), r8d = its packet number's
; offset, r9d = the datagram's length (0 when already counted)
QP_LEVEL	:= 0
QP_PKT		:= 8
QP_PAY		:= 16
QP_END		:= 24
QP_PN		:= 32
QP_ACKEL	:= 40
QP_PNOFF	:= 44
QP_DROP		:= 48				; d: not taken (out of order): not acknowledged
QP_LARGEST	:= 56				; q: the largest received of its space
QP_HSAVE	:= 64				; the first byte and packet number as they came
QP_DGRAM	:= 72				; d: the datagram's length (counted once)
QP_HELLO0	:= 76				; d: the hello was answered before this packet
QP_EARLY	:= 80				; d: a 0-RTT packet
QP_NONPROBE	:= 84				; d: a frame other than a path probe's (RFC 9000 9.1)
QP_SIZE		:= 88
qc_packet:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,QP_SIZE
	mov	ebx,edi
	qc_regs
	mov	[rsp+QP_LEVEL],esi
	mov	dword [rsp+QP_EARLY],0
	mov	dword [rsp+QP_NONPROBE],0
	cmp	esi,QL_0RTT			; 0-RTT: 1-RTT's packet number space
	jne	@f
	mov	esi,QL_APP
	mov	[rsp+QP_LEVEL],esi
	mov	dword [rsp+QP_EARLY],1
@@:
	mov	[rsp+QP_PKT],rdx
	mov	[rsp+QP_PNOFF],r8d
	mov	dword [rsp+QP_ACKEL],0
	mov	dword [rsp+QP_DROP],0
	mov	[rsp+QP_DGRAM],r9d
	mov	eax,[r15+QC_FLAGS]
	and	eax,QF_HELLO or QF_DONE
	mov	[rsp+QP_HELLO0],eax
	add	[r15+QC_RXB],r9
	cmp	dword [r15+QC_STATE],QCS_CLOSING
	je	.out
	mov	r12d,esi
	cmp	r12d,QL_INIT
	jne	@f
	test	dword [r15+QC_FLAGS],QF_INIT_GONE
	jnz	.out
@@:
	cmp	dword [rsp+QP_EARLY],0
	je	.not_early
	test	dword [r15+QC_FLAGS],QF_EARLY	; 0-RTT: only when the hello took it,
	jz	.out				; until the handshake is done
	test	dword [r15+QC_FLAGS],QF_DONE
	jnz	.out
	jmp	@f
.not_early:
	cmp	r12d,QL_APP
	jne	@f
	test	dword [r15+QC_FLAGS],QF_DONE
	jz	.out				; before the client's Finished: dropped (it
						; comes again; its streams are not set up yet)
@@:
	cmp	r12d,QL_HS
	jne	@f
	test	dword [r15+QC_FLAGS],QF_HELLO
	jz	.out
@@:
	; open it
	mov	r13,rdx				; the packet
	mov	r14d,ecx			; its length
	imul	eax,r12d,PS_SIZE
	mov	r8,[r15+QC_PS+rax+PS_LARGEST]
	mov	[rsp+QP_LARGEST],r8
	mov	eax,[r13]			; the header as it came (a second try
	mov	[rsp+QP_HSAVE],eax		; with the next keys starts from it)
	mov	eax,[rsp+QP_PNOFF]
	mov	eax,[r13+rax]
	mov	[rsp+QP_HSAVE+4],eax
	lea	eax,[r12*2]
	imul	eax,eax,QK_SIZE
	lea	rdi,[r15+QC_KEYS+rax]
	cmp	dword [rsp+QP_EARLY],0
	je	@f
	lea	rdi,[r15+QC_K0]
@@:
	mov	rsi,r13
	mov	edx,r14d
	mov	ecx,[rsp+QP_PNOFF]
	call	quic_open
	cmp	eax,-1
	jne	.opened
	; 1-RTT with the other key phase: the client updated its keys
	cmp	r12d,QL_APP
	jne	.out				; not ours, or damaged: dropped
	cmp	dword [rsp+QP_EARLY],0
	jne	.out
	movzx	eax,byte [r13]			; (left unmasked)
	shr	eax,2
	and	eax,1
	cmp	eax,[r15+QC_KPHASE]
	je	.out
	call	qc_ku_prepare
	mov	eax,[rsp+QP_HSAVE]
	mov	[r13],al
	mov	ecx,[rsp+QP_PNOFF]
	mov	eax,[rsp+QP_HSAVE+4]
	mov	[r13+rcx],eax
	lea	rdi,[r15+QC_KU]
	mov	rsi,r13
	mov	edx,r14d
	mov	r8,[rsp+QP_LARGEST]
	call	quic_open
	cmp	eax,-1
	je	.out
	push	rax
	push	rdx
	call	qc_ku_commit			; it is: ours follow
	pop	rdx
	pop	rax
.opened:
	mov	[rsp+QP_PN],rdx
	movzx	ecx,byte [r13]
	and	ecx,3
	inc	ecx				; packet number length
	add	ecx,[rsp+QP_PNOFF]
	lea	rsi,[r13+rcx]			; the payload
	mov	[rsp+QP_PAY],rsi
	lea	rdx,[rsi+rax]
	mov	[rsp+QP_END],rdx
	mov	edi,[rsp+QP_LEVEL]
	mov	rsi,[rsp+QP_PN]
	call	qc_seen
	jc	.out				; a duplicate: once is enough
	mov	eax,[g_qd_ecn]			; its ECN mark, counted in its space
	test	eax,eax
	jz	@f
	movzx	ecx,byte [.ecn_slot+rax]
	imul	edx,[rsp+QP_LEVEL],24
	add	edx,ecx
	inc	qword [r15+QC_ECN+rdx]
@@:

	mov	edi,ebx
	call	idle_touch
	; a Handshake packet: the client's address is good, Initial is over
	cmp	dword [rsp+QP_LEVEL],QL_HS
	jne	.frames_begin
	test	dword [r15+QC_FLAGS],QF_INIT_GONE
	jnz	.frames_begin
	test	dword [r15+QC_FLAGS],QF_VALID
	jnz	@f
	dec	dword [g_qc_unval]
@@:
	or	dword [r15+QC_FLAGS],QF_VALID or QF_INIT_GONE
	; the client names us by our own ID from now on: its first one out
	lea	rdi,[r15+QC_ODCID]
	mov	esi,[r15+QC_ODCIDLEN]
	call	qh_del
.frames_begin:
	; frames
	mov	rsi,[rsp+QP_PAY]
.frame:
	mov	rdx,[rsp+QP_END]
	cmp	rsi,rdx
	jae	.frames_done
	call	qv_read
	jc	.encoding
	test	rax,rax				; anything but a probe's frames: the
	jz	@f				; packet may move the connection
	cmp	rax,0x1A
	je	@f
	cmp	rax,0x1B
	je	@f
	cmp	rax,0x18
	je	@f
	mov	dword [rsp+QP_NONPROBE],1
@@:
	test	rax,rax
	jz	.padding
	cmp	rax,1
	je	.ping
	cmp	rax,2
	je	.ack
	cmp	rax,3
	je	.ack
	cmp	rax,6
	je	.crypto
	cmp	rax,0x1C
	je	.close
	cmp	rax,0x1D
	je	.close
	cmp	dword [rsp+QP_LEVEL],QL_APP
	jne	.violation			; anything else needs 1-RTT
	mov	rdi,rsp				; the application's frames
	call	qc_app_frame			; rsi past it, CF: an error (QC_ERR set)
	jc	.error
	jmp	.frame
.padding:
	cmp	rsi,rdx
	jae	.frames_done
	cmp	byte [rsi],0
	jne	.frame
	inc	rsi
	jmp	.padding
.ping:
	mov	dword [rsp+QP_ACKEL],1
	jmp	.frame
.ack:
	push	rax
	mov	edi,[rsp+8+QP_LEVEL]
	pop	rcx
	call	qc_on_ack			; rsi past the frame, CF on a bad one
	jnc	.frame
	cmp	qword [r15+QC_ERR],0		; (its own error, else the encoding's)
	jne	.error
	jmp	.encoding
.crypto:
	mov	dword [rsp+QP_ACKEL],1
	call	qv_read				; offset
	jc	.encoding
	mov	r8,rax
	call	qv_read				; length
	jc	.encoding
	lea	rcx,[rsi+rax]
	cmp	rcx,rdx
	ja	.encoding
	push	rcx
	mov	edi,[rsp+8+QP_LEVEL]
	mov	rdx,rax				; length
	mov	rcx,r8				; offset
	call	qc_crypto_in			; CF: the connection fails (QC_ERR set)
	pop	rsi
	jc	.error
	qc_regs
	jmp	.frame
.close:
	; the peer closes: we go, silently (draining)
	mov	dword [r15+QC_STATE],QCS_CLOSING
	mov	rax,[g_qnow]
	add	rax,[r15+QC_SRTT]
	add	rax,[r15+QC_SRTT]
	add	rax,[r15+QC_SRTT]
	mov	[r15+QC_CLOSE_AT],rax
	and	dword [r15+QC_FLAGS],not QF_CLOSE
	jmp	.out
.encoding:
	mov	qword [r15+QC_ERR],7		; FRAME_ENCODING_ERROR
	jmp	.error
.violation:
	mov	qword [r15+QC_ERR],0x0A		; PROTOCOL_VIOLATION
.error:
	call	qc_fail
	jmp	.out
.frames_done:
	cmp	dword [rsp+QP_DROP],0
	jne	.out				; it comes again (stream data out of order)
	; recorded as received; acknowledged when it asks for it
	mov	edi,[rsp+QP_LEVEL]
	mov	rsi,[rsp+QP_PN]
	call	qc_received
	; 1-RTT, the newest yet and not only probing, from another address or
	; to another of our sockets (NAT rebinding, our preferred address): the
	; connection moves there, the path validated (RFC 9000 9)
	cmp	dword [rsp+QP_LEVEL],QL_APP
	jne	.stays
	cmp	dword [rsp+QP_EARLY],0
	jne	.stays
	cmp	dword [rsp+QP_NONPROBE],0
	je	.stays
	mov	rax,[rsp+QP_PN]
	cmp	rax,[rsp+QP_LARGEST]
	jle	.stays
	mov	eax,[g_qd_slot]
	cmp	eax,[r15+QC_SOCK]
	jne	.moved
	call	qc_peer_moved			; ZF: same address
	jz	.stays
.moved:
	mov	eax,[g_qd_slot]
	mov	[r15+QC_SOCK],eax
	mov	edi,[rsp+QP_DGRAM]
	call	qc_migrate			; (a probe's answer pending stays on
.stays:						; its own path: QC_ALT_*)
	cmp	dword [rsp+QP_ACKEL],0
	je	.out
	; the client's Initial or Handshake again (its hello retransmitted, a
	; probe) while the handshake is not done: our flight did not reach it,
	; it goes again now rather than at our probe timer (backed off, no RTT
	; known yet)
	cmp	dword [rsp+QP_LEVEL],QL_APP	; (Initial or Handshake: a probe at
	je	@f				; either level says the same)
	cmp	dword [rsp+QP_HELLO0],QF_HELLO
	jne	@f
	test	dword [r15+QC_FLAGS],QF_DONE	; (its Finished came with it: not lost)
	jnz	@f
	call	qc_flight_again
@@:
	imul	eax,[rsp+QP_LEVEL],PS_SIZE
	inc	dword [r15+QC_PS+rax+PS_ACKQ]
	call	qc_dirty
.out:
	add	rsp,QP_SIZE
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret
.ecn_slot	db 0, 8, 0, 16			; (ECT(1), ECT(0), CE: their counters)

; ------------------------------------------------ received, acknowledged

; edi = level, rsi = packet number (r15 = connection): CF when it came already
qc_seen:
	imul	eax,edi,PS_SIZE
	lea	rdx,[r15+QC_PS+rax]
	mov	ecx,[rdx+PS_NR]
	lea	r8,[rdx+PS_R]
.range:
	test	ecx,ecx
	jz	.new
	cmp	rsi,[r8]
	ja	.next
	cmp	rsi,[r8+8]
	jae	.dup
.next:
	add	r8,16
	dec	ecx
	jmp	.range
.new:
	clc
	ret
.dup:
	stc
	ret

; edi = level, rsi = packet number: into its space's ranges (highest
; first, merged; the lowest dropped past PS_RMAX)
qc_received:
	imul	eax,edi,PS_SIZE
	lea	rdx,[r15+QC_PS+rax]
	cmp	rsi,[rdx+PS_LARGEST]
	jle	@f
	cmp	qword [rdx+PS_LARGEST],-1
	je	.larger
	cmp	rsi,[rdx+PS_LARGEST]
	jbe	@f
.larger:
	mov	[rdx+PS_LARGEST],rsi
	mov	rax,[g_qnow]
	mov	[rdx+PS_LTIME],rax
@@:
	mov	ecx,[rdx+PS_NR]
	lea	r8,[rdx+PS_R]
	xor	r9d,r9d				; index
.find:
	cmp	r9d,ecx
	jae	.append
	mov	rax,[r8]			; hi
	lea	r10,[rax+1]
	cmp	rsi,r10
	je	.extend_hi			; just above it
	ja	.insert				; above it, with a gap: a new range before
	mov	r10,[r8+8]			; lo
	dec	r10
	cmp	rsi,r10
	je	.extend_lo
	add	r8,16
	inc	r9d
	jmp	.find
.extend_hi:
	mov	[r8],rsi
	ret
.extend_lo:
	mov	[r8+8],rsi
	; does it touch the next one (lower)?
	inc	r9d
	cmp	r9d,ecx
	jae	.done
	mov	rax,[r8+16]
	inc	rax
	cmp	rax,rsi
	jne	.done
	mov	rax,[r8+24]			; merge: lo of the next
	mov	[r8+8],rax
	; remove the next: shift the rest down
	lea	rdi,[r8+16]
	lea	rsi,[r8+32]
	mov	eax,ecx
	sub	eax,r9d
	dec	eax
	shl	eax,4
	mov	ecx,eax
	rep	movsb
	dec	dword [rdx+PS_NR]
.done:
	ret
.insert:
	cmp	ecx,PS_RMAX
	jb	@f
	dec	ecx				; full: the lowest goes
	mov	[rdx+PS_NR],ecx
	cmp	r9d,ecx
	ja	.done
@@:
	; shift [r9, n) up one, then this one at r9
	push	rsi
	mov	eax,ecx
	sub	eax,r9d
	shl	eax,4
	lea	rsi,[r8+rax-1]
	lea	rdi,[r8+rax+15]
	mov	ecx,eax
	std
	rep	movsb
	cld
	pop	rsi
	mov	[r8],rsi
	mov	[r8+8],rsi
	inc	dword [rdx+PS_NR]
	ret
.append:
	cmp	ecx,PS_RMAX
	jae	.done				; lower than all we keep
	mov	[r8],rsi
	mov	[r8+8],rsi
	inc	dword [rdx+PS_NR]
	ret

; An ACK frame (rcx = 2 or 3): edi = level, rsi past its type, rdx = the
; payload's end (r15 = connection). Every packet of ours it covers is
; acknowledged; an RTT sample from the largest. rsi past the frame, CF
; when it does not parse.
QA_LEVEL	:= 0
QA_TYPE		:= 4
QA_LARGEST	:= 8
QA_HI		:= 16
QA_SPACE	:= 24
QA_NEWLY	:= 32
QA_SIZE		:= 48
qc_on_ack:
	push	rbx
	push	r12
	push	r13
	sub	rsp,QA_SIZE
	mov	[rsp+QA_LEVEL],edi
	mov	[rsp+QA_TYPE],ecx
	mov	dword [rsp+QA_NEWLY],0
	call	qv_read				; largest acknowledged
	jc	.bad
	imul	ecx,[rsp+QA_LEVEL],PS_SIZE	; a packet we never sent: PROTOCOL_VIOLATION
	cmp	rax,[r15+QC_PS+rcx+PS_NEXT]	; (RFC 9000 13.1: an optimistic ACK)
	jae	.unsent
	mov	[rsp+QA_LARGEST],rax
	mov	r12,rax				; the range's top
	call	qv_read				; ack delay
	jc	.bad
	call	qv_read				; range count
	jc	.bad
	mov	r13,rax
	call	qv_read				; first range
	jc	.bad
	cmp	rax,r12
	ja	.bad
	mov	rbx,r12
	sub	rbx,rax				; its bottom
	call	.mark				; [rbx, r12]
.ranges:
	test	r13,r13
	jz	.ecn
	dec	r13
	call	qv_read				; gap
	jc	.bad
	lea	rcx,[rax+2]
	cmp	rcx,rbx
	ja	.bad
	mov	r12,rbx
	sub	r12,rcx				; the next top
	call	qv_read				; its length
	jc	.bad
	cmp	rax,r12
	ja	.bad
	mov	rbx,r12
	sub	rbx,rax
	call	.mark
	jmp	.ranges
.ecn:
	cmp	dword [rsp+QA_TYPE],3
	je	.ecn_counts
	; data acknowledged and no counts: the client or the path does not report
	; ECN, no more marks on this connection (RFC 9000 13.4.2)
	cmp	dword [rsp+QA_LEVEL],QL_APP
	jne	.done
	cmp	dword [rsp+QA_NEWLY],0
	je	.done
	mov	dword [r15+QC_ECNOFF],1
	jmp	.done
.ecn_counts:
	call	qv_read
	jc	.bad
	call	qv_read
	jc	.bad
	call	qv_read				; CE
	jc	.bad
	cmp	dword [rsp+QA_LEVEL],QL_APP
	jne	.done
	cmp	rax,[r15+QC_ECN_CE]
	jbe	.done
	; marked on the way: congestion, as a loss, once a round trip
	mov	[r15+QC_ECN_CE],rax
	mov	rax,[g_qnow]
	mov	rcx,rax
	sub	rcx,[r15+QC_RECOV]
	cmp	rcx,[r15+QC_SRTT]
	jb	.done
	mov	[r15+QC_RECOV],rax
	push	rdx
	call	qc_cc_loss
	pop	rdx
.done:
	; anything newly acknowledged: what was sent well before the largest
	; acknowledged is lost; the probe count starts over, the timer follows
	; what is still out
	cmp	dword [rsp+QA_NEWLY],0
	je	.ok
	push	rsi
	push	rdx
	mov	edi,[rsp+16+QA_LEVEL]
	mov	rsi,[rsp+16+QA_LARGEST]
	call	qc_detect_lost
	pop	rdx
	pop	rsi
	mov	dword [r15+QC_PTOCNT],0
	push	rsi
	push	rdx
	call	qc_pto_arm
	push	rbx				; room in the window, the rings: what
	mov	rbx,[rsp+24+QA_SIZE+16]		; waited may go now (the session again)
	call	qc_dirty
	pop	rbx
	pop	rdx
	pop	rsi
.ok:
	clc
	jmp	.out
.unsent:
	mov	qword [r15+QC_ERR],0x0A
.bad:
	stc
.out:
	lea	rsp,[rsp+QA_SIZE]
	pop	r13
	pop	r12
	pop	rbx
	ret
; [rbx, r12] acknowledged: the packets of ours in that window
.mark:
	push	rsi
	push	rdx
	imul	eax,[rsp+16+8+QA_LEVEL],PS_SIZE
	mov	r8,[r15+QC_PS+rax+PS_NEXT]
	cmp	r12,r8
	jae	.mark_out			; (the top one was checked: not above it)
	sub	r8,SP_N				; only the ring's window: a frame of stale
	jnc	@f				; ranges costs its parsing, no more
	xor	r8d,r8d
@@:
	cmp	r12,r8
	jb	.mark_out
	mov	r10,rbx				; (rbx stays: the next range counts from it)
	cmp	r10,r8
	jae	@f
	mov	r10,r8
@@:
	mov	r9d,[rsp+16+8+QA_LEVEL]
	imul	r9d,r9d,SP_N * SP_SIZE
	lea	r9,[r15+QC_SP+r9]		; (lowest first: stream bytes arrive in order)
.mark_one:
	cmp	r10,r12
	jg	.mark_out
	mov	eax,r10d
	and	eax,SP_N - 1
	shl	eax,6				; SP_SIZE
	lea	r11,[r9+rax]
	cmp	[r11+SP_PN],r10
	jne	.mark_next
	mov	eax,[r11+SP_FL]
	test	eax,SPF_SENT
	jz	.mark_next
	test	eax,SPF_ACKED
	jnz	.mark_next
	or	dword [r11+SP_FL],SPF_ACKED
	mov	dword [rsp+16+8+QA_NEWLY],1
	test	eax,SPF_MTU			; a size the path takes: that, and the next
	jz	@f
	mov	edx,[r15+QC_MTU_TRY]
	test	edx,edx
	jz	@f
	mov	[r15+QC_MTU],edx
	push	rax
	call	qc_mtu_next
	pop	rax
@@:
	test	eax,SPF_ACKEL
	jz	@f
	push	rax				; (the flags: the RTT sample below)
	call	qc_cc_acked			; r11 = the record
	pop	rax
@@:
	cmp	dword [rsp+16+8+QA_LEVEL],QL_APP
	jne	@f
	push	rax
	push	r9
	push	r10
	push	r11
	mov	rdi,r11
	call	qc_app_acked			; http3.inc: its stream data, delivered
	pop	r11
	pop	r10
	pop	r9
	pop	rax
@@:
	; an RTT sample from the largest acknowledged, when it asked for one
	cmp	r10,[rsp+16+8+QA_LARGEST]
	jne	.mark_next
	test	eax,SPF_ACKEL
	jz	.mark_next
	mov	rax,[g_qnow]
	sub	rax,[r11+SP_TIME]
	call	qc_rtt_sample
.mark_next:
	inc	r10
	jmp	.mark_one
.mark_out:
	pop	rdx
	pop	rsi
	ret

; rax = an RTT sample (µs): smoothed RTT and its variation (RFC 9002 5.3)
qc_rtt_sample:
	test	rax,rax
	jg	@f
	mov	eax,1
@@:
	mov	[r15+QC_LATEST],rax
	mov	rcx,[r15+QC_SRTT]
	cmp	rcx,333000
	jne	.update
	cmp	qword [r15+QC_RTTVAR],166500
	jne	.update
	mov	[r15+QC_SRTT],rax		; the first sample
	shr	rax,1
	mov	[r15+QC_RTTVAR],rax
	ret
.update:
	mov	rdx,rcx
	sub	rdx,rax
	jns	@f
	neg	rdx
@@:
	; rttvar = 3/4 rttvar + 1/4 |srtt - sample|; srtt = 7/8 srtt + 1/8 sample
	mov	r8,[r15+QC_RTTVAR]
	lea	r8,[r8*3]
	add	r8,rdx
	shr	r8,2
	mov	[r15+QC_RTTVAR],r8
	lea	r8,[rcx*8]
	sub	r8,rcx
	add	r8,rax
	shr	r8,3
	mov	[r15+QC_SRTT],r8
	ret

; r15 = connection: the probe timer for what is still out, ack-eliciting
; and not acknowledged (crypto at Initial/Handshake, anything at 1-RTT);
; off when nothing is
qc_pto_arm:
	mov	qword [r15+QC_PTO_AT],0
	xor	ecx,ecx				; level
.level:
	cmp	ecx,3
	jae	.none
	mov	eax,ecx
	imul	eax,eax,SP_N * SP_SIZE
	lea	r8,[r15+QC_SP+rax]
	mov	edx,SP_N
.slot:
	mov	eax,[r8+SP_FL]
	and	eax,SPF_SENT or SPF_ACKEL or SPF_ACKED
	cmp	eax,SPF_SENT or SPF_ACKEL
	je	.out_there
	add	r8,SP_SIZE
	dec	edx
	jnz	.slot
	inc	ecx
	jmp	.level
.out_there:
	call	qc_pto_period
	add	rax,[g_qnow]
	mov	[r15+QC_PTO_AT],rax
.none:
	ret

; rax = the probe timeout (µs): srtt + max(4 rttvar, 1 ms) + 25 ms,
; doubled for every probe in a row
qc_pto_period:
	mov	rax,[r15+QC_RTTVAR]
	shl	rax,2
	cmp	rax,1000
	jae	@f
	mov	eax,1000
@@:
	add	rax,[r15+QC_SRTT]
	add	rax,25000
	mov	ecx,[r15+QC_PTOCNT]
	cmp	ecx,8
	jbe	@f
	mov	ecx,8
@@:
	shl	rax,cl
	ret

; ------------------------------------------------------------ crypto

; edi = level, rsi = the bytes, rdx = their length, rcx = their offset
; (r15 = connection, ebx = session). Reassembled; complete messages go
; to the handshake. CF when the connection fails (QC_ERR set).
qc_crypto_in:
	push	rbx
	push	r12
	push	r13
	push	r14
	sub	rsp,8				; (16-aligned at the calls)
	mov	r12d,edi
	cmp	r12d,QL_APP
	je	.ok				; (post-handshake messages: none expected)
	lea	r13,[r15+QC_CRX]
	lea	r14,[r15+QC_CRBM]
	mov	eax,CH_MAX
	cmp	r12d,QL_HS
	jne	@f
	lea	r13,[r15+QC_CRX_HS]
	lea	r14,[r15+QC_CRBM_HS]
	mov	eax,QC_CRX_HSCAP
@@:
	lea	r8,[rcx+rdx]
	cmp	r8,rax
	ja	.exceeded
	; the bytes, and their marks
	lea	rdi,[r13+rcx]
	push	rcx
	mov	rcx,rdx
	rep	movsb
	pop	rcx
	mov	r9,rcx
.mark:
	cmp	r9,r8
	jae	.advance
	mov	rax,r9
	shr	rax,3
	mov	r10d,r9d
	and	r10d,7
	bts	dword [r14+rax],r10d
	inc	r9
	jmp	.mark
.advance:
	mov	r9d,[r15+QC_CR_END+r12*4]
	mov	r10d,r9d
.adv:
	mov	eax,r9d
	shr	eax,3
	mov	ecx,r9d
	and	ecx,7
	movzx	eax,byte [r14+rax]
	bt	eax,ecx
	jnc	@f
	inc	r9d
	jmp	.adv
@@:
	mov	[r15+QC_CR_END+r12*4],r9d
	cmp	r9d,r10d
	je	.ok				; nothing new in order
	cmp	r12d,QL_INIT
	jne	.handshake
	test	dword [r15+QC_FLAGS],QF_HELLO
	jnz	.ok				; (a retransmission)
	; the ClientHello, whole or not yet
	mov	eax,[r15+QC_SOCK]
	mov	eax,[g_qs_lst+rax*4]
	imul	rax,rax,LS_SIZE
	mov	eax,[g_listeners+rax+LS_TLS]
	test	eax,eax
	jz	.internal
	dec	eax
	imul	rax,rax,TL_SIZE
	lea	rsi,[g_tls+rax]
	lea	rdi,[r15+QC_TS]
	mov	rdx,r13
	mov	ecx,r9d
	push	rsi
	push	rdi
	push	rdx
	push	rcx
	call	qc_compat_vn			; v1 offering v2: v2 from here (RFC 9368)
	pop	rcx
	pop	rdx
	pop	rdi
	pop	rsi
	lea	r8,[r15+QC_TLSOUT]
	mov	r9d,QC_TLSROOM
	call	tls_hello
	cmp	eax,TH_MORE
	je	.ok
	cmp	eax,TH_SEND
	jne	.tls_failed
	; the flight: ServerHello for Initial, the rest for Handshake; the
	; keys of both levels from the secrets
	mov	ecx,[r15+QC_QT+QT_SHLEN]
	mov	[r15+QC_CS_LEN+0],ecx
	sub	edx,ecx
	mov	[r15+QC_CS_LEN+4],edx
	or	dword [r15+QC_FLAGS],QF_HELLO
	cmp	dword [r15+QC_QT+QT_EARLY],0	; 0-RTT taken: its keys, and the streams
	je	@f				; (and the client's parameters) now
	lea	rdi,[r15+QC_K0]
	lea	rsi,[r15+QC_QT+QT_CET]
	mov	edx,[r15+QC_VER]
	mov	ecx,[r15+QC_QT+QT_AEAD]
	call	quic_keys
	or	dword [r15+QC_FLAGS],QF_EARLY
	push	rdx
	call	qc_established
	pop	rdx
@@:
	qc_key	QL_HS, 0
	mov	rdi,rax
	lea	rsi,[r15+QC_QT+QT_CHS]
	mov	edx,[r15+QC_VER]
	mov	ecx,[r15+QC_QT+QT_AEAD]
	call	quic_keys
	qc_key	QL_HS, 1
	mov	rdi,rax
	lea	rsi,[r15+QC_QT+QT_SHS]
	mov	edx,[r15+QC_VER]
	mov	ecx,[r15+QC_QT+QT_AEAD]
	call	quic_keys
	qc_key	QL_APP, 0
	mov	rdi,rax
	lea	rsi,[r15+QC_QT+QT_CAP]
	mov	edx,[r15+QC_VER]
	mov	ecx,[r15+QC_QT+QT_AEAD]
	call	quic_keys
	qc_key	QL_APP, 1
	mov	rdi,rax
	lea	rsi,[r15+QC_QT+QT_SAP]
	mov	edx,[r15+QC_VER]
	mov	ecx,[r15+QC_QT+QT_AEAD]
	call	quic_keys
	; the handshake secrets are done with (the handshake's own are in its
	; TS); the application ones stay for key updates
	lea	rdi,[r15+QC_QT]
	mov	ecx,64
	call	secure_zero
	jmp	.ok
.handshake:
	test	dword [r15+QC_FLAGS],QF_DONE
	jnz	.ok
	test	dword [r15+QC_FLAGS],QF_HELLO
	jz	.ok
	lea	rdi,[r15+QC_TS]
	mov	rsi,r13
	mov	ecx,r9d
	call	quic_tls_finished
	cmp	eax,TH_MORE
	je	.ok
	cmp	eax,TH_DONE
	jne	.bad_finished
	; complete: HANDSHAKE_DONE goes, the handshake data needs no more sending;
	; a session ticket goes at 1-RTT (it sits after the flight in TLSOUT)
	mov	eax,[r15+QC_QT+QT_NSTLEN]
	mov	[r15+QC_CS_LEN+8],eax
	or	dword [r15+QC_FLAGS],QF_DONE or QF_HDONE
	mov	dword [r15+QC_STATE],QCS_EST
	mov	eax,[r15+QC_CS_LEN+4]
	mov	[r15+QC_CS_SENT+4],eax
	mov	dword [r15+QC_ACKED_ALL+4],1
	mov	eax,[r15+QC_CS_LEN+0]
	mov	[r15+QC_CS_SENT+0],eax
	test	dword [r15+QC_FLAGS],QF_EARLY
	jz	@f
	call	qc_dirty			; (set up at the hello already: what
	jmp	.ok				; waited for the handshake goes now)
@@:
	call	qc_established			; http3.inc: the control streams
.ok:
	clc
	jmp	.out
.exceeded:
	mov	qword [r15+QC_ERR],0x0D		; CRYPTO_BUFFER_EXCEEDED
	jmp	.fail
.bad_finished:
	mov	qword [r15+QC_ERR],0x100 + 51	; crypto error: decrypt_error
	jmp	.fail
.tls_failed:
	movzx	eax,byte [r15+QC_TLSOUT+6]	; the alert it would have sent
	add	eax,0x100
	mov	[r15+QC_ERR],rax
	jmp	.fail
.internal:
	mov	qword [r15+QC_ERR],1		; INTERNAL_ERROR
.fail:
	stc
.out:
	lea	rsp,[rsp+8]
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; r15 = connection, ebx = session: it fails with QC_ERR: CONNECTION_CLOSE
; goes (at the highest level we can), then it closes
qc_fail:
	cmp	dword [r15+QC_STATE],QCS_CLOSING
	je	.out
	mov	dword [r15+QC_STATE],QCS_CLOSING
	or	dword [r15+QC_FLAGS],QF_CLOSE
	call	qc_pto_period
	lea	rax,[rax*2+rax]
	add	rax,[g_qnow]
	mov	[r15+QC_CLOSE_AT],rax
	jmp	qc_dirty
.out:
	ret

; ------------------------------------------------------------- sending

; ebx = connection: every packet it has to send, a level at a time
qc_send:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	qc_regs
	xor	r12d,r12d
.level:
	cmp	r12d,3
	jae	.done
	mov	r13d,32				; at most this many packets a level a call
.more:
	mov	ecx,r12d
	call	qc_build
	test	eax,eax
	jz	.next
	dec	r13d
	jnz	.more
	call	qc_dirty			; more to send: again on the next flush
.next:
	inc	r12d
	jmp	.level
.done:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; ecx = level (ebx, r15 = connection): one packet of what it has at that
; level, into the send batch. eax = 1 when one went, 0 when nothing did.
QB_LEVEL	:= 0
QB_BUF		:= 8
QB_PN		:= 16
QB_HDR		:= 24
QB_LENAT	:= 28				; where the long header's length goes, 0 short
QB_ACKEL	:= 32
QB_MAX		:= 36				; the datagram's room
QB_CRYPTO	:= 40				; d, d: crypto offset and length in it
QB_HDONE	:= 48
QB_FLAGS	:= 52
QB_SIZE		:= 72
qc_build:
	push	rbx
	push	r12
	push	r13
	push	r14
	sub	rsp,QB_SIZE
	mov	[rsp+QB_LEVEL],ecx
	mov	r12d,ecx
	xor	eax,eax
	mov	[rsp+QB_ACKEL],eax
	mov	[rsp+QB_CRYPTO],eax
	mov	[rsp+QB_CRYPTO+4],eax
	mov	[rsp+QB_HDONE],eax
	; keys for it?
	cmp	r12d,QL_INIT
	jne	@f
	test	dword [r15+QC_FLAGS],QF_INIT_GONE
	jnz	.nothing
	jmp	.keys_ok
@@:
	test	dword [r15+QC_FLAGS],QF_HELLO
	jz	.nothing
.keys_ok:
	; anything to say?
	mov	r13d,0
	imul	eax,r12d,PS_SIZE
	cmp	dword [r15+QC_PS+rax+PS_ACKQ],0
	je	@f
	or	r13d,1				; an ACK
@@:
	cmp	r12d,QL_APP
	je	.app_wants
	mov	eax,[r15+QC_CS_SENT+r12*4]
	cmp	eax,[r15+QC_CS_LEN+r12*4]
	jae	@f
	or	r13d,2				; crypto data
@@:
	jmp	.probe_wants
.app_wants:
	test	dword [r15+QC_FLAGS],QF_HDONE
	jz	@f
	or	r13d,4
@@:
	mov	eax,[r15+QC_CS_SENT+8]		; the session ticket
	cmp	eax,[r15+QC_CS_LEN+8]
	jae	@f
	or	r13d,2
@@:
	call	qc_app_pending			; http3.inc: stream data, flow control
	test	eax,eax
	jz	@f
	or	r13d,16
@@:
	test	dword [r15+QC_FL2],QF2_PCHAL	; a new path's PATH_CHALLENGE: in the
	jz	.probe_wants			; first packet there, past the window
	or	r13d,64
.probe_wants:
	; an answer to a probe on another path: a datagram of its own, there
	cmp	r12d,QL_APP
	jne	@f
	test	dword [r15+QC_FL2],QF2_PALT
	jz	@f
	mov	r13d,256
	jmp	.cc_done
@@:
	; a path MTU probe due: a packet of its own, past the window
	cmp	r12d,QL_APP
	jne	.mtu_wants_done
	cmp	dword [r15+QC_MTU_TRY],0
	je	.mtu_wants_done
	test	dword [r15+QC_FLAGS],QF_DONE
	jz	.mtu_wants_done
	cmp	dword [r15+QC_PATHNV],0
	jne	.mtu_wants_done
	mov	rax,[g_qnow]
	cmp	rax,[r15+QC_MTU_AT]
	jb	.mtu_wants_done
	cmp	dword [r15+QC_MTU_N],3
	jb	@f
	mov	dword [r15+QC_MTU_TRY],0	; not taken: this size is too much
	jmp	.mtu_wants_done
@@:
	or	r13d,128
.mtu_wants_done:
	cmp	dword [r15+QC_PROBE+r12*4],0
	je	@f
	or	r13d,8
@@:
	test	dword [r15+QC_FLAGS],QF_CLOSE
	jz	@f
	call	qc_close_level			; eax = the level CONNECTION_CLOSE goes at
	cmp	eax,r12d
	jne	@f
	mov	r13d,32				; closing: that is all it says
@@:
	; congestion: past the window only ACKs, probes and closing go; nor
	; while the record the packet would take still holds one in flight
	test	r13d,2 or 4 or 16
	jz	.cc_done
	mov	rax,[r15+QC_INFL]
	add	rax,QUIC_DGRAM
	cmp	rax,[r15+QC_CWND]
	ja	.cc_block
	call	qc_sp_next			; rdx = the record the next packet takes
	mov	eax,[rdx+SP_FL]
	and	eax,SPF_SENT or SPF_ACKEL or SPF_ACKED
	cmp	eax,SPF_SENT or SPF_ACKEL
	je	.cc_block
	call	qc_pace				; CF: not yet (QC_PACE_AT set)
	jnc	.cc_done
	and	r13d,not (2 or 4 or 16)
	jmp	.cc_done
.cc_block:
	and	r13d,not (2 or 4 or 16)
	cmp	qword [r15+QC_PTO_AT],0		; something must end the wait: the probe
	jne	.cc_done			; timer (what is out gets lost or acknowledged)
	call	qc_pto_arm
.cc_done:
	test	r13d,r13d
	jz	.nothing
	mov	[rsp+QB_FLAGS],r13d
	; room: a datagram, and before validation (of the address, of a new
	; path) three times what came
	mov	eax,[r15+QC_MTU]
	test	r13d,256
	jz	.not_alt
	mov	eax,QUIC_MTU_MIN		; (the answer padded to 1200, RFC 9000 8.2.2,
	cmp	eax,[r15+QC_ALT_MAX]		; as far as that path may be sent)
	jbe	.room_set
	mov	eax,[r15+QC_ALT_MAX]
	cmp	eax,64
	jae	.room_set
	and	dword [r15+QC_FL2],not QF2_PALT	; (no room: the client probes again)
	jmp	.nothing
.not_alt:
	test	r13d,128
	jz	@f
	and	r13d,1 or 128			; (the probe: an ACK with it, nothing else)
	mov	[rsp+QB_FLAGS],r13d
	mov	eax,[r15+QC_MTU_TRY]
@@:
.room_set:
	test	dword [r15+QC_FLAGS],QF_VALID
	jz	.limited
	cmp	dword [r15+QC_PATHNV],0
	je	@f
.limited:
	mov	rcx,[r15+QC_RXB]
	lea	rcx,[rcx*2+rcx]
	sub	rcx,[r15+QC_TXB]
	jle	.nothing
	cmp	rcx,rax
	jae	@f
	mov	eax,ecx
	cmp	eax,64
	jb	.nothing
@@:
	mov	[rsp+QB_MAX],eax
	call	qtx_slot
	test	rax,rax
	jz	.nothing
	mov	[rsp+QB_BUF],rax
	mov	rdi,rax
	; the header
	imul	eax,r12d,PS_SIZE
	mov	rcx,[r15+QC_PS+rax+PS_NEXT]
	mov	[rsp+QB_PN],rcx
	inc	qword [r15+QC_PS+rax+PS_NEXT]
	cmp	r12d,QL_APP
	je	.short
	; long: the type bits of the version (v1: Initial 0, Handshake 2; v2: 1, 3)
	mov	eax,r12d
	add	eax,eax				; 0 or 2
	cmp	dword [r15+QC_VER],QUIC_V2
	jne	@f
	inc	eax
@@:
	shl	eax,4
	or	eax,0xC3			; long, fixed bit, a 4-byte packet number
	mov	[rdi],al
	mov	eax,[r15+QC_VER]
	bswap	eax
	mov	[rdi+1],eax
	add	rdi,5
	mov	ecx,[r15+QC_DCIDLEN]
	mov	[rdi],cl
	inc	rdi
	lea	rsi,[r15+QC_DCID]
	rep	movsb
	mov	byte [rdi],8
	mov	rax,[r15+QC_SCID]
	mov	[rdi+1],rax
	add	rdi,9
	cmp	r12d,QL_INIT
	jne	@f
	mov	byte [rdi],0			; no token
	inc	rdi
@@:
	mov	rax,rdi
	sub	rax,[rsp+QB_BUF]
	mov	[rsp+QB_LENAT],eax
	add	rdi,2				; the length: two bytes, after
	jmp	.pn
.short:
	mov	al,[r15+QC_KPHASE]		; fixed bit, the key phase, a 4-byte number
	shl	al,2
	or	al,0x43
	mov	[rdi],al
	inc	rdi
	mov	ecx,[r15+QC_DCIDLEN]
	lea	rsi,[r15+QC_DCID]
	rep	movsb
	mov	dword [rsp+QB_LENAT],0
.pn:
	mov	eax,[rsp+QB_PN]
	bswap	eax
	mov	[rdi],eax
	add	rdi,4
	mov	rax,rdi
	sub	rax,[rsp+QB_BUF]
	mov	[rsp+QB_HDR],eax
	; the frames
	mov	r14,[rsp+QB_BUF]
	mov	eax,[rsp+QB_MAX]
	sub	eax,16				; the tag
	add	r14,rax				; their limit
	test	dword [rsp+QB_FLAGS],32
	jnz	.close
	imul	eax,r12d,PS_SIZE
	cmp	dword [r15+QC_PS+rax+PS_NR],0
	je	@f
	mov	ecx,r12d
	call	qc_ack_write			; rdi past it
@@:
	test	dword [rsp+QB_FLAGS],64
	jz	@f
	mov	byte [rdi],0x1A			; PATH_CHALLENGE
	mov	rax,[r15+QC_PCHALO]
	mov	[rdi+1],rax
	add	rdi,9
	and	dword [r15+QC_FL2],not QF2_PCHAL
	or	dword [r15+QC_LW_FR],QF2_PCHAL
	mov	dword [rsp+QB_ACKEL],1
@@:
	test	dword [rsp+QB_FLAGS],256
	jz	.no_alt
	mov	byte [rdi],0x1B			; PATH_RESPONSE, then padding
	mov	rax,[r15+QC_ALT_DATA]
	mov	[rdi+1],rax
	add	rdi,9
	; and our own probe of the way back (RFC 9000 9.6.2): a value of its
	; own, the path only counts once the connection moves (qc_migrate)
	push	rdx
	rdtsc
	shl	rdx,32
	or	rax,rdx
	mov	rdx,0x9E3779B97F4A7C15
	imul	rax,rdx
	xor	rax,[r15+QC_SCID]
	pop	rdx
	mov	byte [rdi],0x1A
	mov	[rdi+1],rax
	add	rdi,9
	and	dword [r15+QC_FL2],not QF2_PALT
	mov	rcx,r14
	sub	rcx,rdi
	xor	eax,eax
	rep	stosb
	jmp	.frames_end
.no_alt:
	test	dword [rsp+QB_FLAGS],128
	jz	.no_mtu_probe
	; the MTU probe: PING, padded to the size tried. Not ack-eliciting in
	; its record: out of flight, no probe timer, its loss no congestion
	mov	byte [rdi],1
	inc	rdi
	mov	rcx,r14
	sub	rcx,rdi
	xor	eax,eax
	rep	stosb
	inc	dword [r15+QC_MTU_N]
	call	qc_pto_period
	lea	rax,[rax*2+rax]
	add	rax,[g_qnow]
	mov	[r15+QC_MTU_AT],rax
	jmp	.frames_end
.no_mtu_probe:
	test	dword [rsp+QB_FLAGS],2
	jz	.no_crypto
	; CRYPTO: as much as fits
	mov	eax,[r15+QC_CS_SENT+r12*4]
	mov	ecx,[r15+QC_CS_LEN+r12*4]
	sub	ecx,eax				; left
	mov	rdx,r14
	sub	rdx,rdi
	sub	rdx,1 + 4 + 2			; type, offset, length
	jle	.no_crypto
	cmp	rcx,rdx
	jbe	@f
	mov	ecx,edx
@@:
	mov	[rsp+QB_CRYPTO],eax
	mov	[rsp+QB_CRYPTO+4],ecx
	mov	byte [rdi],6
	or	eax,0x80000000			; offset: 4-byte varint
	bswap	eax
	mov	[rdi+1],eax
	mov	eax,ecx
	or	eax,0x4000			; length: 2-byte varint
	xchg	al,ah
	mov	[rdi+5],ax
	add	rdi,7
	mov	eax,[rsp+QB_CRYPTO]
	lea	rsi,[r15+QC_TLSOUT+rax]
	cmp	r12d,QL_INIT
	je	@f
	mov	edx,[r15+QC_CS_LEN+0]		; Handshake data follows the ServerHello,
	add	rsi,rdx				; 1-RTT's (the ticket) the Handshake data
	cmp	r12d,QL_APP
	jne	@f
	mov	edx,[r15+QC_CS_LEN+4]
	add	rsi,rdx
@@:
	rep	movsb
	mov	eax,[rsp+QB_CRYPTO+4]
	add	[r15+QC_CS_SENT+r12*4],eax
	mov	dword [rsp+QB_ACKEL],1
.no_crypto:
	test	dword [rsp+QB_FLAGS],4
	jz	@f
	mov	byte [rdi],0x1E			; HANDSHAKE_DONE
	inc	rdi
	and	dword [r15+QC_FLAGS],not QF_HDONE
	mov	dword [rsp+QB_HDONE],1
	mov	dword [rsp+QB_ACKEL],1
@@:
	test	dword [rsp+QB_FLAGS],16
	jz	@f
	mov	rsi,r14				; stream frames, as far as they fit
	call	qc_app_write			; rdi past them; eax = 1 when any
	or	[rsp+QB_ACKEL],eax
@@:
	test	dword [rsp+QB_FLAGS],8
	jz	.frames_end
	mov	dword [r15+QC_PROBE+r12*4],0
	cmp	dword [rsp+QB_ACKEL],0
	jne	.frames_end
	mov	byte [rdi],1			; PING: something to acknowledge
	inc	rdi
	mov	dword [rsp+QB_ACKEL],1
	jmp	.frames_end
.close:
	mov	al,0x1C				; CONNECTION_CLOSE: error, frame type, no reason
	test	dword [r15+QC_FLAGS],QF_APP_ERR
	jz	@f
	cmp	r12d,QL_APP
	jne	@f
	mov	al,0x1D				; the application's: no frame type
@@:
	mov	[rdi],al
	inc	rdi
	push	rax
	mov	rax,[r15+QC_ERR]
	call	qv_write
	pop	rax
	cmp	al,0x1D
	je	@f
	mov	byte [rdi],0
	inc	rdi
@@:
	mov	byte [rdi],0
	inc	rdi
	and	dword [r15+QC_FLAGS],not QF_CLOSE
	mov	dword [rsp+QB_ACKEL],0
.frames_end:
	; a datagram with an ack-eliciting Initial: 1200 bytes at least
	cmp	r12d,QL_INIT
	jne	.padded
	cmp	dword [rsp+QB_ACKEL],0
	je	.padded
	mov	rax,[rsp+QB_BUF]
	add	rax,1200 - 16
	cmp	rdi,rax
	jae	.padded
	mov	rcx,rax
	sub	rcx,rdi
	push	rdi
	xor	eax,eax
	rep	stosb
	pop	rdi
	mov	rdi,[rsp+QB_BUF]
	add	rdi,1200 - 16
.padded:
	; the payload's length; the long header's length field
	mov	r9,rdi
	sub	r9,[rsp+QB_BUF]
	sub	r9d,[rsp+QB_HDR]		; payload
	mov	eax,[rsp+QB_LENAT]
	test	eax,eax
	jz	@f
	lea	ecx,[r9+4+16]			; packet number, payload, tag
	or	ecx,0x4000
	xchg	cl,ch
	mov	rdx,[rsp+QB_BUF]
	mov	[rdx+rax],cx
@@:
	; the record it takes: one still in flight there is lost (a packet
	; must go: an ACK, a probe)
	push	rdi
	mov	rax,[rsp+8+QB_PN]		; (past the push)
	call	qc_sp_at
	mov	eax,[rdx+SP_FL]
	and	eax,SPF_SENT or SPF_ACKEL or SPF_ACKED
	cmp	eax,SPF_SENT or SPF_ACKEL
	jne	.slot_free
	push	r9
	mov	r8,rdx
	mov	edi,r12d
	call	qc_lose_one
	pop	r9
.slot_free:
	pop	rdi
	; recorded, sealed, queued
	mov	eax,[rsp+QB_PN]
	and	eax,SP_N - 1
	shl	eax,6				; SP_SIZE
	mov	ecx,r12d
	imul	ecx,ecx,SP_N * SP_SIZE
	lea	rdx,[r15+QC_SP+rcx]
	add	rdx,rax
	mov	rax,[rsp+QB_PN]
	mov	[rdx+SP_PN],rax
	mov	rax,[g_qnow]
	mov	[rdx+SP_TIME],rax
	mov	eax,SPF_SENT
	cmp	dword [rsp+QB_ACKEL],0
	je	@f
	or	eax,SPF_ACKEL
@@:
	cmp	dword [rsp+QB_HDONE],0
	je	@f
	or	eax,SPF_HDONE
@@:
	test	dword [rsp+QB_FLAGS],128
	jz	@f
	or	eax,SPF_MTU
@@:
	mov	[rdx+SP_FL],eax
	mov	eax,[rsp+QB_CRYPTO]
	mov	[rdx+SP_COFF],eax
	mov	eax,[rsp+QB_CRYPTO+4]
	mov	[rdx+SP_CLEN],eax
	cmp	r12d,QL_APP
	jne	@f
	mov	rdi,rdx				; the stream frames it carried (http3.inc)
	mov	rsi,[rsp+QB_PN]
	call	qc_app_sent
@@:
	imul	eax,r12d,PS_SIZE
	mov	dword [r15+QC_PS+rax+PS_ACKQ],0
	lea	eax,[r12*2+1]
	imul	eax,eax,QK_SIZE
	lea	rdi,[r15+QC_KEYS+rax]
	mov	rsi,[rsp+QB_BUF]
	mov	edx,[rsp+QB_HDR]
	mov	ecx,4
	mov	r8,[rsp+QB_PN]
	call	quic_seal			; eax = the packet's length
	add	[r15+QC_TXB],rax
	push	rax
	mov	ecx,[rsp+8+QB_PN]
	and	ecx,SP_N - 1
	shl	ecx,6				; SP_SIZE
	mov	edx,r12d
	imul	edx,edx,SP_N * SP_SIZE
	add	ecx,edx
	mov	[r15+QC_SP+rcx+SP_BYTES],eax
	cmp	dword [rsp+8+QB_ACKEL],0
	je	@f
	add	[r15+QC_INFL],rax
	cmp	r12d,QL_APP
	jne	@f
	test	dword [r15+QC_FLAGS],QF_BBR
	jz	@f
	call	qc_bbr_sent
@@:
	pop	rax
	mov	ecx,eax
	mov	edi,[r15+QC_SOCK]
	lea	rsi,[r15+QC_PEER]
	mov	r8d,[r15+QC_PEERLEN]
	test	dword [rsp+QB_FLAGS],256	; (a probe's answer: to its path)
	jz	@f
	mov	edi,[r15+QC_ALT_SLOT]
	lea	rsi,[r15+QC_ALT_SA]
	mov	r8d,[r15+QC_ALT_LEN]
@@:
	mov	edx,[r15+QC_ECNOFF]
	xor	edx,1
	mov	[g_qtx_ect],edx
	call	qtx_commit
	cmp	dword [rsp+QB_ACKEL],0
	je	@f
	cmp	qword [r15+QC_PTO_AT],0
	jne	@f
	call	qc_pto_period
	add	rax,[g_qnow]
	mov	[r15+QC_PTO_AT],rax
@@:
	mov	eax,1
	jmp	.out
.nothing:
	xor	eax,eax
.out:
	add	rsp,QB_SIZE
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; eax = the level CONNECTION_CLOSE goes at: the highest with keys
qc_close_level:
	mov	eax,QL_APP
	test	dword [r15+QC_FLAGS],QF_DONE
	jnz	.out
	mov	eax,QL_HS
	test	dword [r15+QC_FLAGS],QF_HELLO
	jnz	.out
	mov	eax,QL_INIT
.out:
	ret

; ecx = level, rdi = where: an ACK frame of its ranges; rdi past it
qc_ack_write:
	imul	eax,ecx,PS_SIZE
	lea	r8,[r15+QC_PS+rax]
	mov	r11,rdi				; (the type: 3 when ECN counts follow)
	imul	edx,ecx,24			; (the space's ECN counts, rcx goes)
	lea	rdx,[r15+QC_ECN+rdx]
	mov	byte [rdi],2
	inc	rdi
	mov	rax,[r8+PS_R]			; largest
	call	qv_write
	mov	rax,[g_qnow]			; ack delay, in units of 8 µs
	sub	rax,[r8+PS_LTIME]
	jns	@f
	xor	eax,eax
@@:
	shr	rax,3
	call	qv_write
	mov	eax,[r8+PS_NR]
	dec	eax
	call	qv_write			; range count
	mov	rax,[r8+PS_R]
	sub	rax,[r8+PS_R+8]
	call	qv_write			; first range
	mov	r9d,1
	lea	r10,[r8+PS_R]
.range:
	cmp	r9d,[r8+PS_NR]
	jae	.done
	mov	rax,[r10+8]			; previous lo
	sub	rax,[r10+16]			; - this hi
	sub	rax,2
	call	qv_write			; gap
	mov	rax,[r10+16]
	sub	rax,[r10+24]
	call	qv_write			; length
	add	r10,16
	inc	r9d
	jmp	.range
.done:
	; ECN marks seen in this space: the ACK_ECN form (type 3) and its counts
	mov	rax,[rdx]
	or	rax,[rdx+8]
	or	rax,[rdx+16]
	jz	.plain
	mov	byte [r11],3
	mov	rax,[rdx]
	call	qv_write			; ECT(0)
	mov	rax,[rdx+8]
	call	qv_write			; ECT(1)
	mov	rax,[rdx+16]
	call	qv_write			; CE
.plain:
	ret

; ------------------------------------------------------- the send batch

; rax = the next datagram's buffer (0 when the batch cannot take one even
; after a flush), edx = its slot
qtx_slot:
	mov	edx,[g_qtx_n]
	cmp	edx,QTX_N
	jb	@f
	push	rdi
	call	qtx_send
	pop	rdi
	mov	edx,[g_qtx_n]
	cmp	edx,QTX_N
	jae	.none
@@:
	imul	rax,rdx,QTX_SZ
	lea	rax,[g_qtx_buf+rax]
	ret
.none:
	xor	eax,eax
	ret

; the datagram in the batch's next slot is ready: edi = socket slot, ecx =
; its length, rsi = the address, r8d = its length
qtx_commit:
	mov	edx,[g_qtx_n]
	mov	rax,rdx
	shl	rax,6
	lea	r9,[g_qtx_mm+rax]
	mov	r10,rdx
	shl	r10,5
	lea	r10,[g_qtx_sa+r10]
	mov	[r9],r10			; msg_name: a copy
	mov	[r9+8],r8d
	push	rdi
	push	rcx
	mov	rdi,r10
	mov	ecx,28
	rep	movsb
	pop	rcx
	pop	rdi
	mov	r10,rdx
	shl	r10,4
	lea	r10,[g_qtx_iov+r10]
	mov	[r9+16],r10
	mov	qword [r9+24],1
	mov	qword [r9+32],0			; no control
	mov	qword [r9+40],0
	cmp	dword [g_qtx_ect],0
	je	.no_mark
	mov	dword [g_qtx_ect],0
	; the socket's IPv4 option for an IPv4 address (mapped, on a dual-stack
	; socket, too), its IPv6 one else
	lea	rax,[ecn_cm_ip]
	cmp	word [r10],AF_INET6
	jne	.mark
	cmp	dword [r10+8],0
	jne	.mark6
	cmp	dword [r10+12],0
	jne	.mark6
	cmp	dword [r10+16],0xFFFF0000
	je	.mark
.mark6:
	lea	rax,[ecn_cm_ip6]
.mark:
	mov	[r9+32],rax
	mov	qword [r9+40],24
.no_mark:
	mov	dword [r9+48],0
	imul	rax,rdx,QTX_SZ
	lea	rax,[g_qtx_buf+rax]
	mov	[r10],rax
	mov	[r10+8],rcx
	mov	eax,[g_qs_fd+rdi*4]
	mov	[g_qtx_fds+rdx*4],eax
	inc	dword [g_qtx_n]
	ret

; the batch goes, a sendmmsg per run of datagrams on one socket. Runs of
; datagrams to one address, of one size (the last may be shorter) and one
; ECN mark go as one message the kernel segments (UDP_SEGMENT); a device
; that cannot (no checksum offload: EIO) turns that off in this worker and
; they go one by one.
QGSO_MAX	:= 32
qtx_send:
	push	rbx
	push	r12
	push	r13
	push	r14
	cmp	dword [g_qgso_off],0
	jne	.plain
	xor	ebx,ebx				; i: the first datagram of a message
	xor	r12d,r12d			; w: the messages
.m_next:
	cmp	ebx,[g_qtx_n]
	jae	.m_done
	lea	r13d,[rbx+1]			; j: past its last
	mov	rax,rbx
	shl	rax,4
	mov	r14,[g_qtx_iov+rax+8]		; the segment size
.m_more:
	cmp	r13d,[g_qtx_n]
	jae	.m_end
	mov	eax,r13d
	sub	eax,ebx
	cmp	eax,QGSO_MAX
	jae	.m_end
	mov	eax,[g_qtx_fds+r13*4]
	cmp	eax,[g_qtx_fds+rbx*4]
	jne	.m_end
	lea	rax,[r13-1]
	shl	rax,4
	cmp	[g_qtx_iov+rax+8],r14		; only the last may be shorter
	jne	.m_end
	mov	rax,r13
	shl	rax,4
	cmp	[g_qtx_iov+rax+8],r14
	ja	.m_end
	mov	rax,r13
	shl	rax,6
	mov	rcx,rbx
	shl	rcx,6
	mov	rdx,[g_qtx_mm+rax+32]
	cmp	rdx,[g_qtx_mm+rcx+32]
	jne	.m_end
	mov	rsi,r13
	shl	rsi,5
	lea	rsi,[g_qtx_sa+rsi]
	mov	rdi,rbx
	shl	rdi,5
	lea	rdi,[g_qtx_sa+rdi]
	mov	ecx,28
	repe	cmpsb
	jne	.m_end
	inc	r13d
	jmp	.m_more
.m_end:
	mov	rsi,rbx
	shl	rsi,6
	lea	rsi,[g_qtx_mm+rsi]
	mov	rdi,r12
	shl	rdi,6
	lea	rdi,[g_qgso_mm+rdi]
	mov	rdx,rdi
	mov	ecx,8
	rep	movsq
	mov	[g_qgso_first+r12*4],ebx
	mov	eax,[g_qtx_fds+rbx*4]
	mov	[g_qgso_fd+r12*4],eax
	mov	eax,r13d
	sub	eax,ebx
	cmp	eax,2
	jb	.m_single
	mov	[rdx+24],rax			; msg_iovlen: its datagrams' iovecs
	imul	rcx,r12,48
	lea	rcx,[g_qgso_cm+rcx]
	mov	qword [rcx],18			; UDP_SEGMENT, and the mark after it
	mov	dword [rcx+8],SOL_UDP
	mov	dword [rcx+12],UDP_SEGMENT
	mov	[rcx+16],r14w
	mov	r8d,24
	mov	rsi,[rdx+32]
	test	rsi,rsi
	jz	@f
	mov	rax,[rsi]
	mov	[rcx+24],rax
	mov	rax,[rsi+8]
	mov	[rcx+32],rax
	mov	rax,[rsi+16]
	mov	[rcx+40],rax
	mov	r8d,48
@@:
	mov	[rdx+32],rcx
	mov	[rdx+40],r8
.m_single:
	inc	r12d
	mov	ebx,r13d
	jmp	.m_next
.m_done:
	xor	ebx,ebx
.s_run:
	cmp	ebx,r12d
	jae	.done
	mov	r13d,ebx			; the run: same socket
	mov	eax,[g_qgso_fd+rbx*4]
@@:
	inc	r13d
	cmp	r13d,r12d
	jae	@f
	cmp	[g_qgso_fd+r13*4],eax
	je	@b
@@:
	mov	edi,eax
	mov	rsi,rbx
	shl	rsi,6
	lea	rsi,[g_qgso_mm+rsi]
	mov	edx,r13d
	sub	edx,ebx
	xor	r10d,r10d
	mov	eax,SYS_sendmmsg
	syscall
	test	eax,eax
	js	.s_err
	add	ebx,eax
	jmp	.s_run
.s_err:
	cmp	eax,-EIO
	je	.s_off
	cmp	eax,-EINVAL
	je	.s_off
	cmp	eax,-EOPNOTSUPP
	je	.s_off
	mov	ebx,r13d			; (a full socket drops the rest: QUIC recovers)
	jmp	.s_run
.s_off:
	mov	dword [g_qgso_off],1
	mov	ebx,[g_qgso_first+rbx*4]	; from there on, one by one
	jmp	.run
.plain:
	xor	ebx,ebx
.run:
	cmp	ebx,[g_qtx_n]
	jae	.done
	mov	r12d,ebx			; the run: same socket
	mov	eax,[g_qtx_fds+rbx*4]
@@:
	inc	r12d
	cmp	r12d,[g_qtx_n]
	jae	@f
	cmp	[g_qtx_fds+r12*4],eax
	je	@b
@@:
	mov	edi,eax
	mov	rsi,rbx
	shl	rsi,6
	lea	rsi,[g_qtx_mm+rsi]
	mov	edx,r12d
	sub	edx,ebx
	xor	r10d,r10d
	mov	eax,SYS_sendmmsg
	syscall				; (a full socket drops the rest: QUIC recovers)
	mov	ebx,r12d
	jmp	.run
.done:
	mov	dword [g_qtx_n],0
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; The worker's loop, after the deliveries: what the connections have to
; send, then the batch
qs_flush:
	cmp	dword [g_qs_n],0
	je	.out
	push	rbx
	push	r12
	xor	r12d,r12d
.next:
	cmp	r12d,[g_qdirty_n]
	jae	.sent
	mov	rax,[g_qdirty+r12*8]
	inc	r12d
	mov	ebx,eax
	shr	rax,32
	push	rax
	call	session_ptr
	pop	rcx
	cmp	[rax+S_GEN],ecx
	jne	.next
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.next
	test	dword [rax+S_FLAGS],SF_QC
	jz	.next
	push	r15
	qc_regs
	mov	dword [r15+QC_DIRTY],0
	pop	r15
	call	qc_send
	jmp	.next
.sent:
	mov	dword [g_qdirty_n],0
	cmp	dword [g_qtx_n],0
	je	@f
	call	qtx_send
@@:
	call	qs_pace_timer
	pop	r12
	pop	rbx
.out:
	ret

; ---------------------------------------------------------------- time

; Every 10 ms while there are connections: probe timeouts, closings
qs_tick:
	cmp	dword [g_qc_count],0
	je	.out
	push	rbx
	push	r12
	push	r15
	call	qs_clock
	mov	qword [g_qpace_next],0		; (found again below, and by qc_pace)
	mov	r12d,[g_qc_head]
.next:
	test	r12d,r12d
	jz	.done
	lea	ebx,[r12-1]
	mov	r15d,ebx
	shl	r15,HB_SHIFT
	add	r15,[g_hbuf_base]
	mov	r12d,[r15+QC_LINK]		; (before it may go)
	cmp	dword [g_draining],2
	jb	@f
	call	qc_drain			; http3.inc: GOAWAY, then close
@@:
	cmp	dword [r15+QC_STATE],QCS_CLOSING
	jne	.pto
	test	dword [r15+QC_FLAGS],QF_CLOSE
	jnz	.next				; its CONNECTION_CLOSE has not gone yet
	mov	rax,[g_qnow]
	cmp	rax,[r15+QC_CLOSE_AT]
	jb	.next
	call	qc_free
	jmp	.next
.pto:
	call	qc_heads_expire			; http3.inc
	mov	rax,[r15+QC_PACE_AT]		; still held by pacing: the timer's
	test	rax,rax
	jz	@f
	cmp	rax,[g_qnow]
	jbe	@f
	mov	rcx,[g_qpace_next]
	test	rcx,rcx
	jz	.pace_min
	cmp	rax,rcx
	jae	@f
.pace_min:
	mov	[g_qpace_next],rax
@@:
	cmp	dword [r15+QC_MTU_TRY],0	; a path MTU probe due
	je	@f
	mov	rax,[r15+QC_MTU_AT]
	cmp	rax,[g_qnow]
	ja	@f
	call	qc_dirty
@@:
	mov	rax,[r15+QC_PACE_AT]		; pacing held data: its time has come
	test	rax,rax
	jz	@f
	cmp	rax,[g_qnow]
	ja	@f
	mov	qword [r15+QC_PACE_AT],0
	call	qc_dirty
@@:
	mov	rax,[r15+QC_LOSS_AT]		; the loss timer first
	test	rax,rax
	jz	@f
	cmp	rax,[g_qnow]
	ja	@f
	mov	qword [r15+QC_LOSS_AT],0
	mov	edi,[r15+QC_LOSS_LVL]
	mov	rsi,[r15+QC_LOSS_PN]
	call	qc_detect_lost
@@:
	mov	rax,[r15+QC_PTO_AT]
	test	rax,rax
	jz	.next
	cmp	rax,[g_qnow]
	ja	.next
	call	qc_on_pto
	jmp	.next
.done:
	pop	r15
	pop	r12
	pop	rbx
	call	qs_flush
.out:
	ret

; ebx, r15 = connection: its probe timer went off. What was sent and not
; acknowledged goes again: crypto data from the lowest offset lost, the
; streams' (http3.inc); a PING where there is nothing else to send
qc_on_pto:
	push	r12
	inc	dword [r15+QC_PTOCNT]
	mov	qword [r15+QC_PTO_AT],0
	xor	r12d,r12d
.level:
	cmp	r12d,3
	jae	.done
	mov	eax,r12d
	imul	eax,eax,SP_N * SP_SIZE
	lea	r8,[r15+QC_SP+rax]
	mov	ecx,SP_N
	mov	r9d,-1				; the lowest crypto offset lost
	xor	r10d,r10d			; anything ack-eliciting out
.slot:
	mov	eax,[r8+SP_FL]
	and	eax,SPF_SENT or SPF_ACKEL or SPF_ACKED
	cmp	eax,SPF_SENT or SPF_ACKEL
	jne	.slot_next
	mov	r10d,1
	and	dword [r8+SP_FL],not SPF_SENT	; lost: it goes again in a new packet
	mov	eax,[r8+SP_BYTES]
	sub	[r15+QC_INFL],rax
	jns	@f
	mov	qword [r15+QC_INFL],0
@@:
	cmp	dword [r8+SP_CLEN],0
	je	@f
	mov	eax,[r8+SP_COFF]
	cmp	eax,r9d
	jae	@f
	mov	r9d,eax
@@:
	test	dword [r8+SP_FL],SPF_HDONE
	jz	@f
	or	dword [r15+QC_FLAGS],QF_HDONE
@@:
	cmp	r12d,QL_APP
	jne	.slot_next
	push	r8
	push	rcx
	push	r9
	push	r10
	mov	rdi,r8
	call	qc_app_lost			; http3.inc: its stream data goes again
	pop	r10
	pop	r9
	pop	rcx
	pop	r8
.slot_next:
	add	r8,SP_SIZE
	dec	ecx
	jnz	.slot
	cmp	r9d,-1
	je	@f
	cmp	r9d,[r15+QC_CS_SENT+r12*4]
	jae	@f
	mov	[r15+QC_CS_SENT+r12*4],r9d
@@:
	test	r10d,r10d
	jz	@f
	mov	dword [r15+QC_PROBE+r12*4],1
@@:
	inc	r12d
	jmp	.level
.done:
	pop	r12
	jmp	qc_dirty

; r15 = connection: what went at Initial and Handshake and is not
; acknowledged is lost (its crypto data goes again), without a probe
; timeout counted
qc_flight_again:
	push	r12
	xor	r12d,r12d
.level:
	mov	eax,r12d
	imul	eax,eax,SP_N * SP_SIZE
	lea	r8,[r15+QC_SP+rax]
	mov	ecx,SP_N
	mov	r9d,-1				; the lowest crypto offset lost
.slot:
	mov	eax,[r8+SP_FL]
	and	eax,SPF_SENT or SPF_ACKEL or SPF_ACKED
	cmp	eax,SPF_SENT or SPF_ACKEL
	jne	.next
	and	dword [r8+SP_FL],not SPF_SENT
	mov	eax,[r8+SP_BYTES]
	sub	[r15+QC_INFL],rax
	jns	@f
	mov	qword [r15+QC_INFL],0
@@:
	cmp	dword [r8+SP_CLEN],0
	je	.next
	mov	eax,[r8+SP_COFF]
	cmp	eax,r9d
	jae	.next
	mov	r9d,eax
.next:
	add	r8,SP_SIZE
	dec	ecx
	jnz	.slot
	cmp	r9d,[r15+QC_CS_SENT+r12*4]
	jae	@f
	mov	[r15+QC_CS_SENT+r12*4],r9d
@@:
	inc	r12d
	cmp	r12d,2
	jb	.level
	pop	r12
	ret

; r15 = connection, before a packet that carries data: CF when pacing
; holds it (RFC 9002 7.7): a budget refilled at 1.25 cwnd / srtt, at most
; a tick and a half of it, a datagram taken a packet; QC_PACE_AT is when it
; allows one again (the QUIC tick sends then). Only on paths whose RTT is
; well above the tick.
qc_pace:
	mov	rcx,[r15+QC_SRTT]
	cmp	rcx,PACE_MIN_RTT
	jb	.go
	mov	rax,[g_qnow]
	mov	rdx,rax
	sub	rax,[r15+QC_PACE_T]		; µs since the last fill
	mov	[r15+QC_PACE_T],rdx
	cmp	rax,1000000
	jbe	@f
	mov	eax,1000000
@@:
	call	qc_pace_window			; r8
	imul	rax,r8
	imul	rax,rax,5
	shr	rax,2				; * 1.25 cwnd
	xor	edx,edx
	div	rcx				; / srtt: bytes earned
	add	rax,[r15+QC_PACE_B]
	mov	r9,r8				; the cap: 15 ms of sending
	imul	r9,r9,15000 * 5 / 4
	push	rax
	mov	rax,r9
	xor	edx,edx
	div	rcx
	mov	r9,rax
	pop	rax
	cmp	r9,10 * QUIC_DGRAM
	jge	@f
	mov	r9d,10 * QUIC_DGRAM
@@:
	cmp	rax,r9
	jle	@f
	mov	rax,r9
@@:
	cmp	rax,QUIC_DGRAM
	jl	.wait
	sub	rax,QUIC_DGRAM
	mov	[r15+QC_PACE_B],rax
	mov	qword [r15+QC_PACE_AT],0
.go:
	clc
	ret
.wait:
	mov	[r15+QC_PACE_B],rax
	push	rax
	mov	rdx,QUIC_DGRAM			; µs to earn the rest of a datagram
	sub	rdx,rax
	mov	rax,rdx
	imul	rax,rcx
	imul	r8,r8,5
	shr	r8,2
	xor	edx,edx
	div	r8
	add	rax,[g_qnow]
	mov	[r15+QC_PACE_AT],rax
	mov	rcx,[g_qpace_next]		; the worker's earliest (its timer)
	test	rcx,rcx
	jz	@f
	cmp	rax,rcx
	jae	.later
@@:
	mov	[g_qpace_next],rax
.later:
	pop	rax
	stc
	ret

; ebx = connection: it goes (session_close calls qc_closing)
qc_free:
	mov	edi,ebx
	jmp	session_close

; session_close of a connection (SF_QC): its IDs out of the hash, out of
; the list, its streams closed. ebx = session; keeps rbx, r12.
qc_closing:
	push	r15
	push	r14
	push	rbx
	push	r12
	qc_regs
	test	dword [r15+QC_FLAGS],QF_LINKED
	jz	.out
	call	session_ptr
	mov	ecx,[rax+S_GEN]
	cmp	ecx,[r15+QC_GEN]
	jne	.out
	and	dword [r15+QC_FLAGS],not QF_LINKED	; (once)
	test	dword [r15+QC_FLAGS],QF_VALID
	jnz	@f
	dec	dword [g_qc_unval]
@@:
	lea	rdi,[r15+QC_SCID]
	mov	esi,8
	call	qh_del
	lea	rdi,[r15+QC_ODCID]
	mov	esi,[r15+QC_ODCIDLEN]
	call	qh_del
	lea	rdi,[r15+QC_CIDS]		; those issued later (not in: a no-op)
	mov	esi,8
	call	qh_del
	lea	rdi,[r15+QC_CIDS+8]
	mov	esi,8
	call	qh_del
	mov	eax,[r15+QC_LINK]
	mov	ecx,[r15+QC_PLINK]
	test	ecx,ecx
	jz	.head
	lea	edx,[rcx-1]
	shl	rdx,HB_SHIFT
	add	rdx,[g_hbuf_base]
	mov	[rdx+QC_LINK],eax
	jmp	@f
.head:
	mov	[g_qc_head],eax
@@:
	test	eax,eax
	jz	@f
	lea	edx,[rax-1]
	shl	rdx,HB_SHIFT
	add	rdx,[g_hbuf_base]
	mov	[rdx+QC_PLINK],ecx
@@:
	dec	dword [g_qc_count]
	call	qc_streams_close		; http3.inc
.out:
	pop	r12
	pop	rbx
	pop	r14
	pop	r15
	ret

; ------------------------------------------------------------ congestion

; r11 = a sent packet's record, acknowledged (it was in flight): out of
; flight; the window grows (slow start, or congestion avoidance), unless
; it was sent before the recovery began. Keeps every register but rax,
; rcx, rdx.
qc_cc_acked:
	mov	eax,[r11+SP_BYTES]
	sub	[r15+QC_INFL],rax
	jns	@f
	mov	qword [r15+QC_INFL],0
@@:
	test	dword [r15+QC_FLAGS],QF_BBR
	jnz	qc_bbr_acked
	mov	rcx,[r11+SP_TIME]
	cmp	rcx,[r15+QC_RECOV]
	jbe	.out				; in recovery: no growth
	mov	rcx,[r15+QC_CWND]
	cmp	rcx,[r15+QC_SSTH]
	jae	.avoid
	add	[r15+QC_CWND],rax		; slow start: a byte a byte acknowledged
	ret
.avoid:
	; CUBIC (RFC 9438): W(t) = C (t - K)^3 + Wmax, C = 0.4 datagrams/s^3,
	; t the epoch's age plus an RTT; never below the Reno-friendly window
	push	rbx
	push	r8
	push	r9
	push	r10
	mov	rbx,rax				; bytes acknowledged
	cmp	qword [r15+QC_EPOCH],0
	jne	.epoch
	mov	rax,[g_qnow]
	mov	[r15+QC_EPOCH],rax
	mov	[r15+QC_WEST],rcx
	xor	r8d,r8d				; K: 0 when at or above Wmax
	mov	rax,[r15+QC_WMAX]
	sub	rax,rcx
	jbe	.k
	mov	rdx,2500000000			; (Wmax - cwnd) / (0.4 datagram) in s^3:
	mul	rdx				; in ms^3, * 1e9
	mov	r9d,QUIC_DGRAM
	div	r9
	call	qc_cbrt
	mov	r8,rax
.k:
	mov	[r15+QC_K],r8
.epoch:
	mov	rax,[g_qnow]			; t in ms
	sub	rax,[r15+QC_EPOCH]
	add	rax,[r15+QC_SRTT]
	xor	edx,edx
	mov	r9d,1000
	div	r9
	sub	rax,[r15+QC_K]			; t - K (signed)
	cmp	rax,100000
	jle	@f
	mov	eax,100000			; (no overflow: 100 s past K is far enough)
@@:
	cmp	rax,-100000
	jge	@f
	mov	rax,-100000
@@:
	mov	r9,rax
	imul	rax,r9
	imul	rax,r9				; (t - K)^3, ms^3
	cqo
	mov	r10,1000
	idiv	r10
	imul	rax,rax,4 * QUIC_DGRAM		; * 0.4 datagram / 1e9 ms^3 = * 4 / 1e10
	cqo
	mov	r10,10000000
	idiv	r10
	add	rax,[r15+QC_WMAX]		; the cubic window
	mov	r9,rax
	; Reno-friendly: + 3(1 - b)/(1 + b) = 9/17 datagram a window acknowledged
	mov	rax,rbx
	imul	rax,rax,9 * QUIC_DGRAM
	mov	rcx,[r15+QC_CWND]
	imul	rcx,rcx,17
	xor	edx,edx
	div	rcx
	add	rax,[r15+QC_WEST]
	mov	[r15+QC_WEST],rax
	cmp	r9,rax
	jge	@f
	mov	r9,rax
@@:
	; toward the target: (target - cwnd) / cwnd a byte acknowledged, at
	; most half a datagram a datagram
	mov	rcx,[r15+QC_CWND]
	mov	rax,r9
	sub	rax,rcx
	jle	.done
	imul	rax,rbx
	xor	edx,edx
	div	rcx
	mov	rdx,rbx
	shr	rdx,1
	cmp	rax,rdx
	jbe	@f
	mov	rax,rdx
@@:
	add	[r15+QC_CWND],rax
.done:
	pop	r10
	pop	r9
	pop	r8
	pop	rbx
.out:
	ret

; r15 = connection: the next datagram size to try on this path (RFC 9000
; 14.3): none past what the client takes. Keeps all but rax.
qc_mtu_next:
	mov	eax,1350
	cmp	eax,[r15+QC_MTU]
	ja	.have
	mov	eax,1452
	cmp	eax,[r15+QC_MTU]
	ja	.have
.none:
	mov	dword [r15+QC_MTU_TRY],0
	ret
.have:
	cmp	rax,[r15+QC_PMAX]
	ja	.none
	mov	[r15+QC_MTU_TRY],eax
	mov	dword [r15+QC_MTU_N],0
	mov	rax,[g_qnow]
	mov	[r15+QC_MTU_AT],rax
	ret

; a congestion event (r15 = connection): CUBIC's reduction to 0.7 of the
; window, Wmax (lower when the window was still shrinking: fast
; convergence), a new epoch
qc_cc_loss:
	test	dword [r15+QC_FLAGS],QF_BBR	; (BBR's model is not of losses)
	jz	@f
	ret
@@:
	mov	rax,[r15+QC_CWND]
	mov	rcx,rax
	cmp	rax,[r15+QC_WMAX]
	jae	@f
	imul	rcx,rcx,17			; 1.7 / 2 of it
	shr	rcx,1
	mov	edx,10
	push	rax
	mov	rax,rcx
	xor	edx,edx
	mov	ecx,10
	div	rcx
	mov	rcx,rax
	pop	rax
@@:
	mov	[r15+QC_WMAX],rcx
	imul	rax,rax,7
	xor	edx,edx
	mov	ecx,10
	div	rcx
	cmp	rax,QUIC_CWNDMIN
	jae	@f
	mov	eax,QUIC_CWNDMIN
@@:
	mov	[r15+QC_SSTH],rax
	mov	[r15+QC_CWND],rax
	mov	qword [r15+QC_EPOCH],0
	ret

; r15 = connection: BBR starts over (a new path). Keeps all but rcx.
qc_bbr_reset:
	lea	rcx,[r15+QC_WMAX]
	test	dword [r15+QC_FLAGS],QF_BBR
	jz	.out
	mov	qword [rcx],0
	mov	qword [rcx+8],0
	mov	qword [rcx+16],0
	mov	qword [rcx+24],0
	mov	qword [r15+QB_SNAP_T],0
	mov	dword [r15+QB_STATE],BBR_STARTUP
	mov	dword [r15+QB_CYCLE],0
.out:
	ret

; r15 = connection, rcx = a 1-RTT packet's record's offset, just sent: one
; packet a round carries the rate sample (the records have no room for one a
; packet). Another takes over from one that was lost.
qc_bbr_sent:
	mov	rdx,[g_qnow]
	mov	r8,[r15+QB_SNAP_T]
	test	r8,r8
	jz	.mark
	mov	r9,rdx
	sub	r9,r8
	mov	r8,[r15+QC_SRTT]
	shl	r8,2
	cmp	r9,r8
	jb	.out
.mark:
	mov	[r15+QB_SNAP_T],rdx
	mov	rdx,[r15+QB_DELIV]
	mov	[r15+QB_SNAP_D],rdx
	or	dword [r15+QC_SP+rcx+SP_FL],SPF_RATE
.out:
	ret

; r15 = connection: the bandwidth estimate (rax), bytes/s, 0 none yet
qc_bbr_bw:
	mov	rax,[r15+QB_BW]
	cmp	rax,[r15+QB_BW2]
	jae	.out
	mov	rax,[r15+QB_BW2]
.out:
	ret

; from qc_cc_acked: rax = bytes acknowledged, r11 = their packet's record. BBR
; (draft-cardwell-iccrg-bbr-congestion-control): the window and the pacing
; follow the path's measured bandwidth and round trip, a sample a round,
; losses aside. Startup at a gain of 2.89 until the bandwidth stops growing,
; a drain of that queue, then a cycle of 1.25, 0.75, 1 x 6; when no lower
; round trip has been seen in 10 s, a round or two of little in flight.
; Keeps r8-r11, rbx.
qc_bbr_acked:
	add	[r15+QB_DELIV],rax
	cmp	dword [r15+QB_STATE],BBR_STARTUP
	jne	@f
	add	[r15+QC_CWND],rax		; (startup: as slow start)
@@:
	test	dword [r11+SP_FL],SPF_RATE
	jz	.out
	mov	rcx,[g_qnow]
	sub	rcx,[r15+QB_SNAP_T]
	jle	.out				; (a stale mark, its sample gone)
	cmp	qword [r15+QB_SNAP_T],0
	je	.out
	mov	qword [r15+QB_SNAP_T],0
	push	r8
	push	r9
	push	r10
	mov	r10,rcx				; the round trip
	mov	rax,[r15+QB_DELIV]
	sub	rax,[r15+QB_SNAP_D]
	mov	rdx,1000000
	mul	rdx
	div	r10				; the rate
	mov	r8,rax
	; the bandwidth: the best of 5 to 10 rounds
	inc	dword [r15+QB_ROUNDS]
	mov	eax,[r15+QB_ROUNDS]
	xor	edx,edx
	mov	ecx,5
	div	ecx
	test	edx,edx
	jnz	@f
	mov	rax,[r15+QB_BW]
	mov	[r15+QB_BW2],rax
	mov	qword [r15+QB_BW],0
@@:
	cmp	r8,[r15+QB_BW]
	jbe	@f
	mov	[r15+QB_BW],r8
@@:
	; the round trip: the least, or a fresh one after 10 s
	xor	r9d,r9d				; expired?
	mov	eax,[g_tick]
	sub	eax,[r15+QB_RT_TICK]
	cmp	eax,10
	jbe	@f
	inc	r9d
	jmp	.rt_take
@@:
	cmp	dword [r15+QB_RT],0
	je	.rt_take
	cmp	r10d,[r15+QB_RT]
	ja	.rt_kept
.rt_take:
	mov	[r15+QB_RT],r10d
	mov	eax,[g_tick]
	mov	[r15+QB_RT_TICK],eax
.rt_kept:
	call	qc_bbr_bw
	mov	r8,rax				; the bandwidth
	mov	ecx,[r15+QB_RT]
	mul	rcx
	mov	rcx,1000000
	div	rcx
	mov	r10,rax				; bandwidth * round trip
	mov	eax,[r15+QB_STATE]
	cmp	eax,BBR_DRAIN
	je	.drain
	cmp	eax,BBR_PROBE_BW
	je	.cycle
	cmp	eax,BBR_PROBE_RTT
	je	.low
	; startup: over after 3 rounds under 25% better, the window in use
	mov	rax,r8
	shr	rax,10
	mov	ecx,[r15+QB_FULL]
	mov	edx,ecx
	shr	edx,2
	add	ecx,edx
	cmp	eax,ecx
	jb	.flat
	mov	[r15+QB_FULL],eax
	mov	dword [r15+QB_FLAT],0
	jmp	.done
.flat:
	mov	rax,[r15+QC_INFL]
	add	rax,rax
	cmp	rax,[r15+QC_CWND]
	jb	.done				; (the application had no more to send)
	inc	dword [r15+QB_FLAT]
	cmp	dword [r15+QB_FLAT],3
	jb	.done
	mov	dword [r15+QB_STATE],BBR_DRAIN
	jmp	.window
.drain:
	cmp	[r15+QC_INFL],r10
	ja	.window
	mov	dword [r15+QB_STATE],BBR_PROBE_BW
	mov	dword [r15+QB_CYCLE],0
	jmp	.window
.cycle:
	test	r9d,r9d
	jnz	.to_low
	inc	dword [r15+QB_CYCLE]
	cmp	dword [r15+QB_CYCLE],8
	jb	.window
	mov	dword [r15+QB_CYCLE],0
	jmp	.window
.to_low:
	mov	dword [r15+QB_STATE],BBR_PROBE_RTT
	mov	dword [r15+QB_CYCLE],0
	jmp	.window
.low:
	inc	dword [r15+QB_CYCLE]
	cmp	dword [r15+QB_CYCLE],2
	jb	.window
	mov	dword [r15+QB_STATE],BBR_PROBE_BW
	mov	dword [r15+QB_CYCLE],0
.window:
	mov	eax,4 * QUIC_DGRAM
	cmp	dword [r15+QB_STATE],BBR_PROBE_RTT
	je	.set
	lea	rax,[r10+r10]			; twice bandwidth * round trip
	cmp	rax,QUIC_CWNDMIN
	jae	.set
	mov	eax,QUIC_CWNDMIN
.set:
	mov	[r15+QC_CWND],rax
.done:
	pop	r10
	pop	r9
	pop	r8
.out:
	ret

; r15 = connection, rcx = the smoothed RTT: r8 = the window qc_pace paces
; (bytes a round trip at 1 / 1.25 of the rate). Keeps rax, rcx.
qc_pace_window:
	mov	r8,[r15+QC_CWND]
	test	dword [r15+QC_FLAGS],QF_BBR
	jz	.out
	push	rax
	push	rcx
	call	qc_bbr_bw
	test	rax,rax
	jz	.none
	mov	ecx,289
	cmp	dword [r15+QB_STATE],BBR_STARTUP
	je	.gain
	mov	ecx,35
	cmp	dword [r15+QB_STATE],BBR_DRAIN
	je	.gain
	mov	ecx,100
	cmp	dword [r15+QB_STATE],BBR_PROBE_BW
	jne	.gain
	cmp	dword [r15+QB_CYCLE],1
	ja	.gain
	mov	ecx,125
	cmp	dword [r15+QB_CYCLE],0
	je	.gain
	mov	ecx,75
.gain:
	mul	rcx
	mov	rcx,100
	div	rcx
	mov	rcx,[rsp]			; the smoothed RTT
	mul	rcx
	mov	rcx,1000000 * 5 / 4
	div	rcx
	mov	r8,rax
.none:
	pop	rcx
	pop	rax
.out:
	ret

; rax = n: rax = floor(cbrt(n)) (n < 2^63)
qc_cbrt:
	push	rbx
	push	rcx
	push	rdx
	mov	rbx,rax
	xor	ecx,ecx				; lo
	mov	r9d,2097152			; hi: (2^21)^3 = 2^63
.step:
	lea	rax,[rcx+r9+1]
	shr	rax,1				; mid, rounded up
	cmp	rax,r9
	ja	.done
	cmp	rcx,r9
	jae	.done
	mov	rdx,rax
	imul	rdx,rax
	imul	rdx,rax
	cmp	rdx,rbx
	ja	.high
	mov	rcx,rax
	jmp	.step
.high:
	lea	r9,[rax-1]
	jmp	.step
.done:
	mov	rax,rcx
	pop	rdx
	pop	rcx
	pop	rbx
	ret

; edi = level, rsi = the largest packet number just acknowledged: the
; packets sent before it that are not acknowledged and are three numbers
; older, or older than 9/8 of the RTT, are lost (RFC 9002 6.1): they go
; again; one congestion event for them
qc_detect_lost:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r12d,edi
	mov	r13,rsi
	; the time threshold: 9/8 max(srtt, latest), at least 1 ms
	mov	rax,[r15+QC_SRTT]
	cmp	rax,[r15+QC_LATEST]
	jae	@f
	mov	rax,[r15+QC_LATEST]
@@:
	mov	rcx,rax
	shr	rcx,3
	add	rax,rcx
	cmp	rax,1000
	jae	@f
	mov	eax,1000
@@:
	mov	r14,[g_qnow]
	sub	r14,rax				; sent before this: lost
	xor	ebx,ebx				; the latest lost packet's send time
	mov	qword [r15+QC_LOSS_AT],-1	; the earliest a packet still out passes it
	mov	eax,r12d
	imul	eax,eax,SP_N * SP_SIZE
	lea	r8,[r15+QC_SP+rax]
	mov	ecx,SP_N
.slot:
	mov	eax,[r8+SP_FL]
	and	eax,SPF_SENT or SPF_ACKEL or SPF_ACKED
	cmp	eax,SPF_SENT or SPF_ACKEL
	jne	.next
	mov	rax,[r8+SP_PN]
	cmp	rax,r13
	jae	.next				; not before the largest
	lea	rdx,[rax+3]
	cmp	rdx,r13
	jbe	.lost				; three numbers older
	cmp	[r8+SP_TIME],r14
	ja	.pending
.lost:
	and	dword [r8+SP_FL],not SPF_SENT
	mov	eax,[r8+SP_BYTES]
	sub	[r15+QC_INFL],rax
	jns	@f
	mov	qword [r15+QC_INFL],0
@@:
	mov	rax,[r8+SP_TIME]
	cmp	rax,rbx
	jbe	@f
	mov	rbx,rax
@@:
	; what it carried goes again
	cmp	dword [r8+SP_CLEN],0
	je	@f
	mov	eax,[r8+SP_COFF]
	cmp	eax,[r15+QC_CS_SENT+r12*4]
	jae	@f
	mov	[r15+QC_CS_SENT+r12*4],eax
@@:
	test	dword [r8+SP_FL],SPF_HDONE
	jz	@f
	or	dword [r15+QC_FLAGS],QF_HDONE
@@:
	cmp	r12d,QL_APP
	jne	.next
	push	rcx
	push	r8
	mov	rdi,r8
	call	qc_app_lost
	pop	r8
	pop	rcx
	jmp	.next
.pending:
	mov	rax,[g_qnow]			; lost at its send time + the threshold,
	sub	rax,r14				; unless acknowledged before (RFC 9002
	add	rax,[r8+SP_TIME]		; 6.1.2): the loss timer
	cmp	rax,[r15+QC_LOSS_AT]
	jae	.next
	mov	[r15+QC_LOSS_AT],rax
.next:
	add	r8,SP_SIZE
	dec	ecx
	jnz	.slot
	cmp	qword [r15+QC_LOSS_AT],-1
	jne	@f
	mov	qword [r15+QC_LOSS_AT],0
	jmp	.timer_set
@@:
	mov	[r15+QC_LOSS_PN],r13
	mov	[r15+QC_LOSS_LVL],r12d
.timer_set:
	test	rbx,rbx
	jz	.out
	; a congestion event, unless the losses were sent before the last one
	cmp	rbx,[r15+QC_RECOV]
	jbe	.dirty
	mov	rax,[g_qnow]
	mov	[r15+QC_RECOV],rax
	call	qc_cc_loss
.dirty:
	mov	rbx,[rsp+24]			; the session again (rbx held a time)
	call	qc_dirty
.out:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; ecx/r12d = level: rdx = the record the next packet of that space takes
qc_sp_next:
	imul	eax,r12d,PS_SIZE
	mov	rax,[r15+QC_PS+rax+PS_NEXT]
	jmp	qc_sp_at
; rax = a packet number: rdx = its record (ecx/r12d = level)
qc_sp_at:
	and	eax,SP_N - 1
	shl	eax,6				; SP_SIZE
	mov	edx,r12d
	imul	edx,edx,SP_N * SP_SIZE
	add	eax,edx
	lea	rdx,[r15+QC_SP+rax]
	ret

; r8 = a record in flight, edi = its level: lost (out of flight, what it
; carried goes again)
qc_lose_one:
	and	dword [r8+SP_FL],not SPF_SENT
	mov	eax,[r8+SP_BYTES]
	sub	[r15+QC_INFL],rax
	jns	@f
	mov	qword [r15+QC_INFL],0
@@:
	cmp	dword [r8+SP_CLEN],0
	je	@f
	mov	eax,[r8+SP_COFF]
	cmp	eax,[r15+QC_CS_SENT+rdi*4]
	jae	@f
	mov	[r15+QC_CS_SENT+rdi*4],eax
@@:
	test	dword [r8+SP_FL],SPF_HDONE
	jz	@f
	or	dword [r15+QC_FLAGS],QF_HDONE
@@:
	cmp	edi,QL_APP
	jne	@f
	mov	rdi,r8
	jmp	qc_app_lost
@@:
	ret


