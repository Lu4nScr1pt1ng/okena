; HTTP/2 towards backends: pools with `protocol h2`.
;
; An upstream connection (UC) is a session of its own (SF_H2U) that owns
; the socket to one server and carries many requests as streams. It
; connects like any upstream (session_connect, TLS through uptls.inc with
; ALPN h2, then kTLS) and then runs the connection code of h2.inc in
; client mode (C2F_CLIENT). At most H2U_PER of them a server, each taking
; streams up to what the server allows (SETTINGS_MAX_CONCURRENT_STREAMS).
;
; A session whose pool speaks HTTP/2 (SF_UPH2) attaches to one instead of
; taking a socket, and its upstream side is served by it, the mirror of
; the client side of HTTP/2 streams:
;
;   h_send on its upstream side (h2u_send) gives the request: its
;       HTTP/1.1 head becomes HEADERS (:authority from Host, te: trailers),
;       its body DATA within the windows; the end of the request is
;       END_STREAM (with HEADERS when there is no body);
;   h_recv on its upstream side (h2u_recv) reads the response written as
;       HTTP/1.1 from the HEADERS and DATA: chunk-framed when the server
;       gave no content-length, its trailers after the last chunk (they
;       reach the client, gRPC's status among them).
;
; A UC's state that must outlive its TLS handshake (whose workspace is
; where the h2 state goes after) lives in its unused HTTP input area: the
; requests waiting for it to connect, its load, its registry slot.

H2U_PER		:= 4				; connections a server
H2U_WAIT_MAX	:= 128				; requests waiting for one to connect

; in a UC's buffers, at HB_IN
W_N		:= 0				; d: waiters
W_LOAD		:= 4				; d: attached requests (waiting, or streams)
W_READY		:= 8				; d: 1 once HTTP/2 runs on it
W_SLOT		:= 12				; d: its registry slot + 1
W_ENT		:= 64				; (session, generation) each

; C2 fields of a UC (client mode)
C2_PMAXS	:= 104				; the server's SETTINGS_MAX_CONCURRENT_STREAMS
C2_NEXTSID	:= 108				; our next stream id
C2F_CLIENT	:= 64				; okena is the client of this connection
assert C2_NEXTSID + 4 <= C2_ST

; a requesting session's upstream state, in its buffers (it never holds a
; UC's or an HTTP/2 connection's state itself)
HB_U2		:= 1 shl 17
U2_UC		:= 0				; d: its UC
U2_UCG		:= 4				; d: that UC's generation
U2_SID		:= 8				; d: its stream id, 0 = none yet
U2_SWIN		:= 12				; d (signed): what it may still send
U2_F		:= 16				; d: U2F_*
U2_PL		:= 20				; d: request bytes waiting for room or window
U2_PP		:= 24				; q
U2_BL		:= 32				; d: next in the UC's waiting list (+ 1)
HB_U2Q		:= HB_U2 + 64			; the response queue (Q_* layout of h2.inc)
U2F_HEAD	:= 1				; HEADERS went out
U2F_END		:= 2				; END_STREAM went out
U2F_RST		:= 4				; the stream failed (reset, or its connection went)
U2F_WAITING	:= 8				; in the UC's waiting list
U2F_SENDING	:= 16				; an h_send is pending
U2F_RHEAD	:= 32				; the final response head came
U2F_RCHUNK	:= 64				; the response is written chunk-framed
U2F_REND	:= 128				; the response is complete
U2F_FINISH	:= 256				; END_STREAM waits for room
U2F_CREDIT	:= 1024				; stream credit waits for room
U2F_DPUMP	:= 2048				; http_duplex_pump is running for it
SF_UPH2		:= 16384			; S_FLAGS: the upstream side is a stream on a UC
SF_H2U		:= 32768			; S_FLAGS: an upstream HTTP/2 connection

bss
	align 4
	g_h2u:		rd MAX_SERVERS * H2U_PER	; UC session + 1, 0 = none
	g_h2ug:		rd MAX_SERVERS * H2U_PER	; its generation
	g_h2u_blen	dd ?			; h2u_head_out: the block left to frame
end bss

; edi = session: rax = its U2 area (requesting sessions)
macro u2_at reg*, sess*
	mov	eax,sess
	shl	rax,H_SHIFT
	add	rax,[g_http_base]
	mov	reg,[rax+H_BUF]
	add	reg,HB_U2
end macro

; ebx = session: session_uncount for it (that one wants r12 = its record)
h2u_uncount:
	push	r12
	call	session_ptr
	mov	r12,rax
	call	session_uncount
	pop	r12
	ret

; ------------------------------------------------------------- attaching

; From h_connect (S_STATE ST_CONNECTING), ebx = session whose pool speaks
; HTTP/2: a server, a connection to it (one with room, or a new one), and
; http_connected once that connection runs HTTP/2.
h2u_connect:
	push	r12
	push	r13
	call	session_ptr
	mov	r12,rax
	mov	edi,[r12+S_POOL]
	mov	esi,NIL
	h_rec
	test	dword [r15+H_FLAGS],HX_AVOID
	jz	@f
	and	dword [r15+H_FLAGS],not HX_AVOID
	mov	esi,[r12+S_SERVER]		; a retry: another server if there is one
@@:
	call	server_pick
	cmp	eax,NIL
	je	.failed
	mov	r13d,eax
	mov	[r12+S_SERVER],eax
	inc	dword [g_sv_active+rax*4]
	or	dword [r12+S_FLAGS],SF_COUNTED or SF_UPH2
	h_rec
	and	dword [r15+H_FLAGS],not HX_REUSED
	mov	rdi,[r15+H_BUF]			; a fresh upstream state
	add	rdi,HB_U2
	xor	eax,eax
	mov	ecx,(64 + Q_DATA) / 8
	rep	stosq
	mov	rax,[r15+H_BUF]
	mov	dword [rax+HB_U2Q+Q_RWIN],H2_INIT_WIN
	mov	qword [rax+HB_U2Q+Q_CLEN],-1
	mov	edi,r13d
	call	h2u_find
	cmp	edi,NIL
	jne	.attach
	mov	edi,r13d
	call	h2u_new
	cmp	edi,NIL
	je	.no_uc
.attach:
	; edi = the UC
	mov	r13d,edi
	mov	eax,edi
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	mov	ecx,[rax+S_GEN]
	h_rec
	mov	rdx,[r15+H_BUF]
	mov	[rdx+HB_U2+U2_UC],r13d
	mov	[rdx+HB_U2+U2_UCG],ecx
	mov	edi,r13d
	call	h2_ptrs				; rdx = the UC's buffers
	inc	dword [rdx+HB_IN+W_LOAD]
	cmp	dword [rdx+HB_IN+W_READY],0
	je	.wait
	mov	dword [r12+S_STATE],ST_OPEN	; it runs: the request goes now
	pop	r13
	pop	r12
	jmp	http_connected
.wait:
	mov	eax,[rdx+HB_IN+W_N]		; until it connects
	inc	dword [rdx+HB_IN+W_N]
	mov	[rdx+HB_IN+W_ENT+rax*8],ebx
	mov	ecx,[r12+S_GEN]
	mov	[rdx+HB_IN+W_ENT+rax*8+4],ecx
	pop	r13
	pop	r12
	ret
.no_uc:
	and	dword [r12+S_FLAGS],not SF_UPH2
	call	session_uncount
.failed:
	pop	r13
	pop	r12
	jmp	http_connect_failed

; edi = server: edi = one of its UCs with room for another request, or NIL
h2u_find:
	push	rbx
	push	r12
	push	r13
	imul	r12d,edi,H2U_PER
	mov	r13d,H2U_PER
.slot:
	mov	ebx,[g_h2u+r12*4]
	test	ebx,ebx
	jz	.next
	dec	ebx
	call	session_ptr
	mov	ecx,[g_h2ug+r12*4]
	cmp	[rax+S_GEN],ecx
	jne	.stale
	test	dword [rax+S_FLAGS],SF_H2U
	jz	.stale
	mov	ecx,[rax+S_STATE]
	cmp	ecx,ST_CLOSING
	je	.next
	cmp	ecx,ST_FREE
	je	.stale
	mov	edi,ebx
	call	h2_ptrs				; rcx = its C2, rdx = its buffers
	mov	r8d,[rdx+HB_IN+W_LOAD]
	cmp	dword [rdx+HB_IN+W_READY],0
	je	.connecting
	test	dword [rcx+C2_FLAGS],C2F_PEERGONE or C2F_CLOSING
	jnz	.next
	cmp	r8d,[rcx+C2_PMAXS]
	jae	.next
	jmp	.found
.connecting:
	cmp	dword [rdx+HB_IN+W_N],H2U_WAIT_MAX
	jae	.next
	cmp	r8d,H2_MAX_OPEN
	jae	.next
.found:
	mov	edi,ebx
	jmp	.out
.stale:
	mov	dword [g_h2u+r12*4],0
.next:
	inc	r12d
	dec	r13d
	jnz	.slot
	mov	edi,NIL
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; edi = server, ebx = the session that asks (its listener and pool are
; the UC's): a new UC, connecting. edi = it, or NIL (no slot, no session).
h2u_new:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r13d,edi			; server
	imul	r12d,edi,H2U_PER		; a free slot
	mov	ecx,H2U_PER
@@:
	cmp	dword [g_h2u+r12*4],0
	je	@f
	inc	r12d
	dec	ecx
	jnz	@b
	jmp	.none
@@:
	call	session_ptr
	mov	r14,rax				; the asking session
	call	session_alloc
	cmp	eax,NIL
	je	.none
	mov	ebx,eax
	mov	ecx,[r14+S_LST]
	inc	dword [g_ls_active+rcx*4]
	inc	dword [g_active]
	call	session_ptr
	mov	dword [rax+S_STATE],ST_CONNECTING
	mov	dword [rax+S_INFL],0
	mov	dword [rax+S_FLAGS],SF_H2U
	mov	dword [rax+S_CLIENT],-1
	mov	ecx,[r14+S_LST]
	mov	[rax+S_LST],ecx
	mov	dword [rax+S_TRIES],0
	mov	dword [rax+S_SERVER],NIL
	mov	dword [rax+S_CU_BID],NIL
	mov	dword [rax+S_UC_BID],NIL
	mov	dword [rax+S_PH_KIND],0
	mov	ecx,[g_tick]
	mov	[rax+S_LAST],ecx
	mov	ecx,[r14+S_POOL]
	mov	[rax+S_POOL],ecx
	mov	ecx,[rax+S_GEN]
	lea	edx,[rbx+1]
	mov	[g_h2u+r12*4],edx
	mov	[g_h2ug+r12*4],ecx
	mov	edi,ebx
	call	idle_append
	h_rec
	mov	eax,ebx
	shl	rax,HB_SHIFT
	add	rax,[g_hbuf_base]
	mov	[r15+H_BUF],rax
	xor	ecx,ecx
	mov	[r15+H_INLEN],ecx
	mov	[r15+H_INOFF],ecx
	mov	[r15+H_FLAGS],ecx
	mov	[r15+H_UTLS],ecx
	mov	[r15+H_EPOP],ecx
	mov	[r15+H_UPKTLS],ecx
	mov	dword [r15+H_STATE],HS_CONNECT
	mov	[rax+HB_IN+W_N],ecx
	mov	[rax+HB_IN+W_LOAD],ecx
	mov	[rax+HB_IN+W_READY],ecx
	lea	edx,[r12+1]
	mov	[rax+HB_IN+W_SLOT],edx
	mov	[g_force_server],r13d		; that server, not another first
	mov	edi,ebx
	cmp	dword [g_engine],ENGINE_EPOLL
	je	.epoll
	call	session_connect
	jmp	.made
.epoll:
	call	ep_connect
.made:
	mov	edi,ebx
	jmp	.out
.none:
	mov	edi,NIL
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; http_connected for a UC (connected, through TLS when the pool has it):
; HTTP/2 starts in client mode; the requests waiting go.
h2u_ready:
	c2_regs
	mov	rdi,r13				; the state and the stream table
	xor	eax,eax
	mov	ecx,C2_ST / 8 + H2_MAXS * S2_SIZE / 8
	rep	stosq
	mov	dword [r13+C2_FLAGS],C2F_CLIENT
	mov	dword [r13+C2_PREF],H2_PREFACE_LEN	; the server sends none
	mov	dword [r13+C2_SWIN],65535
	mov	dword [r13+C2_PINIT],65535
	mov	dword [r13+C2_PMAXF],16384
	mov	dword [r13+C2_RWIN],H2_CONN_WIN
	mov	dword [r13+C2_PMAXS],100	; until its SETTINGS say otherwise
	mov	dword [r13+C2_NEXTSID],1
	mov	dword [r13+C2_BLKH],0
	mov	dword [r13+C2_BLKT],0
	lea	rdi,[r14+HB_H2HP]
	mov	esi,4096
	call	hpack_init
	c2_regs
	mov	dword [r15+H_STATE],HS_H2
	lea	rsi,[h2_preface]		; the client preface, then our SETTINGS
	mov	ecx,H2_PREFACE_LEN
	call	h2_out_raw
	lea	rsi,[h2_settings_c]
	mov	ecx,h2_settings_c.len
	call	h2_out_raw
	mov	dword [r14+HB_IN+W_READY],1
	; the waiting requests go
	push	r12
	xor	r12d,r12d
.waiter:
	c2_regs
	cmp	r12d,[r14+HB_IN+W_N]
	jae	.waited
	mov	edi,[r14+HB_IN+W_ENT+r12*8]
	mov	ecx,[r14+HB_IN+W_ENT+r12*8+4]
	inc	r12d
	mov	eax,edi
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	cmp	[rax+S_GEN],ecx
	jne	.waiter
	test	dword [rax+S_FLAGS],SF_UPH2
	jz	.waiter
	cmp	dword [rax+S_STATE],ST_CONNECTING
	jne	.waiter
	mov	dword [rax+S_STATE],ST_OPEN
	push	rbx
	mov	ebx,edi
	call	http_connected			; its head goes out as HEADERS
	pop	rbx
	jmp	.waiter
.waited:
	mov	dword [r14+HB_IN+W_N],0
	pop	r12
	jmp	h2_pump

; a UC that could not connect (or failed before HTTP/2): its waiting
; requests are told, it closes. ebx = it.
h2u_failed:
	push	r12
	push	r14
	h_rec
	mov	r14,[r15+H_BUF]
	xor	r12d,r12d
.waiter:
	cmp	r12d,[r14+HB_IN+W_N]
	jae	.told
	mov	edi,[r14+HB_IN+W_ENT+r12*8]
	mov	ecx,[r14+HB_IN+W_ENT+r12*8+4]
	inc	r12d
	mov	eax,edi
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	cmp	[rax+S_GEN],ecx
	jne	.waiter
	test	dword [rax+S_FLAGS],SF_UPH2
	jz	.waiter
	cmp	dword [rax+S_STATE],ST_CONNECTING
	jne	.waiter
	and	dword [rax+S_FLAGS],not SF_UPH2
	push	rbx
	push	r14
	mov	ebx,edi
	call	h2u_uncount
	call	http_connect_failed		; (502, or another try)
	pop	r14
	pop	rbx
	jmp	.waiter
.told:
	mov	dword [r14+HB_IN+W_N],0
	pop	r14
	pop	r12
	mov	edi,ebx
	jmp	session_close

; ebx = a UC closing (session_close, both engines): its streams and its
; waiting requests are told, its registry slot freed. Keeps rbx, r12.
h2uc_closing:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	c2_regs
	mov	eax,[r14+HB_IN+W_SLOT]		; out of the registry
	test	eax,eax
	jz	@f
	dec	eax
	mov	ecx,ebx
	inc	ecx
	cmp	[g_h2u+rax*4],ecx
	jne	@f
	mov	dword [g_h2u+rax*4],0
@@:
	cmp	dword [r14+HB_IN+W_READY],0
	je	.waiters
	or	dword [r13+C2_FLAGS],C2F_CLOSING
	call	h2_streams_close		; (client mode: each request is told)
	jmp	.out
.waiters:
	; not connected yet: the waiting requests fail over
	mov	r12d,[r14+HB_IN+W_N]
	mov	dword [r14+HB_IN+W_N],0
	xor	ecx,ecx
.w:
	cmp	ecx,r12d
	jae	.out
	push	rcx
	mov	edi,[r14+HB_IN+W_ENT+rcx*8]
	mov	edx,[r14+HB_IN+W_ENT+rcx*8+4]
	mov	eax,edi
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	cmp	[rax+S_GEN],edx
	jne	.wnext
	test	dword [rax+S_FLAGS],SF_UPH2
	jz	.wnext
	and	dword [rax+S_FLAGS],not SF_UPH2
	push	rbx
	mov	ebx,edi
	call	h2u_uncount
	call	http_connect_failed
	pop	rbx
.wnext:
	pop	rcx
	inc	ecx
	jmp	.w
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; ebx = a requesting session leaving its UC (h_park, h_upclose, closing):
; its stream is reset unless it ended both ways, it leaves the table and
; the waiting list. Keeps rbx and r12-r15.
h2u_detach:
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_UPH2
	jz	.ret
	and	dword [rax+S_FLAGS],not SF_UPH2
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	push	rbp
	call	h2u_uncount
	mov	ebp,ebx				; the request
	u2_at	r12, ebx			; r12 = its U2 area
	mov	edi,[r12+U2_UC]
	mov	eax,edi
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	mov	ecx,[rax+S_GEN]
	cmp	ecx,[r12+U2_UCG]
	jne	.out				; its UC is gone
	cmp	dword [rax+S_STATE],ST_OPEN
	je	@f
	cmp	dword [rax+S_STATE],ST_CONNECTING
	jne	.out
@@:
	mov	ebx,edi
	c2_regs
	dec	dword [r14+HB_IN+W_LOAD]
	cmp	dword [r14+HB_IN+W_READY],0
	je	.out				; (a waiter: the list is skipped by its flag)
	test	dword [r12+U2_F],U2F_HEAD
	jz	.unwait
	mov	eax,[r12+U2_F]
	and	eax,U2F_END or U2F_REND
	cmp	eax,U2F_END or U2F_REND
	je	.untable
	test	dword [r12+U2_F],U2F_RST
	jnz	.untable
	mov	esi,[r12+U2_SID]		; it stops halfway: CANCEL
	mov	edx,H2E_CANCEL
	call	h2_out_rst
.untable:
	call	h2_untable			; ebp = the request
.unwait:
	mov	edi,ebp
	call	h2u_unwait
	or	dword [r12+U2_F],U2F_RST
	call	h2_pump
.out:
	pop	rbp
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
.ret:
	ret

; ------------------------------------------------------- the request side

; h_send on the upstream side of a requesting session: ebx, rdi, esi
h2u_send:
	u2_at	rax, ebx
	mov	[rax+U2_PP],rdi
	mov	[rax+U2_PL],esi
	or	dword [rax+U2_F],U2F_SENDING
	jmp	h2u_kick

; http_start_response of a requesting session: the request is all sent,
; END_STREAM goes if it has not (keeps the registers proxy.inc needs)
h2u_req_end:
	push	rax
	u2_at	rax, ebx
	test	dword [rax+U2_F],U2F_END
	jnz	@f
	or	dword [rax+U2_F],U2F_FINISH
	push	rcx
	push	rdx
	push	rsi
	push	rdi
	push	r8
	push	r9
	push	r10
	push	r11
	call	h2u_kick
	pop	r11
	pop	r10
	pop	r9
	pop	r8
	pop	rdi
	pop	rsi
	pop	rdx
	pop	rcx
@@:
	pop	rax
	ret

; ebx = requesting session: its UC takes what it has (the request, END_
; STREAM, credit), or it waits in the UC's list
h2u_kick:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12d,ebx
	u2_at	rdx, ebx
	mov	edi,[rdx+U2_UC]
	mov	eax,edi
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	mov	ecx,[rax+S_GEN]
	cmp	ecx,[rdx+U2_UCG]
	jne	.orphan
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.orphan
	mov	ebx,edi
	c2_regs
	mov	edi,r12d
	call	h2u_stream_out
	jnc	.pumped
	u2_at	rdx, r12d			; waiting: into the list once
	test	dword [rdx+U2_F],U2F_WAITING
	jnz	.pumped
	or	dword [rdx+U2_F],U2F_WAITING
	mov	dword [rdx+U2_BL],0
	lea	eax,[r12+1]
	mov	ecx,[r13+C2_BLKT]
	mov	[r13+C2_BLKT],eax
	test	ecx,ecx
	jz	.first
	lea	eax,[rcx-1]
	u2_at	rdx, eax
	lea	eax,[r12+1]
	mov	[rdx+U2_BL],eax
	jmp	.pumped
.first:
	mov	[r13+C2_BLKH],eax
.pumped:
	call	h2_pump
	; a body going beside its response (proxy.inc): what waited went
	; out, the next piece
	mov	ebx,r12d
	h_rec
	test	dword [r15+H_FLAGS],HX_DUPLEX
	jz	.out
	u2_at	rdx, ebx
	test	dword [rdx+U2_F],U2F_SENDING or U2F_DPUMP
	jnz	.out
	call	http_duplex_pump
	jmp	.out
.orphan:
	; no connection: a pending send fails
	mov	ebx,r12d
	u2_at	rdx, ebx
	test	dword [rdx+U2_F],U2F_SENDING
	jz	.out
	and	dword [rdx+U2_F],not U2F_SENDING
	h_rec
	test	dword [r15+H_FLAGS],HX_DUPLEX
	jnz	.out				; (the response side fails on its own)
	mov	rax,-1
	mov	edx,2
	mov	ecx,SIDE_UP
	call	hep_queue
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; client mode: the requests waiting for room or window, again
h2u_unblock:
	push	r12
	mov	r12d,[r13+C2_BLKH]
	mov	dword [r13+C2_BLKH],0
	mov	dword [r13+C2_BLKT],0
.next:
	test	r12d,r12d
	jz	.done
	dec	r12d
	u2_at	rdx, r12d
	test	dword [rdx+U2_F],U2F_WAITING
	jz	.done
	mov	ecx,[rdx+U2_BL]
	push	rcx
	and	dword [rdx+U2_F],not U2F_WAITING
	mov	eax,r12d
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	test	dword [rax+S_FLAGS],SF_UPH2
	jz	.skip
	push	rbx
	mov	ebx,r12d
	call	h2u_kick
	pop	rbx
	c2_regs
.skip:
	pop	r12
	jmp	.next
.done:
	pop	r12
	ret

; edi = requesting session: out of the UC's waiting list (c2 registers)
h2u_unwait:
	push	r12
	mov	r12d,edi
	u2_at	rdx, edi
	test	dword [rdx+U2_F],U2F_WAITING
	jz	.out
	and	dword [rdx+U2_F],not U2F_WAITING
	lea	r9d,[r12+1]
	xor	r8d,r8d
	mov	ecx,[r13+C2_BLKH]
.walk:
	test	ecx,ecx
	jz	.out
	lea	eax,[rcx-1]
	push	rcx
	u2_at	rdx, eax
	pop	rcx
	mov	r10d,[rdx+U2_BL]
	cmp	ecx,r9d
	je	.found
	mov	r8d,ecx
	mov	ecx,r10d
	jmp	.walk
.found:
	test	r8d,r8d
	jnz	@f
	mov	[r13+C2_BLKH],r10d
	jmp	.tail
@@:
	lea	eax,[r8-1]
	u2_at	rdx, eax
	mov	[rdx+U2_BL],r10d
.tail:
	cmp	[r13+C2_BLKT],r9d
	jne	.out
	mov	[r13+C2_BLKT],r8d
.out:
	pop	r12
	ret

; edi = requesting session: what it has to send, as frames on its UC (c2
; registers). CF when something waits.
h2u_stream_out:
	push	rbx
	push	rbp
	push	r12
	push	r15
	mov	ebp,edi
	u2_at	r12, edi			; r12 = its U2 area
	mov	eax,ebp
	shl	rax,H_SHIFT
	add	rax,[g_http_base]
	mov	r15,rax				; its record
	test	dword [r12+U2_F],U2F_CREDIT	; credit for the response it read
	jz	.request
	test	dword [r12+U2_F],U2F_HEAD
	jz	.request
	mov	edx,[r12+HB_U2Q-HB_U2+Q_PEND]
	mov	esi,[r12+U2_SID]
	call	h2_out_window
	jc	.wait
	mov	edx,[r12+HB_U2Q-HB_U2+Q_PEND]
	add	[r12+HB_U2Q-HB_U2+Q_RWIN],edx
	mov	dword [r12+HB_U2Q-HB_U2+Q_PEND],0
	and	dword [r12+U2_F],not U2F_CREDIT
.request:
	test	dword [r12+U2_F],U2F_SENDING
	jz	.finish
	test	dword [r12+U2_F],U2F_RST
	jnz	.failed
.chunk:
	cmp	dword [r12+U2_PL],0
	je	.sent
	test	dword [r12+U2_F],U2F_HEAD
	jz	.head
	mov	eax,[r12+U2_PL]			; DATA within the windows
	cmp	eax,[r13+C2_PMAXF]
	jbe	@f
	mov	eax,[r13+C2_PMAXF]
@@:
	cmp	eax,[r13+C2_SWIN]
	jle	@f
	mov	eax,[r13+C2_SWIN]
@@:
	cmp	eax,[r12+U2_SWIN]
	jle	@f
	mov	eax,[r12+U2_SWIN]
@@:
	mov	ebx,eax
	call	h2_room
	sub	eax,9 + H2_CTRL
	cmp	ebx,eax
	jle	@f
	mov	ebx,eax
@@:
	test	ebx,ebx
	jle	.wait
	mov	esi,ebx
	mov	dl,H2F_DATA
	xor	ecx,ecx
	mov	r8d,[r12+U2_SID]
	call	h2_frame
	mov	rsi,[r12+U2_PP]
	mov	ecx,ebx
	rep	movsb
	add	[r12+U2_PP],rbx
	sub	[r12+U2_PL],ebx
	sub	[r13+C2_SWIN],ebx
	sub	[r12+U2_SWIN],ebx
	jmp	.chunk
.head:
	test	dword [r13+C2_FLAGS],C2F_PEERGONE or C2F_CLOSING
	jnz	.failed
	mov	eax,[r13+C2_NSTR]		; room for another stream?
	cmp	eax,[r13+C2_PMAXS]
	jae	.wait
	cmp	eax,H2_MAXS - 1
	jae	.wait
	call	h2u_head_out
	jc	.wait
	jmp	.chunk
.failed:
	mov	dword [r12+U2_PL],0
	and	dword [r12+U2_F],not U2F_SENDING
	test	dword [r15+H_FLAGS],HX_DUPLEX
	jnz	.done				; (the response side fails on its own)
	push	rbx
	mov	ebx,ebp
	mov	rax,-1
	mov	edx,2
	mov	ecx,SIDE_UP
	call	hep_queue
	pop	rbx
	jmp	.done
.sent:
	and	dword [r12+U2_F],not U2F_SENDING
	test	dword [r15+H_FLAGS],HX_DUPLEX
	jnz	.finish				; no exchange waits on it
	push	rbx
	mov	ebx,ebp
	xor	eax,eax
	mov	edx,2
	mov	ecx,SIDE_UP
	call	hep_queue
	pop	rbx
.finish:
	test	dword [r12+U2_F],U2F_FINISH
	jz	.done
	test	dword [r12+U2_F],U2F_HEAD
	jz	.done				; (HEADERS will carry it)
	test	dword [r12+U2_F],U2F_RST or U2F_END
	jnz	.finished
	call	h2_room
	cmp	eax,9 + H2_RESERVE
	jb	.wait
	xor	esi,esi
	mov	dl,H2F_DATA
	mov	cl,H2_END_STREAM
	mov	r8d,[r12+U2_SID]
	call	h2_frame
	or	dword [r12+U2_F],U2F_END
.finished:
	and	dword [r12+U2_F],not U2F_FINISH
.done:
	clc
	jmp	.out
.wait:
	stc
.out:
	pop	r15
	pop	r12
	pop	rbp
	pop	rbx
	ret

; r12 = U2 area, r15 = record, ebp = the request: its pending bytes start
; with the HTTP/1.1 head proxy.inc wrote ("METHOD target HTTP/1.1\r\n"
; fields "\r\n"). HEADERS (and CONTINUATION) from it on a new stream;
; END_STREAM with them when the request has no body. CF when OUT has no
; room. c2 registers of the UC.
h2u_head_out:
	push	rbx
	mov	rsi,[r12+U2_PP]
	mov	ecx,[r12+U2_PL]
	xor	edx,edx				; the head's end
.find:
	lea	eax,[rdx+4]
	cmp	eax,ecx
	ja	.broken
	cmp	dword [rsi+rdx],0x0A0D0A0D
	je	.found
	inc	edx
	jmp	.find
.found:
	lea	ebx,[rdx+4]			; ebx = the head's length
	lea	rdi,[g_h2tmp]
	; :method (to the first space)
	xor	ecx,ecx
@@:
	cmp	ecx,ebx
	jae	.broken
	cmp	byte [rsi+rcx],' '
	je	@f
	inc	ecx
	jmp	@b
@@:
	push	rsi
	push	rcx
	mov	r8d,ecx
	mov	rcx,rsi
	lea	rsi,[.n_method]
	mov	edx,7
	call	hpack_encode
	mov	rdi,rax
	pop	rcx
	pop	rsi
	; :scheme, from the request's pool
	push	rsi
	push	rcx
	mov	eax,ebp
	shl	rax,S_SHIFT
	add	rax,[g_sess_base]
	mov	eax,[rax+S_POOL]
	imul	rax,rax,PL_SIZE
	lea	rdx,[g_pools]
	mov	r10d,[rdx+rax+PL_TLS]
	lea	rsi,[.n_scheme]
	mov	edx,7
	lea	rcx,[.v_http]
	mov	r8d,4
	test	r10d,r10d
	je	@f
	lea	rcx,[.v_https]
	mov	r8d,5
@@:
	call	hpack_encode
	mov	rdi,rax
	pop	rcx
	pop	rsi
	; :path (from after the space to the next space)
	lea	r10d,[rcx+1]
	mov	ecx,r10d
@@:
	cmp	ecx,ebx
	jae	.broken
	cmp	byte [rsi+rcx],' '
	je	@f
	inc	ecx
	jmp	@b
@@:
	push	rsi
	push	rcx
	lea	rax,[rsi+r10]
	mov	r8d,ecx
	sub	r8d,r10d
	mov	rcx,rax
	lea	rsi,[.n_path]
	mov	edx,5
	call	hpack_encode
	mov	rdi,rax
	pop	rcx
	pop	rsi
	; to the first field line
@@:
	cmp	word [rsi+rcx],0x0A0D
	je	@f
	inc	ecx
	jmp	@b
@@:
	add	ecx,2
	push	rcx
	; :authority from Host, before any regular field
	mov	edx,ecx
.host_line:
	lea	eax,[rdx+2]
	cmp	eax,ebx
	jae	.host_done
	mov	eax,[rsi+rdx]
	or	eax,0x20202020
	cmp	eax,'host'
	jne	.host_next
	cmp	byte [rsi+rdx+4],':'
	jne	.host_next
	lea	r9d,[rdx+5]
@@:
	cmp	byte [rsi+r9],' '
	jne	@f
	inc	r9d
	jmp	@b
@@:
	mov	r8d,r9d
@@:
	cmp	word [rsi+r8],0x0A0D
	je	@f
	inc	r8d
	jmp	@b
@@:
	push	rsi
	lea	rcx,[rsi+r9]
	sub	r8d,r9d
	lea	rsi,[.n_auth]
	mov	edx,10
	call	hpack_encode
	mov	rdi,rax
	pop	rsi
	jmp	.host_done
.host_next:
	cmp	word [rsi+rdx],0x0A0D
	je	@f
	inc	edx
	jmp	.host_next
@@:
	add	edx,2
	jmp	.host_line
.host_done:
	pop	rcx
	; the regular fields: lower case, connection-specific dropped
.line:
	lea	eax,[rcx+2]
	cmp	eax,ebx
	jae	.block
	mov	edx,ecx
@@:
	cmp	byte [rsi+rdx],':'
	je	@f
	cmp	byte [rsi+rdx],13
	je	.broken
	movzx	eax,byte [rsi+rdx]
	lea	r8d,[rax-'A']
	cmp	r8d,25
	ja	.lc
	or	byte [rsi+rdx],0x20
.lc:
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
	mov	r9d,edx				; the value's start
@@:
	cmp	word [rsi+rdx],0x0A0D
	je	@f
	inc	edx
	jmp	@b
@@:
	push	rsi
	push	rdx
	push	rcx
	push	r8
	push	r9
	push	rdi
	lea	rdi,[rsi+rcx]
	mov	esi,r8d
	sub	esi,ecx
	lea	rdx,[h2u_drop_names]
	call	h2_name_in
	pop	rdi
	pop	r9
	pop	r8
	pop	rcx
	pop	rdx
	pop	rsi
	jnc	.next_line
	lea	rax,[rdi+1024]
	lea	r10,[g_h2tmp+20480]
	cmp	rax,r10
	ja	.broken
	mov	eax,r8d				; host: sent as :authority already
	sub	eax,ecx
	cmp	eax,4
	jne	@f
	cmp	dword [rsi+rcx],'host'
	je	.next_line
@@:
	push	rsi
	push	rdx
	lea	r10,[rsi+rcx]			; name
	lea	r11,[rsi+r9]			; value
	mov	eax,edx
	sub	eax,r9d
	mov	edx,r8d
	sub	edx,ecx
	mov	r8d,eax
	mov	rsi,r10
	mov	rcx,r11
	call	hpack_encode
	mov	rdi,rax
	pop	rdx
	pop	rsi
.next_line:
	lea	ecx,[rdx+2]
	jmp	.line
.block:
	push	rsi				; te: trailers (gRPC servers ask for it)
	lea	rsi,[.n_te]
	mov	edx,2
	lea	rcx,[.v_trailers]
	mov	r8d,8
	call	hpack_encode
	mov	rdi,rax
	pop	rsi
	lea	rax,[g_h2tmp]
	sub	rdi,rax
	mov	[g_h2u_blen],edi		; the block's length
	mov	eax,edi
	xor	edx,edx
	div	dword [r13+C2_PMAXF]
	inc	eax
	imul	eax,eax,9
	add	eax,[g_h2u_blen]
	add	eax,H2_CTRL
	push	rax
	call	h2_room
	pop	rdx
	cmp	eax,edx
	jb	.full
	; a new stream
	mov	eax,[r13+C2_NEXTSID]
	add	dword [r13+C2_NEXTSID],2
	mov	[r12+U2_SID],eax
	mov	ecx,[r13+C2_PINIT]
	mov	[r12+U2_SWIN],ecx
	mov	r8d,eax				; its home slot
	shr	r8d,1
	and	r8d,H2_MAXS - 1
	shl	r8d,4
	lea	r8,[r13+C2_ST+r8]
	cmp	dword [r8+S2_SID],0
	je	.slot
	lea	r8,[r13+C2_ST]
@@:
	cmp	dword [r8+S2_SID],0
	je	.slot
	add	r8,S2_SIZE
	jmp	@b
.slot:
	mov	[r8+S2_SID],eax
	mov	[r8+S2_SESS],ebp
	push	rbx
	mov	ebx,ebp
	call	session_ptr
	pop	rbx
	mov	ecx,[rax+S_GEN]
	mov	[r8+S2_GEN],ecx
	inc	dword [r13+C2_NSTR]
	; END_STREAM with the head when the request has no body
	xor	r10d,r10d
	cmp	dword [r15+H_BODY],BK_NONE
	jne	@f
	cmp	ebx,[r12+U2_PL]
	jne	@f
	mov	r10d,H2_END_STREAM
	or	dword [r12+U2_F],U2F_END
@@:
	lea	r11,[g_h2tmp]
	mov	r9b,H2F_HEADERS
.frame:
	mov	esi,[g_h2u_blen]
	cmp	esi,[r13+C2_PMAXF]
	jbe	@f
	mov	esi,[r13+C2_PMAXF]
@@:
	mov	ecx,r10d
	cmp	r9b,H2F_HEADERS
	je	@f
	xor	ecx,ecx				; END_STREAM only on HEADERS
@@:
	cmp	esi,[g_h2u_blen]
	jne	@f
	or	cl,H2_END_HEADERS
@@:
	push	rsi
	push	r11
	push	r9
	push	r10
	mov	dl,r9b
	mov	r8d,[r12+U2_SID]
	call	h2_frame
	pop	r10
	pop	r9
	pop	r11
	pop	rcx
	mov	rsi,r11
	add	r11,rcx
	sub	[g_h2u_blen],ecx
	rep	movsb
	mov	r9b,H2F_CONT
	cmp	dword [g_h2u_blen],0
	jne	.frame
	or	dword [r12+U2_F],U2F_HEAD
	add	[r12+U2_PP],rbx
	sub	[r12+U2_PL],ebx
	clc
	jmp	.out
.broken:
	; not a head proxy.inc wrote (cannot happen): the request fails
	or	dword [r12+U2_F],U2F_RST
	mov	dword [r12+U2_PL],0
	clc
	jmp	.out
.full:
	stc
.out:
	pop	rbx
	ret
.n_method db ':method'
.n_scheme db ':scheme'
.n_path	db ':path'
.n_auth	db ':authority'
.n_te	db 'te'
.v_trailers db 'trailers'
.v_http	db 'http'
.v_https db 'https'

; fields not sent to an HTTP/2 backend (te goes as "te: trailers" alone)
h2u_drop_names	db 10,'connection',10,'keep-alive',16,'proxy-connection',17,'transfer-encoding'
		db 7,'upgrade',2,'te',0

; ------------------------------------------------------ the response side

; h_recv on the upstream side of a requesting session: ebx, rdi, esi
h2u_recv:
	push	r14
	u2_at	r14, ebx
	add	r14,HB_U2Q - HB_U2		; r14 = its response queue
	mov	ecx,[r14+Q_LEN]
	sub	ecx,[r14+Q_OFF]
	jnz	.take
	u2_at	rax, ebx
	test	dword [rax+U2_F],U2F_RST or U2F_REND
	jnz	.end
	mov	[r14+Q_DST],rdi
	mov	[r14+Q_ROOM],esi
	mov	dword [r14+Q_WAIT],1
	pop	r14
	ret
.take:
	call	h2u_take
	pop	r14
	ret
.end:
	; drained: an end (a complete response) or an error (a failed stream)
	xor	ecx,ecx
	test	dword [rax+U2_F],U2F_RST
	jz	@f
	test	dword [rax+U2_F],U2F_REND
	jnz	@f
	mov	rcx,-1
@@:
	mov	rax,rcx
	h_rec
	mov	edx,1
	mov	ecx,SIDE_UP
	pop	r14
	jmp	hep_queue

; ebx = request, r14 = its response queue, rdi = buffer, esi = room
h2u_take:
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
	cmp	dword [r14+Q_PEND],0
	je	.deliver
	u2_at	rax, ebx
	test	dword [rax+U2_F],U2F_REND or U2F_RST
	jnz	.deliver			; no credit for a finished stream
	or	dword [rax+U2_F],U2F_CREDIT
	call	h2u_kick
.deliver:
	pop	rax
	h_rec
	mov	edx,1
	mov	ecx,SIDE_UP
	jmp	hep_queue

; ebx = request, r14 = queue: a receive parked there gets what it holds
; (or its end)
h2u_serve:
	cmp	dword [r14+Q_WAIT],0
	je	.out
	mov	dword [r14+Q_WAIT],0
	mov	rdi,[r14+Q_DST]
	mov	esi,[r14+Q_ROOM]
	mov	ecx,[r14+Q_LEN]
	sub	ecx,[r14+Q_OFF]
	jnz	h2u_take
	push	r14
	jmp	h2u_recv.end			; (pops r14)
.out:
	ret

; edi = requesting session: its stream failed (reset by the server, its
; connection gone): what it waits for ends in an error. c2 registers.
h2u_fail:
	push	rbx
	push	r14
	mov	ebx,edi
	u2_at	r14, ebx
	or	dword [r14+U2_F],U2F_RST
	test	dword [r14+U2_F],U2F_SENDING
	jz	@f
	and	dword [r14+U2_F],not U2F_SENDING
	push	r15
	h_rec
	mov	rax,-1
	mov	edx,2
	mov	ecx,SIDE_UP
	call	hep_queue
	pop	r15
@@:
	add	r14,HB_U2Q - HB_U2
	push	r15
	call	h2u_serve
	pop	r15
	pop	r14
	pop	rbx
	ret

; client mode: a complete header block for stream eax (decoded fields at
; HB_H2FLD, ecx of them; C2_HBEND = END_STREAM). The response head, or
; its trailers, written into the request's queue as HTTP/1.1.
h2u_block_done:
	push	rbx
	push	rbp
	push	r12
	push	r15
	mov	ebp,ecx				; how many fields
	mov	r12d,eax			; the stream
	call	h2_find
	cmp	edi,NIL
	je	.out				; reset or gone: decoded, dropped
	mov	ebx,edi
	call	session_ptr
	mov	ecx,[rax+S_GEN]
	cmp	ecx,[r8+S2_GEN]
	jne	.stale
	u2_at	r15, ebx			; r15 = its U2 area
	test	dword [r15+U2_F],U2F_RST
	jnz	.out
	lea	rdi,[r15+HB_U2Q-HB_U2+Q_DATA]	; where the bytes go
	push	rdi
	call	h2q_compact_u
	pop	rdi
	mov	eax,[r15+HB_U2Q-HB_U2+Q_LEN]
	add	rdi,rax
	lea	r11,[r15+HB_U2Q-HB_U2+Q_DATA+H_UP_CAP-16]	; a head must fit the proxy's buffer
	test	dword [r15+U2_F],U2F_RHEAD
	jnz	.trailers
	; :status
	call	.status				; eax = status, CF when missing
	jc	.malformed
	mov	r10d,eax
	cmp	eax,200
	jae	.final
	cmp	eax,101
	je	.malformed
	cmp	dword [r13+C2_HBEND],0
	jne	.malformed			; an interim head cannot end the stream
.final:
	push	r10
	lea	rsi,[.h11]
	mov	ecx,9
	call	.put
	pop	rax
	push	rax
	call	fmt_u64
	mov	dword [rdi],0x0A0D20		; " \r\n"
	add	rdi,3
	xor	r9d,r9d				; content-length seen
	call	.fields
	pop	r10
	jc	.malformed
	cmp	r10d,200
	jb	.interim
	or	dword [r15+U2_F],U2F_RHEAD
	cmp	dword [r13+C2_HBEND],0
	je	.body
	or	dword [r15+U2_F],U2F_REND	; no body
	test	r9d,r9d
	jnz	.end_head
	cmp	r10d,204
	je	.end_head
	cmp	r10d,304
	je	.end_head
	lea	rsi,[.clen0]
	mov	ecx,.clen0.len
	call	.put
	jmp	.end_head
.body:
	test	r9d,r9d
	jnz	.end_head			; a content-length: the body as it is
	cmp	r10d,204
	je	.end_head
	cmp	r10d,304
	je	.end_head
	or	dword [r15+U2_F],U2F_RCHUNK
	lea	rsi,[.chunked]
	mov	ecx,.chunked.len
	call	.put
	jmp	.end_head
.interim:
.end_head:
	mov	word [rdi],0x0A0D
	add	rdi,2
	cmp	rdi,r11
	ja	.malformed			; larger than the proxy takes
	jmp	.queued
.trailers:
	cmp	dword [r13+C2_HBEND],0
	je	.malformed			; trailers end the stream
	or	dword [r15+U2_F],U2F_REND
	test	dword [r15+U2_F],U2F_RCHUNK
	jz	.serve				; a content-length body: no place for them
	mov	dword [rdi],0x000A0D30		; "0\r\n", the fields, "\r\n"
	add	rdi,3
	lea	r11,[rdi+CK_TRAIL_MAX-16]
	xor	r9d,r9d
	call	.fields
	jc	.malformed
	mov	word [rdi],0x0A0D
	add	rdi,2
	cmp	rdi,r11
	ja	.malformed
.queued:
	lea	rax,[r15+HB_U2Q-HB_U2+Q_DATA]
	sub	rdi,rax
	mov	[r15+HB_U2Q-HB_U2+Q_LEN],edi
.serve:
	push	r14
	lea	r14,[r15+HB_U2Q-HB_U2]
	push	r13
	call	h2u_serve
	pop	r13
	pop	r14
	jmp	.out
.malformed:
	mov	esi,r12d
	mov	edx,H2E_PROTOCOL
	call	h2_out_rst
	mov	edi,ebx
	push	rbp
	mov	ebp,ebx
	call	h2_untable
	pop	rbp
	mov	edi,ebx
	call	h2u_fail
	jmp	.out
.stale:
	push	rbp
	mov	ebp,[r8+S2_SESS]
	mov	dword [r8+S2_SID],0
	dec	dword [r13+C2_NSTR]
	pop	rbp
.out:
	pop	r15
	pop	r12
	pop	rbp
	pop	rbx
	ret
; eax = :status of the decoded fields, CF when there is none
.status:
	xor	ecx,ecx
	lea	r8,[r14+HB_H2FLD]
.st_next:
	cmp	ecx,ebp
	jae	.st_none
	cmp	dword [r8+HP_NLEN],7
	jne	.st_skip
	mov	rax,[r8+HP_NAME]
	cmp	dword [rax],':sta'
	jne	.st_skip
	cmp	dword [r8+HP_VLEN],3
	jne	.st_none
	mov	rsi,[r8+HP_VALUE]
	xor	eax,eax
	mov	edx,3
@@:
	movzx	r9d,byte [rsi]
	sub	r9d,'0'
	cmp	r9d,9
	ja	.st_none
	imul	eax,eax,10
	add	eax,r9d
	inc	rsi
	dec	edx
	jnz	@b
	clc
	ret
.st_skip:
	add	r8,HP_SIZE
	inc	ecx
	jmp	.st_next
.st_none:
	stc
	ret
; the regular fields as "name: value\r\n" at rdi (bounded by r11): names
; must be lower case, no value carries CR, LF or NUL (no smuggling through
; the HTTP/1.1 the proxy reads). r9d = 1 when a content-length was seen.
; CF when malformed.
.fields:
	xor	ecx,ecx
	lea	r8,[r14+HB_H2FLD]
.f_next:
	cmp	ecx,ebp
	jae	.f_done
	push	rcx
	mov	rsi,[r8+HP_NAME]
	mov	edx,[r8+HP_NLEN]
	test	edx,edx
	jz	.f_bad
	cmp	byte [rsi],':'
	je	.f_skip				; pseudo-fields
	xor	eax,eax
@@:
	movzx	r10d,byte [rsi+rax]
	cmp	r10b,'A'
	jb	@f
	cmp	r10b,'Z'
	jbe	.f_bad
@@:
	cmp	r10b,' '
	jbe	.f_bad
	cmp	r10b,':'
	je	.f_bad
	inc	eax
	cmp	eax,edx
	jb	@b
	mov	r10,[r8+HP_VALUE]
	mov	eax,[r8+HP_VLEN]
@@:
	test	eax,eax
	jz	@f
	dec	eax
	movzx	edx,byte [r10+rax]
	cmp	dl,13
	je	.f_bad
	cmp	dl,10
	je	.f_bad
	test	dl,dl
	jz	.f_bad
	jmp	@b
@@:
	; connection-specific fields from an HTTP/2 server: dropped
	push	rdi
	push	r8
	push	r9
	push	r11
	mov	rdi,[r8+HP_NAME]
	mov	esi,[r8+HP_NLEN]
	lea	rdx,[h2u_drop_names]
	call	h2_name_in
	pop	r11
	pop	r9
	pop	r8
	pop	rdi
	jnc	.f_skip
	cmp	dword [r8+HP_NLEN],14
	jne	@f
	mov	rax,[r8+HP_NAME]
	mov	rdx,'content-'
	cmp	[rax],rdx
	jne	@f
	mov	r9d,1
@@:
	mov	rsi,[r8+HP_NAME]
	mov	ecx,[r8+HP_NLEN]
	call	.put
	mov	word [rdi],0x203A
	add	rdi,2
	mov	rsi,[r8+HP_VALUE]
	mov	ecx,[r8+HP_VLEN]
	call	.put
	mov	word [rdi],0x0A0D
	add	rdi,2
.f_skip:
	add	r8,HP_SIZE
	pop	rcx
	inc	ecx
	jmp	.f_next
.f_bad:
	pop	rcx
	stc
	ret
.f_done:
	clc
	ret
; rsi/rcx appended at rdi, stopping at r11 (the caller checks rdi > r11)
.put:
	mov	rax,r11
	sub	rax,rdi
	jbe	.put_none
	cmp	rcx,rax
	jbe	@f
	mov	rcx,rax
	inc	rcx
@@:
	rep	movsb
	ret
.put_none:
	inc	rdi
	ret
.h11	db 'HTTP/1.1 '
.clen0	db 'content-length: 0',13,10
.clen0.len = $ - .clen0
.chunked db 'transfer-encoding: chunked',13,10
.chunked.len = $ - .chunked

; r15 = U2 area: its queue's read part leaves the front
h2q_compact_u:
	mov	eax,[r15+HB_U2Q-HB_U2+Q_OFF]
	test	eax,eax
	jz	.out
	mov	ecx,[r15+HB_U2Q-HB_U2+Q_LEN]
	sub	ecx,eax
	mov	[r15+HB_U2Q-HB_U2+Q_LEN],ecx
	mov	dword [r15+HB_U2Q-HB_U2+Q_OFF],0
	lea	rdi,[r15+HB_U2Q-HB_U2+Q_DATA]
	lea	rsi,[rdi+rax]
	rep	movsb
.out:
	ret

; client mode DATA: edi = request, eax = stream, r12 = content, esi = its
; length, edx = the frame's length, ecx = flags (c2 registers)
h2u_data:
	push	rbx
	push	rbp
	push	r12
	push	r14
	push	r15
	mov	ebp,eax
	mov	ebx,edi
	u2_at	r15, ebx
	lea	r14,[r15+HB_U2Q-HB_U2]
	test	dword [r15+U2_F],U2F_RST
	jnz	.done
	test	dword [r15+U2_F],U2F_RHEAD
	jz	.malformed			; DATA before the response head
	test	dword [r15+U2_F],U2F_REND
	jnz	.closed
	sub	[r14+Q_RWIN],edx
	js	.flow
	sub	edx,esi
	add	[r14+Q_PEND],edx		; padding: credited with the rest
	push	rcx
	push	rsi
	call	h2q_compact_u			; (its copy takes rsi, rdi, rcx)
	pop	rsi
	pop	rcx
	mov	eax,[r14+Q_LEN]
	lea	eax,[rax+rsi+32]
	cmp	eax,Q_CAP
	ja	.flow
	add	[r14+Q_PEND],esi
	test	esi,esi
	jz	.end
	test	dword [r15+U2_F],U2F_RCHUNK
	jz	.raw
	push	rcx
	push	rsi
	mov	eax,[r14+Q_LEN]
	lea	rdi,[r14+Q_DATA+rax]
	mov	eax,esi
	call	fmt_hex32
	mov	word [rdi],0x0A0D
	add	rdi,2
	lea	rax,[r14+Q_DATA]
	sub	rdi,rax
	mov	[r14+Q_LEN],edi
	pop	rsi
	pop	rcx
.raw:
	mov	eax,[r14+Q_LEN]
	lea	rdi,[r14+Q_DATA+rax]
	add	[r14+Q_LEN],esi
	push	rcx
	mov	rcx,rsi
	mov	rsi,r12
	rep	movsb
	pop	rcx
	test	dword [r15+U2_F],U2F_RCHUNK
	jz	.end
	mov	word [rdi],0x0A0D
	add	dword [r14+Q_LEN],2
.end:
	test	ecx,H2_END_STREAM
	jz	.serve
	or	dword [r15+U2_F],U2F_REND
	test	dword [r15+U2_F],U2F_RCHUNK
	jz	.serve
	mov	eax,[r14+Q_LEN]			; the last chunk
	mov	dword [r14+Q_DATA+rax],0x0D0A0D30
	mov	byte [r14+Q_DATA+rax+4],10
	add	dword [r14+Q_LEN],5
.serve:
	call	h2u_serve
.done:
	pop	r15
	pop	r14
	pop	r12
	pop	rbp
	pop	rbx
	ret
.closed:
	mov	edx,H2E_CLOSED
	jmp	.reset
.flow:
	mov	edx,H2E_FLOW
	jmp	.reset
.malformed:
	mov	edx,H2E_PROTOCOL
.reset:
	mov	esi,ebp
	call	h2_out_rst
	push	rbp
	mov	ebp,ebx
	call	h2_untable
	pop	rbp
	mov	edi,ebx
	call	h2u_fail
	jmp	.done
