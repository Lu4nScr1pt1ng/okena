; A large response body by the L4 relay. A `Content-Length` body of
; HC_MIN or more that nothing in between needs to see (HTTP/1.1, the client
; in the clear or on kTLS, not compressed, not cached, not re-framed, not a
; copy, a stream or gRPC-Web) goes from the backend to the client as `tcp`
; bytes go: large buffers, a receive at a time capped at what is left of
; the body. Through the session's own 16 KiB, each step a receive and a send
; to complete before the next: 64 KiB bodies through two cores at 18.7
; Gbit/s, HAProxy's 19.8. When the count reaches 0 and the last send is
; done, the exchange ends as always (http_resp_pump: the access log, the
; upstream back to its pool, the next request).
;
; g_cnt holds what is left of the body for a session, plus 1 (0: not
; counted, 1: all of it relayed); the
; relay's receive takes no more than that, so the next response on the
; upstream connection is never read here.
;
; On epoll the body goes backend -> pipe -> client by splice (a pipe of
; bulk.inc, H_EPOP 4): as much as the sockets take, waiting on the side that
; said EAGAIN (edge-triggered, so it is always tried before it waits), a
; MiB a turn of the loop at most. Before, a 16 KiB receive and a send, each
; a delivery through the ready queue: 1 MB bodies 20 Gbit/s on two cores.

HC_MIN		:= 16384

bss
	align 8
	g_cnt		rq 1 shl 20
end bss

; ebx = session, r15 = its exchange, in http_resp_pump with nothing left in
; UP. CF: not for this one (read as always).
http_counted_try:
	cmp	dword [r15+H_RBODY],BK_LENGTH
	jne	.no
	cmp	qword [r15+H_RREMAIN],HC_MIN
	jb	.no
	cmp	dword [r15+H_UTLS],0
	jne	.no
	test	dword [r15+H_FLAGS],HX_CHUNKOUT or HX_TEE or HX_MIRROR or HX_HEDGE or HX_HEDGEW \
		or HX_HWON or HX_HEAD or HX_H2TUN or HX_DUPLEX
	jnz	.no
	mov	rax,[r15+H_BUF]
	cmp	byte [rax+HB_GWEB],0
	jne	.no
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_H2S or SF_H3S or SF_MIR or SF_UPH2 or SF_ZIP or SF_CFILL \
		or SF_FILE or SF_CACHED or SF_IDEMS or SF_IDEMF or SF_SLICE or SF_HEDGE or SF_FWD \
		or SF_CREF or SF_H2C or SF_QC or SF_TUNNEL
	jnz	.no
	call	fcgi_active
	test	eax,eax
	jnz	.no
	cmp	dword [g_engine],ENGINE_EPOLL
	je	hep_counted_start
	mov	rcx,[r15+H_RREMAIN]
	inc	rcx				; (+ 1: 1 is all of it relayed)
	mov	[g_cnt+rbx*8],rcx
	or	byte [g_sbig+rbx],SX_BIG_U	; (large buffers from the first)
	push	r13
	push	r14
	call	session_ptr
	mov	r13,rax
	call	bulk_want			; and reads in the loop once it can
	pop	r14
	pop	r13
	mov	dword [r15+H_STATE],HS_RESP_READ
	test	byte [g_sbig+rbx],SX_FDREQ	; the descriptors asked for: the loop
	jnz	@f				; starts when they come (bulk_fd_handler),
	mov	edi,ebx				; no first piece copied through the ring
	call	post_recv_u
@@:
	clc
	ret
.no:
	stc
	ret

; The relay sent the body's last bytes (ebx = session): back to the
; exchange, which ends.
http_counted_done:
	h_rec
	mov	qword [r15+H_RREMAIN],0
	mov	dword [r15+H_UPLEN],0
	mov	dword [r15+H_UPOFF],0
	mov	dword [r15+H_STATE],HS_RESP_SEND
	jmp	http_resp_pump

; ------------------------------------------------------------------ epoll

bss
	align 4
	g_hc_pipe	rd 1 shl 20	; the pipe's index + 1 (0: none)
	g_hc_pend	rd 1 shl 20	; bytes in it, not yet to the client
end bss

; http_counted_try on epoll (ebx, r15): CF when there is no pipe for it.
hep_counted_start:
	cmp	dword [r15+H_UPKTLS],0
	jne	.no				; (kTLS from the backend: read as always)
	cmp	dword [g_bkp_off],0
	jne	.no
	mov	ecx,[g_bkp_nfree]
	test	ecx,ecx
	jz	.no
	dec	ecx
	mov	[g_bkp_nfree],ecx
	mov	eax,[g_bkp_free+rcx*4]
	inc	eax
	mov	[g_hc_pipe+rbx*4],eax
	mov	dword [g_hc_pend+rbx*4],0
	mov	dword [r15+H_STATE],HS_RESP_SEND
	call	hep_counted_pump
	clc
	ret
.no:
	stc
	ret

; The pipe back to the free ones, emptied (ebx): at the end, on a failure, or
; with the session (ep_close). Keeps rbx, r12-r15.
hep_counted_release:
	mov	edi,[g_hc_pipe+rbx*4]
	test	edi,edi
	jz	.out
	mov	dword [g_hc_pipe+rbx*4],0
	dec	edi
	mov	esi,[g_hc_pend+rbx*4]
	mov	dword [g_hc_pend+rbx*4],0
	jmp	bulk_pipe_put
.out:
	ret

; Move the body on (ebx, r15): until a socket says EAGAIN (wait for it), the
; body is all out (delivered: http_counted_done), or the turn's MiB is spent
; (delivered: on again next turn).
hep_counted_pump:
	push	r12
	mov	r12d,ZC_EP_MAX
.again:
	mov	ecx,[g_hc_pend+rbx*4]
	test	ecx,ecx
	jz	.read
	xor	ecx,ecx				; pipe -> client
	call	hep_fd
	mov	edx,eax
	mov	eax,[g_hc_pipe+rbx*4]
	mov	edi,[g_bkp_fd+rax*8-8]		; (index + 1) the read end
	xor	esi,esi
	xor	r10d,r10d
	mov	r8d,[g_hc_pend+rbx*4]
	mov	r9d,SPLICE_F_MOVE or SPLICE_F_NONBLOCK
	mov	eax,SYS_splice
	syscall
	cmp	rax,-EAGAIN
	je	.wait_client
	cmp	rax,-EINTR
	je	.again
	test	rax,rax
	jle	.failed
	sub	[g_hc_pend+rbx*4],eax
	add	[r15+H_XBYTES],rax
	sub	r12,rax
	jmp	.again
.read:
	cmp	qword [r15+H_RREMAIN],0
	je	.done
	test	r12,r12
	jle	.turn
	mov	ecx,1				; backend -> pipe, no more than the body
	call	hep_fd
	mov	edi,eax
	mov	eax,[g_hc_pipe+rbx*4]
	mov	edx,[g_bkp_fd+rax*8-4]		; the write end
	xor	esi,esi
	xor	r10d,r10d
	mov	r8,[r15+H_RREMAIN]
	cmp	r8,BK_PSZ
	jbe	@f
	mov	r8d,BK_PSZ
@@:
	mov	r9d,SPLICE_F_MOVE or SPLICE_F_NONBLOCK
	mov	eax,SYS_splice
	syscall
	cmp	rax,-EAGAIN
	je	.wait_up
	cmp	rax,-EINTR
	je	.read
	test	rax,rax
	jle	.failed				; (0: the backend ended before the body)
	sub	[r15+H_RREMAIN],rax
	add	[g_hc_pend+rbx*4],eax
	jmp	.again
.wait_client:
	xor	ecx,ecx
	jmp	.wait
.wait_up:
	mov	ecx,1
.wait:
	mov	dword [r15+H_EPOP],4		; (hep_event: on when that side moves)
	mov	[r15+H_EPSIDE],ecx
	pop	r12
	ret
.turn:
	mov	dword [g_hq_later],1		; the rest next turn
	xor	eax,eax
	jmp	.queue
.done:
	call	hep_counted_release
	mov	eax,1
.queue:
	mov	dword [r15+H_EPOP],0
	pop	r12
	mov	edx,5
	xor	ecx,ecx
	jmp	hep_queue
.failed:
	call	hep_counted_release
	mov	dword [r15+H_EPOP],0
	pop	r12
	mov	rax,-1
	mov	edx,2				; as a failed send: the exchange ends
	xor	ecx,ecx
	jmp	hep_queue
