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

HC_MIN		:= 16384

bss
	align 8
	g_cnt		rq 1 shl 20
end bss

; ebx = session, r15 = its exchange, in http_resp_pump with nothing left in
; UP. CF: not for this one (read as always).
http_counted_try:
	cmp	dword [g_engine],ENGINE_EPOLL
	je	.no
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
	mov	edi,ebx
	call	post_recv_u
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
