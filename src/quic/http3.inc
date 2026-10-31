; HTTP/3 (RFC 9114) and its streams on QUIC connections (server.inc).
; (step 1: the handshake only; streams come next)

qc_established:
	ret

; edi = the packet frame (QP_*), rsi past the frame type in rax, rdx = end:
; rsi past the frame, CF on an error (QC_ERR set)
qc_app_frame:
	mov	qword [r15+QC_ERR],0x0A
	stc
	ret

; eax = 1 when the streams have something to send
qc_app_pending:
	xor	eax,eax
	ret

; rdi = where, rsi = the limit: stream frames; rdi past them, eax = 1 when any
qc_app_write:
	xor	eax,eax
	ret

; rdi = the sent packet's record, rsi = its number
qc_app_sent:
	ret

; rdi = a lost packet's record
qc_app_lost:
	ret

qc_streams_close:
	ret
