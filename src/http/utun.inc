; An upgraded exchange (WebSocket, any 101) whose client side is user-space
; TLS (H_UTLS): after the 101 the relay (l4/tcp.inc, l4/tcp_epoll.inc)
; carries it, as it carries every tunnel, but the client's bytes are records.
; These turn them into plaintext for the backend, and the backend's bytes
; into records for the client, on the relay's own buffers: the client's
; ciphertext gathers in HB_RXC (where the HTTP exchange's left off, with
; what it had opened and not yet handed over: H_PTLEN), and an upstream read
; takes at most what one record holds, so it is sealed where it lies.
;
; Without this the relay passed ciphertext to the backend, which closed:
; every wss:// through an https listener (records sealed here, the default)
; failed at its first frame.

UT_SEAL_ROOM	:= BUF_SIZE - 22		; an upstream read: one record, sealed in place
assert UT_SEAL_ROOM <= TLS_RECORD_MAX

bss
	g_utun		rb 1 shl 20		; a session's tunnel has a user-space TLS client
end bss

; ebx = session, rsi = ciphertext from the client, ecx = how many: gathered.
; CF when they do not fit (the relay reads no more than there is room for).
; Keeps rbx, rbp, r12-r15.
ut_in:
	push	r15
	h_rec
	mov	eax,[r15+H_RXC]
	lea	edx,[rax+rcx]
	cmp	edx,UTLS_RX_CAP
	ja	.full
	mov	[r15+H_RXC],edx
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_RXC+rax]
	rep	movsb
	pop	r15
	clc
	ret
.full:
	pop	r15
	stc
	ret

; ebx = session: room for the client's next read (what HB_RXC can still take).
; eax = bytes. Keeps all but rax.
ut_room:
	push	r15
	h_rec
	mov	eax,UTLS_RX_CAP
	sub	eax,[r15+H_RXC]
	pop	r15
	ret

; ebx = session, rdi = where plaintext goes, esi = room: the records gathered,
; opened and handed over while there is room. eax = bytes written (0: more
; ciphertext is needed), -1 when a record is forged or not application data
; (the client is cut off), -2 at an alert (close_notify: the client's end).
; Keeps rbx, rbp, r12-r15.
ut_out:
	push	r12
	push	r13
	push	r14
	push	r15
	h_rec
	mov	r12,rdi
	mov	r13d,esi
	xor	r14d,r14d			; written
.step:
	cmp	r14d,r13d
	jae	.done
	mov	ecx,[r15+H_PTLEN]
	test	ecx,ecx
	jnz	.give
	mov	edx,[r15+H_RXC]
	test	edx,edx
	jz	.done
	mov	rdi,[r15+H_BUF]
	lea	rsi,[rdi+HB_RXC]
	add	rdi,HB_TS
	call	tls_open
	h_rec
	cmp	eax,TH_MORE
	je	.done
	cmp	eax,TH_FAIL
	je	.broken
	cmp	r8d,23				; application_data
	jne	.control
	mov	rax,[r15+H_BUF]
	lea	rax,[rax+HB_RXC]
	sub	rsi,rax
	mov	[r15+H_PTOFF],esi
	mov	[r15+H_PTLEN],ecx
	mov	[r15+H_PTEND],edx
	test	ecx,ecx
	jnz	.give
	call	.drop				; an empty record
	jmp	.step
.give:
	mov	eax,r13d
	sub	eax,r14d
	cmp	ecx,eax
	jbe	@f
	mov	ecx,eax
@@:
	lea	rdi,[r12+r14]
	mov	rsi,[r15+H_BUF]
	mov	eax,[r15+H_PTOFF]
	lea	rsi,[rsi+HB_RXC+rax]
	add	[r15+H_PTOFF],ecx
	sub	[r15+H_PTLEN],ecx
	add	r14d,ecx
	rep	movsb
	cmp	dword [r15+H_PTLEN],0
	jne	.step
	call	.drop
	jmp	.step
.control:
	cmp	r8d,21				; an alert: what came before it goes first,
	jne	.broken				; it is the end (left in HB_RXC: said next)
	test	r14d,r14d
	jnz	.done
	mov	eax,-2
	jmp	.out
.broken:
	mov	eax,-1
	jmp	.out
.done:
	mov	eax,r14d
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	ret
; the record handed over leaves HB_RXC
.drop:
	mov	edx,[r15+H_PTEND]
	mov	ecx,[r15+H_RXC]
	sub	ecx,edx
	mov	[r15+H_RXC],ecx
	mov	rdi,[r15+H_BUF]
	add	rdi,HB_RXC
	lea	rsi,[rdi+rdx]
	rep	movsb
	mov	dword [r15+H_PTLEN],0
	ret

; ebx = session, rdi = a relay buffer holding ecx bytes from the backend
; (at most UT_SEAL_ROOM): sealed in place into one record. eax = its length.
; Keeps rbx, rbp, r12-r15.
ut_seal:
	push	r12
	push	r13
	push	r15
	mov	r12,rdi
	mov	r13d,ecx
	lea	rsi,[rdi+rcx-1]			; the plaintext 5 bytes on, past the
	lea	rdi,[rdi+rcx+4]			; header (copied from its end)
	std
	rep	movsb
	cld
	h_rec
	mov	rdi,[r15+H_BUF]
	add	rdi,HB_TS
	mov	rsi,r12
	mov	edx,r13d
	mov	ecx,23				; application_data
	call	tls_seal			; eax = the record's length
	pop	r15
	pop	r13
	pop	r12
	ret
