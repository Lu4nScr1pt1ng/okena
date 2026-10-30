; Test harness for the TLS 1.3 handshake (not part of okena): a blocking
; echo server on 127.0.0.1, one connection at a time, over the code in
; src/tls/handshake.inc.
;
; stdin: mode byte ('U' records sealed here, 'K' kernel TLS), ALPN byte
; ('H' answers http/1.1, '-' ignores ALPN), the private key (32 bytes, big
; endian), the certificate_list length (u32, little endian), then the
; certificate_list. Prints the port it listens on, then serves until killed.
; Each connection: the handshake, then every byte received is sent back.

format ELF64 executable 3
entry start

include '../../src/core/sections.inc'
include '../../src/sys/linux.inc'
include '../../src/core/limits.inc'

segment readable executable

include '../../src/core/util.inc'
include '../../src/crypto/ct.inc'
include '../../src/crypto/sha256.inc'
include '../../src/crypto/hmac.inc'
include '../../src/crypto/hkdf.inc'
include '../../src/crypto/x25519.inc'
include '../../src/crypto/aesgcm.inc'
include '../../src/crypto/p256.inc'
include '../../src/tls/layout.inc'
include '../../src/tls/handshake.inc'

BUF		:= 1 shl 16
SOL_TLS		:= 282
TLS_TX		:= 1
TLS_RX		:= 2
TCP_ULP		:= 31

bss
	align 16
	g_mode		db ?
	g_alpn		db ?
	align 8
	g_listen	dd ?
	g_fd		dd ?
	g_have		dd ?
	g_rec		dd ?
	g_cred:		rb TL_SIZE
	g_ts:		rb TS_SIZE
	g_crypto_info:	rb 40
	g_addr:		rb 16
	g_addrlen	dd ?
	g_tls_store:	rb TLS_CHAIN_MAX + 64
	g_in:		rb BUF + 64
	g_out:		rb BUF + 64
end bss

macro sys n
	mov	eax,n
	syscall
end macro

; rdi = buffer, edx = bytes: read them all from stdin, or exit.
read_stdin:
	mov	rsi,rdi
.more:
	test	edx,edx
	jz	.done
	push	rsi
	push	rdx
	xor	edi,edi
	sys	SYS_read
	pop	rdx
	pop	rsi
	test	rax,rax
	jle	fail
	add	rsi,rax
	sub	edx,eax
	jmp	.more
.done:
	ret

fail:
	mov	edi,1
	sys	SYS_exit

start:
	mov	dword [g_out_fd],1
	call	crypto_init
	lea	rdi,[g_mode]
	mov	edx,2
	call	read_stdin
	lea	rdi,[g_cred+TL_KEY]
	mov	edx,32
	call	read_stdin
	lea	rdi,[g_cred+TL_CLEN]
	mov	edx,4
	call	read_stdin
	mov	edx,[g_cred+TL_CLEN]
	cmp	edx,TLS_CHAIN_MAX
	ja	fail
	mov	dword [g_cred+TL_CHAIN],0
	lea	rdi,[g_tls_store]
	call	read_stdin
	cmp	byte [g_mode],'P'
	je	profile
	; 127.0.0.1:0, then the port it got
	mov	edi,AF_INET
	mov	esi,SOCK_STREAM
	xor	edx,edx
	sys	SYS_socket
	test	eax,eax
	js	fail
	mov	[g_listen],eax
	mov	word [g_addr],AF_INET
	mov	word [g_addr+2],0
	mov	dword [g_addr+4],0x0100007F
	mov	edi,eax
	lea	rsi,[g_addr]
	mov	edx,16
	sys	SYS_bind
	test	eax,eax
	jnz	fail
	mov	edi,[g_listen]
	mov	esi,16
	sys	SYS_listen
	mov	dword [g_addrlen],16
	mov	edi,[g_listen]
	lea	rsi,[g_addr]
	lea	rdx,[g_addrlen]
	sys	SYS_getsockname
	movzx	eax,word [g_addr+2]
	rol	ax,8
	call	out_u64
	mov	edi,10
	call	out_char
	call	out_flush

serve:
	mov	edi,[g_listen]
	xor	esi,esi
	xor	edx,edx
	xor	r10d,r10d
	sys	SYS_accept4
	test	eax,eax
	js	serve
	mov	[g_fd],eax
	call	connection
	mov	edi,[g_fd]
	sys	SYS_close
	jmp	serve

profile:
	lea	rdi,[g_rec]
	mov	edx,4
	call	read_stdin			; the count
	mov	eax,[g_rec]
	push	rax
	lea	rdi,[g_have]
	mov	edx,4
	call	read_stdin			; the length
	lea	rdi,[g_in]
	mov	edx,[g_have]
	call	read_stdin
	call	.now
	pop	rbx
	push	rax
	push	rbx
.again:
	lea	rdi,[g_ts]
	mov	ecx,TS_SIZE
	xor	eax,eax
	rep	stosb
	mov	dword [g_ts+TS_FLAGS],TF_ALPN_H1
	lea	rdi,[g_ts]
	lea	rsi,[g_cred]
	lea	rdx,[g_in]
	mov	ecx,[g_have]
	lea	r8,[g_out]
	mov	r9d,BUF
	call	tls_hello
	cmp	eax,TH_SEND
	jne	fail
	dec	ebx
	jnz	.again
	call	.now
	pop	rbx
	pop	rcx
	sub	rax,rcx
	xor	edx,edx
	div	rbx
	call	out_u64
	mov	edi,10
	call	out_char
	call	out_flush
	xor	edi,edi
	sys	SYS_exit
.now:
	sub	rsp,16
	mov	edi,CLOCK_MONOTONIC
	mov	rsi,rsp
	sys	SYS_clock_gettime
	mov	rax,[rsp]
	imul	rax,rax,1000000000
	add	rax,[rsp+8]
	add	rsp,16
	ret

; edx = bytes from g_out: written, or CF.
send_out:
	lea	rsi,[g_out]
send_bytes:
	test	edx,edx
	jz	.done
	push	rsi
	push	rdx
	mov	edi,[g_fd]
	sys	SYS_write
	pop	rdx
	pop	rsi
	test	rax,rax
	jle	.bad
	add	rsi,rax
	sub	edx,eax
	jmp	send_bytes
.done:
	clc
	ret
.bad:
	stc
	ret

; edx = bytes wanted at g_in + [g_have]: up to that many read, CF at the end.
recv_in:
	mov	edi,[g_fd]
	mov	esi,[g_have]
	lea	rsi,[g_in+rsi]
	sys	SYS_read
	test	rax,rax
	jle	.end
	add	[g_have],eax
	clc
	ret
.end:
	stc
	ret

connection:
	lea	rdi,[g_ts]
	mov	ecx,TS_SIZE
	xor	eax,eax
	rep	stosb
	cmp	byte [g_alpn],'H'
	jne	@f
	mov	dword [g_ts+TS_FLAGS],TF_ALPN_H1
@@:
	mov	dword [g_have],0
.hello:
	mov	edx,BUF
	sub	edx,[g_have]
	jz	.done
	call	recv_in
	jc	.done
	lea	rdi,[g_ts]
	lea	rsi,[g_cred]
	lea	rdx,[g_in]
	mov	ecx,[g_have]
	lea	r8,[g_out]
	mov	r9d,BUF
	call	tls_hello
	cmp	eax,TH_MORE
	je	.hello
	push	rax
	call	send_out
	pop	rax
	jc	.done
	cmp	eax,TH_FAIL
	je	.done
	cmp	eax,TH_RETRY
	jne	@f
	mov	dword [g_have],0		; the second ClientHello
	jmp	.hello
@@:
	; The client's Finished, read a record at a time so nothing after it
	; is taken from the socket (kTLS reads that).
	mov	dword [g_have],0
.next_record:
	mov	eax,[g_have]
	mov	[g_rec],eax			; this record's start
.header:
	mov	edx,[g_rec]
	add	edx,5
	sub	edx,[g_have]
	jbe	.body
	call	recv_in
	jc	.done
	jmp	.header
.body:
	mov	ecx,[g_rec]
	movzx	edx,word [g_in+rcx+3]
	rol	dx,8
	lea	eax,[rcx+rdx+5]			; its end
	cmp	eax,BUF
	ja	.done
	mov	edx,eax
	sub	edx,[g_have]
	jbe	.whole
	call	recv_in
	jc	.done
	jmp	.body
.whole:
	lea	rdi,[g_ts]
	lea	rsi,[g_in]
	mov	ecx,[g_have]
	call	tls_finished
	cmp	eax,TH_FAIL
	je	.done
	cmp	eax,TH_MORE
	je	.next_record			; that was a ChangeCipherSpec

.established:
	cmp	byte [g_mode],'K'
	je	.ktls
	lea	rdi,[g_ts]
	call	tls_records
	mov	dword [g_have],0
.user_read:
	mov	edx,BUF
	sub	edx,[g_have]
	jz	.done
	call	recv_in
	jc	.done
.user_open:
	lea	rdi,[g_ts]
	lea	rsi,[g_in]
	mov	edx,[g_have]
	call	tls_open
	cmp	eax,TH_MORE
	je	.user_read
	cmp	eax,TH_FAIL
	je	.done
	push	rdx
	cmp	r8d,23
	jne	.user_control
	; echo: the plaintext into a record of its own
	push	rcx
	lea	rdi,[g_out+5]
	rep	movsb
	pop	rdx
	lea	rdi,[g_ts]
	lea	rsi,[g_out]
	mov	ecx,23
	call	tls_seal
	mov	edx,eax
	call	send_out
	jc	.done_pop
	jmp	.user_shift
.user_control:
	cmp	r8d,21				; alert: close_notify or worse
	je	.done_pop
.user_shift:
	pop	rdx
	; drop the record from g_in
	mov	ecx,[g_have]
	sub	ecx,edx
	mov	[g_have],ecx
	lea	rsi,[g_in+rdx]
	lea	rdi,[g_in]
	rep	movsb
	jmp	.user_open
.done_pop:
	pop	rdx
.done:
	ret

.ktls:
	mov	edi,[g_fd]
	mov	esi,6				; SOL_TCP
	mov	edx,TCP_ULP
	push	'tls'
	mov	r10,rsp
	mov	r8d,4
	sys	SYS_setsockopt
	pop	rcx
	test	eax,eax
	jnz	.done
	lea	rsi,[g_ts+TS_TX_KEY]
	mov	edx,TLS_TX
	call	ktls_key
	jnz	.done
	lea	rsi,[g_ts+TS_RX_KEY]
	mov	edx,TLS_RX
	call	ktls_key
	jnz	.done
.ktls_echo:
	mov	edi,[g_fd]
	lea	rsi,[g_in]
	mov	edx,BUF
	sys	SYS_read
	test	rax,rax
	jle	.done
	mov	edx,eax
	lea	rsi,[g_in]
	call	send_bytes
	jc	.done
	jmp	.ktls_echo

; rsi = key (16) then IV (12) at +16, edx = TLS_TX or TLS_RX: installed,
; ZF on success.
ktls_key:
	lea	rdi,[g_crypto_info]
	mov	word [rdi],0x0304		; TLS 1.3
	mov	word [rdi+2],51			; TLS_CIPHER_AES_GCM_128
	mov	rax,[rsi+16+4]			; iv: the last 8 bytes of the IV
	mov	[rdi+4],rax
	movdqu	xmm0,[rsi]			; key
	movdqu	[rdi+12],xmm0
	mov	eax,[rsi+16]			; salt: its first 4
	mov	[rdi+28],eax
	mov	qword [rdi+32],0		; rec_seq
	mov	r10,rdi
	mov	edi,[g_fd]
	mov	esi,SOL_TLS
	mov	r8d,40
	sys	SYS_setsockopt
	test	eax,eax
	ret

segment readable
	rodata_emit

segment readable writeable
	bss_emit
