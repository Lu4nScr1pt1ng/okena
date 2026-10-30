; Harness for the TLS 1.3 client handshake (not part of okena). Reads a
; 2-byte big-endian port from stdin, connects to 127.0.0.1:port, sends a
; ClientHello, reads the server's flight, processes it, and prints the
; decrypted handshake messages as hex. A real TLS server on that port
; lets the client code be exercised end to end.

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
include '../../src/crypto/rsa.inc'
include '../../src/tls/x509.inc'
include '../../src/tls/keyschedule.inc'
include '../../src/tls/client.inc'

SBUF	:= 1 shl 16
SOL_TLS	:= 282
TLS_TX	:= 1
TLS_RX	:= 2
TCP_ULP	:= 31

bss
	align 16
	g_tc:		rb TC_FULL
	g_fd		dd ?
	g_addr:		rb 16
	g_ch:		rb SBUF			; the ClientHello
	g_in:		rb SBUF			; the server's flight / responses
	g_out:		rb SBUF			; the decrypted handshake
	g_send:		rb SBUF			; the client Finished + the GET
	g_mode		db ?			; 0 = user-space records, 1 = kTLS
	g_txinfo:	rb 40			; the kernel's TLS crypto_info, TX then RX
	g_rxinfo:	rb 40
	g_pair:		rb 2
end bss

macro sys n
	mov	eax,n
	syscall
end macro

fail:
	mov	edi,1
	sys	SYS_exit

start:
	mov	dword [g_out_fd],1
	call	crypto_init
	; read the 2-byte port
	xor	edi,edi
	lea	rsi,[g_addr+2]
	mov	edx,2
	xor	eax,eax
	syscall
	cmp	rax,2
	jne	fail
	xor	edi,edi				; one more byte: the data-path mode
	lea	rsi,[g_mode]
	mov	edx,1
	xor	eax,eax
	syscall
	; socket + connect 127.0.0.1:port
	mov	edi,AF_INET
	mov	esi,SOCK_STREAM
	xor	edx,edx
	sys	SYS_socket
	test	eax,eax
	js	fail
	mov	[g_fd],eax
	mov	word [g_addr],AF_INET		; family; port already at +2
	mov	dword [g_addr+4],0x0100007F	; 127.0.0.1
	mov	edi,[g_fd]
	lea	rsi,[g_addr]
	mov	edx,16
	sys	SYS_connect
	test	eax,eax
	jnz	fail
	; a receive timeout, so the read loop stops once the flight is in
	sub	rsp,16
	mov	qword [rsp],2			; tv_sec
	mov	qword [rsp+8],0			; tv_usec
	mov	edi,[g_fd]
	mov	esi,1				; SOL_SOCKET
	mov	edx,20				; SO_RCVTIMEO
	mov	r10,rsp
	mov	r8d,16
	sys	SYS_setsockopt
	add	rsp,16
	; ClientHello
	lea	rdi,[g_tc]
	lea	rsi,[g_ch]
	lea	rdx,[.sni]
	mov	ecx,.sni.len
	call	tlsc_client_hello
	test	eax,eax
	jz	fail
	mov	r12d,eax			; its length
	; send it
	mov	edi,[g_fd]
	lea	rsi,[g_ch]
	mov	edx,r12d
	sys	SYS_write
	; read the server's flight (until it pauses: one read is enough for a
	; small flight, loop a few times to gather it)
	xor	ebx,ebx				; bytes received
.read:
	mov	edi,[g_fd]
	lea	rsi,[g_in+rbx]
	mov	edx,SBUF
	sub	edx,ebx
	jz	.process
	xor	eax,eax				; SYS_read
	syscall
	test	rax,rax
	jle	.process
	add	rbx,rax
	cmp	rbx,16384			; a full flight fits; stop once we have plenty
	jb	.read
.process:
	test	rbx,rbx
	jz	fail
	lea	rdi,[g_tc]
	lea	rsi,[g_in]
	mov	edx,ebx
	lea	rcx,[g_out]
	call	tlsc_server_flight
	test	eax,eax
	jz	fail
	; verify the CertificateVerify and the server Finished
	lea	rdi,[g_tc]
	lea	rsi,[g_out]
	mov	edx,eax
	call	tlsc_verify
	test	eax,eax
	jz	.no
	; complete the handshake: the client Finished + application keys
	lea	rdi,[g_tc]
	lea	rsi,[g_send]
	call	tlsc_finish
	mov	r12d,eax			; the Finished record length
	mov	edi,[g_fd]			; send the client Finished
	lea	rsi,[g_send]
	mov	edx,r12d
	sys	SYS_write
	cmp	byte [g_mode],1
	je	.ktls
.userspace:
	; seal the request as an application_data record, send it, and read
	; the response, opening each record with the server application key
	lea	rdi,[g_tc]
	lea	rsi,[g_send]
	lea	rdx,[.get]
	mov	ecx,.get.len
	call	tlsc_seal
	mov	edi,[g_fd]
	lea	rsi,[g_send]
	mov	edx,eax
	sys	SYS_write
	xor	ebx,ebx
.read2:
	mov	edi,[g_fd]
	lea	rsi,[g_in+rbx]
	mov	edx,SBUF
	sub	edx,ebx
	jz	.scan
	xor	eax,eax
	syscall
	test	rax,rax
	jle	.scan
	add	rbx,rax
	cmp	rbx,16384
	jb	.read2
.scan:
	; walk the records; open each with the server application key and look
	; for an application_data record whose plaintext is an HTTP response
	xor	r13d,r13d			; offset into g_in
.next:
	lea	rax,[r13+5]
	cmp	rax,rbx
	ja	.no				; no full record left
	movzx	ecx,word [g_in+r13+3]
	rol	cx,8
	lea	rax,[r13+rcx+5]			; end of this record
	cmp	rax,rbx
	ja	.no
	lea	rdi,[g_tc]
	lea	rsi,[g_in+r13]
	push	rax				; next offset
	call	tlsc_open
	pop	r13				; advance past this record
	test	eax,eax
	jz	.no				; a bad tag ends it
	cmp	r8d,23				; application_data?
	jne	.next
	cmp	ecx,4
	jb	.next
	cmp	dword [rsi],'HTTP'
	jne	.next
	; success: the encrypted channel carried an HTTP response
	jmp	.yes
.ktls:
	; hand the application keys to the kernel and exchange plaintext
	lea	rdi,[g_tc]
	lea	rsi,[g_txinfo]
	lea	rdx,[g_rxinfo]
	call	tlsc_ktls_info
	mov	edi,[g_fd]			; TCP_ULP "tls"
	mov	esi,IPPROTO_TCP
	mov	edx,TCP_ULP
	lea	r10,[.ulp]
	mov	r8d,4
	mov	eax,SYS_setsockopt
	syscall
	test	eax,eax
	jnz	.userspace			; no tls module: prove it in user space
	mov	edi,[g_fd]			; TLS_TX
	mov	esi,SOL_TLS
	mov	edx,TLS_TX
	lea	r10,[g_txinfo]
	mov	r8d,40
	mov	eax,SYS_setsockopt
	syscall
	test	eax,eax
	jnz	.no
	mov	edi,[g_fd]			; TLS_RX
	mov	esi,SOL_TLS
	mov	edx,TLS_RX
	lea	r10,[g_rxinfo]
	mov	r8d,40
	mov	eax,SYS_setsockopt
	syscall
	test	eax,eax
	jnz	.no
	mov	edi,[g_fd]			; plaintext request; the kernel seals it
	lea	rsi,[.get]
	mov	edx,.get.len
	sys	SYS_write
	mov	edi,[g_fd]			; plaintext response; the kernel opens it
	lea	rsi,[g_in]
	mov	edx,SBUF
	xor	eax,eax
	syscall
	cmp	rax,4
	jb	.no
	cmp	dword [g_in],'HTTP'
	jne	.no
	jmp	.yes
.yes:
	mov	byte [g_pair],'1'
	jmp	.print
.no:
	mov	byte [g_pair],'0'
.print:
	mov	edi,[g_out_fd]
	lea	rsi,[g_pair]
	mov	edx,1
	call	out_str
	call	out_flush
	xor	edi,edi
	sys	SYS_exit
.get		db 'GET / HTTP/1.0',13,10,13,10
.get.len	:= $ - .get
.ulp		db 'tls',0
.sni		db 'localhost'
.sni.len	:= $ - .sni

segment readable
	rodata_emit

segment readable writeable
	bss_emit
