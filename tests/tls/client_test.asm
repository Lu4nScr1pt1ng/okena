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
include '../../src/tls/x509.inc'
include '../../src/tls/keyschedule.inc'
include '../../src/tls/client.inc'

SBUF	:= 1 shl 16

bss
	align 16
	g_tc:		rb TC_FULL
	g_fd		dd ?
	g_addr:		rb 16
	g_ch:		rb SBUF			; the ClientHello
	g_in:		rb SBUF			; the server's flight
	g_out:		rb SBUF			; the decrypted handshake
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
	; print g_out as hex
	mov	r12d,eax
	lea	r8,[g_out]
	xor	ecx,ecx
.hex:
	cmp	ecx,r12d
	jae	.end
	movzx	eax,byte [r8+rcx]
	mov	edx,eax
	shr	eax,4
	mov	dil,[.hexd+rax]
	and	edx,15
	mov	sil,[.hexd+rdx]
	mov	[g_pair],dil
	mov	[g_pair+1],sil
	push	rcx
	push	r8
	push	r12
	mov	edi,[g_out_fd]
	lea	rsi,[g_pair]
	mov	edx,2
	call	out_str
	pop	r12
	pop	r8
	pop	rcx
	inc	ecx
	jmp	.hex
.end:
	call	out_flush
	xor	edi,edi
	sys	SYS_exit
.sni		db 'localhost'
.sni.len	:= $ - .sni
.hexd		db '0123456789abcdef'

segment readable
	rodata_emit

segment readable writeable
	bss_emit
