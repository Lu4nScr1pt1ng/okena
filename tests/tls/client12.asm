; Harness for the TLS 1.2 client handshake (not part of okena). Reads a
; 2-byte big-endian port and a 1-byte data-path mode from stdin, connects
; to 127.0.0.1:port, runs a full TLS 1.2 client handshake (ClientHello,
; the server's ServerHello..ServerHelloDone, ClientKeyExchange + CCS +
; Finished, the server's CCS + Finished), then exchanges an HTTP request
; over the channel (kTLS when mode=1, else user-space records). Prints '1'
; on success. openssl s_server -tls1_2 drives it.

format ELF64 executable 3
entry start

include '../../src/core/sections.inc'
include '../../src/sys/linux.inc'
include '../../src/core/limits.inc'

segment readable executable

include '../../src/core/util.inc'
include '../../src/crypto/ct.inc'
include '../../src/crypto/sha256.inc'
include '../../src/crypto/keccak.inc'
include '../../src/crypto/mlkem.inc'
include '../../src/crypto/hmac.inc'
include '../../src/crypto/hkdf.inc'
include '../../src/crypto/x25519.inc'
include '../../src/crypto/sha512.inc'
include '../../src/crypto/ed25519.inc'
include '../../src/crypto/aesgcm.inc'
include '../../src/crypto/chacha.inc'
include '../../src/crypto/p256.inc'
include '../../src/crypto/rsa.inc'
include '../../src/tls/x509.inc'
include '../../src/tls/keyschedule.inc'
include '../../src/tls/tls12.inc'
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
	g_ch:		rb SBUF
	g_in:		rb SBUF
	g_send:		rb SBUF
	g_mode		db ?
	g_txinfo:	rb 40
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
	xor	edi,edi				; port (2 bytes)
	lea	rsi,[g_addr+2]
	mov	edx,2
	xor	eax,eax
	syscall
	cmp	rax,2
	jne	fail
	xor	edi,edi				; data-path mode (1 byte)
	lea	rsi,[g_mode]
	mov	edx,1
	xor	eax,eax
	syscall
	mov	edi,AF_INET
	mov	esi,SOCK_STREAM
	xor	edx,edx
	sys	SYS_socket
	test	eax,eax
	js	fail
	mov	[g_fd],eax
	mov	word [g_addr],AF_INET
	mov	dword [g_addr+4],0x0100007F
	mov	edi,[g_fd]
	lea	rsi,[g_addr]
	mov	edx,16
	sys	SYS_connect
	test	eax,eax
	jnz	fail
	sub	rsp,16				; a receive timeout
	mov	qword [rsp],2
	mov	qword [rsp+8],0
	mov	edi,[g_fd]
	mov	esi,1
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
	mov	edi,[g_fd]
	lea	rsi,[g_ch]
	mov	edx,eax
	sys	SYS_write
	; read the server's flight (ServerHello..ServerHelloDone)
	xor	ebx,ebx
.read:
	mov	edi,[g_fd]
	lea	rsi,[g_in+rbx]
	mov	edx,SBUF
	sub	edx,ebx
	jz	.flight
	xor	eax,eax
	syscall
	test	rax,rax
	jle	.flight
	add	rbx,rax
	cmp	rbx,16384
	jb	.read
.flight:
	test	rbx,rbx
	jz	fail
	lea	rdi,[g_tc]
	lea	rsi,[g_in]
	mov	edx,ebx
	lea	rcx,[g_send]
	call	tlsc12_flight			; -> the client flight into g_send
	test	eax,eax
	jz	.no
	mov	edi,[g_fd]			; send ClientKeyExchange + CCS + Finished
	lea	rsi,[g_send]
	mov	edx,eax
	sys	SYS_write
	; read the server's CCS + Finished
	xor	ebx,ebx
.read2:
	mov	edi,[g_fd]
	lea	rsi,[g_in+rbx]
	mov	edx,SBUF
	sub	edx,ebx
	jz	.srvfin
	xor	eax,eax
	syscall
	test	rax,rax
	jle	.srvfin
	add	rbx,rax
	cmp	rbx,16384
	jb	.read2
.srvfin:
	test	rbx,rbx
	jz	.no
	lea	rdi,[g_tc]
	lea	rsi,[g_in]
	mov	edx,ebx
	call	tlsc12_server_finished
	test	eax,eax
	jz	.no
	; the handshake is complete; exchange an HTTP request
	cmp	byte [g_mode],1
	je	.ktls
.userspace:
	lea	rdi,[g_send+5]			; seal the GET (client record sequence 1)
	lea	rsi,[g_tc+TC12_TX]
	lea	rdx,[g_tc+TC12_CIV]
	mov	rcx,1
	mov	r8d,23
	lea	r9,[.get]
	mov	r10d,.get.len
	call	tls12_seal
	mov	byte [g_send],23
	mov	word [g_send+1],0x0303
	mov	edx,eax
	rol	dx,8
	mov	[g_send+3],dx
	lea	edx,[rax+5]
	mov	edi,[g_fd]
	lea	rsi,[g_send]
	sys	SYS_write
	xor	ebx,ebx
.read3:
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
	jb	.read3
.scan:
	; the server's first application_data record (its record sequence 1,
	; after the Finished at 0): open it and look for "HTTP"
	cmp	rbx,5
	jb	.no
	cmp	byte [g_in],23			; application_data
	jne	.no
	movzx	esi,word [g_in+3]
	rol	si,8
	lea	rdi,[g_in+5]
	lea	rdx,[g_tc+TC12_RX]
	lea	rcx,[g_tc+TC12_SIV]
	mov	r8,1				; server record sequence 1
	mov	r9d,23
	call	tls12_open
	test	eax,eax
	js	.no
	cmp	eax,4
	jb	.no
	cmp	dword [g_in+5+8],'HTTP'		; plaintext at payload+8
	jne	.no
	jmp	.yes
.ktls:
	lea	rdi,[g_tc]
	lea	rsi,[g_txinfo]
	lea	rdx,[g_rxinfo]
	call	tlsc12_ktls_info
	mov	edi,[g_fd]
	mov	esi,IPPROTO_TCP
	mov	edx,TCP_ULP
	lea	r10,[.ulp]
	mov	r8d,4
	mov	eax,SYS_setsockopt
	syscall
	test	eax,eax
	jnz	.userspace
	mov	edi,[g_fd]
	mov	esi,SOL_TLS
	mov	edx,TLS_TX
	lea	r10,[g_txinfo]
	mov	r8d,40
	mov	eax,SYS_setsockopt
	syscall
	test	eax,eax
	jnz	.no
	mov	edi,[g_fd]
	mov	esi,SOL_TLS
	mov	edx,TLS_RX
	lea	r10,[g_rxinfo]
	mov	r8d,40
	mov	eax,SYS_setsockopt
	syscall
	test	eax,eax
	jnz	.no
	mov	edi,[g_fd]
	lea	rsi,[.get]
	mov	edx,.get.len
	sys	SYS_write
	mov	edi,[g_fd]
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
