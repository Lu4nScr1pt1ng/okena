; Harness for the TLS 1.2 server handshake (not part of okena). Reads from
; stdin a 2-byte big-endian port, the server's P-256 private key (32), a
; 2-byte little-endian certificate_list length and the list itself (TLS
; 1.3 framing). It listens on 127.0.0.1:port, accepts one connection, runs
; the TLS 1.2 handshake with tls12_hello / tls12_finished, then sends one
; application record "okena12\n". openssl s_client -tls1_2 drives it.

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
include '../../src/tls/tls12_server.inc'

SBUF	:= 1 shl 16
SOL_TLS	:= 282
TLS_TX	:= 1
TLS_RX	:= 2
TCP_ULP	:= 31

bss
	align 16
	g_t2:		rb T2_FULL
	g_c12:		rb C12_SIZE
	g_fd		dd ?
	g_cli		dd ?
	g_addr:		rb 16
	g_key:		rb 32
	g_clen:		rb 2
	g_clist:	rb 8192
	g_in:		rb SBUF
	g_out:		rb SBUF
	g_txinfo:	rb 40
	g_rxinfo:	rb 40
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
	; stdin: port (2, into the sockaddr), key (32), clen (2 LE), list
	xor	edi,edi
	lea	rsi,[g_addr+2]
	mov	edx,2
	xor	eax,eax
	syscall
	xor	edi,edi
	lea	rsi,[g_key]
	mov	edx,32
	xor	eax,eax
	syscall
	xor	edi,edi
	lea	rsi,[g_clen]
	mov	edx,2
	xor	eax,eax
	syscall
	movzx	edx,word [g_clen]
	xor	edi,edi
	lea	rsi,[g_clist]
	xor	eax,eax
	syscall
	; C12 credentials
	lea	rax,[g_clist]
	mov	[g_c12+C12_LIST],rax
	movzx	eax,word [g_clen]
	mov	[g_c12+C12_LEN],eax
	lea	rax,[g_key]
	mov	[g_c12+C12_KEY],rax
	; socket, reuse, bind, listen, accept
	mov	edi,AF_INET
	mov	esi,SOCK_STREAM
	xor	edx,edx
	sys	SYS_socket
	test	eax,eax
	js	fail
	mov	[g_fd],eax
	sub	rsp,8
	mov	dword [rsp],1
	mov	edi,[g_fd]
	mov	esi,1				; SOL_SOCKET
	mov	edx,2				; SO_REUSEADDR
	mov	r10,rsp
	mov	r8d,4
	sys	SYS_setsockopt
	add	rsp,8
	mov	word [g_addr],AF_INET
	mov	dword [g_addr+4],0x0100007F
	mov	edi,[g_fd]
	lea	rsi,[g_addr]
	mov	edx,16
	sys	SYS_bind
	test	eax,eax
	jnz	fail
	mov	edi,[g_fd]
	mov	esi,16
	sys	SYS_listen
	mov	edi,[g_fd]
	xor	esi,esi
	xor	edx,edx
	xor	r10d,r10d
	sys	SYS_accept4
	test	eax,eax
	js	fail
	mov	[g_cli],eax
	; a receive timeout, so a read loop ends once a flight is in
	sub	rsp,16
	mov	qword [rsp],2
	mov	qword [rsp+8],0
	mov	edi,[g_cli]
	mov	esi,1
	mov	edx,20				; SO_RCVTIMEO
	mov	r10,rsp
	mov	r8d,16
	sys	SYS_setsockopt
	add	rsp,16
	; read the ClientHello
	mov	edi,[g_cli]
	lea	rsi,[g_in]
	mov	edx,SBUF
	xor	eax,eax
	syscall
	test	rax,rax
	jle	fail
	mov	r12d,eax
	; tls12_hello -> the server flight
	lea	rdi,[g_t2]
	lea	rsi,[g_c12]
	lea	rdx,[g_in]
	mov	ecx,r12d
	lea	r8,[g_out]
	mov	r9d,SBUF
	call	tls12_hello
	test	eax,eax
	jz	fail
	mov	edi,[g_cli]
	lea	rsi,[g_out]
	mov	edx,eax
	sys	SYS_write
	; read ClientKeyExchange + ChangeCipherSpec + Finished
	xor	ebx,ebx
.read:
	mov	edi,[g_cli]
	lea	rsi,[g_in+rbx]
	mov	edx,SBUF
	sub	edx,ebx
	jz	.proc
	xor	eax,eax
	syscall
	test	rax,rax
	jle	.proc
	add	rbx,rax
	cmp	rbx,16384
	jb	.read
.proc:
	test	rbx,rbx
	jz	fail
	lea	rdi,[g_t2]
	lea	rsi,[g_in]
	mov	ecx,ebx
	lea	r8,[g_out]
	call	tls12_finished
	test	eax,eax
	jz	fail
	mov	edi,[g_cli]
	lea	rsi,[g_out]
	mov	edx,eax
	sys	SYS_write
	; hand the TLS 1.2 keys to the kernel (kTLS) and write plaintext
	; TX: server write key/IV, RX: client write key/IV, both at sequence 1
	mov	dword [g_txinfo],0x00330303	; TLS 1.2, AES_GCM_128
	mov	qword [g_txinfo+4],0		; iv = explicit nonce, big-endian 1
	mov	byte [g_txinfo+11],1
	movdqu	xmm0,[g_t2+T2_SWK]
	movdqu	[g_txinfo+12],xmm0		; key
	mov	eax,[g_t2+T2_SWIV]
	mov	[g_txinfo+28],eax		; salt
	mov	qword [g_txinfo+32],0		; rec_seq = 1, big-endian
	mov	byte [g_txinfo+39],1
	mov	dword [g_rxinfo],0x00330303
	mov	qword [g_rxinfo+4],0
	mov	byte [g_rxinfo+11],1
	movdqu	xmm0,[g_t2+T2_CWK]
	movdqu	[g_rxinfo+12],xmm0
	mov	eax,[g_t2+T2_CWIV]
	mov	[g_rxinfo+28],eax
	mov	qword [g_rxinfo+32],0
	mov	byte [g_rxinfo+39],1
	mov	edi,[g_cli]			; TCP_ULP "tls"
	mov	esi,IPPROTO_TCP
	mov	edx,TCP_ULP
	lea	r10,[.ulp]
	mov	r8d,4
	sys	SYS_setsockopt
	test	eax,eax
	jnz	.userspace
	mov	edi,[g_cli]			; TLS_TX
	mov	esi,SOL_TLS
	mov	edx,TLS_TX
	lea	r10,[g_txinfo]
	mov	r8d,40
	sys	SYS_setsockopt
	test	eax,eax
	jnz	.userspace
	mov	edi,[g_cli]			; TLS_RX
	mov	esi,SOL_TLS
	mov	edx,TLS_RX
	lea	r10,[g_rxinfo]
	mov	r8d,40
	sys	SYS_setsockopt
	mov	edi,[g_cli]			; plaintext; the kernel seals it
	lea	rsi,[.app]
	mov	edx,.app.len
	sys	SYS_write
	xor	edi,edi
	sys	SYS_exit
.userspace:
	; no tls module / 1.2 kTLS unavailable: seal in user space (sequence 1)
	lea	rdi,[g_out+5]
	lea	rsi,[g_t2+T2_TXGCM]
	lea	rdx,[g_t2+T2_SWIV]
	mov	rcx,1
	mov	r8d,23
	lea	r9,[.app]
	mov	r10d,.app.len
	call	tls12_seal
	mov	byte [g_out],23
	mov	word [g_out+1],0x0303
	mov	edx,eax
	rol	dx,8
	mov	[g_out+3],dx
	lea	edx,[rax+5]
	mov	edi,[g_cli]
	lea	rsi,[g_out]
	sys	SYS_write
	xor	edi,edi
	sys	SYS_exit
.ulp		db 'tls',0
.app		db 'okena12',10
.app.len	:= $ - .app

segment readable
	rodata_emit

segment readable writeable
	bss_emit
