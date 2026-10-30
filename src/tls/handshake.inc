; TLS 1.3 server handshake (RFC 8446): TLS_AES_128_GCM_SHA256, the x25519
; and secp256r1 groups and ecdsa_secp256r1_sha256 signatures, the set every TLS 1.3
; client offers. One round trip, no state between the two calls but the
; TS block: everything the client Finished needs is computed with the
; server's flight.
;
;   tls_hello(rdi ts, rsi credentials (a TL entry), rdx in, ecx in length,
;             r8 out, r9d out room)
;       in: what the client sent so far (the ClientHello's records).
;       eax = TH_MORE: incomplete, call again with more.
;       eax = TH_SEND: out holds the server's flight, edx bytes:
;             ServerHello, a ChangeCipherSpec for middlebox compatibility
;             when the client sent a session id, then EncryptedExtensions,
;             Certificate, CertificateVerify and Finished under the
;             server's handshake key.
;       eax = TH_RETRY: out holds a HelloRetryRequest (edx bytes): the
;             client offered x25519 but sent another group's share; read
;             its second ClientHello and call again, with in holding
;             only that (a ChangeCipherSpec before it is skipped).
;       eax = TH_FAIL: edx bytes of a plaintext alert in out; close.
;   tls_finished(rdi ts, rsi in, ecx in length)
;       in: the client's records after the flight (an optional
;       ChangeCipherSpec, then its Finished).
;       eax = TH_MORE, or TH_DONE with edx = bytes taken (application data
;       may follow in the same buffer), or TH_FAIL (close).
;       Once done the TS block holds the application traffic keys, for
;       kTLS or for tls_seal / tls_open.
;
; out must hold room for the flight twice (the plaintext is built at its
; end, then sealed into records at its start): 64 KiB covers the largest
; chain the configuration accepts (TLS_CHAIN_MAX). The ClientHello is
; copied out of its records into out first, so in is left as it was.
;
; Key exchange is x25519 or secp256r1 (whichever the client sends a share
; for, x25519 preferred). A client offering a supported group without a
; share for it gets a HelloRetryRequest (RFC 8446 4.1.4) naming x25519, or
; secp256r1 when that is the only one it offered; one that offers neither,
; a handshake_failure alert.
; No resumption and no 0-RTT: no tickets are issued, so no client sends
; early data.

TS_CHS_KEY	:= 0				; client handshake traffic: key
TS_CHS_IV	:= 16				; and IV (12)
TS_CFIN		:= 32				; the client Finished expected (32)
TS_RX_KEY	:= 64				; client application traffic
TS_RX_IV	:= 80
TS_TX_KEY	:= 96				; server application traffic
TS_TX_IV	:= 112
TS_RX_SEQ	:= 128				; q: records opened
TS_TX_SEQ	:= 136				; q: records sealed
TS_FLAGS	:= 144				; d: TF_*
TS_RX_GCM	:= 160				; user-space records only (tls_records)
TS_TX_GCM	:= TS_RX_GCM + GCM_SIZE
TS_HRR_SHA	:= TS_TX_GCM + GCM_SIZE		; after a HelloRetryRequest: the transcript so far
TS_CERT		:= TS_HRR_SHA + SHA256_CTX_SIZE	; q: the entry SNI chose, 0 = the default
TS_SIZE		:= TS_CERT + 8

TF_ALPN_H1	:= 1				; set by the caller: answer ALPN with http/1.1
TF_GOT_H1	:= 2				; the client asked for http/1.1
TF_HRR		:= 4				; a HelloRetryRequest went out: this is the second hello

TH_MORE		:= 0
TH_SEND		:= 1
TH_DONE		:= 1
TH_FAIL		:= 2
TH_TLS12	:= 3		; the client offered no TLS 1.3: try a 1.2 handshake
TH_RETRY	:= 3				; tls_hello: send out, then read a second ClientHello

TLS_RECORD_MAX	:= 16384			; plaintext of one record

; Session tickets (RFC 8446 4.6.1), stateless: the state is sealed into
; the ticket with a key made at the start and shared by the workers.
; ticket = key id (4) | nonce (12) | sealed (TK_PT) | tag (16), the key
; id as additional data. One per handshake, in the server's flight: the
; resumption secret needs the client Finished, already known then.
TK_ID		:= 0
TK_NONCE	:= 4
TK_SEALED	:= 16
TKP_VERSION	:= 0				; in the sealed part: 1
TKP_ISSUED	:= 4				; d: seconds (CLOCK_MONOTONIC)
TKP_AGE_ADD	:= 8
TKP_CERT	:= 16				; 8 bytes of the certificate's key: tickets of
						; another certificate do not resume
TKP_PSK		:= 24				; 32
TK_PT		:= 56
TK_SIZE		:= TK_SEALED + TK_PT + 16	; 88
TICKET_ROTATE	:= 3600				; seconds a key issues tickets (OKENA_TICKET_ROTATE)
; The keys: a page shared by the supervisor and the workers (mapped before
; they fork), three slots. Tickets come from the current key and are
; taken under it or the previous one: valid one to two periods. The
; supervisor rotates into the third slot, then moves TKS_CUR, so the two
; slots in use are never the one being written.
TKS_CUR		:= 0				; d: the current slot, 0..2
TKS_SLOTS	:= 64
TKS_ID		:= 0				; d: the key id (never 0), 0 = empty slot
TKS_GCM		:= 16
TKS_SLOT	:= (TKS_GCM + GCM_SIZE + 63) and not 63
assert TKS_SLOTS + 3 * TKS_SLOT <= 4096
CH_MAX		:= 16384			; a ClientHello (a post-quantum one is ~1.8 KiB)

; alert descriptions
AL_UNEXPECTED	:= 10
AL_OVERFLOW	:= 22
AL_HANDSHAKE	:= 40
AL_ILLEGAL	:= 47
AL_DECODE	:= 50
AL_VERSION	:= 70
AL_DECRYPT	:= 51
AL_INTERNAL	:= 80
AL_NO_ALPN	:= 120

rodata
	; HKDF-Extract(0, 0) and Derive-Secret(that, "derived", ""): without a
	; PSK they never change
	tls13_hrr_random	db 0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91
				db 0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c
end rodata

bss
	align 16
	g_tks		dq ?			; the shared keys, 0 = no tickets
	g_tk_period	dd ?			; seconds between rotations
	g_tk_next	dd ?			; the next one (supervisor)
	g_tk_fixed	dd ?			; 1: keys from a ticket_keys file, no rotation here
	g_tk_life	dd ?			; a ticket's lifetime: the period, an hour with a file
end bss

rodata
end rodata

; ---------------------------------------------------------------- hello

HL_TS		:= 0
HL_TL		:= 8
HL_OUT		:= 16
HL_ROOM		:= 24
HL_MLEN		:= 28				; the ClientHello, header included
HL_SIDLEN	:= 32
HL_GOT		:= 36				; G_*
HL_W		:= 40				; where the encrypted records go
HL_SEQ		:= 48
HL_SID		:= 64				; 32
HL_KS		:= 96				; the client's x25519 share (32)
HL_RAND		:= 128				; server random (32) | x25519 secret (32) | ticket nonce (12) | age_add (4)
HL_PUB		:= 208
HL_SHARED	:= 240
HL_HS		:= 272				; handshake secret
HL_MS		:= 304				; master secret
HL_CHT		:= 336				; client / server handshake traffic
HL_SHT		:= 368
HL_TMP		:= 400
HL_SFK		:= 432				; finished keys
HL_CFK		:= 464
HL_TH		:= 496				; a transcript hash
HL_SKEY		:= 528				; server handshake key (16), IV (12)
HL_SIV		:= 544
HL_NONCE	:= 560
HL_SIG		:= 576				; r | s
HL_DIG		:= 640
HL_SHA		:= 672				; the transcript
HL_SHA2		:= HL_SHA + SHA256_CTX_SIZE
HL_GCM		:= HL_SHA2 + SHA256_CTX_SIZE
HL_CV		:= HL_GCM + GCM_SIZE		; the content CertificateVerify signs (130)
HL_TICKET	:= HL_CV + 136			; a ticket (TK_SIZE): the client's, opened; then ours
HL_PSK		:= HL_TICKET + 96
HL_EARLY	:= HL_PSK + 32			; early secret, from the PSK
HL_IDP		:= HL_EARLY + 32		; q: the client's first PSK identity
HL_BINP		:= HL_IDP + 8			; q: its binder
HL_IDLEN	:= HL_BINP + 8
HL_BINOFF	:= HL_IDLEN + 4			; the ClientHello up to its binders
HL_SHLEN	:= HL_BINOFF + 4		; the ServerHello's record length
HL_NOW		:= HL_SHLEN + 4			; seconds (CLOCK_MONOTONIC)
HL_SNIP		:= HL_NOW + 4			; q: the client's server_name
HL_SNILEN	:= HL_SNIP + 8
HL_PEER256	:= HL_SNILEN + 4		; the client's secp256r1 point (65)
HL_PUB256	:= HL_PEER256 + 72		; the server's (65)
HL_GROUP	:= HL_PUB256 + 72		; d: 0 = x25519, 1 = secp256r1
HL_KSEXT	:= HL_GROUP + 4			; d: the key_share extension's wire length
HL_SIZE		:= ((HL_KSEXT + 4 + 15) and not 15) + 8	; rsp 16-aligned at calls

G_TLS13		:= 1
G_SUITE		:= 2
G_SIGALG	:= 4
G_KS		:= 8
G_ALPN		:= 16
G_H1		:= 32
G_GROUP		:= 64				; x25519 in supported_groups
G_KS256		:= 2048				; the client sent a secp256r1 key share
G_GROUP256	:= 4096				; secp256r1 in supported_groups
G_PSK		:= 128				; pre_shared_key: a ticket-sized identity, a 32-byte binder
G_PSKDHE	:= 256				; psk_key_exchange_modes has psk_dhe_ke
G_RESUME	:= 512				; the ticket opened and the binder is right: resumption
G_TICKET	:= 1024				; a ticket to send after the flight
G_SIGALG_RSA	:= 8192				; rsa_pss_rsae_sha256 offered (TLS 1.3 CertificateVerify)
G_SIGALG_RSA1	:= 16384			; rsa_pkcs1_sha256 offered (a legacy 1.2 client)

; the transcript: rsi = bytes, rdx = length
macro th_add
	lea	rdi,[rbp+HL_SHA]
	call	sha256_update
end macro

; HL_TH = the hash of the transcript so far (the transcript goes on)
macro th_snapshot
	lea	rsi,[rbp+HL_SHA]
	lea	rdi,[rbp+HL_SHA2]
	mov	ecx,SHA256_CTX_SIZE
	rep	movsb
	lea	rdi,[rbp+HL_SHA2]
	lea	rsi,[rbp+HL_TH]
	call	sha256_final
end macro


tls_hello:
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,HL_SIZE
	mov	rbp,rsp
	mov	rbx,rdi				; ts
	mov	r12,r8				; out
	mov	r13,rdx				; in
	mov	r14d,ecx			; in length
	mov	r15,rsi				; credentials
	mov	rdi,rbp				; the frame starts zeroed
	mov	ecx,HL_SIZE
	xor	eax,eax
	rep	stosb
	mov	[rbp+HL_TS],rbx
	mov	[rbp+HL_TL],r15
	mov	[rbp+HL_OUT],r12
	mov	[rbp+HL_ROOM],r9d
	cmp	r9d,CH_MAX + 64
	jb	.internal

	; The ClientHello out of its records, into out. rsi = record, r13 = the
	; end of input, rdi = where its payload goes, r14d = bytes gathered.
	add	r13,r14
	mov	rsi,rdx
	mov	rdi,r12
	xor	r14d,r14d
.record:
	mov	rax,r13
	sub	rax,rsi
	cmp	rax,5
	jb	.more
	movzx	ecx,word [rsi+3]
	rol	cx,8
	cmp	byte [rsi],22			; handshake
	je	@f
	cmp	byte [rsi],20			; ChangeCipherSpec, after a retry only
	jne	.not_handshake
	test	dword [rbx+TS_FLAGS],TF_HRR
	jz	.unexpected
	test	r14d,r14d
	jnz	.unexpected
	cmp	ecx,1
	jne	.unexpected
	cmp	rax,6
	jb	.more
	cmp	byte [rsi+5],1
	jne	.unexpected
	add	rsi,6
	jmp	.record
@@:
	test	ecx,ecx
	jz	.unexpected
	cmp	ecx,TLS_RECORD_MAX
	ja	.overflow
	sub	rax,5
	cmp	rax,rcx
	jb	.more
	lea	eax,[r14+rcx]
	cmp	eax,CH_MAX
	ja	.overflow
	add	rsi,5
	mov	r14d,eax
	rep	movsb
	cmp	r14d,4
	jb	.record
	cmp	byte [r12],1			; client_hello
	jne	.unexpected
	mov	eax,[r12]			; type | uint24 length
	bswap	eax
	and	eax,0xFFFFFF
	add	eax,4
	cmp	eax,CH_MAX
	ja	.overflow
	cmp	r14d,eax
	jb	.record
	jne	.unexpected			; something after it in the same records
	cmp	rsi,r13
	jne	.unexpected
	mov	[rbp+HL_MLEN],eax

	; Parse. rsi = cursor, r13 = the end of the message.
	lea	r13,[r12+rax]
	lea	rsi,[r12+4]
	lea	rax,[rsi+35]
	cmp	rax,r13
	ja	.decode
	cmp	byte [rsi],3			; legacy_version 0x0303
	jne	.version
	cmp	byte [rsi+1],3
	jb	.version
	add	rsi,34				; and the random
	movzx	ecx,byte [rsi]			; legacy_session_id, echoed
	inc	rsi
	cmp	ecx,32
	ja	.decode
	lea	rax,[rsi+rcx]
	cmp	rax,r13
	ja	.decode
	mov	[rbp+HL_SIDLEN],ecx
	lea	rdi,[rbp+HL_SID]
	rep	movsb
	; cipher_suites
	lea	rax,[rsi+2]
	cmp	rax,r13
	ja	.decode
	movzx	ecx,word [rsi]
	rol	cx,8
	add	rsi,2
	test	ecx,ecx
	jz	.decode
	test	ecx,1
	jnz	.decode
	lea	rdx,[rsi+rcx]
	cmp	rdx,r13
	ja	.decode
.suite:
	cmp	word [rsi],0x0113		; TLS_AES_128_GCM_SHA256
	jne	@f
	or	dword [rbp+HL_GOT],G_SUITE
@@:
	add	rsi,2
	cmp	rsi,rdx
	jb	.suite
	; legacy_compression_methods: exactly "null"
	cmp	rsi,r13
	jae	.decode
	movzx	ecx,byte [rsi]
	inc	rsi
	lea	rdx,[rsi+rcx]
	cmp	rdx,r13
	ja	.decode
	cmp	ecx,1
	jne	.illegal
	cmp	byte [rsi],0
	jne	.illegal
	inc	rsi
	; extensions, to the end of the message
	lea	rax,[rsi+2]
	cmp	rax,r13
	ja	.version			; none: not a TLS 1.3 client
	movzx	ecx,word [rsi]
	rol	cx,8
	add	rsi,2
	lea	rdx,[rsi+rcx]
	cmp	rdx,r13
	jne	.decode
.ext:
	cmp	rsi,r13
	jae	.ext_done
	lea	rax,[rsi+4]
	cmp	rax,r13
	ja	.decode
	movzx	eax,word [rsi]
	rol	ax,8
	movzx	ecx,word [rsi+2]
	rol	cx,8
	add	rsi,4
	lea	r14,[rsi+rcx]			; the end of this extension
	cmp	r14,r13
	ja	.decode
	cmp	eax,43
	je	.versions
	cmp	eax,51
	je	.key_share
	cmp	eax,13
	je	.sigalgs
	cmp	eax,16
	je	.alpn
	cmp	eax,10
	je	.groups
	cmp	eax,45
	je	.modes
	test	eax,eax
	je	.server_name
	cmp	eax,41
	je	.psk
.ext_next:
	mov	rsi,r14
	jmp	.ext

.versions:					; supported_versions: u8 length, u16s
	test	ecx,ecx
	jz	.decode
	movzx	edx,byte [rsi]
	inc	rsi
	lea	rax,[rsi+rdx]
	cmp	rax,r14
	jne	.decode
	test	edx,1
	jnz	.decode
.version_item:
	cmp	rsi,r14
	jae	.ext_next
	cmp	word [rsi],0x0403		; TLS 1.3
	jne	@f
	or	dword [rbp+HL_GOT],G_TLS13
@@:
	add	rsi,2
	jmp	.version_item

.sigalgs:					; signature_algorithms: u16 length, u16s
	cmp	ecx,2
	jb	.decode
	movzx	edx,word [rsi]
	rol	dx,8
	add	rsi,2
	lea	rax,[rsi+rdx]
	cmp	rax,r14
	jne	.decode
	test	edx,1
	jnz	.decode
.sigalg_item:
	cmp	rsi,r14
	jae	.ext_next
	cmp	word [rsi],0x0304		; ecdsa_secp256r1_sha256
	jne	@f
	or	dword [rbp+HL_GOT],G_SIGALG
@@:
	cmp	word [rsi],0x0408		; rsa_pss_rsae_sha256
	jne	@f
	or	dword [rbp+HL_GOT],G_SIGALG_RSA
@@:
	cmp	word [rsi],0x0104		; rsa_pkcs1_sha256 (a legacy 1.2 client)
	jne	@f
	or	dword [rbp+HL_GOT],G_SIGALG_RSA1
@@:
	add	rsi,2
	jmp	.sigalg_item

.key_share:					; u16 length, { u16 group, u16 length, key }
	cmp	ecx,2
	jb	.decode
	movzx	edx,word [rsi]
	rol	dx,8
	add	rsi,2
	lea	rax,[rsi+rdx]
	cmp	rax,r14
	jne	.decode
.share:
	cmp	rsi,r14
	jae	.ext_next
	lea	rax,[rsi+4]
	cmp	rax,r14
	ja	.decode
	movzx	eax,word [rsi]
	movzx	edx,word [rsi+2]
	rol	dx,8
	add	rsi,4
	lea	r8,[rsi+rdx]
	cmp	r8,r14
	ja	.decode
	cmp	ax,0x1D00			; x25519
	jne	.ks_p256
	cmp	edx,32
	jne	.illegal
	lea	rdi,[rbp+HL_KS]
	mov	ecx,32
	rep	movsb
	or	dword [rbp+HL_GOT],G_KS
	jmp	.share_next
.ks_p256:
	cmp	ax,0x1700			; secp256r1
	jne	.share_next
	cmp	edx,65
	jne	.share_next			; not uncompressed: ignore this share
	lea	rdi,[rbp+HL_PEER256]
	mov	ecx,65
	rep	movsb
	or	dword [rbp+HL_GOT],G_KS256
.share_next:
	mov	rsi,r8
	jmp	.share

.server_name:					; u16 length, { u8 type, u16 length, name }
	cmp	ecx,5
	jb	.decode
	movzx	edx,word [rsi]
	rol	dx,8
	add	rsi,2
	lea	rax,[rsi+rdx]
	cmp	rax,r14
	jne	.decode
	cmp	byte [rsi],0			; host_name (the only type there is)
	jne	.ext_next
	movzx	ecx,word [rsi+1]
	rol	cx,8
	lea	rax,[rsi+3+rcx]
	cmp	rax,r14
	ja	.decode
	add	rsi,3
	mov	[rbp+HL_SNIP],rsi
	mov	[rbp+HL_SNILEN],ecx
	jmp	.ext_next

.modes:						; psk_key_exchange_modes: u8 length, modes
	test	ecx,ecx
	jz	.decode
	movzx	edx,byte [rsi]
	inc	rsi
	lea	rax,[rsi+rdx]
	cmp	rax,r14
	jne	.decode
.mode_item:
	cmp	rsi,r14
	jae	.ext_next
	cmp	byte [rsi],1			; psk_dhe_ke
	jne	@f
	or	dword [rbp+HL_GOT],G_PSKDHE
@@:
	inc	rsi
	jmp	.mode_item

.psk:						; pre_shared_key, the last extension:
	cmp	r14,r13				; identities, then binders
	jne	.illegal
	cmp	ecx,2
	jb	.decode
	movzx	edx,word [rsi]
	rol	dx,8
	add	rsi,2
	lea	r8,[rsi+rdx]			; the identities' end
	cmp	r8,r14
	ja	.decode
	cmp	edx,7
	jb	.decode
	movzx	ecx,word [rsi]			; the first identity
	rol	cx,8
	add	rsi,2
	test	ecx,ecx
	jz	.decode
	lea	rax,[rsi+rcx+4]			; and its age
	cmp	rax,r8
	ja	.decode
	mov	[rbp+HL_IDP],rsi
	mov	[rbp+HL_IDLEN],ecx
	mov	rsi,r8
	mov	rax,rsi				; the binders: the transcript stops here
	sub	rax,r12
	mov	[rbp+HL_BINOFF],eax
	lea	rax,[rsi+2]
	cmp	rax,r14
	ja	.decode
	movzx	edx,word [rsi]
	rol	dx,8
	add	rsi,2
	lea	rax,[rsi+rdx]
	cmp	rax,r14
	jne	.decode
	cmp	edx,33
	jb	.decode
	movzx	ecx,byte [rsi]			; the first binder
	inc	rsi
	lea	rax,[rsi+rcx]
	cmp	rax,r14
	ja	.decode
	cmp	ecx,32
	jne	.ext_next			; not ours (another hash)
	mov	[rbp+HL_BINP],rsi
	or	dword [rbp+HL_GOT],G_PSK
	jmp	.ext_next

.groups:					; supported_groups: u16 length, u16s
	cmp	ecx,2
	jb	.decode
	movzx	edx,word [rsi]
	rol	dx,8
	add	rsi,2
	lea	rax,[rsi+rdx]
	cmp	rax,r14
	jne	.decode
	test	edx,1
	jnz	.decode
.group_item:
	cmp	rsi,r14
	jae	.ext_next
	cmp	word [rsi],0x1D00		; x25519
	jne	.grp_p256
	or	dword [rbp+HL_GOT],G_GROUP
	jmp	.grp_adv
.grp_p256:
	cmp	word [rsi],0x1700		; secp256r1
	jne	.grp_adv
	or	dword [rbp+HL_GOT],G_GROUP256
.grp_adv:
	add	rsi,2
	jmp	.group_item

.alpn:						; u16 length, { u8 length, name }
	cmp	ecx,2
	jb	.decode
	movzx	edx,word [rsi]
	rol	dx,8
	add	rsi,2
	lea	rax,[rsi+rdx]
	cmp	rax,r14
	jne	.decode
	or	dword [rbp+HL_GOT],G_ALPN
.protocol:
	cmp	rsi,r14
	jae	.ext_next
	movzx	ecx,byte [rsi]
	inc	rsi
	test	ecx,ecx
	jz	.decode
	lea	r8,[rsi+rcx]
	cmp	r8,r14
	ja	.decode
	cmp	ecx,8
	jne	.protocol_next
	mov	rax,'http/1.1'
	cmp	[rsi],rax
	jne	.protocol_next
	or	dword [rbp+HL_GOT],G_H1
.protocol_next:
	mov	rsi,r8
	jmp	.protocol

.ext_done:
	; the certificate for the name asked (SNI), before anything uses it; then
	; prefer ECDSA and fall back to RSA by what the client's ClientHello offers
	cmp	dword [rbp+HL_SNILEN],0
	je	.cert_default
	mov	rdi,[rbp+HL_TL]			; the listener's default entry
	mov	rsi,[rbp+HL_SNIP]
	mov	edx,[rbp+HL_SNILEN]
	call	tls_cert_named			; rax = entry (or 0), rdx = its sibling
	test	rax,rax
	jz	.cert_default
	mov	rdi,rax
	mov	rsi,rdx
	mov	edx,[rbp+HL_GOT]
	call	tls_cert_select			; prefer ECDSA, else RSA
	mov	[rbp+HL_TL],rax
	mov	[rbx+TS_CERT],rax		; the chosen cert (TLS 1.2 reads it too);
	jmp	.cert_done			; both siblings name the host for the 421 check
.cert_default:
	mov	rdi,[rbp+HL_TL]			; reload: tls_cert_named clobbers scratch
	call	tls_cert_sibling		; rdi preserved, rax = sibling or 0
	mov	rsi,rax
	mov	edx,[rbp+HL_GOT]
	call	tls_cert_select
	mov	[rbp+HL_TL],rax
.cert_done:
	mov	eax,[rbp+HL_GOT]
	test	eax,G_TLS13
	jz	.version
	test	eax,G_SUITE
	jz	.handshake
	mov	rcx,[rbp+HL_TL]
	cmp	dword [rcx+TL_KEYTYPE],1
	je	.req_rsa
	test	eax,G_SIGALG
	jz	.handshake
	jmp	.sig_ok
.req_rsa:
	test	eax,G_SIGALG_RSA
	jz	.handshake
.sig_ok:
	mov	dword [rbp+HL_GROUP],0		; the key-exchange group
	mov	dword [rbp+HL_KSEXT],40		; its key_share extension length
	test	eax,G_KS
	jnz	.have_share			; x25519 preferred
	test	eax,G_KS256
	jz	.no_share
	mov	dword [rbp+HL_GROUP],1		; secp256r1
	mov	dword [rbp+HL_KSEXT],73
.have_share:
	and	dword [rbx+TS_FLAGS],not TF_GOT_H1
	test	dword [rbx+TS_FLAGS],TF_ALPN_H1
	jz	.alpn_done
	test	eax,G_ALPN
	jz	.alpn_done
	test	eax,G_H1
	jz	.no_alpn			; RFC 7301: no protocol in common
	or	dword [rbx+TS_FLAGS],TF_GOT_H1
.alpn_done:
	call	tls_now_s
	mov	[rbp+HL_NOW],eax
	mov	eax,[rbp+HL_GOT]
	and	eax,G_PSK or G_PSKDHE
	cmp	eax,G_PSK or G_PSKDHE
	jne	.full
	cmp	qword [g_tks],0
	je	.full
	cmp	dword [rbp+HL_IDLEN],TK_SIZE
	jne	.full
	; open the ticket (a copy: the identity stays in the transcript)
	mov	rsi,[rbp+HL_IDP]
	lea	rdi,[rbp+HL_TICKET]
	mov	ecx,TK_SIZE
	rep	movsb
	mov	eax,[rbp+HL_TICKET+TK_ID]
	call	tls_ticket_key			; rdi = its key, or CF
	jc	.full				; another key, or retired: a full handshake
	lea	rsi,[rbp+HL_TICKET+TK_NONCE]
	lea	rdx,[rbp+HL_TICKET+TK_ID]
	mov	ecx,4
	lea	r8,[rbp+HL_TICKET+TK_SEALED]
	mov	r9d,TK_PT
	call	gcm_open
	test	eax,eax
	jz	.full
	cmp	byte [rbp+HL_TICKET+TK_SEALED+TKP_VERSION],1
	jne	.full
	mov	eax,[rbp+HL_NOW]
	sub	eax,[rbp+HL_TICKET+TK_SEALED+TKP_ISSUED]
	mov	ecx,[g_tk_life]
	add	ecx,ecx
	cmp	eax,ecx
	ja	.full				; expired
	mov	r15,[rbp+HL_TL]
	mov	rax,[r15+TL_PUB+1]
	cmp	rax,[rbp+HL_TICKET+TK_SEALED+TKP_CERT]
	jne	.full				; issued for another certificate
	lea	rsi,[rbp+HL_TICKET+TK_SEALED+TKP_PSK]
	lea	rdi,[rbp+HL_PSK]
	mov	ecx,32
	rep	movsb
	; the binder: HMAC over the ClientHello up to the binders (after the
	; retry's transcript, if there was one), with a key from the PSK
	lea	rdi,[rbp+HL_EARLY]
	lea	rsi,[tls13_zero32]
	mov	edx,32
	lea	rcx,[rbp+HL_PSK]
	mov	r8d,32
	call	hkdf_extract
	tls_label [rbp+HL_TMP], 32, [rbp+HL_EARLY], lbl_res_binder, [sha256_empty], 32
	tls_label [rbp+HL_SFK], 32, [rbp+HL_TMP], lbl_finished
	lea	rdi,[rbp+HL_SHA2]
	call	sha256_init
	test	dword [rbx+TS_FLAGS],TF_HRR
	jz	@f
	lea	rsi,[rbx+TS_HRR_SHA]
	lea	rdi,[rbp+HL_SHA2]
	mov	ecx,SHA256_CTX_SIZE
	rep	movsb
@@:
	lea	rdi,[rbp+HL_SHA2]
	mov	rsi,r12
	mov	edx,[rbp+HL_BINOFF]
	call	sha256_update
	lea	rdi,[rbp+HL_SHA2]
	lea	rsi,[rbp+HL_TH]
	call	sha256_final
	lea	rdi,[rbp+HL_DIG]
	lea	rsi,[rbp+HL_SFK]
	mov	edx,32
	lea	rcx,[rbp+HL_TH]
	mov	r8d,32
	call	hmac_sha256
	lea	rdi,[rbp+HL_DIG]
	mov	rsi,[rbp+HL_BINP]
	mov	edx,32
	call	ct_equal
	test	eax,eax
	jz	.bad_binder
	or	dword [rbp+HL_GOT],G_RESUME
.full:

	; the transcript starts with the ClientHello, or after a retry with
	; what the first one left
	test	dword [rbx+TS_FLAGS],TF_HRR
	jnz	.second_hello
	lea	rdi,[rbp+HL_SHA]
	call	sha256_init
	jmp	.hello_hashed
.second_hello:
	lea	rsi,[rbx+TS_HRR_SHA]
	lea	rdi,[rbp+HL_SHA]
	mov	ecx,SHA256_CTX_SIZE
	rep	movsb
.hello_hashed:
	lea	rdi,[rbp+HL_SHA]
	mov	rsi,r12
	mov	edx,[rbp+HL_MLEN]
	call	sha256_update

	; server random and the ephemeral x25519 key
	lea	rdi,[rbp+HL_RAND]
	mov	esi,80
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	cmp	rax,80
	jne	.internal
	cmp	dword [rbp+HL_GROUP],0
	jne	.eph_p256
	; x25519: the ephemeral public and the shared secret
	lea	rdi,[rbp+HL_PUB]
	lea	rsi,[rbp+HL_RAND+32]
	call	x25519_base			; the fixed-base table: a third of the ladder
	lea	rdi,[rbp+HL_SHARED]
	lea	rsi,[rbp+HL_RAND+32]
	lea	rdx,[rbp+HL_KS]
	call	x25519
	mov	rax,[rbp+HL_SHARED]		; an all-zero secret: a small-order point
	or	rax,[rbp+HL_SHARED+8]
	or	rax,[rbp+HL_SHARED+16]
	or	rax,[rbp+HL_SHARED+24]
	jz	.illegal
	jmp	.eph_done
.eph_p256:
	; secp256r1: scalar * G for the public key, scalar * peer for the secret
	lea	rdi,[rbp+HL_PUB256]
	lea	rsi,[rbp+HL_RAND+32]
	call	p256_public
	lea	rdi,[rbp+HL_SHARED]
	lea	rsi,[rbp+HL_RAND+32]
	lea	rdx,[rbp+HL_PEER256]
	call	p256_ecdh
	test	eax,eax
	jz	.illegal			; the peer point was invalid
.eph_done:

	; ServerHello, its record header first
	mov	edx,[rbp+HL_SIDLEN]
	add	edx,50
	add	edx,[rbp+HL_KSEXT]		; the record's length (one message)
	test	dword [rbp+HL_GOT],G_RESUME
	jz	@f
	add	edx,6				; + pre_shared_key
@@:
	mov	[rbp+HL_SHLEN],edx
	mov	rdi,r12
	mov	byte [rdi],22
	mov	word [rdi+1],0x0303
	mov	[rdi+3],dh
	mov	[rdi+4],dl
	mov	byte [rdi+5],2			; server_hello
	lea	ecx,[rdx-4]
	put24	rdi+6, ecx
	mov	word [rdi+9],0x0303
	add	rdi,11
	lea	rsi,[rbp+HL_RAND]
	mov	ecx,32
	rep	movsb
	mov	ecx,[rbp+HL_SIDLEN]
	mov	[rdi],cl
	inc	rdi
	lea	rsi,[rbp+HL_SID]
	rep	movsb
	mov	dword [rdi],0x00000113		; the suite, null compression, ...
	mov	eax,[rbp+HL_SHLEN]
	sub	eax,[rbp+HL_SIDLEN]
	sub	eax,44
	mov	[rdi+4],al			; ... the extensions' length
	mov	dword [rdi+5],0x02002B00	; supported_versions: TLS 1.3
	mov	word [rdi+9],0x0403
	add	rdi,11
	; key_share: the negotiated group and the server's public key
	mov	word [rdi],0x3300		; extension type key_share (0x0033)
	mov	eax,[rbp+HL_KSEXT]
	sub	eax,4				; the extension body length
	rol	ax,8
	mov	[rdi+2],ax
	cmp	dword [rbp+HL_GROUP],0
	jne	.sh_p256
	mov	dword [rdi+4],0x2000_1D00	; x25519, 32 bytes
	add	rdi,8
	lea	rsi,[rbp+HL_PUB]
	mov	ecx,32
	rep	movsb
	jmp	.sh_ks_done
.sh_p256:
	mov	dword [rdi+4],0x4100_1700	; secp256r1, 65 bytes
	add	rdi,8
	lea	rsi,[rbp+HL_PUB256]
	mov	ecx,65
	rep	movsb
.sh_ks_done:
	test	dword [rbp+HL_GOT],G_RESUME
	jz	@f
	mov	dword [rdi],0x02002900		; pre_shared_key: identity 0
	mov	word [rdi+4],0
	add	rdi,6
@@:
	mov	[rbp+HL_W],rdi
	lea	rsi,[r12+5]
	mov	edx,[rbp+HL_SHLEN]
	th_add
	th_snapshot				; H(ClientHello..ServerHello)

	; the handshake secrets; resumed, the early secret is the PSK's
	lea	rsi,[tls13_derived_early]
	test	dword [rbp+HL_GOT],G_RESUME
	jz	@f
	tls_label [rbp+HL_TMP], 32, [rbp+HL_EARLY], lbl_derived, [sha256_empty], 32
	lea	rsi,[rbp+HL_TMP]
@@:
	lea	rdi,[rbp+HL_HS]
	mov	edx,32
	lea	rcx,[rbp+HL_SHARED]
	mov	r8d,32
	call	hkdf_extract
	tls_label [rbp+HL_CHT], 32, [rbp+HL_HS], lbl_c_hs, [rbp+HL_TH], 32
	tls_label [rbp+HL_SHT], 32, [rbp+HL_HS], lbl_s_hs, [rbp+HL_TH], 32
	tls_label [rbp+HL_TMP], 32, [rbp+HL_HS], lbl_derived, [sha256_empty], 32
	lea	rdi,[rbp+HL_MS]
	lea	rsi,[rbp+HL_TMP]
	mov	edx,32
	lea	rcx,[tls13_zero32]
	mov	r8d,32
	call	hkdf_extract
	tls_label [rbp+HL_SKEY], 16, [rbp+HL_SHT], lbl_key
	tls_label [rbp+HL_SIV], 12, [rbp+HL_SHT], lbl_iv
	tls_label [rbx+TS_CHS_KEY], 16, [rbp+HL_CHT], lbl_key
	tls_label [rbx+TS_CHS_IV], 12, [rbp+HL_CHT], lbl_iv
	tls_label [rbp+HL_SFK], 32, [rbp+HL_SHT], lbl_finished
	tls_label [rbp+HL_CFK], 32, [rbp+HL_CHT], lbl_finished

	; middlebox compatibility (RFC 8446 D.4): a ChangeCipherSpec after the
	; ServerHello when the client sent a session id
	mov	rdi,[rbp+HL_W]
	cmp	dword [rbp+HL_SIDLEN],0
	je	@f
	test	dword [rbx+TS_FLAGS],TF_HRR
	jnz	@f				; it went after the HelloRetryRequest
	mov	dword [rdi],0x00030314
	mov	word [rdi+4],0x0101
	add	rdi,6
	mov	[rbp+HL_W],rdi
@@:

	; The encrypted messages, built at the end of out: r13 = their start,
	; r14 = the cursor.
	mov	r15,[rbp+HL_TL]
	mov	ecx,[r15+TL_CLEN]
	lea	eax,[rcx+192]			; EE + Certificate + CV + Finished
	cmp	dword [r15+TL_KEYTYPE],1		; an RSA CertificateVerify carries
	jne	@f				; an nbytes signature, not ~72 for ECDSA
	add	eax,[r15+TL_RSA_NLEN]
@@:
	mov	edx,[rbp+HL_ROOM]
	sub	edx,eax
	and	edx,not 15
	lea	r13,[r12+rdx]
	lea	rdx,[rdi+rax+256]		; the records (at most two) and a ticket's
	cmp	rdx,r13
	ja	.internal
	mov	r14,r13
	; EncryptedExtensions
	test	dword [rbx+TS_FLAGS],TF_GOT_H1
	jz	.ee_empty
	mov	dword [r14],0x11000008		; 17 bytes:
	mov	dword [r14+4],0x10000F00	; 15 of extensions: ALPN,
	mov	dword [r14+8],0x09000B00	; 11 bytes, a 9-byte list,
	mov	byte [r14+12],8
	mov	rax,'http/1.1'
	mov	[r14+13],rax
	add	r14,21
	jmp	.ee_done
.ee_empty:
	mov	dword [r14],0x02000008
	mov	word [r14+4],0
	add	r14,6
.ee_done:
	test	dword [rbp+HL_GOT],G_RESUME
	jz	.certificate
	mov	rsi,r13				; resumed: no Certificate, no CertificateVerify
	mov	rdx,r14
	sub	rdx,r13
	th_add
	th_snapshot
	jmp	.finished
.certificate:
	; Certificate: empty context, the certificate_list as loaded
	mov	byte [r14],11
	mov	ecx,[r15+TL_CLEN]
	add	ecx,4
	put24	r14+1, ecx
	mov	byte [r14+4],0
	mov	ecx,[r15+TL_CLEN]
	put24	r14+5, ecx
	lea	rdi,[r14+8]
	mov	esi,[r15+TL_CHAIN]
	lea	rsi,[g_tls_store+rsi]
	rep	movsb
	mov	rsi,r13
	mov	rdx,rdi
	sub	rdx,r13
	mov	r14,rdi
	th_add
	th_snapshot				; H(ClientHello..Certificate)
	; CertificateVerify: ECDSA over 64 spaces | context | 0 | the hash
	lea	rsi,[tls13_cv_prefix]
	lea	rdi,[rbp+HL_CV]
	mov	ecx,TLS13_CV_PREFIX
	rep	movsb
	lea	rsi,[rbp+HL_TH]
	mov	ecx,32
	rep	movsb
	lea	rdi,[rbp+HL_DIG]
	lea	rsi,[rbp+HL_CV]
	mov	edx,TLS13_CV_PREFIX + 32
	call	sha256
	cmp	dword [r15+TL_KEYTYPE],1
	je	.cv_rsa
	lea	rdi,[rbp+HL_SIG]
	lea	rsi,[r15+TL_KEY]
	lea	rdx,[rbp+HL_DIG]
	call	p256_sign
	test	eax,eax
	jz	.internal
	lea	rdi,[r14+8]
	lea	rsi,[rbp+HL_SIG]
	call	ecdsa_der
	mov	byte [r14],15
	lea	ecx,[rax+4]
	mov	edx,eax
	put24	r14+1, ecx
	mov	word [r14+4],0x0304		; ecdsa_secp256r1_sha256
	jmp	.cv_len
.cv_rsa:
	lea	rdi,[r14+8]			; RSA-PSS signature, written in place
	lea	rsi,[r15+TL_RSA_N]
	mov	edx,[r15+TL_RSA_NLEN]
	lea	rcx,[r15+TL_RSA_D]
	lea	r8,[rbp+HL_DIG]
	call	rsa_pss_sign
	mov	byte [r14],15
	mov	eax,[r15+TL_RSA_NLEN]
	lea	ecx,[rax+4]
	mov	edx,eax
	put24	r14+1, ecx
	mov	word [r14+4],0x0408		; rsa_pss_rsae_sha256
.cv_len:
	rol	dx,8
	mov	[r14+6],dx
	rol	dx,8
	mov	rsi,r14
	add	edx,8
	add	r14,rdx
	th_add
	th_snapshot				; H(ClientHello..CertificateVerify)
.finished:
	mov	dword [r14],0x20000014
	lea	rdi,[r14+4]
	lea	rsi,[rbp+HL_SFK]
	mov	edx,32
	lea	rcx,[rbp+HL_TH]
	mov	r8d,32
	call	hmac_sha256
	mov	rsi,r14
	mov	edx,36
	add	r14,36
	th_add
	th_snapshot				; H(ClientHello..server Finished)

	; the application secrets and the client Finished to expect
	tls_label [rbp+HL_TMP], 32, [rbp+HL_MS], lbl_c_ap, [rbp+HL_TH], 32
	tls_label [rbx+TS_RX_KEY], 16, [rbp+HL_TMP], lbl_key
	tls_label [rbx+TS_RX_IV], 12, [rbp+HL_TMP], lbl_iv
	tls_label [rbp+HL_TMP], 32, [rbp+HL_MS], lbl_s_ap, [rbp+HL_TH], 32
	tls_label [rbx+TS_TX_KEY], 16, [rbp+HL_TMP], lbl_key
	tls_label [rbx+TS_TX_IV], 12, [rbp+HL_TMP], lbl_iv
	lea	rdi,[rbx+TS_CFIN]
	lea	rsi,[rbp+HL_CFK]
	mov	edx,32
	lea	rcx,[rbp+HL_TH]
	mov	r8d,32
	call	hmac_sha256
	xor	eax,eax
	mov	[rbx+TS_RX_SEQ],rax
	mov	[rbx+TS_TX_SEQ],rax
	cmp	qword [g_tks],0
	je	.no_ticket
	; the ticket: resumption_master_secret over the transcript through the
	; client Finished we expect, the PSK from it, sealed with the key
	mov	dword [rbp+HL_CV],0x20000014
	lea	rsi,[rbx+TS_CFIN]
	lea	rdi,[rbp+HL_CV+4]
	mov	ecx,32
	rep	movsb
	lea	rsi,[rbp+HL_CV]
	mov	edx,36
	th_add
	th_snapshot
	tls_label [rbp+HL_TMP], 32, [rbp+HL_MS], lbl_res_master, [rbp+HL_TH], 32
	lea	rdi,[rbp+HL_TICKET]
	mov	ecx,TK_SIZE
	xor	eax,eax
	rep	stosb
	tls_label [rbp+HL_TICKET+TK_SEALED+TKP_PSK], 32, [rbp+HL_TMP], lbl_resumption
	mov	byte [rbp+HL_TICKET+TK_SEALED+TKP_VERSION],1
	mov	eax,[rbp+HL_NOW]
	mov	[rbp+HL_TICKET+TK_SEALED+TKP_ISSUED],eax
	mov	eax,[rbp+HL_RAND+76]
	mov	[rbp+HL_TICKET+TK_SEALED+TKP_AGE_ADD],eax
	mov	rax,[rbp+HL_TL]
	mov	rax,[rax+TL_PUB+1]
	mov	[rbp+HL_TICKET+TK_SEALED+TKP_CERT],rax
	lea	rsi,[rbp+HL_RAND+64]
	lea	rdi,[rbp+HL_TICKET+TK_NONCE]
	mov	ecx,12
	rep	movsb
	mov	rdi,[g_tks]			; the current key
	mov	eax,[rdi+TKS_CUR]
	imul	eax,eax,TKS_SLOT
	lea	rdi,[rdi+TKS_SLOTS+rax]
	mov	eax,[rdi+TKS_ID]
	mov	[rbp+HL_TICKET+TK_ID],eax
	add	rdi,TKS_GCM
	lea	rsi,[rbp+HL_TICKET+TK_NONCE]
	lea	rdx,[rbp+HL_TICKET+TK_ID]
	mov	ecx,4
	lea	r8,[rbp+HL_TICKET+TK_SEALED]
	mov	r9d,TK_PT
	call	gcm_seal
	or	dword [rbp+HL_GOT],G_TICKET
.no_ticket:

	; Seal them into records: r13 = plaintext left, r14 = its end,
	; r15 = the record being written.
	lea	rdi,[rbp+HL_GCM]
	lea	rsi,[rbp+HL_SKEY]
	call	gcm_init
	mov	r15,[rbp+HL_W]
.seal:
	mov	rcx,r14
	sub	rcx,r13
	jz	.sealed
	cmp	rcx,TLS_RECORD_MAX
	jbe	@f
	mov	ecx,TLS_RECORD_MAX
@@:
	mov	[rbp+HL_MLEN],ecx		; reused: this record's plaintext
	lea	edx,[rcx+17]			; + content type + tag
	mov	dword [r15],0x00030317
	rol	dx,8
	mov	[r15+3],dx
	lea	rdi,[r15+5]
	mov	rsi,r13
	rep	movsb
	mov	byte [rdi],22			; inner content type: handshake
	mov	r13,rsi
	lea	rdi,[rbp+HL_NONCE]
	lea	rsi,[rbp+HL_SIV]
	mov	rdx,[rbp+HL_SEQ]
	call	tls_nonce
	lea	rdi,[rbp+HL_GCM]
	lea	rsi,[rbp+HL_NONCE]
	mov	rdx,r15
	mov	ecx,5
	lea	r8,[r15+5]
	mov	r9d,[rbp+HL_MLEN]
	inc	r9d
	call	gcm_seal
	mov	eax,[rbp+HL_MLEN]
	lea	r15,[r15+rax+22]
	inc	qword [rbp+HL_SEQ]
	jmp	.seal
.sealed:
	test	dword [rbp+HL_GOT],G_TICKET
	jz	.flight_done
	; NewSessionTicket, under the server's application key (record 0)
	mov	rdi,r15
	mov	dword [rdi],0x00030317
	mov	word [rdi+3],0x7A00		; 105 + type + tag = 122
	mov	dword [rdi+5],0x65000004	; new_session_ticket, 101 bytes
	mov	eax,[g_tk_life]			; lifetime: at least this long
	bswap	eax
	mov	[rdi+9],eax
	mov	eax,[rbp+HL_RAND+76]
	mov	[rdi+13],eax			; ticket_age_add
	mov	byte [rdi+17],0			; no ticket_nonce
	mov	word [rdi+18],0x5800		; the ticket, 88 bytes
	lea	rsi,[rbp+HL_TICKET]
	add	rdi,20
	mov	ecx,TK_SIZE
	rep	movsb
	mov	word [rdi],0			; no extensions
	mov	byte [rdi+2],22			; inner content type: handshake
	lea	rdi,[rbp+HL_GCM]
	lea	rsi,[rbx+TS_TX_KEY]
	call	gcm_init
	lea	rdi,[rbp+HL_GCM]
	lea	rsi,[rbx+TS_TX_IV]		; sequence 0
	mov	rdx,r15
	mov	ecx,5
	lea	r8,[r15+5]
	mov	r9d,106
	call	gcm_seal
	add	r15,127
	mov	qword [rbx+TS_TX_SEQ],1		; the application records follow it
.flight_done:
	mov	rdx,r15
	sub	rdx,r12
	mov	eax,TH_SEND
	jmp	.out
.bad_binder:
	mov	ecx,AL_DECRYPT			; a ticket of ours, a binder that is not
	jmp	.alert

.no_share:
	; a group offered without its share: a HelloRetryRequest, once
	test	eax,G_GROUP or G_GROUP256
	jz	.handshake			; no group in common
	test	dword [rbx+TS_FLAGS],TF_HRR
	jnz	.illegal			; asked already, and still no share
	; transcript: message_hash(Hash(ClientHello1)), then the retry request
	lea	rdi,[rbp+HL_TH]
	mov	rsi,r12
	mov	edx,[rbp+HL_MLEN]
	call	sha256
	lea	rdi,[rbp+HL_SHA]
	call	sha256_init
	mov	dword [rbp+HL_CV],0x200000FE	; message_hash, 32 bytes
	lea	rsi,[rbp+HL_TH]
	lea	rdi,[rbp+HL_CV+4]
	mov	ecx,32
	rep	movsb
	lea	rsi,[rbp+HL_CV]
	mov	edx,36
	th_add
	; the HelloRetryRequest: a ServerHello with the special random
	mov	rdi,r12
	mov	edx,[rbp+HL_SIDLEN]
	add	edx,56
	mov	byte [rdi],22
	mov	word [rdi+1],0x0303
	mov	[rdi+3],dh
	mov	[rdi+4],dl
	mov	byte [rdi+5],2
	lea	ecx,[rdx-4]
	put24	rdi+6, ecx
	mov	word [rdi+9],0x0303
	add	rdi,11
	lea	rsi,[tls13_hrr_random]
	mov	ecx,32
	rep	movsb
	mov	ecx,[rbp+HL_SIDLEN]
	mov	[rdi],cl
	inc	rdi
	lea	rsi,[rbp+HL_SID]
	rep	movsb
	mov	dword [rdi],0x00000113		; the suite, null compression, ...
	mov	byte [rdi+4],12			; ... 12 bytes of extensions
	mov	dword [rdi+5],0x02002B00	; supported_versions: TLS 1.3
	mov	word [rdi+9],0x0403
	mov	dword [rdi+11],0x02003300	; key_share: a group, please
	mov	word [rdi+15],0x1D00		; x25519 by default
	test	dword [rbp+HL_GOT],G_GROUP
	jnz	@f
	mov	word [rdi+15],0x1700		; only secp256r1 offered
@@:
	add	rdi,17
	push	rdi
	lea	rsi,[r12+5]
	mov	edx,[rbp+HL_SIDLEN]
	add	edx,56
	th_add
	pop	rdi
	cmp	dword [rbp+HL_SIDLEN],0
	je	@f
	mov	dword [rdi],0x00030314		; middlebox compatibility: its CCS
	mov	word [rdi+4],0x0101
	add	rdi,6
@@:
	push	rdi
	lea	rsi,[rbp+HL_SHA]
	lea	rdi,[rbx+TS_HRR_SHA]
	mov	ecx,SHA256_CTX_SIZE
	rep	movsb
	pop	rdi
	or	dword [rbx+TS_FLAGS],TF_HRR
	mov	rdx,rdi
	sub	rdx,r12
	mov	eax,TH_RETRY
	jmp	.out
.more:
	xor	edx,edx
	mov	eax,TH_MORE
	jmp	.out
.not_handshake:
	cmp	byte [rsi],21			; the client's alert: just close
	jne	.unexpected
	xor	edx,edx
	mov	eax,TH_FAIL
	jmp	.out
.unexpected:
	mov	ecx,AL_UNEXPECTED
	jmp	.alert
.overflow:
	mov	ecx,AL_OVERFLOW
	jmp	.alert
.handshake:
	mov	ecx,AL_HANDSHAKE
	jmp	.alert
.illegal:
	mov	ecx,AL_ILLEGAL
	jmp	.alert
.decode:
	mov	ecx,AL_DECODE
	jmp	.alert
.version:
	mov	eax,TH_TLS12			; no TLS 1.3 offered: let the caller try 1.2
	xor	edx,edx
	jmp	.out
.no_alpn:
	mov	ecx,AL_NO_ALPN
	jmp	.alert
.internal:
	mov	ecx,AL_INTERNAL
.alert:
	mov	rdi,[rbp+HL_OUT]
	mov	dword [rdi],0x00030315		; alert record, 2 bytes: fatal, ecx
	mov	word [rdi+4],0x0202
	mov	[rdi+6],cl
	mov	edx,7
	mov	eax,TH_FAIL
.out:
	push	rax
	push	rdx
	mov	rdi,rbp				; wipe the frame
	mov	ecx,HL_SIZE
	call	secure_zero
	pop	rdx
	pop	rax
	add	rsp,HL_SIZE
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret


; ------------------------------------------------------------- finished

FN_GCM		:= 0
FN_NONCE	:= GCM_SIZE
FN_SIZE		:= GCM_SIZE + 16 + 8		; rsp 16-aligned at calls

tls_finished:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,FN_SIZE
	mov	rbx,rdi
	mov	r12,rsi
	lea	r13,[rsi+rcx]
	mov	r14,rsi
.record:
	mov	rax,r13
	sub	rax,r14
	cmp	rax,5
	jb	.more
	movzx	ecx,word [r14+3]
	rol	cx,8
	cmp	ecx,TLS_RECORD_MAX + 256
	ja	.fail
	lea	r15,[r14+5+rcx]			; the record's end
	cmp	r15,r13
	ja	.more
	cmp	byte [r14],20			; ChangeCipherSpec, compatibility mode
	je	.ccs
	cmp	byte [r14],23			; application_data: an encrypted record
	jne	.fail				; (a plaintext alert too)
	cmp	ecx,17
	jb	.fail
	lea	rdi,[rsp+FN_GCM]
	lea	rsi,[rbx+TS_CHS_KEY]
	call	gcm_init
	lea	rdi,[rsp+FN_GCM]
	lea	rsi,[rbx+TS_CHS_IV]		; the first record: sequence 0
	mov	rdx,r14
	mov	ecx,5
	lea	r8,[r14+5]
	lea	r9,[r15-16]
	sub	r9,r8
	call	gcm_open
	test	eax,eax
	jz	.fail
	; the inner plaintext: content, its type, zero padding
	lea	rdi,[r15-17]
	lea	rsi,[r14+5]
.unpad:
	cmp	rdi,rsi
	jb	.fail				; all zeros: no content type
	cmp	byte [rdi],0
	jne	@f
	dec	rdi
	jmp	.unpad
@@:
	cmp	byte [rdi],22			; handshake
	jne	.fail				; (an alert from the client)
	sub	rdi,rsi
	cmp	rdi,36				; Finished, and nothing else
	jne	.fail
	cmp	dword [rsi],0x20000014
	jne	.fail
	lea	rdi,[rsi+4]
	lea	rsi,[rbx+TS_CFIN]
	mov	edx,32
	call	ct_equal
	test	eax,eax
	jz	.fail
	mov	rdx,r15
	sub	rdx,r12
	mov	eax,TH_DONE
	jmp	.out
.ccs:
	cmp	ecx,1
	jne	.fail
	cmp	byte [r14+5],1
	jne	.fail
	mov	r14,r15
	jmp	.record
.more:
	xor	edx,edx
	mov	eax,TH_MORE
	jmp	.keep
.fail:
	xor	edx,edx
	mov	eax,TH_FAIL
.out:
	; the handshake keys are done with, either way
	push	rax
	push	rdx
	lea	rdi,[rbx+TS_CHS_KEY]
	mov	ecx,TS_RX_KEY - TS_CHS_KEY
	call	secure_zero
	pop	rdx
	pop	rax
.keep:
	push	rax
	push	rdx
	lea	rdi,[rsp+16+FN_GCM]
	mov	ecx,GCM_SIZE
	call	secure_zero
	pop	rdx
	pop	rax
	add	rsp,FN_SIZE
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; ------------------------------------------------- user-space records
; When the kernel's TLS is not there: records sealed and opened here.

; rdi = ts: the application keys expanded for tls_seal and tls_open.
tls_records:
	push	rbx
	mov	rbx,rdi
	lea	rdi,[rbx+TS_RX_GCM]
	lea	rsi,[rbx+TS_RX_KEY]
	call	gcm_init
	lea	rdi,[rbx+TS_TX_GCM]
	lea	rsi,[rbx+TS_TX_KEY]
	call	gcm_init
	pop	rbx
	ret

; rdi = ts, rsi = record (5 bytes for the header, then the plaintext),
; edx = plaintext length (<= TLS_RECORD_MAX), ecx = content type: the
; record sealed in place, eax = its length (plaintext + 22).
tls_seal:
	push	rbx
	push	r12
	push	r13
	sub	rsp,16
	mov	rbx,rdi
	mov	r12,rsi
	mov	r13d,edx
	mov	[rsi+5+rdx],cl
	lea	eax,[rdx+17]
	mov	dword [rsi],0x00030317
	mov	[rsi+3],ah
	mov	[rsi+4],al
	mov	rdi,rsp
	lea	rsi,[rbx+TS_TX_IV]
	mov	rdx,[rbx+TS_TX_SEQ]
	call	tls_nonce
	inc	qword [rbx+TS_TX_SEQ]
	lea	rdi,[rbx+TS_TX_GCM]
	mov	rsi,rsp
	mov	rdx,r12
	mov	ecx,5
	lea	r8,[r12+5]
	lea	r9d,[r13+1]
	call	gcm_seal
	lea	eax,[r13+22]
	add	rsp,16
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = ts, rsi = received bytes, edx = their length: the first record
; opened in place. eax = TH_MORE (incomplete), TH_FAIL (forged, or not a
; record), or TH_DONE with rsi = its plaintext, ecx = the plaintext
; length, r8d = the content type, edx = the bytes it took.
tls_open:
	push	rbx
	push	r12
	push	r13
	sub	rsp,16
	mov	rbx,rdi
	mov	r12,rsi
	cmp	edx,5
	jb	.more
	cmp	byte [rsi],23
	jne	.fail
	movzx	ecx,word [rsi+3]
	rol	cx,8
	cmp	ecx,TLS_RECORD_MAX + 256
	ja	.fail
	cmp	ecx,17
	jb	.fail
	lea	r13d,[rcx+5]			; the record's length
	cmp	edx,r13d
	jb	.more
	mov	rdi,rsp
	lea	rsi,[rbx+TS_RX_IV]
	mov	rdx,[rbx+TS_RX_SEQ]
	call	tls_nonce
	lea	rdi,[rbx+TS_RX_GCM]
	mov	rsi,rsp
	mov	rdx,r12
	mov	ecx,5
	lea	r8,[r12+5]
	lea	r9d,[r13-21]
	call	gcm_open
	test	eax,eax
	jz	.fail
	inc	qword [rbx+TS_RX_SEQ]
	lea	rsi,[r12+5]
	lea	rdi,[r12+r13-17]
.unpad:
	cmp	rdi,rsi
	jb	.fail
	movzx	r8d,byte [rdi]
	test	r8d,r8d
	jnz	@f
	dec	rdi
	jmp	.unpad
@@:
	mov	rcx,rdi
	sub	rcx,rsi
	mov	edx,r13d
	mov	eax,TH_DONE
	jmp	.out
.more:
	mov	eax,TH_MORE
	jmp	.out
.fail:
	mov	eax,TH_FAIL
.out:
	add	rsp,16
	pop	r13
	pop	r12
	pop	rbx
	ret

; eax = seconds on CLOCK_MONOTONIC: ticket ages.
tls_now_s:
	sub	rsp,24
	mov	edi,CLOCK_MONOTONIC
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	mov	eax,[rsp]
	add	rsp,24
	ret

; The ticket keys, once (in the supervisor, before the workers fork, so
; they all share the page; kept across reloads). Without them no ticket is
; issued or taken.
tls_tickets_init:
	cmp	qword [g_tks],0
	jne	.done
	mov	dword [g_tk_period],TICKET_ROTATE
	lea	rdi,[env_okena_ticket_rotate]
	mov	esi,env_okena_ticket_rotate.len
	call	getenv
	test	rax,rax
	jz	.mapped_period
	xor	ecx,ecx				; seconds, for tests
.digit:
	movzx	edx,byte [rax]
	sub	edx,'0'
	cmp	edx,9
	ja	.digits
	imul	ecx,ecx,10
	add	ecx,edx
	inc	rax
	jmp	.digit
.digits:
	test	ecx,ecx
	jz	.mapped_period
	mov	[g_tk_period],ecx
.mapped_period:
	xor	edi,edi
	mov	esi,4096
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_ANONYMOUS
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.done				; no page: no tickets
	mov	[g_tks],rax
	mov	eax,[g_tk_period]
	mov	[g_tk_life],eax
	xor	edi,edi
	call	tls_ticket_fill
	call	tls_now_s
	add	eax,[g_tk_period]
	mov	[g_tk_next],eax
.done:
	ret

; Supervisor, once a second: a new key when the period is over.
tls_tickets_tick:
	cmp	qword [g_tks],0
	je	.done
	cmp	dword [g_tk_fixed],0
	jne	.done				; the file's keys: rotated by whoever writes it
	call	tls_now_s
	cmp	eax,[g_tk_next]
	jb	.done
	add	eax,[g_tk_period]
	mov	[g_tk_next],eax
	mov	rax,[g_tks]
	mov	edi,[rax+TKS_CUR]
	inc	edi
	cmp	edi,3
	jb	@f
	xor	edi,edi
@@:
	push	rdi
	call	tls_ticket_fill
	pop	rdi
	mov	rax,[g_tks]
	mov	[rax+TKS_CUR],edi		; after the slot is whole (x86 keeps the order)
.done:
	ret

; edi = slot: a new key in it (its id last, so a half-written slot never
; matches a ticket).
tls_ticket_fill:
	push	rbx
	sub	rsp,32
	push	rdi
	lea	rdi,[rsp+8]
	mov	esi,20
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	pop	rdi
	cmp	rax,20
	jne	.empty				; left empty: its tickets just do not resume
	mov	rsi,rsp
	call	tls_ticket_set
	jmp	.out
.empty:
	imul	eax,edi,TKS_SLOT
	mov	rbx,[g_tks]
	mov	dword [rbx+TKS_SLOTS+rax+TKS_ID],0
.out:
	mov	rdi,rsp
	mov	ecx,32
	call	secure_zero
	add	rsp,32
	pop	rbx
	ret

; edi = slot, rsi = key (16) then id (4): the slot holds that key; its id
; is written last (0 means empty, so 1 is or-ed in).
tls_ticket_set:
	push	rbx
	push	r12
	sub	rsp,8
	imul	eax,edi,TKS_SLOT
	mov	rbx,[g_tks]
	lea	rbx,[rbx+TKS_SLOTS+rax]
	mov	r12,rsi
	mov	dword [rbx+TKS_ID],0
	lea	rdi,[rbx+TKS_GCM]
	call	gcm_init
	mov	eax,[r12+16]
	or	eax,1
	mov	[rbx+TKS_ID],eax
	add	rsp,8
	pop	r12
	pop	rbx
	ret

; eax = a ticket's key id: rdi = the current or previous key's context
; with that id, or CF.
tls_ticket_key:
	mov	rdi,[g_tks]
	mov	ecx,[rdi+TKS_CUR]
	mov	edx,2				; the current, then the one before
.slot:
	imul	r8d,ecx,TKS_SLOT
	lea	r8,[rdi+TKS_SLOTS+r8]
	cmp	dword [r8+TKS_ID],0
	je	.next
	cmp	[r8+TKS_ID],eax
	je	.found
.next:
	add	ecx,2				; (slot + 2) mod 3 = the previous
	cmp	ecx,3
	jb	@f
	sub	ecx,3
@@:
	dec	edx
	jnz	.slot
	stc
	ret
.found:
	lea	rdi,[r8+TKS_GCM]
	clc
	ret

cstring env_okena_ticket_rotate, 'OKENA_TICKET_ROTATE='

; ------------------------------------------------------- passthrough
;
; rdi = what the client sent, esi = its length, rdx = scratch (CH_MAX):
; the server_name of its ClientHello, without taking part in the
; handshake. eax = TH_MORE (incomplete), TH_FAIL (not a TLS ClientHello),
; or TH_DONE with rsi = the name (in scratch) and ecx = its length (0 when
; it sent none).
tls_sni_peek:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdx				; the message, gathered
	lea	r13,[rdi+rsi]			; the end of input
	mov	rsi,rdi
	mov	rdi,rdx
	xor	ebx,ebx				; bytes gathered
.record:
	mov	rax,r13
	sub	rax,rsi
	cmp	rax,5
	jb	.more
	cmp	byte [rsi],22
	jne	.fail
	movzx	ecx,word [rsi+3]
	rol	cx,8
	test	ecx,ecx
	jz	.fail
	cmp	ecx,TLS_RECORD_MAX
	ja	.fail
	sub	rax,5
	cmp	rax,rcx
	jb	.more
	lea	eax,[rbx+rcx]
	cmp	eax,CH_MAX
	ja	.fail
	add	rsi,5
	mov	ebx,eax
	rep	movsb
	cmp	ebx,4
	jb	.record
	cmp	byte [r12],1			; client_hello
	jne	.fail
	mov	eax,[r12]
	bswap	eax
	and	eax,0xFFFFFF
	add	eax,4
	cmp	eax,CH_MAX
	ja	.fail
	cmp	ebx,eax
	jb	.record
	; parse just far enough: r13 = the message's end
	lea	r13,[r12+rax]
	lea	rsi,[r12+4+34]
	cmp	rsi,r13
	jae	.fail
	movzx	eax,byte [rsi]			; session id
	lea	rsi,[rsi+rax+1]
	lea	rax,[rsi+2]
	cmp	rax,r13
	ja	.fail
	movzx	eax,word [rsi]			; cipher suites
	rol	ax,8
	lea	rsi,[rsi+rax+2]
	cmp	rsi,r13
	jae	.fail
	movzx	eax,byte [rsi]			; compression
	lea	rsi,[rsi+rax+1]
	lea	rax,[rsi+2]
	cmp	rax,r13
	ja	.none				; no extensions: no name
	add	rsi,2
.ext:
	lea	rax,[rsi+4]
	cmp	rax,r13
	ja	.none
	movzx	eax,word [rsi]
	movzx	ecx,word [rsi+2]
	rol	cx,8
	add	rsi,4
	lea	rdx,[rsi+rcx]
	cmp	rdx,r13
	ja	.fail
	test	eax,eax
	jz	.server_name
	mov	rsi,rdx
	jmp	.ext
.server_name:
	cmp	ecx,5
	jb	.fail
	cmp	byte [rsi+2],0			; host_name
	jne	.none
	movzx	ecx,word [rsi+3]
	rol	cx,8
	lea	rax,[rsi+5+rcx]
	cmp	rax,rdx
	ja	.fail
	add	rsi,5
	mov	eax,TH_DONE
	jmp	.out
.none:
	xor	ecx,ecx
	mov	eax,TH_DONE
	jmp	.out
.more:
	mov	eax,TH_MORE
	jmp	.out
.fail:
	mov	eax,TH_FAIL
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret
