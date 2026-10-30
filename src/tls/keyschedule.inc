; TLS 1.3 key schedule (RFC 8446 §7.1): the constants and labels shared by
; the server handshake (src/tls/handshake.inc) and the client handshake
; (src/tls/client.inc), plus the two macros both use. No dependency on the
; configuration layer, so a test harness includes it alone.

rodata
	; HKDF-Extract(0, 0) and Derive-Secret(that, "derived", ""): without a
	; PSK they never change
	tls13_derived_early	db 0x6f,0x26,0x15,0xa1,0x08,0xc7,0x02,0xc5,0x67,0x8f,0x54,0xfc,0x9d,0xba,0xb6,0x97
				db 0x16,0xc0,0x76,0x18,0x9c,0x48,0x25,0x0c,0xeb,0xea,0xc3,0x57,0x6c,0x36,0x11,0xba
	sha256_empty		db 0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24
				db 0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
	tls13_zero32		db 32 dup 0
	lbl_c_hs		db 'c hs traffic',0
	lbl_s_hs		db 's hs traffic',0
	lbl_c_ap		db 'c ap traffic',0
	lbl_s_ap		db 's ap traffic',0
	lbl_derived		db 'derived',0
	lbl_key			db 'key',0
	lbl_iv			db 'iv',0
	lbl_finished		db 'finished',0
	lbl_res_master		db 'res master',0
	lbl_resumption		db 'resumption',0
	lbl_res_binder		db 'res binder',0
end rodata

; tls13_expand_label(out, n, secret, label, context, context length)
macro tls_label out*, n*, secret*, label*, ctx, clen
	lea	rdi,out
	mov	esi,n
	lea	rdx,secret
	lea	rcx,[label]
	match , ctx
		xor	r8d,r8d
		xor	r9d,r9d
	else
		lea	r8,ctx
		mov	r9d,clen
	end match
	call	tls13_expand_label
end macro

; base: a register; value: a 32-bit register or a number. Big endian,
; three bytes. Clobbers eax.
macro put24 base*, value*
	mov	eax,value
	mov	[base+2],al
	shr	eax,8
	mov	[base+1],al
	shr	eax,8
	mov	[base],al
end macro

; rdi = nonce[12], rsi = iv[12], rdx = record sequence number: the IV with
; the sequence number XORed into its last 8 bytes (RFC 8446 5.3).
tls_nonce:
	mov	eax,[rsi]
	mov	[rdi],eax
	mov	rax,[rsi+4]
	bswap	rdx
	xor	rax,rdx
	mov	[rdi+4],rax
	ret
