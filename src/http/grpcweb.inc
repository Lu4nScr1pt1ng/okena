; gRPC-Web for browsers (the gRPC-Web protocol, binary mode): a request whose
; content-type is application/grpc-web[+proto|+json...], to a pool that speaks
; HTTP/2, goes to it as gRPC (content-type application/grpc..., and te: trailers,
; as every request to HTTP/2 backends has); its answer comes back as gRPC-Web:
; content-type application/grpc-web..., the messages as they are, and the gRPC
; trailers (grpc-status, grpc-message, the rest) as the last message, a trailer
; frame (a byte 0x80, a length, the lines), since a browser cannot read HTTP
; trailers. An answer with no body (trailers only: grpc-status in its head) is
; passed as it is, as gRPC-Web allows. Over HTTP/1.1, 2 and 3 alike.
;
; To a pool of HTTP/1.1 (a backend that speaks gRPC-Web itself, Envoy's way), and
; the text mode (application/grpc-web-text, base64), nothing is changed. CORS is
; the route's `cors`, as for any other request from a page.

HB_GWEB		:= HB_LTEXT_H + H_LTEXT_H_CAP	; b: 0 none, 1 gRPC-Web passed on as it is,
						; 2 turned into gRPC, 3 gRPC-Web (binary), the pool not yet known
						; (the byte past the host's text, which never reaches it)

; In http_grpc_mark, rdi = the content-type field (application/grpc...): HB_GWEB.
; Keeps rbx, r12-r15.
gweb_mark:
	mov	rax,[r15+H_BUF]
	mov	byte [rax+HB_GWEB],0
	mov	ecx,[rdi+HF_VLEN]
	cmp	ecx,20
	jb	.out
	mov	rsi,[rdi+HF_VALUE]
	mov	edx,[rsi+16]
	or	edx,0x20202000
	cmp	edx,'-web'
	jne	.out
	mov	byte [rax+HB_GWEB],1		; what follows not +x or -text: as it is
	cmp	ecx,20
	je	.binary
	cmp	byte [rsi+20],'+'
	je	.binary
	cmp	ecx,25				; -web-text[+x]
	jb	.out
	mov	edx,[rsi+20]
	or	edx,0x20202000
	cmp	edx,'-tex'
	jne	.out
	mov	dl,[rsi+24]
	or	dl,0x20
	cmp	dl,'t'
	jne	.out
	cmp	ecx,25
	je	.text
	cmp	byte [rsi+25],'+'
	jne	.out
.text:
	mov	byte [rax+HB_GWEB],5
	ret
.binary:
	mov	byte [rax+HB_GWEB],3
.out:
	ret

; In http_write_request_head: HB_GWEB 3 becomes 2 when the pool speaks HTTP/2,
; else 1. Keeps all but rax, rcx.
gweb_pool:
	mov	rax,[r15+H_BUF]
	cmp	byte [rax+HB_GWEB],3
	je	@f
	cmp	byte [rax+HB_GWEB],5
	jne	.out
@@:
	push	rax
	call	session_ptr
	mov	eax,[rax+S_POOL]
	imul	rax,rax,PL_SIZE
	mov	ecx,[g_pools+rax+PL_H2]
	pop	rax
	test	ecx,ecx
	jz	.passed
	dec	byte [rax+HB_GWEB]		; 3: 2, 5: 4
	mov	dword [rax+HB_GWT+GWT_RCN],0	; (nothing kept yet, either way)
	mov	dword [rax+HB_GWT+GWT_SCN],0
	ret
.passed:
	mov	byte [rax+HB_GWEB],1
.out:
	ret

; A field being copied (r14), rdi = where, r13 = the room's end, edx = 0 the
; request's (towards the backend), 1 the answer's: CF when it was written here,
; its content-type as gRPC (request) or gRPC-Web (answer); rdi past it.
gweb_field:
	mov	rax,[r15+H_BUF]
	movzx	r11d,byte [rax+HB_GWEB]
	cmp	r11d,2
	je	@f
	cmp	r11d,4
	jne	.no
	test	edx,edx				; text, the request's: its Content-Length
	jnz	@f				; is the base64's, not passed on
	push	rdx
	push	rdi
	mov	rdi,r14
	lea	rsi,[hn_content_length]
	call	hf_is
	pop	rdi
	pop	rdx
	jz	.dropped
@@:
	push	rdx
	push	rdi
	mov	rdi,r14
	lea	rsi,[hn_content_type]
	call	hf_is
	pop	rdi
	pop	rdx
	jnz	.no
	mov	ecx,[r14+HF_VLEN]
	cmp	ecx,16
	jb	.no
	lea	rax,[rdi+rcx+32]
	cmp	rax,r13
	ja	.no
	mov	rsi,[r14+HF_VALUE]
	push	rsi
	push	rcx
	lea	rsi,[.ct]
	mov	ecx,.ct_len
	rep	movsb				; content-type: application/grpc
	pop	rcx
	pop	rsi
	add	rsi,16
	sub	ecx,16
	mov	r10d,4				; -web, or -web-text
	cmp	r11d,4
	jne	@f
	mov	r10d,9
@@:
	test	edx,edx
	jnz	.answer
	cmp	ecx,r10d			; the request's: without it
	jb	.rest
	add	rsi,r10
	sub	ecx,r10d
	jmp	.rest
.answer:
	mov	dword [rdi],'-web'		; the answer's: with it
	add	rdi,4
	cmp	r11d,4
	jne	.rest
	mov	dword [rdi],'-tex'
	mov	byte [rdi+4],'t'
	add	rdi,5
.rest:
	rep	movsb
	mov	word [rdi],0x0A0D
	add	rdi,2
	stc
	ret
.dropped:
	stc
	ret
.no:
	clc
	ret
.ct	db 'content-type: application/grpc'
.ct_len := $ - .ct

; In http_last_chunk, HB_GWEB 2 and trailers (CK_TLEN): the trailer frame, then
; the end. HTTP/1.1: a chunk of it and the last one, together; a stream (HTTP/2,
; 3): its data, then END_STREAM with no trailers. Does not return.
gweb_trailers:
	h_rec
	mov	rdi,[r15+H_BUF]
	lea	rdi,[rdi+HB_OUT]
	mov	r8,rdi
	call	session_ptr
	mov	r9d,[rax+S_FLAGS]
	and	r9d,SF_H2S or SF_H3S or SF_HSTRM
	jnz	@f
	add	rdi,16				; (room for the chunk's size, written after)
@@:
	mov	r10,rdi				; the frame
	mov	byte [rdi],0x80
	add	rdi,5
	; the lines, "name:value\r\n", as the backend's trailers had them
	mov	rsi,[r15+H_BUF]
	add	rsi,HB_TRAIL
	mov	ecx,[r15+H_RCK+CK_TLEN]
	rep	movsb
	mov	eax,edi
	sub	eax,r10d
	sub	eax,5
	bswap	eax
	mov	[r10+1],eax
	mov	dword [r15+H_RCK+CK_TLEN],0	; (sent: as data)
	or	dword [r15+H_FLAGS],HX_LASTCHUNK
	mov	dword [r15+H_STATE],HS_RESP_SEND
	test	r9d,r9d
	jnz	.stream
	; HTTP/1.1: SIZE\r\n frame \r\n 0\r\n\r\n
	mov	eax,edi
	sub	eax,r10d			; the frame's length
	mov	word [rdi],0x0A0D		; \r\n 0 \r\n\r\n
	mov	byte [rdi+2],'0'
	mov	dword [rdi+3],0x0A0D0A0D
	add	rdi,7
	push	rdi
	mov	rdi,r8				; its size, in hex, right before it
	call	.hex
	pop	r11
	mov	word [rdi],0x0A0D
	add	rdi,2
	mov	rsi,r10				; the frame up to it
	mov	rcx,r11
	sub	rcx,r10
	rep	movsb
	sub	rdi,r8
	mov	esi,edi
	mov	rdi,r8
	mov	ecx,SIDE_CLIENT
	jmp	h_send
.stream:
	mov	rsi,rdi
	sub	rsi,r10
	mov	rdi,r10
	mov	ecx,SIDE_CLIENT
	jmp	h_send
; rdi = out, eax = a number: in hex, rdi past it
.hex:
	mov	ecx,28
	xor	edx,edx				; a digit written
.digit:
	mov	r9d,eax
	shr	r9d,cl
	and	r9d,15
	test	edx,edx
	jnz	.put
	test	r9d,r9d
	jnz	.put
	test	ecx,ecx
	jnz	.next
.put:
	mov	r9b,[hex_digits+r9]
	mov	[rdi],r9b
	inc	rdi
	mov	edx,1
.next:
	sub	ecx,4
	jns	.digit
	ret

; ---------------------------------------------------------------- text mode
;
; application/grpc-web-text: the request body is base64 (decoded on its way to the
; backend, its Content-Length not passed on), and so is the answer's body, the
; trailer frame included: encoded as it goes, a byte or two kept for the next
; piece so that only the end is padded (a client decodes it as one stream).

HB_GWT		:= HB_U2Q + Q_DATA + Q_CAP	; (past an HTTP/2 stream's response queue)
GWT_RCN		:= 0				; d
GWT_RC		:= 4				; the request's characters kept (3 at most)
GWT_SCN		:= 8				; d
GWT_SC		:= 12				; the answer's bytes kept (2 at most)
GWT_DEC		:= 64				; a piece with what was kept before it
GWT_ENC		:= GWT_DEC + H_IN_CAP + 64	; the answer's base64 (16 before it: a chunk's size)
assert H_UP_CAP <= H_IN_CAP & CK_TRAIL_MAX + 8 <= H_IN_CAP
assert HB_GWT + GWT_ENC + 16 + (H_IN_CAP + 64) * 4 / 3 + 1024 <= 1 shl HB_SHIFT

; HB_GWEB 4, a request body piece (r8, r9d, from IN): r8/r9d = its bytes, what
; was kept before it decoded with it (none: r9d 0). CF: not base64.
gweb_decode:
	mov	r10,[r15+H_BUF]
	lea	r10,[r10+HB_GWT]
	lea	rdi,[r10+GWT_DEC]		; what was kept, then this
	lea	rsi,[r10+GWT_RC]
	mov	ecx,[r10+GWT_RCN]
	rep	movsb
	mov	rsi,r8
	mov	ecx,r9d
	rep	movsb
	lea	rdx,[r10+GWT_DEC]
	mov	rax,rdi
	sub	rax,rdx				; all of it
	mov	ecx,eax
	and	ecx,3				; the rest of a group: kept
	sub	eax,ecx
	mov	[r10+GWT_RCN],ecx
	lea	rsi,[rdx+rax]
	lea	rdi,[r10+GWT_RC]
	rep	movsb
	; groups up to one that is padded at a time: a sender may pad each message
	lea	rdi,[r10+GWT_DEC]		; (in place: written behind what is read)
	mov	rsi,rdi
	mov	r11d,eax			; what is left of it
.segment:
	test	r11d,r11d
	jz	.done
	xor	edx,edx
@@:
	add	edx,4
	cmp	edx,r11d
	jae	@f
	cmp	byte [rsi+rdx-1],'='
	jne	@b
@@:
	sub	r11d,edx
	push	rsi
	push	rdx
	push	r10
	push	r11
	call	base64_decode			; rdi past what it wrote
	pop	r11
	pop	r10
	pop	rdx
	pop	rsi
	cmp	rax,-1
	je	.bad
	add	rsi,rdx
	jmp	.segment
.done:
	lea	r8,[r10+GWT_DEC]
	mov	r9,rdi
	sub	r9,r8
	clc
	ret
.bad:
	xor	r9d,r9d
	stc
	ret

; In h_send_up, HB_GWEB 4 and a body piece (rdi, esi): decoded, then on to the
; HTTP/2 stream (nothing yet: done at once, as h2u_send does); not base64: the
; stream fails.
gweb_send_up:
	h_rec
	mov	r8,rdi
	mov	r9d,esi
	call	gweb_decode
	jnc	@f
	u2_at	rax, ebx
	or	dword [rax+U2_F],U2F_RST
@@:
	mov	rdi,r8
	mov	esi,r9d
	jmp	h2u_send

; In http_resp_pump, HB_GWEB 4: r8/r9d = body bytes: their base64 (what was kept
; first; the bytes past the last whole three kept), rdi/esi = what to send (a chunk
; of it to HTTP/1.1). CF: nothing yet.
gweb_text_feed:
	xor	r11d,r11d			; (not the end: no padding)
gweb_text_out:
	mov	r10,[r15+H_BUF]
	lea	r10,[r10+HB_GWT]
	lea	rdi,[r10+GWT_DEC]
	lea	rsi,[r10+GWT_SC]
	mov	ecx,[r10+GWT_SCN]
	rep	movsb
	mov	rsi,r8
	mov	ecx,r9d
	rep	movsb
	lea	rsi,[r10+GWT_DEC]
	mov	rax,rdi
	sub	rax,rsi				; all of it
	mov	dword [r10+GWT_SCN],0
	test	r11d,r11d
	jnz	.encode				; the end: all, padded
	xor	edx,edx
	mov	ecx,3
	div	ecx
	mov	[r10+GWT_SCN],edx
	imul	eax,eax,3
	push	rax
	lea	rsi,[r10+GWT_DEC+rax]
	lea	rdi,[r10+GWT_SC]
	mov	ecx,edx
	rep	movsb
	pop	rax
.encode:
	test	eax,eax
	jz	.nothing
	mov	edx,eax
	lea	rsi,[r10+GWT_DEC]
	lea	rdi,[r10+GWT_ENC+16]
	push	r10
	call	base64_encode			; rax = its characters
	pop	r10
	lea	rdi,[r10+GWT_ENC+16]
	mov	esi,eax
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_H2S or SF_H3S or SF_HSTRM
	jnz	.out				; a stream: as it is, in DATA
	; HTTP/1.1: a chunk, its size before it
	mov	eax,esi
	xor	ecx,ecx
@@:
	inc	ecx
	shr	eax,4
	jnz	@b
	lea	r9,[rdi-2]			; CRLF, the digits before it
	mov	word [r9],0x0A0D
	mov	eax,esi
@@:
	dec	r9
	mov	edx,eax
	and	edx,15
	mov	dl,[hex_digits+rdx]
	mov	[r9],dl
	shr	eax,4
	dec	ecx
	jnz	@b
	lea	rax,[rdi+rsi]
	mov	word [rax],0x0A0D
	add	esi,2
	mov	rax,rdi
	sub	rax,r9
	add	esi,eax
	mov	rdi,r9
.out:
	clc
	ret
.nothing:
	stc
	ret

; In http_last_chunk, HB_GWEB 4: what was kept and the trailer frame, encoded and
; padded, then the end. Does not return.
gweb_text_end:
	h_rec
	; the frame (none without trailers) into OUT, as bytes to encode
	mov	r8,[r15+H_BUF]
	lea	r8,[r8+HB_OUT]
	xor	r9d,r9d
	mov	ecx,[r15+H_RCK+CK_TLEN]
	test	ecx,ecx
	jz	@f
	mov	byte [r8],0x80
	mov	eax,ecx
	bswap	eax
	mov	[r8+1],eax
	lea	rdi,[r8+5]
	mov	rsi,[r15+H_BUF]
	add	rsi,HB_TRAIL
	lea	r9d,[rcx+5]
	rep	movsb
	mov	dword [r15+H_RCK+CK_TLEN],0
@@:
	mov	r11d,1
	call	gweb_text_out
	jc	.nothing
	or	dword [r15+H_FLAGS],HX_LASTCHUNK
	mov	dword [r15+H_STATE],HS_RESP_SEND
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_H2S or SF_H3S or SF_HSTRM
	jnz	.send
	lea	rax,[rdi+rsi]			; HTTP/1.1: the last chunk with it
	mov	byte [rax],'0'
	mov	dword [rax+1],0x0A0D0A0D
	add	esi,5
.send:
	mov	ecx,SIDE_CLIENT
	jmp	h_send
.nothing:
	call	session_ptr
	test	dword [rax+S_FLAGS],SF_H2S or SF_H3S or SF_HSTRM
	jnz	http_exchange_done
	or	dword [r15+H_FLAGS],HX_LASTCHUNK
	mov	dword [r15+H_STATE],HS_RESP_SEND
	lea	rdi,[str_last_chunk]
	mov	esi,str_last_chunk.len
	mov	ecx,SIDE_CLIENT
	jmp	h_send
