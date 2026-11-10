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
	mov	byte [rax+HB_GWEB],1		; -web-text, or what follows not +x: as it is
	cmp	ecx,20
	je	.binary
	cmp	byte [rsi+20],'+'
	jne	.out
.binary:
	mov	byte [rax+HB_GWEB],3
.out:
	ret

; In http_write_request_head: HB_GWEB 3 becomes 2 when the pool speaks HTTP/2,
; else 1. Keeps all but rax, rcx.
gweb_pool:
	mov	rax,[r15+H_BUF]
	cmp	byte [rax+HB_GWEB],3
	jne	.out
	push	rax
	call	session_ptr
	mov	eax,[rax+S_POOL]
	imul	rax,rax,PL_SIZE
	mov	ecx,[g_pools+rax+PL_H2]
	pop	rax
	mov	byte [rax+HB_GWEB],1
	test	ecx,ecx
	jz	.out
	mov	byte [rax+HB_GWEB],2
.out:
	ret

; A field being copied (r14), rdi = where, r13 = the room's end, edx = 0 the
; request's (towards the backend), 1 the answer's: CF when it was written here,
; its content-type as gRPC (request) or gRPC-Web (answer); rdi past it.
gweb_field:
	mov	rax,[r15+H_BUF]
	cmp	byte [rax+HB_GWEB],2
	jne	.no
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
	test	edx,edx
	jnz	.answer
	cmp	ecx,4				; the request's: without its -web
	jb	.rest
	add	rsi,4
	sub	ecx,4
	jmp	.rest
.answer:
	mov	dword [rdi],'-web'		; the answer's: with it
	add	rdi,4
.rest:
	rep	movsb
	mov	word [rdi],0x0A0D
	add	rdi,2
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
