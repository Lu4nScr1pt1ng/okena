; HTTP/1.x message heads (RFC 9110, 9112), parsed strictly.
;
; A proxy must never read a message differently from the server behind
; it, so anything ambiguous is refused instead of guessed:
;   - lines end in CRLF; a bare LF or a bare CR is an error;
;   - no whitespace between a field name and its colon; no obs-fold;
;   - field values hold no control bytes but HTAB (no NUL, no DEL);
;   - Content-Length is digits only; repeated values must all be equal;
;   - a request's Transfer-Encoding must be exactly "chunked", never
;     together with Content-Length, and never in HTTP/1.0;
;   - HTTP/1.1 requests carry exactly one valid Host.
; The proxy then writes a new head from the parsed fields; the original
; bytes are never forwarded as they came.
;
; Parsing is in place: the message refers to the input buffer.

HM_MAX_HEADERS	:= 100

; Message
HM_METHOD	:= 0		; q: method (request) / version text (response)
HM_MLEN		:= 8		; d
HM_TARGET	:= 16		; q: request target / reason phrase
HM_TLEN		:= 24		; d
HM_PLEN		:= 28		; d: path part of the target (before '?')
HM_VERSION	:= 32		; d: 10 or 11
HM_STATUS	:= 36		; d: response status code
HM_NHDR		:= 40		; d
HM_FLAGS	:= 44		; d: HMF_*
HM_LENGTH	:= 48		; q: Content-Length, -1 when absent
HM_HOST		:= 56		; d: index of the Host field, -1 when absent
HM_HEADLEN	:= 60		; d: bytes of the head, CRLFCRLF included
HM_ERROR	:= 64		; d: HE_* when parsing failed
HM_HDRS		:= 72		; HM_MAX_HEADERS * HF_SIZE
HM_SIZE		:= HM_HDRS + HM_MAX_HEADERS * 32

; Field
HF_NAME		:= 0		; q
HF_NLEN		:= 8		; d
HF_VLEN		:= 12		; d
HF_VALUE	:= 16		; q
HF_FLAGS	:= 24		; d: HFF_*
HF_ID		:= 28		; b: the name's id (hnames below), HID_NONE for others
HF_SIZE		:= 32

HFF_HOP		:= 1		; hop-by-hop: not forwarded
HFF_HOST	:= 2
HFF_LENGTH	:= 4
HFF_TE		:= 8

HMF_CHUNKED	:= 1		; Transfer-Encoding: chunked
HMF_CLOSE	:= 2		; Connection: close (or HTTP/1.0 without keep-alive)
HMF_UPGRADE	:= 4		; Connection: upgrade and an Upgrade field
HMF_CONTINUE	:= 8		; Expect: 100-continue
HMF_KEEPALIVE	:= 16		; Connection: keep-alive
HMF_HAS_UPGRADE	:= 32		; an Upgrade field is present

; Errors (they map to statuses)
HE_NONE		:= 0
HE_BAD		:= 400		; malformed
HE_TOO_LARGE	:= 431		; too many fields
HE_VERSION	:= 505		; HTTP version not supported
HE_NOT_IMPL	:= 501		; a transfer coding we do not take

rodata
	align 8
	; tchar (RFC 9110 5.6.2): token characters, for methods and field names
	http_tchar:
	repeat 256, c:0
		if (c >= '0' & c <= '9') | (c >= 'A' & c <= 'Z') | (c >= 'a' & c <= 'z') | \
		   c = '!' | c = '#' | c = '$' | c = '%' | c = '&' | c = "'" | c = '*' | \
		   c = '+' | c = '-' | c = '.' | c = '^' | c = '_' | c = '`' | c = '|' | c = '~'
			db 1
		else
			db 0
		end if
	end repeat
	; bytes allowed in a request target (no controls, no space, no DEL, no
	; '#'; RFC 3986 characters and '%')
	http_target_ok:
	repeat 256, c:0
		if c > 0x20 & c < 0x7F & c <> '#' & c <> '"' & c <> '<' & c <> '>' & c <> '\' & \
		   c <> '^' & c <> '`' & c <> '{' & c <> '|' & c <> '}'
			db 1
		else
			db 0
		end if
	end repeat
end rodata

; rdi = data, esi = length. eax = length of the head through the empty
; line, 0 when incomplete, -1 on a bare LF, a bare CR, or an empty first
; line (no leading empty lines are tolerated).
http_head_end:
	xor	ecx,ecx				; position
	xor	edx,edx				; start of the current line
.next:
	cmp	ecx,esi
	jae	.incomplete
	movzx	eax,byte [rdi+rcx]
	cmp	al,10
	je	.bad				; LF not after CR
	cmp	al,13
	je	.cr
	inc	ecx
	jmp	.next
.cr:
	lea	eax,[rcx+1]
	cmp	eax,esi
	jae	.incomplete			; the LF may still come
	cmp	byte [rdi+rax],10
	jne	.bad				; bare CR
	cmp	ecx,edx
	je	.empty
	lea	edx,[rcx+2]			; next line
	mov	ecx,edx
	jmp	.next
.empty:
	test	ecx,ecx
	jz	.bad				; nothing before it
	lea	eax,[rcx+2]
	ret
.incomplete:
	xor	eax,eax
	ret
.bad:
	mov	eax,-1
	ret

; Parse a request head. rdi = data, esi = head length (from
; http_head_end), rdx = message. eax = 0 or HE_* (also in HM_ERROR).
http_parse_request:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	rbx,rdi
	mov	r12d,esi
	mov	r13,rdx
	call	hm_reset
	; method: tokens up to SP
	xor	ecx,ecx
.method:
	cmp	ecx,r12d
	jae	.bad
	movzx	eax,byte [rbx+rcx]
	cmp	al,' '
	je	.method_end
	cmp	byte [http_tchar+rax],0
	je	.bad
	inc	ecx
	jmp	.method
.method_end:
	test	ecx,ecx
	jz	.bad
	mov	[r13+HM_METHOD],rbx
	mov	[r13+HM_MLEN],ecx
	inc	ecx
	; target: up to SP
	lea	rax,[rbx+rcx]
	mov	[r13+HM_TARGET],rax
	mov	r14d,ecx			; target start
	mov	dword [r13+HM_PLEN],-1
.target:
	cmp	ecx,r12d
	jae	.bad
	movzx	eax,byte [rbx+rcx]
	cmp	al,' '
	je	.target_end
	cmp	al,'?'
	jne	@f
	cmp	dword [r13+HM_PLEN],-1
	jne	@f
	mov	edx,ecx
	sub	edx,r14d
	mov	[r13+HM_PLEN],edx
@@:
	cmp	byte [http_target_ok+rax],0
	je	.bad
	inc	ecx
	jmp	.target
.target_end:
	mov	edx,ecx
	sub	edx,r14d
	jz	.bad
	mov	[r13+HM_TLEN],edx
	cmp	dword [r13+HM_PLEN],-1
	jne	@f
	mov	[r13+HM_PLEN],edx
@@:
	; origin-form ("/..."), or "*" (OPTIONS) or absolute-form "http://"
	mov	rax,[r13+HM_TARGET]
	cmp	byte [rax],'/'
	je	.form_ok
	cmp	edx,1
	jne	@f
	cmp	byte [rax],'*'
	je	.form_ok
@@:
	cmp	edx,8
	jb	.bad
	mov	r8,[rax]
	mov	r9,0x2020202020202020
	or	r8,r9				; lower case
	mov	r9,'http://'
	mov	r10,0x00FFFFFFFFFFFFFF
	and	r8,r10
	cmp	r8,r9
	jne	.bad
.form_ok:
	inc	ecx
	; version: exactly "HTTP/1.1" or "HTTP/1.0", then CRLF
	lea	eax,[rcx+10]
	cmp	eax,r12d
	ja	.bad
	cmp	dword [rbx+rcx],'HTTP'
	jne	.bad
	cmp	byte [rbx+rcx+4],'/'
	jne	.bad
	movzx	eax,byte [rbx+rcx+5]
	movzx	edx,byte [rbx+rcx+7]
	cmp	byte [rbx+rcx+6],'.'
	jne	.bad
	sub	eax,'0'
	cmp	eax,9
	ja	.bad
	sub	edx,'0'
	cmp	edx,9
	ja	.bad
	cmp	word [rbx+rcx+8],0x0A0D
	jne	.bad
	cmp	eax,1
	jne	.version
	cmp	edx,1
	je	.v11
	test	edx,edx
	jnz	.version
	mov	dword [r13+HM_VERSION],10
	jmp	.fields
.v11:
	mov	dword [r13+HM_VERSION],11
.fields:
	add	ecx,10
	mov	edi,ecx
	call	hm_fields
	test	eax,eax
	jnz	.error
	call	hm_request_rules
	test	eax,eax
	jnz	.error
	jmp	.out
.version:
	mov	eax,HE_VERSION
	jmp	.error
.bad:
	mov	eax,HE_BAD
.error:
	mov	[r13+HM_ERROR],eax
.out:
	mov	[r13+HM_HEADLEN],r12d
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; Parse a response head. Same registers. eax = 0 or HE_*.
http_parse_response:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	rbx,rdi
	mov	r12d,esi
	mov	r13,rdx
	call	hm_reset
	; "HTTP/1.x SP 3DIGIT SP reason CRLF" (the reason may be empty, and its
	; space missing)
	cmp	r12d,14
	jb	.bad
	cmp	dword [rbx],'HTTP'
	jne	.bad
	cmp	dword [rbx+4],'/1.1'
	je	.v11
	cmp	dword [rbx+4],'/1.0'
	jne	.bad
	mov	dword [r13+HM_VERSION],10
	jmp	.status
.v11:
	mov	dword [r13+HM_VERSION],11
.status:
	mov	[r13+HM_METHOD],rbx
	mov	dword [r13+HM_MLEN],8
	cmp	byte [rbx+8],' '
	jne	.bad
	xor	eax,eax
	mov	ecx,9
.digit:
	movzx	edx,byte [rbx+rcx]
	sub	edx,'0'
	cmp	edx,9
	ja	.bad
	imul	eax,eax,10
	add	eax,edx
	inc	ecx
	cmp	ecx,12
	jb	.digit
	cmp	eax,100
	jb	.bad
	mov	[r13+HM_STATUS],eax
	mov	ecx,13
	cmp	byte [rbx+12],' '
	je	@f
	cmp	byte [rbx+12],13		; "HTTP/1.1 200" and its CRLF: no reason, nor
	jne	.bad				; its space (servers send it so; a client
	mov	ecx,12				; ignores the reason anyway)
@@:
	lea	rax,[rbx+rcx]
	mov	[r13+HM_TARGET],rax
.reason:
	cmp	ecx,r12d
	jae	.bad
	movzx	eax,byte [rbx+rcx]
	cmp	al,13
	je	.reason_end
	cmp	al,9
	je	@f
	cmp	al,' '
	jb	.bad
	cmp	al,0x7F
	je	.bad
@@:
	inc	ecx
	jmp	.reason
.reason_end:
	mov	rax,rbx
	add	rax,rcx
	sub	rax,[r13+HM_TARGET]
	mov	[r13+HM_TLEN],eax
	cmp	byte [rbx+rcx+1],10
	jne	.bad
	add	ecx,2
	mov	edi,ecx
	call	hm_fields
	test	eax,eax
	jnz	.error
	call	hm_response_rules
	test	eax,eax
	jnz	.error
	jmp	.out
.bad:
	mov	eax,HE_BAD
.error:
	mov	[r13+HM_ERROR],eax
.out:
	mov	[r13+HM_HEADLEN],r12d
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; r13 = message: empty it.
hm_reset:
	xor	eax,eax
	mov	[r13+HM_NHDR],eax
	mov	[r13+HM_FLAGS],eax
	mov	[r13+HM_ERROR],eax
	mov	[r13+HM_STATUS],eax
	mov	qword [r13+HM_LENGTH],-1
	mov	dword [r13+HM_HOST],-1
	ret

; Field lines from offset edi to the final CRLF. rbx = data, r12d = head
; length, r13 = message. eax = 0 or HE_*.
hm_fields:
	push	r14
	push	r15
	mov	ecx,edi
.line:
	; the last line is the empty one
	cmp	word [rbx+rcx],0x0A0D
	je	.done
	; obs-fold: a line starting with whitespace
	movzx	eax,byte [rbx+rcx]
	cmp	al,' '
	je	.bad
	cmp	al,9
	je	.bad
	mov	eax,[r13+HM_NHDR]
	cmp	eax,HM_MAX_HEADERS
	jae	.too_many
	imul	r14,rax,HF_SIZE
	lea	r14,[r13+HM_HDRS+r14]
	inc	dword [r13+HM_NHDR]
	lea	rax,[rbx+rcx]
	mov	[r14+HF_NAME],rax
	mov	dword [r14+HF_FLAGS],0
	mov	r15d,ecx			; name start
.name:
	movzx	eax,byte [rbx+rcx]
	cmp	al,':'
	je	.name_end
	cmp	byte [http_tchar+rax],0
	je	.bad				; also whitespace before the colon
	inc	ecx
	jmp	.name
.name_end:
	mov	eax,ecx
	sub	eax,r15d
	jz	.bad
	mov	[r14+HF_NLEN],eax
	call	hf_classify
	inc	ecx
	; value: leading OWS skipped
@@:
	movzx	eax,byte [rbx+rcx]
	cmp	al,' '
	je	.ows
	cmp	al,9
	jne	.value
.ows:
	inc	ecx
	jmp	@b
.value:
	lea	rax,[rbx+rcx]
	mov	[r14+HF_VALUE],rax
	mov	r15d,ecx			; value start
.vchar:
	movzx	eax,byte [rbx+rcx]
	cmp	al,13
	je	.value_end
	cmp	al,9
	je	.vok
	cmp	al,' '
	jb	.bad
	cmp	al,0x7F
	je	.bad
.vok:
	inc	ecx
	jmp	.vchar
.value_end:
	cmp	byte [rbx+rcx+1],10
	jne	.bad
	; trailing OWS dropped
	mov	eax,ecx
@@:
	cmp	eax,r15d
	jbe	@f
	movzx	edx,byte [rbx+rax-1]
	cmp	dl,' '
	je	.trail
	cmp	dl,9
	jne	@f
.trail:
	dec	eax
	jmp	@b
@@:
	sub	eax,r15d
	mov	[r14+HF_VLEN],eax
	add	ecx,2
	jmp	.line
.done:
	xor	eax,eax
	jmp	.out
.too_many:
	mov	eax,HE_TOO_LARGE
	jmp	.out
.bad:
	mov	eax,HE_BAD
.out:
	pop	r15
	pop	r14
	ret

; ------------------------------------------------------- field meaning

; r14 = a field whose name and length are set: its HF_ID. Keeps all but rax,
; rdx, rsi, rdi, r8.
hf_classify:
	mov	byte [r14+HF_ID],HID_NONE
	mov	r8d,[r14+HF_NLEN]
	cmp	r8d,HNAME_MAXLEN
	ja	.out
	mov	rsi,[r14+HF_NAME]
	movzx	eax,byte [rsi]
	or	eax,0x20
	imul	eax,eax,14
	movzx	edx,byte [rsi+r8-1]
	or	edx,0x20
	add	eax,edx
	lea	eax,[rax+r8*2]
	and	eax,127
	movzx	eax,byte [hname_slot+rax]
	test	eax,eax
	jz	.out
	cmp	r8b,[hname_len+rax]
	jne	.out
	mov	rdi,[hname_ptr+rax*8]
	mov	[r14+HF_ID],al			; (if the text agrees)
	xor	edx,edx
.byte:
	movzx	eax,byte [rsi+rdx]
	or	al,0x20				; (exact: the parser let only tchars in)
	cmp	al,[rdi+rdx]
	jne	.none
	inc	edx
	cmp	edx,r8d
	jb	.byte
	ret
.none:
	mov	byte [r14+HF_ID],HID_NONE
.out:
	ret

; rdi = field, rsi = lowercase name (NUL-terminated). ZF when it is that
; field (names are case-insensitive). A name of hnames: its id against the
; field's, a byte.
hf_is:
	cmp	rsi,hnames_lo
	jb	.text
	cmp	rsi,hnames_hi
	jae	.text
	movzx	eax,byte [rsi-1]
	cmp	al,[rdi+HF_ID]
	jne	.no
	xor	eax,eax
	ret
.text:
	mov	ecx,[rdi+HF_NLEN]
	mov	rdx,[rdi+HF_NAME]
	xor	r8d,r8d
.next:
	cmp	r8d,ecx
	jae	.end
	movzx	eax,byte [rdx+r8]
	cmp	al,'A'
	jb	@f
	cmp	al,'Z'
	ja	@f
	or	al,0x20
@@:
	cmp	al,[rsi+r8]
	jne	.no
	inc	r8d
	jmp	.next
.end:
	cmp	byte [rsi+r8],0
	jne	.no
	xor	eax,eax				; ZF
	ret
.no:
	or	eax,1
	ret

; rsi/edx = text, rdi = lowercase token (NUL-terminated). ZF when equal
; ignoring ASCII case.
token_is:
	xor	ecx,ecx
.next:
	cmp	ecx,edx
	jae	.end
	movzx	eax,byte [rsi+rcx]
	cmp	al,'A'
	jb	@f
	cmp	al,'Z'
	ja	@f
	or	al,0x20
@@:
	cmp	al,[rdi+rcx]
	jne	.no
	inc	ecx
	jmp	.next
.end:
	cmp	byte [rdi+rcx],0
	jne	.no
	xor	eax,eax
	ret
.no:
	or	eax,1
	ret

cstring tk_chunked, 'chunked',0
cstring tk_close, 'close',0
cstring tk_keep_alive, 'keep-alive',0
cstring tk_upgrade, 'upgrade',0
cstring tk_100_continue, '100-continue',0


; Field names okena compares (hf_is), each with an id in the byte before it;
; hm_fields gives every parsed field the id of its name (HF_ID, HID_NONE for
; the others), so hf_is with one of these names compares a byte instead of
; the text. The ids come from a perfect hash of the length and the first and
; last letters: (length * 2 + first * 14 + last) & 127.
HID_NONE	:= 0xFF
HNAME_MAXLEN	:= 19
rodata
	hnames_lo:
	db 1
	hn_host = $
	db 'host',0
	hn_host.len = $ - hn_host
	db 2
	hn_content_length = $
	db 'content-length',0
	hn_content_length.len = $ - hn_content_length
	db 3
	hn_transfer_encoding = $
	db 'transfer-encoding',0
	hn_transfer_encoding.len = $ - hn_transfer_encoding
	db 4
	hn_connection = $
	db 'connection',0
	hn_connection.len = $ - hn_connection
	db 5
	hn_keep_alive = $
	db 'keep-alive',0
	hn_keep_alive.len = $ - hn_keep_alive
	db 6
	hn_upgrade = $
	db 'upgrade',0
	hn_upgrade.len = $ - hn_upgrade
	db 7
	hn_te = $
	db 'te',0
	hn_te.len = $ - hn_te
	db 8
	hn_trailer = $
	db 'trailer',0
	hn_trailer.len = $ - hn_trailer
	db 9
	hn_proxy_connection = $
	db 'proxy-connection',0
	hn_proxy_connection.len = $ - hn_proxy_connection
	db 10
	hn_proxy_authorization = $
	db 'proxy-authorization',0
	hn_proxy_authorization.len = $ - hn_proxy_authorization
	db 11
	hn_proxy_authenticate = $
	db 'proxy-authenticate',0
	hn_proxy_authenticate.len = $ - hn_proxy_authenticate
	db 12
	hn_expect = $
	db 'expect',0
	hn_expect.len = $ - hn_expect
	db 13
	hn_x_forwarded_for = $
	db 'x-forwarded-for',0
	hn_x_forwarded_for.len = $ - hn_x_forwarded_for
	db 14
	hn_accept_ranges = $
	db 'accept-ranges',0
	hn_accept_ranges.len = $ - hn_accept_ranges
	db 15
	hn_etag = $
	db 'etag',0
	hn_etag.len = $ - hn_etag
	db 16
	hn_x_forwarded_proto = $
	db 'x-forwarded-proto',0
	hn_x_forwarded_proto.len = $ - hn_x_forwarded_proto
	db 17
	hn_x_forwarded_host = $
	db 'x-forwarded-host',0
	hn_x_forwarded_host.len = $ - hn_x_forwarded_host
	db 18
	hn_x_real_ip = $
	db 'x-real-ip',0
	hn_x_real_ip.len = $ - hn_x_real_ip
	db 19
	hn_true_client_ip = $
	db 'true-client-ip',0
	hn_true_client_ip.len = $ - hn_true_client_ip
	db 20
	hn_cf_connecting_ip = $
	db 'cf-connecting-ip',0
	hn_cf_connecting_ip.len = $ - hn_cf_connecting_ip
	db 21
	hn_x_original_url = $
	db 'x-original-url',0
	hn_x_original_url.len = $ - hn_x_original_url
	db 22
	hn_x_rewrite_url = $
	db 'x-rewrite-url',0
	hn_x_rewrite_url.len = $ - hn_x_rewrite_url
	db 23
	hn_forwarded = $
	db 'forwarded',0
	hn_forwarded.len = $ - hn_forwarded
	db 24
	hn_x_request_id = $
	db 'x-request-id',0
	hn_x_request_id.len = $ - hn_x_request_id
	db 25
	hn_content_type = $
	db 'content-type',0
	hn_content_type.len = $ - hn_content_type
	db 26
	hn_traceparent = $
	db 'traceparent',0
	hn_traceparent.len = $ - hn_traceparent
	hnames_hi:
	; hash slot -> id (0: none)
	hname_slot db 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 23, 0, 24, 0, 0, 0
	db 0, 0, 18, 0, 0, 0, 22, 0, 21, 0, 0, 0, 0, 0, 0, 0
	db 13, 16, 0, 0, 17, 0, 0, 0, 0, 11, 0, 0, 1, 0, 9, 0
	db 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	db 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	db 0, 0, 0, 5, 0, 0, 0, 0, 8, 6, 0, 14, 0, 0, 0, 0
	db 0, 3, 26, 0, 19, 0, 0, 25, 0, 0, 0, 0, 4, 0, 2, 0
	db 0, 0, 0, 0, 0, 15, 0, 0, 0, 0, 20, 0, 0, 0, 0, 0
	; id -> its name and length
	align 8
	hname_ptr dq 0, hn_host, hn_content_length, hn_transfer_encoding, hn_connection, hn_keep_alive, hn_upgrade, hn_te, hn_trailer, hn_proxy_connection, hn_proxy_authorization, hn_proxy_authenticate, hn_expect, hn_x_forwarded_for, hn_accept_ranges, hn_etag, hn_x_forwarded_proto, hn_x_forwarded_host, hn_x_real_ip, hn_true_client_ip, hn_cf_connecting_ip, hn_x_original_url, hn_x_rewrite_url, hn_forwarded, hn_x_request_id, hn_content_type, hn_traceparent
	hname_len db 0, 4, 14, 17, 10, 10, 7, 2, 7, 16, 19, 18, 6, 15, 13, 4, 17, 16, 9, 14, 16, 14, 13, 9, 12, 12, 11
end rodata

; Meaning of the fields common to requests and responses: hop-by-hop
; fields, Content-Length, Transfer-Encoding, Connection, Upgrade.
; r13 = message. eax = 0 or HE_*.
hm_common_rules:
	push	rbx
	push	r12
	push	r14
	xor	r12d,r12d			; field index
.field:
	cmp	r12d,[r13+HM_NHDR]
	jae	.connection
	imul	r14,r12,HF_SIZE
	lea	r14,[r13+HM_HDRS+r14]
	mov	rdi,r14
	lea	rsi,[hn_content_length]
	call	hf_is
	jz	.length
	mov	rdi,r14
	lea	rsi,[hn_transfer_encoding]
	call	hf_is
	jz	.te
	mov	rdi,r14
	lea	rsi,[hn_host]
	call	hf_is
	jz	.host
	; hop-by-hop by definition (RFC 9110 7.6.1, and the old proxy ones)
	irp name, hn_connection, hn_keep_alive, hn_te, hn_trailer, hn_proxy_connection, \
		hn_proxy_authorization, hn_proxy_authenticate
		mov	rdi,r14
		lea	rsi,[name]
		call	hf_is
		jz	.hop
	end irp
	mov	rdi,r14
	lea	rsi,[hn_upgrade]
	call	hf_is
	jz	.upgrade
	mov	rdi,r14
	lea	rsi,[hn_expect]
	call	hf_is
	jz	.expect
	jmp	.next
.hop:
	or	dword [r14+HF_FLAGS],HFF_HOP
	jmp	.next
.upgrade:
	or	dword [r14+HF_FLAGS],HFF_HOP
	or	dword [r13+HM_FLAGS],HMF_HAS_UPGRADE
	jmp	.next
.expect:
	mov	rsi,[r14+HF_VALUE]
	mov	edx,[r14+HF_VLEN]
	lea	rdi,[tk_100_continue]
	call	token_is
	jnz	.next
	or	dword [r13+HM_FLAGS],HMF_CONTINUE
	jmp	.next
.host:
	or	dword [r14+HF_FLAGS],HFF_HOST
	cmp	dword [r13+HM_HOST],-1
	jne	.bad				; a second Host
	mov	[r13+HM_HOST],r12d
	jmp	.next
.length:
	or	dword [r14+HF_FLAGS],HFF_LENGTH or HFF_HOP	; written anew
	mov	rdi,r14
	call	hf_content_length
	jc	.bad
	cmp	qword [r13+HM_LENGTH],-1
	je	@f
	cmp	rax,[r13+HM_LENGTH]
	jne	.bad				; disagreeing lengths
@@:
	mov	[r13+HM_LENGTH],rax
	jmp	.next
.te:
	or	dword [r14+HF_FLAGS],HFF_TE or HFF_HOP
	test	dword [r13+HM_FLAGS],HMF_CHUNKED
	jnz	.bad				; Transfer-Encoding twice
	mov	rsi,[r14+HF_VALUE]
	mov	edx,[r14+HF_VLEN]
	lea	rdi,[tk_chunked]
	call	token_is
	jnz	.not_impl
	or	dword [r13+HM_FLAGS],HMF_CHUNKED
.next:
	inc	r12d
	jmp	.field
.connection:
	; Connection options: close, keep-alive, upgrade, and names of
	; further hop-by-hop fields
	xor	r12d,r12d
.cfield:
	cmp	r12d,[r13+HM_NHDR]
	jae	.framing
	imul	r14,r12,HF_SIZE
	lea	r14,[r13+HM_HDRS+r14]
	mov	rdi,r14
	lea	rsi,[hn_connection]
	call	hf_is
	jnz	.cnext
	mov	rdi,r14
	call	hm_connection_options
.cnext:
	inc	r12d
	jmp	.cfield
.framing:
	; Content-Length and Transfer-Encoding together: refused
	test	dword [r13+HM_FLAGS],HMF_CHUNKED
	jz	.ok
	cmp	qword [r13+HM_LENGTH],-1
	jne	.bad
.ok:
	xor	eax,eax
	jmp	.out
.not_impl:
	mov	eax,HE_NOT_IMPL
	jmp	.out
.bad:
	mov	eax,HE_BAD
.out:
	pop	r14
	pop	r12
	pop	rbx
	ret

; rdi = Content-Length field. rax = value, CF when it is not a list of
; equal decimal numbers ("5", "5, 5"; RFC 9110 8.6), or above 2^53.
hf_content_length:
	push	rbx
	mov	rsi,[rdi+HF_VALUE]
	mov	edx,[rdi+HF_VLEN]
	mov	rbx,-1				; value of the first element
	xor	ecx,ecx
.element:
	; skip OWS and commas between elements
	cmp	ecx,edx
	jae	.end
	movzx	eax,byte [rsi+rcx]
	cmp	al,' '
	je	.sep
	cmp	al,9
	je	.sep
	cmp	al,','
	je	.sep
	xor	eax,eax
	xor	r8d,r8d				; digits
.digit:
	cmp	ecx,edx
	jae	.got
	movzx	r9d,byte [rsi+rcx]
	sub	r9d,'0'
	cmp	r9d,9
	ja	.got
	cmp	r8d,16
	jae	.bad
	imul	rax,rax,10
	add	rax,r9
	inc	ecx
	inc	r8d
	jmp	.digit
.got:
	test	r8d,r8d
	jz	.bad				; not a digit
	mov	r9,1 shl 53
	cmp	rax,r9
	ja	.bad
	cmp	rbx,-1
	je	.first
	cmp	rax,rbx
	jne	.bad
.first:
	mov	rbx,rax
	cmp	ecx,edx
	jae	.end
	movzx	eax,byte [rsi+rcx]
	cmp	al,','
	je	.element
	cmp	al,' '
	je	.element
	cmp	al,9
	je	.element
	jmp	.bad
.sep:
	inc	ecx
	jmp	.element
.end:
	cmp	rbx,-1
	je	.bad				; empty
	mov	rax,rbx
	pop	rbx
	clc
	ret
.bad:
	pop	rbx
	stc
	ret

; rdi = Connection field: set flags, and mark the fields it names as
; hop-by-hop. r13 = message.
hm_connection_options:
	push	rbx
	push	r12
	push	r14
	push	r15
	mov	rbx,[rdi+HF_VALUE]
	mov	r12d,[rdi+HF_VLEN]
	xor	r14d,r14d			; position
.token:
	cmp	r14d,r12d
	jae	.done
	movzx	eax,byte [rbx+r14]
	cmp	al,','
	je	.skip
	cmp	al,' '
	je	.skip
	cmp	al,9
	je	.skip
	mov	r15d,r14d			; token start
@@:
	cmp	r14d,r12d
	jae	@f
	movzx	eax,byte [rbx+r14]
	cmp	al,','
	je	@f
	cmp	al,' '
	je	@f
	cmp	al,9
	je	@f
	inc	r14d
	jmp	@b
@@:
	lea	rsi,[rbx+r15]
	mov	edx,r14d
	sub	edx,r15d
	push	rsi
	push	rdx
	lea	rdi,[tk_close]
	call	token_is
	jnz	@f
	or	dword [r13+HM_FLAGS],HMF_CLOSE
@@:
	mov	rsi,[rsp+8]
	mov	edx,[rsp]
	lea	rdi,[tk_keep_alive]
	call	token_is
	jnz	@f
	or	dword [r13+HM_FLAGS],HMF_KEEPALIVE
@@:
	mov	rsi,[rsp+8]
	mov	edx,[rsp]
	lea	rdi,[tk_upgrade]
	call	token_is
	jnz	@f
	or	dword [r13+HM_FLAGS],HMF_UPGRADE
@@:
	; any field with this name is hop-by-hop too
	pop	rdx
	pop	rsi
	call	hm_mark_named_hop
	jmp	.token
.skip:
	inc	r14d
	jmp	.token
.done:
	pop	r15
	pop	r14
	pop	r12
	pop	rbx
	ret

; rsi/edx = field name: mark fields with that name hop-by-hop, except
; the framing fields (they stay as parsed).
hm_mark_named_hop:
	push	rbx
	push	r12
	push	r14
	mov	r12,rsi
	xor	ebx,ebx
.next:
	cmp	ebx,[r13+HM_NHDR]
	jae	.done
	imul	r14,rbx,HF_SIZE
	lea	r14,[r13+HM_HDRS+r14]
	cmp	[r14+HF_NLEN],edx
	jne	.skip
	push	rdx
	mov	rdi,[r14+HF_NAME]
	mov	rsi,r12
	call	mem_eq_nocase
	pop	rdx
	test	eax,eax
	jz	.skip
	test	dword [r14+HF_FLAGS],HFF_HOST
	jnz	.skip				; "Connection: host" cannot hide Host
	or	dword [r14+HF_FLAGS],HFF_HOP
.skip:
	inc	ebx
	jmp	.next
.done:
	pop	r14
	pop	r12
	pop	rbx
	ret

; Request rules on top of the common ones. eax = 0 or HE_*.
hm_request_rules:
	call	hm_common_rules
	test	eax,eax
	jnz	.out
	cmp	dword [r13+HM_VERSION],10
	jne	.v11
	; HTTP/1.0: no chunked; closes unless keep-alive
	test	dword [r13+HM_FLAGS],HMF_CHUNKED
	jnz	.bad
	test	dword [r13+HM_FLAGS],HMF_KEEPALIVE
	jnz	.host_ok
	or	dword [r13+HM_FLAGS],HMF_CLOSE
	jmp	.host_ok
.v11:
	cmp	dword [r13+HM_HOST],-1
	je	.bad				; HTTP/1.1 needs Host
.host_ok:
	mov	eax,[r13+HM_HOST]
	cmp	eax,-1
	je	.star
	imul	rax,rax,HF_SIZE
	lea	rdi,[r13+HM_HDRS+rax]
	call	hf_valid_host
	jc	.bad
	; absolute-form: its authority is the Host, or two hosts are named and a
	; server behind could take the other one (RFC 9112 3.2.2)
	mov	rsi,[r13+HM_TARGET]
	cmp	byte [rsi],'/'
	je	.star
	cmp	byte [rsi],'*'
	je	.star
	mov	edx,[r13+HM_TLEN]
	add	rsi,7				; "http://"
	sub	edx,7
	xor	ecx,ecx				; the authority's length
@@:
	cmp	ecx,edx
	jae	@f
	cmp	byte [rsi+rcx],'/'
	je	@f
	cmp	byte [rsi+rcx],'?'
	je	@f
	inc	ecx
	jmp	@b
@@:
	cmp	ecx,[rdi+HF_VLEN]
	jne	.bad
	test	ecx,ecx
	jz	.bad
	mov	r8,[rdi+HF_VALUE]
@@:
	dec	ecx
	js	.star
	movzx	eax,byte [rsi+rcx]
	movzx	edx,byte [r8+rcx]
	lea	r9d,[rax-'A']			; letters in lower case, nothing else
	cmp	r9d,25				; ('@' and '`' differ by that bit too)
	ja	.lower_t
	or	eax,0x20
.lower_t:
	lea	r9d,[rdx-'A']
	cmp	r9d,25
	ja	.lower_h
	or	edx,0x20
.lower_h:
	cmp	eax,edx
	je	@b
	jmp	.bad
.star:
	; "*" is for OPTIONS only
	mov	rsi,[r13+HM_TARGET]
	cmp	byte [rsi],'*'
	jne	.upgrade
	cmp	dword [r13+HM_MLEN],7
	jne	.bad
	mov	rsi,[r13+HM_METHOD]
	cmp	dword [rsi],'OPTI'
	jne	.bad
	cmp	dword [rsi+3],'IONS'
	jne	.bad
.upgrade:
	; upgrade only with both Connection: upgrade and an Upgrade field
	mov	eax,[r13+HM_FLAGS]
	and	eax,HMF_UPGRADE or HMF_HAS_UPGRADE
	cmp	eax,HMF_UPGRADE or HMF_HAS_UPGRADE
	je	.ok
	and	dword [r13+HM_FLAGS],not HMF_UPGRADE
.ok:
	xor	eax,eax
.out:
	ret
.bad:
	mov	eax,HE_BAD
	ret

hm_response_rules:
	call	hm_common_rules
	test	eax,eax
	jnz	.out
	cmp	dword [r13+HM_VERSION],10
	jne	.ok
	test	dword [r13+HM_FLAGS],HMF_KEEPALIVE
	jnz	.ok
	or	dword [r13+HM_FLAGS],HMF_CLOSE
.ok:
	xor	eax,eax
.out:
	ret

; rdi = Host field. CF when its value is not a host with an optional port
; (RFC 9110 7.2): reg-name characters or an IP literal in brackets.
hf_valid_host:
	mov	rsi,[rdi+HF_VALUE]
	mov	edx,[rdi+HF_VLEN]
	test	edx,edx
	jz	.bad
	xor	ecx,ecx
	cmp	byte [rsi],'['
	jne	.name
	; [IPv6]: hex digits, ':' and '.' inside
	inc	ecx
.v6:
	cmp	ecx,edx
	jae	.bad
	movzx	eax,byte [rsi+rcx]
	inc	ecx
	cmp	al,']'
	je	.port
	cmp	al,':'
	je	.v6
	cmp	al,'.'
	je	.v6
	or	al,0x20
	mov	r8d,eax
	sub	r8d,'0'
	cmp	r8d,9
	jbe	.v6
	sub	eax,'a'
	cmp	eax,5
	jbe	.v6
	jmp	.bad
.name:
	cmp	ecx,edx
	jae	.ok
	movzx	eax,byte [rsi+rcx]
	cmp	al,':'
	je	.colon
	; unreserved and sub-delims (RFC 3986), '%' for pct-encoding
	cmp	byte [http_tchar+rax],0
	jne	.char
	cmp	al,'('
	je	.char
	cmp	al,')'
	je	.char
	cmp	al,','
	je	.char
	cmp	al,';'
	je	.char
	cmp	al,'='
	je	.char
	jmp	.bad
.char:
	inc	ecx
	jmp	.name
.colon:
	test	ecx,ecx
	jz	.bad
	inc	ecx
	jmp	.port_digits0			; (digits only: "a::1" is no host)
.port:
	cmp	ecx,edx
	jae	.ok
	cmp	byte [rsi+rcx],':'
	jne	.port_digits0
	inc	ecx
.port_digits0:
	xor	r8d,r8d				; its value: 65535 at most
.port_digits:
	cmp	ecx,edx
	jae	.ok
	movzx	eax,byte [rsi+rcx]
	sub	eax,'0'
	cmp	eax,9
	ja	.bad
	imul	r8d,r8d,10
	add	r8d,eax
	cmp	r8d,65535
	ja	.bad
	inc	ecx
	jmp	.port_digits
.ok:
	clc
	ret
.bad:
	stc
	ret
