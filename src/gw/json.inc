; A small JSON reader, for tokens and key sets: what it reads comes from outside,
; some of it before any signature has been checked. It never goes past the end,
; has a depth limit, refuses a name with an escape in it and a name given twice
; (two readers of one document must not see two values), and builds nothing.

JSON_DEPTH	:= 32
JSON_NAMES	:= 128				; of the outermost object: more is refused

bss
	g_js_n		dd ?
	align 8
	g_js_names	rq JSON_NAMES * 2	; where each starts, its length
end bss

; rsi = cursor, rdx = end: rsi past white space. Keeps all else.
json_ws:
	cmp	rsi,rdx
	jae	.out
	cmp	byte [rsi],' '
	je	.next
	cmp	byte [rsi],9
	je	.next
	cmp	byte [rsi],10
	je	.next
	cmp	byte [rsi],13
	jne	.out
.next:
	inc	rsi
	jmp	json_ws
.out:
	ret

; rsi at '"': rsi past the closing one. CF: it does not end, or has a control
; byte. Keeps all but rax.
json_skip_string:
	inc	rsi
.next:
	cmp	rsi,rdx
	jae	.bad
	mov	al,[rsi]
	cmp	al,0x20
	jb	.bad
	inc	rsi
	cmp	al,'"'
	je	.ok
	cmp	al,'\'
	jne	.next
	inc	rsi
	jmp	.next
.ok:
	clc
	ret
.bad:
	stc
	ret

; rsi at a value: rsi past it. CF: broken. Keeps rdi, r8-r11.
json_skip_value:
	call	json_ws
	cmp	rsi,rdx
	jae	.bad
	xor	ecx,ecx				; depth
.next:
	cmp	rsi,rdx
	jae	.bad
	mov	al,[rsi]
	cmp	al,'"'
	je	.string
	cmp	al,'{'
	je	.open
	cmp	al,'['
	je	.open
	cmp	al,'}'
	je	.close
	cmp	al,']'
	je	.close
	test	ecx,ecx
	jnz	.inside
	; a number, true, false, null: to what ends it
.scalar:
	cmp	rsi,rdx
	jae	.ok
	mov	al,[rsi]
	cmp	al,','
	je	.ok
	cmp	al,'}'
	je	.ok
	cmp	al,']'
	je	.ok
	cmp	al,' '
	jbe	.ok
	inc	rsi
	jmp	.scalar
.inside:
	inc	rsi
	jmp	.next
.string:
	call	json_skip_string
	jc	.bad
	test	ecx,ecx
	jz	.ok
	jmp	.next
.open:
	inc	ecx
	cmp	ecx,JSON_DEPTH
	ja	.bad
	inc	rsi
	jmp	.next
.close:
	test	ecx,ecx
	jz	.bad
	inc	rsi
	dec	ecx
	jnz	.next
.ok:
	clc
	ret
.bad:
	stc
	ret

; rsi at '{', rdx = its end, rdi = a name, ecx = its length: rax = where its
; value starts, r8 = where it ends, rax = 0 when it is not there. CF: broken, or
; the name is there twice. Keeps rdx, rdi.
json_get:
	push	rbx
	push	r12
	push	r13
	mov	r12d,ecx
	xor	r13d,r13d			; found: its start
	xor	r8d,r8d
	call	json_ws
	cmp	rsi,rdx
	jae	.bad
	cmp	byte [rsi],'{'
	jne	.bad
	inc	rsi
	call	json_ws
	cmp	rsi,rdx
	jae	.bad
	cmp	byte [rsi],'}'
	je	.ok
.member:
	call	json_ws
	cmp	rsi,rdx
	jae	.bad
	cmp	byte [rsi],'"'
	jne	.bad
	lea	rbx,[rsi+1]			; the name
	call	json_skip_string
	jc	.bad
	lea	rcx,[rsi-1]
	sub	rcx,rbx				; its length
	; an escape in a name is refused, whatever the name
	push	rdi
	mov	rdi,rbx
	mov	r9,rcx
	mov	al,'\'
	test	rcx,rcx
	jz	.no_escape
	repne	scasb
	pop	rdi
	je	.bad
	jmp	.compare
.no_escape:
	pop	rdi
.compare:
	call	json_ws
	cmp	rsi,rdx
	jae	.bad
	cmp	byte [rsi],':'
	jne	.bad
	inc	rsi
	call	json_ws
	cmp	r9d,r12d
	jne	.skip
	push	rsi
	push	rdi
	mov	rsi,rbx
	mov	ecx,r12d
	repe	cmpsb
	pop	rdi
	pop	rsi
	jne	.skip
	test	r13,r13
	jnz	.bad				; twice
	mov	r13,rsi
	push	r8
	push	r9
	call	json_skip_value
	pop	r9
	pop	r8
	jc	.bad
	mov	r8,rsi
	jmp	.after
.skip:
	push	r8
	call	json_skip_value
	pop	r8
	jc	.bad
.after:
	call	json_ws
	cmp	rsi,rdx
	jae	.bad
	cmp	byte [rsi],','
	je	.comma
	cmp	byte [rsi],'}'
	je	.ok
	jmp	.bad
.comma:
	inc	rsi
	jmp	.member
.ok:
	mov	rax,r13
	clc
	jmp	.out
.bad:
	stc
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; rsi at a string value, r8 = its end, rdi = out, ecx = room: eax = its length.
; CF: not a string, too long, or an escape not understood. Escapes decode, and
; \uXXXX only below 0x80: what matters here is ASCII. Keeps rdx.
json_string:
	push	rdx
	mov	rdx,rdi
	lea	r9,[rdi+rcx]
	cmp	byte [rsi],'"'
	jne	.bad
	inc	rsi
	dec	r8				; the closing quote
.next:
	cmp	rsi,r8
	jae	.done
	cmp	rdi,r9
	jae	.bad
	lodsb
	cmp	al,'\'
	jne	.put
	cmp	rsi,r8
	jae	.bad
	lodsb
	cmp	al,'"'
	je	.put
	cmp	al,'\'
	je	.put
	cmp	al,'/'
	je	.put
	mov	cl,8
	cmp	al,'b'
	je	.ctrl
	mov	cl,12
	cmp	al,'f'
	je	.ctrl
	mov	cl,10
	cmp	al,'n'
	je	.ctrl
	mov	cl,13
	cmp	al,'r'
	je	.ctrl
	mov	cl,9
	cmp	al,'t'
	je	.ctrl
	cmp	al,'u'
	jne	.bad
	lea	rax,[rsi+4]
	cmp	rax,r8
	ja	.bad
	xor	ecx,ecx
	xor	eax,eax
.hex:
	movzx	r10d,byte [rsi]
	inc	rsi
	sub	r10d,'0'
	cmp	r10d,9
	jbe	.digit
	or	r10d,0x20
	sub	r10d,'a' - '0'
	cmp	r10d,5
	ja	.bad
	add	r10d,10
.digit:
	shl	eax,4
	or	eax,r10d
	inc	ecx
	cmp	ecx,4
	jb	.hex
	cmp	eax,0x80
	jae	.bad
	jmp	.put
.ctrl:
	mov	al,cl
.put:
	stosb
	jmp	.next
.done:
	mov	rax,rdi
	sub	rax,rdx
	pop	rdx
	clc
	ret
.bad:
	pop	rdx
	stc
	ret

; rsi = a document, rdx = its end: CF unless it is one JSON value by the grammar
; (RFC 8259), in valid UTF-8, no deeper than JSON_DEPTH. Run first, so that the
; lookups above never read what another parser would refuse: two readers of one
; token must not disagree. Keeps rdx, rdi.
json_valid:
	push	r8
	xor	r8d,r8d
	mov	dword [g_js_n],0
	call	.value
	jc	.out
	call	json_ws
	cmp	rsi,rdx				; (anything after it: CF)
	jb	.trailing
	clc
	jmp	.out
.trailing:
	stc
.out:
	pop	r8
	ret
.value:
	call	json_ws
	cmp	rsi,rdx
	jae	.bad
	mov	al,[rsi]
	cmp	al,'"'
	je	json_valid_string
	cmp	al,'{'
	je	.object
	cmp	al,'['
	je	.array
	cmp	al,'-'
	je	json_valid_number
	cmp	al,'0'
	jb	.word
	cmp	al,'9'
	jbe	json_valid_number
.word:
	lea	rcx,[rsi+4]
	cmp	rcx,rdx
	ja	.five
	mov	ecx,[rsi]
	cmp	ecx,'true'
	je	.four
	cmp	ecx,'null'
	je	.four
.five:
	lea	rcx,[rsi+5]
	cmp	rcx,rdx
	ja	.bad
	cmp	dword [rsi],'fals'
	jne	.bad
	cmp	byte [rsi+4],'e'
	jne	.bad
	inc	rsi
.four:
	add	rsi,4
	clc
	ret
.array:
	inc	r8d
	cmp	r8d,JSON_DEPTH
	ja	.bad
	inc	rsi
	call	json_ws
	cmp	rsi,rdx
	jae	.bad
	cmp	byte [rsi],']'
	je	.closed
.element:
	call	.value
	jc	.bad
	call	json_ws
	cmp	rsi,rdx
	jae	.bad
	cmp	byte [rsi],']'
	je	.closed
	cmp	byte [rsi],','
	jne	.bad
	inc	rsi
	jmp	.element
.closed:
	inc	rsi
	dec	r8d
	clc
	ret
.object:
	inc	r8d
	cmp	r8d,JSON_DEPTH
	ja	.bad
	inc	rsi
	call	json_ws
	cmp	rsi,rdx
	jae	.bad
	cmp	byte [rsi],'}'
	je	.closed
.member:
	call	json_ws
	cmp	rsi,rdx
	jae	.bad
	cmp	byte [rsi],'"'
	jne	.bad
	lea	r11,[rsi+1]
	call	json_valid_string
	jc	.bad
	cmp	r8d,1
	jne	.named
	call	.name_new
	jc	.bad
.named:
	call	json_ws
	cmp	rsi,rdx
	jae	.bad
	cmp	byte [rsi],':'
	jne	.bad
	inc	rsi
	call	.value
	jc	.bad
	call	json_ws
	cmp	rsi,rdx
	jae	.bad
	cmp	byte [rsi],'}'
	je	.closed
	cmp	byte [rsi],','
	jne	.bad
	inc	rsi
	jmp	.member
; the outermost object: r11 = a name, rsi past its closing quote. CF: it has an
; escape, which would hide what it is, or came before.
.name_new:
	push	rdi
	lea	rcx,[rsi-1]
	sub	rcx,r11				; its length
	mov	r9,rcx
	mov	rdi,r11
	mov	al,'\'
	test	rcx,rcx
	jz	@f
	repne	scasb
	je	.name_bad
@@:
	mov	ecx,[g_js_n]
	cmp	ecx,JSON_NAMES
	jae	.name_bad
	lea	r10,[g_js_names]
.earlier:
	test	ecx,ecx
	jz	.first
	dec	ecx
	cmp	[r10+8],r9
	jne	.other
	push	rcx
	push	rsi
	mov	rdi,[r10]
	mov	rsi,r11
	mov	rcx,r9
	repe	cmpsb
	pop	rsi
	pop	rcx
	je	.name_bad
.other:
	add	r10,16
	jmp	.earlier
.first:
	mov	[r10],r11
	mov	[r10+8],r9
	inc	dword [g_js_n]
	pop	rdi
	clc
	ret
.name_bad:
	pop	rdi
	stc
	ret
.bad:
	stc
	ret

; rsi at '"': past the closing one. CF: an escape not in the grammar, a control
; byte, or bad UTF-8 (overlong forms and surrogates too). Keeps rdx, rdi, r8.
json_valid_string:
	inc	rsi
.next:
	cmp	rsi,rdx
	jae	.bad
	movzx	eax,byte [rsi]
	inc	rsi
	cmp	al,'"'
	je	.ok
	cmp	al,0x20
	jb	.bad
	cmp	al,'\'
	je	.escape
	cmp	al,0x80
	jb	.next
	; UTF-8: how many more, and what the next may be
	mov	ecx,1
	mov	r9d,0x80
	mov	r10d,0xBF
	cmp	al,0xC2
	jb	.bad
	cmp	al,0xDF
	jbe	.more
	inc	ecx
	cmp	al,0xE0
	jne	@f
	mov	r9d,0xA0
	jmp	.more
@@:
	cmp	al,0xED
	jne	@f
	mov	r10d,0x9F
	jmp	.more
@@:
	cmp	al,0xEF
	jbe	.more
	inc	ecx
	cmp	al,0xF0
	jne	@f
	mov	r9d,0x90
	jmp	.more
@@:
	cmp	al,0xF4
	ja	.bad
	jne	.more
	mov	r10d,0x8F
.more:
	cmp	rsi,rdx
	jae	.bad
	movzx	eax,byte [rsi]
	inc	rsi
	cmp	eax,r9d
	jb	.bad
	cmp	eax,r10d
	ja	.bad
	mov	r9d,0x80
	mov	r10d,0xBF
	dec	ecx
	jnz	.more
	jmp	.next
.escape:
	cmp	rsi,rdx
	jae	.bad
	movzx	eax,byte [rsi]
	inc	rsi
	cmp	al,'u'
	je	.hex
	mov	ecx,8
	lea	r9,[.single]
.one:
	cmp	al,[r9]
	je	.next
	inc	r9
	dec	ecx
	jnz	.one
	jmp	.bad
.hex:
	mov	ecx,4
.digit:
	cmp	rsi,rdx
	jae	.bad
	movzx	eax,byte [rsi]
	inc	rsi
	sub	eax,'0'
	cmp	eax,9
	jbe	.fine
	or	eax,0x20
	sub	eax,'a' - '0'
	cmp	eax,5
	ja	.bad
.fine:
	dec	ecx
	jnz	.digit
	jmp	.next
.ok:
	clc
	ret
.bad:
	stc
	ret
.single	db '"\/bfnrt'

; rsi at a number: past it. CF: not one, by the grammar.
json_valid_number:
	cmp	byte [rsi],'-'
	jne	@f
	inc	rsi
@@:
	cmp	rsi,rdx
	jae	.bad
	cmp	byte [rsi],'0'
	jne	.int
	inc	rsi
	jmp	.frac
.int:
	call	.digits
	jc	.bad
.frac:
	cmp	rsi,rdx
	jae	.ok
	cmp	byte [rsi],'.'
	jne	.exp
	inc	rsi
	call	.digits
	jc	.bad
.exp:
	cmp	rsi,rdx
	jae	.ok
	mov	al,[rsi]
	or	al,0x20
	cmp	al,'e'
	jne	.ok
	inc	rsi
	cmp	rsi,rdx
	jae	.bad
	mov	al,[rsi]
	cmp	al,'+'
	je	.sign
	cmp	al,'-'
	jne	.after_sign
.sign:
	inc	rsi
.after_sign:
	call	.digits
	jc	.bad
.ok:
	clc
	ret
.bad:
	stc
	ret
; one digit at least
.digits:
	cmp	rsi,rdx
	jae	.bad
	movzx	eax,byte [rsi]
	sub	eax,'0'
	cmp	eax,9
	ja	.bad
.digit:
	inc	rsi
	cmp	rsi,rdx
	jae	.ok
	movzx	eax,byte [rsi]
	sub	eax,'0'
	cmp	eax,9
	jbe	.digit
	jmp	.ok
