; A small JSON reader, for tokens and key sets: what it reads comes from outside,
; some of it before any signature has been checked. It never goes past the end,
; has a depth limit, refuses a name with an escape in it and a name given twice
; (two readers of one document must not see two values), and builds nothing.

JSON_DEPTH	:= 32

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
