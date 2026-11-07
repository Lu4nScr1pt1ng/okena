; `discover docker label=okena.pool=users [port=8080] [network=NAME]
; [socket=/var/run/docker.sock] [max=64]`: a pool's servers are the running
; containers that have that label, as Docker's Engine API lists them.
;
; The control process asks the socket once a second (GET /containers/json,
; filtered by the label, over HTTP/1.0 so the answer comes whole and the
; connection ends) and publishes what changed, as for `discover file`. A
; container is taken with its address on `network` (or its first network),
; on the port its `okena.port` label says, else `port=`, else the one port it
; exposes; `okena.weight` gives its weight. One with a health check is taken
; only while it is healthy, so a container that starts is not sent traffic
; before it can answer. A container that is not usable that way is left out,
; and the others are served.
;
; Docker not answering, or answering what cannot be read, changes nothing:
; the servers known go on, and it is said once. An empty list is Docker
; saying there are none, and is believed. The socket gives whoever can write
; to it the host; okena only reads, and a read-only proxy of it (Tecnativa's
; docker-socket-proxy with CONTAINERS=1) is the way to give it less.

DK_BUF		:= 4 shl 20
DK_LABEL	:= 0			; q: the label, as written (key=value or key)
DK_LLEN		:= 8			; d
DK_NLEN		:= 12			; d
DK_NET		:= 16			; q: the network, 0 = the first
DK_SIZE		:= 32

bss
	align 8
	g_plan_dk:	rb DK_SIZE * DISC_SOURCES	; per source (plan)
	g_dk_buf	dq ?
	g_dk_req:	rb 2048
	g_dk_sa:	rb 110
end bss

rodata
	align 8
	ts_dk_io	dq 2, 0
end rodata

; ebx = a docker group: ask, and publish. eax = seconds to the next look.
disc_docker_poll:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	imul	r12,rbx,GR_SIZE
	lea	r12,[g_groups+r12]
	mov	r13d,[r12+GR_DISC]
	cmp	qword [g_dk_buf],0
	jne	@f
	xor	edi,edi
	mov	esi,DK_BUF
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_PRIVATE or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.unreachable
	mov	[g_dk_buf],rax
@@:
	call	dk_request			; g_dk_req, r14d = its length
	; the socket
	mov	ecx,[r12+GR_NLEN]
	cmp	ecx,107
	ja	.unreachable
	mov	word [g_dk_sa],AF_UNIX
	lea	rdi,[g_dk_sa+2]
	mov	rsi,[r12+GR_NAME]
	rep	movsb
	mov	byte [rdi],0
	mov	edi,AF_UNIX
	mov	esi,SOCK_STREAM or SOCK_CLOEXEC
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	.unreachable
	mov	r15d,eax
	mov	edi,r15d
	mov	esi,SOL_SOCKET
	mov	edx,SO_RCVTIMEO
	lea	r10,[ts_dk_io]
	mov	r8d,16
	mov	eax,SYS_setsockopt
	syscall
	mov	edi,r15d
	mov	esi,SOL_SOCKET
	mov	edx,SO_SNDTIMEO
	lea	r10,[ts_dk_io]
	mov	r8d,16
	mov	eax,SYS_setsockopt
	syscall
	mov	edi,r15d
	lea	rsi,[g_dk_sa]
	mov	edx,[r12+GR_NLEN]
	add	edx,3
	mov	eax,SYS_connect
	syscall
	test	eax,eax
	js	.unreachable_close
	mov	edi,r15d
	lea	rsi,[g_dk_req]
	mov	edx,r14d
	call	dk_write_all
	jc	.unreachable_close
	; the whole answer, until it closes
	xor	r14d,r14d
.read:
	mov	edi,r15d
	mov	rsi,[g_dk_buf]
	add	rsi,r14
	mov	edx,DK_BUF - 1
	sub	edx,r14d
	jz	.unreadable_close
	xor	eax,eax
	syscall
	cmp	rax,-EINTR
	je	.read
	test	rax,rax
	js	.unreachable_close
	jz	.read_all
	add	r14d,eax
	jmp	.read
.read_all:
	mov	edi,r15d
	mov	eax,SYS_close
	syscall
	; 200, then the body
	mov	rsi,[g_dk_buf]
	cmp	r14d,16
	jb	.unreadable
	cmp	dword [rsi+8],' 200'
	jne	.status
	lea	r13,[rsi+r14]			; (r13: the end, for the parser)
	push	r13
	mov	rcx,r14
	mov	rdi,rsi
.head:
	cmp	rcx,4
	jb	.no_body
	cmp	dword [rdi],0x0A0D0A0D
	je	.body
	inc	rdi
	dec	rcx
	jmp	.head
.no_body:
	pop	r13
	mov	r13d,[r12+GR_DISC]
	jmp	.unreadable
.body:
	lea	rsi,[rdi+4]
	pop	r13
	call	dk_parse			; g_disc_new; CF when it cannot be read
	mov	r13d,[r12+GR_DISC]
	jc	.unreadable
	call	disc_publish
	mov	dword [g_disc_said+r13*4],0
	jmp	.out
.status:
	mov	eax,3
	cstring str_dk_status, ': Docker refused the question (not 200)'
	lea	rsi,[str_dk_status]
	mov	edx,str_dk_status.len
	jmp	.tell
.unreadable_close:
	mov	edi,r15d
	mov	eax,SYS_close
	syscall
.unreadable:
	mov	eax,2
	cstring str_dk_bad, ': an answer that cannot be read'
	lea	rsi,[str_dk_bad]
	mov	edx,str_dk_bad.len
	jmp	.tell
.unreachable_close:
	mov	edi,r15d
	mov	eax,SYS_close
	syscall
.unreachable:
	mov	eax,1
	cstring str_dk_gone, ': no answer on the socket'
	lea	rsi,[str_dk_gone]
	mov	edx,str_dk_gone.len
.tell:
	cmp	[g_disc_said+r13*4],eax
	je	.out
	mov	[g_disc_said+r13*4],eax
	push	rsi
	push	rdx
	call	log_begin
	out_lit 'discover docker '
	imul	rax,r13,DK_SIZE
	mov	rsi,[g_plan_dk+rax+DK_LABEL]
	mov	edx,[g_plan_dk+rax+DK_LLEN]
	call	out_str
	pop	rdx
	pop	rsi
	call	out_str
	out_lit '; keeping the servers known so far'
	mov	edi,AL_DISCOVERY
	call	log_end_alert
.out:
	mov	eax,1
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; edi = socket, rsi/edx = bytes: all of them. CF when it could not.
dk_write_all:
	test	edx,edx
	jz	.done
	push	rdi
	push	rsi
	push	rdx
	mov	eax,SYS_write
	syscall
	pop	rdx
	pop	rsi
	pop	rdi
	cmp	rax,-EINTR
	je	dk_write_all
	test	rax,rax
	jle	.bad
	add	rsi,rax
	sub	edx,eax
	jmp	dk_write_all
.done:
	clc
	ret
.bad:
	stc
	ret

; r13d = source: the question in g_dk_req, r14d = its length. The label goes
; in the filter percent-encoded, all but letters, digits and -._~ (it was
; checked to be printable and short when the file was read).
dk_request:
	lea	rdi,[g_dk_req]
	cstring str_dk_get1, 'GET /containers/json?filters=%7B%22label%22%3A%5B%22'
	lea	rsi,[str_dk_get1]
	mov	ecx,str_dk_get1.len
	rep	movsb
	imul	rax,r13,DK_SIZE
	mov	rsi,[g_plan_dk+rax+DK_LABEL]
	mov	ecx,[g_plan_dk+rax+DK_LLEN]
.char:
	test	ecx,ecx
	jz	.chars
	movzx	eax,byte [rsi]
	inc	rsi
	dec	ecx
	mov	edx,eax
	or	edx,0x20
	cmp	edx,'a'
	jb	@f
	cmp	edx,'z'
	jbe	.plain
@@:
	cmp	al,'0'
	jb	@f
	cmp	al,'9'
	jbe	.plain
@@:
	cmp	al,'-'
	je	.plain
	cmp	al,'.'
	je	.plain
	cmp	al,'_'
	je	.plain
	cmp	al,'~'
	je	.plain
	mov	byte [rdi],'%'
	mov	edx,eax
	shr	edx,4
	mov	dl,[.hex+rdx]
	mov	[rdi+1],dl
	and	eax,15
	mov	al,[.hex+rax]
	mov	[rdi+2],al
	add	rdi,3
	jmp	.char
.plain:
	stosb
	jmp	.char
.chars:
	cstring str_dk_get2, '%22%5D%7D HTTP/1.0',13,10,'Host: docker',13,10,13,10
	lea	rsi,[str_dk_get2]
	mov	ecx,str_dk_get2.len
	rep	movsb
	lea	rax,[g_dk_req]
	sub	rdi,rax
	mov	r14d,edi
	ret
.hex	db '0123456789ABCDEF'

; ------------------------------------------------------------ JSON

; rsi = where, r13 = the end: past blanks
js_ws:
	cmp	rsi,r13
	jae	.out
	movzx	eax,byte [rsi]
	cmp	al,' '
	je	.next
	cmp	al,9
	je	.next
	cmp	al,10
	je	.next
	cmp	al,13
	jne	.out
.next:
	inc	rsi
	jmp	js_ws
.out:
	ret

; rsi at '"': rdi/ecx = the string's bytes (escapes as they are), rsi after
; it. CF when it does not end.
js_str:
	cmp	rsi,r13
	jae	.bad
	cmp	byte [rsi],'"'
	jne	.bad
	inc	rsi
	mov	rdi,rsi
.char:
	cmp	rsi,r13
	jae	.bad
	movzx	eax,byte [rsi]
	cmp	al,'"'
	je	.end
	inc	rsi
	cmp	al,'\'
	jne	.char
	inc	rsi				; (what follows is not the end)
	jmp	.char
.end:
	mov	rcx,rsi
	sub	rcx,rdi
	inc	rsi
	clc
	ret
.bad:
	stc
	ret

; rsi at a value: past it. CF when it does not end. Keeps rbx, r12-r15.
js_skip:
	call	js_ws
	cmp	rsi,r13
	jae	.bad
	movzx	eax,byte [rsi]
	cmp	al,'"'
	je	.string
	cmp	al,'{'
	je	.nested
	cmp	al,'['
	je	.nested
	; a number, true, false, null: up to what ends it
.word:
	cmp	rsi,r13
	jae	.done
	movzx	eax,byte [rsi]
	cmp	al,','
	je	.done
	cmp	al,'}'
	je	.done
	cmp	al,']'
	je	.done
	cmp	al,' '
	jbe	.done
	inc	rsi
	jmp	.word
.string:
	call	js_str
	ret
.nested:
	xor	edx,edx				; depth
.in:
	cmp	rsi,r13
	jae	.bad
	movzx	eax,byte [rsi]
	cmp	al,'"'
	je	.in_string
	inc	rsi
	cmp	al,'{'
	je	.deeper
	cmp	al,'['
	je	.deeper
	cmp	al,'}'
	je	.shallower
	cmp	al,']'
	je	.shallower
	jmp	.in
.deeper:
	inc	edx
	cmp	edx,64
	ja	.bad
	jmp	.in
.shallower:
	dec	edx
	jnz	.in
.done:
	clc
	ret
.in_string:
	push	rdx
	call	js_str
	pop	rdx
	jc	.bad
	jmp	.in
.bad:
	stc
	ret

; rsi at '{', rdi/edx = a key: rsi at its value, CF clear; CF set when the
; object has no such key (rsi then undefined). Keeps rbx, r12-r15.
js_find:
	push	rbx
	push	r12
	mov	rbx,rdi
	mov	r12d,edx
	call	js_ws
	cmp	rsi,r13
	jae	.none
	cmp	byte [rsi],'{'
	jne	.none
	inc	rsi
.member:
	call	js_ws
	cmp	rsi,r13
	jae	.none
	cmp	byte [rsi],'}'
	je	.none
	call	js_str
	jc	.none
	call	js_ws
	cmp	rsi,r13
	jae	.none
	cmp	byte [rsi],':'
	jne	.none
	inc	rsi
	call	js_ws
	cmp	ecx,r12d
	jne	.other
	push	rsi
	mov	rsi,rdi
	mov	rdi,rbx
	repe	cmpsb
	pop	rsi
	je	.found
.other:
	call	js_skip
	jc	.none
	call	js_ws
	cmp	rsi,r13
	jae	.none
	cmp	byte [rsi],','
	jne	.none
	inc	rsi
	jmp	.member
.found:
	clc
	jmp	.out
.none:
	stc
.out:
	pop	r12
	pop	rbx
	ret

macro js_key name*
	local s
	cstring s, name
	lea	rdi,[s]
	mov	edx,s.len
end macro

; rsi at a value: eax = it as a number when it is one (0..65535), CF else
js_port:
	call	js_ws
	xor	eax,eax
	xor	ecx,ecx
	cmp	rsi,r13
	jae	.bad
	cmp	byte [rsi],'"'			; (labels are strings)
	jne	.digits
	inc	rsi
.digits:
	cmp	rsi,r13
	jae	.end
	movzx	edx,byte [rsi]
	sub	edx,'0'
	cmp	edx,9
	ja	.end
	imul	eax,eax,10
	add	eax,edx
	inc	rsi
	inc	ecx
	cmp	ecx,5
	ja	.bad
	jmp	.digits
.end:
	test	ecx,ecx
	jz	.bad
	cmp	eax,65535
	ja	.bad
	clc
	ret
.bad:
	stc
	ret

; rsi at the body, r13 its end, r12 = group: g_disc_new from the list. CF
; when it is not a list of containers.
dk_parse:
	push	rbx
	push	r14
	push	r15
	mov	dword [g_disc_new+DX_COUNT],0
	call	js_ws
	cmp	rsi,r13
	jae	.bad
	cmp	byte [rsi],'['
	jne	.bad
	inc	rsi
.container:
	call	js_ws
	cmp	rsi,r13
	jae	.bad
	cmp	byte [rsi],']'
	je	.done
	mov	rbx,rsi				; the container's object
	call	dk_container
	mov	rsi,rbx
	call	js_skip
	jc	.bad
	call	js_ws
	cmp	rsi,r13
	jae	.bad
	cmp	byte [rsi],','
	jne	@f
	inc	rsi
	jmp	.container
@@:
	cmp	byte [rsi],']'
	jne	.bad
.done:
	clc
	jmp	.out
.bad:
	stc
.out:
	pop	r15
	pop	r14
	pop	rbx
	ret

; rbx = a container's object: into g_disc_new when it can be served
dk_container:
	mov	eax,[g_disc_new+DX_COUNT]
	cmp	eax,[r12+GR_SLOTS]
	jae	.no
	; running
	mov	rsi,rbx
	js_key 'State'
	call	js_find
	jc	.no
	call	js_str
	jc	.no
	cmp	ecx,7
	jne	.no
	cmp	dword [rdi],'runn'
	jne	.no
	; not unhealthy, nor starting: "Up 3 minutes (healthy)"
	mov	rsi,rbx
	js_key 'Status'
	call	js_find
	jc	.healthy
	call	js_str
	jc	.no
	cmp	ecx,8
	jb	.healthy
	lea	r8,[rdi+rcx-8]
.paren:
	cmp	r8,rdi
	jb	.healthy
	cmp	byte [r8],'('
	je	.health
	dec	r8
	jmp	.paren
.health:
	cmp	dword [r8+1],'heal'
	jne	@f
	cmp	dword [r8+5],'thy)'
	je	.healthy
@@:
	cmp	dword [r8+1],'unhe'
	je	.no
	cmp	dword [r8+1],'heal'
	je	.no				; "(health: starting)"
.healthy:
	; its port: okena.port, port=, or the one it exposes
	xor	r14d,r14d
	mov	r15d,1				; weight
	mov	rsi,rbx
	js_key 'Labels'
	call	js_find
	jc	.no_labels
	push	rsi
	js_key 'okena.port'
	call	js_find
	jc	@f
	call	js_port
	jc	@f
	mov	r14d,eax
@@:
	pop	rsi
	js_key 'okena.weight'
	call	js_find
	jc	.no_labels
	call	js_port
	jc	.no_labels
	test	eax,eax
	jz	.no_labels
	mov	r15d,eax
.no_labels:
	test	r14d,r14d
	jnz	.ported
	mov	r14d,[r12+GR_PORT]
	test	r14d,r14d
	jnz	.ported
	call	dk_one_port			; eax = it, or 0
	test	eax,eax
	jz	.no
	mov	r14d,eax
.ported:
	; its address
	mov	rsi,rbx
	js_key 'NetworkSettings'
	call	js_find
	jc	.no
	js_key 'Networks'
	call	js_find
	jc	.no
	mov	eax,[r12+GR_DISC]
	imul	rax,rax,DK_SIZE
	mov	rdi,[g_plan_dk+rax+DK_NET]
	test	rdi,rdi
	jz	.first_net
	mov	edx,[g_plan_dk+rax+DK_NLEN]
	call	js_find
	jc	.no
	jmp	.net
.first_net:
	call	js_ws
	cmp	rsi,r13
	jae	.no
	cmp	byte [rsi],'{'
	jne	.no
	inc	rsi
.next_net:
	call	js_ws
	call	js_str				; its name
	jc	.no
	call	js_ws
	cmp	rsi,r13
	jae	.no
	cmp	byte [rsi],':'
	jne	.no
	inc	rsi
	call	js_ws
	push	rsi
	js_key 'IPAddress'
	call	js_find
	jc	.no_ip
	call	js_str
	jc	.no_ip
	test	ecx,ecx
	jz	.no_ip
	add	rsp,8
	jmp	.ip
.no_ip:
	pop	rsi
	call	js_skip
	jc	.no
	call	js_ws
	cmp	rsi,r13
	jae	.no
	cmp	byte [rsi],','
	jne	.no
	inc	rsi
	jmp	.next_net
.net:
	js_key 'IPAddress'
	call	js_find
	jc	.no
	call	js_str
	jc	.no
	test	ecx,ecx
	jz	.no
.ip:
	; "a.b.c.d" and the port, as an address
	cmp	ecx,15
	ja	.no
	mov	rsi,rdi
	lea	rdi,[g_disc_tok]
	rep	movsb
	mov	byte [rdi],':'
	inc	rdi
	mov	eax,r14d
	call	dk_decimal
	lea	rsi,[g_disc_tok]
	sub	rdi,rsi
	mov	esi,edi
	lea	rdi,[g_disc_tok]
	lea	rdx,[g_disc_ad]
	xor	ecx,ecx
	call	parse_address
	jc	.no
	cmp	dword [g_disc_ad+AD_KIND],ADDR_V4
	jne	.no
	mov	eax,[g_disc_new+DX_COUNT]
	inc	dword [g_disc_new+DX_COUNT]
	imul	rax,rax,DE_SIZE
	lea	rdi,[g_disc_new+DX_E+rax]
	mov	rcx,[g_disc_ad+AD_IP]
	mov	[rdi+DE_ADDR],rcx
	mov	rcx,[g_disc_ad+AD_IP+8]
	mov	[rdi+DE_ADDR+8],rcx
	mov	dword [rdi+DE_FAMILY],4
	mov	[rdi+DE_PORT],r14d
	mov	[rdi+DE_WEIGHT],r15d
	mov	dword [rdi+DE_BACKUP],0
.no:
	ret

; rbx = a container: eax = the one TCP port it exposes, 0 when none or more
dk_one_port:
	push	r14
	xor	r14d,r14d
	mov	rsi,rbx
	js_key 'Ports'
	call	js_find
	jc	.out
	call	js_ws
	cmp	rsi,r13
	jae	.out
	cmp	byte [rsi],'['
	jne	.out
	inc	rsi
.port:
	call	js_ws
	cmp	rsi,r13
	jae	.out
	cmp	byte [rsi],']'
	je	.out
	push	rsi
	js_key 'PrivatePort'
	call	js_find
	jc	.skip
	call	js_port
	jc	.skip
	mov	rsi,[rsp]
	push	rax
	js_key 'Type'
	call	js_find
	pop	rax
	jc	.skip
	push	rax
	call	js_str
	pop	rax
	jc	.skip
	cmp	ecx,3
	jne	.skip
	cmp	word [rdi],'tc'
	jne	.skip
	test	r14d,r14d
	jz	.first
	cmp	r14d,eax
	je	.skip				; (the same port on v4 and v6)
	mov	r14d,-1				; more than one
	jmp	.skip
.first:
	mov	r14d,eax
.skip:
	pop	rsi
	call	js_skip
	jc	.out
	call	js_ws
	cmp	rsi,r13
	jae	.out
	cmp	byte [rsi],','
	jne	.out
	inc	rsi
	jmp	.port
.out:
	mov	eax,r14d
	cmp	eax,-1
	jne	@f
	xor	eax,eax
@@:
	pop	r14
	ret

; eax = a number: its digits at rdi, rdi after them
dk_decimal:
	push	rbx
	mov	ebx,eax
	xor	ecx,ecx
@@:
	xor	edx,edx
	mov	eax,ebx
	mov	r9d,10
	div	r9d
	mov	ebx,eax
	add	edx,'0'
	push	rdx
	inc	ecx
	test	ebx,ebx
	jnz	@b
@@:
	pop	rax
	stosb
	dec	ecx
	jnz	@b
	pop	rbx
	ret
