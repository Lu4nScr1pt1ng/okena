; Name resolution for backends: /etc/hosts, then DNS over UDP to the
; servers in /etc/resolv.conf (search domains and ndots honoured), A and
; AAAA. Blocking, with short timeouts: it runs only in the supervisor at
; startup and in the control process, never in a worker.

RS_MAX_SERVERS	= 3
RS_MAX_SEARCH	= 6
DNS_TIMEOUT_S	= 1
DNS_ATTEMPTS	= 2
DNS_MAX_ADDRS	= 8		; addresses kept per name
DNS_TTL_MIN	= 1
DNS_TTL_MAX	= 60		; re-resolve at least once a minute
DNS_RETRY_S	= 2		; after a failure

; Result of a lookup (rs_result)
RR_COUNT	= 0		; d
RR_TTL		= 4		; d: seconds
RR_STATUS	= 8		; d: RS_*
RR_ADDRS	= 16		; DNS_MAX_ADDRS * 16: IPv4 (first 4 bytes) or IPv6
RR_FAMILY	= RR_ADDRS + DNS_MAX_ADDRS * 16	; DNS_MAX_ADDRS bytes: 4 or 6
RR_SIZE		= RR_FAMILY + DNS_MAX_ADDRS

RS_OK		= 0
RS_NXDOMAIN	= 1		; the name does not exist
RS_NODATA	= 2		; exists, no address
RS_FAILED	= 3		; no answer (timeout, server failure)

bss
	align 8
	g_rs_loaded	dd ?
	g_rs_nservers	dd ?
	g_rs_ndots	dd ?
	g_rs_nsearch	dd ?
	g_rs_servers:	rb 28 * RS_MAX_SERVERS		; sockaddr_in / sockaddr_in6
	g_rs_salen	rd RS_MAX_SERVERS
	g_rs_search:	rb 256 * RS_MAX_SEARCH		; NUL-terminated domains
	g_rs_name:	rb 256				; candidate being queried
	g_rs_query:	rb 512
	g_rs_reply:	rb 1500
	g_rs_result:	rb RR_SIZE
	g_rs_file:	rb 65536 + 64
	g_rs_id		dw ?
end bss

cstring str_resolv_conf, '/etc/resolv.conf',0
cstring str_etc_hosts, '/etc/hosts',0
cstring str_nameserver, 'nameserver',0
cstring str_search, 'search',0
cstring str_domain, 'domain',0
cstring str_options, 'options',0

; rdi = path: read up to 64 KiB into g_rs_file, NUL-terminated.
; rax = length or -1.
rs_read_small:
	mov	rsi,rdi
	mov	edi,AT_FDCWD
	mov	edx,O_RDONLY or O_CLOEXEC
	xor	r10d,r10d
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	js	.none
	push	rbx
	push	r12
	mov	ebx,eax
	xor	r12d,r12d
.read:
	mov	edi,ebx
	lea	rsi,[g_rs_file+r12]
	mov	edx,65536
	sub	edx,r12d
	jz	.end
	xor	eax,eax
	syscall
	test	rax,rax
	jle	.end
	add	r12,rax
	jmp	.read
.end:
	mov	byte [g_rs_file+r12],0
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
	mov	rax,r12
	pop	r12
	pop	rbx
	ret
.none:
	mov	rax,-1
	ret

; Word scanner over g_rs_file. rsi = position. rsi/edx = next word on the
; current line (edx = 0 at the end of the line; rsi then points at it).
rs_word:
.skip:
	mov	al,[rsi]
	cmp	al,' '
	je	@f
	cmp	al,9
	jne	.start
@@:
	inc	rsi
	jmp	.skip
.start:
	xor	edx,edx
	cmp	al,'#'
	je	.comment
	cmp	al,';'
	je	.comment
.len:
	mov	al,[rsi+rdx]
	cmp	al,' '
	jbe	.done
	inc	edx
	jmp	.len
.comment:
	; the rest of the line is a comment
@@:
	mov	al,[rsi]
	test	al,al
	jz	.done
	cmp	al,10
	je	.done
	inc	rsi
	jmp	@b
.done:
	ret

; rsi = position: move to the start of the next line. ZF when at the end.
rs_next_line:
@@:
	mov	al,[rsi]
	test	al,al
	jz	.end
	inc	rsi
	cmp	al,10
	jne	@b
	cmp	byte [rsi],0
	ret
.end:
	cmp	al,0
	ret

; Parse /etc/resolv.conf once. Without a nameserver, 127.0.0.1.
rs_load:
	cmp	dword [g_rs_loaded],0
	jne	.done
	mov	dword [g_rs_loaded],1
	mov	dword [g_rs_ndots],1
	push	rbx
	push	r12
	push	r13
	lea	rdi,[str_resolv_conf]
	call	rs_read_small
	test	rax,rax
	js	.defaults
	lea	rbx,[g_rs_file]
.line:
	mov	rsi,rbx
	call	rs_word
	test	edx,edx
	jz	.next
	mov	r12,rsi
	mov	r13d,edx
	mov	rdi,r12
	mov	esi,r13d
	lea	rdx,[str_nameserver]
	call	mem_eq_cstr
	test	eax,eax
	jnz	.nameserver
	mov	rdi,r12
	mov	esi,r13d
	lea	rdx,[str_search]
	call	mem_eq_cstr
	test	eax,eax
	jnz	.search
	mov	rdi,r12
	mov	esi,r13d
	lea	rdx,[str_domain]
	call	mem_eq_cstr
	test	eax,eax
	jnz	.search
	mov	rdi,r12
	mov	esi,r13d
	lea	rdx,[str_options]
	call	mem_eq_cstr
	test	eax,eax
	jnz	.options
	jmp	.next
.nameserver:
	cmp	dword [g_rs_nservers],RS_MAX_SERVERS
	jae	.next
	lea	rsi,[r12+r13]
	call	rs_word
	test	edx,edx
	jz	.next
	mov	rdi,rsi
	mov	esi,edx
	call	rs_add_server
	jmp	.next
.search:
	; "search a b c" replaces earlier search/domain lines
	mov	dword [g_rs_nsearch],0
	lea	rsi,[r12+r13]
.search_word:
	call	rs_word
	test	edx,edx
	jz	.next
	cmp	dword [g_rs_nsearch],RS_MAX_SEARCH
	jae	.next
	cmp	edx,250
	ja	.search_skip
	mov	ecx,[g_rs_nsearch]
	shl	ecx,8
	lea	rdi,[g_rs_search+rcx]
	push	rsi
	mov	ecx,edx
	rep	movsb
	mov	byte [rdi],0
	pop	rsi
	inc	dword [g_rs_nsearch]
.search_skip:
	add	rsi,rdx
	jmp	.search_word
.options:
	lea	rsi,[r12+r13]
.option:
	call	rs_word
	test	edx,edx
	jz	.next
	cmp	edx,7
	jb	.option_skip
	cmp	dword [rsi],'ndot'
	jne	.option_skip
	cmp	word [rsi+4],'s:'
	jne	.option_skip
	push	rsi
	push	rdx
	lea	rdi,[rsi+6]
	lea	esi,[rdx-6]
	call	parse_decimal
	pop	rdx
	pop	rsi
	jc	.option_skip
	cmp	eax,15
	jbe	@f
	mov	eax,15
@@:
	mov	[g_rs_ndots],eax
.option_skip:
	add	rsi,rdx
	jmp	.option
.next:
	mov	rsi,rbx
	call	rs_next_line
	mov	rbx,rsi
	jnz	.line
.defaults:
	cmp	dword [g_rs_nservers],0
	jne	.loaded
	cstring str_rs_local, '127.0.0.1'
	lea	rdi,[str_rs_local]
	mov	esi,str_rs_local.len
	call	rs_add_server
.loaded:
	pop	r13
	pop	r12
	pop	rbx
.done:
	ret

; rdi/esi = nameserver address text (IPv4 or IPv6, port 53).
rs_add_server:
	push	rbx
	mov	ecx,[g_rs_nservers]
	imul	rbx,rcx,28
	lea	rbx,[g_rs_servers+rbx]
	push	rdi
	push	rsi
	call	parse_ipv4_text
	pop	rsi
	pop	rdi
	jc	.v6
	mov	word [rbx],AF_INET
	mov	word [rbx+2],53 shl 8
	mov	[rbx+4],eax
	mov	ecx,[g_rs_nservers]
	mov	dword [g_rs_salen+rcx*4],16
	inc	dword [g_rs_nservers]
	pop	rbx
	ret
.v6:
	; strip a "%zone" suffix: link-local servers are rare enough
	xor	ecx,ecx
@@:
	cmp	ecx,esi
	jae	@f
	cmp	byte [rdi+rcx],'%'
	je	@f
	inc	ecx
	jmp	@b
@@:
	mov	esi,ecx
	lea	rdx,[rbx+8]
	call	parse_ipv6_text
	jc	.bad
	mov	word [rbx],AF_INET6
	mov	word [rbx+2],53 shl 8
	mov	dword [rbx+4],0
	mov	dword [rbx+24],0
	mov	ecx,[g_rs_nservers]
	mov	dword [g_rs_salen+rcx*4],28
	inc	dword [g_rs_nservers]
.bad:
	pop	rbx
	ret

; Look a name up. rdi/esi = name (as written, no trailing dot needed).
; Fills g_rs_result. eax = RS_* status.
rs_lookup:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r12,rdi
	mov	r13d,esi
	call	rs_load
	lea	rdi,[g_rs_result]
	xor	eax,eax
	mov	ecx,RR_SIZE
	rep	stosb
	mov	dword [g_rs_result+RR_TTL],DNS_TTL_MAX
	; /etc/hosts first, as the C library does
	mov	rdi,r12
	mov	esi,r13d
	call	rs_hosts
	cmp	dword [g_rs_result+RR_COUNT],0
	jne	.ok
	; candidates: the name as-is first when it has ndots dots, else last
	xor	ecx,ecx
	xor	edx,edx
@@:
	cmp	ecx,r13d
	jae	@f
	cmp	byte [r12+rcx],'.'
	jne	.nodot
	inc	edx
.nodot:
	inc	ecx
	jmp	@b
@@:
	mov	r14d,RS_NXDOMAIN		; worst result so far
	cmp	edx,[g_rs_ndots]
	jb	.search_first
	mov	rdi,r12
	mov	esi,r13d
	xor	edx,edx
	call	rs_try
	cmp	eax,RS_OK
	je	.ok
	call	.keep_worst
	call	.search_list
	jmp	.out
.search_first:
	call	.search_list
	cmp	eax,RS_OK
	je	.out
	mov	rdi,r12
	mov	esi,r13d
	xor	edx,edx
	call	rs_try
	cmp	eax,RS_OK
	je	.ok
	call	.keep_worst
	mov	eax,r14d
	jmp	.out
.ok:
	mov	eax,RS_OK
.out:
	mov	[g_rs_result+RR_STATUS],eax
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
; eax = RS_OK on the first search domain that answers, else worst status
.search_list:
	xor	ebx,ebx
.domain:
	cmp	ebx,[g_rs_nsearch]
	jae	.domains_done
	mov	rdi,r12
	mov	esi,r13d
	mov	edx,ebx
	shl	edx,8
	lea	rdx,[g_rs_search+rdx]
	call	rs_try
	cmp	eax,RS_OK
	je	.found
	call	.keep_worst
	inc	ebx
	jmp	.domain
.domains_done:
	mov	eax,r14d
	ret
.found:
	ret
; a server failure outranks "does not exist": the name may well exist
.keep_worst:
	cmp	eax,RS_NXDOMAIN
	je	@f
	cmp	r14d,RS_FAILED
	je	@f
	mov	r14d,eax
@@:
	ret

; Query A and AAAA for name rdi/esi (+ "." + suffix rdx when not 0).
; eax = RS_* (RS_OK when any address was found).
rs_try:
	push	rbx
	push	r12
	; build the candidate in g_rs_name
	lea	rbx,[g_rs_name]
	cmp	esi,250
	ja	.too_long
	push	rsi
	mov	rcx,rsi
	mov	r8,rdx
	mov	rsi,rdi
	mov	rdi,rbx
	rep	movsb
	pop	rsi
	test	r8,r8
	jz	.built
	mov	byte [rdi],'.'
	inc	rdi
	inc	esi
.suffix:
	mov	al,[r8]
	test	al,al
	jz	.built
	cmp	esi,253
	jae	.too_long
	mov	[rdi],al
	inc	rdi
	inc	r8
	inc	esi
	jmp	.suffix
.built:
	mov	byte [rdi],0
	mov	r12d,esi
	mov	edi,1				; A
	mov	esi,r12d
	call	rs_query
	mov	ebx,eax
	mov	edi,28				; AAAA
	mov	esi,r12d
	call	rs_query
	cmp	dword [g_rs_result+RR_COUNT],0
	jne	.ok
	; no address: the most telling status of the two answers
	cmp	ebx,RS_FAILED
	je	.failed
	cmp	eax,RS_FAILED
	je	.failed
	cmp	ebx,RS_NODATA
	je	.nodata
	cmp	eax,RS_NODATA
	je	.nodata
	mov	eax,RS_NXDOMAIN
	jmp	.out
.nodata:
	mov	eax,RS_NODATA
	jmp	.out
.failed:
	mov	eax,RS_FAILED
	jmp	.out
.ok:
	mov	eax,RS_OK
	jmp	.out
.too_long:
	mov	eax,RS_NXDOMAIN
.out:
	pop	r12
	pop	rbx
	ret

; One query of type edi for g_rs_name (length esi), to each nameserver in
; turn, DNS_ATTEMPTS rounds. Addresses go to g_rs_result. eax = RS_*.
rs_query:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12d,edi			; type
	mov	r13d,esi
	; header: random id, RD, one question
	sub	rsp,8
	mov	rdi,rsp
	mov	esi,2
	xor	edx,edx
	mov	eax,SYS_getrandom
	syscall
	mov	ax,[rsp]
	add	rsp,8
	mov	[g_rs_id],ax
	lea	rdi,[g_rs_query]
	mov	[rdi],ax
	mov	word [rdi+2],0x0001		; flags 0x0100 (RD), big endian
	mov	word [rdi+4],0x0100		; qdcount 1
	mov	dword [rdi+6],0
	mov	word [rdi+10],0
	lea	rdi,[g_rs_query+12]
	lea	rsi,[g_rs_name]
	call	dns_encode_name
	jc	.nx
	mov	eax,r12d
	xchg	al,ah
	mov	[rdi],ax			; qtype
	mov	word [rdi+2],0x0100		; qclass IN
	add	rdi,4
	lea	rax,[g_rs_query]
	sub	rdi,rax
	mov	r14d,edi			; query length
	xor	r15d,r15d			; attempt
.attempt:
	mov	eax,[g_rs_nservers]
	imul	eax,eax,DNS_ATTEMPTS
	cmp	r15d,eax
	jae	.failed
	mov	eax,r15d
	xor	edx,edx
	div	dword [g_rs_nservers]
	mov	ebx,edx				; server
	inc	r15d
	mov	edi,ebx
	mov	esi,r14d
	call	dns_exchange			; eax = reply length or -1
	test	eax,eax
	js	.attempt
	mov	esi,eax
	mov	edi,r12d
	call	dns_parse			; eax = RS_* or -1 to retry
	test	eax,eax
	js	.attempt
	jmp	.out
.failed:
	mov	eax,RS_FAILED
	jmp	.out
.nx:
	mov	eax,RS_NXDOMAIN
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rsi = dotted name (NUL-terminated), rdi = output. rdi = after the name.
; CF when a label is empty or longer than 63.
dns_encode_name:
.label:
	mov	rdx,rdi				; length byte goes here
	inc	rdi
	xor	ecx,ecx
.char:
	mov	al,[rsi]
	test	al,al
	jz	.end_label
	inc	rsi
	cmp	al,'.'
	je	.end_label
	mov	[rdi],al
	inc	rdi
	inc	ecx
	cmp	ecx,63
	ja	.bad
	jmp	.char
.end_label:
	test	ecx,ecx
	jz	.empty
	mov	[rdx],cl
	cmp	byte [rsi-1],'.'
	jne	.root
	cmp	byte [rsi],0
	jne	.label
.root:
	mov	byte [rdi],0
	inc	rdi
	clc
	ret
.empty:
	; only a trailing dot may leave an empty label
	cmp	byte [rsi],0
	jne	.bad
	mov	rdi,rdx
	mov	byte [rdi],0
	inc	rdi
	clc
	ret
.bad:
	stc
	ret

; Send the query (esi bytes) to nameserver edi, wait for the reply.
; eax = reply length or -1.
dns_exchange:
	push	rbx
	push	r12
	push	r13
	mov	r12d,edi
	mov	r13d,esi
	imul	rax,r12,28
	movzx	edi,word [g_rs_servers+rax]
	mov	esi,SOCK_DGRAM or SOCK_CLOEXEC
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	.fail
	mov	ebx,eax
	sub	rsp,16
	mov	qword [rsp],DNS_TIMEOUT_S
	mov	qword [rsp+8],0
	mov	edi,ebx
	mov	esi,SOL_SOCKET
	mov	edx,SO_RCVTIMEO
	mov	r10,rsp
	mov	r8d,16
	mov	eax,SYS_setsockopt
	syscall
	add	rsp,16
	; connect, so replies from anyone else are dropped by the kernel
	mov	edi,ebx
	imul	rsi,r12,28
	lea	rsi,[g_rs_servers+rsi]
	mov	edx,[g_rs_salen+r12*4]
	mov	eax,SYS_connect
	syscall
	test	eax,eax
	js	.close_fail
	mov	edi,ebx
	lea	rsi,[g_rs_query]
	mov	edx,r13d
	mov	eax,SYS_write
	syscall
	cmp	eax,r13d
	jne	.close_fail
.recv:
	mov	edi,ebx
	lea	rsi,[g_rs_reply]
	mov	edx,1500
	xor	eax,eax
	syscall
	cmp	rax,-EINTR
	je	.recv
	test	rax,rax
	jle	.close_fail			; timeout (EAGAIN) or error
	cmp	eax,12
	jb	.recv
	mov	cx,[g_rs_reply]
	cmp	cx,[g_rs_id]
	jne	.recv				; not ours: keep waiting
	push	rax
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
	pop	rax
	jmp	.out
.close_fail:
	mov	edi,ebx
	mov	eax,SYS_close
	syscall
.fail:
	mov	eax,-1
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; Parse the reply (esi bytes) to a query of type edi. Appends A/AAAA
; addresses to g_rs_result. eax = RS_*, or -1 to ask another server.
dns_parse:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12d,edi
	lea	rbx,[g_rs_reply]
	lea	r13,[rbx+rsi]			; end
	movzx	eax,word [rbx+2]
	xchg	al,ah
	test	eax,0x8000			; QR
	jz	.retry
	mov	ecx,eax
	and	ecx,0x000F			; RCODE
	cmp	ecx,3
	je	.nx
	test	ecx,ecx
	jnz	.retry				; SERVFAIL, REFUSED: ask another
	movzx	r14d,word [rbx+4]		; qdcount
	rol	r14w,8
	movzx	r15d,word [rbx+6]		; ancount
	rol	r15w,8
	lea	rsi,[rbx+12]
.question:
	test	r14d,r14d
	jz	.answers
	call	dns_skip_name
	jc	.retry
	add	rsi,4
	cmp	rsi,r13
	ja	.retry
	dec	r14d
	jmp	.question
.answers:
	test	r15d,r15d
	jz	.done
	call	dns_skip_name
	jc	.retry
	lea	rax,[rsi+10]
	cmp	rax,r13
	ja	.retry
	movzx	ecx,word [rsi]			; type
	rol	cx,8
	movzx	edx,word [rsi+2]		; class
	rol	dx,8
	mov	r8d,[rsi+4]			; ttl
	bswap	r8d
	movzx	r9d,word [rsi+8]		; rdlength
	rol	r9w,8
	add	rsi,10
	lea	rax,[rsi+r9]
	cmp	rax,r13
	ja	.retry
	cmp	edx,1
	jne	.skip_rr
	cmp	ecx,r12d
	jne	.skip_rr
	mov	eax,[g_rs_result+RR_COUNT]
	cmp	eax,DNS_MAX_ADDRS
	jae	.skip_rr
	cmp	ecx,1
	jne	.aaaa
	cmp	r9d,4
	jne	.skip_rr
	shl	eax,4
	mov	edx,[rsi]
	mov	[g_rs_result+RR_ADDRS+rax],edx
	shr	eax,4
	mov	byte [g_rs_result+RR_FAMILY+rax],4
	jmp	.stored
.aaaa:
	cmp	r9d,16
	jne	.skip_rr
	shl	eax,4
	mov	rdx,[rsi]
	mov	[g_rs_result+RR_ADDRS+rax],rdx
	mov	rdx,[rsi+8]
	mov	[g_rs_result+RR_ADDRS+rax+8],rdx
	shr	eax,4
	mov	byte [g_rs_result+RR_FAMILY+rax],6
.stored:
	inc	dword [g_rs_result+RR_COUNT]
	; the set lives as long as its shortest TTL
	cmp	r8d,[g_rs_result+RR_TTL]
	jae	.skip_rr
	mov	[g_rs_result+RR_TTL],r8d
.skip_rr:
	add	rsi,r9
	dec	r15d
	jmp	.answers
.done:
	cmp	dword [g_rs_result+RR_COUNT],0
	jne	.ok
	mov	eax,RS_NODATA
	jmp	.out
.ok:
	mov	eax,RS_OK
	jmp	.out
.nx:
	mov	eax,RS_NXDOMAIN
	jmp	.out
.retry:
	mov	eax,-1
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rsi = name in a message (labels or a compression pointer), r13 = end.
; rsi = after it, CF when it runs past the end.
dns_skip_name:
.label:
	cmp	rsi,r13
	jae	.bad
	movzx	eax,byte [rsi]
	test	eax,eax
	jz	.end
	mov	ecx,eax
	and	ecx,0xC0
	cmp	ecx,0xC0
	je	.pointer
	test	ecx,ecx
	jnz	.bad
	lea	rsi,[rsi+rax+1]
	jmp	.label
.pointer:
	add	rsi,2
	cmp	rsi,r13
	ja	.bad
	clc
	ret
.end:
	inc	rsi
	clc
	ret
.bad:
	stc
	ret

; /etc/hosts: "address name aliases...". rdi/esi = name. Adds matches
; (case-insensitive) to g_rs_result.
rs_hosts:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rdi
	mov	r13d,esi
	lea	rdi,[str_etc_hosts]
	call	rs_read_small
	test	rax,rax
	js	.done
	lea	rbx,[g_rs_file]
.line:
	mov	rsi,rbx
	call	rs_word
	test	edx,edx
	jz	.next
	mov	r14,rsi				; address
	mov	r15d,edx
	add	rsi,rdx
.name:
	call	rs_word
	test	edx,edx
	jz	.next
	cmp	edx,r13d
	jne	.other
	push	rsi
	mov	rdi,rsi
	mov	rsi,r12
	call	mem_eq_nocase
	pop	rsi
	test	eax,eax
	jnz	.match
.other:
	add	rsi,rdx
	jmp	.name
.match:
	mov	eax,[g_rs_result+RR_COUNT]
	cmp	eax,DNS_MAX_ADDRS
	jae	.next
	mov	rdi,r14
	mov	esi,r15d
	call	parse_ipv4_text
	jc	.v6
	mov	ecx,[g_rs_result+RR_COUNT]
	shl	ecx,4
	mov	[g_rs_result+RR_ADDRS+rcx],eax
	shr	ecx,4
	mov	byte [g_rs_result+RR_FAMILY+rcx],4
	inc	dword [g_rs_result+RR_COUNT]
	jmp	.next
.v6:
	mov	ecx,[g_rs_result+RR_COUNT]
	shl	ecx,4
	mov	rdi,r14
	mov	esi,r15d
	lea	rdx,[g_rs_result+RR_ADDRS+rcx]
	call	parse_ipv6_text
	jc	.next
	mov	ecx,[g_rs_result+RR_COUNT]
	mov	byte [g_rs_result+RR_FAMILY+rcx],6
	inc	dword [g_rs_result+RR_COUNT]
.next:
	mov	rsi,rbx
	call	rs_next_line
	mov	rbx,rsi
	jnz	.line
.done:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi, rsi = buffers, edx = length. eax = 1 when equal ignoring ASCII case.
mem_eq_nocase:
	xor	ecx,ecx
.next:
	cmp	ecx,edx
	jae	.yes
	movzx	eax,byte [rdi+rcx]
	movzx	r8d,byte [rsi+rcx]
	or	eax,0x20
	or	r8d,0x20
	cmp	eax,r8d
	jne	.no
	inc	ecx
	jmp	.next
.yes:
	mov	eax,1
	ret
.no:
	xor	eax,eax
	ret
