; On-demand certificates: `tls { on_demand [PATTERN...] [ask=URL] [max=N] }`. A
; ClientHello for a name no certificate of the listener has, that a pattern allows
; (a name, or *.parent for any name under it), makes okena get one for it from the
; ACME CA, as Caddy's on-demand TLS does; `ask=` (http://) is asked first, GET
; URL?domain=NAME, and only a 200 lets it be: so a stranger's names cannot make
; okena ask the CA for certificates (or use up its rate limits). `max=` caps how
; many (262144 at most, the default).
;
; The store is a table of OD_SLOTS slots found by the name's hash (linear probing,
; slots never emptied: a name keeps its slot), so a handshake looks at one slot or
; a few, however many names there are; memory is taken only as slots are written.
;
; The worker does not block: it puts the name in a ring the acme process reads,
; wakes it, and parks the handshake, looked at again each second; once the
; certificate is there (in a shared store the acme process fills) the handshake
; goes on with it, without a reload. A name refused, or not served within 15 s,
; goes on with the listener's own certificate. The certificates are kept in DIR as
; the others (DIR/NAME/), named in DIR/on_demand.list, and renewed as they are.

OD_MAX		:= 1 shl 18
OD_SLOTS	:= 1 shl 19			; the store: twice as many, for short probes
OD_PROBE	:= 4096				; slots looked at, at most
OD_CFGS		:= 4
OD_WAIT		:= 15				; seconds a handshake waits for one
OD_REFUSE	:= 600				; a refused name, not asked again for

; the plan's, a tls block with on_demand
OC_GROUP	:= 0				; d: its listener's group
OC_NPAT		:= 4				; d: its arguments (the patterns, and key=value)
OC_PATS		:= 8				; q
OC_ASK		:= 16				; q
OC_ASKL		:= 24				; d
OC_MAX		:= 28				; d
OC_SIZE		:= 32

; the shared page
ODP_N		:= 0				; d: requests ever (lock xadd)
ODP_RING	:= 64
ODR_READY	:= 0				; d: its number + 1, written last
ODR_CFG		:= 4				; d
ODR_LEN		:= 8				; d
ODR_NAME	:= 16				; 256
ODR_SIZE	:= 272
ODR_N		:= 16
ODP_STORE	:= 8192
ODS_SEQ		:= 0				; d: odd while written
ODS_STATE	:= 4				; d: 0 free, 1 asked for, 2 there, 3 refused
ODS_NLEN	:= 8				; d
ODS_CLEN	:= 12				; d
ODS_UNTIL	:= 16				; q: refused until
ODS_KEY		:= 24				; 32
ODS_PUB		:= 56				; 65
ODS_NAME	:= 128				; 256
ODS_CHAIN	:= 384
ODS_SIZE	:= 8192
ODS_CHAINMAX	:= ODS_SIZE - ODS_CHAIN
OD_PAGE		:= ODP_STORE + OD_SLOTS * ODS_SIZE

HS_TLS_ODWAIT	:= 33				; the ClientHello waits for its certificate
TH_WAIT		:= 5				; tls_hello: an on-demand certificate is coming
TF_ODWAITED	:= 65536				; it waited long enough: go on without one
ODW_CAP		:= 256				; parked handshakes, a worker

bss
	align 8
	g_plan_odn	dd ?
	g_plan_od:	rb OC_SIZE * OD_CFGS
	g_od_page	dq ?
	; a worker's
	g_od_tl:	rb TL_SIZE		; the certificate found, copied (its chain past g_tls_store)
	g_od_name:	rb 256
	g_od_namel	dd ?
	g_odw_head	dd ?
	g_odw_count	dd ?
	g_odw_deadline	dd ?			; (what a re-parked one keeps)
	g_od_asked	rd 16			; names asked for lately: their hashes,
	g_od_askedt	rd 16			; and when
	align 16
	g_odw:		rb ODW_CAP * 16		; session, generation, the tick it gives up
	; the acme process's
	g_od_n		dd ?			; on-demand certificates, as acme's ACME_CERTS + i
	g_od_seen	dd ?			; requests read
	g_od_active	rb OD_MAX
	g_od_cfg	rd OD_MAX
	g_od_nl		rd OD_MAX
	g_od_names:	rb 256 * OD_MAX
	g_od_args:	rb A_SIZE * OD_MAX
end bss

; ------------------------------------------------------------- compiling

; rdi = the on_demand node, edx = its block's group (r13d of compile_tls), rbx
; free: recorded; a block with no certificate yet gets one signed here (the one
; served while a name waits, or is refused)
compile_tls_od:
	push	rbx
	push	r12
	push	r13
	mov	rbx,rdi
	mov	r13d,edx
	cmp	dword [g_plan_acme+ACM_ON],0
	je	.no_acme
	mov	eax,[g_plan_odn]
	cmp	eax,OD_CFGS
	jae	.too_many
	inc	dword [g_plan_odn]
	imul	r12,rax,OC_SIZE
	lea	r12,[g_plan_od+r12]
	mov	[r12+OC_GROUP],r13d
	mov	rax,[rbx+N_ARGS]
	mov	[r12+OC_PATS],rax
	mov	eax,[rbx+N_ARGC]
	mov	[r12+OC_NPAT],eax
	mov	dword [r12+OC_MAX],OD_MAX
	mov	qword [r12+OC_ASK],0
	mov	dword [r12+OC_ASKL],0
	; the patterns: names, or *.parent
	mov	r8,[rbx+N_ARGS]
	mov	r9d,[rbx+N_ARGC]
	xor	r10d,r10d			; patterns seen
.pat:
	test	r9d,r9d
	jz	.pats
	dec	r9d
	cmp	dword [r8+A_KIND],ARG_KV
	je	.pat_next
	inc	r10d
	mov	rsi,[r8+A_VAL]
	mov	ecx,[r8+A_VLEN]
	cmp	ecx,3
	jb	@f
	cmp	word [rsi],'*.'
	jne	@f
	add	rsi,2
	sub	ecx,2
@@:
	test	ecx,ecx
	jz	.bad
	cmp	ecx,253
	ja	.bad
@@:
	mov	al,[rsi]
	inc	rsi
	cmp	al,'.'
	je	.ch
	cmp	al,'-'
	je	.ch
	cmp	al,'0'
	jb	.bad
	cmp	al,'9'
	jbe	.ch
	or	al,0x20
	cmp	al,'a'
	jb	.bad
	cmp	al,'z'
	ja	.bad
.ch:
	dec	ecx
	jnz	@b
.pat_next:
	add	r8,A_SIZE
	jmp	.pat
.pats:
	push	r10
	mov	rdi,rbx
	cstring .k_ask, 'ask',0
	lea	rsi,[.k_ask]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,8
	jb	.bad_pop
	cmp	ecx,400
	ja	.bad_pop
	mov	rdx,'http://'
	shl	rdx,8
	mov	rax,[rsi]
	shl	rax,8
	cmp	rax,rdx
	jne	.bad_pop
	call	acme_safe
	jc	.bad_pop
	mov	[r12+OC_ASK],rsi
	mov	[r12+OC_ASKL],ecx
@@:
	mov	rdi,rbx
	cstring .k_max, 'max',0
	lea	rsi,[.k_max]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_decimal
	jc	.bad_pop
	test	eax,eax
	jz	.bad_pop
	cmp	eax,OD_MAX
	ja	.bad_pop
	mov	[r12+OC_MAX],eax
@@:
	pop	r10
	; a pattern, or ask=: at least one (else any name would be asked for)
	test	r10d,r10d
	jnz	@f
	cmp	dword [r12+OC_ASKL],0
	je	.unbounded
@@:
	; no certificate of its own: one signed here, for a name no one asks for
	cmp	[g_plan_tls],r13d
	ja	.out
	lea	rdi,[g_ac_names]
	cstring .ph, 'on-demand.okena.invalid',0
	lea	rsi,[.ph]
	mov	ecx,24
	rep	movsb
	mov	byte [rdi],0
	call	x5_keygen
	jc	.no_key
	lea	rsi,[g_ac_names]
	mov	edx,ACME_DAYS_SELF
	call	x5_selfsigned
	jc	.no_key
	mov	ecx,eax
	lea	rsi,[g_x5_der2]
	lea	rdx,[pem_l_cert]
	lea	rdi,[g_x5_pem]
	call	x5_pem
	mov	byte [rdi],0
	call	x5_sec1
	mov	ecx,eax
	lea	rsi,[g_x5_der]
	lea	rdx,[pem_l_ec]
	lea	rdi,[g_ac_kpem]
	call	x5_pem
	mov	byte [rdi],0
	lea	rdi,[g_ac_carg]
	lea	rsi,[g_x5_pem]
	call	.mem_arg
	lea	rdi,[g_ac_karg]
	lea	rsi,[g_ac_kpem]
	call	.mem_arg
	lea	rdi,[g_ac_carg]
	lea	rsi,[g_ac_karg]
	mov	edx,r13d
	call	compile_cert
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret
; rdi = an argument made up, rsi = its text (NUL-ended): in memory
.mem_arg:
	mov	dword [rdi+A_KIND],ARG_MEM
	mov	[rdi+A_VAL],rsi
	xor	ecx,ecx
@@:
	cmp	byte [rsi+rcx],0
	je	@f
	inc	ecx
	jmp	@b
@@:
	mov	[rdi+A_VLEN],ecx
	mov	dword [rdi+A_LINE],0
	mov	qword [rdi+A_RAW],0
	mov	dword [rdi+A_RAWLEN],0
	ret
.no_acme:
	mov	rdi,rbx
	call	tls_error_at_node
	out_lit 'on_demand needs the CA: okena { acme DIR ca=URL }'
	jmp	tls_error_end
.too_many:
	mov	rdi,rbx
	call	tls_error_at_node
	out_lit 'on_demand: 4 tls blocks at most'
	jmp	tls_error_end
.unbounded:
	mov	rdi,rbx
	call	tls_error_at_node
	out_lit 'on_demand needs names it may ask for (a name, or *.parent), or ask=http://URL that says yes or no, or both: else any name a stranger sends would be asked of the CA'
	jmp	tls_error_end
.bad_pop:
	pop	r10
.bad:
	mov	rdi,rbx
	call	tls_error_at_node
	out_lit 'on_demand takes names (or *.parent), ask=http://URL and max=N (262144 at most)'
	jmp	tls_error_end
.no_key:
	mov	rdi,rbx
	call	tls_error_at_node
	out_lit 'on_demand: no randomness for a key'
	jmp	tls_error_end

; rdi = a node: a diagnostic at it (its first argument, or its name)
tls_error_at_node:
	cmp	dword [rdi+N_ARGC],0
	jne	tls_error_at
	mov	rax,rdi
	mov	rdi,[rax+N_NAME]
	mov	esi,[rax+N_NLEN]
	mov	edx,[rax+N_LINE]
	jmp	cfg_error

; --------------------------------------------------------------- workers

; rdi = the listener's default entry, rsi/edx = the SNI: an on-demand
; certificate for it, when the listener has on_demand. rax = the entry to use
; (g_od_tl), or 0, then edx = 1 when one is coming (wait), 0 when not (go on).
; Keeps rbx, rbp, r12-r15.
od_hello:
	push	r12
	push	r13
	xor	eax,eax
	xor	r12d,r12d
	cmp	qword [g_od_page],0
	je	.go_on
	cmp	edx,253
	ja	.go_on
	; the listener's on_demand
	mov	r8d,[rdi+TL_GROUP]
	xor	ecx,ecx
@@:
	cmp	ecx,[g_plan_odn]
	jae	.go_on
	imul	r13,rcx,OC_SIZE
	lea	r13,[g_plan_od+r13]
	cmp	[r13+OC_GROUP],r8d
	je	@f
	inc	ecx
	jmp	@b
@@:
	mov	r12d,ecx			; (its number)
	; the name, lower case
	lea	rdi,[g_od_name]
	mov	ecx,edx
	mov	[g_od_namel],edx
@@:
	lodsb
	cmp	al,'A'
	jb	.low
	cmp	al,'Z'
	ja	.low
	or	al,0x20
.low:
	stosb
	dec	ecx
	jnz	@b
	; in the store?
	call	od_find
	test	rax,rax
	jz	.new
	cmp	dword [rax+ODS_STATE],2
	je	.there
	cmp	dword [rax+ODS_STATE],1
	je	.wait				; (asked for)
	jmp	.go_on				; refused
.there:
	call	od_copy
	jc	.go_on
	lea	rax,[g_od_tl]
	xor	edx,edx
	jmp	.out
.new:
	call	od_allowed			; by its patterns (ask= is the acme process's)
	jc	.go_on
	call	od_request
.wait:
	xor	eax,eax
	mov	edx,1
	jmp	.out
.go_on:
	xor	eax,eax
	xor	edx,edx
.out:
	pop	r13
	pop	r12
	ret

; rsi/ecx = a name: eax = where its probe begins. Keeps all but rax, rdx.
od_hash:
	push	rsi
	push	rcx
	mov	rax,0xCBF29CE484222325
	mov	rdx,0x100000001B3
.byte:
	test	ecx,ecx
	jz	.done
	xor	al,[rsi]
	imul	rax,rdx
	inc	rsi
	dec	ecx
	jmp	.byte
.done:
	mov	rdx,rax
	shr	rdx,29
	xor	rax,rdx
	and	eax,OD_SLOTS - 1
	pop	rcx
	pop	rsi
	ret

; eax = a slot's number: rax = it. Keeps all but rax.
macro od_ptr
	shl	rax,13				; ODS_SIZE
	add	rax,ODP_STORE
	add	rax,[g_od_page]
end macro
assert ODS_SIZE = 8192

; g_od_name: its slot in the store (whatever its state), or 0. Keeps r12, r13.
od_find:
	lea	rsi,[g_od_name]
	mov	ecx,[g_od_namel]
	call	od_hash
	mov	r9d,eax				; the slot's number
	mov	r10d,OD_PROBE
	mov	edx,[g_od_namel]
.slot:
	mov	eax,r9d
	od_ptr
	mov	r8,rax
	cmp	dword [r8+ODS_STATE],0
	je	.none				; (slots are never emptied: not further on)
	cmp	[r8+ODS_NLEN],edx
	jne	.next
	lea	rsi,[g_od_name]
	lea	rdi,[r8+ODS_NAME]
	mov	ecx,edx
	repe	cmpsb
	jne	.next
	mov	rax,r8
	ret
.next:
	inc	r9d
	and	r9d,OD_SLOTS - 1
	dec	r10d
	jnz	.slot
.none:
	xor	eax,eax
	ret

; rax = a slot that is there: its certificate and key into g_od_tl (and its
; chain past g_tls_store), under its seqlock. CF: changing, or too long.
od_copy:
	mov	r8,rax
	mov	r9d,3
.try:
	mov	r10d,[r8+ODS_SEQ]
	test	r10d,1
	jnz	.again
	mov	ecx,[r8+ODS_CLEN]
	cmp	ecx,ODS_CHAINMAX
	ja	.bad
	test	ecx,ecx
	jz	.bad
	lea	rdi,[g_od_tl]
	mov	[rdi+TL_CLEN],ecx
	mov	dword [rdi+TL_CHAIN],TLS_STORE + AX_CHAINMAX
	mov	dword [rdi+TL_KEYTYPE],0
	mov	dword [rdi+TL_ALT],-1
	mov	dword [rdi+TL_GROUP],-1
	lea	rsi,[r8+ODS_CHAIN]
	lea	rdi,[g_od_chain]
	rep	movsb
	lea	rsi,[r8+ODS_KEY]
	lea	rdi,[g_od_tl+TL_KEY]
	mov	ecx,32
	rep	movsb
	lea	rsi,[r8+ODS_PUB]
	lea	rdi,[g_od_tl+TL_PUB]
	mov	ecx,65
	rep	movsb
	cmp	r10d,[r8+ODS_SEQ]
	jne	.again
	clc
	ret
.again:
	dec	r9d
	jnz	.try
.bad:
	stc
	ret

; g_od_name, r13 = the block's on_demand: CF when no pattern allows it (no
; pattern at all: ask= decides). Keeps r12, r13.
od_allowed:
	mov	r8,[r13+OC_PATS]
	mov	r9d,[r13+OC_NPAT]
	xor	r10d,r10d			; patterns seen
.pat:
	test	r9d,r9d
	jz	.none
	dec	r9d
	cmp	dword [r8+A_KIND],ARG_KV
	je	.next
	inc	r10d
	mov	rsi,[r8+A_VAL]
	mov	ecx,[r8+A_VLEN]
	cmp	ecx,3
	jb	.exact
	cmp	word [rsi],'*.'
	jne	.exact
	; *.parent: a name ending in .parent, with a label before it
	dec	ecx				; ".parent"
	inc	rsi
	mov	edx,[g_od_namel]
	cmp	edx,ecx
	jbe	.next
	sub	edx,ecx
	lea	rdi,[g_od_name+rdx]
	jmp	.cmp
.exact:
	cmp	ecx,[g_od_namel]
	jne	.next
	lea	rdi,[g_od_name]
.cmp:
	mov	al,[rsi]			; (letters, digits, '.', '-': | 0x20 lowers
	or	al,0x20				; the letters, leaves the rest)
	cmp	al,[rdi]
	jne	.next
	inc	rsi
	inc	rdi
	dec	ecx
	jnz	.cmp
	clc
	ret
.next:
	add	r8,A_SIZE
	jmp	.pat
.none:
	test	r10d,r10d
	jnz	.no
	clc					; (no patterns: ask= decides)
	ret
.no:
	stc
	ret

; g_od_name, r12d = the block's on_demand: into the ring for the acme process,
; which is woken; not again for 10 s from this worker
od_request:
	; asked lately?
	lea	rsi,[g_od_name]
	mov	ecx,[g_od_namel]
	mov	eax,2166136261
@@:
	movzx	edx,byte [rsi]
	inc	rsi
	xor	eax,edx
	imul	eax,eax,16777619
	dec	ecx
	jnz	@b
	or	eax,1
	mov	ecx,eax
	and	ecx,15
	cmp	[g_od_asked+rcx*4],eax
	jne	@f
	mov	edx,[g_tick]
	sub	edx,[g_od_askedt+rcx*4]
	cmp	edx,10
	jb	.out
@@:
	mov	[g_od_asked+rcx*4],eax
	mov	edx,[g_tick]
	mov	[g_od_askedt+rcx*4],edx
	mov	r8,[g_od_page]
	mov	eax,1
	lock xadd [r8+ODP_N],eax		; its number
	mov	r9d,eax
	and	eax,ODR_N - 1
	imul	eax,eax,ODR_SIZE
	lea	r10,[r8+ODP_RING+rax]
	mov	dword [r10+ODR_READY],0
	mov	[r10+ODR_CFG],r12d
	mov	ecx,[g_od_namel]
	mov	[r10+ODR_LEN],ecx
	lea	rdi,[r10+ODR_NAME]
	lea	rsi,[g_od_name]
	rep	movsb
	inc	r9d
	mov	[r10+ODR_READY],r9d
	; the acme process woken
	mov	r8,[g_acme_page]
	lock inc dword [r8+AH_REVSEQ]
	lea	rdi,[r8+AH_REVSEQ]
	mov	esi,FUTEX_WAKE
	mov	edx,1
	mov	eax,SYS_futex
	syscall
.out:
	ret

; ebx = session, r15 = its record: tls_hello said TH_WAIT. Parked (a session
; that was parked keeps when it gives up), looked at again each second.
od_park:
	cmp	dword [g_odw_count],ODW_CAP
	jae	.full
	mov	eax,[g_odw_head]
	add	eax,[g_odw_count]
	and	eax,ODW_CAP - 1
	shl	eax,4
	lea	rcx,[g_odw+rax]
	mov	[rcx],ebx
	push	rcx
	call	session_ptr
	pop	rcx
	mov	eax,[rax+S_GEN]
	mov	[rcx+4],eax
	mov	eax,[g_odw_deadline]
	test	eax,eax
	jnz	@f
	mov	eax,[g_tick]
	add	eax,OD_WAIT
@@:
	mov	[rcx+8],eax
	inc	dword [g_odw_count]
	mov	dword [r15+H_STATE],HS_TLS_ODWAIT
	ret
.full:
	; no room to wait: on, with the listener's certificate
	mov	rax,[r15+H_BUF]
	or	dword [rax+HB_TS+TS_FLAGS],TF_ODWAITED
	jmp	http_tls_hello_go

; once a second (tick_work): each parked handshake tried again; past its time,
; it goes on without
od_tick:
	cmp	dword [g_odw_count],0
	je	.idle
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r13d,[g_odw_count]		; (only those parked before this tick)
.next:
	test	r13d,r13d
	jz	.done
	dec	r13d
	mov	eax,[g_odw_head]
	mov	ecx,eax
	inc	ecx
	and	ecx,ODW_CAP - 1
	mov	[g_odw_head],ecx
	dec	dword [g_odw_count]
	shl	eax,4
	lea	r12,[g_odw+rax]
	mov	ebx,[r12]
	call	session_ptr
	mov	ecx,[r12+4]
	cmp	ecx,[rax+S_GEN]
	jne	.next
	cmp	dword [rax+S_STATE],ST_OPEN
	jne	.next
	h_rec
	cmp	dword [r15+H_STATE],HS_TLS_ODWAIT
	jne	.next
	mov	eax,[r12+8]
	mov	[g_odw_deadline],eax
	cmp	eax,[g_tick]
	ja	@f
	mov	rax,[r15+H_BUF]			; its time is up
	or	dword [rax+HB_TS+TS_FLAGS],TF_ODWAITED
@@:
	mov	dword [r15+H_STATE],HS_TLS_HELLO
	call	http_tls_hello_go
	mov	dword [g_odw_deadline],0
	jmp	.next
.done:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
.idle:
	ret

; ------------------------------------------------------- the acme process

; ebx = one of acme's certificates: rax = its names (arguments), ecx how many
acme_cert_args:
	cmp	ebx,ACME_CERTS
	jae	.od
	mov	eax,ebx
	shl	eax,4
	mov	ecx,[g_plan_acme+ACM_CERT+rax+8]
	mov	rax,[g_plan_acme+ACM_CERT+rax]
	ret
.od:
	lea	eax,[rbx-ACME_CERTS]
	imul	eax,eax,A_SIZE
	lea	rax,[g_od_args+rax]
	mov	ecx,1
	ret

; ebx = the next certificate to look at (as the loops count it): moved on to
; one there is (the configured, then the on-demand ones that are). CF: none left.
acme_more:
	cmp	ebx,ACME_CERTS
	jae	.od
	cmp	ebx,[g_plan_acme+ACM_NCERT]
	jb	.yes
	mov	ebx,ACME_CERTS
.od:
	lea	eax,[rbx-ACME_CERTS]
	cmp	eax,[g_od_n]
	jae	.no
	cmp	byte [g_od_active+rax],0
	jne	.yes
	inc	ebx
	jmp	.od
.yes:
	clc
	ret
.no:
	stc
	ret

; the name given an on-demand certificate i (eax): its synthetic argument
od_arg:
	imul	ecx,eax,A_SIZE
	lea	rdi,[g_od_args+rcx]
	imul	ecx,eax,256
	lea	rsi,[g_od_names+rcx]
	mov	[rdi+A_VAL],rsi
	mov	ecx,[g_od_nl+rax*4]
	mov	[rdi+A_VLEN],ecx
	mov	dword [rdi+A_KIND],ARG_WORD
	ret

; rsi/ecx = a name (lower case), edx = its on_demand: a certificate of acme's
; for it (ebx = ACME_CERTS + i), its directory made. CF: no room.
od_register:
	mov	eax,[g_od_n]
	cmp	eax,OD_MAX
	jae	.full
	inc	dword [g_od_n]
	mov	[g_od_cfg+rax*4],edx
	mov	[g_od_nl+rax*4],ecx
	imul	edi,eax,256
	lea	rdi,[g_od_names+rdi]
	rep	movsb
	mov	byte [g_od_active+rax],1
	push	rax
	call	od_arg
	pop	rax
	lea	ebx,[rax+ACME_CERTS]
	mov	qword [g_ac_due+rbx*8],-1
	mov	qword [g_ac_back+rbx*8],0
	mov	qword [g_ac_revdone+rbx*8],0
	cstring .none, '',0
	lea	rsi,[.none]
	call	acme_path			; DIR/NAME
	mov	edi,AT_FDCWD
	lea	rsi,[g_ac_fpath]
	mov	edx,0x1C0
	mov	eax,SYS_mkdirat_
	syscall
	clc
	ret
.full:
	stc
	ret

; ebx = an on-demand certificate: its slot in the store (found or taken), rax.
; CF: none free.
od_slot:
	lea	eax,[rbx-ACME_CERTS]
	imul	esi,eax,256
	lea	rsi,[g_od_names+rsi]
	mov	ecx,[g_od_nl+rax*4]
; rsi/ecx = a name: its slot (found, or the free one its probe reaches, made
; its), rax. Only the acme process writes a slot's name: no race for one.
od_slot_of:
	call	od_hash
	mov	r11d,eax
	mov	r10d,OD_PROBE
.slot:
	mov	eax,r11d
	od_ptr
	mov	r8,rax
	mov	eax,[r8+ODS_STATE]
	test	eax,eax
	jz	.free
	cmp	[r8+ODS_NLEN],ecx
	jne	.next
	push	rsi
	push	rcx
	lea	rdi,[r8+ODS_NAME]
	repe	cmpsb
	pop	rcx
	pop	rsi
	jne	.next
	mov	rax,r8
	clc
	ret
.next:
	inc	r11d
	and	r11d,OD_SLOTS - 1
	dec	r10d
	jnz	.slot
	jmp	.none
.free:
	mov	r9,r8
	inc	dword [r9+ODS_SEQ]
	mov	[r9+ODS_NLEN],ecx
	lea	rdi,[r9+ODS_NAME]
	rep	movsb
	mov	dword [r9+ODS_CLEN],0
	mov	dword [r9+ODS_STATE],1
	inc	dword [r9+ODS_SEQ]
	mov	rax,r9
	clc
	ret
.none:
	stc
	ret

; rax = a slot, edx = its state (1 asked for, 3 refused for OD_REFUSE s)
od_slot_state:
	push	rax
	push	rdx
	call	acme_now
	add	rax,OD_REFUSE
	mov	rcx,rax
	pop	rdx
	pop	rax
	inc	dword [rax+ODS_SEQ]
	mov	[rax+ODS_UNTIL],rcx
	mov	[rax+ODS_STATE],edx
	inc	dword [rax+ODS_SEQ]
	ret

; ebx = an on-demand certificate with its files: into the store (its chain as a
; certificate_list, its key), there for the workers. CF: they cannot be read.
od_publish:
	push	r12
	push	r13
	call	od_slot
	jc	.bad
	mov	r12,rax
	; the key
	cstring .f_key, '/key.pem',0
	lea	rsi,[.f_key]
	call	acme_path
	call	acme_read
	jc	.bad
	lea	rsi,[g_ac_file]
	lea	rdx,[g_ac_file+rax]
	lea	rdi,[pem_ec_key]
	call	pem_next
	test	eax,eax
	jle	.bad
	lea	rsi,[g_tls_der]
	mov	edx,eax
	call	key_sec1
	test	eax,eax
	jnz	.bad
	; the chain
	cstring .f_cert, '/cert.pem',0
	lea	rsi,[.f_cert]
	call	acme_path
	call	acme_read
	jc	.bad
	lea	rdx,[g_ac_file+rax]
	push	rdx				; (its end)
	inc	dword [r12+ODS_SEQ]
	lea	rsi,[g_tls_d]
	lea	rdi,[r12+ODS_KEY]
	mov	ecx,32
	rep	movsb
	lea	rdi,[r12+ODS_PUB]
	lea	rsi,[r12+ODS_KEY]
	call	p256_public
	lea	rsi,[g_ac_file]
	lea	r13,[r12+ODS_CHAIN]		; the list's cursor
.cert:
	mov	rdx,[rsp]
	lea	rdi,[pem_certificate]
	call	pem_next			; g_tls_der, eax; rsi past it
	cmp	eax,0
	jle	.chain_done
	lea	ecx,[rax+5]
	lea	r8,[r13+rcx]
	lea	r9,[r12+ODS_SIZE]
	cmp	r8,r9
	ja	.chain_done
	mov	ecx,eax
	bswap	eax
	shr	eax,8
	mov	[r13],ax
	shr	eax,16
	mov	[r13+2],al
	push	rsi
	lea	rdi,[r13+3]
	lea	rsi,[g_tls_der]
	rep	movsb
	pop	rsi
	mov	word [rdi],0
	lea	r13,[rdi+2]
	jmp	.cert
.chain_done:
	add	rsp,8
	lea	rax,[r12+ODS_CHAIN]
	sub	r13,rax
	mov	[r12+ODS_CLEN],r13d
	mov	dword [r12+ODS_STATE],2
	inc	dword [r12+ODS_SEQ]
	test	r13d,r13d
	jz	.bad
	clc
	jmp	.out
.bad:
	stc
.out:
	pop	r13
	pop	r12
	ret

; The requests the workers put in the ring: each name (not one already) asked
; of ask= (when the block has it), counted against max=, registered (its
; certificate due now) and named in DIR/on_demand.list; refused ones refused in
; the store for a while.
od_requests:
	push	rbx
	push	r12
	push	r13
	push	r14
.next:
	mov	r8,[g_od_page]
	mov	eax,[g_od_seen]
	cmp	eax,[r8+ODP_N]
	jae	.done
	mov	ecx,eax
	and	ecx,ODR_N - 1
	imul	ecx,ecx,ODR_SIZE
	lea	r12,[r8+ODP_RING+rcx]
	lea	edx,[rax+1]
	mov	ecx,[r12+ODR_READY]
	cmp	ecx,edx
	je	.take
	jb	.done				; (being written)
	mov	ecx,[r8+ODP_N]			; overwritten: on to the oldest there
	sub	ecx,ODR_N
	mov	[g_od_seen],ecx
	jmp	.next
.take:
	inc	dword [g_od_seen]
	mov	r13d,[r12+ODR_CFG]
	cmp	r13d,[g_plan_odn]
	jae	.next
	mov	r14d,[r12+ODR_LEN]
	test	r14d,r14d
	jz	.next
	cmp	r14d,253
	ja	.next
	lea	rsi,[r12+ODR_NAME]		; (a copy: the ring may be written over)
	lea	rdi,[g_od_name]
	mov	ecx,r14d
	rep	movsb
	mov	[g_od_namel],r14d
	; already one
	xor	ebx,ebx
.known:
	cmp	ebx,[g_od_n]
	jae	.new
	cmp	[g_od_nl+rbx*4],r14d
	jne	.known_next
	imul	esi,ebx,256
	lea	rsi,[g_od_names+rsi]
	lea	rdi,[g_od_name]
	mov	ecx,r14d
	repe	cmpsb
	je	.next
.known_next:
	inc	ebx
	jmp	.known
.new:
	; max=
	xor	ecx,ecx
	xor	edx,edx
@@:
	cmp	ecx,[g_od_n]
	jae	@f
	cmp	[g_od_cfg+rcx*4],r13d
	jne	.not_its
	inc	edx
.not_its:
	inc	ecx
	jmp	@b
@@:
	imul	rax,r13,OC_SIZE
	cmp	edx,[g_plan_od+rax+OC_MAX]
	jae	.refuse
	; ask=
	cmp	dword [g_plan_od+rax+OC_ASKL],0
	je	.yes
	call	od_ask
	jc	.refuse
.yes:
	lea	rsi,[g_od_name]
	mov	ecx,r14d
	mov	edx,r13d
	call	od_register
	jc	.refuse
	; (its slot: asked for, so the workers wait)
	lea	rsi,[g_od_name]
	mov	ecx,r14d
	call	od_slot_of
	jc	@f
	mov	edx,1
	call	od_slot_state
@@:
	call	od_list_add
	call	log_begin
	out_lit 'acme: on demand: '
	lea	rsi,[g_od_name]
	mov	edx,r14d
	call	out_str
	out_lit ': asking the CA for a certificate'
	call	log_end
	jmp	.next
.refuse:
	lea	rsi,[g_od_name]
	mov	ecx,r14d
	call	od_slot_of
	jc	@f
	mov	edx,3
	call	od_slot_state
@@:
	call	log_begin
	out_lit 'acme: on demand: '
	lea	rsi,[g_od_name]
	mov	edx,r14d
	call	out_str
	out_lit ': not asked for (ask= said no, or max= is reached)'
	call	log_end
	jmp	.next
.done:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rax = the on_demand's plan entry, g_od_name: GET its ask= URL?domain=NAME;
; CF unless 200
od_ask:
	push	rbx
	mov	rbx,rax
	mov	rsi,[g_plan_od+rbx+OC_ASK]
	add	rsi,7
	mov	ecx,[g_plan_od+rbx+OC_ASKL]
	sub	ecx,7
	xor	edx,edx				; the authority
@@:
	cmp	edx,ecx
	jae	@f
	cmp	byte [rsi+rdx],'/'
	je	@f
	cmp	byte [rsi+rdx],'?'
	je	@f
	inc	edx
	jmp	@b
@@:
	test	edx,edx
	jz	.no
	push	rcx
	push	rsi
	push	rdx
	; host and port into g_oc_host / g_oc_port
	mov	dword [g_oc_port],80
	mov	r8d,edx
	mov	r9d,edx
.colon:
	dec	r9d
	js	.host
	cmp	byte [rsi+r9],']'
	je	.host
	cmp	byte [rsi+r9],':'
	jne	.colon
	push	rsi
	push	rdx
	lea	rdi,[rsi+r9+1]
	mov	esi,edx
	sub	esi,r9d
	dec	esi
	call	parse_decimal
	pop	rdx
	pop	rsi
	jc	.no_pop
	mov	[g_oc_port],eax
	mov	r8d,r9d
.host:
	mov	[g_oc_hostl],r8d
	lea	rdi,[g_oc_host]
	mov	ecx,r8d
	push	rsi
	rep	movsb
	pop	rsi
	pop	rdx
	pop	rsi
	pop	rcx
	; GET PATH?domain=NAME
	push	rsi
	push	rcx
	push	rdx
	lea	rdi,[g_ac_req]
	memit_x 'GET '
	mov	rdx,[rsp]
	mov	rcx,[rsp+8]
	mov	rsi,[rsp+16]
	lea	rsi,[rsi+rdx]
	sub	ecx,edx
	jnz	@f
	mov	byte [rdi],'/'
	inc	rdi
@@:
	xor	r8d,r8d				; a '?' in it
@@:
	test	ecx,ecx
	jz	@f
	lodsb
	stosb
	dec	ecx
	cmp	al,'?'
	jne	@b
	inc	r8d
	jmp	@b
@@:
	mov	al,'?'
	test	r8d,r8d
	jz	@f
	mov	al,'&'
@@:
	stosb
	memit_x 'domain='
	lea	rsi,[g_od_name]
	mov	ecx,[g_od_namel]
	rep	movsb
	memit_x ' HTTP/1.1',13,10,'Host: '
	pop	rdx
	pop	rcx
	pop	rsi
	mov	ecx,edx
	rep	movsb
	memit_x 13,10,'User-Agent: okena',13,10,'Connection: close',13,10,13,10
	mov	rbx,rdi
	lea	rdi,[g_oc_sa]
	lea	rsi,[g_oc_host]
	mov	ecx,[g_oc_hostl]
	mov	edx,[g_oc_port]
	call	cx_address
	jc	.no
	lea	rsi,[g_oc_sa]
	call	cx_connect
	jc	.no
	lea	rsi,[g_ac_req]
	mov	rdx,rbx
	sub	rdx,rsi
	call	cx_send
	jc	.closed
	call	cx_answer
	jc	.closed
	call	cx_close
	call	cx_status
	jc	.no
	cmp	eax,200
	jne	.no
	clc
	pop	rbx
	ret
.closed:
	call	cx_close
	jmp	.no
.no_pop:
	add	rsp,24
.no:
	stc
	pop	rbx
	ret

; g_od_name: a line of DIR/on_demand.list (so a restart serves and renews it)
od_list_add:
	mov	ebx,-1
	cstring .f_list, '/on_demand.list',0
	lea	rsi,[.f_list]
	call	acme_path
	mov	edi,AT_FDCWD
	lea	rsi,[g_ac_fpath]
	mov	edx,O_WRONLY or O_CREAT or O_APPEND or O_CLOEXEC
	mov	r10d,0x180
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	js	.out
	push	rax
	lea	rsi,[g_od_name]
	mov	ecx,[g_od_namel]
	lea	rdi,[g_ac_tmp]
	rep	movsb
	mov	byte [rdi],10
	mov	edi,[rsp]
	lea	rsi,[g_ac_tmp]
	mov	edx,[g_od_namel]
	inc	edx
	call	write_all
	pop	rdi
	mov	eax,SYS_close
	syscall
.out:
	ret

; at the start: the names DIR/on_demand.list holds whose files are there,
; registered and served (their renewal as the others')
od_load:
	push	rbx
	push	r12
	push	r13
	mov	ebx,-1
	lea	rsi,[od_list_add.f_list]
	call	acme_path
	call	acme_read
	jc	.out
	lea	r12,[g_ac_body]			; (a copy: acme_read's and acme_file_due's
						; buffers are used below)
	cmp	eax,16000
	jbe	@f
	mov	eax,16000
@@:
	mov	r13d,eax
	lea	rsi,[g_ac_file]
	mov	rdi,r12
	mov	ecx,eax
	rep	movsb
	xor	ecx,ecx
.line:
	cmp	ecx,r13d
	jae	.out
	mov	edx,ecx				; its start
@@:
	cmp	ecx,r13d
	jae	@f
	cmp	byte [r12+rcx],10
	je	@f
	inc	ecx
	jmp	@b
@@:
	push	rcx
	mov	eax,ecx
	sub	eax,edx
	jz	.skip
	cmp	eax,253
	ja	.skip
	; not twice
	lea	rsi,[r12+rdx]
	mov	[g_od_namel],eax
	lea	rdi,[g_od_name]
	mov	ecx,eax
	rep	movsb
	xor	ebx,ebx
.dup:
	cmp	ebx,[g_od_n]
	jae	.reg
	mov	eax,[g_od_namel]
	cmp	[g_od_nl+rbx*4],eax
	jne	.dup_next
	imul	esi,ebx,256
	lea	rsi,[g_od_names+rsi]
	lea	rdi,[g_od_name]
	mov	ecx,eax
	repe	cmpsb
	je	.skip
.dup_next:
	inc	ebx
	jmp	.dup
.reg:
	lea	rsi,[g_od_name]
	mov	ecx,[g_od_namel]
	xor	edx,edx
	call	od_register
	jc	.skip
	call	acme_file_due
	cmp	qword [g_ac_end+rbx*8],0
	jne	@f
	lea	eax,[rbx-ACME_CERTS]		; no certificate there: not served
	mov	byte [g_od_active+rax],0
	jmp	.skip
@@:
	call	od_publish
.skip:
	pop	rcx
	inc	ecx
	jmp	.line
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret
