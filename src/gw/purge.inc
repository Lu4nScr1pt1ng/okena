; Purge: what `cache` keeps, taken back by URL, by prefix or by tag, at once, from
; every worker's memory and from the disk store.
;
;   okena purge url https://example.com/a/b?c=1
;   okena purge prefix example.com/assets/
;   okena purge tag product-42           (Cache-Tag, Surrogate-Key)
;   POST /purge?url=...|prefix=...|tag=...   on the metrics listener, with its token
;
; A purge is a rule in a ring that every worker reads: its time, its kind, what it
; names. Nothing is looked for when it is made; an answer is checked when it is
; about to be served, against the rules made after it was fetched (the time its
; fetch began: one in flight when the purge came is purged too). The newest rule's
; time says at once that most answers need no look. When the ring goes round, what
; was fetched before the rule it loses is taken as purged: never served after a
; purge, at worst fetched again.
;
; With `cache_disk` the ring is in okena.idx: every okena process on the store sees
; it, and it outlives them, as what is on disk does. Without, the supervisor's.
;
; `okena { fleet ADDR... }`: the metrics listeners of the other instances; `okena
; purge` asks each of them too (POST /purge, with this one's metrics token), and says
; how each answered.
;
; An answer's purge facts (PM): u16 host length, host, u16 target length, target,
; then its tags, a byte of length each; a tag of length 0 says there were more than
; the room held (then any tag purge takes it).

PR_N		:= 1024
PR_HDR		:= 64
PR_SEQ		:= 0				; q: rules made, ever
PR_LAST		:= 8				; q: µs (wall clock) of the newest
PR_FLOOR	:= 16				; q: fetched before this: purged (the ring went round)
RL_SEQ		:= 0				; q: its number + 1, once whole
RL_TIME		:= 8				; q: µs
RL_KIND		:= 16				; d
RL_HLEN		:= 20				; d: url, prefix: the host's length, first in TEXT
RL_LEN		:= 24				; d: TEXT's length
RL_TEXT		:= 32
RL_SIZE		:= 256
RL_TMAX		:= RL_SIZE - RL_TEXT
PR_SIZE		:= PR_HDR + PR_N * RL_SIZE
PK_URL		:= 1
PK_PREFIX	:= 2
PK_TAG		:= 3
PM_MAX		:= 1024				; an answer's purge facts, at most
MAX_FLEET	:= 16

bss
	align 8
	g_pr_base	dq ?			; the ring
	g_pr_anon	dq ?			; the supervisor's, without a store
	g_pr_now	dq ?
	g_plan_fleet	dd ?			; fleet: how many
	g_plan_fleet_sa	rb 32 * MAX_FLEET
	g_plan_fleet_sl	rd MAX_FLEET
	g_plan_fleet_tx	rq MAX_FLEET		; as written (its Host)
	g_plan_fleet_tl	rd MAX_FLEET
	g_pm:		rb PM_MAX		; an answer's facts, in one piece, to look at
	g_pr_dec:	rb RL_TMAX + 16		; a value from a query, decoded
end bss

; the supervisor, before any fork: a ring for those without a store
pr_init:
	cmp	qword [g_pr_anon],0
	jne	.there
	xor	edi,edi
	mov	esi,PR_SIZE
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_ANONYMOUS
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	test	rax,rax
	js	.none
	mov	[g_pr_anon],rax
.there:
	mov	rax,[g_pr_anon]
	mov	[g_pr_base],rax
.none:
	ret

; g_pr_now = µs, wall clock
pr_clock:
	sub	rsp,24
	mov	edi,CLOCK_REALTIME
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	imul	rax,[rsp],1000000
	mov	rcx,rax
	mov	rax,[rsp+8]
	xor	edx,edx
	mov	r8d,1000
	div	r8
	add	rax,rcx
	mov	[g_pr_now],rax
	add	rsp,24
	ret

; edi = kind, rsi/edx = host (url, prefix), rcx/r8d = the rest (the target, or the
; tag): a rule. CF: too long. Keeps rbx, r12-r15.
pr_add:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12d,edi
	mov	r13,rsi
	mov	r14d,edx
	mov	r15,rcx
	lea	eax,[rdx+r8]
	cmp	eax,RL_TMAX
	ja	.long
	push	r8
	call	pr_clock
	pop	r8
	mov	rbx,[g_pr_base]
	test	rbx,rbx
	jz	.long
	mov	eax,1
	lock xadd [rbx+PR_SEQ],rax		; its number
	mov	rcx,rax
	and	ecx,PR_N - 1
	imul	rcx,rcx,RL_SIZE
	lea	rdi,[rbx+PR_HDR+rcx]
	; the rule it takes the place of: whatever came before it is purged now
	cmp	rax,PR_N
	jb	.place
	mov	rcx,[rdi+RL_TIME]
	mov	rdx,rax
	mov	rax,[rbx+PR_FLOOR]
@@:
	cmp	rax,rcx
	jae	@f
	lock cmpxchg [rbx+PR_FLOOR],rcx
	jne	@b
@@:
	mov	rax,rdx
.place:
	mov	qword [rdi+RL_SEQ],0		; (not whole while it is written)
	mov	rcx,[g_pr_now]
	mov	[rdi+RL_TIME],rcx
	mov	[rdi+RL_KIND],r12d
	mov	[rdi+RL_HLEN],r14d
	lea	ecx,[r14+r8]
	mov	[rdi+RL_LEN],ecx
	push	rdi
	push	rax
	add	rdi,RL_TEXT
	mov	rsi,r13
	mov	ecx,r14d
	rep	movsb
	mov	rsi,r15
	mov	ecx,r8d
	rep	movsb
	pop	rax
	pop	rdi
	inc	rax
	mov	[rdi+RL_SEQ],rax		; whole (x86 keeps stores in order)
	mov	rcx,[g_pr_now]
	mov	rax,[rbx+PR_LAST]
@@:
	cmp	rax,rcx
	jae	@f
	lock cmpxchg [rbx+PR_LAST],rcx
	jne	@b
@@:
	clc
	jmp	.out
.long:
	stc
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = µs an answer's fetch began: CF when a rule may name it (its facts must be
; looked at), the fast way. Keeps all but rax.
macro pr_maybe
	local no
	mov	rax,[g_pr_base]
	test	rax,rax
	jz	no				; (clears CF)
	cmp	rdi,[rax+PR_LAST]		; CF: fetched before the newest
no:
end macro

; rdi = µs its fetch began, g_pm/esi = its facts: CF when purged. Keeps rbx, r12-r15.
pr_check:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	rbx,[g_pr_base]
	test	rbx,rbx
	jz	.kept
	mov	r12,rdi
	mov	r13d,esi
	cmp	r12,[rbx+PR_LAST]
	jae	.kept
	cmp	r12,[rbx+PR_FLOOR]
	jb	.purged
	mov	r14,[rbx+PR_SEQ]		; newest first
	mov	r15d,PR_N
.rule:
	test	r14,r14
	jz	.kept
	test	r15d,r15d
	jz	.kept
	dec	r14
	dec	r15d
	mov	rcx,r14
	and	ecx,PR_N - 1
	imul	rcx,rcx,RL_SIZE
	lea	rdi,[rbx+PR_HDR+rcx]
	lea	rax,[r14+1]
	cmp	[rdi+RL_SEQ],rax
	jne	.rule				; (being written, or replaced: the floor has it)
	cmp	[rdi+RL_TIME],r12
	jbe	.kept				; older than the answer: so are the rest
	mov	esi,r13d
	call	pr_match
	jc	.purged
	jmp	.rule
.kept:
	clc
	jmp	.out
.purged:
	stc
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = a rule, g_pm/esi = an answer's facts: CF when the rule names it
pr_match:
	lea	r8,[g_pm]
	lea	r9,[r8+rsi]			; the end
	movzx	ecx,word [r8]			; its host
	lea	r10,[r8+2]
	lea	r11,[r10+rcx]
	cmp	r11,r9
	ja	.no
	cmp	dword [rdi+RL_KIND],PK_TAG
	je	.tag
	; url, prefix: the same host, in any case
	cmp	ecx,[rdi+RL_HLEN]
	jne	.no
	push	rdi
	lea	rsi,[rdi+RL_TEXT]
	mov	rdi,r10
	mov	edx,ecx
	push	r8
	push	r9
	push	r11
	call	mem_eq_nocase
	pop	r11
	pop	r9
	pop	r8
	pop	rdi
	test	eax,eax
	jz	.no
	movzx	ecx,word [r11]			; its target
	lea	rsi,[r11+2]
	lea	rax,[rsi+rcx]
	cmp	rax,r9
	ja	.no
	mov	edx,[rdi+RL_LEN]
	sub	edx,[rdi+RL_HLEN]		; the rule's target
	cmp	dword [rdi+RL_KIND],PK_PREFIX
	je	@f
	cmp	ecx,edx
	jne	.no
	jmp	.cmp
@@:
	cmp	ecx,edx
	jb	.no
.cmp:
	mov	ecx,edx
	mov	eax,[rdi+RL_HLEN]
	lea	rdi,[rdi+RL_TEXT+rax]
	repe	cmpsb
	jne	.no
	stc
	ret
.tag:
	; past the target, its tags
	movzx	ecx,word [r11]
	lea	r10,[r11+2+rcx]
.next_tag:
	cmp	r10,r9
	jae	.no
	movzx	ecx,byte [r10]
	inc	r10
	test	ecx,ecx
	jz	.yes				; (more tags than room: any tag purge)
	lea	rax,[r10+rcx]
	cmp	rax,r9
	ja	.no
	cmp	ecx,[rdi+RL_LEN]
	jne	.other_tag
	push	rdi
	mov	rsi,r10
	lea	rdi,[rdi+RL_TEXT]
	repe	cmpsb
	pop	rdi
	je	.yes
	movzx	ecx,byte [r10-1]
.other_tag:
	add	r10,rcx
	jmp	.next_tag
.yes:
	stc
	ret
.no:
	clc
	ret

; ------------------------------------------------------- an answer's facts

; r9 = an entry's (first, last, length) of facts, as cw_put takes them: g_ck's
; request's host and target in. CF: no room.
pm_request:
	push	rbx
	push	r12
	push	r13
	mov	r13,r9
	lea	rdi,[.host]
	mov	esi,4
	call	limit_find
	mov	r12,rsi
	mov	ebx,ecx
	cmp	ebx,255
	jbe	@f
	mov	ebx,255
@@:
	sub	rsp,8
	mov	[rsp],bx
	mov	rsi,rsp
	mov	ecx,2
	mov	r9,r13
	call	cw_put
	jc	.out8
	mov	rsi,r12
	mov	ecx,ebx
	mov	r9,r13
	call	cw_put
	jc	.out8
	mov	ecx,[g_hm+HM_TLEN]
	cmp	ecx,PM_MAX - 300
	jbe	@f
	mov	ecx,PM_MAX - 300		; (a target that long: its start)
@@:
	mov	ebx,ecx
	mov	[rsp],bx
	mov	rsi,rsp
	mov	ecx,2
	mov	r9,r13
	call	cw_put
	jc	.out8
	mov	rsi,[g_hm+HM_TARGET]
	mov	ecx,ebx
	mov	r9,r13
	call	cw_put
.out8:
	lea	rsp,[rsp+8]
	pop	r13
	pop	r12
	pop	rbx
	ret
.host	db 'host'

; r12 = an entry being filled, g_hm = its answer's head: its tags (Cache-Tag, comma
; between them; Surrogate-Key, spaces) added to its facts. Keeps rbx, r12-r15.
pm_tags:
	push	rbx
	push	r13
	push	r14
	push	r15
	xor	ebx,ebx
.field:
	cmp	ebx,[g_hm+HM_NHDR]
	jae	.done
	imul	r13,rbx,HF_SIZE
	lea	r13,[g_hm+HM_HDRS+r13]
	inc	ebx
	mov	rdi,[r13+HF_NAME]
	mov	esi,[r13+HF_NLEN]
	lea	rdx,[.names]
	call	name_in
	jz	.field
	mov	rsi,[r13+HF_VALUE]
	mov	eax,[r13+HF_VLEN]
	lea	r15,[rsi+rax]
.tag:
	cmp	rsi,r15
	jae	.field
	mov	al,[rsi]
	cmp	al,' '
	je	.sep
	cmp	al,','
	je	.sep
	cmp	al,9
	jne	.word
.sep:
	inc	rsi
	jmp	.tag
.word:
	mov	r14,rsi
@@:
	cmp	rsi,r15
	jae	@f
	mov	al,[rsi]
	cmp	al,' '
	je	@f
	cmp	al,','
	je	@f
	cmp	al,9
	je	@f
	inc	rsi
	jmp	@b
@@:
	mov	rcx,rsi
	sub	rcx,r14
	cmp	ecx,255
	ja	.more
	mov	eax,[r12+CE_MLEN]
	lea	eax,[rax+rcx+1]
	cmp	eax,PM_MAX - 1
	ja	.more
	push	rsi
	push	rcx
	sub	rsp,8
	mov	[rsp],cl
	mov	rsi,rsp
	mov	ecx,1
	lea	r9,[r12+CE_META]
	call	cw_put
	lea	rsp,[rsp+8]
	pop	rcx
	jc	.fail
	mov	rsi,r14
	lea	r9,[r12+CE_META]
	call	cw_put
	pop	rsi
	jc	.no
	jmp	.tag
.fail:
	pop	rsi
	jmp	.no
.more:
	; no room for all: a mark that any tag purge takes it
	sub	rsp,8
	mov	byte [rsp],0
	mov	rsi,rsp
	mov	ecx,1
	lea	r9,[r12+CE_META]
	call	cw_put
	lea	rsp,[rsp+8]
	jc	.no
.done:
	clc
	jmp	.out
.no:
	stc
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	rbx
	ret
.names	db 9,'cache-tag',13,'surrogate-key',0

; eax = an entry: its facts into g_pm, esi = their length
pm_gather:
	ce_ptr
	mov	esi,[rax+CE_MLEN]
	mov	ecx,esi
	mov	edx,[rax+CE_META]
	lea	rdi,[g_pm]
.block:
	test	ecx,ecx
	jz	.done
	cmp	edx,NIL
	je	.done
	mov	r8d,ecx
	cmp	r8d,CB_SIZE
	jbe	@f
	mov	r8d,CB_SIZE
@@:
	sub	ecx,r8d
	push	rcx
	push	rsi
	mov	rsi,rdx
	shl	rsi,CB_SHIFT
	add	rsi,[g_cb_base]
	mov	ecx,r8d
	rep	movsb
	pop	rsi
	pop	rcx
	mov	r8,[g_cb_nexts]
	mov	edx,[r8+rdx*4]
	jmp	.block
.done:
	ret

; eax = a ready entry of memory: CF when a purge took it (then it is gone).
; Keeps rbx, r12-r15.
pm_purged:
	push	rax				; the entry
	ce_ptr
	mov	rdi,[rax+CE_RB]
	pr_maybe
	jnc	.kept
	mov	eax,[rsp]
	call	pm_gather
	mov	eax,[rsp]
	ce_ptr
	mov	rdi,[rax+CE_RB]
	call	pr_check
	jnc	.kept
	pop	rdi
	call	ce_kill
	stc
	ret
.kept:
	pop	rax
	clc
	ret

; --------------------------------------------------------- asking for one

; rsi/ecx = a URL, with or without its scheme: rsi/edx = its host, r8/r9d = its
; target ("/" when none)
pr_split_url:
	lea	rax,[rsi+rcx]
	cmp	ecx,7
	jb	.host
	cmp	dword [rsi],'http'
	jne	.host
	lea	rdx,[rsi+4]
	cmp	byte [rdx],'s'
	jne	@f
	inc	rdx
@@:
	lea	r8,[rdx+3]
	cmp	r8,rax
	ja	.host
	cmp	word [rdx],':/'
	jne	.host
	cmp	byte [rdx+2],'/'
	jne	.host
	mov	rsi,r8				; past the scheme
.host:
	mov	rdx,rsi
@@:
	cmp	rdx,rax
	jae	@f
	cmp	byte [rdx],'/'
	je	@f
	inc	rdx
	jmp	@b
@@:
	mov	r8,rdx
	sub	rdx,rsi
	mov	r9,rax
	sub	r9,r8
	jnz	@f
	lea	r8,[.slash]
	mov	r9d,1
@@:
	ret
.slash	db '/'

; edi = kind, rsi/ecx = what it names: a rule. eax = 0, or -1 when it is not one
pr_ask:
	cmp	edi,PK_TAG
	je	.tag
	push	rdi
	call	pr_split_url
	pop	rdi
	test	edx,edx
	jz	.bad
	mov	rcx,r8
	mov	r8d,r9d
	call	pr_add
	jc	.bad
	xor	eax,eax
	ret
.tag:
	test	ecx,ecx
	jz	.bad
	cmp	ecx,255
	ja	.bad
	mov	r8d,ecx
	mov	rcx,rsi
	xor	edx,edx
	call	pr_add
	jc	.bad
	xor	eax,eax
	ret
.bad:
	mov	eax,-1
	ret

; rsi/ecx = a word: edi = its kind (url, prefix, tag), 0 none
pr_kind:
	xor	edi,edi
	cmp	ecx,3
	jne	@f
	cmp	word [rsi],'ur'
	jne	.tag
	cmp	byte [rsi+2],'l'
	jne	.tag
	mov	edi,PK_URL
	ret
.tag:
	cmp	word [rsi],'ta'
	jne	.none
	cmp	byte [rsi+2],'g'
	jne	.none
	mov	edi,PK_TAG
	ret
@@:
	cmp	ecx,6
	jne	.none
	cmp	dword [rsi],'pref'
	jne	.none
	cmp	word [rsi+4],'ix'
	jne	.none
	mov	edi,PK_PREFIX
.none:
	ret

; admin: r13 = the rest of a `purge` line, rdi = output: `url|prefix|tag VALUE`
api_purge:
	push	r14
	push	r15
	push	rdi
	call	api_word
	mov	r14,rsi
	mov	r15d,ecx
	call	api_word
	pop	rdi
	test	ecx,ecx
	jz	.usage
	push	rdi
	push	rsi
	push	rcx
	mov	rsi,r14
	mov	ecx,r15d
	call	pr_kind
	pop	rcx
	pop	rsi
	test	edi,edi
	jz	.usage_pop
	call	pr_ask
	pop	rdi
	test	eax,eax
	jnz	.usage
	memit 'ok',10
	jmp	.out
.usage_pop:
	pop	rdi
.usage:
	memit 'err: purge url URL | prefix URL | tag TAG',10
.out:
	pop	r15
	pop	r14
	ret

; admin, HTTP: rsi = past "POST /purge" in the request line. rsi/edx = the answer.
admin_purge:
	cmp	byte [rsi],'?'
	jne	.bad
	inc	rsi
	mov	rdi,rsi				; kind=value
@@:
	cmp	byte [rsi],'='
	je	@f
	cmp	byte [rsi],' '
	jbe	.bad
	inc	rsi
	jmp	@b
@@:
	mov	rcx,rsi
	sub	rcx,rdi
	inc	rsi
	push	rsi
	mov	rsi,rdi
	call	pr_kind
	pop	rsi
	test	edi,edi
	jz	.bad
	; the value, percent-decoded, up to the space before HTTP/1.1
	lea	r8,[g_pr_dec]
	xor	ecx,ecx
.dec:
	movzx	eax,byte [rsi]
	cmp	al,' '
	jbe	.decoded
	cmp	al,'&'
	je	.decoded
	cmp	ecx,RL_TMAX
	jae	.bad
	inc	rsi
	cmp	al,'+'
	jne	@f
	mov	al,' '
	jmp	.put
@@:
	cmp	al,'%'
	jne	.put
	call	.hex
	jc	.bad
	shl	eax,4
	mov	edx,eax
	call	.hex
	jc	.bad
	or	eax,edx
.put:
	mov	[r8+rcx],al
	inc	ecx
	jmp	.dec
.decoded:
	mov	rsi,r8
	call	pr_ask
	test	eax,eax
	jnz	.bad
	cstring str_purged, 'HTTP/1.1 200 OK',13,10,'Content-Length: 7',13,10,'Connection: close',13,10,13,10,'purged',10
	lea	rsi,[str_purged]
	mov	edx,str_purged.len
	ret
.bad:
	cstring str_purge_bad, 'HTTP/1.1 400 Bad Request',13,10,'Content-Length: 36',13,10,'Connection: close',13,10,13,10,'POST /purge?url=|prefix=|tag=VALUE',13,10
	lea	rsi,[str_purge_bad]
	mov	edx,str_purge_bad.len
	ret
; a hex digit at rsi: eax, rsi past it
.hex:
	movzx	eax,byte [rsi]
	inc	rsi
	sub	eax,'0'
	cmp	eax,9
	jbe	.digit
	or	eax,0x20			; (lower case, of what was a letter)
	sub	eax,'a' - '0'
	cmp	eax,5
	ja	.nothex
	add	eax,10
.digit:
	clc
	ret
.nothex:
	stc
	ret

; ---------------------------------------------------------------- the CLI

; `okena purge url|prefix|tag VALUE [-c FILE]`: here, then on every instance the
; `fleet` names (its metrics listener, this one's token)
cli_purge:
	push	rbx
	push	r12
	push	r13
	; the line: purge KIND VALUE
	lea	rdi,[g_admin_req]
	cstring str_purge_w, 'purge'
	lea	rsi,[str_purge_w]
	mov	ecx,str_purge_w.len
	rep	movsb
	mov	r12d,2
	xor	ebx,ebx				; words taken
	mov	r13d,-1				; where -c is
.word:
	cmp	r12,[g_argc]
	jae	.line
	mov	rax,[g_argv]
	mov	rsi,[rax+r12*8]
	cmp	word [rsi],'-c'
	jne	@f
	cmp	byte [rsi+2],0
	jne	@f
	mov	r13d,r12d
	add	r12d,2
	jmp	.word
@@:
	cmp	ebx,2
	jae	.next
	mov	byte [rdi],' '
	inc	rdi
@@:
	lodsb
	test	al,al
	jz	.next
	cmp	al,10
	je	.next				; (one line, whatever it holds)
	stosb
	jmp	@b
.next:
	inc	ebx
	inc	r12d
	jmp	.word
.line:
	mov	byte [rdi],10
	inc	rdi
	lea	rax,[g_admin_req]
	sub	rdi,rax
	push	rdi
	mov	edi,r13d
	cmp	edi,-1
	jne	@f
	mov	rdi,[g_argc]
@@:
	call	cli_source_from_args
	call	api_cli_open
	pop	rdx
	lea	rsi,[g_admin_req]
	call	api_call
	mov	rsi,[g_admin_buf]
	mov	rdx,rax
	mov	edi,1
	call	write_all
	; the others, each its answer
	xor	ebx,ebx
.peer:
	cmp	ebx,[g_plan_fleet]
	jae	.done
	call	cli_purge_peer
	inc	ebx
	jmp	.peer
.done:
	pop	r13
	pop	r12
	pop	rbx
	xor	edi,edi
	jmp	exit_process

; ebx = a fleet instance, g_admin_req = "purge KIND VALUE\n": asked over HTTP; a line
; says how it went
cli_purge_peer:
	push	r12
	push	r13
	; POST /purge?KIND=VALUE, the value percent-encoded
	mov	rdi,[g_admin_buf]
	add	rdi,8192
	mov	r13,rdi
	memit 'POST /purge?'
	lea	rsi,[g_admin_req+6]		; past "purge "
@@:
	lodsb
	cmp	al,' '
	je	@f
	stosb
	jmp	@b
@@:
	mov	byte [rdi],'='
	inc	rdi
.enc:
	lodsb
	cmp	al,10
	je	.encoded
	cmp	al,'a'
	jb	@f
	cmp	al,'z'
	jbe	.plain
@@:
	cmp	al,'A'
	jb	@f
	cmp	al,'Z'
	jbe	.plain
@@:
	cmp	al,'0'
	jb	@f
	cmp	al,'9'
	jbe	.plain
@@:
	cmp	al,'/'
	je	.plain
	cmp	al,'.'
	je	.plain
	cmp	al,'-'
	je	.plain
	cmp	al,'_'
	je	.plain
	mov	byte [rdi],'%'
	movzx	edx,al
	shr	edx,4
	mov	cl,[.hexd+rdx]
	mov	[rdi+1],cl
	and	eax,15
	mov	cl,[.hexd+rax]
	mov	[rdi+2],cl
	add	rdi,3
	jmp	.enc
.plain:
	stosb
	jmp	.enc
.encoded:
	memit ' HTTP/1.1',13,10,'Host: '
	mov	rsi,[g_plan_fleet_tx+rbx*8]
	mov	ecx,[g_plan_fleet_tl+rbx*4]
	rep	movsb
	memit 13,10,'Content-Length: 0',13,10,'Connection: close',13,10
	cmp	dword [g_plan_mtlen],0
	je	@f
	memit 'Authorization: Bearer '
	lea	rsi,[g_plan_mtoken]
	mov	ecx,[g_plan_mtlen]
	rep	movsb
	memit 13,10
@@:
	memit 13,10
	mov	r12,rdi
	sub	r12,r13				; its length
	; one connection, the request, the status line
	imul	eax,ebx,32
	movzx	edi,word [g_plan_fleet_sa+rax]
	mov	esi,SOCK_STREAM or SOCK_CLOEXEC
	xor	edx,edx
	mov	eax,SYS_socket
	syscall
	test	eax,eax
	js	.failed
	mov	r8d,eax
	push	r8
	mov	edi,eax
	mov	esi,SOL_SOCKET
	mov	edx,SO_RCVTIMEO
	lea	r10,[ts_admin_io]
	mov	r8d,16
	mov	eax,SYS_setsockopt
	syscall
	mov	edi,[rsp]
	imul	eax,ebx,32
	lea	rsi,[g_plan_fleet_sa+rax]
	mov	edx,[g_plan_fleet_sl+rbx*4]
	mov	eax,SYS_connect
	syscall
	test	eax,eax
	js	.closed
	mov	edi,[rsp]
	mov	rsi,r13
	mov	rdx,r12
	call	write_all
	mov	edi,[rsp]
	lea	rsi,[g_pm]
	mov	edx,64
	xor	eax,eax
	syscall
	cmp	eax,12
	jl	.closed
	pop	rdi
	push	qword [g_pm+9]			; "200" or another
	mov	eax,SYS_close
	syscall
	call	.who
	out_lit ': '
	pop	rax
	cmp	eax,'200 '
	jne	.said
	out_lit 'ok'
	jmp	.eol
.said:
	push	rax
	out_lit 'answered '
	mov	rsi,rsp
	mov	edx,3
	call	out_str
	pop	rax
	jmp	.eol
.closed:
	pop	rdi
	mov	eax,SYS_close
	syscall
.failed:
	call	.who
	out_lit ': no answer'
.eol:
	out_lit 10
	call	out_flush
	pop	r13
	pop	r12
	ret
.who:
	mov	edi,1
	call	out_select
	out_lit 'fleet '
	mov	rsi,[g_plan_fleet_tx+rbx*8]
	mov	edx,[g_plan_fleet_tl+rbx*4]
	jmp	out_str
.hexd	db '0123456789ABCDEF'

; `okena { fleet ADDR... }`, rbx = the node
compile_fleet:
	push	r12
	push	r13
	mov	r12,[rbx+N_ARGS]
	mov	r13d,[rbx+N_ARGC]
.arg:
	test	r13d,r13d
	jz	.done
	dec	r13d
	cmp	dword [r12+A_KIND],ARG_KV
	je	.skip
	mov	eax,[g_plan_fleet]
	cmp	eax,MAX_FLEET
	jae	.skip
	mov	rdi,[r12+A_VAL]
	mov	esi,[r12+A_VLEN]
	mov	[g_plan_fleet_tx+rax*8],rdi
	mov	[g_plan_fleet_tl+rax*4],esi
	lea	rdx,[g_cmp_addr]
	xor	ecx,ecx
	call	parse_address
	mov	eax,[g_plan_fleet]
	imul	edi,eax,32
	lea	rdi,[g_plan_fleet_sa+rdi]
	lea	rsi,[g_cmp_addr]
	call	sockaddr_build
	mov	ecx,[g_plan_fleet]
	mov	[g_plan_fleet_sl+rcx*4],eax
	inc	dword [g_plan_fleet]
.skip:
	add	r12,A_SIZE
	jmp	.arg
.done:
	pop	r13
	pop	r12
	ret
