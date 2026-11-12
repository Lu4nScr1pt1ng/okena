; `alerts { webhook URL; slack URL; telegram token=T chat=C; on KINDS; every
; 10s; name NAME }`: what goes wrong, and what comes back, told to people.
;
; Any process of okena that logs an event worth telling (a backend ejected or
; back, health checks failing or passing, a worker restarted, a reload
; refused, discovery that cannot be done) also puts its line in a ring of
; shared memory, with no lock: a slot is taken with one atomic add, written,
; and marked written last. The control process reads the ring every 250 ms
; and sends what came, gathered over `every` (10 s). Each target has its own
; place in the ring, shared: it is sent what came since its last message that
; went, so one target that fails does not hold back or repeat the others, and
; a control process that starts again (a reload) loses nothing and tells
; nothing twice. The same line from many
; workers (each ejects a backend on its own) is one line with how many times,
; at most 32 lines a message and the count of the rest. A send that fails
; keeps what it had for the next window, and is said once; an alert never
; makes another. A ring that a burst laps loses its oldest lines, counted.
;
; webhook: POST of JSON, {"source":"okena","name":...,"events":[{"kind":...,
; "text":...,"count":N}]}. slack: an incoming webhook, {"text":...}.
; telegram: the Bot API's sendMessage to `chat`. HTTPS verified against the
; system's roots, or `trust=FILE`'s first certificate; plain http for a
; webhook on a private network.

AL_BACKEND	:= 1
AL_WORKER	:= 2
AL_RELOAD	:= 4
AL_DISCOVERY	:= 8
AL_CERT		:= 16			; a certificate near its end (certexpiry.inc)
AL_ALL		:= 31

ALT_WEBHOOK	:= 0
ALT_SLACK	:= 1
ALT_TELEGRAM	:= 2

ALR_SLOTS	:= 256			; the ring
ALR_HEAD		:= 0			; q: slots taken
ALR_ACK		:= 8			; q a target: the slots sent to it; a new control process goes on from there
ALR_E		:= 128
ALE_SEQ		:= 0			; q: slot + 1 once written
ALE_KIND		:= 8			; d
ALE_LEN		:= 12			; d
ALE_TEXT		:= 16
ALE_SIZE		:= 256
ALE_TEXT_MAX	:= ALE_SIZE - ALE_TEXT
ALR_SIZE		:= ALR_E + ALR_SLOTS * ALE_SIZE

ALB_MAX		:= 32			; distinct lines a message
ALB_SIZE		:= 8 + ALE_TEXT_MAX	; count d, kind d, then the text (NUL ended)

; a target (plan)
ATG_KIND	:= 0			; d: AT_*
ATG_TLS		:= 4			; d
ATG_PORT	:= 8			; d
ATG_HLEN	:= 12			; d
ATG_HOST	:= 16			; q
ATG_PATH	:= 24			; q
ATG_PLEN	:= 32			; d
ATG_CLEN	:= 36			; d: telegram: the chat
ATG_CHAT	:= 40			; q
ATG_TOKEN	:= 48			; q: telegram: the bot's token
ATG_TLEN	:= 56			; d
ATG_HASTRUST	:= 60			; d
ATG_TRUST	:= 64			; the anchor's key, when trust= (PK_SIZE)
ATG_SIZE	:= (ATG_TRUST + PK_SIZE + 63) and not 63
AL_TARGETS	:= 8

bss
	align 8
	g_plan_al_n	dd ?		; targets, 0: no alerts
	g_plan_al_on	dd ?		; AL_* to tell
	g_plan_al_every	dd ?		; seconds
	g_plan_al_nlen	dd ?
	g_plan_al_name	dq ?		; how this okena names itself, 0: its host name
	g_plan_al:	rb ATG_SIZE * AL_TARGETS
	g_al_ring	dq ?		; shared, from the start: it outlives reloads
	; the control process
	g_al_lost	dd ?
	g_al_bn		dd ?		; lines gathered
	g_al_more	dd ?		; and past ALB_MAX
	g_al_next	dq ?		; second of the next send
	g_al_said	rd AL_TARGETS	; a failure already told
	g_al_host:	rb 72		; the host's name
	g_al_hlen	dd ?
	g_al_batch:	rb ALB_SIZE * ALB_MAX
	g_al_body:	rb 16384
	g_al_req:	rb 18432
	g_al_sa:	rb 32
end bss

; supervisor, before any fork: the ring (kept for every generation)
alerts_ring_init:
	cmp	qword [g_al_ring],0
	jne	.have
	xor	edi,edi
	mov	esi,ALR_SIZE
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.have
	mov	[g_al_ring],rax
.have:
	ret

; edi = AL_*: the line being logged is an event: into the ring, then out as
; log_end does. Any process, no lock.
log_end_alert:
	mov	rax,[g_al_ring]
	test	rax,rax
	jz	log_end
	push	rbx
	push	rdi
	mov	ebx,1
	lock xadd [rax+ALR_HEAD],rbx		; this line's slot
	mov	ecx,ebx
	and	ecx,ALR_SLOTS - 1
	imul	rcx,rcx,ALE_SIZE
	lea	rdi,[rax+ALR_E+rcx]
	mov	qword [rdi+ALE_SEQ],0		; (being written)
	pop	rax
	mov	[rdi+ALE_KIND],eax
	mov	ecx,[g_out_len]
	mov	edx,[g_log_body]
	sub	ecx,edx
	jae	@f
	xor	ecx,ecx
@@:
	cmp	ecx,ALE_TEXT_MAX - 1
	jbe	@f
	mov	ecx,ALE_TEXT_MAX - 1
@@:
	mov	[rdi+ALE_LEN],ecx
	lea	rsi,[g_out_buf+rdx]
	push	rdi
	add	rdi,ALE_TEXT
	rep	movsb
	pop	rdi
	lea	rax,[rbx+1]
	mov	[rdi+ALE_SEQ],rax		; written (x86 keeps stores in order)
	pop	rbx
	jmp	log_end

; ------------------------------------------------------------ the control process

; the control process, starting: its host's name
alerts_init:
	cmp	dword [g_plan_al_n],0
	je	.none
	mov	rax,[g_al_ring]
	test	rax,rax
	jz	.none
	mov	rsi,[g_plan_al_name]
	mov	ecx,[g_plan_al_nlen]
	test	rsi,rsi
	jnz	.named
	cstring str_al_hostname, '/proc/sys/kernel/hostname',0
	mov	edi,AT_FDCWD
	lea	rsi,[str_al_hostname]
	mov	edx,O_RDONLY or O_CLOEXEC
	xor	r10d,r10d
	mov	eax,SYS_openat
	syscall
	test	eax,eax
	js	.unnamed
	push	rax
	mov	edi,eax
	lea	rsi,[g_al_host]
	mov	edx,64
	xor	eax,eax
	syscall
	mov	ecx,eax
	pop	rdi
	push	rcx
	mov	eax,SYS_close
	syscall
	pop	rcx
	test	ecx,ecx
	jle	.unnamed
.trim:
	cmp	byte [g_al_host+rcx-1],' '
	ja	.hosted
	dec	ecx
	jnz	.trim
.unnamed:
	cstring str_al_okena, 'okena'
	lea	rsi,[str_al_okena]
	mov	ecx,str_al_okena.len
.named:
	cmp	ecx,64
	jbe	@f
	mov	ecx,64
@@:
	lea	rdi,[g_al_host]
	push	rcx
	rep	movsb
	pop	rcx
.hosted:
	mov	[g_al_hlen],ecx
	call	monotonic_seconds
	add	eax,[g_plan_al_every]
	mov	[g_al_next],rax
.none:
	ret

; the control process, each turn: on time, each target what is new for it
alerts_tick:
	cmp	dword [g_plan_al_n],0
	je	.none
	cmp	qword [g_al_ring],0
	je	.none
	call	monotonic_seconds
	cmp	rax,[g_al_next]
	jb	.none
	add	eax,[g_plan_al_every]
	mov	[g_al_next],rax
	jmp	alerts_send
.none:
	ret

; rsi = a ring entry: into the batch, with those it repeats
alerts_gather:
	push	rbx
	mov	r8d,[rsi+ALE_LEN]
	lea	r9,[rsi+ALE_TEXT]
	; a worker's line says which worker: what follows is the line
	cmp	r8d,8
	jb	.find
	cmp	dword [r9],'work'
	jne	.find
	cmp	word [r9+4],'er'
	jne	.find
	xor	ecx,ecx
@@:
	cmp	ecx,r8d
	jae	.find
	cmp	word [r9+rcx],': '
	je	@f
	inc	ecx
	jmp	@b
@@:
	add	ecx,2
	add	r9,rcx
	sub	r8d,ecx
.find:
	xor	ebx,ebx
.line:
	cmp	ebx,[g_al_bn]
	jae	.new
	imul	rdi,rbx,ALB_SIZE
	lea	rdi,[g_al_batch+rdi]
	cmp	byte [rdi+8+r8],0		; the same length...
	jne	.other
	push	rsi
	push	rdi
	lea	rdi,[rdi+8]
	mov	rsi,r9
	mov	ecx,r8d
	repe	cmpsb
	pop	rdi
	pop	rsi
	jne	.other
	inc	dword [rdi]			; ...and the same words
	jmp	.out
.other:
	inc	ebx
	jmp	.line
.new:
	cmp	ebx,ALB_MAX
	jae	.more
	inc	dword [g_al_bn]
	imul	rdi,rbx,ALB_SIZE
	lea	rdi,[g_al_batch+rdi]
	mov	dword [rdi],1
	mov	eax,[rsi+ALE_KIND]
	mov	[rdi+4],eax
	add	rdi,8
	mov	rsi,r9
	mov	ecx,r8d
	rep	movsb
	mov	byte [rdi],0
	jmp	.out
.more:
	inc	dword [g_al_more]
.out:
	pop	rbx
	ret

; r12d = target: the batch of what is new for it, r13 = where that ends (the
; first slot not written yet). ZF when there is nothing.
alerts_collect:
	push	rbx
	push	r14
	mov	dword [g_al_bn],0
	mov	dword [g_al_more],0
	mov	dword [g_al_lost],0
	mov	r14,[g_al_ring]
	mov	rbx,[r14+ALR_ACK+r12*8]
	; lapped: what was written over is lost, counted
	mov	rax,[r14+ALR_HEAD]
	mov	rcx,rax
	sub	rcx,rbx
	cmp	rcx,ALR_SLOTS
	jbe	.walk
	sub	rcx,ALR_SLOTS
	mov	[g_al_lost],ecx
	add	rbx,rcx
.walk:
	mov	ecx,ebx
	and	ecx,ALR_SLOTS - 1
	imul	rcx,rcx,ALE_SIZE
	lea	rsi,[r14+ALR_E+rcx]
	lea	rdx,[rbx+1]
	cmp	[rsi+ALE_SEQ],rdx
	jne	.end				; not written (yet): the end of what is new
	inc	rbx
	mov	eax,[rsi+ALE_KIND]
	test	eax,[g_plan_al_on]
	jz	.walk
	call	alerts_gather
	jmp	.walk
.end:
	mov	r13,rbx
	mov	eax,[g_al_bn]
	or	eax,[g_al_lost]
	pop	r14
	pop	rbx
	ret

; each target what is new for it; one that fails keeps its place
alerts_send:
	push	rbx
	push	r12
	push	r13
	xor	r12d,r12d
.target:
	cmp	r12d,[g_plan_al_n]
	jae	.sent
	call	alerts_collect			; r13 = its end
	jnz	@f
	mov	rax,[g_al_ring]			; nothing to tell: it is up to date
	mov	[rax+ALR_ACK+r12*8],r13
	jmp	.next
@@:
	imul	rdi,r12,ATG_SIZE
	lea	rdi,[g_plan_al+rdi]
	push	r13
	call	alerts_post
	pop	r13
	jnc	.ok
	cmp	dword [g_al_said+r12*4],0
	jne	.next
	mov	dword [g_al_said+r12*4],1
	push	rax
	call	log_begin			; (a plain line: an alert never makes another)
	out_lit 'alerts: cannot reach '
	imul	rax,r12,ATG_SIZE
	mov	rsi,[g_plan_al+rax+ATG_HOST]
	mov	edx,[g_plan_al+rax+ATG_HLEN]
	call	out_str
	pop	rax
	cmp	eax,4
	jne	@f
	out_lit ' (it is not who it should be)'
	jmp	.said
@@:
	cmp	eax,5
	jne	.said
	out_lit ' (it did not take the message)'
.said:
	out_lit '; trying again in the next window'
	call	log_end
	jmp	.next
.ok:
	mov	dword [g_al_said+r12*4],0
	mov	rax,[g_al_ring]
	mov	[rax+ALR_ACK+r12*8],r13
.next:
	inc	r12d
	jmp	.target
.sent:
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = target: the batch, as it wants it. CF when not taken (eax 1 no
; answer, 4 not who it should be, 5 not 2xx).
alerts_post:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	call	alerts_body			; g_al_body, r13d = its length
	; the address: as written, or resolved
	call	alerts_address			; g_al_sa, edx = its length; CF none
	mov	eax,1
	jc	.out
	lea	rsi,[g_al_sa]
	call	cx_connect
	mov	eax,1
	jc	.out
	cmp	dword [r12+ATG_TLS],0
	je	.plain
	xor	edi,edi
	cmp	dword [r12+ATG_HASTRUST],0
	je	@f
	lea	rdi,[r12+ATG_TRUST]
@@:
	mov	rsi,[r12+ATG_HOST]
	mov	edx,[r12+ATG_HLEN]
	call	cx_handshake
	jc	.close
.plain:
	call	alerts_request			; g_al_req, edx = its length
	lea	rsi,[g_al_req]
	call	cx_send
	mov	eax,1
	jc	.close
	call	cx_answer
	mov	eax,1
	jc	.close
	call	cx_close
	call	cx_status
	mov	ecx,eax
	mov	eax,5
	jc	.bad
	sub	ecx,200
	cmp	ecx,100
	jae	.bad
	clc
	jmp	.out
.close:
	push	rax
	call	cx_close
	pop	rax
.bad:
	stc
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

; r12 = target: g_al_sa (with its port), edx = its length. CF when its host
; has no address.
alerts_address:
	mov	rsi,[r12+ATG_HOST]
	mov	ecx,[r12+ATG_HLEN]
	mov	edx,[r12+ATG_PORT]
	lea	rdi,[g_al_sa]
	jmp	cx_address

; rdi = output, rsi/ecx = text: as a JSON string's inside. rdi after it.
; Keeps rbx, r12-r15.
alerts_json:
	test	ecx,ecx
	jz	.out
	movzx	eax,byte [rsi]
	inc	rsi
	dec	ecx
	cmp	al,'"'
	je	.esc
	cmp	al,'\'
	je	.esc
	cmp	al,' '
	jb	.ctl
	cmp	al,127
	je	.ctl
	stosb
	jmp	alerts_json
.esc:
	mov	byte [rdi],'\'
	mov	[rdi+1],al
	add	rdi,2
	jmp	alerts_json
.ctl:
	mov	dword [rdi],'\u00'
	mov	edx,eax
	shr	edx,4
	mov	dl,[.hex+rdx]
	mov	[rdi+4],dl
	and	eax,15
	mov	al,[.hex+rax]
	mov	[rdi+5],al
	add	rdi,6
	jmp	alerts_json
.out:
	ret
.hex	db '0123456789abcdef'

; rdi = output, rsi = a NUL-ended text: copied. rdi after it.
alerts_lit:
	lodsb
	test	al,al
	jz	.out
	stosb
	jmp	alerts_lit
.out:
	ret

macro al_lit text&
	local s
	cstring s, text,0
	lea	rsi,[s]
	call	alerts_lit
end macro

; r12 = target: the message in g_al_body, r13d = its length
alerts_body:
	push	rbx
	lea	rdi,[g_al_body]
	cmp	dword [r12+ATG_KIND],ALT_WEBHOOK
	jne	.text
	; {"source":"okena","name":"...","events":[{"kind":"...","text":"...","count":N},...]}
	al_lit '{"source":"okena","name":"'
	lea	rsi,[g_al_host]
	mov	ecx,[g_al_hlen]
	call	alerts_json
	al_lit '","events":['
	xor	ebx,ebx
.event:
	cmp	ebx,[g_al_bn]
	jae	.events
	test	ebx,ebx
	jz	@f
	mov	byte [rdi],','
	inc	rdi
@@:
	al_lit '{"kind":"'
	imul	rax,rbx,ALB_SIZE
	mov	eax,[g_al_batch+rax+4]
	call	.kind_name
	al_lit '","text":"'
	imul	rax,rbx,ALB_SIZE
	lea	rsi,[g_al_batch+rax+8]
	call	.len
	call	alerts_json
	al_lit '","count":'
	imul	rax,rbx,ALB_SIZE
	mov	eax,[g_al_batch+rax]
	call	dk_decimal
	mov	byte [rdi],'}'
	inc	rdi
	inc	ebx
	jmp	.event
.events:
	al_lit '],"more":'
	mov	eax,[g_al_more]
	add	eax,[g_al_lost]
	call	dk_decimal
	mov	byte [rdi],'}'
	inc	rdi
	jmp	.done
	; slack: {"text":"..."}; telegram: {"chat_id":"...","text":"..."}
.text:
	cmp	dword [r12+ATG_KIND],ALT_TELEGRAM
	jne	.slack
	al_lit '{"chat_id":"'
	mov	rsi,[r12+ATG_CHAT]
	mov	ecx,[r12+ATG_CLEN]
	call	alerts_json
	al_lit '",'
	jmp	.say
.slack:
	mov	byte [rdi],'{'
	inc	rdi
.say:
	al_lit '"text":"okena '
	lea	rsi,[g_al_host]
	mov	ecx,[g_al_hlen]
	call	alerts_json
	al_lit ':'
	xor	ebx,ebx
.line:
	cmp	ebx,[g_al_bn]
	jae	.lines
	al_lit '\n- '
	imul	rax,rbx,ALB_SIZE
	lea	rsi,[g_al_batch+rax+8]
	call	.len
	call	alerts_json
	imul	rax,rbx,ALB_SIZE
	mov	eax,[g_al_batch+rax]
	cmp	eax,1
	je	@f
	push	rax
	al_lit ' (x'
	pop	rax
	call	dk_decimal
	mov	byte [rdi],')'
	inc	rdi
@@:
	inc	ebx
	jmp	.line
.lines:
	mov	eax,[g_al_more]
	add	eax,[g_al_lost]
	test	eax,eax
	jz	@f
	push	rax
	al_lit '\n- and '
	pop	rax
	call	dk_decimal
	al_lit ' more'
@@:
	al_lit '"}'
.done:
	lea	rax,[g_al_body]
	sub	rdi,rax
	mov	r13d,edi
	pop	rbx
	ret
; rsi = a NUL-ended text: ecx = its length
.len:
	xor	ecx,ecx
@@:
	cmp	byte [rsi+rcx],0
	je	@f
	inc	ecx
	jmp	@b
@@:
	ret
.kind_name:
	cstring str_alk_backend, 'backend',0
	cstring str_alk_worker, 'worker',0
	cstring str_alk_reload, 'reload',0
	cstring str_alk_discovery, 'discovery',0
	cstring str_alk_certificate, 'certificate',0
	lea	rsi,[str_alk_backend]
	cmp	eax,AL_BACKEND
	je	@f
	lea	rsi,[str_alk_worker]
	cmp	eax,AL_WORKER
	je	@f
	lea	rsi,[str_alk_reload]
	cmp	eax,AL_RELOAD
	je	@f
	lea	rsi,[str_alk_discovery]
	cmp	eax,AL_DISCOVERY
	je	@f
	lea	rsi,[str_alk_certificate]
@@:
	jmp	alerts_lit

; r12 = target, r13d = the body's length: the POST in g_al_req, edx = length
alerts_request:
	lea	rdi,[g_al_req]
	al_lit 'POST '
	cmp	dword [r12+ATG_KIND],ALT_TELEGRAM
	jne	.path
	al_lit '/bot'
	mov	rsi,[r12+ATG_TOKEN]
	mov	ecx,[r12+ATG_TLEN]
	rep	movsb
	al_lit '/sendMessage'
	jmp	.pathed
.path:
	mov	rsi,[r12+ATG_PATH]
	mov	ecx,[r12+ATG_PLEN]
	rep	movsb
.pathed:
	al_lit ' HTTP/1.0',13,10,'Host: '
	mov	rsi,[r12+ATG_HOST]
	mov	ecx,[r12+ATG_HLEN]
	rep	movsb
	al_lit 13,10,'User-Agent: okena',13,10,'Content-Type: application/json',13,10,'Content-Length: '
	mov	eax,r13d
	call	dk_decimal
	mov	dword [rdi],0x0A0D0A0D
	add	rdi,4
	lea	rsi,[g_al_body]
	mov	ecx,r13d
	rep	movsb
	lea	rax,[g_al_req]
	sub	rdi,rax
	mov	edx,edi
	ret

; supervisor, with a plan (the start, each reload): what the control process
; will need and may not map once confined (it has no mmap): the answer buffer,
; and the system's roots when a target wants them
alerts_prepare:
	cmp	dword [g_plan_al_n],0
	je	.none
	call	cx_buffer
	xor	ecx,ecx
.target:
	cmp	ecx,[g_plan_al_n]
	jae	.none
	imul	rax,rcx,ATG_SIZE
	cmp	dword [g_plan_al+rax+ATG_TLS],0
	je	.next
	cmp	dword [g_plan_al+rax+ATG_HASTRUST],0
	jne	.next
	push	rcx
	call	cx_store_load
	pop	rcx
.next:
	inc	ecx
	jmp	.target
.none:
	ret

; ------------------------------------------------------------ the block

; rdi = the `alerts` node
compile_alerts:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	mov	dword [g_plan_al_on],AL_ALL
	mov	dword [g_plan_al_every],10
	mov	rbx,[r12+N_CHILD]
.next:
	test	rbx,rbx
	jz	.done
	mov	rax,[rbx+N_DEF]
	lea	rcx,[dir_table + D_SIZE*DIR_WEBHOOK]
	cmp	rax,rcx
	je	.webhook
	lea	rcx,[dir_table + D_SIZE*DIR_SLACK]
	cmp	rax,rcx
	je	.slack
	lea	rcx,[dir_table + D_SIZE*DIR_TELEGRAM]
	cmp	rax,rcx
	je	.telegram
	lea	rcx,[dir_table + D_SIZE*DIR_ALERT_ON]
	cmp	rax,rcx
	je	.on
	lea	rcx,[dir_table + D_SIZE*DIR_EVERY]
	cmp	rax,rcx
	je	.every
	lea	rcx,[dir_table + D_SIZE*DIR_ALERT_NAME]
	cmp	rax,rcx
	je	.name
.advance:
	mov	rbx,[rbx+N_NEXT]
	jmp	.next
.webhook:
	mov	r13d,ALT_WEBHOOK
	jmp	.url
.slack:
	mov	r13d,ALT_SLACK
.url:
	call	.target
	mov	rax,[rbx+N_ARGS]
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	call	al_url
	call	.trust
	jmp	.advance
.telegram:
	mov	r13d,ALT_TELEGRAM
	call	.target
	cstring str_tg_api, 'https://api.telegram.org'
	lea	rsi,[str_tg_api]
	mov	ecx,str_tg_api.len
	mov	rdi,rbx
	push	rsi
	push	rcx
	lea	rsi,[str_key_api]
	call	node_option
	pop	rcx
	pop	rsi
	test	rax,rax
	jz	@f
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
@@:
	call	al_url
	mov	rdi,rbx
	lea	rsi,[str_key_token]
	call	node_option
	test	rax,rax
	jz	plan_bad_alerts
	mov	rcx,[rax+A_VAL]
	mov	edx,[rax+A_VLEN]
	call	al_token
	mov	[r8+ATG_TOKEN],rcx
	mov	[r8+ATG_TLEN],edx
	mov	rdi,rbx
	lea	rsi,[str_key_chat]
	call	node_option
	test	rax,rax
	jz	plan_bad_alerts
	mov	rcx,[rax+A_VAL]
	mov	edx,[rax+A_VLEN]
	call	al_token
	mov	[r8+ATG_CHAT],rcx
	mov	[r8+ATG_CLEN],edx
	call	.trust
	jmp	.advance
.on:
	mov	dword [g_plan_al_on],0
	mov	rax,[rbx+N_ARGS]
	mov	ecx,[rbx+N_ARGC]
.on_arg:
	test	ecx,ecx
	jz	.advance
	push	rcx
	push	rax
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	lea	rdx,[e_alert_on]
	call	list_index
	mov	ecx,eax
	mov	eax,1
	shl	eax,cl
	or	[g_plan_al_on],eax
	pop	rax
	pop	rcx
	add	rax,A_SIZE
	dec	ecx
	jmp	.on_arg
.every:
	mov	rdi,rbx
	call	node_duration
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	test	eax,eax
	jnz	@f
	inc	eax				; (a second at least)
@@:
	mov	[g_plan_al_every],eax
	jmp	.advance
.name:
	mov	rax,[rbx+N_ARGS]
	mov	rcx,[rax+A_VAL]
	mov	[g_plan_al_name],rcx
	mov	ecx,[rax+A_VLEN]
	mov	[g_plan_al_nlen],ecx
	jmp	.advance
; a new target of kind r13d: r8 = it
.target:
	mov	eax,[g_plan_al_n]
	cmp	eax,AL_TARGETS
	jae	plan_bad_alerts
	inc	dword [g_plan_al_n]
	imul	r8,rax,ATG_SIZE
	lea	r8,[g_plan_al+r8]
	mov	[r8+ATG_KIND],r13d
	mov	dword [r8+ATG_HASTRUST],0
	ret
; trust=FILE: its first certificate's key is the anchor
.trust:
	push	r8
	mov	rdi,rbx
	lea	rsi,[str_key_trust]
	call	node_option
	pop	r8
	test	rax,rax
	jz	.no_trust
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,4096
	jae	plan_bad_alerts
	lea	rdi,[g_trust_path]
	push	rcx
	rep	movsb
	pop	rcx
	mov	byte [g_trust_path+rcx],0
	push	r8
	lea	rdi,[g_trust_path]
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	plan_bad_trust
	mov	rsi,rax
	mov	edx,edx
	lea	rdi,[g_trust_der]
	call	pem_first_cert
	test	eax,eax
	jz	plan_bad_trust
	mov	r8,[rsp]
	lea	rsi,[g_trust_der]
	mov	edx,eax
	lea	rdi,[r8+ATG_TRUST]
	call	cert_pubkey
	test	eax,eax
	jz	plan_bad_trust
	pop	r8
	mov	dword [r8+ATG_HASTRUST],1
.no_trust:
	ret
.done:
	cmp	dword [g_plan_al_n],0
	je	plan_bad_alerts
	pop	r13
	pop	r12
	pop	rbx
	ret

; rcx/edx = a token or a chat: 1 to 200 bytes that need no escaping in a
; path or a JSON string (letters, digits, - _ : .)
al_token:
	test	edx,edx
	jz	plan_bad_alerts
	cmp	edx,200
	ja	plan_bad_alerts
	xor	eax,eax
.char:
	movzx	r9d,byte [rcx+rax]
	cmp	r9d,'-'
	je	.ok
	cmp	r9d,'_'
	je	.ok
	cmp	r9d,':'
	je	.ok
	cmp	r9d,'.'
	je	.ok
	mov	r10d,r9d
	sub	r10d,'0'
	cmp	r10d,9
	jbe	.ok
	or	r9d,0x20
	sub	r9d,'a'
	cmp	r9d,25
	ja	plan_bad_alerts
.ok:
	inc	eax
	cmp	eax,edx
	jb	.char
	ret

; rsi/ecx = http://HOST[:PORT][/PATH] or https://...: into the target r8
al_url:
	mov	dword [r8+ATG_TLS],1
	mov	dword [r8+ATG_PORT],443
	cmp	ecx,9
	jb	plan_bad_alerts
	cmp	dword [rsi],'http'
	jne	plan_bad_alerts
	cmp	dword [rsi+4],'s://'
	jne	.plain
	add	rsi,8
	sub	ecx,8
	jmp	.host
.plain:
	cmp	word [rsi+4],':/'
	jne	plan_bad_alerts
	cmp	byte [rsi+6],'/'
	jne	plan_bad_alerts
	mov	dword [r8+ATG_TLS],0
	mov	dword [r8+ATG_PORT],80
	add	rsi,7
	sub	ecx,7
.host:
	; up to the path; a port after the last ':' that is not in brackets
	mov	[r8+ATG_HOST],rsi
	xor	edx,edx
	xor	r9d,r9d				; in brackets
.hchar:
	cmp	edx,ecx
	jae	.hend
	movzx	eax,byte [rsi+rdx]
	cmp	al,'/'
	je	.hend
	cmp	al,'['
	jne	@f
	mov	r9d,1
@@:
	cmp	al,']'
	jne	@f
	xor	r9d,r9d
@@:
	cmp	al,':'
	jne	@f
	test	r9d,r9d
	jz	.port
@@:
	cmp	al,' '
	jbe	plan_bad_alerts
	cmp	al,'"'
	je	plan_bad_alerts
	inc	edx
	jmp	.hchar
.port:
	mov	[r8+ATG_HLEN],edx
	inc	edx
	xor	eax,eax
	xor	r9d,r9d
.digit:
	cmp	edx,ecx
	jae	.ported
	movzx	r10d,byte [rsi+rdx]
	cmp	r10d,'/'
	je	.ported
	sub	r10d,'0'
	cmp	r10d,9
	ja	plan_bad_alerts
	imul	eax,eax,10
	add	eax,r10d
	inc	edx
	inc	r9d
	cmp	r9d,5
	ja	plan_bad_alerts
	jmp	.digit
.ported:
	test	eax,eax
	jz	plan_bad_alerts
	cmp	eax,65535
	ja	plan_bad_alerts
	mov	[r8+ATG_PORT],eax
	jmp	.path
.hend:
	mov	[r8+ATG_HLEN],edx
.path:
	cmp	dword [r8+ATG_HLEN],0
	je	plan_bad_alerts
	; the path, "/" when there is none
	lea	rax,[rsi+rdx]
	sub	ecx,edx
	jnz	@f
	cstring str_al_slash, '/'
	lea	rax,[str_al_slash]
	mov	ecx,1
@@:
	mov	[r8+ATG_PATH],rax
	mov	[r8+ATG_PLEN],ecx
	xor	edx,edx
@@:
	cmp	edx,ecx
	jae	@f
	cmp	byte [rax+rdx],' '
	jbe	plan_bad_alerts
	inc	edx
	jmp	@b
@@:
	ret

plan_bad_alerts:
	call	log_begin
	out_lit 'alerts takes webhook URL, slack URL, telegram token= chat= [api=URL], each with trust=FILE if need be (at most 8), and may take on backend|worker|reload|discovery, every TIME and name NAME'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

plan_bad_trust:
	call	log_begin
	out_lit 'alerts: a trust= file that cannot be read as a certificate'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

cstring str_key_chat, 'chat',0
