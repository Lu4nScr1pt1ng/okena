; Compile the checked configuration tree into the plan: flat, fixed-size
; tables the workers read and never write. Addresses become sockaddr
; structures here, so the data path never parses text.

MAX_LISTENERS	:= 64
MAX_POOLS	:= 512
MAX_SERVERS	:= 1024

; Listener
LS_SA		:= 0		; sockaddr_in6 / sockaddr_in (28 bytes)
LS_SALEN	:= 28		; d
LS_FAMILY	:= 32		; d: AF_INET, AF_INET6, or 0 for ":port" (dual stack)
LS_POOL		:= 36		; d
LS_IDLE		:= 40		; d: idle timeout in seconds
LS_MAXCONN	:= 44		; d: per worker
LS_TEXT		:= 48		; q: address as written
LS_TLEN		:= 56		; d
LS_PORT		:= 60		; d
LS_FLAGS	:= 64		; d: LSF_*
LS_PER_SOURCE	:= 68		; d: connections per client address, 0 = no limit
LS_KIND		:= 72		; d: LK_*
LS_RFIRST	:= 76		; d: first route (http)
LS_RCOUNT	:= 80		; d
LS_HFIRST	:= 84		; d: first host block (http)
LS_HCOUNT	:= 88		; d
LS_T_HEADER	:= 92		; d: http: seconds for a whole request head
LS_T_RESPONSE	:= 96		; d: http: seconds a backend has for its response head
LS_ALOG		:= 100		; d: http: access log destination + 1, 0 = none
LS_TFIRST	:= 104		; d: http: first trusted_proxies range
LS_TCOUNT	:= 108		; d
LS_T_BODY	:= 112		; d: http: seconds between bytes of a request body
LS_PT		:= 116		; d: tls passthrough: names group | (default pool + 1) << 16, 0 = none
LS_TLS		:= 120		; d: its tls entry + 1 (certificate, key), 0 = none
LS_CCA		:= 124		; d: `client_ca`: its place in g_cca (LSF_CCA)
LS_PA4		:= 128		; http3: `preferred_address`'s IPv4 one (sockaddr_in), family 0 none
LS_PA6		:= 144		; and IPv6 one (sockaddr_in6)
LS_RESP		:= 172		; d: udp: answers a flow gets, 0 none, -1 no limit
LS_TRACE	:= 176		; d: http: `tracing` destination + 1, 0 = none
LS_TSAMPLE	:= 180		; d: and the share of new traces kept, in millionths
LS_EFIRST	:= 184		; d: http: its error pages (g_eps), first
LS_ECOUNT	:= 188		; d: and how many
LS_MAINT	:= 192		; d: http: its `maintenance` (g_maints) + 1, 0 none
LS_SIZE		:= 200
assert LS_PA6 + 28 <= LS_RESP

; Host block name (http): routes for requests to that host
HO_NAME		:= 0		; q: the name; for "*.example.com", ".example.com"
HO_NLEN		:= 8		; d
HO_WILD		:= 12		; d: 1 for a wildcard (matched as a suffix)
HO_RFIRST	:= 16		; d
HO_RCOUNT	:= 20		; d
HO_SIZE		:= 24

; Host names are found through one open-addressing table for the whole
; plan: key = (the listener's first host entry, wildcard or not, the
; name in lower case), value = host entry + 1 (0 = empty slot). Load is
; at most 1/4, so a probe sequence is short.
HHASH_SIZE	:= MAX_HOSTS * 4
MAX_HOSTS	:= 1024
MAX_TRUST	:= 1024		; trusted_proxies ranges, all listeners

LK_TCP		:= 0
LK_HTTP		:= 1
LK_UDP		:= 2

; Route (http)
RT_PATH		:= 0		; q: path; for a prefix route, without the "*"
RT_PLEN		:= 8		; d
RT_PREFIX	:= 12		; d: 1 for "/x/*" routes
RT_METHODS	:= 16		; d: RM_* bits, 0 = any
RT_POOL		:= 20		; d: -1 for a route that redirects
RT_ACT		:= 24		; d: its action + 1 (redirect, header changes), 0 = none
RA_FILES	:= 120		; d: its files entry + 1
RA_ZMIN		:= 124		; d: `compress`: from this size, 0 = no
RT_MATCH	:= 28		; d: its first `match` block + 1, 0 = none
RT_SIZE		:= 32

; Route actions: a redirect, and the header changes of requests and of
; responses (ranges of g_hdrops).
RA_CODE		:= 0		; d: redirect status, 0 = forward
RA_TLEN		:= 4		; d
RA_TGT		:= 8		; q: redirect target
RA_QFIRST	:= 16		; d: request header changes
RA_QCOUNT	:= 20
RA_PFIRST	:= 24		; d: response header changes
RA_PCOUNT	:= 28
RA_WFROM	:= 32		; q: rewrite: the prefix it replaces (FROM without {*}), 0 = none
RA_WFLEN	:= 40		; d
RA_WTLEN	:= 44		; d
RA_WTO		:= 48		; q: what replaces it
RA_FCODE	:= 56		; d: fault: the status it answers, 0 = none
RA_FPCT		:= 60		; d: of this many requests in 100
RA_FDELAY	:= 64		; q: fault: µs they wait first, 0 = none
RA_LFIRST	:= 72		; d: its rate limits, in g_limits
RA_LCOUNT	:= 76		; d
RA_CORS		:= 80		; d: its cors entry + 1
RA_SPLIT	:= 84		; d: its split entry + 1
RA_MPCT		:= 88		; d: mirror: this share, 0 = none
RA_MPOOL	:= 92		; d: to this pool
RA_HAFTER	:= 96		; q: hedge: µs before the second try, 0 = none
RA_HPCT		:= 104		; d: or this percentile of the pool's answers
RA_PRIO		:= 108		; d: RP_*
RA_AUTH		:= 112		; d: its auth entry + 1
RA_CACHE	:= 116		; d: its cache entry + 1
RA_EH		:= 128		; q: `early_hints`: the 103, ready
RA_EHLEN	:= 136		; d
RA_HOLD		:= 144		; q: `hold`: µs a request waits for a backend
RA_RMAP		:= 152		; d: its `redirects` + 1
RA_IDEM		:= 156		; d: its `idempotency` + 1
RA_ACL		:= 160		; d: its `allow`, `deny` + 1
RA_EFIRST	:= 164		; d: its error pages (g_eps), first
RA_ECOUNT	:= 168		; d: and how many
RA_WRX		:= 176		; d: rewrite ~REGEX: its regex + 1 (RA_WFROM then the source)
RA_ZENC		:= 180		; d: `compress`: 1 gzip, 2 br, 4 br before gzip
RA_SIZE		:= 184
MAX_ACTS	:= MAX_ROUTES
HD_KIND		:= 0		; d: HOP_SET, HOP_ADD, HOP_DROP
HD_PREFIX	:= 4		; d: 1 when the name ends with * (drop)
HD_NLEN		:= 8		; d: name length (without the *)
HD_VLEN		:= 12		; d
HD_NAME		:= 16		; q
HD_VAL		:= 24		; q
HD_VARS		:= 32		; d: ${...} in the value (how many), 0 = literal
HD_SIZE		:= 40
MAX_HDROPS	:= 4096
HOP_SET		:= 1
HOP_ADD		:= 2
HOP_DROP	:= 3

; Routes are found through one open-addressing table: key = (the route
; set's first entry, exact or prefix, the path), value = route entry + 1.
; Routes that share a path with different methods share a key: a lookup
; walks every entry of its probe sequence.
RHASH_SIZE	:= MAX_ROUTES * 4
MAX_ROUTES	:= 1024

LSF_PEER	:= 1		; sessions need the client's address
LSF_PP_V1	:= 2		; send a PROXY protocol v1 header upstream
LSF_PP_V2	:= 4		; send a PROXY protocol v2 header upstream
LSF_WILDCARD	:= 8		; bound to every address: the local one comes from getsockname
LSF_KTLS	:= 16		; http: the kernel seals and opens the records (`ktls on`)
LSF_H2		:= 32		; http: HTTP/2 (`http2 on`): ALPN h2, prior knowledge without TLS
LSF_H3		:= 64		; http: HTTP/3 (`http3 on`): QUIC on the same port, UDP
LSF_H3RETRY	:= 128		; http: `http3 retry`: every new QUIC connection proves its address first
LSF_H3V2	:= 256		; http: `http3 v2`: a v1 client that offers v2 is moved to it
LSF_CCA		:= 1024		; http: `client_ca`: ask for a certificate
LSF_CCA_REQ	:= 2048		; and refuse the connection with none
LSF_0RTT	:= 512		; http: `early_data on`: QUIC 0-RTT for safe requests

; Pool
PL_FIRST	:= 0		; d: first server
PL_COUNT	:= 4		; d
PL_BALANCE	:= 8		; d: BAL_*
PL_PRIMARY	:= 12		; d: servers that are not backups
PL_TIMEOUT	:= 16		; 16 bytes: connect timeout as __kernel_timespec
PL_NAME		:= 32		; q
PL_NLEN		:= 40		; d
PL_HEALTH	:= 44		; d: 1 when active checks run
PL_H_EVERY	:= 48		; d: milliseconds
PL_H_TIMEOUT	:= 52		; d: milliseconds
PL_H_RISE	:= 56		; d
PL_H_FALL	:= 60		; d
PL_H_HTTP	:= 64		; d: 1 for an HTTP check, 2 for gRPC (0: TCP)
PL_H_PLEN	:= 68		; d
PL_H_PATH	:= 72		; q
PL_H_LO		:= 80		; d: statuses that pass
PL_H_HI		:= 84		; d
PL_H_HOST	:= 88		; q: Host of the check, 0 = the server as written
PL_H_HLEN	:= 96		; d
PL_H_HEAD	:= 100		; d: 1 for HEAD
PL_SLOW		:= 104		; d: slow start window in seconds, 0 = none
PL_TLS		:= 108		; d: 1 when this pool's upstreams speak TLS
PL_TLS_SNI	:= 112		; q: SNI / hostname to verify, 0 = the server as written
PL_TLS_SNILEN	:= 120		; d
PL_TLS_HASANCHOR := 124		; d: 1 when an anchor key was loaded
PL_TLS_ANCHOR	:= 128		; the trust anchor's public key, a PK blob (EC or RSA)
PL_H2		:= 672		; d: 1 when this pool's backends speak HTTP/2 (`protocol h2`)
PL_HKEY		:= 676		; d: maglev, ring-hash: HK_*
PL_HNLEN	:= 680		; d: the header's or cookie's name
PL_HNAME	:= 688		; q
PL_HTAB		:= 696		; q: a worker's table for it
PL_SNAME	:= 704		; q: `sticky`: the cookie's name, 0 none
PL_SNLEN	:= 712		; d
PL_STTL		:= 716		; d: seconds, 0 for the session
PL_SSAME	:= 720		; d: SS_*
PL_QTIMEOUT	:= 728		; q: µs a request may wait for a place, 0: the connect timeout
PL_HBOUND	:= 736		; d: maglev, ring-hash: a server's load at most this % of the mean, 0 none
PL_HASMAX	:= 740		; d: a server of it has a max
PL_TLS_CID	:= 744		; d: `tls { cert; key }`: what it shows the backends (g_tls + 1), 0 none
PL_FCGI		:= 748		; d: 1 when its backends speak FastCGI (`protocol fastcgi`: fastcgi.inc)
PL_SIZE		:= 768		; room for PL_TLS_ANCHOR + a PK blob (16 + 528), then PL_H2
assert PL_TLS_ANCHOR + PK_SIZE <= PL_H2

; Server
SV_SA		:= 0		; sockaddr (sockaddr_un is 110 bytes)
SV_SALEN	:= 112		; d
SV_FAMILY	:= 116		; d
SV_WEIGHT	:= 120		; d
SV_BACKUP	:= 124		; d
SV_TEXT		:= 128		; q
SV_TLEN		:= 136		; d
SV_ACTIVE	:= 140		; d: holds an address (names: once resolved)
SV_MAX		:= 148		; d: connections in use at most, 0 = no limit
SV_GROUP	:= 144		; d: name group + 1, or 0 for an address
SV_SIZE		:= 160

BAL_ROUND_ROBIN	:= 0
BAL_LEAST_CONN	:= 1
BAL_RANDOM	:= 2
BAL_LEAST_REQ	:= 3		; the default: power of two choices
BAL_PEAK_EWMA	:= 4		; power of two choices on latency x load
BAL_MAGLEV	:= 5		; from here on a key picks (src/l4/hash.inc)
BAL_RING	:= 6
BAL_SOURCE	:= 7		; (written so; kept as maglev on the client's address)
BAL_FIRST	:= 8		; the first with room (src/l4/maxconn.inc)

DEFAULT_CONNECTIONS	:= 65536		; per listener, whole instance
DEFAULT_IDLE_SECS	:= 3600
DEFAULT_UDP_IDLE_SECS	:= 30
DEFAULT_HTTP_IDLE_SECS	:= 60
DEFAULT_HEADER_SECS	:= 10		; slow clients (slowloris) get 408
DEFAULT_RESPONSE_SECS	:= 30		; slow backends get 504
DEFAULT_BODY_SECS	:= 30		; a request body that stops coming gets 408
DEFAULT_CONNECT_US	:= 2000000
DEFAULT_DRAIN_US	:= 8000000
DEFAULT_HS_BUDGET_US	:= 100		; handshake_budget: asymmetric crypto per loop iteration
DEFAULT_HS_WAIT_US	:= 1000000	; and how long a queued ClientHello may wait

bss
	align 8
	g_plan_listeners	dd ?
	g_plan_pools		dd ?
	g_plan_servers		dd ?
	g_plan_workers		dd ?		; 0 = auto
	g_plan_engine		dd ?		; 0 auto, 1 io_uring, 2 epoll
	g_plan_drain_delay	dq ?		; microseconds
	g_plan_drain_timeout	dq ?
	g_plan_watchdog		dq ?
	g_plan_busy_poll	dq ?		; microseconds, 0 = off
	g_plan_qcc		dd ?		; quic_cc: 0 cubic, 1 bbr
	g_plan_qlb_len		dd ?		; quic_server_id: its bytes (0: none)
	g_plan_qlb_sid		rb 4
	g_plan_qlb_keyed	dd ?		; its key= was given
	g_plan_qlb_rot		dd ?		; rotation=
	g_plan_qlb_key		rb 16
	g_plan_hs_budget	dq ?		; microseconds per loop iteration, 0 = off
	g_plan_hs_wait		dq ?		; microseconds a queued hello may wait
	g_plan_health		dd ?		; pools with active checks
	g_cmp_resp		dd ?
	g_cmp_hpeer		dd ?
	g_plan_metrics		dd ?		; 1 when an admin address is set
	g_plan_metrics_salen	dd ?
	g_plan_metrics_text	dq ?
	g_plan_metrics_tlen	dd ?
	g_plan_metrics_sa:	rb 28
	g_plan_mtlen		dd ?		; `metrics ... token=FILE`: its token, 0 none
	g_plan_mtoken:		rb 256
	g_listeners:	rb LS_SIZE * MAX_LISTENERS
	g_pools:	rb PL_SIZE * MAX_POOLS
	g_trust_path:	rb 4096			; a trust file's path, NUL-terminated
	g_trust_der:	rb 1 shl 14		; the first certificate's DER
	g_trust_pub:	rb 544			; a scratch anchor key blob (config check)
	g_servers:	rb SV_SIZE * MAX_SERVERS
	g_cmp_addr:	rb AD_SIZE
	g_cmp_flags	dd ?
	g_cmp_per_source dd ?
	g_cmp_t_header	dd ?
	g_cmp_pt	dd ?
	g_cmp_alog	dd ?
	g_cmp_trace	dd ?
	g_cmp_efirst	dd ?
	g_cmp_ecount	dd ?
	g_cmp_maint	dd ?
	g_cmp_tsample	dd ?
	g_cmp_pa4:	rb 16			; `preferred_address`, IPv4 and IPv6
	g_cmp_pa6:	rb 28
	g_cmp_pasa:	rb 28
	g_cmp_pan	dq ?
	g_cmp_pai	dd ?
	g_cmp_tlsi	dd ?
	g_cmp_tfirst	dd ?
	g_cmp_tcount	dd ?
	g_cmp_t_response dd ?
	g_cmp_t_body	dd ?
	g_cmp_rfirst	dd ?
	g_cmp_rcount	dd ?
	g_plan_routes	dd ?
	g_routes:	rb RT_SIZE * MAX_ROUTES
	g_plan_trust	dd ?
	g_trust:	rb TR_SIZE * MAX_TRUST
	g_hhash:	rq HHASH_SIZE
	g_rhash:	rq RHASH_SIZE
	g_plan_acts	dd ?
	g_acts:		rb RA_SIZE * MAX_ACTS
	g_limits:	rb LM_SIZE * MAX_LIMITS
	g_plan_limits	dd ?
	g_cors:		rb CO_SIZE * MAX_CORS
	g_plan_cors	dd ?
	g_splits:	rb SL_SIZE * MAX_SPLITS
	g_plan_splits	dd ?
	g_auths:	rb AU_SIZE * MAX_AUTHS
	g_plan_auths	dd ?
	g_plan_akeys	dd ?
	g_jwk:		rb JK_SIZE * MAX_JWK
	g_plan_jwk	dd ?
	g_claims:	rb CM_SIZE * MAX_CLAIMS
	g_plan_claims	dd ?
	g_auth_tab:	rb AT_SIZE * AT_N
	g_plan_hdrops	dd ?
	g_hdrops:	rb HD_SIZE * MAX_HDROPS
	g_cmp_act	dd ?
	g_plan_hosts	dd ?
	g_hosts:	rb HO_SIZE * MAX_HOSTS
	g_cmp_hfirst	dd ?
	g_cmp_hcount	dd ?
end bss

; Exits with EXIT_CONFIG when something valid in the language cannot be
; served by this build (host names, table limits).
plan_compile:
	push	rbx
	push	r12
	call	errpage_plan_init		; (g_eps[0]: maintenance's text)
	mov	qword [g_plan_drain_timeout],DEFAULT_DRAIN_US
	mov	qword [g_plan_watchdog],2000000
	mov	qword [g_plan_hs_budget],DEFAULT_HS_BUDGET_US
	mov	qword [g_plan_hs_wait],DEFAULT_HS_WAIT_US
	; pools first, so listeners can refer to them
	mov	rax,[g_cfg_root]
	mov	rbx,[rax+N_CHILD]
.pools:
	test	rbx,rbx
	jz	.pools_done
	mov	rax,[rbx+N_DEF]
	lea	rcx,[dir_table + D_SIZE*DIR_ALERTS]
	cmp	rax,rcx
	jne	.not_alerts
	mov	rdi,rbx
	call	compile_alerts
	jmp	@f
.not_alerts:
	lea	rcx,[dir_table + D_SIZE*DIR_VRRP]
	cmp	rax,rcx
	jne	.not_vrrp
	call	compile_vrrp			; (rbx = the node)
	jmp	@f
.not_vrrp:
	lea	rcx,[dir_table + D_SIZE*DIR_POOL]
	cmp	rax,rcx
	jne	@f
	mov	rdi,rbx
	call	compile_pool
@@:
	lea	rcx,[dir_table + D_SIZE*DIR_OKENA]
	cmp	rax,rcx
	jne	@f
	mov	rdi,rbx
	call	compile_settings
@@:
	mov	rbx,[rbx+N_NEXT]
	jmp	.pools
.pools_done:
	mov	rax,[g_cfg_root]
	mov	rbx,[rax+N_CHILD]
.listeners:
	test	rbx,rbx
	jz	.done
	mov	rax,[rbx+N_DEF]
	lea	rcx,[dir_table + D_SIZE*DIR_TCP]
	cmp	rax,rcx
	je	.listener
	lea	rcx,[dir_table + D_SIZE*DIR_UDP]
	cmp	rax,rcx
	je	.listener
	lea	rcx,[dir_table + D_SIZE*DIR_HTTP]
	cmp	rax,rcx
	jne	@f
.listener:
	mov	rdi,rbx
	call	compile_listener
@@:
	mov	rbx,[rbx+N_NEXT]
	jmp	.listeners
.done:
	pop	r12
	pop	rbx
	ret

; Value helpers: rdi = node; first positional value parsed.
node_duration:
	mov	rax,[rdi+N_ARGS]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	jmp	parse_duration

node_decimal:
	mov	rax,[rdi+N_ARGS]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	jmp	parse_decimal

; rdi = node, rsi = NUL-terminated key. rax = the arg holding it (key=value
; on the line or "key value" in the block), or 0.
node_option:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	mov	r13,rsi
	mov	rbx,[r12+N_ARGS]
	mov	ecx,[r12+N_ARGC]
.args:
	test	ecx,ecx
	jz	.block
	cmp	dword [rbx+A_KIND],ARG_KV
	jne	.next_arg
	push	rcx
	mov	rdi,[rbx+A_KEY]
	mov	esi,[rbx+A_KLEN]
	mov	rdx,r13
	call	mem_eq_cstr
	pop	rcx
	test	eax,eax
	jnz	.found
.next_arg:
	add	rbx,A_SIZE
	dec	ecx
	jmp	.args
.block:
	mov	rbx,[r12+N_CHILD]
.child:
	test	rbx,rbx
	jz	.none
	mov	rdi,[rbx+N_NAME]
	mov	esi,[rbx+N_NLEN]
	mov	rdx,r13
	call	mem_eq_cstr
	test	eax,eax
	jnz	.found_child
	mov	rbx,[rbx+N_NEXT]
	jmp	.child
.found_child:
	mov	rax,[rbx+N_ARGS]
	jmp	.out
.found:
	mov	rax,rbx
	jmp	.out
.none:
	xor	eax,eax
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

cstring str_key_delay, 'delay',0
cstring str_key_wait, 'wait',0
cstring str_key_key, 'key',0
cstring str_key_abort, 'abort',0
cstring str_key_keys, 'keys',0
cstring str_key_users, 'users',0
cstring str_key_realm, 'realm',0
cstring str_key_identity, 'identity',0
cstring str_key_forward, 'forward',0
cstring str_key_header, 'header',0
cstring str_word_on, 'on',0
cstring str_word_off, 'off',0
cstring str_x_user_id, 'x-user-id',0
cstring str_authorization, 'authorization',0
cstring str_realm_okena, 'okena',0
cstring str_key_after, 'after',0
cstring str_key_max, 'max',0
cstring str_key_origins, 'origins',0
cstring str_key_methods, 'methods',0
cstring str_key_headers, 'headers',0
cstring str_key_expose, 'expose',0
cstring str_key_max_age, 'max_age',0
cstring str_key_burst, 'burst',0
cstring str_key_instances, 'instances',0
cstring str_key_lkey, 'key',0
cstring str_key_delay, 'delay',0
cstring str_key_percent, 'percent',0
cstring str_key_rotation, 'rotation',0
cstring str_key_timeout, 'timeout',0
cstring str_key_weight, 'weight',0
cstring str_key_every, 'every',0
cstring str_key_rise, 'rise',0
cstring str_key_expect, 'expect',0
cstring str_key_host, 'host',0
cstring str_key_trust, 'trust',0
cstring str_key_sni, 'sni',0
cstring str_key_fall, 'fall',0

; rdi = `okena` node.
compile_settings:
	push	rbx
	push	r12
	mov	r12,rdi
	mov	rbx,[r12+N_CHILD]
.next:
	test	rbx,rbx
	jz	.done
	mov	rax,[rbx+N_DEF]
	lea	rcx,[dir_table + D_SIZE*DIR_WORKERS]
	cmp	rax,rcx
	je	.workers
	lea	rcx,[dir_table + D_SIZE*DIR_IO_ENGINE]
	cmp	rax,rcx
	je	.engine
	lea	rcx,[dir_table + D_SIZE*DIR_WATCHDOG]
	cmp	rax,rcx
	je	.watchdog
	lea	rcx,[dir_table + D_SIZE*DIR_CACHE_MEM]
	cmp	rax,rcx
	je	.cache_memory
	lea	rcx,[dir_table + D_SIZE*DIR_CACHE_DISK]
	cmp	rax,rcx
	je	.cache_disk
	lea	rcx,[dir_table + D_SIZE*DIR_FLEET]
	cmp	rax,rcx
	je	.fleet
	lea	rcx,[dir_table + D_SIZE*DIR_CDNLOOP]
	cmp	rax,rcx
	je	.cdnloop
	lea	rcx,[dir_table + D_SIZE*DIR_BIRD]
	cmp	rax,rcx
	je	.bird
	lea	rcx,[dir_table + D_SIZE*DIR_ACME]
	cmp	rax,rcx
	je	.acme
	lea	rcx,[dir_table + D_SIZE*DIR_LOCALCA]
	cmp	rax,rcx
	je	.local_ca
	lea	rcx,[dir_table + D_SIZE*DIR_GATEWAY]
	cmp	rax,rcx
	je	.gateway
	lea	rcx,[dir_table + D_SIZE*DIR_ECH]
	cmp	rax,rcx
	je	.ech
	lea	rcx,[dir_table + D_SIZE*DIR_GEOIP]
	cmp	rax,rcx
	je	.geoip
	lea	rcx,[dir_table + D_SIZE*DIR_UPGRADE]
	cmp	rax,rcx
	je	.upgrade
	lea	rcx,[dir_table + D_SIZE*DIR_ADMIN]
	cmp	rax,rcx
	je	.admin
	lea	rcx,[dir_table + D_SIZE*DIR_USER]
	cmp	rax,rcx
	je	.user
	lea	rcx,[dir_table + D_SIZE*DIR_DRAIN]
	cmp	rax,rcx
	je	.drain
	lea	rcx,[dir_table + D_SIZE*DIR_BUSY_POLL]
	cmp	rax,rcx
	je	.busy_poll
	lea	rcx,[dir_table + D_SIZE*DIR_METRICS]
	cmp	rax,rcx
	je	.metrics
	lea	rcx,[dir_table + D_SIZE*DIR_HS_BUDGET]
	cmp	rax,rcx
	je	.hs_budget
	lea	rcx,[dir_table + D_SIZE*DIR_QUIC_SID]
	cmp	rax,rcx
	je	.quic_sid
	lea	rcx,[dir_table + D_SIZE*DIR_QUIC_CC]
	cmp	rax,rcx
	je	.quic_cc
	lea	rcx,[dir_table + D_SIZE*DIR_TICKET_KEYS]
	cmp	rax,rcx
	jne	.advance
	mov	rdi,rbx
	call	compile_ticket_keys
	jmp	.advance
.quic_cc:
	; quic_cc cubic|bbr: for connections made from now on
	mov	rax,[rbx+N_ARGS]
	xor	ecx,ecx
	cmp	dword [rax+A_VLEN],3		; (bbr; the schema allows no other of 3)
	sete	cl
	mov	[g_plan_qcc],ecx
	jmp	.advance
.quic_sid:
	; quic_server_id HEX: this instance's server ID in its QUIC connection
	; IDs (QUIC-LB, plaintext): 1 or 2 bytes
	mov	rax,[rbx+N_ARGS]
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	test	ecx,1
	jnz	plan_bad_quic_sid
	shr	ecx,1
	jz	plan_bad_quic_sid
	cmp	ecx,2
	ja	plan_bad_quic_sid
	mov	[g_plan_qlb_len],ecx
	lea	rdi,[g_plan_qlb_sid]
	call	hex_bytes
	jc	plan_bad_quic_sid
	; key=HEX: encrypted IDs (16 bytes, never a key half read: it would
	; leave the IDs in the clear), rotation=N: their first three bits
	mov	rdi,rbx
	lea	rsi,[str_key_key]
	call	node_option
	test	rax,rax
	jz	.sid_rotation
	cmp	dword [rax+A_VLEN],32
	jne	plan_bad_quic_sid
	mov	rsi,[rax+A_VAL]
	mov	ecx,16
	lea	rdi,[g_plan_qlb_key]
	call	hex_bytes
	jc	plan_bad_quic_sid
	mov	dword [g_plan_qlb_keyed],1
.sid_rotation:
	mov	rdi,rbx
	lea	rsi,[str_key_rotation]
	call	node_option
	test	rax,rax
	jz	.advance
	cmp	dword [rax+A_VLEN],1
	jne	plan_bad_quic_sid
	mov	rcx,[rax+A_VAL]
	movzx	eax,byte [rcx]
	sub	eax,'0'
	cmp	eax,6				; (7: unroutable, RFC-to-be 3.1)
	ja	plan_bad_quic_sid
	mov	[g_plan_qlb_rot],eax
	jmp	.advance
.metrics:
	mov	rax,[rbx+N_ARGS]
	mov	rdi,[rax+A_VAL]
	mov	[g_plan_metrics_text],rdi
	mov	esi,[rax+A_VLEN]
	mov	[g_plan_metrics_tlen],esi
	lea	rdx,[g_cmp_addr]
	xor	ecx,ecx
	call	parse_address
	lea	rdi,[g_plan_metrics_sa]
	lea	rsi,[g_cmp_addr]
	call	sockaddr_build
	mov	[g_plan_metrics_salen],eax
	mov	dword [g_plan_metrics],1
	mov	rdi,rbx
	call	compile_metrics_token
	jmp	.advance
.busy_poll:
	mov	rdi,rbx
	call	node_duration
	mov	[g_plan_busy_poll],rax
	jmp	.advance
.hs_budget:
	mov	rdi,rbx
	call	node_duration
	mov	[g_plan_hs_budget],rax
	mov	rdi,rbx
	lea	rsi,[str_key_wait]
	call	node_option
	test	rax,rax
	jz	.advance
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_duration
	mov	[g_plan_hs_wait],rax
	jmp	.advance
.workers:
	mov	rdi,rbx
	call	node_decimal
	jc	.advance			; "auto"
	mov	[g_plan_workers],eax
	jmp	.advance
.engine:
	mov	rax,[rbx+N_ARGS]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	lea	rdx,[e_io_engine]
	call	list_index
	mov	[g_plan_engine],eax
	jmp	.advance
.geoip:
	mov	rdi,rbx
	call	compile_geoip
	jmp	.advance
.upgrade:
	mov	rax,[rbx+N_ARGS]
	mov	rcx,[rax+A_VAL]
	mov	[g_plan_up],rcx
	mov	ecx,[rax+A_VLEN]
	mov	[g_plan_uplen],ecx
	jmp	.advance
.user:
	mov	rdi,rbx
	call	compile_user
	jmp	.advance
.admin:
	mov	rax,[rbx+N_ARGS]
	mov	rcx,[rax+A_VAL]
	mov	edx,[rax+A_VLEN]
	cmp	edx,6
	jb	plan_bad_admin
	cmp	dword [rcx],'unix'
	jne	plan_bad_admin
	cmp	byte [rcx+4],':'
	jne	plan_bad_admin
	add	rcx,5
	sub	edx,5
	mov	[g_plan_api],rcx
	mov	[g_plan_apilen],edx
	jmp	.advance
.cache_disk:
	call	compile_cache_disk
	jmp	.advance
.fleet:
	call	compile_fleet
	jmp	.advance
.cdnloop:
	call	compile_cdnloop
	jmp	.advance
.bird:
	call	compile_bird
	jmp	.advance
.acme:
	call	compile_acme
	jmp	.advance
.local_ca:
	call	compile_local_ca		; (localca.inc)
	jmp	.advance
.gateway:
	call	compile_gateway			; (gateway.inc)
	jmp	.advance
.ech:
	call	compile_ech			; (ech.inc)
	jmp	.advance
.cache_memory:
	mov	rax,[rbx+N_ARGS]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_size
	mov	[g_plan_cmem],rax
	jmp	.advance
.watchdog:
	mov	rdi,rbx
	call	node_duration
	mov	[g_plan_watchdog],rax
	jmp	.advance
.drain:
	mov	rdi,rbx
	lea	rsi,[str_key_delay]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_duration
	mov	[g_plan_drain_delay],rax
@@:
	mov	rdi,rbx
	lea	rsi,[str_key_timeout]
	call	node_option
	test	rax,rax
	jz	.advance
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_duration
	mov	[g_plan_drain_timeout],rax
.advance:
	mov	rbx,[rbx+N_NEXT]
	jmp	.next
.done:
	pop	r12
	pop	rbx
	ret

; New pool. rdi/esi = name (or 0 for an inline pool). rax = pool entry,
; ecx = its index.
pool_new:
	mov	ecx,[g_plan_pools]
	cmp	ecx,MAX_POOLS
	jae	plan_too_many
	inc	dword [g_plan_pools]
	imul	rax,rcx,PL_SIZE
	lea	rax,[g_pools+rax]
	mov	[rax+PL_NAME],rdi
	mov	[rax+PL_NLEN],esi
	mov	edx,[g_plan_servers]
	mov	[rax+PL_FIRST],edx
	mov	qword [rax+PL_TIMEOUT],DEFAULT_CONNECT_US / 1000000
	mov	qword [rax+PL_TIMEOUT+8],(DEFAULT_CONNECT_US mod 1000000) * 1000
	mov	dword [rax+PL_BALANCE],BAL_LEAST_REQ
	ret

; Access log destinations. The table only grows while the supervisor
; lives: a destination keeps its number across reloads, so lines from
; workers still draining an older configuration reach the right file.
ALOG_MAX	:= 32
ALOG_PATH	:= 256

bss
	g_alog_dest	rb ALOG_MAX * ALOG_PATH	; NUL-terminated: stdout, stderr or a path
	g_alog_count	dd ?
	g_alog_tmp	rb ALOG_PATH
	g_alog_tmp2	rb ALOG_PATH
end bss

; rdi = an `access_log` node: rdi/esi = its destination as the logger reads
; it, "URL trust=PATH" when it has trust= (a TLS one's own anchor, checked to
; be a certificate now).
alog_dest_node:
	push	rbx
	mov	rbx,rdi
	lea	rsi,[str_key_trust]
	call	node_option
	mov	rdx,[rbx+N_ARGS]
	mov	rdi,[rdx+A_VAL]
	mov	esi,[rdx+A_VLEN]
	test	rax,rax
	jz	.out
	mov	rbx,rax
	; only where there is TLS
	push	rdi
	push	rsi
	sub	rsp,64
	mov	rsi,rdi
	mov	ecx,[rsp+64]
	mov	rdi,rsp
	call	alog_url
	mov	eax,[rsp+LN_KIND]
	lea	rsp,[rsp+64]
	jc	.no_tls
	cmp	eax,LKS_TLS
	je	@f
	cmp	eax,LKS_OTLPS
	jne	.no_tls
@@:
	; "URL trust=PATH"
	mov	esi,[rsp]
	mov	ecx,[rbx+A_VLEN]
	lea	eax,[rsi+rcx+7]
	cmp	eax,ALOG_PATH - 1
	jae	.long
	cmp	ecx,4096
	jae	.long
	mov	rsi,[rbx+A_VAL]
	lea	rdi,[g_trust_path]
	rep	movsb
	mov	byte [rdi],0
	sub	rsp,PK_SIZE + 8
	lea	rdi,[g_trust_path]
	mov	rsi,rsp
	call	ln_trust
	lea	rsp,[rsp+PK_SIZE + 8]
	jc	.bad_trust
	pop	rcx
	pop	rsi
	lea	rdi,[g_alog_tmp]
	rep	movsb
	cstring str_alog_trust, ' trust='
	lea	rsi,[str_alog_trust]
	mov	ecx,str_alog_trust.len
	rep	movsb
	mov	rsi,[rbx+A_VAL]
	mov	ecx,[rbx+A_VLEN]
	rep	movsb
	lea	rsi,[g_alog_tmp]
	sub	rdi,rsi
	mov	esi,edi
	lea	rdi,[g_alog_tmp]
.out:
	pop	rbx
	ret
.no_tls:
	call	log_begin
	out_lit 'access_log: trust= is for syslog+tls:// and otlp+https:// only'
	jmp	.fail
.long:
	call	log_begin
	out_lit 'access_log: its URL and trust= path are too long together (255 bytes)'
	jmp	.fail
.bad_trust:
	call	log_begin
	out_lit 'access_log: a trust= file that cannot be read as a certificate'
.fail:
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; rdi = the `metrics` node: its token=FILE read (the file's first line, 16 to
; 255 bytes of it), or none
compile_metrics_token:
	mov	dword [g_plan_mtlen],0
	cstring str_key_token, 'token',0
	lea	rsi,[str_key_token]
	call	node_option
	test	rax,rax
	jz	.none
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,4096
	jae	.bad
	lea	rdi,[g_trust_path]
	rep	movsb
	mov	byte [rdi],0
	lea	rdi,[g_trust_path]
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	.bad
	; up to the line's end, without trailing spaces
	xor	ecx,ecx
@@:
	cmp	rcx,rdx
	jae	@f
	cmp	byte [rax+rcx],10
	je	@f
	cmp	byte [rax+rcx],13
	je	@f
	inc	ecx
	jmp	@b
@@:
	test	ecx,ecx
	jz	.bad
	cmp	byte [rax+rcx-1],' '
	ja	@f
	dec	ecx
	jmp	@b
@@:
	cmp	ecx,16
	jb	.short
	cmp	ecx,255
	ja	.bad
	; printable, no space: it travels in a header
	xor	edx,edx
@@:
	cmp	byte [rax+rdx],' '
	jbe	.bad
	cmp	byte [rax+rdx],0x7F
	jae	.bad
	inc	edx
	cmp	edx,ecx
	jb	@b
	mov	[g_plan_mtlen],ecx
	mov	rsi,rax
	lea	rdi,[g_plan_mtoken]
	rep	movsb
.none:
	ret
.short:
	call	log_begin
	out_lit 'metrics: a token= shorter than 16 bytes guards nothing'
	jmp	.fail
.bad:
	call	log_begin
	out_lit 'metrics: token= names a file whose first line is the token (16 to 255 printable bytes)'
.fail:
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; rdi = a `tracing` node: eax = its destination + 1 (the logger's, as
; "traces URL[ trust=PATH]"), edx = the share of new traces kept, millionths.
compile_tracing:
	push	rbx
	mov	rbx,rdi
	mov	rdx,[rbx+N_ARGS]
	mov	rsi,[rdx+A_VAL]
	mov	ecx,[rdx+A_VLEN]
	cmp	ecx,ALOG_PATH - 1
	jae	.bad
	sub	rsp,64
	mov	rdi,rsp
	call	alog_url
	mov	eax,[rsp+LN_KIND]
	lea	rsp,[rsp+64]
	jc	.bad
	cmp	eax,LKS_OTLP
	jb	.bad				; spans go to OTLP only
	cmp	eax,LKS_OTLPS
	ja	.bad
	mov	rdi,rbx
	cstring str_key_sample, 'sample',0
	lea	rsi,[str_key_sample]
	call	node_option
	mov	rdx,rax
	mov	eax,1000000			; all, unless said
	test	rdx,rdx
	jz	@f
	mov	rdi,[rdx+A_VAL]
	mov	esi,[rdx+A_VLEN]
	call	parse_percent			; (hundredths of a percent)
	imul	eax,eax,100
@@:
	push	rax
	mov	rdi,rbx
	call	alog_dest_node
	lea	eax,[rsi+7]
	cmp	eax,ALOG_PATH - 1
	jae	.long
	mov	rcx,rsi
	mov	rsi,rdi
	lea	rdi,[g_alog_tmp2]
	mov	dword [rdi],'trac'
	mov	dword [rdi+3],'ces '
	add	rdi,7
	push	rcx
	rep	movsb
	pop	rsi
	add	esi,7
	lea	rdi,[g_alog_tmp2]
	call	alog_dest_id
	pop	rdx
	pop	rbx
	ret
.long:
	call	log_begin
	out_lit 'tracing: its URL and trust= path are too long together (248 bytes)'
	jmp	.fail
.bad:
	call	log_begin
	out_lit 'tracing takes otlp://HOST[:PORT][/PATH] or otlp+https://..., with sample=PERCENT and trust=FILE'
.fail:
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; rdi/esi = `access_log` argument. eax = destination + 1, or 0 for off.
alog_dest_id:
	cmp	esi,3
	jne	@f
	cmp	word [rdi],'of'
	jne	@f
	cmp	byte [rdi+2],'f'
	jne	@f
	xor	eax,eax
	ret
@@:
	push	rbx
	xor	ebx,ebx
.find:
	cmp	ebx,[g_alog_count]
	jae	.add
	imul	r8,rbx,ALOG_PATH
	lea	r8,[g_alog_dest+r8]
	xor	ecx,ecx
.cmp:
	cmp	ecx,esi
	je	.end
	mov	al,[rdi+rcx]
	cmp	al,[r8+rcx]
	jne	.other
	inc	ecx
	jmp	.cmp
.end:
	cmp	byte [r8+rcx],0
	je	.found
.other:
	inc	ebx
	jmp	.find
.add:
	cmp	ebx,ALOG_MAX
	jae	.too_many
	imul	r8,rbx,ALOG_PATH
	lea	r8,[g_alog_dest+r8]
	xor	ecx,ecx
@@:
	mov	al,[rdi+rcx]
	mov	[r8+rcx],al
	inc	ecx
	cmp	ecx,esi
	jb	@b
	mov	byte [r8+rcx],0
	inc	dword [g_alog_count]
.found:
	lea	eax,[rbx+1]
	pop	rbx
	ret
.too_many:
	call	log_begin
	out_lit 'more than 32 different access log destinations since okena started'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; rdi = route node. eax = its action + 1, or 0 when it only forwards.
compile_route_action:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	; anything to do?
	mov	rbx,[r12+N_CHILD]
@@:
	test	rbx,rbx
	jz	.listener_compress
	mov	rax,[rbx+N_DEF]
	lea	rcx,[dir_table + D_SIZE*DIR_REDIRECT]
	cmp	rax,rcx
	je	@f
	lea	rcx,[dir_table + D_SIZE*DIR_RESPOND]
	cmp	rax,rcx
	je	@f
	lea	rcx,[dir_table + D_SIZE*DIR_RHEADER]
	cmp	rax,rcx
	je	@f
	lea	rcx,[dir_table + D_SIZE*DIR_RRESPONSE]
	cmp	rax,rcx
	je	@f
	lea	rcx,[dir_table + D_SIZE*DIR_REWRITE]
	cmp	rax,rcx
	je	@f
	lea	rcx,[dir_table + D_SIZE*DIR_FAULT]
	cmp	rax,rcx
	je	@f
	lea	rcx,[dir_table + D_SIZE*DIR_RLIMIT]
	cmp	rax,rcx
	je	@f
	lea	rcx,[dir_table + D_SIZE*DIR_CORS]
	cmp	rax,rcx
	je	@f
	lea	rcx,[dir_table + D_SIZE*DIR_SPLIT]
	cmp	rax,rcx
	je	@f
	lea	rcx,[dir_table + D_SIZE*DIR_MIRROR]
	cmp	rax,rcx
	je	@f
	lea	rcx,[dir_table + D_SIZE*DIR_HEDGE]
	cmp	rax,rcx
	je	@f
	lea	rcx,[dir_table + D_SIZE*DIR_PRIORITY]
	cmp	rax,rcx
	je	@f
	lea	rcx,[dir_table + D_SIZE*DIR_CACHE]
	cmp	rax,rcx
	je	@f
	lea	rcx,[dir_table + D_SIZE*DIR_FILES]
	cmp	rax,rcx
	je	@f
	lea	rcx,[dir_table + D_SIZE*DIR_PHP]
	cmp	rax,rcx
	je	@f
	lea	rcx,[dir_table + D_SIZE*DIR_AUTH]
	cmp	rax,rcx
	je	@f
	lea	rcx,[dir_table + D_SIZE*DIR_COMPRESS]
	cmp	rax,rcx
	je	@f
	lea	rcx,[dir_table + D_SIZE*DIR_HEADERS]
	cmp	rax,rcx
	je	@f
	lea	rcx,[dir_table + D_SIZE*DIR_EARLY_HINTS]
	cmp	rax,rcx
	je	@f
	lea	rcx,[dir_table + D_SIZE*DIR_HOLD]
	cmp	rax,rcx
	je	@f
	lea	rcx,[dir_table + D_SIZE*DIR_ALLOW]
	cmp	rax,rcx
	je	@f
	lea	rcx,[dir_table + D_SIZE*DIR_DENY]
	cmp	rax,rcx
	je	@f
	lea	rcx,[dir_table + D_SIZE*DIR_IDEMPOTENCY]
	cmp	rax,rcx
	je	@f
	lea	rcx,[dir_table + D_SIZE*DIR_REDIRECTS]
	cmp	rax,rcx
	je	@f
	lea	rcx,[dir_table + D_SIZE*DIR_ERRORS]
	cmp	rax,rcx
	je	@f
	mov	rbx,[rbx+N_NEXT]
	jmp	@b
.listener_compress:
	mov	rbx,[r12+N_PARENT]		; the listener's, or its host block's
.up:
	test	rbx,rbx
	jz	.none
	mov	rdi,rbx
	mov	ecx,DIR_COMPRESS
	call	find_child
	test	rax,rax
	jnz	@f
	mov	rdi,rbx
	mov	ecx,DIR_HEADERS
	call	find_child
	test	rax,rax
	jnz	@f
	mov	rbx,[rbx+N_PARENT]
	jmp	.up
@@:
	mov	ecx,[g_plan_acts]
	cmp	ecx,MAX_ACTS
	jae	plan_too_many
	inc	dword [g_plan_acts]
	push	rcx
	imul	r13,rcx,RA_SIZE
	lea	r13,[g_acts+r13]
	mov	rdi,r12
	mov	ecx,DIR_RESPOND
	call	find_child
	test	rax,rax
	jz	@f
	mov	rbx,[rax+N_ARGS]		; respond: a code, no target
	mov	rdi,[rbx+A_VAL]
	mov	esi,[rbx+A_VLEN]
	call	parse_decimal
	mov	[r13+RA_CODE],eax
	mov	qword [r13+RA_TGT],0
	mov	dword [r13+RA_TLEN],0
	jmp	.ops
@@:
	mov	rdi,r12
	mov	ecx,DIR_REDIRECT
	call	find_child
	test	rax,rax
	jz	.ops
	mov	rbx,[rax+N_ARGS]
	mov	rdi,[rbx+A_VAL]
	mov	esi,[rbx+A_VLEN]
	call	parse_decimal
	mov	[r13+RA_CODE],eax
	mov	rax,[rbx+A_SIZE+A_VAL]
	mov	[r13+RA_TGT],rax
	mov	eax,[rbx+A_SIZE+A_VLEN]
	mov	[r13+RA_TLEN],eax
.ops:
	mov	eax,[g_plan_limits]
	mov	[r13+RA_LFIRST],eax
	mov	rbx,[r12+N_CHILD]
.rate:
	test	rbx,rbx
	jz	.rates
	lea	rcx,[dir_table + D_SIZE*DIR_RLIMIT]
	cmp	[rbx+N_DEF],rcx
	jne	.rate_next
	mov	rdi,rbx
	call	compile_limit
	inc	dword [r13+RA_LCOUNT]
.rate_next:
	mov	rbx,[rbx+N_NEXT]
	jmp	.rate
.rates:
	mov	rdi,r12
	mov	rdi,r12				; its error pages
	call	compile_errors
	mov	[r13+RA_EFIRST],eax
	mov	[r13+RA_ECOUNT],edx
	mov	rdi,r12
	mov	ecx,DIR_CORS
	call	find_child
	test	rax,rax
	jz	.no_cors
	mov	rdi,rax
	call	compile_cors
	mov	[r13+RA_CORS],eax
.no_cors:
	mov	rdi,r12
	mov	ecx,DIR_SPLIT
	call	find_child
	test	rax,rax
	jz	.no_split
	mov	rdi,rax
	call	compile_split
	mov	[r13+RA_SPLIT],eax
.no_split:
	mov	rdi,r12
	mov	ecx,DIR_MIRROR
	call	find_child
	test	rax,rax
	jz	.no_mirror
	mov	rbx,[rax+N_ARGS]
	mov	ecx,[rax+N_ARGC]
	mov	dword [r13+RA_MPCT],100
	cmp	ecx,3
	jb	.mirror_pool
	mov	rsi,[rbx+2*A_SIZE+A_VAL]	; N%
	mov	ecx,[rbx+2*A_SIZE+A_VLEN]
	cmp	ecx,2
	jb	plan_bad_mirror
	dec	ecx
	cmp	byte [rsi+rcx],'%'
	jne	plan_bad_mirror
	xor	eax,eax
	xor	edx,edx
.mirror_digit:
	movzx	r8d,byte [rsi+rdx]
	sub	r8d,'0'
	cmp	r8d,9
	ja	plan_bad_mirror
	imul	eax,eax,10
	add	eax,r8d
	cmp	eax,100
	ja	plan_bad_mirror
	inc	edx
	cmp	edx,ecx
	jb	.mirror_digit
	test	eax,eax
	jz	plan_bad_mirror
	mov	[r13+RA_MPCT],eax
.mirror_pool:
	mov	rdi,[rbx+A_SIZE+A_VAL]
	mov	esi,[rbx+A_SIZE+A_VLEN]
	call	plan_pool_index
	cmp	eax,-1
	je	plan_bad_mirror
	mov	[r13+RA_MPOOL],eax
.no_mirror:
	mov	rdi,r12
	mov	ecx,DIR_HEDGE
	call	find_child
	test	rax,rax
	jz	.no_hedge
	mov	rbx,rax
	mov	rdi,rbx
	lea	rsi,[str_key_max]
	call	node_option
	test	rax,rax
	jz	.hedge_after
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_decimal
	cmp	eax,1
	jne	plan_bad_hedge
.hedge_after:
	mov	rdi,rbx
	lea	rsi,[str_key_after]
	call	node_option
	test	rax,rax
	jz	plan_bad_hedge
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	cmp	byte [rdi],'p'
	je	.hedge_pct
	call	parse_duration
	test	rax,rax
	jz	plan_bad_hedge
	mov	[r13+RA_HAFTER],rax
	jmp	.no_hedge
.hedge_pct:
	cmp	esi,3
	jne	plan_bad_hedge
	movzx	eax,byte [rdi+1]
	movzx	ecx,byte [rdi+2]
	sub	eax,'0'
	sub	ecx,'0'
	cmp	eax,9
	ja	plan_bad_hedge
	cmp	ecx,9
	ja	plan_bad_hedge
	imul	eax,eax,10
	add	eax,ecx
	jz	plan_bad_hedge
	mov	[r13+RA_HPCT],eax
.no_hedge:
	mov	rdi,r12
	mov	ecx,DIR_PRIORITY
	call	find_child
	test	rax,rax
	jz	.no_priority
	mov	rax,[rax+N_ARGS]
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	xor	edx,edx
	cmp	byte [rsi],'n'
	je	.priority
	mov	edx,RP_CRITICAL
	cmp	byte [rsi],'c'
	je	.priority
	mov	edx,RP_BULK
.priority:
	mov	[r13+RA_PRIO],edx
.no_priority:
	mov	rdi,r12
	mov	ecx,DIR_CACHE
	call	find_child
	test	rax,rax
	jz	.no_cache
	push	r12
	push	rbx
	mov	rbx,rax
	mov	r12,r13
	call	compile_cache
	pop	rbx
	pop	r12
.no_cache:
	mov	rdi,r12
	mov	ecx,DIR_SIGNED
	call	find_child
	test	rax,rax
	jz	.no_signed
	push	r12
	push	rbx
	mov	rbx,rax
	call	compile_signed
	pop	rbx
	pop	r12
.no_signed:
	mov	rdi,r12				; php ROOT: a files entry that picks PHP's
	mov	ecx,DIR_PHP			; scripts (fastcgi.inc)
	call	find_child
	test	rax,rax
	jz	.no_php
	push	r12
	push	rbx
	mov	rbx,rax
	mov	r12,r13
	call	compile_php
	pop	rbx
	pop	r12
.no_php:
	mov	rdi,r12
	mov	ecx,DIR_FILES
	call	find_child
	test	rax,rax
	jz	.no_files
	push	r12
	push	rbx
	mov	rbx,rax
	mov	r12,r13
	call	compile_files
	pop	rbx
	pop	r12
.no_files:
	call	compile_compress
	call	compile_hints
	call	compile_hold
	call	compile_acl
	call	compile_idem
	call	compile_rmap
	mov	rdi,r12
	mov	ecx,DIR_AUTH
	call	find_child
	test	rax,rax
	jz	.no_auth
	mov	rdi,rax
	call	compile_auth
	mov	[r13+RA_AUTH],eax
.no_auth:
	mov	rdi,r12
	mov	ecx,DIR_FAULT
	call	find_child
	test	rax,rax
	jz	.no_fault
	mov	rbx,rax
	mov	rdi,rbx				; fault abort=STATUS delay=T percent=N
	lea	rsi,[str_key_delay]
	call	node_option
	test	rax,rax
	jz	.fault_abort
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_duration
	test	rax,rax
	jz	plan_bad_fault
	mov	rcx,600000000			; (a request held 10 minutes is a mistake)
	cmp	rax,rcx
	ja	plan_bad_fault
	mov	[r13+RA_FDELAY],rax
.fault_abort:
	mov	rdi,rbx
	lea	rsi,[str_key_abort]
	call	node_option
	test	rax,rax
	jz	.fault_only_delay
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_decimal
	mov	[r13+RA_FCODE],eax
	sub	eax,400
	cmp	eax,199
	ja	plan_bad_fault
	jmp	.fault_share
.fault_only_delay:
	cmp	qword [r13+RA_FDELAY],0
	je	plan_bad_fault
.fault_share:
	mov	dword [r13+RA_FPCT],100
	mov	rdi,rbx
	lea	rsi,[str_key_percent]
	call	node_option
	test	rax,rax
	jz	.no_fault
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_decimal
	cmp	eax,100
	ja	plan_bad_fault
	mov	[r13+RA_FPCT],eax
.no_fault:
	mov	rdi,r12
	mov	ecx,DIR_REWRITE
	call	find_child
	test	rax,rax
	jz	@f
	mov	rbx,[rax+N_ARGS]
	mov	rax,[rbx+A_SIZE+A_VAL]
	mov	[r13+RA_WFROM],rax
	mov	eax,[rbx+A_SIZE+A_VLEN]
	mov	rcx,[rbx+A_SIZE+A_VAL]
	cmp	byte [rcx],'~'
	jne	.wfrom_path
	lea	rsi,[rcx+1]			; ~REGEX: its regex + 1, $N in TO
	lea	ecx,[rax-1]
	call	rx_compile_or_exit
	inc	eax
	mov	[r13+RA_WRX],eax
	xor	eax,eax
	jmp	.wfrom_len
.wfrom_path:
	sub	eax,3				; without {*}
.wfrom_len:
	mov	[r13+RA_WFLEN],eax
	mov	rax,[rbx+3*A_SIZE+A_VAL]
	mov	[r13+RA_WTO],rax
	mov	eax,[rbx+3*A_SIZE+A_VLEN]
	mov	[r13+RA_WTLEN],eax
@@:
	mov	eax,[g_plan_hdrops]
	mov	[r13+RA_QFIRST],eax
	mov	ecx,DIR_RHEADER
	xor	edx,edx
	call	.collect
	mov	eax,[g_plan_hdrops]
	sub	eax,[r13+RA_QFIRST]
	mov	[r13+RA_QCOUNT],eax
	mov	eax,[g_plan_hdrops]
	mov	[r13+RA_PFIRST],eax
	call	compile_preset
	mov	ecx,DIR_RRESPONSE
	mov	edx,1				; after "header"
	call	.collect
	mov	eax,[g_plan_hdrops]
	sub	eax,[r13+RA_PFIRST]
	mov	[r13+RA_PCOUNT],eax
	pop	rax
	inc	eax
	jmp	.out
.none:
	xor	eax,eax
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret
; ecx = directive, edx = arguments before the operation: one entry per
; such line of the route, in order.
.collect:
	push	r14
	push	r15
	imul	ecx,ecx,D_SIZE
	lea	r14,[dir_table+rcx]
	mov	r15d,edx
	mov	rbx,[r12+N_CHILD]
.line:
	test	rbx,rbx
	jz	.collected
	cmp	[rbx+N_DEF],r14
	jne	.next_line
	mov	ecx,[g_plan_hdrops]
	cmp	ecx,MAX_HDROPS
	jae	plan_too_many
	inc	dword [g_plan_hdrops]
	imul	r8,rcx,HD_SIZE
	lea	r8,[g_hdrops+r8]
	imul	r9,r15,A_SIZE
	add	r9,[rbx+N_ARGS]			; the operation
	mov	rax,[r9+A_VAL]
	mov	ecx,HOP_SET
	cmp	byte [rax],'s'
	je	@f
	mov	ecx,HOP_ADD
	cmp	byte [rax],'a'
	je	@f
	mov	ecx,HOP_DROP
@@:
	mov	[r8+HD_KIND],ecx
	mov	rax,[r9+A_SIZE+A_VAL]
	mov	[r8+HD_NAME],rax
	mov	eax,[r9+A_SIZE+A_VLEN]
	mov	dword [r8+HD_PREFIX],0
	mov	rdx,[r9+A_SIZE+A_VAL]
	cmp	byte [rdx+rax-1],'*'
	jne	@f
	dec	eax
	mov	dword [r8+HD_PREFIX],1
@@:
	mov	[r8+HD_NLEN],eax
	cmp	ecx,HOP_DROP
	je	.next_line
	mov	rax,[r9+2*A_SIZE+A_VAL]
	mov	[r8+HD_VAL],rax
	mov	eax,[r9+2*A_SIZE+A_VLEN]
	mov	[r8+HD_VLEN],eax
	; count the ${...} (checked already)
	mov	dword [r8+HD_VARS],0
	mov	rdx,rax
	mov	rax,[r8+HD_VAL]
	xor	ecx,ecx
@@:
	lea	r10d,[rcx+1]
	cmp	r10d,edx
	jae	@f
	cmp	word [rax+rcx],'${'
	jne	.no_var
	inc	dword [r8+HD_VARS]
.no_var:
	inc	ecx
	jmp	@b
@@:
.next_line:
	mov	rbx,[rbx+N_NEXT]
	jmp	.line
.collected:
	pop	r15
	pop	r14
	ret

; rcx = route entry, edx = its index: into g_rhash.
route_insert:
	push	rcx
	push	rdx
	mov	edi,[g_cmp_rfirst]
	call	rhash_seed
	mov	rsi,[rcx+RT_PATH]
	mov	edx,[rcx+RT_PLEN]
	call	rhash_bytes
	mov	rcx,[rsp+8]
	mov	ecx,[rcx+RT_PREFIX]
	call	rhash_final
	pop	rdx
	pop	rcx
	mov	r8d,eax
.probe:
	and	r8d,RHASH_SIZE - 1
	cmp	qword [g_rhash+r8*8],0
	je	.slot
	inc	r8d
	jmp	.probe
.slot:
	lea	r9d,[rdx+1]
	shl	r9,32
	or	r9,rax
	mov	[g_rhash+r8*8],r9
	ret

; Path hashing (FNV-1a), in three steps so a request path is hashed in one
; pass: the state after each '/' is the hash of that prefix.
; edi = route set's first entry. eax = the initial state.
rhash_seed:
	mov	eax,2166136261
	xor	eax,edi
	imul	eax,eax,16777619
	ret
; eax = state, rsi/edx = bytes. eax = state after them. Clobbers r8, r9.
rhash_bytes:
	xor	r8d,r8d
@@:
	cmp	r8d,edx
	jae	@f
	movzx	r9d,byte [rsi+r8]
	xor	eax,r9d
	imul	eax,eax,16777619
	inc	r8d
	jmp	@b
@@:
	ret
; eax = state, ecx = 1 for a prefix, 0 for an exact path. eax = the key.
rhash_final:
	xor	eax,ecx
	imul	eax,eax,16777619
	xor	eax,0x5BD1E995
	imul	eax,eax,16777619
	ret

; edi = seed (a listener's first host entry), rsi/edx = name, ecx = 1
; for a wildcard suffix. eax = FNV-1a hash of it all, A-Z folded to
; lower case. Clobbers r8-r10.
host_hash:
	mov	eax,2166136261
	xor	eax,edi
	imul	eax,eax,16777619
	xor	eax,ecx
	imul	eax,eax,16777619
	xor	r8d,r8d
.byte:
	cmp	r8d,edx
	jae	.done
	movzx	r9d,byte [rsi+r8]
	lea	r10d,[r9-'A']
	cmp	r10d,25
	ja	@f
	or	r9d,0x20
@@:
	xor	eax,r9d
	imul	eax,eax,16777619
	inc	r8d
	jmp	.byte
.done:
	ret

; rdi = timeout block, ecx = directive. eax = its duration in whole
; seconds (at least one), or CF when absent.
timeout_secs:
	call	find_child
	test	rax,rax
	jz	.absent
	mov	rdi,rax
	call	node_duration
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	test	eax,eax
	jnz	@f
	inc	eax
@@:
	clc
	ret
.absent:
	stc
	ret

plan_bad_auth:
	call	log_begin
	out_lit 'auth: api_key needs header= and keys=FILE, basic users=FILE; a file has `name:key` or `name:SALT:SHA256HEX` lines, names up to 20 bytes, keys all different, 4096 in all'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; rdi = an `auth` line: eax = its entry + 1. Its file is read here, once a
; plan, and only hashes stay.
compile_auth:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	rbx,rdi
	mov	eax,[g_plan_auths]
	cmp	eax,MAX_AUTHS
	jae	plan_too_many
	inc	dword [g_plan_auths]
	imul	r12,rax,AU_SIZE
	lea	r12,[g_auths+r12]
	mov	[r12+AU_ID],eax
	mov	rax,[rbx+N_ARGS]
	mov	rcx,[rax+A_VAL]
	mov	edx,AK_APIKEY
	cmp	byte [rcx],'a'
	je	@f
	mov	edx,AK_BASIC
	cmp	byte [rcx],'b'
	je	@f
	mov	edx,AK_MTLS
	cmp	byte [rcx],'m'
	je	@f
	mov	edx,AK_FORWARD
	cmp	byte [rcx],'f'
	je	@f
	mov	edx,AK_JWT
@@:
	mov	[r12+AU_KIND],edx
	; identity=
	lea	rax,[str_x_user_id]
	mov	[r12+AU_IDENT],rax
	mov	dword [r12+AU_ILEN],9
	mov	rdi,rbx
	lea	rsi,[str_key_identity]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rcx,[rax+A_VAL]
	mov	[r12+AU_IDENT],rcx
	mov	ecx,[rax+A_VLEN]
	mov	[r12+AU_ILEN],ecx
@@:
	mov	rdi,rbx
	lea	rsi,[str_key_forward]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	lea	rdx,[str_word_on]
	call	mem_eq_cstr
	mov	[r12+AU_FWD],eax
@@:
	cmp	dword [r12+AU_KIND],AK_JWT
	jne	.not_jwt
	call	compile_jwt
	jmp	.done
.not_jwt:
	cmp	dword [r12+AU_KIND],AK_MTLS
	je	.done
	cmp	dword [r12+AU_KIND],AK_FORWARD
	jne	@f
	call	compile_forward
	jmp	.done
@@:
	cmp	dword [r12+AU_KIND],AK_BASIC
	je	.basic
	mov	rdi,rbx
	lea	rsi,[str_key_header]
	call	node_option
	test	rax,rax
	jz	plan_bad_auth
	mov	rcx,[rax+A_VAL]
	mov	[r12+AU_HDR],rcx
	mov	ecx,[rax+A_VLEN]
	mov	[r12+AU_HLEN],ecx
	lea	rsi,[str_key_keys]
	jmp	.file
.basic:
	lea	rax,[str_authorization]
	mov	[r12+AU_HDR],rax
	mov	dword [r12+AU_HLEN],13
	lea	rax,[str_realm_okena]
	mov	[r12+AU_REALM],rax
	mov	dword [r12+AU_RLEN],5
	mov	rdi,rbx
	lea	rsi,[str_key_realm]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rcx,[rax+A_VAL]
	mov	[r12+AU_REALM],rcx
	mov	ecx,[rax+A_VLEN]
	mov	[r12+AU_RLEN],ecx
@@:
	lea	rsi,[str_key_users]
.file:
	mov	rdi,rbx
	call	node_option
	test	rax,rax
	jz	plan_bad_auth
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,1000
	ja	plan_bad_auth
	lea	rdi,[g_au_path]
	rep	movsb
	mov	byte [rdi],0
	lea	rdi,[g_au_path]
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	plan_bad_auth
	mov	r13,rax				; the line
	lea	r14,[rax+rdx]			; the end
.line:
	cmp	r13,r14
	jae	.done
	mov	rsi,r13
.eol:
	cmp	r13,r14
	jae	.got
	cmp	byte [r13],10
	je	.got
	inc	r13
	jmp	.eol
.got:
	mov	rdx,r13				; the line, from rsi to rdx
	inc	r13
	cmp	rdx,rsi
	je	.line
	cmp	byte [rdx-1],13
	jne	@f
	dec	rdx
@@:
	cmp	rdx,rsi
	je	.line
	cmp	byte [rsi],'#'
	je	.line
	call	auth_line
	jmp	.line
.done:
	mov	eax,[r12+AU_ID]
	inc	eax
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; r12 = the auth, rsi = a line, rdx = its end: one more in the table
auth_line:
	push	rbx
	push	r13
	push	r14
	push	r15
	mov	r13,rsi				; the name
	mov	r14,rdx				; the end
	inc	dword [g_plan_akeys]
	cmp	dword [g_plan_akeys],AT_MAX
	ja	plan_bad_auth
	; name:
	mov	rbx,r13
.colon:
	cmp	rbx,r14
	jae	plan_bad_auth
	cmp	byte [rbx],':'
	je	.named
	inc	rbx
	jmp	.colon
.named:
	mov	r15,rbx
	sub	r15,r13				; its length
	jz	plan_bad_auth
	cmp	r15,AUTH_NAME_MAX
	ja	plan_bad_auth
	inc	rbx
	cmp	dword [r12+AU_KIND],AK_BASIC
	je	.user
	; a key
	mov	rsi,rbx
	mov	rdx,r14
	sub	rdx,rbx
	jz	plan_bad_auth
	lea	rdi,[g_au_digest]
	call	sha256
	jmp	.place
.user:
	mov	rsi,r13
	mov	rdx,r15
	lea	rdi,[g_au_digest]
	call	sha256
.place:
	lea	rsi,[g_au_digest]
	mov	edx,[r12+AU_ID]
	call	auth_slot
	test	rax,rax
	jnz	plan_bad_auth			; the same key twice
	; its slot
	mov	ecx,[g_au_digest]
	imul	eax,[r12+AU_ID],0x9E3779B1
	add	ecx,eax
.free:
	and	ecx,AT_N - 1
	mov	eax,ecx
	shl	rax,7
	lea	r8,[g_auth_tab+rax]
	cmp	dword [r8+AT_NLEN],0
	je	.slot
	inc	ecx
	jmp	.free
.slot:
	mov	rdi,r8
	lea	rsi,[g_au_digest]
	mov	ecx,32
	rep	movsb
	mov	eax,[r12+AU_ID]
	mov	[r8+AT_AU],eax
	mov	[r8+AT_NLEN],r15d
	lea	rdi,[r8+AT_NAME]
	mov	rsi,r13
	mov	rcx,r15
	rep	movsb
	cmp	dword [r12+AU_KIND],AK_BASIC
	jne	.out
	; SALT:HEX, of 64 digits
	mov	rax,rbx
.salt_end:
	cmp	rax,r14
	jae	plan_bad_auth
	cmp	byte [rax],':'
	je	.salted
	inc	rax
	jmp	.salt_end
.salted:
	mov	rcx,rax
	sub	rcx,rbx
	cmp	rcx,32
	ja	plan_bad_auth
	mov	[r8+AT_SLEN],ecx
	lea	rdi,[r8+AT_SALT]
	mov	rsi,rbx
	rep	movsb
	lea	rsi,[rax+1]
	mov	rcx,r14
	sub	rcx,rsi
	cmp	rcx,64
	jne	plan_bad_auth
	mov	ecx,32
	lea	rdi,[r8+AT_HASH]
	call	hex_bytes
	jc	plan_bad_auth
.out:
	pop	r15
	pop	r14
	pop	r13
	pop	rbx
	ret

plan_bad_hedge:
	call	log_begin
	out_lit 'hedge: after= is a time or a percentile such as p95; max= can only be 1'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

plan_bad_mirror:
	call	log_begin
	out_lit 'mirror: pool NAME, of a pool that exists, then N% from 1 to 100 if not all'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

plan_bad_split:
	call	log_begin
	out_lit 'split: pools as NAME=N%, 2 to 8 of them, adding up to 100%; sticky= is cookie:NAME or header:NAME'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; rdi = a `split` line: eax = its entry + 1
compile_split:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	rbx,rdi
	mov	eax,[g_plan_splits]
	cmp	eax,MAX_SPLITS
	jae	plan_too_many
	inc	dword [g_plan_splits]
	imul	r12,rax,SL_SIZE
	lea	r12,[g_splits+r12]
	mov	r13,[rbx+N_ARGS]
	mov	r14d,[rbx+N_ARGC]
	xor	ebx,ebx				; shares so far
.arg:
	test	r14d,r14d
	jz	.args_done
	cmp	dword [r13+A_KIND],ARG_KV
	jne	plan_bad_split
	mov	rdi,[r13+A_KEY]
	mov	esi,[r13+A_KLEN]
	lea	rdx,[.sticky]
	call	mem_eq_cstr
	test	eax,eax
	jnz	.is_sticky
	mov	eax,[r12+SL_N]
	cmp	eax,SL_MAX
	jae	plan_bad_split
	mov	rdi,[r13+A_KEY]
	mov	esi,[r13+A_KLEN]
	call	plan_pool_index
	cmp	eax,-1
	je	plan_bad_split
	mov	ecx,[r12+SL_N]
	mov	[r12+SL_P+rcx*8],eax
	; N%
	mov	rsi,[r13+A_VAL]
	mov	ecx,[r13+A_VLEN]
	cmp	ecx,2
	jb	plan_bad_split
	dec	ecx
	cmp	byte [rsi+rcx],'%'
	jne	plan_bad_split
	xor	eax,eax
	xor	edx,edx
.digit:
	movzx	r8d,byte [rsi+rdx]
	sub	r8d,'0'
	cmp	r8d,9
	ja	plan_bad_split
	imul	eax,eax,10
	add	eax,r8d
	cmp	eax,100
	ja	plan_bad_split
	inc	edx
	cmp	edx,ecx
	jb	.digit
	test	eax,eax
	jz	plan_bad_split
	add	ebx,eax
	mov	ecx,[r12+SL_N]
	mov	[r12+SL_P+rcx*8+4],ebx
	inc	dword [r12+SL_N]
	jmp	.next
.is_sticky:
	mov	rsi,[r13+A_VAL]
	mov	ecx,[r13+A_VLEN]
	cmp	ecx,8
	jb	plan_bad_split
	mov	edx,SK_COOKIE
	lea	rax,[rsi+7]
	cmp	dword [rsi],'cook'
	jne	@f
	cmp	word [rsi+4],'ie'
	jne	plan_bad_split
	cmp	byte [rsi+6],':'
	je	.sticky_name
	jmp	plan_bad_split
@@:
	mov	edx,SK_HEADER
	cmp	dword [rsi],'head'
	jne	plan_bad_split
	cmp	word [rsi+4],'er'
	jne	plan_bad_split
	cmp	byte [rsi+6],':'
	jne	plan_bad_split
.sticky_name:
	mov	[r12+SL_KIND],edx
	mov	[r12+SL_NAME],rax
	sub	ecx,7
	mov	[r12+SL_NLEN],ecx
.next:
	add	r13,A_SIZE
	dec	r14d
	jmp	.arg
.args_done:
	cmp	ebx,100
	jne	plan_bad_split
	cmp	dword [r12+SL_N],2
	jb	plan_bad_split
	mov	eax,[g_plan_splits]
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
.sticky	db 'sticky',0

plan_bad_cors:
	call	log_begin
	out_lit 'cors: origins= is needed: a list of origins, each with at most one *, or * alone, and * cannot go with credentials'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; rdi = a `cors` line: eax = its entry + 1
compile_cors:
	push	rbx
	push	r12
	mov	rbx,rdi
	mov	eax,[g_plan_cors]
	cmp	eax,MAX_CORS
	jae	plan_too_many
	inc	dword [g_plan_cors]
	imul	r12,rax,CO_SIZE
	lea	r12,[g_cors+r12]
	mov	rdi,rbx
	lea	rsi,[str_key_origins]
	call	node_option
	test	rax,rax
	jz	plan_bad_cors
	mov	rcx,[rax+A_VAL]
	mov	edx,[rax+A_VLEN]
	test	edx,edx
	jz	plan_bad_cors
	mov	[r12+CO_ORIG],rcx
	mov	[r12+CO_OLEN],edx
	cmp	edx,1
	jne	.stars
	cmp	byte [rcx],'*'
	jne	.stars
	mov	dword [r12+CO_ANY],1
	jmp	.lists
.stars:
	; at most one * an origin
	xor	r8d,r8d
	xor	r9d,r9d
.star:
	cmp	r8d,edx
	jae	.lists
	mov	al,[rcx+r8]
	inc	r8d
	cmp	al,','
	jne	@f
	xor	r9d,r9d
	jmp	.star
@@:
	cmp	al,'*'
	jne	.star
	inc	r9d
	cmp	r9d,1
	ja	plan_bad_cors
	jmp	.star
.lists:
	mov	rdi,rbx
	lea	rsi,[str_key_methods]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rcx,[rax+A_VAL]
	mov	[r12+CO_METH],rcx
	mov	ecx,[rax+A_VLEN]
	mov	[r12+CO_MLEN],ecx
@@:
	mov	rdi,rbx
	lea	rsi,[str_key_headers]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rcx,[rax+A_VAL]
	mov	[r12+CO_HDRS],rcx
	mov	ecx,[rax+A_VLEN]
	mov	[r12+CO_HLEN],ecx
@@:
	mov	rdi,rbx
	lea	rsi,[str_key_expose]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rcx,[rax+A_VAL]
	mov	[r12+CO_EXP],rcx
	mov	ecx,[rax+A_VLEN]
	mov	[r12+CO_ELEN],ecx
@@:
	mov	rdi,rbx
	lea	rsi,[str_key_max_age]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_duration			; µs
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	mov	[r12+CO_AGE],eax
@@:
	; credentials, a word of its own
	mov	rax,[rbx+N_ARGS]
	mov	ecx,[rbx+N_ARGC]
.word:
	test	ecx,ecx
	jz	.worded
	cmp	dword [rax+A_KIND],ARG_KV
	je	.next_word
	mov	dword [r12+CO_CRED],1
	cmp	dword [r12+CO_ANY],0
	jne	plan_bad_cors
.next_word:
	add	rax,A_SIZE
	dec	ecx
	jmp	.word
.worded:
	mov	eax,[g_plan_cors]
	pop	r12
	pop	rbx
	ret

plan_bad_limit:
	call	log_begin
	out_lit 'limit: RATE is N/s, N/m or N/h, of 1 to 1000000000; key= is client.ip, method, header:NAME, query:NAME or cookie:NAME; at most 256 limits'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; rdi = a `limit` line: one more in g_limits
compile_limit:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	rbx,rdi
	mov	eax,[g_plan_limits]
	cmp	eax,MAX_LIMITS
	jae	plan_bad_limit
	inc	dword [g_plan_limits]
	imul	r12,rax,LM_SIZE
	lea	r12,[g_limits+r12]
	mov	[r12+LM_ID],eax
	mov	dword [r12+LM_KIND],LK_ROUTE
	mov	qword [r12+LM_NAME],0
	mov	dword [r12+LM_NLEN],0
	; the rate: N/s, N/m, N/h
	mov	rax,[rbx+N_ARGS]
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	xor	r13d,r13d			; N
	xor	edx,edx
.digit:
	cmp	edx,ecx
	jae	plan_bad_limit
	movzx	eax,byte [rsi+rdx]
	cmp	al,'/'
	je	.unit
	sub	eax,'0'
	cmp	eax,9
	ja	plan_bad_limit
	imul	r13,r13,10
	add	r13,rax
	mov	rax,1000000000
	cmp	r13,rax
	ja	plan_bad_limit
	inc	edx
	jmp	.digit
.unit:
	test	r13,r13
	jz	plan_bad_limit
	lea	eax,[rdx+2]
	cmp	eax,ecx
	jne	plan_bad_limit
	movzx	eax,byte [rsi+rdx+1]
	mov	r14d,1				; seconds in the period
	cmp	al,'s'
	je	.period
	mov	r14d,60
	cmp	al,'m'
	je	.period
	mov	r14d,3600
	cmp	al,'h'
	je	.period
	mov	r14d,86400
	cmp	al,'d'
	jne	plan_bad_limit
.period:
	; instances=N: this instance's share of a fleet's limit
	mov	rdi,rbx
	lea	rsi,[str_key_instances]
	call	node_option
	mov	ecx,1
	test	rax,rax
	jz	.share
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_decimal
	mov	ecx,eax
.share:
	; T = the period / N, the share made longer
	mov	eax,r14d
	imul	rax,rax,1000000000
	imul	rax,rcx
	xor	edx,edx
	div	r13
	test	rax,rax
	jz	plan_bad_limit
	mov	[r12+LM_T],rax
	; burst: as given, else a second of the rate, at least 1
	mov	rdi,rbx
	lea	rsi,[str_key_burst]
	call	node_option
	test	rax,rax
	jz	.second
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_decimal
	jmp	.burst
.second:
	mov	rcx,[r12+LM_T]
	mov	eax,1000000000
	add	rax,rcx
	dec	rax
	xor	edx,edx
	div	rcx
.burst:
	test	rax,rax
	jnz	@f
	mov	eax,1
@@:
	dec	rax
	imul	rax,[r12+LM_T]
	mov	[r12+LM_TOL],rax
	; a batch: 20 ms of the rate, 1 to 64 tokens
	mov	eax,20000000
	xor	edx,edx
	div	qword [r12+LM_T]
	inc	rax
	cmp	rax,64
	jbe	@f
	mov	eax,64
@@:
	mov	[r12+LM_CAP],eax
	; key=
	mov	rdi,rbx
	lea	rsi,[str_key_lkey]
	call	node_option
	test	rax,rax
	jz	.keyed
	mov	r13,[rax+A_VAL]
	mov	r14d,[rax+A_VLEN]
	mov	rdi,r13
	mov	esi,r14d
	lea	rdx,[.client_ip]
	call	mem_eq_cstr
	mov	ecx,LK_IP
	test	eax,eax
	jnz	.kind
	mov	rdi,r13
	mov	esi,r14d
	lea	rdx,[.method]
	call	mem_eq_cstr
	mov	ecx,LK_METHOD
	test	eax,eax
	jnz	.kind
	mov	rdi,r13
	mov	esi,r14d
	lea	rdx,[.auth_user]
	call	mem_eq_cstr
	mov	ecx,LK_AUTH
	test	eax,eax
	jnz	.kind
	mov	rdi,r13
	mov	esi,r14d
	lea	rdx,[.jwt_sub]
	call	mem_eq_cstr
	mov	ecx,LK_AUTH
	test	eax,eax
	jnz	.kind
	; PREFIX:NAME
	xor	edx,edx
.colon:
	cmp	edx,r14d
	jae	plan_bad_limit
	cmp	byte [r13+rdx],':'
	je	.prefix
	inc	edx
	jmp	.colon
.prefix:
	lea	rax,[r13+rdx+1]
	mov	[r12+LM_NAME],rax
	mov	eax,r14d
	sub	eax,edx
	dec	eax
	jz	plan_bad_limit
	mov	[r12+LM_NLEN],eax
	mov	ecx,LK_HEADER
	cmp	edx,6
	jne	@f
	cmp	dword [r13],'head'
	jne	.not_header
	cmp	word [r13+4],'er'
	je	.kind
.not_header:
	mov	ecx,LK_COOKIE
	cmp	dword [r13],'cook'
	jne	plan_bad_limit
	cmp	word [r13+4],'ie'
	je	.kind
	jmp	plan_bad_limit
@@:
	mov	ecx,LK_QUERY
	cmp	edx,5
	jne	plan_bad_limit
	cmp	dword [r13],'quer'
	jne	plan_bad_limit
	cmp	byte [r13+4],'y'
	jne	plan_bad_limit
.kind:
	mov	[r12+LM_KIND],ecx
.keyed:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
.client_ip	db 'client.ip',0
.method		db 'method',0
.auth_user	db 'auth.user',0
.jwt_sub	db 'jwt.sub',0

plan_bad_fault:
	call	log_begin
	out_lit 'fault: abort= is a status from 400 to 599, delay= more than 0 and at most 10m, one of them given; percent= at most 100'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

plan_bad_quic_sid:
	call	log_begin
	out_lit 'quic_server_id: 1 or 2 bytes of hex; key= 16 bytes of hex; rotation= 0 to 6'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; rsi = hex text, ecx = bytes wanted, rdi = where: CF on a digit that is not one
hex_bytes:
	mov	r8d,2
	xor	edx,edx
.digit:
	movzx	eax,byte [rsi]
	inc	rsi
	sub	al,'0'
	cmp	al,9
	jbe	.have
	add	al,'0'
	or	al,0x20				; (lower case)
	sub	al,'a'
	cmp	al,5
	ja	.bad
	add	al,10
.have:
	shl	edx,4
	or	edx,eax
	dec	r8d
	jnz	.digit
	mov	[rdi],dl
	inc	rdi
	dec	ecx
	jnz	hex_bytes
	clc
	ret
.bad:
	stc
	ret

plan_too_many:
	call	log_begin
	out_lit 'the configuration needs more than this build holds: at most '
	mov	eax,MAX_LISTENERS
	call	out_u64
	out_lit ' listener addresses, '
	mov	eax,MAX_POOLS
	call	out_u64
	out_lit ' pools, '
	mov	eax,MAX_SERVERS
	call	out_u64
	out_lit ' servers, '
	mov	eax,MAX_ROUTES
	call	out_u64
	out_lit ' route paths, '
	mov	eax,MAX_HOSTS
	call	out_u64
	out_lit ' host names'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; rdi = pool node.
compile_pool:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	mov	rax,[r12+N_ARGS]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	pool_new
	mov	r13,rax
	mov	rbx,[r12+N_CHILD]
.next:
	test	rbx,rbx
	jz	.done
	mov	rax,[rbx+N_DEF]
	lea	rcx,[dir_table + D_SIZE*DIR_SERVER]
	cmp	rax,rcx
	je	.server
	lea	rcx,[dir_table + D_SIZE*DIR_BALANCE]
	cmp	rax,rcx
	je	.balance
	lea	rcx,[dir_table + D_SIZE*DIR_SLOW_START]
	cmp	rax,rcx
	je	.slow_start
	lea	rcx,[dir_table + D_SIZE*DIR_STICKY]
	cmp	rax,rcx
	je	.sticky
	lea	rcx,[dir_table + D_SIZE*DIR_QUEUE]
	cmp	rax,rcx
	je	.queue
	lea	rcx,[dir_table + D_SIZE*DIR_DISCOVER]
	cmp	rax,rcx
	je	.discover
	lea	rcx,[dir_table + D_SIZE*DIR_CONNECT]
	cmp	rax,rcx
	je	.connect
	lea	rcx,[dir_table + D_SIZE*DIR_HEALTH]
	cmp	rax,rcx
	je	.health
	lea	rcx,[dir_table + D_SIZE*DIR_UPTLS]
	cmp	rax,rcx
	je	.uptls
	lea	rcx,[dir_table + D_SIZE*DIR_PROTOCOL]
	cmp	rax,rcx
	jne	.advance
	mov	rax,[rbx+N_ARGS]		; protocol h1|h2|fastcgi
	mov	rax,[rax+A_VAL]
	cmp	byte [rax],'f'
	jne	@f
	mov	dword [r13+PL_FCGI],1
	jmp	.advance
@@:
	cmp	byte [rax+1],'2'
	jne	.advance
	mov	dword [r13+PL_H2],1
	jmp	.advance
.health:
	mov	dword [r13+PL_HEALTH],1
	inc	dword [g_plan_health]
	mov	dword [r13+PL_H_EVERY],2000
	mov	dword [r13+PL_H_TIMEOUT],1000
	mov	dword [r13+PL_H_RISE],2
	mov	dword [r13+PL_H_FALL],3
	; http: [GET|HEAD] PATH, expect=, host=
	mov	rax,[rbx+N_ARGS]
	mov	rdi,[rax+A_VAL]
	cmp	byte [rdi],'g'
	je	.health_grpc
	cmp	byte [rdi],'h'
	jne	.health_keys
	mov	dword [r13+PL_H_HTTP],1
	mov	dword [r13+PL_H_LO],200
	mov	dword [r13+PL_H_HI],399
	push	rax
	mov	rdi,rbx
	call	positional_count
	mov	ecx,eax
	pop	rax
	cmp	ecx,3
	jne	@f
	mov	rdx,[rax+A_SIZE+A_VAL]
	cmp	byte [rdx],'H'
	jne	@f
	mov	dword [r13+PL_H_HEAD],1
@@:
	dec	ecx
	imul	rcx,rcx,A_SIZE
	add	rax,rcx
	mov	rdx,[rax+A_VAL]
	mov	[r13+PL_H_PATH],rdx
	mov	edx,[rax+A_VLEN]
	mov	[r13+PL_H_PLEN],edx
	mov	rdi,rbx
	lea	rsi,[str_key_expect]
	call	node_option
	test	rax,rax
	jz	.health_host
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_statuses
	mov	[r13+PL_H_LO],eax
	mov	[r13+PL_H_HI],edx
.health_host:
	mov	rdi,rbx
	lea	rsi,[str_key_host]
	call	node_option
	test	rax,rax
	jz	.health_keys
	mov	rdx,[rax+A_VAL]
	mov	[r13+PL_H_HOST],rdx
	mov	edx,[rax+A_VLEN]
	mov	[r13+PL_H_HLEN],edx
	jmp	.health_keys
.health_grpc:
	; grpc [SERVICE], host=: grpc.health.v1.Health/Check over HTTP/2
	mov	dword [r13+PL_H_HTTP],2
	push	rax
	mov	rdi,rbx
	call	positional_count
	pop	rdx
	cmp	eax,2
	jne	.health_host
	mov	rax,[rdx+A_SIZE+A_VAL]
	mov	[r13+PL_H_PATH],rax
	mov	eax,[rdx+A_SIZE+A_VLEN]
	mov	[r13+PL_H_PLEN],eax
	jmp	.health_host
.health_keys:
	mov	rdi,rbx
	lea	rsi,[str_key_every]
	call	node_option
	test	rax,rax
	jz	@f
	call	.ms
	mov	[r13+PL_H_EVERY],eax
@@:
	mov	rdi,rbx
	lea	rsi,[str_key_timeout]
	call	node_option
	test	rax,rax
	jz	@f
	call	.ms
	mov	[r13+PL_H_TIMEOUT],eax
@@:
	mov	rdi,rbx
	lea	rsi,[str_key_rise]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_decimal
	mov	[r13+PL_H_RISE],eax
@@:
	mov	rdi,rbx
	lea	rsi,[str_key_fall]
	call	node_option
	test	rax,rax
	jz	.advance
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_decimal
	mov	[r13+PL_H_FALL],eax
	jmp	.advance
; rax = arg with a duration: eax = milliseconds (at least 1)
.ms:
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_duration
	xor	edx,edx
	mov	ecx,1000
	div	rcx
	test	eax,eax
	jnz	@f
	inc	eax
@@:
	ret
.server:
	mov	rdi,r13
	mov	rsi,rbx
	call	compile_server
	jmp	.advance
.discover:
	mov	rdi,r13
	mov	rsi,rbx
	call	compile_discover
	jmp	.advance
.queue:
	mov	rdi,rbx
	lea	rsi,[str_key_timeout]
	call	node_option
	test	rax,rax
	jz	.advance
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_duration
	mov	[r13+PL_QTIMEOUT],rax
	jmp	.advance
.sticky:
	mov	rdi,rbx
	lea	rsi,[str_key_cookie]
	call	node_option
	test	rax,rax
	jz	plan_bad_sticky
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	test	ecx,ecx
	jz	plan_bad_sticky
	cmp	ecx,64
	ja	plan_bad_sticky
	mov	[r13+PL_SNAME],rsi
	mov	[r13+PL_SNLEN],ecx
@@:
	movzx	eax,byte [rsi]			; a token (RFC 6265): no separators
	inc	rsi
	cmp	eax,'!'
	jb	plan_bad_sticky
	cmp	eax,'~'
	ja	plan_bad_sticky
	cmp	al,'='
	je	plan_bad_sticky
	cmp	al,';'
	je	plan_bad_sticky
	cmp	al,','
	je	plan_bad_sticky
	cmp	al,'"'
	je	plan_bad_sticky
	cmp	al,'\'
	je	plan_bad_sticky
	dec	ecx
	jnz	@b
	mov	dword [r13+PL_STTL],0
	mov	rdi,rbx
	lea	rsi,[str_key_ttl]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_duration
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	test	rax,rax
	jz	plan_bad_sticky
	mov	[r13+PL_STTL],eax
@@:
	mov	dword [r13+PL_SSAME],SS_LAX
	mov	rdi,rbx
	lea	rsi,[str_key_samesite]
	call	node_option
	test	rax,rax
	jz	.advance
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	lea	rdx,[e_samesite]
	call	list_index
	test	eax,eax
	js	plan_bad_sticky
	mov	[r13+PL_SSAME],eax
	jmp	.advance
.slow_start:
	mov	rax,[rbx+N_ARGS]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_duration
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	test	eax,eax
	jnz	@f
	inc	eax				; at least a second
@@:
	mov	[r13+PL_SLOW],eax
	jmp	.advance
.balance:
	mov	rax,[rbx+N_ARGS]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	lea	rdx,[e_balance]
	call	list_index
	mov	dword [r13+PL_HKEY],HK_SOURCE
	cmp	eax,BAL_SOURCE
	jne	@f
	mov	eax,BAL_MAGLEV
@@:
	mov	[r13+PL_BALANCE],eax
	mov	dword [r13+PL_HBOUND],0
	mov	rdi,rbx
	lea	rsi,[str_key_bound]
	call	node_option
	test	rax,rax
	jz	.no_bound
	cmp	dword [r13+PL_BALANCE],BAL_MAGLEV
	jb	plan_bad_bound
	cmp	dword [r13+PL_BALANCE],BAL_RING
	ja	plan_bad_bound
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,2
	jb	plan_bad_bound
	cmp	byte [rsi+rcx-1],'%'
	jne	plan_bad_bound
	dec	ecx
	cmp	ecx,4
	ja	plan_bad_bound
	xor	eax,eax
@@:
	movzx	edx,byte [rsi]
	inc	rsi
	sub	edx,'0'
	cmp	edx,9
	ja	plan_bad_bound
	imul	eax,eax,10
	add	eax,edx
	dec	ecx
	jnz	@b
	cmp	eax,101
	jb	plan_bad_bound
	cmp	eax,1000
	ja	plan_bad_bound
	mov	[r13+PL_HBOUND],eax
.no_bound:
	mov	rdi,rbx
	lea	rsi,[str_key_key]
	call	node_option
	test	rax,rax
	jz	.advance
	cmp	dword [r13+PL_BALANCE],BAL_MAGLEV
	jb	plan_bad_key
	cmp	dword [r13+PL_BALANCE],BAL_RING
	ja	plan_bad_key
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	mov	rdx,'source'
	call	.balance_is
	je	.advance
	mov	dword [r13+PL_HKEY],HK_PATH
	mov	rdx,'path'
	call	.balance_is
	je	.advance
	mov	dword [r13+PL_HKEY],HK_URL
	mov	rdx,'url'
	call	.balance_is
	je	.advance
	mov	dword [r13+PL_HKEY],HK_HEADER
	mov	rdx,'header:'
	call	.balance_named
	je	.advance
	mov	dword [r13+PL_HKEY],HK_COOKIE
	mov	rdx,'cookie:'
	call	.balance_named
	je	.advance
	mov	dword [r13+PL_HKEY],HK_QUERY
	mov	rdx,'query:'
	call	.balance_named
	je	.advance
	jmp	plan_bad_key
; rsi/ecx = the key, rdx = up to 8 bytes: ZF when they are all of it
.balance_is:
	xor	eax,eax
	mov	r8,rdx
@@:
	test	r8,r8
	jz	@f
	shr	r8,8
	inc	eax
	jmp	@b
@@:
	cmp	eax,ecx
	jne	.balance_ne
	push	rsi
	xor	r8d,r8d
@@:
	cmp	r8d,ecx
	jae	@f
	cmp	byte [rsi+r8],dl
	jne	.balance_pop
	shr	rdx,8
	inc	r8d
	jmp	@b
@@:
	pop	rsi
	xor	eax,eax				; ZF
	ret
.balance_pop:
	pop	rsi
.balance_ne:
	or	eax,1
	ret
; the same for a prefix and a name after it, which goes to the pool
.balance_named:
	xor	eax,eax
	mov	r8,rdx
@@:
	test	r8,r8
	jz	@f
	shr	r8,8
	inc	eax
	jmp	@b
@@:
	cmp	ecx,eax
	jbe	.balance_ne
	push	rcx
	mov	ecx,eax
	call	.balance_is
	pop	rcx
	jne	.balance_ne
	mov	r9d,eax				; (0)
	xor	eax,eax
	mov	r8,rdx
	lea	rdi,[rsi]
	; length of the prefix again
@@:
	cmp	byte [rdi],':'
	je	@f
	inc	rdi
	jmp	@b
@@:
	inc	rdi
	mov	[r13+PL_HNAME],rdi
	sub	rdi,rsi
	sub	ecx,edi
	mov	[r13+PL_HNLEN],ecx
	xor	eax,eax
	ret
.connect:
	mov	rdi,rbx
	lea	rsi,[str_key_timeout]
	call	node_option
	test	rax,rax
	jz	.advance
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_duration
	xor	edx,edx
	mov	ecx,1000000
	div	rcx
	mov	[r13+PL_TIMEOUT],rax
	imul	rdx,rdx,1000
	mov	[r13+PL_TIMEOUT+8],rdx
	jmp	.advance
.uptls:
	mov	dword [r13+PL_TLS],1
	; cert= and key=: a certificate to show the backends that ask for one
	mov	rdi,rbx
	cstring str_key_upcert, 'cert',0
	lea	rsi,[str_key_upcert]
	call	node_option
	test	rax,rax
	jz	@f
	push	rax
	mov	rdi,rbx
	cstring str_key_upkey, 'key',0
	lea	rsi,[str_key_upkey]
	call	node_option
	pop	rdi
	test	rax,rax
	jz	plan_bad_upcert
	mov	rsi,rax
	mov	eax,[g_plan_tls]
	inc	eax
	mov	[r13+PL_TLS_CID],eax
	mov	edx,0x40000000			; (a group no listener has: its names serve no SNI)
	add	edx,eax
	call	compile_cert
@@:
	mov	rdi,rbx				; sni = SNI + the name verified (optional)
	lea	rsi,[str_key_sni]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rdx,[rax+A_VAL]
	mov	[r13+PL_TLS_SNI],rdx
	mov	edx,[rax+A_VLEN]
	mov	[r13+PL_TLS_SNILEN],edx
@@:
	mov	rdi,rbx				; trust = a PEM file of trust anchors
	lea	rsi,[str_key_trust]
	call	node_option
	test	rax,rax
	jz	.advance			; (check requires it; absence is handled there)
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,4095
	ja	.advance
	mov	rsi,[rax+A_VAL]			; copy the path, NUL-terminated
	lea	rdi,[g_trust_path]
	push	rcx
	rep	movsb
	pop	rcx
	mov	byte [g_trust_path+rcx],0
	lea	rdi,[g_trust_path]
	lea	rsi,[g_ar_text]			; read_file allocates from this arena
	call	read_file			; rax = contents, rdx = length, or rax < 0
	test	rax,rax
	js	.advance
	mov	rsi,rax				; the first CERTIFICATE -> DER
	mov	edx,edx
	lea	rdi,[g_trust_der]
	call	pem_first_cert
	test	eax,eax
	jz	.advance
	lea	rsi,[g_trust_der]		; -> the anchor's public key (EC or RSA)
	mov	edx,eax
	lea	rdi,[r13+PL_TLS_ANCHOR]
	call	cert_pubkey
	test	eax,eax
	jz	.advance
	mov	dword [r13+PL_TLS_HASANCHOR],1
.advance:
	mov	rbx,[rbx+N_NEXT]
	jmp	.next
.done:
	pop	r13
	pop	r12
	pop	rbx
	ret

plan_bad_upcert:
	call	log_begin
	out_lit 'a pool''s tls cert= wants key= too (the certificate it shows backends that ask for one)'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; rdi = pool entry, rsi = server node.
compile_server:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	mov	r13,rsi
	mov	rbx,[r13+N_ARGS]
	mov	rdi,rbx
	mov	rsi,r12
	call	server_new			; rax = server
	mov	rbx,rax
	; flags and weight
	mov	rcx,[r13+N_ARGS]
	mov	edx,[r13+N_ARGC]
.args:
	add	rcx,A_SIZE
	dec	edx
	jz	.weight
	cmp	dword [rcx+A_KIND],ARG_WORD
	jne	.args
	mov	dword [rbx+SV_BACKUP],1		; the only flag is `backup`
	jmp	.args
.weight:
	mov	rdi,r13
	lea	rsi,[str_key_weight]
	call	node_option
	test	rax,rax
	jz	.counted
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_decimal
	mov	[rbx+SV_WEIGHT],eax
.counted:
	mov	rdi,r13
	lea	rsi,[str_key_max]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_decimal
	mov	[rbx+SV_MAX],eax
	mov	dword [r12+PL_HASMAX],1
@@:
	cmp	dword [rbx+SV_BACKUP],0
	jne	@f
	inc	dword [r12+PL_PRIMARY]
@@:
	; a name's other slots take the same weight and role
	cmp	dword [rbx+SV_GROUP],0
	je	.out
	mov	eax,[rbx+SV_WEIGHT]
	mov	ecx,[rbx+SV_BACKUP]
	mov	r9d,[rbx+SV_MAX]
	mov	edx,DNS_MAX_ADDRS - 1
	lea	r8,[rbx+SV_SIZE]
@@:
	mov	[r8+SV_WEIGHT],eax
	mov	[r8+SV_BACKUP],ecx
	mov	[r8+SV_MAX],r9d			; (each address of a name its own max)
	add	r8,SV_SIZE
	dec	edx
	jnz	@b
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret

cstring str_localhost, 'localhost',0

; rdi = address arg, rsi = pool entry. rax = new server (weight 1).
server_new:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	mov	r13,rsi
	mov	ecx,[g_plan_servers]
	cmp	ecx,MAX_SERVERS
	jae	plan_too_many
	inc	dword [g_plan_servers]
	inc	dword [r13+PL_COUNT]
	imul	rbx,rcx,SV_SIZE
	lea	rbx,[g_servers+rbx]
	mov	dword [rbx+SV_WEIGHT],1
	mov	rax,[r12+A_VAL]
	mov	[rbx+SV_TEXT],rax
	mov	eax,[r12+A_VLEN]
	mov	[rbx+SV_TLEN],eax
	mov	rdi,[r12+A_VAL]
	mov	esi,[r12+A_VLEN]
	lea	rdx,[g_cmp_addr]
	mov	ecx,1
	call	parse_address
	mov	eax,[g_cmp_addr+AD_KIND]
	cmp	eax,ADDR_NAME
	jne	.build
	; "localhost" is the loopback address by definition (RFC 6761)
	mov	rdi,[g_cmp_addr+AD_NAME]
	mov	esi,[g_cmp_addr+AD_NLEN]
	lea	rdx,[str_localhost]
	call	mem_eq_cstr
	test	eax,eax
	jz	.name
	mov	dword [g_cmp_addr+AD_KIND],ADDR_V4
	mov	dword [g_cmp_addr+AD_IP],0x0100007F
.build:
	lea	rdi,[rbx+SV_SA]
	lea	rsi,[g_cmp_addr]
	call	sockaddr_build
	mov	[rbx+SV_SALEN],eax
	mov	[rbx+SV_FAMILY],edx
	mov	dword [rbx+SV_ACTIVE],1
	mov	rax,rbx
	pop	r13
	pop	r12
	pop	rbx
	ret
.name:
	; a name: DNS_MAX_ADDRS slots, filled in when it resolves
	mov	ecx,[g_plan_groups]
	cmp	ecx,MAX_GROUPS
	jae	plan_too_many
	inc	dword [g_plan_groups]
	imul	rax,rcx,GR_SIZE
	lea	rax,[g_groups+rax]
	mov	rdx,[g_cmp_addr+AD_NAME]
	mov	[rax+GR_NAME],rdx
	mov	edx,[g_cmp_addr+AD_NLEN]
	mov	[rax+GR_NLEN],edx
	mov	edx,[g_cmp_addr+AD_PORT]
	mov	[rax+GR_PORT],edx
	mov	dword [rax+GR_KIND],GK_DNS
	mov	dword [rax+GR_SLOTS],DNS_MAX_ADDRS
	mov	edx,[g_plan_servers]
	dec	edx				; this slot is the first
	mov	[rax+GR_FIRST],edx
	inc	ecx
	mov	[rbx+SV_GROUP],ecx
	mov	dword [rbx+SV_ACTIVE],0
	mov	r8d,DNS_MAX_ADDRS - 1
.more_slots:
	mov	edx,[g_plan_servers]
	cmp	edx,MAX_SERVERS
	jae	plan_too_many
	inc	dword [g_plan_servers]
	inc	dword [r13+PL_COUNT]
	imul	rdx,rdx,SV_SIZE
	lea	rdx,[g_servers+rdx]
	mov	dword [rdx+SV_WEIGHT],1
	mov	rax,[rbx+SV_TEXT]
	mov	[rdx+SV_TEXT],rax
	mov	eax,[rbx+SV_TLEN]
	mov	[rdx+SV_TLEN],eax
	mov	[rdx+SV_GROUP],ecx
	dec	r8d
	jnz	.more_slots
	mov	rax,rbx
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = sockaddr output, rsi = parsed address.
; eax = sockaddr length, edx = family.
sockaddr_build:
	mov	ecx,[rsi+AD_KIND]
	cmp	ecx,ADDR_V4
	je	.v4
	cmp	ecx,ADDR_UNIX
	je	.unix
	; IPv6, or ":port" bound as dual-stack IPv6
	mov	word [rdi],AF_INET6
	mov	eax,[rsi+AD_PORT]
	xchg	al,ah
	mov	[rdi+2],ax
	mov	dword [rdi+4],0
	mov	rax,[rsi+AD_IP]
	mov	[rdi+8],rax
	mov	rax,[rsi+AD_IP+8]
	mov	[rdi+16],rax
	mov	dword [rdi+24],0
	mov	eax,28
	mov	edx,AF_INET6
	ret
.v4:
	mov	word [rdi],AF_INET
	mov	eax,[rsi+AD_PORT]
	xchg	al,ah
	mov	[rdi+2],ax
	mov	eax,[rsi+AD_IP]
	mov	[rdi+4],eax
	mov	qword [rdi+8],0
	mov	eax,16
	mov	edx,AF_INET
	ret
.unix:
	mov	word [rdi],AF_UNIX
	push	rsi
	push	rdi
	mov	ecx,[rsi+AD_NLEN]
	mov	rsi,[rsi+AD_NAME]
	add	rdi,2
	rep	movsb
	mov	byte [rdi],0
	pop	rdi
	pop	rsi
	mov	eax,[rsi+AD_NLEN]
	add	eax,3				; family + path + NUL
	mov	edx,AF_UNIX
	ret

cstring str_word_pool, 'pool',0

; rdi = tcp node: one listener per address.
compile_listener:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rdi
	mov	r14d,-1				; http: routes choose the pool
	mov	dword [g_cmp_pt],0
	mov	dword [g_cmp_hpeer],0
	call	compile_udp
	lea	rax,[dir_table + D_SIZE*DIR_HTTP]
	cmp	[r12+N_DEF],rax
	je	.http
	mov	rdi,r12
	call	listener_passthrough
	test	rax,rax
	jz	@f
	mov	rdi,r12
	call	compile_passthrough		; the pools from its sni lines
	mov	r14d,eax
	jmp	.settings
@@:
	mov	rdi,r12
	call	compile_target
	mov	r14d,eax
	mov	edi,eax
	call	pool_hashes_source
	jnc	.settings
	mov	dword [g_cmp_hpeer],LSF_PEER	; (its address picks the server)
	jmp	.settings
.http:
	mov	rdi,r12
	call	compile_hosts			; g_cmp_hfirst/hcount
	mov	rdi,r12
	call	compile_routes			; g_cmp_rfirst/rcount: the default routes
.settings:
	; limits and timeouts
	mov	r15d,DEFAULT_CONNECTIONS
	mov	rdi,r12
	mov	ecx,DIR_LIMITS
	call	find_child
	test	rax,rax
	jz	@f
	mov	rdi,rax
	mov	ecx,DIR_CONNECTIONS
	call	find_child
	test	rax,rax
	jz	@f
	mov	rdi,rax
	call	node_decimal
	mov	r15d,eax
@@:
	; client address features
	mov	eax,[g_cmp_hpeer]
	mov	[g_cmp_flags],eax
	xor	eax,eax
	mov	[g_cmp_per_source],eax
	mov	rdi,r12
	mov	ecx,DIR_LIMITS
	call	find_child
	test	rax,rax
	jz	@f
	mov	rdi,rax
	mov	ecx,DIR_PER_SOURCE
	call	find_child
	test	rax,rax
	jz	@f
	mov	rdi,rax
	call	node_decimal
	mov	[g_cmp_per_source],eax
	or	dword [g_cmp_flags],LSF_PEER
@@:
	mov	rdi,r12
	mov	ecx,DIR_PROXY_PROTOCOL
	call	find_child
	test	rax,rax
	jz	@f
	mov	rax,[rax+N_ARGS]
	add	rax,A_SIZE			; the version
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	lea	rdx,[e_pp_version]
	call	list_index
	mov	ecx,LSF_PEER or LSF_PP_V1
	test	eax,eax
	jz	.pp
	mov	ecx,LSF_PEER or LSF_PP_V2
.pp:
	or	[g_cmp_flags],ecx
@@:
	mov	ebx,DEFAULT_IDLE_SECS
	lea	rax,[dir_table + D_SIZE*DIR_HTTP]
	cmp	[r12+N_DEF],rax
	jne	@f
	mov	ebx,DEFAULT_HTTP_IDLE_SECS	; keep-alive clients
@@:
	lea	rax,[dir_table + D_SIZE*DIR_UDP]
	cmp	[r12+N_DEF],rax
	jne	@f
	mov	ebx,DEFAULT_UDP_IDLE_SECS	; nothing tells a flow is over
@@:
	mov	rdi,r12
	call	compile_tls			; reads and checks the files
	mov	[g_cmp_tlsi],eax
	mov	rdi,r12				; `ktls on`: records in the kernel
	mov	ecx,DIR_TLS
	call	find_child
	test	rax,rax
	jz	@f
	mov	rdi,rax
	mov	ecx,DIR_KTLS
	call	find_child
	test	rax,rax
	jz	@f
	mov	rax,[rax+N_ARGS]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	lea	rdx,[e_onoff]
	call	list_index
	test	eax,eax
	jnz	@f
	or	dword [g_cmp_flags],LSF_KTLS
@@:
	mov	rdi,r12				; `client_ca`
	call	compile_client_ca
	mov	rdi,r12				; `http2 on`
	mov	ecx,DIR_HTTP2
	call	find_child
	test	rax,rax
	jz	@f
	mov	rax,[rax+N_ARGS]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	lea	rdx,[e_onoff]
	call	list_index
	test	eax,eax
	jnz	@f
	or	dword [g_cmp_flags],LSF_H2
@@:
	mov	rdi,r12				; `http3 on`
	mov	ecx,DIR_HTTP3
	call	find_child
	test	rax,rax
	jz	@f
	mov	rax,[rax+N_ARGS]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	lea	rdx,[e_h3]
	call	list_index
	cmp	eax,1
	je	@f				; off
	or	dword [g_cmp_flags],LSF_H3
	cmp	eax,3
	jne	.h3_not_v2
	or	dword [g_cmp_flags],LSF_H3V2
.h3_not_v2:
	cmp	eax,2
	jne	@f
	or	dword [g_cmp_flags],LSF_H3RETRY
@@:
	mov	rdi,r12				; early_data on: QUIC 0-RTT
	mov	ecx,DIR_EARLY
	call	find_child
	test	rax,rax
	jz	@f
	mov	rax,[rax+N_ARGS]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	lea	rdx,[e_onoff]
	call	list_index
	test	eax,eax
	jnz	@f
	or	dword [g_cmp_flags],LSF_0RTT
@@:
	; preferred_address: where a client may move to (QUIC); an IPv4 and an
	; IPv6 address at most
	lea	rdi,[g_cmp_pa4]
	mov	ecx,16 + 28
	xor	eax,eax
	rep	stosb
	mov	rdi,r12
	mov	ecx,DIR_PREFADDR
	call	find_child
	test	rax,rax
	jz	.pa_done
	mov	[g_cmp_pan],rax
	mov	dword [g_cmp_pai],0
.pa_next:
	mov	rax,[g_cmp_pan]
	mov	ecx,[g_cmp_pai]
	cmp	ecx,[rax+N_ARGC]
	jae	.pa_done
	inc	dword [g_cmp_pai]
	imul	rcx,rcx,A_SIZE
	add	rcx,[rax+N_ARGS]
	mov	rdi,[rcx+A_VAL]
	mov	esi,[rcx+A_VLEN]
	lea	rdx,[g_cmp_addr]
	xor	ecx,ecx
	call	parse_address
	jc	.pa_next
	cmp	dword [g_cmp_addr+AD_KIND],ADDR_ANY
	je	.pa_next			; (an address is needed)
	lea	rdi,[g_cmp_pasa]
	lea	rsi,[g_cmp_addr]
	call	sockaddr_build
	lea	rsi,[g_cmp_pasa]
	lea	rdi,[g_cmp_pa4]
	mov	ecx,16
	cmp	edx,AF_INET6
	jne	@f
	lea	rdi,[g_cmp_pa6]
	mov	ecx,28
@@:
	rep	movsb
	jmp	.pa_next
.pa_done:
	mov	dword [g_cmp_alog],0
	mov	rdi,r12
	mov	ecx,DIR_ACCESS_LOG
	call	find_child
	test	rax,rax
	jz	@f
	mov	rdi,rax
	call	alog_dest_node
	call	alog_dest_id
	mov	[g_cmp_alog],eax
@@:
	mov	rdi,r12				; the listener's error pages
	call	compile_errors
	mov	[g_cmp_efirst],eax
	mov	[g_cmp_ecount],edx
	mov	rdi,r12
	call	compile_maintenance
	mov	[g_cmp_maint],eax
	mov	dword [g_cmp_trace],0
	mov	rdi,r12
	mov	ecx,DIR_TRACING
	call	find_child
	test	rax,rax
	jz	@f
	mov	rdi,rax
	call	compile_tracing
	mov	[g_cmp_trace],eax
	mov	[g_cmp_tsample],edx
@@:
	; trusted_proxies
	mov	eax,[g_plan_trust]
	mov	[g_cmp_tfirst],eax
	mov	dword [g_cmp_tcount],0
	mov	rdi,r12
	mov	ecx,DIR_TRUSTED
	call	find_child
	test	rax,rax
	jz	.trust_done
	push	rbx
	push	r13
	mov	rbx,rax
	xor	r13d,r13d
.trust:
	cmp	r13d,[rbx+N_ARGC]
	jae	.trust_end
	imul	rax,r13,A_SIZE
	add	rax,[rbx+N_ARGS]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	inc	r13d
	call	trust_list			; a provider's, or a file's: each of them
	jnc	.trust
	call	trust_add			; (checked already)
	jmp	.trust
.trust_end:
	pop	r13
	pop	rbx
.trust_done:
	mov	dword [g_cmp_t_header],DEFAULT_HEADER_SECS
	mov	dword [g_cmp_t_response],DEFAULT_RESPONSE_SECS
	mov	dword [g_cmp_t_body],DEFAULT_BODY_SECS
	mov	rdi,r12
	mov	ecx,DIR_TIMEOUT
	call	find_child
	test	rax,rax
	jz	.addresses
	push	rax
	mov	rdi,rax
	mov	ecx,DIR_HEADER
	call	timeout_secs
	jc	@f
	mov	[g_cmp_t_header],eax
@@:
	mov	rdi,[rsp]
	mov	ecx,DIR_RESPONSE
	call	timeout_secs
	jc	@f
	mov	[g_cmp_t_response],eax
@@:
	mov	rdi,[rsp]
	mov	ecx,DIR_BODY_IDLE
	call	timeout_secs
	jc	@f
	mov	[g_cmp_t_body],eax
@@:
	pop	rdi
	mov	ecx,DIR_IDLE
	call	timeout_secs
	jc	.addresses
	mov	ebx,eax
.addresses:
	xor	r13d,r13d
.address:
	cmp	r13d,[r12+N_ARGC]
	jae	.done
	mov	ecx,[g_plan_listeners]
	cmp	ecx,MAX_LISTENERS
	jae	plan_too_many
	inc	dword [g_plan_listeners]
	imul	rcx,rcx,LS_SIZE
	lea	rcx,[g_listeners+rcx]
	mov	[rcx+LS_POOL],r14d
	mov	[rcx+LS_IDLE],ebx
	mov	eax,[g_cmp_t_header]
	mov	[rcx+LS_T_HEADER],eax
	mov	eax,[g_cmp_t_response]
	mov	[rcx+LS_T_RESPONSE],eax
	mov	eax,[g_cmp_t_body]
	mov	[rcx+LS_T_BODY],eax
	mov	eax,[g_cmp_alog]
	mov	[rcx+LS_ALOG],eax
	mov	eax,[g_cmp_trace]
	mov	[rcx+LS_TRACE],eax
	mov	eax,[g_cmp_efirst]
	mov	[rcx+LS_EFIRST],eax
	mov	eax,[g_cmp_ecount]
	mov	[rcx+LS_ECOUNT],eax
	mov	eax,[g_cmp_maint]
	mov	[rcx+LS_MAINT],eax
	mov	eax,[g_cmp_tsample]
	mov	[rcx+LS_TSAMPLE],eax
	mov	eax,[g_cmp_tlsi]
	mov	[rcx+LS_TLS],eax
	mov	eax,[g_cmp_pt]
	mov	[rcx+LS_PT],eax
	mov	eax,[g_cmp_tfirst]
	mov	[rcx+LS_TFIRST],eax
	mov	eax,[g_cmp_cca]
	mov	[rcx+LS_CCA],eax
	mov	eax,[g_cmp_tcount]
	mov	[rcx+LS_TCOUNT],eax
	push	rcx
	lea	rdi,[rcx+LS_PA4]
	lea	rsi,[g_cmp_pa4]
	mov	ecx,16 + 28
	rep	movsb
	pop	rcx
	mov	[rcx+LS_MAXCONN],r15d		; whole instance; split per worker later
	imul	rax,r13,A_SIZE
	add	rax,[r12+N_ARGS]
	mov	rdx,[rax+A_VAL]
	mov	[rcx+LS_TEXT],rdx
	mov	edx,[rax+A_VLEN]
	mov	[rcx+LS_TLEN],edx
	push	rcx
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	lea	rdx,[g_cmp_addr]
	xor	ecx,ecx
	call	parse_address
	pop	rdi
	push	rdi
	lea	rsi,[g_cmp_addr]
	call	sockaddr_build
	pop	rcx
	mov	[rcx+LS_SALEN],eax
	mov	[rcx+LS_FAMILY],edx
	cmp	dword [g_cmp_addr+AD_KIND],ADDR_ANY
	jne	@f
	mov	dword [rcx+LS_FAMILY],0		; dual stack
@@:
	mov	eax,[g_cmp_addr+AD_PORT]
	mov	[rcx+LS_PORT],eax
	mov	eax,[g_cmp_resp]
	mov	[rcx+LS_RESP],eax
	mov	eax,[g_cmp_flags]
	cmp	dword [g_cmp_addr+AD_KIND],ADDR_ANY
	je	.wild
	push	rcx
	lea	rdi,[g_cmp_addr+AD_IP]
	call	ip_is_unspecified
	pop	rcx
	jnc	@f
.wild:
	or	eax,LSF_WILDCARD
@@:
	mov	[rcx+LS_FLAGS],eax
	mov	eax,[g_cmp_per_source]
	mov	[rcx+LS_PER_SOURCE],eax
	xor	eax,eax
	lea	rdx,[dir_table + D_SIZE*DIR_HTTP]
	cmp	[r12+N_DEF],rdx
	jne	@f
	inc	eax
	or	dword [rcx+LS_FLAGS],LSF_PEER	; X-Forwarded-For needs the client
@@:
	lea	rdx,[dir_table + D_SIZE*DIR_UDP]
	cmp	[r12+N_DEF],rdx
	jne	@f
	mov	eax,LK_UDP
@@:
	mov	[rcx+LS_KIND],eax
	mov	eax,[g_cmp_rfirst]
	mov	[rcx+LS_RFIRST],eax
	mov	eax,[g_cmp_rcount]
	mov	[rcx+LS_RCOUNT],eax
	mov	eax,[g_cmp_hfirst]
	mov	[rcx+LS_HFIRST],eax
	mov	eax,[g_cmp_hcount]
	mov	[rcx+LS_HCOUNT],eax
	inc	r13d
	jmp	.address
.done:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; r12 = a listener: g_cmp_resp, from `responses`
compile_udp:
	mov	dword [g_cmp_resp],-1
	mov	rdi,r12
	mov	ecx,DIR_RESPONSES
	call	find_child
	test	rax,rax
	jz	.none
	mov	rax,[rax+N_ARGS]
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,9
	ja	plan_bad_responses
	xor	eax,eax
@@:
	movzx	edx,byte [rsi]
	inc	rsi
	sub	edx,'0'
	cmp	edx,9
	ja	plan_bad_responses
	imul	eax,eax,10
	add	eax,edx
	dec	ecx
	jnz	@b
	mov	[g_cmp_resp],eax
.none:
	ret

plan_bad_sticky:
	call	log_begin
	out_lit 'sticky takes cookie=NAME (a cookie name), and may take ttl= and samesite=lax|strict|none'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

cstring str_key_cookie, 'cookie',0
DISC_DEFAULT	:= 64
cstring str_key_max, 'max',0
cstring str_key_ttl, 'ttl',0
cstring str_key_samesite, 'samesite',0

; rdi = pool, rsi = a `discover` node: a source, and its slots
compile_discover:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r12,rdi
	mov	r13,rsi
	mov	ecx,[g_plan_groups]
	cmp	ecx,MAX_GROUPS
	jae	plan_too_many
	mov	edx,[g_plan_discs]
	cmp	edx,DISC_SOURCES
	jae	plan_too_many
	inc	dword [g_plan_discs]
	inc	dword [g_plan_groups]
	imul	rbx,rcx,GR_SIZE
	lea	rbx,[g_groups+rbx]
	mov	r14d,ecx			; the group
	mov	dword [rbx+GR_KIND],GK_FILE
	mov	[rbx+GR_DISC],edx
	mov	rax,[r13+N_ARGS]
	mov	rcx,[rax+A_VAL]
	cmp	byte [rcx],'d'			; `docker`
	je	.docker
	cmp	byte [rcx],'k'			; `kubernetes`
	je	.kube
	cmp	byte [rcx],'c'			; `consul`
	je	.consul
	cmp	byte [rcx],'s'			; `srv`
	jne	@f
	mov	dword [rbx+GR_KIND],GK_SRV
@@:
	cmp	dword [r13+N_ARGC],2
	jb	plan_bad_discover
	cmp	dword [rax+A_SIZE+A_KIND],ARG_KV
	je	plan_bad_discover		; (a path or a name, not key=value)
	add	rax,A_SIZE			; the path, or the name
	mov	rcx,[rax+A_VAL]
	mov	[rbx+GR_NAME],rcx
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,4096
	jae	plan_bad_discover
	mov	[rbx+GR_NLEN],ecx
	mov	rcx,[rbx+GR_NAME]
	mov	dword [rbx+GR_PORT],0
	cmp	dword [rbx+GR_KIND],GK_SRV
	jne	.file_path
	; a name: no trailing dot, at most 253, a port of its own in each record
	mov	edx,[rbx+GR_NLEN]
	cmp	edx,253
	ja	plan_bad_discover
	cmp	byte [rcx+rdx-1],'.'
	jne	@f
	dec	dword [rbx+GR_NLEN]
@@:
	mov	rdi,r13
	lea	rsi,[str_key_port]
	call	node_option
	test	rax,rax
	jnz	plan_bad_discover
	jmp	.max
.file_path:
	cmp	byte [rcx],'/'
	jne	plan_bad_discover		; a path from the root: the control process has no cwd of note
	jmp	.port
	; docker: the socket, the label, the network
.docker:
	mov	dword [rbx+GR_KIND],GK_DOCKER
	lea	rcx,[str_docker_sock]
	mov	[rbx+GR_NAME],rcx
	mov	dword [rbx+GR_NLEN],str_docker_sock.len
	mov	dword [rbx+GR_PORT],0
	mov	rdi,r13
	lea	rsi,[str_key_socket]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rcx,[rax+A_VAL]
	mov	edx,[rax+A_VLEN]
	cmp	edx,107
	ja	plan_bad_discover
	cmp	byte [rcx],'/'
	jne	plan_bad_discover
	mov	[rbx+GR_NAME],rcx
	mov	[rbx+GR_NLEN],edx
@@:
	mov	eax,[rbx+GR_DISC]
	imul	r10,rax,DK_SIZE
	lea	r10,[g_plan_dk+r10]
	mov	qword [r10+DK_NET],0
	mov	rdi,r13
	lea	rsi,[str_key_label]
	push	r10
	call	node_option
	pop	r10
	test	rax,rax
	jz	plan_bad_discover
	mov	rcx,[rax+A_VAL]
	mov	edx,[rax+A_VLEN]
	call	.printable
	mov	[r10+DK_LABEL],rcx
	mov	[r10+DK_LLEN],edx
	mov	rdi,r13
	lea	rsi,[str_key_network]
	push	r10
	call	node_option
	pop	r10
	test	rax,rax
	jz	.port
	mov	rcx,[rax+A_VAL]
	mov	edx,[rax+A_VLEN]
	call	.printable
	mov	[r10+DK_NET],rcx
	mov	[r10+DK_NLEN],edx
	jmp	.port
	; consul: the service, its datacenter and tag, the agent, the token
.consul:
	mov	dword [rbx+GR_KIND],GK_CONSUL
	mov	dword [rbx+GR_PORT],0
	mov	eax,[rbx+GR_DISC]
	imul	r10,rax,CS_SIZE
	lea	r10,[g_plan_cs+r10]
	mov	qword [r10+CS_DC],0
	mov	qword [r10+CS_TAG],0
	mov	qword [r10+CS_TOKEN],0
	mov	rdi,r13
	lea	rsi,[str_key_service]
	push	r10
	call	node_option
	pop	r10
	test	rax,rax
	jz	plan_bad_consul
	mov	rcx,[rax+A_VAL]
	mov	edx,[rax+A_VLEN]
	call	.printable
	mov	[r10+CS_SVC],rcx
	mov	[r10+CS_SVCLEN],edx
	mov	[rbx+GR_NAME],rcx		; (named by it in logs, slots and `okena backend`)
	mov	[rbx+GR_NLEN],edx
	mov	rdi,r13
	lea	rsi,[str_key_dc]
	push	r10
	call	node_option
	pop	r10
	test	rax,rax
	jz	@f
	mov	rcx,[rax+A_VAL]
	mov	edx,[rax+A_VLEN]
	call	.printable
	mov	[r10+CS_DC],rcx
	mov	[r10+CS_DCLEN],edx
@@:
	mov	rdi,r13
	lea	rsi,[str_key_tag]
	push	r10
	call	node_option
	pop	r10
	test	rax,rax
	jz	@f
	mov	rcx,[rax+A_VAL]
	mov	edx,[rax+A_VLEN]
	call	.printable
	mov	[r10+CS_TAG],rcx
	mov	[r10+CS_TAGLEN],edx
@@:
	mov	rdi,r13
	lea	rsi,[str_key_token]
	push	r10
	call	node_option
	pop	r10
	test	rax,rax
	jz	@f
	mov	rcx,[rax+A_VAL]
	mov	edx,[rax+A_VLEN]
	cmp	byte [rcx],'/'
	jne	plan_bad_consul
	cmp	edx,4096
	jae	plan_bad_consul
	mov	[r10+CS_TOKEN],rcx
	mov	[r10+CS_TOKLEN],edx
@@:
	; api=HOST:PORT, else the local agent
	lea	rdi,[str_consul_api]
	mov	esi,str_consul_api.len
	push	rdi
	push	rsi
	mov	rdi,r13
	lea	rsi,[str_key_api]
	push	r10
	call	node_option
	pop	r10
	pop	rsi
	pop	rdi
	test	rax,rax
	jz	@f
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
@@:
	push	r10
	lea	rdx,[g_cmp_addr]
	xor	ecx,ecx
	call	parse_address
	pop	r10
	jc	plan_bad_consul
	mov	eax,[g_cmp_addr+AD_KIND]
	cmp	eax,ADDR_V4
	je	@f
	cmp	eax,ADDR_V6
	jne	plan_bad_consul
@@:
	cmp	dword [g_cmp_addr+AD_PORT],0
	je	plan_bad_consul
	push	r10
	lea	rdi,[r10+CS_SA]
	lea	rsi,[g_cmp_addr]
	call	sockaddr_build
	pop	r10
	mov	[r10+CS_SALEN],eax
	jmp	.port
	; kubernetes: the service, the API, the credentials
.kube:
	mov	dword [rbx+GR_KIND],GK_KUBE
	mov	dword [rbx+GR_PORT],0
	mov	eax,[rbx+GR_DISC]
	imul	r10,rax,KB_SIZE
	lea	r10,[g_plan_kb+r10]
	mov	qword [r10+KB_PNAME],0
	mov	dword [r10+KB_PNLEN],0
	mov	dword [r10+KB_PNUM],0
	; service=NAMESPACE/NAME: DNS labels, lower case
	mov	rdi,r13
	lea	rsi,[str_key_service]
	push	r10
	call	node_option
	pop	r10
	test	rax,rax
	jz	plan_bad_kube
	mov	rcx,[rax+A_VAL]
	mov	edx,[rax+A_VLEN]
	xor	r8d,r8d
@@:
	cmp	r8d,edx
	jae	plan_bad_kube
	cmp	byte [rcx+r8],'/'
	je	@f
	inc	r8d
	jmp	@b
@@:
	test	r8d,r8d
	jz	plan_bad_kube
	mov	[r10+KB_NS],rcx
	mov	[r10+KB_NSLEN],r8d
	lea	r9,[rcx+r8+1]
	mov	[r10+KB_SVC],r9
	sub	edx,r8d
	dec	edx
	jz	plan_bad_kube
	mov	[r10+KB_SVCLEN],edx
	mov	[rbx+GR_NAME],rcx		; (named by it in logs, slots and `okena backend`)
	mov	eax,[rax+A_VLEN]
	mov	[rbx+GR_NLEN],eax
	mov	rcx,[r10+KB_NS]
	mov	edx,[r10+KB_NSLEN]
	call	.dns_label
	mov	rcx,[r10+KB_SVC]
	mov	edx,[r10+KB_SVCLEN]
	call	.dns_label
	; port=: a number, or a port's name
	mov	rdi,r13
	lea	rsi,[str_key_port]
	push	r10
	call	node_option
	pop	r10
	test	rax,rax
	jz	.kube_api
	mov	rcx,[rax+A_VAL]
	mov	edx,[rax+A_VLEN]
	movzx	r8d,byte [rcx]
	sub	r8d,'0'
	cmp	r8d,9
	ja	.port_name
	push	r10
	mov	rdi,rcx
	mov	esi,edx
	call	parse_decimal
	pop	r10
	test	eax,eax
	jz	plan_bad_kube
	cmp	eax,65535
	ja	plan_bad_kube
	mov	[r10+KB_PNUM],eax
	jmp	.kube_api
.port_name:
	call	.dns_label
	mov	[r10+KB_PNAME],rcx
	mov	[r10+KB_PNLEN],edx
.kube_api:
	call	kube_api_options
	jmp	.port
; rcx/edx = a DNS label: 1 to 63 of a-z, 0-9 and -, no - at an end
.dns_label:
	test	edx,edx
	jz	plan_bad_kube
	cmp	edx,63
	ja	plan_bad_kube
	cmp	byte [rcx],'-'
	je	plan_bad_kube
	cmp	byte [rcx+rdx-1],'-'
	je	plan_bad_kube
	xor	eax,eax
@@:
	movzx	r8d,byte [rcx+rax]
	cmp	r8d,'-'
	je	.label_ok
	sub	r8d,'0'
	cmp	r8d,9
	jbe	.label_ok
	movzx	r8d,byte [rcx+rax]
	sub	r8d,'a'
	cmp	r8d,25
	ja	plan_bad_kube
.label_ok:
	inc	eax
	cmp	eax,edx
	jb	@b
	ret
; rcx/edx = a label or a network name: 1 to 200 printable bytes, no quote
; nor backslash (it goes into a URL, and is compared with JSON as it is)
.printable:
	test	edx,edx
	jz	plan_bad_discover
	cmp	edx,200
	ja	plan_bad_discover
	xor	eax,eax
@@:
	movzx	r8d,byte [rcx+rax]
	cmp	r8d,'!'
	jb	plan_bad_discover
	cmp	r8d,'~'
	ja	plan_bad_discover
	cmp	r8d,'"'
	je	plan_bad_discover
	cmp	r8d,'\'
	je	plan_bad_discover
	inc	eax
	cmp	eax,edx
	jb	@b
	ret
.port:
	cmp	dword [rbx+GR_KIND],GK_KUBE
	je	.max				; (its port= was read with the rest)
	mov	rdi,r13
	lea	rsi,[str_key_port]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_decimal
	test	eax,eax
	jz	plan_bad_discover
	cmp	eax,65535
	ja	plan_bad_discover
	mov	[rbx+GR_PORT],eax
@@:
.max:
	; share=N: the source's servers have N between them, however many they are
	mov	eax,[rbx+GR_DISC]
	mov	dword [g_plan_dshare+rax*4],0
	mov	rdi,r13
	lea	rsi,[str_key_share]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_decimal
	test	eax,eax
	jz	plan_bad_discover
	cmp	eax,1000000
	ja	plan_bad_discover
	mov	ecx,[rbx+GR_DISC]
	mov	[g_plan_dshare+rcx*4],eax
@@:
	mov	dword [rbx+GR_SLOTS],DISC_DEFAULT
	mov	rdi,r13
	lea	rsi,[str_key_max]
	call	node_option
	test	rax,rax
	jz	@f
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	call	parse_decimal
	cmp	eax,DISC_MAX
	ja	plan_bad_discover
	mov	[rbx+GR_SLOTS],eax
@@:
	mov	eax,[g_plan_servers]
	mov	[rbx+GR_FIRST],eax
	mov	r8d,[rbx+GR_SLOTS]
.slot:
	mov	edx,[g_plan_servers]
	cmp	edx,MAX_SERVERS
	jae	plan_too_many
	inc	dword [g_plan_servers]
	inc	dword [r12+PL_COUNT]
	imul	rdx,rdx,SV_SIZE
	lea	rdx,[g_servers+rdx]
	mov	dword [rdx+SV_WEIGHT],1
	mov	rax,[rbx+GR_NAME]
	mov	[rdx+SV_TEXT],rax
	mov	eax,[rbx+GR_NLEN]
	mov	[rdx+SV_TLEN],eax
	lea	eax,[r14+1]
	mov	[rdx+SV_GROUP],eax
	mov	dword [rdx+SV_ACTIVE],0
	dec	r8d
	jnz	.slot
	inc	dword [r12+PL_PRIMARY]
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; r13 = a node, r10 = a KB block: api=, name=, token=, ca= into it (as a pod has
; them when not said). Keeps r10, r13.
kube_api_options:
	; api=HOST:PORT, else the pod's KUBERNETES_SERVICE_HOST and _PORT
	mov	rdi,r13
	lea	rsi,[str_key_api]
	push	r10
	call	node_option
	pop	r10
	test	rax,rax
	jz	.api_env
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	jmp	.api_parse
.api_env:
	push	r10
	lea	rdi,[str_env_kube_host]
	mov	esi,str_env_kube_host.len
	call	getenv
	pop	r10
	test	rax,rax
	jz	plan_no_kube_api
	lea	rdi,[g_trust_path]		; (a scratch: "[host]:port")
	mov	rsi,rax
	xor	r8d,r8d				; a colon: IPv6
	xor	ecx,ecx
@@:
	mov	dl,[rsi+rcx]
	test	dl,dl
	jz	@f
	cmp	dl,':'
	sete	r9b
	or	r8b,r9b
	inc	ecx
	cmp	ecx,64
	ja	plan_no_kube_api
	jmp	@b
@@:
	test	r8b,r8b
	jz	@f
	mov	byte [rdi],'['
	inc	rdi
@@:
	rep	movsb
	test	r8b,r8b
	jz	@f
	mov	byte [rdi],']'
	inc	rdi
@@:
	mov	byte [rdi],':'
	inc	rdi
	push	rdi
	push	r10
	lea	rdi,[str_env_kube_port]
	mov	esi,str_env_kube_port.len
	call	getenv
	pop	r10
	pop	rdi
	lea	rsi,[str_kube_443]
	test	rax,rax
	cmovnz	rsi,rax
@@:
	mov	dl,[rsi]
	test	dl,dl
	jz	@f
	mov	[rdi],dl
	inc	rsi
	inc	rdi
	jmp	@b
@@:
	lea	rsi,[g_trust_path]
	sub	rdi,rsi
	mov	esi,edi
	lea	rdi,[g_trust_path]
.api_parse:
	push	r10
	lea	rdx,[g_cmp_addr]
	xor	ecx,ecx
	call	parse_address
	pop	r10
	jc	plan_bad_kube
	mov	eax,[g_cmp_addr+AD_KIND]
	cmp	eax,ADDR_V4
	je	@f
	cmp	eax,ADDR_V6
	jne	plan_bad_kube
@@:
	push	r10
	lea	rdi,[r10+KB_SA]
	lea	rsi,[g_cmp_addr]
	call	sockaddr_build
	pop	r10
	mov	[r10+KB_SALEN],eax
	; the name its certificate must have
	lea	rcx,[str_kb_sni]
	mov	[r10+KB_SNI],rcx
	mov	dword [r10+KB_SNILEN],str_kb_sni.len
	mov	rdi,r13
	lea	rsi,[str_key_name]
	push	r10
	call	node_option
	pop	r10
	test	rax,rax
	jz	@f
	mov	rcx,[rax+A_VAL]
	mov	edx,[rax+A_VLEN]
	call	compile_discover.printable
	mov	[r10+KB_SNI],rcx
	mov	[r10+KB_SNILEN],edx
@@:
	; the token's path
	lea	rcx,[str_kb_token]
	mov	[r10+KB_TOKEN],rcx
	mov	dword [r10+KB_TOKLEN],str_kb_token.len
	mov	rdi,r13
	lea	rsi,[str_key_token]
	push	r10
	call	node_option
	pop	r10
	test	rax,rax
	jz	@f
	mov	rcx,[rax+A_VAL]
	mov	edx,[rax+A_VLEN]
	cmp	byte [rcx],'/'
	jne	plan_bad_kube
	cmp	edx,4096
	jae	plan_bad_kube
	mov	[r10+KB_TOKEN],rcx
	mov	[r10+KB_TOKLEN],edx
@@:
	; the CA, read now: its key is the anchor
	lea	rsi,[str_kb_ca]
	mov	ecx,str_kb_ca.len
	mov	rdi,r13
	push	rsi
	push	rcx
	push	r10
	lea	rsi,[str_key_ca]
	call	node_option
	pop	r10
	pop	rcx
	pop	rsi
	test	rax,rax
	jz	@f
	mov	rsi,[rax+A_VAL]
	mov	ecx,[rax+A_VLEN]
	cmp	ecx,4096
	jae	plan_bad_kube
@@:
	lea	rdi,[g_trust_path]
	push	rcx
	rep	movsb
	pop	rcx
	mov	byte [g_trust_path+rcx],0
	push	r10
	lea	rdi,[g_trust_path]
	lea	rsi,[g_ar_text]
	call	read_file
	test	rax,rax
	js	plan_kube_ca
	mov	rsi,rax
	mov	edx,edx
	lea	rdi,[g_trust_der]
	call	pem_first_cert
	test	eax,eax
	jz	plan_kube_ca
	mov	r10,[rsp]
	lea	rsi,[g_trust_der]
	mov	edx,eax
	lea	rdi,[r10+KB_ANCHOR]
	call	cert_pubkey
	test	eax,eax
	jz	plan_kube_ca
	pop	r10
	ret

plan_bad_consul:
	call	log_begin
	out_lit 'discover consul takes service=NAME, and may take dc=, tag=, token=/PATH, api=HOST:PORT (an IP address and a port; 127.0.0.1:8500 when not said), port=N (for instances that registered none) and max='
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process
cstring str_key_dc, 'dc',0
cstring str_key_share, 'share',0
cstring str_key_tag, 'tag',0
cstring str_consul_api, '127.0.0.1:8500'

plan_bad_kube:
	call	log_begin
	out_lit 'discover kubernetes takes service=NAMESPACE/NAME (DNS labels), and may take port=NAME|N, api=HOST:PORT (an IP address), token=/PATH, ca=PATH, name=HOST and max='
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

plan_no_kube_api:
	call	log_begin
	out_lit 'discover kubernetes: not in a pod (no KUBERNETES_SERVICE_HOST): give api=HOST:PORT'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

plan_kube_ca:
	call	log_begin
	out_lit 'discover kubernetes: its CA (ca=, or the service account'
	out_lit "'s ca.crt) cannot be read as a certificate"
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

cstring str_key_service, 'service',0
cstring str_key_api, 'api',0
cstring str_key_token, 'token',0
cstring str_key_ca, 'ca',0
cstring str_key_name, 'name',0
cstring str_env_kube_host, 'KUBERNETES_SERVICE_HOST='
cstring str_env_kube_port, 'KUBERNETES_SERVICE_PORT='
cstring str_kube_443, '443',0

plan_bad_discover:
	call	log_begin
	out_lit 'discover file takes a path from / and may take port= (1..65535) and max= (1..256); discover srv takes a full name and max=; discover docker takes label=, and may take port=, network=, socket=/PATH and max='
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

cstring str_key_port, 'port',0
cstring str_key_label, 'label',0
cstring str_key_network, 'network',0
cstring str_key_socket, 'socket',0
cstring str_docker_sock, '/var/run/docker.sock'

plan_bad_bound:
	call	log_begin
	out_lit 'balance bound= is for maglev and ring-hash: a server at most this share of the mean load, 101% to 1000%'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

cstring str_key_bound, 'bound',0

plan_bad_key:
	call	log_begin
	out_lit 'balance key= is for maglev and ring-hash: source, path, header:NAME, cookie:NAME or query:NAME'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

cstring str_key_key, 'key',0

plan_bad_responses:
	call	log_begin
	out_lit 'responses takes how many answers a flow gets: a number, 0 for none'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; rdi = 16 address bytes (IPv4 in the first 4). CF when all zero.
; Keeps rax.
ip_is_unspecified:
	mov	rdx,[rdi]
	or	rdx,[rdi+8]
	jnz	.no
	stc
	ret
.no:
	clc
	ret

; rdi = node with a `to` child (tcp listener or route). eax = its pool:
; a named one, or a new anonymous pool for `to ADDR...`.
compile_target:
	push	rbx
	push	r12
	push	r13
	push	r15
	mov	r12,rdi
	mov	ecx,DIR_TO
	call	find_child
	mov	rbx,rax
	mov	r13,[rbx+N_ARGS]
	mov	rdi,[r13+A_VAL]
	mov	esi,[r13+A_VLEN]
	lea	rdx,[str_word_pool]
	call	mem_eq_cstr
	test	eax,eax
	jz	.inline
	add	r13,A_SIZE
	mov	rdi,[r13+A_VAL]
	mov	esi,[r13+A_VLEN]
	call	plan_pool_index
	jmp	.out
.inline:
	; the same addresses as an earlier inline target: the same pool, so
	; routes to one backend share its warm connections and its load
	call	inline_pool_find
	cmp	eax,-1
	jne	.out
	xor	edi,edi
	xor	esi,esi
	call	pool_new
	push	rcx
	mov	r15,rax
	xor	ecx,ecx
.inline_server:
	cmp	ecx,[rbx+N_ARGC]
	jae	.inline_done
	push	rcx
	imul	rdi,rcx,A_SIZE
	add	rdi,[rbx+N_ARGS]
	mov	rsi,r15
	call	server_new
	inc	dword [r15+PL_PRIMARY]
	pop	rcx
	inc	ecx
	jmp	.inline_server
.inline_done:
	pop	rax
.out:
	pop	r15
	pop	r13
	pop	r12
	pop	rbx
	ret

; rbx = `to` node with addresses. eax = an inline pool (no name) with
; exactly these addresses in this order, or -1.
inline_pool_find:
	push	r12
	push	r13
	xor	r12d,r12d
.pool:
	cmp	r12d,[g_plan_pools]
	jae	.none
	imul	r13,r12,PL_SIZE
	lea	r13,[g_pools+r13]
	cmp	qword [r13+PL_NAME],0
	jne	.next
	mov	eax,[r13+PL_COUNT]
	cmp	eax,[rbx+N_ARGC]
	jne	.next
	xor	ecx,ecx
.server:
	cmp	ecx,[rbx+N_ARGC]
	jae	.found
	mov	eax,[r13+PL_FIRST]
	add	eax,ecx
	imul	rax,rax,SV_SIZE
	lea	r8,[g_servers+rax]
	imul	rax,rcx,A_SIZE
	add	rax,[rbx+N_ARGS]
	mov	edx,[rax+A_VLEN]
	cmp	edx,[r8+SV_TLEN]
	jne	.next
	mov	rsi,[rax+A_VAL]
	mov	rdi,[r8+SV_TEXT]
	push	rcx
	xor	r9d,r9d
@@:
	cmp	r9d,edx
	jae	@f
	mov	al,[rsi+r9]
	cmp	al,[rdi+r9]
	jne	.differ
	inc	r9d
	jmp	@b
@@:
	pop	rcx
	inc	ecx
	jmp	.server
.differ:
	pop	rcx
.next:
	inc	r12d
	jmp	.pool
.found:
	mov	eax,r12d
	jmp	.out
.none:
	mov	eax,-1
.out:
	pop	r13
	pop	r12
	ret

; rdi = http node: a host entry per name of each host block, with that
; block's routes. g_cmp_hfirst/hcount = the range.
compile_hosts:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r12,rdi
	mov	eax,[g_plan_hosts]
	mov	[g_cmp_hfirst],eax
	mov	dword [g_cmp_hcount],0
	mov	rbx,[r12+N_CHILD]
.block:
	test	rbx,rbx
	jz	.done
	lea	rax,[dir_table + D_SIZE*DIR_HOST]
	cmp	[rbx+N_DEF],rax
	jne	.next
	mov	rdi,rbx
	call	compile_routes
	xor	r13d,r13d
.name:
	cmp	r13d,[rbx+N_ARGC]
	jae	.next
	mov	ecx,[g_plan_hosts]
	cmp	ecx,MAX_HOSTS
	jae	plan_too_many
	inc	dword [g_plan_hosts]
	inc	dword [g_cmp_hcount]
	imul	r14,rcx,HO_SIZE
	lea	r14,[g_hosts+r14]
	imul	rax,r13,A_SIZE
	add	rax,[rbx+N_ARGS]
	mov	rdi,[rax+A_VAL]
	mov	esi,[rax+A_VLEN]
	mov	dword [r14+HO_WILD],0
	cmp	esi,2
	jb	@f
	cmp	word [rdi],'*.'
	jne	@f
	inc	rdi				; keep the dot: ".example.com"
	dec	esi
	mov	dword [r14+HO_WILD],1
@@:
	mov	[r14+HO_NAME],rdi
	mov	[r14+HO_NLEN],esi
	; into the lookup table
	push	rcx
	mov	edx,esi
	mov	rsi,rdi
	mov	edi,[g_cmp_hfirst]
	mov	ecx,[r14+HO_WILD]
	call	host_hash
	pop	rcx
	mov	edx,HHASH_SIZE - 1
	mov	r8d,eax
.probe:
	and	r8d,edx
	cmp	qword [g_hhash+r8*8],0
	je	.slot
	inc	r8d
	jmp	.probe
.slot:
	lea	r9d,[rcx+1]
	shl	r9,32
	or	r9,rax
	mov	[g_hhash+r8*8],r9
	mov	eax,[g_cmp_rfirst]
	mov	[r14+HO_RFIRST],eax
	mov	eax,[g_cmp_rcount]
	mov	[r14+HO_RCOUNT],eax
	inc	r13d
	jmp	.name
.next:
	mov	rbx,[rbx+N_NEXT]
	jmp	.block
.done:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi = http node: one route entry per path of each route.
; g_cmp_rfirst/rcount = its range.
compile_routes:
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12,rdi
	mov	eax,[g_plan_routes]
	mov	[g_cmp_rfirst],eax
	mov	dword [g_cmp_rcount],0
	mov	rbx,[r12+N_CHILD]
.route:
	test	rbx,rbx
	jz	.done
	lea	rax,[dir_table + D_SIZE*DIR_ROUTE]
	cmp	[rbx+N_DEF],rax
	jne	.next
	mov	r13d,-1				; a redirect has no pool, nor files
	mov	rdi,rbx
	mov	ecx,DIR_REDIRECT
	call	find_child
	test	rax,rax
	jnz	@f
	mov	rdi,rbx
	mov	ecx,DIR_RESPOND
	call	find_child
	test	rax,rax
	jnz	@f
	mov	rdi,rbx
	mov	ecx,DIR_FILES
	call	find_child
	test	rax,rax
	jnz	@f
	mov	rdi,rbx
	mov	ecx,DIR_SPLIT
	call	find_child
	test	rax,rax
	jnz	@f				; (its first pool: below)
	mov	rdi,rbx
	call	compile_target
	mov	r13d,eax			; pool
@@:
	mov	rdi,rbx
	call	compile_route_action
	mov	[g_cmp_act],eax
	test	eax,eax
	jz	.route_pool
	dec	eax
	imul	rax,rax,RA_SIZE
	mov	eax,[g_acts+rax+RA_SPLIT]
	test	eax,eax
	jz	.route_pool
	dec	eax
	imul	rax,rax,SL_SIZE
	cmp	r13d,-1
	jne	.route_pool
	mov	r13d,[g_splits+rax+SL_P]
.route_pool:
	call	compile_matches
	mov	rdi,rbx
	call	route_methods
	mov	r14d,eax
	xor	r15d,r15d
.arg:
	cmp	r15d,[rbx+N_ARGC]
	jae	.next
	imul	rsi,r15,A_SIZE
	add	rsi,[rbx+N_ARGS]
	mov	rdi,[rsi+A_VAL]
	cmp	byte [rdi],'~'
	je	.regex
	cmp	byte [rdi],'/'
	jne	.arg_next
	mov	ecx,[g_plan_routes]
	cmp	ecx,MAX_ROUTES
	jae	plan_too_many
	inc	dword [g_plan_routes]
	inc	dword [g_cmp_rcount]
	imul	rcx,rcx,RT_SIZE
	lea	rcx,[g_routes+rcx]
	mov	[rcx+RT_PATH],rdi
	mov	eax,[rsi+A_VLEN]
	mov	dword [rcx+RT_PREFIX],0
	cmp	byte [rdi+rax-1],'*'
	jne	@f
	dec	eax				; "/api/*" matches what starts with "/api/"
	mov	dword [rcx+RT_PREFIX],1
@@:
	mov	[rcx+RT_PLEN],eax
	mov	[rcx+RT_METHODS],r14d
	mov	[rcx+RT_POOL],r13d
	mov	eax,[g_cmp_act]
	mov	[rcx+RT_ACT],eax
	push	rsi
	push	rdi
	call	match_entries
	mov	edx,[g_plan_routes]
	dec	edx
	call	route_insert
	pop	rdi
	pop	rsi
.arg_next:
	inc	r15d
	jmp	.arg
.regex:
	; ~REGEX: a route the path is matched against, in the order written, when
	; no exact path is (regex.inc); not in the table of paths
	push	rsi
	push	rdi
	inc	rdi
	mov	ecx,[rsi+A_VLEN]
	dec	ecx
	mov	rsi,rdi
	call	rx_compile_or_exit
	pop	rdi
	pop	rsi
	mov	ecx,[g_plan_routes]
	cmp	ecx,MAX_ROUTES
	jae	plan_too_many
	inc	dword [g_plan_routes]
	inc	dword [g_cmp_rcount]
	inc	dword [g_plan_rxroutes]
	imul	rcx,rcx,RT_SIZE
	lea	rcx,[g_routes+rcx]
	mov	[rcx+RT_PATH],rdi		; (its text, ~ and all, for what shows it)
	shl	eax,8
	or	eax,2				; a regex: 2 | which << 8
	mov	[rcx+RT_PREFIX],eax
	mov	eax,[rsi+A_VLEN]
	mov	[rcx+RT_PLEN],eax
	mov	[rcx+RT_METHODS],r14d
	mov	[rcx+RT_POOL],r13d
	mov	eax,[g_cmp_act]
	mov	[rcx+RT_ACT],eax
	push	rsi
	push	rdi
	call	match_entries
	pop	rdi
	pop	rsi
	jmp	.arg_next
.next:
	mov	rbx,[rbx+N_NEXT]
	jmp	.route
.done:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi/esi = pool name. eax = index (the checker made sure it exists).
plan_pool_index:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	mov	r13d,esi
	xor	ebx,ebx
.next:
	cmp	ebx,[g_plan_pools]
	jae	.none
	imul	rax,rbx,PL_SIZE
	lea	rax,[g_pools+rax]
	cmp	[rax+PL_NLEN],r13d
	jne	.skip
	mov	rdi,[rax+PL_NAME]
	mov	rsi,r12
	mov	edx,r13d
	call	mem_eq
	test	eax,eax
	jnz	.found
.skip:
	inc	ebx
	jmp	.next
.found:
	mov	eax,ebx
	jmp	.out
.none:
	mov	eax,-1
.out:
	pop	r13
	pop	r12
	pop	rbx
	ret
