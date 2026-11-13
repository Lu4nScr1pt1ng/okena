; Configuration schema: which directives exist, where, and what they take.
;
; One table drives the checker. An entry says in which contexts the
; directive may appear, what its block contains, how many positional
; arguments it takes and of which type, and which key=value options it
; accepts. A directive with options and F_KEYS_BLOCK may also be written
; as a block with the same keys: `connect timeout=1s` = `connect { timeout 1s }`.

; Contexts (a directive's block opens one of these)
CTX_TOP		:= 1
CTX_OKENA	:= 2
CTX_TCP		:= 3
CTX_POOL	:= 4
CTX_LIMITS	:= 5
CTX_TIMEOUT	:= 6
CTX_HTTP	:= 7
CTX_ROUTE	:= 8
CTX_HOST	:= 9
CTX_TLS		:= 10
CTX_AUTH	:= 11
CTX_UDP		:= 12
CTX_ALERTS	:= 13
CTX_ADDON	:= 14

; Flags
F_BLOCK_REQ	:= 1		; must have a block
F_UNIQUE	:= 2		; at most once per block
F_KEYS_BLOCK	:= 4		; options may be written as a block
F_FREE_KEYS	:= 8		; its name=value have names of its own (`split`)

; Value types. Values of 4096 and above are pointers to enum lists.
T_NONE		:= 0
T_ANY		:= 1
T_NAME		:= 2
T_UINT		:= 3		; 0 .. 2^31
T_COUNT		:= 4		; 1 .. 100 000 000
T_WEIGHT	:= 5		; 1 .. 1000
T_DURATION	:= 6
T_SIZE		:= 7
T_RATE		:= 8
T_PERCENT	:= 9
T_LISTEN	:= 10		; listen address
T_BACKEND	:= 11		; backend address (names and unix paths too)
T_WORKERS	:= 12		; auto or 1 .. 1024 (MAX_WORKERS)
T_TARGET	:= 13		; `to pool NAME` or `to ADDR...`
T_FUTURE	:= 14		; an option of the language not implemented yet
T_HOSTNAME	:= 16		; a host name, or *.example.com
T_ROUTE		:= 15		; a path ("/x", "/x/*", "/*") or a method (GET, POST...)
T_LOGDEST	:= 17		; stdout, stderr, off, an absolute file path, or a syslog or OTLP URL
T_CIDR		:= 18		; an IP address or a range: 10.0.0.0/8, 2001:db8::/32
T_STATUSES	:= 19		; an HTTP status or a range: 200, 200..299
T_DURAUTO	:= 20		; `auto` or a duration
T_COUNTAUTO	:= 21		; `auto` or a count (1 .. 100 000 000)

; Directive entry
D_NAME		:= 0		; 24 bytes, NUL-padded
D_CTX		:= 24		; d: mask of contexts (1 shl CTX_*)
D_CHILD		:= 28		; d: context of its block, 0 = none
D_FLAGS		:= 32		; d
D_MINP		:= 36		; w
D_MAXP		:= 38		; w
D_TYPE1		:= 40		; q: type of the first positional argument
D_TYPEN		:= 48		; q: type of the others
D_KEYS		:= 56		; q: options table or 0
D_SIZE		:= 64

; Option entry
K_NAME		:= 0		; 24 bytes
K_TYPE		:= 24		; q
K_SIZE		:= 32

macro enumdef label*, items&
	rodata
		align 8
		label:
		iterate item, items
			db item,0
		end iterate
		db 0
	end rodata
end macro

macro keysdef label*, pairs&
	rodata
		align 8
		label:
		iterate <kname,ktype>, pairs
			db kname
			db (24 - lengthof kname) dup 0
			dq ktype
		end iterate
		dq 0,0,0,0
	end rodata
end macro

DIR_COUNT = 0

; id becomes the entry's index, for code that looks for one directive.
macro dirdef id*, name*, ctxmask*, child*, flags*, minp*, maxp*, type1*, typen*, keys*
	id = DIR_COUNT
	DIR_COUNT = DIR_COUNT + 1
	rodata
		db name
		db (24 - lengthof name) dup 0
		dd ctxmask, child, flags
		dw minp, maxp
		dq type1, typen, keys
	end rodata
end macro

M_TOP		:= 1 shl CTX_TOP
M_OKENA		:= 1 shl CTX_OKENA
M_TCP		:= 1 shl CTX_TCP
M_POOL		:= 1 shl CTX_POOL
M_LIMITS	:= 1 shl CTX_LIMITS
M_TIMEOUT	:= 1 shl CTX_TIMEOUT
M_HTTP		:= 1 shl CTX_HTTP
M_ROUTE		:= 1 shl CTX_ROUTE
M_HOST		:= 1 shl CTX_HOST
M_TLS		:= 1 shl CTX_TLS
M_AUTH		:= 1 shl CTX_AUTH
M_UDP		:= 1 shl CTX_UDP
M_ALERTS	:= 1 shl CTX_ALERTS
M_ADDON		:= 1 shl CTX_ADDON

enumdef e_io_engine, 'auto', 'io_uring', 'epoll'
enumdef e_samesite, 'lax', 'strict', 'none'
enumdef e_balance, 'round-robin', 'least-conn', 'random', 'least-request', 'peak-ewma', 'maglev', 'ring-hash', 'source-hash', 'first'
enumdef e_server_flags, 'backup'
enumdef e_health, 'tcp', 'http', 'grpc'
enumdef e_pp_mode, 'send'
enumdef e_listen_mode, 'xdp'
enumdef e_redirect_codes, '301', '302', '303', '307', '308'
keysdef k_respond, 'type', T_ANY
enumdef e_header_ops, 'set', 'add', 'drop'
enumdef e_response_what, 'header'
enumdef e_rewrite_what, 'path'
enumdef e_pp_version, 'v1', 'v2'
enumdef e_tls_mode, 'passthrough'
enumdef e_onoff, 'on', 'off'
enumdef e_pin, 'on', 'off', 'auto'
enumdef e_retry_mode, 'idempotent-only'
enumdef e_cors_flags, 'credentials'
enumdef e_auth, 'api_key', 'basic', 'jwt', 'mtls', 'forward'
enumdef e_cca, 'required', 'optional'
enumdef e_priority, 'normal', 'critical', 'bulk'
enumdef e_mirror_what, 'pool'
enumdef e_quic_cc, 'cubic', 'bbr'
enumdef e_h3, 'on', 'off', 'retry', 'v2'
enumdef e_tlsver, '1.2', '1.3'
enumdef e_reload, 'on-change', 'signal'
enumdef e_profile, 'balanced', 'latency', 'throughput', 'memory-lean'
enumdef e_alpn, 'h2', 'http/1.1'
enumdef e_proto, 'h1', 'h2', 'fastcgi'

keysdef k_alog, 'trust', T_ANY
keysdef k_errors, 'file', T_ANY
keysdef k_maint, 'file', T_ANY, 'retry', T_DURATION, 'allow', T_ANY, 'except', T_ANY
keysdef k_metrics, 'token', T_ANY
keysdef k_cdnloop, 'max', T_ANY
keysdef k_bird, 'protocol', T_ANY, 'pool', T_ANY
keysdef k_gateway, 'class', T_ANY, 'dir', T_ANY, 'api', T_ANY, 'token', T_ANY, 'ca', T_ANY, 'name', T_ANY
enumdef e_gateway, 'kubernetes'
keysdef k_acme, 'ca', T_ANY, 'email', T_ANY, 'trust', T_ANY, 'challenge', T_ANY, 'dns', T_ANY, 'dns_token', T_ANY, 'dns_api', T_ANY, 'dns_wait', T_DURATION, 'dns_trust', T_ANY, 'dns_server', T_ANY, 'dns_key', T_ANY, 'fallback', T_ANY, 'fallback_trust', T_ANY, 'eab', T_ANY, 'fallback_eab', T_ANY, 'shared', T_ANY, 'staging', T_ANY
keysdef k_vrrp, 'vrid', T_ANY, 'priority', T_ANY, 'address', T_ANY, 'advert', T_DURATION, 'preempt', T_ANY, 'track', T_ANY
keysdef k_cdisk, 'size', T_SIZE
keysdef k_tracing, 'sample', T_PERCENT, 'trust', T_ANY
keysdef k_drain, 'delay', T_DURATION, 'timeout', T_DURATION
keysdef k_signed, 'key', T_ANY, 'key2', T_ANY
keysdef k_hs_budget, 'wait', T_DURATION
keysdef k_auth, 'header', T_ANY, 'keys', T_ANY, 'users', T_ANY, 'realm', T_ANY, 'identity', T_ANY, 'forward', T_ANY, 'pool', T_ANY, 'path', T_ANY, 'copy', T_ANY, 'cache', T_DURATION, 'timeout', T_DURATION
keysdef k_hedge, 'after', T_ANY, 'max', T_COUNT
keysdef k_cors, 'origins', T_ANY, 'methods', T_ANY, 'headers', T_ANY, 'expose', T_ANY, 'max_age', T_DURATION
keysdef k_jwks, 'trust', T_ANY, 'refresh', T_DURATION, 'stale', T_DURATION
keysdef k_cache, 'stale-while-revalidate', T_DURATION, 'vary', T_ANY, 'max', T_SIZE, 'shared', T_ANY, 'stale-if-error', T_DURATION, 'query', T_ANY, 'host', T_ANY, 'slice', T_SIZE
keysdef k_files, 'index', T_ANY, 'fallback', T_ANY, 'precompressed', T_ANY, 'cache', T_ANY
keysdef k_php, 'index', T_ANY
keysdef k_compress, 'min', T_SIZE
keysdef k_headers, 'preset', T_ANY
keysdef k_rmap, 'code', T_ANY
keysdef k_idem, 'header', T_ANY, 'ttl', T_DURATION, 'lock', T_DURATION
keysdef k_limit, 'burst', T_COUNT, 'key', T_ANY, 'instances', T_COUNT
keysdef k_fault, 'abort', T_COUNT, 'percent', T_COUNT, 'delay', T_DURATION
keysdef k_quic_sid, 'key', T_ANY, 'rotation', T_ANY
keysdef k_server, 'weight', T_WEIGHT, 'max', T_COUNT
keysdef k_queue, 'timeout', T_DURATION
keysdef k_retry, 'on', T_ANY
keysdef k_rtimeout, 'total', T_DURATION, 'try', T_DURATION
keysdef k_outlier, 'errors', T_UINT, 'eject', T_DURATION, 'max_ejected', T_PERCENT
keysdef k_rbudget, 'min', T_RATE
keysdef k_concurrency, 'min', T_COUNT, 'max', T_COUNT
keysdef k_alert, 'trust', T_ANY
keysdef k_telegram, 'token', T_ANY, 'chat', T_ANY, 'api', T_ANY, 'trust', T_ANY
enumdef e_alert_on, 'backend', 'worker', 'reload', 'discovery', 'certificate'
keysdef k_discover, 'port', T_ANY, 'max', T_COUNT, 'label', T_ANY, 'network', T_ANY, 'socket', T_ANY, \
	'service', T_ANY, 'api', T_ANY, 'token', T_ANY, 'ca', T_ANY, 'name', T_ANY, 'dc', T_ANY, 'tag', T_ANY, \
	'share', T_COUNT
enumdef e_discover, 'file', 'srv', 'docker', 'kubernetes', 'consul'
keysdef k_balance, 'key', T_ANY, 'bound', T_ANY
keysdef k_sticky, 'cookie', T_ANY, 'ttl', T_DURATION, 'samesite', T_ANY
keysdef k_cert, 'key', T_ANY
keysdef k_odemand, 'ask', T_ANY, 'max', T_ANY
keysdef k_cca, 'crl', T_ANY
keysdef k_mode, 'encap', T_ANY, 'port', T_UINT
keysdef k_synrate, 'burst', T_COUNT
keysdef k_health, 'every', T_DURATION, 'timeout', T_DURATION, 'rise', T_COUNT, 'fall', T_COUNT, \
	'expect', T_STATUSES, 'host', T_HOSTNAME
keysdef k_uptls, 'trust', T_ANY, 'sni', T_HOSTNAME, 'cert', T_ANY, 'key', T_ANY
keysdef k_breaker, 'errors', T_COUNT, 'open', T_DURATION
enumdef e_ad_phases, 'request_headers'
enumdef e_ad_onerr, 'deny', 'allow'
keysdef k_connect, 'timeout', T_DURATION, 'max', T_UINT, 'idle', T_DURATION, \
	'warm', T_UINT, 'rate', T_RATE

; Names of the contexts, for messages, in CTX_* order starting at 1.
enumdef ctx_names, 'the top level', '`okena`', '`tcp`', '`pool`', '`limits`', '`timeout`', '`http`', '`route`', '`host`', '`tls`', '`auth`', '`udp`', '`alerts`', '`addon`'

; Directives of the language that this version does not implement yet.
enumdef future_names, \
	'log', \
	'acme', \
	'body', \
	'cert', 'warm'

rodata
	align 8
	dir_table:
end rodata
dirdef DIR_OKENA, 'okena',       M_TOP,     CTX_OKENA,   F_BLOCK_REQ or F_UNIQUE, 0, 0, T_NONE, T_NONE, 0
dirdef DIR_WORKERS, 'workers',     M_OKENA,   0,           F_UNIQUE, 1, 1, T_WORKERS, T_NONE, 0
dirdef DIR_IO_ENGINE, 'io_engine',   M_OKENA,   0,           F_UNIQUE, 1, 1, e_io_engine, T_NONE, 0
dirdef DIR_UPGRADE, 'upgrade',  M_OKENA,   0,           F_UNIQUE, 1, 1, T_ANY, T_NONE, 0
dirdef DIR_ADMIN, 'admin',      M_OKENA,   0,           F_UNIQUE, 1, 1, T_ANY, T_NONE, 0
dirdef DIR_USER, 'user',        M_OKENA,   0,           F_UNIQUE, 1, 1, T_ANY, T_NONE, 0
dirdef DIR_GEOIP, 'geoip',      M_OKENA,   0,           F_UNIQUE, 1, 1, T_ANY, T_NONE, 0
dirdef DIR_CACHE_MEM, 'cache_memory', M_OKENA, 0,       F_UNIQUE, 1, 1, T_SIZE, T_NONE, 0
dirdef DIR_CACHE_DISK, 'cache_disk', M_OKENA, 0,       F_UNIQUE, 1, 1, T_ANY, T_NONE, k_cdisk
dirdef DIR_FLEET, 'fleet',      M_OKENA,   0,           F_UNIQUE, 1, 16, T_LISTEN, T_LISTEN, 0
dirdef DIR_CDNLOOP, 'cdn_loop',  M_OKENA,   0,           F_UNIQUE, 1, 1, T_ANY, T_NONE, k_cdnloop
dirdef DIR_BIRD, 'bird',        M_OKENA,   0,           F_UNIQUE, 1, 1, T_ANY, T_NONE, k_bird
dirdef DIR_ACME, 'acme',        M_OKENA,   0,           F_UNIQUE, 1, 1, T_ANY, T_NONE, k_acme
dirdef DIR_LOCALCA, 'local_ca', M_OKENA,  0,           F_UNIQUE, 1, 1, T_ANY, T_NONE, 0
dirdef DIR_ECH, 'ech',           M_OKENA,   0,           F_UNIQUE, 2, 5, T_ANY, T_ANY, 0
dirdef DIR_GATEWAY, 'gateway',   M_OKENA,   0,           F_UNIQUE, 1, 1, e_gateway, T_NONE, k_gateway
dirdef DIR_PROFILE, 'profile',   M_OKENA,   0,           F_UNIQUE, 1, 1, e_profile, T_NONE, 0
dirdef DIR_RELOAD, 'reload',     M_OKENA,   0,           F_UNIQUE, 1, 1, e_reload, T_NONE, 0
dirdef DIR_LAST_GOOD, 'last_good', M_OKENA,  0,           F_UNIQUE, 1, 1, e_onoff, T_NONE, 0
dirdef DIR_PIN_WORKERS, 'pin_workers', M_OKENA, 0,        F_UNIQUE, 1, 1, e_pin, T_NONE, 0
dirdef DIR_WATCHDOG, 'watchdog',    M_OKENA,   0,           F_UNIQUE, 1, 1, T_DURATION, T_NONE, 0
dirdef DIR_METRICS, 'metrics',     M_OKENA,   0,           F_UNIQUE, 1, 1, T_LISTEN, T_NONE, k_metrics
dirdef DIR_BUSY_POLL, 'busy_poll',   M_OKENA,   0,           F_UNIQUE, 1, 1, T_DURAUTO, T_NONE, 0
dirdef DIR_TICKET_KEYS, 'ticket_keys', M_OKENA, 0,       F_UNIQUE, 1, 1, T_ANY, T_NONE, 0
dirdef DIR_QUIC_SID, 'quic_server_id', M_OKENA, 0,      F_UNIQUE or F_KEYS_BLOCK, 1, 1, T_NAME, T_NONE, k_quic_sid
dirdef DIR_QUIC_CC, 'quic_cc',     M_OKENA,   0,           F_UNIQUE, 1, 1, e_quic_cc, T_NONE, 0
dirdef DIR_DRAIN, 'drain',       M_OKENA,   0,           F_UNIQUE or F_KEYS_BLOCK, 0, 0, T_NONE, T_NONE, k_drain
dirdef DIR_HS_BUDGET, 'handshake_budget', M_OKENA, 0,    F_UNIQUE or F_KEYS_BLOCK, 1, 1, T_DURATION, T_NONE, k_hs_budget
dirdef DIR_UDP, 'udp',         M_TOP,     CTX_UDP,     F_BLOCK_REQ, 1, 16, T_LISTEN, T_LISTEN, 0
dirdef DIR_RESPONSES, 'responses', M_UDP,   0,           F_UNIQUE, 1, 1, T_ANY, T_NONE, 0
dirdef DIR_CANONICAL, 'canonical', M_HTTP,  0,           F_UNIQUE, 1, 1, T_HOSTNAME, T_NONE, 0
dirdef DIR_MSS, 'mss',         M_TCP or M_HTTP, 0,         F_UNIQUE, 1, 1, T_UINT, T_NONE, 0
dirdef DIR_TCP, 'tcp',         M_TOP,     CTX_TCP,     F_BLOCK_REQ, 1, 16, T_LISTEN, T_LISTEN, 0
dirdef DIR_HTTP, 'http',        M_TOP,     CTX_HTTP,    F_BLOCK_REQ, 1, 16, T_LISTEN, T_LISTEN, 0
dirdef DIR_HOST, 'host',        M_HTTP,    CTX_HOST,    F_BLOCK_REQ, 1, 64, T_HOSTNAME, T_HOSTNAME, 0
dirdef DIR_ROUTE, 'route',      M_HTTP or M_HOST,    CTX_ROUTE,   F_BLOCK_REQ, 1, 32, T_ROUTE, T_ROUTE, 0
dirdef DIR_ALERTS, 'alerts',    M_TOP,     CTX_ALERTS,  F_BLOCK_REQ or F_UNIQUE, 0, 0, T_NONE, T_NONE, 0
dirdef DIR_VRRP, 'vrrp',        M_TOP,     0,           F_UNIQUE, 1, 1, T_ANY, T_NONE, k_vrrp
dirdef DIR_WEBHOOK, 'webhook',  M_ALERTS,  0,           0, 1, 1, T_ANY, T_NONE, k_alert
dirdef DIR_SLACK, 'slack',      M_ALERTS,  0,           0, 1, 1, T_ANY, T_NONE, k_alert
dirdef DIR_TELEGRAM, 'telegram', M_ALERTS, 0,           F_KEYS_BLOCK, 0, 0, T_NONE, T_NONE, k_telegram
dirdef DIR_ALERT_ON, 'on',      M_ALERTS,  0,           F_UNIQUE, 1, 5, e_alert_on, e_alert_on, 0
dirdef DIR_EVERY, 'every',      M_ALERTS,  0,           F_UNIQUE, 1, 1, T_DURATION, T_NONE, 0
dirdef DIR_ALERT_NAME, 'name',  M_ALERTS,  0,           F_UNIQUE, 1, 1, T_ANY, T_NONE, 0
dirdef DIR_ADDON, 'addon',      M_TOP,     CTX_ADDON,   F_BLOCK_REQ, 1, 1, T_NAME, T_NONE, 0
dirdef DIR_ADRUN, 'run',        M_ADDON,   0,           F_UNIQUE, 1, 64, T_ANY, T_ANY, 0
dirdef DIR_ADPHASES, 'phases',  M_ADDON,   0,           F_UNIQUE, 1, 5, e_ad_phases, e_ad_phases, 0
dirdef DIR_ADTIMEOUT, 'timeout', M_ADDON,  0,           F_UNIQUE, 1, 1, T_DURATION, T_NONE, 0
dirdef DIR_ADONERR, 'on_error', M_ADDON,   0,           F_UNIQUE, 1, 1, e_ad_onerr, T_NONE, 0
dirdef DIR_ADCONC, 'concurrency', M_ADDON, 0,           F_UNIQUE, 1, 1, T_COUNT, T_NONE, 0
dirdef DIR_ADBREAKER, 'breaker', M_ADDON,  0,           F_UNIQUE or F_KEYS_BLOCK, 0, 0, T_NONE, T_NONE, k_breaker
dirdef DIR_RADDON, 'addon',     M_ROUTE,   0,           0, 1, 1, T_NAME, T_NONE, 0
dirdef DIR_POOL, 'pool',        M_TOP,     CTX_POOL,    F_BLOCK_REQ, 1, 1, T_NAME, T_NONE, 0
dirdef DIR_TO, 'to',          M_TCP or M_UDP or M_ROUTE, 0,           F_UNIQUE, 1, 64, T_TARGET, T_TARGET, 0
dirdef DIR_PROXY_PROTOCOL, 'proxy_protocol', M_TCP, 0,      F_UNIQUE, 2, 2, e_pp_mode, e_pp_version, 0
dirdef DIR_LIMITS, 'limits',      M_TCP or M_UDP or M_HTTP,     CTX_LIMITS,  F_BLOCK_REQ or F_UNIQUE, 0, 0, T_NONE, T_NONE, 0
dirdef DIR_CONNECTIONS, 'connections', M_LIMITS,  0,           F_UNIQUE, 1, 1, T_COUNTAUTO, T_NONE, 0
dirdef DIR_PER_SOURCE, 'per_source', M_LIMITS,  0,           F_UNIQUE, 1, 1, T_COUNT, T_NONE, 0
dirdef DIR_BODY_SIZE, 'body_size', M_LIMITS,  0,           F_UNIQUE, 1, 1, T_SIZE, T_NONE, 0
dirdef DIR_TIMEOUT, 'timeout',     M_TCP or M_UDP or M_HTTP,     CTX_TIMEOUT, F_BLOCK_REQ or F_UNIQUE, 0, 0, T_NONE, T_NONE, 0
dirdef DIR_IDLE, 'idle',        M_TIMEOUT, 0,           F_UNIQUE, 1, 1, T_DURATION, T_NONE, 0
dirdef DIR_TRUSTED, 'trusted_proxies', M_HTTP, 0,         F_UNIQUE, 1, 64, T_CIDR, T_CIDR, 0
dirdef DIR_HTTP2, 'http2',       M_HTTP,    0,           F_UNIQUE, 1, 1, e_onoff, T_NONE, 0
dirdef DIR_HTTP3, 'http3',       M_HTTP,    0,           F_UNIQUE, 1, 1, e_h3,    T_NONE, 0
dirdef DIR_PREFADDR, 'preferred_address', M_HTTP, 0,     F_UNIQUE, 1, 2, T_LISTEN, T_LISTEN, 0
dirdef DIR_EARLY, 'early_data',  M_HTTP,    0,           F_UNIQUE, 1, 1, e_onoff, T_NONE, 0
dirdef DIR_AUTH, 'auth',        M_ROUTE,   CTX_AUTH,    F_UNIQUE, 1, 1, e_auth, T_NONE, k_auth
dirdef DIR_POLICY, 'policy',    M_TOP,     CTX_ROUTE,   F_BLOCK_REQ, 1, 1, T_NAME, T_NONE, 0
dirdef DIR_USE, 'use',          M_ROUTE,   0,           0, 1, 1, T_NAME, T_NONE, 0
dirdef DIR_JWKS, 'jwks',        M_AUTH,    0,           F_UNIQUE, 1, 1, T_ANY, T_NONE, k_jwks
dirdef DIR_ISSUER, 'issuer',    M_AUTH,    0,           F_UNIQUE, 1, 1, T_ANY, T_NONE, 0
dirdef DIR_AUDIENCE, 'audience', M_AUTH,   0,           F_UNIQUE, 1, 1, T_ANY, T_NONE, 0
dirdef DIR_LEEWAY, 'leeway',    M_AUTH,    0,           F_UNIQUE, 1, 1, T_DURATION, T_NONE, 0
dirdef DIR_CLAIMS, 'claims',    M_AUTH,    0,           F_UNIQUE, 3, 64, T_ANY, T_ANY, 0
dirdef DIR_COMPRESS, 'compress', M_HTTP or M_HOST or M_ROUTE, 0, F_UNIQUE, 1, 2, T_ANY, T_ANY, k_compress
dirdef DIR_HEADERS, 'headers',  M_HTTP or M_HOST or M_ROUTE, 0, F_UNIQUE, 0, 0, T_NONE, T_NONE, k_headers
dirdef DIR_EARLY_HINTS, 'early_hints', M_ROUTE, 0,    F_UNIQUE, 1, 32, T_ANY, T_ANY, 0
dirdef DIR_IDEMPOTENCY, 'idempotency', M_ROUTE, 0,     F_UNIQUE or F_KEYS_BLOCK, 0, 0, T_NONE, T_NONE, k_idem
dirdef DIR_ALLOW, 'allow',      M_ROUTE,   0,           0, 1, 64, T_ANY, T_ANY, 0
dirdef DIR_DENY, 'deny',        M_ROUTE,   0,           0, 1, 64, T_ANY, T_ANY, 0
dirdef DIR_HOLD, 'hold',        M_ROUTE,   0,           F_UNIQUE, 1, 1, T_DURATION, T_NONE, 0
dirdef DIR_RTIMEOUT, 'timeout',  M_ROUTE,   0,           F_UNIQUE or F_KEYS_BLOCK, 0, 0, T_NONE, T_NONE, k_rtimeout
dirdef DIR_RETRY, 'retry',      M_ROUTE,   0,           F_UNIQUE, 1, 2, T_UINT, e_retry_mode, k_retry
dirdef DIR_ERRORS, 'errors',    M_HTTP or M_ROUTE, 0,  0, 1, 32, T_ANY, T_ANY, k_errors
dirdef DIR_MAINTENANCE, 'maintenance', M_HTTP, 0,     F_UNIQUE, 0, 0, T_NONE, T_NONE, k_maint
dirdef DIR_REDIRECTS, 'redirects', M_ROUTE, 0,         F_UNIQUE, 1, 1, T_ANY, T_NONE, k_rmap
dirdef DIR_FILES, 'files',      M_ROUTE,   0,           F_UNIQUE, 1, 1, T_ANY, T_NONE, k_files
dirdef DIR_PHP, 'php',          M_ROUTE,   0,           F_UNIQUE, 1, 1, T_ANY, T_NONE, k_php
dirdef DIR_MATCH, 'match',      M_ROUTE,   CTX_ROUTE,   F_BLOCK_REQ or F_FREE_KEYS, 0, 16, T_ANY, T_ANY, 0
dirdef DIR_CACHE, 'cache',      M_ROUTE,   0,           F_UNIQUE, 1, 1, T_DURATION, T_NONE, k_cache
dirdef DIR_SIGNED, 'signed_urls', M_ROUTE, 0,           F_UNIQUE or F_KEYS_BLOCK, 0, 0, T_NONE, T_NONE, k_signed
dirdef DIR_PRIORITY, 'priority', M_ROUTE,   0,           F_UNIQUE, 1, 1, e_priority, T_NONE, 0
dirdef DIR_HEDGE, 'hedge',      M_ROUTE,   0,           F_UNIQUE or F_KEYS_BLOCK, 0, 0, T_NONE, T_NONE, k_hedge
dirdef DIR_MIRROR, 'mirror',    M_ROUTE,   0,           F_UNIQUE, 2, 3, e_mirror_what, T_ANY, 0
dirdef DIR_SPLIT, 'split',      M_ROUTE,   0,           F_UNIQUE or F_FREE_KEYS, 0, 0, T_NONE, T_NONE, 0
dirdef DIR_CORS, 'cors',        M_ROUTE,   0,           F_UNIQUE or F_KEYS_BLOCK, 0, 1, e_cors_flags, T_NONE, k_cors
dirdef DIR_RLIMIT, 'limit',      M_ROUTE,   0,           F_KEYS_BLOCK, 1, 1, T_ANY, T_NONE, k_limit
dirdef DIR_FAULT, 'fault',      M_ROUTE,   0,           F_UNIQUE or F_KEYS_BLOCK, 0, 0, T_NONE, T_NONE, k_fault
dirdef DIR_REDIRECT, 'redirect',  M_ROUTE,   0,           F_UNIQUE, 2, 2, e_redirect_codes, T_ANY, 0
dirdef DIR_RESPOND, 'respond',   M_ROUTE,   0,           F_UNIQUE, 1, 2, T_UINT, T_ANY, k_respond
dirdef DIR_REWRITE, 'rewrite',    M_ROUTE,   0,           F_UNIQUE, 4, 4, e_rewrite_what, T_ANY, 0
dirdef DIR_RHEADER, 'header',      M_ROUTE or M_HTTP or M_HOST, 0, 0, 2, 3, e_header_ops, T_ANY, 0
dirdef DIR_RRESPONSE, 'response',  M_ROUTE or M_HTTP or M_HOST, 0, 0, 3, 4, e_response_what, T_ANY, 0
dirdef DIR_TLS, 'tls',          M_TCP or M_HTTP, CTX_TLS,   F_BLOCK_REQ or F_UNIQUE, 0, 1, e_tls_mode, T_NONE, 0
dirdef DIR_SNI, 'sni',          M_TLS,     0,           0, 4, 64, T_ANY, T_ANY, 0
dirdef DIR_DEFAULT, 'default',  M_TLS,     0,           F_UNIQUE, 1, 3, T_ANY, T_ANY, 0
dirdef DIR_CERT, 'cert',        M_TLS,     0,           0, 1, 1, T_ANY, T_NONE, k_cert
dirdef DIR_KEY, 'key',          M_TLS,     0,           F_UNIQUE, 1, 1, T_ANY, T_NONE, 0
dirdef DIR_TLSACME, 'acme',     M_TLS,     0,           0, 1, 15, T_ANY, T_ANY, 0
dirdef DIR_TLSLOCAL, 'local',   M_TLS,     0,           0, 1, 15, T_ANY, T_ANY, 0
dirdef DIR_TLSAUTO, 'auto',     M_TLS,     0,           F_UNIQUE, 0, 0, T_NONE, T_NONE, 0
dirdef DIR_TLSREDIR, 'redirect', M_TLS,    0,           F_UNIQUE, 1, 1, e_onoff, T_NONE, 0
dirdef DIR_OCSP, 'ocsp',        M_TLS,     0,           F_UNIQUE, 1, 1, e_onoff, T_NONE, 0
dirdef DIR_ODEMAND, 'on_demand', M_TLS,     0,           F_UNIQUE, 0, 16, T_ANY, T_ANY, k_odemand
dirdef DIR_CLIENT_CA, 'client_ca', M_TLS,   0,           F_UNIQUE, 1, 2, T_ANY, e_cca, k_cca
dirdef DIR_VERSIONS, 'versions', M_TLS,     0,           F_UNIQUE, 1, 2, e_tlsver, e_tlsver, 0
dirdef DIR_ALPN, 'alpn',        M_TLS,     0,           F_UNIQUE, 1, 2, e_alpn, e_alpn, 0
dirdef DIR_KTLS, 'ktls',        M_TLS,     0,           F_UNIQUE, 1, 1, e_onoff, T_NONE, 0
dirdef DIR_ACCESS_LOG, 'access_log', M_HTTP,   0,           F_UNIQUE, 1, 1, T_LOGDEST, T_NONE, k_alog
dirdef DIR_TRACING, 'tracing',   M_HTTP,   0,           F_UNIQUE, 1, 1, T_ANY, T_NONE, k_tracing
dirdef DIR_HEADER, 'header',      M_TIMEOUT, 0,           F_UNIQUE, 1, 1, T_DURATION, T_NONE, 0
dirdef DIR_RESPONSE, 'response',  M_TIMEOUT, 0,           F_UNIQUE, 1, 1, T_DURATION, T_NONE, 0
dirdef DIR_BODY_IDLE, 'body_idle', M_TIMEOUT, 0,           F_UNIQUE, 1, 1, T_DURATION, T_NONE, 0
dirdef DIR_SERVER, 'server',      M_POOL,    0,           0, 1, 2, T_BACKEND, e_server_flags, k_server
dirdef DIR_DISCOVER, 'discover', M_POOL,    0,           0, 1, 2, e_discover, T_ANY, k_discover
dirdef DIR_QUEUE, 'queue',       M_POOL,    0,           F_UNIQUE or F_KEYS_BLOCK, 0, 0, T_NONE, T_NONE, k_queue
dirdef DIR_SOURCE, 'source',     M_POOL,    0,           F_UNIQUE, 1, 8, T_ANY, T_ANY, 0
dirdef DIR_OUTLIER, 'outlier',   M_POOL,    0,           F_UNIQUE or F_KEYS_BLOCK, 0, 0, T_NONE, T_NONE, k_outlier
dirdef DIR_CONCURRENCY, 'concurrency', M_POOL, 0,       F_UNIQUE, 1, 1, T_ANY, T_NONE, k_concurrency
dirdef DIR_RETRY_BUDGET, 'retry_budget', M_POOL, 0,      F_UNIQUE, 1, 1, T_PERCENT, T_NONE, k_rbudget
dirdef DIR_STICKY, 'sticky',     M_POOL,    0,           F_UNIQUE or F_KEYS_BLOCK, 0, 0, T_NONE, T_NONE, k_sticky
dirdef DIR_SLOW_START, 'slow_start', M_POOL,   0,           F_UNIQUE, 1, 1, T_DURATION, T_NONE, 0
dirdef DIR_BALANCE, 'balance',     M_POOL,    0,           F_UNIQUE, 1, 1, e_balance, T_NONE, k_balance
dirdef DIR_CONNECT, 'connect',     M_POOL,    0,           F_UNIQUE or F_KEYS_BLOCK, 0, 0, T_NONE, T_NONE, k_connect
dirdef DIR_HEALTH, 'health',      M_POOL,    0,           F_UNIQUE or F_KEYS_BLOCK, 1, 3, e_health, T_ANY, k_health
dirdef DIR_UPTLS, 'tls',         M_POOL,    0,           F_UNIQUE or F_KEYS_BLOCK, 0, 0, T_NONE, T_NONE, k_uptls
dirdef DIR_PROTOCOL, 'protocol', M_POOL,    0,           F_UNIQUE, 1, 1, e_proto, T_NONE, 0
dirdef DIR_MODE, 'mode',         M_TCP or M_UDP, 0,      F_UNIQUE, 1, 1, e_listen_mode, T_NONE, k_mode
dirdef DIR_XDP, 'xdp',           M_OKENA,   0,           F_UNIQUE, 1, 8, T_ANY, T_ANY, 0
dirdef DIR_XDROP, 'drop',        M_OKENA,   0,           0, 1, 64, T_ANY, T_ANY, 0
dirdef DIR_SYN_RATE, 'syn_rate', M_OKENA,   0,           F_UNIQUE, 1, 1, T_RATE, T_NONE, k_synrate
rodata
	dir_table_end:
end rodata

; Find a directive. rdi/esi = name, edx = context mask to accept (or -1
; for any). rax = entry or 0.
dir_lookup:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r12,rdi
	mov	r13d,esi
	mov	r14d,edx
	lea	rbx,[dir_table]
.next:
	lea	rax,[dir_table_end]
	cmp	rbx,rax
	jae	.none
	test	[rbx+D_CTX],r14d
	jz	.skip
	mov	rdi,r12
	mov	esi,r13d
	lea	rdx,[rbx+D_NAME]
	call	mem_eq_cstr
	test	eax,eax
	jnz	.found
.skip:
	add	rbx,D_SIZE
	jmp	.next
.found:
	mov	rax,rbx
	jmp	.out
.none:
	xor	eax,eax
.out:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rdi/esi = key, rdx = options table. rax = entry or 0.
key_lookup:
	push	rbx
	push	r12
	push	r13
	mov	r12,rdi
	mov	r13d,esi
	mov	rbx,rdx
	test	rbx,rbx
	jz	.none
.next:
	cmp	byte [rbx+K_NAME],0
	je	.none
	mov	rdi,r12
	mov	esi,r13d
	lea	rdx,[rbx+K_NAME]
	call	mem_eq_cstr
	test	eax,eax
	jnz	.found
	add	rbx,K_SIZE
	jmp	.next
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

; rdi/esi = word, rdx = NUL-separated list ending with an empty string.
; rax = index or -1.
list_index:
	push	rbx
	push	r12
	push	r13
	push	r14
	mov	r12,rdi
	mov	r13d,esi
	mov	rbx,rdx
	xor	r14d,r14d
.next:
	cmp	byte [rbx],0
	je	.none
	mov	rdi,r12
	mov	esi,r13d
	mov	rdx,rbx
	call	mem_eq_cstr
	test	eax,eax
	jnz	.found
@@:
	inc	rbx
	cmp	byte [rbx-1],0
	jne	@b
	inc	r14d
	jmp	.next
.found:
	mov	eax,r14d
	jmp	.out
.none:
	mov	rax,-1
.out:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; ecx = index into a list (rdx). rsi/edx = that item.
list_item:
	mov	rsi,rdx
.skip:
	test	ecx,ecx
	jz	.measure
@@:
	inc	rsi
	cmp	byte [rsi-1],0
	jne	@b
	dec	ecx
	jmp	.skip
.measure:
	xor	edx,edx
@@:
	cmp	byte [rsi+rdx],0
	je	@f
	inc	edx
	jmp	@b
@@:
	ret

; Suggestions: the closest candidate within a small edit distance.
bss
	g_sug_word	dq ?
	g_sug_len	dd ?
	g_sug_best	dd ?
	g_sug_ptr	dq ?
	g_sug_plen	dd ?
end bss

; rdi/esi = the word that was not found.
suggest_begin:
	mov	[g_sug_word],rdi
	mov	[g_sug_len],esi
	; accept at most 1 edit for short words, 2 from 5 bytes, 3 from 9
	mov	eax,1
	cmp	esi,5
	jb	@f
	mov	eax,2
	cmp	esi,9
	jb	@f
	mov	eax,3
@@:
	inc	eax
	mov	[g_sug_best],eax		; best distance + 1
	mov	qword [g_sug_ptr],0
	ret

; rdx = candidate (NUL-terminated).
suggest_offer:
	push	rbx
	mov	rbx,rdx
	xor	ecx,ecx
@@:
	cmp	byte [rbx+rcx],0
	je	@f
	inc	ecx
	jmp	@b
@@:
	push	rcx
	mov	rdi,[g_sug_word]
	mov	esi,[g_sug_len]
	mov	rdx,rbx
	call	edit_distance
	pop	rcx
	cmp	eax,[g_sug_best]
	jae	.done
	mov	[g_sug_best],eax
	mov	[g_sug_ptr],rbx
	mov	[g_sug_plen],ecx
.done:
	pop	rbx
	ret

; rdx = NUL-separated list.
suggest_offer_list:
	push	rbx
	mov	rbx,rdx
.next:
	cmp	byte [rbx],0
	je	.done
	mov	rdx,rbx
	call	suggest_offer
@@:
	inc	rbx
	cmp	byte [rbx-1],0
	jne	@b
	jmp	.next
.done:
	pop	rbx
	ret

; Print "= help: did you mean `x`?" when there is a suggestion.
suggest_note:
	cmp	qword [g_sug_ptr],0
	je	.none
	call	cfg_note
	out_lit 'help: did you mean '
	mov	rsi,[g_sug_ptr]
	mov	edx,[g_sug_plen]
	call	cfg_quote
	out_lit '?'
	call	cfg_note_end
.none:
	ret
