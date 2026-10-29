; The credentials of a tls block, as the plan keeps them (loaded by
; src/tls/certs.inc, used by the handshake in src/tls/handshake.inc).

MAX_TLS		:= 64				; tls blocks in a plan
TLS_STORE	:= 1 shl 20			; their chains
TL_CHAIN	:= 0				; d: offset in g_tls_store
TL_CLEN		:= 4				; d: certificate_list length
TL_KEY		:= 8				; 32 bytes: d, big endian
TL_PUB		:= 40				; 65 bytes: 04 | X | Y
TL_SIZE		:= 112
TLS_DER_MAX	:= 1 shl 16			; one certificate
TLS_CHAIN_MAX	:= 24576			; a certificate_list: the server's flight fits a session buffer
