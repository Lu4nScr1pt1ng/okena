; The addon protocol, version 1: what okena and an addon share (docs/ADDONS.md).
;
; An addon is a process of its own that okena starts (`run`), restarts, and
; calls at phases of a request. They share one memfd per addon, mapped by the
; addon, the supervisor and the workers alike:
;
;   page 0          the header: what the addon needs to find the rest, and the
;                   words that say whether it serves (ADH_READY) and which run of
;                   it this is (ADH_EPOCH)
;   then, per ring  a ring pair for each worker slot: calls from a worker
;                   (worker -> addon), answers to it (addon -> worker)
;
; A ring is a byte ring of records that never wrap: a record that does not fit
; before the end is preceded by a padding record (kind 0) to the end. Head and
; tail count bytes since the ring was made (they never wrap either), each on a
; cache line of its own, each written by one side only. A ring has one producer
; at a time: a worker slot is claimed by one worker process (AD_CLAIM), and a
; worker that takes a slot another left goes on from the head it finds, so no
; ring is ever reset under the addon.
;
; Wakeups: a worker that posted calls writes the addon's eventfd (the bell) once
; a loop iteration, unless the addon said it is polling (ADH_SLEEP = 0); an addon
; that posted answers writes the worker slot's eventfd. Nothing waits on a lock.

AD_MAGIC	:= 0x314E4F4444414B4F		; "OKADDON1"
AD_VERSION	:= 1
AD_HDR		:= 4096				; header page; each ring header is a page too
AD_RING		:= 262144			; bytes of a ring's data (a power of two)
AD_STRIDE	:= 2 * (AD_HDR + AD_RING)	; a ring pair
AD_NAME_MAX	:= 63

; header (page 0)
ADH_MAGIC	:= 0				; q
ADH_VERSION	:= 8				; d
ADH_NRINGS	:= 12				; d
ADH_RBYTES	:= 16				; d: AD_RING
ADH_HBYTES	:= 20				; d: AD_HDR
ADH_STRIDE	:= 24				; q
ADH_BELL		:= 32				; d: the bell's descriptor, in the addon
ADH_WAKE0	:= 36				; d: the first worker slot's eventfd (ADH_NRINGS in a row)
ADH_PHASES	:= 40				; d: ADP_* bits
ADH_INDEX	:= 44				; d
ADH_READY	:= 48				; d: the addon serves (it writes 1; okena 0 at each start)
ADH_EPOCH	:= 52				; d: okena: one more at each start and each exit
ADH_PID		:= 56				; d
ADH_SLEEP	:= 60				; d: the addon may block on the bell: ring it
ADH_NAME		:= 64				; 64: NUL-terminated
ADH_TIMEOUT	:= 128				; q: µs a call is given
ADH_MAXHEAD	:= 136				; d: the largest head a call carries
ADH_POLL	:= 140				; d: µs the addon polls after a call before it sleeps (`poll`)

; a ring pair, at AD_HDR + slot * AD_STRIDE
ADR_HEAD		:= 0				; q: bytes produced (the producer's line)
ADR_TAIL		:= 64				; q: bytes consumed (the consumer's line)
ADR_OWNER	:= 128				; d: calls: the worker's pid, 0 none
ADR_WAWAKE	:= 128				; d: answers: 1 while the worker polls for them
						; (no need to write its eventfd), 0 otherwise
ADR_COUNT	:= 256				; calls: counters (q each, the worker's own)
ADC_CALLS	:= 0				; calls posted
ADC_OK		:= 8				; answers taken
ADC_TIMEOUT	:= 16				; no answer in time
ADC_ERROR	:= 24				; not asked (not ready, full, broken) or a bad answer
ADC_OPENED	:= 32				; the circuit opened
ADC_ALLOWED	:= 40				; on_error allow let a request go on
ADC_DENIED	:= 48				; on_error deny refused one
ADC_RESPOND	:= 56				; the addon answered the client itself
ADC_CRASHED	:= 64				; calls pending when the addon exited
ADC_N		:= 9
ADC_HSUM	:= 120				; ns of the answered calls, summed
ADR_HIST	:= ADR_COUNT + 128		; their round trips: ADH_NB counts (q), by AD_HBOUNDS
AD_NB		:= 32
ADR_CALLS	:= AD_HDR			; the calls' bytes
ADR_ANS		:= AD_HDR + AD_RING		; the answers' ring header
ADR_ANSD		:= AD_HDR * 2 + AD_RING		; the answers' bytes

; phases
ADP_REQ_HEADERS	:= 1
ADP_REQ_BODY	:= 2				; the call carries the request's body too
ADP_RESP_HEADERS := 4				; the backend's response head
ADP_RESP_BODY	:= 8				; and its body (counted, small enough)
ADP_LOG		:= 16				; after the exchange, never answered
ADP_REQ		:= ADP_REQ_HEADERS or ADP_REQ_BODY
ADP_RESP	:= ADP_RESP_HEADERS or ADP_RESP_BODY

; a call (worker -> addon)
ADQ_LEN		:= 0				; d: the record, a multiple of 8
ADQ_KIND		:= 4				; w: 1 a call, 0 padding to the ring's end
ADQ_PHASE	:= 6				; w: ADP_*
ADQ_ID		:= 8				; d: echoed in the answer
ADQ_FLAGS	:= 12				; d: ADQF_*
ADQ_HLEN		:= 16				; d: the head's bytes
ADQ_NHDR		:= 20				; w: fields in the index
ADQ_FAMILY	:= 22				; w: 4, 6, or 0 (a Unix socket)
ADQ_CLIENT	:= 24				; 16: the client's address
ADQ_METHOD	:= 40				; w offset, w length (into the head)
ADQ_TARGET	:= 44				; w offset, w length
ADQ_ROUTE	:= 48				; d: the route's action + 1
ADQ_BLEN	:= 52				; d: the body's bytes, after the head
ADQ_STREAM	:= 56				; q: the same in every call about one request (its phases, its log)
ADQ_INDEX	:= 64				; the fields: w name offset, w length, w value offset, w length
ADQF_TLS		:= 1
ADQF_H2		:= 2
ADQF_H3		:= 4
ADQF_TRUNC	:= 8				; the body goes on past what the call carries
ADQF_CHUNKED	:= 16				; the body as it came: chunk-framed
ADQF_UNREAD	:= 32				; a body not read (the client waits for 100 Continue)

; an answer (addon -> worker)
ANS_LEN		:= 0				; d
ANS_KIND		:= 4				; w: 1 an answer, 0 padding
ANS_ACTION	:= 6				; w: ANA_*
ANS_ID		:= 8				; d
ANS_STATUS	:= 12				; w: respond: the status
ANS_NOPS		:= 14				; w
ANS_BLEN		:= 16				; d: respond: the body's bytes
ANS_FLAGS	:= 20				; d: ANSF_*
ANSF_BODY	:= 1				; continue: the body that follows the ops replaces the body
ANS_OPS		:= 24				; ops: b op, b 0, w name length, w value length, name, value
ANA_CONTINUE	:= 0
ANA_RESPOND	:= 1
ANA_FAIL	:= 2				; it could not decide: on_error now (a failure, for the circuit)
ANO_SET		:= 1				; a request field set (respond: a response field)
ANO_ADD		:= 2				; one more
ANO_REMOVE	:= 3				; gone
ANO_TARGET	:= 4				; the request target (path and query)
ANO_POOL	:= 5				; the pool the request goes to (value: its name)
ANO_HDR		:= 6
