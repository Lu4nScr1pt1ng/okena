; Compile-time limits and process exit codes.

MAX_WORKERS		= 256

; Process exit codes.
EXIT_OK			= 0
EXIT_FAILURE		= 1
EXIT_CONFIG		= 2
EXIT_FATAL		= 3		; worker could not start: supervisor gives up

RING_ENTRIES		= 4096		; submission queue
CQ_ENTRIES		= 16384		; completion queue
REAP_BUDGET		= 1024		; completions handled before flushing submissions
