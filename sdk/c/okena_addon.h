/* okena addon SDK for C (protocol version 1, docs/ADDONS.md).
 *
 *   #include "okena_addon.h"
 *
 *   static void on_request(const okena_request *req, okena_answer *ans, void *ctx)
 *   {
 *       size_t n;
 *       if (okena_header(req, "x-block", &n))
 *           { okena_respond(ans, 403); okena_body(ans, "blocked\n", 8); return; }
 *       okena_set(ans, "x-checked", "yes");     // the default answer: continue
 *   }
 *
 *   int main(void) { return okena_main(on_request, NULL); }
 *
 * One file to build with the program (okena_addon.c), no dependency beyond
 * libc. The handler runs on one thread. After a call the addon polls the rings
 * for the addon's `poll` (default 50 us; OKENA_ADDON_SPIN_US overrides it)
 * before it sleeps on the bell: a call that comes meanwhile is taken without
 * a wakeup.
 */
#ifndef OKENA_ADDON_H
#define OKENA_ADDON_H

#include <stddef.h>
#include <stdint.h>

#define OKENA_PHASE_REQUEST_HEADERS 1
#define OKENA_FLAG_TLS 1
#define OKENA_FLAG_H2 2
#define OKENA_FLAG_H3 4
#define OKENA_PHASE_REQUEST_BODY 2
#define OKENA_PHASE_RESPONSE_HEADERS 4	/* fields and body: the response's; method, target: the request's */
#define OKENA_PHASE_RESPONSE_BODY 8
#define OKENA_PHASE_LOG 16		/* after the exchange: never answered */
#define OKENA_FLAG_BODY_TRUNCATED 8
#define OKENA_FLAG_BODY_CHUNKED 16	/* body as it came; okena_dechunk decodes it */
#define OKENA_FLAG_BODY_UNREAD 32

typedef struct {
	const char *name;
	size_t name_len;
	const char *value;
	size_t value_len;
} okena_field;

typedef struct {
	uint32_t id;
	uint32_t phase;
	uint32_t flags;
	uint32_t route;			/* the route's action + 1 */
	const char *head;		/* request line, fields, empty line (HTTP/1.1 form) */
	size_t head_len;
	const char *method;
	size_t method_len;
	const char *target;
	size_t target_len;
	unsigned nfields;
	unsigned family;		/* 4, 6, or 0 */
	const uint8_t *client;		/* 16 bytes; IPv4 in the first 4 */
	const uint8_t *index_;		/* (the fields, okena_field_at) */
	const char *body;		/* phases request_body: the body, or its first `body` bytes */
	size_t body_len;
	int status;			/* the response phases: the backend's status */
	uint32_t stream_slot;		/* with stream_key: the same in every call */
	uint64_t stream_key;		/* about one request (its phases, its log) */
} okena_request;

/* a chunk-framed body decoded in place: its length; *whole when its last chunk
   was there */
size_t okena_dechunk(char *body, size_t len, int *whole);

typedef struct okena_answer okena_answer;
typedef struct okena_addon okena_addon;
typedef void (*okena_handler)(const okena_request *req, okena_answer *ans, void *ctx);

/* the request's fields */
okena_field okena_field_at(const okena_request *req, unsigned i);
const char *okena_header(const okena_request *req, const char *name, size_t *len);

/* the answer: continue (the default), with changes, or respond */
void okena_set(okena_answer *ans, const char *name, const char *value);
void okena_set_n(okena_answer *ans, const char *name, size_t nlen, const char *value, size_t vlen);
void okena_add(okena_answer *ans, const char *name, const char *value);
void okena_add_n(okena_answer *ans, const char *name, size_t nlen, const char *value, size_t vlen);
void okena_remove(okena_answer *ans, const char *name);
void okena_target(okena_answer *ans, const char *target);
void okena_pool(okena_answer *ans, const char *pool);	/* another pool, by its name */
void okena_respond(okena_answer *ans, int status);	/* then okena_add: its fields */
void okena_body(okena_answer *ans, const void *body, size_t len);	/* respond's; with continue: in place of the body */
void okena_no_answer(okena_answer *ans);		/* okena's on_error, at its time */
void okena_fail(okena_answer *ans);			/* it could not decide: on_error now */

/* the addon */
okena_addon *okena_open(void);		/* from OKENA_ADDON_FD; NULL and errno on failure */
const char *okena_name(const okena_addon *a);
int okena_run(okena_addon *a, okena_handler h, void *ctx);	/* returns only on an error */
int okena_main(okena_handler h, void *ctx);			/* okena_open + okena_run */

#endif
