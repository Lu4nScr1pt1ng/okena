/* okena addon SDK for C: the protocol (docs/ADDONS.md). */
#define _GNU_SOURCE
#include "okena_addon.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MAGIC 0x314E4F4444414B4FULL
#define ANSWER_MAX (1u << 16)

struct okena_addon {
	uint8_t *m;
	size_t size;
	uint32_t nrings, rbytes, hbytes;
	uint64_t stride;
	int bell, wake0;
	uint64_t spin_ns;
	char name[64];
};

struct okena_answer {
	uint8_t buf[ANSWER_MAX];
	size_t len;		/* ops written so far, from 24 */
	size_t body_len;
	uint16_t nops;
	uint16_t action;
	uint16_t status;
	int none;
	int overflow;
	const void *body;
};

#define U32(p) (*(volatile uint32_t *)(p))
#define U64(p) (*(volatile uint64_t *)(p))

static inline uint64_t load_acq(const void *p) { return __atomic_load_n((const uint64_t *)p, __ATOMIC_ACQUIRE); }
static inline void store_rel(void *p, uint64_t v) { __atomic_store_n((uint64_t *)p, v, __ATOMIC_RELEASE); }

static uint64_t now_ns(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint64_t)t.tv_sec * 1000000000u + (uint64_t)t.tv_nsec;
}

okena_addon *okena_open(void)
{
	const char *e = getenv("OKENA_ADDON_FD");
	int fd = e ? atoi(e) : 3;
	struct stat st;
	if (fstat(fd, &st) < 0)
		return NULL;
	okena_addon *a = calloc(1, sizeof *a);
	if (!a)
		return NULL;
	a->size = (size_t)st.st_size;
	a->m = mmap(NULL, a->size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (a->m == MAP_FAILED) {
		free(a);
		return NULL;
	}
	if (U64(a->m) != MAGIC || U32(a->m + 8) != 1) {
		munmap(a->m, a->size);
		free(a);
		errno = EPROTO;
		return NULL;
	}
	a->nrings = U32(a->m + 12);
	a->rbytes = U32(a->m + 16);
	a->hbytes = U32(a->m + 20);
	a->stride = U64(a->m + 24);
	a->bell = (int)U32(a->m + 32);
	a->wake0 = (int)U32(a->m + 36);
	memcpy(a->name, a->m + 64, 63);
	const char *s = getenv("OKENA_ADDON_SPIN_US");	/* (over the configuration's `poll`) */
	a->spin_ns = (s ? strtoull(s, NULL, 10) : U32(a->m + 140)) * 1000;
	return a;
}

const char *okena_name(const okena_addon *a) { return a->name; }

/* -------------------------------------------------------------- requests */

okena_field okena_field_at(const okena_request *req, unsigned i)
{
	okena_field f = {0};
	if (i >= req->nfields)
		return f;
	const uint8_t *x = req->index_ + 8 * i;
	uint16_t no, nl, vo, vl;
	memcpy(&no, x, 2), memcpy(&nl, x + 2, 2), memcpy(&vo, x + 4, 2), memcpy(&vl, x + 6, 2);
	f.name = req->head + no, f.name_len = nl;
	f.value = req->head + vo, f.value_len = vl;
	return f;
}

const char *okena_header(const okena_request *req, const char *name, size_t *len)
{
	size_t n = strlen(name);
	for (unsigned i = 0; i < req->nfields; i++) {
		okena_field f = okena_field_at(req, i);
		if (f.name_len == n && !strncasecmp(f.name, name, n)) {
			if (len)
				*len = f.value_len;
			return f.value;
		}
	}
	return NULL;
}

/* --------------------------------------------------------------- answers */

static void op(okena_answer *ans, int code, const char *name, size_t nlen, const char *value, size_t vlen)
{
	if (nlen > 0xFFFF || vlen > 0xFFFF || ans->len + 6 + nlen + vlen > ANSWER_MAX) {
		ans->overflow = 1;
		return;
	}
	uint8_t *p = ans->buf + ans->len;
	uint16_t a = (uint16_t)nlen, b = (uint16_t)vlen;
	p[0] = (uint8_t)code, p[1] = 0;
	memcpy(p + 2, &a, 2), memcpy(p + 4, &b, 2);
	memcpy(p + 6, name, nlen), memcpy(p + 6 + nlen, value, vlen);
	ans->len += 6 + nlen + vlen;
	ans->nops++;
}

void okena_set_n(okena_answer *ans, const char *n, size_t nl, const char *v, size_t vl) { op(ans, 1, n, nl, v, vl); }
void okena_add_n(okena_answer *ans, const char *n, size_t nl, const char *v, size_t vl) { op(ans, 2, n, nl, v, vl); }
void okena_set(okena_answer *ans, const char *n, const char *v) { op(ans, 1, n, strlen(n), v, strlen(v)); }
void okena_add(okena_answer *ans, const char *n, const char *v) { op(ans, 2, n, strlen(n), v, strlen(v)); }
void okena_remove(okena_answer *ans, const char *n) { op(ans, 3, n, strlen(n), "", 0); }
void okena_target(okena_answer *ans, const char *t) { op(ans, 4, "", 0, t, strlen(t)); }
void okena_pool(okena_answer *ans, const char *p) { op(ans, 5, "", 0, p, strlen(p)); }

size_t okena_dechunk(char *b, size_t len, int *whole)
{
	size_t in = 0, out = 0;
	*whole = 0;
	for (;;) {
		size_t i = in;
		while (i + 1 < len && !(b[i] == '\r' && b[i + 1] == '\n'))
			i++;
		if (i + 1 >= len)
			return out;
		size_t n = (size_t)strtoul(b + in, NULL, 16);
		if (n == 0) {
			*whole = 1;
			return out;
		}
		in = i + 2;
		size_t take = n < len - in ? n : len - in;
		memmove(b + out, b + in, take);
		out += take;
		if (take < n || in + n + 2 > len)
			return out;
		in += n + 2;
	}
}
void okena_respond(okena_answer *ans, int status) { ans->action = 1, ans->status = (uint16_t)status; }
void okena_no_answer(okena_answer *ans) { ans->none = 1; }
void okena_fail(okena_answer *ans) { ans->action = 2; }

void okena_body(okena_answer *ans, const void *body, size_t len)
{
	ans->body = body, ans->body_len = len;
}

/* ----------------------------------------------------------------- rings */

static uint8_t *pair(okena_addon *a, uint32_t r) { return a->m + a->hbytes + (uint64_t)r * a->stride; }

/* the answer into ring r's answers; 0 when there is no room (okena then
   ends the call at its time) */
static int put(okena_addon *a, uint32_t r, uint32_t id, okena_answer *ans)
{
	if (ans->overflow)
		return 0;
	uint8_t *h = pair(a, r) + a->hbytes + a->rbytes;
	uint8_t *d = h + a->hbytes;
	size_t size = (ans->len + ans->body_len + 7) & ~(size_t)7;
	uint64_t head = U64(h), tail = load_acq(h + 64);
	uint64_t pos = head & (a->rbytes - 1);
	uint64_t pad = a->rbytes - pos < size ? a->rbytes - pos : 0;
	if (pad + size > a->rbytes - (head - tail))
		return 0;
	if (pad) {
		uint32_t len = (uint32_t)pad;
		memcpy(d + pos, &len, 4);
		memset(d + pos + 4, 0, 4);
		head += pad, pos = 0;
	}
	uint8_t *p = d + pos;
	uint32_t len = (uint32_t)size, blen = (uint32_t)ans->body_len, rsv = 0;
	uint16_t kind = 1;
	memcpy(p, &len, 4), memcpy(p + 4, &kind, 2), memcpy(p + 6, &ans->action, 2);
	memcpy(p + 8, &id, 4), memcpy(p + 12, &ans->status, 2), memcpy(p + 14, &ans->nops, 2);
	memcpy(p + 16, &blen, 4), memcpy(p + 20, &rsv, 4);
	memcpy(p + 24, ans->buf + 24, ans->len - 24);
	if (ans->body_len)
		memcpy(p + ans->len, ans->body, ans->body_len);
	store_rel(h, head + size);
	return 1;
}

/* every call waiting, once: how many */
static unsigned poll_rings(okena_addon *a, okena_handler fn, void *ctx, okena_answer *ans)
{
	unsigned n = 0;
	for (uint32_t r = 0; r < a->nrings; r++) {
		uint8_t *h = pair(a, r);
		uint8_t *d = h + a->hbytes;
		uint64_t head = load_acq(h), tail = U64(h + 64);
		if (head == tail)
			continue;
		int answered = 0;
		while (tail != head) {
			uint8_t *p = d + (tail & (a->rbytes - 1));
			uint32_t len;
			uint16_t kind;
			memcpy(&len, p, 4), memcpy(&kind, p + 4, 2);
			if (len < 8 || (len & 7) || len > head - tail) {
				tail = head;	/* not a record: the rest is dropped */
				break;
			}
			if (kind == 1) {
				okena_request q;
				uint16_t ph, nh, fam, mo, ml, to, tl;
				uint32_t hl;
				memcpy(&q.id, p + 8, 4), memcpy(&ph, p + 6, 2), memcpy(&q.flags, p + 12, 4);
				memcpy(&hl, p + 16, 4), memcpy(&nh, p + 20, 2), memcpy(&fam, p + 22, 2);
				memcpy(&mo, p + 40, 2), memcpy(&ml, p + 42, 2), memcpy(&to, p + 44, 2), memcpy(&tl, p + 46, 2);
				memcpy(&q.route, p + 48, 4);
				q.phase = ph, q.nfields = nh, q.family = fam, q.client = p + 24;
				q.index_ = p + 56;
				q.head = (const char *)(p + 56 + 8 * nh), q.head_len = hl;
				uint32_t bl;
				memcpy(&bl, p + 52, 4);
				q.body = q.head + hl, q.body_len = bl;
				q.method = q.head + mo, q.method_len = ml;
				q.target = q.head + to, q.target_len = tl;
				ans->len = 24, ans->body_len = 0, ans->nops = 0, ans->action = 0;
				ans->status = 0, ans->none = 0, ans->overflow = 0, ans->body = NULL;
				fn(&q, ans, ctx);
				if (!ans->none)
					answered |= put(a, r, q.id, ans);
				n++;
			}
			tail += len;
		}
		store_rel(h + 64, tail);
		/* the worker polls for its answers (it said so): no eventfd */
		if (answered) {
			uint8_t *ah = h + a->hbytes + a->rbytes;
			__atomic_thread_fence(__ATOMIC_SEQ_CST);
			if (__atomic_load_n((uint32_t *)(ah + 128), __ATOMIC_RELAXED))
				continue;
			uint64_t one = 1;
			if (write(a->wake0 + (int)r, &one, 8) < 0) {
				/* (a worker slot nobody holds now) */
			}
		}
	}
	return n;
}

int okena_run(okena_addon *a, okena_handler fn, void *ctx)
{
	okena_answer *ans = malloc(sizeof *ans);
	if (!ans)
		return -1;
	uint32_t *sleep_ = (uint32_t *)(a->m + 60);
	uint32_t *ready = (uint32_t *)(a->m + 48);
	__atomic_store_n(sleep_, 1, __ATOMIC_SEQ_CST);
	__atomic_store_n(ready, 1, __ATOMIC_SEQ_CST);
	uint64_t last = 0;
	int polling = 0;
	for (;;) {
		if (poll_rings(a, fn, ctx, ans)) {
			if (!polling && a->spin_ns) {
				__atomic_store_n(sleep_, 0, __ATOMIC_SEQ_CST);
				polling = 1;
			}
			last = now_ns();
			continue;
		}
		if (polling && now_ns() - last < a->spin_ns) {
			__builtin_ia32_pause();
			continue;
		}
		/* asleep: said first, then one more look, then the bell */
		__atomic_exchange_n(sleep_, 1, __ATOMIC_SEQ_CST);
		polling = 0;
		if (poll_rings(a, fn, ctx, ans)) {
			last = now_ns();
			continue;
		}
		uint64_t v;
		if (read(a->bell, &v, 8) < 0 && errno != EINTR)
			return -1;
		last = now_ns();
	}
}

int okena_main(okena_handler fn, void *ctx)
{
	okena_addon *a = okena_open();
	if (!a) {
		perror("okena addon: cannot map OKENA_ADDON_FD");
		return 1;
	}
	return okena_run(a, fn, ctx) < 0 ? 1 : 0;
}
