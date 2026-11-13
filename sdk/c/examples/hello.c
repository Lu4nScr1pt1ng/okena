/* An addon in C: lets requests go on with x-checked: yes, answers
 * /blocked itself, and takes x-debug away.
 *
 *   cc -O2 -o hello sdk/c/examples/hello.c sdk/c/okena_addon.c -Isdk/c
 *   addon hello { run /path/to/hello }
 */
#include <string.h>

#include "okena_addon.h"

static void on_request(const okena_request *req, okena_answer *ans, void *ctx)
{
	(void)ctx;
	if (req->target_len >= 8 && !memcmp(req->target + req->target_len - 8, "/blocked", 8)) {
		static const char body[] = "blocked by the addon\n";
		okena_respond(ans, 403);
		okena_add(ans, "content-type", "text/plain");
		okena_body(ans, body, sizeof body - 1);
		return;
	}
	if (req->target_len >= 5 && !memcmp(req->target + req->target_len - 5, "/pass", 5))
		return;				/* continue, nothing changed */
	okena_set(ans, "x-checked", "yes");
	okena_remove(ans, "x-debug");
}

int main(void)
{
	return okena_main(on_request, NULL);
}
