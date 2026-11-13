#!/usr/bin/env python3
"""The addon tests/gateway/addon.py calls: what it does depends on the path's
last segment (after the route's prefix), so one program covers every case."""
import os
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "sdk" / "python"))
import okena_addon as oa  # noqa: E402

START = time.time()


def on_request(req):
    last = req.path.rstrip("/").rsplit("/", 1)[-1]
    if last == "pass":
        return oa.Continue()
    if last == "pid":
        return oa.Respond(200, [("x-addon-pid", str(os.getpid())), ("x-addon-name", os.environ.get("OKENA_ADDON_NAME", ""))], b"pid")
    if last == "set":
        return oa.Continue(set=[("x-addon", "yes"), ("content-length", "999")], add=[("x-multi", "1"), ("x-multi", "2")],
                           remove=["x-drop"])
    if last == "deny":
        return oa.Respond(403, [("content-type", "text/plain"), ("x-why", "test")], b"denied by addon\n")
    if last == "empty":
        return oa.Respond(204, [("x-why", "empty")])
    if last == "target":
        return oa.Continue(target="/rewritten?q=1")
    if last == "slow":
        time.sleep(0.4)
        return oa.Continue()
    if last == "crash":
        os._exit(3)
    if last == "bad":
        return oa.Continue(set=[("bad name", "x")])
    if last == "none":
        return None
    if last == "fail":
        return oa.Fail()
    if last == "body":
        import hashlib
        return oa.Respond(200, [("x-body-len", str(len(req.body))), ("x-body-trunc", str(req.body_truncated)),
                                ("x-body-unread", str(req.body_unread)), ("x-phase", str(req.phase))], req.body[:64])
    if last == "attack":
        if b"DROP TABLE" in req.body:
            return oa.Respond(403, [], b"body refused\n")
        return oa.Continue(set=[("x-body-ok", str(len(req.body)))])
    if last == "pool":
        return oa.Continue(pool="other")
    if last == "nopool":
        return oa.Continue(pool="nowhere")
    if last == "info":
        return oa.Respond(200, [("x-client", req.client_ip), ("x-flags", str(req.flags)), ("x-method", req.method),
                                ("x-target", req.target), ("x-host", req.header("host", ""))], b"info")
    return oa.Continue(set=[("x-seen", "1")])


oa.run(on_request)
