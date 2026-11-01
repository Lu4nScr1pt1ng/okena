#!/usr/bin/env python3
"""The interop container's file server behind okena: GET of a file under
the directory, HTTP/1.1 keep-alive, many requests at once."""
import http.server
import socketserver
import sys
import functools


class H(http.server.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass


class T(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 1024


root, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
T((host, port), functools.partial(H, directory=root)).serve_forever()
