#!/usr/bin/env python3
"""Minimal local HTTP server for endpoints_test.sh (bats).

Serves static files from the given directory (like `python3 -m http.server`)
but additionally answers /redirect-me with a 301 redirect to
/redirect-target, so the bats suite can exercise MonarchDomain's
redirect-following (-L) behavior against a real HTTP round trip instead of
an external site.

Usage: fixture_server.py <port> <webroot>
"""
import http.server
import os
import sys


class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect-me":
            self.send_response(301)
            self.send_header("Location", "/redirect-target")
            self.end_headers()
            return
        super().do_GET()

    def log_message(self, fmt, *args):
        pass  # keep bats output clean


if __name__ == "__main__":
    port = int(sys.argv[1])
    webroot = sys.argv[2]
    os.chdir(webroot)
    http.server.HTTPServer(("127.0.0.1", port), Handler).serve_forever()
