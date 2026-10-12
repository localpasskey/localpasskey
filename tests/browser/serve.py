"""Serve the browser test page on http://localhost:8765 and print what it reports.

    python3 tests/browser/serve.py

Open http://localhost:8765/ and use the buttons, or let the page run steps on
its own: http://localhost:8765/?auto=alice@localhost,signin
"""

import http.server
import os
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8765


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=os.path.dirname(os.path.abspath(__file__)), **kwargs)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        print(body, flush=True)
        self.send_response(204)
        self.end_headers()

    def log_message(self, format, *args):
        pass


http.server.ThreadingHTTPServer(("localhost", PORT), Handler).serve_forever()
