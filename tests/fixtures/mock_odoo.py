#!/usr/bin/env python3
"""Tiny fake Odoo HTTP server for toolkit tests (never use outside a lab).

  mock_odoo.py PORT [--version 17.0] [--expose-db] [--expose-manager]
"""
import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

ap = argparse.ArgumentParser()
ap.add_argument("port", type=int)
ap.add_argument("--version", default="17.0")
ap.add_argument("--expose-db", action="store_true")
ap.add_argument("--expose-manager", action="store_true")
ARGS = ap.parse_args()


class H(BaseHTTPRequestHandler):
    server_version = "Werkzeug/3.0.1"

    def log_message(self, *a):
        pass

    def _json(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, text, status=200):
        body = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        if self.path == "/web/webclient/version_info":
            major = int(ARGS.version.split(".")[0])
            self._json({"jsonrpc": "2.0", "id": 1, "result": {
                "server_version": ARGS.version, "server_version_info": [major, 0, 0, "final", 0, ""],
                "server_serie": ARGS.version, "protocol_version": 1}})
        elif self.path == "/web/database/list":
            if ARGS.expose_db:
                self._json({"jsonrpc": "2.0", "id": 2, "result": ["prod", "staging", "demo"]})
            else:
                self._json({"jsonrpc": "2.0", "id": 2, "error": {"code": 200, "message": "Odoo Server Error",
                                                                 "data": {"name": "odoo.exceptions.AccessDenied"}}})
        else:
            self._html("not found", 404)

    def do_GET(self):
        if self.path.startswith("/web/database/manager") and ARGS.expose_manager:
            self._html('<html><title>Odoo</title><div class="o_database_list">Database Manager</div></html>')
        elif self.path.startswith("/web/login"):
            self._html('<html><title>Login | Odoo</title><link href="/web/static/src/x.css"></html>')
        elif self.path == "/":
            self._html("<html><title>Redirect</title></html>")
        else:
            self._html("not found", 404)


HTTPServer(("127.0.0.1", ARGS.port), H).serve_forever()
