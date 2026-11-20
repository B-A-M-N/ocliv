#!/usr/bin/env python3
"""Loopback-only harmless MCP upstream for isolated Pi qualification."""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

state = {"execs": 0, "last_auth_present": False, "last_sub": None, "last_route": None}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def send_json(self, value):
        body = json.dumps(value).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path != "/__tally__":
            self.send_error(404)
            return
        self.send_json(state)

    def do_POST(self):
        if self.path != "/mcp":
            self.send_error(404)
            return
        size = int(self.headers.get("Content-Length", "0"))
        if size < 0 or size > 1 << 20:
            self.send_error(413)
            return
        try:
            request = json.loads(self.rfile.read(size))
        except (ValueError, json.JSONDecodeError):
            self.send_error(400)
            return
        state["execs"] += 1
        state["last_auth_present"] = bool(self.headers.get("Authorization"))
        state["last_sub"] = self.headers.get("X-Ocliv-Upstream-Sub")
        state["last_route"] = self.headers.get("X-Ocliv-Route")
        method = request.get("method")
        if method == "tools/list":
            result = {"tools": [{
                "name": "ping",
                "description": "harmless isolated qualification probe",
                "inputSchema": {"type": "object", "properties": {}},
            }]}
        elif method == "tools/call":
            result = {"content": [{"type": "text", "text": "pong:ocliv-isolated-stage"}]}
        else:
            result = {}
        self.send_json({"jsonrpc": "2.0", "id": request.get("id", 1), "result": result})


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 28099
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
