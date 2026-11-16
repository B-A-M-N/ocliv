#!/usr/bin/env python3
"""End-to-end regression tests for verify-ingress.sh protocol handling."""
import json
import datetime
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


SCRIPT = Path(__file__).with_name("verify-ingress.sh")
ROUTE_ID = "route-test-1"
TOKEN = "fixture-token"
PROTOCOL = "2026-07-28"


class FixtureServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler, stateful, sse, transition=False):
        super().__init__(address, handler)
        self.stateful = stateful
        self.sse = sse
        self.transition = transition
        self.session_id = "fixture-session-1"
        self.route = f"https://localhost:{self.server_port}/r/{ROUTE_ID}/mcp"
        self.issuer = f"https://localhost:{self.server_port}/r/{ROUTE_ID}/oauth"


class Handler(BaseHTTPRequestHandler):
    server: FixtureServer

    def log_message(self, *_args):
        pass

    def _send(self, status, body=b"", content_type="application/json", extra=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        if self.path == f"/.well-known/oauth-protected-resource/r/{ROUTE_ID}/mcp":
            self._send(200, json.dumps({"resource": self.server.route}).encode())
        elif self.path == f"/.well-known/oauth-authorization-server/r/{ROUTE_ID}/oauth":
            self._send(200, json.dumps({"issuer": self.server.issuer}).encode())
        else:
            self._send(404)

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.path != f"/r/{ROUTE_ID}/mcp":
            self._send(404)
            return
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            self._send(401)
            return
        try:
            request = json.loads(raw)
        except Exception:
            self._send(400)
            return
        method = request.get("method")
        extra = {}
        if method == "initialize":
            result = {"jsonrpc": "2.0", "id": request["id"], "result": {
                "protocolVersion": PROTOCOL, "capabilities": {"tools": {}},
                "serverInfo": {"name": "fixture", "version": "1"}}}
            extra["Mcp-Protocol-Version"] = PROTOCOL
            if self.server.stateful:
                extra["Mcp-Session-Id"] = self.server.session_id
            self._send(200, json.dumps(result).encode(), extra=extra)
            return
        if self.server.stateful:
            if self.headers.get("Mcp-Session-Id") != self.server.session_id or self.headers.get("Mcp-Protocol-Version") != PROTOCOL:
                self._send(400)
                return
        elif self.headers.get("Mcp-Session-Id"):
            self._send(400)
            return
        if method == "notifications/initialized":
            self._send(202)
            return
        if method == "tools/list":
            response = {"jsonrpc": "2.0", "id": request["id"], "result": {"tools": [{"name": "ping"}]}}
        elif method == "tools/call":
            response = {"jsonrpc": "2.0", "id": request["id"], "result": {"content": [{"type": "text", "text": "pong:fixture"}]}}
        else:
            self._send(404)
            return
        extra = {"Mcp-Session-Id": self.server.session_id} if self.server.stateful else {}
        if self.server.transition and method == "tools/list":
            extra["Mcp-Session-Id"] = "different-session"
        encoded = json.dumps(response).encode()
        if self.server.sse:
            body = b"event: message\ndata: " + encoded + b"\n\n"
            self._send(200, body, "text/event-stream", extra)
        else:
            self._send(200, encoded, extra=extra)


class VerifyIngressTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="ocliv-ingress-tests-")
        cls.cert = Path(cls.temp.name) / "localhost.pem"
        cls.key = Path(cls.temp.name) / "localhost-key.pem"
        cls.signing_key = Path(cls.temp.name) / "receipt-key.pem"
        cls.verify_key = Path(cls.temp.name) / "receipt-public.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(cls.key), "-out", str(cls.cert), "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
                        "rsa_keygen_bits:2048", "-out", str(cls.signing_key)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.signing_key.chmod(0o600)
        with cls.verify_key.open("wb") as public:
            subprocess.run(["openssl", "pkey", "-in", str(cls.signing_key), "-pubout"],
                           check=True, stdout=public, stderr=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_verifier(self, stateful, sse, transition=False, expect_success=True, receipt=False):
        server = FixtureServer(("127.0.0.1", 0), Handler, stateful, sse, transition)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            env = os.environ.copy()
            env.update({"MCP_TOKEN": TOKEN, "MCP_CACERT": str(self.cert)})
            args = [str(SCRIPT)]
            receipt_path = Path(self.temp.name) / "qualification.json"
            if receipt:
                env.update({"OCLIV_SOURCE_REVISION": "source-revision-test",
                            "OCLIV_ARTIFACT_SHA256": "a" * 64,
                            "OCLIV_RECEIPT_SIGNING_KEY": str(self.signing_key)})
                args.append(f"--receipt={receipt_path}")
            args.append(server.route)
            result = subprocess.run(args, env=env, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            if expect_success:
                self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
                self.assertIn("PASS: ingress verified", result.stdout)
            else:
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("session ID changed", result.stderr)
            if receipt and expect_success:
                receipt_data = json.loads(receipt_path.read_text(encoding="utf-8"))
                self.assertEqual(receipt_data["source_revision"], "source-revision-test")
                self.assertEqual(receipt_data["artifact_sha256"], "a" * 64)
                subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(self.verify_key),
                                "-signature", str(receipt_path) + ".sig", str(receipt_path)],
                               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_stateful_server_with_session_headers_and_sse(self):
        self.run_verifier(stateful=True, sse=True)

    def test_stateless_server_with_json_responses(self):
        self.run_verifier(stateful=False, sse=False)

    def test_rejects_session_identity_transition(self):
        self.run_verifier(stateful=True, sse=False, transition=True, expect_success=False)

    def test_signed_receipt_binds_source_and_artifact(self):
        self.run_verifier(stateful=False, sse=False, receipt=True)

    def test_release_builder_requires_valid_receipt_signature(self):
        route = "https://qualified.example.net/r/route-test-1/mcp"
        receipt = Path(self.temp.name) / "builder-qualification.json"
        receipt_data = {
            "route_url": route,
            "source_revision": "builder-source-test",
            "artifact_sha256": "b" * 64,
            "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "resource_discovery_verified": True,
            "authorization_server_discovery_verified": True,
            "missing_bearer_rejected": True,
            "invalid_bearer_rejected": True,
            "authenticated_tools_list_verified": True,
            "authenticated_tool_execution_verified": True,
        }
        receipt.write_text(json.dumps(receipt_data, sort_keys=True) + "\n", encoding="utf-8")
        env = os.environ.copy()
        env.update({
            "OCLIV_QUALIFIED_MCP_URL": route,
            "OCLIV_MCP_QUALIFICATION_RECEIPT": str(receipt),
            "OCLIV_RECEIPT_VERIFY_KEY": str(self.verify_key),
            "OCLIV_SOURCE_REVISION": "builder-source-test",
            "OCLIV_ARTIFACT_SHA256": "b" * 64,
        })
        output = Path(self.temp.name) / "plugin-release"
        builder = SCRIPT.parents[1] / "build-plugin.sh"
        unsigned = subprocess.run([str(builder), "--release", str(output)], env=env,
                                  text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertNotEqual(unsigned.returncode, 0, unsigned.stdout)
        self.assertIn("signed", unsigned.stdout + unsigned.stderr)
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(self.signing_key),
                        "-out", str(receipt) + ".sig", str(receipt)], check=True)
        signed = subprocess.run([str(builder), "--release", str(output)], env=env,
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(signed.returncode, 0, signed.stdout + signed.stderr)
        receipt.write_text(receipt.read_text(encoding="utf-8").replace("b" * 64, "c" * 64), encoding="utf-8")
        tampered = subprocess.run([str(builder), "--release", str(output)], env=env,
                                  text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertNotEqual(tampered.returncode, 0, tampered.stdout)


if __name__ == "__main__":
    unittest.main()
