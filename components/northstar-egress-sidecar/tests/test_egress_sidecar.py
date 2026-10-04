"""Egress sidecar: validation, credential brokering, and the enforcement boundary.

The invariant under test: the sidecar resolves DNS itself, authorizes the
resolved destination at CONNECT time, injects brokered credentials where the
agent cannot see them, scrubs credential reflections from responses, and
refuses to start when a referenced credential is missing.
"""
from __future__ import annotations

import base64
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import MappingProxyType

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("NORTHSTAR_RUNTIME_DIR", str(Path(__file__).resolve().parent.parent.parent / "northstar-agent-runtime"))
sys.path.insert(0, os.environ["NORTHSTAR_RUNTIME_DIR"])

from egress_sidecar import (  # noqa: E402
    CredentialStore,
    SidecarContext,
    build_context,
    classify_request,
    run_one,
)
from egress_enforcer import DestinationRule, EgressPolicy  # noqa: E402
from transport import decode_request, encode_response  # noqa: E402

POLICY_TOML = """\
schema_version = "northstar.egress.v1"
revision = "test.r1"

[destinations.local]
hosts = ["svc.local"]
ports = [18090]
methods = ["POST"]
path_prefixes = ["/api"]
allow_private_ips = true
tls = false

[destinations.hook]
hosts = ["hook.local"]
ports = [18091]
methods = ["POST"]
path_prefixes = ["/deploy"]
credential = "hook-token"
allow_private_ips = true
tls = false
"""


def wire(**overrides):
    base = {
        "request_id": "r-1",
        "agent_id": "a1",
        "run_id": "run1",
        "host": "svc.local",
        "port": 18090,
        "method": "POST",
        "path": "/api/echo",
        "headers": {"content-type": "application/json"},
        "body_b64": base64.b64encode(b'{"x":1}').decode(),
        "timeout_ms": 5000,
    }
    base.update(overrides)
    return base


class ValidationTests(unittest.TestCase):
    def test_valid_request(self):
        self.assertTrue(classify_request(wire()).ok)

    def test_missing_fields_rejected(self):
        v = classify_request({"request_id": "r"})
        self.assertFalse(v.ok)
        self.assertTrue(v.errors)

    def test_body_b64_bounded(self):
        v = classify_request(wire(body_b64="A" * 1_900_000))
        self.assertFalse(v.ok)

    def test_invalid_b64_rejected(self):
        v = classify_request(wire(body_b64="!!!not-base64!!!"))
        self.assertFalse(v.ok)

    def test_timeout_bounded(self):
        self.assertFalse(classify_request(wire(timeout_ms=999)).ok)
        self.assertFalse(classify_request(wire(timeout_ms=999_999)).ok)

    def test_transport_round_trip(self):
        line = encode_response({"a": 1})
        self.assertEqual(decode_request(line.rstrip("\n")), {"a": 1})
        self.assertIsNone(decode_request("not json"))


class SidecarTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy_dir = tempfile.mkdtemp()
        Path(cls.policy_dir, "northstar-egress.toml").write_text(POLICY_TOML)
        os.environ["NORTHSTAR_EGRESS_CRED_HOOK_TOKEN"] = "hook-secret-value"

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                # Malicious endpoint: reflects the Authorization header.
                auth = self.headers.get("Authorization", "")
                payload = b'{"auth_seen":"' + auth.encode() + b'","len":' + str(len(body)).encode() + b"}"
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *a):
                pass

        cls.server = HTTPServer(("127.0.0.1", 18090), Handler)
        cls.server2 = HTTPServer(("127.0.0.1", 18091), Handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        threading.Thread(target=cls.server2.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server2.shutdown()
        os.environ.pop("NORTHSTAR_EGRESS_CRED_HOOK_TOKEN", None)

    def _ctx(self):
        ctx = build_context(policy_dir=self.policy_dir)
        ctx._resolver = lambda h: ["127.0.0.1"]
        return ctx

    def test_allow_end_to_end(self):
        resp = run_one(wire(), self._ctx())
        self.assertEqual(resp["status"], "ok")
        self.assertEqual(resp["http_status"], 200)
        body = base64.b64decode(resp["body_b64"]).decode()
        self.assertIn('"len":7', body)
        self.assertEqual(resp["receipt"]["verdict"], "allow")

    def test_deny_unlisted(self):
        resp = run_one(wire(host="evil.com"), self._ctx())
        self.assertEqual(resp["status"], "denied")
        self.assertEqual(resp["deny_code"], "egress.destination_denied")
        self.assertIn("deny_code", resp["receipt"])

    def test_credential_injected_server_side(self):
        req = wire(host="hook.local", port=18091, path="/deploy")
        resp = run_one(req, self._ctx())
        self.assertEqual(resp["status"], "ok")
        body = base64.b64decode(resp["body_b64"]).decode()
        # The server saw a real bearer token...
        self.assertIn("Bearer", body)
        # ...but the agent never sees the value (reflection scrubbed).
        self.assertNotIn("hook-secret-value", body)
        self.assertIn("[REDACTED]", body)

    def test_smuggled_auth_denied(self):
        req = wire(host="hook.local", port=18091, path="/deploy", headers={"Authorization": "Bearer stolen"})
        resp = run_one(req, self._ctx())
        self.assertEqual(resp["status"], "denied")
        self.assertEqual(resp["deny_code"], "egress.credentialless_bypass_attempt")

    def test_malformed_wire_rejected(self):
        resp = run_one({"request_id": "r-bad"}, self._ctx())
        self.assertEqual(resp["status"], "rejected")

    def test_missing_credential_refuses_startup(self):
        os.environ.pop("NORTHSTAR_EGRESS_CRED_HOOK_TOKEN", None)
        try:
            with self.assertRaises(Exception):
                build_context(policy_dir=self.policy_dir)
        finally:
            os.environ["NORTHSTAR_EGRESS_CRED_HOOK_TOKEN"] = "hook-secret-value"


if __name__ == "__main__":
    unittest.main()
