"""Egress sidecar: validation, credential brokering, and the enforcement boundary.

The invariant under test: the sidecar resolves DNS itself, authorizes the
resolved destination at CONNECT time, injects brokered credentials where the
agent cannot see them, scrubs credential reflections from responses, and
refuses to start when a referenced credential is missing.
"""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from unittest import mock
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
    _scrub_bytes,
)
from egress_enforcer import DestinationRule, EgressPolicy, EgressPolicyError  # noqa: E402
from transport import decode_request, encode_response  # noqa: E402
import egress_socket  # noqa: E402
import egress_sidecar  # noqa: E402

POLICY_TOML = """\
schema_version = "northstar.egress.v1"
revision = "test.r1"

[destinations.local]
hosts = ["svc.local"]
ports = [18090, 18092]
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
    def test_response_cap_marks_exactly_one_extra_byte_as_truncated(self):
        class FakeResponse:
            status = 200

            def getheaders(self):
                return []

            def read(self, _size):
                return b"x" * (egress_sidecar.MAX_RESPONSE_BYTES + 1)

        class FakeConnection:
            def request(self, *_args, **_kwargs):
                pass

            def getresponse(self):
                return FakeResponse()

            def close(self):
                pass

        with mock.patch.object(egress_sidecar, "_PinnedHTTPConnection", return_value=FakeConnection()):
            status, headers, body, truncated = egress_sidecar._perform_http(
                host="svc.local", dial_ip="127.0.0.1", port=18090,
                tls=False, method="GET", path="/", headers={}, body=b"", timeout_s=1,
            )
        self.assertEqual(status, 200)
        self.assertEqual(headers, {})
        self.assertEqual(len(body), egress_sidecar.MAX_RESPONSE_BYTES)
        self.assertTrue(truncated)

    def test_production_signing_seed_is_required_and_strictly_parsed(self):
        self.assertEqual(
            egress_socket.signing_seed_from_environment({"NORTHSTAR_EGRESS_SIGNING_SEED": "ab" * 32}),
            bytes.fromhex("ab" * 32),
        )
        for environ in (
            {},
            {"NORTHSTAR_EGRESS_SIGNING_SEED": "not-hex"},
            {"NORTHSTAR_EGRESS_SIGNING_SEED": "ab" * 31},
            {"NORTHSTAR_EGRESS_SIGNING_SEED": "ab " * 32},
        ):
            with self.subTest(environ=environ), self.assertRaises(ValueError):
                egress_socket.signing_seed_from_environment(environ)
        self.assertEqual(egress_socket.key_id_from_environment({"NORTHSTAR_EGRESS_KEY_ID": "ops-v1"}), "ops-v1")
        with self.assertRaises(ValueError):
            egress_socket.key_id_from_environment({})

    def test_trusted_public_key_file_is_bounded_and_validated(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trusted.json"
            self.assertEqual(egress_socket.trusted_public_keys_from_file(path), {})
            path.write_text(json.dumps({"ops-old": "ab" * 32}), encoding="utf-8")
            self.assertEqual(
                egress_socket.trusted_public_keys_from_file(path), {"ops-old": bytes.fromhex("ab" * 32)}
            )
            path.write_text('{"ops-old":"bad"}', encoding="utf-8")
            with self.assertRaises(ValueError):
                egress_socket.trusted_public_keys_from_file(path)
            path.write_text('{"ops-old":"' + "ab" * 32 + '","ops-old":"' + "cd" * 32 + '"}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate key IDs"):
                egress_socket.trusted_public_keys_from_file(path)

    def test_valid_request(self):
        self.assertTrue(classify_request(wire()).ok)

    def test_missing_fields_rejected(self):
        v = classify_request({"request_id": "r"})
        self.assertFalse(v.ok)
        self.assertTrue(v.errors)

    def test_body_b64_bounded(self):
        v = classify_request(wire(body_b64="A" * 1_900_000))
        self.assertFalse(v.ok)

    def test_credential_scrubbing_preserves_non_utf8_response_bytes(self):
        self.assertEqual(
            _scrub_bytes(b"\x00\xffBearer token\x80", ("Bearer token",)),
            b"\x00\xff[REDACTED]\x80",
        )

    def test_invalid_b64_rejected(self):
        v = classify_request(wire(body_b64="!!!not-base64!!!"))
        self.assertFalse(v.ok)

    def test_timeout_bounded(self):
        self.assertFalse(classify_request(wire(timeout_ms=999)).ok)
        self.assertFalse(classify_request(wire(timeout_ms=999_999)).ok)

    def test_http_injection_and_caller_framing_headers_rejected(self):
        for bad in (
            wire(path="/api/echo\r\nHost: attacker.example"),
            wire(path="//attacker.example/api"),
            wire(path="/api/☃"),
            wire(host=" svc.local"),
            wire(host="svc.local/path"),
            wire(method="POST\r\nGET"),
            wire(headers={"X-Test\r\nInjected": "yes"}),
            wire(headers={"X-Test": "ok\r\nInjected: yes"}),
            wire(headers={"Transfer-Encoding": "chunked"}),
            wire(headers={"Content-Length": "999"}),
            wire(headers={"Connection": "keep-alive"}),
        ):
            self.assertFalse(classify_request(bad).ok, bad)

    def test_transport_round_trip(self):
        line = encode_response({"a": 1})
        self.assertEqual(decode_request(line.rstrip("\n")), {"a": 1})
        self.assertIsNone(decode_request("not json"))

    def test_socket_reader_enforces_wire_cap_including_newline(self):
        original = egress_socket.MAX_LINE_BYTES
        egress_socket.MAX_LINE_BYTES = 5
        try:
            for payload, expected in ((b"1234\n", "1234"), (b"12345\n", None), (b"12345", None)):
                with self.subTest(payload=payload):
                    reader, writer = socket.socketpair()
                    try:
                        writer.sendall(payload)
                        writer.shutdown(socket.SHUT_WR)
                        self.assertEqual(egress_socket.read_json_line(reader), expected)
                    finally:
                        reader.close()
                        writer.close()
        finally:
            egress_socket.MAX_LINE_BYTES = original

    def test_socket_reader_rejects_invalid_utf8(self):
        reader, writer = socket.socketpair()
        try:
            writer.sendall(b'{"x":"' + bytes([0xFF]) + b'"}\n')
            writer.shutdown(socket.SHUT_WR)
            self.assertIsNone(egress_socket.read_json_line(reader))
        finally:
            reader.close()
            writer.close()

    def test_socket_server_closes_connections_when_capacity_is_full(self):
        slots = threading.BoundedSemaphore(1)
        self.assertTrue(slots.acquire(blocking=False))
        accepted, peer = socket.socketpair()
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                self.assertFalse(egress_socket.submit_connection(pool, slots, accepted, None))
            self.assertEqual(accepted.fileno(), -1)
            self.assertEqual(peer.recv(1), b"")
        finally:
            peer.close()
            slots.release()


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
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server2_thread = threading.Thread(target=cls.server2.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.server2_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server2.shutdown()
        cls.server_thread.join(timeout=2)
        cls.server2_thread.join(timeout=2)
        cls.server.server_close()
        cls.server2.server_close()
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

    def test_agent_supplied_host_header_is_overridden(self):
        """E7: the sidecar forces Host to the authorized request host; an
        agent-supplied Host must not reach the upstream."""
        seen = {}

        class HostCaptureHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                seen["host"] = self.headers.get("Host", "")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *a):
                pass

        server = HTTPServer(("127.0.0.1", 18092), HostCaptureHandler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        try:
            req = wire(
                host="svc.local",
                port=18092,
                path="/api/echo",
                headers={"host": "attacker.example.com"},
            )
            resp = run_one(req, self._ctx())
            self.assertEqual(resp["status"], "ok")
            self.assertEqual(seen.get("host"), "svc.local")
        finally:
            server.shutdown()
            server_thread.join(timeout=2)
            server.server_close()

    def test_malformed_wire_rejected(self):
        resp = run_one({"request_id": "r-bad"}, self._ctx())
        self.assertEqual(resp["status"], "rejected")

    def test_rejected_carries_receipt(self):
        resp = run_one({"request_id": "r-bad"}, self._ctx())
        self.assertEqual(resp["status"], "rejected")
        receipt = resp.get("receipt")
        self.assertIsNotNone(receipt, "rejected requests must carry a receipt")
        self.assertEqual(receipt["kind"], "egress-rejection-receipt/1")
        self.assertEqual(receipt["request_id"], "r-bad")
        self.assertEqual(receipt["verdict"], "rejected")
        self.assertTrue(receipt["errors"], "receipt must record why it was rejected")
        # Tamper-evident: the receipt is hash-chained.
        self.assertIn("chain_hash", receipt)

    def test_rejection_receipt_bounds_malformed_input(self):
        from egress_enforcer import build_rejection_receipt

        huge = {"request_id": "r-huge", "blob": "x" * 10_000}
        receipt = build_rejection_receipt(
            raw_value=huge,
            errors=["too big"],
            request_id="r-huge",
            now=0.0,
        )
        preview = receipt["received"]["preview"]
        self.assertLessEqual(len(preview), 2_100, "preview must be bounded")
        self.assertIn("truncated", preview)

    def test_missing_credential_refuses_startup(self):
        os.environ.pop("NORTHSTAR_EGRESS_CRED_HOOK_TOKEN", None)
        try:
            with self.assertRaises(Exception):
                build_context(policy_dir=self.policy_dir)
        finally:
            os.environ["NORTHSTAR_EGRESS_CRED_HOOK_TOKEN"] = "hook-secret-value"


class ReceiptFeedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy_dir = tempfile.mkdtemp()
        Path(cls.policy_dir, "northstar-egress.toml").write_text(POLICY_TOML)
        os.environ["NORTHSTAR_EGRESS_CRED_HOOK_TOKEN"] = "hook-secret-value"

    @classmethod
    def tearDownClass(cls):
        os.environ.pop("NORTHSTAR_EGRESS_CRED_HOOK_TOKEN", None)

    def _ctx(self):
        ctx = build_context(policy_dir=self.policy_dir)
        ctx._resolver = lambda h: ["127.0.0.1"]
        return ctx

    def test_feed_appends_receipts(self):
        from pathlib import Path

        from egress_sidecar import ReceiptFeed, build_context, run_one

        with tempfile.TemporaryDirectory() as tmp:
            feed_path = Path(tmp) / "receipts.jsonl"
            feed = ReceiptFeed(feed_path)
            ctx = build_context(policy_dir=self.policy_dir, receipt_feed_path=feed_path)
            ctx._resolver = lambda h: ["127.0.0.1"]
            # Rejected request -> receipt persisted.
            resp = run_one({"request_id": "r-feed-1"}, ctx)
            self.assertEqual(resp["status"], "rejected")
            denied = run_one(wire(host="not-allowlisted.invalid"), ctx)
            self.assertEqual(denied["status"], "denied")
            self.assertTrue(feed_path.is_file())
            lines = feed_path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 2)
            record = json.loads(lines[0])
            self.assertEqual(record["request_id"], "r-feed-1")
            self.assertEqual(record["kind"], "egress-rejection-receipt/1")
            self.assertIn("chain_hash", record)
            from audit_chain import verify_lines

            self.assertTrue(verify_lines(lines).ok, "the complete receipt feed must form one chain")
            self.assertEqual(json.loads(lines[0])["chain_hash"], json.loads(lines[1])["prev_hash"])

    def test_legacy_singleton_receipts_are_verified_and_migrated_into_one_chain(self):
        from audit_chain import verify_lines
        from egress_enforcer import build_rejection_receipt
        from egress_sidecar import ReceiptFeed

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "legacy.jsonl"
            legacy = [
                build_rejection_receipt(
                    raw_value={"request_id": f"legacy-{i}"}, errors=["legacy"],
                    request_id=f"legacy-{i}", now=float(i),
                )
                for i in range(2)
            ]
            path.write_text("".join(json.dumps(item) + "\n" for item in legacy), encoding="utf-8")
            feed = ReceiptFeed(path)
            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertTrue(verify_lines(lines).ok)
            migrated = [json.loads(line) for line in lines]
            self.assertEqual([item["receipt"]["request_id"] for item in migrated], ["legacy-0", "legacy-1"])
            self.assertEqual(feed.appended, 2)

    def test_signed_feed_chain_verifies_and_reloads(self):
        from audit_chain import verify_lines
        from ed25519 import public_key
        from egress_sidecar import ReceiptFeed

        seed = bytes(range(32))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "signed.jsonl"
            feed = ReceiptFeed(path, enforcer_seed=seed, key_id="egress-test")
            self.assertTrue(feed.append({"kind": "test", "request_id": "signed-1"}))
            self.assertTrue(feed.append({"kind": "test", "request_id": "signed-2"}))
            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertTrue(verify_lines(lines, public_key=public_key(seed), expect_session_id=feed._session_id).ok)
            reloaded = ReceiptFeed(path, enforcer_seed=seed, key_id="egress-test")
            self.assertEqual(reloaded.appended, 2)
            unsigned_tail = json.loads(lines[-1])
            unsigned_tail.pop("signature")
            lines[-1] = json.dumps(unsigned_tail, sort_keys=True)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(EgressPolicyError, "signature is required"):
                ReceiptFeed(path, enforcer_seed=seed, key_id="egress-test")

    def test_key_rotation_verifies_old_entries_and_signs_new_entries(self):
        from audit_chain import verify_lines
        from ed25519 import public_key
        from egress_sidecar import ReceiptFeed

        old_seed = bytes(range(32))
        new_seed = bytes(range(1, 33))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rotated.jsonl"
            old_feed = ReceiptFeed(path, enforcer_seed=old_seed, key_id="ops-old")
            self.assertTrue(old_feed.append({"kind": "test", "request_id": "before-rotation"}))
            with self.assertRaises(EgressPolicyError):
                ReceiptFeed(path, enforcer_seed=new_seed, key_id="ops-new")
            new_feed = ReceiptFeed(
                path,
                enforcer_seed=new_seed,
                key_id="ops-new",
                trusted_public_keys={"ops-old": public_key(old_seed)},
            )
            self.assertTrue(new_feed.append({"kind": "test", "request_id": "after-rotation"}))
            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertTrue(verify_lines(
                lines,
                public_key={"ops-old": public_key(old_seed), "ops-new": public_key(new_seed)},
                require_signatures=True,
            ).ok)
            recovered = ReceiptFeed(
                path,
                enforcer_seed=new_seed,
                key_id="ops-new",
                trusted_public_keys={"ops-old": public_key(old_seed)},
            )
            self.assertEqual(recovered.appended, 2)

    def test_production_key_migrates_unsigned_legacy_feed(self):
        from audit_chain import chain_records
        from egress_sidecar import ReceiptFeed

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "legacy.jsonl"
            legacy = chain_records([{"kind": "test", "request_id": "legacy"}], component="legacy")
            path.write_text(json.dumps(legacy[0]) + "\n", encoding="utf-8")
            feed = ReceiptFeed(path, enforcer_seed=bytes(range(32)), key_id="egress-test")
            self.assertEqual(feed.appended, 1)
            migrated = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
            self.assertIn("signature", migrated)

    def test_allowed_request_is_not_sent_when_receipt_persistence_fails(self):
        from unittest.mock import patch
        from egress_sidecar import ReceiptFeed

        with tempfile.TemporaryDirectory() as tmp:
            blocked_parent = Path(tmp) / "not-a-directory"
            blocked_parent.write_text("file", encoding="utf-8")
            feed = ReceiptFeed(blocked_parent / "receipts.jsonl")
            ctx = self._ctx()
            ctx.receipt_feed = feed
            with patch("egress_sidecar._perform_http") as perform:
                response = run_one(wire(), ctx)
            self.assertEqual(response["status"], "error")
            self.assertIn("not sent", response["error"])
            self.assertFalse(perform.called, "no upstream request may occur without a durable receipt")
            self.assertEqual(response["receipt"]["verdict"], "allow")

    def test_allowed_receipt_is_persisted_once_before_request(self):
        from unittest.mock import patch
        from egress_sidecar import ReceiptFeed

        with tempfile.TemporaryDirectory() as tmp:
            feed_path = Path(tmp) / "receipts.jsonl"
            feed = ReceiptFeed(feed_path)
            # Idempotence must not depend on a bounded in-memory digest
            # cache: a slow request may finish after many later appends.
            feed._remember_digest = lambda digest: None
            ctx = self._ctx()
            ctx.receipt_feed = feed
            with patch("egress_sidecar._perform_http", return_value=(200, {}, b"ok", False)) as perform:
                response = run_one(wire(), ctx)
            self.assertEqual(response["status"], "ok")
            self.assertTrue(perform.called)
            lines = feed_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1, "the wrapper must not duplicate the preflight receipt")
            self.assertEqual(json.loads(lines[0])["receipt_id"], response["receipt"]["receipt_id"])

    def test_no_feed_no_persistence(self):
        # Without a feed path, run_one works but writes nothing.
        from egress_sidecar import run_one

        ctx = self._ctx()
        self.assertIsNone(ctx.receipt_feed)
        resp = run_one({"request_id": "r-nofeed"}, ctx)
        self.assertEqual(resp["status"], "rejected")
        self.assertIn("receipt", resp)  # receipt still returned to caller

    def test_feed_is_thread_safe(self):
        import threading
        from pathlib import Path

        from egress_sidecar import ReceiptFeed

        with tempfile.TemporaryDirectory() as tmp:
            feed = ReceiptFeed(Path(tmp) / "r.jsonl")
            errors: list[str] = []

            def worker(n: int) -> None:
                try:
                    for i in range(20):
                        ok = feed.append({"n": n, "i": i, "chain_hash": "x"})
                        if not ok:
                            errors.append(f"worker {n} append failed")
                except Exception as exc:  # noqa: BLE001
                    errors.append(str(exc))

            threads = [threading.Thread(target=worker, args=(n,)) for n in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            self.assertEqual(errors, [])
            self.assertEqual(feed.appended, 100)

    def test_feed_survives_unserializable(self):
        from pathlib import Path

        from egress_sidecar import ReceiptFeed

        with tempfile.TemporaryDirectory() as tmp:
            feed = ReceiptFeed(Path(tmp) / "r.jsonl")
            self.assertFalse(feed.append({"bad": object()}))
            self.assertIsNotNone(feed.last_error)


if __name__ == "__main__":
    unittest.main()
