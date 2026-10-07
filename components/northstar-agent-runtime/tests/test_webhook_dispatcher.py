"""Tests for webhook_dispatcher: signed callbacks + deterministic retry ledger."""

import ast
import unittest
from pathlib import Path

from webhook_dispatcher import (
    BACKOFF_BASE_SEQS,
    BACKOFF_MAX_SEQS,
    DEFAULT_MAX_ATTEMPTS,
    SCHEMA_PIN,
    WEBHOOK_DISPATCHER_VERSION,
    DeliveryRecord,
    DuplicateEndpointError,
    EndpointRecord,
    RetryDecision,
    TerminalDeliveryError,
    UnknownDeliveryError,
    UnknownEndpointError,
    VerificationReport,
    WebhookDispatcher,
    WebhookError,
    backoff_seqs,
    compute_signature,
    verify_sig,
    webhook_dispatcher_audit_event,
)

MODULE_PATH = Path(__file__).resolve().parent.parent / "webhook_dispatcher.py"


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(WEBHOOK_DISPATCHER_VERSION, "webhook-dispatcher.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.webhook-dispatcher.v1")


class TestRegistration(unittest.TestCase):
    def setUp(self):
        self.d = WebhookDispatcher()

    def test_register_happy_path(self):
        rec = self.d.register("gh", "https://example.com/hook", "s3cr3t", 0)
        self.assertIsInstance(rec, EndpointRecord)
        self.assertEqual(rec.endpoint_id, "gh")
        self.assertEqual(rec.url, "https://example.com/hook")
        self.assertEqual(rec.version, WEBHOOK_DISPATCHER_VERSION)
        self.assertTrue(rec.digest.startswith("sha256:"))
        body = rec.as_dict()
        self.assertEqual(body["schema"], SCHEMA_PIN)
        # the secret must never appear in the record or its dict form
        self.assertNotIn("s3cr3t", repr(body))
        self.assertNotIn("s3cr3t", str(body))

    def test_register_bytes_secret(self):
        rec = self.d.register("a", "https://example.com/a", b"bytes-secret", 1)
        self.assertEqual(rec.endpoint_id, "a")

    def test_register_duplicate_refused(self):
        self.d.register("dup", "https://example.com/d", "x", 0)
        with self.assertRaises(DuplicateEndpointError):
            self.d.register("dup", "https://example.com/other", "y", 1)

    def test_register_http_url_refused(self):
        with self.assertRaises(WebhookError):
            self.d.register("p", "http://example.com/hook", "x", 0)

    def test_register_userinfo_url_refused(self):
        with self.assertRaises(WebhookError):
            self.d.register("p", "https://user:pw@example.com/hook", "x", 0)

    def test_register_hostless_url_refused(self):
        with self.assertRaises(WebhookError):
            self.d.register("p", "https:///no-host", "x", 0)

    def test_register_bad_inputs(self):
        with self.assertRaises(WebhookError):
            self.d.register("", "https://example.com/h", "x", 0)
        with self.assertRaises(WebhookError):
            self.d.register(123, "https://example.com/h", "x", 0)
        with self.assertRaises(WebhookError):
            self.d.register("p", "https://example.com/h", "", 0)
        with self.assertRaises(WebhookError):
            self.d.register("p", "https://example.com/h", True, 0)
        with self.assertRaises(WebhookError):
            self.d.register("p", "https://example.com/h", "x", -1)
        with self.assertRaises(WebhookError):
            self.d.register("p", "https://example.com/h", "x", True)

    def test_remove_and_endpoints_view(self):
        self.d.register("b", "https://example.com/b", "x", 0)
        self.d.register("a", "https://example.com/a", "y", 1)
        ids = [e.endpoint_id for e in self.d.endpoints()]
        self.assertEqual(ids, ["a", "b"])
        self.d.remove("a", 2)
        self.assertEqual([e.endpoint_id for e in self.d.endpoints()], ["b"])
        with self.assertRaises(UnknownEndpointError):
            self.d.remove("a", 3)
        # dispatch after removal must refuse: the secret is forgotten too
        with self.assertRaises(UnknownEndpointError):
            self.d.dispatch("a", "evt", {}, 4)


class TestDispatch(unittest.TestCase):
    def setUp(self):
        self.d = WebhookDispatcher()
        self.d.register("ep", "https://example.com/hook", "topsecret", 0)

    def test_dispatch_happy_path(self):
        payload = {"id": "evt_1", "n": 3}
        rec = self.d.dispatch("ep", "order.created", payload, 1)
        self.assertIsInstance(rec, DeliveryRecord)
        self.assertTrue(rec.delivery_id.startswith("dlv-"))
        self.assertEqual(rec.endpoint_id, "ep")
        self.assertEqual(rec.event_type, "order.created")
        self.assertTrue(rec.payload_digest.startswith("sha256:"))
        self.assertTrue(rec.signature.startswith("sha256="))
        self.assertEqual(rec.attempt, 0)
        self.assertEqual(rec.max_attempts, DEFAULT_MAX_ATTEMPTS)
        self.assertEqual(rec.status, "scheduled")
        self.assertTrue(rec.digest.startswith("sha256:"))
        # signature must verify under the registered secret
        self.assertTrue(verify_sig("topsecret", payload, rec.signature))

    def test_dispatch_ids_monotonic(self):
        r1 = self.d.dispatch("ep", "a", {}, 1)
        r2 = self.d.dispatch("ep", "a", {}, 2)
        self.assertNotEqual(r1.delivery_id, r2.delivery_id)
        self.assertLess(r1.delivery_id, r2.delivery_id)

    def test_dispatch_unknown_endpoint(self):
        with self.assertRaises(UnknownEndpointError):
            self.d.dispatch("ghost", "a", {}, 1)

    def test_dispatch_uncanon_payload_refused(self):
        with self.assertRaises(WebhookError):
            self.d.dispatch("ep", "a", {"bad": float("nan")}, 1)

    def test_dispatch_bad_inputs(self):
        with self.assertRaises(WebhookError):
            self.d.dispatch("ep", "", {}, 1)
        with self.assertRaises(WebhookError):
            self.d.dispatch("ep", "a", {}, -1)
        with self.assertRaises(WebhookError):
            self.d.dispatch("ep", "a", {}, 1, max_attempts=0)
        with self.assertRaises(WebhookError):
            self.d.dispatch("ep", "a", {}, 1, max_attempts=True)


class TestVerifySig(unittest.TestCase):
    def test_roundtrip(self):
        payload = {"a": [1, 2], "b": "x"}
        sig = compute_signature(b"key", payload)
        self.assertTrue(sig.startswith("sha256="))
        self.assertEqual(len(sig), len("sha256=") + 64)
        self.assertTrue(verify_sig(b"key", payload, sig))
        self.assertTrue(verify_sig("key", payload, sig))

    def test_wrong_secret_or_payload(self):
        sig = compute_signature(b"key", {"a": 1})
        self.assertFalse(verify_sig(b"other", {"a": 1}, sig))
        self.assertFalse(verify_sig(b"key", {"a": 2}, sig))

    def test_malformed_signature_is_false_not_raise(self):
        for bad in ("", "sha256=", "md5=" + "ab" * 32, "sha256=" + "zz" * 32,
                    "sha256=" + "ab" * 16, 123, None, True):
            self.assertFalse(verify_sig("key", {"a": 1}, bad))

    def test_compute_signature_wrong_secret_type(self):
        with self.assertRaises(TypeError):
            compute_signature("not-bytes", {})

    def test_verify_sig_bad_secret_type(self):
        with self.assertRaises(WebhookError):
            verify_sig(123, {}, compute_signature(b"k", {}))


class TestRetryLedger(unittest.TestCase):
    def setUp(self):
        self.d = WebhookDispatcher()
        self.d.register("ep", "https://example.com/hook", "s", 0)

    def test_success_path(self):
        rec = self.d.dispatch("ep", "a", {"x": 1}, 1)
        dec = self.d.report(rec.delivery_id, True, 2)
        self.assertIsInstance(dec, RetryDecision)
        self.assertEqual(dec.status, "delivered")
        self.assertEqual(dec.attempt, 0)
        self.assertEqual(dec.backoff_seqs, 0)
        self.assertEqual(self.d.delivery_status(rec.delivery_id), "delivered")
        self.assertEqual(self.d.pending(), ())

    def test_retry_then_success(self):
        rec = self.d.dispatch("ep", "a", {"x": 1}, 1, max_attempts=3)
        d1 = self.d.report(rec.delivery_id, False, 2)
        self.assertEqual(d1.status, "retrying")
        self.assertEqual(d1.attempt, 1)
        self.assertEqual(d1.backoff_seqs, 1)
        self.assertIn(rec.delivery_id, self.d.pending())
        d2 = self.d.report(rec.delivery_id, True, 3)
        self.assertEqual(d2.status, "delivered")

    def test_exponential_backoff_schedule(self):
        rec = self.d.dispatch("ep", "a", {}, 1, max_attempts=10)
        delays = [self.d.report(rec.delivery_id, False, i + 2).backoff_seqs
                  for i in range(7)]
        self.assertEqual(delays, [1, 2, 4, 8, 16, 32, 64])

    def test_backoff_cap(self):
        self.assertEqual(backoff_seqs(100), BACKOFF_MAX_SEQS)
        with self.assertRaises(WebhookError):
            backoff_seqs(0)
        with self.assertRaises(WebhookError):
            backoff_seqs(True)

    def test_exhaustion_goes_dead(self):
        rec = self.d.dispatch("ep", "a", {}, 1, max_attempts=3)
        self.d.report(rec.delivery_id, False, 2)
        self.d.report(rec.delivery_id, False, 3)
        dec = self.d.report(rec.delivery_id, False, 4)
        self.assertEqual(dec.status, "dead")
        self.assertEqual(dec.attempt, 3)
        self.assertEqual(dec.backoff_seqs, 0)
        self.assertEqual(self.d.delivery_status(rec.delivery_id), "dead")
        self.assertEqual(self.d.pending(), ())

    def test_terminal_report_refused(self):
        rec = self.d.dispatch("ep", "a", {}, 1, max_attempts=1)
        self.d.report(rec.delivery_id, False, 2)  # -> dead immediately
        with self.assertRaises(TerminalDeliveryError):
            self.d.report(rec.delivery_id, True, 3)

    def test_report_unknown_delivery(self):
        with self.assertRaises(UnknownDeliveryError):
            self.d.report("dlv-999", True, 1)

    def test_report_non_bool_ok_refused(self):
        rec = self.d.dispatch("ep", "a", {}, 1)
        with self.assertRaises(WebhookError):
            self.d.report(rec.delivery_id, "yes", 2)

    def test_delivery_view_and_unknown(self):
        rec = self.d.dispatch("ep", "a", {}, 1)
        self.assertEqual(self.d.delivery(rec.delivery_id).delivery_id,
                         rec.delivery_id)
        with self.assertRaises(UnknownDeliveryError):
            self.d.delivery("dlv-999")
        with self.assertRaises(UnknownDeliveryError):
            self.d.delivery_status("dlv-999")


class TestVerifyDelivery(unittest.TestCase):
    def setUp(self):
        self.d = WebhookDispatcher()
        self.d.register("ep", "https://example.com/hook", "s3cr3t", 0)

    def test_verify_delivery_happy_path(self):
        payload = {"id": 1}
        rec = self.d.dispatch("ep", "a", payload, 1)
        rep = self.d.verify_delivery(rec.delivery_id, payload, rec.signature)
        self.assertIsInstance(rep, VerificationReport)
        self.assertTrue(rep.valid)
        self.assertEqual(rep.version, WEBHOOK_DISPATCHER_VERSION)

    def test_verify_delivery_tampered(self):
        payload = {"id": 1}
        rec = self.d.dispatch("ep", "a", payload, 1)
        rep = self.d.verify_delivery(rec.delivery_id, {"id": 2}, rec.signature)
        self.assertFalse(rep.valid)

    def test_verify_delivery_unknown(self):
        with self.assertRaises(UnknownDeliveryError):
            self.d.verify_delivery("dlv-999", {}, "sha256=" + "ab" * 32)


class TestAuditEvents(unittest.TestCase):
    def setUp(self):
        self.d = WebhookDispatcher()

    def test_shapes(self):
        ep = self.d.register("ep", "https://example.com/h", "regsecret", 0)
        ev = webhook_dispatcher_audit_event("endpoint-registered", 1, endpoint=ep)
        self.assertEqual(ev["event"], "webhook-dispatcher-endpoint-registered")
        self.assertEqual(ev["audit_seq"], 1)
        self.assertEqual(ev["schema"], SCHEMA_PIN)
        self.assertNotIn("regsecret", str(ev))

        rec = self.d.dispatch("ep", "a", {"x": 1}, 2)
        ev2 = webhook_dispatcher_audit_event("dispatched", 3, delivery=rec)
        self.assertEqual(ev2["delivery_id"], rec.delivery_id)
        self.assertEqual(ev2["payload_digest"], rec.payload_digest)

        dec = self.d.report(rec.delivery_id, False, 4)
        ev3 = webhook_dispatcher_audit_event(
            "delivery-reported", 5, delivery=rec, decision=dec)
        self.assertEqual(ev3["status"], "retrying")
        self.assertEqual(ev3["backoff_seqs"], 1)

    def test_no_secret_or_payload_leak(self):
        ep = self.d.register("ep", "https://example.com/h", "supersecret", 0)
        rec = self.d.dispatch("ep", "a", {"token": "abc123"}, 1)
        ev = webhook_dispatcher_audit_event("dispatched", 2, delivery=rec)
        blob = str(ev)
        self.assertNotIn("supersecret", blob)
        self.assertNotIn("abc123", blob)

    def test_bad_kind_and_types(self):
        with self.assertRaises(ValueError):
            webhook_dispatcher_audit_event("nope", 0)
        with self.assertRaises(WebhookError):
            webhook_dispatcher_audit_event("dispatched", -1)
        with self.assertRaises(TypeError):
            webhook_dispatcher_audit_event("dispatched", 0, endpoint="x")


class TestHouseStyle(unittest.TestCase):
    def test_stdlib_only(self):
        tree = ast.parse(MODULE_PATH.read_text())
        allowed = {
            "hashlib", "hmac", "threading", "dataclasses", "typing",
            "urllib", "urllib.parse", "__future__", "json", "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed, a.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed,
                              node.module)

    def test_main_self_check(self):
        import subprocess
        import sys
        out = subprocess.run(
            [sys.executable, str(MODULE_PATH)],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("webhook-dispatcher OK", out.stdout)


if __name__ == "__main__":
    unittest.main()
