"""Tests for webhook_manager: 20 cases."""

import ast
import sys
import os
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import unittest

from webhook_manager import (
    WebhookManager,
    WebhookRecord,
    DeliveryRecord,
    webhook_manager_audit_event,
    WebhookManagerError,
    UnknownWebhookError,
    DuplicateWebhookError,
    BadWebhookError,
    UnknownDeliveryError,
    AlreadyDeliveredError,
    MaxAttemptsError,
    BadDeliveryError,
    SeqOrderError,
    AuditKindError,
    WEBHOOK_MANAGER_VERSION,
    WEBHOOK_MANAGER_SCHEMA,
    MAX_ATTEMPTS,
)

DIGEST = "sha256:" + "ab" * 32


def _mgr(transport=None, seed="test"):
    return WebhookManager(seed=seed, transport=transport)


def _reg(mgr, wid="wh-1", seq=1, **kw):
    kw.setdefault("url", "https://example.com/hook")
    return mgr.register(wid, seq=seq, **kw)


class TestPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(WEBHOOK_MANAGER_VERSION, "webhook-manager.v1")
        self.assertEqual(WEBHOOK_MANAGER_SCHEMA, "northstar.webhook-manager.v1")
        self.assertEqual(MAX_ATTEMPTS, 5)

    def test_stdlib_only(self):
        path = os.path.join(os.path.dirname(__file__), "..", "webhook_manager.py")
        tree = ast.parse(open(path).read())
        allowed = {
            "hashlib", "hmac", "threading", "dataclasses", "typing",
            "__future__", "ast", "json", "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed, a.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed, node.module)


class TestRegister(unittest.TestCase):
    def test_roundtrip(self):
        mgr = _mgr()
        rec = _reg(mgr, events=("a.b",), secret="x" * 16, seq=1)
        self.assertIsInstance(rec, WebhookRecord)
        self.assertTrue(rec.verify())
        self.assertEqual(mgr.webhook("wh-1").webhook_id, "wh-1")

    def test_http_url_refused(self):
        mgr = _mgr()
        with self.assertRaises(BadWebhookError):
            _reg(mgr, url="http://example.com/hook", seq=1)

    def test_duplicate_id_refused(self):
        mgr = _mgr()
        _reg(mgr, seq=1)
        with self.assertRaises(DuplicateWebhookError):
            _reg(mgr, seq=2)

    def test_bad_inputs_refused(self):
        mgr = _mgr()
        with self.assertRaises(BadWebhookError):
            _reg(mgr, wid="", seq=1)
        with self.assertRaises(BadWebhookError):
            _reg(mgr, secret="short", seq=2)
        with self.assertRaises(BadWebhookError):
            _reg(mgr, events=("ok", ""), seq=3)

    def test_seq_order(self):
        mgr = _mgr()
        _reg(mgr, seq=1)
        with self.assertRaises(SeqOrderError):
            _reg(mgr, wid="wh-2", seq=1)
        with self.assertRaises(SeqOrderError):
            _reg(mgr, wid="wh-2", seq=True)
        with self.assertRaises(SeqOrderError):
            _reg(mgr, wid="wh-2", seq=-1)

    def test_secret_not_in_record(self):
        mgr = _mgr()
        secret = "top-secret-12345678"
        rec = _reg(mgr, secret=secret, seq=1)
        self.assertNotIn(secret, repr(rec))
        self.assertTrue(rec.secret_digest.startswith("sha256:"))
        self.assertTrue(rec.verify())

    def test_unknown_webhook_lookup(self):
        mgr = _mgr()
        with self.assertRaises(UnknownWebhookError):
            mgr.webhook("nope")


class TestDeliver(unittest.TestCase):
    def test_delivered_happy_path(self):
        mgr = _mgr(transport=lambda w, e, a: True)
        _reg(mgr, seq=1)
        rec = mgr.deliver("wh-1", "order.created", DIGEST, 2)
        self.assertIsInstance(rec, DeliveryRecord)
        self.assertEqual(rec.status, "delivered")
        self.assertEqual(rec.attempt, 1)
        self.assertTrue(rec.verify())

    def test_failed_is_data_not_raised(self):
        mgr = _mgr(transport=lambda w, e, a: False)
        _reg(mgr, seq=1)
        rec = mgr.deliver("wh-1", "order.created", DIGEST, 2)
        self.assertEqual(rec.status, "failed")
        self.assertTrue(rec.verify())

    def test_raising_transport_counts_as_failure(self):
        def boom(w, e, a):
            raise RuntimeError("net down")
        mgr = _mgr(transport=boom)
        _reg(mgr, seq=1)
        rec = mgr.deliver("wh-1", "x", DIGEST, 2)
        self.assertEqual(rec.status, "failed")

    def test_unknown_webhook(self):
        mgr = _mgr()
        with self.assertRaises(UnknownWebhookError):
            mgr.deliver("nope", "x", DIGEST, 1)

    def test_bad_inputs(self):
        mgr = _mgr()
        _reg(mgr, seq=1)
        with self.assertRaises(BadDeliveryError):
            mgr.deliver("wh-1", "", DIGEST, 2)
        with self.assertRaises(BadDeliveryError):
            mgr.deliver("wh-1", "x", "not-a-digest", 3)


class TestRetry(unittest.TestCase):
    def test_retry_chain(self):
        calls = []
        def t(w, e, a):
            calls.append(a)
            return a >= 2
        mgr = _mgr(transport=t)
        _reg(mgr, seq=1)
        d1 = mgr.deliver("wh-1", "x", DIGEST, 2)
        self.assertEqual(d1.status, "failed")
        d2 = mgr.retry(d1.delivery_id, 3)
        self.assertEqual(d2.status, "delivered")
        self.assertEqual(d2.attempt, 2)
        self.assertEqual(d2.prev_delivery_id, d1.delivery_id)
        self.assertTrue(d2.verify())
        self.assertEqual(mgr.attempts_for(d1.delivery_id), (d1.delivery_id, d2.delivery_id))

    def test_retry_delivered_refused(self):
        mgr = _mgr(transport=lambda w, e, a: True)
        _reg(mgr, seq=1)
        d1 = mgr.deliver("wh-1", "x", DIGEST, 2)
        with self.assertRaises(AlreadyDeliveredError):
            mgr.retry(d1.delivery_id, 3)

    def test_max_attempts(self):
        mgr = _mgr(transport=lambda w, e, a: False)
        _reg(mgr, seq=1)
        head = mgr.deliver("wh-1", "x", DIGEST, 2)
        seq = 3
        for _ in range(MAX_ATTEMPTS - 1):
            head = mgr.retry(head.delivery_id, seq)
            seq += 1
        self.assertEqual(head.attempt, MAX_ATTEMPTS)
        with self.assertRaises(MaxAttemptsError):
            mgr.retry(head.delivery_id, seq)

    def test_unknown_delivery(self):
        mgr = _mgr()
        with self.assertRaises(UnknownDeliveryError):
            mgr.retry("dlv-999", 1)


class TestAuditAndMisc(unittest.TestCase):
    def test_audit_shapes_and_leak_ban(self):
        mgr = _mgr(transport=lambda w, e, a: False)
        _reg(mgr, seq=1, secret="x" * 16)
        d1 = mgr.deliver("wh-1", "x", DIGEST, 2)
        mgr.retry(d1.delivery_id, 3)
        kinds = [e["kind"] for e in mgr.audit_log()]
        self.assertEqual(kinds, ["webhook-registered", "failed", "failed"])
        blob = repr(mgr.audit_log())
        self.assertNotIn(DIGEST, blob)
        self.assertNotIn("x" * 16, blob)

    def test_audit_bad_kind(self):
        with self.assertRaises(AuditKindError):
            webhook_manager_audit_event("nope", 1)

    def test_stats(self):
        mgr = _mgr(transport=lambda w, e, a: True)
        _reg(mgr, seq=1)
        _reg(mgr, wid="wh-2", seq=2)
        mgr.deliver("wh-1", "x", DIGEST, 3)
        self.assertEqual(
            mgr.stats(),
            {"webhooks": 2, "deliveries": 1, "delivered": 1, "failed": 0},
        )

    def test_signature_for(self):
        mgr = _mgr()
        _reg(mgr, seq=1, secret="y" * 20)
        sig = mgr.signature_for("wh-1", DIGEST)
        self.assertTrue(sig.startswith("sha256="))
        self.assertEqual(len(sig), len("sha256=") + 64)
        mgr2 = WebhookManager(seed="test")
        mgr2.register("wh-1", "https://example.com/hook", 1, secret="y" * 20)
        self.assertEqual(mgr2.signature_for("wh-1", DIGEST), sig)

    def test_signature_no_secret_refused(self):
        mgr = _mgr()
        _reg(mgr, seq=1)
        with self.assertRaises(BadWebhookError):
            mgr.signature_for("wh-1", DIGEST)

    def test_failed_mutation_consumes_seq(self):
        mgr = _mgr()
        _reg(mgr, seq=1)
        with self.assertRaises(DuplicateWebhookError):
            _reg(mgr, seq=2)
        with self.assertRaises(SeqOrderError):
            _reg(mgr, wid="wh-2", seq=2)

    def test_thread_safety(self):
        mgr = _mgr(transport=lambda w, e, a: True)
        errors = []
        def worker(i):
            try:
                mgr.register(f"w{i}", "https://e.com/h", i * 2 + 1)
                mgr.deliver(f"w{i}", "x", DIGEST, i * 2 + 2)
            except Exception as e:  # noqa: BLE001
                errors.append(e)
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(mgr.stats()["webhooks"], 8)

    def test_main(self):
        import webhook_manager as m
        self.assertEqual(m.main(), None)


if __name__ == "__main__":
    unittest.main()
