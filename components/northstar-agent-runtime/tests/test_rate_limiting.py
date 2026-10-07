"""Tests for rate_limiting.py — keyed token-bucket quota ledger."""

import ast
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUNTIME = HERE.parent
MODULE = RUNTIME / "rate_limiting.py"

sys.path.insert(0, str(RUNTIME))

from rate_limiting import (  # noqa: E402
    AUDIT_SCHEMA,
    KIND_ALLOWED,
    KIND_DENIED,
    KIND_REFILLED,
    KIND_REGISTERED,
    KIND_REJECTED,
    Allowance,
    BadBucketError,
    BadCostError,
    BadRefillError,
    BucketRecord,
    DuplicateBucketError,
    QuotaView,
    RateLimiting,
    RateLimitingError,
    RefillRecord,
    SeqOrderError,
    UnknownBucketError,
    rate_limiting_audit_event,
    RATE_LIMITING_SCHEMA,
    RATE_LIMITING_VERSION,
)


def make():
    return RateLimiting()


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(RATE_LIMITING_VERSION, "rate-limiting.v1")
        self.assertEqual(RATE_LIMITING_SCHEMA, "northstar.rate-limiting.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")
        self.assertEqual(make().version, "rate-limiting.v1")


class TestStdlibOnly(unittest.TestCase):
    def test_no_third_party_imports(self):
        tree = ast.parse(MODULE.read_text())
        allowed = {
            "hashlib", "threading", "dataclasses", "typing", "json",
            "canonical_json", "__future__",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestRegister(unittest.TestCase):
    def test_register_roundtrip_and_verify(self):
        ledger = make()
        rec = ledger.register("tenant-a", 10, 1)
        self.assertIsInstance(rec, BucketRecord)
        self.assertEqual(rec.key, "tenant-a")
        self.assertEqual(rec.capacity, 10)
        self.assertTrue(rec.verify())
        # Starts full.
        self.assertEqual(ledger.quota("tenant-a").tokens, 10)
        self.assertEqual(ledger.bucket_keys(), ("tenant-a",))

    def test_register_duplicate_refused(self):
        ledger = make()
        ledger.register("k", 5, 1)
        with self.assertRaises(DuplicateBucketError):
            ledger.register("k", 5, 2)

    def test_register_bad_inputs(self):
        ledger = make()
        for bad_key in ("", "   ", None, 123):
            with self.assertRaises((BadBucketError, RateLimitingError)):
                ledger.register(bad_key, 5, 1)
        for bad_cap in (0, -3, True, 2.5, "10"):
            with self.assertRaises((BadBucketError, RateLimitingError)):
                ledger.register("k2", bad_cap, 2)


class TestAllow(unittest.TestCase):
    def test_allow_consumes_tokens(self):
        ledger = make()
        ledger.register("k", 10, 1)
        decision = ledger.allow("k", 4, 2)
        self.assertIsInstance(decision, Allowance)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.tokens_after, 6)
        self.assertTrue(decision.verify())
        self.assertEqual(ledger.quota("k").tokens, 6)

    def test_allow_denial_is_data(self):
        ledger = make()
        ledger.register("k", 10, 1)
        ledger.allow("k", 9, 2)
        decision = ledger.allow("k", 5, 3)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.tokens_after, 1)
        self.assertTrue(decision.verify())
        # Denial does not consume.
        self.assertEqual(ledger.quota("k").tokens, 1)

    def test_allow_unknown_bucket(self):
        ledger = make()
        with self.assertRaises(UnknownBucketError):
            ledger.allow("nope", 1, 1)

    def test_allow_bad_cost(self):
        ledger = make()
        ledger.register("k", 10, 1)
        for bad in (0, -1, True, 1.5, "3"):
            with self.assertRaises((BadCostError, RateLimitingError)):
                ledger.allow("k", bad, 2)


class TestRefill(unittest.TestCase):
    def test_refill_adds_and_clamps(self):
        ledger = make()
        ledger.register("k", 10, 1)
        ledger.allow("k", 8, 2)
        rec = ledger.refill("k", 5, 3)
        self.assertIsInstance(rec, RefillRecord)
        self.assertEqual(rec.tokens_after, 7)
        self.assertTrue(rec.verify())
        # Over-refill clamps at capacity.
        rec2 = ledger.refill("k", 100, 4)
        self.assertEqual(rec2.tokens_after, 10)

    def test_refill_unknown_bucket(self):
        ledger = make()
        with self.assertRaises(UnknownBucketError):
            ledger.refill("nope", 3, 1)

    def test_refill_bad_amount(self):
        ledger = make()
        ledger.register("k", 10, 1)
        for bad in (0, -2, True, 1.5, "3"):
            with self.assertRaises((BadRefillError, RateLimitingError)):
                ledger.refill("k", bad, 2)


class TestQuotaView(unittest.TestCase):
    def test_quota_roundtrip_and_verify(self):
        ledger = make()
        ledger.register("k", 7, 1)
        ledger.allow("k", 2, 2)
        view = ledger.quota("k")
        self.assertIsInstance(view, QuotaView)
        self.assertEqual((view.key, view.capacity, view.tokens), ("k", 7, 5))
        self.assertTrue(view.verify())

    def test_quota_unknown_bucket(self):
        ledger = make()
        with self.assertRaises(UnknownBucketError):
            ledger.quota("nope")


class TestSeqDiscipline(unittest.TestCase):
    def test_seq_rewind_refused(self):
        ledger = make()
        ledger.register("k", 10, 1)
        with self.assertRaises(SeqOrderError):
            ledger.register("k2", 10, 1)
        with self.assertRaises(SeqOrderError):
            ledger.allow("k", 1, 1)

    def test_failed_mutation_consumes_seq_and_audits(self):
        ledger = make()
        ledger.register("k", 10, 1)
        with self.assertRaises(BadCostError):
            ledger.allow("k", 0, 2)  # failed: consumes seq 2
        kinds = [row["kind"] for row in ledger.audit_log()]
        self.assertIn(KIND_REJECTED, kinds)
        # Next mutation must use seq > 2.
        with self.assertRaises(SeqOrderError):
            ledger.allow("k", 1, 2)
        decision = ledger.allow("k", 1, 3)
        self.assertTrue(decision.allowed)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        ledger = make()
        ledger.register("k", 10, 1)
        ledger.allow("k", 3, 2)
        ledger.allow("k", 9, 3)  # denied
        ledger.refill("k", 2, 4)
        kinds = [row["kind"] for row in ledger.audit_log()]
        self.assertEqual(
            kinds, [KIND_REGISTERED, KIND_ALLOWED, KIND_DENIED, KIND_REFILLED]
        )
        for row in ledger.audit_log():
            self.assertEqual(row["schema"], AUDIT_SCHEMA)
            self.assertEqual(row["module"], RATE_LIMITING_VERSION)
            self.assertNotIn("tokens", row["detail"])
            self.assertNotIn("capacity", row["detail"])

    def test_audit_event_bad_kind(self):
        with self.assertRaises(RateLimitingError):
            rate_limiting_audit_event("bogus.kind", {}, 1)
        with self.assertRaises(RateLimitingError):
            rate_limiting_audit_event(KIND_ALLOWED, {"tokens": 5}, 1)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        proc = subprocess.run(
            [sys.executable, str(MODULE)], capture_output=True, text=True
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("rate-limiting OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()
