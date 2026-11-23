"""Targeted tests for the fraud detector interface."""

import ast
import unittest
from pathlib import Path

from fraud_detector import (
    FraudDetector,
    FraudError,
    UnknownRuleError,
    DuplicateRuleError,
    InvalidTransactionError,
    BlockedTransactionError,
    FraudScore,
    BlockDecision,
    ReviewRecord,
    RuleRecord,
    TriggeredRule,
    fraud_detector_audit_event,
    default_detector,
    FRAUD_DETECTOR_VERSION,
    FRAUD_DETECTOR_SCHEMA,
)

MODULE_PATH = Path(__file__).resolve().parent.parent / "fraud_detector.py"

BASE_TS = 1_700_000_000


def txn(**over):
    t = {
        "txn_id": "t1",
        "account_id": "acct-1",
        "amount": 5000,
        "currency": "USD",
        "ts": BASE_TS,
    }
    t.update(over)
    return t


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(FRAUD_DETECTOR_VERSION, "fraud-detector.v1")
        self.assertEqual(FRAUD_DETECTOR_SCHEMA, "northstar.fraud-detector.v1")

    def test_stdlib_only(self):
        tree = ast.parse(MODULE_PATH.read_text())
        allowed = {
            "__future__", "hashlib", "math", "threading", "collections",
            "dataclasses", "decimal", "typing", "canonical_json", "json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestAddRule(unittest.TestCase):
    def test_add_rule_happy_path(self):
        d = FraudDetector()
        rec = d.add_rule("vel", "velocity", 0.35,
                         {"window_s": 300, "limit": 10})
        self.assertIsInstance(rec, RuleRecord)
        self.assertEqual(rec.name, "vel")
        self.assertEqual(rec.kind, "velocity")
        self.assertEqual(rec.weight, 0.35)
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(rec.version, "fraud-detector.v1")
        self.assertEqual(rec.schema, "northstar.fraud-detector.v1")
        self.assertEqual(d.rule_names(), ("vel",))

    def test_add_rule_unknown_kind(self):
        d = FraudDetector()
        with self.assertRaises(UnknownRuleError):
            d.add_rule("x", "neural_net", 0.5)

    def test_add_rule_duplicate_and_bad_weight(self):
        d = FraudDetector()
        d.add_rule("vel", "velocity", 0.35)
        with self.assertRaises(DuplicateRuleError):
            d.add_rule("vel", "velocity", 0.35)
        with self.assertRaises(FraudError):
            d.add_rule("w0", "velocity", 0.0)
        with self.assertRaises(FraudError):
            d.add_rule("w2", "velocity", 1.5)
        with self.assertRaises(FraudError):
            d.add_rule("wb", "velocity", True)

    def test_threshold_ordering_enforced(self):
        with self.assertRaises(FraudError):
            FraudDetector(block_threshold=0.4, review_threshold=0.4)
        with self.assertRaises(FraudError):
            FraudDetector(block_threshold=0.3, review_threshold=0.5)


class TestScore(unittest.TestCase):
    def test_score_clean_txn_allows(self):
        d = FraudDetector()
        d.add_rule("vel", "velocity", 0.35, {"window_s": 300, "limit": 10})
        s = d.score(txn())
        self.assertIsInstance(s, FraudScore)
        self.assertEqual(s.action, "allow")
        self.assertEqual(s.score, 0.0)
        self.assertEqual(s.matched, ())
        self.assertFalse(s.blacklist_hit)
        self.assertTrue(s.digest.startswith("sha256:"))

    def test_score_rejects_bad_shapes(self):
        d = FraudDetector()
        with self.assertRaises(InvalidTransactionError):
            d.score(txn(txn_id=""))
        with self.assertRaises(InvalidTransactionError):
            d.score(txn(amount=12.34))  # float money refused
        with self.assertRaises(InvalidTransactionError):
            d.score(txn(amount=-100))
        with self.assertRaises(InvalidTransactionError):
            d.score(txn(currency="US"))
        with self.assertRaises(InvalidTransactionError):
            d.score({"txn_id": "t", "account_id": "a"})  # missing fields

    def test_score_str_decimal_amount(self):
        d = FraudDetector()
        s = d.score(txn(amount="12.34"))
        self.assertEqual(s.action, "allow")

    def test_blacklist_forces_block(self):
        d = FraudDetector()
        d.add_rule("bl", "blacklisted", 1.0)
        d.add_to_blacklist("merchant_id", "m-evil")
        s = d.score(txn(merchant_id="m-evil"))
        self.assertTrue(s.blacklist_hit)
        self.assertEqual(s.score, 1.0)
        self.assertEqual(s.action, "block")
        self.assertEqual(len(s.matched), 1)
        self.assertIn("blacklisted", s.matched[0].evidence)

    def test_velocity_rule_fires(self):
        d = FraudDetector()
        d.add_rule("vel", "velocity", 0.5, {"window_s": 300, "limit": 3})
        for i in range(2):
            s = d.score(txn(txn_id=f"v{i}", ts=BASE_TS + i * 10))
        s = d.score(txn(txn_id="v2", ts=BASE_TS + 20))
        self.assertEqual(s.action, "review")
        self.assertEqual(len(s.matched), 1)
        self.assertIn("3 txns", s.matched[0].evidence)

    def test_new_device_and_impossible_travel(self):
        d = FraudDetector()
        d.add_rule("nd", "new_device", 0.2)
        d.add_rule("it", "impossible_travel", 0.6)
        d.score(txn(txn_id="g1", device_id="dev-a",
                    geo=(40.7128, -74.0060)))  # NYC
        s = d.score(txn(txn_id="g2", device_id="dev-a",
                        geo=(35.6762, 139.6503),  # Tokyo, 60s later
                        ts=BASE_TS + 60))
        kinds = {m.kind for m in s.matched}
        self.assertEqual(kinds, {"impossible_travel"})
        self.assertEqual(s.action, "review")
        self.assertIn("km/h", s.matched[0].evidence)


class TestBlock(unittest.TestCase):
    def test_block_allows_clean(self):
        d = FraudDetector()
        d.add_rule("vel", "velocity", 0.5, {"window_s": 300, "limit": 3})
        dec = d.block(txn())
        self.assertIsInstance(dec, BlockDecision)
        self.assertTrue(dec.allowed)
        self.assertEqual(dec.txn_id, "t1")

    def test_block_raises_with_decision(self):
        d = default_detector()
        d.add_to_blacklist("ip", "203.0.113.9")
        with self.assertRaises(BlockedTransactionError) as cm:
            d.block(txn(txn_id="b1", ip="203.0.113.9"))
        dec = cm.exception.decision
        self.assertFalse(dec.allowed)
        self.assertEqual(dec.score.score, 1.0)
        self.assertIn("blacklisted", dec.reason)


class TestReview(unittest.TestCase):
    def test_review_band_opens_case(self):
        d = FraudDetector()
        d.add_rule("outlier", "amount_outlier", 0.5)
        d.add_rule("round", "round_amount", 0.1)
        # Seed history: small txns so $5000.00 is 5x+ the median outlier.
        for i in range(4):
            d.score(txn(txn_id=f"s{i}", amount=800, ts=BASE_TS - 3600 - i))
        rec = d.review(txn(txn_id="r1", amount=500000, ts=BASE_TS))
        self.assertIsInstance(rec, ReviewRecord)
        self.assertTrue(rec.needed)
        self.assertTrue(rec.case_id.startswith("fraud-review-acct-1-"))
        self.assertGreaterEqual(rec.score, d.review_threshold)
        self.assertLess(rec.score, d.block_threshold)
        self.assertTrue(any("outlier" in r for r in rec.reasons))

    def test_review_not_needed_for_clean_or_blocked(self):
        d = FraudDetector()
        d.add_rule("vel", "velocity", 0.5, {"window_s": 300, "limit": 3})
        clean = d.review(txn())
        self.assertFalse(clean.needed)
        self.assertEqual(clean.case_id, "")
        for i in range(2):
            d.review(txn(txn_id=f"w{i}", ts=BASE_TS + i * 10))
        hot = d.review(txn(txn_id="w2", ts=BASE_TS + 20))
        self.assertTrue(hot.needed)  # 0.5 is in the review band


class TestAuditAndMain(unittest.TestCase):
    def test_audit_event_shape(self):
        ev = fraud_detector_audit_event(
            "blocked", seq=7, txn_id="t9", account_id="a1",
            score=1.0, action="block",
            detail={"rule": "blacklist"},
        )
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["component"], "fraud-detector")
        self.assertEqual(ev["version"], "fraud-detector.v1")
        self.assertEqual(ev["seq"], 7)
        self.assertEqual(ev["txn_id"], "t9")
        with self.assertRaises(FraudError):
            fraud_detector_audit_event("scored", seq=-1)

    def test_main_self_check(self):
        import subprocess, sys
        out = subprocess.run(
            [sys.executable, str(MODULE_PATH)], capture_output=True, text=True,
        )
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("fraud-detector OK", out.stdout)


if __name__ == "__main__":
    unittest.main()
