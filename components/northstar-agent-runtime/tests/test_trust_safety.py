"""Tests for trust_safety: policy engine, enforcement, audit (15 cases)."""

import ast
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from trust_safety import (
    TRUST_SAFETY_SCHEMA,
    TRUST_SAFETY_VERSION,
    ACTIONS,
    AUDIT_SCHEMA,
    CATEGORIES,
    VERDICTS,
    DisabledPolicyError,
    SeqOrderError,
    TrustSafety,
    TrustSafetyError,
    UnknownCategoryError,
    UnknownPolicyError,
    trust_safety_audit_event,
)

RULES = [
    {"rule_id": "r1", "category": "spam", "action": "rate_limit"},
    {"rule_id": "r2", "category": "hate", "action": "remove"},
    {"rule_id": "r3", "category": "violence", "action": "escalate"},
]


def make_engine(seq_start=1):
    ts = TrustSafety(seed="test")
    ts.policy("p1", seq_start, "standards", RULES)
    return ts


class TestPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(TRUST_SAFETY_VERSION, "trust-safety.v1")
        self.assertEqual(TRUST_SAFETY_SCHEMA, "northstar.trust-safety.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")

    def test_vocabularies_pinned(self):
        self.assertIn("spam", CATEGORIES)
        self.assertIn("hate", CATEGORIES)
        self.assertIn("allow", ACTIONS)
        self.assertIn("remove", ACTIONS)
        self.assertIn("allowed", VERDICTS)
        self.assertIn("removed", VERDICTS)

    def test_stdlib_only(self):
        path = os.path.join(os.path.dirname(__file__), "..", "trust_safety.py")
        tree = ast.parse(open(path).read())
        allowed = {
            "hashlib", "hmac", "threading", "dataclasses", "typing",
            "__future__", "canonical_json", "json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed, a.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed, node.module)


class TestPolicy(unittest.TestCase):
    def test_policy_roundtrip(self):
        ts = TrustSafety()
        pol = ts.policy("p1", 1, "standards", RULES)
        self.assertTrue(pol.verify())
        self.assertEqual(pol.policy_id, "p1")
        self.assertEqual(len(pol.rules), 3)
        self.assertTrue(pol.enabled)
        self.assertEqual(ts.get_policy("p1").digest, pol.digest)
        self.assertIn("p1", ts.policy_ids())

    def test_policy_unknown_category_refused(self):
        ts = TrustSafety()
        with self.assertRaises(UnknownCategoryError):
            ts.policy("p1", 1, "x", [{"rule_id": "r1", "category": "nope", "action": "allow"}])

    def test_policy_duplicate_rule_refused(self):
        ts = TrustSafety()
        dup = RULES + [{"rule_id": "r1", "category": "spam", "action": "allow"}]
        with self.assertRaises(TrustSafetyError):
            ts.policy("p1", 1, "x", dup)

    def test_policy_empty_rules_refused(self):
        ts = TrustSafety()
        with self.assertRaises(TrustSafetyError):
            ts.policy("p1", 1, "x", [])

    def test_seq_rewind_refused(self):
        ts = TrustSafety()
        ts.policy("p1", 5, "x", RULES)
        with self.assertRaises(SeqOrderError):
            ts.policy("p2", 5, "y", RULES)  # must strictly increase
        with self.assertRaises(SeqOrderError):
            ts.policy("p2", 3, "y", RULES)
        with self.assertRaises(TrustSafetyError):
            ts.policy("p2", True, "y", RULES)  # bool seq refused


class TestEnforce(unittest.TestCase):
    def test_enforce_verdicts(self):
        ts = make_engine()
        d = ts.enforce("p1", 2, "post-1", "spam")
        self.assertEqual(d.verdict, "limited")
        self.assertEqual(d.action, "rate_limit")
        self.assertEqual(d.rule_id, "r1")
        self.assertTrue(d.verify())
        d2 = ts.enforce("p1", 3, "post-2", "hate")
        self.assertEqual(d2.verdict, "removed")

    def test_enforce_unmatched_category_allows(self):
        ts = make_engine()
        d = ts.enforce("p1", 2, "post-9", "harassment")  # no rule -> allow
        self.assertEqual(d.verdict, "allowed")
        self.assertEqual(d.action, "allow")
        self.assertEqual(d.rule_id, "")
        self.assertTrue(d.verify())

    def test_enforce_unknown_policy_fail_closed(self):
        ts = make_engine()
        with self.assertRaises(UnknownPolicyError):
            ts.enforce("ghost", 2, "post-1", "spam")

    def test_enforce_disabled_policy_refused(self):
        ts = make_engine()
        ts.disable("p1", 2)
        with self.assertRaises(DisabledPolicyError):
            ts.enforce("p1", 3, "post-1", "spam")

    def test_enforce_bad_inputs(self):
        ts = make_engine()
        with self.assertRaises(UnknownCategoryError):
            ts.enforce("p1", 2, "post-1", "not-a-category")
        with self.assertRaises(TrustSafetyError):
            ts.enforce("p1", 2, "   ", "spam")
        with self.assertRaises(TrustSafetyError):
            ts.get_decision("dec-999")


class TestAudit(unittest.TestCase):
    def test_audit_summary(self):
        ts = make_engine()
        ts.enforce("p1", 2, "a", "spam")
        ts.enforce("p1", 3, "b", "hate")
        ts.enforce("p1", 4, "c", "harassment")
        summary = ts.audit(5)
        self.assertTrue(summary.verify())
        self.assertEqual(summary.policy_count, 1)
        self.assertEqual(summary.decision_count, 3)
        counts = dict(summary.verdict_counts)
        self.assertEqual(counts["limited"], 1)
        self.assertEqual(counts["removed"], 1)
        self.assertEqual(counts["allowed"], 1)
        events = ts.audit_log()
        self.assertEqual(len(events), 4)  # 1 policy-defined + 3 enforced
        kinds = {e["kind"] for e in events}
        self.assertEqual(kinds, {"policy-defined", "enforced"})
        for e in events:
            self.assertEqual(e["schema"], "audit.ndjson/1")

    def test_audit_event_bad_kind(self):
        with self.assertRaises(TrustSafetyError):
            trust_safety_audit_event("nope", 1)

    def test_concurrency(self):
        ts = make_engine()
        errors = []

        def worker(n):
            try:
                ts.enforce("p1", 100 + n, f"s-{n}", "spam")
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(ts.decision_ids()), 8)


if __name__ == "__main__":
    unittest.main()
