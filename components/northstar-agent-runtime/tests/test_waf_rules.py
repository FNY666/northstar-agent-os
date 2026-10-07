"""Tests for waf_rules: OWASP CRS-shaped WAF rule bookkeeping (15 cases)."""

import ast
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from waf_rules import (
    WAF_RULES_VERSION,
    WAF_RULES_SCHEMA,
    AUDIT_SCHEMA,
    CATEGORIES,
    SEVERITY_SCORES,
    MODES,
    DEFAULT_THRESHOLD,
    BadRuleError,
    DuplicateRuleError,
    UnknownRuleError,
    AlreadyBlockingError,
    NotBlockingError,
    BadThresholdError,
    BadMatchError,
    SeqOrderError,
    WAFRulesError,
    RuleRecord,
    WAFRules,
    waf_rules_audit_event,
)

MODULE_PATH = os.path.join(os.path.dirname(__file__), "..", "waf_rules.py")


class TestPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(WAF_RULES_VERSION, "waf-rules.v1")
        self.assertEqual(WAF_RULES_SCHEMA, "northstar.waf-rules.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")
        self.assertEqual(DEFAULT_THRESHOLD, 5)
        self.assertEqual(SEVERITY_SCORES["critical"], 5)
        self.assertEqual(SEVERITY_SCORES["error"], 4)
        self.assertEqual(SEVERITY_SCORES["warning"], 3)
        self.assertEqual(SEVERITY_SCORES["notice"], 2)
        self.assertEqual(tuple(sorted(CATEGORIES)), tuple(sorted({
            "request-method", "protocol", "request-headers",
            "request-cookies", "args", "body", "file-upload",
            "response-headers", "response-body", "scanner-detection",
        })))
        self.assertEqual(set(MODES), {"detect", "blocking"})

    def test_stdlib_only(self):
        tree = ast.parse(open(MODULE_PATH).read())
        allowed = {
            "hashlib", "re", "threading", "dataclasses", "typing",
            "json", "canonical_json", "__future__",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed, a.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestRule(unittest.TestCase):
    def setUp(self):
        self.waf = WAFRules()

    def test_rule_roundtrip_and_verify(self):
        rec = self.waf.rule(
            "R-930100", "body", "critical", 1,
            patterns=(r"(?i)union\s+select",),
        )
        self.assertIsInstance(rec, RuleRecord)
        self.assertEqual(rec.mode, "detect")
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertTrue(rec.verify())
        self.assertEqual(self.waf.rule_record("R-930100").digest, rec.digest)
        self.assertIn("R-930100", self.waf.rule_ids())

    def test_rule_duplicate_refused(self):
        self.waf.rule("R-1", "args", "warning", 1)
        with self.assertRaises(DuplicateRuleError):
            self.waf.rule("R-1", "args", "warning", 2)
        # failed mutation consumed its seq
        with self.assertRaises(SeqOrderError):
            self.waf.rule("R-2", "args", "warning", 2)
        kinds = [e["kind"] for e in self.waf.audit_log()]
        self.assertIn("waf-rule.rejected", kinds)

    def test_rule_bad_inputs(self):
        with self.assertRaises(BadRuleError):
            self.waf.rule("", "args", "warning", 1)
        with self.assertRaises(BadRuleError):
            self.waf.rule("R-x", "nope", "warning", 1)
        with self.assertRaises(BadRuleError):
            self.waf.rule("R-x", "args", "fatal", 1)
        with self.assertRaises(BadRuleError):
            self.waf.rule("R-x", "args", "warning", 1, patterns=("([",))
        with self.assertRaises(BadRuleError):
            self.waf.rule("R-x", "args", "warning", 1, patterns="raw-str")
        # input-validation failures do not consume seq: seq 1 still works
        rec = self.waf.rule("R-ok", "args", "warning", 1)
        self.assertTrue(rec.verify())


class TestModes(unittest.TestCase):
    def setUp(self):
        self.waf = WAFRules()
        self.waf.rule("R-1", "body", "critical", 1)

    def test_block_unblock_cycle(self):
        change = self.waf.block("R-1", 2, "confirmed true positive")
        self.assertEqual(change.from_mode, "detect")
        self.assertEqual(change.to_mode, "blocking")
        self.assertTrue(change.verify())
        self.assertEqual(self.waf.rule_record("R-1").mode, "blocking")
        change2 = self.waf.unblock("R-1", 3, "false positive triaged")
        self.assertEqual(change2.from_mode, "blocking")
        self.assertEqual(change2.to_mode, "detect")

    def test_block_double_and_unknown(self):
        self.waf.block("R-1", 2, "fp confirmed")
        with self.assertRaises(AlreadyBlockingError):
            self.waf.block("R-1", 3, "again")
        with self.assertRaises(UnknownRuleError):
            self.waf.block("R-missing", 4, "x")
        # R-1 is still blocking: unblock succeeds, then NotBlockingError
        self.waf.unblock("R-1", 5, "back to detect")
        self.assertEqual(self.waf.rule_record("R-1").mode, "detect")
        with self.assertRaises(NotBlockingError):
            self.waf.unblock("R-1", 6, "not blocking anymore")
        with self.assertRaises(UnknownRuleError):
            self.waf.unblock("R-missing", 7, "x")


class TestThreshold(unittest.TestCase):
    def test_threshold_set_and_read(self):
        waf = WAFRules()
        self.assertEqual(waf.threshold().threshold, DEFAULT_THRESHOLD)
        rec = waf.set_threshold(10, 1)
        self.assertEqual(rec.threshold, 10)
        self.assertTrue(rec.verify())
        self.assertEqual(waf.threshold().threshold, 10)

    def test_threshold_bad(self):
        waf = WAFRules()
        for bad in (0, -1, True, "5", 5.0):
            with self.assertRaises(BadThresholdError, msg=repr(bad)):
                waf.set_threshold(bad, 1)
        with self.assertRaises(SeqOrderError):
            waf.set_threshold(10, -1)


class TestEvaluate(unittest.TestCase):
    def setUp(self):
        self.waf = WAFRules()
        self.waf.rule("R-SQLI", "body", "critical", 1)   # 5 pts
        self.waf.rule("R-XSS", "args", "error", 2)      # 4 pts
        self.waf.rule("R-SCAN", "request-headers", "notice", 3)  # 2 pts
        self.waf.block("R-SQLI", 4, "escalated")

    def test_evaluate_block_enforced(self):
        rep = self.waf.evaluate("req-1", 0, [("R-SQLI", 1)])
        self.assertEqual(rep.verdict, "block")
        self.assertTrue(rep.enforced)
        self.assertEqual(rep.score, 5)
        self.assertEqual(rep.threshold, 5)
        self.assertTrue(rep.verify())

    def test_evaluate_pass(self):
        rep = self.waf.evaluate("req-2", 0, [("R-XSS", 1)])
        self.assertEqual(rep.verdict, "pass")
        self.assertFalse(rep.enforced)
        self.assertEqual(rep.score, 4)

    def test_evaluate_detection_only_trip(self):
        # R-XSS (4) + R-SCAN (2) = 6 >= 5 trips the verdict, but no
        # matched rule is in blocking mode -> not enforced.
        rep = self.waf.evaluate("req-3", 0, [("R-XSS", 1), ("R-SCAN", 1)])
        self.assertEqual(rep.verdict, "block")
        self.assertFalse(rep.enforced)
        self.assertEqual(rep.score, 6)

    def test_evaluate_bad_inputs(self):
        with self.assertRaises(UnknownRuleError):
            self.waf.evaluate("req-x", 0, [("R-NOPE", 1)])
        with self.assertRaises(BadMatchError):
            self.waf.evaluate("req-x", 0, [("R-XSS", 0)])
        with self.assertRaises(BadMatchError):
            self.waf.evaluate("req-x", 0, [("R-XSS",)])
        with self.assertRaises(BadMatchError):
            self.waf.evaluate("", 0, [("R-XSS", 1)])
        with self.assertRaises(SeqOrderError):
            self.waf.evaluate("req-x", -1, [("R-XSS", 1)])
        # empty matches: clean pass, score 0
        rep = self.waf.evaluate("req-clean", 0, [])
        self.assertEqual(rep.verdict, "pass")
        self.assertEqual(rep.score, 0)

    def test_evaluate_is_read_seq_not_consumed(self):
        self.waf.evaluate("req-1", 0, [("R-XSS", 1)])
        # seq 0 did not advance the mutation ledger: seq 5 still claimable
        rec = self.waf.rule("R-NEW", "args", "warning", 5)
        self.assertEqual(rec.seq, 5)


class TestSeqAndAudit(unittest.TestCase):
    def test_seq_order_enforcement(self):
        waf = WAFRules()
        waf.rule("R-1", "args", "warning", 1)
        with self.assertRaises(SeqOrderError):
            waf.rule("R-2", "args", "warning", 1)  # rewind
        with self.assertRaises(SeqOrderError):
            waf.rule("R-2", "args", "warning", True)  # bool
        with self.assertRaises(SeqOrderError):
            waf.block("R-1", 0, "rewind")

    def test_audit_shapes_and_bad_kind(self):
        waf = WAFRules()
        waf.rule("R-1", "args", "warning", 1, patterns=(r"x+",))
        waf.block("R-1", 2, "fp")
        log = waf.audit_log()
        kinds = {e["kind"] for e in log}
        self.assertIn("waf-rule.defined", kinds)
        self.assertIn("waf-rule.blocked", kinds)
        for e in log:
            self.assertEqual(e["schema"], "audit.ndjson/1")
            self.assertEqual(e["module"], "waf-rules.v1")
            self.assertNotIn("patterns", e["detail"])
        with self.assertRaises(WAFRulesError):
            waf_rules_audit_event("bogus-kind", {}, 1)
        with self.assertRaises(WAFRulesError):
            waf_rules_audit_event("waf-rule.defined", {"patterns": ["x"]}, 1)

    def test_main_selfcheck(self):
        import subprocess
        proc = subprocess.run(
            [sys.executable, MODULE_PATH],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("waf-rules OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()
