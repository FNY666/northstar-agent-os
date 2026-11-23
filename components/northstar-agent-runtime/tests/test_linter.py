"""Tests for linter.py: rule registry, lint detection, auto-fix ledger."""

import ast
import pathlib
import sys
import unittest

_TESTS_DIR = pathlib.Path(__file__).resolve().parent
_COMPONENT_DIR = _TESTS_DIR.parent
sys.path.insert(0, str(_COMPONENT_DIR))

import linter
from linter import (
    AppliedFix,
    FixReport,
    LintReport,
    Linter,
    LinterError,
    RuleRecord,
    SeqOrderError,
    UnknownRuleError,
    Violation,
    linter_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(linter.LINTER_VERSION, "linter.v1")
        self.assertEqual(linter.SCHEMA_PIN, "northstar.linter.v1")

    def test_stdlib_only(self):
        tree = ast.parse((_COMPONENT_DIR / "linter.py").read_text())
        allowed = {
            "__future__", "hashlib", "re", "threading", "dataclasses",
            "typing", "json", "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)

    def test_main_selfcheck(self):
        # must not raise
        linter.main()


class TestRegistry(unittest.TestCase):
    def test_rules_sorted_and_pinned(self):
        l = Linter()
        rules = l.rules()
        ids = [r.rule_id for r in rules]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(len(ids), len(set(ids)))
        for r in rules:
            self.assertIsInstance(r, RuleRecord)
            self.assertEqual(r.version, "linter.v1")
            self.assertIn(r.severity, ("error", "warning"))
            self.assertIsInstance(r.fixable, bool)

    def test_registry_digest_deterministic(self):
        self.assertEqual(Linter().registry_digest(), Linter().registry_digest())
        self.assertTrue(Linter().registry_digest().startswith("sha256:"))

    def test_expected_rule_ids(self):
        ids = {r.rule_id for r in Linter().rules()}
        self.assertEqual(
            ids,
            {"E501", "W291", "W292", "W191", "T001", "T201", "F403", "F401"},
        )

    def test_bad_constructor(self):
        with self.assertRaises(LinterError):
            Linter(max_line_length=True)
        with self.assertRaises(LinterError):
            Linter(max_line_length=0)


class TestLintDetection(unittest.TestCase):
    def test_clean_source_no_violations(self):
        l = Linter()
        report = l.lint("import os\nos.getcwd()\n", 0)
        self.assertIsInstance(report, LintReport)
        self.assertEqual(report.violations, ())
        self.assertTrue(report.verify())
        self.assertEqual(len(report.rules_applied), 8)

    def test_each_rule_fires(self):
        l = Linter()
        src = "import os\n"          # F401 (os unused)
        src += "\tprint('x')   \n"  # W191, T201, W291
        src += "# TODO: fix\n"      # T001
        src += "from m import *\n"  # F403
        src += "y = " + "1" * 90    # E501, W292
        report = l.lint(src, 0)
        found = {v.rule_id for v in report.violations}
        for rid in ("F401", "W191", "T201", "W291", "T001", "F403", "E501", "W292"):
            self.assertIn(rid, found)
        self.assertTrue(report.verify())

    def test_violation_shape(self):
        l = Linter()
        report = l.lint("x = 1   \n", 0)
        self.assertEqual(len(report.violations), 1)
        v = report.violations[0]
        self.assertIsInstance(v, Violation)
        self.assertEqual(v.rule_id, "W291")
        self.assertEqual((v.line, v.column), (1, 6))
        self.assertTrue(v.fixable)
        self.assertTrue(v.message)

    def test_rule_selection(self):
        l = Linter()
        src = "x = 1   \n"  # W291 + W292
        report = l.lint(src, 0, rule_ids=["W291"])
        self.assertEqual({v.rule_id for v in report.violations}, {"W291"})
        self.assertEqual(report.rules_applied, ("W291",))

    def test_unknown_rule_refused(self):
        l = Linter()
        with self.assertRaises(UnknownRuleError):
            l.lint("x = 1\n", 0, rule_ids=["E999"])
        with self.assertRaises(UnknownRuleError):
            Linter().fix("x = 1\n", 0, rule_ids=["NOPE"])

    def test_seq_must_increase(self):
        l = Linter()
        l.lint("x = 1\n", 5)
        with self.assertRaises(SeqOrderError):
            l.lint("x = 1\n", 5)
        with self.assertRaises(SeqOrderError):
            l.lint("x = 1\n", 2)

    def test_bad_source_refused(self):
        l = Linter()
        with self.assertRaises(LinterError):
            l.lint(123, 0)
        with self.assertRaises(LinterError):
            l.lint("x = 1\n", 0, rule_ids="E501")
        with self.assertRaises(LinterError):
            l.lint("x = 1\n", True)

    def test_used_import_not_flagged(self):
        l = Linter()
        report = l.lint("import sys\nsys.exit(1)\n", 0, rule_ids=["F401"])
        self.assertEqual(report.violations, ())

    def test_print_in_identifier_not_flagged(self):
        l = Linter()
        report = l.lint("sprint(1)\n", 0, rule_ids=["T201"])
        self.assertEqual(report.violations, ())


class TestFix(unittest.TestCase):
    def test_fix_trailing_whitespace_tab_newline(self):
        l = Linter()
        report = l.fix("\t x = 1  ", 0)
        self.assertIsInstance(report, FixReport)
        self.assertTrue(report.verify())
        self.assertEqual(
            {f.rule_id for f in report.applied_fixes},
            {"W191", "W291", "W292"},
        )
        for f in report.applied_fixes:
            self.assertIsInstance(f, AppliedFix)
            self.assertNotEqual(f.before_digest, f.after_digest)
            self.assertTrue(f.before_digest.startswith("sha256:"))
        # remaining violations no longer include the fixed rules
        self.assertNotIn("W191", {v.rule_id for v in report.remaining})
        self.assertNotIn("W291", {v.rule_id for v in report.remaining})
        fixed = l.fixed_source("\t x = 1  ", 1)
        self.assertEqual(fixed, "     x = 1\n")

    def test_fix_idempotent(self):
        l = Linter()
        fixed = l.fixed_source("x = 1  \n", 0)
        again = l.fix(fixed, 1)
        self.assertEqual(again.applied_fixes, ())
        self.assertEqual(again.before_digest, again.after_digest)

    def test_fix_does_not_touch_non_fixable(self):
        l = Linter()
        report = l.fix("# TODO: later\n", 0)
        self.assertEqual(report.applied_fixes, ())
        self.assertEqual({v.rule_id for v in report.remaining}, {"T001"})

    def test_fix_subset_of_rules(self):
        l = Linter()
        # W291 (trailing ws) is not selected: it must not be fixed or reported.
        report = l.fix("x = 1  ", 0, rule_ids=["W292"])
        self.assertEqual([f.rule_id for f in report.applied_fixes], ["W292"])
        self.assertEqual(report.remaining, ())
        fixed = l.fixed_source("x = 1  ", 1, rule_ids=["W292"])
        self.assertEqual(fixed, "x = 1  \n", "unselected W291 must be left alone")


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        ev = linter_audit_event("linted", 3, violations=2)
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["event"], "linted")
        self.assertEqual(ev["audit_seq"], 3)
        self.assertEqual(ev["module_version"], "linter.v1")
        for kind in ("linter-created", "fixed", "rejected"):
            linter_audit_event(kind, 4)

    def test_audit_bad_kind_and_seq(self):
        with self.assertRaises(LinterError):
            linter_audit_event("nope", 0)
        with self.assertRaises(LinterError):
            linter_audit_event("linted", -1)


if __name__ == "__main__":
    unittest.main()
