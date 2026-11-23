"""Targeted tests for sast_scanner (Semgrep-style SAST bookkeeping)."""

import ast
import unittest
from pathlib import Path

import sast_scanner
from sast_scanner import (
    SASTScanner,
    SASTError,
    UnknownRuleError,
    BadSourceError,
    SeqOrderError,
    sast_scanner_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(sast_scanner.SAST_SCANNER_VERSION, "sast-scanner.v1")
        self.assertEqual(sast_scanner.SCHEMA_PIN, "northstar.sast-scanner.v1")

    def test_stdlib_only(self):
        tree = ast.parse(Path(sast_scanner.__file__).read_text())
        allowed = {
            "__future__", "hashlib", "re", "threading",
            "dataclasses", "typing", "json", "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(
                        a.name.split(".")[0], allowed, a.name,
                    )
            elif isinstance(node, ast.ImportFrom):
                self.assertIn(node.module.split(".")[0], allowed)


class TestRegistry(unittest.TestCase):
    def test_rules_sorted_and_pinned(self):
        scanner = SASTScanner()
        ids = [r.rule_id for r in scanner.rules()]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(len(ids), 10)
        for r in scanner.rules():
            self.assertIn(r.severity, ("critical", "high", "medium", "low"))
            self.assertIn(
                r.category,
                ("injection", "deserialization", "crypto", "auth", "config", "style"),
            )

    def test_registry_digest_deterministic(self):
        a, b = SASTScanner(), SASTScanner()
        self.assertEqual(a.registry_digest(), b.registry_digest())
        self.assertTrue(a.registry_digest().startswith("sha256:"))


class TestScan(unittest.TestCase):
    def setUp(self):
        self.scanner = SASTScanner()

    def test_clean_source_no_findings(self):
        report = self.scanner.scan("import os\nos.getcwd()\n", 0)
        self.assertTrue(report.verify())
        self.assertEqual(report.findings, ())

    def test_eval_injection(self):
        report = self.scanner.scan("eval(user_input)\n", 0)
        self.assertTrue(report.verify())
        ids = {f.rule_id for f in report.findings}
        self.assertIn("PY001", ids)
        self.assertEqual(report.findings[0].line, 1)
        self.assertEqual(report.findings[0].severity, "critical")

    def test_os_system_shell(self):
        report = self.scanner.scan("os.system('ls')\n", 0)
        ids = {f.rule_id for f in report.findings}
        self.assertIn("PY002", ids)

    def test_pickle_deserialization(self):
        report = self.scanner.scan("data = pickle.loads(blob)\n", 0)
        ids = {f.rule_id for f in report.findings}
        self.assertIn("PY003", ids)

    def test_hardcoded_secret(self):
        report = self.scanner.scan("password = \"hunter2\"\n", 0)
        ids = {f.rule_id for f in report.findings}
        self.assertIn("PY005", ids)

    def test_weak_hash(self):
        report = self.scanner.scan("h = hashlib.md5(b'x')\n", 0)
        ids = {f.rule_id for f in report.findings}
        self.assertIn("PY006", ids)

    def test_rule_subset_selection(self):
        report = self.scanner.scan("eval(x)\nos.system('y')\n", 0,
                                   rule_ids=["PY001"])
        self.assertEqual({f.rule_id for f in report.findings}, {"PY001"})

    def test_unknown_rule_refused(self):
        with self.assertRaises(UnknownRuleError):
            self.scanner.scan("x = 1\n", 0, rule_ids=["NOPE"])


class TestTaint(unittest.TestCase):
    def setUp(self):
        self.scanner = SASTScanner()

    def test_tainted_var_to_sink(self):
        src = "x = input()\neval(x)\n"
        report = self.scanner.taint(src, 0)
        self.assertTrue(report.verify())
        flows = {(f.rule_id, f.variable) for f in report.flows}
        self.assertIn(("PY001", "x"), flows)
        for f in report.flows:
            self.assertEqual(f.source_line, 1)
            self.assertEqual(f.sink_line, 2)

    def test_sanitizer_cleanses(self):
        src = "x = input()\ny = escape(x)\neval(y)\n"
        report = self.scanner.taint(src, 0)
        self.assertTrue(report.verify())
        self.assertEqual(report.flows, ())

    def test_propagates_through_assignment(self):
        src = "a = sys.argv[1]\nb = a\nexec(b)\n"
        report = self.scanner.taint(src, 0)
        flows = {(f.rule_id, f.variable) for f in report.flows}
        self.assertIn(("PY001", "b"), flows)


class TestSuppress(unittest.TestCase):
    def test_nosast_marker(self):
        scanner = SASTScanner()
        src = "password = \"hunter2\"  # nosast\napi_key = \"xyz\"\n"
        report = scanner.suppress(src, 0)
        self.assertTrue(report.verify())
        self.assertEqual(len(report.suppressed), 1)
        self.assertEqual(report.suppressed[0].finding.line, 1)
        self.assertEqual(len(report.active), 1)
        self.assertEqual(report.active[0].line, 2)


class TestDiscipline(unittest.TestCase):
    def test_seq_rewind_refused(self):
        scanner = SASTScanner()
        scanner.scan("x = 1\n", 5)
        with self.assertRaises(SeqOrderError):
            scanner.scan("x = 1\n", 4)

    def test_bool_seq_refused(self):
        scanner = SASTScanner()
        with self.assertRaises(SASTError):
            scanner.scan("x = 1\n", True)

    def test_bad_source_refused(self):
        scanner = SASTScanner()
        with self.assertRaises(BadSourceError):
            scanner.scan(123, 0)

    def test_audit_shapes(self):
        ev = sast_scanner_audit_event("scanned", 0, findings=2)
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["event"], "scanned")
        self.assertEqual(ev["findings"], 2)
        with self.assertRaises(SASTError):
            sast_scanner_audit_event("bogus", 1)

    def test_main_self_check(self):
        self.assertIsNone(sast_scanner.main())


if __name__ == "__main__":
    unittest.main()
