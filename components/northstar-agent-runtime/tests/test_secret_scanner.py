"""Tests for secret_scanner (Gitleaks shaped, simulated)."""

import ast
import unittest
from pathlib import Path

import secret_scanner as ss
from secret_scanner import SecretScanner


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(ss.SECRET_SCANNER_VERSION, "secret-scanner.v1")
        self.assertEqual(ss.SECRET_SCANNER_SCHEMA, "northstar.secret-scanner.v1")
        self.assertEqual(ss.AUDIT_SCHEMA, "audit.ndjson/1")


class TestStdlibOnly(unittest.TestCase):
    def test_stdlib_only_imports(self):
        tree = ast.parse(Path(ss.__file__).read_text())
        allowed = {"__future__", "hashlib", "json", "math", "re",
                   "threading", "dataclasses", "typing", "canonical_json"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestPatterns(unittest.TestCase):
    def test_patterns_vocabulary(self):
        scanner = SecretScanner()
        patterns = scanner.patterns()
        self.assertEqual(len(patterns), len(ss._BUILTINS))
        for wanted in ("aws-access-key-id", "github-pat", "slack-token",
                       "stripe-secret-key", "private-key", "jwt",
                       "password-in-url", "generic-api-key"):
            self.assertIn(wanted, patterns)

    def test_pattern_detail_and_unknown(self):
        scanner = SecretScanner()
        record = scanner.pattern("aws-access-key-id")
        self.assertTrue(record.builtin)
        self.assertEqual(record.severity, "high")
        self.assertTrue(record.digest.startswith("sha256:"))
        with self.assertRaises(ss.UnknownPatternError):
            scanner.pattern("no-such-pattern")

    def test_add_pattern_happy_and_duplicates(self):
        scanner = SecretScanner()
        record = scanner.add_pattern(
            "acme-key", r"acme_[A-Za-z0-9]{32}", ss.HIGH, 1,
            description="Acme internal key")
        self.assertIn("acme-key", scanner.patterns())
        self.assertFalse(record.builtin)
        with self.assertRaises(ss.DuplicatePatternError):
            scanner.add_pattern("acme-key", r"acme_[A-Za-z0-9]{32}",
                                ss.HIGH, 2, description="dup")

    def test_add_pattern_bad_inputs(self):
        scanner = SecretScanner()
        with self.assertRaises(ss.BadPatternError):
            scanner.add_pattern("Bad_Id!", r"x", ss.LOW, 1, description="d")
        with self.assertRaises(ss.BadPatternError):
            scanner.add_pattern("ok-id", r"([a-z", ss.LOW, 2,
                                description="d")
        with self.assertRaises(ss.BadPatternError):
            scanner.add_pattern("ok-id", r"x", "critical", 3,
                                description="d")
        with self.assertRaises(ss.BadPatternError):
            scanner.add_pattern("ok-id", r"x", ss.LOW, 4, description="")
        # Failed adds do not consume the seq position for the next valid add.
        record = scanner.add_pattern("ok-id", r"x", ss.LOW, 5,
                                     description="d")
        self.assertEqual(record.pattern_id, "ok-id")


class TestScan(unittest.TestCase):
    def test_scan_aws_key(self):
        scanner = SecretScanner()
        report = scanner.scan("repo-a", "key = AKIAIOSFODNN7EXAMPLE\n", 1)
        self.assertEqual(report.report_id, "scan-1")
        self.assertEqual(report.finding_count, 1)
        finding = report.findings[0]
        self.assertEqual(finding.pattern_id, "aws-access-key-id")
        self.assertEqual((finding.line_no, finding.col_no), (1, 7))
        self.assertEqual(finding.match_length, 20)
        self.assertTrue(finding.verify_match("AKIAIOSFODNN7EXAMPLE"))
        self.assertFalse(finding.verify_match("AKIAIOSFODNN7EXAMPLF"))
        self.assertTrue(finding.verify())
        self.assertTrue(report.verify())
        self.assertFalse(finding.allowlisted)

    def test_scan_redacts_match(self):
        scanner = SecretScanner()
        report = scanner.scan("repo-a", "xoxb-1234567890-abcdefghij", 1)
        finding = report.findings[0]
        self.assertEqual(finding.pattern_id, "slack-token")
        self.assertNotIn("xoxb-1234567890-abcdefghij", finding.redacted)
        self.assertEqual(finding.redacted, "xoxb\u2026ij")

    def test_scan_multiple_patterns(self):
        scanner = SecretScanner()
        content = (
            "aws_key = AKIAIOSFODNN7EXAMPLE\n"
            "token: ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            "-----BEGIN RSA PRIVATE KEY-----\n"
        )
        report = scanner.scan("repo-b", content, 1)
        ids = {f.pattern_id for f in report.findings}
        self.assertEqual(ids, {"aws-access-key-id", "github-pat",
                               "private-key"})
        lines = {f.pattern_id: f.line_no for f in report.findings}
        self.assertEqual(lines["github-pat"], 2)
        self.assertEqual(lines["private-key"], 3)

    def test_scan_no_findings_is_valid(self):
        scanner = SecretScanner()
        report = scanner.scan("clean", "just some harmless prose here\n", 1)
        self.assertEqual(report.finding_count, 0)
        self.assertEqual(report.findings, ())
        self.assertTrue(report.verify())

    def test_scan_entropy_heuristic(self):
        scanner = SecretScanner()
        # High-entropy base64 run, no pinned pattern claims it.
        token = "dGhpcyBpcyBhIHZlcnkgc2VjcmV0IHN0cmluZyB3aXRoIGhpZ2ggZW50cm9weQ=="
        report = scanner.scan("blob", f"data={token}\n", 1)
        self.assertEqual(report.finding_count, 1)
        self.assertEqual(report.findings[0].pattern_id,
                         ss.ENTROPY_PATTERN)

    def test_scan_bad_inputs(self):
        scanner = SecretScanner()
        with self.assertRaises(ss.BadContentError):
            scanner.scan("s", "", 1)
        with self.assertRaises(ss.BadContentError):
            scanner.scan("s", b"bytes", 2)
        with self.assertRaises(ss.SecretScannerError):
            scanner.scan("s", "x", True)
        scanner.scan("s", "clean text", 3)
        with self.assertRaises(ss.SeqOrderError):
            scanner.scan("s", "clean text", 3)


class TestAllowlist(unittest.TestCase):
    def test_allowlist_and_remove(self):
        scanner = SecretScanner()
        entry = scanner.allowlist("aws-access-key-id", 1, "test fixture")
        self.assertEqual(entry.entry_id, "al-1")
        self.assertTrue(entry.active)
        report = scanner.scan("repo", "AKIAIOSFODNN7EXAMPLE", 2)
        self.assertEqual(report.allowlisted_count, 1)
        self.assertTrue(report.findings[0].allowlisted)
        removal = scanner.remove_allowlist("al-1", 3)
        self.assertEqual(removal.pattern_id, "aws-access-key-id")
        report2 = scanner.scan("repo", "AKIAIOSFODNN7EXAMPLE", 4)
        self.assertEqual(report2.allowlisted_count, 0)
        with self.assertRaises(ss.AllowlistRemovedError):
            scanner.remove_allowlist("al-1", 5)
        with self.assertRaises(ss.UnknownAllowlistError):
            scanner.remove_allowlist("al-99", 6)
        with self.assertRaises(ss.DuplicateAllowlistError):
            scanner.allowlist("jwt", 7, "r")
            scanner.allowlist("jwt", 8, "r")
        with self.assertRaises(ss.UnknownPatternError):
            scanner.allowlist("nope", 9, "r")


class TestAudit(unittest.TestCase):
    def test_audit_shapes_and_secret_ban(self):
        event = ss.secret_scanner_audit_event(
            ss.KIND_SCANNED, 1, report_id="scan-1", findings=2)
        self.assertEqual(event["schema"], "audit.ndjson/1")
        self.assertEqual(event["kind"], "scanned")
        with self.assertRaises(ss.SecretScannerError):
            ss.secret_scanner_audit_event(
                ss.KIND_SCANNED, 2, match="AKIAIOSFODNN7EXAMPLE")
        with self.assertRaises(ss.SecretScannerError):
            ss.secret_scanner_audit_event("bogus-kind", 3)

    def test_main_self_check(self):
        ss.main()

    def test_views(self):
        scanner = SecretScanner()
        report = scanner.scan("s", "AKIAIOSFODNN7EXAMPLE", 1)
        self.assertEqual(scanner.report("scan-1").report_id, "scan-1")
        self.assertEqual(scanner.report_ids(), ("scan-1",))
        self.assertEqual(scanner.finding("find-1").finding_id, "find-1")
        self.assertEqual(scanner.finding("find-1").digest,
                         report.findings[0].digest)
        with self.assertRaises(ss.UnknownReportError):
            scanner.report("scan-99")
        with self.assertRaises(ss.UnknownFindingError):
            scanner.finding("find-99")
        # Frozen records.
        with self.assertRaises(AttributeError):
            report.finding_count = 5  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
