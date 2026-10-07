"""Tests for capability_reassembly.py."""
import unittest

from capability_reassembly import (
    CAPABILITY_REASSEMBLY_VERSION,
    SCHEMA_PIN,
    EmergingPattern,
    ReassemblyFinding,
    ReassemblyPattern,
    ReassemblySeverity,
    PATTERNS,
    detect_emerging,
    detect_reassembly,
    main,
    scan_reassembly,
)


class VersionPinTests(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(CAPABILITY_REASSEMBLY_VERSION, "capability-reassembly.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.capability-reassembly.v1")

    def test_pattern_table_nonempty_and_unique_names(self):
        self.assertTrue(len(PATTERNS) >= 5)
        names = [p.name for p in PATTERNS]
        self.assertEqual(len(names), len(set(names)))
        for p in PATTERNS:
            self.assertIsInstance(p, ReassemblyPattern)
            self.assertTrue(p.tools)
            self.assertTrue(p.capability)


class DetectReassemblyTests(unittest.TestCase):
    def test_canonical_browser_rce_chain(self):
        chain = [{"tool": "httpbin"}, {"tool": "urlquery"}, {"tool": "eval"}]
        self.assertTrue(detect_reassembly(chain))

    def test_order_independent(self):
        chain = ["eval", "urlquery", "httpbin"]
        self.assertTrue(detect_reassembly(chain))

    def test_case_insensitive(self):
        chain = ["HTTPBIN", "UrlQuery", "EVAL"]
        self.assertTrue(detect_reassembly(chain))

    def test_exec_variant(self):
        chain = ["httpbin", "urlquery", "exec"]
        self.assertTrue(detect_reassembly(chain))

    def test_partial_chain_no_fire(self):
        self.assertFalse(detect_reassembly([{"tool": "httpbin"}, {"tool": "urlquery"}]))

    def test_empty_sequence(self):
        self.assertFalse(detect_reassembly([]))

    def test_unrelated_tools_clean(self):
        self.assertFalse(detect_reassembly(["list_dir", "echo", "date"]))

    def test_string_and_mapping_mixed(self):
        self.assertTrue(detect_reassembly(["shell", {"tool": "curl"}]))

    def test_alternate_name_keys(self):
        self.assertTrue(
            detect_reassembly([{"name": "env"}, {"tool_name": "http_post"}])
        )

    def test_function_key(self):
        self.assertTrue(detect_reassembly([{"function": "read_file"}, {"function": "http_post"}]))

    def test_malformed_entries_skipped(self):
        self.assertTrue(detect_reassembly([None, 42, {"tool": "httpbin"}, {"tool": "urlquery"}, "eval"]))

    def test_non_sequence_raises(self):
        with self.assertRaises(TypeError):
            detect_reassembly("httpbin")
        with self.assertRaises(TypeError):
            detect_reassembly(None)

    def test_duplicate_calls_still_fire(self):
        chain = ["httpbin", "httpbin", "urlquery", "urlquery", "eval"]
        self.assertTrue(detect_reassembly(chain))


class ScanReassemblyTests(unittest.TestCase):
    def test_finding_shape(self):
        findings = scan_reassembly(["shell", "curl"])
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertIsInstance(f, ReassemblyFinding)
        self.assertEqual(f.pattern, "shell-download-execute")
        self.assertEqual(f.severity, ReassemblySeverity.CRITICAL)
        self.assertEqual(f.schema, SCHEMA_PIN)

    def test_finding_frozen(self):
        (f,) = scan_reassembly(["shell", "curl"])
        with self.assertRaises(Exception):
            f.pattern = "x"

    def test_multiple_patterns(self):
        findings = scan_reassembly(["read_file", "write_file", "http_post"])
        names = {f.pattern for f in findings}
        self.assertIn("file-exfiltration", names)
        self.assertIn("privilege-read-then-write", names)

    def test_clean_returns_empty_tuple(self):
        self.assertEqual(scan_reassembly(["echo"]), ())

    def test_pattern_table_order(self):
        findings = scan_reassembly(["httpbin", "urlquery", "eval", "exec"])
        names = [f.pattern for f in findings]
        self.assertEqual(names, sorted(names, key=lambda n: [p.name for p in PATTERNS].index(n)))


class DetectEmergingTests(unittest.TestCase):
    def test_emerging_partial_chain(self):
        emerging = detect_emerging([{"tool": "httpbin"}, {"tool": "urlquery"}])
        self.assertTrue(any(e.pattern == "browser-rce" for e in emerging))
        e = next(x for x in emerging if x.pattern == "browser-rce")
        self.assertIsInstance(e, EmergingPattern)
        self.assertEqual(e.missing_tools, ("eval",))
        self.assertAlmostEqual(e.coverage, 2 / 3)

    def test_completed_not_emerging(self):
        emerging = detect_emerging(["httpbin", "urlquery", "eval"])
        self.assertFalse(any(e.pattern == "browser-rce" for e in emerging))

    def test_below_threshold_silent(self):
        # 1/3 = 0.33 < 0.5 default threshold
        emerging = detect_emerging(["httpbin"])
        self.assertFalse(any(e.pattern == "browser-rce" for e in emerging))

    def test_custom_threshold(self):
        emerging = detect_emerging(["httpbin"], threshold=0.3)
        self.assertTrue(any(e.pattern == "browser-rce" for e in emerging))

    def test_threshold_validation(self):
        with self.assertRaises(TypeError):
            detect_emerging(["httpbin"], threshold="high")
        with self.assertRaises(ValueError):
            detect_emerging(["httpbin"], threshold=1.0)
        with self.assertRaises(ValueError):
            detect_emerging(["httpbin"], threshold=0.0)

    def test_no_match_no_emerging(self):
        self.assertEqual(detect_emerging(["echo", "date"]), ())


class MainTests(unittest.TestCase):
    def test_main_runs(self):
        main()


if __name__ == "__main__":
    unittest.main()
