"""Tests for code_formatter."""

import ast
import unittest
from pathlib import Path

import code_formatter as mod
from code_formatter import (
    AUDIT_SCHEMA,
    CODE_FORMATTER_VERSION,
    FINDING_CODES,
    LOSS_LEDGER,
    SCHEMA_PIN,
    BadOptionError,
    CodeFormatter,
    DuplicateSourceError,
    SeqOrderError,
    UnknownLanguageError,
    UnknownSourceError,
    ValidationError,
    code_formatter_audit_event,
)


class TestVersionAndSchema(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(CODE_FORMATTER_VERSION, "code-formatter.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.code-formatter.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")

    def test_loss_ledger_declared(self):
        self.assertEqual(
            LOSS_LEDGER,
            (
                "line-wrapping",
                "magic-trailing-comma",
                "string-quote-normalization",
                "bracket-spacing",
            ),
        )

    def test_finding_codes(self):
        self.assertIn("trailing-whitespace", FINDING_CODES)
        self.assertIn("line-too-long", FINDING_CODES)


class TestRegister(unittest.TestCase):
    def test_register_roundtrip(self):
        f = CodeFormatter()
        rec = f.register("s1", "x = 1\n", 1, language="python")
        self.assertTrue(rec.pin.startswith("sha256:"))
        self.assertEqual(f.source("s1").pin, rec.pin)
        self.assertEqual(f.source_ids(), ("s1",))

    def test_register_default_language(self):
        f = CodeFormatter()
        rec = f.register("s1", "x = 1\n", 1)
        self.assertEqual(rec.language, "python")

    def test_register_duplicate(self):
        f = CodeFormatter()
        f.register("s1", "x\n", 1)
        with self.assertRaises(DuplicateSourceError):
            f.register("s1", "y\n", 2)

    def test_register_bad_language(self):
        f = CodeFormatter()
        with self.assertRaises(UnknownLanguageError):
            f.register("s1", "x\n", 1, language="cobol")

    def test_register_unknown_source(self):
        f = CodeFormatter()
        with self.assertRaises(UnknownSourceError):
            f.source("nope")

    def test_register_bad_source_id(self):
        f = CodeFormatter()
        with self.assertRaises(ValidationError):
            f.register("", "x\n", 1)

    def test_seq_order(self):
        f = CodeFormatter()
        f.register("s1", "x\n", 1)
        with self.assertRaises(SeqOrderError):
            f.register("s2", "y\n", 1)  # not strictly increasing
        with self.assertRaises(SeqOrderError):
            f.register("s2", "y\n", True)  # bool seq refused


class TestFormat(unittest.TestCase):
    def test_format_strips_trailing_whitespace(self):
        f = CodeFormatter()
        f.register("s1", "x = 1   \ny = 2\n", 1)
        out = f.format("s1", 2)
        self.assertEqual(out.output, "x = 1\ny = 2\n")
        self.assertTrue(out.changed)

    def test_format_tab_to_space4(self):
        f = CodeFormatter()
        f.register("s1", "\tx = 1\n", 1)
        out = f.format("s1", 2)
        self.assertEqual(out.output, "    x = 1\n")

    def test_format_crlf_normalized(self):
        f = CodeFormatter()
        f.register("s1", "a\r\nb\r\n", 1)
        out = f.format("s1", 2)
        self.assertEqual(out.output, "a\nb\n")

    def test_format_collapses_blank_lines(self):
        f = CodeFormatter()
        f.register("s1", "a\n\n\n\n\nb\n", 1)
        out = f.format("s1", 2)
        self.assertEqual(out.output, "a\n\n\nb\n")

    def test_format_final_newline(self):
        f = CodeFormatter()
        f.register("s1", "a", 1)
        out = f.format("s1", 2)
        self.assertEqual(out.output, "a\n")

    def test_format_already_clean_no_change(self):
        f = CodeFormatter()
        f.register("s1", "a\n", 1)
        out = f.format("s1", 2)
        self.assertFalse(out.changed)
        self.assertEqual(out.output, "a\n")

    def test_format_verify_pin(self):
        f = CodeFormatter()
        f.register("s1", "x = 1  \n", 1)
        out = f.format("s1", 2)
        self.assertTrue(out.verify())
        self.assertTrue(out.output_pin.startswith("sha256:"))

    def test_format_determinism(self):
        a, b = CodeFormatter(), CodeFormatter()
        a.register("s1", "x = 1  \n", 1)
        b.register("s1", "x = 1  \n", 1)
        self.assertEqual(a.format("s1", 2).output_pin, b.format("s1", 2).output_pin)

    def test_format_unknown_source(self):
        f = CodeFormatter()
        with self.assertRaises(UnknownSourceError):
            f.format("nope", 1)

    def test_format_bad_options(self):
        f = CodeFormatter()
        f.register("s1", "x\n", 1)
        with self.assertRaises(BadOptionError):
            f.format("s1", 2, line_length=5)
        with self.assertRaises(BadOptionError):
            f.format("s1", 3, indent="spaces-8")

    def test_format_history(self):
        f = CodeFormatter()
        f.register("s1", "x  \n", 1)
        f.format("s1", 2)
        f.format("s1", 3, indent="space2")
        hist = f.format_history("s1")
        self.assertEqual(len(hist), 2)
        with self.assertRaises(UnknownSourceError):
            f.format_history("nope")


class TestCheck(unittest.TestCase):
    def test_check_clean(self):
        f = CodeFormatter()
        f.register("s1", "def f():\n    return 1\n", 1)
        report = f.check("s1", 2)
        self.assertEqual(report.verdict, "clean")
        self.assertEqual(report.findings, ())

    def test_check_dirty_findings(self):
        f = CodeFormatter()
        f.register("s1", "x = 1   \n\tindented\n", 1)
        report = f.check("s1", 2)
        self.assertEqual(report.verdict, "dirty")
        codes = {finding["code"] for finding in report.findings}
        self.assertIn("trailing-whitespace", codes)
        self.assertIn("tab-indentation", codes)

    def test_check_line_too_long(self):
        f = CodeFormatter()
        f.register("s1", "x = '" + "a" * 100 + "'\n", 1)
        report = f.check("s1", 2, line_length=88)
        codes = {finding["code"] for finding in report.findings}
        self.assertIn("line-too-long", codes)

    def test_check_missing_final_newline(self):
        f = CodeFormatter()
        f.register("s1", "x = 1", 1)
        report = f.check("s1", 2)
        codes = {finding["code"] for finding in report.findings}
        self.assertIn("missing-final-newline", codes)

    def test_check_report_pin(self):
        f = CodeFormatter()
        f.register("s1", "x = 1\n", 1)
        report = f.check("s1", 2)
        self.assertTrue(report.report_pin.startswith("sha256:"))

    def test_check_unknown_source(self):
        f = CodeFormatter()
        with self.assertRaises(UnknownSourceError):
            f.check("nope", 1)


class TestDiff(unittest.TestCase):
    def test_diff_changed(self):
        f = CodeFormatter()
        f.register("s1", "x = 1  \n", 1)
        report = f.diff("s1", 2)
        self.assertTrue(report.changed)
        self.assertGreater(report.hunks, 0)
        self.assertIn("--- a/source", report.diff)
        self.assertTrue(report.diff_pin.startswith("sha256:"))

    def test_diff_no_change(self):
        f = CodeFormatter()
        f.register("s1", "x = 1\n", 1)
        report = f.diff("s1", 2)
        self.assertFalse(report.changed)
        self.assertEqual(report.hunks, 0)
        self.assertEqual(report.diff, "")


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        event = code_formatter_audit_event(
            "formatted", 2, {"output_pin": "sha256:abc"}
        )
        self.assertEqual(event["kind"], "formatted")
        self.assertEqual(event["audit_schema"], AUDIT_SCHEMA)
        self.assertEqual(event["version"], CODE_FORMATTER_VERSION)

    def test_audit_unknown_kind(self):
        with self.assertRaises(ValidationError):
            code_formatter_audit_event("exploded", 1, {})

    def test_audit_log_accumulates(self):
        f = CodeFormatter()
        f.register("s1", "x = 1  \n", 1)
        f.format("s1", 2)
        f.check("s1", 3)
        f.diff("s1", 4)
        kinds = [e["kind"] for e in f.audit_log()]
        self.assertEqual(
            kinds, ["source-registered", "formatted", "checked", "diffed"]
        )


class TestHouseConventions(unittest.TestCase):
    def test_stdlib_only(self):
        tree = ast.parse(Path(mod.__file__).read_text())
        allowed = {
            "difflib",
            "hashlib",
            "json",
            "threading",
            "dataclasses",
            "typing",
            "__future__",
        }
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module and node.level == 0:
                    imported.add(node.module.split(".")[0])
        self.assertLessEqual(imported, allowed | {"canonical_json"})

    def test_main_self_check(self):
        mod.main()

    def test_error_hierarchy(self):
        for exc in (
            UnknownSourceError,
            DuplicateSourceError,
            UnknownLanguageError,
            BadOptionError,
            SeqOrderError,
            ValidationError,
        ):
            self.assertTrue(issubclass(exc, mod.CodeFormatterError))


if __name__ == "__main__":
    unittest.main()
