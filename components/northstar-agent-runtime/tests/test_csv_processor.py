"""Tests for csv_processor (RFC 4180 parse/emit/validate)."""

import unittest

from csv_processor import (
    CSV_PROCESSOR_VERSION,
    SCHEMA_PIN,
    BadDialectError,
    BadRecordError,
    CSVError,
    CSVProcessor,
    EmptyInputError,
    RaggedRowError,
    SeqOrderError,
    UnbalancedQuoteError,
    csv_processor_audit_event,
    main,
)


class TestVersionPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(CSV_PROCESSOR_VERSION, "csv-processor.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.csv-processor.v1")


class TestParse(unittest.TestCase):
    def test_simple(self):
        p = CSVProcessor()
        parsed = p.parse("a,b,c\r\n1,2,3\r\n", 1)
        self.assertEqual(parsed.header, ("a", "b", "c"))
        self.assertEqual(parsed.rows, (("1", "2", "3"),))
        self.assertEqual(parsed.record_count, 1)
        self.assertEqual(parsed.field_count, 3)
        self.assertEqual(parsed.line_ending, "\r\n")
        self.assertTrue(parsed.digest.startswith("sha256:"))

    def test_quoted_fields(self):
        p = CSVProcessor()
        parsed = p.parse('a,b\r\n"x, y","he said ""hi"""\r\n', 1)
        self.assertEqual(parsed.rows, (("x, y", 'he said "hi"'),))

    def test_embedded_newline(self):
        p = CSVProcessor()
        parsed = p.parse('a\r\n"line1\nline2"\r\n', 1)
        self.assertEqual(parsed.rows, (("line1\nline2",),))
        self.assertEqual(parsed.record_count, 1)

    def test_unbalanced_quote_raises(self):
        p = CSVProcessor()
        with self.assertRaises(UnbalancedQuoteError):
            p.parse('a\r\n"x\r\n', 1)

    def test_ragged_row_raises(self):
        p = CSVProcessor()
        with self.assertRaises(RaggedRowError):
            p.parse("a,b\r\n1,2,3\r\n", 1)

    def test_empty_input_raises(self):
        p = CSVProcessor()
        with self.assertRaises(EmptyInputError):
            p.parse("", 1)

    def test_header_only(self):
        p = CSVProcessor()
        parsed = p.parse("a,b\r\n", 1)
        self.assertEqual(parsed.record_count, 0)
        self.assertEqual(parsed.rows, ())


class TestEmit(unittest.TestCase):
    def test_roundtrip_digest(self):
        p = CSVProcessor()
        parsed = p.parse('a,b\r\n"x","y,y"\r\n', 1)
        emitted = p.emit(["a", "b"], [["x", "y,y"]], 2)
        self.assertEqual(emitted.text, 'a,b\r\nx,"y,y"\r\n')
        self.assertEqual(parsed.digest, emitted.digest)

    def test_quotes_doubled(self):
        p = CSVProcessor()
        emitted = p.emit(["a"], [['say "hi"']], 1)
        self.assertEqual(emitted.text, 'a\r\n"say ""hi"""\r\n')

    def test_empty_header_raises(self):
        p = CSVProcessor()
        with self.assertRaises(EmptyInputError):
            p.emit([], [], 1)

    def test_ragged_emit_raises(self):
        p = CSVProcessor()
        with self.assertRaises(RaggedRowError):
            p.emit(["a", "b"], [["1"]], 1)


class TestValidate(unittest.TestCase):
    def test_valid_crlf(self):
        p = CSVProcessor()
        report = p.validate("a,b\r\n1,2\r\n", 1)
        self.assertTrue(report.valid)
        self.assertEqual(report.issues, ())

    def test_lf_flagged(self):
        p = CSVProcessor()
        report = p.validate("a,b\n1,2\n", 1)
        self.assertFalse(report.valid)
        self.assertIn("line-ending:'\\n'", report.issues)

    def test_unbalanced_reported(self):
        p = CSVProcessor()
        report = p.validate('a\r\n"x\r\n', 1)
        self.assertFalse(report.valid)
        self.assertIn("unbalanced-quote", report.issues)


class TestDialectAndSeq(unittest.TestCase):
    def test_bad_dialect(self):
        with self.assertRaises(BadDialectError):
            CSVProcessor(delimiter="::")
        with self.assertRaises(BadDialectError):
            CSVProcessor(delimiter=",", quotechar=",")

    def test_seq_monotonic(self):
        p = CSVProcessor()
        p.parse("a\r\n1\r\n", 5)
        with self.assertRaises(SeqOrderError):
            p.parse("a\r\n1\r\n", 5)

    def test_custom_delimiter(self):
        p = CSVProcessor(delimiter=";")
        parsed = p.parse("a;b\r\n1;2\r\n", 1)
        self.assertEqual(parsed.header, ("a", "b"))


class TestAuditAndMain(unittest.TestCase):
    def test_audit_shape(self):
        evt = csv_processor_audit_event("validated", 3, "sha256:abc")
        self.assertEqual(evt["schema"], SCHEMA_PIN)
        self.assertEqual(evt["kind"], "validated")

    def test_audit_bad_kind(self):
        with self.assertRaises(CSVError):
            csv_processor_audit_event("frobnicate", 1)

    def test_main(self):
        main()


if __name__ == "__main__":
    unittest.main()
