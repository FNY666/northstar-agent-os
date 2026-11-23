"""Tests for doc_converter: Pandoc-style format conversion bookkeeping."""

import ast
import unittest

from doc_converter import (
    DOC_CONVERTER_VERSION,
    SCHEMA_PIN,
    DocConverter,
    DocumentTooLargeError,
    EmptyDocumentError,
    SeqOrderError,
    UnsupportedConversionError,
    UnknownFormatError,
    ValidationError,
    doc_converter_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_and_schema(self):
        self.assertEqual(DOC_CONVERTER_VERSION, "doc-converter.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.doc-converter.v1")

    def test_stdlib_only(self):
        tree = ast.parse(open("doc_converter.py").read())
        allowed = {
            "hashlib", "re", "threading", "dataclasses", "typing",
            "__future__", "json", "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn(node.module.split(".")[0], allowed)


class TestFormats(unittest.TestCase):
    def test_formats_all(self):
        fmts = DocConverter().formats()
        for f in ("markdown", "html", "text", "rst", "json"):
            self.assertIn(f, fmts)

    def test_formats_direction(self):
        dc = DocConverter()
        self.assertIn("markdown", dc.formats("in"))
        self.assertIn("json", dc.formats("out"))
        self.assertNotIn("json", dc.formats("in"))

    def test_bad_direction(self):
        with self.assertRaises(ValidationError):
            DocConverter().formats("sideways")


class TestConvert(unittest.TestCase):
    def test_md_to_html(self):
        dc = DocConverter()
        rec, out = dc.convert("# Hi\n\n**bold**", "markdown", "html", 1)
        self.assertIn("<h1>Hi</h1>", out)
        self.assertIn("<strong>bold</strong>", out)
        self.assertTrue(rec.verify(out))
        self.assertTrue(rec.input_digest.startswith("sha256:"))
        self.assertEqual(rec.seq, 1)

    def test_md_to_text_losses(self):
        dc = DocConverter()
        rec, out = dc.convert("[Docs](https://x.example) *em*", "markdown", "text", 1)
        self.assertNotIn("https://", out)
        self.assertIn("Docs", out)
        self.assertTrue(any("URL" in l for l in rec.losses))

    def test_determinism(self):
        dc = DocConverter()
        r1, o1 = dc.convert("hello", "text", "html", 1)
        r2, o2 = dc.convert("hello", "text", "html", 2)
        self.assertEqual(o1, o2)
        self.assertEqual(r1.output_digest, r2.output_digest)

    def test_unsupported_pair(self):
        with self.assertRaises(UnsupportedConversionError):
            DocConverter().convert("<p>x</p>", "html", "json", 1)

    def test_unknown_format(self):
        with self.assertRaises(UnknownFormatError):
            DocConverter().convert("x", "docx", "html", 1)

    def test_empty_document(self):
        with self.assertRaises(EmptyDocumentError):
            DocConverter().convert("   ", "markdown", "html", 1)

    def test_seq_rewind(self):
        dc = DocConverter()
        dc.convert("a", "text", "html", 5)
        with self.assertRaises(SeqOrderError):
            dc.convert("a", "text", "html", 5)


class TestMetadata(unittest.TestCase):
    def test_metadata_fields(self):
        md = DocConverter().metadata(
            "# Title\nAuthor: Ada\nDate: 2026-10-07", "markdown", 1
        )
        self.assertEqual(md.title, "Title")
        self.assertEqual(md.author, "Ada")
        self.assertEqual(md.date, "2026-10-07")
        self.assertTrue(md.doc_digest.startswith("sha256:"))

    def test_metadata_unknown_format(self):
        with self.assertRaises(UnknownFormatError):
            DocConverter().metadata("x", "docx", 1)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        ev = doc_converter_audit_event("converted", 3, "conv-1")
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        with self.assertRaises(ValidationError):
            doc_converter_audit_event("nope", 1, "")


if __name__ == "__main__":
    unittest.main()
