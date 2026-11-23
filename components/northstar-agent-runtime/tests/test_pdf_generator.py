"""Tests for pdf_generator.py."""

import ast
import re
import unittest

import pdf_generator
from pdf_generator import (
    PDFGenerator,
    DuplicateDocumentError,
    FinalizedError,
    PDF_GENERATOR_VERSION,
    SCHEMA_PIN,
    SeqOrderError,
    UnknownDocumentError,
    UnknownPageError,
    ValidationError,
    pdf_generator_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(PDF_GENERATOR_VERSION, "pdf-generator.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.pdf-generator.v1")


class TestDocumentLifecycle(unittest.TestCase):
    def setUp(self):
        self.gen = PDFGenerator()

    def test_new_document_returns_id(self):
        self.assertEqual(self.gen.new_document("D1", 1), "D1")

    def test_duplicate_document_refused(self):
        self.gen.new_document("D1", 1)
        with self.assertRaises(DuplicateDocumentError):
            self.gen.new_document("D1", 2)

    def test_metadata_optional_and_accepted(self):
        self.gen.new_document(
            "D1", 1, title="Report", author="northstar",
            subject="q", keywords="a,b",
        )
        self.gen.page("D1", 2)
        doc = self.gen.save("D1", 3)
        self.assertIn(b"/Title (Report)", doc.body)
        self.assertIn(b"/Author (northstar)", doc.body)

    def test_empty_doc_id_refused(self):
        with self.assertRaises(ValidationError):
            self.gen.new_document("  ", 1)


class TestPages(unittest.TestCase):
    def setUp(self):
        self.gen = PDFGenerator()
        self.gen.new_document("D1", 1)

    def test_page_default_letter(self):
        p = self.gen.page("D1", 2)
        self.assertEqual((p.width, p.height), (612, 792))
        self.assertEqual(p.page_no, 1)

    def test_page_numbering_monotonic(self):
        self.gen.page("D1", 2)
        p2 = self.gen.page("D1", 3, width=595, height=842)
        self.assertEqual(p2.page_no, 2)

    def test_bad_dimensions_refused(self):
        for i, (w, h) in enumerate([(0, 100), (-5, 100), (100, 0), (True, 100), (100.5, 100)]):
            with self.assertRaises(ValidationError, msg=f"{w}x{h}"):
                self.gen.page("D1", 10 + i, width=w, height=h)

    def test_page_on_unknown_document(self):
        with self.assertRaises(UnknownDocumentError):
            self.gen.page("NOPE", 2)


class TestText(unittest.TestCase):
    def setUp(self):
        self.gen = PDFGenerator()
        self.gen.new_document("D1", 1)
        self.gen.page("D1", 2)

    def test_text_happy_path(self):
        t = self.gen.text("D1", 1, 3, 72, 700, "Hello", font="Helvetica", size=12)
        self.assertEqual(t.text_id, "tx-1")
        self.assertEqual((t.x, t.y), (72, 700))
        self.assertTrue(t.pin.startswith("sha256:"))

    def test_text_ids_unique_per_document(self):
        t1 = self.gen.text("D1", 1, 3, 0, 0, "a")
        t2 = self.gen.text("D1", 1, 4, 0, 0, "b")
        self.assertNotEqual(t1.text_id, t2.text_id)
        self.assertEqual(t1.pin != t2.pin, True)

    def test_unknown_font_refused(self):
        with self.assertRaises(ValidationError):
            self.gen.text("D1", 1, 3, 0, 0, "x", font="ComicSans")

    def test_bad_size_refused(self):
        for i, s in enumerate((0, -3, 289, 12.5, True)):
            with self.assertRaises(ValidationError, msg=f"size={s}"):
                self.gen.text("D1", 1, 10 + i, 0, 0, "x", size=s)

    def test_unknown_page_refused(self):
        with self.assertRaises(UnknownPageError):
            self.gen.text("D1", 9, 3, 0, 0, "x")

    def test_non_ascii_refused(self):
        with self.assertRaises(ValidationError):
            self.gen.text("D1", 1, 3, 0, 0, "héllo")

    def test_empty_text_refused(self):
        with self.assertRaises(ValidationError):
            self.gen.text("D1", 1, 3, 0, 0, "")


class TestSave(unittest.TestCase):
    def setUp(self):
        self.gen = PDFGenerator()
        self.gen.new_document("D1", 1, title="T")
        self.gen.page("D1", 2)
        self.gen.text("D1", 1, 3, 72, 700, "Hello (world) \\ ok", size=12)

    def test_save_header_and_eof(self):
        doc = self.gen.save("D1", 4)
        self.assertTrue(doc.body.startswith(b"%PDF-1.7"))
        self.assertTrue(doc.body.rstrip().endswith(b"%%EOF"))

    def test_save_pins_and_counts(self):
        doc = self.gen.save("D1", 4)
        self.assertEqual(doc.page_count, 1)
        self.assertTrue(doc.pin.startswith("sha256:"))
        self.assertTrue(doc.model_pin.startswith("sha256:"))
        self.assertEqual(doc.byte_length, len(doc.body))
        # deterministic: same model replays to the same pin
        gen2 = PDFGenerator()
        gen2.new_document("D1", 1, title="T")
        gen2.page("D1", 2)
        gen2.text("D1", 1, 3, 72, 700, "Hello (world) \\ ok", size=12)
        doc2 = gen2.save("D1", 4)
        self.assertEqual(doc.pin, doc2.pin)
        self.assertEqual(doc.model_pin, doc2.model_pin)

    def test_text_escaping_in_stream(self):
        doc = self.gen.save("D1", 4)
        self.assertIn(b"(Hello \\(world\\) \\\\ ok)", doc.body)

    def test_multiline_text_emits_each_line(self):
        gen = PDFGenerator()
        gen.new_document("D2", 1)
        gen.page("D2", 2)
        gen.text("D2", 1, 3, 72, 700, "one\ntwo", size=12)
        doc = gen.save("D2", 4)
        self.assertIn(b"(one) Tj ET", doc.body)
        self.assertIn(b"(two) Tj ET", doc.body)

    def test_xref_offsets_byte_exact(self):
        doc = self.gen.save("D1", 4)
        body = doc.body
        xref_at = body.rfind(b"startxref")
        xref_pos = int(body[xref_at:].split()[1])
        self.assertEqual(body[xref_pos:xref_pos + 4], b"xref")
        # parse each offset and check the object header is really there
        xref = body[xref_pos:].split(b"\n")
        n_objects = int(xref[1].split()[1])
        for line in xref[2:2 + n_objects]:
            offset = int(line[:10])
            if offset == 0:
                continue
            gen_no = line[11:16]
            self.assertEqual(gen_no, b"00000")
            obj_head = body[offset:].split(b"\n")[0]
            self.assertRegex(obj_head, rb"^\d+ 0 obj$")

    def test_trailer_points_at_catalog(self):
        doc = self.gen.save("D1", 4)
        self.assertIn(b"/Root 1 0 R", doc.body)
        self.assertIn(b"/Info", doc.body)
        self.assertIn(b"/Size 7", doc.body)

    def test_mediabox_in_page_object(self):
        doc = self.gen.save("D1", 4)
        self.assertIn(b"/MediaBox [0 0 612 792]", doc.body)

    def test_content_references_fonts(self):
        doc = self.gen.save("D1", 4)
        self.assertIn(b"/BaseFont /Helvetica", doc.body)
        self.assertIn(b"BT /F1 12 Tf 72 700 Td", doc.body)

    def test_save_requires_pages(self):
        gen = PDFGenerator()
        gen.new_document("E1", 1)
        with self.assertRaises(ValidationError):
            gen.save("E1", 2)

    def test_post_save_mutations_refused(self):
        self.gen.save("D1", 4)
        with self.assertRaises(FinalizedError):
            self.gen.page("D1", 5)
        with self.assertRaises(FinalizedError):
            self.gen.text("D1", 1, 6, 0, 0, "late")
        with self.assertRaises(FinalizedError):
            self.gen.save("D1", 7)

    def test_save_unknown_document(self):
        with self.assertRaises(UnknownDocumentError):
            self.gen.save("NOPE", 4)


class TestSeqOrder(unittest.TestCase):
    def test_rewind_refused(self):
        gen = PDFGenerator()
        gen.new_document("D1", 5)
        with self.assertRaises(SeqOrderError):
            gen.page("D1", 5)
        with self.assertRaises(SeqOrderError):
            gen.page("D1", 3)

    def test_bool_seq_refused(self):
        gen = PDFGenerator()
        with self.assertRaises(ValidationError):
            gen.new_document("D1", True)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        ev = pdf_generator_audit_event(
            "document-saved", 7, {"doc_id": "D1"}
        )
        self.assertEqual(ev["kind"], "document-saved")
        self.assertEqual(ev["seq"], 7)
        self.assertEqual(ev["version"], PDF_GENERATOR_VERSION)
        self.assertEqual(ev["schema"], SCHEMA_PIN)

    def test_unknown_kind_rejected(self):
        with self.assertRaises(ValidationError):
            pdf_generator_audit_event("nope", 1, {})

    def test_stdlib_only(self):
        with open(pdf_generator.__file__) as fh:
            tree = ast.parse(fh.read())
        allowed = {
            "hashlib", "re", "threading", "dataclasses", "typing",
            "__future__", "json", "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed, a.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed, node.module)

    def test_main_self_check(self):
        pdf_generator.main()


if __name__ == "__main__":
    unittest.main()
