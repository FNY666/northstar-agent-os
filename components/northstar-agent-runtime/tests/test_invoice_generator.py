"""Targeted tests for invoice_generator."""

import unittest

from invoice_generator import (
    SCHEMA_PIN,
    INVOICE_GENERATOR_VERSION,
    DuplicateInvoiceError,
    FinalizedError,
    InvoiceError,
    InvoiceGenerator,
    LineItem,
    SeqOrderError,
    UnknownInvoiceError,
    ValidationError,
    invoice_generator_audit_event,
    main,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(INVOICE_GENERATOR_VERSION, "invoice-generator.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.invoice-generator.v1")

    def test_error_hierarchy(self):
        for cls in (DuplicateInvoiceError, UnknownInvoiceError, FinalizedError,
                    ValidationError, SeqOrderError):
            self.assertTrue(issubclass(cls, InvoiceError))


class TestCreate(unittest.TestCase):
    def setUp(self):
        self.gen = InvoiceGenerator()

    def test_create_happy_path(self):
        view = self.gen.create("INV-1", "Acme Corp", 1)
        self.assertEqual(view.invoice_id, "INV-1")
        self.assertEqual(view.customer, "Acme Corp")
        self.assertFalse(view.finalized)
        self.assertEqual(view.item_count, 0)
        self.assertTrue(view.digest.startswith("sha256:"))
        self.assertEqual(view.version, INVOICE_GENERATOR_VERSION)
        self.assertEqual(view.schema, SCHEMA_PIN)

    def test_create_duplicate(self):
        self.gen.create("INV-1", "Acme", 1)
        with self.assertRaises(DuplicateInvoiceError):
            self.gen.create("INV-1", "Acme", 2)

    def test_create_bad_inputs(self):
        for bad in ("", "   ", None, 5, b"INV"):
            with self.assertRaises(ValidationError):
                self.gen.create(bad, "Acme", 1)
        for bad in ("", "   ", None):
            with self.assertRaises(ValidationError):
                self.gen.create("INV-9", bad, 1)

    def test_create_bad_seq(self):
        for bad in (True, -1, "1", 1.0):
            with self.assertRaises(ValidationError):
                self.gen.create("INV-1", "Acme", bad)

    def test_invoice_view_roundtrip(self):
        self.gen.create("INV-1", "Acme", 1)
        view = self.gen.invoice("INV-1")
        self.assertEqual(view.customer, "Acme")

    def test_invoice_unknown(self):
        with self.assertRaises(UnknownInvoiceError):
            self.gen.invoice("NOPE")


class TestLineItems(unittest.TestCase):
    def setUp(self):
        self.gen = InvoiceGenerator()
        self.gen.create("INV-1", "Acme", 1)

    def test_add_item_happy_path(self):
        item = self.gen.add_item("INV-1", "Widgets", 3, 1999, 2)
        self.assertIsInstance(item, LineItem)
        self.assertEqual(item.line_no, 1)
        self.assertEqual(item.description, "Widgets")
        self.assertEqual(item.line_total_cents, 3 * 1999)
        self.assertTrue(item.digest.startswith("sha256:"))

    def test_line_numbering(self):
        a = self.gen.add_item("INV-1", "A", 1, 100, 2)
        b = self.gen.add_item("INV-1", "B", 2, 100, 3)
        self.assertEqual((a.line_no, b.line_no), (1, 2))

    def test_add_item_bad_inputs(self):
        with self.assertRaises(ValidationError):
            self.gen.add_item("INV-1", "A", 0, 100, 2)  # qty must be positive
        with self.assertRaises(ValidationError):
            self.gen.add_item("INV-1", "A", True, 100, 2)  # bool qty
        with self.assertRaises(ValidationError):
            self.gen.add_item("INV-1", "A", 1, -5, 2)  # negative price
        with self.assertRaises(ValidationError):
            self.gen.add_item("INV-1", "A", 1, 19.99, 2)  # float price
        with self.assertRaises(ValidationError):
            self.gen.add_item("INV-1", "  ", 1, 100, 2)  # empty description

    def test_add_item_unknown_invoice(self):
        with self.assertRaises(UnknownInvoiceError):
            self.gen.add_item("NOPE", "A", 1, 100, 2)

    def test_add_item_seq_rewind(self):
        self.gen.add_item("INV-1", "A", 1, 100, 5)
        with self.assertRaises(SeqOrderError):
            self.gen.add_item("INV-1", "B", 1, 100, 5)  # must strictly increase

    def test_add_item_after_finalize(self):
        self.gen.finalize("INV-1", 2)
        with self.assertRaises(FinalizedError):
            self.gen.add_item("INV-1", "A", 1, 100, 3)

    def test_items_view(self):
        item = self.gen.add_item("INV-1", "Widgets", 3, 1999, 2)
        rows = self.gen.items("INV-1")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0], item)  # digest round-trips the recorded seq

    def test_frozen_records(self):
        item = self.gen.add_item("INV-1", "A", 1, 100, 2)
        with self.assertRaises(Exception):
            item.quantity = 9  # type: ignore[misc]


class TestTaxAndTotals(unittest.TestCase):
    def setUp(self):
        self.gen = InvoiceGenerator()
        self.gen.create("INV-1", "Acme", 1)
        self.gen.add_item("INV-1", "Widgets", 3, 1999, 2)
        self.gen.add_item("INV-1", "Gadgets", 1, 4999, 3)

    def test_tax_set(self):
        rec = self.gen.tax("INV-1", 825, 4)
        self.assertEqual(rec.tax_rate_bp, 825)
        self.assertTrue(rec.digest.startswith("sha256:"))

    def test_tax_default_zero(self):
        totals = self.gen.totals("INV-1", 4)
        self.assertEqual(totals.tax_rate_bp, 0)
        self.assertEqual(totals.tax_cents, 0)

    def test_totals_math(self):
        subtotal = 3 * 1999 + 4999  # 10996
        self.gen.tax("INV-1", 825, 4)
        totals = self.gen.totals("INV-1", 5)
        self.assertEqual(totals.subtotal_cents, subtotal)
        # half-up: (10996 * 825 + 5000) // 10000 = (9071700+5000)//10000 = 907
        self.assertEqual(totals.tax_cents, (subtotal * 825 + 5000) // 10000)
        self.assertEqual(totals.tax_cents, 907)
        self.assertEqual(totals.total_cents, subtotal + 907)
        self.assertTrue(totals.digest.startswith("sha256:"))

    def test_tax_half_up_boundary(self):
        # subtotal 1 cent at 5000 bp (50%): (1*5000+5000)//10000 = 1 -> half-up rounds up
        g2 = InvoiceGenerator()
        g2.create("INV-2", "B", 1)
        g2.add_item("INV-2", "Penny", 1, 1, 2)
        g2.tax("INV-2", 5000, 3)
        totals = g2.totals("INV-2", 4)
        self.assertEqual(totals.tax_cents, 1)

    def test_tax_bad_rate(self):
        for bad in (-1, 10001, True, 8.25, "825"):
            with self.assertRaises(ValidationError):
                self.gen.tax("INV-1", bad, 4)

    def test_tax_after_finalize(self):
        self.gen.finalize("INV-1", 4)
        with self.assertRaises(FinalizedError):
            self.gen.tax("INV-1", 100, 5)

    def test_tax_seq_rewind(self):
        self.gen.tax("INV-1", 100, 9)
        with self.assertRaises(SeqOrderError):
            self.gen.tax("INV-1", 200, 9)

    def test_totals_digest_determinism(self):
        t1 = self.gen.totals("INV-1", 4)
        t2 = self.gen.totals("INV-1", 4)
        self.assertEqual(t1.digest, t2.digest)


class TestRender(unittest.TestCase):
    def setUp(self):
        self.gen = InvoiceGenerator()
        self.gen.create("INV-1", "Acme Corp", 1)
        self.gen.add_item("INV-1", "Widgets", 3, 1999, 2)
        self.gen.tax("INV-1", 825, 3)

    def test_render_text(self):
        r = self.gen.render("INV-1", 4)
        self.assertEqual(r.format, "text")
        self.assertIn("INVOICE INV-1", r.body)
        self.assertIn("Acme Corp", r.body)
        self.assertIn("Widgets", r.body)
        self.assertIn("TOTAL", r.body)
        self.assertIn("64.92", r.body)  # 5997+495 = 6492 cents
        self.assertTrue(r.digest.startswith("sha256:"))

    def test_render_dict(self):
        r = self.gen.render("INV-1", 4, format="dict")
        self.assertEqual(r.format, "dict")
        body = r.body
        self.assertEqual(body["invoice_id"], "INV-1")
        self.assertEqual(len(body["lines"]), 1)
        self.assertEqual(body["subtotal_cents"], 5997)
        self.assertEqual(body["tax_rate_bp"], 825)
        self.assertEqual(body["total_cents"], body["subtotal_cents"] + body["tax_cents"])

    def test_render_deterministic(self):
        r1 = self.gen.render("INV-1", 4)
        r2 = self.gen.render("INV-1", 4)
        self.assertEqual(r1.digest, r2.digest)

    def test_render_bad_format(self):
        with self.assertRaises(ValidationError):
            self.gen.render("INV-1", 4, format="pdf")

    def test_render_unknown_invoice(self):
        with self.assertRaises(UnknownInvoiceError):
            self.gen.render("NOPE", 4)

    def test_render_finalized(self):
        self.gen.finalize("INV-1", 4)
        r = self.gen.render("INV-1", 5)
        self.assertIn("TOTAL", r.body)

    def test_as_dict_shapes(self):
        item = self.gen.add_item("INV-1", "A", 1, 100, 4)
        self.assertIn("line_total_cents", item.as_dict())
        totals = self.gen.totals("INV-1", 5)
        self.assertIn("total_cents", totals.as_dict())
        rec = self.gen.tax("INV-1", 100, 6)
        self.assertIn("tax_rate_bp", rec.as_dict())
        r = self.gen.render("INV-1", 7)
        self.assertIn("body", r.as_dict())
        view = self.gen.invoice("INV-1")
        self.assertIn("finalized", view.as_dict())


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        ev = invoice_generator_audit_event("item-added", 3, {"invoice_id": "INV-1"})
        self.assertEqual(ev["kind"], "item-added")
        self.assertEqual(ev["seq"], 3)
        self.assertEqual(ev["version"], "invoice-generator.v1")
        self.assertEqual(ev["schema"], "northstar.invoice-generator.v1")

    def test_audit_unknown_kind(self):
        with self.assertRaises(ValidationError):
            invoice_generator_audit_event("printed", 1, {})

    def test_audit_bad_seq(self):
        with self.assertRaises(ValidationError):
            invoice_generator_audit_event("rendered", -1, {})

    def test_audit_bad_detail(self):
        with self.assertRaises(ValidationError):
            invoice_generator_audit_event("rendered", 1, "nope")  # type: ignore[arg-type]


class TestMain(unittest.TestCase):
    def test_main(self):
        main()


if __name__ == "__main__":
    unittest.main()
