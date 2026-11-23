"""Tests for barcode_scanner (QR / DataMatrix shaped, simulated)."""

import unittest

from barcode_scanner import (
    AUDIT_SCHEMA,
    AZTEC,
    BARCODE_SCANNER_SCHEMA,
    BARCODE_SCANNER_VERSION,
    CODE128,
    CODE39,
    DATAMATRIX,
    EAN13,
    FORMATS,
    KIND_DECODED,
    KIND_GENERATED,
    KIND_REJECTED,
    PDF417,
    QR,
    UPCA,
    BadOptionError,
    BadPayloadError,
    BarcodeScanner,
    BarcodeScannerError,
    DecodedCode,
    FormatMismatchError,
    GeneratedCode,
    PayloadTooLargeError,
    SeqOrderError,
    UnknownCodeError,
    UnknownFormatError,
    UnknownSymbolError,
    barcode_scanner_audit_event,
)


def fresh() -> BarcodeScanner:
    return BarcodeScanner()


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(BARCODE_SCANNER_VERSION, "barcode-scanner.v1")
        self.assertEqual(BARCODE_SCANNER_SCHEMA, "northstar.barcode-scanner.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")
        bs = fresh()
        rec = bs.generate(QR, "hello", 1)
        self.assertEqual(rec.version, BARCODE_SCANNER_VERSION)
        self.assertEqual(rec.schema, BARCODE_SCANNER_SCHEMA)
        self.assertTrue(rec.digest.startswith("sha256:"))

    def test_stdlib_only(self):
        import ast
        from pathlib import Path

        tree = ast.parse(
            (Path(__file__).resolve().parent.parent / "barcode_scanner.py").read_text()
        )
        allowed = {
            "threading", "dataclasses", "typing", "__future__",
            "hashlib", "json", "canonical_json", "re",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestFormats(unittest.TestCase):
    def test_formats_vocab(self):
        bs = fresh()
        fmts = bs.formats()
        self.assertEqual(
            fmts,
            (QR, DATAMATRIX, AZTEC, PDF417, CODE128, CODE39, EAN13, UPCA),
        )
        self.assertIn("qr", fmts)
        self.assertIn("datamatrix", fmts)  # research-line formats pinned


class TestGenerate(unittest.TestCase):
    def test_generate_qr_happy(self):
        bs = fresh()
        rec = bs.generate(QR, "northstar://pair?session=7f3a", 1)
        self.assertIsInstance(rec, GeneratedCode)
        self.assertEqual(rec.code_id, "bc-1")
        self.assertEqual(rec.format, QR)
        self.assertEqual(rec.payload, "northstar://pair?session=7f3a")
        self.assertEqual(rec.full_code, rec.payload)
        self.assertEqual(rec.ec_level, "M")  # default
        self.assertTrue(rec.symbol.startswith("sym-"))

    def test_generate_ec_level_explicit(self):
        bs = fresh()
        rec = bs.generate(QR, "x", 1, ec_level="H")
        self.assertEqual(rec.ec_level, "H")

    def test_generate_digest_deterministic(self):
        a, b = fresh(), fresh()
        ra = a.generate(DATAMATRIX, "serial-123", 1)
        rb = b.generate(DATAMATRIX, "serial-123", 1)
        self.assertEqual(ra.digest, rb.digest)
        self.assertEqual(ra.symbol, rb.symbol)

    def test_generate_ean13_check_digit(self):
        bs = fresh()
        rec = bs.generate(EAN13, "590123412345", 1)
        self.assertEqual(rec.full_code, "5901234123457")

    def test_generate_upca_check_digit(self):
        bs = fresh()
        rec = bs.generate(UPCA, "03600029145", 1)
        self.assertEqual(rec.full_code, "036000291452")

    def test_generate_code39_charset_refusal(self):
        bs = fresh()
        with self.assertRaises(BadPayloadError):
            bs.generate(CODE39, "lowercase!", 1)
        rec = bs.generate(CODE39, "ABC-123", 2)
        self.assertEqual(rec.format, CODE39)

    def test_generate_code128_nonascii_refusal(self):
        bs = fresh()
        with self.assertRaises(BadPayloadError):
            bs.generate(CODE128, "héllo", 1)

    def test_generate_payload_too_large(self):
        bs = fresh()
        with self.assertRaises(PayloadTooLargeError):
            bs.generate(QR, "x" * 2954, 1)
        with self.assertRaises(PayloadTooLargeError):
            bs.generate(CODE39, "A" * 44, 2)

    def test_generate_unknown_format(self):
        bs = fresh()
        with self.assertRaises(UnknownFormatError):
            bs.generate("maxicode", "x", 1)

    def test_generate_bad_ec_level(self):
        bs = fresh()
        with self.assertRaises(BadOptionError):
            bs.generate(QR, "x", 1, ec_level="X")
        with self.assertRaises(BadOptionError):
            bs.generate(CODE128, "x", 2, ec_level="H")

    def test_generate_seq_order(self):
        bs = fresh()
        bs.generate(QR, "a", 5)
        with self.assertRaises(SeqOrderError):
            bs.generate(QR, "b", 5)   # rewind / equal
        with self.assertRaises(BarcodeScannerError):
            bs.generate(QR, "b", True)  # bool is not an int


class TestDecode(unittest.TestCase):
    def test_decode_roundtrip(self):
        bs = fresh()
        g = bs.generate(QR, "payload-42", 1)
        d = bs.decode(g.symbol, 2)
        self.assertIsInstance(d, DecodedCode)
        self.assertEqual(d.code_id, g.code_id)
        self.assertEqual(d.format, "qr")
        self.assertEqual(d.payload, "payload-42")
        self.assertTrue(d.digest.startswith("sha256:"))

    def test_decode_format_hint_match(self):
        bs = fresh()
        g = bs.generate(DATAMATRIX, "dm-1", 1)
        d = bs.decode(g.symbol, 2, format_hint=DATAMATRIX)
        self.assertEqual(d.format, DATAMATRIX)

    def test_decode_format_hint_mismatch(self):
        bs = fresh()
        g = bs.generate(QR, "q-1", 1)
        with self.assertRaises(FormatMismatchError):
            bs.decode(g.symbol, 2, format_hint=AZTEC)

    def test_decode_unknown_symbol(self):
        bs = fresh()
        with self.assertRaises(UnknownSymbolError):
            bs.decode("sym-ffffffffffffffff", 1)

    def test_code_views(self):
        bs = fresh()
        g = bs.generate(PDF417, "pdf-1", 1)
        self.assertEqual(bs.code(g.code_id).payload, "pdf-1")
        self.assertEqual(bs.code_ids(), ("bc-1",))
        self.assertEqual(bs.code_count(), 1)
        with self.assertRaises(UnknownCodeError):
            bs.code("bc-99")


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        ev = barcode_scanner_audit_event(
            KIND_GENERATED, 1, code_id="bc-1", format="qr"
        )
        self.assertEqual(ev["kind"], KIND_GENERATED)
        self.assertEqual(ev["schema"], AUDIT_SCHEMA)
        self.assertEqual(ev["module"], BARCODE_SCANNER_SCHEMA)
        ev2 = barcode_scanner_audit_event(KIND_DECODED, 2, code_id="bc-1")
        self.assertEqual(ev2["kind"], KIND_DECODED)
        ev3 = barcode_scanner_audit_event(KIND_REJECTED, 3)
        self.assertEqual(ev3["kind"], KIND_REJECTED)

    def test_audit_rejects_unknown_kind(self):
        with self.assertRaises(BarcodeScannerError):
            barcode_scanner_audit_event("scanned", 1)

    def test_audit_bans_payload(self):
        with self.assertRaises(BarcodeScannerError):
            barcode_scanner_audit_event(KIND_GENERATED, 1, payload="secret")
        with self.assertRaises(BarcodeScannerError):
            barcode_scanner_audit_event(KIND_DECODED, 2, full_code="123")


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        from barcode_scanner import main

        main()  # must not raise


if __name__ == "__main__":
    unittest.main()
