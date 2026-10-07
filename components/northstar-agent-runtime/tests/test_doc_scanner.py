"""Tests for doc_scanner (simulated document-scanning ledger)."""

import ast
import unittest

from doc_scanner import (
    DOC_SCANNER_VERSION,
    SCHEMA_PIN,
    AUDIT_SCHEMA,
    BadGeometryError,
    BadOperationError,
    CornersRecord,
    CropRecord,
    DocScanner,
    DocScannerError,
    DuplicateImageError,
    EnhanceRecord,
    ImageRecord,
    SeqOrderError,
    UnknownImageError,
    ValidationError,
    doc_scanner_audit_event,
)


def _scanner(seq_start=1):
    return DocScanner()


def _register(scanner, image_id="img-1", width=1200, height=1600, seq=1):
    return scanner.register_image(image_id, width, height, seq)


def _quad(width=1200, height=1600):
    return ((100, 120), (1100, 140), (1080, 1500), (80, 1480))


class TestVersionPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(DOC_SCANNER_VERSION, "doc-scanner.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.doc-scanner.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")


class TestRegisterImage(unittest.TestCase):
    def test_register_roundtrip(self):
        s = _scanner()
        rec = _register(s)
        self.assertIsInstance(rec, ImageRecord)
        self.assertEqual(rec.width, 1200)
        self.assertEqual(rec.height, 1600)
        self.assertTrue(rec.pin.startswith("sha256:"))
        self.assertEqual(rec.pin, s.image("img-1").pin)

    def test_register_pin_determinism(self):
        s1, s2 = _scanner(), _scanner()
        self.assertEqual(
            _register(s1).pin,
            _register(s2).pin,
        )

    def test_register_duplicate_refused(self):
        s = _scanner()
        _register(s)
        with self.assertRaises(DuplicateImageError):
            _register(s, seq=2)

    def test_register_bad_dims_refused(self):
        s = _scanner()
        for width, height in ((0, 10), (10, 0), (-5, 10), (10, 99999), (True, 10)):
            with self.assertRaises(ValidationError):
                s.register_image("img-x", width, height, 1)

    def test_register_unknown_image_lookup(self):
        s = _scanner()
        with self.assertRaises(UnknownImageError):
            s.image("nope")

    def test_register_seq_monotonicity(self):
        s = _scanner()
        _register(s, seq=5)
        with self.assertRaises(SeqOrderError):
            s.register_image("img-2", 10, 10, 5)
        with self.assertRaises(SeqOrderError):
            s.register_image("img-2", 10, 10, 2)


class TestCorners(unittest.TestCase):
    def test_corners_roundtrip(self):
        s = _scanner()
        _register(s)
        rec = s.corners("img-1", _quad(), 2)
        self.assertIsInstance(rec, CornersRecord)
        self.assertTrue(rec.pin.startswith("sha256:"))
        self.assertGreater(rec.area_px2, 0.0)
        # area of the quad is roughly the rectangle it spans
        self.assertGreater(rec.area_px2, 1_000_000.0)

    def test_corners_unknown_image_refused(self):
        s = _scanner()
        with self.assertRaises(UnknownImageError):
            s.corners("ghost", _quad(), 1)

    def test_corners_bad_quad_refused(self):
        s = _scanner()
        _register(s)
        with self.assertRaises(BadGeometryError):
            s.corners("img-1", ((0, 0), (1, 1), (2, 2)), 2)  # only 3
        with self.assertRaises(BadGeometryError):
            s.corners("img-1", ((0, 0), (1, 1), (2, 2), (5000, 5000)), 2)  # OOB

    def test_corners_degenerate_refused(self):
        s = _scanner()
        _register(s)
        with self.assertRaises(BadGeometryError):
            s.corners("img-1", ((5, 5), (5, 5), (5, 5), (5, 5)), 2)


class TestEnhance(unittest.TestCase):
    def test_enhance_roundtrip(self):
        s = _scanner()
        _register(s)
        rec = s.enhance("img-1", ("grayscale", "deskew", "contrast"), 2)
        self.assertIsInstance(rec, EnhanceRecord)
        self.assertEqual(rec.operations, ("grayscale", "deskew", "contrast"))
        self.assertEqual(rec.strength, 1.0)
        self.assertTrue(rec.pin.startswith("sha256:"))

    def test_enhance_unknown_op_refused(self):
        s = _scanner()
        _register(s)
        with self.assertRaises(BadOperationError):
            s.enhance("img-1", ("grayscale", "teleport"), 2)

    def test_enhance_bad_strength_refused(self):
        s = _scanner()
        _register(s)
        for strength in (0.0, -1.0, 2.5, float("inf"), True):
            with self.assertRaises(BadOperationError):
                s.enhance("img-1", ("grayscale",), 2, strength=strength)


class TestCrop(unittest.TestCase):
    def test_crop_uses_pinned_corners(self):
        s = _scanner()
        _register(s)
        corners = s.corners("img-1", _quad(), 2)
        rec = s.crop("img-1", 3, out_width=2480, out_height=3508)
        self.assertIsInstance(rec, CropRecord)
        self.assertEqual(rec.out_width, 2480)
        self.assertEqual(rec.out_height, 3508)
        self.assertEqual(
            [c.as_dict() for c in rec.corners],
            [c.as_dict() for c in corners.corners],
        )

    def test_crop_without_corners_refused(self):
        s = _scanner()
        _register(s)
        with self.assertRaises(BadGeometryError):
            s.crop("img-1", 2, out_width=100, out_height=100)

    def test_crop_explicit_quad(self):
        s = _scanner()
        _register(s)
        rec = s.crop("img-1", 2, quad=_quad(), out_width=800, out_height=600)
        self.assertEqual(rec.out_width, 800)
        self.assertEqual(rec.out_height, 600)


class TestAuditAndMain(unittest.TestCase):
    def test_audit_event_shapes(self):
        ev = doc_scanner_audit_event("corners-pinned", 2, {"image_id": "img-1"})
        self.assertEqual(ev["kind"], "corners-pinned")
        self.assertEqual(ev["seq"], 2)
        self.assertEqual(ev["audit_schema"], AUDIT_SCHEMA)

    def test_audit_bad_kind_refused(self):
        with self.assertRaises(ValidationError):
            doc_scanner_audit_event("nope", 1, {})

    def test_audit_log_accumulates(self):
        s = _scanner()
        _register(s)
        s.corners("img-1", _quad(), 2)
        s.enhance("img-1", ("grayscale",), 3)
        kinds = [e["kind"] for e in s.audit_log()]
        self.assertEqual(kinds, ["image-registered", "corners-pinned", "enhance-declared"])

    def test_error_hierarchy(self):
        self.assertTrue(issubclass(UnknownImageError, DocScannerError))
        self.assertTrue(issubclass(BadGeometryError, DocScannerError))

    def test_stdlib_only(self):
        import pathlib

        src = pathlib.Path("doc_scanner.py").read_text()
        tree = ast.parse(src)
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
        allowed = {
            "hashlib",
            "json",
            "math",
            "threading",
            "dataclasses",
            "typing",
            "__future__",
            "canonical_json",
        }
        self.assertLessEqual(imports, allowed, f"non-stdlib imports: {imports - allowed}")

    def test_main_self_check(self):
        import subprocess

        result = subprocess.run(
            ["python3", "doc_scanner.py"], capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("doc-scanner OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
