"""Targeted tests for image_processor (batch 25)."""

import ast
import unittest
from pathlib import Path

from image_processor import (
    IMAGE_PROCESSOR_VERSION,
    SCHEMA_PIN,
    BadDimensionError,
    BadQualityError,
    DuplicateImageError,
    ImageError,
    ImageProcessor,
    NoopTransformError,
    SeqOrderError,
    UnknownFormatError,
    UnknownImageError,
    UnknownMethodError,
    image_processor_audit_event,
)

MODULE_PATH = Path(__file__).parent.parent / "image_processor.py"


class TestVersionPins(unittest.TestCase):
    def test_pins(self):
        self.assertEqual(IMAGE_PROCESSOR_VERSION, "image-processor.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.image-processor.v1")


class TestStdlibOnly(unittest.TestCase):
    def test_stdlib_only(self):
        tree = ast.parse(MODULE_PATH.read_text())
        allowed = {"hashlib", "threading", "dataclasses", "typing", "__future__", "math"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestRegister(unittest.TestCase):
    def test_register_roundtrip(self):
        p = ImageProcessor()
        rec = p.register("img-1", 800, 600, "png", 1)
        self.assertEqual(rec.image_id, "img-1")
        self.assertEqual((rec.width, rec.height), (800, 600))
        self.assertTrue(rec.pin.startswith("sha256:"))
        self.assertEqual(p.image("img-1").pin, rec.pin)
        self.assertEqual(p.image_ids(), ("img-1",))

    def test_register_pin_determinism(self):
        p1, p2 = ImageProcessor(), ImageProcessor()
        r1 = p1.register("img-1", 800, 600, "png", 1)
        r2 = p2.register("img-1", 800, 600, "png", 1)
        self.assertEqual(r1.pin, r2.pin)

    def test_register_duplicate_refused(self):
        p = ImageProcessor()
        p.register("img-1", 800, 600, "png", 1)
        with self.assertRaises(DuplicateImageError):
            p.register("img-1", 100, 100, "jpeg", 2)

    def test_register_bad_dimensions(self):
        p = ImageProcessor()
        for i, (w, h) in enumerate(((0, 10), (10, 0), (-1, 10), (10, 20000), (True, 10), (10, 10.5))):
            with self.assertRaises(BadDimensionError, msg=f"{w}x{h}"):
                p.register("img-bad", w, h, "png", 1 + i)

    def test_register_unknown_format_refused(self):
        p = ImageProcessor()
        with self.assertRaises(UnknownFormatError):
            p.register("img-1", 800, 600, "heic", 1)

    def test_register_seq_order(self):
        p = ImageProcessor()
        p.register("img-1", 800, 600, "png", 5)
        with self.assertRaises(SeqOrderError):
            p.register("img-2", 100, 100, "jpeg", 5)
        with self.assertRaises(SeqOrderError):
            p.register("img-3", 100, 100, "jpeg", True)


class TestResize(unittest.TestCase):
    def test_resize_happy_path(self):
        p = ImageProcessor()
        p.register("img-1", 800, 600, "png", 1)
        rz = p.resize("img-1", 400, 300, 2, method="nearest")
        self.assertEqual((rz.to_width, rz.to_height), (400, 300))
        self.assertEqual(rz.method, "nearest")
        self.assertEqual((rz.scale_x_num, rz.scale_x_den), (1, 2))
        self.assertTrue(rz.pin.startswith("sha256:"))
        self.assertEqual(rz.source_pin, p.image("img-1").pin)

    def test_resize_unknown_image(self):
        p = ImageProcessor()
        with self.assertRaises(UnknownImageError):
            p.resize("nope", 100, 100, 1)

    def test_resize_bad_dimensions(self):
        p = ImageProcessor()
        p.register("img-1", 800, 600, "png", 1)
        with self.assertRaises(BadDimensionError):
            p.resize("img-1", 0, 100, 2)

    def test_resize_unknown_method(self):
        p = ImageProcessor()
        p.register("img-1", 800, 600, "png", 1)
        with self.assertRaises(UnknownMethodError):
            p.resize("img-1", 400, 300, 2, method="mitchell")

    def test_resize_noop_refused(self):
        p = ImageProcessor()
        p.register("img-1", 800, 600, "png", 1)
        with self.assertRaises(NoopTransformError):
            p.resize("img-1", 800, 600, 2)

    def test_resize_pin_determinism(self):
        p1, p2 = ImageProcessor(), ImageProcessor()
        p1.register("img-1", 800, 600, "png", 1)
        p2.register("img-1", 800, 600, "png", 1)
        self.assertEqual(p1.resize("img-1", 400, 300, 2).pin,
                         p2.resize("img-1", 400, 300, 2).pin)


class TestFormat(unittest.TestCase):
    def test_format_happy_path(self):
        p = ImageProcessor()
        p.register("img-1", 800, 600, "png", 1)
        fm = p.format("img-1", "jpeg", 2, quality=85)
        self.assertEqual(fm.from_format, "png")
        self.assertEqual(fm.to_format, "jpeg")
        self.assertEqual(fm.quality, 85)
        self.assertEqual(fm.source_pin, p.image("img-1").pin)

    def test_format_same_format_refused(self):
        p = ImageProcessor()
        p.register("img-1", 800, 600, "png", 1)
        with self.assertRaises(NoopTransformError):
            p.format("img-1", "png", 2)

    def test_format_bad_quality(self):
        p = ImageProcessor()
        p.register("img-1", 800, 600, "png", 1)
        with self.assertRaises(BadQualityError):
            p.format("img-1", "jpeg", 2, quality=0)
        with self.assertRaises(BadQualityError):
            p.format("img-1", "jpeg", 3, quality=101)
        with self.assertRaises(BadQualityError):
            p.format("img-1", "jpeg", 4, quality=85.0)

    def test_format_quality_for_lossless_refused(self):
        p = ImageProcessor()
        p.register("img-1", 800, 600, "jpeg", 1)
        with self.assertRaises(BadQualityError):
            p.format("img-1", "png", 2, quality=90)


class TestMetadata(unittest.TestCase):
    def test_metadata_roundtrip(self):
        p = ImageProcessor()
        rec = p.register("img-1", 800, 600, "png", 1)
        md = p.metadata("img-1", 2)
        self.assertEqual(md.pin, rec.pin)
        self.assertEqual(md.pixel_count, 480000)

    def test_metadata_unknown_image(self):
        p = ImageProcessor()
        with self.assertRaises(UnknownImageError):
            p.metadata("nope", 1)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        evt = image_processor_audit_event("registered", 1)
        self.assertEqual(evt["schema"], SCHEMA_PIN)
        self.assertEqual(evt["module"], IMAGE_PROCESSOR_VERSION)
        for kind in ("resized", "converted", "metadata-read", "rejected"):
            self.assertEqual(image_processor_audit_event(kind, 2)["kind"], kind)

    def test_audit_bad_kind_rejected(self):
        with self.assertRaises(ImageError):
            image_processor_audit_event("mangled", 1)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        import image_processor

        image_processor.main()


if __name__ == "__main__":
    unittest.main()
