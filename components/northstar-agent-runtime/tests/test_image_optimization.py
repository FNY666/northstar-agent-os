"""Tests for image_optimization: 20 cases."""

import ast
import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from image_optimization import (
    IMAGE_OPTIMIZATION_VERSION,
    SCHEMA_PIN,
    FORMATS,
    LOSSY_FORMATS,
    OPTIMIZE_MODES,
    PLACEHOLDERS,
    DEFAULT_QUALITY,
    BadDimensionError,
    BadQualityError,
    DuplicateImageError,
    ImageOptimization,
    ImageOptimizationError,
    SeqOrderError,
    UnknownFormatError,
    UnknownImageError,
    UnknownModeError,
    UnknownPlaceholderError,
    image_optimization_audit_event,
)


def fresh(seed_img=True):
    o = ImageOptimization()
    if seed_img:
        o.register("img-1", 800, 600, "png", 1)
    return o


class TestPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(IMAGE_OPTIMIZATION_VERSION, "image-optimization.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.image-optimization.v1")

    def test_vocabularies(self):
        self.assertIn("avif", FORMATS)
        self.assertIn("webp", LOSSY_FORMATS)
        self.assertNotIn("png", LOSSY_FORMATS)
        self.assertEqual(tuple(OPTIMIZE_MODES), ("lossless", "lossy"))
        self.assertEqual(tuple(PLACEHOLDERS), ("blur", "color", "none"))

    def test_stdlib_only(self):
        path = os.path.join(os.path.dirname(__file__), "..", "image_optimization.py")
        tree = ast.parse(open(path).read())
        allowed = {
            "hashlib", "threading", "dataclasses", "typing",
            "__future__",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed, a.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed, node.module)


class TestRegister(unittest.TestCase):
    def test_register_roundtrip(self):
        o = ImageOptimization()
        rec = o.register("img-1", 800, 600, "png", 1)
        self.assertEqual((rec.width, rec.height, rec.format), (800, 600, "png"))
        self.assertTrue(rec.pin.startswith("sha256:"))
        self.assertEqual(o.image("img-1").pin, rec.pin)
        self.assertEqual(o.image_ids(), ("img-1",))

    def test_register_duplicate(self):
        o = fresh()
        with self.assertRaises(DuplicateImageError):
            o.register("img-1", 100, 100, "png", 2)

    def test_register_bad_inputs(self):
        o = ImageOptimization()
        with self.assertRaises(BadDimensionError):
            o.register("a", 0, 100, "png", 1)
        with self.assertRaises(BadDimensionError):
            o.register("b", 100, 16385, "png", 2)
        with self.assertRaises(BadDimensionError):
            o.register("c", True, 100, "png", 3)
        with self.assertRaises(UnknownFormatError):
            o.register("d", 100, 100, "heic", 4)
        with self.assertRaises(UnknownImageError):
            o.image("nope")


class TestOptimize(unittest.TestCase):
    def test_optimize_lossy_fit(self):
        o = fresh()
        opt = o.optimize("img-1", 2, mode="lossy", max_width=400)
        self.assertEqual(opt.opt_id, "opt-1")
        self.assertEqual((opt.to_width, opt.to_height), (400, 300))
        self.assertTrue(opt.resized)
        self.assertEqual(opt.quality, DEFAULT_QUALITY)
        self.assertTrue(opt.pin.startswith("sha256:"))

    def test_optimize_never_upscales(self):
        o = fresh()
        opt = o.optimize("img-1", 2, mode="lossy", max_width=4000, max_height=4000)
        self.assertEqual((opt.to_width, opt.to_height), (800, 600))
        self.assertFalse(opt.resized)

    def test_optimize_lossless_refuses_quality(self):
        o = fresh()
        with self.assertRaises(BadQualityError):
            o.optimize("img-1", 2, mode="lossless", quality=80)

    def test_optimize_lossy_quality_bounds(self):
        o = fresh()
        with self.assertRaises(BadQualityError):
            o.optimize("img-1", 2, mode="lossy", quality=0)
        with self.assertRaises(BadQualityError):
            o.optimize("img-1", 3, mode="lossy", quality=101)
        ok = o.optimize("img-1", 4, mode="lossy", quality=60)
        self.assertEqual(ok.quality, 60)

    def test_optimize_bad_mode_and_unknown_image(self):
        o = fresh()
        with self.assertRaises(UnknownModeError):
            o.optimize("img-1", 2, mode="turbo")
        with self.assertRaises(UnknownImageError):
            o.optimize("ghost", 3, mode="lossy")


class TestFormat(unittest.TestCase):
    def test_format_roundtrip(self):
        o = fresh()
        conv = o.format("img-1", "webp", 2, quality=80)
        self.assertEqual(conv.conv_id, "conv-1")
        self.assertEqual((conv.from_format, conv.to_format), ("png", "webp"))
        self.assertEqual(conv.quality, 80)

    def test_format_same_format_refused(self):
        o = fresh()
        with self.assertRaises(ImageOptimizationError):
            o.format("img-1", "png", 2)

    def test_format_quality_only_for_lossy(self):
        o = fresh()
        with self.assertRaises(BadQualityError):
            o.format("img-1", "gif", 2, quality=80)
        with self.assertRaises(UnknownFormatError):
            o.format("img-1", "heic", 3)


class TestLazy(unittest.TestCase):
    def test_lazy_roundtrip(self):
        o = fresh()
        lz = o.lazy("img-1", 2, placeholder="color", eager_above_fold=True)
        self.assertEqual(lz.lazy_id, "lazy-1")
        self.assertEqual((lz.intrinsic_width, lz.intrinsic_height), (800, 600))
        self.assertTrue(lz.eager_above_fold)

    def test_lazy_bad_placeholder(self):
        o = fresh()
        with self.assertRaises(UnknownPlaceholderError):
            o.lazy("img-1", 2, placeholder="skeleton")


class TestSeqAndAudit(unittest.TestCase):
    def test_seq_ordering(self):
        o = fresh()
        with self.assertRaises(SeqOrderError):
            o.optimize("img-1", 1, mode="lossy")  # rewind
        with self.assertRaises(SeqOrderError):
            o.optimize("img-1", True, mode="lossy")  # bool seq

    def test_failed_mutation_consumes_seq(self):
        o = fresh()
        with self.assertRaises(UnknownImageError):
            o.optimize("ghost", 2, mode="lossy")
        # seq 2 was consumed by the failed call; next valid call needs seq 3
        with self.assertRaises(SeqOrderError):
            o.optimize("img-1", 2, mode="lossy")
        ok = o.optimize("img-1", 3, mode="lossy")
        self.assertEqual(ok.opt_id, "opt-1")

    def test_audit_shapes(self):
        evt = image_optimization_audit_event("optimized", 1, "opt-1")
        self.assertEqual(evt["kind"], "optimized")
        self.assertEqual(evt["module"], IMAGE_OPTIMIZATION_VERSION)
        self.assertEqual(evt["schema"], SCHEMA_PIN)
        with self.assertRaises(ImageOptimizationError):
            image_optimization_audit_event("bogus", 1)
        o = fresh()
        o.optimize("img-1", 2, mode="lossy")
        kinds = [e["kind"] for e in o.audit_log()]
        self.assertEqual(kinds, ["registered", "optimized"])

    def test_main(self):
        from image_optimization import main
        main()


if __name__ == "__main__":
    unittest.main()
