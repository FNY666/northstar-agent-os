"""Targeted tests for image_captioner (BLIP-style simulated captioning)."""

import ast
import unittest
from pathlib import Path

from image_captioner import (
    DuplicateImageError,
    ImageCaptioner,
    ImageCaptionerError,
    IMAGE_CAPTIONER_VERSION,
    SCHEMA_PIN,
    SeqOrderError,
    UnknownImageError,
    UnknownStyleError,
    ValidationError,
    image_captioner_audit_event,
)

MODULE = Path(__file__).parent.parent / "image_captioner.py"


def make_registered(seq_start: int = 1, image_id: str = "img-1") -> ImageCaptioner:
    ic = ImageCaptioner()
    ic.register_image(
        image_id,
        seq_start,
        width=640,
        height=480,
        scene="a beach at sunset",
        objects=["sun", "waves"],
        tags=["beach", "sunset", "ocean"],
        colors=["orange", "blue"],
    )
    return ic


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(IMAGE_CAPTIONER_VERSION, "image-captioner.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.image-captioner.v1")


class TestRegister(unittest.TestCase):
    def test_register_roundtrip_and_verify(self):
        ic = make_registered()
        rec = ic.image("img-1")
        self.assertEqual(rec.width, 640)
        self.assertEqual(rec.scene, "a beach at sunset")
        self.assertTrue(rec.verify())
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(ic.image_count(), 1)
        self.assertEqual(ic.image_ids(), ("img-1",))

    def test_register_duplicate_refused(self):
        ic = make_registered()
        with self.assertRaises(DuplicateImageError):
            ic.register_image("img-1", 2, width=10, height=10)

    def test_register_bad_inputs_refused(self):
        # failed mutations consume their seq (house style), so use fresh seqs
        ic = ImageCaptioner()
        with self.assertRaises(ValidationError):
            ic.register_image("", 1)
        with self.assertRaises(ValidationError):
            ic.register_image("a", 2, width=0, height=10)
        with self.assertRaises(ValidationError):
            ic.register_image("a", 3, width=True, height=10)
        with self.assertRaises(ValidationError):
            ic.register_image("a", 4, width=10, height=10, tags=["BAD TAG"])
        with self.assertRaises(ValidationError):
            ic.register_image("a", 5, width=10, height=10, tags=[])

    def test_seq_strictly_increases(self):
        ic = make_registered()
        with self.assertRaises(SeqOrderError):
            ic.register_image("img-2", 1, width=10, height=10)
        with self.assertRaises(ValidationError):
            ic.register_image("img-2", True, width=10, height=10)


class TestCaption(unittest.TestCase):
    def test_caption_neutral_content(self):
        ic = make_registered()
        cap = ic.caption("img-1", 2)
        self.assertEqual(cap.style, "neutral")
        self.assertIn("beach at sunset", cap.text)
        self.assertIn("sun", cap.text)
        self.assertTrue(cap.verify())

    def test_caption_styles(self):
        ic = make_registered()
        alt = ic.caption("img-1", 2, style="alt")
        neutral = ic.caption("img-1", 3, style="neutral")
        detailed = ic.caption("img-1", 4, style="detailed")
        self.assertIn("Image of a beach at sunset", alt.text)
        self.assertIn("640x480", detailed.text)
        self.assertIn("beach", detailed.text)
        self.assertNotEqual(alt.text, detailed.text)
        self.assertTrue(alt.verify() and neutral.verify() and detailed.verify())

    def test_caption_determinism(self):
        ic1 = make_registered()
        ic2 = make_registered()
        c1 = ic1.caption("img-1", 2, style="neutral")
        c2 = ic2.caption("img-1", 2, style="neutral")
        self.assertEqual(c1.text, c2.text)
        self.assertEqual(c1.digest, c2.digest)

    def test_caption_unknown_image_refused(self):
        ic = make_registered()
        with self.assertRaises(UnknownImageError):
            ic.caption("nope", 2)

    def test_caption_unknown_style_refused(self):
        ic = make_registered()
        with self.assertRaises(UnknownStyleError):
            ic.caption("img-1", 2, style="poetic")


class TestTags(unittest.TestCase):
    def test_tags_sorted_and_verify(self):
        ic = make_registered()
        rep = ic.tags("img-1", 2)
        self.assertEqual(len(rep.tags), 3)
        confs = [t.confidence for t in rep.tags]
        self.assertEqual(confs, sorted(confs, reverse=True))
        self.assertTrue(rep.verify())
        self.assertTrue(rep.digest.startswith("sha256:"))

    def test_tags_max_tags(self):
        ic = make_registered()
        rep = ic.tags("img-1", 2, max_tags=2)
        self.assertEqual(len(rep.tags), 2)
        with self.assertRaises(ValidationError):
            ic.tags("img-1", 3, max_tags=0)
        with self.assertRaises(ValidationError):
            ic.tags("img-1", 4, max_tags=True)

    def test_tags_determinism(self):
        ic1 = make_registered()
        ic2 = make_registered()
        r1 = ic1.tags("img-1", 2)
        r2 = ic2.tags("img-1", 2)
        self.assertEqual(r1.digest, r2.digest)
        self.assertEqual([t.tag for t in r1.tags], [t.tag for t in r2.tags])


class TestDescribe(unittest.TestCase):
    def test_describe_content_and_verify(self):
        ic = make_registered()
        desc = ic.describe("img-1", 2)
        self.assertIn("img-1", desc.text)
        self.assertIn("beach at sunset", desc.text)
        self.assertIn("640x480", desc.text)
        self.assertTrue(desc.verify())
        with self.assertRaises(UnknownImageError):
            ic.describe("ghost", 3)


class TestAudit(unittest.TestCase):
    def test_audit_shapes_and_bad_kind(self):
        ev = image_captioner_audit_event("registered", 1, "img-1")
        self.assertEqual(ev["module"], "image-captioner")
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        with self.assertRaises(ValidationError):
            image_captioner_audit_event("bogus", 1, "img-1")

    def test_audit_log_accumulates(self):
        ic = make_registered()
        ic.caption("img-1", 2)
        ic.tags("img-1", 3)
        ic.describe("img-1", 4)
        kinds = [e["kind"] for e in ic.audit_log()]
        self.assertEqual(kinds, ["registered", "captioned", "tagged", "described"])


class TestStdlibOnly(unittest.TestCase):
    def test_module_is_stdlib_only(self):
        tree = ast.parse(MODULE.read_text())
        allowed = {
            "__future__", "ast", "hashlib", "re", "threading", "dataclasses",
            "typing", "pathlib", "canonical_json", "json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    self.assertIn(node.module.split(".")[0], allowed)


if __name__ == "__main__":
    unittest.main()
