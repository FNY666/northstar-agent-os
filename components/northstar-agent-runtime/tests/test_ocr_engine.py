"""Tests for ocr_engine: Tesseract-shaped OCR bookkeeping."""

import ast
import unittest

import ocr_engine
from ocr_engine import (
    OCREngine,
    OCRError,
    InvalidImageError,
    DuplicateImageError,
    UnknownImageError,
    InvalidWordError,
    NoRecognitionError,
    SeqOrderError,
    ocr_engine_audit_event,
    OCR_ENGINE_VERSION,
    SCHEMA_PIN,
    main,
)


def make_engine() -> OCREngine:
    return OCREngine()


def submit(e: OCREngine, image_id: str = "img-1", seq: int = 1):
    return e.submit(image_id, 800, 600, seq)


def two_line_words():
    return [
        {"text": "hello", "confidence": 0.95, "bbox": [10, 10, 60, 30]},
        {"text": "world", "confidence": 0.90, "bbox": [70, 12, 120, 32]},
        {"text": "foo", "confidence": 0.50, "bbox": [10, 60, 50, 80]},
        {"text": "bar", "confidence": 0.85, "bbox": [60, 62, 100, 82]},
    ]


class TestPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(OCR_ENGINE_VERSION, "ocr-engine.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.ocr-engine.v1")


class TestSubmit(unittest.TestCase):
    def test_submit_roundtrip(self):
        e = make_engine()
        rec = submit(e)
        self.assertEqual(rec.image_id, "img-1")
        self.assertEqual((rec.width, rec.height), (800, 600))
        self.assertIsNone(rec.dpi)
        self.assertEqual(rec.seq, 1)
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(rec.version, OCR_ENGINE_VERSION)
        self.assertIn("digest", rec.as_dict())

    def test_submit_with_dpi(self):
        e = make_engine()
        rec = e.submit("img-1", 100, 100, 1, dpi=300)
        self.assertEqual(rec.dpi, 300)

    def test_submit_duplicate_refused(self):
        e = make_engine()
        submit(e, seq=1)
        with self.assertRaises(DuplicateImageError):
            e.submit("img-1", 800, 600, 2)

    def test_submit_bad_dimensions(self):
        for bad in (0, -5, True, 1.5, "800", None):
            # fresh engine per case: a failed submit consumes its seq
            e = make_engine()
            with self.assertRaises(InvalidImageError):
                e.submit("img-w-%r" % (bad,), bad, 600, 1)
            e = make_engine()
            with self.assertRaises(InvalidImageError):
                e.submit("img-h-%r" % (bad,), 800, bad, 1)

    def test_submit_bad_image_id(self):
        for bad in ("", 123, None, b"img"):
            e = make_engine()  # failed submit consumes its seq
            with self.assertRaises(InvalidImageError):
                e.submit(bad, 800, 600, 1)

    def test_submit_bad_dpi(self):
        for bad in (0, -300, True, 1.5):
            e = make_engine()  # failed submit consumes its seq
            with self.assertRaises(InvalidImageError):
                e.submit("dpi-%r" % (bad,), 800, 600, 1, dpi=bad)

    def test_submit_seq_must_increase(self):
        e = make_engine()
        submit(e, seq=5)
        with self.assertRaises(SeqOrderError):
            e.submit("img-2", 800, 600, 5)
        with self.assertRaises(SeqOrderError):
            e.submit("img-2", 800, 600, 3)
        with self.assertRaises(OCRError):
            e.submit("img-2", 800, 600, True)

    def test_image_views(self):
        e = make_engine()
        submit(e, "b", seq=1)
        submit(e, "a", seq=2)
        self.assertEqual(e.image_ids(), ("a", "b"))
        self.assertEqual(e.image("a").width, 800)
        with self.assertRaises(UnknownImageError):
            e.image("nope")


class TestRecognize(unittest.TestCase):
    def test_recognize_happy_path(self):
        e = make_engine()
        submit(e, seq=1)
        r = e.recognize("img-1", two_line_words(), seq=2)
        self.assertEqual(r.recognition_id, "rc-1")
        self.assertEqual(r.word_count, 4)
        self.assertAlmostEqual(r.mean_confidence, 0.8)
        self.assertEqual([w.word_id for w in r.words], ["w-1", "w-2", "w-3", "w-4"])
        self.assertTrue(all(w.digest.startswith("sha256:") for w in r.words))
        self.assertTrue(r.digest.startswith("sha256:"))
        self.assertEqual(r.version, OCR_ENGINE_VERSION)

    def test_recognize_digest_deterministic(self):
        e1, e2 = make_engine(), make_engine()
        submit(e1, seq=1)
        submit(e2, seq=1)
        r1 = e1.recognize("img-1", two_line_words(), seq=2)
        r2 = e2.recognize("img-1", two_line_words(), seq=2)
        self.assertEqual(r1.digest, r2.digest)
        self.assertEqual(
            [w.digest for w in r1.words], [w.digest for w in r2.words]
        )

    def test_recognize_unknown_image(self):
        e = make_engine()
        with self.assertRaises(UnknownImageError):
            e.recognize("ghost", two_line_words(), seq=1)

    def test_recognize_empty_words_refused(self):
        e = make_engine()
        submit(e, seq=1)
        with self.assertRaises(InvalidWordError):
            e.recognize("img-1", [], seq=2)

    def test_recognize_bad_word_text(self):
        for bad_text in ("", 123, None, "x" * 257):
            e = make_engine()  # failed recognize consumes its seq
            submit(e, seq=1)
            words = [{"text": bad_text, "confidence": 0.9, "bbox": [0, 0, 10, 10]}]
            with self.assertRaises(InvalidWordError):
                e.recognize("img-1", words, seq=2)

    def test_recognize_bad_confidence(self):
        for bad in (-0.1, 1.5, float("nan"), float("inf"), True, "0.9", None):
            e = make_engine()  # failed recognize consumes its seq
            submit(e, seq=1)
            words = [{"text": "ok", "confidence": bad, "bbox": [0, 0, 10, 10]}]
            with self.assertRaises(InvalidWordError):
                e.recognize("img-1", words, seq=2)

    def test_recognize_confidence_int_edges(self):
        e = make_engine()
        submit(e, seq=1)
        r = e.recognize(
            "img-1",
            [
                {"text": "a", "confidence": 0, "bbox": [0, 0, 10, 10]},
                {"text": "b", "confidence": 1, "bbox": [20, 0, 30, 10]},
            ],
            seq=2,
        )
        self.assertAlmostEqual(r.mean_confidence, 0.5)

    def test_recognize_bad_bbox(self):
        e = make_engine()
        submit(e, seq=1)
        bad_boxes = (
            [10, 10, 10, 20],      # x0 == x1
            [20, 10, 10, 20],      # x0 > x1
            [0, 0, 801, 10],       # outside width
            [0, 0, 10, 601],       # outside height
            [-1, 0, 10, 10],       # negative
            [0, 0, 10],            # wrong length
            [True, 0, 10, 10],     # bool coord
            [0.5, 0, 10, 10],      # float coord
            "bbox",
        )
        for bbox in bad_boxes:
            e = make_engine()  # failed recognize consumes its seq
            submit(e, seq=1)
            words = [{"text": "ok", "confidence": 0.9, "bbox": bbox}]
            with self.assertRaises(InvalidWordError):
                e.recognize("img-1", words, seq=2)

    def test_recognize_missing_keys(self):
        e = make_engine()
        submit(e, seq=1)
        words = [{"text": "ok", "confidence": 0.9}]  # no bbox
        with self.assertRaises(InvalidWordError):
            e.recognize("img-1", words, seq=2)

    def test_failed_recognize_consumes_seq(self):
        e = make_engine()
        submit(e, seq=1)
        with self.assertRaises(InvalidWordError):
            e.recognize("img-1", [], seq=2)
        # seq 2 was consumed by the failed call
        with self.assertRaises(SeqOrderError):
            e.recognize("img-1", two_line_words(), seq=2)
        r = e.recognize("img-1", two_line_words(), seq=3)
        self.assertEqual(r.recognition_id, "rc-1")

    def test_recognition_views(self):
        e = make_engine()
        submit(e, seq=1)
        with self.assertRaises(NoRecognitionError):
            e.recognition("img-1")
        r1 = e.recognize("img-1", two_line_words(), seq=2)
        r2 = e.recognize("img-1", two_line_words(), seq=3)
        self.assertEqual(e.recognition("img-1").recognition_id, "rc-2")
        self.assertEqual(
            [r.recognition_id for r in e.recognitions("img-1")], ["rc-1", "rc-2"]
        )
        self.assertIsInstance(r1.words[0].bbox, tuple)
        self.assertEqual(r1.words[0].bbox, (10, 10, 60, 30))


class TestLayout(unittest.TestCase):
    def test_two_lines_one_paragraph_one_block(self):
        e = make_engine()
        submit(e, seq=1)
        e.recognize("img-1", two_line_words(), seq=2)
        lay = e.layout("img-1", seq=3)
        self.assertEqual(len(lay.lines), 2)
        self.assertEqual([ln.text for ln in lay.lines], ["hello world", "foo bar"])
        self.assertEqual(lay.lines[0].bbox, (10, 10, 120, 32))
        self.assertEqual(len(lay.paragraphs), 1)
        self.assertEqual(lay.paragraphs[0].text, "hello world\nfoo bar")
        self.assertEqual(len(lay.blocks), 1)
        self.assertTrue(lay.digest.startswith("sha256:"))
        self.assertEqual(lay.recognition_id, "rc-1")

    def test_paragraph_split_on_big_gap(self):
        e = make_engine()
        submit(e, seq=1)
        words = [
            {"text": "top", "confidence": 0.9, "bbox": [10, 10, 50, 30]},
            {"text": "bottom", "confidence": 0.9, "bbox": [10, 200, 70, 220]},
        ]
        e.recognize("img-1", words, seq=2)
        lay = e.layout("img-1", seq=3)
        self.assertEqual(len(lay.lines), 2)
        self.assertEqual(len(lay.paragraphs), 2)

    def test_column_gap_splits_line_and_block(self):
        e = make_engine()
        submit(e, seq=1)
        words = [
            {"text": "left", "confidence": 0.9, "bbox": [10, 10, 100, 30]},
            {"text": "right", "confidence": 0.9, "bbox": [500, 10, 600, 30]},
        ]
        e.recognize("img-1", words, seq=2)
        lay = e.layout("img-1", seq=3)
        # one baseline band, but the x-gap splits it into two column lines
        self.assertEqual([ln.text for ln in lay.lines], ["left", "right"])
        self.assertEqual(len(lay.paragraphs), 2)
        self.assertEqual(len(lay.blocks), 2)

    def test_two_columns_two_blocks(self):
        e = make_engine()
        submit(e, seq=1)
        words = [
            {"text": "l1", "confidence": 0.9, "bbox": [10, 10, 60, 30]},
            {"text": "l2", "confidence": 0.9, "bbox": [10, 50, 60, 70]},
            {"text": "r1", "confidence": 0.9, "bbox": [500, 10, 560, 30]},
            {"text": "r2", "confidence": 0.9, "bbox": [500, 50, 560, 70]},
        ]
        e.recognize("img-1", words, seq=2)
        lay = e.layout("img-1", seq=3)
        self.assertEqual([ln.text for ln in lay.lines], ["l1", "r1", "l2", "r2"])
        self.assertEqual(len(lay.paragraphs), 4)
        self.assertEqual(len(lay.blocks), 2)
        left_block, right_block = lay.blocks
        self.assertEqual(left_block.bbox, (10, 10, 60, 70))
        self.assertEqual(right_block.bbox, (500, 10, 560, 70))

    def test_layout_before_recognize(self):
        e = make_engine()
        submit(e, seq=1)
        with self.assertRaises(NoRecognitionError):
            e.layout("img-1", seq=2)

    def test_layout_unknown_image(self):
        e = make_engine()
        with self.assertRaises(UnknownImageError):
            e.layout("ghost", seq=1)

    def test_layout_uses_latest_recognition(self):
        e = make_engine()
        submit(e, seq=1)
        e.recognize("img-1", two_line_words(), seq=2)
        e.recognize(
            "img-1",
            [{"text": "solo", "confidence": 1.0, "bbox": [0, 0, 40, 20]}],
            seq=3,
        )
        lay = e.layout("img-1", seq=4)
        self.assertEqual(lay.recognition_id, "rc-2")
        self.assertEqual([ln.text for ln in lay.lines], ["solo"])


class TestConfidence(unittest.TestCase):
    def test_confidence_report(self):
        e = make_engine()
        submit(e, seq=1)
        e.recognize("img-1", two_line_words(), seq=2)
        conf = e.confidence("img-1", seq=3)
        self.assertEqual(conf.word_count, 4)
        self.assertAlmostEqual(conf.mean_confidence, 0.8)
        self.assertEqual(conf.min_confidence, 0.5)
        self.assertEqual(conf.max_confidence, 0.95)
        self.assertEqual(conf.threshold, 0.8)
        self.assertEqual([w.text for w in conf.low_confidence], ["foo"])
        self.assertEqual(conf.low_confidence[0].word_id, "w-3")
        self.assertTrue(conf.digest.startswith("sha256:"))

    def test_confidence_custom_threshold(self):
        e = make_engine()
        submit(e, seq=1)
        e.recognize("img-1", two_line_words(), seq=2)
        conf = e.confidence("img-1", seq=3, threshold=0.9)
        self.assertEqual(
            sorted(w.text for w in conf.low_confidence), ["bar", "foo"]
        )

    def test_confidence_bad_threshold(self):
        e = make_engine()
        submit(e, seq=1)
        e.recognize("img-1", two_line_words(), seq=2)
        for bad in (1.5, -0.1, float("nan"), True, "0.8"):
            with self.assertRaises(InvalidWordError):
                e.confidence("img-1", seq=3, threshold=bad)

    def test_confidence_before_recognize(self):
        e = make_engine()
        submit(e, seq=1)
        with self.assertRaises(NoRecognitionError):
            e.confidence("img-1", seq=2)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        ev = ocr_engine_audit_event("recognized", 7, {"recognition_id": "rc-1"})
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["module"], "ocr-engine")
        self.assertEqual(ev["module_version"], OCR_ENGINE_VERSION)
        self.assertEqual(ev["kind"], "recognized")
        self.assertEqual(ev["seq"], 7)
        self.assertEqual(ev["detail"], {"recognition_id": "rc-1"})

    def test_audit_unknown_kind_rejected(self):
        with self.assertRaises(OCRError):
            ocr_engine_audit_event("nope", 1)

    def test_audit_bad_seq_rejected(self):
        with self.assertRaises(OCRError):
            ocr_engine_audit_event("recognized", -1)


class TestHouseStyle(unittest.TestCase):
    def test_stdlib_only(self):
        with open(ocr_engine.__file__) as fh:
            tree = ast.parse(fh.read())
        allowed = {
            "__future__", "hashlib", "json", "math", "threading",
            "dataclasses", "typing", "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed, a.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed, node.module)

    def test_records_frozen(self):
        e = make_engine()
        rec = submit(e)
        with self.assertRaises(Exception):
            rec.width = 1  # type: ignore[misc]

    def test_main_self_check(self):
        main()


if __name__ == "__main__":
    unittest.main()
