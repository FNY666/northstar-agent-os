"""Tests for face_detector.py."""

import ast
import unittest
from pathlib import Path

from face_detector import (
    ATTRIBUTE_VOCAB,
    LANDMARK_KEYS,
    AUDIT_KINDS,
    FACE_DETECTOR_SCHEMA,
    FACE_DETECTOR_VERSION,
    AttributeRecord,
    BadConfidenceError,
    BadGeometryError,
    BadKindError,
    DetectionReport,
    DuplicateImageError,
    FaceBox,
    FaceDetector,
    FaceDetectorError,
    ImageRecord,
    LandmarkSet,
    SeqOrderError,
    UnknownAttributeError,
    UnknownFaceError,
    UnknownImageError,
    face_detector_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(FACE_DETECTOR_VERSION, "face-detector.v1")
        self.assertEqual(FACE_DETECTOR_SCHEMA, "northstar.face-detector.v1")
        self.assertTrue(LANDMARK_KEYS)
        self.assertIn("glasses", ATTRIBUTE_VOCAB)
        self.assertEqual(len(AUDIT_KINDS), 5)


class TestImages(unittest.TestCase):
    def test_register_roundtrip_and_pin_determinism(self):
        d1 = FaceDetector()
        r1 = d1.register_image("img-1", 640, 480, seq=1)
        d2 = FaceDetector()
        r2 = d2.register_image("img-1", 640, 480, seq=9)
        self.assertEqual(r1.pin, r2.pin)  # pins bind content, not seq
        self.assertTrue(r1.pin.startswith("sha256:"))
        self.assertEqual(d1.image("img-1"), r1)
        self.assertEqual(d1.image_ids(), ("img-1",))

    def test_register_duplicate(self):
        d = FaceDetector()
        d.register_image("img-1", 640, 480, seq=1)
        with self.assertRaises(DuplicateImageError):
            d.register_image("img-1", 640, 480, seq=2)

    def test_register_bad_dimensions(self):
        d = FaceDetector()
        seq = 0
        for width, height in [(0, 480), (640, -1), (640.0, 480),
                              (True, 480), (640, None)]:
            seq += 1
            with self.assertRaises(FaceDetectorError):
                d.register_image(f"img-{width}-{height}", width, height, seq=seq)


class TestDetection(unittest.TestCase):
    def _det(self):
        d = FaceDetector()
        d.register_image("img-1", 640, 480, seq=1)
        return d

    def test_detect_happy_path(self):
        d = self._det()
        report = d.detect("img-1", [(10, 20, 100, 120, 0.97),
                                    (200, 200, 50, 60, 0.55)], seq=2)
        self.assertIsInstance(report, DetectionReport)
        self.assertEqual(report.face_count, 2)
        self.assertEqual(report.face_ids, ("face-1", "face-2"))
        box = d.face("face-1")
        self.assertIsInstance(box, FaceBox)
        self.assertEqual((box.x, box.y, box.w, box.h), (10, 20, 100, 120))
        self.assertEqual(box.confidence, 0.97)
        self.assertTrue(box.pin.startswith("sha256:"))
        self.assertEqual(len(d.faces_of("img-1")), 2)

    def test_detect_unknown_image(self):
        d = FaceDetector()
        with self.assertRaises(UnknownImageError):
            d.detect("nope", [(0, 0, 10, 10, 0.9)], seq=1)

    def test_detect_bad_boxes(self):
        d = self._det()
        bad = [
            (0, 0, 0, 10, 0.9),       # zero width
            (0, 0, 10, -5, 0.9),      # negative height
            (-1, 0, 10, 10, 0.9),     # negative origin
            (600, 0, 100, 10, 0.9),  # exceeds width
            (0, 470, 10, 20, 0.9),   # exceeds height
            (10.5, 0, 10, 10, 0.9),  # float x
            ((0, 0, 10, 10),),        # wrong arity
        ]
        seq = 1
        for entry in bad:
            seq += 1
            with self.assertRaises(BadGeometryError):
                d.detect("img-1", [entry], seq=seq)

    def test_detect_bad_confidence(self):
        d = self._det()
        seq = 1
        for conf in [-0.1, 1.5, float("nan"), float("inf"), "high"]:
            seq += 1
            with self.assertRaises(BadConfidenceError):
                d.detect("img-1", [(0, 0, 10, 10, conf)], seq=seq)

    def test_detect_empty_is_valid(self):
        d = self._det()
        report = d.detect("img-1", [], seq=2)
        self.assertEqual(report.face_count, 0)
        self.assertEqual(report.face_ids, ())


class TestLandmarks(unittest.TestCase):
    def _face(self):
        d = FaceDetector()
        d.register_image("img-1", 640, 480, seq=1)
        d.detect("img-1", [(10, 20, 100, 120, 0.9)], seq=2)
        return d, "face-1"

    def test_landmarks_happy_path(self):
        d, face_id = self._face()
        record = d.landmarks(face_id, {"right_eye": (80, 60),
                                       "left_eye": (40, 60)}, seq=3)
        self.assertIsInstance(record, LandmarkSet)
        self.assertEqual(record.points[0], ("left_eye", 40, 60))  # sorted
        self.assertTrue(record.pin.startswith("sha256:"))
        self.assertEqual(d.landmark_set(face_id), record)

    def test_landmarks_must_be_inside_box(self):
        d, face_id = self._face()
        with self.assertRaises(BadGeometryError):
            d.landmarks(face_id, {"nose_tip": (500, 500)}, seq=3)

    def test_landmarks_unknown_face_and_bad_keys(self):
        d, _ = self._face()
        with self.assertRaises(UnknownFaceError):
            d.landmarks("face-999", {"left_eye": (40, 60)}, seq=3)
        with self.assertRaises(BadGeometryError):
            d.landmarks("face-1", {"earlobe": (40, 60)}, seq=4)
        with self.assertRaises(BadGeometryError):
            d.landmarks("face-1", {}, seq=5)
        # idx-N free-form points are accepted
        record = d.landmarks("face-1", {"idx-7": (40, 60)}, seq=6)
        self.assertEqual(record.points[0][0], "idx-7")


class TestAttributes(unittest.TestCase):
    def _face(self):
        d = FaceDetector()
        d.register_image("img-1", 640, 480, seq=1)
        d.detect("img-1", [(10, 20, 100, 120, 0.9)], seq=2)
        return d, "face-1"

    def test_attributes_happy_path(self):
        d, face_id = self._face()
        record = d.attributes(face_id, {"mask": "none",
                                        "glasses": "sunglasses"}, seq=3)
        self.assertIsInstance(record, AttributeRecord)
        self.assertEqual(record.attrs[0], ("glasses", "sunglasses"))  # sorted
        self.assertTrue(record.pin.startswith("sha256:"))
        self.assertEqual(d.attribute_set(face_id), record)

    def test_attributes_vocab_refusals(self):
        d, face_id = self._face()
        with self.assertRaises(UnknownAttributeError):
            d.attributes(face_id, {"mood": "happy"}, seq=3)
        with self.assertRaises(UnknownAttributeError):
            d.attributes(face_id, {"glasses": "monocle"}, seq=4)
        with self.assertRaises(UnknownAttributeError):
            d.attributes(face_id, {}, seq=5)
        with self.assertRaises(UnknownFaceError):
            d.attributes("face-999", {"mask": "none"}, seq=6)


class TestSeqs(unittest.TestCase):
    def test_seq_must_strictly_increase(self):
        d = FaceDetector()
        d.register_image("img-1", 640, 480, seq=1)
        with self.assertRaises(SeqOrderError):
            d.register_image("img-2", 640, 480, seq=1)  # rewind
        with self.assertRaises(SeqOrderError):
            d.register_image("img-2", 640, 480, seq=True)
        d.register_image("img-2", 640, 480, seq=3)  # failed seqs still consumed
        self.assertEqual(d.image_ids(), ("img-1", "img-2"))


class TestAuditAndHouseStyle(unittest.TestCase):
    def test_audit_shapes_and_bad_kind(self):
        event = face_detector_audit_event("detected", seq=2, image_id="img-1",
                                          detail={"face_count": 1})
        self.assertEqual(event["schema"], "audit.ndjson/1")
        self.assertEqual(event["component"], "face-detector")
        self.assertEqual(event["kind"], "detected")
        self.assertNotIn("x", str(event))  # coords never cross the audit boundary
        with self.assertRaises(BadKindError):
            face_detector_audit_event("unpinned", seq=1)
        d = FaceDetector()
        d.register_image("img-1", 640, 480, seq=1)
        d.detect("img-1", [(0, 0, 10, 10, 0.9)], seq=2)
        kinds = [e["kind"] for e in d.audit_log()]
        self.assertEqual(kinds, ["image-registered", "detected"])

    def test_frozen_records_and_stdlib_only(self):
        d = FaceDetector()
        d.register_image("img-1", 640, 480, seq=1)
        box = d.detect("img-1", [(0, 0, 10, 10, 0.9)], seq=2).face_ids
        record = d.face(box[0])
        with self.assertRaises(Exception):
            record.x = 99  # frozen dataclass
        src = Path(__file__).parent.parent / "face_detector.py"
        tree = ast.parse(src.read_text())
        allowed = {"__future__", "hashlib", "math", "threading",
                   "dataclasses", "typing", "canonical_json", "json"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    self.assertIn(node.module.split(".")[0], allowed)

    def test_main_self_check(self):
        import face_detector
        face_detector.main()


if __name__ == "__main__":
    unittest.main()
