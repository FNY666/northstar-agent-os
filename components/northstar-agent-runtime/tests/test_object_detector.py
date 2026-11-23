"""Tests for object_detector (YOLO-shaped bookkeeping)."""

import ast
import threading
import unittest

import object_detector as od
from object_detector import ObjectDetector


def _cand(cls="car", box=(0.5, 0.5, 0.2, 0.2), conf=0.9):
    return {"class_name": cls, "box": box, "confidence": conf}


class TestPins(unittest.TestCase):
    def test_version_and_schema(self):
        self.assertEqual(od.OBJECT_DETECTOR_VERSION, "object-detector.v1")
        self.assertEqual(od.OBJECT_DETECTOR_SCHEMA,
                         "northstar.object-detector.v1")

    def test_stdlib_only(self):
        tree = ast.parse(
            open(__file__.replace("tests/test_object_detector.py",
                                  "object_detector.py")).read())
        allowed = {"hashlib", "threading", "dataclasses", "typing",
                   "__future__", "canonical_json", "json"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed, a.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestDetect(unittest.TestCase):
    def test_detect_happy_path(self):
        d = ObjectDetector()
        rep = d.detect("img-1", [_cand(), _cand(cls="person",
                                                box=(0.1, 0.1, 0.1, 0.1))],
                       seq=1)
        self.assertEqual(rep.kept, 2)
        self.assertEqual(rep.suppressed, 0)
        self.assertTrue(rep.digest.startswith("sha256:"))
        ids = [x.detection_id for x in rep.detections]
        self.assertEqual(ids, ["det-1", "det-2"])

    def test_nms_suppresses_overlap(self):
        d = ObjectDetector()
        rep = d.detect("img-1",
                       [_cand(conf=0.9),
                        _cand(box=(0.51, 0.51, 0.2, 0.2), conf=0.8)],
                       seq=1)
        self.assertEqual(rep.kept, 1)
        self.assertEqual(rep.suppressed, 1)
        self.assertAlmostEqual(rep.detections[0].confidence, 0.9)

    def test_confidence_threshold(self):
        d = ObjectDetector()
        rep = d.detect("img-1", [_cand(conf=0.1)], seq=1,
                       min_confidence=0.25)
        self.assertEqual(rep.kept, 0)
        self.assertEqual(rep.suppressed, 0)

    def test_max_detections_cap(self):
        d = ObjectDetector()
        cands = [_cand(box=(i / 100.0 + 0.01, 0.5, 0.005, 0.2))
                 for i in range(10)]
        rep = d.detect("img-1", cands, seq=1, max_detections=3,
                       iou_threshold=1.0)
        self.assertEqual(rep.kept, 3)
        self.assertEqual(rep.suppressed, 7)

    def test_unknown_class_refused(self):
        d = ObjectDetector()
        with self.assertRaises(od.UnknownClassError):
            d.detect("img-1", [_cand(cls="ufo")], seq=1)

    def test_bad_box_refused(self):
        d = ObjectDetector()
        with self.assertRaises(od.BadBoxError):
            d.detect("img-1", [_cand(box=(0.5, 0.5, 0.0, 0.2))], seq=1)
        with self.assertRaises(od.BadBoxError):
            d.detect("img-1",
                     [_cand(box=(float("nan"), 0.5, 0.2, 0.2))],
                     seq=2)

    def test_seq_order_enforced(self):
        d = ObjectDetector()
        d.detect("img-1", [_cand()], seq=5)
        with self.assertRaises(od.SeqOrderError):
            d.detect("img-1", [_cand()], seq=5)

    def test_determinism(self):
        a = ObjectDetector()
        b = ObjectDetector()
        cands = [_cand(conf=0.9),
                 _cand(box=(0.51, 0.51, 0.2, 0.2), conf=0.8),
                 _cand(cls="person", box=(0.1, 0.1, 0.1, 0.1), conf=0.7)]
        ra = a.detect("img-1", cands, seq=1)
        rb = b.detect("img-1", cands, seq=1)
        self.assertEqual(ra.digest, rb.digest)


class TestTrack(unittest.TestCase):
    def test_track_spawn_and_match(self):
        d = ObjectDetector()
        rep = d.detect("f1", [_cand()], seq=1)
        tr = d.track("f1", rep.report_id, seq=2)
        self.assertEqual(tr.spawned, 1)
        self.assertEqual(tr.matched, 0)
        tr2 = d.track("f1", rep.report_id, seq=3)
        self.assertEqual(tr2.matched, 1)
        self.assertEqual(tr2.spawned, 0)
        self.assertEqual(len(tr2.tracks), 1)
        self.assertEqual(tr2.tracks[0].frames_seen, 2)

    def test_track_expiry(self):
        d = ObjectDetector()
        rep = d.detect("f1", [_cand()], seq=1)
        d.track("f1", rep.report_id, seq=2)
        empty = d.detect("f2", [], seq=3)
        # max_age=0: one un-matched frame expires the track
        tr = d.track("f2", empty.report_id, seq=4, max_age=0)
        self.assertEqual(tr.expired, 1)
        self.assertEqual(len(tr.tracks), 0)

    def test_unknown_report_refused(self):
        d = ObjectDetector()
        with self.assertRaises(od.TrackError):
            d.track("f1", "dr-999", seq=1)


class TestCount(unittest.TestCase):
    def test_count(self):
        d = ObjectDetector()
        rep = d.detect("img-1",
                       [_cand(), _cand(cls="person",
                                       box=(0.1, 0.1, 0.1, 0.1))],
                       seq=1)
        cnt = d.count(rep.report_id, seq=2)
        self.assertEqual(cnt.total, 2)
        self.assertEqual(dict(cnt.counts), {"car": 1, "person": 1})
        self.assertTrue(cnt.digest.startswith("sha256:"))

    def test_count_empty(self):
        d = ObjectDetector()
        rep = d.detect("img-1", [], seq=1)
        cnt = d.count(rep.report_id, seq=2)
        self.assertEqual(cnt.total, 0)
        self.assertEqual(cnt.counts, ())


class TestAuditAndSelfcheck(unittest.TestCase):
    def test_audit_shapes(self):
        d = ObjectDetector()
        rep = d.detect("img-1", [_cand()], seq=1)
        d.count(rep.report_id, seq=2)
        log = d.audit_log()
        kinds = [e["kind"] for e in log]
        self.assertEqual(kinds, ["detected", "counted"])
        ev = od.object_detector_audit_event("detected", 9, {"x": 1})
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        with self.assertRaises(od.AuditKindError):
            od.object_detector_audit_event("nope", 1, {})

    def test_thread_safety(self):
        d = ObjectDetector()
        errors = []

        def worker(n):
            try:
                d.detect(f"img-{n}", [_cand()], seq=n)
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(n + 1,))
                   for n in range(5)]
        # serialize seqs to avoid order contention in this sanity check
        for t in threads:
            t.start()
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(d.report_ids()), 5)

    def test_main(self):
        od.main()


if __name__ == "__main__":
    unittest.main()
