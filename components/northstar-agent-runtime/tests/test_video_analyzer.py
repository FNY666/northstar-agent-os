"""Tests for video_analyzer (scene detection + motion estimation, simulated)."""

import ast
import unittest
from pathlib import Path

import video_analyzer as va
from video_analyzer import VideoAnalyzer


def _make_two_shot(seq_start=1):
    """6-frame video: frames 0-2 dark, frames 3-5 bright (cut at 3)."""
    a = VideoAnalyzer()
    a.register_video("v", frame_count=6, fps=30, seq=seq_start, feature_len=4)
    dark = (10, 10, 10, 10)
    bright = (200, 200, 200, 200)
    for i, feat in enumerate([dark, dark, dark, bright, bright, bright]):
        a.report_frame("v", i, feat, seq=seq_start + 1 + i)
    return a


class TestVersionPins(unittest.TestCase):
    def test_pins(self):
        self.assertEqual(va.VIDEO_ANALYZER_VERSION, "video-analyzer.v1")
        self.assertEqual(va.VIDEO_ANALYZER_SCHEMA, "northstar.video-analyzer.v1")
        self.assertEqual(va.AUDIT_SCHEMA, "audit.ndjson/1")
        self.assertEqual(va.DEFAULT_CUT_THRESHOLD_BP, 3500)


class TestStdlibOnly(unittest.TestCase):
    def test_stdlib_only(self):
        tree = ast.parse(Path(va.__file__).read_text())
        allowed = {
            "threading", "dataclasses", "typing", "__future__",
            "canonical_json", "hashlib", "json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestRegister(unittest.TestCase):
    def test_register_roundtrip(self):
        a = VideoAnalyzer()
        rec = a.register_video("v", 10, 24, seq=1)
        self.assertEqual(rec.video_id, "v")
        self.assertEqual(rec.frame_count, 10)
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(a.video("v").digest, rec.digest)
        self.assertEqual(a.video_ids(), ("v",))

    def test_register_duplicate_and_bad_inputs(self):
        a = VideoAnalyzer()
        a.register_video("v", 10, 24, seq=1)
        with self.assertRaises(va.DuplicateVideoError):
            a.register_video("v", 10, 24, seq=2)
        with self.assertRaises(va.BadVideoSpecError):
            a.register_video("", 10, 24, seq=3)
        with self.assertRaises(va.BadVideoSpecError):
            a.register_video("v2", 0, 24, seq=4)
        with self.assertRaises(va.BadVideoSpecError):
            a.register_video("v2", 10, True, seq=5)


class TestReportFrame(unittest.TestCase):
    def test_report_roundtrip(self):
        a = _make_two_shot()
        rec = a.frame("v", 0)
        self.assertEqual(rec.feature, (10, 10, 10, 10))
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(a.frames_reported("v"), 6)

    def test_report_duplicate_and_bad_feature(self):
        a = VideoAnalyzer()
        a.register_video("v", 3, 24, seq=1, feature_len=2)
        a.report_frame("v", 0, (1, 2), seq=2)
        with self.assertRaises(va.DuplicateFrameError):
            a.report_frame("v", 0, (1, 2), seq=3)
        with self.assertRaises(va.BadFeatureError):
            a.report_frame("v", 1, (1,), seq=4)  # wrong length
        with self.assertRaises(va.BadFeatureError):
            a.report_frame("v", 1, (1, 256), seq=5)  # out of range
        with self.assertRaises(va.BadFeatureError):
            a.report_frame("v", 1, (1, True), seq=6)  # bool refused
        with self.assertRaises(va.BadFeatureError):
            a.report_frame("v", 3, (1, 2), seq=7)  # index out of range
        with self.assertRaises(va.UnknownVideoError):
            a.report_frame("nope", 0, (1, 2), seq=8)


class TestScenes(unittest.TestCase):
    def test_cut_detected(self):
        a = _make_two_shot()
        rep = a.scenes("v", seq=8)
        self.assertEqual(rep.cut_frames, (3,))
        self.assertEqual(rep.scene_count, 2)
        self.assertEqual(
            [(s.start_frame, s.end_frame) for s in rep.scenes],
            [(0, 2), (3, 5)],
        )
        self.assertTrue(rep.digest.startswith("sha256:"))

    def test_no_cut_uniform(self):
        a = VideoAnalyzer()
        a.register_video("u", 4, 24, seq=1, feature_len=2)
        for i in range(4):
            a.report_frame("u", i, (50, 50), seq=2 + i)
        rep = a.scenes("u", seq=6)
        self.assertEqual(rep.cut_frames, ())
        self.assertEqual(rep.scene_count, 1)
        self.assertEqual((rep.scenes[0].start_frame, rep.scenes[0].end_frame), (0, 3))

    def test_missing_frames_refused(self):
        a = VideoAnalyzer()
        a.register_video("v", 3, 24, seq=1, feature_len=2)
        a.report_frame("v", 0, (1, 2), seq=2)
        with self.assertRaises(va.MissingFramesError):
            a.scenes("v", seq=3)

    def test_bad_threshold(self):
        a = _make_two_shot()
        for i, bad in enumerate((0, 10001, True, "3500")):
            with self.assertRaises(va.BadThresholdError):
                a.scenes("v", seq=8 + i, cut_threshold_bp=bad)
        # threshold above the observed jump: no cut
        rep = a.scenes("v", seq=12, cut_threshold_bp=10000)
        self.assertEqual(rep.cut_frames, ())


class TestMotion(unittest.TestCase):
    def test_motion_scores(self):
        a = _make_two_shot()
        rep = a.motion("v", seq=8, window=1)
        scores = {s.frame_index: s.motion_bp for s in rep.samples}
        self.assertEqual(scores[0], 0)
        self.assertEqual(scores[1], 0)
        self.assertEqual(scores[2], 0)
        # L1 = 4*190 = 760; max = 4*255 = 1020; bp = round(760*10000/1020) = 7451
        self.assertEqual(scores[3], 7451)
        self.assertEqual(scores[4], 0)
        self.assertEqual(scores[5], 0)
        self.assertEqual(rep.max_motion_frame, 3)
        self.assertEqual(rep.avg_motion_bp, (7451 + 3) // 6)
        self.assertTrue(rep.digest.startswith("sha256:"))

    def test_motion_window_and_bad_window(self):
        a = _make_two_shot()
        rep = a.motion("v", seq=8, window=2)
        scores = {s.frame_index: s.motion_bp for s in rep.samples}
        self.assertEqual(scores[0], 0)
        self.assertEqual(scores[1], 0)
        self.assertEqual(scores[4], 7451)  # compares frame 4 to frame 2
        with self.assertRaises(va.BadThresholdError):
            a.motion("v", seq=9, window=0)


class TestKeyframes(unittest.TestCase):
    def test_keyframes_union(self):
        a = _make_two_shot()
        rep = a.keyframes("v", seq=8, interval=2)
        got = [(k.frame_index, k.reason) for k in rep.keyframes]
        self.assertEqual(
            got,
            [
                (0, va.REASON_FIRST_FRAME),
                (2, va.REASON_INTERVAL),
                (3, va.REASON_SCENE_START),
                (4, va.REASON_INTERVAL),
            ],
        )
        self.assertEqual(rep.count, 4)
        self.assertTrue(rep.digest.startswith("sha256:"))

    def test_keyframes_bad_interval(self):
        a = _make_two_shot()
        with self.assertRaises(va.BadThresholdError):
            a.keyframes("v", seq=8, interval=0)


class TestSeqOrder(unittest.TestCase):
    def test_rewind_refused_and_consumes_seq(self):
        a = VideoAnalyzer()
        a.register_video("v", 2, 24, seq=1, feature_len=1)
        with self.assertRaises(va.DuplicateVideoError):
            a.register_video("v", 2, 24, seq=2)  # fails but consumes seq 2
        with self.assertRaises(va.SeqOrderError):
            a.register_video("w", 2, 24, seq=2)  # rewind refused
        with self.assertRaises(va.SeqOrderError):
            a.register_video("w", 2, 24, seq=True)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        ev = va.video_analyzer_audit_event("scenes-detected", seq=1,
                                           detail={"video_id": "v"})
        self.assertEqual(ev["kind"], "scenes-detected")
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertTrue(ev["pin"].startswith("sha256:"))
        self.assertNotIn("feature", str(ev["detail"]))
        with self.assertRaises(va.VideoAnalyzerError):
            va.video_analyzer_audit_event("nope", seq=2)


class TestFrozenRecords(unittest.TestCase):
    def test_immutable(self):
        a = _make_two_shot()
        rep = a.scenes("v", seq=8)
        with self.assertRaises(Exception):
            rep.scene_count = 99  # frozen dataclass


class TestMain(unittest.TestCase):
    def test_main(self):
        va.main()


if __name__ == "__main__":
    unittest.main()
