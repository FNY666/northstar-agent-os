"""Targeted tests for video_transcoder (simulated FFmpeg-style planning)."""

import ast
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import video_transcoder as vt
from video_transcoder import (
    SCHEMA_PIN,
    VIDEO_TRANSCODER_VERSION,
    MediaInfo,
    NoOpTranscodeError,
    SeqOrderError,
    ThumbnailRecord,
    TranscodeJob,
    UnknownCodecError,
    UnknownContainerError,
    UnknownProfileError,
    UnknownSourceError,
    ValidationError,
    VideoTranscoder,
    video_transcoder_audit_event,
)


def _meta(**over):
    base = {
        "codec": "h264",
        "container": "mp4",
        "width": 1920,
        "height": 1080,
        "duration_ms": 60_000,
        "fps": 30,
    }
    base.update(over)
    return base


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(VIDEO_TRANSCODER_VERSION, "video-transcoder.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.video-transcoder.v1")


class TestStdlibOnly(unittest.TestCase):
    def test_stdlib_imports_only(self):
        tree = ast.parse(Path(vt.__file__).read_text())
        allowed = {
            "hashlib",
            "json",
            "threading",
            "dataclasses",
            "typing",
            "__future__",
            "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed, a.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    self.assertIn(node.module.split(".")[0], allowed, node.module)


class TestRegistry(unittest.TestCase):
    def test_codecs_list(self):
        codecs = VideoTranscoder().codecs()
        for c in ("h264", "h265", "vp9", "av1", "aac", "mp3"):
            self.assertIn(c, codecs)
        self.assertEqual(codecs, sorted(codecs))

    def test_profiles_list(self):
        profiles = VideoTranscoder().profiles()
        for p in ("uhd", "fullhd", "hd", "sd", "ld", "audio-only"):
            self.assertIn(p, profiles)
        self.assertEqual(profiles["fullhd"]["width"], 1920)
        self.assertEqual(profiles["fullhd"]["height"], 1080)
        self.assertIsNone(profiles["audio-only"]["width"])


class TestProbe(unittest.TestCase):
    def test_probe_happy_path(self):
        t = VideoTranscoder()
        info = t.probe(_meta(), 1)
        self.assertIsInstance(info, MediaInfo)
        self.assertEqual(info.info_id, "info-1")
        self.assertTrue(info.source_digest.startswith("sha256:"))
        self.assertEqual(info.schema, SCHEMA_PIN)
        self.assertEqual(t.source("info-1"), info)

    def test_probe_digest_determinism(self):
        t1 = VideoTranscoder()
        t2 = VideoTranscoder()
        self.assertEqual(
            t1.probe(_meta(), 1).source_digest, t2.probe(_meta(), 1).source_digest
        )

    def test_probe_unknown_codec(self):
        with self.assertRaises(UnknownCodecError):
            VideoTranscoder().probe(_meta(codec="dirac"), 1)

    def test_probe_unknown_container(self):
        with self.assertRaises(UnknownContainerError):
            VideoTranscoder().probe(_meta(container="rmvb"), 1)

    def test_probe_bad_dimensions(self):
        t = VideoTranscoder()
        for bad in (0, -1, True, "1920", 99999):
            with self.assertRaises(Exception, msg=str(bad)):
                t.probe(_meta(width=bad), 1)

    def test_probe_bad_duration(self):
        t = VideoTranscoder()
        for bad in (0, -5, True, vt.MAX_DURATION_MS + 1):
            with self.assertRaises(Exception, msg=str(bad)):
                t.probe(_meta(duration_ms=bad), 1)

    def test_probe_bad_fps(self):
        t = VideoTranscoder()
        for bad in (0, -24, True, float("nan"), float("inf"), 999.0):
            with self.assertRaises(Exception, msg=str(bad)):
                t.probe(_meta(fps=bad), 1)

    def test_probe_not_mapping(self):
        with self.assertRaises(Exception):
            VideoTranscoder().probe(["not", "a", "mapping"], 1)

    def test_probe_optional_audio_fields(self):
        t = VideoTranscoder()
        info = t.probe(_meta(audio_codec="aac", bitrate_kbps=8000), 1)
        self.assertEqual(info.audio_codec, "aac")
        self.assertEqual(info.bitrate_kbps, 8000)
        with self.assertRaises(Exception):
            t.probe(_meta(bitrate_kbps=-3), 2)


class TestTranscode(unittest.TestCase):
    def _probed(self, t, seq=1, **over):
        return t.probe(_meta(**over), seq)

    def test_transcode_happy_path_and_verify(self):
        t = VideoTranscoder()
        info = self._probed(t)
        job, out = t.transcode(info.info_id, "h265", "hd", 2)
        self.assertIsInstance(job, TranscodeJob)
        self.assertEqual(out["width"], 1280)
        self.assertEqual(out["height"], 720)
        self.assertTrue(job.verify(out))
        self.assertFalse(job.verify({**out, "width": 640}))
        self.assertEqual(len(job.losses), 2)  # codec change + downscale

    def test_transcode_size_estimate_math(self):
        t = VideoTranscoder()
        info = self._probed(t)
        job, out = t.transcode(info.info_id, "vp9", "sd", 2)
        self.assertEqual(out["estimated_size_kb"], 60_000 * 1200 // 8000)
        self.assertEqual(job.estimated_size_kb, 60_000 * 1200 // 8000)

    def test_transcode_unknown_source(self):
        t = VideoTranscoder()
        with self.assertRaises(UnknownSourceError):
            t.transcode("info-999", "h265", "hd", 1)

    def test_transcode_unknown_codec(self):
        t = VideoTranscoder()
        info = self._probed(t)
        with self.assertRaises(UnknownCodecError):
            t.transcode(info.info_id, "dirac", "hd", 2)

    def test_transcode_unknown_profile(self):
        t = VideoTranscoder()
        info = self._probed(t)
        with self.assertRaises(UnknownProfileError):
            t.transcode(info.info_id, "h265", "vhs", 2)

    def test_transcode_noop_refused(self):
        t = VideoTranscoder()
        info = self._probed(t)
        with self.assertRaises(NoOpTranscodeError):
            t.transcode(info.info_id, "h264", "fullhd", 2)

    def test_transcode_audio_codec_needs_audio_profile(self):
        t = VideoTranscoder()
        info = self._probed(t)
        with self.assertRaises(ValidationError):
            t.transcode(info.info_id, "aac", "hd", 2)
        with self.assertRaises(ValidationError):
            t.transcode(info.info_id, "h265", "audio-only", 3)

    def test_transcode_audio_only_drops_video(self):
        t = VideoTranscoder()
        info = self._probed(t)
        job, out = t.transcode(info.info_id, "mp3", "audio-only", 2)
        self.assertIsNone(out["width"])
        self.assertIn("video track dropped", job.losses)

    def test_transcode_upscale_loss(self):
        t = VideoTranscoder()
        info = self._probed(t, width=640, height=360)
        job, _ = t.transcode(info.info_id, "h265", "uhd", 2)
        self.assertTrue(any("upscale" in loss for loss in job.losses))

    def test_transcode_efficiency_loss(self):
        t = VideoTranscoder()
        info = t.probe(_meta(codec="av1"), 1)
        job, _ = t.transcode(info.info_id, "h264", "hd", 2)
        self.assertTrue(any("compression efficiency" in loss for loss in job.losses))

    def test_job_lookup(self):
        t = VideoTranscoder()
        info = self._probed(t)
        job, _ = t.transcode(info.info_id, "h265", "hd", 2)
        self.assertEqual(t.job(job.job_id), job)
        with self.assertRaises(ValidationError):
            t.job("job-999")


class TestThumbnail(unittest.TestCase):
    def test_thumbnail_happy_path(self):
        t = VideoTranscoder()
        info = t.probe(_meta(), 1)
        thumb = t.thumbnail(info.info_id, 30_000, 2)
        self.assertIsInstance(thumb, ThumbnailRecord)
        self.assertEqual(thumb.thumb_id, "thumb-2")
        self.assertEqual(thumb.height, 180)
        self.assertEqual(thumb.width, 320)  # 180 * 1920/1080
        self.assertEqual(thumb.format, "jpeg")
        self.assertTrue(thumb.thumb_digest.startswith("sha256:"))

    def test_thumbnail_at_ms_bounds(self):
        t = VideoTranscoder()
        info = t.probe(_meta(), 1)
        t.thumbnail(info.info_id, 0, 2)
        t.thumbnail(info.info_id, 60_000, 3)
        with self.assertRaises(ValidationError):
            t.thumbnail(info.info_id, 60_001, 4)
        with self.assertRaises(ValidationError):
            t.thumbnail(info.info_id, -1, 5)
        with self.assertRaises(ValidationError):
            t.thumbnail(info.info_id, True, 6)

    def test_thumbnail_bad_format(self):
        t = VideoTranscoder()
        info = t.probe(_meta(), 1)
        with self.assertRaises(ValidationError):
            t.thumbnail(info.info_id, 1000, 2, format="bmp")
        png = t.thumbnail(info.info_id, 1000, 3, format="PNG")
        self.assertEqual(png.format, "png")

    def test_thumbnail_unknown_source(self):
        with self.assertRaises(UnknownSourceError):
            VideoTranscoder().thumbnail("info-999", 100, 1)

    def test_thumbnail_aspect_ratio(self):
        t = VideoTranscoder()
        info = t.probe(_meta(width=640, height=480), 1)
        thumb = t.thumbnail(info.info_id, 1000, 2)
        self.assertEqual(thumb.width, round(180 * 640 / 480))


class TestSeqAndAudit(unittest.TestCase):
    def test_seq_rewind_refused(self):
        t = VideoTranscoder()
        t.probe(_meta(), 5)
        with self.assertRaises(SeqOrderError):
            t.probe(_meta(), 5)
        with self.assertRaises(SeqOrderError):
            t.probe(_meta(), 3)

    def test_bool_seq_refused(self):
        with self.assertRaises(ValidationError):
            VideoTranscoder().probe(_meta(), True)

    def test_audit_shapes(self):
        t = VideoTranscoder()
        info = t.probe(_meta(), 1)
        t.transcode(info.info_id, "h265", "hd", 2)
        t.thumbnail(info.info_id, 1000, 3)
        log = t.audit_log()
        self.assertEqual([e["kind"] for e in log], ["probed", "transcoded", "thumbnail-captured"])
        for e in log:
            self.assertEqual(e["schema"], "audit.ndjson/1")
            self.assertEqual(e["module"], "video-transcoder")

    def test_audit_bad_kind(self):
        with self.assertRaises(ValidationError):
            video_transcoder_audit_event("burned", 1, "x-1")

    def test_frozen_records(self):
        t = VideoTranscoder()
        info = t.probe(_meta(), 1)
        with self.assertRaises(Exception):
            info.codec = "h265"  # frozen dataclass


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        vt.main()


if __name__ == "__main__":
    unittest.main()
