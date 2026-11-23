"""Tests for audio_processor: format conversion, normalization, trim."""

import ast
import struct
import threading
import unittest

from audio_processor import (
    AUDIO_PROCESSOR_VERSION,
    SCHEMA_PIN,
    AudioProcessor,
    AudioTooLargeError,
    BadRangeError,
    DuplicateTrackError,
    SeqOrderError,
    UnknownFormatError,
    UnknownTrackError,
    ValidationError,
    audio_processor_audit_event,
)


def _pcm(values):
    return struct.pack(f"<{len(values)}h", *values)


class TestPins(unittest.TestCase):
    def test_version_and_schema(self):
        self.assertEqual(AUDIO_PROCESSOR_VERSION, "audio-processor.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.audio-processor.v1")

    def test_stdlib_only(self):
        tree = ast.parse(open("audio_processor.py").read())
        allowed = {
            "hashlib", "math", "struct", "threading", "dataclasses",
            "typing", "__future__", "json", "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestRegister(unittest.TestCase):
    def setUp(self):
        self.proc = AudioProcessor()

    def test_register_roundtrip(self):
        pcm = _pcm([1000, -1000] * 44100)
        rec = self.proc.register_track("t1", pcm, 44100, 2, 1)
        self.assertEqual(rec.format, "raw")
        self.assertEqual(rec.sample_rate, 44100)
        self.assertEqual(rec.channels, 2)
        self.assertEqual(rec.bit_depth, 16)
        self.assertEqual(rec.frames, 44100)
        self.assertEqual(rec.duration_ms, 1000)
        self.assertEqual(self.proc.pcm("t1"), pcm)
        self.assertEqual(self.proc.track_ids(), ("t1",))

    def test_register_digest_determinism(self):
        pcm = _pcm([1, -1] * 100)
        a = self.proc.register_track("a", pcm, 8000, 1, 1)
        b_proc = AudioProcessor()
        b = b_proc.register_track("a", pcm, 8000, 1, 1)
        self.assertEqual(a.record_pin, b.record_pin)

    def test_register_duplicate_refused(self):
        self.proc.register_track("t1", _pcm([1, 2]), 8000, 1, 1)
        with self.assertRaises(DuplicateTrackError):
            self.proc.register_track("t1", _pcm([3, 4]), 8000, 1, 2)

    def test_register_bad_inputs(self):
        with self.assertRaises(ValidationError):
            self.proc.register_track("", _pcm([1]), 8000, 1, 1)
        with self.assertRaises(ValidationError):
            self.proc.register_track("t", b"", 8000, 1, 2)
        with self.assertRaises(ValidationError):
            self.proc.register_track("t", b"\x00", 8000, 1, 3)
        with self.assertRaises(ValidationError):
            self.proc.register_track("t", _pcm([1]), 12345, 1, 4)
        with self.assertRaises(ValidationError):
            self.proc.register_track("t", _pcm([1]), 8000, 3, 5)
        with self.assertRaises(ValidationError):
            self.proc.register_track("t", _pcm([1]), True, 1, 6)
        with self.assertRaises(AudioTooLargeError):
            big = bytes(2 * (64 << 20) + 2)
            self.proc.register_track("t", big, 8000, 1, 7)

    def test_seq_monotonic_and_rewind(self):
        self.proc.register_track("t1", _pcm([1]), 8000, 1, 5)
        with self.assertRaises(SeqOrderError):
            self.proc.register_track("t2", _pcm([1]), 8000, 1, 5)
        with self.assertRaises(ValidationError):
            self.proc.register_track("t2", _pcm([1]), 8000, 1, True)

    def test_failed_mutation_consumes_seq(self):
        with self.assertRaises(ValidationError):
            self.proc.register_track("t1", b"", 8000, 1, 1)
        with self.assertRaises(SeqOrderError):  # seq 1 was consumed
            self.proc.register_track("t1", _pcm([1]), 8000, 1, 1)

    def test_unknown_track(self):
        with self.assertRaises(UnknownTrackError):
            self.proc.track("nope")
        with self.assertRaises(ValidationError):
            self.proc.track("")


class TestConvert(unittest.TestCase):
    def setUp(self):
        self.proc = AudioProcessor()
        self.proc.register_track("t1", _pcm([1000] * 100), 44100, 1, 1)

    def test_convert_mp3_loss_ledger(self):
        conv = self.proc.convert("t1", "mp3", 2)
        self.assertEqual(conv.from_format, "raw")
        self.assertEqual(conv.to_format, "mp3")
        self.assertTrue(len(conv.losses) >= 1)
        self.assertEqual(conv.losses, self.proc.losses("mp3"))
        out = self.proc.track(conv.to_track)
        self.assertEqual(out.format, "mp3")
        self.assertEqual(out.frames, 100)
        self.assertEqual(out.pcm_pin, self.proc.track("t1").pcm_pin)

    def test_convert_lossless_has_no_losses(self):
        conv = self.proc.convert("t1", "wav", 2)
        self.assertEqual(conv.losses, ())
        conv2 = self.proc.convert("t1", "flac", 3)
        self.assertEqual(conv2.losses, ())

    def test_convert_unknown_format(self):
        with self.assertRaises(UnknownFormatError):
            self.proc.convert("t1", "midi", 2)
        with self.assertRaises(UnknownFormatError):
            self.proc.losses("midi")

    def test_formats_listing(self):
        fmts = self.proc.formats()
        self.assertIn("mp3", fmts)
        self.assertIn("wav", fmts)
        self.assertEqual(fmts, tuple(sorted(fmts)))


class TestNormalize(unittest.TestCase):
    def setUp(self):
        self.proc = AudioProcessor()

    def test_normalize_gain_math(self):
        # peak 16384 = 0.5 full scale = -6.0206 dBFS
        self.proc.register_track("t1", _pcm([16384, -16384]), 44100, 1, 1)
        report = self.proc.normalize("t1", 2, -1.0)
        self.assertAlmostEqual(report.peak_dbfs, -6.020599913279624, places=9)
        self.assertAlmostEqual(report.gain_db, 5.020599913279624, places=9)
        gain = 10 ** (report.gain_db / 20.0)
        out = self.proc.pcm(report.to_track)
        samples = struct.unpack("<2h", out)
        self.assertEqual(samples[0], int(round(16384 * gain)))
        self.assertEqual(samples[1], -int(round(16384 * gain)))

    def test_normalize_clips_at_full_scale(self):
        self.proc.register_track("t1", _pcm([32767]), 44100, 1, 1)
        report = self.proc.normalize("t1", 2, 0.0)
        samples = struct.unpack("<1h", self.proc.pcm(report.to_track))
        self.assertEqual(samples[0], 32767)
        self.assertEqual(report.peak_sample, 32767)

    def test_normalize_noop_at_same_level(self):
        peak = -6.020599913279624
        self.proc.register_track("t1", _pcm([16384]), 44100, 1, 1)
        report = self.proc.normalize("t1", 2, peak)
        out = self.proc.pcm(report.to_track)
        self.assertEqual(struct.unpack("<1h", out)[0], 16384)

    def test_normalize_determinism(self):
        self.proc.register_track("t1", _pcm([5000, -2000]), 16000, 1, 1)
        p2 = AudioProcessor()
        p2.register_track("t1", _pcm([5000, -2000]), 16000, 1, 1)
        r1 = self.proc.normalize("t1", 2, -3.0, new_id="n")
        r2 = p2.normalize("t1", 2, -3.0, new_id="n")
        self.assertEqual(r1.record_pin, r2.record_pin)

    def test_normalize_silence_refused(self):
        self.proc.register_track("t1", _pcm([0, 0]), 8000, 1, 1)
        with self.assertRaises(ValidationError):
            self.proc.normalize("t1", 2, -1.0)

    def test_normalize_bad_target(self):
        self.proc.register_track("t1", _pcm([1000]), 8000, 1, 1)
        with self.assertRaises(ValidationError):
            self.proc.normalize("t1", 2, 1.0)  # positive dBFS
        with self.assertRaises(ValidationError):
            self.proc.normalize("t1", 3, True)
        with self.assertRaises(ValidationError):
            self.proc.normalize("t1", 4, float("inf"))


class TestTrim(unittest.TestCase):
    def setUp(self):
        self.proc = AudioProcessor()
        # 2s mono 44100: 88200 frames
        self.proc.register_track("t1", _pcm(list(range(-1000, 1000)) * 88 + [1] * 200), 44100, 1, 1)

    def test_trim_exact_bytes(self):
        rec = self.proc.trim("t1", 2, 500, 1500)
        out = self.proc.track(rec.to_track)
        self.assertEqual(out.frames, 44100)
        self.assertEqual(out.duration_ms, 1000)
        self.assertEqual(rec.start_frame, 22050)
        self.assertEqual(rec.end_frame, 66150)
        src = self.proc.pcm("t1")
        self.assertEqual(self.proc.pcm(rec.to_track), src[44100:132300])

    def test_trim_bad_ranges(self):
        with self.assertRaises(BadRangeError):
            self.proc.trim("t1", 2, 1500, 500)   # start >= end
        with self.assertRaises(BadRangeError):
            self.proc.trim("t1", 3, -1, 100)     # negative
        with self.assertRaises(BadRangeError):
            self.proc.trim("t1", 4, 0, 5000)     # beyond duration
        with self.assertRaises(ValidationError):
            self.proc.trim("t1", 5, 0.5, 100)    # float ms
        with self.assertRaises(ValidationError):
            self.proc.trim("t1", 6, 0, True)     # bool ms


class TestAuditAndMisc(unittest.TestCase):
    def test_audit_shapes(self):
        proc = AudioProcessor()
        proc.register_track("t1", _pcm([1, 2]), 8000, 1, 1)
        ev = audio_processor_audit_event("converted", 2, {"conversion_id": "cv-1"})
        self.assertEqual(ev["kind"], "converted")
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        with self.assertRaises(ValidationError):
            audio_processor_audit_event("bogus", 3, {})
        with self.assertRaises(ValidationError):
            audio_processor_audit_event("converted", True, {})

    def test_concurrent_registers(self):
        proc = AudioProcessor()
        seq_lock = threading.Lock()
        seq = [0]

        def worker(i):
            with seq_lock:
                seq[0] += 1
                s = seq[0]
            proc.register_track(f"w{i}", _pcm([i % 32767]), 8000, 1, s)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(proc.track_ids()), 8)

    def test_main(self):
        from audio_processor import main
        main()


if __name__ == "__main__":
    unittest.main()
