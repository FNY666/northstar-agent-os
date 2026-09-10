"""Crash-consistent segmented evidence log: rotation, compaction, recovery."""
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from evidence_rotation import (
    MANIFEST_NAME,
    RotationError,
    SegmentedEvidenceLog,
    verify_log,
)


def _write(path, text):
    Path(path).write_text(text, encoding="utf-8")


class RotationBasics(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="rot-")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def test_append_and_read_roundtrip(self):
        log = SegmentedEvidenceLog(self.dir, max_records_per_segment=4)
        for i in range(3):
            log.append({"event_id": "e%d" % i, "value": i})
        self.assertEqual([r["event_id"] for r in log.read_all()], ["e0", "e1", "e2"])
        self.assertEqual(log.read_all()[2]["value"], 2)

    def test_rotate_seals_segment_and_continues(self):
        log = SegmentedEvidenceLog(self.dir, max_records_per_segment=2)
        log.append({"event_id": "e0"})
        log.append({"event_id": "e1"})
        ref = log.rotate()
        self.assertEqual(ref.segment_id, 1)
        self.assertEqual((ref.first_sequence, ref.last_sequence, ref.record_count), (1, 2, 2))
        self.assertFalse(ref.compacted)
        log.append({"event_id": "e2"})
        self.assertEqual([r["event_id"] for r in log.read_all()], ["e0", "e1", "e2"])
        self.assertEqual([s.segment_id for s in log.segments()], [1])
        self.assertEqual(log.active_segment_id, 2)

    def test_auto_rotate_on_segment_limit(self):
        log = SegmentedEvidenceLog(self.dir, max_records_per_segment=2)
        for i in range(5):
            log.append({"event_id": "e%d" % i})
        self.assertEqual([s.segment_id for s in log.segments()], [1, 2])
        self.assertEqual(log.active_record_count, 1)
        self.assertEqual(len(log.read_all()), 5)

    def test_segment_digest_is_stable_and_content_bound(self):
        log = SegmentedEvidenceLog(self.dir, max_records_per_segment=8)
        log.append({"event_id": "e0"})
        ref = log.rotate()
        self.assertEqual(ref.segment_digest, log.segments()[0].segment_digest)
        seg = Path(self.dir) / ("segment-%06d.log" % ref.segment_id)
        self.assertTrue(seg.exists())
        seg.write_text(seg.read_text(encoding="utf-8").replace("e0", "e1"), encoding="utf-8")
        self.assertEqual(log.verify().state, "unverifiable")

    def test_records_are_chained_across_segments(self):
        log = SegmentedEvidenceLog(self.dir, max_records_per_segment=2)
        for i in range(4):
            log.append({"event_id": "e%d" % i})
        log.append({"event_id": "e4"})
        records = log.read_all()
        digests = [r["record_digest"] for r in records]
        self.assertEqual(len(set(digests)), 5)
        self.assertEqual(records[0]["previous_digest"], "sha256:" + "0" * 64)
        for i in range(1, 5):
            self.assertEqual(records[i]["previous_digest"], digests[i - 1])


class CrashRecovery(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="rot-")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def test_truncated_tail_line_is_ignored(self):
        log = SegmentedEvidenceLog(self.dir, max_records_per_segment=8)
        log.append({"event_id": "e0"})
        log.append({"event_id": "e1"})
        active = Path(self.dir) / "active.log"
        active.write_text(active.read_text(encoding="utf-8") + '{"event_id":"e2"', encoding="utf-8")
        fresh = SegmentedEvidenceLog(self.dir, max_records_per_segment=8)
        self.assertEqual([r["event_id"] for r in fresh.read_all()], ["e0", "e1"])
        self.assertEqual(fresh.verify().state, "replayable")

    def test_rotation_interrupted_after_manifest_is_completed(self):
        log = SegmentedEvidenceLog(self.dir, max_records_per_segment=8)
        log.append({"event_id": "e0"})
        log.append({"event_id": "e1"})
        log.rotate()
        # Simulate a crash between the manifest publish and the segment rename:
        # the sealed file goes back to being the active file.
        sealed = Path(self.dir) / "segment-000001.log"
        manifest = json.loads((Path(self.dir) / MANIFEST_NAME).read_text(encoding="utf-8"))
        os.replace(sealed, Path(self.dir) / "active.log")
        self.assertEqual([s.segment_id for s in SegmentedEvidenceLog(self.dir, max_records_per_segment=8).segments()], [1])
        fresh = SegmentedEvidenceLog(self.dir, max_records_per_segment=8)
        self.assertEqual([r["event_id"] for r in fresh.read_all()], ["e0", "e1"])
        self.assertEqual(fresh.verify().state, "replayable")
        self.assertEqual(manifest["generation"], 1)

    def test_unregistered_segment_file_is_reported_not_adopted(self):
        log = SegmentedEvidenceLog(self.dir, max_records_per_segment=8)
        log.append({"event_id": "e0"})
        log.rotate()
        rogue = Path(self.dir) / "segment-000009.log"
        _write(rogue, '{"event_id":"rogue"}\n')
        verdict = SegmentedEvidenceLog(self.dir, max_records_per_segment=8).verify()
        self.assertEqual(verdict.state, "unverifiable")
        self.assertIn("orphan_segment", verdict.reasons)

    def test_missing_segment_is_unverifiable(self):
        log = SegmentedEvidenceLog(self.dir, max_records_per_segment=8)
        log.append({"event_id": "e0"})
        log.rotate()
        (Path(self.dir) / "segment-000001.log").unlink()
        verdict = SegmentedEvidenceLog(self.dir, max_records_per_segment=8).verify()
        self.assertEqual(verdict.state, "unverifiable")
        self.assertIn("segment_missing", verdict.reasons)

    def test_missing_manifest_with_sealed_segments_is_unverifiable(self):
        log = SegmentedEvidenceLog(self.dir, max_records_per_segment=8)
        log.append({"event_id": "e0"})
        log.rotate()
        (Path(self.dir) / MANIFEST_NAME).unlink()
        self.assertEqual(SegmentedEvidenceLog(self.dir, max_records_per_segment=8).verify().state, "unverifiable")

    def test_corrupt_manifest_line_is_unverifiable(self):
        log = SegmentedEvidenceLog(self.dir, max_records_per_segment=8)
        log.append({"event_id": "e0"})
        log.rotate()
        _write(Path(self.dir) / MANIFEST_NAME, "{not json")
        with self.assertRaises(RotationError):
            SegmentedEvidenceLog(self.dir, max_records_per_segment=8).verify()


class Compaction(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="rot-")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def test_compaction_degrades_readability_not_provability(self):
        log = SegmentedEvidenceLog(self.dir, max_records_per_segment=2)
        log.append({"event_id": "e0"})
        log.append({"event_id": "e1"})
        ref = log.rotate()
        digest = ref.segment_digest
        log.compact(1)
        self.assertEqual(log.verify().state, "digest-only")
        self.assertEqual(log.verify().reasons, ("segment_compacted",))
        self.assertEqual(log.segments()[0].segment_digest, digest)
        with self.assertRaises(RotationError):
            log.read_segment(1)
        self.assertEqual([s.segment_id for s in log.segments()], [1])
        self.assertFalse((Path(self.dir) / "segment-000001.log").exists())

    def test_compacted_stream_stays_replayable_for_live_records(self):
        log = SegmentedEvidenceLog(self.dir, max_records_per_segment=2)
        log.append({"event_id": "e0"})
        log.append({"event_id": "e1"})
        log.rotate()
        log.compact(1)
        log.append({"event_id": "e2"})
        self.assertEqual([r["event_id"] for r in log.read_all()], ["e2"])
        self.assertEqual(log.verify().state, "digest-only")

    def test_cannot_compact_twice_or_compact_active_segment(self):
        log = SegmentedEvidenceLog(self.dir, max_records_per_segment=2)
        log.append({"event_id": "e0"})
        log.append({"event_id": "e1"})
        log.rotate()
        log.compact(1)
        with self.assertRaises(RotationError):
            log.compact(1)
        with self.assertRaises(RotationError):
            log.compact(log.active_segment_id)

    def test_compaction_survives_restart_and_keeps_checkpoint_chain(self):
        log = SegmentedEvidenceLog(self.dir, max_records_per_segment=2)
        log.append({"event_id": "e0"})
        log.append({"event_id": "e1"})
        first = log.rotate()
        log.compact(1)
        log.append({"event_id": "e2"})
        log.append({"event_id": "e3"})
        second = log.rotate()
        self.assertNotEqual(first.segment_digest, second.segment_digest)
        fresh = SegmentedEvidenceLog(self.dir, max_records_per_segment=2)
        self.assertEqual([s.segment_digest for s in fresh.segments()], [first.segment_digest, second.segment_digest])
        self.assertEqual(fresh.verify().state, "digest-only")


class VerifyHelper(unittest.TestCase):
    def test_verify_log_helper_matches_instance_verdict(self):
        root = tempfile.mkdtemp(prefix="rot-")
        self.addCleanup(shutil.rmtree, root, True)
        log = SegmentedEvidenceLog(root, max_records_per_segment=2)
        log.append({"event_id": "e0"})
        self.assertEqual(verify_log(root).state, log.verify().state)
        self.assertEqual(verify_log(root).state, "replayable")


if __name__ == "__main__":
    unittest.main()
