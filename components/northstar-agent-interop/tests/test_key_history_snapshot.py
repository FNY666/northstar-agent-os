"""Tests for pinned key-history prefixes and as-of key verdicts."""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from key_history_snapshot import (
    HistoricalKeyVerdict,
    KeyHistorySnapshot,
    SnapshotError,
    SnapshotVerdict,
    make_snapshot,
    verdict_at,
    verify_snapshot,
)
from key_lifecycle import KeyHistory

MATERIAL_1 = b"historical-key-material-00000001"
MATERIAL_2 = b"historical-key-material-00000002"
MATERIAL_3 = b"historical-key-material-00000003"


class SnapshotFixture(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.mkdtemp(prefix="key-snapshot-")
        self.addCleanup(shutil.rmtree, self.directory, True)
        self.path = Path(self.directory) / "history.jsonl"
        writer = KeyHistory(self.path)
        writer.introduce("k1", MATERIAL_1)
        writer.rotate("k2", MATERIAL_2)
        writer.revoke("k1")
        self.anchor = writer.records[0].record_digest
        self.history = KeyHistory(self.path, anchor=self.anchor)


class SnapshotTests(SnapshotFixture):
    def test_latest_and_historical_snapshots_verify(self):
        first = make_snapshot(self.history, revision=1)
        latest = make_snapshot(self.history)
        self.assertEqual(first.revision, 1)
        self.assertEqual(latest.revision, 3)
        self.assertEqual(verify_snapshot(self.history, first).state, "trusted")
        self.assertEqual(verify_snapshot(self.history, latest).state, "trusted")

    def test_snapshot_wire_form_is_strict_and_round_trips(self):
        snapshot = make_snapshot(self.history, revision=2)
        self.assertEqual(KeyHistorySnapshot.from_dict(snapshot.to_dict()), snapshot)
        with self.assertRaises(SnapshotError):
            KeyHistorySnapshot.from_dict({**snapshot.to_dict(), "extra": True})
        with self.assertRaises(SnapshotError):
            KeyHistorySnapshot.from_dict({})

    def test_future_and_zero_revisions_are_refused(self):
        for revision in (0, -1, 4, True):
            with self.assertRaises(SnapshotError):
                make_snapshot(self.history, revision=revision)

    def test_anchor_mismatch_is_not_trusted(self):
        other = KeyHistory(self.path, anchor="sha256:" + "f" * 64)
        snapshot = make_snapshot(self.history, revision=2)
        verdict = verify_snapshot(other, snapshot)
        self.assertEqual(verdict.state, "untrusted-anchor")
        self.assertIn("anchor_mismatch", verdict.reasons)

    def test_head_mismatch_is_unverifiable(self):
        snapshot = make_snapshot(self.history, revision=2)
        forged = KeyHistorySnapshot(
            snapshot.schema_version,
            snapshot.revision,
            snapshot.anchor_digest,
            "sha256:" + "e" * 64,
        )
        verdict = verify_snapshot(self.history, forged)
        self.assertEqual(verdict.state, "unverifiable")
        self.assertIn("head_mismatch", verdict.reasons)

    def test_missing_history_is_unverifiable(self):
        snapshot = make_snapshot(self.history, revision=2)
        self.path.unlink()
        verdict = verify_snapshot(self.history, snapshot)
        self.assertEqual(verdict.state, "unverifiable")
        self.assertIn("history_missing", verdict.reasons)

    def test_prefix_corruption_is_unverifiable(self):
        snapshot = make_snapshot(self.history, revision=2)
        lines = self.path.read_text(encoding="utf-8").splitlines()
        value = json.loads(lines[0])
        value["material_digest"] = "sha256:" + "0" * 64
        lines[0] = json.dumps(value, sort_keys=True, separators=(",", ":"))
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        verdict = verify_snapshot(self.history, snapshot)
        self.assertEqual(verdict.state, "unverifiable")

    def test_suffix_corruption_does_not_invalidate_pinned_prefix(self):
        snapshot = make_snapshot(self.history, revision=1)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write('{"complete":"but-invalid-ledger-record"}\n')
        verdict = verify_snapshot(self.history, snapshot)
        self.assertEqual(verdict.state, "trusted")
        self.assertEqual(verdict.revision, 1)
        self.assertEqual(verdict.head_digest, snapshot.head_digest)

    def test_unpinned_history_is_explicitly_unpinned(self):
        unpinned = KeyHistory(self.path)
        snapshot = make_snapshot(unpinned, revision=1)
        verdict = verify_snapshot(unpinned, snapshot)
        self.assertEqual(verdict.state, "verified-unpinned")
        self.assertIn("anchor_unpinned", verdict.reasons)

    def test_snapshot_never_contains_key_material(self):
        snapshot = make_snapshot(self.history, revision=2)
        encoded = json.dumps(snapshot.to_dict(), sort_keys=True)
        self.assertNotIn(MATERIAL_1.decode(), encoded)
        self.assertNotIn(MATERIAL_1.hex(), encoded)
        self.assertNotIn(MATERIAL_2.decode(), encoded)
        self.assertNotIn(MATERIAL_2.hex(), encoded)


class HistoricalVerdictTests(SnapshotFixture):
    def test_revision_one_sees_only_the_introduced_key(self):
        snapshot = make_snapshot(self.history, revision=1)
        self.assertEqual(verdict_at(self.history, "k1", snapshot).state, "trusted")
        self.assertEqual(verdict_at(self.history, "k2", snapshot).state, "unknown-key")

    def test_rotation_marks_old_key_retired_at_the_later_revision(self):
        snapshot = make_snapshot(self.history, revision=2)
        old = verdict_at(self.history, "k1", snapshot)
        new = verdict_at(self.history, "k2", snapshot)
        self.assertEqual(old.state, "trusted-retired")
        self.assertEqual(new.state, "trusted")
        self.assertEqual(old.revision, 2)
        self.assertEqual(old.head_digest, snapshot.head_digest)

    def test_revocation_changes_only_the_later_as_of_verdict(self):
        before = make_snapshot(self.history, revision=2)
        after = make_snapshot(self.history, revision=3)
        self.assertEqual(verdict_at(self.history, "k1", before).state, "trusted-retired")
        self.assertEqual(verdict_at(self.history, "k1", after).state, "revoked")

    def test_historical_verdict_does_not_use_current_suffix_state(self):
        before = make_snapshot(self.history, revision=1)
        result = verdict_at(self.history, "k1", before)
        self.assertEqual(result.state, "trusted")
        self.assertNotIn("revoked", result.reasons)

    def test_unknown_key_and_broken_snapshot_fail_closed(self):
        snapshot = make_snapshot(self.history, revision=2)
        unknown = verdict_at(self.history, "ghost", snapshot)
        self.assertEqual(unknown.state, "unknown-key")
        forged = KeyHistorySnapshot(snapshot.schema_version, snapshot.revision,
                                    snapshot.anchor_digest, "sha256:" + "1" * 64)
        broken = verdict_at(self.history, "k1", forged)
        self.assertEqual(broken.state, "unverifiable")

    def test_unpinned_as_of_verdict_preserves_key_state_and_warning(self):
        unpinned = KeyHistory(self.path)
        snapshot = make_snapshot(unpinned, revision=1)
        result = verdict_at(unpinned, "k1", snapshot)
        self.assertEqual(result.state, "trusted")
        self.assertIn("anchor_unpinned", result.reasons)

    def test_snapshot_argument_must_be_a_snapshot(self):
        with self.assertRaises(SnapshotError):
            verdict_at(self.history, "k1", object())


if __name__ == "__main__":
    unittest.main()
