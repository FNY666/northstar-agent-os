import json
import os
import stat
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from evidence_chain import EvidenceChain
from evidence_contract import EvidenceRef
from evidence_store import (
    EvidenceCommitUncertainError,
    EvidenceIntegrityError,
    EvidenceStore,
    EvidenceStoreError,
)


class EvidenceStoreTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name) / "evidence"
        self.root.mkdir(mode=0o700)
        self.path = self.root / "run-001.evidence.jsonl"
        self.store = EvidenceStore(self.path, "run-001")

    def tearDown(self):
        self.tempdir.cleanup()

    def append_one(self, *, source_id="start-1", subject=None):
        return self.store.append(
            source="runtime",
            kind="session.started",
            occurred_at=1_800_000_000,
            subject=subject if subject is not None else {"session_id": "s1"},
            source_id=source_id,
        )

    def test_empty_store_is_a_valid_empty_chain(self):
        self.assertEqual(self.store.load(), ())
        report = self.store.verify()
        self.assertTrue(report.ok, report.errors)
        self.assertEqual(report.entries_checked, 0)
        self.assertIsNone(report.head_digest)
        self.assertFalse(self.store.ledger_path.exists())

    def test_append_is_canonical_private_and_survives_reopen(self):
        first = self.append_one()
        second = self.store.append(
            source="verifier",
            kind="artifact.verified",
            occurred_at=1_800_000_001,
            subject={"verdict": "verified"},
            refs=(EvidenceRef("session", "s1", first.subject_digest),),
            source_id="verify-1",
        )

        reopened = EvidenceStore(self.path, "run-001")
        entries = reopened.load()
        self.assertEqual(entries, (first, second))
        self.assertEqual([entry.sequence for entry in entries], [1, 2])
        report = reopened.verify()
        self.assertTrue(report.ok, report.errors)
        self.assertEqual(report.head_digest, second.entry_digest)

        rows = self.store.ledger_path.read_bytes().splitlines()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0], first.canonical_json())
        self.assertEqual(rows[1], second.canonical_json())
        self.assertEqual(stat.S_IMODE(self.store.run_dir.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.store.ledger_path.stat().st_mode), 0o600)

    def test_append_requires_stable_source_id(self):
        with self.assertRaisesRegex(ValueError, "source_id is required"):
            self.store.append(
                source="runtime",
                kind="session.started",
                occurred_at=1_800_000_000,
                subject={"session_id": "s1"},
                source_id=None,
            )
        prepared_without_id = EvidenceChain("run-001").append(
            source="runtime",
            kind="session.started",
            occurred_at=1_800_000_000,
            subject={"session_id": "s1"},
        )
        with self.assertRaisesRegex(ValueError, "must include source_id"):
            self.store.append_entry(prepared_without_id)
        self.assertFalse(self.store.ledger_path.exists())

    def test_append_is_idempotent_and_conflicting_source_id_is_rejected(self):
        first = self.append_one()
        original = self.store.ledger_path.read_bytes()
        retry = self.append_one()
        self.assertEqual(retry, first)
        self.assertEqual(self.store.ledger_path.read_bytes(), original)

        with self.assertRaisesRegex(ValueError, "conflicts"):
            self.append_one(subject={"session_id": "different"})
        self.assertEqual(self.store.load(), (first,))

    def test_prebuilt_entry_with_source_id_can_be_appended_idempotently(self):
        prepared = EvidenceChain("run-001").append(
            source="runtime",
            kind="session.started",
            occurred_at=1_800_000_000,
            subject={"session_id": "s1"},
            source_id="start-1",
        )
        self.assertEqual(self.store.append_entry(prepared), prepared)
        original = self.store.ledger_path.read_bytes()
        self.assertEqual(self.store.append_entry(prepared), prepared)
        self.assertEqual(self.store.ledger_path.read_bytes(), original)
        self.assertTrue(self.store.verify().ok)

    def test_replace_failure_preserves_previous_complete_ledger(self):
        first = self.append_one()
        original = self.store.ledger_path.read_bytes()
        with patch("evidence_store.os.replace", side_effect=OSError("injected failure")):
            with self.assertRaisesRegex(EvidenceStoreError, "before rename"):
                self.store.append(
                    source="runtime",
                    kind="session.ended",
                    occurred_at=1_800_000_001,
                    subject={"session_id": "s1"},
                    source_id="end-1",
                )
        self.assertEqual(self.store.ledger_path.read_bytes(), original)
        self.assertEqual(self.store.load(), (first,))
        self.assertTrue(self.store.verify().ok)
        self.assertEqual(list(self.store.run_dir.glob(".ledger-*.tmp")), [])

    def test_directory_fsync_failure_is_retry_safe_after_atomic_rename(self):
        first = self.append_one()
        real_fsync = os.fsync
        calls = 0

        def fail_directory_fsync(descriptor):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected directory fsync failure")
            return real_fsync(descriptor)

        with patch("evidence_store.os.fsync", side_effect=fail_directory_fsync):
            with self.assertRaises(EvidenceCommitUncertainError):
                self.store.append(
                    source="runtime",
                    kind="session.ended",
                    occurred_at=1_800_000_001,
                    subject={"session_id": "s1"},
                    source_id="end-1",
                )

        committed = self.store.load()
        self.assertEqual(len(committed), 2)
        self.assertEqual(committed[0], first)
        retry = self.store.append(
            source="runtime",
            kind="session.ended",
            occurred_at=1_800_000_001,
            subject={"session_id": "s1"},
            source_id="end-1",
        )
        self.assertEqual(retry, committed[1])
        self.assertEqual(len(self.store.load()), 2)

    def test_hash_corruption_is_reported_and_blocks_reads_and_appends(self):
        self.append_one()
        row = json.loads(self.store.ledger_path.read_text(encoding="utf-8"))
        row["kind"] = "session.ended"
        self.store.ledger_path.write_text(
            json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

        report = self.store.verify()
        self.assertFalse(report.ok)
        self.assertIn("entry_digest", " ".join(report.errors))
        with self.assertRaises(EvidenceIntegrityError):
            self.store.load()
        with self.assertRaises(EvidenceIntegrityError):
            self.append_one(source_id="next")

    def test_zero_byte_existing_ledger_fails_closed(self):
        self.append_one()
        self.store.ledger_path.write_bytes(b"")
        report = self.store.verify()
        self.assertFalse(report.ok)
        self.assertIn("empty", " ".join(report.errors))
        with self.assertRaisesRegex(EvidenceIntegrityError, "empty"):
            self.store.load()
        with self.assertRaisesRegex(EvidenceIntegrityError, "empty"):
            self.append_one(source_id="next")
        self.assertEqual(self.store.ledger_path.read_bytes(), b"")

    def test_noncanonical_jsonl_row_is_rejected_even_if_it_parses(self):
        self.append_one()
        canonical = self.store.ledger_path.read_bytes()
        self.store.ledger_path.write_bytes(b" " + canonical)
        report = self.store.verify()
        self.assertFalse(report.ok)
        self.assertIn("canonical JSON", " ".join(report.errors))

    def test_torn_tail_is_not_silently_repaired_or_extended(self):
        self.append_one()
        complete = self.store.ledger_path.read_bytes()
        self.store.ledger_path.write_bytes(complete[:-1])
        report = self.store.verify()
        self.assertFalse(report.ok)
        self.assertIn("final newline", " ".join(report.errors))
        with self.assertRaisesRegex(EvidenceIntegrityError, "final newline"):
            self.append_one(source_id="next")

    def test_deeply_nested_json_fails_closed_without_recursion_error(self):
        self.store.ledger_path.write_bytes(b'{"nested":' + b"[" * 70 + b"0" + b"]" * 70 + b"}\n")
        report = self.store.verify()
        self.assertFalse(report.ok)
        self.assertIn("nesting", " ".join(report.errors))
        with self.assertRaises(EvidenceIntegrityError):
            self.append_one()

    def test_symlink_ledger_and_lock_are_rejected_without_touching_targets(self):
        target = Path(self.tempdir.name) / "outside.jsonl"
        target.write_text("do not touch\n", encoding="utf-8")
        self.store.ledger_path.symlink_to(target)
        report = self.store.verify()
        self.assertFalse(report.ok)
        self.assertIn("regular file", " ".join(report.errors))
        with self.assertRaises(EvidenceIntegrityError):
            self.store.load()
        self.assertEqual(target.read_text(encoding="utf-8"), "do not touch\n")

        self.store.ledger_path.unlink()
        lock_target = Path(self.tempdir.name) / "outside.lock"
        lock_target.write_text("lock target", encoding="utf-8")
        (self.store.run_dir / ".ledger.lock").unlink()
        (self.store.run_dir / ".ledger.lock").symlink_to(lock_target)
        with self.assertRaises(EvidenceStoreError):
            self.store.verify()
        self.assertEqual(lock_target.read_text(encoding="utf-8"), "lock target")

    def test_directory_fd_pins_writes_if_run_path_is_swapped_mid_operation(self):
        outside = Path(self.tempdir.name) / "outside"
        outside.mkdir()
        displaced = Path(self.tempdir.name) / "evidence-moved"
        real_replace = os.replace

        def swap_run_path_then_replace(src, dst, *, src_dir_fd, dst_dir_fd):
            os.rename(self.store.run_dir, displaced)
            self.store.run_dir.symlink_to(outside, target_is_directory=True)
            return real_replace(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

        with patch("evidence_store.os.replace", side_effect=swap_run_path_then_replace):
            entry = self.append_one()
        displaced_ledger = displaced / self.store.ledger_path.name
        self.assertTrue(displaced_ledger.is_file())
        self.assertEqual(displaced_ledger.read_bytes(), entry.canonical_json() + b"\n")
        self.assertFalse((outside / "ledger.jsonl").exists())

    def test_symlink_run_directory_root_and_unsafe_root_permissions_are_rejected(self):
        root = Path(self.tempdir.name) / "linked-root"
        root.mkdir()
        target = Path(self.tempdir.name) / "target"
        target.mkdir()
        (root / "run-001").symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(EvidenceStoreError, "symlink"):
            EvidenceStore(root / "run-001" / "ledger.jsonl", "run-001")

        root_link = Path(self.tempdir.name) / "root-link"
        root_link.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(EvidenceStoreError, "symlink"):
            EvidenceStore(root_link / "ledger.jsonl", "run-001")

        unsafe_root = Path(self.tempdir.name) / "world-writable"
        unsafe_root.mkdir()
        unsafe_root.chmod(0o777)
        with self.assertRaisesRegex(EvidenceStoreError, "group/world writable"):
            EvidenceStore(unsafe_root / "ledger.jsonl", "run-001")

        for run_id in (".", "..", "../outside"):
            with self.subTest(run_id=run_id):
                with self.assertRaises(ValueError):
                    EvidenceStore(Path(self.tempdir.name) / "other", run_id)

    def test_concurrent_appends_are_serialized_without_lost_entries(self):
        def append(index):
            return self.store.append(
                source="runtime",
                kind="event.recorded",
                occurred_at=1_800_000_000 + index,
                subject={"event_index": index},
                source_id=f"event-{index}",
            )

        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(append, range(16)))

        entries = self.store.load()
        self.assertEqual(len(entries), 16)
        self.assertEqual([entry.sequence for entry in entries], list(range(1, 17)))
        report = self.store.verify()
        self.assertTrue(report.ok, report.errors)

    def test_oversized_ledger_write_is_rejected_before_replace(self):
        with patch("evidence_store.MAX_LEDGER_BYTES", 32):
            with self.assertRaisesRegex(EvidenceStoreError, "exceed"):
                self.append_one()
        self.assertEqual(self.store.load(), ())
        self.assertFalse(self.store.ledger_path.exists())


if __name__ == "__main__":
    unittest.main()
