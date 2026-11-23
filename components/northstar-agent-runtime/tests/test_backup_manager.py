"""Tests for backup_manager."""

import ast
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backup_manager import (
    BACKUP_MANAGER_SCHEMA,
    BACKUP_MANAGER_VERSION,
    BackupManager,
    BackupManagerError,
    BadInputError,
    BadScheduleError,
    DuplicateScheduleError,
    ExpiredSnapshotError,
    SeqOrderError,
    UnknownScheduleError,
    UnknownSnapshotError,
    backup_manager_audit_event,
)

GOOD_DIGEST = "sha256:" + "ab" * 32


def make_manager():
    return BackupManager()


class TestPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(BACKUP_MANAGER_VERSION, "backup-manager.v1")
        self.assertEqual(BACKUP_MANAGER_SCHEMA, "northstar.backup-manager.v1")

    def test_stdlib_only(self):
        path = os.path.join(os.path.dirname(__file__), "..", "backup_manager.py")
        tree = ast.parse(open(path).read())
        allowed = {
            "hashlib", "re", "threading", "dataclasses", "typing",
            "json", "canonical_json", "__future__",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestSnapshot(unittest.TestCase):
    def test_snapshot_roundtrip_and_verify(self):
        mgr = make_manager()
        rec = mgr.snapshot("app", 1, sources=[("etc/a", GOOD_DIGEST)])
        self.assertEqual(rec.snapshot_id, "snap-1")
        self.assertEqual(rec.backup_set, "app")
        self.assertEqual(rec.kind, "full")
        rec.verify()

    def test_snapshot_pin_determinism(self):
        a = make_manager()
        b = make_manager()
        ra = a.snapshot("x", 1, sources=[("f", GOOD_DIGEST)])
        rb = b.snapshot("x", 1, sources=[("f", GOOD_DIGEST)])
        self.assertEqual(ra.digest, rb.digest)

    def test_snapshot_bad_kind(self):
        mgr = make_manager()
        with self.assertRaises(BadInputError):
            mgr.snapshot("app", 1, kind="weird")

    def test_incremental_requires_parent(self):
        mgr = make_manager()
        with self.assertRaises(BadInputError):
            mgr.snapshot("app", 1, kind="incremental")

    def test_incremental_with_parent(self):
        mgr = make_manager()
        base = mgr.snapshot("app", 1)
        inc = mgr.snapshot("app", 2, kind="incremental", parent_id=base.snapshot_id)
        self.assertEqual(inc.parent_id, base.snapshot_id)
        inc.verify()

    def test_unknown_parent(self):
        mgr = make_manager()
        with self.assertRaises(UnknownSnapshotError):
            mgr.snapshot("app", 1, kind="incremental", parent_id="snap-99")

    def test_failed_mutation_consumes_seq(self):
        mgr = make_manager()
        with self.assertRaises(BadInputError):
            mgr.snapshot("app", 1, kind="bogus")
        with self.assertRaises(SeqOrderError):
            mgr.snapshot("app", 1)
        rec = mgr.snapshot("app", 2)
        self.assertEqual(rec.snapshot_id, "snap-1")

    def test_seq_rewind_refused(self):
        mgr = make_manager()
        mgr.snapshot("app", 5)
        with self.assertRaises(SeqOrderError):
            mgr.snapshot("app", 5)
        with self.assertRaises(SeqOrderError):
            mgr.snapshot("app", True)


class TestRestore(unittest.TestCase):
    def test_restore_roundtrip_and_verify(self):
        mgr = make_manager()
        snap = mgr.snapshot("app", 1)
        rst = mgr.restore(snap.snapshot_id, 2, target_map=[("a", "b")])
        self.assertEqual(rst.restore_id, "rst-1")
        self.assertEqual(rst.snapshot_digest, snap.digest)
        rst.verify()

    def test_restore_unknown_snapshot(self):
        mgr = make_manager()
        with self.assertRaises(UnknownSnapshotError):
            mgr.restore("snap-99", 1)

    def test_restore_pruned_refused(self):
        mgr = make_manager()
        s1 = mgr.snapshot("app", 1)
        mgr.snapshot("app", 2)
        mgr.prune("app", 1, 3)
        with self.assertRaises(ExpiredSnapshotError):
            mgr.restore(s1.snapshot_id, 4)


class TestSchedule(unittest.TestCase):
    def test_schedule_roundtrip_and_verify(self):
        mgr = make_manager()
        rec = mgr.schedule("app", "0 2 * * *", 1)
        self.assertEqual(rec.schedule_id, "sch-1")
        rec.verify()

    def test_bad_cron(self):
        mgr = make_manager()
        for i, bad in enumerate(
            ("not a cron", "0 2 * *", "99 99 99 99 99", "*/x * * * *")
        ):
            with self.assertRaises(BadScheduleError, msg=bad):
                mgr.schedule("app", bad, i + 1)

    def test_duplicate_schedule(self):
        mgr = make_manager()
        mgr.schedule("app", "0 2 * * *", 1)
        with self.assertRaises(DuplicateScheduleError):
            mgr.schedule("app", "0 3 * * *", 2)

    def test_tick_advances(self):
        mgr = make_manager()
        mgr.schedule("app", "0 2 * * *", 1)
        rec = mgr.tick("app", 2)
        self.assertEqual(rec.last_tick_seq, 2)
        rec.verify()

    def test_tick_unknown_schedule(self):
        mgr = make_manager()
        with self.assertRaises(UnknownScheduleError):
            mgr.tick("ghost", 1)


class TestPrune(unittest.TestCase):
    def test_prune_keeps_last(self):
        mgr = make_manager()
        ids = [mgr.snapshot("app", i + 1).snapshot_id for i in range(3)]
        report = mgr.prune("app", 2, 4)
        self.assertEqual(report.expired_ids, (ids[0],))
        self.assertEqual(report.retained_ids, tuple(ids[1:]))
        self.assertIn(ids[0], mgr.pruned_ids())

    def test_prune_all(self):
        mgr = make_manager()
        mgr.snapshot("app", 1)
        report = mgr.prune("app", 0, 2)
        self.assertEqual(len(report.expired_ids), 1)

    def test_prune_negative(self):
        mgr = make_manager()
        with self.assertRaises(BadInputError):
            mgr.prune("app", -1, 1)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        mgr = make_manager()
        mgr.snapshot("app", 1)
        mgr.schedule("app", "0 2 * * *", 2)
        kinds = [e["kind"] for e in mgr.audit_log()]
        self.assertIn("snapshot-created", kinds)
        self.assertIn("schedule-defined", kinds)
        for e in mgr.audit_log():
            self.assertEqual(e["schema"], "audit.ndjson/1")
            self.assertEqual(e["module"], "backup-manager.v1")

    def test_audit_banned_keys(self):
        with self.assertRaises(BackupManagerError):
            backup_manager_audit_event(
                "snapshot-created", {"sources": [("a", "b")]}, 1
            )
        with self.assertRaises(BackupManagerError):
            backup_manager_audit_event("x-bad", {}, 1)

    def test_audit_no_source_leak(self):
        mgr = make_manager()
        mgr.snapshot("app", 1, sources=[("etc/secret", GOOD_DIGEST)])
        blob = str(mgr.audit_log())
        self.assertNotIn("etc/secret", blob)


class TestConcurrency(unittest.TestCase):
    def test_thread_safety(self):
        mgr = make_manager()
        errors = []

        def worker(n):
            try:
                mgr.snapshot(f"set-{n % 3}", n + 1)
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(mgr.snapshot_ids()), 12)


class TestMain(unittest.TestCase):
    def test_main_selfcheck(self):
        import backup_manager as mod

        mod.main()


if __name__ == "__main__":
    unittest.main()
