"""Targeted tests for the data sync interface."""

import ast
import unittest
from pathlib import Path

from data_sync import (
    AUDIT_SCHEMA,
    DELETED,
    LIVE,
    OPEN,
    RESOLVED,
    STRATEGY_LOCAL_WINS,
    STRATEGY_MERGE,
    STRATEGY_REMOTE_WINS,
    BadChangeError,
    BadKeyError,
    BadStrategyError,
    BadValueError,
    ConflictStateError,
    DataSync,
    DataSyncError,
    SeqOrderError,
    UnknownConflictError,
    compute_value_digest,
    data_sync_audit_event,
    DATA_SYNC_SCHEMA,
    DATA_SYNC_VERSION,
    main,
)

MODULE_PATH = Path(__file__).resolve().parent.parent / "data_sync.py"


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(DATA_SYNC_VERSION, "data-sync.v1")
        self.assertEqual(DATA_SYNC_SCHEMA, "northstar.data-sync.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")

    def test_stdlib_only(self):
        tree = ast.parse(MODULE_PATH.read_text())
        allowed = {
            "__future__", "hashlib", "json", "dataclasses",
            "threading", "typing",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)

    def test_strategy_vocabulary(self):
        self.assertEqual(
            (STRATEGY_LOCAL_WINS, STRATEGY_REMOTE_WINS, STRATEGY_MERGE),
            ("local-wins", "remote-wins", "merge"),
        )

    def test_value_digest_pins(self):
        self.assertTrue(compute_value_digest({"a": 1}).startswith("sha256:"))
        self.assertEqual(
            compute_value_digest({"a": 1}), compute_value_digest({"a": 1})
        )
        self.assertNotEqual(
            compute_value_digest({"a": 1}), compute_value_digest({"a": 2})
        )


def _remote(change_id, key, version, value, origin="remote", deleted=False):
    change = {
        "change_id": change_id,
        "key": key,
        "version": version,
        "origin": origin,
        "deleted": deleted,
    }
    if not deleted:
        change["value"] = value
    return change


class TestPut(unittest.TestCase):
    def test_put_happy_path(self):
        mgr = DataSync()
        change = mgr.put("k", {"a": 1}, seq=1)
        self.assertEqual(change.change_id, "chg-1")
        self.assertEqual(change.local_version, 1)
        self.assertFalse(change.deleted)
        self.assertTrue(change.verify())
        self.assertTrue(change.value_digest.startswith("sha256:"))

    def test_put_version_monotonic(self):
        mgr = DataSync()
        first = mgr.put("k", "v1", seq=1)
        second = mgr.put("k", "v2", seq=2)
        self.assertEqual((first.local_version, second.local_version), (1, 2))
        item = mgr.get("k")
        self.assertEqual(item.local_version, 2)
        self.assertTrue(item.verify())

    def test_delete_stages_tombstone(self):
        mgr = DataSync()
        mgr.put("k", "v", seq=1)
        tombstone = mgr.delete("k", seq=2)
        self.assertTrue(tombstone.deleted)
        self.assertTrue(tombstone.verify())
        item = mgr.get("k")
        self.assertTrue(item.deleted)

    def test_bad_keys_refused(self):
        mgr = DataSync()
        for bad in ("", 123, None, b"k"):
            with self.assertRaises(BadKeyError):
                mgr.put(bad, "v", seq=1)

    def test_bad_values_refused(self):
        mgr = DataSync()
        for bad in (1.5, 2 ** 53, -(2 ** 53), {"f": float("inf")}):
            with self.assertRaises(BadValueError):
                mgr.put("k", bad, seq=1)

    def test_seq_discipline(self):
        mgr = DataSync()
        mgr.put("k", "v", seq=1)
        with self.assertRaises(SeqOrderError):
            mgr.put("k", "v", seq=1)  # rewind
        with self.assertRaises(SeqOrderError):
            mgr.put("k", "v", seq=True)  # bool refused
        with self.assertRaises(SeqOrderError):
            mgr.put("k", "v", seq=-1)
        # failed mutations consume their seq: next valid seq is 2
        change = mgr.put("k", "v2", seq=2)
        self.assertEqual(change.local_version, 2)


class TestPush(unittest.TestCase):
    def test_push_packages_and_clears(self):
        mgr = DataSync()
        mgr.put("a", 1, seq=1)
        mgr.put("b", 2, seq=2)
        receipt = mgr.push(seq=3)
        self.assertEqual(receipt.batch_id, "batch-1")
        self.assertEqual(receipt.change_count, 2)
        self.assertEqual(receipt.change_ids, ("chg-1", "chg-2"))
        self.assertTrue(receipt.verify())
        self.assertEqual(mgr.staged_changes(), [])

    def test_empty_push_valid(self):
        mgr = DataSync()
        receipt = mgr.push(seq=1)
        self.assertEqual(receipt.change_count, 0)
        self.assertTrue(receipt.verify())


class TestPull(unittest.TestCase):
    def test_pull_new_key_adopted(self):
        mgr = DataSync()
        receipt = mgr.pull(seq=1, remote_changes=[_remote("r-1", "k", 1, "v")])
        self.assertEqual(receipt.applied[0].outcome, "adopted-new")
        self.assertTrue(receipt.verify())
        self.assertEqual(mgr.get("k").base_version, 1)

    def test_pull_fast_forward_when_local_unchanged(self):
        mgr = DataSync()
        mgr.pull(seq=1, remote_changes=[_remote("r-1", "k", 1, "v1")])
        receipt = mgr.pull(seq=2, remote_changes=[_remote("r-2", "k", 2, "v2")])
        self.assertEqual(receipt.applied[0].outcome, "adopted-fast-forward")
        self.assertEqual(mgr.get("k").base_version, 2)

    def test_pull_stale_ignored(self):
        mgr = DataSync()
        mgr.pull(seq=1, remote_changes=[_remote("r-1", "k", 5, "v")])
        receipt = mgr.pull(seq=2, remote_changes=[_remote("r-2", "k", 3, "old")])
        self.assertEqual(receipt.applied[0].outcome, "ignored-stale")

    def test_pull_identical_convergence_no_conflict(self):
        mgr = DataSync()
        mgr.put("k", "same", seq=1)
        receipt = mgr.pull(seq=2, remote_changes=[_remote("r-1", "k", 2, "same")])
        self.assertEqual(receipt.applied[0].outcome, "adopted-identical")
        self.assertEqual(mgr.open_conflicts(), [])

    def test_pull_conflict_when_both_advanced(self):
        mgr = DataSync()
        mgr.put("k", "local", seq=1)
        receipt = mgr.pull(seq=2, remote_changes=[_remote("r-1", "k", 2, "remote")])
        self.assertEqual(receipt.applied[0].outcome, "conflict")
        self.assertEqual(len(receipt.conflict_ids), 1)
        conflict = mgr.conflict(receipt.conflict_ids[0])
        self.assertEqual(conflict.status, OPEN)
        self.assertEqual(conflict.key, "k")
        self.assertTrue(conflict.verify())
        # neither side applied: local still authoritative
        self.assertEqual(mgr.get("k").base_version, 0)

    def test_pull_remote_delete_conflicts_with_local_edit(self):
        mgr = DataSync()
        mgr.put("k", "local", seq=1)
        receipt = mgr.pull(seq=2, remote_changes=[_remote("r-1", "k", 2, None, deleted=True)])
        self.assertEqual(receipt.applied[0].outcome, "conflict")

    def test_pull_duplicate_remote_id_ignored(self):
        mgr = DataSync()
        receipt = mgr.pull(
            seq=1,
            remote_changes=[
                _remote("r-1", "a", 1, "v"),
                _remote("r-1", "b", 1, "v"),
            ],
        )
        outcomes = [a.outcome for a in receipt.applied]
        self.assertEqual(outcomes, ["adopted-new", "ignored-duplicate"])

    def test_pull_bad_change_refused(self):
        mgr = DataSync()
        with self.assertRaises(BadChangeError):
            mgr.pull(seq=1, remote_changes=[{"change_id": "r-1"}])
        with self.assertRaises(BadChangeError):
            mgr.pull(seq=2, remote_changes=[
                _remote("r-2", "k", -1, "v")
            ])
        with self.assertRaises(BadChangeError):
            mgr.pull(seq=3, remote_changes="not-a-sequence")


class TestResolve(unittest.TestCase):
    def _conflicted(self):
        mgr = DataSync()
        mgr.put("k", "local", seq=1)
        receipt = mgr.pull(seq=2, remote_changes=[_remote("r-1", "k", 2, "remote")])
        return mgr, receipt.conflict_ids[0]

    def test_local_wins(self):
        mgr, conflict_id = self._conflicted()
        resolution = mgr.resolve(conflict_id, seq=3, strategy=STRATEGY_LOCAL_WINS)
        self.assertTrue(resolution.verify())
        self.assertEqual(mgr.conflict(conflict_id).status, RESOLVED)
        item = mgr.get("k")
        self.assertEqual(item.value_digest, compute_value_digest("local"))
        self.assertFalse(item.deleted)
        self.assertEqual(item.base_version, item.local_version)
        self.assertEqual(mgr.open_conflicts(), [])

    def test_remote_wins(self):
        mgr, conflict_id = self._conflicted()
        mgr.resolve(conflict_id, seq=3, strategy=STRATEGY_REMOTE_WINS)
        self.assertEqual(mgr.get("k").value_digest, compute_value_digest("remote"))

    def test_merge(self):
        mgr, conflict_id = self._conflicted()
        resolution = mgr.resolve(
            conflict_id, seq=3, strategy=STRATEGY_MERGE, merged_value="both"
        )
        self.assertTrue(resolution.verify())
        item = mgr.get("k")
        self.assertEqual(item.value_digest, compute_value_digest("both"))
        self.assertFalse(item.deleted)

    def test_merge_requires_merged_value(self):
        mgr, conflict_id = self._conflicted()
        with self.assertRaises(BadStrategyError):
            mgr.resolve(conflict_id, seq=3, strategy=STRATEGY_MERGE)

    def test_unknown_strategy_refused(self):
        mgr, conflict_id = self._conflicted()
        with self.assertRaises(BadStrategyError):
            mgr.resolve(conflict_id, seq=3, strategy="theirs-wins")

    def test_double_resolve_terminal(self):
        mgr, conflict_id = self._conflicted()
        mgr.resolve(conflict_id, seq=3, strategy=STRATEGY_LOCAL_WINS)
        with self.assertRaises(ConflictStateError):
            mgr.resolve(conflict_id, seq=4, strategy=STRATEGY_REMOTE_WINS)

    def test_unknown_conflict_refused(self):
        mgr = DataSync()
        with self.assertRaises(UnknownConflictError):
            mgr.resolve("cfl-404", seq=1, strategy=STRATEGY_LOCAL_WINS)

    def test_remote_delete_vs_local_resolve(self):
        mgr = DataSync()
        mgr.put("k", "local", seq=1)
        receipt = mgr.pull(seq=2, remote_changes=[_remote("r-1", "k", 2, None, deleted=True)])
        conflict_id = receipt.conflict_ids[0]
        mgr.resolve(conflict_id, seq=3, strategy=STRATEGY_REMOTE_WINS)
        item = mgr.get("k")
        self.assertTrue(item.deleted)


class TestStateAndAudit(unittest.TestCase):
    def test_audit_summary(self):
        mgr = DataSync()
        mgr.put("a", 1, seq=1)
        mgr.push(seq=2)
        summary = mgr.audit(seq=3)
        self.assertEqual(summary["item_count"], 1)
        self.assertEqual(summary["staged_count"], 0)
        self.assertEqual(summary["pushed_count"], 1)
        self.assertEqual(summary["open_conflict_count"], 0)
        self.assertTrue(summary["state_digest"].startswith("sha256:"))

    def test_audit_event_shapes(self):
        event = data_sync_audit_event("sync.pushed", 1, batch_id="batch-1")
        self.assertEqual(event["schema"], AUDIT_SCHEMA)
        self.assertEqual(event["module_version"], DATA_SYNC_VERSION)
        self.assertEqual(event["detail"]["batch_id"], "batch-1")
        with self.assertRaises(DataSyncError):
            data_sync_audit_event("bogus-kind", 1)

    def test_audit_log_no_values(self):
        mgr = DataSync()
        mgr.put("k", "supersecret", seq=1)
        log = mgr.audit_log()
        blob = str(log)
        self.assertIn("sync.staged", blob)
        self.assertNotIn("supersecret", blob)

    def test_main_self_check(self):
        self.assertIsNone(main())


if __name__ == "__main__":
    unittest.main()
