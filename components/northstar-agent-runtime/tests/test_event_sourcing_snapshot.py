"""Tests for event_sourcing snapshots: pin derived state, replay the tail."""

import ast
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from event_sourcing import (
    EVENT_SOURCING_VERSION,
    GENESIS_HEAD,
    SCHEMA_PIN,
    DuplicateSnapshotError,
    Event,
    EventStore,
    ReplayError,
    SnapshotError,
    SnapshotRecord,
    event_audit_event,
    replay,
    snapshot_audit_event,
)

_HERE = Path(__file__).resolve().parents[1] / "event_sourcing.py"


def _mk(seq, event_id=None, event_type="test.happened", payload=None,
        prev_head=GENESIS_HEAD):
    return Event(event_id or f"e{seq}", event_type,
                 payload if payload is not None else {"n": seq}, seq,
                 prev_head=prev_head)


def _store3():
    """Store with e0/e1/e2 chained, seqs 0/1/2."""
    store = EventStore()
    e0 = _mk(0)
    e1 = _mk(1, prev_head=e0.digest)
    e2 = _mk(2, prev_head=e1.digest)
    store.append(e0)
    store.append(e1)
    store.append(e2)
    return store, (e0, e1, e2)


def _handlers():
    return {
        "test.happened": lambda state, payload: (state or 0) + payload["n"],
    }


class TestSnapshotRecord(unittest.TestCase):
    def test_version_pins_unchanged(self):
        self.assertEqual(EVENT_SOURCING_VERSION, "event-sourcing.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.event-sourcing.v1")

    def test_record_roundtrip(self):
        store, (e0, e1, e2) = _store3()
        rec = store.snapshot({"balance": 100})
        self.assertEqual(rec.at_seq, 2)
        self.assertEqual(rec.state, {"balance": 100})
        self.assertEqual(rec.head_digest, e2.digest)
        self.assertTrue(rec.state_digest.startswith("sha256:"))
        self.assertEqual(len(rec.state_digest), 71)

    def test_digest_deterministic(self):
        a = SnapshotRecord(1, {"x": 1}, GENESIS_HEAD)
        b = SnapshotRecord(1, {"x": 1}, GENESIS_HEAD)
        self.assertEqual(a.state_digest, b.state_digest)

    def test_digest_covers_head(self):
        a = SnapshotRecord(1, {"x": 1}, GENESIS_HEAD)
        e = _mk(0)
        b = SnapshotRecord(1, {"x": 1}, e.digest)
        self.assertNotEqual(a.state_digest, b.state_digest)

    def test_frozen(self):
        rec = SnapshotRecord(1, {"x": 1}, GENESIS_HEAD)
        with self.assertRaises(Exception):
            rec.at_seq = 99  # type: ignore

    def test_verify_ok(self):
        rec = SnapshotRecord(1, {"x": [1, 2], "y": None}, GENESIS_HEAD)
        self.assertTrue(rec.verify())

    def test_state_normalized_not_aliased(self):
        mutable = {"items": [1, 2]}
        rec = SnapshotRecord(1, mutable, GENESIS_HEAD)
        mutable["items"].append(3)
        self.assertEqual(rec.state, {"items": [1, 2]})

    def test_bool_is_not_int_in_pin(self):
        a = SnapshotRecord(1, {"flag": True}, GENESIS_HEAD)
        b = SnapshotRecord(1, {"flag": 1}, GENESIS_HEAD)
        self.assertNotEqual(a.state_digest, b.state_digest)

    def test_bad_state_refused(self):
        bad_states = [
            object(),
            {1: "non-str-key"},
            {"f": float("inf")},
            {"f": float("nan")},
            {"n": 2**53},
            {"n": -(2**53)},
            {"nested": [{"deep": {"bad": object()}}]},
        ]
        for bad in bad_states:
            with self.assertRaises(SnapshotError, msg=repr(bad)):
                SnapshotRecord(1, bad, GENESIS_HEAD)

    def test_bad_at_seq_refused(self):
        for bad in (-1, True, "1", 1.0):
            with self.assertRaises((TypeError, ValueError), msg=repr(bad)):
                SnapshotRecord(bad, {}, GENESIS_HEAD)

    def test_bad_head_refused(self):
        with self.assertRaises((TypeError, ValueError)):
            SnapshotRecord(1, {}, "not-a-digest")

    def test_as_dict_schema(self):
        rec = SnapshotRecord(1, {"x": 1}, GENESIS_HEAD)
        d = rec.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["kind"], "snapshot")
        self.assertEqual(d["at_seq"], 1)
        self.assertIn("state_digest", d)

    def test_stdlib_only(self):
        tree = ast.parse(_HERE.read_text())
        allowed = {"hashlib", "threading", "dataclasses", "typing",
                   "canonical_json", "json", "__future__"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestStoreSnapshot(unittest.TestCase):
    def test_snapshot_books_through_head(self):
        store, (e0, e1, e2) = _store3()
        rec = store.snapshot({"n": 6})
        self.assertEqual(rec.at_seq, 2)
        self.assertEqual(rec.head_digest, store.head())
        self.assertTrue(rec.verify())

    def test_empty_store_refused(self):
        with self.assertRaises(SnapshotError):
            EventStore().snapshot({"n": 1})

    def test_duplicate_at_seq_refused(self):
        store, _ = _store3()
        store.snapshot({"n": 1})
        with self.assertRaises(DuplicateSnapshotError):
            store.snapshot({"n": 2})

    def test_newer_at_seq_allowed(self):
        store, (e0, e1, e2) = _store3()
        store.snapshot({"n": 1})
        e3 = _mk(3, prev_head=e2.digest)
        store.append(e3)
        rec = store.snapshot({"n": 2})
        self.assertEqual(rec.at_seq, 3)

    def test_snapshots_sorted(self):
        store, (e0, e1, e2) = _store3()
        store.snapshot({"a": 1})
        e3 = _mk(3, prev_head=e2.digest)
        store.append(e3)
        store.snapshot({"a": 2})
        seqs = [s.at_seq for s in store.snapshots()]
        self.assertEqual(seqs, [2, 3])

    def test_latest_snapshot_none_when_empty(self):
        self.assertIsNone(EventStore().latest_snapshot())

    def test_latest_snapshot(self):
        store, (e0, e1, e2) = _store3()
        first = store.snapshot({"a": 1})
        e3 = _mk(3, prev_head=e2.digest)
        store.append(e3)
        second = store.snapshot({"a": 2})
        self.assertEqual(store.latest_snapshot(), second)
        self.assertNotEqual(store.latest_snapshot(), first)


class TestReplayFrom(unittest.TestCase):
    def test_replay_from_folds_only_tail(self):
        store, (e0, e1, e2) = _store3()
        base = store.snapshot(6)  # sum of n=0+1+2
        e3 = _mk(3, payload={"n": 10}, prev_head=e2.digest)
        store.append(e3)
        resumed = store.replay_from(base, _handlers())
        self.assertEqual(resumed, 16)

    def test_replay_from_matches_full_replay(self):
        store = EventStore()
        e0 = _mk(0)
        e1 = _mk(1, prev_head=e0.digest)
        store.append(e0)
        store.append(e1)
        partial = replay(store.events(), _handlers())
        base = store.snapshot(partial)
        e2 = _mk(2, prev_head=e1.digest)
        store.append(e2)
        self.assertEqual(store.replay_from(base, _handlers()),
                         replay(store.events(), _handlers()))

    def test_replay_from_latest(self):
        store, (e0, e1, e2) = _store3()
        store.snapshot(replay(store.events()[:2], _handlers()))
        e3 = _mk(3, payload={"n": 5}, prev_head=e2.digest)
        store.append(e3)
        self.assertEqual(store.replay_from_latest(_handlers()), 6)

    def test_replay_from_latest_no_snapshot_refused(self):
        store, _ = _store3()
        with self.assertRaises(SnapshotError):
            store.replay_from_latest(_handlers())

    def test_replay_from_unknown_snapshot_refused(self):
        store, (e0, e1, e2) = _store3()
        store.snapshot({"n": 1})
        forged = SnapshotRecord(2, {"n": 999}, e2.digest)
        with self.assertRaises(SnapshotError):
            store.replay_from(forged, _handlers())

    def test_replay_from_non_record_refused(self):
        store, _ = _store3()
        with self.assertRaises(TypeError):
            store.replay_from({"at_seq": 2}, _handlers())

    def test_replay_from_missing_handler_raises(self):
        store, (e0, e1, e2) = _store3()
        base = store.snapshot(6)
        e3 = _mk(3, prev_head=e2.digest)
        store.append(e3)
        with self.assertRaises(ReplayError):
            store.replay_from(base, {})


class TestSnapshotAudit(unittest.TestCase):
    def test_audit_shape(self):
        store, _ = _store3()
        rec = store.snapshot({"n": 1})
        row = snapshot_audit_event(rec, 9)
        self.assertEqual(row["schema"], "audit.ndjson/1")
        self.assertEqual(row["module"], SCHEMA_PIN)
        self.assertEqual(row["outcome"], "snapshotted")
        self.assertEqual(row["snapshot_at_seq"], 2)
        self.assertEqual(row["state_digest"], rec.state_digest)
        self.assertEqual(row["head_digest"], rec.head_digest)
        self.assertEqual(row["audit_seq"], 9)
        self.assertNotIn("state", row)

    def test_audit_bad_record_refused(self):
        with self.assertRaises(TypeError):
            snapshot_audit_event({"at_seq": 1}, 1)

    def test_audit_bad_seq_refused(self):
        store, _ = _store3()
        rec = store.snapshot({"n": 1})
        for bad in (-1, True, "9"):
            with self.assertRaises((TypeError, ValueError), msg=repr(bad)):
                snapshot_audit_event(rec, bad)

    def test_event_audit_kinds_still_intact(self):
        store, (e0, _, _) = _store3()
        row = event_audit_event(e0, "appended", 1)
        self.assertEqual(row["outcome"], "appended")


class TestMainSelfCheck(unittest.TestCase):
    def test_main_subprocess(self):
        proc = subprocess.run(
            [sys.executable, str(_HERE)],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("snapshot", proc.stdout)


if __name__ == "__main__":
    unittest.main()
