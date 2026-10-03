"""Tests for claim-check (blob area) and event schema migration.

Claim-check: payloads at or above 64 KiB never go inline into the JSONL
history or the ledger sidecar. They are stored once in the
content-addressed ``<events>.blobs/`` area and referenced by ``blob_ref``;
fold/replay fetches them on demand. Missing or corrupt blobs are
fail-closed, never silent.

Schema migration: the event schema moved v1 -> v2 (added ``blob_ref``).
Histories written by v1 migrate in-memory before fold; unknown revisions
are rejected.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
if str(COMPONENT_ROOT) not in sys.path:
    sys.path.insert(0, str(COMPONENT_ROOT))

from blob_store import CLAIM_CHECK_THRESHOLD_BYTES, BlobStore
from durable_contract import (
    EVENT_SCHEMA_VERSION,
    EVENT_SCHEMA_VERSION_V1,
    EventContract,
    RunContract,
)
from event_migration import migrate_event_dict
from event_store import EventStore
from runner import DurableRunner
from tool_ledger import ToolEffectLedger


def _make_run(run_id="run-claimcheck-001", deadline_at=2000):
    return RunContract.from_dict(
        {
            "schema_version": "northstar.durable-run.v1",
            "task_id": "task-001",
            "thread_id": "thread-001",
            "run_id": run_id,
            "parent_run_id": None,
            "status": "planned",
            "deadline_at": deadline_at,
            "scope_snapshot": ["workspace:read", "workspace:write"],
            "trace_id": "trace-001",
        }
    )


def _v1_event_dict(*, event_id, sequence, event_type, status, step_id="__run__"):
    """A hand-built v1 event dict: 13 fields, no blob_ref."""
    return {
        "schema_version": EVENT_SCHEMA_VERSION_V1,
        "event_id": event_id,
        "task_id": "task-001",
        "thread_id": "thread-001",
        "run_id": "run-claimcheck-001",
        "step_id": step_id,
        "sequence": sequence,
        "event_type": event_type,
        "status": status,
        "occurred_at": 100 + sequence,
        "idempotency_key": f"key-{sequence}",
        "trace_id": "trace-001",
        "payload_digest": "sha256:" + "0" * 64,
    }


def _write_jsonl(path, dicts):
    with open(path, "w", encoding="utf-8") as stream:
        for value in dicts:
            stream.write(
                json.dumps(value, ensure_ascii=False, sort_keys=True,
                           separators=(",", ":")) + "\n"
            )


class BlobStoreTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name) / "events.jsonl.blobs"
        self.blobs = BlobStore(self.root)

    def test_put_get_round_trip(self):
        ref = self.blobs.put(b"hello")
        self.assertTrue(ref.startswith("sha256:"))
        self.assertEqual(self.blobs.get(ref), b"hello")

    def test_put_is_idempotent(self):
        ref1 = self.blobs.put(b"same bytes")
        ref2 = self.blobs.put(b"same bytes")
        self.assertEqual(ref1, ref2)
        self.assertEqual(len(list(self.root.iterdir())), 1)

    def test_root_created_lazily(self):
        self.assertFalse(self.root.exists())

    def test_missing_blob_fails_closed(self):
        ref = "sha256:" + "ab" * 32
        with self.assertRaisesRegex(ValueError, "missing"):
            self.blobs.get(ref)

    def test_corrupt_blob_fails_closed(self):
        ref = self.blobs.put(b"original")
        (self.root / ref).write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "corrupt"):
            self.blobs.get(ref)

    def test_invalid_ref_rejected(self):
        with self.assertRaisesRegex(ValueError, "blob_ref"):
            self.blobs.get("not-a-digest")

    def test_put_rejects_non_bytes(self):
        with self.assertRaises(ValueError):
            self.blobs.put("text")

    def test_no_temp_files_left_behind(self):
        self.blobs.put(b"x" * 100)
        leftovers = [p for p in self.root.iterdir() if p.name.startswith("blob.")]
        self.assertEqual(leftovers, [])


class EventMigrationTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.events_path = Path(self.tempdir.name) / "events.jsonl"

    def test_v1_history_migrates_on_read(self):
        _write_jsonl(
            self.events_path,
            [
                _v1_event_dict(event_id="event-000001", sequence=1,
                               event_type="run.created", status="planned"),
                _v1_event_dict(event_id="event-000002", sequence=2,
                               event_type="run.started", status="running"),
            ],
        )
        store = EventStore(self.events_path)
        events = store.read_history("run-claimcheck-001")
        self.assertEqual(len(events), 2)
        for event in events:
            self.assertEqual(event.schema_version, EVENT_SCHEMA_VERSION)
            self.assertIsNone(event.blob_ref)
        # Fold runs on the migrated events.
        state = store.derive_state("run-claimcheck-001")
        self.assertEqual(state["status"], "running")
        self.assertEqual(state["sequence"], 2)

    def test_migrate_event_dict_adds_blob_ref_none(self):
        migrated = migrate_event_dict(
            _v1_event_dict(event_id="event-000001", sequence=1,
                           event_type="run.created", status="planned")
        )
        self.assertEqual(migrated["schema_version"], EVENT_SCHEMA_VERSION)
        self.assertIsNone(migrated["blob_ref"])
        self.assertEqual(len(migrated), 14)

    def test_unknown_schema_version_fails_closed(self):
        value = _v1_event_dict(event_id="event-000001", sequence=1,
                               event_type="run.created", status="planned")
        value["schema_version"] = "northstar.durable-event.v99"
        with self.assertRaisesRegex(ValueError, "no upcaster"):
            EventContract.from_dict(value)

    def test_migration_does_not_mask_invalid_content(self):
        value = _v1_event_dict(event_id="event-000001", sequence=1,
                               event_type="run.created", status="bogus")
        with self.assertRaises(ValueError):
            EventContract.from_dict(value)

    def test_migrate_rejects_non_object(self):
        with self.assertRaises(ValueError):
            migrate_event_dict(["not", "an", "object"])

    def test_v2_blob_ref_must_be_a_digest(self):
        value = _v1_event_dict(event_id="event-000001", sequence=1,
                               event_type="run.created", status="planned")
        migrated = migrate_event_dict(value)
        migrated["blob_ref"] = "garbage"
        with self.assertRaisesRegex(ValueError, "blob_ref"):
            EventContract.from_dict(migrated)

    def test_new_writes_use_v2(self):
        store = EventStore(self.events_path)
        runner = DurableRunner(
            _make_run(), store,
            lease_path=Path(self.tempdir.name) / "run.lease.json",
        )
        runner._append(
            event_type="run.created", status="planned", step_id="__run__",
            idempotency_key="k1", now=100, payload={"hello": "world"},
        )
        events = store.read_history("run-claimcheck-001")
        self.assertEqual(events[0].schema_version, EVENT_SCHEMA_VERSION)
        self.assertIsNone(events[0].blob_ref)


class EventClaimCheckTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.events_path = Path(self.tempdir.name) / "events.jsonl"
        self.store = EventStore(self.events_path)
        self.runner = DurableRunner(
            _make_run(), self.store,
            lease_path=Path(self.tempdir.name) / "run.lease.json",
        )
        self.runner._append(
            event_type="run.created", status="planned", step_id="__run__",
            idempotency_key="k1", now=100, payload={"hello": "world"},
        )

    def _big_payload(self):
        return {"transcript": "x" * (CLAIM_CHECK_THRESHOLD_BYTES + 1024)}

    def test_large_payload_is_claim_checked(self):
        payload = self._big_payload()
        self.runner._append(
            event_type="run.started", status="running", step_id="__run__",
            idempotency_key="k2", now=101, payload=payload,
        )
        events = self.store.read_history("run-claimcheck-001")
        event = events[1]
        self.assertIsNotNone(event.blob_ref)
        # The blob is named by its content: ref equals the payload digest.
        self.assertEqual(event.blob_ref, event.payload_digest)
        # The JSONL history itself stays small.
        for line in self.events_path.read_text(encoding="utf-8").splitlines():
            self.assertLess(len(line.encode("utf-8")), CLAIM_CHECK_THRESHOLD_BYTES)
        # Fold-time fetch returns the original bytes.
        raw = self.store.read_blob(event)
        self.assertEqual(
            json.loads(raw.decode("utf-8")), json.loads(json.dumps(payload))
        )

    def test_small_payload_has_no_blob_ref(self):
        self.runner._append(
            event_type="run.started", status="running", step_id="__run__",
            idempotency_key="k2", now=101, payload={"small": True},
        )
        events = self.store.read_history("run-claimcheck-001")
        self.assertIsNone(events[1].blob_ref)
        self.assertFalse(
            (self.events_path.parent / (self.events_path.name + ".blobs")).exists()
        )

    def test_read_blob_none_when_no_ref(self):
        events = self.store.read_history("run-claimcheck-001")
        self.assertIsNone(self.store.read_blob(events[0]))

    def test_missing_blob_fails_closed(self):
        payload = self._big_payload()
        self.runner._append(
            event_type="run.started", status="running", step_id="__run__",
            idempotency_key="k2", now=101, payload=payload,
        )
        event = self.store.read_history("run-claimcheck-001")[1]
        blob_path = self.store.blob_store.root / event.blob_ref
        blob_path.unlink()
        with self.assertRaisesRegex(ValueError, "missing"):
            self.store.read_blob(event)

    def test_corrupt_blob_fails_closed(self):
        self.runner._append(
            event_type="run.started", status="running", step_id="__run__",
            idempotency_key="k2", now=101, payload=self._big_payload(),
        )
        event = self.store.read_history("run-claimcheck-001")[1]
        blob_path = self.store.blob_store.root / event.blob_ref
        blob_path.write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "corrupt"):
            self.store.read_blob(event)

    def test_threshold_boundary(self):
        # Exactly at the threshold: claim-checked (>= is forced).
        payload = {"pad": "y" * CLAIM_CHECK_THRESHOLD_BYTES}
        self.runner._append(
            event_type="run.started", status="running", step_id="__run__",
            idempotency_key="k2", now=101, payload=payload,
        )
        event = self.store.read_history("run-claimcheck-001")[1]
        self.assertIsNotNone(event.blob_ref)


class LedgerClaimCheckTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.events_path = Path(self.tempdir.name) / "events.jsonl"
        self.ledger_path = Path(self.tempdir.name) / "events.jsonl.ledger.json"
        self.store = EventStore(self.events_path)
        self.run_id = "run-claimcheck-ledger"

    def _ledger(self, ledger_path=None):
        def append(*, event_type, status, step_id, idempotency_key, now, payload):
            history = self.store.read_history(self.run_id)
            self.store.append_event(
                EventContract.from_dict(
                    {
                        "schema_version": EVENT_SCHEMA_VERSION,
                        "event_id": f"event-{len(history) + 1:06d}",
                        "task_id": "task-001",
                        "thread_id": "thread-001",
                        "run_id": self.run_id,
                        "step_id": step_id,
                        "sequence": len(history) + 1,
                        "event_type": event_type,
                        "status": status,
                        "occurred_at": now,
                        "idempotency_key": idempotency_key,
                        "trace_id": "trace-001",
                        "payload_digest": "sha256:" + "0" * 64,
                        "blob_ref": None,
                    }
                )
            )

        return ToolEffectLedger(
            self.store,
            run_id=self.run_id,
            ledger_path=ledger_path or self.ledger_path,
            append=append,
        )

    def _seed_run_created(self):
        history = []
        self.store.append_event(
            EventContract.from_dict(
                {
                    "schema_version": EVENT_SCHEMA_VERSION,
                    "event_id": "event-000001",
                    "task_id": "task-001",
                    "thread_id": "thread-001",
                    "run_id": self.run_id,
                    "step_id": "__run__",
                    "sequence": 1,
                    "event_type": "run.created",
                    "status": "planned",
                    "occurred_at": 100,
                    "idempotency_key": "run-key",
                    "trace_id": "trace-001",
                    "payload_digest": "sha256:" + "0" * 64,
                    "blob_ref": None,
                }
            )
        )
        return history

    def test_large_result_goes_to_blob_area(self):
        self._seed_run_created()
        ledger = self._ledger()
        big = {"data": "z" * (CLAIM_CHECK_THRESHOLD_BYTES + 512)}
        calls = []

        def fn(key):
            calls.append(key)
            return big

        result = ledger.run_tool(
            step_id="s1", tool_call_id="bigtool", fn=fn, now=100,
            idempotency_key="idem-big-1",
        )
        self.assertEqual(result, big)
        self.assertEqual(calls, ["idem-big-1"])

        entry = json.loads(self.ledger_path.read_text(encoding="utf-8"))["results"]["bigtool"]
        self.assertFalse(entry["result_inline"])
        self.assertIsNone(entry["result"])
        self.assertTrue(entry["blob_ref"].startswith("sha256:"))
        # The sidecar JSON stays small.
        self.assertLess(
            len(self.ledger_path.read_bytes()), CLAIM_CHECK_THRESHOLD_BYTES
        )

    def test_large_result_replays_from_blob(self):
        self._seed_run_created()
        ledger = self._ledger()
        big = {"data": "z" * (CLAIM_CHECK_THRESHOLD_BYTES + 512)}
        ledger.run_tool(
            step_id="s1", tool_call_id="bigtool", fn=lambda key: big, now=100,
            idempotency_key="idem-big-1",
        )
        # A fresh ledger (empty sidecar cache is impossible — the sidecar is
        # shared; simulate resume by re-reading through a new instance).
        ledger2 = self._ledger()
        found, result = ledger2.replay_result("bigtool")
        self.assertTrue(found)
        self.assertEqual(result, big)

    def test_missing_blob_replay_fails_closed(self):
        self._seed_run_created()
        ledger = self._ledger()
        big = {"data": "z" * (CLAIM_CHECK_THRESHOLD_BYTES + 512)}
        ledger.run_tool(
            step_id="s1", tool_call_id="bigtool", fn=lambda key: big, now=100,
            idempotency_key="idem-big-1",
        )
        entry = json.loads(self.ledger_path.read_text(encoding="utf-8"))["results"]["bigtool"]
        (self.store.blob_store.root / entry["blob_ref"]).unlink()
        with self.assertRaisesRegex(ValueError, "unrecoverable"):
            self._ledger().replay_result("bigtool")

    def test_completed_large_result_needs_no_receiver(self):
        self._seed_run_created()
        ledger = self._ledger()
        big = {"data": "z" * (CLAIM_CHECK_THRESHOLD_BYTES + 512)}
        ledger.run_tool(
            step_id="s1", tool_call_id="bigtool", fn=lambda key: big, now=100,
            idempotency_key="idem-big-1",
        )
        # No receiver at all: the blob area is the recovery path.
        calls = []
        returned = self._ledger().run_tool(
            step_id="s1", tool_call_id="bigtool",
            fn=lambda key: calls.append(key) or {"should": "not run"},
            now=200, idempotency_key="idem-big-1", receiver=None,
        )
        self.assertEqual(returned, big)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
