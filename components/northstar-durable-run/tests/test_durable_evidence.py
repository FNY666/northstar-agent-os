"""Integration tests for DurableRunner's optional hash-linked evidence sink."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ROOT = COMPONENT_ROOT.parent / "northstar-run-contract"
EVIDENCE_ROOT = COMPONENT_ROOT.parent / "northstar-run-evidence"
for root in (COMPONENT_ROOT, CONTRACT_ROOT, EVIDENCE_ROOT):
    sys.path.insert(0, str(root))

from durable_audit import DurableEvidenceSink  # noqa: E402
from durable_contract import RunContract  # noqa: E402
from event_store import EventStore  # noqa: E402
from evidence_store import EvidenceStore  # noqa: E402
from runner import DurableRunner, StepPlan  # noqa: E402


RUN = RunContract.from_dict(
    {
        "schema_version": "northstar.durable-run.v1",
        "task_id": "task-001",
        "thread_id": "thread-001",
        "run_id": "run-001",
        "parent_run_id": None,
        "status": "planned",
        "deadline_at": 2_000,
        "scope_snapshot": ["workspace:read", "workspace:write"],
        "trace_id": "trace-001",
    }
)


class DurableEvidenceIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.events = EventStore(self.root / "events.jsonl")
        self.evidence = EvidenceStore(self.root / "evidence.jsonl", "run-001")
        self.sink = DurableEvidenceSink(
            self.evidence, artifact_store=self.events.blob_store
        )

    def make_runner(self, sink=None):
        return DurableRunner(
            RUN,
            self.events,
            lease_path=self.root / "run.lease.json",
            lease_ttl_seconds=20,
            evidence_sink=self.sink if sink is None else sink,
        )

    @staticmethod
    def plan():
        return StepPlan(
            step_id="work",
            input_payload={"action": "write", "path": "result.txt"},
            scope_snapshot=["workspace:write"],
            expected_postconditions=["result_exists"],
            action=lambda key: {"ok": True, "idempotency_key": key},
        )

    def test_runner_mirrors_each_event_and_binds_payload_blob(self):
        runner = self.make_runner()
        state = runner.execute([self.plan()], owner_id="worker-a", now=100)
        self.assertEqual(state["status"], "finished")

        events = self.events.read_history("run-001")
        entries = self.evidence.entries
        self.assertEqual(len(entries), len(events))
        self.assertEqual(self.sink.last_sequence, len(events))
        for event, entry in zip(events, entries):
            self.assertEqual(entry.sequence, event.sequence)
            self.assertEqual(entry.source, "northstar-durable-run")
            self.assertEqual(entry.source_id, f"durable-event-{event.sequence}")
            self.assertEqual(entry.kind, f"durable.{event.event_type}")
            self.assertIsNotNone(event.blob_ref)
            refs = {ref.kind: ref for ref in entry.refs}
            self.assertEqual(set(refs), {"durable-payload", "durable-subject"})
            self.assertEqual(refs["durable-payload"].ref_id, event.event_id)
            self.assertEqual(refs["durable-payload"].digest, event.blob_ref)
            subject_bytes = self.events.blob_store.get(refs["durable-subject"].digest)
            self.assertIn(event.event_id.encode(), subject_bytes)
            payload = self.events.read_blob(event)
            self.assertIsInstance(payload, bytes)
            digest = "sha256:" + hashlib.sha256(payload).hexdigest()
            self.assertEqual(digest, event.payload_digest)
            self.assertEqual(digest, event.blob_ref)

    def test_new_runner_repairs_event_persisted_before_evidence_append(self):
        class FailingSink(DurableEvidenceSink):
            def append_event(self, event, *, payload_bytes=None):
                raise RuntimeError("simulated evidence sink outage")

        failing_sink = FailingSink(self.evidence, artifact_store=self.events.blob_store)
        runner = self.make_runner(failing_sink)
        with self.assertRaisesRegex(RuntimeError, "sink outage"):
            runner.prepare(owner_id="worker-a", now=100)

        persisted = self.events.read_history("run-001")
        self.assertGreaterEqual(len(persisted), 1)
        self.assertEqual(self.evidence.entry_count, 0)

        recovered_sink = DurableEvidenceSink(
            self.evidence, artifact_store=self.events.blob_store
        )
        self.make_runner(recovered_sink)
        self.assertEqual(recovered_sink.last_sequence, len(persisted))
        self.assertEqual(self.evidence.entry_count, len(persisted))
        for event, entry in zip(persisted, self.evidence.entries):
            refs = {ref.kind: ref for ref in entry.refs}
            self.assertEqual(refs["durable-payload"].digest, event.blob_ref)
            self.assertIn("durable-subject", refs)
            payload = self.events.read_blob(event)
            digest = "sha256:" + hashlib.sha256(payload).hexdigest()
            self.assertEqual(digest, event.payload_digest)

    def test_sink_recovers_legacy_events_without_payload_blobs(self):
        legacy_runner = DurableRunner(
            RUN,
            self.events,
            lease_path=self.root / "run.lease.json",
            lease_ttl_seconds=20,
        )
        legacy_runner.prepare(owner_id="worker-a", now=100)
        history = self.events.read_history("run-001")
        self.assertTrue(history)
        self.assertTrue(all(event.blob_ref is None for event in history))

        recovered_sink = DurableEvidenceSink(
            self.evidence, artifact_store=self.events.blob_store
        )
        self.make_runner(recovered_sink)
        self.assertEqual(recovered_sink.last_sequence, len(history))
        for event, entry in zip(history, self.evidence.entries):
            refs = {ref.kind: ref for ref in entry.refs}
            self.assertEqual(set(refs), {"durable-subject"})
            subject = json.loads(
                self.events.blob_store.get(refs["durable-subject"].digest)
            )
            self.assertEqual(
                subject["payload"],
                {
                    "available": False,
                    "blob_ref": None,
                    "digest": event.payload_digest,
                },
            )

    def test_corrupt_reused_subject_blob_is_rejected_before_ledger_append(self):
        runner = self.make_runner()
        payload = b'{"ok":true}'
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        self.events.blob_store.put(payload)
        event = runner._event(
            event_id="event-000001",
            sequence=1,
            event_type="run.created",
            status="planned",
            step_id="run",
            idempotency_key="run-001:create",
            occurred_at=100,
            payload_digest=digest,
            blob_ref=digest,
        )
        original_put = self.events.blob_store.put

        def corrupt_subject_blob(data):
            ref = original_put(data)
            if data != payload:
                (self.events.blob_store.root / ref).write_bytes(b"tampered")
            return ref

        with patch.object(self.events.blob_store, "put", side_effect=corrupt_subject_blob):
            with self.assertRaisesRegex(ValueError, "corrupt"):
                self.sink.append_event(event, payload_bytes=payload)
        self.assertEqual(self.evidence.entry_count, 0)


if __name__ == "__main__":
    unittest.main()
