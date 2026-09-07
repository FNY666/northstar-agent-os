import hashlib
import json
import multiprocessing
import sys
import tempfile
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMPONENT_ROOT))

from durable_contract import EventContract  # noqa: E402
from event_store import EventStore  # noqa: E402


BASE_EVENT = {
    "schema_version": "northstar.durable-event.v1",
    "event_id": "event-001",
    "task_id": "task-001",
    "thread_id": "thread-001",
    "run_id": "run-001",
    "step_id": "__run__",
    "sequence": 1,
    "event_type": "run.created",
    "status": "planned",
    "occurred_at": 1_000,
    "idempotency_key": "run-001-created-1",
    "trace_id": "trace-001",
    "payload_digest": "sha256:" + "1" * 64,
}


def event(**changes):
    value = dict(BASE_EVENT)
    value.update(changes)
    return EventContract.from_dict(value)


def append_event_in_process(path, barrier):
    store = EventStore(path)
    barrier.wait(timeout=10)
    store.append_event(event())


class EventStoreTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tempdir.name) / "events.jsonl"
        self.store = EventStore(self.path)

    def tearDown(self):
        self.tempdir.cleanup()

    def test_append_and_read_history_preserve_canonical_events(self):
        first = event()
        second = event(
            event_id="event-002",
            sequence=2,
            event_type="run.started",
            status="running",
            occurred_at=1_001,
            idempotency_key="run-001-started-1",
            payload_digest="sha256:" + "2" * 64,
        )
        self.assertEqual(self.store.append_event(first), first)
        self.assertEqual(self.store.append_event(second), second)
        history = self.store.read_history("run-001")
        self.assertEqual(history, [first, second])
        lines = self.path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[0]), first.to_dict())
        self.assertEqual(json.loads(lines[1]), second.to_dict())

    def test_append_is_idempotent_for_same_key_and_rejects_conflict(self):
        first = event()
        self.assertEqual(self.store.append_event(first), first)
        self.assertEqual(self.store.append_event(first), first)
        conflict = event(payload_digest="sha256:" + "9" * 64)
        with self.assertRaises(ValueError):
            self.store.append_event(conflict)
        self.assertEqual(len(self.store.read_history("run-001")), 1)

    def test_concurrent_idempotent_append_is_serialized_by_stream_lock(self):
        if "fork" not in multiprocessing.get_all_start_methods():
            self.skipTest("process locking test requires fork")
        context = multiprocessing.get_context("fork")
        barrier = context.Barrier(2)
        processes = [
            context.Process(target=append_event_in_process, args=(str(self.path), barrier))
            for _ in range(2)
        ]
        for process in processes:
            process.start()
        for process in processes:
            process.join(timeout=10)
        self.assertTrue(all(process.exitcode == 0 for process in processes))
        self.assertEqual(self.store.read_history("run-001"), [event()])
        self.assertTrue(self.path.with_name("events.jsonl.lock").exists())

    def test_append_rejects_sequence_gaps_duplicates_and_cross_run_history(self):
        self.store.append_event(event())
        gap = event(
            event_id="event-003",
            sequence=3,
            event_type="run.started",
            status="running",
            idempotency_key="run-001-started-3",
            payload_digest="sha256:" + "3" * 64,
        )
        with self.assertRaises(ValueError):
            self.store.append_event(gap)

        duplicate_sequence = event(
            event_id="event-002",
            sequence=1,
            idempotency_key="run-001-created-duplicate",
            payload_digest="sha256:" + "4" * 64,
        )
        with self.assertRaises(ValueError):
            self.store.append_event(duplicate_sequence)

        other_run = event(
            event_id="event-other",
            task_id="task-other",
            thread_id="thread-other",
            run_id="run-other",
            step_id="__run__",
            idempotency_key="run-other-created-1",
        )
        with self.assertRaises(ValueError):
            self.store.append_event(other_run)

    def test_append_rejects_invalid_json_lines_and_does_not_continue_after_corruption(self):
        self.path.write_text("not-json\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.store.read_history("run-001")
        with self.assertRaises(ValueError):
            self.store.append_event(event())

    def test_derive_state_applies_run_lifecycle_and_step_statuses(self):
        self.store.append_event(event())
        self.store.append_event(
            event(
                event_id="event-002",
                sequence=2,
                event_type="run.started",
                status="running",
                occurred_at=1_001,
                idempotency_key="run-001-started-1",
                payload_digest="sha256:" + "2" * 64,
            )
        )
        self.store.append_event(
            event(
                event_id="event-003",
                step_id="planner",
                sequence=3,
                event_type="step.started",
                status="running",
                occurred_at=1_002,
                idempotency_key="run-001-planner-started-1",
                payload_digest="sha256:" + "3" * 64,
            )
        )
        self.store.append_event(
            event(
                event_id="event-004",
                step_id="planner",
                sequence=4,
                event_type="step.finished",
                status="finished",
                occurred_at=1_003,
                idempotency_key="run-001-planner-finished-1",
                payload_digest="sha256:" + "4" * 64,
            )
        )
        state = self.store.derive_state("run-001")
        self.assertEqual(state["status"], "running")
        self.assertEqual(state["sequence"], 4)
        self.assertEqual(state["steps"]["planner"], {"status": "finished", "sequence": 4})
        replayed = self.store.replay("run-001")
        self.assertEqual(replayed, state)
        historical = self.store.replay_at("run-001", 2)
        self.assertEqual(historical["status"], "running")
        self.assertEqual(historical["sequence"], 2)
        with self.assertRaises(ValueError):
            self.store.replay_at("run-001", 0)
        with self.assertRaises(ValueError):
            self.store.replay_at("run-001", 5)

    def test_derive_state_replays_failed_run_retry_and_new_step_attempt(self):
        events = [
            event(),
            event(
                event_id="event-002", sequence=2, event_type="run.started", status="running",
                idempotency_key="run-001-started-1", payload_digest="sha256:" + "2" * 64,
            ),
            event(
                event_id="event-003", sequence=3, step_id="planner", event_type="step.planned", status="planned",
                idempotency_key="run-001-planner-planned-attempt-1", payload_digest="sha256:" + "3" * 64,
            ),
            event(
                event_id="event-004", sequence=4, step_id="planner", event_type="step.started", status="running",
                idempotency_key="run-001-planner-started-attempt-1", payload_digest="sha256:" + "4" * 64,
            ),
            event(
                event_id="event-005", sequence=5, step_id="planner", event_type="step.failed", status="failed",
                idempotency_key="run-001-planner-failed-attempt-1", payload_digest="sha256:" + "5" * 64,
            ),
            event(
                event_id="event-006", sequence=6, event_type="run.failed", status="failed",
                idempotency_key="run-001-failed", payload_digest="sha256:" + "6" * 64,
            ),
            event(
                event_id="event-007", sequence=7, event_type="run.retry", status="planned",
                idempotency_key="run-001-retry-1", payload_digest="sha256:" + "7" * 64,
            ),
            event(
                event_id="event-008", sequence=8, step_id="planner", event_type="step.retry", status="planned",
                idempotency_key="run-001-planner-retry-attempt-2", payload_digest="sha256:" + "8" * 64,
            ),
            event(
                event_id="event-009", sequence=9, event_type="run.started", status="running",
                idempotency_key="run-001-started-attempt-2", payload_digest="sha256:" + "9" * 64,
            ),
        ]
        for item in events:
            self.store.append_event(item)
        state = self.store.replay("run-001")
        self.assertEqual(state["status"], "running")
        self.assertEqual(state["steps"]["planner"]["status"], "planned")
        self.assertEqual(state["sequence"], 9)

    def test_derive_state_replays_cancelled_active_step_before_run_cancel(self):
        events = [
            event(),
            event(
                event_id="event-002", sequence=2, event_type="run.started", status="running",
                idempotency_key="run-001-started-1", payload_digest="sha256:" + "2" * 64,
            ),
            event(
                event_id="event-003", sequence=3, step_id="planner", event_type="step.planned", status="planned",
                idempotency_key="run-001-planner-planned-attempt-1", payload_digest="sha256:" + "3" * 64,
            ),
            event(
                event_id="event-004", sequence=4, step_id="planner", event_type="step.started", status="running",
                idempotency_key="run-001-planner-started-attempt-1", payload_digest="sha256:" + "4" * 64,
            ),
            event(
                event_id="event-005", sequence=5, step_id="planner", event_type="step.cancelled", status="cancelled",
                idempotency_key="run-001-planner-cancelled-attempt-1", payload_digest="sha256:" + "5" * 64,
            ),
            event(
                event_id="event-006", sequence=6, event_type="run.cancelled", status="cancelled",
                idempotency_key="run-001-cancelled-6", payload_digest="sha256:" + "6" * 64,
            ),
        ]
        for item in events:
            self.store.append_event(item)
        state = self.store.replay("run-001")
        self.assertEqual(state["status"], "cancelled")
        self.assertEqual(state["steps"]["planner"]["status"], "cancelled")

    def test_derive_state_rejects_illegal_run_transition(self):
        self.store.append_event(event())
        illegal = event(
            event_id="event-002",
            sequence=2,
            event_type="run.finished",
            status="finished",
            occurred_at=1_001,
            idempotency_key="run-001-finished-1",
            payload_digest="sha256:" + "2" * 64,
        )
        with self.assertRaises(ValueError):
            self.store.append_event(illegal)

    def test_terminal_run_cannot_receive_more_lifecycle_events(self):
        for current, event_type, status, sequence in (
            ("planned", "run.created", "planned", 1),
            ("running", "run.started", "running", 2),
            ("finished", "run.finished", "finished", 3),
        ):
            if sequence == 1:
                self.store.append_event(event())
            else:
                self.store.append_event(
                    event(
                        event_id=f"event-{sequence}",
                        sequence=sequence,
                        event_type=event_type,
                        status=status,
                        idempotency_key=f"run-001-{event_type}-{sequence}",
                        payload_digest="sha256:" + str(sequence) * 64,
                    )
                )
        after_terminal = event(
            event_id="event-004",
            sequence=4,
            event_type="run.started",
            status="running",
            idempotency_key="run-001-restart-4",
            payload_digest="sha256:" + "4" * 64,
        )
        with self.assertRaises(ValueError):
            self.store.append_event(after_terminal)

    def test_checkpoint_restore_validates_history_sequence_and_state_digest(self):
        self.store.append_event(event())
        self.store.append_event(
            event(
                event_id="event-002",
                sequence=2,
                event_type="run.started",
                status="running",
                occurred_at=1_001,
                idempotency_key="run-001-started-1",
                payload_digest="sha256:" + "2" * 64,
            )
        )
        state = self.store.derive_state("run-001")
        checkpoint = self.store.create_checkpoint("run-001")
        self.assertEqual(checkpoint["sequence"], 2)
        self.assertEqual(checkpoint["state"], state)
        expected = "sha256:" + hashlib.sha256(
            json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.assertEqual(checkpoint["state_digest"], expected)
        self.assertEqual(self.store.restore("run-001"), state)

        self.store.append_event(
            event(
                event_id="event-003",
                sequence=3,
                event_type="run.waiting",
                status="waiting",
                occurred_at=1_002,
                idempotency_key="run-001-waiting-1",
                payload_digest="sha256:" + "3" * 64,
            )
        )
        with self.assertRaises(ValueError):
            self.store.restore("run-001", checkpoint=checkpoint)

        tampered = dict(checkpoint)
        tampered["state"] = dict(tampered["state"], status="finished")
        with self.assertRaises(ValueError):
            self.store.restore("run-001", checkpoint=tampered)

    def test_checkpoint_rejects_unknown_fields_and_checkpoint_for_unknown_run(self):
        with self.assertRaises(ValueError):
            self.store.create_checkpoint("run-001")
        self.store.append_event(event())
        checkpoint = self.store.create_checkpoint("run-001")
        invalid = dict(checkpoint)
        invalid["prompt"] = "must not be persisted"
        with self.assertRaises(ValueError):
            self.store.restore("run-001", checkpoint=invalid)


if __name__ == "__main__":
    unittest.main()
