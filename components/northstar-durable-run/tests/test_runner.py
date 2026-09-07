import json
import sys
import tempfile
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMPONENT_ROOT))

from durable_contract import RunContract  # noqa: E402
from event_store import EventStore  # noqa: E402
from runner import DurableRunner, LeaseManager, StepPlan  # noqa: E402


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


class LeaseManagerTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tempdir.name) / "run.lease.json"
        self.leases = LeaseManager(self.path)

    def tearDown(self):
        self.tempdir.cleanup()

    def test_acquire_heartbeat_and_release_are_owner_bound(self):
        lease = self.leases.acquire("worker-a", now=100, ttl_seconds=20)
        self.assertEqual(lease, {"owner_id": "worker-a", "expires_at": 120})
        self.assertTrue(Path(str(self.path) + ".lock").exists())
        self.assertEqual(
            self.leases.heartbeat("worker-a", now=110, ttl_seconds=20),
            {"owner_id": "worker-a", "expires_at": 130},
        )
        with self.assertRaises(ValueError):
            self.leases.heartbeat("worker-b", now=111, ttl_seconds=20)
        with self.assertRaises(ValueError):
            self.leases.acquire("worker-b", now=111, ttl_seconds=20)
        self.leases.release("worker-a")
        self.assertFalse(self.path.exists())

    def test_expired_lease_can_be_reclaimed_but_invalid_file_fails_closed(self):
        self.leases.acquire("worker-a", now=100, ttl_seconds=5)
        reclaimed = self.leases.acquire("worker-b", now=105, ttl_seconds=10)
        self.assertEqual(reclaimed["owner_id"], "worker-b")
        self.path.write_text('{"owner_id":"worker-b","unexpected":true}\n')
        with self.assertRaises(ValueError):
            self.leases.assert_valid("worker-b", now=106)


class DurableRunnerTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = EventStore(Path(self.tempdir.name) / "events.jsonl")
        self.runner = DurableRunner(
            RUN,
            self.store,
            lease_path=Path(self.tempdir.name) / "run.lease.json",
            lease_ttl_seconds=20,
        )
        self.calls = []

    def tearDown(self):
        self.tempdir.cleanup()

    def plan(self, step_id, *, action=None):
        if action is None:
            action = lambda key: self.calls.append((step_id, key)) or {"step": step_id}
        return StepPlan(
            step_id=step_id,
            input_payload={"step": step_id},
            scope_snapshot=["workspace:write"],
            expected_postconditions=[f"{step_id}_done"],
            action=action,
        )

    def test_runner_executes_steps_and_writes_checkpoint_before_next_step(self):
        first = self.plan("edit")
        second = self.plan("test")
        state = self.runner.execute([first, second], owner_id="worker-a", now=100)
        self.assertEqual(state["status"], "finished")
        self.assertEqual(state["steps"]["edit"]["status"], "finished")
        self.assertEqual(state["steps"]["test"]["status"], "finished")
        self.assertEqual([item[0] for item in self.calls], ["edit", "test"])
        history = self.store.read_history("run-001")
        self.assertEqual(
            [item.event_type for item in history],
            [
                "run.created",
                "run.started",
                "step.planned",
                "step.started",
                "step.finished",
                "checkpoint.created",
                "step.planned",
                "step.started",
                "step.finished",
                "checkpoint.created",
                "run.finished",
            ],
        )
        self.assertFalse((Path(self.tempdir.name) / "run.lease.json").exists())

    def test_resume_skips_a_finished_step_and_executes_only_remaining_steps(self):
        first = self.plan("edit")
        second = self.plan("test")
        self.runner.execute([first], owner_id="worker-a", now=100, finalize=False)
        self.calls.clear()
        state = self.runner.execute([first, second], owner_id="worker-b", now=101)
        self.assertEqual(state["status"], "finished")
        self.assertEqual([item[0] for item in self.calls], ["test"])
        step_finished = [
            item for item in self.store.read_history("run-001")
            if item.event_type == "step.finished"
        ]
        self.assertEqual(len(step_finished), 2)

    def test_crash_after_external_idempotent_action_can_resume_without_duplicate_side_effect(self):
        side_effects = []
        crashed = {"value": False}

        def idempotent_action(key):
            if key not in side_effects:
                side_effects.append(key)
            if not crashed["value"]:
                crashed["value"] = True
                raise KeyboardInterrupt("simulated process death")
            return {"done": True}

        plan = self.plan("edit", action=idempotent_action)
        with self.assertRaises(KeyboardInterrupt):
            self.runner.execute([plan], owner_id="worker-a", now=100)
        self.assertEqual(len(side_effects), 1)
        self.assertEqual(side_effects, ["run-001:edit:attempt-1"])
        recovered = DurableRunner(
            RUN,
            self.store,
            lease_path=Path(self.tempdir.name) / "run.lease.json",
            lease_ttl_seconds=20,
        )
        state = recovered.execute([plan], owner_id="worker-b", now=101)
        self.assertEqual(state["status"], "finished")
        self.assertEqual(len(side_effects), 1)

    def test_failed_step_is_terminal_and_does_not_report_success(self):
        def fail(_key):
            raise RuntimeError("fixture test failed")

        state = self.runner.execute(
            [self.plan("test", action=fail)], owner_id="worker-a", now=100
        )
        self.assertEqual(state["status"], "failed")
        self.assertEqual(state["steps"]["test"]["status"], "failed")
        self.assertIn("run.failed", [item.event_type for item in self.store.read_history("run-001")])
        with self.assertRaises(ValueError):
            self.runner.execute([self.plan("test")], owner_id="worker-b", now=101)

    def test_pause_and_resume_are_durable_boundaries(self):
        plan = self.plan("edit")
        state = self.runner.execute([plan], owner_id="worker-a", now=100, finalize=False)
        self.assertEqual(state["status"], "running")
        paused = self.runner.pause(owner_id="worker-a", now=101, reason="operator requested pause")
        self.assertEqual(paused["status"], "waiting")
        self.assertFalse((Path(self.tempdir.name) / "run.lease.json").exists())
        with self.assertRaises(ValueError):
            self.runner.execute([plan], owner_id="worker-b", now=102)
        self.assertEqual(self.runner.pause(owner_id="worker-a", now=102)["status"], "waiting")
        resumed = self.runner.resume(owner_id="worker-b", now=103)
        self.assertEqual(resumed["status"], "running")
        finished = self.runner.execute([plan], owner_id="worker-b", now=104)
        self.assertEqual(finished["status"], "finished")
        self.assertEqual([item[0] for item in self.calls], ["edit"])
        self.assertEqual(
            [event.event_type for event in self.store.read_history("run-001") if event.event_type in {"run.waiting", "run.started"}],
            ["run.started", "run.waiting", "run.started"],
        )

    def test_failed_run_can_retry_with_a_new_step_attempt(self):
        attempts: list[str] = []

        def fail_once(key):
            attempts.append(key)
            if len(attempts) == 1:
                raise RuntimeError("transient fixture failure")
            return {"ok": True}

        plan = self.plan("edit", action=fail_once)
        first = self.runner.execute([plan], owner_id="worker-a", now=100)
        self.assertEqual(first["status"], "failed")
        recovered = self.runner.retry([plan], owner_id="worker-b", now=101)
        self.assertEqual(recovered["status"], "finished")
        self.assertEqual(attempts, ["run-001:edit:attempt-1", "run-001:edit:attempt-2"])
        event_types = [event.event_type for event in self.store.read_history("run-001")]
        self.assertIn("run.retry", event_types)
        self.assertIn("step.retry", event_types)
        self.assertEqual(event_types.count("step.started"), 2)

    def test_cancel_persists_active_step_cancellation_before_run_cancellation(self):
        def cancel_from_action(_key):
            self.runner.cancel(owner_id="worker-a", now=101)
            return {"unreachable": "step is now cancelled"}

        state = self.runner.execute(
            [self.plan("edit", action=cancel_from_action)], owner_id="worker-a", now=100
        )
        self.assertEqual(state["status"], "cancelled")
        self.assertEqual(state["steps"]["edit"]["status"], "cancelled")
        self.assertEqual(
            [event.event_type for event in self.store.read_history("run-001")][-2:],
            ["step.cancelled", "run.cancelled"],
        )
        self.assertNotIn("step.finished", [event.event_type for event in self.store.read_history("run-001")])

    def test_cancelled_run_does_not_start_any_step(self):
        self.runner.prepare(owner_id="worker-a", now=100)
        self.runner.cancel(owner_id="worker-a", now=101)
        state = self.runner.execute([self.plan("edit")], owner_id="worker-b", now=102)
        self.assertEqual(state["status"], "cancelled")
        self.assertEqual(self.calls, [])
        self.assertNotIn("step.started", [item.event_type for item in self.store.read_history("run-001")])

    def test_control_mutations_are_fenced_by_the_owner_bound_lease(self):
        self.runner.execute([self.plan("edit")], owner_id="worker-a", now=100, finalize=False)
        self.runner.lease.acquire("worker-b", now=101, ttl_seconds=20)
        with self.assertRaises(ValueError):
            self.runner.pause(owner_id="worker-a", now=102)
        self.assertEqual(self.store.derive_state("run-001")["status"], "running")
        self.runner.lease.release("worker-b")
        self.assertEqual(self.runner.pause(owner_id="worker-a", now=103)["status"], "waiting")

    def test_expired_lease_blocks_execution_and_does_not_start_a_step(self):
        self.runner.prepare(owner_id="worker-a", now=100)
        self.runner.lease.acquire("worker-a", now=100, ttl_seconds=1)
        with self.assertRaises(ValueError):
            self.runner.execute([self.plan("edit")], owner_id="worker-a", now=101)
        self.assertEqual(self.calls, [])
        self.assertNotIn("step.started", [item.event_type for item in self.store.read_history("run-001")])

    def test_deadline_blocks_new_step_and_writes_failed_run(self):
        with self.assertRaises(ValueError):
            self.runner.execute([self.plan("edit")], owner_id="worker-a", now=2_000)
        self.assertEqual(self.calls, [])
        self.assertFalse(self.store.read_history("run-001"))

    def test_step_plan_rejects_unbounded_or_duplicate_scope_data(self):
        with self.assertRaises(ValueError):
            StepPlan(
                step_id="edit",
                input_payload={"x": object()},
                scope_snapshot=["workspace:write"],
                expected_postconditions=["done"],
                action=lambda key: {},
            )
        with self.assertRaises(ValueError):
            StepPlan(
                step_id="edit",
                input_payload={},
                scope_snapshot=["workspace:write", "workspace:write"],
                expected_postconditions=["done"],
                action=lambda key: {},
            )


if __name__ == "__main__":
    unittest.main()
