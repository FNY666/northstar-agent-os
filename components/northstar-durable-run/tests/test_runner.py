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

    def test_cancelled_run_does_not_start_any_step(self):
        self.runner.prepare(owner_id="worker-a", now=100)
        self.runner.cancel(owner_id="worker-a", now=101)
        state = self.runner.execute([self.plan("edit")], owner_id="worker-b", now=102)
        self.assertEqual(state["status"], "cancelled")
        self.assertEqual(self.calls, [])
        self.assertNotIn("step.started", [item.event_type for item in self.store.read_history("run-001")])

    def test_expired_lease_is_reclaimed_and_execution_resumes(self):
        # worker-a crashed without releasing; the expired lease is acquirable
        # (LeaseManager.acquire encodes that rule), so worker-b recovers it.
        self.runner.prepare(owner_id="worker-a", now=100)
        self.runner.lease.acquire("worker-a", now=100, ttl_seconds=1)
        state = self.runner.execute([self.plan("edit")], owner_id="worker-b", now=101)
        self.assertEqual(state["status"], "finished")
        self.assertEqual([item[0] for item in self.calls], ["edit"])

    def test_active_foreign_lease_still_blocks_execution(self):
        self.runner.prepare(owner_id="worker-a", now=100)
        self.runner.lease.acquire("worker-a", now=100, ttl_seconds=60)
        with self.assertRaises(ValueError):
            self.runner.execute([self.plan("edit")], owner_id="worker-b", now=101)
        self.assertEqual(self.calls, [])
        self.assertNotIn("step.started", [item.event_type for item in self.store.read_history("run-001")])

    def test_same_owner_may_reenter_while_lease_is_active(self):
        self.runner.lease.acquire("worker-a", now=100, ttl_seconds=60)
        state = self.runner.execute([self.plan("edit")], owner_id="worker-a", now=101)
        self.assertEqual(state["status"], "finished")

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


class RunnerLeaseHeartbeatTests(unittest.TestCase):
    """The execution lease must survive long runs and be lost loudly, not silently."""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.now = [100]

    def tearDown(self):
        self.tempdir.cleanup()

    def make_runner(self, **kwargs):
        store = EventStore(self.root / "events.jsonl")
        kwargs.setdefault("clock", lambda: self.now[0])
        return DurableRunner(
            RUN,
            store,
            lease_path=self.root / "run.lease.json",
            lease_ttl_seconds=20,
            **kwargs,
        )

    def plan(self, step_id, action):
        return StepPlan(
            step_id=step_id,
            input_payload={"step": step_id},
            scope_snapshot=["workspace:write"],
            expected_postconditions=[f"{step_id}_done"],
            action=action,
        )

    def test_heartbeat_keeps_lease_alive_across_slow_steps(self):
        runner = self.make_runner()
        ran = []

        def slow(step_id):
            def action(key):
                self.now[0] += 15  # each step takes 15s; TTL is 20s
                ran.append(step_id)
                # A thief trying to grab the lease mid-run must be refused:
                # the heartbeat already extended it past the original expiry.
                if step_id == "s2":
                    with self.assertRaises(ValueError):
                        LeaseManager(self.root / "run.lease.json").acquire(
                            "thief", now=self.now[0], ttl_seconds=20
                        )
                return {"step": step_id}

            return action

        state = runner.execute(
            [self.plan("s1", slow("s1")), self.plan("s2", slow("s2"))],
            owner_id="worker-a",
            now=100,
        )
        self.assertEqual(state["status"], "finished")
        self.assertEqual(ran, ["s1", "s2"])

    def test_stolen_lease_aborts_the_run_before_the_next_step(self):
        runner = self.make_runner()
        ran = []

        def s1(key):
            ran.append("s1")
            self.now[0] = 500  # the lease (expires at 120) lapses mid-step
            LeaseManager(self.root / "run.lease.json").acquire(
                "worker-b", now=500, ttl_seconds=60
            )
            return {"ok": True}

        state = runner.execute(
            [self.plan("s1", s1), self.plan("s2", lambda key: ran.append("s2") or {})],
            owner_id="worker-a",
            now=100,
        )
        self.assertEqual(state["status"], "failed")
        self.assertEqual(ran, ["s1"], "s2 must never run without the lease")

    def test_finished_result_survives_a_lost_lease(self):
        # The finally-block release must not mask the run outcome when the
        # lease was taken over mid-run.
        runner = self.make_runner()

        def s1(key):
            self.now[0] = 500
            LeaseManager(self.root / "run.lease.json").acquire(
                "worker-b", now=500, ttl_seconds=60
            )
            return {"ok": True}

        state = runner.execute([self.plan("s1", s1)], owner_id="worker-a", now=100)
        self.assertEqual(state["status"], "finished")

    def test_release_quietly_ignores_a_foreign_lease(self):
        runner = self.make_runner()
        LeaseManager(self.root / "run.lease.json").acquire("worker-b", now=100, ttl_seconds=60)
        runner._release_quietly("worker-a")  # must not raise
        self.assertTrue((self.root / "run.lease.json").exists())

    def test_bad_clock_is_rejected(self):
        with self.assertRaises(ValueError):
            self.make_runner(clock="not-a-clock")

    def test_clock_must_return_positive_integers(self):
        self.now[0] = -5
        runner = self.make_runner()
        state = runner.execute([self.plan("s1", lambda key: {})], owner_id="worker-a", now=100)
        self.assertEqual(state["status"], "failed")


if __name__ == "__main__":
    unittest.main()
