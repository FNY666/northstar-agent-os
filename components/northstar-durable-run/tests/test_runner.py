import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMPONENT_ROOT))

from durable_contract import RunContract  # noqa: E402
from event_store import EventStore  # noqa: E402
from runner import DurableRunner, FencingError, LeaseManager, StepPlan  # noqa: E402


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
        self.assertEqual(
            lease,
            {"owner_id": "worker-a", "expires_at": 120, "fencing_token": 1},
        )
        self.assertEqual(
            self.leases.heartbeat("worker-a", token=1, now=110, ttl_seconds=20),
            {"owner_id": "worker-a", "expires_at": 130, "fencing_token": 1},
        )
        with self.assertRaises(ValueError):
            self.leases.heartbeat("worker-b", token=1, now=111, ttl_seconds=20)
        with self.assertRaises(FencingError):
            # Right owner, stale token: the epoch moved on.
            self.leases.heartbeat("worker-a", token=2, now=111, ttl_seconds=20)
        with self.assertRaises(ValueError):
            self.leases.acquire("worker-b", now=111, ttl_seconds=20)
        self.leases.release("worker-a")
        self.assertFalse(self.path.exists())

    def test_expired_lease_can_be_reclaimed_but_invalid_file_fails_closed(self):
        self.leases.acquire("worker-a", now=100, ttl_seconds=5)
        reclaimed = self.leases.acquire("worker-b", now=105, ttl_seconds=10)
        self.assertEqual(reclaimed["owner_id"], "worker-b")
        # Takeover starts a new fencing epoch: the token moves forward.
        self.assertEqual(reclaimed["fencing_token"], 2)
        self.path.write_text('{"owner_id":"worker-b","unexpected":true}\n')
        with self.assertRaises(ValueError):
            self.leases.assert_valid("worker-b", now=106)

    def test_fencing_token_is_monotonic_and_stale_tokens_are_refused(self):
        first = self.leases.acquire("worker-a", now=100, ttl_seconds=10)
        self.assertEqual(first["fencing_token"], 1)
        taken = self.leases.acquire("worker-b", now=110, ttl_seconds=10)
        self.assertEqual(taken["fencing_token"], 2)
        with self.assertRaises(FencingError):
            self.leases.heartbeat("worker-a", token=1, now=111, ttl_seconds=10)
        with self.assertRaises(FencingError):
            self.leases.check_token("worker-a", token=1)
        with self.assertRaises(FencingError):
            self.leases.renew("worker-a", token=1, now=111, ttl_seconds=10)
        self.leases.check_token("worker-b", token=2)  # current holder passes
        renewed = self.leases.renew("worker-b", token=2, now=115, ttl_seconds=10)
        self.assertEqual(renewed["fencing_token"], 2)  # unexpired: same epoch
        self.assertEqual(renewed["expires_at"], 125)
        relapsed = self.leases.renew("worker-b", token=2, now=200, ttl_seconds=10)
        self.assertEqual(relapsed["fencing_token"], 3)  # clean expiry: new epoch
        with self.assertRaises(FencingError):
            self.leases.renew("worker-b", token=2, now=201, ttl_seconds=10)

    def test_check_token_is_time_agnostic_but_owner_strict(self):
        self.leases.acquire("worker-a", now=100, ttl_seconds=10)
        # Expired but untaken: no rival writer, so not a fence.
        self.leases.check_token("worker-a", token=1)
        with self.assertRaises(FencingError):
            self.leases.check_token("worker-b", token=1)
        self.leases.release("worker-a")
        with self.assertRaises(FencingError):
            self.leases.check_token("worker-a", token=1)


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

    def test_stolen_lease_refuses_the_stale_write_and_raises_fencing(self):
        # worker-b takes over mid-step: worker-a's step.finished must NOT land
        # in the new epoch's event stream, and s2 must never run unowned.
        runner = self.make_runner()
        ran = []

        def s1(key):
            ran.append("s1")
            self.now[0] = 500  # the lease (expires at 120) lapses mid-step
            LeaseManager(self.root / "run.lease.json").acquire(
                "worker-b", now=500, ttl_seconds=60
            )
            return {"ok": True}

        with self.assertRaises(FencingError):
            runner.execute(
                [
                    self.plan("s1", s1),
                    self.plan("s2", lambda key: ran.append("s2") or {"ok": True}),
                ],
                owner_id="worker-a",
                now=100,
            )
        self.assertEqual(ran, ["s1"], "s2 must never run without the lease")
        event_types = [item.event_type for item in runner.store.read_history("run-001")]
        self.assertNotIn("step.finished", event_types)
        self.assertNotIn("run.failed", event_types)

    def test_lost_lease_no_longer_lands_a_stale_step_finished(self):
        # Regression: the old code let the taken-over holder's step.finished
        # land after the takeover. Fencing refuses the stale write instead;
        # the new holder resumes the unfinished step itself.
        runner = self.make_runner()

        def s1(key):
            self.now[0] = 500
            LeaseManager(self.root / "run.lease.json").acquire(
                "worker-b", now=500, ttl_seconds=60
            )
            return {"ok": True}

        with self.assertRaises(FencingError):
            runner.execute([self.plan("s1", s1)], owner_id="worker-a", now=100)
        event_types = [item.event_type for item in runner.store.read_history("run-001")]
        self.assertNotIn("step.finished", event_types)
        self.assertNotIn("run.finished", event_types)

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


class RunnerFencingTests(unittest.TestCase):
    """Fencing tokens: stale holders cannot write, takeovers are marked."""

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

    def test_fenced_holder_cannot_append_events(self):
        runner = self.make_runner()
        runner.prepare(owner_id="worker-a", now=100)
        token = runner._ensure_execution_lease("worker-a", now=100)
        self.assertEqual(token, 1)
        # worker-b takes over the expired lease: token moves to 2.
        LeaseManager(self.root / "run.lease.json").acquire(
            "worker-b", now=200, ttl_seconds=60
        )
        with self.assertRaises(FencingError):
            runner._append(
                event_type="step.finished",
                status="finished",
                step_id="s1",
                idempotency_key="run-001-s1-finished",
                now=200,
                payload={"output_digest": "sha256:" + "0" * 64},
                owner_id="worker-a",
            )
        # Only run.created (pre-epoch) is in history: the stale write landed nowhere.
        self.assertEqual(len(runner.store.read_history("run-001")), 1)

    def test_takeover_appends_run_fenced_marker_for_the_new_holder(self):
        runner = self.make_runner()
        runner.prepare(owner_id="worker-a", now=100)
        runner.lease.acquire("worker-a", now=100, ttl_seconds=1)
        state = runner.execute(
            [self.plan("s1", lambda key: {"ok": True})],
            owner_id="worker-b",
            now=101,
        )
        self.assertEqual(state["status"], "finished")
        history = runner.store.read_history("run-001")
        markers = [item for item in history if item.event_type == "run.fenced"]
        self.assertEqual(len(markers), 1)
        # The tripwire names the fenced epoch; it is state-neutral so the new
        # epoch still runs to completion.
        self.assertIn("worker-a", markers[0].idempotency_key)
        self.assertEqual(
            [item.event_type for item in history],
            [
                "run.created",
                "run.fenced",
                "run.started",
                "step.planned",
                "step.started",
                "step.finished",
                "checkpoint.created",
                "run.finished",
            ],
        )

    def test_background_heartbeat_renews_lease_during_long_action(self):
        runner = self.make_runner(heartbeat_interval_seconds=1)
        seen = {}

        def long_action(key):
            self.now[0] += 30  # the fake clock jumps past the 20s TTL mid-action
            time.sleep(2.5)  # give the heartbeat thread room to renew
            lease = json.loads((self.root / "run.lease.json").read_text(encoding="utf-8"))
            seen["expires_at"] = lease["expires_at"]
            seen["fencing_token"] = lease["fencing_token"]
            return {"ok": True}

        state = runner.execute(
            [self.plan("s1", long_action)], owner_id="worker-a", now=100
        )
        self.assertEqual(state["status"], "finished")
        # The thread renewed with the advanced clock (now=130): expiry moved
        # past the original 120, on a new epoch after the clean lapse.
        self.assertEqual(seen["expires_at"], 150)
        self.assertEqual(seen["fencing_token"], 2)

    def test_lease_lost_during_action_is_detected(self):
        runner = self.make_runner(heartbeat_interval_seconds=1)

        def compromised(key):
            self.now[0] = 500
            LeaseManager(self.root / "run.lease.json").acquire(
                "worker-b", now=500, ttl_seconds=60
            )
            time.sleep(2.5)  # the heartbeat thread observes the takeover
            return {"ok": True}

        with self.assertRaises(FencingError):
            runner.execute(
                [self.plan("s1", compromised)], owner_id="worker-a", now=100
            )
        event_types = [item.event_type for item in runner.store.read_history("run-001")]
        self.assertNotIn("step.finished", event_types)

    def test_heartbeat_interval_requires_clock_and_fits_inside_ttl(self):
        store = EventStore(self.root / "events.jsonl")
        with self.assertRaises(ValueError):
            DurableRunner(
                RUN,
                store,
                lease_path=self.root / "run.lease.json",
                lease_ttl_seconds=20,
                heartbeat_interval_seconds=1,
            )
        with self.assertRaises(ValueError):
            DurableRunner(
                RUN,
                store,
                lease_path=self.root / "run.lease.json",
                lease_ttl_seconds=20,
                clock=lambda: self.now[0],
                heartbeat_interval_seconds=20,
            )
        with self.assertRaises(ValueError):
            DurableRunner(
                RUN,
                store,
                lease_path=self.root / "run.lease.json",
                lease_ttl_seconds=20,
                clock=lambda: self.now[0],
                heartbeat_interval_seconds=0,
            )


if __name__ == "__main__":
    unittest.main()
