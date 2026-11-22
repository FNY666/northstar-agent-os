import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMPONENT_ROOT))
sys.path.insert(0, str(COMPONENT_ROOT.parent / "northstar-run-contract"))

from durable_contract import RunContract  # noqa: E402
from agent_loop import AgentPlan, AgentLoop, LoopEvent, PlanStep, PostconditionResult  # noqa: E402


RUN = RunContract.from_dict(
    {
        "schema_version": "northstar.durable-run.v1",
        "task_id": "task-loop-001",
        "thread_id": "thread-loop-001",
        "run_id": "run-loop-001",
        "parent_run_id": None,
        "status": "planned",
        "deadline_at": 2_000,
        "scope_snapshot": ["workspace:read", "workspace:write"],
        "trace_id": "trace-loop-001",
    }
)


def planner_output():
    return {
        "schema_version": "northstar.agent-plan.v1",
        "plan_id": "plan-loop-001",
        "plan_version": 1,
        "task_id": RUN.task_id,
        "thread_id": RUN.thread_id,
        "run_id": RUN.run_id,
        "actor_id": "actor-loop-001",
        "workspace_id": "workspace-loop-001",
        "policy_revision": "policy-loop-1",
        "trace_id": RUN.trace_id,
        "steps": [
            {
                "schema_version": "northstar.agent-plan-step.v1",
                "step_id": "write",
                "action_id": "workspace.write",
                "input_payload": {"path": "out.txt", "content": "verified"},
                "scope_snapshot": ["workspace:write"],
                "expected_postconditions": ["out_file_matches"],
                "idempotency_key": "loop-write-1",
                "max_attempts": 2,
                "deadline_at": 1_900,
            }
        ],
    }


class AgentPlanAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tempdir.name) / "loop-evidence.jsonl"

    def tearDown(self):
        self.tempdir.cleanup()

    def test_plan_digest_is_deterministic_and_admission_does_not_execute_action(self):
        calls = []
        loop = AgentLoop(
            RUN,
            self.path,
            actor_id="actor-loop-001",
            workspace_id="workspace-loop-001",
            actions={"workspace.write": lambda step, attempt: calls.append((step, attempt))},
            observer=lambda step, attempt: None,
        )
        plan = loop.admit(planner_output(), current_policy_revision="policy-loop-1")
        again = loop.admit(dict(planner_output()), current_policy_revision="policy-loop-1")
        self.assertIsInstance(plan, AgentPlan)
        self.assertEqual(plan.plan_digest, again.plan_digest)
        self.assertTrue(plan.plan_digest.startswith("sha256:"))
        self.assertEqual(calls, [])

    def test_admission_rejects_unknown_action_scope_overrun_and_identity_mismatch(self):
        loop = AgentLoop(
            RUN,
            self.path,
            actor_id="actor-loop-001",
            workspace_id="workspace-loop-001",
            actions={"workspace.write": lambda step, attempt: {}},
            observer=lambda step, attempt: None,
        )
        unknown = planner_output()
        unknown["steps"][0]["action_id"] = "shell.exec"
        with self.assertRaises(ValueError):
            loop.admit(unknown, current_policy_revision="policy-loop-1")

        overrun = planner_output()
        overrun["steps"][0]["scope_snapshot"] = ["network:egress"]
        with self.assertRaises(ValueError):
            loop.admit(overrun, current_policy_revision="policy-loop-1")

        mismatch = planner_output()
        mismatch["run_id"] = "run-other"
        with self.assertRaises(ValueError):
            loop.admit(mismatch, current_policy_revision="policy-loop-1")

    def test_admission_rejects_stale_policy_and_invalid_deadline_or_duplicate_step(self):
        loop = AgentLoop(
            RUN,
            self.path,
            actor_id="actor-loop-001",
            workspace_id="workspace-loop-001",
            actions={"workspace.write": lambda step, attempt: {}},
            observer=lambda step, attempt: None,
        )
        with self.assertRaises(ValueError):
            loop.admit(planner_output(), current_policy_revision="policy-old")

        expired = planner_output()
        expired["steps"][0]["deadline_at"] = 2_001
        with self.assertRaises(ValueError):
            loop.admit(expired, current_policy_revision="policy-loop-1")

        duplicate = planner_output()
        duplicate["steps"].append(dict(duplicate["steps"][0]))
        with self.assertRaises(ValueError):
            loop.admit(duplicate, current_policy_revision="policy-loop-1")


class AgentLoopExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tempdir.name) / "loop-evidence.jsonl"
        self.calls = []
        self.observations = []
        self.loop = AgentLoop(
            RUN,
            self.path,
            actor_id="actor-loop-001",
            workspace_id="workspace-loop-001",
            actions={"workspace.write": self.action},
            observer=self.observe,
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def action(self, step, attempt_id):
        self.calls.append((step.step_id, attempt_id))
        return {"claimed": "finished", "raw": "must-not-be-persisted"}

    def observe(self, step, attempt_id):
        self.observations.append((step.step_id, attempt_id))
        return PostconditionResult("verified", "fixture_matches", "sha256:" + "a" * 64)

    def plan(self, *, max_attempts=2):
        value = planner_output()
        value["steps"][0]["max_attempts"] = max_attempts
        return self.loop.admit(value, current_policy_revision="policy-loop-1")

    def test_run_rechecks_current_policy_before_action(self):
        plan = self.plan()
        with self.assertRaises(ValueError):
            self.loop.run(
                plan,
                owner_id="worker-loop-001",
                now=100,
                current_policy_revision="policy-old",
            )
        self.assertEqual(self.calls, [])
        self.assertFalse(self.path.exists())

    def test_verified_postcondition_is_required_before_loop_finishes(self):
        plan = self.plan()
        state = self.loop.run(plan, owner_id="worker-loop-001", now=100, current_policy_revision="policy-loop-1")
        self.assertEqual(state.status, "finished")
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(len(self.observations), 1)
        self.assertEqual(state.steps["write"]["status"], "verified_committed")
        rendered = self.path.read_text(encoding="utf-8")
        self.assertNotIn("must-not-be-persisted", rendered)

    def test_action_return_alone_cannot_finish_loop(self):
        self.loop.observer = lambda step, attempt_id: PostconditionResult(
            "unknown", "readback_unavailable"
        )
        state = self.loop.run(
            self.plan(),
            owner_id="worker-loop-001",
            now=100,
            current_policy_revision="policy-loop-1",
        )
        self.assertEqual(state.status, "paused_unknown")
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(state.steps["write"]["status"], "paused_unknown")

    def test_verified_absence_allows_a_bounded_retry(self):
        results = iter((
            PostconditionResult("absent", "not_present"),
            PostconditionResult("verified", "fixture_matches", "sha256:" + "b" * 64),
        ))
        self.loop.observer = lambda step, attempt_id: next(results)
        state = self.loop.run(
            self.plan(max_attempts=2),
            owner_id="worker-loop-001",
            now=100,
            current_policy_revision="policy-loop-1",
        )
        self.assertEqual(state.status, "finished")
        self.assertEqual(len(self.calls), 2)
        self.assertEqual([item[1] for item in self.calls], [
            "execution-loop-write-1:attempt-1",
            "execution-loop-write-1:attempt-2",
        ])

    def test_unknown_postcondition_does_not_authorize_a_retry(self):
        self.loop.observer = lambda step, attempt_id: PostconditionResult(
            "unknown", "provider_readback_timeout"
        )
        state = self.loop.run(
            self.plan(max_attempts=2),
            owner_id="worker-loop-001",
            now=100,
            current_policy_revision="policy-loop-1",
        )
        self.assertEqual(state.status, "paused_unknown")
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(state.steps["write"]["attempt"], 1)

    def test_action_side_effect_then_crash_resumes_by_readback_without_duplicate_action(self):
        external = {"written": False}
        first_calls = []

        def side_effect_then_crash(step, attempt_id):
            first_calls.append(attempt_id)
            external["written"] = True
            raise RuntimeError("simulated worker death")

        crashed = AgentLoop(
            RUN,
            self.path,
            actor_id="actor-loop-001",
            workspace_id="workspace-loop-001",
            actions={"workspace.write": side_effect_then_crash},
            observer=lambda step, attempt_id: PostconditionResult(
                "unknown", "worker_died_before_readback"
            ),
        )
        plan = crashed.admit(planner_output(), current_policy_revision="policy-loop-1")
        paused = crashed.run(
            plan,
            owner_id="worker-loop-001",
            now=100,
            current_policy_revision="policy-loop-1",
        )
        self.assertEqual(paused.status, "paused_unknown")
        self.assertEqual(first_calls, ["execution-loop-write-1:attempt-1"])
        self.assertTrue(external["written"])

        second_calls = []
        resumed = AgentLoop(
            RUN,
            self.path,
            actor_id="actor-loop-001",
            workspace_id="workspace-loop-001",
            actions={"workspace.write": lambda step, attempt_id: second_calls.append(attempt_id)},
            observer=lambda step, attempt_id: PostconditionResult(
                "verified", "readback_confirms_write", "sha256:" + "d" * 64
            ),
        )
        finished = resumed.resume(
            plan,
            owner_id="worker-loop-002",
            now=101,
            current_policy_revision="policy-loop-1",
        )
        self.assertEqual(finished.status, "finished")
        self.assertEqual(second_calls, [])
        self.assertEqual(finished.steps["write"]["attempt"], 1)

    def test_resume_from_unknown_observation_reopens_loop_before_readback(self):
        self.loop.observer = lambda step, attempt_id: PostconditionResult(
            "unknown", "readback_unavailable"
        )
        plan = self.plan(max_attempts=2)
        paused = self.loop.run(
            plan,
            owner_id="worker-loop-001",
            now=100,
            current_policy_revision="policy-loop-1",
        )
        self.assertEqual(paused.status, "paused_unknown")

        new_calls = []
        resumed = AgentLoop(
            RUN,
            self.path,
            actor_id="actor-loop-001",
            workspace_id="workspace-loop-001",
            actions={"workspace.write": lambda step, attempt_id: new_calls.append(attempt_id)},
            observer=lambda step, attempt_id: PostconditionResult(
                "verified", "readback_matches", "sha256:" + "c" * 64
            ),
        )
        finished = resumed.resume(
            plan,
            owner_id="worker-loop-002",
            now=101,
            current_policy_revision="policy-loop-1",
        )
        self.assertEqual(finished.status, "finished")
        self.assertEqual(new_calls, [])
        self.assertEqual(finished.steps["write"]["status"], "verified_committed")


class AgentLoopDurabilityTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tempdir.name) / "loop-evidence.jsonl"
        self.loop = AgentLoop(
            RUN,
            self.path,
            actor_id="actor-loop-001",
            workspace_id="workspace-loop-001",
            actions={"workspace.write": lambda step, attempt_id: {"ok": True}},
            observer=lambda step, attempt_id: PostconditionResult(
                "verified", "readback_matches", "sha256:" + "e" * 64
            ),
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def plan(self):
        return self.loop.admit(planner_output(), current_policy_revision="policy-loop-1")

    def test_state_rejects_missing_or_tampered_checkpoint(self):
        plan = self.plan()
        self.loop.run(
            plan,
            owner_id="worker-loop-001",
            now=100,
            current_policy_revision="policy-loop-1",
        )
        checkpoint = self.path.with_name(self.path.name + ".checkpoint.json")
        original = checkpoint.read_text(encoding="utf-8")
        checkpoint.unlink()
        with self.assertRaises(ValueError):
            self.loop.state(plan.plan_digest)
        checkpoint.write_text(original, encoding="utf-8")
        value = json.loads(original)
        value["state"]["status"] = "paused_unknown"
        checkpoint.write_text(json.dumps(value) + "\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.loop.state(plan.plan_digest)

    def test_loop_event_rejects_status_type_and_predecessor_mismatch(self):
        plan_digest = "sha256:" + "a" * 64
        with self.assertRaises(ValueError):
            LoopEvent.create(
                sequence=1,
                prev_event_digest=None,
                plan_digest=plan_digest,
                event_type="loop.finished",
                step_id="__loop__",
                execution_id=None,
                attempt_id=None,
                attempt=0,
                status="running",
                reason_code="bad_status",
                observed_digest=None,
                output_digest=None,
                idempotency_key="bad-status-event",
                recorded_at=100,
            )
        with self.assertRaises(ValueError):
            LoopEvent.create(
                sequence=2,
                prev_event_digest="not-a-digest",
                plan_digest=plan_digest,
                event_type="loop.started",
                step_id="__loop__",
                execution_id=None,
                attempt_id=None,
                attempt=0,
                status="running",
                reason_code="bad_predecessor",
                observed_digest=None,
                output_digest=None,
                idempotency_key="bad-predecessor-event",
                recorded_at=100,
            )

    def test_run_rejects_evidence_plan_manifest_not_matching_plan(self):
        plan = self.plan()
        forged_manifest = (
            {
                "step_id": "write",
                "execution_id": "execution-loop-write-1",
                "idempotency_key": "loop-write-1",
                "max_attempts": 99,
                "deadline_at": 1_900,
            },
        )
        self.loop._append_event(
            plan_digest=plan.plan_digest,
            event_type="plan.admitted",
            step_id="__plan__",
            plan_step_manifest=forged_manifest,
            status="admitted",
            reason_code="plan_admitted",
            idempotency_key=f"{plan.plan_digest}:admitted",
            recorded_at=100,
        )
        with self.assertRaises(ValueError):
            self.loop.run(
                plan,
                owner_id="worker-loop-001",
                now=101,
                current_policy_revision="policy-loop-1",
            )

    def test_run_rejects_evidence_attempt_identity_not_bound_to_plan(self):
        plan = self.plan()
        self.loop._append_event(
            plan_digest=plan.plan_digest,
            event_type="plan.admitted",
            step_id="__plan__",
            plan_step_manifest=(
                {
                    "step_id": "write",
                    "execution_id": "execution-loop-write-1",
                    "idempotency_key": "loop-write-1",
                    "max_attempts": 2,
                    "deadline_at": 1_900,
                },
            ),
            status="admitted",
            reason_code="plan_admitted",
            idempotency_key=f"{plan.plan_digest}:admitted",
            recorded_at=100,
        )
        self.loop._append_event(
            plan_digest=plan.plan_digest,
            event_type="loop.started",
            step_id="__loop__",
            status="running",
            reason_code="loop_started",
            idempotency_key=f"{plan.plan_digest}:started",
            recorded_at=100,
        )
        with self.assertRaises(ValueError):
            self.loop._append_event(
                plan_digest=plan.plan_digest,
                event_type="step.attempted",
                step_id="write",
                execution_id="execution-loop-write-1",
                attempt_id="execution-loop-write-1:attempt-1-forged",
                attempt=1,
                status="attempted",
                reason_code="action_attempted",
                idempotency_key="execution-loop-write-1:attempt-1-forged:attempted",
                recorded_at=100,
            )
        self.assertNotIn("forged", self.path.read_text(encoding="utf-8"))

        plan = self.plan()
        self.loop._append_event(
            plan_digest=plan.plan_digest,
            event_type="plan.admitted",
            step_id="__plan__",
            plan_step_manifest=(
                {
                    "step_id": "write",
                    "execution_id": "execution-loop-write-1",
                    "idempotency_key": "loop-write-1",
                    "max_attempts": 2,
                    "deadline_at": 1_900,
                },
            ),
            status="admitted",
            reason_code="plan_admitted",
            idempotency_key=f"{plan.plan_digest}:admitted",
            recorded_at=100,
        )
        self.loop._append_event(
            plan_digest=plan.plan_digest,
            event_type="loop.started",
            step_id="__loop__",
            status="running",
            reason_code="loop_started",
            idempotency_key=f"{plan.plan_digest}:started",
            recorded_at=100,
        )
        with self.assertRaises(ValueError):
            self.loop._append_event(
                plan_digest=plan.plan_digest,
                event_type="step.attempted",
                step_id="unplanned",
                execution_id="execution-unplanned",
                attempt_id="execution-unplanned:attempt-1",
                attempt=1,
                status="attempted",
                reason_code="action_attempted",
                idempotency_key="execution-unplanned:attempt-1:attempted",
                recorded_at=100,
            )
        self.assertFalse("unplanned" in self.path.read_text(encoding="utf-8"))

if __name__ == "__main__":
    unittest.main()
