import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / "northstar-run-contract"))

from agent_loop import AgentLoop, AgentPlan, PostconditionResult  # noqa: E402
from durable_contract import RunContract  # noqa: E402
from planner_adapter import PlannerCandidate, PlannerModelResponse, PlannerResult, TypedPlannerAdapter  # noqa: E402

RUN = RunContract.from_dict({
    "schema_version": "northstar.durable-run.v1",
    "task_id": "task-planner-001", "thread_id": "thread-planner-001",
    "run_id": "run-planner-001", "parent_run_id": None, "status": "planned",
    "deadline_at": 2_000, "scope_snapshot": ["workspace:read"],
    "trace_id": "trace-planner-001",
})


def plan_value():
    return {
        "schema_version": "northstar.agent-plan.v1", "plan_id": "plan-planner-001",
        "plan_version": 1, "task_id": RUN.task_id, "thread_id": RUN.thread_id,
        "run_id": RUN.run_id, "actor_id": "actor-planner-001",
        "workspace_id": "workspace-planner-001", "policy_revision": "policy-1",
        "trace_id": RUN.trace_id, "steps": [{
            "schema_version": "northstar.agent-plan-step.v1", "step_id": "inspect",
            "action_id": "repo.read", "input_payload": {"path": "README.md"},
            "scope_snapshot": ["workspace:read"], "expected_postconditions": ["read_ok"],
            "idempotency_key": "planner-read-1", "max_attempts": 1, "deadline_at": 1_900,
        }],
    }


class PlannerCandidateTests(unittest.TestCase):
    def test_candidate_requires_strict_envelope_and_deterministic_digest(self):
        value = {"schema_version": "northstar.planner-candidate.v1", "plan": plan_value(), "model_id": "model-a", "provider": "provider-a", "model_revision": "rev-1"}
        candidate = PlannerCandidate.from_value(value)
        again = PlannerCandidate.from_value(dict(value))
        self.assertIsInstance(candidate.plan, AgentPlan)
        self.assertEqual(candidate.output_digest, again.output_digest)
        self.assertTrue(candidate.output_digest.startswith("sha256:"))
        for bad in ({**value, "extra": True}, {**value, "model_id": "bad id"}):
            with self.assertRaises(ValueError): PlannerCandidate.from_value(bad)

    def test_candidate_rejects_invalid_json_and_forbidden_fields(self):
        with self.assertRaises(ValueError): PlannerCandidate.from_value("not json")
        value = {"schema_version": "northstar.planner-candidate.v1", "plan": {**plan_value(), "callable": "bad"}, "model_id": "m", "provider": "p", "model_revision": "r"}
        with self.assertRaises(ValueError): PlannerCandidate.from_value(value)


class PlannerAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tempdir.name) / "evidence.jsonl"
        self.calls = []
        self.loop = AgentLoop(RUN, self.path, actor_id="actor-planner-001", workspace_id="workspace-planner-001", actions={"repo.read": lambda step, attempt: self.calls.append(attempt)}, observer=lambda step, attempt: PostconditionResult("verified", "read_ok", "sha256:" + "a" * 64))

    def tearDown(self): self.tempdir.cleanup()

    def test_valid_model_output_is_admitted_without_executing_action(self):
        def caller(**kwargs): return PlannerModelResponse(plan_value(), "model-a", "provider-a", "rev-1")
        result = TypedPlannerAdapter(caller).generate("inspect README", context={"ref": "ctx"}, loop=self.loop, current_policy_revision="policy-1", owner_id="owner-1", now=100)
        self.assertEqual(result.model_id, "model-a")
        self.assertIsInstance(result, PlannerResult)
        self.assertEqual(result.attempts, 1)
        self.assertEqual(self.calls, [])

    def test_malformed_output_gets_one_repair_call_then_fails_closed(self):
        calls = []
        def caller(**kwargs):
            calls.append(kwargs)
            return PlannerModelResponse("still invalid", "m", "p", "r") if len(calls) == 1 else PlannerModelResponse({"plan": plan_value()}, "m", "p", "r")
        result = TypedPlannerAdapter(caller).generate("inspect", context={}, loop=self.loop, current_policy_revision="policy-1", owner_id="o", now=100)
        self.assertEqual(result.attempts, 2)
        self.assertEqual(self.calls, [])
        self.assertEqual(calls[1]["attempt"], 2)
        self.assertIsNotNone(calls[1]["repair_error"])
        with self.assertRaises(ValueError): TypedPlannerAdapter(lambda **kwargs: PlannerModelResponse("bad", "m", "p", "r")).generate("inspect", context={}, loop=self.loop, current_policy_revision="policy-1", owner_id="o", now=100)

    def test_raw_model_dictionary_is_rejected(self):
        caller = lambda **kwargs: {"schema_version": "northstar.planner-candidate.v1", "plan": plan_value(), "model_id": "m", "provider": "p", "model_revision": "r"}
        with self.assertRaises(ValueError): TypedPlannerAdapter(caller).generate("inspect", context={}, loop=self.loop, current_policy_revision="policy-1", owner_id="o", now=100)

    def test_admission_rejection_propagates(self):
        bad = plan_value(); bad["actor_id"] = "other"
        caller = lambda **kwargs: PlannerModelResponse({"plan": bad}, "m", "p", "r")
        with self.assertRaises(ValueError): TypedPlannerAdapter(caller).generate("inspect", context={}, loop=self.loop, current_policy_revision="policy-1", owner_id="o", now=100)

    def test_model_exception_fails_closed_without_unbounded_retry(self):
        calls = []
        def caller(**kwargs):
            calls.append(kwargs)
            raise RuntimeError("provider failure")
        with self.assertRaises(ValueError):
            TypedPlannerAdapter(caller).generate("inspect", context={}, loop=self.loop, current_policy_revision="policy-1", owner_id="o", now=100)
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.calls, [])

    def test_oversized_output_is_rejected_before_admission(self):
        calls = []
        def caller(**kwargs):
            calls.append(kwargs)
            return PlannerModelResponse("{" + ("x" * 1000), "m", "p", "r")
        with self.assertRaises(ValueError):
            TypedPlannerAdapter(caller, max_output_bytes=100).generate("inspect", context={}, loop=self.loop, current_policy_revision="policy-1", owner_id="o", now=100)
        self.assertEqual(len(calls), 2)


if __name__ == "__main__": unittest.main()
