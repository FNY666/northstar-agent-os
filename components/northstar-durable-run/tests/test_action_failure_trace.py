"""Action failure must be traceable in the evidence stream.

A committed-unknown recovery may still trust an independent observer after an
action error. What must never happen is that the evidence stream cannot tell
"the action ran" apart from "the action raised". These tests pin that contract.
"""
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

RUN = RunContract.from_dict({
    "schema_version": "northstar.durable-run.v1",
    "task_id": "task-fail-001", "thread_id": "thread-fail-001",
    "run_id": "run-fail-001", "parent_run_id": None, "status": "planned",
    "deadline_at": 2_000, "scope_snapshot": ["workspace:read"], "trace_id": "trace-fail-001",
})
PLAN = {
    "schema_version": "northstar.agent-plan.v1", "plan_id": "plan-fail-001",
    "plan_version": 1, "task_id": RUN.task_id, "thread_id": RUN.thread_id,
    "run_id": RUN.run_id, "actor_id": "actor-fail-001", "workspace_id": "workspace-fail-001",
    "policy_revision": "policy-1", "trace_id": RUN.trace_id,
    "steps": [{
        "schema_version": "northstar.agent-plan-step.v1", "step_id": "inspect",
        "action_id": "repo.read", "input_payload": {"path": "README.md", "max_bytes": 100},
        "scope_snapshot": ["workspace:read"], "expected_postconditions": ["read_ok"],
        "idempotency_key": "fail-read-1", "max_attempts": 1, "deadline_at": 1_900,
    }],
}
DIGEST = "sha256:" + "a" * 64


def verified(step, attempt_id):
    return PostconditionResult("verified", "read_ok", DIGEST)


class ActionFailureTraceTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.evidence = Path(self.tempdir.name) / "evidence.jsonl"

    def tearDown(self):
        self.tempdir.cleanup()

    def _run(self, action):
        loop = AgentLoop(RUN, self.evidence, actor_id="actor-fail-001",
                         workspace_id="workspace-fail-001", actions={"repo.read": action},
                         observer=verified)
        state = loop.run(AgentPlan.from_dict(PLAN), owner_id="actor-fail-001", now=110,
                         current_policy_revision="policy-1")
        events = [json.loads(line) for line in self.evidence.read_text().splitlines()]
        return state, events

    def test_action_error_is_recorded_and_message_is_not_leaked(self):
        def action(step, attempt_id):
            raise ValueError("secret-token-abc123 must not reach evidence")

        state, events = self._run(action)
        failed = [e for e in events if e.get("event_type") == "step.action_failed"]
        self.assertEqual(len(failed), 1, "action error must produce exactly one traceable event")
        self.assertEqual(failed[0]["reason_code"], "ValueError")
        raw = self.evidence.read_text()
        self.assertNotIn("secret-token-abc123", raw)
        # Recovery through an independent observer stays legal.
        self.assertEqual(state.steps["inspect"]["status"], "verified_committed")
        self.assertEqual(state.status, "finished")

    def test_successful_action_records_no_failure_event(self):
        state, events = self._run(lambda step, attempt_id: {"text": "ok"})
        self.assertEqual([e for e in events if e.get("event_type") == "step.action_failed"], [])
        self.assertEqual(state.status, "finished")

    def test_error_kind_does_not_leak_exception_arguments(self):
        class CustomFailure(Exception):
            pass

        def action(step, attempt_id):
            raise CustomFailure("inner detail")

        _, events = self._run(action)
        failed = [e for e in events if e.get("event_type") == "step.action_failed"]
        self.assertEqual(failed[0]["reason_code"], "CustomFailure")
        self.assertNotIn("inner detail", self.evidence.read_text())


if __name__ == "__main__": unittest.main()
