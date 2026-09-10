"""Waiting for approval is not a failed attempt.

An approval gate is a human time scale: minutes to hours. The attempt budget
counts *executions*, so a step that only ever waited must still be able to run
once approval arrives. These tests pin that contract against the existing
fail-closed behaviour for genuine refusals.
"""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / "northstar-run-contract"))
sys.path.insert(0, str(ROOT.parent / "northstar-host"))

from action_gateway import ActionGateway, ToolSpec, sign_approval  # noqa: E402
from agent_loop import AgentLoop, AgentPlan, PostconditionResult  # noqa: E402
from authorization import HostPolicy, authorize_run  # noqa: E402
from binding import sign_binding, verify_binding  # noqa: E402
from durable_contract import RunContract  # noqa: E402
from governed_dispatch import GovernedActionDispatcher  # noqa: E402

BINDING_SECRET = b"await-binding"
AUTH_SECRET = b"await-authorization"
APPROVAL_SECRET = b"await-approval"
ACTOR, WORKSPACE, POLICY = "actor-await", "workspace-await", "policy-1"

RUN = RunContract.from_dict({
    "schema_version": "northstar.durable-run.v1",
    "task_id": "task-await", "thread_id": "thread-await", "run_id": "run-await",
    "parent_run_id": None, "status": "planned", "deadline_at": 9_000,
    "scope_snapshot": ["workspace:write"], "trace_id": "trace-await",
})


def plan_value(*, max_attempts=1, deadline_at=1_900):
    return {
        "schema_version": "northstar.agent-plan.v1", "plan_id": "plan-await",
        "plan_version": 1, "task_id": RUN.task_id, "thread_id": RUN.thread_id,
        "run_id": RUN.run_id, "actor_id": ACTOR, "workspace_id": WORKSPACE,
        "policy_revision": POLICY, "trace_id": RUN.trace_id,
        "steps": [{
            "schema_version": "northstar.agent-plan-step.v1", "step_id": "write",
            "action_id": "workspace.write_file",
            "input_payload": {"path": "notes.txt", "content": "x"},
            "scope_snapshot": ["workspace:write"], "expected_postconditions": ["write_ok"],
            "idempotency_key": "await-write-1", "max_attempts": max_attempts,
            "deadline_at": deadline_at,
        }],
    }


def token():
    run = {
        "schema_version": "northstar.run.v1", "run_id": RUN.run_id, "actor_id": ACTOR,
        "workspace_id": WORKSPACE, "task_kind": "implementation", "prompt": "write",
        "timeout_ms": 60_000, "requested_capabilities": ["workspace:write"], "parent_run_id": None,
    }
    binding = {"schema_version": "northstar.run.v1", "run_id": RUN.run_id, "actor_id": ACTOR,
               "workspace_id": WORKSPACE, "expires_at": 9_000}
    verified = verify_binding(sign_binding(binding, BINDING_SECRET), BINDING_SECRET, now=1_000)
    policy = HostPolicy.from_mapping(POLICY, {ACTOR: ["workspace:write"]})
    return authorize_run(run, verified, policy, now=1_000, secret=AUTH_SECRET, grant_ttl_seconds=3_000)


def approval():
    return sign_approval({
        "schema_version": "northstar.approval.v1", "approval_id": "approval-await",
        "approver_id": "human-1", "task_id": RUN.task_id, "thread_id": RUN.thread_id,
        "run_id": RUN.run_id, "step_id": "write", "actor_id": ACTOR,
        "tool_name": "workspace.write_file", "resource_id": WORKSPACE,
        "decision": "approved", "expires_at": 9_000,
    }, APPROVAL_SECRET)


class AwaitingApprovalTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.evidence = Path(self.tempdir.name) / "evidence.jsonl"
        self.calls = []

    def tearDown(self):
        self.tempdir.cleanup()

    def _run(self, approval_provider, *, now=1_001, max_attempts=1, deadline_at=1_900):
        gateway = ActionGateway(approval_secret=APPROVAL_SECRET)
        gateway.register(ToolSpec(
            name="workspace.write_file", required_capability="workspace:write",
            required_scope="workspace:write", resource_kind="workspace", risk_level="high",
            executor=lambda arguments: (self.calls.append(arguments), {"status": "written"})[1],
        ))
        plan = AgentPlan.from_dict(plan_value(max_attempts=max_attempts, deadline_at=deadline_at))
        dispatcher = GovernedActionDispatcher(
            gateway, authorization_token_provider=token, authorization_secret=AUTH_SECRET,
            now_provider=lambda: now, approval_provider=approval_provider,
        )
        dispatcher.register_plan(plan)

        def observer(step, attempt_id):
            if not self.calls:
                return PostconditionResult("unknown", "write_unverified")
            return PostconditionResult("verified", "write_ok",
                                       "sha256:" + hashlib.sha256(b"written").hexdigest())

        loop = AgentLoop(RUN, self.evidence, actor_id=ACTOR, workspace_id=WORKSPACE,
                         actions={"workspace.write_file": dispatcher.bind("workspace.write_file")},
                         observer=observer)
        loop.admit(plan, current_policy_revision=POLICY)
        return loop.run(plan, owner_id=ACTOR, now=now, current_policy_revision=POLICY), plan

    def _events(self):
        return [json.loads(line) for line in self.evidence.read_text().splitlines()]

    def _attempts(self):
        return len([event for event in self._events() if event["event_type"] == "step.attempted"])

    def _waits(self):
        return len([event for event in self._events() if event["event_type"] == "step.awaiting_approval"])

    def test_waiting_does_not_consume_the_attempt_budget(self):
        ready = {"value": False}
        provider = lambda call: approval() if ready["value"] else None

        state, _ = self._run(provider, max_attempts=1)
        self.assertEqual(state.status, "awaiting_approval")
        self.assertEqual(self.calls, [], "a waiting step must not execute")
        self.assertEqual(state.steps["write"]["status"], "awaiting_approval")

        ready["value"] = True
        state, _ = self._run(provider, max_attempts=1)
        self.assertEqual(state.status, "finished",
                         "approval arriving later must still allow the single execution")
        self.assertEqual(len(self.calls), 1, "exactly one real execution")
        self.assertEqual(self._waits(), 1, "the wait is recorded as a wait, never as an execution")

    def test_repeated_waiting_still_leaves_the_budget_intact(self):
        ready = {"value": False}
        provider = lambda call: approval() if ready["value"] else None

        for _ in range(3):
            state, _ = self._run(provider, max_attempts=1)
            self.assertEqual(state.status, "awaiting_approval")
        self.assertEqual(self.calls, [])

        ready["value"] = True
        state, _ = self._run(provider, max_attempts=1)
        self.assertEqual(state.status, "finished")
        self.assertEqual(len(self.calls), 1)

    def test_waiting_is_visible_and_sanitized(self):
        state, _ = self._run(lambda call: None, max_attempts=1)
        events = self._events()
        awaiting = [event for event in events if event["event_type"] == "step.awaiting_approval"]
        self.assertEqual(len(awaiting), 1)
        self.assertEqual(awaiting[0]["reason_code"], "ApprovalPending")
        self.assertNotIn("step.observed", [event["event_type"] for event in events],
                         "a step that never ran has no postcondition to observe")

    def test_waiting_past_the_deadline_fails_closed(self):
        state, _ = self._run(lambda call: None, now=2_000, max_attempts=1, deadline_at=1_900)
        self.assertEqual(state.status, "failed")
        self.assertNotEqual(state.status, "finished")

    def test_a_real_refusal_still_consumes_the_budget(self):
        # Expired grant is a configuration refusal, not a wait: it must stay fail-closed.
        state, _ = self._run(lambda call: approval(), now=5_000, max_attempts=1)
        self.assertNotEqual(state.status, "finished")
        self.assertNotEqual(state.status, "awaiting_approval")
        self.assertEqual(self.calls, [])


if __name__ == "__main__": unittest.main()
