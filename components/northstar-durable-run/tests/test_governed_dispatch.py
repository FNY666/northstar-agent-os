"""AgentLoop actions must pass the same ToolCall authorization chain.

Before this slice the loop called `actions[action_id](step, attempt_id)`
directly, so a "governed" step was governed only by path checks inside the
tool. These tests pin the calling-layer contract: dispatch goes through
ActionGateway, and every rejection is fail-closed and traceable.
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

from action_gateway import ActionGateway, ToolSpec, digest_arguments, sign_approval  # noqa: E402
from agent_loop import AgentLoop, AgentPlan, PostconditionResult  # noqa: E402
from authorization import HostPolicy, authorize_run  # noqa: E402
from binding import sign_binding, verify_binding  # noqa: E402
from durable_contract import RunContract  # noqa: E402
from repo_read import RepoReadTool  # noqa: E402

BINDING_SECRET = b"dispatch-binding-secret"
AUTH_SECRET = b"dispatch-authorization-secret"
APPROVAL_SECRET = b"dispatch-approval-secret"
ACTOR = "actor-dispatch-001"
WORKSPACE = "workspace-dispatch-001"
POLICY = "policy-1"

RUN = RunContract.from_dict({
    "schema_version": "northstar.durable-run.v1",
    "task_id": "task-dispatch-001", "thread_id": "thread-dispatch-001",
    "run_id": "run-dispatch-001", "parent_run_id": None, "status": "planned",
    "deadline_at": 2_000, "scope_snapshot": ["workspace:read", "workspace:write"],
    "trace_id": "trace-dispatch-001",
})


def plan_value(*, scope=("workspace:read",), step_id="inspect", path="README.md", max_attempts=1,
               action_id="repo.read", payload=None):
    return {
        "schema_version": "northstar.agent-plan.v1", "plan_id": "plan-dispatch-001",
        "plan_version": 1, "task_id": RUN.task_id, "thread_id": RUN.thread_id,
        "run_id": RUN.run_id, "actor_id": ACTOR, "workspace_id": WORKSPACE,
        "policy_revision": POLICY, "trace_id": RUN.trace_id,
        "steps": [{
            "schema_version": "northstar.agent-plan-step.v1", "step_id": step_id,
            "action_id": action_id,
            "input_payload": payload if payload is not None else {"path": path, "max_bytes": 4096},
            "scope_snapshot": list(scope), "expected_postconditions": ["read_ok"],
            "idempotency_key": f"dispatch-{step_id}-1", "max_attempts": max_attempts,
            "deadline_at": 1_900,
        }],
    }


def authorization_token(*, capability="workspace:read", now=1_000, expires_at=2_000):
    run = {
        "schema_version": "northstar.run.v1", "run_id": RUN.run_id, "actor_id": ACTOR,
        "workspace_id": WORKSPACE, "task_kind": "implementation",
        "prompt": "Read the fixture.", "timeout_ms": 10_000,
        "requested_capabilities": [capability], "parent_run_id": None,
    }
    binding = {
        "schema_version": "northstar.run.v1", "run_id": RUN.run_id, "actor_id": ACTOR,
        "workspace_id": WORKSPACE, "expires_at": expires_at,
    }
    verified = verify_binding(sign_binding(binding, BINDING_SECRET), BINDING_SECRET, now=now)
    policy = HostPolicy.from_mapping(POLICY, {ACTOR: [capability]})
    return authorize_run(run, verified, policy, now=now, secret=AUTH_SECRET, grant_ttl_seconds=300)


def approval_for(*, step_id="inspect", tool_name="workspace.write_file", decision="approved",
                 expires_at=2_000):
    return sign_approval({
        "schema_version": "northstar.approval.v1",
        "approval_id": "approval-001", "approver_id": "human-001",
        "task_id": RUN.task_id, "thread_id": RUN.thread_id, "run_id": RUN.run_id,
        "step_id": step_id, "actor_id": ACTOR, "tool_name": tool_name,
        "resource_id": WORKSPACE, "decision": decision, "expires_at": expires_at,
    }, APPROVAL_SECRET)


class GovernedDispatchTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name) / "repo"
        self.root.mkdir(mode=0o700)
        (self.root / "README.md").write_text("governed content\n", encoding="utf-8")
        self.evidence = Path(self.tempdir.name) / "evidence.jsonl"
        self.gateway = ActionGateway(approval_secret=APPROVAL_SECRET)
        self.tool = RepoReadTool(self.root, allowed_paths=["README.md"])
        self.gateway.register(ToolSpec(
            name="repo.read", required_capability="workspace:read",
            required_scope="workspace:read", resource_kind="workspace",
            risk_level="low", executor=lambda arguments: {"text": self.tool(arguments).content},
        ))
        self.executed = []

    def tearDown(self):
        self.tempdir.cleanup()

    def _loop(self, plan, dispatcher, *, action_id="repo.read", observer=None):
        def default_observer(step, attempt_id):
            requested = step.input_payload.get("path", "")
            candidate = (self.root / requested).resolve()
            if not candidate.is_relative_to(self.root) or not candidate.is_file():
                return PostconditionResult("unknown", "read_unverified")
            return PostconditionResult("verified", "read_ok",
                                       "sha256:" + hashlib.sha256(candidate.read_bytes()).hexdigest())

        return AgentLoop(RUN, self.evidence, actor_id=ACTOR, workspace_id=WORKSPACE,
                         actions={action_id: dispatcher.bind(action_id)},
                         observer=observer or default_observer)

    def _events(self):
        return [json.loads(line) for line in self.evidence.read_text().splitlines()]

    def _run(self, *, token=None, token_factory=None, gateway=None, now=1_001,
             approval_provider=None, capability="workspace:read", action_id="repo.read",
             observer=None, **plan_kwargs):
        from governed_dispatch import GovernedActionDispatcher

        plan = AgentPlan.from_dict(plan_value(action_id=action_id, **plan_kwargs))
        provider = token_factory or (
            lambda: token if token is not None else authorization_token(capability=capability))
        dispatcher = GovernedActionDispatcher(
            gateway or self.gateway, authorization_token_provider=provider,
            authorization_secret=AUTH_SECRET, now_provider=lambda: now,
            approval_provider=approval_provider,
        )
        dispatcher.register_plan(plan)
        loop = self._loop(plan, dispatcher, action_id=action_id, observer=observer)
        loop.admit(plan, current_policy_revision=POLICY)
        state = loop.run(plan, owner_id=ACTOR, now=110, current_policy_revision=POLICY)
        return state, plan

    def _denied_reason(self):
        denied = [event for event in self._events() if event["event_type"] == "step.action_denied"]
        return denied[0]["reason_code"] if denied else None

    def _attempts(self):
        return len([event for event in self._events() if event["event_type"] == "step.attempted"])

    def test_authorized_dispatch_executes_and_finishes(self):
        state, _ = self._run()
        self.assertEqual(state.status, "finished")
        self.assertEqual(state.steps["inspect"]["status"], "verified_committed")
        self.assertIn("governed content", self.tool({"path": "README.md", "max_bytes": 100}).content)

    def test_missing_step_binding_fails_closed(self):
        from governed_dispatch import GovernedActionDispatcher

        plan = AgentPlan.from_dict(plan_value())
        dispatcher = GovernedActionDispatcher(
            self.gateway, authorization_token_provider=lambda: authorization_token(),
            authorization_secret=AUTH_SECRET, now_provider=lambda: 1_001,
        )  # deliberately not registered
        loop = self._loop(plan, dispatcher)
        loop.admit(plan, current_policy_revision=POLICY)
        state = loop.run(plan, owner_id=ACTOR, now=110, current_policy_revision=POLICY)
        # A step that was never dispatched must not pass on a favourable world state.
        self.assertNotEqual(state.status, "finished")
        self.assertEqual(self._denied_reason(), "UnboundAction")

    def test_capability_beyond_grant_is_denied(self):
        state, _ = self._run(token_factory=lambda: authorization_token(capability="workspace:write"))
        self.assertNotEqual(state.status, "finished")
        self.assertEqual(self._denied_reason(), "GovernanceDenied")

    def test_tool_scope_not_requested_is_denied(self):
        gateway = ActionGateway(approval_secret=APPROVAL_SECRET)
        gateway.register(ToolSpec(
            name="repo.read", required_capability="workspace:read",
            required_scope="workspace:write", resource_kind="workspace",
            risk_level="low", executor=lambda arguments: {"text": "unreachable"},
        ))
        state, _ = self._run(gateway=gateway)
        self.assertNotEqual(state.status, "finished")
        self.assertEqual(self._denied_reason(), "GovernanceDenied")

    def test_expired_grant_is_denied(self):
        # The grant lives for now+300s, so a later clock must void it.
        state, _ = self._run(token=authorization_token(now=1_000, expires_at=2_000), now=1_400)
        self.assertNotEqual(state.status, "finished")
        self.assertEqual(self._denied_reason(), "GovernanceDenied")

    def test_unregistered_tool_is_denied(self):
        empty = ActionGateway(approval_secret=APPROVAL_SECRET)  # no tools registered
        state, _ = self._run(gateway=empty)
        self.assertNotEqual(state.status, "finished")
        self.assertEqual(self._denied_reason(), "GovernanceDenied")

    def test_denied_step_is_redispatched_on_recovery(self):
        state, _ = self._run(
            token=authorization_token(now=1_000, expires_at=2_000), now=1_400, max_attempts=2)
        self.assertEqual(state.status, "paused_unknown")
        self.assertEqual(self._attempts(), 1)

        # Same evidence file, working authorization: the refused attempt must be
        # re-dispatched rather than waved through by observation.
        state, _ = self._run(max_attempts=2)
        self.assertEqual(state.status, "finished")
        self.assertEqual(self._attempts(), 2, "recovery must re-dispatch, not just observe")

    def test_denied_step_fails_closed_when_budget_is_spent(self):
        state, _ = self._run(
            token=authorization_token(now=1_000, expires_at=2_000), now=1_400)
        self.assertEqual(state.status, "paused_unknown")

        # Budget of one is already spent, and the world already looks correct.
        # Observation alone must never finish a step that never ran.
        state, _ = self._run()
        self.assertEqual(state.status, "failed")
        self.assertEqual(self._attempts(), 1)

    # --- high-risk tools: the approval gate must survive recovery ---

    def _write_gateway(self, calls):
        gateway = ActionGateway(approval_secret=APPROVAL_SECRET)
        gateway.register(ToolSpec(
            name="workspace.write_file", required_capability="workspace:write",
            required_scope="workspace:write", resource_kind="workspace", risk_level="high",
            executor=lambda arguments: (calls.append(arguments), {"status": "written"})[1],
        ))
        return gateway

    def _write_observer(self, calls):
        def observer(step, attempt_id):
            if not calls:
                return PostconditionResult("unknown", "write_unverified")
            return PostconditionResult("verified", "write_ok",
                                       "sha256:" + hashlib.sha256(b"written").hexdigest())
        return observer

    def _run_write(self, calls, *, approval_provider=None, max_attempts=1):
        return self._run(
            gateway=self._write_gateway(calls), capability="workspace:write",
            action_id="workspace.write_file", observer=self._write_observer(calls),
            scope=("workspace:write",), payload={"path": "notes.txt", "content": "x"},
            approval_provider=approval_provider, max_attempts=max_attempts,
        )

    def test_high_risk_tool_never_runs_without_approval(self):
        calls = []
        state, _ = self._run_write(calls)
        self.assertNotEqual(state.status, "finished")
        self.assertEqual(calls, [], "an unapproved high-risk tool must not reach the executor")
        self.assertEqual(self._denied_reason(), "GovernanceDenied")

    def test_high_risk_tool_runs_once_with_approval(self):
        calls = []
        state, _ = self._run_write(calls, approval_provider=lambda call: approval_for())
        self.assertEqual(state.status, "finished")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["path"], "notes.txt")

    def test_approval_arriving_later_is_redispatched_on_recovery(self):
        calls = []
        approved = {"ready": False}
        provider = lambda call: approval_for() if approved["ready"] else None

        state, _ = self._run_write(calls, approval_provider=provider, max_attempts=2)
        self.assertEqual(state.status, "paused_unknown")
        self.assertEqual(calls, [], "waiting for approval must not execute the tool")

        approved["ready"] = True
        state, _ = self._run_write(calls, approval_provider=provider, max_attempts=2)
        self.assertEqual(state.status, "finished")
        self.assertEqual(len(calls), 1, "the approved write must execute exactly once")

    def test_denied_high_risk_approval_is_sanitized(self):
        calls = []
        state, _ = self._run_write(
            calls, approval_provider=lambda call: approval_for(decision="denied"), max_attempts=2)
        self.assertNotEqual(state.status, "finished")
        self.assertEqual(calls, [], "a denied approval must not reach the executor")
        raw = self.evidence.read_text()
        reasons = {json.loads(line)["reason_code"] for line in raw.splitlines()}
        self.assertIn("GovernanceDenied", reasons, "the refusal kind must be traceable")
        self.assertNotIn("approval was denied", raw, "provider detail must not enter evidence")

    def test_each_attempt_uses_a_distinct_idempotency_key(self):
        from governed_dispatch import GovernedActionDispatcher

        plan = AgentPlan.from_dict(plan_value())
        seen = []

        def spy_executor(arguments):
            seen.append(arguments["path"])
            return {"text": "spy"}

        gateway = ActionGateway(approval_secret=APPROVAL_SECRET)
        gateway.register(ToolSpec(
            name="repo.read", required_capability="workspace:read",
            required_scope="workspace:read", resource_kind="workspace",
            risk_level="low", executor=spy_executor,
        ))
        dispatcher = GovernedActionDispatcher(
            gateway, authorization_token_provider=lambda: authorization_token(),
            authorization_secret=AUTH_SECRET, now_provider=lambda: 1_001,
        )
        dispatcher.register_plan(plan)
        actions = {"repo.read": dispatcher.bind("repo.read")}
        step = plan.steps[0]
        first = actions["repo.read"](step, "execution-x:attempt-1")
        second = actions["repo.read"](step, "execution-x:attempt-2")
        self.assertEqual(len(seen), 2, "a new attempt must really execute, not replay a cached result")
        self.assertEqual(first["text"], "spy")
        self.assertEqual(second["text"], "spy")


if __name__ == "__main__": unittest.main()
