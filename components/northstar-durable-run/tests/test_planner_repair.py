"""R22: the planner retry loop must carry a bounded, redacted repair reason."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT)]

from planner_adapter import (  # noqa: E402
    TypedPlannerAdapter,
    PlannerModelCallFailed,
    PlannerModelResponse,
    bounded_error_detail,
)
from agent_loop import AgentPlan, AgentLoop  # noqa: E402

_CANDIDATE_SCHEMA = "northstar.planner-candidate.v1"
_PLAN_SCHEMA = "northstar.agent-plan.v1"
_STEP_SCHEMA = "northstar.agent-plan-step.v1"


def _valid_plan_value():
    return {
        "schema_version": _PLAN_SCHEMA,
        "plan_id": "plan-1", "plan_version": 1, "task_id": "task-1",
        "thread_id": "thread-1", "run_id": "run-1", "actor_id": "actor-1",
        "workspace_id": "ws-1", "policy_revision": "policy-1",
        "trace_id": "trace-1",
        "steps": [{
            "schema_version": _STEP_SCHEMA,
            "step_id": "s1", "action_id": "workspace.list",
            "input_payload": {},
            "scope_snapshot": ["workspace:read"],
            "expected_postconditions": ["listing_ok"],
            "idempotency_key": "k1", "max_attempts": 1,
            "deadline_at": 2_000_000_000,
        }],
    }


def _candidate(plan_value, model_id="test-model"):
    return {
        "schema_version": _CANDIDATE_SCHEMA,
        "plan": plan_value,
        "model_id": model_id,
        "provider": "test-provider",
        "model_revision": "rev-1",
    }


def _response(candidate):
    return PlannerModelResponse(
        content=json.dumps(candidate),
        model_id=candidate["model_id"],
        provider=candidate["provider"],
        model_revision=candidate["model_revision"],
    )


def _bad_scope_plan():
    plan = _valid_plan_value()
    plan["steps"][0]["scope_snapshot"] = ["not-a-scope"]
    return plan


class BoundedRepairDetailTests(unittest.TestCase):
    def test_value_error_message_is_preserved(self) -> None:
        detail = bounded_error_detail(
            ValueError("scope_snapshot contains an invalid or duplicate scope")
        )
        self.assertEqual(
            detail, "scope_snapshot contains an invalid or duplicate scope"
        )

    def test_non_value_error_stays_opaque(self) -> None:
        for error in (RuntimeError("boom"), KeyError("k")):
            self.assertIsNone(bounded_error_detail(error))

    def test_credential_shaped_tokens_are_redacted(self) -> None:
        detail = bounded_error_detail(
            ValueError("rejected key sk-abcdef1234567890 for tenant acme")
        )
        self.assertNotIn("sk-abcdef1234567890", detail)
        self.assertIn("<redacted>", detail)
        self.assertIn("tenant acme", detail)

    def test_message_is_bounded_and_single_line(self) -> None:
        detail = bounded_error_detail(ValueError("x" * 5000 + "\n\ttail"))
        self.assertEqual(len(detail), 400)
        self.assertNotIn("\n", detail)


class RepairLoopTests(unittest.TestCase):
    def _make_adapter(self, responses):
        calls = []

        def model_caller(*, goal, context, repair_error, attempt):
            calls.append({"repair_error": repair_error, "attempt": attempt})
            return responses[min(attempt - 1, len(responses) - 1)]

        adapter = TypedPlannerAdapter(model_caller, max_attempts=2)
        loop = mock.MagicMock(spec=AgentLoop)
        loop.admit.side_effect = lambda plan, **kw: plan
        return adapter, loop, calls

    def test_second_attempt_receives_the_validator_reason(self) -> None:
        bad = _response(_candidate(_bad_scope_plan()))
        good = _response(_candidate(_valid_plan_value()))
        adapter, loop, calls = self._make_adapter([bad, good])

        result = adapter.generate(
            "test goal", context={}, loop=loop,
            current_policy_revision="policy-1", owner_id="owner-1", now=1,
        )
        self.assertEqual(len(calls), 2)
        self.assertIsNone(calls[0]["repair_error"])
        self.assertIn(
            "scope_snapshot contains an invalid or duplicate scope",
            calls[1]["repair_error"],
            "repair_error must name the failing field, not just 'ValueError'",
        )

    def test_exhausted_retries_raise_with_the_reason(self) -> None:
        bad = _response(_candidate(_bad_scope_plan()))
        adapter, loop, calls = self._make_adapter([bad])
        with self.assertRaises(PlannerModelCallFailed) as ctx:
            adapter.generate(
                "test goal", context={}, loop=loop,
                current_policy_revision="policy-1", owner_id="owner-1", now=1,
            )
        self.assertIn("scope_snapshot", str(ctx.exception.detail))
        self.assertNotIn("sk-", str(ctx.exception.detail))


if __name__ == "__main__":
    unittest.main()
