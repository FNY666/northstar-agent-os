"""R25: repo.read payload shape is rejected during admission, not execution."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT.parent / "northstar-host"),
                str(ROOT.parent / "northstar-run-contract")]

from agent_entry import AgentHarness, READ_ACTION  # noqa: E402
from durable_contract import RunContract  # noqa: E402
from repo_read import RepoReadTool  # noqa: E402


def run_contract():
    return RunContract.from_dict({
        "schema_version": "northstar.durable-run.v1",
        "task_id": "task-read-r25", "thread_id": "thread-read-r25",
        "run_id": "run-read-r25", "parent_run_id": None,
        "status": "planned", "deadline_at": 2_000,
        "scope_snapshot": ["workspace:read"], "trace_id": "trace-read-r25",
    })


def step(payload):
    return {
        "schema_version": "northstar.agent-plan-step.v1",
        "step_id": "read-1", "action_id": READ_ACTION,
        "input_payload": payload, "scope_snapshot": ["workspace:read"],
        "expected_postconditions": ["read_ok"],
        "idempotency_key": "read-key-1", "max_attempts": 1,
        "deadline_at": 1_900,
    }


def candidate(plan_value):
    return {
        "schema_version": "northstar.planner-candidate.v1",
        "plan": plan_value,
        "model_id": "r25-model",
        "provider": "r25-provider",
        "model_revision": "r25-rev",
    }


def plan(run, payload):
    return {
        "schema_version": "northstar.agent-plan.v1",
        "plan_id": "plan-r25", "plan_version": 1,
        "task_id": run.task_id, "thread_id": run.thread_id,
        "run_id": run.run_id, "actor_id": "actor-r25",
        "workspace_id": "workspace-r25", "policy_revision": "policy-agent-1",
        "trace_id": run.trace_id, "steps": [step(payload)],
    }


class ReadAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        (root / "data").mkdir()
        (root / "data" / "records.csv").write_text("name,score\nA,1\n", encoding="utf-8")
        self.harness = AgentHarness(
            run_contract(), root, root / "evidence.jsonl",
            actor_id="actor-r25", workspace_id="workspace-r25",
            allowed_read_paths=["data/records.csv"], clock=lambda: 100,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_valid_repo_read_payload_is_admitted(self):
        self.harness.loop.admit(
            plan(self.harness.run, {"path": "data/records.csv", "max_bytes": 4096}),
            current_policy_revision="policy-agent-1",
        )

    def test_bad_repo_read_payload_is_rejected_at_admission_with_field_reason(self):
        cases = [
            ({"path": "data/records.csv", "max_bytes": "4096"}, "max_bytes"),
            ({"path": "data/records.csv", "max_bytes": 4096.0}, "max_bytes"),
            ({"path": "data/records.csv", "max_bytes": True}, "max_bytes"),
            ({"path": "data/records.csv", "max_bytes": 65537}, "max_bytes"),
            ({"path": "data/records.csv", "max_bytes": 0}, "max_bytes"),
            ({"path": "data/records.csv"}, "max_bytes"),
            ({"path": "data/records.csv", "max_bytes": 4096, "extra": True}, "payload"),
            ({"path": "../records.csv", "max_bytes": 4096}, "path"),
        ]
        for payload, field in cases:
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(ValueError, field):
                    self.harness.loop.admit(
                        plan(self.harness.run, payload),
                        current_policy_revision="policy-agent-1",
                    )

    def test_executor_still_rejects_bad_payload_when_admission_is_bypassed(self):
        tool = RepoReadTool(Path(self.tmp.name), allowed_paths=["data/records.csv"])
        with self.assertRaises(ValueError):
            tool({"path": "data/records.csv", "max_bytes": "4096"})

    def test_planner_can_repair_admission_shape_error(self):
        from planner_adapter import PlannerModelResponse, TypedPlannerAdapter
        bad = plan(self.harness.run, {"path": "data/records.csv", "max_bytes": "4096"})
        good = plan(self.harness.run, {"path": "data/records.csv", "max_bytes": 4096})
        calls = []
        def caller(*, goal, context, repair_error, attempt):
            calls.append(repair_error)
            value = candidate(bad if attempt == 1 else good)
            return PlannerModelResponse(json.dumps(value), "m", "p", "r")
        adapter = TypedPlannerAdapter(caller, max_attempts=2)
        result = adapter.generate(
            "read records", context={}, loop=self.harness.loop,
            current_policy_revision="policy-agent-1", owner_id="actor-r25", now=100,
        )
        self.assertEqual(result.attempts, 2)
        self.assertIsNone(calls[0])
        self.assertIn("repo.read max_bytes is invalid", calls[1])

    def test_missing_file_with_valid_shape_is_admitted(self):
        self.harness.loop.admit(
            plan(self.harness.run, {"path": "data/missing.csv", "max_bytes": 4096}),
            current_policy_revision="policy-agent-1",
        )

    def test_executor_shape_refusal_has_fixed_safe_reason(self):
        tool = RepoReadTool(Path(self.tmp.name), allowed_paths=["data/records.csv"])
        with self.assertRaises(ValueError) as ctx:
            tool({"path": "data/records.csv", "max_bytes": "sk-secret"})
        self.assertEqual(getattr(ctx.exception, "safe_reason", None), "payload_shape_invalid")
        self.assertNotIn("sk-secret", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
