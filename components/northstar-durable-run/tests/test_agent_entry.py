import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / "northstar-run-contract"))
sys.path.insert(0, str(ROOT.parent / "northstar-host"))

from agent_entry import (  # noqa: E402
    READ_ACTION,
    WRITE_ACTION,
    AgentHarness,
    ExpectedArtifact,
    build_run,
)
from agent_loop import PostconditionResult  # noqa: E402
from planner_adapter import PlannerModelResponse, TypedPlannerAdapter  # noqa: E402


def step_value(step_id, action_id, payload, postconditions, *, key=None, attempts=2):
    scope = "workspace:read" if action_id == READ_ACTION else "workspace:write"
    return {
        "schema_version": "northstar.agent-plan-step.v1",
        "step_id": step_id,
        "action_id": action_id,
        "input_payload": payload,
        "scope_snapshot": [scope],
        "expected_postconditions": list(postconditions),
        "idempotency_key": key or f"{step_id}-key-1",
        "max_attempts": attempts,
        "deadline_at": 690,
    }


def plan_value(run, steps, *, workspace_id="workspace-agent-001", actor_id="actor-agent-001"):
    return {
        "schema_version": "northstar.agent-plan.v1",
        "plan_id": "plan-1",
        "plan_version": 1,
        "task_id": run.task_id,
        "thread_id": run.thread_id,
        "run_id": run.run_id,
        "actor_id": actor_id,
        "workspace_id": workspace_id,
        "policy_revision": "policy-agent-1",
        "trace_id": run.trace_id,
        "steps": steps,
    }


class ScriptedCaller:
    """Stand-in for a model caller: deterministic fixture, host-declared identity."""

    def __init__(self, value, *, fail_first=False):
        self.value = value
        self.fail_first = fail_first
        self.calls = []

    def __call__(self, *, goal, context, repair_error, attempt):
        self.calls.append({"goal": goal, "context": context, "repair_error": repair_error})
        if self.fail_first and len(self.calls) == 1:
            return PlannerModelResponse("not json at all", "scripted-planner", "fixture", "rev-1")
        return PlannerModelResponse(
            json.dumps({"plan": self.value}), "scripted-planner", "fixture", "rev-1"
        )


class AgentEntryTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir(mode=0o700)
        (self.workspace / "README.md").write_text("handbook\n", encoding="utf-8")
        self.run = build_run("agent-001", clock=lambda: 100)
        self.harness = AgentHarness(
            self.run,
            self.workspace,
            self.root / "evidence.jsonl",
            actor_id="actor-agent-001",
            workspace_id="workspace-agent-001",
            clock=lambda: 100,
            secrets={
                "binding": b"b" * 32,
                "authorization": b"a" * 32,
                "approval": b"p" * 32,
            },
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def planner(self, steps, **kwargs):
        return TypedPlannerAdapter(ScriptedCaller(plan_value(self.run, steps), **kwargs))

    def events(self, name="evidence.jsonl"):
        raw = (self.root / name).read_text(encoding="utf-8")
        return [json.loads(line) for line in raw.splitlines()]

    def test_multi_step_task_delivers_two_verified_files(self):
        steps = [
            step_value("inspect", READ_ACTION, {"path": "README.md", "max_bytes": 4096}, ["read_ok"]),
            step_value(
                "write-report",
                WRITE_ACTION,
                {"path": "reports/summary.txt", "content": "summary: handbook\n"},
                ["content_matches_payload"],
            ),
            step_value(
                "write-index",
                WRITE_ACTION,
                {"path": "reports/index.txt", "content": "index\n"},
                ["content_matches_payload"],
            ),
        ]
        outcome = self.harness.run_goal(
            "Summarize the handbook into two files",
            self.planner(steps),
            expectations=[
                ExpectedArtifact("reports/summary.txt", content="summary: handbook\n"),
                ExpectedArtifact("reports/index.txt", content="index\n"),
                ExpectedArtifact("reports/absent.txt", absent=True),
            ],
        )
        self.assertTrue(outcome.ok)
        self.assertEqual(outcome.run_status, "finished")
        self.assertEqual([item.status for item in outcome.steps], ["verified_committed"] * 3)
        self.assertEqual((self.workspace / "reports" / "summary.txt").read_text(), "summary: handbook\n")
        self.assertEqual(outcome.verification.verdict, "verified")
        self.assertEqual(outcome.verification.checked, ("reports/summary.txt", "reports/index.txt", "reports/absent.txt"))

    def test_finished_run_with_unmet_expectation_is_not_a_done_task(self):
        steps = [
            step_value(
                "write-report",
                WRITE_ACTION,
                {"path": "report.txt", "content": "draft\n"},
                ["content_matches_payload"],
            )
        ]
        outcome = self.harness.run_goal(
            "Write the report",
            self.planner(steps),
            expectations=[ExpectedArtifact("report.txt", content="final\n")],
        )
        self.assertEqual(outcome.run_status, "finished")
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.verification.verdict, "failed")
        self.assertEqual(outcome.verification.failures, ("report.txt:content_mismatch",))

    def test_missing_artifact_is_reported_as_missing(self):
        steps = [
            step_value(
                "write-report",
                WRITE_ACTION,
                {"path": "report.txt", "content": "draft\n"},
                ["content_matches_payload"],
            )
        ]
        outcome = self.harness.run_goal(
            "Write the report",
            self.planner(steps),
            expectations=[ExpectedArtifact("other.txt", content="x\n")],
        )
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.verification.failures, ("other.txt:missing",))

    def test_escape_path_is_refused_and_never_leaves_the_root(self):
        steps = [
            step_value(
                "escape",
                WRITE_ACTION,
                {"path": "../escape.txt", "content": "nope\n"},
                ["content_matches_payload"],
            )
        ]
        outcome = self.harness.run_goal("Write outside", self.planner(steps))
        self.assertNotEqual(outcome.run_status, "finished")
        self.assertFalse(outcome.ok)
        self.assertFalse((self.root / "escape.txt").exists())
        self.assertIn("step.action_denied", [event["event_type"] for event in self.events()])

    def test_write_outside_the_allowlist_is_refused(self):
        harness = AgentHarness(
            self.run,
            self.workspace,
            self.root / "evidence-allow.jsonl",
            actor_id="actor-agent-001",
            workspace_id="workspace-agent-001",
            clock=lambda: 100,
            allowed_write_paths=["reports/ok.txt"],
        )
        steps = [
            step_value(
                "write-other",
                WRITE_ACTION,
                {"path": "other.txt", "content": "x\n"},
                ["content_matches_payload"],
            )
        ]
        outcome = harness.run_goal("Write elsewhere", self.planner(steps))
        self.assertFalse(outcome.ok)
        self.assertFalse((self.workspace / "other.txt").exists())

    def test_transient_action_failure_recovers_within_the_attempt_budget(self):
        def fail_first_call(step, attempt_id, ordinal):
            if ordinal == 1:
                raise RuntimeError("injected transient failure")

        harness = AgentHarness(
            self.run,
            self.workspace,
            self.root / "evidence-transient.jsonl",
            actor_id="actor-agent-001",
            workspace_id="workspace-agent-001",
            clock=lambda: 100,
            faults={WRITE_ACTION: fail_first_call},
        )
        steps = [
            step_value(
                "write-report",
                WRITE_ACTION,
                {"path": "report.txt", "content": "final\n"},
                ["content_matches_payload"],
            )
        ]
        outcome = harness.run_goal(
            "Write the report",
            self.planner(steps),
            expectations=[ExpectedArtifact("report.txt", content="final\n")],
        )
        self.assertTrue(outcome.ok)
        self.assertEqual(outcome.steps[0].attempts, 2)
        self.assertIn(
            "step.action_failed",
            [event["event_type"] for event in self.events("evidence-transient.jsonl")],
        )

    def test_unknown_observation_pauses_then_the_harness_resumes_autonomously(self):
        def unknown_once(step, attempt_id, ordinal):
            if ordinal == 1:
                return PostconditionResult("unknown", "observer_unavailable")
            return None

        harness = AgentHarness(
            self.run,
            self.workspace,
            self.root / "evidence-resume.jsonl",
            actor_id="actor-agent-001",
            workspace_id="workspace-agent-001",
            clock=lambda: 100,
            observer_hook=unknown_once,
        )
        steps = [
            step_value(
                "write-report",
                WRITE_ACTION,
                {"path": "report.txt", "content": "final\n"},
                ["content_matches_payload"],
            )
        ]
        outcome = harness.run_goal(
            "Write the report",
            self.planner(steps),
            expectations=[ExpectedArtifact("report.txt", content="final\n")],
        )
        self.assertTrue(outcome.ok)
        self.assertEqual(outcome.resumes, 1)
        self.assertEqual(outcome.run_status, "finished")
        self.assertIn(
            "loop.paused", [event["event_type"] for event in self.events("evidence-resume.jsonl")]
        )

    def test_plan_cannot_redefine_host_identity(self):
        steps = [
            step_value(
                "write-report",
                WRITE_ACTION,
                {"path": "report.txt", "content": "x\n"},
                ["content_matches_payload"],
            )
        ]
        adapter = TypedPlannerAdapter(
            ScriptedCaller(plan_value(self.run, steps, workspace_id="workspace-someone-else"))
        )
        with self.assertRaises(ValueError):
            self.harness.run_goal("Write the report", adapter)

    def test_planner_repair_is_used_once_and_reported(self):
        steps = [
            step_value(
                "write-report",
                WRITE_ACTION,
                {"path": "report.txt", "content": "x\n"},
                ["content_matches_payload"],
            )
        ]
        adapter = TypedPlannerAdapter(ScriptedCaller(plan_value(self.run, steps), fail_first=True))
        outcome = self.harness.run_goal("Write the report", adapter)
        self.assertTrue(outcome.ok)
        self.assertEqual(outcome.planner_attempts, 2)

    def test_planner_context_carries_tool_schema_and_no_secrets(self):
        captured = {}

        class Recorder(ScriptedCaller):
            def __call__(self, **kwargs):
                captured.update(kwargs["context"])
                return super().__call__(**kwargs)

        steps = [
            step_value(
                "write-report",
                WRITE_ACTION,
                {"path": "report.txt", "content": "x\n"},
                ["content_matches_payload"],
            )
        ]
        adapter = TypedPlannerAdapter(Recorder(plan_value(self.run, steps)))
        self.harness.run_goal("Write the report", adapter)
        self.assertEqual(captured["run_id"], self.run.run_id)
        self.assertEqual(captured["deadline_at"], self.run.deadline_at)
        self.assertEqual(
            [action["action_id"] for action in captured["actions"]], [READ_ACTION, WRITE_ACTION]
        )
        rendered = json.dumps(captured).lower()
        self.assertNotIn("secret", rendered)
        self.assertNotIn("api_key", rendered)

    def test_run_goal_twice_on_the_same_plan_is_not_rebound(self):
        steps = [
            step_value(
                "write-report",
                WRITE_ACTION,
                {"path": "report.txt", "content": "x\n"},
                ["content_matches_payload"],
            )
        ]
        planner = self.planner(steps)
        first = self.harness.run_goal("Write the report", planner)
        second = self.harness.run_goal("Write the report", planner)
        self.assertTrue(first.ok)
        self.assertTrue(second.ok)


class AgentEntryCliTests(unittest.TestCase):
    def test_cli_runs_a_host_supplied_plan_and_reports_json(self):
        from contextlib import redirect_stdout
        import io
        import time

        from agent_entry import main

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir(mode=0o700)
            now = int(time.time())
            steps_path = root / "steps.json"
            steps_path.write_text(
                json.dumps(
                    [
                        {
                            "schema_version": "northstar.agent-plan-step.v1",
                            "step_id": "write-report",
                            "action_id": WRITE_ACTION,
                            "input_payload": {"path": "report.txt", "content": "cli\n"},
                            "scope_snapshot": ["workspace:write"],
                            "expected_postconditions": ["content_matches_payload"],
                            "idempotency_key": "cli-write-1",
                            "max_attempts": 1,
                            "deadline_at": now + 300,
                        }
                    ]
                ),
                encoding="utf-8",
            )
            expect_path = root / "expect.json"
            expect_path.write_text(
                json.dumps([{"path": "report.txt", "content": "cli\n"}]), encoding="utf-8"
            )
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = main(
                    [
                        "--task-id", "cli-001",
                        "--goal", "Write the report",
                        "--workspace", str(workspace),
                        "--steps", str(steps_path),
                        "--expect", str(expect_path),
                    ]
                )
            report = json.loads(buffer.getvalue())
            self.assertEqual(code, 0)
            self.assertTrue(report["ok"])
            self.assertEqual(report["run_status"], "finished")
            self.assertEqual((workspace / "report.txt").read_text(encoding="utf-8"), "cli\n")

    def test_cli_exits_nonzero_when_the_deliverable_is_unmet(self):
        from contextlib import redirect_stdout
        import io
        import time

        from agent_entry import main

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir(mode=0o700)
            now = int(time.time())
            (root / "steps.json").write_text(
                json.dumps(
                    [
                        {
                            "schema_version": "northstar.agent-plan-step.v1",
                            "step_id": "write-report",
                            "action_id": WRITE_ACTION,
                            "input_payload": {"path": "report.txt", "content": "draft\n"},
                            "scope_snapshot": ["workspace:write"],
                            "expected_postconditions": ["content_matches_payload"],
                            "idempotency_key": "cli-write-2",
                            "max_attempts": 1,
                            "deadline_at": now + 300,
                        }
                    ]
                ),
                encoding="utf-8",
            )
            (root / "expect.json").write_text(
                json.dumps([{"path": "report.txt", "content": "final\n"}]), encoding="utf-8"
            )
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = main(
                    [
                        "--task-id", "cli-002",
                        "--goal", "Write the report",
                        "--workspace", str(workspace),
                        "--steps", str(root / "steps.json"),
                        "--expect", str(root / "expect.json"),
                    ]
                )
            self.assertEqual(code, 1)
            self.assertIn("content_mismatch", buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
