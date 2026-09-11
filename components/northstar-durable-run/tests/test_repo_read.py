import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / "northstar-run-contract"))

from agent_loop import AgentLoop, PostconditionResult  # noqa: E402
from action_gateway import ToolExecutionFailed, ToolRefused  # noqa: E402
from durable_contract import RunContract  # noqa: E402
from openai_compatible_planner import (  # noqa: E402
    OpenAICompatiblePlannerCaller,
    OpenAICompatiblePlannerConfig,
)
from planner_adapter import TypedPlannerAdapter  # noqa: E402
from repo_read import RepoReadResult, RepoReadTool  # noqa: E402

RUN = RunContract.from_dict({
    "schema_version": "northstar.durable-run.v1",
    "task_id": "task-repo-001", "thread_id": "thread-repo-001",
    "run_id": "run-repo-001", "parent_run_id": None, "status": "planned",
    "deadline_at": 2_000, "scope_snapshot": ["workspace:read"],
    "trace_id": "trace-repo-001",
})


def provider_response(content):
    return json.dumps({
        "id": "response-1", "model": "ignored-by-host",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
    }).encode("utf-8")


class RepoReadToolTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name) / "repo"
        self.root.mkdir(mode=0o700)
        (self.root / "README.md").write_text("hello Northstar\n", encoding="utf-8")
        (self.root / "nested").mkdir()
        (self.root / "nested" / "file.txt").write_text("nested\n", encoding="utf-8")
        self.tool = RepoReadTool(self.root)

    def tearDown(self):
        self.tempdir.cleanup()

    def test_reads_relative_file_with_bounded_metadata_and_digest(self):
        result = self.tool({"path": "README.md", "max_bytes": 100})
        self.assertIsInstance(result, RepoReadResult)
        self.assertEqual(result.path, "README.md")
        self.assertEqual(result.content, "hello Northstar\n")
        self.assertEqual(result.size_bytes, len(result.content.encode()))
        self.assertEqual(result.digest, "sha256:" + hashlib.sha256(result.content.encode()).hexdigest())

    def test_missing_file_is_execution_failure_not_input_refusal(self):
        with self.assertRaises(ToolExecutionFailed):
            self.tool({"path": "missing.txt", "max_bytes": 100})

    def test_escape_path_remains_input_refusal(self):
        with self.assertRaises(ToolRefused):
            self.tool({"path": "../outside.txt", "max_bytes": 100})

    def test_symlink_path_remains_input_refusal(self):
        outside = Path(self.tempdir.name) / "outside.txt"
        outside.write_text("outside\n", encoding="utf-8")
        link = self.root / "link.txt"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaises(ToolRefused):
            self.tool({"path": "link.txt", "max_bytes": 100})

    def test_rejects_escape_absolute_directory_missing_and_invalid_payload(self):
        for payload in (
            {"path": "../outside", "max_bytes": 100},
            {"path": "/etc/passwd", "max_bytes": 100},
            {"path": "nested", "max_bytes": 100},
            {"path": "missing.txt", "max_bytes": 100},
            {"path": "README.md", "max_bytes": 0},
            {"path": "README.md", "max_bytes": 10, "extra": True},
            "README.md",
        ):
            with self.assertRaises(ValueError): self.tool(payload)

    def test_rejects_symlink_escape(self):
        outside = Path(self.tempdir.name) / "outside.txt"
        outside.write_text("secret\n", encoding="utf-8")
        link = self.root / "link.txt"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaises(ValueError): self.tool({"path": "link.txt", "max_bytes": 100})

    def test_enforces_read_bound(self):
        with self.assertRaises(ValueError): self.tool({"path": "README.md", "max_bytes": 5})


    def test_rejects_symlinked_intermediate_directory(self):
        outside = Path(self.tempdir.name) / "outside-dir"
        outside.mkdir()
        (outside / "secret.txt").write_text("secret\n", encoding="utf-8")
        try:
            (self.root / "linkdir").symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaises(ValueError): self.tool({"path": "linkdir/secret.txt", "max_bytes": 100})

    def test_host_root_may_contain_symlink_prefix_and_is_resolved_once(self):
        alias = Path(self.tempdir.name) / "alias"
        try:
            alias.symlink_to(self.root, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        alias_tool = RepoReadTool(alias)
        self.assertEqual(alias_tool({"path": "README.md", "max_bytes": 100}).content, "hello Northstar\n")

    def test_read_does_not_mutate_the_file(self):
        target = self.root / "README.md"
        before = (target.read_text(encoding="utf-8"), target.stat().st_mtime_ns)
        self.tool({"path": "README.md", "max_bytes": 100})
        self.assertEqual((target.read_text(encoding="utf-8"), target.stat().st_mtime_ns), before)

    def test_allowed_paths_allowlist_blocks_other_files(self):
        tool = RepoReadTool(self.root, allowed_paths=["README.md"])
        self.assertEqual(tool({"path": "README.md", "max_bytes": 100}).path, "README.md")
        with self.assertRaises(ValueError): tool({"path": "nested/file.txt", "max_bytes": 100})


class RepoReadGovernedPipelineTests(unittest.TestCase):
    """Prove the full planner -> admission -> real read -> independent verify path."""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name) / "repo"
        self.root.mkdir(mode=0o700)
        self.content = "hello Northstar\n"
        (self.root / "README.md").write_text(self.content, encoding="utf-8")
        self.tool = RepoReadTool(self.root, allowed_paths=["README.md"])
        self.evidence = Path(self.tempdir.name) / "evidence.jsonl"
        self.executions = []

    def tearDown(self):
        self.tempdir.cleanup()

    def _plan_value(self, *, path="README.md"):
        return {
            "schema_version": "northstar.agent-plan.v1", "plan_id": "plan-repo-001",
            "plan_version": 1, "task_id": RUN.task_id, "thread_id": RUN.thread_id,
            "run_id": RUN.run_id, "actor_id": "actor-task-repo-001",
            "workspace_id": "workspace-task-repo-001",
            "policy_revision": "policy-1", "trace_id": RUN.trace_id,
            "steps": [{
                "schema_version": "northstar.agent-plan-step.v1", "step_id": "inspect",
                "action_id": "repo.read", "input_payload": {"path": path, "max_bytes": 4096},
                "scope_snapshot": ["workspace:read"], "expected_postconditions": ["read_ok"],
                "idempotency_key": "task-repo-001-read-1", "max_attempts": 1, "deadline_at": 1_900,
            }],
        }

    def _loop(self, run, task, *, independent_readback=True):
        """Observer re-reads the path the step asked for, independently of the tool."""
        actor, workspace = f"actor-{task}", f"workspace-{task}"

        def observer(step, attempt_id):
            if not independent_readback:
                return PostconditionResult("unknown", "read_unverified")
            requested = step.input_payload.get("path", "")
            candidate = (self.root / requested).resolve()
            # Unverifiable outside the root: never claim success by assumption.
            if not candidate.is_relative_to(self.root) or not candidate.is_file():
                return PostconditionResult("unknown", "read_unverified")
            raw = candidate.read_bytes()
            return PostconditionResult("verified", "read_ok", "sha256:" + hashlib.sha256(raw).hexdigest())

        def action(step, attempt_id):
            self.executions.append((step.step_id, attempt_id))
            return self.tool(step.input_payload)

        return AgentLoop(RUN, self.evidence, actor_id=actor, workspace_id=workspace, actions={"repo.read": action}, observer=observer)

    def _run_admitted_plan(self, *, path="README.md", model_id="host-model"):
        task = "task-repo-001"
        plan_value = self._plan_value(path=path)
        run = RUN
        caller = OpenAICompatiblePlannerCaller(
            OpenAICompatiblePlannerConfig(
                endpoint="https://planner.example/v1/chat/completions",
                api_key_env="TEST_PLANNER_API_KEY",
                model_id=model_id, provider="host-provider", model_revision="rev-1",
            ),
            transport=lambda request, timeout: provider_response(json.dumps({"plan": plan_value})),
        )
        loop = self._loop(run, task)
        with mock.patch.dict(os.environ, {"TEST_PLANNER_API_KEY": "fixture-key"}, clear=False):
            result = TypedPlannerAdapter(caller).generate(
                "Inspect README", context={}, loop=loop,
                current_policy_revision="policy-1", owner_id=f"actor-{task}", now=100,
            )
        return loop, result.candidate, result

    def test_governed_pipeline_reads_real_file_and_finishes(self):
        loop, plan, result = self._run_admitted_plan()
        self.assertEqual(result.model_id, "host-model")
        state = loop.run(plan, owner_id="actor-task-repo-001", now=110, current_policy_revision="policy-1")
        self.assertEqual(state.status, "finished")
        self.assertEqual(state.steps["inspect"]["status"], "verified_committed")
        self.assertEqual([execution[0] for execution in self.executions], ["inspect"])
        self.assertEqual(state.steps["inspect"]["observed_digest"], "sha256:" + hashlib.sha256(self.content.encode()).hexdigest())

    def test_escape_path_is_rejected_and_never_finishes(self):
        loop, plan, _ = self._run_admitted_plan(path="../outside.txt")
        state = loop.run(plan, owner_id="actor-task-repo-001", now=110, current_policy_revision="policy-1")
        self.assertNotEqual(state.status, "finished")
        self.assertFalse((Path(self.tempdir.name) / "outside.txt").exists())
        events = [json.loads(line) for line in self.evidence.read_text().splitlines()]
        self.assertIn("step.action_failed", [event["event_type"] for event in events])

    def test_host_metadata_cannot_be_overridden_by_model_payload(self):
        loop, plan, result = self._run_admitted_plan()
        self.assertEqual((result.provider, result.model_revision), ("host-provider", "rev-1"))
        self.assertNotIn("model", plan.to_dict())


if __name__ == "__main__": unittest.main()
