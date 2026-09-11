import json
import os
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / "northstar-run-contract"))
sys.path.insert(0, str(ROOT.parent / "northstar-host"))

from live_benchmark import (  # noqa: E402
    UsageRecorderTransport,
    load_live_tasks,
    run_live_benchmark,
)


class LiveBenchmarkTests(unittest.TestCase):
    def setUp(self):
        self._environment = mock.patch.dict(
            os.environ, {"TEST_PLANNER_API_KEY": "fixture-key"}, clear=False
        )
        self._environment.start()

    def tearDown(self):
        self._environment.stop()

    def fixture(self, root, task_id="fixture-001"):
        path = root / f"{task_id}.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": "northstar.live-task.v1",
                    "task_id": task_id,
                    "goal": "Read README.md and write out/report.md with the word ready.",
                    "rounds": 2,
                    "seed": {"README.md": "write out/report.md\n"},
                    "expect": [{"path": "out/report.md", "contains": ["ready"]}],
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_loader_accepts_directory_and_rejects_duplicate_ids(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root, "one")
            tasks = load_live_tasks(root)
            self.assertEqual(len(tasks), 1)
            self.assertEqual(tasks[0]["task_id"], "one")
            duplicate = root / "duplicate.json"
            duplicate.write_text((root / "one.json").read_text(), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_live_tasks(root)

    def test_loader_rejects_malformed_expectation(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bad.json"
            path.write_text(
                json.dumps(
                    {
                        "task_id": "bad",
                        "goal": "x",
                        "seed": {},
                        "expect": [{"path": "x", "contains": []}],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_live_tasks(path)

    def test_loader_rejects_seed_path_escape_and_absolute_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, seed_path in enumerate(("../escape.txt", "/tmp/escape.txt")):
                path = root / f"bad-{index}.json"
                path.write_text(
                    json.dumps(
                        {
                            "task_id": f"bad-{index}",
                            "goal": "x",
                            "seed": {seed_path: "no"},
                            "expect": [],
                        }
                    ),
                    encoding="utf-8",
                )
                with self.assertRaises(ValueError):
                    load_live_tasks(path)

    def test_usage_recorder_keeps_only_provider_usage_metadata(self):
        requests = []

        def transport(request, timeout):
            requests.append(request)
            return json.dumps(
                {
                    "choices": [{"message": {"content": "ignored"}, "finish_reason": "stop"}],
                    "usage": {
                        "cost": 0.0012,
                        "prompt_tokens": 10,
                        "completion_tokens": 20,
                        "total_tokens": 30,
                    },
                }
            ).encode("utf-8")

        recorder = UsageRecorderTransport(transport)
        raw = recorder(object(), 3.0)
        self.assertEqual(json.loads(raw)["usage"]["total_tokens"], 30)
        self.assertEqual(recorder.records, [{
            "cost": 0.0012,
            "prompt_tokens": 10,
            "completion_tokens": 20,
            "total_tokens": 30,
        }])
        self.assertEqual(len(requests), 1)
        self.assertNotIn("ignored", recorder.records.__repr__())

    def test_fake_planner_runs_task_and_reports_usage_and_success(self):
        def fake_transport(request, timeout):
            body = json.loads(request.data.decode("utf-8"))
            user = json.loads(body["messages"][1]["content"])
            context = user["context"]
            step = {
                "schema_version": "northstar.agent-plan-step.v1",
                "step_id": "read-readme",
                "action_id": "repo.read",
                "input_payload": {"path": "README.md", "max_bytes": 4096},
                "scope_snapshot": ["workspace:read"],
                "expected_postconditions": ["read_ok"],
                "idempotency_key": f"read-{context['run_id']}",
                "max_attempts": 1,
                "deadline_at": context["deadline_at"] - 10,
            }
            if context.get("observations", {}).get("README.md"):
                step = {
                    "schema_version": "northstar.agent-plan-step.v1",
                    "step_id": "write-report",
                    "action_id": "workspace.write",
                    "input_payload": {"path": "out/report.md", "content": "ready\n"},
                    "scope_snapshot": ["workspace:write"],
                    "expected_postconditions": ["content_matches_payload"],
                    "idempotency_key": f"write-{context['run_id']}",
                    "max_attempts": 1,
                    "deadline_at": context["deadline_at"] - 10,
                }
            plan = {
                "schema_version": "northstar.agent-plan.v1",
                "plan_id": f"plan-{context['run_id']}",
                "plan_version": 1,
                "task_id": context["task_id"],
                "thread_id": context["thread_id"],
                "run_id": context["run_id"],
                "actor_id": context["actor_id"],
                "workspace_id": context["workspace_id"],
                "policy_revision": context["policy_revision"],
                "trace_id": context["trace_id"],
                "steps": [step],
            }
            return json.dumps(
                {
                    "choices": [{"message": {"content": json.dumps({"plan": plan})}, "finish_reason": "stop"}],
                    "usage": {"cost": 0.0002, "prompt_tokens": 50, "completion_tokens": 40, "total_tokens": 90},
                }
            ).encode("utf-8")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            task_path = self.fixture(root / "tasks") if False else None
            tasks_dir = root / "tasks"
            tasks_dir.mkdir()
            self.fixture(tasks_dir)
            report = run_live_benchmark(
                load_live_tasks(tasks_dir),
                endpoint="https://planner.example/v1/chat/completions",
                key_env="TEST_PLANNER_API_KEY",
                model="fixture/model",
                provider="fixture",
                model_revision="rev-1",
                reasoning_effort="off",
                max_output_tokens=1024,
                sandbox=root / "sandbox",
                transport_factory=lambda task: fake_transport,
            )
        self.assertEqual(report["summary"]["total"], 1)
        self.assertEqual(report["summary"]["ok"], 1)
        self.assertEqual(report["summary"]["success_rate"], 1.0)
        self.assertEqual(report["summary"]["total_model_calls"], 2)
        self.assertEqual(report["summary"]["recovered_tasks"], 1)
        self.assertAlmostEqual(report["summary"]["total_cost"], 0.0004)

    def test_failed_task_is_counted_as_failed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tasks_dir = root / "tasks"
            tasks_dir.mkdir()
            path = self.fixture(tasks_dir, "failed")
            value = json.loads(path.read_text())
            value["expect"] = [{"path": "out/report.md", "content": "never"}]
            path.write_text(json.dumps(value), encoding="utf-8")

            def invalid_transport(request, timeout):
                body = json.loads(request.data.decode("utf-8"))
                context = json.loads(body["messages"][1]["content"])["context"]
                plan = {
                    "schema_version": "northstar.agent-plan.v1",
                    "plan_id": "plan-failed",
                    "plan_version": 1,
                    "task_id": context["task_id"],
                    "thread_id": context["thread_id"],
                    "run_id": context["run_id"],
                    "actor_id": context["actor_id"],
                    "workspace_id": context["workspace_id"],
                    "policy_revision": context["policy_revision"],
                    "trace_id": context["trace_id"],
                    "steps": [{
                        "schema_version": "northstar.agent-plan-step.v1",
                        "step_id": "write",
                        "action_id": "workspace.write",
                        "input_payload": {"path": "out/report.md", "content": "wrong"},
                        "scope_snapshot": ["workspace:write"],
                        "expected_postconditions": ["content_matches_payload"],
                        "idempotency_key": f"write-{context['run_id']}",
                        "max_attempts": 1,
                        "deadline_at": context["deadline_at"] - 10,
                    }],
                }
                return json.dumps({"choices": [{"message": {"content": json.dumps({"plan": plan})}}], "usage": {"cost": 0}}).encode()

            report = run_live_benchmark(
                load_live_tasks(tasks_dir),
                endpoint="https://planner.example/v1/chat/completions",
                key_env="TEST_PLANNER_API_KEY",
                model="fixture/model",
                provider="fixture",
                model_revision="rev-1",
                reasoning_effort="off",
                max_output_tokens=1024,
                sandbox=root / "sandbox",
                transport_factory=lambda task: invalid_transport,
            )
        self.assertEqual(report["summary"]["ok"], 0)
        self.assertEqual(report["summary"]["success_rate"], 0.0)
        self.assertFalse(report["tasks"][0]["ok"])


if __name__ == "__main__":
    unittest.main()
