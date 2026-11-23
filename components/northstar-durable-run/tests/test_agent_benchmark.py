import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / "northstar-run-contract"))
sys.path.insert(0, str(ROOT.parent / "northstar-host"))

from agent_benchmark import (  # noqa: E402
    BenchmarkTask,
    load_tasks,
    run_benchmark,
    run_task,
)


class AgentBenchmarkTests(unittest.TestCase):
    def test_every_fixture_task_completes_and_is_independently_verified(self):
        report = run_benchmark(load_tasks())
        summary = report["summary"]
        self.assertEqual(summary["total"], 5)
        self.assertEqual(summary["ok"], summary["total"])
        self.assertEqual(summary["success_rate"], 1.0)
        self.assertEqual(summary["finished"], summary["total"])
        self.assertEqual(summary["verified"], summary["total"])
        self.assertEqual(summary["steps_verified"], summary["steps"])
        self.assertEqual(summary["faults_injected"], 2)
        self.assertEqual(summary["faults_recovered"], summary["faults_injected"])
        self.assertTrue(all(record["ok"] for record in report["tasks"]))

    def test_fault_tasks_really_pause_and_really_retry(self):
        report = run_benchmark(load_tasks())
        records = {record["task_id"]: record for record in report["tasks"]}
        self.assertEqual(records["bench-observer-pause-recovery"]["resumes"], 1)
        self.assertGreater(
            records["bench-transient-recovery"]["evidence_events"],
            records["bench-nested-deliverable"]["evidence_events"],
        )

    def test_report_fails_when_the_deliverable_does_not_match(self):
        """A finished run with an unmet host expectation must not count as done."""
        task = BenchmarkTask.from_dict(
            {
                "task_id": "unmet-expectation",
                "goal": "Write a report that does not match the requirement.",
                "steps": [
                    {
                        "step_id": "write-report",
                        "action_id": "workspace.write",
                        "payload": {"path": "report.txt", "content": "draft\n"},
                        "postconditions": ["content_matches_payload"],
                    }
                ],
                "expect": [{"path": "report.txt", "content": "final\n"}],
            }
        )
        report = run_benchmark([task])
        record = report["tasks"][0]
        self.assertEqual(record["run_status"], "finished")
        self.assertFalse(record["ok"])
        self.assertEqual(record["verification"]["verdict"], "failed")
        self.assertEqual(record["verification"]["failures"], ["report.txt:content_mismatch"])
        self.assertEqual(report["summary"]["ok"], 0)
        self.assertEqual(report["summary"]["success_rate"], 0.0)

    def test_fixture_schema_rejects_unknown_actions(self):
        value = json.loads(
            (ROOT / "benchmarks" / "agent_tasks.json").read_text(encoding="utf-8")
        )
        value["tasks"][0]["steps"][0]["action_id"] = "shell.exec"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "tasks.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_tasks(path)

    def test_each_task_run_gets_a_fresh_workspace(self):
        """A run must never inherit another run's workspace; reuse is refused."""
        tasks = load_tasks()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = run_task(tasks[0], root / "one")
            second = run_task(tasks[0], root / "two")
            self.assertTrue(first["ok"])
            self.assertTrue(second["ok"])
            self.assertEqual(
                (root / "one" / tasks[0].task_id / "workspace" / "out" / "notes.md").read_text(
                    encoding="utf-8"
                ),
                "note: keep it boring\n",
            )
            with self.assertRaises(OSError):
                run_task(tasks[0], root / "one")


if __name__ == "__main__":
    unittest.main()
