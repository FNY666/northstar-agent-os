import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ROOT = COMPONENT_ROOT.parent / "northstar-run-contract"
sys.path.insert(0, str(COMPONENT_ROOT))
sys.path.insert(0, str(CONTRACT_ROOT))

from cli import main  # noqa: E402
from durable_contract import RunContract  # noqa: E402
from event_store import EventStore  # noqa: E402
from runner import DurableRunner, StepPlan  # noqa: E402


RUN = RunContract.from_dict(
    {
        "schema_version": "northstar.durable-run.v1",
        "task_id": "task-cli-001",
        "thread_id": "thread-cli-001",
        "run_id": "run-cli-001",
        "parent_run_id": None,
        "status": "planned",
        "deadline_at": 2_000,
        "scope_snapshot": ["workspace:read", "workspace:write"],
        "trace_id": "trace-cli-001",
    }
)


class DurableCliTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.events = self.root / "events.jsonl"
        self.contract = self.root / "run.json"
        self.contract.write_text(json.dumps(RUN.to_dict()), encoding="utf-8")
        self.store = EventStore(self.events)
        self.runner = DurableRunner(
            RUN,
            self.store,
            lease_path=self.root / "run-cli-001.lease.json",
            lease_ttl_seconds=20,
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def invoke(self, *arguments):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(list(arguments))
        return code, stdout.getvalue(), stderr.getvalue()

    def create_running_run(self):
        return self.runner.execute(
            [
                StepPlan(
                    step_id="inspect",
                    input_payload={"fixture": True},
                    scope_snapshot=["workspace:read"],
                    expected_postconditions=["inspection_recorded"],
                    action=lambda key: {"key": key},
                )
            ],
            owner_id="worker-cli",
            now=100,
            finalize=False,
        )

    def test_status_history_and_audit_are_read_only_views(self):
        self.create_running_run()

        code, output, error = self.invoke(
            "status", "--events", str(self.events), "--run-id", RUN.run_id
        )
        self.assertEqual((code, error), (0, ""))
        status = json.loads(output)
        self.assertEqual(status["state"]["status"], "running")
        self.assertEqual(status["event_count"], 6)

        code, output, error = self.invoke(
            "history", "--events", str(self.events), "--run-id", RUN.run_id
        )
        self.assertEqual((code, error), (0, ""))
        self.assertEqual(len(json.loads(output)["events"]), 6)

        code, output, error = self.invoke(
            "audit", "--events", str(self.events), "--run-id", RUN.run_id
        )
        self.assertEqual((code, error), (0, ""))
        self.assertEqual(len(output.splitlines()), 6)
        self.assertEqual(self.store.replay(RUN.run_id)["status"], "running")

    def test_control_command_applies_pause_resume_and_cancel(self):
        self.create_running_run()

        code, output, error = self.invoke(
            "control",
            "--events",
            str(self.events),
            "--run-contract",
            str(self.contract),
            "--owner-id",
            "operator-cli",
            "--now",
            "101",
            "pause",
            "--reason",
            "manual hold",
        )
        self.assertEqual((code, error), (0, ""))
        self.assertEqual(json.loads(output)["state"]["status"], "waiting")

        code, output, error = self.invoke(
            "control",
            "--events",
            str(self.events),
            "--run-contract",
            str(self.contract),
            "--owner-id",
            "operator-cli",
            "--now",
            "102",
            "resume",
        )
        self.assertEqual((code, error), (0, ""))
        self.assertEqual(json.loads(output)["state"]["status"], "running")

        code, output, error = self.invoke(
            "control",
            "--events",
            str(self.events),
            "--run-contract",
            str(self.contract),
            "--owner-id",
            "operator-cli",
            "--now",
            "103",
            "cancel",
        )
        self.assertEqual((code, error), (0, ""))
        result = json.loads(output)
        self.assertEqual(result["state"]["status"], "cancelled")
        self.assertEqual(result["action"], "cancel")

    def test_status_reports_missing_history_as_a_cli_error(self):
        code, output, error = self.invoke(
            "status", "--events", str(self.events), "--run-id", RUN.run_id
        )
        self.assertEqual(code, 2)
        self.assertEqual(output, "")
        self.assertIn("no event history", error)


if __name__ == "__main__":
    unittest.main()
