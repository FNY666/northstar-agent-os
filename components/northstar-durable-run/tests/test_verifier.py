import hashlib
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMPONENT_ROOT))

from durable_contract import RunContract  # noqa: E402
from event_store import EventStore  # noqa: E402
from runner import DurableRunner, StepPlan  # noqa: E402
from verifier import (  # noqa: E402
    VerificationResult,
    make_final_receipt,
    verify_run_completion,
)


RUN = RunContract.from_dict(
    {
        "schema_version": "northstar.durable-run.v1",
        "task_id": "task-001",
        "thread_id": "thread-001",
        "run_id": "run-001",
        "parent_run_id": None,
        "status": "planned",
        "deadline_at": 2_000,
        "scope_snapshot": ["workspace:read", "workspace:write"],
        "trace_id": "trace-001",
    }
)


class VerifierTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir(mode=0o700)
        self.store = EventStore(self.root / "events.jsonl")
        self.runner = DurableRunner(
            RUN,
            self.store,
            lease_path=self.root / "run.lease.json",
            lease_ttl_seconds=20,
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def run_success(self):
        target = self.workspace / "src" / "main.py"

        def write_target(_key):
            target.parent.mkdir(mode=0o700)
            target.write_text("print('fixed')\n", encoding="utf-8")
            return {"claimed": "finished"}

        state = self.runner.execute(
            [
                StepPlan(
                    step_id="edit",
                    input_payload={"file": "src/main.py"},
                    scope_snapshot=["workspace:write"],
                    expected_postconditions=["tests_pass"],
                    action=write_target,
                )
            ],
            owner_id="worker-a",
            now=100,
        )
        return target, state

    def expected_digest(self, path):
        return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

    def test_verified_requires_real_finished_state_file_digest_and_test_exit_zero(self):
        target, state = self.run_success()
        result = verify_run_completion(
            RUN,
            self.store,
            workspace=self.workspace,
            required_files={"src/main.py": self.expected_digest(target)},
            test_exit_code=0,
            now=101,
        )
        self.assertEqual(
            result,
            VerificationResult(
                verdict="verified",
                errors=(),
                artifact_digests={"src/main.py": self.expected_digest(target)},
            ),
        )
        receipt = make_final_receipt(RUN, result)
        self.assertEqual(receipt["status"], "ok")
        self.assertEqual(receipt["run_id"], "run-001")
        self.assertEqual(receipt["verification"], "verified")
        self.assertEqual(receipt["artifacts"]["src/main.py"], self.expected_digest(target))

    def test_model_claimed_success_does_not_override_missing_file_or_failed_test(self):
        _target, state = self.run_success()
        missing = verify_run_completion(
            RUN,
            self.store,
            workspace=self.workspace,
            required_files={"src/missing.py": "sha256:" + "0" * 64},
            test_exit_code=0,
            now=101,
            claimed_status="ok",
        )
        self.assertEqual(missing.verdict, "failed")
        self.assertTrue(any("missing" in error for error in missing.errors))

        target = self.workspace / "src" / "main.py"
        failed_test = verify_run_completion(
            RUN,
            self.store,
            workspace=self.workspace,
            required_files={"src/main.py": self.expected_digest(target)},
            test_exit_code=1,
            now=101,
            claimed_status="ok",
        )
        self.assertEqual(failed_test.verdict, "failed")
        self.assertTrue(any("exit code" in error for error in failed_test.errors))
        self.assertEqual(make_final_receipt(RUN, failed_test)["status"], "failed")

    def test_running_or_cancelled_state_cannot_be_verified_even_with_files(self):
        target = self.workspace / "src" / "main.py"
        target.parent.mkdir(mode=0o700)
        target.write_text("fixed\n", encoding="utf-8")
        self.runner.prepare(owner_id="worker-a", now=100)
        running = verify_run_completion(
            RUN,
            self.store,
            workspace=self.workspace,
            required_files={"src/main.py": self.expected_digest(target)},
            test_exit_code=0,
            now=101,
        )
        self.assertEqual(running.verdict, "unknown")
        self.assertTrue(any("not finished" in error for error in running.errors))

        self.runner.cancel(owner_id="worker-a", now=101)
        cancelled = verify_run_completion(
            RUN,
            self.store,
            workspace=self.workspace,
            required_files={"src/main.py": self.expected_digest(target)},
            test_exit_code=0,
            now=102,
        )
        self.assertEqual(cancelled.verdict, "failed")
        self.assertEqual(make_final_receipt(RUN, cancelled)["status"], "failed")

    def test_workspace_path_traversal_symlink_wrong_digest_and_non_private_mode_fail(self):
        target, _state = self.run_success()
        checks = [
            {"../escape": self.expected_digest(target)},
            {"/absolute": self.expected_digest(target)},
            {"src/link.py": self.expected_digest(target)},
            {"src/main.py": "sha256:" + "f" * 64},
        ]
        target.unlink()
        target.symlink_to(self.root / "outside")
        (self.root / "outside").write_text("outside\n", encoding="utf-8")
        for required in checks:
            with self.subTest(required=required):
                result = verify_run_completion(
                    RUN,
                    self.store,
                    workspace=self.workspace,
                    required_files=required,
                    test_exit_code=0,
                    now=101,
                )
                self.assertEqual(result.verdict, "failed")

        target.unlink()
        target.write_text("fixed\n", encoding="utf-8")
        self.workspace.chmod(0o755)
        result = verify_run_completion(
            RUN,
            self.store,
            workspace=self.workspace,
            required_files={"src/main.py": self.expected_digest(target)},
            test_exit_code=0,
            now=101,
        )
        self.assertEqual(result.verdict, "failed")

    def test_verifier_rejects_intermediate_symlink_escape(self):
        target, _state = self.run_success()
        outside = self.root / "outside-dir"
        outside.mkdir(mode=0o700)
        escaped = outside / "escaped.py"
        escaped.write_text("outside\n", encoding="utf-8")
        source_dir = self.workspace / "src"
        target.unlink()
        source_dir.rmdir()
        source_dir.symlink_to(outside, target_is_directory=True)
        result = verify_run_completion(
            RUN,
            self.store,
            workspace=self.workspace,
            required_files={"src/escaped.py": self.expected_digest(escaped)},
            test_exit_code=0,
            now=101,
        )
        self.assertEqual(result.verdict, "failed")
        self.assertTrue(any("symlink" in error for error in result.errors))

    def test_unknown_when_test_result_is_not_observed_or_history_is_corrupt(self):
        target, _state = self.run_success()
        unknown = verify_run_completion(
            RUN,
            self.store,
            workspace=self.workspace,
            required_files={"src/main.py": self.expected_digest(target)},
            test_exit_code=None,
            now=101,
        )
        self.assertEqual(unknown.verdict, "unknown")
        self.assertTrue(any("not observed" in error for error in unknown.errors))

        self.store._path.write_text("corrupt\n", encoding="utf-8")
        corrupt = verify_run_completion(
            RUN,
            self.store,
            workspace=self.workspace,
            required_files={},
            test_exit_code=0,
            now=101,
        )
        self.assertEqual(corrupt.verdict, "unknown")
        self.assertTrue(any("history" in error for error in corrupt.errors))

    def test_receipt_rejects_wrong_run_and_unverified_result(self):
        result = VerificationResult("failed", ("not verified",), {})
        self.assertEqual(make_final_receipt(RUN, result)["status"], "failed")
        with self.assertRaises(ValueError):
            make_final_receipt("run-001", VerificationResult("verified", (), {}))
        with self.assertRaises(ValueError):
            make_final_receipt(RUN, VerificationResult("verified", ("contradiction",), {}))


if __name__ == "__main__":
    unittest.main()
