from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from loop import AgentRuntime, RuntimeConfig
from providers.scripted import ScriptedProvider
from tools import ToolContext, ToolResult, ToolSandbox
from verification import VerificationError, run_commands, validate_commands


class VerificationTests(unittest.TestCase):
    def test_validation_rejects_empty_and_duplicate_commands(self):
        with self.assertRaisesRegex(VerificationError, "non-empty"):
            validate_commands(("",))
        with self.assertRaisesRegex(VerificationError, "duplicates"):
            validate_commands(("pytest -q", "pytest -q"))

    def test_failed_check_stops_later_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            context = ToolContext(sandbox=ToolSandbox(directory))
            results = [
                ToolResult(content="first failed", data={"exit_code": 2, "duration_ms": 3}),
                ToolResult(content="must not run", data={"exit_code": 0}),
            ]
            with patch("verification.shell_handler", side_effect=results) as handler:
                receipts = run_commands(("false", "echo later"), context=context)
        self.assertEqual(len(receipts), 1)
        self.assertFalse(receipts[0].ok)
        self.assertEqual(receipts[0].exit_code, 2)
        handler.assert_called_once()

    def test_runtime_demotes_success_when_host_check_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = AgentRuntime(
                provider=ScriptedProvider([{"text": "done"}]),
                config=RuntimeConfig(
                    workspace=directory,
                    verification_commands=("python3 -c 'raise SystemExit(7)'",),
                    shell_backend="process",
                    shell_landlock="off",
                    shell_seccomp="off",
                    shell_capdrop="off",
                ),
            )
            report = runtime.run_collect("finish the task")
        self.assertEqual(report.subtype, "error_postconditions_failed")
        records = [
            event for event in report.events
            if type(event).__name__ == "SystemMessage" and event.subtype == "verification"
        ]
        self.assertEqual(len(records), 1)
        self.assertFalse(records[0].data["ok"])
        self.assertEqual(records[0].data["results"][0]["exit_code"], 7)

    def test_programming_completion_without_checks_is_explicitly_unverified(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = AgentRuntime(
                provider=ScriptedProvider([{"text": "done"}]),
                config=RuntimeConfig(workspace=directory, require_verification=True),
            )
            report = runtime.run_collect("finish the task")
        self.assertEqual(report.subtype, "success_unverified")
        self.assertFalse(report.result.is_error)


if __name__ == "__main__":
    unittest.main()
