"""Runtime integration for opt-in automatic checkpoint boundaries."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import support  # noqa: F401
from checkpoints import CheckpointError, CheckpointPolicy, list_checkpoints
from loop import AgentRuntime, RuntimeConfig, RuntimeConfigurationError
from providers.scripted import ScriptedProvider
from sessions import SessionStore


class AutomaticCheckpointRuntimeTests(unittest.TestCase):
    def test_mutation_and_turn_boundaries_are_recorded_and_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "workspace"
            workspace.mkdir()
            sessions = SessionStore(root / "sessions", session_id="session-auto")
            provider = ScriptedProvider([
                {"tool": {"name": "Write", "input": {"path": "note.txt", "content": "created"}}},
                {"text": "finished"},
            ])
            runtime = AgentRuntime(
                provider=provider,
                config=RuntimeConfig(
                    workspace=str(workspace),
                    session_id="session-auto",
                    permission_mode="acceptEdits",
                    checkpoint_policy=CheckpointPolicy(
                        enabled=True,
                        every_turns=2,
                        after_mutation=True,
                        max_checkpoints=1,
                    ),
                ),
                sessions=sessions,
            )
            report = runtime.run_collect("write and finish")
            self.assertEqual(report.subtype, "success")
            self.assertEqual(len(report.checkpoints), 2)
            self.assertEqual([item["trigger"] for item in report.checkpoints], ["mutation", "turn"])
            self.assertEqual(report.checkpoints[-1]["removed_checkpoint_ids"], [report.checkpoints[0]["checkpoint_id"]])
            checkpoints = list_checkpoints(sessions.directory, "session-auto")
            self.assertEqual(len(checkpoints), 1)
            self.assertEqual(checkpoints[0].label, "auto:turn-2")
            records, _dropped = sessions.read()
            notices = [
                record for record in records
                if record.get("data", {}).get("subtype") == "checkpoint_created"
            ]
            self.assertEqual(len(notices), 2)
            self.assertTrue((workspace / "note.txt").is_file())

    def test_enabled_policy_requires_durable_session_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "workspace"
            workspace.mkdir()
            with self.assertRaises(RuntimeConfigurationError):
                AgentRuntime(
                    provider=ScriptedProvider([{"text": "done"}]),
                    config=RuntimeConfig(
                        workspace=str(workspace),
                        checkpoint_policy=CheckpointPolicy(enabled=True),
                    ),
                )

    def test_checkpoint_failure_stops_before_the_next_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "workspace"
            workspace.mkdir()
            sessions = SessionStore(root / "sessions", session_id="session-failure")
            provider = ScriptedProvider([
                {"text": "first"},
                {"text": "must not run"},
            ])
            runtime = AgentRuntime(
                provider=provider,
                config=RuntimeConfig(
                    workspace=str(workspace),
                    session_id="session-failure",
                    checkpoint_policy=CheckpointPolicy(enabled=True),
                ),
                sessions=sessions,
            )
            with mock.patch("loop.create_checkpoint", side_effect=CheckpointError("disk full")):
                report = runtime.run_collect("finish safely")
            self.assertEqual(report.subtype, "error_during_execution")
            self.assertEqual(len(provider.requests), 1)
            self.assertTrue(any("automatic checkpoint failed" in error for error in report.errors))

    def test_checkpoint_policy_mapping_is_accepted_by_runtime_config(self):
        config = RuntimeConfig(
            checkpoint_policy={
                "enabled": False,
                "every_turns": 4,
                "after_mutation": False,
                "max_checkpoints": 3,
                "label_prefix": "host-auto",
            }
        )
        self.assertEqual(config.checkpoint_policy.every_turns, 4)
        self.assertEqual(config.as_dict()["checkpoint_policy"]["label_prefix"], "host-auto")


if __name__ == "__main__":
    unittest.main()
