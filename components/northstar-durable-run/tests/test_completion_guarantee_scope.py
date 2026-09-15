"""Test-only guards on the guarantee boundary the completion contract needs.

The contract only means something while the evidence journal sits outside the
actor's write domain, and the run layout places ``workspace/`` and the journal
side by side. These checks drive the real production harness -- the registered
tools it wires in agent_entry.py, not stand-ins -- and attempt to cross that
boundary, so a future change that swaps a path-safe executor for a direct write
makes them fail. Gateway identity, resource, capability, and arguments-digest
binding is covered by test_action_gateway.py and is not duplicated here.
"""
from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
for _path in (
    COMPONENT_ROOT,
    COMPONENT_ROOT.parent / "northstar-run-contract",
    COMPONENT_ROOT.parent / "northstar-host",
    Path(__file__).resolve().parent,
):
    sys.path.insert(0, str(_path))

from agent_entry import (  # noqa: E402
    AgentHarness,
    ExpectedArtifact,
    READ_ACTION,
    WRITE_ACTION,
    build_run,
)
from planner_adapter import TypedPlannerAdapter  # noqa: E402
from test_agent_entry import ScriptedCaller, plan_value, step_value  # noqa: E402

WRITE_POSTCONDITION = "content_matches_payload"
READ_POSTCONDITION = "read_ok"
JOURNAL_NAME = "evidence.jsonl"
FORGED_MARKER = "FORGED-BY-AGENT"


class GuaranteeScopeTest(unittest.TestCase):
    """Drive the real production harness against its own boundary."""

    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        (self.workspace / "README.md").write_text("handbook\n", encoding="utf-8")
        self.journal = self.root / JOURNAL_NAME
        self.run = build_run("agent-001", clock=lambda: 100)
        self.harness = AgentHarness(
            self.run,
            self.workspace,
            self.journal,
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
        self._temporary.cleanup()

    def drive(self, action, payload, *, artifact_path, artifact_content="ok\n"):
        """Run one step through the real registered production tool."""
        postcondition = (
            WRITE_POSTCONDITION if action == WRITE_ACTION else READ_POSTCONDITION
        )
        steps = [step_value("step-1", action, payload, [postcondition])]
        planner = TypedPlannerAdapter(ScriptedCaller(plan_value(self.run, steps)))
        expectations = [ExpectedArtifact(artifact_path, content=artifact_content)]
        try:
            return self.harness.run_goal(
                "Cross the workspace boundary", planner, expectations=expectations
            )
        except Exception as error:  # a refusal may surface as an exception
            return error

    def assertNoForgedMarker(self):
        """The agent's marker must not appear anywhere outside its workspace."""
        for path in self.root.rglob("*"):
            if not path.is_file() or self.workspace in path.parents:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            self.assertNotIn(FORGED_MARKER, text, f"forged content reached {path}")

    def test_a_legitimate_write_reaches_the_executor(self):
        # Positive control: without this, every boundary assertion below could
        # pass simply because the step never ran.
        result = self.drive(
            WRITE_ACTION,
            {"path": "notes/ok.txt", "content": "hello\n"},
            artifact_path="notes/ok.txt",
            artifact_content="hello\n",
        )
        self.assertTrue(getattr(result, "ok", False), str(result)[:200])
        self.assertEqual((self.workspace / "notes" / "ok.txt").read_text(), "hello\n")

    def test_agent_cannot_write_a_sibling_of_the_workspace_root(self):
        self.drive(
            WRITE_ACTION,
            {"path": f"../escaped.txt", "content": FORGED_MARKER},
            artifact_path="notes/ok.txt",
        )
        self.assertFalse((self.root / "escaped.txt").exists())
        self.assertNoForgedMarker()

    def test_agent_cannot_forge_the_evidence_journal(self):
        self.drive(
            WRITE_ACTION,
            {"path": f"../{JOURNAL_NAME}", "content": FORGED_MARKER},
            artifact_path="notes/ok.txt",
        )
        self.assertNoForgedMarker()
        if self.journal.exists():
            self.assertNotIn(FORGED_MARKER, self.journal.read_text(errors="replace"))

    def test_agent_cannot_follow_a_symlink_out_of_the_workspace(self):
        (self.workspace / "escape").symlink_to(self.root)
        result = self.drive(
            WRITE_ACTION,
            {"path": "escape/escaped.txt", "content": FORGED_MARKER},
            artifact_path="notes/ok.txt",
        )
        self.assertFalse((self.root / "escaped.txt").exists())
        self.assertNoForgedMarker()
        self.assertFalse(getattr(result, "ok", False) is True)

    def test_agent_cannot_read_outside_the_workspace(self):
        result = self.drive(
            READ_ACTION,
            {"path": "../../etc/hostname"},
            artifact_path="notes/ok.txt",
        )
        self.assertFalse(getattr(result, "ok", False) is True)
