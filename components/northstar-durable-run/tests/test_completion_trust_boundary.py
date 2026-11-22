"""Test-only checks that the agent cannot reach the evidence journal.

The completion contract only means something while the journal sits outside the
actor's write domain, so this pins that boundary rather than assuming it. The
gateway's own identity, resource, capability, and arguments-digest binding is
already covered by test_action_gateway.py; what is checked here is the property
the completion contract depends on, namely that no agent-reachable tool call can
reach the sibling evidence directory.
"""
from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMPONENT_ROOT))
sys.path.insert(0, str(COMPONENT_ROOT.parent / "northstar-host"))
sys.path.insert(0, str(COMPONENT_ROOT.parent / "northstar-run-contract"))

from action_gateway import ActionGateway, ToolSpec  # noqa: E402
from workspace_list import WorkspaceListTool  # noqa: E402
from workspace_write import WorkspaceWriteTool  # noqa: E402

EVIDENCE_NAME = "round-1.evidence.jsonl"


def _digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TrustBoundaryTest(unittest.TestCase):
    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory()
        self.sandbox = Path(self._temporary.name)
        self.workspace = self.sandbox / "workspace"
        self.evidence = self.sandbox / "evidence"
        self.workspace.mkdir()
        self.evidence.mkdir()
        self.journal = self.evidence / EVIDENCE_NAME
        self.journal.write_text(
            '{"sequence": 1, "event_type": "loop.finished"}\n', encoding="utf-8"
        )
        self.before = _digest(self.journal)

    def tearDown(self):
        self._temporary.cleanup()

    def assertJournalUnchanged(self):
        self.assertEqual(_digest(self.journal), self.before)

    def test_workspace_write_refuses_parent_traversal(self):
        tool = WorkspaceWriteTool(self.workspace)
        with self.assertRaises(ValueError):
            tool({"path": "../evidence/" + EVIDENCE_NAME, "content": "forged\n"})
        self.assertJournalUnchanged()

    def test_workspace_write_refuses_symlink_escape(self):
        (self.workspace / "escape").symlink_to(self.evidence, target_is_directory=True)
        tool = WorkspaceWriteTool(self.workspace)
        with self.assertRaises((ValueError, OSError)):
            tool({"path": "escape/" + EVIDENCE_NAME, "content": "forged\n"})
        self.assertJournalUnchanged()
    def test_workspace_write_refuses_absolute_path(self):
        tool = WorkspaceWriteTool(self.workspace)
        with self.assertRaises(ValueError):
            tool({"path": str(self.journal), "content": "forged\n"})
        self.assertJournalUnchanged()

    def test_workspace_list_refuses_parent_traversal(self):
        tool = WorkspaceListTool(self.workspace)
        with self.assertRaises(ValueError):
            tool({"path": ".."})
        self.assertJournalUnchanged()

    def test_every_escape_attempt_leaves_the_journal_byte_identical(self):
        attempts = (
            ("../evidence/" + EVIDENCE_NAME, "workspace_write"),
            ("../../evidence/" + EVIDENCE_NAME, "workspace_write"),
            (str(self.journal), "workspace_write"),
            ("escape/" + EVIDENCE_NAME, "workspace_write"),
            ("..", "workspace_list"),
            ("../evidence", "workspace_list"),
        )
        (self.workspace / "escape").symlink_to(self.evidence, target_is_directory=True)
        for path, tool_name in attempts:
            with self.subTest(path=path, tool=tool_name):
                tool = (
                    WorkspaceWriteTool(self.workspace)
                    if tool_name == "workspace_write"
                    else WorkspaceListTool(self.workspace)
                )
                arguments = {"path": path, "content": "forged\n"} if tool_name == "workspace_write" else {"path": path}
                try:
                    tool(arguments)
                except (ValueError, OSError):
                    pass
                self.assertJournalUnchanged()
        self.assertTrue(self.journal.exists())
