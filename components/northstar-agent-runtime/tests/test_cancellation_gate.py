"""A recorded cancellation must be enforced where the effect happens.

Slice 17 (`cancellation-gate`).  The tombstone slice built the *state*: a
sticky revocation that survives compaction, carried by every handoff.
Slice 15 and 16 built its *visibility*: one rendering, wired into the
audit feed, the replay frames, `sessions show`, and the offline replay
page.

None of that **enforces** anything.  Measured with a real `AgentRuntime`
and a scripted `Write`:

    record types : ['cancellation', 'session_start', 'user_prompt',
                    'assistant', 'tool_result', 'assistant', 'result',
                    'session_end']
    denials      : []
    result subtype: success

The session said the action was cancelled.  The write happened anyway.
`ForwardSealLedger.set_tombstones` -- the ledger's injection point, whose
compare-and-swap *does* refuse a covered grant -- has **no production
caller**: the only one in the tree is a test.

THE RULE THIS SLICE PINS:

> **A live cancellation tombstone blocks the tool call it names.**
> The refusal is enforced at the gate, before the handler runs, and it
> lands as a `denial` record in the transcript.

> **The block is scoped, not blanket.**  A tombstone naming a subject
> blocks that subject; a tombstone naming no subject blocks every subject
> of the action.  A tombstone for a *different* action blocks nothing.

> **A lifted tombstone does not block.**  The lift is a record, and the
> gate reads the *live* set.

> **An unrelated tool still runs.**  A stop on `Write` must not stop
> `Read` -- a gate that refuses everything is not a gate.

THE IDENTITY QUESTION, AND ITS HONEST ANSWER
----------------------------------------------
`Tombstone.covers(grant_id, action, subject)` matches on three fields.
A tool call has **no grant id**: `PermissionRequestContext` carries
`session_id`/`agent`/`call_id`/`arguments_digest` and no `grant_id`; nor
does `ToolSpec`.  So the gate cannot reproduce the ledger's three-field
comparison.

The slice's answer: the gate compares the two fields it *can* derive --
the canonical tool name as the action, and the call's target as the
subject -- and does **not** match the grant id.  That is a deliberate
coarsening, and the alternative is worse: a gate that demanded an exact
grant id would match **nothing**, and a gate that failed closed on that
would refuse every tool call in every session holding any tombstone.
The grant id is carried into the refusal message instead, so the reader
still sees *which* stop refused the call.

These tests drive a real `AgentRuntime`.  The point of the slice is an
end-to-end property ("the write did not happen"), so a test that only
exercised a helper would not prove it.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cancellation_tombstone import PERMISSION, Lift, Tombstone  # noqa: E402
from sessions import SessionStore  # noqa: E402
from tests.support import RuntimeTestCase, tool_turn  # noqa: E402


def a_tombstone(*, grant_id: str = "grant-1", action: str = "Write",
                subject: str = "", reason: str = "stop, do not write",
                declarer: str = "user", declarer_channel: str = "chat",
                kind: str = PERMISSION) -> Tombstone:
    """A permission tombstone -- a stop that never expires."""
    return Tombstone(
        grant_id=grant_id,
        action=action,
        subject=subject,
        declarer=declarer,
        declarer_channel=declarer_channel,
        declared_at=1760000000.0,
        kind=kind,
        reason=reason,
    )


def a_lift(tombstone: Tombstone) -> Lift:
    """A named lift of ``tombstone`` -- the instruction that undoes it."""
    return Lift(
        declarer=tombstone.declarer,
        declarer_channel=tombstone.declarer_channel,
        grant_id=tombstone.grant_id,
        action=tombstone.action,
        subject=tombstone.subject,
        text="I authorize the Write again, for notes.md.",
    )


class GateRefusalTests(RuntimeTestCase):
    """The gate refuses a call covered by a live tombstone."""

    def _runtime_with_stop(self, tombstone: Tombstone, *, turns: list, **kwargs):
        """A runtime whose session already carries ``tombstone``."""
        workspace = self.workspace()
        store = SessionStore(workspace, session_id="ns-gate-test")
        store.record_cancellation(tombstone)
        runtime = self.runtime(
            turns, workspace=workspace, sessions=store,
            permission_mode="bypassPermissions", **kwargs,
        )
        return runtime, store

    def test_a_stopped_write_is_refused_and_the_file_is_not_written(self):
        """THE core property: the stopped effect does not happen."""
        runtime, store = self._runtime_with_stop(
            a_tombstone(action="Write"),
            turns=[tool_turn("Write", {"path": "notes.md", "content": "secret"})],
        )
        report = self.drive(runtime)

        self.assertFalse(
            (Path(runtime.config.workspace) / "notes.md").exists(),
            "the write landed even though a live tombstone names it",
        )
        self.assertTrue(report.denials, "the refusal was not recorded as a denial")
        self.assertEqual(report.denials[0].tool, "Write")
        self.assertEqual(
            report.denials[0].source, "cancellation",
            "the refusal did not come from the cancellation gate",
        )

    def test_the_refusal_lands_as_a_denial_record(self):
        """The refusal is on the record, not just in the report."""
        runtime, store = self._runtime_with_stop(
            a_tombstone(action="Write"),
            turns=[tool_turn("Write", {"path": "notes.md", "content": "secret"})],
        )
        self.drive(runtime)
        records, _ = store.read()
        denials = [r for r in records if r.get("type") == "denial"]
        self.assertTrue(denials, "no denial record was written to the transcript")
        self.assertEqual(denials[0].get("tool"), "Write")
        self.assertIn("cancel", str(denials[0].get("reason", "")).lower())

    def test_the_model_is_told_the_call_was_refused(self):
        """The refusal reaches the model as a structured denial, not a crash."""
        runtime, store = self._runtime_with_stop(
            a_tombstone(action="Write"),
            turns=[
                tool_turn("Write", {"path": "notes.md", "content": "secret"}),
                tool_turn("Write", {"path": "notes.md", "content": "secret"}),
            ],
        )
        report = self.drive(runtime)
        blocks = [
            block
            for event in report.events
            for block in (getattr(event, "content", None) or [])
            if getattr(block, "kind", "") == "tool_result"
        ]
        self.assertTrue(blocks, "the run produced no tool result block")
        payload = str(getattr(blocks[0], "content", ""))
        self.assertIn("Write", payload)
        self.assertIn("cancel", payload.lower())

    def test_an_unrelated_tool_still_runs(self):
        """A stop on Write must not stop Read."""
        runtime, store = self._runtime_with_stop(
            a_tombstone(action="Write"),
            turns=[tool_turn("Read", {"path": "notes.md"})],
        )
        self.workspace({"notes.md": "hello"})
        report = self.drive(runtime)
        self.assertFalse(
            report.denials,
            f"an unrelated tool was refused: {report.denials}",
        )


class GateScopeTests(RuntimeTestCase):
    """The block is scoped: the subject decides, when the tombstone names one."""

    def _runtime_with_stop(self, tombstone: Tombstone, *, turns: list, files=None):
        workspace = self.workspace(files or {})
        store = SessionStore(workspace, session_id="ns-gate-scope")
        store.record_cancellation(tombstone)
        runtime = self.runtime(
            turns, workspace=workspace, sessions=store,
            permission_mode="bypassPermissions",
        )
        return runtime, store

    def test_a_subject_scoped_stop_blocks_that_subject(self):
        runtime, _ = self._runtime_with_stop(
            a_tombstone(action="Write", subject="notes.md"),
            turns=[tool_turn("Write", {"path": "notes.md", "content": "secret"})],
        )
        report = self.drive(runtime)
        self.assertTrue(report.denials, "the scoped stop did not block its subject")
        self.assertFalse((Path(runtime.config.workspace) / "notes.md").exists())

    def test_a_subject_scoped_stop_does_not_block_another_subject(self):
        runtime, _ = self._runtime_with_stop(
            a_tombstone(action="Write", subject="notes.md"),
            turns=[tool_turn("Write", {"path": "other.md", "content": "fine"})],
        )
        report = self.drive(runtime)
        self.assertFalse(
            report.denials,
            f"the scoped stop blocked a different subject: {report.denials}",
        )
        self.assertTrue((Path(runtime.config.workspace) / "other.md").exists())

    def test_a_stop_for_another_action_blocks_nothing(self):
        runtime, _ = self._runtime_with_stop(
            a_tombstone(action="publish"),
            turns=[tool_turn("Write", {"path": "notes.md", "content": "fine"})],
        )
        report = self.drive(runtime)
        self.assertFalse(
            report.denials,
            f"a tombstone for another action blocked a tool call: {report.denials}",
        )
        self.assertTrue((Path(runtime.config.workspace) / "notes.md").exists())

    def test_the_action_is_matched_canonically(self):
        """`write` and `Write` are the same action."""
        runtime, _ = self._runtime_with_stop(
            a_tombstone(action="write"),
            turns=[tool_turn("Write", {"path": "notes.md", "content": "secret"})],
        )
        report = self.drive(runtime)
        self.assertTrue(
            report.denials,
            "the action was matched case-sensitively, so a spelling variant slipped through",
        )


class GateLiftTests(RuntimeTestCase):
    """A lifted tombstone does not block."""

    def test_a_lifted_stop_does_not_block(self):
        workspace = self.workspace()
        store = SessionStore(workspace, session_id="ns-gate-lift")
        tombstone = a_tombstone(action="Write")
        store.record_cancellation(tombstone)
        store.record_cancellation_lift(tombstone, a_lift(tombstone))
        runtime = self.runtime(
            [tool_turn("Write", {"path": "notes.md", "content": "fine"})],
            workspace=workspace,
            sessions=store,
            permission_mode="bypassPermissions",
        )
        report = self.drive(runtime)
        self.assertFalse(
            report.denials,
            f"a lifted tombstone still blocked the call: {report.denials}",
        )
        self.assertTrue((Path(workspace) / "notes.md").exists())


class GateResumeTests(RuntimeTestCase):
    """A resumed session enforces the stops it inherited."""

    def test_a_reopened_session_enforces_its_inherited_stop(self):
        workspace = self.workspace()
        store = SessionStore(workspace, session_id="ns-gate-resume")
        store.record_cancellation(a_tombstone(action="Write"))
        # A fresh store over the same transcript: the stop was written by a
        # previous process, and this one has never been told about it.
        reopened = SessionStore(workspace, session_id="ns-gate-resume")
        runtime = self.runtime(
            [tool_turn("Write", {"path": "notes.md", "content": "secret"})],
            workspace=workspace,
            sessions=reopened,
            permission_mode="bypassPermissions",
        )
        report = self.drive(runtime)
        self.assertTrue(
            report.denials,
            "the resumed session did not enforce the stop it inherited",
        )
        self.assertFalse((Path(workspace) / "notes.md").exists())


if __name__ == "__main__":
    unittest.main()
