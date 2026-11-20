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

import shutil
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


class GateIdentityTests(unittest.TestCase):
    """The identity derivation, on crafted inputs.

    A guard that only reads clean real files is unverifiable: the whole
    point of these is the shapes a real session does not produce -- a
    path spelled three ways, a host in mixed case, a tool with no path
    argument at all.

    These are the tests that would have caught the bug the first GREEN
    run had: the subject derivation compared a *canonicalised* action
    against a set of capitalised names, so it never matched, and every
    subject came back empty -- which, because an empty subject is
    covered by every tombstone, silently widened every stop to every
    call of that action.
    """

    def test_the_action_is_canonical(self):
        from sessions import canonical_action

        self.assertEqual(canonical_action("Write"), "write")
        self.assertEqual(canonical_action("  Write  "), "write")
        self.assertEqual(canonical_action("WRITE"), "write")

    def test_a_file_tool_names_its_relative_path(self):
        from sessions import canonical_subject

        self.assertEqual(
            canonical_subject("Write", {"path": "notes.md"}, root="/tmp/ws"),
            "notes.md",
        )
        self.assertEqual(
            canonical_subject("write", {"path": "notes.md"}, root="/tmp/ws"),
            "notes.md",
            "the subject derivation missed a canonicalised tool name",
        )

    def test_the_path_is_normalized_lexically(self):
        from sessions import canonical_subject

        for spelling in ("notes.md", "./notes.md", "sub/../notes.md"):
            self.assertEqual(
                canonical_subject("Write", {"path": spelling}, root="/tmp/ws"),
                "notes.md",
                f"the path spelling {spelling!r} named a different subject",
            )

    def test_a_fetch_names_its_host(self):
        from sessions import canonical_subject

        self.assertEqual(
            canonical_subject("Fetch", {"host": "Example.COM"}, root="/tmp/ws"),
            "example.com",
        )

    def test_a_tool_with_no_subject_names_none(self):
        from sessions import canonical_subject

        self.assertEqual(canonical_subject("Shell", {"command": "ls"}, root="/tmp/ws"), "")
        self.assertEqual(canonical_subject("Write", {}, root="/tmp/ws"), "")
        self.assertEqual(canonical_subject("Write", {"path": 42}, root="/tmp/ws"), "")
        self.assertEqual(canonical_subject("Write", "not-a-dict", root="/tmp/ws"), "")

    def test_a_scoped_tombstone_does_not_cover_another_subject(self):
        from sessions import cancellation_gate_matches

        tombstone = a_tombstone(action="Write", subject="notes.md")
        self.assertTrue(
            cancellation_gate_matches(tombstone, "write", "notes.md"),
            "the tombstone did not cover the subject it names",
        )
        self.assertFalse(
            cancellation_gate_matches(tombstone, "write", "other.md"),
            "the tombstone covered a subject it does not name",
        )

    def test_an_unscoped_tombstone_covers_every_subject(self):
        from sessions import cancellation_gate_matches

        tombstone = a_tombstone(action="Write", subject="")
        self.assertTrue(cancellation_gate_matches(tombstone, "write", "notes.md"))
        self.assertTrue(cancellation_gate_matches(tombstone, "write", "other.md"))

    def test_a_tombstone_for_another_action_covers_nothing(self):
        from sessions import cancellation_gate_matches

        tombstone = a_tombstone(action="publish", subject="")
        self.assertFalse(
            cancellation_gate_matches(tombstone, "write", "notes.md"),
            "a tombstone for another action covered a tool call",
        )

    def test_an_empty_subject_is_covered_by_a_scoped_tombstone(self):
        """The tombstone's own rule: an unspecified subject is not evidence
        of being outside the scope."""
        from sessions import cancellation_gate_matches

        tombstone = a_tombstone(action="Write", subject="notes.md")
        self.assertTrue(
            cancellation_gate_matches(tombstone, "write", ""),
            "a call that names no subject escaped a scoped stop",
        )

    def test_a_malformed_tombstone_covers_nothing(self):
        """A tombstone the gate cannot read is refused, not honoured.

        The gate is fail-closed on the *state* (an unreadable live set
        refuses the call), and fail-closed on a *malformed* tombstone in
        the other direction: a tombstone whose action is not a string
        names nothing, so it cannot be matched -- and the gate does not
        mistake "I cannot read this" for "this covers the call".

        These are the guards the mutant probe reaches and cannot kill
        without a test: a guard that only ever sees well-formed input is
        unverifiable.
        """
        from sessions import cancellation_gate_matches

        class Malformed:
            action = None
            subject = ""

        malformed = Malformed()
        self.assertFalse(
            cancellation_gate_matches(malformed, "write", "notes.md"),
            "a tombstone with no action covered a call",
        )
        malformed.action = 42
        self.assertFalse(
            cancellation_gate_matches(malformed, "write", "notes.md"),
            "a tombstone with a non-string action covered a call",
        )
        malformed.action = "Write"
        malformed.subject = 42
        self.assertFalse(
            cancellation_gate_matches(malformed, "write", "notes.md"),
            "a tombstone with a non-string subject covered a call",
        )
        self.assertFalse(
            cancellation_gate_matches(None, "write", "notes.md"),
            "a missing tombstone covered a call",
        )

    def test_a_host_that_is_not_a_string_names_no_subject(self):
        """A Fetch with a nonsense host names no subject, so an unscoped
        stop covers it and a scoped one does not."""
        from sessions import canonical_subject

        self.assertEqual(canonical_subject("Fetch", {"host": 42}, root="/tmp/ws"), "")
        self.assertEqual(canonical_subject("Fetch", {"host": "   "}, root="/tmp/ws"), "")

    def test_a_subject_without_a_root_is_the_normalized_absolute_path(self):
        """With no workspace root to be relative to, the subject is the
        normalized path itself."""
        from sessions import canonical_subject

        self.assertEqual(
            canonical_subject("Write", {"path": "notes.md"}),
            "notes.md",
        )
        self.assertEqual(
            canonical_subject("Write", {"path": "/tmp/ws/notes.md"}),
            "/tmp/ws/notes.md",
        )
        self.assertEqual(
            canonical_subject("Write", {"path": "sub/../notes.md"}),
            "notes.md",
        )

    def test_another_sessions_tombstones_are_read_from_its_own_file(self):
        """The cache is this store's; another session's file is not.

        The two branches of ``tombstones()`` -- "this session, from the
        cache" and "another session, from its own file" -- have to be
        told apart, or the gate would enforce one session's stops for
        another (or miss the ones it should see).
        """
        from sessions import SessionStore

        import tempfile

        directory = tempfile.mkdtemp(prefix="nsar-cg-")
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        writer = SessionStore(directory, session_id="ns-cg-writer")
        writer.record_cancellation(a_tombstone(action="Write"))
        other = SessionStore(directory, session_id="ns-cg-other")

        self.assertEqual(
            len(other.tombstones("ns-cg-writer").list()),
            1,
            "another session's tombstones were not read from its own file",
        )
        self.assertEqual(
            len(other.tombstones().list()),
            0,
            "another session's cache claimed tombstones it never declared",
        )

    def test_a_store_with_no_transcript_still_answers_from_its_cache(self):
        """A store with no directory has no file to read.

        Its live set is still the cache, so the gate still enforces the
        stops it was told about -- a session that writes nothing to disk
        must not be the one session where a stop is ignored.
        """
        from sessions import SessionStore

        store = SessionStore(None, session_id="ns-cg-nodir")
        store.record_cancellation(a_tombstone(action="Write"))
        self.assertEqual(len(store.live_tombstones().list()), 1)
        self.assertEqual(len(store.tombstones().list()), 1)
        self.assertEqual(len(store.tombstones("ns-cg-nodir").list()), 1)


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


class SessionGuardSecondHalfTests(unittest.TestCase):
    """The SECOND half of two session-file guards.

    Both guards are *double* guards: a type half joined to a second half
    by `and`.  The session suite drove only the first half, so flipping
    the connective left the suite green -- the planted faults `and@102`
    and `eq@140` SURVIVED it.

      and@102  `isinstance(key, str) and key.lower() in _SESSION_CONTENT_KEYS`
                The second half is the MEMBERSHIP test.  The first half
                says "the key is a string"; the second says "and it
                names a content key".  A string key that is NOT a
                content key must keep its value; a string key that IS
                one must have its value replaced.  The two halves say
                different things, and the membership half is the one
                under test: flipping `and` to `or` would replace EVERY
                string key's value, which is a false redaction of data
                the guard never meant to touch.
      eq@140   `error.errno == errno.ELOOP`
                `== -> !=` swaps which errno takes the branch, so the
                symlink refusal must fire on ELOOP and NOT fire on any
                other errno.

    Each test here fails when its planted fault is applied alone.
    """

    def test_a_content_key_has_its_value_replaced(self):
        """The membership half of `and@102`, taken one way.

        ``"content"`` IS in ``_SESSION_CONTENT_KEYS``, so its value is
        the secret and must be replaced by the omission marker.
        """
        from sessions import _redact_session_payload

        redacted = _redact_session_payload({"content": "secret"})

        self.assertEqual(
            redacted.get("content"),
            "[omitted by session privacy mode]",
            "a content key's value must be replaced",
        )

    def test_a_string_key_that_is_not_a_content_key_keeps_its_value(self):
        """The membership half of `and@102`, taken the other way.

        ``"kind"`` is a string but is NOT in ``_SESSION_CONTENT_KEYS``:
        it names no conversational content, so its value is kept.
        Flipping `and` to `or` makes the branch fire for ANY string key
        and replaces this value too -- which is the false redaction
        this test closes.
        """
        from sessions import _redact_session_payload

        redacted = _redact_session_payload({"kind": "note"})

        self.assertEqual(
            redacted.get("kind"),
            "note",
            "a string key that is not a content key must keep its value",
        )

    def test_the_membership_test_is_case_insensitive(self):
        """The membership half again, with a case variant.

        The guard lowercases the key before the membership test, so
        ``"CONTENT"`` is a content key.  A guard that compared without
        lowering would keep the secret -- and flipping the connective
        would hide that, because the redacting branch would fire anyway.
        """
        from sessions import _redact_session_payload

        redacted = _redact_session_payload({"CONTENT": "secret"})

        self.assertEqual(
            redacted.get("CONTENT"),
            "[omitted by session privacy mode]",
            "the membership test must be case-insensitive",
        )

    def test_a_non_string_key_is_not_treated_as_a_content_key(self):
        """The type half still guards.

        The first half of `and@102` says "the key is a string".  A
        non-string key cannot be lowered, so the guard must leave it
        alone -- the type half must still hold when the membership half
        is exercised.
        """
        from sessions import _redact_session_payload

        redacted = _redact_session_payload({1: "value", "content": "secret"})

        self.assertEqual(redacted.get(1), "value")
        self.assertEqual(redacted.get("content"), "[omitted by session privacy mode]")

    def test_a_symlinked_transcript_is_refused(self):
        """The `eq@140` half: ELOOP takes the branch.

        Opening a symlink with ``O_NOFOLLOW`` raises ``ELOOP``.  The
        guard must turn that into a ``SessionIntegrityError`` that says
        it is refusing to follow a transcript symlink -- not a bare
        ``OSError``.
        """
        import errno
        import os
        import tempfile

        from sessions import SessionIntegrityError, _open_regular_nofollow

        with tempfile.TemporaryDirectory() as workspace:
            root = Path(workspace)
            target = root / "target.jsonl"
            target.write_text("{}\n", encoding="utf-8")
            link = root / "link.jsonl"
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks are not available here")

            with self.assertRaises(SessionIntegrityError) as caught:
                _open_regular_nofollow(link, os.O_RDONLY)
            self.assertIn("symlink", str(caught.exception))
            self.assertIsInstance(caught.exception.__cause__, OSError)
            self.assertEqual(caught.exception.__cause__.errno, errno.ELOOP)

    def test_a_transcript_that_is_not_a_symlink_is_not_refused_as_one(self):
        """The `eq@140` half from the other side.

        ``== -> !=`` makes the branch fire on EVERY errno other than
        ELOOP, so an ordinary error (say ``ENOENT``) would be reported
        as "refusing to follow a transcript symlink" -- a lie about the
        cause.  A missing file must raise the ordinary ``OSError``, not
        a ``SessionIntegrityError`` about symlinks.
        """
        import errno
        import os
        import tempfile

        from sessions import SessionIntegrityError, _open_regular_nofollow

        with tempfile.TemporaryDirectory() as workspace:
            missing = Path(workspace) / "absent.jsonl"
            with self.assertRaises(OSError) as caught:
                _open_regular_nofollow(missing, os.O_RDONLY)
            self.assertNotIsInstance(caught.exception, SessionIntegrityError)
            self.assertEqual(caught.exception.errno, errno.ENOENT)

    def test_a_regular_transcript_opens_without_a_symlink_refusal(self):
        """The control: the ordinary path is untouched."""
        import os
        import tempfile

        from sessions import _open_regular_nofollow

        with tempfile.TemporaryDirectory() as workspace:
            path = Path(workspace) / "plain.jsonl"
            path.write_text("{}\n", encoding="utf-8")
            fd = _open_regular_nofollow(path, os.O_RDONLY)
            try:
                self.assertGreaterEqual(os.fstat(fd).st_size, 0)
            finally:
                os.close(fd)


if __name__ == "__main__":
    unittest.main()
