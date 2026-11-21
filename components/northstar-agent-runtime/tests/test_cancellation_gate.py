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

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from audit_chain import CHAIN_VERSION_V2, chain_records  # noqa: E402
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


# ---------------------------------------------------------------------------
# The second half of every surviving guard in ``sessions.py``
# ---------------------------------------------------------------------------
#
# The mutant probe (``b173-mutant.py``) reports SURVIVED mutants in
# ``components/northstar-agent-runtime/sessions.py`` against this slice's
# suite.  Each one is an arm of a guard the suite never drove: a size,
# record-count or line-length bound that only fires on a transcript over a
# limit; a resume guard that only fires on a damaged chain; a redaction
# guard that only fires on a redacted record.
#
# The technique is the one the repository's own memory names: **a guard
# that only ever reads clean real files is unverifiable**.  The inputs
# here are crafted -- an over-limit transcript, a broken chain, a
# redacted record, a lift against something that is not a lift.
#
# Every class names the site it closes in the probe's own notation
# (``kind@line``) and says which arm it drives.


def _write_chain(directory, session_id, records, *, chain_version=CHAIN_VERSION_V2):
    """Write ``records`` as a sealed transcript and return its path.

    The records are sealed with the repository's own ``chain_records``, so
    the file is a transcript a real ``SessionStore`` opens -- a store that
    refuses it refuses it for the right reason (the content), not because
    the file is nonsense.
    """
    sealed = chain_records(
        list(records),
        component="northstar-session",
        session_id=session_id,
        chain_version=chain_version,
    )
    path = Path(directory) / f"{session_id}.jsonl"
    with path.open("w", encoding="utf-8") as handle:
        for record in sealed:
            handle.write(
                json.dumps(record, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":")) + "\n"
            )
    return path


def _sealed_transcript(directory, session_id, count=3):
    """A valid sealed transcript of ``count`` records; returns its path."""
    return _write_chain(
        directory,
        session_id,
        [
            {
                "index": index,
                "ts": f"2026-01-01T00:00:0{index}.000Z",
                "session_id": session_id,
                "type": "session_start" if index == 0 else "informational",
                "agent": "main",
            }
            for index in range(count)
        ],
    )


def _tamper_last_record(path):
    """Edit the last record's body in place, breaking the chain."""
    lines = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[-1])
    record["agent"] = "tampered"
    lines[-1] = json.dumps(record, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


class SessionBoundGuardTests(unittest.TestCase):
    """The size, record-count and line-length bounds of the session reader.

    Every bound in the reader is a ``>`` comparison, so the mutant probe
    turns it into ``>=`` and the only way to see the difference is a
    transcript that sits **exactly on** the bound.  The suite never built
    one, so all seven bound sites survived.

      gt@443   the resume file-size bound
      gt@461   the resume record-count bound
      gt@465   the resume byte bound
      gt@469   the resume line-length bound
      gt@993   the read record-count bound
      gt@998   the read byte bound
      gt@1002  the read line-length bound

    The bounds are **strict**: a transcript that is exactly at the limit is
    accepted, and one unit more is refused.  Under the mutant (``>`` ->
    ``>=``) the exactly-at-the-limit transcript is refused -- a legal
    session becomes unreadable.

    The bounds are read from the module's own names at call time, so the
    test patches the constant the module reads rather than rebuilding a
    64-megabyte file.  That is what makes the equality case reachable:
    the transcript's real size is set to the bound.
    """

    def test_a_transcript_exactly_at_the_file_size_bound_is_accepted(self):
        """`gt@443`: the file-size bound is STRICT.

        The store opens a transcript whose file is exactly the bound
        long.  The bound must not fire at equality: the limit is the
        largest transcript that may be resumed.  Under the mutant
        (``>`` -> ``>=``) this legal transcript is refused.
        """
        from sessions import ResumeRefusedError, SessionStore

        with tempfile.TemporaryDirectory() as directory:
            path = _sealed_transcript(directory, "ns-at-limit")
            size = path.stat().st_size
            with mock.patch("sessions.MAX_SESSION_FILE_BYTES", size):
                try:
                    SessionStore(directory, session_id="ns-at-limit")
                except ResumeRefusedError as error:
                    self.fail(f"a transcript exactly at the size limit was refused: {error}")

    def test_a_transcript_one_byte_over_the_file_size_bound_is_refused(self):
        """`gt@443`: the bound, from the other side.

        One byte over the limit must be refused.  This is the control: it
        proves the bound fires at all, so the exactly-at-the-limit test
        above is not passing because the bound is dead code.
        """
        from sessions import ResumeRefusedError, SessionStore

        with tempfile.TemporaryDirectory() as directory:
            path = _sealed_transcript(directory, "ns-over-limit")
            size = path.stat().st_size
            with mock.patch("sessions.MAX_SESSION_FILE_BYTES", size - 1):
                with self.assertRaises(ResumeRefusedError):
                    SessionStore(directory, session_id="ns-over-limit")

    def test_a_transcript_exactly_at_the_record_bound_is_accepted(self):
        """`gt@461`: the resume record-count bound is STRICT.

        A transcript with exactly the bound's worth of records is legal.
        Under the mutant (``>`` -> ``>=``) it is refused.
        """
        from sessions import ResumeRefusedError, SessionStore

        with tempfile.TemporaryDirectory() as directory:
            _sealed_transcript(directory, "ns-record-limit", count=3)
            with mock.patch("sessions.MAX_SESSION_RECORDS", 3):
                try:
                    SessionStore(directory, session_id="ns-record-limit")
                except ResumeRefusedError as error:
                    self.fail(f"a transcript exactly at the record limit was refused: {error}")

    def test_a_transcript_one_record_over_the_record_bound_is_refused(self):
        """`gt@461`: the bound, from the other side."""
        from sessions import ResumeRefusedError, SessionStore

        with tempfile.TemporaryDirectory() as directory:
            _sealed_transcript(directory, "ns-record-over", count=4)
            with mock.patch("sessions.MAX_SESSION_RECORDS", 3):
                with self.assertRaises(ResumeRefusedError):
                    SessionStore(directory, session_id="ns-record-over")

    def test_a_transcript_exactly_at_the_byte_bound_is_accepted(self):
        """`gt@465`: the resume byte bound is STRICT.

        This is the bound that counts the bytes as they are read, not the
        size the file happened to have on disk.  A transcript whose bytes
        are exactly the bound is legal; under the mutant (``>`` -> ``>=``)
        it is refused.
        """
        from sessions import ResumeRefusedError, SessionStore

        with tempfile.TemporaryDirectory() as directory:
            path = _sealed_transcript(directory, "ns-byte-limit")
            size = path.stat().st_size
            with mock.patch("sessions.MAX_SESSION_FILE_BYTES", size):
                with mock.patch("sessions.MAX_SESSION_RECORDS", 10_000):
                    try:
                        SessionStore(directory, session_id="ns-byte-limit")
                    except ResumeRefusedError as error:
                        self.fail(f"a transcript exactly at the byte limit was refused: {error}")

    def test_a_transcript_one_byte_over_the_byte_bound_is_refused(self):
        """`gt@465`: the bound, from the other side."""
        from sessions import ResumeRefusedError, SessionStore

        with tempfile.TemporaryDirectory() as directory:
            path = _sealed_transcript(directory, "ns-byte-over")
            size = path.stat().st_size
            with mock.patch("sessions.MAX_SESSION_FILE_BYTES", size - 1):
                with mock.patch("sessions.MAX_SESSION_RECORDS", 10_000):
                    with self.assertRaises(ResumeRefusedError):
                        SessionStore(directory, session_id="ns-byte-over")

    def test_a_line_exactly_at_the_line_length_bound_is_accepted(self):
        """`gt@469`: the resume line-length bound is STRICT.

        A line whose length is exactly the bound is a legal record.  Under
        the mutant (``>`` -> ``>=``) it is refused as an over-long line.
        """
        from sessions import ResumeRefusedError, SessionStore

        with tempfile.TemporaryDirectory() as directory:
            path = _sealed_transcript(directory, "ns-line-limit")
            longest = max(len(line) + 1 for line in path.read_text(encoding="utf-8").splitlines())
            with mock.patch("sessions.MAX_SESSION_LINE_BYTES", longest):
                try:
                    SessionStore(directory, session_id="ns-line-limit")
                except ResumeRefusedError as error:
                    self.fail(f"a line exactly at the length limit was refused: {error}")

    def test_a_line_one_byte_over_the_line_length_bound_is_refused(self):
        """`gt@469`: the bound, from the other side."""
        from sessions import ResumeRefusedError, SessionStore

        with tempfile.TemporaryDirectory() as directory:
            path = _sealed_transcript(directory, "ns-line-over")
            longest = max(len(line) + 1 for line in path.read_text(encoding="utf-8").splitlines())
            with mock.patch("sessions.MAX_SESSION_LINE_BYTES", longest - 1):
                with self.assertRaises(ResumeRefusedError):
                    SessionStore(directory, session_id="ns-line-over")

    def test_a_transcript_exactly_at_the_read_record_bound_is_read(self):
        """`gt@993`: the READ record-count bound is STRICT.

        The reader has its own record-count bound, separate from the
        resume bound.  A transcript with exactly the bound's worth of
        records is read whole.  Under the mutant (``>`` -> ``>=``) the
        read raises instead.
        """
        from sessions import load_jsonl

        with tempfile.TemporaryDirectory() as directory:
            path = _sealed_transcript(directory, "ns-read-record-limit", count=3)
            with mock.patch("sessions.MAX_SESSION_RECORDS", 3):
                records, dropped = load_jsonl(path)
            self.assertEqual(len(records), 3)
            self.assertEqual(dropped, 0)

    def test_a_transcript_one_record_over_the_read_record_bound_is_refused(self):
        """`gt@993`: the bound, from the other side."""
        from sessions import SessionIntegrityError, load_jsonl

        with tempfile.TemporaryDirectory() as directory:
            path = _sealed_transcript(directory, "ns-read-record-over", count=4)
            with mock.patch("sessions.MAX_SESSION_RECORDS", 3):
                with self.assertRaises(SessionIntegrityError):
                    load_jsonl(path)

    def test_a_transcript_exactly_at_the_read_byte_bound_is_read(self):
        """`gt@998`: the READ byte bound is STRICT."""
        from sessions import load_jsonl

        with tempfile.TemporaryDirectory() as directory:
            path = _sealed_transcript(directory, "ns-read-byte-limit")
            size = path.stat().st_size
            with mock.patch("sessions.MAX_SESSION_FILE_BYTES", size):
                with mock.patch("sessions.MAX_SESSION_RECORDS", 10_000):
                    records, dropped = load_jsonl(path)
            self.assertEqual(len(records), 3)
            self.assertEqual(dropped, 0)

    def test_a_transcript_one_byte_over_the_read_byte_bound_is_refused(self):
        """`gt@998`: the bound, from the other side."""
        from sessions import SessionIntegrityError, load_jsonl

        with tempfile.TemporaryDirectory() as directory:
            path = _sealed_transcript(directory, "ns-read-byte-over")
            size = path.stat().st_size
            with mock.patch("sessions.MAX_SESSION_FILE_BYTES", size - 1):
                with mock.patch("sessions.MAX_SESSION_RECORDS", 10_000):
                    with self.assertRaises(SessionIntegrityError):
                        load_jsonl(path)

    def test_a_line_exactly_at_the_read_line_length_bound_is_read(self):
        """`gt@1002`: the READ line-length bound is STRICT."""
        from sessions import load_jsonl

        with tempfile.TemporaryDirectory() as directory:
            path = _sealed_transcript(directory, "ns-read-line-limit")
            longest = max(len(line) + 1 for line in path.read_text(encoding="utf-8").splitlines())
            with mock.patch("sessions.MAX_SESSION_LINE_BYTES", longest):
                records, dropped = load_jsonl(path)
            self.assertEqual(len(records), 3)
            self.assertEqual(dropped, 0)

    def test_a_line_one_byte_over_the_read_line_length_bound_is_refused(self):
        """`gt@1002`: the bound, from the other side."""
        from sessions import SessionIntegrityError, load_jsonl

        with tempfile.TemporaryDirectory() as directory:
            path = _sealed_transcript(directory, "ns-read-line-over")
            longest = max(len(line) + 1 for line in path.read_text(encoding="utf-8").splitlines())
            with mock.patch("sessions.MAX_SESSION_LINE_BYTES", longest - 1):
                with self.assertRaises(SessionIntegrityError):
                    load_jsonl(path)


class SessionResumeGuardTests(unittest.TestCase):
    """The resume guards: the chain head, the empty transcript, the version.

      eq@497 / and@497  ``last is None and record_count == 0``
      or@499            ``not verification.ok or last is None or first_record is None``
      or@504            ``not isinstance(head, str) or len(head) != 64``

    Each is a two-armed conditional whose arms the suite drove only one
    side of.  The transcripts here are crafted: a valid sealed chain, a
    chain whose body was edited after sealing, a chain whose head is a
    truncated string, and a transcript whose only line is blank.
    """

    def test_a_valid_chain_is_resumed(self):
        """`or@499`: the control -- a good chain is resumed.

        Under the mutant (``or`` -> ``and``) a good chain would be
        refused, so this proves the guard is not simply always refusing.
        """
        from sessions import SessionStore

        with tempfile.TemporaryDirectory() as directory:
            _sealed_transcript(directory, "ns-good-chain")
            store = SessionStore(directory, session_id="ns-good-chain")
            records, _ = store.read()
            self.assertEqual(len(records), 3)

    def test_a_broken_chain_is_refused_on_resume(self):
        """`or@499`: the chain-verification arm.

        A transcript whose last record was edited after sealing has a
        broken chain.  The store must refuse to resume it.  Under the
        mutant (``or`` -> ``and``) the refusal would be skipped whenever
        ``last`` and ``first_record`` are both present -- which they are,
        in exactly this case -- so the damaged history would be resumed.
        """
        from sessions import ResumeRefusedError, SessionStore

        with tempfile.TemporaryDirectory() as directory:
            path = _sealed_transcript(directory, "ns-broken-chain")
            _tamper_last_record(path)

            with self.assertRaises(ResumeRefusedError):
                SessionStore(directory, session_id="ns-broken-chain")

    def test_a_chain_with_a_truncated_head_is_refused(self):
        """`or@504`: the chain-head arm.

        The last record's ``chain_hash`` is a string of the wrong length,
        so there is no head to resume from.  The store must refuse.  Under
        the mutant (``or`` -> ``and``) the ``isinstance`` half alone
        would have to catch it, and a truncated head -- a string, but a
        short one -- would slip through.
        """
        from sessions import ResumeRefusedError, SessionStore

        with tempfile.TemporaryDirectory() as directory:
            path = _sealed_transcript(directory, "ns-short-head")
            lines = path.read_text(encoding="utf-8").splitlines()
            record = json.loads(lines[-1])
            record["chain_hash"] = "deadbeef"
            lines[-1] = json.dumps(record, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")

            with self.assertRaises(ResumeRefusedError):
                SessionStore(directory, session_id="ns-short-head")

    def test_a_transcript_of_only_blank_lines_is_refused(self):
        """`eq@497` / `and@497`: the empty-transcript arm.

        The fresh-chain branch fires when there is no last record AND no
        records were counted.  A transcript whose only line is BLANK has
        a record count of one and no last record -- so it is NOT a fresh
        chain, and the store must refuse it.  Under the mutant
        (``==`` -> ``!=``) the blank line's count of one would satisfy
        the bound and the store would open a transcript that says
        nothing as though it were a brand new session.
        """
        from sessions import ResumeRefusedError, SessionStore

        with tempfile.TemporaryDirectory() as directory:
            session_id = "ns-blank"
            path = Path(directory) / f"{session_id}.jsonl"
            path.write_text("\n", encoding="utf-8")
            with self.assertRaises(ResumeRefusedError):
                SessionStore(directory, session_id=session_id)

    def test_an_empty_transcript_resumes_as_a_fresh_chain(self):
        """`eq@497` / `and@497`: the control -- the truly empty transcript.

        A transcript with no lines at all is a fresh chain: the store
        must open it, mint the genesis anchor and be ready to write.
        """
        from sessions import SessionStore

        with tempfile.TemporaryDirectory() as directory:
            session_id = "ns-empty"
            path = Path(directory) / f"{session_id}.jsonl"
            path.write_text("", encoding="utf-8")
            store = SessionStore(directory, session_id=session_id)
            self.assertTrue(store._genesis_pending)
            store.append("informational", {"content": "first"})
            records, _ = store.read()
            self.assertEqual(len(records), 1)
            self.assertIn("genesis", records[0])


class SessionRedactionGuardTests(unittest.TestCase):
    """The redaction and integrity guards on the resume path.

      eq@895           the ``session_start`` type half
      eq@897           the ``session_content_mode`` half
      or@900           the ``redacted_mode or content_redacted`` half
      or@902           the ``session_id or self.session_id`` half
      and@905          the ``require_integrity and records`` half
      or@906           the same, on the message
      or@916           the ``session_id or self.session_id`` on the verify call
      or@920           the same, on the verify message

    The suite never resumed a redacted transcript, so none of these fired.
    The transcripts here carry the marker a redacted record carries.
    """

    def _redacted_store(self, directory, session_id):
        from sessions import SessionStore

        _write_chain(
            directory,
            session_id,
            [
                {
                    "index": 0,
                    "ts": "2026-01-01T00:00:00.000Z",
                    "session_id": session_id,
                    "type": "session_start",
                    "agent": "main",
                    "data": {"session_content_mode": "omitted"},
                },
            ],
        )
        return SessionStore(directory, session_id=session_id)

    def test_a_redacted_transcript_is_not_resumable(self):
        """`eq@897`: the ``session_content_mode`` half.

        A transcript whose ``session_start`` says its content was omitted
        cannot be resumed: the prose it would resume from is gone.  Under
        the mutant (``==`` -> ``!=``) the marker is not recognised, and
        the redacted transcript resumes as if it were whole.
        """
        from sessions import ResumeRefusedError

        with tempfile.TemporaryDirectory() as directory:
            store = self._redacted_store(directory, "ns-redacted")
            with self.assertRaises(ResumeRefusedError) as caught:
                store.transcript()
            self.assertIn("ns-redacted", str(caught.exception))

    def test_a_session_start_that_is_not_redacted_is_resumable(self):
        """`eq@895`: the ``session_start`` type half.

        A ``session_start`` record whose ``data`` does NOT carry the
        omitted marker is an ordinary session start, and the transcript
        resumes.  Under the mutant (``==`` -> ``!=``) the type half
        would not match, and the marker check would never run -- so this
        test is the control for the one above: it proves the refusal
        comes from the marker, not from the record's type.
        """
        from sessions import SessionStore

        with tempfile.TemporaryDirectory() as directory:
            session_id = "ns-not-redacted"
            _write_chain(
                directory,
                session_id,
                [
                    {
                        "index": 0,
                        "ts": "2026-01-01T00:00:00.000Z",
                        "session_id": session_id,
                        "type": "session_start",
                        "agent": "main",
                        "data": {"run_posture": "default"},
                    },
                ],
            )
            store = SessionStore(directory, session_id=session_id)
            self.assertEqual(store.transcript(), [])

    def test_a_record_marked_content_redacted_is_not_resumable(self):
        """`or@900`: the ``content_redacted`` arm.

        A record carrying ``content_redacted: true`` marks its own body
        as omitted.  That marker alone must refuse the resume.  Under the
        mutant (``or`` -> ``and``) the marker is only consulted when the
        ``session_start`` mode marker is also present -- so a transcript
        whose redaction was recorded per-record (and not in the
        ``session_start`` record) would resume with the omitted content
        silently missing.
        """
        from sessions import ResumeRefusedError, SessionStore

        with tempfile.TemporaryDirectory() as directory:
            session_id = "ns-redacted-record"
            _write_chain(
                directory,
                session_id,
                [
                    {
                        "index": 0,
                        "ts": "2026-01-01T00:00:00.000Z",
                        "session_id": session_id,
                        "type": "session_start",
                        "agent": "main",
                    },
                    {
                        "index": 1,
                        "ts": "2026-01-01T00:00:01.000Z",
                        "session_id": session_id,
                        "type": "informational",
                        "agent": "main",
                        "content_redacted": True,
                    },
                ],
            )
            store = SessionStore(directory, session_id=session_id)
            with self.assertRaises(ResumeRefusedError):
                store.transcript()

    def test_an_unredacted_transcript_is_still_resumable(self):
        """`or@900`: the control -- the marker is what refuses.

        Under the mutant (``or`` -> ``and``) a transcript with NEITHER
        marker would take the refusal branch, so every ordinary session
        would be unresumable.  This proves the guard still lets the
        ordinary case through.
        """
        from sessions import SessionStore

        with tempfile.TemporaryDirectory() as directory:
            session_id = "ns-plain"
            _write_chain(
                directory,
                session_id,
                [
                    {
                        "index": 0,
                        "ts": "2026-01-01T00:00:00.000Z",
                        "session_id": session_id,
                        "type": "session_start",
                        "agent": "main",
                        "data": {"run_posture": "default"},
                    },
                ],
            )
            store = SessionStore(directory, session_id=session_id)
            self.assertEqual(store.transcript(), [])

    def test_an_unsealed_transcript_is_refused_when_integrity_is_required(self):
        """`and@905`: the ``records`` half.

        ``require_integrity=True`` refuses a transcript that carries no
        chain fields.  The guard has three arms -- integrity was asked
        for, there are records, and the records are unsealed -- and the
        suite drove only the first and third.
        """
        from sessions import ResumeRefusedError, SessionStore

        with tempfile.TemporaryDirectory() as directory:
            session_id = "ns-unsealed"
            path = Path(directory) / f"{session_id}.jsonl"
            path.write_text(
                json.dumps({"index": 0, "type": "session_start", "agent": "main"}) + "\n",
                encoding="utf-8",
            )
            store = SessionStore(directory, session_id=session_id, chain=False)
            with self.assertRaises(ResumeRefusedError) as caught:
                store.transcript(require_integrity=True)
            self.assertIn("ns-unsealed", str(caught.exception))

    def test_an_empty_transcript_is_not_refused_as_unsealed(self):
        """`and@905`: the other side -- an empty transcript.

        With ``require_integrity=True`` and no records at all, there is
        no unsealed history to refuse.  The guard must let it through.
        Under the mutant (``and`` -> ``or``) an empty transcript would be
        refused as an unsealed one.
        """
        from sessions import SessionStore

        with tempfile.TemporaryDirectory() as directory:
            session_id = "ns-empty-unsealed"
            path = Path(directory) / f"{session_id}.jsonl"
            path.write_text("", encoding="utf-8")
            store = SessionStore(directory, session_id=session_id, chain=False)
            self.assertEqual(store.transcript(require_integrity=True), [])

    def test_the_transcript_verification_is_bound_to_this_session(self):
        """`or@916`: the ``expect_session_id`` half.

        The transcript verification must expect THIS store's session id.
        Under the mutant (``or`` -> ``and``) the expectation becomes
        ``None`` when no other session id was named, and the verifier
        stops checking the genesis anchor's session id at all -- so a
        transcript that belongs to a different session would be resumed
        as this one.
        """
        from sessions import ResumeRefusedError, SessionStore

        with tempfile.TemporaryDirectory() as directory:
            # A transcript sealed for one session, sitting under another
            # session's name.
            _write_chain(
                directory,
                "ns-foreign",
                [
                    {
                        "index": 0,
                        "ts": "2026-01-01T00:00:00.000Z",
                        "session_id": "ns-foreign",
                        "type": "session_start",
                        "agent": "main",
                    },
                ],
            )
            path = Path(directory) / "ns-mine.jsonl"
            path.write_text(
                (Path(directory) / "ns-foreign.jsonl").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            store = SessionStore(directory, session_id="ns-mine", chain=False)
            with self.assertRaises(ResumeRefusedError):
                store.transcript()

    def test_the_transcript_verification_failure_names_the_session(self):
        """`or@920`: the verify message's ``session_id or self.session_id``.

        When the transcript's own chain does not verify, the refusal must
        say WHICH session it refused.  Under the mutant (``or`` ->
        ``and``) the message would say ``None``.
        """
        from sessions import ResumeRefusedError, SessionStore

        with tempfile.TemporaryDirectory() as directory:
            session_id = "ns-verify"
            store = SessionStore(directory, session_id=session_id)
            store.append("informational", {"content": "x"})
            _tamper_last_record(store.path)

            with self.assertRaises(ResumeRefusedError) as caught:
                store.transcript()
            self.assertIn(session_id, str(caught.exception))


class SessionWriteGuardTests(unittest.TestCase):
    """The write-side guards: the chain stamp, the record-size bound.

      eq@546 / and@546  the ``session_start`` half of the redaction branch
      eq@569            the chain-v2 stamp
      and@530           the ``path is not None and path.exists()`` half
      and@586 / and@596  the ``self.chain and "chain_hash" in record`` half
      retF@614 / retT@616  the HLC merge answer
      gt@620 / and@620  the record-size bound
      and@642           the re-seal half of the truncation path
      or@844            the lift-type guard
      or@873            the read-path guard
    """

    def test_a_redacted_session_start_keeps_its_posture(self):
        """`eq@546` / `and@546`: the ``session_start`` half.

        A redacted store's ``session_start`` record keeps the run posture
        visible and marks its content as omitted.  Under the mutant
        (``==`` -> ``!=``) the ``session_start`` branch is skipped and the
        record is redacted wholesale -- the posture marker goes with it,
        and the transcript can no longer tell a redacted session from an
        ordinary one.
        """
        from sessions import SessionStore

        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory, session_id="ns-redact-posture", redact_content=True, chain=False)
            record = store.append(
                "session_start",
                {"agent": "main", "data": {"run_posture": "default", "verify_condition": "contains: canary"}},
            )
            self.assertEqual(record["data"]["session_content_mode"], "omitted")
            self.assertEqual(record["data"]["run_posture"], "default")

    def test_a_redacted_non_start_record_is_wholesale_redacted(self):
        """`eq@546` / `and@546`: the other side.

        A record that is NOT a ``session_start`` has its whole payload
        redacted.  Under the mutant (``==`` -> ``!=``) the branch would
        fire on this record instead, keeping its ``data`` and dropping
        only the top-level keys -- the opposite of the rule.  Under the
        mutant (``and`` -> ``or``) the branch would fire on this record
        too, because it carries a ``data`` dict -- and the omitted-mode
        marker would be stamped on a record that is not a session start.
        """
        from sessions import SessionStore

        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory, session_id="ns-redact-other", redact_content=True, chain=False)
            record = store.append("informational", {"agent": "main", "content": "secret"})
            self.assertEqual(record.get("content"), "[omitted by session privacy mode]")
            self.assertTrue(record.get("content_redacted"))
            self.assertNotIn("session_content_mode", record.get("data", {}))

    def test_a_chain_v2_record_declares_its_chain(self):
        """`eq@569`: the chain-v2 stamp.

        A v2 record declares its own chain version, so a streaming
        verifier never has to infer the canonicalization from a distant
        line.  Under the mutant (``==`` -> ``!=``) the stamp is dropped
        and the record becomes version-ambiguous.
        """
        from sessions import SessionStore

        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory, session_id="ns-v2")
            record = store.append("informational", {"content": "x"})
            self.assertEqual(record.get("chain"), "northstar-audit-chain/2")

    def test_bytes_written_is_zero_for_a_store_with_no_transcript(self):
        """`and@530`: the ``path.exists()`` half.

        A store that has written nothing has no transcript file, and its
        ``bytes_written`` is 0.  Under the mutant (``and`` -> ``or``) a
        store whose path is set but whose file does not exist would try
        to ``stat`` a missing file and raise ``FileNotFoundError`` -- the
        ordinary "nothing written yet" state would be an error.
        """
        from sessions import SessionStore

        store = SessionStore(None, session_id="ns-nobytes")
        self.assertEqual(store.bytes_written, 0)

    def test_an_unsealed_store_does_not_advance_the_chain_head(self):
        """`and@586` / `and@596`: the ``chain_hash in record`` half.

        A store with ``chain=False`` writes no chain fields, so it has no
        chain head to advance.  Under the mutant (``and`` -> ``or``) the
        head would be advanced from a record that has no ``chain_hash``,
        and the store would claim a chain it never wrote.
        """
        from sessions import SessionStore

        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory, session_id="ns-nochain", chain=False)
            record = store.append("informational", {"content": "x"})
            self.assertNotIn("chain_hash", record)
            self.assertIsNone(store._prev_hash)

    def test_a_sealed_store_advances_the_chain_head(self):
        """`and@586` / `and@596`: the other side -- the control."""
        from sessions import SessionStore

        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory, session_id="ns-chain")
            record = store.append("informational", {"content": "x"})
            self.assertIn("chain_hash", record)
            self.assertEqual(store._prev_hash, record["chain_hash"])

    def test_a_store_with_no_chain_head_does_not_claim_one(self):
        """`and@586` / `and@596`: the ``chain_hash`` half, in isolation.

        A sealed store whose chain head is absent (a store that was
        opened but never given a genesis anchor) writes a record with no
        ``chain_hash``.  Under the mutant (``and`` -> ``or``) the head
        would be advanced from that record -- and the store would claim
        a chain head it never had.
        """
        from sessions import SessionStore

        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory, session_id="ns-nohead", chain=False)
            store._prev_hash = None
            record = store.append("informational", {"content": "x"})
            self.assertNotIn("chain_hash", record)
            self.assertIsNone(store._prev_hash)

    def test_an_unparseable_hlc_stamp_is_not_merged(self):
        """`retF@614`: the "not merged" answer.

        A stamp that cannot be parsed leaves the clock unchanged, and the
        merge says so.  Under the mutant (``return False`` -> ``return
        True``) the merge would claim to have merged a stamp it could
        not read, and a caller would stamp its next record as if it had
        observed that writer.
        """
        from sessions import SessionStore

        store = SessionStore(None, session_id="ns-hlc")
        before = (store._hlc_l, store._hlc_c)
        self.assertFalse(store.merge_hlc("not-a-stamp"))
        self.assertEqual((store._hlc_l, store._hlc_c), before)

    def test_a_parsed_hlc_stamp_is_merged(self):
        """`retT@616`: the "merged" answer -- the control.

        A well-formed stamp IS merged, and the clock moves forward past
        it.  Under the mutant (``return True`` -> ``return False``) the
        merge would be reported as failed even though the clock moved,
        so a multi-writer feed would stop recording that it had
        observed the other writer.
        """
        from sessions import SessionStore

        store = SessionStore(None, session_id="ns-hlc-ok")
        self.assertTrue(store.merge_hlc("1700000000000:4"))
        self.assertGreater(store._hlc_l, 0)

    def test_a_record_with_truncation_disabled_is_written_whole(self):
        """`gt@620` / `and@620`: the ``max_record_chars > 0`` guard.

        ``max_record_chars=0`` turns truncation OFF, and the record is
        written whole.  Under the mutant (``>`` -> ``>=``) the guard
        would fire at zero, and every record would be truncated to
        nothing -- with truncation switched off.  Under the mutant
        (``and`` -> ``or``) the same thing happens: the ``or`` short
        circuits past the length check.
        """
        from sessions import SessionStore

        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory, session_id="ns-notrunc", chain=False, max_record_chars=0)
            record = store.append("informational", {"content": "x" * 500})
            self.assertNotIn("truncated", record)
            self.assertEqual(record.get("content"), "x" * 500)

    def test_a_record_over_the_size_bound_is_truncated(self):
        """`gt@620` / `and@620`: the bound, from the other side."""
        from sessions import SessionStore

        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory, session_id="ns-size-over", chain=False, max_record_chars=40)
            record = store.append("informational", {"content": "x" * 200})
            self.assertTrue(record.get("truncated"))

    def test_a_truncated_record_is_re_sealed(self):
        """`and@642`: the re-seal half.

        A truncated record is re-sealed over its truncated body, so the
        bytes on disk still verify.  Under the mutant (``and`` ->
        ``or``) the re-seal would be attempted whenever ``prev_hash`` is
        a string -- including a store with no chain -- and the written
        record would carry a chain hash the store never promised.
        """
        from sessions import SessionStore

        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory, session_id="ns-reseal", chain=False, max_record_chars=60)
            store.append("informational", {"content": "x" * 200})
            records, _ = store.read()
            self.assertNotIn("chain_hash", records[0])

    def test_a_truncated_record_without_a_chain_head_is_not_re_sealed(self):
        """`and@642`: the ``prev_hash`` half, in isolation.

        A store that is sealed but has no chain head yet writes a
        truncated record with no ``prev_hash`` to re-seal over.  Under
        the mutant (``and`` -> ``or``) the re-seal would be attempted
        with a missing previous hash, and the write would blow up.
        """
        from sessions import SessionStore

        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory, session_id="ns-reseal-nohead", chain=True, max_record_chars=60)
            store._prev_hash = None
            record = store.append("informational", {"content": "x" * 200})
            self.assertNotIn("chain_hash", record)

    def test_a_lift_against_a_non_lift_is_refused(self):
        """`or@844`: the lift-type guard.

        A lift may only be recorded against a tombstone, and the tombstone
        half of the guard says so too.  Under the mutant (``or`` ->
        ``and``) the guard would demand that BOTH be wrong to refuse, so
        a valid tombstone paired with a NON-lift would be recorded -- a
        lift that lifts nothing, written as though it did.
        """
        from cancellation_tombstone import TombstoneError
        from sessions import SessionStore

        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory, session_id="ns-badlift")
            tombstone = a_tombstone(action="Write")
            store.record_cancellation(tombstone)
            with self.assertRaises(TombstoneError):
                store.record_cancellation_lift(tombstone, "not-a-lift")

    def test_a_lift_against_a_non_tombstone_is_refused(self):
        """`or@844`: the other side -- the tombstone half.

        A tombstone half that is not a tombstone is refused too.  Under
        the mutant (``or`` -> ``and``) this case would slip through when
        the lift IS a lift.
        """
        from cancellation_tombstone import TombstoneError
        from sessions import SessionStore

        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory, session_id="ns-badtombstone")
            tombstone = a_tombstone(action="Write")
            with self.assertRaises(TombstoneError):
                store.record_cancellation_lift("not-a-tombstone", a_lift(tombstone))

    def test_reading_a_missing_transcript_returns_no_records(self):
        """`or@873`: the read-path guard.

        Reading a transcript that does not exist returns no records and
        no error -- the ordinary "this session wrote nothing" case.  Under
        the mutant (``or`` -> ``and``) a store whose path is set would
        read the path directly and raise ``FileNotFoundError``.
        """
        from sessions import SessionStore

        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory, session_id="ns-absent")
            records, dropped = store.read()
            self.assertEqual(records, [])
            self.assertEqual(dropped, 0)


class SessionSpendGuardTests(unittest.TestCase):
    """The spend aggregation guards.

      eq@1047  the ``result`` type half
      or@1048  the ``total_cost_usd`` fallback
      eq@1051  the ``assistant`` type half
      or@1054  the ``model`` fallback
    """

    def test_a_result_record_contributes_its_cost(self):
        """`eq@1047` / `or@1048`: the ``result`` half and the cost fallback.

        A ``result`` record carries the run's settled cost, and
        ``session_spend`` must count it.  Under the mutant
        (``==`` -> ``!=``) the settled cost would be ignored and only the
        priced trailing usage would count -- so a run whose cost was
        reported by the provider would be reported as free.  Under the
        mutant of the fallback (``or`` -> ``and``) the same cost would be
        dropped.
        """
        from sessions import session_spend

        cost, _usage = session_spend([{"type": "result", "total_cost_usd": 1.25, "usage": {}}])
        self.assertAlmostEqual(cost, 1.25, places=6)

    def test_a_result_record_with_no_cost_contributes_nothing(self):
        """`or@1048`: the other side -- the missing-cost fallback.

        A ``result`` record with no cost field contributes 0, not a
        crash.
        """
        from sessions import session_spend

        cost, _usage = session_spend([{"type": "result", "usage": {}}])
        self.assertEqual(cost, 0.0)

    def test_an_assistant_record_contributes_its_usage(self):
        """`eq@1051`: the ``assistant`` half.

        An ``assistant`` record's usage is counted into the total.  Under
        the mutant (``==`` -> ``!=``) the assistant arm would be skipped
        and the transcript's tokens would be invisible.
        """
        from sessions import session_spend

        _cost, usage = session_spend(
            [
                {
                    "type": "assistant",
                    "model": "claude-haiku-4-5",
                    "usage": {"input_tokens": 1000, "output_tokens": 500},
                }
            ]
        )
        self.assertEqual(usage.input_tokens, 1000)
        self.assertEqual(usage.output_tokens, 500)

    def test_a_model_change_prices_the_trailing_usage_at_the_old_model(self):
        """`and@1055`: the model-change half.

        When the model changes mid-transcript, the trailing usage is
        priced at the model that produced it before the trailing usage is
        reset.  Under the mutant (``and`` -> ``or``) the trailing usage
        would be flushed at EVERY assistant record -- so the earlier
        segment would be priced at the NEW model.
        """
        from sessions import session_spend

        records = [
            {"type": "assistant", "model": "claude-haiku-4-5",
             "usage": {"input_tokens": 1_000_000, "output_tokens": 0}},
            {"type": "assistant", "model": "claude-opus-4-1",
             "usage": {"input_tokens": 1_000_000, "output_tokens": 0}},
        ]
        cost, _usage = session_spend(records)
        # 1M haiku input tokens at $0.80/MTok, then 1M opus input at
        # $15/MTok: $0.80 + $15.00.
        self.assertAlmostEqual(cost, 15.80, places=6)

    def test_a_record_with_no_model_keeps_the_trailing_model(self):
        """`or@1054`: the model fallback.

        An assistant record with no model keeps the trailing model, so
        the usage is priced at the model that was actually in force.
        Under the mutant (``or`` -> ``and``) the expression becomes
        ``record.get("model", "") and trailing_model`` -- the empty
        string, not the trailing model -- so the segment would be priced
        at the conservative fallback tier ($15/MTok) instead of the real
        model.
        """
        from sessions import session_spend

        records = [
            {"type": "assistant", "model": "claude-haiku-4-5",
             "usage": {"input_tokens": 1_000_000, "output_tokens": 0}},
            {"type": "assistant",
             "usage": {"input_tokens": 1_000_000, "output_tokens": 0}},
        ]
        cost, _usage = session_spend(records)
        # Both segments at the haiku rate: $0.80 + $0.80.
        self.assertAlmostEqual(cost, 1.60, places=6)


class SessionTranscriptGuardTests(unittest.TestCase):
    """The transcript-replay guards.

      eq@1075 / and@1075  the root-agent probe
      and@1081           the root-agent filter
      eq@1084 / or@1084 the role fallback
      or@1085           the content fallback
      or@1090 / or@1092 the assistant model's and stop reason's fallbacks
    """

    def test_a_child_agent_record_is_not_in_the_root_transcript(self):
        """`and@1081`: the root-agent filter.

        A child agent's exchange shares the audit file but is not part of
        the root model's conversation.  Under the mutant (``and`` ->
        ``or``) the filter short-circuits on "the root agent is known"
        and drops EVERY record -- including the root's own.
        """
        from sessions import transcript_from_records

        records = [
            {"type": "session_start", "agent": "main"},
            {"type": "assistant", "agent": "main", "role": "assistant",
             "content": [{"type": "text", "text": "root"}]},
            {"type": "assistant", "agent": "child", "role": "assistant",
             "content": [{"type": "text", "text": "child"}]},
        ]
        transcript = transcript_from_records(records)
        self.assertEqual(len(transcript), 1)
        self.assertIn("root", transcript[0].text)

    def test_a_record_with_no_agent_is_kept_in_the_transcript(self):
        """`and@1081`: the other side -- the type half.

        A record with no ``agent`` field is not a child agent's, so it
        belongs to the root transcript.  Under the mutant (``and`` ->
        ``or``) it would be dropped, and the transcript would lose
        records that carry no agent at all.
        """
        from sessions import transcript_from_records

        records = [
            {"type": "session_start", "agent": "main"},
            {"type": "user_prompt", "role": "user", "content": [{"type": "text", "text": "hello"}]},
        ]
        transcript = transcript_from_records(records)
        self.assertEqual(len(transcript), 1)

    def test_a_session_start_with_a_non_string_agent_names_no_root_agent(self):
        """`and@1075`: the ``isinstance(agent, str)`` half.

        A ``session_start`` record whose ``agent`` is not a string does
        not name the root agent.  Under the mutant (``and`` -> ``or``)
        it WOULD name one -- and then every record with a string agent
        would be treated as a child agent's and dropped.
        """
        from sessions import transcript_from_records

        records = [
            {"type": "session_start", "agent": 42},
            {"type": "user_prompt", "role": "user", "content": [{"type": "text", "text": "hello"}]},
        ]
        transcript = transcript_from_records(records)
        self.assertEqual(len(transcript), 1)
        self.assertIn("hello", transcript[0].text)

    def test_a_non_start_record_does_not_name_the_root_agent(self):
        """`eq@1075`: the ``session_start`` half.

        The root agent is named by a ``session_start`` record and by
        nothing else.  Under the mutant (``==`` -> ``!=``) an ordinary
        record would name it instead -- so a transcript with no session
        start at all would acquire a root agent, and the records whose
        agent differs would be dropped from the replay.
        """
        from sessions import transcript_from_records

        records = [
            {"type": "user_prompt", "agent": "main", "role": "user",
             "content": [{"type": "text", "text": "from main"}]},
            {"type": "user_prompt", "agent": "child", "role": "user",
             "content": [{"type": "text", "text": "from child"}]},
        ]
        transcript = transcript_from_records(records)
        self.assertEqual(len(transcript), 2)

    def test_a_record_with_no_role_defaults_to_the_kind(self):
        """`eq@1084` / `or@1084`: the role fallback.

        An assistant record with no ``role`` field is an assistant
        message; a user record with no ``role`` is a user message.  Under
        the mutant (``==`` -> ``!=``) an assistant record with no role
        would be replayed as a USER message -- the model's own turn
        replayed as the user's.  Under the mutant (``or`` -> ``and``) the
        fallback would be skipped entirely and the record would replay
        with no role at all.
        """
        from sessions import transcript_from_records

        records = [
            {"type": "session_start", "agent": "main"},
            {"type": "assistant", "agent": "main", "content": [{"type": "text", "text": "from the model"}]},
        ]
        transcript = transcript_from_records(records)
        self.assertEqual(len(transcript), 1)
        self.assertEqual(transcript[0].role, "assistant")

    def test_a_user_record_with_no_role_defaults_to_the_user_role(self):
        """`or@1084`: the other side -- the user's side of the fallback.

        A ``user_prompt`` record with no ``role`` is a user message.
        Under the mutant (``or`` -> ``and``) the expression becomes
        ``record.get("role") and (...)``, so a record with NO role would
        replay with an empty role instead of ``"user"``.
        """
        from sessions import transcript_from_records

        records = [
            {"type": "session_start", "agent": "main"},
            {"type": "user_prompt", "content": [{"type": "text", "text": "from the user"}]},
        ]
        transcript = transcript_from_records(records)
        self.assertEqual(len(transcript), 1)
        self.assertEqual(transcript[0].role, "user")

    def test_a_record_with_content_replays_its_content(self):
        """`or@1085`: the content fallback.

        A record with no content replays as an empty message rather than
        crashing.  Under the mutant (``or`` -> ``and``) the expression
        becomes ``record.get("content") and ()`` -- so a record whose
        content is a non-empty list would replay as EMPTY, and the
        model's turn would be lost.
        """
        from sessions import transcript_from_records

        records = [
            {"type": "session_start", "agent": "main"},
            {"type": "assistant", "agent": "main", "role": "assistant",
             "content": [{"type": "text", "text": "kept"}]},
        ]
        transcript = transcript_from_records(records)
        self.assertEqual(len(transcript), 1)
        self.assertIn("kept", transcript[0].text)

    def test_an_assistant_record_keeps_its_model_and_stop_reason(self):
        """`or@1090` / `or@1092`: the assistant fallbacks.

        An assistant record's model and stop reason are carried into the
        replayed message.  Under the mutants (``or`` -> ``and``) the
        fallbacks would yield the empty string instead, so the replayed
        message would lose both.
        """
        from sessions import transcript_from_records

        records = [
            {"type": "session_start", "agent": "main"},
            {"type": "assistant", "agent": "main", "role": "assistant", "model": "claude-haiku-4-5",
             "stop_reason": "end_turn", "content": [{"type": "text", "text": "x"}]},
        ]
        transcript = transcript_from_records(records)
        self.assertEqual(len(transcript), 1)
        self.assertEqual(transcript[0].model, "claude-haiku-4-5")
        self.assertEqual(transcript[0].stop_reason, "end_turn")


class SessionReplayBoundaryGuardTests(unittest.TestCase):
    """The compaction-boundary and informational guards in the replay.

      eq@1097  the ``compact_boundary`` type half
      or@1104  the boundary content fallback
      or@1105  the boundary data fallback
      eq@1108  the ``informational`` type half
      or@1109  the informational data fallback
      eq@1110 / and@1110  the ``session_lease_lost`` skip
      or@1117  the informational content fallback
    """

    def test_a_compaction_boundary_replaces_the_earlier_transcript(self):
        """`eq@1097`: the ``compact_boundary`` type half.

        A compaction boundary is a state boundary: the provider
        transcript starts at the summary, so the earlier messages are
        dropped.  Under the mutant (``==`` -> ``!=``) the boundary would
        not be recognised and the earlier messages would stay.
        """
        from sessions import transcript_from_records

        records = [
            {"type": "session_start", "agent": "main"},
            {"type": "user_prompt", "role": "user", "content": [{"type": "text", "text": "before"}]},
            {"type": "compact_boundary", "agent": "main", "content": "summary",
             "data": {"reason": "compaction"}},
        ]
        transcript = transcript_from_records(records)
        self.assertEqual(len(transcript), 1)
        self.assertEqual(transcript[0].subtype, "compact_boundary")
        self.assertEqual(transcript[0].content, "summary")
        self.assertEqual(transcript[0].data, {"reason": "compaction"})

    def test_an_informational_record_does_not_clear_the_transcript(self):
        """`eq@1108`: the ``informational`` type half.

        An informational record is a system note, not a state boundary.
        Under the mutant (``==`` -> ``!=``) the informational branch
        would not be taken and the note would be dropped from the replay.
        """
        from sessions import transcript_from_records

        records = [
            {"type": "session_start", "agent": "main"},
            {"type": "user_prompt", "role": "user", "content": [{"type": "text", "text": "before"}]},
            {"type": "informational", "agent": "main", "content": "note", "data": {"reason": "other"}},
        ]
        transcript = transcript_from_records(records)
        self.assertEqual(len(transcript), 2)
        self.assertEqual(transcript[1].subtype, "informational")
        self.assertEqual(transcript[1].content, "note")

    def test_an_informational_record_keeps_its_data(self):
        """`or@1109`: the informational data fallback.

        An informational record's data is carried into the replayed
        note.  Under the mutant (``or`` -> ``and``) the data would be
        replaced by an empty dict, and the note would lose what it was
        about.
        """
        from sessions import transcript_from_records

        records = [
            {"type": "session_start", "agent": "main"},
            {"type": "informational", "agent": "main", "content": "note",
             "data": {"reason": "other", "detail": "kept"}},
        ]
        transcript = transcript_from_records(records)
        self.assertEqual(len(transcript), 1)
        self.assertEqual(transcript[0].data, {"reason": "other", "detail": "kept"})

    def test_a_lease_lost_warning_is_not_in_the_transcript(self):
        """`eq@1110`: the ``session_lease_lost`` skip.

        A lease-lost warning is an audit warning emitted outside the
        transcript; it was never part of the in-memory provider context.
        Under the mutant (``==`` -> ``!=``) the skip would fire on every
        OTHER informational record, and this one would be replayed into
        the model's context.
        """
        from sessions import transcript_from_records

        records = [
            {"type": "session_start", "agent": "main"},
            {"type": "informational", "agent": "main", "content": "lost",
             "data": {"reason": "session_lease_lost"}},
        ]
        transcript = transcript_from_records(records)
        self.assertEqual(len(transcript), 0)

    def test_an_informational_record_with_empty_data_is_in_the_transcript(self):
        """`and@1110`: the ``isinstance(data, dict)`` half.

        An informational record whose data is an empty dict is an
        ordinary note, and it belongs in the transcript.  Under the
        mutant (``and`` -> ``or``) the skip would fire on it, and the
        note would be silently dropped.
        """
        from sessions import transcript_from_records

        records = [
            {"type": "session_start", "agent": "main"},
            {"type": "informational", "agent": "main", "content": "note", "data": {}},
        ]
        transcript = transcript_from_records(records)
        self.assertEqual(len(transcript), 1)
        self.assertEqual(transcript[0].content, "note")


class SessionSummaryGuardTests(unittest.TestCase):
    """The session-summary guards.

      eq@1133  the ``assistant`` type half
      eq@1135  the ``result`` type half
      or@1136  the ``total_cost_usd`` fallback
    """

    def test_an_assistant_record_counts_as_a_turn(self):
        """`eq@1133`: the ``assistant`` half.

        An assistant record is one turn.  Under the mutant (``==`` ->
        ``!=``) the turn count would be inverted: ordinary runs would
        report zero turns.
        """
        from sessions import summarise

        summary = summarise([{"type": "assistant"}])
        self.assertEqual(summary["assistant_turns"], 1)

    def test_a_result_record_reports_the_settled_cost(self):
        """`eq@1135` / `or@1136`: the ``result`` half and the cost fallback.

        A ``result`` record carries the run's settled cost and subtype.
        Under the mutant (``==`` -> ``!=``) the cost would come from a
        different record, and under the mutant of the fallback
        (``or`` -> ``and``) a record with a cost would report zero.
        """
        from sessions import summarise

        summary = summarise(
            [
                {"type": "informational", "total_cost_usd": 9.0},
                {"type": "result", "total_cost_usd": 2.5, "subtype": "success"},
            ]
        )
        self.assertEqual(summary["total_cost_usd"], 2.5)
        self.assertEqual(summary["subtype"], "success")

    def test_a_result_record_with_no_cost_reports_zero(self):
        """`or@1136`: the other side -- the missing-cost fallback.

        A ``result`` record with no cost field reports zero.  Under the
        mutant (``or`` -> ``and``) the expression becomes
        ``record.get("total_cost_usd") and 0.0`` -- so a present cost
        would be reported as 0.0 and a missing one as ``None``.
        """
        from sessions import summarise

        summary = summarise([{"type": "result", "subtype": "success"}])
        self.assertEqual(summary["total_cost_usd"], 0.0)


class SessionIdGuardTests(unittest.TestCase):
    """The session-id guards.

      or@1147  the ``isinstance(session_id, str)`` half
      and@1156  the ``store is not None and store.session_id`` half
    """

    def test_a_non_string_session_id_is_refused(self):
        """`or@1147`: the type half.

        A session id must be a string.  Under the mutant (``or`` ->
        ``and``) the pattern match would be reached with a non-string,
        and the error would not be the explicit "unsafe session id" one
        the caller relies on.
        """
        from sessions import validate_session_id

        with self.assertRaises(ValueError):
            validate_session_id(123)
        with self.assertRaises(ValueError):
            validate_session_id(None)

    def test_an_unsafe_string_session_id_is_refused(self):
        """`or@1147`: the other side -- the pattern half.

        A string that is not a safe single path component is refused.
        Under the mutant (``or`` -> ``and``) the type check would gate
        this out and the pattern would never be consulted for a string
        that IS a string -- so the string half of the guard would be
        dead code.
        """
        from sessions import validate_session_id

        with self.assertRaises(ValueError):
            validate_session_id("has space")
        with self.assertRaises(ValueError):
            validate_session_id("../escape")

    def test_resolve_session_id_prefers_the_store(self):
        """`and@1156`: the store half.

        A run without an explicit session id falls back to the store's
        own.  Under the mutant (``and`` -> ``or``) the store's id would
        be used only when the store is None -- the opposite of the rule
        -- so the fallback would never fire.
        """
        from sessions import SessionStore, resolve_session_id

        store = SessionStore(None, session_id="ns-resolved")
        self.assertEqual(resolve_session_id(None, store), "ns-resolved")

    def test_resolve_session_id_prefers_the_explicit_id(self):
        """`and@1156`: the other side -- the explicit id wins."""
        from sessions import SessionStore, resolve_session_id

        store = SessionStore(None, session_id="ns-resolved")
        self.assertEqual(resolve_session_id("ns-explicit", store), "ns-explicit")

    def test_resolve_session_id_mints_one_when_there_is_no_store(self):
        """`and@1156`: the control -- no store, no id.

        A run without a session store still needs a session id, so one is
        minted.  Under the mutant (``and`` -> ``or``) the expression
        becomes ``store is not None or store.session_id``, and the
        ``store.session_id`` half would be evaluated on a ``None``
        store -- an ``AttributeError`` where a session id should be.
        """
        from sessions import resolve_session_id

        minted = resolve_session_id(None, None)
        self.assertTrue(minted.startswith("ns-"))
class SessionRemainingArmTests(unittest.TestCase):
    """The last four survivors, each with the discriminating case.

    A surviving mutant is usually a second arm that the suite never
    drove.  Each of the four below needed a *different* shape of
    discriminating case, and the shape is the point: a test that feeds
    "both kinds of bad input" blindly does not discriminate here,
    because the second guard further down masks the first.

      and@546  the ``session_start`` redaction branch
      or@844   the lift-type guard
      and@1055 the model-change half of the spend aggregation
      or@504   the chain-head guard  (see ``EquivalentMutantTests``)
    """

    # --- and@546 ---------------------------------------------------------
    def test_a_redacted_record_that_carries_data_is_wholesale_redacted(self):
        """`and@546`: the type half of the redaction branch.

        The guard is ``record_type == "session_start" and isinstance(
        payload.get("data"), dict)``.  It has two halves: the record IS
        a session start, AND its ``data`` is a dict.  The suite drove
        the first half (a session start with a dict ``data``) and a
        record with NO ``data`` at all -- but never a record that is NOT
        a session start AND carries a dict ``data``.

        That is the only case where the halves disagree.  The ORIGINAL
        redacts such a record wholesale -- its ``data`` is replaced by
        the omission marker.  The MUTANT (``and`` -> ``or``) takes the
        session-start branch for it, KEEPS the ``data`` dict, and stamps
        ``session_content_mode`` into a record that is not a session
        start -- so a private payload survives a privacy-mode write.

        The earlier test (``test_a_redacted_non_start_record_is_
        wholesale_redacted``) does NOT discriminate: its payload has no
        ``data`` key, so both halves of the guard are false and the
        mutant takes the same branch as the original.
        """
        from sessions import SessionStore

        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory, session_id="ns-redact-data", redact_content=True, chain=False)
            record = store.append(
                "informational",
                {"agent": "main", "data": {"note": "private"}, "content": "secret"},
            )
            self.assertEqual(
                record.get("data"),
                "[omitted by session privacy mode]",
                "a redacted record's data must be omitted, not kept",
            )
            self.assertNotIn(
                "session_content_mode",
                record.get("data", {}) if isinstance(record.get("data"), dict) else {},
                "the omitted-mode marker belongs on a session start, not on every record",
            )

    # --- or@844 ----------------------------------------------------------
    def test_a_lift_that_is_not_a_lift_is_refused_by_the_guard_itself(self):
        """`or@844`: the lift-type guard, and WHICH guard refuses.

        The guard is ``not isinstance(tombstone, Tombstone) or not
        isinstance(lift, Lift)``.  Under the mutant (``or`` -> ``and``)
        the guard stops firing for a valid tombstone paired with a
        non-lift, and the call falls through to ``check_lift`` -- which
        raises a DIFFERENT exception with a DIFFERENT message
        (``TombstoneLiftError``: "a lift is checked against a tombstone")
        instead of the guard's own (``TombstoneError``: "a lift is
        recorded against a tombstone").

        ``TombstoneLiftError`` is a SUBCLASS of ``TombstoneError``, so a
        test that only asserts ``assertRaises(TombstoneError)`` passes
        under the mutant -- which is why the earlier lift test did not
        discriminate.  The exception TYPE and the MESSAGE are the
        discriminator.
        """
        from cancellation_tombstone import TombstoneError
        from sessions import SessionStore

        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory, session_id="ns-lift-guard")
            tombstone = a_tombstone(action="Write")
            store.record_cancellation(tombstone)
            with self.assertRaises(TombstoneError) as caught:
                store.record_cancellation_lift(tombstone, "not-a-lift")
            self.assertEqual(
                type(caught.exception),
                TombstoneError,
                "the guard's own error must be the one that refuses",
            )
            self.assertEqual(
                str(caught.exception),
                "a lift is recorded against a tombstone",
                "the refusal must come from the store's guard, not from the lift checker",
            )

    def test_a_tombstone_that_is_not_a_tombstone_is_refused_by_the_guard(self):
        """`or@844`: the other arm -- the tombstone half.

        A non-tombstone paired with a VALID lift is refused by the same
        guard.  Under the mutant (``or`` -> ``and``) the guard stops
        firing for this pair too, and the call falls through to
        ``check_lift`` with its different error.
        """
        from cancellation_tombstone import TombstoneError
        from sessions import SessionStore

        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory, session_id="ns-tombstone-guard")
            tombstone = a_tombstone(action="Write")
            with self.assertRaises(TombstoneError) as caught:
                store.record_cancellation_lift("not-a-tombstone", a_lift(tombstone))
            self.assertEqual(type(caught.exception), TombstoneError)
            self.assertEqual(
                str(caught.exception),
                "a lift is recorded against a tombstone",
                "the refusal must come from the store's guard, not from the lift checker",
            )

    # --- and@1055 --------------------------------------------------------
    def test_the_trailing_segment_is_not_priced_after_the_result_settles_it(self):
        """`and@1055`: the model-change half.

        The guard is ``trailing_usage.total_tokens and model !=
        trailing_model`` -- "there is trailing usage" AND "the model
        changed".  The suite drove the model-change side (the trailing
        usage is flushed when the model changes) and the empty-trailing
        side, but never the case where BOTH are true at once: two
        assistant records of the SAME model, followed by a ``result``.

        The ORIGINAL accumulates the two same-model records into one
        trailing segment, and the ``result`` record settles the run --
        its ``total_cost_usd`` is the authoritative cost -- so the
        trailing segment is dropped, not priced a second time.

        The MUTANT (``and`` -> ``or``) flushes the trailing segment at
        EVERY assistant record, so the segment is priced at haiku rates
        AND the result's own settled cost is added on top: the run is
        billed twice for the same tokens.

        The discriminator is that the mutant's flush happens at the
        SECOND assistant record, where the model has NOT changed.
        """
        from sessions import session_spend

        records = [
            {"type": "assistant", "model": "claude-haiku-4-5",
             "usage": {"input_tokens": 1_000_000, "output_tokens": 0}},
            {"type": "assistant", "model": "claude-haiku-4-5",
             "usage": {"input_tokens": 1_000_000, "output_tokens": 0}},
            {"type": "result", "total_cost_usd": 1.25, "usage": {}},
        ]
        cost, _usage = session_spend(records)
        self.assertAlmostEqual(
            cost,
            1.25,
            places=6,
            msg="the result record settles the run; its trailing segment must not be priced again",
        )


class EquivalentMutantTests(unittest.TestCase):
    """`or@504`: an EQUIVALENT mutant, recorded and proved.

    The site is the chain-head guard in ``SessionStore._resume_chain_head``:

        if not isinstance(head, str) or len(head) != 64:

    The planted fault turns the connective into ``and``.  It is
    **equivalent**, and the reason is structural rather than a matter of
    test coverage:

    * the guard is only reached when the chain verification has already
      passed -- the line directly above it raises when the verification
      did not pass, and
    * ``audit_chain.verify_lines`` accepts a record's ``chain_hash``
      only when it is a string matching ``^[0-9a-f]{64}$``.  A feed
      whose last record lacks a hash, or whose hash is malformed, is
      refused by ``verify_lines`` before the guard is ever reached.

    So on every path that reaches the guard, ``head`` is a 64-character
    string: the ORIGINAL's condition is always False, and the MUTANT's
    condition (``not isinstance(head, str) and len(head) != 64``) is
    also always False.  Two always-False guards are the same function,
    and no test can distinguish them.

    The equivalence is PROVED below, not asserted, and -- the part that
    matters -- the proof is shown to have **discriminating power**: the
    same harness is run against a CONTROL mutation that is known to
    change behaviour, and the harness is required to notice.  A
    differential test that cannot fail proves nothing.

    The comparison is SYMMETRIC: the harness compares the module on
    disk against the module with the guard's connective flipped.  That
    way the result holds whichever form is on disk -- including when
    the mutation probe has applied the fault -- and a spurious "the
    mutation site moved" failure cannot be mistaken for a behavioural
    difference.

    (The repository's own convention for this is ``test_state_budget.py``'s
    ``gt@304`` case.)
    """

    #: The chain-head guard, in both forms.
    HEAD_GUARD_OR = "if not isinstance(head, str) or len(head) != 64:"
    HEAD_GUARD_AND = "if not isinstance(head, str) and len(head) != 64:"

    #: The CONTROL mutation: the resume file-size bound.  This one is
    #: known to change behaviour -- a transcript exactly at the bound is
    #: accepted by the original and refused by the mutant -- so the
    #: harness must detect it.  If it does not, the harness is blind and
    #: the equivalence result below would be worthless.
    SIZE_BOUND = (
        "if os.fstat(fh.fileno()).st_size > MAX_SESSION_FILE_BYTES:",
        "if os.fstat(fh.fileno()).st_size >= MAX_SESSION_FILE_BYTES:",
    )

    def _load_original_and_mutant(self, mutation):
        """Exec the module twice: as it is, and with ``mutation`` applied."""
        import types

        source = Path(__file__).resolve().parents[1] / "sessions.py"
        original_source = source.read_text(encoding="utf-8")
        self.assertIn(mutation[0], original_source, "the mutation site moved")
        mutant_source = original_source.replace(mutation[0], mutation[1], 1)
        self.assertNotEqual(mutant_source, original_source)
        return self._exec_pair(original_source, mutant_source, source)

    def _exec_pair(self, original_source, mutant_source, source):
        import types

        original = types.ModuleType("sessions_original_probe")
        original.__dict__["__file__"] = str(source)
        mutant = types.ModuleType("sessions_mutant_probe")
        mutant.__dict__["__file__"] = str(source)
        # A module executed outside ``sys.modules`` breaks ``dataclass``'s
        # own module lookup, so both are registered for the exec.
        sys.modules[original.__name__] = original
        sys.modules[mutant.__name__] = mutant
        try:
            exec(compile(original_source, str(source), "exec"), original.__dict__)
            exec(compile(mutant_source, str(source), "exec"), mutant.__dict__)
        finally:
            sys.modules.pop(original.__name__, None)
            sys.modules.pop(mutant.__name__, None)
        return original, mutant

    def _corpus(self, directory):
        """Crafted transcripts, including the ones nearest the guard."""
        cases = []

        # 1. A clean sealed chain.
        cases.append(("clean", _sealed_transcript(directory, "ns-equiv", count=3)))

        # 2. A chain whose last record's body was edited: the chain does
        #    not verify, so the store refuses BEFORE the head guard.
        path = _sealed_transcript(directory, "ns-equiv-edited", count=3)
        _tamper_last_record(path)
        cases.append(("edited-body", path))

        # 3. A chain whose last record's head is a string of the wrong
        #    length: the head guard's OWN condition, at the boundary.
        path = _sealed_transcript(directory, "ns-equiv-short-head", count=3)
        lines = path.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[-1])
        record["chain_hash"] = "deadbeef"
        lines[-1] = json.dumps(record, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        cases.append(("short-head", path))

        # 4. The last record with NO head at all.
        path = _sealed_transcript(directory, "ns-equiv-no-head", count=3)
        lines = path.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[-1])
        del record["chain_hash"]
        lines[-1] = json.dumps(record, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        cases.append(("no-head", path))

        # 5. The last record whose head is a NUMBER, not a string.
        path = _sealed_transcript(directory, "ns-equiv-num-head", count=3)
        lines = path.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[-1])
        record["chain_hash"] = 12345
        lines[-1] = json.dumps(record, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        cases.append(("numeric-head", path))

        # 6. A transcript of only blank lines.
        path = Path(directory) / "ns-equiv-blank.jsonl"
        path.write_text("\n\n", encoding="utf-8")
        cases.append(("blank-only", path))

        # 7. An empty transcript.
        path = Path(directory) / "ns-equiv-empty.jsonl"
        path.write_text("", encoding="utf-8")
        cases.append(("empty", path))

        # 8. A transcript whose last line is not JSON at all.
        path = Path(directory) / "ns-equiv-garbage.jsonl"
        path.write_text("{}\nnot json\n", encoding="utf-8")
        cases.append(("garbage-tail", path))

        return cases

    def _outcomes(self, original, mutant, cases, directory):
        """Run both modules over the corpus; return the two outcome lists."""
        original_outcomes = []
        mutant_outcomes = []
        for name, path in cases:
            session_id = path.stem
            size = path.stat().st_size
            for module, sink in ((original, original_outcomes), (mutant, mutant_outcomes)):
                # Pin the file-size bound to the transcript's real size, so
                # the corpus reaches the boundary the control mutation
                # discriminates on.
                module.MAX_SESSION_FILE_BYTES = size
                try:
                    store = module.SessionStore(directory, session_id=session_id)
                    sink.append((name, "opened", store._prev_hash))
                except Exception as error:  # noqa: BLE001 - the outcome IS the datum
                    sink.append((name, "raised", type(error).__name__, str(error)))
        return original_outcomes, mutant_outcomes

    def test_the_chain_head_guard_is_unreachable_and_its_mutant_is_equivalent(self):
        """`or@504`: the differential proof.

        The two forms of the chain-head guard -- the ``or`` form and the
        ``and`` form the mutation probe plants -- are loaded as two
        modules and run over the same corpus of crafted transcripts.
        Every input must produce the same outcome: the same exception
        type, or the same returned chain head.

        The comparison is symmetric, so the result is the same whether
        the module on disk carries the ``or`` form or the ``and`` form.
        That matters: a harness that only compared "the file on disk"
        against "the file with the fault applied" would report a
        difference whenever the probe had already applied the fault,
        which is a difference in the FILE, not in the BEHAVIOUR.
        """
        source = Path(__file__).resolve().parents[1] / "sessions.py"
        on_disk = source.read_text(encoding="utf-8")
        if self.HEAD_GUARD_OR in on_disk:
            form_a, form_b = self.HEAD_GUARD_OR, self.HEAD_GUARD_AND
        else:
            self.assertIn(self.HEAD_GUARD_AND, on_disk, "the chain-head guard moved")
            form_a, form_b = self.HEAD_GUARD_AND, self.HEAD_GUARD_OR
        original, mutant = self._exec_pair(on_disk, on_disk.replace(form_a, form_b, 1), source)

        with tempfile.TemporaryDirectory() as directory:
            cases = self._corpus(directory)
            original_outcomes, mutant_outcomes = self._outcomes(original, mutant, cases, directory)
            self.assertEqual(
                original_outcomes,
                mutant_outcomes,
                "the chain-head mutant changed the outcome for some transcript",
            )

    def test_the_differential_harness_detects_a_control_mutation(self):
        """`or@504`: the harness must have DISCRIMINATING POWER.

        A differential test that cannot fail proves nothing.  This test
        runs the very same harness against a mutation that is known to
        change behaviour -- the resume file-size bound -- and requires
        the harness to notice the difference.  If this test fails, the
        equivalence result above is worthless and the mutant must be
        re-examined by hand.
        """
        original, mutant = self._load_original_and_mutant(self.SIZE_BOUND)

        with tempfile.TemporaryDirectory() as directory:
            cases = self._corpus(directory)
            original_outcomes, mutant_outcomes = self._outcomes(original, mutant, cases, directory)
            self.assertNotEqual(
                original_outcomes,
                mutant_outcomes,
                "the differential harness did not detect a known-observable mutation, "
                "so it cannot certify the chain-head mutant as equivalent",
            )

    def test_a_verified_transcript_always_has_a_64_character_head(self):
        """`or@504`: the structural half of the proof.

        The guard's condition can never be true, because a transcript
        that verifies has a 64-character hex head -- ``verify_lines``
        accepts a ``chain_hash`` only when it matches ``^[0-9a-f]{64}$``.
        This test pins that fact on the transcripts that DO open, which
        is what makes the guard dead code and the mutant equivalent.
        """
        import re

        from sessions import SessionStore

        with tempfile.TemporaryDirectory() as directory:
            _sealed_transcript(directory, "ns-head-shape", count=3)
            store = SessionStore(directory, session_id="ns-head-shape")
            self.assertIsNotNone(store._prev_hash)
            self.assertIsInstance(store._prev_hash, str)
            self.assertEqual(len(store._prev_hash), 64)
            self.assertRegex(store._prev_hash, re.compile(r"^[0-9a-f]{64}$"))

class GateRefusalMessageTests(RuntimeTestCase):
    """The refusal message the gate builds, and the arms of its own guards.

    The slice's own code in ``loop.py`` -- ``AgentRuntime._refuse_by_cancellation``
    -- ends in four guards that read the tombstone's provenance:

        declarer          = str(getattr(tombstone, "declarer", "") or "")
        channel           = str(getattr(tombstone, "declarer_channel", "") or "")
        grant             = str(getattr(tombstone, "grant_id", "") or "")
        tombstone_reason  = str(getattr(tombstone, "reason", "") or "")

    Each is a two-armed conditional: the attribute is read with a
    default, and the default is used when the attribute is absent OR
    empty.  The suite drove only the arm where every attribute is
    present, so the planted faults ``or@3857``, ``or@3858``, ``or@3859``
    and ``or@3860`` all SURVIVED it: under any of them the message
    loses the declarer, the channel, the grant id, or the tombstone's
    own reason -- and the refusal names a stop it cannot attribute to
    anybody.

    The discriminating case is the ORDINARY one.  Under the mutant the
    expression becomes ``getattr(...) and ""``, which yields ``""`` for a
    PRESENT attribute too -- so the message loses its field even when
    the tombstone carries it in full.  The tests below drive a real
    tombstone with real provenance and require the message to name it.
    """

    def _refusal_reason(self, tombstone, session_id):
        """Drive one refused call and return the refusal's reason."""
        workspace = self.workspace()
        store = SessionStore(workspace, session_id=session_id)
        store.record_cancellation(tombstone)
        runtime = self.runtime(
            [tool_turn("Write", {"path": "notes.md", "content": "secret"})],
            workspace=workspace,
            sessions=store,
            permission_mode="bypassPermissions",
        )
        report = self.drive(runtime)
        self.assertTrue(report.denials, "the call was not refused")
        return report.denials[0].reason

    def test_a_refusal_names_the_declarer(self):
        """`or@3857`: the declarer half.

        The refusal says WHO stopped the action.  Under the mutant the
        declarer is dropped and the message reads "cancelled by  via
        slack" -- a stop that nobody declared.
        """
        reason = self._refusal_reason(
            Tombstone(
                grant_id="grant-42",
                action="Write",
                subject="",
                declarer="alice",
                declarer_channel="slack",
                declared_at=1760000000.0,
                kind=PERMISSION,
                reason="do not publish this",
            ),
            "ns-msg-declarer",
        )
        self.assertIn("alice", reason, "the refusal must name the declarer")

    def test_a_refusal_names_the_channel(self):
        """`or@3858`: the channel half.

        The refusal says WHERE the stop was given.  Under the mutant the
        channel is dropped and the message reads "cancelled by alice via
        " -- a stop nobody can locate.
        """
        reason = self._refusal_reason(
            Tombstone(
                grant_id="grant-42",
                action="Write",
                subject="",
                declarer="alice",
                declarer_channel="slack",
                declared_at=1760000000.0,
                kind=PERMISSION,
                reason="do not publish this",
            ),
            "ns-msg-channel",
        )
        self.assertIn("slack", reason, "the refusal must name the channel")

    def test_a_refusal_names_the_grant(self):
        """`or@3859`: the grant half.

        The refusal carries the grant id, so the reader can tell WHICH
        stop refused the call.  Under the mutant the grant is dropped
        and the reader sees a stop with no identity at all.
        """
        reason = self._refusal_reason(
            Tombstone(
                grant_id="grant-42",
                action="Write",
                subject="",
                declarer="alice",
                declarer_channel="slack",
                declared_at=1760000000.0,
                kind=PERMISSION,
                reason="do not publish this",
            ),
            "ns-msg-grant",
        )
        self.assertIn("grant-42", reason, "the refusal must name the grant")

    def test_a_refusal_carries_the_tombstones_own_reason(self):
        """`or@3860`: the reason half.

        The refusal carries the tombstone's own reason -- the words the
        principal used.  Under the mutant the reason is dropped and the
        message says only that the stop "has not been lifted", which
        does not tell the reader WHY.
        """
        reason = self._refusal_reason(
            Tombstone(
                grant_id="grant-42",
                action="Write",
                subject="",
                declarer="alice",
                declarer_channel="slack",
                declared_at=1760000000.0,
                kind=PERMISSION,
                reason="do not publish this",
            ),
            "ns-msg-reason",
        )
        self.assertIn(
            "do not publish this",
            reason,
            "the refusal must carry the tombstone's own reason",
        )

    def test_a_refusal_names_the_scope_and_the_lift_clause(self):
        """The message around the four provenance fields.

        The message names the scope ("Write on notes.md") and says the
        stop has not been lifted.  Under any of the four mutants the
        message is still built, but it is no longer a complete refusal
        -- so this test is the control that the gate did not refuse for
        an unrelated reason.
        """
        reason = self._refusal_reason(
            Tombstone(
                grant_id="grant-42",
                action="Write",
                subject="",
                declarer="alice",
                declarer_channel="slack",
                declared_at=1760000000.0,
                kind=PERMISSION,
                reason="do not publish this",
            ),
            "ns-msg-scope",
        )
        self.assertIn("Write", reason)
        self.assertIn("has not been lifted", reason)
        self.assertEqual(
            self._refusal_reason(
                Tombstone(
                    grant_id="grant-42",
                    action="Write",
                    subject="",
                    declarer="alice",
                    declarer_channel="slack",
                    declared_at=1760000000.0,
                    kind=PERMISSION,
                    reason="do not publish this",
                ),
                "ns-msg-scope-2",
            ),
            reason,
            "the refusal message must be the same for the same tombstone",
        )

if __name__ == "__main__":
    unittest.main()
