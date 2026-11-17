"""A cancellation must be legible wherever a transcript is read.

Commit ``695a25b7`` (B173 tombstone) added the ``cancellation`` record
type to the runtime's ``RECORD_TYPES``: a sticky revocation that says
"stop, do not publish", written as structure beside the conversation so
that a compaction cannot prune it.

The record is written correctly.  What was missing is every path that
READS a transcript:

  * ``audit_export.record_to_audit`` gave a cancellation
    ``level: "info"`` -- the same level as an ordinary assistant turn --
    so a revocation was indistinguishable from a routine line in the
    audit feed;
  * ``session_replay.build_replay`` had no case for it, so it fell
    through to the generic "note" branch and rendered as a 160-character
    prefix of the record's own JSON.  Because JSON sorts its keys
    alphabetically, that prefix was ``chain``, ``chain_hash``,
    ``digest``, ``genesis``, ``hlc`` -- so the label contained the
    action, the subject, the declarer and the reason **nowhere**;
  * ``session_view._record_text`` did the same thing.

Measured during this slice, on a real transcript written by the
runtime's own ``SessionStore.record_cancellation``:

    label contains 'publish'             -> False
    label contains 'the release'         -> False
    label contains 'user'                -> False
    label contains 'stop, do not publish'-> False
    label contains 'tombstone'           -> False

THE RULE THIS SLICE PINS:

> **A cancellation, on every path that reads a transcript, says what
> was revoked, on what, and who declared it -- never a wall of hashes.**
> **And it says whether the stop is still standing.**

> **A cancellation is `error` level in the audit feed**, because it is a
> withheld authorization, exactly as a denial is.

> **A lifted cancellation says it was lifted.**  A reader cannot
> otherwise tell a standing stop from a lifted one.

The tests here measure the READ paths against records the RUNTIME
wrote, not against hand-written samples: the shapes are what the
runtime actually writes, so a shape guess cannot make a guard pass
while proving nothing.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cancellation_tombstone import PERMISSION, Lift, Tombstone  # noqa: E402
from sessions import SessionStore  # noqa: E402


def a_tombstone(*, grant_id: str = "grant-1", action: str = "publish",
                subject: str = "the release", reason: str = "stop, do not publish") -> Tombstone:
    """A permission tombstone -- a stop that never expires."""
    return Tombstone(
        grant_id=grant_id,
        action=action,
        subject=subject,
        declarer="user",
        declarer_channel="chat",
        declared_at=1760000000.0,
        kind=PERMISSION,
        reason=reason,
    )


def a_lift(tombstone: Tombstone) -> Lift:
    """A named lift of ``tombstone`` -- the instruction that undoes it."""
    return Lift(
        declarer="user",
        declarer_channel="chat",
        grant_id=tombstone.grant_id,
        action=tombstone.action,
        subject=tombstone.subject,
        text="publish the release, the stop on it is lifted",
        lifted_at=1760000100.0,
    )


def written_records(store: SessionStore, session_id: str) -> list[dict]:
    """The transcript the runtime itself wrote."""
    records, _ = store.read(session_id)
    return records


class CancellationRecordTests(unittest.TestCase):
    """The runtime writes the records this slice reads."""

    def test_the_runtime_writes_a_cancellation_record_with_a_tombstone(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory=directory, session_id="cv-record")
            record = store.record_cancellation(a_tombstone())
            self.assertIsNotNone(record)
            self.assertEqual(record["type"], "cancellation")
            self.assertEqual(record["tombstone"]["action"], "publish")
            self.assertEqual(record["tombstone"]["subject"], "the release")
            self.assertEqual(record["tombstone"]["declarer"], "user")

    def test_a_lifted_cancellation_carries_its_lift(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory=directory, session_id="cv-lift")
            tombstone = a_tombstone()
            record = store.record_cancellation_lift(tombstone, a_lift(tombstone))
            self.assertIsNotNone(record)
            self.assertIn("lift", record)
            self.assertEqual(record["lift"]["declarer"], "user")


class AuditLevelTests(unittest.TestCase):
    """R1: a cancellation is `error` level in the audit feed.

    A revocation is a WITHHELD AUTHORIZATION -- the same category as a
    denial.  `info` says "this happened and it was routine".
    """

    def test_a_cancellation_is_error_level_in_the_audit_feed(self):
        from audit_export import record_to_audit

        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory=directory, session_id="cv-level")
            record = store.record_cancellation(a_tombstone())
            audit = record_to_audit(record)
            self.assertEqual(audit["event"], "cancellation")
            self.assertEqual(
                audit["level"], "error",
                "a revocation is a withheld authorization, not an informational line",
            )

    def test_a_lifted_cancellation_is_still_error_level(self):
        from audit_export import record_to_audit

        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory=directory, session_id="cv-level-lift")
            tombstone = a_tombstone()
            record = store.record_cancellation_lift(tombstone, a_lift(tombstone))
            audit = record_to_audit(record)
            self.assertEqual(
                audit["level"], "error",
                "a revocation that was lifted still happened, and it is still a revocation",
            )

    def test_the_ordinary_record_is_still_info_level(self):
        """The change must not turn every record into an error."""
        from audit_export import record_to_audit

        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory=directory, session_id="cv-level-info")
            store.append("assistant", {"agent": "main", "role": "assistant",
                                       "content": [{"type": "text", "text": "hi"}],
                                       "model": "m", "usage": {}, "stop_reason": "end_turn"})
            record = written_records(store, "cv-level-info")[0]
            self.assertEqual(record_to_audit(record)["level"], "info")


class ReplayFrameTests(unittest.TestCase):
    """R2-R4: the replay gives a cancellation its own frame, legibly."""

    def _replay(self, store: SessionStore, session_id: str):
        from session_replay import build_replay

        return build_replay(written_records(store, session_id), session_id=session_id)

    def test_a_cancellation_gets_its_own_frame_rather_than_a_note(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory=directory, session_id="cv-frame")
            store.record_cancellation(a_tombstone())
            replay = self._replay(store, "cv-frame")
            kinds = [frame.kind for frame in replay.frames]
            self.assertIn("cancellation", kinds)
            self.assertNotIn(
                "note", kinds,
                "a revocation is not an unknown note; it has its own kind",
            )

    def test_the_frame_label_says_what_was_revoked_and_by_whom(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory=directory, session_id="cv-label")
            store.record_cancellation(a_tombstone())
            replay = self._replay(store, "cv-label")
            frame = next(f for f in replay.frames if f.kind == "cancellation")
            self.assertIn("publish", frame.label)
            self.assertIn("the release", frame.label)
            self.assertIn("user", frame.label)
            self.assertNotIn(
                "chain_hash", frame.label,
                "the frame is about the revocation, not about the envelope's hashes",
            )

    def test_the_replay_counts_the_cancellation(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory=directory, session_id="cv-count")
            store.record_cancellation(a_tombstone())
            replay = self._replay(store, "cv-count")
            self.assertEqual(replay.counts["cancellations"], 1)
            self.assertIn("cancellation", replay.summary())

    def test_a_run_with_no_cancellation_counts_none(self):
        from session_replay import build_replay

        replay = build_replay(
            [{"index": 0, "ts": "2026-09-09T00:00:00.000Z", "session_id": "s",
              "type": "assistant", "agent": "main", "role": "assistant",
              "content": [{"type": "text", "text": "hi"}], "model": "m",
              "usage": {}, "stop_reason": "end_turn"}],
            session_id="s",
        )
        self.assertEqual(replay.counts["cancellations"], 0)

    def test_the_rendered_replay_shows_the_cancellation(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory=directory, session_id="cv-render")
            store.record_cancellation(a_tombstone())
            rendered = self._replay(store, "cv-render").render()
            self.assertIn("publish", rendered)
            self.assertIn("the release", rendered)


class SessionViewTests(unittest.TestCase):
    """R5: `sessions show` names the revocation."""

    def test_the_show_path_names_what_was_revoked(self):
        from session_view import _record_text

        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory=directory, session_id="cv-show")
            record = store.record_cancellation(a_tombstone())
            text = _record_text(record, "cancellation")
            self.assertIn("publish", text)
            self.assertIn("the release", text)
            self.assertIn("user", text)
            self.assertNotIn("chain_hash", text)


class StandingVersusLiftedTests(unittest.TestCase):
    """R6: a reader can tell a standing stop from a lifted one."""

    def _describe(self, record: dict) -> str:
        from cancellation_view import describe_cancellation

        return describe_cancellation(record)

    def test_a_standing_cancellation_says_it_is_standing(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory=directory, session_id="cv-standing")
            record = store.record_cancellation(a_tombstone())
            text = self._describe(record)
            self.assertIn("standing", text.lower())

    def test_a_lifted_cancellation_says_it_was_lifted(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory=directory, session_id="cv-lifted")
            tombstone = a_tombstone()
            record = store.record_cancellation_lift(tombstone, a_lift(tombstone))
            text = self._describe(record)
            self.assertIn("lifted", text.lower())

    def test_the_two_are_distinguishable(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory=directory, session_id="cv-distinguish")
            tombstone = a_tombstone()
            standing = self._describe(store.record_cancellation(tombstone))
            lifted = self._describe(store.record_cancellation_lift(tombstone, a_lift(tombstone)))
            self.assertNotEqual(standing, lifted)

    def test_the_reason_the_principal_gave_is_shown(self):
        """The reason is the principal's own words, and they are shown.

        This test exists because the mutation probe found the gap: the
        reason check could be flipped and no test noticed, because the
        description would then read "reason: (none given)" -- which is
        wrong, and which no assertion was watching.
        """
        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory=directory, session_id="cv-reason")
            record = store.record_cancellation(a_tombstone())
            text = self._describe(record)
            self.assertIn("stop, do not publish", text)
            self.assertNotIn("(none given)", text)

    def test_a_record_with_no_reason_says_so_rather_than_inventing_one(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SessionStore(directory=directory, session_id="cv-noreason")
            record = store.record_cancellation(a_tombstone(reason=""))
            text = self._describe(record)
            self.assertIn("(none given)", text)


class MalformedRecordTests(unittest.TestCase):
    """R7: the guard survives a record whose shape it did not expect."""

    def test_a_record_with_no_tombstone_still_reads(self):
        from cancellation_view import describe_cancellation

        text = describe_cancellation({"type": "cancellation", "index": 3})
        self.assertIsInstance(text, str)
        self.assertTrue(text.strip(), "an unreadable revocation must still say something")

    def test_a_record_with_a_malformed_tombstone_still_reads(self):
        from cancellation_view import describe_cancellation

        text = describe_cancellation(
            {"type": "cancellation", "tombstone": {"action": 17, "subject": None}}
        )
        self.assertIsInstance(text, str)
        self.assertIn("17", text)

    def test_an_empty_record_does_not_raise(self):
        from cancellation_view import describe_cancellation

        self.assertIsInstance(describe_cancellation({}), str)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
