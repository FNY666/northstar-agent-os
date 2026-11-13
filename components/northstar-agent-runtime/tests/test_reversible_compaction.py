"""Tests for reversible_compaction: a compaction that can be undone, or refused.

The suite is deliberately paranoid about the places where a reversibility
rule usually lies:

* the record must carry **both** hashes -- a record with a transcript hash
  but no prompt hash is not reversible, and minting one must be refused
  rather than quietly done,
* the record must **not** carry the transcript -- storing it would defeat
  the compaction it describes,
* revert must be **by hash**: an archived transcript that differs by one
  character is not the transcript, and "close enough" is not a criterion,
* a missing archive, a mismatched archive, and a record without hashes must
  all fail closed (``False`` / ``None``) -- never an exception, never an
  approximation,
* ``rederive()`` is a **hash-consistency** check, not a semantic
  re-derivation of the summary,
* **two compactions in a row** must be revertible one at a time: reverting
  the second must land on the transcript *after* the first compaction, not
  before both,
* the whole path must be driven **end to end** -- a chain that survives each
  part but not the whole is not reversible.
"""

from __future__ import annotations

import unittest

import reversible_compaction as rc


def _transcript() -> list:
    """A small pre-compaction transcript (three messages, one tool exchange)."""
    from providers.base import AssistantMessage, TextBlock, ToolUseBlock, UserMessage

    return [
        UserMessage.text_block("run the tests"),
        AssistantMessage(
            content=(
                TextBlock(text="running them"),
                ToolUseBlock(id="call-1", name="Bash", input={"command": "make test"}),
            ),
            model="test-model",
        ),
        UserMessage.text_block("the tests failed"),
    ]


def _summary() -> str:
    return "the agent ran the tests and they failed"


def _prompt() -> str:
    return "run the tests and tell me what broke"


def _record(transcript=None, summary=None, prompt_hash=None):
    transcript = _transcript() if transcript is None else transcript
    summary = _summary() if summary is None else summary
    prompt_hash = rc.prompt_hash_for(_prompt()) if prompt_hash is None else prompt_hash
    return rc.compact_reversible(transcript, summary, prompt_hash)


class CompactReversibleTests(unittest.TestCase):
    """The record that a reversible compaction mints."""

    def test_record_carries_transcript_hash_and_prompt_hash(self):
        transcript = _transcript()
        record = _record(transcript)
        self.assertEqual(record.transcript_hash, rc.transcript_hash(transcript))
        self.assertEqual(record.prompt_hash, rc.prompt_hash_for(_prompt()))
        self.assertTrue(record.is_reversible())

    def test_record_does_not_store_the_transcript(self):
        record = _record()
        blob = repr(record.as_dict())
        self.assertNotIn("run the tests", blob)
        self.assertNotIn("make test", blob)
        self.assertEqual(
            sorted(record.as_dict().keys()),
            ["prompt_hash", "revert_token", "schema", "summary", "transcript_hash"],
        )

    def test_missing_prompt_hash_is_refused(self):
        transcript = _transcript()
        for bad in ("", None, "not-a-hash", "sha256:xyz"):
            with self.assertRaises(rc.MissingHashError):
                rc.compact_reversible(transcript, _summary(), bad)

    def test_malformed_transcript_hash_is_refused_on_the_record(self):
        record = rc.CompactionRecord(
            summary=_summary(),
            transcript_hash="sha256:deadbeef",
            prompt_hash=rc.prompt_hash_for(_prompt()),
            revert_token="revert:abc",
        )
        self.assertFalse(record.is_reversible())
        self.assertFalse(rc.can_revert(record, {}))
        self.assertIsNone(rc.revert(record, {}))

    def test_record_without_hashes_fails_closed(self):
        record = rc.CompactionRecord(
            summary=_summary(),
            transcript_hash="",
            prompt_hash="",
            revert_token="revert:abc",
        )
        self.assertFalse(rc.can_revert(record, {rc.transcript_hash(_transcript()): _transcript()}))
        self.assertIsNone(rc.revert(record, {rc.transcript_hash(_transcript()): _transcript()}))
        self.assertFalse(rc.rederive(record, rc.prompt_hash_for(_prompt())))

    def test_record_round_trips_through_its_dict(self):
        record = _record()
        again = rc.CompactionRecord.from_dict(record.as_dict())
        self.assertEqual(again, record)
        self.assertIsNone(rc.CompactionRecord.from_dict({"summary": "x"}))


class CanRevertTests(unittest.TestCase):
    """Whether the archive holds what the record needs."""

    def test_can_revert_is_true_when_the_archive_holds_the_transcript(self):
        transcript = _transcript()
        record = _record(transcript)
        archive = {record.transcript_hash: transcript}
        self.assertTrue(rc.can_revert(record, archive))

    def test_can_revert_is_false_when_the_archive_is_empty(self):
        record = _record()
        self.assertFalse(rc.can_revert(record, {}))

    def test_can_revert_is_false_when_there_is_no_archive(self):
        record = _record()
        self.assertFalse(rc.can_revert(record, None))

    def test_can_revert_is_false_when_the_archived_copy_was_edited(self):
        transcript = _transcript()
        record = _record(transcript)
        edited = list(transcript)
        edited[0] = edited[0].__class__.text_block("run the test")
        archive = {record.transcript_hash: edited}
        self.assertFalse(rc.can_revert(record, archive))


class RevertTests(unittest.TestCase):
    """Getting back to before the compaction."""

    def test_revert_returns_the_verbatim_transcript(self):
        transcript = _transcript()
        record = _record(transcript)
        archive = {record.transcript_hash: transcript}
        restored = rc.revert(record, archive)
        self.assertIsNotNone(restored)
        self.assertEqual(list(restored), list(transcript))

    def test_revert_is_none_when_the_archive_is_empty(self):
        record = _record()
        self.assertIsNone(rc.revert(record, {}))

    def test_revert_is_none_when_the_archived_copy_differs_by_one_character(self):
        transcript = _transcript()
        record = _record(transcript)
        edited = list(transcript)
        edited[0] = edited[0].__class__.text_block("run the tests!")
        archive = {record.transcript_hash: edited}
        self.assertIsNone(rc.revert(record, archive))

    def test_revert_is_none_when_the_archive_holds_a_different_transcript(self):
        record = _record()
        other = _transcript()
        other[0] = other[0].__class__.text_block("something else entirely")
        archive = {record.transcript_hash: other}
        self.assertIsNone(rc.revert(record, archive))

    def test_revert_never_raises_on_a_broken_archive(self):
        class Broken:
            def get(self, key):
                raise RuntimeError("the archive is down")

        record = _record()
        self.assertIsNone(rc.revert(record, Broken()))
        self.assertFalse(rc.can_revert(record, Broken()))


class RederiveTests(unittest.TestCase):
    """Hash consistency between a record and the prompt the caller dispatched."""

    def test_rederive_is_true_when_the_prompt_hash_agrees(self):
        record = _record()
        self.assertTrue(rc.rederive(record, rc.prompt_hash_for(_prompt())))

    def test_rederive_is_false_when_the_prompt_hash_disagrees(self):
        record = _record()
        self.assertFalse(rc.rederive(record, rc.prompt_hash_for("a different prompt")))

    def test_rederive_is_false_for_a_malformed_prompt_hash(self):
        record = _record()
        for bad in ("", None, "sha256:nope", "not-a-hash"):
            self.assertFalse(rc.rederive(record, bad))

    def test_rederive_is_false_when_the_record_has_no_summary(self):
        record = rc.CompactionRecord(
            summary="",
            transcript_hash=rc.transcript_hash(_transcript()),
            prompt_hash=rc.prompt_hash_for(_prompt()),
            revert_token="revert:abc",
        )
        self.assertFalse(rc.rederive(record, rc.prompt_hash_for(_prompt())))


class ChainedCompactionTests(unittest.TestCase):
    """Two compactions in a row, reverted one at a time."""

    def test_reverting_the_second_lands_after_the_first_compaction(self):
        first = _transcript()
        first_record = _record(first)
        # After the first compaction the transcript is the summarised form.
        second = [rc.CompactionRecord(summary=first_record.summary,
                                     transcript_hash=first_record.transcript_hash,
                                     prompt_hash=first_record.prompt_hash,
                                     revert_token=first_record.revert_token)]
        second_transcript = list(second)
        second_record = rc.compact_reversible(
            second_transcript,
            "the second summary",
            rc.prompt_hash_for(_prompt()),
        )
        archive = {
            first_record.transcript_hash: first,
            second_record.transcript_hash: second_transcript,
        }
        self.assertTrue(rc.can_revert(second_record, archive))
        restored = rc.revert(second_record, archive)
        self.assertEqual(list(restored), second_transcript)
        # And the first compaction is still revertible underneath it.
        self.assertTrue(rc.can_revert(first_record, archive))
        self.assertEqual(list(rc.revert(first_record, archive)), list(first))

    def test_reverting_the_second_does_not_reach_before_the_first(self):
        first = _transcript()
        first_record = _record(first)
        second_transcript = [first_record]
        second_record = rc.compact_reversible(
            second_transcript,
            "the second summary",
            rc.prompt_hash_for(_prompt()),
        )
        archive = {second_record.transcript_hash: second_transcript}
        restored = rc.revert(second_record, archive)
        self.assertIsNotNone(restored)
        self.assertNotEqual(list(restored), list(first))


class EndToEndPathTests(unittest.TestCase):
    """The whole path, driven once, the way a host would drive it."""

    def test_a_compaction_can_be_undone_after_the_session_dies_on_the_seam(self):
        import compaction as compaction_mod

        transcript = _transcript()
        prompt_hash = rc.prompt_hash_for(_prompt())

        # 1. The host compacts the transcript for real.
        outcome = compaction_mod.compact(transcript, force=True, keep_messages=1)
        self.assertTrue(outcome.performed)

        # 2. It records the compaction reversibly, against the transcript as
        #    it was *before* the cut.
        record = rc.compact_reversible(transcript, outcome.summary, prompt_hash)
        self.assertTrue(record.is_reversible())
        self.assertEqual(record.transcript_hash, rc.transcript_hash(transcript))

        # 3. The archive holds the pre-compaction transcript.
        archive = {record.transcript_hash: transcript}
        self.assertTrue(rc.can_revert(record, archive))
        restored = rc.revert(record, archive)
        self.assertEqual(list(restored), list(transcript))

        # 4. The seam dies: the archive lost the transcript.
        self.assertFalse(rc.can_revert(record, {}))
        self.assertIsNone(rc.revert(record, {}))

        # 5. The seam dies and the archive kept a corrupted copy.
        corrupted = list(transcript)
        corrupted[-1] = corrupted[-1].__class__.text_block("the tests passed")
        self.assertFalse(rc.can_revert(record, {record.transcript_hash: corrupted}))
        self.assertIsNone(rc.revert(record, {record.transcript_hash: corrupted}))

        # 6. The prompt was fine: the record agrees with the dispatched prompt.
        self.assertTrue(rc.rederive(record, prompt_hash))


class TranscriptHashTests(unittest.TestCase):
    """The hash is canonical, so the same transcript always pins the same."""

    def test_hash_is_stable_across_calls(self):
        transcript = _transcript()
        self.assertEqual(rc.transcript_hash(transcript), rc.transcript_hash(list(transcript)))

    def test_hash_changes_when_a_message_changes(self):
        transcript = _transcript()
        before = rc.transcript_hash(transcript)
        edited = list(transcript)
        edited[0] = edited[0].__class__.text_block("run the linter")
        self.assertNotEqual(before, rc.transcript_hash(edited))

    def test_hash_of_an_empty_transcript_is_well_formed(self):
        digest = rc.transcript_hash([])
        self.assertTrue(digest.startswith("sha256:"))
        self.assertEqual(len(digest), len("sha256:") + 64)


class ArchiveShapeTests(unittest.TestCase):
    """The archive is a read port; the shapes of it are the caller's business."""

    def test_a_plain_dict_is_a_valid_archive(self):
        transcript = _transcript()
        record = _record(transcript)
        self.assertTrue(rc.can_revert(record, {record.transcript_hash: transcript}))

    def test_a_callable_archive_is_accepted(self):
        transcript = _transcript()
        record = _record(transcript)
        calls = []

        def archive(h):
            calls.append(h)
            return transcript if h == record.transcript_hash else None

        self.assertTrue(rc.can_revert(record, archive))
        self.assertEqual(calls, [record.transcript_hash])

    def test_an_archive_that_holds_nothing_else_is_not_a_match(self):
        record = _record()
        self.assertFalse(rc.can_revert(record, {"sha256:" + "0" * 64: _transcript()}))
        self.assertIsNone(rc.revert(record, {"sha256:" + "0" * 64: _transcript()}))


class NonRecordInputsTests(unittest.TestCase):
    """The functions refuse things that are not records, without raising."""

    def test_non_records_fail_closed(self):
        for junk in (None, "record", 42, {"summary": "x"}):
            self.assertFalse(rc.can_revert(junk, {}))
            self.assertIsNone(rc.revert(junk, {}))
            self.assertFalse(rc.rederive(junk, rc.prompt_hash_for(_prompt())))
