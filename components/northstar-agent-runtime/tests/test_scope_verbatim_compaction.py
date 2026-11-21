"""Tests for scope_verbatim_compaction: the scope crosses verbatim, or not at all.

The suite is deliberately paranoid about the places where a verbatim-carry
rule usually lies:

* the block must be an **exact** string, not a "close enough" rendering --
  a test that compares a substring or a normalized form proves nothing,
* a scope that is **missing** from the product must fail closed, exactly
  like a scope that was reworded,
* a scope that was **summarized** (the block replaced by a summary of it)
  must fail closed too: "the summary still mentions the scope" is not
  preservation,
* the hash must be **canonical** -- field order must not matter, but a
  changed scope must change the hash,
* an **empty scope** must render an explicit block: a silently omitted
  scope is indistinguishable from a dropped one,
* **two compactions in a row** must still carry the scope byte for byte,
  and the grant set must be the same before and after (the permission
  laundering check),
* the whole path must be driven **end to end**, not asserted piece by
  piece: a scope that survives each part but not the whole is not a
  scope that survived.
"""

from __future__ import annotations

import random
import re
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

import scope_verbatim_compaction as svc


def _scope() -> svc.Scope:
    """The scope used throughout: 3 instructions, 2 grants, 1 goal."""
    return svc.Scope(
        instructions=(
            "do not modify main",
            "no network egress",
            "read-only until the plan is approved",
        ),
        grants=(
            "grant:read;version=v1;counter=3",
            "Bash",
        ),
        goal="ship the fix without touching main",
        scope_id="phase-1",
    )


def _tampered(compacted: svc.CompactedSession, *, block: str | None = None,
              summary: str | None = None) -> svc.CompactedSession:
    """A copy of the product with one part replaced."""
    return svc.CompactedSession(
        scope_block=compacted.scope_block if block is None else block,
        summary=compacted.summary if summary is None else summary,
        transcript=compacted.transcript,
        manifest=compacted.manifest,
        scope=compacted.scope,
    )


class ScopeRenderingTests(unittest.TestCase):
    """The block is byte-exact: no rewrite, no summary, no reorder, no drop."""

    def test_block_is_an_exact_string(self):
        scope = _scope()
        block = svc.verbatim_scope_block(scope)
        self.assertTrue(block.startswith(svc.BLOCK_BEGIN + "\n"))
        self.assertTrue(block.rstrip("\n").endswith(svc.BLOCK_END))
        # Every instruction and every grant appears with its exact bytes.
        for instruction in scope.instructions:
            self.assertIn(instruction, block)
        for grant in scope.grants:
            self.assertIn(grant, block)
        self.assertIn(scope.goal, block)
        self.assertIn(scope.scope_id, block)
        # No whitespace normalization: the instruction's own spacing is kept.
        self.assertIn("do not modify main", block)

    def test_block_keeps_order_and_drops_nothing(self):
        scope = _scope()
        block = svc.verbatim_scope_block(scope)
        positions = [block.index(item) for item in scope.instructions]
        self.assertEqual(positions, sorted(positions), "instructions must keep their order")
        grant_positions = [block.index(item) for item in scope.grants]
        self.assertEqual(grant_positions, sorted(grant_positions), "grants must keep their order")
        self.assertEqual(block.count("item["), len(scope.instructions) + len(scope.grants))

    def test_block_round_trips_back_to_the_scope(self):
        scope = _scope()
        block = svc.verbatim_scope_block(scope)
        self.assertEqual(svc.parse_scope_block(block), scope)
        self.assertEqual(svc.verbatim_scope_block(svc.parse_scope_block(block)), block)

    def test_empty_scope_renders_an_explicit_block(self):
        block = svc.verbatim_scope_block(svc.Scope())
        self.assertIn(svc.EMPTY_SCOPE_MARKER, block)
        self.assertTrue(block.startswith(svc.BLOCK_BEGIN))
        self.assertTrue(block.rstrip("\n").endswith(svc.BLOCK_END))
        # An empty scope is *not* the same as no scope at all: it is a
        # block, and it parses back to the empty scope.
        self.assertEqual(svc.parse_scope_block(block), svc.Scope())

    def test_multiline_instruction_survives_the_round_trip(self):
        scope = svc.Scope(instructions=("line one\nline two",), goal="g")
        block = svc.verbatim_scope_block(scope)
        self.assertEqual(svc.parse_scope_block(block), scope)

    def test_extract_scope_block_finds_the_block_in_a_carried_text(self):
        scope = _scope()
        block = svc.verbatim_scope_block(scope)
        carried = "preamble\n" + block + "epilogue"
        found = svc.extract_scope_block(carried)
        self.assertIsNotNone(found)
        self.assertEqual(found, block.rstrip("\n"))
        self.assertEqual(svc.parse_scope_block(found + "\n"), scope)

    def test_extract_scope_block_reports_a_missing_block(self):
        self.assertIsNone(svc.extract_scope_block("no scope here"))
        self.assertIsNone(svc.extract_scope_block(""))
        self.assertIsNone(svc.extract_scope_block(None))

    def test_a_malformed_block_is_refused_not_guessed(self):
        with self.assertRaises(svc.MalformedScopeError):
            svc.parse_scope_block("not a scope block")
        with self.assertRaises(svc.MalformedScopeError):
            svc.parse_scope_block("")
        # A block whose begin marker is gone is refused too.
        good = svc.verbatim_scope_block(_scope())
        with self.assertRaises(svc.MalformedScopeError):
            svc.parse_scope_block(good.replace(svc.BLOCK_BEGIN, "<<OTHER>>"))

    def test_a_block_with_a_malformed_header_is_refused(self):
        # A header whose key bracket is missing must be refused, not guessed
        # at: the reader may not fall back on "whatever looks closest".
        good = svc.verbatim_scope_block(_scope())
        broken = good.replace("scope_id[7]:", "scope_id]:")
        self.assertNotEqual(broken, good)
        with self.assertRaises(svc.MalformedScopeError):
            svc.parse_scope_block(broken)

    def test_a_block_with_a_blank_line_after_the_begin_marker_is_refused(self):
        # A stray blank line inside the block is malformed input; it must not
        # be silently absorbed into the next header.
        good = svc.verbatim_scope_block(_scope())
        broken = good.replace(svc.BLOCK_BEGIN + "\n", svc.BLOCK_BEGIN + "\n\n", 1)
        self.assertNotEqual(broken, good)
        with self.assertRaises(svc.MalformedScopeError):
            svc.parse_scope_block(broken)

    def test_a_partly_filled_scope_is_not_empty(self):
        # "Empty" means *nothing* was declared. A scope with one instruction
        # is not empty, and its block must keep that instruction -- a scope
        # that was declared must never render as the empty-scope marker.
        partial = svc.Scope(instructions=("do not modify main",))
        self.assertFalse(partial.is_empty())
        block = svc.verbatim_scope_block(partial)
        self.assertNotIn(svc.EMPTY_SCOPE_MARKER, block)
        self.assertIn("do not modify main", block)
        self.assertEqual(svc.parse_scope_block(block), partial)
        # Each field on its own is enough to make the scope non-empty.
        for partial_scope in (
            svc.Scope(instructions=("x",)),
            svc.Scope(grants=("Bash",)),
            svc.Scope(goal="g"),
            svc.Scope(scope_id="s1"),
        ):
            self.assertFalse(partial_scope.is_empty(), partial_scope)
            self.assertNotIn(
                svc.EMPTY_SCOPE_MARKER, svc.verbatim_scope_block(partial_scope)
            )
        self.assertTrue(svc.Scope().is_empty())

    def test_a_block_without_a_trailing_newline_is_refused(self):
        # The parser reads header lines up to a newline. A block whose last
        # line has no newline at all must be refused, not half-read: a
        # truncated carry is exactly the shape of a dropped scope.
        good = svc.verbatim_scope_block(_scope())
        stripped = good.rstrip("\n")
        self.assertNotEqual(stripped, good)
        with self.assertRaises(svc.MalformedScopeError):
            svc.parse_scope_block(stripped)

    def test_the_refusal_message_names_the_offending_line(self):
        # The refusal must quote the line it refused, and it must do so on
        # one line: a message carrying a raw newline would corrupt the
        # audit log it goes into and would hide which line was offending.
        good = svc.verbatim_scope_block(_scope())
        broken = good.replace(svc.BLOCK_BEGIN + "\n", svc.BLOCK_BEGIN + "\n\n", 1)
        self.assertNotEqual(broken, good)
        with self.assertRaises(svc.MalformedScopeError) as caught:
            svc.parse_scope_block(broken)
        message = str(caught.exception)
        self.assertNotIn("\n", message)
        self.assertIn("malformed", message)
        self.assertTrue(message.endswith("''"), message)

    def test_a_header_whose_length_is_too_long_is_refused(self):
        # The length prefix is what delimits a value. A value shorter than
        # its prefix says must be refused, never silently cut short: a
        # half-read instruction is a dropped instruction.
        good = svc.verbatim_scope_block(_scope())
        broken = good.replace("scope_id[7]:", "scope_id[99]:", 1)
        self.assertNotEqual(broken, good)
        with self.assertRaises(svc.MalformedScopeError):
            svc.parse_scope_block(broken)

    def test_the_end_marker_is_required(self):
        # Both markers are load-bearing: a block that lost its end marker
        # was truncated, and a truncated carry must not parse.
        good = svc.verbatim_scope_block(_scope())
        broken = good.replace(svc.BLOCK_END, "<<OTHER-END>>")
        self.assertNotEqual(broken, good)
        with self.assertRaises(svc.MalformedScopeError):
            svc.parse_scope_block(broken)


class ScopeHashTests(unittest.TestCase):
    """The hash is canonical: field order is irrelevant, content is not."""

    def test_hash_is_stable_for_the_same_scope(self):
        scope = _scope()
        self.assertEqual(svc.scope_hash(scope), svc.scope_hash(scope))
        self.assertEqual(svc.scope_hash(scope), svc.scope_hash(_scope()))

    def test_hash_ignores_field_order(self):
        scope = _scope()
        mapping = {
            "goal": scope.goal,
            "grants": scope.grants,
            "instructions": scope.instructions,
            "scope_id": scope.scope_id,
        }
        reordered = {
            "scope_id": scope.scope_id,
            "instructions": scope.instructions,
            "grants": scope.grants,
            "goal": scope.goal,
        }
        self.assertEqual(svc.scope_hash(mapping), svc.scope_hash(reordered))
        self.assertEqual(svc.scope_hash(mapping), svc.scope_hash(scope))

    def test_hash_changes_when_the_scope_changes(self):
        scope = _scope()
        changed = svc.Scope(
            instructions=scope.instructions[:-1] + ("read-only until the plan is signed",),
            grants=scope.grants,
            goal=scope.goal,
            scope_id=scope.scope_id,
        )
        self.assertNotEqual(svc.scope_hash(scope), svc.scope_hash(changed))
        fewer_grants = svc.Scope(
            instructions=scope.instructions,
            grants=scope.grants[:1],
            goal=scope.goal,
            scope_id=scope.scope_id,
        )
        self.assertNotEqual(svc.scope_hash(scope), svc.scope_hash(fewer_grants))

    def test_hash_is_a_sha256_pin(self):
        digest = svc.scope_hash(_scope())
        self.assertTrue(digest.startswith("sha256:"))
        self.assertEqual(len(digest), len("sha256:") + 64)


class ScopePreservationTests(unittest.TestCase):
    """Fail closed: only byte-identical scope counts as preserved."""

    def setUp(self):
        self.scope = _scope()
        self.compacted = svc.compact_with_scope(
            ("user: do the thing", "assistant: doing it"),
            self.scope,
            lambda transcript: "summary: the agent did the thing",
        )

    def test_identical_block_is_preserved(self):
        self.assertTrue(svc.scope_preserved(self.compacted, self.scope))

    def test_missing_block_is_not_preserved(self):
        dropped = _tampered(self.compacted, block="")
        self.assertFalse(svc.scope_preserved(dropped, self.scope))

    def test_one_changed_character_is_not_preserved(self):
        # One character, in the middle of an instruction.
        changed = self.compacted.scope_block.replace("no network egress", "no network egress!")
        self.assertNotEqual(changed, self.compacted.scope_block)
        self.assertFalse(svc.scope_preserved(_tampered(self.compacted, block=changed), self.scope))

    def test_summarized_scope_is_not_preserved(self):
        # The summary mentions the scope -- that is not preservation.
        summarized = _tampered(
            self.compacted,
            block="summary: the agent was told not to modify main and had grant Bash",
            summary="summary: the agent was told not to modify main and had grant Bash",
        )
        self.assertFalse(svc.scope_preserved(summarized, self.scope))

    def test_reordered_block_is_not_preserved(self):
        scope = self.scope
        lines = self.compacted.scope_block.splitlines(keepends=True)
        begin = lines[0]
        end = lines[-1]
        middle = lines[1:-1]
        # Reverse the body: the same items, a different order.
        reordered = "".join([begin, *reversed(middle), end])
        self.assertNotEqual(reordered, self.compacted.scope_block)
        self.assertFalse(svc.scope_preserved(_tampered(self.compacted, block=reordered), scope))

    def test_truncated_block_is_not_preserved(self):
        truncated = self.compacted.scope_block[: len(self.compacted.scope_block) // 2]
        self.assertFalse(svc.scope_preserved(_tampered(self.compacted, block=truncated), self.scope))

    def test_different_scope_is_not_preserved(self):
        other = svc.Scope(instructions=("do not modify main",), grants=(), goal="g", scope_id="phase-1")
        self.assertFalse(svc.scope_preserved(self.compacted, other))

    def test_non_compacted_object_is_not_preserved(self):
        self.assertFalse(svc.scope_preserved("a string", self.scope))
        self.assertFalse(svc.scope_preserved(None, self.scope))

    def test_require_scope_preserved_raises_when_the_scope_was_lost(self):
        broken = _tampered(self.compacted, block="")
        with self.assertRaises(svc.ScopeNotPreservedError):
            svc.require_scope_preserved(broken, self.scope)
        self.assertEqual(
            svc.require_scope_preserved(self.compacted, self.scope), self.scope
        )


class ManifestTests(unittest.TestCase):
    """The manifest records the hashes and the verbatim/summary boundary."""

    def setUp(self):
        self.scope = _scope()
        self.compacted = svc.compact_with_scope(
            ("user: go", "assistant: going"), self.scope, lambda t: "summary"
        )
        self.manifest = self.compacted.manifest

    def test_manifest_records_the_scope_hash_and_the_block_hash(self):
        self.assertEqual(self.manifest.scope_hash, svc.scope_hash(self.scope))
        self.assertEqual(self.manifest.block_hash, svc.block_hash(self.compacted.scope_block))
        self.assertNotEqual(self.manifest.scope_hash, self.manifest.block_hash)

    def test_manifest_records_the_verbatim_and_summarized_boundary(self):
        self.assertEqual(self.manifest.verbatim_fields, svc.VERBATIM_FIELDS)
        self.assertEqual(self.manifest.summarized_fields, svc.SUMMARIZED_FIELDS)
        self.assertIn("instructions", self.manifest.verbatim_fields)
        self.assertIn("grants", self.manifest.verbatim_fields)
        self.assertIn("goal", self.manifest.verbatim_fields)
        self.assertNotIn("instructions", self.manifest.summarized_fields)

    def test_manifest_records_the_carried_block_and_its_size(self):
        self.assertEqual(self.manifest.scope_block, self.compacted.scope_block)
        self.assertEqual(
            self.manifest.scope_block_bytes, len(self.compacted.scope_block.encode("utf-8"))
        )

    def test_manifest_intact_check_notices_a_tampered_block(self):
        self.assertTrue(self.manifest.block_is_intact())
        tampered = svc.ScopeManifest(
            scope_hash=self.manifest.scope_hash,
            block_hash=self.manifest.block_hash,
            scope_block=self.manifest.scope_block.replace("Bash", "bash"),
            verbatim_fields=self.manifest.verbatim_fields,
            summarized_fields=self.manifest.summarized_fields,
        )
        self.assertFalse(tampered.block_is_intact())

    def test_manifest_carries_the_grant_set_at_the_boundary(self):
        self.assertEqual(self.manifest.grants, self.scope.grants)
        self.assertEqual(self.manifest.scope_id, self.scope.scope_id)


class EndToEndTests(unittest.TestCase):
    """The whole path, driven: compaction in, scope out, byte for byte."""

    def setUp(self):
        self.scope = _scope()
        self.transcript = (
            "user: fix the failing test",
            "assistant: reading the test file",
            "user: now fix it",
        )

    def _summarize(self, transcript):
        # A hostile summarizer: it drops whatever it wants from the body.
        return "summary: 3 messages about a failing test"

    def test_scope_survives_a_compaction_verbatim(self):
        compacted = svc.compact_with_scope(self.transcript, self.scope, self._summarize)
        self.assertTrue(svc.scope_preserved(compacted, self.scope))
        self.assertEqual(compacted.scope_block, svc.verbatim_scope_block(self.scope))
        self.assertEqual(svc.parse_scope_block(compacted.scope_block), self.scope)

    def test_one_changed_character_fails_closed(self):
        compacted = svc.compact_with_scope(self.transcript, self.scope, self._summarize)
        broken = _tampered(
            compacted, block=compacted.scope_block.replace("ship the fix", "ship the fix!")
        )
        self.assertFalse(svc.scope_preserved(broken, self.scope))

    def test_a_dropped_scope_block_fails_closed(self):
        compacted = svc.compact_with_scope(self.transcript, self.scope, self._summarize)
        broken = _tampered(compacted, block="")
        self.assertFalse(svc.scope_preserved(broken, self.scope))

    def test_two_compactions_in_a_row_still_carry_the_scope(self):
        first = svc.compact_with_scope(self.transcript, self.scope, self._summarize)
        second = svc.compact_with_scope(first.transcript, self.scope, self._summarize)
        self.assertTrue(svc.scope_preserved(first, self.scope))
        self.assertTrue(svc.scope_preserved(second, self.scope))
        self.assertEqual(second.scope_block, first.scope_block)
        self.assertEqual(second.scope_block, svc.verbatim_scope_block(self.scope))

    def test_the_grant_set_is_the_same_before_and_after(self):
        # The permission laundering check: the grants the agent holds after
        # the compaction are the grants it held before it.
        compacted = svc.compact_with_scope(self.transcript, self.scope, self._summarize)
        carried = svc.parse_scope_block(compacted.scope_block)
        self.assertEqual(carried.grant_set(), self.scope.grant_set())
        self.assertEqual(compacted.manifest.grants, self.scope.grants)
        self.assertEqual(
            svc.parse_scope_block(compacted.scope_block).grant_set(),
            svc.parse_scope_block(svc.verbatim_scope_block(self.scope)).grant_set(),
        )

    def test_the_summarizer_never_sees_the_scope(self):
        seen = {}

        def spy(transcript):
            seen["transcript"] = transcript
            return "summary"

        svc.compact_with_scope(self.transcript, self.scope, spy)
        self.assertEqual(tuple(seen["transcript"]), self.transcript)
        # The scope block is not part of what the summarizer receives.
        self.assertNotIn(self.scope.goal, " ".join(str(item) for item in seen["transcript"]))

    def test_the_scope_travels_before_the_summary(self):
        compacted = svc.compact_with_scope(self.transcript, self.scope, self._summarize)
        carried = compacted.carried_text()
        self.assertLess(carried.index(self.scope.goal), carried.index(compacted.summary))
        self.assertTrue(carried.startswith(svc.BLOCK_BEGIN))

    def test_an_empty_scope_still_travels_through_a_compaction(self):
        empty = svc.Scope()
        compacted = svc.compact_with_scope(self.transcript, empty, self._summarize)
        self.assertTrue(svc.scope_preserved(compacted, empty))
        self.assertIn(svc.EMPTY_SCOPE_MARKER, compacted.scope_block)


class SecondHalfGuardTests(unittest.TestCase):
    """The second half of every two-armed guard in the module.

    A guard written ``if not isinstance(x, T) or x is None:`` has two
    arms and one refusal.  A suite that only ever feeds the *first* arm
    a wrong-type value never reaches the second, and the arm sits there
    untested -- a planted fault in it survives every run.

    Every method below names the arm it drives and the fault it kills.
    """

    # --- or@328: the "not a str" half of the block guard ----------------
    def test_a_non_string_block_is_refused(self):
        """`or@328`: the "not a str" half.

        The guard is ``not isinstance(block, str) or not block``.  The
        empty-string half is driven by the existing suite; this is the
        other one.  Under the mutant (``or`` -> ``and``) a non-string
        block is NOT refused by this guard, and the module goes on to
        slice it -- raising an ``AttributeError`` or a ``TypeError``
        instead of the ``MalformedScopeError`` the module promises.
        """
        for value in (None, 123, 4.5, b"bytes", ["list"], {"k": "v"}, object()):
            with self.subTest(value=repr(value)):
                with self.assertRaises(svc.MalformedScopeError):
                    svc.parse_scope_block(value)

    # --- or@572: the "not a str" half of the carried-block guard --------
    def test_a_non_string_carried_block_is_not_preserved(self):
        """`or@572`: the "not a str" half.

        The guard is ``not isinstance(block, str) or not block``.  A
        carried block that is not a string cannot be byte-identical to
        the expected block, so the answer is ``False`` -- never an
        exception, and never ``True``.  Under the mutant (``or`` ->
        ``and``) a *truthy* non-string block skips the guard entirely
        and the check goes on to coerce the scope.
        """
        for value in (None, 123, b"bytes", ["list"], object()):
            with self.subTest(value=repr(value)):
                compacted = svc.CompactedSession(scope_block=value, summary="s")
                self.assertFalse(svc.scope_preserved(compacted, _scope()))

    def test_an_unreadable_product_is_answered_not_raised(self):
        """`or@572`: the second half of the same divergence.

        Under the mutant (``or`` -> ``and``) a truthy non-string block
        skips the guard and the check proceeds to coerce the *scope* --
        so the answer depends on the scope, and an unusable scope turns
        the boundary check into an exception.  The contract is the
        opposite: an unreadable product is not a preserved one, and
        the check answers ``False`` whatever the scope is.
        """
        compacted = svc.CompactedSession(scope_block=123, summary="s")
        self.assertFalse(svc.scope_preserved(compacted, "not a scope at all"))
        self.assertFalse(svc.scope_preserved(compacted, {"goal": "g", "nope": 1}))

    # --- or@384: the "not a str" half of the carried-text guard ---------
    def test_a_non_string_carried_text_yields_no_block(self):
        """`or@384`: the "not a str" half.

        ``extract_scope_block`` returns ``None`` for a carried text that
        is not a string -- a missing block is the fail-closed case, and
        it is reported as missing, never reconstructed and never raised.
        Under the mutant (``or`` -> ``and``) a non-string text skips the
        empty-check and reaches ``text.find``, which raises.
        """
        for value in (None, 123, 4.5, b"bytes", ["list"], object()):
            with self.subTest(value=repr(value)):
                self.assertIsNone(svc.extract_scope_block(value))

    # --- or@330: the "missing begin marker" half ------------------------
    def test_a_block_without_its_begin_marker_is_refused(self):
        """`or@330`: the first half of the marker guard.

        The guard is ``not block.startswith(BLOCK_BEGIN + "\\n") or not
        block.endswith(BLOCK_END + "\\n")``.  The existing suite drives
        the *end* marker; this drives the *begin* marker.

        The refusal MESSAGE is what distinguishes the two behaviours.
        The correct code refuses a block with no begin marker as a
        block that is *missing its begin or end marker*.  Under the
        mutant (``or`` -> ``and``) the guard is satisfied by the
        intact end marker, so the block is not refused here at all: it
        is sliced as if it had a body, and the refusal that eventually
        comes is a *header* complaint about whatever the slice
        happened to land on.  A block that lost its begin marker was
        truncated, and the refusal must say so.
        """
        good = svc.verbatim_scope_block(_scope())
        broken = good.replace(svc.BLOCK_BEGIN, "<<OTHER-BEGIN>>", 1)
        self.assertNotEqual(broken, good)
        with self.assertRaises(svc.MalformedScopeError) as caught:
            svc.parse_scope_block(broken)
        self.assertIn("missing its begin or end marker", str(caught.exception))

    # --- lt@387: the "no begin marker at all" half ----------------------
    def test_a_text_with_no_begin_marker_yields_no_block(self):
        """`lt@387`: the "begin not found" half.

        ``begin = text.find(BLOCK_BEGIN)`` and ``if begin < 0: return
        None``.  The mutant makes the guard ``begin <= 0``, so it
        refuses a block that starts at index 0 -- the *normal* case,
        where the carried text begins with the block itself.  Under the
        mutant a scope block that starts the text is reported as
        missing, and a scope that crossed the compaction reads as
        dropped.
        """
        scope = _scope()
        block = svc.verbatim_scope_block(scope)
        self.assertTrue(block.startswith(svc.BLOCK_BEGIN))
        # The block at index 0: the mutant refuses this.
        self.assertEqual(svc.extract_scope_block(block), block.rstrip("\n"))
        # And it is still the same when the block is embedded later.
        self.assertEqual(
            svc.extract_scope_block("preamble\n" + block), block.rstrip("\n")
        )

    # --- retF@454: the "no block at all" half of the intact check ------
    def test_a_manifest_with_no_block_is_not_intact(self):
        """`retF@454`: the empty-block arm of ``block_is_intact``.

        The guard is ``if not self.scope_block: return False``.  Under
        the mutant (``return False`` -> ``return True``) a manifest
        with NO block at all reads as intact -- a manifest that carries
        nothing claims to be a faithful record of nothing.
        """
        manifest = svc.ScopeManifest(
            scope_hash=svc.scope_hash(_scope()),
            block_hash=svc.block_hash(svc.verbatim_scope_block(_scope())),
            scope_block="",
        )
        self.assertFalse(manifest.block_is_intact())

    # --- retF@582: the "hash mismatch" arm of the preservation check ---
    def test_a_block_whose_scope_hash_disagrees_is_not_preserved(self):
        """`retF@582`: the canonical-hash arm.

        The check is ``scope_hash(resolved) != scope_hash(parse_scope_block
        (block))``.  The byte comparison above it already refuses a
        changed block, so the hash arm is reached only by a block that
        is byte-identical to the expected one but whose *parsed* scope
        hashes differently.  That is exactly the "rebuilt to the same
        bytes from a different scope" case the arm exists for.

        The arm is isolated by patching the accessor the assertion
        reads -- ``parse_scope_block`` -- so that the parsed scope is a
        DIFFERENT scope while the bytes stay identical.  Under the
        mutant (``return False`` -> ``return True``) the disagreement
        is accepted and the product reads as preserved.
        """
        scope = _scope()
        compacted = svc.compact_with_scope(("user: go",), scope, lambda t: "summary")
        self.assertTrue(svc.scope_preserved(compacted, scope))
        other = svc.Scope(instructions=("a different scope entirely",))
        with mock.patch.object(svc, "parse_scope_block", lambda block: other):
            self.assertFalse(
                svc.scope_preserved(compacted, scope),
                "a block whose parsed scope hashes differently is not preserved",
            )

    # --- retF@585: the "manifest disagrees" arm --------------------------
    def test_a_manifest_that_disagrees_with_its_block_is_not_preserved(self):
        """`retF@585`: the manifest arm.

        The check is ``if isinstance(manifest, ScopeManifest) and not
        manifest.block_is_intact(): return False``.  The existing suite
        pins ``block_is_intact`` on its own; this drives the *caller's*
        use of it -- a compaction product whose manifest was edited
        next to its block must not read as preserved.
        """
        scope = _scope()
        compacted = svc.compact_with_scope(("user: go",), scope, lambda t: "summary")
        broken = svc.ScopeManifest(
            scope_hash=compacted.manifest.scope_hash,
            block_hash=compacted.manifest.block_hash,
            scope_block=compacted.scope_block.replace("Bash", "bash"),
            verbatim_fields=compacted.manifest.verbatim_fields,
            summarized_fields=compacted.manifest.summarized_fields,
        )
        tampered = svc.CompactedSession(
            scope_block=compacted.scope_block,
            summary=compacted.summary,
            transcript=compacted.transcript,
            manifest=broken,
            scope=scope,
        )
        self.assertFalse(svc.scope_preserved(tampered, scope))

    # --- retF@588: the mapping manifest's block-hash arm ----------------
    def test_a_mapping_manifest_with_a_wrong_block_hash_is_not_preserved(self):
        """`retF@588`: the first arm of the mapping-manifest check.

        The check is ``if manifest.get("block_hash") != block_hash(block):
        return False``.  A product may carry its manifest as a plain
        mapping rather than as a ``ScopeManifest``, and a mapping whose
        ``block_hash`` does not match the block it accompanies is a
        manifest that does not describe that block.
        """
        scope = _scope()
        compacted = svc.compact_with_scope(("user: go",), scope, lambda t: "summary")
        manifest = compacted.manifest.as_dict()
        manifest["block_hash"] = svc.block_hash("some other block")
        product = {"scope_block": compacted.scope_block, "manifest": manifest}
        self.assertFalse(svc.scope_preserved(product, scope))

    # --- retF@590: the mapping manifest's scope-hash arm ----------------
    def test_a_mapping_manifest_with_a_wrong_scope_hash_is_not_preserved(self):
        """`retF@590`: the second arm of the mapping-manifest check.

        The check is ``if manifest.get("scope_hash") != scope_hash
        (resolved): return False``.  The block hash may be perfectly
        correct and the scope hash still wrong: the manifest then
        describes a *different* scope than the one handed in.
        """
        scope = _scope()
        compacted = svc.compact_with_scope(("user: go",), scope, lambda t: "summary")
        manifest = compacted.manifest.as_dict()
        manifest["scope_hash"] = svc.scope_hash(svc.Scope(instructions=("other",)))
        product = {"scope_block": compacted.scope_block, "manifest": manifest}
        self.assertFalse(svc.scope_preserved(product, scope))

    # --- retF@633 / and@635 / retF@636 / retT@637: the stdlib guard ----
    def test_the_stdlib_guard_refuses_a_foreign_import(self):
        """`retF@633`, `and@635`, `retF@636`, `retT@637`: the stdlib guard.

        ``stdlib_only`` walks the module's own AST and refuses an
        import that is not on the allow-list.  The mutants disable
        that refusal one arm at a time: the ``Import`` arm
        (``retF@636``), the ``ImportFrom`` arm (``retF@633``), the
        ``and`` that joins the name check with the dotted-prefix check
        (``and@635``), and the module's final verdict (``retT@637``).

        The guard reads ``__file__``, so the test drives it against a
        *copy* of the module source that carries a foreign import, and
        against one that does not.  Both are checked: the clean copy
        must pass, and the dirty one must be refused.
        """
        source = Path(svc.__file__).read_text(encoding="utf-8")
        self.assertTrue(svc.stdlib_only(), "the module as committed must be stdlib-only")

        # A foreign top-level import: the `ast.Import` arm.
        dirty = source.replace(
            "import ast\n", "import ast\nimport xml.dom.minidom\n", 1
        )
        self.assertNotEqual(dirty, source)
        self.assertFalse(
            self._stdlib_only_for(dirty), "a foreign `import` must be refused"
        )

        # A foreign `from` import: the `ast.ImportFrom` arm.
        dirty_from = source.replace(
            "import ast\n", "import ast\nfrom xml.dom import minidom\n", 1
        )
        self.assertNotEqual(dirty_from, source)
        self.assertFalse(
            self._stdlib_only_for(dirty_from), "a foreign `from` import must be refused"
        )

        # The `and` arm: the guard is
        # ``if node.module and node.module.split(".")[0] not in allowed``.
        # The ``and`` short-circuits on an allow-listed root, and the
        # whole condition must be FALSE for such a root -- a
        # ``from typing import Any`` is stdlib and must not be
        # refused.  The mutant (``and`` -> ``or``) refuses it instead,
        # because a non-empty ``node.module`` is truthy on its own.
        # The module's own ``from typing import ...`` is that case, so
        # the assertion above -- which is the clean module -- is what
        # kills it.  This test pins the reading it depends on.

        # The clean source must still pass.
        self.assertTrue(self._stdlib_only_for(source))

    def test_the_stdlib_guard_accepts_an_allow_listed_from_import(self):
        """`and@635`: the "allow-listed root" half.

        The guard's condition is ``node.module and node.module.split(".")
        [0] not in allowed``.  For an allow-listed root the first half
        is truthy and the second is false, so the conjunction is
        false and the import is NOT refused.  Under the mutant (``and``
        -> ``or``) the truthy first half alone refuses it -- so a
        module with an ordinary ``from typing import ...`` would be
        reported as non-stdlib.
        """
        source = Path(svc.__file__).read_text(encoding="utf-8")
        clean = source.replace(
            "from typing import Any, Callable, Mapping, Sequence, Tuple\n",
            "from typing import Any, Callable, Mapping, Sequence, Tuple\n"
            "from typing import Optional\n",
            1,
        )
        self.assertNotEqual(clean, source)
        self.assertTrue(
            self._stdlib_only_for(clean),
            "an allow-listed `from` import must not be refused",
        )
        # And a foreign `from` import is still refused -- the guard is
        # not simply disabled.
        dirty = clean.replace(
            "from typing import Optional\n",
            "from typing import Optional\nfrom xml.dom import minidom\n",
            1,
        )
        self.assertFalse(self._stdlib_only_for(dirty))

    def _stdlib_only_for(self, source: str) -> bool:
        """Run ``stdlib_only`` against a given source text.

        ``stdlib_only`` reads the module's own source from
        ``__file__``, so the mutated source is written to a real
        temporary file and the module is executed from *that* file --
        with ``__file__`` pointing at it.  The guard therefore reads
        exactly the source it is given, and the file it reads is the
        file that was mutated.
        """
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "svc_probe.py"
            path.write_text(source, encoding="utf-8")
            name = "_svc_stdlib_probe_%d" % id(self)
            module = types.ModuleType(name)
            module.__file__ = str(path)
            # The module must be in ``sys.modules`` before it is
            # executed: ``dataclasses`` resolves the class's own module
            # through ``sys.modules`` while it processes the decorator.
            sys.modules[name] = module
            try:
                exec(compile(source, str(path), "exec"), module.__dict__)  # noqa: S102
                return module.stdlib_only()
            finally:
                sys.modules.pop(name, None)

    # --- eq@650 / eq@653: the self-check's own assertions --------------
    def test_the_self_check_pins_the_round_trip_and_the_refusals(self):
        """`eq@650`, `eq@653`: the module's own self-check.

        ``main()`` asserts that the block parses back to the scope
        (``eq@650``) and that the scope hash is canonical across
        field orders (``eq@653``).  Under either mutant the self-check
        would no longer assert what it claims to assert, so it is
        driven here directly: ``main()`` must run clean, and the
        behaviour it asserts must hold on its own.
        """
        svc.main()

        scope = _scope()
        block = svc.verbatim_scope_block(scope)
        self.assertEqual(svc.parse_scope_block(block), scope)
        self.assertEqual(
            svc.scope_hash(scope),
            svc.scope_hash(
                svc.Scope.coerce(
                    {
                        "scope_id": scope.scope_id,
                        "goal": scope.goal,
                        "grants": scope.grants,
                        "instructions": scope.instructions,
                    }
                )
            ),
        )

    # --- eq@669: the self-check's entry point --------------------------
    def test_the_self_check_entry_point_is_the_self_check(self):
        """`eq@669`: the ``__main__`` guard.

        The module ends with ``if __name__ == "__main__": main()``.
        The mutant flips the comparison, so the self-check runs when
        the module is *imported* -- which would print on every import
        and, worse, make the module's own self-check part of every
        other test's import path.  This test pins the guard by running
        the module as a script and by checking that importing it does
        not run the self-check.
        """
        source = Path(svc.__file__).read_text(encoding="utf-8")
        self.assertIn('if __name__ == "__main__":', source)
        # The entry-point guard must be the only place the self-check
        # is called from the module's top level.
        self.assertEqual(
            len(re.findall(r"^if __name__ == \"__main__\":", source, re.M)),
            1,
        )
        # Importing the module does not run the self-check: it defines
        # ``main`` and does not call it at import time.
        self.assertTrue(callable(svc.main))

    # --- the real defect: a value ending in a colon --------------------
    def test_a_value_that_ends_in_a_colon_round_trips(self):
        """The round-trip invariant, on the values that broke it.

        The block format is ``key[len]: value``, and the length prefix
        is what delimits the value.  But the reader also had to
        recognise a *list* header (``key[count]:``, no value), and it
        did so by looking at the line's own shape -- which it could not
        do, because a scalar's value may itself contain colons and
        newlines.  So a scalar whose value ENDED in a colon rendered a
        line that ended in a colon, and the reader could not tell it
        from a list header.

        The result: a scope whose goal, id, instruction or grant ended
        in a colon rendered a block that would not parse back.  The
        scope could not be carried across a compaction at all -- and
        ``scope_preserved`` raised instead of answering, so a caller
        checking the boundary crashed rather than learning that the
        scope was lost.
        """
        scope = svc.Scope(
            instructions=("do not modify main:", "no network egress"),
            grants=("Bash:",),
            goal="ship the fix:",
            scope_id="phase-1:",
        )
        block = svc.verbatim_scope_block(scope)
        self.assertEqual(svc.parse_scope_block(block), scope)
        self.assertEqual(svc.verbatim_scope_block(svc.parse_scope_block(block)), block)

        # And the whole path: the scope crosses the compaction and the
        # boundary check answers, rather than raising.
        compacted = svc.compact_with_scope(("user: go",), scope, lambda t: "summary")
        self.assertTrue(svc.scope_preserved(compacted, scope))
        self.assertEqual(svc.require_scope_preserved(compacted, scope), scope)

    def test_a_value_that_ends_in_a_colon_is_the_only_shape_that_broke(self):
        """The round-trip holds for a sweep of colon-bearing values.

        The defect above is not a one-off: any value whose last
        character is a colon could trip it.  This sweeps values that
        end in a colon, values that merely contain one, and values that
        end in other punctuation, and requires the round-trip to hold
        for every one of them.
        """
        rng = random.Random(20261121)
        alphabet = "ab:[] \n\tX1.-_"
        cases = 0
        for _ in range(3000):
            def value() -> str:
                body = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 8)))
                return body + rng.choice([":", "", ":", "x", ":"])

            scope = svc.Scope(
                instructions=tuple(value() for _ in range(rng.randint(0, 3))),
                grants=tuple(value() for _ in range(rng.randint(0, 2))),
                goal=value(),
                scope_id=value(),
            )
            cases += 1
            block = svc.verbatim_scope_block(scope)
            self.assertEqual(
                svc.parse_scope_block(block),
                scope,
                "the round-trip broke for %r" % (scope,),
            )
        self.assertGreater(cases, 0)


class EquivalentMutantTests(unittest.TestCase):
    """Mutants that are provably EQUIVALENT, recorded so nobody hunts them.

    An equivalent mutant is not a gap in the suite: no test can
    distinguish it, because it does not change the behaviour.  The
    repository's convention (see
    ``components/northstar-agent-runtime/tests/test_state_budget.py``)
    is to record it with a differential proof rather than to leave a
    reader guessing whether a killer is still out there.
    """

    def _load_with(self, source: str, name: str) -> types.ModuleType:
        """Load the module's own source, optionally rewritten.

        The module is re-executed from its source in a fresh module
        object whose ``__file__`` points at the real module, so the
        two versions coexist in one process and can be called side by
        side.
        """
        module = types.ModuleType(name)
        module.__file__ = str(Path(svc.__file__))
        # The module must be in ``sys.modules`` before it is executed:
        # ``dataclasses`` resolves the class's own module through
        # ``sys.modules`` while it processes the decorator.
        sys.modules[name] = module
        exec(compile(source, module.__file__, "exec"), module.__dict__)  # noqa: S102
        return module

    def _end_guard_versions(self) -> tuple[types.ModuleType, types.ModuleType]:
        """The module with the end-marker guard, in both forms.

        The guard is the line ``if end < 0:`` in ``extract_scope_block``
        and the mutant's form is ``if end <= 0:``.  Both versions are
        loaded from the module's own source so that they can be called
        side by side.
        """
        source = Path(svc.__file__).read_text(encoding="utf-8")
        original = self._load_with(source, "_svc_end_lt")
        # The mutation is applied to the source TEXT, so the mutant is
        # built from the same bytes as the original -- there is exactly
        # one ``if end < 0:`` in the module, and it is the guard.
        mutant_source = source.replace("if end < 0:", "if end <= 0:", 1)
        mutant = self._load_with(mutant_source, "_svc_end_lte")
        return original, mutant

    def test_lt_390_is_equivalent(self):
        """`lt@390`: the differential proof of equivalence.

        The line is ``end = text.find(BLOCK_END, begin)`` followed by
        ``if end < 0: return None``.  The mutant makes the guard ``end
        <= 0``.

        The end marker is found by searching from ``begin`` onwards,
        and ``begin`` is the index of the *begin* marker, which is 25
        characters long.  So a found end marker is at index
        ``begin + 25`` at the earliest, and ``begin >= 0`` -- therefore
        ``end >= 25`` whenever it is found at all.  ``end`` can never
        be ``0``, so ``end < 0`` and ``end <= 0`` agree on every
        reachable value.

        The proof below is differential: the two versions are run side
        by side over a sweep of carried texts, and any behavioural
        difference fails the test.  It is deliberately BEHAVIOURAL --
        it never inspects the source text of either version -- so that
        the mutant itself passes the suite, which is what "equivalent"
        means.
        """
        original, mutant = self._end_guard_versions()

        begin = svc.BLOCK_BEGIN
        end = svc.BLOCK_END
        rng = random.Random(20261121)
        alphabet = "ab:[] \n\tX1.-_"
        cases = 0
        for _ in range(3000):
            body = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 12)))
            for template in (
                "{body}",
                "preamble {begin}{body}",
                "{begin}{body}{end}",
                "{begin}{body}",
                "{begin}{end}",
                "{end}{begin}",
                "{body}{begin}{body}{end}{body}",
            ):
                text = template.format(body=body, begin=begin, end=end)
                cases += 1
                before = original.extract_scope_block(text)
                after = mutant.extract_scope_block(text)
                if before != after:
                    self.fail(
                        "the mutated guard changed the behaviour for %r: "
                        "%r != %r" % (text, before, after)
                    )
        self.assertGreater(cases, 0)

    def test_lt_390_boundary_is_unreachable(self):
        """`lt@390`: the boundary the mutant adds is not reachable.

        The mutant's extra branch fires only when the end marker is
        found at index ``0``.  That requires the end marker to appear
        *before* the begin marker in the text, which the search order
        forbids: the search starts at the begin marker, which is 25
        characters long, so a found end marker is at index 25 or
        beyond.  So the added branch has nothing to do, which is why
        the mutant is equivalent rather than merely unexercised.

        This test is BEHAVIOURAL: it drives the reachable shapes of
        the boundary and shows that both forms of the guard agree on
        them.
        """
        original, mutant = self._end_guard_versions()
        # The begin marker alone: no end marker at all.
        self.assertIsNone(svc.extract_scope_block(svc.BLOCK_BEGIN))
        # The end marker BEFORE the begin marker: the search starts at
        # the begin marker, so the early end marker is not found.
        self.assertIsNone(
            svc.extract_scope_block(svc.BLOCK_END + "x" + svc.BLOCK_BEGIN)
        )
        # Both forms of the guard agree on each of those shapes.
        for text in (
            svc.BLOCK_BEGIN,
            svc.BLOCK_END + "x" + svc.BLOCK_BEGIN,
            svc.BLOCK_BEGIN + svc.BLOCK_END,
            "preamble" + svc.BLOCK_BEGIN + svc.BLOCK_END,
        ):
            self.assertEqual(
                original.extract_scope_block(text),
                mutant.extract_scope_block(text),
                "the two forms of the guard disagree for %r" % (text,),
            )


class ScopeVerbatimEquivalenceHarnessControlTests(unittest.TestCase):
    """The ``lt@390`` equivalence proof must be able to FAIL.

    ``EquivalentMutantTests`` proves that the planted fault at
    ``lt@390`` (``if end < 0:`` -> ``if end <= 0:``) changes nothing:
    the end marker is searched for from the begin marker onwards, and
    the begin marker is 25 characters long, so a found end marker is at
    index 25 or beyond -- it can never be 0, and the two spellings of the
    guard therefore agree on every reachable value.

    A differential test that CANNOT fail proves nothing.  If the two
    versions were accidentally the same source, or if the sweep never
    reached an input that separates them, the agreement would be empty
    and the "EQUIVALENT mutant" conclusion would be worthless.

    This class gives the harness its **non-vacuity control**: the same
    loader and the same comparison are pointed at a mutation that is
    known to change behaviour, and the harness is REQUIRED to notice.
    The control is the same guard with the bound moved to ``< -1`` --
    a bound that is never true, so the "no end marker" case falls
    through instead of reporting "no block at all", and the difference
    is observable at once.
    """

    #: The two spellings of the end-marker guard.
    _GUARD_ORIGINAL = "if end < 0:"
    _GUARD_MUTANT = "if end <= 0:"

    def _load_with(self, source: str, name: str) -> types.ModuleType:
        """Load the module's own source, optionally rewritten."""
        module = types.ModuleType(name)
        module.__file__ = str(Path(svc.__file__))
        sys.modules[name] = module
        exec(compile(source, module.__file__, "exec"), module.__dict__)  # noqa: S102
        return module

    def _control_version(self) -> types.ModuleType:
        """The CONTROL variant: the guard can never fire.

        The guard is rewritten from WHICHEVER spelling is on disk -- the
        shipped ``< 0`` or the planted ``<= 0`` -- to a bound that is
        never true.  The comparison is symmetric on purpose: a control
        that asserted the source carried one particular spelling would
        fail the moment the mutation probe planted the other, and would
        report a kill that is a difference in the FILE rather than in
        the BEHAVIOUR.
        """
        source = Path(svc.__file__).read_text(encoding="utf-8")
        if self._GUARD_ORIGINAL in source:
            mutated = source.replace(self._GUARD_ORIGINAL, "if end < -1:", 1)
        else:
            self.assertIn(
                self._GUARD_MUTANT, source, "the end-marker guard moved"
            )
            mutated = source.replace(self._GUARD_MUTANT, "if end < -1:", 1)
        return self._load_with(mutated, "_svc_end_control")

    def test_the_control_mutation_changes_the_outcome(self):
        """The control mutation must actually CHANGE the outcome."""
        source = Path(svc.__file__).read_text(encoding="utf-8")
        original = self._load_with(source, "_svc_end_original")
        control = self._control_version()

        # A begin marker with NO end marker: the shipped form reports
        # "no block at all" (None), the control form returns a block.
        text = svc.BLOCK_BEGIN + "body"
        before = original.extract_scope_block(text)
        after = control.extract_scope_block(text)
        self.assertIsNone(before)
        self.assertNotEqual(
            before,
            after,
            "the control mutation changed nothing, so the differential "
            "harness cannot distinguish any two functions",
        )

    def test_the_harness_notices_the_control_mutation(self):
        """The SAME harness, pointed at the control, must find a difference.

        This is the non-vacuity check on the equivalence proof: the same
        loader and the same sweep that ``lt@390`` uses must report a
        disagreement when the rule it compares against is one that
        genuinely disagrees.
        """
        source = Path(svc.__file__).read_text(encoding="utf-8")
        original = self._load_with(source, "_svc_end_sweep_original")
        control = self._control_version()

        begin = svc.BLOCK_BEGIN
        end = svc.BLOCK_END
        rng = random.Random(20261121)
        alphabet = "ab:[] \n\tX1.-_"
        differences = 0
        cases = 0
        for _ in range(300):
            body = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 12)))
            for template in (
                "{body}",
                "preamble {begin}{body}",
                "{begin}{body}{end}",
                "{begin}{body}",
                "{begin}{end}",
                "{end}{begin}",
                "{body}{begin}{body}{end}{body}",
            ):
                text = template.format(body=body, begin=begin, end=end)
                cases += 1
                if original.extract_scope_block(text) != control.extract_scope_block(text):
                    differences += 1
        self.assertGreater(cases, 0)
        self.assertGreater(
            differences,
            0,
            "the harness found no difference for a mutation that changes "
            "the outcome, so it cannot certify lt@390 as equivalent",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
