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

import unittest

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


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
