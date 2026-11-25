"""Tests for scope_qualifier: the dispatch-time scope-qualifier check.

B173 diviner (Moltbook post ``71f96b42``, *diviner*): scope qualifiers
are the first casualty of summarization, and "a dropped 'folder X only'
converts a restriction into an apparent entitlement".  These tests pin
the rules the module states:

* the grant is a structured record, and the gate reads only that;
* a dropped fence BLOCKS the action (it is not logged and re-scoped);
* a widened fence BLOCKS the action;
* a matching fence passes;
* a narrower fence falls back to the narrower scope, under a clock;
* the fallback's clock expiring keeps the action blocked;
* a missing source line is fail-closed;
* a store that cannot be read is ``outcome_unknown``, never a clean read;
* a missing denial row is ``outcome_unknown``, never a clean read;
* the survival of a qualifier is a measurable number.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scope_qualifier import (
    BLOCKING_OUTCOMES,
    DEFAULT_FALLBACK_TTL_SECONDS,
    OUTCOME_EXPIRED,
    OUTCOME_FALLBACK,
    OUTCOME_MATCH,
    OUTCOME_MISMATCH,
    OUTCOME_UNKNOWN,
    ROW_CLEAR,
    ROW_DENIED,
    KIND_CHECKED,
    DenialRow,
    DenialRowStore,
    GrantRecord,
    MalformedGrantError,
    QualifierDiff,
    ScopeCheck,
    ScopeFallback,
    ScopeGrantRegistry,
    ScopeQualifier,
    ScopeQualifierError,
    ScopeQualifierGate,
    ScopeSourceError,
    SourceLine,
    SourceStore,
    SurvivalMetrics,
    check_compaction_boundary,
    diff_qualifiers,
    measure_qualifier_survival,
    narrower_scope,
    permitted_targets,
    scope_audit_event,
    scope_relation,
    scope_tokens,
    stdlib_only,
)


FOLDER_X = ScopeQualifier("only", "folder X")
FOLDER_Y = ScopeQualifier("only", "folder Y")
ALL_FOLDERS = ScopeQualifier("only", "all folders")
EXCEPT_Z = ScopeQualifier("except", "folder Z")


def source_line(
    source_ref: str = "src-1",
    grant_id: str = "grant-1",
    qualifiers=(FOLDER_X,),
    revoked: bool = False,
) -> SourceLine:
    return SourceLine(
        source_ref=source_ref,
        grant_id=grant_id,
        qualifiers=tuple(qualifiers),
        revoked=revoked,
    )


def grant(
    grant_id: str = "grant-1",
    verb: str = "write",
    qualifiers=(FOLDER_X,),
    source_ref: str = "src-1",
) -> GrantRecord:
    return GrantRecord(
        grant_id=grant_id,
        verb=verb,
        qualifiers=tuple(qualifiers),
        source_ref=source_ref,
    )


def clear_row(scope: str = "grant-1/write") -> DenialRow:
    return DenialRow(scope=scope, kind=ROW_CLEAR, signature="sig-1")


def make_gate(
    sources=(FOLDER_X,),
    rows=(clear_row(),),
    grant_id: str = "grant-1",
    ttl: int = 100,
    revoked: bool = False,
) -> ScopeQualifierGate:
    store = SourceStore(
        [source_line(grant_id=grant_id, qualifiers=sources, revoked=revoked)]
    )
    row_store = DenialRowStore(list(rows))
    return ScopeQualifierGate(store, denial_rows=row_store, fallback_ttl_seconds=ttl)


class ScopeQualifierRecordTests(unittest.TestCase):
    """The grant is a structured record: verb and fence on one row."""

    def test_a_grant_carries_its_verb_and_its_fence_together(self):
        record = grant()
        self.assertEqual(record.verb, "write")
        self.assertEqual(record.scope_text(), "folder X only")
        self.assertTrue(record.is_bounded())

    def test_a_grant_with_no_qualifier_is_unbounded_not_empty(self):
        record = grant(qualifiers=())
        self.assertFalse(record.is_bounded())
        self.assertEqual(record.scope_text(), "")
        self.assertIsNone(permitted_targets(record.qualifiers))

    def test_the_record_round_trips_through_a_mapping(self):
        record = grant()
        again = GrantRecord.from_dict(record.to_dict())
        self.assertEqual(again.to_dict(), record.to_dict())

    def test_a_grant_with_an_empty_id_is_refused(self):
        with self.assertRaises(ScopeQualifierError):
            GrantRecord(grant_id="", verb="write")
        with self.assertRaises(ScopeQualifierError):
            GrantRecord(grant_id="g", verb="")


class ScopeAlgebraTests(unittest.TestCase):
    """Narrowness is decided by the permitted targets, not by length."""

    def test_the_same_fence_is_equal(self):
        self.assertEqual(scope_relation((FOLDER_X,), (FOLDER_X,)), "equal")

    def test_a_dropped_fence_is_wider_than_a_bounded_source(self):
        self.assertEqual(scope_relation((), (FOLDER_X,)), "wider")

    def test_a_widened_fence_is_wider(self):
        # "all folders" names no fence at all, so it is wider than a
        # bounded source: the widened grant asks for more than it was
        # given.
        self.assertEqual(scope_relation((ALL_FOLDERS,), (FOLDER_X,)), "wider")

    def test_a_narrower_fence_is_narrower(self):
        self.assertEqual(
            scope_relation((FOLDER_X,), (FOLDER_X, FOLDER_Y)), "narrower"
        )

    def test_the_narrower_scope_is_the_intersection_of_both_fences(self):
        agreed = narrower_scope((FOLDER_X,), (FOLDER_X, FOLDER_Y))
        self.assertEqual([q.resource for q in agreed], ["folder X"])

    def test_a_dropped_fence_has_no_fence_the_source_agrees_with(self):
        # The presented grant asserts no fence at all, so the gate never
        # reaches a fallback for it: it is wider, and it is blocked.
        # (The intersection helper alone still reports the source's
        # fence, because the source's fence *is* a subset of an
        # unbounded one -- which is exactly why the gate checks the
        # relation first and refuses the widened grant outright.)
        self.assertEqual(scope_relation((), (FOLDER_X,)), "wider")
        self.assertEqual(narrower_scope((), (FOLDER_X,)), (FOLDER_X,))

    def test_two_only_clauses_union_their_targets(self):
        permitted = permitted_targets((FOLDER_X, FOLDER_Y))
        self.assertEqual(permitted, frozenset({"folder x", "folder y"}))


class ScopeCheckTests(unittest.TestCase):
    """The check: re-derive the scope from the source, block on mismatch."""

    def test_a_matching_fence_passes(self):
        gate = make_gate()
        check = gate.check(grant(), now=100)
        self.assertFalse(check.blocked)
        self.assertEqual(check.outcome, OUTCOME_MATCH)
        self.assertEqual(check.effective_scope, "folder X only")

    def test_a_dropped_fence_is_blocked(self):
        """The post's case: "folder X only" lost, so the grant is wider."""
        gate = make_gate()
        check = gate.check(grant(qualifiers=()), now=100)
        self.assertTrue(check.blocked)
        self.assertEqual(check.outcome, OUTCOME_MISMATCH)
        self.assertEqual(check.effective_scope, "", "a blocked action runs under no scope")

    def test_a_widened_fence_is_blocked(self):
        """The grant grew from "folder X only" to everything."""
        gate = make_gate()
        check = gate.check(grant(qualifiers=(ALL_FOLDERS,)), now=100)
        self.assertTrue(check.blocked)
        self.assertEqual(check.outcome, OUTCOME_MISMATCH)

    def test_a_narrower_fence_falls_back_to_the_narrower_scope(self):
        """The grant asks for less than it was given: the agreed scope is
        the narrower one, and it runs under a clock."""
        gate = make_gate(sources=(FOLDER_X, FOLDER_Y))
        check = gate.check(grant(qualifiers=(FOLDER_X,)), now=100)
        self.assertFalse(check.blocked)
        self.assertEqual(check.outcome, OUTCOME_FALLBACK)
        self.assertEqual(check.effective_scope, "folder X only")
        self.assertIsNotNone(check.fallback)
        assert check.fallback is not None
        self.assertEqual(check.fallback.issued_at, 100)
        self.assertEqual(check.fallback.expires_at, 100 + gate.fallback_ttl_seconds)

    def test_the_fallback_clock_expiry_keeps_the_action_blocked(self):
        """The narrowed grant must not become a permanent one."""
        gate = make_gate(sources=(FOLDER_X, FOLDER_Y), ttl=100)
        first = gate.check(grant(qualifiers=(FOLDER_X,)), now=100)
        self.assertFalse(first.blocked)
        expired = gate.check(grant(qualifiers=(FOLDER_X,)), now=200)
        self.assertTrue(expired.blocked)
        self.assertEqual(expired.outcome, OUTCOME_EXPIRED)
        self.assertIn(OUTCOME_EXPIRED, BLOCKING_OUTCOMES)

    def test_a_repeated_dispatch_does_not_extend_the_fallback_clock(self):
        """A fresh clock per dispatch would be an infinite extension
        wearing a deadline."""
        gate = make_gate(sources=(FOLDER_X, FOLDER_Y), ttl=100)
        first = gate.check(grant(qualifiers=(FOLDER_X,)), now=100)
        second = gate.check(grant(qualifiers=(FOLDER_X,)), now=150)
        assert first.fallback is not None and second.fallback is not None
        self.assertEqual(first.fallback.expires_at, second.fallback.expires_at)
        third = gate.check(grant(qualifiers=(FOLDER_X,)), now=200)
        self.assertTrue(third.blocked, "the clock must still run out")

    def test_a_missing_source_line_is_fail_closed(self):
        """No source to check against: the grant does not stand."""
        gate = make_gate()
        check = gate.check(grant(source_ref="src-does-not-exist"), now=100)
        self.assertTrue(check.blocked)
        self.assertEqual(check.outcome, OUTCOME_MISMATCH)

    def test_an_unreadable_source_store_is_outcome_unknown(self):
        """A store that cannot answer is not a clean read."""
        gate = make_gate()
        gate.store.break_reads()
        check = gate.check(grant(), now=100)
        self.assertTrue(check.blocked)
        self.assertEqual(check.outcome, OUTCOME_UNKNOWN)
        self.assertIn(OUTCOME_UNKNOWN, BLOCKING_OUTCOMES)

    def test_a_missing_denial_row_is_outcome_unknown(self):
        """Conclusion 96: the gate needs a row or a signed "no denial"
        proof.  An absent row is not permission."""
        gate = make_gate(rows=())
        check = gate.check(grant(), now=100)
        self.assertTrue(check.blocked)
        self.assertEqual(check.outcome, OUTCOME_UNKNOWN)

    def test_an_unreadable_denial_row_store_is_outcome_unknown(self):
        gate = make_gate()
        gate._rows.break_reads()
        check = gate.check(grant(), now=100)
        self.assertTrue(check.blocked)
        self.assertEqual(check.outcome, OUTCOME_UNKNOWN)

    def test_a_denial_row_refuses_the_scope(self):
        gate = make_gate(rows=(DenialRow(scope="grant-1/write", kind=ROW_DENIED, reason="operator revoked"),))
        check = gate.check(grant(), now=100)
        self.assertTrue(check.blocked)
        self.assertIn("operator revoked", check.reason)

    def test_a_revoked_source_blocks(self):
        gate = make_gate(revoked=True)
        check = gate.check(grant(), now=100)
        self.assertTrue(check.blocked)
        self.assertEqual(check.outcome, OUTCOME_MISMATCH)

    def test_a_source_for_a_different_grant_blocks(self):
        gate = make_gate()
        check = gate.check(grant(source_ref="src-1"), now=100)
        self.assertFalse(check.blocked)
        other = ScopeGrantRegistry(
            sources=[source_line(grant_id="grant-2")],
            rows=[clear_row("grant-1/write")],
        )
        check = other.gate.check(grant(), now=100)
        self.assertTrue(check.blocked)

    def test_an_unsigned_clear_row_is_refused_at_construction(self):
        """An unsigned "no denial" row is a claim, not a proof."""
        with self.assertRaises(ScopeQualifierError):
            DenialRow(scope="grant-1/write", kind=ROW_CLEAR)

    def test_the_gate_rejects_a_non_grant(self):
        gate = make_gate()
        with self.assertRaises(ScopeQualifierError):
            gate.check({"grant_id": "x"}, now=100)  # type: ignore[arg-type]


class CompactionBoundaryTests(unittest.TestCase):
    """Every compaction boundary is an authorization boundary."""

    def test_a_grant_that_kept_its_fence_survives_the_boundary(self):
        check = check_compaction_boundary([grant()])
        self.assertFalse(check.blocked)
        self.assertEqual(check.survived_grants, ("grant-1",))

    def test_a_grant_that_lost_a_scope_token_is_refused_at_the_boundary(self):
        """The cheaper qualifier diff (reportio's proposal): pull the
        scope tokens from the input and the output and see which the
        rewrite dropped."""
        source = "write to folder X only"
        check = check_compaction_boundary(
            [grant(qualifiers=())],
            source_text_for=lambda _grant_id: source,
        )
        self.assertTrue(check.blocked)
        self.assertEqual(check.blocked_grants, ("grant-1",))

    def test_a_dropped_token_with_an_explicit_removal_note_is_not_a_loss(self):
        source = "write to folder X only"
        check = check_compaction_boundary(
            [grant(qualifiers=(ScopeQualifier("only", "folder X"),))],
            source_text_for=lambda _grant_id: source + " (removed: no longer needed)",
        )
        self.assertFalse(check.blocked)

    def test_a_grant_with_no_source_to_compare_against_is_refused(self):
        check = check_compaction_boundary(
            [grant()], source_text_for=lambda _grant_id: None
        )
        self.assertTrue(check.blocked)
        self.assertEqual(check.blocked_grants, ("grant-1",))

    def test_the_reissue_drops_a_refused_grant(self):
        """A grant refused at the boundary is not reissued: it cannot
        come back as an entitlement."""
        registry = ScopeGrantRegistry(
            sources=[source_line()],
            presented=[grant()],
            rows=[clear_row()],
        )
        registry.reissue(
            [grant(qualifiers=())],
            source_text_for=lambda _grant_id: "write to folder X only",
        )
        self.assertEqual(registry.presented(), ())


class QualifierDiffTests(unittest.TestCase):
    """The scope-token diff, and its removal note."""

    def test_a_dropped_token_is_a_loss(self):
        diff = diff_qualifiers("write to folder X only", "write to folder X")
        self.assertEqual(diff.dropped, ("only",))
        self.assertEqual(diff.lost, ("only",))

    def test_an_explicit_removal_is_not_a_loss(self):
        diff = diff_qualifiers(
            "write to folder X only", "write to folder X (removed: only)"
        )
        self.assertEqual(diff.lost, ())

    def test_the_tokens_are_the_scope_words(self):
        self.assertEqual(
            scope_tokens("only except until unless per within"),
            ("only", "except", "until", "unless", "per", "within"),
        )

    def test_an_empty_diff_has_no_loss(self):
        diff = diff_qualifiers("write", "write")
        self.assertEqual(diff.lost, ())
        self.assertIsInstance(diff, QualifierDiff)


class SurvivalMeasurementTests(unittest.TestCase):
    """"Grants generalize, fences shrink" -- as a number, not a metaphor."""

    def test_the_measure_reports_a_qualifier_survival_rate(self):
        grants = [grant(grant_id=f"g{i}", source_ref=f"s{i}") for i in range(6)]
        metrics = measure_qualifier_survival(grants, rounds=1)
        self.assertEqual(metrics.rounds, 1)
        self.assertEqual(metrics.grants_in, 6)
        self.assertEqual(metrics.grants_out, 6, "the verb generalizes: the grant survives")
        self.assertLess(
            metrics.qualifier_survival,
            metrics.grant_survival,
            "the fence must shrink faster than the grant",
        )
        self.assertGreater(metrics.widening_rate, 0.0)

    def test_the_measure_shows_the_gate_catching_the_widenings(self):
        sources = [source_line(source_ref=f"s{i}", grant_id=f"g{i}") for i in range(6)]
        rows = [clear_row(scope=f"g{i}/write") for i in range(6)]
        registry = ScopeGrantRegistry(sources=sources, rows=rows)
        grants = [
            GrantRecord(grant_id=f"g{i}", verb="write", qualifiers=(FOLDER_X,), source_ref=f"s{i}")
            for i in range(6)
        ]
        metrics = measure_qualifier_survival(grants, gate=registry.gate, rounds=1)
        self.assertGreater(metrics.widening_rate, 0.0)
        self.assertEqual(metrics.caught, metrics.widened, "every widening is caught")
        self.assertEqual(metrics.caught_rate, 1.0)

    def test_a_perfect_compaction_has_full_survival(self):
        grants = [grant(grant_id=f"g{i}", source_ref=f"s{i}") for i in range(3)]
        metrics = measure_qualifier_survival(grants, rounds=1)
        # Every third grant is rewritten, so the fences do shrink.
        self.assertLessEqual(metrics.qualifier_survival, 1.0)
        self.assertGreaterEqual(metrics.qualifier_survival, 0.0)


class ScopeQualifierModuleTests(unittest.TestCase):
    """House-style self-checks."""

    def test_the_module_is_stdlib_only(self):
        self.assertTrue(stdlib_only())

    def test_the_default_fallback_ttl_is_positive(self):
        self.assertGreater(DEFAULT_FALLBACK_TTL_SECONDS, 0)

    def test_a_fallback_must_expire_after_it_is_issued(self):
        with self.assertRaises(ScopeQualifierError):
            ScopeFallback(
                grant_id="g", scope_text="folder X only", issued_at=100, expires_at=100
            )


class QualifierGuardSecondHalfTests(unittest.TestCase):
    """The SECOND half of each scope-qualifier guard.

    Every guard here is a double guard: a type half joined to a second
    half -- an emptiness half, a bound half, or a defaulting half -- by
    `or`.  The diviner slice's own suite drove only ONE half of each, so
    flipping the connective left the suite green: the planted faults
    gt@204, or@274, or@276, gt@278, gt@280 and or@303 all SURVIVED it.

      gt@204   len(canonical) > _MAX_ID_CHARS
               The bound is on the CANONICAL verb (after strip and
               casefold), so the exact limit must be ACCEPTED and the
               limit plus one REFUSED.  A suite that only fed a very
               long verb never measured where the line is.
      or@274   not isinstance(self.kind, str) or not self.kind.strip()
               The second half is the EMPTINESS half: a kind that is a
               string but only whitespace must be refused.
      or@276   the same for the resource.
      gt@278   len(self.kind) > _MAX_SCOPE_CHARS
               The bound is on the kind, and the exact limit must be
               accepted.
      gt@280   the same for the resource.
      or@303   str(value.get("note", "") or "")
               The second half is the DEFAULTING half: a note that is
               None, absent, or empty must become the empty string
               rather than the string "None" or a crash.

    Each test here fails when its planted fault is applied alone.
    """

    def test_a_verb_at_the_character_limit_is_accepted(self):
        """`gt@204`: the exact limit is inside the bound.

        `_MAX_ID_CHARS` is 256 and the bound is on the CANONICAL verb,
        so a 256-character verb must be accepted.
        """
        from scope_qualifier import _MAX_ID_CHARS, canonical_verb

        verb = "v" * _MAX_ID_CHARS
        self.assertEqual(canonical_verb(verb), verb)

    def test_a_verb_one_character_over_the_limit_is_refused(self):
        """`gt@204`: the limit plus one is outside it.

        With `> -> >=` the verb exactly at the limit is refused, which
        is the off-by-one this test closes.
        """
        from scope_qualifier import _MAX_ID_CHARS, canonical_verb

        verb = "v" * (_MAX_ID_CHARS + 1)
        with self.assertRaises(ScopeQualifierError):
            canonical_verb(verb)

    def test_the_verb_bound_is_measured_after_stripping(self):
        """`gt@204`: the bound is on the canonical form.

        A verb with leading whitespace is stripped before the bound is
        measured, so a verb that is exactly at the limit once stripped
        must be accepted even though the raw string is longer.
        """
        from scope_qualifier import _MAX_ID_CHARS, canonical_verb

        verb = "  " + ("v" * _MAX_ID_CHARS) + "  "
        self.assertEqual(canonical_verb(verb), "v" * _MAX_ID_CHARS)

    def test_a_whitespace_only_kind_is_refused(self):
        """`or@274`: the EMPTINESS half of the kind guard.

        A kind that is a string but holds only whitespace names
        nothing, so it must be refused -- the type half alone cannot
        see that.
        """
        with self.assertRaises(ScopeQualifierError):
            ScopeQualifier(kind="   ", resource="the China segment")

    def test_a_whitespace_only_resource_is_refused(self):
        """`or@276`: the EMPTINESS half of the resource guard."""
        with self.assertRaises(ScopeQualifierError):
            ScopeQualifier(kind="only", resource="\t\n ")

    def test_a_kind_at_the_character_limit_is_accepted(self):
        """`gt@278`: the exact limit is inside the bound."""
        from scope_qualifier import _MAX_SCOPE_CHARS

        kind = "k" * _MAX_SCOPE_CHARS
        qualifier = ScopeQualifier(kind=kind, resource="segment")
        self.assertEqual(qualifier.kind, kind)

    def test_a_kind_one_character_over_the_limit_is_refused(self):
        """`gt@278`: the limit plus one is outside it."""
        from scope_qualifier import _MAX_SCOPE_CHARS

        with self.assertRaises(ScopeQualifierError):
            ScopeQualifier(kind="k" * (_MAX_SCOPE_CHARS + 1), resource="segment")

    def test_a_resource_at_the_character_limit_is_accepted(self):
        """`gt@280`: the exact limit is inside the bound."""
        from scope_qualifier import _MAX_SCOPE_CHARS

        resource = "r" * _MAX_SCOPE_CHARS
        qualifier = ScopeQualifier(kind="only", resource=resource)
        self.assertEqual(qualifier.resource, resource)

    def test_a_resource_one_character_over_the_limit_is_refused(self):
        """`gt@280`: the limit plus one is outside it."""
        from scope_qualifier import _MAX_SCOPE_CHARS

        with self.assertRaises(ScopeQualifierError):
            ScopeQualifier(kind="only", resource="r" * (_MAX_SCOPE_CHARS + 1))

    def test_a_missing_note_becomes_the_empty_string(self):
        """`or@303`: the DEFAULTING half of the note guard.

        A qualifier built from a mapping with no note must carry the
        empty string, not the string "None" and not a crash.
        """
        qualifier = ScopeQualifier.from_dict({"kind": "only", "resource": "segment"})
        self.assertEqual(qualifier.note, "")

    def test_a_null_note_becomes_the_empty_string(self):
        """`or@303`: a note that is explicitly None.

        `str(value.get("note", "") or "")` -- the `or ""` is the half
        under test.  A note of None must become the empty string; with
        the connective flipped to `and`, `None` would reach `str()` and
        become the literal text "None", which is a note the grant never
        had.
        """
        qualifier = ScopeQualifier.from_dict(
            {"kind": "only", "resource": "segment", "note": None}
        )
        self.assertEqual(qualifier.note, "")
        self.assertNotEqual(qualifier.note, "None")

    def test_a_present_note_is_kept_verbatim(self):
        """`or@303`: the control -- a real note survives."""
        qualifier = ScopeQualifier.from_dict(
            {"kind": "only", "resource": "segment", "note": "as of Q3"}
        )
        self.assertEqual(qualifier.note, "as of Q3")


class ScopeQualifierCommonGuardTests(unittest.TestCase):
    """The guards both scope-qualifier slices share, woken with crafted
    inputs.

    ``scope-verb-canonical`` and ``diviner`` read the SAME module, so the
    same planted faults survive BOTH suites.  This class drives the arm
    of each guard that neither suite drove, and it is added to BOTH test
    files so that each slice's own census -- the one that measures *that*
    slice's tests -- sees the kill.

    Each test names the mutant it kills.  The technique is always the
    same: the guard has two arms and the suite drove one of them, so the
    test drives the other.

      or@274   ``not isinstance(self.kind, str) or
               not self.kind.strip()``        -- the EMPTINESS half
      or@276   the same for the resource
      gt@278   ``len(self.kind) > _MAX_SCOPE_CHARS``  -- the bound
      gt@280   ``len(self.resource) > _MAX_SCOPE_CHARS``
      or@303   ``str(value.get("note", "") or "")``    -- the DEFAULTING half
      gt@334   ``len(self.grant_id) > _MAX_ID_CHARS``  -- the bound
      or@336   ``not isinstance(self.verb, str) or
               not self.verb.strip()``         -- the TYPE half
      or@349   ``isinstance(self.counter, bool) or
               not isinstance(self.counter, int)``     -- the BOOL half
      lt@351   ``self.counter < 0``            -- the bound
      or@368   ``value.get("qualifiers") or ()``       -- the DEFAULTING half
      or@369   ``isinstance(quals, (str, bytes)) or
               not isinstance(quals, (list, tuple))``   -- the "not a list" half
      retF@455 ``_is_wildcard``'s ``return False``
      or@483   the source line's source_ref guard -- the EMPTINESS half
      or@485   the source line's grant_id guard  -- the EMPTINESS half
      or@516   ``value.get("qualifiers") or ()``       -- the DEFAULTING half
      or@517   the source line's qualifier-list guard -- the "not a list" half
      or@575   ``not isinstance(source_ref, str) or not source_ref``
               -- the EMPTINESS half
      eq@661   ``presented_targets == source_targets``
      eq@662   ``presented_atoms == source_atoms``
      or@746   the fallback's grant_id guard   -- the EMPTINESS half
      or@748   the fallback's scope_text guard -- the EMPTINESS half
      or@752   the fallback's int guard         -- the BOOL half
      or@759   the fallback clock's int guard   -- the BOOL half
      or@782   the fallback mapping's source_ref defaulting half
      or@783   the fallback mapping's reason defaulting half
      or@870   ``not isinstance(text, str) or not text``  -- the TYPE half
      and@888  ``isinstance(compacted_text, str) and
               REMOVAL_MARKER in compacted_text.lower()`` -- the TYPE half
      or@927   the gate's TTL int guard          -- the BOOL half
      or@983   the gate's clock int guard        -- the BOOL half
      or@1054  ``row.reason or 'denial row'``    -- the DEFAULTING half
      eq@1328  ``canonical_verb(grant.verb) == canonical``
      or@1396  the denial row's scope guard      -- the EMPTINESS half
      or@1483  ``not isinstance(scope, str) or not scope``
               -- the EMPTINESS half
      or@1550  the boundary check's sequence guard -- the "not a list" half
      eq@1618  ``if self.rounds == 0`` in ``grant_survival``
      eq@1625  the same in ``qualifier_survival``
      eq@1632  the same in ``widening_rate``
      eq@1639  ``if self.widened == 0`` in ``caught_rate``
      or@1682  the measure's sequence guard       -- the "not a list" half
      or@1684  the measure's rounds guard        -- the BOOL half
      lt@1684  the measure's ``rounds < 1`` bound
      eq@1696  ``drops = (index + round_index) % 3 == 0``
      and@1697 ``if drops and grant.qualifiers``
      and@1714 ``if check is not None and check.blocked``
      or@1744  the audit event's kind guard      -- the EMPTINESS half
      or@1746  the audit event's seq guard       -- the BOOL half
      lt@1746  the audit event's ``seq < 0`` bound
    """

    # -- the qualifier record's guards ----------------------------------

    def test_a_whitespace_only_kind_is_refused(self):
        """or@274: the EMPTINESS half of the kind guard.

        A kind that is a string but holds only whitespace names nothing,
        so it must be refused: the type half cannot see it.
        """
        with self.assertRaises(MalformedGrantError):
            ScopeQualifier(kind="   ", resource="the China segment")

    def test_a_whitespace_only_resource_is_refused(self):
        """or@276: the EMPTINESS half of the resource guard."""
        with self.assertRaises(MalformedGrantError):
            ScopeQualifier(kind="only", resource="\t\n ")

    def test_a_kind_at_the_character_limit_is_accepted(self):
        """gt@278: the bound on the kind is STRICT.

        A kind of exactly the cap's length is inside it.  Under the
        planted fault (``>`` -> ``>=``) it would be refused.
        """
        from scope_qualifier import _MAX_SCOPE_CHARS

        kind = "k" * _MAX_SCOPE_CHARS
        qualifier = ScopeQualifier(kind=kind, resource="segment")
        self.assertEqual(qualifier.kind, kind)

    def test_a_resource_at_the_character_limit_is_accepted(self):
        """gt@280: the bound on the resource is STRICT."""
        from scope_qualifier import _MAX_SCOPE_CHARS

        resource = "r" * _MAX_SCOPE_CHARS
        qualifier = ScopeQualifier(kind="only", resource=resource)
        self.assertEqual(qualifier.resource, resource)

    def test_a_null_note_becomes_the_empty_string(self):
        """or@303: the DEFAULTING half of the note guard.

        ``str(value.get("note", "") or "")`` -- the ``or ""`` is the half
        under test.  A note of None must become the empty string; with
        the connective flipped to ``and``, None would reach ``str()``
        and become the literal text "None", which is a note the grant
        never had.
        """
        qualifier = ScopeQualifier.from_dict(
            {"kind": "only", "resource": "segment", "note": None}
        )
        self.assertEqual(qualifier.note, "")
        self.assertNotEqual(qualifier.note, "None")

    def test_a_missing_note_becomes_the_empty_string(self):
        """or@303: the same, for an ABSENT note."""
        qualifier = ScopeQualifier.from_dict(
            {"kind": "only", "resource": "segment"}
        )
        self.assertEqual(qualifier.note, "")

    # -- the grant record's guards --------------------------------------

    def test_a_grant_id_at_the_character_limit_is_accepted(self):
        """gt@334: the bound on the grant id is STRICT."""
        from scope_qualifier import _MAX_ID_CHARS

        record = GrantRecord(grant_id="g" * _MAX_ID_CHARS, verb="write")
        self.assertEqual(len(record.grant_id), _MAX_ID_CHARS)

    def test_a_grant_with_a_non_string_verb_is_refused(self):
        """or@336: the TYPE half of the verb guard.

        Without it the guard is skipped and the record's own
        canonicalisation is handed a non-string, so the refusal
        arrives as an ``AttributeError`` (no ``strip``) rather than as
        the ``MalformedGrantError`` the record's contract promises.
        The *type* is asserted, not just "some exception".
        """
        with self.assertRaises(MalformedGrantError):
            GrantRecord(grant_id="grant-1", verb=None)

    def test_a_grant_with_a_bool_counter_is_refused(self):
        """or@349: the BOOL half of the counter guard.

        ``True`` IS an ``int`` in Python, so the "not an int" half never
        refuses a boolean -- only the explicit ``bool`` half does.
        """
        with self.assertRaises(MalformedGrantError):
            GrantRecord(grant_id="grant-1", verb="write", counter=True)

    def test_a_grant_with_a_zero_counter_is_accepted(self):
        """lt@351: the bound on the counter is STRICT.

        ``0`` is a legal counter, so the bound is ``counter < 0``.  Under
        the planted fault (``<`` -> ``<=``) a zero counter would be
        refused -- the first grant ever issued would be unbuildable.
        """
        record = GrantRecord(grant_id="grant-1", verb="write", counter=0)
        self.assertEqual(record.counter, 0)

    def test_a_grant_with_no_qualifiers_key_is_accepted(self):
        """or@368: the DEFAULTING half of the qualifier-list read.

        ``quals = value.get("qualifiers") or ()`` -- the ``or ()`` is the
        half under test.  A mapping with no ``qualifiers`` key must build
        a grant with an empty fence; with the connective flipped to
        ``and`` the None would fall through to the type guard and the
        grant would be refused for a field it never mentioned.
        """
        record = GrantRecord.from_dict({
            "grant_id": "grant-1",
            "verb": "write",
        })
        self.assertEqual(record.qualifiers, ())

    def test_a_grant_with_a_mapping_qualifier_list_is_refused(self):
        """or@369: the "not a list/tuple" half of the guard.

        The *message* is asserted, not just the exception type: with
        the connective flipped to ``and`` the mapping slips past the
        guard and is then iterated key by key, and the refusal arrives
        later from a different guard with a different message ("a
        qualifier must be a mapping").  The type alone would not
        distinguish "refused by this guard" from "refused later by
        accident".
        """
        with self.assertRaises(MalformedGrantError) as caught:
            GrantRecord.from_dict({
                "grant_id": "grant-1",
                "verb": "write",
                "qualifiers": {"kind": "only"},
            })
        self.assertIn("qualifiers must be a list", str(caught.exception))

    # -- the wildcard check ---------------------------------------------

    def test_an_empty_resource_is_not_the_unbounded_scope(self):
        """retF@455: the ``return False`` of the wildcard check.

        ``_is_wildcard`` answers "does this resource name everything?".
        An empty resource names nothing, so the answer is False.  Under
        the planted fault (``return False`` -> ``return True``) an empty
        resource would read as the unbounded scope -- the widest fence
        there is -- the opposite of the fail-closed rule.
        """
        from scope_qualifier import _is_wildcard

        self.assertFalse(_is_wildcard(""))
        self.assertFalse(_is_wildcard("   "))
        self.assertTrue(_is_wildcard("all folders"))
        self.assertFalse(_is_wildcard("folder X"))

    # -- the source line's guards ---------------------------------------

    def test_a_source_line_with_a_blank_source_ref_is_refused(self):
        """or@483: the EMPTINESS half of the source_ref guard."""
        with self.assertRaises(MalformedGrantError):
            SourceLine(source_ref="   ", grant_id="grant-1")

    def test_a_source_line_with_a_blank_grant_id_is_refused(self):
        """or@485: the EMPTINESS half of the source line's grant_id guard."""
        with self.assertRaises(MalformedGrantError):
            SourceLine(source_ref="src-1", grant_id="   ")

    def test_a_source_line_with_no_qualifiers_key_is_accepted(self):
        """or@516: the DEFAULTING half of the qualifier-list read.

        The same shape as the grant's or@368: a mapping that does not
        mention ``qualifiers`` must build a source line with an empty
        fence, not be refused for a field it never mentioned.
        """
        line = SourceLine.from_dict({
            "source_ref": "src-1",
            "grant_id": "grant-1",
        })
        self.assertEqual(line.qualifiers, ())

    def test_a_source_line_with_a_mapping_qualifier_list_is_refused(self):
        """or@517: the "not a list/tuple" half of the guard.

        The *message* is asserted, not just the exception type: with
        the connective flipped to ``and`` the mapping slips past the
        guard and is then iterated key by key, and the refusal arrives
        later from a different guard with a different message.
        """
        with self.assertRaises(MalformedGrantError) as caught:
            SourceLine.from_dict({
                "source_ref": "src-1",
                "grant_id": "grant-1",
                "qualifiers": {"kind": "only"},
            })
        self.assertIn("qualifiers must be a list", str(caught.exception))

    def test_the_source_store_refuses_an_empty_source_ref(self):
        """or@575: the EMPTINESS half of the fetch guard.

        An empty source_ref names no line, so it is a *read error*
        (``ScopeSourceError``) and not a clean miss.  Under the planted
        fault the empty ref would be looked up in the map and read as
        "no such line" -- a clean read from a malformed request.
        """
        store = SourceStore()
        with self.assertRaises(ScopeSourceError):
            store.fetch("")

    # -- the scope algebra ----------------------------------------------

    def test_the_same_fence_is_equal(self):
        """eq@661 and eq@662: the equality arm of the scope algebra.

        Two fences that permit the same targets under the same
        qualifiers are ``equal``.  Under eq@661 the equality test is
        inverted and an equal pair falls through to the incomparable
        answer; under eq@662 the atom test is inverted and the equal
        pair reads as ``narrower``.  Both would let a grant that stands
        as authorized be re-scoped instead.
        """
        self.assertEqual(scope_relation((FOLDER_X,), (FOLDER_X,)), "equal")

    def test_the_same_targets_under_a_different_qualifier_is_narrower(self):
        """eq@662: the second equality, on the ATOMS.

        The same permitted targets under a different qualifier are
        ``narrower`` -- the presented fence asks for no more, so it may
        run.  Under the inverted atom test this pair would read as
        ``equal``, which would let a presented fence that adds a
        restriction be reported as standing exactly as authorized.
        """
        self.assertEqual(
            scope_relation((ScopeQualifier("per", "folder X"),), (FOLDER_X,)),
            "narrower",
        )

    # -- the fallback's guards ------------------------------------------

    def test_a_fallback_with_an_empty_grant_id_is_refused(self):
        """or@746: the EMPTINESS half of the fallback's grant_id guard."""
        with self.assertRaises(MalformedGrantError):
            ScopeFallback(
                grant_id="", scope_text="folder X only", issued_at=0, expires_at=10
            )

    def test_a_fallback_with_an_empty_scope_text_is_refused(self):
        """or@748: the EMPTINESS half of the fallback's scope_text guard."""
        with self.assertRaises(MalformedGrantError):
            ScopeFallback(
                grant_id="grant-1", scope_text="", issued_at=0, expires_at=10
            )

    def test_a_fallback_with_a_boolean_issued_at_is_refused(self):
        """or@752: the BOOL half of the fallback's int guard.

        ``True`` IS an ``int`` in Python, so the "not an int" half never
        refuses a boolean -- only the explicit ``bool`` half does.  Under
        the planted fault a boolean clock would be accepted and used as
        the integer 1.
        """
        with self.assertRaises(MalformedGrantError):
            ScopeFallback(
                grant_id="grant-1", scope_text="folder X only",
                issued_at=True, expires_at=10,
            )

    def test_the_fallback_clock_refuses_a_boolean_now(self):
        """or@759: the BOOL half of the clock's int guard."""
        fallback = ScopeFallback(
            grant_id="grant-1", scope_text="folder X only",
            issued_at=0, expires_at=10,
        )
        with self.assertRaises(MalformedGrantError):
            fallback.is_expired(True)

    def test_a_fallback_mapping_defaults_its_source_ref(self):
        """or@782: the DEFAULTING half of the source_ref read.

        A source_ref that is explicitly None must become the empty
        string.  Under the planted fault (``or`` -> ``and``) the None
        would reach ``str()`` and become the literal text "None" -- a
        source ref the fallback never had.
        """
        fallback = ScopeFallback.from_dict({
            "grant_id": "grant-1",
            "scope_text": "folder X only",
            "issued_at": 0,
            "expires_at": 10,
            "source_ref": None,
        })
        self.assertEqual(fallback.source_ref, "")
        self.assertNotEqual(fallback.source_ref, "None")

    def test_a_fallback_mapping_defaults_its_reason(self):
        """or@783: the DEFAULTING half of the reason read."""
        fallback = ScopeFallback.from_dict({
            "grant_id": "grant-1",
            "scope_text": "folder X only",
            "issued_at": 0,
            "expires_at": 10,
            "reason": None,
        })
        self.assertEqual(fallback.reason, "")
        self.assertNotEqual(fallback.reason, "None")

    # -- the qualifier diff ---------------------------------------------

    def test_the_scope_tokens_of_a_non_string_are_empty(self):
        """or@870: the TYPE half of the scope-token guard.

        A non-string names no scope tokens, so the answer is the empty
        tuple.  Under the planted fault the guard is skipped and the
        token regex is handed a non-string, which raises a TypeError
        instead of returning "no tokens".
        """
        self.assertEqual(scope_tokens(5), ())
        self.assertEqual(scope_tokens(None), ())
        self.assertEqual(scope_tokens(""), ())

    def test_a_diff_against_a_non_string_compaction_is_not_an_error(self):
        """and@888: the TYPE half of the removal-note guard.

        The guard reads the compacted text's own spelling for the
        removal marker.  When the compacted text is not a string there
        is no spelling to read, so nothing is noted -- and the diff is
        still a diff.  Under the planted fault (``and`` -> ``or``) the
        second half runs on a non-string and raises AttributeError.
        """
        diff = diff_qualifiers("write to folder X only", None)
        self.assertEqual(diff.dropped, ("only",))
        self.assertEqual(diff.noted, ())
        self.assertEqual(diff.lost, ("only",))

    # -- the gate's guards ----------------------------------------------

    def test_the_gate_refuses_a_boolean_fallback_ttl(self):
        """or@927: the BOOL half of the TTL guard.

        ``True`` IS an ``int`` in Python, so without the explicit bool
        half a boolean TTL would be accepted as the TTL 1 -- a one
        second fallback, which expires before it can be used.
        """
        with self.assertRaises(ScopeQualifierError):
            ScopeQualifierGate(SourceStore(), fallback_ttl_seconds=True)

    def test_the_gate_refuses_a_boolean_now(self):
        """or@983: the BOOL half of the clock's int guard."""
        gate = ScopeQualifierGate(SourceStore())
        with self.assertRaises(ScopeQualifierError):
            gate.check(
                GrantRecord(
                    grant_id="grant-1", verb="write",
                    qualifiers=(FOLDER_X,), source_ref="src-1",
                ),
                now=True,
            )

    def test_a_denied_row_without_a_reason_still_names_the_denial(self):
        """or@1054: the DEFAULTING half of the denial reason.

        A denial row may carry no reason of its own; the gate still has
        to say that the scope is refused.  Under the planted fault
        (``or`` -> ``and``) the reason would be silently empty and the
        audit trail would not say what refused the scope.
        """
        store = SourceStore([
            SourceLine(
                source_ref="src-1", grant_id="grant-1", qualifiers=(FOLDER_X,)
            )
        ])
        rows = DenialRowStore([
            DenialRow(scope="grant-1/write", kind=ROW_DENIED)
        ])
        gate = ScopeQualifierGate(store, denial_rows=rows)
        check = gate.check(
            GrantRecord(
                grant_id="grant-1", verb="write",
                qualifiers=(FOLDER_X,), source_ref="src-1",
            ),
            now=0,
        )
        self.assertTrue(check.blocked)
        self.assertIn("denial row", check.reason)

    # -- the presented-grant lookup -------------------------------------

    def test_the_presented_lookup_finds_only_the_asked_verb(self):
        """eq@1328: the equality of the presented-grant lookup.

        The lookup answers "which presented grants authorize this
        verb?".  A grant that authorizes a DIFFERENT verb must not be
        in the answer.  Under the planted fault (``==`` -> ``!=``) the
        lookup would return exactly the grants that do NOT match.
        """
        from scope_qualifier import ScopeGrantRegistry

        registry = ScopeGrantRegistry()
        registry.present(GrantRecord(grant_id="grant-1", verb="write"))
        registry.present(GrantRecord(grant_id="grant-2", verb="read"))
        found = registry.presented_for("write")
        self.assertEqual([g.grant_id for g in found], ["grant-1"])
        self.assertEqual(registry.presented_for("read")[0].grant_id, "grant-2")

    # -- the denial row's guards ----------------------------------------

    def test_a_denial_row_with_a_blank_scope_is_refused(self):
        """or@1396: the EMPTINESS half of the row's scope guard.

        A scope that holds only whitespace names no scope, so the row
        must be refused: the type half cannot see it.
        """
        with self.assertRaises(MalformedGrantError):
            DenialRow(scope="   ", kind=ROW_CLEAR, signature="sig-1")

    def test_the_row_store_refuses_an_empty_scope(self):
        """or@1483: the EMPTINESS half of the row store's fetch guard.

        An empty scope names no row, so it is a *read error*
        (``ScopeSourceError``) and not a clean miss.  Under the planted
        fault the empty scope would be looked up in the map and read as
        "no such row" -- a clean read from a malformed request, and the
        gate would answer ``outcome_unknown`` for the wrong reason.
        """
        store = DenialRowStore()
        with self.assertRaises(ScopeSourceError):
            store.fetch("")

    # -- the compaction boundary ----------------------------------------

    def test_the_boundary_check_refuses_a_mapping_of_grants(self):
        """or@1550: the "not a list/tuple" half of the guard.

        The *message* is asserted, not just the exception type: with
        the connective flipped to ``and`` the mapping slips past the
        guard and is then iterated key by key, and the refusal arrives
        from a different guard with a different message.
        """
        with self.assertRaises(ScopeQualifierError) as caught:
            check_compaction_boundary({"grant-1": object()})
        self.assertIn("grants must be a sequence", str(caught.exception))

    # -- the survival measure -------------------------------------------

    def test_the_grant_survival_rate_is_the_share_that_survived(self):
        """eq@1618: the zero-round guard of ``grant_survival``.

        ``grant_survival`` reports 1.0 when NO round was measured (there
        is nothing to lose).  When a round WAS measured the rate is the
        share that survived.  Under the planted fault (``==`` -> ``!=``)
        the guard would fire on every measured round and report 1.0
        whatever happened -- exactly the "nothing was lost" reading the
        measure exists to disprove.
        """
        metrics = SurvivalMetrics(rounds=1, grants_in=2, grants_out=1)
        self.assertEqual(metrics.grant_survival, 0.5)

    def test_the_qualifier_survival_rate_is_the_share_that_survived(self):
        """eq@1625: the zero-round guard of ``qualifier_survival``."""
        metrics = SurvivalMetrics(rounds=1, qualifiers_in=2, qualifiers_out=1)
        self.assertEqual(metrics.qualifier_survival, 0.5)

    def test_the_widening_rate_is_the_share_that_widened(self):
        """eq@1632: the zero-round guard of ``widening_rate``."""
        metrics = SurvivalMetrics(rounds=1, grants_in=2, widened=1)
        self.assertEqual(metrics.widening_rate, 0.5)

    def test_the_caught_rate_is_the_share_of_the_widenings_caught(self):
        """eq@1639: the zero-widenings guard of ``caught_rate``.

        ``caught_rate`` reports 1.0 when nothing widened (there was
        nothing to catch).  When widenings happened, the rate is the
        share of them the gate caught.  Under the planted fault
        (``==`` -> ``!=``) the guard would fire whenever widenings
        existed and report 1.0 -- claiming every widening was caught
        when some were not.
        """
        metrics = SurvivalMetrics(rounds=1, widened=2, caught=1)
        self.assertEqual(metrics.caught_rate, 0.5)

    def test_the_measure_refuses_a_mapping_of_grants(self):
        """or@1682: the "not a list/tuple" half of the measure's guard.

        The *message* is asserted, not just the exception type: with
        the connective flipped to ``and`` the mapping slips past the
        guard and is then iterated key by key, and the refusal arrives
        from a different guard with a different message.
        """
        with self.assertRaises(ScopeQualifierError) as caught:
            measure_qualifier_survival({"grant-1": object()})
        self.assertIn("grants must be a sequence", str(caught.exception))

    def test_the_measure_refuses_a_boolean_round_count(self):
        """or@1684: the BOOL half of the round-count guard.

        ``True`` IS an ``int`` in Python, so without the explicit bool
        half a boolean round count would be accepted as one round.
        """
        with self.assertRaises(ScopeQualifierError):
            measure_qualifier_survival([], rounds=True)

    def test_the_measure_accepts_a_single_round(self):
        """lt@1684: the bound on the round count is STRICT.

        One round is a legal measurement, so the bound is ``rounds < 1``.
        Under the planted fault (``<`` -> ``<=``) a single round would
        be refused -- the measurement the survival tests exist to make
        could not be run at all.
        """
        metrics = measure_qualifier_survival([], rounds=1)
        self.assertEqual(metrics.rounds, 1)

    def test_the_measure_drops_the_fence_of_every_third_grant(self):
        """eq@1696 and and@1697: the deterministic rewrite.

        The simulation is deliberately deterministic: every third grant
        loses its fence.  With three grants, exactly ONE is rewritten
        and the other two keep their fences.  Under eq@1696
        (``==`` -> ``!=``) two grants would lose their fence; under
        and@1697 (``and`` -> ``or``) every grant would lose its fence,
        because a grant that still has qualifiers would be rewritten
        even when it was not the chosen one.
        """
        grants = [
            GrantRecord(
                grant_id=f"g{index}", verb="write",
                qualifiers=(FOLDER_X,), source_ref=f"s{index}",
            )
            for index in range(3)
        ]
        metrics = measure_qualifier_survival(grants, rounds=1)
        self.assertEqual(metrics.widened, 1, "exactly every third grant widens")
        self.assertEqual(metrics.qualifiers_out, 2, "the other two keep their fence")

    def test_the_measure_counts_only_the_widenings_the_gate_caught(self):
        """and@1714: the caught counter.

        A widening is caught when the gate BLOCKS the rewritten grant.
        The grants that were not rewritten were not blocked, so they
        are not widenings and must not be counted.  Under the planted
        fault (``and`` -> ``or``) every grant the gate answered at all
        would be counted as caught, and the catch rate would read 1.0
        no matter how many widenings went uncaught.
        """
        sources = [
            SourceLine(
                source_ref=f"s{index}", grant_id=f"g{index}",
                qualifiers=(FOLDER_X,),
            )
            for index in range(3)
        ]
        rows = [
            DenialRow(scope=f"g{index}/write", kind=ROW_CLEAR, signature="sig-1")
            for index in range(3)
        ]
        registry = ScopeGrantRegistry(sources=sources, rows=rows)
        grants = [
            GrantRecord(
                grant_id=f"g{index}", verb="write",
                qualifiers=(FOLDER_X,), source_ref=f"s{index}",
            )
            for index in range(3)
        ]
        metrics = measure_qualifier_survival(grants, gate=registry.gate, rounds=1)
        self.assertGreater(metrics.widened, 0)
        self.assertEqual(metrics.caught, metrics.widened, "every widening is caught")
        self.assertEqual(metrics.caught_rate, 1.0)

    # -- the audit event -----------------------------------------------

    def test_the_audit_event_refuses_an_empty_kind(self):
        """or@1744: the EMPTINESS half of the audit kind guard.

        An empty kind is not one of the module's audit kinds, so the
        event must be refused.  Under the planted fault the guard is
        skipped and an event with an unnamed kind is emitted -- a record
        no reader can route.
        """
        check = ScopeCheck(
            grant_id="grant-1", blocked=True, outcome=OUTCOME_MISMATCH
        )
        with self.assertRaises(ScopeQualifierError):
            scope_audit_event("", check)

    def test_the_audit_event_accepts_a_zero_sequence(self):
        """lt@1746: the bound on the audit sequence is STRICT.

        Sequence 0 is the first record of a stream, so it is legal: the
        bound is ``seq < 0``.  Under the planted fault (``<`` -> ``<=``)
        the first record of every stream would be refused.
        """
        check = ScopeCheck(
            grant_id="grant-1", blocked=True, outcome=OUTCOME_MISMATCH
        )
        event = scope_audit_event(KIND_CHECKED, check, seq=0)
        self.assertEqual(event["seq"], 0)

    def test_the_audit_event_refuses_a_boolean_sequence(self):
        """or@1746: the BOOL half of the audit sequence guard.

        ``True`` IS an ``int`` in Python, so without the explicit bool
        half a boolean sequence would be accepted as the sequence 1.
        """
        check = ScopeCheck(
            grant_id="grant-1", blocked=True, outcome=OUTCOME_MISMATCH
        )
        with self.assertRaises(ScopeQualifierError):
            scope_audit_event(KIND_CHECKED, check, seq=True)


class ScopeRelationEquivalenceTests(unittest.TestCase):
    """Two EQUIVALENT mutants in ``scope_relation``, proved rather than
    asserted.

    The scope algebra compares the two fences' *permitted target sets*::

        if presented_targets == source_targets:   # eq@661
            if presented_atoms == source_atoms:   # eq@662
                return SCOPE_EQUAL
            return SCOPE_NARROWER
        if presented_targets < source_targets:    # lt@667
            return SCOPE_NARROWER
        if presented_targets > source_targets:    # gt@669
            return SCOPE_WIDER
        return SCOPE_INCOMPARABLE

    The two comparisons at lt@667 and gt@669 are reached **only** when
    the equality test above them has already failed -- i.e. only when
    the two target sets are DIFFERENT.  For two different sets ``P < S``
    and ``P <= S`` agree (they differ only when ``P == S``), and so do
    ``P > S`` and ``P >= S``.  The planted faults are therefore
    EQUIVALENT mutants: no input can distinguish them.

    Equivalence is not asserted here, it is MEASURED.  The sweep below
    enumerates every subset of a four-element universe -- every pair of
    target sets there is, in that universe -- and compares the two
    spellings of each comparison directly.  The counts are pinned too,
    so a later edit that shrinks the sweep's coverage is visible.
    """

    #: The universe the sweep runs over.
    UNIVERSE = ("a", "b", "c", "d")

    def _all_target_sets(self):
        import itertools

        sets = []
        for size in range(len(self.UNIVERSE) + 1):
            for combo in itertools.combinations(self.UNIVERSE, size):
                sets.append(frozenset(combo))
        return sets

    def test_the_subset_comparison_is_equivalent_to_the_non_strict_one(self):
        """lt@667: the differential sweep that proves the equivalence.

        For every pair of DIFFERENT target sets, the strict subset test
        and the non-strict one must agree.  The count of disagreements
        is zero, so the planted fault cannot change the relation at any
        input.
        """
        sets = self._all_target_sets()
        disagreements = 0
        compared = 0
        for presented in sets:
            for source in sets:
                if presented == source:
                    continue
                compared += 1
                if (presented < source) != (presented <= source):
                    disagreements += 1
        self.assertEqual(disagreements, 0)
        self.assertEqual(compared, len(sets) * (len(sets) - 1))

    def test_the_superset_comparison_is_equivalent_to_the_non_strict_one(self):
        """gt@669: the differential sweep that proves the equivalence."""
        sets = self._all_target_sets()
        disagreements = 0
        compared = 0
        for presented in sets:
            for source in sets:
                if presented == source:
                    continue
                compared += 1
                if (presented > source) != (presented >= source):
                    disagreements += 1
        self.assertEqual(disagreements, 0)
        self.assertEqual(compared, len(sets) * (len(sets) - 1))

    def test_an_equal_target_set_is_decided_above_the_subset_comparison(self):
        """lt@667 and gt@669: the reason the sweep's precondition holds.

        The equality test at eq@661 comes FIRST, so an equal pair of
        target sets never reaches the subset or superset comparison at
        all.  That ordering is what makes the two planted faults
        equivalent, and it is pinned here so that reordering the
        algebra would be visible.
        """
        self.assertEqual(scope_relation((FOLDER_X,), (FOLDER_X,)), "equal")
        # The same permitted targets under a different qualifier: still
        # decided above the comparison.
        self.assertEqual(
            scope_relation((ScopeQualifier("per", "folder X"),), (FOLDER_X,)),
            "narrower",
        )

    def test_a_strict_subset_is_narrower_and_a_strict_superset_is_wider(self):
        """lt@667 and gt@669: the behaviour the two comparisons decide.

        A proper subset of the source's permitted targets is narrower;
        a proper superset is wider.  These are the two branches the
        equivalent mutants would have to change, and they do not.
        """
        self.assertEqual(
            scope_relation((FOLDER_X,), (FOLDER_X, FOLDER_Y)), "narrower"
        )
        self.assertEqual(
            scope_relation((FOLDER_X, FOLDER_Y), (FOLDER_X,)), "wider"
        )

if __name__ == "__main__":  # pragma: no cover
    unittest.main()


class ScopeRelationEquivalenceHarnessControlTests(unittest.TestCase):
    """The ``lt@667`` / ``gt@669`` equivalence proof must be able to FAIL.

    ``ScopeRelationEquivalenceTests`` proves that the two planted faults
    in ``scope_relation`` change nothing: the strict and non-strict
    comparisons are reached only when the two target sets are already
    known to be DIFFERENT, and for two different sets the strict and
    non-strict spellings agree.

    A differential test that CANNOT fail proves nothing.  The sweep
    above SKIPS the equal pairs on purpose -- that skip is exactly the
    precondition the argument rests on, and it is also the place a
    difference would hide if the precondition ever stopped holding.

    This class gives the proof its **non-vacuity control**: the very
    same comparison, run over the pairs the sweep SKIPS, must find a
    difference.  A difference there is what licenses the "no difference
    over the different pairs" conclusion the sweep draws -- and it is
    also what shows the sweep is not skipping everything.

    A second control pins that the sweep is not vacuous in the other
    direction: it must actually COMPARE a substantial number of pairs,
    not zero.
    """

    #: The universe the sweep runs over.
    UNIVERSE = ("a", "b", "c", "d")

    def _all_target_sets(self):
        import itertools

        sets = []
        for size in range(len(self.UNIVERSE) + 1):
            for combo in itertools.combinations(self.UNIVERSE, size):
                sets.append(frozenset(combo))
        return sets

    def test_the_same_comparison_finds_a_difference_on_the_skipped_pairs(self):
        """The SAME comparison, over the SKIPPED pairs, must disagree.

        The equal pairs are the ones the sweep skips.  If the strict and
        non-strict spellings agreed even there, the sweep would be
        skipping for no reason and its "no difference" result would say
        nothing.
        """
        sets = self._all_target_sets()
        differences = 0
        compared = 0
        for presented in sets:
            for source in sets:
                if presented != source:
                    continue
                compared += 1
                if (presented < source) != (presented <= source):
                    differences += 1
        self.assertGreater(compared, 0)
        self.assertGreater(
            differences,
            0,
            "the strict and non-strict comparisons agree even on the "
            "equal pairs, so the sweep's skip is not doing the work the "
            "equivalence argument claims",
        )

    def test_the_sweep_compares_a_substantial_number_of_pairs(self):
        """The sweep must actually COMPARE pairs, not zero of them.

        The other way a differential sweep goes vacuous: it compares
        nothing at all and reports zero disagreements.
        """
        sets = self._all_target_sets()
        compared = 0
        for presented in sets:
            for source in sets:
                if presented == source:
                    continue
                compared += 1
        self.assertEqual(compared, len(sets) * (len(sets) - 1))
        self.assertGreater(compared, 100)


class ScopeQualifierStdlibGuardTests(unittest.TestCase):
    """The stdlib guard's OWN branches must be reachable.

    ``stdlib_only()`` used to read only its own module's source, which is
    clean by construction: every import in it is in the allowed set, so
    the guard's two ``return False`` branches were UNREACHABLE from any
    test.  A guard whose branches cannot be reached cannot be told apart
    from a guard that always says "yes", so a planted fault in it
    (``return False`` -> ``return True``) survived every test.

    The guard now takes the source to check, defaulting to its own --
    the same shape ``deny_hotpath.stdlib_only`` already uses.  Crafted
    sources make each branch reachable.
    """

    def test_a_foreign_import_is_refused(self):
        """retF@1775: the ``ast.Import`` branch.

        A plain ``import numpy`` names a package that is not stdlib, so
        the guard must refuse it.
        """
        self.assertFalse(stdlib_only("import numpy\n"))

    def test_a_dotted_foreign_package_is_refused(self):
        """retF@1775: the dotted spelling of the same branch.

        ``import numpy.linalg`` names ``numpy`` as its root, and the root
        is what decides.
        """
        self.assertFalse(stdlib_only("import numpy.linalg\n"))

    def test_an_allowed_import_is_accepted(self):
        """retF@1775: the CONTROL -- the branch is not always taken.

        Without this, the guard could be "always refuse" and the test
        above would still pass.
        """
        self.assertTrue(stdlib_only("import json\n"))

    def test_a_foreign_from_import_is_refused(self):
        """retF@1778: the ``ast.ImportFrom`` branch.

        ``from numpy import array`` names a non-stdlib module.
        """
        self.assertFalse(stdlib_only("from numpy import array\n"))

    def test_an_allowed_from_import_is_accepted(self):
        """retF@1778: the CONTROL for the from-import branch."""
        self.assertTrue(stdlib_only("from typing import Optional\n"))

    def test_a_relative_import_is_refused(self):
        """retF@1778: the relative-import shape.

        ``from . import sibling`` parses with ``module=None``, so the
        guard's "not in allowed" test never runs on it and the import
        would pass.  A relative import reaches outside the stdlib exactly
        as a foreign one does, so the guard must refuse it.
        """
        self.assertFalse(stdlib_only("from . import sibling\n"))

    def test_the_module_itself_is_stdlib_only(self):
        """The default argument still checks THIS module."""
        self.assertTrue(stdlib_only())

    def test_a_source_with_no_imports_at_all_is_accepted(self):
        """A module with no imports imports nothing, so nothing is foreign."""
        self.assertTrue(stdlib_only("x = 1\n"))


class ScopeQualifierSelfCheckTests(unittest.TestCase):
    """The module's own ``main()`` self-check is part of the contract.

    The census found four survivors inside ``main()``: no test ran it, so
    a weakened assertion inside it survived.  Running ``main()`` is not
    enough either -- it only proves the self-check does not raise, and a
    weakened assertion (``and`` -> ``or``) does not raise.  So the
    self-check is executed here, AND its claims are re-derived from
    outside it.
    """

    def _gate(self):
        store = SourceStore(
            [
                SourceLine(
                    source_ref="src-1",
                    grant_id="grant-1",
                    qualifiers=(ScopeQualifier("only", "folder X"),),
                )
            ]
        )
        rows = DenialRowStore(
            [DenialRow(scope="grant-1/write", kind=ROW_CLEAR, signature="sig-1")]
        )
        return ScopeQualifierGate(store, denial_rows=rows)

    def test_the_module_self_check_runs(self):
        import scope_qualifier

        scope_qualifier.main()

    def test_the_module_self_check_prints_its_verdict(self):
        import contextlib
        import io

        import scope_qualifier

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            scope_qualifier.main()
        self.assertIn("scope-qualifier OK", buffer.getvalue())

    def test_the_self_check_entry_point_is_the_main_guard(self):
        """eq@1819: the ``__name__ == "__main__"`` guard.

        The entry point is the module's own self-check, and it is
        reachable: running the module as a script runs the self-check.
        The guard is asserted by RUNNING the module as a script, which is
        the only thing that can distinguish ``==`` from ``!=``.
        """
        import subprocess
        import sys

        result = subprocess.run(
            [sys.executable, "-m", "scope_qualifier"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("scope-qualifier OK", result.stdout)

    def test_the_self_check_claims_a_matching_grant_passes(self):
        """eq@1805: the MATCH claim, re-derived from outside.

        The self-check asserts ``check.outcome == OUTCOME_MATCH`` and
        ``not check.blocked``.  A mutation of that assertion
        (``==`` -> ``!=``) would make the self-check assert the
        opposite and still not raise, so the claim is re-derived here.
        """
        gate = self._gate()
        check = gate.check(grant(qualifiers=(FOLDER_X,)), now=100)
        self.assertEqual(check.outcome, OUTCOME_MATCH)
        self.assertFalse(check.blocked)

    def test_the_self_check_claims_a_dropped_fence_blocks(self):
        """eq@1810: the DROPPED-FENCE claim, re-derived from outside."""
        gate = self._gate()
        check = gate.check(grant(qualifiers=()), now=100)
        self.assertTrue(check.blocked)
        self.assertEqual(check.outcome, OUTCOME_MISMATCH)

    def test_the_self_check_claims_the_module_is_stdlib_only(self):
        """The self-check's own stdlib claim, re-derived."""
        self.assertTrue(stdlib_only())
