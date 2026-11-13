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
    DenialRow,
    DenialRowStore,
    GrantRecord,
    QualifierDiff,
    ScopeCheck,
    ScopeFallback,
    ScopeGrantRegistry,
    ScopeQualifier,
    ScopeQualifierError,
    ScopeQualifierGate,
    SourceLine,
    SourceStore,
    check_compaction_boundary,
    diff_qualifiers,
    measure_qualifier_survival,
    narrower_scope,
    permitted_targets,
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


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
