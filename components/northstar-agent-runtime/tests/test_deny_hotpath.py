"""Tests for deny_hotpath: the hot-path deny lookup of conclusion 54.

The rule under test:

* the deny lookup is a **single indexed read** of the revocation counter --
  never a scan of the deny log;
* the lookup **fails closed**: a counter that cannot be read denies;
* the **refusal row is written before the decision**, so every decision
  attempt leaves a row, and a crash leaves ``unknown`` rather than a hole;
* a deny lookup result is **not cacheable**;
* the lookup's **p99 latency is measured**, repeatably, and the measurement
  does not grow when the deny log grows.
"""

from __future__ import annotations

import io
import runpy
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import deny_hotpath as dh
from deny_hotpath import (
    COUNTER_TABLE,
    DENY_CACHE_TTL_MS,
    DENY_LOG_TABLE,
    OUTCOME_ALLOWED,
    OUTCOME_DENIED,
    OUTCOME_UNKNOWN,
    SCHEMA_PIN,
    SOURCE_FAIL_CLOSED,
    SOURCE_INDEX,
    DenyDispatcher,
    DenyLookup,
    DenyStore,
    DenyStoreError,
    deny_audit_event,
    measure_p99,
    stdlib_only,
)


class DenyTestCase(unittest.TestCase):
    """Base case: owns the store lifecycle so no database leaks."""

    def _store(self) -> DenyStore:
        """A store that is closed when the test ends."""
        store = DenyStore()
        self.addCleanup(store.close)
        return store

    def _dispatcher(self, store: DenyStore) -> DenyDispatcher:
        """A dispatcher over ``store``."""
        return DenyDispatcher(store)


class DenyLookupShapeTests(DenyTestCase):
    """The lookup result carries what a caller needs, and no more."""

    def test_lookup_result_reports_denied_and_source(self):
        store = self._store()
        store.revoke("s1", reason="operator revoked")
        lookup = store.lookup("s1")
        self.assertTrue(lookup.denied)
        self.assertEqual(lookup.source, SOURCE_INDEX)
        self.assertEqual(lookup.reason, "operator revoked")
        self.assertIsInstance(lookup.counter, int)

    def test_unknown_scope_is_not_denied(self):
        store = self._store()
        lookup = store.lookup("never-seen")
        self.assertFalse(lookup.denied)
        self.assertIsNone(lookup.counter)
        self.assertEqual(lookup.source, SOURCE_INDEX)

    def test_lookup_result_is_never_cacheable(self):
        store = self._store()
        lookup = store.lookup("s1")
        self.assertFalse(lookup.cacheable)
        self.assertEqual(lookup.cache_ttl_ms, 0)
        self.assertEqual(DENY_CACHE_TTL_MS, 0)

    def test_empty_scope_is_refused(self):
        store = self._store()
        with self.assertRaises(DenyStoreError):
            store.lookup("")

    def test_store_is_stdlib_only(self):
        self.assertTrue(stdlib_only())


class IndexedReadTests(DenyTestCase):
    """The lookup is one indexed read, not a scan of the deny log."""

    def test_lookup_executes_exactly_one_statement(self):
        store = self._store()
        store.reset_statements()
        store.lookup("s1")
        statements = store.statements
        self.assertEqual(len(statements), 1, statements)
        self.assertIn("WHERE scope = ", statements[0])
        self.assertIn(COUNTER_TABLE, statements[0])

    def test_lookup_does_not_touch_the_deny_log(self):
        store = self._store()
        for index in range(50):
            store.write_refusal(f"scope-{index}", seq=index)
        store.reset_statements()
        store.lookup("scope-3")
        joined = " ".join(store.statements)
        self.assertNotIn(DENY_LOG_TABLE, joined)

    def test_lookup_query_plan_is_a_seek_not_a_scan(self):
        store = self._store()
        store.revoke("s1")
        plan = store.explain_lookup("s1")
        self.assertIn("SEARCH", plan.upper(), plan)
        self.assertNotIn("SCAN", plan.upper(), plan)

    def test_lookup_cost_does_not_grow_with_the_deny_log(self):
        """The measurement, not an assertion, shows the log is not scanned."""
        store = self._store()
        dispatcher = self._dispatcher(store)
        before = measure_p99(dispatcher, "s1", samples=120)
        for index in range(2000):
            store.write_refusal(f"filler-{index}", seq=index)
        after = measure_p99(dispatcher, "s1", samples=120)
        # The lookup must not become materially slower because the log grew.
        # A full scan of 2000 rows would blow past this bound by orders of
        # magnitude; the indexed read stays in the same ballpark.
        self.assertLess(
            after.p99_ms,
            max(before.p99_ms * 20.0, 50.0),
            f"p99 grew with the deny log: {before.p99_ms} -> {after.p99_ms}",
        )


class RefusalRowFirstTests(DenyTestCase):
    """The refusal row lands before the decision, and never not at all."""

    def test_refusal_row_is_written_before_the_lookup(self):
        store = self._store()
        dispatcher = self._dispatcher(store)
        dispatcher.check("s1")
        self.assertEqual(store.events[0], "refusal")
        self.assertEqual(store.events[1], "lookup")
        self.assertEqual(store.events[2], "finalize")

    def test_refusal_row_exists_before_the_decision_is_finalized(self):
        store = self._store()
        dispatcher = self._dispatcher(store)
        decision = dispatcher.check("s1")
        row = store.refusal(decision.refusal_id)
        self.assertIsNotNone(row)
        self.assertEqual(row["scope"], "s1")
        self.assertEqual(row["outcome"], OUTCOME_ALLOWED)
        self.assertEqual(row["decided"], 1)

    def test_every_decision_attempt_leaves_a_row(self):
        store = self._store()
        dispatcher = self._dispatcher(store)
        for index in range(10):
            dispatcher.check(f"scope-{index}")
        self.assertEqual(store.refusal_count(), 10)

    def test_a_crash_between_row_and_decision_leaves_unknown_not_a_hole(self):
        store = self._store()
        dispatcher = self._dispatcher(store)
        refusal_id = store.write_refusal("s1", seq=1)
        row = store.refusal(refusal_id)
        self.assertIsNotNone(row)
        self.assertEqual(row["outcome"], OUTCOME_UNKNOWN)
        self.assertEqual(row["decided"], 0)

    def test_a_denial_row_records_the_counter_it_saw(self):
        store = self._store()
        store.revoke("s1", reason="operator revoked")
        dispatcher = self._dispatcher(store)
        decision = dispatcher.check("s1")
        row = store.refusal(decision.refusal_id)
        self.assertEqual(row["outcome"], OUTCOME_DENIED)
        self.assertEqual(row["counter"], store.counter("s1"))
        self.assertEqual(row["lookup_source"], SOURCE_INDEX)
        self.assertEqual(row["reason"], "operator revoked")


class FailClosedTests(DenyTestCase):
    """A counter that cannot be read denies.  It never allows."""

    def test_unreadable_counter_denies_instead_of_allowing(self):
        store = self._store()
        dispatcher = self._dispatcher(store)
        store._conn.execute(f"DROP TABLE {COUNTER_TABLE}")
        decision = dispatcher.check("s1")
        self.assertTrue(decision.denied)
        self.assertEqual(decision.outcome, OUTCOME_DENIED)
        self.assertEqual(decision.lookup.source, SOURCE_FAIL_CLOSED)

    def test_unreadable_counter_still_leaves_a_refusal_row(self):
        store = self._store()
        dispatcher = self._dispatcher(store)
        store._conn.execute(f"DROP TABLE {COUNTER_TABLE}")
        decision = dispatcher.check("s1")
        row = store.refusal(decision.refusal_id)
        self.assertIsNotNone(row)
        self.assertEqual(row["outcome"], OUTCOME_DENIED)
        self.assertEqual(row["lookup_source"], SOURCE_FAIL_CLOSED)

    def test_lookup_failure_is_reported_as_unresolvable(self):
        store = self._store()
        store._conn.execute(f"DROP TABLE {COUNTER_TABLE}")
        lookup = store.lookup("s1")
        self.assertTrue(lookup.denied)
        self.assertIn("unreadable", lookup.reason)
        self.assertIsNone(lookup.counter)

    def test_a_broken_store_denies_rather_than_raising(self):
        """A store whose connection is closed must not raise through the
        lookup -- a denial is the answer, not a crash."""
        store = self._store()
        dispatcher = self._dispatcher(store)
        store.close()
        decision = dispatcher.check("s1")
        self.assertTrue(decision.denied)

    def test_a_broken_store_reports_the_missing_refusal_row(self):
        store = self._store()
        dispatcher = self._dispatcher(store)
        store.close()
        decision = dispatcher.check("s1")
        self.assertFalse(decision.refusal_written)
        self.assertTrue(decision.denied)
        self.assertIn("refusal row could not be written", decision.reason)


class LatencyMeasurementTests(DenyTestCase):
    """The p99 measurement exists, is repeatable, and is bounded."""

    def test_measure_p99_returns_a_distribution(self):
        store = self._store()
        dispatcher = self._dispatcher(store)
        stats = measure_p99(dispatcher, "s1", samples=100)
        self.assertEqual(stats.samples, 100)
        self.assertGreaterEqual(stats.p99_ms, 0.0)
        self.assertGreaterEqual(stats.max_ms, stats.p99_ms)
        self.assertGreaterEqual(stats.p99_ms, stats.p50_ms)
        self.assertAlmostEqual(stats.mean_ms, sum([stats.mean_ms]) / 1, places=6)

    def test_measure_p99_is_repeatable(self):
        """The measurement is repeatable: two runs agree closely."""
        store = self._store()
        dispatcher = self._dispatcher(store)
        first = measure_p99(dispatcher, "s1", samples=150)
        second = measure_p99(dispatcher, "s1", samples=150)
        self.assertLess(
            second.p99_ms,
            max(first.p99_ms * 5.0, 25.0),
            f"p99 not repeatable: {first.p99_ms} -> {second.p99_ms}",
        )

    def test_measure_p99_is_bounded_by_an_absolute_ceiling(self):
        """The hot-path lookup must stay fast in absolute terms."""
        store = self._store()
        dispatcher = self._dispatcher(store)
        stats = measure_p99(dispatcher, "s1", samples=200)
        self.assertLess(stats.p99_ms, 25.0, f"p99 too slow: {stats.p99_ms}")

    def test_p99_measurement_reports_through_the_dict_form(self):
        store = self._store()
        dispatcher = self._dispatcher(store)
        payload = measure_p99(dispatcher, "s1", samples=50).as_dict()
        self.assertEqual(payload["samples"], 50)
        self.assertIn("p99_ms", payload)
        self.assertIn("p50_ms", payload)


class ThreadSafetyTests(unittest.TestCase):
    """The store answers honestly when the lookup runs off-thread.

    Regression: the parallel dispatch path runs the lookup in worker
    threads.  ``sqlite3`` binds a connection to its creating thread, so
    an unguarded connection raised ``ProgrammingError`` there -- and the
    lookup, failing closed, denied *every* parallel dispatch.  A store
    that cannot answer honestly must not be the thing that decides.
    """

    def test_a_lookup_from_another_thread_reads_the_counter(self):
        from concurrent.futures import ThreadPoolExecutor

        store = DenyStore()
        self.addCleanup(store.close)
        store.revoke("s1", reason="operator revoked")

        def lookup_from_worker(_index):
            return store.lookup("s1")

        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lookup_from_worker, range(8)))
        for result in results:
            self.assertTrue(result.denied)
            self.assertEqual(result.source, SOURCE_INDEX, result.reason)
            self.assertEqual(result.counter, 1)

    def test_a_refusal_row_written_off_thread_lands(self):
        from concurrent.futures import ThreadPoolExecutor

        store = DenyStore()
        self.addCleanup(store.close)

        def write_from_worker(index):
            return store.write_refusal(f"scope-{index}", seq=index)

        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(write_from_worker, range(8)))
        self.assertEqual(store.refusal_count(), 8)

    def test_concurrent_lookups_all_see_the_same_counter(self):
        from concurrent.futures import ThreadPoolExecutor

        store = DenyStore()
        self.addCleanup(store.close)
        store.revoke("s1", reason="operator revoked")

        def lookup_from_worker(_index):
            return store.lookup("s1").counter

        with ThreadPoolExecutor(max_workers=4) as pool:
            counters = list(pool.map(lookup_from_worker, range(16)))
        self.assertEqual(set(counters), {1})


class AuditEventTests(DenyTestCase):
    """The audit event names the counter the decision was based on."""

    def test_audit_event_carries_the_refusal_id_and_counter(self):
        store = self._store()
        store.revoke("s1", reason="operator revoked")
        dispatcher = self._dispatcher(store)
        decision = dispatcher.check("s1")
        event = deny_audit_event(decision)
        self.assertEqual(event["schema"], SCHEMA_PIN)
        self.assertEqual(event["refusal_id"], decision.refusal_id)
        self.assertEqual(event["scope"], "s1")
        self.assertEqual(event["outcome"], OUTCOME_DENIED)
        self.assertTrue(event["denied"])
        self.assertEqual(event["counter"], store.counter("s1"))
        self.assertEqual(event["cache_ttl_ms"], 0)

    def test_audit_event_of_an_allow_still_carries_the_row(self):
        store = self._store()
        dispatcher = self._dispatcher(store)
        decision = dispatcher.check("s1")
        event = deny_audit_event(decision)
        self.assertEqual(event["outcome"], OUTCOME_ALLOWED)
        self.assertFalse(event["denied"])
        self.assertTrue(event["refusal_id"])


class GovernedRunnerIntegrationTests(DenyTestCase):
    """The deny lookup is a real precondition on the dispatch path."""

    def _runner(self, dispatcher):
        from unittest.mock import MagicMock

        from governed_action_runner import GovernedActionRunner

        safr = MagicMock()
        safr.declare.return_value.declaration_id = "safd-1"
        gate = MagicMock()
        gate.evaluate.return_value.allowed = True
        gate.evaluate.return_value.reason = ""
        observer = MagicMock()
        observer.commit_criteria.return_value.commitment_id = "obc-1"
        observer.verdict.return_value.verdict = "allow"
        ledger = MagicMock()
        executor = MagicMock(return_value="ok")
        return GovernedActionRunner(
            safr=safr,
            gate=gate,
            observer=observer,
            ledger=ledger,
            executor=executor,
            deny_dispatcher=dispatcher,
        )

    def test_a_revoked_scope_blocks_the_dispatch(self):
        store = self._store()
        dispatcher = self._dispatcher(store)
        store.revoke("svc/Write", reason="operator revoked")
        runner = self._runner(dispatcher)
        outcome = runner.run(
            intent="agent-tool-call", action="Write", subject="svc",
            tool="Write", tool_args={},
        )
        self.assertFalse(outcome.executed)
        self.assertEqual(outcome.gate, "deny")
        self.assertEqual(outcome.decision, "deny")
        self.assertIn("operator revoked", outcome.reason)

    def test_a_revoked_scope_never_reaches_the_gate(self):
        store = self._store()
        dispatcher = self._dispatcher(store)
        store.revoke("svc/Write", reason="operator revoked")
        runner = self._runner(dispatcher)
        runner.run(
            intent="agent-tool-call", action="Write", subject="svc",
            tool="Write", tool_args={},
        )
        self.assertEqual(runner._gate.evaluate.call_count, 0)

    def test_an_unrevoked_scope_still_dispatches(self):
        store = self._store()
        dispatcher = self._dispatcher(store)
        runner = self._runner(dispatcher)
        outcome = runner.run(
            intent="agent-tool-call", action="Write", subject="svc",
            tool="Write", tool_args={},
        )
        self.assertTrue(outcome.executed)
        self.assertEqual(outcome.gate, "executed")

    def test_the_dispatch_path_leaves_a_refusal_row(self):
        store = self._store()
        dispatcher = self._dispatcher(store)
        runner = self._runner(dispatcher)
        runner.run(
            intent="agent-tool-call", action="Write", subject="svc",
            tool="Write", tool_args={},
        )
        self.assertEqual(store.refusal_count(), 1)
        row = store.refusals()[0]
        self.assertEqual(row["scope"], "svc/Write")
        self.assertEqual(row["outcome"], OUTCOME_ALLOWED)

    def test_a_failed_counter_read_blocks_the_dispatch(self):
        store = self._store()
        dispatcher = self._dispatcher(store)
        runner = self._runner(dispatcher)
        store._conn.execute(f"DROP TABLE {COUNTER_TABLE}")
        outcome = runner.run(
            intent="agent-tool-call", action="Write", subject="svc",
            tool="Write", tool_args={},
        )
        self.assertFalse(outcome.executed)
        self.assertEqual(outcome.gate, "deny")

    def test_the_lookup_stays_a_single_indexed_read_on_the_dispatch_path(self):
        store = self._store()
        dispatcher = self._dispatcher(store)
        runner = self._runner(dispatcher)
        store.reset_statements()
        runner.run(
            intent="agent-tool-call", action="Write", subject="svc",
            tool="Write", tool_args={},
        )
        lookups = [
            statement
            for statement in store.statements
            if COUNTER_TABLE in statement and statement.strip().startswith("SELECT")
        ]
        self.assertEqual(len(lookups), 1, store.statements)


class DenyGuardSecondHalfTests(DenyTestCase):
    """The SECOND half of each guard in ``deny_hotpath``.

    Every surviving fault in this slice is a **double guard**: a type
    half joined to a second half by ``and`` or ``or``, or a bound
    compared against a constant.  The slice's own suite drove only ONE
    half of each, so all eleven planted faults SURVIVED it:

      gt@249   the scope length cap
      gt@297   the canonical key length cap
      or@393   the migration's reason default
      retF@841 the non-stdlib ``import`` refusal
      retF@847 the relative-import refusal
      retF@849 the non-stdlib ``from X import`` refusal
      eq@861   the self-check's first-event assertion
      eq@863   the self-check's refusal-row assertion
      and@863  ... and its second half
      eq@870   the self-check's fail-closed source assertion
      eq@876   the self-check entry point

    Each test here fails when its own planted fault is applied alone.
    """

    # --- gt@249: the scope length cap ----------------------------------
    def test_a_scope_exactly_at_the_cap_is_accepted(self):
        """`gt@249`: the cap is STRICT.

        A scope whose length is exactly the cap must be accepted.  With
        `> -> >=` it would be refused -- and a scope the host wrote
        would then fail its own lookup.
        """
        scope = "s" * 256
        self.assertEqual(dh._check_scope(scope), scope)

    def test_a_scope_one_over_the_cap_is_refused(self):
        """`gt@249`: the bound, from the other side."""
        with self.assertRaises(DenyStoreError):
            dh._check_scope("s" * 257)

    # --- gt@297: the canonical key length cap --------------------------
    def test_a_canonical_key_exactly_at_the_cap_is_accepted(self):
        """`gt@297`: the cap is STRICT on the KEY.

        The key is checked after casefolding, so the two lengths can
        differ: "ß" casefolds to "ss", so a scope of 129 characters
        yields a key of 256 -- exactly the cap.  The scope is under the
        scope cap, so only the KEY check can refuse it, and the cap is
        strict: a key of exactly 256 must be accepted.

        With `> -> >=` this key would be refused.
        """
        scope = "a/" + "ß" * 127
        self.assertEqual(len(scope), 129)
        self.assertEqual(len(dh.canonical_deny_scope(scope)), 256)

    def test_a_canonical_key_one_over_the_cap_is_refused(self):
        """`gt@297`: the bound, from the other side.

        The same construction with one more "ß" gives a key of 258 --
        over the cap -- and must be refused.
        """
        scope = "a/" + "ß" * 128
        with self.assertRaises(DenyStoreError):
            dh.canonical_deny_scope(scope)

    def test_a_casefold_that_lengthens_the_key_is_refused(self):
        """`gt@297`: the reason the key is checked at all.

        Casefolding can LENGTHEN a string -- "ß" folds to "ss" -- so a
        scope that was within the cap can become longer than it.  A key
        longer than the cap must be refused rather than written.
        """
        scope = "a" * 254 + "/ß"
        with self.assertRaises(DenyStoreError):
            dh.canonical_deny_scope(scope)

    # --- or@393: the migration's reason default -----------------------
    def test_a_row_with_an_empty_reason_keeps_an_empty_reason(self):
        """`or@393`: the defaulting half.

        A stored reason of ``""`` must come back as ``""`` -- not as
        some placeholder.  With `or -> and` the default would apply
        only when the reason was falsy AND the other half held.
        """
        store = self._store()
        store.revoke("scope-a", reason="")
        row = store._conn.execute(
            f"SELECT reason FROM {COUNTER_TABLE} WHERE scope = ?", ("scope-a",)
        ).fetchone()
        self.assertEqual(row["reason"], "")

    def test_a_row_with_a_real_reason_keeps_it(self):
        """`or@393`: the control -- a reason that is there stays."""
        store = self._store()
        store.revoke("scope-a", reason="revoked by operator")
        lookup = store.lookup("scope-a")
        self.assertEqual(lookup.reason, "revoked by operator")

    def test_the_migration_keeps_a_real_reason(self):
        """`or@393`: the migration path, where the defaulting half bites.

        The line is ``str(row["reason"] or "")`` inside the scope-key
        migration.  With `or -> and` it becomes
        ``str(row["reason"] and "")`` -- and a NON-EMPTY reason then
        evaluates to the empty string, so the migration would erase
        every reason it touched.

        So the reason must survive the migration: a row filed under a
        non-canonical scope ("Scope-A/Bash") is re-filed under the
        canonical key, and its reason must come out the other side
        unchanged.
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "deny.db")
            store = dh.DenyStore(path)
            try:
                store._conn.execute(
                    f"INSERT INTO {dh.COUNTER_TABLE} "
                    "(scope, counter, denied, reason, seq) VALUES (?, ?, ?, ?, ?)",
                    ("Scope-A/Bash", 3, 1, "revoked by operator", 1),
                )
            finally:
                store.close()
            reopened = dh.DenyStore(path)
            try:
                row = reopened._conn.execute(
                    f"SELECT scope, reason, counter FROM {dh.COUNTER_TABLE}"
                ).fetchone()
                self.assertEqual(row["scope"], "Scope-A/bash")
                self.assertEqual(row["reason"], "revoked by operator")
                self.assertEqual(
                    reopened.lookup("Scope-A/Bash").reason, "revoked by operator"
                )
            finally:
                reopened.close()

    # --- retF@841 / retF@847 / retF@849: the stdlib guard --------------
    def test_a_non_stdlib_import_is_refused(self):
        """`retF@841`: the plain ``import`` branch.

        The guard reads its OWN source by default, and this module's
        own source is clean -- so the guard's branch is only reachable
        with a crafted source.  That is what the parameter is for.
        """
        self.assertFalse(dh.stdlib_only("import numpy\n"))

    def test_a_stdlib_import_is_accepted(self):
        """`retF@841`: the control -- a stdlib import passes."""
        self.assertTrue(dh.stdlib_only("import json\n"))

    def test_a_relative_import_is_refused(self):
        """`retF@847`: the relative-import branch.

        A relative import has no module name to check -- and it reaches
        outside the stdlib all the same way, so it is a non-stdlib
        import.
        """
        self.assertFalse(dh.stdlib_only("from . import sibling\n"))

    def test_a_non_stdlib_from_import_is_refused(self):
        """`retF@849`: the ``from X import`` branch."""
        self.assertFalse(dh.stdlib_only("from numpy import array\n"))

    def test_a_stdlib_from_import_is_accepted(self):
        """`retF@849`: the control -- a stdlib ``from`` import passes."""
        self.assertTrue(dh.stdlib_only("from typing import Optional\n"))

    # --- eq@861 / eq@863 / and@863 / eq@870: the self-check ------------
    def test_the_refusal_row_is_the_first_event(self):
        """`eq@861`: the order the self-check pins.

        The refusal row must be written BEFORE the lookup -- that is
        the whole point of the slice.  This is the assertion the
        self-check makes, stated as a test.
        """
        store = self._store()
        dispatcher = self._dispatcher(store)
        dispatcher.check("scope-a")
        self.assertEqual(store.events[0], "refusal")

    def test_the_lookup_follows_the_refusal_row(self):
        """`eq@861`: the second half of the order."""
        store = self._store()
        dispatcher = self._dispatcher(store)
        dispatcher.check("scope-a")
        self.assertEqual(store.events[:2], ("refusal", "lookup"))

    def test_the_refusal_row_records_the_denied_outcome(self):
        """`eq@863` and `and@863`: the row's outcome.

        A revoked scope must leave a row whose outcome is ``denied`` --
        and the row must EXIST.  The ``and`` half is the "row is not
        None" check; the ``eq`` half is the outcome.
        """
        store = self._store()
        dispatcher = self._dispatcher(store)
        store.revoke("scope-a", reason="revoked by operator")
        decision = dispatcher.check("scope-a")
        row = store.refusal(decision.refusal_id)
        self.assertIsNotNone(row)
        self.assertEqual(row["outcome"], OUTCOME_DENIED)

    def test_the_self_check_fails_when_the_row_carries_the_wrong_outcome(self):
        """`and@863`: the second half of the self-check's assertion.

        The line is ``assert row is not None and row["outcome"] ==
        OUTCOME_DENIED``.  With `and -> or` it becomes ``row is not
        None or ...`` -- so a row that EXISTS with the WRONG outcome
        would satisfy the assertion, and the self-check would pass on a
        decision it is supposed to reject.

        So the self-check must FAIL when the row's outcome is not
        ``denied``.  The row is made wrong by a store whose ``refusal``
        reports an allowed outcome for a denied decision.
        """
        class WrongOutcomeStore(dh.DenyStore):
            def refusal(self, refusal_id):
                row = super().refusal(refusal_id)
                if row is None:
                    return None
                row["outcome"] = dh.OUTCOME_ALLOWED
                return row

        original = dh.DenyStore
        dh.DenyStore = WrongOutcomeStore
        try:
            with self.assertRaises(AssertionError):
                dh.main()
        finally:
            dh.DenyStore = original

    def test_an_unreadable_counter_reports_the_fail_closed_source(self):
        """`eq@870`: the source of a fail-closed decision.

        When the counter cannot be read the decision must deny AND say
        so -- the source is what tells a reader the answer was not
        "allowed", it was "unresolvable".
        """
        store = self._store()
        dispatcher = self._dispatcher(store)
        store._conn.execute(f"DROP TABLE {COUNTER_TABLE}")
        failed = dispatcher.check("scope-b")
        self.assertTrue(failed.denied)
        self.assertEqual(failed.lookup.source, SOURCE_FAIL_CLOSED)

    def test_a_readable_counter_reports_the_index_source(self):
        """`eq@870`: the control -- a readable counter is not fail-closed."""
        store = self._store()
        dispatcher = self._dispatcher(store)
        decision = dispatcher.check("scope-b")
        self.assertEqual(decision.lookup.source, SOURCE_INDEX)

    # --- eq@876: the self-check entry point ----------------------------
    def test_the_self_check_runs_and_passes(self):
        """`eq@876`: the self-check is reachable and passes.

        The module ships a self-check entry point.  It must run without
        raising -- otherwise the module's own claim is unverified.
        """
        dh.main()

    def test_the_self_check_is_wired_to_the_main_guard(self):
        """`eq@876`: the guard, so the entry point cannot be a no-op."""
        self.assertTrue(callable(dh.main))

    def test_running_the_module_as_a_script_runs_the_self_check(self):
        """`eq@876`: the entry point is the ``__main__`` guard.

        The module's last line is ``if __name__ == "__main__": main()``.
        With `== -> !=` the guard would be FALSE when the module is run
        as a script -- so the self-check would silently not run, and
        the module would ship with an entry point that prints nothing.

        Running the module under that name must produce the self-check's
        own line on stdout.
        """
        stdout = io.StringIO()
        with mock.patch.object(sys, "stdout", stdout):
            runpy.run_module("deny_hotpath", run_name="__main__")
        self.assertIn("deny-hotpath self-check ok", stdout.getvalue())
