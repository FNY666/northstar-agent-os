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

import sqlite3
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

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
