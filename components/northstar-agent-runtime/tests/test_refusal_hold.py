"""Tests for the refusal hold (``refusal_hold``).

The rule under test: **a refusal row blocks the re-dispatch of the same
action, and an unusable gate blocks too.**

Northstar already records refusals faithfully as rows
(:mod:`refusal_row`) and records scope verdicts as denial rows
(:mod:`scope_qualifier`), but the two paths that actually *send the
action again* -- ``JobQueue.retry()`` and ``LeasedTaskClaim.fail()`` --
consulted neither.  So a refusal was recorded on the ledger and the same
job went out again, failed again, and produced another refusal row.
"Recorded but not enforced" is worse than "not recorded": the ledger
creates the illusion that the refusal was handled.

This module is the missing gate.  Its contract:

* **block** -- after a refusal is recorded, a second dispatch of the same
  action is refused, and the answer carries a **row reference** so the
  blocked caller can see which row stopped it;
* **no over-blocking** -- a different action, a different job and a
  different task are not blocked;
* **fail closed** -- an unreadable store, a tampered row and a malformed
  key all block; none of them silently allows;
* **the single-instrument weak basis blocks** (the semantics declared in
  ``docs/design/refusal-hold.md``);
* **refusal rows do not expire** (the expiry fork declared in the same
  doc);
* **the two refusal families** -- ``refusal_row.RefusalRow`` is
  recognized, ``scope_qualifier.DenialRow`` is explicitly excluded;
* **no wall clock** -- every time value comes from the caller.

The tests drive real paths, not just the happy one: a refusal is
recorded, a dispatch is blocked, another dispatch is not blocked, the row
is tampered with behind the frozen check, the store is broken, and the key
is malformed.
"""
import unittest
from dataclasses import replace as dataclasses_replace

from refusal_hold import (
    REASON_ALLOWED_NO_REFUSAL,
    REASON_BLOCKED_BY_REFUSAL,
    REASON_BLOCKED_KEY_INVALID,
    REASON_BLOCKED_ROW_INVALID,
    REASON_BLOCKED_ROW_TAMPERED,
    REASON_BLOCKED_STORE_UNREADABLE,
    SCOPE_KIND_QUEUE,
    SCOPE_KIND_TASK,
    RefusalHold,
    RefusalHoldEntry,
    RefusalHoldError,
    RefusalHoldKey,
    RefusalHoldKeyError,
    RefusalHoldStore,
)
from refusal_row import (
    MARKER_SINGLE_INSTRUMENT,
    RefusalRow,
    digest_of,
    record_refusal,
    verify_row,
)

EVIDENCE = digest_of({"evidence": "stale snapshot"})
RULESET = digest_of({"ruleset": "gate-v3"})
POPULATION = digest_of({"population": "nightly-regression"})

#: The two keys the block / no-over-block tests use.
QUEUE_KEY = RefusalHoldKey(SCOPE_KIND_QUEUE, "job-1", "checkout")
TASK_KEY = RefusalHoldKey(SCOPE_KIND_TASK, "task-9", "checkout")


def refusal_row(**overrides):
    """A refusal resting on two distinct instruments."""
    kwargs = dict(
        verdict="denied",
        evidence_hash=EVIDENCE,
        ruleset_hash=RULESET,
        verifier_key="check-alpha@v1",
        population_digest=POPULATION,
        reason="the evidence digest does not match the ruleset",
        refused_at=1_700_000_000,
        instruments=["check-alpha@v1", "check-beta@v2"],
    )
    kwargs.update(overrides)
    return record_refusal(**kwargs)


def single_instrument_row():
    """A refusal resting on one instrument, declared and marked."""
    return record_refusal(
        verdict="denied",
        evidence_hash=EVIDENCE,
        ruleset_hash=RULESET,
        verifier_key="check-alpha@v1",
        population_digest=POPULATION,
        reason="only one verifier was available at the boundary",
        refused_at=1_700_000_000,
        instruments=["check-alpha@v1"],
        single_instrument=True,
    )


def forge(row, **changes):
    """Tamper with a row the way a forger would: behind the frozen check.

    ``object.__setattr__`` bypasses ``frozen=True``, which is exactly
    the attack the row's own digest is there to catch.
    """
    for name, value in changes.items():
        object.__setattr__(row, name, value)
    return row


class RefusalHoldKeyTests(unittest.TestCase):
    """The key: what one refusal blocks."""

    def test_the_key_carries_scope_kind_scope_id_and_action(self):
        self.assertEqual(QUEUE_KEY.scope_kind, "queue")
        self.assertEqual(QUEUE_KEY.scope_id, "job-1")
        self.assertEqual(QUEUE_KEY.action, "checkout")

    def test_the_canonical_form_names_the_action_and_the_scope(self):
        self.assertEqual(QUEUE_KEY.identity, "queue:job-1:checkout")
        self.assertEqual(TASK_KEY.identity, "task:task-9:checkout")

    def test_two_keys_name_the_same_action_only_when_all_three_match(self):
        same = RefusalHoldKey("queue", "job-1", "checkout")
        other_action = RefusalHoldKey("queue", "job-1", "refund")
        other_job = RefusalHoldKey("queue", "job-2", "checkout")
        other_kind = RefusalHoldKey("task", "job-1", "checkout")
        self.assertEqual(QUEUE_KEY, same)
        self.assertNotEqual(QUEUE_KEY, other_action)
        self.assertNotEqual(QUEUE_KEY, other_job)
        self.assertNotEqual(QUEUE_KEY, other_kind)

    def test_a_malformed_key_is_refused_and_never_defaulted(self):
        for bad in (
            lambda: RefusalHoldKey("galaxy", "job-1", "checkout"),
            lambda: RefusalHoldKey("queue", "", "checkout"),
            lambda: RefusalHoldKey("queue", "job-1", ""),
            lambda: RefusalHoldKey("queue", None, "checkout"),
            lambda: RefusalHoldKey("queue", "job:1", "checkout"),
            lambda: RefusalHoldKey("queue", "job-1", 7),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(RefusalHoldKeyError):
                    bad()

    def test_a_key_built_from_a_mapping_needs_every_field(self):
        key = RefusalHoldKey.from_mapping(
            {"scope_kind": "queue", "scope_id": "job-1", "action": "checkout"}
        )
        self.assertEqual(key, QUEUE_KEY)
        with self.assertRaises(RefusalHoldKeyError):
            RefusalHoldKey.from_mapping({"scope_kind": "queue", "scope_id": "job-1"})

    def test_the_key_error_carries_the_blocked_key_invalid_reason(self):
        try:
            RefusalHoldKey("queue", "", "checkout")
        except RefusalHoldKeyError as exc:
            self.assertEqual(exc.reason, REASON_BLOCKED_KEY_INVALID)
        else:  # pragma: no cover - the constructor must refuse
            self.fail("an empty scope_id must be refused")


class RefusalHoldBlockTests(unittest.TestCase):
    """Path (a): a refusal blocks the re-dispatch of the same action."""

    def setUp(self):
        self.row = refusal_row()
        self.hold = RefusalHold.from_rows([self.row], [QUEUE_KEY], now=1_700_000_000)

    def test_a_second_dispatch_of_the_same_action_is_blocked(self):
        result = self.hold.check(QUEUE_KEY, now=1_700_000_100)
        self.assertTrue(result.blocked)
        self.assertEqual(result.reason, REASON_BLOCKED_BY_REFUSAL)
        self.assertTrue(self.hold.is_blocked(QUEUE_KEY))

    def test_the_block_carries_the_row_reference_that_stopped_the_dispatch(self):
        result = self.hold.check(QUEUE_KEY, now=1_700_000_100)
        self.assertIs(result.row, self.row)
        self.assertEqual(result.row_digest, self.row.row_digest)
        self.assertTrue(result.has_row)
        self.assertIs(self.hold.blocked_row(QUEUE_KEY), self.row)

    def test_the_blocked_caller_can_audit_the_refusal_it_hit(self):
        result = self.hold.check(QUEUE_KEY, now=1_700_000_100)
        self.assertTrue(verify_row(result.row))
        self.assertEqual(result.row.verdict, "denied")
        self.assertEqual(result.row.evidence_hash, EVIDENCE)
        self.assertEqual(result.row.ruleset_hash, RULESET)
        self.assertEqual(result.row.population_digest, POPULATION)
        self.assertEqual(result.row.instrument_count, 2)

    def test_the_hold_keeps_a_reference_and_never_a_copy(self):
        # The row is stored by reference: mutating the live row changes
        # what the hold sees.  That is the whole point -- a copy would
        # let a forgery hide behind a pristine duplicate.
        entry = self.hold.entries()[0]
        self.assertIs(entry.row, self.row)
        forge(self.row, evidence_hash=digest_of({"evidence": "something else"}))
        self.assertFalse(entry.is_intact())
        self.assertEqual(self.hold.check(QUEUE_KEY).reason, REASON_BLOCKED_ROW_TAMPERED)


class RefusalHoldNoOverBlockingTests(unittest.TestCase):
    """Path (b): a different action is not blocked."""

    def setUp(self):
        self.row = refusal_row()
        self.hold = RefusalHold.from_rows([self.row], [QUEUE_KEY], now=1_700_000_000)

    def test_a_different_action_in_the_same_job_is_not_blocked(self):
        result = self.hold.check(
            RefusalHoldKey("queue", "job-1", "refund"), now=1_700_000_100
        )
        self.assertFalse(result.blocked)
        self.assertEqual(result.reason, REASON_ALLOWED_NO_REFUSAL)
        self.assertIsNone(result.row)

    def test_a_different_job_in_the_same_queue_is_not_blocked(self):
        result = self.hold.check(
            RefusalHoldKey("queue", "job-2", "checkout"), now=1_700_000_100
        )
        self.assertFalse(result.blocked)
        self.assertEqual(result.reason, REASON_ALLOWED_NO_REFUSAL)

    def test_a_different_scope_granularity_is_not_blocked(self):
        # The same action name, but on a task: the queue key does not
        # cover it.  A hold that over-blocked across granularities would
        # be unusable in practice.
        result = self.hold.check(TASK_KEY, now=1_700_000_100)
        self.assertFalse(result.blocked)
        self.assertEqual(result.reason, REASON_ALLOWED_NO_REFUSAL)

    def test_the_task_granularity_blocks_only_its_own_scope(self):
        task_hold = RefusalHold.from_rows([self.row], [TASK_KEY], now=1_700_000_000)
        self.assertTrue(task_hold.check(TASK_KEY).blocked)
        self.assertFalse(task_hold.check(QUEUE_KEY).blocked)
        self.assertFalse(
            task_hold.check(RefusalHoldKey("task", "task-8", "checkout")).blocked
        )


class RefusalHoldFailClosedTests(unittest.TestCase):
    """Path (c): an unusable gate blocks, because an unknown state is
    never a clean read (``scope_qualifier.BLOCKING_OUTCOMES`` contains
    ``OUTCOME_UNKNOWN``)."""

    def test_an_unreadable_store_blocks(self):
        row = refusal_row()
        store = RefusalHoldStore([RefusalHoldEntry(key=QUEUE_KEY, row=row)])
        store.break_reads()
        hold = RefusalHold(store=store)
        result = hold.check(QUEUE_KEY, now=1_700_000_100)
        self.assertTrue(result.blocked)
        self.assertEqual(result.reason, REASON_BLOCKED_STORE_UNREADABLE)
        self.assertIsNone(result.row)
        self.assertTrue(hold.is_blocked(QUEUE_KEY))

    def test_an_unreadable_store_blocks_even_a_key_with_no_refusal(self):
        # The gate could not answer, so it may not answer "allowed"
        # either -- not even for a key it has never heard of.
        store = RefusalHoldStore()
        store.break_reads()
        hold = RefusalHold(store=store)
        result = hold.check(RefusalHoldKey("queue", "job-404", "checkout"))
        self.assertTrue(result.blocked)
        self.assertEqual(result.reason, REASON_BLOCKED_STORE_UNREADABLE)

    def test_a_tampered_row_blocks(self):
        row = refusal_row()
        hold = RefusalHold.from_rows([row], [QUEUE_KEY], now=1_700_000_000)
        self.assertTrue(hold.check(QUEUE_KEY).blocked)
        forge(row, evidence_hash=digest_of({"evidence": "something else"}))
        self.assertFalse(verify_row(row))
        result = hold.check(QUEUE_KEY, now=1_700_000_100)
        self.assertTrue(result.blocked)
        self.assertEqual(result.reason, REASON_BLOCKED_ROW_TAMPERED)
        # A forged row is not handed back as an audit trail, but its
        # digest is named so the operator can find it.
        self.assertIsNone(result.row)
        self.assertEqual(result.row_digest, row.row_digest)

    def test_a_tampered_row_digest_blocks(self):
        row = refusal_row()
        hold = RefusalHold.from_rows([row], [QUEUE_KEY], now=1_700_000_000)
        forge(row, row_digest=digest_of("nonsense"))
        result = hold.check(QUEUE_KEY)
        self.assertTrue(result.blocked)
        self.assertEqual(result.reason, REASON_BLOCKED_ROW_TAMPERED)

    def test_a_malformed_key_is_refused_and_never_silently_allowed(self):
        row = refusal_row()
        hold = RefusalHold.from_rows([row], [QUEUE_KEY], now=1_700_000_000)
        for bad in ("queue:job-1:checkout", None, 7, {"scope_kind": "queue"}):
            with self.subTest(bad=bad):
                with self.assertRaises(RefusalHoldKeyError):
                    hold.check(bad)

    def test_a_key_missing_a_field_is_refused_before_the_store_is_read(self):
        hold = RefusalHold(entries=[], now=1_700_000_000)
        with self.assertRaises(RefusalHoldKeyError):
            RefusalHoldKey.from_mapping({"scope_kind": "queue"})

    def test_the_hold_never_allows_when_the_store_raises(self):
        class ExplodingStore(RefusalHoldStore):
            def fetch(self, key):
                raise RuntimeError("the store is on fire")

        hold = RefusalHold(store=ExplodingStore())
        result = hold.check(QUEUE_KEY)
        self.assertTrue(result.blocked)
        self.assertEqual(result.reason, REASON_BLOCKED_STORE_UNREADABLE)


class RefusalHoldSingleInstrumentTests(unittest.TestCase):
    """The single-instrument weak basis **blocks**.

    The semantics declared in ``docs/design/refusal-hold.md`` §6: a
    weak basis is not an invalid refusal.  ``refusal_row.verify_row()``
    returns True for a properly declared single-instrument row, so the
    hold treats it as a blocking refusal -- and the weakness travels with
    the row, where the blocked caller can read it.
    """

    def test_a_single_instrument_refusal_still_blocks(self):
        row = single_instrument_row()
        self.assertEqual(row.marker, MARKER_SINGLE_INSTRUMENT)
        self.assertTrue(verify_row(row))
        hold = RefusalHold.from_rows([row], [QUEUE_KEY], now=1_700_000_000)
        result = hold.check(QUEUE_KEY, now=1_700_000_100)
        self.assertTrue(result.blocked)
        self.assertEqual(result.reason, REASON_BLOCKED_BY_REFUSAL)

    def test_the_weak_basis_travels_with_the_blocking_row(self):
        row = single_instrument_row()
        hold = RefusalHold.from_rows([row], [QUEUE_KEY], now=1_700_000_000)
        result = hold.check(QUEUE_KEY)
        self.assertIs(result.row, row)
        self.assertEqual(result.row.marker, MARKER_SINGLE_INSTRUMENT)
        self.assertTrue(result.row.reason)

    def test_a_two_instrument_refusal_carries_no_marker(self):
        row = refusal_row()
        self.assertEqual(row.marker, "")
        hold = RefusalHold.from_rows([row], [QUEUE_KEY], now=1_700_000_000)
        result = hold.check(QUEUE_KEY)
        self.assertEqual(result.row.marker, "")


class RefusalHoldExpiryTests(unittest.TestCase):
    """Refusal rows **do not expire** (the expiry fork declared in
    ``docs/design/refusal-hold.md`` §7).

    A refusal is a permission-class decision, not a capacity bound: there
    is no bound on it to pass.  The mechanism for changing it is another
    row, because ``refusal_row`` is append-only -- not the clock.
    """

    def test_a_refusal_still_blocks_far_in_the_future(self):
        row = refusal_row(refused_at=1_700_000_000)
        hold = RefusalHold.from_rows([row], [QUEUE_KEY], now=1_700_000_000)
        late = hold.check(QUEUE_KEY, now=1_700_000_000 + 10 * 365 * 24 * 3600)
        self.assertTrue(late.blocked)
        self.assertEqual(late.reason, REASON_BLOCKED_BY_REFUSAL)

    def test_a_refusal_still_blocks_far_in_the_past(self):
        row = refusal_row(refused_at=1_700_000_000)
        hold = RefusalHold.from_rows([row], [QUEUE_KEY], now=1_700_000_000)
        early = hold.check(QUEUE_KEY, now=0)
        self.assertTrue(early.blocked)
        self.assertEqual(early.reason, REASON_BLOCKED_BY_REFUSAL)

    def test_the_answer_does_not_depend_on_the_clock(self):
        row = refusal_row()
        hold = RefusalHold.from_rows([row], [QUEUE_KEY], now=1_700_000_000)
        first = hold.check(QUEUE_KEY, now=1_700_000_000)
        second = hold.check(QUEUE_KEY, now=9_999_999_999)
        self.assertEqual(first.blocked, second.blocked)
        self.assertEqual(first.reason, second.reason)


class RefusalHoldNoWallClockTests(unittest.TestCase):
    """No wall clock: every time value comes from the caller."""

    def test_the_hold_reads_no_clock_of_its_own(self):
        row = refusal_row()
        # Two holds built with different "now" values answer identically,
        # and neither one needed a clock to be told what time it is.
        early = RefusalHold.from_rows([row], [QUEUE_KEY], now=0)
        late = RefusalHold.from_rows([row], [QUEUE_KEY], now=10**12)
        self.assertEqual(early.now, 0)
        self.assertEqual(late.now, 10**12)
        self.assertTrue(early.check(QUEUE_KEY).blocked)
        self.assertTrue(late.check(QUEUE_KEY).blocked)
        self.assertFalse(
            early.check(RefusalHoldKey("queue", "job-2", "checkout")).blocked
        )

    def test_the_module_imports_no_wall_clock_reader(self):
        import refusal_hold

        with open(refusal_hold.__file__, encoding="utf-8") as handle:
            source = handle.read()
        self.assertNotIn("import time", source)
        self.assertNotIn("time.time()", source)
        self.assertNotIn("datetime.now", source)
        self.assertNotIn("datetime.utcnow", source)


class RefusalHoldRefusalFamilyTests(unittest.TestCase):
    """The two refusal families: one recognized, one explicitly excluded.

    ``refusal_row.RefusalRow`` is the hold's input.
    ``scope_qualifier.DenialRow`` is a scope verdict sidecar with no
    evidence hash, no ruleset hash, no instrument and no population
    digest, so it cannot be re-verified and it does not carry the "two
    instruments or none" basis -- it is excluded, and it is excluded
    *loudly*: it blocks as an invalid row, never silently ignored.
    """

    def test_the_refusal_row_family_is_recognized(self):
        row = refusal_row()
        entry = RefusalHoldEntry(key=QUEUE_KEY, row=row)
        self.assertTrue(entry.is_refusal_row())
        self.assertTrue(entry.is_intact())
        self.assertEqual(entry.row_digest, row.row_digest)

    def test_the_denial_row_family_is_explicitly_excluded(self):
        from scope_qualifier import DenialRow, ROW_DENIED

        denial = DenialRow(scope="queue:job-1:checkout", kind=ROW_DENIED)
        entry = RefusalHoldEntry(key=QUEUE_KEY, row=denial)
        self.assertFalse(entry.is_refusal_row())
        self.assertFalse(entry.is_intact())
        self.assertIsNone(entry.row_digest)

    def test_a_denial_row_on_the_key_blocks_as_an_invalid_row(self):
        from scope_qualifier import DenialRow, ROW_DENIED

        denial = DenialRow(scope="queue:job-1:checkout", kind=ROW_DENIED)
        hold = RefusalHold(entries=[RefusalHoldEntry(key=QUEUE_KEY, row=denial)])
        result = hold.check(QUEUE_KEY, now=1_700_000_100)
        self.assertTrue(result.blocked)
        self.assertEqual(result.reason, REASON_BLOCKED_ROW_INVALID)

    def test_the_denial_row_is_never_silently_ignored(self):
        # A hold that met a DenialRow and shrugged would be the exact
        # "recorded but not enforced" failure this slice exists to close.
        from scope_qualifier import DenialRow, ROW_DENIED

        denial = DenialRow(scope="queue:job-1:checkout", kind=ROW_DENIED)
        hold = RefusalHold(entries=[RefusalHoldEntry(key=QUEUE_KEY, row=denial)])
        self.assertNotEqual(
            hold.check(QUEUE_KEY).reason, REASON_ALLOWED_NO_REFUSAL
        )


class RefusalHoldReDispatchPathTests(unittest.TestCase):
    """The real path: a refusal recorded on a job stops the re-dispatch.

    The hold is not wired into ``JobQueue.retry()`` in this slice (that
    module is read-only here), so the test drives the gate the way the
    caller would: the job is retried by the queue, and the *gate* is
    asked before the retry goes out.
    """

    def test_a_refused_job_is_not_re_dispatched(self):
        from job_queue import JobQueue

        queue = JobQueue()
        queue.enqueue("job-1", "work", "checkout", digest_of({"p": 1}), seq=1)
        row = refusal_row(reason="the evidence digest does not match the ruleset")
        hold = RefusalHold.from_rows([row], [QUEUE_KEY], now=1_700_000_000)

        dequeued = queue.dequeue("worker-1", "work", seq=2)
        self.assertIsNotNone(dequeued)
        queue.retry("job-1", seq=3)

        # The queue is happy to send it again -- it does not know about
        # refusal rows.  The gate is what stops it.
        key = RefusalHoldKey("queue", dequeued.job_id, "checkout")
        result = hold.check(key, now=1_700_000_100)
        self.assertTrue(result.blocked)
        self.assertEqual(result.reason, REASON_BLOCKED_BY_REFUSAL)
        self.assertIs(result.row, row)

    def test_a_job_with_no_refusal_is_re_dispatched(self):
        from job_queue import JobQueue

        queue = JobQueue()
        queue.enqueue("job-2", "work", "checkout", digest_of({"p": 2}), seq=1)
        queue.dequeue("worker-1", "work", seq=2)
        queue.retry("job-2", seq=3)

        hold = RefusalHold(entries=[], now=1_700_000_000)
        result = hold.check(RefusalHoldKey("queue", "job-2", "checkout"))
        self.assertFalse(result.blocked)
        self.assertEqual(result.reason, REASON_ALLOWED_NO_REFUSAL)

    def test_a_refused_task_is_not_re_dispatched(self):
        from leased_task_claim import LeasedTaskClaim

        claim = LeasedTaskClaim()
        claim.enqueue_task("task-9", "checkout")
        lease = claim.claim("task-9", "worker-1", ttl=30.0, now=100.0)
        row = refusal_row()
        hold = RefusalHold.from_rows([row], [TASK_KEY], now=100)

        claim.fail("task-9", lease.token, reason="refused upstream", now=101.0)
        result = hold.check(TASK_KEY, now=101.0)
        self.assertTrue(result.blocked)
        self.assertEqual(result.reason, REASON_BLOCKED_BY_REFUSAL)
        self.assertIs(result.row, row)

    def test_the_hold_reports_its_entries_and_serializes_them(self):
        row = refusal_row()
        hold = RefusalHold.from_rows([row], [QUEUE_KEY], now=1_700_000_000)
        self.assertEqual(len(hold), 1)
        self.assertEqual([e.identity for e in hold], ["queue:job-1:checkout"])
        payload = hold.to_list()[0]
        self.assertEqual(payload["key"], "queue:job-1:checkout")
        self.assertEqual(payload["row_digest"], row.row_digest)
        self.assertEqual(payload["row"]["verdict"], "denied")


class RefusalHoldBoundTests(unittest.TestCase):
    """A hold is a gate, not a ledger: it carries a bounded number of
    refusals (house convention, as in
    ``cancellation_tombstone.MAX_TOMBSTONES``)."""

    def test_a_hold_beyond_the_bound_is_refused(self):
        from refusal_hold import MAX_HOLD_ENTRIES

        entries = [
            RefusalHoldEntry(
                key=RefusalHoldKey("queue", f"job-{i}", "checkout"), row=refusal_row()
            )
            for i in range(MAX_HOLD_ENTRIES + 1)
        ]
        with self.assertRaises(RefusalHoldError):
            RefusalHoldStore(entries)

    def test_a_hold_at_the_bound_is_accepted(self):
        from refusal_hold import MAX_HOLD_ENTRIES

        entries = [
            RefusalHoldEntry(
                key=RefusalHoldKey("queue", f"job-{i}", "checkout"), row=refusal_row()
            )
            for i in range(MAX_HOLD_ENTRIES)
        ]
        store = RefusalHoldStore(entries)
        self.assertEqual(len(store.entries()), MAX_HOLD_ENTRIES)

    def test_a_hold_needs_one_key_per_refusal_row(self):
        row = refusal_row()
        with self.assertRaises(RefusalHoldError):
            RefusalHold.from_rows([row], [], now=0)
        with self.assertRaises(RefusalHoldError):
            RefusalHold.from_rows([row, row], [QUEUE_KEY], now=0)

    def test_an_entry_needs_a_key_and_a_row(self):
        row = refusal_row()
        with self.assertRaises(RefusalHoldError):
            RefusalHoldEntry(key="queue:job-1:checkout", row=row)
        with self.assertRaises(RefusalHoldError):
            RefusalHoldEntry(key=QUEUE_KEY, row=None)

    def test_the_store_says_whether_it_can_answer(self):
        store = RefusalHoldStore()
        self.assertTrue(store.is_readable())
        store.break_reads()
        self.assertFalse(store.is_readable())
        store.repair()
        self.assertTrue(store.is_readable())



class RefusalHoldSelfCheckTests(unittest.TestCase):
    """The module's own ``main()`` self-check is real code, and its
    asserts are the last line of defence.

    Four ``eq`` faults and four ``and`` faults survived the suite that
    drives the *library*: every one of them sat in the self-check's own
    asserts (and one in its ``__main__`` guard), which **no test ever
    executed**.  A fault in a self-check assert turns the self-check into
    a **no-op that still prints "ok"** -- the module's last guard
    silently stops guarding, and the module's own ``if __name__ ==
    "__main__"`` entry point becomes a lie.

    Two techniques are used here, and both are the repository's own:

    * **run the self-check for real** (``runpy`` / a direct call).  The
      self-check's asserts state the *correct* semantics, so on the
      unmutated module they hold; a fault in one of them turns the
      self-check into a failing one.  The plain "it completes" test is
      therefore the killer for every ``==`` -> ``!=`` fault: the mutant
      makes the real, correct answer FAIL the assert.
    * **drive one half of a conjunction at a time**.  ``and`` -> ``or``
      cannot be killed by the real behaviour (both halves are true
      there, so both spellings pass), and it cannot be killed by a
      failing behaviour either (the original assert would fail too).
      The killer is a case where **exactly one** half holds: the
      original assert raises, the mutant's passes.  The collaborator
      the assert reads -- ``RefusalHold.check`` -- is patched so that
      one half is true and the other false, and the self-check is
      expected to raise.

    The self-check asserts, and what each one says:

    * ``main()`` line 645 -- ``assert blocked.blocked and
      blocked.reason == REASON_BLOCKED_BY_REFUSAL`` -- the refusal
      blocks **and** the reason names it.
    * ``main()`` line 646 -- ``assert blocked.row is row and
      blocked.row_digest == row.row_digest`` -- the block carries **the
      row itself** and **its digest**.
    * ``main()`` line 649 -- ``assert not other.blocked and
      other.reason == REASON_ALLOWED_NO_REFUSAL`` -- a different job is
      **not** blocked **and** the reason says so.
    * ``main()`` line 654 -- ``assert unreadable.blocked and
      unreadable.reason == REASON_BLOCKED_STORE_UNREADABLE`` -- a
      broken store blocks **and** the reason says so.
    """

    def _run_main(self):
        """Run the module's self-check, capturing what it printed."""
        import io
        from contextlib import redirect_stdout

        import refusal_hold

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            refusal_hold.main()
        return buffer.getvalue()

    def _run_main_with_patched_check(self, patch):
        """Run the self-check with ``RefusalHold.check`` replaced.

        ``patch`` receives the real result and returns the result the
        assert under test will see.  Every other part of the hold --
        the store, the row, the key -- is left alone, so the assert
        under test is the only thing that changes.
        """
        import dataclasses

        import refusal_hold

        original = refusal_hold.RefusalHold.check

        def patched(self, key, now=None):
            return patch(dataclasses.replace(original(self, key, now=now)))

        refusal_hold.RefusalHold.check = patched
        try:
            with self.assertRaises(AssertionError):
                refusal_hold.main()
        finally:
            refusal_hold.RefusalHold.check = original

    # -- the self-check really runs ---------------------------------------

    def test_the_self_check_passes_on_the_real_code(self):
        """`eq@645` / `eq@646` / `eq@649` / `eq@654`: the self-check's
        own asserts, on the real behaviour.

        The self-check states the *correct* semantics -- the refusal
        blocks with the ``blocked_by_refusal`` reason, the block carries
        the row and its digest, a different job is allowed with the
        ``allowed_no_refusal`` reason, and a broken store blocks with
        the ``blocked_store_unreadable`` reason.  So on the unmutated
        module every assert holds and the self-check completes.

        Under a fault (``==`` -> ``!=``) one of those asserts asks the
        opposite question -- "the reason is NOT blocked_by_refusal",
        "the row is NOT the row" -- and the correct behaviour FAILS it.
        The self-check then raises instead of printing "ok", which is
        exactly the no-op self-check the fault creates.
        """
        self.assertIn("refusal-hold self-check: ok", self._run_main())

    def test_running_the_module_as_a_script_runs_the_self_check(self):
        """`eq@659`: the ``__main__`` guard.

        ``if __name__ == "__main__":`` becomes ``!=`` under the fault,
        and then the self-check runs on EVERY import and NEVER runs when
        the module is run as a script -- which is how it is used, and
        how its faults would reach production.
        """
        import io
        from contextlib import redirect_stdout

        import runpy

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            runpy.run_module("refusal_hold", run_name="__main__")
        self.assertIn("refusal-hold self-check: ok", buffer.getvalue())

    # -- and@645: the block and its reason -------------------------------

    def test_the_self_check_fails_when_the_block_is_right_and_the_reason_is_wrong(self):
        """`and@645`: the conjunction's two halves, driven apart.

        The assert is ``blocked.blocked and blocked.reason ==
        REASON_BLOCKED_BY_REFUSAL``.  Under the fault (``and`` ->
        ``or``) it reads "the refusal blocks OR the reason names it".

        The killer is the case where **exactly one** half holds: the
        block is real but the reason is not
        ``blocked_by_refusal``.  There the original assert FAILS (both
        halves must hold) while the mutant's PASSES (one half is
        enough), so the self-check's "not a refusal block" reasoning is
        what the fault removes.
        """
        import refusal_hold

        def patch(result):
            if result.reason == refusal_hold.REASON_BLOCKED_BY_REFUSAL:
                return dataclasses_replace(
                    result, reason=refusal_hold.REASON_BLOCKED_ROW_INVALID
                )
            return result

        self._run_main_with_patched_check(patch)

    # -- and@646: the row and the digest ---------------------------------

    def test_the_self_check_fails_when_the_digest_is_right_and_the_row_is_missing(self):
        """`and@646`: the conjunction's two halves, driven apart.

        The assert is ``blocked.row is row and blocked.row_digest ==
        row.row_digest``.  The killer is the case where the **digest**
        is the row's and the **row** is missing: the original assert
        fails, the mutant's (``or``) passes on the digest alone.
        """
        import refusal_hold

        def patch(result):
            if result.reason == refusal_hold.REASON_BLOCKED_BY_REFUSAL:
                return dataclasses_replace(result, row=None)
            return result

        self._run_main_with_patched_check(patch)

    # -- and@649: the no-over-block half ---------------------------------

    def test_the_self_check_fails_when_a_different_job_is_blocked_but_claims_to_pass(self):
        """`and@649`: the conjunction's two halves, driven apart.

        The assert is ``not other.blocked and other.reason ==
        REASON_ALLOWED_NO_REFUSAL``.  The killer is the case where the
        different job **is blocked** while the reason still claims it
        may pass: the original assert fails (the first half is false),
        the mutant's (``or``) passes on the reason alone.
        """
        import refusal_hold

        def patch(result):
            if not result.blocked:
                return dataclasses_replace(result, blocked=True)
            return result

        self._run_main_with_patched_check(patch)

    # -- and@654: the broken store ---------------------------------------

    def test_the_self_check_fails_when_a_broken_store_fail_opens(self):
        """`and@654`: the conjunction's two halves, driven apart.

        The assert is ``unreadable.blocked and unreadable.reason ==
        REASON_BLOCKED_STORE_UNREADABLE``.  The killer is the case
        where the broken store **does not block** while the reason
        still names the fail-closed slug: the original assert fails (the
        first half is false -- the gate fail-opened), the mutant's
        (``or``) passes on the reason alone.
        """
        import refusal_hold

        def patch(result):
            if result.reason == refusal_hold.REASON_BLOCKED_STORE_UNREADABLE:
                return dataclasses_replace(result, blocked=False)
            return result

        self._run_main_with_patched_check(patch)
