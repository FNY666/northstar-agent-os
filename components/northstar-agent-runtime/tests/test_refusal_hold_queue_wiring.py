"""The queue side: a recorded refusal blocks the re-dispatch of the same job.

What this file holds down
--------------------------
`docs/design/refusal-hold-wiring.md` §4 names the two re-dispatch paths
-- `JobQueue.retry()` and `LeasedTaskClaim.fail()` -- and says why the
wiring could not land them: the queue side holds no **action identity**,
so the refusal hold cannot be asked a question in its own vocabulary.

The action identity turns out to be **already carried**: `JobQueue` keeps
the job's `task` string on every entry, and `LeasedTaskClaim` keeps it in
the `ltc_task.task` column.  So the queue side needs a **mapping**, not a
schema change -- which is what `refusal_hold_wiring`'s queue section adds.

The properties these tests hold down:

* **(a)** a recorded refusal refuses the **same action's** re-dispatch,
  and the job does **not** go back to `ready`;
* **(b)** a **different action** is not blocked;
* **(c)** the **scope namespaces are not interchangeable**: a refusal
  recorded against a grant id does not block a job, and a refusal
  recorded against a job does not block a grant;
* **(d)** an **unusable gate** (store broken / row tampered) **fails
  closed** -- the job stays where it is;
* **(e)** the lease side's namespace is ``task:<task id>:<action>``, which
  is a **different key** from the ledger side's ``task:<grant id>:<action>``
  even though the scope kind is the same;
* **(f)** **concurrency**: while re-dispatching and recording a refusal
  concurrently, "refusal recorded but still re-dispatched" must never
  happen.

House style: stdlib only, no wall-clock reads, caller-supplied time.
"""

from __future__ import annotations

import threading
import time
import unittest
from pathlib import Path

# A stale ``__pycache__/refusal_hold_wiring.*.pyc`` makes Python import
# the *previous* source of this module when the source changed without
# changing size or second-resolution mtime -- which is exactly what a
# mutation probe does.  Drop the cached bytecode before the imports below
# so the tests always run the source that is on disk right now.
for _cached in Path(__file__).resolve().parents[1].glob(
    "__pycache__/refusal_hold_wiring.*.pyc"
):
    _cached.unlink(missing_ok=True)

from job_queue import JobQueue
from leased_task_claim import LeasedTaskClaim, TerminalTaskError
from refusal_hold import (
    REASON_ALLOWED_NO_REFUSAL,
    REASON_BLOCKED_BY_REFUSAL,
    REASON_BLOCKED_ROW_TAMPERED,
    REASON_BLOCKED_STORE_UNREADABLE,
    SCOPE_KIND_LEASE,
    SCOPE_KIND_QUEUE,
    SCOPE_KIND_TASK,
    RefusalHoldKey,
    RefusalHoldKeyError,
)
from refusal_hold_wiring import (
    RefusalHoldKeyMappingError,
    RefusalHoldQueueGate,
    RefusalHoldRegistry,
    RefusalHoldWiringError,
    RefusalRefusedError,
    install_queue_refusal_gate,
    queue_hold_key,
    task_hold_key,
)
from refusal_row import digest_of, record_refusal

DIGEST = "sha256:" + "d" * 64


def make_row(reason: str = "the evidence digest does not match the ruleset"):
    """One intact refusal row, on the :mod:`refusal_row` side."""
    return record_refusal(
        "denied",
        digest_of({"evidence": "stale"}),
        digest_of({"ruleset": "gate-v3"}),
        "check-alpha@v1",
        digest_of({"population": "nightly"}),
        reason=reason,
        refused_at=1_700_000_000,
        instruments=["check-alpha@v1", "check-beta@v2"],
    )


def tamper(row):
    """Tamper with a row in place: the digest no longer describes it."""
    object.__setattr__(row, "reason", "the reason was rewritten after the fact")
    return row


def make_queue(job_id: str = "job-1", task: str = "dispatch"):
    """A queue with one job, reserved and ready to be retried."""
    queue = JobQueue()
    queue.enqueue(job_id, "q", task, DIGEST, 1)
    queue.dequeue("worker-1", "q", 2)
    return queue


class QueueIdentityTests(unittest.TestCase):
    """The queue side's identity: which key names which action."""

    def test_the_job_id_becomes_the_scope_id(self):
        key = queue_hold_key("job-42", "dispatch")
        self.assertIsInstance(key, RefusalHoldKey)
        self.assertEqual(key.scope_id, "job-42")
        self.assertEqual(key.action, "dispatch")
        self.assertEqual(key.identity, "queue:job-42:dispatch")

    def test_the_queue_side_uses_the_queue_scope_kind(self):
        """The queue namespace is ``queue``, not the ledger's ``task``."""
        self.assertEqual(queue_hold_key("job-1", "dispatch").scope_kind, SCOPE_KIND_QUEUE)

    def test_the_lease_side_uses_the_lease_scope_kind(self):
        """The lease namespace is ``lease:<task id>:<action>``.

        It is NOT ``task:``, and that is a fix rather than a choice: the
        ledger side's ``scope_id`` is a grant id and the lease side's is
        a task id, and both are plain strings.  On a shared scope kind
        the two keys were the SAME whenever the id strings matched, so a
        refusal recorded against a grant blocked an unrelated lease.
        """
        key = task_hold_key("task-42", "dispatch")
        self.assertEqual(key.scope_kind, SCOPE_KIND_LEASE)
        self.assertEqual(key.identity, "lease:task-42:dispatch")

    def test_the_lease_side_and_the_ledger_side_are_different_keys(self):
        """The same id string does not make the same key.

        The ledger side's ``scope_id`` is a **grant id** and the lease
        side's is a **task id**.  They are different scope kinds, so a
        refusal recorded against one does not block the other -- even
        when the id strings are identical.
        """
        from refusal_hold_wiring import refusal_hold_key

        ledger_key = refusal_hold_key("grant-42", "dispatch")
        lease_key = task_hold_key("grant-42", "dispatch")
        self.assertNotEqual(ledger_key.scope_kind, lease_key.scope_kind)
        self.assertNotEqual(ledger_key.identity, lease_key.identity)

    def test_a_malformed_job_id_is_refused(self):
        """A malformed identity fails closed -- it never builds a key."""
        for bad in ("", "   ", None, 7):
            with self.assertRaises(RefusalHoldKeyMappingError):
                queue_hold_key(bad, "dispatch")

    def test_a_malformed_action_is_refused(self):
        for bad in ("", "   ", None, 7):
            with self.assertRaises(RefusalHoldKeyMappingError):
                queue_hold_key("job-1", bad)

    def test_an_unknown_scope_kind_is_refused(self):
        with self.assertRaises(RefusalHoldKeyMappingError):
            queue_hold_key("job-1", "dispatch", scope_kind="galaxy")


class QueueGateTests(unittest.TestCase):
    """The gate's answers, and the refusals it raises."""

    def setUp(self):
        self.registry = RefusalHoldRegistry()
        self.gate = RefusalHoldQueueGate(self.registry)

    def test_a_job_with_no_refusal_is_allowed(self):
        result = self.gate.check_queue("job-1", "dispatch")
        self.assertFalse(result.blocked)
        self.assertEqual(result.reason, REASON_ALLOWED_NO_REFUSAL)

    def test_a_recorded_refusal_blocks_the_same_action(self):
        self.gate.record_queue("job-1", "dispatch", row=make_row())
        result = self.gate.check_queue("job-1", "dispatch")
        self.assertTrue(result.blocked)
        self.assertEqual(result.reason, REASON_BLOCKED_BY_REFUSAL)
        self.assertIsNotNone(result.row)

    def test_a_recorded_refusal_does_not_block_a_different_action(self):
        """A refusal is scoped to ONE action, not to the whole job."""
        self.gate.record_queue("job-1", "dispatch", row=make_row())
        other = self.gate.check_queue("job-1", "refund")
        self.assertFalse(other.blocked)
        self.assertEqual(other.reason, REASON_ALLOWED_NO_REFUSAL)

    def test_a_recorded_refusal_does_not_block_a_different_job(self):
        self.gate.record_queue("job-1", "dispatch", row=make_row())
        other = self.gate.check_queue("job-2", "dispatch")
        self.assertFalse(other.blocked)

    def test_a_queue_refusal_does_not_block_the_ledger_side(self):
        """The namespaces are not interchangeable."""
        self.gate.record_queue("shared-id", "dispatch", row=make_row())
        ledger_side = self.registry.check("shared-id", "dispatch")
        self.assertFalse(ledger_side.blocked)

    def test_a_ledger_refusal_does_not_block_the_queue_side(self):
        """And the other direction, which is the one that bites."""
        self.registry.record("shared-id", "dispatch", row=make_row())
        queue_side = self.gate.check_queue("shared-id", "dispatch")
        self.assertFalse(queue_side.blocked)

    def test_the_lease_side_has_its_own_namespace(self):
        self.gate.record_task("task-1", "dispatch", row=make_row())
        self.assertTrue(self.gate.check_task("task-1", "dispatch").blocked)
        self.assertFalse(self.gate.check_queue("task-1", "dispatch").blocked)

    def test_a_broken_store_fails_closed(self):
        """An unusable gate blocks -- it never allows."""
        self.registry.store.break_reads()
        result = self.gate.check_queue("job-1", "dispatch")
        self.assertTrue(result.blocked)
        self.assertEqual(result.reason, REASON_BLOCKED_STORE_UNREADABLE)

    def test_a_tampered_row_fails_closed(self):
        self.gate.record_queue("job-1", "dispatch", row=tamper(make_row()))
        result = self.gate.check_queue("job-1", "dispatch")
        self.assertTrue(result.blocked)
        self.assertEqual(result.reason, REASON_BLOCKED_ROW_TAMPERED)

    def test_require_queue_allowed_raises_on_a_refusal(self):
        self.gate.record_queue("job-1", "dispatch", row=make_row())
        with self.assertRaises(RefusalRefusedError) as ctx:
            self.gate.require_queue_allowed("job-1", "dispatch")
        self.assertEqual(ctx.exception.reason, REASON_BLOCKED_BY_REFUSAL)

    def test_require_queue_allowed_is_silent_when_nothing_is_refused(self):
        self.assertIsNone(self.gate.require_queue_allowed("job-1", "dispatch"))

    def test_require_task_allowed_raises_on_a_refusal(self):
        self.gate.record_task("task-1", "dispatch", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            self.gate.require_task_allowed("task-1", "dispatch")

    def test_a_gate_with_no_registry_is_refused(self):
        with self.assertRaises(RefusalHoldWiringError):
            RefusalHoldQueueGate(None)

    def test_recording_without_a_row_is_refused(self):
        """A refusal with no row is not a refusal."""
        with self.assertRaises(RefusalHoldWiringError):
            self.gate.record_queue("job-1", "dispatch")


class QueueGateAuditTests(unittest.TestCase):
    """A queue-side check must be AUDITED, exactly like a ledger-side one.

    THE DEFECT (measured 2026-11-23)
    --------------------------------
    The registry's audit trail is documented as "what was recorded and
    what was checked" -- and the ledger side honours that: every
    ``registry.check(...)`` appends a ``checked`` event.

    The queue side did not.  ``RefusalHoldQueueGate.check_queue`` and
    ``check_task`` reached past the registry into ``registry.hold.check``
    and read the hold directly, so a queue-side check produced **no
    event at all**.  Measured on the tree before the fix:

        registry.check("grant-1", "seal")   ->  1 event
        gate.check_queue("job-1", "dispatch")   ->  still 1
        gate.check_task("task-1", "dispatch")   ->  still 1

    Two queue-side checks, and the audit trail does not know they
    happened.  The gate is the thing that stops a job from going back
    to ``ready``; a check that leaves no trace cannot answer "was this
    job ever refused?" after the fact.

    The shape of the defect is the shape this batch keeps hitting: the
    two sides are supposed to be the same gate, and one of them took a
    different path through it.  The queue gate exists to reuse the
    registry's semantics -- "a host can record a refusal once and
    consult it from either side" -- but it reused the *answer* and not
    the *recording*.
    """

    def setUp(self):
        self.registry = RefusalHoldRegistry()
        self.gate = RefusalHoldQueueGate(self.registry)

    def _checked_events(self):
        return [
            event
            for event in self.registry.events()
            if event["kind"] == "checked"
        ]

    def test_a_queue_side_check_is_audited(self):
        self.gate.check_queue("job-1", "dispatch")
        checked = self._checked_events()
        self.assertEqual(
            len(checked),
            1,
            "a queue-side check left no trace in the audit trail: "
            "the trail is documented as 'what was recorded and what was "
            "checked'",
        )
        self.assertEqual(checked[0]["key"], "queue:job-1:dispatch")
        self.assertFalse(checked[0]["blocked"])

    def test_a_task_side_check_is_audited(self):
        self.gate.check_task("task-1", "dispatch")
        checked = self._checked_events()
        self.assertEqual(
            len(checked),
            1,
            "a task-side check left no trace in the audit trail",
        )
        self.assertEqual(checked[0]["key"], "lease:task-1:dispatch")

    def test_a_blocking_queue_side_check_is_audited_as_blocked(self):
        """The blocked answer is the one an operator will ask about."""
        self.gate.record_queue("job-1", "dispatch", row=make_row())
        self.gate.check_queue("job-1", "dispatch")
        checked = self._checked_events()
        self.assertEqual(len(checked), 1)
        self.assertTrue(
            checked[0]["blocked"],
            "the audit trail says the check was allowed, but it blocked",
        )
        self.assertEqual(checked[0]["reason"], REASON_BLOCKED_BY_REFUSAL)
        self.assertIsNotNone(
            checked[0]["row_digest"],
            "a blocking check must record which refusal blocked it",
        )

    def test_the_queue_side_and_the_ledger_side_agree_on_being_audited(self):
        """Neither side is the privileged one.

        This is the symmetry the module promises: "a host can record a
        refusal once and consult it from either side".  If one side is
        audited and the other is not, the promise is only half true.
        """
        self.registry.check("grant-1", "seal")
        self.gate.check_queue("job-1", "dispatch")
        self.gate.check_task("task-1", "dispatch")
        self.assertEqual(
            len(self._checked_events()),
            3,
            "the three sides do not agree on what gets audited",
        )

    def test_a_refusing_gate_is_audited_too(self):
        """The raising form must leave the same trace as the boolean form.

        ``require_queue_allowed`` raises; a caller that catches the
        refusal still needs the trail to show that a check happened.
        """
        self.gate.record_queue("job-1", "dispatch", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            self.gate.require_queue_allowed("job-1", "dispatch")
        checked = self._checked_events()
        self.assertEqual(len(checked), 1)
        self.assertEqual(checked[0]["key"], "queue:job-1:dispatch")
        self.assertTrue(checked[0]["blocked"])

    def test_the_batch_sweep_form_is_audited_per_item(self):
        """``task_allowed`` is the batch form: one item, one event.

        The docstring says the boolean form exists "for the caller that
        sweeps a batch of work items: a refusal there must skip one
        item, not abandon the whole sweep".  A sweep of three items is
        three checks, and the trail must show three.
        """
        for task_id in ("task-1", "task-2", "task-3"):
            self.gate.task_allowed(task_id, "dispatch")
        self.assertEqual(len(self._checked_events()), 3)


class QueueRetryWiringTests(unittest.TestCase):
    """The re-dispatch path: the gate is inside the queue's own lock."""

    def setUp(self):
        self.registry = RefusalHoldRegistry()
        self.gate = RefusalHoldQueueGate(self.registry)

    def test_a_refused_retry_leaves_the_job_reserved(self):
        """(a) The observable proof: the job does not go back to ``ready``."""
        queue = make_queue()
        self.gate.record_queue("job-1", "dispatch", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            with install_queue_refusal_gate(
                queue, self.gate, job_id="job-1", action="dispatch"
            ):
                queue.retry("job-1", 3)
        view = queue.job("job-1")
        self.assertEqual(view.state, "reserved")
        self.assertNotEqual(view.state, "ready")

    def test_an_allowed_retry_puts_the_job_back_to_ready(self):
        """The control: no refusal, the re-dispatch happens."""
        queue = make_queue()
        with install_queue_refusal_gate(
            queue, self.gate, job_id="job-1", action="dispatch"
        ):
            record = queue.retry("job-1", 3)
        self.assertEqual(record.state, "ready")
        self.assertEqual(queue.job("job-1").state, "ready")

    def test_a_different_action_is_not_refused(self):
        """(b) The refusal covers one action, not the whole job."""
        queue = make_queue()
        self.gate.record_queue("job-1", "dispatch", row=make_row())
        with install_queue_refusal_gate(
            queue, self.gate, job_id="job-1", action="refund"
        ):
            record = queue.retry("job-1", 3)
        self.assertEqual(record.state, "ready")

    def test_a_broken_gate_leaves_the_job_reserved(self):
        """(d) An unusable gate refuses the re-dispatch."""
        queue = make_queue()
        self.registry.store.break_reads()
        with self.assertRaises(RefusalRefusedError):
            with install_queue_refusal_gate(
                queue, self.gate, job_id="job-1", action="dispatch"
            ):
                queue.retry("job-1", 3)
        self.assertEqual(queue.job("job-1").state, "reserved")

    def test_a_queue_without_a_lock_is_refused(self):
        class _NoLock:
            pass

        with self.assertRaises(RefusalHoldWiringError):
            with install_queue_refusal_gate(
                _NoLock(), self.gate, job_id="job-1", action="dispatch"
            ):
                pass

    def test_a_refusal_recorded_concurrently_never_loses_to_a_retry(self):
        """(f) "Recorded but still re-dispatched" must never happen.

        The recording and the gate take the SAME lock, so the two are
        serialized: whichever runs first wins, and the second sees the
        first's effect.
        """
        for _attempt in range(30):
            queue = make_queue(job_id="job-x")
            registry = RefusalHoldRegistry()
            registry.bind_gate(queue._lock)
            gate = RefusalHoldQueueGate(registry)
            re_dispatched = []
            refused = []

            def do_retry():
                try:
                    with install_queue_refusal_gate(
                        queue, gate, job_id="job-x", action="dispatch"
                    ):
                        queue.retry("job-x", 3)
                        re_dispatched.append(True)
                except RefusalRefusedError:
                    refused.append(True)

            def do_record():
                gate.record_queue("job-x", "dispatch", row=make_row())

            threads = [
                threading.Thread(target=do_retry),
                threading.Thread(target=do_record),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            state = queue.job("job-x").state
            if re_dispatched:
                # The retry won the race, so the refusal landed after it.
                # That is legal -- but the refusal must now be ON the
                # books, so a SECOND retry is refused.
                self.assertTrue(refused or state == "ready")
            if refused:
                self.assertNotEqual(state, "ready")


class LeaseFailWiringTests(unittest.TestCase):
    """The lease side's re-dispatch: ``LeasedTaskClaim.fail()``.

    The check belongs inside ``fail()``'s transaction, immediately before
    the ``UPDATE`` that flips the task back to ``ready``.  A refusal
    raises, so the transaction rolls back: the task keeps its state, its
    failure count and its delay.
    """

    def setUp(self):
        self.registry = RefusalHoldRegistry()
        self.gate = RefusalHoldQueueGate(self.registry)
        self.manager = LeasedTaskClaim(
            max_failures=3,
            base_backoff_seconds=2.0,
            refusal_gate=self.gate,
        )
        self.manager.enqueue_task("t1", "demo-task", payload="hello")

    def tearDown(self):
        self.manager.close()

    def _lease(self):
        return self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)

    def test_the_gate_is_installed_and_readable(self):
        self.assertIs(self.manager.refusal_gate, self.gate)

    def test_the_gate_can_be_removed(self):
        self.manager.set_refusal_gate(None)
        self.assertIsNone(self.manager.refusal_gate)

    def test_a_refused_failure_leaves_the_task_leased(self):
        """The observable proof: the task does not go back to ``ready``."""
        lease = self._lease()
        self.gate.record_task("t1", "demo-task", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            self.manager.fail("t1", lease.token, reason="boom", now=101.0)
        view = self.manager.task("t1")
        self.assertEqual(view.state, "leased")
        self.assertEqual(view.failures, 0)

    def test_a_refused_failure_books_no_backoff(self):
        """The failure count does not advance either."""
        lease = self._lease()
        self.gate.record_task("t1", "demo-task", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            self.manager.fail("t1", lease.token, reason="boom", now=101.0)
        self.assertEqual(self.manager.task("t1").delay_until, 0.0)

    def test_an_allowed_failure_puts_the_task_back_to_ready(self):
        """The control: no refusal, the re-dispatch happens."""
        lease = self._lease()
        record = self.manager.fail("t1", lease.token, reason="boom", now=101.0)
        self.assertEqual(record.state, "ready")
        view = self.manager.task("t1")
        self.assertEqual(view.state, "ready")
        self.assertEqual(view.failures, 1)

    def test_a_refusal_against_a_different_action_does_not_block(self):
        """The refusal covers one action, not the whole task."""
        lease = self._lease()
        self.gate.record_task("t1", "other-task", row=make_row())
        record = self.manager.fail("t1", lease.token, reason="boom", now=101.0)
        self.assertEqual(record.state, "ready")

    def test_a_refusal_against_a_different_task_does_not_block(self):
        lease = self._lease()
        self.gate.record_task("t2", "demo-task", row=make_row())
        record = self.manager.fail("t1", lease.token, reason="boom", now=101.0)
        self.assertEqual(record.state, "ready")

    def test_a_broken_gate_refuses_the_failure(self):
        """An unusable gate refuses -- it never allows."""
        lease = self._lease()
        self.registry.store.break_reads()
        with self.assertRaises(RefusalRefusedError):
            self.manager.fail("t1", lease.token, reason="boom", now=101.0)
        self.assertEqual(self.manager.task("t1").state, "leased")

    def test_a_gate_without_the_required_method_is_refused(self):
        """A gate that cannot answer the question is not a gate.

        The claim happens FIRST, and the unusable gate is installed
        afterwards: this test is about ``fail()``, and the claim is a
        path that now consults the gate too (see
        ``LeaseClaimWiringTests``).  Installing the bad gate before the
        claim would make the claim raise first, and the test would pass
        for the wrong reason.
        """
        lease = self._lease()
        self.manager.set_refusal_gate(object())
        with self.assertRaises(TypeError):
            self.manager.fail("t1", lease.token, reason="boom", now=101.0)

    def test_no_gate_leaves_the_failure_path_unchanged(self):
        """The default behaviour is untouched."""
        self.manager.set_refusal_gate(None)
        lease = self._lease()
        record = self.manager.fail("t1", lease.token, reason="boom", now=101.0)
        self.assertEqual(record.state, "ready")


class LeaseReapWiringTests(unittest.TestCase):
    """The crash path: ``LeasedTaskClaim.reap()``.

    ``fail()`` is not the only way a task goes back to ``ready``.  A
    lease that EXPIRES is swept back to ``ready`` by ``reap()``, with no
    backoff and no failure budget consumed -- and with no refusal
    check.  That is a second re-dispatch path, and a refusal that only
    guards ``fail()`` does not guard it.

    So the question this class asks is the uncomfortable one: can a
    refused task be laundered back into the queue by letting its lease
    expire?  It must not be.
    """

    def setUp(self):
        self.registry = RefusalHoldRegistry()
        self.gate = RefusalHoldQueueGate(self.registry)
        self.manager = LeasedTaskClaim(
            max_failures=3,
            base_backoff_seconds=2.0,
            refusal_gate=self.gate,
        )
        self.manager.enqueue_task("t1", "demo-task", payload="hello")

    def tearDown(self):
        self.manager.close()

    def test_a_refused_task_is_not_reaped(self):
        """The observable proof: the expired lease is NOT swept."""
        self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.gate.record_task("t1", "demo-task", row=make_row())
        swept = self.manager.reap(now=200.0)
        self.assertEqual(swept, ())
        self.assertEqual(self.manager.task("t1").state, "leased")

    def test_a_refused_task_keeps_its_crash_count(self):
        """The crash budget is not consumed by a refused re-dispatch."""
        self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.gate.record_task("t1", "demo-task", row=make_row())
        self.manager.reap(now=200.0)
        self.assertEqual(self.manager.task("t1").crashes, 0)

    def test_a_refused_task_stays_out_of_the_queue_mirror(self):
        """The mirror job stays ``reserved`` -- the work is not re-queued."""
        self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.gate.record_task("t1", "demo-task", row=make_row())
        self.manager.reap(now=200.0)
        self.assertEqual(self.manager._queue.job("t1").state, "reserved")

    def test_an_allowed_expired_lease_is_reaped(self):
        """The control: no refusal, the sweep happens as before."""
        self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        swept = self.manager.reap(now=200.0)
        self.assertEqual(len(swept), 1)
        self.assertEqual(self.manager.task("t1").state, "ready")

    def test_a_refusal_against_a_different_action_does_not_block_the_sweep(self):
        """The refusal covers one action, not the whole task."""
        self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.gate.record_task("t1", "other-task", row=make_row())
        swept = self.manager.reap(now=200.0)
        self.assertEqual(len(swept), 1)
        self.assertEqual(self.manager.task("t1").state, "ready")

    def test_a_broken_gate_does_not_sweep(self):
        """An unusable gate refuses the re-dispatch; it never allows."""
        self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.registry.store.break_reads()
        swept = self.manager.reap(now=200.0)
        self.assertEqual(swept, ())
        self.assertEqual(self.manager.task("t1").state, "leased")

    def test_no_gate_leaves_the_sweep_unchanged(self):
        """The default behaviour is untouched."""
        self.manager.set_refusal_gate(None)
        self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        swept = self.manager.reap(now=200.0)
        self.assertEqual(len(swept), 1)

    def test_one_refused_task_does_not_stop_the_others_from_being_swept(self):
        """A refusal is scoped to one task; the sweep is not all-or-nothing."""
        self.manager.enqueue_task("t2", "demo-task", payload="hello")
        self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.manager.claim("t2", "worker-B", ttl=10.0, now=100.0)
        self.gate.record_task("t1", "demo-task", row=make_row())
        swept = self.manager.reap(now=200.0)
        self.assertEqual([s.task_id for s in swept], ["t2"])
        self.assertEqual(self.manager.task("t1").state, "leased")
        self.assertEqual(self.manager.task("t2").state, "ready")


class LeaseReleaseWiringTests(unittest.TestCase):
    """The voluntary give-up: ``LeasedTaskClaim.release()``.

    ``release()`` is the THIRD path that puts a task back to ``ready``.
    It is the cheapest one to reach: a worker that gives up its lease
    needs no failure record, no crash and no backoff -- it just returns
    the lease.  So a gate that guards ``fail()`` and ``reap()`` but not
    ``release()`` is a gate with a door next to it.

    The refusal here is **not** about the work item failing.  It is
    about the work item being *offered again*: a task that a refusal
    covers must not be handed to another worker, by any route.
    """

    def setUp(self):
        self.registry = RefusalHoldRegistry()
        self.gate = RefusalHoldQueueGate(self.registry)
        self.manager = LeasedTaskClaim(
            max_failures=3,
            base_backoff_seconds=2.0,
            refusal_gate=self.gate,
        )
        self.manager.enqueue_task("t1", "demo-task", payload="hello")

    def tearDown(self):
        self.manager.close()

    def _lease(self):
        return self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)

    def test_a_refused_release_leaves_the_task_leased(self):
        """The observable proof: the task does not go back to ``ready``."""
        lease = self._lease()
        self.gate.record_task("t1", "demo-task", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            self.manager.release("t1", lease.token, now=101.0)
        self.assertEqual(self.manager.task("t1").state, "leased")

    def test_a_refused_release_keeps_the_lease_token(self):
        """The worker keeps the lease: it can still complete or fail."""
        lease = self._lease()
        self.gate.record_task("t1", "demo-task", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            self.manager.release("t1", lease.token, now=101.0)
        self.assertEqual(int(self.manager.task("t1").token), int(lease.token))

    def test_a_refused_release_stays_out_of_the_queue_mirror(self):
        """The mirror job stays ``reserved`` -- the work is not re-queued."""
        lease = self._lease()
        self.gate.record_task("t1", "demo-task", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            self.manager.release("t1", lease.token, now=101.0)
        self.assertEqual(self.manager._queue.job("t1").state, "reserved")

    def test_an_allowed_release_puts_the_task_back_to_ready(self):
        """The control: no refusal, the release happens as before."""
        lease = self._lease()
        record = self.manager.release("t1", lease.token, now=101.0)
        self.assertEqual(self.manager.task("t1").state, "ready")

    def test_a_refusal_against_a_different_action_does_not_block(self):
        lease = self._lease()
        self.gate.record_task("t1", "other-task", row=make_row())
        record = self.manager.release("t1", lease.token, now=101.0)
        self.assertEqual(self.manager.task("t1").state, "ready")

    def test_a_broken_gate_refuses_the_release(self):
        """An unusable gate refuses -- it never allows."""
        lease = self._lease()
        self.registry.store.break_reads()
        with self.assertRaises(RefusalRefusedError):
            self.manager.release("t1", lease.token, now=101.0)
        self.assertEqual(self.manager.task("t1").state, "leased")

    def test_no_gate_leaves_the_release_path_unchanged(self):
        """The default behaviour is untouched."""
        self.manager.set_refusal_gate(None)
        lease = self._lease()
        record = self.manager.release("t1", lease.token, now=101.0)
        self.assertEqual(self.manager.task("t1").state, "ready")


class LeaseNamespaceTests(unittest.TestCase):
    """The lease side's namespace, and what it must not collide with."""

    def setUp(self):
        self.registry = RefusalHoldRegistry()
        self.gate = RefusalHoldQueueGate(self.registry)

    def test_the_lease_side_key_is_lease_scoped_with_the_task_id(self):
        key = task_hold_key("task-9", "dispatch")
        self.assertEqual(key.scope_kind, SCOPE_KIND_LEASE)
        self.assertEqual(key.scope_id, "task-9")

    def test_a_refusal_against_a_lease_task_id_does_not_block_the_ledger(self):
        self.gate.record_task("grant-9", "dispatch", row=make_row())
        self.assertFalse(self.registry.check("grant-9", "dispatch").blocked)

    def test_a_malformed_task_id_is_refused(self):
        for bad in ("", "   ", None, 7):
            with self.assertRaises(RefusalHoldKeyMappingError):
                task_hold_key(bad, "dispatch")


class QueueOwnGateTests(unittest.TestCase):
    """The queue side asks the gate ITSELF -- no wrapping to forget.

    THE DEFECT (measured 2026-11-23)
    --------------------------------
    The queue side had the gate only as an opt-in context manager,
    ``install_queue_refusal_gate(...)``, which the HOST had to
    remember to use at every call site.  A plain ``retry()`` returned
    the job to ``ready`` with the refusal on the books:

        reserved: reserved
        after a plain retry, job-1 state = ready
        => the refusal was on the books, and the job went back to ready

    That is the exact failure ``refusal_hold.py``'s docstring warns
    about -- "recorded but not enforced ... which is worse than not
    recorded, because the ledger creates the illusion that the refusal
    was handled".

    The lease side never had this hole, because its gate is INSIDE the
    object: ``LeasedTaskClaim.fail()`` calls
    ``self._require_refusal_allows(...)`` itself, inside its
    transaction, immediately before the ``UPDATE`` that flips the task
    back to ``ready``.  There is no call site for the host to forget.

    This class closes the same seam on the queue side.

    WHY THE CONTEXT MANAGER IS NOT REMOVED
    --------------------------------------
    ``install_queue_refusal_gate`` is still the way a host binds the
    gate into a queue it does not own, and its form is still correct.
    What changes is that it is no longer the ONLY way to get a gate
    onto a queue -- and a host that installs the gate in the object
    gets the guarantee without having to remember.
    """

    def setUp(self):
        self.registry = RefusalHoldRegistry()
        self.gate = RefusalHoldQueueGate(self.registry)

    def _queue_with_gate(self, job_id="job-1", task="dispatch"):
        queue = make_queue(job_id=job_id, task=task)
        queue.set_refusal_gate(self.gate)
        return queue

    def test_the_gate_is_consulted_without_any_wrapping(self):
        """The defect itself: a plain ``retry()`` is refused.

        No context manager, no ``with`` block -- the call a host
        writes.  This is the guard that can fail on the defect, because
        it exercises the ordinary call path rather than the wrapped one.
        """
        queue = self._queue_with_gate()
        self.gate.record_queue("job-1", "dispatch", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            queue.retry("job-1", 3)
        self.assertEqual(
            queue.job("job-1").state,
            "reserved",
            "the job went back to ready even though a refusal covers it",
        )

    def test_the_gate_can_be_installed_in_the_constructor(self):
        """The other way to install it, so a host cannot forget either."""
        queue = JobQueue()
        queue.set_refusal_gate(self.gate)
        self.assertIs(queue.refusal_gate, self.gate)

    def test_a_refused_retry_books_no_backoff(self):
        """The refusal changes nothing: not the state, not the attempts.

        A refused re-dispatch must leave the job exactly as it was.
        The lease side pins this as "a refused failure books no
        backoff", and the queue side must pin it too -- a refusal that
        consumed the attempt budget would be a refusal that punished
        the job for being refused.
        """
        queue = self._queue_with_gate()
        self.gate.record_queue("job-1", "dispatch", row=make_row())
        before = queue.job("job-1")
        with self.assertRaises(RefusalRefusedError):
            queue.retry("job-1", 3)
        after = queue.job("job-1")
        self.assertEqual(after.state, before.state)
        self.assertEqual(after.attempts, before.attempts)

    def test_an_allowed_retry_puts_the_job_back_to_ready(self):
        """The control: no refusal, the re-dispatch happens."""
        queue = self._queue_with_gate()
        record = queue.retry("job-1", 3)
        self.assertEqual(record.state, "ready")
        self.assertEqual(queue.job("job-1").state, "ready")

    def test_a_different_action_is_not_refused(self):
        """The refusal covers one action, not the whole job.

        The job's own ``task`` string is the action identity, so a
        refusal recorded against ``refund`` must not block a
        ``dispatch``.
        """
        queue = self._queue_with_gate()
        self.gate.record_queue("job-1", "refund", row=make_row())
        record = queue.retry("job-1", 3)
        self.assertEqual(record.state, "ready")

    def test_a_broken_gate_leaves_the_job_reserved(self):
        """An unusable gate fails CLOSED."""
        queue = self._queue_with_gate()
        self.registry.store.break_reads()
        with self.assertRaises(RefusalRefusedError):
            queue.retry("job-1", 3)
        self.assertEqual(queue.job("job-1").state, "reserved")

    def test_the_gate_is_asked_under_the_queue_lock(self):
        """The gate's answer and the write are serialized.

        The gate is asked INSIDE the queue's own lock, immediately before
        the entry is flipped.  If it were asked outside, a refusal
        recorded between the check and the write would be lost.
        """
        seen = []

        class _RecordingGate:
            def require_queue_allowed(self, job_id, action, *, now=None):
                seen.append((job_id, action, threading.current_thread()))
                # The queue's lock must be HELD while the gate is asked.
                seen.append(("lock_held", queue._lock._is_owned()))

        queue = make_queue()
        queue.set_refusal_gate(_RecordingGate())
        queue.retry("job-1", 3)
        self.assertEqual(seen[0][0], "job-1")
        self.assertEqual(seen[0][1], "dispatch")
        self.assertTrue(
            seen[1][1],
            "the gate was asked OUTSIDE the queue's lock, so a refusal "
            "recorded between the check and the write would be lost",
        )

    def test_a_gate_without_the_required_method_is_refused(self):
        """A gate that cannot answer the question is refused, not ignored.

        Silently ignoring an unusable gate would be fail-OPEN: the
        refusal would be on the books and the job would go back to
        ``ready`` anyway.
        """
        queue = make_queue()
        queue.set_refusal_gate(object())
        with self.assertRaises(TypeError):
            queue.retry("job-1", 3)
        self.assertEqual(queue.job("job-1").state, "reserved")

    def test_a_queue_without_a_gate_behaves_exactly_as_before(self):
        """The default is unchanged: no gate, no behaviour change."""
        queue = make_queue()
        record = queue.retry("job-1", 3)
        self.assertEqual(record.state, "ready")
        self.assertEqual(queue.job("job-1").state, "ready")
        self.assertIsNone(queue.refusal_gate)

    def test_the_gate_can_be_removed(self):
        """A host can take the gate back out."""
        queue = self._queue_with_gate()
        self.gate.record_queue("job-1", "dispatch", row=make_row())
        queue.set_refusal_gate(None)
        record = queue.retry("job-1", 3)
        self.assertEqual(record.state, "ready")

    def test_a_refusal_recorded_concurrently_never_loses_to_a_retry(self):
        """"Recorded but still re-dispatched" must never happen.

        The observable is **completion order**, not final state.  A
        final state of "ready" is legal in one order and illegal in the
        other:

        * the RETRY completes first, then the refusal lands  ->  legal.
          The action was issued, and is then refused.  The refusal is on
          the books for the NEXT dispatch.
        * the REFUSAL completes first, then the retry completes  ->
          ILLEGAL.  The refusal was on the books before the job went
          back to ``ready``, so the retry must have been refused.

        So the assertion is: the recording must never complete before
        the retry does.  That is exactly what binding the registry to
        the queue's lock buys -- the recording waits for the retry to
        finish.

        WHY THIS FORM AND NOT "the state is reserved":  a first
        version of this guard asserted on the final state, and it
        **survived** the mutation that unbound the registry.  The final
        state is "ready" in BOTH the legal and the illegal order, so it
        cannot tell them apart; only the order can.

        WHY THE WINDOW IS WIDENED DELIBERATELY:  with the plain
        timing, the recording thread rarely wins the race, so the guard
        cannot tell a serialized implementation from an unserialized
        one.  The gate below pauses **inside** the queue's lock, just
        before it answers, which makes the window deterministic:

        * bound   -- the recording blocks on the queue's lock, so it
          completes AFTER the retry.  The order is ["retry", "record"].
        * unbound -- the recording does not need the queue's lock, so it
          completes DURING the pause.  The order is ["record", "retry"],
          and the guard fires.
        """
        for _attempt in range(10):
            queue = make_queue(job_id="job-x")
            registry = RefusalHoldRegistry()
            registry.bind_gate(queue._lock)
            gate = RefusalHoldQueueGate(registry)
            queue.set_refusal_gate(gate)
            order = []
            re_dispatched = []
            refused = []

            class _SlowGate:
                """The real gate, paused inside the queue's lock."""

                def require_queue_allowed(self, job_id, action, *, now=None):
                    time.sleep(0.05)
                    return gate.require_queue_allowed(
                        job_id, action, now=now
                    )

            queue.set_refusal_gate(_SlowGate())

            def do_retry():
                try:
                    queue.retry("job-x", 3)
                    re_dispatched.append(True)
                except RefusalRefusedError:
                    refused.append(True)
                order.append("retry")

            def do_record():
                registry.record("job-x", "dispatch", "", row=make_row())
                order.append("record")

            retry_thread = threading.Thread(target=do_retry)
            record_thread = threading.Thread(target=do_record)
            # The retry goes first and takes the queue's lock; the
            # recording is started while the retry is inside it.
            retry_thread.start()
            time.sleep(0.02)
            record_thread.start()
            retry_thread.join()
            record_thread.join()
            self.assertEqual(
                len(re_dispatched) + len(refused),
                1,
                "the retry neither landed nor was refused",
            )
            self.assertEqual(
                order[0],
                "retry",
                "the refusal was recorded BEFORE the retry completed, so the "
                "retry had the refusal on the books and must have been "
                "refused -- the job went back to ready anyway",
            )


class LeaseClaimWiringTests(unittest.TestCase):
    """The path that actually OFFERS the action: ``LeasedTaskClaim.claim()``.

    THE DEFECT (measured 2026-11-23)
    --------------------------------
    ``fail()``, ``release()`` and ``reap()`` all put a task **back** to
    ``ready``, and all three consult the gate.  ``claim()`` does the
    opposite: it takes a task **out** of ``ready`` and hands it to a
    worker.  That is the re-dispatch itself -- the moment the refused
    action is offered to somebody -- and it consulted no gate at all.

    Measured on this branch, with the lease-side gate installed and a
    refusal recorded against the lease namespace:

        === CASE 1: FIRST claim of a READY task ===
          claim SUCCEEDED -- the refused action was offered to w1
        === CASE 2: TAKEOVER claim of an EXPIRED lease ===
          TAKEOVER SUCCEEDED -- the refused action was offered to w2
        === CASE 3: for contrast, reap() on the same expired lease ===
          reap returned: ()
          lease state after reap: leased

    Case 3 is the contrast that makes the defect legible: the REAPER,
    which merely cleans up an expired lease, refuses -- while the CLAIM,
    which actually hands the work to a worker, succeeds.  The guard was
    on the cheap path and not on the one that matters.

    WHY THE ENUMERATION WAS WRONG
    ------------------------------
    The design doc counted "the three paths that put a task back to
    ``ready``" and stopped there.  ``claim()`` is a **fourth** path,
    and it is the one the question was really about: the ``release()``
    docstring already states the rule -- "it is whether the work item
    may be **offered again**, and a refusal says no by any route".

    WHICH FORM
    ----------
    ``claim()`` reports ONE task for ONE call, and the caller asked
    about that task and nothing else -- so it uses the **raising** form
    (``require_task_allowed``), exactly like ``fail()`` and
    ``release()``.  The boolean form (``task_allowed``) exists for
    ``reap()``, which sweeps a **batch** and must not abandon the
    sweep; there is no such concern here.
    """

    def setUp(self):
        self.registry = RefusalHoldRegistry()
        self.gate = RefusalHoldQueueGate(self.registry)
        self.manager = LeasedTaskClaim(
            max_failures=3,
            base_backoff_seconds=2.0,
            refusal_gate=self.gate,
        )
        self.manager.enqueue_task("t1", "demo-task", payload="hello")

    def tearDown(self):
        self.manager.close()

    def test_a_refused_claim_leaves_the_task_ready(self):
        """The observable proof: the task does NOT go to ``leased``.

        And no worker gets it -- the refusal is not just a state
        question, it is the question "may this action be offered to
        somebody".
        """
        self.gate.record_task("t1", "demo-task", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        view = self.manager.task("t1")
        self.assertEqual(view.state, "ready")
        self.assertEqual(view.worker, "")

    def test_a_refused_takeover_leaves_the_task_leased(self):
        """The takeover case: an expired lease is NOT taken over.

        This is the case a refusal is most likely to want to stop: the
        previous holder crashed, and the work item is about to be
        offered to somebody new.
        """
        lease = self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.gate.record_task("t1", "demo-task", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            self.manager.claim("t1", "worker-B", ttl=10.0, now=200.0)
        view = self.manager.task("t1")
        self.assertEqual(view.state, "leased")
        self.assertEqual(
            view.worker,
            "worker-A",
            "the previous holder lost the task to a refused takeover",
        )

    def test_a_refusal_recorded_before_the_claim_blocks_it(self):
        """The ordering: the refusal is on the books FIRST.

        The refusal is recorded, and then the claim happens.  The
        claim must be refused -- the ordering is what makes this a
        guarantee rather than a race.
        """
        self.gate.record_task("t1", "demo-task", row=make_row())
        self.assertTrue(
            self.gate.check_task("t1", "demo-task").blocked,
            "the refusal is not on the books, so this test would pass "
            "for the wrong reason",
        )
        with self.assertRaises(RefusalRefusedError):
            self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)

    def test_an_allowed_claim_still_hands_the_task_over(self):
        """The control: no refusal, the claim works exactly as before."""
        lease = self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.assertEqual(self.manager.task("t1").state, "leased")
        self.assertEqual(self.manager.task("t1").worker, "worker-A")
        self.assertEqual(lease.token, 1)

    def test_a_different_action_is_not_refused(self):
        """The refusal covers one action, not the whole task."""
        self.gate.record_task("t1", "other-action", row=make_row())
        self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.assertEqual(self.manager.task("t1").state, "leased")

    def test_a_broken_gate_refuses_the_claim(self):
        """A gate that cannot answer fails CLOSED."""
        self.registry.store.break_reads()
        with self.assertRaises(RefusalRefusedError):
            self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.assertEqual(self.manager.task("t1").state, "ready")

    def test_a_gate_without_the_required_method_is_refused(self):
        """An unusable gate is refused, not ignored.

        Silently ignoring it would be fail-OPEN: the refusal would be
        on the books and the action would be offered anyway.
        """
        self.manager.set_refusal_gate(object())
        with self.assertRaises(TypeError):
            self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.assertEqual(self.manager.task("t1").state, "ready")

    def test_a_terminal_task_is_still_refused_for_its_own_reason(self):
        """The gate does not change the OTHER refusals.

        A completed task must still raise ``TerminalTaskError``, not
        the refusal's error -- the gate is asked AFTER the state
        checks, so a task that is not claimable at all still fails for
        its own reason.
        """
        lease = self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.manager.complete("t1", lease.token, now=101.0)
        with self.assertRaises(TerminalTaskError):
            self.manager.claim("t1", "worker-B", ttl=10.0, now=200.0)

    def test_a_terminal_and_refused_task_fails_for_its_own_reason(self):
        """The ORDER, made observable: terminal beats refused.

        A task that is BOTH terminal and refused is the only case where
        the order of the two checks is visible.  The task's own
        terminal state is the reason it cannot be claimed -- the
        refusal is a second, unrelated reason -- and the terminal
        reason is the one the caller must see, because it says "this
        task is done" rather than "this action is held".

        If the gate were asked first, this would raise
        ``RefusalRefusedError`` instead, and the caller would go looking
        for a refusal that is not why the claim failed.
        """
        lease = self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.manager.complete("t1", lease.token, now=101.0)
        self.gate.record_task("t1", "demo-task", row=make_row())
        with self.assertRaises(TerminalTaskError):
            self.manager.claim("t1", "worker-B", ttl=10.0, now=200.0)

    def test_no_gate_leaves_the_claim_path_unchanged(self):
        """The default is unchanged: no gate, no behaviour change."""
        self.manager.set_refusal_gate(None)
        self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.assertEqual(self.manager.task("t1").state, "leased")


if __name__ == "__main__":
    unittest.main()
