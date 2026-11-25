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


class _LyingGate:
    """A gate whose two forms answer the SAME question DIFFERENTLY.

    ``queue_allowed`` says "allowed"; ``require_queue_allowed`` raises.
    The two are supposed to be the same question, so a gate whose two
    forms disagree is a **host's bug** -- but the queue must not be
    more permissive because it happened to ask the permissive one.
    """

    def queue_allowed(self, job_id, action, *, now=None):
        return True

    def require_queue_allowed(self, job_id, action, *, now=None):
        raise RuntimeError("this action is refused")


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


#: The correspondence between the two ledgers' vocabularies.
#:
#: The lease ledger says ``ready`` / ``leased`` / ``completed`` / ``dead``;
#: the queue mirror says ``ready`` / ``reserved`` / ``done`` / ``dead``.
#: A guard that compares the two states directly compares two different
#: vocabularies and fails for the wrong reason, so the correspondence is
#: stated once, here.
MIRROR_OF = {
    "ready": "ready",
    "leased": "reserved",
    "completed": "done",
    "dead": "dead",
}


def _mirror_of(lease_state: str) -> str:
    """The mirror state a lease state must correspond to."""
    if lease_state not in MIRROR_OF:
        raise AssertionError(f"unknown lease state: {lease_state!r}")
    return MIRROR_OF[lease_state]


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


class MirrorReleaseInsideTransactionTests(unittest.TestCase):
    """The mirror's release must run INSIDE the lease transaction.

    THE DEFECT (measured 2026-11-23)
    --------------------------------
    ``_mirror_release`` was called **after** the lease transaction
    committed, in ``complete()``, ``fail()``, ``release()`` and
    ``reap()``.  Only ``claim()`` called its mirror inside the
    transaction.  A structural scan of the module:

        line 895:  def claim(...)     -> INSIDE   the transaction
        line 1108: def complete(...)  -> OUTSIDE  the transaction
        line 1185: def fail(...)      -> OUTSIDE  the transaction
        line 1230: def release(...)   -> OUTSIDE  the transaction
        line 1292: def reap(...)      -> OUTSIDE  the transaction

    The consequence is a **divergence between the two ledgers** that no
    guard could see, because every guard looked at only one of them.
    A refusal recorded in the **queue** namespace -- the mirror's own
    gate, and a namespace deliberately distinct from the lease's -- made
    the mirror's own ``retry()`` refuse, and that refusal arrived
    **after** the lease transaction had already committed:

        === (a) queue-namespace refusal on release ===
          release RAISED: RefusalRefusedError
          ledger state: ready
          mirror state: reserved
          audit kinds: ['task.enqueued', 'lease.claimed', 'lease.released']

    Three things are wrong at once:

    * the ledger says ``ready`` and the mirror says ``reserved`` -- the
      two ledgers disagree, which is exactly what ``QueueMirrorError``
      exists to prevent;
    * a ``lease.released`` audit row was written for a release that was
      **refused** -- the trail says the release happened;
    * the task was **stuck**: the ledger said ``ready`` (so the reaper
      found no lease to sweep) while the mirror said ``reserved`` (so
      the claim refused to reserve it again).  Neither the ledger nor
      the mirror would move it.

    WHY THE FIX IS "MOVE THE CALL INSIDE", AND NOT "SWALLOW IT"
    ----------------------------------------------------------
    Swallowing the mirror's refusal would hide it: the caller would
    believe the release happened, and the trail would say so, while
    the mirror kept the job reserved.  That is the "recorded but not
    enforced" failure the refusal hold's own docstring warns about.

    So the mirror's release moves **inside** the transaction.  A
    refusal then rolls the lease write back, and all three symptoms
    go away at once: the task stays **leased** by the same worker, no
    ``lease.released`` row is written, and the mirror stays
    ``reserved`` -- which is the state a leased task's mirror job is
    in.

    The two namespaces now say the SAME thing about the same write:
    a lease-namespace refusal and a queue-namespace refusal both leave
    the task leased and the mirror reserved.

    This is PRE-EXISTING, not a regression: measured against
    ``372f5225`` (before the ``claim()`` work) the same probe prints
    the same divergence, and the behaviour dates to the module's first
    commit ``1c7e44b1``.
    """

    def setUp(self):
        self.registry = RefusalHoldRegistry()
        self.gate = RefusalHoldQueueGate(self.registry)
        self.queue = JobQueue(refusal_gate=self.gate)
        self.manager = LeasedTaskClaim(queue=self.queue, refusal_gate=self.gate)
        self.manager.enqueue_task("t1", "demo-task", payload="hello")

    def tearDown(self):
        self.manager.close()

    def _lease(self):
        return self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)

    def _audit_kinds(self):
        return [row["kind"] for row in self.manager.audit_log()]

    def test_a_refused_release_leaves_the_task_leased(self):
        """A refused release is NOT a release.

        The release is the act of giving the lease back.  A refusal
        says the work item may not be **offered again**; it does not
        say the worker may not stop working on it.  So the refusal
        undoes the whole release -- the task stays leased, by the same
        worker, and the worker can still finish it.

        This is the semantics the lease-side gate already has (a
        lease-namespace refusal rolls the release back), and the
        queue-side refusal must agree with it.
        """
        lease = self._lease()
        self.gate.record_queue("t1", "demo-task", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            self.manager.release("t1", lease.token, now=101.0)
        view = self.manager.task("t1")
        self.assertEqual(view.state, "leased")
        self.assertEqual(view.worker, "worker-A")

    def test_a_refused_release_leaves_the_ledger_and_the_mirror_in_step(self):
        """The two ledgers must not disagree after a refused release.

        The two ledgers have different vocabularies, so they are
        compared through the correspondence between them: a task that
        is ``leased`` is ``reserved`` in the mirror, a task that is
        ``ready`` is ``ready``, a ``completed`` task is ``done`` and a
        ``dead`` task is ``dead``.
        """
        lease = self._lease()
        self.gate.record_queue("t1", "demo-task", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            self.manager.release("t1", lease.token, now=101.0)
        ledger = self.manager.task("t1").state
        mirror = self.queue.job("t1").state
        self.assertEqual(
            _mirror_of(ledger),
            mirror,
            f"the two ledgers disagree after a refused release: "
            f"the lease ledger says {ledger!r}, the mirror says {mirror!r}",
        )

    def test_a_refused_release_writes_no_released_audit_row(self):
        """The trail must not say a release happened when it did not.

        ``lease.released`` is the record of a release.  A refused
        release is not a release, and a trail that says it was is a
        trail that lies to whoever reads it after the fact.
        """
        lease = self._lease()
        self.gate.record_queue("t1", "demo-task", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            self.manager.release("t1", lease.token, now=101.0)
        self.assertNotIn(
            "lease.released",
            self._audit_kinds(),
            "the audit trail records a release that was refused",
        )

    def test_a_refused_release_leaves_the_worker_able_to_finish(self):
        """The worker keeps its lease, so it can still complete the task.

        This is the control for "the refusal undoes the whole
        release": if the release had half-happened, the worker would
        have lost the lease and could not finish the work it was doing.
        """
        lease = self._lease()
        self.gate.record_queue("t1", "demo-task", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            self.manager.release("t1", lease.token, now=101.0)
        record = self.manager.complete("t1", lease.token, now=102.0)
        self.assertEqual(record.message_id, "t1:completed")
        self.assertEqual(self.manager.task("t1").state, "completed")

    def test_a_refused_release_does_not_book_a_failure(self):
        """A refused release is not a failure.

        The failure budget counts *reported failures*; a refused
        release reports nothing, so it must not consume the budget.
        """
        lease = self._lease()
        self.gate.record_queue("t1", "demo-task", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            self.manager.release("t1", lease.token, now=101.0)
        self.assertEqual(self.manager.task("t1").failures, 0)

    def test_an_allowed_release_still_releases(self):
        """The control: without a refusal nothing changes."""
        lease = self._lease()
        record = self.manager.release("t1", lease.token, now=101.0)
        self.assertEqual(self.manager.task("t1").state, "ready")
        self.assertIn("lease.released", self._audit_kinds())

    def test_a_refused_release_in_the_lease_namespace_is_the_same(self):
        """Both namespaces say the same thing about the same write.

        The lease namespace refuses the write in the lease ledger's own
        transaction; the queue namespace refuses it in the mirror's.
        Both must leave the task leased and the mirror reserved.
        """
        lease = self._lease()
        self.gate.record_task("t1", "demo-task", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            self.manager.release("t1", lease.token, now=101.0)
        self.assertEqual(self.manager.task("t1").state, "leased")
        self.assertEqual(self.queue.job("t1").state, "reserved")

    def test_a_refused_failure_leaves_the_task_leased(self):
        """``fail()`` is a re-dispatch too, and its mirror call was outside.

        The same fix applies: a refused mirror release rolls the
        failure back, so the task keeps its lease and its failure
        count.
        """
        lease = self._lease()
        self.gate.record_queue("t1", "demo-task", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            self.manager.fail("t1", lease.token, reason="boom", now=101.0)
        view = self.manager.task("t1")
        self.assertEqual(view.state, "leased")
        self.assertEqual(view.failures, 0)
        self.assertEqual(self.queue.job("t1").state, "reserved")


class MirrorSweepTests(unittest.TestCase):
    """The sweep must not be abandoned because of one refused task.

    ``reap()`` sweeps a **batch** of expired leases.  A refusal there
    must skip ONE task, not stop the sweep -- and the skipped task
    must be left exactly as it was: leased in the ledger, reserved in
    the mirror.  A sweep that flipped the ledger and then failed to
    flip the mirror would leave the two out of step for that task too.
    """

    def setUp(self):
        self.registry = RefusalHoldRegistry()
        self.gate = RefusalHoldQueueGate(self.registry)
        self.queue = JobQueue(refusal_gate=self.gate)
        self.manager = LeasedTaskClaim(queue=self.queue, refusal_gate=self.gate)
        self.manager.enqueue_task("t1", "demo-task", payload="hello")
        self.manager.enqueue_task("t2", "demo-task", payload="hello")

    def tearDown(self):
        self.manager.close()

    def test_one_refused_task_does_not_stop_the_sweep(self):
        self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.manager.claim("t2", "worker-B", ttl=10.0, now=100.0)
        self.gate.record_queue("t1", "demo-task", row=make_row())
        swept = self.manager.reap(now=200.0)
        self.assertEqual([s.task_id for s in swept], ["t2"])

    def test_a_refused_task_stays_leased_in_the_ledger(self):
        self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.manager.claim("t2", "worker-B", ttl=10.0, now=100.0)
        self.gate.record_queue("t1", "demo-task", row=make_row())
        self.manager.reap(now=200.0)
        self.assertEqual(self.manager.task("t1").state, "leased")
        self.assertEqual(self.manager.task("t2").state, "ready")

    def test_a_refused_task_stays_reserved_in_the_mirror(self):
        """The skipped task's mirror job is NOT re-offered.

        The whole point of the skip: the work item is not handed out
        again.  If the mirror said ``ready`` while the ledger said
        ``leased``, the queue would hand out a task whose lease is
        still live.
        """
        self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.manager.claim("t2", "worker-B", ttl=10.0, now=100.0)
        self.gate.record_queue("t1", "demo-task", row=make_row())
        self.manager.reap(now=200.0)
        self.assertEqual(self.queue.job("t1").state, "reserved")
        self.assertEqual(self.queue.job("t2").state, "ready")

    def test_a_refused_task_is_not_swept_again_either(self):
        """A refused sweep leaves the task's lease to expire again.

        The next sweep asks again -- the refusal stays on the record,
        and the task is not silently swept on a later pass.
        """
        self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.gate.record_queue("t1", "demo-task", row=make_row())
        self.assertEqual(self.manager.reap(now=200.0), ())
        self.assertEqual(self.manager.reap(now=300.0), ())
        self.assertEqual(self.manager.task("t1").state, "leased")

    def test_a_refused_task_keeps_its_crash_count(self):
        """The crash budget is not consumed by a refused re-dispatch."""
        self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.gate.record_queue("t1", "demo-task", row=make_row())
        self.manager.reap(now=200.0)
        self.assertEqual(self.manager.task("t1").crashes, 0)


class MirrorTerminalStateTests(unittest.TestCase):
    """The mirror's TERMINAL transition: a completed task's job is DONE.

    THE DEFECT (measured 2026-11-23)
    --------------------------------
    `LeasedTaskClaim` keeps two ledgers: the lease ledger (SQLite) and the
    **queue mirror** (`job_queue.JobQueue`).  Every terminal path --
    `complete()` and a `fail()` that exhausts the budget -- calls
    `_mirror_release()`, which calls `queue.retry()`.  And `retry()` puts a
    job back to **ready** -- it is the re-dispatch operation.

    So a **completed** task's mirror job went back to `ready`:

        === a COMPLETED task's mirror job goes back to 'ready' ===
          mirror state after complete(): ready
          ledger state: completed

        === so the mirror can DEQUEUE a completed task's job ===
          dequeue -> t1
          mirror state now: reserved

        === the same for a DEAD task ===
          mirror state after fail(): ready
          ledger state: dead

    The mirror and the ledger now disagree: the ledger says the work is
    finished, the mirror says it is waiting to be handed out, and the mirror
    is the ledger the queue actually reads.  The lease side refuses the
    re-claim (`TerminalTaskError`), so the work is not re-run -- but the
    mirror advertises a finished work item as available, and the queue's
    own `dequeue` will hand it to a worker.

    The queue already has the right operation for this: `ack()`, which
    moves a reserved job to **done**.  `retry()` is for a job that goes
    back to being available; `ack()` is for a job that is finished.

    This is PRE-EXISTING, not a regression: measured against
    `372f5225` (before the `claim()` work) the two probes print the same
    output, and the behaviour dates to the module's first commit
    `1c7e44b1`.
    """

    def setUp(self):
        self.registry = RefusalHoldRegistry()
        self.gate = RefusalHoldQueueGate(self.registry)
        self.queue = JobQueue(refusal_gate=self.gate)
        self.manager = LeasedTaskClaim(queue=self.queue, refusal_gate=self.gate)
        self.manager.enqueue_task("t1", "demo-task", payload="hello")

    def tearDown(self):
        self.manager.close()

    def test_a_completed_task_is_done_in_the_mirror(self):
        """The mirror says DONE, because the ledger says COMPLETED."""
        lease = self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.manager.complete("t1", lease.token, now=101.0)
        self.assertEqual(self.manager.task("t1").state, "completed")
        self.assertEqual(
            self.queue.job("t1").state,
            "done",
            "a completed task's mirror job is still advertised as ready to "
            "be handed out",
        )

    def test_a_dead_task_is_not_ready_in_the_mirror(self):
        """The same for a task whose failure budget is exhausted."""
        manager = LeasedTaskClaim(
            queue=JobQueue(refusal_gate=self.gate),
            max_failures=1,
            refusal_gate=self.gate,
        )
        manager.enqueue_task("t2", "demo-task", payload="hello")
        lease = manager.claim("t2", "worker-A", ttl=10.0, now=100.0)
        manager.fail("t2", lease.token, reason="boom", now=101.0)
        self.assertEqual(manager.task("t2").state, "dead")
        self.assertNotEqual(
            manager._queue.job("t2").state,
            "ready",
            "a dead task's mirror job is still advertised as ready to be "
            "handed out",
        )
        manager.close()

    def test_a_completed_task_cannot_be_dequeued_from_the_mirror(self):
        """The observable consequence: the queue will not hand it out."""
        lease = self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.manager.complete("t1", lease.token, now=101.0)
        reserved = self.queue.dequeue(
            "worker-B", self.manager.queue_name_for("t1"), 500
        )
        self.assertIsNone(
            reserved,
            "the mirror handed out a COMPLETED task's job",
        )

    def test_a_released_task_is_still_ready_in_the_mirror(self):
        """The control: a released task really does go back to ready.

        This is the case `retry()` is FOR -- the work item is not
        finished, it is available again -- and the fix must not turn it
        into `done`.
        """
        lease = self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.manager.release("t1", lease.token, now=101.0)
        self.assertEqual(self.manager.task("t1").state, "ready")
        self.assertEqual(self.queue.job("t1").state, "ready")

    def test_a_reaped_task_is_still_ready_in_the_mirror(self):
        """And the crash path: reaped means available again, not done."""
        self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.manager.reap(now=200.0)
        self.assertEqual(self.manager.task("t1").state, "ready")
        self.assertEqual(self.queue.job("t1").state, "ready")

    def test_a_failed_task_that_still_has_budget_is_ready(self):
        """A failure with budget left is a re-dispatch, not a terminal."""
        manager = LeasedTaskClaim(
            queue=JobQueue(refusal_gate=self.gate),
            max_failures=3,
            refusal_gate=self.gate,
        )
        manager.enqueue_task("t3", "demo-task", payload="hello")
        lease = manager.claim("t3", "worker-A", ttl=10.0, now=100.0)
        manager.fail("t3", lease.token, reason="boom", now=101.0)
        self.assertEqual(manager.task("t3").state, "ready")
        self.assertEqual(manager._queue.job("t3").state, "ready")
        manager.close()


class QueueDequeueGateTests(unittest.TestCase):
    """``dequeue()`` hands the action out, so it consults the gate.

    THE DEFECT (measured 2026-11-23)
    --------------------------------
    The queue side's gate guarded ``retry()`` -- the path that puts a
    job back to ``ready`` -- and NOT ``dequeue()``, which takes a job
    **out** of ``ready`` and offers it to a worker.  A refusal says
    "this action may not be issued", and ``dequeue()`` is the moment it
    is issued.

        check job-1/send_email: blocked_by_refusal
        DEQUEUE RESULT: ('job-1', 'send_email', 'w-1')
        job state: reserved
        audit kinds: ['job.enqueued', 'job.dequeued']

    The refusal was on the books, the gate could answer it, and the
    action was handed to a worker anyway.

    **What exposed it: the asymmetry with the lease side.**  The lease
    side guards BOTH ``fail()`` (back to ``ready``) and ``claim()``
    (out of ``ready`` into a lease) -- and §11 of the design doc
    closed the ``claim()`` hole.  The queue side guarded only one of
    the two.  A gate that guards one route is a gate with a door next
    to it, and the door was the more direct one: ``dequeue()`` is the
    ordinary call a dispatcher writes.

    **Why this is not the same defect as §10's.**  §10's was "the gate
    exists but the host must remember to install it"; this one is "the
    gate IS installed and the path does not ask".  The fix is the same
    shape as the lease side's ``claim()``: ask the gate inside the
    object's own lock, immediately before the write.
    """

    def setUp(self):
        self.registry = RefusalHoldRegistry()
        self.gate = RefusalHoldQueueGate(self.registry)

    def _queue(self, job_id="job-1", task="dispatch", gate=None):
        queue = JobQueue()
        queue.enqueue(job_id, "q", task, DIGEST, 1)
        queue.set_refusal_gate(self.gate if gate is None else gate)
        return queue

    def test_a_refused_dequeue_does_not_hand_the_job_out(self):
        """The defect itself: the plain ``dequeue()`` is refused.

        No context manager and no wrapping -- the call a dispatcher
        writes.  This is the guard that can fail on the defect.
        """
        queue = self._queue()
        self.gate.record_queue("job-1", "dispatch", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            queue.dequeue("worker-1", "q", 2)
        self.assertEqual(
            queue.job("job-1").state,
            "ready",
            "the job was handed out even though a refusal covers it",
        )

    def test_a_refused_dequeue_leaves_no_worker_holding_the_job(self):
        """No worker, and no attempt booked."""
        queue = self._queue()
        self.gate.record_queue("job-1", "dispatch", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            queue.dequeue("worker-1", "q", 2)
        job = queue.job("job-1")
        self.assertEqual(job.worker_id, "")
        self.assertEqual(job.attempts, 0)

    def test_a_refused_dequeue_books_no_dequeued_audit_row(self):
        """The audit trail must not claim a hand-out that did not happen."""
        queue = self._queue()
        self.gate.record_queue("job-1", "dispatch", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            queue.dequeue("worker-1", "q", 2)
        kinds = [row["kind"] for row in queue.audit_log()]
        self.assertNotIn("job.dequeued", kinds)
        self.assertIn("job.enqueued", kinds)

    def test_an_allowed_dequeue_still_hands_the_job_out(self):
        """The control: no refusal, the dequeue works exactly as before."""
        queue = self._queue()
        got = queue.dequeue("worker-1", "q", 2)
        self.assertIsNotNone(got)
        self.assertEqual(got.job_id, "job-1")
        self.assertEqual(got.worker_id, "worker-1")
        self.assertEqual(queue.job("job-1").state, "reserved")

    def test_a_refusal_against_a_different_action_is_not_refused(self):
        """The refusal covers one action, not the whole queue."""
        queue = self._queue(task="dispatch")
        self.gate.record_queue("job-1", "other-action", row=make_row())
        got = queue.dequeue("worker-1", "q", 2)
        self.assertIsNotNone(got)

    def test_a_broken_gate_refuses_the_dequeue(self):
        """A gate that cannot answer fails CLOSED."""
        class _Broken:
            def require_queue_allowed(self, job_id, action, *, now=None):
                raise RuntimeError("the gate cannot answer")

        queue = self._queue(gate=_Broken())
        with self.assertRaises(RuntimeError):
            queue.dequeue("worker-1", "q", 2)
        self.assertEqual(queue.job("job-1").state, "ready")

    def test_a_gate_without_the_required_method_is_refused(self):
        """An unusable gate is refused, not ignored."""
        class _Mute:
            pass

        queue = self._queue(gate=_Mute())
        with self.assertRaises(TypeError):
            queue.dequeue("worker-1", "q", 2)
        self.assertEqual(queue.job("job-1").state, "ready")

    def test_no_gate_leaves_the_dequeue_path_unchanged(self):
        """The default is unchanged: no gate, no behaviour change."""
        queue = JobQueue()
        queue.enqueue("job-1", "q", "dispatch", DIGEST, 1)
        got = queue.dequeue("worker-1", "q", 2)
        self.assertIsNotNone(got)
        self.assertEqual(queue.job("job-1").state, "reserved")

    def test_the_gate_is_asked_under_the_queue_lock(self):
        """The gate's answer and the write are serialized.

        The refused job must not be observable as ``reserved`` from
        inside the gate's own call: the gate is asked BEFORE the
        write, so a recording that races the dequeue cannot be lost.
        """
        seen = []

        class _Watching:
            def require_queue_allowed(self, job_id, action, *, now=None):
                seen.append(queue.job(job_id).state)
                return None

        queue = self._queue(gate=_Watching())
        queue.dequeue("worker-1", "q", 2)
        self.assertEqual(
            seen,
            ["ready"],
            "the gate was asked AFTER the job was reserved, so a refusal "
            "recorded concurrently could be lost",
        )

    def test_a_refusal_recorded_concurrently_never_loses_to_a_dequeue(self):
        """'Recorded but still handed out' must never happen.

        The gate pauses inside the queue's lock just before it
        answers, so the recording thread gets in.  The refusal is
        recorded while the dequeue is in flight, and the dequeue must
        still refuse the job.
        """
        order = []

        class _Slow:
            def __init__(self):
                self.in_gate = threading.Event()
                self.resume = threading.Event()

            def require_queue_allowed(self, job_id, action, *, now=None):
                order.append("dequeue:gate")
                self.in_gate.set()
                self.resume.wait(5.0)
                order.append("dequeue:gate:done")
                raise RefusalRefusedError("refused")

        gate = _Slow()
        queue = self._queue(gate=gate)

        def record():
            gate.in_gate.wait(5.0)
            order.append("record")
            self.gate.record_queue("job-1", "dispatch", row=make_row())
            gate.resume.set()

        worker = threading.Thread(target=record)
        worker.start()
        try:
            with self.assertRaises(RefusalRefusedError):
                queue.dequeue("worker-1", "q", 2)
        finally:
            gate.resume.set()
            worker.join(5.0)

        self.assertEqual(queue.job("job-1").state, "ready")
        self.assertLess(
            order.index("record"),
            order.index("dequeue:gate:done"),
            "the refusal was recorded after the gate answered, so the "
            "dequeue had no way to see it",
        )


class RefusedCandidateDoesNotWedgeTheQueueTests(unittest.TestCase):
    """A refused candidate is SKIPPED, not a wedge on the whole queue.

    THE DEFECT (measured 2026-11-23)
    --------------------------------
    The first version of the ``dequeue()`` guard asked the gate about
    the HEAD of the eligible list only, and let a refused head block the
    whole dequeue.  The justification was "the queue's contract is
    FIFO-by-priority, so skipping the refused job would silently
    reorder the queue".

    That justification was wrong, because the refusal is scoped to ONE
    (job, action) pair and not to the queue.  And the consequence was
    that ONE refusal wedged the queue **permanently**:

        --- refused HEAD, two healthy jobs behind it ---
        dequeue raised: RefusalRefusedError
        states: [('j1', 'ready'), ('j2', 'ready'), ('j3', 'ready')]

        --- can the refused job ever be retired? ---
        ack   raised: JobStateError job j1 is ready, only reserved jobs may be acked
        dead  raised: JobStateError job j1 is ready, only reserved jobs may be killed
        retry raised: JobStateError job j1 is ready, only reserved jobs may be retried

        --- does j2 ever become reachable? ---
        dequeue raised: RefusalRefusedError   (x3, forever)

    Every terminal operation needs the job ``reserved``, and the refused
    job could never be reserved -- so it could never be retired.  And it
    blocked every job behind it, forever.  That is the refusal's own
    denial of service: the very thing the slice's own table says a
    refusal must not be able to do.

    So the gate is now asked about the candidates **in order**, and the
    first one it ALLOWS is handed out.
    """

    def setUp(self):
        self.registry = RefusalHoldRegistry()
        self.gate = RefusalHoldQueueGate(self.registry)

    def _queue(self, job_ids, task="dispatch"):
        queue = JobQueue(refusal_gate=self.gate)
        for index, job_id in enumerate(job_ids):
            queue.enqueue(job_id, "q", task, DIGEST, index + 1)
        return queue

    def test_a_refused_head_does_not_block_the_jobs_behind_it(self):
        """The defect: one refused job denied the queue to the rest."""
        queue = self._queue(["j1", "j2", "j3"])
        self.gate.record_queue("j1", "dispatch", row=make_row())
        got = queue.dequeue("worker-1", "q", 10)
        self.assertIsNotNone(got, "the refused head wedged the whole queue")
        self.assertEqual(got.job_id, "j2")
        self.assertEqual(queue.job("j1").state, "ready")
        self.assertEqual(queue.job("j2").state, "reserved")

    def test_the_refused_candidate_is_still_ready_and_still_eligible(self):
        """The skipped job is not consumed -- it is still in the queue."""
        queue = self._queue(["j1", "j2"])
        self.gate.record_queue("j1", "dispatch", row=make_row())
        queue.dequeue("worker-1", "q", 10)
        job = queue.job("j1")
        self.assertEqual(job.state, "ready")
        self.assertEqual(job.worker_id, "")
        self.assertEqual(job.attempts, 0, "the skipped job was attempted")
        self.assertIn("j1", queue.ready("q"))

    def test_the_refused_candidate_is_asked_about_first(self):
        """The queue's own order is kept: the head is asked about first.

        The skip must not REORDER the queue -- it only removes a job
        that is not eligible to be handed out anyway.
        """
        asked = []

        class _Watching:
            def require_queue_allowed(self, job_id, action, *, now=None):
                asked.append(job_id)
                if job_id == "j1":
                    raise RefusalRefusedError("refused")
                return None

        queue = JobQueue(refusal_gate=_Watching())
        for index, job_id in enumerate(["j1", "j2", "j3"]):
            queue.enqueue(job_id, "q", "dispatch", DIGEST, index + 1)
        got = queue.dequeue("worker-1", "q", 10)
        self.assertEqual(got.job_id, "j2")
        self.assertEqual(asked, ["j1", "j2"])

    def test_every_refused_candidate_raises_and_hands_nothing_out(self):
        """When nothing is allowed, the caller is told and nothing moves."""
        queue = self._queue(["j1", "j2"])
        self.gate.record_queue("j1", "dispatch", row=make_row())
        self.gate.record_queue("j2", "dispatch", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            queue.dequeue("worker-1", "q", 10)
        for job_id in ("j1", "j2"):
            job = queue.job(job_id)
            self.assertEqual(job.state, "ready")
            self.assertEqual(job.worker_id, "")
            self.assertEqual(job.attempts, 0)

    def test_every_refused_candidate_books_a_rejected_row(self):
        """The trail records the refusal, not a hand-out."""
        queue = self._queue(["j1", "j2"])
        self.gate.record_queue("j1", "dispatch", row=make_row())
        self.gate.record_queue("j2", "dispatch", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            queue.dequeue("worker-1", "q", 10)
        kinds = [row["kind"] for row in queue.audit_log()]
        self.assertNotIn("job.dequeued", kinds)
        self.assertIn("job.rejected", kinds)

    def test_a_broken_gate_is_NOT_skipped(self):
        """A gate that cannot answer must fail the whole call, closed.

        The skip is only sound for a per-JOB refusal.  A broken gate is
        a property of the GATE, and skipping it would turn a broken
        gate into a silently degraded queue -- fail-OPEN.

        The gate here fails on the FIRST job and works on the second,
        which is what makes the guard able to tell the two behaviours
        apart:

        * not skipped -- the error reaches the caller and NOTHING is
          handed out;
        * skipped -- the broken job is passed over and the NEXT job is
          handed out, which is the fail-open this guard forbids.

        A gate that fails on EVERY job cannot distinguish the two: it
        raises in both versions.  So the guard asks about the shape of
        the OUTCOME, not just whether an error was raised.
        """
        class _BrokenOnFirst:
            def __init__(self):
                self.calls = 0

            def require_queue_allowed(self, job_id, action, *, now=None):
                self.calls += 1
                if self.calls == 1:
                    raise RuntimeError("the gate cannot answer")
                return None

        queue = JobQueue(refusal_gate=_BrokenOnFirst())
        for index, job_id in enumerate(["j1", "j2"]):
            queue.enqueue(job_id, "q", "dispatch", DIGEST, index + 1)
        with self.assertRaises(RuntimeError):
            queue.dequeue("worker-1", "q", 10)
        for job_id in ("j1", "j2"):
            self.assertEqual(
                queue.job(job_id).state,
                "ready",
                "a job was handed out behind a broken gate",
            )

    def test_an_unreadable_store_hands_out_nothing(self):
        """A gate that cannot READ refuses everything -- fail-closed.

        The hold's own answer for an unreadable store is
        ``blocked_store_unreadable``, which is refusal-shaped, so the
        candidate is skipped like any other refusal.  That is safe
        because EVERY candidate gets the same answer: the skip walks
        the whole eligible list and hands nothing out.

        This guard pins that the fail-closed direction survives the
        skip -- the skip must not become a way to hand out a job when
        the hold cannot read its own store.
        """
        registry = RefusalHoldRegistry()
        gate = RefusalHoldQueueGate(registry)
        gate.record_queue("j1", "dispatch", row=make_row())
        # Break the store the gate reads.
        store = registry.hold.store
        store._entries = {}

        class _Unreadable:
            def require_queue_allowed(self, job_id, action, *, now=None):
                raise RefusalRefusedError(
                    "the store cannot answer", reason="blocked_store_unreadable"
                )

        queue = JobQueue(refusal_gate=_Unreadable())
        for index, job_id in enumerate(["j1", "j2"]):
            queue.enqueue(job_id, "q", "dispatch", DIGEST, index + 1)
        with self.assertRaises(RefusalRefusedError):
            queue.dequeue("worker-1", "q", 10)
        for job_id in ("j1", "j2"):
            self.assertEqual(queue.job(job_id).state, "ready")

    def test_a_gate_without_the_required_method_is_NOT_skipped(self):
        """An unusable gate is refused, not ignored -- and not skipped.

        The gate offers no usable method at all, so every job fails.
        The gate raises ``TypeError`` on the FIRST job; if the skip
        were applied to it, the call would carry on and hand out a job
        behind a broken gate.  So the TypeError must reach the caller
        and nothing must be handed out.
        """
        class _Mute:
            pass

        queue = JobQueue(refusal_gate=_Mute())
        for index, job_id in enumerate(["j1", "j2"]):
            queue.enqueue(job_id, "q", "dispatch", DIGEST, index + 1)
        with self.assertRaises(TypeError):
            queue.dequeue("worker-1", "q", 10)
        for job_id in ("j1", "j2"):
            self.assertEqual(queue.job(job_id).state, "ready")

    def test_the_skipped_candidate_is_audited_by_the_gate(self):
        """The skip must leave a trail.

        The queue's own audit trail records the hand-out (``job.dequeued``
        for the job that WAS handed out) and, when nothing could be
        handed out, the rejection.  The skipped candidate's refusal is
        audited by the **gate**, which books a ``checked`` event with
        ``blocked=True`` -- the same place every other check is audited
        (§8: the queue side reaches the registry, so the check is
        audited like every other check).

        Without that event, a host could not tell "the queue skipped a
        refused job" from "the queue never looked at it".
        """
        queue = self._queue(["j1", "j2"])
        self.gate.record_queue("j1", "dispatch", row=make_row())
        got = queue.dequeue("worker-1", "q", 10)
        self.assertEqual(got.job_id, "j2")
        checks = [
            (event["key"], event["blocked"])
            for event in self.registry.events()
            if event["kind"] == "checked"
        ]
        self.assertIn(("queue:j1:dispatch", True), checks)
        self.assertIn(("queue:j2:dispatch", False), checks)

    def test_a_refusal_scoped_to_another_action_does_not_skip_anything(self):
        """The control: a refusal about a DIFFERENT action blocks nothing."""
        queue = self._queue(["j1", "j2"])
        self.gate.record_queue("j1", "other-action", row=make_row())
        got = queue.dequeue("worker-1", "q", 10)
        self.assertEqual(got.job_id, "j1")

    def test_a_refused_job_cannot_be_retired_and_does_not_need_to_be(self):
        """The wedge had two halves; both are gone.

        The refused job stays ``ready``, so it is not retried (a retry
        needs ``reserved``) -- but that no longer matters, because the
        job BEHIND it is reachable.  The point of this guard is that the
        two halves of the old wedge cannot be reassembled: nothing about
        the refused job's state can stop the rest of the queue.
        """
        queue = self._queue(["j1", "j2"])
        self.gate.record_queue("j1", "dispatch", row=make_row())
        got = queue.dequeue("worker-1", "q", 10)
        self.assertEqual(got.job_id, "j2")
        # The refused job is still ready, and still blocked.
        self.assertEqual(queue.job("j1").state, "ready")
        with self.assertRaises(RefusalRefusedError):
            queue.dequeue("worker-1", "q", 11)
        # ... and the healthy job was really handed out.
        self.assertEqual(queue.job("j2").state, "reserved")

    def test_the_mirror_may_NOT_fall_back_to_another_tasks_job(self):
        """The skip is safe in the queue and NOT safe in the mirror.

        The mirror reserves a **fixed** task's job -- there is no "the
        next one" for it to fall back to, and handing out a DIFFERENT
        task's job would break the correspondence between the two
        ledgers, which is what ``QueueMirrorError`` exists to prevent.

        Each mirror task has its OWN queue (``task:<id>``), so the
        mirror's reservation has exactly one candidate; the skip has
        nothing to skip to, and the refusal is taken.
        """
        queue = JobQueue(refusal_gate=self.gate)
        manager = LeasedTaskClaim(queue=queue)
        try:
            manager.enqueue_task("t1", "demo-task", payload="hello")
            manager.enqueue_task("t2", "demo-task", payload="world")
            self.assertNotEqual(
                queue.job("t1").queue,
                queue.job("t2").queue,
                "the mirror must give each task its own queue, or the "
                "skip could hand out another task's job",
            )
            self.gate.record_queue("t1", "demo-task", row=make_row())
            with self.assertRaises(RefusalRefusedError):
                manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
            self.assertEqual(manager.task("t1").state, "ready")
            self.assertEqual(queue.job("t1").state, "ready")
            self.assertEqual(queue.job("t2").state, "ready")
        finally:
            manager.close()


class RefusedCandidatesAreAllAuditedTests(unittest.TestCase):
    """The queue's OWN trail must name EVERY candidate it refused.

    §16 landed the skip: the gate is asked about the candidates in the
    queue's own order and the first one it ALLOWS is handed out.  That
    fix is correct, but it left the **audit trail** naming only the
    FIRST refused candidate -- and naming NONE at all when a later
    candidate was allowed.

    Measured 2026-11-24, on the tree as §16 left it:

        --- ONE refused head + 1 healthy -> handed j2
           job.rejected rows: 0 -> []
        --- BOTH refused -> raised RefusalRefusedError
           job.rejected rows: 1 -> [(10, {'reason': 'RefusalRefusedError', 'job_id': 'j1'})]
        --- THREE refused -> raised RefusalRefusedError
           job.rejected rows: 1 -> [(10, {'reason': 'RefusalRefusedError', 'job_id': 'j1'})]

    Read the middle and bottom rows together: **three** candidates were
    refused and the trail named **one** of them.  And the top row is
    worse: the refused head left NO trace at all in the queue's own
    trail, because a healthy job was handed out instead and the
    rejection was never booked.

    So a host reading the queue's trail cannot tell "the queue skipped
    a refused job" from "the queue never looked at it" -- the very
    distinction the registry's `checked` event exists to make (§8).  The
    registry's trail *does* carry the truth; the queue's own trail does
    not.

    The guard named ``test_every_refused_candidate_books_a_rejected_row``
    claims the stronger property and does not hold it: it asserts
    ``assertIn("job.rejected", kinds)``, which one row satisfies.  A
    guard whose NAME says "every" must count them.

    What the trail must now say, in both shapes:

    * a candidate the gate refused is named -- **who** was refused and
      **why**;
    * and the rows are per-candidate: N refused candidates, N rows.
    """

    def setUp(self):
        self.registry = RefusalHoldRegistry()
        self.gate = RefusalHoldQueueGate(self.registry)

    def _queue(self, job_ids, task="dispatch"):
        queue = JobQueue(refusal_gate=self.gate)
        for index, job_id in enumerate(job_ids):
            queue.enqueue(job_id, "q", task, DIGEST, index + 1)
        return queue

    def _rejected(self, queue):
        return [
            row for row in queue.audit_log() if row["kind"] == "job.rejected"
        ]

    def test_a_skipped_candidate_is_named_in_the_queue_trail(self):
        """The defect: a skipped head left NO row in the queue's trail."""
        queue = self._queue(["j1", "j2"])
        self.gate.record_queue("j1", "dispatch", row=make_row())
        got = queue.dequeue("worker-1", "q", 10)
        self.assertEqual(got.job_id, "j2", "the healthy job was not handed out")
        rejected = self._rejected(queue)
        self.assertEqual(
            [row["detail"].get("job_id") for row in rejected],
            ["j1"],
            "the refused head left no trace in the queue's own trail",
        )

    def test_every_refused_candidate_is_named_not_just_the_first(self):
        """N refused candidates, N rows -- not one row for the first."""
        queue = self._queue(["j1", "j2", "j3"])
        for job_id in ("j1", "j2", "j3"):
            self.gate.record_queue(job_id, "dispatch", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            queue.dequeue("worker-1", "q", 10)
        rejected = self._rejected(queue)
        self.assertEqual(
            [row["detail"].get("job_id") for row in rejected],
            ["j1", "j2", "j3"],
            "the trail named one refused candidate out of three",
        )

    def test_the_rejected_row_names_the_reason_and_the_action(self):
        """A row that says only "rejected" is not an audit trail.

        The operator's question is "what was refused, and why".  So the
        row names the job, the reason slug the gate gave, and the action
        the refusal was about.
        """
        queue = self._queue(["j1", "j2"])
        self.gate.record_queue("j1", "dispatch", row=make_row())
        queue.dequeue("worker-1", "q", 10)
        rejected = self._rejected(queue)
        self.assertEqual(len(rejected), 1)
        detail = rejected[0]["detail"]
        self.assertEqual(detail.get("job_id"), "j1")
        self.assertEqual(detail.get("reason"), "RefusalRefusedError")
        self.assertEqual(
            detail.get("action"),
            "dispatch",
            "the row does not name the action that was refused",
        )

    def test_the_refusal_slug_is_carried_not_just_the_class_name(self):
        """The class name is not the reason.

        ``RefusalRefusedError`` is the *shape* of the refusal; the
        *slug* says which condition produced it
        (``blocked_by_refusal``, ``blocked_store_unreadable``, ...).
        The class name is the same for all of them, so a trail built
        from the class name alone cannot tell a recorded refusal from
        an unreadable store.
        """
        queue = self._queue(["j1", "j2"])
        self.gate.record_queue("j1", "dispatch", row=make_row())
        queue.dequeue("worker-1", "q", 10)
        detail = self._rejected(queue)[0]["detail"]
        self.assertEqual(
            detail.get("refusal_reason"),
            "blocked_by_refusal",
            "the trail does not say WHICH condition refused the candidate",
        )

    def test_the_trail_and_the_registry_trail_agree_on_the_count(self):
        """Two trails, one truth: they must not disagree.

        The registry books one ``checked`` event per candidate (§8).  The
        queue's own trail books one ``job.rejected`` row per REFUSED
        candidate.  So the number of rejected rows must equal the number
        of the registry's blocked checks -- no more, no fewer.
        """
        queue = self._queue(["j1", "j2", "j3"])
        for job_id in ("j1", "j2"):
            self.gate.record_queue(job_id, "dispatch", row=make_row())
        queue.dequeue("worker-1", "q", 10)
        blocked_checks = [
            event for event in self.registry.events()
            if event["kind"] == "checked" and event["blocked"]
        ]
        self.assertEqual(len(blocked_checks), 2)
        self.assertEqual(
            len(self._rejected(queue)),
            len(blocked_checks),
            "the two trails disagree about how many candidates were refused",
        )

    def test_an_allowed_candidate_books_no_rejected_row(self):
        """The control: the trail does not invent refusals."""
        queue = self._queue(["j1"])
        queue.dequeue("worker-1", "q", 10)
        self.assertEqual(self._rejected(queue), [])
        kinds = [row["kind"] for row in queue.audit_log()]
        self.assertIn("job.dequeued", kinds)

    def test_a_broken_gate_books_no_rejected_row(self):
        """A broken gate is not a refusal -- it must not be recorded as one.

        A broken gate fails the whole call; it refuses nothing in
        particular.  Booking a ``job.rejected`` row for it would put a
        refusal in the trail that never happened.
        """
        class _Broken:
            def require_queue_allowed(self, job_id, action, *, now=None):
                raise RuntimeError("the gate cannot answer")

        queue = JobQueue(refusal_gate=_Broken())
        for index, job_id in enumerate(["j1", "j2"]):
            queue.enqueue(job_id, "q", "dispatch", DIGEST, index + 1)
        with self.assertRaises(RuntimeError):
            queue.dequeue("worker-1", "q", 10)
        self.assertEqual(self._rejected(queue), [])

    def test_the_rejected_rows_come_before_the_hand_out(self):
        """The trail is chronological: the refusals, then the hand-out."""
        queue = self._queue(["j1", "j2"])
        self.gate.record_queue("j1", "dispatch", row=make_row())
        queue.dequeue("worker-1", "q", 10)
        kinds = [row["kind"] for row in queue.audit_log()]
        self.assertLess(
            kinds.index("job.rejected"),
            kinds.index("job.dequeued"),
            "the trail shows the hand-out before the refusal that caused it",
        )

    def test_the_rejected_row_books_the_same_seq_as_the_call(self):
        """One call, one seq -- and the refusals are booked under it."""
        queue = self._queue(["j1", "j2"])
        self.gate.record_queue("j1", "dispatch", row=make_row())
        queue.dequeue("worker-1", "q", 10)
        rejected = self._rejected(queue)
        self.assertEqual(len(rejected), 1)
        self.assertEqual(
            rejected[0]["seq"],
            10,
            "the rejection was booked under a different seq than the call",
        )

    def test_the_rejected_row_carries_no_payload(self):
        """The audit boundary still holds: no payload crosses it."""
        queue = self._queue(["j1", "j2"])
        self.gate.record_queue("j1", "dispatch", row=make_row())
        queue.dequeue("worker-1", "q", 10)
        detail = self._rejected(queue)[0]["detail"]
        for banned in ("payload", "payload_bytes", "value", "raw"):
            self.assertNotIn(banned, detail)

    def test_a_malformed_identity_is_audited_as_a_refusal_not_a_hand_out(self):
        """A malformed identity must not vanish from the trail.

        A job whose task name cannot become a hold key (it carries a
        colon) is refused by the gate with ``blocked_key_invalid``.  The
        job cannot be handed out -- and the trail must say so, naming
        the job, rather than leaving no trace at all.
        """
        queue = JobQueue(refusal_gate=self.gate)
        queue.enqueue("j1", "q", "ns:op", DIGEST, 1)
        queue.enqueue("j2", "q", "dispatch", DIGEST, 2)
        got = queue.dequeue("worker-1", "q", 10)
        self.assertEqual(got.job_id, "j2")
        rejected = self._rejected(queue)
        self.assertEqual(
            [row["detail"].get("job_id") for row in rejected],
            ["j1"],
            "the malformed job left no trace in the queue's trail",
        )
        self.assertEqual(
            rejected[0]["detail"].get("refusal_reason"),
            "blocked_key_invalid",
        )
        self.assertEqual(queue.job("j1").state, "ready")


class RefusedRetryIsAuditedTests(unittest.TestCase):
    """A refused RE-DISPATCH must be named in the queue's own trail.

    §17 fixed the hand-out side: every refused **candidate** now books
    its own ``job.rejected`` row.  The re-dispatch side had the same
    gap, and the same shape of blindness.

    Measured 2026-11-24, on the tree as §17 left it:

        retry() raised: RefusalRefusedError

        What an operator reading the QUEUE trail sees:
            job.enqueued {'job_id': 'j1', ...}
            job.dequeued {'job_id': 'j1', 'queue': 'q', 'worker_id': 'w', ...}
        job state: reserved

        What the REGISTRY trail sees:
            recorded queue:j1:dispatch blocked= False None
            checked  queue:j1:dispatch blocked= True blocked_by_refusal

    Read the two trails together.  The queue's trail says "dequeued,
    then nothing" -- which is **indistinguishable from a worker that
    died mid-flight**.  The registry's trail knows the re-dispatch was
    refused, but the registry is a *different* ledger, and a host
    reading the queue's own audit cannot tell a refusal from a crash.

    And the **batch** form is worse.  ``retry_allowed()`` returns
    ``None`` for "not re-dispatched", and it uses the boolean gate
    form, which catches the gate's exception and throws it away:

        retry_allowed -> None
          (the reason is GONE: the batch form returns a bare None)

    So on the batch path the reason is lost *entirely* -- not even the
    registry's event survives with the right shape, because the gate
    was asked through the boolean form and the exception never
    reached the caller.

    The rule this pins: **the same gate, the same queue, the same
    trail.**  A refusal that stops a hand-out is named; a refusal that
    stops a re-dispatch is named too.
    """

    def setUp(self):
        self.registry = RefusalHoldRegistry()
        self.gate = RefusalHoldQueueGate(self.registry)

    def _reserved(self, job_id="j1", task="dispatch"):
        """A job that is enqueued and RESERVED, with the gate installed."""
        queue = JobQueue(refusal_gate=self.gate)
        queue.enqueue(job_id, "q", task, DIGEST, 1)
        queue.set_refusal_gate(None)
        queue.dequeue("worker-1", "q", 2)
        queue.set_refusal_gate(self.gate)
        return queue

    def _rejected(self, queue):
        return [
            row for row in queue.audit_log() if row["kind"] == "job.rejected"
        ]

    def test_a_refused_retry_is_named_in_the_queue_trail(self):
        """The defect: a refused re-dispatch left NO row."""
        queue = self._reserved()
        self.gate.record_queue("j1", "dispatch", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            queue.retry("j1", 3)
        rejected = self._rejected(queue)
        self.assertEqual(
            [row["detail"].get("job_id") for row in rejected],
            ["j1"],
            "the refused re-dispatch left no trace in the queue's own trail",
        )

    def test_the_refused_retry_row_names_the_action_and_the_slug(self):
        """The row says WHO, WHAT and WHY -- not merely "rejected"."""
        queue = self._reserved()
        self.gate.record_queue("j1", "dispatch", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            queue.retry("j1", 3)
        detail = self._rejected(queue)[0]["detail"]
        self.assertEqual(detail.get("job_id"), "j1")
        self.assertEqual(detail.get("action"), "dispatch")
        self.assertEqual(
            detail.get("refusal_reason"),
            "blocked_by_refusal",
            "the trail does not say WHICH condition refused the re-dispatch",
        )

    def test_a_refused_retry_allowed_is_named_in_the_queue_trail(self):
        """The BATCH form books a row too.

        ``retry_allowed()`` is the form a sweep uses, so it is the form
        most likely to run unattended -- and the form whose refusal
        was the most invisible.
        """
        queue = self._reserved()
        self.gate.record_queue("j1", "dispatch", row=make_row())
        self.assertIsNone(queue.retry_allowed("j1", 3))
        rejected = self._rejected(queue)
        self.assertEqual(
            [row["detail"].get("job_id") for row in rejected],
            ["j1"],
            "the refused batch re-dispatch left no trace in the trail",
        )

    def test_the_batch_form_does_not_lose_the_reason(self):
        """The batch form must not throw the reason away.

        ``retry_allowed()`` returns ``None`` -- a bare "no".  The row
        it books must still carry the hold's reason slug, or a sweep's
        refusal is unexplainable.
        """
        queue = self._reserved()
        self.gate.record_queue("j1", "dispatch", row=make_row())
        queue.retry_allowed("j1", 3)
        detail = self._rejected(queue)[0]["detail"]
        self.assertEqual(
            detail.get("refusal_reason"),
            "blocked_by_refusal",
            "the batch form lost the reason: the refusal is unexplained",
        )

    def test_the_raising_and_the_batch_form_book_the_same_row(self):
        """Two forms, one truth: the rows must agree.

        The two forms are one writer (``_retry``), so a refusal must
        leave the same trail whichever form asked.
        """
        raising = self._reserved()
        self.gate.record_queue("j1", "dispatch", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            raising.retry("j1", 3)

        batch = self._reserved()
        self.gate.record_queue("j1", "dispatch", row=make_row())
        batch.retry_allowed("j1", 3)

        self.assertEqual(
            self._rejected(raising)[0]["detail"],
            self._rejected(batch)[0]["detail"],
            "the two forms left different trails",
        )

    def test_an_allowed_retry_books_no_rejected_row(self):
        """The control: the trail does not invent refusals."""
        queue = self._reserved()
        record = queue.retry("j1", 3)
        self.assertEqual(record.state, "ready")
        self.assertEqual(self._rejected(queue), [])
        kinds = [row["kind"] for row in queue.audit_log()]
        self.assertIn("job.retried", kinds)

    def test_a_broken_gate_books_no_rejected_row(self):
        """A broken gate is not a refusal -- it must not be recorded as one.

        A broken gate fails the call (or fails the batch closed), but
        it refuses nothing in particular.  Booking a ``job.rejected``
        row for it would put a refusal in the trail that never
        happened.
        """
        class _Broken:
            def require_queue_allowed(self, job_id, action, *, now=None):
                raise RuntimeError("the gate cannot answer")

        queue = JobQueue(refusal_gate=_Broken())
        queue.enqueue("j1", "q", "dispatch", DIGEST, 1)
        queue.set_refusal_gate(None)
        queue.dequeue("worker-1", "q", 2)
        queue.set_refusal_gate(_Broken())
        with self.assertRaises(RuntimeError):
            queue.retry("j1", 3)
        self.assertEqual(self._rejected(queue), [])

    def test_a_refused_retry_leaves_the_job_exactly_where_it_was(self):
        """The row is a record; it must not change the job.

        A refused re-dispatch must leave the state, the attempts and
        the backoff exactly as they were.  The existing guard pins the
        state and the attempts; this one pins that booking the row did
        not disturb them either.
        """
        queue = self._reserved()
        self.gate.record_queue("j1", "dispatch", row=make_row())
        before = queue.job("j1")
        with self.assertRaises(RefusalRefusedError):
            queue.retry("j1", 3)
        after = queue.job("j1")
        self.assertEqual(after.state, before.state)
        self.assertEqual(after.attempts, before.attempts)
        self.assertEqual(after.worker_id, before.worker_id)

    def test_the_trail_and_the_registry_trail_agree_on_the_refusal(self):
        """One gate call, one refusal, one row in each trail."""
        queue = self._reserved()
        self.gate.record_queue("j1", "dispatch", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            queue.retry("j1", 3)
        blocked_checks = [
            event for event in self.registry.events()
            if event["kind"] == "checked" and event["blocked"]
        ]
        self.assertEqual(
            len(blocked_checks), 1, "the gate was asked more than once"
        )
        self.assertEqual(
            len(self._rejected(queue)),
            len(blocked_checks),
            "the two trails disagree about how many refusals there were",
        )

    def test_the_refused_retry_row_books_the_calls_seq(self):
        """One call, one seq -- and the refusal is booked under it."""
        queue = self._reserved()
        self.gate.record_queue("j1", "dispatch", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            queue.retry("j1", 3)
        rejected = self._rejected(queue)
        self.assertEqual(len(rejected), 1)
        self.assertEqual(
            rejected[0]["seq"], 3, "the refusal was booked under another seq"
        )

    def test_the_refused_retry_row_carries_no_payload(self):
        """The audit boundary still holds: no payload crosses it."""
        queue = self._reserved()
        self.gate.record_queue("j1", "dispatch", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            queue.retry("j1", 3)
        detail = self._rejected(queue)[0]["detail"]
        for banned in ("payload", "payload_bytes", "value", "raw"):
            self.assertNotIn(banned, detail)

    def test_a_non_string_reason_is_not_written_into_the_trail(self):
        """The slug slot holds a slug or nothing -- never a stray value.

        A host that re-implements the gate's contract may raise an
        error whose ``reason`` attribute is not a string.  The row's
        ``refusal_reason`` slot documents a **slug**, so a non-string
        must not land there: the trail is machine-read, and a number or
        a list in a slot that says "slug" is a value the reader cannot
        interpret.
        """
        class _OddReason:
            def require_queue_allowed(self, job_id, action, *, now=None):
                raise RefusalRefusedError("refused", reason=12345)

        queue = JobQueue(refusal_gate=_OddReason())
        queue.enqueue("j1", "q", "dispatch", DIGEST, 1)
        queue.set_refusal_gate(None)
        queue.dequeue("worker-1", "q", 2)
        queue.set_refusal_gate(_OddReason())
        with self.assertRaises(RefusalRefusedError):
            queue.retry("j1", 3)
        detail = self._rejected(queue)[0]["detail"]
        self.assertIsNone(
            detail.get("refusal_reason"),
            "a non-string reason was written into the slug slot",
        )
        self.assertEqual(
            detail.get("reason"),
            "RefusalRefusedError",
            "the class name must still say that a refusal happened",
        )

    def test_a_refused_retry_is_still_visible_to_a_later_sweep(self):
        """A refusal is not a one-off: the trail shows the history.

        The job stays ``reserved`` (a refusal does not release it), so
        a host that sweeps later sees the same refusal again.  The
        trail must then show **both** -- two refusals, two rows -- so
        the trail is a history and not a single snapshot.
        """
        queue = self._reserved()
        self.gate.record_queue("j1", "dispatch", row=make_row())
        with self.assertRaises(RefusalRefusedError):
            queue.retry("j1", 3)
        with self.assertRaises(RefusalRefusedError):
            queue.retry("j1", 4)
        rejected = self._rejected(queue)
        self.assertEqual(
            len(rejected), 2, "the trail shows one refusal where there were two"
        )
        self.assertEqual(
            [row["seq"] for row in rejected], [3, 4],
            "the refusals are not in the order they happened",
        )


class RecordSchemaPinIsVerifiedTests(unittest.TestCase):
    """The schema pin must be part of ``verify()``, not decoration.

    Every record this module books carries a ``schema`` field, and
    every record's ``verify()`` recomputes the digest and compares it.
    The schema is checked in the same expression:

        return recomputed == self.digest and (
            self.schema == JOB_QUEUE_SCHEMA
        )

    Measured 2026-11-24, by the whole-file census over
    ``job_queue.py`` (the accept probe's ``MUTANT`` check is an accept
    *metric*, not a census -- it stops at the first kill):

        MUTANT RESULT: killed 42/81

    and the survivors include the ``and`` that joins the digest check to
    the schema check, at **five** places -- ``EnqueueRecord``,
    ``DequeuedJob``, ``AckRecord``, ``DeadRecord`` and ``RetryRecord``.
    Inverting the schema comparison in all five at once:

        return recomputed == self.digest and (
            self.schema != JOB_QUEUE_SCHEMA
        )

    leaves the **whole suite green**.  So the schema pin was carried by
    every record and checked by none.

    **Why that matters.**  The schema pin is what says "this record is
    a ``northstar.job-queue.v1`` record".  A record from a *different*
    schema -- a future revision with a different field set, or a record
    that crossed a boundary it should not have -- would carry a digest
    computed over its own fields, and ``verify()`` would say True
    because the digest matched.  The digest says "this record is
    internally consistent"; the schema says "this record is the shape
    the reader expects".  A verifier that checks only the first is
    verifying the wrong thing.

    This is the same shape as §17's lesson, one level down: the
    property was **written** in the code, so every reader of the code
    believed it was **held**.  Nothing tested it.
    """

    def test_every_records_verify_is_true_for_a_real_record(self):
        """The control: the pin is not simply broken."""
        for record in self._real_records():
            self.assertTrue(
                record.verify(),
                f"{type(record).__name__}.verify() is False for a real record",
            )

    def test_every_record_rejects_a_foreign_schema(self):
        """The defect: a foreign schema verified as True.

        Flipping the comparison in the module made the whole suite
        green, so this is a real gap and not an equivalent mutant.
        """
        import dataclasses

        for record in self._real_records():
            forged = dataclasses.replace(record, schema="northstar.other.v1")
            self.assertFalse(
                forged.verify(),
                f"{type(record).__name__}.verify() accepted a record with a "
                f"foreign schema: {forged.schema!r}",
            )

    def test_every_record_rejects_an_empty_schema(self):
        """An empty schema is a foreign schema too."""
        import dataclasses

        for record in self._real_records():
            forged = dataclasses.replace(record, schema="")
            self.assertFalse(
                forged.verify(),
                f"{type(record).__name__}.verify() accepted an empty schema",
            )

    def test_the_digest_still_verifies(self):
        """The control for the control: the digest is not what changed.

        The schema check is *additional* to the digest check, not a
        replacement for it.  A record with the right schema and a
        wrong digest must still fail.
        """
        import dataclasses

        for record in self._real_records():
            forged = dataclasses.replace(record, digest="sha256:" + "0" * 64)
            self.assertFalse(
                forged.verify(),
                f"{type(record).__name__}.verify() accepted a wrong digest",
            )

    def test_every_record_type_is_covered(self):
        """All FIVE kinds are covered -- the count matters.

        The census found the survivor at five places, so a guard that
        checked one of them would be a predicate, not a count.  This
        guard names the kinds it expects, so a kind that is dropped
        from the set fails here.
        """
        expected = {
            "EnqueueRecord",
            "DequeuedJob",
            "AckRecord",
            "DeadRecord",
            "RetryRecord",
        }
        covered = {type(record).__name__ for record in self._real_records()}
        self.assertEqual(
            covered,
            expected,
            "the guard does not cover every record kind: a dropped kind "
            "would leave its schema pin unverified",
        )

    def _real_records(self):
        """One REAL record of every kind, made by the ledger itself.

        They are made by the queue, not hand-built, so the digests are
        the ones the module actually books.
        """
        from job_queue import JobQueue

        queue = JobQueue()
        enqueued = queue.enqueue("j1", "q", "dispatch", DIGEST, 1)
        dequeued = queue.dequeue("worker-1", "q", 2)
        acked = queue.ack("j1", 3)

        # A dead record: kill a reserved job outright.
        queue.enqueue("j2", "q", "dispatch", DIGEST, 4)
        queue.dequeue("worker-1", "q", 5)
        dead = queue.dead("j2", 6)

        # A retry record: a job that was retried successfully.
        queue.enqueue("j3", "q", "dispatch", DIGEST, 7)
        queue.dequeue("worker-1", "q", 8)
        retried = queue.retry("j3", 9)

        return (enqueued, dequeued, acked, dead, retried)


class RecordVerifyErrorTaxonomyTests(unittest.TestCase):
    """``verify()`` must ANSWER, not raise.

    Each record's ``verify()`` recomputes the digest and answers
    ``True`` or ``False``.  It wraps that computation in
    ``except JobQueueError: return False`` -- the shape that says "an
    unencodable record is not a verifying record", never "this call
    raised".

    Measured 2026-11-24, by the whole-file census over
    ``job_queue.py``: the mutant that turns that ``return False`` into
    ``return True`` in all five record types **survives** the whole
    suite.  The reason is not a weak guard -- it is that the clause is
    **dead** in the shipped configuration.

    ``_canonical()`` uses ``canonical_json.jcs_dumps()`` whenever the
    sibling helper is importable, and that raises ``JcsError`` -- a
    ``ValueError``, **not** a ``JobQueueError``.  So the
    ``except JobQueueError`` never fires, and an unencodable record
    makes ``verify()`` **raise** instead of answering ``False``.

    The stdlib fallback (``_cj is None``) *does* raise
    ``JobQueueError``, so the clause is live only there -- which is
    why the mutant survives the shipped configuration and dies in the
    fallback.

    **Why that matters.**  ``verify()`` is the module's integrity
    predicate.  A caller asks "is this record intact?" and gets an
    exception instead of an answer.  Worse, the exception is a
    ``ValueError``, so a caller guarding with ``except ValueError``
    treats a *tampered record* as a *parse error* and moves on --
    the record is neither verified nor rejected.
    """

    def _record_with(self, **fields):
        """A real record, with one field replaced."""
        import dataclasses

        from job_queue import AckRecord

        record = AckRecord(
            job_id="j1", attempts=1, digest=DIGEST, seq=1
        )
        return dataclasses.replace(record, **fields)

    def test_an_unencodable_record_answers_false_and_does_not_raise(self):
        """The defect: ``verify()`` raised instead of answering.

        A lone surrogate is the input the JCS canonicalizer refuses.
        """
        record = self._record_with(job_id="j\ud800x")
        try:
            answer = record.verify()
        except Exception as exc:  # noqa: BLE001 -- the point is the type
            self.fail(
                f"verify() raised {type(exc).__name__} instead of "
                f"answering False: {exc}"
            )
        self.assertFalse(
            answer,
            "an unencodable record must not verify",
        )

    def test_a_non_finite_field_answers_false_and_does_not_raise(self):
        """The same, for a float the canonicalizer refuses."""
        record = self._record_with(attempts=float("inf"))
        try:
            answer = record.verify()
        except Exception as exc:  # noqa: BLE001 -- the point is the type
            self.fail(
                f"verify() raised {type(exc).__name__} instead of "
                f"answering False: {exc}"
            )
        self.assertFalse(
            answer,
            "a record with a non-finite field must not verify",
        )

    def test_the_answer_is_false_in_the_stdlib_fallback_too(self):
        """The two configurations must AGREE.

        The fallback raises ``JobQueueError`` and the shipped path
        raises ``JcsError``; both must answer ``False``.  Before the
        fix the shipped path raised and the fallback answered, so the
        two configurations disagreed about the same record.
        """
        import job_queue

        original = job_queue._cj
        try:
            for label, canonical in (
                ("shipped", original),
                ("fallback", None),
            ):
                job_queue._cj = canonical
                record = self._record_with(job_id="j\ud800x")
                try:
                    answer = record.verify()
                except Exception as exc:  # noqa: BLE001
                    self.fail(
                        f"{label}: verify() raised "
                        f"{type(exc).__name__} instead of answering "
                        f"False: {exc}"
                    )
                self.assertFalse(
                    answer,
                    f"{label}: an unencodable record must not verify",
                )
        finally:
            job_queue._cj = original

    def test_the_control_a_real_record_still_verifies(self):
        """The control: the fix did not break the working path."""
        from job_queue import JobQueue

        queue = JobQueue()
        record = queue.enqueue("j1", "q", "dispatch", DIGEST, 1)
        self.assertTrue(
            record.verify(),
            "a real record must still verify",
        )

    def test_every_record_kind_answers_false_for_an_unencodable_field(self):
        """The COUNT: all FIVE kinds, not just ``AckRecord``.

        Measured 2026-11-24 by the whole-file census over
        ``job_queue.py``: the mutant that turns ``return False`` into
        ``return True`` **survives** in ``DequeuedJob``,
        ``DeadRecord`` and ``RetryRecord`` -- and is killed in
        ``EnqueueRecord`` and ``AckRecord``.

        The reason is that the guard above uses ONE kind
        (``AckRecord``).  A guard that checks one kind is a predicate,
        not a count -- the §17 lesson, one level down.  Planting the
        mutant in ``DeadRecord.verify()`` alone leaves the whole suite
        green.
        """
        import dataclasses

        records = self._all_record_kinds()
        self.assertEqual(
            len(records),
            5,
            "the guard must cover every record kind",
        )
        for name, record in records.items():
            forged = dataclasses.replace(record, job_id="j\ud800x")
            try:
                answer = forged.verify()
            except Exception as exc:  # noqa: BLE001
                self.fail(
                    f"{name}.verify() raised {type(exc).__name__} instead "
                    f"of answering False: {exc}"
                )
            self.assertFalse(
                answer,
                f"{name}.verify() accepted an unencodable record",
            )

    def _all_record_kinds(self):
        """One REAL record of every kind, made by the ledger."""
        from job_queue import JobQueue

        queue = JobQueue()
        enqueued = queue.enqueue("j1", "q", "dispatch", DIGEST, 1)
        dequeued = queue.dequeue("worker-1", "q", 2)
        acked = queue.ack("j1", 3)

        queue2 = JobQueue()
        queue2.enqueue("j2", "q", "dispatch", DIGEST, 4)
        queue2.dequeue("worker-1", "q", 5)
        dead = queue2.dead("j2", 6)

        queue3 = JobQueue()
        queue3.enqueue("j3", "q", "dispatch", DIGEST, 7)
        queue3.dequeue("worker-1", "q", 8)
        retried = queue3.retry("j3", 9)

        return {
            "EnqueueRecord": enqueued,
            "DequeuedJob": dequeued,
            "AckRecord": acked,
            "DeadRecord": dead,
            "RetryRecord": retried,
        }


class StatsCountersAreVerifiedTests(unittest.TestCase):
    """Every counter in ``stats()`` must count what it says.

    Measured 2026-11-24 by the whole-file census over
    ``job_queue.py``: the mutant that flips ``_STATE_DONE`` to
    something else in ``stats()`` **survives** -- nothing asserted the
    ``done`` counter.

    And nothing in the repo reads it either: ``stats().done`` had no
    assertion anywhere, in the component suite or the repo suite.  So
    a counter that was silently wrong was also silently useless.
    """

    def test_every_counter_counts_what_it_says(self):
        """The counters, after a known sequence of transitions."""
        from job_queue import JobQueue

        queue = JobQueue()
        queue.enqueue("j1", "q", "dispatch", DIGEST, 1)
        queue.enqueue("j2", "q", "dispatch", DIGEST, 2)
        queue.enqueue("j3", "q", "dispatch", DIGEST, 3)
        queue.dequeue("worker-1", "q", 4)
        queue.ack("j1", 5)
        queue.dequeue("worker-1", "q", 6)
        queue.dead("j2", 7)

        stats = queue.stats()
        self.assertEqual(stats.ready, 1, "one job is still ready")
        self.assertEqual(stats.reserved, 0, "nothing is reserved")
        self.assertEqual(stats.done, 1, "one job was acked")
        self.assertEqual(stats.dead, 1, "one job was killed")
        self.assertEqual(stats.enqueued, 3, "three jobs were enqueued")
        self.assertEqual(stats.dequeued, 2, "two jobs were handed out")

    def test_the_done_counter_counts_only_acked_jobs(self):
        """A dead job is not a done job.

        The mutant that breaks this makes ``dead`` and ``done`` share
        a state, so the counter cannot tell a success from a failure.
        """
        from job_queue import JobQueue

        queue = JobQueue()
        queue.enqueue("j1", "q", "dispatch", DIGEST, 1)
        queue.dequeue("worker-1", "q", 2)
        queue.dead("j1", 3)
        self.assertEqual(queue.stats().done, 0)
        self.assertEqual(queue.stats().dead, 1)

        queue2 = JobQueue()
        queue2.enqueue("j2", "q", "dispatch", DIGEST, 1)
        queue2.dequeue("worker-1", "q", 2)
        queue2.ack("j2", 3)
        self.assertEqual(queue2.stats().done, 1)
        self.assertEqual(queue2.stats().dead, 0)

    def test_the_counters_add_up_to_the_ledger(self):
        """The counters must agree with each other.

        A guard that checks one counter cannot see another being
        wrong; this one checks the whole set against the ledger.
        """
        from job_queue import JobQueue

        queue = JobQueue()
        for index in range(4):
            queue.enqueue(
                f"j{index}", "q", "dispatch", DIGEST, index + 1
            )
        queue.dequeue("worker-1", "q", 5)
        queue.ack("j0", 6)
        queue.dequeue("worker-1", "q", 7)
        queue.dead("j1", 8)
        queue.dequeue("worker-1", "q", 9)

        stats = queue.stats()
        self.assertEqual(
            stats.ready + stats.reserved + stats.done + stats.dead,
            stats.enqueued,
            "the state counters do not add up to the number of jobs "
            "enqueued: a job is in two states or in none",
        )


class ValidationErrorsArePinpointedTests(unittest.TestCase):
    """A refusal must say **which** rule was broken.

    Measured 2026-11-24 by the whole-file census over
    ``job_queue.py``: **nine** mutants in the validation functions
    survive the whole suite --

        or@219   isinstance(job_id, bool) or not isinstance(job_id, str)
        gt@225   len(job_id) > 256
        or@286   priority < _PRIORITY_MIN or priority > _PRIORITY_MAX
        or@294   isinstance(max_retries, bool) or not isinstance(...)
        gt@312   delay_seqs > _MAX_INT
        or@318   isinstance(seq, bool) or not isinstance(seq, int)
        lt@320   seq < 0
        gt@427   abs(v) > _MAX_INT          (the fallback canonicalizer)
        or@431   v != v or v in (inf, -inf)  (the fallback canonicalizer)

    The reason is not that the validation is wrong -- measured, every
    bad input raises the RIGHT error type with the RIGHT message.  The
    reason is that the existing test asserts only the **base** class:

        with pytest.raises(JobQueueError):
            jq.enqueue(...)

    Every one of these errors IS a ``JobQueueError``, so a mutant that
    replaces a *specific* rule with a *different* specific rule -- a
    bool check for a str check, a bound moved by one -- still raises
    ``JobQueueError`` and the test still passes.

    A guard that asserts the base class cannot see which rule fired.
    This one asserts the **exact type** and the **message**, so the
    mutant has to break the rule it claims to check.
    """

    def _cases(self):
        """Every bad input, with the type and the message it owes."""
        from job_queue import (
            BadDelayError,
            BadDigestError,
            BadJobError,
            BadPriorityError,
            BadQueueError,
            BadRetryError,
            BadTaskError,
            SeqOrderError,
        )

        digest = "sha256:" + "d" * 64
        return [
            # (label, error type, a fragment of the message, the call)
            (
                "job_id must be a str",
                BadJobError,
                "job_id must be str",
                lambda q: q.enqueue(True, "q", "t", digest, 1),
            ),
            (
                "job_id must be a str (not a bool)",
                BadJobError,
                "job_id must be str",
                lambda q: q.enqueue(42, "q", "t", digest, 1),
            ),
            (
                "job_id must be non-empty",
                BadJobError,
                "job_id must be non-empty",
                lambda q: q.enqueue("", "q", "t", digest, 1),
            ),
            (
                "job_id must fit",
                BadJobError,
                "job_id exceeds 256 chars",
                lambda q: q.enqueue("x" * 257, "q", "t", digest, 1),
            ),
            (
                "queue must be non-empty",
                BadQueueError,
                "queue must be non-empty",
                lambda q: q.enqueue("j", "", "t", digest, 1),
            ),
            (
                "task must be non-empty",
                BadTaskError,
                "task must be non-empty",
                lambda q: q.enqueue("j", "q", "", digest, 1),
            ),
            (
                "digest must be a digest",
                BadDigestError,
                "payload_digest must be",
                lambda q: q.enqueue("j", "q", "t", "nope", 1),
            ),
            (
                "priority must be an int",
                BadPriorityError,
                "priority must be int",
                lambda q: q.enqueue("j", "q", "t", digest, 1, priority=True),
            ),
            (
                "priority must be in range",
                BadPriorityError,
                "priority must be in [-100, 100]",
                lambda q: q.enqueue(
                    "j", "q", "t", digest, 1, priority=101
                ),
            ),
            (
                "priority must be in range (low)",
                BadPriorityError,
                "priority must be in [-100, 100]",
                lambda q: q.enqueue(
                    "j", "q", "t", digest, 1, priority=-101
                ),
            ),
            (
                "max_retries must be an int",
                BadRetryError,
                "max_retries must be int",
                lambda q: q.enqueue(
                    "j", "q", "t", digest, 1, max_retries=True
                ),
            ),
            (
                "max_retries must be in range",
                BadRetryError,
                "max_retries must be in [1, 64]",
                lambda q: q.enqueue(
                    "j", "q", "t", digest, 1, max_retries=65
                ),
            ),
            (
                "delay_seqs must be an int",
                BadDelayError,
                "delay_seqs must be int",
                lambda q: q.enqueue(
                    "j", "q", "t", digest, 1, delay_seqs=True
                ),
            ),
            (
                "delay_seqs must be non-negative",
                BadDelayError,
                "delay_seqs must be non-negative",
                lambda q: q.enqueue(
                    "j", "q", "t", digest, 1, delay_seqs=-1
                ),
            ),
            (
                "delay_seqs must fit",
                BadDelayError,
                "delay_seqs exceeds safe range",
                lambda q: q.enqueue(
                    "j", "q", "t", digest, 1, delay_seqs=2**53
                ),
            ),
            (
                "seq must be an int",
                SeqOrderError,
                "seq must be int",
                lambda q: q.enqueue("j", "q", "t", digest, "x"),
            ),
            (
                "seq must not be a bool",
                SeqOrderError,
                "seq must be int",
                lambda q: q.enqueue("j", "q", "t", digest, True),
            ),
            (
                "seq must be non-negative",
                SeqOrderError,
                "seq must be non-negative",
                lambda q: q.enqueue("j", "q", "t", digest, -1),
            ),
            (
                "seq must fit",
                SeqOrderError,
                "seq exceeds the safe range",
                lambda q: q.enqueue("j", "q", "t", digest, 2**53),
            ),
        ]

    def _accepted_cases(self):
        """The values that are AT a limit and must be ACCEPTED.

        A guard that checks only "over the limit is refused" cannot see
        a mutant that moves the edge.  These are the legal values at
        each boundary, and they are what kills an edge mutant.
        """
        digest = "sha256:" + "d" * 64
        return [
            ("job_id at 256 chars", lambda q: q.enqueue(
                "x" * 256, "q", "t", digest, 1)),
            ("delay_seqs at the safe range", lambda q: q.enqueue(
                "j", "q", "t", digest, 1, delay_seqs=2**53 - 1)),
            ("seq at zero", lambda q: q.enqueue(
                "j", "q", "t", digest, 0)),
            ("max_retries at its minimum", lambda q: q.enqueue(
                "j", "q", "t", digest, 1, max_retries=1)),
            ("priority at its maximum", lambda q: q.enqueue(
                "j", "q", "t", digest, 1, priority=100)),
            ("priority at its minimum", lambda q: q.enqueue(
                "j", "q", "t", digest, 1, priority=-100)),
            ("queue at 128 chars", lambda q: q.enqueue(
                "j", "q" * 128, "t", digest, 1)),
        ]

    def test_each_limit_edge_value_is_accepted(self):
        """The edge is legal -- a mutant that moves it is caught here.

        The census reported four edge mutants that survived the case
        list alone: ``gt@225`` (job id length), ``gt@312``
        (delay_seqs), ``lt@320`` (seq sign) and the fallback's
        ``gt@427``.  All four move a boundary by one, and all four are
        killed by a case that says the boundary VALUE is legal.
        """
        from job_queue import JobQueue

        for label, call in self._accepted_cases():
            queue = JobQueue()
            try:
                call(queue)
            except Exception as exc:  # noqa: BLE001
                self.fail(
                    f"{label}: a legal value was refused with "
                    f"{type(exc).__name__}: {exc}"
                )

    def test_the_fallback_canonicalizer_refuses_the_same_inputs(self):
        """The fallback's own rules, which the census cannot see.

        The fallback branch is marked ``# pragma: no cover`` -- the
        repo declares it uncovered -- so a mutant there survives
        (the census's ``gt@427`` and ``or@431``).  But the fallback is
        a **configuration**, and §20 established that the two
        configurations must agree.

        So the fallback is exercised here, deliberately, with the
        same inputs.
        """
        import job_queue

        original = job_queue._cj
        try:
            job_queue._cj = None
            # The LAST legal integer must be accepted: a guard that
            # only checks "a big int is refused" cannot see the edge
            # move by one.
            job_queue._canonical([1, 2**53 - 1])
            for label, payload, fragment in (
                ("big int", [1, 2**53], "integer outside safe range"),
                ("non-finite float", [1, float("inf")],
                 "non-finite float refused"),
                ("unsupported type", [1, object()],
                 "unencodable type"),
            ):
                with self.assertRaises(
                    job_queue.JobQueueError, msg=f"fallback: {label}"
                ) as caught:
                    job_queue._canonical(payload)
                self.assertIn(
                    fragment,
                    str(caught.exception),
                    f"fallback: {label} -- the refusal does not say "
                    f"which rule was broken",
                )
        finally:
            job_queue._cj = original

    def test_the_fallback_and_the_shipped_path_agree_on_the_error_type(self):
        """The two configurations must use the module's OWN error type.

        This is §20's property, applied to the canonicalizer's rules
        rather than to the records: whatever each configuration
        refuses, it refuses with ``JobQueueError`` -- never with the
        sibling helper's ``JcsError``, which is what §20 found
        escaping.

        The two do NOT agree on *how much* they refuse, and need not:
        the fallback is **stricter** (it refuses an integer above the
        safe range, which the shipped path accepts and the JCS helper
        serializes losslessly as a double).  A stricter fallback is
        safe -- it refuses more, never less.  What would not be safe
        is the fallback refusing something the shipped path accepts
        *silently*, which is exactly what a differing error type
        looks like to a caller.
        """
        import job_queue

        original = job_queue._cj
        refusals = {
            "non-finite float": [1, float("inf")],
            "unsupported type": [1, object()],
        }
        try:
            for label, payload in refusals.items():
                for configuration, canonical in (
                    ("shipped", original),
                    ("fallback", None),
                ):
                    job_queue._cj = canonical
                    try:
                        job_queue._canonical(payload)
                        self.fail(
                            f"{label}/{configuration}: the input was "
                            f"accepted"
                        )
                    except job_queue.JobQueueError:
                        pass
                    except Exception as exc:  # noqa: BLE001
                        self.fail(
                            f"{label}/{configuration}: refused with "
                            f"{type(exc).__name__} instead of the "
                            f"module's own JobQueueError"
                        )
        finally:
            job_queue._cj = original

    def test_each_bad_input_raises_its_own_error_type(self):
        """The TYPE is pinned, not just the base class."""
        from job_queue import JobQueue

        for label, expected, message, call in self._cases():
            queue = JobQueue()
            with self.assertRaises(
                expected, msg=f"{label}: wrong error type"
            ):
                call(queue)

    def test_each_bad_input_says_which_rule_was_broken(self):
        """The MESSAGE names the rule."""
        from job_queue import JobQueue

        for label, expected, fragment, call in self._cases():
            queue = JobQueue()
            with self.assertRaises(expected) as caught:
                call(queue)
            self.assertIn(
                fragment,
                str(caught.exception),
                f"{label}: the refusal does not say which rule was "
                f"broken",
            )

    def test_the_case_list_covers_every_validation_rule(self):
        """The COUNT: a rule dropped from the list fails here.

        A guard that checked one bad input would be a predicate, not a
        count.  The list names 18 rules; a rule that loses its case
        fails this guard.
        """
        expected_rules = {
            "job_id must be a str",
            "job_id must be a str (not a bool)",
            "job_id must be non-empty",
            "job_id must fit",
            "queue must be non-empty",
            "task must be non-empty",
            "digest must be a digest",
            "priority must be an int",
            "priority must be in range",
            "priority must be in range (low)",
            "max_retries must be an int",
            "max_retries must be in range",
            "delay_seqs must be an int",
            "delay_seqs must be non-negative",
            "delay_seqs must fit",
            "seq must be an int",
            "seq must not be a bool",
            "seq must be non-negative",
            "seq must fit",
        }
        covered = {case[0] for case in self._cases()}
        self.assertEqual(
            covered,
            expected_rules,
            "the guard does not cover every validation rule: a rule "
            "that loses its case would leave its bound unverified",
        )

    def _other_field_cases(self):
        """The type and length rules of the OTHER four fields.

        Measured 2026-11-24: the census reported six more survivors in
        the validation functions once ``job_id``'s rules were pinned --
        ``or@231`` (queue type), ``or@243`` (worker id type), ``gt@249``
        (worker id length), ``or@255`` (task type), ``gt@261`` (task
        length) and ``or@267`` (digest type).

        Every field has the SAME three rules -- it must be a str, not a
        bool; it must be non-empty; it must fit -- so this table holds
        them all together.  A guard that pinned ``job_id``'s rules and
        left the other four fields alone is a predicate, not a count.
        """
        from job_queue import (
            BadDigestError,
            BadQueueError,
            BadTaskError,
            BadWorkerError,
        )

        digest = "sha256:" + "d" * 64
        return [
            (
                "queue must be a str",
                BadQueueError,
                "queue must be str",
                lambda q: q.enqueue("j", 42, "t", digest, 1),
            ),
            (
                "queue must not be a bool",
                BadQueueError,
                "queue must be str",
                lambda q: q.enqueue("j", True, "t", digest, 1),
            ),
            (
                "queue must fit",
                BadQueueError,
                "queue exceeds 128 chars",
                lambda q: q.enqueue("j", "q" * 129, "t", digest, 1),
            ),
            (
                "task must be a str",
                BadTaskError,
                "task must be str",
                lambda q: q.enqueue("j", "q", 42, digest, 1),
            ),
            (
                "task must not be a bool",
                BadTaskError,
                "task must be str",
                lambda q: q.enqueue("j", "q", True, digest, 1),
            ),
            (
                "task must fit",
                BadTaskError,
                "task exceeds 256 chars",
                lambda q: q.enqueue("j", "q", "t" * 257, digest, 1),
            ),
            (
                "digest must be a str",
                BadDigestError,
                "payload_digest must be str",
                lambda q: q.enqueue("j", "q", "t", 42, 1),
            ),
            (
                "digest must not be a bool",
                BadDigestError,
                "payload_digest must be str",
                lambda q: q.enqueue("j", "q", "t", True, 1),
            ),
            (
                "worker_id must be a str",
                BadWorkerError,
                "worker_id must be str",
                lambda q: q.dequeue(42, "q", 1),
            ),
            (
                "worker_id must not be a bool",
                BadWorkerError,
                "worker_id must be str",
                lambda q: q.dequeue(True, "q", 1),
            ),
            (
                "worker_id must be non-empty",
                BadWorkerError,
                "worker_id must be non-empty",
                lambda q: q.dequeue("", "q", 1),
            ),
            (
                "worker_id must fit",
                BadWorkerError,
                "worker_id exceeds 256 chars",
                lambda q: q.dequeue("w" * 257, "q", 1),
            ),
        ]

    def test_every_other_field_has_its_own_error_type(self):
        """The TYPE, for the other four fields."""
        from job_queue import JobQueue

        for label, expected, fragment, call in self._other_field_cases():
            queue = JobQueue()
            with self.assertRaises(
                expected, msg=f"{label}: wrong error type"
            ):
                call(queue)

    def test_every_other_field_says_which_rule_was_broken(self):
        """The MESSAGE, for the other four fields."""
        from job_queue import JobQueue

        for label, expected, fragment, call in self._other_field_cases():
            queue = JobQueue()
            with self.assertRaises(expected) as caught:
                call(queue)
            self.assertIn(
                fragment,
                str(caught.exception),
                f"{label}: the refusal does not say which rule was "
                f"broken",
            )

    def test_the_other_fields_edge_values_are_accepted(self):
        """The edge is legal, for the other four fields."""
        from job_queue import JobQueue

        digest = "sha256:" + "d" * 64
        cases = [
            ("queue at 128 chars",
             lambda q: q.enqueue("j", "q" * 128, "t", digest, 1)),
            ("task at 256 chars",
             lambda q: q.enqueue("j", "q", "t" * 256, digest, 1)),
        ]
        for label, call in cases:
            queue = JobQueue()
            try:
                call(queue)
            except Exception as exc:  # noqa: BLE001
                self.fail(
                    f"{label}: a legal value was refused with "
                    f"{type(exc).__name__}: {exc}"
                )

        # The worker's edge is a dequeue, which needs a booked job.
        queue = JobQueue()
        queue.enqueue("j", "q", "t", digest, 1)
        try:
            queue.dequeue("w" * 256, "q", 2)
        except Exception as exc:  # noqa: BLE001
            self.fail(
                f"worker_id at 256 chars: a legal value was refused with "
                f"{type(exc).__name__}: {exc}"
            )

    def test_the_case_list_covers_every_other_field(self):
        """The COUNT: a rule dropped from the list fails here."""
        expected_rules = {
            "queue must be a str",
            "queue must not be a bool",
            "queue must fit",
            "task must be a str",
            "task must not be a bool",
            "task must fit",
            "digest must be a str",
            "digest must not be a bool",
            "worker_id must be a str",
            "worker_id must not be a bool",
            "worker_id must be non-empty",
            "worker_id must fit",
        }
        covered = {case[0] for case in self._other_field_cases()}
        self.assertEqual(
            covered,
            expected_rules,
            "the guard does not cover every other field's rules",
        )


class UnencodableIdentityIsAuditedTests(unittest.TestCase):
    """A rejected call must leave a trail row.

    ``enqueue()`` and the other mutators wrap their validation in
    ``except JobQueueError: self._reject(...); raise`` -- so a call
    refused for a bad shape books a ``job.rejected`` row naming the
    reason.

    Measured 2026-11-24: an identity the canonicalizer refuses (a lone
    surrogate) is refused **before** that clause, because the refusal
    is a ``JcsError``.  The call fails -- which is right -- but it
    books **no row**, so the trail cannot tell "the queue refused this
    job" from "the queue never saw it".

    This is the same property §17 and §18 established for refusals:
    a refusal that leaves no trace is invisible.
    """

    def test_an_unencodable_enqueue_books_a_rejected_row(self):
        from job_queue import JobQueue

        queue = JobQueue()
        with self.assertRaises(Exception):
            queue.enqueue("j\ud800x", "q", "dispatch", DIGEST, 1)
        kinds = [row["kind"] for row in queue.audit_log()]
        self.assertIn(
            "job.rejected",
            kinds,
            "a refused enqueue left no trail row: the trail cannot "
            "tell 'the queue refused this job' from 'the queue never "
            "saw it'",
        )

    def test_the_rejected_row_names_the_job(self):
        from job_queue import JobQueue

        queue = JobQueue()
        with self.assertRaises(Exception):
            queue.enqueue("j\ud800x", "q", "dispatch", DIGEST, 1)
        rejected = [
            row
            for row in queue.audit_log()
            if row["kind"] == "job.rejected"
        ]
        self.assertEqual(
            len(rejected),
            1,
            "the refusal must be booked exactly once",
        )
        self.assertEqual(
            rejected[0]["detail"]["job_id"],
            "j\ud800x",
            "the row must name the job that was refused",
        )

    def test_a_refused_dequeue_does_not_strand_the_job(self):
        """A refused hand-out must leave the job READY, not RESERVED.

        Measured before the fix: ``dequeue()`` raised, the entry stayed
        ``reserved``, and ``stats()`` reported ``reserved=1,
        dequeued=0`` -- a job nobody holds, that no worker ever got,
        and that the trail never mentioned.
        """
        from job_queue import JobQueue

        queue = JobQueue()
        queue.enqueue("j1", "q", "dispatch", DIGEST, 1)
        with self.assertRaises(Exception):
            queue.dequeue("w\ud800x", "q", 2)

        stats = queue.stats()
        self.assertEqual(
            stats.reserved,
            0,
            "a refused hand-out left the job reserved: nobody holds it "
            "and no worker ever got it",
        )
        self.assertEqual(
            stats.ready,
            1,
            "the refused job must still be offerable",
        )
        self.assertEqual(
            stats.dequeued,
            0,
            "a refused hand-out booked no dequeue",
        )

    def test_a_refused_dequeue_books_a_rejected_row(self):
        """The refusal is visible in the trail."""
        from job_queue import JobQueue

        queue = JobQueue()
        queue.enqueue("j1", "q", "dispatch", DIGEST, 1)
        with self.assertRaises(Exception):
            queue.dequeue("w\ud800x", "q", 2)
        kinds = [row["kind"] for row in queue.audit_log()]
        self.assertIn(
            "job.rejected",
            kinds,
            "a refused hand-out left no trail row",
        )
        self.assertNotIn(
            "job.dequeued",
            kinds,
            "a refused hand-out booked a dequeue it never made",
        )

    def test_the_job_is_still_handable_out_after_the_refusal(self):
        """The refusal is per-call, not permanent."""
        from job_queue import JobQueue

        queue = JobQueue()
        queue.enqueue("j1", "q", "dispatch", DIGEST, 1)
        with self.assertRaises(Exception):
            queue.dequeue("w\ud800x", "q", 2)
        record = queue.dequeue("w-good", "q", 3)
        self.assertIsNotNone(
            record,
            "the job must still be offerable after a refused hand-out",
        )
        self.assertEqual(record.job_id, "j1")


class SeqIsDigestFaithfullyTests(unittest.TestCase):
    """A record's digest must pin its ``seq``.

    ``canonical_json`` serializes an integer outside the safe range as
    an IEEE-754 **double** (RFC 8785 Appendix B note (2)), so two
    different seqs at ``|seq| >= 2**53`` canonicalize to the *same*
    bytes::

        jcs_dumps([2**53])   == b'[9007199254740992]'
        jcs_dumps([2**53+1]) == b'[9007199254740992]'

    So a **real** record's digest stops pinning its seq there, and a
    *tampered* seq still verifies:

        real DequeuedJob seq: 9007199254740992
        tampered seq:         9007199254740993   same digest
        tampered.verify() = True

    The stdlib fallback refuses that integer outright
    (``JobQueueError: integer outside safe range``), so the two
    configurations also disagreed about whether a large seq is legal
    at all.

    The repo's house pattern is to bound the counter: see
    ``grant_pin_ledger.py`` (``_MAX_COUNTER = 2**53 - 1``) and
    ``profiler.py`` (``record_digest()`` refuses a huge integral
    fail-closed).  ``job_queue.py``'s ``seq`` was the outlier: it was
    the one integer in a digest that was **unbounded**.
    """

    def test_a_seq_at_the_safe_range_is_accepted(self):
        """The upper edge of the safe range is legal."""
        from job_queue import JobQueue

        queue = JobQueue()
        record = queue.enqueue(
            "j1", "q", "dispatch", DIGEST, 2**53 - 1
        )
        self.assertEqual(record.seq, 2**53 - 1)
        self.assertTrue(record.verify())

    def test_a_seq_one_over_the_safe_range_is_refused(self):
        """One over is not."""
        from job_queue import JobQueue
        from job_queue import SeqOrderError

        queue = JobQueue()
        with self.assertRaises(SeqOrderError) as caught:
            queue.enqueue("j1", "q", "dispatch", DIGEST, 2**53)
        self.assertIn(
            "safe range",
            str(caught.exception),
            "the refusal must say why: an unbounded seq silently loses "
            "the digest's fidelity",
        )

    def test_a_tampered_seq_is_caught(self):
        """The property: a changed seq must not verify.

        At a small seq the digest already caught this.  The defect was
        that it did **not** at a large one.
        """
        import dataclasses

        from job_queue import JobQueue

        queue = JobQueue()
        queue.enqueue("j1", "q", "dispatch", DIGEST, 1)
        record = queue.dequeue("worker-1", "q", 2)
        tampered = dataclasses.replace(record, seq=3)
        self.assertFalse(
            tampered.verify(),
            "a record with a changed seq verified: the digest does not "
            "pin the seq",
        )

    def test_a_tampered_seq_is_caught_at_the_safe_range_edge(self):
        """The edge is where the loss was.

        At ``2**53 - 1`` -- the largest legal seq -- the digest must
        still pin the seq.  Before the bound, a seq of ``2**53`` and
        one of ``2**53 + 1`` canonicalized to the same bytes, so a
        tampered seq verified.
        """
        import dataclasses

        from job_queue import JobQueue

        queue = JobQueue()
        queue.enqueue("j1", "q", "dispatch", DIGEST, 1)
        record = queue.dequeue("worker-1", "q", 2**53 - 1)
        tampered = dataclasses.replace(record, seq=2**53 - 2)
        self.assertFalse(
            tampered.verify(),
            "a record with a changed seq verified at the safe range edge",
        )

    def test_every_mutator_refuses_an_oversized_seq(self):
        """The bound must hold on every mutator, not just ``enqueue``.

        A guard that checked one mutator would be a predicate, not a
        count.
        """
        from job_queue import JobQueue
        from job_queue import SeqOrderError

        big = 2**53
        queue = JobQueue()
        queue.enqueue("j1", "q", "dispatch", DIGEST, 1)
        queue.dequeue("worker-1", "q", 2)

        calls = {
            "enqueue": lambda: queue.enqueue(
                "j2", "q", "dispatch", DIGEST, big
            ),
            "dequeue": lambda: queue.dequeue("worker-2", "q", big),
            "ack": lambda: queue.ack("j1", big),
            "retry": lambda: queue.retry("j1", big),
        }
        for name, call in calls.items():
            with self.assertRaises(
                SeqOrderError, msg=f"{name} accepted an oversized seq"
            ):
                call()

    def test_a_refused_seq_does_not_consume_the_seq(self):
        """A bad seq is not a bad argument.

        The module's convention, measured: a malformed **seq** does
        not consume a seq and books no trail row, because the call
        never reached the ledger.  A malformed **argument** at a valid
        seq does consume it and books a row.  The oversized seq is a
        malformed seq, so it follows the first rule -- and the two
        rules must not be confused.
        """
        from job_queue import JobQueue
        from job_queue import SeqOrderError

        queue = JobQueue()
        with self.assertRaises(SeqOrderError):
            queue.enqueue("j1", "q", "dispatch", DIGEST, 2**53)
        # The refused seq did not consume the position.
        record = queue.enqueue("j1", "q", "dispatch", DIGEST, 5)
        self.assertEqual(
            record.seq,
            5,
            "the refused seq consumed the ledger position",
        )


if __name__ == "__main__":
    unittest.main()


class ChainGateBranchesAreReachedTests(unittest.TestCase):
    """The gate's FALLBACK branches, and the fail-closed catch.

    Measured 2026-11-24 by the whole-file census over the chain's own
    modules -- ``leased_task_claim.py`` and ``refusal_hold_wiring.py`` --
    which reported **four** survivors in the gate's own plumbing:

        leased_task_claim.py:666  the `return False` in the BOOLEAN
                                  method's `except Exception`
        leased_task_claim.py:677  the `return False` in the RAISING
                                  method's `except Exception`
        leased_task_claim.py:678  the `return True` after the raising
                                  method returned without raising
        leased_task_claim.py:1035 the `return True` when the mirror job
                                  is NOT `reserved`
        refusal_hold_wiring.py:753 the `>` in the event-cap's length test

    Three of them are in **the same helper**, and the reason is the
    same in all three:

        allows = getattr(gate, "task_allowed", None)
        if callable(allows):
            try:
                return bool(allows(task_id, action, now=now))
            except Exception:
                return False
        require = getattr(gate, "require_task_allowed", None)
        ...
        try:
            require(task_id, action, now=now)
        except Exception:
            return False
        return True

    The repo's own gate offers BOTH methods, so the boolean branch is
    always taken and the raising branch is **never** reached.  And the
    `except Exception` in the boolean branch is never taken either,
    because the repo's gate's boolean method does not raise -- it
    answers ``False``.

    So the whole fail-closed contract of this helper -- "a gate that
    cannot answer blocks" -- was **verified by nothing**.

    A fallback branch that nothing reaches is not a weak guard; it is
    an **unreached branch**, and the fix is to reach it.  These guards
    install gates that exercise each branch deliberately.
    """

    def _manager(self, gate):
        """A manager whose mirror is gated by the SAME gate.

        The manager's gate answers the *lease* question and the queue
        mirror's gate answers the *queue* question; the mirror's release
        is judged by the queue's gate.  Both are installed, so a guard
        that exercises the mirror is exercising the real wiring.
        """
        manager = LeasedTaskClaim(
            max_failures=3,
            base_backoff_seconds=2.0,
            queue=JobQueue(refusal_gate=gate),
            refusal_gate=gate,
        )
        self.addCleanup(manager.close)
        manager.enqueue_task("t1", "demo-task", payload="hello")
        return manager

    def test_a_gate_whose_boolean_method_raises_blocks_the_sweep(self):
        """A gate that CANNOT ANSWER must not be read as an ALLOW.

        The boolean method raises -- the store cannot be read.  The
        helper catches it and answers "not allowed", so the sweep
        skips this task.  If the catch answered "allowed" instead, the
        broken gate would be laundered into a re-dispatch: the task
        would go back to ``ready`` behind a gate that never answered.

        This is the fail-closed direction, and it is the one the
        census found nothing to hold it down.
        """
        class _BooleanRaises:
            """The gate's boolean method cannot answer."""

            def task_allowed(self, task_id, action, *, now=None):
                raise RuntimeError("the store cannot be read")

            def require_task_allowed(self, task_id, action, *, now=None):
                return None

            def require_queue_allowed(self, job_id, action, *, now=None):
                return None

        manager = self._manager(_BooleanRaises())
        manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        swept = manager.reap(now=200.0)
        self.assertEqual(
            swept, (),
            "a gate that could not answer was treated as an ALLOW: the "
            "task was re-dispatched behind a broken gate",
        )
        self.assertEqual(manager.task("t1").state, "leased")

    def test_the_boolean_helper_answers_false_when_the_gate_raises(self):
        """The helper itself: a raising boolean method is NOT allowed.

        This is the same contract as the guard above, one level down,
        so a mutant that changes the helper's answer fails here even
        if the sweep's own guard is also satisfied by accident.
        """
        class _BooleanRaises:
            def task_allowed(self, task_id, action, *, now=None):
                raise RuntimeError("the store cannot be read")

            def require_task_allowed(self, task_id, action, *, now=None):
                return None

            def require_queue_allowed(self, job_id, action, *, now=None):
                return None

        manager = self._manager(_BooleanRaises())
        self.assertFalse(
            manager._refusal_allows_reap("t1", "demo-task", 200.0),
            "a gate that raised was treated as allowing the re-dispatch",
        )

    def test_a_gate_that_only_offers_the_raising_method_blocks_the_sweep(self):
        """The FALLBACK branch: the boolean method is absent.

        The repo's own gate offers both methods, so the fallback --
        "ask the raising one instead" -- is never taken.  A gate that
        offers only the raising method is the shape a host that
        implements the gate's contract partially provides, and the
        fallback must still fail closed.

        Note the asymmetry, which is the point: the gate here refuses
        by RAISING, and the helper catches the raise and answers "not
        allowed".  It does not let the raise escape, because the sweep
        must not be abandoned by one refused task.
        """
        class _RaisingOnly:
            """Only the raising method -- the boolean one is absent."""

            def __init__(self):
                self.refuse = False

            def require_task_allowed(self, task_id, action, *, now=None):
                if self.refuse:
                    raise RuntimeError("this action is refused")

            def require_queue_allowed(self, job_id, action, *, now=None):
                if self.refuse:
                    raise RuntimeError("this action is refused")

        gate = _RaisingOnly()
        manager = self._manager(gate)
        # The claim happens while the gate allows: ``claim`` uses the
        # raising form directly, so a refusing gate stops the claim
        # before the sweep is ever reached.  The refusal is introduced
        # AFTER the lease exists, which is the state the sweep sees.
        manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        gate.refuse = True
        self.assertFalse(
            manager._refusal_allows_reap("t1", "demo-task", 200.0),
            "a refusal raised by the fallback branch was treated as "
            "allowing the re-dispatch",
        )

    def test_the_fallback_branch_allows_when_the_gate_does_not_refuse(self):
        """The CONTROL for the fallback: no refusal means allowed.

        Without this, a helper that answered "not allowed" forever
        would pass the guard above.  The two guards together pin the
        answer in BOTH directions.
        """
        class _RaisingOnly:
            def require_task_allowed(self, task_id, action, *, now=None):
                return None

            def require_queue_allowed(self, job_id, action, *, now=None):
                return None

        manager = self._manager(_RaisingOnly())
        self.assertTrue(
            manager._refusal_allows_reap("t1", "demo-task", 200.0),
            "a gate that did not refuse was treated as refusing the "
            "re-dispatch",
        )

    def test_a_mirror_job_that_is_not_reserved_needs_no_release(self):
        """The mirror's release is only owed for a RESERVED job.

        ``_mirror_release_allowed`` answers "is the mirror's release
        allowed?" -- and for a job that is not ``reserved`` there is
        nothing to release, so the answer is yes: the call is a no-op
        and must not block the sweep.

        The census found the ``return True`` here untested, so the
        answer was pinned in neither direction.
        """
        class _Both:
            def task_allowed(self, task_id, action, *, now=None):
                return True

            def require_task_allowed(self, task_id, action, *, now=None):
                return None

            def require_queue_allowed(self, job_id, action, *, now=None):
                return None

        manager = self._manager(_Both())
        manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        token = manager.task("t1").token
        manager.release("t1", token, now=105.0)
        self.assertEqual(
            manager._queue.job("t1").state,
            "ready",
            "the mirror job should be `ready` after a release",
        )
        self.assertTrue(
            manager._mirror_release_allowed("t1"),
            "a mirror job that is not `reserved` has nothing to "
            "release, so the release must be allowed",
        )

    def test_a_reserved_mirror_job_is_released_only_when_the_gate_allows(self):
        """The CONTROL for the guard above: `reserved` means it is owed.

        The two guards together pin the answer in both directions, so
        a helper that always answered the same thing fails one of them.
        """
        class _Both:
            def __init__(self):
                self.refuse = False

            def task_allowed(self, task_id, action, *, now=None):
                return not self.refuse

            def require_task_allowed(self, task_id, action, *, now=None):
                return None

            def require_queue_allowed(self, job_id, action, *, now=None):
                if self.refuse:
                    raise RefusalRefusedError(
                        "the queue-side action is refused",
                        reason=REASON_BLOCKED_BY_REFUSAL,
                    )

        gate = _Both()
        manager = self._manager(gate)
        manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.assertEqual(manager._queue.job("t1").state, "reserved")

        # The REFUSING answer first, while the job is still `reserved`:
        # the question "is the release allowed?" is only meaningful
        # while there is a release to make.
        gate.refuse = True
        self.assertFalse(
            manager._mirror_release_allowed("t1"),
            "a refusing gate must forbid the mirror's release",
        )
        self.assertEqual(
            manager._queue.job("t1").state,
            "reserved",
            "a refused mirror release moved the mirror's job anyway",
        )

        # And the ALLOWING answer on a fresh task: the two together
        # pin the answer in both directions.
        gate.refuse = False
        manager.enqueue_task("t2", "demo-task", payload="hello")
        manager.claim("t2", "worker-B", ttl=10.0, now=100.0)
        self.assertTrue(
            manager._mirror_release_allowed("t2"),
            "an allowed gate must permit the mirror's release",
        )


class TheEventCapIsHonouredTests(unittest.TestCase):
    """The wiring registry's audit trail is capped -- and the cap is a
    number, not a mood.

    Measured 2026-11-24 by the whole-file census over
    ``refusal_hold_wiring.py``: the event-cap's length test

        if len(self._events) > MAX_WIRING_EVENTS:
            del self._events[: len(self._events) - MAX_WIRING_EVENTS]

    survived, because no test ever put the registry over its cap.  A
    boundary that is never crossed is a boundary that is never tested.

    **But the mutation that survives here is an EQUIVALENT one.**
    Moving ``>`` to ``>=`` changes nothing, and the reason is
    arithmetic: at ``len(self._events) == MAX_WIRING_EVENTS`` the
    deletion ``self._events[: len(self._events) - MAX_WIRING_EVENTS]``
    is ``self._events[:0]`` -- a no-op.  So the two variants keep
    exactly the same trail for every number of events:

        MAX = 4096, 4106 events:
          ">"   -> 4096 kept, first is job-10,   last is job-4105
          ">="  -> 4096 kept, first is job-10,   last is job-4105

    Verified exhaustively for every ``n`` from 1 to ``MAX + 11`` and
    for MAX in {1, 2, 3, 5, 4096}: the two variants agree on every
    trail.  A mutant that changes no observable behaviour is an
    **equivalent mutant**, and no guard can kill it -- the honest
    thing is to say so rather than to claim the cap is now verified.

    So these guards do not target that mutation.  They pin the
    properties that ARE observable -- the cap's length, and WHICH end
    of the trail survives -- because a cap that kept the newest would
    silently discard the refusal recorded first, and a cap that let
    the trail grow would make the registry's memory unbounded.
    """

    def test_the_registry_keeps_exactly_the_cap(self):
        """At the cap, the trail holds exactly ``MAX_WIRING_EVENTS``."""
        from refusal_hold_wiring import MAX_WIRING_EVENTS

        registry = RefusalHoldRegistry()
        gate = RefusalHoldQueueGate(registry)
        for index in range(MAX_WIRING_EVENTS + 10):
            gate.check_queue(f"job-{index}", "dispatch")
        self.assertEqual(
            len(registry.events()),
            MAX_WIRING_EVENTS,
            "the registry's audit trail does not hold exactly the cap",
        )

    def test_the_cap_drops_the_OLDEST_events(self):
        """The cap drops the oldest, not the newest.

        A cap that kept the newest would silently discard the refusal
        that was recorded first -- the one a host reads to learn what
        happened.  So the guard asserts which end survives.
        """
        from refusal_hold_wiring import MAX_WIRING_EVENTS

        registry = RefusalHoldRegistry()
        gate = RefusalHoldQueueGate(registry)
        for index in range(MAX_WIRING_EVENTS + 5):
            gate.check_queue(f"job-{index}", "dispatch")
        keys = [event["key"] for event in registry.events()]
        self.assertEqual(
            keys[0],
            "queue:job-5:dispatch",
            "the cap dropped the newest events instead of the oldest",
        )
        self.assertEqual(
            keys[-1],
            f"queue:job-{MAX_WIRING_EVENTS + 4}:dispatch",
            "the newest event was dropped by the cap",
        )

    def test_the_cap_never_exceeds_the_limit(self):
        """The trail is never LONGER than the cap.

        The guard above proves the length at the cap; this one proves
        the cap is never exceeded, which is the property that makes
        the registry's memory bounded.
        """
        from refusal_hold_wiring import MAX_WIRING_EVENTS

        registry = RefusalHoldRegistry()
        gate = RefusalHoldQueueGate(registry)
        for index in range(MAX_WIRING_EVENTS + 1):
            gate.check_queue(f"job-{index}", "dispatch")
            self.assertLessEqual(
                len(registry.events()),
                MAX_WIRING_EVENTS,
                "the registry's audit trail grew past its cap",
            )


class TheBatchFormAgreesWithTheRaisingFormTests(unittest.TestCase):
    """``retry_allowed()`` and ``retry()`` must answer the SAME question.

    §17 gave the batch form its reason, and its own docstring says the
    gate "is consulted **once**, by the same writer that :meth:`retry`
    uses" -- but the two forms do **not** ask the gate the same
    question.

    ``retry()`` asks the **raising** form:
    ``require_queue_allowed(job_id, action, now=...)``.

    ``retry_allowed()`` asks the **boolean** form:
    ``queue_allowed(job_id, action, now=...)`` -- and only falls back to
    the raising form when the gate does not offer the boolean one.

    A host gate that offers BOTH is expected to answer both the same
    way, because they are the same question.  Nothing in the contract
    says so, and nothing checks it, so the two forms can disagree and
    the disagreement is invisible: the same gate, the same job, the
    same action, two answers.

    Measured 2026-11-24, on the tree as §17 left it:

        --- the RAISING form ---
        retry raised: RuntimeError refused
        state j1: reserved

        --- the BATCH form, same gate, same job ---
        retry_allowed -> RetryRecord(job_id='j1', attempts=1, ..., state='ready')
        state j1: ready

    The gate REFUSED the re-dispatch, and the batch form re-dispatched
    it anyway.  The job went back to ``ready`` -- so the refused action
    was offered again.

    The rule this pins: **the batch form must not be more permissive
    than the raising form.**  The batch form exists to avoid abandoning
    a sweep; it does not exist to answer a different question.
    """

    def _reserved(self, gate=None):
        """A job that is enqueued and RESERVED, with the gate installed."""
        queue = JobQueue(refusal_gate=gate)
        queue.enqueue("j1", "q", "dispatch", DIGEST, 1)
        queue.set_refusal_gate(None)
        queue.dequeue("worker-1", "q", 2)
        queue.set_refusal_gate(gate)
        return queue

    def test_the_batch_form_refuses_what_the_raising_form_refuses(self):
        """The defect: the batch form re-dispatched a REFUSED action.

        The gate offers both methods.  The raising one refuses; the
        boolean one allows.  The batch form took the boolean answer and
        put the job back to ``ready``.
        """

        class _Lying:
            """The boolean form allows; the raising form refuses.

            A host gate whose two forms disagree.  The contract says
            they are the same question, so the queue must not depend on
            which one it happens to ask.
            """

            def queue_allowed(self, job_id, action, *, now=None):
                return True

            def require_queue_allowed(self, job_id, action, *, now=None):
                raise RuntimeError("this action is refused")

        gate = _Lying()
        queue = self._reserved(gate)
        record = queue.retry_allowed("j1", 3)
        self.assertIsNone(
            record,
            "the batch form re-dispatched an action the raising form refuses",
        )
        self.assertEqual(
            queue.job("j1").state,
            "reserved",
            "the refused action went back to 'ready' and would be offered again",
        )

    def test_the_batch_form_leaves_a_refused_job_where_it_was(self):
        """The job keeps its state, its attempts and its backoff."""
        queue = self._reserved(_LyingGate())
        before = queue.job("j1")
        queue.retry_allowed("j1", 3)
        after = queue.job("j1")
        self.assertEqual(after.state, before.state)
        self.assertEqual(after.attempts, before.attempts)

    def test_the_two_forms_agree_on_a_gate_that_offers_only_the_raising_one(self):
        """The control: a gate with ONE form is unchanged.

        A gate that offers only ``require_queue_allowed`` -- the repo's
        own gate does offer a boolean one for the *lease* side, but the
        queue side is duck-typed -- must still be refused by both forms.
        """

        class _RaisingOnly:
            def require_queue_allowed(self, job_id, action, *, now=None):
                raise RuntimeError("this action is refused")

        queue = self._reserved(_RaisingOnly())
        self.assertIsNone(queue.retry_allowed("j1", 3))
        self.assertEqual(queue.job("j1").state, "reserved")

    def test_an_allowed_gate_still_re_dispatches(self):
        """The control: the fix must not break the ordinary path."""
        registry = RefusalHoldRegistry()
        gate = RefusalHoldQueueGate(registry)
        queue = self._reserved(gate)
        record = queue.retry_allowed("j1", 3)
        self.assertIsNotNone(record, "an allowed job was not re-dispatched")
        self.assertEqual(queue.job("j1").state, "ready")


class TheBatchFormNamesWhatItBookedTests(unittest.TestCase):
    """A ``job.rejected`` row must name a REAL refusal.

    §17 landed the rule on the **raising** form: a broken gate books no
    row, because a broken gate "refuses nothing in particular" and a
    ``job.rejected`` row would "put a refusal in the trail that never
    happened".

    The batch form never got the same rule.  It books the row through
    the same helper, but it decides **whether** to book it from the
    boolean answer alone -- and the boolean answer cannot tell a
    refusal from a broken gate.

    Measured 2026-11-24, on the tree as §17 left it:

        --- a BROKEN gate, the RAISING form ---
        retry raised: RuntimeError the gate cannot answer
        audit: [('job.enqueued', ...), ('job.dequeued', ...)]      <- no row

        --- a BROKEN gate, the BATCH form ---
        retry_allowed -> None
        audit: [..., ('job.rejected', {'reason': 'RuntimeError', ...})]   <- a row

    So the same broken gate books a refusal row on one form and not on
    the other, and the row names a refusal that never happened.

    And when the gate's boolean form answers ``False`` without
    raising, the row has no reason at all -- the boolean form threw
    the exception away, so the reason was never in the helper's hands:

        the row: {'reason': 'NoneType', 'refusal_reason': None, ...}

    A reader of the trail sees a refusal whose reason is the *absence*
    of an exception.
    """

    def _reserved(self, gate=None):
        queue = JobQueue(refusal_gate=gate)
        queue.enqueue("j1", "q", "dispatch", DIGEST, 1)
        queue.set_refusal_gate(None)
        queue.dequeue("worker-1", "q", 2)
        queue.set_refusal_gate(gate)
        return queue

    def _rejected(self, queue):
        return [
            row for row in queue.audit_log() if row["kind"] == "job.rejected"
        ]

    def test_a_broken_gate_books_no_rejected_row_on_the_batch_form(self):
        """The defect: the batch form booked a refusal for a broken gate.

        The raising form books nothing here.  The batch form booked a
        ``job.rejected`` row whose ``reason`` is the broken gate's
        exception class -- so the trail claims the queue refused this
        job, when in fact the gate never answered.
        """

        class _Broken:
            def queue_allowed(self, job_id, action, *, now=None):
                raise RuntimeError("the gate cannot answer")

            def require_queue_allowed(self, job_id, action, *, now=None):
                raise RuntimeError("the gate cannot answer")

        queue = self._reserved(_Broken())
        queue.retry_allowed("j1", 3)
        self.assertEqual(
            self._rejected(queue),
            [],
            "the batch form booked a refusal row for a gate that never answered",
        )

    def test_a_refused_row_names_a_reason_that_is_not_the_absence_of_one(self):
        """A row whose reason is ``NoneType`` names nothing.

        The boolean form answers ``False`` without raising, so the
        helper's exception slot is empty, and the row's ``reason`` was
        the *class name of that empty slot*.
        """

        class _NoReason:
            """Answers False, and cannot say why."""

            def queue_allowed(self, job_id, action, *, now=None):
                return False

        queue = self._reserved(_NoReason())
        queue.retry_allowed("j1", 3)
        rejected = self._rejected(queue)
        self.assertEqual(len(rejected), 1, "the refusal left no row at all")
        self.assertNotEqual(
            rejected[0]["detail"].get("reason"),
            "NoneType",
            "the row's reason is the class name of a missing exception",
        )

    def test_a_refused_row_still_names_the_job_and_the_action(self):
        """The control: the row keeps naming WHO and WHAT."""
        registry = RefusalHoldRegistry()
        gate = RefusalHoldQueueGate(registry)
        queue = self._reserved(gate)
        gate.record_queue("j1", "dispatch", row=make_row())
        queue.retry_allowed("j1", 3)
        rejected = self._rejected(queue)
        self.assertEqual(len(rejected), 1)
        detail = rejected[0]["detail"]
        self.assertEqual(detail.get("job_id"), "j1")
        self.assertEqual(detail.get("action"), "dispatch")
        self.assertEqual(
            detail.get("refusal_reason"),
            "blocked_by_refusal",
            "the row does not say WHICH condition refused the re-dispatch",
        )

    def test_the_raising_form_and_the_batch_form_book_the_same_rows(self):
        """Two forms, one trail: the same gate must produce the same rows.

        This is the property that makes the rule above checkable: the
        raising form is the reference, and the batch form must agree
        with it row for row.
        """

        class _Broken:
            def queue_allowed(self, job_id, action, *, now=None):
                raise RuntimeError("the gate cannot answer")

            def require_queue_allowed(self, job_id, action, *, now=None):
                raise RuntimeError("the gate cannot answer")

        raising = self._reserved(_Broken())
        with self.assertRaises(RuntimeError):
            raising.retry("j1", 3)
        batch = self._reserved(_Broken())
        batch.retry_allowed("j1", 3)
        self.assertEqual(
            len(self._rejected(raising)),
            len(self._rejected(batch)),
            "the two forms booked a different number of refusal rows",
        )
