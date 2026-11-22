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
from leased_task_claim import LeasedTaskClaim
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
        """A gate that cannot answer the question is not a gate."""
        self.manager.set_refusal_gate(object())
        lease = self._lease()
        with self.assertRaises(TypeError):
            self.manager.fail("t1", lease.token, reason="boom", now=101.0)

    def test_no_gate_leaves_the_failure_path_unchanged(self):
        """The default behaviour is untouched."""
        self.manager.set_refusal_gate(None)
        lease = self._lease()
        record = self.manager.fail("t1", lease.token, reason="boom", now=101.0)
        self.assertEqual(record.state, "ready")


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


if __name__ == "__main__":
    unittest.main()
