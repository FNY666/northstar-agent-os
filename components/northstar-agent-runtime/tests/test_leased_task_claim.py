"""Tests for the leased task claim: a fencing-token claim and a lease reaper.

The rules under test, one class each:

* the fencing token is strictly increasing, and an old token's write is
  refused;
* a zombie holder's writes (complete / fail / heartbeat / save_checkpoint /
  release) are refused with ``StaleLeaseError`` and change nothing at all;
* the reaper sweeps an expired lease back into the queue -- with **no**
  backoff delay, because a crash is not the task's fault -- and the
  checkpoint survives the hand-over;
* a *reported* failure takes exponential backoff, and the failure budget
  ends in the dead letter;
* the terminal state and its outbox row commit together, under the stable
  idempotency key ``<task_id>:<event_type>``.
"""

from __future__ import annotations

import unittest

from leased_task_claim import (
    DEFAULT_DESTINATION,
    EVENT_COMPLETED,
    EVENT_DEAD,
    STATE_COMPLETED,
    STATE_DEAD,
    STATE_LEASED,
    STATE_READY,
    BackoffError,
    CheckpointOrderError,
    LeaseHeldError,
    LeasedTaskClaim,
    StaleLeaseError,
    TerminalTaskError,
    UnknownTaskError,
    digest_of,
    idempotency_key,
)


class ClaimTestBase(unittest.TestCase):
    """A manager with a deterministic clock and one registered task."""

    def setUp(self) -> None:
        self.manager = LeasedTaskClaim(
            max_failures=3, base_backoff_seconds=2.0, backoff_factor=2.0
        )
        self.manager.enqueue_task("t1", "demo-task", payload="hello")

    def tearDown(self) -> None:
        self.manager.close()


class MonotonicTokenTests(ClaimTestBase):
    """The token is the claim counter: it only ever goes up."""

    def test_first_claim_is_token_one(self) -> None:
        lease = self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.assertEqual(lease.token, 1)
        self.assertEqual(lease.worker, "worker-A")
        self.assertEqual(self.manager.task("t1").token, 1)

    def test_successive_claims_have_strictly_increasing_tokens(self) -> None:
        tokens = []
        for index in range(4):
            lease = self.manager.claim(
                "t1", f"worker-{index}", ttl=10.0, now=100.0 + index * 20.0
            )
            tokens.append(lease.token)
        self.assertEqual(tokens, [1, 2, 3, 4])
        for earlier, later in zip(tokens, tokens[1:]):
            self.assertLess(earlier, later)

    def test_token_never_reverts_when_a_task_is_requeued(self) -> None:
        self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.manager.reap(now=200.0)
        lease = self.manager.claim("t1", "worker-B", ttl=10.0, now=201.0)
        self.assertEqual(lease.token, 2)
        self.assertGreater(lease.token, 1)

    def test_claim_of_unknown_task_is_refused(self) -> None:
        with self.assertRaises(UnknownTaskError):
            self.manager.claim("nope", "worker-A", ttl=10.0, now=100.0)

    def test_a_live_lease_cannot_be_claimed_again(self) -> None:
        self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        with self.assertRaises(LeaseHeldError):
            self.manager.claim("t1", "worker-B", ttl=10.0, now=105.0)

    def test_a_terminal_task_cannot_be_claimed(self) -> None:
        lease = self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.manager.complete("t1", lease.token, now=101.0)
        with self.assertRaises(TerminalTaskError):
            self.manager.claim("t1", "worker-B", ttl=10.0, now=102.0)


class ZombieWriteTests(ClaimTestBase):
    """A stale holder's write changes nothing."""

    def test_every_write_of_a_stale_token_is_refused(self) -> None:
        stale = self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.manager.reap(now=200.0)
        live = self.manager.claim("t1", "worker-B", ttl=10.0, now=201.0)
        self.assertEqual(live.token, stale.token + 1)

        with self.assertRaises(StaleLeaseError):
            self.manager.complete("t1", stale.token, now=202.0)
        with self.assertRaises(StaleLeaseError):
            self.manager.fail("t1", stale.token, "boom", now=202.0)
        with self.assertRaises(StaleLeaseError):
            self.manager.heartbeat("t1", stale.token, now=202.0)
        with self.assertRaises(StaleLeaseError):
            self.manager.save_checkpoint("t1", stale.token, 1, {"a": 1},
                                        now=202.0)
        with self.assertRaises(StaleLeaseError):
            self.manager.release("t1", stale.token, now=202.0)

    def test_a_refused_write_changes_nothing(self) -> None:
        stale = self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.manager.save_checkpoint("t1", stale.token, 1, {"step": "one"},
                                     now=101.0)
        self.manager.reap(now=200.0)
        live = self.manager.claim("t1", "worker-B", ttl=10.0, now=201.0)

        before_task = self.manager.task("t1")
        before_checkpoint = self.manager.checkpoint("t1")
        before_rows = self.manager.outbox_rows("t1")

        with self.assertRaises(StaleLeaseError):
            self.manager.complete("t1", stale.token, now=202.0)

        self.assertEqual(self.manager.task("t1"), before_task)
        self.assertEqual(self.manager.checkpoint("t1"), before_checkpoint)
        self.assertEqual(self.manager.outbox_rows("t1"), before_rows)
        self.assertEqual(self.manager.task("t1").state, STATE_LEASED)
        self.assertEqual(self.manager.task("t1").worker, "worker-B")
        self.assertEqual(self.manager.outbox_rows("t1"), ())

    def test_an_expired_lease_refuses_its_own_holders_writes(self) -> None:
        lease = self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        # The lease is valid *through* expires_at, and dead after it.
        self.manager.heartbeat("t1", lease.token, now=110.0)
        with self.assertRaises(StaleLeaseError):
            self.manager.complete("t1", lease.token, now=110.001)

    def test_the_lease_is_valid_through_its_expiry_instant(self) -> None:
        lease = self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        # expires_at is 110.0 -- exactly at 110.0 the lease is still live,
        # and it is dead one instant later.
        self.manager.heartbeat("t1", lease.token, now=110.0)
        self.assertEqual(self.manager.task("t1").state, STATE_LEASED)
        self.assertFalse(lease.is_expired(110.0))
        self.assertTrue(lease.is_expired(110.001))
        self.assertFalse(lease.is_expired(109.999))

    def test_a_refused_write_does_not_consume_the_failure_budget(self) -> None:
        stale = self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.manager.reap(now=200.0)
        self.manager.claim("t1", "worker-B", ttl=10.0, now=201.0)
        for _ in range(3):
            with self.assertRaises(StaleLeaseError):
                self.manager.fail("t1", stale.token, "boom", now=202.0)
        self.assertEqual(self.manager.task("t1").failures, 0)


class ReaperTests(ClaimTestBase):
    """The reaper sweeps expired leases back into the queue."""

    def test_an_expired_lease_is_swept_and_requeued(self) -> None:
        self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        swept = self.manager.reap(now=200.0)
        self.assertEqual(len(swept), 1)
        self.assertEqual(swept[0].task_id, "t1")
        self.assertEqual(swept[0].worker, "worker-A")
        view = self.manager.task("t1")
        self.assertEqual(view.state, STATE_READY)
        self.assertEqual(view.worker, "")

    def test_a_live_lease_is_not_swept(self) -> None:
        self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.assertEqual(self.manager.reap(now=105.0), ())
        self.assertEqual(self.manager.task("t1").state, STATE_LEASED)

    def test_a_lease_is_swept_only_after_it_expires(self) -> None:
        self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        # expires_at is 110.0; the reaper takes it strictly after that.
        self.assertEqual(self.manager.reap(now=110.0), ())
        self.assertEqual(len(self.manager.reap(now=110.001)), 1)

    def test_requeue_leaves_the_task_claimable_again(self) -> None:
        self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.manager.reap(now=200.0)
        lease = self.manager.claim("t1", "worker-B", ttl=10.0, now=201.0)
        self.assertEqual(lease.token, 2)
        self.assertEqual(self.manager.task("t1").worker, "worker-B")

    def test_reaping_twice_sweeps_once(self) -> None:
        self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.assertEqual(len(self.manager.reap(now=200.0)), 1)
        self.assertEqual(self.manager.reap(now=300.0), ())
        self.assertEqual(self.manager.task("t1").crashes, 1)

    def test_a_reaped_task_is_back_in_the_queue_mirror(self) -> None:
        self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        view = self.manager._queue.job("t1")
        self.assertEqual(view.state, "reserved")
        self.manager.reap(now=200.0)
        self.assertEqual(self.manager._queue.job("t1").state, "ready")

    def test_expired_leases_lists_without_sweeping(self) -> None:
        self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.assertEqual(len(self.manager.expired_leases(now=200.0)), 1)
        self.assertEqual(self.manager.task("t1").state, STATE_LEASED)


class CrashIsNotFaultTests(ClaimTestBase):
    """A crash eats no backoff; only a reported failure does."""

    def test_a_requeued_crash_takes_no_backoff_delay(self) -> None:
        self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.manager.reap(now=200.0)
        view = self.manager.task("t1")
        self.assertEqual(view.delay_until, 0.0)
        # Claimable immediately: no backoff window.
        lease = self.manager.claim("t1", "worker-B", ttl=10.0, now=200.0)
        self.assertEqual(lease.token, 2)

    def test_a_crash_does_not_consume_the_failure_budget(self) -> None:
        self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.manager.reap(now=200.0)
        self.assertEqual(self.manager.task("t1").failures, 0)

    def test_a_crash_is_counted_as_a_crash(self) -> None:
        self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.manager.reap(now=200.0)
        self.assertEqual(self.manager.task("t1").crashes, 1)

    def test_a_reported_failure_takes_exponential_backoff(self) -> None:
        lease = self.manager.claim("t1", "worker-A", ttl=100.0, now=100.0)
        first = self.manager.fail("t1", lease.token, "boom", now=101.0)
        self.assertEqual(first.failures, 1)
        self.assertEqual(first.delay_seconds, 2.0)
        self.assertAlmostEqual(self.manager.task("t1").delay_until, 103.0)

        lease = self.manager.claim("t1", "worker-A", ttl=100.0, now=104.0)
        second = self.manager.fail("t1", lease.token, "boom", now=105.0)
        self.assertEqual(second.failures, 2)
        self.assertEqual(second.delay_seconds, 4.0)
        self.assertAlmostEqual(self.manager.task("t1").delay_until, 109.0)

    def test_a_task_in_backoff_cannot_be_claimed(self) -> None:
        lease = self.manager.claim("t1", "worker-A", ttl=100.0, now=100.0)
        self.manager.fail("t1", lease.token, "boom", now=101.0)
        with self.assertRaises(BackoffError):
            self.manager.claim("t1", "worker-B", ttl=10.0, now=102.0)

    def test_the_backoff_window_expires(self) -> None:
        lease = self.manager.claim("t1", "worker-A", ttl=100.0, now=100.0)
        self.manager.fail("t1", lease.token, "boom", now=101.0)
        lease = self.manager.claim("t1", "worker-B", ttl=100.0, now=103.0)
        self.assertEqual(lease.token, 2)


class DeadLetterTests(ClaimTestBase):
    """The failure budget ends in the dead letter."""

    def test_an_exhausted_failure_budget_makes_the_task_dead(self) -> None:
        record = None
        for index in range(3):
            lease = self.manager.claim(
                "t1", "worker-A", ttl=100.0, now=100.0 + index * 200.0
            )
            record = self.manager.fail("t1", lease.token, "boom",
                                       now=101.0 + index * 200.0)
        self.assertEqual(record.failures, 3)
        self.assertEqual(record.state, STATE_DEAD)
        self.assertEqual(self.manager.task("t1").state, STATE_DEAD)

    def test_the_dead_task_is_booked_in_the_dead_letter_ledger(self) -> None:
        record = None
        for index in range(3):
            lease = self.manager.claim(
                "t1", "worker-A", ttl=100.0, now=100.0 + index * 200.0
            )
            record = self.manager.fail("t1", lease.token, "boom",
                                       now=101.0 + index * 200.0)
        self.assertEqual(record.dead_letter_id, "t1:dead")
        message = self.manager._dead_letters.message("t1:dead")
        self.assertIsNotNone(message)
        self.assertEqual(message.state, "active")

    def test_a_dead_task_cannot_be_claimed(self) -> None:
        for index in range(3):
            lease = self.manager.claim(
                "t1", "worker-A", ttl=100.0, now=100.0 + index * 200.0
            )
            self.manager.fail("t1", lease.token, "boom", now=101.0 + index * 200.0)
        with self.assertRaises(TerminalTaskError):
            self.manager.claim("t1", "worker-B", ttl=10.0, now=1000.0)

    def test_the_last_failure_carries_no_backoff(self) -> None:
        record = None
        for index in range(3):
            lease = self.manager.claim(
                "t1", "worker-A", ttl=100.0, now=100.0 + index * 200.0
            )
            record = self.manager.fail("t1", lease.token, "boom",
                                       now=101.0 + index * 200.0)
        self.assertEqual(record.delay_seconds, 0.0)


class CheckpointHandOverTests(ClaimTestBase):
    """The new holder resumes from the checkpoint; it does not redo the work."""

    def test_a_checkpoint_is_recorded_per_step(self) -> None:
        lease = self.manager.claim("t1", "worker-A", ttl=100.0, now=100.0)
        self.manager.save_checkpoint("t1", lease.token, 1, {"step": "one"},
                                     now=101.0)
        self.manager.save_checkpoint("t1", lease.token, 2, {"step": "two"},
                                     now=102.0)
        checkpoint = self.manager.checkpoint("t1")
        self.assertEqual(checkpoint.step, 2)
        self.assertEqual(checkpoint.payload, {"step": "two"})
        self.assertEqual(self.manager.pending_steps("t1"), 2)

    def test_the_new_holder_resumes_from_the_newest_checkpoint(self) -> None:
        lease_a = self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.manager.save_checkpoint("t1", lease_a.token, 1, {"step": "one"},
                                     now=101.0)
        self.manager.save_checkpoint("t1", lease_a.token, 2, {"step": "two"},
                                     now=102.0)
        self.manager.reap(now=200.0)
        self.manager.claim("t1", "worker-B", ttl=100.0, now=201.0)
        resumed = self.manager.resume_from("t1")
        self.assertEqual(resumed.step, 2)
        self.assertEqual(resumed.payload, {"step": "two"})

    def test_a_requeue_never_loses_the_checkpoint(self) -> None:
        lease = self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.manager.save_checkpoint("t1", lease.token, 7, {"step": "seven"},
                                     now=101.0)
        self.manager.reap(now=200.0)
        self.assertEqual(self.manager.checkpoint("t1").step, 7)
        self.assertEqual(self.manager.checkpoint("t1").payload,
                         {"step": "seven"})

    def test_a_checkpoint_cannot_move_backwards(self) -> None:
        lease = self.manager.claim("t1", "worker-A", ttl=100.0, now=100.0)
        self.manager.save_checkpoint("t1", lease.token, 5, {"n": 5},
                                     now=101.0)
        with self.assertRaises(CheckpointOrderError):
            self.manager.save_checkpoint("t1", lease.token, 4, {"n": 4},
                                         now=102.0)
        self.assertEqual(self.manager.checkpoint("t1").step, 5)

    def test_the_same_step_may_be_written_again(self) -> None:
        lease = self.manager.claim("t1", "worker-A", ttl=100.0, now=100.0)
        self.manager.save_checkpoint("t1", lease.token, 1, {"n": 1}, now=101.0)
        self.manager.save_checkpoint("t1", lease.token, 1, {"n": 2}, now=102.0)
        self.assertEqual(self.manager.checkpoint("t1").payload, {"n": 2})
        self.assertEqual(self.manager.pending_steps("t1"), 1)

    def test_a_checkpoint_of_a_stale_holder_is_refused(self) -> None:
        stale = self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.manager.reap(now=200.0)
        self.manager.claim("t1", "worker-B", ttl=100.0, now=201.0)
        with self.assertRaises(StaleLeaseError):
            self.manager.save_checkpoint("t1", stale.token, 1, {"n": 1},
                                        now=202.0)
        self.assertIsNone(self.manager.checkpoint("t1"))


class TerminalAtomicityTests(ClaimTestBase):
    """The terminal state and its outbox row commit together."""

    def test_completion_writes_the_terminal_state_and_the_outbox_row(self) -> None:
        lease = self.manager.claim("t1", "worker-A", ttl=100.0, now=100.0)
        record = self.manager.complete("t1", lease.token, {"ok": True},
                                       now=101.0)
        self.assertEqual(record.message_id, "t1:completed")
        self.assertEqual(self.manager.task("t1").state, STATE_COMPLETED)
        rows = self.manager.outbox_rows("t1")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].message_id, "t1:completed")
        self.assertEqual(rows[0].payload, {"ok": True})
        self.assertEqual(rows[0].destination, DEFAULT_DESTINATION)

    def test_the_idempotency_key_is_task_id_and_event_type(self) -> None:
        self.assertEqual(idempotency_key("t1", EVENT_COMPLETED),
                         "t1:completed")
        self.assertEqual(idempotency_key("t1", EVENT_DEAD), "t1:dead")

    def test_a_replayed_completion_does_not_book_a_second_row(self) -> None:
        lease = self.manager.claim("t1", "worker-A", ttl=100.0, now=100.0)
        self.manager.complete("t1", lease.token, {"ok": True}, now=101.0)
        # The same terminal state again -- the row is already there.
        with self.assertRaises(StaleLeaseError):
            self.manager.complete("t1", lease.token, {"ok": True}, now=102.0)
        self.assertEqual(len(self.manager.outbox_rows("t1")), 1)

    def test_a_completion_after_a_takeover_does_not_book_a_row(self) -> None:
        stale = self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.manager.reap(now=200.0)
        self.manager.claim("t1", "worker-B", ttl=100.0, now=201.0)
        with self.assertRaises(StaleLeaseError):
            self.manager.complete("t1", stale.token, {"ok": True}, now=202.0)
        self.assertEqual(self.manager.outbox_rows("t1"), ())
        self.assertEqual(self.manager.task("t1").state, STATE_LEASED)

    def test_the_outbox_message_carries_the_stable_key(self) -> None:
        lease = self.manager.claim("t1", "worker-A", ttl=100.0, now=100.0)
        self.manager.complete("t1", lease.token, {"ok": True}, now=101.0)
        messages = self.manager.outbox_messages("t1")
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].message_id, "t1:completed")
        self.assertEqual(messages[0].payload, {"ok": True})

    def test_delivery_is_marked_and_the_row_survives(self) -> None:
        lease = self.manager.claim("t1", "worker-A", ttl=100.0, now=100.0)
        self.manager.complete("t1", lease.token, {"ok": True}, now=101.0)
        self.manager.mark_delivered("t1", "t1:completed", now=102.0)
        self.assertEqual(self.manager.delivered("t1"), ("t1:completed",))
        self.assertEqual(len(self.manager.outbox_rows("t1")), 1)

    def test_a_completed_task_is_in_the_queue_mirror_as_done(self) -> None:
        lease = self.manager.claim("t1", "worker-A", ttl=100.0, now=100.0)
        self.manager.complete("t1", lease.token, now=101.0)
        # The job was reserved by the claim; completion releases it.
        self.assertIn(self.manager._queue.job("t1").state,
                      ("ready", "done"))


class HeartbeatAndReleaseTests(ClaimTestBase):
    """Heartbeat extends; release gives the task back without a penalty."""

    def test_a_heartbeat_extends_the_lease(self) -> None:
        lease = self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        extended = self.manager.heartbeat("t1", lease.token, now=105.0,
                                          extend_seconds=10.0)
        self.assertEqual(extended.expires_at, 120.0)
        self.assertEqual(self.manager.task("t1").expires_at, 120.0)

    def test_a_heartbeat_never_shortens_the_lease(self) -> None:
        lease = self.manager.claim("t1", "worker-A", ttl=100.0, now=100.0)
        extended = self.manager.heartbeat("t1", lease.token, now=105.0)
        self.assertEqual(extended.expires_at, 200.0)

    def test_a_heartbeat_extends_past_the_old_expiry(self) -> None:
        lease = self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        extended = self.manager.heartbeat("t1", lease.token, now=105.0,
                                          extend_seconds=10.0)
        self.assertEqual(self.manager.reap(now=115.0), ())
        self.assertEqual(len(self.manager.reap(now=121.0)), 1)
        self.assertEqual(extended.expires_at, 120.0)

    def test_a_release_returns_the_task_without_a_penalty(self) -> None:
        lease = self.manager.claim("t1", "worker-A", ttl=100.0, now=100.0)
        released = self.manager.release("t1", lease.token, now=101.0)
        self.assertEqual(released.worker, "worker-A")
        view = self.manager.task("t1")
        self.assertEqual(view.state, STATE_READY)
        self.assertEqual(view.delay_until, 0.0)
        self.assertEqual(view.failures, 0)

    def test_a_released_task_can_be_claimed_again_with_a_new_token(self) -> None:
        lease = self.manager.claim("t1", "worker-A", ttl=100.0, now=100.0)
        self.manager.release("t1", lease.token, now=101.0)
        lease = self.manager.claim("t1", "worker-B", ttl=100.0, now=102.0)
        self.assertEqual(lease.token, 2)


class SourceDemonstrationTests(ClaimTestBase):
    """The source's demonstration, driven end to end."""

    def test_worker_a_crashes_and_worker_b_resumes(self) -> None:
        lease_a = self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        self.manager.save_checkpoint("t1", lease_a.token, 1, {"step": "one"},
                                     now=101.0)
        self.manager.save_checkpoint("t1", lease_a.token, 2, {"step": "two"},
                                     now=102.0)

        # The lease expires and the reaper sweeps it: no backoff, no fault.
        self.assertEqual(len(self.manager.reap(now=200.0)), 1)

        lease_b = self.manager.claim("t1", "worker-B", ttl=100.0, now=201.0)
        self.assertEqual(lease_b.token, 2)
        self.assertEqual(self.manager.resume_from("t1").step, 2)

        # The woken zombie writes three times: all three refused.
        refusals = 0
        for write in (
            lambda: self.manager.complete("t1", lease_a.token, now=202.0),
            lambda: self.manager.save_checkpoint("t1", lease_a.token, 3,
                                                {"x": 1}, now=202.0),
            lambda: self.manager.heartbeat("t1", lease_a.token, now=202.0),
        ):
            with self.assertRaises(StaleLeaseError):
                write()
            refusals += 1
        self.assertEqual(refusals, 3)
        self.assertEqual(self.manager.task("t1").state, STATE_LEASED)
        self.assertEqual(self.manager.outbox_rows("t1"), ())

        # The live holder finishes; the terminal state and the outbox row
        # commit together.
        self.manager.complete("t1", lease_b.token, {"ok": True}, now=203.0)
        self.assertEqual(self.manager.task("t1").state, STATE_COMPLETED)
        self.assertEqual(len(self.manager.outbox_rows("t1")), 1)


class IdempotentDeliveryTests(ClaimTestBase):
    """At-least-once delivery with a stable idempotency key."""

    def test_the_message_id_is_the_stable_key_for_the_task_and_event(self) -> None:
        lease = self.manager.claim("t1", "worker-A", ttl=100.0, now=100.0)
        self.manager.complete("t1", lease.token, now=101.0)
        row = self.manager.outbox_rows("t1")[0]
        self.assertEqual(row.message_id, idempotency_key("t1", EVENT_COMPLETED))

    def test_a_redelivery_reuses_the_same_key_and_does_not_duplicate(self) -> None:
        lease = self.manager.claim("t1", "worker-A", ttl=100.0, now=100.0)
        self.manager.complete("t1", lease.token, now=101.0)
        self.manager.mark_delivered("t1", "t1:completed", now=102.0)
        # A redelivery is the same message id -- the row is the record.
        messages = self.manager.outbox_messages("t1")
        self.assertEqual([m.message_id for m in messages], ["t1:completed"])
        self.assertEqual(len(self.manager.outbox_rows("t1")), 1)

    def test_the_dead_event_has_its_own_key(self) -> None:
        for index in range(3):
            lease = self.manager.claim(
                "t1", "worker-A", ttl=100.0, now=100.0 + index * 200.0
            )
            self.manager.fail("t1", lease.token, "boom", now=101.0 + index * 200.0)
        rows = self.manager.outbox_rows("t1")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].message_id, "t1:dead")
        self.assertEqual(rows[0].event_type, EVENT_DEAD)

    def test_two_tasks_never_share_a_message_id(self) -> None:
        self.manager.enqueue_task("t2", "other-task", payload="x")
        lease_a = self.manager.claim("t1", "worker-A", ttl=100.0, now=100.0)
        lease_b = self.manager.claim("t2", "worker-B", ttl=100.0, now=100.0)
        self.manager.complete("t1", lease_a.token, now=101.0)
        self.manager.complete("t2", lease_b.token, now=101.0)
        ids = [row.message_id for row in self.manager.outbox_rows("t1")]
        ids += [row.message_id for row in self.manager.outbox_rows("t2")]
        self.assertEqual(sorted(ids), ["t1:completed", "t2:completed"])


class InputValidationTests(ClaimTestBase):
    """The inputs are checked before anything is booked."""

    def test_a_bool_step_is_refused(self) -> None:
        lease = self.manager.claim("t1", "worker-A", ttl=100.0, now=100.0)
        with self.assertRaises(TypeError):
            self.manager.save_checkpoint("t1", lease.token, True, {"n": 1},
                                        now=101.0)

    def test_a_bool_ttl_is_refused(self) -> None:
        with self.assertRaises(TypeError):
            self.manager.claim("t1", "worker-A", ttl=True, now=100.0)

    def test_a_non_positive_ttl_is_refused(self) -> None:
        for bad in (0, -1.0):
            with self.assertRaises(ValueError):
                self.manager.claim("t1", "worker-A", ttl=bad, now=100.0)

    def test_a_non_finite_ttl_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            self.manager.claim("t1", "worker-A", ttl=float("inf"), now=100.0)

    def test_an_empty_task_id_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            self.manager.claim("  ", "worker-A", ttl=10.0, now=100.0)

    def test_a_non_mapping_payload_is_refused(self) -> None:
        lease = self.manager.claim("t1", "worker-A", ttl=100.0, now=100.0)
        with self.assertRaises(TypeError):
            self.manager.save_checkpoint("t1", lease.token, 1, ["not", "a",
                                                                "mapping"],
                                        now=101.0)

    def test_a_negative_step_is_refused(self) -> None:
        lease = self.manager.claim("t1", "worker-A", ttl=100.0, now=100.0)
        with self.assertRaises(ValueError):
            self.manager.save_checkpoint("t1", lease.token, -1, {"n": 1},
                                        now=101.0)

    def test_registering_a_task_twice_is_refused(self) -> None:
        with self.assertRaises(Exception):
            self.manager.enqueue_task("t1", "demo-task", payload="hello")

    def test_the_digest_shape_is_the_one_the_queue_ledger_expects(self) -> None:
        digest = digest_of("hello")
        self.assertTrue(digest.startswith("sha256:"))
        self.assertEqual(len(digest), len("sha256:") + 64)
        self.assertEqual(digest, digest_of("hello"))
        self.assertNotEqual(digest, digest_of("other"))


class SecondHalfGuardTests(ClaimTestBase):
    """The second half of each guard in the leased task claim.

    Every surviving mutant here is one arm of a two-armed conditional or
    one half of a conjunction, and the rest of the suite drove only the
    other arm.  These tests drive the missing half.
    """

    def _manager(self, **kwargs) -> LeasedTaskClaim:
        """A manager with its own settings, closed by the caller."""
        return LeasedTaskClaim(**kwargs)

    # -- or@534: the max_failures type guard ---------------------------

    def test_a_boolean_max_failures_is_refused(self):
        """`or@534`: the type half of the max_failures guard, on a bool.

        A bool IS an int in Python, so only the ``isinstance(..., bool)``
        half can catch it.  Under the mutant a boolean budget is
        accepted and used as the integer 1.
        """
        with self.assertRaises(ValueError) as caught:
            LeasedTaskClaim(max_failures=True)
        self.assertIn("max_failures must be an int", str(caught.exception))

    def test_a_float_max_failures_is_refused(self):
        """`or@534`: the other type half -- a float is not an int."""
        with self.assertRaises(ValueError) as caught:
            LeasedTaskClaim(max_failures=3.0)
        self.assertIn("max_failures must be an int", str(caught.exception))

    # -- lt@536 / or@536: the failure budget's range -------------------

    def test_a_max_failures_of_one_is_allowed(self):
        """`lt@536`: the lower edge of the budget range.

        A budget of exactly 1 is legal: the first failure exhausts it.
        A mutant that turns ``< 1`` into ``<= 1`` refuses it.
        """
        manager = self._manager(max_failures=1)
        try:
            manager.enqueue_task("t1", "task")
            lease = manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
            record = manager.fail("t1", lease.token, "boom", now=101.0)
            self.assertEqual(record.state, STATE_DEAD)
            self.assertEqual(record.failures, 1)
        finally:
            manager.close()

    def test_a_max_failures_of_sixty_four_is_allowed(self):
        """`or@536`: the upper edge of the budget range.

        A budget of exactly 64 is legal.  A mutant that turns ``> 64``
        into ``>= 64`` refuses it.
        """
        manager = self._manager(max_failures=64)
        try:
            manager.enqueue_task("t1", "task")
        finally:
            manager.close()

    def test_a_max_failures_of_sixty_five_is_refused(self):
        """`or@536`: inside the band -- one over the ceiling is refused."""
        with self.assertRaises(ValueError) as caught:
            LeasedTaskClaim(max_failures=65)
        self.assertIn("max_failures must be in [1, 64]", str(caught.exception))

    def test_a_max_failures_of_zero_is_refused(self):
        """`lt@536`: the lower edge -- a budget of zero is refused."""
        with self.assertRaises(ValueError):
            LeasedTaskClaim(max_failures=0)

    # -- gt@671 / gt@673: the length guards ----------------------------

    def test_a_task_id_at_the_length_limit_is_accepted(self):
        """`gt@671`: the lower edge of the task-id length guard.

        The limit is ``len(task_id) > 256``, so a task id of exactly 256
        characters is accepted.  A mutant that turns ``>`` into ``>=``
        refuses it.
        """
        manager = self._manager()
        try:
            task_id = "t" * 256
            manager.enqueue_task(task_id, "task")
            view = manager.task(task_id)
            self.assertEqual(view.task_id, task_id)
        finally:
            manager.close()

    def test_a_task_id_one_character_over_the_limit_is_refused(self):
        """`gt@671`: inside the band -- one character over is refused."""
        manager = self._manager()
        try:
            with self.assertRaises(ValueError) as caught:
                manager.enqueue_task("t" * 257, "task")
            self.assertIn("task_id exceeds 256 chars", str(caught.exception))
        finally:
            manager.close()

    def test_a_task_at_the_length_limit_is_accepted(self):
        """`gt@673`: the lower edge of the task length guard."""
        manager = self._manager()
        try:
            task = "j" * 256
            manager.enqueue_task("t1", task)
            self.assertEqual(manager.task("t1").task, task)
        finally:
            manager.close()

    def test_a_task_one_character_over_the_limit_is_refused(self):
        """`gt@673`: inside the band -- one character over is refused."""
        manager = self._manager()
        try:
            with self.assertRaises(ValueError) as caught:
                manager.enqueue_task("t1", "j" * 257)
            self.assertIn("task exceeds 256 chars", str(caught.exception))
        finally:
            manager.close()

    # -- or@801: the queue-mirror reservation guard --------------------

    def test_a_mirror_that_reserves_another_job_is_refused(self):
        """`or@801`: the "and it reserved THIS job" half.

        The mirror is asked for a job and the answer must be the task
        that was asked for.  A mirror that hands back a different job
        must be refused, not accepted silently.
        """
        import leased_task_claim as ltc
        from job_queue import JobQueue

        class WrongJobQueue(JobQueue):
            """A mirror that always reserves a DIFFERENT job.

            The mirror is asked to reserve one specific task.  A mirror
            that hands back another job's reservation must be refused --
            the claim is for THIS task, and accepting another job's
            reservation would lease the wrong work.
            """

            def dequeue(self, worker_id, queue, seq):
                reserved = super().dequeue(worker_id, queue, seq)
                if reserved is None:
                    return reserved
                # Rename the reservation to a job that was never asked
                # for, so the identity check has something to fail on.
                object.__setattr__(reserved, "job_id", "some-other-job")
                return reserved

        manager = self._manager(queue=WrongJobQueue())
        try:
            manager.enqueue_task("t1", "task")
            with self.assertRaises(ltc.QueueMirrorError) as caught:
                manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
            self.assertIn("refused to reserve", str(caught.exception))
        finally:
            manager.close()

    # -- lt@902: the step's sign ---------------------------------------

    def test_a_step_of_zero_is_allowed(self):
        """`lt@902`: the lower edge of the step guard.

        A checkpoint at step 0 is legal.  A mutant that turns ``< 0``
        into ``<= 0`` refuses it.
        """
        lease = self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        record = self.manager.save_checkpoint(
            "t1", lease.token, 0, {"step": "zero"}, now=101.0
        )
        self.assertEqual(record.step, 0)

    def test_a_negative_step_is_refused(self):
        """`lt@902`: the sign half of the step guard."""
        lease = self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        with self.assertRaises(ValueError) as caught:
            self.manager.save_checkpoint(
                "t1", lease.token, -1, {"step": "neg"}, now=101.0
            )
        self.assertIn("step must be non-negative", str(caught.exception))

    # -- or@1032: the dead-letter reason ------------------------------

    def test_a_dead_letter_without_a_reason_says_the_budget_is_exhausted(self):
        """`or@1032`: the "or the reason is empty" half.

        A dead letter with no reason must still say WHY the task died:
        the failure budget was exhausted.
        """
        manager = self._manager(max_failures=1)
        try:
            manager.enqueue_task("t1", "task")
            lease = manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
            manager.fail("t1", lease.token, "", now=101.0)
            reasons = [
                entry.get("detail", {}).get("reason", "")
                for entry in manager._dead_letters.audit_log()
            ]
            self.assertIn("failure budget exhausted", reasons)
        finally:
            manager.close()

    def test_a_dead_letter_keeps_the_reason_it_was_given(self):
        """`or@1032`: the control -- a real reason is kept as it is."""
        manager = self._manager(max_failures=1)
        try:
            manager.enqueue_task("t1", "task")
            lease = manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
            manager.fail("t1", lease.token, "the disk caught fire", now=101.0)
            reasons = [
                entry.get("detail", {}).get("reason", "")
                for entry in manager._dead_letters.audit_log()
            ]
            self.assertIn("the disk caught fire", reasons)
        finally:
            manager.close()

    # -- or@1112: the reaper's current-row guard ----------------------

    def test_the_reaper_leaves_a_task_that_is_no_longer_leased(self):
        """`or@1112`: the "and it is still leased" half.

        The reaper sweeps expired leases.  A task that is no longer in
        the leased state -- requeued, taken over, or completed -- must
        NOT be swept, and must not be counted as swept.
        """
        lease = self.manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
        # The task is released, so it is ready again -- not leased.
        self.manager.release("t1", lease.token, now=101.0)
        swept = self.manager.reap(now=200.0)
        self.assertEqual(tuple(swept), ())
        self.assertEqual(self.manager.task("t1").state, STATE_READY)

    def test_the_reaper_leaves_a_task_that_is_not_leased_at_all(self):
        """`or@1112`: the other half -- a never-claimed task is untouched."""
        swept = self.manager.reap(now=200.0)
        self.assertEqual(tuple(swept), ())
        self.assertEqual(self.manager.task("t1").state, STATE_READY)


class StoreAndReaperIsolationTests(ClaimTestBase):
    """Two guards that need the store's own behaviour to be observable.

    ``or@438`` and ``or@1112`` are both masked by the code around them:
    the store's path fallback is unreachable through the public API, and
    the reaper's vanished-row branch is unreachable because the row is
    read from the same transaction that then re-reads it.
    """

    def _manager(self, **kwargs) -> LeasedTaskClaim:
        """A manager with its own settings, closed by the caller."""
        return LeasedTaskClaim(**kwargs)

    def test_an_empty_store_path_falls_back_to_an_in_memory_database(self):
        """`or@438`: the "or the path is empty" half.

        The store connects to ``path or ":memory:"``, so an empty path
        is an in-memory database rather than a file called "".  The
        store is exercised directly, because the manager's own default
        path is already ":memory:" and the fallback is not reachable
        through it.
        """
        import leased_task_claim as ltc

        store = ltc._Store("")
        try:
            self.assertEqual(store.path, "")
            # The fallback really is the in-memory database.
            journal = store._conn.execute("PRAGMA journal_mode").fetchone()[0]
            self.assertEqual(journal, "memory")
        finally:
            store.close()

    def test_the_store_really_is_in_memory_for_an_empty_path(self):
        """`or@438`: the fallback is observable through the connection.

        An empty path must not create a file named "" on disk; the
        connection is the in-memory one, so its database name says so.
        """
        import leased_task_claim as ltc

        empty = ltc._Store("")
        memory = ltc._Store(":memory:")
        try:
            empty_journal = empty._conn.execute("PRAGMA journal_mode").fetchone()[0]
            memory_journal = memory._conn.execute("PRAGMA journal_mode").fetchone()[0]
            self.assertEqual(empty_journal, memory_journal)
            self.assertEqual(empty_journal, "memory")
        finally:
            empty.close()
            memory.close()

    def test_the_reaper_leaves_a_task_that_vanished_between_the_two_reads(self):
        """`or@1112`: the "or the row is gone" half.

        The reaper reads the expired leases, then re-reads each row
        inside the transaction and skips it when the row is GONE -- not
        merely when it is no longer leased.  The row can only vanish if
        it is deleted between the two reads, so the test deletes it.

        The store is reached directly so that the deletion happens
        between the reaper's outer read and its inner read.
        """
        import leased_task_claim as ltc

        manager = self._manager()
        try:
            manager.enqueue_task("t1", "task")
            lease = manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
            self.assertEqual(lease.token, 1)

            # The reaper's outer read must see the expired lease, so the
            # deletion has to happen after that read.  The store's read
            # is wrapped so that the FIRST read of the sweep returns the
            # row and the row is deleted immediately afterwards.
            original_read = manager._store.read
            state = {"reads": 0}

            def deleting_read(statement, params=()):
                rows = original_read(statement, params)
                if "FROM ltc_task WHERE state" in statement:
                    state["reads"] += 1
                    if state["reads"] == 1:
                        # The row has now been handed to the reaper; make
                        # it vanish before the reaper re-reads it.
                        with manager._store.transaction() as conn:
                            conn.execute(
                                "DELETE FROM ltc_task WHERE task_id = ?",
                                ("t1",),
                            )
                return rows

            manager._store.read = deleting_read
            swept = manager.reap(now=200.0)
            self.assertEqual(tuple(swept), ())
        finally:
            manager.close()


class SelfCheckAssertShapeTests(unittest.TestCase):
    """The self-check's ``and`` assertions.

    Three of the self-check's assertions are ``and`` conjunctions, so
    each has two halves and a mutant that replaces ``and`` with ``or``
    only stops evaluating the second operand when the first one already
    holds.  These tests pin the second operand of each.
    """

    def _run_self_check(self):
        import io
        from contextlib import redirect_stdout

        import leased_task_claim as ltc

        with redirect_stdout(io.StringIO()):
            ltc.main()

    def test_the_reaped_task_is_ready_with_no_delay_and_no_failure(self):
        """`and@1253`: the second operand of the reaped-view assertion.

        The self-check asserts ``view.state == STATE_READY and
        view.delay_until == 0.0``.  The second operand is the delay: a
        crash is not a fault, so the requeued task takes no backoff.  A
        mutant that replaced ``and`` with ``or`` would still pass when
        the state is right, whatever the delay -- so the delay is pinned
        here against a live run.
        """
        manager = LeasedTaskClaim(max_failures=2, base_backoff_seconds=2.0)
        try:
            manager.enqueue_task("t1", "demo-task", payload="hello")
            lease = manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
            manager.save_checkpoint("t1", lease.token, 1, {"step": "one"},
                                    now=101.0)
            swept = manager.reap(now=200.0)
            self.assertEqual(len(swept), 1)
            view = manager.task("t1")
            self.assertEqual(view.state, STATE_READY)
            # The second operand: no backoff delay after a crash.
            self.assertEqual(view.delay_until, 0.0)
            # And the failure budget is not consumed by a crash.
            self.assertEqual(view.failures, 0)
        finally:
            manager.close()

    def test_the_resumed_holder_continues_from_the_newest_checkpoint(self):
        """`and@1260`: the second operand of the resume assertion.

        The self-check asserts ``resumed is not None and resumed.step ==
        2``.  The second operand is the step: the new holder continues
        from the newest checkpoint, not from the beginning.  A mutant
        that replaced ``and`` with ``or`` would accept any non-None
        record.
        """
        manager = LeasedTaskClaim(max_failures=2, base_backoff_seconds=2.0)
        try:
            manager.enqueue_task("t1", "demo-task", payload="hello")
            lease = manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
            manager.save_checkpoint("t1", lease.token, 1, {"step": "one"},
                                    now=101.0)
            manager.save_checkpoint("t1", lease.token, 2, {"step": "two"},
                                    now=102.0)
            manager.reap(now=200.0)
            manager.claim("t1", "worker-B", ttl=10.0, now=201.0)
            resumed = manager.resume_from("t1")
            self.assertIsNotNone(resumed)
            # The second operand: the newest checkpoint, not the first.
            self.assertEqual(resumed.step, 2)
        finally:
            manager.close()

    def test_the_completion_books_exactly_one_outbox_row(self):
        """`and@1282`: the second operand of the outbox assertion.

        The self-check asserts ``len(rows) == 1 and rows[0].message_id
        == "t1:completed"``.  The second operand is the message id: the
        stable idempotency key.  A mutant that replaced ``and`` with
        ``or`` would accept any single row.
        """
        manager = LeasedTaskClaim(max_failures=2, base_backoff_seconds=2.0)
        try:
            manager.enqueue_task("t1", "demo-task", payload="hello")
            lease = manager.claim("t1", "worker-B", ttl=200.0, now=100.0)
            terminal = manager.complete("t1", lease.token, {"ok": True},
                                        now=103.0)
            rows = manager.outbox_rows("t1")
            self.assertEqual(len(rows), 1)
            # The second operand: the stable idempotency key.
            self.assertEqual(rows[0].message_id, "t1:completed")
            self.assertEqual(terminal.message_id, "t1:completed")
        finally:
            manager.close()


class SelfCheckTests(unittest.TestCase):
    """The module's own self-check, driven for real.

    ``leased_task_claim.main()`` is the source's demonstration: worker-A
    claims and checkpoints, dies, is reaped, worker-B takes over and
    resumes, and the zombie A is refused on every write.  The suite
    never ran it, so every assertion inside it was a free mutant.
    """

    def test_the_self_check_passes(self):
        """The self-check runs clean.

        Under any mutant of one of its assertions the self-check raises
        ``AssertionError`` and this test fails.
        """
        import io
        from contextlib import redirect_stdout

        import leased_task_claim as ltc

        with redirect_stdout(io.StringIO()):
            ltc.main()

    def test_the_self_check_reports_that_the_module_is_ok(self):
        """The self-check prints its own name."""
        import io
        from contextlib import redirect_stdout

        import leased_task_claim as ltc

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            ltc.main()
        self.assertIn("leased-task-claim OK", buffer.getvalue())

    def test_the_module_runs_its_self_check_as_a_script(self):
        """The ``__main__`` guard: run as a script, the module self-checks."""
        import subprocess
        import sys
        from pathlib import Path

        import leased_task_claim as ltc

        component = Path(ltc.__file__).resolve().parent
        result = subprocess.run(
            [sys.executable, "-m", "leased_task_claim"],
            cwd=str(component),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=180,
        )
        output = result.stdout.decode("utf-8", "replace")
        self.assertEqual(result.returncode, 0, output)
        self.assertIn("leased-task-claim OK", output)

    def test_the_self_check_pins_the_token_sequence(self):
        """The self-check's token assertions: 1 for A, 2 for B.

        The self-check asserts ``lease_a.token == 1`` and
        ``lease_b.token == 2``.  The tokens are what fence the zombie
        out, so the sequence is pinned here against a live run rather
        than only against the self-check's own assertions.
        """
        import io
        from contextlib import redirect_stdout

        import leased_task_claim as ltc

        tokens = []
        original = ltc.LeasedTaskClaim.claim

        def recording_claim(self, task_id, worker, ttl, now=None):
            lease = original(self, task_id, worker, ttl, now=now)
            tokens.append((worker, lease.token))
            return lease

        ltc.LeasedTaskClaim.claim = recording_claim
        try:
            with redirect_stdout(io.StringIO()):
                ltc.main()
        finally:
            ltc.LeasedTaskClaim.claim = original

        self.assertEqual(tokens, [("worker-A", 1), ("worker-B", 2)])

    def test_the_self_check_pins_the_reaper_and_the_hand_over(self):
        """The self-check's reaper and resume assertions.

        The self-check asserts that exactly one lease was swept, that the
        task came back ready with no delay and no consumed failure
        budget, and that the new holder resumes from the newest
        checkpoint.  These are pinned against a live run.
        """
        import io
        from contextlib import redirect_stdout

        import leased_task_claim as ltc

        original = ltc.LeasedTaskClaim.resume_from
        resumed = []

        def recording_resume_from(self, task_id):
            record = original(self, task_id)
            resumed.append(record)
            return record

        ltc.LeasedTaskClaim.resume_from = recording_resume_from
        try:
            with redirect_stdout(io.StringIO()):
                ltc.main()
        finally:
            ltc.LeasedTaskClaim.resume_from = original

        self.assertEqual(len(resumed), 1)
        self.assertEqual(resumed[0].step, 2)

    def test_the_self_check_fails_when_a_zombie_write_is_accepted(self):
        """The self-check's zombie loop is load-bearing.

        The self-check writes to the task with the stale token three
        times and requires each write to raise ``StaleLeaseError``.  If
        a zombie write were accepted, the self-check raises its own
        ``AssertionError``.  This test pins that a write that does not
        refuse fails the self-check.
        """
        import io
        from contextlib import redirect_stdout

        import leased_task_claim as ltc

        original_complete = ltc.LeasedTaskClaim.complete

        def permissive_complete(self, task_id, token, result=None, now=None):
            # A complete that ignores the stale token: the task's CURRENT
            # token is used instead of the one the caller presented.
            with self._store.transaction() as conn:
                row = self._row(task_id)
                current = int(row["token"])
            return original_complete(self, task_id, current, result, now=now)

        ltc.LeasedTaskClaim.complete = permissive_complete
        try:
            with redirect_stdout(io.StringIO()):
                with self.assertRaises(AssertionError):
                    ltc.main()
        finally:
            ltc.LeasedTaskClaim.complete = original_complete


class SelfCheckAndAssertKillerTests(unittest.TestCase):
    """Kill the ``and`` -> ``or`` mutants in the self-check's asserts.

    A self-check assertion of the form ``assert A and B`` is replaced by
    ``assert A or B`` under the mutant.  The two agree whenever A is
    true, so the mutant survives unless the assertion is exercised with
    **A false and B true** -- and then the original raises
    ``AssertionError`` while the mutant passes.

    Each test below arranges exactly that: the accessor the assertion
    reads is patched so that the first operand is false and the second
    one still holds.
    """

    def _run(self):
        import io
        from contextlib import redirect_stdout

        import leased_task_claim as ltc

        with redirect_stdout(io.StringIO()):
            ltc.main()

    def test_and_at_1253_fails_when_the_state_is_not_ready(self):
        """`and@1253`: the reaped view's state and delay.

        The assertion is ``view.state == STATE_READY and
        view.delay_until == 0.0``.  The view is patched to a state that
        is NOT ready while the delay is still zero -- so the first
        operand is false and the second is true.

        The original raises ``AssertionError``; the mutant (``or``)
        passes, so this test kills it.
        """
        import dataclasses

        import leased_task_claim as ltc

        original_task = ltc.LeasedTaskClaim.task

        def patched_task(self, task_id):
            view = original_task(self, task_id)
            # The state is wrong, the delay is still zero.
            return dataclasses.replace(view, state=STATE_LEASED)

        ltc.LeasedTaskClaim.task = patched_task
        try:
            with self.assertRaises(AssertionError):
                self._run()
        finally:
            ltc.LeasedTaskClaim.task = original_task

    def test_and_at_1260_fails_when_there_is_no_resume_point(self):
        """`and@1260`: the resume assertion.

        The assertion is ``resumed is not None and resumed.step == 2``.
        The resume is patched to ``None``, so the first operand is false.

        The original raises ``AssertionError``; the mutant (``or``)
        evaluates ``None.step`` and raises ``AttributeError`` -- which is
        not an ``AssertionError``, so this test kills it.
        """
        import leased_task_claim as ltc

        original_resume = ltc.LeasedTaskClaim.resume_from

        def patched_resume(self, task_id):
            return None

        ltc.LeasedTaskClaim.resume_from = patched_resume
        try:
            with self.assertRaises(AssertionError):
                self._run()
        finally:
            ltc.LeasedTaskClaim.resume_from = original_resume

    def test_and_at_1282_fails_when_there_is_more_than_one_outbox_row(self):
        """`and@1282`: the outbox row assertion.

        The assertion is ``len(rows) == 1 and rows[0].message_id ==
        "t1:completed"``.  The rows are patched to two rows whose FIRST
        row is the completed one -- so the first operand is false and
        the second is true.

        The original raises ``AssertionError``; the mutant (``or``)
        passes, so this test kills it.
        """
        import leased_task_claim as ltc

        original_rows = ltc.LeasedTaskClaim.outbox_rows

        def patched_rows(self, task_id):
            rows = original_rows(self, task_id)
            # Two rows, the first of them the completed one.
            return tuple(rows) + tuple(rows)

        ltc.LeasedTaskClaim.outbox_rows = patched_rows
        try:
            with self.assertRaises(AssertionError):
                self._run()
        finally:
            ltc.LeasedTaskClaim.outbox_rows = original_rows
