"""Tests for approval_sla_time.py (wall-clock SLA variant)."""

import time
import unittest
from unittest import mock

import approval_sla_time as sla


def _req(**kw):
    base = dict(
        id="apr-test",
        action="rm -rf /tmp/x",
        reason="abstain: destructive",
        requested_at=1_000_000.0,
        timeout_seconds=60.0,
    )
    base.update(kw)
    return sla.ApprovalRequest(**base)


class VersionPinTests(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(sla.APPROVAL_SLA_TIME_VERSION, "approval-sla-time.v1")
        # Distinct from the seq-based record shape: not interchangeable.
        self.assertNotEqual(sla.APPROVAL_SLA_TIME_VERSION, "approval-sla.v1")


class RequestConstructionTests(unittest.TestCase):
    def test_defaults_pending(self):
        r = _req()
        self.assertEqual(r.status, sla.STATUS_PENDING)
        self.assertIsNone(r.decided_by)
        self.assertIsNone(r.decided_at)

    def test_deadline_property(self):
        r = _req(requested_at=1000.0, timeout_seconds=30.0)
        self.assertEqual(r.deadline, 1030.0)

    def test_frozen(self):
        r = _req()
        with self.assertRaises(Exception):
            r.status = sla.STATUS_APPROVED  # type: ignore[misc]

    def test_rejects_negative_requested_at(self):
        with self.assertRaises(ValueError):
            _req(requested_at=-1.0)

    def test_rejects_bool_requested_at(self):
        with self.assertRaises(TypeError):
            _req(requested_at=True)

    def test_rejects_non_numeric_requested_at(self):
        with self.assertRaises(TypeError):
            _req(requested_at="yesterday")

    def test_rejects_non_positive_timeout(self):
        for bad in (0.0, -5.0):
            with self.assertRaises(ValueError, msg=f"timeout={bad}"):
                _req(timeout_seconds=bad)

    def test_rejects_bool_timeout(self):
        with self.assertRaises(TypeError):
            _req(timeout_seconds=True)

    def test_rejects_empty_action_reason(self):
        with self.assertRaises(ValueError):
            _req(action="")
        with self.assertRaises(ValueError):
            _req(reason="")

    def test_pending_must_not_carry_decision(self):
        with self.assertRaises(ValueError):
            _req(decided_by="op-1")
        with self.assertRaises(ValueError):
            _req(decided_at=1_000_001.0)

    def test_approved_requires_decision_fields(self):
        with self.assertRaises(ValueError):
            _req(status=sla.STATUS_APPROVED)
        r = _req(
            status=sla.STATUS_APPROVED,
            decided_by="op-1",
            decided_at=1_000_001.0,
        )
        self.assertEqual(r.status, sla.STATUS_APPROVED)

    def test_rejects_unknown_status(self):
        with self.assertRaises(ValueError):
            _req(status="maybe")


class IsExpiredTests(unittest.TestCase):
    def test_expired_when_past_deadline(self):
        r = _req(requested_at=time.time() - 100.0, timeout_seconds=10.0)
        self.assertTrue(r.is_expired())

    def test_not_expired_when_before_deadline(self):
        r = _req(requested_at=time.time() + 3600.0, timeout_seconds=60.0)
        self.assertFalse(r.is_expired())

    def test_boundary_exactly_at_deadline_is_not_expired(self):
        # Strict: now > deadline. At exactly the deadline, still pending.
        r = _req(requested_at=1000.0, timeout_seconds=30.0)
        self.assertFalse(r._is_expired_at(1030.0))
        self.assertTrue(r._is_expired_at(1030.000001))

    def test_is_expired_uses_wall_clock(self):
        # requested_at=now-100, timeout=10: expired under any real clock.
        with mock.patch.object(sla.time, "time", return_value=2_000_000.0):
            r = _req(requested_at=1_999_800.0, timeout_seconds=10.0)
            self.assertTrue(r.is_expired())
            r2 = _req(requested_at=1_999_990.0, timeout_seconds=60.0)
            self.assertFalse(r2.is_expired())


class QueueEnqueueTests(unittest.TestCase):
    def test_enqueue_returns_unique_ids(self):
        q = sla.ApprovalQueue()
        a = q.enqueue("act", "why", 60.0)
        b = q.enqueue("act", "why", 60.0)
        self.assertNotEqual(a, b)
        self.assertTrue(a.startswith("apr-"))

    def test_enqueue_validation(self):
        q = sla.ApprovalQueue()
        with self.assertRaises(ValueError):
            q.enqueue("", "why", 60.0)
        with self.assertRaises(ValueError):
            q.enqueue("act", "", 60.0)
        with self.assertRaises(ValueError):
            q.enqueue("act", "why", 0.0)
        with self.assertRaises(TypeError):
            q.enqueue("act", "why", True)

    def test_len_contains_iter(self):
        q = sla.ApprovalQueue()
        self.assertEqual(len(q), 0)
        rid = q.enqueue("act", "why", 60.0)
        self.assertEqual(len(q), 1)
        self.assertIn(rid, q)
        self.assertNotIn("apr-nope", q)
        self.assertEqual([r.id for r in q], [rid])


class QueuePollTests(unittest.TestCase):
    def test_poll_pending(self):
        q = sla.ApprovalQueue()
        rid = q.enqueue("act", "why", 3600.0)
        self.assertEqual(q.poll(rid), sla.STATUS_PENDING)

    def test_poll_expires_and_sticks(self):
        q = sla.ApprovalQueue()
        rid = q.enqueue("act", "why", 3600.0)
        rec = q.get(rid)
        # Rewrite the stored record with a past timestamp (white-box,
        # avoids sleeping): the queue must observe expiry and stick.
        q._requests[rid] = sla.ApprovalRequest(
            id=rec.id,
            action=rec.action,
            reason=rec.reason,
            requested_at=time.time() - 100.0,
            timeout_seconds=10.0,
        )
        self.assertEqual(q.poll(rid), sla.STATUS_EXPIRED)
        self.assertEqual(q.poll(rid), sla.STATUS_EXPIRED)
        self.assertEqual(q.get(rid).status, sla.STATUS_EXPIRED)

    def test_poll_unknown_raises(self):
        q = sla.ApprovalQueue()
        with self.assertRaises(KeyError):
            q.poll("apr-nope")


class QueueDecideTests(unittest.TestCase):
    def test_decide_approve(self):
        q = sla.ApprovalQueue()
        rid = q.enqueue("act", "why", 3600.0)
        rec = q.decide(rid, True, "op-1")
        self.assertEqual(rec.status, sla.STATUS_APPROVED)
        self.assertEqual(rec.decided_by, "op-1")
        self.assertIsNotNone(rec.decided_at)
        self.assertEqual(q.poll(rid), sla.STATUS_APPROVED)

    def test_decide_deny(self):
        q = sla.ApprovalQueue()
        rid = q.enqueue("act", "why", 3600.0)
        rec = q.decide(rid, False, "op-2")
        self.assertEqual(rec.status, sla.STATUS_DENIED)

    def test_decide_expired_fails_closed(self):
        q = sla.ApprovalQueue()
        rid = q.enqueue("act", "why", 3600.0)
        rec = q.get(rid)
        q._requests[rid] = sla.ApprovalRequest(
            id=rec.id,
            action=rec.action,
            reason=rec.reason,
            requested_at=time.time() - 100.0,
            timeout_seconds=10.0,
        )
        # decide() itself sweeps expiry first: never approves a lapsed SLA.
        with self.assertRaises(ValueError):
            q.decide(rid, True, "op-1")
        self.assertEqual(q.get(rid).status, sla.STATUS_EXPIRED)

    def test_decide_twice_refused(self):
        q = sla.ApprovalQueue()
        rid = q.enqueue("act", "why", 3600.0)
        q.decide(rid, True, "op-1")
        with self.assertRaises(ValueError):
            q.decide(rid, False, "op-2")

    def test_decide_rejects_non_bool(self):
        q = sla.ApprovalQueue()
        rid = q.enqueue("act", "why", 3600.0)
        with self.assertRaises(TypeError):
            q.decide(rid, "yes", "op-1")  # type: ignore[arg-type]

    def test_decide_rejects_empty_decider(self):
        q = sla.ApprovalQueue()
        rid = q.enqueue("act", "why", 3600.0)
        with self.assertRaises(ValueError):
            q.decide(rid, True, "")

    def test_decide_unknown_raises(self):
        q = sla.ApprovalQueue()
        with self.assertRaises(KeyError):
            q.decide("apr-nope", True, "op-1")


class QueueViewsTests(unittest.TestCase):
    def test_pending_expired_decided_views(self):
        q = sla.ApprovalQueue()
        r1 = q.enqueue("a1", "why", 3600.0)
        r2 = q.enqueue("a2", "why", 3600.0)
        r3 = q.enqueue("a3", "why", 3600.0)
        q.decide(r1, True, "op-1")
        rec3 = q.get(r3)
        q._requests[r3] = sla.ApprovalRequest(
            id=rec3.id,
            action=rec3.action,
            reason=rec3.reason,
            requested_at=time.time() - 100.0,
            timeout_seconds=10.0,
            status=sla.STATUS_EXPIRED,
        )
        self.assertEqual([r.id for r in q.pending()], [r2])
        self.assertEqual([r.id for r in q.expired()], [r3])
        self.assertEqual([r.id for r in q.decided()], [r1])


class MainTests(unittest.TestCase):
    def test_main_runs(self):
        sla.main()


if __name__ == "__main__":
    unittest.main()
