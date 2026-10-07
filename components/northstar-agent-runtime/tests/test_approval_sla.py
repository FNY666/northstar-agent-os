"""Tests for approval_sla."""

from __future__ import annotations

import unittest

from approval_sla import (
    APPROVAL_SLA_VERSION,
    STATUS_APPROVED,
    STATUS_DENIED,
    STATUS_EXPIRED,
    STATUS_PENDING,
    ApprovalQueue,
    ApprovalRequest,
)


class VersionTest(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(APPROVAL_SLA_VERSION, "approval-sla.v1")


class EnqueueTest(unittest.TestCase):
    def setUp(self):
        self.q = ApprovalQueue()

    def test_enqueue_returns_id_and_stores_record(self):
        rid = self.q.enqueue("restart db", "abstain: stateful", 10, current_seq=100)
        self.assertIsInstance(rid, str)
        self.assertTrue(rid)
        rec = self.q.get(rid)
        self.assertEqual(rec.id, rid)
        self.assertEqual(rec.action, "restart db")
        self.assertEqual(rec.reason, "abstain: stateful")
        self.assertEqual(rec.requested_seq, 100)
        self.assertEqual(rec.sla_deadline_seq, 110)
        self.assertEqual(rec.status, STATUS_PENDING)
        self.assertIsNone(rec.decided_by)

    def test_ids_are_unique(self):
        a = self.q.enqueue("a", "r", 5, current_seq=0)
        b = self.q.enqueue("a", "r", 5, current_seq=0)
        self.assertNotEqual(a, b)
        self.assertEqual(len(self.q), 2)

    def test_rejects_empty_action(self):
        with self.assertRaises(ValueError):
            self.q.enqueue("", "r", 5, current_seq=0)

    def test_rejects_empty_reason(self):
        with self.assertRaises(ValueError):
            self.q.enqueue("a", "", 5, current_seq=0)

    def test_rejects_non_positive_sla(self):
        for bad in (0, -3):
            with self.assertRaises(ValueError, msg=f"sla={bad}"):
                self.q.enqueue("a", "r", bad, current_seq=0)

    def test_rejects_bool_sla(self):
        with self.assertRaises(TypeError):
            self.q.enqueue("a", "r", True, current_seq=0)

    def test_rejects_bad_current_seq(self):
        with self.assertRaises(ValueError):
            self.q.enqueue("a", "r", 5, current_seq=-1)
        with self.assertRaises(TypeError):
            self.q.enqueue("a", "r", 5, current_seq=True)

    def test_request_record_is_frozen(self):
        rid = self.q.enqueue("a", "r", 5, current_seq=0)
        rec = self.q.get(rid)
        with self.assertRaises(AttributeError):
            rec.status = STATUS_APPROVED  # type: ignore[misc]


class PollTest(unittest.TestCase):
    def setUp(self):
        self.q = ApprovalQueue()

    def test_pending_within_sla(self):
        rid = self.q.enqueue("a", "r", 10, current_seq=100)
        self.assertEqual(self.q.poll(rid, 100), STATUS_PENDING)
        self.assertEqual(self.q.poll(rid, 105), STATUS_PENDING)

    def test_pending_at_exact_deadline(self):
        # Expiry is strict: current_seq > deadline. At the deadline
        # itself the request is still pending.
        rid = self.q.enqueue("a", "r", 10, current_seq=100)
        self.assertEqual(self.q.poll(rid, 110), STATUS_PENDING)

    def test_expired_past_deadline(self):
        rid = self.q.enqueue("a", "r", 10, current_seq=100)
        self.assertEqual(self.q.poll(rid, 111), STATUS_EXPIRED)

    def test_expiry_is_sticky(self):
        rid = self.q.enqueue("a", "r", 10, current_seq=100)
        self.assertEqual(self.q.poll(rid, 111), STATUS_EXPIRED)
        self.assertEqual(self.q.poll(rid, 112), STATUS_EXPIRED)
        self.assertEqual(self.q.poll(rid, 10_000), STATUS_EXPIRED)
        self.assertEqual(self.q.get(rid).status, STATUS_EXPIRED)

    def test_poll_unknown_raises_keyerror(self):
        with self.assertRaises(KeyError):
            self.q.poll("apr-nope", 0)

    def test_poll_rejects_bad_seq(self):
        rid = self.q.enqueue("a", "r", 10, current_seq=0)
        with self.assertRaises(TypeError):
            self.q.poll(rid, True)
        with self.assertRaises(ValueError):
            self.q.poll(rid, -1)


class DecideTest(unittest.TestCase):
    def setUp(self):
        self.q = ApprovalQueue()

    def test_decide_approve(self):
        rid = self.q.enqueue("a", "r", 10, current_seq=50)
        rec = self.q.decide(rid, True, "op-1")
        self.assertEqual(rec.status, STATUS_APPROVED)
        self.assertEqual(rec.decided_by, "op-1")
        self.assertEqual(self.q.poll(rid, 55), STATUS_APPROVED)

    def test_decide_deny(self):
        rid = self.q.enqueue("a", "r", 10, current_seq=50)
        rec = self.q.decide(rid, False, "op-2")
        self.assertEqual(rec.status, STATUS_DENIED)
        self.assertEqual(rec.decided_by, "op-2")
        self.assertEqual(self.q.poll(rid, 55), STATUS_DENIED)

    def test_decide_twice_raises(self):
        rid = self.q.enqueue("a", "r", 10, current_seq=50)
        self.q.decide(rid, True, "op-1")
        with self.assertRaises(ValueError):
            self.q.decide(rid, False, "op-1")

    def test_decide_expired_raises_fail_closed(self):
        # Expiry never converts into an approval: deciding an expired
        # request is refused.
        rid = self.q.enqueue("a", "r", 10, current_seq=50)
        self.assertEqual(self.q.poll(rid, 61), STATUS_EXPIRED)
        with self.assertRaises(ValueError):
            self.q.decide(rid, True, "op-1")
        with self.assertRaises(ValueError):
            self.q.decide(rid, False, "op-1")
        self.assertEqual(self.q.get(rid).status, STATUS_EXPIRED)

    def test_decide_unknown_raises_keyerror(self):
        with self.assertRaises(KeyError):
            self.q.decide("apr-nope", True, "op-1")

    def test_decide_rejects_non_bool(self):
        rid = self.q.enqueue("a", "r", 10, current_seq=50)
        with self.assertRaises(TypeError):
            self.q.decide(rid, 1, "op-1")  # type: ignore[arg-type]

    def test_decide_rejects_empty_decider(self):
        rid = self.q.enqueue("a", "r", 10, current_seq=50)
        with self.assertRaises(ValueError):
            self.q.decide(rid, True, "")


class ViewsTest(unittest.TestCase):
    def test_pending_expired_decided_views(self):
        q = ApprovalQueue()
        r_pending = q.enqueue("a", "r", 100, current_seq=0)
        r_expire = q.enqueue("b", "r", 5, current_seq=0)
        r_ok = q.enqueue("c", "r", 100, current_seq=0)
        r_no = q.enqueue("d", "r", 100, current_seq=0)
        q.decide(r_ok, True, "op-1")
        q.decide(r_no, False, "op-1")
        q.poll(r_expire, 6)  # expire it

        self.assertEqual([r.id for r in q.pending()], [r_pending])
        self.assertEqual([r.id for r in q.expired()], [r_expire])
        self.assertEqual(
            sorted(r.id for r in q.decided()), sorted([r_ok, r_no])
        )

    def test_len_contains_iter(self):
        q = ApprovalQueue()
        self.assertEqual(len(q), 0)
        rid = q.enqueue("a", "r", 5, current_seq=0)
        self.assertEqual(len(q), 1)
        self.assertIn(rid, q)
        self.assertNotIn("apr-nope", q)
        self.assertEqual([r.id for r in q], [rid])


class RecordValidationTest(unittest.TestCase):
    def test_deadline_before_requested_rejected(self):
        with self.assertRaises(ValueError):
            ApprovalRequest(
                id="x",
                action="a",
                reason="r",
                requested_seq=10,
                sla_deadline_seq=9,
            )

    def test_unknown_status_rejected(self):
        with self.assertRaises(ValueError):
            ApprovalRequest(
                id="x",
                action="a",
                reason="r",
                requested_seq=0,
                sla_deadline_seq=1,
                status="bogus",
            )

    def test_pending_with_decision_fields_rejected(self):
        with self.assertRaises(ValueError):
            ApprovalRequest(
                id="x",
                action="a",
                reason="r",
                requested_seq=0,
                sla_deadline_seq=1,
                decided_by="op-1",
            )

    def test_approved_without_decider_rejected(self):
        with self.assertRaises(ValueError):
            ApprovalRequest(
                id="x",
                action="a",
                reason="r",
                requested_seq=0,
                sla_deadline_seq=1,
                status=STATUS_APPROVED,
            )


class MainTest(unittest.TestCase):
    def test_main_runs(self):
        import approval_sla

        approval_sla.main()


if __name__ == "__main__":
    unittest.main()
