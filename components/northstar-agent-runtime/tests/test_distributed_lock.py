"""Tests for distributed_lock: fencing tokens, contention, stale-holder refusal."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from distributed_lock import (
    DistributedLock,
    FencingToken,
    LockEvent,
    LockLease,
    distributed_lock_audit_event,
    DISTRIBUTED_LOCK_SCHEMA,
    DISTRIBUTED_LOCK_VERSION,
    EVENT_ACQUIRED,
    EVENT_EXPIRED,
    EVENT_REFUSED,
    EVENT_RELEASED,
    EVENT_RELEASE_REFUSED,
    EVENT_RENEWED,
)


class TestVersionPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(DISTRIBUTED_LOCK_VERSION, "distributed-lock.v1")

    def test_schema_pin(self):
        self.assertEqual(
            DISTRIBUTED_LOCK_SCHEMA, "northstar.distributed-lock.v1"
        )


class TestAcquire(unittest.TestCase):
    def setUp(self):
        self.mgr = DistributedLock()

    def test_acquire_happy_path(self):
        lease = self.mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=0)
        self.assertIsNotNone(lease)
        self.assertEqual(lease.lock_id, "ledger")
        self.assertEqual(lease.owner, "host-a")
        self.assertEqual(lease.fencing_token.token, 1)
        self.assertEqual(lease.acquired_seq, 0)
        self.assertEqual(lease.expiry_seq, 10)

    def test_acquire_contention_returns_none(self):
        self.mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=0)
        lease = self.mgr.acquire("ledger", "host-b", ttl_seqs=10, current_seq=1)
        self.assertIsNone(lease)
        self.assertTrue(self.mgr.is_locked("ledger", 1))
        self.assertEqual(self.mgr.current_holder("ledger"), "host-a")

    def test_same_owner_cannot_reacquire_while_held(self):
        self.mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=0)
        lease = self.mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=1)
        self.assertIsNone(lease)

    def test_acquire_after_expiry_mints_higher_token(self):
        first = self.mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=0)
        # Expired at seq 11 (valid through 10).
        second = self.mgr.acquire("ledger", "host-b", ttl_seqs=10, current_seq=11)
        self.assertIsNotNone(second)
        self.assertGreater(
            second.fencing_token.token, first.fencing_token.token
        )
        self.assertEqual(second.fencing_token.token, 2)

    def test_expiry_boundary_inclusive(self):
        lease = self.mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=0)
        self.assertFalse(lease.is_expired(10))  # valid through expiry_seq
        self.assertTrue(lease.is_expired(11))

    def test_frozen_lease(self):
        lease = self.mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=0)
        with self.assertRaises(Exception):
            lease.owner = "host-b"  # type: ignore[misc]

    def test_validation(self):
        with self.assertRaises(ValueError):
            self.mgr.acquire("", "host-a", ttl_seqs=10, current_seq=0)
        with self.assertRaises(ValueError):
            self.mgr.acquire("ledger", "  ", ttl_seqs=10, current_seq=0)
        with self.assertRaises(ValueError):
            self.mgr.acquire("ledger", "host-a", ttl_seqs=0, current_seq=0)
        with self.assertRaises(TypeError):
            self.mgr.acquire("ledger", "host-a", ttl_seqs=True, current_seq=0)
        with self.assertRaises(TypeError):
            self.mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=True)
        with self.assertRaises(ValueError):
            self.mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=-1)


class TestRelease(unittest.TestCase):
    def setUp(self):
        self.mgr = DistributedLock()

    def test_release_happy_path(self):
        lease = self.mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=0)
        self.assertTrue(
            self.mgr.release("ledger", "host-a", lease.fencing_token, 1)
        )
        self.assertFalse(self.mgr.is_locked("ledger", 1))

    def test_release_with_int_token(self):
        self.mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=0)
        self.assertTrue(self.mgr.release("ledger", "host-a", 1, 1))

    def test_stale_token_release_refused(self):
        self.mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=0)
        self.mgr.release("ledger", "host-a", 1, current_seq=1)
        # host-b re-acquires with token 2.
        lease2 = self.mgr.acquire("ledger", "host-b", ttl_seqs=10, current_seq=2)
        self.assertEqual(lease2.fencing_token.token, 2)
        # Stale holder host-a cannot release host-b's lock.
        self.assertFalse(self.mgr.release("ledger", "host-a", 1, current_seq=3))
        self.assertTrue(self.mgr.is_locked("ledger", 3))
        self.assertEqual(self.mgr.current_holder("ledger"), "host-b")

    def test_release_by_non_holder_refused(self):
        self.mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=0)
        self.assertFalse(self.mgr.release("ledger", "host-b", 1, current_seq=1))
        self.assertTrue(self.mgr.is_locked("ledger", 1))

    def test_release_free_lock_refused(self):
        self.assertFalse(self.mgr.release("ledger", "host-a", 1, current_seq=0))

    def test_release_expired_lease_refused_and_cleared(self):
        self.mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=0)
        # Lease died at seq 11; release at 12 clears the dead record.
        self.assertFalse(self.mgr.release("ledger", "host-a", 1, current_seq=12))
        # A fresh acquire works and mints a higher token.
        lease = self.mgr.acquire("ledger", "host-b", ttl_seqs=10, current_seq=13)
        self.assertEqual(lease.fencing_token.token, 2)

    def test_release_token_for_other_lock_rejected(self):
        lease = self.mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=0)
        with self.assertRaises(ValueError):
            self.mgr.release("other", "host-a", lease.fencing_token, 1)


class TestFencing(unittest.TestCase):
    def setUp(self):
        self.mgr = DistributedLock()

    def test_verify_fencing_current(self):
        self.mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=0)
        self.assertTrue(self.mgr.verify_fencing("ledger", 1))

    def test_verify_fencing_stale(self):
        self.mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=0)
        self.mgr.release("ledger", "host-a", 1, current_seq=1)
        self.mgr.acquire("ledger", "host-b", ttl_seqs=10, current_seq=2)
        self.assertFalse(self.mgr.verify_fencing("ledger", 1))
        self.assertTrue(self.mgr.verify_fencing("ledger", 2))

    def test_verify_fencing_unknown_lock(self):
        self.assertFalse(self.mgr.verify_fencing("never-taken", 1))

    def test_verify_fencing_with_token_record(self):
        lease = self.mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=0)
        self.assertTrue(self.mgr.verify_fencing("ledger", lease.fencing_token))

    def test_current_token_none_for_unknown_lock(self):
        self.assertIsNone(self.mgr.current_token("never-taken"))

    def test_token_never_reset_across_cycles(self):
        for i, owner in enumerate(["a", "b", "c"]):
            self.mgr.acquire("ledger", owner, ttl_seqs=10, current_seq=i * 20)
            self.mgr.release("ledger", owner, i + 1, current_seq=i * 20 + 1)
        self.assertEqual(self.mgr.current_token("ledger"), 3)


class TestEventsAndAudit(unittest.TestCase):
    def test_event_ordering(self):
        mgr = DistributedLock()
        mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=0)
        mgr.acquire("ledger", "host-b", ttl_seqs=10, current_seq=1)
        mgr.release("ledger", "host-a", 1, current_seq=2)
        kinds = [e.kind for e in mgr.events()]
        self.assertEqual(
            kinds, [EVENT_ACQUIRED, EVENT_REFUSED, EVENT_RELEASED]
        )

    def test_expiry_event_on_lazy_reacquire(self):
        mgr = DistributedLock()
        mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=0)
        mgr.acquire("ledger", "host-b", ttl_seqs=10, current_seq=11)
        kinds = [e.kind for e in mgr.events()]
        self.assertEqual(kinds, [EVENT_ACQUIRED, EVENT_EXPIRED, EVENT_ACQUIRED])

    def test_release_refused_event(self):
        mgr = DistributedLock()
        mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=0)
        mgr.release("ledger", "host-b", 1, current_seq=1)
        last = mgr.events()[-1]
        self.assertEqual(last.kind, EVENT_RELEASE_REFUSED)
        self.assertEqual(last.reason, "not-holder")

    def test_event_frozen(self):
        mgr = DistributedLock()
        mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=0)
        with self.assertRaises(Exception):
            mgr.events()[0].kind = "tampered"  # type: ignore[misc]

    def test_lease_digest_roundtrip(self):
        mgr = DistributedLock()
        lease = mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=0)
        digest = lease.digest()
        self.assertTrue(digest.startswith("sha256:"))
        self.assertEqual(digest, lease.digest())

    def test_audit_event_shape(self):
        event = distributed_lock_audit_event(
            EVENT_ACQUIRED, "ledger", "host-a", seq=7, token=1
        )
        self.assertEqual(event["type"], "audit.ndjson/1")
        self.assertEqual(event["event"], EVENT_ACQUIRED)
        self.assertEqual(event["lock_id"], "ledger")
        self.assertEqual(event["token"], 1)
        self.assertEqual(event["seq"], 7)
        self.assertEqual(event["schema"], DISTRIBUTED_LOCK_SCHEMA)

    def test_audit_event_validation(self):
        with self.assertRaises(ValueError):
            distributed_lock_audit_event("bogus", "ledger", "host-a", seq=0)


class TestRenew(unittest.TestCase):
    def setUp(self):
        self.mgr = DistributedLock()

    def test_renew_happy_path_extends_expiry(self):
        lease = self.mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=0)
        renewed = self.mgr.renew("ledger", "host-a", 1, ttl_seqs=20, current_seq=5)
        self.assertIsNotNone(renewed)
        self.assertEqual(renewed.expiry_seq, 25)
        self.assertEqual(renewed.acquired_seq, 0)

    def test_renew_keeps_fencing_token(self):
        lease = self.mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=0)
        renewed = self.mgr.renew("ledger", "host-a", 1, ttl_seqs=10, current_seq=3)
        self.assertEqual(renewed.fencing_token.token, 1)
        self.assertEqual(self.mgr.current_token("ledger"), 1)
        self.assertTrue(renewed.digest())

    def test_renew_by_non_holder_refused(self):
        self.mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=0)
        self.assertIsNone(self.mgr.renew("ledger", "host-b", 1, 10, 1))
        kinds = [e.kind for e in self.mgr.events()]
        self.assertIn(EVENT_REFUSED, kinds)

    def test_renew_stale_token_refused(self):
        self.mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=0)
        self.mgr.release("ledger", "host-a", 1, current_seq=1)
        self.mgr.acquire("ledger", "host-b", ttl_seqs=10, current_seq=2)
        # old token 1 is stale now; renew with it is refused
        self.assertIsNone(self.mgr.renew("ledger", "host-a", 1, 10, 3))
        self.assertTrue(self.mgr.is_locked("ledger", 3))

    def test_renew_expired_lease_refused(self):
        self.mgr.acquire("ledger", "host-a", ttl_seqs=5, current_seq=0)
        # lease valid through seq 5; renew at seq 6 is too late
        self.assertIsNone(self.mgr.renew("ledger", "host-a", 1, 10, 6))
        self.assertFalse(self.mgr.is_locked("ledger", 6))
        # stale holder must re-acquire and takes a fresh token
        lease = self.mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=7)
        self.assertEqual(lease.fencing_token.token, 2)

    def test_renew_unknown_lock_refused(self):
        self.assertIsNone(self.mgr.renew("ghost", "host-a", 1, 10, 0))

    def test_renew_bad_ttl(self):
        self.mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=0)
        with self.assertRaises(ValueError):
            self.mgr.renew("ledger", "host-a", 1, 0, 1)
        with self.assertRaises(TypeError):
            self.mgr.renew("ledger", "host-a", 1, True, 1)

    def test_renew_bad_seq(self):
        self.mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=0)
        with self.assertRaises(ValueError):
            self.mgr.renew("ledger", "host-a", 1, 10, -1)

    def test_renew_event_recorded(self):
        self.mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=0)
        self.mgr.renew("ledger", "host-a", 1, ttl_seqs=10, current_seq=4)
        kinds = [e.kind for e in self.mgr.events()]
        self.assertEqual(kinds, [EVENT_ACQUIRED, EVENT_RENEWED])

    def test_renew_audit_event_shape(self):
        event = distributed_lock_audit_event(
            EVENT_RENEWED, "ledger", "host-a", seq=9, token=2
        )
        self.assertEqual(event["type"], "audit.ndjson/1")
        self.assertEqual(event["event"], EVENT_RENEWED)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        import distributed_lock as mod

        # main() asserts internally; it must not raise.
        mod.main()


if __name__ == "__main__":
    unittest.main()
