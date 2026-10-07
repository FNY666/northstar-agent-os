"""Tests for the audit_shipper module (SIEM forwarding batch/forward/retry)."""

import unittest

from audit_shipper import (
    AUDIT_SHIPPER_VERSION,
    SCHEMA_PIN,
    AuditShipper,
    AuditShipperError,
    BatchError,
    DuplicateEnqueueError,
    ShippedBatch,
    audit_shipper_audit_event,
    main,
)


class TestPins(unittest.TestCase):
    def test_version_and_schema(self):
        self.assertEqual(AUDIT_SHIPPER_VERSION, "audit-shipper.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.audit-shipper.v1")


class TestEnqueue(unittest.TestCase):
    def test_enqueue_happy_path(self):
        ship = AuditShipper()
        rec = ship.enqueue("a-1", {"event": "granted"}, 0)
        self.assertEqual(rec.record_id, "a-1")
        self.assertTrue(rec.payload_digest.startswith("sha256:"))
        self.assertEqual(ship.pending_count(), 1)

    def test_enqueue_duplicate_rejected(self):
        ship = AuditShipper()
        ship.enqueue("a-1", {"event": "x"}, 0)
        with self.assertRaises(DuplicateEnqueueError):
            ship.enqueue("a-1", {"event": "x"}, 1)

    def test_enqueue_validation(self):
        ship = AuditShipper()
        with self.assertRaises(AuditShipperError):
            ship.enqueue("", {"event": "x"}, 0)
        with self.assertRaises(AuditShipperError):
            ship.enqueue("a-2", {"event": "x"}, -1)
        with self.assertRaises(AuditShipperError):
            ship.enqueue("a-3", {"event": "x"}, True)
        with self.assertRaises(AuditShipperError):
            ship.enqueue("a-4", "not-a-mapping", 2)
        with self.assertRaises(AuditShipperError):
            ship.enqueue("a-5", {"v": float("nan")}, 3)

    def test_seq_must_strictly_increase(self):
        ship = AuditShipper()
        ship.enqueue("a-1", {"event": "x"}, 5)
        with self.assertRaises(AuditShipperError):
            ship.enqueue("a-2", {"event": "x"}, 5)

    def test_constructor_validation(self):
        with self.assertRaises(AuditShipperError):
            AuditShipper(max_batch_size=0)
        with self.assertRaises(AuditShipperError):
            AuditShipper(max_batch_size=True)


class TestFlush(unittest.TestCase):
    def test_flush_happy_path(self):
        seen: list[ShippedBatch] = []
        ship = AuditShipper(sink=lambda b: seen.append(b) or True)
        ship.enqueue("a-1", {"event": "x"}, 0)
        out = ship.flush(1)
        self.assertEqual((out.batches_delivered, out.records_delivered), (1, 1))
        self.assertEqual(out.records_pending, 0)
        self.assertEqual(ship.pending_count(), 0)

    def test_flush_empty_noop(self):
        ship = AuditShipper()
        out = ship.flush(0)
        self.assertEqual(out.as_dict()["batches_delivered"], 0)

    def test_batch_size_respected(self):
        seen: list[ShippedBatch] = []
        ship = AuditShipper(max_batch_size=2, sink=lambda b: seen.append(b) or True)
        for i in range(5):
            ship.enqueue(f"a-{i}", {"event": "x"}, i)
        out = ship.flush(5)
        self.assertEqual(out.records_delivered, 2)
        self.assertEqual(ship.pending_count(), 3)

    def test_batch_digest_verifies(self):
        seen: list[ShippedBatch] = []
        ship = AuditShipper(sink=lambda b: seen.append(b) or True)
        ship.enqueue("a-1", {"event": "x"}, 0)
        ship.flush(1)
        self.assertTrue(seen[0].verify())

    def test_failed_flush_keeps_pending(self):
        ship = AuditShipper(sink=lambda b: False)
        ship.enqueue("a-1", {"event": "x"}, 0)
        out = ship.flush(1)
        self.assertEqual(out.batches_failed, 1)
        self.assertEqual(out.records_pending, 1)
        self.assertEqual(ship.pending_count(), 1)
        self.assertEqual(ship.stats()["failed_batches"], 1)


class TestRetry(unittest.TestCase):
    def test_retry_succeeds_after_failure(self):
        calls = {"fail": True}
        seen: list[ShippedBatch] = []

        def flaky(batch: ShippedBatch) -> bool:
            seen.append(batch)
            if calls["fail"]:
                calls["fail"] = False
                return False
            return True

        ship = AuditShipper(sink=flaky)
        ship.enqueue("a-1", {"event": "x"}, 0)
        ship.flush(1)
        out = ship.retry(2)
        self.assertEqual((out.batches_delivered, out.records_delivered), (1, 1))
        self.assertEqual(seen[-1].attempt, 2)

    def test_retry_empty_outbox_refused(self):
        ship = AuditShipper()
        with self.assertRaises(BatchError):
            ship.retry(0)

    def test_retry_failed_again_keeps_pending(self):
        ship = AuditShipper(sink=lambda b: False)
        ship.enqueue("a-1", {"event": "x"}, 0)
        ship.flush(1)
        out = ship.retry(2)
        self.assertEqual(out.batches_failed, 1)
        self.assertEqual(ship.pending_count(), 1)


class TestAuditAndMain(unittest.TestCase):
    def test_audit_event_shapes(self):
        ev = audit_shipper_audit_event("enqueued", 3, record_id="a-1")
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["event"], "enqueued")
        self.assertEqual(ev["audit_seq"], 3)
        with self.assertRaises(AuditShipperError):
            audit_shipper_audit_event("bogus", 0)

    def test_main(self):
        self.assertIsNone(main())


if __name__ == "__main__":
    unittest.main()
