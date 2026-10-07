"""Tests for bilinear_accumulator (simulated pairing-based set commitments)."""

import unittest

from bilinear_accumulator import (
    BILINEAR_ACCUMULATOR_SCHEMA,
    BILINEAR_ACCUMULATOR_VERSION,
    EVENT_ADDED,
    EVENT_REJECTED,
    EVENT_REMOVED,
    EVENT_VERIFIED,
    EVENT_WITNESS_ISSUED,
    AccumulatorError,
    AccumulatorValue,
    BilinearAccumulator,
    CapacityExceededError,
    MembershipWitness,
    UnknownElementError,
    bilinear_accumulator_audit_event,
    main,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(BILINEAR_ACCUMULATOR_VERSION, "bilinear-accumulator.v1")

    def test_schema_pin(self):
        self.assertEqual(
            BILINEAR_ACCUMULATOR_SCHEMA, "northstar.bilinear-accumulator.v1"
        )


class TestConstructor(unittest.TestCase):
    def test_default(self):
        acc = BilinearAccumulator()
        self.assertEqual(acc.max_size, 64)
        self.assertEqual(acc.member_count, 0)

    def test_custom_max_size(self):
        acc = BilinearAccumulator(max_size=3)
        self.assertEqual(acc.max_size, 3)

    def test_bad_max_size(self):
        for bad in (0, -1, True, False, "8", 8.0, None):
            with self.assertRaises((TypeError, ValueError)):
                BilinearAccumulator(max_size=bad)


class TestAdd(unittest.TestCase):
    def test_add_happy_path(self):
        acc = BilinearAccumulator()
        value = acc.add("alice", seq=1)
        self.assertIsInstance(value, AccumulatorValue)
        self.assertEqual(value.member_count, 1)
        self.assertEqual(acc.member_count, 1)
        self.assertTrue(value.digest.startswith("sha256:"))

    def test_add_digest_determinism(self):
        a1 = BilinearAccumulator()
        a2 = BilinearAccumulator()
        a1.add("alice", seq=1)
        a2.add("alice", seq=1)
        self.assertEqual(a1.value().digest, a2.value().digest)

    def test_add_order_independence(self):
        # The accumulator is a product: insertion order must not matter.
        a1 = BilinearAccumulator()
        a2 = BilinearAccumulator()
        for el in ("alice", "bob", "carol"):
            a1.add(el, seq=1)
        for el in ("carol", "alice", "bob"):
            a2.add(el, seq=1)
        self.assertEqual(a1.value().digest, a2.value().digest)

    def test_add_duplicate_idempotent(self):
        acc = BilinearAccumulator()
        v1 = acc.add("alice", seq=1)
        v2 = acc.add("alice", seq=2)
        self.assertEqual(v1.digest, v2.digest)
        self.assertEqual(acc.member_count, 1)

    def test_add_capacity(self):
        acc = BilinearAccumulator(max_size=2)
        acc.add("a", seq=1)
        acc.add("b", seq=2)
        with self.assertRaises(CapacityExceededError):
            acc.add("c", seq=3)
        self.assertEqual(acc.member_count, 2)

    def test_add_bad_seq(self):
        acc = BilinearAccumulator()
        for bad in (-1, True, "1", 1.0, None):
            with self.assertRaises((TypeError, ValueError)):
                acc.add("alice", seq=bad)

    def test_element_validation(self):
        acc = BilinearAccumulator()
        bad_elements = ("", b"", True, False, -1, None, 1.5, ["x"], {"x": 1})
        for bad in bad_elements:
            with self.assertRaises((TypeError, ValueError)):
                acc.add(bad, seq=1)
        self.assertEqual(acc.member_count, 0)

    def test_type_tagging_distinct(self):
        # "1", 1, b"1" are three distinct elements.
        acc = BilinearAccumulator()
        acc.add("1", seq=1)
        acc.add(1, seq=2)
        acc.add(b"1", seq=3)
        self.assertEqual(acc.member_count, 3)

    def test_int_zero_ok(self):
        acc = BilinearAccumulator()
        acc.add(0, seq=1)
        self.assertEqual(acc.member_count, 1)


class TestRemove(unittest.TestCase):
    def test_remove_happy_path(self):
        acc = BilinearAccumulator()
        acc.add("alice", seq=1)
        acc.add("bob", seq=2)
        value = acc.remove("alice", seq=3)
        self.assertEqual(value.member_count, 1)
        self.assertEqual(acc.member_count, 1)
        self.assertEqual(acc.members(), ("bob",))

    def test_remove_unknown_raises(self):
        acc = BilinearAccumulator()
        acc.add("alice", seq=1)
        with self.assertRaises(UnknownElementError):
            acc.remove("mallory", seq=2)

    def test_remove_from_empty_raises(self):
        acc = BilinearAccumulator()
        with self.assertRaises(UnknownElementError):
            acc.remove("alice", seq=1)

    def test_remove_restores_empty_digest(self):
        acc = BilinearAccumulator()
        empty_digest = acc.value().digest
        acc.add("alice", seq=1)
        acc.remove("alice", seq=2)
        self.assertEqual(acc.value().digest, empty_digest)
        self.assertEqual(acc.member_count, 0)

    def test_remove_then_readd(self):
        acc = BilinearAccumulator()
        d1 = acc.add("alice", seq=1).digest
        acc.remove("alice", seq=2)
        d2 = acc.add("alice", seq=3).digest
        self.assertEqual(d1, d2)

    def test_remove_bad_seq(self):
        acc = BilinearAccumulator()
        acc.add("alice", seq=1)
        with self.assertRaises((TypeError, ValueError)):
            acc.remove("alice", seq=-1)


class TestWitnessVerify(unittest.TestCase):
    def test_witness_verify_happy_path(self):
        acc = BilinearAccumulator()
        acc.add("alice", seq=1)
        acc.add("bob", seq=2)
        w = acc.witness("alice")
        self.assertIsInstance(w, MembershipWitness)
        self.assertTrue(w.digest.startswith("sha256:"))
        self.assertTrue(acc.verify("alice", w))

    def test_verify_wrong_element_false(self):
        acc = BilinearAccumulator()
        acc.add("alice", seq=1)
        w = acc.witness("alice")
        self.assertFalse(acc.verify("mallory", w))

    def test_verify_stale_after_add(self):
        acc = BilinearAccumulator()
        acc.add("alice", seq=1)
        w = acc.witness("alice")
        acc.add("bob", seq=2)
        self.assertFalse(acc.verify("alice", w))
        # Refreshing fixes it.
        self.assertTrue(acc.verify("alice", acc.witness("alice")))

    def test_verify_stale_after_remove(self):
        acc = BilinearAccumulator()
        acc.add("alice", seq=1)
        acc.add("bob", seq=2)
        w = acc.witness("bob")
        acc.remove("alice", seq=3)
        self.assertFalse(acc.verify("bob", w))
        self.assertTrue(acc.verify("bob", acc.witness("bob")))

    def test_verify_removed_element_false(self):
        acc = BilinearAccumulator()
        acc.add("alice", seq=1)
        w = acc.witness("alice")
        acc.remove("alice", seq=2)
        self.assertFalse(acc.verify("alice", w))

    def test_verify_empty_accumulator(self):
        acc = BilinearAccumulator()
        other = BilinearAccumulator()
        other.add("alice", seq=1)
        w = other.witness("alice")
        # Witness is bound to other's accumulator value: stale here.
        self.assertFalse(acc.verify("alice", w))

    def test_verify_tampered_witness_exponent(self):
        acc = BilinearAccumulator()
        acc.add("alice", seq=1)
        w = acc.witness("alice")
        tampered = MembershipWitness(
            element_digest=w.element_digest,
            accumulator_digest=w.accumulator_digest,
            # Singleton set: the true witness exponent is 1; 2 breaks the
            # pairing equation (2*(x+s) != (x+s) mod p since (x+s) != 0).
            witness_exponent_hex="00" * 31 + "02",
            digest=w.digest,  # digest not recomputed: verify checks algebra, not this
        )
        # Algebra no longer holds (unless astronomically unlucky).
        self.assertFalse(acc.verify("alice", tampered))

    def test_verify_bad_witness_type(self):
        acc = BilinearAccumulator()
        acc.add("alice", seq=1)
        with self.assertRaises(TypeError):
            acc.verify("alice", "not-a-witness")

    def test_verify_bad_element(self):
        acc = BilinearAccumulator()
        acc.add("alice", seq=1)
        w = acc.witness("alice")
        with self.assertRaises((TypeError, ValueError)):
            acc.verify("", w)

    def test_witness_unknown_raises(self):
        acc = BilinearAccumulator()
        acc.add("alice", seq=1)
        with self.assertRaises(UnknownElementError):
            acc.witness("mallory")

    def test_witness_bound_to_accumulator(self):
        acc = BilinearAccumulator()
        acc.add("alice", seq=1)
        w = acc.witness("alice")
        self.assertEqual(w.accumulator_digest, acc.value().digest)

    def test_single_element_witness(self):
        # Singleton set: witness exponent must be 1 (empty product).
        acc = BilinearAccumulator()
        acc.add("only", seq=1)
        w = acc.witness("only")
        self.assertEqual(w.witness_exponent_hex, "00" * 31 + "01")
        self.assertTrue(acc.verify("only", w))


class TestRecords(unittest.TestCase):
    def test_records_frozen(self):
        acc = BilinearAccumulator()
        acc.add("alice", seq=1)
        value = acc.value()
        w = acc.witness("alice")
        with self.assertRaises(Exception):
            value.member_count = 99  # type: ignore[assignment]
        with self.assertRaises(Exception):
            w.digest = "x"  # type: ignore[assignment]

    def test_as_dict_shapes(self):
        acc = BilinearAccumulator()
        acc.add("alice", seq=1)
        vd = acc.value().as_dict()
        self.assertEqual(vd["schema"], BILINEAR_ACCUMULATOR_SCHEMA)
        self.assertEqual(vd["member_count"], 1)
        self.assertIn("digest", vd)
        wd = acc.witness("alice").as_dict()
        self.assertEqual(wd["schema"], BILINEAR_ACCUMULATOR_SCHEMA)
        self.assertIn("witness_exponent", wd)

    def test_events_log(self):
        acc = BilinearAccumulator()
        acc.add("alice", seq=1)
        acc.add("bob", seq=2)
        acc.remove("alice", seq=3)
        kinds = [kind for kind, _, _ in acc.events()]
        self.assertEqual(kinds, [EVENT_ADDED, EVENT_ADDED, EVENT_REMOVED])


class TestAuditEvents(unittest.TestCase):
    def test_audit_event_shapes(self):
        acc = BilinearAccumulator()
        value = acc.add("alice", seq=1)
        w = acc.witness("alice")
        for kind, record in (
            (EVENT_ADDED, value),
            (EVENT_REMOVED, value),
            (EVENT_WITNESS_ISSUED, w),
            (EVENT_VERIFIED, w),
            (EVENT_REJECTED, w),
        ):
            event = bilinear_accumulator_audit_event(kind, record, seq=7)
            self.assertEqual(event["schema"], "northstar.audit.ndjson/1")
            self.assertEqual(event["event"], kind)
            self.assertEqual(event["module"], BILINEAR_ACCUMULATOR_VERSION)
            self.assertEqual(event["audit_seq"], 7)

    def test_audit_event_bad_kind(self):
        acc = BilinearAccumulator()
        value = acc.add("alice", seq=1)
        with self.assertRaises(ValueError):
            bilinear_accumulator_audit_event("nope", value, seq=1)

    def test_audit_event_bad_record(self):
        acc = BilinearAccumulator()
        value = acc.add("alice", seq=1)
        with self.assertRaises(TypeError):
            bilinear_accumulator_audit_event(EVENT_ADDED, "x", seq=1)

    def test_audit_event_bad_seq(self):
        acc = BilinearAccumulator()
        value = acc.add("alice", seq=1)
        with self.assertRaises((TypeError, ValueError)):
            bilinear_accumulator_audit_event(EVENT_ADDED, value, seq=-1)


class TestMain(unittest.TestCase):
    def test_main(self):
        main()


if __name__ == "__main__":
    unittest.main()
