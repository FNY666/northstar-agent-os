"""Tests for mpc_interface: Shamir sharing + BGW local addition (simulated)."""

import dataclasses
import unittest

from mpc_interface import (
    EVENT_RECONSTRUCTED,
    EVENT_REJECTED,
    EVENT_SHARES_ADDED,
    EVENT_SHARED,
    FIELD_PRIME,
    MPC,
    MPC_INTERFACE_SCHEMA,
    MPC_INTERFACE_VERSION,
    MPCError,
    ReconstructionError,
    Share,
    ShareValidationError,
    mpc_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(MPC_INTERFACE_VERSION, "mpc-interface.v1")

    def test_schema_pin(self):
        self.assertEqual(MPC_INTERFACE_SCHEMA, "northstar.mpc-interface.v1")

    def test_field_prime_is_mersenne(self):
        self.assertEqual(FIELD_PRIME, (1 << 61) - 1)
        self.assertEqual(MPC.field_prime, FIELD_PRIME)


class TestShareValidation(unittest.TestCase):
    def setUp(self):
        self.mpc = MPC()

    def test_share_happy_path(self):
        shares = self.mpc.share(42, n=5, t=3)
        self.assertEqual(len(shares), 5)
        self.assertEqual([s.share_id for s in shares], [1, 2, 3, 4, 5])
        for s in shares:
            self.assertIsInstance(s, Share)
            self.assertEqual(s.n, 5)
            self.assertEqual(s.threshold, 3)
            self.assertTrue(0 <= s.value < FIELD_PRIME)

    def test_t_equals_1_shares_are_secret(self):
        shares = self.mpc.share(7, n=4, t=1)
        for s in shares:
            self.assertEqual(s.value, 7)

    def test_t_equals_n(self):
        shares = self.mpc.share(9, n=3, t=3)
        self.assertEqual(self.mpc.reconstruct(shares), 9)
        with self.assertRaises(ReconstructionError):
            self.mpc.reconstruct(shares[:2])

    def test_secret_zero(self):
        shares = self.mpc.share(0, n=3, t=2)
        self.assertEqual(self.mpc.reconstruct(shares[:2]), 0)

    def test_secret_max_field_element(self):
        shares = self.mpc.share(FIELD_PRIME - 1, n=3, t=2)
        self.assertEqual(self.mpc.reconstruct(shares), FIELD_PRIME - 1)

    def test_bool_secret_rejected(self):
        with self.assertRaises(TypeError):
            self.mpc.share(True, n=3, t=2)

    def test_str_secret_rejected(self):
        with self.assertRaises(TypeError):
            self.mpc.share("42", n=3, t=2)

    def test_negative_secret_rejected(self):
        with self.assertRaises(ValueError):
            self.mpc.share(-1, n=3, t=2)

    def test_secret_at_prime_rejected(self):
        with self.assertRaises(ValueError):
            self.mpc.share(FIELD_PRIME, n=3, t=2)

    def test_n_zero_rejected(self):
        with self.assertRaises(ValueError):
            self.mpc.share(1, n=0, t=1)

    def test_t_zero_rejected(self):
        with self.assertRaises(ValueError):
            self.mpc.share(1, n=3, t=0)

    def test_t_greater_than_n_rejected(self):
        with self.assertRaises(ValueError):
            self.mpc.share(1, n=3, t=4)

    def test_bool_n_rejected(self):
        with self.assertRaises(TypeError):
            self.mpc.share(1, n=True, t=1)

    def test_float_t_rejected(self):
        with self.assertRaises(TypeError):
            self.mpc.share(1, n=3, t=2.0)


class TestDeterminism(unittest.TestCase):
    def setUp(self):
        self.mpc = MPC()

    def test_same_inputs_identical_shares(self):
        a = self.mpc.share(1234, n=5, t=3)
        b = self.mpc.share(1234, n=5, t=3)
        self.assertEqual(a, b)

    def test_distinct_secrets_distinct_shares(self):
        a = self.mpc.share(1, n=5, t=3)
        b = self.mpc.share(2, n=5, t=3)
        self.assertNotEqual(
            [s.value for s in a], [s.value for s in b]
        )

    def test_degree_one_linear_relation(self):
        # t=2 -> p(x) = s + c1*x, so consecutive share differences are constant.
        shares = self.mpc.share(500, n=6, t=2)
        diffs = {
            (shares[i + 1].value - shares[i].value) % FIELD_PRIME
            for i in range(5)
        }
        self.assertEqual(len(diffs), 1)


class TestReconstruct(unittest.TestCase):
    def setUp(self):
        self.mpc = MPC()

    def test_exactly_t_shares(self):
        shares = self.mpc.share(777, n=5, t=3)
        self.assertEqual(self.mpc.reconstruct(shares[:3]), 777)

    def test_non_prefix_subset(self):
        shares = self.mpc.share(777, n=5, t=3)
        self.assertEqual(
            self.mpc.reconstruct((shares[1], shares[3], shares[4])), 777
        )

    def test_all_n_shares(self):
        shares = self.mpc.share(777, n=5, t=3)
        self.assertEqual(self.mpc.reconstruct(shares), 777)

    def test_order_independent(self):
        shares = self.mpc.share(31337, n=7, t=4)
        self.assertEqual(
            self.mpc.reconstruct(tuple(reversed(shares))), 31337
        )

    def test_fewer_than_t_raises(self):
        shares = self.mpc.share(5, n=5, t=3)
        with self.assertRaises(ReconstructionError):
            self.mpc.reconstruct(shares[:2])

    def test_empty_raises(self):
        with self.assertRaises(ReconstructionError):
            self.mpc.reconstruct([])

    def test_duplicate_ids_raise(self):
        shares = self.mpc.share(5, n=5, t=3)
        with self.assertRaises(ReconstructionError):
            self.mpc.reconstruct((shares[0], shares[0], shares[1]))

    def test_mixed_thresholds_raise(self):
        a = self.mpc.share(5, n=5, t=3)
        b = self.mpc.share(6, n=5, t=2)
        with self.assertRaises(ReconstructionError):
            self.mpc.reconstruct((a[0], a[1], b[0]))

    def test_non_share_input_raises(self):
        shares = self.mpc.share(5, n=5, t=3)
        with self.assertRaises(TypeError):
            self.mpc.reconstruct([shares[0], shares[1], (3, 99)])

    def test_roundtrip_vectors(self):
        for secret, n, t in [
            (0, 1, 1),
            (1, 2, 2),
            (999999, 10, 6),
            (FIELD_PRIME - 2, 4, 4),
            (2**40, 8, 5),
        ]:
            shares = self.mpc.share(secret, n=n, t=t)
            self.assertEqual(self.mpc.reconstruct(shares[:t]), secret)


class TestAddShares(unittest.TestCase):
    def setUp(self):
        self.mpc = MPC()

    def test_add_happy_path(self):
        a = self.mpc.share(100, n=5, t=3)
        b = self.mpc.share(23, n=5, t=3)
        summed = self.mpc.add_shares(a, b)
        self.assertEqual(len(summed), 5)
        self.assertEqual(self.mpc.reconstruct(summed), 123)

    def test_add_commutative(self):
        a = self.mpc.share(100, n=5, t=3)
        b = self.mpc.share(23, n=5, t=3)
        self.assertEqual(
            self.mpc.add_shares(a, b), self.mpc.add_shares(b, a)
        )

    def test_add_wraps_mod_prime(self):
        a = self.mpc.share(FIELD_PRIME - 1, n=3, t=2)
        b = self.mpc.share(1, n=3, t=2)
        summed = self.mpc.add_shares(a, b)
        self.assertEqual(self.mpc.reconstruct(summed), 0)

    def test_add_preserves_metadata(self):
        a = self.mpc.share(10, n=4, t=2)
        b = self.mpc.share(20, n=4, t=2)
        summed = self.mpc.add_shares(a, b)
        for s in summed:
            self.assertEqual((s.n, s.threshold), (4, 2))
        self.assertEqual([s.share_id for s in summed], [1, 2, 3, 4])

    def test_add_mismatched_threshold_raises(self):
        a = self.mpc.share(10, n=4, t=2)
        b = self.mpc.share(20, n=4, t=3)
        with self.assertRaises(ShareValidationError):
            self.mpc.add_shares(a, b)

    def test_add_mismatched_n_raises(self):
        a = self.mpc.share(10, n=4, t=2)
        b = self.mpc.share(20, n=5, t=2)
        with self.assertRaises(ShareValidationError):
            self.mpc.add_shares(a, b)

    def test_add_different_ids_raise(self):
        a = self.mpc.share(10, n=4, t=2)
        b = self.mpc.share(20, n=4, t=2)
        with self.assertRaises(ShareValidationError):
            self.mpc.add_shares(a[:3], b)

    def test_add_duplicate_ids_raise(self):
        a = self.mpc.share(10, n=4, t=2)
        b = self.mpc.share(20, n=4, t=2)
        dup = (a[0], a[0], a[2], a[3])
        with self.assertRaises(ShareValidationError):
            self.mpc.add_shares(dup, b)

    def test_add_empty_vector_raises(self):
        b = self.mpc.share(20, n=4, t=2)
        with self.assertRaises(ShareValidationError):
            self.mpc.add_shares([], b)

    def test_add_non_share_raises(self):
        a = self.mpc.share(10, n=4, t=2)
        with self.assertRaises(TypeError):
            self.mpc.add_shares(a, ["not-a-share"] * 4)


class TestShareRecord(unittest.TestCase):
    def test_frozen(self):
        s = Share(share_id=1, value=5, n=3, threshold=2)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            s.value = 6  # type: ignore[misc]

    def test_share_id_out_of_range(self):
        with self.assertRaises(ShareValidationError):
            Share(share_id=0, value=5, n=3, threshold=2)
        with self.assertRaises(ShareValidationError):
            Share(share_id=4, value=5, n=3, threshold=2)

    def test_bool_share_id_rejected(self):
        with self.assertRaises(TypeError):
            Share(share_id=True, value=5, n=3, threshold=2)

    def test_value_out_of_field(self):
        with self.assertRaises(ShareValidationError):
            Share(share_id=1, value=FIELD_PRIME, n=3, threshold=2)

    def test_as_dict_shape(self):
        s = Share(share_id=2, value=9, n=5, threshold=3)
        d = s.as_dict()
        self.assertEqual(d["schema"], MPC_INTERFACE_SCHEMA)
        self.assertEqual(d["share_id"], 2)
        self.assertEqual(d["value"], 9)
        self.assertEqual(d["n"], 5)
        self.assertEqual(d["threshold"], 3)
        self.assertEqual(d["field_prime"], FIELD_PRIME)

    def test_errors_are_mpc_errors(self):
        self.assertTrue(issubclass(ShareValidationError, MPCError))
        self.assertTrue(issubclass(ReconstructionError, MPCError))


class TestDigest(unittest.TestCase):
    def setUp(self):
        self.mpc = MPC()

    def test_digest_shape(self):
        shares = self.mpc.share(42, n=3, t=2)
        digest = self.mpc.share_digest(shares)
        self.assertTrue(digest.startswith("sha256:"))
        self.assertEqual(len(digest), len("sha256:") + 64)

    def test_digest_deterministic(self):
        a = self.mpc.share(42, n=3, t=2)
        b = self.mpc.share(42, n=3, t=2)
        self.assertEqual(self.mpc.share_digest(a), self.mpc.share_digest(b))

    def test_digest_changes_with_secret(self):
        a = self.mpc.share(42, n=3, t=2)
        b = self.mpc.share(43, n=3, t=2)
        self.assertNotEqual(self.mpc.share_digest(a), self.mpc.share_digest(b))

    def test_digest_rejects_non_shares(self):
        with self.assertRaises(TypeError):
            self.mpc.share_digest(["x"])


class TestAuditEvent(unittest.TestCase):
    def test_all_kinds(self):
        for kind in (
            EVENT_SHARED,
            EVENT_RECONSTRUCTED,
            EVENT_SHARES_ADDED,
            EVENT_REJECTED,
        ):
            event = mpc_audit_event(kind, seq=7, note="x")
            self.assertEqual(event["schema"], "audit.ndjson/1")
            self.assertEqual(event["module"], MPC_INTERFACE_SCHEMA)
            self.assertEqual(event["kind"], kind)
            self.assertEqual(event["audit_seq"], 7)
            self.assertEqual(event["note"], "x")

    def test_bad_kind_rejected(self):
        with self.assertRaises(ValueError):
            mpc_audit_event("nope", seq=1)

    def test_bad_seq_rejected(self):
        with self.assertRaises(TypeError):
            mpc_audit_event(EVENT_SHARED, seq=True)
        with self.assertRaises(ValueError):
            mpc_audit_event(EVENT_SHARED, seq=-1)
        with self.assertRaises(TypeError):
            mpc_audit_event(EVENT_SHARED, seq="1")


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        from mpc_interface import main

        main()  # raises on failure; prints on success


if __name__ == "__main__":
    unittest.main()
