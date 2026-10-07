"""Tests for secure_aggregation: shares hide individuals, commitments verify sums."""

import unittest

from secure_aggregation import (
    FIELD_PRIME,
    SECURE_AGGREGATION_SCHEMA,
    SECURE_AGGREGATION_VERSION,
    AggregationResult,
    Commitment,
    Share,
    aggregate_shares,
    commit_update,
    open_aggregate,
    split_update,
    verify_aggregation,
)


class TestVersionPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(SECURE_AGGREGATION_VERSION, "secure-aggregation.v1")

    def test_schema_pin(self):
        self.assertEqual(SECURE_AGGREGATION_SCHEMA, "northstar.secure-aggregation.v1")


class TestSplitUpdate(unittest.TestCase):
    def test_shares_sum_to_value(self):
        shares = split_update("alice", 12345, 4, seed=b"seed-1")
        self.assertEqual(len(shares), 4)
        self.assertEqual(sum(s.value for s in shares) % FIELD_PRIME, 12345)

    def test_deterministic(self):
        a = split_update("alice", 999, 3, seed=b"same")
        b = split_update("alice", 999, 3, seed=b"same")
        self.assertEqual(a, b)

    def test_different_seeds_differ(self):
        a = split_update("alice", 999, 3, seed=b"seed-a")
        b = split_update("alice", 999, 3, seed=b"seed-b")
        self.assertNotEqual(a, b)

    def test_indices_cover_range(self):
        shares = split_update("alice", 7, 5, seed=b"s")
        self.assertEqual([s.share_index for s in shares], [0, 1, 2, 3, 4])
        self.assertTrue(all(s.n_shares == 5 for s in shares))

    def test_single_share_reveals_nothing(self):
        shares = split_update("alice", 424242, 3, seed=b"hide")
        # No individual share equals the value; masks look random.
        self.assertTrue(all(s.value != 424242 for s in shares[:2]))

    def test_zero_value(self):
        shares = split_update("alice", 0, 2, seed=b"z")
        self.assertEqual(sum(s.value for s in shares) % FIELD_PRIME, 0)

    def test_validation(self):
        with self.assertRaises(ValueError):
            split_update("", 1, 2, seed=b"s")
        with self.assertRaises(ValueError):
            split_update("a", -1, 2, seed=b"s")
        with self.assertRaises(TypeError):
            split_update("a", True, 2, seed=b"s")
        with self.assertRaises(ValueError):
            split_update("a", 1, 1, seed=b"s")
        with self.assertRaises(ValueError):
            split_update("a", 1, 2, seed=b"")
        with self.assertRaises(ValueError):
            split_update("a", FIELD_PRIME, 2, seed=b"s")

    def test_frozen(self):
        s = split_update("alice", 1, 2, seed=b"s")[0]
        with self.assertRaises(Exception):
            s.value = 2  # type: ignore


class TestAggregateShares(unittest.TestCase):
    def _round(self):
        shares = []
        for cid, val in (("a", 100), ("b", 200), ("c", 300)):
            shares.extend(split_update(cid, val, 2, seed=cid.encode()))
        return shares

    def test_multi_client_sum(self):
        agg = aggregate_shares(self._round())
        self.assertEqual(agg.total, 600)
        self.assertEqual(agg.n_clients, 3)

    def test_empty_raises(self):
        with self.assertRaises(ValueError):
            aggregate_shares([])

    def test_wrong_type_raises(self):
        with self.assertRaises(TypeError):
            aggregate_shares("not-a-sequence")  # type: ignore

    def test_tampered_share_aborts(self):
        shares = list(self._round())
        bad = shares[0]
        tampered = Share(client_id=bad.client_id, share_index=bad.share_index,
                         n_shares=bad.n_shares, value=(bad.value + 1) % FIELD_PRIME,
                         digest=bad.digest)
        shares[0] = tampered
        with self.assertRaises(ValueError):
            aggregate_shares(shares)

    def test_result_digest_pinned(self):
        agg = aggregate_shares(self._round())
        self.assertTrue(agg.digest.startswith("sha256:"))
        d = agg.as_dict()
        self.assertEqual(d["schema"], SECURE_AGGREGATION_SCHEMA)


class TestCommitAndVerify(unittest.TestCase):
    def _honest(self):
        clients = [("alice", 100, 111), ("bob", 250, 222), ("carol", 175, 333)]
        commitments = [commit_update(c, v, r) for c, v, r in clients]
        total = sum(v for _, v, _ in clients) % FIELD_PRIME
        blinding_sum = sum(r for _, _, r in clients) % FIELD_PRIME
        result = open_aggregate(total, blinding_sum, len(clients))
        return result, commitments

    def test_commit_deterministic(self):
        self.assertEqual(commit_update("a", 5, 6), commit_update("a", 5, 6))

    def test_honest_round_verifies(self):
        result, commitments = self._honest()
        self.assertTrue(verify_aggregation(result, commitments))

    def test_tampered_total_fails(self):
        result, commitments = self._honest()
        tampered = open_aggregate((result.total + 1) % FIELD_PRIME,
                                  result.blinding_sum, result.n_clients)
        self.assertFalse(verify_aggregation(tampered, commitments))

    def test_tampered_blinding_sum_fails(self):
        result, commitments = self._honest()
        tampered = open_aggregate(result.total,
                                  (result.blinding_sum + 1) % FIELD_PRIME,
                                  result.n_clients)
        self.assertFalse(verify_aggregation(tampered, commitments))

    def test_dropped_commitment_fails(self):
        result, commitments = self._honest()
        self.assertFalse(verify_aggregation(result, commitments[:2]))

    def test_duplicate_client_fails(self):
        result, commitments = self._honest()
        dup = list(commitments) + [commitments[0]]
        result2 = open_aggregate(result.total, result.blinding_sum, len(dup))
        self.assertFalse(verify_aggregation(result2, dup))

    def test_empty_commitments_fails(self):
        result, _ = self._honest()
        self.assertFalse(verify_aggregation(result, []))

    def test_wrong_types_never_raise(self):
        result, commitments = self._honest()
        self.assertFalse(verify_aggregation("nope", commitments))
        self.assertFalse(verify_aggregation(result, "nope"))
        self.assertFalse(verify_aggregation(None, None))
        self.assertFalse(verify_aggregation(result, [None]))

    def test_tampered_result_digest_fails(self):
        result, commitments = self._honest()
        bad = AggregationResult(total=result.total,
                                blinding_sum=result.blinding_sum,
                                n_clients=result.n_clients,
                                digest="sha256:" + "0" * 64)
        self.assertFalse(verify_aggregation(bad, commitments))

    def test_forged_commitment_value_fails(self):
        result, commitments = self._honest()
        forged = Commitment(client_id="mallory", commitment=999999,
                            blinding_digest="sha256:" + "ab" * 32)
        result2 = open_aggregate(result.total, result.blinding_sum,
                                 len(commitments) + 1)
        self.assertFalse(verify_aggregation(result2, list(commitments) + [forged]))

    def test_open_aggregate_validation(self):
        with self.assertRaises(ValueError):
            open_aggregate(-1, 0, 1)
        with self.assertRaises(ValueError):
            open_aggregate(0, 0, 0)

    def test_end_to_end_full_protocol(self):
        # split -> aggregate -> commit -> open -> verify, all wired together.
        clients = [("alice", 100), ("bob", 250), ("carol", 175)]
        shares, commitments, blindings = [], [], []
        for i, (cid, val) in enumerate(clients):
            shares.extend(split_update(cid, val, 3, seed=f"e2e-{i}".encode()))
            r = (i + 1) * 1000
            blindings.append(r)
            commitments.append(commit_update(cid, val, r))
        agg = aggregate_shares(shares)
        result = open_aggregate(agg.total, sum(blindings) % FIELD_PRIME, len(clients))
        self.assertTrue(verify_aggregation(result, commitments))
        self.assertEqual(agg.total, 525)


if __name__ == "__main__":
    unittest.main()
