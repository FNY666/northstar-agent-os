"""Tests for secure_aggregation protocol layer: SecureAggregation mask/aggregate/unmask."""

import dataclasses
import subprocess
import sys
import unittest

from secure_aggregation import (
    FIELD_PRIME,
    SECURE_AGGREGATION_SCHEMA,
    SECURE_AGGREGATION_VERSION,
    BadMemberError,
    BadRoundError,
    DuplicateMaskError,
    MaskedAggregate,
    MaskedInput,
    MemberMismatchError,
    RoundMismatchError,
    SecureAggregation,
    SecureAggregationError,
    TamperedInputError,
    UnknownMemberError,
)


class TestProtocolRound(unittest.TestCase):
    def setUp(self):
        self.sa = SecureAggregation()
        self.members = ("alice", "bob", "carol")
        self.values = {"alice": 100, "bob": 250, "carol": 175}
        self.seed = b"round-seed-1"

    def _mask_all(self, values=None, members=None, round_id="r1", seed=None):
        members = self.members if members is None else members
        values = self.values if values is None else values
        seed = self.seed if seed is None else seed
        return [self.sa.mask(cid, values[cid], members, round_id, seed)
                for cid in members]

    def test_deterministic(self):
        a = self.sa.mask("alice", 100, self.members, "r1", self.seed)
        b = self.sa.mask("alice", 100, self.members, "r1", self.seed)
        self.assertEqual(a, b)

    def test_digest_pin_and_as_dict(self):
        mi = self.sa.mask("alice", 100, self.members, "r1", self.seed)
        self.assertTrue(mi.digest.startswith("sha256:"))
        self.assertEqual(len(mi.digest), 7 + 64)
        d = mi.as_dict()
        self.assertEqual(d["schema"], SECURE_AGGREGATION_SCHEMA)
        self.assertEqual(d["version"], SECURE_AGGREGATION_VERSION)
        self.assertEqual(d["client_id"], "alice")
        self.assertEqual(d["round_id"], "r1")

    def test_masked_differs_from_value(self):
        for cid in self.members:
            mi = self.sa.mask(cid, self.values[cid], self.members, "r1",
                              self.seed)
            self.assertNotEqual(mi.masked_value, self.values[cid])

    def test_round_trip_recovers_sum(self):
        masked = self._mask_all()
        agg = self.sa.aggregate(masked)
        self.assertIsInstance(agg, MaskedAggregate)
        self.assertEqual(agg.client_ids, tuple(sorted(self.members)))
        total = self.sa.unmask(agg, self.members, "r1", self.seed)
        self.assertEqual(total, sum(self.values.values()) % FIELD_PRIME)

    def test_single_client_round(self):
        mi = self.sa.mask("solo", 42, ("solo",), "r1", self.seed)
        agg = self.sa.aggregate([mi])
        self.assertEqual(self.sa.unmask(agg, ("solo",), "r1", self.seed), 42)

    def test_equal_values_mask_differ_but_sum_recovers(self):
        # Pairwise masks enter with opposite signs: identical values differ.
        a = self.sa.mask("alice", 100, ("alice", "bob"), "r1", self.seed)
        b = self.sa.mask("bob", 100, ("alice", "bob"), "r1", self.seed)
        self.assertNotEqual(a.masked_value, b.masked_value)
        agg = self.sa.aggregate([a, b])
        self.assertEqual(self.sa.unmask(agg, ("alice", "bob"), "r1",
                                        self.seed), 200)

    def test_bad_client_id(self):
        # Existing module convention: both branches raise ValueError.
        with self.assertRaises(ValueError):
            self.sa.mask("", 1, self.members, "r1", self.seed)
        with self.assertRaises(ValueError):
            self.sa.mask(123, 1, self.members, "r1", self.seed)

    def test_bad_value(self):
        with self.assertRaises(TypeError):
            self.sa.mask("alice", True, self.members, "r1", self.seed)
        with self.assertRaises(ValueError):
            self.sa.mask("alice", -1, self.members, "r1", self.seed)
        with self.assertRaises(ValueError):
            self.sa.mask("alice", FIELD_PRIME, self.members, "r1", self.seed)

    def test_client_not_in_members(self):
        with self.assertRaises(UnknownMemberError) as ctx:
            self.sa.mask("mallory", 1, self.members, "r1", self.seed)
        self.assertIsInstance(ctx.exception, SecureAggregationError)
        for cls in (BadMemberError, DuplicateMaskError, RoundMismatchError,
                    BadRoundError, TamperedInputError, MemberMismatchError):
            self.assertTrue(issubclass(cls, SecureAggregationError))

    def test_bad_members(self):
        with self.assertRaises(BadMemberError):
            self.sa.mask("alice", 1, (), "r1", self.seed)
        with self.assertRaises(BadMemberError):
            self.sa.mask("alice", 1, ("alice", "alice"), "r1", self.seed)
        with self.assertRaises(BadMemberError):
            self.sa.mask("alice", 1, ("alice", 42), "r1", self.seed)

    def test_bad_round_and_seed(self):
        with self.assertRaises(BadRoundError):
            self.sa.mask("alice", 1, self.members, "", self.seed)
        with self.assertRaises(BadRoundError):
            self.sa.mask("alice", 1, self.members, "r1", b"")
        with self.assertRaises(BadRoundError):
            self.sa.mask("alice", 1, self.members, "r1", "not-bytes")

    def test_aggregate_tampered_input(self):
        masked = self._mask_all()
        bad = dataclasses.replace(masked[0], digest="sha256:" + "0" * 64)
        with self.assertRaises(TamperedInputError):
            self.sa.aggregate([bad] + masked[1:])

    def test_aggregate_round_mismatch_and_duplicate(self):
        masked = self._mask_all()
        other = self.sa.mask("alice", 1, self.members, "r2", self.seed)
        with self.assertRaises(RoundMismatchError):
            self.sa.aggregate(masked + [other])
        with self.assertRaises(DuplicateMaskError):
            self.sa.aggregate(masked + [masked[0]])
        with self.assertRaises(ValueError):
            self.sa.aggregate([])
        with self.assertRaises(TypeError):
            self.sa.aggregate("nope")

    def test_unmask_member_mismatch(self):
        masked = self._mask_all()
        agg = self.sa.aggregate(masked)
        with self.assertRaises(MemberMismatchError):
            self.sa.unmask(agg, ("alice", "bob"), "r1", self.seed)
        with self.assertRaises(RoundMismatchError):
            self.sa.unmask(agg, self.members, "r2", self.seed)
        bad = dataclasses.replace(agg, digest="sha256:" + "0" * 64)
        with self.assertRaises(TamperedInputError):
            self.sa.unmask(bad, self.members, "r1", self.seed)

    def test_main_subprocess(self):
        r = subprocess.run([sys.executable, "secure_aggregation.py"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("protocol OK", r.stdout)


if __name__ == "__main__":
    unittest.main()
