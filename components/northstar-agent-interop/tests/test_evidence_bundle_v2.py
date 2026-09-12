"""Tests for padded v2 commitments and non-inclusion proofs."""
from __future__ import annotations

import json
import unittest

from evidence_bundle import EvidenceError, EvidenceBundle
from evidence_bundle_v2 import (
    AbsenceProofV2,
    DisclosureVerdict,
    InclusionProofV2,
    PAD_DIGEST,
    PaddedEvidenceBundle,
    SCHEMA_V2,
    V2Error,
    build_bundle_v2,
    leaf_digest_v2,
    make_absence_v2,
    make_inclusion_v2,
    verify_absence_v2,
    verify_inclusion_v2,
)


def events(count):
    return [{"event_id": "event-%02d" % i, "value": i} for i in range(count)]


class BundleV2Tests(unittest.TestCase):
    def test_root_is_deterministic_for_counts_one_through_seventeen(self):
        for count in range(1, 18):
            first = build_bundle_v2(events(count))
            second = build_bundle_v2(events(count))
            self.assertEqual(first, second)
            expected = 1
            while expected < count:
                expected *= 2
            self.assertEqual(first.padded_count, expected)
            self.assertEqual(first.leaf_count, count)
            self.assertEqual(len(first.leaf_digests), count)
            self.assertTrue(first.root_digest.startswith("sha256:"))

    def test_real_leaf_digests_are_sorted_and_pad_is_not_a_real_leaf(self):
        bundle = build_bundle_v2(events(5))
        self.assertEqual(list(bundle.leaf_digests), sorted(bundle.leaf_digests))
        self.assertNotIn(PAD_DIGEST, bundle.leaf_digests)
        self.assertTrue(PAD_DIGEST.startswith("sha256:"))

    def test_duplicate_events_are_rejected(self):
        repeated = {"event_id": "same", "value": 1}
        with self.assertRaises(V2Error):
            build_bundle_v2([repeated, dict(repeated)])

    def test_sensitive_event_fields_are_rejected(self):
        with self.assertRaises(EvidenceError):
            build_bundle_v2([{"event_id": "x", "raw_output": "secret"}])

    def test_wire_round_trip_is_strict(self):
        bundle = build_bundle_v2(events(3))
        self.assertEqual(PaddedEvidenceBundle.from_dict(bundle.to_dict()), bundle)
        forged = {**bundle.to_dict(), "schema_version": "northstar.evidence-bundle.v1"}
        with self.assertRaises(V2Error):
            PaddedEvidenceBundle.from_dict(forged)
        forged = {**bundle.to_dict(), "extra": True}
        with self.assertRaises(V2Error):
            PaddedEvidenceBundle.from_dict(forged)

    def test_v1_bundle_parser_rejects_v2_wire_data(self):
        bundle = build_bundle_v2(events(2))
        with self.assertRaises(EvidenceError):
            EvidenceBundle.from_dict(bundle.to_dict())


class InclusionV2Tests(unittest.TestCase):
    def test_every_real_leaf_has_a_verifiable_path(self):
        source = events(5)
        bundle = build_bundle_v2(source)
        for index in range(bundle.leaf_count):
            proof = make_inclusion_v2(bundle, index)
            subject = next(item for item in source if leaf_digest_v2(item) == proof.leaf_digest)
            verdict = verify_inclusion_v2(
                proof, subject, expected_root=bundle.root_digest
            )
            self.assertEqual(verdict.state, "verified")
            self.assertEqual(verdict.unverified, ("index", "padded_count"))

    def test_pad_positions_cannot_be_requested_as_real_inclusions(self):
        bundle = build_bundle_v2(events(3))
        with self.assertRaises(V2Error):
            make_inclusion_v2(bundle, 3)
        with self.assertRaises(V2Error):
            make_inclusion_v2(bundle, -1)
        with self.assertRaises(V2Error):
            make_inclusion_v2(bundle, True)

    def test_wrong_subject_is_rejected(self):
        source = events(4)
        bundle = build_bundle_v2(source)
        proof = make_inclusion_v2(bundle, 1)
        wrong = {"event_id": "not-in-the-leaf", "value": 999}
        with self.assertRaises(V2Error):
            verify_inclusion_v2(proof, wrong, expected_root=bundle.root_digest)

    def test_tampered_sibling_and_wrong_root_are_rejected(self):
        bundle = build_bundle_v2(events(5))
        proof = make_inclusion_v2(bundle, 2)
        direction, digest = proof.siblings[0]
        forged = InclusionProofV2(
            SCHEMA_V2, proof.root_digest, proof.padded_count, proof.index,
            proof.leaf_digest,
            ((direction, "sha256:" + "0" * 64),) + proof.siblings[1:],
        )
        with self.assertRaises(V2Error):
            verify_inclusion_v2(forged, events(5)[0], expected_root=bundle.root_digest)
        with self.assertRaises(V2Error):
            verify_inclusion_v2(proof, events(5)[0], expected_root="sha256:" + "f" * 64)

    def test_unpinned_root_is_explicitly_not_verified(self):
        source = events(2)
        bundle = build_bundle_v2(source)
        proof = make_inclusion_v2(bundle, 0)
        verdict = verify_inclusion_v2(proof, next(item for item in source if leaf_digest_v2(item) == proof.leaf_digest))
        self.assertEqual(verdict.state, "verified-unpinned")
        self.assertIn("root_unpinned", verdict.reasons)

    def test_wire_form_round_trips_and_rejects_unknown_fields(self):
        bundle = build_bundle_v2(events(5))
        proof = make_inclusion_v2(bundle, 1)
        restored = InclusionProofV2.from_dict(proof.to_dict())
        self.assertEqual(restored, proof)
        with self.assertRaises(V2Error):
            InclusionProofV2.from_dict({**proof.to_dict(), "extra": 1})


class AbsenceV2Tests(unittest.TestCase):
    def test_target_before_first_leaf_has_a_verified_successor_boundary(self):
        source = events(6)
        bundle = build_bundle_v2(source)
        first = bundle.leaf_digests[0]
        target = {"event_id": "before", "value": 0}
        while leaf_digest_v2(target) >= first:
            target["value"] -= 1
            target["event_id"] = "before-%d" % target["value"]
        proof = make_absence_v2(bundle, target)
        self.assertIsNone(proof.predecessor)
        self.assertIsNotNone(proof.successor)
        verdict = verify_absence_v2(proof, expected_root=bundle.root_digest)
        self.assertEqual(verdict.state, "verified")

    def test_target_after_last_leaf_has_a_verified_predecessor_boundary(self):
        source = events(6)
        bundle = build_bundle_v2(source)
        last = bundle.leaf_digests[-1]
        target = {"event_id": "after", "value": 0}
        while leaf_digest_v2(target) <= last:
            target["value"] += 1
            target["event_id"] = "after-%d" % target["value"]
        proof = make_absence_v2(bundle, target)
        self.assertIsNotNone(proof.predecessor)
        self.assertIsNone(proof.successor)
        verdict = verify_absence_v2(proof, expected_root=bundle.root_digest)
        self.assertEqual(verdict.state, "verified")

    def test_target_between_two_leaves_has_strict_adjacent_neighbors(self):
        source = [{"event_id": "a"}, {"event_id": "c"}, {"event_id": "z"}]
        bundle = build_bundle_v2(source)
        target = {"event_id": "m"}
        proof = make_absence_v2(bundle, target)
        self.assertIsNotNone(proof.predecessor)
        self.assertIsNotNone(proof.successor)
        self.assertEqual(proof.successor.index, proof.predecessor.index + 1)
        verdict = verify_absence_v2(proof, expected_root=bundle.root_digest)
        self.assertEqual(verdict.state, "verified")

    def test_present_target_cannot_receive_an_absence_proof(self):
        source = events(5)
        bundle = build_bundle_v2(source)
        with self.assertRaises(V2Error):
            make_absence_v2(bundle, source[2])

    def test_tampered_neighbor_or_ordering_is_rejected(self):
        source = [{"event_id": "a"}, {"event_id": "c"}, {"event_id": "z"}]
        bundle = build_bundle_v2(source)
        target = {"event_id": "m"}
        proof = make_absence_v2(bundle, target)
        predecessor = proof.predecessor
        assert predecessor is not None
        forged_pred = InclusionProofV2(
            predecessor.schema_version, predecessor.root_digest,
            predecessor.padded_count, predecessor.index,
            "sha256:" + "0" * 64, predecessor.siblings,
        )
        forged = AbsenceProofV2(
            proof.schema_version, proof.root_digest, proof.target_digest,
            proof.leaf_count, proof.padded_count,
            forged_pred, proof.successor,
        )
        with self.assertRaises(V2Error):
            verify_absence_v2(forged, expected_root=bundle.root_digest)
        forged = AbsenceProofV2(
            proof.schema_version, proof.root_digest,
            proof.predecessor.leaf_digest, proof.leaf_count, proof.padded_count,
            proof.predecessor, proof.successor,
        )
        with self.assertRaises(V2Error):
            verify_absence_v2(forged, expected_root=bundle.root_digest)

    def test_pad_positions_cannot_be_neighbors(self):
        bundle = build_bundle_v2(events(3))
        target = {"event_id": "zzzz"}
        proof = make_absence_v2(bundle, target)
        predecessor = proof.predecessor
        self.assertIsNotNone(predecessor)
        assert predecessor is not None
        forged_pred = InclusionProofV2(
            predecessor.schema_version, predecessor.root_digest,
            predecessor.padded_count, bundle.padded_count - 1,
            PAD_DIGEST, predecessor.siblings,
        )
        forged = AbsenceProofV2(
            proof.schema_version, proof.root_digest, proof.target_digest,
            proof.leaf_count, proof.padded_count,
            forged_pred, proof.successor,
        )
        with self.assertRaises(V2Error):
            verify_absence_v2(forged, expected_root=bundle.root_digest)

    def test_nonpad_digest_at_padding_index_is_rejected(self):
        bundle = build_bundle_v2(events(3))
        target = {"event_id": "zzzz"}
        proof = make_absence_v2(bundle, target)
        predecessor = proof.predecessor
        self.assertIsNotNone(predecessor)
        assert predecessor is not None
        forged_pred = InclusionProofV2(
            predecessor.schema_version, predecessor.root_digest,
            predecessor.padded_count, bundle.leaf_count,
            predecessor.leaf_digest, predecessor.siblings,
        )
        forged = AbsenceProofV2(
            proof.schema_version, proof.root_digest, proof.target_digest,
            proof.leaf_count, proof.padded_count,
            forged_pred, proof.successor,
        )
        with self.assertRaises(V2Error):
            verify_absence_v2(forged, expected_root=bundle.root_digest)

    def test_absence_wire_form_round_trips(self):
        bundle = build_bundle_v2(events(5))
        proof = make_absence_v2(bundle, {"event_id": "middle"})
        self.assertEqual(AbsenceProofV2.from_dict(proof.to_dict()), proof)
        with self.assertRaises(V2Error):
            AbsenceProofV2.from_dict({**proof.to_dict(), "extra": 1})

    def test_unpinned_absence_is_explicit(self):
        bundle = build_bundle_v2(events(4))
        proof = make_absence_v2(bundle, {"event_id": "outside"})
        verdict = verify_absence_v2(proof)
        self.assertEqual(verdict.state, "verified-unpinned")
        self.assertIn("root_unpinned", verdict.reasons)


if __name__ == "__main__":
    unittest.main()
