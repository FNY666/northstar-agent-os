"""Tests for self-contained inclusion disclosure of evidence."""
import json
import unittest

from evidence_bundle import EvidenceError, build_bundle
from evidence_disclosure import (
    Disclosure,
    DisclosureError,
    SCHEMA,
    make_disclosure,
    verify_disclosure,
)


def _events(count):
    return [{"event_id": "e%d" % i, "sequence": i + 1} for i in range(count)]


class DisclosureBasics(unittest.TestCase):
    def test_a_disclosure_verifies_without_the_bundle(self):
        bundle = build_bundle(_events(5))
        disclosure = make_disclosure(bundle, 3)
        verdict = verify_disclosure(
            disclosure, subject=_events(5)[3], expected_root=bundle.root_digest
        )
        self.assertEqual(verdict.state, "verified")
        self.assertEqual(verdict.reasons, ())

    def test_an_unpinned_root_is_reported_not_hidden(self):
        bundle = build_bundle(_events(5))
        disclosure = make_disclosure(bundle, 3)
        verdict = verify_disclosure(disclosure, subject=_events(5)[3])
        self.assertEqual(verdict.state, "verified-unpinned")
        self.assertEqual(verdict.reasons, ("root_unpinned",))

    def test_the_expected_root_is_enforced(self):
        bundle = build_bundle(_events(5))
        disclosure = make_disclosure(bundle, 3)
        other = build_bundle(_events(4))
        with self.assertRaises(DisclosureError):
            verify_disclosure(
                disclosure, subject=_events(5)[3], expected_root=other.root_digest
            )

    def test_the_disclosure_carries_the_path_not_the_bundle(self):
        bundle = build_bundle(_events(16))
        disclosure = make_disclosure(bundle, 2)
        self.assertLessEqual(len(disclosure.siblings), 4)
        self.assertLess(len(disclosure.siblings), bundle.leaf_count)
        self.assertNotIn("events", disclosure.to_dict())

    def test_a_sibling_that_is_a_leaf_is_exposed_by_construction(self):
        # A merkle inclusion proof cannot hide a sibling node that is itself a
        # leaf. Padding the tree to a power of two is what removes the exposure;
        # the disclosure does not pretend otherwise.
        bundle = build_bundle(_events(6))
        disclosure = make_disclosure(bundle, 2)
        exposed = {digest for _, digest in disclosure.siblings}
        self.assertTrue(exposed & set(bundle.leaf_digests))

    def test_the_bounds_are_reported_as_unverified_metadata(self):
        bundle = build_bundle(_events(5))
        disclosure = make_disclosure(bundle, 3)
        verdict = verify_disclosure(
            disclosure, subject=_events(5)[3], expected_root=bundle.root_digest
        )
        self.assertEqual(verdict.unverified, ("index", "leaf_count"))

    def test_another_subject_is_refused(self):
        bundle = build_bundle(_events(5))
        disclosure = make_disclosure(bundle, 3)
        with self.assertRaises(DisclosureError):
            verify_disclosure(
                disclosure,
                subject={"event_id": "e9", "sequence": 9},
                expected_root=bundle.root_digest,
            )

    def test_a_tampered_sibling_is_refused(self):
        bundle = build_bundle(_events(5))
        disclosure = make_disclosure(bundle, 3)
        direction, digest = disclosure.siblings[0]
        flipped = "sha256:" + ("0" * 64 if digest[7] != "0" else "1" * 64)
        forged = Disclosure(
            SCHEMA,
            disclosure.root_digest,
            disclosure.leaf_count,
            disclosure.index,
            ((direction, flipped),) + disclosure.siblings[1:],
        )
        with self.assertRaises(DisclosureError):
            verify_disclosure(
                forged, subject=_events(5)[3], expected_root=bundle.root_digest
            )


class DisclosureShape(unittest.TestCase):
    def test_a_single_leaf_bundle_has_an_empty_path(self):
        bundle = build_bundle(_events(1))
        disclosure = make_disclosure(bundle, 0)
        self.assertEqual(disclosure.siblings, ())
        verdict = verify_disclosure(
            disclosure, subject=_events(1)[0], expected_root=bundle.root_digest
        )
        self.assertEqual(verdict.state, "verified")

    def test_odd_and_even_leaf_counts_agree_with_make_proof(self):
        from evidence_bundle import make_proof

        for count in (2, 3, 4, 5, 9):
            bundle = build_bundle(_events(count))
            for index in range(count):
                proof = make_proof(bundle, index)
                disclosure = make_disclosure(bundle, index)
                self.assertEqual(disclosure.siblings, tuple(proof.siblings))
                self.assertEqual(disclosure.index, index)
                self.assertEqual(disclosure.leaf_count, count)

    def test_the_index_must_be_in_range(self):
        bundle = build_bundle(_events(3))
        for bad in (-1, 3, True, "1"):
            with self.assertRaises(DisclosureError):
                make_disclosure(bundle, bad)

    def test_the_path_length_is_checked_against_the_leaf_count(self):
        bundle = build_bundle(_events(5))
        disclosure = make_disclosure(bundle, 3)
        forged = Disclosure(
            SCHEMA,
            disclosure.root_digest,
            disclosure.leaf_count * 2 + 1,
            disclosure.index,
            disclosure.siblings,
        )
        with self.assertRaises(DisclosureError):
            verify_disclosure(
                forged, subject=_events(5)[3], expected_root=bundle.root_digest
            )

    def test_the_exposure_is_declared(self):
        bundle = build_bundle(_events(8))
        disclosure = make_disclosure(bundle, 5)
        exposure = disclosure.exposure()
        self.assertEqual(exposure["index"], 5)
        self.assertEqual(exposure["leaf_count"], 8)
        self.assertEqual(exposure["sibling_count"], 3)
        self.assertFalse(exposure["reveals_other_leaves"])
        self.assertEqual(exposure["root_digest"], bundle.root_digest)

    def test_the_disclosure_round_trips_through_its_wire_form(self):
        bundle = build_bundle(_events(5))
        disclosure = make_disclosure(bundle, 1)
        self.assertEqual(Disclosure.from_dict(disclosure.to_dict()), disclosure)

    def test_the_wire_form_is_validated(self):
        bundle = build_bundle(_events(5))
        valid = make_disclosure(bundle, 1).to_dict()
        for field, value in (
            ("schema_version", "northstar.other.v1"),
            ("root_digest", "sha256:zz"),
            ("leaf_count", 0),
            ("index", -1),
        ):
            forged = dict(valid)
            forged[field] = value
            with self.assertRaises(DisclosureError):
                Disclosure.from_dict(forged)
        with self.assertRaises(DisclosureError):
            Disclosure.from_dict({})
        forged = dict(valid)
        forged["siblings"] = [["sideways", valid["siblings"][0][1]]]
        with self.assertRaises(DisclosureError):
            Disclosure.from_dict(forged)

    def test_a_sensitive_subject_is_refused(self):
        bundle = build_bundle(_events(5))
        disclosure = make_disclosure(bundle, 1)
        with self.assertRaises(EvidenceError):
            verify_disclosure(
                disclosure,
                subject={"event_id": "e1", "token": "s"},
                expected_root=bundle.root_digest,
            )


if __name__ == "__main__":
    unittest.main()
