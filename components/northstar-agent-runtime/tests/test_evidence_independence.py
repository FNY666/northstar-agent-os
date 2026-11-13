"""Tests for evidence_independence.py.

Evidence independence counts *independent origins*, not hits: "Ten matching
chunks can still be one source wearing ten hats" -- different URLs do not
establish independence (neo_konsi_s2bw, Moltbook).

These tests drive the whole path, not just the parts: they show that
confidence is computed over independent origins rather than over matching
hits, that a dissent citing the seal's own origin is a mirror rather than a
witness, and that unattributed evidence is marked rather than counted.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evidence_independence import (  # noqa: E402
    SCHEMA_PIN,
    UNATTRIBUTED,
    VERSION,
    EvidenceIndependenceError,
    EvidenceItem,
    InvalidThresholdError,
    MirrorStatus,
    Origin,
    claim_supported,
    correlated_fields,
    group_by_origin,
    independent_origin_count,
    is_independent_witness,
    is_mirror,
    item_origin,
    mirror_status,
    origin_keys,
    partition_by_origin,
)


def item(evidence_id, source_system="", upstream_field="", uri="", owner=""):
    """One evidence item, with the fields a retrieval result carries."""
    return EvidenceItem(
        evidence_id=evidence_id,
        source_system=source_system,
        upstream_field=upstream_field,
        uri=uri,
        owner=owner,
    )


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(VERSION, "evidence-independence.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.evidence-independence.v1")


class TestCanonicalOriginKey(unittest.TestCase):
    """The origin key is canonical: one origin, many surface forms."""

    def test_different_urls_of_one_site_are_one_origin(self):
        left = Origin(source_system="https://www.news.example.com/a?q=1")
        right = Origin(source_system="http://news.example.com/b#frag")
        self.assertEqual(left.key, right.key)
        self.assertEqual(left.source_system, "news.example.com")

    def test_a_declared_source_system_outranks_a_bare_locator(self):
        # The host says it read from "filing.example.net"; the locator it
        # recorded points somewhere else.  The declared source wins.
        evidence = item("e1", source_system="filing.example.net",
                        uri="https://cache.example.org/blob/7")
        self.assertEqual(item_origin(evidence).key, "filing.example.net")

    def test_an_owner_is_part_of_the_origin_identity(self):
        one = Origin(source_system="news.example.com", owner="Acme Wire")
        two = Origin(source_system="news.example.com", owner="Beta Wire")
        self.assertNotEqual(one.key, two.key)
        self.assertEqual(one.key, "news.example.com#acme wire")

    def test_the_same_origin_in_two_surface_forms_has_one_key(self):
        # Spelled differently, but the same upstream source.
        left = Origin(source_system="  Registry.Example.ORG ")
        right = Origin(source_system="registry.example.org")
        self.assertEqual(left.key, right.key)


class TestCountingIsOverOriginsNotHits(unittest.TestCase):
    """Ten chunks of one source are one source wearing ten hats."""

    def test_ten_evidence_items_from_one_origin_count_as_one(self):
        ten = [item("chunk-%d" % i, source_system="news.example.com")
               for i in range(10)]
        self.assertEqual(len(ten), 10)
        self.assertEqual(independent_origin_count(ten), 1)
        self.assertEqual(origin_keys(ten), ("news.example.com",))

    def test_ten_hits_never_meet_a_two_origin_threshold(self):
        ten = [item("chunk-%d" % i, source_system="news.example.com")
               for i in range(10)]
        self.assertFalse(claim_supported(ten, min_origins=2))
        self.assertTrue(claim_supported(ten, min_origins=1))

    def test_three_independent_origins_count_as_three(self):
        three = [
            item("a", source_system="news.example.com"),
            item("b", source_system="registry.example.org"),
            item("c", source_system="filing.example.net"),
        ]
        self.assertEqual(independent_origin_count(three), 3)

    def test_ten_urls_of_one_site_still_count_as_one(self):
        # Ten *different* URLs, one upstream source.
        urls = [
            item("u%d" % i, uri="https://news.example.com/story/%d" % i)
            for i in range(10)
        ]
        self.assertEqual(independent_origin_count(urls), 1)

    def test_the_same_origin_written_two_ways_groups_together(self):
        evidence = [
            item("a", source_system="news.example.com"),
            item("b", uri="https://www.news.example.com/x"),
            item("c", source_system="https://news.example.com/y"),
        ]
        groups = group_by_origin(evidence)
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups["news.example.com"]), 3)


class TestThreshold(unittest.TestCase):
    """The threshold is the caller's, and it must be a real threshold."""

    def test_the_boundary_is_inclusive(self):
        three = [
            item("a", source_system="one.example.com"),
            item("b", source_system="two.example.com"),
            item("c", source_system="three.example.com"),
        ]
        self.assertTrue(claim_supported(three, min_origins=3))
        self.assertFalse(claim_supported(three, min_origins=4))

    def test_a_non_positive_threshold_is_refused(self):
        three = [item("a", source_system="one.example.com")]
        for bad in (0, -1, -100):
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidThresholdError):
                    claim_supported(three, min_origins=bad)

    def test_a_non_integer_threshold_is_refused(self):
        three = [item("a", source_system="one.example.com")]
        for bad in (1.5, "2", True, None):
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidThresholdError):
                    claim_supported(three, min_origins=bad)

    def test_a_threshold_of_one_still_needs_an_attributed_origin(self):
        self.assertFalse(claim_supported([], min_origins=1))
        self.assertFalse(claim_supported([item("u")], min_origins=1))


class TestUnattributedEvidence(unittest.TestCase):
    """No provenance means no origin -- marked, never counted."""

    def test_missing_provenance_is_marked_unattributed(self):
        evidence = [item("u1"), item("u2")]
        groups = group_by_origin(evidence)
        self.assertIn(UNATTRIBUTED, groups)
        self.assertEqual(len(groups[UNATTRIBUTED]), 2)
        self.assertIsNone(item_origin(evidence[0]))

    def test_unattributed_evidence_never_counts_toward_independence(self):
        evidence = [
            item("a", source_system="news.example.com"),
            item("u1"),
            item("u2"),
        ]
        self.assertEqual(independent_origin_count(evidence), 1)
        self.assertFalse(claim_supported(evidence, min_origins=2))

    def test_partition_separates_unattributed_from_attributed(self):
        groups, unattributed = partition_by_origin(
            [item("a", source_system="news.example.com"), item("u1")]
        )
        self.assertEqual(list(groups), ["news.example.com"])
        self.assertEqual(len(unattributed), 1)


class TestDissentAgainstSeal(unittest.TestCase):
    """A dissent that cites the seal's origin is a mirror, not a witness."""

    def setUp(self):
        self.seal = [
            item("s1", source_system="news.example.com"),
            item("s2", source_system="registry.example.org"),
        ]

    def test_a_dissent_citing_the_same_origin_is_a_mirror(self):
        dissent = [item("d1", source_system="news.example.com")]
        self.assertTrue(is_mirror(dissent, self.seal))
        self.assertFalse(is_independent_witness(dissent, self.seal))
        self.assertIs(mirror_status(dissent, self.seal), MirrorStatus.MIRROR)

    def test_a_dissent_citing_the_seal_itself_is_a_mirror(self):
        dissent = list(self.seal)
        self.assertTrue(is_mirror(dissent, self.seal))

    def test_a_dissent_citing_a_new_origin_is_not_a_mirror(self):
        dissent = [item("d1", source_system="audit.example.net")]
        self.assertFalse(is_mirror(dissent, self.seal))
        self.assertTrue(is_independent_witness(dissent, self.seal))

    def test_a_dissent_citing_a_new_origin_beside_the_seals_is_a_witness(self):
        dissent = [
            item("d1", source_system="news.example.com"),
            item("d2", source_system="audit.example.net"),
        ]
        self.assertFalse(is_mirror(dissent, self.seal))
        self.assertIs(mirror_status(dissent, self.seal), MirrorStatus.INDEPENDENT)

    def test_an_empty_dissent_is_undecidable_not_independent(self):
        self.assertIs(mirror_status([], self.seal), MirrorStatus.UNDECIDABLE)
        self.assertFalse(is_mirror([], self.seal))
        self.assertFalse(is_independent_witness([], self.seal))

    def test_an_unattributed_dissent_is_undecidable(self):
        dissent = [item("d1")]
        self.assertIs(mirror_status(dissent, self.seal), MirrorStatus.UNDECIDABLE)
        self.assertFalse(is_mirror(dissent, self.seal))
        self.assertFalse(is_independent_witness(dissent, self.seal))

    def test_a_seal_with_no_origin_leaves_the_dissent_undecidable(self):
        self.assertIs(
            mirror_status([item("d1", source_system="news.example.com")], []),
            MirrorStatus.UNDECIDABLE,
        )


class TestCorrelatedFields(unittest.TestCase):
    """Two checks reading one upstream field can agree and be jointly wrong."""

    def test_the_same_upstream_field_of_one_origin_is_one_correlation(self):
        evidence = [
            item("a", source_system="news.example.com", upstream_field="headline"),
            item("b", source_system="news.example.com", upstream_field="headline"),
        ]
        buckets = correlated_fields(evidence)
        self.assertEqual(list(buckets), ["news.example.com#headline"])
        self.assertEqual(len(buckets["news.example.com#headline"]), 2)
        # Correlation is not independence: the origin count is still one.
        self.assertEqual(independent_origin_count(evidence), 1)

    def test_two_fields_of_one_origin_are_still_one_origin(self):
        evidence = [
            item("a", source_system="news.example.com", upstream_field="headline"),
            item("b", source_system="news.example.com", upstream_field="body"),
        ]
        self.assertEqual(len(correlated_fields(evidence)), 2)
        self.assertEqual(independent_origin_count(evidence), 1)


class TestEvidenceItemShape(unittest.TestCase):
    """Fail-closed construction."""

    def test_an_item_needs_a_non_empty_evidence_id(self):
        with self.assertRaises(EvidenceIndependenceError):
            item("")
        with self.assertRaises(EvidenceIndependenceError):
            item("   ")

    def test_an_origin_needs_a_non_empty_source_system(self):
        with self.assertRaises(EvidenceIndependenceError):
            Origin(source_system="")

    def test_mapping_shaped_evidence_is_accepted(self):
        # A mapping with a nested provenance mapping (the TaggedValue shape).
        record = {
            "evidence_id": "r1",
            "provenance": {"source_system": "news.example.com", "owner": "Acme"},
        }
        self.assertEqual(item_origin(record).key, "news.example.com#acme")
        self.assertEqual(independent_origin_count([record]), 1)

    def test_mapping_shaped_evidence_falls_back_to_the_locator(self):
        record = {"evidence_id": "r2", "uri": "https://news.example.com/x"}
        self.assertEqual(item_origin(record).key, "news.example.com")


class TestEndToEndPath(unittest.TestCase):
    """One path, driven whole: retrieval -> counting -> dissent judgement."""

    def test_the_whole_path_from_ten_hits_to_a_mirror_dissent(self):
        # The retrieval returns ten matching chunks.  They look like ten
        # supporting hits -- but nine of them are the same upstream source
        # wearing nine more hats, and the tenth is the same site reached at
        # a different URL.
        retrieved = [
            item("hit-%d" % i, source_system="news.example.com",
                 upstream_field="headline")
            for i in range(9)
        ]
        retrieved.append(item("hit-9", uri="https://www.news.example.com/x"))

        # The claim needs two independent origins.
        self.assertEqual(len(retrieved), 10)
        self.assertEqual(independent_origin_count(retrieved), 1)
        self.assertFalse(claim_supported(retrieved, min_origins=2))

        # A second, genuinely independent source arrives.
        retrieved.append(item("hit-10", source_system="audit.example.net"))
        self.assertEqual(independent_origin_count(retrieved), 2)
        self.assertTrue(claim_supported(retrieved, min_origins=2))
        self.assertFalse(claim_supported(retrieved, min_origins=3))

        # The seal is what the claim rests on: two origins.
        seal = [
            item("seal-1", source_system="news.example.com"),
            item("seal-2", source_system="audit.example.net"),
        ]

        # A dissent that cites the seal's own origin is a mirror, not a
        # witness -- it agrees with the seal by construction.
        mirror = [item("dissent-1", source_system="news.example.com")]
        self.assertIs(mirror_status(mirror, seal), MirrorStatus.MIRROR)
        self.assertTrue(is_mirror(mirror, seal))
        self.assertFalse(is_independent_witness(mirror, seal))

        # A dissent that cites a third origin is an independent witness.
        witness = [
            item("dissent-2", source_system="news.example.com"),
            item("dissent-3", source_system="filing.example.gov"),
        ]
        self.assertFalse(is_mirror(witness, seal))
        self.assertTrue(is_independent_witness(witness, seal))

        # A dissent with nothing attributable is undecidable: it is not
        # counted as a witness just because nobody could place it.
        self.assertIs(mirror_status([], seal), MirrorStatus.UNDECIDABLE)
        self.assertFalse(is_independent_witness([], seal))

        # Unattributed evidence is marked and never counts.
        loose = list(retrieved) + [item("orphan")]
        self.assertEqual(independent_origin_count(loose), 2)
        self.assertIn(UNATTRIBUTED, group_by_origin(loose))
