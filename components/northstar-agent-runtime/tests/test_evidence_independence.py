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

import evidence_independence  # noqa: E402
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


class TestOriginResolutionGuards(unittest.TestCase):
    """The second half of every guard in the origin resolver.

    The resolver's guards are all of one shape:

        if isinstance(value, str) and value.strip():

    The FIRST half is "is it a string at all?" and the SECOND half is
    "is it non-blank?".  The suite drove the string half and left the
    blank half, so a fault planted in the blank half survived.

    The two halves are NOT interchangeable, and the difference is
    observable:

    * ``and`` -> ``or`` means a BLANK value takes the branch.  For a
      source system that raises -- an empty origin is refused -- and for
      a locator it means the resolver evaluates ``.strip()`` on a
      value that is not a string and crashes.
    * A blank source system is not an origin, so the resolver must fall
      THROUGH it and return None.

    Every test here names a value that sits exactly on that boundary.
    """

    @staticmethod
    def _blank():
        """An object whose every provenance field is blank or absent."""
        from types import SimpleNamespace

        return SimpleNamespace(
            source_system=" ",
            source=" ",
            upstream=" ",
            upstream_source=" ",
            provenance=" ",
            generator=" ",
            uri=None,
            url=None,
            locator=None,
        )

    def test_an_object_with_only_blank_provenance_has_no_origin(self):
        """`and@284` / `and@294`: the blank half of the attribute guards.

        The object declares every provenance field, but every one of
        them is blank.  The resolver must find nothing and return None.

        Under the mutant (``and`` -> ``or``) the blank source system
        takes the branch and ``Origin(source_system=" ")`` refuses an
        empty origin -- so the resolver raises instead of returning
        None.  Under the mutant at the locator guard the resolver
        evaluates ``.strip()`` on the absent locator attribute and
        raises ``AttributeError``.

        Both faults turn "this evidence has no origin" into a crash.
        """
        self.assertIsNone(item_origin(self._blank()))

    def test_an_object_with_a_blank_source_system_and_a_blank_locator_has_no_origin(self):
        """`and@294`: the locator guard, on a blank locator.

        The source fields are all blank and the locator is blank too.
        The resolver must return None.

        Under the mutant the blank locator takes the branch, the
        canonical host comes back empty, and the resolver moves on to
        the next locator -- where it evaluates ``.strip()`` on an
        absent attribute.
        """
        from types import SimpleNamespace

        obj = SimpleNamespace(
            source_system=" ",
            source=" ",
            upstream=" ",
            upstream_source=" ",
            provenance=" ",
            generator=" ",
            uri=" ",
            url=None,
            locator=None,
        )
        self.assertIsNone(item_origin(obj))

    def test_an_object_without_an_owner_has_an_origin_with_no_owner(self):
        """`and@288`: the blank half of the owner guard.

        The object names a real source system and declares NO owner
        attribute at all.  The resolver must fall back to an empty
        owner, so the origin key is the bare source system.

        Under the mutant the resolver evaluates ``.strip()`` on the
        absent owner attribute and raises ``AttributeError``.
        """
        from types import SimpleNamespace

        obj = SimpleNamespace(source_system="news.example.com")
        origin = item_origin(obj)
        self.assertIsNotNone(origin)
        self.assertEqual(origin.key, "news.example.com")
        self.assertEqual(origin.owner, "")

    def test_a_mapping_without_an_owner_has_an_origin_with_no_owner(self):
        """`and@321`: the blank half of the top-level owner guard.

        The mapping names a real source system and carries no owner key.
        The resolver must fall back to an empty owner.

        Under the mutant the resolver evaluates ``.strip()`` on the
        absent owner key and raises ``AttributeError``.
        """
        origin = item_origin({"evidence_id": "r1", "source_system": "news.example.com"})
        self.assertIsNotNone(origin)
        self.assertEqual(origin.key, "news.example.com")
        self.assertEqual(origin.owner, "")

    def test_a_nested_provenance_without_an_owner_has_an_origin_with_no_owner(self):
        """`and@311`: the blank half of the nested owner guard.

        The nested provenance mapping names a real source system and
        carries no owner key.  The resolver must fall back to an empty
        owner.

        Under the mutant the resolver evaluates ``.strip()`` on the
        absent owner key and raises ``AttributeError``.
        """
        record = {
            "evidence_id": "r1",
            "provenance": {"source_system": "news.example.com"},
        }
        origin = item_origin(record)
        self.assertIsNotNone(origin)
        self.assertEqual(origin.key, "news.example.com")
        self.assertEqual(origin.owner, "")

    def test_a_nested_provenance_with_only_blank_fields_has_no_origin(self):
        """`and@307`: the blank half of the nested source guard.

        The nested provenance mapping declares every source field, and
        every one of them is blank.  The resolver must find nothing and
        return None -- the record is unattributed, not an empty origin.

        Under the mutant the blank nested source system takes the
        branch and ``Origin(source_system=" ")`` refuses an empty
        origin, so the resolver raises instead of returning None.
        """
        record = {
            "evidence_id": "r1",
            "provenance": {
                "source_system": " ",
                "source": " ",
                "upstream": " ",
                "upstream_source": " ",
                "provenance": " ",
                "generator": " ",
            },
        }
        self.assertIsNone(item_origin(record))

    def test_a_mapping_with_only_a_non_string_locator_has_no_origin(self):
        """`and@327`: the blank half of the mapping locator guard.

        The mapping carries no source system and a locator that is not
        a string.  The resolver must return None.

        Under the mutant the resolver evaluates ``.strip()`` on the
        non-string locator and raises ``AttributeError``.
        """
        self.assertIsNone(item_origin({"evidence_id": "r1", "uri": None}))


class TestCorrelatedFieldFallbacks(unittest.TestCase):
    """The second half of the correlated-field fallback chain.

    ``correlated_fields`` reads the upstream field of an item, and the
    field has TWO spellings: ``upstream_field`` and ``field``.  The
    fallback is a CHAIN -- ``a or b or ""`` -- so the fault is in the
    chain itself.

    Under the mutant (``or`` -> ``and``) the chain becomes
    ``a and b and ""``: a record that declares ONLY ``upstream_field``
    yields an empty field, and the item is grouped under the origin's
    bare key instead of under ``origin#field``.  That silently merges
    two genuinely different correlation dimensions -- the exact blind
    spot the view exists to expose.
    """

    def test_a_mapping_that_declares_only_upstream_field_keeps_its_field(self):
        """`or@413`: the mapping fallback chain."""
        record = {
            "evidence_id": "r1",
            "source_system": "news.example.com",
            "upstream_field": "headline",
        }
        buckets = correlated_fields([record])
        self.assertEqual(list(buckets), ["news.example.com#headline"])

    def test_a_mapping_that_declares_only_field_keeps_its_field(self):
        """`or@413`: the other spelling, as the control."""
        record = {
            "evidence_id": "r1",
            "source_system": "news.example.com",
            "field": "body",
        }
        buckets = correlated_fields([record])
        self.assertEqual(list(buckets), ["news.example.com#body"])

    def test_an_object_that_declares_only_upstream_field_keeps_its_field(self):
        """`or@416`: the attribute fallback chain."""
        from types import SimpleNamespace

        obj = SimpleNamespace(
            source_system="news.example.com",
            upstream_field="headline",
        )
        buckets = correlated_fields([obj])
        self.assertEqual(list(buckets), ["news.example.com#headline"])

    def test_an_object_that_declares_only_field_keeps_its_field(self):
        """`or@416`: the other spelling, as the control."""
        from types import SimpleNamespace

        obj = SimpleNamespace(
            source_system="news.example.com",
            field="body",
        )
        buckets = correlated_fields([obj])
        self.assertEqual(list(buckets), ["news.example.com#body"])


class TestSelfCheckAsserts(unittest.TestCase):
    """The self-check's own asserts are guards too.

    ``assert independent_origin_count(ten) == 1`` is a fault site like
    any other.  Under the mutant (``==`` -> ``!=``) the self-check
    asserts the opposite of what it means, and on the real inputs it
    FAILS -- which is how the fault is detected.

    The discriminator is that the self-check must complete on the real
    code.  A self-check that raises is a broken self-check, and a
    self-check that cannot raise is a self-check that proves nothing.
    """

    def test_the_self_check_completes_on_the_real_code(self):
        """`eq@512` / `eq@521` / `eq@529` / `eq@550`: the counting asserts.

        Each of these four asserts states a counting rule.  Under the
        mutant it states the opposite, and the real inputs make it
        fail -- so the self-check raises and the module's last line of
        defence is gone.
        """
        import io
        from contextlib import redirect_stdout

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            evidence_independence.main()
        self.assertIn("evidence-independence OK", buffer.getvalue())

    def test_running_the_module_as_a_script_runs_the_self_check(self):
        """`eq@564`: the ``__main__`` guard.

        ``if __name__ == "__main__":`` becomes ``!=`` under the mutant,
        and then the self-check runs on EVERY import and NEVER runs when
        the module is run as a script -- which is how it is used.
        """
        import io
        import runpy
        from contextlib import redirect_stdout

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            runpy.run_module("evidence_independence", run_name="__main__")
        self.assertIn("evidence-independence OK", buffer.getvalue())
