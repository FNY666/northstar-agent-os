"""Tests for the frontier registry.

The registry's job is to be a *cumulative* record: every survey round adds
to it, and a reader can query what was found, what was decided, and which
slice implements it.  These tests pin the four behaviours that make it
trustworthy:

  1. add / get / list -- the read path;
  2. verdict transitions -- the lattice that makes a change of mind
     auditable;
  3. dedup by ``source_url`` -- the identity rule that stops the registry
     from over-counting what it has covered;
  4. invalid input -- the errors that stop a bad row reaching the registry.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from frontier_registry import (  # noqa: E402
    SEED_ENTRIES,
    SURVEY_ROUND,
    VERDICTS,
    FrontierEntry,
    FrontierRegistry,
    FrontierRegistryError,
    load_seed_registry,
)


def _entry(
    name="agentmem",
    url="https://github.com/AgentMem/agentmem",
    category="memory",
    verdict="absorb-now",
    status="proposed",
    linked_slice=None,
    notes="quoted from the README",
):
    return FrontierEntry(
        name=name,
        source_url=url,
        category=category,
        verdict=verdict,
        status=status,
        linked_slice=linked_slice,
        notes=notes,
    )


class AddGetListTests(unittest.TestCase):
    def test_a_new_registry_is_empty(self):
        reg = FrontierRegistry()
        self.assertEqual(0, len(reg))
        self.assertEqual([], reg.list())

    def test_add_then_get_returns_the_same_entry(self):
        reg = FrontierRegistry()
        entry = _entry()
        self.assertIs(entry, reg.add(entry))
        self.assertIs(entry, reg.get(entry.source_url))
        self.assertEqual(1, len(reg))

    def test_get_of_an_unknown_url_is_none(self):
        reg = FrontierRegistry()
        self.assertIsNone(reg.get("https://example.com/nope"))
        self.assertIsNone(reg.get(None))

    def test_list_returns_entries_in_insertion_order(self):
        reg = FrontierRegistry()
        first = _entry(name="a", url="https://example.com/a")
        second = _entry(name="b", url="https://example.com/b")
        reg.add(first)
        reg.add(second)
        self.assertEqual(["a", "b"], [e.name for e in reg.list()])

    def test_list_filters_by_verdict_category_and_status(self):
        reg = FrontierRegistry()
        reg.add(_entry(name="a", url="https://example.com/a", verdict="absorb-now", category="memory"))
        reg.add(_entry(name="b", url="https://example.com/b", verdict="reject", category="framework", status="dropped"))
        reg.add(_entry(name="c", url="https://example.com/c", verdict="absorb-later", category="memory"))
        self.assertEqual(["a"], [e.name for e in reg.list(verdict="absorb-now")])
        self.assertEqual(["a", "c"], [e.name for e in reg.list(category="memory")])
        self.assertEqual(["b"], [e.name for e in reg.list(status="dropped")])
        self.assertEqual(["a"], [e.name for e in reg.list(verdict="absorb-now", status="proposed")])

    def test_as_list_and_source_urls_expose_the_whole_registry(self):
        reg = FrontierRegistry()
        reg.add(_entry(name="a", url="https://example.com/a"))
        reg.add(_entry(name="b", url="https://example.com/b"))
        self.assertEqual(
            ["https://example.com/a", "https://example.com/b"], reg.source_urls()
        )
        rows = reg.as_list()
        self.assertEqual(2, len(rows))
        self.assertEqual("a", rows[0]["name"])
        self.assertEqual("memory", rows[0]["category"])


class DedupTests(unittest.TestCase):
    def test_adding_the_same_source_url_twice_keeps_one_entry(self):
        reg = FrontierRegistry()
        reg.add(_entry(name="agentmem"))
        reg.add(_entry(name="agentmem-again"))
        self.assertEqual(1, len(reg))
        self.assertEqual("agentmem", reg.get("https://github.com/AgentMem/agentmem").name)

    def test_a_duplicate_add_returns_the_entry_already_held(self):
        reg = FrontierRegistry()
        first = reg.add(_entry())
        second = reg.add(_entry(name="different-name"))
        self.assertIs(first, second)

    def test_dedup_is_by_source_url_not_by_name(self):
        reg = FrontierRegistry()
        reg.add(_entry(name="same", url="https://example.com/a"))
        reg.add(_entry(name="same", url="https://example.com/b"))
        self.assertEqual(2, len(reg))

    def test_membership_follows_the_source_url(self):
        reg = FrontierRegistry()
        reg.add(_entry())
        self.assertIn("https://github.com/AgentMem/agentmem", reg)
        self.assertNotIn("https://example.com/other", reg)
        self.assertNotIn(None, reg)


class VerdictTransitionTests(unittest.TestCase):
    def test_absorb_now_to_absorb_later_is_allowed(self):
        reg = FrontierRegistry()
        reg.add(_entry(verdict="absorb-now"))
        moved = reg.transition(
            "https://github.com/AgentMem/agentmem", "absorb-later"
        )
        self.assertEqual("absorb-later", moved.verdict)
        self.assertEqual("surveyed", moved.status)

    def test_a_transition_replaces_the_entry_and_keeps_its_place(self):
        reg = FrontierRegistry()
        reg.add(_entry(name="a", url="https://example.com/a"))
        reg.add(_entry(name="b", url="https://example.com/b"))
        reg.transition("https://example.com/a", "absorb-later")
        self.assertEqual(["a", "b"], [e.name for e in reg.list()])
        self.assertEqual(2, len(reg))

    def test_a_transition_leaves_the_old_entry_object_untouched(self):
        reg = FrontierRegistry()
        old = reg.add(_entry(verdict="absorb-now"))
        moved = reg.transition(
            "https://github.com/AgentMem/agentmem", "absorb-later"
        )
        self.assertEqual("absorb-now", old.verdict)
        self.assertEqual("absorb-later", moved.verdict)
        self.assertIsNot(old, moved)

    def test_a_transition_can_attach_the_follow_up_slice(self):
        reg = FrontierRegistry()
        reg.add(_entry(verdict="absorb-now"))
        moved = reg.transition(
            "https://github.com/AgentMem/agentmem",
            "absorb-later",
            linked_slice="memory-provenance-gate",
        )
        self.assertEqual("memory-provenance-gate", moved.linked_slice)

    def test_transitioning_to_the_same_verdict_is_refused(self):
        reg = FrontierRegistry()
        reg.add(_entry(verdict="absorb-now"))
        with self.assertRaises(FrontierRegistryError):
            reg.transition("https://github.com/AgentMem/agentmem", "absorb-now")

    def test_transitioning_an_unknown_entry_is_refused(self):
        reg = FrontierRegistry()
        with self.assertRaises(FrontierRegistryError):
            reg.transition("https://example.com/missing", "reject")

    def test_an_unknown_verdict_is_refused(self):
        reg = FrontierRegistry()
        reg.add(_entry(verdict="absorb-now"))
        with self.assertRaises(FrontierRegistryError):
            reg.transition("https://github.com/AgentMem/agentmem", "absorb-eventually")

    def test_link_attaches_a_slice_without_changing_the_verdict(self):
        reg = FrontierRegistry()
        reg.add(_entry(verdict="absorb-later"))
        linked = reg.link(
            "https://github.com/AgentMem/agentmem", "memory-provenance-gate"
        )
        self.assertEqual("absorb-later", linked.verdict)
        self.assertEqual("memory-provenance-gate", linked.linked_slice)

    def test_link_of_an_unknown_entry_is_refused(self):
        reg = FrontierRegistry()
        with self.assertRaises(FrontierRegistryError):
            reg.link("https://example.com/missing", "some-slug")


class InvalidInputTests(unittest.TestCase):
    def test_add_rejects_a_non_entry(self):
        reg = FrontierRegistry()
        with self.assertRaises(FrontierRegistryError):
            reg.add({"name": "not an entry"})

    def test_a_relative_source_url_is_refused(self):
        with self.assertRaises(FrontierRegistryError):
            _entry(url="github.com/AgentMem/agentmem")

    def test_an_empty_name_is_refused(self):
        with self.assertRaises(FrontierRegistryError):
            _entry(name="   ")

    def test_an_unknown_verdict_in_a_filter_is_refused(self):
        reg = FrontierRegistry()
        with self.assertRaises(FrontierRegistryError):
            reg.list(verdict="absorb-someday")

    def test_an_unknown_status_in_a_filter_is_refused(self):
        reg = FrontierRegistry()
        with self.assertRaises(FrontierRegistryError):
            reg.list(status="half-done")

    def test_a_linked_slice_must_be_text(self):
        reg = FrontierRegistry()
        reg.add(_entry())
        with self.assertRaises(FrontierRegistryError):
            reg.link("https://github.com/AgentMem/agentmem", "")

    def test_the_verdict_vocabulary_is_the_documented_one(self):
        self.assertEqual(("absorb-now", "absorb-later", "reject"), VERDICTS)


class SeedRegistryTests(unittest.TestCase):
    """The seeded rows -- the survey's own data -- are checked here.

    Without these, the registry would be machinery with nothing in it, and
    the design document's claim that it "holds one entry per surveyed
    approach" would be false.
    """

    def test_the_seed_holds_one_row_per_surveyed_source(self):
        self.assertEqual(20, len(SEED_ENTRIES))

    def test_the_seed_urls_are_all_distinct(self):
        urls = [entry.source_url for entry in SEED_ENTRIES]
        self.assertEqual(len(urls), len(set(urls)))

    def test_the_seed_rows_are_all_well_formed(self):
        for entry in SEED_ENTRIES:
            self.assertIn(entry.verdict, VERDICTS)
            self.assertTrue(entry.name.strip())
            self.assertTrue(entry.category.strip())
            self.assertTrue(entry.source_url.startswith("http"))

    def test_every_seed_row_names_the_document_record_it_comes_from(self):
        for entry in SEED_ENTRIES:
            self.assertTrue(
                entry.notes.startswith("Record S"),
                "%s does not name its record" % entry.name,
            )

    def test_the_seed_has_both_absorbed_and_deferred_rows(self):
        verdicts = {entry.verdict for entry in SEED_ENTRIES}
        self.assertEqual({"absorb-now", "absorb-later"}, verdicts)

    def test_the_three_follow_up_slices_are_linked_from_the_seed(self):
        linked = {entry.linked_slice for entry in SEED_ENTRIES if entry.linked_slice}
        self.assertEqual(
            {
                "memory-provenance-axis",
                "agent-authorization-boundary",
                "state-transfer-audit",
            },
            linked,
        )

    def test_loading_the_seed_gives_a_registry_of_the_surveyed_rows(self):
        reg = load_seed_registry()
        self.assertEqual(len(SEED_ENTRIES), len(reg))
        self.assertIn("https://arxiv.org/abs/2606.30306", reg)

    def test_the_loaded_seed_is_a_copy_and_does_not_mutate_the_constant(self):
        reg = load_seed_registry()
        reg.transition("https://arxiv.org/abs/2606.30306", "absorb-later")
        self.assertEqual(
            "absorb-now",
            next(
                e.verdict
                for e in SEED_ENTRIES
                if e.source_url == "https://arxiv.org/abs/2606.30306"
            ),
        )

    def test_a_later_round_can_append_to_the_loaded_seed(self):
        reg = load_seed_registry()
        before = len(reg)
        reg.add(
            FrontierEntry(
                name="a later source",
                source_url="https://example.com/round-two",
                category="memory",
                verdict="absorb-later",
                status="surveyed",
            )
        )
        self.assertEqual(before + 1, len(reg))
        self.assertEqual(before, len(load_seed_registry()))


if __name__ == "__main__":
    unittest.main()
