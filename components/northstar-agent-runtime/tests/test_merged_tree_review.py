"""Tests for the merged-tree review tool.

The tool is read-only and purely functional, so every test builds a tiny
tree in a ``tmpdir`` and points the tool at it.  The real repository is
never modified and never imported by the tool under test.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import merged_tree_review as mtr  # noqa: E402


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


class _TreeCase(unittest.TestCase):
    """Base class: a throwaway tree in a tmpdir."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def module(self, name: str, body: str) -> Path:
        return _write(self.root / f"{name}.py", body)

    def doc(self, name: str, body: str) -> Path:
        return _write(self.root / f"{name}.md", body)

    def modules(self) -> list:
        return sorted(self.root.glob("*.py"))

    def docs(self) -> list:
        return sorted(self.root.glob("*.md"))


# ---------------------------------------------------------------------------
# Rule 1 -- dangling symbols
# ---------------------------------------------------------------------------


class DanglingSymbolTests(_TreeCase):
    def test_positive_names_a_symbol_that_no_longer_exists(self) -> None:
        self.module("alpha", "def present():\n    return 1\n")
        doc = self.doc("alpha.md", "See `alpha.gone` for the entry point.\n")
        facts = mtr.collect_module_facts(self.modules())
        found = mtr.scan_dangling_symbols([doc], facts, known_modules=["alpha"])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].symbol, "gone")
        self.assertEqual(found[0].reason, "symbol-not-found")
        self.assertEqual(found[0].line, 1)

    def test_negative_a_live_reference_is_not_reported(self) -> None:
        self.module("alpha", "def kept():\n    return 1\n")
        doc = self.doc("alpha.md", "See `alpha.kept` for the entry point.\n")
        facts = mtr.collect_module_facts(self.modules())
        found = mtr.scan_dangling_symbols([doc], facts, known_modules=["alpha"])
        self.assertEqual(found, [])

    def test_negative_a_renamed_symbol_is_reported_as_dangling(self) -> None:
        """The doc drift case: slice B renamed the function."""
        self.module("alpha", "def renamed():\n    return 1\n")
        doc = self.doc("alpha.md", "Call `alpha.kept`.\n")
        facts = mtr.collect_module_facts(self.modules())
        found = mtr.scan_dangling_symbols([doc], facts, known_modules=["alpha"])
        self.assertEqual([item.symbol for item in found], ["kept"])

    def test_class_method_reference_resolves(self) -> None:
        self.module(
            "alpha",
            "class Thing:\n"
            "    def do_it(self):\n"
            "        return 1\n",
        )
        doc = self.doc("alpha.md", "Use `alpha.Thing.do_it`.\n")
        facts = mtr.collect_module_facts(self.modules())
        found = mtr.scan_dangling_symbols([doc], facts, known_modules=["alpha"])
        self.assertEqual(found, [])

    def test_class_method_that_is_gone_is_dangling(self) -> None:
        self.module(
            "alpha",
            "class Thing:\n"
            "    def other(self):\n"
            "        return 1\n",
        )
        doc = self.doc("alpha.md", "Use `alpha.Thing.do_it`.\n")
        facts = mtr.collect_module_facts(self.modules())
        found = mtr.scan_dangling_symbols([doc], facts, known_modules=["alpha"])
        self.assertEqual([item.symbol for item in found], ["Thing.do_it"])

    def test_reference_to_an_unreviewed_module_is_ignored(self) -> None:
        """``os.replace`` is prose, not a cross-slice reference."""
        self.module("alpha", "def kept():\n    return 1\n")
        doc = self.doc("alpha.md", "Call `os.replace` and `json.dumps`.\n")
        facts = mtr.collect_module_facts(self.modules())
        found = mtr.scan_dangling_symbols([doc], facts, known_modules=["alpha"])
        self.assertEqual(found, [])

    def test_missing_module_file_is_reported(self) -> None:
        self.module("alpha", "def kept():\n    return 1\n")
        doc = self.doc("alpha.md", "See `ghost.py` for the other half.\n")
        missing = mtr.scan_missing_modules([doc], ["alpha"])
        self.assertEqual([item.module for item in missing], ["ghost"])
        self.assertEqual(missing[0].reason, "module-not-found")

    def test_present_module_file_is_not_reported_missing(self) -> None:
        self.module("alpha", "def kept():\n    return 1\n")
        doc = self.doc("alpha.md", "See `alpha.py` for the other half.\n")
        self.assertEqual(mtr.scan_missing_modules([doc], ["alpha"]), [])

    def test_a_foreign_citation_is_marked_as_such(self) -> None:
        """A doc citing another project's file is not Northstar drift."""
        self.module("alpha", "def kept():\n    return 1\n")
        doc = self.doc("alpha.md", "LangGraph `types.py` holds the policy.\n")
        missing = mtr.scan_missing_modules([doc], ["alpha"])
        self.assertEqual([item.reason for item in missing], ["foreign-citation"])

    def test_a_module_from_another_component_is_not_missing(self) -> None:
        self.module("alpha", "def kept():\n    return 1\n")
        doc = self.doc("alpha.md", "See `transport.py` from the sidecar.\n")
        missing = mtr.scan_missing_modules(
            [doc], ["alpha"], repo_modules=["transport"]
        )
        self.assertEqual(missing, [])

    def test_a_method_of_a_class_resolves(self) -> None:
        self.module(
            "alpha",
            "class Thing:\n"
            "    def do_it(self):\n"
            "        return 1\n",
        )
        doc = self.doc("alpha.md", "Use `alpha.Thing.do_it`.\n")
        facts = mtr.collect_module_facts(self.modules())
        found = mtr.scan_dangling_symbols([doc], facts, known_modules=["alpha"])
        self.assertEqual(found, [])

    def test_a_private_method_named_without_its_class_resolves(self) -> None:
        """``context_controller._screen`` cites a real private method."""
        self.module(
            "alpha",
            "class Thing:\n"
            "    def _screen(self):\n"
            "        return 1\n",
        )
        doc = self.doc("alpha.md", "Uses `alpha._screen` today.\n")
        facts = mtr.collect_module_facts(self.modules())
        found = mtr.scan_dangling_symbols([doc], facts, known_modules=["alpha"])
        self.assertEqual(found, [])

    def test_a_module_level_constant_resolves(self) -> None:
        self.module("alpha", "MAX_SIZE = 120\n")
        doc = self.doc("alpha.md", "Pins `alpha.MAX_SIZE`.\n")
        facts = mtr.collect_module_facts(self.modules())
        found = mtr.scan_dangling_symbols([doc], facts, known_modules=["alpha"])
        self.assertEqual(found, [])


# ---------------------------------------------------------------------------
# Rule 2 -- same name, different meaning
# ---------------------------------------------------------------------------


class SameNameTests(_TreeCase):
    def test_positive_same_name_different_signature(self) -> None:
        self.module("alpha", "def shared(a):\n    return a\n")
        self.module("beta", "def shared(a, b):\n    return a + b\n")
        facts = mtr.collect_module_facts(self.modules())
        groups = mtr.find_same_name_symbols(facts)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].name, "shared")
        self.assertFalse(groups[0].same_signature)
        self.assertEqual(set(groups[0].modules), {"alpha", "beta"})

    def test_negative_same_name_same_signature_is_duplicate(self) -> None:
        self.module("alpha", "def shared(a):\n    return a\n")
        self.module("beta", "def shared(a):\n    return a\n")
        facts = mtr.collect_module_facts(self.modules())
        groups = mtr.find_same_name_symbols(facts)
        self.assertEqual(len(groups), 1)
        self.assertTrue(groups[0].same_signature)

    def test_negative_distinct_names_produce_no_group(self) -> None:
        self.module("alpha", "def one(a):\n    return a\n")
        self.module("beta", "def two(a):\n    return a\n")
        facts = mtr.collect_module_facts(self.modules())
        self.assertEqual(mtr.find_same_name_symbols(facts), [])

    def test_negative_private_names_are_not_public(self) -> None:
        self.module("alpha", "def _shared(a):\n    return a\n")
        self.module("beta", "def _shared(a, b):\n    return a\n")
        facts = mtr.collect_module_facts(self.modules())
        self.assertEqual(mtr.find_same_name_symbols(facts), [])

    def test_positive_a_name_in_three_modules_is_one_group(self) -> None:
        for name in ("alpha", "beta", "gamma"):
            self.module(name, "def shared(a):\n    return a\n")
        facts = mtr.collect_module_facts(self.modules())
        groups = mtr.find_same_name_symbols(facts)
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0].modules), 3)


# ---------------------------------------------------------------------------
# Rule 3 -- vocabulary overlap
# ---------------------------------------------------------------------------


class VocabularyTests(_TreeCase):
    GROUPS = {"g": ("alpha", "beta")}

    def test_positive_two_modules_mint_the_same_verdict_word(self) -> None:
        self.module("alpha", "OUTCOME = ('pass', 'fail')\n")
        self.module("beta", "RESULT = ('pass', 'blocked')\n")
        facts = mtr.collect_module_facts(self.modules())
        overlaps = mtr.vocabulary_overlap(facts, self.GROUPS)
        words = {item.word: item for item in overlaps}
        self.assertIn("pass", words)
        self.assertEqual(set(words["pass"].holders), {"alpha", "beta"})

    def test_negative_disjoint_vocabularies_do_not_overlap(self) -> None:
        self.module("alpha", "OUTCOME = ('pass', 'fail')\n")
        self.module("beta", "RESULT = ('blocked', 'revoked')\n")
        facts = mtr.collect_module_facts(self.modules())
        self.assertEqual(mtr.vocabulary_overlap(facts, self.GROUPS), [])

    def test_negative_modules_in_different_groups_do_not_overlap(self) -> None:
        self.module("alpha", "OUTCOME = ('pass', 'fail')\n")
        self.module("beta", "RESULT = ('pass', 'blocked')\n")
        facts = mtr.collect_module_facts(self.modules())
        groups = {"one": ("alpha",), "two": ("beta",)}
        self.assertEqual(mtr.vocabulary_overlap(facts, groups), [])

    def test_positive_enum_members_are_part_of_the_vocabulary(self) -> None:
        self.module(
            "alpha",
            "from enum import Enum\n"
            "class Tier(str, Enum):\n"
            "    GOLD = 'gold'\n"
            "    SILVER = 'silver'\n",
        )
        self.module("beta", "RESULT = ('gold', 'blocked')\n")
        facts = mtr.collect_module_facts(self.modules())
        overlaps = mtr.vocabulary_overlap(facts, self.GROUPS)
        words = {item.word for item in overlaps}
        self.assertIn("gold", words)

    def test_error_types_are_collected(self) -> None:
        self.module(
            "alpha",
            "class AlphaError(Exception):\n"
            "    pass\n",
        )
        facts = mtr.collect_module_facts(self.modules())
        self.assertIn("AlphaError", facts["alpha"].error_types)


# ---------------------------------------------------------------------------
# Rule 4 -- record shapes
# ---------------------------------------------------------------------------


class RecordShapeTests(_TreeCase):
    GROUPS = {"g": ("alpha", "beta")}

    def test_positive_records_with_unjoinable_fields_conflict(self) -> None:
        self.module(
            "alpha",
            "from dataclasses import dataclass\n"
            "@dataclass(frozen=True)\n"
            "class CompactionRecord:\n"
            "    summary: str = ''\n"
            "    transcript_hash: str = ''\n",
        )
        self.module(
            "beta",
            "from dataclasses import dataclass\n"
            "@dataclass(frozen=True)\n"
            "class CondensationEvent:\n"
            "    forgotten: tuple = ()\n",
        )
        facts = mtr.collect_module_facts(self.modules())
        conflicts = mtr.record_shape_conflicts(facts, self.GROUPS)
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(
            conflicts[0].left_type + "/" + conflicts[0].right_type,
            "CompactionRecord/CondensationEvent",
        )
        self.assertIn("transcript_hash", conflicts[0].missing)

    def test_negative_records_with_identical_fields_do_not_conflict(self) -> None:
        body = (
            "from dataclasses import dataclass\n"
            "@dataclass(frozen=True)\n"
            "class Record:\n"
            "    summary: str = ''\n"
            "    digest: str = ''\n"
        )
        self.module("alpha", body)
        self.module("beta", body.replace("Record", "Record"))
        facts = mtr.collect_module_facts(self.modules())
        self.assertEqual(mtr.record_shape_conflicts(facts, self.GROUPS), [])

    def test_negative_a_class_that_is_not_a_record_is_ignored(self) -> None:
        self.module(
            "alpha",
            "from dataclasses import dataclass\n"
            "@dataclass(frozen=True)\n"
            "class Helper:\n"
            "    summary: str = ''\n",
        )
        self.module(
            "beta",
            "from dataclasses import dataclass\n"
            "@dataclass(frozen=True)\n"
            "class Helper:\n"
            "    other: str = ''\n",
        )
        facts = mtr.collect_module_facts(self.modules())
        self.assertEqual(mtr.record_shape_conflicts(facts, self.GROUPS), [])

    def test_negative_the_same_module_does_not_conflict_with_itself(self) -> None:
        self.module(
            "alpha",
            "from dataclasses import dataclass\n"
            "@dataclass(frozen=True)\n"
            "class Record:\n"
            "    summary: str = ''\n"
            "    digest: str = ''\n",
        )
        facts = mtr.collect_module_facts(self.modules())
        self.assertEqual(mtr.record_shape_conflicts(facts, self.GROUPS), [])


# ---------------------------------------------------------------------------
# Read-only-ness
# ---------------------------------------------------------------------------


class ReadOnlyTests(_TreeCase):
    def test_analyze_does_not_touch_the_tree_it_reads(self) -> None:
        self.module("alpha", "def kept():\n    return 1\n")
        doc = self.doc("alpha.md", "See `alpha.gone`.\n")
        before = {
            path: path.stat().st_mtime_ns for path in list(self.modules()) + list(self.docs())
        }
        listing_before = sorted(os.listdir(self.root))
        mtr.analyze(self.modules(), self.docs())
        after = {
            path: path.stat().st_mtime_ns for path in list(self.modules()) + list(self.docs())
        }
        self.assertEqual(before, after)
        self.assertEqual(listing_before, sorted(os.listdir(self.root)))

    def test_analyze_creates_no_files_anywhere(self) -> None:
        self.module("alpha", "def kept():\n    return 1\n")
        self.doc("alpha", "See `alpha.gone`.\n")
        mtr.analyze(self.modules(), self.docs())
        self.assertEqual(
            sorted(p.name for p in self.root.iterdir()),
            ["alpha.md", "alpha.py"],
        )

    def test_the_tool_does_not_import_the_modules_it_inspects(self) -> None:
        """A module that explodes on import must still be reviewable."""
        self.module(
            "alpha",
            "raise SystemExit('importing this module must never happen')\n",
        )
        facts = mtr.collect_module_facts(self.modules())
        self.assertIn("alpha", facts)

    def test_analyze_on_the_real_tree_is_read_only(self) -> None:
        """The real repository must not change when the review runs."""
        repo = Path(__file__).resolve().parent.parent.parent.parent
        runtime = repo / "components" / "northstar-agent-runtime"
        docs = repo / "docs" / "design"
        if not docs.is_dir():
            self.skipTest("repository layout not available")
        before = subprocess.run(
            ["git", "-C", str(repo), "status", "--porcelain"],
            capture_output=True, text=True, check=False,
        ).stdout
        modules = sorted(runtime.glob("*.py"))
        mtr.analyze(modules, sorted(docs.glob("*.md")))
        after = subprocess.run(
            ["git", "-C", str(repo), "status", "--porcelain"],
            capture_output=True, text=True, check=False,
        ).stdout
        self.assertEqual(before, after)


# ---------------------------------------------------------------------------
# The whole review, end to end
# ---------------------------------------------------------------------------


class AnalyzeTests(_TreeCase):
    def test_analyze_runs_all_four_rules(self) -> None:
        self.module("alpha", "def shared(a):\n    return a\n")
        self.module("beta", "def shared(a, b):\n    return a\n")
        doc = self.doc("alpha.md", "See `alpha.shared` and `alpha.missing`.\n")
        result = mtr.analyze(self.modules(), self.docs())
        self.assertEqual(len(result.dangling), 1)
        self.assertEqual(len(result.same_name), 1)
        self.assertEqual(len(result.summary_lines()), 4)

    def test_result_is_json_shaped_data(self) -> None:
        self.module("alpha", "def kept():\n    return 1\n")
        doc = self.doc("alpha.md", "See `alpha.gone`.\n")
        data = mtr.analyze(self.modules(), self.docs()).as_dict()
        for key in ("modules", "docs", "dangling", "same_name", "vocabulary", "record_shapes"):
            self.assertIn(key, data)
        self.assertEqual(data["dangling"][0]["symbol"], "gone")

    def test_the_real_tree_review_finds_the_four_groups(self) -> None:
        repo = Path(__file__).resolve().parent.parent.parent.parent
        runtime = repo / "components" / "northstar-agent-runtime"
        docs = repo / "docs" / "design"
        if not docs.is_dir():
            self.skipTest("repository layout not available")
        result = mtr.analyze(
            sorted(runtime.glob("*.py")), sorted(docs.glob("*.md"))
        )
        self.assertTrue(result.dangling, "the merged tree has dangling doc references")
        self.assertTrue(result.same_name, "the merged tree has same-name symbols")
        self.assertTrue(result.record_shapes, "the merged tree has record shape conflicts")
        groups = {item.group for item in result.vocabulary}
        self.assertTrue(groups.issubset(set(mtr.GROUP_MODULES)))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
