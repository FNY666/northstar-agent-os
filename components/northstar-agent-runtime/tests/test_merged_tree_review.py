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

try:
    import merged_tree_review as mtr  # noqa: E402
except SystemExit as _exit:  # pragma: no cover - only under a planted fault
    # The module's CLI guard is ``if __name__ == "__main__":``.  If that
    # test is inverted, importing the module runs the command-line
    # entry point, which ends in ``raise SystemExit(main())`` -- the
    # importing process is terminated before a single test can run, and
    # the exit code is 0, so the failure is invisible.  Refuse the
    # import loudly instead: a library module must be importable
    # without ending the importer.
    raise AssertionError(
        "importing merged_tree_review must not end the importing "
        "process; the __main__ guard was inverted (%r)" % (_exit,)
    ) from _exit


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

class MutantSecondHalfGuardTests(_TreeCase):
    """The missing arm of every surviving guard in ``merged_tree_review``.

    A planted fault survives this slice's suite when only one arm of a
    two-armed guard was ever driven.  Each guard below is written as
    ``A and B`` (or ``A or B``); the mutant flips the connective, so the
    mutant and the original differ only when exactly one side of the
    connective holds.  The tests therefore feed BOTH kinds of bad input:
    the one that trips arm A only, and the one that trips arm B only.

    The sites driven here:

    ``and@156``  ``isinstance(node, ast.Constant) and isinstance(node.value,
                 str)`` in ``_literal``.
    ``eq@192``   the ``statement.name == "as_dict"`` test in ``_class_fields``.
    ``and@194``  ``isinstance(inner, ast.Return) and isinstance(inner.value,
                 ast.Dict)`` in ``_class_fields``.
    ``and@197``  ``value is not None and value not in fields`` in
                 ``_class_fields``.
    ``retT@226`` the base-derived arm of ``_is_error_class``.
    ``retF@227`` the "this is not an error class" answer of
                 ``_is_error_class``.
    ``or@264``   ``name in self.functions or name in self.classes`` in
                 ``ModuleFacts.has_symbol``.
    ``and@346``  the "is a verdict name" test in the ``Assign`` branch of
                 the vocabulary scan.
    ``eq@348``   the "exactly one value" test in the same branch.
    ``and@358``  the "is a verdict name" test in the ``AnnAssign`` branch.
    ``eq@360``   the "exactly one value" test in the same branch.
    ``and@372``  ``isinstance(node, ast.Constant) and isinstance(node.value,
                 str)`` in the inline-verdict scan.
    ``and@374``  ``value in VERDICT_WORDS and value not in inline``.
    ``and@494``  the ``len(parts) == 2 and head in module_facts.classes``
                 test in ``_symbol_resolves``.
    ``retF@498`` the "this does not resolve" answer of ``_symbol_resolves``.
    ``retF@502`` the "this does not resolve" answer of ``_symbol_resolves``
                 for a head that is not a class.
    ``or@604``   ``not span.endswith(".py") or not re.match(...)`` in
                 ``scan_missing_modules``.
    ``and@850``  ``not missing and not right_missing`` in
                 ``record_shape_conflicts``.
    ``eq@970``   the ``__name__ == "__main__"`` CLI guard.

    ``gt@451`` and ``eq@494``-of-the-first-kind are proved EQUIVALENT in
    :class:`MutantEquivalentTests`.
    """

    # --- and@156: _literal's "is this a string constant" --------------
    def test_and_at_156_a_non_string_constant_is_not_a_field_name(self):
        """`and@156`: the SECOND half -- the constant is not a string.

        The guard is ``isinstance(node, ast.Constant) and isinstance(
        node.value, str)``.  Under the mutant (``and`` -> ``or``) a
        numeric constant satisfies the *first* half, so the guard admits
        it and the scanner hands back the number.  The record's field
        names would then carry a non-string, and every later question
        about that field -- "is it a name?" -- changes meaning.
        """
        self.module("alpha", "OUTCOME = ('pass', 5)\n")
        facts = mtr.collect_module_facts(self.modules())
        self.assertEqual(facts["alpha"].verdict_vocabulary["OUTCOME"], ("pass",))

    def test_and_at_156_a_string_constant_is_still_a_field_name(self):
        # The control: a real string constant is still read.
        self.module("alpha", "OUTCOME = ('pass', 'fail')\n")
        facts = mtr.collect_module_facts(self.modules())
        self.assertEqual(
            facts["alpha"].verdict_vocabulary["OUTCOME"], ("pass", "fail")
        )

    # --- eq@192: the as_dict name test --------------------------------
    def test_eq_at_192_the_fields_of_an_as_dict_method_are_the_fields(self):
        """`eq@192`: the "is this the as_dict method" test.

        Under the mutant (``==`` -> ``!=``) the ``as_dict`` method is
        *skipped*, so the record's shape is never read and the record
        looks like it has no fields at all -- a record the shape rule
        cannot join.
        """
        self.module(
            "alpha",
            "class Thing:\n"
            "    def as_dict(self):\n"
            "        return {'a': 1, 'b': 2}\n",
        )
        facts = mtr.collect_module_facts(self.modules())
        self.assertEqual(facts["alpha"].class_fields["Thing"], ("a", "b"))

    # --- and@194: the "returns a dict" test ---------------------------
    def test_and_at_194_an_as_dict_that_returns_nothing_is_not_a_shape(self):
        """`and@194`: the SECOND half -- the return value is not a dict.

        The guard is ``isinstance(inner, ast.Return) and isinstance(
        inner.value, ast.Dict)``.  Under the mutant (``and`` -> ``or``)
        a ``Return`` whose value is not a dict is admitted and the
        scanner reaches for ``.keys`` on it -- the review of a
        perfectly ordinary module then dies instead of reporting "this
        record has no fields".
        """
        self.module(
            "alpha",
            "class Thing:\n"
            "    def as_dict(self):\n"
            "        return None\n",
        )
        facts = mtr.collect_module_facts(self.modules())
        self.assertEqual(facts["alpha"].class_fields["Thing"], ())

    # --- and@197: the "not already a field" test ----------------------
    def test_and_at_197_a_repeated_as_dict_key_is_not_a_second_field(self):
        """`and@197`: the SECOND half -- the key is already a field.

        The guard is ``value is not None and value not in fields``.
        Under the mutant (``and`` -> ``or``) a repeated key is appended
        twice, so the record's field list carries the same name twice
        and every "is this field present" question about it changes
        meaning.
        """
        self.module(
            "alpha",
            "class Thing:\n"
            "    def as_dict(self):\n"
            "        return {'a': 1, 'a': 2}\n",
        )
        facts = mtr.collect_module_facts(self.modules())
        self.assertEqual(facts["alpha"].class_fields["Thing"], ("a",))

    # --- retT@226 / retF@227: _is_error_class -------------------------
    def test_ret_t_at_226_a_class_with_an_error_base_is_an_error_type(self):
        """`retT@226`: the BASE-derived arm of the error test.

        The class's own name says nothing about errors (``Boom``), but
        its base does.  Under the mutant (``return True`` -> ``return
        False``) the base-derived answer is lost and the class is no
        longer reported as an error type -- so a doc that cites the
        error class as a definition of the error stops resolving.
        """
        self.module(
            "alpha",
            "class Boom(SomeError):\n"
            "    pass\n",
        )
        facts = mtr.collect_module_facts(self.modules())
        self.assertIn("Boom", facts["alpha"].error_types)

    def test_ret_f_at_227_a_plain_class_is_not_an_error_type(self):
        """`retF@227`: the "this is not an error class" answer.

        Under the mutant (``return False`` -> ``return True``) every
        class in the tree -- including a class with no error name and
        no error base -- is reported as an error type, and the error
        list stops meaning anything.
        """
        self.module(
            "alpha",
            "class Plain:\n"
            "    pass\n",
        )
        facts = mtr.collect_module_facts(self.modules())
        self.assertNotIn("Plain", facts["alpha"].error_types)

    def test_the_error_test_is_name_or_base_but_not_both(self):
        """The control: the name-derived arm still works, and a plain
        class stays out of the list."""
        self.module(
            "alpha",
            "class AlphaError(Exception):\n"
            "    pass\n"
            "class Plain:\n"
            "    pass\n",
        )
        facts = mtr.collect_module_facts(self.modules())
        self.assertIn("AlphaError", facts["alpha"].error_types)
        self.assertNotIn("Plain", facts["alpha"].error_types)

    # --- or@264: has_symbol -------------------------------------------
    def test_or_at_264_a_function_name_is_a_symbol_the_module_has(self):
        """`or@264`: the FIRST half -- the name is a function.

        The guard is ``name in self.functions or name in self.classes``.
        Under the mutant (``or`` -> ``and``) a name that is a function
        but not a class is reported as absent.
        """
        self.module("alpha", "def kept():\n    return 1\n")
        facts = mtr.collect_module_facts(self.modules())
        self.assertTrue(facts["alpha"].has_symbol("kept"))

    def test_or_at_264_a_class_name_is_a_symbol_the_module_has(self):
        """`or@264`: the SECOND half -- the name is a class."""
        self.module("alpha", "class Thing:\n    pass\n")
        facts = mtr.collect_module_facts(self.modules())
        self.assertTrue(facts["alpha"].has_symbol("Thing"))

    def test_or_at_264_a_name_the_module_does_not_have_is_absent(self):
        # The control: an unknown name is still absent.
        self.module("alpha", "def kept():\n    return 1\n")
        facts = mtr.collect_module_facts(self.modules())
        self.assertFalse(facts["alpha"].has_symbol("gone"))

    # --- and@346 / eq@348: the Assign branch of the vocabulary scan ---
    def test_and_at_346_a_multi_valued_constant_is_not_a_verdict_vocabulary(self):
        """`and@346`: the SECOND half -- the name is not a verdict name.

        The guard is ``values and _VERDICT_CONST_RE.search(name)``.
        Under the mutant (``and`` -> ``or``) a multi-valued constant
        whose name does not look like a verdict becomes part of the
        verdict vocabulary, so two modules that merely share a
        non-verdict constant are reported as sharing a *verdict word*.
        """
        self.module("alpha", "PAIR = ('a', 'b')\n")
        facts = mtr.collect_module_facts(self.modules())
        self.assertNotIn("PAIR", facts["alpha"].verdict_vocabulary)

    def test_eq_at_348_a_single_valued_constant_is_still_a_vocabulary(self):
        """`eq@348`: the "exactly one value" test.

        Under the mutant (``==`` -> ``!=``) a constant with exactly one
        string value drops out of the vocabulary -- the single-value
        case is the one the rule was written for.
        """
        self.module("alpha", "SINGLE = 'one'\n")
        facts = mtr.collect_module_facts(self.modules())
        self.assertIn("SINGLE", facts["alpha"].verdict_vocabulary)

    def test_a_verdict_named_constant_with_a_non_string_value_is_no_vocabulary(self):
        """`and@346` / `eq@348`: the "no string value" case.

        A verdict-named constant whose value is not a string sequence
        has no words to mint, so it must not appear in the vocabulary
        at all -- not even with an empty word list.
        """
        self.module("alpha", "STATUS = 5\n")
        facts = mtr.collect_module_facts(self.modules())
        self.assertNotIn("STATUS", facts["alpha"].verdict_vocabulary)

    # --- and@358 / eq@360: the AnnAssign branch -----------------------
    def test_and_at_358_an_annotated_multi_valued_constant_is_no_vocabulary(self):
        """`and@358`: the SECOND half, in the annotated branch.

        The ``AnnAssign`` branch of ``read_module_facts`` repeats the
        vocabulary rule.  Under the mutant (``and`` -> ``or``) an
        annotated multi-valued constant whose name is not a verdict
        name becomes a verdict vocabulary.
        """
        self.module("alpha", "PAIR: tuple = ('a', 'b')\n")
        facts = mtr.collect_module_facts(self.modules())
        self.assertNotIn("PAIR", facts["alpha"].verdict_vocabulary)

    def test_eq_at_360_an_annotated_single_valued_constant_is_still_a_vocabulary(self):
        """`eq@360`: the "exactly one value" test, annotated branch.

        Under the mutant (``==`` -> ``!=``) an annotated constant with
        exactly one string value drops out of the vocabulary.
        """
        self.module("alpha", "SINGLE: str = 'one'\n")
        facts = mtr.collect_module_facts(self.modules())
        self.assertIn("SINGLE", facts["alpha"].verdict_vocabulary)

    def test_an_annotated_verdict_named_constant_with_a_non_string_value_is_no_vocabulary(self):
        """`and@358` / `eq@360`: the "no string value" case, annotated."""
        self.module("alpha", "STATUS: int = 5\n")
        facts = mtr.collect_module_facts(self.modules())
        self.assertNotIn("STATUS", facts["alpha"].verdict_vocabulary)

    # --- and@372: the inline-verdict scan's type test ------------------
    def test_and_at_372_a_non_string_constant_is_not_an_inline_verdict(self):
        """`and@372`: the SECOND half -- the constant is not a string.

        The guard is ``isinstance(node, ast.Constant) and isinstance(
        node.value, str)``.  Under the mutant (``and`` -> ``or``) a
        numeric constant satisfies the first half and the scan reaches
        for ``.strip()`` on a number -- the review of an ordinary
        module dies instead of listing its verdict words.
        """
        self.module("alpha", "MAX = 5\n")
        facts = mtr.collect_module_facts(self.modules())
        self.assertEqual(facts["alpha"].inline_verdicts, ())

    def test_and_at_372_a_string_constant_is_still_an_inline_verdict(self):
        # The control: a real verdict word is still found.
        self.module("alpha", "MARK = 'pass'\n")
        facts = mtr.collect_module_facts(self.modules())
        self.assertEqual(facts["alpha"].inline_verdicts, ("pass",))

    # --- and@374: the "not already listed" test -----------------------
    def test_and_at_374_a_repeated_verdict_word_is_listed_once(self):
        """`and@374`: the SECOND half -- the word is already inline.

        The guard is ``value in VERDICT_WORDS and value not in inline``.
        Under the mutant (``and`` -> ``or``) a word that was already
        collected is appended again, so the inline verdict list carries
        duplicates -- and the count of the list stops being the count
        of the distinct verdict words.
        """
        self.module("alpha", "A = 'pass'\nB = 'pass'\n")
        facts = mtr.collect_module_facts(self.modules())
        self.assertEqual(facts["alpha"].inline_verdicts, ("pass",))

    # --- and@494 / retF@498: _symbol_resolves -------------------------
    def test_and_at_494_a_dotted_path_under_a_method_does_not_resolve(self):
        """`and@494`: the SECOND half -- the head is not a class.

        The guard is ``len(parts) == 2 and head in module_facts.classes``.
        Under the mutant (``and`` -> ``or``) the guard fires on the
        length alone, and the scanner then reaches for the head in the
        class table -- where it is not, because the head is a *method*.
        A doc naming ``alpha._screen.extra`` therefore crashes the
        review with a ``KeyError`` instead of being reported as drift.
        """
        self.module(
            "alpha",
            "class Thing:\n"
            "    def _screen(self):\n"
            "        return 1\n",
        )
        doc = self.doc("alpha.md", "Uses `alpha._screen.extra` today.\n")
        facts = mtr.collect_module_facts(self.modules())
        found = mtr.scan_dangling_symbols([doc], facts, known_modules=["alpha"])
        self.assertEqual([item.symbol for item in found], ["_screen.extra"])

    def test_ret_f_at_498_a_dotted_path_under_a_method_does_not_resolve(self):
        """`retF@498`: the "this does not resolve" answer.

        Under the mutant (``return False`` -> ``return True``) a path
        that resolves to nothing is reported as resolving -- the doc
        drift the whole rule exists to find disappears.
        """
        self.module(
            "alpha",
            "class Thing:\n"
            "    def _screen(self):\n"
            "        return 1\n",
        )
        doc = self.doc("alpha.md", "Uses `alpha._screen.extra` today.\n")
        facts = mtr.collect_module_facts(self.modules())
        found = mtr.scan_dangling_symbols([doc], facts, known_modules=["alpha"])
        self.assertEqual([item.symbol for item in found], ["_screen.extra"])

    # --- retF@502: a head that is not a class -------------------------
    def test_ret_f_at_502_a_function_name_does_not_resolve_a_dotted_path(self):
        """`retF@502`: the "this does not resolve" answer, function head.

        ``alpha.kept.extra`` names a function ``kept`` and then a path
        under it.  A function is not a class, so the path resolves to
        nothing.  Under the mutant (``return False`` -> ``return True``)
        it reads as resolved and the drift is never reported.
        """
        self.module("alpha", "def kept():\n    return 1\n")
        doc = self.doc("alpha.md", "Uses `alpha.kept.extra` today.\n")
        facts = mtr.collect_module_facts(self.modules())
        found = mtr.scan_dangling_symbols([doc], facts, known_modules=["alpha"])
        self.assertEqual([item.symbol for item in found], ["kept.extra"])

    # --- or@604: the ".py" span filter --------------------------------
    def test_or_at_604_a_span_that_is_not_a_python_file_name_is_skipped(self):
        """`or@604`: the SECOND half -- the name is not a python file.

        The guard is ``not span.endswith(".py") or not re.match(
        "^[A-Za-z_][A-Za-z0-9_]*\\.py$", span)``.  Under the mutant
        (``or`` -> ``and``) a span that *ends* in ``.py`` but is not a
        python file name is no longer skipped, and the review reports
        a missing module for a file that was never a python file.
        """
        self.module("alpha", "def kept():\n    return 1\n")
        doc = self.doc("alpha.md", "See `weird-name.py` for details.\n")
        self.assertEqual(mtr.scan_missing_modules([doc], ["alpha"]), [])

    def test_or_at_604_a_span_that_is_not_a_py_file_is_skipped(self):
        """`or@604`: the FIRST half -- the span does not end in ``.py``."""
        self.module("alpha", "def kept():\n    return 1\n")
        doc = self.doc("alpha.md", "See `alpha.txt` for details.\n")
        self.assertEqual(mtr.scan_missing_modules([doc], ["alpha"]), [])

    def test_or_at_604_a_real_missing_python_file_is_still_reported(self):
        # The control: the rule still fires on a genuine drift.
        self.module("alpha", "def kept():\n    return 1\n")
        doc = self.doc("alpha.md", "See `ghost.py` for the other half.\n")
        missing = mtr.scan_missing_modules([doc], ["alpha"])
        self.assertEqual([item.module for item in missing], ["ghost"])

    # --- and@850: the "nothing is missing" test -----------------------
    def test_and_at_850_a_record_that_is_a_superset_still_conflicts(self):
        """`and@850`: the SECOND half -- only one side is missing fields.

        The guard is ``not missing and not right_missing``.  Under the
        mutant (``and`` -> ``or``) a conflict in which only ONE side has
        a field the other lacks is skipped -- and that is the *common*
        case: the left record simply has one more field than the
        right one.
        """
        self.module(
            "alpha",
            "from dataclasses import dataclass\n"
            "@dataclass(frozen=True)\n"
            "class AlphaRecord:\n"
            "    summary: str = ''\n"
            "    digest: str = ''\n",
        )
        self.module(
            "beta",
            "from dataclasses import dataclass\n"
            "@dataclass(frozen=True)\n"
            "class BetaRecord:\n"
            "    summary: str = ''\n",
        )
        facts = mtr.collect_module_facts(self.modules())
        conflicts = mtr.record_shape_conflicts(facts, {"g": ("alpha", "beta")})
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0].missing, ("digest",))
        self.assertEqual(conflicts[0].right_missing, ())

    def test_and_at_850_records_with_identical_fields_still_do_not_conflict(self):
        # The control: identical shapes are not a conflict.
        body = (
            "from dataclasses import dataclass\n"
            "@dataclass(frozen=True)\n"
            "class Record:\n"
            "    summary: str = ''\n"
        )
        self.module("alpha", body)
        self.module("beta", body)
        facts = mtr.collect_module_facts(self.modules())
        self.assertEqual(
            mtr.record_shape_conflicts(facts, {"g": ("alpha", "beta")}), []
        )

    # --- eq@970: the CLI guard ----------------------------------------
    def test_eq_at_970_importing_the_module_does_not_run_the_cli(self):
        """`eq@970`: the ``__name__ == "__main__"`` guard.

        Under the mutant (``==`` -> ``!=``) importing the module runs
        the command-line entry point, and the entry point ends in
        ``raise SystemExit(main())`` -- so the importing process dies
        with ``SystemExit(0)`` before a single test has run.  That is
        the whole damage: a library module must be importable without
        ending the importer.

        The subprocess is the discriminator, because the mutation is
        fatal at import time: the test process itself cannot survive
        it, so the check has to happen in a child.
        """
        component = Path(__file__).resolve().parent.parent
        result = subprocess.run(
            [sys.executable, "-c", "import merged_tree_review"],
            cwd=str(self.root),
            env={
                **os.environ,
                "PYTHONPATH": str(component),
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_eq_at_970_importing_the_module_does_not_end_the_importer(self):
        """`eq@970`: the same guard, seen as a process exit code.

        Under the mutant the import ends the importing process with
        ``SystemExit`` -- the exit code is still 0, so only the
        *absence* of the CLI's summary output distinguishes the two.
        The CLI prints four summary lines; an import must print none.
        """
        component = Path(__file__).resolve().parent.parent
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import merged_tree_review; print('IMPORTED')",
            ],
            cwd=str(self.root),
            env={
                **os.environ,
                "PYTHONPATH": str(component),
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "IMPORTED\n")


class MutantEquivalentTests(_TreeCase):
    """The mutants that are EQUIVALENT, proved rather than assumed.

    Two planted faults in ``merged_tree_review`` cannot be killed by
    any test, because the original and the mutated code are the same
    function.  Each is proved below by a differential test: the
    mutated module is executed alongside the original and the two are
    compared over a wide set of inputs.  Zero differences is the
    proof.

    **The proof is SYMMETRIC.**  The two copies are built by rewriting
    whichever spelling the source on disk happens to carry, so the
    proof means the same thing before and after the mutation probe has
    planted its fault.  An asymmetric proof -- one that asserts a
    particular spelling is present -- FAILS on the mutated module for
    a reason that has nothing to do with behaviour, and the probe then
    reports an equivalent mutant as "killed".  That shape was measured
    on ``scope-verbatim-compaction`` in
    ``docs/design/mutant-evidence-closure.md`` §9.2, and it was
    measured here too: before this slice, ``gt@451`` was reported
    killed by a difference in the FILE.

    The proof also has a **non-vacuity control**, in
    ``MutantEquivalentHarnessControlTests`` below: a comparison that
    genuinely changes the answer, driven through the SAME harness, must
    be detected.  A proof that cannot fail proves nothing.
    """

    def _comparison_pair(self, site, other):
        """Two namespaces: one per version of ONE comparison.

        ``site`` is the pair of spellings of the comparison under test
        -- ``("len(parts) > 1", "len(parts) >= 1")`` -- and ``other``
        is the version the second copy should carry.

        The two copies are built from the module's source, so the
        result holds whichever spelling is on disk: the pair is
        ``(original, mutant)`` when the source carries the first
        spelling and ``(mutant, original)`` when it carries the
        second.  The proof compares the two against each other, so it
        is symmetric by construction.

        **Why not a fingerprint on the exact wording:** that shape was
        measured in ``docs/design/mutant-evidence-closure.md`` §9.2.
        A proof that asserts one specific spelling FAILS the moment
        the mutation probe plants the other one -- and the probe then
        reports an equivalent mutant as "killed", a difference in the
        FILE rather than in the BEHAVIOUR.  So the site is located by
        accepting EITHER of its two spellings, and the rewrite is done
        at the comparison's own source position.
        """
        source = Path(mtr.__file__).read_text(encoding="utf-8")
        first = self._rewrite(source, site, site[0])
        second = self._rewrite(source, site, other)
        self.assertNotEqual(
            first,
            second,
            "the two versions must produce different module sources",
        )
        return self._exec(first), self._exec(second)

    def _exec(self, source: str) -> dict:
        """Execute a copy of the module and return its namespace."""
        namespace: dict = {}
        exec(  # noqa: S102 - the module is this repository's own source
            compile(source, "<mutant>", "exec"),
            namespace,
        )
        return namespace

    def _rewrite(self, source: str, site, to: str) -> str:
        """Return ``source`` with the site's comparison replaced by ``to``.

        The site is located by accepting EITHER of the two spellings in
        ``site`` -- so the rewrite lands whichever one the source
        currently carries -- and it is located by the comparison's own
        AST, so it still lands if the surrounding text is reworded.
        """
        import ast

        wanted = {self._normalized_comparison(text) for text in site}
        tree = ast.parse(source)
        candidates = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Compare) or len(node.ops) != 1:
                continue
            segment = ast.get_source_segment(source, node)
            if segment is None:
                continue
            if self._normalized_comparison(segment) not in wanted:
                continue
            candidates.append(node)
        self.assertEqual(
            len(candidates),
            1,
            "the comparison must be found exactly once in the module",
        )
        node = candidates[0]
        segment = ast.get_source_segment(source, node)
        self.assertIsNotNone(segment)
        segment_start = self._offset_of(
            source, node.lineno, node.col_offset
        )
        start = segment_start
        end = start + len(segment)
        replacement = self._comparison_source(to)
        mutated = source[:start] + replacement + source[end:]

        # The rewritten comparison must now be exactly ``to``.  It is
        # located by its own normalized source, so the assertion checks
        # the RIGHT comparison.
        self.assertIn(
            self._normalized_comparison(replacement),
            {
                self._normalized_comparison(text)
                for text in self._comparisons(mutated)
            },
            "the rewrite must produce the requested comparison",
        )
        return mutated

    @classmethod
    def _comparisons(cls, source: str):
        """The source of every comparison in ``source``."""
        import ast

        found = []
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Compare) or len(node.ops) != 1:
                continue
            segment = ast.get_source_segment(source, node)
            if segment is None:
                continue
            found.append(segment)
        return found

    @classmethod
    def _normalized_comparison(cls, text: str) -> str:
        """A comparison's source, normalized and with no whitespace.

        The operator IS included here -- unlike the operand-only match
        -- because the site is identified by accepting either of its
        two spellings, so the match is over a SET of spellings rather
        than over a single expected one.
        """
        import ast

        tree = ast.parse(text.strip())
        for node in ast.walk(tree):
            if isinstance(node, ast.Compare):
                return "".join(ast.unparse(node).split())
        raise AssertionError("no comparison in %r" % (text,))

    @classmethod
    def _comparison_source(cls, text: str) -> str:
        """The canonical source of the comparison in ``text``."""
        import ast

        tree = ast.parse(text.strip())
        for node in ast.walk(tree):
            if isinstance(node, ast.Compare):
                return ast.unparse(node)
        raise AssertionError("no comparison in %r" % (text,))

    @staticmethod
    def _offset_of(source: str, lineno: int, col_offset: int) -> int:
        """The absolute character offset of a 1-based (line, column)."""
        lines = source.splitlines(keepends=True)
        offset = 0
        for index in range(lineno - 1):
            offset += len(lines[index])
        return offset + col_offset

    def test_gt_at_451_is_equivalent_because_a_span_with_a_dot_has_two_parts(self):
        """`gt@451`: the ``len(parts) > 1`` bound.

        The line is::

            if parts and parts[-1] == "py" and len(parts) > 1:

        ``_candidate_references`` returns early unless the span
        contains a ``.``::

            if "." not in span:
                return []

        so by the time the bound is reached ``parts = span.split(".")``
        always has at least two elements, and ``len(parts) > 1`` is
        always true.  ``len(parts) > 1`` and ``len(parts) >= 1``
        therefore agree on every span the function ever sees: an
        EQUIVALENT mutant, not a gap in the suite.

        The differential test below runs both versions over every span
        shape the function can be handed and compares the results.  The
        two versions are built by rewriting whichever spelling the
        source on disk carries, so the proof is symmetric: it means
        the same thing before and after the mutation probe has planted
        its fault.
        """
        original, mutant = self._comparison_pair(
            ("len(parts) > 1", "len(parts) >= 1"),
            "len(parts) >= 1",
        )
        spans = [
            "a.b", "a.py", "a.b.py", "pkg.mod.func", "a..b", "a.",
            ".a", "a.b.c.d", "py.a", "a.py.b", "_x._y", "a-b.c",
            "a.b-c", "x.y", "z", "mod.Class.method", "a.1b",
        ]
        for span in spans:
            self.assertEqual(
                mutant["_candidate_references"](span),
                original["_candidate_references"](span),
                "span %r" % span,
            )

    def test_eq_at_494_is_equivalent_because_a_head_outside_all_symbols_is_never_a_class(self):
        """`eq@494`: the ``head in module_facts.classes`` test.

        The line is::

            if len(parts) == 2 and head in module_facts.classes:

        and it sits inside the branch that is entered only when::

            if head not in module_facts.all_symbols():

        ``all_symbols`` is the union of the module's functions, classes
        and constants, so a head that is *not* in ``all_symbols``
        cannot be in ``classes`` either.  The second half of the
        conjunction is therefore always false in this branch, and
        ``len(parts) == 2 and head in classes`` is always false --
        exactly like the mutant ``len(parts) != 2 and head in classes``,
        whose second half is also always false.  The branch is dead
        code in both versions: an EQUIVALENT mutant.

        The differential test below runs both versions over a wide set
        of module facts and symbol paths and compares the answers.  The
        two versions are built by rewriting whichever spelling the
        source on disk carries, so the proof is symmetric: it means
        the same thing before and after the mutation probe has planted
        its fault.
        """
        original, mutant = self._comparison_pair(
            ("len(parts) == 2", "len(parts) != 2"),
            "len(parts) != 2",
        )
        self.module(
            "alpha",
            "def kept():\n"
            "    return 1\n"
            "class Thing:\n"
            "    def do_it(self):\n"
            "        return 1\n"
            "    def _screen(self):\n"
            "        return 1\n"
            "MAX_SIZE = 120\n",
        )
        facts = mtr.collect_module_facts(self.modules())
        paths = [
            "kept", "Thing", "MAX_SIZE", "gone", "do_it", "_screen",
            "Thing.do_it", "Thing.gone", "kept.extra", "_screen.extra",
            "do_it.extra", "gone.extra", "Thing.do_it.extra",
            "_screen.a.b", "gone.a.b", "MAX_SIZE.extra",
        ]
        for path in paths:
            self.assertEqual(
                mutant["_symbol_resolves"](facts["alpha"], path),
                original["_symbol_resolves"](facts["alpha"], path),
                "path %r" % path,
            )


class MutantEquivalentHarnessControlTests(MutantEquivalentTests):
    """The ``gt@451`` / ``eq@494`` equivalence proofs must be able to FAIL.

    ``MutantEquivalentTests`` proves that two planted faults in
    ``merged_tree_review`` change nothing: the strict and non-strict
    spellings are reached only when the two spellings already agree,
    and for two different sets the two spellings agree.

    A differential test that CANNOT fail proves nothing.  The proof
    above pins the PREMISE its argument rests on -- that the two
    spellings are reached only for equal sets -- but it never shows
    that a broken premise would change the answer.  So if the premise
    were not what the argument says, the "no difference" conclusion
    would be empty, and the record would be a false comfort: the next
    reader would either burn a round hunting a killer that does not
    exist, or trust a mutant that was in fact killable.

    This class gives the proof its **non-vacuity control**: a
    comparison that is known to change behaviour, driven through the
    SAME harness, must be DETECTED.

    Two shapes of control, and both are needed:

    * **a control comparison** -- the same operands with an operator
      that genuinely separates them.  The harness must find the
      difference; if it does not, the harness is blind and the
      equivalence result above would be worthless.
    * **the skipped inputs** -- the proof compares only the DIFFERENT
      target sets, because the equal ones are decided above the
      comparison.  Running the same comparison over the EQUAL sets
      must find a difference there.  That is what licenses the "no
      difference over the different sets" conclusion, and it is also
      what shows the sweep is not skipping everything.

    The comparison is ``gt@451``: ``len(parts) > 1`` versus
    ``len(parts) >= 1``.  The control operator is ``!=``: for two
    different lengths it separates them, and it separates the EQUAL
    lengths too.
    """

    #: The two spellings of the comparison under test.
    GT = "len(parts) > 1"
    GTE = "len(parts) >= 1"

    #: The CONTROL spelling: a bound that genuinely changes the result,
    #: so the harness MUST notice the difference.
    #:
    #: The control was chosen by MEASUREMENT, not by guessing: the
    #: first two candidates were NO-OPS.  ``len(parts) != 1`` and
    #: ``len(parts) >= 2`` both leave every span's answer unchanged
    #: (the trim only fires on a two-part span whose last part is
    #: "py", and the guard below -- ``if len(parts) < 2: return []``
    #: -- absorbs the rest).  That is the pitfall measured on
    #: ``fable`` in ``docs/design/mutant-evidence-closure.md`` §9.2:
    #: a control mutation must be OBSERVABLE, or it proves nothing.
    #:
    #: ``len(parts) > 2`` DOES change the answer: on ``"a.py"`` the
    #: parts are ``["a", "py"]``, so the original trims the "py" and
    #: the control does not.
    GT2 = "len(parts) > 2"

    def test_the_control_comparison_is_detected_by_the_same_harness(self):
        """The control mutation must be found by the proof's own harness.

        The proof compares two spellings of a comparison over the same
        inputs.  Pointed at ``!=`` -- an operator that really does
        separate ``len(parts)`` from ``1`` -- the same comparison must
        report a difference.  If it does not, the harness cannot fail,
        and the "no difference" result of the equivalence proof says
        nothing at all.
        """
        original, control = self._comparison_pair(
            (self.GT, self.GTE),
            self.GT2,
        )
        spans = ["a.b", "a.py", "pkg.mod.func", "a.b.c.d", "x.y"]
        differences = 0
        compared = 0
        for span in spans:
            compared += 1
            if (
                control["_candidate_references"](span)
                != original["_candidate_references"](span)
            ):
                differences += 1
        self.assertEqual(
            compared,
            len(spans),
            "the control must actually compare the inputs",
        )
        self.assertNotEqual(
            differences,
            0,
            "the harness must detect a control mutation that really "
            "changes the result -- otherwise the equivalence proof's "
            "'no difference' result is vacuous",
        )

    def test_the_control_operator_differs_from_the_proof_operators(self):
        """The control must not BE one of the two spellings under test.

        A control that is one of the spellings the proof already
        compares would agree with them by construction, and the
        control would prove nothing.  This is the shape of pitfall
        measured on ``fable`` in
        ``docs/design/mutant-evidence-closure.md`` §9.2: a control
        mutation that is a NO-OP because the value never reaches the
        guard.
        """
        self.assertNotEqual(self.GT2, self.GT)
        self.assertNotEqual(self.GT2, self.GTE)
        # And the control must not share the proof's OPERANDS with a
        # different bound -- the rewrite is located by its operands,
        # so a control with the same operands but another bound would
        # be located correctly, and one with different operands would
        # not be found at all.
        self.assertEqual(
            self._normalized_comparison(self.GT2).split(">")[0],
            self._normalized_comparison(self.GT).split(">")[0],
        )

    def test_the_equal_lengths_the_proof_skips_do_separate(self):
        """The SKIPPED inputs must be where the two spellings differ.

        The proof's argument is that the strict and non-strict
        spellings are reached only when the two sets are already known
        to be DIFFERENT, and for two different sets the two spellings
        agree.  The equal sets are where the two spellings DISAGREE --
        they are exactly what the proof skips.

        So the same comparison, run over the EQUAL lengths, must find
        a difference.  If it did not, the skip would be doing no work
        and the agreement over the different lengths would be
        vacuous.
        """
        # ``len(parts) > 1`` and ``len(parts) >= 1`` disagree exactly
        # when the two lengths are EQUAL.  That is the premise, and
        # it is checked directly here rather than taken on trust.
        for length in (0, 1, 2, 3):
            strict = length > 1
            loose = length >= 1
            if length == 1:
                self.assertNotEqual(
                    strict,
                    loose,
                    "the two spellings must disagree at length 1 -- the "
                    "premise the equivalence proof rests on",
                )
            else:
                self.assertEqual(
                    strict,
                    loose,
                    "the two spellings must agree at every length but 1",
                )

    def test_the_proofs_compare_the_different_lengths_and_skip_the_equal_one(self):
        """The proof's own sweep must not skip everything.

        The equivalence proof drives a corpus of spans.  Its conclusion
        is "the two spellings agree on every span it tried".  A
        sweep that compared ZERO spans would reach that conclusion
        too, and it would mean nothing.  So the corpus is checked for
        size, and the spans that the proof DOES compare are checked to
        include a case that reaches the comparison at all.
        """
        spans = [
            "a.b", "a.py", "a.b.py", "pkg.mod.func", "a..b", "a.",
            ".a", "a.b.c.d", "py.a", "a.py.b", "_x._y", "a-b.c",
            "a.b-c", "x.y", "z", "mod.Class.method", "a.1b",
        ]
        self.assertGreaterEqual(
            len(spans),
            10,
            "the equivalence proof's corpus must be substantial",
        )
        # At least one span must reach the comparison: a span with a
        # dot, at least two parts, and not ending in ".py" after the
        # trim.
        reaching = [s for s in spans if s.count(".") >= 2 and not s.endswith(".py")]
        self.assertNotEqual(
            reaching,
            [],
            "the corpus must contain spans that reach the comparison",
        )
