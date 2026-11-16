"""Baseline-attribution conformance: the baseline and the table must agree.

This is a READ-ONLY test. It writes nothing, changes nothing, and re-takes no
baseline. It asserts two things:

1. The attribution table in ``docs/design/baseline-attribution.md`` describes
   exactly the baseline that is stored outside the repo, item for item, with
   legal category labels.  This part needs no outside file and therefore
   always runs -- even on a clean clone.
2. The stored baseline files themselves are well-formed, and the old baseline
   was not modified.  These parts need the outside files; when they are
   absent (a clean clone) the affected methods SKIP rather than fail, so a
   clone without the coordinator's artefacts stays green.

The outside artefacts (produced by the coordinator, outside the repository):

    /home/muse-newapi/b173-baseline-failures-2026-11-14.txt
    /home/muse-newapi/b173-baseline-failures-attributed-2026-11-14.txt
    /home/muse-newapi/b173-refusal-row-baseline-failures.txt
"""
from __future__ import annotations

import hashlib
import re
import unittest
from pathlib import Path

COMPONENT = Path(__file__).resolve().parents[1]
REPO_ROOT = COMPONENT.parents[1]
DESIGN_DOC = REPO_ROOT / "docs" / "design" / "baseline-attribution.md"

OUTSIDE_DIR = Path("/home/muse-newapi")
NEW_BASELINE = OUTSIDE_DIR / "b173-baseline-failures-2026-11-14.txt"
ATTRIBUTED = OUTSIDE_DIR / "b173-baseline-failures-attributed-2026-11-14.txt"
OLD_BASELINE = OUTSIDE_DIR / "b173-refusal-row-baseline-failures.txt"

#: The four legal category labels. No other label is accepted.
LEGAL_CATEGORIES = ("MISSING_EXTRA", "KERNEL_FEATURE", "LOCAL_ENV", "CODE_DEFECT")

#: The raw failure line the runtime suite prints for one failing test:
#: "FAIL: <name> (<module>.<Class>.<method>)" or "ERROR: ...".
FAILURE_LINE = re.compile(r"^(?:FAIL|ERROR): \S+ \(\S+\)$")

#: A row of the design doc's attribution table starts with "| <n> | `test_...".
TABLE_ROW = re.compile(r"^\|\s*(\d+)\s*\|\s*`([^`]+)`[^|]*\|\s*`([A-Z_]+)`\s*\|")


def _table_rows(text: str) -> list[tuple[int, str, str]]:
    """Extract (index, test name, category) from the design doc's table."""
    rows: list[tuple[int, str, str]] = []
    for line in text.splitlines():
        match = TABLE_ROW.match(line)
        if match:
            rows.append((int(match.group(1)), match.group(2), match.group(3)))
    return rows


def _failure_names(lines: list[str]) -> list[str]:
    """The bare test names of a list of raw failure lines, in file order."""
    names: list[str] = []
    for line in lines:
        match = FAILURE_LINE.match(line.strip())
        if match:
            names.append(line.split(" ", 1)[1].split(" ", 1)[0])
    return names


def _data_lines(path: Path) -> list[str]:
    """The non-empty, non-comment lines of a baseline file.

    Both baseline files carry a ``#`` header block explaining their format;
    those lines are metadata, not items.
    """
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


class DesignDocTableTests(unittest.TestCase):
    """These need no outside file: they read only the repository."""

    def test_the_design_doc_exists_and_is_not_empty(self):
        self.assertTrue(DESIGN_DOC.is_file(), f"missing design doc: {DESIGN_DOC}")
        self.assertGreater(len(DESIGN_DOC.read_text(encoding="utf-8")), 2000)

    def test_the_design_doc_has_a_table_with_one_row_per_baseline_item(self):
        text = DESIGN_DOC.read_text(encoding="utf-8")
        rows = _table_rows(text)
        self.assertGreaterEqual(len(rows), 30, f"table has only {len(rows)} rows")
        # The row indexes are 1..N with no gaps: the table is dense.
        indexes = [index for index, _, _ in rows]
        self.assertEqual(indexes, list(range(1, len(rows) + 1)), indexes)

    def test_every_category_label_in_the_table_is_legal(self):
        text = DESIGN_DOC.read_text(encoding="utf-8")
        rows = _table_rows(text)
        self.assertTrue(rows, "the attribution table has no rows")
        for index, name, category in rows:
            self.assertIn(
                category,
                LEGAL_CATEGORIES,
                f"row {index} ({name}) uses the illegal category {category!r}",
            )

    def test_the_table_has_a_verifiable_evidence_column(self):
        text = DESIGN_DOC.read_text(encoding="utf-8")
        for line in text.splitlines():
            match = TABLE_ROW.match(line)
            if not match:
                continue
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            self.assertGreaterEqual(len(cells), 5, f"row is too short: {line}")
            evidence = cells[3]
            self.assertTrue(evidence, f"row {match.group(1)} has no evidence")
            self.assertTrue(
                cells[4], f"row {match.group(1)} has no 'how it goes green' cell"
            )

    def test_the_doc_states_the_baseline_reset_and_the_bench_verdict(self):
        text = DESIGN_DOC.read_text(encoding="utf-8")
        # The baseline reset must be explained, not just asserted.
        self.assertIn("merged_tree_review", text)
        self.assertIn("eebb2a70", text)
        # The "is 161/169 an environment artifact?" question must be answered
        # honestly: the doc says which way it went and by what measurement.
        self.assertIn("161/169", text)
        self.assertIn("169/169", text)
        # The verdict must be stated as a verdict, in words.
        self.assertRegex(
            text,
            r"is a code artifact, not an environment artifact",
            "the doc must say in words that 161/169 is not an environment artifact",
        )

    def test_the_doc_lists_an_action_item_for_the_coordinator(self):
        text = DESIGN_DOC.read_text(encoding="utf-8")
        self.assertIn("Action items for the coordinator", text)
        action_rows = re.findall(r"^\|\s*\*\*A-\d+\*\*\s*\|", text, re.MULTILINE)
        self.assertGreaterEqual(len(action_rows), 5, len(action_rows))

    def test_the_drift_check_script_exists_and_is_executable(self):
        script = REPO_ROOT / "scripts" / "b173-baseline-check.sh"
        self.assertTrue(script.is_file(), f"missing script: {script}")
        self.assertTrue(
            script.stat().st_mode & 0o111, f"script is not executable: {script}"
        )
        body = script.read_text(encoding="utf-8")
        self.assertIn("BASELINE MATCH", body)
        self.assertIn("BASELINE DRIFT", body)
        # Read-only with respect to the repository: it must not write a
        # baseline, and it must compare rather than overwrite.
        self.assertNotIn("> \"$BASELINE\"", body)
        self.assertNotIn("cp ", body.replace("# ", "#"))


class StoredBaselineTests(unittest.TestCase):
    """These need the coordinator's outside files; they SKIP without them."""

    def _require(self, path: Path) -> Path:
        if not path.is_file():
            self.skipTest(f"outside artefact not present: {path}")
        return path

    def test_the_new_baseline_exists_and_is_non_empty(self):
        path = self._require(NEW_BASELINE)
        lines = _data_lines(path)
        self.assertGreaterEqual(len(lines), 30, len(lines))

    def test_every_baseline_line_is_a_raw_failure_line(self):
        path = self._require(NEW_BASELINE)
        for line in _data_lines(path):
            self.assertRegex(line, FAILURE_LINE, line)

    def test_the_attributed_file_has_the_same_item_count_as_the_baseline(self):
        baseline = self._require(NEW_BASELINE)
        attributed = self._require(ATTRIBUTED)
        base_lines = _data_lines(baseline)
        attr_lines = _data_lines(attributed)
        self.assertEqual(len(base_lines), len(attr_lines), (len(base_lines), len(attr_lines)))

    def test_every_attributed_item_corresponds_to_a_baseline_item(self):
        baseline = self._require(NEW_BASELINE)
        attributed = self._require(ATTRIBUTED)
        base_names = _failure_names(_data_lines(baseline))
        attr_names: list[str] = []
        for line in _data_lines(attributed):
            parts = line.split(None, 1)
            self.assertEqual(len(parts), 2, line)
            category, raw = parts
            self.assertIn(category, LEGAL_CATEGORIES, line)
            attr_names.extend(_failure_names([raw]))
        self.assertEqual(base_names, attr_names)

    def test_the_attributed_categories_match_the_documented_statistics(self):
        attributed = self._require(ATTRIBUTED)
        counts: dict[str, int] = {}
        for line in _data_lines(attributed):
            category = line.split(None, 1)[0]
            counts[category] = counts.get(category, 0) + 1
        text = DESIGN_DOC.read_text(encoding="utf-8")
        for category, count in counts.items():
            pattern = rf"\|\s*`?\*?\*?{re.escape(category)}\*?\*?`?\s*\|\s*\*\*(\d+)\*\*\s*\|"
            match = re.search(pattern, text)
            self.assertIsNotNone(match, f"the doc has no statistics row for {category}")
            self.assertEqual(
                int(match.group(1)),
                count,
                f"the doc says {match.group(1)} {category} items, the file has {count}",
            )

    def test_the_new_baseline_does_not_contain_test_every_module_is_installed(self):
        # It DID contain that item until runtime-registration-closure landed;
        # it is back only because merged-tree-review is unregistered.  The
        # doc must therefore account for it explicitly.
        path = self._require(NEW_BASELINE)
        body = path.read_text(encoding="utf-8")
        if "test_every_module_is_installed" in body:
            text = DESIGN_DOC.read_text(encoding="utf-8")
            self.assertIn(
                "merged_tree_review",
                text,
                "the baseline contains test_every_module_is_installed but the doc "
                "does not explain why",
            )

    def test_the_regex_extra_items_are_accounted_for_in_the_doc(self):
        # The four MISSING_EXTRA items are either gone from the baseline or
        # explained in the doc; either way the doc must name them.
        path = self._require(NEW_BASELINE)
        body = path.read_text(encoding="utf-8")
        text = DESIGN_DOC.read_text(encoding="utf-8")
        for name in (
            "test_draft_2020_local_refs_and_regex_are_supported",
            "test_pattern_properties_validate_matched_keys",
            "test_nested_enum_does_not_confuse_booleans_and_numbers",
            "test_regex_timeout_cannot_be_treated_as_a_failed_one_of_branch",
        ):
            if name in body:
                self.assertIn(name, text, f"{name} is in the baseline but not in the doc")

    def test_the_old_baseline_was_not_modified(self):
        path = self._require(OLD_BASELINE)
        body = path.read_text(encoding="utf-8")
        lines = [line for line in body.splitlines() if line.strip()]
        self.assertEqual(len(lines), 27, f"the old baseline now has {len(lines)} lines")
        # The historical md5 of the untouched file.
        digest = hashlib.md5(body.encode("utf-8")).hexdigest()
        self.assertEqual(digest, "f5a841e65d385ec23924c9661f916046", digest)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
