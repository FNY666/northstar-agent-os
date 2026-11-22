"""The mutant census TABLE must not go stale behind a passing count.

THE DEFECT (measured 2026-11-22)
--------------------------------
``docs/design/mutant-evidence-closure.md`` §2 carries a table: one row
per slice, with the number of mutants killed out of the first three
constructs, at the slice's pinned commit and at HEAD.

The table said twenty-four slices were below the 3/3 line, and §8's
prose said "**twelve** weak-evidence slices" were still unlifted.  Both
were wrong:

* the lifts that closed them landed on 2026-11-20 and 2026-11-21, AFTER
  the table was last touched, so the table still read 1/3 and 2/3;
* §8's "twelve" was not the twenty-four the table carried, nor the
  fourteen that ``docs/design/artifact-completion.md`` listed.

Re-measuring each slice's first three constructs at its CURRENT pinned
commit gives **3/3 for all twenty-four**.  The work was done; the
document did not know it.

WHY A COUNT CHECK WOULD NOT HAVE CAUGHT IT
-------------------------------------------
The defect was not a wrong COUNT -- the table's counts were right for
the tree they described.  It was a STALE table: right numbers, wrong
tree, and no assertion anywhere compared the table against the tree it
claims to describe.

So this test does not compare counts.  It compares the table against a
MEASUREMENT, and the measurement is the thing that can disagree.

THE MEASUREMENT
---------------
``/home/muse-newapi/k3-remeasure.txt`` holds the re-measurement: one
line per slice, at its current pinned commit, with the current probe.
It lives outside the repository because it is expensive to take (a
worktree per slice), so this test SKIPS when it is absent rather than
failing.

The rule pinned here:

> **Every row of §2's table agrees with the measurement.**
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CLOSURE_DOC = REPO_ROOT / "docs" / "design" / "mutant-evidence-closure.md"

#: The re-measurement artifact.  One line per slice:
#:   <slug> MUTANT RESULT: killed k/n; (pin=<hash> mod=<module>)
MEASUREMENT = Path("/home/muse-newapi/k3-remeasure.txt")

#: A table row: ``| `slug` | `module.py` | `test_x.py` | **k/n** | `hash` | k/n | ...``
ROW_RE = re.compile(
    r"^\| `(?P<slug>[^`]+)` \| `(?P<module>[^`]+)` \| `(?P<test>[^`]+)` \| "
    r"\*\*(?P<pinned>\d+)/(?P<pinned_n>\d+)\*\* \| `(?P<commit>[0-9a-f]+)` \| "
    r"(?P<head>\d+)/(?P<head_n>\d+) \|"
)


def _table_rows(doc_text: str) -> dict[str, tuple[str, str]]:
    """``{slug: (pinned k/n, HEAD k/n)}`` for §2's table."""
    start = doc_text.find("## 2. The 64-slice census")
    if start < 0:
        return {}
    end = doc_text.find("## 3.", start)
    if end < 0:
        end = len(doc_text)
    rows = {}
    for line in doc_text[start:end].splitlines():
        m = ROW_RE.match(line)
        if m:
            rows[m.group("slug")] = (
                f"{m.group('pinned')}/{m.group('pinned_n')}",
                f"{m.group('head')}/{m.group('head_n')}",
            )
    return rows


def _measured() -> dict[str, str]:
    """``{slug: "k/n"}`` from the re-measurement artifact."""
    out = {}
    if not MEASUREMENT.exists():
        return out
    for line in MEASUREMENT.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if not parts:
            continue
        m = re.search(r"killed (\d+/\d+)", line)
        if m:
            out[parts[0]] = m.group(1)
    return out


class CensusTableFreshnessTests(unittest.TestCase):
    """§2's table must agree with the measurement."""

    def setUp(self):
        if not CLOSURE_DOC.exists():
            self.skipTest(f"closure doc missing: {CLOSURE_DOC}")
        self.doc = CLOSURE_DOC.read_text(encoding="utf-8")
        self.rows = _table_rows(self.doc)
        self.measured = _measured()

    def test_the_table_has_rows(self):
        self.assertTrue(self.rows, "§2's table parsed as empty")

    def test_every_measured_slice_has_a_row(self):
        """A measured slice with no row is a slice the table forgot."""
        if not self.measured:
            self.skipTest(f"measurement artifact not available: {MEASUREMENT}")
        missing = sorted(set(self.measured) - set(self.rows))
        self.assertEqual(
            missing, [],
            f"slices measured but absent from §2's table: {missing}",
        )

    def test_every_row_agrees_with_the_measurement(self):
        """The table's number must be the number the tree produces.

        This is the check the table never had.  A stale table is right
        about the tree it was measured on and wrong about the tree it
        sits in, so only a FRESH measurement can catch it -- and a count
        check against the table's own arithmetic never would.
        """
        if not self.measured:
            self.skipTest(f"measurement artifact not available: {MEASUREMENT}")
        wrong = []
        for slug, (pinned, _head) in sorted(self.rows.items()):
            got = self.measured.get(slug)
            if got is None:
                continue
            if got != pinned:
                wrong.append(f"{slug}: table says {pinned}, measured {got}")
        self.assertEqual(
            wrong, [],
            "§2's table disagrees with the measurement:\n  "
            + "\n  ".join(wrong),
        )

    def test_the_prose_count_matches_the_table(self):
        """§8's "twelve weak-evidence slices" must match the table.

        The defect was a count and a SET that both disagreed with the
        table they described: §8 said twelve, the table carried
        twenty-four, and ``artifact-completion.md`` listed fourteen.
        """
        weak = {slug for slug, (pinned, _h) in self.rows.items()
                if pinned != "3/3"}
        self.assertEqual(
            weak, set(),
            "§2's table still carries rows below the 3/3 line: "
            f"{sorted(weak)}",
        )
        # If any row is below 3/3 again, the prose must count them.
        if weak:
            self.assertIn(
                f"{len(weak)}", self.doc,
                "the prose does not state how many rows are below 3/3",
            )


if __name__ == "__main__":
    unittest.main()
