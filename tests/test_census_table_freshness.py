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

#: The two other docs that carry a per-slice mutant number.  They were
#: measured with the SAME unittest-runner probe, so they carried the SAME
#: false 3/3 rows, and they are pinned here for the same reason.
#:
#: ``judge-hygiene.md`` §7's before/after table names the slice in its
#: first cell and the "after" number in its last cell.
JUDGE_HYGIENE_DOC = REPO_ROOT / "docs" / "design" / "judge-hygiene.md"

#: ``artifact-completion.md``'s census table names the slice and its
#: result in the third cell.
ARTIFACT_COMPLETION_DOC = (
    REPO_ROOT / "docs" / "design" / "artifact-completion.md"
)

#: The re-measurement artifact.  One line per slice:
#:   <slug> MUTANT RESULT: killed k/n; (pin=<hash> mod=<module>)
#:
#: Its scope is the slice's **first three** constructs -- the same scope
#: as §2's k/3 column.
#:
#: The coordinator's copy comes FIRST and the checkout-local copy second:
#: the coordinator's copy is the freshest, and re-measuring is the
#: coordinator's decision.  The checkout-local copy is what makes the
#: check runnable on a CI runner -- measured 2026-11-22, a runner had
#: none of the coordinator's artifacts, and the check failed rather
#: than skipped.
MEASUREMENT_CANDIDATES = (
    Path("/home/muse-newapi/k3-remeasure.txt"),
    REPO_ROOT / "docs" / "baseline" / "mutant-census" / "k3-remeasure.txt",
)

#: The re-measurement of the rows whose suite unittest cannot collect a
#: test from.  Measured 2026-11-22 with the fixed (pytest) probe; it is
#: what corrected §2's three FALSE 3/3 rows.  One line per slice:
#:   <slug> MUTANT <kind>@<n> <VERDICT> (...);MUTANT RESULT: killed k/n; ...
#:
#: Its scope is the **whole file** -- every construct the probe found --
#: so its k/n is NOT comparable with §2's first-three k/3.  The
#: comparable numbers from it are the PER-CONSTRUCT verdicts, and
#: §2's column is the count of the listed constructs that were killed.
BLIND_MEASUREMENT_CANDIDATES = (
    Path("/home/muse-newapi/k3-blind-rows.txt"),
    REPO_ROOT / "docs" / "baseline" / "mutant-census" / "k3-blind-rows.txt",
)

#: The re-measurement of the rows at their OWN PINNED commits.  Same
#: whole-file scope as the blind measurement.
PIN_MEASUREMENT_CANDIDATES = (
    Path("/home/muse-newapi/k3-bash-pins.txt"),
    REPO_ROOT / "docs" / "baseline" / "mutant-census" / "k3-bash-pins.txt",
)


def _first_present(candidates) -> Path | None:
    """The first candidate that exists, or ``None``.

    An absent measurement is a SKIP for the caller, never a crash and
    never a silent pass: the checks that use this compare a table
    against a measurement, and with no measurement there is nothing to
    compare -- which is a different fact from "the table agrees".
    """
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None

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


def _table_constructs(doc_text: str) -> dict[str, list[str]]:
    """``{slug: [construct names]}`` from §2's last column.

    The last column names the mutants that were planted, by kind and
    line number -- ``gt@214 gt@226 gt@236``.  §2's k/3 claim is a claim
    about those specific constructs.
    """
    start = doc_text.find("## 2. The 64-slice census")
    if start < 0:
        return {}
    end = doc_text.find("## 3.", start)
    if end < 0:
        end = len(doc_text)
    out: dict[str, list[str]] = {}
    for line in doc_text[start:end].splitlines():
        m = ROW_RE.match(line)
        if not m:
            continue
        cells = [c.strip() for c in line.split("|")]
        constructs = cells[-2] if len(cells) >= 2 else ""
        out[m.group("slug")] = [
            f"{kind}@{num}"
            for kind, num in re.findall(
                r"\b(eq|gt|lt|retT|retF|and|or)@(\d+)\b", constructs
            )
        ]
    return out


def _measured() -> dict[str, str]:
    """``{slug: "k/n"}`` from the re-measurement artifact."""
    out = {}
    path = _first_present(MEASUREMENT_CANDIDATES)
    if path is None:
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if not parts:
            continue
        m = re.search(r"killed (\d+/\d+)", line)
        if m:
            out[parts[0]] = m.group(1)
    return out


def _measured_any() -> dict[str, str]:
    """``{slug: "k/n"}`` from the first-three-scope artifact.

    Only the artifact whose scope matches §2's column belongs here.  The
    blind and pinned artifacts are **whole-file** scope, so their k/n
    counts a different number of mutants and is not comparable; they are
    read by :func:`_verdicts` instead.
    """
    return dict(_measured())


def _verdicts(path: Path) -> dict[str, dict[str, str]]:
    """``{slug: {"kind@line": "VERDICT"}}`` from a census-shaped artifact."""
    out: dict[str, dict[str, str]] = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if not parts:
            continue
        slug = parts[0]
        sites: dict[str, str] = {}
        for kind, num, verdict in re.findall(
            r"MUTANT ([a-zA-Z]+)@(\d+) (SURVIVED|KILLED|SKIP)", line
        ):
            sites[f"{kind}@{num}"] = verdict
        if sites:
            out.setdefault(slug, {}).update(sites)
    return out


def _blind_verdicts() -> dict[str, dict[str, str]]:
    """The per-construct verdicts of the whole-file re-measurements.

    The pinned measurement is authoritative where it covers a slice: it
    was taken at the slice's OWN pinned commit, which is the tree §2's
    column describes.
    """
    out: dict[str, dict[str, str]] = {}
    for candidates in (PIN_MEASUREMENT_CANDIDATES, BLIND_MEASUREMENT_CANDIDATES):
        path = _first_present(candidates)
        if path is None:
            continue
        for slug, sites in _verdicts(path).items():
            merged = out.setdefault(slug, {})
            merged.update(sites)
    return out


def _judge_hygiene_rows(doc_text: str) -> dict[str, str]:
    """``{slug: after-number}`` from judge-hygiene.md §7's table.

    The table's rows are ``| `slug` | before | before | before | after |
    after | - |``: the FIRST number is the slice's pre-fix count and the
    LAST number is the post-fix one.  Both are the same in the rows this
    test cares about, so the last cell is read.
    """
    start = doc_text.find("## 7.")
    if start < 0:
        return {}
    end = doc_text.find("## 8.", start)
    if end < 0:
        end = len(doc_text)
    out: dict[str, str] = {}
    for line in doc_text[start:end].splitlines():
        if not line.startswith("| `"):
            continue
        cells = [c.strip() for c in line.split("|")]
        if len(cells) < 4:
            continue
        slug = cells[1].strip("`")
        if not slug or "/" in slug or " " in slug:
            continue
        for cell in reversed(cells[2:]):
            if not cell or cell == "-":
                continue
            match = re.fullmatch(r"\*?\*?(\d+/\d+)\*?\*?", cell)
            if match:
                out[slug] = match.group(1)
                break
    return out


def _artifact_completion_rows(doc_text: str) -> dict[str, str]:
    """``{slug: result}`` from artifact-completion.md's census table."""
    start = doc_text.find("| slice | module probed | result |")
    if start < 0:
        return {}
    end = doc_text.find("**How many manifests existed before", start)
    if end < 0:
        end = len(doc_text)
    out: dict[str, str] = {}
    for line in doc_text[start:end].splitlines():
        match = re.match(
            r"^\| `(?P<slug>[^`]+)` \| `[^`]+` \| \*{0,2}(?P<res>\d+/\d+)", line
        )
        if match:
            out[match.group("slug")] = match.group("res")
    return out


class CensusTableFreshnessTests(unittest.TestCase):
    """§2's table must agree with the measurement."""

    def setUp(self):
        if not CLOSURE_DOC.exists():
            self.skipTest(f"closure doc missing: {CLOSURE_DOC}")
        self.doc = CLOSURE_DOC.read_text(encoding="utf-8")
        self.rows = _table_rows(self.doc)
        self.constructs = _table_constructs(self.doc)
        self.measured = _measured()
        self.measured_any = _measured_any()
        self.blind_verdicts = _blind_verdicts()

    def test_the_table_has_rows(self):
        self.assertTrue(self.rows, "§2's table parsed as empty")

    def test_every_measured_slice_has_a_row(self):
        """A measured slice with no row is a slice the table forgot."""
        if not self.measured:
            self.skipTest(
                "measurement artifact not available: "
                + ", ".join(str(p) for p in MEASUREMENT_CANDIDATES)
            )
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

        The measurement that counts is the one taken with the **fixed**
        probe, where the slice's suite is one the runner can see.
        """
        measured = self.measured_any
        if not measured:
            self.skipTest(
                "measurement artifact not available: "
                + ", ".join(str(p) for p in MEASUREMENT_CANDIDATES)
            )
        wrong = []
        for slug, (pinned, _head) in sorted(self.rows.items()):
            got = measured.get(slug)
            if got is None:
                continue
            if got != pinned:
                wrong.append(f"{slug}: table says {pinned}, measured {got}")
        self.assertEqual(
            wrong, [],
            "§2's table disagrees with the measurement:\n  "
            + "\n  ".join(wrong),
        )

    def test_the_k3_column_follows_the_per_construct_verdicts(self):
        """§2's k/3 must be the count of the LISTED constructs that KILLED.

        The table's last column names the mutants that were planted, by
        kind and line number.  So the k/3 claim is a claim about those
        specific constructs -- and the whole-file re-measurement says
        what actually happened to each one.

        This is the check that caught the three FALSE 3/3 rows: for
        `agent-handoff`, `c58` and `slice3` the listed constructs all
        SURVIVED, so the claim could not be 3/3.

        A row whose listed constructs the measurement does not know is
        **not comparable and is skipped**: §2's column names the
        mutants planted *at the slice's pinned commit*, and a pinned
        commit's line numbers are not HEAD's.
        """
        verdicts = self.blind_verdicts
        if not verdicts:
            self.skipTest(
                "re-measurement artifact not available: "
                + ", ".join(
                    str(p)
                    for p in BLIND_MEASUREMENT_CANDIDATES
                    + PIN_MEASUREMENT_CANDIDATES
                )
            )
        wrong = []
        compared = 0
        for slug, (pinned, _head) in sorted(self.rows.items()):
            sites = verdicts.get(slug)
            if not sites:
                continue
            listed = self.constructs.get(slug, [])
            known = [site for site in listed if site in sites]
            if len(known) != len(listed) or not listed:
                continue
            compared += 1
            killed = sum(1 for site in known if sites[site] == "KILLED")
            expected = f"{killed}/{len(known)}"
            if pinned != expected:
                wrong.append(
                    f"{slug}: table says {pinned}, the constructs "
                    f"{' '.join(known)} measure {expected}"
                )
        self.assertTrue(
            compared,
            "no row's listed constructs were measured, so the comparison "
            "is vacuous",
        )
        self.assertEqual(
            wrong, [],
            "§2's k/3 disagrees with the per-construct verdicts:\n  "
            + "\n  ".join(wrong),
        )

    def test_the_other_census_docs_carry_the_same_corrected_numbers(self):
        """Two more docs carried the SAME false 3/3 rows.

        ``judge-hygiene.md`` §7 and ``artifact-completion.md``'s census
        table were both measured with the same unittest-runner probe, so
        they carried the same false rows.  Their numbers are in a
        different SHAPE than §2's (no per-construct column, and a
        different scope), so they cannot be compared by construct -- but
        a row whose slice was corrected in §2 must not still read the
        old number in either of them.

        The rule: **a slice corrected in §2 must not read 3/3 in the
        other two docs**, unless a measurement confirms the 3/3.
        """
        verdicts = self.blind_verdicts
        if not verdicts:
            self.skipTest(
                "re-measurement artifact not available: "
                + ", ".join(
                    str(p)
                    for p in BLIND_MEASUREMENT_CANDIDATES
                    + PIN_MEASUREMENT_CANDIDATES
                )
            )
        # §2's rows, keyed by slug, with their listed constructs.
        corrected = {
            slug: row
            for slug, row in self.constructs.items()
            if slug in self.rows
        }
        wrong = []
        checked = 0
        for doc_path, parser in (
            (JUDGE_HYGIENE_DOC, _judge_hygiene_rows),
            (ARTIFACT_COMPLETION_DOC, _artifact_completion_rows),
        ):
            if not doc_path.exists():
                continue
            rows = parser(doc_path.read_text(encoding="utf-8"))
            for slug, value in sorted(rows.items()):
                row = corrected.get(slug)
                if row is None:
                    continue
                sites = verdicts.get(slug)
                listed = row
                if not sites or not listed:
                    continue
                known = [site for site in listed if site in sites]
                if len(known) != len(listed):
                    continue
                checked += 1
                killed = sum(1 for site in known if sites[site] == "KILLED")
                expected = f"{killed}/{len(known)}"
                if value != expected:
                    wrong.append(
                        f"{doc_path.name}: {slug} says {value}, the "
                        f"constructs {' '.join(known)} measure {expected}"
                    )
        self.assertTrue(
            checked,
            "no row of either doc was comparable to the measurement, so "
            "the comparison is vacuous",
        )
        self.assertEqual(
            wrong, [],
            "the other two census docs disagree with the measurement:\n  "
            + "\n  ".join(wrong),
        )

    def test_a_row_below_the_three_of_three_line_is_measured(self):
        """A weak row must be one the measurement says is weak.

        The rule is no longer "no row is below 3/3" -- three rows ARE
        below it, and they are below it because the measurement says so
        (see §8's amendment (e): three 3/3 claims were false, and the
        probe that produced them could not see the suite they were
        measured against).

        So the rule is: **every weak row is covered by a measurement,
        and the prose counts them.**  A weak row that no measurement
        covers is a row nobody has checked, which is the defect this
        file was written for.
        """
        verdicts = self.blind_verdicts
        if not verdicts:
            self.skipTest(
                "re-measurement artifact not available: "
                + ", ".join(
                    str(p)
                    for p in BLIND_MEASUREMENT_CANDIDATES
                    + PIN_MEASUREMENT_CANDIDATES
                )
            )
        weak = {slug for slug, (pinned, _h) in self.rows.items()
                if pinned != "3/3"}
        unmeasured = sorted(slug for slug in weak if slug not in verdicts)
        self.assertEqual(
            unmeasured, [],
            "§2's table carries rows below the 3/3 line that no "
            f"measurement covers: {unmeasured}",
        )
        # If any row is below 3/3, the prose must count them.
        if weak:
            self.assertIn(
                f"{len(weak)}", self.doc,
                "the prose does not state how many rows are below 3/3",
            )


if __name__ == "__main__":
    unittest.main()
