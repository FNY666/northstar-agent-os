"""A slice's 3/3 claim must not rest on a suite that ran NO tests.

THE DEFECT (measured 2026-11-22)
--------------------------------
§2's table in ``docs/design/mutant-evidence-closure.md`` claims **3/3**
for sixty-one slices: three of the module's first mutable constructs were
planted and the slice's own suite caught all three.

Two of those rows were **false**:

| slice | table says | measured | its first three constructs |
|---|---|---|---|
| `agent-handoff` | 3/3 | **0/3** | `gt@214` `gt@226` `gt@236` all SURVIVED |
| `c58` | 3/3 | **0/3** | `gt@127` `retT@128` `gt@129` all SURVIVED |

Both suites are **pytest-style**: ``tests/test_agent_handoff.py`` holds
40 standalone ``test_*`` functions and no ``TestCase`` class at all.
unittest's loader collects **zero** tests from such a file and exits 5
("NO TESTS RAN"), and the probe of the day read any non-zero exit as
"the mutant was KILLED".  So the whole 3/3 was manufactured by a suite
that ran nothing -- and it pointed the *stronger* way, so nothing else
in the census could have caught it.

Measured on the same trees, with the same probes:

| slice | old census (unittest) | fixed probe (pytest) |
|---|---|---|
| `agent-handoff` | 38/38 | **22/38** |
| `c58` | 63/63 | **70/115** |
| `slice3` | 63/63 | **70/115** |
| `slice4` | 4/4 | **3/4** |
| `toolfail` | 11/11 | **10/11** |
| `lightningzero` | 24/24 | **12/24** |
| `slice5` | 13/13 | 13/13 |

The `c58` row also shows the second half of the defect: the old probe
saw **63** constructs where there are **115**, because it stopped
counting at a different point.  The false kill was not only in the
verdict; it was in the denominator too.

`slice5` is the one that does **not** fall, and it is the control: the
defect was the *runner*, not the slices.  Where the fixed probe still
reads perfect, the per-construct verdicts confirm the listed constructs
really were killed -- so the old number was a fact about the runner, not
an excuse for the slice.

WHAT THIS TEST PINS
--------------------
For a slice whose suite unittest cannot collect a single test from, the
table's k/3 claim must agree with the **per-construct verdicts** of the
re-measurement.  A suite that ran zero tests cannot have caught
anything, so its 3/3 is not evidence of coverage -- and the check is
by unittest's OWN loader (the authority the old probe used), not by a
heuristic about the file's text.

The measurement lives outside the repository (it is expensive), so the
test SKIPS when it is absent rather than failing -- but it reports what
it skipped.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
RUNTIME_DIR = REPO_ROOT / "components" / "northstar-agent-runtime"
CLOSURE_DOC = REPO_ROOT / "docs" / "design" / "mutant-evidence-closure.md"

#: The re-measurement artifact for the unittest-blind rows.  One line
#: per slice:
#:   <slug> MUTANT <kind>@<n> <VERDICT> (...);MUTANT RESULT: killed k/n; ...
#:
#: The coordinator's copy comes FIRST and the checkout-local copy second:
#: the coordinator's copy is the freshest, and re-measuring is the
#: coordinator's decision.  The checkout-local copy is what makes the
#: check runnable on a CI runner -- measured 2026-11-22, a runner had
#: none of the coordinator's artifacts, and the check FAILED (it did not
#: skip) because a blind suite's 3/3 claim had nothing behind it.
MEASUREMENT_CANDIDATES = (
    Path("/home/muse-newapi/k3-blind-rows.txt"),
    REPO_ROOT / "docs" / "baseline" / "mutant-census" / "k3-blind-rows.txt",
)

#: The same re-measurement, taken at each slice's OWN pinned commit.
#: It is authoritative where it covers a slice, because a pinned commit's
#: line numbers are the ones §2's table lists.
PIN_MEASUREMENT_CANDIDATES = (
    Path("/home/muse-newapi/k3-bash-pins.txt"),
    REPO_ROOT / "docs" / "baseline" / "mutant-census" / "k3-bash-pins.txt",
)

#: The slice census artifact (the old, unittest-runner census).
OLD_CENSUS_CANDIDATES = (
    Path("/home/muse-newapi/census-parallel.txt"),
    REPO_ROOT / "docs" / "baseline" / "mutant-census" / "census-parallel.txt",
)


def _first_present(candidates) -> Path | None:
    """The first candidate that exists, or ``None``.

    An absent measurement is a SKIP for the caller, never a crash and
    never a silent pass: these checks compare a claim against a
    measurement, and with no measurement there is nothing to compare --
    which is a different fact from "the claim agrees".
    """
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None

#: A §2 table row: ``| `slug` | `module.py` | `test_x.py` | **k/n** | ...``
ROW_RE = re.compile(
    r"^\| `(?P<slug>[^`]+)` \| `(?P<module>[^`]+)` \| `(?P<test>[^`]+)` \| "
    r"\*\*(?P<pinned>\d+)/(?P<pinned_n>\d+)\*\* \|"
)

#: A verdict: ``killed 22/38``.
RESULT_RE = re.compile(r"killed (\d+)/(\d+)")

#: A construct name: ``gt@214``.
SITE_RE = re.compile(r"\b(eq|gt|lt|retT|retF|and|or)@(\d+)\b")


def _table_rows(doc_text: str) -> dict[str, dict[str, str]]:
    """§2's rows: ``{slug: {module, test, pinned, constructs}}``.

    The *constructs* are the last column: the mutants that were planted,
    by kind and line number.  They are what the k/3 claim is about.
    """
    start = doc_text.find("## 2.")
    if start < 0:
        return {}
    end = doc_text.find("## 3.", start)
    if end < 0:
        end = len(doc_text)
    rows: dict[str, dict[str, str]] = {}
    for line in doc_text[start:end].splitlines():
        match = ROW_RE.match(line)
        if not match:
            continue
        cells = [c.strip() for c in line.split("|")]
        # The constructs are the LAST cell before the trailing empty one.
        constructs = cells[-2] if len(cells) >= 2 else ""
        rows[match.group("slug")] = {
            "module": match.group("module"),
            "test": match.group("test"),
            "pinned": f"{match.group('pinned')}/{match.group('pinned_n')}",
            "constructs": constructs,
        }
    return rows


def _verdicts(path: Path) -> dict[str, dict[str, str]]:
    """``{slug: {"site": "VERDICT"}}`` from a census-shaped artifact."""
    if not path.exists():
        return {}
    out: dict[str, dict[str, str]] = {}
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


def _measured(path: Path) -> dict[str, str]:
    """``{slug: "k/n"}`` from a census-shaped artifact."""
    if not path.exists():
        return {}
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if not parts:
            continue
        match = RESULT_RE.search(line)
        if match:
            out[parts[0]] = f"{match.group(1)}/{match.group(2)}"
    return out


def _unittest_collected_counts() -> dict[str, int]:
    """``{test module stem: number of tests unittest collects}``.

    Measured by **unittest's own loader**, which is the authority the old
    probe used.  A file whose loader count is zero is one the old runner
    could not see at all.

    The key is the module's stem **with** its ``test_`` prefix
    (``test_agent_handoff``), because that is the name the loader is
    asked for.
    """
    import unittest as _unittest

    collected: dict[str, int] = {}
    for path in sorted((RUNTIME_DIR / "tests").glob("test_*.py")):
        stem = path.stem
        loader = _unittest.TestLoader()
        try:
            count = loader.loadTestsFromName(stem).countTestCases()
        except Exception:  # noqa: BLE001 - a suite that cannot load sees nothing
            count = 0
        collected[stem] = count
    return collected


class UnittestBlindSliceTests(unittest.TestCase):
    """A 3/3 claim must rest on a suite that actually ran."""

    def setUp(self):
        if not CLOSURE_DOC.exists():
            self.skipTest(f"closure doc missing: {CLOSURE_DOC}")
        self.doc = CLOSURE_DOC.read_text(encoding="utf-8")
        self.rows = _table_rows(self.doc)
        self.measurement = _first_present(MEASUREMENT_CANDIDATES)
        self.verdicts = _verdicts(self.measurement) if self.measurement else {}
        self.measured = _measured(self.measurement) if self.measurement else {}

    def _blind_slices(self) -> set[str]:
        """The slices whose suite unittest collects nothing from."""
        collected = _unittest_collected_counts()
        out = set()
        for slug, row in self.rows.items():
            test = row["test"]
            if not test.startswith("test_") or not test.endswith(".py"):
                continue
            if collected.get(test[:-3], 1) == 0:
                out.add(slug)
        return out

    def _all_verdicts(self) -> dict[str, dict[str, str]]:
        """The per-construct verdicts of every re-measurement.

        The pinned measurement is authoritative where it covers a slice:
        it was taken at the slice's OWN pinned commit, which is the tree
        §2's column describes.
        """
        out: dict[str, dict[str, str]] = {}
        for candidates in (PIN_MEASUREMENT_CANDIDATES, MEASUREMENT_CANDIDATES):
            path = _first_present(candidates)
            if path is None:
                continue
            for slug, sites in _verdicts(path).items():
                out.setdefault(slug, {}).update(sites)
        return out

    def test_the_table_agrees_with_the_per_construct_verdicts(self):
        """The rule: the k/3 claim must follow the constructs' verdicts.

        For every slice the re-measurement covers, the table's k/3 must
        equal the number of the listed constructs that were KILLED.
        This is the check that catches a false 3/3: `agent-handoff`'s
        three listed constructs all SURVIVED, so its claim must not be
        3/3.

        **A row whose listed constructs the measurement does not know is
        not comparable and is skipped.**  §2's last column names the
        mutants planted *at the slice's pinned commit*, and a pinned
        commit's line numbers are not HEAD's: `slice3` and `c58` both
        probe ``bash_parser.py``, but `slice3`'s row lists ``gt@117``
        (its pin) while `c58`'s lists ``gt@127`` (HEAD's).  Comparing a
        pinned construct against a HEAD measurement would report a
        difference that is only a line-number shift.
        """
        if not self.verdicts:
            self.skipTest(
                "measurement artifact not available: "
                + ", ".join(str(p) for p in MEASUREMENT_CANDIDATES)
            )
        wrong = []
        compared = 0
        for slug, sites in sorted(self.verdicts.items()):
            row = self.rows.get(slug)
            if row is None:
                continue
            listed = [f"{k}@{n}" for k, n in SITE_RE.findall(row["constructs"])]
            if not listed:
                continue
            # Only compare what the measurement actually measured.
            known = [site for site in listed if site in sites]
            if len(known) != len(listed):
                continue
            compared += 1
            killed = sum(1 for site in known if sites[site] == "KILLED")
            expected = f"{killed}/{len(known)}"
            if row["pinned"] != expected:
                wrong.append(
                    f"{slug}: table says {row['pinned']}, the constructs "
                    f"{' '.join(known)} measure {expected}"
                )
        self.assertTrue(
            compared,
            "no row's listed constructs were measured, so the comparison "
            "is vacuous",
        )
        self.assertEqual(
            wrong, [],
            "§2's table disagrees with the per-construct verdicts:\n  "
            + "\n  ".join(wrong),
        )

    def test_a_blind_suites_claim_must_be_backed_by_a_measurement(self):
        """A suite that ran ZERO tests cannot have caught anything.

        This is the rule stated directly, independent of the numbers: if
        unittest collects no test from the slice's suite, then a 3/3
        measured *against that suite by the unittest runner* is not
        evidence -- it is the exit code.

        A blind suite **may** legitimately carry 3/3 if a re-measurement
        with a runner that CAN see the suite says so.  `slice5` is
        exactly that case: `test_blind_rerunner.py` is pytest-style, and
        the fixed probe confirms 13/13.  So the rule is not "no blind
        suite may claim 3/3" -- it is "**no blind suite may claim 3/3
        without a measurement behind it**".
        """
        blind = self._blind_slices()
        verdicts = self._all_verdicts()
        # With NO measurement at all, every blind 3/3 claim is
        # "unbacked" -- which would report the absence of a measurement
        # as a finding about the slices.  Measured 2026-11-22: on a
        # simulated CI runner this test FAILED with "these slices claim
        # 3/3 ... and no re-measurement backs the claim", listing three
        # slices that were fine.  "The measurement is not here" is not
        # "the claim is unbacked".
        if not verdicts:
            self.skipTest(
                "re-measurement artifact not available: "
                + ", ".join(
                    str(p)
                    for p in PIN_MEASUREMENT_CANDIDATES
                    + MEASUREMENT_CANDIDATES
                )
            )
        unbacked = []
        for slug in sorted(blind):
            row = self.rows.get(slug)
            if row is None or row["pinned"] != "3/3":
                continue
            sites = verdicts.get(slug)
            listed = [f"{k}@{n}" for k, n in SITE_RE.findall(row["constructs"])]
            if not sites or not listed:
                unbacked.append(slug)
                continue
            known = [site for site in listed if site in sites]
            if len(known) != len(listed):
                unbacked.append(slug)
                continue
            killed = sum(1 for site in known if sites[site] == "KILLED")
            if killed != len(listed):
                unbacked.append(slug)
        self.assertEqual(
            unbacked, [],
            "these slices claim 3/3 against a suite unittest collected "
            "nothing from, and no re-measurement backs the claim: "
            + ", ".join(unbacked),
        )

    def test_the_measured_rows_differ_from_the_old_census(self):
        """The re-measurement must be READY to differ from the old census.

        If the two agree exactly, the measurement is not measuring
        anything -- it would be a copy of the artifact it is checking.
        """
        if not self.measured:
            self.skipTest(
                "measurement artifact not available: "
                + ", ".join(str(p) for p in MEASUREMENT_CANDIDATES)
            )
        old_census = _first_present(OLD_CENSUS_CANDIDATES)
        if old_census is None:
            self.skipTest(
                "old census artifact not available: "
                + ", ".join(str(p) for p in OLD_CENSUS_CANDIDATES)
            )
        old = _measured(old_census)
        shared = sorted(set(old) & set(self.measured))
        self.assertTrue(shared, "the two artifacts share no slice")
        differing = [s for s in shared if old[s] != self.measured[s]]
        self.assertTrue(
            differing,
            "every re-measured slice matches the old census exactly, so the "
            "re-measurement is not measuring anything",
        )

    def test_the_old_perfect_scores_were_the_false_kills(self):
        """The shape of the finding: the old numbers were all-or-nothing.

        Every unittest-blind row the old census reported was a perfect
        score -- 38/38, 63/63, 4/4, 11/11.  A perfect score from a suite
        that ran zero tests is not a measurement; it is the exit code.

        Five of the six fall under the fixed probe.  The sixth, `slice5`,
        does **not** fall -- and that is the point of pinning it here:
        the finding is about the *runner*, not about the slices.  Where
        the fixed probe still reads perfect, the per-construct verdicts
        must confirm that the listed constructs really were killed, so
        "the old number was perfect" is a fact about the runner rather
        than an excuse for the slice.
        """
        if not self.measured:
            self.skipTest(
                "measurement artifact not available: "
                + ", ".join(str(p) for p in MEASUREMENT_CANDIDATES)
            )
        old_census = _first_present(OLD_CENSUS_CANDIDATES)
        if old_census is None:
            self.skipTest(
                "old census artifact not available: "
                + ", ".join(str(p) for p in OLD_CENSUS_CANDIDATES)
            )
        old = _measured(old_census)
        blind = self._blind_slices()
        perfect_old = {
            slug: old[slug]
            for slug in self.measured
            if slug in old
            and old[slug].split("/")[0] == old[slug].split("/")[1]
            and int(old[slug].split("/")[1]) > 1
        }
        self.assertTrue(
            perfect_old,
            "no re-measured slice had a perfect score under the old census",
        )
        verdicts = self._all_verdicts()
        still_perfect = []
        for slug, value in sorted(perfect_old.items()):
            if slug not in blind:
                continue
            if value == self.measured.get(slug):
                still_perfect.append(slug)
        # Every old perfect score on a blind suite must have been
        # re-measured; and those that stay perfect must be CONFIRMED by
        # the per-construct verdicts.
        for slug in still_perfect:
            row = self.rows.get(slug)
            sites = verdicts.get(slug)
            self.assertIsNotNone(
                row, f"{slug} still reads perfect and has no table row"
            )
            self.assertIsNotNone(
                sites, f"{slug} still reads perfect and no measurement "
                "confirms it",
            )
            listed = [
                f"{k}@{n}" for k, n in SITE_RE.findall(row["constructs"])
            ]
            known = [site for site in listed if site in sites]
            self.assertEqual(
                len(known),
                len(listed),
                f"{slug} still reads perfect but its listed constructs "
                f"{listed} are not all measured",
            )
            for site in known:
                self.assertEqual(
                    sites[site],
                    "KILLED",
                    f"{slug} still reads perfect but {site} "
                    f"{sites[site]}",
                )


if __name__ == "__main__":
    unittest.main()
