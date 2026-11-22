"""The equivalence-record table must cover every site the census reports.

THE DEFECT (measured 2026-11-22)
--------------------------------
``docs/design/mutant-evidence-closure.md`` §9.1 carries a table with one
row per equivalent-mutant site, and the section itself prescribes the
check: *"extract the site names from the table, extract them from the
census, and diff"*.  Two of the three times that enumeration was short,
the diff is what found it.

Running the diff produced a NON-EMPTY result:

    census only:  lt@701  or@504
    table only:   eq@494  gt@451

The first line is the defect.  ``durable-resume``'s ``lt@701`` and
``cancellation-gate``'s ``or@504`` had full differential proofs with
non-vacuity controls, and **no row in §9.1's table**.  The second line
is not a defect: ``merged-tree-review``'s census row reads ``ERROR``,
so the census cannot see ``gt@451`` and ``eq@494`` at all.

What made this the *worst* kind of gap is that the COUNTS matched.  The
census reports 15 distinct survivor sites; the table carried 15 sites --
but a **different** 15.  A count check would have passed.  Only the
**set** diff found it.

WHAT THIS TEST PINS
--------------------
Every site the census reports must have a row in §9.1's table, and
every site in the table must have a proof in some test file.  The
census artifact lives outside the repository, so the test skips when it
is absent -- but it does not skip silently: it reports what it skipped.

The census cannot see ``merged-tree-review``, so the table is allowed to
carry sites the census does not.  The test therefore checks the census's
sites are a SUBSET of the table's, not that the two are equal -- and it
checks the table's every site has a proof, which is what catches the
table drifting away from the proofs.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
RUNTIME_DIR = REPO_ROOT / "components" / "northstar-agent-runtime"
CLOSURE_DOC = REPO_ROOT / "docs" / "design" / "mutant-evidence-closure.md"

#: The census artifact.  It lives outside the repository -- it is the
#: referee's run over every slice -- so this test skips when it is
#: absent rather than failing.
CENSUS = Path("/home/muse-newapi/census-parallel.txt")

#: A site name: ``eq@387``, ``gt@451`` and so on.
SITE_RE = re.compile(r"\b(eq|gt|lt|retT|retF|and|or)@(\d+)\b")


def _table_sites(doc_text: str) -> set[str]:
    """The site names in §9.1's table."""
    start = doc_text.find("### 9.1")
    if start < 0:
        return set()
    end = doc_text.find("### 9.2", start)
    if end < 0:
        end = len(doc_text)
    section = doc_text[start:end]
    # Only the TABLE's rows, not the prose around it.
    rows = [ln for ln in section.splitlines() if ln.startswith("| `")]
    return {f"{m}@{n}" for row in rows for m, n in SITE_RE.findall(row)}


def _census_sites(census_text: str) -> set[str]:
    """The distinct survivor sites the census reports."""
    return {
        f"{m}@{n}"
        for m, n in SITE_RE.findall(census_text)
        if True
    }


class EquivalenceTableCoverageTests(unittest.TestCase):
    """§9.1's table must cover every site the census reports."""

    def setUp(self):
        if not CLOSURE_DOC.exists():
            self.skipTest(f"closure doc missing: {CLOSURE_DOC}")
        self.doc = CLOSURE_DOC.read_text(encoding="utf-8")
        self.table = _table_sites(self.doc)

    def test_the_table_is_not_empty(self):
        self.assertTrue(self.table, "§9.1's table parsed to no sites")

    def test_every_table_site_has_a_proof_in_a_test_file(self):
        """A row without a proof is a claim; a claim needs evidence."""
        missing = []
        for site in sorted(self.table):
            found = False
            for test_file in list(RUNTIME_DIR.glob("tests/test_*.py")) + \
                    list(REPO_ROOT.glob("tests/test_*.py")):
                if site in test_file.read_text(encoding="utf-8", errors="replace"):
                    found = True
                    break
            if not found:
                missing.append(site)
        self.assertEqual(
            missing, [],
            f"§9.1's table names sites with no proof in any test file: {missing}",
        )

    def test_every_census_site_has_a_row_in_the_table(self):
        """The census's sites must be a SUBSET of the table's.

        The table is allowed to carry sites the census cannot see --
        ``merged-tree-review``'s census row reads ``ERROR``, so
        ``gt@451`` and ``eq@494`` are invisible to it.  The reverse is
        not allowed: a census site with no row is a site whose proof is
        not recorded.
        """
        if not CENSUS.exists():
            self.skipTest(f"census artifact not available: {CENSUS}")
        census_text = CENSUS.read_text(encoding="utf-8")
        census = {
            f"{m}@{n}"
            for line in census_text.splitlines()
            if "SURVIVED" in line
            for m, n in SITE_RE.findall(line)
        }
        self.assertTrue(census, "the census artifact reports no survivors")
        missing = sorted(census - self.table)
        self.assertEqual(
            missing, [],
            f"census sites with no row in §9.1's table: {missing}",
        )

    def test_the_table_covers_the_sites_the_census_cannot_see(self):
        """``merged-tree-review`` reads ``ERROR`` in the census.

        Its two sites are therefore invisible to the diff above, and
        they must be in the table anyway -- they are the reason the
        table is a superset rather than an equality.
        """
        for site in ("gt@451", "eq@494"):
            self.assertIn(
                site, self.table,
                f"{site} is missing from §9.1's table; the census cannot "
                "see it, so nothing else would catch the omission",
            )


if __name__ == "__main__":
    unittest.main()
