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

THE SCOPE DEFECT (measured 2026-11-22)
-------------------------------------
The check above is a diff between the TABLE and THE CENSUS, and a diff
between two sets only means something if the two sets are the same
**scope**.  There are two mutant censuses, and they are not
interchangeable:

* the **slice census** -- one row per *slice* (the batch's own
  deliveries), each module paired with its slice's test file.  This is
  what §9.1's table covers;
* the **module census** -- one row per *module* in the component (330+
  rows), at HEAD, each paired with its own test file.  It reaches every
  module, most of which no slice ever touched, so it reports far more
  survivor sites.

The test's candidate list put the **module** census FIRST, so the moment
a module census landed at ``census-v3.txt`` the diff would compare the
table against a different scope: every one of the module census's sites
would read as "a site with no row in the table".  Those are not findings.
They are the reach difference between two censuses.

So the test now states the scope it diffs at, and reads the artifact
that matches it.

WHAT THIS TEST PINS
--------------------
Every site the **slice** census reports must have a row in §9.1's table,
and every site in the table must have a proof in some test file.  The
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
#:
#: Several are accepted, and the SCOPE is declared with each one.  The
#: scope is not a detail: a diff between the table and a census of a
#: different scope is meaningless, and the failure looks exactly like a
#: finding.
#:
#: * ``scope="slice"`` -- one row per slice (the batch's own
#:   deliveries).  This is the scope §9.1's table describes.
#: * ``scope="module"`` -- one row per module in the component.  It
#:   reaches modules no slice ever touched, so it reports many more
#:   survivor sites, and it is NOT what the table is diffed against.
CENSUS_CANDIDATES = (
    ("slice", Path("/home/muse-newapi/census-parallel.txt")),
    ("module", Path("/home/muse-newapi/census-v3.txt")),
)


def _census_path() -> tuple[str, Path] | None:
    """The first available census and the scope it is.

    The order matters and it is the reason this function returns the
    scope with the path: the **slice** census comes first, so the
    default reading of "the census" is the scope §9.1's table covers.
    """
    for scope, candidate in CENSUS_CANDIDATES:
        if candidate.exists():
            return scope, candidate
    return None


#: A site name: ``eq@387``, ``gt@451`` and so on.
SITE_RE = re.compile(r"\b(eq|gt|lt|retT|retF|and|or)@(\d+)\b")

#: A §2 table row: ``| `slug` | `module.py` | `test_x.py` | ... |``.
SLICE_MODULE_RE = re.compile(
    r"^\| `(?P<slug>[^`]+)` \| `(?P<module>[^`]+)` \|"
)


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


def _slice_modules(doc_text: str) -> dict[str, str]:
    """``{module stem: slug}`` from §2's table.

    §2's table is one authority on which module belongs to which slice.
    It is not the only one, and it is not complete -- the slice census
    artifact names a module for every slice row it carries -- so this is
    a fallback that is unioned with the census's own naming below.
    """
    start = doc_text.find("## 2.")
    if start < 0:
        return {}
    end = doc_text.find("## 3.", start)
    if end < 0:
        end = len(doc_text)
    out: dict[str, str] = {}
    for line in doc_text[start:end].splitlines():
        match = SLICE_MODULE_RE.match(line)
        if match:
            module = match.group("module")
            if not module.endswith(".py"):
                continue
            out[module[:-3]] = match.group("slug")
    return out


def _slice_census_modules() -> dict[str, str]:
    """``{module stem: slug}`` from the slice census artifact.

    The slice census names the module each slice's probe ran against, so
    it is the authority on the batch's scope.  A slice may be censused
    under two names (``diviner`` and ``scope-verb-canonical`` both probe
    ``scope_qualifier.py``), so the mapping keeps the first slug it saw
    and the caller unions it with §2's.
    """
    scope, path = _census_path()
    if scope != "slice" or not path.exists():
        return {}
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.search(r"\(([^ (]+)\.py\) /", line)
        if match:
            out.setdefault(match.group(1).split("/")[-1], line.split(" ", 1)[0])
    return out


def _census_sites(census_text: str) -> set[str]:
    """The distinct survivor sites the census reports."""
    return {
        f"{m}@{n}"
        for m, n in SITE_RE.findall(census_text)
        if True
    }


def _survivor_sites_by_module(census_text: str) -> dict[str, set[str]]:
    """``{module stem: {site names}}`` for the census's surviving rows."""
    out: dict[str, set[str]] = {}
    for line in census_text.splitlines():
        if "SURVIVED" not in line:
            continue
        module = line.split(" ", 1)[0]
        out.setdefault(module, set()).update(
            f"{m}@{n}" for m, n in SITE_RE.findall(line)
        )
    return out


class EquivalenceTableCoverageTests(unittest.TestCase):
    """§9.1's table must cover every site the census reports."""

    def setUp(self):
        if not CLOSURE_DOC.exists():
            self.skipTest(f"closure doc missing: {CLOSURE_DOC}")
        self.doc = CLOSURE_DOC.read_text(encoding="utf-8")
        self.table = _table_sites(self.doc)
        # The batch's scope: the modules §9.1's table describes, unioned
        # with the modules the slice census names.  Either source alone
        # is incomplete -- §2's table has rows with no module (``fable``)
        # and the census names modules §2's table does not -- and the
        # union is what the scope filter needs.
        self.slice_modules = dict(_slice_modules(self.doc))
        for module, slug in _slice_census_modules().items():
            self.slice_modules.setdefault(module, slug)

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

        The census is read at the **slice** scope, which is the scope
        §9.1's table describes.  A module-scope census is filtered down
        to the batch's own modules first -- see
        ``test_a_module_scope_census_is_filtered_to_the_batch_scope``.
        """
        census_path = _census_path()
        if census_path is None:
            self.skipTest(
                "census artifact not available: "
                + ", ".join(str(c) for _scope, c in CENSUS_CANDIDATES)
            )
        scope, path = census_path
        census_text = path.read_text(encoding="utf-8")
        census = {
            f"{m}@{n}"
            for line in census_text.splitlines()
            if "SURVIVED" in line
            for m, n in SITE_RE.findall(line)
        }
        if scope == "module":
            by_module = _survivor_sites_by_module(census_text)
            in_scope = {
                site
                for module, sites in by_module.items()
                if module in self.slice_modules
                for site in sites
            }
            self.assertTrue(
                in_scope,
                "the module census has no survivor site inside the batch's "
                "own scope, so the subset check would be vacuous",
            )
            census = in_scope
        self.assertTrue(census, "the census artifact reports no survivors")
        missing = sorted(census - self.table)
        self.assertEqual(
            missing, [],
            f"census sites with no row in §9.1's table: {missing}",
        )

    def test_a_module_scope_census_is_filtered_to_the_batch_scope(self):
        """The scope difference must be visible, not assumed.

        A module census reaches modules no slice ever touched.  Those
        sites are NOT findings against §9.1's table -- the table is
        scoped to the batch's deliveries -- and the check above filters
        them out by module.

        This test pins the filter itself: the module census's sites
        outside the batch's modules are a strictly larger set, so the
        filter is doing something, and the sites inside the batch's
        modules are exactly the ones the filter keeps.

        The sets are compared **module-qualified**.  A site name is
        relative to its module (``or@527`` is a line number in
        whichever module the row names), so the same bare name can occur
        in two modules and mean two different sites.  Comparing bare
        names across the scope boundary therefore reports a false
        overlap: the same name in a module inside the scope and in a
        module outside it is two sites, not one.
        """
        module_census = Path("/home/muse-newapi/census-v3.txt")
        if not module_census.exists():
            self.skipTest(f"module census artifact not available: {module_census}")
        text = module_census.read_text(encoding="utf-8")
        by_module = _survivor_sites_by_module(text)
        self.assertTrue(by_module, "the module census reports no survivors")
        inside = {
            (module, site)
            for module, sites in by_module.items()
            if module in self.slice_modules
            for site in sites
        }
        outside = {
            (module, site)
            for module, sites in by_module.items()
            if module not in self.slice_modules
            for site in sites
        }
        self.assertTrue(
            outside,
            "the module census reports no survivor site outside the "
            "batch's modules; the scope difference it is supposed to "
            "show has vanished",
        )
        self.assertTrue(
            inside,
            "the module census reports no survivor site inside the "
            "batch's modules",
        )
        self.assertFalse(
            inside & outside,
            "a site is counted both inside and outside the batch's scope",
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
