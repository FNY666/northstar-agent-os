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

THE VERDICT DEFECT (measured 2026-11-22)
------------------------------------------
A census line names EVERY mutant it planted -- the survivors AND the
kills -- and the word ``SURVIVED`` appears in the line for either.  A
line filter of "the line mentions SURVIVED" therefore collects the
**killed** sites too, and reports a site as a survivor when the probe
killed it.  Measured: a corrected census row for ``agent-handoff`` names
38 sites, 13 of them SURVIVED, and reading the whole line reported all
38 as survivors -- 25 phantom findings.

So a site name is read **with its verdict**, and only the ``SURVIVED``
ones are collected.

THE PROOF-LOOKUP DEFECT (measured 2026-11-22)
-----------------------------------------------
A site name is relative to its module: ``or@45`` is a line number in
whichever module the row names.  Searching every test file for the bare
name therefore finds a *different* module's proof and calls it covered.
The lookup is now **row-scoped**: the proof must be in the test file the
census row itself names.

WHAT THIS TEST PINS
--------------------
Every site the census reports as SURVIVED must be accounted for:
either a row in §9.1's table (an equivalence proof) or a killer test in
the suite the census row names.  The census artifact lives outside the
repository, so the test skips when it is absent -- but it does not skip
silently: it reports what it skipped.
"""

from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
RUNTIME_DIR = REPO_ROOT / "components" / "northstar-agent-runtime"
CLOSURE_DOC = REPO_ROOT / "docs" / "design" / "mutant-evidence-closure.md"

#: The census artifacts, each with the SCOPE it is read at.  The scope
#: is not a detail: a diff between the table and a census of a different
#: scope is meaningless, and the failure looks exactly like a finding.
#:
#: * ``scope="slice"`` -- one row per slice (the batch's own
#:   deliveries).  This is the scope §9.1's table describes.
#: * ``scope="module"`` -- one row per module in the component.  It
#:   reaches modules no slice ever touched, so it reports many more
#:   survivor sites, and it is NOT what the table is diffed against.
CENSUS_CANDIDATES = (
    ("slice", Path("/home/muse-newapi/census-parallel-corrected.txt")),
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

#: A site name **with its verdict**: ``eq@387 SURVIVED``.
VERDICT_SITE_RE = re.compile(
    r"\b(eq|gt|lt|retT|retF|and|or)@(\d+)\s+(SURVIVED|KILLED|SKIP)\b"
)

#: A §2 table row: ``| `slug` | `module.py` | `test_x.py` | ... |``.
SLICE_MODULE_RE = re.compile(
    r"^\| `(?P<slug>[^`]+)` \| `(?P<module>[^`]+)` \|"
)

#: The backticked names inside a table cell.  A cell may name several
#: entities -- `` `c58` / `slice3` `` -- and the cell's own outer
#: backticks do not wrap the whole cell, so the names must be extracted
#: rather than the cell de-quoted and split.
_SLUG_CELL_RE = re.compile(r"`([^`]+)`")

#: The stripped source of each file already parsed, keyed by its text.
_STRIPPED_CACHE: dict[str, str] = {}


def _strip_comments(source: str) -> str:
    """The source with its **comments** removed.

    A proof is code that names the site.  A **comment** that names the
    site is a note about the site -- it is not attached to any test, so
    it is not evidence that the site is covered.  A **docstring** is
    kept: a docstring is the documentation of the test it documents, so
    a test that says "``lt@701``: the boundary, and why the mutant is
    equivalent" does name its site in the place where the proof lives.

    The strip is done by **re-parsing and unparsing**: the AST holds no
    comments, so unparsing drops them while keeping everything else --
    including docstrings, which are ordinary string statements in the
    tree.  A line filter would instead remove a comment that trails a
    code line's tail, or leave a docstring's body behind.

    If the file does not parse, the source is returned **unchanged** --
    and the caller sees the comments, which is the old (lax) behaviour.
    That fallback is deliberate and is not silent: :func:`_suite_text`
    is only ever handed a file the suite itself ran.

    The result is **cached by source text**: the caller searches one
    stripped file for every site, and re-parsing per site made the
    check quadratic in the number of test files.
    """
    cached = _STRIPPED_CACHE.get(source)
    if cached is not None:
        return cached
    try:
        tree = ast.parse(source)
    except SyntaxError:
        result = source
    else:
        try:
            result = ast.unparse(tree)
        except Exception:
            result = source
    _STRIPPED_CACHE[source] = result
    return result

#: A census row's module/test pair: ``(a/b/mod.py / a/b/tests/test_x.py)``.
CENSUS_PAIR_RE = re.compile(r"\(([^()]*\.py)\s*/\s*([^()]*\.py)\)")


def _site_regex(site: str) -> re.Pattern[str]:
    """A matcher for a site name in either spelling.

    §3.4 names a test method after the mutant it kills, and the name
    it prescribes is ``test_or_at_127_...`` -- the **underscore**
    spelling.  The census spells the same site ``or@127``.  A proof
    lookup that accepted only one of them would either miss every
    §3.4-conforming test or match a different site.
    """
    kind, _, number = site.partition("@")
    return re.compile(
        rf"(?<![A-Za-z0-9]){re.escape(kind)}(?:@{re.escape(number)}"
        rf"|_at_{re.escape(number)})(?![0-9])"
    )


def _table_sites(doc_text: str) -> set[str]:
    """The site names in §9.1's table."""
    return {site for _slug, sites in _table_rows(doc_text).items() for site in sites}


def _table_rows(doc_text: str) -> dict[str, set[str]]:
    """``{slice: {site names}}`` from §9.1's table.

    The table's rows are keyed by SLUG, and the slug is what makes a
    site name unambiguous: ``or@45`` in ``slice4``'s row is
    ``alert_trigger_registry.py``'s line 45, and a bare search across
    the whole table would let one row's site satisfy another's.
    """
    start = doc_text.find("### 9.1")
    if start < 0:
        return {}
    end = doc_text.find("### 9.2", start)
    if end < 0:
        end = len(doc_text)
    section = doc_text[start:end]
    out: dict[str, set[str]] = {}
    for row in section.splitlines():
        if not row.startswith("| `"):
            continue
        cells = [c.strip() for c in row.strip().strip("|").split("|")]
        if len(cells) < 2:
            continue
        # One row may name TWO slugs (`diviner` / `scope-verb-canonical`
        # -- the same module, censused under two names).  The row's
        # sites belong to BOTH, and the census rows for the two are two
        # rows naming the same sites, so the lookup must find the row
        # under either name.
        #
        # The cell is parsed by EXTRACTING its backticked names, not by
        # splitting it on a separator.  The cell reads
        # `` `c58` / `slice3` ``, so the outer backticks are around the
        # FIRST name and the LAST: stripping them from the whole cell
        # leaves ``c58` / `slice3`` and splitting that on " / " leaves
        # ``c58` `` and ``` ``slice3`` -- keys no census slug ever
        # matches.  The equivalence row for those nine sites was
        # therefore unreachable, and the check passed only because the
        # sites happened to be satisfied by its second branch.
        slugs = _SLUG_CELL_RE.findall(cells[0])
        if not slugs:
            continue
        sites = {f"{m}@{n}" for m, n in SITE_RE.findall(cells[1])}
        if sites:
            for s in slugs:
                out.setdefault(s, set()).update(sites)
    return out


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
        pair = CENSUS_PAIR_RE.search(line)
        if pair:
            module = Path(pair.group(1)).name
            out.setdefault(module[:-3], line.split(" ", 1)[0])
    return out


def _census_rows(census_text: str) -> list[dict[str, object]]:
    """The census's rows, each with its slug, module, suite and sites.

    Only the sites that actually **SURVIVED** are collected.  A census
    line names every mutant it planted -- the survivors AND the kills --
    so a line filter of "the line mentions SURVIVED" is not enough: the
    line also carries the KILLED sites, and including those would report
    a site as a survivor when the probe killed it.

    This was not a hypothetical: a corrected census row for
    `agent-handoff` names 38 sites and 13 of them SURVIVED, and reading
    the whole line would report all 38 as survivors.
    """
    rows: list[dict[str, object]] = []
    for line in census_text.splitlines():
        if "SURVIVED" not in line:
            continue
        slug = line.split(" ", 1)[0]
        pair = CENSUS_PAIR_RE.search(line)
        module = test = ""
        if pair:
            module = Path(pair.group(1)).name
            test = Path(pair.group(2)).name
        else:
            # The MODULE census keys its rows by the module's own name
            # (``agent_handoff``), not by a slice slug, and only names
            # the pair in some rows.  Fall back to the row's own key.
            module = f"{slug}.py"
        survivors = {
            f"{m}@{n}"
            for m, n, verdict in VERDICT_SITE_RE.findall(line)
            if verdict == "SURVIVED"
        }
        all_sites = {
            f"{m}@{n}" for m, n, _verdict in VERDICT_SITE_RE.findall(line)
        }
        rows.append(
            {
                "slug": slug,
                "module": module,
                "test": test,
                "survivors": survivors,
                "sites": all_sites,
            }
        )
    return rows


def _survivor_sites_by_module(census_text: str) -> dict[str, set[str]]:
    """``{module stem: {site names}}`` for the census's surviving rows.

    Verdict-filtered -- see :func:`_census_rows` for why the line
    filter alone is not enough.
    """
    out: dict[str, set[str]] = {}
    for row in _census_rows(census_text):
        module = str(row["module"])
        if not module:
            continue
        stem = module[:-3] if module.endswith(".py") else module
        out.setdefault(stem, set()).update(row["survivors"])  # type: ignore[arg-type]
    return out


class EquivalenceTableCoverageTests(unittest.TestCase):
    """§9.1's table must cover every site the census reports."""

    def setUp(self):
        if not CLOSURE_DOC.exists():
            self.skipTest(f"closure doc missing: {CLOSURE_DOC}")
        self.doc = CLOSURE_DOC.read_text(encoding="utf-8")
        self.table = _table_sites(self.doc)
        self.rows = _table_rows(self.doc)
        # The batch's scope: the modules §9.1's table describes, unioned
        # with the modules the slice census names.  Either source alone
        # is incomplete -- §2's table has rows with no module (``fable``)
        # and the census names modules §2's table does not -- and the
        # union is what the scope filter needs.
        self.slice_modules = dict(_slice_modules(self.doc))
        for module, slug in _slice_census_modules().items():
            self.slice_modules.setdefault(module, slug)

    # -- helpers --------------------------------------------------------

    def _census_text(self) -> str:
        census_path = _census_path()
        if census_path is None:
            self.skipTest(
                "census artifact not available: "
                + ", ".join(str(c) for _scope, c in CENSUS_CANDIDATES)
            )
        return census_path[1].read_text(encoding="utf-8")

    def _suite_text(self, name: str) -> str:
        """The **code** of a suite named by a census row.

        The lookup is **row-scoped**: the proof for a site must be in the
        suite the census row itself names.  A bare search across every
        test file would let one module's proof satisfy another module's
        site -- and a site name is relative to its module, so that is a
        false proof, not a lax one.

        The text is returned with its **comments stripped**.  A proof is
        code that names the site; a comment that names the site is a note
        about the site, and matching it proves nothing.  Measured: the
        nine bash_parser ``lt`` sites appear in ``test_bash_parser.py``
        only inside comments (the proof itself is the parametrized
        ``EQUIVALENT_LT_SITES`` table, whose ids are ``lt_at_{line}``),
        so nine of the table's twenty-six sites had a comment-only
        proof.  The check read them as proven.
        """
        for candidate in (
            RUNTIME_DIR / "tests" / name,
            REPO_ROOT / "tests" / name,
        ):
            if candidate.exists():
                return _strip_comments(
                    candidate.read_text(encoding="utf-8", errors="replace")
                )
        return ""

    # -- the checks -----------------------------------------------------

    def test_the_table_is_not_empty(self):
        self.assertTrue(self.table, "§9.1's table parsed to no sites")

    def test_every_census_slug_has_a_reachable_table_row(self):
        """A row nobody can look up is not a row.

        §9.1's table spells a multi-slug row's cell as
        `` `c58` / `slice3` `` -- the outer backticks are around the
        FIRST name and the LAST, not around the cell.  Parsing that cell
        by stripping its outer backticks and splitting it on ``" / "``
        leaves the keys ``c58` `` and ``` ``slice3``: a trailing
        backtick, and a leading backtick-space.  No census slug ever
        matches those, so the equivalence row for those nine sites was
        **unreachable** -- and the coverage check still passed, because
        the sites happened to be satisfied by its second branch (a
        killer test) rather than its first (the equivalence row).

        So the keys are checked against the slugs the census actually
        uses.  A row whose key is not a census slug is a row nobody can
        reach.
        """
        census_text = self._census_text()
        rows = _census_rows(census_text)
        self.assertTrue(rows, "the census artifact carries no rows at all")
        unreachable = []
        for row in rows:
            slug = str(row["slug"])
            if slug not in self.rows:
                unreachable.append(slug)
        self.assertEqual(
            sorted(set(unreachable)), [],
            "census slugs with no reachable §9.1 table row: "
            f"{sorted(set(unreachable))}",
        )

    def test_the_table_row_for_a_multi_slug_cell_names_every_slug(self):
        """The multi-slug rows must land under BOTH of their names.

        This is the row-level restatement of the check above: the
        ``c58`` / ``slice3`` row carries nine sites, and the census has
        two rows (one per name) that both report those nine as
        survivors.  If only one of the names resolved, one of the two
        census rows would fall back to the killer-test branch and the
        equivalence proof would be invisible for it.
        """
        for slug, expected in (
            ("c58", {"lt@547", "lt@552", "lt@557", "lt@620", "lt@686",
                     "lt@690", "lt@709", "lt@756", "lt@773"}),
            ("slice3", {"lt@547", "lt@552", "lt@557", "lt@620", "lt@686",
                        "lt@690", "lt@709", "lt@756", "lt@773"}),
        ):
            self.assertEqual(
                self.rows.get(slug, set()), expected,
                f"§9.1's table row for {slug} does not resolve to its "
                f"nine `lt` sites",
            )

    def test_a_comment_is_not_a_proof(self):
        """The proof must be code, and this check says so.

        ``_strip_comments`` removes the comments from a suite before the
        site is searched for.  Without it, a note in a comment that
        names a site counts as a proof of that site: the nine
        bash_parser ``lt`` sites were named only in
        ``test_bash_parser.py``'s comments, and the check read them as
        proven.

        So the strip has to actually strip, and the stripped text has
        to lose a site that only a comment mentioned.
        """
        commented = (
            "def test_x():\n"
            "    # lt@999 -- a note about the site\n"
            "    assert True\n"
        )
        stripped = _strip_comments(commented)
        self.assertNotIn(
            "lt@999", stripped,
            "a site named only in a comment survived the strip",
        )
        self.assertIn(
            "assert True", stripped,
            "the strip removed the code along with the comment",
        )
        # A docstring is the documentation of the test it documents, so
        # a site named in one IS named by that test's code.
        documented = (
            "def test_y():\n"
            '    """`lt@998`: the boundary."""\n'
            "    assert True\n"
        )
        self.assertIn(
            "lt@998", _strip_comments(documented),
            "the strip removed a docstring, which is a test's own text",
        )

    def test_every_table_site_has_a_proof_in_a_test_file(self):
        """A row without a proof is a claim; a claim needs evidence.

        The search is over the files' **code**, with comments and
        docstrings stripped.  A comment that names a site is a note
        about the site, not a test of it: the nine bash_parser ``lt``
        sites were named only in ``test_bash_parser.py``'s comments,
        and this check read them as proven.

        The name may be spelled either way -- ``lt@547`` or
        ``lt_at_547`` -- because §3.4 prescribes the underscore
        spelling for a test method's name.
        """
        missing = []
        for site in sorted(self.table):
            found = False
            for test_file in list(RUNTIME_DIR.glob("tests/test_*.py")) + \
                    list(REPO_ROOT.glob("tests/test_*.py")):
                code = _strip_comments(
                    test_file.read_text(encoding="utf-8", errors="replace")
                )
                if _site_regex(site).search(code):
                    found = True
                    break
            if not found:
                missing.append(site)
        self.assertEqual(
            missing, [],
            f"§9.1's table names sites with no proof in any test file: {missing}",
        )

    def test_the_census_carries_per_site_verdicts(self):
        """The non-vacuity guard.

        The check above reads only the sites a census row marks
        ``SURVIVED``.  If the artifact carried no per-site verdicts, that
        set would be empty and the check would pass vacuously -- the
        same failure mode as a count check that compares the wrong
        number.

        So the artifact must actually name the mutants it planted.  The
        threshold is a floor on the ARTIFACT's detail, not on the number
        of survivors: after the survivors are killed, a census row still
        names every mutant it planted.
        """
        census_text = self._census_text()
        rows = _census_rows(census_text)
        with_verdicts = [r for r in rows if r["sites"]]
        self.assertGreaterEqual(
            len(with_verdicts), 5,
            "the census artifact names per-site verdicts for fewer than "
            f"five rows ({len(with_verdicts)}); the survivor check would "
            "be vacuous",
        )
        named = sum(len(r["sites"]) for r in with_verdicts)  # type: ignore[arg-type]
        self.assertGreaterEqual(
            named, 50,
            f"the census artifact names only {named} sites in total; the "
            "survivor check would be vacuous",
        )

    def test_every_census_site_has_a_row_or_a_killer(self):
        """Every surviving site must be accounted for, one way or the other.

        There are TWO kinds of proof for a surviving mutant, and a site
        needs only one of them:

        * a row in §9.1's table -- an equivalence proof with a non-vacuity
          control, for a mutant that genuinely cannot be killed;
        * a killer test -- a test that observes the difference, for a
          mutant that can be killed.

        So the check is NOT "every survivor is in the table".  That was
        the old shape, and it was wrong twice over: it demanded an
        equivalence proof for sites that have a perfectly good killer
        test, and it had no notion of the row a site belongs to.

        The census is read at the **slice** scope, which is the scope
        §9.1's table describes.  A module-scope census is filtered down
        to the batch's own modules first -- see
        ``test_a_module_scope_census_is_filtered_to_the_batch_scope``.
        """
        census_text = self._census_text()
        rows = _census_rows(census_text)
        self.assertTrue(rows, "the census artifact carries no rows at all")
        missing = []
        for row in rows:
            slug = str(row["slug"])
            table_sites = self.rows.get(slug, set())
            suite = self._suite_text(str(row["test"]))
            for site in sorted(row["survivors"]):  # type: ignore[arg-type]
                if site in table_sites:
                    continue
                if suite and _site_regex(site).search(suite):
                    continue
                missing.append(f"{slug}:{site}")
        self.assertEqual(
            missing, [],
            "surviving census sites with no equivalence row and no killer "
            f"test: {missing}",
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
