"""The census scope must be the UNION of every suite that references a module.

``scripts/b173-census-all.sh`` pairs each module with a test scope before
asking the probe whether a planted fault is noticed.  If that scope is too
narrow, a mutant that a sibling suite DOES catch is reported as SURVIVED --
a false accusation of a weak test suite, the mirror image of the
stale-bytecode false kill.

Measured 2026-11-25 on ``job_queue.py``:

    its own suite alone   killed 43/85   (42 survivors)
    the four-suite union  killed 76/85   (9 survivors)

Twenty-nine of the narrow scope's "survivors" were caught by the sibling
suites.  The union scope is the one that is true.

This test pins the resolver's DEFINITION, which is the part that can go
wrong quietly:

* "references" means a real IMPORT, read from the AST -- not a grep.  Two
  suites mention ``job_queue.py`` in prose and import it in neither; a
  grep-based scope counts them and measures suites that do not exercise
  the module at all.
* the module's own suite comes FIRST, so a census log is comparable
  between runs.
* a module with no referencing suite resolves to the empty scope, and the
  census script SKIPs it rather than falling back to an arbitrary suite.
"""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "census-scope.py"
RUNTIME = ROOT / "components" / "northstar-agent-runtime"

SPEC = importlib.util.spec_from_file_location("census_scope", SCRIPT)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - repository corruption
    raise RuntimeError(f"cannot load {SCRIPT}")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class CensusScopeTests(unittest.TestCase):
    """The scope the real component resolves to."""

    def test_job_queue_resolves_to_the_four_suite_union(self) -> None:
        # These four are the suites docs/design/refusal-hold-wiring.md
        # §22.1 names as the scope for `job_queue.py`, and the scope the
        # 76/85 measurement was taken at.
        self.assertEqual(
            MODULE.referencing_suites(RUNTIME, "job_queue"),
            [
                "test_job_queue",
                "test_leased_task_claim",
                "test_refusal_hold",
                "test_refusal_hold_queue_wiring",
            ],
        )

    def test_a_prose_mention_is_not_a_reference(self) -> None:
        # `test_graph_database.py` and `test_status_page.py` both MENTION
        # `job_queue.py` -- they quote its rules in a comment.  Neither
        # imports it, and neither exercises it.  A grep-based scope counts
        # them and measures suites that never touch the module.
        suites = MODULE.referencing_suites(RUNTIME, "job_queue")
        self.assertNotIn("test_graph_database", suites)
        self.assertNotIn("test_status_page", suites)

    def test_the_own_suite_comes_first(self) -> None:
        for base in ("job_queue", "status_page", "graph_database", "zero_knowledge"):
            suites = MODULE.referencing_suites(RUNTIME, base)
            self.assertTrue(suites, f"{base} resolved to no suite at all")
            self.assertEqual(
                suites[0],
                f"test_{base}",
                f"{base}'s own suite must come first",
            )

    def test_the_scope_is_deterministic(self) -> None:
        # A census log is only comparable between runs if the scope is
        # stable.  The sibling suites are sorted, not filesystem-ordered.
        first = MODULE.referencing_suites(RUNTIME, "job_queue")
        for _ in range(3):
            self.assertEqual(MODULE.referencing_suites(RUNTIME, "job_queue"), first)
        self.assertEqual(first[1:], sorted(first[1:]))


class CensusScopeShapeTests(unittest.TestCase):
    """The resolver must recognise every import shape the runtime uses."""

    def _resolve(self, sources: dict[str, str], base: str):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tests").mkdir()
            for name, body in sources.items():
                (root / "tests" / name).write_text(body, encoding="utf-8")
            return MODULE.referencing_suites(root, base)

    def test_a_plain_import_is_a_reference(self) -> None:
        suites = self._resolve(
            {"test_thing.py": "import thing\n"}, "thing"
        )
        self.assertEqual(suites, ["test_thing"])

    def test_a_from_import_is_a_reference(self) -> None:
        suites = self._resolve(
            {"test_thing.py": "from thing import Thing\n"}, "thing"
        )
        self.assertEqual(suites, ["test_thing"])

    def test_a_parenthesised_from_import_is_a_reference(self) -> None:
        suites = self._resolve(
            {"test_thing.py": "from thing import (\n    Thing,\n    Other,\n)\n"},
            "thing",
        )
        self.assertEqual(suites, ["test_thing"])

    def test_a_mention_in_a_comment_is_not_a_reference(self) -> None:
        suites = self._resolve(
            {"test_thing.py": "# see thing.py's `_check_seq`\nimport os\n"},
            "thing",
        )
        self.assertEqual(suites, [])

    def test_a_mention_in_a_docstring_is_not_a_reference(self) -> None:
        suites = self._resolve(
            {"test_thing.py": '"""thing.py does the thing."""\nimport os\n'},
            "thing",
        )
        self.assertEqual(suites, [])

    def test_a_prefix_is_not_a_reference(self) -> None:
        # `thing_registry` is a different module.  A substring match would
        # count it, and the scope would then measure a suite that never
        # touches `thing`.
        suites = self._resolve(
            {"test_thing.py": "import thing_registry\n"}, "thing"
        )
        self.assertEqual(suites, [])

    def test_a_module_with_no_referencing_suite_resolves_to_empty(self) -> None:
        # The census script must SKIP such a module rather than fall back
        # to an arbitrary suite -- a fallback measures the wrong thing.
        suites = self._resolve({"test_other.py": "import other\n"}, "thing")
        self.assertEqual(suites, [])

    def test_the_resolver_is_not_vacuous(self) -> None:
        # A resolver that found nothing would satisfy the empty cases.
        suites = self._resolve(
            {"test_thing.py": "import thing\n", "test_other.py": "import os\n"},
            "thing",
        )
        self.assertEqual(suites, ["test_thing"])


if __name__ == "__main__":
    unittest.main()


class CensusScopeScaleTests(unittest.TestCase):
    """How many modules does the single-suite pairing get WRONG?

    A scope defect that touches one module is a bug.  A scope defect
    that touches a seventh of the runtime is a DESIGN defect, and the
    number is what says so.  So the number is measured and pinned.

    Measured 2026-11-25 over the runtime's 1620 top-level modules:
    **123** are referenced by more than one test suite, so the old
    single-suite pairing understated the scope for 7.6% of the runtime.

    **AMENDED 2026-11-25 (the dynamic-load fix).**  The first count was
    123, and it was computed by a resolver that read only STATIC
    imports.  519 of the runtime's suites load their module by FILE
    PATH, so the count understated the scope for a second reason -- and
    for **121 of the 270 rows** in the census artifact it understated it
    all the way to EMPTY, which made the census SKIP the row.

    With the dynamic loads read as well, the count is **133**.  The
    number is a measurement, so it moved; what did not move is the
    guard, which is what says so.

    **AMENDED 2026-11-26 (the `audit_cli` CLI-surface slice).**  The
    new `components/northstar-agent-runtime/tests/test_audit_cli_surface.py`
    drives `audit_cli.py`'s `verify-archive` command, so `audit_archive`
    now has TWO referencing suites and is itself multi-suite.  The
    count is **134**.

    The count moved for a REAL reason and not because the guard is
    loose: a module becomes multi-suite when a SECOND suite loads it,
    and this is a second suite loading it.  A count that moves is a
    count that was measured.

    **AMENDED 2026-11-26 (the `attack_extra_*` family slice).**  The
    new `components/northstar-agent-runtime/tests/test_attack_extra_family.py`
    loads ALL TWENTY `attack_extra_NN` modules, so every one of them now
    has TWO referencing suites -- its own, plus the family suite.  The
    count is **154**, exactly twenty more than 134, and the twenty new
    rows are exactly the twenty family modules.

    That the delta is EXACTLY twenty is the check that matters.  A
    family suite that loaded the twenty modules in a LOOP would have
    added ZERO to this count, because the scope resolver only sees a
    load whose module name is a LITERAL -- the same fact that made the
    family suite invisible to the census in the first place.  A guard
    that counts "modules with more than one suite" cannot tell the
    difference between "a second suite loads this" and "a second suite
    loads this", but a reader of this docstring can: the twenty rows
    listed below are the twenty that moved.
    """

    def test_the_multi_suite_modules_are_counted(self) -> None:
        runtime = RUNTIME
        modules = sorted(p.stem for p in runtime.glob("*.py"))
        self.assertEqual(len(modules), 1620)
        multi = [
            stem for stem in modules
            if len(MODULE.referencing_suites(runtime, stem)) > 1
        ]
        self.assertEqual(
            len(multi), 154,
            "the number of modules whose scope the single-suite pairing "
            "understated",
        )

    def test_the_twenty_family_modules_are_multi_suite(self) -> None:
        # The delta above was EXACTLY twenty.  Pin the twenty by name,
        # so a family suite that silently stops loading some of them
        # cannot be absorbed into the count.  A count that moves is a
        # count that was measured -- but only if the reader can see
        # WHICH rows moved.
        for n in range(1, 21):
            stem = f"attack_extra_{n:02d}"
            suites = MODULE.referencing_suites(RUNTIME, stem)
            with self.subTest(module=stem):
                self.assertEqual(
                    suites, ["test_attack_extra_01".replace("01", f"{n:02d}"),
                             "test_attack_extra_family"],
                    f"{stem} is not multi-suite",
                )

    def test_agents_is_exercised_by_eleven_suites(self) -> None:
        # The clearest case: `agents.py` has ONE own suite and TEN
        # siblings that exercise it.  A census that paired it with
        # `test_agents` alone would report survivors that ten other
        # suites catch.
        suites = MODULE.referencing_suites(RUNTIME, "agents")
        self.assertEqual(len(suites), 11)
        self.assertEqual(suites[0], "test_agents")


class TheScopeMustSeeDynamicLoadsTests(unittest.TestCase):
    """A STATIC import index is not the scope.

    THE DEFECT (measured 2026-11-25)
    --------------------------------
    ``scripts/census-scope.py`` decided "this suite exercises this
    module" by reading the suite's IMPORT statements from the AST.  That
    is right as far as it goes, and it is wrong about a third of the
    runtime.

    **519** of the runtime's suites do not import their module at all.
    They load it BY FILE PATH, because the module is not importable in
    isolation (it reaches for siblings that are not on the path) and the
    suite needs it standalone.  The house loader is::

        def _load(name):
            spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            spec.loader.exec_module(module)
            return module

        ap = _load("annotation_pin")

    For those suites the import index had no entry, so the scope
    resolver returned the EMPTY scope, and the census script printed::

        MUTANT SKIP: no test file exercises annotation_pin

    **121 of the 270 rows** in ``docs/baseline/mutant-census/census-v3.txt``
    name such a module.  So 121 of 270 measurements were SKIPped -- and
    a SKIP reads as a deliberate scope decision, so nothing looked
    wrong.

    The harm is not the SKIP itself.  It is that a SKIP is INVISIBLE: the
    artifact still holds a number for the row, the number was measured
    at the SINGLE-suite scope, and the row looked like a measurement.

    THE FIX
    -------
    The scope resolver now reads the dynamic loads too, so the union
    scope is the union of the suites that reach the module BY ANY MEANS.

    THE NON-VACUITY CONTROL
    -----------------------
    A resolver that read nothing at all would satisfy "the scope is not
    empty".  So every shape below is tested in BOTH directions: the
    shape must be FOUND, and a suite that does NOT contain it must not
    be counted.
    """

    def _resolve(self, sources: dict[str, str], base: str):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tests").mkdir()
            for name, body in sources.items():
                (root / "tests" / name).write_text(body, encoding="utf-8")
            return MODULE.referencing_suites(root, base)

    def test_the_house_loader_is_seen(self) -> None:
        """The runtime's own loader shape, with double quotes."""
        suites = self._resolve(
            {
                "test_thing.py": (
                    "import importlib.util\n"
                    "import sys\n"
                    "from pathlib import Path\n"
                    "RUNTIME = Path(__file__).resolve().parent.parent\n"
                    "def _load(name):\n"
                    "    spec = importlib.util.spec_from_file_location("
                    "name, RUNTIME / f\"{name}.py\")\n"
                    "    module = importlib.util.module_from_spec(spec)\n"
                    "    sys.modules[name] = module\n"
                    "    spec.loader.exec_module(module)\n"
                    "    return module\n"
                    "t = _load(\"thing\")\n"
                )
            },
            "thing",
        )
        self.assertEqual(
            suites,
            ["test_thing"],
            "the house loader is how the runtime's suites reach their "
            "module; a resolver that cannot see it reports an EMPTY scope "
            "and the census SKIPs the row",
        )

    def test_the_house_loader_with_single_quotes_is_seen(self) -> None:
        """The same loader, single-quoted.

        Measured: half the runtime's suites write `f'{name}.py'` and half
        write `f"{name}.py"`.  A resolver that reads only one of them
        misses half the runtime -- and the miss is silent, because the
        other half still resolves.
        """
        suites = self._resolve(
            {
                "test_thing.py": (
                    "import importlib.util\n"
                    "import sys\n"
                    "from pathlib import Path\n"
                    "RUNTIME = Path(__file__).resolve().parent.parent\n"
                    "def _load(name):\n"
                    "    spec = importlib.util.spec_from_file_location("
                    "name, RUNTIME / f'{name}.py')\n"
                    "    module = importlib.util.module_from_spec(spec)\n"
                    "    sys.modules[name] = module\n"
                    "    spec.loader.exec_module(module)\n"
                    "    return module\n"
                    "t = _load(\"thing\")\n"
                )
            },
            "thing",
        )
        self.assertEqual(suites, ["test_thing"])

    def test_a_literal_spec_from_file_location_is_seen(self) -> None:
        suites = self._resolve(
            {
                "test_thing.py": (
                    "import importlib.util\n"
                    "import sys\n"
                    "from pathlib import Path\n"
                    "_MOD_PATH = Path(__file__).resolve().parent.parent / \"thing.py\"\n"
                    "_spec = importlib.util.spec_from_file_location(\"thing\", _MOD_PATH)\n"
                    "m = importlib.util.module_from_spec(_spec)\n"
                    "sys.modules[\"thing\"] = m\n"
                    "_spec.loader.exec_module(m)\n"
                )
            },
            "thing",
        )
        self.assertEqual(suites, ["test_thing"])

    def test_the_module_type_and_exec_pattern_is_seen(self) -> None:
        """The other house shape: `types.ModuleType` plus `exec`."""
        suites = self._resolve(
            {
                "test_thing.py": (
                    "import sys\n"
                    "import types\n"
                    "from pathlib import Path\n"
                    "_MODULE_PATH = Path(__file__).parent.parent / \"thing.py\"\n"
                    "def _load_module():\n"
                    "    src = _MODULE_PATH.read_text()\n"
                    "    mod = types.ModuleType(\"thing\")\n"
                    "    mod.__file__ = str(_MODULE_PATH)\n"
                    "    sys.modules[\"thing\"] = mod\n"
                    "    exec(compile(src, str(_MODULE_PATH), \"exec\"), mod.__dict__)\n"
                    "    return mod\n"
                    "t = _load_module()\n"
                )
            },
            "thing",
        )
        self.assertEqual(suites, ["test_thing"])

    def test_a_docstring_naming_the_module_is_not_a_reference(self) -> None:
        """A docstring is documentation, not a load.

        Without this, a suite whose DOCSTRING names a module would be
        counted as exercising it -- and the census would measure a suite
        that never touches the module.
        """
        suites = self._resolve(
            {
                "test_thing.py": (
                    '"""thing.py does the thing."""\n'
                    "import os\n"
                )
            },
            "thing",
        )
        self.assertEqual(suites, [])

    def test_a_prose_mention_is_still_not_a_reference(self) -> None:
        """The original rule still holds for prose."""
        suites = self._resolve(
            {
                "test_thing.py": (
                    "# see thing.py's `_check`\n"
                    "import os\n"
                )
            },
            "thing",
        )
        self.assertEqual(suites, [])

    def test_the_resolver_is_not_vacuous(self) -> None:
        """THE NON-VACUITY CONTROL.

        A resolver that found nothing would satisfy every "is not a
        reference" case above.  So the same tree must ALSO produce a
        real reference -- and the two must not be confused.
        """
        suites = self._resolve(
            {
                "test_thing.py": (
                    "import importlib.util\n"
                    "import sys\n"
                    "from pathlib import Path\n"
                    "RUNTIME = Path(__file__).resolve().parent.parent\n"
                    "def _load(name):\n"
                    "    spec = importlib.util.spec_from_file_location("
                    "name, RUNTIME / f\"{name}.py\")\n"
                    "    module = importlib.util.module_from_spec(spec)\n"
                    "    sys.modules[name] = module\n"
                    "    spec.loader.exec_module(module)\n"
                    "    return module\n"
                    "t = _load(\"thing\")\n"
                ),
                "test_other.py": (
                    '"""thing.py is mentioned here."""\n'
                    "import os\n"
                ),
            },
            "thing",
        )
        self.assertEqual(suites, ["test_thing"])


class TheCensusArtifactIsMeasuredTests(unittest.TestCase):
    """The census artifact's rows must resolve to a scope.

    THE DEFECT (measured 2026-11-25)
    --------------------------------
    121 of the 270 rows in ``docs/baseline/mutant-census/census-v3.txt``
    name a module that no suite imports STATICALLY, so the scope
    resolver returned the EMPTY scope and the census SKIPped the row.

    The SKIP was invisible: the artifact still carries a number for
    every row, measured at the SINGLE-suite scope, and a row that was
    never measured at the union scope looks exactly like a row that was
    measured and found wanting.

    So the guard is on the ARTIFACT: how many of its rows resolve to a
    scope today.  The number is a measurement and it is pinned, so a
    future resolver that loses the dynamic loads again fails HERE rather
    than silently in a census that nobody reads.
    """

    #: The rows that resolve to the EMPTY scope, and why that is right.
    #:
    #: ``allowlist`` and ``ba_01``..``ba_04`` have no suite of their own
    #: and are mentioned only in PROSE elsewhere:
    #:
    #:   tests/test_action_card.py:52   # Auto-approve allowlisted and ...
    #:   tests/test_py_modules_list.py:21   "ba_01", "ba_02", ...
    #:
    #: So the census SKIPs them, and that is the correct answer: no
    #: suite exercises them.  Every OTHER row must resolve.
    EXPECTED_EMPTY = {"allowlist", "ba_01", "ba_02", "ba_03", "ba_04"}

    def _rows(self):
        import re

        artifact = (
            ROOT / "docs" / "baseline" / "mutant-census" / "census-v3.txt"
        )
        if not artifact.exists():
            self.skipTest(f"the census artifact is absent: {artifact}")
        text = artifact.read_text(encoding="utf-8")
        rows = []
        for line in text.splitlines():
            match = re.match(
                r"^(\S+) .*MUTANT RESULT: killed (\d+)/(\d+);", line)
            if match:
                rows.append(match.group(1))
        return rows

    def test_the_artifact_has_the_rows_it_is_expected_to_have(self) -> None:
        rows = self._rows()
        self.assertEqual(
            len(rows), 270,
            "the census artifact's row count changed; the guards below "
            "are stated against it",
        )

    def test_every_row_but_the_five_resolves_to_a_scope(self) -> None:
        empty = []
        for module in self._rows():
            base = module[:-3] if module.endswith(".py") else module
            if not (RUNTIME / f"{base}.py").exists():
                continue
            if not MODULE.referencing_suites(RUNTIME, base):
                empty.append(module)
        self.assertEqual(
            sorted(empty),
            sorted(self.EXPECTED_EMPTY),
            "a census row that resolves to NO scope is a row the census "
            "SKIPS, and a SKIP is invisible: the artifact still carries a "
            "number for it.  Either the resolver cannot see the suite "
            "that exercises the module (the dynamic-load shapes), or the "
            "row genuinely has no suite",
        )

    def test_the_five_unresolved_rows_have_no_suite_of_their_own(self) -> None:
        """The five exceptions must stay exceptions, for the stated reason."""
        for module in sorted(self.EXPECTED_EMPTY):
            own = RUNTIME / "tests" / f"test_{module}.py"
            self.assertFalse(
                own.exists(),
                f"{module} now has a suite of its own, so it must no "
                "longer be in the exception set",
            )
