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
            len(multi), 123,
            "the number of modules whose scope the single-suite pairing "
            "understated",
        )

    def test_agents_is_exercised_by_eleven_suites(self) -> None:
        # The clearest case: `agents.py` has ONE own suite and TEN
        # siblings that exercise it.  A census that paired it with
        # `test_agents` alone would report survivors that ten other
        # suites catch.
        suites = MODULE.referencing_suites(RUNTIME, "agents")
        self.assertEqual(len(suites), 11)
        self.assertEqual(suites[0], "test_agents")
