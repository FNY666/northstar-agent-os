"""The digest-pin census: the counts the design docs quote must reproduce.

Five design docs state how large the "the canonicalizer's error escapes the
module's own taxonomy" class is:

    docs/design/status-page-digest-pin.md
    docs/design/zero-knowledge-digest-pin.md
    docs/design/ai-constitution-digest-pin.md
    docs/design/ai-interpretability-perturbation-digest-pin.md
    docs/design/graphql-gateway-digest-pin.md

An earlier version of those docs claimed "672 modules, 189 with a
fallback, 165 candidate sites across 54 modules".  That claim does NOT
reproduce under any of ~40 definitions tried, and the ``grep`` in it ran
with ugrep, which skips git-ignored directories -- so its result depended
on the directory it started in (343 from the repository root, 679 from the
runtime directory, 341 with ``build/`` excluded by hand).

So the counts are now produced by a script, and this test pins them.  A
count in a doc is a claim too; this is the difference between a claim and
a measurement.

The census is a STATIC sweep.  It is a worklist, not a finding: it cannot
tell whether the bad value ever reaches the pin.  The dynamic probe that
established the seven live modules lives in the design docs, and the
lesson it teaches is exactly why this test pins the sweep's definition and
not a verdict.
"""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "digest-pin-census.py"
RUNTIME = ROOT / "components" / "northstar-agent-runtime"

SPEC = importlib.util.spec_from_file_location("digest_pin_census", SCRIPT)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - repository corruption
    raise RuntimeError(f"cannot load {SCRIPT}")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class DigestPinCensusTests(unittest.TestCase):
    """The counts the five design docs quote."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.report = MODULE.census(RUNTIME)

    def test_the_module_count_is_pinned(self) -> None:
        # The runtime's top-level modules, the helper excluded.  The repo
        # suite pins the same number twice (tests/test_package_member_
        # publication.py and tests/test_component_packaging_closure.py).
        self.assertEqual(self.report["modules"], 1620)

    def test_the_canonicalizer_user_count_is_pinned(self) -> None:
        self.assertEqual(self.report["canonicalizer_users"], 687)

    def test_the_fallback_importer_count_is_pinned(self) -> None:
        # The configuration this defect class lives in: the sibling helper
        # imported behind a try/except, so the module has a fallback path
        # whose canonical bytes differ from the shipped path's.
        self.assertEqual(self.report["fallback_importers"], 629)
        self.assertEqual(self.report["fallback_importers_any"], 643)

    def test_the_candidate_site_count_is_pinned(self) -> None:
        # A try whose body reaches a canonicalizer and whose first handler
        # catches the module's own error class without catching ValueError.
        #
        # The count is a function of the tree it ran on: 611 on the
        # pre-fix tree, 628 now.  The difference is `status_page.py` and
        # its six siblings -- the fix moved each pin INSIDE the guarded
        # region, which is exactly what the defect was, so the fixed
        # modules now LOOK like dead-guard sites to a sweep that reads
        # shape alone.  A sweep's count must therefore name its tree.
        self.assertEqual(self.report["candidate_sites"], 628)
        self.assertEqual(self.report["candidate_modules"], 201)

    def test_the_sweep_finds_each_of_the_seven_live_modules(self) -> None:
        # The sweep is a worklist, not a finding -- but it MUST contain
        # every module a dynamic probe found live, or it is not a sweep of
        # this class.
        #
        # On the CURRENT (fixed) tree it finds all seven, because each
        # fix moved the pin inside the guarded region.  On the PRE-FIX
        # tree it found only six: `status_page.py`'s pin sat OUTSIDE its
        # guarded try, so it was not a dead-guard site at all, and it was
        # found by exercising the module rather than by reading it.  That
        # gap is why a sweep's output must be paired with a probe's.
        names = set(self.report["candidate_module_names"])
        for module in (
            "ai_constitution.py",
            "ai_interpretability.py",
            "ai_perturbation.py",
            "graph_database.py",
            "graphql_gateway.py",
            "status_page.py",
            "zero_knowledge.py",
        ):
            self.assertIn(module, names)

    def test_the_sweep_is_not_vacuous(self) -> None:
        # A sweep that found nothing would satisfy every other assertion
        # above.  The control needs real subjects to hold.
        self.assertGreater(self.report["candidate_modules"], 100)
        self.assertGreater(self.report["candidate_sites"], 300)

    def test_the_pre_fix_tree_numbers_are_reproducible(self) -> None:
        # The docs quote 611 sites / 200 modules for the PRE-FIX tree and
        # name the commit that tree came from.  Rebuilding that tree from
        # git and re-running the census must reproduce both numbers, and
        # the rebuilt tree must NOT contain `status_page.py` in the
        # candidate set -- that omission is the fact the docs rely on to
        # say "a sweep that misses a live module is not a sweep".
        #
        # If this test cannot build the tree (no git, no history), it
        # SKIPs rather than passing for the wrong reason.
        import subprocess
        import tempfile

        repo = ROOT
        try:
            proc = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "--verify", "66e6ccd4~1"],
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError:
            self.skipTest("git is not available")
        if proc.returncode != 0:
            self.skipTest("the pre-fix commit is not in this clone")
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "runtime"
            target.mkdir()
            archive = subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "archive",
                    "66e6ccd4~1",
                    "components/northstar-agent-runtime",
                ],
                capture_output=True,
                check=False,
            )
            if archive.returncode != 0:
                self.skipTest("cannot archive the pre-fix tree")
            extract = subprocess.run(
                ["tar", "-x", "-C", str(target), "--strip-components=2"],
                input=archive.stdout,
                capture_output=True,
                check=False,
            )
            if extract.returncode != 0:
                self.skipTest("cannot extract the pre-fix tree")
            report = MODULE.census(target)
        self.assertEqual(report["candidate_sites"], 611)
        self.assertEqual(report["candidate_modules"], 200)
        # The PRE-FIX tree's own module count.  This number describes the
        # tree at 66e6ccd4~1 and does not move when the working tree
        # gains a module -- the working tree's count is pinned above.
        self.assertEqual(report["modules"], 1619)
        self.assertEqual(report["canonicalizer_users"], 687)
        self.assertEqual(report["fallback_importers"], 629)
        self.assertNotIn(
            "status_page.py",
            report["candidate_module_names"],
            "on the pre-fix tree status_page's pin sat OUTSIDE the guarded "
            "try, so the sweep could not see it; if it now appears, the "
            "docs' claim that the sweep missed a live module is stale",
        )


class DigestPinCensusShapeTests(unittest.TestCase):
    """The census must recognise BOTH import shapes the runtime uses."""

    def _census_one(self, body: str):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "canonical_json.py").write_text("", encoding="utf-8")
            (root / "sample.py").write_text(body, encoding="utf-8")
            return MODULE.census(root)

    def test_a_function_alias_import_is_recognised(self) -> None:
        report = self._census_one(
            "try:\n"
            "    from canonical_json import jcs_dumps as _jcs_dumps\n"
            "except ImportError:\n"
            "    _jcs_dumps = None\n"
            "\n"
            "def _pin(payload):\n"
            "    return _jcs_dumps(payload)\n"
            "\n"
            "class SampleError(Exception):\n"
            "    pass\n"
            "\n"
            "def go():\n"
            "    try:\n"
            "        return _pin({'a': 1})\n"
            "    except SampleError:\n"
            "        return None\n"
        )
        self.assertEqual(report["fallback_importers_any"], 1)
        self.assertEqual(report["candidate_sites"], 1)
        self.assertEqual(report["candidate_modules"], 1)

    def test_a_module_alias_import_is_recognised(self) -> None:
        # The shape status_page.py, graph_database.py and the ai_* modules
        # use after their fixes: `import canonical_json as _cj`, then
        # `_cj.jcs_dumps(...)`.  A sweep that only understands the dotted
        # function form misses every one of them.
        report = self._census_one(
            "try:\n"
            "    import canonical_json as _cj\n"
            "except Exception:\n"
            "    _cj = None\n"
            "\n"
            "def _canonical(payload):\n"
            "    return _cj.jcs_dumps(payload)\n"
            "\n"
            "class SampleError(Exception):\n"
            "    pass\n"
            "\n"
            "def go():\n"
            "    try:\n"
            "        return _canonical({'a': 1})\n"
            "    except SampleError:\n"
            "        return None\n"
        )
        self.assertEqual(report["fallback_importers_any"], 1)
        self.assertEqual(report["candidate_sites"], 1)
        self.assertEqual(report["candidate_modules"], 1)

    def test_a_handler_that_catches_valueerror_is_not_a_candidate(self) -> None:
        # The whole point of the class: a handler that catches ValueError
        # DOES cover JcsError, because JcsError IS a ValueError.  Such a
        # site is not a defect.
        report = self._census_one(
            "try:\n"
            "    from canonical_json import jcs_dumps as _jcs_dumps\n"
            "except ImportError:\n"
            "    _jcs_dumps = None\n"
            "\n"
            "def _pin(payload):\n"
            "    return _jcs_dumps(payload)\n"
            "\n"
            "class SampleError(Exception):\n"
            "    pass\n"
            "\n"
            "def go():\n"
            "    try:\n"
            "        return _pin({'a': 1})\n"
            "    except (SampleError, ValueError):\n"
            "        return None\n"
        )
        self.assertEqual(report["candidate_sites"], 0)
        self.assertEqual(report["candidate_modules"], 0)


if __name__ == "__main__":
    unittest.main()
