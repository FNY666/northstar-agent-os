"""RED test: the two slices that promised test methods and delivered none.

THE GAP (measured 2026-11-16)
-----------------------------
Two slices have a taskbook that promises test methods and a commit history
that contains none:

    $ bash b173-accept.sh mutant-evidence-closure
    FAIL NEW_TESTS 0 (threshold 9)
    ACCEPT: FAIL (10/11, 1 skipped) mutant-evidence-closure

    $ bash b173-accept.sh orphan-adoption
    FAIL NEW_TESTS 0 (threshold 9)
    ACCEPT: FAIL (10/11, 1 skipped) orphan-adoption

    mutant-evidence-closure  promised: "New test methods >= 18"
    orphan-adoption          promised: ">= 5 new methods" in
                              test_revision_checked_tool_results.py and
                              ">= 4 new methods" in
                              test_scope_verbatim_compaction.py,
                              ">= 9 combined"

WHAT ACTUALLY HAPPENED
----------------------
**`mutant-evidence-closure`.**  Three commits:

    bb2af74f  the 64-slice mutant census          (a 577-line doc)
    17f92733  lift the tombstone mutant-kill tests out of the blindspots commit
    b9aefc06  lift the vina mutant-kill tests out of the blindspots commit

The two "lift" commits only **delete** test classes — they move the
mutant-kill tests *out* of the `*-mutant-blindspots` commits so that the
probe, which pins each slice's own last commit, can see them.  The classes
are re-landed by the target slices themselves (`dd3746a3` for `tombstone`,
`ebc66910` for `vina`).  So the work is real and the tests exist — but
**this slice's own commits contain zero new test methods**, which is what
the referee counts.

**`orphan-adoption`.**  One commit:

    1c947e7b  record the orphan adoption decisions  (two markdown docs)

The test methods it was supposed to add are in the two slices it adopted
from — `35956952` (`revision-checked-tool-results`, 13 methods) and
`cd3b9fab` (`scope-verbatim-compaction`, 4 methods) — because the adoption
work was done *by those slices*, under their prefixes.

WHAT THIS TEST PINS
--------------------
The slices' **promised test methods must exist under the slice's OWN
commits**.  Not that the tests exist somewhere in the tree — they do, and
that is not the point.  The promise was made in *this* slice's taskbook,
so it must be discharged in *this* slice's history, or the slice must say
plainly that it was discharged elsewhere.

Two legitimate ways to discharge it, and the test accepts both:

1. the slice's own commits add the promised number of test methods; or
2. the slice's **design doc** records the discharge explicitly — naming
   the commit that carries the methods and saying why they are not in this
   slice's own history.

What the test rejects is the third way: a slice that promises test
methods, delivers none under its own prefix, and does not say so.
"""
from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
HOME = Path("/home/muse-newapi")

#: slug -> (promised new test methods, the doc that must record it)
SLICES = {
    "mutant-evidence-closure": (
        18,
        REPO_ROOT / "docs" / "design" / "mutant-evidence-closure.md",
    ),
    "orphan-adoption": (
        9,
        REPO_ROOT / "docs" / "design" / "orphan-adoption.md",
    ),
}

#: A commit subject line, and the test methods it added.
METHOD_RE = re.compile(r"^\+[ \t]*(?:async[ \t]+)?def[ \t]+(test_[A-Za-z0-9_]+)")


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(REPO_ROOT), *args],
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def _slice_commits(slug: str) -> list:
    out = _git("log", "--format=%H", "--grep=^B173 %s[^A-Za-z0-9_-]" % re.escape(slug), "-i")
    return [h for h in out.splitlines() if h.strip()]


def _new_methods(slug: str) -> set:
    methods = set()
    for h in _slice_commits(slug):
        for line in _git("show", h).splitlines():
            m = METHOD_RE.match(line)
            if m:
                methods.add(m.group(1))
    return methods


class PromisedTestMethodsTests(unittest.TestCase):
    """Each slice must discharge its promise, or say that it did not."""

    def test_each_slice_discharges_its_test_method_promise(self):
        for slug, (promised, doc) in SLICES.items():
            with self.subTest(slug=slug):
                methods = _new_methods(slug)
                if len(methods) >= promised:
                    continue
                self.assertTrue(
                    doc.is_file(),
                    "%s promised >= %d new test methods and its own commits "
                    "carry %d; the design doc %s does not exist, so the "
                    "promise is discharged nowhere"
                    % (slug, promised, len(methods), doc),
                )
                text = doc.read_text(encoding="utf-8")
                self.assertRegex(
                    text,
                    r"(?i)(discharg|promise|carried by|landed under|prefix)",
                    "%s promised >= %d new test methods and its own commits "
                    "carry %d; the design doc must record where the methods "
                    "were landed and why" % (slug, promised, len(methods)),
                )
                # The doc must name a real commit that carries the methods.
                hashes = set(re.findall(r"\b[0-9a-f]{7,40}\b", text))
                named = {
                    h
                    for h in hashes
                    if _git("log", "--format=%H", "-1", h, "--grep=^\\+.*def test_").strip()
                    or "def test_" in _git("show", h)
                }
                self.assertTrue(
                    named,
                    "%s's design doc names no commit that actually carries "
                    "test methods" % slug,
                )

    def test_the_promised_counts_are_the_taskbooks(self):
        """The numbers this test enforces are the taskbooks' own."""
        # The taskbooks live in the COORDINATOR's directory, not in the
        # repository, so a CI runner does not have them.  Measured
        # 2026-11-22: on a simulated runner this test FAILED (twice, as
        # subtests) with "no taskbook for mutant-evidence-closure" --
        # it read a file that is not there and called that a failure of
        # the slice.  An absent taskbook is a SKIP: "the promise could
        # not be compared" is not "the promise was broken".
        taskbooks = [
            HOME / ("b173-%s-cc-prompt-rerun.md" % slug) for slug in SLICES
        ]
        if not any(t.is_file() for t in taskbooks):
            self.skipTest(
                "no taskbook available: "
                + ", ".join(str(t) for t in taskbooks)
            )
        for slug, (promised, _doc) in SLICES.items():
            taskbook = HOME / ("b173-%s-cc-prompt-rerun.md" % slug)
            with self.subTest(slug=slug):
                if not taskbook.is_file():
                    # One taskbook missing is not comparable; the
                    # others still are.
                    continue
                text = taskbook.read_text(encoding="utf-8")
                # The taskbook states the count in two places: the
                # acceptance list ("New test methods **>=18**") and the
                # constraint line (">=9 ge xin ceshi fangfa").  The
                # acceptance list is the stricter one and is the promise
                # this slice was made; the constraint line is the generic
                # template clause every taskbook carries.
                pattern = (
                    r"[>=≥]+\s*(?:\*\*)?\s*(\d+)\s*(?:\*\*)?\s*"
                    r"(?:new test methods|new methods|个新测试方法|个新方法)"
                    r"|"
                    r"(?:new test methods|new methods|个新测试方法|个新方法)"
                    r"\s*(?:\*\*)?\s*[>=≥]\s*(?:\*\*)?\s*(\d+)"
                )
                counts = [
                    int(a or b)
                    for a, b in re.findall(pattern, text, re.IGNORECASE)
                ]
                self.assertTrue(
                    counts,
                    "the taskbook for %s does not state a new-test-method "
                    "count" % slug,
                )
                self.assertEqual(
                    promised,
                    max(counts),
                    "the taskbook for %s promises up to %s new test methods; "
                    "this test enforces %d"
                    % (slug, max(counts), promised),
                )
                self.assertIn(
                    "\u22659 \u4e2a\u65b0\u6d4b\u8bd5\u65b9\u6cd5",
                    text,
                    "the taskbook for %s carries the generic template clause "
                    "'\u22659 \u4e2a\u65b0\u6d4b\u8bd5\u65b9\u6cd5'; every taskbook does"
                    % slug,
                )


class TheMethodsExistTests(unittest.TestCase):
    """Whichever way the promise is discharged, the methods must exist."""

    def test_the_adopted_methods_are_in_the_tree(self):
        """The orphan-adoption methods must be real, wherever they live."""
        cases = {
            "components/northstar-agent-runtime/tests/test_revision_checked_tool_results.py": 5,
            "components/northstar-agent-runtime/tests/test_scope_verbatim_compaction.py": 4,
        }
        for rel, minimum in cases.items():
            with self.subTest(path=rel):
                path = REPO_ROOT / rel
                self.assertTrue(path.is_file(), "missing %s" % rel)
                text = path.read_text(encoding="utf-8")
                methods = re.findall(r"def (test_[A-Za-z0-9_]+)", text)
                self.assertGreaterEqual(
                    len(methods),
                    minimum,
                    "%s has %d test methods, the taskbook promised at least %d"
                    % (rel, len(methods), minimum),
                )

    def test_the_mutant_kill_methods_are_in_the_tree(self):
        """The mutant-evidence-closure methods must be real."""
        cases = {
            "components/northstar-agent-runtime/tests/test_cancellation_tombstone.py": 15,
            "components/northstar-agent-runtime/tests/test_artifact_authority.py": 9,
        }
        for rel, minimum in cases.items():
            with self.subTest(path=rel):
                path = REPO_ROOT / rel
                self.assertTrue(path.is_file(), "missing %s" % rel)
                text = path.read_text(encoding="utf-8")
                methods = re.findall(r"def (test_[A-Za-z0-9_]+)", text)
                self.assertGreaterEqual(
                    len(methods),
                    minimum,
                    "%s has %d test methods, the mutant census promised at "
                    "least %d" % (rel, len(methods), minimum),
                )


if __name__ == "__main__":
    unittest.main()
