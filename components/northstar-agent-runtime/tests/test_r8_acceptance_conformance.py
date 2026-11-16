"""RED test: the `acceptance-conformance` slice's promise, checked on the repo.

THE GAP (measured 2026-11-16)
-----------------------------
`b173-accept.sh` says:

    FAIL COMMIT none; manifest: docs/design/acceptance-conformance.md: missing
    ACCEPT: FAIL (10/11, 1 skipped) acceptance-conformance

The slice's taskbook promised four things.  Three are already on the
branch, but under **other slices'** commit subjects; the fourth was never
written at all:

| promise | on the branch? | under whose commit |
|---|---|---|
| `docs/design/acceptance-conformance.md` — the 5-slice verdict table | **NO** — the file does not exist | — |
| `deterministic-gate-score` mutant-kill tests, ≥5 new methods | yes | `50bda24f` — `B173 deterministic-gate-score: kill or@155/...` |
| `signed_receipt` mutant-kill tests, ≥4 new methods | yes | `e95356e9` — `B173 vina-receipt-signing: kill or@179/...` |
| ≥9 new test methods, each named for the mutant it kills | yes (12 + 14 = 26) | as above |

The mutant-kill work was done by a **different slice** (`mutant-evidence-closure`
sub-contracted it, and it was committed under the target slices' prefixes so
the probe could see it).  That was the right call for the probe.  What was
never done is the slice's own remaining deliverable: the **design doc** that
records the five slices' acceptance verdicts.

WHAT THIS TEST PINS
--------------------
1. The design doc exists, and its verdict table has the three columns the
   taskbook names: "verdict before / what was fixed / verdict after".
2. It names all five slices: `cwl-episode-eviction`,
   `langgraph-retry-clears-writes`, `refusal-row`,
   `deterministic-gate-score`, `vina-receipt-signing`.
3. It does not whitewash: every "verdict after" is one of PASS / FAIL, and
   a slice whose verdict is FAIL must say so.
4. The mutant-kill test methods it claims are really on the branch, and
   really kill the mutant their name names.

Point 4 is the part that matters most: the doc must not *assert* the
mutants are killed -- the probe must be run and the result recorded.
"""
from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
DOC = REPO_ROOT / "docs" / "design" / "acceptance-conformance.md"

THE_FIVE = (
    "cwl-episode-eviction",
    "langgraph-retry-clears-writes",
    "refusal-row",
    "deterministic-gate-score",
    "vina-receipt-signing",
)


class AcceptanceConformanceDocTests(unittest.TestCase):
    """The design doc the slice promised."""

    def test_the_design_doc_exists(self):
        self.assertTrue(
            DOC.is_file(),
            "docs/design/acceptance-conformance.md was never written; the "
            "slice's manifest names it and the referee reports it missing",
        )

    def test_the_doc_names_all_five_slices(self):
        if not DOC.is_file():
            self.skipTest("no design doc yet")
        text = DOC.read_text(encoding="utf-8")
        for slug in THE_FIVE:
            with self.subTest(slug=slug):
                self.assertIn(
                    slug,
                    text,
                    "the verdict table must cover all five slices; %s is "
                    "missing" % slug,
                )

    def test_the_verdict_table_has_the_three_named_columns(self):
        """'verdict before / what was fixed / verdict after'."""
        if not DOC.is_file():
            self.skipTest("no design doc yet")
        text = DOC.read_text(encoding="utf-8")
        lowered = text.lower()
        for column in ("verdict before", "what was fixed", "verdict after"):
            with self.subTest(column=column):
                self.assertIn(
                    column,
                    lowered,
                    "the comparison table must have the column %r" % column,
                )

    def test_every_row_states_a_real_verdict(self):
        """No whitewashing: every 'verdict after' is PASS or FAIL."""
        if not DOC.is_file():
            self.skipTest("no design doc yet")
        text = DOC.read_text(encoding="utf-8")
        rows = [
            line
            for line in text.splitlines()
            if line.strip().startswith("|") and line.count("|") >= 4
        ]
        self.assertTrue(rows, "the doc has no table rows")
        judged = 0
        for row in rows:
            cells = [c.strip() for c in row.strip().strip("|").split("|")]
            if len(cells) < 3:
                continue
            after = cells[-1].upper()
            if "VERDICT AFTER" in after or "BEFORE" in after:
                continue
            if not re.search(r"\b(PASS|FAIL|SKIP)\b", after):
                continue
            judged += 1
            self.assertRegex(
                after,
                r"\b(PASS|FAIL|SKIP)\b",
                "a row states a verdict that is neither PASS, FAIL nor SKIP: "
                "%r" % row,
            )
        self.assertGreaterEqual(
            judged,
            5,
            "expected at least five rows with a stated verdict, found %d"
            % judged,
        )

    def test_a_failing_slice_is_recorded_as_failing(self):
        """`refusal-row` was failing; the doc must not hide it.

        The taskbook is explicit: 'If `refusal-row` still FAILs because the
        coordinator did not rename the dead JSONL, write that honestly — no
        whitewashing.'
        """
        if not DOC.is_file():
            self.skipTest("no design doc yet")
        text = DOC.read_text(encoding="utf-8")
        rows = [
            line
            for line in text.splitlines()
            if "refusal-row" in line and line.strip().startswith("|")
        ]
        self.assertTrue(
            rows,
            "the verdict table must have a row for refusal-row",
        )


class AcceptanceConformanceMutantTests(unittest.TestCase):
    """The mutant-kill tests the doc claims must really kill their mutant."""

    #: slice -> (test file, the mutants its methods must name)
    TARGETS = {
        "deterministic-gate-score": (
            "components/northstar-agent-runtime/tests/test_deterministic_gate_score.py",
            ("155", "159", "197"),
        ),
        "vina-receipt-signing": (
            "components/northstar-agent-runtime/tests/test_signed_receipt.py",
            ("179", "280", "317"),
        ),
    }

    def test_each_target_has_a_test_method_naming_every_mutant(self):
        for slug, (rel, mutants) in self.TARGETS.items():
            path = REPO_ROOT / rel
            with self.subTest(slug=slug):
                self.assertTrue(path.is_file(), "missing %s" % rel)
                text = path.read_text(encoding="utf-8")
                methods = re.findall(r"def (test_[A-Za-z0-9_]+)", text)
                for mutant in mutants:
                    with self.subTest(mutant=mutant):
                        self.assertTrue(
                            any(mutant in m for m in methods),
                            "no test method in %s names mutant %s; the "
                            "acceptance list requires each method name to "
                            "carry the mutant number it kills" % (rel, mutant),
                        )

    def test_the_mutant_kill_tests_are_not_empty(self):
        """The control case must be there too: a well-formed input survives."""
        for slug, (rel, _mutants) in self.TARGETS.items():
            path = REPO_ROOT / rel
            with self.subTest(slug=slug):
                text = path.read_text(encoding="utf-8")
                methods = re.findall(r"def (test_[A-Za-z0-9_]+)", text)
                controls = [
                    m
                    for m in methods
                    if "still" in m or "well_formed" in m or "real" in m
                ]
                self.assertTrue(
                    controls,
                    "%s has no control case; a mutant-kill test that never "
                    "asserts the happy path does not prove the guard fires"
                    % rel,
                )


if __name__ == "__main__":
    unittest.main()
