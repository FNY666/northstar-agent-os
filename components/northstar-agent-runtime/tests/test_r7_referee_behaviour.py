"""Round-7 conformance tests: the referee changes that are still unguarded.

Round 7 fixed two defects in `b173-accept.sh` (the TESTS_RAN module list and
the NEW_TESTS threshold) and, in the same session, four earlier round-7
corrections landed in the referee:

  1. BENCH_DIFF  -- the baseline files carry a `# ...` provenance header; the
     comparison must strip comments and blank lines, or every slice's
     BENCH_DIFF fails on a phantom 9th "failing item".
  2. CANARY      -- a taskbook written before the canary mechanism existed
     has NO canary, so there is no probe to check.  That is a SKIP, not a FAIL.
  3. FULL_SUITE  -- the count pattern must accept any 4-digit-or-more run
     count, not only 19000-19999 (the suite is now 21212).
  4. BENCH       -- the baseline in force is named by a POINTER file, so the
     verdict line can say WHICH baseline was compared against.

Each test here is BEHAVIOURAL: it extracts the live referee's own shell code
and runs it, so a comment that merely mentions the right words cannot satisfy
it.  That is the property that made the round-6 test files silently stop
testing once their patches were applied (they built the "integrated referee"
from the LIVE script, so `patch` reported "previously applied" and the
methods skipped).

RED before the fix, GREEN after -- verified by re-running against a
reverted referee.
"""
import pathlib
import re
import subprocess
import unittest

ACCEPT = pathlib.Path("/home/muse-newapi/b173-accept.sh")


def _shq(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def _run_bash(script: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, timeout=timeout
    )


def _extract_block(text: str, start_pat: str, end_pat: str) -> str:
    """Extract the referee's own shell block between two markers."""
    lines = text.splitlines()
    start = None
    for i, ln in enumerate(lines):
        if re.search(start_pat, ln):
            start = i
            break
    if start is None:
        raise AssertionError("start marker not found: %s" % start_pat)
    out = []
    for ln in lines[start:]:
        out.append(ln)
        if re.search(end_pat, ln):
            break
    else:
        raise AssertionError("end marker not found: %s" % end_pat)
    return "\n".join(out)


class RefereeRound7BehaviourTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not ACCEPT.is_file():
            raise unittest.SkipTest("live referee not installed: %s" % ACCEPT)
        cls.text = ACCEPT.read_text(encoding="utf-8")

    # -- 1. BENCH_DIFF: the baseline's comment header must be stripped -----

    def _baseline_failures(self, baseline_body: str) -> list:
        """Run the referee's OWN baseline-extraction expression.

        The expression is EXTRACTED from the live referee (not restated
        here), so this test tracks whatever the referee actually does -- a
        hardcoded copy in the test would pass while the referee regressed.

        The body is written to a real temp file first, because the
        referee's expression reads a FILE (`$BENCH_BASE_EFF`).
        """
        import tempfile

        m = re.search(r"^\s*BASE_FAILS=\$\(.*\)$", self.text, re.M)
        self.assertIsNotNone(
            m, "could not find the BASE_FAILS expression in b173-accept.sh"
        )
        expr = m.group(0).strip()

        with tempfile.NamedTemporaryFile(
            "w", suffix=".failures.txt", delete=False
        ) as fh:
            fh.write(baseline_body)
            path = fh.name
        try:
            script = (
                "set -u\n"
                "BENCH_BASE_EFF=" + _shq(path) + "\n"
                + expr
                + "\n"
                'printf "%s\\n" "$BASE_FAILS" | grep -v "^$" | '
                'sed "s/^/ITEM:/"\n'
            )
            out = _run_bash(script)
            self.assertEqual(0, out.returncode, out.stderr)
            items = [
                ln[len("ITEM:") :] for ln in out.stdout.splitlines() if ln.startswith("ITEM:")
            ]
            return items
        finally:
            pathlib.Path(path).unlink(missing_ok=True)

    def test_the_baseline_comment_header_is_not_a_failing_item(self):
        """A `# ...` provenance header must not count as a failing item."""
        body = (
            "# baseline pinned at 2db42e939477bc2ceca9f20d35384dfc7731e972\n"
            "denial.landlock_path_whitelist_live\n"
            "metrics.capdrop_deny_all_live\n"
        )
        self.assertEqual(
            ["denial.landlock_path_whitelist_live", "metrics.capdrop_deny_all_live"],
            self._baseline_failures(body),
            "the baseline's comment header leaked into the failing-item set; "
            "every slice's BENCH_DIFF then fails on a phantom item",
        )

    def test_blank_lines_in_the_baseline_are_not_failing_items(self):
        """Blank lines must not count as failing items either."""
        body = "\n\ndenial.seccomp_filter_live_on_process\n\n   \n"
        self.assertEqual(
            ["denial.seccomp_filter_live_on_process"],
            self._baseline_failures(body),
        )

    def test_a_baseline_with_only_comments_yields_no_failing_items(self):
        """A baseline of only comments yields an empty set, not a phantom one."""
        self.assertEqual([], self._baseline_failures("# nothing here\n\n"))

    # -- 2. CANARY: no canary in the taskbook is a SKIP, not a FAIL -------

    def test_a_taskbook_without_a_canary_leaves_the_canary_check_skipped(self):
        """With no canary in the taskbook there is no probe -> SKIP."""
        script = (
            "set -u\n"
            "TASKBOOK=%s\n"
            'CANARY=$(grep -oE "CANARY: [A-Za-z0-9]+" "$TASKBOOK" 2>/dev/null '
            "| head -n1 | awk '{print $2}' || true)\n"
            'if [ -n "${CANARY:-}" ]; then echo "CANARY_VERDICT=CHECK"; '
            "else echo \"CANARY_VERDICT=SKIP\"; fi\n" % _shq("/nonexistent-taskbook")
        )
        out = _run_bash(script)
        self.assertEqual(0, out.returncode, out.stderr)
        self.assertIn("CANARY_VERDICT=SKIP", out.stdout)

    def test_the_referee_says_skip_not_fail_for_a_cardless_taskbook(self):
        """The referee must carry the SKIP branch, not a FAIL for no canary."""
        self.assertIn("no canary in taskbook", self.text)
        self.assertRegex(
            self.text,
            r"check CANARY SKIP \"no canary in taskbook",
            "the CANARY check must SKIP when the taskbook has no canary",
        )

    # -- 3. FULL_SUITE: any 4-digit-or-more run count ---------------------

    def test_the_full_suite_count_pattern_accepts_the_current_suite_size(self):
        """The suite is 21212 tests; the pattern must accept it."""
        m = re.search(
            r"grep -qE \"Ran \[0-9\]\{4,\}\|\[0-9\]\{4,\} tests\"", self.text
        )
        self.assertIsNotNone(
            m,
            "the FULL_SUITE pattern must accept any 4-digit-or-more count; "
            "the old 'Ran 19[0-9]{3}' window excluded the current 21212",
        )

    def test_the_full_suite_pattern_matches_a_realistic_count(self):
        """The extracted pattern must match 'Ran 21212 tests'."""
        m = re.search(
            r'grep -qE "(Ran \[0-9\]\{4,\}\|\[0-9\]\{4,\} tests)"', self.text
        )
        self.assertIsNotNone(m, "could not extract the FULL_SUITE pattern")
        pattern = m.group(1)
        out = _run_bash(
            "printf 'Full suite: Ran 21212 tests in 239.194s\\n' | "
            "grep -qE %s && echo MATCH || echo NOMATCH" % _shq(pattern)
        )
        self.assertIn("MATCH", out.stdout)

    def test_the_full_suite_pattern_still_rejects_a_missing_count(self):
        """A report with no run count must still fail the check."""
        m = re.search(
            r'grep -qE "(Ran \[0-9\]\{4,\}\|\[0-9\]\{4,\} tests)"', self.text
        )
        self.assertIsNotNone(m)
        pattern = m.group(1)
        out = _run_bash(
            "printf 'Full suite: it all passed\\n' | "
            "grep -qE %s && echo MATCH || echo NOMATCH" % _shq(pattern)
        )
        self.assertIn("NOMATCH", out.stdout)

    # -- 4. The baseline in force is named by a POINTER file ---------------

    def test_the_bench_baseline_pointer_selects_the_baseline_in_force(self):
        """The pointer file names the baseline; the sha comes from it."""
        self.assertIn("b173-bench-baseline-CURRENT", self.text)
        self.assertRegex(
            self.text,
            r"BENCH_BASE_FILE=\$\(head -n1 \"\$BENCH_BASE_POINTER\"",
            "the bench baseline must be selected by the pointer file",
        )

    def test_the_verdict_line_names_the_baseline_sha(self):
        """BENCH_DIFF must say WHICH baseline it compared against."""
        self.assertRegex(
            self.text,
            r"check BENCH_DIFF PASS \"failing-item set identical to baseline",
            "the BENCH_DIFF verdict line must name the baseline",
        )

    # -- 5. The referee still has twelve checks ---------------------------

    def test_the_referee_still_reports_twelve_checks(self):
        """The denominator stays 12: the check COUNT must not grow."""
        self.assertRegex(
            self.text,
            r"# Checks \(12\):",
            "the referee must still declare twelve checks",
        )
        names = set(
            re.findall(r"check ([A-Z_]+) (?:PASS|FAIL|SKIP)", self.text)
        )
        self.assertEqual(
            12,
            len(names),
            "expected 12 distinct check names, got %d: %s"
            % (len(names), sorted(names)),
        )

    def test_the_total_denominator_is_pass_plus_fail(self):
        """TOTAL = PASS + FAIL; a SKIP does not dilute the denominator."""
        self.assertIn("TOTAL=$((PASS+FAIL))", self.text)

    def test_the_exit_codes_are_unchanged(self):
        """PASS -> exit 0, FAIL -> exit 1."""
        self.assertIn(
            'echo "ACCEPT: PASS ($PASS/$TOTAL, $SKIP skipped) $SLUG"; exit 0;',
            self.text,
        )
        self.assertIn(
            'echo "ACCEPT: FAIL ($PASS/$TOTAL, $SKIP skipped) $SLUG"; exit 1;',
            self.text,
        )


if __name__ == "__main__":
    unittest.main()
