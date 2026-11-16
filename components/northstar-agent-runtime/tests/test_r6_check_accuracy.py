"""Read-only conformance tests for the two count checks of the referee
(``b173-accept.sh``).

The referee decides whether a B173 slice is accepted.  Two of its twelve
checks count things, and both counted the wrong thing:

* **D-1** ``WORKTREE_CLEAN`` read the dirty paths out of
  ``git status --porcelain`` with ``awk '{print $2}'``.  Git's porcelain
  format for a rename is a SINGLE line holding BOTH paths
  (``R  old.py -> new.py``), so field 2 is the **OLD** path.  A slice that
  renamed a file it owns therefore dirtied the tree without ever overlapping
  the committed file names, and the check reported PASS.

* **D-2** ``NEW_TESTS`` counted matching diff **LINES**
  (``grep -c '^\\+.*def test_'``), not distinct **method names**.  One
  method could be counted several times: once per added line that mentions
  it, and once per commit that re-adds it.  The very same expression used
  the GNU-only BRE escape ``\\+``, which the interactive shell's ugrep
  rejects outright ("invalid syntax", rc=2), so every measurement taken in
  an interactive shell about that line was suspect.

These tests assert the **behaviour** of the referee, not the text of its
source.  The live ``b173-accept.sh`` is the judge's own file and is never
modified here: the tests build a **patched copy** of it in a temporary
directory (by applying this slice's patch file) and run that copy against
throwaway sandbox repositories created with ``tempfile.mkdtemp()`` and
removed again with ``shutil.rmtree()``.

The behavioural tests skip cleanly when the outside-the-repo artefacts are
absent (patch file, live script).  At least one test depends only on
in-repository files, so the file remains meaningful without them.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
LIVE_ACCEPT = Path("/home/muse-newapi/b173-accept.sh")
PATCH_FILE = Path("/home/muse-newapi/b173-r6-check-accuracy-fix.patch")
DESIGN_DOC = REPO_ROOT / "docs" / "design" / "r6-check-accuracy.md"

# The referee must keep exactly these 12 check names.
EXPECTED_CHECK_NAMES = {
    "COMMIT",
    "REPORT",
    "CANARY",
    "FABLE_VERIF",
    "FULL_SUITE",
    "BENCH",
    "NEW_TESTS",
    "WORKTREE_CLEAN",
    "TESTS_RAN",
    "BENCH_DIFF",
    "REPORT_NUMBERS",
    "MUTANT",
}

MODDIR = "components/northstar-agent-runtime"

# The pattern the patched referee uses to pull a test method NAME out of an
# added diff line.  It is a plain ERE: the literal '+' is spelled as a
# bracket expression so that GNU grep 3.12 and ugrep 7.8.4 agree on it.
PATCHED_NAME_PATTERN = (
    r"^[+][[:space:]]*(async[[:space:]]+)?def[[:space:]]+test_[A-Za-z0-9_]*"
)

# The OLD, defective pattern: a GNU-only BRE escape.
DEFECTIVE_BRE_PATTERN = r"^\+.*def test_"


def _git(repo: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return out.stdout.strip()


def _run(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=str(cwd) if cwd else None,
    )


class _Sandbox:
    """A throwaway git repository used to produce real porcelain output."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.repo = root / "repo"
        self.repo.mkdir(parents=True, exist_ok=True)
        _git(self.repo, "init", "-q", ".")
        _git(self.repo, "config", "user.email", "sandbox@example.invalid")
        _git(self.repo, "config", "user.name", "sandbox")

    def write(self, relpath: str, content: str) -> Path:
        p = self.repo / relpath
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def add(self, *relpaths: str) -> None:
        _git(self.repo, "add", "--", *relpaths)

    def commit(self, subject: str) -> str:
        _git(self.repo, "commit", "-q", "-m", subject)
        return _git(self.repo, "rev-parse", "HEAD")

    def porcelain(self) -> str:
        # git's porcelain output is NOT safe to pass through strip() on the
        # whole blob: the second column of "XY path" is a space for
        # worktree-only changes, and strip() would eat it.  Only the
        # trailing newline is removed.
        out = subprocess.run(
            ["git", "-C", str(self.repo), "status", "--porcelain"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        return out.rstrip("\n")


# --- the two shell expressions the patch installs -----------------------------
# These are copied VERBATIM from the patch.  A separate test asserts that the
# patched referee really contains them, so they cannot drift silently.

# WORKTREE_CLEAN: turn porcelain lines into the set of dirty paths.  A rename
# line holds BOTH paths, so both are emitted.
DIRTY_PIPELINE = (
    r"""sed -E 's/^.. //' """
    r"""| awk '{n = index($0, " -> "); if (n > 0) {print substr($0, 1, n - 1); print substr($0, n + 4)} else {print $0}}' """
    r"""| sort -u"""
)

# The OLD, defective expression, kept so the defect stays reproducible.
DIRTY_PIPELINE_DEFECTIVE = r"""awk '{print $2}' | sort -u"""

# NEW_TESTS: pull the test method NAME out of an added diff line.
NAME_PIPELINE = (
    r"""grep -oE '^[+][[:space:]]*(async[[:space:]]+)?def[[:space:]]+test_[A-Za-z0-9_]*' """
    r"""| sed -E 's/^[+][[:space:]]*(async[[:space:]]+)?def[[:space:]]+//' """
    r"""| sort -u"""
)


def _bash(script: str, cwd: Path) -> str:
    res = _run(["bash", "-c", script], cwd=cwd)
    if res.returncode != 0:
        raise AssertionError(f"bash failed ({res.returncode}): {res.stderr.strip()}")
    return res.stdout


def _dirty_paths(repo: Path, pipeline: str = DIRTY_PIPELINE) -> list[str]:
    """Run the patched dirty-path extraction over a real porcelain listing."""
    out = _bash(f"git status --porcelain | {pipeline}", repo)
    return [ln for ln in out.splitlines() if ln.strip()]


def _distinct_test_names(diff_text: str) -> list[str]:
    """Run the patched name extraction over a diff and return distinct names."""
    proc = subprocess.run(
        ["bash", "-c", f"cat | {NAME_PIPELINE}"],
        input=diff_text,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise AssertionError(f"name pipeline failed: {proc.stderr.strip()}")
    return [ln for ln in proc.stdout.splitlines() if ln.strip()]


class TestDirtyPathExtraction(unittest.TestCase):
    """(a)-(d) plus the defect-1 reproduction: porcelain -> dirty paths."""

    def setUp(self) -> None:
        self.workdir = Path(tempfile.mkdtemp(prefix="b173-r6-ca-"))
        self.addCleanup(shutil.rmtree, self.workdir, True)
        self.sb = _Sandbox(self.workdir)

    def test_a_rename_line_yields_the_new_path(self) -> None:
        """(a) 'R  old.py -> new.py' contributes the NEW path."""
        self.sb.write("old.py", "x\n")
        self.sb.add("old.py")
        self.sb.commit("base")
        _git(self.sb.repo, "mv", "old.py", "new.py")
        porcelain = self.sb.porcelain()
        self.assertIn("old.py -> new.py", porcelain)
        dirty = _dirty_paths(self.sb.repo)
        self.assertIn("new.py", dirty)
        # The old path is kept too: the slice committed the old name, so a
        # later rename of that name must still be visible to the check.
        self.assertIn("old.py", dirty)
        self.assertTrue((self.sb.repo / "new.py").is_file())

    def test_a_defect_1_the_old_extraction_missed_the_rename(self) -> None:
        """(a) the OLD expression never saw the NEW path at all.

        Git's porcelain rename line is ONE line with TWO paths.  Field 2 is
        the OLD path, so the NEW path -- the name the file actually has on
        disk -- never entered the dirty set and was never compared against
        the committed file names.
        """
        self.sb.write("old.py", "x\n")
        self.sb.add("old.py")
        self.sb.commit("base")
        _git(self.sb.repo, "mv", "old.py", "new.py")
        old_dirty = _dirty_paths(self.sb.repo, DIRTY_PIPELINE_DEFECTIVE)
        new_dirty = _dirty_paths(self.sb.repo)
        # The OLD extraction produced the old path and nothing else.
        self.assertEqual(old_dirty, ["old.py"])
        self.assertNotIn("new.py", old_dirty)
        # The patched extraction sees both.
        self.assertIn("new.py", new_dirty)
        self.assertIn("old.py", new_dirty)
        # The file on disk is the NEW name.
        self.assertTrue((self.sb.repo / "new.py").is_file())
        self.assertFalse((self.sb.repo / "old.py").exists())

    def test_b_modified_line_yields_its_path(self) -> None:
        """(b) ' M path' contributes 'path'."""
        self.sb.write("mod.py", "x\n")
        self.sb.add("mod.py")
        self.sb.commit("base")
        self.sb.write("mod.py", "x\ny\n")
        porcelain = self.sb.porcelain()
        self.assertRegex(porcelain, r"(?m)^ M mod\.py$")
        self.assertEqual(_dirty_paths(self.sb.repo), ["mod.py"])

    def test_c_untracked_line_yields_its_path(self) -> None:
        """(c) '?? path' contributes 'path'."""
        self.sb.write("new.txt", "x\n")
        porcelain = self.sb.porcelain()
        self.assertRegex(porcelain, r"(?m)^\?\? new\.txt$")
        self.assertEqual(_dirty_paths(self.sb.repo), ["new.txt"])

    def test_d_added_line_yields_its_path(self) -> None:
        """(d) 'A  path' contributes 'path'."""
        self.sb.write("added.py", "x\n")
        self.sb.add("added.py")
        porcelain = self.sb.porcelain()
        self.assertRegex(porcelain, r"(?m)^A  added\.py$")
        self.assertEqual(_dirty_paths(self.sb.repo), ["added.py"])


class TestDistinctMethodCounting(unittest.TestCase):
    """(e)-(f) plus the defect-2 reproduction: lines vs distinct names."""

    def setUp(self) -> None:
        self.workdir = Path(tempfile.mkdtemp(prefix="b173-r6-ca2-"))
        self.addCleanup(shutil.rmtree, self.workdir, True)
        self.sb = _Sandbox(self.workdir)

    def _defective_line_count(self, diff_text: str) -> int:
        """The OLD counting method: matching diff LINES."""
        proc = subprocess.run(
            ["bash", "-c", "cat | grep -c '" + DEFECTIVE_BRE_PATTERN + "'"],
            input=diff_text,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            return 0
        return int(proc.stdout.strip() or 0)

    def test_e_a_method_is_counted_once_even_when_two_lines_match(self) -> None:
        """(e) two added lines that match -> ONE method name."""
        diff = (
            "diff --git a/tests/test_x.py b/tests/test_x.py\n"
            "--- a/tests/test_x.py\n"
            "+++ b/tests/test_x.py\n"
            "@@\n"
            "+def test_alpha():\n"
            "+    assert True\n"
            "+    # def test_alpha():  <- a second added line matching the pattern\n"
        )
        names = _distinct_test_names(diff)
        self.assertEqual(names, ["test_alpha"])
        # The old counting method saw two matching lines for one method.
        self.assertEqual(self._defective_line_count(diff), 2)

    def test_e_two_different_methods_count_as_two(self) -> None:
        """(e) two different method names -> TWO."""
        diff = (
            "@@\n"
            "+def test_alpha():\n"
            "+    assert True\n"
            "+def test_beta():\n"
            "+    assert True\n"
        )
        self.assertEqual(_distinct_test_names(diff), ["test_alpha", "test_beta"])

    def test_f_the_same_method_in_two_commits_counts_once(self) -> None:
        """(f) one method name added in two commits -> ONE."""
        self.sb.write("tests/test_x.py", "def test_alpha():\n    assert True\n")
        self.sb.add("tests/test_x.py")
        self.sb.commit("B173 probe: first commit")
        self.sb.write(
            "tests/test_x.py",
            "def test_alpha():\n    assert True\n\n\ndef test_alpha():\n    assert True\n",
        )
        self.sb.add("tests/test_x.py")
        self.sb.commit("B173 probe: second commit re-adds the same name")

        diffs = [
            _git(self.sb.repo, "show", h)
            for h in _git(self.sb.repo, "log", "--format=%H").splitlines()
        ]
        per_commit = [_distinct_test_names(d) for d in diffs]
        self.assertEqual(len(per_commit), 2)
        # Each commit alone sees one name ...
        self.assertEqual(per_commit[0], ["test_alpha"])
        self.assertEqual(per_commit[1], ["test_alpha"])
        # ... but the union over the slice's commits is still one name.
        union = sorted({n for names in per_commit for n in names})
        self.assertEqual(union, ["test_alpha"])
        # The old per-commit summing counted two.
        old_total = sum(self._defective_line_count(d) for d in diffs)
        self.assertEqual(old_total, 2)

    def test_f_defect_2_the_old_count_overstated_the_true_number(self) -> None:
        """(f) reproduction: old count != distinct-name count."""
        self.sb.write(
            "tests/test_x.py",
            "def test_alpha():\n    assert True\n\n\ndef test_beta():\n    assert True\n",
        )
        self.sb.add("tests/test_x.py")
        self.sb.commit("B173 probe: two methods")
        self.sb.write(
            "tests/test_x.py",
            "def test_alpha():\n    assert True\n\n\n"
            "def test_beta():\n    assert True\n\n\n"
            "def test_alpha():\n    assert True\n",
        )
        self.sb.add("tests/test_x.py")
        self.sb.commit("B173 probe: re-add alpha plus a stray mention")
        diffs = [
            _git(self.sb.repo, "show", h)
            for h in _git(self.sb.repo, "log", "--format=%H").splitlines()
        ]
        old_total = sum(self._defective_line_count(d) for d in diffs)
        union = sorted({n for d in diffs for n in _distinct_test_names(d)})
        self.assertEqual(union, ["test_alpha", "test_beta"])
        self.assertGreater(old_total, len(union))


class TestGrepEnginePortability(unittest.TestCase):
    """(g) the pattern must mean the same thing in every grep engine."""

    SAMPLE = (
        "+def test_alpha\n"
        "+    def test_beta(self):\n"
        "+    async def test_gamma(self):\n"
        "+    # def test_delta(self):\n"
    )

    def _gnu_grep(self, pattern: str, text: str = "") -> subprocess.CompletedProcess:
        # /usr/bin/grep is GNU grep in a script context (no alias, no shell
        # function).  Invoke the binary directly so the engine is explicit.
        # The sample is written to a file: grep reading its own stdin would
        # block forever under the test runner.
        with tempfile.NamedTemporaryFile(
            "w", suffix=".txt", delete=False, encoding="utf-8"
        ) as fh:
            fh.write(text or self.SAMPLE)
            sample = fh.name
        try:
            return subprocess.run(
                ["/usr/bin/grep", "-oE", pattern, sample],
                capture_output=True,
                text=True,
                timeout=60,
            )
        finally:
            os.unlink(sample)

    def _grep_engine(self, name: str) -> str | None:
        """Return the version banner of a grep engine, or None if absent."""
        res = _run(["bash", "-c", f"command -v {name} && {name} --version | head -1"])
        if res.returncode != 0 or not res.stdout.strip():
            return None
        return res.stdout.strip().splitlines()[-1]

    def _ugrep_match(
        self, pattern: str, text: str, bre: bool = False
    ) -> subprocess.CompletedProcess:
        """Run the pattern through ugrep, the engine the interactive shell uses.

        The interactive shell on this machine resolves ``grep`` to ugrep
        7.8.4 (a Claude Code shell wrapper), while a script sees GNU grep
        3.12.  ugrep is reached here the same way the wrapper reaches it:
        the claude binary re-executed with ARGV0=ugrep.
        """
        exec_path = os.environ.get("CLAUDE_CODE_EXECPATH") or ""
        if not exec_path or not os.access(exec_path, os.X_OK):
            return subprocess.CompletedProcess([], 127, "", "no claude exec path")
        env = dict(os.environ)
        env["ARGV0"] = "ugrep"
        # The file argument form is used on purpose: passing the sample on
        # stdin makes the claude binary read its own stdin and block.
        with tempfile.NamedTemporaryFile(
            "w", suffix=".txt", delete=False, encoding="utf-8"
        ) as fh:
            fh.write(text)
            sample = fh.name
        try:
            args = [exec_path, "-G"]
            if not bre:
                args.append("-E")
            args += ["-o", pattern, sample]
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                env=env,
                timeout=60,
            )
        finally:
            os.unlink(sample)
        return proc

    def test_g_the_patched_pattern_is_accepted_by_both_engines(self) -> None:
        """(g) GNU grep and ugrep agree on the patched pattern."""
        gnu = self._gnu_grep(PATCHED_NAME_PATTERN, self.SAMPLE)
        self.assertEqual(gnu.returncode, 0, gnu.stderr)
        gnu_out = gnu.stdout.split()

        ugrep = self._ugrep_match(PATCHED_NAME_PATTERN, self.SAMPLE)
        if ugrep.returncode == 127:
            self.skipTest("ugrep is not reachable on this machine")
        self.assertEqual(ugrep.returncode, 0, ugrep.stderr)
        ugrep_out = ugrep.stdout.split()

        self.assertEqual(gnu_out, ugrep_out)
        self.assertIn("test_alpha", gnu_out)
        self.assertIn("test_beta", gnu_out)

    def test_g_the_old_pattern_is_rejected_by_ugrep(self) -> None:
        """(g) the OLD pattern is a GNU extension ugrep refuses."""
        # The OLD expression is a BRE, so it must be run as one (-G).
        ugrep = self._ugrep_match(DEFECTIVE_BRE_PATTERN, self.SAMPLE, bre=True)
        if ugrep.returncode == 127:
            self.skipTest("ugrep is not reachable on this machine")
        self.assertNotEqual(ugrep.returncode, 0)
        self.assertIn("invalid syntax", ugrep.stderr)

    def test_g_the_old_pattern_still_works_under_gnu_grep(self) -> None:
        """(g) GNU grep accepts the old pattern -- which is why the defect
        was invisible to every measurement taken inside a script."""
        gnu = self._run_gnu_bre(DEFECTIVE_BRE_PATTERN, self.SAMPLE)
        self.assertEqual(gnu.returncode, 0, gnu.stderr)
        # GNU grep counts the four sample lines; ugrep refuses the pattern.
        self.assertEqual(gnu.stdout.strip(), "4")

    def _run_gnu_bre(self, pattern: str, text: str) -> subprocess.CompletedProcess:
        with tempfile.NamedTemporaryFile(
            "w", suffix=".txt", delete=False, encoding="utf-8"
        ) as fh:
            fh.write(text)
            sample = fh.name
        try:
            return subprocess.run(
                ["/usr/bin/grep", "-c", pattern, sample],
                capture_output=True,
                text=True,
                timeout=60,
            )
        finally:
            os.unlink(sample)


class TestRefereeSemanticsPreserved(unittest.TestCase):
    """(h) the patch must not change the referee's shape."""

    def setUp(self) -> None:
        self.workdir = Path(tempfile.mkdtemp(prefix="b173-r6-ca3-"))
        self.addCleanup(shutil.rmtree, self.workdir, True)
        self.patched = self._patched_copy()

    def _patched_copy(self) -> Path:
        if not LIVE_ACCEPT.is_file():
            raise unittest.SkipTest(f"live referee not installed: {LIVE_ACCEPT}")
        if not PATCH_FILE.is_file():
            raise unittest.SkipTest(f"patch file not present: {PATCH_FILE}")
        target_dir = self.workdir / "accept"
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / "b173-accept.sh"
        shutil.copyfile(LIVE_ACCEPT, target)
        res = subprocess.run(
            ["patch", "-p1", "-d", str(target_dir)],
            input=PATCH_FILE.read_text(encoding="utf-8"),
            capture_output=True,
            text=True,
        )
        if res.returncode != 0:
            live_text = LIVE_ACCEPT.read_text(encoding="utf-8")
            if "distinct new test methods" in live_text:
                # The coordinator already applied the fix to the live script.
                return LIVE_ACCEPT
            raise unittest.SkipTest(f"patch does not apply any more: {res.stdout.strip()}")
        target.chmod(0o755)
        return target

    def test_h_the_referee_still_has_twelve_checks_with_the_same_names(self) -> None:
        """(h) 12 check names, unchanged."""
        text = self.patched.read_text(encoding="utf-8")
        found = set(re.findall(r"\bcheck ([A-Z_]+) ", text))
        self.assertEqual(found, EXPECTED_CHECK_NAMES)
        self.assertEqual(len(EXPECTED_CHECK_NAMES), 12)

    def test_h_the_total_denominator_is_still_pass_plus_fail(self) -> None:
        """(h) TOTAL=$((PASS+FAIL)) unchanged."""
        text = self.patched.read_text(encoding="utf-8")
        self.assertIn("TOTAL=$((PASS+FAIL))", text)

    def test_h_the_check_output_format_is_unchanged(self) -> None:
        """(h) PASS/FAIL/SKIP <name> <detail> unchanged."""
        text = self.patched.read_text(encoding="utf-8")
        self.assertIn('PASS) PASS=$((PASS+1)); echo "PASS $name $detail";;', text)
        self.assertIn('FAIL) FAIL=$((FAIL+1)); echo "FAIL $name $detail";;', text)
        self.assertIn('*)    SKIP=$((SKIP+1)); echo "SKIP $name $detail";;', text)

    def test_h_the_exit_codes_are_unchanged(self) -> None:
        """(h) 0 = ACCEPT PASS, 1 = ACCEPT FAIL."""
        text = self.patched.read_text(encoding="utf-8")
        self.assertIn(
            'echo "ACCEPT: PASS ($PASS/$TOTAL, $SKIP skipped) $SLUG"; exit 0;', text
        )
        self.assertIn(
            'echo "ACCEPT: FAIL ($PASS/$TOTAL, $SKIP skipped) $SLUG"; exit 1;', text
        )

    def test_h_the_new_tests_threshold_matches_the_taskbook_contract(self) -> None:
        """(h) the NEW_TESTS threshold must match the taskbook contract.

        Originally this test asserted the threshold STAYS at 1, because
        raising it was "a separate coordinator decision".  That decision
        was made on 2026-11-16: the round-6 measurement showed that with
        the distinct-name counter in place, 69 of 76 slices have >= 9
        distinct new test methods and the 7 that do not are ALREADY FAIL
        for another reason -- so raising the threshold flips 0
        currently-PASS slices and costs nothing.

        The taskbook template (b173-taskbook-template.md line 104) says
        ">= 9 ge test methods", so 9 is the contract.  The counting RULE
        (distinct names, not lines) is still what this slice was about,
        and that is unchanged.

        ROUND 7 UPDATE: the threshold is no longer a literal.  Seven slices
        have no taskbook at all (runtime-registration, slice1..slice6);
        they ran before the template's ">= 9" clause existed, so they were
        never promised 9 test methods.  The referee therefore COMPUTES the
        threshold from the taskbook's existence: 9 with a taskbook, 1
        without.  This test reads the 9 off the taskbook branch.
        """
        text = self.patched.read_text(encoding="utf-8")
        self.assertIn("NTEST_THRESHOLD=9", text)
        self.assertIn("NTEST_THRESHOLD=1", text)
        self.assertNotIn('[ "$NTEST" -ge 9 ]', text)

    def test_h_the_patched_referee_installs_the_two_fixed_expressions(self) -> None:
        """(h) the patched referee really carries the fixed expressions."""
        text = self.patched.read_text(encoding="utf-8")
        self.assertIn("distinct new test methods", text)
        self.assertIn("^[+][[:space:]]*(async[[:space:]]+)?def[[:space:]]+test_", text)
        self.assertIn("index($0, \" -> \")", text)
        # The defective expressions are gone from the EXECUTABLE lines
        # (they survive only inside the explanatory comments).
        code = [
            ln
            for ln in text.splitlines()
            if not ln.lstrip().startswith("#")
        ]
        code = "\n".join(code)
        self.assertNotIn("grep -c '^\\+.*def test_'", code)
        # The DIRTY extraction no longer uses the second whitespace field.
        self.assertNotIn("status --porcelain 2>/dev/null | awk '{print $2}'", code)


class TestDesignDocIsPresent(unittest.TestCase):
    """(i) a test that depends only on in-repository files."""

    def test_i_the_design_doc_exists_and_records_the_before_after_table(self) -> None:
        """(i) docs/design/r6-check-accuracy.md exists and has the table."""
        self.assertTrue(
            DESIGN_DOC.is_file(), f"missing design doc: {DESIGN_DOC}"
        )
        text = DESIGN_DOC.read_text(encoding="utf-8")
        # The before/after table must name both defects and both verdicts.
        self.assertIn("WORKTREE_CLEAN", text)
        self.assertIn("NEW_TESTS", text)
        self.assertIn("b173-accept.sh", text)
        # The change specification: exact old and new text.
        self.assertIn("grep -c '^\\+.*def test_'", text)
        self.assertIn("awk '{print $2}'", text)
        # The threshold decision.
        self.assertIn("threshold", text.lower())

    def test_i_the_design_doc_states_the_threshold_stays_at_one(self) -> None:
        """(i) the doc must say the threshold is NOT raised here."""
        text = DESIGN_DOC.read_text(encoding="utf-8")
        self.assertIn("distinct new test methods", text)
        self.assertIn("TECHNICALITY", text.upper())
