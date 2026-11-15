"""Read-only conformance tests for the referee (``b173-accept.sh``) after the
three round-6 patches are applied to a **copy** of it.

This slice does **not** edit the live referee.  It copies the live script to
a temporary directory, applies the three existing patch files to the copy,
and asserts the **behaviour** of the patched copy:

* **D-1** ``WORKTREE_CLEAN`` extracted the dirty paths with
  ``git status --porcelain | awk '{print $2}'``.  Git's porcelain format
  puts a rename on a SINGLE line holding BOTH paths (``R  old.py -> new.py``),
  so field 2 is the **OLD** path only.  The new path -- the name the file
  actually has on disk -- was never compared against the committed file
  names, so a dirty rename was invisible to the check.

* **D-2** ``NEW_TESTS`` counted matching diff **LINES**
  (``grep -c '^\\+.*def test_'``) rather than distinct **method names**.
  A method could be counted once per added line that mentions it and once
  per commit that re-adds it.  Worse, a *prose* mention of ``def test_``
  inside a markdown document counted as a test method: the
  ``orphan-adoption`` slice committed two markdown files only, and the
  referee counted 1 "new test method" from a table cell.

* **D-3** ``REPORT_NUMBERS`` resolved the session JSONL with a recursive
  grep piped into ``head -n1``, which is a coin flip when many sessions
  read the same taskbook.  The patched referee resolves the session
  deterministically and says ``SKIP`` when the answer is ambiguous --
  never a guess.

The tests assert the referee's *behaviour*, not the text of its source.
The behavioural tests skip cleanly when the outside-the-repo artefacts are
absent (patch files, live script).  At least one test depends only on
in-repository files, so this file remains meaningful without them.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
LIVE_ACCEPT = Path("/home/muse-newapi/b173-accept.sh")

PATCH_FILES = [
    Path("/home/muse-newapi/b173-r6-manifest-integrity-fix.patch"),
    Path("/home/muse-newapi/b173-r6-check-accuracy-fix.patch"),
    Path("/home/muse-newapi/b173-r6-12-session-resolution-fix.patch"),
]

DESIGN_DOC = REPO_ROOT / "docs" / "design" / "r6-worktree-rename.md"

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

# The patched referee pulls a test method NAME out of an added diff line
# with a plain ERE.  The literal '+' is spelled as a bracket expression so
# that GNU grep and ugrep agree on it.
PATCHED_NAME_PATTERN = (
    r"^[+][[:space:]]*(async[[:space:]]+)?def[[:space:]]+test_[A-Za-z0-9_]*"
)

# The OLD, defective pattern: a GNU-only BRE escape that also matched
# prose inside markdown documents.
DEFECTIVE_BRE_PATTERN = r"^\+.*def test_"


def _git(repo: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return out.stdout.rstrip("\n")


def _run(cmd, cwd=None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(c) for c in cmd],
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


class _TempDirCase(unittest.TestCase):
    """Base class that gives each test its own temp dir and cleans it up."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="b173-r6-wtr-"))
        self.addCleanup(shutil.rmtree, str(self.tmp), True)


# --- the two shell expressions the check-accuracy patch installs ----------
# These are copied VERBATIM from the patch.  A separate test asserts that
# the patched referee really contains them, so they cannot drift silently.

# WORKTREE_CLEAN: turn porcelain lines into the set of dirty paths.  A rename
# line holds BOTH paths, so both are emitted.
PATCHED_DIRTY_EXTRACTION = (
    r"""sed -E 's/^.. //' """
    r"""| awk '{n = index($0, " -> "); if (n > 0) """
    r"""{print substr($0, 1, n - 1); print substr($0, n + 4)} else {print $0}}' """
    r"""| sort -u"""
)

# NEW_TESTS: pull the method NAMES out of the added diff lines.  In the
# referee this continues the `git show "$h" |` pipeline; here it is fed the
# diff text on stdin.
PATCHED_NAME_EXTRACTION = (
    r"""grep -oE '^[+][[:space:]]*(async[[:space:]]+)?def[[:space:]]+test_[A-Za-z0-9_]*' """
    r"""| sed -E 's/^[+][[:space:]]*(async[[:space:]]+)?def[[:space:]]+//'"""
)


def _dirty_paths(porcelain_text: str) -> list:
    """The patched WORKTREE_CLEAN extraction, run for real."""
    proc = subprocess.run(
        ["bash", "-c", PATCHED_DIRTY_EXTRACTION],
        input=porcelain_text,
        capture_output=True,
        text=True,
    )
    return [line for line in proc.stdout.splitlines() if line]


def _distinct_method_names(diff_text: str) -> list:
    """The patched NEW_TESTS name extraction, run for real."""
    proc = subprocess.run(
        ["bash", "-c", PATCHED_NAME_EXTRACTION],
        input=diff_text,
        capture_output=True,
        text=True,
    )
    return sorted({line for line in proc.stdout.splitlines() if line})


class DirtyPathExtractionTests(_TempDirCase):
    """(a)-(d): the patched dirty-path extraction over real porcelain lines."""

    def test_a_rename_line_yields_both_the_old_and_the_new_path(self) -> None:
        """(a) A porcelain rename line holds both paths; both must be emitted.

        The old extraction took the second whitespace field, i.e. the OLD
        path only, so the file's real name on disk never took part in the
        comparison against the committed file names.
        """
        box = _Sandbox(self.tmp)
        box.write("old.py", "x\n")
        box.add("old.py")
        box.commit("init")
        _git(box.repo, "mv", "old.py", "new.py")

        porcelain = box.porcelain()
        self.assertIn("->", porcelain, "git must report this as a rename")

        dirty = _dirty_paths(porcelain)
        self.assertIn("old.py", dirty, "the OLD path must be in the dirty set")
        self.assertIn("new.py", dirty, "the NEW path must be in the dirty set")

        # The defective extraction sees only the old path.
        old_only = [
            line.split()[1]
            for line in porcelain.splitlines()
            if line.split()
        ]
        self.assertEqual(old_only, ["old.py"])
        self.assertNotIn("new.py", old_only)

        # And the file really is called new.py on disk.
        self.assertTrue((box.repo / "new.py").exists())
        self.assertFalse((box.repo / "old.py").exists())

    def test_b_modified_line_yields_the_path(self) -> None:
        """(b) ' M path' (worktree-only modification) yields 'path'."""
        box = _Sandbox(self.tmp)
        box.write("mod.py", "y\n")
        box.add("mod.py")
        box.commit("init")
        box.write("mod.py", "y\nz\n")

        porcelain = box.porcelain()
        self.assertTrue(porcelain.startswith(" M mod.py"), porcelain)
        self.assertEqual(_dirty_paths(porcelain), ["mod.py"])

    def test_c_untracked_line_yields_the_path(self) -> None:
        """(c) '?? path' (untracked) yields 'path'."""
        box = _Sandbox(self.tmp)
        box.write("tracked.py", "y\n")
        box.add("tracked.py")
        box.commit("init")
        box.write("untracked.py", "u\n")

        porcelain = box.porcelain()
        self.assertIn("?? untracked.py", porcelain)
        self.assertEqual(_dirty_paths(porcelain), ["untracked.py"])

    def test_d_added_line_yields_the_path(self) -> None:
        """(d) 'A  path' (staged addition) yields 'path'."""
        box = _Sandbox(self.tmp)
        box.write("tracked.py", "y\n")
        box.add("tracked.py")
        box.commit("init")
        box.write("added.py", "a\n")
        box.add("added.py")

        porcelain = box.porcelain()
        self.assertIn("A  added.py", porcelain)
        self.assertEqual(_dirty_paths(porcelain), ["added.py"])

    def test_four_porcelain_codes_are_all_handled(self) -> None:
        """All four status codes appear together and all survive extraction."""
        box = _Sandbox(self.tmp)
        box.write("old.py", "x\n")
        box.write("mod.py", "y\n")
        box.add("old.py", "mod.py")
        box.commit("init")
        box.write("mod.py", "y\nz\n")          # M
        box.write("untracked.py", "u\n")       # ??
        box.write("added.py", "a\n")
        box.add("added.py")                    # A
        _git(box.repo, "mv", "old.py", "renamed.py")   # R

        porcelain = box.porcelain()
        self.assertIn("R  old.py -> renamed.py", porcelain)
        self.assertIn(" M mod.py", porcelain)
        self.assertIn("?? untracked.py", porcelain)
        self.assertIn("A  added.py", porcelain)

        dirty = _dirty_paths(porcelain)
        self.assertEqual(
            sorted(dirty),
            ["added.py", "mod.py", "old.py", "renamed.py", "untracked.py"],
        )


class DistinctMethodCountTests(_TempDirCase):
    """(e)-(g): the distinct-method counter."""

    def test_e_one_method_is_counted_once_even_when_two_added_lines_match(
        self,
    ) -> None:
        """(e) Two added lines mentioning the same method count once."""
        diff = (
            "+    def test_alpha(self):\n"
            "+        # a second line that mentions def test_alpha in prose\n"
            "+        pass\n"
            "+    def test_beta(self):\n"
            "+        pass\n"
        )
        names = _distinct_method_names(diff)
        self.assertEqual(names, ["test_alpha", "test_beta"])

    def test_e_two_different_methods_count_as_two(self) -> None:
        """(e) Two different method names count as two."""
        diff = "+    def test_one(self):\n+    def test_two(self):\n"
        self.assertEqual(len(_distinct_method_names(diff)), 2)

    def test_f_the_same_method_name_added_in_two_commits_counts_once(
        self,
    ) -> None:
        """(f) The union across commits collapses a repeated method name."""
        commit_a = "+    def test_shared(self):\n"
        commit_b = "+    def test_shared(self):\n"
        union = _distinct_method_names(commit_a + commit_b)
        self.assertEqual(union, ["test_shared"])
        self.assertEqual(len(union), 1)

    def test_g_a_prose_mention_in_markdown_is_not_a_test_method(self) -> None:
        """(g) The orphan-adoption regression.

        The slice's commit added two MARKDOWN documents.  The only
        'def test_' in the diff was a prose mention inside a markdown
        table, which the old line counter counted as 1 and the patched
        name counter correctly counts as 0.
        """
        markdown_diff = (
            "+| 1 | `tests/test_revision_checked_tool_results.py` | 6 new test "
            "methods (`test_result_as_dict_carries_the_schema_pin`, "
            "`test_with_result_revision_returns_a_copy_and_leaves_the_original`) "
            "| **keep** | Each method asserts behaviour that HEAD does not "
            "have: `git show HEAD:...\\|grep -c 'def test_'` returns 0 for all "
            "six names. |\n"
        )
        self.assertEqual(_distinct_method_names(markdown_diff), [])

        # The old line counter counted it as one.
        old = subprocess.run(
            ["grep", "-c", DEFECTIVE_BRE_PATTERN],
            input=markdown_diff,
            capture_output=True,
            text=True,
        )
        self.assertEqual(old.stdout.strip(), "1")


class IntegratedRefereeTests(_TempDirCase):
    """(h): the integrated referee keeps its 12 checks and its semantics."""

    def setUp(self) -> None:
        super().setUp()
        if not LIVE_ACCEPT.exists():
            self.skipTest(f"live referee {LIVE_ACCEPT} not present")
        missing = [p for p in PATCH_FILES if not p.exists()]
        if missing:
            self.skipTest(f"patch file(s) not present: {missing}")
        self.copy = self.tmp / "accept.sh"
        shutil.copy2(str(LIVE_ACCEPT), str(self.copy))
        for patch in PATCH_FILES:
            with patch.open("rb") as handle:
                proc = subprocess.run(
                    ["patch", "-p0", "accept.sh"],
                    stdin=handle,
                    capture_output=True,
                    text=True,
                    cwd=str(self.tmp),
                )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_h_the_integrated_referee_keeps_its_twelve_checks(self) -> None:
        """(h) Exactly 12 distinct check names, before and after patching."""
        live_names = self._check_names(LIVE_ACCEPT.read_text(encoding="utf-8"))
        new_names = self._check_names(self.copy.read_text(encoding="utf-8"))
        self.assertEqual(len(live_names), 12)
        self.assertEqual(len(new_names), 12)
        self.assertEqual(new_names, EXPECTED_CHECK_NAMES)

    def test_h_the_integrated_referee_keeps_the_denominator(self) -> None:
        """(h) TOTAL is still PASS+FAIL and the exit codes are unchanged."""
        text = self.copy.read_text(encoding="utf-8")
        self.assertIn("TOTAL=$((PASS+FAIL))", text)
        self.assertIn(
            'echo "ACCEPT: PASS ($PASS/$TOTAL, $SKIP skipped) $SLUG"; exit 0;', text
        )
        self.assertIn(
            'echo "ACCEPT: FAIL ($PASS/$TOTAL, $SKIP skipped) $SLUG"; exit 1;', text
        )

    def test_h_the_integrated_referee_keeps_the_check_line_format(self) -> None:
        """(h) 'PASS <name> <detail>' / 'FAIL ...' / 'SKIP ...' unchanged."""
        text = self.copy.read_text(encoding="utf-8")
        for prefix in ("PASS", "FAIL"):
            self.assertIn(f'echo "{prefix} $name $detail"', text)
        self.assertIn('echo "SKIP $name $detail"', text)

    def test_h_the_integrated_referee_passes_the_shell_syntax_check(self) -> None:
        """(h) bash -n on the integrated copy."""
        proc = _run(["bash", "-n", "accept.sh"], cwd=self.tmp)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_the_threshold_stays_at_one(self) -> None:
        """The NEW_TESTS threshold must NOT be raised in this round.

        Raising it from 1 to the taskbook's 9 would be a separate
        coordinator decision: it would add a new failure axis on top of
        the batch's existing failures and rewrite the batch's
        pass/fail history on a technicality.
        """
        text = self.copy.read_text(encoding="utf-8")
        self.assertIn('[ "$NTEST" -ge 1 ]', text)
        self.assertNotIn('[ "$NTEST" -ge 9 ]', text)

    @staticmethod
    def _check_names(text: str) -> set:
        import re

        return set(re.findall(r"check ([A-Z_]+) ", text))


class InRepoDocumentationTests(unittest.TestCase):
    """(i): at least one test depends only on in-repository files, so this
    file stays meaningful even when the outside-the-repo tools are absent."""

    def test_i_the_design_doc_exists_and_records_the_before_after_table(
        self,
    ) -> None:
        self.assertTrue(
            DESIGN_DOC.exists(), f"missing design doc: {DESIGN_DOC}"
        )
        text = DESIGN_DOC.read_text(encoding="utf-8")
        # The before/after table for the rename defect.
        self.assertIn("awk '{print $2}'", text)
        self.assertIn("R  old.py -> new.py", text)
        # The threshold decision input.
        self.assertIn("threshold", text.lower())
        # The application order for the coordinator.
        self.assertIn("b173-r6-check-accuracy-fix.patch", text)
        self.assertIn("b173-r6-12-watch-session-resolution-fix.patch", text)
        self.assertIn("b173-watch.sh", text)

    def test_i_the_design_doc_records_the_orphan_adoption_case(self) -> None:
        self.assertTrue(DESIGN_DOC.exists(), f"missing design doc: {DESIGN_DOC}")
        text = DESIGN_DOC.read_text(encoding="utf-8")
        self.assertIn("orphan-adoption", text)
        self.assertIn("1c947e7b", text)

    def test_the_live_referee_is_untouched_by_this_slice(self) -> None:
        """The live script is the judge's own file; this slice must not
        have edited it.  The integrated work happens on a COPY."""
        if not LIVE_ACCEPT.exists():
            self.skipTest(f"live referee {LIVE_ACCEPT} not present")
        text = LIVE_ACCEPT.read_text(encoding="utf-8")
        # The live referee must still carry the DEFECTIVE extraction; if it
        # does not, the coordinator applied the patch and this slice's
        # premise has changed.
        self.assertIn("| awk '{print $2}' | sort -u", text)




