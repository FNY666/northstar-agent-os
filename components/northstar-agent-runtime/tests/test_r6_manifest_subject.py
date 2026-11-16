"""Read-only conformance tests for the R6-2 attribution fix.

R6-2 (round-6 candidate, rank 1) is the defect that the referee used the
**path-based fallback** as if it were an **attribution** rule::

    SLICE_HASHES=$(git log --format=%H --grep="^B173 ${SLUG}:" -i | head -20)
    if [ -z "$SLICE_HASHES" ] && [ -f "$MANIFEST" ]; then
      SLICE_HASHES=$(git log --format=%H -1 -- $(cat "$MANIFEST" | tr '\n' ' '))
    fi

The fallback takes "the newest commit that touched any path named in the
manifest" and never checks that commit's subject.  A slice that only edited
files another slice also owns therefore inherits that slice's commit and is
judged on it.

The fix separates the two questions:

* **attribution** (``COMMIT``) only accepts a commit whose subject is
  ``B173 <slug>:``; the fallback candidate is rejected unless its subject
  matches;
* **evidence** (``NEW_TESTS`` / ``WORKTREE_CLEAN`` / ``TESTS_RAN`` /
  ``MUTANT``) still uses the path-based fallback, so those verdicts do not
  move when attribution tightens.

These tests assert the **behaviour** of the referee, not the text of its
source.  The live ``/home/muse-newapi/b173-accept.sh`` is the judge's own
file and is **never modified**: the tests build a patched copy of it in a
temporary directory (by applying the three round-6 patch files in order)
and run that copy against throwaway sandbox repositories created with
``tempfile.mkdtemp()`` and removed again with ``shutil.rmtree()``.

The behavioural tests skip cleanly when the outside-the-repo artefacts are
absent (the live script, the patch files).  The last test class depends
only on in-repository files, so this file remains meaningful without them.

No runtime ``.py`` module is added by this slice, so there is nothing to
register in ``runtime_registration.py`` / ``pyproject.toml``.
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

# The referee as it was BEFORE the round-6 patches.  The integrated referee
# is built from this, not from the live script, so these tests keep their
# coverage whether or not the coordinator has applied the patches yet.
# (2026-11-16: building from the live script made every test in the class
# skip once the patches were applied, because `patch` then correctly reports
# "Reversed (or previously applied)".  A test that silently stops testing is
# worse than no test.)
BASE_ACCEPT = Path("/home/muse-newapi/b173-accept.sh.preround6")
PATCH_FILES = [
    Path("/home/muse-newapi/b173-r6-manifest-integrity-fix.patch"),
    Path("/home/muse-newapi/b173-r6-check-accuracy-fix.patch"),
    Path("/home/muse-newapi/b173-r6-12-session-resolution-fix.patch"),
]
DESIGN_DOC = REPO_ROOT / "docs" / "design" / "r6-manifest-subject.md"

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
TEST_BODY = (
    "import unittest\n\n\n"
    "class SandboxTests(unittest.TestCase):\n"
    "    def test_sandbox_module_is_importable(self):\n"
    "        self.assertTrue(True)\n"
)


def _git(repo: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return out.stdout.strip()


def run(cmd, cwd=None, env=None):
    """Run a command, returning (rc, stdout, stderr)."""
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout, proc.stderr


class _Sandbox:
    """A throwaway ``$HOME_DIR`` holding a fake repo and a fake manifest.

    The referee reads ``$HOME_DIR/northstar-agent-os`` as the repository and
    ``$HOME_DIR/b173-<slug>.files`` as the slice's manifest, so the sandbox
    has to look like a small home directory.
    """

    def __init__(self, root: Path, slug: str) -> None:
        self.root = root
        self.slug = slug
        self.repo = root / "northstar-agent-os"
        self.repo.mkdir(parents=True, exist_ok=True)
        _git(self.repo, "init", "-q", "-b", "main", ".")
        _git(self.repo, "config", "user.email", "sandbox@example.invalid")
        _git(self.repo, "config", "user.name", "sandbox")

    def write(self, relpath: str, content: str) -> Path:
        p = self.repo / relpath
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def commit(self, subject: str, paths: list[str]) -> str:
        for rel in paths:
            _git(self.repo, "add", "--", rel)
        _git(self.repo, "commit", "-q", "-m", subject)
        return _git(self.repo, "rev-parse", "HEAD")

    def manifest(self, lines: list[str]) -> Path:
        p = self.root / f"b173-{self.slug}.files"
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return p

    def report(self, text: str) -> Path:
        p = self.root / f"b173-{self.slug}-cc-final.txt"
        p.write_text(text, encoding="utf-8")
        return p

    def taskbook(self, text: str) -> Path:
        p = self.root / f"b173-{self.slug}-cc-prompt-rerun.md"
        p.write_text(text, encoding="utf-8")
        return p


def _integrated_copy(workdir: Path) -> Path:
    """Build the integrated referee in ``workdir``.

    Copies the live ``b173-accept.sh`` and applies the three round-6
    patches **in order**.  Raises ``unittest.SkipTest`` when the live script
    or a patch file is missing, or when a patch no longer applies.
    """
    if not LIVE_ACCEPT.is_file():
        raise unittest.SkipTest(f"live referee not installed: {LIVE_ACCEPT}")
    for pf in PATCH_FILES:
        if not pf.is_file():
            raise unittest.SkipTest(f"patch file not present: {pf}")
    target_dir = workdir / "integrated"
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / "b173-accept.sh"
    # Build from the PRE-round-6 referee when it is available, so these
    # tests keep their coverage whether or not the coordinator has applied
    # the round-6 patches to the live script yet.  (2026-11-16: building
    # from the live script made 10 of 12 tests skip once the patches were
    # applied, because `patch` then reports "Reversed (or previously
    # applied)" -- a test that silently stops testing is worse than no
    # test.)  Fall back to the live script when the base is absent.
    source = BASE_ACCEPT if BASE_ACCEPT.is_file() else LIVE_ACCEPT
    shutil.copyfile(source, target)
    for pf in PATCH_FILES:
        res = subprocess.run(
            ["patch", "-p1", "-d", str(target_dir)],
            input=pf.read_text(encoding="utf-8"),
            capture_output=True,
            text=True,
        )
        if res.returncode != 0:
            raise unittest.SkipTest(
                f"patch does not apply any more ({pf.name}): "
                f"{res.stdout.strip()} {res.stderr.strip()}"
            )
    target.chmod(0o755)
    return target


def _run_accept(script: Path, sandbox: _Sandbox):
    """Run the referee against a sandbox; returns (rc, stdout)."""
    env = dict(os.environ)
    env["B173_HOME_DIR"] = str(sandbox.root)
    res = subprocess.run(
        ["bash", str(script), sandbox.slug],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(sandbox.root),
    )
    return res.returncode, res.stdout


def _verdict(stdout: str, name: str) -> str:
    for ln in stdout.splitlines():
        parts = ln.split()
        if len(parts) >= 2 and parts[0] in ("PASS", "FAIL", "SKIP") and parts[1] == name:
            return ln
    raise AssertionError(f"no verdict line for {name} in {stdout}")


def _accept_line(stdout: str) -> str:
    for ln in stdout.splitlines():
        if ln.startswith("ACCEPT:"):
            return ln
    raise AssertionError(f"no ACCEPT line in {stdout}")


class SubjectBase(unittest.TestCase):
    """Base: an integrated referee copy plus a sandbox helper."""

    def setUp(self) -> None:
        self.workdir = Path(tempfile.mkdtemp(prefix="b173-r6-subject-"))
        self.addCleanup(shutil.rmtree, self.workdir, True)
        self.script = _integrated_copy(self.workdir)

    def sandbox(self, slug: str) -> _Sandbox:
        root = self.workdir / slug
        root.mkdir(parents=True, exist_ok=True)
        return _Sandbox(root, slug)

    def _slice_with_module(self, sb: _Sandbox, subject: str) -> str:
        """Write a module + a test file and commit them under ``subject``."""
        sb.write(f"{MODDIR}/mod_a.py", "VALUE = 1\n")
        sb.write(f"{MODDIR}/tests/test_mod_a.py", TEST_BODY)
        return sb.commit(
            subject,
            [f"{MODDIR}/mod_a.py", f"{MODDIR}/tests/test_mod_a.py"],
        )


class TestAttributionSubjectCheck(SubjectBase):
    """(a)-(c): the COMMIT gate only credits this slice's own commits."""

    def test_a_foreign_subject_is_not_credited_as_this_slice(self) -> None:
        """(a) A commit whose subject belongs to another slug is rejected."""
        sb = self.sandbox("own-slice")
        sb.write(f"{MODDIR}/mod_a.py", "VALUE = 1\n")
        sb.write(f"{MODDIR}/tests/test_mod_a.py", TEST_BODY)
        foreign = sb.commit(
            "B173 other-slice: work that belongs to another slice",
            [f"{MODDIR}/mod_a.py", f"{MODDIR}/tests/test_mod_a.py"],
        )
        # The manifest names the paths, so the path fallback finds `foreign`.
        sb.manifest([f"{MODDIR}/mod_a.py", f"{MODDIR}/tests/test_mod_a.py"])
        rc, out = _run_accept(self.script, sb)
        verdict = _verdict(out, "COMMIT")
        self.assertTrue(verdict.startswith("FAIL "), verdict)
        self.assertNotIn(foreign[:8], verdict, verdict)
        self.assertEqual(1, rc, out)

    def test_b_own_subject_is_credited(self) -> None:
        """(b) A commit whose subject is 'B173 <slug>: ...' is accepted."""
        sb = self.sandbox("own-slice")
        sb.write(f"{MODDIR}/mod_a.py", "VALUE = 1\n")
        sb.write(f"{MODDIR}/tests/test_mod_a.py", TEST_BODY)
        own = sb.commit(
            "B173 own-slice: my own work",
            [f"{MODDIR}/mod_a.py", f"{MODDIR}/tests/test_mod_a.py"],
        )
        sb.manifest([f"{MODDIR}/mod_a.py", f"{MODDIR}/tests/test_mod_a.py"])
        rc, out = _run_accept(self.script, sb)
        verdict = _verdict(out, "COMMIT")
        self.assertTrue(verdict.startswith("PASS "), verdict)
        self.assertIn(own[:8], verdict, verdict)

    def test_c_slice_without_own_commit_fails_commit(self) -> None:
        """(c) No commit of its own -> COMMIT FAIL, not a foreign commit."""
        sb = self.sandbox("own-slice")
        sb.write(f"{MODDIR}/mod_a.py", "VALUE = 1\n")
        sb.write(f"{MODDIR}/tests/test_mod_a.py", TEST_BODY)
        foreign = sb.commit(
            "B173 other-slice: work that belongs to another slice",
            [f"{MODDIR}/mod_a.py", f"{MODDIR}/tests/test_mod_a.py"],
        )
        sb.manifest([f"{MODDIR}/mod_a.py", f"{MODDIR}/tests/test_mod_a.py"])
        rc, out = _run_accept(self.script, sb)
        verdict = _verdict(out, "COMMIT")
        self.assertTrue(verdict.startswith("FAIL "), verdict)
        self.assertNotIn(foreign[:8], verdict, verdict)
        # The detail names the reason, not just a hash.
        self.assertRegex(verdict, r"^FAIL COMMIT (none|manifest:)")
        self.assertEqual(1, rc, out)

    def test_c2_unrelated_commit_is_also_rejected(self) -> None:
        """(c') A commit with no 'B173 <slug>:' prefix is rejected too."""
        sb = self.sandbox("own-slice")
        sb.write(f"{MODDIR}/mod_a.py", "VALUE = 1\n")
        sb.write(f"{MODDIR}/tests/test_mod_a.py", TEST_BODY)
        sb.commit(
            "chore: an unrelated commit that touches the manifest path",
            [f"{MODDIR}/mod_a.py", f"{MODDIR}/tests/test_mod_a.py"],
        )
        sb.manifest([f"{MODDIR}/mod_a.py", f"{MODDIR}/tests/test_mod_a.py"])
        rc, out = _run_accept(self.script, sb)
        verdict = _verdict(out, "COMMIT")
        self.assertTrue(verdict.startswith("FAIL "), verdict)
        self.assertEqual(1, rc, out)


class TestAttributionSeparatedFromEvidence(SubjectBase):
    """(d) The content checks still see the path-based fallback."""

    def test_d_content_checks_still_use_the_path_fallback(self) -> None:
        """(d) NEW_TESTS still counts the fallback commit's test methods.

        The slice has no commit of its own, so COMMIT fails -- but the
        *content* checks keep reading the code through the path-based
        fallback, exactly as before the fix.  If the fallback were removed
        from the content checks too, NEW_TESTS would flip to FAIL and the
        two questions ("whose work is this?" / "is there enough evidence?")
        would be mixed into one verdict.
        """
        sb = self.sandbox("own-slice")
        sb.write(f"{MODDIR}/mod_a.py", "VALUE = 1\n")
        sb.write(f"{MODDIR}/tests/test_mod_a.py", TEST_BODY)
        sb.commit(
            "B173 other-slice: work that belongs to another slice",
            [f"{MODDIR}/mod_a.py", f"{MODDIR}/tests/test_mod_a.py"],
        )
        sb.manifest([f"{MODDIR}/mod_a.py", f"{MODDIR}/tests/test_mod_a.py"])
        rc, out = _run_accept(self.script, sb)
        commit = _verdict(out, "COMMIT")
        new_tests = _verdict(out, "NEW_TESTS")
        self.assertTrue(commit.startswith("FAIL "), commit)
        self.assertTrue(new_tests.startswith("PASS "), new_tests)
        self.assertIn("new test methods", new_tests)

    def test_d2_tested_files_are_still_re_run_through_the_fallback(self) -> None:
        """(d') TESTS_RAN still re-runs the fallback commit's test file."""
        sb = self.sandbox("own-slice")
        sb.write(f"{MODDIR}/mod_a.py", "VALUE = 1\n")
        sb.write(f"{MODDIR}/tests/test_mod_a.py", TEST_BODY)
        sb.commit(
            "B173 other-slice: work that belongs to another slice",
            [f"{MODDIR}/mod_a.py", f"{MODDIR}/tests/test_mod_a.py"],
        )
        sb.manifest([f"{MODDIR}/mod_a.py", f"{MODDIR}/tests/test_mod_a.py"])
        rc, out = _run_accept(self.script, sb)
        tests_ran = _verdict(out, "TESTS_RAN")
        self.assertTrue(tests_ran.startswith("PASS "), tests_ran)
        self.assertIn("unittest", tests_ran)


class TestIntegratedScriptShape(SubjectBase):
    """(e)-(g): the three patches apply in sequence and the shape holds."""

    def test_e_the_three_patches_apply_in_sequence(self) -> None:
        """(e) Patches apply cleanly in order; the result passes 'bash -n'."""
        for pf in PATCH_FILES:
            self.assertTrue(pf.is_file(), f"missing patch: {pf}")
        target_dir = self.workdir / "seq"
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / "b173-accept.sh"
        # From the PRE-round-6 referee when available: the live script may
        # already carry the patches, and then `patch` correctly reports
        # "Reversed (or previously applied)" and this test would fail for
        # a reason that has nothing to do with what it is testing.
        source = BASE_ACCEPT if BASE_ACCEPT.is_file() else LIVE_ACCEPT
        shutil.copyfile(source, target)
        applied = []
        for pf in PATCH_FILES:
            res = subprocess.run(
                ["patch", "-p1", "-d", str(target_dir)],
                input=pf.read_text(encoding="utf-8"),
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                0, res.returncode,
                f"{pf.name} did not apply: {res.stdout} {res.stderr}",
            )
            self.assertNotIn("FAILED", res.stdout, res.stdout)
            self.assertNotIn("Reversed", res.stdout, res.stdout)
            applied.append(pf.name)
        self.assertEqual(3, len(applied))
        rc, out, err = run(["bash", "-n", str(target)])
        self.assertEqual(0, rc, f"bash -n failed: {out} {err}")

    def test_f_the_integrated_script_keeps_twelve_checks(self) -> None:
        """(f) Exactly 12 distinct check names, and the same denominator."""
        text = self.script.read_text(encoding="utf-8")
        names = set()
        for line in text.splitlines():
            stripped = line.strip()
            # "check NAME VERDICT detail" is the direct call; the REPORT and
            # FABLE_VERIF checks are written as "check ... && check NAME ...".
            if stripped.startswith("check "):
                names.add(stripped.split()[1])
            elif "&& check " in stripped:
                names.add(stripped.split("&& check ", 1)[1].split()[0])
            elif "|| check " in stripped:
                names.add(stripped.split("|| check ", 1)[1].split()[0])
            elif "then check " in stripped:
                names.add(stripped.split("then check ", 1)[1].split()[0])
            elif "else check " in stripped:
                names.add(stripped.split("else check ", 1)[1].split()[0])
        self.assertEqual(EXPECTED_CHECK_NAMES, names)
        self.assertEqual(12, len(names))
        self.assertIn("TOTAL=$((PASS+FAIL))", text)

    def test_g_exit_codes_and_line_format_are_unchanged(self) -> None:
        """(g) 0 = ACCEPT PASS, 1 = ACCEPT FAIL; 'PASS <name> <detail>'."""
        sb = self.sandbox("good-slice")
        self._slice_with_module(sb, "B173 good-slice: my own work")
        sb.manifest([f"{MODDIR}/mod_a.py", f"{MODDIR}/tests/test_mod_a.py"])
        sb.report("CANARY: abc\nFABLE VERIFICATION\nfull suite Ran 19000 tests\n"
                  "161/169\n")
        sb.taskbook("CANARY: abc\n")
        rc, out = _run_accept(self.script, sb)
        # Every check is green or skipped -> ACCEPT: PASS -> exit 0.
        self.assertEqual(0, rc, out)
        self.assertTrue(_accept_line(out).startswith("ACCEPT: PASS"), out)
        for line in out.splitlines():
            parts = line.split()
            if parts and parts[0] in ("PASS", "FAIL", "SKIP"):
                self.assertIn(parts[1], EXPECTED_CHECK_NAMES, line)
                if parts[1] == "COMMIT":
                    self.assertTrue(
                        line.startswith(("PASS COMMIT ", "FAIL COMMIT ",
                                         "SKIP COMMIT ")),
                        line,
                    )
        # A slice that owns no commit gets COMMIT FAIL -> exit 1.
        sb2 = self.sandbox("bad-slice")
        sb2.write(f"{MODDIR}/mod_a.py", "VALUE = 2\n")
        sb2.write(f"{MODDIR}/tests/test_mod_b.py", TEST_BODY)
        sb2.commit(
            "B173 other-slice: foreign work",
            [f"{MODDIR}/mod_a.py", f"{MODDIR}/tests/test_mod_b.py"],
        )
        sb2.manifest([f"{MODDIR}/mod_a.py", f"{MODDIR}/tests/test_mod_a.py"])
        sb2.report("CANARY: abc\nFABLE VERIFICATION\nfull suite Ran 19000 tests\n"
                   "161/169\n")
        sb2.taskbook("CANARY: abc\n")
        rc2, out2 = _run_accept(self.script, sb2)
        self.assertEqual(1, rc2, out2)
        self.assertTrue(_accept_line(out2).startswith("ACCEPT: FAIL"), out2)
        self.assertTrue(_verdict(out2, "COMMIT").startswith("FAIL "), out2)


class TestDeterminism(SubjectBase):
    """(h) The integrated referee gives the same answer twice."""

    def test_h_two_consecutive_runs_agree(self) -> None:
        """(h) Two runs on the same slice produce the same ACCEPT: line."""
        sb = self.sandbox("probe-slice")
        self._slice_with_module(sb, "B173 probe-slice: my own work")
        sb.manifest([f"{MODDIR}/mod_a.py", f"{MODDIR}/tests/test_mod_a.py"])
        sb.report("CANARY: abc\nFABLE VERIFICATION\nfull suite Ran 19000 tests\n"
                  "161/169\n")
        sb.taskbook("CANARY: abc\n")
        rc1, out1 = _run_accept(self.script, sb)
        rc2, out2 = _run_accept(self.script, sb)
        self.assertEqual(_accept_line(out1), _accept_line(out2))
        self.assertEqual(rc1, rc2)
        # The whole verdict set is identical, not just the summary line.
        checks1 = [ln for ln in out1.splitlines()
                   if ln.startswith(("PASS ", "FAIL ", "SKIP "))]
        checks2 = [ln for ln in out2.splitlines()
                   if ln.startswith(("PASS ", "FAIL ", "SKIP "))]
        self.assertEqual(checks1, checks2)


class TestInRepoArtefacts(unittest.TestCase):
    """(i) The slice's own in-repo artefacts, independent of the outside."""

    def test_i_design_doc_exists_and_carries_the_before_after_table(self) -> None:
        """(i) The design doc names the two mis-attributed slices."""
        self.assertTrue(DESIGN_DOC.is_file(), f"missing: {DESIGN_DOC}")
        text = DESIGN_DOC.read_text(encoding="utf-8")
        self.assertIn("acceptance-conformance", text)
        self.assertIn("capability-ceiling-probe", text)
        self.assertIn("orphan-adoption", text)
        # The doc must show the before/after verdict table, not just prose.
        self.assertIn("OLD", text)
        self.assertIn("NEW", text)
        self.assertIn("ACCEPT:", text)

    def test_i2_the_patch_files_are_named_in_the_design_doc(self) -> None:
        """(i') The doc names the three patches and their order."""
        self.assertTrue(DESIGN_DOC.is_file(), f"missing: {DESIGN_DOC}")
        text = DESIGN_DOC.read_text(encoding="utf-8")
        for pf in PATCH_FILES:
            self.assertIn(pf.name, text)
        # The watch patch targets b173-watch.sh, not the accept script.
        self.assertIn("b173-r6-12-watch-session-resolution-fix.patch", text)
