"""Read-only conformance tests for the manifest checks of the referee
(``b173-accept.sh``).

The referee decides whether a B173 slice is accepted.  It consults the
slice's *manifest* (``/home/muse-newapi/b173-<slug>.files``) twice:

* as a **fallback** for finding the slice's commit, and
* (not at all) as a **claim about what the slice owns**.

Nothing checked the second use, so three defects survived in the batch:

* **D-1** the manifest names paths that do not exist (or that were never
  committed), and the referee did not notice;
* **D-2** the path-based fallback hands a slice a commit that belongs to a
  *different* slice, so a slice with no commit of its own is accepted on
  another slice's work;
* **D-3** 18 of the 79 manifests start with a junk line (the bare slug
  instead of a path), which a naive "every manifest path must exist" rule
  would turn into 18 unrelated failures.

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
PATCH_FILE = Path("/home/muse-newapi/b173-r6-manifest-integrity-fix.patch")
DESIGN_DOC = REPO_ROOT / "docs" / "design" / "r6-manifest-integrity.md"

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


def _git(repo: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return out.stdout.strip()


class _Sandbox:
    """A throwaway ``$HOME_DIR`` holding a fake repo and a fake manifest."""

    def __init__(self, root: Path, slug: str) -> None:
        self.root = root
        self.slug = slug
        self.repo = root / "northstar-agent-os"
        self.repo.mkdir(parents=True, exist_ok=True)
        _git(self.repo, "init", "-q", ".")
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


def _patched_copy(workdir: Path) -> Path:
    """Build a patched copy of the referee in ``workdir``.

    Returns the copy's path.  Raises ``unittest.SkipTest`` when the live
    script or the patch file is missing, and when the patch no longer
    applies (the live script drifted).
    """
    if not LIVE_ACCEPT.is_file():
        raise unittest.SkipTest(f"live referee not installed: {LIVE_ACCEPT}")
    if not PATCH_FILE.is_file():
        raise unittest.SkipTest(f"patch file not present: {PATCH_FILE}")
    target_dir = workdir / "accept"
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
        if "manifest_violations" in live_text:
            # The coordinator already applied the fix to the live script.
            return LIVE_ACCEPT
        raise unittest.SkipTest(f"patch does not apply any more: {res.stdout.strip()}")
    target.chmod(0o755)
    return target


def _run_accept(script: Path, sandbox: _Sandbox) -> tuple[int, list[str]]:
    env = dict(os.environ)
    env["B173_HOME_DIR"] = str(sandbox.root)
    res = subprocess.run(
        ["bash", str(script), sandbox.slug],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(sandbox.root),
    )
    lines = [ln for ln in res.stdout.splitlines() if ln.strip()]
    return res.returncode, lines


def _verdict(lines: list[str], name: str) -> str:
    for ln in lines:
        parts = ln.split()
        if len(parts) >= 2 and parts[0] in ("PASS", "FAIL", "SKIP") and parts[1] == name:
            return ln
    raise AssertionError(f"no verdict line for {name} in {lines}")


class ManifestIntegrityBase(unittest.TestCase):
    def setUp(self) -> None:
        self.workdir = Path(tempfile.mkdtemp(prefix="b173-r6-mi-"))
        self.addCleanup(shutil.rmtree, self.workdir, True)
        self.script = _patched_copy(self.workdir)

    def sandbox(self, slug: str = "probe-slice") -> _Sandbox:
        sb = _Sandbox(self.workdir / slug, slug)
        return sb


class TestManifestTruth(ManifestIntegrityBase):
    """(a)-(d): what the manifest truth check reports."""

    def _one_commit_sandbox(self, slug: str = "probe-slice") -> _Sandbox:
        sb = self.sandbox(slug)
        sb.write(f"{MODDIR}/mod_a.py", "VALUE = 1\n")
        sb.write(f"{MODDIR}/tests/test_mod_a.py", "def test_x():\n    assert True\n")
        sb.commit(
            f"B173 {slug}: sandbox base commit",
            [f"{MODDIR}/mod_a.py", f"{MODDIR}/tests/test_mod_a.py"],
        )
        return sb

    def test_a_missing_manifest_path_is_a_violation(self) -> None:
        """(a) A path the manifest names that does not exist -> FAIL."""
        sb = self._one_commit_sandbox("miss-slice")
        sb.manifest(
            [
                f"{MODDIR}/mod_a.py",
                f"{MODDIR}/tests/test_mod_a.py",
                f"{MODDIR}/mod_never_written.py",
            ]
        )
        rc, lines = _run_accept(self.script, sb)
        verdict = _verdict(lines, "COMMIT")
        self.assertTrue(verdict.startswith("FAIL "), verdict)
        self.assertIn("mod_never_written.py", verdict)
        self.assertIn("missing", verdict)
        self.assertEqual(1, rc, lines)  # FAIL -> ACCEPT: FAIL -> exit 1

    def test_b_untracked_manifest_path_is_a_violation(self) -> None:
        """(b) A path that exists on disk but is untracked -> FAIL."""
        sb = self._one_commit_sandbox("untracked-slice")
        sb.write(f"{MODDIR}/mod_ghost.py", "VALUE = 2\n")
        sb.manifest([f"{MODDIR}/mod_a.py", f"{MODDIR}/mod_ghost.py"])
        rc, lines = _run_accept(self.script, sb)
        verdict = _verdict(lines, "COMMIT")
        self.assertTrue(verdict.startswith("FAIL "), verdict)
        self.assertIn("mod_ghost.py", verdict)
        self.assertIn("untracked", verdict)
        self.assertEqual(1, rc, lines)
        # The sandbox is gone; the real repo was never touched.
        self.assertFalse((REPO_ROOT / f"{MODDIR}/mod_ghost.py").exists())

    def test_c_tracked_manifest_path_is_not_a_violation(self) -> None:
        """(c) A path that exists AND is committed -> COMMIT passes."""
        sb = self._one_commit_sandbox("clean-slice")
        sb.manifest([f"{MODDIR}/mod_a.py", f"{MODDIR}/tests/test_mod_a.py"])
        rc, lines = _run_accept(self.script, sb)
        verdict = _verdict(lines, "COMMIT")
        self.assertTrue(verdict.startswith("PASS "), verdict)
        self.assertNotIn("missing", verdict)
        self.assertNotIn("untracked", verdict)

    def test_d_junk_non_path_line_is_ignored(self) -> None:
        """(d) A bare slug line does not by itself cause a violation.

        Decision (documented in docs/design/r6-manifest-integrity.md): the
        rule IGNORES manifest lines that are not paths.  A line counts as a
        path iff it contains a "/".  The 18 junk first lines are handed to
        the coordinator as a cleanup table, but they must not fail a slice.
        """
        sb = self._one_commit_sandbox("junk-slice")
        sb.manifest(["junk-slice", f"{MODDIR}/mod_a.py"])
        rc, lines = _run_accept(self.script, sb)
        verdict = _verdict(lines, "COMMIT")
        self.assertTrue(verdict.startswith("PASS "), verdict)
        self.assertNotIn("junk-slice:", verdict)


class TestFallbackAttribution(ManifestIntegrityBase):
    """(e): the path fallback may not credit another slice's commit."""

    def _sandbox_with_foreign_commit(self, slug: str) -> _Sandbox:
        sb = self.sandbox(slug)
        sb.write(f"{MODDIR}/mod_shared.py", "VALUE = 1\n")
        sb.write(f"{MODDIR}/tests/test_mod_shared.py", "def test_x():\n    assert True\n")
        sb.commit(
            "B173 some-other-slice: a commit that merely touches the path",
            [f"{MODDIR}/mod_shared.py", f"{MODDIR}/tests/test_mod_shared.py"],
        )
        return sb

    def test_e_fallback_rejects_a_foreign_subject(self) -> None:
        sb = self._sandbox_with_foreign_commit("foreign-slice")
        sb.manifest([f"{MODDIR}/mod_shared.py"])
        _rc, lines = _run_accept(self.script, sb)
        verdict = _verdict(lines, "COMMIT")
        self.assertTrue(verdict.startswith("FAIL "), verdict)
        self.assertIn("none", verdict)

    def test_e_fallback_accepts_the_slugs_own_subject(self) -> None:
        slug = "own-slice"
        sb = self.sandbox(slug)
        sb.write(f"{MODDIR}/mod_shared.py", "VALUE = 1\n")
        sb.write(f"{MODDIR}/tests/test_mod_shared.py", "def test_x():\n    assert True\n")
        sb.commit(
            "B173 some-other-slice: touches the path first",
            [f"{MODDIR}/mod_shared.py"],
        )
        sb.commit(
            f"B173 {slug}: the slice's own commit",
            [f"{MODDIR}/tests/test_mod_shared.py"],
        )
        sb.manifest([f"{MODDIR}/mod_shared.py", f"{MODDIR}/tests/test_mod_shared.py"])
        _rc, lines = _run_accept(self.script, sb)
        verdict = _verdict(lines, "COMMIT")
        self.assertTrue(verdict.startswith("PASS "), verdict)
        # The credited commit is the slice's own, not the other slice's.
        self.assertNotIn("some-other-slice", "\n".join(lines))


class TestRefereeShape(ManifestIntegrityBase):
    """(f)-(g): the check count, the denominator and the output contract."""

    def test_f_check_count_and_denominator_are_unchanged(self) -> None:
        """(f) Exactly 12 checks, and TOTAL is still PASS+FAIL."""
        text = self.script.read_text(encoding="utf-8")
        names = set(re.findall(r"check\s+([A-Z_]+)\s+(?:PASS|FAIL|SKIP)", text))
        self.assertEqual(
            EXPECTED_CHECK_NAMES,
            names,
            "the patched referee must keep the same 12 check names",
        )
        self.assertEqual(12, len(names))
        self.assertIn("TOTAL=$((PASS+FAIL))", text)
        self.assertNotIn("TOTAL=$((PASS+FAIL+SKIP))", text)

    def test_f_no_thirteenth_check_was_added(self) -> None:
        """(f) The manifest truth is folded into COMMIT, not added as #13."""
        text = self.script.read_text(encoding="utf-8")
        # The COMMIT verdict is decided in exactly one place, and that is
        # where the manifest truth is folded in.
        # Four branches, but they are the branches of ONE verdict: the
        # check count (12) is asserted separately.
        self.assertEqual(4, len(re.findall(r"check\s+COMMIT\s+(?:PASS|FAIL)", text)))
        self.assertIn("manifest_violations", text)
        # No new check name appears.
        for extra in ("MANIFEST", "MANIFEST_TRUTH", "MANIFEST_TRUTHY"):
            self.assertNotIn(f"check {extra} ", text)

    def test_g_output_format_and_exit_codes_are_unchanged(self) -> None:
        """(g) 'PASS/FAIL/SKIP <name> <detail>' and 0 = ACCEPT PASS."""
        text = self.script.read_text(encoding="utf-8")
        self.assertIn('PASS) PASS=$((PASS+1)); echo "PASS $name $detail"', text)
        self.assertIn('FAIL) FAIL=$((FAIL+1)); echo "FAIL $name $detail"', text)
        self.assertIn('*)    SKIP=$((SKIP+1)); echo "SKIP $name $detail"', text)
        self.assertIn('echo "ACCEPT: PASS ($PASS/$TOTAL, $SKIP skipped) $SLUG"; exit 0', text)
        self.assertIn('echo "ACCEPT: FAIL ($PASS/$TOTAL, $SKIP skipped) $SLUG"; exit 1', text)

    def test_g_verdict_lines_keep_the_three_field_shape(self) -> None:
        """(g) Every verdict line the referee prints still has its shape."""
        sb = self.sandbox("shape-slice")
        sb.write(f"{MODDIR}/mod_a.py", "VALUE = 1\n")
        sb.write(f"{MODDIR}/tests/test_mod_a.py", "def test_x():\n    assert True\n")
        sb.commit(
            "B173 shape-slice: sandbox base commit",
            [f"{MODDIR}/mod_a.py", f"{MODDIR}/tests/test_mod_a.py"],
        )
        sb.manifest([f"{MODDIR}/mod_a.py"])
        rc, lines = _run_accept(self.script, sb)
        verdicts = [
            ln for ln in lines
            if ln.split() and ln.split()[0] in ("PASS", "FAIL", "SKIP")
        ]
        self.assertEqual(12, len(verdicts), verdicts)
        for ln in verdicts:
            parts = ln.split()
            self.assertIn(parts[0], ("PASS", "FAIL", "SKIP"))
            self.assertIn(parts[1], EXPECTED_CHECK_NAMES)
        # A FAIL verdict means exit 1; a fully passing run means exit 0.
        self.assertIn(rc, (0, 1))
        self.assertEqual(any(v.startswith("FAIL ") for v in verdicts), rc == 1)


class TestNoManifest(ManifestIntegrityBase):
    """(h): a slice with no manifest must not fail for a new reason."""

    def test_h_missing_manifest_does_not_fail_commit(self) -> None:
        sb = self.sandbox("nomanifest-slice")
        sb.write(f"{MODDIR}/mod_a.py", "VALUE = 1\n")
        sb.write(f"{MODDIR}/tests/test_mod_a.py", "def test_x():\n    assert True\n")
        sb.commit(
            "B173 nomanifest-slice: sandbox base commit",
            [f"{MODDIR}/mod_a.py", f"{MODDIR}/tests/test_mod_a.py"],
        )
        # No manifest file at all.
        _rc, lines = _run_accept(self.script, sb)
        verdict = _verdict(lines, "COMMIT")
        self.assertTrue(verdict.startswith("PASS "), verdict)
        self.assertNotIn("manifest:", verdict)

    def test_h_empty_manifest_does_not_fail_commit(self) -> None:
        sb = self.sandbox("emptymanifest-slice")
        sb.write(f"{MODDIR}/mod_a.py", "VALUE = 1\n")
        sb.write(f"{MODDIR}/tests/test_mod_a.py", "def test_x():\n    assert True\n")
        sb.commit(
            "B173 emptymanifest-slice: sandbox base commit",
            [f"{MODDIR}/mod_a.py", f"{MODDIR}/tests/test_mod_a.py"],
        )
        sb.manifest([])
        _rc, lines = _run_accept(self.script, sb)
        verdict = _verdict(lines, "COMMIT")
        self.assertTrue(verdict.startswith("PASS "), verdict)


class TestInRepoOnly(unittest.TestCase):
    """(i): a test that depends only on in-repository files."""

    def test_i_design_doc_exists_and_has_the_before_after_table(self) -> None:
        self.assertTrue(
            DESIGN_DOC.is_file(),
            f"missing design doc: {DESIGN_DOC}",
        )
        text = DESIGN_DOC.read_text(encoding="utf-8")
        self.assertIn("## The precise change specification", text)
        self.assertIn("| slice | before | after |", text)
        for slug in (
            "acceptance-conformance",
            "capability-ceiling-probe",
            "refusal-hold-wiring",
            "merged-tree-review",
            "judge-hygiene",
            "r6-12-session-resolution",
        ):
            self.assertIn(slug, text)

    def test_i_design_doc_records_the_three_defects(self) -> None:
        text = DESIGN_DOC.read_text(encoding="utf-8")
        for marker in (
            "Defect 1",
            "Defect 2",
            "Defect 3",
            "junk",
            "12",
        ):
            self.assertIn(marker, text)
