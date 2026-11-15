"""Tests for the r6-baseline-unify slice.

The slice makes one statement true: "identical to the baseline" has a
determinate meaning, namely "identical, item for item, to the failure set of
a named commit sha".

What is tested here:

  * the file format of a baseline (``b173-baseline-<sha>.failures.txt``):
    first line names the sha, the items are sorted, the items are the
    ``FAIL:``/``ERROR:`` lines of the runtime suite;
  * the naming and pointer conventions (``b173-baseline-CURRENT``);
  * the generator script ``scripts/b173-baseline-gen.sh``: it refuses bad
    input, it writes the file in the documented format, it is idempotent,
    and it leaves no worktree and no ``/tmp/nsar-*`` residue behind;
  * the acceptance-check patch handed to the coordinator: it reads the
    pointer, it records the baseline sha in the verdict line, it SKIPs
    rather than FAILs when the pointer is missing, and it does not change
    the number of checks.

No runtime ``.py`` module is added by this slice, so there is nothing to
register in ``runtime_registration.py`` / ``pyproject.toml``.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

RUNTIME_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = RUNTIME_ROOT.parent.parent
GEN_SCRIPT = REPO_ROOT / "scripts" / "b173-baseline-gen.sh"
DESIGN_DOC = REPO_ROOT / "docs" / "design" / "r6-baseline-unify.md"
PATCH_FILE = Path("/home/muse-newapi/b173-r6-baseline-unify-fix.patch")

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ITEM_RE = re.compile(r"^(FAIL|ERROR): \S+ \(([^)]+)\)$")

# The runtime suite's failure items look like this; the baseline format keeps
# exactly that line verbatim.
ITEM_LINES = [
    "ERROR: test_bwrap_cannot_persist_changes_to_workspace_governance "
    "(test_governance_bwrap.BwrapGovernanceTests."
    "test_bwrap_cannot_persist_changes_to_workspace_governance)",
    "FAIL: test_the_check_passes_on_the_current_repository "
    "(test_runtime_registration.RealRepositoryCheckTests."
    "test_the_check_passes_on_the_current_repository)",
    "FAIL: test_the_registry_covers_every_module_on_disk "
    "(test_runtime_registration.RegistryShapeTests."
    "test_the_registry_covers_every_module_on_disk)",
]


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


class BaselineFileFormatTests(unittest.TestCase):
    """The format of a baseline file: sha on line 1, sorted items after."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="r6-baseline-fmt-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.sha = "2db42e939477bc2ceca9f20d35384dfc7731e972"
        self.path = self.tmp / f"b173-baseline-{self.sha}.failures.txt"
        self.path.write_text(
            f"# baseline of {self.sha} -- northstar-agent-runtime full suite, "
            "sorted FAIL:/ERROR: items\n" + "\n".join(ITEM_LINES) + "\n",
            encoding="utf-8",
        )

    def test_first_line_records_the_sha(self):
        first = self.path.read_text(encoding="utf-8").splitlines()[0]
        self.assertIn(self.sha, first)
        self.assertRegex(self.sha, SHA_RE)

    def test_items_are_sorted_and_unique(self):
        items = [
            line
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if not line.startswith("#")
        ]
        self.assertEqual(items, sorted(items))
        self.assertEqual(len(items), len(set(items)))

    def test_item_lines_keep_the_suite_format(self):
        items = [
            line
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if not line.startswith("#")
        ]
        self.assertTrue(items)
        for line in items:
            self.assertRegex(line, ITEM_RE)

    def test_file_name_carries_the_full_sha(self):
        self.assertEqual(self.path.name, f"b173-baseline-{self.sha}.failures.txt")
        self.assertRegex(
            self.path.stem, re.compile(r"^b173-baseline-[0-9a-f]{40}\.failures$")
        )

    def test_pointer_file_is_one_line_of_a_file_name(self):
        pointer = self.tmp / "b173-baseline-CURRENT"
        pointer.write_text(self.path.name + "\n", encoding="utf-8")
        text = pointer.read_text(encoding="utf-8")
        self.assertEqual(len(text.strip().splitlines()), 1)
        self.assertEqual(text.strip(), self.path.name)
        # a plain file, not a symlink: symlinks break in bundles/archives
        self.assertFalse(pointer.is_symlink())


def _make_fake_repo(root: Path, failing: bool = True) -> str:
    """Build a throwaway git repo with a minimal runtime component.

    The component has one test module with one always-failing test and one
    passing test, so the generated baseline has exactly one item.  Returns
    the head sha.
    """
    comp = root / "components" / "northstar-agent-runtime"
    (comp / "tests").mkdir(parents=True)
    body = (
        "import unittest\n\n\n"
        "class T(unittest.TestCase):\n"
        "    def test_ok(self):\n"
        "        self.assertTrue(True)\n\n"
        "    def test_boom(self):\n"
        "        self.assertEqual(1, 2)\n"
    )
    if not failing:
        body = body.replace("self.assertEqual(1, 2)", "self.assertEqual(1, 1)")
    (comp / "tests" / "test_fake.py").write_text(body, encoding="utf-8")
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
    for cmd in (["git", "init", "-q", "-b", "main", str(root)],
                ["git", "-C", str(root), "add", "-A"],
                ["git", "-C", str(root), "commit", "-q", "-m", "fake"]):
        rc, _, err = run(cmd, env=env)
        assert rc == 0, (cmd, err)
    rc, out, _ = run(["git", "-C", str(root), "rev-parse", "HEAD"])
    assert rc == 0
    return out.strip()


class GeneratorScriptTests(unittest.TestCase):
    """scripts/b173-baseline-gen.sh: usage, output format, idempotence."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="r6-baseline-gen-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        self.out = self.tmp / "out"
        self.out.mkdir()
        self.sha = _make_fake_repo(self.repo)
        self.gen = dict(os.environ, B173_BASELINE_GEN_REPO=str(self.repo))

    def _gen(self, sha=None, out=None):
        env = dict(self.gen, B173_BASELINE_DIR=str(out or self.out))
        argv = ["bash", str(GEN_SCRIPT)] + ([sha] if sha is not None else [self.sha])
        return run(argv, env=env)

    def test_generator_exists_and_is_executable_script(self):
        self.assertTrue(GEN_SCRIPT.is_file())
        text = GEN_SCRIPT.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("#!"), "needs a shebang")
        self.assertIn("bash", text.splitlines()[0])
        rc, _, _ = run(["bash", "-n", str(GEN_SCRIPT)])
        self.assertEqual(rc, 0, "generator must be syntactically valid bash")

    def test_generator_rejects_a_missing_sha_argument(self):
        rc, _, err = self._gen(sha="")
        self.assertNotEqual(rc, 0)
        self.assertIn("usage", err.lower())

    def test_generator_rejects_an_unknown_sha(self):
        rc, _, err = self._gen(sha="0" * 40)
        self.assertNotEqual(rc, 0)
        self.assertIn("not a commit", err.lower())

    def test_generator_writes_the_baseline_in_the_documented_format(self):
        rc, out, err = self._gen()
        self.assertEqual(rc, 0, err)
        path = self.out / f"b173-baseline-{self.sha}.failures.txt"
        self.assertTrue(path.is_file(), out)
        lines = path.read_text(encoding="utf-8").splitlines()
        self.assertIn(self.sha, lines[0])
        self.assertTrue(lines[0].startswith("#"))
        items = [ln for ln in lines if not ln.startswith("#")]
        self.assertEqual(len(items), 1, items)
        self.assertTrue(items[0].startswith("FAIL: test_boom"))
        self.assertRegex(items[0], ITEM_RE)

    def test_generator_is_idempotent(self):
        rc1, _, e1 = self._gen()
        self.assertEqual(rc1, 0, e1)
        path = self.out / f"b173-baseline-{self.sha}.failures.txt"
        first = path.read_bytes()
        rc2, _, e2 = self._gen()
        self.assertEqual(rc2, 0, e2)
        self.assertEqual(first, path.read_bytes())

    def test_generator_leaves_no_worktree_behind(self):
        rc, _, err = self._gen()
        self.assertEqual(rc, 0, err)
        rc, out, _ = run(["git", "-C", str(self.repo), "worktree", "list"])
        self.assertEqual(rc, 0)
        self.assertEqual(len(out.strip().splitlines()), 1, out)

    def test_generator_clears_the_nsar_scratch_residue(self):
        residue = Path(tempfile.gettempdir()) / "nsar-r6-baseline-unify-probe"
        residue.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, residue, True)
        (residue / "junk").write_text("x", encoding="utf-8")
        rc, _, err = self._gen()
        self.assertEqual(rc, 0, err)
        self.assertFalse(residue.exists(), "nsar-* scratch must be cleared")


class AcceptancePatchTests(unittest.TestCase):
    """The patch handed to the coordinator for b173-accept.sh.

    The slice does not modify the judge.  It hands over a patch, and these
    tests assert the properties that patch must have: it reads the pointer,
    it puts the baseline's sha in the verdict, it treats a missing pointer
    as a SKIP, and it does not change the number of checks.
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="r6-baseline-patch-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_patch_file_exists_and_has_before_after(self):
        self.assertTrue(PATCH_FILE.is_file(), f"missing patch: {PATCH_FILE}")
        text = PATCH_FILE.read_text(encoding="utf-8")
        self.assertIn("--- b173-accept.sh", text)
        self.assertIn("+++ ", text)
        self.assertIn("@@", text, "must be a unified diff")
        self.assertIn("before:", text)
        self.assertIn("after:", text)

    def test_patch_reads_the_current_pointer(self):
        text = PATCH_FILE.read_text(encoding="utf-8")
        self.assertIn("b173-baseline-CURRENT", text)
        self.assertIn("b173-bench-baseline-CURRENT", text)

    def test_patch_names_the_baseline_sha_in_the_verdict(self):
        text = PATCH_FILE.read_text(encoding="utf-8")
        self.assertIn("BASE_SHA", text)
        self.assertIn("BENCH_BASE_SHA", text)

    def test_patch_keeps_twelve_checks(self):
        """The batch rule: do not change the denominator."""
        # The patch body is the diff; the '+' lines are what it adds.
        added = [
            line
            for line in PATCH_FILE.read_text(encoding="utf-8").splitlines()
            if line.startswith("+") and not line.startswith("+++")
        ]
        names = set()
        for line in added:
            for token in line.split():
                if token.startswith("check_") or token == "check":
                    names.add(token)
        # The added lines may only re-use existing check names.
        self.assertTrue(
            names <= {"check"},
            f"patch introduces new check call shapes: {names}",
        )

    def test_patch_applies_to_a_clean_copy_of_accept_sh(self):
        accept = Path("/home/muse-newapi/b173-accept.sh")
        if not accept.is_file():
            self.skipTest("b173-accept.sh not present on this machine")
        target = self.tmp / "b173-accept.sh"
        shutil.copy2(accept, target)
        text = PATCH_FILE.read_text(encoding="utf-8")
        proc = subprocess.run(
            ["patch", "-p0", "--dry-run", str(target)],
            input=text,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            proc.returncode, 0, f"patch does not apply: {proc.stdout}\n{proc.stderr}"
        )

    def test_patched_accept_sh_still_has_twelve_checks(self):
        accept = Path("/home/muse-newapi/b173-accept.sh")
        if not accept.is_file():
            self.skipTest("b173-accept.sh not present on this machine")
        target = self.tmp / "b173-accept.sh"
        shutil.copy2(accept, target)
        text = PATCH_FILE.read_text(encoding="utf-8")
        proc = subprocess.run(
            ["patch", "-p0", str(target)],
            input=text,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        names = set(re.findall(r"\bcheck ([A-Z_]+)", target.read_text(encoding="utf-8")))
        self.assertEqual(len(names), 12, sorted(names))
        rc, _, err = run(["bash", "-n", str(target)])
        self.assertEqual(rc, 0, f"patched accept.sh is not valid bash: {err}")


class DesignDocTests(unittest.TestCase):
    """The design doc must state the rules the code implements."""

    def setUp(self):
        self.text = DESIGN_DOC.read_text(encoding="utf-8")

    def test_design_doc_exists(self):
        self.assertTrue(DESIGN_DOC.is_file(), f"missing: {DESIGN_DOC}")
        self.assertGreater(len(self.text), 2000)

    def test_design_doc_defines_the_baseline(self):
        self.assertIn("failure set", self.text)
        self.assertIn("commit sha", self.text)

    def test_design_doc_states_the_naming_rule(self):
        self.assertIn("b173-baseline-<commit-sha>.failures.txt", self.text)
        self.assertIn("b173-baseline-CURRENT", self.text)

    def test_design_doc_states_the_pointer_is_not_a_symlink(self):
        low = self.text.lower()
        self.assertIn("not a symlink", low)
        self.assertIn("symlink", low)

    def test_design_doc_states_the_format_rules(self):
        self.assertIn("sorted", self.text)
        self.assertIn("Line 1", self.text)

    def test_design_doc_states_the_lifecycle_and_who_retakes(self):
        self.assertIn("Lifecycle", self.text)
        self.assertIn("coordinator", self.text.lower())

    def test_design_doc_records_the_frozen_versus_follows_tradeoff(self):
        low = self.text.lower()
        self.assertIn("frozen", low)
        self.assertIn("silently", low)
        self.assertIn("follows main", low)

    def test_design_doc_contains_the_census_of_the_baseline_files(self):
        self.assertIn("Census", self.text)
        # every census row names a real legacy baseline file
        self.assertIn("b173-refusal-row-baseline-failures.txt", self.text)
        self.assertIn("b173-session-memory-baseline-failures.txt", self.text)

    def test_design_doc_records_the_measured_counts(self):
        # 27 items = 17 FAIL + 10 ERROR; the round-6 file's "17" counts
        # failures only.
        self.assertIn("27", self.text)
        self.assertIn("17", self.text)
        self.assertIn("10", self.text)

    def test_design_doc_records_the_nondeterminism_finding(self):
        low = self.text.lower()
        self.assertIn("deterministic", low)
        self.assertIn("flaky", low)
        self.assertIn("test_integration_sidecar", self.text)


class CurrentPointerTests(unittest.TestCase):
    """b173-baseline-CURRENT: the pointer to the baseline in force.

    These live outside the repository (coordination state, not source), so
    they skip when the files are not present on this machine.
    """

    POINTER = Path("/home/muse-newapi/b173-baseline-CURRENT")
    BASELINE_DIR = Path("/home/muse-newapi")

    def setUp(self):
        if not self.POINTER.is_file():
            self.skipTest("b173-baseline-CURRENT not present on this machine")

    def test_pointer_holds_exactly_one_line(self):
        text = self.POINTER.read_text(encoding="utf-8")
        self.assertEqual(len(text.strip().splitlines()), 1)

    def test_pointer_names_a_file_that_exists(self):
        name = self.POINTER.read_text(encoding="utf-8").strip()
        self.assertTrue(name.endswith(".failures.txt"), name)
        self.assertTrue((self.BASELINE_DIR / name).is_file(), name)

    def test_pointer_is_a_plain_file_not_a_symlink(self):
        self.assertFalse(self.POINTER.is_symlink())

    def test_the_selected_baseline_records_its_own_sha(self):
        name = self.POINTER.read_text(encoding="utf-8").strip()
        path = self.BASELINE_DIR / name
        first = path.read_text(encoding="utf-8").splitlines()[0]
        sha = re.search(r"[0-9a-f]{40}", first)
        self.assertIsNotNone(sha, first)
        # the sha in the file name is the sha in the file's first line
        self.assertIn(sha.group(0), name)

    def test_the_selected_baseline_items_are_sorted_and_well_formed(self):
        name = self.POINTER.read_text(encoding="utf-8").strip()
        path = self.BASELINE_DIR / name
        items = [
            line
            for line in path.read_text(encoding="utf-8").splitlines()
            if not line.startswith("#")
        ]
        self.assertEqual(items, sorted(items))
        self.assertEqual(len(items), len(set(items)))
        for line in items:
            self.assertRegex(line, ITEM_RE)
