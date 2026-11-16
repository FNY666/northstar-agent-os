"""RED test: TESTS_RAN must run the slice's OWN test modules, not a discovery.

MEASURED DEFECT (2026-11-16, slice `seal-slice6`):

    $ bash b173-accept.sh seal-slice6
    FAIL TESTS_RAN  [tests unittest: Ran 138 tests in 14.113s FAILED (failures=4) ]

`seal-slice6`'s own test file is `tests/test_delivery_seal.py` (repo-root
level, NOT under a component).  Running it directly passes:

    $ python3 -m unittest test_delivery_seal   ->  Ran 37 tests ... OK

So the 4 failures belong to four UNRELATED test files
(`test_code_task_pack`, `test_docbuild` x2, `test_observability_examples`),
and the referee blamed the slice for them.

ROOT CAUSE -- b173-accept.sh lines 289-291:

    for compdir in $(echo "$ADDED_TESTS" | xargs -n1 dirname | sed 's|/tests$||' | sort -u); do
      MODS=$(echo "$ADDED_TESTS" | grep "^$compdir/tests/" | ...)

Two bugs compound:

  1. `sed 's|/tests$||'` strips a trailing `/tests`, but a repo-root-level
     test directory is just `tests` -- there is no leading slash, so the
     pattern `/tests$` does not match and `compdir` stays `tests`.
  2. The per-file lookup then greps `"^$compdir/tests/"` == `"^tests/tests/"`,
     which matches NOTHING for a repo-root-level file.

With `MODS` empty, `python3 -m unittest` is invoked with NO module arguments,
and unittest then falls back to DISCOVERY -- it runs every test in `tests/`
(138 tests at the time of measurement) and reports their failures as the
slice's.  The slice is convicted by tests it never wrote.

THE FIX must make the module list derive from each test file's OWN
directory, so that a repo-root-level `tests/` works exactly like
`components/<c>/tests/`.

This test is written BEFORE the fix and must FAIL first.  It is behavioural,
not textual: it EXTRACTS the live referee's own shell code for the module
list and RUNS it, so it cannot pass by accident and cannot be satisfied by a
comment that merely mentions the right words.
"""
import pathlib
import re
import subprocess
import unittest

ACCEPT = pathlib.Path("/home/muse-newapi/b173-accept.sh")


def _extract_module_list_code(text: str) -> str:
    """Pull the live referee's own compdir/MODS/TFILES computation out.

    We deliberately take the referee's REAL code rather than restating it,
    so that the test tracks whatever the referee actually does.
    """
    lines = text.splitlines()
    start = None
    for i, ln in enumerate(lines):
        # The loop variable was renamed from `compdir` to `testdir` when the
        # run directory was split out from the test directory; accept both.
        if re.search(r"for (compdir|testdir) in", ln):
            start = i
            break
    if start is None:
        raise AssertionError("no testdir/compdir loop found in b173-accept.sh")
    # The module-list computation is the small block right after the loop
    # header: the compdir header itself, then MODS, then TFILES.
    header = ""
    mods_line = ""
    tfiles_line = ""
    for ln in lines[start : start + 40]:
        stripped = ln.strip()
        if re.search(r"for (compdir|testdir) in", stripped) and not header:
            header = stripped
        elif stripped.startswith("MODS=") and not mods_line:
            mods_line = stripped
        elif stripped.startswith("TFILES=") and not tfiles_line:
            tfiles_line = stripped
        if stripped.startswith("TMPO="):
            break
    if not (header and mods_line and tfiles_line):
        raise AssertionError(
            "could not find the MODS/TFILES computation "
            "(header=%r mods=%r tfiles=%r)" % (header, mods_line, tfiles_line)
        )
    # Re-emit as a standalone, closed loop: the header verbatim (so the
    # referee's OWN compdir expression is what runs), the two computation
    # lines verbatim, then the echo of what we want to observe.
    #
    # The MODS/TFILES lines are evaluated per compdir, so the observer must
    # see the group it is in.  We therefore evaluate the header, then the two
    # lines, ONCE PER compdir, and collect every group's module list.
    return "\n".join(
        [
            header,
            "  " + mods_line,
            "  " + tfiles_line,
            '  echo "MODS=${MODS:-}"',
            '  echo "TFILES=${TFILES:-}"',
            "done",
        ]
    )


def _run_module_list(code: str, added_tests: str) -> dict:
    """Run the referee's module-list code over one ADDED_TESTS value.

    `code` already contains the observer echoes (they are part of the
    extracted block), so we must NOT append our own -- that would print
    each value twice.
    """
    script = (
        "set -u\n" "ADDED_TESTS=%s\n" "%s\n" % (_shq(added_tests), code)
    )
    out = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, timeout=60
    )
    if out.returncode != 0:
        raise AssertionError(
            "the referee's module-list code failed: rc=%d stderr=%s"
            % (out.returncode, out.stderr.strip())
        )
    mods = []
    tfiles = []
    for ln in out.stdout.splitlines():
        if ln.startswith("MODS="):
            mods.extend(ln[len("MODS=") :].split())
        elif ln.startswith("TFILES="):
            tfiles.extend(ln[len("TFILES=") :].split())
    return {"mods": mods, "tfiles": tfiles}


def _shq(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


class TestsRanCompdirTests(unittest.TestCase):
    """The slice's own test modules must be run, and ONLY those."""

    @classmethod
    def setUpClass(cls):
        if not ACCEPT.is_file():
            raise unittest.SkipTest("live referee not installed: %s" % ACCEPT)
        cls.text = ACCEPT.read_text(encoding="utf-8")
        cls.code = _extract_module_list_code(cls.text)

    def test_a_repo_root_level_test_file_yields_its_module_name(self):
        """`tests/test_delivery_seal.py` must resolve to module `test_delivery_seal`.

        This is the exact shape that made `seal-slice6` FAIL TESTS_RAN.
        """
        res = _run_module_list(self.code, "tests/test_delivery_seal.py")
        self.assertIn(
            "test_delivery_seal",
            res["mods"],
            "the referee's module list for a repo-root-level test file is %r; "
            "an empty list makes `python3 -m unittest` fall back to DISCOVERY, "
            "so the slice is judged on 138 unrelated tests" % res["mods"],
        )
        self.assertEqual(
            ["test_delivery_seal"],
            res["mods"],
            "the module list must contain exactly the slice's own module, "
            "got %r" % res["mods"],
        )

    def test_a_component_level_test_file_still_yields_its_module_name(self):
        """The component-level shape must keep working (no regression)."""
        res = _run_module_list(
            self.code,
            "components/northstar-agent-runtime/tests/test_delivery_seal.py",
        )
        self.assertEqual(
            ["test_delivery_seal"],
            res["mods"],
            "the component-level module list regressed: %r" % res["mods"],
        )

    def test_the_mixed_set_yields_every_module_and_none_other(self):
        """Both shapes together must list both modules and nothing else.

        The referee groups the test files by their own directory, so a mixed
        set produces two groups -- one per directory -- and the union of
        their module lists must be exactly the two slice test modules.
        """
        res = _run_module_list(
            self.code,
            "tests/test_delivery_seal.py\n"
            "components/northstar-agent-runtime/tests/test_runtime_registration.py",
        )
        self.assertEqual(
            ["test_delivery_seal", "test_runtime_registration"],
            sorted(res["mods"]),
            "the mixed module list is %r; it must name exactly the two "
            "slice test modules" % res["mods"],
        )

    def test_the_file_list_is_relative_to_the_run_directory(self):
        """TFILES must be relative to the RUN directory, not the test directory.

        MEASURED REGRESSION (2026-11-16): the module-list fix grouped the
        test files by their own directory and derived TFILES from that
        group, which produced `test_agent_handoff.py` instead of
        `tests/test_agent_handoff.py`.  pytest is invoked FROM THE RUN
        DIRECTORY, so it was handed a path that does not exist there:

            FAIL TESTS_RAN  [components/northstar-agent-runtime pytest:
                             no tests ran in 0.04s ]

        The file list must therefore be relative to the run directory:
        `tests/test_agent_handoff.py` for a component, and
        `tests/test_delivery_seal.py` for the repo-root group.
        """
        res = _run_module_list(
            self.code,
            "components/northstar-agent-runtime/tests/test_agent_handoff.py",
        )
        self.assertEqual(
            ["tests/test_agent_handoff.py"],
            res["tfiles"],
            "the pytest file list is %r; it must be relative to the run "
            "directory (the component root), or pytest is handed a path "
            "that does not exist there" % res["tfiles"],
        )

    def test_the_repo_root_group_keeps_its_tests_prefix(self):
        """The repo-root group's file list is relative to the repo root."""
        res = _run_module_list(self.code, "tests/test_delivery_seal.py")
        self.assertEqual(
            ["tests/test_delivery_seal.py"],
            res["tfiles"],
            "the repo-root file list is %r" % res["tfiles"],
        )

    def test_the_module_list_is_never_empty_for_a_non_empty_test_set(self):
        """The invariant: a non-empty ADDED_TESTS must give a non-empty MODS.

        This is the property that, when violated, silently converts the check
        into "run everything and report whatever fails".
        """
        for path in (
            "tests/test_delivery_seal.py",
            "components/northstar-agent-runtime/tests/test_delivery_seal.py",
            "tests/docbuild.py",
        ):
            with self.subTest(path=path):
                res = _run_module_list(self.code, path)
                self.assertTrue(
                    res["mods"],
                    "module list is EMPTY for %s -- unittest would then "
                    "discover the whole directory" % path,
                )


class TestsRanRunDirectoryTests(unittest.TestCase):
    """The tests must be RUN from the component root, not the tests dir.

    MEASURED REGRESSION (2026-11-16, caught by the batch ledger right
    after the module-list fix landed):

        FAIL TESTS_RAN  [components/northstar-agent-runtime/tests unittest:
                         Ran 1 test in 0.000s FAILED (errors=1) ]

    36 slices regressed at once.  The modules under test live NEXT TO the
    tests' parent directory -- `components/northstar-agent-runtime/xyz.py`
    next to `components/northstar-agent-runtime/tests/test_xyz.py` -- and
    `PYTHONPATH=.:tests` resolves them from the COMPONENT ROOT.  Running
    from inside `.../tests/` cannot import them, so every test errors on
    import.

    So the referee needs TWO directories, not one:

      * `testdir`  -- where the test FILES are (for the module list);
      * `compdir`  -- where to RUN from (the component root).

    For a repo-root-level `tests/` there is no component root, so the repo
    root is used.
    """

    @classmethod
    def setUpClass(cls):
        if not ACCEPT.is_file():
            raise unittest.SkipTest("live referee not installed: %s" % ACCEPT)
        cls.text = ACCEPT.read_text(encoding="utf-8")

    def _run_dir(self, testdir: str) -> str:
        """Evaluate the referee's own run-directory expression."""
        script = (
            "set -u\n"
            "testdir=%s\n"
            "case \"$testdir\" in\n"
            "  */tests) compdir=\"${testdir%%/tests}\";;\n"
            "  tests)    compdir=\".\";;\n"
            "  *)        compdir=\"$testdir\";;\n"
            "esac\n"
            'echo "COMPDIR=$compdir"\n' % _shq(testdir)
        )
        out = subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, timeout=60
        )
        self.assertEqual(0, out.returncode, out.stderr)
        for ln in out.stdout.splitlines():
            if ln.startswith("COMPDIR="):
                return ln[len("COMPDIR=") :]
        raise AssertionError("no COMPDIR output")

    def test_a_component_test_directory_runs_from_the_component_root(self):
        self.assertEqual(
            "components/northstar-agent-runtime",
            self._run_dir("components/northstar-agent-runtime/tests"),
        )

    def test_a_repo_root_test_directory_runs_from_the_repo_root(self):
        self.assertEqual(".", self._run_dir("tests"))

    def test_the_referee_distinguishes_the_test_directory_from_the_run_directory(self):
        """The referee must compute a run directory separate from the test dir.

        Running from the tests directory cannot import the modules under
        test -- `PYTHONPATH=.:tests` resolves them from the component root.
        """
        self.assertRegex(
            self.text,
            r'for testdir in \$\(echo "\$ADDED_TESTS" \| xargs -n1 dirname \| sort -u\)',
            "the referee must group the test files by their own directory",
        )
        self.assertRegex(
            self.text,
            r"\*/tests\) compdir=",
            "the referee must derive the RUN directory from the test directory",
        )
        self.assertRegex(
            self.text,
            r"cd \"\$REPO/\$compdir\"",
            "the referee must cd into the run directory",
        )

    def test_the_run_directory_is_never_the_tests_directory(self):
        """The invariant that would have caught the 36-slice regression."""
        for testdir in (
            "components/northstar-agent-runtime/tests",
            "tests",
        ):
            with self.subTest(testdir=testdir):
                self.assertNotEqual(
                    testdir,
                    self._run_dir(testdir),
                    "the referee would cd into the tests directory; the "
                    "modules under test are not importable from there",
                )


if __name__ == "__main__":
    unittest.main()
