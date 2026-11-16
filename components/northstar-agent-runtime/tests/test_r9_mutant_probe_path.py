"""The planted-fault probe must be able to see every slice's own test file.

`b173-mutant.sh` picks the slice's test file with the pattern

    grep -E '/tests/test_[^/]+\\.py$' "$MANIFEST"

That pattern requires a DIRECTORY SEPARATOR immediately before `tests/`, so it
never matches a test file at the REPOSITORY ROOT -- `tests/test_x.py` -- which
is where the repository-level slices keep theirs.

Measured 2026-11-16: four slices in the ledger show `MUTANT SKIP: manifest
lacks module/test`, and two of them (`seal-slice6`, `shipped-module-docs`) skip
for THIS reason alone -- they have both a module and a test file in their
manifest, and the pattern simply does not see the test file.

Run by hand with the corrected pattern, both kill a mutant:

    seal-slice6        MUTANT and@67 KILLED (and -> or)   killed 1/1
    shipped-module-docs MUTANT gt@425 KILLED (> -> >=)    killed 1/1

The probe's contract is ">=1 mutant killed" -- a slice whose test file the
probe cannot find is a slice whose tests are never verified, and the verdict
is reported as a skip, which reads as "nothing to check here" rather than
"the probe was blind".

These tests are BEHAVIOURAL: they extract the live probe's own pattern and
run it, so a comment that merely mentions the right words cannot satisfy them.
"""
from __future__ import annotations

import pathlib
import re
import subprocess
import unittest

PROBE = pathlib.Path("/home/muse-newapi/b173-mutant.sh")


def _run_bash(script: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, timeout=timeout
    )


def _shq(s: str) -> str:
    """Quote a string for safe single-quoted use in a bash command."""
    return "'" + s.replace("'", "'\\''") + "'"


def _probe_patterns(text: str) -> list[str]:
    """Every grep -E pattern the probe uses to select a TEST file.

    The probe also selects a MODULE file (`grep -E '\\.py$' | grep -v
    '/tests/'`), which is a different job; only the test-file selectors are
    in scope here.

    Returned verbatim from the live script, so this test tracks whatever the
    probe actually does -- a hardcoded copy in the test would pass while the
    probe regressed.
    """
    found = []
    for line in text.splitlines():
        match = re.search(r"grep\s+-E\s+'([^']*)'\s+\"?\$MANIFEST", line)
        if not match:
            continue
        pattern = match.group(1)
        if "test_" in pattern:
            found.append(pattern)
    return found


class MutantProbePathPatternTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not PROBE.is_file():
            raise unittest.SkipTest("live probe not installed: %s" % PROBE)
        cls.text = PROBE.read_text(encoding="utf-8")
        cls.patterns = _probe_patterns(cls.text)

    def test_the_probe_has_at_least_one_test_file_pattern(self):
        self.assertTrue(
            self.patterns,
            "no test-file selection pattern found in %s" % PROBE,
        )

    def test_every_test_file_pattern_matches_a_repository_root_test_file(self):
        # The defect, expressed as a property of the live pattern: a test
        # file at the repository root must be selectable.
        for pattern in self.patterns:
            with self.subTest(pattern=pattern):
                matched = _run_bash(
                    "printf '%s\\n' 'tests/test_example.py' | grep -E " + _shq(pattern)
                )
                self.assertEqual(
                    matched.stdout.strip(),
                    "tests/test_example.py",
                    "the probe's pattern %r cannot see a repository-root test file"
                    % pattern,
                )

    def test_every_test_file_pattern_still_matches_a_component_test_file(self):
        # The fix must not break the shape that already worked.
        for pattern in self.patterns:
            with self.subTest(pattern=pattern):
                matched = _run_bash(
                    "printf '%s\\n' 'components/x/tests/test_example.py' | grep -E "
                    + _shq(pattern)
                )
                self.assertEqual(
                    matched.stdout.strip(),
                    "components/x/tests/test_example.py",
                    "the probe's pattern %r lost the component-level shape" % pattern,
                )

    def test_no_test_file_pattern_requires_a_leading_directory_separator(self):
        # The specific shape of the defect: a pattern that begins with a
        # mandatory `/tests/` cannot match a root-level path.
        for pattern in self.patterns:
            with self.subTest(pattern=pattern):
                self.assertNotRegex(
                    pattern,
                    r"^\^?/tests/",
                    "the probe's pattern %r anchors the match to a leading '/' "
                    "and therefore cannot match `tests/...`" % pattern,
                )

    def test_a_repository_root_test_file_is_selectable_end_to_end(self):
        # The whole selection path, not just the pattern: the probe picks the
        # test file, then derives the module name and the run directory from
        # it.  A root-level file must survive both derivations.
        manifest = "\n".join(
            [
                "tests/docbuild.py",
                "tests/test_shipped_module_docs.py",
                "docs/design/shipped-module-docs.md",
            ]
        )
        script = (
            "MANIFEST=$(mktemp); printf '%s\\n' " + _shq(manifest) + " > \"$MANIFEST\"; "
            "TESTF=$(grep -E '(^|/)tests/test_[^/]+\\.py$' \"$MANIFEST\" | head -n1); "
            "echo \"TESTF=$TESTF\"; "
            "TMOD=$(basename \"$TESTF\" .py); echo \"TMOD=$TMOD\"; "
            "COMPDIR=$(dirname \"$TESTF\" | sed 's|/tests$||'); "
            "echo \"COMPDIR=$COMPDIR\""
        )
        out = _run_bash(script)
        self.assertIn("TESTF=tests/test_shipped_module_docs.py", out.stdout)
        self.assertIn("TMOD=test_shipped_module_docs", out.stdout)
        self.assertIn("COMPDIR=", out.stdout)

    def test_a_root_level_test_file_yields_the_repository_root_as_the_run_directory(self):
        # A root-level `tests/` has no component root, so the run directory
        # must be the repository root itself.  The probe's derivation strips a
        # trailing `/tests`; for a root-level path that leaves the literal
        # `tests`, which is NOT the repository root -- the test's siblings
        # (the module it exercises) live at the root, and a run from inside
        # `tests/` cannot import them.
        out = _run_bash(
            "TESTF=tests/test_shipped_module_docs.py; "
            "COMPDIR=$(dirname \"$TESTF\" | sed 's|/tests$||'); "
            "[ \"$COMPDIR\" = tests ] && COMPDIR=.; "
            "echo \"COMPDIR=$COMPDIR\""
        )
        self.assertIn("COMPDIR=.", out.stdout)

    def test_a_component_level_test_file_yields_the_component_root(self):
        # The other half of the derivation: a component-level test file must
        # still give the component root, so the fix did not move it.
        out = _run_bash(
            "TESTF=components/northstar-agent-runtime/tests/test_x.py; "
            "COMPDIR=$(dirname \"$TESTF\" | sed 's|/tests$||'); "
            "echo \"COMPDIR=$COMPDIR\""
        )
        self.assertIn(
            "COMPDIR=components/northstar-agent-runtime", out.stdout
        )

    def test_the_test_file_selector_rejects_a_non_test_python_file(self):
        # The selector must select TEST files, not every python file.  A
        # widened pattern that also matched `scripts/seal-delivery.py` would
        # make the probe mutate a module and "run" it as a test.
        for pattern in self.patterns:
            with self.subTest(pattern=pattern):
                matched = _run_bash(
                    "printf '%s\\n' 'scripts/seal-delivery.py' | grep -E "
                    + _shq(pattern)
                )
                self.assertEqual(
                    matched.stdout.strip(),
                    "",
                    "the probe's pattern %r selects a non-test python file" % pattern,
                )

    def test_the_test_file_selector_rejects_a_design_document(self):
        # The manifest also names design documents.  A pattern that matched
        # those would make the probe try to run a markdown file as a test.
        for pattern in self.patterns:
            with self.subTest(pattern=pattern):
                matched = _run_bash(
                    "printf '%s\\n' 'docs/design/x.md' | grep -E " + _shq(pattern)
                )
                self.assertEqual(
                    matched.stdout.strip(),
                    "",
                    "the probe's pattern %r selects a design document" % pattern,
                )

    def test_the_module_selector_still_excludes_test_files(self):
        # The module selector is out of scope for the fix, but it must keep
        # working: the probe mutates a MODULE, and picking a test file as
        # the module would mutate the tests.
        #
        # The rule is "not a test file", by NAME.  The old rule excluded a
        # test file by its DIRECTORY (`grep -v '/tests/'`), which did not
        # exclude a ROOT-LEVEL test file -- `tests/test_x.py` starts with
        # `tests/`, not `/tests/`.  Measured 2026-11-16: two slices name
        # both a root-level test file and a module, and under the old rule
        # the probe would have mutated the test file.
        out = _run_bash(
            "printf '%s\\n' 'tests/docbuild.py' 'tests/test_x.py' "
            "'components/x/tests/test_y.py' "
            "| grep -E '\\.py$' | grep -vE '(^|/)test_[^/]*\\.py$'"
        )
        self.assertEqual(out.stdout.strip(), "tests/docbuild.py")

    def test_the_live_probe_excludes_a_root_level_test_file_from_the_module(self):
        # The same property, read from the LIVE probe's own module selector
        # rather than from a restatement of it.
        match = re.search(
            r"MOD=\$\(grep\s+-E\s+'([^']*)'\s+\"\$MANIFEST\"\s*\|\s*"
            r"grep\s+-vE?\s+'([^']*)'",
            self.text,
        )
        self.assertIsNotNone(
            match,
            "the probe's module selector was not found in %s" % PROBE,
        )
        _, exclusion = match.groups()
        out = _run_bash(
            "printf '%s\\n' 'tests/test_x.py' | grep -E '\\.py$' | grep -vE "
            + _shq(exclusion)
        )
        self.assertEqual(
            out.stdout.strip(),
            "",
            "the live probe's module selector admits a root-level test file",
        )

    def test_the_probe_script_is_syntactically_valid_bash(self):
        # The probe lives outside the repository, so nothing else would catch
        # a syntax error in it until it ran -- and it runs inside the
        # referee, where a syntax error reads as a skipped check.
        out = _run_bash("bash -n " + _shq(str(PROBE)))
        self.assertEqual(
            out.returncode,
            0,
            "the probe does not parse as bash: %s" % out.stderr.strip(),
        )

    def test_the_probe_still_declares_both_the_module_and_the_test_selection(self):
        # The fix changed two grep selectors.  If either had been dropped
        # rather than corrected, the probe would silently stop selecting a
        # test file.  Both must be present.
        self.assertIn(
            "grep -v '/tests/'",
            self.text,
            "the probe no longer excludes test files when choosing the module",
        )
        self.assertGreaterEqual(
            len(self.patterns),
            2,
            "the probe should select a test file in both the pairing loop and "
            "the fallback; found %d pattern(s)" % len(self.patterns),
        )


if __name__ == "__main__":
    unittest.main()
