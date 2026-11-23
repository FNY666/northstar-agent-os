"""RED test: the referee's TESTS_RAN must re-run the slice's OWN test file.

THE DEFECT (measured 2026-11-16)
--------------------------------
Round 8 made the referee's content-commit set a UNION: the slice's subject
commits plus the commits that introduced the manifest's files.  The union is
right for the CONTENT checks -- it stops a corrected subject from hiding a
slice's evidence -- but it also pulls in commits that introduced ANOTHER
slice's files, and those commits carry other slices' test files.

To stop that, the round-8 filter admitted a test file only when the commit
that introduced it was ALSO one of the slice's own subject commits.  The
side-effect was measured on `capability-ceiling-probe`:

    $ bash b173-accept.sh capability-ceiling-probe
    PASS TESTS_RAN  [components/northstar-agent-runtime unittest: Ran 4 tests in 0.011s OK ]

**4** tests.  The slice's own test file has **63** methods.  The filter threw
them away, because the commit that introduced
`tests/test_capability_ceiling_probe.py` is `4e5a9657`, whose subject names
`scorer-disagreement` -- the amend that cost the slice its own name.  The
slice's test file is named in the slice's own MANIFEST, and the filter threw
that away too.

So the filter threw away the very evidence it was written to protect, and the
referee stopped re-running the slice's tests.

THE RULE
--------
A test file is the slice's evidence when either:

  * the slice's MANIFEST names it -- the manifest is the slice's declaration
    of what it delivered, so a file it names is the slice's own; or
  * the commit that introduced it is one of the slice's own subject commits.

Nothing else.  A file the slice merely adopted, or that arrived with a commit
that introduced another slice's module, is not evidence -- that is what keeps
`msaf-lineage` from being convicted of eleven `test_cli`/`test_sessions`
failures it never wrote.

WHAT THIS TEST PINS
-------------------
1. The filter admits a manifest-named test file even when the commit that
   introduced it carries a different slice's subject.
2. The filter still refuses a test file that is neither manifest-named nor
   introduced by the slice's own subject commit.
3. The referee's own filter, extracted and run against the real repository,
   keeps `capability-ceiling-probe`'s 63-method test file.
"""
from __future__ import annotations

import pathlib
import re
import subprocess
import unittest

ACCEPT = pathlib.Path("/home/muse-newapi/b173-accept.sh")
REPO = pathlib.Path("/home/muse-newapi/northstar-agent-os")
HOME = pathlib.Path("/home/muse-newapi")


def _shq(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def _run_bash(script: str, timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, timeout=timeout
    )


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(REPO), *args], capture_output=True, text=True
    ).stdout


def _manifest_paths(slug: str) -> list:
    manifest = HOME / ("b173-%s.files" % slug)
    if not manifest.is_file():
        return []
    return [
        p.strip()
        for p in manifest.read_text(encoding="utf-8").splitlines()
        if "/" in p.strip()
    ]


def _helper_block(text: str) -> str:
    """The referee's own `list_has` / `list_add` helpers, extracted."""
    out = []
    for name in ("list_has", "list_add"):
        m = re.search(r"^%s\(\) \{$" % name, text, re.M)
        if m is None:
            raise AssertionError("no %s helper in b173-accept.sh" % name)
        block = []
        for ln in text[m.start() :].splitlines():
            block.append(ln)
            if ln.strip() == "}":
                break
        out.append("\n".join(block))
    return "\n".join(out)


class FilterSemanticsTests(unittest.TestCase):
    """The referee's own TESTS_RAN filter, extracted and exercised."""

    @classmethod
    def setUpClass(cls):
        if not ACCEPT.is_file():
            raise unittest.SkipTest("live referee not installed: %s" % ACCEPT)
        cls.text = ACCEPT.read_text(encoding="utf-8")

    def _filter_block(self) -> str:
        """The referee's own TESTS_RAN ownership filter, extracted.

        The block runs from the assignment that seeds the manifest-named set
        to the assignment that finally sets ADDED_TESTS.  The referee's
        list helpers (`list_has`, `list_add`) are extracted too, because
        the block calls them.
        """
        helpers = _helper_block(self.text)
        start = None
        for pat in (r"^\s*MANIFEST_NAMED=", r"^\s*SLICE_INTRO=", r"^\s*SLICE_INTRO_OWN="):
            m = re.search(pat, self.text, re.M)
            if m is not None:
                if start is None or m.start() < start:
                    start = m.start()
        self.assertIsNotNone(
            start, "could not find the TESTS_RAN ownership filter in b173-accept.sh"
        )
        lines = self.text[start:].splitlines()
        block_lines = []
        for ln in lines:
            block_lines.append(ln)
            if ln.strip().startswith('ADDED_TESTS="$FILTERED"'):
                break
        block = "\n".join(block_lines)
        self.assertIn("FILTERED", block)
        return helpers + "\n" + block

    def _run_filter(self, slug: str) -> str:
        """Run the extracted filter against the real repository."""
        paths = _manifest_paths(slug)
        self.assertTrue(paths, "no manifest paths for %s" % slug)
        block = self._filter_block()
        script = (
            "set -u\n"
            "REPO=" + _shq(str(REPO)) + "\n"
            "MANIFEST=" + _shq(str(HOME / ("b173-%s.files" % slug))) + "\n"
            "SLUG=" + _shq(slug) + "\n"
            "SUBJ_HASHES=$(git -C \"$REPO\" log --format=%H --grep=\"^B173 "
            "\\([^:,][^:,]*,\\ \\)*${SLUG}[^A-Za-z0-9_-]\" -i 2>/dev/null "
            "| head -20 || true)\n"
            "ADDED_TESTS=\n"
            "for mp in $(cat \"$MANIFEST\" | tr '\\n' ' '); do :; done\n"
            + block
            + "\nprintf '%s\\n' \"$FILTERED\" | grep -v '^[[:space:]]*$' || true\n"
        )
        out = _run_bash(script)
        self.assertEqual(0, out.returncode, out.stderr)
        return out.stdout

    def test_a_manifest_named_test_file_is_the_slices_own_evidence(self):
        """The manifest names the file -- so it is the slice's, whatever
        the subject of the commit that introduced it says."""
        slug = "capability-ceiling-probe"
        kept = [ln for ln in self._run_filter(slug).splitlines() if ln.strip()]
        names = [ln.split("/")[-1] for ln in kept]
        self.assertIn(
            "test_capability_ceiling_probe.py",
            names,
            "the slice's own test file is named in its manifest, so the "
            "referee must re-run it; kept instead: %r" % (names,),
        )

    def test_the_manifest_named_test_file_is_not_the_only_thing_kept(self):
        """The filter is not a special case: it keeps every manifest-named
        test file, across every slice that has one.

        Only slices that have DELIVERED are checked.  A manifest is a
        DECLARATION written when a slice is launched, so a slice whose
        manifest exists but whose work has not landed has no test file
        to keep -- and the filter legitimately returns nothing for it.
        Measured 2026-11-23: ``agent-authorization-boundary``,
        ``memory-provenance-axis``, ``northstar-expand-search`` and
        ``state-transfer-audit`` had manifests and no commit on this
        branch, and their manifest files do not exist in the tree.
        """
        checked = 0
        for manifest in sorted(HOME.glob("b173-*.files")):
            slug = manifest.name[len("b173-") : -len(".files")]
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", slug):
                continue
            paths = _manifest_paths(slug)
            named_tests = [p for p in paths if "/tests/test_" in p]
            if not named_tests:
                continue
            # A slice that has not delivered has no test file yet: the
            # manifest names a file that does not exist.  Checking it
            # would convict a slice of not having written tests it has
            # not been asked to write yet.
            if not all((REPO / p).exists() for p in named_tests):
                continue
            checked += 1
            kept = [ln for ln in self._run_filter(slug).splitlines() if ln.strip()]
            for want in named_tests:
                self.assertIn(
                    want,
                    kept,
                    "%s's manifest names %s; the filter dropped it" % (slug, want),
                )
        self.assertGreater(
            checked, 10, "expected many slices to name a test file; got %d" % checked
        )

    def test_a_file_the_slice_merely_adopted_is_not_evidence(self):
        """A test file that is neither manifest-named nor introduced by the
        slice's own subject commit must not be re-run as the slice's."""
        slug = "msaf-lineage"
        kept = [ln for ln in self._run_filter(slug).splitlines() if ln.strip()]
        names = [ln.split("/")[-1] for ln in kept]
        for foreign in ("test_cli.py", "test_sessions.py", "test_permissions.py"):
            self.assertNotIn(
                foreign,
                names,
                "%s did not write %s; the union must not convict it of that "
                "file's failures.  kept: %r" % (slug, foreign, names),
            )

    def test_the_slices_own_test_methods_are_actually_re_run(self):
        """End to end: the referee's TESTS_RAN verdict must show the slice's
        own test file running."""
        out = _run_bash("bash " + _shq(str(ACCEPT)) + " capability-ceiling-probe")
        self.assertIn(
            "ACCEPT: PASS",
            out.stdout,
            "the referee must still accept capability-ceiling-probe",
        )
        m = re.search(r"^PASS TESTS_RAN\s+(.*)$", out.stdout, re.M)
        self.assertIsNotNone(m, out.stdout)
        detail = m.group(1)
        ran = re.search(r"Ran (\d+) tests", detail)
        self.assertIsNotNone(ran, detail)
        self.assertGreaterEqual(
            int(ran.group(1)),
            63,
            "the referee must re-run the slice's own 63 test methods; the "
            "verdict says: %s" % detail,
        )


class SubjectHashListTests(unittest.TestCase):
    """The subject-hash list is NEWLINE separated; every membership test
    must be newline aware.

    THE DEFECT (measured 2026-11-16)
    -------------------------------
    `SUBJ_HASHES` is produced by `git log --format=%H`, so it is a
    NEWLINE-separated list.  Two places in the referee matched a hash
    against it with a SPACE-delimited `case`:

        case " $SUBJ_HASHES " in *" $ih "*) keep=1;; esac

    With one hash in the list that matches; with two or more it matches
    **nothing**, because the list's interior separator is a newline and the
    pattern looks for a space:

        $ S=$(printf 'h1\\nh2\\n'); case " $S " in *" h2 "*) echo MATCH;; *) echo NOMATCH;; esac
        NOMATCH

    So the first half of the ownership rule -- "the commit that introduced
    this file is one of the slice's own subject commits" -- silently did
    nothing for every slice with TWO OR MORE subject commits.  Measured:
    47 of the batch's 84 slices have 2+ subject commits.
    """

    @classmethod
    def setUpClass(cls):
        if not ACCEPT.is_file():
            raise unittest.SkipTest("live referee not installed: %s" % ACCEPT)
        cls.text = ACCEPT.read_text(encoding="utf-8")

    def test_the_membership_tests_are_not_space_delimited(self):
        """No `case " $VAR " in *" $x "*` on a newline-separated list."""
        offenders = []
        for i, line in enumerate(self.text.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                # a comment quoting the broken form is documentation, not code
                continue
            m = re.search(r'case\s+"\s*\$([A-Z_]+)\s+"\s+in', line)
            if not m:
                continue
            var = m.group(1)
            # the variable must be a space-separated list to be matched
            # this way; a newline-separated one must be matched per-line.
            if var in ("SUBJ_HASHES", "PATH_HASHES", "SLICE_HASHES"):
                offenders.append((i, var, line.strip()))
        self.assertEqual(
            [],
            offenders,
            "these membership tests match a NEWLINE-separated hash list with "
            "a SPACE-delimited pattern, so they match NOTHING when the list "
            "holds two or more hashes:\n  "
            + "\n  ".join("%d: %s" % (i, ln) for i, _, ln in offenders),
        )

    def test_every_membership_test_on_the_subject_list_works(self):
        """The referee must match the subject list through the newline-aware
        helper, never through a space-delimited `case`."""
        lines = self.text.splitlines()
        found = False
        for i, line in enumerate(lines):
            if "case" not in line:
                continue
            window = "\n".join(lines[i : i + 4])
            if "SUBJ_HASHES" not in window:
                continue
            if line.strip().startswith("#"):
                continue
            found = True
            self.assertNotRegex(
                window,
                r'case\s+"[ \t]*\$SUBJ_HASHES[ \t]+"',
                "the membership test at line %d matches the subject list with "
                "a space-delimited pattern:\n%s" % (i + 1, window),
            )
        if found:
            self.fail(
                "the referee still has a `case` that mentions SUBJ_HASHES; "
                "the membership test must go through list_has",
            )
        # The subject list must be consulted -- through the helper.
        self.assertRegex(
            self.text,
            r'list_has\s+"\$SUBJ_HASHES"',
            "the referee must consult the subject list through list_has",
        )

    def test_the_subject_list_membership_is_newline_aware_in_code(self):
        """The referee must match the subject list through `list_has`."""
        self.assertRegex(
            self.text,
            r'list_has\s+"\$SUBJ_HASHES"',
            "the referee must match the subject list through the newline-aware "
            'list_has helper: list_has "$SUBJ_HASHES" "$ih"',
        )
        self.assertRegex(
            self.text,
            r"(?m)^list_has\(\) \{$",
            "the referee must define the newline-aware list_has helper",
        )

    def test_the_helper_finds_a_hash_in_the_middle_of_the_list(self):
        """Behavioural: the referee's own helper finds a middle hash."""
        block = _helper_block(self.text)
        script = (
            "set -u\n"
            + block
            + "\nS=$(printf 'aaa\\nbbb\\nccc\\n')\n"
            'if list_has "$S" "bbb"; then echo FOUND; else echo LOST; fi\n'
            'if list_has "$S" "zzz"; then echo FOUND; else echo LOST; fi\n'
        )
        out = _run_bash(script)
        self.assertEqual(0, out.returncode, out.stderr)
        lines = [ln for ln in out.stdout.splitlines() if ln.strip()]
        self.assertEqual(["FOUND", "LOST"], lines, out.stdout)


class SubjectCommitCountTests(unittest.TestCase):
    """The size of the defect, measured rather than asserted."""

    def test_many_slices_have_two_or_more_subject_commits(self):
        """If this ever drops to 0, the newline bug is no longer reachable."""
        slugs = 0
        multi = 0
        manifests = sorted(HOME.glob("b173-*.files"))
        # The manifests live in the COORDINATOR's directory, so a CI
        # runner does not have them -- and the glob then finds nothing.
        # Measured 2026-11-22: on a simulated runner this test FAILED
        # with "expected the whole batch, got 0", because it treated
        # an ABSENT batch as a batch of zero slices.  "The batch is not
        # here" is not "the batch has no slices with 2+ commits".
        if not manifests:
            self.skipTest(
                f"no slice manifests available: {HOME}/b173-*.files"
            )
        for manifest in manifests:
            slug = manifest.name[len("b173-") : -len(".files")]
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", slug):
                continue
            slugs += 1
            n = len(
                [
                    h
                    for h in _git(
                        "log",
                        "--format=%H",
                        "--grep=^B173 %s[^A-Za-z0-9_-]" % re.escape(slug),
                        "-i",
                    ).split()
                ]
            )
            if n >= 2:
                multi += 1
        self.assertGreater(slugs, 50, "expected the whole batch, got %d" % slugs)
        self.assertGreater(
            multi,
            20,
            "expected many slices with 2+ subject commits, got %d of %d"
            % (multi, slugs),
        )


if __name__ == "__main__":
    unittest.main()
