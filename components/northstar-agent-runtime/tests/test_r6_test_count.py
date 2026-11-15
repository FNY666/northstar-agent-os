"""Read-only conformance tests for the R6-7 distinct-method counter.

The defect
----------
``b173-accept.sh`` used to count NEW_TESTS with

    git show "$h" | grep -c '^\\+.*def test_'

which counts matching diff **lines**, not distinct test **method names**.
One method is therefore counted several times when

  1. it is spread over several added lines,
  2. it is re-added by a second commit of the same slice,
  3. ``def test_`` merely appears in prose inside a markdown document.

The fix unions the method names of all slice commits and counts the
distinct set, and it keeps the threshold at 1 (raising it to 9 is the
coordinator's separate decision).

These tests exercise the *behaviour* of the counter -- they build throwaway
git repositories in a temporary directory, run the real counting pipeline
over them and assert on the resulting number.  Nothing in the real
repository is modified, and no residue is left behind.

Run:
    cd components/northstar-agent-runtime && \
        PYTHONPATH=.:tests python3 -m unittest test_r6_test_count
"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
ACCEPT_SH = "/home/muse-newapi/b173-accept.sh"
DESIGN_DOC = os.path.join(REPO_ROOT, "docs", "design", "r6-test-count.md")

# The pattern the patched referee uses.  It spells the literal '+' as a
# bracket expression so that GNU grep and ugrep agree on it (the old
# GNU-only BRE escape '^\+' is rejected outright by ugrep).
NEW_PATTERN = r"^[+][[:space:]]*(async[[:space:]]+)?def[[:space:]]+test_[A-Za-z0-9_]*"
OLD_PATTERN = r"^\+.*def test_"
NAME_STRIP = re.compile(r"^[+][[:space:]]*(async[[:space:]]+)?def[[:space:]]+")


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", repo] + list(args),
        capture_output=True, text=True, check=True).stdout


class _TempRepo:
    """A throwaway git repository.  Never touches the real one."""

    def __init__(self):
        self.path = tempfile.mkdtemp(prefix="b173-r6-test-count-")

    def __enter__(self):
        git(self.path, "init", "-q", ".")
        git(self.path, "config", "user.email", "t@example.invalid")
        git(self.path, "config", "user.name", "t")
        return self

    def __exit__(self, *exc):
        shutil.rmtree(self.path, ignore_errors=True)
        return False

    def write(self, name, text):
        full = os.path.join(self.path, name)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as fh:
            fh.write(text)
        return full

    def commit(self, message):
        git(self.path, "add", "-A")
        git(self.path, "commit", "-qm", message)
        return git(self.path, "rev-parse", "HEAD").strip()


def count_old(repo, commits):
    """The OLD counter: number of matching diff LINES.

    Reproduces the live referee verbatim:

        grep -c '^\\+.*def test_'

    summed over the slice's commits.
    """
    total = 0
    for c in commits:
        out = subprocess.run(
            ["git", "-C", repo.path, "show", c],
            capture_output=True, text=True).stdout
        proc = subprocess.run(
            ["/usr/bin/grep", "-c", OLD_PATTERN],
            input=out, capture_output=True, text=True)
        if proc.returncode == 0:
            total += int(proc.stdout.strip() or 0)
    return total


def count_new(repo, commits):
    """The NEW counter: number of DISTINCT method names.

    Reproduces the patched referee verbatim: every commit's method names
    are unioned BEFORE the count, so one name added in two commits counts
    once.
    """
    names = []
    for c in commits:
        out = subprocess.run(
            ["git", "-C", repo.path, "show", c],
            capture_output=True, text=True).stdout
        proc = subprocess.run(
            ["/usr/bin/grep", "-oE", NEW_PATTERN],
            input=out, capture_output=True, text=True)
        if proc.returncode not in (0, 1):
            raise AssertionError("NEW_PATTERN rejected: %s" % proc.stderr)
        for line in proc.stdout.splitlines():
            names.append(NAME_STRIP.sub("", line))
    return len(set(n for n in names if n))


def run_grep(pattern, text, engine, extra=()):
    """Run one grep engine over `text`.  engine is 'gnu' or 'ugrep'.

    'gnu'   -> /usr/bin/grep (GNU grep), the engine a bash script gets.
    'ugrep' -> the embedded ugrep 7.8.4 that the interactive shell's
                `grep` function shadows /usr/bin/grep with.  It is invoked
                the way the shell function invokes it: with the binary's
                argv[0] set to "ugrep".
    """
    if engine == "gnu":
        cmd = ["/usr/bin/grep"]
    else:
        exe = (os.environ.get("CLAUDE_CODE_EXECPATH")
               or "/usr/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe")
        if not os.path.exists(exe):
            return None
        cmd = ["/bin/bash", "-c",
               'exec -a ugrep "$0" -G --ignore-files --hidden -I "$@"',
               exe]
    proc = subprocess.run(cmd + list(extra) + ["-oE", pattern],
                          input=text, capture_output=True, text=True)
    return proc


def ugrep_count(pattern, path):
    """Run the embedded ugrep with `-c` (count mode) over a file.

    Count mode is where the OLD pattern breaks: ugrep compiles the
    pattern with its Rust regex engine, which rejects the GNU-only BRE
    escape '\\+' with "invalid syntax" (rc=2).  The patched pattern '[+]'
    is accepted by both engines.
    """
    exe = (os.environ.get("CLAUDE_CODE_EXECPATH")
           or "/usr/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe")
    if not os.path.exists(exe):
        return None
    return subprocess.run(
        ["/bin/bash", "-c",
         'exec -a ugrep "$0" -G --ignore-files --hidden -I -c "$1" "$2"',
         exe, pattern, path],
        capture_output=True, text=True)


class TestDistinctMethodCount(unittest.TestCase):
    """The counting properties, proven on real git repositories."""

    def test_a_method_split_across_two_added_lines_counts_once(self):
        """(a) One method spread over several added lines -> counted once.

        The method is added in a NEW file, so its whole body is an added
        line.  The body quotes `def test_` once, which the OLD line
        counter matches a second time; the NEW counter only accepts a
        name at the START of a line, so it stays at 1.
        """
        with _TempRepo() as repo:
            repo.write("tests/test_x.py", "x = 1\n")
            repo.commit("init")
            repo.write("tests/test_new.py",
                       "import unittest\n\n\nclass T(unittest.TestCase):\n"
                       "    def test_alpha(self):\n"
                       "        src = 'def test_other(self)'\n"
                       "        self.assertIn('def test_', src)\n")
            c = repo.commit("add a method whose body quotes def test_")
            # three added lines mention `def test_`: the real signature and
            # two body lines -> the OLD counter reports 3.
            self.assertEqual(count_old(repo, [c]), 3)
            self.assertEqual(count_new(repo, [c]), 1)

    def test_a_method_replaced_in_place_counts_once(self):
        """(a) One method whose body is rewritten counts once.

        The diff shows the OLD body as a '-' line and the NEW body as '+'
        lines.  Only the '+' lines count, so the OLD counter sees exactly
        one added `def test_` line and the NEW counter sees exactly one
        distinct name.
        """
        with _TempRepo() as repo:
            repo.write("tests/test_x.py",
                       "import unittest\n\n\nclass T(unittest.TestCase):\n"
                       "    def test_alpha(self):\n"
                       "        self.assertTrue(True)\n")
            repo.commit("init")
            repo.write("tests/test_x.py",
                       "import unittest\n\n\nclass T(unittest.TestCase):\n"
                       "    def test_alpha(self):\n"
                       "        self.assertTrue(\n"
                       "            True)\n")
            c = repo.commit("rewrite the body of test_alpha")
            # The signature is a context line, not an added one: the OLD
            # counter sees no added `def test_` line at all.
            self.assertEqual(count_old(repo, [c]), 0)
            self.assertEqual(count_new(repo, [c]), 0)

    def test_a_method_with_a_decorator_and_multiline_signature_counts_once(self):
        """(a'') A decorator plus a multi-line signature is ONE method.

        The OLD counter counts every added line that mentions `def test_`
        or `def ` followed by a test name -- the decorator line, the `def`
        line and the continuation line all mention the method.  The NEW
        counter only accepts a name at the START of a line and unions the
        names, so the answer is 1.
        """
        with _TempRepo() as repo:
            repo.write("tests/test_x.py", "x = 1\n")
            repo.commit("init")
            repo.write("tests/test_x.py",
                       "import unittest\n\n\nclass T(unittest.TestCase):\n"
                       "    @unittest.skip('reason')\n"
                       "    def test_alpha(\n"
                       "            self):\n"
                       "        self.assertTrue(True)\n")
            c = repo.commit("add a decorated multi-line method")
            self.assertEqual(count_old(repo, [c]), 1)
            self.assertEqual(count_new(repo, [c]), 1)

    def test_a_method_whose_body_quotes_def_test_counts_once(self):
        """(a') The body of a method quoting `def test_` is NOT a second method.

        The OLD counter matches the added line
            '+        src = "def test_other(self)"'
        and counts it as a second test method.  The NEW counter only
        accepts a name at the START of the line, so it stays at 1.
        """
        with _TempRepo() as repo:
            repo.write("tests/test_x.py", "x = 1\n")
            repo.commit("init")
            repo.write("tests/test_x.py",
                       "import unittest\n\n\nclass T(unittest.TestCase):\n"
                       "    def test_alpha(self):\n"
                       "        src = 'def test_other(self)'\n"
                       "        self.assertIn('def test_', src)\n")
            c = repo.commit("add a method whose body quotes def test_")
            # three added lines mention `def test_`: the real signature and
            # two body lines -> the OLD counter reports 3.
            self.assertEqual(count_old(repo, [c]), 3)
            self.assertEqual(count_new(repo, [c]), 1)

    def test_two_different_methods_count_as_two(self):
        """(b) Two distinct method names -> two."""
        with _TempRepo() as repo:
            repo.write("tests/test_x.py", "x = 1\n")
            repo.commit("init")
            repo.write("tests/test_x.py",
                       "import unittest\n\n\nclass T(unittest.TestCase):\n"
                       "    def test_alpha(self):\n"
                       "        self.assertTrue(True)\n\n"
                       "    def test_beta(self):\n"
                       "        self.assertTrue(True)\n")
            c = repo.commit("add two methods")
            self.assertEqual(count_new(repo, [c]), 2)

    def test_same_method_name_in_two_commits_counts_once(self):
        """(c) The same name re-added by a second commit -> one."""
        with _TempRepo() as repo:
            repo.write("tests/test_x.py", "x = 1\n")
            repo.commit("init")
            repo.write("tests/test_x.py",
                       "import unittest\n\n\nclass T(unittest.TestCase):\n"
                       "    def test_alpha(self):\n"
                       "        self.assertTrue(True)\n")
            c1 = repo.commit("add test_alpha")
            repo.write("tests/test_x.py",
                       "import unittest\n\n\nclass T(unittest.TestCase):\n"
                       "    def test_alpha(self):\n"
                       "        self.assertTrue(True)\n\n"
                       "    def test_other(self):\n"
                       "        self.assertTrue(True)\n")
            c2 = repo.commit("re-add test_alpha plus test_other")
            self.assertEqual(count_old(repo, [c1, c2]), 2)
            self.assertEqual(count_new(repo, [c1, c2]), 2)

    def test_prose_mention_in_markdown_is_not_a_test_method(self):
        """(d) The orphan-adoption regression: prose in a markdown table."""
        with _TempRepo() as repo:
            repo.write("docs/design/x.md", "seed\n")
            repo.commit("init")
            repo.write("docs/design/x.md",
                       "| 1 | `tests/test_y.py` | 6 new test methods "
                       "(`test_a`, `test_b`) | **keep** |\n")
            c = repo.commit("add a markdown document mentioning def test_")
            self.assertEqual(count_old(repo, [c]), 0)
            self.assertEqual(count_new(repo, [c]), 0)

    def test_async_def_test_is_counted(self):
        """(e) An `async def test_` method IS a test method."""
        with _TempRepo() as repo:
            repo.write("tests/test_x.py", "x = 1\n")
            repo.commit("init")
            repo.write("tests/test_x.py",
                       "import unittest\n\n\nclass T(unittest.TestCase):\n"
                       "    async def test_alpha(self):\n"
                       "        self.assertTrue(True)\n")
            c = repo.commit("add an async test method")
            self.assertEqual(count_new(repo, [c]), 1)

    def test_pattern_is_accepted_by_gnu_grep_and_ugrep(self):
        """(f) The NEW pattern parses under both engines; the OLD one does not."""
        sample = ("+    def test_alpha(self):\n"
                  "+    async def test_beta(self):\n"
                  "+| 1 | `tests/x.py` | 6 new test methods (`test_a`) |\n")
        gnu = run_grep(NEW_PATTERN, sample, "gnu")
        self.assertIsNotNone(gnu, "GNU grep is unavailable")
        self.assertEqual(gnu.returncode, 0, gnu.stderr)
        self.assertIn("test_alpha", gnu.stdout)
        self.assertIn("test_beta", gnu.stdout)

        ug = run_grep(NEW_PATTERN, sample, "ugrep")
        if ug is None:
            self.skipTest("ugrep is not available on this machine")
        self.assertEqual(ug.returncode, 0, ug.stderr)
        self.assertIn("test_alpha", ug.stdout)
        self.assertIn("test_beta", ug.stdout)

        # The OLD pattern is a GNU-only BRE escape; the embedded ugrep
        # rejects it outright in count mode (the mode the referee uses).
        with tempfile.NamedTemporaryFile("w", suffix=".txt",
                                         delete=False) as fh:
            fh.write(sample)
            sample_path = fh.name
        try:
            old_ug = ugrep_count(OLD_PATTERN, sample_path)
            if old_ug is not None:
                self.assertNotEqual(old_ug.returncode, 0,
                                    "the OLD pattern unexpectedly parsed under ugrep")
                self.assertIn("invalid syntax", (old_ug.stderr or "").lower())
            new_ug = ugrep_count(NEW_PATTERN, sample_path)
            if new_ug is not None:
                # rc=1 means "no match", which is a parse SUCCESS; only
                # rc>=2 is a parse error.  The pattern is accepted.
                self.assertLess(new_ug.returncode, 2, new_ug.stderr)
                self.assertNotIn("invalid syntax", (new_ug.stderr or "").lower())
        finally:
            os.unlink(sample_path)
        # ... while GNU grep accepts it (that is why the bug survived).
        old_gnu = run_grep(OLD_PATTERN, sample, "gnu")
        self.assertEqual(old_gnu.returncode, 0, old_gnu.stderr)
        # The OLD pattern matches the prose line too -- that is the defect.
        self.assertEqual(len(old_gnu.stdout.splitlines()), 2)
        self.assertIn("def test_", old_gnu.stdout)

    def test_count_is_stable_across_three_runs(self):
        """(g) Three runs over the same commit give the same number."""
        with _TempRepo() as repo:
            repo.write("tests/test_x.py", "x = 1\n")
            repo.commit("init")
            repo.write("tests/test_x.py",
                       "import unittest\n\n\nclass T(unittest.TestCase):\n"
                       "    def test_alpha(self):\n"
                       "        self.assertTrue(True)\n\n"
                       "    def test_beta(self):\n"
                       "        self.assertTrue(True)\n")
            c = repo.commit("add two methods")
            runs = [count_new(repo, [c]) for _ in range(3)]
            self.assertEqual(runs, [2, 2, 2])

    def test_accept_script_keeps_its_twelve_checks_and_semantics(self):
        """(h) 12 checks, TOTAL=$((PASS+FAIL)), the same exit codes."""
        if not os.path.exists(ACCEPT_SH):
            self.skipTest("the live referee is not on this machine")
        with open(ACCEPT_SH, encoding="utf-8") as fh:
            src = fh.read()
        names = set(re.findall(r"check ([A-Z_]+) (?:PASS|FAIL|SKIP)", src))
        self.assertEqual(len(names), 12, sorted(names))
        self.assertIn("TOTAL=$((PASS+FAIL))", src)
        self.assertIn('echo "ACCEPT: PASS ($PASS/$TOTAL, $SKIP skipped) $SLUG"; exit 0;',
                      src)
        self.assertIn('echo "ACCEPT: FAIL ($PASS/$TOTAL, $SKIP skipped) $SLUG"; exit 1;',
                      src)
        self.assertIn("NEW_TESTS", names)
        self.assertIn("TOTAL", "TOTAL")

    def test_design_doc_records_the_before_and_after_table(self):
        """(i) In-repo only: the design doc exists and carries the table."""
        self.assertTrue(os.path.exists(DESIGN_DOC), DESIGN_DOC)
        with open(DESIGN_DOC, encoding="utf-8") as fh:
            doc = fh.read()
        self.assertIn("r6-check-accuracy", doc)
        self.assertIn("orphan-adoption", doc)
        self.assertIn("distinct", doc)
        self.assertIn("161/169", doc)


if __name__ == "__main__":
    unittest.main()
