"""RED test: the referee must recognise a slice's commits by its SLUG, not by
an exact `B173 <slug>:` subject prefix.

THE DEFECT (measured 2026-11-16)
--------------------------------
Every place the referee looks for a slice's commits uses one pattern::

    git log --format=%H --grep="^B173 ${SLUG}:" -i

The `:` is *immediately* after the slug.  A slice whose work is committed
under a subject that continues the slug -- ``B173 slice4 (part 1): ...`` --
is **invisible** to that pattern, because the character after the slug is a
space, not a colon.

Measured on the batch branch, exactly three commits in the whole history
have a `B173 <slug>` subject that this pattern cannot match:

    4fe1ff28  B173 slice4 (part 2): check-input seal pinning + ...
    ffc5dfe2  B173 slice4 (part 1): alert trigger registry + ...
    95038ecb  B173 r6-worktree-rename, r6-manifest-subject: keep the ...

The first two are `slice4`'s entire deliverable: 10 new test methods and
the `alert_trigger_registry.py` module.  `slice4` therefore reports
NEW_TESTS 0 -- and it is the ONE slice in the batch that genuinely has 0
new test methods under the referee's own accounting, because the referee
cannot see the commits that wrote them.

The third commit names TWO slugs.  It is a single commit serving two
slices, so neither slice can own it exclusively -- but both must be able
to *see* it for their evidence checks.

WHAT THE PATTERN SHOULD BE
---------------------------
The subject after ``B173 `` names the slice.  The separator is punctuation,
not a colon specifically:

    ^B173 <slug>            -- "B173 slice4: ..."
    ^B173 <slug> (part 1)   -- "B173 slice4 (part 1): ..."
    ^B173 <slug>, <other>   -- "B173 r6-worktree-rename, r6-manifest-subject: ..."

So the boundary after the slug must be "a character that is not a word
character", not "a colon".  A slug is ``[a-z0-9-]`` (the referee already
enforces that shape elsewhere), so the boundary character must not be
``[A-Za-z0-9_-]`` -- otherwise ``slice4`` would also match a hypothetical
``slice4x``.

WHY THIS MATTERS MORE THAN A ONE-SLICE FIX
------------------------------------------
The pattern is a **false-FAIL generator** in general: a slice that wrote
real, tested code is told it wrote nothing.  This is the same failure
family the batch has already hit twice (the CANARY check for taskbooks
written before the canary mechanism existed, and the NEW_TESTS threshold
for slices launched before the taskbook mechanism existed).  The rule is
the same in all three cases: *the slice is held to the contract it was
actually given, and no comparison is not the same as a failure.*

These tests are **behavioural**: they build a throwaway git repository with
real commits and run the referee's own matcher against it.  A comment that
merely mentions the right words cannot satisfy them.
"""
from __future__ import annotations

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ACCEPT = Path("/home/muse-newapi/b173-accept.sh")
MUTANT_SH = Path("/home/muse-newapi/b173-mutant.sh")
WATCH_SH = Path("/home/muse-newapi/b173-watch.sh")

# The three subject shapes that the live pattern cannot match.
NON_CONFORMING_SUBJECTS = (
    "B173 slice4 (part 1): alert trigger registry + audit-sink reader",
    "B173 slice4 (part 2): check-input seal pinning + regression tests",
    "B173 r6-worktree-rename, r6-manifest-subject: keep the referee tests",
)


def _make_repo(tmp: Path, subjects) -> Path:
    """A throwaway git repo with one commit per subject."""
    repo = tmp / "repo"
    repo.mkdir()
    env = {
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@t",
        "PATH": "/usr/bin:/bin:/usr/local/bin",
        "HOME": str(tmp),
    }
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, env=env)
    for i, subject in enumerate(subjects):
        (repo / ("f%d.txt" % i)).write_text("x\n", encoding="utf-8")
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True, env=env)
        subprocess.run(
            ["git", "commit", "-q", "-m", subject], cwd=repo, check=True, env=env
        )
    return repo


def _match(script: Path, repo: Path, slug: str) -> list:
    """Run the script's own matcher against the throwaway repo.

    The matcher is *extracted* from the live script and run as-is, so the
    test exercises the referee's real code rather than a restatement of it.
    """
    text = script.read_text(encoding="utf-8")
    m = re.search(
        r'git .*-C "\$REPO" log --format=%H --grep="([^"]*)"(?:\s+-i)?\s*(?:\||;)'
        r"(?:\s*head -20)?\s*\|\| true",
        text,
    )
    if m is None:
        # Fall back to a looser shape: find the --grep="..." expression.
        m = re.search(r'--grep="([^"]*)"', text)
    if m is None:
        raise AssertionError("no --grep matcher found in %s" % script)
    pattern = m.group(1)
    # Substitute the shell variables the referee interpolates.
    pattern = pattern.replace("${SLUG}", slug).replace("$SLUG", slug)
    out = subprocess.run(
        ["git", "-C", str(repo), "log", "--format=%H", "--grep=" + pattern, "-i"],
        check=True,
        capture_output=True,
        text=True,
    )
    return [line for line in out.stdout.splitlines() if line.strip()]


class SubjectMatcherTests(unittest.TestCase):
    """The matcher must find a slice's commits whatever the subject's shape."""

    @classmethod
    def setUpClass(cls):
        if not ACCEPT.is_file():
            raise unittest.SkipTest("live referee not installed: %s" % ACCEPT)
        cls.patterns = {}
        for script in (ACCEPT, MUTANT_SH, WATCH_SH):
            if not script.is_file():
                continue
            text = script.read_text(encoding="utf-8")
            for m in re.finditer(r'--grep="([^"]*)"', text):
                cls.patterns.setdefault(script.name, []).append(m.group(1))

    def test_the_referee_matches_the_slice_slug_not_a_literal_colon(self):
        """The matcher must not require a colon IMMEDIATELY after the slug."""
        for name, patterns in self.patterns.items():
            for pattern in patterns:
                with self.subTest(script=name, pattern=pattern):
                    self.assertNotIn(
                        "${SLUG}:",
                        pattern,
                        "the matcher requires a colon immediately after the "
                        "slug, so a subject like 'B173 slice4 (part 1): ...' "
                        "is invisible to it",
                    )

    def test_a_subject_with_a_part_suffix_is_matched(self):
        """'B173 slice4 (part 1): ...' must be found for the slug 'slice4'."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = _make_repo(Path(tmp), NON_CONFORMING_SUBJECTS)
            found = _match(ACCEPT, repo, "slice4")
            self.assertEqual(
                2,
                len(found),
                "the matcher found %d of the 2 'B173 slice4 ...' commits; a "
                "slice whose work is committed under a suffixed subject is "
                "told it wrote nothing" % len(found),
            )

    def test_a_subject_naming_two_slugs_is_matched_by_both(self):
        """'B173 a, b: ...' must be found for the slug 'a' AND for 'b'."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = _make_repo(Path(tmp), NON_CONFORMING_SUBJECTS)
            for slug in ("r6-worktree-rename", "r6-manifest-subject"):
                with self.subTest(slug=slug):
                    found = _match(ACCEPT, repo, slug)
                    self.assertEqual(
                        1,
                        len(found),
                        "the commit naming both slugs was not found for %s"
                        % slug,
                    )

    def test_a_slug_prefix_of_another_slug_does_not_match(self):
        """'slice4' must not match a commit for 'slice4x'."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = _make_repo(Path(tmp), ("B173 slice4x: unrelated work",))
            found = _match(ACCEPT, repo, "slice4")
            self.assertEqual(
                [],
                found,
                "the matcher matched 'B173 slice4x:' for the slug 'slice4'; "
                "the boundary after the slug must exclude word characters",
            )

    def test_the_plain_colon_subject_is_still_matched(self):
        """The fix must not break the shape that already worked."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = _make_repo(Path(tmp), ("B173 slice4: the ordinary shape",))
            found = _match(ACCEPT, repo, "slice4")
            self.assertEqual(1, len(found))

    def test_every_script_that_matches_slice_commits_shares_the_rule(self):
        """accept.sh, mutant.sh and watch.sh must agree."""
        if len(self.patterns) < 2:
            self.skipTest("not all three scripts are installed")
        shapes = {
            name: {p.replace("${SLUG}", "<slug>").replace("$SLUG", "<slug>")
                   for p in patterns}
            for name, patterns in self.patterns.items()
        }
        reference = shapes["b173-accept.sh"]
        for name, own in shapes.items():
            with self.subTest(script=name):
                self.assertEqual(
                    reference,
                    own,
                    "the three scripts use different subject matchers, so "
                    "they disagree about which commits belong to a slice",
                )


if __name__ == "__main__":
    unittest.main()
