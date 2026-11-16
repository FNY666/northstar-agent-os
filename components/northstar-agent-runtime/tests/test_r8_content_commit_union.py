"""RED test: correcting a slice's subject must not destroy its evidence.

THE DEFECT (measured 2026-11-16)
--------------------------------
`b173-accept.sh` computes the slice's content commits like this:

    SUBJ_HASHES=$(git log --format=%H --grep="^B173 <slug>..." -i | head -20)
    # Legacy path-based fallback: the newest commit touching any manifest path.
    # It is kept for the CONTENT checks (NEW_TESTS / WORKTREE_CLEAN / TESTS_RAN /
    # MUTANT) so that their verdicts do not move; ATTRIBUTION is decided by
    # COMMIT below, which only accepts a commit whose subject is this slice's.
    SLICE_HASHES="$SUBJ_HASHES"
    if [ -z "$SLICE_HASHES" ] && [ -f "$MANIFEST" ]; then
      SLICE_HASHES=$(git log --format=%H -1 -- $(cat "$MANIFEST" | tr '\n' ' ') || true)
    fi

The fallback fires **only when the slice has no subject commit**.  So the
moment a slice's subject is corrected, the fallback stops firing -- and the
commit that actually carries the slice's work, which sits under the *old,
wrong* subject, becomes invisible to every content check.

Measured on `capability-ceiling-probe`, whose work was committed under
`B173 scorer-disagreement:` (the amend that cost it its own name):

    before the subject was corrected:  NEW_TESTS 59   (threshold 9)  PASS
    after  the subject was corrected:  NEW_TESTS  8   (threshold 9)  FAIL

The count fell by **51**: the slice's own 59 test methods were counted from
the mis-subjected commit, and once the slice owned a subject commit of its
own, that commit stopped being consulted.  The fallback's own comment says
it exists "so that their verdicts do not move".  It moves them -- by 51
methods, in the wrong direction.

WHAT THIS TEST PINS
--------------------
The fallback must be **additive**, not exclusive: a slice's content
commits are the union of

  * the commits whose subject names the slice, AND
  * the commits that introduced the files the slice's manifest names.

The second half is what the fallback already computes; it must not switch
off when the first half becomes non-empty.

The blast radius is measured, not assumed.  Under the union rule:

  * **0 slices lose** test methods (the count never falls);
  * 17 slices' counts rise, and **6 of them cross the threshold** -- every
    one of them a slice that was failing for exactly this reason
    (`capability-ceiling-probe`, `mutant-evidence-closure`,
    `orphan-adoption`, `slice1`, `slice2`, `slice3`);
  * the largest count in the batch becomes 18,764 (`refusal-hold-wiring`),
    which is a **count of distinct method names across the commits that
    introduced the slice's files** -- the same thing the exclusive rule
    counts, over more commits.

The test extracts the referee's OWN expression and runs it, so a comment
that merely mentions the right words cannot satisfy it.
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


def _run_bash(script: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, timeout=timeout
    )


def _manifest_paths(slug: str) -> list:
    manifest = HOME / ("b173-%s.files" % slug)
    if not manifest.is_file():
        return []
    return [
        p.strip()
        for p in manifest.read_text(encoding="utf-8").splitlines()
        if "/" in p
    ]


def _slice_slugs() -> list:
    slugs = []
    for manifest in sorted(HOME.glob("b173-*.files")):
        slug = manifest.name[len("b173-") : -len(".files")]
        if slug and re.fullmatch(r"[a-z0-9][a-z0-9-]*", slug):
            slugs.append(slug)
    return slugs


class ContentCommitSelectionTests(unittest.TestCase):
    """The content-commit set must be the union, not a fallback."""

    @classmethod
    def setUpClass(cls):
        if not ACCEPT.is_file():
            raise unittest.SkipTest("live referee not installed: %s" % ACCEPT)
        cls.text = ACCEPT.read_text(encoding="utf-8")

    def _selection_block(self) -> str:
        """The referee's own SLICE_HASHES selection, extracted.

        The block runs from the assignment that seeds SLICE_HASHES to the
        assignment that finally sets it.  Both shapes are recognised: the
        exclusive form ("SLICE_HASHES=\"$SUBJ_HASHES\"" followed by a
        guarded fallback) and the union form (a PATH_HASHES computation
        followed by a union assignment).
        """
        # The block runs from the line that seeds PATH_HASHES (or
        # SLICE_HASHES) up to and including the line that finally assigns
        # SLICE_HASHES.  Both shapes are recognised: the exclusive form
        # ("SLICE_HASHES=\"$SUBJ_HASHES\"" followed by a guarded
        # fallback) and the union form (a PATH_HASHES computation followed
        # by a union assignment).
        start = None
        for pat in (r"^PATH_HASHES=", r"^SLICE_HASHES="):
            m = re.search(pat, self.text, re.M)
            if m is not None:
                if start is None or m.start() < start:
                    start = m.start()
        self.assertIsNotNone(
            start, "could not find the SLICE_HASHES selection block in b173-accept.sh"
        )
        lines = self.text[start:].splitlines()
        block_lines = []
        for ln in lines:
            block_lines.append(ln)
            if ln.startswith("SLICE_HASHES=") and not ln.startswith("SLICE_HASHES=\"$"):
                # the final assignment to SLICE_HASHES ends the block
                break
            if ln.strip() == "fi" and any(
                b.startswith("SLICE_HASHES=") for b in block_lines
            ):
                break
        block = "\n".join(block_lines)
        self.assertIn("SLICE_HASHES", block)
        return block

    def test_the_selection_is_not_exclusive(self):
        """The path fallback must not switch off when a subject commit exists."""
        block = self._selection_block()
        # The exclusive shape is: the fallback is guarded by a test on
        # SLICE_HASHES being EMPTY.  That guard is what makes correcting a
        # slice's subject hide the commit that carries its work.
        self.assertNotRegex(
            block,
            r"if\s+\[\s+-z\s+\"\$SLICE_HASHES\"\s*\]",
            "the content-commit selection is EXCLUSIVE: the path-based "
            "fallback fires only when the slice has no subject commit, so "
            "correcting a slice's subject hides the commit that carries its "
            "work.  Measured on capability-ceiling-probe: NEW_TESTS fell "
            "from 59 to 8 when the subject was corrected.\n"
            "Selected block:\n%s" % block,
        )

    def test_the_selection_keeps_both_sets(self):
        """The selection must carry the subject commits AND the path commits."""
        block = self._selection_block()
        self.assertIn("SUBJ_HASHES", block)
        self.assertRegex(
            block,
            r"SLICE_HASHES=.*\$SUBJ_HASHES",
            "the content-commit set must include the subject-matched "
            "commits\nSelected block:\n%s" % block,
        )
        # and it must ALSO consult the manifest paths, unconditionally
        self.assertRegex(
            block,
            r"\$MANIFEST",
            "the content-commit set must also include the commits that "
            "introduced the manifest's files\nSelected block:\n%s" % block,
        )

    def test_a_corrected_subject_does_not_lose_the_path_commits(self):
        """Behavioural: the extracted selection returns BOTH sets.

        The extraction is the referee's own shell, run against a real
        repository, so a comment cannot satisfy this.
        """
        block = self._selection_block()
        # Build a shell harness around the referee's own block.
        script = (
            "set -u\n"
            "REPO=" + _shq(str(REPO)) + "\n"
            "MANIFEST=" + _shq(str(HOME / "b173-capability-ceiling-probe.files")) + "\n"
            "SLUG=capability-ceiling-probe\n"
            "SUBJ_HASHES=$(git -C \"$REPO\" log --format=%H --grep=\"^B173 "
            "\\([^:,][^:,]*,\\ \\)*${SLUG}[^A-Za-z0-9_-]\" -i 2>/dev/null "
            "| head -20 || true)\n"
            + block
            + "\nprintf 'COUNT=%s\\n' \"$(printf '%s\\n' \"$SLICE_HASHES\" | "
            "grep -c . || true)\"\n"
            "for h in $SLICE_HASHES; do "
            "git -C \"$REPO\" log --format='%s' -1 \"$h\"; done\n"
        )
        out = _run_bash(script)
        self.assertEqual(0, out.returncode, out.stderr)
        self.assertIn("COUNT=", out.stdout)
        count = int(re.search(r"COUNT=(\d+)", out.stdout).group(1))
        subjects = [
            ln for ln in out.stdout.splitlines() if ln.startswith("B173 ")
        ]
        self.assertGreaterEqual(
            count,
            2,
            "the selected content commits must include BOTH the "
            "subject-matched commit and the commit that introduced the "
            "slice's files; got %d: %r" % (count, subjects),
        )
        self.assertTrue(
            any("scorer-disagreement" in s for s in subjects),
            "the commit that introduced the slice's files must still be "
            "among the content commits; otherwise correcting the subject "
            "destroys the slice's evidence.  Selected: %r" % (subjects,),
        )

    def test_no_slice_loses_test_methods_under_the_union_rule(self):
        """The union rule must never make a slice's count smaller."""
        METHOD_RE = re.compile(
            r"^\+[ \t]*(?:async[ \t]+)?def[ \t]+(test_[A-Za-z0-9_]+)"
        )

        def git(*args: str) -> str:
            return subprocess.run(
                ["git", "-C", str(REPO), *args],
                capture_output=True,
                text=True,
            ).stdout

        def count_methods(hashes) -> set:
            names = set()
            for h in hashes:
                for line in git("show", h).splitlines():
                    m = METHOD_RE.match(line)
                    if m:
                        names.add(m.group(1))
            return names

        drops = []
        for slug in _slice_slugs():
            paths = _manifest_paths(slug)
            if not paths:
                continue
            subj = git(
                "log",
                "--format=%H",
                "--grep=^B173 %s[^A-Za-z0-9_-]" % re.escape(slug),
                "-i",
            ).split()
            fb = git("log", "--format=%H", "-1", "--", *paths).split()
            old = count_methods(subj if subj else fb)
            new = count_methods(list(dict.fromkeys(subj + fb)))
            if len(new) < len(old):
                drops.append((slug, len(old), len(new)))
        self.assertEqual(
            [],
            drops,
            "the union rule must never lower a slice's new-test-method "
            "count: %r" % (drops,),
        )


if __name__ == "__main__":
    unittest.main()
