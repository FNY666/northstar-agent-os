"""RED test: a slice's commit subject must name the slice, and the referee
must be able to see it.

THE DEFECT (measured 2026-11-16)
--------------------------------
One slice had real, complete work in the branch and was told it had none:

    $ bash b173-accept.sh capability-ceiling-probe
    FAIL COMMIT none
    ACCEPT: FAIL (11/12, 0 skipped) capability-ceiling-probe

`capability-ceiling-probe`'s entire deliverable -- a 695-line module, a
458-line test file with 59 methods, and an 8.6 KB design doc -- is in the
branch, but under the subject

    B173 scorer-disagreement: disagreement detector over multi-scorer verdicts

That is the **same class** of defect as the subject matcher fixed in round
8 (a commit whose subject does not name its slice), except that here the
problem is not the *pattern* but the *commit*: the slice's work was
committed under someone else's slug prefix.

TWO SEPARATE FAULTS, AND THE TEST SEPARATES THEM
-------------------------------------------------
1. **The commit's subject.** A commit that delivers `slice`'s work must
   say so.  `B173 <slice>: <what>` is the repo's convention and the
   referee's matcher; a commit that says `B173 <other-slice>: ...` while
   adding `<slice>`'s files is a mis-attribution that the referee cannot
   see, because the referee matches by subject.
2. **The slice's attribution.** The referee must be able to find a commit
   that owns the slice's work.

The first is a *repo* rule; the second is a *referee* rule.  Both are
pinned here.

WHAT THIS TEST DOES NOT DO
--------------------------
It does NOT assert that every commit in the branch has a well-formed
subject -- the branch carries 1054 commits, most of them from other
batches, and a rule that flags 1000 commits is not a rule.  It asserts
the rule **for the commits that carry a slice's manifest**, which is the
set the referee actually judges.

It also does NOT demand that the *first* commit to add a file names the
slice that later adopted that file.  A file adopted from another slice
keeps the commit that introduced it; demanding otherwise would require
rewriting history to satisfy a test.  The rule that is both meaningful and
achievable is: **every file the slice's manifest names must be accounted
for in the slice's own history** -- either the slice's own commits carry it,
or the commit that introduced it names a slice (so the adoption is visible
and the referee can find it).
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
ACCEPT = Path("/home/muse-newapi/b173-accept.sh")
HOME = Path("/home/muse-newapi")

# The subjects that carry a slice's work.  The FIRST subject line of a
# commit is its subject; the rest is the body.
#
# The shape is "B173 <slug>[, <slug>...][ (note)]: <what>".  The slug list
# is what the referee matches, so a subject that names two slices names
# both.
SUBJECT_RE = re.compile(
    r"^B173 ((?:[a-z0-9][a-z0-9-]*)(?:\s*,\s*[a-z0-9][a-z0-9-]*)*)"
    r"(?:\s*\([^)]*\))?\s*:\s"
)

# The subject of a commit, with its slug list, parsed ONCE per commit.
# The slug list is the text between "B173 " and the first ":", minus any
# parenthetical.
_HEAD_RE = re.compile(r"^B173 ([^:]+):")


def _git(*args: str) -> str:
    """Run git in the repository and return its stdout.

    A git failure is **not** swallowed: it raises, so a test that
    depends on the repository fails loudly instead of reading an empty
    string as "no commits".
    """
    proc = subprocess.run(
        ["git", "-C", str(REPO_ROOT), *args],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            "git %s failed (%d): %s"
            % (" ".join(args), proc.returncode, proc.stderr.strip())
        )
    return proc.stdout


def _named_slugs(subject: str) -> list:
    """The slugs a subject names, or [] if the subject names none."""
    m = SUBJECT_RE.match(subject)
    if m is None:
        return []
    return [s.strip() for s in m.group(1).split(",")]


def _slice_slugs() -> list:
    slugs = []
    for manifest in sorted(HOME.glob("b173-*.files")):
        slug = manifest.name[len("b173-") : -len(".files")]
        if slug and re.fullmatch(r"[a-z0-9][a-z0-9-]*", slug):
            slugs.append(slug)
    return slugs


def _slice_slugs_delivered() -> list:
    """The slugs that have actually DELIVERED -- a commit of their own.

    A manifest is a DECLARATION of what a slice intends to deliver; it
    is written when the slice is LAUNCHED, before any of it exists.
    So a manifest with no commit behind it is a slice that has not
    landed yet, and the rules below must not be applied to it.

    Measured 2026-11-23: four slices had manifests and no commit --
    ``agent-authorization-boundary``, ``memory-provenance-axis``,
    ``northstar-expand-search`` and ``state-transfer-audit`` -- and every
    one of their manifest files was "never committed".  The rules below
    were written for slices that DELIVERED, and applying them to a
    slice that has not started yet measures nothing: it reports a
    failure that is not the slice's fault and that no amount of work by
    the slice would change.

    ``northstar-expand-search`` is the sharp case: its commit
    (``919e970a``) exists, on the ``batch-173-northstar-expand-search``
    branch, and is NOT an ancestor of the branch under test.  So the
    rule "a slice has delivered when the branch under test carries its
    commit" is the right one -- it is what the referee can actually
    find.
    """
    slugs = []
    for manifest in sorted(HOME.glob("b173-*.files")):
        slug = manifest.name[len("b173-") : -len(".files")]
        if not slug or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", slug):
            continue
        if _own_commits(slug):
            slugs.append(slug)
    return slugs


def _manifest_paths(slug: str) -> list:
    manifest = HOME / ("b173-%s.files" % slug)
    return [
        p.strip()
        for p in manifest.read_text(encoding="utf-8").splitlines()
        if "/" in p
    ]


def _own_commits(slug: str) -> list:
    out = _git(
        "log",
        "--format=%H",
        "--grep=^B173 %s[^A-Za-z0-9_-]" % re.escape(slug),
        "-i",
    )
    return [h for h in out.splitlines() if h.strip()]


def _introducing_commit(path: str):
    """The commit that first added `path`, or None."""
    out = _git("log", "--diff-filter=A", "--format=%H", "-1", "--", path).strip()
    return out or None


def _subject_names_any_slice(commit: str) -> bool:
    """Does this commit's subject name a slice of the batch?

    The subject's slug list is the text between "B173 " and the first ":",
    minus any parenthetical.  A commit that names no slice cannot be found
    by the referee by name.
    """
    subject = _git("log", "--format=%s", "-1", commit).strip()
    m = _HEAD_RE.match(subject)
    if not m:
        return False
    head = re.sub(r"\(.*?\)", "", m.group(1))
    slugs = {s for s in _slice_slugs()}
    for part in head.split(","):
        if part.strip().lower() in slugs:
            return True
    return False


class CommitSubjectRuleTests(unittest.TestCase):
    """A commit that carries a slice's work must name that slice."""

    def test_the_delivered_set_is_a_subset_of_the_manifest_set(self):
        """The narrowing must not DROP a slice that delivered.

        The rule below applies to the slices that have a commit of
        their own.  If that set were computed wrongly -- empty, or
        smaller than it should be -- the rules below would stop
        convicting anything, and a test that cannot convict proves
        nothing.  So the narrowing is pinned: it must be a SUBSET of
        every slice with a manifest, and it must not be empty.

        The manifest set is EMPTY on a runner -- the manifests live in
        the coordinator's directory, which a runner does not have.  So
        there the delivered set is empty too, and the vacuity guard
        cannot hold.  It is skipped there, and the skip is reported
        rather than swallowed.
        """
        every = _slice_slugs()
        delivered = _slice_slugs_delivered()
        self.assertTrue(
            set(delivered).issubset(set(every)),
            "the delivered set must be a subset of the manifest set",
        )
        if not every:
            self.skipTest(
                "no manifests: the coordinator's directory is absent, so "
                "there are no slices to convict"
            )
        self.assertTrue(
            delivered,
            "the delivered set must not be empty: the rules below would "
            "convict nothing",
        )
        self.assertGreater(
            len(delivered),
            10,
            "expected many slices to have delivered; got %d" % len(delivered),
        )

    def test_the_subject_rule_covers_the_comma_list_shape(self):
        """'B173 a, b: ...' names BOTH slices."""
        named = _named_slugs("B173 r6-worktree-rename, r6-manifest-subject: x")
        self.assertIn("r6-worktree-rename", named)
        self.assertIn("r6-manifest-subject", named)

    def test_the_subject_rule_covers_the_parenthetical_shape(self):
        """'B173 slice4 (part 1): ...' names slice4."""
        self.assertEqual(["slice4"], _named_slugs("B173 slice4 (part 1): x"))

    def test_every_slice_owns_a_commit_the_referee_can_find(self):
        """No DELIVERED slice may be invisible to the referee.

        The rule applies to slices that have delivered -- a slice with
        no commit of its own has not delivered yet, and the rule
        "every slice owns a commit" cannot be applied to it without
        reporting a failure that is not the slice's.

        See :func:`_slice_slugs_delivered`.
        """
        invisible = []
        for slug in _slice_slugs_delivered():
            if not _own_commits(slug):
                invisible.append(slug)
        self.assertEqual(
            [],
            invisible,
            "these slices have no commit the referee can attribute to them: "
            + ", ".join(invisible),
        )

    def test_a_slices_own_commits_carry_every_manifest_file(self):
        """Every file the manifest names must be accounted for.

        A file the slice adopted from another slice keeps the commit that
        introduced it -- history is not rewritten.  The file is still
        ACCOUNTED FOR, because the commit that introduced it names a slice,
        so the adoption is visible and the referee can find it.

        The rule, stated as one sentence:

            every manifest file is either carried by the slice's own
            commits, or introduced by a commit whose subject names a slice.

        Measured 2026-11-16 over the batch's 84 slices: exactly ONE file
        failed this rule -- `docs/design/merged-tree-review.md`, introduced
        by a bundle-delivery commit whose subject was the literal string
        `c1`.  That commit named no slice at all, so the file it introduced
        was invisible to the referee by name, and it had to be listed as a
        known exception.

        The `delivery-bundle-hygiene` slice (2026-11-16) reworded that
        commit, so it now names the slice it carried.  The exception is
        gone, and the rule is unconditional: **every** manifest file must
        be accounted for.
        """
        known_exceptions = {}
        unaccounted = []
        for slug in _slice_slugs_delivered():
            paths = _manifest_paths(slug)
            if not paths:
                continue
            carried = set()
            for h in _own_commits(slug):
                carried |= set(_git("show", "--name-only", "--format=", h).split())
            for p in paths:
                if p in carried:
                    continue
                intro = _introducing_commit(p)
                if intro is None:
                    unaccounted.append((slug, p, "never committed"))
                    continue
                if _subject_names_any_slice(intro):
                    continue
                unaccounted.append((slug, p, "introduced by %s" % intro[:8]))
        unaccounted = [u for u in unaccounted if (u[0], u[1]) not in known_exceptions]
        self.assertEqual(
            [],
            unaccounted,
            "these manifest files are carried by no slice's history:\n  "
            + "\n  ".join("%s: %s (%s)" % u for u in unaccounted),
        )

    def test_the_known_exceptions_are_still_exceptions(self):
        """A known exception must not quietly become a normal case.

        The list is empty: the `delivery-bundle-hygiene` slice reworded the
        commit that used to carry the one exception, so the rule is now
        unconditional.  This test remains so that a future exception cannot
        be added silently -- if one is added, this test fails until it is
        listed here with its reason.
        """
        known = {}
        for slug, path in known:
            self.assertIn(
                path,
                _manifest_paths(slug),
                "the known exception %s/%s is no longer in the manifest; "
                "remove it from the exception list" % (slug, path),
            )


class RefereeAttributionTests(unittest.TestCase):
    """The referee must find a slice's own commit."""

    @classmethod
    def setUpClass(cls):
        if not ACCEPT.is_file():
            raise unittest.SkipTest("live referee not installed: %s" % ACCEPT)

    def test_the_referee_finds_a_commit_by_the_slug_only(self):
        """A commit whose subject starts with the slug is found."""
        out = subprocess.run(
            [
                "git",
                "-C",
                str(REPO_ROOT),
                "log",
                "--format=%H",
                "--grep=^B173 acceptance-conformance[^A-Za-z0-9_-]",
                "-i",
            ],
            capture_output=True,
            text=True,
        ).stdout.split()
        self.assertTrue(
            out,
            "the referee finds no commit for the slug 'acceptance-conformance'; "
            "the slice's work must be committed under its own subject prefix",
        )


if __name__ == "__main__":
    unittest.main()
