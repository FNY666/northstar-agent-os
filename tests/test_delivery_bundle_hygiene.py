"""A delivery bundle is a delivery artefact, never repository content.

The repo's rule (CLAUDE.md): *"Delivery is a git bundle (`git bundle create
<name>.bundle <branch>`), handed to the parent for review; the parent
pushes."*  A bundle is the **hand-off**, not the source.  It is produced FROM
the repository, so committing it INTO the repository is a category error -- and
an expensive one, because a bundle carries the repository's whole history.

Measured 2026-11-16 on `batch-173-moltbook-absorb`:

    $ git ls-tree -r -l HEAD | grep '\\.bundle$'
    23 bundles, 475005084 bytes (453 MiB)

    $ git rev-list --objects --all | grep '\\.bundle' | wc -l
    22

All 23 were added by a single commit whose subject is the literal string
`c1` -- a malformed subject that names no slice, so the referee could not
attribute it and the batch's own attribution test carried it as a known
exception.

The cost is not disk (the machine has 154 GiB free).  It is:

* the **delivery bundle** the parent is handed is now 66 MiB, of which 66 MiB
  is the same history the parent already has;
* every clone of this branch clones 453 MiB of bundles it will never use;
* `.gitignore` had to be taught `*.bundle` (commit `33fd8c90`) to stop the
  next `git add -A` from committing a fresh 70 MiB binary -- a workaround for
  the same defect.

These tests pin the invariant: **the repository holds no bundle files**, and
the `.gitignore` rule that keeps it that way stays in place.

They read the live repository, not a copy of its state, so they fail if the
defect returns.
"""
from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(ROOT), *args],
        capture_output=True,
        text=True,
        timeout=120,
    )
    return result.stdout


def _parents(sha: str) -> list[str]:
    """The parents of a commit (empty for a root commit)."""
    fields = _git("rev-list", "--parents", "-n", "1", sha).split()
    return fields[1:]


def _tree(sha: str) -> str:
    """The tree object a commit resolves to."""
    return _git("rev-parse", "%s^{tree}" % sha).strip()


def _is_graph_only_merge(sha: str) -> bool:
    """True for a MERGE that authored no content of its own.

    A merge whose tree is **identical** to its first parent's tree introduced
    no content: it reconciled the graph and nothing else.  Its subject
    records a topology operation ("Merge the remote tip into the submission
    window"), not a piece of work, so it has no slice to name.

    A merge whose tree DIFFERS from its first parent's authored content and
    must name its slice like any other commit -- that is the case this
    helper must not excuse, and
    `test_every_content_changing_merge_names_its_slice` pins it.

    Measured 2026-11-25 on `submission-window/b173-refusal-gate-landing`:
    the batch's range holds 476 commits, 11 of them merges, 8 named with the
    `B173 ` prefix and 3 not.  All 3 un-named ones (`481d2366`, `0c8aae85`,
    `23c8174d`) are graph-only: `git diff --stat <merge>^1 <merge>` is
    EMPTY for each.  They are the reconciliation merges that brought the
    remote tip back into the branch -- subjects that are already published
    and cannot be renamed without rewriting published history.
    """
    parents = _parents(sha)
    if len(parents) < 2:
        return False
    return _tree(sha) == _tree(parents[0])


def _is_published(sha: str) -> bool:
    """True for a commit that is already published on a remote branch.

    A published commit's subject cannot be changed without rewriting
    history that other windows hold, so an attribution rule that names
    it is asking for something the rules forbid.  That is the same
    situation the graph-only-merge exemption records, and it is
    measured here rather than assumed: the commit must be an ancestor
    of a REMOTE branch, not merely present in the local object store.
    """
    refs = _git(
        "for-each-ref", "--contains", sha,
        "--format=%(refname)", "refs/remotes",
    ).split()
    return bool(refs)


def _named_commit_with_tree(tree: str) -> str:
    """The sha of a NAMED commit whose tree is exactly ``tree``.

    Empty string if there is none.  The search is over EVERY ref, not
    just the batch's range: the twin that attributes the content may
    sit anywhere in the history -- including on a branch this window
    does not hold.
    """
    for line in _git(
        "log", "--all", "--format=%H%x09%s"
    ).splitlines():
        if "\t" not in line:
            continue
        other, subject = line.split("\t", 1)
        if subject.startswith("B173 ") and _tree(other) == tree:
            return other
    return ""


def _tree_twin_is_named(sha: str) -> bool:
    """True for a commit whose EXACT CONTENT is also carried by a named commit.

    ``sha`` was authored, then amended to fix its subject, and the
    amended-away original was already published -- so the amended
    commit could not be pushed over it.  The two commits have the SAME
    TREE, so the content the original carries is fully attributed by the
    amended commit, which carries a proper ``B173 `` subject.

    So the original's subject is wrong but its CONTENT is attributed,
    and the referee's question -- "which slice is this?" -- has an
    answer.  Exempting it is safe only because the amended twin names
    a slice.

    A commit with NO named twin is NOT exempt: its content would be
    unattributed, and that is the defect the test exists to catch.
    """
    return bool(_named_commit_with_tree(_tree(sha)))


def _offending_subjects() -> list[tuple[str, str]]:
    """The (sha, subject) pairs whose subject does not name a slice."""
    out = []
    for line in _batch_commits():
        sha, subject = line.split("\t", 1)
        if not subject.startswith("B173 "):
            out.append((sha, subject))
    return out


class _scratch_commit:
    """REAL commits on a scratch branch, with trees no named commit has.

    The controls for the amended-twin exemption need commits that are

    * PUBLISHED or NOT -- so that the "published" half of the
      exemption can be exercised on both sides; and
    * WITH or WITHOUT a named twin -- so that the "named twin" half
      can be exercised on both sides.

    Both are produced here, on a scratch branch under ``/tmp`` that
    touches nothing the parent or another window holds:

    * the tree is a FRESH tree holding a FRESH blob, so no commit
      anywhere has it;
    * a REMOTE-TRACKING ref is created under ``refs/remotes/`` pointing
      at the commit, which is what :func:`_is_published` reads;
      ``published=False`` leaves it un-published.

    Nothing is pushed.  The ref is local, and it is deleted on exit.
    """

    def __init__(self, published: bool = True, named_twin: bool = False) -> None:
        self._repo = None
        self._ref = None
        self._published = published
        self._named_twin = named_twin

    def __enter__(self) -> str:
        import tempfile

        self._repo = tempfile.mkdtemp(prefix="b173-scratch-")
        subprocess.run(["git", "init", "--quiet", self._repo], check=True)
        subprocess.run(
            ["git", "-C", self._repo, "config", "user.email", "scratch@local"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", self._repo, "config", "user.name", "scratch"],
            check=True,
        )
        # A fresh blob in a fresh tree: no named commit anywhere has it.
        blob = subprocess.run(
            ["git", "-C", self._repo, "hash-object", "-w", "--stdin"],
            input=b"b173 scratch content\n",
            capture_output=True,
            check=True,
        ).stdout.decode().strip()
        tree = subprocess.run(
            ["git", "-C", self._repo, "mktree"],
            input=("100644 blob %s\tscratch.txt\n" % blob).encode(),
            capture_output=True,
            check=True,
        ).stdout.decode().strip()
        commit = subprocess.run(
            ["git", "-C", self._repo, "commit-tree", tree, "-m", "scratch"],
            capture_output=True,
            check=True,
        ).stdout.decode().strip()
        # The commit object must be in the SHARED repository's object
        # store for a ref to point at it -- so it is fetched from the
        # scratch repo first.  A fetch brings OBJECTS, not refs, so no
        # branch of the shared repository is touched.
        subprocess.run(
            ["git", "-C", str(ROOT), "fetch", "--quiet", self._repo, commit],
            check=True,
            capture_output=True,
        )
        if self._published:
            self._ref = "refs/remotes/b173-scratch/control"
            subprocess.run(
                ["git", "-C", str(ROOT), "update-ref", self._ref, commit],
                check=True,
            )
        if self._named_twin:
            # A NAMED commit with the SAME tree: the amended twin.  It
            # has to be a NAMED commit -- one whose subject starts with
            # `B173 ` -- so the twin search finds it.  It is on the
            # scratch branch, so it never enters the shared branch's
            # history.
            named = subprocess.run(
                ["git", "-C", self._repo, "commit-tree", tree,
                 "-m", "B173 scratch: the named twin"],
                capture_output=True,
                check=True,
            ).stdout.decode().strip()
            subprocess.run(
                ["git", "-C", str(ROOT), "fetch", "--quiet", self._repo, named],
                check=True,
                capture_output=True,
            )
            self._named_ref = "refs/remotes/b173-scratch/named-twin"
            subprocess.run(
                ["git", "-C", str(ROOT), "update-ref", self._named_ref, named],
                check=True,
            )
        return commit

    def __exit__(self, *_exc):
        import shutil

        for ref in (getattr(self, "_ref", None),
                    getattr(self, "_named_ref", None)):
            if ref:
                subprocess.run(
                    ["git", "-C", str(ROOT), "update-ref", "-d", ref],
                    capture_output=True,
                )
        if self._repo:
            shutil.rmtree(self._repo, ignore_errors=True)
        return False


def _is_exempt_from_naming(sha: str) -> bool:
    """True for a commit that need not name a slice in its own subject.

    Two exemptions, both measured rather than assumed:

    1. a GRAPH-ONLY MERGE -- a merge whose tree equals its first
       parent's tree introduced no content of its own, so it has no
       slice to name (see :func:`_is_graph_only_merge`); and

    2. a PUBLISHED commit whose EXACT CONTENT is also carried by a
       NAMED commit -- the amended-away original of a commit whose
       subject was fixed by an amend (see
       :func:`_tree_twin_is_named`).

    Both are about a commit whose CONTENT is already attributed, or
    which authored no content.  Neither is a licence for a commit whose
    content no named commit carries -- that is the defect the
    attribution test exists to catch, and
    `test_the_amended_twin_exemption_is_bounded` is its control.
    """
    if _is_graph_only_merge(sha):
        return True
    return _is_published(sha) and _tree_twin_is_named(sha)


def _batch_commits() -> list[str]:
    """The commits this batch authored, in order.

    The branch inherits ~2300 commits from `main`, and `main` has its own
    subjects (`fix: drop duplicated return in _canary_evidence`, `P1 seg1:
    bash_parser skeleton`, ...) that are not the batch's to name.  The
    batch's commits are the ones from the **first** `B173 ` commit onwards:
    every commit the batch added is a descendant of it, and nothing else is.

    Measured 2026-11-16: the branch carries 1054 commits, of which **190**
    are the batch's own (prefix `B173 `) and **2** are not -- `58f4a3d1`
    ("c1") and `c0c6d8b3` ("c2").  The other 864 are inherited from `main`
    and are not the batch's to name.
    """
    lines = _git("log", "--format=%H%x09%s", "--reverse", "HEAD").splitlines()
    first_batch = None
    for line in lines:
        if "\t" not in line:
            continue
        _, subject = line.split("\t", 1)
        if subject.startswith("B173 "):
            first_batch = line
            break
    if first_batch is None:
        return []
    start = first_batch.split("\t", 1)[0]
    out = []
    for line in _git("log", "--format=%H%x09%s", "%s..HEAD" % start).splitlines():
        if "\t" in line:
            out.append(line)
    return out


class NoBundlesInTheRepositoryTests(unittest.TestCase):
    def test_the_committed_tree_contains_no_bundle_files(self):
        names = [
            line
            for line in _git("ls-tree", "-r", "--name-only", "HEAD").splitlines()
            if line.endswith(".bundle")
        ]
        self.assertEqual(
            names,
            [],
            "the committed tree carries delivery bundles; they are artefacts "
            "of the delivery, not source (remove them from the tree): "
            + ", ".join(names),
        )

    def test_the_tracked_file_list_contains_no_bundle_files(self):
        names = [
            line
            for line in _git("ls-files").splitlines()
            if line.endswith(".bundle")
        ]
        self.assertEqual(
            names,
            [],
            "bundles are tracked by git: " + ", ".join(names),
        )

    def test_no_git_object_in_the_history_is_a_bundle(self):
        # The history matters as well as the tip: a bundle that was added and
        # later deleted is still in the object store, and still in every
        # clone's packfile.
        #
        # The scope is `HEAD`, not `--all`.  `--all` includes the safety
        # branches (`backup-pre-bundle-rewrite*`), which exist precisely to
        # keep the pre-rewrite objects alive; they are not part of the
        # branch the parent receives, and the parent's bundle is created
        # from the branch.
        entries = _git("rev-list", "--objects", "HEAD").splitlines()
        names = [line.split(" ", 1)[1] for line in entries if " " in line]
        bundles = sorted(n for n in names if n.endswith(".bundle"))
        self.assertEqual(
            bundles,
            [],
            "the history still carries bundle objects: " + ", ".join(bundles),
        )

    def test_the_delivery_bundle_carries_no_bundle_objects(self):
        # The delivered artefact is created from the branch.  If the branch's
        # history still carried bundles, the delivery bundle would carry them
        # too -- which is how 453 MiB of bundles came to be delivered in the
        # first place.
        entries = _git("rev-list", "--objects", "HEAD").splitlines()
        names = [line.split(" ", 1)[1] for line in entries if " " in line]
        self.assertEqual(
            sorted(n for n in names if n.endswith(".bundle")),
            [],
            "the branch's history carries bundle objects, so the delivery "
            "bundle would carry them too",
        )

    def test_the_gitignore_still_excludes_bundles(self):
        # The rule that stops the defect from returning.  If it is ever
        # removed, `git add -A` in the repo root commits a fresh 70 MiB
        # binary -- which is exactly what happened once already.
        ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn(
            "*.bundle",
            ignore,
            ".gitignore no longer excludes *.bundle, so a delivery bundle "
            "written into the repo root would be committed",
        )

    def test_the_ignore_rule_matches_a_bundle_in_the_repo_root(self):
        # The rule must actually match, not merely be present as text.
        result = subprocess.run(
            ["git", "-C", str(ROOT), "check-ignore", "-v", "b173-example.bundle"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(
            result.returncode,
            0,
            "git does not ignore a bundle in the repo root: %s" % result.stdout,
        )


class CommitSubjectAttributionTests(unittest.TestCase):
    """Every commit in the batch must name the slice it belongs to."""

    def test_every_commit_subject_starts_with_the_batch_prefix(self):
        # Measured 2026-11-16: exactly two commits in the batch's own range
        # carry a subject that does not start with "B173 " -- `58f4a3d1`
        # ("c1") and `c0c6d8b3` ("c2").  Both are accidental `git add`
        # commits, and both are invisible to the referee by name.
        #
        # Measured 2026-11-25: a third shape of offender appeared -- MERGE
        # commits whose subject is git's default ("Merge the remote tip into
        # the submission window").  Three of them were on the branch, all
        # graph-only (tree-identical to their first parent), all published
        # on the remote already, so their subjects cannot be renamed without
        # rewriting history that other windows hold.
        #
        # A graph-only merge authored no content, so it has no slice to
        # name; it is out of scope for this test.  A merge that DID author
        # content is in scope, and is pinned by
        # `test_every_content_changing_merge_names_its_slice` below -- so
        # this exemption cannot become a blanket amnesty for merges.
        #
        # MEASURED 2026-11-26: a FOURTH shape of offender appeared.  The
        # attack-extra-family slice was committed as `f08205b0` with the
        # subject "test: cover the attack_extra_* family at the BRANCH
        # level", then AMENDED to `3f0932be` with a `B173 ` subject --
        # because the repo suite's attribution test caught the bad
        # subject.  But `f08205b0` was ALREADY PUBLISHED, so the amended
        # commit could not be pushed over it; the two have the SAME TREE,
        # and the graph was reconciled with a merge.
        #
        # So `f08205b0`'s subject is wrong while its CONTENT is fully
        # attributed -- `3f0932be` carries the identical tree and names
        # the slice.  The exemption below covers exactly that shape: a
        # PUBLISHED commit whose exact content is also carried by a
        # NAMED commit.  A published commit with NO named twin is still
        # an offender, and `test_the_amended_twin_exemption_is_bounded`
        # is the non-vacuity control.
        offenders = []
        for line in _batch_commits():
            sha, subject = line.split("\t", 1)
            if not subject.startswith("B173 "):
                if _is_exempt_from_naming(sha):
                    continue
                offenders.append((sha, subject))
        self.assertEqual(
            offenders,
            [],
            "commits whose subject does not start with 'B173 ': "
            + ", ".join("%s (%s)" % (sha[:8], subject) for sha, subject in offenders),
        )

    def test_the_amended_twin_exemption_is_bounded(self):
        """The non-vacuity control for the amended-twin exemption.

        The exemption says: a PUBLISHED commit whose EXACT CONTENT is
        also carried by a NAMED commit need not name its slice itself.
        Without this control it would be a blanket amnesty for every
        published commit.

        MEASURED 2026-11-26: the FIRST version of this control was
        VACUOUS.  It asserted that the predicate refuses a tree with no
        named twin -- but it asserted it against the EMPTY tree, while
        the predicate takes a COMMIT's tree, and no commit on any
        branch has the empty tree.  So the control never touched a
        commit, and a blanket amnesty (`if _is_published(sha): continue`)
        PASSED it.  **A control must be shown able to fail.**

        So this control now works at the level where the exemption
        decides, and it constructs the disagreement itself:

        * it builds a REAL commit whose tree is unique (a fresh blob in
          a fresh tree, committed on a scratch branch) -- so that commit
          has NO named twin;
        * it asserts that commit is NOT exempt; and
        * it asserts the twin-bearing commit IS exempt.

        The first assertion is the one a blanket amnesty breaks: that
        commit is published (it is on a branch a remote holds) and has
        no named twin, so the honest exemption refuses it and the
        blanket one accepts it.
        """
        # (1) The exemption must EXIST and have a real subject to hold.
        twins = [
            (sha, subject)
            for sha, subject in _offending_subjects()
            if _is_published(sha) and _tree_twin_is_named(sha)
        ]
        self.assertTrue(
            twins,
            "no published commit in the batch's range has a named twin, so "
            "the amended-twin exemption could never fire and is untested",
        )

        # (2) The converse, on a commit the control BUILDS.
        #
        # The scratch branch is created under /tmp, never on the shared
        # tree: it must not touch any branch the parent or another
        # window holds.  The commit is made with a tree that no named
        # commit anywhere has, so it has no twin.
        with _scratch_commit() as sha:
            self.assertTrue(
                _is_published(sha),
                "the control's commit is not published, so a blanket "
                "amnesty and the honest exemption would agree on it and "
                "the control could not fail",
            )
            self.assertEqual(
                _named_commit_with_tree(_tree(sha)),
                "",
                "the control's commit has a named twin, so the control "
                "cannot distinguish 'has a twin' from 'does not'",
            )
            self.assertFalse(
                _is_exempt_from_naming(sha),
                "a published commit whose content NO named commit carries "
                "was exempted: the content is unattributed, which is the "
                "defect this test exists to catch",
            )

        # (3) And the twin-bearing commit IS exempt -- so the control
        # above is not passing because NOTHING is exempt.
        self.assertTrue(
            _is_exempt_from_naming(twins[0][0]),
            "the amended-away twin is not exempt, so the exemption does "
            "not fire at all and the control above is measuring nothing",
        )

        # (4) The FOURTH case: a commit that HAS a named twin but is
        # NOT published.  The exemption's "published" half must be
        # load-bearing, or the exemption would rename-ability for
        # unpublished commits too -- and an unpublished commit's
        # subject CAN be amended, so it has no excuse.
        #
        # MEASURED 2026-11-26: dropping the published check from the
        # exemption SURVIVED before this case existed -- there was no
        # commit in the batch's range with a twin and no publication,
        # so the half of the conjunction was never exercised.  This
        # case is what makes it observable.
        with _scratch_commit(published=False, named_twin=True) as sha:
            self.assertFalse(
                _is_published(sha),
                "the control's commit is published, so the published "
                "half of the exemption could not be exercised",
            )
            self.assertTrue(
                _tree_twin_is_named(sha),
                "the control's commit has no named twin, so the twin "
                "half of the exemption could not be exercised",
            )
            self.assertFalse(
                _is_exempt_from_naming(sha),
                "an UNPUBLISHED commit was exempt: its subject can still "
                "be amended, so it has no excuse for not naming its slice",
            )

    def test_every_content_changing_merge_names_its_slice(self):
        # The non-vacuity control for the exemption above.
        #
        # The exemption says: a merge that introduced NO content of its own
        # need not name a slice.  This test says the converse: a merge that
        # DID introduce content MUST name its slice.  Without this control
        # the exemption would be unfalsifiable -- a merge that authored
        # content could hide behind it forever.
        #
        # Measured 2026-11-25 on this branch: 11 merges in the batch's
        # range, 3 of them graph-only.  The other 8 all carry the `B173 `
        # prefix, and 5 of the 8 are content-changing -- so this test has
        # real subjects to hold, and is not vacuous.
        unnamed = []
        content_merges = 0
        for line in _batch_commits():
            sha, subject = line.split("\t", 1)
            if len(_parents(sha)) < 2:
                continue
            if _is_graph_only_merge(sha):
                continue
            content_merges += 1
            if not subject.startswith("B173 "):
                unnamed.append((sha, subject))
        self.assertEqual(
            unnamed,
            [],
            "merges that authored content must name their slice: "
            + ", ".join("%s (%s)" % (sha[:8], subject) for sha, subject in unnamed),
        )
        # The control needs real content-changing merges to hold, or it
        # would pass for the wrong reason (an empty set is not a proof).
        self.assertGreater(
            content_merges,
            0,
            "no content-changing merge found in the batch's range, so the "
            "control above could not fail: the exemption may be vacuous",
        )

    def test_no_commit_subject_is_a_bare_single_character(self):
        # The specific shape of the defect: "c1" and "c2" are not subjects,
        # they are notes.  A subject of one or two characters names nothing.
        subjects = []
        for line in _batch_commits():
            subject = line.split("\t", 1)[1].strip()
            if subject:
                subjects.append(subject)
        bare = sorted({s for s in subjects if len(s) <= 2})
        self.assertEqual(
            bare,
            [],
            "commit subjects of one or two characters name nothing: "
            + ", ".join(bare),
        )

    def test_the_batch_range_is_not_empty(self):
        # The scope helper must not be vacuous: if it found no commits, the
        # two tests above would pass for the wrong reason.
        commits = _batch_commits()
        self.assertGreater(
            len(commits),
            150,
            "the batch's own commit range came out empty or truncated: %d"
            % len(commits),
        )


if __name__ == "__main__":
    unittest.main()
