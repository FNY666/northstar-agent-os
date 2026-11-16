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
        offenders = []
        for line in _batch_commits():
            sha, subject = line.split("\t", 1)
            if not subject.startswith("B173 "):
                offenders.append((sha, subject))
        self.assertEqual(
            offenders,
            [],
            "commits whose subject does not start with 'B173 ': "
            + ", ".join("%s (%s)" % (sha[:8], subject) for sha, subject in offenders),
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
