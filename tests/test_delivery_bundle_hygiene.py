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
        entries = _git("rev-list", "--objects", "--all").splitlines()
        names = [line.split(" ", 1)[1] for line in entries if " " in line]
        bundles = sorted(n for n in names if n.endswith(".bundle"))
        self.assertEqual(
            bundles,
            [],
            "the history still carries bundle objects: " + ", ".join(bundles),
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
        # Measured 2026-11-16: exactly two commits in the whole branch carry
        # a subject that does not start with "B173 " -- `71b606b8` ("c1") and
        # `a96df9a1` ("c2").  Both are bundle-delivery commits, and both are
        # invisible to the referee by name.
        subjects = []
        for line in _git("log", "--format=%H%x09%s", "--all").splitlines():
            if "\t" not in line:
                continue
            sha, subject = line.split("\t", 1)
            subjects.append((sha, subject))
        offenders = [
            (sha, subject)
            for sha, subject in subjects
            if not subject.startswith("B173 ")
        ]
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
        for line in _git("log", "--format=%s", "--all").splitlines():
            subject = line.strip()
            if subject:
                subjects.append(subject)
        bare = sorted({s for s in subjects if len(s) <= 2})
        self.assertEqual(
            bare,
            [],
            "commit subjects of one or two characters name nothing: "
            + ", ".join(bare),
        )


if __name__ == "__main__":
    unittest.main()
