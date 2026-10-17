"""Local fixture tests for committed Git snapshot export.

These tests create only temporary repositories.  They do not contact a remote, inspect
user repositories, or read credentials/signing keys.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import export_git_snapshot as snapshot  # noqa: E402
from trusted_common import EvidenceError  # noqa: E402


GIT = "/usr/bin/git"


def git(directory: Path, *arguments: str, input: bytes | None = None) -> bytes:
    completed = subprocess.run(
        [GIT, *arguments], cwd=directory, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
    )
    if completed.returncode:
        raise AssertionError(f"fixture Git failed: {arguments!r}: {completed.stderr!r}")
    return completed.stdout


def make_raw_commit(directory: Path, tree: str) -> str:
    raw = (
        f"tree {tree}\n"
        "author Fixture <fixture@example.invalid> 0 +0000\n"
        "committer Fixture <fixture@example.invalid> 0 +0000\n\n"
        "malformed-tree fixture\n"
    ).encode("ascii")
    return git(directory, "hash-object", "-t", "commit", "-w", "--stdin", input=raw).strip().decode("ascii")


def write_raw_tree(directory: Path, raw: bytes) -> str:
    """Write intentionally malformed fixture bytes without asking Git to fsck them."""
    framed = b"tree " + str(len(raw)).encode("ascii") + b"\0" + raw
    oid = hashlib.sha1(framed).hexdigest()
    destination = directory / ".git" / "objects" / oid[:2] / oid[2:]
    destination.parent.mkdir(exist_ok=True)
    destination.write_bytes(zlib.compress(framed))
    return oid


class ExportGitSnapshotCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="git-snapshot-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.name", "Fixture")
        git(self.repo, "config", "user.email", "fixture@example.invalid")
        (self.repo / "src").mkdir()
        (self.repo / "src" / "app.py").write_bytes(b"print('committed source')\n")
        (self.repo / "run.sh").write_bytes(b"#!/bin/sh\necho fixture\n")
        os.chmod(self.repo / "run.sh", 0o755)
        (self.repo / ".gitignore").write_text("tracked-but-ignored.txt\n", encoding="utf-8")
        (self.repo / ".gitattributes").write_text("tracked-but-ignored.txt export-ignore\nfiltered.txt filter=marker\n", encoding="utf-8")
        (self.repo / "tracked-but-ignored.txt").write_bytes(b"Git archive must not choose this\n")
        (self.repo / "filtered.txt").write_bytes(b"raw committed filter bytes\n")
        git(self.repo, "add", "-A", "-f")
        git(self.repo, "commit", "-q", "-m", "fixture")
        self.commit = git(self.repo, "rev-parse", "HEAD").strip().decode("ascii")

    def assert_rejected_without_output(self, repo: Path, commit: str, name: str) -> None:
        output = self.root / name
        with self.assertRaises(EvidenceError):
            snapshot.export_git_snapshot(repo, commit, output)
        self.assertFalse(output.exists(), "a rejected snapshot must not publish partial output")

    def test_exports_raw_commit_tree_not_archive_checkout_or_filters(self) -> None:
        marker = self.root / "candidate-command-must-not-run"
        git(self.repo, "config", "filter.marker.clean", f"sh -c 'touch {marker}'")
        git(self.repo, "config", "filter.marker.smudge", f"sh -c 'touch {marker}'")
        hook = self.repo / ".git" / "hooks" / "post-checkout"
        hook.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
        os.chmod(hook, 0o755)

        # These must not alter the selected commit tree.  The untracked file also
        # demonstrates that only tree entries, not a working-tree copy, are exported.
        (self.repo / "src" / "app.py").write_bytes(b"uncommitted working-tree edit\n")
        (self.repo / "untracked-extra.txt").write_bytes(b"not committed\n")
        result = snapshot.export_git_snapshot(self.repo, self.commit, self.root / "snapshot")

        exported = self.root / "snapshot" / "source"
        self.assertEqual(b"print('committed source')\n", (exported / "src" / "app.py").read_bytes())
        self.assertEqual(b"Git archive must not choose this\n", (exported / "tracked-but-ignored.txt").read_bytes())
        self.assertEqual(b"raw committed filter bytes\n", (exported / "filtered.txt").read_bytes())
        self.assertFalse((exported / "untracked-extra.txt").exists())
        self.assertFalse(marker.exists(), "filters and hooks must never execute")
        self.assertEqual(self.commit, result["git_commit"])
        self.assertEqual(git(self.repo, "rev-parse", f"{self.commit}^{{tree}}").strip().decode("ascii"), result["git_tree"])
        self.assertEqual(0, stat.S_IMODE((exported / "src" / "app.py").stat().st_mode) & 0o222)
        self.assertTrue(stat.S_IMODE((exported / "run.sh").stat().st_mode) & stat.S_IXUSR)
        self.assertEqual(0, stat.S_IMODE((exported / "run.sh").stat().st_mode) & 0o222)

        manifest_raw = (self.root / "snapshot" / "candidate-manifest.json").read_bytes()
        manifest = json.loads(manifest_raw)
        self.assertEqual("northstar.git-snapshot.v1", manifest["schema"])
        self.assertEqual(result["candidate_manifest_sha256"], hashlib.sha256(manifest_raw).hexdigest())
        self.assertEqual(result["candidate_manifest_sha256"], result["manifest_sha256"])
        self.assertEqual([entry["path"] for entry in result["files"]], sorted(entry["path"] for entry in result["files"]))
        self.assertEqual(0, stat.S_IMODE((self.root / "snapshot").stat().st_mode) & 0o222)

    def test_bare_repository_is_a_supported_normal_case(self) -> None:
        bare = self.root / "fixture.git"
        git(self.root, "init", "--bare", "-q", str(bare))
        git(self.repo, "remote", "add", "local", str(bare))
        git(self.repo, "push", "-q", "local", f"{self.commit}:refs/heads/main")
        result = snapshot.export_git_snapshot(bare, self.commit, self.root / "bare-snapshot")
        self.assertEqual(self.commit, result["git_commit"])
        self.assertEqual(b"print('committed source')\n", (self.root / "bare-snapshot/source/src/app.py").read_bytes())

    def test_rejects_ref_existing_output_gitfile_and_gitdir_link(self) -> None:
        self.assert_rejected_without_output(self.repo, "HEAD", "bad-ref")
        existing = self.root / "existing"
        existing.mkdir()
        sentinel = existing / "sentinel"
        sentinel.write_bytes(b"preserve")
        with self.assertRaises(EvidenceError):
            snapshot.export_git_snapshot(self.repo, self.commit, existing)
        self.assertEqual(b"preserve", sentinel.read_bytes())

        linked = self.root / "linked-worktree"
        git(self.repo, "worktree", "add", "--detach", "-q", str(linked), self.commit)
        self.assert_rejected_without_output(linked, self.commit, "gitfile")
        git(self.repo, "worktree", "remove", "--force", str(linked))

        fake = self.root / "gitdir-link"
        fake.mkdir()
        (fake / ".git").symlink_to(self.repo / ".git", target_is_directory=True)
        self.assert_rejected_without_output(fake, self.commit, "rejected-gitdir-link")

    def test_rejects_tree_path_symlink_submodule_and_special_entries(self) -> None:
        blob = git(self.repo, "hash-object", "-w", "--stdin", input=b"fixture\n").strip().decode("ascii")
        commit_bytes = bytes.fromhex(self.commit)
        cases = {
            "path": b"100644 ../escape\0" + bytes.fromhex(blob),
            "symlink": b"120000 link\0" + bytes.fromhex(blob),
            "submodule": b"160000 nested\0" + commit_bytes,
            "special": b"100600 unusual\0" + bytes.fromhex(blob),
        }
        for name, tree_raw in cases.items():
            with self.subTest(name=name):
                tree = write_raw_tree(self.repo, tree_raw)
                bad_commit = make_raw_commit(self.repo, tree)
                self.assert_rejected_without_output(self.repo, bad_commit, f"bad-{name}")

    def test_rejects_alternates_partial_config_damaged_objects_and_oversize(self) -> None:
        objects_info = self.repo / ".git" / "objects" / "info"
        (objects_info / "alternates").write_text("/no/such/object/store\n", encoding="utf-8")
        self.assert_rejected_without_output(self.repo, self.commit, "alternates")
        (objects_info / "alternates").unlink()

        with (self.repo / ".git" / "config").open("a", encoding="utf-8") as handle:
            handle.write("\n[extensions]\n\tpartialClone = fixture\n")
        self.assert_rejected_without_output(self.repo, self.commit, "partial")
        # Restore a conventional local config for the following independent cases.
        git(self.repo, "config", "--unset", "extensions.partialClone")

        blob = git(self.repo, "rev-parse", "HEAD:src/app.py").strip().decode("ascii")
        loose = self.repo / ".git" / "objects" / blob[:2] / blob[2:]
        self.assertTrue(loose.is_file(), "the fixture blob must be loose to damage it locally")
        os.chmod(loose, 0o644)
        loose.write_bytes(b"not a valid Git object")
        self.assert_rejected_without_output(self.repo, self.commit, "damaged")

        # A fresh fixture isolates the budget case from the intentionally damaged one.
        too_big = self.root / "too-big"
        too_big.mkdir()
        git(too_big, "init", "-q")
        git(too_big, "config", "user.name", "Fixture")
        git(too_big, "config", "user.email", "fixture@example.invalid")
        (too_big / "large.txt").write_bytes(b"more-than-four-bytes")
        git(too_big, "add", "large.txt")
        git(too_big, "commit", "-q", "-m", "large")
        large_commit = git(too_big, "rev-parse", "HEAD").strip().decode("ascii")
        original = snapshot.MAX_BLOB_BYTES
        self.addCleanup(setattr, snapshot, "MAX_BLOB_BYTES", original)
        snapshot.MAX_BLOB_BYTES = 4
        self.assert_rejected_without_output(too_big, large_commit, "oversize")


if __name__ == "__main__":
    unittest.main()
