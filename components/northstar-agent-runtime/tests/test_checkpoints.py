"""Deterministic contracts for the local reversible workspace kernel."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

import support  # noqa: F401
from checkpoints import (
    CheckpointError,
    CheckpointPolicy,
    create_checkpoint,
    diff_checkpoint,
    fork_checkpoint,
    list_checkpoints,
    prune_checkpoints,
    rewind_checkpoint,
)


class CheckpointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="northstar-checkpoint-"))
        self.workspace = self.tmp / "workspace"
        self.workspace.mkdir()
        self.sessions = self.tmp / "sessions"
        (self.workspace / "src").mkdir()
        (self.workspace / "src" / "main.py").write_text("print('before')\n", encoding="utf-8")
        (self.workspace / "README.md").write_text("before\n", encoding="utf-8")

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_policy_is_opt_in_and_has_deterministic_boundaries(self):
        policy = CheckpointPolicy(enabled=True, every_turns=3, after_mutation=True, max_checkpoints=2)
        self.assertFalse(policy.should_checkpoint(turn_index=1, mutated=False))
        self.assertTrue(policy.should_checkpoint(turn_index=1, mutated=True))
        self.assertFalse(policy.should_checkpoint(turn_index=2, mutated=False))
        self.assertTrue(policy.should_checkpoint(turn_index=3, mutated=False))
        self.assertEqual(policy.label(turn_index=3, mutated=False), "auto:turn-3")
        with self.assertRaises(ValueError):
            CheckpointPolicy(enabled=True, every_turns=0)
        with self.assertRaises(ValueError):
            CheckpointPolicy(enabled=True, label_prefix="bad\nlabel")

    def test_automatic_retention_preserves_manual_checkpoints_and_rebases_chain(self):
        manual = create_checkpoint(self.workspace, self.sessions, "ns-retain", label="operator baseline")
        for index in range(1, 4):
            (self.workspace / "README.md").write_text(f"automatic {index}\\n", encoding="utf-8")
            create_checkpoint(self.workspace, self.sessions, "ns-retain", label=f"auto:turn-{index}")
        removed = prune_checkpoints(
            self.sessions,
            "ns-retain",
            max_checkpoints=2,
            label_prefix="auto",
        )
        self.assertEqual(len(removed), 1)
        remaining = list_checkpoints(self.sessions, "ns-retain")
        self.assertEqual([item.label for item in remaining], ["operator baseline", "auto:turn-2", "auto:turn-3"])
        self.assertEqual(remaining[1].parent_checkpoint_id, manual.checkpoint_id)
        self.assertTrue((remaining[-1].snapshot_root / "README.md").is_file())

    def test_manifest_is_bounded_content_addressed_and_reloadable(self):
        checkpoint = create_checkpoint(self.workspace, self.sessions, "ns-check", label="before edit")
        self.assertEqual(len(list_checkpoints(self.sessions, "ns-check")), 1)
        self.assertEqual(checkpoint.label, "before edit")
        self.assertEqual(checkpoint.as_dict()["file_count"], 2)
        manifest = json.loads(checkpoint.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema_version"], "northstar.checkpoint.v1")
        self.assertEqual(manifest["checkpoint_id"], checkpoint.checkpoint_id)
        self.assertEqual(manifest["workspace_digest"], checkpoint.workspace_digest)
        self.assertEqual(manifest["session_index"], -1)
        self.assertIsNone(manifest["parent_checkpoint_id"])
        self.assertTrue((checkpoint.snapshot_root / "src" / "main.py").is_file())

    def test_later_checkpoints_link_to_the_parent_and_transcript_index(self):
        session_file = self.sessions / "ns-chain.jsonl"
        self.sessions.mkdir()
        session_file.write_text(
            json.dumps({"index": 0, "type": "session_start"}) + "\n" +
            json.dumps({"index": 3, "type": "result"}) + "\n",
            encoding="utf-8",
        )
        first = create_checkpoint(self.workspace, self.sessions, "ns-chain", label="first")
        second = create_checkpoint(self.workspace, self.sessions, "ns-chain", label="second")
        self.assertEqual(first.session_index, 3)
        self.assertEqual(second.parent_checkpoint_id, first.checkpoint_id)
        self.assertEqual(second.session_index, 3)

    def test_symlinked_files_fail_closed_instead_of_being_followed(self):
        outside = self.tmp / "outside.txt"
        outside.write_text("must not be copied", encoding="utf-8")
        try:
            os.symlink(outside, self.workspace / "leak.txt")
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are unavailable on this platform")
        with self.assertRaisesRegex(CheckpointError, "symlink"):
            create_checkpoint(self.workspace, self.sessions, "ns-symlink")

    def test_diff_reports_modified_deleted_and_added_files(self):
        checkpoint = create_checkpoint(self.workspace, self.sessions, "ns-diff")
        (self.workspace / "README.md").write_text("after\n", encoding="utf-8")
        (self.workspace / "src" / "main.py").unlink()
        (self.workspace / "new.txt").write_text("new\n", encoding="utf-8")
        comparison = diff_checkpoint(checkpoint, self.workspace)
        self.assertFalse(comparison.clean)
        self.assertEqual(
            [(change.path, change.status) for change in comparison.changes],
            [("README.md", "modified"), ("new.txt", "added"), ("src/main.py", "deleted")],
        )

    def test_rewind_requires_force_restores_bytes_and_keeps_added_files_by_default(self):
        checkpoint = create_checkpoint(self.workspace, self.sessions, "ns-rewind")
        (self.workspace / "README.md").write_text("after\n", encoding="utf-8")
        (self.workspace / "new.txt").write_text("keep me\n", encoding="utf-8")
        with self.assertRaisesRegex(CheckpointError, "force"):
            rewind_checkpoint(checkpoint, self.workspace)
        report = rewind_checkpoint(
            checkpoint,
            self.workspace,
            force=True,
            safety_session_dir=self.sessions,
            safety_session_id="ns-rewind",
        )
        self.assertEqual((self.workspace / "README.md").read_text(encoding="utf-8"), "before\n")
        self.assertEqual((self.workspace / "new.txt").read_text(encoding="utf-8"), "keep me\n")
        self.assertEqual(report["remaining_added_files"], 1)
        self.assertIsNotNone(report["safety_checkpoint_id"])
        self.assertEqual(len(list_checkpoints(self.sessions, "ns-rewind")), 2)

    def test_rewind_can_explicitly_delete_regular_files_added_after_checkpoint(self):
        checkpoint = create_checkpoint(self.workspace, self.sessions, "ns-delete")
        (self.workspace / "added.txt").write_text("delete me", encoding="utf-8")
        report = rewind_checkpoint(checkpoint, self.workspace, force=True, delete_added=True)
        self.assertFalse((self.workspace / "added.txt").exists())
        self.assertEqual(report["deleted_added_files"], 1)
        self.assertEqual(report["remaining_added_files"], 0)

    def test_fork_materialises_a_new_workspace_and_records_lineage(self):
        checkpoint = create_checkpoint(self.workspace, self.sessions, "ns-source")
        target = self.tmp / "forked-workspace"
        report = fork_checkpoint(checkpoint, target, self.sessions, "ns-fork")
        self.assertEqual(report.source_session_id, "ns-source")
        self.assertEqual(report.source_checkpoint_id, checkpoint.checkpoint_id)
        self.assertEqual((target / "README.md").read_text(encoding="utf-8"), "before\n")
        self.assertEqual((target / "src" / "main.py").read_text(encoding="utf-8"), "print('before')\n")
        self.assertEqual(len(list_checkpoints(self.sessions, "ns-fork")), 1)
        lineage = json.loads((self.sessions / "checkpoints" / "ns-fork" / "fork.json").read_text(encoding="utf-8"))
        self.assertEqual(lineage["source_checkpoint_id"], checkpoint.checkpoint_id)
        self.assertEqual(lineage["session_id"], "ns-fork")
        with self.assertRaisesRegex(CheckpointError, "already exists"):
            fork_checkpoint(checkpoint, target, self.sessions, "ns-other")

    def test_tampered_snapshot_fails_closed_before_rewind(self):
        checkpoint = create_checkpoint(self.workspace, self.sessions, "ns-tamper")
        snapshot = checkpoint.snapshot_root / "README.md"
        snapshot.write_text("tampered", encoding="utf-8")
        with self.assertRaisesRegex(CheckpointError, "digest mismatch"):
            diff_checkpoint(checkpoint, self.workspace)

    def test_symlinked_checkpoint_tree_fails_closed(self):
        checkpoint = create_checkpoint(self.workspace, self.sessions, "ns-snapshot-link")
        outside = self.tmp / "outside-dir"
        outside.mkdir()
        (outside / "main.py").write_text("outside", encoding="utf-8")
        import shutil

        try:
            shutil.rmtree(checkpoint.snapshot_root / "src")
            os.symlink(outside, checkpoint.snapshot_root / "src", target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are unavailable on this platform")
        with self.assertRaisesRegex(CheckpointError, "symlink"):
            diff_checkpoint(checkpoint, self.workspace)

    def test_runtime_storage_inside_workspace_is_not_snapshotted(self):
        session_id = "ns-inside"
        (self.workspace / f"{session_id}.jsonl").write_text(
            json.dumps({"index": 2, "type": "result"}) + "\n", encoding="utf-8"
        )
        checkpoint = create_checkpoint(self.workspace, self.workspace, session_id)
        paths = {entry.path for entry in checkpoint.files}
        self.assertEqual(paths, {"README.md", "src/main.py"})

    def test_empty_workspace_still_has_a_verified_snapshot_root(self):
        empty = self.tmp / "empty"
        empty.mkdir()
        checkpoint = create_checkpoint(empty, self.sessions, "ns-empty")
        self.assertTrue(checkpoint.snapshot_root.is_dir())
        self.assertTrue(diff_checkpoint(checkpoint, empty).clean)

    def test_checkpoint_rejects_an_unmanifested_snapshot_file(self):
        checkpoint = create_checkpoint(self.workspace, self.sessions, "ns-extra")
        (checkpoint.snapshot_root / "extra.txt").write_text("not in manifest", encoding="utf-8")
        with self.assertRaisesRegex(CheckpointError, "unmanifested"):
            diff_checkpoint(checkpoint, self.workspace)

    def test_checkpoint_rejects_a_manifest_with_duplicate_paths(self):
        checkpoint = create_checkpoint(self.workspace, self.sessions, "ns-manifest")
        manifest = json.loads(checkpoint.manifest_path.read_text(encoding="utf-8"))
        manifest["files"].append(dict(manifest["files"][0]))
        checkpoint.manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(CheckpointError, "duplicate"):
            list_checkpoints(self.sessions, "ns-manifest")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
