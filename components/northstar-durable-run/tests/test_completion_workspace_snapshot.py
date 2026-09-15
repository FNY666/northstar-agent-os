import hashlib
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from completion_batch_replay import (  # noqa: E402
    default_context,
    load_spec,
    observe_archived_workspace,
    replay_archive_task,
)
from completion_workspace_snapshot import (  # noqa: E402
    SnapshotPolicy,
    WorkspaceObservationRefused,
    materialize_workspace,
    observe_workspace,
)


ARCHIVE_ROOT = Path("/var/minis/shared/northstar-live-runs")
SPEC_PATH = ROOT / "replay" / "archive-replay-spec.json"
EVALUATOR = ROOT / "completion_contract_v2.py"
EMPTY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()


class WorkspaceObservationTests(unittest.TestCase):
    def observe(self, files, policy=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = materialize_workspace(temporary, files)
            return observe_workspace(root, policy)

    def test_text_files_are_retained_as_content(self):
        snapshot = self.observe({"README.md": "notes\n", "out/report.md": "Top scorer: carol\n"})
        self.assertEqual(sorted(snapshot.files), ["README.md", "out/report.md"])
        self.assertEqual(snapshot.files["out/report.md"].content, "Top scorer: carol\n")

    def test_observation_is_deterministic_and_sorted(self):
        snapshot = self.observe({"b.txt": "b", "a.txt": "a", "d/c.txt": "c"})
        self.assertEqual(list(snapshot.files), sorted(snapshot.files))

    def test_binary_content_is_reduced_to_a_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "blob.bin").write_bytes(b"\xff\xfe\x00\x01binary")
            snapshot = observe_workspace(root)
        self.assertIsNone(snapshot.files["blob.bin"].content)
        self.assertTrue(snapshot.files["blob.bin"].digest.startswith("sha256:"))

    def test_empty_file_is_a_digest_not_absence(self):
        """The contract needs absence and emptiness to stay distinguishable."""
        snapshot = self.observe({"empty.txt": ""})
        self.assertEqual(snapshot.as_dict(), {"empty.txt": EMPTY_DIGEST})
        self.assertNotEqual(snapshot.files["empty.txt"].content, "")

    def test_large_text_is_reduced_to_a_digest_under_policy(self):
        payload = "x" * 64
        snapshot = self.observe({"big.txt": payload}, SnapshotPolicy(max_text_bytes=16))
        self.assertIsNone(snapshot.files["big.txt"].content)
        self.assertEqual(
            snapshot.files["big.txt"].digest, "sha256:" + hashlib.sha256(payload.encode()).hexdigest()
        )

    def test_symlink_refuses_the_whole_observation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "real.txt").write_text("real", encoding="utf-8")
            (root / "link.txt").symlink_to(root / "real.txt")
            with self.assertRaises(WorkspaceObservationRefused):
                observe_workspace(root)

    def test_ignored_names_are_not_reported(self):
        snapshot = self.observe({".git/config": "x", "keep.txt": "y"})
        self.assertEqual(sorted(snapshot.files), ["keep.txt"])

    def test_depth_bound_refuses_the_whole_observation(self):
        with self.assertRaises(WorkspaceObservationRefused):
            self.observe({"a/b/c.txt": "x"}, SnapshotPolicy(max_depth=1))

    def test_entry_bound_refuses_the_whole_observation(self):
        with self.assertRaises(WorkspaceObservationRefused):
            self.observe({"a.txt": "a", "b.txt": "b"}, SnapshotPolicy(max_entries=1))

    def test_root_that_is_not_a_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "file.txt"
            target.write_text("x", encoding="utf-8")
            with self.assertRaises(WorkspaceObservationRefused):
                observe_workspace(target)

    def test_materialize_rejects_unsafe_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            for bad in ("../escape.txt", "/absolute.txt", "a/../b.txt"):
                with self.assertRaises(ValueError):
                    materialize_workspace(temporary, {bad: "x"})


class ArchivedObservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not ARCHIVE_ROOT.is_dir():
            raise unittest.SkipTest("archived runs are not available")
        cls.specs = load_spec(SPEC_PATH)
        cls.context = default_context(ARCHIVE_ROOT, EVALUATOR)

    def spec(self, run_name, task_id):
        for run in self.specs:
            if run.run != run_name:
                continue
            for task in run.tasks:
                if task.task_id == task_id:
                    return run, task
        raise AssertionError(f"spec not found: {run_name}/{task_id}")

    def test_observed_snapshot_is_seed_then_deliverable(self):
        run, task = self.spec("2026-09-11-action-failure-recovery", "live-transient-write-recovery-v1")
        with tempfile.TemporaryDirectory() as temporary:
            before, after = observe_archived_workspace(self.context, run, task, Path(temporary))
        self.assertEqual(sorted(before.files), ["README.md", "data/service-status.txt"])
        self.assertEqual(sorted(after.files), ["README.md", "data/service-status.txt", "out/recovery.md"])
        archived = (ARCHIVE_ROOT / run.run / "deliverables" / "recovery.md").read_text(encoding="utf-8")
        self.assertEqual(after.files["out/recovery.md"].content, archived)

    def test_observed_replay_matches_constructed_replay(self):
        """Real observation of materialized state must not change any verdict."""
        for run in self.specs:
            for task in run.tasks:
                for mode in ("digest", "semantic"):
                    constructed = replay_archive_task(self.context, run, task, mode=mode)
                    with tempfile.TemporaryDirectory() as temporary:
                        observed = replay_archive_task(
                            self.context, run, task, mode=mode, observed_root=Path(temporary)
                        )
                    self.assertEqual(
                        (observed.verdict, observed.errors),
                        (constructed.verdict, constructed.errors),
                        f"{run.run}/{task.task_id}/{mode}",
                    )

    def test_unbound_artifact_still_refuses_under_real_observation(self):
        """Tampering must be caught by binding, not by whichever snapshot source is used."""
        run, task = self.spec("2026-09-11-action-failure-recovery", "live-transient-write-recovery-v1")
        tampered = replace(task, artifacts={"out/recovery.md": "deliverables/never-written.md"})
        with tempfile.TemporaryDirectory() as temporary:
            outcome = replay_archive_task(
                self.context, run, tampered, mode="digest", observed_root=Path(temporary)
            )
        self.assertEqual(outcome.verdict, "insufficient_information")
        self.assertEqual(outcome.errors, ("archived_artifact_missing",))


if __name__ == "__main__":
    unittest.main()
