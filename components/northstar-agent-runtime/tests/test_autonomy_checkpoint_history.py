"""Tests for the persisted continuation objective-continuity history."""
import unittest

from autonomy_checkpoint import capture_checkpoint
from autonomy_checkpoint_store import (
    AutonomyCheckpointStore,
    AutonomyCheckpointStoreError,
    ContinuationHistory,
)


def checkpoint(goal, *, observed_at, session_id="ns-history"):
    return capture_checkpoint(
        goal=goal,
        session_id=session_id,
        runtime={"permission_mode": "default"},
        transcript=[{"role": "user", "content": "continue"}],
        budget={"max_budget_usd": 1.0},
        observed_at=observed_at,
    )


class ContinuationHistoryTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        from pathlib import Path

        self._root = tempfile.TemporaryDirectory()
        self.addCleanup(self._root.cleanup)
        self.store = AutonomyCheckpointStore(Path(self._root.name) / "continuations.jsonl")

    def test_an_unchanged_objective_stays_continuous(self):
        first = self.store.append(checkpoint({"objective": "keep going"}, observed_at=1000))
        second = self.store.append(checkpoint({"objective": "keep going"}, observed_at=1010))
        history = self.store.history("ns-history")
        self.assertEqual(history.state, "continuous")
        self.assertEqual(history.changed_at_sequence, None)
        self.assertEqual([entry.sequence for entry in history.entries], [1, 2])
        self.assertEqual([entry.record_digest for entry in history.entries],
                         [first.record_digest, second.record_digest])
        self.assertEqual(history.head_digest, second.record_digest)
        self.assertEqual(history.reasons, ())
        self.assertFalse(history.execution_authorized)

    def test_a_silent_objective_change_is_reported_while_the_store_stays_green(self):
        self.store.append(checkpoint({"objective": "ship the release"}, observed_at=1000))
        self.store.append(checkpoint({"objective": "delete production"}, observed_at=1010))
        resolution = self.store.resolve("ns-history")
        self.assertEqual(resolution.state, "recorded-unpinned")
        self.assertEqual(resolution.reasons, ())
        history = self.store.history("ns-history")
        self.assertEqual(history.state, "objective_changed")
        self.assertEqual(history.changed_at_sequence, 2)
        self.assertIn("objective_changed", history.reasons)
        self.assertNotEqual(
            history.entries[0].objective_digest, history.entries[1].objective_digest
        )
        self.assertEqual(history.entries[1].objective_digest,
                         checkpoint({"objective": "delete production"}, observed_at=1010).goal_digest)

    def test_a_tampered_store_is_unverifiable_and_lists_no_entries(self):
        import json
        from pathlib import Path

        self.store.append(checkpoint({"objective": "keep going"}, observed_at=1000))
        rows = self.store.path.read_text(encoding="utf-8").splitlines()
        row = json.loads(rows[0])
        row["checkpoint"]["goal_digest"] = "sha256:" + "0" * 64
        self.store.path.write_text(json.dumps(row) + "\n", encoding="utf-8")
        history = self.store.history("ns-history")
        self.assertEqual(history.state, "unverifiable")
        self.assertEqual(history.entries, ())
        self.assertFalse(history.execution_authorized)

    def test_an_unrecorded_session_is_reported_without_entries(self):
        history = self.store.history("ns-history")
        self.assertEqual(history.state, "unrecorded")
        self.assertEqual(history.entries, ())
        self.assertEqual(history.head_digest, None)
        self.assertIn("continuation_history_unrecorded", history.reasons)

    def test_another_session_history_is_not_mixed_in(self):
        self.store.append(checkpoint({"objective": "keep going"}, observed_at=1000))
        self.store.append(checkpoint({"objective": "other"}, observed_at=1010, session_id="ns-other"))
        self.assertEqual(self.store.history("ns-history").state, "continuous")
        self.assertEqual(len(self.store.history("ns-other").entries), 1)

    def test_head_drift_and_the_missing_pin_are_both_reported(self):
        self.store.append(checkpoint({"objective": "keep going"}, observed_at=1000))
        head = self.store.history("ns-history").head_digest
        pinned = self.store.history("ns-history", expected_head_digest=head)
        self.assertEqual(pinned.unverified, ())
        self.assertEqual(pinned.reasons, ())
        drifted = self.store.history("ns-history", expected_head_digest="sha256:" + "0" * 64)
        self.assertIn("history_head_changed", drifted.reasons)
        unpinned = self.store.history("ns-history")
        self.assertIn("history_head_unpinned", unpinned.unverified)

    def test_history_wire_revalidates_structure_and_never_authorizes(self):
        self.store.append(checkpoint({"objective": "keep going"}, observed_at=1000))
        history = self.store.history("ns-history")
        self.assertEqual(ContinuationHistory.from_dict(history.to_dict()), history)
        claimed = history.to_dict()
        claimed["execution_authorized"] = True
        with self.assertRaises(AutonomyCheckpointStoreError):
            ContinuationHistory.from_dict(claimed)
        for field, value in (
            ("state", "not-a-state"),
            ("head_digest", "nope"),
            ("changed_at_sequence", "abc"),
            ("entries", "nope"),
            ("session_id", ""),
        ):
            tampered = history.to_dict()
            tampered[field] = value
            with self.assertRaises(AutonomyCheckpointStoreError):
                ContinuationHistory.from_dict(tampered)
        # A derived report carries no self digest, so rewriting a field with
        # another *valid* value is not detectable in the wire form; that is only
        # caught by recomputation from the chain, or by pinning head_digest.
        rewritten = history.to_dict()
        rewritten["state"] = "objective_changed"
        self.assertEqual(ContinuationHistory.from_dict(rewritten).state, "objective_changed")


class RuntimeContinuationHistoryTests(unittest.TestCase):
    def _runtime(self, *, sessions=None):
        from loop import AgentRuntime, RuntimeConfig
        from providers.scripted import ScriptedProvider

        return AgentRuntime(
            provider=ScriptedProvider([]),
            config=RuntimeConfig(session_id="ns-history", workspace=".", max_budget_usd=1.0),
            sessions=sessions,
        )

    def test_runtime_reports_objective_continuity_without_resuming_anything(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as root:
            store = AutonomyCheckpointStore(Path(root) / "continuations.jsonl")
            runtime = self._runtime()
            runtime.persist_continuation_checkpoint(
                store, goal={"objective": "keep going"}, observed_at=1000
            )
            runtime.persist_continuation_checkpoint(
                store, goal={"objective": "something else"}, observed_at=1010
            )
            history = runtime.continuation_objective_history(store)
            self.assertEqual(history.state, "objective_changed")
            self.assertEqual(history.changed_at_sequence, 2)
            self.assertFalse(history.execution_authorized)
            self.assertEqual(runtime.provider.requests, [])


if __name__ == "__main__":
    unittest.main()
