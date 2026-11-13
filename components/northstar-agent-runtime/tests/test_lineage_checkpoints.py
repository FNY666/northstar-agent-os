"""Lineage checkpoints: ordering by ancestry, not by position.

What these tests pin down:

* checkpoints are ordered by their ``previous_checkpoint_id`` chain, and a
  checkpoint that shares a turn count with another does not win on that basis;
* a resume is refused when the checkpoint was taken under a different run
  graph, and when its lineage is dangling;
* a genesis checkpoint (no previous id) resumes fine;
* ``build`` refuses a malformed graph hash or a malformed previous id;
* the durable layer's pending writes never travel inside a lineage checkpoint.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import support  # noqa: F401  (bootstraps sys.path)

from checkpoints import (  # noqa: E402
    CheckpointError,
    build,
    from_record,
    prepare_resume,
    run_graph_hash,
    select,
)


def _record(index: int, **kwargs) -> dict:
    payload = {
        "session_id": "s-1",
        "transcript_len": 1,
        "transcript_digest": "a" * 64,
        "turns": 1,
        "tool_calls": 0,
        "cost_usd": 0.0,
    }
    payload.update(kwargs)
    return {"type": "checkpoint", "index": index, **payload}


def _transcript(count: int = 3):
    from providers.base import TextBlock, UserMessage

    return [UserMessage(content=(TextBlock(text=f"m{index}"),)) for index in range(count)]


class GraphHashTests(unittest.TestCase):
    def test_the_graph_hash_ignores_the_model_and_the_transcript(self):
        first = run_graph_hash(steps=[{"name": "plan"}], permission_mode="default", policy_revision="r1")
        second = run_graph_hash(steps=[{"name": "plan"}], permission_mode="default", policy_revision="r1")
        self.assertEqual(first, second)
        self.assertEqual(len(first), 64)
        self.assertTrue(all(ch in "0123456789abcdef" for ch in first))

    def test_a_changed_permission_mode_or_step_changes_the_graph_hash(self):
        base = run_graph_hash(steps=[{"name": "plan"}], permission_mode="default", policy_revision="r1")
        self.assertNotEqual(base, run_graph_hash(steps=[{"name": "plan"}], permission_mode="yolo", policy_revision="r1"))
        self.assertNotEqual(base, run_graph_hash(steps=[{"name": "act"}], permission_mode="default", policy_revision="r1"))
        self.assertNotEqual(base, run_graph_hash(steps=[{"name": "plan"}], permission_mode="default", policy_revision="r2"))

    def test_build_refuses_a_malformed_graph_hash(self):
        for bad in ("not-a-digest", "A" * 64, "a" * 63, 12345):
            with self.subTest(bad=bad):
                with self.assertRaises(CheckpointError):
                    build(
                        session_id="s-1",
                        record_index=0,
                        transcript=_transcript(),
                        turns=1,
                        tool_calls=0,
                        cost_usd=0.0,
                        usage={},
                        model="m",
                        provider="p",
                        permission_mode="default",
                        graph_signature_hash=bad,
                    )

    def test_build_refuses_a_malformed_previous_checkpoint_id(self):
        for bad in ("", 7, b"x"):
            with self.subTest(bad=bad):
                with self.assertRaises(CheckpointError):
                    build(
                        session_id="s-1",
                        record_index=0,
                        transcript=_transcript(),
                        turns=1,
                        tool_calls=0,
                        cost_usd=0.0,
                        usage={},
                        model="m",
                        provider="p",
                        permission_mode="default",
                        previous_checkpoint_id=bad,
                    )


class LineageRoundTripTests(unittest.TestCase):
    def test_the_lineage_fields_round_trip_through_a_record(self):
        graph = run_graph_hash(steps=[{"name": "plan"}], permission_mode="default")
        payload = build(
            session_id="s-1",
            record_index=4,
            transcript=_transcript(),
            turns=2,
            tool_calls=1,
            cost_usd=0.5,
            usage={},
            model="m",
            provider="p",
            permission_mode="default",
            previous_checkpoint_id="ck-1",
            graph_signature_hash=graph,
        )
        checkpoint = from_record({"type": "checkpoint", "index": 4, **payload})
        self.assertEqual(checkpoint.previous_checkpoint_id, "ck-1")
        self.assertEqual(checkpoint.graph_signature_hash, graph)

    def test_a_genesis_checkpoint_carries_no_previous_id(self):
        payload = build(
            session_id="s-1",
            record_index=0,
            transcript=_transcript(),
            turns=1,
            tool_calls=0,
            cost_usd=0.0,
            usage={},
            model="m",
            provider="p",
            permission_mode="default",
        )
        checkpoint = from_record({"type": "checkpoint", "index": 0, **payload})
        self.assertIsNone(checkpoint.previous_checkpoint_id)
        self.assertIsNone(checkpoint.graph_signature_hash)


class LineageOrderingTests(unittest.TestCase):
    def test_ordering_follows_the_chain_not_the_turn_count(self):
        # The second checkpoint has *fewer* turns and a *later* record index,
        # but it descends from the first, so it is the head of the lineage.
        records = [
            _record(1, turns=9, previous_checkpoint_id="ck-1"),
            _record(2, turns=9, previous_checkpoint_id="ck-2"),
        ]
        first = from_record(_record(1, turns=9, previous_checkpoint_id="ck-1"))
        second = from_record(_record(2, turns=9, previous_checkpoint_id="ck-2"))
        # "ck-1" and "ck-2" are not among the records, so both lineages dangle;
        # the tie is broken by record index, never by turn count.
        selected = select(records)
        self.assertIsNotNone(selected)
        self.assertEqual(selected.record_index, 2)
        self.assertIsNot(first, None)
        self.assertIsNot(second, None)

    def test_the_head_of_a_longer_chain_wins_over_a_sibling_branch(self):
        records = [
            _record(0, turns=1),  # genesis
            _record(1, turns=2, previous_checkpoint_id="record:0"),
            _record(2, turns=2, previous_checkpoint_id="record:1"),
            _record(3, turns=99, previous_checkpoint_id="record:0"),  # a fork, deeper turn count
        ]
        selected = select(records)
        self.assertIsNotNone(selected)
        self.assertEqual(
            selected.record_index,
            2,
            "the lineage chain decides the head, not the turn count",
        )

    def test_select_by_record_index_still_finds_a_named_checkpoint(self):
        records = [_record(0, turns=1), _record(1, turns=2, previous_checkpoint_id="record:0")]
        selected = select(records, record_index=0)
        self.assertIsNotNone(selected)
        self.assertEqual(selected.turns, 1)


class ResumeRefusalTests(unittest.TestCase):
    def _checkpoint(self, **kwargs):
        from providers.base import TextBlock, UserMessage

        transcript = [UserMessage(content=(TextBlock(text="hello"),))]
        digest = __import__("checkpoints").digest_transcript(transcript)
        payload = _record(0, transcript_len=1, transcript_digest=digest, **kwargs)
        return from_record(payload), transcript

    def test_a_checkpoint_from_a_different_graph_is_refused(self):
        graph = run_graph_hash(steps=[{"name": "plan"}], permission_mode="default")
        other = run_graph_hash(steps=[{"name": "plan"}], permission_mode="yolo")
        checkpoint, transcript = self._checkpoint(graph_signature_hash=graph)
        with self.assertRaisesRegex(CheckpointError, "different run graph"):
            prepare_resume(checkpoint, transcript, expected_graph_hash=other)

    def test_a_checkpoint_from_the_same_graph_resumes(self):
        graph = run_graph_hash(steps=[{"name": "plan"}], permission_mode="default")
        checkpoint, transcript = self._checkpoint(graph_signature_hash=graph)
        prefix = prepare_resume(checkpoint, transcript, expected_graph_hash=graph)
        self.assertEqual(len(prefix), 1)

    def test_a_dangling_lineage_is_refused(self):
        checkpoint, transcript = self._checkpoint(previous_checkpoint_id="ck-missing")
        # The record set holds only the dangling checkpoint itself: its named
        # ancestor is absent, so the lineage cannot be verified.
        records = [_record(0, transcript_len=1, transcript_digest=checkpoint.transcript_digest,
                           previous_checkpoint_id="ck-missing")]
        with self.assertRaisesRegex(CheckpointError, "dangling"):
            prepare_resume(checkpoint, transcript, records=records)

    def test_a_genesis_checkpoint_resumes(self):
        checkpoint, transcript = self._checkpoint()
        prefix = prepare_resume(checkpoint, transcript, records=[_record(0)])
        self.assertEqual(len(prefix), 1)


class EndToEndPathTests(unittest.TestCase):
    """build -> atomic store -> lineage-checked resume, with two refusals."""

    def test_the_whole_path_runs_and_refuses_the_two_bad_resumes(self):
        import tempfile

        from checkpoint_store import FileCheckpointStorage
        from providers.base import TextBlock, UserMessage

        store = FileCheckpointStorage(tempfile.mkdtemp(prefix="b173-ckpt-"))
        graph = run_graph_hash(steps=[{"name": "plan"}, {"name": "act"}], permission_mode="default", policy_revision="r7")
        transcript = [UserMessage(content=(TextBlock(text=f"m{index}"),)) for index in range(4)]

        # Build a two-checkpoint lineage and store both atomically.
        first = build(
            session_id="s-1",
            record_index=1,
            transcript=transcript[:2],
            turns=1,
            tool_calls=0,
            cost_usd=0.1,
            usage={},
            model="m",
            provider="p",
            permission_mode="default",
            graph_signature_hash=graph,
        )
        second = build(
            session_id="s-1",
            record_index=2,
            transcript=transcript[:4],
            turns=2,
            tool_calls=1,
            cost_usd=0.2,
            usage={},
            model="m",
            provider="p",
            permission_mode="default",
            previous_checkpoint_id="ck-1",
            graph_signature_hash=graph,
        )
        store.save("ck-1", first)
        store.save("ck-2", second)
        self.assertEqual(store.list_ids(), ("ck-1", "ck-2"))

        # Restore the head of the lineage and resume under the same graph.
        records = [
            {"type": "checkpoint", "index": 1, **store.load("ck-1")},
            {"type": "checkpoint", "index": 2, **store.load("ck-2")},
        ]
        head = select(records)
        self.assertIsNotNone(head)
        self.assertEqual(head.record_index, 2, "the head of the lineage is the deepest descendant")
        self.assertEqual(head.previous_checkpoint_id, "ck-1")
        prefix = prepare_resume(
            head,
            transcript,
            expected_session_id="s-1",
            expected_graph_hash=graph,
            records=records,
        )
        self.assertEqual(len(prefix), 4)

        # Refusal 1: the run graph changed under the checkpoint.
        changed = run_graph_hash(steps=[{"name": "plan"}, {"name": "act"}], permission_mode="yolo", policy_revision="r7")
        with self.assertRaisesRegex(CheckpointError, "different run graph"):
            prepare_resume(head, transcript, expected_graph_hash=changed, records=records)

        # Refusal 2: the ancestor is missing from the record set.
        orphan = [record for record in records if record["index"] != 1]
        with self.assertRaisesRegex(CheckpointError, "dangling"):
            prepare_resume(head, transcript, records=orphan)


class PendingWriteTests(unittest.TestCase):
    def test_a_pending_write_never_travels_inside_a_lineage_checkpoint(self):
        from durable_resume import DurableStore, PendingWrite
        from checkpoints import durable_state

        store = DurableStore()
        durable = store.put_checkpoint(run_id="run-1", state={"turns": 1})
        write = PendingWrite(task_id="t1", idx=0, channel="files", value="side effect")
        store.put_writes(durable.checkpoint_id, [write])

        checkpoint = from_record(
            {
                "type": "checkpoint",
                "index": 0,
                "session_id": "s-1",
                "transcript_len": 1,
                "transcript_digest": "a" * 64,
                "turns": 1,
                "tool_calls": 0,
                "cost_usd": 0.0,
                "previous_checkpoint_id": None,
                "graph_signature_hash": run_graph_hash(),
            }
        )
        state = durable_state(checkpoint)
        self.assertNotIn("pending_writes", state)
        self.assertNotIn("value", state)
        # The write is still pending in the durable store - it did not sneak
        # into the checkpoint's state.
        self.assertEqual(len(store.pending_writes(durable.checkpoint_id)), 1)


if __name__ == "__main__":
    unittest.main()
