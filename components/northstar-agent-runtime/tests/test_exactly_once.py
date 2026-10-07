"""Tests for exactly_once.py."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from exactly_once import (  # noqa: E402
    EXACTLY_ONCE_VERSION,
    SCHEMA_PIN,
    Checkpoint,
    CheckpointIntegrityError,
    EventOrderError,
    ExactlyOnce,
    ExactlyOnceError,
    PayloadMismatchError,
    ProcessOutcome,
    ProcessedEntry,
    ResultNotCanonicalError,
    exactly_once_audit_event,
)


def _handler(payload):
    return {"echo": payload}


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(EXACTLY_ONCE_VERSION, "exactly-once.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.exactly-once.v1")


class TestValidation(unittest.TestCase):
    def setUp(self):
        self.proc = ExactlyOnce()

    def test_empty_event_id(self):
        with self.assertRaises(ValueError):
            self.proc.process("", {"n": 1}, _handler, seq=0)

    def test_non_str_event_id(self):
        with self.assertRaises(TypeError):
            self.proc.process(123, {"n": 1}, _handler, seq=0)

    def test_bool_event_id(self):
        with self.assertRaises(TypeError):
            self.proc.process(True, {"n": 1}, _handler, seq=0)

    def test_long_event_id(self):
        with self.assertRaises(ValueError):
            self.proc.process("e" * 1025, {"n": 1}, _handler, seq=0)

    def test_bool_seq(self):
        with self.assertRaises(TypeError):
            self.proc.process("e1", {"n": 1}, _handler, seq=True)

    def test_negative_seq(self):
        with self.assertRaises(ValueError):
            self.proc.process("e1", {"n": 1}, _handler, seq=-1)

    def test_nan_payload(self):
        with self.assertRaises(TypeError):
            self.proc.process("e1", {"n": float("nan")}, _handler, seq=0)

    def test_inf_payload(self):
        with self.assertRaises(TypeError):
            self.proc.process("e1", [float("inf")], _handler, seq=0)

    def test_non_str_dict_key_payload(self):
        with self.assertRaises(TypeError):
            self.proc.process("e1", {1: "x"}, _handler, seq=0)

    def test_non_callable_handler(self):
        with self.assertRaises(TypeError):
            self.proc.process("e1", {"n": 1}, "not-callable", seq=0)


class TestProcess(unittest.TestCase):
    def setUp(self):
        self.proc = ExactlyOnce()

    def test_first_sight_runs_handler(self):
        outcome = self.proc.process("e1", {"n": 1}, _handler, seq=0)
        self.assertFalse(outcome.hit)
        self.assertEqual(outcome.event_id, "e1")
        self.assertEqual(outcome.result, {"echo": {"n": 1}})
        self.assertEqual(outcome.first_seq, 0)
        self.assertTrue(outcome.result_digest.startswith("sha256:"))
        self.assertTrue(outcome.payload_digest.startswith("sha256:"))
        self.assertEqual(outcome.schema, SCHEMA_PIN)

    def test_replay_does_not_rerun_handler(self):
        calls = []

        def counting(payload):
            calls.append(payload)
            return "ok"

        self.proc.process("e1", {"n": 5}, counting, seq=0)
        replay = self.proc.process("e1", {"n": 5}, counting, seq=0)
        self.assertTrue(replay.hit)
        self.assertEqual(replay.result, "ok")
        self.assertEqual(replay.first_seq, 0)
        self.assertEqual(len(calls), 1)

    def test_replay_result_is_cached_not_recomputed(self):
        state = {"n": 0}

        def mutating(payload):
            state["n"] += 1
            return state["n"]

        first = self.proc.process("e1", {}, mutating, seq=0)
        replay = self.proc.process("e1", {}, mutating, seq=0)
        self.assertEqual(first.result, 1)
        self.assertEqual(replay.result, 1)
        self.assertTrue(replay.hit)

    def test_payload_mismatch_raises(self):
        self.proc.process("e1", {"n": 1}, _handler, seq=0)
        with self.assertRaises(PayloadMismatchError):
            self.proc.process("e1", {"n": 2}, _handler, seq=1)
        self.assertTrue(self.proc.seen("e1"))

    def test_payload_mismatch_is_exactly_once_error(self):
        self.assertTrue(issubclass(PayloadMismatchError, ExactlyOnceError))

    def test_handler_exception_propagates_and_not_recorded(self):
        def bad(payload):
            raise RuntimeError("boom")

        with self.assertRaises(RuntimeError):
            self.proc.process("e1", {"n": 1}, bad, seq=0)
        self.assertFalse(self.proc.seen("e1"))
        # redelivery retries the handler exactly once
        outcome = self.proc.process("e1", {"n": 1}, _handler, seq=0)
        self.assertFalse(outcome.hit)

    def test_non_canonicalizable_result_raises_and_not_recorded(self):
        def nan_handler(payload):
            return float("nan")

        with self.assertRaises(ResultNotCanonicalError):
            self.proc.process("e1", {"n": 1}, nan_handler, seq=0)
        self.assertFalse(self.proc.seen("e1"))

    def test_new_event_requires_increasing_seq(self):
        self.proc.process("e1", {}, _handler, seq=3)
        with self.assertRaises(EventOrderError):
            self.proc.process("e2", {}, _handler, seq=3)
        with self.assertRaises(EventOrderError):
            self.proc.process("e2", {}, _handler, seq=0)
        self.assertFalse(self.proc.seen("e2"))

    def test_replay_does_not_move_high_water_mark(self):
        self.proc.process("e1", {}, _handler, seq=5)
        self.proc.process("e1", {}, _handler, seq=99)  # replay, any seq
        self.assertEqual(self.proc.last_seq, 5)
        # next new event still needs seq > 5
        with self.assertRaises(EventOrderError):
            self.proc.process("e2", {}, _handler, seq=5)
        ok = self.proc.process("e2", {}, _handler, seq=6)
        self.assertFalse(ok.hit)

    def test_last_seq_starts_at_minus_one(self):
        self.assertEqual(ExactlyOnce().last_seq, -1)


class TestViews(unittest.TestCase):
    def test_seen_and_lookup(self):
        proc = ExactlyOnce()
        self.assertFalse(proc.seen("e1"))
        self.assertIsNone(proc.lookup("e1"))
        proc.process("e1", {"a": 1}, _handler, seq=0)
        self.assertTrue(proc.seen("e1"))
        entry = proc.lookup("e1")
        self.assertIsInstance(entry, ProcessedEntry)
        self.assertEqual(entry.event_id, "e1")

    def test_processed_count_and_len(self):
        proc = ExactlyOnce()
        proc.process("e1", {}, _handler, seq=0)
        proc.process("e2", {}, _handler, seq=1)
        proc.process("e1", {}, _handler, seq=0)  # replay
        self.assertEqual(proc.processed_count(), 2)
        self.assertEqual(len(proc), 2)

    def test_head_digest_determinism(self):
        a, b = ExactlyOnce(), ExactlyOnce()
        for p in (a, b):
            p.process("e1", {"n": 1}, _handler, seq=0)
            p.process("e2", {"n": 2}, _handler, seq=1)
        self.assertEqual(a.head_digest(), b.head_digest())
        self.assertTrue(a.head_digest().startswith("sha256:"))

    def test_head_digest_changes_on_process(self):
        proc = ExactlyOnce()
        before = proc.head_digest()
        proc.process("e1", {}, _handler, seq=0)
        self.assertNotEqual(before, proc.head_digest())

    def test_entries_first_seen_order(self):
        proc = ExactlyOnce()
        proc.process("e2", {}, _handler, seq=0)
        proc.process("e1", {}, _handler, seq=1)
        self.assertEqual([e.event_id for e in proc.entries()], ["e2", "e1"])


class TestCheckpointRecover(unittest.TestCase):
    def test_checkpoint_shape(self):
        proc = ExactlyOnce()
        proc.process("e1", {"n": 1}, _handler, seq=0)
        proc.process("e2", {"n": 2}, _handler, seq=1)
        cp = proc.checkpoint(seq=7)
        self.assertIsInstance(cp, Checkpoint)
        self.assertEqual(cp.checkpoint_seq, 7)
        self.assertEqual(cp.processed_count, 2)
        self.assertTrue(cp.events_digest.startswith("sha256:"))
        self.assertEqual(len(cp.snapshot), 2)
        self.assertEqual(cp.schema, SCHEMA_PIN)

    def test_checkpoint_empty_processor(self):
        cp = ExactlyOnce().checkpoint(seq=0)
        self.assertEqual(cp.processed_count, 0)
        self.assertEqual(cp.snapshot, ())

    def test_checkpoint_bad_seq(self):
        with self.assertRaises(TypeError):
            ExactlyOnce().checkpoint(seq=True)
        with self.assertRaises(ValueError):
            ExactlyOnce().checkpoint(seq=-1)

    def test_recover_roundtrip(self):
        proc = ExactlyOnce()
        proc.process("e1", {"n": 1}, _handler, seq=0)
        proc.process("e2", {"n": 2}, _handler, seq=1)
        cp = proc.checkpoint(seq=3)
        revived = ExactlyOnce.recover(cp)
        self.assertEqual(revived.processed_count(), 2)
        self.assertTrue(revived.seen("e1"))
        self.assertEqual(revived.head_digest(), proc.head_digest())
        self.assertEqual(revived.last_seq, 1)

    def test_recover_continues_processing(self):
        proc = ExactlyOnce()
        proc.process("e1", {}, _handler, seq=0)
        revived = ExactlyOnce.recover(proc.checkpoint(seq=1))
        outcome = revived.process("e2", {}, _handler, seq=1)
        self.assertFalse(outcome.hit)
        with self.assertRaises(EventOrderError):
            revived.process("e3", {}, _handler, seq=0)

    def test_recover_replay_returns_none_result_with_pinned_digest(self):
        proc = ExactlyOnce()
        first = proc.process("e1", {"n": 1}, _handler, seq=0)
        revived = ExactlyOnce.recover(proc.checkpoint(seq=1))
        replay = revived.process("e1", {"n": 1}, _handler, seq=0)
        self.assertTrue(replay.hit)
        self.assertIsNone(replay.result)  # values are not pinned
        self.assertEqual(replay.result_digest, first.result_digest)

    def test_recover_tampered_snapshot_raises(self):
        proc = ExactlyOnce()
        proc.process("e1", {}, _handler, seq=0)
        cp = proc.checkpoint(seq=1)
        tampered = Checkpoint(
            checkpoint_seq=cp.checkpoint_seq,
            processed_count=cp.processed_count,
            events_digest="sha256:" + "00" * 32,
            snapshot=cp.snapshot,
        )
        with self.assertRaises(CheckpointIntegrityError):
            ExactlyOnce.recover(tampered)

    def test_recover_wrong_type(self):
        with self.assertRaises(TypeError):
            ExactlyOnce.recover("not-a-checkpoint")

    def test_recover_rejects_modified_entries(self):
        proc = ExactlyOnce()
        proc.process("e1", {"n": 1}, _handler, seq=0)
        proc.process("e2", {"n": 2}, _handler, seq=1)
        cp = proc.checkpoint(seq=2)
        forged_snapshot = cp.snapshot[:-1]  # drop an entry, keep old digest
        forged = Checkpoint(
            checkpoint_seq=2,
            processed_count=1,
            events_digest=cp.events_digest,
            snapshot=forged_snapshot,
        )
        with self.assertRaises(CheckpointIntegrityError):
            ExactlyOnce.recover(forged)


class TestAudit(unittest.TestCase):
    def test_processed_event_shape(self):
        proc = ExactlyOnce()
        outcome = proc.process("evt-alpha-1", {"n": 1}, _handler, seq=0)
        ev = exactly_once_audit_event(
            "processed", seq=3, event_id="evt-alpha-1", outcome=outcome
        )
        self.assertEqual(ev["event"], "exactly-once-processed")
        self.assertEqual(ev["audit_seq"], 3)
        self.assertEqual(ev["schema"], SCHEMA_PIN)
        self.assertFalse(ev["hit"])
        self.assertEqual(ev["first_seq"], 0)
        # raw event_id must never leak into the audit record
        self.assertNotIn("evt-alpha-1", str(ev))

    def test_replay_event_shape(self):
        proc = ExactlyOnce()
        proc.process("e1", {}, _handler, seq=0)
        replay = proc.process("e1", {}, _handler, seq=0)
        ev = exactly_once_audit_event("replay", seq=4, event_id="e1", outcome=replay)
        self.assertEqual(ev["event"], "exactly-once-replay")
        self.assertTrue(ev["hit"])

    def test_checkpointed_event_shape(self):
        proc = ExactlyOnce()
        proc.process("e1", {}, _handler, seq=0)
        cp = proc.checkpoint(seq=2)
        ev = exactly_once_audit_event("checkpointed", seq=5, checkpoint=cp)
        self.assertEqual(ev["event"], "exactly-once-checkpointed")
        self.assertEqual(ev["processed_count"], 1)
        self.assertEqual(ev["events_digest"], cp.events_digest)
        self.assertEqual(ev["checkpoint_seq"], 2)

    def test_recovered_event_shape(self):
        ev = exactly_once_audit_event("recovered", seq=6)
        self.assertEqual(ev["event"], "exactly-once-recovered")
        self.assertIsNone(ev["event_id_digest"])

    def test_bad_kind(self):
        with self.assertRaises(ValueError):
            exactly_once_audit_event("exploded", seq=0)

    def test_bad_seq(self):
        with self.assertRaises(TypeError):
            exactly_once_audit_event("processed", seq=True)

    def test_bad_outcome_type(self):
        with self.assertRaises(TypeError):
            exactly_once_audit_event("processed", seq=0, outcome="x")


class TestFrozen(unittest.TestCase):
    def test_outcome_frozen(self):
        proc = ExactlyOnce()
        outcome = proc.process("e1", {}, _handler, seq=0)
        with self.assertRaises(Exception):
            outcome.hit = True

    def test_checkpoint_frozen(self):
        cp = ExactlyOnce().checkpoint(seq=0)
        with self.assertRaises(Exception):
            cp.processed_count = 9

    def test_entry_frozen(self):
        entry = ProcessedEntry(
            event_id="e1",
            payload_digest="sha256:" + "ab" * 32,
            result_digest="sha256:" + "cd" * 32,
            first_seq=0,
        )
        with self.assertRaises(Exception):
            entry.first_seq = 5


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        import exactly_once

        exactly_once.main()  # must not raise


if __name__ == "__main__":
    unittest.main()
