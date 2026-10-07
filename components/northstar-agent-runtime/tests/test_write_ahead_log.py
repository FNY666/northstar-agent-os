"""Tests for write_ahead_log: append-only log, replay, verified checkpoints."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from write_ahead_log import (
    GENESIS_HEAD,
    SCHEMA_PIN,
    WRITE_AHEAD_LOG_VERSION,
    Checkpoint,
    CheckpointError,
    LogRecord,
    OutOfOrderAppend,
    ReplayError,
    WAL,
    WriteAheadLogError,
    apply,
    replay_records,
    state_digest,
    verify_record_chain,
    wal_audit_event,
)


def _put(seq, record_id=None, key="k", value=1, prev_head=GENESIS_HEAD):
    return LogRecord(record_id or f"r{seq}", "put", key, value, seq,
                     prev_head=prev_head)


class TestVersionPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(WRITE_AHEAD_LOG_VERSION, "write-ahead-log.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.write-ahead-log.v1")

    def test_genesis_head_shape(self):
        self.assertTrue(GENESIS_HEAD.startswith("sha256:"))
        self.assertEqual(len(GENESIS_HEAD), 71)


class TestLogRecord(unittest.TestCase):
    def test_put_record(self):
        r = _put(0)
        self.assertEqual(r.op, "put")
        self.assertEqual(r.key, "k")
        self.assertEqual(r.value, 1)
        self.assertTrue(r.digest.startswith("sha256:"))

    def test_delete_record(self):
        r = LogRecord("d0", "delete", "k", None, 0)
        self.assertEqual(r.op, "delete")
        self.assertIsNone(r.value)

    def test_bad_op(self):
        with self.assertRaises(ValueError):
            LogRecord("x", "update", "k", 1, 0)

    def test_empty_key(self):
        with self.assertRaises(ValueError):
            LogRecord("x", "put", "", 1, 0)

    def test_put_requires_value(self):
        with self.assertRaises(ValueError):
            LogRecord("x", "put", "k", None, 0)

    def test_delete_must_not_carry_value(self):
        with self.assertRaises(ValueError):
            LogRecord("x", "delete", "k", 1, 0)

    def test_non_canonicalizable_value(self):
        with self.assertRaises(TypeError):
            LogRecord("x", "put", "k", object(), 0)

    def test_bool_seq_rejected(self):
        with self.assertRaises(TypeError):
            _put(True)

    def test_negative_seq_rejected(self):
        with self.assertRaises(ValueError):
            _put(-1)

    def test_bad_prev_head(self):
        with self.assertRaises(ValueError):
            LogRecord("x", "put", "k", 1, 0, prev_head="nope")

    def test_digest_deterministic(self):
        self.assertEqual(_put(0).digest, _put(0).digest)

    def test_as_dict_schema(self):
        d = _put(0).as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["op"], "put")

    def test_frozen(self):
        r = _put(0)
        with self.assertRaises(Exception):
            r.seq = 99  # type: ignore


class TestApply(unittest.TestCase):
    def test_put(self):
        r = _put(0, key="a", value=1)
        self.assertEqual(apply({}, r), {"a": 1})

    def test_put_overwrites(self):
        r = _put(1, key="a", value=2)
        self.assertEqual(apply({"a": 1}, r), {"a": 2})

    def test_delete(self):
        r = LogRecord("d", "delete", "a", None, 1)
        self.assertEqual(apply({"a": 1, "b": 2}, r), {"b": 2})

    def test_delete_missing_key_is_noop(self):
        r = LogRecord("d", "delete", "zzz", None, 1)
        self.assertEqual(apply({"a": 1}, r), {"a": 1})

    def test_apply_does_not_mutate(self):
        state = {"a": 1}
        apply(state, _put(0, key="b", value=2))
        self.assertEqual(state, {"a": 1})

    def test_non_record_rejected(self):
        with self.assertRaises(TypeError):
            apply({}, "nope")


class TestStateDigest(unittest.TestCase):
    def test_deterministic(self):
        self.assertEqual(state_digest({"a": 1}), state_digest({"a": 1}))

    def test_key_order_independent(self):
        self.assertEqual(
            state_digest({"a": 1, "b": 2}), state_digest({"b": 2, "a": 1}))

    def test_shape(self):
        d = state_digest({})
        self.assertTrue(d.startswith("sha256:"))
        self.assertEqual(len(d), 71)

    def test_non_mapping_rejected(self):
        with self.assertRaises(TypeError):
            state_digest([1, 2])

    def test_non_str_keys_rejected(self):
        with self.assertRaises(TypeError):
            state_digest({1: "x"})


class TestReplayRecords(unittest.TestCase):
    def _chain(self):
        r0 = _put(0, key="a", value=1)
        r1 = _put(1, key="b", value=2, prev_head=r0.digest)
        r2 = LogRecord("r2", "delete", "a", None, 2, prev_head=r1.digest)
        return r0, r1, r2

    def test_replay_folds(self):
        r0, r1, r2 = self._chain()
        self.assertEqual(replay_records([r0, r1, r2]), {"b": 2})

    def test_replay_sorted_input(self):
        r0, r1, r2 = self._chain()
        self.assertEqual(replay_records([r2, r0, r1]), {"b": 2})

    def test_replay_duplicate_seq_fails(self):
        r0, r1, _ = self._chain()
        with self.assertRaises(ReplayError):
            replay_records([r0, r0, r1])

    def test_replay_with_initial(self):
        r0, _, _ = self._chain()
        self.assertEqual(replay_records([r0], initial={"z": 9}),
                         {"z": 9, "a": 1})

    def test_replay_non_record_fails(self):
        with self.assertRaises(TypeError):
            replay_records(["x"])

    def test_replay_empty(self):
        self.assertEqual(replay_records([]), {})


class TestWALAppend(unittest.TestCase):
    def _wal2(self):
        wal = WAL()
        r0 = _put(0)
        r1 = _put(1, key="b", value=2, prev_head=r0.digest)
        wal.append(r0)
        wal.append(r1)
        return wal, r0, r1

    def test_append_returns_digest(self):
        wal = WAL()
        r = _put(0)
        self.assertEqual(wal.append(r), r.digest)

    def test_len_and_head(self):
        wal, r0, r1 = self._wal2()
        self.assertEqual(len(wal), 2)
        self.assertEqual(wal.head(), r1.digest)

    def test_head_on_empty_is_genesis(self):
        self.assertEqual(WAL().head(), GENESIS_HEAD)
        self.assertEqual(WAL().base_head(), GENESIS_HEAD)

    def test_out_of_order_seq(self):
        wal, r0, _ = self._wal2()
        with self.assertRaises(OutOfOrderAppend):
            wal.append(_put(1, record_id="late", prev_head=r0.digest))

    def test_chain_break(self):
        wal, _, r1 = self._wal2()
        with self.assertRaises(OutOfOrderAppend):
            wal.append(_put(2, record_id="x", prev_head=GENESIS_HEAD))

    def test_duplicate_record_id(self):
        wal, _, r1 = self._wal2()
        with self.assertRaises(OutOfOrderAppend):
            wal.append(_put(2, record_id="r0", prev_head=r1.digest))

    def test_non_record_rejected(self):
        with self.assertRaises(TypeError):
            WAL().append("nope")

    def test_nothing_appended_on_failure(self):
        wal, _, _ = self._wal2()
        with self.assertRaises(OutOfOrderAppend):
            wal.append(_put(0, record_id="dup0"))
        self.assertEqual(len(wal), 2)

    def test_records_since(self):
        wal, r0, r1 = self._wal2()
        self.assertEqual([r.record_id for r in wal.records_since(0)],
                         ["r1"])

    def test_verify_chain_true(self):
        wal, _, _ = self._wal2()
        self.assertTrue(wal.verify_chain())

    def test_verify_chain_false_on_tampered_head(self):
        # Construction allows any prev_head (it is the caller's chain
        # context); verification -- e.g. on a persisted log handed back
        # after a restart -- catches the mismatch.
        r = LogRecord("r0", "put", "k", 1, 0,
                      prev_head="sha256:" + "f" * 64)
        self.assertFalse(verify_record_chain([r], GENESIS_HEAD))
        self.assertTrue(verify_record_chain([r], "sha256:" + "f" * 64))

    def test_replay(self):
        wal, _, _ = self._wal2()
        self.assertEqual(wal.replay(), {"k": 1, "b": 2})


class TestCheckpoint(unittest.TestCase):
    def _wal3(self):
        wal = WAL()
        r0 = _put(0, key="a", value=1)
        r1 = _put(1, key="b", value=2, prev_head=r0.digest)
        r2 = _put(2, key="c", value=3, prev_head=r1.digest)
        wal.append(r0)
        wal.append(r1)
        wal.append(r2)
        return wal, r0, r1, r2

    def test_checkpoint_verified(self):
        wal, _, _, _ = self._wal3()
        digest = state_digest({"a": 1, "b": 2})
        point = wal.checkpoint(1, digest, 10)
        self.assertIsInstance(point, Checkpoint)
        self.assertEqual(point.upto_seq, 1)
        self.assertEqual(point.state_digest, digest)
        self.assertEqual(point.prev_head, wal.head())
        self.assertEqual(len(wal.checkpoints()), 1)

    def test_checkpoint_wrong_digest_refused(self):
        wal, _, _, _ = self._wal3()
        with self.assertRaises(CheckpointError):
            wal.checkpoint(1, GENESIS_HEAD, 10)
        self.assertEqual(len(wal.checkpoints()), 0)

    def test_checkpoint_beyond_last(self):
        wal, _, _, _ = self._wal3()
        digest = state_digest(wal.replay())
        with self.assertRaises(CheckpointError):
            wal.checkpoint(99, digest, 10)

    def test_checkpoint_empty_wal(self):
        wal = WAL()
        with self.assertRaises(CheckpointError):
            wal.checkpoint(0, state_digest({}), 0)

    def test_checkpoint_as_dict(self):
        wal, _, _, _ = self._wal3()
        digest = state_digest({"a": 1, "b": 2})
        point = wal.checkpoint(1, digest, 10)
        d = point.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["upto_seq"], 1)


class TestCompact(unittest.TestCase):
    def _wal_with_checkpoint(self):
        wal = WAL()
        r0 = _put(0, key="a", value=1)
        r1 = _put(1, key="b", value=2, prev_head=r0.digest)
        r2 = LogRecord("r2", "delete", "a", None, 2, prev_head=r1.digest)
        wal.append(r0)
        wal.append(r1)
        wal.append(r2)
        digest = state_digest({"a": 1, "b": 2})
        point = wal.checkpoint(1, digest, 10)
        return wal, point, r0, r1, r2

    def test_compact_drops_prefix(self):
        wal, point, r0, r1, r2 = self._wal_with_checkpoint()
        compacted = wal.compact(point)
        self.assertEqual(len(compacted), 1)
        self.assertEqual([r.record_id for r in compacted.records()], ["r2"])

    def test_compact_pins_truncation_point(self):
        wal, point, r0, r1, r2 = self._wal_with_checkpoint()
        compacted = wal.compact(point)
        self.assertEqual(compacted.base_head(), r1.digest)

    def test_compact_chain_still_verifies(self):
        wal, point, _, _, _ = self._wal_with_checkpoint()
        compacted = wal.compact(point)
        self.assertTrue(compacted.verify_chain())

    def test_compact_original_untouched(self):
        wal, point, _, _, _ = self._wal_with_checkpoint()
        wal.compact(point)
        self.assertEqual(len(wal), 3)
        self.assertEqual(wal.base_head(), GENESIS_HEAD)

    def test_compact_recovery_from_checkpoint_state(self):
        wal, point, _, _, _ = self._wal_with_checkpoint()
        compacted = wal.compact(point)
        recovered = replay_records(
            compacted.records(), initial={"a": 1, "b": 2})
        self.assertEqual(recovered, {"b": 2})

    def test_compact_foreign_checkpoint_refused(self):
        wal, point, _, _, _ = self._wal_with_checkpoint()
        other = Checkpoint(1, point.state_digest, wal.head(), 99)
        with self.assertRaises(CheckpointError):
            wal.compact(other)

    def test_compact_non_checkpoint_rejected(self):
        wal, point, _, _, _ = self._wal_with_checkpoint()
        with self.assertRaises(TypeError):
            wal.compact("nope")


class TestAuditEvent(unittest.TestCase):
    def test_appended_shape(self):
        r = _put(0)
        event = wal_audit_event("appended", 5, record=r)
        self.assertEqual(event["schema"], "audit.ndjson/1")
        self.assertEqual(event["module"], SCHEMA_PIN)
        self.assertEqual(event["record_id"], "r0")
        self.assertEqual(event["audit_seq"], 5)

    def test_checkpointed_shape(self):
        wal = WAL()
        r = _put(0)
        wal.append(r)
        point = wal.checkpoint(0, state_digest({"k": 1}), 1)
        event = wal_audit_event("checkpointed", 2, checkpoint=point)
        self.assertEqual(event["kind"], "checkpointed")
        self.assertEqual(event["checkpoint_upto_seq"], 0)

    def test_rejected_shape(self):
        event = wal_audit_event("rejected", 0)
        self.assertEqual(event["kind"], "rejected")

    def test_bad_kind(self):
        with self.assertRaises(ValueError):
            wal_audit_event("exploded", 0)

    def test_bad_seq(self):
        with self.assertRaises(TypeError):
            wal_audit_event("appended", True)

    def test_bad_record_type(self):
        with self.assertRaises(TypeError):
            wal_audit_event("appended", 0, record="nope")


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        import write_ahead_log
        write_ahead_log.main()  # raises on any self-check failure


if __name__ == "__main__":
    unittest.main()
