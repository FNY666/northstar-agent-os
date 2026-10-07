"""Tests for savepoint_manager (Flink savepoint lifecycle)."""

import sys
import unittest

sys.path.insert(0, "..")

from savepoint_manager import (
    AUDIT_KINDS,
    AUDIT_SCHEMA,
    MAX_STATE_BYTES,
    SAVEPOINT_MANAGER_SCHEMA,
    SAVEPOINT_MANAGER_VERSION,
    DisposedSavepointError,
    DisposalRecord,
    IncompatibleSavepointError,
    RestoredSnapshot,
    SavepointHandle,
    SavepointHealth,
    SavepointManager,
    SavepointManagerError,
    UnknownSavepointError,
    savepoint_manager_audit_event,
)


def _states(**kwargs):
    return {uid: payload.encode() if isinstance(payload, str) else payload
            for uid, payload in kwargs.items()}


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(SAVEPOINT_MANAGER_VERSION, "savepoint-manager.v1")

    def test_schema_pin(self):
        self.assertEqual(SAVEPOINT_MANAGER_SCHEMA, "northstar.savepoint-manager.v1")

    def test_audit_schema_pin(self):
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")


class TestTrigger(unittest.TestCase):
    def setUp(self):
        self.mgr = SavepointManager()

    def test_trigger_happy_path(self):
        handle = self.mgr.trigger({"op-a": b"state-a", "op-b": b"state-b"}, seq=1)
        self.assertIsInstance(handle, SavepointHandle)
        self.assertEqual(handle.savepoint_id, "savepoint-1")
        self.assertEqual(handle.created_seq, 1)
        self.assertTrue(handle.digest.startswith("sha256:"))
        self.assertEqual(handle.operator_uids, ("op-a", "op-b"))
        self.assertEqual(handle.version, SAVEPOINT_MANAGER_VERSION)
        self.assertEqual(handle.schema, SAVEPOINT_MANAGER_SCHEMA)

    def test_trigger_sequential_ids(self):
        h1 = self.mgr.trigger({"op-a": b"a"}, seq=1)
        h2 = self.mgr.trigger({"op-a": b"b"}, seq=2)
        self.assertEqual(h1.savepoint_id, "savepoint-1")
        self.assertEqual(h2.savepoint_id, "savepoint-2")

    def test_trigger_digest_deterministic(self):
        m1, m2 = SavepointManager(), SavepointManager()
        h1 = m1.trigger({"op-a": b"same"}, seq=7)
        h2 = m2.trigger({"op-a": b"same"}, seq=7)
        self.assertEqual(h1.digest, h2.digest)  # same id, seq, states

    def test_trigger_order_independent(self):
        h1 = self.mgr.trigger({"op-a": b"a", "op-b": b"b"}, seq=1)
        m2 = SavepointManager()
        h2 = m2.trigger({"op-b": b"b", "op-a": b"a"}, seq=1)
        self.assertEqual(h1.digest, h2.digest)

    def test_trigger_rejects_seq_rewind(self):
        self.mgr.trigger({"op-a": b"a"}, seq=5)
        with self.assertRaises(ValueError):
            self.mgr.trigger({"op-a": b"a"}, seq=4)

    def test_trigger_same_seq_ok(self):
        self.mgr.trigger({"op-a": b"a"}, seq=5)
        h = self.mgr.trigger({"op-a": b"a"}, seq=5)
        self.assertEqual(h.savepoint_id, "savepoint-2")

    def test_trigger_validation(self):
        bad_inputs = [
            None, [], "op-a", b"\x00", {"op-a": "not-bytes"},
            {"": b"x"}, {"op-a": b""}, {1: b"x"}, {True: b"x"},
            {}, {"op-a": b"x" * (MAX_STATE_BYTES + 1)},
        ]
        for bad in bad_inputs:
            with self.assertRaises((TypeError, ValueError), msg=repr(bad)[:40]):
                self.mgr.trigger(bad, seq=1)

    def test_trigger_bad_seq(self):
        for bad in (True, -1, "1", 1.0, None):
            with self.assertRaises((TypeError, ValueError)):
                self.mgr.trigger({"op-a": b"a"}, seq=bad)

    def test_handle_as_dict(self):
        handle = self.mgr.trigger({"op-a": b"a"}, seq=3)
        d = handle.as_dict()
        self.assertEqual(d["savepoint_id"], "savepoint-1")
        self.assertEqual(d["created_seq"], 3)
        self.assertEqual(d["operator_uids"], ["op-a"])
        self.assertEqual(d["schema"], SAVEPOINT_MANAGER_SCHEMA)

    def test_handle_validation(self):
        with self.assertRaises((TypeError, ValueError)):
            SavepointHandle(savepoint_id="", created_seq=1, digest="sha256:x",
                            operator_uids=("a",))
        with self.assertRaises(TypeError):
            SavepointHandle(savepoint_id="x", created_seq=1, digest="nope",
                            operator_uids=("a",))
        with self.assertRaises(ValueError):
            SavepointHandle(savepoint_id="x", created_seq=1, digest="sha256:x",
                            operator_uids=("a",), version="wrong.v9")


class TestRestore(unittest.TestCase):
    def setUp(self):
        self.mgr = SavepointManager()
        self.handle = self.mgr.trigger({"op-a": b"state-a", "op-b": b"state-b"}, seq=1)

    def test_restore_happy_path(self):
        snap = self.mgr.restore(self.handle.savepoint_id, seq=2,
                                job_operator_uids=("op-a", "op-b"))
        self.assertIsInstance(snap, RestoredSnapshot)
        self.assertEqual(snap.savepoint_id, "savepoint-1")
        self.assertEqual(snap.state_for("op-a"), b"state-a")
        self.assertEqual(snap.state_for("op-b"), b"state-b")
        self.assertEqual(snap.digest, self.handle.digest)

    def test_restore_accepts_handle(self):
        snap = self.mgr.restore(self.handle, seq=2, job_operator_uids=("op-a", "op-b"))
        self.assertEqual(snap.savepoint_id, "savepoint-1")

    def test_restore_returns_copies(self):
        snap = self.mgr.restore(self.handle.savepoint_id, seq=2,
                                job_operator_uids=("op-a", "op-b"))
        payload = snap.state_for("op-a")
        payload_arr = bytearray(payload)
        payload_arr[0] = 0xFF  # mutating the returned copy must not corrupt the registry
        snap2 = self.mgr.restore(self.handle.savepoint_id, seq=3,
                                 job_operator_uids=("op-a", "op-b"))
        self.assertEqual(snap2.state_for("op-a"), b"state-a")

    def test_restore_unknown_id(self):
        with self.assertRaises(UnknownSavepointError):
            self.mgr.restore("savepoint-99", seq=2, job_operator_uids=("op-a",))

    def test_restore_empty_job_uids_allowed(self):
        # empty job set with a non-empty savepoint -> all unmapped -> refused
        with self.assertRaises(IncompatibleSavepointError):
            self.mgr.restore(self.handle.savepoint_id, seq=2, job_operator_uids=())

    def test_restore_unmapped_refused_by_default(self):
        with self.assertRaises(IncompatibleSavepointError):
            self.mgr.restore(self.handle.savepoint_id, seq=2,
                             job_operator_uids=("op-a",))  # op-b missing

    def test_restore_allow_unmapped(self):
        snap = self.mgr.restore(self.handle.savepoint_id, seq=2,
                                job_operator_uids=("op-a",),
                                allow_unmapped_operators=True)
        # snapshot still carries the full pinned state; the host drops op-b
        self.assertEqual(snap.state_for("op-b"), b"state-b")

    def test_restore_extra_job_operators_ok(self):
        snap = self.mgr.restore(self.handle.savepoint_id, seq=2,
                                job_operator_uids=("op-a", "op-b", "op-new"))
        self.assertIsNone(snap.state_for("op-new"))

    def test_restore_corrupted_record_refused(self):
        # test-side corruption: break the pinned digest
        record = self.mgr._records[self.handle.savepoint_id]
        record.digest = "sha256:" + "00" * 32
        with self.assertRaises(IncompatibleSavepointError):
            self.mgr.restore(self.handle.savepoint_id, seq=2,
                             job_operator_uids=("op-a", "op-b"))

    def test_restore_state_for_unknown(self):
        snap = self.mgr.restore(self.handle.savepoint_id, seq=2,
                                job_operator_uids=("op-a", "op-b"))
        self.assertIsNone(snap.state_for("op-nope"))

    def test_restore_bad_allow_unmapped_type(self):
        with self.assertRaises(TypeError):
            self.mgr.restore(self.handle.savepoint_id, seq=2,
                             job_operator_uids=("op-a", "op-b"),
                             allow_unmapped_operators="yes")

    def test_snapshot_as_dict_pins_states(self):
        snap = self.mgr.restore(self.handle.savepoint_id, seq=2,
                                job_operator_uids=("op-a", "op-b"))
        d = snap.as_dict()
        self.assertEqual(d["savepoint_id"], "savepoint-1")
        self.assertTrue(all("state_pin" in op for op in d["operators"]))
        # pins, never raw bytes
        self.assertNotIn(b"state-a", str(d).encode())


class TestDispose(unittest.TestCase):
    def setUp(self):
        self.mgr = SavepointManager()
        self.handle = self.mgr.trigger({"op-a": b"state-a", "op-b": b"state-b"}, seq=1)

    def test_dispose_happy_path(self):
        receipt = self.mgr.dispose(self.handle.savepoint_id, seq=2)
        self.assertIsInstance(receipt, DisposalRecord)
        self.assertEqual(receipt.savepoint_id, "savepoint-1")
        self.assertEqual(receipt.dispose_seq, 2)
        self.assertEqual(receipt.operator_count, 2)
        self.assertEqual(receipt.digest, self.handle.digest)

    def test_restore_after_dispose_refused(self):
        self.mgr.dispose(self.handle.savepoint_id, seq=2)
        with self.assertRaises(DisposedSavepointError):
            self.mgr.restore(self.handle.savepoint_id, seq=3,
                             job_operator_uids=("op-a", "op-b"))

    def test_double_dispose_refused(self):
        self.mgr.dispose(self.handle.savepoint_id, seq=2)
        with self.assertRaises(DisposedSavepointError):
            self.mgr.dispose(self.handle.savepoint_id, seq=3)

    def test_dispose_unknown_refused(self):
        with self.assertRaises(UnknownSavepointError):
            self.mgr.dispose("savepoint-99", seq=2)

    def test_dispose_accepts_handle(self):
        receipt = self.mgr.dispose(self.handle, seq=2)
        self.assertEqual(receipt.savepoint_id, "savepoint-1")

    def test_disposal_record_as_dict(self):
        receipt = self.mgr.dispose(self.handle.savepoint_id, seq=2)
        d = receipt.as_dict()
        self.assertEqual(d["operator_count"], 2)
        self.assertEqual(d["schema"], SAVEPOINT_MANAGER_SCHEMA)


class TestVerifyAndList(unittest.TestCase):
    def setUp(self):
        self.mgr = SavepointManager()
        self.h1 = self.mgr.trigger({"op-a": b"a"}, seq=1)
        self.h2 = self.mgr.trigger({"op-b": b"b"}, seq=2)

    def test_verify_healthy(self):
        health = self.mgr.verify(self.h1.savepoint_id)
        self.assertIsInstance(health, SavepointHealth)
        self.assertTrue(health.restorable)
        self.assertEqual(health.reason, "healthy")

    def test_verify_disposed(self):
        self.mgr.dispose(self.h1.savepoint_id, seq=3)
        health = self.mgr.verify(self.h1.savepoint_id)
        self.assertFalse(health.restorable)
        self.assertEqual(health.reason, "disposed")

    def test_verify_corrupted(self):
        self.mgr._records[self.h1.savepoint_id].digest = "sha256:" + "ff" * 32
        health = self.mgr.verify(self.h1.savepoint_id)
        self.assertFalse(health.restorable)
        self.assertEqual(health.reason, "digest-mismatch")

    def test_verify_unknown_raises(self):
        with self.assertRaises(UnknownSavepointError):
            self.mgr.verify("savepoint-99")

    def test_list_live_in_order(self):
        self.assertEqual(
            [h.savepoint_id for h in self.mgr.list()],
            ["savepoint-1", "savepoint-2"],
        )

    def test_list_excludes_disposed(self):
        self.mgr.dispose(self.h1.savepoint_id, seq=3)
        self.assertEqual([h.savepoint_id for h in self.mgr.list()], ["savepoint-2"])

    def test_info_pins_not_bytes(self):
        mgr = SavepointManager()
        handle = mgr.trigger({"op-a": b"raw-payload-never-in-info"}, seq=1)
        info = mgr.info("savepoint-1")
        self.assertEqual(info["savepoint_id"], "savepoint-1")
        self.assertEqual(info["created_seq"], 1)
        self.assertEqual(info["operator_uids"], ["op-a"])
        self.assertEqual(info["digest"], handle.digest)
        self.assertNotIn(b"raw-payload-never-in-info", str(info).encode())
        self.assertTrue(info["state_pins"][0]["state_pin"].startswith("sha256:"))

    def test_info_disposed_refused(self):
        self.mgr.dispose(self.h1.savepoint_id, seq=3)
        with self.assertRaises(DisposedSavepointError):
            self.mgr.info(self.h1.savepoint_id)

    def test_health_as_dict(self):
        health = self.mgr.verify(self.h1.savepoint_id)
        d = health.as_dict()
        self.assertEqual(d, {
            "savepoint_id": "savepoint-1",
            "restorable": True,
            "reason": "healthy",
            "version": SAVEPOINT_MANAGER_VERSION,
            "schema": SAVEPOINT_MANAGER_SCHEMA,
        })


class TestAuditEvents(unittest.TestCase):
    def test_audit_vocab(self):
        self.assertEqual(tuple(AUDIT_KINDS), ("triggered", "restored", "disposed", "rejected"))

    def test_audit_event_shapes(self):
        for kind in AUDIT_KINDS:
            ev = savepoint_manager_audit_event(kind, seq=9, savepoint_id="savepoint-1")
            self.assertEqual(ev["event"], "savepoint-manager")
            self.assertEqual(ev["kind"], kind)
            self.assertEqual(ev["audit_seq"], 9)
            self.assertEqual(ev["savepoint_id"], "savepoint-1")
            self.assertEqual(ev["schema"], "audit.ndjson/1")

    def test_audit_event_without_id(self):
        ev = savepoint_manager_audit_event("rejected", seq=0)
        self.assertNotIn("savepoint_id", ev)

    def test_audit_event_rejections(self):
        with self.assertRaises(ValueError):
            savepoint_manager_audit_event("exploded", seq=1)
        for bad in (True, -1, "1"):
            with self.assertRaises((TypeError, ValueError)):
                savepoint_manager_audit_event("triggered", seq=bad)
        with self.assertRaises((TypeError, ValueError)):
            savepoint_manager_audit_event("triggered", seq=1, savepoint_id="")
        with self.assertRaises(TypeError):
            savepoint_manager_audit_event("triggered", seq=1, savepoint_id=42)


class TestMain(unittest.TestCase):
    def test_main(self):
        import io
        from contextlib import redirect_stdout

        import savepoint_manager

        buf = io.StringIO()
        with redirect_stdout(buf):
            savepoint_manager.main()
        self.assertIn("savepoint-manager OK", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
