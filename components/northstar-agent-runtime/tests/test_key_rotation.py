"""Targeted tests for the key rotation interface."""

import ast
import unittest
from pathlib import Path

from key_rotation import (
    AUDIT_SCHEMA,
    KEY_ROTATION_SCHEMA,
    KEY_ROTATION_VERSION,
    KIND_KEY_REGISTERED,
    KIND_REJECTED,
    KIND_ROTATED,
    KIND_SCHEDULED,
    REASON_COMPROMISED,
    REASON_EXPIRED,
    REASON_INITIAL,
    REASON_MANUAL,
    REASON_SCHEDULED,
    ROTATION_REASONS,
    STATUS_ACTIVE,
    STATUS_RETIRED,
    BadKeyError,
    BadRotationError,
    BadScheduleError,
    DuplicateKeyError,
    DuplicateScheduleError,
    KeyRotation,
    KeyRotationError,
    KeyVersion,
    ScheduleRecord,
    SeqOrderError,
    UnknownKeyError,
    UnknownScheduleError,
    key_rotation_audit_event,
    main,
)

MODULE_PATH = Path(__file__).resolve().parent.parent / "key_rotation.py"


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(KEY_ROTATION_VERSION, "key-rotation.v1")
        self.assertEqual(KEY_ROTATION_SCHEMA, "northstar.key-rotation.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")
        self.assertEqual(
            ROTATION_REASONS,
            ("initial", "scheduled", "manual", "compromised", "expired"),
        )

    def test_stdlib_only(self):
        tree = ast.parse(MODULE_PATH.read_text())
        allowed = {
            "__future__", "hashlib", "json", "threading", "dataclasses", "typing",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestRegister(unittest.TestCase):
    def setUp(self):
        self.mgr = KeyRotation(seed=1)

    def test_register_roundtrip(self):
        v = self.mgr.register("api-key", seq=1)
        self.assertIsInstance(v, KeyVersion)
        self.assertEqual(v.key_id, "api-key")
        self.assertEqual(v.version_index, 1)
        self.assertEqual(v.status, STATUS_ACTIVE)
        self.assertEqual(v.reason, REASON_INITIAL)
        self.assertEqual(v.prev_digest, "genesis")
        self.assertTrue(v.material_digest.startswith("sha256:"))
        self.assertTrue(v.verify())
        self.assertEqual(self.mgr.key_ids(), ("api-key",))

    def test_register_duplicate_refused(self):
        self.mgr.register("api-key", seq=1)
        with self.assertRaises(DuplicateKeyError):
            self.mgr.register("api-key", seq=2)

    def test_register_bad_key_ids(self):
        for bad in ("", "   ", None, 123, b"bytes"):
            with self.assertRaises(BadKeyError, msg=f"key_id={bad!r}"):
                self.mgr.register(bad, seq=1)
            # fresh manager per attempt: seq accounting would otherwise trip
            self.mgr = KeyRotation(seed=1)


class TestSeqDiscipline(unittest.TestCase):
    def test_rewind_bool_negative_refused(self):
        mgr = KeyRotation(seed=1)
        mgr.register("k", seq=1)
        for bad in (1, 0, -1, True, False, "2", 2.0):
            with self.assertRaises(SeqOrderError, msg=f"seq={bad!r}"):
                mgr.register("k2", seq=bad)

    def test_failed_mutation_consumes_seq(self):
        mgr = KeyRotation(seed=1)
        mgr.register("k", seq=1)
        with self.assertRaises(DuplicateKeyError):
            mgr.register("k", seq=2)  # refused, but seq 2 is burned
        with self.assertRaises(SeqOrderError):
            mgr.register("k2", seq=2)
        v = mgr.register("k2", seq=3)  # fresh seq works
        self.assertTrue(v.verify())


class TestSchedule(unittest.TestCase):
    def setUp(self):
        self.mgr = KeyRotation(seed=2)
        self.mgr.register("api-key", seq=1)

    def test_schedule_roundtrip(self):
        sch = self.mgr.schedule("api-key", interval_seq=10, seq=2)
        self.assertIsInstance(sch, ScheduleRecord)
        self.assertTrue(sch.schedule_id.startswith("sch-"))
        self.assertEqual(sch.key_id, "api-key")
        self.assertEqual(sch.start_seq, 2)
        self.assertEqual(sch.next_due_seq, 12)
        self.assertTrue(sch.enabled)
        self.assertTrue(sch.verify())

    def test_schedule_explicit_start_seq(self):
        sch = self.mgr.schedule("api-key", interval_seq=10, seq=2, start_seq=5)
        self.assertEqual(sch.start_seq, 5)
        self.assertEqual(sch.next_due_seq, 15)
        self.assertTrue(sch.verify())

    def test_schedule_unknown_key_refused(self):
        with self.assertRaises(UnknownKeyError):
            self.mgr.schedule("nope", interval_seq=10, seq=2)

    def test_schedule_duplicate_refused(self):
        self.mgr.schedule("api-key", interval_seq=10, seq=2)
        with self.assertRaises(DuplicateScheduleError):
            self.mgr.schedule("api-key", interval_seq=20, seq=3)

    def test_schedule_bad_intervals(self):
        for bad in (0, -5, True, False, "10", 1.5, None):
            with self.assertRaises(BadScheduleError, msg=f"interval={bad!r}"):
                self.mgr.schedule("api-key", interval_seq=bad, seq=2)
            self.mgr = KeyRotation(seed=2)
            self.mgr.register("api-key", seq=1)


class TestRotate(unittest.TestCase):
    def setUp(self):
        self.mgr = KeyRotation(seed=3)
        self.mgr.register("api-key", seq=1)

    def test_rotate_mints_version_2(self):
        v1 = self.mgr.active_version("api-key")
        v2 = self.mgr.rotate("api-key", seq=2)
        self.assertEqual(v2.version_index, 2)
        self.assertEqual(v2.status, STATUS_ACTIVE)
        self.assertEqual(v2.reason, REASON_MANUAL)
        self.assertEqual(v2.prev_digest, self.mgr.versions("api-key")[0].digest)
        self.assertTrue(v2.verify())
        self.assertNotEqual(v2.material_digest, v1.material_digest)
        retired = self.mgr.versions("api-key")[0]
        self.assertEqual(retired.status, STATUS_RETIRED)
        self.assertTrue(retired.verify())

    def test_rotate_reasons(self):
        for reason in (REASON_SCHEDULED, REASON_COMPROMISED, REASON_EXPIRED):
            mgr = KeyRotation(seed=3)
            mgr.register("k", seq=1)
            v = mgr.rotate("k", seq=2, reason=reason)
            self.assertEqual(v.reason, reason)

    def test_rotate_bad_reasons(self):
        for bad in ("initial", "rotated", "", None, 42):
            with self.assertRaises(BadRotationError, msg=f"reason={bad!r}"):
                self.mgr.rotate("api-key", seq=2, reason=bad)
            self.mgr = KeyRotation(seed=3)
            self.mgr.register("api-key", seq=1)

    def test_rotate_unknown_key_refused(self):
        with self.assertRaises(UnknownKeyError):
            self.mgr.rotate("nope", seq=2)

    def test_rotate_advances_schedule(self):
        sch = self.mgr.schedule("api-key", interval_seq=10, seq=2)
        self.assertEqual(sch.next_due_seq, 12)
        self.mgr.rotate("api-key", seq=5, reason="manual")
        advanced = self.mgr.schedule_record(sch.schedule_id)
        self.assertEqual(advanced.next_due_seq, 15)
        self.assertTrue(advanced.verify())


class TestViews(unittest.TestCase):
    def setUp(self):
        self.mgr = KeyRotation(seed=4)
        self.mgr.register("a", seq=1)
        self.mgr.register("b", seq=2)

    def test_versions_history_oldest_first(self):
        self.mgr.rotate("a", seq=3)
        self.mgr.rotate("a", seq=4)
        vs = self.mgr.versions("a")
        self.assertEqual([v.version_index for v in vs], [1, 2, 3])
        self.assertEqual([v.status for v in vs], ["retired", "retired", "active"])
        self.assertTrue(all(v.verify() for v in vs))

    def test_versions_unknown_key_refused(self):
        with self.assertRaises(UnknownKeyError):
            self.mgr.versions("nope")

    def test_due_view(self):
        self.mgr.schedule("a", interval_seq=10, seq=3)   # due at 13
        self.mgr.schedule("b", interval_seq=100, seq=4)  # due at 104
        self.assertEqual(self.mgr.due(12), ())
        due13 = self.mgr.due(13)
        self.assertEqual(len(due13), 1)
        self.assertEqual(due13[0].key_id, "a")
        due104 = self.mgr.due(104)
        self.assertEqual(len(due104), 2)
        # due is a pure view: seq validated but not consumed
        self.mgr.register("c", seq=5)

    def test_due_bad_seq_refused(self):
        with self.assertRaises(KeyRotationError):
            self.mgr.due(-1)

    def test_schedule_record_unknown_refused(self):
        with self.assertRaises(UnknownScheduleError):
            self.mgr.schedule_record("sch-99")

    def test_material_never_in_records_or_audit(self):
        self.mgr.rotate("a", seq=3)
        blob = repr(self.mgr.versions("a")) + repr(self.mgr.audit_log())
        raw = self.mgr.material_for("a", 1).hex()
        self.assertNotIn(raw, blob)
        self.assertNotIn(self.mgr.material_for("a", 1).decode("latin1", "ignore"), blob)


class TestDeterminism(unittest.TestCase):
    def test_same_seed_same_material(self):
        a = KeyRotation(seed=9)
        b = KeyRotation(seed=9)
        a.register("k", seq=1)
        b.register("k", seq=1)
        self.assertEqual(
            a.versions("k")[0].material_digest, b.versions("k")[0].material_digest
        )
        self.assertEqual(a.material_for("k", 1), b.material_for("k", 1))

    def test_different_seed_diverges(self):
        a = KeyRotation(seed=9)
        b = KeyRotation(seed=10)
        a.register("k", seq=1)
        b.register("k", seq=1)
        self.assertNotEqual(
            a.versions("k")[0].material_digest, b.versions("k")[0].material_digest
        )


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        mgr = KeyRotation(seed=5)
        mgr.register("k", seq=1)
        mgr.schedule("k", interval_seq=5, seq=2)
        mgr.rotate("k", seq=3, reason="scheduled")
        log = mgr.audit_log()
        self.assertEqual(
            [e["kind"] for e in log],
            [KIND_KEY_REGISTERED, KIND_SCHEDULED, KIND_ROTATED],
        )
        for e in log:
            self.assertEqual(e["schema"], AUDIT_SCHEMA)
            self.assertEqual(e["module"], "key_rotation")

    def test_audit_bad_kind_refused(self):
        with self.assertRaises(KeyRotationError):
            key_rotation_audit_event("bogus", seq=1)

    def test_main(self):
        main()  # must not raise


if __name__ == "__main__":
    unittest.main()
