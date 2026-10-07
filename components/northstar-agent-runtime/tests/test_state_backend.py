"""Tests for state_backend.py (RocksDB-style keyed state)."""

import unittest

from state_backend import (
    STATE_BACKEND_SCHEMA,
    STATE_BACKEND_VERSION,
    Snapshot,
    SnapshotVerificationError,
    StateBackend,
    StateBackendError,
    state_backend_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(STATE_BACKEND_VERSION, "state-backend.v1")

    def test_schema_pin(self):
        self.assertEqual(STATE_BACKEND_SCHEMA, "northstar.state-backend.v1")


class TestPutGet(unittest.TestCase):
    def test_roundtrip(self):
        be = StateBackend("t")
        be.put("k", {"a": [1, 2, 3]})
        self.assertEqual(be.get("k"), {"a": [1, 2, 3]})

    def test_missing_returns_none(self):
        be = StateBackend("t")
        self.assertIsNone(be.get("nope"))

    def test_overwrite(self):
        be = StateBackend("t")
        be.put("k", 1)
        be.put("k", 2)
        self.assertEqual(be.get("k"), 2)

    def test_namespace_isolation(self):
        be = StateBackend("t")
        be.put("k", "ns1-val", namespace="a")
        be.put("k", "ns2-val", namespace="b")
        self.assertEqual(be.get("k", namespace="a"), "ns1-val")
        self.assertEqual(be.get("k", namespace="b"), "ns2-val")

    def test_no_aliasing_on_put(self):
        be = StateBackend("t")
        v = {"x": 1}
        be.put("k", v)
        v["x"] = 999
        self.assertEqual(be.get("k"), {"x": 1})

    def test_no_aliasing_on_get(self):
        be = StateBackend("t")
        be.put("k", {"x": 1})
        v = be.get("k")
        v["x"] = 999
        self.assertEqual(be.get("k"), {"x": 1})

    def test_key_ordering_independent(self):
        be = StateBackend("t")
        be.put("k", {"b": 2, "a": 1})
        self.assertEqual(be.state_digest(), be.state_digest())
        be2 = StateBackend("t")
        be2.put("k", {"a": 1, "b": 2})
        self.assertEqual(be.state_digest(), be2.state_digest())


class TestValidation(unittest.TestCase):
    def test_empty_key_rejected(self):
        be = StateBackend("t")
        with self.assertRaises(ValueError):
            be.put("", 1)

    def test_non_str_key_rejected(self):
        be = StateBackend("t")
        with self.assertRaises(TypeError):
            be.put(1, "v")

    def test_bool_key_rejected(self):
        be = StateBackend("t")
        with self.assertRaises(TypeError):
            be.put(True, "v")

    def test_none_value_rejected(self):
        be = StateBackend("t")
        with self.assertRaises(TypeError):
            be.put("k", None)

    def test_nan_value_rejected(self):
        be = StateBackend("t")
        with self.assertRaises(TypeError):
            be.put("k", float("nan"))

    def test_bytes_value_rejected(self):
        be = StateBackend("t")
        with self.assertRaises(TypeError):
            be.put("k", b"raw")

    def test_bad_name_rejected(self):
        with self.assertRaises(ValueError):
            StateBackend("")
        with self.assertRaises(TypeError):
            StateBackend(123)


class TestDeleteContains(unittest.TestCase):
    def test_delete_existing(self):
        be = StateBackend("t")
        be.put("k", 1)
        self.assertTrue(be.delete("k"))
        self.assertIsNone(be.get("k"))

    def test_delete_missing(self):
        be = StateBackend("t")
        self.assertFalse(be.delete("k"))

    def test_contains(self):
        be = StateBackend("t")
        be.put("k", 1, namespace="n")
        self.assertTrue(be.contains("k", namespace="n"))
        self.assertFalse(be.contains("k", namespace="other"))
        self.assertFalse(be.contains("missing"))


class TestViews(unittest.TestCase):
    def test_size_keys_namespaces(self):
        be = StateBackend("t")
        be.put("b", 1, namespace="ns")
        be.put("a", 2, namespace="ns")
        be.put("z", 3)
        self.assertEqual(be.size(), 3)
        self.assertEqual(be.keys(), (("", "z"), ("ns", "a"), ("ns", "b")))
        self.assertEqual(be.keys(namespace="ns"), (("ns", "a"), ("ns", "b")))
        self.assertEqual(be.namespaces(), ("", "ns"))

    def test_clear(self):
        be = StateBackend("t")
        be.put("k", 1)
        be.clear()
        self.assertEqual(be.size(), 0)
        self.assertIsNone(be.get("k"))


class TestSnapshot(unittest.TestCase):
    def test_snapshot_shape(self):
        be = StateBackend("t")
        be.put("k", "v")
        snap = be.snapshot(1)
        self.assertEqual(snap.backend_name, "t")
        self.assertEqual(snap.seq, 1)
        self.assertEqual(snap.entry_count, 1)
        self.assertTrue(snap.digest.startswith("sha256:"))
        self.assertEqual(snap.schema, STATE_BACKEND_SCHEMA)

    def test_snapshot_seq_strictly_increases(self):
        be = StateBackend("t")
        be.snapshot(1)
        with self.assertRaises(StateBackendError):
            be.snapshot(1)
        with self.assertRaises(TypeError):
            be.snapshot(True)

    def test_snapshot_matches_live_digest(self):
        be = StateBackend("t")
        be.put("k", "v")
        snap = be.snapshot(1)
        self.assertEqual(be.state_digest(), snap.digest)
        self.assertTrue(snap.verify())

    def test_snapshot_isolation(self):
        be = StateBackend("t")
        be.put("k", 1)
        snap = be.snapshot(1)
        be.put("k", 2)
        restored = StateBackend("t")
        restored.restore(snap, 2)
        self.assertEqual(restored.get("k"), 1)

    def test_snapshot_frozen(self):
        be = StateBackend("t")
        snap = be.snapshot(0)
        with self.assertRaises(Exception):
            snap.seq = 99  # type: ignore[misc]

    def test_empty_snapshot(self):
        be = StateBackend("t")
        snap = be.snapshot(0)
        self.assertEqual(snap.entry_count, 0)
        be.put("k", 1)
        be.restore(snap, 1)
        self.assertEqual(be.size(), 0)


class TestRestore(unittest.TestCase):
    def test_restore_roundtrip(self):
        be = StateBackend("t")
        be.put("k1", {"a": 1}, namespace="n1")
        be.put("k2", [1, 2], namespace="n2")
        snap = be.snapshot(1)
        be2 = StateBackend("t")
        be2.restore(snap, 1)
        self.assertEqual(be2.get("k1", namespace="n1"), {"a": 1})
        self.assertEqual(be2.get("k2", namespace="n2"), [1, 2])
        self.assertEqual(be2.state_digest(), snap.digest)

    def test_restore_tampered_digest_refused(self):
        be = StateBackend("t")
        be.put("k", "v")
        snap = be.snapshot(1)
        tampered = Snapshot(
            backend_name="t",
            seq=9,
            entry_count=1,
            digest="sha256:" + "0" * 64,
            payload=snap.payload,
        )
        with self.assertRaises(SnapshotVerificationError):
            be.restore(tampered, 2)

    def test_restore_foreign_backend_refused(self):
        be = StateBackend("t")
        be.put("k", "v")
        snap = be.snapshot(1)
        other = StateBackend("other")
        with self.assertRaises(SnapshotVerificationError):
            other.restore(snap, 2)

    def test_restore_non_snapshot_rejected(self):
        be = StateBackend("t")
        with self.assertRaises(TypeError):
            be.restore({"digest": "x"}, 1)

    def test_restore_never_partial(self):
        be = StateBackend("t")
        be.put("keep", "me")
        before = be.state_digest()
        bad = Snapshot(
            backend_name="t",
            seq=9,
            entry_count=0,
            digest="sha256:" + "f" * 64,
            payload=b"",
        )
        with self.assertRaises(SnapshotVerificationError):
            be.restore(bad, 2)
        self.assertEqual(be.state_digest(), before)
        self.assertEqual(be.get("keep"), "me")


class TestAuditEvents(unittest.TestCase):
    def test_event_shape(self):
        ev = state_backend_audit_event("put", 3, namespace="n", key="k")
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["kind"], "state-backend.put")
        self.assertEqual(ev["module"], STATE_BACKEND_SCHEMA)
        self.assertEqual(ev["version"], STATE_BACKEND_VERSION)
        self.assertEqual(ev["seq"], 3)
        self.assertEqual(ev["key"], "k")

    def test_all_kinds(self):
        for kind in ("put", "got", "deleted", "snapshotted", "restored", "cleared", "rejected"):
            ev = state_backend_audit_event(kind, 0)
            self.assertEqual(ev["kind"], f"state-backend.{kind}")

    def test_bad_kind_rejected(self):
        with self.assertRaises(ValueError):
            state_backend_audit_event("nope", 0)

    def test_bad_seq_rejected(self):
        with self.assertRaises((TypeError, ValueError)):
            state_backend_audit_event("put", -1)
        with self.assertRaises((TypeError, ValueError)):
            state_backend_audit_event("put", True)


class TestMain(unittest.TestCase):
    def test_main(self):
        from state_backend import main

        main()


if __name__ == "__main__":
    unittest.main()
