"""Tests for idempotency_manager.py."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from idempotency_manager import (  # noqa: E402
    IDEMPOTENCY_MANAGER_VERSION,
    SCHEMA_PIN,
    IdempotencyError,
    IdempotencyKey,
    IdempotencyManager,
    IdempotencyOutcome,
    PayloadMismatchError,
    idempotency_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(IDEMPOTENCY_MANAGER_VERSION, "idempotency-manager.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.idempotency-manager.v1")


class TestIdempotencyKey(unittest.TestCase):
    def _good_hash(self):
        return "sha256:" + "ab" * 32

    def test_happy_path(self):
        k = IdempotencyKey(key="op-1", result_hash=self._good_hash())
        self.assertEqual(k.key, "op-1")
        self.assertEqual(k.schema, SCHEMA_PIN)

    def test_frozen(self):
        k = IdempotencyKey(key="op-1", result_hash=self._good_hash())
        with self.assertRaises(Exception):
            k.key = "other"  # type: ignore[misc]

    def test_empty_key_rejected(self):
        with self.assertRaises(ValueError):
            IdempotencyKey(key="", result_hash=self._good_hash())

    def test_non_str_key_rejected(self):
        with self.assertRaises(TypeError):
            IdempotencyKey(key=123, result_hash=self._good_hash())  # type: ignore[arg-type]

    def test_bad_hash_prefix_rejected(self):
        with self.assertRaises(ValueError):
            IdempotencyKey(key="op-1", result_hash="md5:" + "ab" * 32)

    def test_bad_hash_hex_rejected(self):
        with self.assertRaises(ValueError):
            IdempotencyKey(key="op-1", result_hash="sha256:" + "zz" * 32)

    def test_as_dict_shape(self):
        d = IdempotencyKey(key="op-1", result_hash=self._good_hash()).as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["key"], "op-1")


class TestCheckOrStore(unittest.TestCase):
    def test_first_store_hit_false(self):
        mgr = IdempotencyManager()
        out = mgr.check_or_store("k1", {"ok": True}, seq=1)
        self.assertFalse(out.hit)
        self.assertEqual(out.result, {"ok": True})
        self.assertEqual(out.first_seq, 1)
        self.assertTrue(out.result_consistent)

    def test_replay_hit_true_first_seq_preserved(self):
        mgr = IdempotencyManager()
        mgr.check_or_store("k1", {"ok": True}, seq=1)
        out = mgr.check_or_store("k1", {"ok": True}, seq=99)
        self.assertTrue(out.hit)
        self.assertEqual(out.first_seq, 1)
        self.assertEqual(out.result, {"ok": True})

    def test_replay_returns_cached_not_new(self):
        mgr = IdempotencyManager()
        mgr.check_or_store("k1", {"v": 1}, seq=1)
        out = mgr.check_or_store("k1", {"v": 2}, seq=2)
        self.assertTrue(out.hit)
        self.assertEqual(out.result, {"v": 1})
        self.assertFalse(out.result_consistent)

    def test_payload_binding_same_payload_ok(self):
        mgr = IdempotencyManager()
        mgr.check_or_store("k1", "r", payload={"x": 1}, seq=0)
        out = mgr.check_or_store("k1", "r", payload={"x": 1}, seq=1)
        self.assertTrue(out.hit)

    def test_payload_mismatch_raises(self):
        mgr = IdempotencyManager()
        mgr.check_or_store("k1", "r", payload={"x": 1}, seq=0)
        with self.assertRaises(PayloadMismatchError):
            mgr.check_or_store("k1", "r", payload={"x": 2}, seq=1)

    def test_payload_presence_mismatch_raises(self):
        mgr = IdempotencyManager()
        mgr.check_or_store("k1", "r", payload={"x": 1}, seq=0)
        with self.assertRaises(PayloadMismatchError):
            mgr.check_or_store("k1", "r", seq=1)  # payload dropped

    def test_payload_mismatch_is_idempotency_error(self):
        self.assertTrue(issubclass(PayloadMismatchError, IdempotencyError))

    def test_empty_key_rejected(self):
        mgr = IdempotencyManager()
        with self.assertRaises(ValueError):
            mgr.check_or_store("", "r")

    def test_bool_seq_rejected(self):
        mgr = IdempotencyManager()
        with self.assertRaises(TypeError):
            mgr.check_or_store("k1", "r", seq=True)  # type: ignore[arg-type]

    def test_negative_seq_rejected(self):
        mgr = IdempotencyManager()
        with self.assertRaises(ValueError):
            mgr.check_or_store("k1", "r", seq=-1)

    def test_nan_result_rejected(self):
        mgr = IdempotencyManager()
        with self.assertRaises(TypeError):
            mgr.check_or_store("k1", float("nan"))

    def test_non_canonicalizable_result_rejected(self):
        mgr = IdempotencyManager()
        with self.assertRaises(TypeError):
            mgr.check_or_store("k1", object())

    def test_non_str_dict_key_rejected(self):
        mgr = IdempotencyManager()
        with self.assertRaises(TypeError):
            mgr.check_or_store("k1", {1: "x"})

    def test_lookup_and_stored_keys(self):
        mgr = IdempotencyManager()
        self.assertIsNone(mgr.lookup("missing"))
        mgr.check_or_store("a", 1, seq=0)
        mgr.check_or_store("b", 2, seq=0)
        self.assertEqual(mgr.stored_keys(), ("a", "b"))
        self.assertEqual(len(mgr), 2)
        found = mgr.lookup("a")
        self.assertIsNotNone(found)
        assert found is not None
        self.assertEqual(found.key, "a")
        self.assertTrue(found.result_hash.startswith("sha256:"))

    def test_lookup_bad_key_rejected(self):
        mgr = IdempotencyManager()
        with self.assertRaises(TypeError):
            mgr.lookup(123)  # type: ignore[arg-type]


class TestAuditEvent(unittest.TestCase):
    def test_store_event_shape(self):
        mgr = IdempotencyManager()
        out = mgr.check_or_store("secret-key", {"ok": 1}, seq=0)
        evt = idempotency_audit_event("secret-key", out, seq=5)
        self.assertEqual(evt["event"], "idempotency-store")
        self.assertFalse(evt["hit"])
        self.assertEqual(evt["audit_seq"], 5)
        self.assertEqual(evt["schema"], SCHEMA_PIN)
        # raw key must not leak into the audit record
        self.assertNotIn("secret-key", str(evt))
        self.assertTrue(evt["key_digest"].startswith("sha256:"))

    def test_replay_event_shape(self):
        mgr = IdempotencyManager()
        mgr.check_or_store("k", "r", seq=0)
        out = mgr.check_or_store("k", "r", seq=1)
        evt = idempotency_audit_event("k", out, seq=2)
        self.assertEqual(evt["event"], "idempotency-replay")
        self.assertTrue(evt["hit"])

    def test_bad_seq_rejected(self):
        mgr = IdempotencyManager()
        out = mgr.check_or_store("k", "r", seq=0)
        with self.assertRaises(ValueError):
            idempotency_audit_event("k", out, seq=-1)
        with self.assertRaises(TypeError):
            idempotency_audit_event("k", out, seq="1")  # type: ignore[arg-type]

    def test_bad_outcome_rejected(self):
        with self.assertRaises(TypeError):
            idempotency_audit_event("k", "not-an-outcome", seq=0)  # type: ignore[arg-type]


class TestOutcomeFrozen(unittest.TestCase):
    def test_outcome_frozen(self):
        mgr = IdempotencyManager()
        out = mgr.check_or_store("k", "r", seq=0)
        with self.assertRaises(Exception):
            out.hit = True  # type: ignore[misc]
        self.assertIsInstance(out, IdempotencyOutcome)
        self.assertEqual(out.schema, SCHEMA_PIN)


if __name__ == "__main__":
    unittest.main()
