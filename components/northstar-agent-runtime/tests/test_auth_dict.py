"""Tests for auth_dict: Merkle authenticated dictionary."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from auth_dict import (
    AUTH_DICT_SCHEMA,
    AUTH_DICT_VERSION,
    EVENT_PROOF,
    EVENT_PUT,
    EVENT_ROOT,
    EVENT_VERIFY,
    AuthDict,
    AuthDictError,
    DictSummary,
    InclusionProof,
    auth_dict_audit_event,
    verify,
)


class TestVersionPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(AUTH_DICT_VERSION, "auth-dict.v1")

    def test_schema_pin(self):
        self.assertEqual(AUTH_DICT_SCHEMA, "northstar.auth-dict.v1")


class TestPutGet(unittest.TestCase):
    def test_put_get_roundtrip(self):
        d = AuthDict()
        d.put("k1", "v1")
        self.assertEqual(d.get("k1"), b"v1")

    def test_put_bytes_value(self):
        d = AuthDict()
        d.put("k", b"\x00\xff")
        self.assertEqual(d.get("k"), b"\x00\xff")

    def test_get_missing_returns_none(self):
        d = AuthDict()
        d.put("k", "v")
        self.assertIsNone(d.get("other"))

    def test_put_overwrites(self):
        d = AuthDict()
        d.put("k", "v1")
        d.put("k", "v2")
        self.assertEqual(d.get("k"), b"v2")
        self.assertEqual(len(d), 1)

    def test_len_and_keys(self):
        d = AuthDict()
        d.put("b", "1")
        d.put("a", "2")
        self.assertEqual(len(d), 2)
        self.assertEqual(d.keys(), ("a", "b"))  # proof order: sorted

    def test_key_validation(self):
        d = AuthDict()
        for bad in ("", True, False, 1, None, b"k"):
            with self.assertRaises((TypeError, ValueError), msg=repr(bad)):
                d.put(bad, "v")
        with self.assertRaises((TypeError, ValueError)):
            d.get("")

    def test_value_validation(self):
        d = AuthDict()
        for bad in (True, False, 1, None, ["v"], {"v": 1}):
            with self.assertRaises(TypeError, msg=repr(bad)):
                d.put("k", bad)

    def test_value_not_mutated(self):
        d = AuthDict()
        buf = bytearray(b"abc")
        d.put("k", buf)
        buf[0] = 0xFF
        self.assertEqual(d.get("k"), b"abc")


class TestRoot(unittest.TestCase):
    def test_empty_root_defined(self):
        d = AuthDict()
        r = d.root()
        self.assertTrue(r.startswith("sha256:"))
        self.assertEqual(len(r), len("sha256:") + 64)

    def test_root_changes_on_put(self):
        d = AuthDict()
        r0 = d.root()
        d.put("a", "1")
        self.assertNotEqual(d.root(), r0)

    def test_root_order_independent(self):
        d1 = AuthDict()
        d2 = AuthDict()
        d1.put("a", "1")
        d1.put("b", "2")
        d2.put("b", "2")
        d2.put("a", "1")
        self.assertEqual(d1.root(), d2.root())

    def test_root_deterministic(self):
        roots = set()
        for _ in range(3):
            d = AuthDict()
            d.put("x", "1")
            d.put("y", "2")
            roots.add(d.root())
        self.assertEqual(len(roots), 1)

    def test_overwrite_changes_root(self):
        d = AuthDict()
        d.put("a", "1")
        r1 = d.root()
        d.put("a", "2")
        self.assertNotEqual(d.root(), r1)

    def test_summary(self):
        d = AuthDict()
        d.put("a", "1")
        s = d.summary()
        self.assertIsInstance(s, DictSummary)
        self.assertEqual(s.root_digest, d.root())
        self.assertEqual(s.entries, 1)
        self.assertEqual(s.version, AUTH_DICT_VERSION)
        self.assertEqual(s.schema, AUTH_DICT_SCHEMA)


class TestProofVerify(unittest.TestCase):
    def _dict3(self):
        d = AuthDict()
        d.put("budget:skill-x", "100")
        d.put("policy:kill-switch", b"\x01armed")
        d.put("config:region", "gd")
        return d

    def test_proof_verifies(self):
        d = self._dict3()
        p = d.proof("policy:kill-switch")
        self.assertIsInstance(p, InclusionProof)
        self.assertTrue(verify(p, "policy:kill-switch", b"\x01armed", d.root()))

    def test_proof_all_keys(self):
        d = self._dict3()
        for key, val in (("budget:skill-x", "100"), ("policy:kill-switch", b"\x01armed"),
                         ("config:region", "gd")):
            self.assertTrue(verify(d.proof(key), key, val, d.root()), key)

    def test_proof_single_entry_empty_path(self):
        d = AuthDict()
        d.put("only", "one")
        p = d.proof("only")
        self.assertEqual(p.steps, ())
        self.assertEqual(p.leaf_count, 1)
        self.assertTrue(verify(p, "only", "one", d.root()))

    def test_verify_wrong_value_false(self):
        d = self._dict3()
        p = d.proof("budget:skill-x")
        self.assertFalse(verify(p, "budget:skill-x", "999", d.root()))

    def test_verify_wrong_key_false(self):
        d = self._dict3()
        p = d.proof("budget:skill-x")
        self.assertFalse(verify(p, "config:region", "100", d.root()))

    def test_verify_wrong_root_false(self):
        d = self._dict3()
        p = d.proof("budget:skill-x")
        d.put("budget:skill-x", "changed")
        self.assertFalse(verify(p, "budget:skill-x", "100", d.root()))

    def test_proof_missing_key_raises(self):
        d = self._dict3()
        with self.assertRaises(AuthDictError):
            d.proof("nope")

    def test_proof_empty_dict_raises(self):
        with self.assertRaises(AuthDictError):
            AuthDict().proof("nope")

    def test_tampered_sibling_false(self):
        d = self._dict3()
        p = d.proof("budget:skill-x")
        tampered_steps = tuple(
            (side, "00" * 32 if i == 0 else sib)
            for i, (side, sib) in enumerate(p.steps)
        )
        tampered = InclusionProof(
            key=p.key, value_digest=p.value_digest, steps=tampered_steps,
            leaf_count=p.leaf_count, leaf_index=p.leaf_index,
            root_digest=p.root_digest,
        )
        self.assertFalse(verify(tampered, p.key, "100", d.root()))

    def test_flipped_side_false(self):
        d = self._dict3()
        p = d.proof("config:region")
        if p.steps:  # skip for single-entry trees
            flipped = tuple(
                (("L" if s == "R" else "R"), h) for s, h in p.steps
            )
            bad = InclusionProof(
                key=p.key, value_digest=p.value_digest, steps=flipped,
                leaf_count=p.leaf_count, leaf_index=p.leaf_index,
                root_digest=p.root_digest,
            )
            self.assertFalse(verify(bad, p.key, "gd", d.root()))
        else:
            self.assertTrue(verify(p, p.key, "gd", d.root()))

    def test_leaf_length_prefix_binding(self):
        # ("a","bc") vs ("ab","c") must hash to different leaves
        d1 = AuthDict()
        d1.put("a", "bc")
        d2 = AuthDict()
        d2.put("ab", "c")
        self.assertNotEqual(d1.root(), d2.root())
        p1 = d1.proof("a")
        self.assertFalse(verify(p1, "ab", "c", d1.root()))

    def test_verify_bad_types_raise(self):
        d = self._dict3()
        p = d.proof("budget:skill-x")
        with self.assertRaises(TypeError):
            verify("not-a-proof", "budget:skill-x", "100", d.root())
        with self.assertRaises(TypeError):
            verify(p, "budget:skill-x", "100", 123)
        with self.assertRaises(TypeError):
            verify(p, 123, "100", d.root())

    def test_proof_stale_after_overwrite(self):
        d = AuthDict()
        d.put("k", "v1")
        p = d.proof("k")
        r1 = d.root()
        self.assertTrue(verify(p, "k", "v1", r1))
        d.put("k", "v2")
        self.assertFalse(verify(p, "k", "v1", d.root()))  # root moved on
        p2 = d.proof("k")
        self.assertTrue(verify(p2, "k", "v2", d.root()))

    def test_proof_record_shape(self):
        d = AuthDict()
        d.put("k", "v")
        p = d.proof("k")
        bd = p.as_dict()
        self.assertEqual(bd["key"], "k")
        self.assertEqual(bd["schema"], AUTH_DICT_SCHEMA)
        self.assertEqual(bd["root_digest"], d.root())

    def test_many_entries_proofs(self):
        d = AuthDict()
        for i in range(20):
            d.put(f"key-{i:02d}", f"value-{i}")
        root = d.root()
        for i in (0, 7, 13, 19):
            k = f"key-{i:02d}"
            self.assertTrue(verify(d.proof(k), k, f"value-{i}", root), k)


class TestAuditEvents(unittest.TestCase):
    def test_event_shapes(self):
        d = AuthDict()
        d.put("k", "v")
        for kind in (EVENT_PUT, EVENT_PROOF, EVENT_VERIFY, EVENT_ROOT):
            ev = auth_dict_audit_event(kind, d.summary(), seq=3)
            self.assertEqual(ev["schema"], "audit.ndjson/1")
            self.assertEqual(ev["kind"], kind)
            self.assertEqual(ev["seq"], 3)
            self.assertIn("root_digest", ev["body"])

    def test_event_bad_kind(self):
        with self.assertRaises(ValueError):
            auth_dict_audit_event("nope", {}, seq=1)

    def test_event_bad_seq(self):
        with self.assertRaises((TypeError, ValueError)):
            auth_dict_audit_event(EVENT_PUT, {}, seq=-1)
        with self.assertRaises((TypeError, ValueError)):
            auth_dict_audit_event(EVENT_PUT, {}, seq=True)

    def test_event_kind_constants(self):
        self.assertEqual((EVENT_PUT, EVENT_PROOF, EVENT_VERIFY, EVENT_ROOT),
                         ("put", "proof", "verify", "root"))


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        from auth_dict import main
        main()


if __name__ == "__main__":
    unittest.main()
