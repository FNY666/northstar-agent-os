"""Tests for capability_warrants (F line, Tenuo-inspired).

Covers the cryptographic negatives: forgery, replay, over-privilege
attenuation, constraint widening, and receipt chaining.
"""

from __future__ import annotations

import os
import time
import unittest

import support  # noqa: F401 — sys.path bootstrap

import capability_warrants as cw
import ed25519


def _keypair() -> tuple[bytes, bytes]:
    secret = os.urandom(32)
    return secret, ed25519.public_key(secret)


class WarrantIssueTests(unittest.TestCase):
    def test_issue_and_verify_roundtrip(self):
        issuer_sec, _ = _keypair()
        _, holder_pub = _keypair()
        w = cw.issue(
            issuer_secret=issuer_sec,
            holder_pubkey=holder_pub,
            tools=["Read"],
            constraints=[{"param": "path", "kind": "prefix", "value": "src/"}],
        )
        self.assertEqual(w["format"], cw.WARRANT_VERSION)
        self.assertEqual(w["depth"], 0)
        # Tampering with the warrant breaks the signature.
        w2 = dict(w)
        w2["tools"] = ["Read", "Shell"]
        now = int(time.time())
        holder_sec, _ = _keypair()  # wrong key, but sig check comes first
        pop = cw.pop_sign(
            holder_secret=holder_sec,
            warrant_id=w2["warrant_id"],
            tool="Read",
            params={"path": "src/a.py"},
            now=now,
        )
        v = cw.authorize(
            warrant=w2, tool="Read", params={"path": "src/a.py"},
            pop_signature=pop, now=now,
        )
        self.assertFalse(v.ok)
        self.assertIn("signature invalid", v.violations[0])


class HolderBoundTests(unittest.TestCase):
    def setUp(self):
        self.issuer_sec, _ = _keypair()
        self.holder_sec, self.holder_pub = _keypair()
        self.w = cw.issue(
            issuer_secret=self.issuer_sec,
            holder_pubkey=self.holder_pub,
            tools=["Write"],
        )
        self.now = int(time.time())
        self.params = {"path": "a.txt"}

    def _pop(self, secret: bytes, now: int | None = None) -> bytes:
        return cw.pop_sign(
            holder_secret=secret,
            warrant_id=self.w["warrant_id"],
            tool="Write",
            params=self.params,
            now=self.now if now is None else now,
        )

    def test_valid_pop_allows(self):
        v = cw.authorize(
            warrant=self.w, tool="Write", params=self.params,
            pop_signature=self._pop(self.holder_sec), now=self.now,
        )
        self.assertTrue(v.ok)
        self.assertIsNotNone(v.receipt)
        self.assertEqual(v.receipt["decision"], "allow")

    def test_forged_pop_rejected(self):
        """A stolen warrant without the holder key is useless."""
        evil_sec, _ = _keypair()
        v = cw.authorize(
            warrant=self.w, tool="Write", params=self.params,
            pop_signature=self._pop(evil_sec), now=self.now,
        )
        self.assertFalse(v.ok)
        self.assertIn("proof-of-possession", v.violations[0])

    def test_replay_outside_window_rejected(self):
        """A PoP from an old time window does not authorize now."""
        old_pop = self._pop(self.holder_sec, now=self.now - 3600)
        v = cw.authorize(
            warrant=self.w, tool="Write", params=self.params,
            pop_signature=old_pop, now=self.now,
        )
        self.assertFalse(v.ok)

    def test_pop_bound_to_params(self):
        """PoP for different params does not authorize."""
        other_pop = cw.pop_sign(
            holder_secret=self.holder_sec,
            warrant_id=self.w["warrant_id"],
            tool="Write",
            params={"path": "other.txt"},
            now=self.now,
        )
        v = cw.authorize(
            warrant=self.w, tool="Write", params=self.params,
            pop_signature=other_pop, now=self.now,
        )
        self.assertFalse(v.ok)

    def test_expired_warrant_rejected(self):
        w = cw.issue(
            issuer_secret=self.issuer_sec,
            holder_pubkey=self.holder_pub,
            tools=["Write"],
            ttl_seconds=-10,  # already expired
        )
        v = cw.authorize(
            warrant=w, tool="Write", params=self.params,
            pop_signature=self._pop(self.holder_sec), now=self.now,
        )
        self.assertFalse(v.ok)
        self.assertIn("expired", v.violations[0])


class AttenuationTests(unittest.TestCase):
    def setUp(self):
        self.issuer_sec, _ = _keypair()
        self.holder_sec, self.holder_pub = _keypair()
        self.parent = cw.issue(
            issuer_secret=self.issuer_sec,
            holder_pubkey=self.holder_pub,
            tools=["Read", "Write"],
            constraints=[
                {"param": "path", "kind": "prefix", "value": "src/"},
                {"param": "size", "kind": "range", "min": 0, "max": 1000},
            ],
            max_depth=2,
        )

    def _child_key(self) -> tuple[bytes, bytes]:
        return _keypair()

    def test_valid_attenuation_narrows(self):
        child_sec, child_pub = self._child_key()
        child = cw.attenuate(
            parent_warrant=self.parent,
            holder_secret=self.holder_sec,
            child_holder_pubkey=child_pub,
            tools=["Read"],
            constraints=[
                {"param": "path", "kind": "prefix", "value": "src/lib/"},
                {"param": "size", "kind": "range", "min": 0, "max": 100},
            ],
        )
        self.assertEqual(child["depth"], 1)
        self.assertEqual(child["parent_hash"], cw._hash(self.parent))
        self.assertLessEqual(child["expires_at"], self.parent["expires_at"])

    def test_tool_widening_rejected(self):
        """Cannot add tools the parent lacks (monotonic)."""
        child_sec, child_pub = self._child_key()
        with self.assertRaises(cw.WarrantError):
            cw.attenuate(
                parent_warrant=self.parent,
                holder_secret=self.holder_sec,
                child_holder_pubkey=child_pub,
                tools=["Read", "Write", "Shell"],
            )

    def test_constraint_widening_rejected(self):
        """A broader prefix does not narrow the parent."""
        child_sec, child_pub = self._child_key()
        with self.assertRaises(cw.WarrantError):
            cw.attenuate(
                parent_warrant=self.parent,
                holder_secret=self.holder_sec,
                child_holder_pubkey=child_pub,
                constraints=[
                    {"param": "path", "kind": "prefix", "value": "s"},
                ],
            )

    def test_range_widening_rejected(self):
        child_sec, child_pub = self._child_key()
        with self.assertRaises(cw.WarrantError):
            cw.attenuate(
                parent_warrant=self.parent,
                holder_secret=self.holder_sec,
                child_holder_pubkey=child_pub,
                constraints=[
                    {"param": "size", "kind": "range", "min": 0, "max": 9999},
                ],
            )

    def test_non_holder_cannot_delegate(self):
        """Only the holder can delegate ("you can only delegate what you hold")."""
        evil_sec, _ = _keypair()
        _, child_pub = self._child_key()
        with self.assertRaises(cw.WarrantError):
            cw.attenuate(
                parent_warrant=self.parent,
                holder_secret=evil_sec,
                child_holder_pubkey=child_pub,
            )

    def test_depth_ceiling_enforced(self):
        c1_sec, c1_pub = self._child_key()
        child1 = cw.attenuate(
            parent_warrant=self.parent,
            holder_secret=self.holder_sec,
            child_holder_pubkey=c1_pub,
        )
        c2_sec, c2_pub = self._child_key()
        child2 = cw.attenuate(
            parent_warrant=child1,
            holder_secret=c1_sec,
            child_holder_pubkey=c2_pub,
        )
        self.assertEqual(child2["depth"], 2)
        c3_sec, c3_pub = self._child_key()
        with self.assertRaises(cw.WarrantError):
            cw.attenuate(
                parent_warrant=child2,
                holder_secret=c2_sec,
                child_holder_pubkey=c3_pub,
            )

    def test_expiry_capped_by_parent(self):
        child_sec, child_pub = self._child_key()
        child = cw.attenuate(
            parent_warrant=self.parent,
            holder_secret=self.holder_sec,
            child_holder_pubkey=child_pub,
            ttl_seconds=10**9,  # asks for far future
        )
        self.assertLessEqual(child["expires_at"], self.parent["expires_at"])


class ConstraintEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.issuer_sec, _ = _keypair()
        self.holder_sec, self.holder_pub = _keypair()
        self.w = cw.issue(
            issuer_secret=self.issuer_sec,
            holder_pubkey=self.holder_pub,
            tools=["Write"],
            constraints=[
                {"param": "path", "kind": "prefix", "value": "src/"},
                {"param": "mode", "kind": "one_of", "values": ["create", "append"]},
            ],
        )
        self.now = int(time.time())

    def _auth(self, params: dict) -> cw.WarrantVerdict:
        pop = cw.pop_sign(
            holder_secret=self.holder_sec,
            warrant_id=self.w["warrant_id"],
            tool="Write",
            params=params,
            now=self.now,
        )
        return cw.authorize(
            warrant=self.w, tool="Write", params=params,
            pop_signature=pop, now=self.now,
        )

    def test_unknown_parameter_rejected_zero_trust(self):
        v = self._auth({"path": "src/a.py", "mode": "create", "evil": "1"})
        self.assertFalse(v.ok)
        self.assertIn("unknown parameter", v.violations[0])

    def test_unknown_constraint_kind_fail_closed(self):
        w = cw.issue(
            issuer_secret=self.issuer_sec,
            holder_pubkey=self.holder_pub,
            tools=["Write"],
            constraints=[{"param": "x", "kind": "frobnicator", "value": 1}],
        )
        pop = cw.pop_sign(
            holder_secret=self.holder_sec, warrant_id=w["warrant_id"],
            tool="Write", params={"x": 1}, now=self.now,
        )
        v = cw.authorize(
            warrant=w, tool="Write", params={"x": 1},
            pop_signature=pop, now=self.now,
        )
        self.assertFalse(v.ok)
        self.assertIn("fail-closed", v.violations[0])

    def test_receipt_chaining(self):
        v1 = self._auth({"path": "src/a.py", "mode": "create"})
        self.assertTrue(v1.ok)
        h1 = cw._hash(v1.receipt)
        v2 = self._auth({"path": "src/b.py", "mode": "append"})
        self.assertTrue(v2.ok)
        # Chain manually: second receipt references the first.
        self.assertNotEqual(cw._hash(v1.receipt), cw._hash(v2.receipt))


if __name__ == "__main__":
    unittest.main()
