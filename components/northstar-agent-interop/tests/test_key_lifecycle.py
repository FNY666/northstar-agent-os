"""RED tests for signing-key lifecycle bound to a pinned trust anchor."""
import json
import os
import shutil
import tempfile
import unittest

from key_lifecycle import (
    KeyHistory,
    KeyLifecycleError,
    KeyRecord,
    KeyRing,
    KeyVerdict,
)
from proof_signing import (
    ProofSignatureError,
    sign_attestation,
    verify_signed_attestation,
)
from evidence_proof import ProofAttestation


def _material(seed: bytes, size: int = 32) -> bytes:
    return (seed * size)[:size]


def _attestation(route_id: str = "route-1") -> ProofAttestation:
    digest = "sha256:" + "a" * 64
    return ProofAttestation(
        "northstar.proof-attestation.v1",
        "verified",
        route_id,
        digest,
        digest,
        digest,
        digest,
    )


class KeyHistoryBasics(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="keys-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.path = os.path.join(self.dir, "key-history.jsonl")
        self.history = KeyHistory(self.path)

    def test_introduced_key_is_trusted(self):
        self.history.introduce("k1", _material(b"1"))
        verdict = self.history.verdict("k1")
        self.assertEqual(verdict.state, "trusted")
        self.assertEqual(self.history.verify_chain().state, "trusted")

    def test_rotation_retires_the_previous_key_without_forgetting_it(self):
        self.history.introduce("k1", _material(b"1"))
        self.history.rotate("k2", _material(b"2"))
        self.assertEqual(self.history.verdict("k1").state, "trusted-retired")
        self.assertEqual(self.history.verdict("k2").state, "trusted")
        self.assertEqual([r.action for r in self.history.records], ["introduced", "rotated"])
        self.assertEqual([r.key_id for r in self.history.records], ["k1", "k2"])

    def test_revoked_key_is_refused_after_revocation(self):
        self.history.introduce("k1", _material(b"1"))
        self.history.revoke("k1")
        self.assertEqual(self.history.verdict("k1").state, "revoked")

    def test_rotation_then_revocation_keeps_both_facts(self):
        self.history.introduce("k1", _material(b"1"))
        self.history.rotate("k2", _material(b"2"))
        self.history.revoke("k1")
        self.assertEqual(self.history.verdict("k1").state, "revoked")
        self.assertEqual(self.history.verdict("k2").state, "trusted")

    def test_unknown_key_is_reported_not_trusted(self):
        self.history.introduce("k1", _material(b"1"))
        verdict = self.history.verdict("k-ghost")
        self.assertEqual(verdict.state, "unknown-key")
        self.assertIn("key_not_in_history", verdict.reasons)

    def test_duplicate_introduction_is_refused(self):
        self.history.introduce("k1", _material(b"1"))
        with self.assertRaises(KeyLifecycleError):
            self.history.introduce("k1", _material(b"1"))

    def test_rotation_requires_a_new_key_id(self):
        self.history.introduce("k1", _material(b"1"))
        with self.assertRaises(KeyLifecycleError):
            self.history.rotate("k1", _material(b"1"))

    def test_revoking_an_unknown_key_is_refused(self):
        self.history.introduce("k1", _material(b"1"))
        with self.assertRaises(KeyLifecycleError):
            self.history.revoke("k-ghost")

    def test_revoking_twice_is_refused(self):
        self.history.introduce("k1", _material(b"1"))
        self.history.revoke("k1")
        with self.assertRaises(KeyLifecycleError):
            self.history.revoke("k1")


class KeyHistoryIntegrity(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="keys-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.path = os.path.join(self.dir, "key-history.jsonl")
        self.history = KeyHistory(self.path)
        self.history.introduce("k1", _material(b"1"))
        self.history.rotate("k2", _material(b"2"))
        self.anchor = self.history.records[0].record_digest

    def test_records_are_chained(self):
        first, second = self.history.records
        self.assertEqual(second.previous_digest, first.record_digest)
        self.assertNotEqual(first.record_digest, second.record_digest)

    def test_chain_is_bound_to_the_trust_anchor(self):
        other = KeyHistory(self.path, anchor="sha256:" + "b" * 64)
        self.assertEqual(other.verify_chain().state, "untrusted-anchor")

    def test_correct_anchor_is_accepted(self):
        pinned = KeyHistory(self.path, anchor=self.anchor)
        self.assertEqual(pinned.verify_chain().state, "trusted")
        self.assertEqual(pinned.verdict("k2").state, "trusted")

    def test_unpinned_history_says_so(self):
        unpinned = KeyHistory(self.path)
        self.assertIn("anchor_unpinned", unpinned.verify_chain().reasons)

    def test_tampered_history_is_unverifiable(self):
        with open(self.path, "r", encoding="utf-8") as handle:
            lines = handle.read().splitlines()
        value = json.loads(lines[0])
        value["material_digest"] = "sha256:" + "c" * 64
        lines[0] = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        pinned = KeyHistory(self.path)
        self.assertEqual(pinned.verify_chain().state, "unverifiable")
        self.assertEqual(pinned.verdict("k2").state, "unverifiable")

    def test_deleted_history_is_unverifiable_not_trusted(self):
        os.unlink(self.path)
        pinned = KeyHistory(self.path, anchor=self.anchor)
        self.assertEqual(pinned.verify_chain().state, "unverifiable")
        self.assertEqual(pinned.verdict("k1").state, "unverifiable")

    def test_material_never_appears_in_the_history_file(self):
        secret = _material(b"7")
        history = KeyHistory(os.path.join(self.dir, "second.jsonl"))
        history.introduce("k7", secret)
        with open(os.path.join(self.dir, "second.jsonl"), "rb") as handle:
            raw = handle.read()
        self.assertNotIn(secret, raw)
        self.assertNotIn(secret.hex().encode(), raw)
        self.assertIn(b"sha256:", raw)

    def test_record_digest_covers_the_key_identity(self):
        with open(self.path, encoding="utf-8") as handle:
            raw = json.loads(handle.read().splitlines()[0])
        self.assertEqual(set(raw), {"revision", "key_id", "material_digest", "action", "previous_digest", "record_digest"})
        self.assertEqual(raw["revision"], 1)
        self.assertNotIn("material", raw)


class KeyRingIntegration(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="keys-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.path = os.path.join(self.dir, "key-history.jsonl")
        self.history = KeyHistory(self.path)
        self.history.introduce("k1", _material(b"1"))
        self.ring = KeyRing(self.history)
        self.ring.register("k1", _material(b"1"))

    def test_registered_key_resolves(self):
        self.assertEqual(self.ring.resolver()("k1"), _material(b"1"))

    def test_registering_an_introduced_key_is_enough(self):
        self.history.rotate("k2", _material(b"2"))
        self.ring.register("k2", _material(b"2"))
        self.assertEqual(self.ring.resolver()("k2"), _material(b"2"))

    def test_unregistered_key_resolves_to_none(self):
        self.assertIsNone(self.ring.resolver()("k-ghost"))

    def test_ring_refuses_material_that_does_not_match_the_history(self):
        with self.assertRaises(KeyLifecycleError):
            self.ring.register("k1", _material(b"9"))

    def test_ring_refuses_a_key_absent_from_the_history(self):
        with self.assertRaises(KeyLifecycleError):
            self.ring.register("k-ghost", _material(b"3"))

    def test_revoked_key_stops_resolving(self):
        signed = sign_attestation(_attestation(), key_id="k1", secret=_material(b"1"))
        self.assertEqual(
            verify_signed_attestation(signed, key_resolver=self.ring.resolver()).route_id,
            "route-1",
        )
        self.history.revoke("k1")
        self.assertIsNone(self.ring.resolver()("k1"))
        with self.assertRaises(ProofSignatureError):
            verify_signed_attestation(signed, key_resolver=self.ring.resolver())

    def test_retired_key_still_resolves_for_old_attestations(self):
        self.history.rotate("k2", _material(b"2"))
        signed = sign_attestation(_attestation(), key_id="k1", secret=_material(b"1"))
        self.assertEqual(
            verify_signed_attestation(signed, key_resolver=self.ring.resolver()).route_id,
            "route-1",
        )
        self.assertEqual(self.ring.verdict("k1").state, "trusted-retired")

    def test_ring_refuses_to_resolve_against_a_broken_history(self):
        os.unlink(self.path)
        self.assertIsNone(self.ring.resolver()("k1"))

    def test_ring_verdict_matches_history_verdict(self):
        self.assertEqual(self.ring.verdict("k1").state, "trusted")
        self.assertEqual(self.ring.verdict("k-ghost").state, "unknown-key")


if __name__ == "__main__":
    unittest.main()
