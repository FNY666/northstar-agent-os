"""Tests for memory_combo.MemoryGate.

Integration tests over the four memory modules on github/main:
consent admission OR capability admission, fact/belief typing,
bitemporal storage, privilege-at-recall.
"""

import hashlib
import unittest

import ed25519

import memory_admission as consent_mod
import memory_bitemporal as bitemporal_mod
import memory_capability as cap_mod
import memory_combo as combo_mod
import memory_fact_belief as fb_mod


def _consent(**kw):
    base = dict(scope=("preference", "fact"), retention_days=30, granted_at=100)
    base.update(kw)
    return consent_mod.MemoryConsent(**base)


def _cap_issuer():
    seed = hashlib.sha256(b"memory-combo test issuer").digest()
    return seed, ed25519.public_key(seed)


def _cap_gate(categories=("preference", "fact"), expires_seq=200):
    seed, pub = _cap_issuer()
    token = cap_mod.issue_token(set(categories), expires_seq, seed)
    return cap_mod.CapabilityAdmission(pub), token


def _gate_both():
    seed, pub = _cap_issuer()
    return (
        combo_mod.MemoryGate(
            consent_admission=consent_mod.MemoryAdmission(),
            capability_admission=cap_mod.CapabilityAdmission(pub),
        ),
        seed,
    )


class TestVersion(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(combo_mod.MEMORY_COMBO_VERSION, "memory-combo.v1")
        self.assertEqual(combo_mod.SCHEMA_PIN, "northstar.memory-combo.v1")


class TestGateConstruction(unittest.TestCase):
    def test_requires_at_least_one_gate(self):
        with self.assertRaises(combo_mod.ComboError):
            combo_mod.MemoryGate()

    def test_consent_only_ok(self):
        gate = combo_mod.MemoryGate(
            consent_admission=consent_mod.MemoryAdmission()
        )
        self.assertEqual(len(gate), 0)


class TestWriteAdmission(unittest.TestCase):
    def test_write_consent_admitted(self):
        gate, _ = _gate_both()
        rec = gate.write("likes tea", "preference", _consent(), 110)
        self.assertIsNotNone(rec)
        self.assertEqual(gate.decisions()[-1].reason,
                         combo_mod.REASON_WRITE_ADMITTED_CONSENT)

    def test_write_capability_admitted(self):
        gate, seed = _gate_both()
        _, token = _cap_gate()
        rec = gate.write("shipped v2", "fact", token, 110)
        self.assertIsNotNone(rec)
        self.assertEqual(gate.decisions()[-1].reason,
                         combo_mod.REASON_WRITE_ADMITTED_CAPABILITY)

    def test_write_credential_denied(self):
        gate, _ = _gate_both()
        rec = gate.write("sk-secret", "credential", _consent(), 110)
        self.assertIsNone(rec)
        self.assertIn(gate.decisions()[-1], gate.denied())

    def test_write_prohibited_inference_denied(self):
        gate, _ = _gate_both()
        _, token = _cap_gate()
        self.assertIsNone(gate.write("seems anxious", "health", _consent(), 110))
        self.assertIsNone(gate.write("seems anxious", "health", token, 110))

    def test_write_no_matching_gate(self):
        # Consent auth presented, but only the capability gate is configured.
        _, pub = _cap_issuer()
        gate = combo_mod.MemoryGate(
            capability_admission=cap_mod.CapabilityAdmission(pub)
        )
        rec = gate.write("likes tea", "preference", _consent(), 110)
        self.assertIsNone(rec)
        self.assertEqual(gate.decisions()[-1].reason,
                         combo_mod.REASON_WRITE_DENIED_NO_CONSENT_GATE)

    def test_write_expired_consent_denied(self):
        gate, _ = _gate_both()
        rec = gate.write("likes tea", "preference", _consent(), 131)
        self.assertIsNone(rec)
        self.assertEqual(gate.decisions()[-1].reason,
                         combo_mod.REASON_WRITE_DENIED_CONSENT)

    def test_write_token_wrong_category_denied(self):
        gate, _ = _gate_both()
        _, token = _cap_gate(categories=("fact",))
        rec = gate.write("likes tea", "preference", token, 110)
        self.assertIsNone(rec)
        self.assertEqual(gate.decisions()[-1].reason,
                         combo_mod.REASON_WRITE_DENIED_CAPABILITY)

    def test_write_malformed_auth_denied(self):
        gate, _ = _gate_both()
        rec = gate.write("likes tea", "preference", {"fake": "auth"}, 110)
        self.assertIsNone(rec)
        self.assertEqual(gate.decisions()[-1].reason,
                         combo_mod.REASON_WRITE_DENIED_MALFORMED_AUTH)

    def test_write_fact_bad_confidence_denied(self):
        gate, _ = _gate_both()
        rec = gate.write(
            "maybe true", "fact", _consent(), 110,
            mem_type=fb_mod.MemoryType.FACT, confidence=0.5,
        )
        self.assertIsNone(rec)
        self.assertEqual(gate.decisions()[-1].reason,
                         combo_mod.REASON_WRITE_DENIED_FACT_BELIEF)

    def test_write_stores_record(self):
        gate, _ = _gate_both()
        rec = gate.write("likes tea", "preference", _consent(), 110)
        self.assertIsNotNone(rec)
        self.assertEqual(len(gate), 1)
        stored = gate._store.get(rec.id)
        self.assertEqual(stored.content, "likes tea")


class TestOrSemantics(unittest.TestCase):
    def test_capability_admits_when_consent_revoked(self):
        gate, _ = _gate_both()
        revoked = _consent().revoke()
        self.assertIsNone(gate.write("likes tea", "preference", revoked, 110))
        _, token = _cap_gate()
        rec = gate.write("likes tea", "preference", token, 110)
        self.assertIsNotNone(rec)


class TestRead(unittest.TestCase):
    def _write_private_fact(self):
        gate, _ = _gate_both()
        rec = gate.write("likes tea", "preference", _consent(), 110)
        self.assertIsNotNone(rec)
        return gate, rec

    def test_read_allowed_sufficient_privilege(self):
        gate, rec = self._write_private_fact()
        out = gate.read(rec.id, fb_mod.PrivilegeLevel.PRIVATE, 120)
        self.assertIsNotNone(out)
        self.assertEqual(out.id, rec.id)
        self.assertEqual(gate.decisions()[-1].reason,
                         combo_mod.REASON_READ_ALLOWED)

    def test_read_denied_insufficient_privilege(self):
        gate, rec = self._write_private_fact()
        out = gate.read(rec.id, fb_mod.PrivilegeLevel.PUBLIC, 120)
        self.assertIsNone(out)
        self.assertEqual(gate.decisions()[-1].reason,
                         combo_mod.REASON_READ_DENIED_PRIVILEGE)

    def test_read_denied_belief_below_threshold(self):
        gate, _ = _gate_both()
        rec = gate.write(
            "maybe likes tea", "preference", _consent(), 110,
            mem_type=fb_mod.MemoryType.BELIEF, confidence=0.5,
            privilege=fb_mod.PrivilegeLevel.PUBLIC,
        )
        self.assertIsNotNone(rec)  # admitted at write; recall refuses
        out = gate.read(rec.id, fb_mod.PrivilegeLevel.SECRET, 120)
        self.assertIsNone(out)
        self.assertEqual(gate.decisions()[-1].reason,
                         combo_mod.REASON_READ_DENIED_BELIEF_THRESHOLD)

    def test_read_belief_above_threshold_allowed(self):
        gate, _ = _gate_both()
        rec = gate.write(
            "probably likes tea", "preference", _consent(), 110,
            mem_type=fb_mod.MemoryType.BELIEF, confidence=0.9,
            privilege=fb_mod.PrivilegeLevel.PUBLIC,
        )
        out = gate.read(rec.id, fb_mod.PrivilegeLevel.PUBLIC, 120)
        self.assertIsNotNone(out)

    def test_read_unknown_id_none(self):
        gate, _ = _gate_both()
        out = gate.read("mem-nope", fb_mod.PrivilegeLevel.SECRET, 120)
        self.assertIsNone(out)
        self.assertEqual(gate.decisions()[-1].reason,
                         combo_mod.REASON_READ_DENIED_UNKNOWN)

    def test_read_malformed_privilege_none(self):
        gate, rec = self._write_private_fact()
        out = gate.read(rec.id, "PRIVATE", 120)
        self.assertIsNone(out)
        self.assertEqual(gate.decisions()[-1].reason,
                         combo_mod.REASON_READ_MALFORMED)

    def test_read_refreshes_decay_clock(self):
        gate, rec = self._write_private_fact()
        before = gate._store.get(rec.id).last_accessed_seq
        gate.read(rec.id, fb_mod.PrivilegeLevel.PRIVATE, 150)
        after = gate._store.get(rec.id).last_accessed_seq
        self.assertGreaterEqual(after, before)
        self.assertEqual(after, 150)


class TestDecisionLog(unittest.TestCase):
    def test_decisions_recorded_and_denied_filters(self):
        gate, _ = _gate_both()
        gate.write("likes tea", "preference", _consent(), 110)
        gate.write("sk-x", "credential", _consent(), 110)
        decisions = gate.decisions()
        self.assertEqual(len(decisions), 2)
        self.assertTrue(decisions[0].allowed)
        self.assertFalse(decisions[1].allowed)
        denied = gate.denied()
        self.assertEqual(len(denied), 1)
        self.assertEqual(denied[0].action, "write")


if __name__ == "__main__":
    unittest.main()
