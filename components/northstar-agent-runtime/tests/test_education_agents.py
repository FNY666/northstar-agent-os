"""Tests for education_agents (one-hundred-fifty-first batch)."""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ed25519
from canonical_json import jcs_canonical_json

from education_agents import (
    EducationError,
    EducationVerdict,
    AuthorityRegistry,
    CapabilityLockReceipt,
    CapabilityLockRegistry,
    RetentionScheduleReceipt,
    RetentionScheduleRegistry,
    StagingPolicyReceipt,
    StagingPolicyRegistry,
    ParityProbeReceipt,
    LanguageParityRegistry,
    PseudonymReceipt,
    PseudonymRegistry,
    temporal_capability_lock,
    retention_schedule_mandate,
    evidentiary_tiering,
    ai_proposes_human_disposes_gate,
    developmental_access_staging,
    language_parity_audit,
    pseudonymous_student_mode,
    CLASS_AUTHORITATIVE,
    CLASS_NON_AUTHORITATIVE,
)


SEC = b"\x0b" * 32
PUB = ed25519.public_key(SEC).hex()
T0 = 1_800_000_000
HEX64 = "ab" * 32
HEX64_B = "cd" * 32

WINDOW = 86_400  # one exam day


def _authorities():
    reg = AuthorityRegistry()
    reg.register("edu-op", PUB)
    return reg


def _prev(log):
    return log[-1].receipt_digest if log else "genesis"


def _issue_lock(reg, lock_id="lock-1", capability_id="photo_solve",
                locked_from=T0, locked_until=T0 + WINDOW):
    bare = CapabilityLockReceipt(
        lock_id=lock_id, window_id="gaokao-2026", capability_id=capability_id,
        locked_from=locked_from, locked_until=locked_until,
        authority_id="edu-op", authority_pubkey_hex=PUB,
        signature_hex="00" * 64, prev_digest=_prev(reg.log))
    return reg.issue(
        lock_id=lock_id, window_id="gaokao-2026", capability_id=capability_id,
        locked_from=locked_from, locked_until=locked_until,
        authority_id="edu-op",
        signature=ed25519.sign(SEC, jcs_canonical_json(bare._payload())),
        issued_at=T0)


def _issue_schedule(reg, schedule_id="sched-1", data_category="student_records",
                    retain_until=T0 + WINDOW):
    bare = RetentionScheduleReceipt(
        schedule_id=schedule_id, data_category=data_category,
        retain_until=retain_until, authority_id="edu-op",
        authority_pubkey_hex=PUB, signature_hex="00" * 64,
        prev_digest=_prev(reg.log))
    return reg.issue(
        schedule_id=schedule_id, data_category=data_category,
        retain_until=retain_until, authority_id="edu-op",
        signature=ed25519.sign(SEC, jcs_canonical_json(bare._payload())),
        issued_at=T0)


def _issue_policy(reg, policy_id="pol-1", band="grades_3_8",
                  capability="companion_chatbot", access="deny",
                  exceptions=("special_needs",), sunset_at=T0 + WINDOW):
    bare = StagingPolicyReceipt(
        policy_id=policy_id, band=band, capability=capability, access=access,
        exceptions=exceptions, effective_from=T0, sunset_at=sunset_at,
        authority_id="edu-op", authority_pubkey_hex=PUB,
        signature_hex="00" * 64, prev_digest=_prev(reg.log))
    return reg.issue(
        policy_id=policy_id, band=band, capability=capability, access=access,
        exceptions=exceptions, effective_from=T0, sunset_at=sunset_at,
        authority_id="edu-op",
        signature=ed25519.sign(SEC, jcs_canonical_json(bare._payload())),
        issued_at=T0)


def _issue_probe(reg, probe_id="probe-1", pair_id="kk-ru",
                 language_a="kk", language_b="ru",
                 delta_bps=300, tolerance_bps=500):
    bare = ParityProbeReceipt(
        probe_id=probe_id, pair_id=pair_id, language_a=language_a,
        language_b=language_b, delta_bps=delta_bps,
        tolerance_bps=tolerance_bps, measured_at=T0, authority_id="edu-op",
        authority_pubkey_hex=PUB, signature_hex="00" * 64,
        prev_digest=_prev(reg.log))
    return reg.issue(
        probe_id=probe_id, pair_id=pair_id, language_a=language_a,
        language_b=language_b, delta_bps=delta_bps,
        tolerance_bps=tolerance_bps, measured_at=T0, authority_id="edu-op",
        signature=ed25519.sign(SEC, jcs_canonical_json(bare._payload())),
        issued_at=T0)


def _issue_pseudonym(reg, pseudonym_id="pseudo-1", expires_at=T0 + WINDOW):
    bare = PseudonymReceipt(
        pseudonym_id=pseudonym_id, subject_digest=HEX64, issued_at=T0,
        expires_at=expires_at, authority_id="edu-op",
        authority_pubkey_hex=PUB, signature_hex="00" * 64,
        prev_digest=_prev(reg.log))
    return reg.issue(
        pseudonym_id=pseudonym_id, subject_digest=HEX64, issued_at=T0,
        expires_at=expires_at, authority_id="edu-op",
        signature=ed25519.sign(SEC, jcs_canonical_json(bare._payload())))


class TestTemporalCapabilityLock(unittest.TestCase):
    def test_window_breach_deny(self):
        reg = CapabilityLockRegistry(_authorities())
        _issue_lock(reg)
        v = temporal_capability_lock(reg, "photo_solve", T0 + 3600)
        self.assertFalse(v.allowed)
        self.assertIn("window_breach", v.reason)
        self.assertEqual(v.classification, CLASS_NON_AUTHORITATIVE)

    def test_outside_window_allow(self):
        reg = CapabilityLockRegistry(_authorities())
        _issue_lock(reg)
        v = temporal_capability_lock(reg, "photo_solve", T0 + WINDOW + 1)
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, CLASS_AUTHORITATIVE)

    def test_other_capability_allow(self):
        reg = CapabilityLockRegistry(_authorities())
        _issue_lock(reg)
        v = temporal_capability_lock(reg, "everyday_chat", T0 + 3600)
        self.assertTrue(v.allowed)

    def test_bad_signature_raises(self):
        reg = CapabilityLockRegistry(_authorities())
        with self.assertRaises(EducationError):
            reg.issue(lock_id="x", window_id="w", capability_id="c",
                      locked_from=T0, locked_until=T0 + 1,
                      authority_id="edu-op", signature=b"\x00" * 64,
                      issued_at=T0)

    def test_unknown_authority_raises(self):
        reg = CapabilityLockRegistry(AuthorityRegistry())
        with self.assertRaises(EducationError):
            reg.issue(lock_id="x", window_id="w", capability_id="c",
                      locked_from=T0, locked_until=T0 + 1,
                      authority_id="ghost", signature=b"\x00" * 64,
                      issued_at=T0)


class TestRetentionSchedule(unittest.TestCase):
    def test_overdue_deny(self):
        reg = RetentionScheduleRegistry(_authorities())
        _issue_schedule(reg, retain_until=T0 + 100)
        v = retention_schedule_mandate(reg, "sched-1", T0 + 101)
        self.assertFalse(v.allowed)
        self.assertIn("retention_overdue", v.reason)

    def test_live_schedule_allow(self):
        reg = RetentionScheduleRegistry(_authorities())
        _issue_schedule(reg, retain_until=T0 + WINDOW)
        v = retention_schedule_mandate(reg, "sched-1", T0 + 10)
        self.assertTrue(v.allowed)
        self.assertTrue(v.receipt_digest)

    def test_no_schedule_deny(self):
        reg = RetentionScheduleRegistry(_authorities())
        v = retention_schedule_mandate(reg, "ghost-sched", T0)
        self.assertFalse(v.allowed)
        self.assertIn("no_retention_schedule", v.reason)


class TestEvidentiaryTiering(unittest.TestCase):
    def test_signal_allow(self):
        v = evidentiary_tiering("det-1", "signal", False)
        self.assertTrue(v.allowed)

    def test_evidence_without_review_deny(self):
        v = evidentiary_tiering("det-1", "evidence", False)
        self.assertFalse(v.allowed)
        self.assertIn("tier_escalation", v.reason)

    def test_evidence_with_review_allow(self):
        v = evidentiary_tiering("det-1", "evidence", True)
        self.assertTrue(v.allowed)

    def test_unknown_tier_raises(self):
        with self.assertRaises(EducationError):
            evidentiary_tiering("det-1", "proof", False)


class TestAIProposesHumanDisposes(unittest.TestCase):
    def test_ai_decided_grading_deny(self):
        v = ai_proposes_human_disposes_gate("d-1", "grading", "decide", False)
        self.assertFalse(v.allowed)
        self.assertIn("ai_decided", v.reason)

    def test_ai_decided_admissions_deny(self):
        v = ai_proposes_human_disposes_gate("d-2", "admissions", "decide", False)
        self.assertFalse(v.allowed)
        self.assertIn("ai_decided", v.reason)

    def test_flag_plus_human_allow(self):
        v = ai_proposes_human_disposes_gate("d-3", "grading", "flag", True)
        self.assertTrue(v.allowed)

    def test_ai_decide_non_evaluative_allow(self):
        v = ai_proposes_human_disposes_gate("d-4", "room_scheduling", "decide", False)
        self.assertTrue(v.allowed)

    def test_bad_role_raises(self):
        with self.assertRaises(EducationError):
            ai_proposes_human_disposes_gate("d-5", "grading", "oracle", False)


class TestDevelopmentalStaging(unittest.TestCase):
    def test_deny_band_no_exception(self):
        reg = StagingPolicyRegistry(_authorities())
        _issue_policy(reg)
        v = developmental_access_staging(reg, "grades_3_8", "companion_chatbot",
                                         T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("developmental_ban", v.reason)

    def test_deny_band_with_exception_allow(self):
        reg = StagingPolicyRegistry(_authorities())
        _issue_policy(reg)
        v = developmental_access_staging(reg, "grades_3_8", "companion_chatbot",
                                         T0 + 10, exception="special_needs")
        self.assertTrue(v.allowed)

    def test_no_policy_deny(self):
        reg = StagingPolicyRegistry(_authorities())
        v = developmental_access_staging(reg, "pre_k_2", "tutor_bot", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("no_staging_policy", v.reason)

    def test_sunset_policy_deny(self):
        reg = StagingPolicyRegistry(_authorities())
        _issue_policy(reg, sunset_at=T0 + 100)
        v = developmental_access_staging(reg, "grades_3_8", "companion_chatbot",
                                         T0 + 101)
        self.assertFalse(v.allowed)
        self.assertIn("stale_staging_policy", v.reason)

    def test_bad_band_raises(self):
        reg = StagingPolicyRegistry(_authorities())
        with self.assertRaises(EducationError):
            developmental_access_staging(reg, "college", "tutor_bot", T0)


class TestLanguageParity(unittest.TestCase):
    def test_gap_deny(self):
        reg = LanguageParityRegistry(_authorities())
        _issue_probe(reg, delta_bps=900, tolerance_bps=500)
        v = language_parity_audit(reg, "kk-ru", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("language_parity_gap", v.reason)

    def test_within_tolerance_allow(self):
        reg = LanguageParityRegistry(_authorities())
        _issue_probe(reg, delta_bps=300, tolerance_bps=500)
        v = language_parity_audit(reg, "kk-ru", T0 + 10)
        self.assertTrue(v.allowed)

    def test_no_probe_deny(self):
        reg = LanguageParityRegistry(_authorities())
        v = language_parity_audit(reg, "kk-ru", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("no_parity_probe", v.reason)


class TestPseudonymousMode(unittest.TestCase):
    def test_pii_without_pseudonym_deny(self):
        reg = PseudonymRegistry(_authorities())
        v = pseudonymous_student_mode(reg, "ghost-pseudo", True, T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("pii_without_pseudonym", v.reason)

    def test_pii_with_live_pseudonym_allow(self):
        reg = PseudonymRegistry(_authorities())
        _issue_pseudonym(reg)
        v = pseudonymous_student_mode(reg, "pseudo-1", True, T0 + 10)
        self.assertTrue(v.allowed)

    def test_no_pii_allow(self):
        reg = PseudonymRegistry(_authorities())
        v = pseudonymous_student_mode(reg, "unused", False, T0 + 10)
        self.assertTrue(v.allowed)

    def test_expired_pseudonym_deny(self):
        reg = PseudonymRegistry(_authorities())
        _issue_pseudonym(reg, expires_at=T0 + 100)
        v = pseudonymous_student_mode(reg, "pseudo-1", True, T0 + 101)
        self.assertFalse(v.allowed)
        self.assertIn("pseudonym_expired", v.reason)


class TestChainIntegrity(unittest.TestCase):
    def test_tampered_log_denies(self):
        reg = CapabilityLockRegistry(_authorities())
        _issue_lock(reg)
        # Tamper: swap in a receipt with a recomputed-but-unsigned chain link.
        bad = CapabilityLockReceipt(
            lock_id="lock-1", window_id="gaokao-2026",
            capability_id="photo_solve", locked_from=T0,
            locked_until=T0 + WINDOW, authority_id="edu-op",
            authority_pubkey_hex=PUB, signature_hex="00" * 128,
            prev_digest="genesis")
        reg.log[0] = bad
        v = temporal_capability_lock(reg, "photo_solve", T0 + WINDOW + 1)
        self.assertFalse(v.allowed)
        self.assertIn("chain_broken", v.reason)

    def test_verdict_shape(self):
        reg = RetentionScheduleRegistry(_authorities())
        v = retention_schedule_mandate(reg, "ghost", T0)
        self.assertIsInstance(v, EducationVerdict)
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, CLASS_NON_AUTHORITATIVE)


if __name__ == "__main__":
    unittest.main()
