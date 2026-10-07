"""Tests for memory_admission.py: consent-gated memory write admission."""

from __future__ import annotations

import unittest

from memory_admission import (
    ADMITTABLE_CATEGORIES,
    KNOWN_CATEGORIES,
    PROHIBITED_INFERENCES,
    AdmissionDecision,
    MemoryAdmission,
    MemoryAdmissionError,
    MemoryConsent,
    check_retention,
)


def _grant(**kwargs):
    base = {"scope": ("preference", "fact", "conversation"), "retention_days": 30, "granted_at": 100}
    base.update(kwargs)
    return MemoryConsent(**base)


class CheckRetentionTests(unittest.TestCase):
    def test_not_expired_within_window(self):
        self.assertFalse(check_retention(100, 30, 129))

    def test_expired_at_exact_boundary(self):
        # granted_at + retention_days == current_seq is expired.
        self.assertTrue(check_retention(100, 30, 130))

    def test_expired_after_window(self):
        self.assertTrue(check_retention(100, 30, 500))

    def test_future_grant_is_expired_fail_closed(self):
        self.assertTrue(check_retention(200, 30, 100))

    def test_malformed_inputs_raise(self):
        with self.assertRaises(MemoryAdmissionError):
            check_retention(-1, 30, 100)
        with self.assertRaises(MemoryAdmissionError):
            check_retention(100, 0, 100)
        with self.assertRaises(MemoryAdmissionError):
            check_retention(100, 30, True)


class MemoryConsentTests(unittest.TestCase):
    def test_construction_ok(self):
        c = _grant()
        self.assertEqual(c.scope, ("preference", "fact", "conversation"))
        self.assertFalse(c.revoked)

    def test_scope_cannot_cover_credential(self):
        with self.assertRaises(MemoryAdmissionError):
            _grant(scope=("credential",))

    def test_scope_cannot_cover_prohibited_inferences(self):
        for bad in PROHIBITED_INFERENCES:
            with self.assertRaises(MemoryAdmissionError):
                _grant(scope=(bad,))

    def test_scope_rejects_unknown_category(self):
        with self.assertRaises(MemoryAdmissionError):
            _grant(scope=("mood",))

    def test_non_positive_retention_rejected(self):
        with self.assertRaises(MemoryAdmissionError):
            _grant(retention_days=0)
        with self.assertRaises(MemoryAdmissionError):
            _grant(retention_days=-5)

    def test_revoke_returns_revoked_copy(self):
        c = _grant()
        r = c.revoke()
        self.assertTrue(r.revoked)
        self.assertFalse(c.revoked)  # original untouched (frozen)

    def test_expired_predicate(self):
        c = _grant()
        self.assertFalse(c.expired(110))
        self.assertTrue(c.expired(200))

    def test_as_dict_schema_pin(self):
        d = _grant().as_dict()
        self.assertEqual(d["schema"], "northstar.memory-consent.v1")


class AdmitWriteTests(unittest.TestCase):
    def test_admit_preference_fact_conversation(self):
        gate = MemoryAdmission(_grant())
        for category in ADMITTABLE_CATEGORIES:
            self.assertTrue(
                gate.admit_write(category, "some content", current_seq=110),
                category,
            )

    def test_credential_always_denied(self):
        gate = MemoryAdmission(_grant())
        self.assertFalse(gate.admit_write("credential", "api-key", current_seq=110))
        self.assertEqual(gate.denied()[-1].reason, "credential-never-admitted")

    def test_prohibited_inferences_denied(self):
        gate = MemoryAdmission(_grant())
        for bad in PROHIBITED_INFERENCES:
            self.assertFalse(gate.admit_write(bad, "content", current_seq=110), bad)
            self.assertEqual(gate.denied()[-1].reason, "prohibited-inference")

    def test_no_consent_denied(self):
        gate = MemoryAdmission()
        self.assertFalse(gate.admit_write("fact", "content", current_seq=110))
        self.assertEqual(gate.denied()[-1].reason, "no-consent")

    def test_revoked_consent_denied(self):
        gate = MemoryAdmission(_grant().revoke())
        self.assertFalse(gate.admit_write("fact", "content", current_seq=110))
        self.assertEqual(gate.denied()[-1].reason, "consent-revoked")

    def test_expired_consent_denied(self):
        gate = MemoryAdmission(_grant())
        self.assertFalse(gate.admit_write("fact", "content", current_seq=500))
        self.assertEqual(gate.denied()[-1].reason, "consent-expired")

    def test_outside_scope_denied(self):
        gate = MemoryAdmission(_grant(scope=("fact",)))
        self.assertFalse(gate.admit_write("preference", "content", current_seq=110))
        self.assertEqual(gate.denied()[-1].reason, "outside-consent-scope")
        # but the in-scope category still passes
        self.assertTrue(gate.admit_write("fact", "content", current_seq=110))

    def test_unknown_category_denied(self):
        gate = MemoryAdmission(_grant())
        self.assertFalse(gate.admit_write("mood", "content", current_seq=110))
        self.assertEqual(gate.denied()[-1].reason, "unknown-category")

    def test_malformed_category_denied(self):
        gate = MemoryAdmission(_grant())
        for bad in ("", "   ", None, 42):
            self.assertFalse(gate.admit_write(bad, "content", current_seq=110))

    def test_malformed_content_denied(self):
        gate = MemoryAdmission(_grant())
        for bad in ("", "   ", None, 123):
            self.assertFalse(
                gate.admit_write("fact", bad, current_seq=110),
                repr(bad),
            )
        self.assertEqual(gate.denied()[-1].reason, "malformed-content")

    def test_retention_unverifiable_denied_fail_closed(self):
        gate = MemoryAdmission(_grant())
        for bad_seq in (None, "110", True, -1):
            self.assertFalse(
                gate.admit_write("fact", "content", current_seq=bad_seq),
                repr(bad_seq),
            )
        self.assertEqual(gate.denied()[-1].reason, "retention-unverifiable")

    def test_explicit_consent_beats_default(self):
        gate = MemoryAdmission(_grant(scope=("fact",)))
        narrow = _grant(scope=("preference",))
        # explicit consent wins: preference admitted though default lacks it
        self.assertTrue(
            gate.admit_write("preference", "content", consent=narrow, current_seq=110)
        )
        # and the default still denies preference without the explicit grant
        self.assertFalse(gate.admit_write("preference", "content", current_seq=110))

    def test_malformed_consent_object_denied(self):
        gate = MemoryAdmission()
        self.assertFalse(
            gate.admit_write("fact", "content", consent="not-a-consent", current_seq=110)
        )
        self.assertEqual(gate.denied()[-1].reason, "malformed-consent")

    def test_rule_order_credential_before_consent(self):
        # credential is denied even when there is no consent at all --
        # the hard rule fires before the consent rules.
        gate = MemoryAdmission()
        self.assertFalse(gate.admit_write("credential", "x", current_seq=110))
        self.assertEqual(gate.denied()[-1].reason, "credential-never-admitted")

    def test_decision_log_records_everything(self):
        gate = MemoryAdmission(_grant())
        gate.admit_write("fact", "ok", current_seq=110)
        gate.admit_write("health", "nope", current_seq=110)
        decisions = gate.decisions()
        self.assertEqual(len(decisions), 2)
        self.assertTrue(decisions[0].allowed)
        self.assertEqual(decisions[0].reason, "admitted")
        self.assertFalse(decisions[1].allowed)
        self.assertIsInstance(decisions[0], AdmissionDecision)


class RevocationTests(unittest.TestCase):
    def test_revoke_consent_blocks_later_writes(self):
        gate = MemoryAdmission(_grant())
        self.assertTrue(gate.admit_write("fact", "before", current_seq=110))
        revoked = gate.revoke_consent()
        self.assertTrue(revoked.revoked)
        self.assertFalse(gate.admit_write("fact", "after", current_seq=110))
        self.assertEqual(gate.denied()[-1].reason, "consent-revoked")

    def test_revoke_with_no_consent_returns_none(self):
        gate = MemoryAdmission()
        self.assertIsNone(gate.revoke_consent())

    def test_set_consent_replaces_default(self):
        gate = MemoryAdmission()
        gate.set_consent(_grant(scope=("conversation",)))
        self.assertTrue(gate.admit_write("conversation", "hi", current_seq=110))
        self.assertFalse(gate.admit_write("fact", "hi", current_seq=110))

    def test_constructor_rejects_non_consent(self):
        with self.assertRaises(MemoryAdmissionError):
            MemoryAdmission(consent="bogus")


class VocabularyTests(unittest.TestCase):
    def test_known_categories_cover_admittable_plus_hard_denies(self):
        for c in ADMITTABLE_CATEGORIES:
            self.assertIn(c, KNOWN_CATEGORIES)
        self.assertIn("credential", KNOWN_CATEGORIES)
        for p in PROHIBITED_INFERENCES:
            self.assertIn(p, KNOWN_CATEGORIES)

    def test_main_runs(self):
        import memory_admission

        memory_admission.main()  # smoke: prints the demo matrix, asserts nothing


if __name__ == "__main__":
    unittest.main()
