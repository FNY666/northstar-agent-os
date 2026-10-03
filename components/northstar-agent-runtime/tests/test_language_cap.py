"""Tests for language_cap.py (one-hundred-fourteenth batch).

Deterministic: fixed 32-byte seeds, injected integer timestamps.
"""
import dataclasses
import unittest

import ed25519
from canonical_json import jcs_canonical_json, jcs_sha256_hex

from language_cap import (
    ACCURACY_BANDS,
    CLASS_AUTHORITATIVE,
    CLASS_FLUENT_UNVERIFIED,
    CLASS_NON_AUTHORITATIVE,
    CLASS_UNVERIFIABLE,
    DENY_CHAIN_BROKEN,
    DENY_COMMUNITY_EXPIRED,
    DENY_COMMUNITY_NO_GRANT,
    DENY_COMMUNITY_PURPOSE,
    DENY_COMMUNITY_REVOKED,
    DENY_LOCALE_MISMATCH,
    DENY_NO_RECEIPT,
    DENY_RECEIPT_EXPIRED,
    FLUENCY_BANDS,
    MISTRANSLATION_HARM_EVENT,
    PROBE_FAIL,
    PROBE_PASS,
    UNMEASURED_DIGEST,
    LanguageCapError,
    alignment_probe,
    check_community_use,
    check_language_servable,
    check_output_gate,
    compute_receipt_digest,
    grant_community_data,
    issue_capability_receipt,
    mistranslation_audit_event,
    restrict_accuracy_band,
    revoke_community_data,
    serve_audit_event,
)


AUTH_SECRET = b"lang-auth-seed-00000000000000001"
OTHER_SECRET = b"lang-auth-seed-00000000000000002"
COMMUNITY_SECRET = b"lang-comm-seed-00000000000000001"

T0 = 1_800_000_000  # fixed "now" for tests
MODEL = "ab" * 32
BENCH = "cd" * 32


def _receipt(tag="en", variant="us", band="high", fluency="fluent",
             secret=AUTH_SECRET, prev="genesis", measured_at=T0,
             expires_at=T0 + 10_000, bench=BENCH):
    return issue_capability_receipt(
        receipt_id=f"r-{tag}-{variant}-{band}",
        model_digest=MODEL,
        language_tag=tag,
        locale_variant=variant,
        accuracy_band=band,
        fluency_band=fluency,
        measured_on_benchmark_digest=(
            UNMEASURED_DIGEST if band == "unmeasured" else bench
        ),
        authority_secret=secret,
        issued_by="lang-board",
        measured_at=measured_at,
        expires_at=expires_at,
        prev_digest=prev,
    )


class IssueTests(unittest.TestCase):
    def test_happy_path_seals(self):
        r = _receipt()
        self.assertEqual(compute_receipt_digest(r), r.receipt_digest)
        self.assertEqual(len(r.signature_hex), 128)
        self.assertEqual(r.authority_pubkey_hex, ed25519.public_key(AUTH_SECRET).hex())

    def test_unmeasured_must_pin_zero_marker(self):
        with self.assertRaises(LanguageCapError):
            issue_capability_receipt(
                receipt_id="r-x", model_digest=MODEL,
                language_tag="en", locale_variant="us",
                accuracy_band="unmeasured", fluency_band="unknown",
                measured_on_benchmark_digest=BENCH,
                authority_secret=AUTH_SECRET, issued_by="lang-board",
                measured_at=T0, expires_at=T0 + 10_000,
            )

    def test_unmeasured_with_marker_ok(self):
        r = _receipt(band="unmeasured")
        self.assertEqual(r.measured_on_benchmark_digest, UNMEASURED_DIGEST)

    def test_measured_band_may_not_use_zero_marker(self):
        with self.assertRaises(LanguageCapError):
            _receipt(band="moderate", bench=UNMEASURED_DIGEST)

    def test_unknown_band_rejected(self):
        with self.assertRaises(LanguageCapError):
            _receipt(band="stellar")

    def test_expiry_must_follow_measurement(self):
        with self.assertRaises(LanguageCapError):
            _receipt(measured_at=T0, expires_at=T0)


class ServeTests(unittest.TestCase):
    def test_exact_triple_servable(self):
        r = _receipt(tag="sw", variant="ke")
        v = check_language_servable([r], model_digest=MODEL,
                                    language_tag="sw", locale_variant="ke",
                                    check_time=T0 + 1)
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, CLASS_AUTHORITATIVE)

    def test_undeclared_language_unverifiable(self):
        r = _receipt(tag="en", variant="us")
        v = check_language_servable([r], model_digest=MODEL,
                                    language_tag="yo", locale_variant="ng",
                                    check_time=T0 + 1)
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, CLASS_UNVERIFIABLE)
        self.assertIn(DENY_NO_RECEIPT, v.reason)

    def test_locale_variant_distinct_pt_vs_ptbr(self):
        r = _receipt(tag="pt", variant="pt")
        v = check_language_servable([r], model_digest=MODEL,
                                    language_tag="pt", locale_variant="br",
                                    check_time=T0 + 1)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_LOCALE_MISMATCH, v.reason)

    def test_expired_receipt_denies(self):
        r = _receipt(expires_at=T0 + 5)
        v = check_language_servable([r], model_digest=MODEL,
                                    language_tag="en", locale_variant="us",
                                    check_time=T0 + 100)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_RECEIPT_EXPIRED, v.reason)

    def test_tampered_chain_denies_everything(self):
        r1 = _receipt(tag="en", variant="us")
        r2 = _receipt(tag="fr", variant="fr", prev=r1.receipt_digest)
        bad = dataclasses.replace(r2, accuracy_band="high",
                                  fluency_band="unknown")
        v = check_language_servable([r1, bad], model_digest=MODEL,
                                    language_tag="en", locale_variant="us",
                                    check_time=T0 + 1)
        self.assertFalse(v.allowed)


class OutputGateTests(unittest.TestCase):
    def test_medical_low_band_non_authoritative_mandatory_review(self):
        r = _receipt(tag="fa", variant="ir", band="low", fluency="degraded")
        v = check_output_gate([r], model_digest=MODEL, language_tag="fa",
                              locale_variant="ir", domain="medical",
                              check_time=T0 + 1)
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, CLASS_NON_AUTHORITATIVE)
        self.assertTrue(v.mandatory_human_review)
        self.assertTrue(v.mistranslation_harm_event)
        ev = mistranslation_audit_event(v, action="medical-summary")
        self.assertEqual(ev["event"], MISTRANSLATION_HARM_EVENT)

    def test_fluency_trap_flagged(self):
        # fluent surface, low accuracy, medical domain -> fluent_unverified
        r = _receipt(tag="kk", variant="kz", band="low", fluency="fluent")
        v = check_output_gate([r], model_digest=MODEL, language_tag="kk",
                              locale_variant="kz", domain="medical",
                              check_time=T0 + 1)
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, CLASS_FLUENT_UNVERIFIED)
        self.assertTrue(v.mandatory_human_review)

    def test_unmeasured_legal_gated(self):
        r = _receipt(tag="hy", variant="am", band="unmeasured",
                     fluency="unknown")
        v = check_output_gate([r], model_digest=MODEL, language_tag="hy",
                              locale_variant="am", domain="legal",
                              check_time=T0 + 1)
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, CLASS_NON_AUTHORITATIVE)

    def test_general_domain_low_band_allows(self):
        r = _receipt(tag="fa", variant="ir", band="low", fluency="degraded")
        v = check_output_gate([r], model_digest=MODEL, language_tag="fa",
                              locale_variant="ir", domain="general",
                              check_time=T0 + 1)
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, CLASS_AUTHORITATIVE)

    def test_high_band_medical_authoritative(self):
        r = _receipt(tag="en", variant="us", band="high")
        v = check_output_gate([r], model_digest=MODEL, language_tag="en",
                              locale_variant="us", domain="medical",
                              check_time=T0 + 1)
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, CLASS_AUTHORITATIVE)

    def test_unservable_output_is_unverifiable(self):
        r = _receipt(tag="en", variant="us")
        v = check_output_gate([r], model_digest=MODEL, language_tag="bm",
                              locale_variant="ml", domain="medical",
                              check_time=T0 + 1)
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, CLASS_UNVERIFIABLE)


class AmendAndProbeTests(unittest.TestCase):
    def test_narrow_only_amendment(self):
        r = _receipt(tag="hi", variant="in", band="high")
        log = [r]
        r2 = restrict_accuracy_band(
            log, model_digest=MODEL, language_tag="hi", locale_variant="in",
            new_band="moderate", authority_secret=AUTH_SECRET,
            issued_by="lang-board", issued_at=T0 + 10, expires_at=T0 + 10_000,
        )
        log.append(r2)
        v = check_language_servable(log, model_digest=MODEL,
                                    language_tag="hi", locale_variant="in",
                                    check_time=T0 + 20)
        self.assertTrue(v.allowed)
        self.assertEqual(v.receipt_digest, r2.receipt_digest)

    def test_widening_via_amendment_rejected(self):
        r = _receipt(tag="hi", variant="in", band="low")
        with self.assertRaises(LanguageCapError):
            restrict_accuracy_band(
                [r], model_digest=MODEL, language_tag="hi",
                locale_variant="in", new_band="high",
                authority_secret=AUTH_SECRET, issued_by="lang-board",
                issued_at=T0 + 10, expires_at=T0 + 10_000,
            )

    def test_alignment_probe_downgrades_failures(self):
        r_en = _receipt(tag="en", variant="us", band="high")
        r_hi = _receipt(tag="hi", variant="in", band="high",
                        prev=r_en.receipt_digest)
        log = [r_en, r_hi]

        def probe(tag, variant):
            return tag != "hi"  # hindi rendering fails the safety test

        results = alignment_probe(log, model_digest=MODEL, probe_fn=probe,
                                  check_time=T0 + 1)
        self.assertEqual(results["en/us"], PROBE_PASS)
        self.assertEqual(results["hi/in"], PROBE_FAIL)


class CommunityTests(unittest.TestCase):
    def _grant(self, prev="genesis", purpose="nlp-research",
               scope="ngalia-corpus", granted_at=T0,
               expires_at=T0 + 10_000):
        return grant_community_data(
            grant_id="g-ngalia-1", community_id="kiwa-ngalia",
            data_scope=scope, purpose=purpose,
            community_secret=COMMUNITY_SECRET,
            granted_at=granted_at, expires_at=expires_at, prev_digest=prev,
        )

    def test_consented_use_allows(self):
        g = self._grant()
        v = check_community_use(g, [g], data_scope="ngalia-corpus",
                                purpose="nlp-research", use_time=T0 + 1)
        self.assertTrue(v.allowed)

    def test_use_without_grant_in_log_denies(self):
        g = self._grant()
        v = check_community_use(g, [], data_scope="ngalia-corpus",
                                purpose="nlp-research", use_time=T0 + 1)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_COMMUNITY_NO_GRANT, v.reason)

    def test_revocation_is_immediate(self):
        g = self._grant()
        rev = revoke_community_data(grant=g, community_secret=COMMUNITY_SECRET,
                                    revoked_at=T0 + 5,
                                    prev_digest=g.grant_digest)
        log = [g, rev]
        v = check_community_use(g, log, data_scope="ngalia-corpus",
                                purpose="nlp-research", use_time=T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_COMMUNITY_REVOKED, v.reason)

    def test_wrong_community_key_cannot_revoke(self):
        g = self._grant()
        with self.assertRaises(LanguageCapError):
            revoke_community_data(grant=g, community_secret=OTHER_SECRET,
                                  revoked_at=T0 + 5,
                                  prev_digest=g.grant_digest)

    def test_purpose_mismatch_denies(self):
        g = self._grant()
        v = check_community_use(g, [g], data_scope="ngalia-corpus",
                                purpose="ad-targeting", use_time=T0 + 1)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_COMMUNITY_PURPOSE, v.reason)


if __name__ == "__main__":
    unittest.main()
