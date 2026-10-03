"""Tests for healthcare_agents (one-hundred-fifty-second batch)."""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ed25519
from canonical_json import jcs_canonical_json

from healthcare_agents import (
    HealthcareError,
    HealthcareVerdict,
    AuthorityRegistry,
    CalibrationRegistry,
    ResponsibilityRegistry,
    BiasVignetteRegistry,
    DenialEvidenceRegistry,
    TriageSafetyRegistry,
    UsageNoticeRegistry,
    DissentAckRegistry,
    ConsistencyRegistry,
    MaturityRegistry,
    SurveillanceRegistry,
    _verify_signature,
    alert_burden_ledger,
    responsibility_manifest,
    bias_vignette_regression,
    denial_evidence_provenance,
    triage_ordering_ban,
    ai_usage_notice,
    adversarial_dissent_protocol,
    consistency_uncertainty_signal,
    maturity_mapping,
    postmarket_surveillance,
    CLASS_AUTHORITATIVE,
    CLASS_NON_AUTHORITATIVE,
    CLASS_ALERT_SILENCED,
    CLASS_NON_COMPLIANT,
)


SEC = b"\x0b" * 32
PUB = ed25519.public_key(SEC).hex()
T0 = 1_800_000_000
HEX64 = "ab" * 32
HEX64_B = "cd" * 32


def _authorities():
    reg = AuthorityRegistry()
    reg.register("bench-op", PUB)
    return reg


def _sign(payload):
    bare = dict(payload)
    bare["signature_hex"] = "00" * 64
    return ed25519.sign(SEC, jcs_canonical_json(bare))


class TestFieldChecks(unittest.TestCase):
    def test_bad_hex64_raises(self):
        reg = ConsistencyRegistry(_authorities())
        with self.assertRaises(HealthcareError):
            reg.issue("r", "nope", 5, 9000, T0, "bench-op",
                       ed25519.sign(SEC, b"x"))

    def test_bad_bps_raises(self):
        reg = CalibrationRegistry(_authorities())
        with self.assertRaises(HealthcareError):
            reg.issue("r", "d", "v1", "s", 10001, 10, 0, T0,
                       "bench-op", ed25519.sign(SEC, b"x"))

    def test_unknown_authority_raises(self):
        reg = CalibrationRegistry(AuthorityRegistry())
        with self.assertRaises(HealthcareError):
            reg.issue("r", "d", "v1", "s", 2000, 10, 0, T0,
                       "ghost", ed25519.sign(SEC, b"x"))

    def test_bad_maturity_level_raises(self):
        reg = MaturityRegistry(_authorities())
        with self.assertRaises(HealthcareError):
            reg.issue("m", "a", 7, "core", T0, "bench-op",
                       ed25519.sign(SEC, b"x"))

    def test_verdict_shapes(self):
        v = alert_burden_ledger(CalibrationRegistry(_authorities()), "d", T0)
        self.assertIsInstance(v, HealthcareVerdict)
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, CLASS_ALERT_SILENCED)


class TestAlertBurdenLedger(unittest.TestCase):
    def _issue(self, reg, receipt_id="c1", deployment_id="dep-sepsis",
               model_version="esm-v2", site_id="site-a", ppv_bps=2000,
               alerts_per_1k=40, before_bps=3000, at=T0):
        # Build the unsigned payload, then sign.
        proto = {
            "schema": "northstar.healthcare-discipline.v1",
            "type": "calibration",
            "receipt_id": receipt_id,
            "deployment_id": deployment_id,
            "model_version": model_version,
            "site_id": site_id,
            "ppv_bps": ppv_bps,
            "alerts_per_1k": alerts_per_1k,
            "processed_before_bps": before_bps,
            "calibrated_at": at,
            "authority_id": "bench-op",
            "authority_pubkey_hex": PUB,
            "prev_digest": reg.log[-1].receipt_digest if reg.log else "genesis",
        }
        return reg.issue(receipt_id, deployment_id, model_version, site_id,
                         ppv_bps, alerts_per_1k, before_bps, at, "bench-op",
                         _sign(proto))

    def test_no_calibration_denies_silenced(self):
        v = alert_burden_ledger(CalibrationRegistry(_authorities()),
                                "dep-x", T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, CLASS_ALERT_SILENCED)
        self.assertIn("no_calibration", v.reason)

    def test_good_calibration_allows(self):
        reg = CalibrationRegistry(_authorities())
        self._issue(reg)
        v = alert_burden_ledger(reg, "dep-sepsis", T0)
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, CLASS_AUTHORITATIVE)

    def test_low_ppv_silences(self):
        reg = CalibrationRegistry(_authorities())
        self._issue(reg, ppv_bps=1000)  # below 0.15 floor
        v = alert_burden_ledger(reg, "dep-sepsis", T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, CLASS_ALERT_SILENCED)
        self.assertIn("low_ppv_silenced", v.reason)

    def test_posthoc_alerts_silence(self):
        reg = CalibrationRegistry(_authorities())
        self._issue(reg, before_bps=6700)  # ESM-v2-like 2/3 post-hoc
        v = alert_burden_ledger(reg, "dep-sepsis", T0)
        self.assertFalse(v.allowed)
        self.assertIn("posthoc_alerts_silenced", v.reason)

    def test_stale_calibration_denies(self):
        reg = CalibrationRegistry(_authorities())
        self._issue(reg, at=T0 - 366 * 86_400)
        v = alert_burden_ledger(reg, "dep-sepsis", T0)
        self.assertFalse(v.allowed)
        self.assertIn("stale_calibration", v.reason)


class TestResponsibilityManifest(unittest.TestCase):
    def _issue(self, reg, manifest_id="m1", model_version="v9",
               at=T0):
        proto = {
            "schema": "northstar.healthcare-discipline.v1",
            "type": "responsibility-manifest",
            "manifest_id": manifest_id,
            "model_version": model_version,
            "developer_id": "dev-acme",
            "operator_id": "op-hospital",
            "clinician_role": "attending-physician",
            "issued_at": at,
            "authority_id": "bench-op",
            "authority_pubkey_hex": PUB,
            "prev_digest": reg.log[-1].receipt_digest if reg.log else "genesis",
        }
        return reg.issue(manifest_id, model_version, "dev-acme",
                         "op-hospital", "attending-physician", at,
                         "bench-op", _sign(proto))

    def test_missing_manifest_denies(self):
        v = responsibility_manifest(ResponsibilityRegistry(_authorities()),
                                    "v9", T0)
        self.assertFalse(v.allowed)
        self.assertIn("no_responsibility_manifest", v.reason)

    def test_live_manifest_allows(self):
        reg = ResponsibilityRegistry(_authorities())
        self._issue(reg)
        v = responsibility_manifest(reg, "v9", T0)
        self.assertTrue(v.allowed)
        self.assertIn("dev-acme", v.reason)

    def test_stale_manifest_denies(self):
        reg = ResponsibilityRegistry(_authorities())
        self._issue(reg, at=T0 - 181 * 86_400)
        v = responsibility_manifest(reg, "v9", T0)
        self.assertFalse(v.allowed)
        self.assertIn("stale_responsibility_manifest", v.reason)

    def test_wrong_version_denies(self):
        reg = ResponsibilityRegistry(_authorities())
        self._issue(reg, model_version="v9")
        v = responsibility_manifest(reg, "v10", T0)
        self.assertFalse(v.allowed)


class TestBiasVignetteRegression(unittest.TestCase):
    def _issue(self, reg, receipt_id, model_version, race, gender, at=T0):
        proto = {
            "schema": "northstar.healthcare-discipline.v1",
            "type": "bias-vignette",
            "receipt_id": receipt_id,
            "model_version": model_version,
            "n_vignettes": 36000,
            "race_misrep_bps": race,
            "gender_misrep_bps": gender,
            "evaluated_at": at,
            "authority_id": "bench-op",
            "authority_pubkey_hex": PUB,
            "prev_digest": reg.log[-1].receipt_digest if reg.log else "genesis",
        }
        return reg.issue(receipt_id, model_version, 36000, race, gender,
                         at, "bench-op", _sign(proto))

    def test_stable_allows(self):
        reg = BiasVignetteRegistry(_authorities())
        self._issue(reg, "b1", "v1", 4400, 3100)
        self._issue(reg, "b2", "v2", 4300, 3200)
        v = bias_vignette_regression(reg, "v2", "v1")
        self.assertTrue(v.allowed)

    def test_regression_refuses_deploy(self):
        reg = BiasVignetteRegistry(_authorities())
        self._issue(reg, "b1", "v1", 4400, 3100)
        self._issue(reg, "b2", "v2", 7800, 3200)  # race +34pp
        v = bias_vignette_regression(reg, "v2", "v1")
        self.assertFalse(v.allowed)
        self.assertIn("fairness_regressed", v.reason)

    def test_no_baseline_denies(self):
        reg = BiasVignetteRegistry(_authorities())
        self._issue(reg, "b2", "v2", 4300, 3200)
        v = bias_vignette_regression(reg, "v2", "v1")
        self.assertFalse(v.allowed)
        self.assertIn("no_vignette_baseline", v.reason)


class TestDenialEvidenceProvenance(unittest.TestCase):
    def _issue(self, reg):
        proto = {
            "schema": "northstar.healthcare-discipline.v1",
            "type": "denial-evidence",
            "receipt_id": "e1",
            "recommendation_id": "rec-1",
            "clinical_logic": "snf-not-medically-necessary",
            "evidence_source": "milliman-care-guidelines-2026",
            "tool_version": "nh-predict-2.3",
            "issued_at": T0,
            "authority_id": "bench-op",
            "authority_pubkey_hex": PUB,
            "prev_digest": "genesis",
        }
        return reg.issue("e1", "rec-1", "snf-not-medically-necessary",
                         "milliman-care-guidelines-2026", "nh-predict-2.3",
                         T0, "bench-op", _sign(proto))

    def test_missing_provenance_refuses(self):
        v = denial_evidence_provenance(
            DenialEvidenceRegistry(_authorities()), "rec-ghost")
        self.assertFalse(v.allowed)
        self.assertIn("no_evidence_provenance", v.reason)

    def test_bound_provenance_allows(self):
        reg = DenialEvidenceRegistry(_authorities())
        self._issue(reg)
        v = denial_evidence_provenance(reg, "rec-1")
        self.assertTrue(v.allowed)


class TestTriageOrderingBan(unittest.TestCase):
    def _issue(self, reg, site="ed-a", realtime=True, at=T0,
               expires=None):
        expires = T0 + 30 * 86_400 if expires is None else expires
        proto = {
            "schema": "northstar.healthcare-discipline.v1",
            "type": "triage-safety-case",
            "case_id": "tc1",
            "site_id": site,
            "independent_case_digest": HEX64,
            "human_review_realtime": realtime,
            "approved_at": at,
            "expires_at": expires,
            "authority_id": "bench-op",
            "authority_pubkey_hex": PUB,
            "prev_digest": "genesis",
        }
        return reg.issue("tc1", site, HEX64, realtime, at, expires,
                         "bench-op", _sign(proto))

    def test_default_deny(self):
        v = triage_ordering_ban(TriageSafetyRegistry(_authorities()),
                                "ed-a", T0)
        self.assertFalse(v.allowed)
        self.assertIn("triage_ordering_banned", v.reason)

    def test_live_case_with_human_allows(self):
        reg = TriageSafetyRegistry(_authorities())
        self._issue(reg)
        v = triage_ordering_ban(reg, "ed-a", T0 + 100)
        self.assertTrue(v.allowed)

    def test_case_without_realtime_keeps_ban(self):
        reg = TriageSafetyRegistry(_authorities())
        self._issue(reg, realtime=False)
        v = triage_ordering_ban(reg, "ed-a", T0 + 100)
        self.assertFalse(v.allowed)

    def test_expired_case_keeps_ban(self):
        reg = TriageSafetyRegistry(_authorities())
        self._issue(reg, at=T0 - 60 * 86_400,
                    expires=T0 - 30 * 86_400)
        v = triage_ordering_ban(reg, "ed-a", T0)
        self.assertFalse(v.allowed)


class TestUsageNotice(unittest.TestCase):
    def _issue(self, reg, encounter="enc-1", optout=True):
        proto = {
            "schema": "northstar.healthcare-discipline.v1",
            "type": "usage-notice",
            "notice_id": "n1",
            "encounter_id": encounter,
            "patient_id": "pat-1",
            "ai_components": ["dx-agent", "scribe"],
            "opt_out_available": optout,
            "issued_at": T0,
            "authority_id": "bench-op",
            "authority_pubkey_hex": PUB,
            "prev_digest": "genesis",
        }
        return reg.issue("n1", encounter, "pat-1", ("dx-agent", "scribe"),
                         optout, T0, "bench-op", _sign(proto))

    def test_missing_notice_non_compliant(self):
        v = ai_usage_notice(UsageNoticeRegistry(_authorities()),
                            "enc-ghost", T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, CLASS_NON_COMPLIANT)
        self.assertIn("no_ai_notice", v.reason)

    def test_no_optout_non_compliant(self):
        reg = UsageNoticeRegistry(_authorities())
        self._issue(reg, optout=False)
        v = ai_usage_notice(reg, "enc-1", T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, CLASS_NON_COMPLIANT)

    def test_notice_with_optout_allows(self):
        reg = UsageNoticeRegistry(_authorities())
        self._issue(reg)
        v = ai_usage_notice(reg, "enc-1", T0)
        self.assertTrue(v.allowed)


class TestDissentProtocol(unittest.TestCase):
    def _issue(self, reg, decision="dec-1", u=True, c=True, r=True):
        proto = {
            "schema": "northstar.healthcare-discipline.v1",
            "type": "dissent-ack",
            "ack_id": "a1",
            "decision_id": decision,
            "clinician_id": "dr-wu",
            "uncertainty_shown": u,
            "counter_evidence_shown": c,
            "read_acknowledged": r,
            "signed_at": T0,
            "authority_id": "bench-op",
            "authority_pubkey_hex": PUB,
            "prev_digest": "genesis",
        }
        return reg.issue("a1", decision, "dr-wu", u, c, r, T0,
                         "bench-op", _sign(proto))

    def test_no_ack_denies(self):
        v = adversarial_dissent_protocol(
            DissentAckRegistry(_authorities()), "dec-ghost")
        self.assertFalse(v.allowed)
        self.assertIn("no_dissent_ack", v.reason)

    def test_full_ack_allows(self):
        reg = DissentAckRegistry(_authorities())
        self._issue(reg)
        v = adversarial_dissent_protocol(reg, "dec-1")
        self.assertTrue(v.allowed)

    def test_missing_counter_evidence_is_rubber_stamp(self):
        reg = DissentAckRegistry(_authorities())
        self._issue(reg, c=False)
        v = adversarial_dissent_protocol(reg, "dec-1")
        self.assertFalse(v.allowed)
        self.assertIn("rubber_stamp", v.reason)


class TestConsistencySignal(unittest.TestCase):
    def _issue(self, reg, digest=HEX64, agree=9200):
        proto = {
            "schema": "northstar.healthcare-discipline.v1",
            "type": "consistency",
            "receipt_id": "k1",
            "output_digest": digest,
            "n_samples": 8,
            "agree_bps": agree,
            "measured_at": T0,
            "authority_id": "bench-op",
            "authority_pubkey_hex": PUB,
            "prev_digest": "genesis",
        }
        return reg.issue("k1", digest, 8, agree, T0, "bench-op",
                         _sign(proto))

    def test_no_signal_denies(self):
        v = consistency_uncertainty_signal(
            ConsistencyRegistry(_authorities()), HEX64)
        self.assertFalse(v.allowed)

    def test_high_consistency_allows(self):
        reg = ConsistencyRegistry(_authorities())
        self._issue(reg)
        v = consistency_uncertainty_signal(reg, HEX64)
        self.assertTrue(v.allowed)

    def test_low_consistency_degrades(self):
        reg = ConsistencyRegistry(_authorities())
        self._issue(reg, agree=5000)
        v = consistency_uncertainty_signal(reg, HEX64)
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, CLASS_NON_AUTHORITATIVE)
        self.assertIn("low_consistency_needs_second_review", v.reason)


class TestMaturityMapping(unittest.TestCase):
    def _issue(self, reg, agent="agent-a", level=2):
        proto = {
            "schema": "northstar.healthcare-discipline.v1",
            "type": "maturity-label",
            "label_id": "m1",
            "agent_id": agent,
            "level": level,
            "scope": "clinical-core",
            "labeled_at": T0,
            "authority_id": "bench-op",
            "authority_pubkey_hex": PUB,
            "prev_digest": "genesis",
        }
        return reg.issue("m1", agent, level, "clinical-core", T0,
                         "bench-op", _sign(proto))

    def test_no_label_denies(self):
        v = maturity_mapping(MaturityRegistry(_authorities()), "agent-x")
        self.assertFalse(v.allowed)

    def test_below_l2_barred_from_core(self):
        reg = MaturityRegistry(_authorities())
        self._issue(reg, level=1)
        v = maturity_mapping(reg, "agent-a", clinical_core=True)
        self.assertFalse(v.allowed)
        self.assertIn("maturity_too_low", v.reason)

    def test_l2_core_allows(self):
        reg = MaturityRegistry(_authorities())
        self._issue(reg, level=2)
        v = maturity_mapping(reg, "agent-a", clinical_core=True)
        self.assertTrue(v.allowed)

    def test_l1_outside_core_recorded(self):
        reg = MaturityRegistry(_authorities())
        self._issue(reg, level=1)
        v = maturity_mapping(reg, "agent-a", clinical_core=False)
        self.assertTrue(v.allowed)


class TestPostmarketSurveillance(unittest.TestCase):
    def _issue(self, reg, drop=200, override=1000, drift=500,
               version="v9"):
        proto = {
            "schema": "northstar.healthcare-discipline.v1",
            "type": "surveillance-window",
            "window_id": "w1",
            "model_version": version,
            "sensitivity_drop_bps": drop,
            "override_rate_bps": override,
            "demographic_drift_bps": drift,
            "rollback_version": "v8",
            "window_end": T0 + 90 * 86_400,
            "authority_id": "bench-op",
            "authority_pubkey_hex": PUB,
            "prev_digest": "genesis",
        }
        return reg.issue("w1", version, drop, override, drift, "v8",
                         T0 + 90 * 86_400, "bench-op", _sign(proto))

    def test_no_window_denies(self):
        v = postmarket_surveillance(
            SurveillanceRegistry(_authorities()), "v9", T0)
        self.assertFalse(v.allowed)

    def test_within_envelope_allows(self):
        reg = SurveillanceRegistry(_authorities())
        self._issue(reg)
        v = postmarket_surveillance(reg, "v9", T0)
        self.assertTrue(v.allowed)

    def test_breach_rolls_back(self):
        reg = SurveillanceRegistry(_authorities())
        self._issue(reg, override=4500)
        v = postmarket_surveillance(reg, "v9", T0)
        self.assertFalse(v.allowed)
        self.assertIn("drift_rollback", v.reason)
        self.assertIn("v8", v.reason)


class TestChainIntegrity(unittest.TestCase):
    def test_digest_recomputes(self):
        reg = CalibrationRegistry(_authorities())
        proto = {
            "schema": "northstar.healthcare-discipline.v1",
            "type": "calibration",
            "receipt_id": "c9",
            "deployment_id": "dep-9",
            "model_version": "v1",
            "site_id": "site-9",
            "ppv_bps": 2000,
            "alerts_per_1k": 40,
            "processed_before_bps": 3000,
            "calibrated_at": T0,
            "authority_id": "bench-op",
            "authority_pubkey_hex": PUB,
            "prev_digest": "genesis",
        }
        r = reg.issue("c9", "dep-9", "v1", "site-9", 2000, 40, 3000,
                      T0, "bench-op", _sign(proto))
        from canonical_json import jcs_sha256_hex
        self.assertEqual(r.receipt_digest,
                         jcs_sha256_hex(r._payload()))


class TamperedSignatureTest(unittest.TestCase):
    """ed25519.verify returns bool and never raises — the return value must be
    used. A tampered signature must verify as False, not silently pass."""

    def test_verify_signature_accepts_valid_rejects_tampered(self):
        seed = b"\x0c" * 32
        pub_hex = ed25519.public_key(seed).hex()
        body = {"deployment_id": "dep-tamper", "model_version": "v1"}
        body["signature_hex"] = "00" * 64
        sig_hex = ed25519.sign(seed, jcs_canonical_json(body)).hex()
        self.assertTrue(_verify_signature(pub_hex, body, sig_hex))
        self.assertFalse(_verify_signature(pub_hex, body, "00" * 64))


if __name__ == "__main__":
    unittest.main()
