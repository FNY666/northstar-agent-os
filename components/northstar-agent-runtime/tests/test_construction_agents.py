"""Tests for construction_agents (one-hundred-sixtieth batch)."""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ed25519
from canonical_json import jcs_canonical_json

from construction_agents import (
    CONSTRUCTION_SCHEMA_VERSION,
    AuthorityRegistry,
    ConstructionError,
    ProgressAssessmentRegistry,
    ProgressAssessmentReceipt,
    ScheduleChangeRegistry,
    ScheduleChangeReceipt,
    TwinUpdateRegistry,
    TwinUpdateReceipt,
    PerimeterRegistry,
    PerimeterReceipt,
    InterlockRegistry,
    InterlockReceipt,
    ValidationFeedbackRegistry,
    ValidationFeedbackReceipt,
    SurveillanceConsentRegistry,
    SurveillanceConsentReceipt,
    ClausePinRegistry,
    ClausePinReceipt,
    ForecastRegistry,
    ForecastReceipt,
    ConstructionEnvelopeRegistry,
    ConstructionEnvelopeReceipt,
    OrchestrationRegistry,
    OrchestrationManifest,
    AlertBudgetRegistry,
    AlertBudgetReceipt,
    progress_evidence_receipt,
    schedule_rationale_binding,
    digital_twin_integrity_log,
    hri_perimeter_gate,
    safety_interlock_receipt,
    validation_loop_clock,
    worker_surveillance_consent,
    hallucinated_clause_screen,
    forecast_uncertainty_band,
    capability_envelope_gate,
    fleet_orchestration_manifest,
    safety_alert_budget,
    EVIDENCE_MAX_AGE_S,
    PERIMETER_STATUS_MAX_AGE_S,
    INTERLOCK_MAX_AGE_S,
    VALIDATION_MAX_AGE_S,
    ALERT_MEASUREMENT_MAX_AGE_S,
    FORECAST_MAX_AGE_S,
)

_SEED = bytes(range(32))
_PUB = ed25519.public_key(_SEED).hex()
_AUTH = "auth-1"
_T0 = 1_800_000_000


def _auths():
    auth = AuthorityRegistry()
    auth.register(_AUTH, _PUB)
    return auth


def _hex(c):
    return c * 64


def _issue(reg, receipt_cls, **fields):
    """Issue a receipt, signing the exact payload the module verifies."""
    prev = reg.log[-1].receipt_digest if reg.log else "genesis"
    tmp = receipt_cls(
        prev_digest=prev,
        signature_hex="00" * 64,
        authority_id=_AUTH,
        authority_pubkey_hex=_PUB,
        **fields,
    )
    sig = ed25519.sign(_SEED, jcs_canonical_json(tmp._payload()))
    return reg.issue(signature=sig, authority_id=_AUTH, **fields)


class TestProgressEvidence(unittest.TestCase):
    def _progress(self, reg, claim_id="pc-1", captured_at=_T0,
                  payment=False, signoff="", rid="pa-1"):
        return _issue(
            reg, ProgressAssessmentReceipt,
            receipt_id=rid, claim_id=claim_id, site_id="site-a",
            assessment_method="photo_cv", evidence_digest=_hex("a"),
            captured_at=captured_at, assessor_id="cv-model-v2",
            payment_certificate=payment, human_signoff_id=signoff,
        )

    def test_allow_bound_evidence(self):
        reg = ProgressAssessmentRegistry(_auths())
        self._progress(reg)
        v = progress_evidence_receipt(reg, "pc-1", _T0 + 100)
        self.assertTrue(v.allowed)
        self.assertTrue(v.receipt_digest)

    def test_allow_payment_with_signoff(self):
        reg = ProgressAssessmentRegistry(_auths())
        self._progress(reg, payment=True, signoff="foreman-zhang")
        v = progress_evidence_receipt(reg, "pc-1", _T0 + 100)
        self.assertTrue(v.allowed)

    def test_deny_missing_evidence(self):
        reg = ProgressAssessmentRegistry(_auths())
        v = progress_evidence_receipt(reg, "pc-ghost", _T0)
        self.assertFalse(v.allowed)
        self.assertIn("no_progress_evidence", v.reason)

    def test_deny_payment_without_signoff(self):
        reg = ProgressAssessmentRegistry(_auths())
        self._progress(reg, payment=True, signoff="")
        v = progress_evidence_receipt(reg, "pc-1", _T0 + 100)
        self.assertFalse(v.allowed)
        self.assertIn("payment_without_signoff", v.reason)

    def test_deny_stale_evidence(self):
        reg = ProgressAssessmentRegistry(_auths())
        self._progress(reg, captured_at=_T0 - EVIDENCE_MAX_AGE_S - 1)
        v = progress_evidence_receipt(reg, "pc-1", _T0)
        self.assertFalse(v.allowed)
        self.assertIn("stale_evidence", v.reason)


class TestScheduleRationale(unittest.TestCase):
    def _change(self, reg, change_id="sc-1", critical=True,
                rationale="crane delay forces shift", impact="2d slip",
                rid="sr-1"):
        return _issue(
            reg, ScheduleChangeReceipt,
            receipt_id=rid, change_id=change_id, activity_id="act-7",
            old_start=_T0, new_start=_T0 + 86_400,
            rationale_summary=rationale, critical_path=critical,
            impact_statement=impact, recorded_at=_T0,
        )

    def test_allow_rationale_change(self):
        reg = ScheduleChangeRegistry(_auths())
        self._change(reg)
        v = schedule_rationale_binding(reg, "sc-1", _T0 + 10)
        self.assertTrue(v.allowed)

    def test_deny_unrationale_critical_path(self):
        reg = ScheduleChangeRegistry(_auths())
        self._change(reg, rationale="", impact="")
        v = schedule_rationale_binding(reg, "sc-1", _T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("unrationale_reschedule", v.reason)

    def test_deny_missing_change(self):
        reg = ScheduleChangeRegistry(_auths())
        v = schedule_rationale_binding(reg, "sc-ghost", _T0)
        self.assertFalse(v.allowed)
        self.assertIn("unrationale_reschedule", v.reason)


class TestTwinIntegrity(unittest.TestCase):
    def _update(self, reg, update_id="tu-1", source="sensor",
                isolated=False, rid="tw-1"):
        return _issue(
            reg, TwinUpdateReceipt,
            receipt_id=rid, update_id=update_id, twin_section="level-3",
            state_digest=_hex("b"), source_kind=source,
            provenance_digest=_hex("c"), isolated=isolated, issued_at=_T0,
        )

    def test_allow_sensor_update(self):
        reg = TwinUpdateRegistry(_auths())
        self._update(reg)
        v = digital_twin_integrity_log(reg, "tu-1", _T0 + 10)
        self.assertTrue(v.allowed)

    def test_allow_isolated_user_upload(self):
        reg = TwinUpdateRegistry(_auths())
        self._update(reg, source="user_upload", isolated=True)
        v = digital_twin_integrity_log(reg, "tu-1", _T0 + 10)
        self.assertTrue(v.allowed)

    def test_deny_contamination(self):
        reg = TwinUpdateRegistry(_auths())
        self._update(reg, source="user_upload", isolated=False)
        v = digital_twin_integrity_log(reg, "tu-1", _T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("twin_contamination", v.reason)


class TestPerimeterGate(unittest.TestCase):
    def _status(self, reg, machine_id="exc-1", sensor="nominal",
                mode="autonomous", assessed_at=_T0, rid="pm-1"):
        return _issue(
            reg, PerimeterReceipt,
            receipt_id=rid, machine_id=machine_id,
            perimeter_radius_m=15.0, sensor_status=sensor,
            autonomy_mode=mode, assessed_at=assessed_at,
        )

    def test_allow_nominal_autonomous(self):
        reg = PerimeterRegistry(_auths())
        self._status(reg)
        v = hri_perimeter_gate(reg, "exc-1", _T0 + 60)
        self.assertTrue(v.allowed)

    def test_deny_degraded_autonomous(self):
        reg = PerimeterRegistry(_auths())
        self._status(reg, sensor="degraded", mode="autonomous")
        v = hri_perimeter_gate(reg, "exc-1", _T0 + 60)
        self.assertFalse(v.allowed)
        self.assertIn("degraded_autonomy", v.reason)

    def test_allow_degraded_supervised(self):
        reg = PerimeterRegistry(_auths())
        self._status(reg, sensor="degraded", mode="supervised")
        v = hri_perimeter_gate(reg, "exc-1", _T0 + 60)
        self.assertTrue(v.allowed)

    def test_deny_stale_status(self):
        reg = PerimeterRegistry(_auths())
        self._status(reg, assessed_at=_T0 - PERIMETER_STATUS_MAX_AGE_S - 1)
        v = hri_perimeter_gate(reg, "exc-1", _T0)
        self.assertFalse(v.allowed)
        self.assertIn("stale_perimeter", v.reason)


class TestInterlock(unittest.TestCase):
    def _interlock(self, reg, start_id="st-1", event="pass",
                   recorded_at=_T0, rid="il-1"):
        return _issue(
            reg, InterlockReceipt,
            receipt_id=rid, machine_id="crane-2", start_request_id=start_id,
            interlock_kind="ppe_gate", event=event,
            ppe_evidence_digest=_hex("d"), recorded_at=recorded_at,
        )

    def test_allow_pass(self):
        reg = InterlockRegistry(_auths())
        self._interlock(reg)
        v = safety_interlock_receipt(reg, "crane-2", "st-1", _T0 + 60)
        self.assertTrue(v.allowed)

    def test_deny_no_interlock(self):
        reg = InterlockRegistry(_auths())
        v = safety_interlock_receipt(reg, "crane-2", "st-ghost", _T0)
        self.assertFalse(v.allowed)
        self.assertIn("no_interlock", v.reason)

    def test_deny_override_blocked(self):
        reg = InterlockRegistry(_auths())
        self._interlock(reg, event="blocked_start")
        v = safety_interlock_receipt(reg, "crane-2", "st-1", _T0 + 60)
        self.assertFalse(v.allowed)
        self.assertIn("interlock_override", v.reason)

    def test_deny_stale_interlock(self):
        reg = InterlockRegistry(_auths())
        self._interlock(reg, recorded_at=_T0 - INTERLOCK_MAX_AGE_S - 1)
        v = safety_interlock_receipt(reg, "crane-2", "st-1", _T0)
        self.assertFalse(v.allowed)
        self.assertIn("stale_interlock", v.reason)


class TestValidationLoop(unittest.TestCase):
    def _feedback(self, reg, alert_id="al-1", feedback="true_positive",
                  reviewed_at=_T0, rid="vf-1"):
        return _issue(
            reg, ValidationFeedbackReceipt,
            receipt_id=rid, alert_id=alert_id, feedback=feedback,
            reviewer_id="supervisor-li", reviewed_at=reviewed_at,
        )

    def test_allow_validated(self):
        reg = ValidationFeedbackRegistry(_auths())
        self._feedback(reg)
        v = validation_loop_clock(reg, "al-1", _T0 + 3600)
        self.assertTrue(v.allowed)

    def test_deny_unvalidated(self):
        reg = ValidationFeedbackRegistry(_auths())
        v = validation_loop_clock(reg, "al-ghost", _T0)
        self.assertFalse(v.allowed)
        self.assertIn("unvalidated_alert", v.reason)

    def test_deny_expired_feedback(self):
        reg = ValidationFeedbackRegistry(_auths())
        self._feedback(reg, reviewed_at=_T0 - VALIDATION_MAX_AGE_S - 1)
        v = validation_loop_clock(reg, "al-1", _T0)
        self.assertFalse(v.allowed)
        self.assertIn("unvalidated_alert", v.reason)


class TestSurveillanceConsent(unittest.TestCase):
    def _consent(self, reg, worker="w-1", scope="video",
                 consented_at=_T0, rid="co-1"):
        return _issue(
            reg, SurveillanceConsentReceipt,
            receipt_id=rid, site_id="site-a", worker_id=worker, scope=scope,
            data_owner="contractor-xyz", reuse_purposes=["safety"],
            consented_at=consented_at, expires_at=consented_at + 365 * 86_400,
        )

    def test_allow_consented(self):
        reg = SurveillanceConsentRegistry(_auths())
        self._consent(reg)
        v = worker_surveillance_consent(reg, "site-a", "w-1", "video", _T0 + 10)
        self.assertTrue(v.allowed)

    def test_deny_unconsented(self):
        reg = SurveillanceConsentRegistry(_auths())
        v = worker_surveillance_consent(reg, "site-a", "w-9", "video", _T0)
        self.assertFalse(v.allowed)
        self.assertIn("unconsented_surveillance", v.reason)

    def test_deny_wrong_scope(self):
        reg = SurveillanceConsentRegistry(_auths())
        self._consent(reg, scope="video")
        v = worker_surveillance_consent(reg, "site-a", "w-1", "audio", _T0)
        self.assertFalse(v.allowed)
        self.assertIn("unconsented_surveillance", v.reason)


class TestClauseScreen(unittest.TestCase):
    def _pin(self, reg, doc="doc-1", clause="OSHA-1926.501",
             verified=True, rid="cp-1"):
        return _issue(
            reg, ClausePinReceipt,
            receipt_id=rid, document_id=doc, clause_reference=clause,
            regulation_source="OSHA 29 CFR 1926", pinned_text_digest=_hex("e"),
            verified=verified, issued_at=_T0,
        )

    def test_allow_verified_clause(self):
        reg = ClausePinRegistry(_auths())
        self._pin(reg)
        v = hallucinated_clause_screen(reg, "doc-1", "OSHA-1926.501")
        self.assertTrue(v.allowed)

    def test_deny_fabricated_clause(self):
        reg = ClausePinRegistry(_auths())
        v = hallucinated_clause_screen(reg, "doc-1", "OSHA-1926.999")
        self.assertFalse(v.allowed)
        self.assertIn("fabricated_clause", v.reason)

    def test_deny_unverified_pin(self):
        reg = ClausePinRegistry(_auths())
        self._pin(reg, verified=False)
        v = hallucinated_clause_screen(reg, "doc-1", "OSHA-1926.501")
        self.assertFalse(v.allowed)
        self.assertIn("fabricated_clause", v.reason)


class TestForecastBand(unittest.TestCase):
    def _forecast(self, reg, fid="fc-1", assumptions="crane uptime 90%",
                  issued_at=_T0, rid="fb-1"):
        return _issue(
            reg, ForecastReceipt,
            receipt_id=rid, forecast_id=fid, forecast_kind="schedule",
            value_text="milestone in 12 days",
            uncertainty_low=10.0, uncertainty_high=16.0,
            assumptions_digest=_hex("f"), assumptions_text=assumptions,
            issued_at=issued_at,
        )

    def test_allow_band(self):
        reg = ForecastRegistry(_auths())
        self._forecast(reg)
        v = forecast_uncertainty_band(reg, "fc-1", _T0 + 3600)
        self.assertTrue(v.allowed)

    def test_deny_unstated_assumptions(self):
        reg = ForecastRegistry(_auths())
        self._forecast(reg, assumptions="")
        v = forecast_uncertainty_band(reg, "fc-1", _T0 + 3600)
        self.assertFalse(v.allowed)
        self.assertIn("unstated_assumptions", v.reason)
        self.assertEqual(v.classification, "non_authoritative")

    def test_deny_stale_forecast(self):
        reg = ForecastRegistry(_auths())
        self._forecast(reg, issued_at=_T0 - FORECAST_MAX_AGE_S - 1)
        v = forecast_uncertainty_band(reg, "fc-1", _T0)
        self.assertFalse(v.allowed)
        self.assertIn("stale_forecast", v.reason)


class TestEnvelopeGate(unittest.TestCase):
    def _envelope(self, reg, machine="exc-1", tasks=("excavate", "grade"),
                  max_payload=20.0, valid_until=_T0 + 10 * 86_400,
                  rid="ev-1"):
        return _issue(
            reg, ConstructionEnvelopeReceipt,
            receipt_id=rid, machine_id=machine, task_kinds=list(tasks),
            max_payload_t=max_payload, max_speed_ms=2.5,
            allowed_conditions=["daylight", "dry_soil"],
            valid_from=_T0, valid_until=valid_until,
        )

    def test_allow_within_envelope(self):
        reg = ConstructionEnvelopeRegistry(_auths())
        self._envelope(reg)
        v = capability_envelope_gate(reg, "exc-1", "excavate", 12.0, _T0 + 10)
        self.assertTrue(v.allowed)

    def test_deny_unknown_task(self):
        reg = ConstructionEnvelopeRegistry(_auths())
        self._envelope(reg)
        v = capability_envelope_gate(reg, "exc-1", "weld", 5.0, _T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("envelope_breach", v.reason)

    def test_deny_payload_over(self):
        reg = ConstructionEnvelopeRegistry(_auths())
        self._envelope(reg)
        v = capability_envelope_gate(reg, "exc-1", "excavate", 25.0, _T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("envelope_breach", v.reason)

    def test_deny_no_envelope(self):
        reg = ConstructionEnvelopeRegistry(_auths())
        v = capability_envelope_gate(reg, "exc-9", "excavate", 5.0, _T0)
        self.assertFalse(v.allowed)
        self.assertIn("envelope_breach", v.reason)


class TestOrchestration(unittest.TestCase):
    def _manifest(self, reg, fleet="fleet-1", rid="om-1",
                  responsible="site-manager-chen"):
        return _issue(
            reg, OrchestrationManifest,
            receipt_id=rid, manifest_id="mf-1", fleet_id=fleet,
            machine_ids=["exc-1", "truck-3"], responsible_party=responsible,
            window_start=_T0, window_end=_T0 + 86_400, issued_at=_T0,
        )

    def test_allow_manifest(self):
        reg = OrchestrationRegistry(_auths())
        self._manifest(reg)
        v = fleet_orchestration_manifest(reg, "fleet-1", _T0 + 3600)
        self.assertTrue(v.allowed)

    def test_deny_no_manifest(self):
        reg = OrchestrationRegistry(_auths())
        v = fleet_orchestration_manifest(reg, "fleet-ghost", _T0)
        self.assertFalse(v.allowed)
        self.assertIn("no_orchestration_manifest", v.reason)

    def test_deny_out_of_window(self):
        reg = OrchestrationRegistry(_auths())
        self._manifest(reg)
        v = fleet_orchestration_manifest(reg, "fleet-1", _T0 + 200_000)
        self.assertFalse(v.allowed)
        self.assertIn("manifest_out_of_window", v.reason)


class TestAlertBudget(unittest.TestCase):
    def _budget(self, reg, channel="ch-1", budget=200.0, fp=180,
                total=4000, measured_at=_T0, rid="ab-1"):
        return _issue(
            reg, AlertBudgetReceipt,
            receipt_id=rid, channel_id=channel, budget_fp_per_day=budget,
            measured_fp=fp, measured_total=total, measured_at=measured_at,
        )

    def test_allow_within_budget(self):
        reg = AlertBudgetRegistry(_auths())
        self._budget(reg)
        v = safety_alert_budget(reg, "ch-1", _T0 + 3600)
        self.assertTrue(v.allowed)

    def test_deny_over_budget(self):
        reg = AlertBudgetRegistry(_auths())
        self._budget(reg, fp=260)
        v = safety_alert_budget(reg, "ch-1", _T0 + 3600)
        self.assertFalse(v.allowed)
        self.assertIn("alert_budget_exceeded", v.reason)

    def test_deny_stale_measurement(self):
        reg = AlertBudgetRegistry(_auths())
        self._budget(reg, measured_at=_T0 - ALERT_MEASUREMENT_MAX_AGE_S - 1)
        v = safety_alert_budget(reg, "ch-1", _T0)
        self.assertFalse(v.allowed)
        self.assertIn("stale_alert_measurement", v.reason)


class TestChainIntegrity(unittest.TestCase):
    def test_tampered_signature_fails(self):
        reg = ProgressAssessmentRegistry(_auths())
        prev = "genesis"
        tmp = ProgressAssessmentReceipt(
            receipt_id="pa-x", claim_id="pc-x", site_id="site-a",
            assessment_method="photo_cv", evidence_digest=_hex("a"),
            captured_at=_T0, assessor_id="cv", payment_certificate=False,
            human_signoff_id="", authority_id=_AUTH,
            authority_pubkey_hex=_PUB, signature_hex="00" * 64,
            prev_digest=prev,
        )
        sig = ed25519.sign(_SEED, jcs_canonical_json(tmp._payload()))
        # tamper: flip a byte of the valid signature
        bad = bytearray(sig)
        bad[0] ^= 0xFF
        with self.assertRaises(ConstructionError):
            reg.issue(
                receipt_id="pa-x", claim_id="pc-x", site_id="site-a",
                assessment_method="photo_cv", evidence_digest=_hex("a"),
                captured_at=_T0, assessor_id="cv", payment_certificate=False,
                human_signoff_id="", authority_id=_AUTH, signature=bytes(bad),
            )

    def test_schema_version(self):
        self.assertEqual(CONSTRUCTION_SCHEMA_VERSION, "northstar.construction.v1")


if __name__ == "__main__":
    unittest.main()
