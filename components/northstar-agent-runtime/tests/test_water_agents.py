"""Tests for water_agents.py (one-hundred-thirty-first batch).

Deterministic: pinned keys, pinned times. No network, no clock reads.
"""
import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ed25519 import public_key, sign

from water_agents import (
    DENY_AI_ASSISTED_ATTACK,
    DENY_AIRGAP_DIGEST_MISMATCH,
    DENY_AIRGAP_REVOKED,
    DENY_AIRGAP_STALE,
    DENY_BOIL_NOTICE_NO_COUNTERSIGN,
    DENY_BOIL_NOTICE_UNEVIDENCED,
    DENY_DATA_PURPOSE_UNSIGNED,
    DENY_DATA_REPURPOSE,
    DENY_DOSING_ENVELOPE_EXPIRED,
    DENY_DOSING_OUT_OF_ENVELOPE,
    DENY_FOOTPRINT_LEDGER_MISMATCH,
    DENY_LEAK_PROTOCOL_MISMATCH,
    DENY_NO_AIRGAP_RECEIPT,
    DENY_PLC_EXPOSURE,
    DENY_PLC_INVENTORY_MISMATCH,
    DENY_QUALITY_PROTOCOL_STALE,
    DENY_QUALITY_UNBOUND,
    DENY_UNDECLARED_WATER_FOOTPRINT,
    DENY_UNKNOWN_TELEMETRY_MARKER,
    DENY_UNVERIFIED_LEAK_CLAIM,
    AIRGAP_SCHEMA,
    WATER_AUTHORITATIVE,
    WATER_NON_AUTHORITATIVE,
    AuthorityRegistry,
    DataPurposeRegistry,
    DosingEnvelopeRegistry,
    OTAirgapRegistry,
    PLCExposureProbe,
    WaterError,
    ai_attack_telemetry,
    boil_notice_evidence,
    chemical_dosing_envelope,
    data_sovereignty_gate,
    leak_claim_receipt,
    ot_airgap_receipt,
    plc_exposure_probe,
    quality_forecast_gate,
    water_audit_event,
    water_footprint_binding,
)

AUTH_SEC = b"water-authority-seed-00000000001"  # 32 bytes
AUTH2_SEC = b"water-authority-seed-00000000002"
AUTH_PUB = public_key(AUTH_SEC)
AUTH2_PUB = public_key(AUTH2_SEC)
T0 = 1_800_000_000
HEX64 = "ab" * 32
HEX64_B = "cd" * 32
HEX64_C = "ef" * 32


def _authorities() -> AuthorityRegistry:
    reg = AuthorityRegistry()
    reg.register("water-op", AUTH_PUB)
    reg.register("water-op2", AUTH2_PUB)
    return reg


def _issue_airgap(reg: OTAirgapRegistry, utility_id="util-1",
                  mechanism="physical_airgap", scope=HEX64,
                  declared_at=T0, authority="water-op", sec=AUTH_SEC):
    tmp = OTAirgapRegistry(reg._authorities)
    # build receipt digest by issuing unsigned-equivalent then signing
    from water_agents import OTAirgapReceipt
    r = OTAirgapReceipt(
        utility_id=utility_id, isolation_mechanism=mechanism,
        scope_digest=scope, declared_at=declared_at, revoked=False,
        authority_id=authority, signature=b"\x00" * 64)
    sig = sign(sec, r.digest().encode("utf-8"))
    return reg.issue(utility_id=utility_id, isolation_mechanism=mechanism,
                     scope_digest=scope, declared_at=declared_at,
                     authority_id=authority, signature=sig)


class OTAirgapTest(unittest.TestCase):
    def test_no_receipt_fails_closed(self) -> None:
        reg = OTAirgapRegistry(_authorities())
        v = ot_airgap_receipt(airgap_registry=reg, utility_id="util-1",
                              scope_digest=HEX64, now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_NO_AIRGAP_RECEIPT)
        self.assertEqual(v.classification, WATER_NON_AUTHORITATIVE)

    def test_valid_receipt_allows(self) -> None:
        reg = OTAirgapRegistry(_authorities())
        _issue_airgap(reg)
        v = ot_airgap_receipt(airgap_registry=reg, utility_id="util-1",
                              scope_digest=HEX64, now=T0)
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, WATER_AUTHORITATIVE)

    def test_stale_receipt_denied(self) -> None:
        reg = OTAirgapRegistry(_authorities())
        _issue_airgap(reg, declared_at=T0 - 91 * 24 * 3600)
        v = ot_airgap_receipt(airgap_registry=reg, utility_id="util-1",
                              scope_digest=HEX64, now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_AIRGAP_STALE)

    def test_revoked_receipt_denied(self) -> None:
        reg = OTAirgapRegistry(_authorities())
        _issue_airgap(reg)
        reg.revoke("util-1")
        v = ot_airgap_receipt(airgap_registry=reg, utility_id="util-1",
                              scope_digest=HEX64, now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_AIRGAP_REVOKED)

    def test_scope_mismatch_denied(self) -> None:
        reg = OTAirgapRegistry(_authorities())
        _issue_airgap(reg)
        v = ot_airgap_receipt(airgap_registry=reg, utility_id="util-1",
                              scope_digest=HEX64_B, now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_AIRGAP_DIGEST_MISMATCH)

    def test_bad_mechanism_rejected_at_issue(self) -> None:
        reg = OTAirgapRegistry(_authorities())
        with self.assertRaises(WaterError):
            reg.issue(utility_id="u", isolation_mechanism="trust_me",
                      scope_digest=HEX64, declared_at=T0,
                      authority_id="water-op", signature=b"\x00" * 64)


class PLCProbeTest(unittest.TestCase):
    def test_exposed_without_mfa_denied(self) -> None:
        p = PLCExposureProbe(utility_id="u", inventory_digest=HEX64,
                             plc_id="plc-7", exposed=True,
                             mfa_enabled=False, isolated=True, probed_at=T0)
        v = plc_exposure_probe(probe=p, inventory_digest=HEX64, now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_PLC_EXPOSURE)

    def test_exposed_with_mfa_and_isolation_allows(self) -> None:
        p = PLCExposureProbe(utility_id="u", inventory_digest=HEX64,
                             plc_id="plc-7", exposed=True,
                             mfa_enabled=True, isolated=True, probed_at=T0)
        v = plc_exposure_probe(probe=p, inventory_digest=HEX64, now=T0)
        self.assertTrue(v.allowed)

    def test_inventory_mismatch_denied(self) -> None:
        p = PLCExposureProbe(utility_id="u", inventory_digest=HEX64,
                             plc_id="plc-7", exposed=False,
                             mfa_enabled=True, isolated=True, probed_at=T0)
        v = plc_exposure_probe(probe=p, inventory_digest=HEX64_B, now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_PLC_INVENTORY_MISMATCH)


class TelemetryTest(unittest.TestCase):
    def test_critical_marker_flagged(self) -> None:
        v = ai_attack_telemetry(session_id="s1",
                                markers=["llm_vnode_gateway_identification"],
                                now=T0)
        self.assertTrue(v.flagged)
        self.assertEqual(v.deny_code, DENY_AI_ASSISTED_ATTACK)

    def test_two_noncritical_flagged(self) -> None:
        v = ai_attack_telemetry(session_id="s1",
                                markers=["llm_scada_recon",
                                         "boil_notice_suppression_attempt"],
                                now=T0)
        self.assertTrue(v.flagged)
        self.assertEqual(v.deny_code, DENY_AI_ASSISTED_ATTACK)

    def test_single_noncritical_not_flagged(self) -> None:
        v = ai_attack_telemetry(session_id="s1",
                                markers=["llm_scada_recon"], now=T0)
        self.assertFalse(v.flagged)
        self.assertIsNone(v.deny_code)

    def test_unknown_marker_fails_closed(self) -> None:
        v = ai_attack_telemetry(session_id="s1",
                                markers=["zero_day_magic"], now=T0)
        self.assertTrue(v.flagged)
        self.assertEqual(v.deny_code, DENY_UNKNOWN_TELEMETRY_MARKER)


class QualityForecastTest(unittest.TestCase):
    def test_unbound_forecast_non_authoritative(self) -> None:
        v = quality_forecast_gate(utility_id="u", forecast_digest=HEX64,
                                  measurement_protocol_digest=None,
                                  protocol_measured_at=None, now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_QUALITY_UNBOUND)
        self.assertEqual(v.classification, WATER_NON_AUTHORITATIVE)

    def test_stale_protocol_denied(self) -> None:
        v = quality_forecast_gate(
            utility_id="u", forecast_digest=HEX64,
            measurement_protocol_digest=HEX64_B,
            protocol_measured_at=T0 - 181 * 24 * 3600, now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_QUALITY_PROTOCOL_STALE)

    def test_bound_fresh_protocol_allows(self) -> None:
        v = quality_forecast_gate(
            utility_id="u", forecast_digest=HEX64,
            measurement_protocol_digest=HEX64_B,
            protocol_measured_at=T0 - 10 * 24 * 3600, now=T0)
        self.assertTrue(v.allowed)


def _arm_dosing(reg: DosingEnvelopeRegistry, agent_id="dose-1",
                actions=("chlorine_dose",), scope=HEX64,
                armed_at=T0, expires_at=T0 + 3600,
                authority="water-op", sec=AUTH_SEC):
    from water_agents import DosingEnvelope
    e = DosingEnvelope(agent_id=agent_id, plant_id="plant-1",
                       allowed_actions=tuple(actions), scope_digest=scope,
                       armed_at=armed_at, expires_at=expires_at,
                       authority_id=authority, signature=b"\x00" * 64)
    sig = sign(sec, e.digest().encode("utf-8"))
    return reg.arm(agent_id=agent_id, plant_id="plant-1",
                   allowed_actions=list(actions), scope_digest=scope,
                   armed_at=armed_at, expires_at=expires_at,
                   authority_id=authority, signature=sig)


class DosingEnvelopeTest(unittest.TestCase):
    def test_no_envelope_denied(self) -> None:
        reg = DosingEnvelopeRegistry(_authorities())
        v = chemical_dosing_envelope(envelope_registry=reg, agent_id="dose-1",
                                     action="chlorine_dose",
                                     scope_digest=HEX64, now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_DOSING_OUT_OF_ENVELOPE)

    def test_in_envelope_allows(self) -> None:
        reg = DosingEnvelopeRegistry(_authorities())
        _arm_dosing(reg)
        v = chemical_dosing_envelope(envelope_registry=reg, agent_id="dose-1",
                                     action="chlorine_dose",
                                     scope_digest=HEX64, now=T0)
        self.assertTrue(v.allowed)

    def test_out_of_vocabulary_denied(self) -> None:
        reg = DosingEnvelopeRegistry(_authorities())
        _arm_dosing(reg)
        v = chemical_dosing_envelope(envelope_registry=reg, agent_id="dose-1",
                                     action="fluoride_dose",
                                     scope_digest=HEX64, now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_DOSING_OUT_OF_ENVELOPE)

    def test_expired_envelope_denied(self) -> None:
        reg = DosingEnvelopeRegistry(_authorities())
        _arm_dosing(reg, expires_at=T0 + 10)
        v = chemical_dosing_envelope(envelope_registry=reg, agent_id="dose-1",
                                     action="chlorine_dose",
                                     scope_digest=HEX64, now=T0 + 3600)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_DOSING_ENVELOPE_EXPIRED)


class LeakClaimTest(unittest.TestCase):
    def _signed(self, vendor="v1", utility="u", claim=HEX64,
                protocol=HEX64_B, measured=T0, authority="water-op",
                sec=AUTH_SEC):
        from water_agents import LeakClaimReceipt
        r = LeakClaimReceipt(vendor_id=vendor, utility_id=utility,
                             claim_digest=claim, protocol_digest=protocol,
                             measured_at=measured, authority_id=authority,
                             signature=b"\x00" * 64)
        return sign(sec, r.digest().encode("utf-8"))

    def test_no_protocol_denied(self) -> None:
        v = leak_claim_receipt(authorities=_authorities(), vendor_id="v1",
                               utility_id="u", claim_digest=HEX64,
                               protocol_digest=None, measured_at=T0,
                               authority_id="water-op",
                               signature=b"\x00" * 64, now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_UNVERIFIED_LEAK_CLAIM)

    def test_signed_bound_claim_allows(self) -> None:
        v = leak_claim_receipt(authorities=_authorities(), vendor_id="v1",
                               utility_id="u", claim_digest=HEX64,
                               protocol_digest=HEX64_B, measured_at=T0,
                               authority_id="water-op",
                               signature=self._signed(), now=T0)
        self.assertTrue(v.allowed)

    def test_wrong_key_signature_denied(self) -> None:
        v = leak_claim_receipt(authorities=_authorities(), vendor_id="v1",
                               utility_id="u", claim_digest=HEX64,
                               protocol_digest=HEX64_B, measured_at=T0,
                               authority_id="water-op",
                               signature=self._signed(sec=AUTH2_SEC), now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_LEAK_PROTOCOL_MISMATCH)


class BoilNoticeTest(unittest.TestCase):
    def _countersign(self, utility="u", notice="n-1", evidence=HEX64,
                     issued=T0, authority="water-op", sec=AUTH_SEC):
        from water_agents import jcs_sha256_hex, BOIL_NOTICE_SCHEMA, SCHEMA_VERSION
        digest = jcs_sha256_hex({
            "schema": BOIL_NOTICE_SCHEMA, "schema_version": SCHEMA_VERSION,
            "utility_id": utility, "notice_id": notice,
            "event_evidence_digest": evidence, "issued_at": issued,
            "countersign_authority_id": authority})
        return sign(sec, digest.encode("utf-8"))

    def test_no_evidence_denied(self) -> None:
        v = boil_notice_evidence(authorities=_authorities(), utility_id="u",
                                 notice_id="n-1", event_evidence_digest=None,
                                 countersign_authority_id=None,
                                 countersign_signature=None,
                                 issued_at=T0, now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_BOIL_NOTICE_UNEVIDENCED)

    def test_no_countersign_denied(self) -> None:
        v = boil_notice_evidence(authorities=_authorities(), utility_id="u",
                                 notice_id="n-1",
                                 event_evidence_digest=HEX64,
                                 countersign_authority_id=None,
                                 countersign_signature=None,
                                 issued_at=T0, now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_BOIL_NOTICE_NO_COUNTERSIGN)

    def test_evidenced_countersigned_allows(self) -> None:
        v = boil_notice_evidence(authorities=_authorities(), utility_id="u",
                                 notice_id="n-1",
                                 event_evidence_digest=HEX64,
                                 countersign_authority_id="water-op",
                                 countersign_signature=self._countersign(),
                                 issued_at=T0, now=T0)
        self.assertTrue(v.allowed)


class DataSovereigntyTest(unittest.TestCase):
    def _issue(self, reg: DataPurposeRegistry, export_id="exp-1",
               purpose="leak_detection_research", scope=HEX64,
               issued=T0, expires=T0 + 3600, authority="water-op",
               sec=AUTH_SEC):
        from water_agents import DataPurposeReceipt
        r = DataPurposeReceipt(exporter_id="util-1", recipient_id="lab-1",
                               purpose=purpose, scope_digest=scope,
                               issued_at=issued, expires_at=expires,
                               authority_id=authority,
                               signature=b"\x00" * 64)
        sig = sign(sec, r.digest().encode("utf-8"))
        return reg.issue(export_id=export_id, exporter_id="util-1",
                         recipient_id="lab-1", purpose=purpose,
                         scope_digest=scope, issued_at=issued,
                         expires_at=expires, authority_id=authority,
                         signature=sig)

    def test_no_receipt_denied(self) -> None:
        reg = DataPurposeRegistry(_authorities())
        v = data_sovereignty_gate(purpose_registry=reg, export_id="exp-1",
                                  purpose="leak_detection_research",
                                  scope_digest=HEX64, now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_DATA_PURPOSE_UNSIGNED)

    def test_repurpose_denied(self) -> None:
        reg = DataPurposeRegistry(_authorities())
        self._issue(reg)
        v = data_sovereignty_gate(purpose_registry=reg, export_id="exp-1",
                                  purpose="emergency_response",
                                  scope_digest=HEX64, now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_DATA_REPURPOSE)

    def test_matching_purpose_allows(self) -> None:
        reg = DataPurposeRegistry(_authorities())
        self._issue(reg)
        v = data_sovereignty_gate(purpose_registry=reg, export_id="exp-1",
                                  purpose="leak_detection_research",
                                  scope_digest=HEX64, now=T0)
        self.assertTrue(v.allowed)


class FootprintTest(unittest.TestCase):
    def test_undeclared_denied(self) -> None:
        v = water_footprint_binding(workload_id="w1", water_liters=None,
                                    ledger_receipt_digest=None,
                                    expected_ledger_digest=HEX64)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_UNDECLARED_WATER_FOOTPRINT)

    def test_ledger_mismatch_denied(self) -> None:
        v = water_footprint_binding(workload_id="w1", water_liters=1200,
                                    ledger_receipt_digest=HEX64_B,
                                    expected_ledger_digest=HEX64)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_FOOTPRINT_LEDGER_MISMATCH)

    def test_bound_footprint_allows(self) -> None:
        v = water_footprint_binding(workload_id="w1", water_liters=1200,
                                    ledger_receipt_digest=HEX64,
                                    expected_ledger_digest=HEX64)
        self.assertTrue(v.allowed)

    def test_audit_event_digest_pinned(self) -> None:
        e = water_audit_event("water.dosing_denied", utility_id="u",
                              deny_code=DENY_DOSING_OUT_OF_ENVELOPE, now=T0)
        self.assertIn("event_digest", e)
        self.assertEqual(e["deny_code"], DENY_DOSING_OUT_OF_ENVELOPE)


if __name__ == "__main__":
    unittest.main()
