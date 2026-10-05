"""Tests for permit_agents (one-hundred-thirty-sixth batch)."""

import unittest

import ed25519
from canonical_json import jcs_canonical_json

from permit_agents import (
    AppealPathReceipt,
    AuthorityRegistry,
    DisparityProbeReceipt,
    OverrideWindow,
    PermitError,
    _verify_sig,
    appeal_window_gate,
    automation_bias_clock,
    code_version_pin,
    disparate_impact_probe,
    final_human_signoff,
    issue_appeal_path,
    issue_code_pin,
    issue_disparity_probe,
    issue_human_signoff,
    issue_normative_source,
    issue_precheck,
    issue_vendor_cost,
    normative_source_receipt,
    precheck_advisory_gate,
    vendor_cost_receipt,
)


AUTH = b"permit-test-authority-0000000001"
VENDOR = b"permit-test-vendor-0000000000001"
OTHER = b"permit-test-other-00000000000001"
T0 = 1_800_000_000
HEX = "ab" * 32
HEX2 = "cd" * 32


def _authorities():
    reg = AuthorityRegistry()
    # register() takes the 32-byte *public* key; signing uses the secret.
    reg.register("city-permit-office", ed25519.public_key(AUTH))
    return reg


class PrecheckTest(unittest.TestCase):
    def test_advisory_use_is_authoritative(self):
        r = issue_precheck(
            precheck_id="pc-1", application_id="app-1", outcome="flag",
            ai_model_digest=HEX, findings_digest=HEX2, issued_at=T0,
            issuer_id="civcheck", issuer_secret=VENDOR,
        )
        v = precheck_advisory_gate(r, decision_was_issued=False, human_reviewed=False)
        self.assertTrue(v.allowed)
        self.assertEqual(v.tier, "authoritative")

    def test_issued_on_ai_say_so_denies(self):
        r = issue_precheck(
            precheck_id="pc-2", application_id="app-2", outcome="pass",
            ai_model_digest=HEX, findings_digest=HEX2, issued_at=T0,
            issuer_id="civcheck", issuer_secret=VENDOR,
        )
        v = precheck_advisory_gate(r, decision_was_issued=True, human_reviewed=False)
        self.assertFalse(v.allowed)
        self.assertIn("unhuman_reviewed", v.deny_code)

    def test_issued_with_human_review_allows(self):
        r = issue_precheck(
            precheck_id="pc-3", application_id="app-3", outcome="recommend",
            ai_model_digest=HEX, findings_digest=HEX2, issued_at=T0,
            issuer_id="civcheck", issuer_secret=VENDOR,
        )
        v = precheck_advisory_gate(r, decision_was_issued=True, human_reviewed=True)
        self.assertTrue(v.allowed)

    def test_outcome_vocabulary_rejects_permit(self):
        with self.assertRaises(PermitError):
            issue_precheck(
                precheck_id="pc-4", application_id="app-4", outcome="permit",
                ai_model_digest=HEX, findings_digest=HEX2, issued_at=T0,
                issuer_id="civcheck", issuer_secret=VENDOR,
            )


class SignoffTest(unittest.TestCase):
    def test_valid_signoff_allows(self):
        reg = _authorities()
        s = issue_human_signoff(
            signoff_id="so-1", decision_id="dec-1",
            decision_kind="building_permit", reviewer_name="Li Wei",
            review_role="reviewing_officer",
            reasons="Structural drawings verified against code sections 4.2 and 7.1; "
                    "fire egress compliant; approving with conditions.",
            ai_score_digest=HEX, signed_at=T0,
            authority_id="city-permit-office", signer_secret=AUTH,
        )
        v = final_human_signoff("dec-1", "building_permit", s, reg, reviewed_at=T0 + 100)
        self.assertTrue(v.allowed)

    def test_vague_reason_raises(self):
        with self.assertRaises(PermitError):
            issue_human_signoff(
                signoff_id="so-2", decision_id="dec-2",
                decision_kind="building_permit", reviewer_name="Li Wei",
                review_role="reviewing_officer", reasons="model output",
                ai_score_digest=HEX, signed_at=T0,
                authority_id="city-permit-office", signer_secret=AUTH,
            )

    def test_missing_signoff_denies(self):
        reg = _authorities()
        v = final_human_signoff("dec-9", "building_permit", None, reg, reviewed_at=T0)
        self.assertFalse(v.allowed)
        self.assertIn("no_human_countersign", v.deny_code)

    def test_signoff_for_other_decision_denies(self):
        reg = _authorities()
        s = issue_human_signoff(
            signoff_id="so-3", decision_id="dec-other",
            decision_kind="building_permit", reviewer_name="Li Wei",
            review_role="reviewing_officer", reasons="Reviewed and approved.",
            ai_score_digest=HEX, signed_at=T0,
            authority_id="city-permit-office", signer_secret=AUTH,
        )
        v = final_human_signoff("dec-1", "building_permit", s, reg, reviewed_at=T0 + 100)
        self.assertFalse(v.allowed)


class CodePinTest(unittest.TestCase):
    def test_signed_current_pin_authoritative(self):
        pin = issue_code_pin(
            pin_id="pin-1", code_name="LGUC", code_version="2026-A",
            effective_from=T0, issuer_id="city-permit-office",
            issuer_secret=AUTH,
        )
        v = code_version_pin(pin, "2026-A", checked_at=T0 + 1000)
        self.assertTrue(v.allowed)

    def test_superseded_citation_degrades(self):
        pin = issue_code_pin(
            pin_id="pin-2", code_name="LGUC", code_version="2026-B",
            effective_from=T0, superseded_by="2026-C",
            issuer_id="city-permit-office", issuer_secret=AUTH,
        )
        v = code_version_pin(pin, "2026-B", checked_at=T0 + 1000)
        self.assertFalse(v.allowed)
        self.assertIn("superseded", v.deny_code)

    def test_no_pin_degrades(self):
        v = code_version_pin(None, "2026-A", checked_at=T0)
        self.assertFalse(v.allowed)
        self.assertIn("unpinned", v.deny_code)


class CitationTest(unittest.TestCase):
    def _pin(self):
        return issue_code_pin(
            pin_id="pin-9", code_name="LGUC", code_version="2026-A",
            effective_from=T0, issuer_id="city-permit-office",
            issuer_secret=AUTH,
        )

    def test_bound_citation_authoritative(self):
        pin = self._pin()
        c = issue_normative_source(
            citation_id="cit-1", precheck_id="pc-9", code_name="LGUC",
            code_version="2026-A", provision="LGUC Art. 116",
            quoted_text="All structural drawings must be signed by a licensed engineer.",
            pin_id="pin-9", cited_at=T0, issuer_id="civcheck",
            issuer_secret=VENDOR,
        )
        v = normative_source_receipt("rec-1", "pc-9", c, pin)
        self.assertTrue(v.allowed)

    def test_no_citation_degrades(self):
        v = normative_source_receipt("rec-2", "pc-9", None, None)
        self.assertFalse(v.allowed)
        self.assertIn("uncited", v.deny_code)

    def test_citation_for_other_precheck_degrades(self):
        pin = self._pin()
        c = issue_normative_source(
            citation_id="cit-2", precheck_id="pc-other", code_name="LGUC",
            code_version="2026-A", provision="LGUC Art. 116",
            quoted_text="quote", pin_id="pin-9", cited_at=T0,
            issuer_id="civcheck", issuer_secret=VENDOR,
        )
        v = normative_source_receipt("rec-3", "pc-9", c, pin)
        self.assertFalse(v.allowed)


class DisparityTest(unittest.TestCase):
    def test_balanced_rates_pass(self):
        r = issue_disparity_probe(
            probe_id="dp-1", model_digest=HEX,
            slice_labels=["north", "south", "east"],
            slice_flag_rates=[0.10, 0.12, 0.11],
            measured_at=T0, expires_at=T0 + 10_000,
            vendor_id="civcheck", vendor_secret=VENDOR,
        )
        v = disparate_impact_probe(r, checked_at=T0 + 100)
        self.assertTrue(v.allowed)
        self.assertEqual(v.audit_code, "")

    def test_skewed_rates_trigger_audit(self):
        r = issue_disparity_probe(
            probe_id="dp-2", model_digest=HEX,
            slice_labels=["affluent", "low-income"],
            slice_flag_rates=[0.08, 0.30],
            measured_at=T0, expires_at=T0 + 10_000,
            vendor_id="civcheck", vendor_secret=VENDOR,
        )
        v = disparate_impact_probe(r, checked_at=T0 + 100)
        self.assertFalse(v.allowed)
        self.assertIn("disparate_impact_audit", v.audit_code)
        self.assertGreater(v.max_ratio, 2.0)

    def test_expired_probe_fails_closed(self):
        r = issue_disparity_probe(
            probe_id="dp-3", model_digest=HEX,
            slice_labels=["a", "b"],
            slice_flag_rates=[0.10, 0.11],
            measured_at=T0, expires_at=T0 + 10,
            vendor_id="civcheck", vendor_secret=VENDOR,
        )
        v = disparate_impact_probe(r, checked_at=T0 + 100_000)
        self.assertFalse(v.allowed)

    def test_empty_slices_raise(self):
        with self.assertRaises(PermitError):
            issue_disparity_probe(
                probe_id="dp-4", model_digest=HEX,
                slice_labels=[], slice_flag_rates=[],
                measured_at=T0, expires_at=T0 + 10,
                vendor_id="civcheck", vendor_secret=VENDOR,
            )


class AppealTest(unittest.TestCase):
    def test_bound_appeal_path_allows(self):
        a = issue_appeal_path(
            path_id="ap-1", decision_id="dec-1",
            decision_kind="building_permit",
            appeals_reviewer_name="Chen Mei",
            appeal_deadline=T0 + 30 * 86400,
            appeal_contact="appeals@example.gov",
            issued_at=T0, authority_id="city-permit-office",
            issuer_secret=AUTH,
        )
        v = appeal_window_gate("dec-1", a, checked_at=T0 + 1000)
        self.assertTrue(v.allowed)

    def test_no_appeal_path_denies(self):
        v = appeal_window_gate("dec-2", None, checked_at=T0)
        self.assertFalse(v.allowed)
        self.assertIn("no_appeal", v.deny_code)

    def test_expired_window_denies(self):
        a = issue_appeal_path(
            path_id="ap-2", decision_id="dec-3",
            decision_kind="zoning_variance",
            appeals_reviewer_name="Chen Mei",
            appeal_deadline=T0 + 100,
            appeal_contact="appeals@example.gov",
            issued_at=T0, authority_id="city-permit-office",
            issuer_secret=AUTH,
        )
        v = appeal_window_gate("dec-3", a, checked_at=T0 + 100_000)
        self.assertFalse(v.allowed)


class BiasClockTest(unittest.TestCase):
    def test_healthy_override_rate_clears(self):
        w = OverrideWindow("w-1", overridden=8, total=100, observed_at=T0)
        v = automation_bias_clock(w)
        self.assertFalse(v.audit_required)

    def test_zero_override_triggers_audit(self):
        w = OverrideWindow("w-2", overridden=0, total=100, observed_at=T0)
        v = automation_bias_clock(w)
        self.assertTrue(v.audit_required)
        self.assertIn("automation_bias_audit", v.audit_code)

    def test_insufficient_observation_triggers_audit(self):
        w = OverrideWindow("w-3", overridden=0, total=5, observed_at=T0)
        v = automation_bias_clock(w)
        self.assertTrue(v.audit_required)


class VendorCostTest(unittest.TestCase):
    def test_declared_cost_allows(self):
        reg = _authorities()
        r = issue_vendor_cost(
            receipt_id="vc-1", vendor_id="civcheck", contract_years=5,
            total_cost_cents=460_000_000, exit_assistance_disclosed=True,
            contract_digest=HEX, issued_at=T0,
            authority_id="city-permit-office", issuer_secret=AUTH,
        )
        v = vendor_cost_receipt(r, reg)
        self.assertTrue(v.allowed)

    def test_undeclared_exit_assistance_raises(self):
        with self.assertRaises(PermitError):
            issue_vendor_cost(
                receipt_id="vc-2", vendor_id="civcheck", contract_years=5,
                total_cost_cents=460_000_000, exit_assistance_disclosed=False,
                contract_digest=HEX, issued_at=T0,
                authority_id="city-permit-office", issuer_secret=AUTH,
            )

    def test_unknown_authority_denies(self):
        reg = AuthorityRegistry()
        r = issue_vendor_cost(
            receipt_id="vc-3", vendor_id="civcheck", contract_years=5,
            total_cost_cents=460_000_000, exit_assistance_disclosed=True,
            contract_digest=HEX, issued_at=T0,
            authority_id="city-permit-office", issuer_secret=AUTH,
        )
        v = vendor_cost_receipt(r, reg)
        self.assertFalse(v.allowed)


class TamperedSignatureTest(unittest.TestCase):
    """ed25519.verify returns bool and never raises — the return value must be
    used. A tampered signature must verify as False, not silently pass."""

    def test_verify_sig_accepts_valid_rejects_tampered(self):
        seed = b"\x0d" * 32
        pub_hex = ed25519.public_key(seed).hex()
        msg = jcs_canonical_json({"application_id": "app-tamper", "outcome": "flag"})
        sig_hex = ed25519.sign(seed, msg).hex()
        self.assertTrue(_verify_sig(pub_hex, msg, sig_hex))
        self.assertFalse(_verify_sig(pub_hex, msg, "00" * 64))


if __name__ == "__main__":
    unittest.main()
