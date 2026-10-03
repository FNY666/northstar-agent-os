"""Tests for insurance.py (one-hundred-twenty-fifth batch)."""

import unittest

import insurance
from insurance import InsuranceError


def _secret(seed: int = 1) -> bytes:
    return bytes([(seed + i) % 256 or 1 for i in range(32)])


def _hex64(ch: str = "ab") -> str:
    return ch * 32


def _make_denial(
    *,
    claim_id="c1",
    ai_involved=False,
    reasons=("Policy exclusion 4.2: flood not covered",),
    denied_at=1000,
    secret=None,
):
    return insurance.issue_denial_receipt(
        denial_id="d-" + claim_id,
        claim_id=claim_id,
        policy_id="p1",
        decision_kind="claims_adjudication",
        human_reviewer_id="rev1",
        reviewer_secret=secret or _secret(1),
        reasons=reasons,
        evidence_pack_digest=_hex64("ab"),
        ai_involved=ai_involved,
        denied_at=denied_at,
    )


def _make_proxy_probe(*, feature="zip_code", model_digest=None, measured_at=1000, expires_at=2000, secret=None):
    return insurance.issue_proxy_probe(
        probe_id="pp-" + feature,
        model_digest=model_digest or _hex64("cd"),
        feature=feature,
        probe_digest=_hex64("ef"),
        authority_id="naic",
        authority_secret=secret or _secret(3),
        measured_at=measured_at,
        expires_at=expires_at,
    )


def _make_admission(*, model_digest=None, admitted_at=1000, expires_at=5000, secret=None):
    return insurance.issue_high_risk_admission(
        admission_id="adm1",
        model_digest=model_digest or _hex64("12"),
        use_kind="underwriting",
        committee_approval_digest=_hex64("34"),
        supervision_declaration="human review at every adverse node",
        filing_digest=_hex64("56"),
        stop_conditions=("kill switch A", "manual override B"),
        authority_id="regulator",
        authority_secret=secret or _secret(5),
        admitted_at=admitted_at,
        expires_at=expires_at,
    )


def _make_vendor(*, vendor_id="v1", model_digest=None, admitted_at=1000, expires_at=5000, secret=None):
    return insurance.issue_vendor_admission(
        vendor_id=vendor_id,
        insurer_id="ins1",
        model_digest=model_digest or _hex64("78"),
        audit_rights_digest=_hex64("9a"),
        bias_test_digest=_hex64("bc"),
        authority_id="regulator",
        authority_secret=secret or _secret(7),
        admitted_at=admitted_at,
        expires_at=expires_at,
    )


def _make_appeals(model_digest, overturned_flags, start=1000):
    records, prev = [], "genesis"
    for i, ov in enumerate(overturned_flags):
        r = insurance.record_appeal(
            appeal_id=f"a{i}",
            claim_id=f"c{i}",
            model_digest=model_digest,
            overturned=ov,
            decided_at=start + i,
            prev_digest=prev,
        )
        records.append(r)
        prev = r.appeal_digest
    return records


class DenialReceiptTests(unittest.TestCase):
    def test_human_signed_denial_allows(self):
        d = _make_denial()
        v = insurance.denial_receipt([d], claim_id="c1", check_time=2000)
        self.assertTrue(v.allowed)
        self.assertEqual(v.denial_id, "d-c1")

    def test_no_receipt_denies(self):
        v = insurance.denial_receipt([], claim_id="c1", check_time=2000)
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, insurance.DENY_NO_COUNTERSIGN)

    def test_ai_involved_requires_human_escalation(self):
        d = _make_denial(claim_id="c2", ai_involved=True)
        v = insurance.denial_receipt([d], claim_id="c2", check_time=2000)
        self.assertFalse(v.allowed)
        self.assertTrue(v.requires_human_escalation)
        self.assertEqual(v.reason, insurance.DENY_AI_ONLY)

    def test_vague_reason_raises_at_issuance(self):
        with self.assertRaises(InsuranceError):
            _make_denial(reasons=("model output",))

    def test_tampered_denial_denies(self):
        d = _make_denial()
        tampered = insurance.DenialReceipt(
            **{**d.__dict__, "reasons": ("something else",)}
        )
        v = insurance.denial_receipt([tampered], claim_id="c1", check_time=2000)
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, insurance.DENY_DENIAL_TAMPERED)

    def test_wrong_claim_receipt_ignored(self):
        d = _make_denial(claim_id="other")
        v = insurance.denial_receipt([d], claim_id="c1", check_time=2000)
        self.assertFalse(v.allowed)

    def test_denial_audit_event_shape(self):
        d = _make_denial()
        v = insurance.denial_receipt([d], claim_id="c1", check_time=2000)
        ev = insurance.denial_audit_event(v, action="deny_claim")
        self.assertEqual(ev["event"], insurance.DENIAL_ALLOWED_EVENT)
        self.assertTrue(ev["allowed"])


class DisclosureTests(unittest.TestCase):
    def test_disclosed_ai_allows(self):
        dis = insurance.issue_ai_disclosure(
            decision_id="dec1", decision_digest=_hex64("cd"), ai_involved=True, disclosed_at=900
        )
        v = insurance.ai_involvement_disclosure(
            [dis], decision_id="dec1", decision_digest=_hex64("cd"),
            ai_actually_involved=True, check_time=2000,
        )
        self.assertTrue(v.allowed)

    def test_hidden_ai_denies(self):
        v = insurance.ai_involvement_disclosure(
            [], decision_id="dec1", decision_digest=_hex64("cd"),
            ai_actually_involved=True, check_time=2000,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, insurance.DENY_HIDDEN_AI)

    def test_no_ai_involved_allows_without_disclosure(self):
        v = insurance.ai_involvement_disclosure(
            [], decision_id="dec1", decision_digest=_hex64("cd"),
            ai_actually_involved=False, check_time=2000,
        )
        self.assertTrue(v.allowed)

    def test_swapped_digest_denies(self):
        dis = insurance.issue_ai_disclosure(
            decision_id="dec1", decision_digest=_hex64("cd"), ai_involved=True, disclosed_at=900
        )
        v = insurance.ai_involvement_disclosure(
            [dis], decision_id="dec1", decision_digest=_hex64("ff"),
            ai_actually_involved=True, check_time=2000,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, insurance.DENY_DISCLOSURE_DIGEST_MISMATCH)


class TripwireTests(unittest.TestCase):
    def test_tripwire_fires_at_threshold(self):
        md = _hex64("aa")
        recs = _make_appeals(md, [True] * 15 + [False] * 9)
        tw = insurance.appeal_overturn_tripwire(recs, model_digest=md)
        self.assertTrue(tw.suspended)
        self.assertEqual(tw.reason, insurance.DENY_SUSPENDED)

    def test_tripwire_below_threshold(self):
        md = _hex64("bb")
        recs = _make_appeals(md, [True] * 5 + [False] * 19)
        tw = insurance.appeal_overturn_tripwire(recs, model_digest=md)
        self.assertFalse(tw.suspended)

    def test_tripwire_needs_minimum_appeals(self):
        md = _hex64("cc")
        recs = _make_appeals(md, [True] * 10)
        tw = insurance.appeal_overturn_tripwire(recs, model_digest=md)
        self.assertFalse(tw.suspended)
        self.assertEqual(tw.reason, "insufficient-appeals")

    def test_tampered_appeal_log_is_fail_closed(self):
        md = _hex64("dd")
        recs = _make_appeals(md, [False] * 24)
        tampered = insurance.AppealRecord(
            **{**recs[0].__dict__, "overturned": True}
        )
        tw = insurance.appeal_overturn_tripwire([tampered] + recs[1:], model_digest=md)
        self.assertTrue(tw.suspended)


class ProxyProbeTests(unittest.TestCase):
    def test_probed_proxy_allows(self):
        md = _hex64("cd")
        probe = _make_proxy_probe(model_digest=md)
        v = insurance.proxy_discrimination_probe(
            [probe], model_digest=md, features=["zip_code"], check_time=1500
        )
        self.assertTrue(v.allowed)

    def test_unprobed_proxy_denies(self):
        md = _hex64("cd")
        v = insurance.proxy_discrimination_probe(
            [], model_digest=md, features=["zip_code"], check_time=1500
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, insurance.DENY_PROXY)

    def test_expired_probe_denies(self):
        md = _hex64("cd")
        probe = _make_proxy_probe(model_digest=md, measured_at=1000, expires_at=1200)
        v = insurance.proxy_discrimination_probe(
            [probe], model_digest=md, features=["zip_code"], check_time=1500
        )
        self.assertFalse(v.allowed)

    def test_unknown_proxy_feature_raises(self):
        with self.assertRaises(InsuranceError):
            _make_proxy_probe(feature="star_sign")


class HighRiskGateTests(unittest.TestCase):
    def test_full_admission_allows(self):
        md = _hex64("12")
        adm = _make_admission(model_digest=md)
        v = insurance.high_risk_gate(
            [adm], model_digest=md, use_kind="underwriting", check_time=2000
        )
        self.assertTrue(v.allowed)

    def test_no_admission_denies(self):
        v = insurance.high_risk_gate(
            [], model_digest=_hex64("12"), use_kind="underwriting", check_time=2000
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, insurance.DENY_HIGH_RISK_UNADMITTED)

    def test_empty_stop_conditions_raise(self):
        with self.assertRaises(InsuranceError):
            insurance.issue_high_risk_admission(
                admission_id="adm2", model_digest=_hex64("12"), use_kind="pricing",
                committee_approval_digest=_hex64("34"),
                supervision_declaration="x", filing_digest=_hex64("56"),
                stop_conditions=[], authority_id="r",
                authority_secret=_secret(5), admitted_at=1000, expires_at=5000,
            )

    def test_expired_admission_denies(self):
        md = _hex64("12")
        adm = _make_admission(model_digest=md, admitted_at=1000, expires_at=1500)
        v = insurance.high_risk_gate(
            [adm], model_digest=md, use_kind="underwriting", check_time=2000
        )
        self.assertFalse(v.allowed)


class FraudGateTests(unittest.TestCase):
    def test_score_only_denies(self):
        req = insurance.FraudDenialRequest(
            request_id="r1", claim_id="c1", fraud_score_digest=_hex64("de"),
            human_review_digest=None, evidence_digest=None,
        )
        v = insurance.fraud_signal_gate(req)
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, insurance.DENY_FRAUD_SCORE_ONLY)

    def test_score_plus_human_plus_evidence_allows(self):
        req = insurance.FraudDenialRequest(
            request_id="r1", claim_id="c1", fraud_score_digest=_hex64("de"),
            human_review_digest=_hex64("ad"), evidence_digest=_hex64("be"),
        )
        v = insurance.fraud_signal_gate(req)
        self.assertTrue(v.allowed)

    def test_score_without_evidence_denies(self):
        req = insurance.FraudDenialRequest(
            request_id="r1", claim_id="c1", fraud_score_digest=_hex64("de"),
            human_review_digest=_hex64("ad"), evidence_digest=None,
        )
        v = insurance.fraud_signal_gate(req)
        self.assertFalse(v.allowed)


class VendorLiabilityTests(unittest.TestCase):
    def test_admitted_vendor_allows_with_insurer_liable(self):
        md = _hex64("78")
        adm = _make_vendor(model_digest=md)
        v = insurance.vendor_liability(
            [adm], vendor_id="v1", model_digest=md, check_time=2000
        )
        self.assertTrue(v.allowed)
        self.assertEqual(v.liable_party, "insurer")

    def test_unadmitted_vendor_denies(self):
        v = insurance.vendor_liability(
            [], vendor_id="v1", model_digest=_hex64("78"), check_time=2000
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, insurance.DENY_VENDOR_NO_AUDIT)


class DarkPatternTests(unittest.TestCase):
    def test_clean_flow_allows(self):
        v = insurance.dark_pattern_gate([])
        self.assertTrue(v.allowed)

    def test_dark_pattern_denies_and_names_markers(self):
        v = insurance.dark_pattern_gate(["false_urgency", "hidden_opt_out"])
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, insurance.DENY_DARK_PATTERN)
        self.assertEqual(v.markers_found, ("false_urgency", "hidden_opt_out"))

    def test_unknown_marker_raises(self):
        with self.assertRaises(InsuranceError):
            insurance.dark_pattern_gate(["subliminal_messaging"])


if __name__ == "__main__":
    unittest.main()
