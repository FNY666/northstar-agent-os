"""Tests for finance_agents.py (one-hundred-fifty-fifth batch)."""

import hashlib
import sys
import unittest

sys.path.insert(0, ".")  # run from components/northstar-agent-runtime

import ed25519
from finance_agents import (
    AdverseActionRegistry,
    AuthorityRegistry,
    ClosureNoticeRegistry,
    DecisionRoutingRegistry,
    FinanceError,
    FreezeRegistry,
    FraudFlag,
    HighImpactRegistry,
    HumanReviewReceipt,
    LaneDeclaration,
    ModelProxyAuditRegistry,
    PremiumExplanationRegistry,
    PricingEvaluationLog,
    SharedMarkerAppealRegistry,
    TippingOffBarRegistry,
    adverse_action_receipt,
    closure_notice_receipt,
    debanking_share_guard,
    flag_is_not_guilt_gate,
    freeze_proportionality_gate,
    high_impact_registry,
    human_escalation_lane,
    premium_explanation_receipt,
    pricing_fairness_rules_layer,
    proxy_screen,
    tipping_off_boundary,
)

SEC = b"fi-bench-auth-" + b"0" * 18  # 32 bytes
assert len(SEC) == 32
PUB = ed25519.public_key(SEC).hex()
T0 = 1_800_000_000
HEX64 = "ab" * 32
HEX64_B = "cd" * 32
UK_CUTOFF = 1_746_700_800  # 2026-04-28 00:00:00 UTC


def _auth() -> AuthorityRegistry:
    reg = AuthorityRegistry()
    reg.register("bench-fin-op", PUB)
    return reg


def _flag(**kw) -> FraudFlag:
    payload = {
        "schema": "northstar.finance.v1",
        "type": "fraud_flag",
        "flag_id": kw.get("flag_id", "fl-1"),
        "account_id": kw.get("account_id", "acct-1"),
        "model_id": kw.get("model_id", "mule-model-v2"),
        "false_positive_bps": kw.get("false_positive_bps", 1200),
        "raised_at": kw.get("raised_at", T0),
        "authority_id": "bench-fin-op",
        "authority_pubkey_hex": PUB,
    }
    sig_body = dict(payload)
    from canonical_json import jcs_canonical_json

    sig = ed25519.sign(SEC, jcs_canonical_json(sig_body)).hex()
    return FraudFlag(
        flag_id=payload["flag_id"],
        account_id=payload["account_id"],
        model_id=payload["model_id"],
        false_positive_bps=payload["false_positive_bps"],
        raised_at=payload["raised_at"],
        authority_id="bench-fin-op",
        authority_pubkey_hex=PUB,
        signature_hex=sig,
    )


def _review(flag_id: str, decision: str = "uphold") -> HumanReviewReceipt:
    return HumanReviewReceipt(
        review_id="rv-1",
        flag_id=flag_id,
        reviewer_id="officer-7",
        reviewed_at=T0 + 3600,
        decision=decision,
        authority_pubkey_hex=PUB,
        signature_hex="00" * 128,
    )


class ClosureNoticeTests(unittest.TestCase):
    def test_notice_ok_new_account(self):
        auth = _auth()
        notices = ClosureNoticeRegistry(auth)
        bars = TippingOffBarRegistry(auth)
        notices.issue(
            "n1", "acct-1", HEX64, 95, T0, UK_CUTOFF + 100,
            "bench-fin-op", SEC,
        )
        v = closure_notice_receipt(notices, bars, "n1", T0 + 95 * 86400, UK_CUTOFF)
        self.assertTrue(v.allowed)

    def test_short_notice_denied(self):
        auth = _auth()
        notices = ClosureNoticeRegistry(auth)
        bars = TippingOffBarRegistry(auth)
        notices.issue(
            "n2", "acct-2", HEX64, 30, T0, UK_CUTOFF + 100,
            "bench-fin-op", SEC,
        )
        v = closure_notice_receipt(notices, bars, "n2", T0 + 30 * 86400, UK_CUTOFF)
        self.assertFalse(v.allowed)
        self.assertIn("finance:short_notice_closure", v.reason)

    def test_short_notice_with_bar_receipt_allowed(self):
        auth = _auth()
        notices = ClosureNoticeRegistry(auth)
        bars = TippingOffBarRegistry(auth)
        notices.issue(
            "n3", "acct-3", HEX64, 7, T0, UK_CUTOFF + 100,
            "bench-fin-op", SEC,
        )
        bars.issue("b1", "acct-3", "s.333A Proceeds of Crime Act 2002",
                   T0, "bench-fin-op", SEC)
        v = closure_notice_receipt(notices, bars, "n3", T0 + 7 * 86400, UK_CUTOFF)
        self.assertTrue(v.allowed)

    def test_no_notice_denied(self):
        auth = _auth()
        notices = ClosureNoticeRegistry(auth)
        bars = TippingOffBarRegistry(auth)
        v = closure_notice_receipt(notices, bars, "nope", T0, UK_CUTOFF)
        self.assertFalse(v.allowed)
        self.assertIn("finance:no_closure_notice", v.reason)

    def test_old_account_60_days_enough(self):
        auth = _auth()
        notices = ClosureNoticeRegistry(auth)
        bars = TippingOffBarRegistry(auth)
        notices.issue(
            "n4", "acct-4", HEX64, 60, T0, UK_CUTOFF - 100,
            "bench-fin-op", SEC,
        )
        v = closure_notice_receipt(notices, bars, "n4", T0 + 60 * 86400, UK_CUTOFF)
        self.assertTrue(v.allowed)


class FreezeTests(unittest.TestCase):
    def _issue(self, **kw):
        auth = _auth()
        freezes = FreezeRegistry(auth)
        params = dict(
            receipt_id="fz-1", account_id="acct-1",
            disputed_amount_minor=50_000, frozen_amount_minor=50_000,
            account_balance_minor=500_000, hold_started_at=T0,
            rebuttal_deadline=T0 + 21 * 86400, review_completed_at=T0 + 8 * 86400,
            whole_account_frozen=False, authority_id="bench-fin-op",
            authority_secret=SEC,
        )
        params.update(kw)
        return freezes, freezes.issue(**params)

    def test_proportional_freeze_allowed(self):
        freezes, _ = self._issue()
        v = freeze_proportionality_gate(freezes, "fz-1", T0 + 10 * 86400)
        self.assertTrue(v.allowed)

    def test_disproportionate_freeze_denied(self):
        freezes, _ = self._issue(whole_account_frozen=True,
                                 frozen_amount_minor=500_000)
        v = freeze_proportionality_gate(freezes, "fz-1", T0 + 10 * 86400)
        self.assertFalse(v.allowed)
        self.assertIn("finance:disproportionate_freeze", v.reason)

    def test_hold_overdue_denied(self):
        freezes, _ = self._issue()
        v = freeze_proportionality_gate(freezes, "fz-1", T0 + 61 * 86400)
        self.assertFalse(v.allowed)
        self.assertIn("finance:hold_overdue", v.reason)

    def test_short_rebuttal_denied(self):
        freezes, _ = self._issue(rebuttal_deadline=T0 + 10 * 86400)
        v = freeze_proportionality_gate(freezes, "fz-1", T0 + 5 * 86400)
        self.assertFalse(v.allowed)
        self.assertIn("finance:short_rebuttal", v.reason)

    def test_late_review_denied(self):
        freezes, _ = self._issue(review_completed_at=T0 + 15 * 86400)
        v = freeze_proportionality_gate(freezes, "fz-1", T0 + 20 * 86400)
        self.assertFalse(v.allowed)
        self.assertIn("finance:late_review", v.reason)


class FlagTests(unittest.TestCase):
    def test_lead_action_allowed(self):
        v = flag_is_not_guilt_gate(_flag(), "queue_review", None, T0 + 10)
        self.assertTrue(v.allowed)

    def test_account_action_without_review_denied(self):
        v = flag_is_not_guilt_gate(_flag(), "close_account", None, T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("finance:no_human_review", v.reason)

    def test_account_action_with_review_allowed(self):
        v = flag_is_not_guilt_gate(_flag(), "freeze_account",
                                   _review("fl-1"), T0 + 10)
        self.assertTrue(v.allowed)

    def test_undisclosed_fp_denied(self):
        v = flag_is_not_guilt_gate(_flag(false_positive_bps=0), "close_account",
                                   _review("fl-1"), T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("finance:fp_undisclosed", v.reason)

    def test_tampered_flag_signature_denied(self):
        flag = _flag()
        bad = FraudFlag(**{**flag.__dict__, "signature_hex": "ff" * 64})
        v = flag_is_not_guilt_gate(bad, "close_account", _review("fl-1"), T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("finance:flag_sig_invalid", v.reason)

    def test_review_mismatch_denied(self):
        v = flag_is_not_guilt_gate(_flag(flag_id="fl-9"), "close_account",
                                   _review("fl-1"), T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("finance:review_mismatch", v.reason)


class ProxyScreenTests(unittest.TestCase):
    def _audit(self, **kw):
        auth = _auth()
        reg = ModelProxyAuditRegistry(auth)
        params = dict(
            audit_id="pa-1", model_id="score-v3", model_version="2026.1",
            declared_features=("income_bps", "delinquency_count"),
            proxy_features_removed=True, less_discriminatory_alternative=False,
            audited_at=T0, authority_id="bench-fin-op", authority_secret=SEC,
        )
        params.update(kw)
        return reg, reg.issue(**params)

    def test_clean_model_allowed(self):
        reg, _ = self._audit()
        v = proxy_screen(reg, "score-v3", "2026.1", T0 + 10)
        self.assertTrue(v.allowed)

    def test_proxy_without_removal_or_lda_denied(self):
        reg, _ = self._audit(
            declared_features=("income_bps", "postal_code"),
            proxy_features_removed=False,
        )
        v = proxy_screen(reg, "score-v3", "2026.1", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("finance:proxy_feature", v.reason)

    def test_proxy_with_lda_allowed(self):
        reg, _ = self._audit(
            declared_features=("income_bps", "postal_code"),
            proxy_features_removed=False,
            less_discriminatory_alternative=True,
        )
        v = proxy_screen(reg, "score-v3", "2026.1", T0 + 10)
        self.assertTrue(v.allowed)

    def test_no_audit_denied(self):
        reg = ModelProxyAuditRegistry(_auth())
        v = proxy_screen(reg, "score-v3", "2026.1", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("finance:no_proxy_audit", v.reason)


class AdverseActionTests(unittest.TestCase):
    def _issue(self, **kw):
        auth = _auth()
        reg = AdverseActionRegistry(auth)
        params = dict(
            receipt_id="aa-1", subject_id="appl-1", decision="decline",
            reasons=("insufficient credit history", "high utilization ratio"),
            decided_at=T0, disputable=True, authority_id="bench-fin-op",
            authority_secret=SEC,
        )
        params.update(kw)
        return reg, reg.issue(**params)

    def test_specific_reasons_allowed(self):
        reg, _ = self._issue()
        v = adverse_action_receipt(reg, "aa-1", T0 + 10)
        self.assertTrue(v.allowed)

    def test_vague_reason_denied(self):
        reg, _ = self._issue(reasons=("model output",))
        v = adverse_action_receipt(reg, "aa-1", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("finance:vague_reason", v.reason)

    def test_missing_receipt_denied(self):
        reg = AdverseActionRegistry(_auth())
        v = adverse_action_receipt(reg, "ghost", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("finance:no_adverse_action", v.reason)

    def test_non_disputable_denied(self):
        reg, _ = self._issue(disputable=False)
        v = adverse_action_receipt(reg, "aa-1", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("finance:non_disputable", v.reason)


class PricingRulesTests(unittest.TestCase):
    def _log(self, disparity: bool) -> PricingEvaluationLog:
        log = PricingEvaluationLog()
        for i in range(10):
            log.record(f"e-b-{i}", "price-v2", "UK", 1200,
                       False, False, T0 + i)
        for i in range(10):
            quoted = 1380 if disparity else 1210
            log.record(f"e-p-{i}", "price-v2", "UK", quoted,
                       True, False, T0 + 100 + i)
        return log

    def test_within_disparity_allowed(self):
        v = pricing_fairness_rules_layer(self._log(False), "price-v2", "UK",
                                         1210, 1200)
        self.assertTrue(v.allowed)

    def test_over_disparity_denied(self):
        v = pricing_fairness_rules_layer(self._log(True), "price-v2", "UK",
                                         1380, 1200)
        self.assertFalse(v.allowed)
        self.assertIn("finance:proxy_pricing_disparity", v.reason)

    def test_empty_log_denied(self):
        v = pricing_fairness_rules_layer(PricingEvaluationLog(), "price-v2",
                                         "UK", 1200, 1200)
        self.assertFalse(v.allowed)
        self.assertIn("finance:no_pricing_log", v.reason)


class DebankingTests(unittest.TestCase):
    def test_refusal_without_appeal_denied(self):
        appeals = SharedMarkerAppealRegistry(_auth())
        v = debanking_share_guard(appeals, "cust-1", "ukf-marker", True)
        self.assertFalse(v.allowed)
        self.assertIn("finance:systemic_exclusion", v.reason)

    def test_refusal_with_appeal_allowed(self):
        auth = _auth()
        appeals = SharedMarkerAppealRegistry(auth)
        appeals.issue(
            "ap-1", "cust-1", "ukf-marker", HEX64, "ombudsman-portal",
            T0, False, "bench-fin-op", SEC,
        )
        v = debanking_share_guard(appeals, "cust-1", "ukf-marker", True)
        self.assertTrue(v.allowed)

    def test_no_refusal_allowed(self):
        appeals = SharedMarkerAppealRegistry(_auth())
        v = debanking_share_guard(appeals, "cust-9", "ukf-marker", False)
        self.assertTrue(v.allowed)


class HighImpactTests(unittest.TestCase):
    def test_shadow_ai_denied(self):
        v = high_impact_registry(HighImpactRegistry(_auth()), "score-v9",
                                 "credit_scoring", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("finance:shadow_ai", v.reason)

    def test_registered_model_allowed(self):
        auth = _auth()
        reg = HighImpactRegistry(auth)
        reg.issue("c-1", "score-v3", "credit_scoring",
                  ("model-card", "fairness-report"), T0, "bench-fin-op", SEC)
        v = high_impact_registry(reg, "score-v3", "credit_scoring", T0 + 10)
        self.assertTrue(v.allowed)

    def test_stale_registration_denied(self):
        auth = _auth()
        reg = HighImpactRegistry(auth)
        reg.issue("c-2", "score-v4", "credit_scoring",
                  ("model-card",), T0, "bench-fin-op", SEC)
        v = high_impact_registry(reg, "score-v4", "credit_scoring",
                                 T0 + 400 * 86400)
        self.assertFalse(v.allowed)
        self.assertIn("finance:stale_registration", v.reason)


class EscalationLaneTests(unittest.TestCase):
    def _routing(self, lane: str) -> DecisionRoutingRegistry:
        auth = _auth()
        reg = DecisionRoutingRegistry(auth)
        reg.issue("dr-1", "appl-1", "decline", lane, T0,
                  "bench-fin-op", SEC)
        return reg

    def test_auto_with_lane_allowed(self):
        decl = LaneDeclaration("dep-1", ("auto_accept", "auto_decline",
                                         "escalate_to_officer"))
        v = human_escalation_lane(decl, self._routing("auto_decline"), "dr-1")
        self.assertTrue(v.allowed)

    def test_no_human_lane_denied(self):
        decl = LaneDeclaration("dep-2", ("auto_accept", "auto_decline"))
        v = human_escalation_lane(decl, self._routing("auto_decline"), "dr-1")
        self.assertFalse(v.allowed)
        self.assertIn("finance:no_human_lane", v.reason)

    def test_undeclared_lane_denied(self):
        decl = LaneDeclaration("dep-3", ("auto_accept", "escalate_to_officer"))
        v = human_escalation_lane(decl, self._routing("auto_decline"), "dr-1")
        self.assertFalse(v.allowed)
        self.assertIn("finance:undeclared_lane", v.reason)


class PremiumTests(unittest.TestCase):
    def _issue(self, **kw):
        auth = _auth()
        reg = PremiumExplanationRegistry(auth)
        params = dict(
            receipt_id="pe-1", quote_id="q-1", premium_minor=120_000,
            key_factors=("postcode risk band", "vehicle group"),
            yoy_change_bps=800, yoy_change_explained=True,
            quoted_at=T0, authority_id="bench-fin-op",
            authority_secret=SEC,
        )
        params.update(kw)
        return reg, reg.issue(**params)

    def test_explained_quote_allowed(self):
        reg, _ = self._issue()
        v = premium_explanation_receipt(reg, "pe-1", T0 + 10)
        self.assertTrue(v.allowed)

    def test_missing_receipt_denied(self):
        reg = PremiumExplanationRegistry(_auth())
        v = premium_explanation_receipt(reg, "ghost", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("finance:premium_unexplained", v.reason)

    def test_unexplained_change_denied(self):
        reg, _ = self._issue(yoy_change_explained=False)
        v = premium_explanation_receipt(reg, "pe-1", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("finance:unexplained_change", v.reason)


class TippingOffTests(unittest.TestCase):
    def test_barred_silence_allowed(self):
        auth = _auth()
        bars = TippingOffBarRegistry(auth)
        bars.issue("tb-1", "acct-1", "s.333A", T0, "bench-fin-op", SEC)
        v = tipping_off_boundary(bars, "acct-1", False)
        self.assertTrue(v.allowed)

    def test_unbarred_silence_denied(self):
        bars = TippingOffBarRegistry(_auth())
        v = tipping_off_boundary(bars, "acct-2", False)
        self.assertFalse(v.allowed)
        self.assertIn("finance:silent_bar", v.reason)

    def test_bar_violated_denied(self):
        auth = _auth()
        bars = TippingOffBarRegistry(auth)
        bars.issue("tb-2", "acct-3", "s.333A", T0, "bench-fin-op", SEC)
        v = tipping_off_boundary(bars, "acct-3", True)
        self.assertFalse(v.allowed)
        self.assertIn("finance:bar_violated", v.reason)


if __name__ == "__main__":
    unittest.main()
