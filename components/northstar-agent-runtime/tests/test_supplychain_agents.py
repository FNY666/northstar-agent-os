"""Tests for supplychain_agents (one-hundred-forty-fourth batch)."""

import unittest

from ed25519 import public_key as _pub  # noqa: E402

from supplychain_agents import (
    AlarmBudgetRegistry,
    AuthorityRegistry,
    ConcentrationProbe,
    DecisionRegistry,
    DeskillingRegistry,
    LaborProbe,
    RiskScoreRegistry,
    ScenarioRegistry,
    SupplyChainAgentsError,
    SupplyChainVerdict,
    VendorClaimRegistry,
    algorithmic_labor_probe,
    check_alarm_budget,
    concentration_probe,
    deskilling_clock,
    human_final_gate,
    issue_alarm_budget,
    issue_concentration_probe,
    issue_decision_approval,
    issue_deskilling_audit,
    issue_labor_probe,
    issue_risk_score,
    issue_scenario,
    issue_vendor_claim,
    risk_score_evidence,
    scenario_version_binding,
    supplychain_audit_event,
    vendor_claim_receipt,
)


def _sec(tag):
    return (b"sc-test-" + tag.encode() + b"0" * 32)[:32]


AUTH = _sec("authority")
OTHER = _sec("other")

AUTH_PUB = _pub(AUTH)
T0 = 1_800_000_000
HEX = "ab" * 32
HEX2 = "cd" * 32
HEX3 = "ef" * 32


def _auth():
    reg = AuthorityRegistry()
    reg.register("supply-chain-board", AUTH_PUB)
    return reg


def _approval(**kw):
    defaults = dict(
        decision_id="dec-1",
        decision_kind="reroute",
        ai_decision_digest=HEX,
        human_approver_id="supply-chain-board",
        approved_at=T0,
        approver_secret=AUTH,
    )
    defaults.update(kw)
    return issue_decision_approval(**defaults)


class HumanFinalGateTests(unittest.TestCase):
    def test_live_approval_allows(self):
        approvals = DecisionRegistry()
        approvals.record(_approval())
        v = human_final_gate(
            approvals, _auth(), decision_id="dec-1", decision_kind="reroute",
            ai_decision_digest=HEX, decided_at=T0 + 10,
            approver_id="supply-chain-board",
        )
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, "supplychain-authoritative")
        self.assertTrue(v.receipt_digest)

    def test_no_approval_denies_autonomous(self):
        v = human_final_gate(
            DecisionRegistry(), _auth(), decision_id="dec-ghost",
            decision_kind="reroute", ai_decision_digest=HEX,
            decided_at=T0 + 10, approver_id="supply-chain-board",
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "supplychain:autonomous_decision")
        self.assertEqual(v.classification, "supplychain-non-authoritative")

    def test_digest_mismatch_denies(self):
        approvals = DecisionRegistry()
        approvals.record(_approval())
        v = human_final_gate(
            approvals, _auth(), decision_id="dec-1", decision_kind="reroute",
            ai_decision_digest=HEX2, decided_at=T0 + 10,
            approver_id="supply-chain-board",
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "supplychain:decision_digest_mismatch")

    def test_approval_after_decision_denies(self):
        approvals = DecisionRegistry()
        approvals.record(_approval(approved_at=T0 + 100))
        v = human_final_gate(
            approvals, _auth(), decision_id="dec-1", decision_kind="reroute",
            ai_decision_digest=HEX, decided_at=T0 + 10,
            approver_id="supply-chain-board",
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "supplychain:autonomous_decision")

    def test_wrong_signer_denies(self):
        approvals = DecisionRegistry()
        approvals.record(_approval(approver_secret=OTHER))
        v = human_final_gate(
            approvals, _auth(), decision_id="dec-1", decision_kind="reroute",
            ai_decision_digest=HEX, decided_at=T0 + 10,
            approver_id="supply-chain-board",
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "supplychain:decision_signature_invalid")

    def test_closed_decision_kind_vocab(self):
        with self.assertRaises(SupplyChainAgentsError):
            issue_decision_approval(
                decision_id="dec-9", decision_kind="teleport",
                ai_decision_digest=HEX, human_approver_id="supply-chain-board",
                approved_at=T0, approver_secret=AUTH,
            )


class RiskScoreEvidenceTests(unittest.TestCase):
    def _score(self, **kw):
        defaults = dict(
            score_id="s-1", supplier_id="sup-1", score_bps=7500,
            warning_lead_days=91, false_positive_bps=1800,
            evidence_digest=HEX, measured_at=T0, expires_at=T0 + 86400,
            issuer_id="supply-chain-board", issuer_secret=AUTH,
        )
        defaults.update(kw)
        return issue_risk_score(**defaults)

    def test_live_evidence_allows(self):
        scores = RiskScoreRegistry()
        scores.record(self._score())
        v = risk_score_evidence(
            scores, _auth(), score_id="s-1", supplier_id="sup-1",
            used_at=T0 + 10, issuer_id="supply-chain-board",
        )
        self.assertTrue(v.allowed)

    def test_unknown_score_denies(self):
        v = risk_score_evidence(
            RiskScoreRegistry(), _auth(), score_id="s-ghost",
            supplier_id="sup-1", used_at=T0 + 10,
            issuer_id="supply-chain-board",
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "supplychain:no_risk_evidence")

    def test_expired_score_denies(self):
        scores = RiskScoreRegistry()
        scores.record(self._score(expires_at=T0 + 5))
        v = risk_score_evidence(
            scores, _auth(), score_id="s-1", supplier_id="sup-1",
            used_at=T0 + 10, issuer_id="supply-chain-board",
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "supplychain:no_risk_evidence")

    def test_bps_out_of_range_rejected(self):
        with self.assertRaises(SupplyChainAgentsError):
            self._score(false_positive_bps=10001)


class AlarmBudgetTests(unittest.TestCase):
    def _budget(self, **kw):
        defaults = dict(
            budget_id="b-1", channel_id="ch-1", budget_bps=2000,
            alerts_total=100, false_alerts=10,
            window_start=T0, window_end=T0 + 86400,
            issuer_id="supply-chain-board", issuer_secret=AUTH,
        )
        defaults.update(kw)
        return issue_alarm_budget(**defaults)

    def test_within_budget_allows(self):
        budgets = AlarmBudgetRegistry()
        budgets.record(self._budget())
        v = check_alarm_budget(
            budgets, _auth(), channel_id="ch-1", checked_at=T0 + 10,
            issuer_id="supply-chain-board",
        )
        self.assertTrue(v.allowed)

    def test_exceeded_budget_degrades(self):
        budgets = AlarmBudgetRegistry()
        budgets.record(self._budget(false_alerts=50))  # 5000bps > 2000bps
        v = check_alarm_budget(
            budgets, _auth(), channel_id="ch-1", checked_at=T0 + 10,
            issuer_id="supply-chain-board",
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "supplychain:false_alarm_budget_exceeded")

    def test_no_budget_fail_closed(self):
        v = check_alarm_budget(
            AlarmBudgetRegistry(), _auth(), channel_id="ch-ghost",
            checked_at=T0 + 10, issuer_id="supply-chain-board",
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "supplychain:no_alarm_budget")

    def test_false_alerts_exceeding_total_rejected(self):
        with self.assertRaises(SupplyChainAgentsError):
            self._budget(alerts_total=10, false_alerts=11)


class LaborProbeTests(unittest.TestCase):
    def _probe(self, **kw):
        defaults = dict(
            probe_id="p-1", workforce_id="wf-1",
            rest_minutes_counted_as_inefficiency=0,
            scan_rate_penalty_applied=False, toilet_break_penalized=False,
            measured_at=T0, expires_at=T0 + 86400,
            issuer_id="supply-chain-board", issuer_secret=AUTH,
        )
        defaults.update(kw)
        return issue_labor_probe(**defaults)

    def test_clean_probe_allows(self):
        v = algorithmic_labor_probe(
            self._probe(), _auth(), issuer_id="supply-chain-board",
            checked_at=T0 + 10,
        )
        self.assertTrue(v.allowed)

    def test_rest_counted_as_inefficiency_denies(self):
        v = algorithmic_labor_probe(
            self._probe(rest_minutes_counted_as_inefficiency=30),
            _auth(), issuer_id="supply-chain-board", checked_at=T0 + 10,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "supplychain.rest_violation")

    def test_scan_rate_penalty_denies(self):
        v = algorithmic_labor_probe(
            self._probe(scan_rate_penalty_applied=True),
            _auth(), issuer_id="supply-chain-board", checked_at=T0 + 10,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "supplychain.rest_violation")

    def test_stale_probe_denies(self):
        v = algorithmic_labor_probe(
            self._probe(expires_at=T0 + 5),
            _auth(), issuer_id="supply-chain-board", checked_at=T0 + 10,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "supplychain:probe_stale")

    def test_wrong_type_rejected(self):
        with self.assertRaises(SupplyChainAgentsError):
            algorithmic_labor_probe(
                "not-a-probe", _auth(), issuer_id="supply-chain-board",
                checked_at=T0,
            )


class DeskillingClockTests(unittest.TestCase):
    def _audit(self, **kw):
        defaults = dict(
            audit_id="da-1", facility_id="fac-1",
            resilience_score_bps=7500, stress_test_digest=HEX,
            measured_at=T0, next_audit_due=T0 + 86400 * 90,
            issuer_id="supply-chain-board", issuer_secret=AUTH,
        )
        defaults.update(kw)
        return issue_deskilling_audit(**defaults)

    def test_resilient_facility_allows(self):
        audits = DeskillingRegistry()
        audits.record(self._audit())
        v = deskilling_clock(
            audits, _auth(), facility_id="fac-1", checked_at=T0 + 10,
            issuer_id="supply-chain-board",
        )
        self.assertTrue(v.allowed)

    def test_brittle_denies(self):
        audits = DeskillingRegistry()
        audits.record(self._audit(resilience_score_bps=4000))
        v = deskilling_clock(
            audits, _auth(), facility_id="fac-1", checked_at=T0 + 10,
            issuer_id="supply-chain-board",
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "supplychain.brittle")

    def test_floor_boundary_allows(self):
        audits = DeskillingRegistry()
        audits.record(self._audit(resilience_score_bps=5000))
        v = deskilling_clock(
            audits, _auth(), facility_id="fac-1", checked_at=T0 + 10,
            issuer_id="supply-chain-board",
        )
        self.assertTrue(v.allowed)

    def test_overdue_audit_denies(self):
        audits = DeskillingRegistry()
        audits.record(self._audit(next_audit_due=T0 + 5))
        v = deskilling_clock(
            audits, _auth(), facility_id="fac-1", checked_at=T0 + 10,
            issuer_id="supply-chain-board",
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "supplychain:audit_overdue")

    def test_no_audit_denies(self):
        v = deskilling_clock(
            DeskillingRegistry(), _auth(), facility_id="fac-ghost",
            checked_at=T0 + 10, issuer_id="supply-chain-board",
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "supplychain:no_deskilling_audit")


class ScenarioBindingTests(unittest.TestCase):
    def _scenario(self, **kw):
        defaults = dict(
            scenario_id="sc-1", scenario_version="v3",
            assumption_digest=HEX, valid_from=T0,
            valid_until=T0 + 86400 * 30,
            issuer_id="supply-chain-board", issuer_secret=AUTH,
        )
        defaults.update(kw)
        return issue_scenario(**defaults)

    def test_bound_scenario_allows(self):
        scenarios = ScenarioRegistry()
        scenarios.record(self._scenario())
        v = scenario_version_binding(
            scenarios, _auth(), scenario_id="sc-1", scenario_version="v3",
            used_at=T0 + 10, issuer_id="supply-chain-board",
        )
        self.assertTrue(v.allowed)

    def test_version_mismatch_denies(self):
        scenarios = ScenarioRegistry()
        scenarios.record(self._scenario())
        v = scenario_version_binding(
            scenarios, _auth(), scenario_id="sc-1", scenario_version="v9",
            used_at=T0 + 10, issuer_id="supply-chain-board",
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "supplychain.unbound_scenario")

    def test_expired_window_denies(self):
        scenarios = ScenarioRegistry()
        scenarios.record(self._scenario(valid_until=T0 + 5))
        v = scenario_version_binding(
            scenarios, _auth(), scenario_id="sc-1", scenario_version="v3",
            used_at=T0 + 10, issuer_id="supply-chain-board",
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "supplychain.unbound_scenario")


class ConcentrationProbeTests(unittest.TestCase):
    def _probe(self, **kw):
        defaults = dict(
            probe_id="cp-1", sku_family="resistors",
            top_supplier_share_bps=4000, tolerance_bps=6000,
            measured_at=T0, expires_at=T0 + 86400,
            issuer_id="supply-chain-board", issuer_secret=AUTH,
        )
        defaults.update(kw)
        return issue_concentration_probe(**defaults)

    def test_within_tolerance_allows(self):
        v = concentration_probe(
            self._probe(), _auth(), issuer_id="supply-chain-board",
            checked_at=T0 + 10,
        )
        self.assertTrue(v.allowed)

    def test_breach_denies(self):
        v = concentration_probe(
            self._probe(top_supplier_share_bps=8000),
            _auth(), issuer_id="supply-chain-board", checked_at=T0 + 10,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "supplychain:concentration_breach")

    def test_tampered_signature_denies(self):
        probe = self._probe()
        tampered = ConcentrationProbe(
            probe_id=probe.probe_id, sku_family=probe.sku_family,
            top_supplier_share_bps=100, tolerance_bps=probe.tolerance_bps,
            measured_at=probe.measured_at, expires_at=probe.expires_at,
            issuer_id=probe.issuer_id, signature_hex=probe.signature_hex,
        )
        v = concentration_probe(
            tampered, _auth(), issuer_id="supply-chain-board",
            checked_at=T0 + 10,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "supplychain:probe_signature_invalid")


class VendorClaimTests(unittest.TestCase):
    def _claim(self, **kw):
        defaults = dict(
            claim_id="vc-1", vendor_id="vendor-1",
            metric_name="tasks_per_year", claimed_value=21000000,
            measurement_protocol_digest=HEX2, self_reported=False,
            measured_at=T0, issuer_id="supply-chain-board",
            issuer_secret=AUTH,
        )
        defaults.update(kw)
        return issue_vendor_claim(**defaults)

    def test_protocol_bound_claim_allows(self):
        claims = VendorClaimRegistry()
        claims.record(self._claim())
        v = vendor_claim_receipt(
            claims, _auth(), claim_id="vc-1", vendor_id="vendor-1",
            checked_at=T0 + 10, issuer_id="supply-chain-board",
        )
        self.assertTrue(v.allowed)

    def test_self_reported_claim_denies(self):
        claims = VendorClaimRegistry()
        claims.record(self._claim(self_reported=True))
        v = vendor_claim_receipt(
            claims, _auth(), claim_id="vc-1", vendor_id="vendor-1",
            checked_at=T0 + 10, issuer_id="supply-chain-board",
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "supplychain.unverified_claim")

    def test_unknown_claim_denies(self):
        v = vendor_claim_receipt(
            VendorClaimRegistry(), _auth(), claim_id="vc-ghost",
            vendor_id="vendor-1", checked_at=T0 + 10,
            issuer_id="supply-chain-board",
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "supplychain.unverified_claim")

    def test_unknown_metric_rejected(self):
        with self.assertRaises(SupplyChainAgentsError):
            self._claim(metric_name="vibes")


class VerdictAndEventTests(unittest.TestCase):
    def test_verdict_as_dict(self):
        v = SupplyChainVerdict(
            allowed=True, deny_code=None,
            classification="supplychain-authoritative",
            receipt_digest=HEX,
        )
        d = v.as_dict()
        self.assertEqual(d["kind"], "supplychain-verdict")
        self.assertTrue(d["allowed"])
        self.assertEqual(d["receipt_digest"], HEX)

    def test_audit_event(self):
        v = SupplyChainVerdict(
            allowed=False, deny_code="supplychain.rest_violation",
            classification="supplychain-non-authoritative",
        )
        ev = supplychain_audit_event(v, action="labor_violation")
        self.assertEqual(ev["event"], "supplychain.labor_violation")
        self.assertFalse(ev["allowed"])
        self.assertEqual(ev["deny_code"], "supplychain.rest_violation")

    def test_labor_probe_as_dict(self):
        probe = issue_labor_probe(
            probe_id="p-x", workforce_id="wf-x",
            rest_minutes_counted_as_inefficiency=0,
            scan_rate_penalty_applied=False, toilet_break_penalized=False,
            measured_at=T0, expires_at=T0 + 60,
            issuer_id="supply-chain-board", issuer_secret=AUTH,
        )
        d = probe.as_dict()
        self.assertEqual(d["kind"], "supplychain-labor-probe")
        self.assertEqual(d["probe_id"], "p-x")

    def test_secret_must_be_32_bytes(self):
        with self.assertRaises(SupplyChainAgentsError):
            issue_vendor_claim(
                claim_id="vc-2", vendor_id="vendor-1",
                metric_name="cost_reduction", claimed_value=7,
                measurement_protocol_digest=HEX2, self_reported=False,
                measured_at=T0, issuer_id="supply-chain-board",
                issuer_secret=b"short",
            )


if __name__ == "__main__":
    unittest.main()
