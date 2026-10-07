"""Tests for a2a_budget_combo: budget-gated A2A delegation."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from a2a_budget_combo import (
    A2A_BUDGET_COMBO_VERSION,
    A2ABudgetGate,
    DENY_BUDGET,
    DelegationDecision,
    DelegationGrant,
    a2a_budget_audit_event,
)
from a2a_gates import ALLOW, DENY_SABOTAGE, DENY_TURF_WAR
from per_call_budget import BudgetExhausted, CEILING_PER_CALL, CEILING_RUN


class TestVersionPin(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(A2A_BUDGET_COMBO_VERSION, "a2a-budget-combo.v1")


class TestDelegateAllow(unittest.TestCase):
    def test_happy_path(self):
        gate = A2ABudgetGate(max_budget_usd=1.0)
        d = gate.delegate(
            "parent", "worker",
            {"action_type": "analyse", "target": "logs"}, 0.005,
        )
        self.assertEqual(d.verdict, ALLOW)
        self.assertIsNotNone(d.grant)
        self.assertIsInstance(d, DelegationDecision)
        self.assertIsInstance(d.grant, DelegationGrant)

    def test_pre_charge_hits_parent_budget(self):
        gate = A2ABudgetGate(max_budget_usd=1.0)
        gate.delegate("parent", "worker",
                      {"action_type": "analyse", "target": "logs"}, 0.005)
        self.assertAlmostEqual(gate.total_spent_usd, 0.005)
        self.assertAlmostEqual(gate.remaining, 0.995)

    def test_grant_ids_deterministic(self):
        gate = A2ABudgetGate()
        d1 = gate.delegate("p", "w1", {"action_type": "a", "target": "t"}, 0.001)
        d2 = gate.delegate("p", "w2", {"action_type": "b", "target": "t"}, 0.001)
        self.assertEqual(d1.grant.grant_id, "grant-000000")
        self.assertEqual(d2.grant.grant_id, "grant-000001")

    def test_grant_frozen(self):
        gate = A2ABudgetGate()
        d = gate.delegate("p", "w", {"action_type": "a", "target": "t"}, 0.001)
        with self.assertRaises(Exception):
            d.grant.grant_id = "x"  # frozen dataclass

    def test_active_grants(self):
        gate = A2ABudgetGate()
        d = gate.delegate("p", "w", {"action_type": "a", "target": "t"}, 0.001)
        self.assertEqual(len(gate.active_grants), 1)
        self.assertEqual(gate.active_grants[0].grant_id, d.grant.grant_id)


class TestDelegateDenyBudget(unittest.TestCase):
    def test_run_ceiling(self):
        gate = A2ABudgetGate(max_budget_usd=0.001)
        d = gate.delegate("parent", "worker",
                          {"action_type": "analyse", "target": "logs"}, 0.005)
        self.assertEqual(d.verdict, DENY_BUDGET)
        self.assertIsNone(d.grant)
        self.assertEqual(gate.total_spent_usd, 0.0)

    def test_per_call_ceiling(self):
        gate = A2ABudgetGate(max_budget_usd=100.0)
        d = gate.delegate("parent", "worker",
                          {"action_type": "analyse", "target": "logs"},
                          0.05, call_type="tool")  # tool ceiling is 0.01
        self.assertEqual(d.verdict, DENY_BUDGET)
        self.assertIsNone(d.grant)
        self.assertEqual(gate.total_spent_usd, 0.0)

    def test_negative_estimate(self):
        gate = A2ABudgetGate()
        d = gate.delegate("p", "w", {"action_type": "a", "target": "t"}, -1.0)
        self.assertEqual(d.verdict, DENY_BUDGET)
        self.assertIsNone(d.grant)

    def test_non_numeric_estimate(self):
        gate = A2ABudgetGate()
        d = gate.delegate("p", "w", {"action_type": "a", "target": "t"}, "cheap")
        self.assertEqual(d.verdict, DENY_BUDGET)

    def test_bool_estimate_rejected(self):
        gate = A2ABudgetGate()
        d = gate.delegate("p", "w", {"action_type": "a", "target": "t"}, True)
        self.assertEqual(d.verdict, DENY_BUDGET)

    def test_unknown_call_type(self):
        gate = A2ABudgetGate()
        d = gate.delegate("p", "w", {"action_type": "a", "target": "t"},
                          0.001, call_type="teleport")
        self.assertEqual(d.verdict, DENY_BUDGET)
        self.assertIsNone(d.grant)

    def test_budget_checked_before_handoff(self):
        # Even a sabotaging handoff gets deny_budget when the parent is broke:
        # the safety gate is never consulted.
        gate = A2ABudgetGate(max_budget_usd=0.0001)
        d = gate.delegate("p", "w", {"action_type": "delete", "target": "x"},
                          0.005)
        self.assertEqual(d.verdict, DENY_BUDGET)
        self.assertEqual(len(gate.a2a_gate.history()), 0)


class TestDelegateDenyHandoff(unittest.TestCase):
    def test_sabotage_denial_refunds(self):
        gate = A2ABudgetGate(max_budget_usd=1.0)
        ok = gate.delegate("parent", "w1",
                           {"action_type": "create", "target": "report"}, 0.001)
        self.assertEqual(ok.verdict, ALLOW)
        bad = gate.delegate("parent", "w2",
                            {"action_type": "delete", "target": "report"}, 0.002)
        self.assertEqual(bad.verdict, DENY_SABOTAGE)
        self.assertIsNone(bad.grant)
        # Only the first (allowed) delegation's estimate remains.
        self.assertAlmostEqual(gate.total_spent_usd, 0.001)

    def test_turf_war_denial_refunds(self):
        gate = A2ABudgetGate(max_budget_usd=1.0)
        ok = gate.delegate("parent", "w1", {"resources": ["gpu0"]}, 0.001)
        self.assertEqual(ok.verdict, ALLOW)
        bad = gate.delegate("parent", "w2", {"resources": ["gpu0"]}, 0.002)
        self.assertEqual(bad.verdict, DENY_TURF_WAR)
        self.assertIsNone(bad.grant)
        self.assertAlmostEqual(gate.total_spent_usd, 0.001)

    def test_malformed_handoff_no_budget_churn(self):
        gate = A2ABudgetGate(max_budget_usd=1.0)
        d = gate.delegate("", "w", {"action_type": "a", "target": "t"}, 0.005)
        self.assertEqual(d.verdict, DENY_SABOTAGE)
        self.assertEqual(gate.total_spent_usd, 0.0)
        self.assertEqual(len(gate._budget.charges), 0)

    def test_non_mapping_payload_no_budget_churn(self):
        gate = A2ABudgetGate(max_budget_usd=1.0)
        d = gate.delegate("p", "w", "not-a-mapping", 0.005)
        self.assertEqual(d.verdict, DENY_SABOTAGE)
        self.assertEqual(gate.total_spent_usd, 0.0)


class TestReportActual(unittest.TestCase):
    def _allowed(self, estimate=0.005, max_budget=1.0):
        gate = A2ABudgetGate(max_budget_usd=max_budget)
        d = gate.delegate("p", "w", {"action_type": "a", "target": "t"},
                          estimate)
        assert d.verdict == ALLOW
        return gate, d.grant.grant_id

    def test_exact_reconcile(self):
        gate, gid = self._allowed(0.005)
        remaining = gate.report_actual(gid, 0.005)
        self.assertAlmostEqual(gate.total_spent_usd, 0.005)
        self.assertAlmostEqual(remaining, 0.995)
        self.assertEqual(len(gate.active_grants), 0)

    def test_under_run_refunds_difference(self):
        gate, gid = self._allowed(0.005)
        gate.report_actual(gid, 0.002)
        self.assertAlmostEqual(gate.total_spent_usd, 0.002)

    def test_over_run_charges_delta(self):
        gate, gid = self._allowed(0.005)
        gate.report_actual(gid, 0.008)
        self.assertAlmostEqual(gate.total_spent_usd, 0.008)

    def test_over_run_blows_run_budget(self):
        gate, gid = self._allowed(0.005, max_budget=0.006)
        with self.assertRaises(BudgetExhausted) as ctx:
            gate.report_actual(gid, 0.009)
        self.assertEqual(ctx.exception.ceiling, CEILING_RUN)

    def test_actual_above_per_call_ceiling_refused(self):
        gate, gid = self._allowed(0.005)
        with self.assertRaises(BudgetExhausted) as ctx:
            gate.report_actual(gid, 0.05)  # tool ceiling 0.01
        self.assertEqual(ctx.exception.ceiling, CEILING_PER_CALL)
        # Pre-charged estimate stands; the violation is not normalised.
        self.assertAlmostEqual(gate.total_spent_usd, 0.005)

    def test_unknown_grant(self):
        gate = A2ABudgetGate()
        with self.assertRaises(KeyError):
            gate.report_actual("grant-999999", 0.001)

    def test_double_report(self):
        gate, gid = self._allowed()
        gate.report_actual(gid, 0.005)
        with self.assertRaises(KeyError):
            gate.report_actual(gid, 0.005)

    def test_negative_actual(self):
        gate, gid = self._allowed()
        with self.assertRaises(ValueError):
            gate.report_actual(gid, -0.001)


class TestReleaseGrant(unittest.TestCase):
    def test_release_refunds_full_estimate(self):
        gate = A2ABudgetGate(max_budget_usd=1.0)
        d = gate.delegate("p", "w", {"action_type": "a", "target": "t"}, 0.005)
        remaining = gate.release_grant(d.grant.grant_id)
        self.assertAlmostEqual(gate.total_spent_usd, 0.0)
        self.assertAlmostEqual(remaining, 1.0)
        self.assertEqual(len(gate.active_grants), 0)

    def test_release_unknown_grant(self):
        gate = A2ABudgetGate()
        with self.assertRaises(KeyError):
            gate.release_grant("grant-999999")


class TestRecords(unittest.TestCase):
    def test_decision_as_dict(self):
        gate = A2ABudgetGate()
        d = gate.delegate("p", "w", {"action_type": "a", "target": "t"}, 0.001)
        shape = d.as_dict()
        self.assertEqual(shape["verdict"], ALLOW)
        self.assertEqual(shape["grant"]["grant_id"], "grant-000000")
        self.assertEqual(shape["version"], A2A_BUDGET_COMBO_VERSION)

    def test_denied_decision_as_dict(self):
        gate = A2ABudgetGate(max_budget_usd=0.0001)
        d = gate.delegate("p", "w", {"action_type": "a", "target": "t"}, 0.005)
        shape = d.as_dict()
        self.assertEqual(shape["verdict"], DENY_BUDGET)
        self.assertIsNone(shape["grant"])

    def test_audit_event(self):
        gate = A2ABudgetGate()
        d = gate.delegate("p", "w", {"action_type": "a", "target": "t"}, 0.001)
        ev = a2a_budget_audit_event(d, seq=7)
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["seq"], 7)
        self.assertEqual(ev["verdict"], ALLOW)
        self.assertEqual(ev["grant_id"], "grant-000000")

    def test_audit_event_bad_seq(self):
        gate = A2ABudgetGate()
        d = gate.delegate("p", "w", {"action_type": "a", "target": "t"}, 0.001)
        with self.assertRaises(ValueError):
            a2a_budget_audit_event(d, seq=-1)

    def test_gate_as_dict(self):
        gate = A2ABudgetGate(max_budget_usd=1.0)
        gate.delegate("p", "w", {"action_type": "a", "target": "t"}, 0.001)
        shape = gate.as_dict()
        self.assertEqual(shape["version"], A2A_BUDGET_COMBO_VERSION)
        self.assertAlmostEqual(shape["total_spent_usd"], 0.001)
        self.assertEqual(len(shape["active_grants"]), 1)


class TestMain(unittest.TestCase):
    def test_main(self):
        import a2a_budget_combo as m
        m.main()  # asserts internally


if __name__ == "__main__":
    unittest.main()
