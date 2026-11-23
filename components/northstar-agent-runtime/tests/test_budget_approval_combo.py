"""Tests for budget_approval_combo: budget gate before human approval."""

from __future__ import annotations

import unittest

from approval_sla import (
    STATUS_APPROVED,
    STATUS_DENIED,
    STATUS_EXPIRED,
    STATUS_PENDING,
    ApprovalQueue,
)
from budget_approval_combo import (
    BUDGET_APPROVAL_COMBO_SCHEMA,
    BUDGET_APPROVAL_COMBO_VERSION,
    CEILING_PER_CALL,
    CEILING_RUN,
    DECISION_ALLOWED,
    DECISION_DENIED,
    DECISION_PENDING,
    DENIAL_BUDGET,
    DENIAL_BUDGET_DRIFT,
    DENIAL_NOT_APPROVED,
    BudgetApprovalGate,
    GateDecision,
)
from per_call_budget import PerCallBudget


def make_gate(max_budget=1.0, threshold=0.01):
    return BudgetApprovalGate(
        PerCallBudget(max_budget_usd=max_budget),
        ApprovalQueue(),
        high_cost_threshold_usd=threshold,
    )


class VersionTests(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(BUDGET_APPROVAL_COMBO_VERSION, "budget-approval-combo.v1")
        self.assertEqual(
            BUDGET_APPROVAL_COMBO_SCHEMA, "northstar.budget-approval-combo.v1"
        )

    def test_as_dict_reports_versions(self):
        gate = make_gate()
        d = gate.as_dict()
        self.assertEqual(d["version"], "budget-approval-combo.v1")
        self.assertEqual(d["approval_sla_version"], "approval-sla.v1")
        self.assertEqual(d["high_cost_threshold_usd"], 0.01)


class ConstructorTests(unittest.TestCase):
    def test_default_queue_created(self):
        gate = BudgetApprovalGate(PerCallBudget(max_budget_usd=1.0))
        self.assertIsInstance(gate._queue, ApprovalQueue)

    def test_rejects_non_budget(self):
        with self.assertRaises(TypeError):
            BudgetApprovalGate("not-a-budget")

    def test_rejects_non_queue(self):
        with self.assertRaises(TypeError):
            BudgetApprovalGate(PerCallBudget(), queue="nope")

    def test_rejects_bool_threshold(self):
        with self.assertRaises(TypeError):
            BudgetApprovalGate(PerCallBudget(), high_cost_threshold_usd=True)

    def test_rejects_negative_threshold(self):
        with self.assertRaises(ValueError):
            BudgetApprovalGate(PerCallBudget(), high_cost_threshold_usd=-0.1)


class CheapPathTests(unittest.TestCase):
    def test_cheap_call_allowed_and_charged(self):
        gate = make_gate()
        d = gate.request("summarize", "tool", 0.005, "routine", 10, 0)
        self.assertEqual(d.decision, DECISION_ALLOWED)
        self.assertIsNone(d.request_id)
        self.assertAlmostEqual(gate._budget.total_spent_usd, 0.005)

    def test_zero_estimate_allowed(self):
        gate = make_gate()
        d = gate.request("noop", "tool", 0.0, "free", 10, 0)
        self.assertEqual(d.decision, DECISION_ALLOWED)

    def test_threshold_boundary_routes_to_approval(self):
        gate = make_gate(threshold=0.01)
        d = gate.request("edge", "tool", 0.01, "at threshold", 10, 0)
        self.assertEqual(d.decision, DECISION_PENDING)
        self.assertIsNotNone(d.request_id)


class BudgetFirstTests(unittest.TestCase):
    def test_over_budget_denied_no_human_bothered(self):
        gate = make_gate(max_budget=0.05)
        gate.request("first", "tool", 0.005, "ok", 10, 0)  # spend a little
        d = gate.request("huge", "model", 0.09, "too much", 10, 1)
        self.assertEqual(d.decision, DECISION_DENIED)
        self.assertEqual(d.denial_reason, DENIAL_BUDGET)
        self.assertEqual(d.ceiling, CEILING_RUN)
        # No approval request was enqueued: the human was never bothered.
        self.assertEqual(len(gate._queue), 0)
        self.assertEqual(gate.pending_requests(), [])

    def test_per_call_ceiling_breach_denied(self):
        gate = make_gate()
        d = gate.request("monster", "tool", 0.5, "way over tool ceiling", 10, 0)
        self.assertEqual(d.decision, DECISION_DENIED)
        self.assertEqual(d.denial_reason, DENIAL_BUDGET)
        self.assertEqual(d.ceiling, CEILING_PER_CALL)
        self.assertEqual(len(gate._queue), 0)

    def test_denied_call_charges_nothing(self):
        gate = make_gate(max_budget=0.05)
        spent_before = gate._budget.total_spent_usd
        gate.request("huge", "model", 0.09, "too much", 10, 0)
        self.assertAlmostEqual(gate._budget.total_spent_usd, spent_before)


class ApprovalPathTests(unittest.TestCase):
    def test_expensive_call_parked_pending(self):
        gate = make_gate()
        d = gate.request("full-eval", "model", 0.08, "abstain: costly", 10, 0)
        self.assertEqual(d.decision, DECISION_PENDING)
        self.assertIsNotNone(d.request_id)
        self.assertIn(d.request_id, gate.pending_requests())
        # Dry-run: nothing charged while pending.
        self.assertAlmostEqual(gate._budget.total_spent_usd, 0.0)

    def test_approved_finalize_charges(self):
        gate = make_gate()
        d = gate.request("full-eval", "model", 0.08, "abstain: costly", 10, 0)
        gate._queue.decide(d.request_id, True, "op-1")
        done = gate.finalize(d.request_id, 1)
        self.assertEqual(done.decision, DECISION_ALLOWED)
        self.assertAlmostEqual(gate._budget.total_spent_usd, 0.08)

    def test_denied_approval_charges_nothing(self):
        gate = make_gate()
        d = gate.request("full-eval", "model", 0.08, "abstain: costly", 10, 0)
        gate._queue.decide(d.request_id, False, "op-1")
        done = gate.finalize(d.request_id, 1)
        self.assertEqual(done.decision, DECISION_DENIED)
        self.assertEqual(done.denial_reason, DENIAL_NOT_APPROVED)
        self.assertAlmostEqual(gate._budget.total_spent_usd, 0.0)

    def test_expired_approval_denied(self):
        gate = make_gate()
        d = gate.request("full-eval", "model", 0.08, "abstain: costly", 5, 0)
        self.assertEqual(gate.poll(d.request_id, 99), STATUS_EXPIRED)
        done = gate.finalize(d.request_id, 99)
        self.assertEqual(done.decision, DECISION_DENIED)
        self.assertEqual(done.denial_reason, DENIAL_NOT_APPROVED)
        self.assertAlmostEqual(gate._budget.total_spent_usd, 0.0)

    def test_finalize_before_decision_denied(self):
        gate = make_gate()
        d = gate.request("full-eval", "model", 0.08, "abstain: costly", 10, 0)
        self.assertEqual(gate.poll(d.request_id, 1), STATUS_PENDING)
        done = gate.finalize(d.request_id, 1)
        self.assertEqual(done.decision, DECISION_DENIED)
        self.assertEqual(done.denial_reason, DENIAL_NOT_APPROVED)

    def test_double_finalize_no_double_charge(self):
        gate = make_gate()
        d = gate.request("full-eval", "model", 0.08, "abstain: costly", 10, 0)
        gate._queue.decide(d.request_id, True, "op-1")
        first = gate.finalize(d.request_id, 1)
        self.assertEqual(first.decision, DECISION_ALLOWED)
        second = gate.finalize(d.request_id, 2)
        self.assertEqual(second.decision, DECISION_DENIED)
        self.assertEqual(second.denial_reason, DENIAL_NOT_APPROVED)
        self.assertAlmostEqual(gate._budget.total_spent_usd, 0.08)

    def test_budget_drift_between_request_and_approval(self):
        gate = make_gate(max_budget=0.10)
        d = gate.request("eval", "model", 0.08, "abstain: costly", 100, 0)
        self.assertEqual(d.decision, DECISION_PENDING)
        # Someone else spends budget on cheap (immediately-charged) calls
        # while the human decides: 6 x $0.005 = $0.03, so the pending $0.08
        # no longer fits in the $0.10 run budget.
        for i in range(6):
            other = gate.request("other", "tool", 0.005, "routine", 100, 1 + i)
            self.assertEqual(other.decision, DECISION_ALLOWED)
        gate._queue.decide(d.request_id, True, "op-1")
        done = gate.finalize(d.request_id, 2)
        self.assertEqual(done.decision, DECISION_DENIED)
        self.assertEqual(done.denial_reason, DENIAL_BUDGET_DRIFT)
        self.assertEqual(done.ceiling, CEILING_RUN)
        # The drifting call was not charged.
        self.assertAlmostEqual(gate._budget.total_spent_usd, 0.03)

    def test_unknown_request_id_finalize_raises(self):
        gate = make_gate()
        with self.assertRaises(KeyError):
            gate.finalize("apr-nonexistent", 0)


class ValidationTests(unittest.TestCase):
    def test_unknown_call_type_rejected(self):
        gate = make_gate()
        with self.assertRaises(ValueError):
            gate.request("x", "nuke", 0.001, "bad", 10, 0)

    def test_negative_estimate_rejected(self):
        gate = make_gate()
        with self.assertRaises(ValueError):
            gate.request("x", "tool", -0.001, "bad", 10, 0)

    def test_bool_estimate_rejected(self):
        gate = make_gate()
        with self.assertRaises(TypeError):
            gate.request("x", "tool", True, "bad", 10, 0)

    def test_nonpositive_sla_rejected(self):
        gate = make_gate()
        with self.assertRaises(ValueError):
            gate.request("x", "tool", 0.001, "bad", 0, 0)

    def test_empty_action_rejected(self):
        gate = make_gate()
        with self.assertRaises(ValueError):
            gate.request("", "tool", 0.001, "bad", 10, 0)


class ConsistencyTests(unittest.TestCase):
    def test_fits_budget_agrees_with_check_and_charge(self):
        # Property: fits_budget says (False, ceiling) exactly when a
        # fresh check_and_charge would raise BudgetExhausted, and
        # (True, None) exactly when it would succeed.
        from per_call_budget import BudgetExhausted

        scenarios = [
            ("model", 0.05, 1.0),   # fits
            ("model", 0.50, 1.0),   # per-call ceiling
            ("tool", 0.005, 1.0),   # fits
            ("tool", 0.05, 1.0),    # per-call ceiling
            ("model", 0.09, 0.05),  # run ceiling
            ("memory_read", 0.0005, 1.0),  # fits
            ("memory_write", 0.002, 1.0),  # per-call ceiling
        ]
        for call_type, estimate, max_budget in scenarios:
            gate = make_gate(max_budget=max_budget)
            fits, ceiling = gate.fits_budget(call_type, estimate)
            try:
                gate._budget.check_and_charge(call_type, estimate)
                raised = None
            except BudgetExhausted as exc:
                raised = exc.ceiling
            if raised is None:
                self.assertTrue(fits, f"{call_type}/{estimate} should fit")
                self.assertIsNone(ceiling)
            else:
                self.assertFalse(fits, f"{call_type}/{estimate} should not fit")
                self.assertEqual(ceiling, raised)


class RecordShapeTests(unittest.TestCase):
    def test_gate_decision_frozen(self):
        d = GateDecision(decision=DECISION_ALLOWED)
        with self.assertRaises(AttributeError):
            d.decision = DECISION_DENIED  # type: ignore[misc]

    def test_gate_decision_invariants(self):
        with self.assertRaises(ValueError):
            GateDecision(decision=DECISION_PENDING)  # no request_id
        with self.assertRaises(ValueError):
            GateDecision(decision=DECISION_DENIED)  # no reason
        with self.assertRaises(ValueError):
            GateDecision(
                decision=DECISION_ALLOWED, request_id="apr-x"
            )  # stray request_id

    def test_as_dict_shape(self):
        d = GateDecision(
            decision=DECISION_DENIED,
            denial_reason=DENIAL_BUDGET,
            ceiling=CEILING_RUN,
        )
        asd = d.as_dict()
        self.assertEqual(asd["decision"], "denied")
        self.assertEqual(asd["denial_reason"], "budget_exhausted")
        self.assertEqual(asd["ceiling"], "run")
        self.assertEqual(asd["schema"], BUDGET_APPROVAL_COMBO_SCHEMA)

    def test_audit_event_shape(self):
        gate = make_gate()
        # $0.50 exceeds the model per-call ceiling ($0.10) -> denied.
        d = gate.request("huge", "model", 0.50, "too much", 10, 0)
        self.assertEqual(d.decision, DECISION_DENIED)
        event = gate.gate_audit_event(d, seq=7)
        self.assertEqual(event["schema"], BUDGET_APPROVAL_COMBO_SCHEMA)
        self.assertEqual(event["seq"], 7)
        self.assertEqual(event["decision"], "denied")
        with self.assertRaises(TypeError):
            gate.gate_audit_event(d, seq=True)

    def test_main_self_check(self):
        import budget_approval_combo

        budget_approval_combo.main()


if __name__ == "__main__":
    unittest.main()
