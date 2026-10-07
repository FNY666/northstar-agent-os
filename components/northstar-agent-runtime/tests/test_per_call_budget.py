"""Tests for per_call_budget: per-call gate over the run budget."""
from __future__ import annotations

import unittest

from per_call_budget import (
    CALL_TYPES,
    CEILING_PER_CALL,
    CEILING_RUN,
    BudgetExhausted,
    PER_CALL_CEILINGS,
    PerCallBudget,
)


class CallTypeTests(unittest.TestCase):
    def test_call_types_cover_model_tool_memory(self):
        self.assertEqual(
            set(CALL_TYPES), {"model", "tool", "memory_read", "memory_write"}
        )

    def test_default_per_call_ceilings(self):
        self.assertEqual(
            PER_CALL_CEILINGS,
            {
                "model": 0.10,
                "tool": 0.01,
                "memory_read": 0.001,
                "memory_write": 0.001,
            },
        )

    def test_unknown_call_type_rejected(self):
        gate = PerCallBudget(max_budget_usd=1.0)
        with self.assertRaises(ValueError):
            gate.check_and_charge("network", 0.001)

    def test_unknown_call_type_never_defaults_to_cheapest(self):
        # Fail closed: a typo'd type must not silently become memory-priced.
        gate = PerCallBudget()
        with self.assertRaises(ValueError):
            gate.check_and_charge("memroy_read", 0.0001)


class EstimateValidationTests(unittest.TestCase):
    def test_negative_estimate_rejected(self):
        gate = PerCallBudget(max_budget_usd=1.0)
        with self.assertRaises(ValueError):
            gate.check_and_charge("tool", -0.001)

    def test_bool_estimate_rejected(self):
        gate = PerCallBudget(max_budget_usd=1.0)
        with self.assertRaises(ValueError):
            gate.check_and_charge("tool", True)

    def test_string_estimate_rejected(self):
        gate = PerCallBudget(max_budget_usd=1.0)
        with self.assertRaises(ValueError):
            gate.check_and_charge("tool", "0.001")

    def test_zero_cost_call_allowed(self):
        gate = PerCallBudget(max_budget_usd=1.0)
        remaining = gate.check_and_charge("memory_read", 0.0)
        self.assertAlmostEqual(remaining, 1.0)
        self.assertAlmostEqual(gate.total_spent_usd, 0.0)


class PerCallCeilingTests(unittest.TestCase):
    def test_single_call_above_type_ceiling_refused(self):
        gate = PerCallBudget(max_budget_usd=100.0)  # run budget has room
        with self.assertRaises(BudgetExhausted) as ctx:
            gate.check_and_charge("tool", 0.011)
        self.assertEqual(ctx.exception.ceiling, CEILING_PER_CALL)
        self.assertEqual(ctx.exception.call_type, "tool")

    def test_call_exactly_at_ceiling_allowed(self):
        gate = PerCallBudget(max_budget_usd=100.0)
        remaining = gate.check_and_charge("tool", 0.01)
        self.assertAlmostEqual(remaining, 100.0 - 0.01)

    def test_model_ceiling_is_highest(self):
        gate = PerCallBudget(max_budget_usd=100.0)
        # $0.10 fits the model ceiling but would blow the tool ceiling.
        gate.check_and_charge("model", 0.10)
        with self.assertRaises(BudgetExhausted):
            gate.check_and_charge("tool", 0.10)

    def test_per_call_refusal_carries_needed_and_available(self):
        gate = PerCallBudget(max_budget_usd=5.0)
        gate.check_and_charge("tool", 0.005)
        with self.assertRaises(BudgetExhausted) as ctx:
            gate.check_and_charge("memory_write", 0.002)
        exc = ctx.exception
        self.assertEqual(exc.call_type, "memory_write")
        self.assertAlmostEqual(exc.needed, 0.002)
        self.assertAlmostEqual(exc.available, 5.0 - 0.005)
        self.assertEqual(exc.ceiling, CEILING_PER_CALL)

    def test_custom_per_call_ceilings(self):
        gate = PerCallBudget(
            max_budget_usd=100.0, per_call_ceilings={"tool": 0.50, **{k: v for k, v in PER_CALL_CEILINGS.items() if k != "tool"}}
        )
        gate.check_and_charge("tool", 0.40)  # above default, below custom
        self.assertAlmostEqual(gate.total_spent_usd, 0.40)

    def test_unknown_type_in_custom_ceilings_rejected(self):
        with self.assertRaises(ValueError):
            PerCallBudget(per_call_ceilings={"teleport": 1.0})


class RunCeilingTests(unittest.TestCase):
    def test_charge_within_run_budget_succeeds(self):
        gate = PerCallBudget(max_budget_usd=1.0)
        remaining = gate.check_and_charge("model", 0.05)
        self.assertAlmostEqual(remaining, 0.95)
        self.assertAlmostEqual(gate.total_spent_usd, 0.05)
        self.assertFalse(gate.exhausted)

    def test_charge_over_run_budget_refused(self):
        gate = PerCallBudget(max_budget_usd=0.05)
        gate.check_and_charge("model", 0.04)
        gate.check_and_charge("tool", 0.008)  # 0.048 spent, fits tool ceiling
        with self.assertRaises(BudgetExhausted) as ctx:
            gate.check_and_charge("tool", 0.005)  # 0.053 > 0.05, fits tool ceiling
        exc = ctx.exception
        self.assertEqual(exc.ceiling, CEILING_RUN)
        self.assertEqual(exc.call_type, "tool")
        self.assertAlmostEqual(exc.needed, 0.005)
        self.assertAlmostEqual(exc.available, 0.002)

    def test_refused_charge_does_not_spend(self):
        gate = PerCallBudget(max_budget_usd=0.05)
        gate.check_and_charge("model", 0.04)
        gate.check_and_charge("tool", 0.008)
        with self.assertRaises(BudgetExhausted):
            gate.check_and_charge("tool", 0.005)
        self.assertAlmostEqual(gate.total_spent_usd, 0.048)
        self.assertEqual(len(gate.charges), 2)

    def test_spend_exactly_to_ceiling_allowed(self):
        gate = PerCallBudget(max_budget_usd=0.05)
        gate.check_and_charge("model", 0.04)
        remaining = gate.check_and_charge("tool", 0.01)
        self.assertAlmostEqual(remaining, 0.0)
        self.assertTrue(gate.exhausted)

    def test_no_run_ceiling_never_refuses_on_run(self):
        gate = PerCallBudget()  # max_budget_usd=None
        for _ in range(100):
            gate.check_and_charge("model", 0.09)
        self.assertIsNone(gate.remaining)
        self.assertFalse(gate.exhausted)
        # ...but the per-call ceiling still applies.
        with self.assertRaises(BudgetExhausted):
            gate.check_and_charge("model", 0.11)

    def test_charges_accumulate_across_types(self):
        gate = PerCallBudget(max_budget_usd=10.0)
        gate.check_and_charge("model", 0.05)
        gate.check_and_charge("tool", 0.005)
        gate.check_and_charge("memory_read", 0.0005)
        gate.check_and_charge("memory_write", 0.0005)
        self.assertAlmostEqual(gate.total_spent_usd, 0.056)
        self.assertEqual(len(gate.charges), 4)


class AccountingTests(unittest.TestCase):
    def test_charges_for_filters_by_type(self):
        gate = PerCallBudget(max_budget_usd=10.0)
        gate.check_and_charge("tool", 0.005)
        gate.check_and_charge("model", 0.05)
        gate.check_and_charge("tool", 0.003)
        tool_charges = gate.charges_for("tool")
        self.assertEqual(len(tool_charges), 2)
        self.assertTrue(all(c.call_type == "tool" for c in tool_charges))

    def test_charges_for_unknown_type_rejected(self):
        gate = PerCallBudget()
        with self.assertRaises(ValueError):
            gate.charges_for("network")

    def test_charge_records_remaining_after(self):
        gate = PerCallBudget(max_budget_usd=1.0)
        gate.check_and_charge("tool", 0.01)
        charge = gate.charges[0]
        self.assertEqual(charge.call_type, "tool")
        self.assertAlmostEqual(charge.estimated_cost_usd, 0.01)
        self.assertAlmostEqual(charge.remaining_after_usd, 0.99)

    def test_as_dict_status(self):
        gate = PerCallBudget(max_budget_usd=2.0)
        gate.check_and_charge("memory_read", 0.001)
        status = gate.as_dict()
        self.assertEqual(status["max_budget_usd"], 2.0)
        self.assertAlmostEqual(status["total_spent_usd"], 0.001)
        self.assertAlmostEqual(status["remaining_usd"], 1.999)
        self.assertFalse(status["exhausted"])
        self.assertEqual(status["charges"], 1)
        self.assertEqual(status["per_call_ceilings"]["tool"], 0.01)

    def test_observe_model_reconciles_actuals(self):
        gate = PerCallBudget(max_budget_usd=10.0)
        breakdown = gate.observe_model(
            {
                "input_tokens": 1000,
                "output_tokens": 500,
                "cache_read_input_tokens": 0,
                "cache_creation_input_tokens": 0,
            },
            "claude-haiku-4-5",
        )
        # 1000 * 0.80/1e6 + 500 * 4.00/1e6 = 0.0008 + 0.002 = 0.0028
        self.assertAlmostEqual(breakdown.total_usd, 0.0028)
        self.assertAlmostEqual(gate.total_spent_usd, 0.0028)

    def test_invalid_max_budget_rejected(self):
        with self.assertRaises(ValueError):
            PerCallBudget(max_budget_usd=0)
        with self.assertRaises(ValueError):
            PerCallBudget(max_budget_usd=-5.0)
        with self.assertRaises(ValueError):
            PerCallBudget(max_budget_usd=True)


if __name__ == "__main__":
    unittest.main()
