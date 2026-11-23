"""Targeted tests for memory_budget_combo (consent + budget composition)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from memory_admission import MemoryAdmission, MemoryConsent
from memory_budget_combo import (
    DEFAULT_EMBED_CEILING_USD,
    DEFAULT_READ_ESTIMATE_USD,
    DEFAULT_WRITE_ESTIMATE_USD,
    EMBED_CALL_TYPE,
    MEMORY_BUDGET_COMBO_VERSION,
    REASON_ADMITTED,
    REASON_BUDGET_EXHAUSTED,
    REASON_CONSENT_DENIED,
    SCHEMA_PIN,
    GateDecision,
    MemoryBudgetError,
    MemoryBudgetGate,
)
from per_call_budget import CEILING_PER_CALL, CEILING_RUN, BudgetExhausted, PerCallBudget


def make_grant(**kwargs):
    base = dict(scope=("preference", "fact", "conversation"), retention_days=30, granted_at=100)
    base.update(kwargs)
    return MemoryConsent(**base)


def make_gate(**kwargs):
    grant = kwargs.pop("grant", make_grant())
    admission = MemoryAdmission(grant)
    budget = kwargs.pop("budget", PerCallBudget(max_budget_usd=1.0))
    return MemoryBudgetGate(admission=admission, budget=budget, **kwargs), budget


class VersionPinTest(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(MEMORY_BUDGET_COMBO_VERSION, "memory-budget-combo.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.memory-budget-combo.v1")


class WriteConsentFirstTest(unittest.TestCase):
    def test_write_admitted_with_consent_and_budget(self):
        gate, _ = make_gate()
        d = gate.write("preference", "likes dark mode", current_seq=110)
        self.assertTrue(d.allowed)
        self.assertEqual(d.reason, REASON_ADMITTED)
        self.assertEqual(d.operation, "write")
        self.assertAlmostEqual(d.remaining_usd, 1.0 - DEFAULT_WRITE_ESTIMATE_USD)

    def test_write_denied_without_consent(self):
        gate = MemoryBudgetGate(budget=PerCallBudget(max_budget_usd=1.0))
        d = gate.write("preference", "likes dark mode", current_seq=110)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, f"{REASON_CONSENT_DENIED}:no-consent")

    def test_write_denied_revoked_consent(self):
        gate, _ = make_gate(grant=make_grant().revoke())
        d = gate.write("fact", "deadline Friday", current_seq=110)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, f"{REASON_CONSENT_DENIED}:consent-revoked")

    def test_write_denied_credential_never_admitted(self):
        gate, _ = make_gate()
        d = gate.write("credential", "api-key-123", current_seq=110)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, f"{REASON_CONSENT_DENIED}:credential-never-admitted")

    def test_write_denied_expired_consent(self):
        gate, _ = make_gate()
        d = gate.write("fact", "deadline Friday", current_seq=200)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, f"{REASON_CONSENT_DENIED}:consent-expired")

    def test_consent_denial_does_not_charge_budget(self):
        gate, budget = make_gate()
        before = len(budget.charges)
        gate.write("credential", "api-key-123", current_seq=110)
        self.assertEqual(len(budget.charges), before)


class WriteBudgetSecondTest(unittest.TestCase):
    def test_write_denied_when_per_call_ceiling_exceeded(self):
        gate, _ = make_gate()
        d = gate.write("preference", "x", current_seq=110, estimate_usd=0.05)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, f"{REASON_BUDGET_EXHAUSTED}:{CEILING_PER_CALL}")

    def test_write_denied_when_run_ceiling_exceeded(self):
        gate, _ = make_gate(budget=PerCallBudget(max_budget_usd=0.0006))
        d = gate.write("preference", "x", current_seq=110)  # 0.0005 fits...
        self.assertTrue(d.allowed)
        d2 = gate.write("preference", "y", current_seq=110)  # ...this one does not
        self.assertFalse(d2.allowed)
        self.assertEqual(d2.reason, f"{REASON_BUDGET_EXHAUSTED}:{CEILING_RUN}")

    def test_explicit_consent_overrides_default(self):
        grant = make_grant(scope=("fact",))
        gate = MemoryBudgetGate(
            admission=MemoryAdmission(make_grant(scope=("preference",))),
            budget=PerCallBudget(max_budget_usd=1.0),
        )
        d = gate.write("fact", "deadline Friday", consent=grant, current_seq=110)
        self.assertTrue(d.allowed)


class ReadTest(unittest.TestCase):
    def test_read_charges_memory_read(self):
        gate, budget = make_gate()
        d = gate.read()
        self.assertTrue(d.allowed)
        self.assertEqual(d.reason, REASON_ADMITTED)
        self.assertEqual(len(budget.charges_for("memory_read")), 1)

    def test_read_denied_when_per_call_ceiling_exceeded(self):
        gate, _ = make_gate()
        d = gate.read(estimate_usd=0.05)
        self.assertFalse(d.allowed)
        self.assertTrue(d.reason.startswith(REASON_BUDGET_EXHAUSTED))

    def test_read_denied_when_run_exhausted(self):
        gate, _ = make_gate(budget=PerCallBudget(max_budget_usd=0.0001))
        d = gate.read()  # 0.0002 default does not fit
        self.assertFalse(d.allowed)


class EmbedTest(unittest.TestCase):
    def test_embed_charges_model_call_type(self):
        gate, budget = make_gate()
        d = gate.embed(0.005)
        self.assertTrue(d.allowed)
        self.assertEqual(d.reason, REASON_ADMITTED)
        self.assertEqual(len(budget.charges_for("model")), 1)

    def test_embed_refused_over_embed_ceiling(self):
        gate, budget = make_gate()
        before = len(budget.charges)
        with self.assertRaises(BudgetExhausted) as ctx:
            gate.embed(DEFAULT_EMBED_CEILING_USD + 0.001)
        self.assertEqual(ctx.exception.call_type, EMBED_CALL_TYPE)
        self.assertEqual(ctx.exception.ceiling, CEILING_PER_CALL)
        self.assertEqual(len(budget.charges), before)  # budget untouched

    def test_embed_at_ceiling_boundary_fits(self):
        gate, _ = make_gate()
        d = gate.embed(DEFAULT_EMBED_CEILING_USD)
        self.assertTrue(d.allowed)

    def test_embed_denied_when_run_exhausted(self):
        gate, _ = make_gate(budget=PerCallBudget(max_budget_usd=0.001))
        d = gate.embed(0.005)  # fits embed cap, not the run ceiling
        self.assertFalse(d.allowed)
        self.assertTrue(d.reason.startswith(REASON_BUDGET_EXHAUSTED))

    def test_custom_embed_ceiling(self):
        gate, _ = make_gate(embed_ceiling_usd=0.002)
        self.assertAlmostEqual(gate.embed_ceiling_usd, 0.002)
        with self.assertRaises(BudgetExhausted):
            gate.embed(0.005)


class ValidationTest(unittest.TestCase):
    def test_malformed_estimate_rejected(self):
        gate, _ = make_gate()
        for bad in (-0.1, True, "0.001", None):
            with self.assertRaises(MemoryBudgetError):
                gate.write("preference", "x", current_seq=110, estimate_usd=bad)
            with self.assertRaises(MemoryBudgetError):
                gate.read(estimate_usd=bad)
            with self.assertRaises(MemoryBudgetError):
                gate.embed(estimate_usd=bad)

    def test_gate_decision_frozen(self):
        gate, _ = make_gate()
        d = gate.write("preference", "x", current_seq=110)
        self.assertIsInstance(d, GateDecision)
        with self.assertRaises(Exception):
            d.allowed = False  # frozen

    def test_decision_as_dict_schema(self):
        gate, _ = make_gate()
        d = gate.write("preference", "x", current_seq=110)
        as_dict = d.as_dict()
        self.assertEqual(as_dict["schema"], SCHEMA_PIN)
        self.assertEqual(as_dict["operation"], "write")
        self.assertTrue(as_dict["allowed"])

    def test_denied_view(self):
        gate, _ = make_gate()
        gate.write("credential", "x", current_seq=110)
        gate.write("preference", "y", current_seq=110)
        self.assertEqual(len(gate.denied()), 1)
        self.assertEqual(len(gate.decisions()), 2)


if __name__ == "__main__":
    unittest.main()
