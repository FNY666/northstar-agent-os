"""Tests for skill_budget_combo: grant + auth + budget integration."""
import sys
import unittest

sys.path.insert(0, "..")

from per_call_budget import PerCallBudget
from skill_budget_combo import (
    REASON_AUTHORIZED,
    REASON_BUDGET_PER_CALL,
    REASON_BUDGET_RUN,
    REASON_PRE_AUTH_REQUIRED,
    REASON_UNAUTHORIZED,
    SCHEMA_PIN,
    SKILL_BUDGET_COMBO_VERSION,
    PreAuthorization,
    SkillBudgetDecision,
    SkillBudgetError,
    SkillBudgetGate,
    combo_audit_event,
)
from skill_wiring import SKILL_WIRING_VERSION, SkillPolicy, SkillRegistry


def _registry():
    registry = SkillRegistry()
    registry.register(
        SkillPolicy(
            skill_name="cheap",
            allowed_callers=frozenset({"agent"}),
            estimated_cost_usd=0.005,
        )
    )
    registry.register(
        SkillPolicy(
            skill_name="pricey",
            allowed_callers=frozenset({"agent"}),
            estimated_cost_usd=2.0,
        )
    )
    registry.register(
        SkillPolicy(
            skill_name="review-me",
            allowed_callers=frozenset({"agent"}),
            estimated_cost_usd=0.001,
            requires_review=True,
        )
    )
    return registry


def _gate(registry=None, **kwargs):
    budget_kwargs = {
        "max_budget_usd": 10.0,
        "per_call_ceilings": {
            "model": 0.10,
            "tool": 5.0,
            "memory_read": 0.001,
            "memory_write": 0.001,
        },
    }
    budget_kwargs.update(kwargs.pop("budget_kwargs", {}))
    kwargs.setdefault("expensive_threshold_usd", 1.0)
    return SkillBudgetGate(
        registry=registry or _registry(),
        budget=PerCallBudget(**budget_kwargs),
        **kwargs,
    )


class TestSkillBudgetCombo(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(SKILL_BUDGET_COMBO_VERSION, "skill-budget-combo.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.skill-budget-combo.v1")
        # Sanity: the wiring version it composes is present.
        self.assertTrue(SKILL_WIRING_VERSION.startswith("skill-wiring."))

    def test_cheap_skill_authorized_and_charged(self):
        gate = _gate()
        d = gate.invoke("cheap", {"q": "x"}, "agent", 1)
        self.assertTrue(d.allowed)
        self.assertEqual(d.reason, REASON_AUTHORIZED)
        self.assertAlmostEqual(d.cost_usd, 0.005)
        self.assertFalse(d.pre_auth_used)
        self.assertEqual(len(gate._budget.charges), 1)

    def test_unknown_skill_unauthorized_budget_untouched(self):
        gate = _gate()
        d = gate.invoke("nope", {}, "agent", 1)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, REASON_UNAUTHORIZED)
        self.assertEqual(len(gate._budget.charges), 0)

    def test_wrong_caller_unauthorized(self):
        gate = _gate()
        d = gate.invoke("cheap", {}, "mallory", 1)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, REASON_UNAUTHORIZED)
        self.assertEqual(len(gate._budget.charges), 0)

    def test_expensive_skill_needs_grant(self):
        gate = _gate()
        d = gate.invoke("pricey", {}, "agent", 1)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, REASON_PRE_AUTH_REQUIRED)
        self.assertEqual(len(gate._budget.charges), 0)

    def test_grant_flow_burns_one_shot(self):
        gate = _gate()
        gate.grant_pre_authorization("pricey", "agent", 10)
        self.assertTrue(gate.has_grant("pricey", "agent"))
        d = gate.invoke("pricey", {}, "agent", 11)
        self.assertTrue(d.allowed)
        self.assertTrue(d.pre_auth_used)
        # One-shot: the next expensive call needs a fresh grant.
        self.assertFalse(gate.has_grant("pricey", "agent"))
        d2 = gate.invoke("pricey", {}, "agent", 12)
        self.assertEqual(d2.reason, REASON_PRE_AUTH_REQUIRED)

    def test_denied_call_does_not_burn_grant(self):
        # Grant exists, but the caller is unauthorized: grant survives.
        registry = _registry()
        gate = _gate(registry=registry)
        gate.grant_pre_authorization("pricey", "mallory", 10)
        d = gate.invoke("pricey", {}, "mallory", 11)
        self.assertEqual(d.reason, REASON_UNAUTHORIZED)
        self.assertTrue(gate.has_grant("pricey", "mallory"))

    def test_grant_does_not_override_budget_run_ceiling(self):
        gate = _gate(budget_kwargs={"max_budget_usd": 0.01})
        gate.grant_pre_authorization("pricey", "agent", 10)
        d = gate.invoke("pricey", {}, "agent", 11)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, REASON_BUDGET_RUN)
        # Grant survived: authorization (grant) is not money.
        self.assertTrue(gate.has_grant("pricey", "agent"))

    def test_per_call_ceiling_refuses_runaway_skill(self):
        gate = _gate(budget_kwargs={
            "max_budget_usd": 100.0,
            "per_call_ceilings": {
                "model": 0.10,
                "tool": 0.01,  # default tool ceiling
                "memory_read": 0.001,
                "memory_write": 0.001,
            },
        })
        gate.grant_pre_authorization("pricey", "agent", 10)
        d = gate.invoke("pricey", {}, "agent", 11)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, REASON_BUDGET_PER_CALL)

    def test_requires_review_needs_grant_even_when_cheap(self):
        gate = _gate()
        d = gate.invoke("review-me", {}, "agent", 1)
        self.assertEqual(d.reason, REASON_PRE_AUTH_REQUIRED)
        gate.grant_pre_authorization("review-me", "agent", 2)
        d2 = gate.invoke("review-me", {}, "agent", 3)
        self.assertTrue(d2.allowed)

    def test_threshold_boundary(self):
        # cost == threshold needs a grant; just below does not.
        registry = SkillRegistry()
        registry.register(
            SkillPolicy(
                skill_name="edge",
                allowed_callers=frozenset({"agent"}),
                estimated_cost_usd=1.0,
            )
        )
        registry.register(
            SkillPolicy(
                skill_name="under",
                allowed_callers=frozenset({"agent"}),
                estimated_cost_usd=0.99,
            )
        )
        gate = _gate(registry=registry, expensive_threshold_usd=1.0)
        self.assertEqual(gate.invoke("edge", {}, "agent", 1).reason,
                         REASON_PRE_AUTH_REQUIRED)
        self.assertEqual(gate.invoke("under", {}, "agent", 2).reason,
                         REASON_AUTHORIZED)

    def test_constructor_validation(self):
        registry, budget = _registry(), PerCallBudget()
        with self.assertRaises(SkillBudgetError):
            SkillBudgetGate(registry="x", budget=budget)
        with self.assertRaises(SkillBudgetError):
            SkillBudgetGate(registry=registry, budget="x")
        with self.assertRaises(SkillBudgetError):
            SkillBudgetGate(registry=registry, budget=budget,
                            expensive_threshold_usd=-1.0)
        with self.assertRaises(SkillBudgetError):
            SkillBudgetGate(registry=registry, budget=budget,
                            expensive_threshold_usd=True)
        with self.assertRaises(SkillBudgetError):
            SkillBudgetGate(registry=registry, budget=budget,
                            budget_call_type="skill")

    def test_invoke_validation(self):
        gate = _gate()
        with self.assertRaises(SkillBudgetError):
            gate.invoke("", {}, "agent", 1)
        with self.assertRaises(SkillBudgetError):
            gate.invoke("cheap", {}, "", 1)
        with self.assertRaises(SkillBudgetError):
            gate.invoke("cheap", {}, "agent", True)
        with self.assertRaises(SkillBudgetError):
            gate.invoke("cheap", {}, "agent", -1)

    def test_grant_validation_and_revoke(self):
        gate = _gate()
        with self.assertRaises(SkillBudgetError):
            gate.grant_pre_authorization("", "agent", 1)
        with self.assertRaises(SkillBudgetError):
            gate.grant_pre_authorization("pricey", "", 1)
        with self.assertRaises(SkillBudgetError):
            gate.grant_pre_authorization("pricey", "agent", -1)
        g = gate.grant_pre_authorization("pricey", "agent", 5)
        self.assertIsInstance(g, PreAuthorization)
        # Duplicate grant overwrites deterministically (one live grant).
        g2 = gate.grant_pre_authorization("pricey", "agent", 6)
        self.assertEqual(len(gate.pending_grants()), 1)
        self.assertEqual(gate.pending_grants()[0].granted_seq, 6)
        self.assertTrue(gate.revoke_pre_authorization("pricey", "agent"))
        self.assertFalse(gate.revoke_pre_authorization("pricey", "agent"))

    def test_pending_grants_deterministic_order(self):
        gate = _gate()
        gate.grant_pre_authorization("pricey", "zed", 1)
        gate.grant_pre_authorization("pricey", "amy", 2)
        grants = gate.pending_grants()
        self.assertEqual([g.caller_id for g in grants], ["amy", "zed"])

    def test_decision_and_audit_shapes(self):
        gate = _gate()
        d = gate.invoke("cheap", {"q": 1}, "agent", 7)
        self.assertIsInstance(d, SkillBudgetDecision)
        asd = d.as_dict()
        self.assertEqual(asd["reason"], REASON_AUTHORIZED)
        self.assertEqual(asd["schema"], SCHEMA_PIN)
        self.assertEqual(asd["call"]["skill_name"], "cheap")
        evt = combo_audit_event(d, 100)
        self.assertEqual(evt["schema"], "audit.ndjson/1")
        self.assertEqual(evt["event"], "skill-budget-decision")
        self.assertEqual(evt["seq"], 100)
        self.assertTrue(evt["allowed"])
        with self.assertRaises(SkillBudgetError):
            combo_audit_event(d, -1)

    def test_code_mode_flows_through_same_gate(self):
        # skill_wiring's "code-mode" pseudo-skill is gated like any skill.
        from skill_wiring import CodeModeSession
        registry = SkillRegistry()
        registry.register(
            SkillPolicy(
                skill_name=CodeModeSession.CODE_MODE_SKILL,
                allowed_callers=frozenset({"agent"}),
                estimated_cost_usd=3.0,
            )
        )
        gate = _gate(registry=registry)
        d = gate.invoke(CodeModeSession.CODE_MODE_SKILL, "print(1)", "agent", 1)
        self.assertEqual(d.reason, REASON_PRE_AUTH_REQUIRED)
        gate.grant_pre_authorization(CodeModeSession.CODE_MODE_SKILL, "agent", 2)
        d2 = gate.invoke(CodeModeSession.CODE_MODE_SKILL, "print(1)", "agent", 3)
        self.assertTrue(d2.allowed)

    def test_grant_for_unknown_skill_survives_unauthorized(self):
        gate = _gate()
        gate.grant_pre_authorization("ghost", "agent", 1)
        d = gate.invoke("ghost", {}, "agent", 2)
        self.assertEqual(d.reason, REASON_UNAUTHORIZED)
        self.assertTrue(gate.has_grant("ghost", "agent"))

    def test_main_self_check(self):
        import skill_budget_combo
        skill_budget_combo.main()  # must not raise


if __name__ == "__main__":
    unittest.main()
