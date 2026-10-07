"""Tests for skill_wiring: per-call authorization + budget enforcement."""
from __future__ import annotations

import unittest

import skill_wiring
from skill_wiring import (
    BudgetExhausted,
    CallBudget,
    ClosedSession,
    CodeModeSession,
    SkillCall,
    SkillDecision,
    SkillPolicy,
    SkillRegistry,
    SkillWiringError,
    UnauthorizedCall,
    args_digest,
    authorize_skill_call,
    decide_skill_call,
    make_default_registry,
)


def _policy(name="deploy", callers=("agent-1",), cost=0.05):
    return SkillPolicy(
        skill_name=name,
        allowed_callers=frozenset(callers),
        estimated_cost_usd=cost,
    )


def _call(name="deploy", caller="agent-1", seq=1):
    return SkillCall(
        skill_name=name,
        args_hash=args_digest({"env": "prod"}),
        caller_id=caller,
        seq=seq,
    )


class ArgsDigestTests(unittest.TestCase):
    def test_deterministic(self):
        self.assertEqual(args_digest({"a": 1, "b": 2}), args_digest({"b": 2, "a": 1}))

    def test_differs_on_content(self):
        self.assertNotEqual(args_digest({"a": 1}), args_digest({"a": 2}))

    def test_sha256_prefixed(self):
        self.assertTrue(args_digest("x").startswith("sha256:"))

    def test_non_json_args_fall_back(self):
        d = args_digest(object())
        self.assertTrue(d.startswith("sha256:"))


class SkillCallTests(unittest.TestCase):
    def test_frozen(self):
        call = _call()
        with self.assertRaises(AttributeError):
            call.seq = 99  # type: ignore[misc]

    def test_as_dict_shape(self):
        d = _call().as_dict()
        self.assertEqual(
            set(d), {"skill_name", "args_hash", "caller_id", "seq", "version"}
        )
        self.assertEqual(d["version"], skill_wiring.SKILL_WIRING_VERSION)


class AuthorizeTests(unittest.TestCase):
    def test_unknown_skill_denied(self):
        self.assertFalse(authorize_skill_call(_call(), None))

    def test_allowed_caller(self):
        self.assertTrue(authorize_skill_call(_call(), _policy()))

    def test_other_caller_denied(self):
        self.assertFalse(authorize_skill_call(_call(caller="agent-9"), _policy()))

    def test_empty_caller_denied(self):
        self.assertFalse(authorize_skill_call(_call(caller=""), _policy()))

    def test_name_mismatch_denied(self):
        self.assertFalse(authorize_skill_call(_call(name="other"), _policy()))

    def test_empty_allow_list_denies_everyone(self):
        self.assertFalse(authorize_skill_call(_call(), _policy(callers=())))


class RegistryTests(unittest.TestCase):
    def test_register_and_lookup(self):
        reg = SkillRegistry()
        reg.register(_policy())
        self.assertEqual(reg.policy_for("deploy").allowed_callers, frozenset({"agent-1"}))
        self.assertIsNone(reg.policy_for("nope"))

    def test_register_rejects_empty_name(self):
        reg = SkillRegistry()
        with self.assertRaises(SkillWiringError):
            reg.register(_policy(name=""))

    def test_register_rejects_negative_cost(self):
        reg = SkillRegistry()
        with self.assertRaises(SkillWiringError):
            reg.register(_policy(cost=-1.0))

    def test_known_skills_sorted(self):
        reg = SkillRegistry()
        reg.register(_policy(name="zeta"))
        reg.register(_policy(name="alpha"))
        self.assertEqual(reg.known_skills(), ("alpha", "zeta"))


class CallBudgetTests(unittest.TestCase):
    def test_charge_within_ceiling(self):
        b = CallBudget(ceiling_usd=1.0)
        self.assertTrue(b.try_charge(0.4))
        self.assertAlmostEqual(b.spent_usd, 0.4)
        self.assertAlmostEqual(b.remaining, 0.6)
        self.assertFalse(b.exhausted)

    def test_charge_over_ceiling_denied_and_not_applied(self):
        b = CallBudget(ceiling_usd=1.0)
        self.assertFalse(b.try_charge(1.5))
        self.assertAlmostEqual(b.spent_usd, 0.0)

    def test_exact_ceiling_exhausts(self):
        b = CallBudget(ceiling_usd=1.0)
        self.assertTrue(b.try_charge(1.0))
        self.assertTrue(b.exhausted)
        self.assertFalse(b.try_charge(0.01))

    def test_negative_charge_denied(self):
        b = CallBudget(ceiling_usd=1.0)
        self.assertFalse(b.try_charge(-0.5))
        self.assertAlmostEqual(b.spent_usd, 0.0)

    def test_negative_ceiling_rejected(self):
        with self.assertRaises(SkillWiringError):
            CallBudget(ceiling_usd=-1.0)

    def test_spent_over_ceiling_rejected(self):
        with self.assertRaises(SkillWiringError):
            CallBudget(ceiling_usd=1.0, spent_usd=2.0)


class DecideSkillCallTests(unittest.TestCase):
    def test_authorized_charges_budget(self):
        reg = SkillRegistry()
        reg.register(_policy(cost=0.05))
        budget = CallBudget(ceiling_usd=1.0)
        decision = decide_skill_call(_call(), reg, budget)
        self.assertIsInstance(decision, SkillDecision)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, "authorized")
        self.assertAlmostEqual(decision.cost_usd, 0.05)
        self.assertAlmostEqual(budget.spent_usd, 0.05)

    def test_unauthorized_does_not_touch_budget(self):
        reg = SkillRegistry()  # no policy registered
        budget = CallBudget(ceiling_usd=1.0)
        decision = decide_skill_call(_call(), reg, budget)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "unauthorized")
        self.assertAlmostEqual(budget.spent_usd, 0.0)

    def test_budget_exhausted_after_authorization(self):
        reg = SkillRegistry()
        reg.register(_policy(cost=0.05))
        budget = CallBudget(ceiling_usd=0.01)
        decision = decide_skill_call(_call(), reg, budget)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "budget-exhausted")
        self.assertAlmostEqual(budget.spent_usd, 0.0)


class CodeModeSessionTests(unittest.TestCase):
    def _session(self, callers=("agent-1",), ceiling=1.0, cost=0.02, ran=None):
        reg = make_default_registry(code_mode_callers=callers, code_mode_cost_usd=cost)
        budget = CallBudget(ceiling_usd=ceiling)
        seen = ran if ran is not None else []
        session = CodeModeSession(
            caller_id="agent-1",
            registry=reg,
            budget=budget,
            executor=lambda code: seen.append(code) or "ok:" + code,
        )
        return session, budget, seen

    def test_execute_runs_through_gate(self):
        session, budget, seen = self._session()
        result = session.execute("print('hi')")
        self.assertEqual(result, "ok:print('hi')")
        self.assertEqual(seen, ["print('hi')"])
        self.assertEqual(session.executed_count, 1)
        self.assertAlmostEqual(budget.spent_usd, 0.02)

    def test_execute_unauthorized_caller_never_reaches_executor(self):
        session, budget, seen = self._session(callers=("someone-else",))
        with self.assertRaises(UnauthorizedCall):
            session.execute("print('hi')")
        self.assertEqual(seen, [])
        self.assertAlmostEqual(budget.spent_usd, 0.0)

    def test_execute_budget_exhausted_never_reaches_executor(self):
        session, budget, seen = self._session(ceiling=0.01, cost=0.02)
        with self.assertRaises(BudgetExhausted):
            session.execute("print('hi')")
        self.assertEqual(seen, [])
        self.assertEqual(session.executed_count, 0)

    def test_execute_after_close_raises(self):
        session, _, _ = self._session()
        session.close()
        self.assertTrue(session.closed)
        with self.assertRaises(ClosedSession):
            session.execute("print('hi')")

    def test_execute_empty_code_rejected(self):
        session, _, seen = self._session()
        with self.assertRaises(SkillWiringError):
            session.execute("")
        self.assertEqual(seen, [])

    def test_empty_caller_id_rejected(self):
        reg = make_default_registry(code_mode_callers=("agent-1",))
        with self.assertRaises(SkillWiringError):
            CodeModeSession(
                caller_id="",
                registry=reg,
                budget=CallBudget(ceiling_usd=1.0),
                executor=lambda code: code,
            )

    def test_seq_increments_per_call(self):
        digests = []
        reg = make_default_registry(code_mode_callers=("agent-1",))
        budget = CallBudget(ceiling_usd=10.0)

        def executor(code):
            return code

        session = CodeModeSession(
            caller_id="agent-1", registry=reg, budget=budget, executor=executor
        )
        session.execute("a = 1")
        session.execute("b = 2")
        self.assertEqual(session.executed_count, 2)
        # distinct code digests, distinct calls: both were gated individually
        self.assertNotEqual(args_digest("a = 1"), args_digest("b = 2"))

    def test_budget_drains_across_calls(self):
        session, budget, seen = self._session(ceiling=0.05, cost=0.02)
        session.execute("1")
        session.execute("2")
        with self.assertRaises(BudgetExhausted):
            session.execute("3")
        self.assertEqual(len(seen), 2)


class MakeDefaultRegistryTests(unittest.TestCase):
    def test_builds_from_spec(self):
        reg = make_default_registry(
            {"deploy": {"allowed_callers": ["agent-1"], "estimated_cost_usd": 0.1}},
            code_mode_callers=("agent-1",),
        )
        policy = reg.policy_for("deploy")
        self.assertIsNotNone(policy)
        assert policy is not None
        self.assertEqual(policy.allowed_callers, frozenset({"agent-1"}))
        self.assertAlmostEqual(policy.estimated_cost_usd, 0.1)
        code_policy = reg.policy_for(CodeModeSession.CODE_MODE_SKILL)
        self.assertIsNotNone(code_policy)

    def test_empty_spec_still_registers_code_mode(self):
        reg = make_default_registry(code_mode_callers=("agent-1",))
        self.assertIn(CodeModeSession.CODE_MODE_SKILL, reg.known_skills())


if __name__ == "__main__":
    unittest.main()
