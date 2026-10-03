"""Structured decision-model approval path: format, policy, gate wiring.
"""
from __future__ import annotations

import unittest

import support  # noqa: F401

from decision_model import (
    DecisionModelResult,
    DecisionPolicy,
    DecisionQuestion,
    QuestionAnswer,
    StaticDecisionModel,
    adjudicate,
    approval_questions,
    build_decision_audit,
    build_decision_state,
)
from permissions import (
    PermissionConfig,
    PermissionDecision,
    PermissionEngine,
    PermissionRequestContext,
    digest_arguments,
)


def _allow_spec(p: float = 0.95) -> dict:
    return {"verdict": {"allow": p, "deny": (1 - p) / 2, "escalate": (1 - p) / 2}, "approval": p}


def _deny_spec(p: float = 0.93) -> dict:
    return {"verdict": {"allow": (1 - p) / 2, "deny": p, "escalate": (1 - p) / 2}, "approval": 1 - p}


def _ctx(call_id: str = "call-1") -> PermissionRequestContext:
    return PermissionRequestContext(
        session_id="s1",
        agent="main",
        call_id=call_id,
        arguments_digest=digest_arguments({"path": "a.txt"}),
    )


class QuestionValidationTests(unittest.TestCase):
    def test_choice_needs_two_options(self):
        with self.assertRaises(ValueError):
            DecisionQuestion(name="q", type="choice", criteria={"only": "one"})

    def test_score_needs_ordered_levels(self):
        with self.assertRaises(ValueError):
            DecisionQuestion(name="q", type="score", legend=("low",))

    def test_noul_takes_no_criteria(self):
        with self.assertRaises(ValueError):
            DecisionQuestion(name="q", type="noul", criteria={"a": "b"})

    def test_empty_name_rejected(self):
        with self.assertRaises(ValueError):
            DecisionQuestion(name="  ", type="noul")

    def test_canonical_schema(self):
        questions = approval_questions()
        self.assertEqual(set(questions), {"approval", "verdict"})
        self.assertEqual(questions["approval"].type, "noul")
        self.assertEqual(questions["verdict"].type, "choice")


class StateBuilderTests(unittest.TestCase):
    def test_digest_travels_not_raw_arguments(self):
        state = build_decision_state(
            "Write", kind="edit", mutating=True, context=_ctx(),
            payload_digest=digest_arguments({"secret": 1}),
        )
        self.assertEqual(state["arguments_digest"], digest_arguments({"secret": 1}))
        self.assertNotIn("secret", str(state))
        self.assertEqual(state["call_id"], "call-1")
        self.assertTrue(state["features"]["is_mutating"])
        self.assertTrue(state["features"]["is_edit"])
        self.assertFalse(state["features"]["is_network"])


class PolicyTests(unittest.TestCase):
    def test_thresholds_must_straddle(self):
        with self.assertRaises(ValueError):
            DecisionPolicy(approve_threshold=0.5, deny_threshold=0.5)
        with self.assertRaises(ValueError):
            DecisionPolicy(approve_threshold=0.2, deny_threshold=0.8)

    def test_confidence_bounded(self):
        with self.assertRaises(ValueError):
            DecisionPolicy(min_confidence=1.5)

    def _choice_result(self, dist: dict) -> DecisionModelResult:
        return DecisionModelResult(
            answers={
                "verdict": QuestionAnswer(
                    name="verdict", type="choice",
                    probabilities=dict(dist), choice="allow", confidence=max(dist.values()),
                )
            },
            model="t",
        )

    def test_choice_allow_above_confidence(self):
        outcome, _ = adjudicate(
            self._choice_result({"allow": 0.9, "deny": 0.05, "escalate": 0.05}),
            DecisionPolicy(),
        )
        self.assertEqual(outcome, "allow")

    def test_choice_low_confidence_escalates(self):
        outcome, reason = adjudicate(
            self._choice_result({"allow": 0.4, "deny": 0.35, "escalate": 0.25}),
            DecisionPolicy(min_confidence=0.6),
        )
        self.assertEqual(outcome, "escalate")
        self.assertIn("confidence", reason)

    def test_malformed_probabilities_escalate(self):
        outcome, _ = adjudicate(
            self._choice_result({"allow": 0.3, "deny": 0.2, "escalate": 0.0}),
            DecisionPolicy(),
        )
        self.assertEqual(outcome, "escalate")

    def test_noul_thresholds(self):
        policy = DecisionPolicy(approve_threshold=0.8, deny_threshold=0.2)

        def noul(p: float) -> DecisionModelResult:
            return DecisionModelResult(
                answers={
                    "approval": QuestionAnswer(
                        name="approval", type="noul",
                        probabilities={"yes": p, "no": 1 - p}, confidence=p,
                    )
                },
                model="t",
            )

        self.assertEqual(adjudicate(noul(0.9), policy)[0], "allow")
        self.assertEqual(adjudicate(noul(0.1), policy)[0], "deny")
        self.assertEqual(adjudicate(noul(0.5), policy)[0], "escalate")

    def test_no_usable_answer_escalates(self):
        outcome, _ = adjudicate(DecisionModelResult(answers={}, model="t"), DecisionPolicy())
        self.assertEqual(outcome, "escalate")


class StaticModelTests(unittest.TestCase):
    def test_deterministic_and_keyed(self):
        model = StaticDecisionModel(
            profiles={"tool:Write": _allow_spec(0.95), "kind:exec": _allow_spec(0.02)},
            default=_allow_spec(0.5),
        )
        questions = approval_questions()
        first = model.decide({"tool": "Write", "kind": "edit"}, questions)
        second = model.decide({"tool": "Write", "kind": "edit"}, questions)
        self.assertEqual(first.as_dict(), second.as_dict())
        self.assertEqual(first.answers["verdict"].choice, "allow")
        by_kind = model.decide({"tool": "Bash", "kind": "exec"}, questions)
        self.assertEqual(by_kind.answers["verdict"].choice, "deny")
        fallback = model.decide({"tool": "Other", "kind": "read"}, questions)
        self.assertAlmostEqual(fallback.answers["approval"].probabilities["yes"], 0.5)

    def test_bad_profile_raises(self):
        model = StaticDecisionModel(
            profiles={"tool:Write": {"verdict": {"allow": 0.3, "deny": 0.2, "escalate": 0.0}}}
        )
        with self.assertRaises(ValueError):
            model.decide({"tool": "Write", "kind": "edit"}, approval_questions())


class GateWiringTests(unittest.TestCase):
    def _engine(self, model, host_verdict=True):
        calls: list[str] = []

        def host_callback(name, payload, ctx):
            calls.append(name)
            return host_verdict

        engine = PermissionEngine(
            PermissionConfig(mode="default", can_use_tool=host_callback, decision_model=model)
        )
        return engine, calls

    def test_model_allow_decides(self):
        engine, calls = self._engine(StaticDecisionModel(profiles={"tool:Write": _allow_spec()}))
        decision = engine.evaluate("Write", kind="edit", payload={"path": "a.txt"}, context=_ctx())
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.source, "decision_model")
        self.assertEqual(decision.rule, "decision_model:allow")
        self.assertEqual(calls, [])  # host callback not consulted
        audit = decision.decision_model_audit
        self.assertIsNotNone(audit)
        assert audit is not None
        self.assertEqual(audit["outcome"], "allow")
        self.assertIn("probabilities", str(audit["output"]))
        self.assertEqual(audit["input"]["state"]["call_id"], "call-1")
        self.assertEqual(
            audit["input"]["state"]["arguments_digest"], digest_arguments({"path": "a.txt"})
        )

    def test_model_deny_decides(self):
        engine, calls = self._engine(
            StaticDecisionModel(profiles={"tool:Bash": _deny_spec()})
        )
        decision = engine.evaluate("Bash", kind="exec", context=_ctx("call-9"))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.source, "decision_model")
        self.assertEqual(decision.rule, "decision_model:deny")
        self.assertEqual(calls, [])

    def test_escalate_defers_to_host_callback(self):
        engine, calls = self._engine(
            StaticDecisionModel(
                profiles={
                    "tool:WebFetch": {
                        "verdict": {"allow": 0.4, "deny": 0.35, "escalate": 0.25},
                        "approval": 0.5,
                    }
                }
            ),
            host_verdict=False,
        )
        decision = engine.evaluate("WebFetch", kind="network", context=_ctx())
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.source, "host_callback")
        self.assertEqual(calls, ["WebFetch"])

    def test_raising_model_falls_back_never_grants(self):
        class Broken:
            model_name = "broken"

            def decide(self, state, questions):
                raise RuntimeError("outage")

        engine, calls = self._engine(Broken(), host_verdict=True)
        decision = engine.evaluate("Write", kind="edit", context=_ctx())
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.source, "host_callback")  # fallback path, not the model
        self.assertEqual(calls, ["Write"])

    def test_no_model_keeps_deterministic_path(self):
        calls: list[str] = []

        def host_callback(name, payload, ctx):
            calls.append(name)
            return False

        engine = PermissionEngine(
            PermissionConfig(mode="default", can_use_tool=host_callback)
        )
        decision = engine.evaluate("Write", kind="edit", context=_ctx())
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.source, "host_callback")
        self.assertIsNone(decision.decision_model_audit)
        self.assertEqual(calls, ["Write"])

    def test_config_validation(self):
        with self.assertRaises(TypeError):
            PermissionConfig(decision_model=object())
        with self.assertRaises(TypeError):
            PermissionConfig(decision_policy="not-a-policy")

    def test_as_dict_shape(self):
        with_audit = PermissionDecision(
            True, source="decision_model", tool="Write",
            decision_model_audit={"type": "decision_model"},
        )
        self.assertIn("decision_model_audit", with_audit.as_dict())
        without = PermissionDecision(True, source="mode", tool="Read")
        self.assertNotIn("decision_model_audit", without.as_dict())

    def test_audit_builder(self):
        questions = approval_questions()
        model = StaticDecisionModel(default=_allow_spec(0.9))
        state = build_decision_state("Write", kind="edit", mutating=True, context=_ctx())
        result = model.decide(state, questions)
        policy = DecisionPolicy()
        outcome, reason = adjudicate(result, policy)
        audit = build_decision_audit(
            state=state, questions=questions, result=result,
            policy=policy, outcome=outcome, reason=reason,
        )
        self.assertEqual(audit["type"], "decision_model")
        self.assertEqual(audit["outcome"], "allow")
        self.assertEqual(audit["policy"]["approve_threshold"], 0.8)


if __name__ == "__main__":
    unittest.main()
