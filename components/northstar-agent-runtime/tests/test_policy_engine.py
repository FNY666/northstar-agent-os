"""Tests for policy_engine.py: OPA-style allow/deny rules, eval, explain."""

import ast
import threading
import unittest
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from policy_engine import (  # noqa: E402
    POLICY_ENGINE_VERSION,
    SCHEMA_PIN,
    ConditionTrace,
    DecisionReport,
    DuplicatePolicyError,
    ExplanationReport,
    InvalidInputError,
    InvalidPolicyError,
    PolicyEngine,
    PolicyEngineError,
    PolicyRecord,
    RuleTrace,
    UnknownPolicyError,
    main,
    policy_engine_audit_event,
)


def _simple_policy(**overrides):
    base = {
        "default_allow": False,
        "rules": [
            {
                "id": "admins-allow",
                "decision": "allow",
                "when": {"path": "subject.role", "op": "eq", "value": "admin"},
            },
            {
                "id": "suspended-deny",
                "decision": "deny",
                "when": {"path": "subject.status", "op": "eq", "value": "suspended"},
            },
        ],
    }
    base.update(overrides)
    return base


class TestPins(unittest.TestCase):
    def test_version_and_schema(self):
        self.assertEqual(POLICY_ENGINE_VERSION, "policy-engine.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.policy-engine.v1")


class TestLoad(unittest.TestCase):
    def setUp(self):
        self.eng = PolicyEngine()

    def test_load_shape(self):
        rec = self.eng.load("p1", _simple_policy(), seq=1)
        self.assertIsInstance(rec, PolicyRecord)
        self.assertEqual(rec.name, "p1")
        self.assertFalse(rec.default_allow)
        self.assertEqual(rec.rule_count, 2)
        self.assertTrue(rec.digest.startswith("sha256:"))

    def test_load_duplicate(self):
        self.eng.load("p1", _simple_policy(), seq=1)
        with self.assertRaises(DuplicatePolicyError):
            self.eng.load("p1", _simple_policy(), seq=2)

    def test_load_digest_deterministic(self):
        r1 = self.eng.load("a", _simple_policy(), seq=1)
        r2 = PolicyEngine().load("b", _simple_policy(), seq=1)
        self.assertNotEqual(r1.digest, r2.digest)  # name binds
        r3 = PolicyEngine().load("b", _simple_policy(), seq=1)
        self.assertEqual(r2.digest, r3.digest)

    def test_load_not_mapping(self):
        with self.assertRaises(InvalidPolicyError):
            self.eng.load("p1", ["not", "a", "mapping"], seq=1)

    def test_load_rules_not_list(self):
        with self.assertRaises(InvalidPolicyError):
            self.eng.load("p1", {"rules": "nope"}, seq=1)

    def test_load_rule_missing_id(self):
        policy = {"rules": [{"decision": "allow", "when": {"path": "a", "op": "exists"}}]}
        with self.assertRaises(TypeError):
            self.eng.load("p1", policy, seq=1)

    def test_load_rule_bad_decision(self):
        policy = {
            "rules": [
                {
                    "id": "r1",
                    "decision": "maybe",
                    "when": {"path": "a", "op": "exists"},
                }
            ]
        }
        with self.assertRaises(InvalidPolicyError):
            self.eng.load("p1", policy, seq=1)

    def test_load_rule_duplicate_ids(self):
        rule = {"id": "r1", "decision": "allow", "when": {"path": "a", "op": "exists"}}
        with self.assertRaises(InvalidPolicyError):
            self.eng.load("p1", {"rules": [rule, dict(rule)]}, seq=1)

    def test_load_rule_missing_when(self):
        with self.assertRaises(InvalidPolicyError):
            self.eng.load("p1", {"rules": [{"id": "r1", "decision": "allow"}]}, seq=1)

    def test_load_unknown_op(self):
        policy = {
            "rules": [
                {"id": "r1", "decision": "allow",
                 "when": {"path": "a", "op": "approximately", "value": 1}}
            ]
        }
        with self.assertRaises(InvalidPolicyError):
            self.eng.load("p1", policy, seq=1)

    def test_load_bad_default_allow_type(self):
        with self.assertRaises(TypeError):
            self.eng.load("p1", {"default_allow": "yes"}, seq=1)

    def test_load_bad_seq(self):
        with self.assertRaises(TypeError):
            self.eng.load("p1", _simple_policy(), seq=True)
        with self.assertRaises(ValueError):
            self.eng.load("p1", _simple_policy(), seq=-1)

    def test_policy_views(self):
        self.eng.load("beta", _simple_policy(), seq=1)
        self.eng.load("alpha", _simple_policy(), seq=2)
        self.assertEqual(self.eng.policies(), ("alpha", "beta"))
        self.assertIsInstance(self.eng.policy("alpha"), PolicyRecord)
        with self.assertRaises(UnknownPolicyError):
            self.eng.policy("missing")


class TestEval(unittest.TestCase):
    def setUp(self):
        self.eng = PolicyEngine()
        self.eng.load("p1", _simple_policy(), seq=1)

    def test_allow_fires(self):
        rep = self.eng.eval({"subject": {"role": "admin"}}, seq=1)
        self.assertIsInstance(rep, DecisionReport)
        self.assertTrue(rep.allowed)
        self.assertEqual(rep.reason, "allow")
        self.assertEqual(rep.fired_allow, ("admins-allow",))
        self.assertEqual(rep.fired_deny, ())
        self.assertTrue(rep.digest.startswith("sha256:"))

    def test_deny_overrides_allow(self):
        inp = {"subject": {"role": "admin", "status": "suspended"}}
        rep = self.eng.eval(inp, seq=2)
        self.assertFalse(rep.allowed)
        self.assertEqual(rep.reason, "deny")
        self.assertEqual(rep.fired_deny, ("suspended-deny",))
        self.assertEqual(rep.fired_allow, ("admins-allow",))

    def test_default_deny(self):
        rep = self.eng.eval({"subject": {"role": "guest"}}, seq=3)
        self.assertFalse(rep.allowed)
        self.assertEqual(rep.reason, "default")
        self.assertEqual(rep.fired_allow, ())
        self.assertEqual(rep.fired_deny, ())

    def test_default_allow_policy(self):
        eng = PolicyEngine()
        eng.load("open", {"default_allow": True, "rules": []}, seq=1)
        rep = eng.eval({"anything": 1}, seq=1)
        self.assertTrue(rep.allowed)
        self.assertEqual(rep.reason, "default")

    def test_unknown_policy(self):
        with self.assertRaises(UnknownPolicyError):
            self.eng.eval({}, seq=1, policy_name="nope")

    def test_policy_name_required_with_multiple(self):
        self.eng.load("p2", _simple_policy(), seq=2)
        with self.assertRaises(PolicyEngineError):
            self.eng.eval({}, seq=3)
        rep = self.eng.eval({"subject": {"role": "admin"}}, seq=3, policy_name="p2")
        self.assertTrue(rep.allowed)

    def test_input_not_mapping(self):
        with self.assertRaises(InvalidInputError):
            self.eng.eval([1, 2], seq=1)

    def test_input_nan_refused(self):
        with self.assertRaises(InvalidPolicyError):
            self.eng.eval({"x": float("nan")}, seq=1)

    def test_report_binds_policy_digest(self):
        rec = self.eng.policy("p1")
        rep = self.eng.eval({"subject": {"role": "admin"}}, seq=1)
        self.assertEqual(rep.policy_digest, rec.digest)
        self.assertEqual(rep.policy_name, "p1")


class TestConditions(unittest.TestCase):
    def setUp(self):
        self.eng = PolicyEngine()

    def _eval(self, when, doc, decision="allow", rid="r1"):
        eng = PolicyEngine()
        eng.load(
            "t",
            {"rules": [{"id": rid, "decision": decision, "when": when}]},
            seq=1,
        )
        return eng.eval(doc, seq=1)

    def test_numeric_comparisons(self):
        when = {"path": "n", "op": "gte", "value": 10}
        self.assertTrue(self._eval(when, {"n": 10}).allowed)
        self.assertTrue(self._eval(when, {"n": 10.5}).allowed)
        self.assertFalse(self._eval(when, {"n": 9.9}).allowed)

    def test_bool_is_not_a_number(self):
        when = {"path": "flag", "op": "gt", "value": 0}
        # bool actual against a numeric op fails closed, never matches
        self.assertFalse(self._eval(when, {"flag": True}).allowed)

    def test_ne_and_type_strictness(self):
        when = {"path": "n", "op": "eq", "value": 1}
        self.assertFalse(self._eval(when, {"n": True}).allowed)
        when2 = {"path": "n", "op": "ne", "value": 1}
        self.assertTrue(self._eval(when2, {"n": True}).allowed)

    def test_in_op(self):
        when = {"path": "action", "op": "in", "value": ["read", "list"]}
        self.assertTrue(self._eval(when, {"action": "read"}).allowed)
        self.assertFalse(self._eval(when, {"action": "delete"}).allowed)

    def test_contains_string_and_list(self):
        when = {"path": "path", "op": "contains", "value": "secret"}
        self.assertTrue(self._eval(when, {"path": "/a/secret/b"}).allowed)
        self.assertFalse(self._eval(when, {"path": "/a/public"}).allowed)
        when2 = {"path": "scopes", "op": "contains", "value": "write"}
        self.assertTrue(self._eval(when2, {"scopes": ["read", "write"]}).allowed)
        self.assertFalse(self._eval(when2, {"scopes": 42}).allowed)

    def test_startswith_endswith(self):
        when = {"path": "res", "op": "startswith", "value": "/admin"}
        self.assertTrue(self._eval(when, {"res": "/admin/x"}).allowed)
        when2 = {"path": "file", "op": "endswith", "value": ".md"}
        self.assertFalse(self._eval(when2, {"file": "a.txt"}).allowed)

    def test_exists(self):
        when = {"path": "mfa", "op": "exists", "value": True}
        self.assertTrue(self._eval(when, {"mfa": None}).allowed)
        self.assertFalse(self._eval(when, {}).allowed)
        when2 = {"path": "mfa", "op": "exists", "value": False}
        self.assertTrue(self._eval(when2, {}).allowed)

    def test_missing_path_fails_closed(self):
        when = {"path": "deep.missing.here", "op": "eq", "value": "x"}
        self.assertFalse(self._eval(when, {"other": 1}).allowed)

    def test_all_any_not(self):
        when = {
            "all": [
                {"path": "a", "op": "eq", "value": 1},
                {"any": [
                    {"path": "b", "op": "eq", "value": 2},
                    {"not": {"path": "c", "op": "eq", "value": 3}},
                ]},
            ]
        }
        self.assertTrue(self._eval(when, {"a": 1, "b": 2, "c": 3}).allowed)
        self.assertTrue(self._eval(when, {"a": 1, "b": 9, "c": 4}).allowed)
        self.assertFalse(self._eval(when, {"a": 1, "b": 9, "c": 3}).allowed)
        self.assertFalse(self._eval(when, {"a": 0, "b": 2, "c": 3}).allowed)

    def test_dotted_path_nested(self):
        when = {"path": "subject.tenant.region", "op": "eq", "value": "eu"}
        self.assertTrue(
            self._eval(when, {"subject": {"tenant": {"region": "eu"}}}).allowed
        )


class TestExplain(unittest.TestCase):
    def setUp(self):
        self.eng = PolicyEngine()
        self.eng.load("p1", _simple_policy(), seq=1)

    def test_explain_shape(self):
        inp = {"subject": {"role": "admin", "status": "suspended"}}
        expl = self.eng.explain(inp, seq=1)
        self.assertIsInstance(expl, ExplanationReport)
        self.assertFalse(expl.allowed)
        self.assertEqual(len(expl.rules), 2)
        self.assertTrue(expl.digest.startswith("sha256:"))
        by_id = {t.rule_id: t for t in expl.rules}
        self.assertTrue(by_id["suspended-deny"].fired)
        self.assertTrue(by_id["admins-allow"].fired)
        self.assertEqual(by_id["admins-allow"].decision, "allow")
        for t in expl.rules:
            self.assertTrue(t.digest.startswith("sha256:"))

    def test_explain_condition_detail(self):
        inp = {"subject": {"role": "guest", "status": "active"}}
        expl = self.eng.explain(inp, seq=1)
        by_id = {t.rule_id: t for t in expl.rules}
        self.assertFalse(by_id["admins-allow"].fired)
        trace = by_id["admins-allow"].conditions[0]
        self.assertIsInstance(trace, ConditionTrace)
        self.assertEqual(trace.path, "subject.role")
        self.assertEqual(trace.op, "eq")
        self.assertEqual(trace.expected, "admin")
        self.assertEqual(trace.actual, "guest")
        self.assertFalse(trace.matched)
        self.assertTrue(trace.detail)

    def test_explain_matches_eval_verdict(self):
        cases = [
            ({"subject": {"role": "admin", "status": "active"}}, True),
            ({"subject": {"role": "admin", "status": "suspended"}}, False),
            ({"subject": {"role": "guest"}}, False),
        ]
        for doc, expected in cases:
            self.assertEqual(self.eng.eval(doc, seq=1).allowed, expected)
            self.assertEqual(self.eng.explain(doc, seq=2).allowed, expected)


class TestAudit(unittest.TestCase):
    def test_shapes(self):
        evt = policy_engine_audit_event("policy-loaded", 1, policy="p1")
        self.assertEqual(evt["schema"], "audit.ndjson/1")
        self.assertEqual(evt["kind"], "policy-engine.policy-loaded")
        self.assertEqual(evt["module"], POLICY_ENGINE_VERSION)
        self.assertEqual(evt["policy"], "p1")
        evt2 = policy_engine_audit_event("evaluated", 2, allowed=True)
        self.assertEqual(evt2["kind"], "policy-engine.evaluated")

    def test_unknown_kind(self):
        with self.assertRaises(PolicyEngineError):
            policy_engine_audit_event("nope", 1)

    def test_bad_seq(self):
        with self.assertRaises(TypeError):
            policy_engine_audit_event("evaluated", True)


class TestConcurrency(unittest.TestCase):
    def test_thread_safe_eval(self):
        eng = PolicyEngine()
        eng.load("p1", _simple_policy(), seq=1)
        results = []

        def worker():
            rep = eng.eval({"subject": {"role": "admin"}}, seq=1)
            results.append(rep.allowed)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results, [True] * 8)


class TestStdlibOnly(unittest.TestCase):
    def test_stdlib_only(self):
        path = Path(__file__).resolve().parent.parent / "policy_engine.py"
        tree = ast.parse(path.read_text())
        allowed = {
            "hashlib", "threading", "dataclasses", "typing", "__future__", "json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed, a.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed, node.module)


class TestMain(unittest.TestCase):
    def test_main(self):
        main()


if __name__ == "__main__":
    unittest.main()
