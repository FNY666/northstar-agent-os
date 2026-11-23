"""Targeted tests for the ABAC engine interface."""

import ast
import unittest
from pathlib import Path

from abac_engine import (
    ABACEngine,
    ABACError,
    DuplicatePolicyError,
    UnknownPolicyError,
    Decision,
    PolicyExplanation,
    PolicyRecord,
    RuleCondition,
    abac_engine_audit_event,
    ABAC_ENGINE_VERSION,
    ABAC_ENGINE_SCHEMA,
)

MODULE_PATH = Path(__file__).resolve().parent.parent / "abac_engine.py"


def cond(target, attribute, op, value):
    return {"target": target, "attribute": attribute, "op": op, "value": value}


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(ABAC_ENGINE_VERSION, "abac-engine.v1")
        self.assertEqual(ABAC_ENGINE_SCHEMA, "northstar.abac-engine.v1")

    def test_stdlib_only(self):
        tree = ast.parse(MODULE_PATH.read_text())
        allowed = {
            "__future__", "math", "re", "threading", "dataclasses",
            "typing", "canonical_json", "hashlib", "json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestAddPolicy(unittest.TestCase):
    def test_add_happy_path(self):
        e = ABACEngine()
        rec = e.add_policy("p1", "allow",
                           [[cond("subject", "role", "eq", "admin")]], seq=1)
        self.assertIsInstance(rec, PolicyRecord)
        self.assertEqual(rec.policy_id, "p1")
        self.assertEqual(rec.effect, "allow")
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(rec.version, "abac-engine.v1")
        self.assertEqual(rec.schema, "northstar.abac-engine.v1")
        self.assertEqual(len(rec.rules), 1)
        self.assertIsInstance(rec.rules[0][0], RuleCondition)

    def test_digest_determinism(self):
        e1, e2 = ABACEngine(), ABACEngine()
        r1 = e1.add_policy("p", "allow", [[cond("subject", "role", "eq", "a")]], seq=1)
        r2 = e2.add_policy("p", "allow", [[cond("subject", "role", "eq", "a")]], seq=1)
        self.assertEqual(r1.digest, r2.digest)

    def test_duplicate_policy_id(self):
        e = ABACEngine()
        e.add_policy("p", "allow", [[cond("subject", "role", "eq", "a")]], seq=1)
        with self.assertRaises(DuplicatePolicyError):
            e.add_policy("p", "deny", [[cond("subject", "role", "eq", "b")]], seq=2)

    def test_bad_effect(self):
        e = ABACEngine()
        with self.assertRaises(ABACError):
            e.add_policy("p", "maybe", [[cond("subject", "role", "eq", "a")]], seq=1)

    def test_unknown_op_refused_at_add_time(self):
        e = ABACEngine()
        with self.assertRaises(ABACError):
            e.add_policy("p", "allow", [[cond("subject", "role", "matches", "a")]], seq=1)

    def test_bad_target(self):
        e = ABACEngine()
        with self.assertRaises(ABACError):
            e.add_policy("p", "allow", [[cond("world", "role", "eq", "a")]], seq=1)

    def test_bad_attribute_path(self):
        e = ABACEngine()
        for bad in ("", ".role", "role.", "a..b"):
            with self.assertRaises(ABACError):
                e.add_policy("p", "allow", [[cond("subject", bad, "eq", "a")]], seq=1)

    def test_empty_rules_refused(self):
        e = ABACEngine()
        with self.assertRaises(ABACError):
            e.add_policy("p", "allow", [], seq=1)

    def test_vacuous_rule_refused(self):
        e = ABACEngine()
        with self.assertRaises(ABACError):
            e.add_policy("p", "allow", [[]], seq=1)

    def test_non_canonical_value_refused(self):
        e = ABACEngine()
        with self.assertRaises(ABACError):
            e.add_policy("p", "allow",
                         [[cond("subject", "x", "eq", float("nan"))]], seq=1)
        with self.assertRaises(ABACError):
            e.add_policy("p", "allow",
                         [[cond("subject", "x", "eq", 2 ** 54)]], seq=1)

    def test_bad_regex_refused_at_add_time(self):
        e = ABACEngine()
        with self.assertRaises(ABACError):
            e.add_policy("p", "allow",
                         [[cond("subject", "name", "regex", "([")]], seq=1)

    def test_in_needs_list(self):
        e = ABACEngine()
        with self.assertRaises(ABACError):
            e.add_policy("p", "allow",
                         [[cond("subject", "role", "in", "admin")]], seq=1)

    def test_comparison_needs_number(self):
        e = ABACEngine()
        with self.assertRaises(ABACError):
            e.add_policy("p", "allow",
                         [[cond("subject", "role", "gt", "admin")]], seq=1)

    def test_bad_seq(self):
        e = ABACEngine()
        for bad in (True, -1, "1"):
            with self.assertRaises(ABACError):
                e.add_policy("p", "allow", [[cond("subject", "role", "eq", "a")]], seq=bad)

    def test_rule_condition_input(self):
        e = ABACEngine()
        rec = e.add_policy("p", "allow",
                           [[RuleCondition("subject", "role", "eq", "a")]], seq=1)
        self.assertEqual(rec.rules[0][0].value, "a")


class TestEvaluate(unittest.TestCase):
    def _engine(self):
        e = ABACEngine()
        e.add_policy("admins", "allow",
                     [[cond("subject", "role", "eq", "admin")]], seq=1)
        e.add_policy("banned", "deny",
                     [[cond("subject", "banned", "eq", True)]], seq=2)
        return e

    def test_allow(self):
        d = self._engine().evaluate({"role": "admin"}, {"owner": "x"}, "read", seq=3)
        self.assertIsInstance(d, Decision)
        self.assertEqual(d.decision, "allow")
        self.assertEqual(d.matched_policies, ("admins",))
        self.assertTrue(d.digest.startswith("sha256:"))

    def test_deny_overrides(self):
        d = self._engine().evaluate({"role": "admin", "banned": True},
                                    {"owner": "x"}, "read", seq=3)
        self.assertEqual(d.decision, "deny")
        self.assertEqual(d.matched_policies, ("admins", "banned"))

    def test_default_deny(self):
        d = self._engine().evaluate({"role": "viewer"}, {"owner": "x"}, "read", seq=3)
        self.assertEqual(d.decision, "deny")
        self.assertEqual(d.matched_policies, ())

    def test_missing_attribute_is_false(self):
        d = self._engine().evaluate({}, {"owner": "x"}, "read", seq=3)
        self.assertEqual(d.decision, "deny")

    def test_nested_path(self):
        e = ABACEngine()
        e.add_policy("p", "allow",
                     [[cond("subject", "profile.clearance", "gte", 3)]], seq=1)
        d = e.evaluate({"profile": {"clearance": 4}}, {}, "read", seq=2)
        self.assertEqual(d.decision, "allow")
        d2 = e.evaluate({"profile": {"clearance": 2}}, {}, "read", seq=3)
        self.assertEqual(d2.decision, "deny")

    def test_action_value(self):
        e = ABACEngine()
        e.add_policy("p", "allow", [[cond("action", "value", "eq", "read")]], seq=1)
        self.assertEqual(e.evaluate({}, {}, "read", seq=2).decision, "allow")
        self.assertEqual(e.evaluate({}, {}, "write", seq=3).decision, "deny")

    def test_context_attribute(self):
        e = ABACEngine()
        e.add_policy("p", "allow",
                     [[cond("context", "mfa", "eq", True)]], seq=1)
        self.assertEqual(
            e.evaluate({}, {}, "read", seq=2, context={"mfa": True}).decision, "allow")
        self.assertEqual(
            e.evaluate({}, {}, "read", seq=3, context={"mfa": False}).decision, "deny")

    def test_or_of_and_rules(self):
        e = ABACEngine()
        e.add_policy("p", "allow", [
            [cond("subject", "role", "eq", "admin")],
            [cond("subject", "role", "eq", "editor"),
             cond("resource", "sensitivity", "eq", "low")],
        ], seq=1)
        self.assertEqual(e.evaluate({"role": "admin"}, {}, "read", seq=2).decision, "allow")
        self.assertEqual(
            e.evaluate({"role": "editor"}, {"sensitivity": "low"}, "read", seq=3).decision,
            "allow")
        self.assertEqual(
            e.evaluate({"role": "editor"}, {"sensitivity": "high"}, "read", seq=4).decision,
            "deny")

    def test_bool_is_not_int(self):
        e = ABACEngine()
        e.add_policy("p", "allow", [[cond("subject", "flag", "eq", 1)]], seq=1)
        self.assertEqual(e.evaluate({"flag": True}, {}, "read", seq=2).decision, "deny")
        self.assertEqual(e.evaluate({"flag": 1}, {}, "read", seq=3).decision, "allow")

    def test_int_is_not_float(self):
        e = ABACEngine()
        e.add_policy("p", "allow", [[cond("subject", "n", "eq", 1)]], seq=1)
        self.assertEqual(e.evaluate({"n": 1.0}, {}, "read", seq=2).decision, "deny")

    def test_type_mismatch_comparison_is_false(self):
        e = ABACEngine()
        e.add_policy("p", "allow", [[cond("subject", "n", "gt", 3)]], seq=1)
        self.assertEqual(e.evaluate({"n": "big"}, {}, "read", seq=2).decision, "deny")
        self.assertEqual(e.evaluate({"n": 5}, {}, "read", seq=3).decision, "allow")

    def test_in_operator(self):
        e = ABACEngine()
        e.add_policy("p", "allow",
                     [[cond("subject", "role", "in", ["admin", "editor"])]], seq=1)
        self.assertEqual(e.evaluate({"role": "editor"}, {}, "read", seq=2).decision, "allow")
        self.assertEqual(e.evaluate({"role": "viewer"}, {}, "read", seq=3).decision, "deny")

    def test_contains_list_and_str(self):
        e = ABACEngine()
        e.add_policy("p", "allow",
                     [[cond("subject", "scopes", "contains", "read")]], seq=1)
        self.assertEqual(
            e.evaluate({"scopes": ["read", "write"]}, {}, "read", seq=2).decision, "allow")
        e.add_policy("q", "allow",
                     [[cond("resource", "path", "contains", "/etc")]], seq=3)
        self.assertEqual(
            e.evaluate({"scopes": []}, {"path": "/etc/passwd"}, "read", seq=4).decision,
            "allow")

    def test_startswith_endswith(self):
        e = ABACEngine()
        e.add_policy("p", "allow",
                     [[cond("resource", "path", "startswith", "/pub/")]], seq=1)
        self.assertEqual(
            e.evaluate({}, {"path": "/pub/x"}, "read", seq=2).decision, "allow")
        self.assertEqual(
            e.evaluate({}, {"path": "/priv/x"}, "read", seq=3).decision, "deny")

    def test_regex(self):
        e = ABACEngine()
        e.add_policy("p", "allow",
                     [[cond("subject", "email", "regex", r"@corp\.example$")]], seq=1)
        self.assertEqual(
            e.evaluate({"email": "a@corp.example"}, {}, "read", seq=2).decision, "allow")
        self.assertEqual(
            e.evaluate({"email": "a@evil.example"}, {}, "read", seq=3).decision, "deny")

    def test_decision_determinism(self):
        e = self._engine()
        d1 = e.evaluate({"role": "admin"}, {"owner": "x"}, "read", seq=3)
        d2 = e.evaluate({"role": "admin"}, {"owner": "x"}, "read", seq=3)
        self.assertEqual(d1.digest, d2.digest)

    def test_bad_inputs(self):
        e = self._engine()
        with self.assertRaises(ABACError):
            e.evaluate("nope", {}, "read", seq=1)
        with self.assertRaises(ABACError):
            e.evaluate({}, {}, "", seq=1)
        with self.assertRaises(ABACError):
            e.evaluate({}, {}, "read", seq=True)


class TestExplain(unittest.TestCase):
    def test_explain(self):
        e = ABACEngine()
        e.add_policy("p1", "allow", [
            [cond("subject", "role", "eq", "admin")],
            [cond("resource", "sensitivity", "ne", "high"),
             cond("action", "value", "eq", "read")],
        ], seq=1)
        expl = e.explain("p1", seq=2)
        self.assertIsInstance(expl, PolicyExplanation)
        self.assertEqual(expl.policy_id, "p1")
        self.assertEqual(expl.effect, "allow")
        self.assertEqual(expl.rule_count, 2)
        self.assertEqual(len(expl.rendered_rules), 2)
        self.assertIn("subject.role eq 'admin'", expl.rendered_rules[0])
        self.assertIn("AND", expl.rendered_rules[1])
        self.assertTrue(expl.digest.startswith("sha256:"))

    def test_explain_unknown(self):
        e = ABACEngine()
        with self.assertRaises(UnknownPolicyError):
            e.explain("nope", seq=1)


class TestViewsAndAudit(unittest.TestCase):
    def test_views(self):
        e = ABACEngine()
        e.add_policy("b", "allow", [[cond("subject", "r", "eq", "a")]], seq=1)
        e.add_policy("a", "deny", [[cond("subject", "r", "eq", "b")]], seq=2)
        self.assertEqual(e.policies(), ("a", "b"))
        self.assertEqual(e.policy_count(), 2)
        self.assertEqual(e.policy("a").effect, "deny")
        with self.assertRaises(UnknownPolicyError):
            e.policy("zzz")

    def test_frozen_records(self):
        e = ABACEngine()
        rec = e.add_policy("p", "allow", [[cond("subject", "r", "eq", "a")]], seq=1)
        with self.assertRaises(Exception):
            rec.policy_id = "q"  # type: ignore[misc]

    def test_audit_shapes(self):
        ev = abac_engine_audit_event("policy-added", 1, policy_id="p")
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["kind"], "policy-added")
        self.assertEqual(ev["module"], "abac_engine")
        self.assertEqual(ev["seq"], 1)
        self.assertEqual(ev["detail"]["policy_id"], "p")
        with self.assertRaises(ABACError):
            abac_engine_audit_event("nope", 1)
        with self.assertRaises(ABACError):
            abac_engine_audit_event("evaluated", -1)

    def test_main(self):
        import abac_engine
        abac_engine.main()


if __name__ == "__main__":
    unittest.main()
