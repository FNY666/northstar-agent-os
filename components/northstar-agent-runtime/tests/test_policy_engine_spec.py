"""Tests for the policy_engine spec API: rule()/evaluate()/enforce().

Additive to tests/test_policy_engine.py: none of the pre-existing
load()/eval()/explain() behavior is retested here except through the
spec-named paths.
"""

import unittest
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from policy_engine import (  # noqa: E402
    POLICY_ENGINE_VERSION,
    DeniedActionError,
    DuplicateRuleError,
    InvalidPolicyError,
    PolicyEngine,
    PolicyEngineError,
    UnknownPolicyError,
    main,
    policy_engine_audit_event,
)


def _rbac_policy(**overrides):
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


_ADMIN = {"subject": {"role": "admin", "status": "active"}, "action": "write"}
_SUSPENDED = {"subject": {"role": "admin", "status": "suspended"}, "action": "write"}
_GUEST_READ = {"subject": {"role": "guest", "status": "active"}, "action": "read"}
_GUEST_WRITE = {"subject": {"role": "guest", "status": "active"}, "action": "write"}


class TestSpecApiPresent(unittest.TestCase):
    def test_spec_api_present(self):
        eng = PolicyEngine()
        self.assertTrue(callable(eng.rule))
        self.assertTrue(callable(eng.evaluate))
        self.assertTrue(callable(eng.enforce))
        self.assertTrue(issubclass(DuplicateRuleError, PolicyEngineError))
        self.assertTrue(issubclass(DeniedActionError, PolicyEngineError))


class TestRule(unittest.TestCase):
    def setUp(self):
        self.eng = PolicyEngine()
        self.rec = self.eng.load("rbac", _rbac_policy(), seq=1)

    def test_rule_appends_and_repins_digest(self):
        rec2 = self.eng.rule(
            "rbac",
            "guests-may-read",
            "allow",
            {"path": "action", "op": "eq", "value": "read"},
            seq=2,
        )
        self.assertEqual(rec2.rule_count, 3)
        self.assertEqual(rec2.name, "rbac")
        self.assertNotEqual(rec2.digest, self.rec.digest)
        self.assertTrue(rec2.digest.startswith("sha256:"))
        # The stored record is updated in place.
        self.assertEqual(self.eng.policy("rbac").digest, rec2.digest)

    def test_rule_changes_verdict(self):
        before = self.eng.evaluate(_GUEST_READ, seq=2)
        self.assertFalse(before.allowed)  # default deny
        rec2 = self.eng.rule(
            "rbac",
            "guests-may-read",
            "allow",
            {"path": "action", "op": "eq", "value": "read"},
            seq=3,
        )
        after = self.eng.evaluate(_GUEST_READ, seq=4)
        self.assertTrue(after.allowed)
        self.assertEqual(after.reason, "allow")
        self.assertEqual(after.policy_digest, rec2.digest)

    def test_rule_deny_still_overrides(self):
        self.eng.rule(
            "rbac",
            "suspended-admins-allow",
            "allow",
            {"path": "subject.role", "op": "eq", "value": "admin"},
            seq=2,
        )
        rep = self.eng.evaluate(_SUSPENDED, seq=3)
        self.assertFalse(rep.allowed)
        self.assertEqual(rep.reason, "deny")
        self.assertIn("suspended-deny", rep.fired_deny)

    def test_rule_unknown_policy(self):
        with self.assertRaises(UnknownPolicyError):
            self.eng.rule(
                "nope",
                "r1",
                "allow",
                {"path": "x", "op": "exists", "value": True},
                seq=2,
            )

    def test_rule_duplicate_id(self):
        with self.assertRaises(DuplicateRuleError):
            self.eng.rule(
                "rbac",
                "admins-allow",
                "allow",
                {"path": "x", "op": "exists", "value": True},
                seq=2,
            )

    def test_rule_bad_inputs(self):
        with self.assertRaises(InvalidPolicyError):  # bad decision
            self.eng.rule(
                "rbac", "r-bad", "maybe",
                {"path": "x", "op": "exists", "value": True}, seq=2,
            )
        with self.assertRaises(InvalidPolicyError):  # unknown op
            self.eng.rule(
                "rbac", "r-bad2", "allow",
                {"path": "x", "op": "frob", "value": True}, seq=2,
            )
        with self.assertRaises(TypeError):  # rule_id not a str
            self.eng.rule(
                "rbac", 42, "allow",
                {"path": "x", "op": "exists", "value": True}, seq=2,
            )
        with self.assertRaises(TypeError):  # bad seq
            self.eng.rule(
                "rbac", "r-bad3", "allow",
                {"path": "x", "op": "exists", "value": True}, seq=True,
            )


class TestEvaluate(unittest.TestCase):
    def setUp(self):
        self.eng = PolicyEngine()
        self.eng.load("rbac", _rbac_policy(), seq=1)

    def test_evaluate_matches_eval(self):
        for doc, want_allowed, want_reason in (
            (_ADMIN, True, "allow"),
            (_SUSPENDED, False, "deny"),
            (_GUEST_WRITE, False, "default"),
        ):
            got = self.eng.evaluate(doc, seq=2)
            want = self.eng.eval(doc, seq=2)
            self.assertEqual(got.allowed, want_allowed)
            self.assertEqual(got.reason, want_reason)
            self.assertEqual(got.digest, want.digest)
            self.assertEqual(got.policy_digest, want.policy_digest)

    def test_evaluate_named_policy(self):
        self.eng.load("strict", _rbac_policy(), seq=2)
        got = self.eng.evaluate(_ADMIN, seq=3, policy_name="strict")
        self.assertEqual(got.policy_name, "strict")
        self.assertTrue(got.allowed)

    def test_evaluate_bad_inputs(self):
        with self.assertRaises(UnknownPolicyError):
            self.eng.evaluate(_ADMIN, seq=2, policy_name="nope")
        self.eng.load("strict", _rbac_policy(), seq=2)  # now 2 policies loaded
        with self.assertRaises(PolicyEngineError):
            self.eng.evaluate(_ADMIN, seq=3)  # policy_name required


class TestEnforce(unittest.TestCase):
    def setUp(self):
        self.eng = PolicyEngine()
        self.eng.load("rbac", _rbac_policy(), seq=1)

    def test_enforce_allowed_returns_report(self):
        rep = self.eng.enforce(_ADMIN, seq=2)
        self.assertTrue(rep.allowed)
        self.assertEqual(rep.reason, "allow")
        self.assertTrue(rep.digest.startswith("sha256:"))
        self.assertEqual(rep.policy_digest, self.eng.policy("rbac").digest)

    def test_enforce_denied_raises(self):
        with self.assertRaises(DeniedActionError) as ctx:
            self.eng.enforce(_SUSPENDED, seq=2)
        msg = str(ctx.exception)
        self.assertIn("rbac", msg)
        self.assertIn("suspended-deny", msg)
        self.assertIn("reason=deny", msg)
        with self.assertRaises(PolicyEngineError):  # DeniedActionError is fail-closed
            self.eng.enforce(_GUEST_WRITE, seq=3)

    def test_enforce_default_deny_raises(self):
        with self.assertRaises(DeniedActionError) as ctx:
            self.eng.enforce(_GUEST_WRITE, seq=2)
        self.assertIn("reason=default", str(ctx.exception))


class TestAuditAndConventions(unittest.TestCase):
    def test_audit_new_kinds(self):
        evt = policy_engine_audit_event("ruled", 1, policy="rbac", rule="r1")
        self.assertEqual(evt["kind"], "policy-engine.ruled")
        self.assertEqual(evt["schema"], "audit.ndjson/1")
        self.assertEqual(evt["module"], POLICY_ENGINE_VERSION)
        evt2 = policy_engine_audit_event("enforced", 2, policy="rbac", allowed=True)
        self.assertEqual(evt2["kind"], "policy-engine.enforced")
        with self.assertRaises(PolicyEngineError):
            policy_engine_audit_event("nope", 3)

class TestMain(unittest.TestCase):
    def test_main(self):
        main()


if __name__ == "__main__":
    unittest.main()
