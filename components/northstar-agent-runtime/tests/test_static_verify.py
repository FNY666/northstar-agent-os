"""Tests for static_verify (ninety-first batch, Janus absorption)."""

import unittest

from static_verify import (
    ALLOW,
    DENY,
    DefinitionRegistry,
    DefinitionTamper,
    PolicyRule,
    StaticVerifier,
    StaticVerifyError,
    ToolDefinition,
    ToolParam,
    definition_digest,
    sha256_hex,
    sort_policy,
    verify_policy_structure,
)


def _read_file() -> ToolDefinition:
    return ToolDefinition(
        name="read_file",
        description="Read a file",
        params=(ToolParam("file_path", "string", required=True),),
        required_caps=frozenset({"fs.read"}),
    )


def _write_file() -> ToolDefinition:
    return ToolDefinition(
        name="write_file",
        description="Write a file",
        params=(
            ToolParam("file_path", "string", required=True),
            ToolParam("content", "string", required=True),
            ToolParam("mode", "string", required=False, enum=("w", "a")),
        ),
        required_caps=frozenset({"fs.write"}),
    )


def _registry() -> DefinitionRegistry:
    reg = DefinitionRegistry()
    reg.register(_read_file())
    reg.register(_write_file())
    return reg


def _policy() -> dict:
    return {
        "read_file": [
            PolicyRule(priority=1, effect=ALLOW, conditions={"file_path": {"type": "string", "pattern": r"^/data/"}}),
        ],
        "write_file": [
            PolicyRule(priority=1, effect=DENY, conditions={"file_path": {"type": "string", "pattern": r"^/etc/"}}),
            PolicyRule(priority=2, effect=ALLOW, conditions={}),
        ],
    }


class DigestTest(unittest.TestCase):
    def test_digest_stable(self):
        self.assertEqual(definition_digest(_read_file().to_dict()), _read_file().digest)

    def test_digest_changes_on_param_change(self):
        d1 = _read_file().digest
        altered = ToolDefinition(
            name="read_file",
            description="Read a file",
            params=(ToolParam("file_path", "string", required=False),),
            required_caps=frozenset({"fs.read"}),
        )
        self.assertNotEqual(d1, altered.digest)

    def test_digest_changes_on_caps_change(self):
        d1 = _read_file().digest
        altered = ToolDefinition(
            name="read_file",
            description="Read a file",
            params=(ToolParam("file_path", "string", required=True),),
            required_caps=frozenset({"fs.admin"}),
        )
        self.assertNotEqual(d1, altered.digest)

    def test_sha256_hex_known(self):
        self.assertEqual(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )


class RegistryTest(unittest.TestCase):
    def test_register_and_lookup(self):
        reg = _registry()
        self.assertEqual(reg.get("read_file").name, "read_file")
        self.assertIn("read_file", reg.names())

    def test_idempotent_reregister(self):
        reg = _registry()
        d1 = reg.register(_read_file())  # identical digest: no-op
        self.assertEqual(d1, reg.pinned_digest("read_file"))
        self.assertFalse(reg.is_tampered("read_file"))

    def test_tampered_reregister_raises_and_flags(self):
        reg = _registry()
        altered = ToolDefinition(
            name="read_file",
            description="Read a file (totally legit update)",
            params=(ToolParam("file_path", "string", required=True),),
            required_caps=frozenset({"fs.read"}),
        )
        with self.assertRaises(DefinitionTamper):
            reg.register(altered)
        self.assertTrue(reg.is_tampered("read_file"))

    def test_force_reregister_requires_reason(self):
        reg = _registry()
        altered = ToolDefinition(name="read_file", description="v2", params=())
        with self.assertRaises(StaticVerifyError):
            reg.force_reregister(altered, reason="  ")
        reg.force_reregister(altered, reason="schema migration, ticket-123")
        self.assertFalse(reg.is_tampered("read_file"))

    def test_bad_param_type_rejected(self):
        with self.assertRaises(StaticVerifyError):
            ToolParam("x", "nonsense")

    def test_duplicate_param_rejected(self):
        with self.assertRaises(StaticVerifyError):
            ToolDefinition(
                name="t",
                params=(ToolParam("a", "string"), ToolParam("a", "string")),
            )


class PolicyBuildTest(unittest.TestCase):
    def test_unknown_restriction_key_refused(self):
        with self.assertRaises(StaticVerifyError):
            PolicyRule(priority=1, effect=ALLOW, conditions={"x": {"contains": "y"}})

    def test_invalid_regex_refused(self):
        with self.assertRaises(StaticVerifyError):
            PolicyRule(priority=1, effect=ALLOW, conditions={"x": {"pattern": "(["}})

    def test_bad_effect_refused(self):
        with self.assertRaises(StaticVerifyError):
            PolicyRule(priority=1, effect=7, conditions={})

    def test_sort_deny_before_allow_same_priority(self):
        policy = sort_policy(
            {
                "t": [
                    PolicyRule(priority=1, effect=ALLOW, conditions={}),
                    PolicyRule(priority=1, effect=DENY, conditions={}),
                ]
            }
        )
        self.assertEqual(policy["t"][0].effect, DENY)

    def test_policy_unknown_tool_refused_at_build(self):
        reg = _registry()
        with self.assertRaises(StaticVerifyError):
            StaticVerifier(reg, {"nope": [PolicyRule(1, ALLOW, {})]})

    def test_policy_unknown_arg_refused_at_build(self):
        reg = _registry()
        bad = {"read_file": [PolicyRule(1, ALLOW, {"bogus_arg": {"type": "string"}})]}
        with self.assertRaises(StaticVerifyError):
            StaticVerifier(reg, bad)

    def test_verify_policy_structure_findings(self):
        reg = _registry()
        findings = verify_policy_structure(
            {"ghost": [PolicyRule(1, ALLOW, {})]}, reg
        )
        self.assertTrue(any("ghost" in f for f in findings))


class GateTest(unittest.TestCase):
    def setUp(self):
        self.v = StaticVerifier(_registry(), _policy())

    def test_clean_call_allowed(self):
        r = self.v.verify_call("read_file", {"file_path": "/data/a.csv"}, {"fs.read"})
        self.assertTrue(r.allowed)
        self.assertEqual(r.definition_digest, _read_file().digest)

    def test_unknown_tool_denied(self):
        r = self.v.verify_call("exec", {"cmd": "id"}, set())
        self.assertFalse(r.allowed)
        self.assertIn("unknown tool", r.reason)

    def test_pattern_violation_denied(self):
        r = self.v.verify_call("read_file", {"file_path": "/etc/passwd"}, {"fs.read"})
        self.assertFalse(r.allowed)

    def test_arg_smuggling_denied(self):
        r = self.v.verify_call(
            "read_file", {"file_path": "/data/a.csv", "extra": "x"}, {"fs.read"}
        )
        self.assertFalse(r.allowed)
        self.assertIn("smuggling", r.reason)

    def test_missing_required_denied(self):
        r = self.v.verify_call("read_file", {}, {"fs.read"})
        self.assertFalse(r.allowed)
        self.assertIn("missing required", r.reason)

    def test_type_mismatch_denied(self):
        r = self.v.verify_call("read_file", {"file_path": 42}, {"fs.read"})
        self.assertFalse(r.allowed)

    def test_missing_capability_denied(self):
        r = self.v.verify_call("read_file", {"file_path": "/data/a.csv"}, set())
        self.assertFalse(r.allowed)
        self.assertIn("lacks required capabilities", r.reason)

    def test_deny_rule_matches(self):
        r = self.v.verify_call(
            "write_file",
            {"file_path": "/etc/x", "content": "y"},
            {"fs.write"},
        )
        self.assertFalse(r.allowed)
        self.assertIn("deny rule matched", r.reason)

    def test_deny_before_allow_tiebreak(self):
        # /etc/ path is denied by priority-1 deny even though priority-2
        # allow has empty conditions.
        r = self.v.verify_call(
            "write_file",
            {"file_path": "/etc/x", "content": "y"},
            {"fs.write"},
        )
        self.assertFalse(r.allowed)

    def test_tool_not_in_policy_denied(self):
        reg = DefinitionRegistry()
        reg.register(_read_file())
        v = StaticVerifier(reg, {})  # no policy entries at all
        r = v.verify_call("read_file", {"file_path": "/data/a.csv"}, {"fs.read"})
        self.assertFalse(r.allowed)
        self.assertIn("default-deny", r.reason)

    def test_strict_allow_absent_arg_falls_through(self):
        # allow rule constrains mode, but the call omits mode -> the allow
        # rule must NOT match under strict mode; unconditional allow at
        # lower priority still allows. Here use a policy with ONLY the
        # strict rule to prove fall-through denies.
        reg = DefinitionRegistry()
        reg.register(_write_file())
        v = StaticVerifier(
            reg,
            {
                "write_file": [
                    PolicyRule(
                        priority=1,
                        effect=ALLOW,
                        conditions={"mode": {"type": "string", "enum": ["w"]}},
                    )
                ]
            },
        )
        r = v.verify_call(
            "write_file",
            {"file_path": "/data/a", "content": "x"},
            {"fs.write"},
        )
        self.assertFalse(r.allowed)
        self.assertIn("default-deny", r.reason)

    def test_tampered_tool_denies_everything(self):
        reg = _registry()
        altered = ToolDefinition(
            name="read_file",
            description="Read a file (updated)",
            params=(ToolParam("file_path", "string", required=True),),
            required_caps=frozenset({"fs.read"}),
        )
        with self.assertRaises(DefinitionTamper):
            reg.register(altered)
        v = StaticVerifier(reg, _policy())
        r = v.verify_call("read_file", {"file_path": "/data/a.csv"}, {"fs.read"})
        self.assertFalse(r.allowed)
        self.assertIn("tamper", r.reason)

    def test_renamed_tool_shadow_denied(self):
        # Attacker registers lookalike name hoping the policy for the real
        # tool applies: the lookalike has no policy entry -> default-deny.
        reg = _registry()
        reg.register(
            ToolDefinition(
                name="read_file_",
                description="Read a file",
                params=(ToolParam("file_path", "string", required=True),),
            )
        )
        v = StaticVerifier(reg, _policy())
        r = v.verify_call("read_file_", {"file_path": "/data/a.csv"}, set())
        self.assertFalse(r.allowed)

    def test_enum_violation_denied(self):
        r = self.v.verify_call(
            "write_file",
            {"file_path": "/data/a", "content": "x", "mode": "rwx"},
            {"fs.write"},
        )
        self.assertFalse(r.allowed)

    def test_denials_are_values_not_exceptions(self):
        # verify_call never raises for call-time denials.
        r = self.v.verify_call("ghost", {}, set())
        self.assertEqual(r.verdict, "deny")

    def test_events_recorded(self):
        self.v.verify_call("ghost", {}, set())
        kinds = [e["event"] for e in self.v.events()]
        self.assertIn("static_verify.decision", kinds)


if __name__ == "__main__":
    unittest.main()
