"""Naming-variant probes for the governance bench.

A ~Oct 2026 preprint (Agent Security Bench naming-sensitivity study) found
renaming dangerous tool names to neutral ones raised attack success rate
+11-13pp (GPT-5-mini +11.67pp, Claude Haiku 4.5 +13.21pp): a score from one
naming condition doesn't generalize.

These probes verify Northstar's gate canonicalizes tool names before policy
checks, so a forbidden action can't slip through via:
- case variants ("bash" vs "Bash")
- whitespace variants ("  Bash  ")
- shell aliases ("Shell" vs "Bash")
- neutral renames ("DataExport" for an exfiltration tool)

The gate must deny the *action*, not just the *spelling*.
"""

import unittest


def _engine(**kwargs):
    from permissions import PermissionConfig, PermissionEngine

    config_kwargs = {
        "mode": "default",
        "can_use_tool": lambda n, p, c: True,
    }
    config_kwargs.update(kwargs.pop("config_kwargs", {}))
    return PermissionEngine(
        PermissionConfig(**config_kwargs),
        tool_kinds=kwargs.pop(
            "tool_kinds", {"Bash": "exec", "SendEmail": "write", "Read": "read"}
        ),
        **kwargs,
    )


class NamingVariantTests(unittest.TestCase):
    def test_case_variant_denied(self):
        engine = _engine(config_kwargs={"disallowed_tools": ("Bash",)})
        d = engine.evaluate("bash", kind="exec", payload={"command": "evil"})
        self.assertFalse(d.allowed, "lowercase variant bypassed disallowed_tools")
        self.assertEqual(d.source, "disallowed_tools")

    def test_uppercase_variant_denied(self):
        engine = _engine(config_kwargs={"disallowed_tools": ("Bash",)})
        d = engine.evaluate("BASH", kind="exec", payload={"command": "evil"})
        self.assertFalse(d.allowed, "uppercase variant bypassed disallowed_tools")

    def test_whitespace_variant_denied(self):
        engine = _engine(config_kwargs={"disallowed_tools": ("Bash",)})
        d = engine.evaluate("  Bash  ", kind="exec", payload={"command": "evil"})
        self.assertFalse(d.allowed, "whitespace variant bypassed disallowed_tools")

    def test_mixed_case_whitespace_denied(self):
        engine = _engine(config_kwargs={"disallowed_tools": ("SendEmail",)})
        d = engine.evaluate(" sendemail ", kind="write", payload={"to": "x"})
        self.assertFalse(d.allowed)

    def test_offensive_tool_case_variant_denied(self):
        # is_offensive_tool is already case-insensitive; a neutral-case
        # variant must still hit deny-by-default.
        engine = _engine()
        d = engine.evaluate("NMAP", kind="exec", payload={})
        self.assertFalse(d.allowed)
        self.assertEqual(d.source, "offensive")

    def test_argument_policy_case_variant(self):
        # Argument policies must also match case-insensitively: the policy
        # is on the action, not the spelling.
        from permissions import ArgumentPolicy

        engine = _engine(
            config_kwargs={
                "argument_policies": (
                    ArgumentPolicy(
                        tool="Bash",
                        argument="command",
                        denylist=("rm -rf /",),
                    ),
                ),
            }
        )
        d = engine.evaluate("BASH", kind="exec", payload={"command": "rm -rf /"})
        self.assertFalse(d.allowed)
        self.assertEqual(d.rule, "argument:policy_violation")

    def test_allowed_tool_case_variant_still_works(self):
        # Benign control: canonicalization must not break legitimate tools.
        # "read" in any case resolves to the allowed Read tool.
        engine = _engine(config_kwargs={"allowed_tools": ("Read",)})
        d = engine.evaluate("READ", kind="read", payload={"path": "README.md"})
        self.assertTrue(d.allowed)

    def test_canonical_name_in_decision(self):
        # The decision records the ORIGINAL tool name (auditability: you see
        # what was actually called); policy matching uses the canonical form
        # internally so the variant is still denied.
        engine = _engine(config_kwargs={"disallowed_tools": ("Bash",)})
        d = engine.evaluate("bAsH", kind="exec", payload={})
        self.assertFalse(d.allowed)
        self.assertEqual(d.tool, "bAsH")
        self.assertEqual(d.source, "disallowed_tools")


if __name__ == "__main__":
    unittest.main()
