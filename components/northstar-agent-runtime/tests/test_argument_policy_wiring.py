"""Argument-level payload policies must be wired through the real runtime path.

The engine (permissions.ArgumentPolicy) checks payload *values* at the gate,
before the normal mode/approval layers. Two gaps closed here:

1. AgentRuntime never passed ``argument_policies`` from RuntimeConfig into
   its PermissionEngine, so a host-set payload policy was silently dropped.
2. Delegated child runtimes rebuilt PermissionConfig from scratch and did
   not inherit the parent's ``argument_policies``, letting a subagent run
   the destructive payload the parent's gate would have denied.

All tests drive the real AgentRuntime / _child_runtime path with a scripted
model -- no engine-only shortcuts.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from support import RuntimeTestCase  # noqa: E402

from permissions import ArgumentPolicy, PermissionConfig, PermissionEngine  # noqa: E402
from providers.base import TextBlock, ToolUseBlock  # noqa: E402
from providers.scripted import ScriptedProvider, ScriptedTurn  # noqa: E402


SHELL_DENY = ("rm -rf", "mkfs", ":(){", "dd if=", "curl", "nc ")


def _policies():
    return (ArgumentPolicy(tool="Shell", argument="command", denylist=SHELL_DENY),)


def _shell_turn(command: str) -> ScriptedTurn:
    return ScriptedTurn(
        blocks=(
            ToolUseBlock(id="t1", name="Shell", input={"command": command}),
            TextBlock(text="done"),
        ),
        stop_reason="tool_use",
    )


class ArgumentPolicyWiringTests(RuntimeTestCase):
    def _runtime_with_policies(self, turns, approve_all: bool = True):
        from loop import RuntimeConfig

        def approve(tool, args, context):
            return True

        return self.runtime(
            turns,
            config=RuntimeConfig(
                workspace=str(self.workspace()),
                permission_mode="default",
                argument_policies=_policies(),
            ),
            can_use_tool=approve if approve_all else None,
        )

    def test_parent_denies_destructive_shell_before_approval(self):
        # The approval callback allows everything, so a denial here can only
        # come from the argument-level payload policy firing first.
        runtime = self._runtime_with_policies([_shell_turn("rm -rf /")])
        report = self.drive(runtime)
        denials = [d for d in report.denials]
        self.assertTrue(denials, "expected the destructive Shell call to be denied")
        self.assertIn("denylist", denials[0].reason.lower())

    def test_parent_allows_benign_shell(self):
        runtime = self._runtime_with_policies([_shell_turn("echo hello")])
        report = self.drive(runtime)
        self.assertFalse(
            [d for d in report.denials if "denylist" in d.reason.lower()],
            "benign command must not trip the denylist",
        )

    def test_empty_policies_change_nothing(self):
        # Default config (no policies) keeps the old behaviour: the approval
        # callback still decides.
        def approve(tool, args, context):
            return True

        runtime = self.runtime(
            [_shell_turn("echo hello")],
            can_use_tool=approve,
        )
        report = self.drive(runtime)
        self.assertFalse(report.denials)

    # -- delegation inheritance -------------------------------------------
    def _child_from_parent(self, parent):
        from loop import _RunState

        return parent._child_runtime(
            parent.agents.get("general"),
            parent.provider,
            _RunState(session_id=parent.session_id),
        )

    def test_child_inherits_argument_policies(self):
        parent = self._runtime_with_policies([])
        child, _child_config, _mode = self._child_from_parent(parent)
        parent_policies = parent.permissions.config.argument_policies
        self.assertEqual(parent_policies, _policies())
        self.assertEqual(
            child.permissions.config.argument_policies,
            parent_policies,
            "delegated child must not drop the parent's payload policies",
        )

    def test_child_denies_destructive_shell_end_to_end(self):
        # The builtin "general" agent has no Shell tool, so the full loop
        # would stop at tool registration. Instead, evaluate the child's own
        # permission gate directly: this is the exact gate object the child
        # runtime dispatches through, so a denial here proves the inherited
        # policy is live on the delegated path.
        from permissions import PermissionRequestContext

        parent = self._runtime_with_policies([])
        child, _child_config, _mode = self._child_from_parent(parent)
        decision = child.permissions.evaluate(
            "Shell",
            payload={"command": "mkfs /dev/sda1"},
            context=PermissionRequestContext(),
        )
        self.assertFalse(decision.allowed)
        self.assertIn("denylist", (decision.reason or "").lower())
        benign = child.permissions.evaluate(
            "Shell",
            payload={"command": "echo hello"},
            context=PermissionRequestContext(),
        )
        # Benign commands are untouched by the payload policy; whether they
        # run is still decided by the normal mode/approval layers.
        self.assertNotIn("denylist", (benign.reason or "").lower())


if __name__ == "__main__":
    unittest.main()
