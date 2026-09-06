import unittest

from agents import AgentRegistry, SubagentDefinition
from helpers import make_runtime, tool_results_of
from permissions import PermissionGate

KINDS = {"Read": "read", "Grep": "read", "List": "read", "Write": "edit", "Edit": "edit",
         "CodexReadOnly": "exec", "Task": "delegate"}


def gate(**kwargs) -> PermissionGate:
    base = dict(permission_mode="default", tool_kinds=KINDS)
    base.update(kwargs)
    return PermissionGate(**base)


def readonly_agent(name="evaluator", **kwargs) -> SubagentDefinition:
    base = dict(name=name, description="d", system="s", tools=("Read", "Grep", "List"))
    base.update(kwargs)
    base["tools"] = tuple(base["tools"])
    return SubagentDefinition(**base)


class GateConstructionTests(unittest.TestCase):
    def test_tool_in_both_lists_raises(self):
        with self.assertRaises(ValueError):
            gate(allowed_tools=("Read",), disallowed_tools=("Read",))

    def test_unknown_mode_raises(self):
        with self.assertRaises(ValueError):
            gate(permission_mode="yolo")


class TierPrecedenceTests(unittest.TestCase):
    def test_disallowed_wins_over_everything(self):
        g = gate(disallowed_tools=("Read",), permission_mode="bypassPermissions")
        decision = g.check_tool("Read", "read", {})
        self.assertFalse(decision.allowed)
        self.assertIn("disallowed", decision.reason)

    def test_overlap_between_lists_is_rejected_at_construction(self):
        # A tool cannot be both allowed and disallowed: the guard fails fast
        # instead of letting a silently contradictory policy run.
        with self.assertRaises(ValueError):
            gate(allowed_tools=("Write",), disallowed_tools=("Write",))

    def test_explicit_allow_auto_approves_mutating_in_default_mode(self):
        g = gate(allowed_tools=("Write",))
        decision = g.check_tool("Write", "edit", {})
        self.assertTrue(decision.allowed)

    def test_default_mode_denies_mutating_without_callback(self):
        g = gate()
        decision = g.check_tool("Write", "edit", {})
        self.assertFalse(decision.allowed)
        self.assertIn("requires approval", decision.reason)
        self.assertIn("deny", decision.reason)

    def test_default_mode_callback_can_approve(self):
        g = gate(can_use_tool=lambda name, inp, mode: True)
        self.assertTrue(g.check_tool("Write", "edit", {}).allowed)

    def test_default_mode_callback_can_deny_with_reason(self):
        g = gate(can_use_tool=lambda name, inp, mode: {"approved": False, "reason": "no writes after 18:00"})
        decision = g.check_tool("Write", "edit", {})
        self.assertFalse(decision.allowed)
        self.assertIn("no writes after 18:00", decision.reason)

    def test_broken_callback_denies(self):
        def broken(name, inp, mode):
            raise RuntimeError("callback exploded")

        g = gate(can_use_tool=broken)
        decision = g.check_tool("Write", "edit", {})
        self.assertFalse(decision.allowed)
        self.assertIn("callback exploded", decision.reason)

    def test_read_tools_never_need_approval(self):
        g = gate()
        self.assertTrue(g.check_tool("Read", "read", {}).allowed)
        self.assertTrue(g.check_tool("Grep", "read", {}).allowed)


class ModeTests(unittest.TestCase):
    def test_acceptEdits_auto_approves_edits_only(self):
        g = gate(permission_mode="acceptEdits")
        self.assertTrue(g.check_tool("Write", "edit", {}).allowed)
        self.assertTrue(g.check_tool("Edit", "edit", {}).allowed)
        self.assertFalse(g.check_tool("CodexReadOnly", "exec", {}).allowed)

    def test_acceptEdits_still_asks_callback_for_exec(self):
        seen = []
        g = gate(permission_mode="acceptEdits", can_use_tool=lambda n, i, m: seen.append(n) or True)
        self.assertTrue(g.check_tool("CodexReadOnly", "exec", {}).allowed)
        self.assertEqual(seen, ["CodexReadOnly"])

    def test_plan_denies_mutating_outright(self):
        g = gate(permission_mode="plan", can_use_tool=lambda n, i, m: True)
        decision = g.check_tool("Write", "edit", {})
        self.assertFalse(decision.allowed)
        self.assertIn("plan mode", decision.reason)
        self.assertTrue(g.check_tool("Read", "read", {}).allowed)

    def test_bypass_permissions_passes_mutating(self):
        g = gate(permission_mode="bypassPermissions")
        self.assertTrue(g.check_tool("Write", "edit", {}).allowed)
        self.assertTrue(g.check_tool("CodexReadOnly", "exec", {}).allowed)


class TaskDelegationGateTests(unittest.TestCase):
    def test_readonly_subagent_passes_without_any_callback(self):
        g = gate(subagents=AgentRegistry([readonly_agent()]))
        decision = g.check_tool("Task", "delegate", {"agent": "evaluator"})
        self.assertTrue(decision.allowed, decision.reason)

    def test_subagent_declaring_disallowed_tool_denied_naming_that_tool(self):
        agent = readonly_agent(tools=("Read", "Write"))
        g = gate(subagents=AgentRegistry([agent]), disallowed_tools=("Write",))
        decision = g.check_tool("Task", "delegate", {"agent": "evaluator"})
        self.assertFalse(decision.allowed)
        self.assertIn("Write", decision.reason)
        self.assertIn("evaluator", decision.reason)
        self.assertNotRegex(decision.reason, r"^.*tool 'Task' is disallowed")

    def test_subagent_declaring_write_in_default_mode_denied_naming_write_not_task(self):
        agent = readonly_agent(tools=("Read", "Write"))
        g = gate(subagents=AgentRegistry([agent]))  # no callback
        decision = g.check_tool("Task", "delegate", {"agent": "evaluator"})
        self.assertFalse(decision.allowed)
        self.assertIn("Write", decision.reason)
        self.assertIn("requires approval", decision.reason)

    def test_unknown_agent_denied(self):
        g = gate(subagents=AgentRegistry([readonly_agent()]))
        decision = g.check_tool("Task", "delegate", {"agent": "ghost"})
        self.assertFalse(decision.allowed)
        self.assertIn("unknown agent 'ghost'", decision.reason)

    def test_subagent_declaring_unavailable_tool_denied(self):
        agent = readonly_agent(tools=("Read", "CodexReadOnly"))
        g = gate(subagents=AgentRegistry([agent]))
        g._tool_kinds.pop("CodexReadOnly")  # not registered in this context (no socket)
        decision = g.check_tool("Task", "delegate", {"agent": "evaluator"})
        self.assertFalse(decision.allowed)
        self.assertIn("CodexReadOnly", decision.reason)
        self.assertIn("not available", decision.reason)

    def test_callback_is_invoked_for_mutating_declared_tools(self):
        seen = []
        agent = readonly_agent(tools=("Read", "Write"))
        g = gate(subagents=AgentRegistry([agent]),
                 can_use_tool=lambda n, i, m: seen.append(n) or True)
        decision = g.check_tool("Task", "delegate", {"agent": "evaluator"})
        self.assertTrue(decision.allowed, decision.reason)
        self.assertEqual(seen, ["Write"], "only the mutating declared tool may be asked")

    def test_missing_agent_field_denied(self):
        g = gate(subagents=AgentRegistry([readonly_agent()]))
        self.assertFalse(g.check_tool("Task", "delegate", {}).allowed)


class RuntimePermissionFlowTests(unittest.TestCase):
    def test_denied_write_reaches_model_as_error_and_run_continues(self):
        runtime, provider = make_runtime(
            [
                {"text": "writing", "tools": [{"name": "Write", "input": {"path": "a.txt", "content": "x"}}]},
                "ok",
            ],
            permission_mode="default",  # no callback
        )
        report = runtime.run("go")
        self.assertEqual(report.result.subtype, "success")
        results = tool_results_of(provider.calls[1])
        self.assertTrue(results[0]["is_error"])
        self.assertIn("requires approval", results[0]["content"])
        self.assertFalse((runtime.workspace / "a.txt").exists())
        # denial is surfaced as an informational system event
        infos = [
            e for e in report.events
            if getattr(e, "subtype", None) == "informational" and "denied" in e.data.get("note", "")
        ]
        self.assertTrue(infos)

    def test_bypass_mode_executes_write(self):
        runtime, _ = make_runtime(
            [
                {"text": "writing", "tools": [{"name": "Write", "input": {"path": "a.txt", "content": "x"}}]},
                "ok",
            ],
            permission_mode="bypassPermissions",
        )
        report = runtime.run("go")
        self.assertEqual(report.result.subtype, "success")
        self.assertTrue((runtime.workspace / "a.txt").exists())

    def test_task_denial_message_never_blames_task_itself(self):
        agent = readonly_agent(tools=("Read", "Write"))
        runtime, provider = make_runtime(
            [
                {"text": "delegating", "tools": [{"name": "Task", "input": {"agent": "evaluator", "prompt": "p"}}]},
                "ok",
            ],
            subagents=AgentRegistry([agent]),
            permission_mode="default",  # no callback: Write cannot be approved
        )
        runtime.run("go")
        results = tool_results_of(provider.calls[1])
        self.assertTrue(results[0]["is_error"])
        self.assertIn("Write", results[0]["content"])
        self.assertNotIn("tool 'Task' is disallowed", results[0]["content"])
        self.assertNotIn("mutating tool 'Task'", results[0]["content"])


if __name__ == "__main__":
    unittest.main()
