import unittest

from agents import AgentRegistry, SubagentDefinition, evaluator_agent
from providers.scripted import ScriptedProvider

from helpers import make_runtime, make_workspace, tool_results_of


def child_agent(name, tools, script, **kwargs):
    provider = kwargs.pop("provider", ScriptedProvider(script))
    base = dict(name=name, description=name, system=f"you are {name}", tools=tuple(tools), provider=provider)
    base.update(kwargs)
    base["tools"] = tuple(base["tools"])
    return SubagentDefinition(**base)


class SubagentContextTests(unittest.TestCase):
    def test_subagent_gets_a_fresh_context(self):
        # The parent's prompt must not leak into the child's model requests.
        child = child_agent("worker", ("Read",), ["done"], provider=ScriptedProvider(["done"]))
        runtime, _ = make_runtime(
            [
                {"text": "delegating", "tools": [{"name": "Task", "input": {"agent": "worker", "prompt": "task prompt"}}]},
                "ok",
            ],
            subagents=AgentRegistry([child]),
        )
        report = runtime.run("PARENT-SECRET-PROMPT")
        self.assertEqual(report.result.subtype, "success")
        child_provider = child.provider
        self.assertEqual(len(child_provider.calls), 1)
        first = child_provider.calls[0]
        self.assertEqual(first.messages[0]["content"], "task prompt")
        self.assertNotIn("PARENT-SECRET-PROMPT", str(first.messages))
        self.assertEqual(first.system, "you are worker")

    def test_child_uses_declared_model(self):
        child = child_agent("worker", ("Read",), ["done"], model="claude-haiku-4-5")
        runtime, _ = make_runtime(
            [
                {"text": "delegating", "tools": [{"name": "Task", "input": {"agent": "worker", "prompt": "p"}}]},
                "ok",
            ],
            subagents=AgentRegistry([child]),
        )
        runtime.run("go")
        self.assertEqual(child.provider.calls[0].model, "claude-haiku-4-5")

    def test_tool_subset_is_enforced(self):
        child = child_agent("worker", ("Read",), [
            {"text": "try to write", "tools": [{"name": "Write", "input": {"path": "x.txt", "content": "x"}}]},
            "ok",
        ])
        runtime, _ = make_runtime(
            [
                {"text": "delegating", "tools": [{"name": "Task", "input": {"agent": "worker", "prompt": "p"}}]},
                "ok",
            ],
            subagents=AgentRegistry([child]),
            permission_mode="bypassPermissions",
        )
        report = runtime.run("go")
        child_results = tool_results_of(child.provider.calls[1])
        self.assertTrue(child_results[0]["is_error"])
        self.assertIn("unknown tool: Write", child_results[0]["content"])
        self.assertEqual(report.result.subtype, "success")


class SubagentLimitTests(unittest.TestCase):
    def test_child_max_turns_caps_the_subagent(self):
        child = child_agent("worker", ("Read",), [
            {"text": "r1", "tools": [{"name": "Read", "input": {"path": "a.txt"}}]},
            {"text": "r2", "tools": [{"name": "Read", "input": {"path": "b.txt"}}]},
        ], max_turns=2)
        runtime, _ = make_runtime(
            [
                {"text": "delegating", "tools": [{"name": "Task", "input": {"agent": "worker", "prompt": "p"}}]},
                "ok",
            ],
            subagents=AgentRegistry([child]),
        )
        report = runtime.run("go")
        self.assertEqual(report.result.subtype, "success", "parent survives a capped child")
        # the Task tool result must carry the child's error subtype
        parent_results = tool_results_of(runtime.provider.calls[1])
        self.assertTrue(parent_results[0]["is_error"])
        self.assertIn("error_max_turns", parent_results[0]["content"])
        self.assertEqual(len(child.provider.calls), 2, "the child must stop at its own cap")

    def test_child_budget_cap_caps_the_subagent(self):
        child = child_agent(
            "worker", ("Read",),
            [{"text": "r1", "tools": [{"name": "Read", "input": {"path": "a.txt"}}],
              "usage": {"input_tokens": 1_000_000, "output_tokens": 10}}],
            max_budget_usd=1.0,  # 1M input tokens on sonnet costs $3 > $1
        )
        runtime, _ = make_runtime(
            [
                {"text": "delegating", "tools": [{"name": "Task", "input": {"agent": "worker", "prompt": "p"}}]},
                "ok",
            ],
            subagents=AgentRegistry([child]),
        )
        report = runtime.run("go")
        parent_results = tool_results_of(runtime.provider.calls[1])
        self.assertTrue(parent_results[0]["is_error"])
        self.assertIn("error_max_budget_usd", parent_results[0]["content"])

    def test_child_spend_counts_toward_parent_budget(self):
        child = child_agent(
            "worker", ("Read",),
            [{"text": "r1", "usage": {"input_tokens": 1_000_000, "output_tokens": 0}}],
        )
        runtime, _ = make_runtime(
            [
                {"text": "delegating", "tools": [{"name": "Task", "input": {"agent": "worker", "prompt": "p"}}]},
                "ok",
            ],
            subagents=AgentRegistry([child]),
            max_budget_usd=100.0,
        )
        report = runtime.run("go")
        # parent gen1 ~$0.0001 + child $3.0 must all be in the reported total
        self.assertGreaterEqual(report.result.total_cost_usd, 3.0)


class NestingTests(unittest.TestCase):
    def test_nested_delegation_denied_by_default(self):
        # Invariant: with max_subagent_depth=1 (the default), a subagent that
        # declares Task cannot spawn a grandchild — the parent's gate denies
        # the delegation before the mid subagent even starts.
        leaf = child_agent("leaf", ("Read",), ["leaf done"])
        mid = child_agent("mid", ("Read", "Task"), [
            {"text": "try nesting", "tools": [{"name": "Task", "input": {"agent": "leaf", "prompt": "p"}}]},
            "mid done",
        ])
        runtime, _ = make_runtime(
            [
                {"text": "delegating", "tools": [{"name": "Task", "input": {"agent": "mid", "prompt": "p"}}]},
                "ok",
            ],
            subagents=AgentRegistry([mid, leaf]),
        )
        report = runtime.run("go")
        self.assertEqual(report.result.subtype, "success")
        parent_results = tool_results_of(runtime.provider.calls[1])
        self.assertTrue(parent_results[0]["is_error"])
        self.assertIn("max_subagent_depth", parent_results[0]["content"])
        self.assertEqual(len(mid.provider.calls), 0, "the mid subagent must not start")
        self.assertEqual(len(leaf.provider.calls), 0, "no nested subagent may run")

    def test_max_subagent_depth_allows_one_level_of_nesting(self):
        leaf = child_agent("leaf", ("Read",), ["leaf done"])
        mid = child_agent("mid", ("Read", "Task"), [
            {"text": "nesting", "tools": [{"name": "Task", "input": {"agent": "leaf", "prompt": "inner"}}]},
            "mid done",
        ])
        runtime, _ = make_runtime(
            [
                {"text": "delegating", "tools": [{"name": "Task", "input": {"agent": "mid", "prompt": "p"}}]},
                "ok",
            ],
            subagents=AgentRegistry([mid, leaf]),
            max_subagent_depth=2,
        )
        report = runtime.run("go")
        self.assertEqual(report.result.subtype, "success")
        self.assertEqual(len(leaf.provider.calls), 1, "depth 2 must be reachable with the backstop raised")
        self.assertEqual(leaf.provider.calls[0].messages[0]["content"], "inner")

    def test_lookahead_denies_target_whose_nesting_would_exceed_limit(self):
        # Even with max_subagent_depth=2, delegating to a target that itself
        # declares Task would create depth 3 — the caller's gate denies the
        # whole delegation before the target starts.
        deep = child_agent("deep", ("Read",), ["deep done"])
        leaf = child_agent("leaf", ("Read", "Task"), ["leaf done"])
        mid = child_agent("mid", ("Read", "Task"), [
            {"text": "nesting", "tools": [{"name": "Task", "input": {"agent": "leaf", "prompt": "inner"}}]},
            "mid done",
        ])
        runtime, _ = make_runtime(
            [
                {"text": "delegating", "tools": [{"name": "Task", "input": {"agent": "mid", "prompt": "p"}}]},
                "ok",
            ],
            subagents=AgentRegistry([mid, leaf, deep]),
            max_subagent_depth=2,
        )
        report = runtime.run("go")
        self.assertEqual(report.result.subtype, "success")
        mid_denials = [r for c in mid.provider.calls for r in tool_results_of(c) if r.get("is_error")]
        self.assertTrue(mid_denials, "mid's delegation to leaf must be denied")
        self.assertIn("max_subagent_depth", mid_denials[0]["content"])
        self.assertEqual(len(leaf.provider.calls), 0)
        self.assertEqual(len(deep.provider.calls), 0, "depth 3 must be unreachable")

    def test_gate_depth_backstop_denies_task_at_the_limit(self):
        # The backstop layer, unit-level: a gate sitting AT the depth limit
        # refuses any delegation, whatever the target declares.
        from permissions import PermissionGate

        g = PermissionGate(
            permission_mode="bypassPermissions",
            tool_kinds={"Task": "delegate", "Read": "read"},
            subagents=AgentRegistry([child_agent("leaf", ("Read",), ["x"])]),
            depth=2,
            max_subagent_depth=2,
        )
        decision = g.check_tool("Task", "delegate", {"agent": "leaf"})
        self.assertFalse(decision.allowed)
        self.assertIn("max_subagent_depth", decision.reason)
        # one level up, the same gate shape allows it
        g1 = PermissionGate(
            permission_mode="bypassPermissions",
            tool_kinds={"Task": "delegate", "Read": "read"},
            subagents=AgentRegistry([child_agent("leaf", ("Read",), ["x"])]),
            depth=1,
            max_subagent_depth=2,
        )
        self.assertTrue(g1.check_tool("Task", "delegate", {"agent": "leaf"}).allowed)


class EvaluatorAgentTests(unittest.TestCase):
    def test_evaluator_is_read_only(self):
        definition = evaluator_agent()
        self.assertEqual(definition.name, "evaluator")
        self.assertTrue(set(definition.tools) <= {"Read", "Grep", "List"})
        self.assertNotIn("Task", definition.tools)
        self.assertNotIn("Write", definition.tools)

    def test_evaluator_prompt_encodes_default_fail(self):
        definition = evaluator_agent()
        self.assertIn("FAIL", definition.system)
        self.assertIn("Default to FAIL", definition.system)

    def test_evaluator_passes_the_delegation_gate_without_a_callback(self):
        runtime, _ = make_runtime(
            [
                {"text": "delegating", "tools": [{"name": "Task", "input": {"agent": "evaluator", "prompt": "p"}}]},
                "ok",
            ],
            subagents=AgentRegistry([evaluator_agent(provider=ScriptedProvider(["PASS\nverified"]))]),
            permission_mode="default",  # no can_use_tool
        )
        report = runtime.run("go")
        self.assertEqual(report.result.subtype, "success")
        results = tool_results_of(runtime.provider.calls[1])
        self.assertFalse(results[0]["is_error"])
        self.assertIn("PASS", results[0]["content"])

    def test_evaluator_default_fail_semantics_flow_through(self):
        workspace = make_workspace()
        (workspace / "report.md").write_text("half done\n")
        evaluator = evaluator_agent(provider=ScriptedProvider([
            {"text": "checking", "tools": [{"name": "Read", "input": {"path": "report.md"}}]},
            "FAIL\nreport.md says 'half done', claim not supported",
        ]))
        runtime, _ = make_runtime(
            [
                {"text": "delegating", "tools": [{"name": "Task", "input": {"agent": "evaluator", "prompt": "is report.md done?"}}]},
                "ok",
            ],
            subagents=AgentRegistry([evaluator]),
            workspace=workspace,
        )
        report = runtime.run("go")
        results = tool_results_of(runtime.provider.calls[1])
        self.assertFalse(results[0]["is_error"])
        self.assertTrue(results[0]["content"].startswith("FAIL"))

    def test_evaluator_overrides(self):
        definition = evaluator_agent(name="auditor", max_turns=5)
        self.assertEqual(definition.name, "auditor")
        self.assertEqual(definition.max_turns, 5)
        self.assertEqual(definition.tools, ("Read", "Grep", "List"))


class SubagentSessionTests(unittest.TestCase):
    def test_child_records_parent_session_id(self):
        import sessions as sessions_module

        workspace = make_workspace()
        session_file = workspace / "s.jsonl"
        child = child_agent("worker", ("Read",), ["done"])
        runtime, _ = make_runtime(
            [
                {"text": "delegating", "tools": [{"name": "Task", "input": {"agent": "worker", "prompt": "p"}}]},
                "ok",
            ],
            subagents=AgentRegistry([child]),
            session_path=session_file,
        )
        report = runtime.run("go")
        records = sessions_module.load_records(session_file)
        child_inits = [
            r for r in records
            if r["event"]["type"] == "system" and r["event"]["subtype"] == "init"
            and r["event"]["data"].get("parent_session_id") == report.session_id
        ]
        self.assertEqual(len(child_inits), 1)
        child_session_id = child_inits[0]["session_id"]
        self.assertNotEqual(child_session_id, report.session_id)


if __name__ == "__main__":
    unittest.main()
