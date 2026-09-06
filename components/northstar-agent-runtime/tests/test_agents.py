"""Subagents: isolated context, declared tool subsets, ceilings, providers, and
the default-FAIL acceptance gate.
"""
from __future__ import annotations

import json
import unittest

import support  # noqa: F401
from support import RuntimeTestCase, text_turn, tool_turn

from agents import (
    AgentDefinition,
    AgentRegistry,
    Verdict,
    builtin_agents,
    builtin_registry,
    evaluator_agent,
    explorer_agent,
    general_agent,
    parse_criteria,
    parse_verdict,
    planner_agent,
)
from loop import RuntimeConfig
from providers.scripted import ScriptedProvider


def agents_with(child_provider: str = "child") -> AgentRegistry:
    return AgentRegistry(
        [
            general_agent(),
            explorer_agent().override(provider=child_provider),
            planner_agent().override(provider=child_provider),
            evaluator_agent().override(provider=child_provider),
        ]
    )


class DefinitionTests(unittest.TestCase):
    def test_builtin_set_and_their_read_only_flags(self):
        agents = builtin_agents()
        self.assertEqual(sorted(agents), ["evaluator", "explorer", "general", "planner"])
        self.assertTrue(agents["explorer"].is_read_only)
        self.assertTrue(agents["evaluator"].is_read_only)
        self.assertFalse(agents["general"].is_read_only)
        self.assertEqual(agents["planner"].permission_mode, "plan")
        self.assertEqual(agents["evaluator"].permission_mode, "plan")

    def test_no_builtin_agent_may_delegate(self):
        for definition in builtin_registry():
            with self.subTest(agent=definition.name):
                self.assertFalse(definition.allow_delegation, "nesting must be an explicit host decision")

    def test_evaluator_is_read_only_and_requires_a_verdict(self):
        evaluator = evaluator_agent(criteria=("tests pass", "no secrets committed"))
        self.assertEqual(evaluator.tools, ("Read", "Grep", "LS", "DescribeTools"))
        self.assertIn("Write", evaluator.disallowed_tools)
        self.assertIn("Edit", evaluator.disallowed_tools)
        self.assertIn("Task", evaluator.disallowed_tools)
        self.assertTrue(evaluator.require_verdict)
        self.assertEqual(evaluator.acceptance_criteria, ("tests pass", "no secrets committed"))
        self.assertIn("VERDICT: PASS", evaluator.system_prompt())
        self.assertIn("tests pass", evaluator.system_prompt())

    def test_definitions_are_validated(self):
        for kwargs in (
            {"name": ""},
            {"name": "x", "permission_mode": "godmode"},
            {"name": "x", "max_turns": 0},
            {"name": "x", "tools": ()},
            {"name": "x", "tools": "Read"},
        ):
            with self.subTest(**kwargs):
                with self.assertRaises((ValueError, TypeError)):
                    AgentDefinition(**kwargs)

    def test_registry_lookups_and_override(self):
        registry = builtin_registry()
        self.assertEqual(registry.names()[0], "evaluator")
        self.assertIsNone(registry.get("ghost"))
        with self.assertRaises(KeyError) as caught:
            registry.require("ghost")
        self.assertIn("known agents", str(caught.exception))
        self.assertEqual(registry.default().name, "general")
        doubled = registry.require("explorer").override(max_turns=2)
        self.assertEqual(doubled.max_turns, 2)
        self.assertEqual(registry.require("explorer").max_turns, 8, "override must not mutate the original")


class VerdictTests(unittest.TestCase):
    def test_missing_marker_defaults_to_fail(self):
        verdict = parse_verdict("Everything looks good, ship it I think")
        self.assertEqual(verdict.acceptance, "FAIL")
        self.assertFalse(verdict.explicit)
        self.assertIn("no `VERDICT: PASS|FAIL` line", verdict.reasons[0])

    def test_an_empty_answer_is_a_fail(self):
        self.assertEqual(parse_verdict("").acceptance, "FAIL")
        self.assertEqual(parse_verdict(None).acceptance, "FAIL")

    def test_explicit_pass_with_evidence_is_a_pass(self):
        text = (
            "Read the diff and ran the suite; the two changed modules are covered.\n"
            "- [x] tests pass\n"
            "VERDICT: PASS"
        )
        verdict = parse_verdict(text, criteria=("tests pass",))
        self.assertEqual(verdict.acceptance, "PASS")
        self.assertTrue(verdict.explicit)
        self.assertEqual(verdict.unverified_criteria, ())

    def test_pass_with_an_unverified_criterion_is_downgraded(self):
        text = "Ran what I could locally and it is fine overall.\n- [x] tests pass\n- [ ] no secrets committed\nVERDICT: PASS"
        verdict = parse_verdict(text, criteria=("tests pass", "no secrets committed"))
        self.assertEqual(verdict.acceptance, "FAIL")
        self.assertIn("no secrets committed", verdict.unverified_criteria)
        self.assertTrue(verdict.explicit, "the model did state a verdict; the gate overrode it")

    def test_criterion_never_mentioned_is_unverified(self):
        text = "Reviewed the change and every test file was executed successfully here.\nVERDICT: PASS"
        verdict = parse_verdict(text, criteria=("tests pass",))
        self.assertEqual(verdict.acceptance, "FAIL")
        self.assertIn("no verification line for", verdict.reasons[0])

    def test_a_bare_pass_without_justification_is_a_fail(self):
        verdict = parse_verdict("VERDICT: PASS")
        self.assertEqual(verdict.acceptance, "FAIL")
        self.assertIn("too thin to audit", verdict.reasons[0])

    def test_any_fail_marker_wins(self):
        text = "Verified locally.\nVERDICT: PASS\nActually blocked by the environment.\nVERDICT: FAIL (network)"
        verdict = parse_verdict(text)
        self.assertEqual(verdict.acceptance, "FAIL")
        self.assertTrue(verdict.explicit)

    def test_prose_mentioning_pass_does_not_count(self):
        verdict = parse_verdict("This would pass if the tests were green, but they are not.")
        self.assertEqual(verdict.acceptance, "FAIL")

    def test_criteria_lines_parse_independently_of_the_marker(self):
        criteria = parse_criteria("- [x] done one\n- [ ] done two\n* [X] done three\n3. [ ] done four")
        self.assertEqual([item.verified for item in criteria], [True, False, True, False])
        self.assertEqual(criteria[0].criterion, "done one")

    def test_verdict_renders_for_the_parent_model(self):
        rendered = parse_verdict("VERDICT: FAIL (missing evidence)").render()
        self.assertIn("ACCEPTANCE: FAIL", rendered)
        self.assertIn("missing evidence", rendered)


class DelegationTests(RuntimeTestCase):
    def test_a_subagent_runs_with_its_own_context_and_tools(self):
        workspace = self.workspace({"a.txt": "alpha\n"})
        parent = self.provider([tool_turn("Task", {"agent": "explorer", "prompt": "read a.txt and report"}), text_turn("parent done")])
        child = self.provider([tool_turn("Read", {"path": "a.txt"}), text_turn("alpha, from the child")])
        runtime = self.runtime(
            provider=parent, providers={"child": child}, workspace=workspace, agents=agents_with("child")
        )
        report = self.drive(runtime, "delegate")
        self.assertEqual(report.subagents[0].agent, "explorer")
        self.assertEqual(report.subagents[0].subtype, "success")
        self.assertIn("alpha, from the child", parent.sent_tool_results()[0]["content"])
        # The child saw only its own prompt, never the parent's transcript.
        child_first_messages = json.dumps(child.requests[0].messages, ensure_ascii=False)
        self.assertNotIn("delegate", child_first_messages)
        self.assertIn("read a.txt and report", child_first_messages)
        self.assertEqual(child.requests[0].turn_index, 1)
        self.assertEqual(
            [tool["name"] for tool in child.requests[0].tools],
            ["DescribeTools", "Grep", "LS", "Read"],
            "the child only gets its declared subset",
        )
        self.assertIn("read-only", child.requests[0].system)
        self.assertEqual(report.subagents[0].turns, 2)
        self.assertEqual(report.subagents[0].tool_calls, 1)

    def test_a_subagent_cannot_use_a_tool_it_did_not_declare(self):
        workspace = self.workspace({"a.txt": "x"})
        parent = self.provider([tool_turn("Task", {"agent": "explorer", "prompt": "write a file"}, usage={"input_tokens": 10})])
        child = self.provider([tool_turn("Write", {"path": "b.txt", "content": "y"}), text_turn("tried")], on_exhausted="stop")
        runtime = self.runtime(provider=parent, providers={"child": child}, workspace=workspace, agents=agents_with("child"))
        report = self.drive(runtime, "delegate")
        self.assertFalse((workspace / "b.txt").exists())
        self.assertEqual([tool["name"] for tool in child.requests[0].tools], ["DescribeTools", "Grep", "LS", "Read"])
        dumped = json.dumps(report.subagents[0].transcript, ensure_ascii=False)
        self.assertIn("unknown tool 'Write'", dumped, "the registry subset, not the permission mode, is what refuses it")

    def test_delegation_is_gated_per_tool_not_by_the_task_name(self):
        parent = self.provider([tool_turn("Task", {"agent": "general", "prompt": "edit the file"}), text_turn("understood")])
        runtime = self.runtime(provider=parent, workspace=self.workspace())
        report = self.drive(runtime, "delegate to a writer")
        self.assertEqual(report.subagents, (), "the general subagent needs Write, which the parent policy refuses")
        text = parent.sent_tool_results()[0]["content"]
        self.assertIn("Write", text, "the message must name the tool that broke the gate")
        self.assertNotIn("Task refused", text)
        self.assertEqual({denial.tool for denial in report.denials}, {"Write", "Edit"}, "every tool the subagent declared is gated")
        self.assertEqual({denial.agent for denial in report.denials}, {"general"}, "the denial is attributed to the subagent that asked")
        self.assertEqual({denial.source for denial in report.denials}, {"delegation_gate"})
        self.assertEqual(self.assertExactlyOneResult(report).subtype, "success")

    def test_the_same_delegation_is_approved_once_write_is_auto_approved(self):
        workspace = self.workspace({"a.txt": "x"})
        parent = self.provider([tool_turn("Task", {"agent": "general", "prompt": "write b.txt"}, usage={"input_tokens": 10}), text_turn("done")])
        child = self.provider([tool_turn("Write", {"path": "b.txt", "content": "created"}), text_turn("wrote it")])
        runtime = self.runtime(
            provider=parent,
            providers={"child": child},
            workspace=workspace,
            agents=AgentRegistry([general_agent().override(provider="child")]),
            allowed_tools=("Read", "Grep", "LS", "Write", "Edit", "DescribeTools"),
        )
        report = self.drive(runtime, "delegate")
        self.assertEqual((workspace / "b.txt").read_text(), "created")
        self.assertEqual(report.subagents[0].subtype, "success")

    def test_an_unknown_agent_names_the_available_agents(self):
        parent = self.provider([tool_turn("Task", {"agent": "reviewer-9000", "prompt": "look"}), text_turn("fine")])
        report = self.drive(self.runtime(provider=parent))
        text = parent.sent_tool_results()[0]["content"]
        self.assertIn("unknown subagent 'reviewer-9000'", text)
        self.assertIn("evaluator", text)
        self.assertEqual(report.subagents, ())

    def test_a_delegation_without_a_prompt_is_refused(self):
        parent = self.provider([tool_turn("Task", {"agent": "explorer"}, ), text_turn("ok")])
        self.drive(self.runtime(provider=parent))
        self.assertIn("non-empty 'prompt'", parent.sent_tool_results()[0]["content"])

    def test_delegation_depth_is_capped_and_nested_delegation_is_opt_in(self):
        workspace = self.workspace()
        nested_child = AgentDefinition(
            name="middle",
            description="delegates onward",
            tools=("Read", "Task"),
            allow_delegation=True,
            provider="child",
            max_turns=3,
        )
        parent = self.provider([tool_turn("Task", {"agent": "middle", "prompt": "go deeper"}, usage={"input_tokens": 5})])
        child = self.provider([tool_turn("Task", {"agent": "explorer", "prompt": "deeper"}), text_turn("middle done")], on_exhausted="stop")
        runtime = self.runtime(
            provider=parent,
            providers={"child": child},
            workspace=workspace,
            agents=AgentRegistry([nested_child, explorer_agent().override(provider="child")]),
            max_subagent_depth=1,
        )
        report = self.drive(runtime, "one level")
        self.assertEqual(len(report.subagents), 1)
        refusal = child.sent_tool_results()[0]["content"]
        self.assertIn("Delegation is not available at depth 1", refusal)
        self.assertIn("max_subagent_depth=1", refusal)
        self.assertEqual(report.subagents[0].agent, "middle")

    def test_max_subagent_depth_zero_removes_the_task_tool_entirely(self):
        provider = self.provider([text_turn("solo")])
        runtime = self.runtime(provider=provider, max_subagent_depth=0)
        self.assertNotIn("Task", runtime.tools.names())
        report = self.drive(runtime, "go")
        names = [tool["name"] for tool in provider.requests[0].tools]
        self.assertNotIn("Task", names)
        self.assertTrue(report.ok)

    def test_nested_delegation_can_be_enabled_one_level_down(self):
        workspace = self.workspace({"a.txt": "x"})
        nested_child = AgentDefinition(
            name="middle",
            description="delegates onward",
            tools=("Read", "Grep", "LS", "DescribeTools", "Task"),
            allow_delegation=True,
            provider="child",
            max_turns=3,
        )
        parent = self.provider([tool_turn("Task", {"agent": "middle", "prompt": "go deeper"}), text_turn("done")])
        middle = self.provider([tool_turn("Task", {"agent": "explorer", "prompt": "deeper"}), text_turn("middle forwarded")])
        leaf = self.provider([text_turn("leaf answer")])
        runtime = self.runtime(
            provider=parent,
            providers={"child": middle, "leaf": leaf},
            workspace=workspace,
            agents=AgentRegistry([nested_child, explorer_agent().override(provider="leaf")]),
            max_subagent_depth=2,
            allow_nested_delegation=True,
        )
        report = self.drive(runtime, "two levels")
        self.assertEqual([entry.agent for entry in report.subagents], ["middle"])
        self.assertIn("middle forwarded", parent.sent_tool_results()[0]["content"])
        self.assertIn("leaf answer", middle.sent_tool_results()[0]["content"])
        self.assertEqual(leaf.requests[0].depth, 2)

    def test_a_subagent_turn_ceiling_is_independent_of_the_parents(self):
        parent = self.provider([tool_turn("Task", {"agent": "explorer", "prompt": "loop forever"})])
        child = self.provider([tool_turn("Read", {"path": "x"}) for _ in range(6)], on_exhausted="repeat_last")
        runtime = self.runtime(
            provider=parent,
            providers={"child": child},
            agents=AgentRegistry([explorer_agent().override(provider="child", max_turns=2, max_tool_calls=None)]),
            max_turns=50,
            max_tool_calls=None,
        )
        report = self.drive(runtime, "delegate")
        self.assertEqual(report.subagents[0].subtype, "error_max_turns")
        self.assertEqual(report.subagents[0].turns, 2)
        self.assertEqual(len(child.requests), 2)
        self.assertTrue(parent.sent_tool_results()[0]["is_error"])

    def test_subagent_cost_rolls_up_into_the_parents_meter(self):
        parent = self.provider([tool_turn("Task", {"agent": "explorer", "prompt": "read"}, usage={"input_tokens": 1_000_000})])
        child = self.provider([text_turn("cheap answer", usage={"input_tokens": 2_000_000})])
        runtime = self.runtime(
            provider=parent, providers={"child": child}, agents=AgentRegistry([explorer_agent().override(provider="child")])
        )
        report = self.drive(runtime, "delegate")
        self.assertAlmostEqual(report.subagents[0].cost_usd, 6.0)
        self.assertAlmostEqual(report.result.total_cost_usd, 9.0, msg="parent 3.0 + child 6.0")
        self.assertEqual(report.result.total_usage.input_tokens, 3_000_000)

    def test_a_parent_budget_limits_the_children_it_borrows_against(self):
        parent = self.provider(
            [
                tool_turn("Task", {"agent": "explorer", "prompt": "read"}, usage={"input_tokens": 1_000_000}),
                tool_turn("Task", {"agent": "explorer", "prompt": "read again"}),
            ]
        )
        child = self.provider([text_turn("answer", usage={"input_tokens": 1_000_000}) for _ in range(4)], on_exhausted="repeat_last")
        runtime = self.runtime(
            provider=parent,
            providers={"child": child},
            agents=AgentRegistry([explorer_agent().override(provider="child", max_turns=5, max_tool_calls=None)]),
            max_budget_usd=4.0,
            max_turns=6,
        )
        report = self.drive(runtime, "delegate twice")
        self.assertEqual(self.assertExactlyOneResult(report).subtype, "error_max_budget_usd")
        self.assertEqual(len(report.subagents), 1, "the second delegation never starts: the ceiling is already gone")

    def test_a_child_may_run_on_a_different_provider(self):
        parent = self.provider([tool_turn("Task", {"agent": "explorer", "prompt": "read"}, usage={"input_tokens": 1_000})])
        child = ScriptedProvider(
            [text_turn("answered by the cheap model", usage={"input_tokens": 1000, "output_tokens": 100})],
            model="claude-haiku-4-5",
        )
        runtime = self.runtime(
            provider=parent,
            providers={"child": child},
            agents=AgentRegistry([explorer_agent().override(provider="child", model="claude-haiku-4-5")]),
        )
        report = self.drive(runtime, "delegate")
        self.assertEqual(child.requests[0].model, "claude-haiku-4-5")
        # haiku: 0.8/M input, 4/M output -> 1000 * 0.8e-6 + 100 * 4e-6
        self.assertAlmostEqual(report.subagents[0].cost_usd, 0.0012)

    def test_an_unconfigured_child_provider_is_reported_not_crashed(self):
        parent = self.provider([tool_turn("Task", {"agent": "explorer", "prompt": "read"}), text_turn("fine")])
        runtime = self.runtime(provider=parent, agents=AgentRegistry([explorer_agent().override(provider="missing")]))
        report = self.drive(runtime, "delegate")
        self.assertIn("requests provider 'missing'", parent.sent_tool_results()[0]["content"])
        self.assertEqual(report.subagents, ())

    def test_evaluator_verdict_reaches_the_parent_as_acceptance(self):
        for child_text, expected in (
            ("Reviewed the diff and the tests; nothing was changed by me.\nVERDICT: FAIL (no tests run)", "FAIL"),
            ("Read every changed file and re-ran the suite twice; both runs were green.\n- [x] tests pass\nVERDICT: PASS", "PASS"),
        ):
            with self.subTest(expected=expected):
                parent = self.provider([tool_turn("Task", {"agent": "evaluator", "prompt": "judge the change"}), text_turn("noted")])
                child = self.provider([text_turn(child_text)])
                runtime = self.runtime(
                    provider=parent,
                    providers={"child": child},
                    agents=AgentRegistry([evaluator_agent(criteria=("tests pass",)).override(provider="child")]),
                )
                report = self.drive(runtime, "evaluate")
                verdict = report.subagents[0].verdict
                self.assertEqual(verdict.acceptance, expected)
                self.assertIn(f"ACCEPTANCE: {expected}", parent.sent_tool_results()[0]["content"])
                self.assertEqual(parent.sent_tool_results()[0]["is_error"], False, "a FAIL verdict is an answer, not a crash")

    def test_evaluator_cannot_be_asked_to_edit(self):
        parent = self.provider([tool_turn("Task", {"agent": "evaluator", "prompt": "fix the tests"})])
        child = self.provider([tool_turn("Write", {"path": "x", "content": "y"}), text_turn("done")], on_exhausted="stop")
        runtime = self.runtime(
            provider=parent,
            providers={"child": child},
            agents=AgentRegistry([evaluator_agent().override(provider="child", tools=("Read", "Write"))]),
        )
        report = self.drive(runtime, "evaluate and fix")
        # Write is disallowed for the evaluator by definition, so the gate refuses.
        self.assertIn("Write", str([denial.tool for denial in report.denials]))


if __name__ == "__main__":
    unittest.main()
