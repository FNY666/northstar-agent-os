import unittest

from agents import AgentRegistry, evaluator_agent
from compaction import COMPACT_MARKER
from hooks import HOOK_NAMES, HookDecision, HookRegistry
from loop import SystemMessage
from providers.scripted import ScriptedProvider

from helpers import make_runtime, results_of, tool_results_of


class SpyHooks:
    def __init__(self, registry: HookRegistry):
        self.fired: list[tuple[str, dict]] = []
        for name in HOOK_NAMES:
            spy = self
            registry.add(name, lambda payload, n=name: spy.fired.append((n, dict(payload))) or None)

    def names(self):
        return [name for name, _ in self.fired]


class AllHooksFiringTests(unittest.TestCase):
    def test_all_ten_hooks_fire_in_one_full_run(self):
        hooks = HookRegistry()
        spy = SpyHooks(hooks)
        child_script = ["PASS"]
        runtime, provider = make_runtime(
            [
                {"text": "delegating", "tools": [{"name": "Task", "input": {"agent": "evaluator", "prompt": "check"}}]},
                {"text": "checking missing file", "tools": [{"name": "Read", "input": {"path": "missing.txt"}}]},
                "all done",
            ],
            hooks=hooks,
            subagents=AgentRegistry([evaluator_agent(provider=ScriptedProvider(child_script))]),
            compaction_threshold_tokens=10,
        )
        report = runtime.run("go")
        self.assertEqual(report.result.subtype, "success", report.result.summary)
        # Every one of the ten hooks must have fired at least once. (Some fire
        # more than once: the subagent shares the parent's hook registry.)
        self.assertEqual(set(spy.names()), set(HOOK_NAMES))
        for name in HOOK_NAMES:
            self.assertGreaterEqual(spy.names().count(name), 1, f"hook {name} never fired")


class PreToolUseTests(unittest.TestCase):
    def test_deny_stops_the_tool_and_feeds_an_error_to_the_model(self):
        hooks = HookRegistry()
        hooks.add("PreToolUse", lambda p: HookDecision.deny("not today"))
        runtime, provider = make_runtime(
            [
                {"text": "writing", "tools": [{"name": "Write", "input": {"path": "a.txt", "content": "x"}}]},
                "ok",
            ],
            hooks=hooks,
            permission_mode="bypassPermissions",
        )
        report = runtime.run("go")
        self.assertEqual(report.result.subtype, "success")
        results = tool_results_of(provider.calls[1])
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["is_error"])
        self.assertIn("not today", results[0]["content"])
        # and it never ran
        self.assertFalse((runtime.workspace / "a.txt").exists())

    def test_rewrite_replaces_the_payload_seen_by_the_handler(self):
        hooks = HookRegistry()
        hooks.add("PreToolUse", lambda p: {"updated_input": {"path": "safe.txt", "content": "rewritten"}})
        runtime, _ = make_runtime(
            [
                {"text": "writing", "tools": [{"name": "Write", "input": {"path": "a.txt", "content": "x"}}]},
                "ok",
            ],
            hooks=hooks,
            permission_mode="bypassPermissions",
        )
        runtime.run("go")
        self.assertTrue((runtime.workspace / "safe.txt").exists())
        self.assertEqual((runtime.workspace / "safe.txt").read_text(), "rewritten")
        self.assertFalse((runtime.workspace / "a.txt").exists())

    def test_first_deny_is_terminal_later_hooks_are_not_called(self):
        calls = []
        hooks = HookRegistry()
        hooks.add("PreToolUse", lambda p: calls.append("deny") or HookDecision.deny("first"))
        hooks.add("PreToolUse", lambda p: calls.append("allow") or None)
        runtime, provider = make_runtime(
            [
                {"text": "writing", "tools": [{"name": "Write", "input": {"path": "a.txt", "content": "x"}}]},
                "ok",
            ],
            hooks=hooks,
            permission_mode="bypassPermissions",
        )
        runtime.run("go")
        self.assertEqual(calls, ["deny"], "a later hook must not run after a deny")
        results = tool_results_of(provider.calls[1])
        self.assertTrue(results[0]["is_error"])
        self.assertIn("first", results[0]["content"])


class UserPromptSubmitTests(unittest.TestCase):
    def test_context_is_injected_into_the_model_request(self):
        hooks = HookRegistry()
        hooks.add("UserPromptSubmit", lambda p: {"additional_context": "extra rules apply"})
        runtime, provider = make_runtime(["done"], hooks=hooks)
        report = runtime.run("base prompt")
        self.assertEqual(report.result.subtype, "success")
        first_user = provider.calls[0].messages[0]
        self.assertEqual(first_user["role"], "user")
        self.assertIn("base prompt", first_user["content"])
        self.assertIn("extra rules apply", first_user["content"])
        notes = [e for e in report.events if isinstance(e, SystemMessage) and e.subtype == "informational"]
        self.assertTrue(notes)

    def test_deny_rejects_the_whole_run(self):
        hooks = HookRegistry()
        hooks.add("UserPromptSubmit", lambda p: HookDecision.deny("policy X forbids this"))
        runtime, provider = make_runtime(["done"], hooks=hooks)
        report = runtime.run("hello")
        self.assertEqual(report.result.subtype, "error_permission_denied")
        self.assertIn("policy X forbids this", report.result.summary)
        self.assertEqual(len(provider.calls), 0, "no model call may happen after a prompt denial")
        self.assertEqual(len(results_of(report)), 1)


class StopTests(unittest.TestCase):
    def test_block_feeds_reason_back_as_new_user_turn(self):
        hooks = HookRegistry()
        blocks = {"count": 0}

        def stop_hook(payload):
            blocks["count"] += 1
            if blocks["count"] == 1:
                return HookDecision.deny("you forgot to test edge case B")
            return None

        hooks.add("Stop", stop_hook)
        runtime, provider = make_runtime(["almost done", "truly done"], hooks=hooks)
        report = runtime.run("go")
        self.assertEqual(report.result.subtype, "success")
        self.assertEqual(len(provider.calls), 2)
        last_message = provider.calls[1].messages[-1]
        self.assertEqual(last_message["role"], "user")
        self.assertEqual(last_message["content"], "you forgot to test edge case B")

    def test_blocks_are_bounded_by_max_turns(self):
        hooks = HookRegistry()
        hooks.add("Stop", lambda p: HookDecision.deny("never stop"))
        runtime, provider = make_runtime(["a", "b"], hooks=hooks, max_turns=2)
        report = runtime.run("go")
        self.assertEqual(report.result.subtype, "error_max_turns")
        self.assertEqual(len(provider.calls), 2)


class PostToolUseTests(unittest.TestCase):
    def test_post_tool_use_receives_result(self):
        seen = []
        hooks = HookRegistry()
        hooks.add("PostToolUse", lambda p: seen.append(p) or None)
        runtime, _ = make_runtime(
            [
                {"text": "writing", "tools": [{"name": "Write", "input": {"path": "a.txt", "content": "x"}}]},
                "ok",
            ],
            hooks=hooks,
            permission_mode="bypassPermissions",
        )
        runtime.run("go")
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]["tool_name"], "Write")
        self.assertIn("wrote", seen[0]["output"])
        self.assertFalse(seen[0]["input"].get("__never__"))

    def test_post_tool_use_failure_receives_failure(self):
        seen = []
        hooks = HookRegistry()
        hooks.add("PostToolUseFailure", lambda p: seen.append(p) or None)
        runtime, _ = make_runtime(
            [
                {"text": "reading", "tools": [{"name": "Read", "input": {"path": "missing.txt"}}]},
                "ok",
            ],
            hooks=hooks,
        )
        runtime.run("go")
        self.assertEqual(len(seen), 1)
        self.assertIn("no such file", seen[0]["output"])

    def test_post_tool_use_deny_converts_success_to_failure(self):
        hooks = HookRegistry()
        hooks.add("PostToolUse", lambda p: HookDecision.deny("result looked wrong"))
        runtime, provider = make_runtime(
            [
                {"text": "writing", "tools": [{"name": "Write", "input": {"path": "a.txt", "content": "x"}}]},
                "ok",
            ],
            hooks=hooks,
            permission_mode="bypassPermissions",
        )
        runtime.run("go")
        results = tool_results_of(provider.calls[1])
        self.assertTrue(results[0]["is_error"])
        self.assertIn("result looked wrong", results[0]["content"])


class PreCompactTests(unittest.TestCase):
    def test_deny_skips_compaction(self):
        hooks = HookRegistry()
        hooks.add("PreCompact", lambda p: HookDecision.deny("no compacting"))
        runtime, _ = make_runtime(
            [
                {"text": "t1", "tools": [{"name": "Read", "input": {"path": "missing.txt"}}]},
                {"text": "t2", "tools": [{"name": "Read", "input": {"path": "missing.txt"}}]},
                "done",
            ],
            hooks=hooks,
            compaction_threshold_tokens=10,
        )
        report = runtime.run("go")
        boundary_events = [e for e in report.events if isinstance(e, SystemMessage) and e.subtype == "compact_boundary"]
        self.assertEqual(boundary_events, [], "a denied PreCompact must not compact")


class SessionEndTests(unittest.TestCase):
    def test_session_end_fires_even_on_failed_runs(self):
        seen = []
        hooks = HookRegistry()
        hooks.add("SessionEnd", lambda p: seen.append(p) or None)
        runtime, _ = make_runtime([{"error": "kaboom"}], hooks=hooks)
        report = runtime.run("go")
        self.assertEqual(report.result.subtype, "error_during_execution")
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]["result_subtype"], "error_during_execution")


class HookRobustnessTests(unittest.TestCase):
    def test_raising_hook_is_treated_as_deny(self):
        def broken(payload):
            raise ValueError("hook exploded")

        hooks = HookRegistry()
        hooks.add("PreToolUse", broken)
        runtime, provider = make_runtime(
            [
                {"text": "writing", "tools": [{"name": "Write", "input": {"path": "a.txt", "content": "x"}}]},
                "ok",
            ],
            hooks=hooks,
            permission_mode="bypassPermissions",
        )
        report = runtime.run("go")
        self.assertEqual(report.result.subtype, "success")
        results = tool_results_of(provider.calls[1])
        self.assertTrue(results[0]["is_error"])
        self.assertIn("hook exploded", results[0]["content"])

    def test_unknown_hook_name_rejected(self):
        hooks = HookRegistry()
        with self.assertRaises(ValueError):
            hooks.add("PostToolMaybe", lambda p: None)
        with self.assertRaises(ValueError):
            hooks.fire("PostToolMaybe", {})

    def test_dict_and_decision_return_types_equivalent(self):
        registry = HookRegistry()
        registry.add("PreToolUse", lambda p: {"deny": True, "reason": "r1"})
        self.assertFalse(registry.fire("PreToolUse", {}).allowed)
        registry2 = HookRegistry()
        registry2.add("PreToolUse", lambda p: HookDecision.deny("r2"))
        self.assertFalse(registry2.fire("PreToolUse", {}).allowed)
        registry3 = HookRegistry()
        registry3.add("PreToolUse", lambda p: None)
        self.assertTrue(registry3.fire("PreToolUse", {}).allowed)


if __name__ == "__main__":
    unittest.main()
