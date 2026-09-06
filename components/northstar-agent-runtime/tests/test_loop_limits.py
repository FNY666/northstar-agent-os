import unittest

from loop import RunConfig
from providers.base import Usage

from helpers import make_runtime, tool_results_of


def read_step(name="Read", path="m.txt"):
    return {"text": f"using {name}", "tools": [{"name": name, "input": {"path": path}}]}


class MaxTurnsTests(unittest.TestCase):
    def test_max_turns_produces_its_own_subtype(self):
        runtime, provider = make_runtime([read_step("Read", f"m{i}.txt") for i in range(10)], max_turns=3)
        report = runtime.run("go")
        self.assertEqual(report.result.subtype, "error_max_turns")
        self.assertEqual(report.result.num_turns, 3)
        self.assertEqual(len(provider.calls), 3, "the 4th generation must never happen")

    def test_turns_counted_in_result(self):
        runtime, _ = make_runtime(["done"])
        report = runtime.run("go")
        self.assertEqual(report.result.subtype, "success")
        self.assertEqual(report.result.num_turns, 1)


class MaxToolCallsTests(unittest.TestCase):
    def test_max_tool_calls_produces_its_own_subtype(self):
        runtime, provider = make_runtime(
            [
                {"text": "w1", "tools": [{"name": "Write", "input": {"path": "a.txt", "content": "1"}}]},
                {"text": "w2", "tools": [{"name": "Write", "input": {"path": "b.txt", "content": "2"}}]},
                {"text": "w3", "tools": [{"name": "Write", "input": {"path": "c.txt", "content": "3"}}]},
            ],
            permission_mode="bypassPermissions",
            max_tool_calls=2,
        )
        report = runtime.run("go")
        self.assertEqual(report.result.subtype, "error_max_tool_calls")
        self.assertEqual(report.result.num_tool_calls, 3)
        # the third call was denied: a and b exist, c does not
        self.assertTrue((runtime.workspace / "a.txt").exists())
        self.assertTrue((runtime.workspace / "b.txt").exists())
        self.assertFalse((runtime.workspace / "c.txt").exists())

    def test_denied_calls_count_toward_the_limit(self):
        # A model that keeps retrying a denied tool must not loop forever:
        # denials consume tool-call budget too.
        runtime, provider = make_runtime(
            [
                {"text": "w", "tools": [{"name": "Write", "input": {"path": "a.txt", "content": "1"}}]},
                {"text": "w", "tools": [{"name": "Write", "input": {"path": "b.txt", "content": "2"}}]},
                {"text": "w", "tools": [{"name": "Write", "input": {"path": "c.txt", "content": "3"}}]},
                "never reached",
            ],
            permission_mode="default",  # no callback: every Write is denied
            max_tool_calls=2,
        )
        report = runtime.run("go")
        self.assertEqual(report.result.subtype, "error_max_tool_calls")
        self.assertEqual(len(provider.calls), 3, "the third generation's call trips the limit")


class MaxBudgetTests(unittest.TestCase):
    def test_budget_exhausted_by_a_generation_stops_before_its_tools(self):
        # Invariant: once a generation spends the budget, its pending tool
        # calls are NOT executed.
        runtime, provider = make_runtime(
            [
                {"text": "writing", "tools": [{"name": "Write", "input": {"path": "expensive.txt", "content": "x"}}],
                 "usage": {"input_tokens": 1_000_000, "output_tokens": 0}},  # $3.00 on sonnet
                "done",
            ],
            permission_mode="bypassPermissions",
            max_budget_usd=1.00,
        )
        report = runtime.run("go")
        self.assertEqual(report.result.subtype, "error_max_budget_usd")
        self.assertFalse((runtime.workspace / "expensive.txt").exists())
        self.assertEqual(len(provider.calls), 1)
        self.assertGreaterEqual(report.result.total_cost_usd, 1.00)

    def test_budget_check_between_turns(self):
        # Even without a tool call in the over-budget generation, the next turn
        # must not start.
        runtime, provider = make_runtime(
            [
                {"text": "big", "usage": {"input_tokens": 1_000_000, "output_tokens": 0}},
                "never reached",
            ],
            max_budget_usd=2.00,
        )
        report = runtime.run("go")
        self.assertEqual(report.result.subtype, "error_max_budget_usd")
        self.assertEqual(len(provider.calls), 1)

    def test_under_budget_run_succeeds(self):
        runtime, _ = make_runtime(["done"], max_budget_usd=10.0)
        report = runtime.run("go")
        self.assertEqual(report.result.subtype, "success")


class ExecutionErrorsTests(unittest.TestCase):
    def test_provider_error_maps_to_error_during_execution(self):
        runtime, provider = make_runtime([{"error": "model exploded"}])
        report = runtime.run("go")
        self.assertEqual(report.result.subtype, "error_during_execution")
        self.assertIn("model exploded", report.result.summary)
        self.assertEqual(len(report.events), 3)  # init, user, result

    def test_unexpected_provider_exception_is_an_event_not_a_raise(self):
        from providers.base import Provider

        class ExplodingProvider(Provider):
            def create_message(self, request):
                raise RuntimeError("socket on fire")

        from loop import AgentRuntime
        from helpers import make_workspace

        runtime = AgentRuntime(ExplodingProvider(), RunConfig(workspace=make_workspace()))
        report = runtime.run("go")
        self.assertEqual(report.result.subtype, "error_during_execution")
        self.assertIn("RuntimeError", report.result.summary)

    def test_crashing_tool_handler_is_a_tool_failure_not_a_run_failure(self):
        from tools import Tool

        def boom(payload, ctx):
            raise ValueError("handler bug")

        runtime, provider = make_runtime([
            read_step(),
            "recovered",
        ])
        registry = runtime._tool_registry
        original_tool = registry.get("Read")
        registry._tools["Read"] = Tool(
            original_tool.name, original_tool.description, original_tool.kind,
            original_tool.input_schema, boom,
        )
        try:
            report = runtime.run("go")
        finally:
            registry._tools["Read"] = original_tool
        self.assertEqual(report.result.subtype, "success")
        results = tool_results_of(provider.calls[1])
        self.assertTrue(results[0]["is_error"])
        self.assertIn("handler bug", results[0]["content"])


class IndependentLimitsTests(unittest.TestCase):
    def test_each_limit_has_its_own_subtype(self):
        scenarios = {
            "error_max_turns": ([read_step()], dict(max_turns=1)),
            "error_max_tool_calls": ([read_step()], dict(max_tool_calls=0)),
            "error_max_budget_usd": ([{"text": "x", "usage": {"input_tokens": 1_000_000}}], dict(max_budget_usd=0.0)),
            "error_during_execution": ([{"error": "e"}], {}),
        }
        for subtype, (script, kwargs) in scenarios.items():
            runtime, _ = make_runtime(script, **kwargs)
            report = runtime.run("go")
            self.assertEqual(report.result.subtype, subtype, f"kwargs {kwargs}")
            matches = [e for e in report.events if getattr(e, "subtype", None) == report.result.subtype]
            self.assertEqual(len(matches), 1)


if __name__ == "__main__":
    unittest.main()
