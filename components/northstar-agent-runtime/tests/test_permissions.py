"""The three permission layers, the four modes, and delegation gating by tool.
"""
from __future__ import annotations

import unittest

import support  # noqa: F401
from support import RuntimeTestCase, text_turn, tool_turn

from permissions import (
    PERMISSION_MODES,
    PermissionConfig,
    PermissionEngine,
    PermissionRequestContext,
    digest_arguments,
    normalise_names,
    subtract,
    validate_mode,
)
from tools import ToolRegistry, ToolSpec


def registry_with_extra() -> ToolRegistry:
    """Adds an exec-classified tool so acceptEdits has something to refuse."""
    from tools import ToolResult

    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="Bash",
            description="run a command",
            input_schema={},
            handler=lambda payload, ctx: ToolResult.ok("ran"),
            kind="exec",
        )
    )
    return registry


class LayerOrderTests(unittest.TestCase):
    def make(self, **kwargs) -> PermissionEngine:
        return PermissionEngine(PermissionConfig(**kwargs))

    def test_disallowed_tools_beats_everything_including_bypass(self):
        for mode in PERMISSION_MODES:
            with self.subTest(mode=mode):
                engine = self.make(
                    mode=mode,
                    allowed_tools=("Write",),
                    disallowed_tools=("Write",),
                    can_use_tool=lambda name, payload, ctx: True,
                )
                decision = engine.evaluate("Write", kind="edit")
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.source, "disallowed_tools")

    def test_allowed_tools_auto_approves_before_the_mode_is_consulted(self):
        engine = self.make(mode="default", allowed_tools=("Write",))
        decision = engine.evaluate("Write", kind="edit")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.source, "allowed_tools")

    def test_an_overlap_is_reported_but_never_raises_because_deny_wins(self):
        config = PermissionConfig(mode="default", allowed_tools=("Read", "Write"), disallowed_tools=("Write",))
        self.assertEqual(config.overlap, ("Write",))
        engine = PermissionEngine(config)
        self.assertTrue(engine.evaluate("Read", kind="read").allowed)
        self.assertFalse(engine.evaluate("Write", kind="edit").allowed)

    def test_subtract_is_the_only_correct_way_to_combine_cli_lists(self):
        self.assertEqual(subtract(["Read", "Write"], ["Write"]), ("Read",))
        self.assertEqual(subtract([], ["Write"]), ())

    def test_names_are_normalised_and_bare_strings_refused(self):
        self.assertEqual(normalise_names([" Read ", "Read", "", "Grep"]), ("Read", "Grep"))
        with self.assertRaises(TypeError):
            normalise_names("Read")

    def test_unknown_mode_is_refused_at_construction(self):
        self.assertEqual(validate_mode("plan"), "plan")
        with self.assertRaises(ValueError):
            validate_mode("yolo")


class ModeTests(unittest.TestCase):
    def test_default_mode_allows_read_only_and_refuses_mutating_without_a_callback(self):
        engine = PermissionEngine(PermissionConfig(mode="default"))
        self.assertTrue(engine.evaluate("Read", kind="read").allowed)
        decision = engine.evaluate("Write", kind="edit")
        self.assertFalse(decision.allowed)
        self.assertIn("no host approval callback", decision.reason)

    def test_default_mode_asks_the_host_callback_for_mutating_tools(self):
        asked: list[tuple[str, dict]] = []

        def approve(name, payload, ctx):
            asked.append((name, payload))
            return True

        engine = PermissionEngine(PermissionConfig(mode="default", can_use_tool=approve))
        decision = engine.evaluate("Write", kind="edit", payload={"path": "a.txt"})
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.source, "host_callback")
        self.assertEqual(asked, [("Write", {"path": "a.txt"})])

    def test_a_callback_that_raises_fails_closed(self):
        def explode(name, payload, ctx):
            raise RuntimeError("approval service down")

        engine = PermissionEngine(PermissionConfig(mode="default", can_use_tool=explode))
        decision = engine.evaluate("Write", kind="edit")
        self.assertFalse(decision.allowed)
        self.assertIn("failing closed", decision.reason)

    def test_every_callback_verdict_shape_is_understood(self):
        cases = [
            (True, True),
            (False, False),
            ("allow", True),
            ("deny", False),
            ({"allowed": True}, True),
            ({"allow": False, "reason": "nope"}, False),
            ("nonsense", False),
            (None, False),
        ]
        for verdict, expected in cases:
            with self.subTest(verdict=str(verdict)):
                engine = PermissionEngine(PermissionConfig(mode="default", can_use_tool=lambda *args: verdict))
                self.assertEqual(engine.evaluate("Write", kind="edit").allowed, expected)

    def test_a_dict_reason_reaches_the_denial_text(self):
        engine = PermissionEngine(PermissionConfig(mode="default", can_use_tool=lambda *args: {"allowed": False, "reason": "outside business hours"}))
        self.assertIn("outside business hours", engine.evaluate("Write", kind="edit").reason)

    def test_plan_mode_is_a_hard_read_only_boundary(self):
        approve_everything = PermissionEngine(PermissionConfig(mode="plan", can_use_tool=lambda *args: True))
        decision = approve_everything.evaluate("Write", kind="edit")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.rule, "mode:plan")
        self.assertTrue(approve_everything.evaluate("Grep", kind="read").allowed)

    def test_accept_edits_approves_edits_but_not_execution(self):
        engine = PermissionEngine(PermissionConfig(mode="acceptEdits"))
        self.assertTrue(engine.evaluate("Edit", kind="edit").allowed)
        self.assertTrue(engine.evaluate("Write", kind="edit").allowed)
        refused = engine.evaluate("Bash", kind="exec")
        self.assertFalse(refused.allowed)
        self.assertIn("no host approval callback", refused.reason)

    def test_bypass_permissions_still_respects_the_deny_list(self):
        engine = PermissionEngine(PermissionConfig(mode="bypassPermissions", disallowed_tools=("Bash",)))
        self.assertTrue(engine.evaluate("Bash", kind="exec").allowed is False)
        self.assertTrue(engine.evaluate("rm", kind="exec").allowed)

    def test_unknown_tools_are_refused_rather_than_defaulted_open(self):
        engine = PermissionEngine(PermissionConfig(mode="bypassPermissions"))
        decision = engine.evaluate("Mystery", kind="other", known=False)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.source, "unknown_tool")

    def test_a_delegation_tool_is_not_classified_as_mutating(self):
        engine = PermissionEngine(PermissionConfig(mode="default"))
        decision = engine.evaluate("Task", kind="task", mutating=False)
        self.assertTrue(decision.allowed, "denying Task by name would prevent subagents existing at all")


class DelegationGateTests(unittest.TestCase):
    def test_each_declared_tool_is_checked_on_its_own_merits(self):
        registry = registry_with_extra()
        engine = PermissionEngine(PermissionConfig(mode="default"))
        verdict = engine.check_delegation(
            "general",
            ("Read", "Grep", "Write"),
            kinds={**registry.kinds(), "Read": "read", "Grep": "read", "Write": "edit"},
        )
        self.assertFalse(verdict.ok)
        self.assertEqual([name for name, _reason in verdict.denied], ["Write"])
        self.assertEqual(verdict.allowed, ("Read", "Grep"))

    def test_the_failure_text_names_the_tool_not_the_task_wrapper(self):
        engine = PermissionEngine(PermissionConfig(mode="plan"))
        verdict = engine.check_delegation("general", ("Read", "Edit"), kinds={"Read": "read", "Edit": "edit"})
        self.assertIn("Edit", verdict.summary)
        self.assertNotIn("Task", verdict.summary)

    def test_host_extra_disallow_list_reaches_subagents(self):
        engine = PermissionEngine(PermissionConfig(mode="default"))
        verdict = engine.check_delegation("general", ("Read", "Grep"), kinds={"Read": "read", "Grep": "read"}, disallowed_extra=("Grep",))
        self.assertFalse(verdict.ok)
        self.assertEqual(verdict.denied[0][0], "Grep")


class PerCallApprovalBindingTests(unittest.TestCase):
    """Per-call approval binding: no caching, no replay.

    Absorbed from byquexo/agent-approval-gate (``gate.ts``): the gate holds
    no state between calls, every gated call re-invokes the approver with
    the exact call (id + arguments), and a "yes" is scoped to exactly one
    tool call. These tests pin that rule on the runtime engine.
    """

    def make(self, **kwargs) -> PermissionEngine:
        return PermissionEngine(PermissionConfig(mode="default", **kwargs))

    def test_callback_sees_call_id_and_arguments_digest(self):
        seen: list[tuple[str, str, str]] = []

        def callback(name: str, payload: dict, ctx: PermissionRequestContext) -> bool:
            seen.append((name, ctx.call_id, ctx.arguments_digest))
            return True

        engine = self.make(can_use_tool=callback)
        payload = {"path": "a.txt", "content": "x"}
        decision = engine.evaluate(
            "Write",
            kind="edit",
            payload=payload,
            context=PermissionRequestContext(call_id="call-1"),
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(len(seen), 1)
        name, call_id, digest = seen[0]
        self.assertEqual(name, "Write")
        self.assertEqual(call_id, "call-1")
        self.assertEqual(digest, digest_arguments(payload))
        self.assertTrue(digest.startswith("sha256:"))

    def test_digest_is_backfilled_when_caller_did_not_pin_it(self):
        seen: list[str] = []

        def callback(name: str, payload: dict, ctx: PermissionRequestContext) -> bool:
            seen.append(ctx.arguments_digest)
            return True

        engine = self.make(can_use_tool=callback)
        payload = {"path": "a.txt", "content": "x"}
        engine.evaluate("Write", kind="edit", payload=payload)
        self.assertEqual(seen, [digest_arguments(payload)])

    def test_approver_is_reinvoked_per_call_never_cached(self):
        calls: list[tuple[str, str]] = []

        def callback(name: str, payload: dict, ctx: PermissionRequestContext) -> bool:
            calls.append((name, ctx.arguments_digest))
            return len(calls) == 1  # approve only the very first call

        engine = self.make(can_use_tool=callback)
        first = engine.evaluate(
            "Write",
            kind="edit",
            payload={"path": "a.txt"},
            context=PermissionRequestContext(call_id="c1"),
        )
        second = engine.evaluate(
            "Write",
            kind="edit",
            payload={"path": "b.txt"},
            context=PermissionRequestContext(call_id="c2"),
        )
        self.assertTrue(first.allowed)
        # The first approval must not replay onto the second call: the
        # approver is asked again and now says no.
        self.assertFalse(second.allowed)
        self.assertEqual(second.source, "host_callback")
        self.assertEqual(len(calls), 2)
        self.assertNotEqual(calls[0][1], calls[1][1])

    def test_reused_approval_for_new_arguments_fails_closed(self):
        approved_digests = {digest_arguments({"path": "a.txt", "content": "1"})}

        def callback(name: str, payload: dict, ctx: PermissionRequestContext) -> bool:
            # A host grant scoped to one exact arguments digest.
            return ctx.arguments_digest in approved_digests

        engine = self.make(can_use_tool=callback)
        granted = engine.evaluate(
            "Write",
            kind="edit",
            payload={"path": "a.txt", "content": "1"},
            context=PermissionRequestContext(call_id="c1"),
        )
        # Same tool, different arguments: the old approval must not carry.
        replay = engine.evaluate(
            "Write",
            kind="edit",
            payload={"path": "a.txt", "content": "2"},
            context=PermissionRequestContext(call_id="c2"),
        )
        self.assertTrue(granted.allowed)
        self.assertFalse(replay.allowed)
        self.assertEqual(replay.source, "host_callback")


class EngineAtRuntimeTests(RuntimeTestCase):
    def test_mutating_tool_never_touches_disk_without_approval(self):
        workspace = self.workspace()
        provider = self.provider([tool_turn("Write", {"path": "note.txt", "content": "written"})])
        report = self.drive(self.runtime(provider=provider, workspace=workspace))
        self.assertFalse((workspace / "note.txt").exists())
        self.assertEqual(report.denials[0].source, "mode")
        refusal = report.transcript[2].tool_results[0]
        self.assertTrue(refusal.is_error)
        self.assertIn("permission gate", refusal.text())

    def test_host_approval_lets_the_write_through(self):
        workspace = self.workspace()
        provider = self.provider([tool_turn("Write", {"path": "note.txt", "content": "written"}), text_turn("done")])
        runtime = self.runtime(provider=provider, workspace=workspace, can_use_tool=lambda name, payload, ctx: True)
        report = self.drive(runtime, "write it")
        self.assertEqual((workspace / "note.txt").read_text(), "written")
        self.assertEqual([call.permission_source for call in report.tool_calls], ["host_callback"])
        self.assertEqual([call.name for call in report.tool_calls], ["Write"])
        self.assertEqual(report.denials, ())

    def test_plan_mode_at_runtime_refuses_writes_even_with_an_approving_callback(self):
        workspace = self.workspace()
        provider = self.provider([tool_turn("Write", {"path": "note.txt", "content": "x"})])
        report = self.drive(self.runtime(provider=provider, workspace=workspace, permission_mode="plan", can_use_tool=lambda *args: True))
        self.assertFalse((workspace / "note.txt").exists())
        self.assertEqual(report.denials[0].source, "mode")

    def test_read_only_tool_output_is_capped_and_flagged(self):
        workspace = self.workspace({"big.txt": "0123456789" * 40_000})
        provider = self.provider([tool_turn("Read", {"path": "big.txt"}), text_turn("done")])
        report = self.drive(self.runtime(provider=provider, workspace=workspace))
        text = provider.sent_tool_results()[0]["content"]
        self.assertIn("[first 262144 of 400000 bytes", text)
        self.assertLess(len(text), 280_000)

    def test_denial_is_recorded_once_per_call_with_its_source(self):
        provider = self.provider([tool_turn("Write", {"path": "a", "content": "1"}), tool_turn("Write", {"path": "b", "content": "2"}), text_turn("done")])
        report = self.drive(self.runtime(provider=provider, max_turns=5))
        self.assertEqual(len(report.denials), 2)
        self.assertEqual({denial.source for denial in report.denials}, {"mode"})
        self.assertEqual([denial.turn_index for denial in report.denials], [1, 2])

    def test_denial_tool_result_is_structured_with_tier_and_retryability(self):
        provider = self.provider([tool_turn("Write", {"path": "a", "content": "1"}), text_turn("done")])
        report = self.drive(self.runtime(provider=provider, can_use_tool=lambda *args: False))
        refusal = report.transcript[2].tool_results[0]
        self.assertTrue(refusal.is_error)
        content = refusal.content
        self.assertIsInstance(content, dict)
        self.assertEqual(content["status"], "denied")
        self.assertEqual(content["tool"], "Write")
        self.assertEqual(content["tier"], "host_callback")
        self.assertTrue(content["retryable"])
        self.assertIn("refused by the permission gate", content["message"])
        # The flattened text the model actually sees still carries the refusal.
        self.assertIn("refused by the permission gate", refusal.text())

    def test_policy_denial_tool_result_is_not_retryable(self):
        provider = self.provider([tool_turn("Write", {"path": "a", "content": "1"}), text_turn("done")])
        report = self.drive(
            self.runtime(
                provider=provider,
                disallowed_tools=("Write",),
                can_use_tool=lambda *args: True,
            )
        )
        refusal = report.transcript[2].tool_results[0]
        content = refusal.content
        self.assertIsInstance(content, dict)
        self.assertEqual(content["status"], "denied")
        self.assertEqual(content["tier"], "disallowed_tools")
        self.assertFalse(content["retryable"])

    def test_host_callback_receives_call_id_and_digest_at_runtime(self):
        seen: list[tuple[str, str]] = []

        def callback(name: str, payload: dict, ctx: PermissionRequestContext) -> bool:
            seen.append((ctx.call_id, ctx.arguments_digest))
            return True

        provider = self.provider([tool_turn("Write", {"path": "a", "content": "1"}), text_turn("done")])
        self.drive(self.runtime(provider=provider, workspace=self.workspace(), can_use_tool=callback))
        self.assertEqual(len(seen), 1)
        call_id, digest = seen[0]
        self.assertTrue(call_id)
        self.assertEqual(digest, digest_arguments({"path": "a", "content": "1"}))


if __name__ == "__main__":
    unittest.main()
