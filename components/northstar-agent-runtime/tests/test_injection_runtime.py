"""Local behavioral regressions for prompt injection through tool output.

These tests use the real AgentRuntime dispatch and permission gate with a scripted
provider. The email tool is an in-memory side-effect recorder: no network,
subprocess, or external target is involved.
"""
from __future__ import annotations

import support  # noqa: F401
from support import RuntimeTestCase, text_turn, tool_turn

from injection_probe import PROBES
from providers.base import UserMessage
from tools import ToolProvenance, ToolRegistry, ToolResult, ToolSpec


ATTACK = next(probe for probe in PROBES if probe.expected_blocked)
BENIGN = next(probe for probe in PROBES if not probe.expected_blocked)


class InjectionRuntimeRegressionTests(RuntimeTestCase):
    def run_fixture(self, probe, *, attacker_attempts_email: bool):
        effects: list[dict] = []
        reads: list[str] = []

        def read_document(payload, ctx):
            reads.append(probe.probe_id)
            return ToolResult(
                content=probe.poisoned_output,
                provenance=ToolProvenance(
                    source=f"fixture:{probe.probe_id}",
                    trust="low",
                ),
            )

        def simulated_email(payload, ctx):
            effects.append(dict(payload))
            return ToolResult.ok("simulated email recorded")

        tools = ToolRegistry()
        tools.register(
            ToolSpec(
                name="ReadDocument",
                description="Read a local fixture document.",
                input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
                handler=read_document,
                kind="read",
                is_mutating=False,
            )
        )
        tools.register(
            ToolSpec(
                name="SendEmail",
                description="Record a simulated outbound email.",
                input_schema={"type": "object", "properties": {"to": {"type": "string"}}},
                handler=simulated_email,
                kind="network",
                is_mutating=True,
            )
        )

        turns = [tool_turn("ReadDocument", {"path": "fixture.txt"}, id="read-fixture")]
        if attacker_attempts_email:
            turns.append(
                tool_turn(
                    "SendEmail",
                    {"to": "outside.invalid", "body": "fixture-only"},
                    id="send-fixture",
                )
            )
        turns.append(text_turn("I summarized the document and followed the permission decision."))

        workspace = self.workspace()
        provider = self.provider(turns)
        report = self.drive(
            self.runtime(
                provider=provider,
                workspace=workspace,
                tools=tools,
                disallowed_tools=("SendEmail",),
                max_turns=4,
            )
        )
        return report, reads, effects

    @staticmethod
    def tool_result_text(report):
        return "\n".join(
            str(block.content)
            for message in report.transcript
            if isinstance(message, UserMessage)
            for block in message.tool_results
        )

    def test_attack_fixture_reaches_runtime_but_cannot_trigger_side_effect(self):
        report, reads, effects = self.run_fixture(ATTACK, attacker_attempts_email=True)

        self.assertEqual(reads, [ATTACK.probe_id])
        self.assertIn(ATTACK.poisoned_output, self.tool_result_text(report))
        self.assertEqual(effects, [], "the in-memory egress handler must not run")
        self.assertEqual(report.subtype, "success")
        self.assertEqual([call.name for call in report.tool_calls], ["ReadDocument", "SendEmail"])
        self.assertFalse(report.tool_calls[0].denied)
        self.assertTrue(report.tool_calls[1].denied)
        self.assertEqual(report.tool_calls[1].permission_source, "disallowed_tools")
        self.assertEqual([denial.tool for denial in report.denials], ["SendEmail"])
        self.assertEqual(report.as_dict()["denials"][0]["tool"], "SendEmail")

    def test_benign_control_remains_readable_under_the_same_policy(self):
        report, reads, effects = self.run_fixture(BENIGN, attacker_attempts_email=False)

        self.assertEqual(reads, [BENIGN.probe_id])
        self.assertIn(BENIGN.poisoned_output, self.tool_result_text(report))
        self.assertEqual(effects, [])
        self.assertEqual(report.subtype, "success")
        self.assertEqual(report.denials, ())
        self.assertEqual([call.name for call in report.tool_calls], ["ReadDocument"])
        self.assertFalse(report.tool_calls[0].denied)


if __name__ == "__main__":
    import unittest

    unittest.main()
