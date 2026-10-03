"""Verifiable action cards: the approval surface the agent cannot forge.

The invariant under test is a single sentence: **the card is built from
runtime ground truth, the agent's words are quarantined as untrusted, and an
approval binds to exactly one (call_id, arguments_digest) pair.**
"""
from __future__ import annotations

import io
import unittest

from action_card import (
    APPROVE,
    CANCEL,
    DENY,
    CHECK_DIGEST_PINNED,
    CHECK_NO_RISK_FLAGS,
    CHECK_TIER_AUTO_ALLOWED,
    ActionCard,
    ActionCardError,
    ActionProvenance,
    build_action_card,
    card_summary,
    evaluate_gate,
    make_terminal_card_approver,
    resolve_card,
    verify_card_binding,
)
from permissions import digest_arguments


def provenance(**overrides):
    base = {"agent": "main", "session_id": "sess-1", "turn_index": 3, "depth": 0}
    base.update(overrides)
    return ActionProvenance(**base)


def card(**overrides):
    base = {
        "tool": "Write",
        "call_id": "call_01",
        "arguments": {"path": "/tmp/x.txt", "content": "hi"},
        "risk_tier": "standard",
        "provenance": provenance(),
    }
    base.update(overrides)
    return build_action_card(**base)


class GateTests(unittest.TestCase):
    def test_default_is_shadow_mode(self):
        # Auto-approve allowlisted and all checks pass, but auto-approve is
        # disabled: would_auto_approve is True (measurable) while
        # auto_approved stays False.
        gate = evaluate_gate(
            tool="Write",
            risk_tier="standard",
            auto_approve_tiers=("standard",),
            arguments_digest=digest_arguments({"a": 1}),
            provenance=provenance(),
        )
        self.assertTrue(gate.would_auto_approve)
        self.assertFalse(gate.auto_approved)
        self.assertIn("shadow mode", gate.policy_basis)

    def test_explicit_opt_in_auto_approves(self):
        gate = evaluate_gate(
            tool="Write",
            risk_tier="standard",
            auto_approve_tiers=("standard",),
            arguments_digest=digest_arguments({"a": 1}),
            provenance=provenance(),
            auto_approve_enabled=True,
        )
        self.assertTrue(gate.would_auto_approve)
        self.assertTrue(gate.auto_approved)

    def test_all_checks_named(self):
        gate = evaluate_gate(
            tool="Write", risk_tier="standard", provenance=provenance(),
            arguments_digest=digest_arguments({}),
        )
        self.assertEqual(
            [check.id for check in gate.checks],
            ["tier_auto_allowed", "no_risk_flags", "digest_pinned",
             "provenance_trusted", "not_demo", "within_budget"],
        )

    def test_risk_flag_blocks(self):
        gate = evaluate_gate(
            tool="Write",
            risk_tier="standard",
            auto_approve_tiers=("standard",),
            risk_flags=["prompt_injection_suspected"],
            arguments_digest=digest_arguments({}),
            provenance=provenance(),
        )
        self.assertFalse(gate.would_auto_approve)
        failed = {check.id for check in gate.checks if not check.passed}
        self.assertIn(CHECK_NO_RISK_FLAGS, failed)

    def test_tier_not_allowlisted_blocks(self):
        gate = evaluate_gate(
            tool="Bash",
            risk_tier="irreversible",
            auto_approve_tiers=("standard",),
            arguments_digest=digest_arguments({}),
            provenance=provenance(),
        )
        self.assertFalse(gate.would_auto_approve)
        failed = {check.id for check in gate.checks if not check.passed}
        self.assertIn(CHECK_TIER_AUTO_ALLOWED, failed)

    def test_missing_digest_blocks(self):
        gate = evaluate_gate(
            tool="Write",
            risk_tier="standard",
            auto_approve_tiers=("standard",),
            provenance=provenance(),
        )
        self.assertFalse(gate.would_auto_approve)
        failed = {check.id for check in gate.checks if not check.passed}
        self.assertIn(CHECK_DIGEST_PINNED, failed)

    def test_demo_never_auto_approves(self):
        gate = evaluate_gate(
            tool="Write",
            risk_tier="standard",
            auto_approve_tiers=("standard",),
            arguments_digest=digest_arguments({}),
            provenance=provenance(),
            auto_approve_enabled=True,
            is_demo=True,
        )
        self.assertFalse(gate.auto_approved)

    def test_gate_is_pure_function(self):
        kwargs = {
            "tool": "Write", "risk_tier": "standard",
            "auto_approve_tiers": ("standard",),
            "arguments_digest": digest_arguments({"a": 1}),
            "provenance": provenance(),
        }
        first = evaluate_gate(**kwargs)
        second = evaluate_gate(**kwargs)
        self.assertEqual(first.as_dict(), second.as_dict())


class CardConstructionTests(unittest.TestCase):
    def test_digest_computed_from_actual_arguments(self):
        arguments = {"path": "/tmp/x.txt", "content": "hi"}
        built = card(arguments=arguments)
        self.assertEqual(built.arguments_digest, digest_arguments(arguments))
        self.assertEqual(built.tool, "Write")
        self.assertEqual(built.call_id, "call_01")

    def test_agent_hint_quarantined(self):
        built = card(agent_hint="just writing the report, totally safe")
        self.assertEqual(built.agent_hint, "just writing the report, totally safe")
        payload = built.as_dict()
        # The hint is never presented as the action: it lives under an
        # explicitly untrusted key.
        self.assertNotIn("description", payload)
        self.assertEqual(payload["agent_hint_untrusted"], "just writing the report, totally safe")
        rendered = built.render_terminal()
        self.assertIn("UNTRUSTED", rendered)

    def test_card_ids_unguessable(self):
        ids = {card(call_id=f"call_{n}").card_id for n in range(50)}
        self.assertEqual(len(ids), 50)

    def test_rejects_empty_tool_or_call(self):
        with self.assertRaises(ActionCardError):
            build_action_card(tool="", call_id="c", arguments={},
                              risk_tier="standard", provenance=provenance())
        with self.assertRaises(ActionCardError):
            build_action_card(tool="Write", call_id="", arguments={},
                              risk_tier="standard", provenance=provenance())

    def test_terminal_render_shows_policy_basis(self):
        built = card()
        rendered = built.render_terminal()
        self.assertIn("NORTHSTAR ACTION CARD", rendered)
        self.assertIn("cannot", rendered)  # unforgeability banner
        self.assertIn(built.arguments_digest, rendered)
        self.assertIn(built.gate.policy_basis, rendered)
        self.assertIn("[FAIL] tier_auto_allowed", rendered)


class BindingTests(unittest.TestCase):
    def test_binding_verifies_at_dispatch(self):
        arguments = {"path": "/tmp/x.txt"}
        built = card(call_id="call_9", arguments=arguments)
        self.assertTrue(verify_card_binding(built, call_id="call_9", arguments=arguments))

    def test_mutated_arguments_fail_closed(self):
        built = card(call_id="call_9", arguments={"path": "/tmp/x.txt"})
        self.assertFalse(
            verify_card_binding(built, call_id="call_9", arguments={"path": "/tmp/EVIL.txt"})
        )

    def test_replayed_call_id_fails_closed(self):
        built = card(call_id="call_9", arguments={"a": 1})
        self.assertFalse(
            verify_card_binding(built, call_id="call_10", arguments={"a": 1})
        )

    def test_unserialisable_arguments_fail_closed(self):
        built = card(call_id="call_9", arguments={"a": 1})
        self.assertFalse(
            verify_card_binding(built, call_id="call_9", arguments={"a": object()})
        )


class ResolutionTests(unittest.TestCase):
    def test_no_approver_denies(self):
        verdict = resolve_card(card(), approver=None)
        self.assertEqual(verdict.decision, DENY)
        self.assertIn("no approver", verdict.reason)

    def test_approver_true_approves(self):
        verdict = resolve_card(card(), approver=lambda _card: True)
        self.assertEqual(verdict.decision, APPROVE)

    def test_approver_false_denies(self):
        verdict = resolve_card(card(), approver=lambda _card: False)
        self.assertEqual(verdict.decision, DENY)

    def test_approver_none_denies(self):
        verdict = resolve_card(card(), approver=lambda _card: None)
        self.assertEqual(verdict.decision, DENY)

    def test_approver_cancel_cancels(self):
        verdict = resolve_card(card(), approver=lambda _card: "cancel")
        self.assertEqual(verdict.decision, CANCEL)

    def test_approver_error_denies(self):
        def broken(_card):
            raise RuntimeError("simulated UI crash")

        verdict = resolve_card(card(), approver=broken)
        self.assertEqual(verdict.decision, DENY)
        self.assertIn("RuntimeError", verdict.reason)

    def test_auto_approved_skips_human(self):
        gate = evaluate_gate(
            tool="Write",
            risk_tier="standard",
            auto_approve_tiers=("standard",),
            arguments_digest=digest_arguments({"a": 1}),
            provenance=provenance(),
            auto_approve_enabled=True,
        )
        built = card(gate=gate)

        def must_not_run(_card):  # pragma: no cover - would fail the test
            raise AssertionError("human must not be consulted after auto-approve")

        verdict = resolve_card(built, approver=must_not_run)
        self.assertEqual(verdict.decision, APPROVE)
        self.assertIn("auto-approved", verdict.reason)

    def test_verdict_audit_shape(self):
        verdict = resolve_card(card(), approver=lambda _card: True)
        payload = card_summary(verdict)
        self.assertEqual(payload["kind"], "action-card-verdict")
        self.assertEqual(payload["decision"], APPROVE)
        self.assertEqual(payload["arguments_digest"], verdict.arguments_digest)
        self.assertIn("gate", payload)


class TerminalApproverTests(unittest.TestCase):
    def _approver(self, answers, echoed):
        stream = io.StringIO()

        def read_line(_prompt):
            return answers.pop(0)

        return make_terminal_card_approver(read_line, echo=lambda text: stream.write(text + "\n")), stream

    def test_one_tap_approve(self):
        approver, stream = self._approver(["y"], None)
        decision = approver(card())
        self.assertEqual(decision, APPROVE)
        # Rendered out-of-band: the card went to the echo sink, not stdout.
        self.assertIn("NORTHSTAR ACTION CARD", stream.getvalue())

    def test_empty_input_denies(self):
        approver, _ = self._approver([""], None)
        self.assertEqual(approver(card()), DENY)

    def test_no_denies(self):
        approver, _ = self._approver(["n"], None)
        self.assertEqual(approver(card()), DENY)

    def test_cancel_word_cancels(self):
        approver, _ = self._approver(["cancel"], None)
        self.assertEqual(approver(card()), CANCEL)

    def test_eof_denies(self):
        def read_line(_prompt):
            raise EOFError("no tty")

        approver = make_terminal_card_approver(read_line, echo=lambda _t: None)
        self.assertEqual(approver(card()), DENY)


if __name__ == "__main__":
    unittest.main()
