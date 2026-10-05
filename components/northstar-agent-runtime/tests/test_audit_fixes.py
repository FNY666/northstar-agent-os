"""Regression tests for the 2026-10-04 enforcement-audit fixes.

Each test pins a REAL finding from the adversarial audit:
P1/D1 child-engine field drop, P3 unknown-tool silence, B5 budget-denial
silence, E4 DLP header bypass, A2 body-swap bypass, D5 agent-impersonation.
"""
from __future__ import annotations

import os
import time
import unittest

import support  # noqa: F401
from support import RuntimeTestCase

from action_card import ActionProvenance, build_action_card
from ed25519 import public_key
from egress_enforcer import (
    DENY_APPROVAL_BINDING,
    DENY_DLP,
    EgressRequest,
    authorize_egress,
    build_approval_receipt,
)
from loop import Denial


def _egress_policy(**overrides):
    from egress_enforcer import DestinationRule, EgressPolicy
    from types import MappingProxyType

    rule = DestinationRule(
        name="hook",
        hosts=("hook.internal.example.com",),
        ports=(443,),
        methods=("POST",),
        path_prefixes=("/x",),
        require_approval=overrides.pop("require_approval", False),
        max_bytes_per_day=overrides.pop("max_bytes_per_day", None),
        allow_private_ips=True,
    )
    return EgressPolicy(
        revision="test.r1",
        destinations=MappingProxyType({"hook": rule}),
        dlp_patterns=("sk-[A-Za-z0-9]{16,}",),
    )


NOW = 1_780_000_000.0


class ChildEngineInheritanceTests(RuntimeTestCase):
    """P1/D1: the child runtime must not escape the parent's enforcement."""

    def _runtime_with_enforcement(self):
        from permissions import PermissionConfig, PermissionEngine, PreTradeRiskConfig

        audit_seen = []
        pretrade = PreTradeRiskConfig(max_calls_per_window=5)
        engine = PermissionEngine(
            PermissionConfig(),
            pretrade=pretrade,
            audit_sink=audit_seen.append,
        )
        provider = self.provider([])
        runtime = self.runtime(
            provider=provider,
            workspace=self.workspace({}),
        )
        runtime.permissions = engine
        return runtime, audit_seen, pretrade

    def _make_state(self, runtime):
        from loop import _RunState

        return _RunState(session_id=runtime.session_id)

    def test_child_inherits_pretrade_and_audit_sink(self):
        runtime, audit_seen, pretrade = self._runtime_with_enforcement()
        child, _child_config, _mode = runtime._child_runtime(
            runtime.agents.get("general"),
            runtime.provider,
            self._make_state(runtime),
        )
        self.assertIs(child.permissions.pretrade, pretrade)
        self.assertIsNotNone(child.permissions.audit_sink)

    def test_child_inherits_decision_model_and_multisig(self):
        from multisig import MultisigPolicy
        from permissions import PermissionConfig, PermissionEngine

        seed = os.urandom(32)
        pubkeys = {"op1": public_key(seed)}
        engine = PermissionEngine(
            PermissionConfig(
                multisig=MultisigPolicy(approvers=("op1",), threshold=1),
            ),
            multisig_pubkeys=pubkeys,
        )
        provider = self.provider([])
        runtime = self.runtime(provider=provider, workspace=self.workspace({}))
        runtime.permissions = engine
        child, _child_config, _mode = runtime._child_runtime(
            runtime.agents.get("general"),
            runtime.provider,
            self._make_state(runtime),
        )
        self.assertIsNotNone(child.permissions.config.multisig)
        self.assertEqual(child.permissions.config.multisig.approvers, ("op1",))
        self.assertIsNotNone(child.permissions.multisig_pubkeys)


class UnknownToolDenialTests(RuntimeTestCase):
    """P3: hallucinated-tool refusals must hit the denial ledger."""

    def test_unknown_tool_records_denial(self):
        from support import tool_turn, text_turn

        provider = self.provider([tool_turn("DeleteTheInternet", {}), text_turn("done")])
        runtime = self.runtime(provider=provider, workspace=self.workspace({}))
        report = self.drive(runtime, "go")
        denials = [d for d in report.denials if d.tool == "DeleteTheInternet"]
        self.assertEqual(len(denials), 1)
        self.assertEqual(denials[0].source, "unknown_tool")


class BudgetDenialTests(RuntimeTestCase):
    """B5: budget blocks must emit Denial records."""

    def test_exhausted_budget_records_denial_at_turn_head(self):
        from support import text_turn

        provider = self.provider([text_turn("done")])
        runtime = self.runtime(
            provider=provider,
            workspace=self.workspace({}),
            max_budget_usd=0.01,
        )
        # Force the budget to look exhausted: the turn-head ceiling fires
        # before any generation and must record a Denial.
        runtime.budget.total_cost_usd = 1.0
        report = self.drive(runtime, "go")
        budget_denials = [d for d in report.denials if d.source == "limit:max_budget_usd"]
        self.assertTrue(budget_denials, "budget stop must record a Denial")


class DlpHeaderTests(unittest.TestCase):
    """E4: the DLP tripwire must scan headers, not just the body."""

    def _req(self, **overrides):
        base = {
            "request_id": "r-1",
            "agent_id": "main",
            "run_id": "run1",
            "host": "hook.internal.example.com",
            "port": 443,
            "method": "POST",
            "path": "/x",
            "body": b"{}",
            "call_id": "c1",
            "arguments": {},
        }
        base.update(overrides)
        return EgressRequest(**base)

    def test_secret_in_header_denied(self):
        v = authorize_egress(
            _egress_policy(),
            self._req(headers={"X-Data": "sk-abcdefghij1234567890"}),
            resolve=lambda h: ["10.0.0.5"],
            now=NOW,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_DLP)

    def test_clean_headers_allowed(self):
        v = authorize_egress(
            _egress_policy(),
            self._req(headers={"X-Data": "nothing secret here"}),
            resolve=lambda h: ["10.0.0.5"],
            now=NOW,
        )
        self.assertTrue(v.allowed)


class ApprovalBodyBindingTests(unittest.TestCase):
    """A2: swapping the body after approval must fail closed."""

    def setUp(self):
        self.seed = os.urandom(32)
        self.pub = public_key(self.seed)
        self.args = {"target": "prod"}
        self.card = build_action_card(
            tool="Egress",
            call_id="call-9",
            arguments=self.args,
            risk_tier="high",
            provenance=ActionProvenance(agent="main", session_id="s1"),
        )
        self.body = b'{"deploy": true}'
        self.receipt = build_approval_receipt(
            card_id=self.card.card_id,
            call_id="call-9",
            arguments_digest=self.card.arguments_digest,
            approver_id="op1",
            approver_seed=self.seed,
            decided_at=time.time(),
            body=self.body,
        )
        self.pol = _egress_policy(require_approval=True)

    def _req(self, **overrides):
        base = {
            "request_id": "r-1",
            "agent_id": "main",
            "run_id": "run1",
            "host": "hook.internal.example.com",
            "port": 443,
            "method": "POST",
            "path": "/x",
            "body": self.body,
            "call_id": "call-9",
            "arguments": dict(self.args),
            "card": self.card,
            "approval_receipt": self.receipt,
        }
        base.update(overrides)
        return EgressRequest(**base)

    def test_matching_body_allows(self):
        v = authorize_egress(
            self.pol, self._req(), resolve=lambda h: ["10.0.0.5"], now=NOW,
            approver_keys={"op1": self.pub},
        )
        self.assertTrue(v.allowed)

    def test_swapped_body_denied(self):
        v = authorize_egress(
            self.pol,
            self._req(body=b'{"deploy": false, "evil": true}'),
            resolve=lambda h: ["10.0.0.5"],
            now=NOW,
            approver_keys={"op1": self.pub},
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_APPROVAL_BINDING)

    def test_wrong_agent_denied(self):
        """D5: agent B cannot reuse agent A's approved card+receipt."""
        v = authorize_egress(
            self.pol,
            self._req(agent_id="intruder"),
            resolve=lambda h: ["10.0.0.5"],
            now=NOW,
            approver_keys={"op1": self.pub},
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_APPROVAL_BINDING)


if __name__ == "__main__":
    unittest.main()
