"""Egress enforcer: the enforcement half of the gateway.

The invariant under test: every egress decision is made against the
*resolved* destination at CONNECT time, never the agent's word for it; every
denial carries a stable ``egress.*`` code; every decision emits a chained
receipt; and a forged or replayed approval never authorizes a mutated
request.
"""
from __future__ import annotations

import os
import tempfile
import time
import unittest
from pathlib import Path
from types import MappingProxyType

from action_card import ActionProvenance, build_action_card
from audit_chain import verify_lines
from ed25519 import public_key

from egress_enforcer import (
    DENY_APPROVAL_BINDING,
    DENY_BUDGET,
    DENY_BYPASS,
    DENY_DESTINATION_DENIED,
    DENY_DLP,
    DENY_SHAPE,
    DENY_UNRESOLVED,
    EgressBudgetLedger,
    EgressPolicy,
    EgressPolicyError,
    EgressRequest,
    approval_receipt_from_dict,
    authorize_egress,
    build_approval_receipt,
    card_from_dict,
    load_egress_policy,
    verify_approval_receipt,
    DestinationRule,
)

NOW = 1_780_000_000.0


def policy(**overrides) -> EgressPolicy:
    rule_kwargs = {
        "name": "rekor",
        "hosts": ("rekor.sigstore.dev",),
        "ports": (443,),
        "methods": ("POST",),
        "path_prefixes": ("/api/v1/log/entries",),
    }
    rule_kwargs.update(overrides.pop("rule", {}))
    rule = DestinationRule(**rule_kwargs)
    return EgressPolicy(revision="test.r1", destinations=MappingProxyType({"rekor": rule}), **overrides)


def request(**overrides) -> EgressRequest:
    base = {
        "request_id": "r-1",
        "agent_id": "agent-1",
        "run_id": "run-1",
        "host": "rekor.sigstore.dev",
        "port": 443,
        "method": "POST",
        "path": "/api/v1/log/entries",
        "body": b"{}",
    }
    base.update(overrides)
    return EgressRequest(**base)


def decide(*, pol=None, req=None, **kwargs):
    kwargs.setdefault("resolve", lambda h: ["1.2.3.4"])
    kwargs.setdefault("now", NOW)
    return authorize_egress(pol or policy(), req or request(), **kwargs)


class PolicyLoadingTests(unittest.TestCase):
    def _write(self, text: str) -> str:
        d = tempfile.mkdtemp()
        Path(d, "northstar-egress.toml").write_text(text)
        return d

    def test_loads_minimal_policy(self):
        d = self._write(
            'revision = "2026-10-04.r1"\n'
            "[destinations.rekor]\n"
            'hosts = ["rekor.sigstore.dev"]\n'
            "ports = [443]\n"
            'methods = ["POST"]\n'
            'path_prefixes = ["/api/v1/log/entries"]\n'
        )
        pol = load_egress_policy(d)
        self.assertEqual(pol.revision, "2026-10-04.r1")
        self.assertIn("rekor", pol.destinations)

    def test_missing_file_fails_closed(self):
        with self.assertRaises(EgressPolicyError):
            load_egress_policy(tempfile.mkdtemp())

    def test_wildcard_host_rejected(self):
        d = self._write(
            'revision = "r1"\n[destinations.x]\nhosts = ["*.example.com"]\nports = [443]\n'
            'methods = ["GET"]\npath_prefixes = ["/"]\n'
        )
        with self.assertRaises(EgressPolicyError):
            load_egress_policy(d)

    def test_credential_value_rejected_reference_only(self):
        d = self._write(
            'revision = "r1"\n[destinations.x]\nhosts = ["example.com"]\nports = [443]\n'
            'methods = ["GET"]\npath_prefixes = ["/"]\n'
            'credential = "sk-abcdefghijklmnopqrstuvwx1234567890EXTRA"\n'
        )
        with self.assertRaises(EgressPolicyError):
            load_egress_policy(d)

    def test_credential_reference_accepted(self):
        d = self._write(
            'revision = "r1"\n[destinations.x]\nhosts = ["example.com"]\nports = [443]\n'
            'methods = ["GET"]\npath_prefixes = ["/"]\ncredential = "hook-token"\n'
        )
        pol = load_egress_policy(d)
        self.assertEqual(pol.destinations["x"].credential, "hook-token")

    def test_duplicate_host_across_destinations_rejected(self):
        d = self._write(
            'revision = "r1"\n[destinations.a]\nhosts = ["example.com"]\nports = [443]\n'
            'methods = ["GET"]\npath_prefixes = ["/"]\n[destinations.b]\n'
            'hosts = ["example.com"]\nports = [443]\nmethods = ["GET"]\npath_prefixes = ["/"]\n'
        )
        with self.assertRaises(EgressPolicyError):
            load_egress_policy(d)

    def test_suffix_does_not_match(self):
        pol = policy()
        self.assertIsNone(pol.destination_for("evil-rekor.sigstore.dev"))
        self.assertIsNone(pol.destination_for("rekor.sigstore.dev.evil.com"))
        self.assertIsNotNone(pol.destination_for("REKOR.SIGSTORE.DEV"))


class DecisionTests(unittest.TestCase):
    def test_allow_happy_path(self):
        v = decide()
        self.assertTrue(v.allowed)
        self.assertEqual(v.deny_code, "")
        self.assertEqual(v.dial_ips, ("1.2.3.4",))
        self.assertEqual(v.receipt["verdict"], "allow")
        self.assertEqual(v.receipt["policy_revision"], "test.r1")

    def test_unlisted_destination_denied(self):
        v = decide(req=request(host="evil.com"))
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_DESTINATION_DENIED)

    def test_unlisted_port_denied(self):
        v = decide(req=request(port=8080))
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_DESTINATION_DENIED)

    def test_unresolved_destination(self):
        v = decide(resolve=lambda h: [])
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_UNRESOLVED)

    def test_resolver_exception_fails_closed(self):
        def boom(h):
            raise RuntimeError("dns down")

        v = decide(resolve=boom)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_UNRESOLVED)

    def test_ssrf_private_ip_denied(self):
        for ip in ("10.0.0.1", "127.0.0.1", "169.254.169.254", "192.168.1.1", "::1"):
            v = decide(resolve=lambda h, ip=ip: [ip])
            self.assertFalse(v.allowed, ip)
            self.assertEqual(v.deny_code, DENY_DESTINATION_DENIED, ip)

    def test_private_ip_allowed_when_opted_in(self):
        pol = policy(rule={"allow_private_ips": True})
        v = decide(pol=pol, resolve=lambda h: ["10.0.0.5"])
        self.assertTrue(v.allowed)
        self.assertEqual(v.dial_ips, ("10.0.0.5",))

    def test_mixed_ips_filters_to_public(self):
        v = decide(resolve=lambda h: ["169.254.169.254", "1.2.3.4"])
        self.assertTrue(v.allowed)
        self.assertEqual(v.dial_ips, ("1.2.3.4",))

    def test_shape_method_violation(self):
        v = decide(req=request(method="DELETE"))
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_SHAPE)

    def test_shape_path_violation(self):
        v = decide(req=request(path="/admin/drop"))
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_SHAPE)

    def test_bypass_smuggled_auth_denied(self):
        pol = policy(rule={"credential": "hook-token"})
        v = decide(pol=pol, req=request(headers={"Authorization": "Bearer stolen"}))
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_BYPASS)

    def test_bypass_only_applies_to_brokered_destinations(self):
        v = decide(req=request(headers={"Authorization": "Bearer user-key"}))
        self.assertTrue(v.allowed)

    def test_dlp_tripwire(self):
        v = decide(req=request(body=b"key=sk-abcdefghijklmnopqrstuvwx"))
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_DLP)

    def test_budget_exceeded(self):
        pol = policy(rule={"max_bytes_per_day": 10})
        budgets = EgressBudgetLedger()
        v = decide(pol=pol, req=request(body=b"12345"), budgets=budgets)
        self.assertTrue(v.allowed)
        v = decide(pol=pol, req=request(body=b"123456"), budgets=budgets)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_BUDGET)

    def test_deny_receipt_is_chained(self):
        v = decide(req=request(host="evil.com"))
        receipt = v.receipt
        self.assertEqual(receipt["deny_code"], DENY_DESTINATION_DENIED)
        self.assertIn("chain_hash", receipt)
        self.assertIn("prev_hash", receipt)

    def test_signed_receipt_verifies(self):
        seed = os.urandom(32)
        pub = public_key(seed)
        v = decide(enforcer_seed=seed, key_id="egress-1")
        receipt = v.receipt
        self.assertIn("signature", receipt)
        lines = [__import__("json").dumps(receipt)]
        result = verify_lines(lines, public_key=pub)
        self.assertTrue(result.ok, result.reason)

    def test_receipt_records_resolved_destination(self):
        v = decide(resolve=lambda h: ["1.2.3.4", "5.6.7.8"])
        dest = v.receipt["resolved_destination"]
        self.assertEqual(dest["host"], "rekor.sigstore.dev")
        self.assertEqual(dest["ips"], ["1.2.3.4", "5.6.7.8"])
        self.assertEqual(v.dial_ips, ("1.2.3.4", "5.6.7.8"))  # sidecar dials dial_ips[0]


class ApprovalBindingTests(unittest.TestCase):
    def setUp(self):
        self.seed = os.urandom(32)
        self.pub = public_key(self.seed)
        self.args = {"target": "prod", "ref": "abc123"}
        self.card = build_action_card(
            tool="Egress",
            call_id="call-9",
            arguments=self.args,
            risk_tier="high",
            provenance=ActionProvenance(agent="main", session_id="s1"),
        )
        self.receipt = build_approval_receipt(
            card_id=self.card.card_id,
            call_id="call-9",
            arguments_digest=self.card.arguments_digest,
            approver_id="op1",
            approver_seed=self.seed,
            decided_at=time.time(),
            body=b"{}",
        )
        self.pol = policy(rule={"require_approval": True, "allow_private_ips": True})

    def _req(self, **overrides):
        base = {
            "request_id": "r-1",
            # D5: agent_id must match the card's provenance agent ("main").
            "agent_id": "main",
            "run_id": "run1",
            "host": "rekor.sigstore.dev",
            "port": 443,
            "method": "POST",
            "path": "/api/v1/log/entries",
            "body": b"{}",
            "call_id": "call-9",
            "arguments": dict(self.args),
            "card": self.card,
            "approval_receipt": self.receipt,
        }
        base.update(overrides)
        return EgressRequest(**base)

    def test_valid_approval_allows(self):
        v = authorize_egress(
            self.pol, self._req(), resolve=lambda h: ["10.0.0.5"], now=NOW, approver_keys={"op1": self.pub}
        )
        self.assertTrue(v.allowed)
        self.assertEqual(v.receipt["approval_binding"]["approver_id"], "op1")

    def test_missing_card_denied(self):
        v = authorize_egress(
            self.pol,
            self._req(card=None, approval_receipt=None),
            resolve=lambda h: ["10.0.0.5"],
            now=NOW,
            approver_keys={"op1": self.pub},
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_APPROVAL_BINDING)

    def test_mutated_arguments_denied(self):
        v = authorize_egress(
            self.pol,
            self._req(arguments={"target": "prod", "ref": "EVIL"}),
            resolve=lambda h: ["10.0.0.5"],
            now=NOW,
            approver_keys={"op1": self.pub},
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_APPROVAL_BINDING)

    def test_wrong_approver_key_denied(self):
        v = authorize_egress(
            self.pol,
            self._req(),
            resolve=lambda h: ["10.0.0.5"],
            now=NOW,
            approver_keys={"op1": os.urandom(32)},
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_APPROVAL_BINDING)

    def test_tampered_receipt_signature_denied(self):
        tampered = approval_receipt_from_dict(
            {**self.receipt.as_dict(), "signature": "00" * 64}
        )
        v = authorize_egress(
            self.pol,
            self._req(approval_receipt=tampered),
            resolve=lambda h: ["10.0.0.5"],
            now=NOW,
            approver_keys={"op1": self.pub},
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_APPROVAL_BINDING)

    def test_receipt_for_other_card_denied(self):
        other = build_approval_receipt(
            card_id="other-card",
            call_id="call-9",
            arguments_digest=self.card.arguments_digest,
            approver_id="op1",
            approver_seed=self.seed,
            decided_at=NOW,
        )
        v = authorize_egress(
            self.pol,
            self._req(approval_receipt=other),
            resolve=lambda h: ["10.0.0.5"],
            now=NOW,
            approver_keys={"op1": self.pub},
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_APPROVAL_BINDING)

    def test_card_dict_round_trip(self):
        rebuilt = card_from_dict(self.card.as_dict())
        self.assertEqual(rebuilt.card_id, self.card.card_id)
        self.assertEqual(rebuilt.arguments_digest, self.card.arguments_digest)

    def test_malformed_card_dict_rejected(self):
        with self.assertRaises(EgressPolicyError):
            card_from_dict({"card_id": "x"})


class ApprovalReceiptTtlTests(unittest.TestCase):
    def test_fresh_receipt_verifies(self):
        from ed25519 import public_key as ed_pubkey

        seed = bytes(32)
        receipt = build_approval_receipt(
            card_id="c1",
            call_id="call-1",
            arguments_digest="sha256:abc",
            approver_id="op1",
            approver_seed=seed,
            decided_at=1000.0,
            body=b"{}",
        )
        pubkey = ed_pubkey(seed)
        self.assertTrue(verify_approval_receipt(receipt, pubkey, now=1000.0 + 60.0))

    def test_expired_receipt_rejected(self):
        from ed25519 import public_key as ed_pubkey

        seed = bytes(32)
        receipt = build_approval_receipt(
            card_id="c1",
            call_id="call-1",
            arguments_digest="sha256:abc",
            approver_id="op1",
            approver_seed=seed,
            decided_at=1000.0,
            body=b"{}",
        )
        pubkey = ed_pubkey(seed)
        # 10 minutes later, past the 5-minute default TTL.
        self.assertFalse(verify_approval_receipt(receipt, pubkey, now=1000.0 + 600.0))

    def test_future_receipt_rejected(self):
        from ed25519 import public_key as ed_pubkey

        seed = bytes(32)
        receipt = build_approval_receipt(
            card_id="c1",
            call_id="call-1",
            arguments_digest="sha256:abc",
            approver_id="op1",
            approver_seed=seed,
            decided_at=2000.0,
            body=b"{}",
        )
        pubkey = ed_pubkey(seed)
        # decided_at is in the future relative to now -> reject (clock skew / replay).
        self.assertFalse(verify_approval_receipt(receipt, pubkey, now=1000.0))

    def test_custom_ttl(self):
        from ed25519 import public_key as ed_pubkey

        seed = bytes(32)
        receipt = build_approval_receipt(
            card_id="c1",
            call_id="call-1",
            arguments_digest="sha256:abc",
            approver_id="op1",
            approver_seed=seed,
            decided_at=1000.0,
            body=b"{}",
        )
        pubkey = ed_pubkey(seed)
        # With a 1-hour TTL, 10 minutes is fine.
        self.assertTrue(
            verify_approval_receipt(receipt, pubkey, now=1000.0 + 600.0, max_age_seconds=3600.0)
        )


if __name__ == "__main__":
    unittest.main()
