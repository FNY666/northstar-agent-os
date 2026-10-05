"""Tests for mandate_credentials (E.2, AP2-inspired)."""

from __future__ import annotations

import os
import time
import unittest

import support  # noqa: F401 — sys.path bootstrap

import mandate_credentials as mc
import ed25519


def _keypair() -> tuple[bytes, bytes]:
    secret = os.urandom(32)
    return secret, ed25519.public_key(secret)


class OpenMandateTests(unittest.TestCase):
    def test_issue_and_close_roundtrip(self):
        issuer_sec, _ = _keypair()
        cnf_sec, cnf_pub = _keypair()
        verifier_sec, _ = _keypair()
        now = int(time.time())

        open_m = mc.issue_open(
            issuer_secret=issuer_sec,
            delegate_to_did="did:northstar:abc123",
            cnf_pubkey=cnf_pub,
            constraints=[
                {"type": mc.C_ACTION_ALLOW, "actions": ["tool.exec"]},
                {"type": mc.C_BUDGET_MAX_SPEND, "amount": 100, "currency": "CNY"},
            ],
            expires_at=now + 3600,
        )
        self.assertEqual(open_m["state"], "open")

        closed = mc.close_mandate(
            open_mandate=open_m,
            cnf_secret=cnf_sec,
            action={"type": "tool.exec", "cost": 10, "card_hash": "abc"},
            verifier_id="verifier-1",
            nonce=os.urandom(16),
        )
        self.assertEqual(closed["state"], "closed")

        ctx = mc.UsageContext()
        v = mc.verify_closed(
            closed_mandate=closed, open_mandate=open_m, ctx=ctx, now=now
        )
        self.assertTrue(v.ok, v.violations)

        # Receipt
        receipt = mc.issue_receipt(
            verifier_secret=verifier_sec, closed_mandate=closed, ok=True
        )
        self.assertTrue(
            mc.verify_receipt(receipt, verifier_pubkey=ed25519.public_key(verifier_sec))
        )

    def test_unknown_constraint_type_fail_closed(self):
        issuer_sec, _ = _keypair()
        cnf_sec, cnf_pub = _keypair()
        now = int(time.time())
        open_m = mc.issue_open(
            issuer_secret=issuer_sec,
            delegate_to_did="did:northstar:x",
            cnf_pubkey=cnf_pub,
            constraints=[{"type": "evil.unknown", "whatever": 1}],
            expires_at=now + 3600,
        )
        closed = mc.close_mandate(
            open_mandate=open_m, cnf_secret=cnf_sec,
            action={"type": "tool.exec"}, verifier_id="v", nonce=os.urandom(16),
        )
        v = mc.verify_closed(
            closed_mandate=closed, open_mandate=open_m,
            ctx=mc.UsageContext(), now=now,
        )
        self.assertFalse(v.ok)
        self.assertIn("unknown constraint type", v.violations[0])

    def test_preset_claims_immutable(self):
        issuer_sec, _ = _keypair()
        cnf_sec, cnf_pub = _keypair()
        now = int(time.time())
        open_m = mc.issue_open(
            issuer_secret=issuer_sec,
            delegate_to_did="did:northstar:x",
            cnf_pubkey=cnf_pub,
            constraints=[{"type": mc.C_ACTION_ALLOW, "actions": ["tool.exec"]}],
            preset_claims={"payee": "alice"},
            expires_at=now + 3600,
        )
        closed = mc.close_mandate(
            open_mandate=open_m, cnf_secret=cnf_sec,
            action={"type": "tool.exec"}, verifier_id="v", nonce=os.urandom(16),
        )
        # Tamper: rewrite preset claims in the closed mandate, re-sign.
        closed["preset_claims"] = {"payee": "mallory"}
        body = {k: v for k, v in closed.items() if k != "signature"}
        from audit_chain import canonical_json
        closed["signature"] = ed25519.sign(cnf_sec, canonical_json(body)).hex()
        v = mc.verify_closed(
            closed_mandate=closed, open_mandate=open_m,
            ctx=mc.UsageContext(), now=now,
        )
        self.assertFalse(v.ok)
        self.assertIn("preset_claims", v.violations[0])

    def test_wrong_cnf_key_rejected(self):
        issuer_sec, _ = _keypair()
        _, cnf_pub = _keypair()
        evil_sec, _ = _keypair()
        now = int(time.time())
        open_m = mc.issue_open(
            issuer_secret=issuer_sec,
            delegate_to_did="did:northstar:x",
            cnf_pubkey=cnf_pub,
            constraints=[],
            expires_at=now + 3600,
        )
        with self.assertRaises(mc.MandateError):
            mc.close_mandate(
                open_mandate=open_m, cnf_secret=evil_sec,
                action={"type": "x"}, verifier_id="v", nonce=os.urandom(16),
            )

    def test_budget_enforced_with_usage_context(self):
        issuer_sec, _ = _keypair()
        cnf_sec, cnf_pub = _keypair()
        now = int(time.time())
        open_m = mc.issue_open(
            issuer_secret=issuer_sec,
            delegate_to_did="did:northstar:x",
            cnf_pubkey=cnf_pub,
            constraints=[
                {"type": mc.C_ACTION_ALLOW, "actions": ["tool.exec"]},
                {"type": mc.C_BUDGET_MAX_SPEND, "amount": 100, "currency": "CNY"},
            ],
            expires_at=now + 3600,
        )
        ctx = mc.UsageContext(spent={"CNY": 95.0})
        closed = mc.close_mandate(
            open_mandate=open_m, cnf_secret=cnf_sec,
            action={"type": "tool.exec", "cost": 10}, verifier_id="v",
            nonce=os.urandom(16),
        )
        v = mc.verify_closed(
            closed_mandate=closed, open_mandate=open_m, ctx=ctx, now=now
        )
        self.assertFalse(v.ok)
        self.assertIn("budget exceeded", v.violations[0])


if __name__ == "__main__":
    unittest.main()
