"""ASI07 corpus tests: multi-agent attack probes vs the gate.

Each probe from asi07_corpus.py is executed as a concrete gate interaction.
Adversarial probes must be denied; benign controls must be allowed.
"""

from __future__ import annotations

import unittest

from asi07_corpus import ASI07_BENIGN, ASI07_PROBES, ASI07_VERSION


class Asi07ProbeTests(unittest.TestCase):
    def test_supervisor_impersonate_denied(self):
        from permissions import PermissionConfig, PermissionEngine

        engine = PermissionEngine(PermissionConfig(mode="default"))
        verdict = engine.check_delegation(
            "supervisor",
            ("Read",),
            kinds={"Read": "read"},
            require_stable_identity=True,
        )
        self.assertFalse(verdict.ok)

    def test_confused_deputy_denied(self):
        from permissions import PermissionConfig, PermissionEngine

        # Subagent approved for Read only; attacker asks it to Write.
        engine = PermissionEngine(PermissionConfig(mode="default"))
        verdict = engine.check_delegation(
            "did:example:subagent",
            ("Read", "Write"),
            kinds={"Read": "read", "Write": "edit"},
            disallowed_extra=("Write",),
            require_stable_identity=True,
        )
        self.assertFalse(verdict.ok)
        self.assertEqual(verdict.denied[0][0], "Write")

    def test_collusion_induce_denied(self):
        from permissions import (
            CompositionRule,
            PermissionConfig,
            PermissionEngine,
        )

        engine = PermissionEngine(
            PermissionConfig(mode="default", can_use_tool=lambda n, p, c: True),
            tool_kinds={"ReadSecrets": "read", "SendEmail": "read"},
            composition_rules=[
                CompositionRule(sequence=("read_sensitive", "external_send"))
            ],
            tool_categories={
                "ReadSecrets": "read_sensitive",
                "SendEmail": "external_send",
            },
        )
        # Agent 1 reads; agent 2 (colluding) sends.
        d1 = engine.evaluate("ReadSecrets", kind="read", payload={})
        self.assertTrue(d1.allowed)
        d2 = engine.evaluate("SendEmail", kind="read", payload={})
        self.assertFalse(d2.allowed)
        self.assertEqual(d2.rule, "composition:forbidden_sequence")

    def test_trust_message_replay_denied(self):
        from ed25519 import public_key as ed_pubkey
        from permissions import mint_delegation_token, verify_delegation_token

        seed = bytes(32)
        pubkey = ed_pubkey(seed)
        token = mint_delegation_token(
            delegator_id="did:example:alice",
            delegatee_id="did:example:bob",
            tools=("Read",),
            delegator_seed=seed,
            ttl_seconds=300.0,
            issued_at=1000.0,
        )
        # Replay after expiry.
        self.assertFalse(verify_delegation_token(token, pubkey, now=2000.0))

    def test_agent_card_spoof_denied(self):
        from permissions import _is_stable_agent_identity

        # A spoofed card with a display name is not a stable identity.
        self.assertFalse(_is_stable_agent_identity("trusted-agent"))
        self.assertFalse(_is_stable_agent_identity("supervisor"))

    def test_benign_delegation_allowed(self):
        from permissions import PermissionConfig, PermissionEngine

        engine = PermissionEngine(PermissionConfig(mode="default"))
        verdict = engine.check_delegation(
            "did:example:legit-agent",
            ("Read",),
            kinds={"Read": "read"},
            require_stable_identity=True,
        )
        self.assertTrue(verdict.ok)

    def test_benign_token_chain_allowed(self):
        from ed25519 import public_key as ed_pubkey
        from permissions import (
            mint_delegation_token,
            verify_delegation_token,
        )

        seed = bytes(32)
        pubkey = ed_pubkey(seed)
        parent = mint_delegation_token(
            delegator_id="did:example:alice",
            delegatee_id="did:example:bob",
            tools=("Read", "Grep"),
            delegator_seed=seed,
            issued_at=1000.0,
        )
        child = mint_delegation_token(
            delegator_id="did:example:bob",
            delegatee_id="did:example:carol",
            tools=("Read",),
            delegator_seed=seed,
            parent_token=parent,
            issued_at=1000.0,
        )
        self.assertTrue(
            verify_delegation_token(
                child, pubkey, now=1100.0,
                expected_parent_hash=parent.token_hash(),
            )
        )

    def test_corpus_metadata(self):
        self.assertEqual(ASI07_VERSION, "asi07.v1")
        self.assertEqual(len(ASI07_PROBES), 8)
        self.assertEqual(len(ASI07_BENIGN), 2)


if __name__ == "__main__":
    unittest.main()
