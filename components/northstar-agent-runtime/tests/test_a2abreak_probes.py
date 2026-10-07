"""A2ABreak-derived probe tests: multi-hop identity loss, unattested
capability claims, and scope amplification vs the gate.

Each probe from a2abreak_probes.py is executed as a concrete gate
interaction. Adversarial probes must be denied; benign controls must be
allowed.
"""

from __future__ import annotations

import unittest

from a2abreak_probes import A2ABREAK_BENIGN, A2ABREAK_PROBES, A2ABREAK_VERSION


class A2abreakCorpusTests(unittest.TestCase):
    def test_corpus_shape(self):
        families = {p["family"] for p in A2ABREAK_PROBES}
        self.assertEqual(
            families,
            {
                "multi-hop-identity-loss",
                "unattested-capability-claims",
                "scope-amplification",
            },
        )
        self.assertGreaterEqual(len(A2ABREAK_PROBES), 6)
        self.assertEqual(len(A2ABREAK_BENIGN), 2)

    # ---- Family 1: multi-hop identity loss ---------------------------

    def _mint_token(self, tools, audience, parent_token=None, delegator_seed=None):
        from ed25519 import public_key as ed_pubkey
        from permissions import mint_delegation_token

        seed = bytes(32) if delegator_seed is None else delegator_seed
        pubkey = ed_pubkey(seed)
        token = mint_delegation_token(
            delegator_id="did:example:alice",
            delegatee_id="did:example:bob",
            tools=tools,
            delegator_seed=seed,
            ttl_seconds=3600.0,
            issued_at=1000.0,
            audience=audience,
            parent_token=parent_token,
        )
        return token, pubkey, seed

    def test_hop_audience_swap_denied(self):
        from permissions import verify_delegation_token

        token, pubkey, _ = self._mint_token(("Read",), audience="agent-B")
        # Agent C presents the token minted for agent B: the presenter is
        # bound, not the holder.
        self.assertFalse(
            verify_delegation_token(token, pubkey, now=1200.0, expected_audience="agent-C")
        )
        # Control: the intended presenter is accepted.
        self.assertTrue(
            verify_delegation_token(token, pubkey, now=1200.0, expected_audience="agent-B")
        )

    def test_hop_scope_growth_denied(self):
        parent, _, seed = self._mint_token(("Read",), audience="agent-B")
        from permissions import mint_delegation_token

        # Mint-time attenuation: a child may not exceed its parent's tools.
        with self.assertRaises(ValueError):
            mint_delegation_token(
                delegator_id="did:example:bob",
                delegatee_id="did:example:carol",
                tools=("Read", "Write"),
                delegator_seed=seed,
                ttl_seconds=3600.0,
                issued_at=1000.0,
                audience="agent-C",
                parent_token=parent,
            )

    def test_hop_parent_hash_continuity_denied(self):
        from ed25519 import public_key as ed_pubkey
        from permissions import mint_delegation_token, verify_delegation_token

        seed = bytes(32)
        pubkey = ed_pubkey(seed)
        root_a = mint_delegation_token(
            delegator_id="did:example:alice",
            delegatee_id="did:example:bob",
            tools=("Read", "Write"),
            delegator_seed=seed,
            ttl_seconds=3600.0,
            issued_at=1000.0,
        )
        # Attacker signs a child claiming a DIFFERENT parent's hash while
        # the verifier expects continuity with root_a.
        rogue = mint_delegation_token(
            delegator_id="did:example:bob",
            delegatee_id="did:example:carol",
            tools=("Read",),
            delegator_seed=seed,
            ttl_seconds=3600.0,
            issued_at=1000.0,
            parent_token=None,  # parent_hash = "" -- not root_a
        )
        self.assertFalse(
            verify_delegation_token(
                rogue,
                pubkey,
                now=1200.0,
                expected_parent_hash=root_a.token_hash(),
            )
        )
        # Control: a genuine child verifies against its real parent hash.
        genuine = mint_delegation_token(
            delegator_id="did:example:bob",
            delegatee_id="did:example:carol",
            tools=("Read",),
            delegator_seed=seed,
            ttl_seconds=3600.0,
            issued_at=1000.0,
            parent_token=root_a,
        )
        self.assertTrue(
            verify_delegation_token(
                genuine,
                pubkey,
                now=1200.0,
                expected_parent_hash=root_a.token_hash(),
            )
        )

    # ---- Family 2: unattested capability claims ---------------------

    def test_capability_claim_inflation_denied(self):
        from permissions import PermissionConfig, PermissionEngine

        # The host granted only Read; the peer's card claims Admin too.
        engine = PermissionEngine(PermissionConfig(mode="default"))
        verdict = engine.check_delegation(
            "did:example:peer",
            ("Read", "Admin"),
            kinds={"Read": "read", "Admin": "edit"},
            disallowed_extra=("Admin",),
            require_stable_identity=True,
        )
        self.assertIn("Read", verdict.allowed)
        self.assertEqual(verdict.denied[0][0], "Admin")
        self.assertFalse(any(a == "Admin" for a in verdict.allowed))

    def test_unattested_card_display_name_denied(self):
        from permissions import PermissionConfig, PermissionEngine

        # A card signed with a display name claiming privileged tools.
        engine = PermissionEngine(PermissionConfig(mode="default"))
        verdict = engine.check_delegation(
            "admin-agent",
            ("Read", "Admin"),
            kinds={"Read": "read", "Admin": "edit"},
            require_stable_identity=True,
        )
        self.assertEqual(verdict.allowed, ())
        self.assertEqual(
            [t for t, _ in verdict.denied], ["Read", "Admin"]
        )

    # ---- Family 3: scope amplification -------------------------------

    def _scoped_engine(self, config):
        from permissions import PermissionEngine, ScopeManager

        mgr = ScopeManager()
        engine = PermissionEngine(config, scope_manager=mgr)
        return engine, mgr

    def test_ceiling_creep_fail_closed(self):
        from permissions import (
            PermissionConfig,
            PermissionEngine,
            PermissionRequestContext,
        )

        engine, mgr = self._scoped_engine(PermissionConfig(mode="default"))
        mgr.open_scope("phase-1", capabilities=("Read",))
        ctx = PermissionRequestContext(scope_id="phase-1")
        decision = engine.evaluate("Write", kind="edit", context=ctx)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.rule, "ceiling:needs_approval")

    def test_ceiling_ascent_does_not_persist(self):
        from permissions import (
            PermissionConfig,
            PermissionEngine,
            PermissionRequestContext,
        )

        calls = []

        def host_callback(tool, payload, context):
            calls.append(tool)
            return True  # host approves this one call

        engine, mgr = self._scoped_engine(
            PermissionConfig(mode="default", can_use_tool=host_callback)
        )
        mgr.open_scope("phase-1", capabilities=("Read",))
        ctx = PermissionRequestContext(scope_id="phase-1")
        first = engine.evaluate("Write", kind="edit", context=ctx)
        self.assertTrue(first.allowed)
        self.assertEqual(first.rule, "ceiling:ascent_approved")
        # The ceiling is NOT raised by the approval...
        self.assertEqual(
            mgr.ceiling("phase-1"), frozenset({"Read"})
        )
        # ...so the next call asks the host again.
        second = engine.evaluate("Write", kind="edit", context=ctx)
        self.assertTrue(second.allowed)
        self.assertEqual(calls, ["Write", "Write"])

    # ---- Benign controls ---------------------------------------------

    def test_benign_chained_delegation(self):
        from ed25519 import public_key as ed_pubkey
        from permissions import mint_delegation_token, verify_delegation_token

        seed = bytes(32)
        pubkey = ed_pubkey(seed)
        root = mint_delegation_token(
            delegator_id="did:example:alice",
            delegatee_id="did:example:bob",
            tools=("Read", "Write"),
            delegator_seed=seed,
            ttl_seconds=3600.0,
            issued_at=1000.0,
            audience="agent-B",
        )
        child = mint_delegation_token(
            delegator_id="did:example:bob",
            delegatee_id="did:example:carol",
            tools=("Read",),  # shrinks across the hop
            delegator_seed=seed,
            ttl_seconds=1800.0,
            issued_at=1000.0,
            audience="agent-C",
            parent_token=root,
        )
        self.assertTrue(
            verify_delegation_token(
                child,
                pubkey,
                now=1200.0,
                expected_parent_hash=root.token_hash(),
                expected_audience="agent-C",
            )
        )

    def test_benign_within_ceiling(self):
        from permissions import (
            PermissionConfig,
            PermissionEngine,
            PermissionRequestContext,
        )

        engine, mgr = self._scoped_engine(PermissionConfig(mode="default"))
        mgr.open_scope("phase-1", capabilities=("Read",))
        ctx = PermissionRequestContext(scope_id="phase-1")
        decision = engine.evaluate("Read", kind="read", context=ctx)
        self.assertTrue(decision.allowed)


if __name__ == "__main__":
    unittest.main()
