"""Verify-time depth limit for DelegationToken.

Regression coverage for the abaxxlabs/agents v0.12.5 lesson: a depth limit
enforced only at issuance is bypassable -- the verifier must enforce it
itself. Every test mints fresh tokens; depth is signature-bound, so a
forged shallower depth breaks the signature.
"""

import json
import unittest


def _keys():
    from ed25519 import public_key as ed_pubkey

    seeds = [bytes([i + 1]) * 32 for i in range(4)]
    return [(s, ed_pubkey(s)) for s in seeds]


class DelegationDepthTests(unittest.TestCase):
    def _chain(self):
        from permissions import mint_delegation_token

        keys = _keys()
        root = mint_delegation_token(
            delegator_id="did:example:alice",
            delegatee_id="did:example:bob",
            tools=("Read", "Grep"),
            delegator_seed=keys[0][0],
            issued_at=1000.0,
        )
        child = mint_delegation_token(
            delegator_id="did:example:bob",
            delegatee_id="did:example:carol",
            tools=("Read",),
            delegator_seed=keys[1][0],
            parent_token=root,
            issued_at=1000.0,
        )
        grandchild = mint_delegation_token(
            delegator_id="did:example:carol",
            delegatee_id="did:example:dave",
            tools=("Read",),
            delegator_seed=keys[2][0],
            parent_token=child,
            issued_at=1000.0,
        )
        return keys, root, child, grandchild

    def test_root_depth_is_zero(self):
        from permissions import mint_delegation_token, verify_delegation_token

        keys, root, _, _ = self._chain()
        self.assertEqual(root.depth, 0)
        self.assertTrue(
            verify_delegation_token(root, keys[0][1], now=1100.0, max_depth=0)
        )

    def test_child_depth_increments(self):
        _, root, child, grandchild = self._chain()
        self.assertEqual((root.depth, child.depth, grandchild.depth), (0, 1, 2))

    def test_deep_chain_rejected_at_verify(self):
        """The abaxxlabs case: issuance had no limit, verifier enforces."""
        from permissions import verify_delegation_token

        keys, _, _, grandchild = self._chain()
        # grandchild is depth 2, minted with no issuance limit.
        self.assertFalse(
            verify_delegation_token(
                grandchild, keys[2][1], now=1100.0, max_depth=1
            )
        )

    def test_exact_limit_passes(self):
        from permissions import verify_delegation_token

        keys, _, child, grandchild = self._chain()
        self.assertTrue(
            verify_delegation_token(child, keys[1][1], now=1100.0, max_depth=1)
        )
        self.assertTrue(
            verify_delegation_token(
                grandchild, keys[2][1], now=1100.0, max_depth=2
            )
        )

    def test_mint_enforces_max_depth(self):
        from permissions import mint_delegation_token

        keys, root, child, _ = self._chain()
        with self.assertRaises(ValueError):
            mint_delegation_token(
                delegator_id="did:example:carol",
                delegatee_id="did:example:dave",
                tools=("Read",),
                delegator_seed=keys[2][0],
                parent_token=child,
                max_depth=1,  # child is depth 1, grandchild would be 2
                issued_at=1000.0,
            )
        # Minting at exactly the limit is fine.
        ok = mint_delegation_token(
            delegator_id="did:example:bob",
            delegatee_id="did:example:carol",
            tools=("Read",),
            delegator_seed=keys[1][0],
            parent_token=root,
            max_depth=1,
            issued_at=1000.0,
        )
        self.assertEqual(ok.depth, 1)

    def test_tampered_depth_breaks_signature(self):
        """Depth is in the signed body: re-labeling shallower voids the sig."""
        from permissions import DelegationToken, verify_delegation_token

        keys, _, _, grandchild = self._chain()
        forged = DelegationToken(**{**grandchild.__dict__, "depth": 0})
        self.assertFalse(
            verify_delegation_token(forged, keys[2][1], now=1100.0, max_depth=5)
        )

    def test_negative_depth_rejected_fail_closed(self):
        """A validly-signed negative depth is still malformed -> reject."""
        from ed25519 import sign as ed_sign
        from permissions import DelegationToken, verify_delegation_token

        keys = _keys()
        tok = DelegationToken(
            delegator_id="did:example:mallory",
            delegatee_id="did:example:dave",
            tools=("Read",),
            issued_at=1000.0,
            expires_at=4600.0,
            depth=-1,
        )
        body = json.dumps(tok._signing_body(), sort_keys=True).encode()
        sig = ed_sign(keys[3][0], body).hex()
        tok = DelegationToken(**{**tok.__dict__, "signature": sig})
        self.assertFalse(
            verify_delegation_token(tok, keys[3][1], now=1100.0, max_depth=10)
        )

    def test_legacy_verify_without_max_depth_accepts_any_depth(self):
        """Opt-in: no max_depth means the old behavior is unchanged."""
        from permissions import verify_delegation_token

        keys, _, _, grandchild = self._chain()
        self.assertTrue(
            verify_delegation_token(grandchild, keys[2][1], now=1100.0)
        )


if __name__ == "__main__":
    unittest.main()
