"""Chain-walking cascade revocation for DelegationToken.

Research consensus (mandatum V8, UCAN, adtp): the verifier must walk
leaf->root via parent_hash and check revocation for EVERY link, not just
the leaf. A revoked ancestor kills the whole subtree.

Every test mints fresh tokens; the chain is root -> mid -> leaf unless
noted. ``now=1100.0`` with ``issued_at=1000.0`` keeps all tokens inside
their own time windows so failures isolate the property under test.
"""

import dataclasses
import json
import unittest


def _keypairs(n):
    from ed25519 import public_key as ed_pubkey

    seeds = [bytes([i + 1]) * 32 for i in range(n)]
    return [(s, ed_pubkey(s)) for s in seeds]


def _resign(token, seed):
    """Re-sign a (possibly modified) token with the given seed."""
    from ed25519 import sign as ed_sign
    from permissions import DelegationToken

    body = json.dumps(token._signing_body(), sort_keys=True).encode()
    sig = ed_sign(bytes(seed), body).hex()
    return DelegationToken(**{**token.__dict__, "signature": sig})


class DelegationChainTests(unittest.TestCase):
    def _chain(self, leaf_ttl=3600.0):
        from permissions import mint_delegation_token

        keys = _keypairs(3)
        root = mint_delegation_token(
            delegator_id="did:example:alice",
            delegatee_id="did:example:bob",
            tools=("Read", "Write"),
            delegator_seed=keys[0][0],
            issued_at=1000.0,
        )
        mid = mint_delegation_token(
            delegator_id="did:example:bob",
            delegatee_id="did:example:carol",
            tools=("Read",),
            delegator_seed=keys[1][0],
            parent_token=root,
            issued_at=1000.0,
        )
        leaf = mint_delegation_token(
            delegator_id="did:example:carol",
            delegatee_id="did:example:dave",
            tools=("Read",),
            delegator_seed=keys[2][0],
            parent_token=mid,
            issued_at=1000.0,
            ttl_seconds=leaf_ttl,
        )
        store = {t.token_hash(): t for t in (root, mid, leaf)}
        pubkeys = {
            "did:example:alice": keys[0][1],
            "did:example:bob": keys[1][1],
            "did:example:carol": keys[2][1],
        }
        return keys, root, mid, leaf, store, pubkeys

    def _verify(self, leaf, store, pubkeys, **kw):
        from permissions import verify_delegation_chain

        kw.setdefault("now", 1100.0)
        return verify_delegation_chain(
            leaf,
            public_key_for=lambda did: pubkeys.get(did),
            chain_resolver=lambda h: store.get(h),
            **kw,
        )

    def test_valid_chain_passes(self):
        _, _, _, leaf, store, pubkeys = self._chain()
        self.assertTrue(self._verify(leaf, store, pubkeys))

    def test_revoked_parent_kills_child(self):
        """Cascade: revoking mid invalidates the leaf presented below it."""
        _, _, mid, leaf, store, pubkeys = self._chain()
        revoked = {mid.token_hash()}
        oracle = lambda tok: tok.token_hash() in revoked
        self.assertFalse(self._verify(leaf, store, pubkeys, revocation_oracle=oracle))

    def test_revoked_grandparent_kills_grandchild(self):
        """Cascade reaches past one hop: revoking the root kills the leaf."""
        _, root, _, leaf, store, pubkeys = self._chain()
        revoked = {root.token_hash()}
        oracle = lambda tok: tok.token_hash() in revoked
        self.assertFalse(self._verify(leaf, store, pubkeys, revocation_oracle=oracle))

    def test_revoked_leaf_fails(self):
        _, _, _, leaf, store, pubkeys = self._chain()
        revoked = {leaf.token_hash()}
        oracle = lambda tok: tok.token_hash() in revoked
        self.assertFalse(self._verify(leaf, store, pubkeys, revocation_oracle=oracle))

    def test_unrelated_revocation_does_not_kill_chain(self):
        _, _, _, leaf, store, pubkeys = self._chain()
        oracle = lambda tok: tok.token_hash() == "deadbeef"
        self.assertTrue(self._verify(leaf, store, pubkeys, revocation_oracle=oracle))

    def test_unresolvable_ancestor_fails_closed(self):
        """The resolver cannot produce the parent: fail, do not skip."""
        _, _, _, leaf, store, pubkeys = self._chain()
        partial = {leaf.token_hash(): leaf}  # mid/root missing
        from permissions import verify_delegation_chain

        ok = verify_delegation_chain(
            leaf,
            public_key_for=lambda did: pubkeys.get(did),
            chain_resolver=lambda h: partial.get(h),
            now=1100.0,
        )
        self.assertFalse(ok)

    def test_child_expiry_exceeds_parent_fails(self):
        """A child must not outlive its parent (attenuation in time)."""
        _, _, _, leaf, store, pubkeys = self._chain(leaf_ttl=7200.0)
        # leaf.exp = 8200 > root/mid exp = 4600; every token is inside its
        # own window at now=1100, so only the link invariant can fail.
        self.assertFalse(self._verify(leaf, store, pubkeys))

    def test_max_depth_respected(self):
        _, _, _, leaf, store, pubkeys = self._chain()
        # Chain depths are 0/1/2.
        self.assertFalse(self._verify(leaf, store, pubkeys, max_depth=1))
        self.assertTrue(self._verify(leaf, store, pubkeys, max_depth=2))

    def test_wrong_token_from_resolver_fails(self):
        """Resolver returns a token whose hash does not match: fail closed."""
        keys, root, mid, leaf, store, pubkeys = self._chain()
        # Poison the store: mid's slot holds the root token instead.
        store[mid.token_hash()] = root
        self.assertFalse(self._verify(leaf, store, pubkeys))

    def test_cycle_fails_closed(self):
        """A <-> B via parent_hash links: the seen-set must stop the walk."""
        keys, _, mid, leaf, _, pubkeys = self._chain()
        # Build a 2-cycle with valid signatures: leaf4.parent_hash == hash(mid4)
        # and mid4.parent_hash == hash(leaf4). Both links resolve and verify;
        # only the cycle guard can stop the walk.
        mid4 = _resign(dataclasses.replace(mid, parent_hash="placeholder"), keys[1][0])
        leaf4 = _resign(
            dataclasses.replace(leaf, parent_hash=mid4.token_hash()), keys[2][0]
        )
        mid4 = _resign(
            dataclasses.replace(mid4, parent_hash=leaf4.token_hash()), keys[1][0]
        )
        leaf4 = _resign(
            dataclasses.replace(leaf4, parent_hash=mid4.token_hash()), keys[2][0]
        )
        cyc = {mid4.token_hash(): mid4, leaf4.token_hash(): leaf4}
        from permissions import verify_delegation_chain

        ok = verify_delegation_chain(
            leaf4,
            public_key_for=lambda did: pubkeys.get(did),
            chain_resolver=lambda h: cyc.get(h),
            now=1100.0,
        )
        self.assertFalse(ok)

    def test_single_token_api_escalates_with_resolver(self):
        """verify_delegation_token walks the chain when given a resolver."""
        from permissions import verify_delegation_token

        keys, _, mid, leaf, store, pubkeys = self._chain()
        revoked = {mid.token_hash()}
        oracle = lambda tok: tok.token_hash() in revoked
        # With resolver: revoked parent kills the leaf (chain semantics).
        self.assertFalse(
            verify_delegation_token(
                leaf,
                keys[2][1],
                now=1100.0,
                revocation_oracle=oracle,
                chain_resolver=lambda h: store.get(h),
                public_key_for=lambda did: pubkeys.get(did),
            )
        )
        # Without resolver: legacy single-token behavior is preserved --
        # the leaf alone verifies (documenting the pre-chain semantics).
        self.assertTrue(
            verify_delegation_token(
                leaf, keys[2][1], now=1100.0, revocation_oracle=oracle
            )
        )

    def test_unknown_ancestor_key_fails_closed(self):
        _, _, _, leaf, store, _ = self._chain()
        from permissions import verify_delegation_chain

        ok = verify_delegation_chain(
            leaf,
            public_key_for=lambda did: None,  # no keys known
            chain_resolver=lambda h: store.get(h),
            now=1100.0,
        )
        self.assertFalse(ok)

    def test_oracle_error_fails_closed(self):
        _, _, _, leaf, store, pubkeys = self._chain()

        def bad_oracle(tok):
            raise RuntimeError("oracle down")

        self.assertFalse(
            self._verify(leaf, store, pubkeys, revocation_oracle=bad_oracle)
        )


if __name__ == "__main__":
    unittest.main()
