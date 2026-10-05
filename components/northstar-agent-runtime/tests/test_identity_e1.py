"""Tests for E.1 identity additions: manifest + challenge-response."""

from __future__ import annotations

import hashlib
import os
import time
import unittest

import support  # noqa: F401 — sys.path bootstrap

import agent_identity as ai
import ed25519


def _keypair() -> tuple[bytes, bytes]:
    secret = os.urandom(32)
    return secret, ed25519.public_key(secret)


class ManifestTests(unittest.TestCase):
    def test_build_and_verify_manifest(self):
        issuer = ai.IdentityIssuer(root_secret=os.urandom(32))
        ident, _secret = issuer.issue(agent="test-agent", role="worker")
        manifest = ai.build_manifest(
            ident,
            name="test",
            trust=("action-card", "mandate"),
            services=[{"protocol": "a2a", "endpoint": "https://x", "version": "1"}],
        )
        self.assertEqual(manifest.to_dict()["format"], ai.MANIFEST_VERSION)
        self.assertTrue(manifest.active)
        self.assertIn("action-card", manifest.trust)
        self.assertEqual(manifest.did, ident.did)

    def test_inactive_manifest_rejected(self):
        _, pub = _keypair()
        m = ai.IdentityManifest(did=ai.did_of(pub), active=False)
        self.assertFalse(ai.verify_manifest(m, b"\x00" * 64, public_key=pub))


class ChallengeResponseTests(unittest.TestCase):
    def test_roundtrip(self):
        secret, pub = _keypair()
        stmt = hashlib.sha256(b"hello").digest()
        nonce = os.urandom(32)
        now = int(time.time())
        chal = ai.create_challenge(
            statement_hash=stmt, nonce=nonce, expiry=now + 300
        )
        sig = ed25519.sign(secret, chal)
        self.assertTrue(
            ai.verify_challenge_response(
                public_key=pub, challenge=chal, signature=sig, now=now
            )
        )

    def test_expired_rejected(self):
        secret, pub = _keypair()
        chal = ai.create_challenge(
            statement_hash=hashlib.sha256(b"x").digest(),
            nonce=os.urandom(32),
            expiry=int(time.time()) - 1,
        )
        sig = ed25519.sign(secret, chal)
        self.assertFalse(
            ai.verify_challenge_response(
                public_key=pub, challenge=chal, signature=sig,
                now=int(time.time()),
            )
        )

    def test_wrong_key_rejected(self):
        secret, pub = _keypair()
        _, other_pub = _keypair()
        chal = ai.create_challenge(
            statement_hash=hashlib.sha256(b"x").digest(),
            nonce=os.urandom(32),
            expiry=int(time.time()) + 300,
        )
        sig = ed25519.sign(secret, chal)
        self.assertFalse(
            ai.verify_challenge_response(
                public_key=other_pub, challenge=chal, signature=sig,
                now=int(time.time()),
            )
        )

    def test_tampered_challenge_rejected(self):
        secret, pub = _keypair()
        chal = ai.create_challenge(
            statement_hash=hashlib.sha256(b"x").digest(),
            nonce=os.urandom(32),
            expiry=int(time.time()) + 300,
        )
        sig = ed25519.sign(secret, chal)
        # Tamper the challenge AFTER signing: signature no longer matches.
        tampered = bytearray(chal)
        tampered[-1] ^= 0xFF
        self.assertFalse(
            ai.verify_challenge_response(
                public_key=pub, challenge=bytes(tampered), signature=sig,
                now=int(time.time()),
            )
        )


if __name__ == "__main__":
    unittest.main()
