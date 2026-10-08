"""Crypto Defense 02: Cosign verification (mock), Simulated.

Mock Cosign: verify artifact signatures against expected signer identity.
Real Cosign verifies container image signatures.
This is an interface mock, NOT real Cosign.

What this IS: identity-bound verification API.
What this IS NOT: real signature verification.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import secrets
from typing Dict

#: Module version.
CRYPTO_DEFENSE_02_VERSION = "crypto-defense-02.v1"
SCHEMA_PIN = "northstar.crypto-defense-02.v1"


class CosignError(Exception):
    """Fail-closed."""


class MockCosign:
    """Mock Cosign verifier."""

    def __init__(self) -> None:
        self._identities: Dict[str, bytes] = {}  # identity -> key

    def register_identity(self, identity: str) -> None:
        """Register a signer identity."""
        if not identity:
            raise CosignError("identity required")
        self._identities[identity] = secrets.token_bytes(32)

    def sign(self, artifact: bytes, identity: str) -> bytes:
        """Sign artifact as identity (mock)."""
        if identity not in self._identities:
            raise CosignError(f"unknown identity '{identity}'")
        sig = hmac.new(
            self._identities[identity], artifact, hashlib.sha256
        ).hexdigest()
        return f"{identity}:{sig}".encode()

    def verify(
        self, artifact: bytes, signature: bytes, expected_identity: str
    ) -> bool:
        """Verify artifact was signed by expected_identity."""
        if expected_identity not in self._identities:
            return False
        try:
            parts = signature.decode().split(":", 1)
            if len(parts) != 2:
                return False
            sig_identity, sig_hex = parts
            # Must match expected identity (not just any valid sig).
            if sig_identity != expected_identity:
                return False
            expected = hmac.new(
                self._identities[expected_identity],
                artifact,
                hashlib.sha256,
            ).hexdigest()
            return hmac.compare_digest(sig_hex, expected)
        except Exception:
            return False


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "hashlib", "hmac", "pathlib", "secrets", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    c = MockCosign()
    c.register_identity("alice@example.com")
    c.register_identity("bob@example.com")
    art = b"container-image"
    sig = c.sign(art, "alice@example.com")
    assert c.verify(art, sig, "alice@example.com") is True
    # Wrong expected identity: fail even though sig is valid.
    assert c.verify(art, sig, "bob@example.com") is False
    assert c.verify(b"tampered", sig, "alice@example.com") is False
    assert stdlib_only()
    print("crypto-defense-02 OK")


if __name__ == "__main__":
    main()
