"""Crypto Defense 01: Sigstore interface (mock), Simulated.

Mock Sigstore: sign artifacts with a key ID, verify against the key ID.
Real Sigstore uses Fulcio short-lived certs + Rekor transparency log.
This is an interface mock for integration testing, NOT real Sigstore.

What this IS: sign/verify API shape.
What this IS NOT: real cryptographic signatures.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import secrets
from typing import Dict

#: Module version.
CRYPTO_DEFENSE_01_VERSION = "crypto-defense-01.v1"
SCHEMA_PIN = "northstar.crypto-defense-01.v1"


class SigstoreError(Exception):
    """Fail-closed."""


class MockSigstore:
    """Mock Sigstore signer/verifier."""

    def __init__(self) -> None:
        self._keys: Dict[str, bytes] = {}

    def register_key(self, key_id: str) -> str:
        """Register a new signing key. Returns key_id."""
        if not key_id:
            raise SigstoreError("key_id required")
        self._keys[key_id] = secrets.token_bytes(32)
        return key_id

    def sign(self, data: bytes, key_id: str) -> bytes:
        """Sign data with key_id. Returns signature."""
        if not isinstance(data, bytes):
            raise SigstoreError("data must be bytes")
        if key_id not in self._keys:
            raise SigstoreError(f"unknown key_id '{key_id}'")
        # Mock: HMAC-SHA256 (NOT real Sigstore).
        sig = hmac.new(self._keys[key_id], data, hashlib.sha256).digest()
        # Prepend key_id for verification routing (mock).
        return key_id.encode() + b":" + sig.hex().encode()

    def verify(self, data: bytes, signature: bytes, key_id: str) -> bool:
        """Verify signature. Returns True/False (never raises on bad sig)."""
        if not isinstance(data, bytes) or not isinstance(signature, bytes):
            return False
        if key_id not in self._keys:
            return False
        try:
            parts = signature.split(b":", 1)
            if len(parts) != 2:
                return False
            sig_key_id, sig_hex = parts
            if sig_key_id.decode() != key_id:
                return False
            expected = hmac.new(
                self._keys[key_id], data, hashlib.sha256
            ).hexdigest()
            return hmac.compare_digest(sig_hex.decode(), expected)
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
    s = MockSigstore()
    s.register_key("key1")
    data = b"artifact"
    sig = s.sign(data, "key1")
    assert s.verify(data, sig, "key1") is True
    assert s.verify(b"tampered", sig, "key1") is False
    assert s.verify(data, sig, "wrong_key") is False
    assert s.verify(data, b"bad", "key1") is False
    assert stdlib_only()
    print("crypto-defense-01 OK")


if __name__ == "__main__":
    main()
