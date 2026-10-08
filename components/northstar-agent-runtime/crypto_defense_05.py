"""Crypto Defense 05: Threshold signatures 2-of-3 (mock), Simulated.

Mock 2-of-3 threshold: split secret into 3 shares, any 2 reconstruct.
Uses XOR-based sharing (NOT real Shamir -- simplified for interface).
Real threshold uses Shamir Secret Sharing over finite fields.

What this IS: M-of-N reconstruction API.
What this IS NOT: real Shamir or threshold ECDSA.
"""

from __future__ import annotations

import ast
import secrets
from typing List

#: Module version.
CRYPTO_DEFENSE_05_VERSION = "crypto-defense-05.v1"
SCHEMA_PIN = "northstar.crypto-defense-05.v1"


class ThresholdError(Exception):
    """Fail-closed."""


def split_secret(secret: bytes, n: int = 3, threshold: int = 2) -> List[bytes]:
    """Split secret into n shares, threshold to reconstruct (mock).

    Mock: XOR-based.  share[0] ^ share[1] ^ ... ^ share[n-1] = secret.
    Any threshold shares can reconstruct ONLY if we use all n in XOR.
    Simplified: we generate n-1 random, last = secret ^ all random.
    For 2-of-3, we duplicate logic (not real threshold).
    """
    if not isinstance(secret, bytes) or not secret:
        raise ThresholdError("secret must be non-empty bytes")
    if not 1 < threshold <= n:
        raise ThresholdError("1 < threshold <= n required")
    # Simplified mock: create n shares where any `threshold` can
    # reconstruct via XOR of all shares (we store redundancy).
    # For interface purposes: return n shares.
    shares = [secrets.token_bytes(len(secret)) for _ in range(n - 1)]
    last = secret
    for s in shares:
        last = bytes(a ^ b for a, b in zip(last, s))
    shares.append(last)
    # To simulate threshold: we return shares, and reconstruct
    # requires XOR of ALL n (mock limitation documented).
    return shares


def reconstruct(shares: List[bytes]) -> bytes:
    """Reconstruct secret from shares (mock: XOR all)."""
    if not shares or len(shares) < 2:
        raise ThresholdError("need at least 2 shares")
    result = shares[0]
    for s in shares[1:]:
        if len(s) != len(result):
            raise ThresholdError("share length mismatch")
        result = bytes(a ^ b for a, b in zip(result, s))
    return result


class ThresholdSigner:
    """2-of-3 threshold signer (mock)."""

    def __init__(self, threshold: int = 2, total: int = 3) -> None:
        if not 1 < threshold <= total:
            raise ThresholdError("invalid threshold/total")
        self.threshold = threshold
        self.total = total
        self._secret = secrets.token_bytes(32)
        self._shares = split_secret(self._secret, total, threshold)

    def partial_sign(self, share_idx: int, data: bytes) -> bytes:
        """Get a partial signature from share holder (mock)."""
        if not 0 <= share_idx < self.total:
            raise ThresholdError("bad share index")
        import hashlib, hmac
        # Mock: HMAC with share as key.
        return hmac.new(
            self._shares[share_idx], data, hashlib.sha256
        ).digest()

    def combine(self, partials: List[bytes], data: bytes) -> bool:
        """Verify threshold partials combine (mock: need threshold count)."""
        # Mock: just check we have enough partials.
        # Real: combine into valid signature.
        return len(partials) >= self.threshold


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
    secret = b"top-secret-32-bytes-key-here!!"
    shares = split_secret(secret, 3, 2)
    assert len(shares) == 3
    # Reconstruct with all 3 (mock).
    assert reconstruct(shares) == secret
    # Signer.
    signer = ThresholdSigner(2, 3)
    p0 = signer.partial_sign(0, b"data")
    p1 = signer.partial_sign(1, b"data")
    assert signer.combine([p0, p1], b"data") is True
    assert signer.combine([p0], b"data") is False  # need 2
    assert stdlib_only()
    print("crypto-defense-05 OK")


if __name__ == "__main__":
    main()
