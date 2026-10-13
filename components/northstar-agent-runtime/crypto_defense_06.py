"""Crypto Defense 06: MPC for keys (mock), Simulated.

Mock MPC: split a key into N parts, require M parts to perform
an operation.  No single party ever holds the full key.
This is an interface mock, NOT real MPC.

What this IS: split-key operation API.
What this IS NOT: real secure multi-party computation.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import secrets
from typing import List

#: Module version.
CRYPTO_DEFENSE_06_VERSION = "crypto-defense-06.v1"
SCHEMA_PIN = "northstar.crypto-defense-06.v1"


class MpcError(Exception):
    """Fail-closed."""


class MockMpcKey:
    """A key split across N parties (mock)."""

    def __init__(self, n_parties: int = 3, threshold: int = 2) -> None:
        if not 1 < threshold <= n_parties:
            raise MpcError("1 < threshold <= n_parties required")
        self.n_parties = n_parties
        self.threshold = threshold
        # Split: n-1 random, last = key ^ all.
        self._key = secrets.token_bytes(32)
        self._shares = [secrets.token_bytes(32) for _ in range(n_parties - 1)]
        last = self._key
        for s in self._shares:
            last = bytes(a ^ b for a, b in zip(last, s))
        self._shares.append(last)

    def party_sign(
        self, party_idx: int, data: bytes
    ) -> bytes:
        """One party contributes to signing (mock)."""
        if not 0 <= party_idx < self.n_parties:
            raise MpcError("bad party index")
        if not isinstance(data, bytes):
            raise MpcError("data must be bytes")
        return hmac.new(
            self._shares[party_idx], data, hashlib.sha256
        ).digest()

    def combine_signatures(
        self, partials: List[bytes], data: bytes
    ) -> bytes:
        """Combine threshold partials into final signature (mock)."""
        if len(partials) < self.threshold:
            raise MpcError(
                f"need {self.threshold} partials, got {len(partials)}"
            )
        # Mock: XOR partials together (NOT real).
        result = partials[0]
        for p in partials[1:]:
            result = bytes(a ^ b for a, b in zip(result, p))
        return result

    def verify_combined(
        self, combined: bytes, data: bytes, partials: List[bytes]
    ) -> bool:
        """Verify combined signature (mock: recompute)."""
        try:
            expected = self.combine_signatures(partials, data)
            return hmac.compare_digest(combined, expected)
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
    mpc = MockMpcKey(n_parties=3, threshold=2)
    data = b"sign me"
    p0 = mpc.party_sign(0, data)
    p1 = mpc.party_sign(1, data)
    combined = mpc.combine_signatures([p0, p1], data)
    assert mpc.verify_combined(combined, data, [p0, p1]) is True
    # Not enough partials.
    try:
        mpc.combine_signatures([p0], data)
        raise AssertionError("should raise")
    except MpcError:
        pass
    # Bad party.
    try:
        mpc.party_sign(99, data)
        raise AssertionError("should raise")
    except MpcError:
        pass
    assert stdlib_only()
    print("crypto-defense-06 OK")


if __name__ == "__main__":
    main()
