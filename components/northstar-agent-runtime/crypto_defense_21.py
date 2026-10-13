"""Crypto Defense 21: Biometric auth (mock), Simulated.

Enrollment stores a template hash.  Authentication compares a fresh
sample against the template with a distance threshold, and requires a
liveness signal.  Missing liveness is fail-closed.

What this IS: template matching + liveness-gated auth API.
What this IS NOT: real biometric sensors or matching algorithms.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import secrets

#: Module version.
CRYPTO_DEFENSE_21_VERSION = "crypto-defense-21.v1"
SCHEMA_PIN = "northstar.crypto-defense-21.v1"


class BiometricError(Exception):
    """Fail-closed."""


def _distance(a: bytes, b: bytes) -> int:
    """Mock template distance: count of differing bytes."""
    n = max(len(a), len(b))
    aa = a.ljust(n, b"\x00")
    bb = b.ljust(n, b"\x00")
    return sum(1 for x, y in zip(aa, bb) if x != y)


class MockBiometric:
    """Mock biometric authenticator."""

    def __init__(self, threshold: int = 4) -> None:
        if threshold < 0:
            raise BiometricError("threshold must be non-negative")
        self._threshold = threshold
        self._template: bytes | None = None
        self._salt = secrets.token_bytes(16)

    def enroll(self, sample: bytes) -> str:
        """Enroll a biometric sample. Returns template id."""
        if not isinstance(sample, bytes) or not sample:
            raise BiometricError("sample must be non-empty bytes")
        self._template = bytes(sample)
        tid = hashlib.sha256(self._salt + sample).hexdigest()[:16]
        return tid

    def authenticate(self, sample: bytes, *, liveness: bool) -> bool:
        """Authenticate; liveness signal is mandatory."""
        if self._template is None:
            raise BiometricError("no template enrolled")
        if not liveness:
            raise BiometricError("liveness check required")
        if not isinstance(sample, bytes) or not sample:
            return False
        return _distance(sample, self._template) <= self._threshold


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "hashlib", "hmac", "pathlib", "secrets", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    bio = MockBiometric(threshold=2)
    tid = bio.enroll(b"fingerprint-template-001")
    assert tid
    # Genuine sample (1 byte differs): accepted.
    assert bio.authenticate(b"fingerprint-template-002", liveness=True) is True
    # Impostor: rejected.
    assert bio.authenticate(b"totally-different-person!!", liveness=True) is False
    # No liveness: fail-closed.
    try:
        bio.authenticate(b"fingerprint-template-001", liveness=False)
        raise AssertionError("should raise")
    except BiometricError:
        pass
    assert stdlib_only()
    print("crypto-defense-21 OK")


if __name__ == "__main__":
    main()
