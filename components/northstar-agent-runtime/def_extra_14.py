"""Digital signature verification (mock), Simulated.

Verifies signatures against a registry of known public keys with an
algorithm allowlist.  The mock signature is HMAC(key_material, message);
production would use real asymmetric verify.

What this IS: key-registry + algorithm-policy enforcement.

What this IS NOT:
* Not real asymmetric crypto -- mock only.
* Unknown key, disallowed algorithm, or bad signature FAILS CLOSED.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
from dataclasses import dataclass
from typing import Dict, Tuple

#: Module version.
DEF_EXTRA_14_VERSION = "def-extra-14.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.def-extra-14.v1"


class SigVerifyError(Exception):
    """Fail-closed."""


#: Allowed signature algorithms (mock names).
ALLOWED_ALGORITHMS = frozenset({"ed25519", "ecdsa-p256", "rsa-pss"})


@dataclass(frozen=True)
class PubKey:
    """Registered public key material."""

    key_id: str
    algorithm: str
    material: bytes  # mock stand-in for the public key


class KeyRegistry:
    """Registry of trusted public keys."""

    def __init__(self) -> None:
        self._keys: Dict[str, PubKey] = {}

    def add(self, key: PubKey) -> None:
        """Register a key.  Algorithm must be allowlisted."""
        if key.algorithm not in ALLOWED_ALGORITHMS:
            raise SigVerifyError(f"algorithm not allowed: {key.algorithm}")
        if not key.key_id or not key.material:
            raise SigVerifyError("key_id and material required")
        self._keys[key.key_id] = key

    def sign_mock(self, key_id: str, message: bytes) -> Tuple[str, str]:
        """Test helper: produce a mock signature.  Returns (algorithm, sig)."""
        key = self._keys.get(key_id)
        if key is None:
            raise SigVerifyError("unknown key")
        sig = hmac.new(key.material, message, hashlib.sha256).hexdigest()
        return key.algorithm, sig

    def verify(
        self, key_id: str, message: bytes, algorithm: str, signature: str
    ) -> Tuple[bool, str]:
        """Verify a signature.  Fail closed on any problem."""
        key = self._keys.get(key_id)
        if key is None:
            return False, "unknown key"
        if algorithm not in ALLOWED_ALGORITHMS:
            return False, f"algorithm not allowed: {algorithm}"
        if algorithm != key.algorithm:
            return False, "algorithm mismatch for key"
        expected = hmac.new(key.material, message, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            return False, "bad signature"
        return True, "ok"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "hashlib", "hmac", "pathlib", "typing"}
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
    """Self-check."""
    registry = KeyRegistry()
    registry.add(PubKey("k1", "ed25519", b"pub-material-1"))
    alg, sig = registry.sign_mock("k1", b"hello")
    ok, reason = registry.verify("k1", b"hello", alg, sig)
    assert ok is True, reason
    # Tampered message fails.
    ok, _ = registry.verify("k1", b"hellx", alg, sig)
    assert ok is False
    # Unknown key fails closed.
    ok, _ = registry.verify("k9", b"hello", alg, sig)
    assert ok is False
    # Disallowed algorithm rejected at registration.
    try:
        registry.add(PubKey("k2", "md5-rsa", b"x"))
    except SigVerifyError:
        pass
    else:
        raise AssertionError("expected SigVerifyError")
    # Algorithm mismatch fails.
    ok, _ = registry.verify("k1", b"hello", "rsa-pss", sig)
    assert ok is False
    assert stdlib_only()
    print("def-extra-14 OK: registry, allowlist, verify")


if __name__ == "__main__":
    main()
