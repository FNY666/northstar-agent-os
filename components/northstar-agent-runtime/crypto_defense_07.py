"""Crypto Defense 07: HSM integration (mock), Simulated.

Mock HSM: keys are generated inside the HSM and never leave.
Operations (sign, decrypt) happen inside.  This is an interface
mock, NOT real HSM hardware.

What this IS: key-never-leaves API shape.
What this IS NOT: real hardware security module.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import secrets
from typing import Dict, Optional

#: Module version.
CRYPTO_DEFENSE_07_VERSION = "crypto-defense-07.v1"
SCHEMA_PIN = "northstar.crypto-defense-07.v1"


class HsmError(Exception):
    """Fail-closed."""


class MockHsm:
    """Mock Hardware Security Module."""

    def __init__(self) -> None:
        # Keys stored "inside" -- never exposed.
        self._keys: Dict[str, bytes] = {}
        self._counter = 0

    def generate_key(self, label: str) -> str:
        """Generate key inside HSM. Returns key handle (not the key)."""
        if not label:
            raise HsmError("label required")
        self._counter += 1
        handle = f"hsm-key-{self._counter}"
        self._keys[handle] = secrets.token_bytes(32)
        return handle

    def get_public_key(self, handle: str) -> bytes:
        """Get public part (mock: hash of private)."""
        if handle not in self._keys:
            raise HsmError(f"unknown handle '{handle}'")
        # Mock: public = SHA256(private) (NOT real).
        return hashlib.sha256(self._keys[handle]).digest()

    def sign(self, handle: str, data: bytes) -> bytes:
        """Sign inside HSM. Key never leaves."""
        if handle not in self._keys:
            raise HsmError(f"unknown handle '{handle}'")
        if not isinstance(data, bytes):
            raise HsmError("data must be bytes")
        return hmac.new(self._keys[handle], data, hashlib.sha256).digest()

    def verify(
        self, handle: str, data: bytes, signature: bytes
    ) -> bool:
        """Verify using HSM key."""
        try:
            expected = self.sign(handle, data)
            return hmac.compare_digest(signature, expected)
        except Exception:
            return False

    def delete_key(self, handle: str) -> None:
        """Delete key from HSM."""
        if handle not in self._keys:
            raise HsmError(f"unknown handle '{handle}'")
        # Overwrite before delete (mock zeroization).
        self._keys[handle] = b"\x00" * 32
        del self._keys[handle]

    def key_exists(self, handle: str) -> bool:
        return handle in self._keys


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
    hsm = MockHsm()
    handle = hsm.generate_key("signing-key")
    assert hsm.key_exists(handle) is True
    data = b"important"
    sig = hsm.sign(handle, data)
    assert hsm.verify(handle, data, sig) is True
    assert hsm.verify(handle, b"tampered", sig) is False
    # Public key doesn't reveal private.
    pub = hsm.get_public_key(handle)
    assert len(pub) == 32
    # Delete.
    hsm.delete_key(handle)
    assert hsm.key_exists(handle) is False
    assert stdlib_only()
    print("crypto-defense-07 OK")


if __name__ == "__main__":
    main()
