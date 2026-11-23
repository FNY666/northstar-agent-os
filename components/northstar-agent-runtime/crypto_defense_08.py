"""Crypto Defense 08: Key rotation (mock), Simulated.

Rotate keys on schedule or on demand.  Keep history for verifying
old signatures.  New signatures always use current key.

What this IS: rotation with verification history.
What this IS NOT: real key ceremony or PKI.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, List

#: Module version.
CRYPTO_DEFENSE_08_VERSION = "crypto-defense-08.v1"
SCHEMA_PIN = "northstar.crypto-defense-08.v1"


class RotationError(Exception):
    """Fail-closed."""


@dataclass
class KeyVersion:
    """One key version."""

    version: int
    key: bytes
    created_at: float
    retired_at: float = 0.0  # 0 = active


class KeyRotator:
    """Manages key rotation with history."""

    def __init__(self) -> None:
        self._versions: List[KeyVersion] = []
        self._by_version: Dict[int, KeyVersion] = {}
        self.rotate()  # initial key

    def rotate(self) -> int:
        """Rotate to new key. Returns new version number."""
        now = time.time()
        # Retire current.
        if self._versions:
            self._versions[-1].retired_at = now
        version = len(self._versions) + 1
        kv = KeyVersion(
            version=version,
            key=secrets.token_bytes(32),
            created_at=now,
        )
        self._versions.append(kv)
        self._by_version[version] = kv
        return version

    @property
    def current_version(self) -> int:
        return self._versions[-1].version

    def sign(self, data: bytes) -> bytes:
        """Sign with current key. Format: version:sig."""
        if not isinstance(data, bytes):
            raise RotationError("data must be bytes")
        kv = self._versions[-1]
        sig = hmac.new(kv.key, data, hashlib.sha256).hexdigest()
        return f"v{kv.version}:{sig}".encode()

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify with any key version (current or retired)."""
        try:
            parts = signature.decode().split(":", 1)
            if len(parts) != 2 or not parts[0].startswith("v"):
                return False
            version = int(parts[0][1:])
            sig_hex = parts[1]
            kv = self._by_version.get(version)
            if kv is None:
                return False
            expected = hmac.new(
                kv.key, data, hashlib.sha256
            ).hexdigest()
            return hmac.compare_digest(sig_hex, expected)
        except Exception:
            return False

    def versions(self) -> List[int]:
        return [kv.version for kv in self._versions]


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "hashlib", "hmac", "pathlib", "secrets", "time", "typing"}
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
    kr = KeyRotator()
    assert kr.current_version == 1
    sig1 = kr.sign(b"data")
    assert kr.verify(b"data", sig1) is True
    # Rotate.
    kr.rotate()
    assert kr.current_version == 2
    sig2 = kr.sign(b"data")
    assert kr.verify(b"data", sig2) is True
    # Old signature still verifies (history kept).
    assert kr.verify(b"data", sig1) is True
    # Tampered.
    assert kr.verify(b"bad", sig2) is False
    assert kr.versions() == [1, 2]
    assert stdlib_only()
    print("crypto-defense-08 OK")


if __name__ == "__main__":
    main()
