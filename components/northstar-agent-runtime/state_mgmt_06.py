"""State 06: mock KMS for key management, Simulated.

Mock KMS: creates, versions, rotates, and revokes data keys.
- create_key(alias) -> key_id (v1)
- rotate(alias) -> key_id (v2); old versions stay decryptable
- encrypt(alias, plaintext) uses latest version
- decrypt(key_id, token) picks the right version
- revoke(alias) blocks future encrypts; decrypts still allowed

Fail-closed: unknown key_id, revoked alias, empty plaintext raise.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import hmac
import os
from typing import Dict, Tuple

MODULE_VERSION = "state-mgmt-06.v1"
SCHEMA_PIN = "northstar.state-mgmt-06.v1"


class KMSError(Exception):
    pass


def _ks(key: bytes, nonce: bytes, n: int) -> bytes:
    out, c = b"", 0
    while len(out) < n:
        out += hmac.new(key, nonce + c.to_bytes(8, "big"), hashlib.sha256).digest()
        c += 1
    return out[:n]


class MockKMS:
    def __init__(self) -> None:
        self._versions: Dict[str, Dict[int, bytes]] = {}
        self._revoked: set = set()

    def create_key(self, alias: str) -> str:
        if not alias:
            raise KMSError("alias required")
        if alias in self._versions:
            raise KMSError(f"alias {alias!r} already exists")
        self._versions[alias] = {1: os.urandom(32)}
        return f"{alias}:v1"

    def rotate(self, alias: str) -> str:
        vers = self._versions.get(alias)
        if vers is None:
            raise KMSError(f"unknown alias {alias!r}")
        if alias in self._revoked:
            raise KMSError(f"alias {alias!r} revoked")
        v = max(vers) + 1
        vers[v] = os.urandom(32)
        return f"{alias}:v{v}"

    def revoke(self, alias: str) -> None:
        if alias not in self._versions:
            raise KMSError(f"unknown alias {alias!r}")
        self._revoked.add(alias)

    def _latest(self, alias: str) -> Tuple[int, bytes]:
        vers = self._versions.get(alias)
        if vers is None:
            raise KMSError(f"unknown alias {alias!r}")
        if alias in self._revoked:
            raise KMSError(f"alias {alias!r} revoked")
        v = max(vers)
        return v, vers[v]

    def _by_id(self, key_id: str) -> bytes:
        try:
            alias, vs = key_id.rsplit(":v", 1)
            v = int(vs)
        except ValueError:
            raise KMSError(f"bad key_id {key_id!r}")
        vers = self._versions.get(alias)
        if vers is None or v not in vers:
            raise KMSError(f"unknown key_id {key_id!r}")
        return vers[v]

    def encrypt(self, alias: str, plaintext: bytes) -> str:
        if not isinstance(plaintext, bytes) or not plaintext:
            raise KMSError("plaintext must be non-empty bytes")
        v, key = self._latest(alias)
        nonce = os.urandom(16)
        ct = bytes(a ^ b for a, b in zip(plaintext, _ks(key, nonce, len(plaintext))))
        tag = hmac.new(key, nonce + ct, hashlib.sha256).digest()
        token = base64.urlsafe_b64encode(nonce + tag + ct).decode()
        return f"{alias}:v{v}:{token}"

    def decrypt(self, token: str) -> bytes:
        parts = token.split(":", 2)
        if len(parts) != 3:
            raise KMSError("malformed token")
        alias, vs, b64 = parts
        key = self._by_id(f"{alias}:{vs}")
        try:
            blob = base64.urlsafe_b64decode(b64.encode())
        except Exception as e:
            raise KMSError(f"bad encoding: {e}")
        nonce, tag, ct = blob[:16], blob[16:48], blob[48:]
        if not hmac.compare_digest(tag, hmac.new(key, nonce + ct, hashlib.sha256).digest()):
            raise KMSError("tag mismatch")
        return bytes(a ^ b for a, b in zip(ct, _ks(key, nonce, len(ct))))


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "base64", "hashlib", "hmac", "os", "pathlib", "typing"}
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
    kms = MockKMS()
    kid1 = kms.create_key("ledger")
    t1 = kms.encrypt("ledger", b"hello")
    assert kms.decrypt(t1) == b"hello"
    # Rotate: old token still decrypts, new encrypts use v2.
    kid2 = kms.rotate("ledger")
    assert kid1 != kid2
    t2 = kms.encrypt("ledger", b"world")
    assert kms.decrypt(t1) == b"hello"
    assert kms.decrypt(t2) == b"world"
    assert t2.split(":")[1] == "v2"
    # Revoke blocks encrypt, not decrypt.
    kms.revoke("ledger")
    try:
        kms.encrypt("ledger", b"x")
        raise AssertionError("should raise")
    except KMSError:
        pass
    assert kms.decrypt(t2) == b"world"
    # Unknown alias
    try:
        kms.encrypt("nope", b"x")
        raise AssertionError("should raise")
    except KMSError:
        pass
    assert stdlib_only()
    print("state_mgmt_06 OK: create/rotate/revoke, versioned decrypt, fail-closed")


if __name__ == "__main__":
    main()
