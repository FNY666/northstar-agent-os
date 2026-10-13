"""Crypto Defense 23: Passkeys (mock), Simulated.

Passkeys = WebAuthn credentials synced across a user's devices.
Devices can be added and revoked; authentication works from any
enrolled device but fails after revocation.

What this IS: multi-device passkey lifecycle API.
What this IS NOT: real iCloud/Google sync or CTAP.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

#: Module version.
CRYPTO_DEFENSE_23_VERSION = "crypto-defense-23.v1"
SCHEMA_PIN = "northstar.crypto-defense-23.v1"


class PasskeyError(Exception):
    """Fail-closed."""


@dataclass
class Device:
    """One synced device holding the passkey."""

    device_id: str
    key: bytes
    revoked: bool = False


@dataclass
class Passkey:
    """A passkey synced across devices."""

    passkey_id: str
    user_id: str
    devices: Dict[str, Device] = field(default_factory=dict)


class MockPasskeyManager:
    """Mock passkey provider."""

    def __init__(self, rp_id: str) -> None:
        if not rp_id:
            raise PasskeyError("rp_id required")
        self._rp_id = rp_id
        self._passkeys: Dict[str, Passkey] = {}
        self._nonces: Dict[str, float] = {}

    def create_passkey(self, user_id: str, device_id: str) -> Passkey:
        """Create a passkey on the first device."""
        if not user_id or not device_id:
            raise PasskeyError("user_id and device_id required")
        pk = Passkey(
            passkey_id=secrets.token_hex(16),
            user_id=user_id,
        )
        pk.devices[device_id] = Device(device_id, secrets.token_bytes(32))
        self._passkeys[pk.passkey_id] = pk
        return pk

    def add_device(self, passkey_id: str, device_id: str) -> None:
        """Sync the passkey to another device (new key share)."""
        pk = self._passkeys.get(passkey_id)
        if pk is None:
            raise PasskeyError("unknown passkey")
        if device_id in pk.devices:
            raise PasskeyError("device already enrolled")
        pk.devices[device_id] = Device(device_id, secrets.token_bytes(32))

    def revoke_device(self, passkey_id: str, device_id: str) -> None:
        pk = self._passkeys.get(passkey_id)
        if pk is None or device_id not in pk.devices:
            raise PasskeyError("unknown passkey/device")
        pk.devices[device_id].revoked = True

    def challenge(self, passkey_id: str) -> str:
        if passkey_id not in self._passkeys:
            raise PasskeyError("unknown passkey")
        nonce = secrets.token_hex(16)
        self._nonces[nonce] = time.time()
        return nonce

    def authenticate(
        self, passkey_id: str, device_id: str, nonce: str
    ) -> Optional[str]:
        """Authenticate with a device; returns assertion MAC or None."""
        pk = self._passkeys.get(passkey_id)
        if pk is None:
            return None
        dev = pk.devices.get(device_id)
        if dev is None or dev.revoked:
            return None
        if nonce not in self._nonces:
            return None
        body = f"{nonce}|{device_id}|{passkey_id}".encode()
        assertion = hmac.new(dev.key, body, hashlib.sha256).hexdigest()
        del self._nonces[nonce]
        return assertion

    def verify(
        self, passkey_id: str, device_id: str, nonce: str, assertion: str
    ) -> bool:
        pk = self._passkeys.get(passkey_id)
        if pk is None:
            return False
        dev = pk.devices.get(device_id)
        if dev is None or dev.revoked:
            return False
        body = f"{nonce}|{device_id}|{passkey_id}".encode()
        expected = hmac.new(dev.key, body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, assertion)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__",
        "ast",
        "dataclasses",
        "hashlib",
        "hmac",
        "pathlib",
        "secrets",
        "time",
        "typing",
    }
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
    mgr = MockPasskeyManager("example.com")
    pk = mgr.create_passkey("alice", "phone")
    mgr.add_device(pk.passkey_id, "laptop")
    # Auth from either device.
    n1 = mgr.challenge(pk.passkey_id)
    a1 = mgr.authenticate(pk.passkey_id, "phone", n1)
    assert a1 is not None and mgr.verify(pk.passkey_id, "phone", n1, a1) is True
    n2 = mgr.challenge(pk.passkey_id)
    a2 = mgr.authenticate(pk.passkey_id, "laptop", n2)
    assert a2 is not None and mgr.verify(pk.passkey_id, "laptop", n2, a2) is True
    # Revoke laptop: auth fails.
    mgr.revoke_device(pk.passkey_id, "laptop")
    n3 = mgr.challenge(pk.passkey_id)
    assert mgr.authenticate(pk.passkey_id, "laptop", n3) is None
    assert stdlib_only()
    print("crypto-defense-23 OK")


if __name__ == "__main__":
    main()
