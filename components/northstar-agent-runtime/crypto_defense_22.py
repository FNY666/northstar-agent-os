"""Crypto Defense 22: WebAuthn (mock), Simulated.

Mock WebAuthn registration and authentication ceremonies.
Registration binds a credential id to a user.  Authentication checks
origin, challenge freshness, and monotonic signature counter
(cloned authenticators are detected).

What this IS: WebAuthn ceremony verification API.
What this IS NOT: real CBOR/COSE parsing or authenticator hardware.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Set

#: Module version.
CRYPTO_DEFENSE_22_VERSION = "crypto-defense-22.v1"
SCHEMA_PIN = "northstar.crypto-defense-22.v1"


class WebAuthnError(Exception):
    """Fail-closed."""


@dataclass
class Credential:
    """Registered credential (mock)."""

    cred_id: str
    user_id: str
    key: bytes  # mock private key (server stores verifier)
    sign_count: int = 0


@dataclass(frozen=True)
class Assertion:
    """Authentication assertion (mock)."""

    cred_id: str
    challenge: str
    origin: str
    sign_count: int
    mac: str


class MockWebAuthn:
    """Mock WebAuthn relying party."""

    def __init__(self, rp_id: str, origin: str) -> None:
        if not rp_id or not origin:
            raise WebAuthnError("rp_id and origin required")
        self._rp_id = rp_id
        self._origin = origin
        self._creds: Dict[str, Credential] = {}
        self._challenges: Set[str] = set()
        self._last_seen: Dict[str, int] = {}

    def register(self, user_id: str) -> Credential:
        """Registration ceremony: create a credential for a user."""
        if not user_id:
            raise WebAuthnError("user_id required")
        cred = Credential(
            cred_id=secrets.token_hex(16),
            user_id=user_id,
            key=secrets.token_bytes(32),
        )
        self._creds[cred.cred_id] = cred
        self._last_seen[cred.cred_id] = 0
        return cred

    def start_authentication(self, user_id: str) -> str:
        """Issue a fresh challenge for a user with a credential."""
        if not any(c.user_id == user_id for c in self._creds.values()):
            raise WebAuthnError("no credential for user")
        ch = secrets.token_hex(16)
        self._challenges.add(ch)
        return ch

    def make_assertion(
        self, cred: Credential, challenge: str, origin: str
    ) -> Assertion:
        """Authenticator side (mock): sign the challenge."""
        cred.sign_count += 1
        body = f"{challenge}|{origin}|{cred.sign_count}".encode()
        mac = hmac.new(cred.key, body, hashlib.sha256).hexdigest()
        return Assertion(cred.cred_id, challenge, origin, cred.sign_count, mac)

    def verify_assertion(self, assertion: Assertion) -> bool:
        """Verify: origin, fresh challenge, MAC, monotonic counter."""
        if not isinstance(assertion, Assertion):
            return False
        if assertion.origin != self._origin:
            return False
        if assertion.challenge not in self._challenges:
            return False  # stale or forged challenge
        cred = self._creds.get(assertion.cred_id)
        if cred is None:
            return False
        body = f"{assertion.challenge}|{assertion.origin}|{assertion.sign_count}".encode()
        mac = hmac.new(cred.key, body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, assertion.mac):
            return False
        if assertion.sign_count <= self._last_seen.get(assertion.cred_id, 0):
            return False  # cloned authenticator: counter not increasing
        self._last_seen[assertion.cred_id] = assertion.sign_count
        self._challenges.discard(assertion.challenge)
        return True


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
    rp = MockWebAuthn("example.com", "https://example.com")
    cred = rp.register("alice")
    ch = rp.start_authentication("alice")
    a = rp.make_assertion(cred, ch, "https://example.com")
    assert rp.verify_assertion(a) is True
    # Wrong origin: fails.
    rp2 = MockWebAuthn("example.com", "https://example.com")
    cred2 = rp2.register("bob")
    ch2 = rp2.start_authentication("bob")
    bad = rp2.make_assertion(cred2, ch2, "https://evil.com")
    assert rp2.verify_assertion(bad) is False
    # Replay (challenge consumed): fails.
    assert rp.verify_assertion(a) is False
    assert stdlib_only()
    print("crypto-defense-22 OK")


if __name__ == "__main__":
    main()
