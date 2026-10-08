"""Crypto Defense 30: mTLS client certs (mock), Simulated.

Mock mutual TLS: a CA issues client certificates (subject, serial,
validity window, key binding, CA MAC).  The server handshake verifies
the CA signature, the validity window, and a revocation list.

What this IS: client-certificate issuance + handshake verification API.
What this IS NOT: real X.509 parsing or TLS handshake.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Dict, Optional, Set

#: Module version.
CRYPTO_DEFENSE_30_VERSION = "crypto-defense-30.v1"
SCHEMA_PIN = "northstar.crypto-defense-30.v1"


class MtlsError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class ClientCert:
    """Mock client certificate."""

    subject: str
    serial: str
    pubkey_hash: str  # sha256 hex binding the client key
    not_before: int
    not_after: int
    ca_mac: str  # CA signature over the fields


class MockCA:
    """Mock certificate authority."""

    def __init__(self, name: str = "northstar-mock-ca") -> None:
        self._name = name
        self._ca_key = secrets.token_bytes(32)

    def issue(
        self, subject: str, pubkey_hash: str, ttl: int = 86400
    ) -> ClientCert:
        """Issue a client certificate."""
        if not subject or not pubkey_hash:
            raise MtlsError("subject and pubkey_hash required")
        now = int(time.time())
        serial = secrets.token_hex(8)
        not_before, not_after = now - 60, now + ttl
        body = (
            f"{subject}|{serial}|{pubkey_hash}|{not_before}|{not_after}"
        ).encode()
        mac = hmac.new(self._ca_key, body, hashlib.sha256).hexdigest()
        return ClientCert(
            subject=subject,
            serial=serial,
            pubkey_hash=pubkey_hash,
            not_before=not_before,
            not_after=not_after,
            ca_mac=mac,
        )

    def ca_key(self) -> bytes:
        return self._ca_key


class MockMTLSServer:
    """Server side of the mock mTLS handshake."""

    def __init__(self, ca: MockCA) -> None:
        self._ca_key = ca.ca_key()
        self._revoked: Set[str] = set()

    def revoke(self, serial: str) -> None:
        self._revoked.add(serial)

    def handshake(self, cert: ClientCert, proof_key_hash: str) -> bool:
        """Verify cert chain, window, revocation, and key possession."""
        if not isinstance(cert, ClientCert):
            return False
        body = (
            f"{cert.subject}|{cert.serial}|{cert.pubkey_hash}|"
            f"{cert.not_before}|{cert.not_after}"
        ).encode()
        mac = hmac.new(self._ca_key, body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, cert.ca_mac):
            return False  # not issued by our CA
        now = int(time.time())
        if not (cert.not_before <= now <= cert.not_after):
            return False
        if cert.serial in self._revoked:
            return False
        # Proof of possession: presenter must hold the bound key.
        return hmac.compare_digest(cert.pubkey_hash, proof_key_hash)


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
    ca = MockCA()
    srv = MockMTLSServer(ca)
    key_hash = hashlib.sha256(b"client-key").hexdigest()
    cert = ca.issue("service-a", key_hash)
    assert srv.handshake(cert, key_hash) is True
    # Wrong key: fails proof of possession.
    assert srv.handshake(cert, hashlib.sha256(b"other").hexdigest()) is False
    # Revoked.
    srv.revoke(cert.serial)
    assert srv.handshake(cert, key_hash) is False
    # Expired.
    cert2 = ca.issue("service-b", key_hash, ttl=-1)
    assert srv.handshake(cert2, key_hash) is False
    assert stdlib_only()
    print("crypto-defense-30 OK")


if __name__ == "__main__":
    main()
