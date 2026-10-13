"""Crypto Defense 04: Fulcio certificates (mock), Simulated.

Mock Fulcio: issue short-lived certificates bound to identity.
Real Fulcio issues 10-minute certs via OIDC.
This is an interface mock, NOT real PKI.

What this IS: short-lived cert API with expiry enforcement.
What this IS NOT: real X.509 or CA.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Dict

#: Module version.
CRYPTO_DEFENSE_04_VERSION = "crypto-defense-04.v1"
SCHEMA_PIN = "northstar.crypto-defense-04.v1"


class FulcioError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class Certificate:
    """Short-lived certificate (mock)."""

    cert_id: str
    identity: str
    issued_at: float
    expires_at: float
    signature: str  # mock CA signature


class MockFulcio:
    """Mock certificate authority."""

    def __init__(self, default_ttl: float = 600.0) -> None:
        self._ca_key = secrets.token_bytes(32)
        self._default_ttl = default_ttl
        self._issued: Dict[str, Certificate] = {}

    def issue_cert(
        self, identity: str, ttl: float = None
    ) -> Certificate:
        """Issue short-lived cert for identity."""
        if not identity:
            raise FulcioError("identity required")
        ttl = ttl if ttl is not None else self._default_ttl
        if ttl <= 0:
            raise FulcioError("ttl must be positive")
        now = time.time()
        cert_id = secrets.token_hex(8)
        # Mock CA signature over identity+expiry.
        msg = f"{cert_id}:{identity}:{now + ttl}".encode()
        sig = hmac.new(self._ca_key, msg, hashlib.sha256).hexdigest()
        cert = Certificate(
            cert_id=cert_id,
            identity=identity,
            issued_at=now,
            expires_at=now + ttl,
            signature=sig,
        )
        self._issued[cert_id] = cert
        return cert

    def verify_cert(self, cert: Certificate) -> bool:
        """Verify cert is valid and not expired."""
        try:
            # Check CA signature.
            msg = f"{cert.cert_id}:{cert.identity}:{cert.expires_at}".encode()
            expected = hmac.new(
                self._ca_key, msg, hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(cert.signature, expected):
                return False
            # Check expiry (fail-closed on expired).
            if time.time() > cert.expires_at:
                return False
            return True
        except Exception:
            return False


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
    f = MockFulcio(default_ttl=600)
    cert = f.issue_cert("alice@example.com")
    assert f.verify_cert(cert) is True
    # Expired cert.
    expired = f.issue_cert("bob@example.com", ttl=0.01)
    time.sleep(0.02)
    assert f.verify_cert(expired) is False
    # Tampered.
    bad = Certificate(
        cert.cert_id, "eve@example.com",
        cert.issued_at, cert.expires_at, cert.signature,
    )
    assert f.verify_cert(bad) is False
    assert stdlib_only()
    print("crypto-defense-04 OK")


if __name__ == "__main__":
    main()
