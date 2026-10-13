"""Crypto Defense 24: OIDC integration (mock), Simulated.

Mock OpenID Connect provider: issues ID tokens (header.payload.sig
with HMAC), validates issuer, audience, expiry, and nonce.

What this IS: OIDC ID-token issue/validate API.
What this IS NOT: real discovery, JWKS, or asymmetric signatures.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

#: Module version.
CRYPTO_DEFENSE_24_VERSION = "crypto-defense-24.v1"
SCHEMA_PIN = "northstar.crypto-defense-24.v1"


class OidcError(Exception):
    """Fail-closed."""


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


@dataclass(frozen=True)
class IdToken:
    """Parsed ID token claims."""

    iss: str
    sub: str
    aud: str
    exp: int
    iat: int
    nonce: str


class MockOIDCProvider:
    """Mock OIDC identity provider."""

    def __init__(self, issuer: str, ttl: int = 3600) -> None:
        if not issuer:
            raise OidcError("issuer required")
        self._issuer = issuer
        self._ttl = ttl
        self._key = secrets.token_bytes(32)

    def issue(
        self, sub: str, aud: str, nonce: str, extra: Optional[Dict[str, Any]] = None
    ) -> str:
        """Issue an ID token."""
        if not sub or not aud or not nonce:
            raise OidcError("sub, aud, nonce required")
        now = int(time.time())
        payload: Dict[str, Any] = {
            "iss": self._issuer,
            "sub": sub,
            "aud": aud,
            "exp": now + self._ttl,
            "iat": now,
            "nonce": nonce,
        }
        if extra:
            payload.update(extra)
        header = _b64e(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        body = _b64e(json.dumps(payload, sort_keys=True).encode())
        sig = hmac.new(self._key, f"{header}.{body}".encode(), hashlib.sha256).digest()
        return f"{header}.{body}.{_b64e(sig)}"

    def validate(self, token: str, aud: str, nonce: str) -> Optional[IdToken]:
        """Validate an ID token. Returns claims or None."""
        try:
            header_b, body_b, sig_b = token.split(".")
            expected = hmac.new(
                self._key, f"{header_b}.{body_b}".encode(), hashlib.sha256
            ).digest()
            if not hmac.compare_digest(expected, _b64d(sig_b)):
                return None
            payload = json.loads(_b64d(body_b))
            now = int(time.time())
            if payload.get("iss") != self._issuer:
                return None
            if payload.get("aud") != aud:
                return None
            if payload.get("nonce") != nonce:
                return None
            if int(payload.get("exp", 0)) <= now:
                return None
            return IdToken(
                iss=payload["iss"],
                sub=payload["sub"],
                aud=payload["aud"],
                exp=int(payload["exp"]),
                iat=int(payload["iat"]),
                nonce=payload["nonce"],
            )
        except Exception:
            return None


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__",
        "ast",
        "base64",
        "dataclasses",
        "hashlib",
        "hmac",
        "json",
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
    op = MockOIDCProvider("https://idp.example.com")
    tok = op.issue("user-1", "client-a", "n-123")
    claims = op.validate(tok, "client-a", "n-123")
    assert claims is not None and claims.sub == "user-1"
    # Wrong audience.
    assert op.validate(tok, "client-b", "n-123") is None
    # Wrong nonce.
    assert op.validate(tok, "client-a", "n-999") is None
    # Tampered payload.
    parts = tok.split(".")
    evil = _b64e(json.dumps({"iss": "x", "sub": "root"}).encode())
    assert op.validate(f"{parts[0]}.{evil}.{parts[2]}", "client-a", "n-123") is None
    # Expired.
    op2 = MockOIDCProvider("https://idp.example.com", ttl=-1)
    tok2 = op2.issue("u", "a", "n")
    assert op2.validate(tok2, "a", "n") is None
    assert stdlib_only()
    print("crypto-defense-24 OK")


if __name__ == "__main__":
    main()
