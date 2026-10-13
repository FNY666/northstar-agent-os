"""Crypto Defense 27: JWT validation (mock with HMAC), Simulated.

Mock JWT: base64url(header).base64url(payload).HMAC-SHA256.
Validates signature, expiry (exp), not-before (nbf), issuer, audience,
and rejects alg=none and algorithm confusion.

What this IS: JWT encode/decode/validate API.
What this IS NOT: real RSA/ECDSA or JWKS verification.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

#: Module version.
CRYPTO_DEFENSE_27_VERSION = "crypto-defense-27.v1"
SCHEMA_PIN = "northstar.crypto-defense-27.v1"


class JwtError(Exception):
    """Fail-closed."""


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


@dataclass(frozen=True)
class JwtClaims:
    """Validated claims."""

    claims: Dict[str, Any]


def encode(payload: Dict[str, Any], key: bytes) -> str:
    """Encode a JWT with HS256."""
    if not isinstance(key, bytes) or not key:
        raise JwtError("key required")
    header = _b64e(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64e(json.dumps(payload, sort_keys=True).encode())
    sig = hmac.new(key, f"{header}.{body}".encode(), hashlib.sha256).digest()
    return f"{header}.{body}.{_b64e(sig)}"


def decode(
    token: str,
    key: bytes,
    *,
    issuer: Optional[str] = None,
    audience: Optional[str] = None,
    leeway: int = 0,
) -> JwtClaims:
    """Decode and validate. Raises JwtError on any failure."""
    if not isinstance(token, str):
        raise JwtError("token must be str")
    parts = token.split(".")
    if len(parts) != 3:
        raise JwtError("malformed token")
    header_b, body_b, sig_b = parts
    try:
        header = json.loads(_b64d(header_b))
    except Exception:
        raise JwtError("bad header")
    # Reject alg=none and algorithm confusion.
    if header.get("alg") != "HS256":
        raise JwtError(f"unsupported alg: {header.get('alg')}")
    expected = hmac.new(key, f"{header_b}.{body_b}".encode(), hashlib.sha256).digest()
    try:
        sig = _b64d(sig_b)
    except Exception:
        raise JwtError("bad signature encoding")
    if not hmac.compare_digest(expected, sig):
        raise JwtError("bad signature")
    try:
        payload = json.loads(_b64d(body_b))
    except Exception:
        raise JwtError("bad payload")
    now = int(time.time())
    if "exp" in payload and int(payload["exp"]) <= now - leeway:
        raise JwtError("token expired")
    if "nbf" in payload and int(payload["nbf"]) > now + leeway:
        raise JwtError("token not yet valid")
    if issuer is not None and payload.get("iss") != issuer:
        raise JwtError("bad issuer")
    if audience is not None and payload.get("aud") != audience:
        raise JwtError("bad audience")
    return JwtClaims(claims=payload)


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
    key = b"test-key-32-bytes-long..........."
    now = int(time.time())
    tok = encode(
        {"sub": "u1", "iss": "idp", "aud": "api", "exp": now + 3600},
        key,
    )
    claims = decode(tok, key, issuer="idp", audience="api")
    assert claims.claims["sub"] == "u1"
    # Tampered signature.
    try:
        decode(tok[:-2] + "AA", key)
        raise AssertionError("should raise")
    except JwtError:
        pass
    # Expired.
    old = encode({"sub": "u1", "exp": now - 10}, key)
    try:
        decode(old, key)
        raise AssertionError("should raise")
    except JwtError as e:
        assert "expired" in str(e)
    # alg=none rejected.
    header = _b64e(json.dumps({"alg": "none"}).encode())
    body = _b64e(json.dumps({"sub": "u1"}).encode())
    try:
        decode(f"{header}.{body}.", key)
        raise AssertionError("should raise")
    except JwtError as e:
        assert "alg" in str(e)
    assert stdlib_only()
    print("crypto-defense-27 OK")


if __name__ == "__main__":
    main()
