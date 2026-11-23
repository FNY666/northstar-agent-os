"""Crypto Defense 29: DPoP (mock), Simulated.

Demonstrating Proof of Possession (RFC 9449, mock): the client signs a
DPoP proof JWT over the HTTP method + URL with its key.  The server
validates the proof is bound to the request, the jti is fresh
(replay cache), and iat is within the freshness window.

What this IS: DPoP proof creation/validation API.
What this IS NOT: real JWK/JWS or EC keys.
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
from typing import Dict, Set

#: Module version.
CRYPTO_DEFENSE_29_VERSION = "crypto-defense-29.v1"
SCHEMA_PIN = "northstar.crypto-defense-29.v1"


class DPoPError(Exception):
    """Fail-closed."""


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


@dataclass
class DPoPKey:
    """Client DPoP key (mock)."""

    key_id: str
    secret: bytes


class DPoPServer:
    """Validates DPoP proofs."""

    def __init__(self, freshness: int = 300) -> None:
        self._freshness = freshness
        self._seen_jtis: Set[str] = set()
        self._keys: Dict[str, bytes] = {}

    def register_key(self, key: DPoPKey) -> None:
        self._keys[key.key_id] = key.secret

    def make_proof(self, key: DPoPKey, method: str, url: str) -> str:
        """Client side: build a DPoP proof for a request."""
        if not method or not url:
            raise DPoPError("method and url required")
        header = _b64e(
            json.dumps(
                {"typ": "dpop+jwt", "alg": "HS256", "jwk": {"kid": key.key_id}}
            ).encode()
        )
        body = _b64e(
            json.dumps(
                {
                    "htm": method.upper(),
                    "htu": url,
                    "iat": int(time.time()),
                    "jti": secrets.token_hex(12),
                },
                sort_keys=True,
            ).encode()
        )
        sig = hmac.new(
            key.secret, f"{header}.{body}".encode(), hashlib.sha256
        ).digest()
        return f"{header}.{body}.{_b64e(sig)}"

    def validate(self, proof: str, method: str, url: str) -> bool:
        """Server side: validate proof bound to this request."""
        try:
            header_b, body_b, sig_b = proof.split(".")
            header = json.loads(_b64d(header_b))
            if header.get("typ") != "dpop+jwt":
                return False
            kid = header.get("jwk", {}).get("kid")
            secret = self._keys.get(kid)
            if secret is None:
                return False
            expected = hmac.new(
                secret, f"{header_b}.{body_b}".encode(), hashlib.sha256
            ).digest()
            if not hmac.compare_digest(expected, _b64d(sig_b)):
                return False
            payload = json.loads(_b64d(body_b))
            if payload.get("htm") != method.upper():
                return False
            if payload.get("htu") != url:
                return False
            now = int(time.time())
            if abs(now - int(payload.get("iat", 0))) > self._freshness:
                return False
            jti = payload.get("jti")
            if not jti or jti in self._seen_jtis:
                return False  # replay
            self._seen_jtis.add(jti)
            return True
        except Exception:
            return False


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
    srv = DPoPServer()
    key = DPoPKey("k1", secrets.token_bytes(32))
    srv.register_key(key)
    proof = srv.make_proof(key, "POST", "https://api.example.com/token")
    assert srv.validate(proof, "POST", "https://api.example.com/token") is True
    # Replay: same proof again fails.
    assert srv.validate(proof, "POST", "https://api.example.com/token") is False
    # Wrong URL binding.
    proof2 = srv.make_proof(key, "POST", "https://api.example.com/token")
    assert srv.validate(proof2, "POST", "https://api.example.com/other") is False
    # Wrong method binding.
    proof3 = srv.make_proof(key, "GET", "https://api.example.com/token")
    assert srv.validate(proof3, "POST", "https://api.example.com/token") is False
    assert stdlib_only()
    print("crypto-defense-29 OK")


if __name__ == "__main__":
    main()
