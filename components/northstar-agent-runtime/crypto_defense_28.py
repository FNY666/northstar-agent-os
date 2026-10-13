"""Crypto Defense 28: Token binding (mock), Simulated.

Binds an access token to a client key: the binder MACs (token, key_id)
with a server secret.  A presenter must prove possession of the bound
key; presenting the token with a different key fails.

What this IS: proof-of-possession binding for bearer tokens.
What this IS NOT: real TLS token binding (RFC 8471) or mTLS.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import secrets
from dataclasses import dataclass

#: Module version.
CRYPTO_DEFENSE_28_VERSION = "crypto-defense-28.v1"
SCHEMA_PIN = "northstar.crypto-defense-28.v1"


class BindingError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class BoundToken:
    """A token bound to a client key id."""

    token: str
    key_id: str
    binding: str  # hex MAC over token|key_id


class TokenBinder:
    """Binds tokens to client keys (mock)."""

    def __init__(self) -> None:
        self._secret = secrets.token_bytes(32)

    def bind(self, token: str, key_id: str) -> BoundToken:
        """Bind a token to a client key id."""
        if not token or not key_id:
            raise BindingError("token and key_id required")
        binding = hmac.new(
            self._secret, f"{token}|{key_id}".encode(), hashlib.sha256
        ).hexdigest()
        return BoundToken(token, key_id, binding)

    def verify(self, bound: BoundToken, key_id: str) -> bool:
        """Verify the binding AND that the presenter holds key_id."""
        if not isinstance(bound, BoundToken):
            return False
        expected = hmac.new(
            self._secret, f"{bound.token}|{bound.key_id}".encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, bound.binding):
            return False
        # Presenter must prove the bound key.
        return hmac.compare_digest(bound.key_id, key_id)


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
    binder = TokenBinder()
    bound = binder.bind("access-token-xyz", "client-key-1")
    assert binder.verify(bound, "client-key-1") is True
    # Wrong key: fails.
    assert binder.verify(bound, "client-key-2") is False
    # Tampered token: fails.
    tampered = BoundToken("access-token-EVIL", bound.key_id, bound.binding)
    assert binder.verify(tampered, "client-key-1") is False
    assert stdlib_only()
    print("crypto-defense-28 OK")


if __name__ == "__main__":
    main()
