"""Crypto helpers: HMAC-SHA256, PBKDF2, salts. What this IS: message auth and password hashing. What this IS NOT: not public-key crypto."""

from __future__ import annotations

import ast
import hashlib
import hmac
import secrets

#: Module version.
UTIL_12_VERSION = "util-12.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-12.v1"


class CryptoError(Exception):
    """Crypto helper failure."""


def hmac_sha256_hex(key: bytes, msg: bytes) -> str:
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def verify_hmac(key: bytes, msg: bytes, expected_hex: str) -> bool:
    return hmac.compare_digest(hmac_sha256_hex(key, msg), expected_hex.lower())


def pbkdf2_hex(password: str, salt: bytes, iterations=100_000) -> str:
    if iterations <= 0:
        raise CryptoError("iterations must be positive")
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations).hex()


def new_salt(nbytes=16) -> bytes:
    if nbytes <= 0:
        raise CryptoError("nbytes must be positive")
    return secrets.token_bytes(nbytes)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'hashlib', 'hmac', 'pathlib', 'secrets']
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
    """Self-check."""
    assert hmac_sha256_hex(b"key", b"The quick brown fox jumps over the lazy dog") == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
    mac = hmac_sha256_hex(b"k", b"m")
    assert verify_hmac(b"k", b"m", mac) is True
    assert verify_hmac(b"k", b"m", "00" * 32) is False
    assert len(pbkdf2_hex("pw", b"salt", iterations=1000)) == 64
    assert len(new_salt(16)) == 16
    print("crypto helpers OK")


if __name__ == "__main__":
    main()
