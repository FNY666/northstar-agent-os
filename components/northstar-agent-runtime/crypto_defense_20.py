"""Crypto Defense 20: Hardware tokens (mock), Simulated.

Mock FIDO-style hardware token: operations require user presence
(physical touch), the key never leaves the token, and a PIN retry
counter locks the token after too many failures.

What this IS: presence-gated signing + PIN lockout API.
What this IS NOT: real CTAP2/USB-HID hardware.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import secrets

#: Module version.
CRYPTO_DEFENSE_20_VERSION = "crypto-defense-20.v1"
SCHEMA_PIN = "northstar.crypto-defense-20.v1"


class TokenError(Exception):
    """Fail-closed."""


class MockHardwareToken:
    """Mock hardware security token."""

    def __init__(self, pin: str, max_retries: int = 3) -> None:
        if not pin:
            raise TokenError("pin required")
        if max_retries <= 0:
            raise TokenError("max_retries must be positive")
        self._pin_hash = hashlib.sha256(pin.encode()).hexdigest()
        self._max_retries = max_retries
        self._retries = 0
        self._unlocked = False
        self._key = secrets.token_bytes(32)
        self._handle = secrets.token_hex(8)

    @property
    def key_handle(self) -> str:
        return self._handle

    @property
    def is_locked(self) -> bool:
        return self._retries >= self._max_retries

    def unlock(self, pin: str) -> bool:
        """Verify PIN; locks after max_retries failures."""
        if self.is_locked:
            return False
        if hmac.compare_digest(
            hashlib.sha256(pin.encode()).hexdigest(), self._pin_hash
        ):
            self._retries = 0
            self._unlocked = True
            return True
        self._retries += 1
        return False

    def lock(self) -> None:
        self._unlocked = False

    def sign(self, data: bytes, *, user_present: bool) -> bytes:
        """Sign only when unlocked AND user presence confirmed."""
        if self.is_locked:
            raise TokenError("token locked")
        if not self._unlocked:
            raise TokenError("token not unlocked")
        if not user_present:
            raise TokenError("user presence required")
        if not isinstance(data, bytes):
            raise TokenError("data must be bytes")
        return hmac.new(self._key, data, hashlib.sha256).digest()

    def verify(self, data: bytes, sig: bytes) -> bool:
        if not isinstance(data, bytes) or not isinstance(sig, bytes):
            return False
        expected = hmac.new(self._key, data, hashlib.sha256).digest()
        return hmac.compare_digest(expected, sig)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__",
        "ast",
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
    tok = MockHardwareToken("1234")
    assert tok.unlock("1234") is True
    sig = tok.sign(b"auth-data", user_present=True)
    assert tok.verify(b"auth-data", sig) is True
    # No presence: refused.
    try:
        tok.sign(b"x", user_present=False)
        raise AssertionError("should raise")
    except TokenError:
        pass
    # PIN lockout.
    tok2 = MockHardwareToken("9999", max_retries=2)
    assert tok2.unlock("0000") is False
    assert tok2.unlock("0000") is False
    assert tok2.is_locked is True
    assert tok2.unlock("9999") is False  # locked stays locked
    assert stdlib_only()
    print("crypto-defense-20 OK")


if __name__ == "__main__":
    main()
