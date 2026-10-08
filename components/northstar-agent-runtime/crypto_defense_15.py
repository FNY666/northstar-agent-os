"""Crypto Defense 15: Homomorphic encryption (mock), Simulated.

Mock additive homomorphic: Enc(a) + Enc(b) = Enc(a+b).
Server computes on ciphertexts without seeing plaintext.

Mock uses simple additive masking (NOT real FHE).

What this IS: homomorphic addition API.
What this IS NOT: real fully homomorphic encryption.
"""

from __future__ import annotations

import ast
import secrets
from dataclasses import dataclass

#: Module version.
CRYPTO_DEFENSE_15_VERSION = "crypto-defense-15.v1"
SCHEMA_PIN = "northstar.crypto-defense-15.v1"


class HeError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class Ciphertext:
    """Homomorphically encrypted integer (mock)."""

    value: int  # masked value
    mask_id: int  # identifies the mask used


class MockHomomorphic:
    """Mock additive homomorphic encryption."""

    def __init__(self, bit_length: int = 32) -> None:
        self._modulus = 2 ** bit_length
        # Secret mask (in real FHE, this is the secret key).
        self._mask = secrets.randbelow(self._modulus)

    def encrypt(self, plaintext: int) -> Ciphertext:
        """Encrypt integer."""
        if not isinstance(plaintext, int):
            raise HeError("plaintext must be int")
        if not 0 <= plaintext < self._modulus:
            raise HeError("plaintext out of range")
        masked = (plaintext + self._mask) % self._modulus
        return Ciphertext(value=masked, mask_id=1)

    def decrypt(self, ct: Ciphertext) -> int:
        """Decrypt."""
        if not isinstance(ct, Ciphertext):
            raise HeError("bad ciphertext")
        return (ct.value - self._mask) % self._modulus

    def add(self, a: Ciphertext, b: Ciphertext) -> Ciphertext:
        """Homomorphic addition: Enc(a) + Enc(b) = Enc(a+b)."""
        if not isinstance(a, Ciphertext) or not isinstance(b, Ciphertext):
            raise HeError("bad ciphertext")
        # (a+mask) + (b+mask) = (a+b) + 2*mask.
        # To keep single mask, subtract one mask.
        result = (a.value + b.value - self._mask) % self._modulus
        return Ciphertext(value=result, mask_id=1)

    def add_plain(self, ct: Ciphertext, plain: int) -> Ciphertext:
        """Add plaintext to ciphertext."""
        if not isinstance(plain, int):
            raise HeError("plain must be int")
        result = (ct.value + plain) % self._modulus
        return Ciphertext(value=result, mask_id=1)


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "secrets", "typing"}
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
    he = MockHomomorphic()
    ct_a = he.encrypt(10)
    ct_b = he.encrypt(20)
    # Homomorphic add.
    ct_sum = he.add(ct_a, ct_b)
    assert he.decrypt(ct_sum) == 30
    # Add plain.
    ct_c = he.add_plain(ct_a, 5)
    assert he.decrypt(ct_c) == 15
    # Roundtrip.
    assert he.decrypt(he.encrypt(42)) == 42
    # Bad input.
    try:
        he.encrypt("not-int")  # type: ignore
        raise AssertionError("should raise")
    except HeError:
        pass
    assert stdlib_only()
    print("crypto-defense-15 OK")


if __name__ == "__main__":
    main()
