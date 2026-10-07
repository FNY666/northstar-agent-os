"""Homomorphic-encryption wrapper (simulated interface).

Research datum: fully homomorphic encryption (FHE) lets an agent run
inference / aggregation over data it cannot read — the model computes on
ciphertexts and only the key holder decrypts the result. That is the
right shape for private inference, delegated analytics, and
confidential multi-party agent workflows.

This module is an *interface contract*, not real cryptography. The
"ciphertexts" are simulated records: the plaintext value is held in
process memory under an integrity digest, and `add` performs the
addition that a real BFV/BGV scheme would perform homomorphically.
Production code written against this API — ``encrypt`` → compute on
ciphertexts → ``decrypt`` — can be swapped for a real FHE library
(Congressional, OpenFHE, TFHE-rs, …) without changing call sites.

Honest scope (read before relying on this):
- The plaintext is *visible to the process* — this provides zero
  confidentiality. It is a shape check and a noise-budget model, not
  encryption.
- Only *exact integer* arithmetic is simulated (BFV/BGV style). CKKS
  approximate-float semantics are NOT simulated.
- The noise model is deliberately simple: fresh ciphertexts carry noise
  0, each homomorphic add grows noise additively, and decryption
  fail-closes past ``MAX_NOISE``. Real schemes have subtler growth.
- Integrity is an HMAC over the record (tamper-evidence), not semantic
  security.

House style: frozen dataclasses, no wall-clock, deterministic,
fail-closed, stdlib only, standalone-importable.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from enum import Enum
from typing import Union

#: Version pin for auditability.
FHE_WRAPPER_VERSION = "fhe-wrapper.v1"

#: Schema pin stamped on records.
SCHEMA_PIN = "northstar.fhe-wrapper.v1"

#: Maximum accumulated noise a ciphertext may carry and still decrypt.
MAX_NOISE = 100

#: Noise added by one homomorphic addition, on top of operand noise.
ADD_NOISE = 1


class FHEError(ValueError):
    """Raised for malformed FHE inputs (fail-closed)."""


class IntegrityError(FHEError):
    """Raised when a ciphertext digest does not verify."""


class ContextMismatchError(FHEError):
    """Raised when ciphertexts from different contexts are combined."""


class NoiseExhaustedError(FHEError):
    """Raised when decrypting a ciphertext past its noise budget."""


class FHEScheme(str, Enum):
    """Supported (simulated) FHE schemes."""

    BGV = "bgv"
    BFV = "bfv"
    CKKS = "ckks"
    TFHE = "tfhe"


def _check_int(name: str, value: object) -> int:
    """Validate an exact-integer operand; bool is rejected explicitly."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise FHEError(f"{name} must be an int, got {type(value).__name__}")
    return value


def _mac_key(key_id: str) -> bytes:
    return hashlib.sha256(b"northstar-fhe-wrapper.v1:" + key_id.encode("utf-8")).digest()


def _digest(scheme: str, key_id: str, value: int, noise: int, nonce: str) -> str:
    body = f"{scheme}|{key_id}|{value}|{noise}|{nonce}".encode("utf-8")
    return hmac.new(_mac_key(key_id), body, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class FHEContext:
    """A (simulated) FHE key context. All ops bind to this context."""

    scheme: FHEScheme
    key_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.scheme, FHEScheme):
            raise FHEError(f"scheme must be FHEScheme, got {type(self.scheme).__name__}")
        if not isinstance(self.key_id, str) or not self.key_id:
            raise FHEError("key_id must be a non-empty str")

    # -- API ----------------------------------------------------------------

    def encrypt(self, value: int, seq: int) -> "FHECiphertext":
        """Encrypt an integer. ``seq`` is caller-supplied (no wall-clock)."""
        _check_int("value", value)
        _check_int("seq", seq)
        nonce = f"{self.key_id}:{seq}"
        return FHECiphertext(
            scheme=self.scheme.value,
            key_id=self.key_id,
            value=value,
            noise=0,
            nonce=nonce,
            digest=_digest(self.scheme.value, self.key_id, value, 0, nonce),
        )

    def _verify(self, ciphertext: "FHECiphertext", name: str) -> None:
        """Context + integrity check without the noise-budget gate.

        Homomorphic ops may legally proceed on noisy ciphertexts (the
        arithmetic is still well-defined); only *decryption* fail-closes
        past the noise budget, matching real FHE semantics.
        """
        if not isinstance(ciphertext, FHECiphertext):
            raise FHEError(f"{name} must be FHECiphertext, got {type(ciphertext).__name__}")
        if ciphertext.key_id != self.key_id or ciphertext.scheme != self.scheme.value:
            raise ContextMismatchError("ciphertext was not produced by this context")
        expected = _digest(
            ciphertext.scheme, ciphertext.key_id,
            ciphertext.value, ciphertext.noise, ciphertext.nonce,
        )
        if not hmac.compare_digest(expected, ciphertext.digest):
            raise IntegrityError("ciphertext digest does not verify (tampered)")

    def decrypt(self, ciphertext: "FHECiphertext") -> int:
        """Decrypt, fail-closed on integrity, context, or noise failure."""
        self._verify(ciphertext, "ciphertext")
        if ciphertext.noise > MAX_NOISE:
            raise NoiseExhaustedError(
                f"noise {ciphertext.noise} exceeds budget {MAX_NOISE}"
            )
        return ciphertext.value

    def add(self, c1: "FHECiphertext", c2: "FHECiphertext") -> "FHECiphertext":
        """Homomorphic addition: decrypt(add(c1, c2)) == v1 + v2."""
        self._verify(c1, "c1")
        self._verify(c2, "c2")
        if c1.key_id != c2.key_id or c1.scheme != c2.scheme:
            raise ContextMismatchError("cannot combine ciphertexts from different contexts")
        value = c1.value + c2.value
        noise = max(c1.noise, c2.noise) + ADD_NOISE
        nonce = f"add({c1.nonce},{c2.nonce})"
        return FHECiphertext(
            scheme=self.scheme.value,
            key_id=self.key_id,
            value=value,
            noise=noise,
            nonce=nonce,
            digest=_digest(self.scheme.value, self.key_id, value, noise, nonce),
        )


@dataclass(frozen=True)
class FHECiphertext:
    """A simulated FHE ciphertext. Integrity-pinned, noise-tracked."""

    scheme: str
    key_id: str
    value: int
    noise: int
    nonce: str
    digest: str

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "scheme": self.scheme,
            "key_id": self.key_id,
            "noise": self.noise,
            "nonce": self.nonce,
            "digest": self.digest,
        }


def main() -> None:
    ctx = FHEContext(scheme=FHEScheme.BFV, key_id="test-key")
    c1 = ctx.encrypt(40, seq=1)
    c2 = ctx.encrypt(2, seq=2)
    total = ctx.add(c1, c2)
    assert ctx.decrypt(total) == 42, "homomorphic add roundtrip"
    # Noise exhaustion is fail-closed.
    deep = c1
    for i in range(MAX_NOISE + 2):
        deep = ctx.add(deep, ctx.encrypt(0, seq=100 + i))
    try:
        ctx.decrypt(deep)
    except NoiseExhaustedError:
        print("fhe-wrapper OK: add roundtrip, noise budget enforced")
    else:  # pragma: no cover
        raise AssertionError("noise budget not enforced")


if __name__ == "__main__":
    main()
