"""HKDF key derivation: turn raw key material into domain-bound keys.

Production primitives (KEMs, threshold signers, sealed audit writers) all
start from "some bytes the host trusts" -- a shared secret, a master key,
an attestation seed. Deriving the keys each protocol *actually uses*
directly from that material is dangerous: the same material reused across
two domains (two algorithms, two purposes) can cross-contaminate, and raw
secrets rarely have the exact length a protocol needs.

HKDF (RFC 5869) fixes both:

* **Extract** concentrates a (possibly long, non-uniform) input keying
  material ``ikm`` and an optional ``salt`` into a fixed-length
  pseudorandom key ``prk``: ``prk = HMAC-HASH(salt, ikm)``.
* **Expand** stretches ``prk`` into exactly ``length`` bytes of output
  keying material bound to a domain ``info``:
  ``T(0) = empty; T(i) = HMAC-HASH(prk, T(i-1) || info || i)``;
  ``okm = T(1) || ... || T(ceil(length / HashLen))`` truncated.

This module pins SHA-256 as the hash (``HashLen = 32``, ``okm`` bound
``255 * 32``). Contexts differ only through ``info`` and ``salt`` -- the
same ``ikm`` with ``info=b"mcp-sign"`` and ``info=b"audit-seal"`` derives
independent keys, and two deployments that agree on ``(ikm, salt,
info, length)`` compute bit-identical keys with no randomness and no
wall-clock (deterministic, audit-replayable).

Honest scope: HKDF is a *derivation* primitive, not a key-management
policy. It cannot make weak input keying material strong (low-entropy
passwords need a KDF with a cost parameter, e.g. scrypt/argon2 -- see
the ``KDFError`` on short IKM), cannot prevent the host reusing ``info``
for two purposes, and cannot detect that a salt was reused (salt reuse
across deployments is the host's job to avoid). The keys derived here
are honest bytes in memory; storage, rotation, and revocation are the
host's job (see ``kms_interface``). This is real HKDF over HMAC-SHA256
(stdlib), not a simulation -- the extract/expand equations are the
RFC 5869 equations.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Tuple


#: Version pin for this module's record shape.
KEY_DERIVATION_VERSION = "key-derivation.v1"

#: Schema pin carried on audit records.
KEY_DERIVATION_SCHEMA = "northstar.key-derivation.v1"

#: Hash pinned for the whole module (RFC 5869 allows any; we fix one so
#: two deployments cannot silently disagree on the KDF).
_HASH_NAME = "sha256"

#: Hash output length in bytes (SHA-256).
_HASH_LEN = 32

#: RFC 5869 bound: L <= 255 * HashLen.
_MAX_OKM_LEN = 255 * _HASH_LEN

#: Minimum input keying material length. Below this the module refuses to
#: derive: a short, low-entropy secret is a password, not a key, and needs
#: a costed KDF (scrypt/argon2). Fail-closed rather than silently weak.
_MIN_IKM_LEN = 16

#: Domain-separation prefix so KDF records/audit pins cannot collide with
#: pins from other modules.
_DOMAIN = b"northstar.key-derivation.v1:"


class KDFError(Exception):
    """Raised for malformed KDF inputs or derivation failures."""


def _require_bytes(value: object, name: str, *, allow_empty: bool) -> bytes:
    """Fail-closed bytes coercion: str is rejected, never silently encoded."""
    if isinstance(value, bool) or not isinstance(value, bytes):
        raise KDFError(f"{name} must be bytes, got {type(value).__name__}")
    if not allow_empty and len(value) == 0:
        raise KDFError(f"{name} must be non-empty")
    return value


def _sha256_pin(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(_DOMAIN + data).hexdigest()


@dataclass(frozen=True)
class DerivedKey:
    """An HKDF output keying material record.

    The key bytes themselves are *not* logged: the record carries a
    digest pin (``key_pin``) so audits can prove *which* key was derived
    without exposing it. ``info`` and ``length`` are recorded so a
    verifier can re-derive; ``ikm`` is never stored.
    """

    key_pin: str
    info: bytes
    length: int
    version: str = KEY_DERIVATION_VERSION
    schema: str = KEY_DERIVATION_SCHEMA

    def __post_init__(self) -> None:
        if not self.key_pin.startswith("sha256:"):
            raise KDFError("key_pin must be a sha256: pin")
        if not isinstance(self.info, bytes):
            raise KDFError("info must be bytes")
        if not isinstance(self.length, int) or isinstance(self.length, bool):
            raise KDFError("length must be an int")
        if not (1 <= self.length <= _MAX_OKM_LEN):
            raise KDFError("length out of range")
        if self.version != KEY_DERIVATION_VERSION:
            raise KDFError("bad version pin")
        if self.schema != KEY_DERIVATION_SCHEMA:
            raise KDFError("bad schema pin")

    def as_dict(self) -> dict:
        return {
            "key_pin": self.key_pin,
            "info": self.info.decode("latin-1"),
            "length": self.length,
            "version": self.version,
            "schema": self.schema,
        }


class HKDF:
    """RFC 5869 HKDF pinned to SHA-256.

    Stateless: :meth:`extract` and :meth:`expand` are pure functions of
    their arguments, so the same ``(ikm, salt, info, length)`` always
    yields the same key -- deterministic key derivation for audit
    replay. ``extract`` returns the PRK; :meth:`derive` runs the full
    extract-then-expand pipeline in one call.
    """

    @staticmethod
    def extract(salt: bytes | None, ikm: bytes) -> bytes:
        """HKDF-Extract: ``prk = HMAC-HASH(salt, ikm)``.

        ``salt`` may be ``None`` (defaults to ``HashLen`` zero bytes, per
        RFC 5869). ``ikm`` must be non-empty bytes of at least
        :data:`_MIN_IKM_LEN` bytes; ``str`` is rejected (no silent
        encoding coercion).
        """
        material = _require_bytes(ikm, "ikm", allow_empty=False)
        if len(material) < _MIN_IKM_LEN:
            raise KDFError(
                f"ikm too short ({len(material)} < {_MIN_IKM_LEN}): "
                "use a costed KDF (scrypt/argon2) for low-entropy input"
            )
        if salt is None:
            salt_bytes = b"\x00" * _HASH_LEN
        else:
            salt_bytes = _require_bytes(salt, "salt", allow_empty=True)
        return hmac.new(salt_bytes, material, _HASH_NAME).digest()

    @staticmethod
    def expand(prk: bytes, info: bytes, length: int) -> bytes:
        """HKDF-Expand: stretch ``prk`` into ``length`` bytes bound to ``info``.

        ``prk`` must be exactly ``HashLen`` bytes (the extract output);
        ``info`` is the domain separation (may be empty); ``length`` is
        bounded by ``255 * HashLen`` and must be >= 1. Fail-closed on
        every violation.
        """
        prk_bytes = _require_bytes(prk, "prk", allow_empty=False)
        if len(prk_bytes) != _HASH_LEN:
            raise KDFError(
                f"prk must be {_HASH_LEN} bytes (HKDF-Extract output), "
                f"got {len(prk_bytes)}"
            )
        info_bytes = _require_bytes(info, "info", allow_empty=True)
        if isinstance(length, bool) or not isinstance(length, int):
            raise KDFError("length must be an int")
        if not (1 <= length <= _MAX_OKM_LEN):
            raise KDFError(
                f"length must be in [1, {_MAX_OKM_LEN}], got {length}"
            )
        blocks = (length + _HASH_LEN - 1) // _HASH_LEN
        okm = b""
        previous = b""
        for counter in range(1, blocks + 1):
            previous = hmac.new(
                prk_bytes,
                previous + info_bytes + bytes([counter]),
                _HASH_NAME,
            ).digest()
            okm += previous
        return okm[:length]

    def derive(
        self,
        ikm: bytes,
        info: bytes,
        length: int,
        salt: bytes | None = None,
    ) -> Tuple[bytes, DerivedKey]:
        """Full HKDF: extract then expand, returning ``(okm, record)``.

        The record pins the key by digest -- audits record the pin, never
        the key bytes.
        """
        prk = self.extract(salt, ikm)
        okm = self.expand(prk, info, length)
        record = DerivedKey(
            key_pin=_sha256_pin(okm),
            info=info,
            length=length,
        )
        return okm, record


#: Fixed vocabulary for :func:`key_derivation_audit_event`.
_AUDIT_KINDS = ("extracted", "expanded", "derived")


def key_derivation_audit_event(kind: str, record: DerivedKey, seq: int) -> dict:
    """Shape an ``audit.ndjson/1`` record for a KDF operation.

    The record carries the key *pin*, never key bytes.
    """
    if kind not in _AUDIT_KINDS:
        raise KDFError(f"unknown audit kind: {kind!r}")
    if not isinstance(record, DerivedKey):
        raise KDFError("record must be a DerivedKey")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise KDFError("seq must be a non-negative int")
    return {
        "schema": KEY_DERIVATION_SCHEMA,
        "kind": kind,
        "seq": seq,
        "key_pin": record.key_pin,
        "info": record.info.decode("latin-1"),
        "length": record.length,
        "version": KEY_DERIVATION_VERSION,
    }


def _self_check() -> None:
    # RFC 5869 Appendix A.1, test case 1 (SHA-256) -- proves the equations
    # are real HKDF. Constants copied from the RFC text verbatim.
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    expected_prk = bytes.fromhex(
        "077709362c2e32df0ddc3f0dc47bba63"
        "90b6c73bb50f9c3122ec844ad7c2b3e5"
    )
    expected_okm = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
    kdf = HKDF()
    prk = kdf.extract(salt, ikm)
    assert prk == expected_prk, "extract diverged from RFC 5869 A.1"
    okm = kdf.expand(prk, info, 42)
    assert okm == expected_okm, "expand diverged from RFC 5869 A.1"
    material, record = kdf.derive(ikm, info, 42, salt)
    assert material == expected_okm
    assert record.key_pin.startswith("sha256:")
    # Determinism: same inputs, bit-identical keys.
    assert kdf.expand(prk, info, 42) == okm
    print("key-derivation OK: RFC 5869 vector, derive, pins")


def main() -> None:
    _self_check()


if __name__ == "__main__":
    main()
