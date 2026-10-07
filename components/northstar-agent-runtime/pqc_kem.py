"""Post-quantum KEM interface (ML-KEM / Kyber shape, simulated).

Research motivation: NIST FIPS 203 standardised ML-KEM (CRYSTALS-Kyber)
in August 2024 as the post-quantum key-establishment primitive - the
algorithm that replaces ECDH/ECIES in TLS 1.3 handshakes, WireGuard
re-keying, and Signal's PQXDH against a store-now-decrypt-later quantum
adversary. A KEM is the right primitive for an agent runtime: the agent
never needs interactive Diffie-Hellman, it needs *encapsulate a fresh
secret to a peer's public key* and *decapsulate with the secret key*,
with the ciphertext carrying everything the recipient needs.

This module is the *mechanics half*: it pins the keygen / encaps /
decaps call shape, the record layout, the integrity rule, and the
failure vocabulary, so production code written against it can swap in a
real ML-KEM library (liboqs, libcrux, or a hardware module) without
changing call sites.

Construction (documented, all symmetric plumbing over SHA-256):

- Parameter sets: ``ml-kem-512`` / ``ml-kem-768`` / ``ml-kem-1024`` -
  the real FIPS 203 names, mapped to NIST security levels 1 / 3 / 5.
  The shared secret is 32 bytes in every set (as in real ML-KEM). Key
  and ciphertext *sizes* are simulation placeholders, not the real
  800/1568/1184-byte public keys.
- ``generate_keypair(param_set, seed)``: deterministic. ``sk_secret =
  SHA-256(domain || "kem-sk" || seed)``; ``pk = SHA-256(domain ||
  "kem-pk" || sk_secret)``. The seed is caller-supplied bytes (the host
  owns the entropy source - this module never touches ``random`` or
  ``secrets``, so runs are replayable and audit-safe).
- ``encaps(pk, nonce)``: the caller supplies the ephemeral randomness
  (a fresh nonce per encapsulation - reusing a nonce reuses the shared
  secret, exactly as reusing randomness would in a real KEM; the host
  is told so). ``shared_secret = SHA-256(domain || "kem-ss" || pk ||
  nonce)``; ``ciphertext = nonce || tag`` with ``tag = SHA-256(domain
  || "kem-tag" || pk || nonce)`` - the tag binds the ciphertext to the
  *public key*, so a ciphertext minted for one recipient cannot be
  transplanted onto another's decapsulation.
- ``decaps(sk, ct)``: re-derives ``pk`` from the secret key, verifies
  the tag with ``hmac.compare_digest`` (fail-closed on mismatch -
  tampered or wrong-recipient ciphertexts are *refused*, never
  decrypted), then re-derives the shared secret from the sealed nonce.

Public API:

- ``PARAM_SETS`` -- mapping ``name -> {"nist_level": int}``.
- ``PQCKEM(param_set)`` -- parameter holder. Unknown parameter sets are
  rejected fail-closed at construction, so two deployments cannot
  silently disagree on the KEM in use.
- ``PQCKEM.generate_keypair(seed: bytes) -> KeyPair`` -- frozen record
  with ``public_key``, ``secret_key``, ``param_set``, ``sha256:`` pins,
  and ``as_dict()``.
- ``PQCKEM.encaps(public_key: bytes, nonce: bytes) -> Encapsulation``
  -- frozen record with ``ciphertext``, ``shared_secret`` (32 bytes),
  ``as_dict()``.
- ``PQCKEM.decaps(secret_key: bytes, ciphertext: bytes) -> bytes`` --
  the shared secret, or raises ``DecapsulationError`` fail-closed.
- ``pqc_kem_audit_event(kind, seq, ...)`` -- ``audit.ndjson/1``-shaped
  records (``keygen`` / ``encapsulated`` / ``decapsulated`` /
  ``decaps-rejected``).

Honest scope: simulated - there is no Module-LWE hardness here, no
IND-CCA2 argument, and key/ciphertext sizes are toy values. The shared
secret is a *deterministic* function of (pk, nonce): whoever sees the
nonce and the public key can recompute it, so this is an interface and
bookkeeping exercise, not a confidentiality boundary. Do not ship this
as post-quantum protection; wire a FIPS 203 implementation behind this
API for that.

Version pin: ``pqc-kem.v1``. Schema pin: ``northstar.pqc-kem.v1``.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Dict, Tuple

KEM_VERSION = "pqc-kem.v1"
SCHEMA_PIN = "northstar.pqc-kem.v1"
_AUDIT_SCHEMA = "audit.ndjson/1"
_DOMAIN = b"northstar-pqc-kem.v1"

# Real FIPS 203 parameter-set names and their NIST security levels.
# Shared secret size is 32 bytes in every set (as in real ML-KEM).
PARAM_SETS: Dict[str, Dict[str, int]] = {
    "ml-kem-512": {"nist_level": 1, "shared_secret_bytes": 32},
    "ml-kem-768": {"nist_level": 3, "shared_secret_bytes": 32},
    "ml-kem-1024": {"nist_level": 5, "shared_secret_bytes": 32},
}

_MAX_SEED_BYTES = 1024
_MAX_NONCE_BYTES = 64
_NONCE_MIN_BYTES = 1
_TAG_BYTES = 32


class PqcKemError(Exception):
    """Base error for the post-quantum KEM interface."""


class DecapsulationError(PqcKemError):
    """Raised when a ciphertext cannot be decapsulated (fail-closed)."""


def _sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def _pin(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _check_bytes(value: object, name: str, min_len: int, max_len: int) -> bytes:
    if isinstance(value, bool) or not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes")
    raw = bytes(value)
    if not (min_len <= len(raw) <= max_len):
        raise ValueError(f"{name} must be {min_len}..{max_len} bytes")
    return raw


def _sk_secret(seed: bytes) -> bytes:
    return _sha256(_DOMAIN, b"kem-sk", seed)


def _public_key(sk_secret: bytes) -> bytes:
    return _sha256(_DOMAIN, b"kem-pk", sk_secret)


def _tag(pk: bytes, nonce: bytes) -> bytes:
    return _sha256(_DOMAIN, b"kem-tag", pk, nonce)


def _shared_secret(pk: bytes, nonce: bytes) -> bytes:
    return _sha256(_DOMAIN, b"kem-ss", pk, nonce)


@dataclass(frozen=True)
class KeyPair:
    """A deterministic KEM key pair (frozen)."""

    public_key: bytes
    secret_key: bytes
    param_set: str
    schema: str = field(default=SCHEMA_PIN)

    def __post_init__(self) -> None:
        if self.schema != SCHEMA_PIN:
            raise PqcKemError("schema pin mismatch")
        if self.param_set not in PARAM_SETS:
            raise PqcKemError("unknown parameter set")
        if not isinstance(self.public_key, bytes) or not isinstance(
            self.secret_key, bytes
        ):
            raise TypeError("keys must be bytes")

    def as_dict(self) -> dict:
        return {
            "version": KEM_VERSION,
            "schema": self.schema,
            "param_set": self.param_set,
            "public_key_pin": _pin(self.public_key),
            "secret_key_pin": _pin(self.secret_key),
        }


@dataclass(frozen=True)
class Encapsulation:
    """The result of encapsulating to a public key (frozen)."""

    ciphertext: bytes
    shared_secret: bytes
    param_set: str
    schema: str = field(default=SCHEMA_PIN)

    def __post_init__(self) -> None:
        if self.schema != SCHEMA_PIN:
            raise PqcKemError("schema pin mismatch")
        if self.param_set not in PARAM_SETS:
            raise PqcKemError("unknown parameter set")
        if not isinstance(self.ciphertext, bytes) or not isinstance(
            self.shared_secret, bytes
        ):
            raise TypeError("ciphertext and shared_secret must be bytes")
        expected = PARAM_SETS[self.param_set]["shared_secret_bytes"]
        if len(self.shared_secret) != expected:
            raise PqcKemError("shared secret has wrong length")

    def as_dict(self) -> dict:
        return {
            "version": KEM_VERSION,
            "schema": self.schema,
            "param_set": self.param_set,
            "ciphertext_pin": _pin(self.ciphertext),
            "shared_secret_pin": _pin(self.shared_secret),
        }


class PQCKEM:
    """Post-quantum KEM parameter holder (simulated ML-KEM shape)."""

    def __init__(self, param_set: str = "ml-kem-768") -> None:
        if not isinstance(param_set, str) or param_set not in PARAM_SETS:
            raise PqcKemError(f"unknown parameter set: {param_set!r}")
        self._param_set = param_set

    @property
    def param_set(self) -> str:
        return self._param_set

    @property
    def nist_level(self) -> int:
        return PARAM_SETS[self._param_set]["nist_level"]

    def generate_keypair(self, seed: bytes) -> KeyPair:
        """Deterministically derive a key pair from a caller seed."""
        raw_seed = _check_bytes(seed, "seed", 1, _MAX_SEED_BYTES)
        secret = _sk_secret(raw_seed)
        public = _public_key(secret)
        return KeyPair(
            public_key=public, secret_key=secret, param_set=self._param_set
        )

    def encaps(self, public_key: bytes, nonce: bytes) -> Encapsulation:
        """Encapsulate a fresh shared secret to ``public_key``.

        ``nonce`` is the caller-supplied ephemeral randomness - it MUST be
        fresh per encapsulation; reusing it reuses the shared secret.
        """
        pk = _check_bytes(public_key, "public_key", 32, 32)
        raw_nonce = _check_bytes(nonce, "nonce", _NONCE_MIN_BYTES, _MAX_NONCE_BYTES)
        ciphertext = raw_nonce + _tag(pk, raw_nonce)
        secret = _shared_secret(pk, raw_nonce)
        return Encapsulation(
            ciphertext=ciphertext,
            shared_secret=secret,
            param_set=self._param_set,
        )

    def decaps(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Recover the shared secret, or raise ``DecapsulationError``."""
        sk = _check_bytes(secret_key, "secret_key", 32, 32)
        ct = _check_bytes(
            ciphertext, "ciphertext", _NONCE_MIN_BYTES + _TAG_BYTES,
            _MAX_NONCE_BYTES + _TAG_BYTES,
        )
        pk = _public_key(sk)
        nonce, tag = ct[:-_TAG_BYTES], ct[-_TAG_BYTES:]
        expected = _tag(pk, nonce)
        if not hmac.compare_digest(tag, expected):
            raise DecapsulationError(
                "ciphertext tag mismatch: wrong key or tampered ciphertext"
            )
        return _shared_secret(pk, nonce)


def pqc_kem_audit_event(kind: str, seq: int, **fields: object) -> dict:
    """Audit-shaped record for a KEM observation."""
    if kind not in ("keygen", "encapsulated", "decapsulated", "decaps-rejected"):
        raise ValueError("unknown kind")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError("seq must be a non-negative int")
    record = {
        "event": "pqc-kem",
        "kind": kind,
        "audit_seq": seq,
        "schema": _AUDIT_SCHEMA,
    }
    record.update(fields)
    return record


def main() -> None:
    kem = PQCKEM("ml-kem-768")
    kp = kem.generate_keypair(b"northstar-test-seed")
    enc = kem.encaps(kp.public_key, b"fresh-nonce-0001")
    ss = kem.decaps(kp.secret_key, enc.ciphertext)
    assert ss == enc.shared_secret, "roundtrip"
    assert len(ss) == 32, "32-byte shared secret"
    try:
        kem.decaps(_sha256(b"wrong"), enc.ciphertext)
    except DecapsulationError:
        pass
    else:
        raise AssertionError("wrong key must fail closed")
    print(f"pqc-kem OK: {kem.param_set} roundtrip, ss={ss.hex()[:16]}...")


if __name__ == "__main__":
    main()
