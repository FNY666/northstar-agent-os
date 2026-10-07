"""STARK-friendly algebraic hash interface (Poseidon/Rescue-style, simulated).

Research motivation: STARK provers work over prime fields, so a hash used
*inside* a STARK circuit must itself be algebraic - built from field
additions, multiplications, and low-degree power maps - or the circuit
becomes enormous. Poseidon (GKR+19) and Rescue are the standard answers:
a sponge whose permutation is round constants, an x^alpha S-box, and an
MDS matrix multiply, all over the field. A bit-oriented hash like SHA-256
costs tens of thousands of constraints per compression; Poseidon costs a
few hundred.

This module is the *algebraic mechanics* half, over a toy field, so the
plumbing the runtime depends on is pinned:

Algebraic structure (documented, all arithmetic in F_p):

- Field: F_p with p = 2^31 - 1 (Mersenne prime). **Toy field, chosen so
  every value fits in 4 bytes and tests run fast.** A real deployment uses
  a 64-bit STARK field (e.g. Goldilocks, p = 2^64 - 2^32 + 1) with
  cryptanalyzed round counts. Nothing here is secure; the *shape* is real.
- State: (x0, x1, x2) in F_p^3 (t = 3, rate r = 2, capacity c = 1).
- Permutation (Poseidon layout): R_F full rounds split around R_P partial
  rounds. Each round:
    1. add round constants:  x_i <- x_i + C[round*t + i]
    2. S-box:               x_i <- x_i^5            (full round, all i)
                            x_0 <- x_0^5            (partial round, first only)
    3. MDS layer:           x <- M x, M a 3x3 Cauchy matrix over F_p
  x^5 is a permutation of F_p because gcd(5, p-1) = 1 (asserted at import).
- Round constants: SHA-256("northstar-stark-hash.v1" || round || index)
  reduced mod p - deterministic, nothing-up-my-sleeve.
- Sponge: state starts at zero; the message is split into 4-byte chunks,
  each reduced mod p into a field element; a ``1`` padding element then
  zero padding fill the last block; each rate-sized block is added into
  the rate part and the permutation runs; the digest is state[0].
- ``hash_many`` uses a distinct initial state (domain tag in x0) and
  length-prefixes every item, so a batch hash can never collide with a
  single ``hash`` of the concatenated bytes, and item boundaries are
  unambiguous.

Public API:

- ``StarkHash`` -- parameter holder (``rate``, ``rounds_full``,
  ``rounds_partial`` are fixed to the documented defaults; the constructor
  rejects anything else fail-closed so two deployments cannot silently
  disagree on parameters).
- ``StarkHash.hash(data: bytes) -> FieldDigest`` -- sponge hash of bytes.
- ``StarkHash.hash_many(items: Sequence[bytes]) -> FieldDigest`` --
  domain-separated batch hash.
- ``FieldDigest`` -- frozen record: ``value`` (field element int),
  ``field_prime``, hex encoding via ``as_hex()`` / ``as_dict()``.
- ``stark_hash_audit_event(kind, digest, seq)`` -- ``audit.ndjson/1``
  shaped records (``hashed`` / ``batch-hashed``).

Honest scope:

- Simulated cryptography: the permutation, S-box, MDS diffusion, and
  sponge are genuine algebra, but over a 31-bit field with 8+13+8 rounds
  no cryptanalyst has reviewed. It is a *collision-finding exercise* for
  an attacker, not a security boundary. Do not use for commitments,
  proofs, or anything adversarial.
- The algebraic shape is what this pins: S-box degree, MDS linearity,
  sponge absorb/squeeze, and domain separation. A real Poseidon/Goldilocks
  instance drops in later without changing call sites.
- Deterministic and pure: no randomness, no wall-clock. Same bytes always
  give the same digest on every machine.
- ``str`` inputs are rejected (``TypeError``) - hash the explicit
  ``.encode(...)`` bytes instead, so the encoding choice stays visible at
  the call site.

No wall-clock anywhere. stdlib only (``hashlib``, ``dataclasses``,
``typing``).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import List, Sequence

#: Version pin for the hash interface described here.
STARK_HASH_VERSION = "stark-hash.v1"

#: Schema pin stamped on structured outputs.
SCHEMA_PIN = "northstar.stark-hash.v1"

#: Toy prime field. p = 2^31 - 1 is prime; every element fits in 4 bytes.
#: Real STARK deployments use a 64-bit field - see honest scope above.
FIELD_PRIME = (1 << 31) - 1

#: Sponge state width (t = rate + capacity).
_STATE_WIDTH = 3
#: Sponge rate: field elements absorbed per block.
_RATE = 2
#: Full rounds (split half before / half after the partial rounds).
_ROUNDS_FULL = 8
#: Partial rounds (S-box on the first state element only).
_ROUNDS_PARTIAL = 13
#: S-box exponent. Must satisfy gcd(alpha, p - 1) == 1 so x -> x^alpha is a
#: permutation of the field.
_SBOX_ALPHA = 5
#: Bytes per field element when splitting input (4 bytes < p < 2^32).
_CHUNK_BYTES = 4
#: Domain tag absorbed as the initial x0 for hash_many (single hash uses 0).
_BATCH_DOMAIN_TAG = 0x48415348  # "HASH"

# Fail-closed parameter agreement: two deployments must use the same
# parameters or their digests silently differ. The constructor rejects
# anything but the documented defaults.
_PINNED_PARAMS = {
    "rate": _RATE,
    "rounds_full": _ROUNDS_FULL,
    "rounds_partial": _ROUNDS_PARTIAL,
}


def _modinv(a: int) -> int:
    """Modular inverse in F_p (p prime, a != 0)."""
    return pow(a, FIELD_PRIME - 2, FIELD_PRIME)


def _round_constants() -> List[int]:
    """Deterministic nothing-up-my-sleeve round constants."""
    total = (_ROUNDS_FULL + _ROUNDS_PARTIAL) * _STATE_WIDTH
    consts: List[int] = []
    for i in range(total):
        seed = b"northstar-stark-hash.v1" + i.to_bytes(4, "big")
        consts.append(int.from_bytes(hashlib.sha256(seed).digest(), "big") % FIELD_PRIME)
    return consts


def _mds_matrix() -> List[List[int]]:
    """3x3 Cauchy matrix over F_p (Cauchy matrices are MDS)."""
    xs = (0, 1, 2)
    ys = (3, 4, 5)
    return [[_modinv((x + y) % FIELD_PRIME) for y in ys] for x in xs]


_ROUND_CONSTANTS = _round_constants()
_MDS = _mds_matrix()

# Import-time invariant: the S-box must be a field permutation.
assert __import__("math").gcd(_SBOX_ALPHA, FIELD_PRIME - 1) == 1, (
    "S-box exponent is not a permutation of F_p"
)


class StarkHashError(ValueError):
    """Malformed hash input or parameters - a programming error, not a verdict."""


def _sbox_full(state: List[int]) -> List[int]:
    return [pow(x, _SBOX_ALPHA, FIELD_PRIME) for x in state]


def _sbox_partial(state: List[int]) -> List[int]:
    out = list(state)
    out[0] = pow(out[0], _SBOX_ALPHA, FIELD_PRIME)
    return out


def _mds_mul(state: List[int]) -> List[int]:
    p = FIELD_PRIME
    return [
        (row[0] * state[0] + row[1] * state[1] + row[2] * state[2]) % p
        for row in _MDS
    ]


def _permute(state: List[int]) -> List[int]:
    """Poseidon-layout permutation: half full rounds, partials, half full."""
    t = _STATE_WIDTH
    half = _ROUNDS_FULL // 2
    rc = _ROUND_CONSTANTS
    idx = 0
    for _ in range(half):
        state = [(s + rc[idx * t + i]) % FIELD_PRIME for i, s in enumerate(state)]
        state = _mds_mul(_sbox_full(state))
        idx += 1
    for _ in range(_ROUNDS_PARTIAL):
        state = [(s + rc[idx * t + i]) % FIELD_PRIME for i, s in enumerate(state)]
        state = _mds_mul(_sbox_partial(state))
        idx += 1
    for _ in range(half):
        state = [(s + rc[idx * t + i]) % FIELD_PRIME for i, s in enumerate(state)]
        state = _mds_mul(_sbox_full(state))
        idx += 1
    return state


def _bytes_to_field_elements(data: bytes) -> List[int]:
    """Split bytes into 4-byte chunks, each reduced mod p."""
    elems = []
    for off in range(0, len(data), _CHUNK_BYTES):
        chunk = data[off:off + _CHUNK_BYTES]
        elems.append(int.from_bytes(chunk, "big") % FIELD_PRIME)
    return elems


def _sponge(elems: Sequence[int], domain_tag: int) -> int:
    """Absorb field elements through the sponge; return state[0]."""
    p = FIELD_PRIME
    state = [domain_tag % p, 0, 0]
    # 10*1-style padding on the element level: append 1, zero-pad to rate.
    padded = list(elems) + [1]
    while len(padded) % _RATE:
        padded.append(0)
    for off in range(0, len(padded), _RATE):
        for i in range(_RATE):
            state[i] = (state[i] + padded[off + i]) % p
        state = _permute(state)
    return state[0]


@dataclass(frozen=True)
class FieldDigest:
    """Frozen digest record: one field element plus its field pin."""

    value: int
    field_prime: int = FIELD_PRIME
    version: str = STARK_HASH_VERSION

    def __post_init__(self) -> None:
        if isinstance(self.value, bool) or not isinstance(self.value, int):
            raise TypeError("value must be an int field element")
        if isinstance(self.field_prime, bool) or not isinstance(self.field_prime, int):
            raise TypeError("field_prime must be an int")
        if self.field_prime != FIELD_PRIME:
            raise StarkHashError("field_prime disagrees with this module's field")
        if not 0 <= self.value < FIELD_PRIME:
            raise StarkHashError("value is not a field element")
        if self.version != STARK_HASH_VERSION:
            raise StarkHashError("unknown version pin")

    def as_hex(self) -> str:
        """4-byte big-endian hex of the field element."""
        return self.value.to_bytes(_CHUNK_BYTES, "big").hex()

    def as_dict(self) -> dict:
        return {
            "value": self.value,
            "value_hex": self.as_hex(),
            "field_prime": self.field_prime,
            "version": self.version,
            "schema": SCHEMA_PIN,
        }


class StarkHash:
    """Poseidon/Rescue-style algebraic sponge over the toy field.

    Parameters are pinned to the documented defaults; the constructor is
    fail-closed so parameter drift between deployments is impossible.
    """

    def __init__(
        self,
        rate: int = _RATE,
        rounds_full: int = _ROUNDS_FULL,
        rounds_partial: int = _ROUNDS_PARTIAL,
    ) -> None:
        for name, got, want in (
            ("rate", rate, _RATE),
            ("rounds_full", rounds_full, _ROUNDS_FULL),
            ("rounds_partial", rounds_partial, _ROUNDS_PARTIAL),
        ):
            if isinstance(got, bool) or not isinstance(got, int):
                raise TypeError(f"{name} must be an int")
            if got != want:
                raise StarkHashError(
                    f"{name}={got} disagrees with pinned {name}={want}"
                )
        self._rate = rate

    @staticmethod
    def _check_bytes(data: object, name: str) -> bytes:
        if isinstance(data, bool) or not isinstance(data, bytes):
            raise TypeError(f"{name} must be bytes, not {type(data).__name__}")
        return data

    def hash(self, data: bytes) -> FieldDigest:
        """Sponge hash of ``data``; empty input is well-defined."""
        raw = self._check_bytes(data, "data")
        return FieldDigest(value=_sponge(_bytes_to_field_elements(raw), 0))

    def hash_many(self, items: Sequence[bytes]) -> FieldDigest:
        """Domain-separated batch hash: length-prefixed items, tagged IV.

        Never equal to ``hash(b"".join(items))`` for the same items - the
        domain tag and length prefixes keep the two domains apart.
        """
        if not isinstance(items, (list, tuple)):
            raise TypeError("items must be a list or tuple of bytes")
        prefixed = b"".join(
            len(self._check_bytes(it, "item")).to_bytes(4, "big") + it
            for it in items
        )
        return FieldDigest(
            value=_sponge(_bytes_to_field_elements(prefixed), _BATCH_DOMAIN_TAG)
        )


def stark_hash_audit_event(kind: str, digest: FieldDigest, seq: int) -> dict:
    """Audit-shaped record for a hash observation."""
    if kind not in ("hashed", "batch-hashed"):
        raise ValueError("unknown kind")
    if not isinstance(digest, FieldDigest):
        raise TypeError("digest must be a FieldDigest")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError("seq must be a non-negative int")
    return {
        "event": "stark-hash",
        "kind": kind,
        "digest": digest.as_dict(),
        "audit_seq": seq,
        "schema": "audit.ndjson/1",
    }


def main() -> None:
    h = StarkHash()
    d1 = h.hash(b"northstar")
    d2 = h.hash(b"northstar")
    d3 = h.hash(b"northstar!")
    assert d1.value == d2.value, "determinism"
    assert d1.value != d3.value, "avalanche"
    b = h.hash_many([b"north", b"star"])
    assert b.value != h.hash(b"northstar").value, "domain separation"
    print(f"stark-hash OK: {d1.as_hex()} batch={b.as_hex()}")


if __name__ == "__main__":
    main()
