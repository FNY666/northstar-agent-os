"""Simulated KZG-style polynomial commitments (API + bookkeeping, NOT real crypto).

A polynomial commitment scheme has three algorithms:

* ``commit(p)`` — bind to a polynomial ``p``; outputs a short commitment ``C``.
* ``eval_proof(p, z)`` — prove that ``p(z) = y``; outputs ``(y, proof)``.
* ``verify(C, z, y, proof)`` — check the opening against the commitment.

In Kate-Zaverucha-Goldberg (KZG), the proof is a commitment to the
*quotient polynomial* ``q(x) = (p(x) - y) / (x - z)`` and verification is a
pairing check. This module keeps that exact three-algorithm shape — the
proof carries the quotient coefficients and the verifier checks the
algebraic identity ``(x - z)*q(x) + y == p(x)`` — but the binding is a
SHA-256 digest over canonical coefficients, not elliptic-curve hardness.

Honest scope, stated plainly:

* This is a **simulation of the interface**, the same way
  ``consensus_interface`` simulates the Raft/Paxos message half without a
  network. There are no elliptic curves, no pairings, no trusted setup, no
  SRS. Binding rests on SHA-256 collision resistance, not on discrete-log
  assumptions.
* The simulated proof **reveals the committed coefficients**. A real KZG
  proof is constant-size and succinct; this one is linear in the degree.
  The reveal is what lets the verifier re-derive the digest and check the
  quotient identity without any trapdoor.
* Coefficients are integers with exact arithmetic (synthetic division by
  the monic ``(x - z)`` is exact over the integers). There is no prime
  field, no modular inverse, no rounding.
* Do **not** use this as a cryptographic commitment scheme. It exists so
  Northstar code can program against the commit/open/verify API surface —
  e.g. for audit-log polynomial checkpoints — with deterministic,
  testable behavior.

Everything here is offline and deterministic. No network, no clock reads,
no randomness. ``hashlib``, ``json``, ``dataclasses`` only.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Mapping, Sequence

#: Module version.
POLY_COMMITMENT_VERSION = "poly-commitment.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.poly-commitment.v1"

#: Digest prefix used for commitment pins.
_DIGEST_PREFIX = "sha256:"

_AUDIT_KINDS = (
    "committed",
    "proof-generated",
    "verified",
    "verification-failed",
)


class PolyCommitmentError(Exception):
    """Malformed input or broken invariant (programming error)."""


def _check_int(value: object, what: str) -> int:
    """Integers only; ``bool`` is rejected (``True == 1`` would alias coefficients)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise PolyCommitmentError(f"{what} must be an int, got {type(value).__name__}")
    return value


def _check_seq(seq: object, what: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise PolyCommitmentError(f"{what} must be a non-negative int")
    return seq


def _check_digest(value: object, what: str = "digest") -> str:
    if (
        not isinstance(value, str)
        or not value.startswith(_DIGEST_PREFIX)
        or len(value) != len(_DIGEST_PREFIX) + 64
    ):
        raise PolyCommitmentError(f"{what} must be a '{_DIGEST_PREFIX}<64 hex>' pin")
    return value


def _encode_int(value: int) -> str:
    """Deterministic, injective encoding of a signed bigint as a string.

    JCS (RFC 8785) serializes integers outside +/-2**53 as IEEE 754 doubles,
    which is lossy. Sign-aware hex keeps the digest body deterministic *and*
    injective for arbitrary-size coefficients (same trick as
    ``secure_aggregation._hexint``).
    """
    return "-" + format(-value, "x") if value < 0 else format(value, "x")


def _canonicalize_coeffs(coeffs: Sequence[object]) -> tuple[int, ...]:
    """Validate and canonicalize ``a_0..a_n`` (constant term first).

    Trailing zero coefficients are stripped so ``[1, 2, 0]`` and ``[1, 2]``
    commit identically; at least one coefficient is kept (the zero
    polynomial is ``(0,)``). Fail-closed on empty input, bools, non-ints.
    """
    if not isinstance(coeffs, (tuple, list)) or len(coeffs) == 0:
        raise PolyCommitmentError("coeffs must be a non-empty tuple/list")
    checked = tuple(_check_int(c, f"coeffs[{i}]") for i, c in enumerate(coeffs))
    stripped = list(checked)
    while len(stripped) > 1 and stripped[-1] == 0:
        stripped.pop()
    return tuple(stripped)


def _commitment_digest(coeffs: tuple[int, ...]) -> str:
    """``sha256:`` pin over the canonical coefficient body."""
    body = json.dumps(
        {"coeffs": [_encode_int(c) for c in coeffs]},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _DIGEST_PREFIX + hashlib.sha256(body).hexdigest()


def _evaluate(coeffs: Sequence[int], point: int) -> int:
    """Horner evaluation of ``p(point)``."""
    result = 0
    for coeff in reversed(coeffs):
        result = result * point + coeff
    return result


def _quotient_coeffs(coeffs: tuple[int, ...], point: int) -> tuple[int, ...]:
    """Coefficients of ``q(x) = (p(x) - p(z)) / (x - z)`` via synthetic division.

    Division by the monic ``(x - z)`` is exact over the integers. For a
    constant polynomial the quotient is the empty tuple.
    """
    n = len(coeffs) - 1
    if n == 0:
        return ()
    # b_n = a_n; b_k = a_k + z * b_{k+1}; q = (b_1, ..., b_n).
    b = [0] * (n + 1)
    b[n] = coeffs[n]
    for k in range(n - 1, 0, -1):
        b[k] = coeffs[k] + point * b[k + 1]
    quotient = tuple(b[1:])
    # Prover-side invariant: the remainder must equal p(z).
    if coeffs[0] + point * b[1] != _evaluate(coeffs, point):
        raise PolyCommitmentError("internal error: synthetic division remainder mismatch")
    return quotient


@dataclass(frozen=True)
class Commitment:
    """The binding output of ``commit``: a digest pin plus public metadata."""

    digest: str
    degree: int
    n_coeffs: int

    def __post_init__(self) -> None:
        _check_digest(self.digest)
        if isinstance(self.degree, bool) or not isinstance(self.degree, int) or self.degree < 0:
            raise PolyCommitmentError("degree must be a non-negative int")
        if isinstance(self.n_coeffs, bool) or not isinstance(self.n_coeffs, int) or self.n_coeffs < 1:
            raise PolyCommitmentError("n_coeffs must be a positive int")
        if self.n_coeffs != self.degree + 1:
            raise PolyCommitmentError("n_coeffs must equal degree + 1")

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "digest": self.digest,
            "degree": self.degree,
            "n_coeffs": self.n_coeffs,
        }


@dataclass(frozen=True)
class EvalProof:
    """A simulated KZG evaluation proof.

    Carries the KZG witness shape — the quotient coefficients — plus the
    revealed canonical coefficients the simulator's verifier needs to
    re-derive the digest. A real KZG proof would not reveal the
    coefficients; see the module docstring.
    """

    commitment_digest: str
    point: int
    value: int
    quotient_coeffs: tuple[int, ...]
    coeffs: tuple[int, ...]

    def __post_init__(self) -> None:
        _check_digest(self.commitment_digest, "commitment_digest")
        object.__setattr__(self, "point", _check_int(self.point, "point"))
        object.__setattr__(self, "value", _check_int(self.value, "value"))
        if not isinstance(self.quotient_coeffs, tuple) or any(
            isinstance(c, bool) or not isinstance(c, int) for c in self.quotient_coeffs
        ):
            raise PolyCommitmentError("quotient_coeffs must be a tuple of ints")
        object.__setattr__(self, "coeffs", _canonicalize_coeffs(self.coeffs))

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "commitment_digest": self.commitment_digest,
            "point": _encode_int(self.point),
            "value": _encode_int(self.value),
            "quotient_coeffs": [_encode_int(c) for c in self.quotient_coeffs],
            "coeffs": [_encode_int(c) for c in self.coeffs],
        }


class PolyCommitment:
    """A polynomial held for committing and proving evaluations.

    ``coeffs`` are ``a_0..a_n`` (constant term first), canonicalized on
    construction: trailing zeros stripped, bools and non-ints rejected.
    """

    def __init__(self, coeffs: Sequence[object]):
        self._coeffs = _canonicalize_coeffs(coeffs)

    @property
    def coeffs(self) -> tuple[int, ...]:
        """Canonical coefficients, constant term first."""
        return self._coeffs

    @property
    def degree(self) -> int:
        return len(self._coeffs) - 1

    def commit(self) -> Commitment:
        """Bind to the polynomial; returns the digest commitment."""
        return Commitment(
            digest=_commitment_digest(self._coeffs),
            degree=self.degree,
            n_coeffs=len(self._coeffs),
        )

    def evaluate(self, point: object) -> int:
        """Evaluate ``p(point)`` (Horner)."""
        return _evaluate(self._coeffs, _check_int(point, "point"))

    def eval_proof(self, point: object) -> EvalProof:
        """Open the commitment at ``point``: returns ``(value, proof)`` witness."""
        z = _check_int(point, "point")
        value = _evaluate(self._coeffs, z)
        return EvalProof(
            commitment_digest=_commitment_digest(self._coeffs),
            point=z,
            value=value,
            quotient_coeffs=_quotient_coeffs(self._coeffs, z),
            coeffs=self._coeffs,
        )


def verify(
    commitment: Commitment,
    point: object,
    value: object,
    proof: EvalProof,
) -> bool:
    """Check an evaluation opening against a commitment.

    Returns ``True`` iff the proof is well-formed *and* verifies:
    the proof names this commitment, the revealed coefficients re-derive
    the commitment digest, and the KZG quotient identity
    ``(x - z)*q(x) + y == p(x)`` holds coefficient-wise (which implies
    ``p(z) == y``). Malformed inputs raise ``PolyCommitmentError``;
    a well-formed proof that does not verify returns ``False`` (policy
    outcome, not an error).
    """
    if not isinstance(commitment, Commitment):
        raise PolyCommitmentError("commitment must be a Commitment")
    if not isinstance(proof, EvalProof):
        raise PolyCommitmentError("proof must be an EvalProof")
    z = _check_int(point, "point")
    y = _check_int(value, "value")

    # 1. The proof must name this commitment.
    if proof.commitment_digest != commitment.digest:
        return False
    # 2. The revealed coefficients must re-derive the commitment digest.
    if _commitment_digest(proof.coeffs) != commitment.digest:
        return False
    coeffs = proof.coeffs
    quotient = proof.quotient_coeffs
    # 3. Quotient shape must match the polynomial degree.
    if len(quotient) != len(coeffs) - 1:
        return False
    if proof.point != z or proof.value != y:
        return False
    # 4. KZG identity: (x - z)*q(x) + y == p(x), coefficient-wise.
    #    r_0 = y - z*q_0; r_k = q_{k-1} - z*q_k; r_m = q_{m-1}.
    m = len(quotient)
    if m == 0:
        if len(coeffs) != 1 or coeffs[0] != y:
            return False
    else:
        if y - z * quotient[0] != coeffs[0]:
            return False
        for k in range(1, m):
            if quotient[k - 1] - z * quotient[k] != coeffs[k]:
                return False
        if quotient[m - 1] != coeffs[m]:
            return False
    # 5. Defense-in-depth: direct evaluation agrees with the claimed value.
    return _evaluate(coeffs, z) == y


def poly_commitment_audit_event(
    kind: str, record: Mapping[str, object], seq: int
) -> dict:
    """Shape an ``audit.ndjson/1``-style record for a commitment event."""
    if kind not in _AUDIT_KINDS:
        raise PolyCommitmentError(f"kind must be one of {_AUDIT_KINDS}")
    if not isinstance(record, Mapping):
        raise PolyCommitmentError("record must be a mapping")
    seq = _check_seq(seq, "audit seq")
    return {
        "schema": SCHEMA_PIN,
        "kind": f"poly-commitment.{kind}",
        "record": dict(record),
        "audit_seq": seq,
    }


def main() -> None:
    # p(x) = 1 + 2x + 3x^2; p(2) = 17.
    pc = PolyCommitment([1, 2, 3])
    commitment = pc.commit()
    assert commitment.degree == 2, commitment
    assert commitment.n_coeffs == 3, commitment
    assert pc.evaluate(2) == 17, pc.evaluate(2)

    proof = pc.eval_proof(2)
    assert proof.value == 17, proof
    # q(x) = (p(x) - 17) / (x - 2) = 8 + 3x.
    assert proof.quotient_coeffs == (8, 3), proof.quotient_coeffs
    assert verify(commitment, 2, 17, proof) is True

    # Wrong value does not verify.
    assert verify(commitment, 2, 18, proof) is False
    # Tampered quotient does not verify.
    bad = EvalProof(
        commitment_digest=proof.commitment_digest,
        point=proof.point,
        value=proof.value,
        quotient_coeffs=(9, 3),
        coeffs=proof.coeffs,
    )
    assert verify(commitment, 2, 17, bad) is False

    # Canonicalization: trailing zeros commit identically.
    assert PolyCommitment([1, 2, 0, 0]).commit().digest == PolyCommitment([1, 2]).commit().digest

    # Zero and constant polynomials.
    zero = PolyCommitment([0])
    assert verify(zero.commit(), 5, 0, zero.eval_proof(5)) is True
    const = PolyCommitment([7])
    assert verify(const.commit(), -3, 7, const.eval_proof(-3)) is True

    print("poly-commitment OK: commit, open, verify; tampered proofs rejected")


if __name__ == "__main__":
    main()
