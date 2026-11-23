"""Bilinear accumulator interface: pairing-based set commitments (simulated).

Research motivation: Nguyen's bilinear accumulator (2005, "Accumulators
from Bilinear Pairings and Applications to ID-based Ring Signatures and
Group Membership Revocation") commits to a set ``S = {x_1, ..., x_n}`` as
a single constant-size group element ``A = g^{prod_i (x_i + s)}``, where
``s`` is a secret trapdoor. A member ``x_i`` proves membership with a
constant-size witness ``w_i = g^{prod_{j != i} (x_j + s)}``; anyone holding
the public parameters checks the pairing equation::

    e(w_i, g^{x_i + s}) == e(A, g)

Witnesses stay constant-size no matter how large the set grows, and the
accumulator is *dynamic*: elements can be added or removed (with the
trapdoor). This is the primitive behind pairing-based membership
revocation lists, allow-list proofs, and stateless set-membership checks.

What this module is:

* The mechanical bookkeeping half: ``add`` / ``remove`` / ``witness`` /
  ``verify`` over the accumulator's algebra, with frozen records, digest
  pins, and ``audit.ndjson/1`` events in house style.
* The pairing is *simulated* by exponent arithmetic in the BLS12-381
  scalar field: group elements are tracked by their discrete log, and
  ``e(w, g^{x+s}) == e(A, g)`` is checked as
  ``exp(w) * (x + s) == exp(A)  (mod p)``. The protocol logic -- witness
  structure, freshness binding, the verification equation -- is real;
  the cryptography is not.

Honest scope (read before relying on this):

* **Not a security boundary.** There is no real pairing, no trusted
  setup, and the simulated trapdoor is derived deterministically, so
  every instance shares the same simulated parameters. Do not use this
  to enforce membership against an adversary; use it to pin the
  *protocol logic* (who must present what witness, when witnesses go
  stale) in tests, audits, and design reviews.
* A real deployment needs a pairing-friendly curve (e.g. BLS12-381), a
  trusted (or updatable) setup ceremony for ``s``, and the public key
  ``(g, g^s, ..., g^{s^q})`` for the max accumulation size ``q``.
* ``verify`` returning ``True`` means "the pairing equation holds for
  the current accumulator value", never "an independent party agrees".
* Witnesses are bound to the accumulator value they were issued
  against: after any ``add`` / ``remove`` the accumulator moves on,
  outstanding witnesses are stale, and ``verify`` returns ``False``
  (a policy outcome, not an error) until the witness is refreshed.
* Non-membership proofs (also supported by Nguyen's construction) are
  not implemented here.
* No wall-clock anywhere; all seqs are caller-supplied ints.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any

#: Module version pin.
BILINEAR_ACCUMULATOR_VERSION = "bilinear-accumulator.v1"

#: Schema pin carried by records and audit events.
BILINEAR_ACCUMULATOR_SCHEMA = "northstar.bilinear-accumulator.v1"

#: Audit event kinds.
EVENT_ADDED = "accumulator-added"
EVENT_REMOVED = "accumulator-removed"
EVENT_WITNESS_ISSUED = "accumulator-witness-issued"
EVENT_VERIFIED = "accumulator-membership-verified"
EVENT_REJECTED = "accumulator-membership-rejected"

_EVENT_KINDS = frozenset(
    {EVENT_ADDED, EVENT_REMOVED, EVENT_WITNESS_ISSUED, EVENT_VERIFIED, EVENT_REJECTED}
)

#: Digest prefix for pinned values.
_DIGEST_PREFIX = "sha256:"

#: BLS12-381 scalar field order (prime). The simulation does its exponent
#: arithmetic in a real curve's field so the algebra is faithful; the
#: "pairing" itself is still simulated (see module docstring).
_FIELD_PRIME = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001

#: Domain separator for the deterministic simulated trapdoor.
_TRAPDOOR_DST = b"northstar.bilinear-accumulator.v1:trapdoor"


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _hex64(value: int) -> str:
    """Fixed-width 64-hex-char encoding of a field element (no >2**53 loss)."""
    return format(value, "064x")


class AccumulatorError(Exception):
    """Base error for accumulator bookkeeping (fail-closed)."""


class UnknownElementError(AccumulatorError):
    """Raised when witnessing/removing an element that is not accumulated."""


class CapacityExceededError(AccumulatorError):
    """Raised when adding beyond the configured max accumulation size."""


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied logical seq: non-negative int, bool rejected."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be >= 0")
    return value


def _check_max_size(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"max_size must be an int, got {type(value).__name__}")
    if value < 1:
        raise ValueError("max_size must be >= 1")
    return value


def _check_digest(value: object, name: str = "digest") -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string, got {type(value).__name__}")
    if not value.startswith(_DIGEST_PREFIX) or len(value) != len(_DIGEST_PREFIX) + 64:
        raise ValueError(f"{name} must look like 'sha256:' + 64 hex chars")
    return value


def _canonicalize_element(element: object) -> bytes:
    """Type-tagged canonical bytes for an element.

    ``"1"``, ``1`` and ``b"1"`` are distinct elements (no caller
    type-confusion collision). ``bool`` is rejected outright (``True == 1``
    would alias keys); empty str/bytes and negative ints are rejected.
    """
    if isinstance(element, bool):
        raise TypeError("element must not be a bool (True == 1 would alias elements)")
    if isinstance(element, str):
        if not element:
            raise ValueError("element string must be non-empty")
        return b"s:" + element.encode("utf-8")
    if isinstance(element, bytes):
        if not element:
            raise ValueError("element bytes must be non-empty")
        return b"b:" + element
    if isinstance(element, int):
        if element < 0:
            raise ValueError("element int must be >= 0")
        return b"i:" + str(element).encode("ascii")
    raise TypeError(
        f"element must be str, bytes, or int; got {type(element).__name__}"
    )


def _element_digest(canonical: bytes) -> str:
    return _DIGEST_PREFIX + _sha256(canonical).hex()


def _field_element(canonical: bytes) -> int:
    """Map an element's canonical bytes into the scalar field, never 0."""
    return (int.from_bytes(_sha256(canonical), "big") % (_FIELD_PRIME - 1)) + 1


def _simulated_trapdoor() -> int:
    """Deterministic simulated trapdoor ``s`` in [1, p-1].

    Simulation-only: every instance shares these parameters, which is
    precisely why this module is not a security boundary.
    """
    return (int.from_bytes(_sha256(_TRAPDOOR_DST), "big") % (_FIELD_PRIME - 1)) + 1


def _accumulator_digest(exponent: int, member_count: int, max_size: int) -> str:
    body = "|".join(
        (
            BILINEAR_ACCUMULATOR_VERSION,
            _hex64(exponent),
            str(member_count),
            str(max_size),
        )
    )
    return _DIGEST_PREFIX + _sha256(body.encode("ascii")).hex()


def _witness_digest(
    element_digest: str, accumulator_digest: str, witness_exponent: int
) -> str:
    body = "|".join(
        (
            BILINEAR_ACCUMULATOR_VERSION,
            "witness",
            element_digest,
            accumulator_digest,
            _hex64(witness_exponent),
        )
    )
    return _DIGEST_PREFIX + _sha256(body.encode("ascii")).hex()


@dataclass(frozen=True)
class AccumulatorValue:
    """The pinned accumulator state: ``A = g^{prod_i (x_i + s)}`` (simulated).

    The exponent is public in the real scheme (it *is* the accumulator
    value, up to the generator); only the trapdoor ``s`` is secret, and it
    never appears in any record.
    """

    exponent_hex: str
    member_count: int
    max_size: int
    digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.exponent_hex, str) or len(self.exponent_hex) != 64:
            raise ValueError("exponent_hex must be 64 hex chars")
        int(self.exponent_hex, 16)  # validates hex
        if isinstance(self.member_count, bool) or not isinstance(
            self.member_count, int
        ):
            raise TypeError("member_count must be an int")
        if self.member_count < 0:
            raise ValueError("member_count must be >= 0")
        _check_max_size(self.max_size)
        _check_digest(self.digest)

    def as_dict(self) -> dict:
        return {
            "schema": BILINEAR_ACCUMULATOR_SCHEMA,
            "exponent": self.exponent_hex,
            "member_count": self.member_count,
            "max_size": self.max_size,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class MembershipWitness:
    """A constant-size membership witness ``w_i`` for one element.

    Bound to the accumulator digest it was issued against: if the set
    changes, the accumulator moves on and this witness goes stale.
    """

    element_digest: str
    accumulator_digest: str
    witness_exponent_hex: str
    digest: str

    def __post_init__(self) -> None:
        _check_digest(self.element_digest, "element_digest")
        _check_digest(self.accumulator_digest, "accumulator_digest")
        if (
            not isinstance(self.witness_exponent_hex, str)
            or len(self.witness_exponent_hex) != 64
        ):
            raise ValueError("witness_exponent_hex must be 64 hex chars")
        int(self.witness_exponent_hex, 16)  # validates hex
        _check_digest(self.digest)

    def as_dict(self) -> dict:
        return {
            "schema": BILINEAR_ACCUMULATOR_SCHEMA,
            "element_digest": self.element_digest,
            "accumulator_digest": self.accumulator_digest,
            "witness_exponent": self.witness_exponent_hex,
            "digest": self.digest,
        }


class BilinearAccumulator:
    """Dynamic bilinear accumulator (simulated pairing).

    ``add`` / ``remove`` update the accumulated set; ``witness`` mints a
    constant-size membership witness; ``verify`` checks the simulated
    pairing equation ``exp(w) * (x + s) == exp(A) (mod p)`` against the
    *current* accumulator value.
    """

    def __init__(self, max_size: int = 64):
        self._max_size = _check_max_size(max_size)
        self._trapdoor = _simulated_trapdoor()
        self._lock = threading.RLock()
        # element_digest -> (original element, field element x)
        self._members: dict[str, tuple[Any, int]] = {}
        self._accumulator_exponent = 1  # empty set: A = g^1
        self._events: list[tuple[str, int, str]] = []

    @property
    def max_size(self) -> int:
        return self._max_size

    @property
    def member_count(self) -> int:
        return len(self._members)

    def members(self) -> tuple:
        """Original elements in insertion order (a view, not a proof)."""
        return tuple(original for original, _ in self._members.values())

    def value(self) -> AccumulatorValue:
        """The current pinned accumulator value."""
        return self._mint_value()

    def _mint_value(self) -> AccumulatorValue:
        exponent = self._accumulator_exponent
        count = len(self._members)
        return AccumulatorValue(
            exponent_hex=_hex64(exponent),
            member_count=count,
            max_size=self._max_size,
            digest=_accumulator_digest(exponent, count, self._max_size),
        )

    def _record(self, kind: str, seq: int, digest: str) -> None:
        self._events.append((kind, seq, digest))

    def events(self) -> tuple[tuple[str, int, str], ...]:
        """Append-only (kind, seq, digest) event log."""
        return tuple(self._events)

    def _accumulate_factor(self, field_element: int) -> int:
        """The ``(x + s)`` factor for one element; never 0 mod p."""
        factor = (field_element + self._trapdoor) % _FIELD_PRIME
        if factor == 0:
            # Degenerate for this trapdoor: probability ~2^-255, but the
            # simulation refuses deterministically rather than dividing by 0.
            raise AccumulatorError(
                "degenerate element: (x + s) == 0 mod p for the simulated trapdoor"
            )
        return factor

    def add(self, element: object, seq: int) -> AccumulatorValue:
        """Accumulate ``element``; duplicate adds are idempotent.

        Returns the (possibly unchanged) pinned accumulator value.
        """
        _check_seq(seq)
        canonical = _canonicalize_element(element)
        digest = _element_digest(canonical)
        with self._lock:
            if digest in self._members:
                current = self._mint_value()
                self._record(EVENT_ADDED, seq, current.digest)
                return current
            if len(self._members) >= self._max_size:
                raise CapacityExceededError(
                    f"accumulator full: {len(self._members)} >= max_size {self._max_size}"
                )
            field_element = _field_element(canonical)
            factor = self._accumulate_factor(field_element)
            self._accumulator_exponent = (
                self._accumulator_exponent * factor
            ) % _FIELD_PRIME
            self._members[digest] = (element, field_element)
            current = self._mint_value()
            self._record(EVENT_ADDED, seq, current.digest)
            return current

    def remove(self, element: object, seq: int) -> AccumulatorValue:
        """Remove ``element`` (dynamic accumulator); unknown elements raise."""
        _check_seq(seq)
        canonical = _canonicalize_element(element)
        digest = _element_digest(canonical)
        with self._lock:
            entry = self._members.get(digest)
            if entry is None:
                raise UnknownElementError(
                    f"element not accumulated: {digest[:19]}..."
                )
            _, field_element = entry
            factor = self._accumulate_factor(field_element)
            # Divide the factor back out: multiply by its modular inverse.
            self._accumulator_exponent = (
                self._accumulator_exponent * pow(factor, _FIELD_PRIME - 2, _FIELD_PRIME)
            ) % _FIELD_PRIME
            del self._members[digest]
            current = self._mint_value()
            self._record(EVENT_REMOVED, seq, current.digest)
            return current

    def witness(self, element: object) -> MembershipWitness:
        """Mint a membership witness for an accumulated element.

        ``w_i = g^{prod_{j != i} (x_j + s)}`` (simulated): the accumulator
        exponent divided by this element's factor.
        """
        canonical = _canonicalize_element(element)
        digest = _element_digest(canonical)
        with self._lock:
            entry = self._members.get(digest)
            if entry is None:
                raise UnknownElementError(
                    f"element not accumulated: {digest[:19]}..."
                )
            _, field_element = entry
            factor = self._accumulate_factor(field_element)
            witness_exponent = (
                self._accumulator_exponent
                * pow(factor, _FIELD_PRIME - 2, _FIELD_PRIME)
            ) % _FIELD_PRIME
            acc_value = self._mint_value()
            witness_hex = _hex64(witness_exponent)
            return MembershipWitness(
                element_digest=digest,
                accumulator_digest=acc_value.digest,
                witness_exponent_hex=witness_hex,
                digest=_witness_digest(digest, acc_value.digest, witness_exponent),
            )

    def verify(self, element: object, witness: MembershipWitness) -> bool:
        """Check the simulated pairing equation for ``element``.

        Returns ``True`` iff the witness is fresh (bound to the current
        accumulator value), names this element, and
        ``exp(w) * (x + s) == exp(A) (mod p)``. ``False`` is a policy
        outcome (stale witness, wrong element, bad algebra) -- malformed
        inputs raise fail-closed instead.
        """
        if not isinstance(witness, MembershipWitness):
            raise TypeError(
                f"witness must be a MembershipWitness, got {type(witness).__name__}"
            )
        canonical = _canonicalize_element(element)
        digest = _element_digest(canonical)
        if digest != witness.element_digest:
            return False
        with self._lock:
            current = self._mint_value()
            if witness.accumulator_digest != current.digest:
                return False  # stale witness: the set moved on
            field_element = _field_element(canonical)
            factor = self._accumulate_factor(field_element)
            witness_exponent = int(witness.witness_exponent_hex, 16)
            return (
                witness_exponent * factor
            ) % _FIELD_PRIME == self._accumulator_exponent


def bilinear_accumulator_audit_event(
    kind: str, record: AccumulatorValue | MembershipWitness, seq: int
) -> dict:
    """Shape an ``audit.ndjson/1`` record for an accumulator event."""
    if kind not in _EVENT_KINDS:
        raise ValueError(f"unknown event kind {kind!r}")
    if not isinstance(record, (AccumulatorValue, MembershipWitness)):
        raise TypeError(
            f"record must be an accumulator record, got {type(record).__name__}"
        )
    _check_seq(seq, "seq")
    return {
        "schema": "northstar.audit.ndjson/1",
        "event": kind,
        "module": BILINEAR_ACCUMULATOR_VERSION,
        "record": record.as_dict(),
        "audit_seq": seq,
    }


def main() -> None:
    acc = BilinearAccumulator(max_size=8)
    acc.add("alice", seq=1)
    acc.add("bob", seq=2)
    acc.add(42, seq=3)
    w = acc.witness("alice")
    assert acc.verify("alice", w) is True
    assert acc.verify("mallory", w) is False  # witness names alice, not mallory
    w_bob = acc.witness("bob")
    acc.add("carol", seq=4)
    assert acc.verify("bob", w_bob) is False  # stale after the set moved on
    w_bob2 = acc.witness("bob")
    assert acc.verify("bob", w_bob2) is True
    acc.remove("alice", seq=5)
    assert acc.verify("alice", w) is False  # removed: fresh witness impossible
    try:
        acc.witness("alice")
    except UnknownElementError:
        pass
    else:
        raise AssertionError("witness for removed element must raise")
    print("bilinear-accumulator OK: add, witness, verify, stale-witness, remove")


if __name__ == "__main__":
    main()
