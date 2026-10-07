"""RSA accumulator interface (simulated).

Research motivation: an *accumulator* compresses a set into one short
value plus per-element *witnesses* that prove membership without
revealing the whole set. RSA accumulators (Benaloh-de Mare 1993;
Baric-Pfitzmann 1997) work as ``A = g^(p1 * p2 * ... * pn) mod N`` where
each member maps to a distinct prime ``pi``; the witness for ``pi`` is
``g^(product / pi) mod N`` -- the accumulator with that one factor
divided out -- and verification re-multiplies: ``witness^pi == A``.

This module models that construction's *interface and state machine*
with the RSA replaced by deterministic hashing:

- ``element_prime(element)`` -- the hash-to-prime representative mapping
  (real accumulators need this step too); a deterministic 32-bit prime
  in ``[2**31, 2**32)`` derived from ``sha256`` of the element.
- The accumulator value is a ``sha256:`` pin over the sorted prime set
  (standing in for ``g^product mod N``).
- ``witness(element)`` returns the pin inputs for the set *minus* the
  element's prime -- the structural analogue of ``g^(product/pi)``.
- ``verify(element, witness, digest=None)`` re-inserts the prime and
  checks the pin, i.e. the analogue of ``witness^pi == A``.

Public API:

- ``element_prime(element)`` -- deterministic prime representative.
- ``RSAAccumulator`` -- RLock-guarded set with ``add`` / ``remove`` /
  ``witness`` / ``verify`` / ``accumulator_digest`` / ``contains`` /
  ``members`` / ``member_count`` / ``events``.
- ``MembershipWitness`` -- frozen record binding element, prime, the
  accumulator digest it was issued against, and the other primes.
- ``rsa_accumulator_audit_event(kind, element, seq, digest=None)`` --
  ``audit.ndjson/1``-shaped record; kinds ``"add"`` / ``"remove"`` /
  ``"witness-issued"``.
- ``RSAAccumulatorError`` / ``UnknownElementError``.

Honest scope:

- **Simulated, not RSA.** There is no modulus, no trapdoor, no group.
  None of the real security properties (collision-resistance under the
  strong-RSA assumption) transfer. Do not use this where an adversarial
  prover exists; it is an interface/state-machine model for wiring and
  testing accumulator-shaped protocols.
- Witnesses here are ``O(n)`` and reveal the member prime set. Real RSA
  witnesses are constant-size and opaque. The algebra is preserved
  (divide-out / re-multiply becomes set-minus / re-insert); the
  succinctness is not.
- ``verify`` checks structural consistency and digest equality. It
  cannot detect a host that lies about the member set -- accumulator
  state is host-held, like every other module in this runtime.
- Distinct elements map to distinct 32-bit primes with overwhelming
  probability (``2**32`` space); the mapping is deterministic, so a
  re-added element always recovers its original prime.
- A witness is issued against one accumulator digest. After any
  add/remove the digest changes and old witnesses verify as ``False``
  against the *current* state; pass the historical digest explicitly to
  check a witness against the state it was issued for.

Version pin: ``rsa-accumulator.v1`` / schema pin
``northstar.rsa-accumulator.v1``.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Union

#: Module version.
RSA_ACCUMULATOR_VERSION = "rsa-accumulator.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.rsa-accumulator.v1"

#: Version pin carried inside audit records.
AUDIT_FORMAT = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
_AUDIT_KINDS = frozenset({"add", "remove", "witness-issued"})

#: Domain separator for the hash-to-prime mapping.
_PRIME_DOMAIN = b"northstar.rsa-accumulator.prime-v1\x00"

#: Elements are str or bytes, non-empty, bounded.
_MAX_ELEMENT_BYTES = 4096

#: Prime representatives live in [2**31, 2**32).
_PRIME_LO = 1 << 31
_PRIME_HI = 1 << 32


class RSAAccumulatorError(Exception):
    """Base error for accumulator failures."""


class UnknownElementError(RSAAccumulatorError):
    """Raised when addressing an element that is not a member."""


def _check_element(element: object) -> bytes:
    """Validate an element. Returns its canonical key, or raises fail-closed.

    ``str`` and ``bytes`` are type-tagged so ``"a"`` and ``b"a"`` are
    distinct members (no caller type-confusion collision).
    """
    if isinstance(element, bool) or not isinstance(element, (str, bytes)):
        raise TypeError(
            f"element must be str or bytes, got {type(element).__name__}"
        )
    if isinstance(element, str):
        raw = element.encode("utf-8")
        if not raw:
            raise ValueError("element must be non-empty")
        if len(raw) > _MAX_ELEMENT_BYTES:
            raise ValueError(
                f"element exceeds {_MAX_ELEMENT_BYTES} bytes"
            )
        return b"s\x00" + raw
    raw = bytes(element)
    if not raw:
        raise ValueError("element must be non-empty")
    if len(raw) > _MAX_ELEMENT_BYTES:
        raise ValueError(f"element exceeds {_MAX_ELEMENT_BYTES} bytes")
    return b"b\x00" + raw


def _check_seq(seq: object) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError(f"seq must be int, got {type(seq).__name__}")
    if seq < 0:
        raise ValueError("seq must be non-negative")
    return seq


def _is_prime(n: int) -> bool:
    """Deterministic Miller-Rabin, exact for n < 2**32 (bases 2, 7, 61)."""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in (2, 7, 61):
        if a % n == 0:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def element_prime(element: Union[str, bytes]) -> int:
    """Deterministic prime representative for ``element``.

    Mirrors the hash-to-prime step of real RSA accumulators: the same
    element always maps to the same 32-bit prime, distinct elements map
    to distinct primes with overwhelming probability.
    """
    key = _check_element(element)
    seed = int.from_bytes(
        hashlib.sha256(_PRIME_DOMAIN + key).digest()[:4], "big"
    )
    candidate = (seed | _PRIME_LO) | 1  # odd, in [2**31, 2**32)
    while True:
        if _is_prime(candidate):
            return candidate
        candidate += 2
        if candidate >= _PRIME_HI:
            candidate = _PRIME_LO | 1


def _canonical(value: object) -> bytes:
    """Deterministic encoding for digest pinning.

    Ints are encoded in hex (never via float), so there is no >2**53
    precision loss of the kind documented in ``secure_aggregation``.
    """
    if value is None:
        return b"n:"
    if value is True:
        return b"t:"
    if value is False:
        return b"f:"
    if isinstance(value, int):
        hexpart = format(-value, "x") if value < 0 else format(value, "x")
        sign = b"-" if value < 0 else b""
        return b"i:" + sign + hexpart.encode("ascii")
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return b"s:" + str(len(raw)).encode("ascii") + b":" + raw
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        return b"b:" + str(len(raw)).encode("ascii") + b":" + raw
    if isinstance(value, (list, tuple)):
        return b"l:" + b",".join(_canonical(v) for v in value) + b";"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: _canonical(kv[0]))
        return (
            b"d:"
            + b",".join(_canonical(k) + b"=" + _canonical(v) for k, v in items)
            + b";"
        )
    raise TypeError(f"cannot canonicalize {type(value).__name__}")


def _pin(obj: object) -> str:
    """``sha256:`` digest pin over the canonical encoding."""
    return "sha256:" + hashlib.sha256(_canonical(obj)).hexdigest()


def _element_ref(element: Union[str, bytes]) -> dict:
    """JSON-safe element reference for audit records."""
    if isinstance(element, str):
        return {"type": "str", "value": element}
    return {"type": "bytes", "hex": bytes(element).hex()}


@dataclass(frozen=True)
class MembershipWitness:
    """Frozen membership witness issued against one accumulator digest.

    ``other_primes`` is the sorted prime set *minus* this element's
    prime -- the structural analogue of ``g^(product/pi) mod N``.
    Verification re-inserts ``element_prime`` and re-pins.
    """

    element: Union[str, bytes]
    element_prime: int
    accumulator_digest: str
    other_primes: Tuple[int, ...]
    member_count: int

    def __post_init__(self) -> None:
        _check_element(self.element)
        if isinstance(self.element_prime, bool) or not isinstance(
            self.element_prime, int
        ):
            raise TypeError(
                "element_prime must be int, "
                f"got {type(self.element_prime).__name__}"
            )
        if self.element_prime <= 0:
            raise ValueError("element_prime must be positive")
        if not isinstance(self.accumulator_digest, str) or not (
            self.accumulator_digest.startswith("sha256:")
        ):
            raise ValueError("accumulator_digest must be a 'sha256:' pin")
        if not isinstance(self.other_primes, (tuple, list)):
            raise TypeError("other_primes must be a tuple of ints")
        clean: List[int] = []
        for p in self.other_primes:
            if isinstance(p, bool) or not isinstance(p, int):
                raise TypeError(
                    f"other_primes entries must be int, got {type(p).__name__}"
                )
            if p <= 0:
                raise ValueError("other_primes entries must be positive")
            clean.append(p)
        object.__setattr__(self, "other_primes", tuple(clean))
        if isinstance(self.member_count, bool) or not isinstance(
            self.member_count, int
        ):
            raise TypeError(
                f"member_count must be int, got {type(self.member_count).__name__}"
            )
        if self.member_count < 1:
            raise ValueError("member_count must be >= 1")

    def witness_digest(self) -> str:
        """Pin binding this witness's own contents."""
        return _pin(
            {
                "element_prime": self.element_prime,
                "accumulator_digest": self.accumulator_digest,
                "other_primes": list(self.other_primes),
                "member_count": self.member_count,
            }
        )

    def as_dict(self) -> dict:
        """JSON-safe record with the schema pin."""
        return {
            "schema": SCHEMA_PIN,
            "element": _element_ref(self.element),
            "element_prime": format(self.element_prime, "x"),
            "accumulator_digest": self.accumulator_digest,
            "other_primes": [format(p, "x") for p in self.other_primes],
            "member_count": self.member_count,
            "witness_digest": self.witness_digest(),
        }


class RSAAccumulator:
    """Simulated RSA accumulator: prime-pinned set with witnesses.

    RLock-guarded; all state transitions are deterministic and
    order-independent (the digest depends only on the member set).
    No wall-clock anywhere; caller seqs only appear in audit records.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._members: Dict[bytes, Tuple[Union[str, bytes], int]] = {}
        self._event_seq = 0
        self._events: List[dict] = []

    def _record(self, kind: str, element: Union[str, bytes]) -> None:
        self._event_seq += 1
        self._events.append(
            {
                "format": AUDIT_FORMAT,
                "schema": SCHEMA_PIN,
                "kind": kind,
                "element": _element_ref(element),
                "seq": self._event_seq,
                "digest": self.accumulator_digest(),
            }
        )

    def add(self, element: Union[str, bytes]) -> bool:
        """Add ``element``. Returns True when newly added, False when
        already a member (idempotent, matching accumulator math)."""
        key = _check_element(element)
        with self._lock:
            if key in self._members:
                return False
            original = element if isinstance(element, str) else bytes(element)
            self._members[key] = (original, element_prime(element))
            self._record("add", original)
            return True

    def remove(self, element: Union[str, bytes]) -> bool:
        """Remove ``element``. Raises ``UnknownElementError`` when the
        element is not a member (fail-closed: removing a non-member is a
        caller bug, never a silent no-op)."""
        key = _check_element(element)
        with self._lock:
            if key not in self._members:
                raise UnknownElementError(
                    f"element not in accumulator: {element!r}"
                )
            original = self._members[key][0]
            del self._members[key]
            self._record("remove", original)
            return True

    def contains(self, element: Union[str, bytes]) -> bool:
        """Membership test against current state."""
        key = _check_element(element)
        with self._lock:
            return key in self._members

    def members(self) -> Tuple[Union[str, bytes], ...]:
        """Current members, ordered by canonical key (deterministic)."""
        with self._lock:
            return tuple(
                self._members[key][0] for key in sorted(self._members)
            )

    def member_count(self) -> int:
        """Number of current members."""
        with self._lock:
            return len(self._members)

    def accumulator_digest(self) -> str:
        """``sha256:`` pin over the sorted prime set.

        Depends only on the member *set*: insertion order never matters.
        """
        with self._lock:
            primes = sorted(p for _, p in self._members.values())
        return _pin({"primes": primes})

    def witness(self, element: Union[str, bytes]) -> MembershipWitness:
        """Issue a membership witness for ``element`` against the current
        digest. Raises ``UnknownElementError`` for non-members."""
        key = _check_element(element)
        with self._lock:
            if key not in self._members:
                raise UnknownElementError(
                    f"element not in accumulator: {element!r}"
                )
            original, prime = self._members[key]
            others = sorted(
                p for k, (_, p) in self._members.items() if k != key
            )
            wit = MembershipWitness(
                element=original,
                element_prime=prime,
                accumulator_digest=self.accumulator_digest(),
                other_primes=tuple(others),
                member_count=len(self._members),
            )
            self._record("witness-issued", original)
            return wit

    def verify(
        self,
        element: Union[str, bytes],
        witness: MembershipWitness,
        digest: Optional[str] = None,
    ) -> bool:
        """Verify ``witness`` for ``element``.

        Re-derives the prime, checks the witness is internally
        consistent (re-insert + re-pin matches the digest it was issued
        against), then checks that digest against ``digest`` -- or the
        *current* accumulator digest when ``digest`` is None. Returns a
        boolean verdict; raises only on bad *types*, never on a failed
        proof.
        """
        if not isinstance(witness, MembershipWitness):
            raise TypeError(
                f"witness must be MembershipWitness, "
                f"got {type(witness).__name__}"
            )
        _check_element(element)
        if digest is not None and not isinstance(digest, str):
            raise TypeError(
                f"digest must be str or None, got {type(digest).__name__}"
            )
        prime = element_prime(element)
        if prime != witness.element_prime:
            return False
        if witness.element != element:
            return False
        expected = _pin(
            {"primes": sorted(witness.other_primes + (prime,))}
        )
        if expected != witness.accumulator_digest:
            return False
        target = digest if digest is not None else self.accumulator_digest()
        return witness.accumulator_digest == target

    def events(self) -> Tuple[dict, ...]:
        """Append-only mutation log (audit-shaped dicts)."""
        with self._lock:
            return tuple(dict(e) for e in self._events)


def rsa_accumulator_audit_event(
    kind: str,
    element: Union[str, bytes],
    seq: int,
    digest: Optional[str] = None,
) -> dict:
    """Build an ``audit.ndjson/1``-shaped record for an accumulator op.

    ``kind`` is one of ``"add"`` / ``"remove"`` / ``"witness-issued"``.
    """
    if not isinstance(kind, str) or kind not in _AUDIT_KINDS:
        raise ValueError(f"kind must be one of {sorted(_AUDIT_KINDS)}")
    _check_element(element)
    event = {
        "format": AUDIT_FORMAT,
        "schema": SCHEMA_PIN,
        "kind": kind,
        "element": _element_ref(element),
        "seq": _check_seq(seq),
    }
    if digest is not None:
        if not isinstance(digest, str):
            raise TypeError(
                f"digest must be str or None, got {type(digest).__name__}"
            )
        event["digest"] = digest
    return event


def main() -> None:
    """Self-check: add/remove, witnesses, verify, order-independence."""
    acc = RSAAccumulator()
    assert acc.add("alice") is True
    assert acc.add("alice") is False  # idempotent
    assert acc.add(b"bob") is True
    assert acc.member_count() == 2
    assert acc.contains("alice") and not acc.contains("mallory")

    d1 = acc.accumulator_digest()
    assert d1.startswith("sha256:")

    w = acc.witness("alice")
    assert acc.verify("alice", w)
    assert not acc.verify("mallory", w)  # prime mismatch
    assert not acc.verify(b"alice", w)  # type-tagged: b"alice" != "alice"

    # Digest depends only on the set, never insertion order.
    acc2 = RSAAccumulator()
    acc2.add(b"bob")
    acc2.add("alice")
    assert acc2.accumulator_digest() == d1
    assert acc2.verify("alice", w)  # witness is state-bound, not host-bound

    # Removal invalidates the witness against current state...
    acc.remove("alice")
    assert not acc.verify("alice", w)
    # ...but it still checks against the historical digest it was issued for.
    assert acc.verify("alice", w, digest=d1)

    # Re-adding recovers the original prime (deterministic mapping).
    assert acc.add("alice") is True
    assert element_prime("alice") == w.element_prime
    assert acc.accumulator_digest() == d1

    try:
        acc.witness("mallory")
        raise AssertionError("expected UnknownElementError")
    except UnknownElementError:
        pass
    try:
        acc.remove("mallory")
        raise AssertionError("expected UnknownElementError")
    except UnknownElementError:
        pass

    # Tampered witness fails closed.
    bad = MembershipWitness(
        element="alice",
        element_prime=w.element_prime,
        accumulator_digest=w.accumulator_digest,
        other_primes=w.other_primes + (3,),
        member_count=w.member_count,
    )
    assert not acc.verify("alice", bad)

    print("rsa-accumulator OK: add/remove, witness, verify, order-independent")
    print("audit:", rsa_accumulator_audit_event("add", "alice", 1, d1)["kind"])


if __name__ == "__main__":
    main()
