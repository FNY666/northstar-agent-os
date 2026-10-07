"""MPC interface: Shamir secret sharing + linear share arithmetic (simulated).

Research motivation: secure multi-party computation (Yao 1982; Goldreich,
Micali, Wigderson 1987) lets ``n`` parties compute a joint function over
private inputs without revealing them. The workhorse underneath is
*secret sharing*: Shamir's (t, n) threshold scheme (1979) splits a secret
``s`` into ``n`` shares so that any ``t`` shares reconstruct ``s`` while
any fewer reveal nothing. The BGW protocol (Ben-Or, Goldwasser, Wigderson
1988) then evaluates arithmetic circuits *on the shares*: addition is
local (parties add their shares pointwise -- a degree ``t-1`` polynomial
plus a degree ``t-1`` polynomial is a degree ``t-1`` sharing of the sum),
multiplication needs one interactive degree-reduction round.

What this module is:

* The mechanical bookkeeping half: ``share`` / ``reconstruct`` /
  ``add_shares`` over a prime field, with frozen ``Share`` records,
  digest pins, and ``audit.ndjson/1`` events in house style.
* Shamir sharing is real algebra: a random degree ``t-1`` polynomial
  ``p`` with ``p(0) = secret``; share ``i`` is ``p(i)``; reconstruction is
  Lagrange interpolation at ``x = 0``; ``add_shares`` is pointwise
  modular addition, which is exactly BGW's local addition step.

Honest scope (read before relying on this):

* **Not a security boundary; simulated.** The polynomial coefficients are
  derived *deterministically* from the secret via a SHA-256 KDF, so two
  sharings of the same ``(secret, n, t)`` are byte-identical. Real Shamir
  sharing needs fresh randomness per sharing (a CSPRNG) plus secure
  channels to each party; without it there is no hiding property at all.
  Do not use this to protect a real secret from an adversary.
* Shares are *unauthenticated*: there is no Feldman/Pedersen VSS
  commitment, so ``reconstruct`` cannot detect a corrupted share -- it
  will silently interpolate the wrong secret. A real deployment needs
  verifiable secret sharing or authenticated (MAC'd) shares.
* ``reconstruct`` is fail-closed on *fewer than t* shares: it raises
  rather than guessing. With exactly ``t`` shares the answer is exact;
  with more, Lagrange still lands on ``p(0)``.
* Only linear operations are local. Multiplication of shared secrets
  needs BGW's interactive degree-reduction ( Beaver triples in modern
  form) and is deliberately *not* implemented here.
* Field: the Mersenne prime ``P = 2**61 - 1``. Secrets must satisfy
  ``0 <= secret < P``. Arithmetic that would overflow a real deployment's
  field must be reduced by the host before sharing.
* No wall-clock anywhere; no randomness; fully deterministic.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

#: Module version pin.
MPC_INTERFACE_VERSION = "mpc-interface.v1"

#: Schema pin carried by records and audit events.
MPC_INTERFACE_SCHEMA = "northstar.mpc-interface.v1"

#: Audit event kinds.
EVENT_SHARED = "mpc-secret-shared"
EVENT_RECONSTRUCTED = "mpc-secret-reconstructed"
EVENT_SHARES_ADDED = "mpc-shares-added"
EVENT_REJECTED = "mpc-operation-rejected"

_EVENT_KINDS = frozenset(
    {EVENT_SHARED, EVENT_RECONSTRUCTED, EVENT_SHARES_ADDED, EVENT_REJECTED}
)

#: Digest prefix for pinned values.
_DIGEST_PREFIX = "sha256:"

#: Field prime: 2**61 - 1 (Mersenne prime, fits in 64 bits). All share
#: arithmetic happens in F_P.
FIELD_PRIME = (1 << 61) - 1

#: Domain separation for the deterministic coefficient KDF.
_KDF_DOMAIN = b"northstar-mpc.v1/coeff"


class MPCError(Exception):
    """Base error for the MPC interface (fail-closed)."""


class ShareValidationError(MPCError):
    """A share or sharing parameter failed validation."""


class ReconstructionError(MPCError):
    """Reconstruction was refused (too few shares, inconsistent set)."""


def _reject_bool(value: Any, name: str) -> None:
    # bool is a subclass of int; True == 1 would alias share ids and
    # thresholds, so bools are always rejected at the boundary.
    if isinstance(value, bool):
        raise TypeError(f"{name} must not be bool")


def _check_int(value: Any, name: str) -> int:
    _reject_bool(value, name)
    if not isinstance(value, int):
        raise TypeError(f"{name} must be int, got {type(value).__name__}")
    return value


def _kdf_coeff(secret: int, n: int, t: int, index: int) -> int:
    """Deterministic stand-in for the random polynomial coefficients.

    Real Shamir sharing draws c_1..c_{t-1} uniformly from the field.
    Here they are derived from SHA-256 so the module stays deterministic
    (no RNG, no wall-clock) and test fixtures are reproducible. This is
    precisely what makes the simulation *not* a hiding scheme: see the
    honest-scope docstring.
    """
    body = (
        _KDF_DOMAIN
        + b"\x00"
        + secret.to_bytes(8, "big")
        + b"\x00"
        + n.to_bytes(8, "big")
        + b"\x00"
        + t.to_bytes(8, "big")
        + b"\x00"
        + index.to_bytes(8, "big")
    )
    return int(hashlib.sha256(body).hexdigest(), 16) % FIELD_PRIME


def _eval_poly(coeffs: Sequence[int], x: int) -> int:
    """Horner evaluation of sum(coeffs[i] * x**i) mod FIELD_PRIME."""
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % FIELD_PRIME
    return acc


def _modinv(a: int) -> int:
    """Modular inverse via Fermat (FIELD_PRIME is prime; a != 0)."""
    return pow(a, FIELD_PRIME - 2, FIELD_PRIME)


def _lagrange_at_zero(points: Sequence[tuple[int, int]]) -> int:
    """Interpolate the unique degree <k polynomial through ``points`` at x=0.

    ``points`` are (x_i, y_i) with distinct nonzero x_i. Standard Lagrange
    basis evaluated at 0:

        p(0) = sum_i y_i * prod_{j != i} x_j / (x_j - x_i)
    """
    total = 0
    for i, (xi, yi) in enumerate(points):
        num = 1
        den = 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            num = (num * xj) % FIELD_PRIME
            den = (den * (xj - xi)) % FIELD_PRIME
        total = (total + yi * num % FIELD_PRIME * _modinv(den)) % FIELD_PRIME
    return total


@dataclass(frozen=True)
class Share:
    """One Shamir share: the evaluation of the sharing polynomial at x=share_id.

    ``value`` is ``p(share_id) mod FIELD_PRIME``. The ``n``/``threshold``
    pins let ``reconstruct`` and ``add_shares`` fail closed on mismatched
    sharings instead of silently mixing them.
    """

    share_id: int
    value: int
    n: int
    threshold: int

    def __post_init__(self) -> None:
        _check_int(self.share_id, "share_id")
        _check_int(self.value, "value")
        _check_int(self.n, "n")
        _check_int(self.threshold, "threshold")
        if not 1 <= self.share_id <= self.n:
            raise ShareValidationError("share_id out of range 1..n")
        if not 0 <= self.value < FIELD_PRIME:
            raise ShareValidationError("share value out of field range")
        if self.n < 1:
            raise ShareValidationError("n must be >= 1")
        if not 1 <= self.threshold <= self.n:
            raise ShareValidationError("threshold must satisfy 1 <= t <= n")

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": MPC_INTERFACE_SCHEMA,
            "share_id": self.share_id,
            "value": self.value,
            "n": self.n,
            "threshold": self.threshold,
            "field_prime": FIELD_PRIME,
        }


def _validate_share_params(secret: int, n: int, t: int) -> None:
    _check_int(secret, "secret")
    _check_int(n, "n")
    _check_int(t, "t")
    if not 0 <= secret < FIELD_PRIME:
        raise ValueError("secret must satisfy 0 <= secret < FIELD_PRIME")
    if n < 1:
        raise ValueError("n must be >= 1")
    if not 1 <= t <= n:
        raise ValueError("threshold must satisfy 1 <= t <= n")


class MPC:
    """Shamir (t, n) secret sharing over F_{2**61-1} (simulated).

    Deterministic: the "random" polynomial coefficients come from a
    SHA-256 KDF, so there is no hiding property -- see module docstring.
    The sharing/reconstruction/addition *algebra* is exact.
    """

    #: Pinned field prime (class-level so hosts can read it).
    field_prime: int = FIELD_PRIME

    def share(self, secret: int, n: int, t: int) -> tuple[Share, ...]:
        """Split ``secret`` into ``n`` shares with reconstruction threshold ``t``.

        Builds ``p(x) = secret + c_1 x + ... + c_{t-1} x^{t-1}`` and
        returns ``(Share(1, p(1)), ..., Share(n, p(n)))``.
        """
        _validate_share_params(secret, n, t)
        coeffs = [secret] + [_kdf_coeff(secret, n, t, i) for i in range(1, t)]
        return tuple(
            Share(share_id=i, value=_eval_poly(coeffs, i), n=n, threshold=t)
            for i in range(1, n + 1)
        )

    def reconstruct(self, shares: Iterable[Share]) -> int:
        """Recover the secret from ``t`` or more shares (Lagrange at x=0).

        Fail-closed: fewer than ``t`` shares, duplicate share ids, mixed
        thresholds, or non-``Share`` inputs all raise instead of guessing.
        """
        items = list(shares)
        if not items:
            raise ReconstructionError("no shares provided")
        for s in items:
            if not isinstance(s, Share):
                raise TypeError(
                    f"shares must be Share records, got {type(s).__name__}"
                )
        thresholds = {s.threshold for s in items}
        if len(thresholds) != 1:
            raise ReconstructionError("shares disagree on threshold")
        ns = {s.n for s in items}
        if len(ns) != 1:
            raise ReconstructionError("shares disagree on n")
        t = thresholds.pop()
        if len(items) < t:
            raise ReconstructionError(
                f"need at least {t} shares, got {len(items)}"
            )
        ids = [s.share_id for s in items]
        if len(set(ids)) != len(ids):
            raise ReconstructionError("duplicate share_id in share set")
        points = [(s.share_id, s.value) for s in items]
        return _lagrange_at_zero(points)

    def add_shares(
        self, shares_a: Iterable[Share], shares_b: Iterable[Share]
    ) -> tuple[Share, ...]:
        """BGW local addition: pointwise share addition of two sharings.

        If ``shares_a`` shares secret ``x`` and ``shares_b`` shares secret
        ``y`` under the *same* ``(n, t)``, the result shares ``x + y``
        (mod FIELD_PRIME): ``p(x) + q(x)`` is a degree ``t-1`` sharing of
        the sum. The two vectors must carry the same share ids.
        """
        a = list(shares_a)
        b = list(shares_b)
        if not a or not b:
            raise ShareValidationError("both share vectors must be non-empty")
        for s in a + b:
            if not isinstance(s, Share):
                raise TypeError(
                    f"shares must be Share records, got {type(s).__name__}"
                )
        if len(a) != len(b):
            raise ShareValidationError("share vectors have different lengths")
        meta_a = {(s.n, s.threshold) for s in a}
        meta_b = {(s.n, s.threshold) for s in b}
        if len(meta_a) != 1 or len(meta_b) != 1:
            raise ShareValidationError("inconsistent (n, threshold) in a vector")
        if meta_a != meta_b:
            raise ShareValidationError(
                "share vectors use different (n, threshold)"
            )
        ids_a = [s.share_id for s in a]
        ids_b = [s.share_id for s in b]
        if sorted(ids_a) != sorted(ids_b):
            raise ShareValidationError("share vectors cover different share ids")
        if len(set(ids_a)) != len(ids_a):
            raise ShareValidationError("duplicate share_id in share vector")
        n, t = meta_a.pop()
        b_by_id = {s.share_id: s.value for s in b}
        return tuple(
            Share(
                share_id=s.share_id,
                value=(s.value + b_by_id[s.share_id]) % FIELD_PRIME,
                n=n,
                threshold=t,
            )
            for s in sorted(a, key=lambda s: s.share_id)
        )

    def share_digest(self, shares: Iterable[Share]) -> str:
        """Pin a share vector with a ``sha256:`` digest (audit aid).

        Binds the ordered (share_id, value, n, threshold) tuples. This pins
        *integrity of the vector as handled*, not secrecy.
        """
        items = list(shares)
        for s in items:
            if not isinstance(s, Share):
                raise TypeError("shares must be Share records")
        body = "|".join(
            f"{s.share_id}:{s.value}:{s.n}:{s.threshold}" for s in items
        )
        return _DIGEST_PREFIX + hashlib.sha256(body.encode()).hexdigest()


def mpc_audit_event(kind: str, seq: int, **fields: Any) -> dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for an MPC operation.

    ``seq`` is caller-supplied (no wall-clock). Unknown kinds and
    non-int/bool/negative seqs are rejected fail-closed.
    """
    _reject_bool(seq, "seq")
    if kind not in _EVENT_KINDS:
        raise ValueError(f"unknown MPC audit event kind: {kind!r}")
    if not isinstance(seq, int):
        raise TypeError("seq must be int")
    if seq < 0:
        raise ValueError("seq must be non-negative")
    event: dict[str, Any] = {
        "schema": "audit.ndjson/1",
        "module": MPC_INTERFACE_SCHEMA,
        "kind": kind,
        "audit_seq": seq,
    }
    event.update(fields)
    return event


def main() -> None:
    mpc = MPC()
    shares = mpc.share(42, n=5, t=3)
    assert len(shares) == 5
    assert mpc.reconstruct(shares[:3]) == 42
    assert mpc.reconstruct(shares) == 42  # more than t is fine
    try:
        mpc.reconstruct(shares[:2])
    except ReconstructionError:
        pass
    else:
        raise AssertionError("reconstruct with < t shares must raise")
    a = mpc.share(100, n=5, t=3)
    b = mpc.share(23, n=5, t=3)
    summed = mpc.add_shares(a, b)
    assert mpc.reconstruct(summed) == 123  # BGW local addition
    assert mpc.share_digest(shares) == mpc.share_digest(mpc.share(42, 5, 3))
    print("mpc-interface OK: share, reconstruct, add_shares, fail-closed <t")


if __name__ == "__main__":
    main()
