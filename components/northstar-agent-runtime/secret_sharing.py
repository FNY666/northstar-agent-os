"""Shamir secret sharing for key backup (simulated).

Research motivation: Shamir's (t, n) threshold scheme (1979) splits a
secret into ``n`` shares so that any ``t`` shares reconstruct it while
any fewer reveal nothing. This is the standard primitive for *key
backup*: an operator's master key is split across custodians, HSMs, or
paper envelopes, and recovery needs a quorum.

What this module is:

* The byte-oriented mechanical half of key backup: ``split`` /
  ``recover`` over raw key bytes, with frozen ``BackupShare`` records,
  digest pins, and ``audit.ndjson/1`` events in house style.
* The *algebra* is real Shamir sharing: the secret is chunked into
  7-byte words over the Mersenne prime field ``P = 2**61 - 1``, each
  chunk gets its own random degree ``t-1`` polynomial, and recovery is
  Lagrange interpolation at ``x = 0`` per chunk.

How this differs from ``mpc_interface``:

* ``mpc_interface`` shares *integers* for live computation (BGW local
  addition); this module shares *byte strings* for offline backup --
  exact byte round-trips, leading-zero preservation, arbitrary key
  lengths, and a ``secret_len`` pin so padding is stripped on recovery.
* The polynomial coefficients here are KDF-derived from the
  *secret digest plus the chunk index* (domain-separated from
  ``mpc_interface``), so sharing the same bytes under this module and
  under ``mpc_interface`` never produces the same share set.

Honest scope (read before relying on this):

* **Not a security boundary; simulated.** The polynomial coefficients
  are derived *deterministically* from the secret via a SHA-256 KDF, so
  two splits of the same ``(secret, n, t)`` are byte-identical. Real
  Shamir backup needs fresh randomness per split (a CSPRNG) plus secure
  distribution to each custodian; without it there is no hiding property
  at all. Do not use this to protect a real key from an adversary.
* Shares are *unauthenticated*: there is no Feldman/Pedersen VSS
  commitment, so ``recover`` cannot detect a corrupted share -- it will
  silently interpolate the wrong bytes. A real deployment needs
  verifiable secret sharing or MAC'd shares.
* ``recover`` is fail-closed on *fewer than t* shares: it raises rather
  than guessing. With exactly ``t`` shares the recovery is exact; with
  more, Lagrange still lands on the same bytes.
* Secrets must fit the field chunking: words are 7-byte big-endian
  integers, so every chunk is `< 2**56 < FIELD_PRIME` by construction.
  The secret length is unbounded (shares scale linearly in chunks).
* No wall-clock anywhere; no randomness; fully deterministic.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

#: Module version pin.
SECRET_SHARING_VERSION = "secret-sharing.v1"

#: Schema pin carried by records and audit events.
SECRET_SHARING_SCHEMA = "northstar.secret-sharing.v1"

#: Audit event kinds.
EVENT_SPLIT = "secret-shared"
EVENT_RECOVERED = "secret-recovered"
EVENT_REJECTED = "secret-operation-rejected"

_EVENT_KINDS = frozenset({EVENT_SPLIT, EVENT_RECOVERED, EVENT_REJECTED})

#: Digest prefix for pinned values.
_DIGEST_PREFIX = "sha256:"

#: Field prime: 2**61 - 1 (Mersenne prime, fits in 64 bits). All share
#: arithmetic happens in F_P.
FIELD_PRIME = (1 << 61) - 1

#: Bytes per field word: 7 bytes = 56 bits < 61-bit field.
_BYTES_PER_WORD = 7

#: Domain separation for the deterministic coefficient KDF (deliberately
#: distinct from mpc_interface's domain).
_KDF_DOMAIN = b"northstar-secret-sharing.v1/coeff"


class SecretSharingError(Exception):
    """Base error for the secret-sharing module (fail-closed)."""


class BackupValidationError(SecretSharingError):
    """A share or split parameter failed validation."""


class RecoveryError(SecretSharingError):
    """Recovery was refused (too few shares, inconsistent set)."""


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


def _kdf_coeff(
    secret_digest: bytes, chunk_index: int, coeff_index: int, n: int, t: int
) -> int:
    """Deterministic stand-in for the random polynomial coefficients.

    Real Shamir backup draws fresh coefficients per chunk per split from
    a CSPRNG. Here they are derived from SHA-256 so the module stays
    deterministic (no RNG, no wall-clock) and test fixtures are
    reproducible. The chunk index is bound in so no two chunks share a
    polynomial even for repeated byte patterns. This is precisely what
    makes the simulation *not* a hiding scheme: see the honest-scope
    docstring.
    """
    body = (
        _KDF_DOMAIN
        + b"\x00"
        + secret_digest
        + b"\x00"
        + chunk_index.to_bytes(8, "big")
        + b"\x00"
        + coeff_index.to_bytes(8, "big")
        + b"\x00"
        + n.to_bytes(8, "big")
        + b"\x00"
        + t.to_bytes(8, "big")
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
class BackupShare:
    """One backup share for a byte-string secret.

    ``words`` is the per-chunk evaluation of this share's polynomial at
    ``x = share_id``: ``words[i] = p_i(share_id)`` where ``p_i`` is the
    chunk-``i`` polynomial. ``secret_len`` pins the original secret length
    so ``recover`` can strip chunk padding byte-exactly.
    """

    share_id: int
    words: tuple[int, ...]
    secret_len: int
    n: int
    threshold: int

    def __post_init__(self) -> None:
        _check_int(self.share_id, "share_id")
        _check_int(self.secret_len, "secret_len")
        _check_int(self.n, "n")
        _check_int(self.threshold, "threshold")
        if not isinstance(self.words, tuple):
            raise TypeError("words must be a tuple of ints")
        for w in self.words:
            _check_int(w, "word")
            if not 0 <= w < FIELD_PRIME:
                raise BackupValidationError("share word out of field range")
        if not self.words:
            raise BackupValidationError("share must carry at least one word")
        if not 1 <= self.share_id <= self.n:
            raise BackupValidationError("share_id out of range 1..n")
        if self.n < 1:
            raise BackupValidationError("n must be >= 1")
        if not 1 <= self.threshold <= self.n:
            raise BackupValidationError("threshold must satisfy 1 <= t <= n")
        if self.secret_len < 0:
            raise BackupValidationError("secret_len must be non-negative")
        max_len = len(self.words) * _BYTES_PER_WORD
        if self.secret_len > max_len:
            raise BackupValidationError("secret_len exceeds chunk capacity")

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SECRET_SHARING_SCHEMA,
            "share_id": self.share_id,
            "words": list(self.words),
            "secret_len": self.secret_len,
            "n": self.n,
            "threshold": self.threshold,
            "field_prime": FIELD_PRIME,
        }


def _validate_split_params(secret: bytes, n: int, t: int) -> None:
    if not isinstance(secret, bytes):
        raise TypeError(
            f"secret must be bytes, got {type(secret).__name__}"
        )
    if not secret:
        raise ValueError("secret must be non-empty")
    _check_int(n, "n")
    _check_int(t, "t")
    if n < 1:
        raise ValueError("n must be >= 1")
    if not 1 <= t <= n:
        raise ValueError("threshold must satisfy 1 <= t <= n")


def _to_words(secret: bytes) -> tuple[int, ...]:
    """Chunk secret bytes into FIELD_PRIME-sized words (7 bytes each)."""
    padded = secret + b"\x00" * (-len(secret) % _BYTES_PER_WORD)
    return tuple(
        int.from_bytes(padded[i : i + _BYTES_PER_WORD], "big")
        for i in range(0, len(padded), _BYTES_PER_WORD)
    )


def _from_words(words: Sequence[int], secret_len: int) -> bytes:
    """Reassemble secret bytes from chunk words, stripping chunk padding."""
    raw = b"".join(w.to_bytes(_BYTES_PER_WORD, "big") for w in words)
    return raw[:secret_len]


class SecretSharing:
    """Shamir (t, n) byte-string secret sharing for key backup (simulated).

    Deterministic: the "random" polynomial coefficients come from a
    SHA-256 KDF, so there is no hiding property -- see module docstring.
    The split/recover *algebra* is exact, and byte round-trips are exact.
    """

    #: Pinned field prime (class-level so hosts can read it).
    field_prime: int = FIELD_PRIME

    def split(
        self, secret: bytes, n: int, t: int
    ) -> tuple[BackupShare, ...]:
        """Split ``secret`` bytes into ``n`` backup shares with threshold ``t``.

        Each 7-byte chunk gets its own polynomial ``p_i(x) = word_i +
        c_1 x + ... + c_{t-1} x^{t-1}``; share ``j`` carries
        ``p_i(j)`` for every chunk ``i``. Returns
        ``(BackupShare(1, ...), ..., BackupShare(n, ...))``.
        """
        _validate_split_params(secret, n, t)
        words = _to_words(secret)
        digest = hashlib.sha256(secret).digest()
        shares: list[BackupShare] = []
        for share_id in range(1, n + 1):
            share_words = []
            for chunk_index, word in enumerate(words):
                coeffs = [word] + [
                    _kdf_coeff(digest, chunk_index, c, n, t)
                    for c in range(1, t)
                ]
                share_words.append(_eval_poly(coeffs, share_id))
            shares.append(
                BackupShare(
                    share_id=share_id,
                    words=tuple(share_words),
                    secret_len=len(secret),
                    n=n,
                    threshold=t,
                )
            )
        return tuple(shares)

    def recover(self, shares: Iterable[BackupShare]) -> bytes:
        """Reconstruct the original secret bytes from ``t`` or more shares.

        Fail-closed: fewer than ``t`` shares, duplicate share ids, mixed
        thresholds/``n``/chunk counts/``secret_len``, or non-``BackupShare``
        inputs all raise instead of guessing.
        """
        items = list(shares)
        if not items:
            raise RecoveryError("no shares provided")
        for s in items:
            if not isinstance(s, BackupShare):
                raise TypeError(
                    f"shares must be BackupShare records, "
                    f"got {type(s).__name__}"
                )
        meta = {
            (s.n, s.threshold, len(s.words), s.secret_len) for s in items
        }
        if len(meta) != 1:
            raise RecoveryError(
                "shares disagree on (n, threshold, chunk count, secret_len)"
            )
        (n, t, chunk_count, secret_len) = meta.pop()
        if len(items) < t:
            raise RecoveryError(
                f"need at least {t} shares, got {len(items)}"
            )
        ids = [s.share_id for s in items]
        if len(set(ids)) != len(ids):
            raise RecoveryError("duplicate share_id in share set")
        points_per_chunk: list[list[tuple[int, int]]] = [
            [] for _ in range(chunk_count)
        ]
        for s in items:
            for chunk_index, word in enumerate(s.words):
                points_per_chunk[chunk_index].append((s.share_id, word))
        words = tuple(
            _lagrange_at_zero(points) for points in points_per_chunk
        )
        return _from_words(words, secret_len)

    def share_digest(self, shares: Iterable[BackupShare]) -> str:
        """Pin a share vector with a ``sha256:`` digest (audit aid).

        Binds share ids, words, secret length, n, and threshold. This pins
        *integrity of the vector as handled*, not secrecy.
        """
        items = list(shares)
        for s in items:
            if not isinstance(s, BackupShare):
                raise TypeError("shares must be BackupShare records")
        body = "|".join(
            f"{s.share_id}:"
            + ",".join(str(w) for w in s.words)
            + f":{s.secret_len}:{s.n}:{s.threshold}"
            for s in items
        )
        return _DIGEST_PREFIX + hashlib.sha256(body.encode()).hexdigest()


def secret_sharing_audit_event(
    kind: str, seq: int, **fields: Any
) -> dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for a secret-sharing operation.

    ``seq`` is caller-supplied (no wall-clock). Unknown kinds and
    non-int/bool/negative seqs are rejected fail-closed.
    """
    _reject_bool(seq, "seq")
    if kind not in _EVENT_KINDS:
        raise ValueError(f"unknown secret-sharing audit event kind: {kind!r}")
    if not isinstance(seq, int):
        raise TypeError("seq must be int")
    if seq < 0:
        raise ValueError("seq must be non-negative")
    event: dict[str, Any] = {
        "schema": "audit.ndjson/1",
        "module": SECRET_SHARING_SCHEMA,
        "kind": kind,
        "audit_seq": seq,
    }
    event.update(fields)
    return event


def main() -> None:
    ss = SecretSharing()
    key = b"northstar-backup-key-42"
    shares = ss.split(key, n=5, t=3)
    assert len(shares) == 5
    assert ss.recover(shares[:3]) == key  # exactly t, non-prefix works
    assert ss.recover(shares[2:]) == key  # trailing subset too
    assert ss.recover(shares) == key  # more than t is fine
    try:
        ss.recover(shares[:2])
    except RecoveryError:
        pass
    else:
        raise AssertionError("recover with < t shares must raise")
    # byte-exactness: leading zeros and odd lengths survive
    tricky = b"\x00\x00\x01key\xff"
    assert ss.recover(ss.split(tricky, n=3, t=2)[:2]) == tricky
    assert ss.share_digest(shares) == ss.share_digest(ss.split(key, 5, 3))
    print("secret-sharing OK: split, recover, byte-exact, fail-closed <t")


if __name__ == "__main__":
    main()
