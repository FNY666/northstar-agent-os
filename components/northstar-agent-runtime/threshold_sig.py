"""Threshold signature interface (FROST-style, simulated DKG).

Research motivation: *threshold signatures* let any ``t`` of ``n``
participants jointly produce a signature that verifies under one group
public key, so no single participant ever holds the signing key. FROST
(Komlo-Goldberg 2020) is the modern Schnorr threshold construction; it
runs in two rounds (nonce commitments, then signature shares) and needs
a distributed key generation (DKG) ceremony so the group secret is
never assembled in one place.

This module models the FROST *interface and state machine* with two
deliberate simplifications:

- **Trusted-dealer keygen.** ``keygen`` plays the dealer: it samples
  the master secret and Shamir-shares it. There is no DKG; the dealer
  (the host) sees the master secret. Real deployments must replace
  this with a DKG ceremony.
- **Single deterministic round.** Real FROST exchanges nonce
  commitments in round 1 so the challenge binds them; here each
  signer's nonce is a deterministic function of
  ``(share, message, signer set)``, so ``sign_share`` can recompute
  every co-signer's nonce commitment and derive the challenge without
  a network round. The challenge still binds the signer set: the same
  participant signing the same message with a different co-signer set
  produces a different share, and shares from one signer set do not
  verify against a signature record naming another.

The Schnorr math itself is genuine, over a prime-order subgroup of a
safe-prime field. Group parameters are generated deterministically at
import from a pinned domain seed: a 128-bit safe prime ``p = 2q + 1``
(``q`` prime) with generator ``g = 4`` of the order-``q`` subgroup.
Signing follows the Schnorr equation ``z = r + c * a`` with Shamir
shares ``s_i`` and Lagrange coefficients ``lambda_i``:

- share: ``z_i = r_i + c * lambda_i * s_i   (mod q)``
- aggregate: ``z = sum(z_i)  (mod q)``, ``R = prod(R_i)  (mod p)``
- verify: ``g^z == R * A^c  (mod p)`` where ``c = H(R || A || m)``

Any ``k >= t`` distinct shares combine into a verifying signature;
fewer than ``t`` shares cannot reconstruct the secret, so ``combine``
refuses to mint from them (fail-closed).

Public API:

- ``keygen(n, t, seed=b"")`` -- trusted-dealer key generation; returns
  frozen ``KeyShares``.
- ``sign_share(shares, participant_id, message, signer_ids)`` -- one
  deterministic FROST-style signature share; returns frozen
  ``SignatureShare``.
- ``combine(shares, signature_shares)`` -- aggregates ``>= t`` shares
  into a frozen ``ThresholdSignature``.
- ``verify(shares, message, signature)`` -- Schnorr verification
  against the group public key; ``True`` / ``False`` (policy outcome,
  never raises on a bad signature).
- ``lagrange_coefficient(i, signer_ids)`` -- Lagrange basis at 0.
- ``threshold_sig_audit_event(kind, seq, ...)`` -- ``audit.ndjson/1``
  records; kinds ``"keygen"`` / ``"share-signed"`` / ``"combined"`` /
  ``"verified"`` / ``"rejected"``.
- ``ThresholdSigError``.

Honest scope:

- **No DKG.** ``keygen`` is a trusted dealer. The master secret exists
  in memory during keygen and the shares are its Shamir image. This is
  an interface/state-machine model for wiring threshold-signing
  protocols, not a key-management solution.
- **Deterministic nonces.** ``r_i`` derives from the share, message,
  and signer set. Real FROST uses fresh random nonces per signing
  session; determinism here buys replayable tests and auditability but
  removes the per-session freshness a deployment needs.
- **Single round.** The two-round nonce-commitment structure of FROST
  is folded into one deterministic pass. The algebraic binding
  (challenge commits to every co-signer's nonce) is preserved; the
  network protocol is not.
- ``verify`` checks the Schnorr equation. It cannot tell whether the
  ``t`` shares came from distinct live participants or one host
  holding ``t`` shares -- share custody is the host's problem, like
  every other module in this runtime.
- The group is a 128-bit safe-prime field -- a *toy* size chosen for
  fast deterministic generation and tests. Real deployments need a
  standard 256-bit group. The *shape* of the protocol is what this
  pins; the security parameter is not.

Version pin: ``threshold-sig.v1`` / schema pin
``northstar.threshold-sig.v1``.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional, Sequence, Tuple, Union

#: Module version.
THRESHOLD_SIG_VERSION = "threshold-sig.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.threshold-sig.v1"

#: Version pin carried inside audit records.
AUDIT_FORMAT = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
_AUDIT_KINDS = frozenset(
    {"keygen", "share-signed", "combined", "verified", "rejected"}
)

#: Domain separator for every hash in this module.
_DOMAIN = b"northstar.threshold-sig.v1\x00"

#: Field size: 128-bit safe prime p = 2q + 1, q prime.
_FIELD_BITS = 128

#: Miller-Rabin bases for the deterministic prime search (first 12
#: primes; error bound 4**-12 per candidate -- negligible next to the
#: toy field size, which is documented as non-deployment-grade).
_MR_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


class ThresholdSigError(Exception):
    """Base error for threshold-signature failures."""


def _is_probable_prime(n: int) -> bool:
    """Deterministic Miller-Rabin over the pinned base set."""
    if n < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for p in small:
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in _MR_BASES:
        if a % n == 0:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _find_safe_prime(bits: int, seed: bytes) -> Tuple[int, int]:
    """Deterministically find a ``bits``-bit safe prime ``p = 2q + 1``.

    Candidates derive from ``sha256(seed || counter)``; the search is
    fully deterministic, so every deployment of this module version
    uses the same group.
    """
    counter = 0
    while True:
        digest = hashlib.sha256(seed + counter.to_bytes(8, "big")).digest()
        q = int.from_bytes(digest, "big")
        q |= (1 << (bits - 1)) | 1  # top bit set, odd
        q &= (1 << bits) - 1
        if _is_probable_prime(q):
            p = 2 * q + 1
            if _is_probable_prime(p):
                return p, q
        counter += 1


# Group parameters, generated once at import from the pinned domain.
_P, _Q = _find_safe_prime(_FIELD_BITS, _DOMAIN + b"group-params\x00")

#: Generator of the order-q subgroup: 4 = 2^2 is a square, hence in the
#: subgroup; the asserts below pin the subgroup membership.
_G = 4
assert pow(_G, _Q, _P) == 1, "generator not in order-q subgroup"
assert _G % _P != 1, "generator is trivial"

#: Fixed byte/hex widths for field elements and group elements.
_SCALAR_HEX = (_Q.bit_length() + 7) // 8 * 2
_GROUP_HEX = (_P.bit_length() + 7) // 8 * 2


def _check_int(value: object, name: str) -> int:
    """Reject bools and non-ints fail-closed."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be int, got {type(value).__name__}")
    return value


def _hash_to_scalar(*parts: bytes) -> int:
    """Domain-separated hash to a scalar in ``[1, q)`` (never zero)."""
    out = int.from_bytes(
        hashlib.sha256(_DOMAIN + b"scalar\x00" + b"".join(parts)).digest(),
        "big",
    ) % _Q
    if out == 0:
        out = int.from_bytes(
            hashlib.sha256(_DOMAIN + b"scalar-retry\x00" + b"".join(parts)).digest(),
            "big",
        ) % _Q or 1
    return out


def _hash_to_challenge(*parts: bytes) -> int:
    """Domain-separated Fiat-Shamir challenge in ``[0, q)``."""
    return int.from_bytes(
        hashlib.sha256(_DOMAIN + b"challenge\x00" + b"".join(parts)).digest(),
        "big",
    ) % _Q


def _int_to_fixed(value: int, width: int) -> bytes:
    return value.to_bytes(width // 2, "big")


def _message_parts(message: Union[str, bytes]) -> Tuple[bytes, str]:
    """Canonicalize a message. Returns (digest, ``sha256:`` pin).

    ``str`` and ``bytes`` are type-tagged so ``"m"`` and ``b"m"`` sign
    different digests (no caller type-confusion collision).
    """
    if isinstance(message, bool) or not isinstance(message, (str, bytes)):
        raise TypeError(
            f"message must be str or bytes, got {type(message).__name__}"
        )
    if isinstance(message, str):
        raw = b"s\x00" + message.encode("utf-8")
    else:
        raw = b"b\x00" + bytes(message)
    if len(raw) == 2:  # tag only: empty message
        raise ValueError("message must be non-empty")
    digest = hashlib.sha256(_DOMAIN + b"message\x00" + raw).digest()
    return digest, "sha256:" + digest.hex()


def _modinv(x: int) -> int:
    """Modular inverse mod q (q is prime by construction)."""
    return pow(x % _Q, _Q - 2, _Q)


def lagrange_coefficient(i: int, signer_ids: Sequence[int]) -> int:
    """Lagrange basis polynomial at 0 for participant ``i``.

    ``lambda_i = prod_{j in S, j != i} j / (j - i)  (mod q)``.
    """
    ids = [_check_int(v, "signer_id") for v in signer_ids]
    i = _check_int(i, "participant_id")
    if i not in ids:
        raise ThresholdSigError(f"participant {i} not in signer set")
    if len(set(ids)) != len(ids):
        raise ThresholdSigError("signer set has duplicate ids")
    num = 1
    den = 1
    for j in ids:
        if j == i:
            continue
        num = (num * j) % _Q
        den = (den * (j - i)) % _Q
    return (num * _modinv(den)) % _Q


def _nonce_scalar(share: int, participant_id: int, msg_digest: bytes,
                  signer_ids: Sequence[int]) -> int:
    """Deterministic per-share nonce bound to share, message, signers."""
    ids = ",".join(str(v) for v in sorted(signer_ids)).encode()
    return _hash_to_scalar(
        b"nonce\x00",
        _int_to_fixed(share, _SCALAR_HEX),
        participant_id.to_bytes(4, "big"),
        msg_digest,
        ids,
    )


@dataclass(frozen=True)
class KeyShares:
    """Result of trusted-dealer key generation (the dealer's record).

    ``shares`` maps participant id (1..n) to its Shamir share scalar,
    carried as fixed-width hex. ``group_public`` is the hex encoding of
    ``A = g^a``. ``params_digest`` pins ``(n, t, seed)`` plus the group
    parameters so shares from different keygens cannot be mixed.
    """

    n: int
    t: int
    group_public: str
    shares: Tuple[Tuple[int, str], ...]
    params_digest: str
    version: str = THRESHOLD_SIG_VERSION
    schema: str = SCHEMA_PIN

    def share_of(self, participant_id: int) -> int:
        """Return the scalar share for a participant, or raise."""
        for pid, shex in self.shares:
            if pid == participant_id:
                return int(shex, 16)
        raise ThresholdSigError(f"no share for participant {participant_id}")

    def as_dict(self) -> dict:
        return {
            "version": self.version,
            "schema": self.schema,
            "n": self.n,
            "t": self.t,
            "group_public": self.group_public,
            "shares": [
                {"participant_id": pid, "share": shex}
                for pid, shex in self.shares
            ],
            "params_digest": self.params_digest,
        }


@dataclass(frozen=True)
class SignatureShare:
    """One participant's deterministic signature share."""

    participant_id: int
    signer_ids: Tuple[int, ...]
    nonce_commitment: str  # hex of R_i = g^{r_i}
    z: str  # hex of z_i = r_i + c * lambda_i * s_i
    message_digest: str  # sha256: pin of the signed message
    params_digest: str  # pins the keygen these shares belong to
    version: str = THRESHOLD_SIG_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict:
        return {
            "version": self.version,
            "schema": self.schema,
            "participant_id": self.participant_id,
            "signer_ids": list(self.signer_ids),
            "nonce_commitment": self.nonce_commitment,
            "z": self.z,
            "message_digest": self.message_digest,
            "params_digest": self.params_digest,
        }


@dataclass(frozen=True)
class ThresholdSignature:
    """Aggregated t-of-n Schnorr signature."""

    r: str  # hex of R = prod(R_i)
    z: str  # hex of z = sum(z_i)
    signer_ids: Tuple[int, ...]
    message_digest: str
    params_digest: str
    version: str = THRESHOLD_SIG_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict:
        return {
            "version": self.version,
            "schema": self.schema,
            "r": self.r,
            "z": self.z,
            "signer_ids": list(self.signer_ids),
            "message_digest": self.message_digest,
            "params_digest": self.params_digest,
        }


def _params_digest(n: int, t: int, seed: bytes) -> str:
    body = (
        n.to_bytes(4, "big") + t.to_bytes(4, "big") + seed
        + _P.to_bytes((_P.bit_length() + 7) // 8, "big")
        + _Q.to_bytes((_Q.bit_length() + 7) // 8, "big")
        + _G.to_bytes(1, "big")
    )
    return "sha256:" + hashlib.sha256(_DOMAIN + b"params\x00" + body).hexdigest()


def keygen(n: int, t: int, seed: bytes = b"") -> KeyShares:
    """Trusted-dealer key generation for a t-of-n threshold scheme.

    Samples a master secret and Shamir-shares it (degree ``t - 1``).
    Deterministic in ``(n, t, seed)``. The dealer sees the master
    secret -- replace with a DKG ceremony before any adversarial use.
    """
    n = _check_int(n, "n")
    t = _check_int(t, "t")
    if isinstance(seed, bool) or not isinstance(seed, bytes):
        raise TypeError(f"seed must be bytes, got {type(seed).__name__}")
    if n < 1:
        raise ValueError("n must be >= 1")
    if t < 1:
        raise ValueError("t must be >= 1")
    if t > n:
        raise ValueError("t must be <= n")

    tag = b"keygen\x00" + n.to_bytes(4, "big") + t.to_bytes(4, "big") + seed
    master = _hash_to_scalar(tag + b"master\x00")
    coeffs = [master] + [
        _hash_to_scalar(tag + b"coeff\x00" + j.to_bytes(4, "big"))
        for j in range(1, t)
    ]
    shares = []
    for pid in range(1, n + 1):
        s = 0
        power = 1
        for c in coeffs:
            s = (s + c * power) % _Q
            power = (power * pid) % _Q
        shares.append((pid, format(s, f"0{_SCALAR_HEX}x")))
    group_public = format(pow(_G, master, _P), f"0{_GROUP_HEX}x")
    return KeyShares(
        n=n,
        t=t,
        group_public=group_public,
        shares=tuple(shares),
        params_digest=_params_digest(n, t, seed),
    )


def _aggregate_nonce(shares: KeyShares, signer_ids: Sequence[int],
                     msg_digest: bytes) -> Tuple[int, Dict[int, int], Dict[int, int]]:
    """Recompute every co-signer's nonce: R = prod(R_j), plus maps."""
    r_of: Dict[int, int] = {}
    R_of: Dict[int, int] = {}
    agg = 1
    for pid in signer_ids:
        share = shares.share_of(pid)  # raises on unknown participant
        r = _nonce_scalar(share, pid, msg_digest, signer_ids)
        R = pow(_G, r, _P)
        r_of[pid] = r
        R_of[pid] = R
        agg = (agg * R) % _P
    return agg, r_of, R_of


def sign_share(shares: KeyShares, participant_id: int,
               message: Union[str, bytes],
               signer_ids: Sequence[int]) -> SignatureShare:
    """Produce one deterministic signature share for ``participant_id``.

    ``signer_ids`` is the exact co-signer set for this signing round;
    the Fiat-Shamir challenge binds it, so a share cannot be replayed
    into a different signer set.
    """
    if not isinstance(shares, KeyShares):
        raise TypeError(
            f"shares must be KeyShares, got {type(shares).__name__}"
        )
    participant_id = _check_int(participant_id, "participant_id")
    ids = [_check_int(v, "signer_id") for v in signer_ids]
    if len(ids) == 0:
        raise ValueError("signer_ids must be non-empty")
    if len(set(ids)) != len(ids):
        raise ThresholdSigError("signer_ids has duplicate ids")
    if participant_id not in ids:
        raise ThresholdSigError(
            f"participant {participant_id} not in signer set"
        )
    for pid in ids:
        if pid < 1 or pid > shares.n:
            raise ThresholdSigError(f"signer id {pid} out of range 1..{shares.n}")

    msg_digest_raw, msg_pin = _message_parts(message)
    agg_R, r_of, R_of = _aggregate_nonce(shares, ids, msg_digest_raw)
    A = int(shares.group_public, 16)
    c = _hash_to_challenge(
        _int_to_fixed(agg_R, _GROUP_HEX),
        _int_to_fixed(A, _GROUP_HEX),
        msg_digest_raw,
    )
    lam = lagrange_coefficient(participant_id, ids)
    share = shares.share_of(participant_id)
    z = (r_of[participant_id] + c * lam * share) % _Q
    return SignatureShare(
        participant_id=participant_id,
        signer_ids=tuple(sorted(ids)),
        nonce_commitment=format(R_of[participant_id], f"0{_GROUP_HEX}x"),
        z=format(z, f"0{_SCALAR_HEX}x"),
        message_digest=msg_pin,
        params_digest=shares.params_digest,
    )


def combine(shares: KeyShares,
            signature_shares: Sequence[SignatureShare]) -> ThresholdSignature:
    """Aggregate ``>= t`` signature shares into one threshold signature.

    Fail-closed: refuses duplicate participants, mixed signer sets,
    mixed messages, mixed keygens, and fewer than ``t`` shares -- a
    short set cannot reconstruct the secret, so no signature is
    minted for it.
    """
    if not isinstance(shares, KeyShares):
        raise TypeError(
            f"shares must be KeyShares, got {type(shares).__name__}"
        )
    parts = list(signature_shares)
    if len(parts) == 0:
        raise ValueError("signature_shares must be non-empty")
    for p in parts:
        if not isinstance(p, SignatureShare):
            raise TypeError(
                f"expected SignatureShare, got {type(p).__name__}"
            )
    pids = [p.participant_id for p in parts]
    if len(set(pids)) != len(pids):
        raise ThresholdSigError("duplicate signature share")
    if len(parts) < shares.t:
        raise ThresholdSigError(
            f"need at least t={shares.t} shares, got {len(parts)}"
        )
    first = parts[0]
    for p in parts[1:]:
        if p.signer_ids != first.signer_ids:
            raise ThresholdSigError("mixed signer sets")
        if p.message_digest != first.message_digest:
            raise ThresholdSigError("mixed messages")
        if p.params_digest != first.params_digest:
            raise ThresholdSigError("mixed keygens")
    if first.params_digest != shares.params_digest:
        raise ThresholdSigError("shares do not match this keygen")
    if set(pids) != set(first.signer_ids):
        raise ThresholdSigError("share set does not match declared signers")

    agg_R = 1
    agg_z = 0
    for p in parts:
        agg_R = (agg_R * int(p.nonce_commitment, 16)) % _P
        agg_z = (agg_z + int(p.z, 16)) % _Q
    return ThresholdSignature(
        r=format(agg_R, f"0{_GROUP_HEX}x"),
        z=format(agg_z, f"0{_SCALAR_HEX}x"),
        signer_ids=first.signer_ids,
        message_digest=first.message_digest,
        params_digest=first.params_digest,
    )


def verify(shares: KeyShares, message: Union[str, bytes],
           signature: ThresholdSignature) -> bool:
    """Verify a threshold signature: ``g^z == R * A^c``.

    Returns ``True``/``False`` (policy outcome); raises ``TypeError``
    only on caller type misuse, never on a bad signature.
    """
    if not isinstance(shares, KeyShares):
        raise TypeError(
            f"shares must be KeyShares, got {type(shares).__name__}"
        )
    if not isinstance(signature, ThresholdSignature):
        raise TypeError(
            f"signature must be ThresholdSignature, got "
            f"{type(signature).__name__}"
        )
    if signature.params_digest != shares.params_digest:
        return False
    try:
        msg_digest_raw, msg_pin = _message_parts(message)
    except (TypeError, ValueError):
        raise
    if msg_pin != signature.message_digest:
        return False
    try:
        R = int(signature.r, 16)
        z = int(signature.z, 16)
        A = int(shares.group_public, 16)
    except ValueError:
        return False
    if not (1 <= R < _P and 0 <= z < _Q and 1 <= A < _P):
        return False
    c = _hash_to_challenge(
        _int_to_fixed(R, _GROUP_HEX),
        _int_to_fixed(A, _GROUP_HEX),
        msg_digest_raw,
    )
    left = pow(_G, z, _P)
    right = (R * pow(A, c, _P)) % _P
    return bool(hmac.compare_digest(
        left.to_bytes((_P.bit_length() + 7) // 8, "big"),
        right.to_bytes((_P.bit_length() + 7) // 8, "big"),
    ))


def threshold_sig_audit_event(kind: str, seq: int,
                              message_digest: Optional[str] = None,
                              params_digest: Optional[str] = None) -> dict:
    """Build an ``audit.ndjson/1``-shaped record for this module."""
    if kind not in _AUDIT_KINDS:
        raise ValueError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError(f"seq must be int, got {type(seq).__name__}")
    if seq < 0:
        raise ValueError("seq must be non-negative")
    record = {
        "format": AUDIT_FORMAT,
        "module": THRESHOLD_SIG_VERSION,
        "schema": SCHEMA_PIN,
        "kind": f"threshold-sig-{kind}",
        "seq": seq,
    }
    if message_digest is not None:
        record["message_digest"] = message_digest
    if params_digest is not None:
        record["params_digest"] = params_digest
    return record


def main() -> None:
    shares = keygen(5, 3, seed=b"self-check")
    signers = [1, 2, 4]
    parts = [sign_share(shares, pid, "hello northstar", signers)
             for pid in signers]
    sig = combine(shares, parts)
    assert verify(shares, "hello northstar", sig)
    assert not verify(shares, "tampered", sig)
    print("threshold-sig OK: 3-of-5 keygen, sign, combine, verify")


if __name__ == "__main__":
    main()
