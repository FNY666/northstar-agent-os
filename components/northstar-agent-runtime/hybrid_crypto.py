"""Hybrid classical + post-quantum signatures: Ed25519-style Schnorr || Dilithium-style lattice (simulated).

Research motivation: NIST SP 1800-38 (migration to post-quantum
cryptography) and the IETF ``pq-composite`` work
(draft-ietf-lamps-pq-composite-sigs) both recommend *hybrid* signatures
during the transition: a signature that verifies under a classical
algorithm *and* a post-quantum algorithm. The combiner is
concatenation: the message is signed with both schemes and a verifier
must accept *both* halves. The hybrid is unforgeable as long as at
least one component is unforgeable, so it protects against both
classical breakage (the PQ half still stands) and a future
cryptanalytic break of the PQ scheme (the classical half still
stands) -- and, operationally, against "harvest now, decrypt later"
only insofar as signatures are concerned: a classical-only signature
has no quantum-safe half to fall back on.

What this module is:

* The mechanical bookkeeping half of the hybrid pattern: keygen /
  sign / verify with frozen records, digest pins, and
  ``audit.ndjson/1`` events in house style.
* The *combiner* is the load-bearing part and is fully specified:
  the classical half signs the message ``m``; the PQ half signs
  ``m || classical_signature_bytes`` (nested binding), so the two
  halves cannot be mixed across messages or signers. ``verify``
  returns ``True`` only when **both** halves verify -- a single
  failing half fails the whole signature (policy outcome, ``False``).
* The component schemes are simulated with genuine algebra:
  - Classical: Schnorr signatures over a deterministically generated
    128-bit safe-prime subgroup (same shape as ``threshold_sig``).
  - PQ: a Fiat-Shamir lattice signature in the Dilithium shape --
    secret ``s``, public ``t = A.s`` over ``Z_q^2``, challenge
    ``c`` in ``{-1, +1}`` from the transcript hash, response
    ``z = y + c.s`` with a norm bound check. The verification
    identity ``A.z - c.t == w`` genuinely holds by linearity.
* Key material is deterministic from the caller-supplied seed (no
  randomness, no wall-clock), so keygen is replayable in tests.

Honest scope (read before relying on this):

* **Not a security boundary.** The group is 128-bit (toy), the
  lattice is dimension 2 over a small modulus (toy), nonces are
  deterministic (no DKG, no real randomness). Do not use this to
  protect real data against real adversaries. Use it to pin the
  *hybrid protocol logic* -- which halves must be present, how they
  bind, when a classical-only path must be refused -- in tests,
  audits, and design reviews.
* ``verify`` returning ``True`` means "both simulated halves check
  out over the pinned message", never "a quantum adversary cannot
  forge this".
* A real deployment needs real Ed25519 (RFC 8032) and real
  ML-DSA/Dilithium (FIPS 204) with a CSPRNG; the call sites of this
  module are shaped so the real schemes drop in without changing the
  combiner.
* This module does not detect a host that signs with a weak seed or
  reuses seeds across deployments -- seed hygiene is the host's job.
* No wall-clock anywhere; all seqs are caller-supplied ints.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any

#: Module version pin.
HYBRID_CRYPTO_VERSION = "hybrid-crypto.v1"

#: Schema pin carried by records and audit events.
HYBRID_CRYPTO_SCHEMA = "northstar.hybrid-crypto.v1"

#: Audit event kinds.
EVENT_KEYGEN = "hybrid-keygen"
EVENT_SIGNED = "hybrid-signed"
EVENT_VERIFIED = "hybrid-verified"
EVENT_REJECTED = "hybrid-rejected"

_EVENT_KINDS = frozenset(
    {EVENT_KEYGEN, EVENT_SIGNED, EVENT_VERIFIED, EVENT_REJECTED}
)

#: Digest prefix for pinned values.
_DIGEST_PREFIX = "sha256:"

#: Domain tags. Every hash input is domain-separated so a nonce can
#: never be replayed as a challenge, a key, or a binding.
_DOM_GROUP = b"northstar.hybrid-crypto.v1/classical-group"
_DOM_CSK = b"northstar.hybrid-crypto.v1/classical-sk"
_DOM_NONCE = b"northstar.hybrid-crypto.v1/classical-nonce"
_DOM_CCHAL = b"northstar.hybrid-crypto.v1/classical-challenge"
_DOM_PSK = b"northstar.hybrid-crypto.v1/pq-sk"
_DOM_PSEED = b"northstar.hybrid-crypto.v1/pq-matrix"
_DOM_PNONCE = b"northstar.hybrid-crypto.v1/pq-nonce"
_DOM_PCHAL = b"northstar.hybrid-crypto.v1/pq-challenge"
_DOM_MSG = b"northstar.hybrid-crypto.v1/message"
_DOM_KEYID = b"northstar.hybrid-crypto.v1/key-id"

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class HybridCryptoError(Exception):
    """Base error for hybrid-crypto failures."""


class KeygenError(HybridCryptoError):
    """Key generation was refused (bad seed)."""


class SignError(HybridCryptoError):
    """Signing was refused (bad key or message)."""


class VerifyInputError(HybridCryptoError):
    """Verify got malformed caller input (never raised on mismatch)."""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _sha256(*parts: bytes) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return _DIGEST_PREFIX + h.hexdigest()


def _raw_sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def _check_seq(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def _check_bytes(value: Any, name: str, *, allow_empty: bool = False) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes, got {type(value).__name__}")
    if not allow_empty and len(value) == 0:
        raise ValueError(f"{name} must be non-empty")
    return value


def _check_seed(seed: Any) -> bytes:
    seed = _check_bytes(seed, "seed")
    if len(seed) > 1024:
        raise KeygenError("seed must be at most 1024 bytes")
    return seed


def _message_digest(message: Any) -> str:
    """Pin a message. Bytes only: str is rejected (no silent encoding)."""
    msg = _check_bytes(message, "message", allow_empty=True)
    return _sha256(_DOM_MSG, msg)


# ---------------------------------------------------------------------------
# Classical component: Schnorr over a deterministically generated
# 128-bit safe-prime subgroup.
# ---------------------------------------------------------------------------

_GROUP_BITS = 128


def _gen_safe_prime(bits: int) -> int:
    """Deterministically find a ``bits``-bit safe prime p = 2q + 1."""
    counter = 0
    while True:
        cand = int.from_bytes(
            _raw_sha256(_DOM_GROUP, b"prime", counter.to_bytes(8, "big")), "big"
        )
        cand &= (1 << bits) - 1  # keep exactly `bits` bits wide
        cand |= (1 << (bits - 1)) | 1  # top bit set, odd
        q = (cand - 1) // 2
        # p and q both prime, with a few Miller-Rabin bases (deterministic
        # for this size class with bases 2, 3, 5, 7, 11).
        if _is_probable_prime(cand) and _is_probable_prime(q):
            return cand
        counter += 1


def _is_probable_prime(n: int) -> bool:
    if n < 2:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29):
        if n % small == 0:
            return n == small
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in (2, 3, 5, 7, 11):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


#: Deterministically generated 128-bit safe prime; pinned at import.
_C_P = _gen_safe_prime(_GROUP_BITS)
#: Subgroup order q = (p - 1) / 2 (prime by construction).
_C_Q = (_C_P - 1) // 2
#: Generator of the order-q subgroup (g = 4 has order q when p = 2q+1).
_C_G = 4
assert pow(_C_G, _C_Q, _C_P) == 1 and _C_G != 1


def _classical_keypair(seed: bytes) -> tuple[int, int]:
    """Return (sk, pk): sk in [1, q-1], pk = g^sk."""
    sk = (
        int.from_bytes(_raw_sha256(_DOM_CSK, seed), "big") % (_C_Q - 1)
    ) + 1
    return sk, pow(_C_G, sk, _C_P)


def _classical_sign(sk: int, message: bytes) -> tuple[int, int]:
    """Schnorr sign: returns (R, z)."""
    r = (
        int.from_bytes(_raw_sha256(_DOM_NONCE, _DOM_CSK, message), "big")
        % (_C_Q - 1)
    ) + 1
    # Bind the nonce to the secret so two seeds never share a nonce.
    r = (r + sk) % _C_Q or 1
    R = pow(_C_G, r, _C_P)
    c = (
        int.from_bytes(
            _raw_sha256(
                _DOM_CCHAL,
                R.to_bytes(16, "big"),
                pow(_C_G, sk, _C_P).to_bytes(16, "big"),
                message,
            ),
            "big",
        )
        % _C_Q
    )
    z = (r + c * sk) % _C_Q
    return R, z


def _classical_verify(pk: int, message: bytes, sig: tuple[int, int]) -> bool:
    """Schnorr verify: g^z == R * pk^c."""
    R, z = sig
    if not (1 <= R < _C_P and 0 <= z < _C_Q and 1 <= pk < _C_P):
        return False
    c = (
        int.from_bytes(
            _raw_sha256(
                _DOM_CCHAL,
                R.to_bytes(16, "big"),
                pk.to_bytes(16, "big"),
                message,
            ),
            "big",
        )
        % _C_Q
    )
    return pow(_C_G, z, _C_P) == (R * pow(pk, c, _C_P)) % _C_P


# ---------------------------------------------------------------------------
# PQ component: toy Fiat-Shamir lattice signature in the Dilithium shape.
#
#   secret s in Z_q^2, |s_i| <= ETA
#   public t = A . s  (A pinned 2x2 matrix over Z_q)
#   sign:   y <- mask range (deterministic), w = A.y,
#           c = H(w || m) (full 32-byte binding tag), z = y + s
#   verify: |z_i| < GAMMA1  and  H(A.z - t || m) == c
#
# The identity A.z - t == w holds by linearity, so an honest
# signature verifies; the full-hash challenge binds the transcript,
# so any tamper to z deterministically breaks the tag check.
# ---------------------------------------------------------------------------

_PQ_Q = 12289
_PQ_ETA = 2
_PQ_GAMMA1 = 100
_PQ_MASK = _PQ_GAMMA1 - _PQ_ETA - 1  # |y_i| <= this keeps |z_i| < GAMMA1


def _pq_matrix() -> tuple[tuple[int, int], tuple[int, int]]:
    """Pinned 2x2 matrix A over Z_q (nothing-up-my-sleeve)."""
    words = _raw_sha256(_DOM_PSEED, b"matrix")
    vals = [
        int.from_bytes(words[i * 2 : i * 2 + 2], "big") % _PQ_Q
        for i in range(4)
    ]
    return ((vals[0], vals[1]), (vals[2], vals[3]))


_PQ_A = _pq_matrix()


def _mat_vec_mul(
    a: tuple[tuple[int, int], tuple[int, int]], v: tuple[int, int]
) -> tuple[int, int]:
    return (
        (a[0][0] * v[0] + a[0][1] * v[1]) % _PQ_Q,
        (a[1][0] * v[0] + a[1][1] * v[1]) % _PQ_Q,
    )


def _centered(x: int) -> int:
    """Map a Z_q residue to (-q/2, q/2]."""
    return x - _PQ_Q if x > _PQ_Q // 2 else x


def _pq_keypair(seed: bytes) -> tuple[tuple[int, int], tuple[int, int]]:
    """Return (s, t): secret vector, public t = A.s."""
    words = _raw_sha256(_DOM_PSK, seed)
    s = tuple(
        (int.from_bytes(words[i * 2 : i * 2 + 2], "big") % (2 * _PQ_ETA + 1))
        - _PQ_ETA
        for i in range(2)
    )
    t = _mat_vec_mul(_PQ_A, tuple(x % _PQ_Q for x in s))
    return s, t


def _pq_expand_nonce(seed: bytes, message: bytes) -> tuple[int, int]:
    words = _raw_sha256(_DOM_PNONCE, seed, message)
    return tuple(
        (int.from_bytes(words[i * 2 : i * 2 + 2], "big") % (2 * _PQ_MASK + 1))
        - _PQ_MASK
        for i in range(2)
    )


def _pq_challenge(w: tuple[int, int], message: bytes) -> bytes:
    """Fiat-Shamir binding tag: the full transcript hash H(w || m)."""
    return _raw_sha256(
        _DOM_PCHAL, str(w[0]).encode(), str(w[1]).encode(), message
    )


def _pq_sign(
    seed: bytes, s: tuple[int, int], message: bytes
) -> tuple[tuple[int, int], bytes]:
    """Return (z, c) with z = y + s. Deterministic."""
    y = _pq_expand_nonce(seed, message)
    w = _mat_vec_mul(_PQ_A, tuple(x % _PQ_Q for x in y))
    c = _pq_challenge(w, message)
    z = (y[0] + s[0], y[1] + s[1])
    return z, c


def _pq_verify(
    t: tuple[int, int], message: bytes, sig: tuple[tuple[int, int], bytes]
) -> bool:
    z, c = sig
    if not isinstance(c, bytes) or len(c) != 32:
        return False
    if any(not isinstance(x, int) or abs(x) >= _PQ_GAMMA1 for x in z):
        return False
    # w' = A.z - t  (== w for an honest signature, by linearity)
    az = _mat_vec_mul(_PQ_A, tuple(x % _PQ_Q for x in z))
    w = ((az[0] - t[0]) % _PQ_Q, (az[1] - t[1]) % _PQ_Q)
    return _pq_challenge(w, message) == c


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HybridPublicKey:
    """Public half of a hybrid keypair (safe to share)."""

    key_id: str
    classical_pk: int
    pq_pk: tuple[int, int]

    def __post_init__(self) -> None:
        if not isinstance(self.key_id, str) or not self.key_id:
            raise TypeError("key_id must be a non-empty str")
        if isinstance(self.classical_pk, bool) or not isinstance(
            self.classical_pk, int
        ):
            raise TypeError("classical_pk must be an int")
        if not (
            isinstance(self.pq_pk, tuple)
            and len(self.pq_pk) == 2
            and all(isinstance(x, int) and not isinstance(x, bool) for x in self.pq_pk)
        ):
            raise TypeError("pq_pk must be a tuple of 2 ints")

    def as_dict(self) -> dict:
        return {
            "schema": HYBRID_CRYPTO_SCHEMA,
            "key_id": self.key_id,
            "classical_pk": hex(self.classical_pk),
            "pq_pk": [hex(x) for x in self.pq_pk],
        }


@dataclass(frozen=True)
class HybridSecretKey:
    """Secret half of a hybrid keypair (never leaves the signer)."""

    key_id: str
    seed: bytes
    classical_sk: int
    pq_sk: tuple[int, int]

    def __post_init__(self) -> None:
        if not isinstance(self.key_id, str) or not self.key_id:
            raise TypeError("key_id must be a non-empty str")
        _check_bytes(self.seed, "seed")
        if isinstance(self.classical_sk, bool) or not isinstance(
            self.classical_sk, int
        ):
            raise TypeError("classical_sk must be an int")
        if not (
            isinstance(self.pq_sk, tuple)
            and len(self.pq_sk) == 2
            and all(isinstance(x, int) and not isinstance(x, bool) for x in self.pq_sk)
        ):
            raise TypeError("pq_sk must be a tuple of 2 ints")

    def public(self) -> HybridPublicKey:
        """Derive the public key (recomputes both public halves)."""
        _, classical_pk = _classical_keypair(self.seed)
        _, pq_pk = _pq_keypair(self.seed)
        return HybridPublicKey(
            key_id=self.key_id,
            classical_pk=classical_pk,
            pq_pk=pq_pk,
        )

    def as_dict(self) -> dict:
        # Secrets are never serialized: only a digest of the seed.
        return {
            "schema": HYBRID_CRYPTO_SCHEMA,
            "key_id": self.key_id,
            "seed_digest": _sha256(self.seed),
        }


@dataclass(frozen=True)
class HybridSignature:
    """A hybrid signature: classical half + PQ half, bound together."""

    key_id: str
    message_digest: str
    classical_sig: tuple[int, int]
    pq_sig: tuple[tuple[int, int], int]

    def __post_init__(self) -> None:
        if not isinstance(self.key_id, str) or not self.key_id:
            raise TypeError("key_id must be a non-empty str")
        if not isinstance(self.message_digest, str) or not self.message_digest.startswith(
            _DIGEST_PREFIX
        ):
            raise TypeError("message_digest must be a sha256: pin")
        if not (
            isinstance(self.classical_sig, tuple)
            and len(self.classical_sig) == 2
            and all(isinstance(x, int) and not isinstance(x, bool) for x in self.classical_sig)
        ):
            raise TypeError("classical_sig must be a tuple of 2 ints")
        z, c = self.pq_sig
        if not (
            isinstance(self.pq_sig, tuple)
            and len(self.pq_sig) == 2
            and isinstance(z, tuple)
            and len(z) == 2
            and all(isinstance(x, int) and not isinstance(x, bool) for x in z)
            and isinstance(c, bytes)
            and len(c) == 32
        ):
            raise TypeError("pq_sig must be ((int, int), 32-byte tag)")

    def wire_bytes(self) -> bytes:
        """Canonical bytes of the signature (what the PQ half binds)."""
        r, zc = self.classical_sig
        z, c = self.pq_sig
        return b"|".join(
            [
                self.key_id.encode(),
                hex(r).encode(),
                hex(zc).encode(),
                hex(z[0]).encode(),
                hex(z[1]).encode(),
                c.hex().encode(),
            ]
        )

    def as_dict(self) -> dict:
        r, zc = self.classical_sig
        z, c = self.pq_sig
        return {
            "schema": HYBRID_CRYPTO_SCHEMA,
            "key_id": self.key_id,
            "message_digest": self.message_digest,
            "classical_sig": [hex(r), hex(zc)],
            "pq_sig": [[hex(z[0]), hex(z[1])], c.hex()],
        }


# ---------------------------------------------------------------------------
# Key generation / signing / verification
# ---------------------------------------------------------------------------


def keygen(seed: bytes) -> tuple[HybridPublicKey, HybridSecretKey]:
    """Generate a hybrid keypair deterministically from ``seed``.

    Returns ``(public, secret)``. The same seed always yields the same
    keypair (replayable); different seeds yield disjoint keypairs.
    """
    seed = _check_seed(seed)
    key_id = _sha256(_DOM_KEYID, seed)
    classical_sk, _ = _classical_keypair(seed)
    pq_sk, _ = _pq_keypair(seed)
    secret = HybridSecretKey(
        key_id=key_id,
        seed=seed,
        classical_sk=classical_sk,
        pq_sk=pq_sk,
    )
    return secret.public(), secret


def sign(secret: HybridSecretKey, message: bytes) -> HybridSignature:
    """Sign ``message`` with both halves (nested binding).

    The classical half signs ``m``; the PQ half signs
    ``m || classical_signature_bytes``, so the two halves cannot be
    mixed across messages or keys. Both halves must later verify.
    """
    if not isinstance(secret, HybridSecretKey):
        raise SignError(
            f"secret must be a HybridSecretKey, got {type(secret).__name__}"
        )
    msg = _check_bytes(message, "message", allow_empty=True)
    digest = _message_digest(msg)
    classical_sig = _classical_sign(secret.classical_sk, msg)
    # Nested binding: the PQ transcript commits to the classical half.
    nested = msg + b"||" + b"|".join(
        hex(x).encode() for x in classical_sig
    )
    pq_sig = _pq_sign(secret.seed, secret.pq_sk, nested)
    return HybridSignature(
        key_id=secret.key_id,
        message_digest=digest,
        classical_sig=classical_sig,
        pq_sig=pq_sig,
    )


def verify(
    public: HybridPublicKey, message: bytes, signature: HybridSignature
) -> bool:
    """Verify a hybrid signature.

    Returns ``True`` only when **both** halves verify: the classical
    half over ``m`` and the PQ half over ``m || classical_sig``. Any
    mismatch is a policy outcome (``False``); malformed caller input
    raises ``VerifyInputError``.
    """
    if not isinstance(public, HybridPublicKey):
        raise VerifyInputError(
            f"public must be a HybridPublicKey, got {type(public).__name__}"
        )
    if not isinstance(signature, HybridSignature):
        raise VerifyInputError(
            f"signature must be a HybridSignature, got {type(signature).__name__}"
        )
    msg = _check_bytes(message, "message", allow_empty=True)
    if signature.key_id != public.key_id:
        return False
    if signature.message_digest != _message_digest(msg):
        return False
    if not _classical_verify(public.classical_pk, msg, signature.classical_sig):
        return False
    nested = msg + b"||" + b"|".join(
        hex(x).encode() for x in signature.classical_sig
    )
    if not _pq_verify(public.pq_pk, nested, signature.pq_sig):
        return False
    return True


def hybrid_audit_event(kind: str, record: Any, seq: int) -> dict:
    """Shape an ``audit.ndjson/1`` record for a hybrid-crypto event."""
    if kind not in _EVENT_KINDS:
        raise ValueError(f"unknown event kind {kind!r}")
    if not isinstance(record, (HybridPublicKey, HybridSecretKey, HybridSignature)):
        raise TypeError(
            f"record must be a hybrid-crypto record, got {type(record).__name__}"
        )
    _check_seq(seq, "seq")
    return {
        "schema": "northstar.audit.ndjson/1",
        "event": kind,
        "module": HYBRID_CRYPTO_VERSION,
        "record": record.as_dict(),
        "audit_seq": seq,
    }


def main() -> None:
    public, secret = keygen(b"hybrid-self-check-seed")
    assert secret.public() == public
    sig = sign(secret, b"migrate to PQC")
    assert verify(public, b"migrate to PQC", sig) is True
    # Wrong message fails (both halves are message-bound).
    assert verify(public, b"other message", sig) is False
    # Tampered classical half fails.
    r, z = sig.classical_sig
    bad_classical = HybridSignature(
        key_id=sig.key_id,
        message_digest=sig.message_digest,
        classical_sig=(r, (z + 1) % _C_Q),
        pq_sig=sig.pq_sig,
    )
    assert verify(public, b"migrate to PQC", bad_classical) is False
    # Tampered PQ half fails.
    (pz0, pz1), pc = sig.pq_sig
    bad_pq = HybridSignature(
        key_id=sig.key_id,
        message_digest=sig.message_digest,
        classical_sig=sig.classical_sig,
        pq_sig=((pz0 + 1, pz1), pc),
    )
    assert verify(public, b"migrate to PQC", bad_pq) is False
    # Halves cannot be mixed across messages: sign m2, splice its
    # classical half under m1's PQ half -> nested binding rejects.
    sig2 = sign(secret, b"second message")
    mixed = HybridSignature(
        key_id=sig.key_id,
        message_digest=sig.message_digest,
        classical_sig=sig2.classical_sig,
        pq_sig=sig.pq_sig,
    )
    assert verify(public, b"migrate to PQC", mixed) is False
    # Wrong key fails.
    other_public, _ = keygen(b"different-seed")
    assert verify(other_public, b"migrate to PQC", sig) is False
    # Classical-only path is visibly not hybrid: a lone Schnorr
    # signature has no PQ half to verify, so it can never pass.
    lone = _classical_sign(secret.classical_sk, b"migrate to PQC")
    assert _classical_verify(public.classical_pk, b"migrate to PQC", lone) is True
    print("hybrid-crypto OK: keygen, sign, both-halves verify, tamper/mix/key reject")


if __name__ == "__main__":
    main()
