"""Verifiable random function interface (simulated).

A verifiable random function binds a deterministic pseudorandom output to an
input and a secret key, with a proof anyone can check against the public key:
prove(sk, x) -> (y, proof); verify(pk, x, y, proof) -> bool.

This is a **simulated interface**: the "VRF" here is deterministic HMAC-SHA256
bookkeeping, not ECVRF or any real public-key construction. It pins the API
shape (key generation, prove, verify) and the deterministic binding properties
hosts must enforce. It does **not** provide real unforgeability.

Simulation boundary (honest scope):
  - The proof tag is ``HMAC(sk, domain || pk || input_digest || output)`` —
    unforgeable without the secret key, deterministic, and bound to every
    field it covers.
  - A *stateless* verifier holding only ``pk`` cannot recompute that tag, so
    module-level ``verify`` checks everything a verifier *can* check without
    ``sk``: public-key binding, input binding (``alpha`` is re-digested),
    output binding, and proof shape. Those bindings are real and enforced.
  - The secret holder rechecks the sk-bound tag with ``VRF.recheck``; an
    attacker holding only ``pk`` cannot mint a tag that passes ``recheck``.
  - Do not use this module as a cryptographic VRF. A real ECVRF drops in
    without changing call sites: same ``generate_keypair`` / ``prove`` /
    ``verify`` / ``recheck`` shape.

Properties pinned:
  - Determinism: prove(sk, x) always returns the same (y, proof).
  - Uniqueness: one output per (sk, x); a different claimed output for the
    same proof fails binding checks.
  - Key binding: a proof made under sk only verifies under the matching pk.
  - Input binding: verify(pk, x', y, proof) with x' != x fails.

House rules: frozen dataclasses, fail-closed validation (bool numerics
rejected, empty inputs refused), no wall-clock, no randomness, stdlib-only
(`hashlib`, `hmac`, `dataclasses`, `typing`), version pin ``vrf-interface.v1``,
schema pin ``northstar.vrf-interface.v1``. Outputs and proofs are
``sha256:``-style 64-hex digests; ``vrf_audit_event`` shapes
``audit.ndjson/1`` records.

The >2**53 canonical-JSON caveat documented in ``secure_aggregation`` does not
apply here: digests are computed over bytes, never raw JSON numbers.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

VERSION = "vrf-interface.v1"
SCHEMA = "northstar.vrf-interface.v1"

_DOMAIN = b"northstar-vrf-interface.v1"

_HEX = frozenset("0123456789abcdef")


class VRFError(Exception):
    """Base error for VRF interface misuse."""


def _is_hex64(value: str) -> bool:
    return len(value) == 64 and all(c in _HEX for c in value)


def _fail_closed_str(value: Any, name: str, *, allow_empty: bool = False) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise VRFError(f"{name} must be str, got {type(value).__name__}")
    if not allow_empty and not value:
        raise VRFError(f"{name} must be non-empty")
    return value


def _fail_closed_hex64(value: Any, name: str) -> str:
    value = _fail_closed_str(value, name)
    if not _is_hex64(value):
        raise VRFError(f"{name} must be a 64-hex-char digest")
    return value


def _to_bytes(value: Any, name: str) -> bytes:
    """Accept str/bytes only; never silently coerce other types."""
    if isinstance(value, bool):
        raise VRFError(f"{name} must be str or bytes, got bool")
    if isinstance(value, str):
        out = value.encode("utf-8")
    elif isinstance(value, bytes):
        out = bytes(value)
    else:
        raise VRFError(f"{name} must be str or bytes, got {type(value).__name__}")
    if not out:
        raise VRFError(f"{name} must be non-empty")
    return out


def _hmac_hex(key: bytes, msg: bytes) -> str:
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _input_digest(alpha: bytes) -> str:
    return hashlib.sha256(_DOMAIN + b"/input" + alpha).hexdigest()


def _public_key_of(sk_hex: str) -> str:
    return _hmac_hex(_DOMAIN + b"/pk", sk_hex.encode("ascii"))


def _vrf_output(sk_hex: str, input_digest_hex: str) -> str:
    """Deterministic pseudorandom output y = HMAC(sk, domain || input_digest)."""
    return _hmac_hex(
        _DOMAIN + b"/output",
        sk_hex.encode("ascii") + input_digest_hex.encode("ascii"),
    )


def _vrf_proof_tag(sk_hex: str, pk_hex: str, input_digest_hex: str, output_hex: str) -> str:
    """sk-bound proof tag over the full tuple (pk, input_digest, output)."""
    msg = (
        pk_hex.encode("ascii")
        + input_digest_hex.encode("ascii")
        + output_hex.encode("ascii")
    )
    return _hmac_hex(_DOMAIN + b"/proof" + sk_hex.encode("ascii"), msg)


def generate_keypair(seed: Any) -> "KeyPair":
    """Deterministically derive a (secret_key, public_key) pair from seed."""
    seed_b = _to_bytes(seed, "seed")
    sk = _hmac_hex(_DOMAIN + b"/seed", seed_b)
    return KeyPair(secret_key=sk, public_key=_public_key_of(sk))


@dataclass(frozen=True)
class KeyPair:
    """Frozen key pair record. public_key derives deterministically from secret."""

    secret_key: str = field()
    public_key: str = field()

    def __post_init__(self) -> None:
        _fail_closed_hex64(self.secret_key, "secret_key")
        _fail_closed_hex64(self.public_key, "public_key")
        if _public_key_of(self.secret_key) != self.public_key:
            raise VRFError("public_key does not derive from secret_key")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "version": VERSION,
            "schema": SCHEMA,
            "secret_key": self.secret_key,
            "public_key": self.public_key,
        }


@dataclass(frozen=True)
class VRFProof:
    """Frozen proof record binding (public_key, input_digest, output_digest)."""

    public_key: str = field()
    input_digest: str = field()
    output_digest: str = field()
    proof_tag: str = field()

    def __post_init__(self) -> None:
        _fail_closed_hex64(self.public_key, "public_key")
        _fail_closed_hex64(self.input_digest, "input_digest")
        _fail_closed_hex64(self.output_digest, "output_digest")
        _fail_closed_hex64(self.proof_tag, "proof_tag")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "version": VERSION,
            "schema": SCHEMA,
            "public_key": self.public_key,
            "input_digest": self.input_digest,
            "output_digest": self.output_digest,
            "proof_tag": self.proof_tag,
        }


class VRF:
    """Simulated VRF prover, constructed from a secret key.

    ``prove`` is deterministic. ``recheck`` lets the secret holder fully
    re-verify a proof tag (the check a stateless verifier cannot perform).
    """

    def __init__(self, secret_key: Any) -> None:
        self._sk = _fail_closed_hex64(secret_key, "secret_key")
        self._pk = _public_key_of(self._sk)

    @property
    def public_key(self) -> str:
        """Public key under which proofs from this instance verify."""
        return self._pk

    def prove(self, alpha: Any) -> Tuple[str, VRFProof]:
        """Deterministic prove: returns (output_digest, VRFProof)."""
        alpha_b = _to_bytes(alpha, "alpha")
        inp = _input_digest(alpha_b)
        out = _vrf_output(self._sk, inp)
        tag = _vrf_proof_tag(self._sk, self._pk, inp, out)
        return out, VRFProof(
            public_key=self._pk,
            input_digest=inp,
            output_digest=out,
            proof_tag=tag,
        )

    def recheck(self, proof: Any) -> bool:
        """Issuer-side full re-verification of the sk-bound proof tag.

        Raises VRFError on malformed proof; returns False when the tag does
        not match what this secret key would have issued for the bound fields.
        """
        if not isinstance(proof, VRFProof):
            raise VRFError(f"proof must be VRFProof, got {type(proof).__name__}")
        if proof.public_key != self._pk:
            return False
        expected = _vrf_proof_tag(
            self._sk, proof.public_key, proof.input_digest, proof.output_digest
        )
        return hmac.compare_digest(expected, proof.proof_tag)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "version": VERSION,
            "schema": SCHEMA,
            "public_key": self._pk,
        }


def verify(
    public_key: Any,
    alpha: Any,
    output_digest: Any,
    proof: Any,
) -> bool:
    """Stateless verifier-side check of the bindings a verifier can recompute.

    ``alpha`` is the original input (str/bytes); it is re-digested, so a proof
    for a different input fails. Raises VRFError on malformed inputs (wrong
    types, bad digests); returns False on any binding mismatch — wrong key,
    wrong input, wrong output, or a proof record that does not name this key.
    The sk-bound proof *tag* itself is recheckable only by the secret holder
    (see ``VRF.recheck``); this is the documented simulation boundary.
    """
    pk = _fail_closed_hex64(public_key, "public_key")
    alpha_b = _to_bytes(alpha, "alpha")
    out = _fail_closed_hex64(output_digest, "output_digest")
    if not isinstance(proof, VRFProof):
        raise VRFError(f"proof must be VRFProof, got {type(proof).__name__}")
    if proof.public_key != pk:
        return False
    if proof.input_digest != _input_digest(alpha_b):
        return False
    if proof.output_digest != out:
        return False
    return True


def vrf_audit_event(
    kind: Any, public_key: Any, seq: Any, *, extra: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Shape an audit.ndjson/1 record for VRF operations."""
    if isinstance(kind, bool) or not isinstance(kind, str) or not kind:
        raise VRFError("kind must be a non-empty str")
    allowed = {"key-generated", "proved", "verified", "rejected"}
    if kind not in allowed:
        raise VRFError(f"kind must be one of {sorted(allowed)}")
    pk = _fail_closed_hex64(public_key, "public_key")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise VRFError("seq must be a non-negative int")
    record: Dict[str, Any] = {
        "format": "audit.ndjson/1",
        "version": VERSION,
        "schema": SCHEMA,
        "kind": kind,
        "public_key": pk,
        "seq": seq,
    }
    if extra is not None:
        if not isinstance(extra, dict):
            raise VRFError("extra must be a mapping or None")
        record["extra"] = dict(extra)
    return record


def main() -> None:
    """Self-check: generate, prove, verify, reject tampering, recheck tags."""
    kp = generate_keypair(b"self-check-seed")
    vrf = VRF(kp.secret_key)
    out, proof = vrf.prove("alpha-1")
    assert verify(vrf.public_key, "alpha-1", out, proof), "self-verify failed"
    assert not verify(vrf.public_key, "alpha-2", out, proof), "input swap verified"
    assert not verify(vrf.public_key, "alpha-1", "0" * 64, proof), "output swap verified"
    wrong = generate_keypair(b"other-seed")
    assert not verify(wrong.public_key, "alpha-1", out, proof), "key swap verified"
    # Determinism.
    out2, proof2 = vrf.prove("alpha-1")
    assert out2 == out and proof2 == proof, "prove not deterministic"
    # Issuer-side tag recheck; tampered tags fail it.
    assert vrf.recheck(proof), "recheck failed"
    print("vrf-interface OK: generate, prove, verify, recheck, reject")


if __name__ == "__main__":
    main()
