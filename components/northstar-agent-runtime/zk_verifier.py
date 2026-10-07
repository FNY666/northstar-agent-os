"""Zero-knowledge proof verifier interface for verifiable computation.

Research basis (second-hand):
- ZK proofs (Groth16 / Plonk / STARK families) let a prover convince a
  verifier that a computation was done correctly without revealing the
  private inputs. In an agent runtime the natural use is: the agent claims
  "I ran circuit C on public inputs X and got output Y" and attaches a
  proof; the gate layer verifies *before* acting on Y.
- The security property a verifier actually checks is *binding*: the proof
  is about *this* statement (this circuit, these exact public inputs), not
  some other statement the prover would rather have proven. Statement
  substitution - reusing a valid proof for a different claim - is the
  classic attack this interface exists to stop.

Design: a verifier *interface*, not a real ZK scheme. The cryptography is
simulated with deterministic hash checks, which is enough to pin the
mechanics the runtime depends on:

1. ``bind_statement(circuit_id, public_inputs)`` - deterministic 32-byte
   statement digest: ``sha256(domain || circuit_id || canonical(public_inputs))``.
   Public and deterministic, like a real statement hash.
2. Proof wire format: ``proof_bytes = binding_digest || body``, where the
   first 32 bytes must equal ``bind_statement(...)`` for the claimed
   statement. A proof bound to different public inputs (or a different
   circuit) fails verification - this is the statement-substitution check.
3. Optional key seal: ``seal_with_key`` appends ``HMAC(key, proof_bytes)``;
   ``verify(..., verification_key=key)`` then also checks the trailing MAC.
   This models the trusted-setup verification-key binding (Groth16 vk):
   only proofs sealed under the deployment's key are accepted.

``verify`` never raises on policy: malformed proofs verify False. It raises
``TypeError`` only on a non-``ZKProof`` argument (programming error), and
the ``ZKProof`` constructor itself rejects malformed records fail-closed.

Honest scope: interface, not real zero-knowledge. This module provides no
soundness, no zero-knowledge property, and no protection against a prover
who can compute sha256/HMAC - which is everyone. It pins the *plumbing*:
statement binding, key scoping, canonical public-input encoding, and the
fail-closed verify contract, so the real scheme can be dropped in later
without changing call sites. A True verdict means "the proof is bound to
this statement (and this key)", never "the computation was correct".

No wall-clock anywhere. All functions are pure over the arguments given.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")


#: Version pin for the verifier interface described here.
ZK_VERIFIER_VERSION = "zk-verifier.v1"

#: Schema pin stamped on structured outputs.
SCHEMA_PIN = "northstar.zk-verifier.v1"

#: Domain separator for the statement binding digest.
_BINDING_DOMAIN = b"northstar-zk-binding.v1"

#: Length of the statement binding digest (sha256).
_DIGEST_LEN = 32

#: Length of the key-seal MAC (HMAC-SHA256).
_MAC_LEN = 32

#: Fail-closed upper bound on proof size (1 MiB); larger is a DoS vector.
_MAX_PROOF_BYTES = 1 << 20

#: Fail-closed upper bound on circuit id length.
_MAX_CIRCUIT_ID_LEN = 256

#: Fail-closed upper bound on verification key length.
_MAX_KEY_LEN = 256


def _check_public_inputs(public_inputs: Any) -> Mapping[str, Any]:
    """Validate public inputs are a JSON-canonicalizable string-keyed mapping."""
    if isinstance(public_inputs, bool) or not isinstance(public_inputs, Mapping):
        raise TypeError("public_inputs must be a mapping")
    for key in public_inputs.keys():
        if not isinstance(key, str) or not key:
            raise TypeError("public_inputs keys must be non-empty strings")
    try:
        jcs_canonical_json(dict(public_inputs))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"public_inputs must be JSON-canonicalizable: {exc}") from exc
    return public_inputs


@dataclass(frozen=True)
class ZKProof:
    """A proof object as presented to the verifier.

    ``proof_bytes`` must start with the 32-byte statement binding digest
    for the claimed (``circuit_id``, ``public_inputs``); anything after the
    digest is opaque prover data, optionally ending with a 32-byte key MAC.
    """

    proof_bytes: bytes
    public_inputs: Mapping[str, Any]
    circuit_id: str
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if isinstance(self.proof_bytes, bool) or not isinstance(self.proof_bytes, bytes):
            raise TypeError("proof_bytes must be bytes")
        if not self.proof_bytes:
            raise ValueError("proof_bytes must be non-empty")
        if len(self.proof_bytes) > _MAX_PROOF_BYTES:
            raise ValueError("proof_bytes exceeds maximum size")
        if isinstance(self.circuit_id, bool) or not isinstance(self.circuit_id, str):
            raise TypeError("circuit_id must be a string")
        if not self.circuit_id:
            raise ValueError("circuit_id must be non-empty")
        if len(self.circuit_id) > _MAX_CIRCUIT_ID_LEN:
            raise ValueError("circuit_id exceeds maximum length")
        # Re-validate the mapping (also normalizes nothing - frozen stays as given).
        _check_public_inputs(self.public_inputs)
        if self.schema != SCHEMA_PIN:
            raise ValueError(f"schema must be {SCHEMA_PIN!r}")

    def has_seal(self) -> bool:
        """True if the proof is long enough to carry a trailing key MAC."""
        return len(self.proof_bytes) >= _DIGEST_LEN + _MAC_LEN


def _check_key(key: Any) -> bytes:
    if isinstance(key, bool) or not isinstance(key, bytes):
        raise TypeError("verification_key must be bytes")
    if not key:
        raise ValueError("verification_key must be non-empty")
    if len(key) > _MAX_KEY_LEN:
        raise ValueError("verification_key exceeds maximum length")
    return key


def bind_statement(circuit_id: str, public_inputs: Mapping[str, Any]) -> bytes:
    """Deterministic 32-byte digest binding a circuit to its public inputs.

    Pure function of the statement; provers and verifiers compute the same
    value. Any change to the circuit id or to any public input changes the
    digest.
    """
    if isinstance(circuit_id, bool) or not isinstance(circuit_id, str) or not circuit_id:
        raise ValueError("circuit_id must be a non-empty string")
    _check_public_inputs(public_inputs)
    h = hashlib.sha256()
    h.update(_BINDING_DOMAIN)
    h.update(b"\x00")
    h.update(circuit_id.encode("utf-8"))
    h.update(b"\x00")
    h.update(jcs_canonical_json(dict(public_inputs)))
    return h.digest()


def seal_with_key(proof_bytes: bytes, verification_key: bytes) -> bytes:
    """Append a key MAC to proof bytes (prover/test helper, not verification).

    Documented as a helper on purpose: in a real deployment the prover side
    lives elsewhere; this exists so tests and harnesses can mint sealed
    proofs through the same construction ``verify`` checks.
    """
    if isinstance(proof_bytes, bool) or not isinstance(proof_bytes, bytes) or not proof_bytes:
        raise ValueError("proof_bytes must be non-empty bytes")
    _check_key(verification_key)
    sealed = proof_bytes + hmac.new(verification_key, proof_bytes, hashlib.sha256).digest()
    if len(sealed) > _MAX_PROOF_BYTES:
        raise ValueError("sealed proof exceeds maximum size")
    return sealed


@dataclass(frozen=True)
class VerifyReport:
    """Structured verdict from :func:`verify_detailed`."""

    valid: bool
    reasons: Tuple[str, ...]
    circuit_id: str
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict:
        return {
            "valid": self.valid,
            "reasons": list(self.reasons),
            "circuit_id": self.circuit_id,
            "schema": self.schema,
            "version": ZK_VERIFIER_VERSION,
        }


def verify_detailed(proof: ZKProof,
                    verification_key: Optional[bytes] = None) -> VerifyReport:
    """Verify a proof against its claimed statement, with reasons.

    Checks, in order:
    - ``binding-ok`` / ``binding-mismatch``: first 32 bytes of
      ``proof_bytes`` equal ``bind_statement(circuit_id, public_inputs)``.
    - When ``verification_key`` is given: ``mac-ok`` / ``mac-mismatch`` /
      ``mac-absent`` - the trailing 32 bytes are a valid HMAC over the
      preceding bytes under the key.
    """
    if not isinstance(proof, ZKProof):
        raise TypeError("proof must be a ZKProof")
    if verification_key is not None:
        _check_key(verification_key)

    reasons: list[str] = []
    expected = bind_statement(proof.circuit_id, proof.public_inputs)
    if len(proof.proof_bytes) >= _DIGEST_LEN and hmac.compare_digest(
            proof.proof_bytes[:_DIGEST_LEN], expected):
        reasons.append("binding-ok")
        binding_ok = True
    else:
        reasons.append("binding-mismatch")
        binding_ok = False

    mac_ok = True
    if verification_key is not None:
        if len(proof.proof_bytes) >= _DIGEST_LEN + _MAC_LEN:
            body, tag = proof.proof_bytes[:-_MAC_LEN], proof.proof_bytes[-_MAC_LEN:]
            if hmac.compare_digest(
                    hmac.new(verification_key, body, hashlib.sha256).digest(), tag):
                reasons.append("mac-ok")
            else:
                reasons.append("mac-mismatch")
                mac_ok = False
        else:
            reasons.append("mac-absent")
            mac_ok = False

    valid = binding_ok and mac_ok
    return VerifyReport(valid=valid, reasons=tuple(reasons),
                        circuit_id=proof.circuit_id)


def verify(proof: ZKProof, verification_key: Optional[bytes] = None) -> bool:
    """True if the proof is bound to the claimed statement (and key).

    Never raises on policy: structurally invalid proofs verify False.
    Raises ``TypeError`` only on a non-``ZKProof`` argument.
    """
    return verify_detailed(proof, verification_key).valid


def make_proof(circuit_id: str, public_inputs: Mapping[str, Any],
               body: bytes = b"simulated-prover-output",
               verification_key: Optional[bytes] = None) -> ZKProof:
    """Mint a valid proof for tests/harnesses (prover-side helper).

    Not part of verification. Documented as a helper so call sites never
    mistake proof minting for proof checking.
    """
    if isinstance(body, bool) or not isinstance(body, bytes):
        raise TypeError("body must be bytes")
    raw = bind_statement(circuit_id, public_inputs) + body
    if verification_key is not None:
        raw = seal_with_key(raw, verification_key)
    return ZKProof(proof_bytes=raw, public_inputs=dict(public_inputs),
                   circuit_id=circuit_id)


def main() -> None:
    """Self-check: valid proof verifies, substituted statement does not."""
    good = make_proof("range-check.v1", {"x": 42, "max": 100})
    assert verify(good), "valid proof must verify"
    # Statement substitution: same bytes, different claimed public inputs.
    substituted = ZKProof(proof_bytes=good.proof_bytes,
                          public_inputs={"x": 4200, "max": 100},
                          circuit_id="range-check.v1")
    assert not verify(substituted), "substituted statement must not verify"
    # Key scoping: sealed proof verifies under the right key only.
    key = b"deployment-verification-key"
    sealed = make_proof("range-check.v1", {"x": 42}, verification_key=key)
    assert verify(sealed, verification_key=key), "sealed proof must verify under key"
    assert not verify(sealed, verification_key=b"wrong-key"), \
        "sealed proof must not verify under wrong key"
    print("zk-verifier OK: binding enforced, substitution rejected, key scoped")


if __name__ == "__main__":
    main()
